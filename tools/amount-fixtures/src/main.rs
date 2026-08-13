//! Emits `contracts/test/fixtures/amount.json` -- the oracle for opening a
//! MobileCoin TxOut's amount and beneficiary on chain.
//!
//! # What this file is for
//!
//! `MobileCoinVerifier` is being changed so that it stops trusting the
//! `amount`, `tokenId` and `beneficiary` a relayer types into a `Proof`, and
//! instead derives all three from bytes the TxOut digest actually commits to.
//! That derivation is not obvious and it is the only thing standing between
//! the escrow and anyone holding one genuine quorum-signed return. So it needs
//! an oracle that is external to the Solidity, and the oracle must not be a
//! second hand-written implementation of the same spec -- two independent
//! transcriptions of a spec can agree with each other and both be wrong.
//!
//! So: nothing here re-derives anything. Every published byte comes out of
//! MobileCoin's own crates --
//! `MaskedAmountV2::new` / `get_value` / `compute_amount_shared_secret`,
//! `generators`, `CompressedCommitment::new`, `MemoPayload::encrypt` /
//! `decrypt_from`, `get_tx_out_shared_secret` -- or out of curve25519-dalek.
//!
//! # Why intermediates are published at all
//!
//! A Solidity test that only compares the final value tells you "wrong" and
//! nothing else. So the fixture also carries the amount shared secret, the two
//! 8-byte masks, the 64 wide bytes the blinding is reduced from, the memo OKM,
//! the AES counter blocks and the keystream. Those are NOT returned by
//! MobileCoin's public API, so the generator recomputes them with the same
//! `hkdf`/`sha2`/`aes`/`ctr` versions MobileCoin pins and then ASSERTS they
//! reproduce what the MobileCoin API returned. An intermediate that did not
//! reconstruct the API's answer would abort this program rather than be
//! written out. See the asserts in `amount_case` and `memo_case`.
//!
//! # Regenerate
//!
//! ```text
//! cd tools/amount-fixtures && cargo run --offline
//! ```

use std::collections::BTreeMap;
use std::path::PathBuf;

use aes::cipher::{KeyIvInit, StreamCipher};
use aes::Aes256;
use ctr::Ctr64BE;
use curve25519_dalek::{
    constants::{RISTRETTO_BASEPOINT_COMPRESSED, RISTRETTO_BASEPOINT_POINT},
    ristretto::RistrettoPoint,
    scalar::Scalar,
};
use hkdf::Hkdf;
use mc_crypto_hashes::{Blake2b512, Digest};
use mc_crypto_keys::{RistrettoPrivate, RistrettoPublic};
use mc_crypto_ring_signature::{generators, CompressedCommitment};
use mc_transaction_core::{get_tx_out_shared_secret, MemoPayload};
use mc_transaction_types::{Amount, AmountError, MaskedAmountV2, TokenId};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use serde_json::{json, Value};
use sha2::{Sha256, Sha512};

/// MobileCoin token id for eUSD. Mirrors `two_cohort::EUSD_TOKEN_ID`; the
/// verifier will pin `B_token` for exactly this id at construction.
const EUSD_TOKEN_ID: u64 = 8192;

/// `crates/mc-return/src/disclosure.rs::BRIDGE_RETURN_MEMO_TYPE`.
const BRIDGE_RETURN_MEMO_TYPE: [u8; 2] = [0x80, 0x01];

// Domain separators. Spelled out rather than imported so that the JSON records
// the literal bytes a Solidity implementation has to hash; each is asserted
// equal to MobileCoin's own constant in `check_domain_separators` below, so a
// typo here is a build-time failure, not a silent divergence.
const AMOUNT_SHARED_SECRET_TAG: &str = "mc_amount_shared_secret";
const AMOUNT_BLINDING_FACTORS_TAG: &[u8] = b"mc_amount_blinding_factors";
const AMOUNT_VALUE_TAG: &str = "mc_amount_value";
const AMOUNT_TOKEN_ID_TAG: &str = "mc_amount_token_id";
const AMOUNT_BLINDING_TAG: &str = "mc_amount_blinding";
const MEMO_OKM_SALT: &[u8] = b"mc-memo-okm";
/// `crypto/ring-signature/src/domain_separators.rs::HASH_TO_POINT_DOMAIN_TAG`.
const HASH_TO_POINT_TAG: &str = "mc_onetime_key_hash_to_point";

fn hx(b: &[u8]) -> String {
    format!("0x{}", hex::encode(b))
}

/// u64s are emitted as decimal STRINGS. JSON numbers are IEEE doubles in
/// JavaScript, and several of these cases are deliberately larger than 2^53
/// (`u64::MAX`, and the token-id masks, which are uniformly random 64-bit
/// values). `JSON.parse` would silently round them.
fn u64s(v: u64) -> String {
    v.to_string()
}

fn rand_scalar(rng: &mut ChaCha20Rng) -> Scalar {
    let mut b = [0u8; 64];
    rng.fill_bytes(&mut b);
    Scalar::from_bytes_mod_order_wide(&b)
}

// ---------------------------------------------------------------------------
// Domain separators: assert the literals above are MobileCoin's
// ---------------------------------------------------------------------------

fn check_domain_separators() {
    use mc_transaction_types::domain_separators as ds;
    assert_eq!(AMOUNT_SHARED_SECRET_TAG, ds::AMOUNT_SHARED_SECRET_DOMAIN_TAG);
    assert_eq!(
        AMOUNT_BLINDING_FACTORS_TAG,
        ds::AMOUNT_BLINDING_FACTORS_DOMAIN_TAG
    );
    assert_eq!(AMOUNT_VALUE_TAG, ds::AMOUNT_VALUE_DOMAIN_TAG);
    assert_eq!(AMOUNT_TOKEN_ID_TAG, ds::AMOUNT_TOKEN_ID_DOMAIN_TAG);
    assert_eq!(AMOUNT_BLINDING_TAG, ds::AMOUNT_BLINDING_DOMAIN_TAG);
}

// ---------------------------------------------------------------------------
// Section 4: Pedersen generators
// ---------------------------------------------------------------------------

/// `B_token` and `B_blinding`, compressed.
///
/// The verifier must NOT do hash-to-curve on chain. It accepts exactly one
/// token id, so `B_token` is a deployment constant -- and a constant with no
/// provenance is just a magic number, which is why this section exists and why
/// the JS test must assert the pinned immutable equals `byTokenId[eusd]`.
///
/// This also re-derives `B_token` the long way (Blake2b512 over the domain tag
/// and the basepoint encoding with the token id XORed over bytes 0..8) and
/// asserts it matches `generators()`, so the JSON documents *how* the constant
/// is obtained, not merely what it is.
fn generator_section(token_ids: &[u64]) -> Value {
    // `B_BLINDING` is not re-exported from the crate root, so it is read back
    // out of `generators()` -- which is where the verifier's copy has to come
    // from anyway -- and checked against dalek's basepoint, which is what
    // ring_signature/mod.rs:48 defines it to be.
    let b_blinding = generators(0).B_blinding;
    assert_eq!(
        b_blinding, RISTRETTO_BASEPOINT_POINT,
        "B_blinding is no longer the Ristretto basepoint"
    );

    // MobileCoin publishes no known-answer for B_token, so the one EXTERNAL
    // anchor under this whole section is the ristretto255 draft's basepoint
    // encoding, which is the preimage every B_token is built from. If this
    // matched nothing published, `bToken` would be pinned only to whatever
    // this repository's dalek happens to compute.
    const RISTRETTO255_BASEPOINT_ENCODING: &str =
        "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76";
    assert_eq!(
        hex::encode(RISTRETTO_BASEPOINT_COMPRESSED.to_bytes()),
        RISTRETTO255_BASEPOINT_ENCODING,
        "basepoint encoding is not the published ristretto255 vector"
    );

    let mut by_token = Vec::new();
    for &id in token_ids {
        let gens = generators(id);
        assert_eq!(
            gens.B_blinding, b_blinding,
            "B_blinding must not vary with token id"
        );

        // The construction, spelled out, from
        // crypto/ring-signature/src/ring_signature/mod.rs:85. MobileCoin's
        // HASH_TO_POINT_DOMAIN_TAG is not `pub`, so the tag is retyped here --
        // but the assert below is what makes that safe: a wrong tag cannot
        // reproduce `generators(id).B`.
        let mut buf: [u8; 32] = RISTRETTO_BASEPOINT_COMPRESSED.to_bytes();
        let id_bytes = id.to_le_bytes();
        for i in 0..8 {
            buf[i] ^= id_bytes[i];
        }
        let mut hasher = Blake2b512::new();
        hasher.update(HASH_TO_POINT_TAG);
        hasher.update(buf);
        let rederived = RistrettoPoint::from_hash(hasher);
        assert_eq!(
            rederived, gens.B,
            "spelled-out B_token construction disagrees with generators({id})"
        );

        by_token.push(json!({
            "tokenId": u64s(id),
            "preimage": hx(&buf),
            "bToken": hx(gens.B.compress().as_bytes()),
        }));
    }

    // Distinct token ids must give distinct, unrelated B points -- that
    // orthogonality is why a masked amount cannot be replayed under a
    // different token id.
    for i in 0..token_ids.len() {
        for j in (i + 1)..token_ids.len() {
            assert_ne!(
                generators(token_ids[i]).B,
                generators(token_ids[j]).B,
                "B_token collided across token ids"
            );
        }
    }

    json!({
        "hashToPointDomainTag": HASH_TO_POINT_TAG,
        "basepointCompressed": hx(&RISTRETTO_BASEPOINT_COMPRESSED.to_bytes()),
        "bBlinding": hx(b_blinding.compress().as_bytes()),
        "byTokenId": by_token,
    })
}

// ---------------------------------------------------------------------------
// Section 3: raw HKDF-SHA512 vectors, plus RFC 5869
// ---------------------------------------------------------------------------

/// HKDF-SHA512, the KDF both constructions use. `Some(salt)` rather than
/// `None` matches upstream exactly -- for an empty salt the two agree anyway
/// (HMAC zero-pads a short key to the block size), but the calls being pinned
/// all pass a real salt.
fn hkdf512(salt: &[u8], ikm: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let kdf = Hkdf::<Sha512>::new(Some(salt), ikm);
    let mut okm = vec![0u8; len];
    kdf.expand(info, &mut okm).expect("okm length");
    okm
}

/// HKDF-SHA256, used only to check this generator's HKDF against the published
/// RFC 5869 vectors.
fn hkdf256(salt: &[u8], ikm: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let kdf = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = vec![0u8; len];
    kdf.expand(info, &mut okm).expect("okm length");
    okm
}

fn hkdf_case(name: &str, hash: &str, salt: &[u8], ikm: &[u8], info: &[u8], okm: &[u8]) -> Value {
    json!({
        "name": name,
        "hash": hash,
        "salt": hx(salt),
        "ikm": hx(ikm),
        "info": hx(info),
        "length": okm.len(),
        "okm": hx(okm),
    })
}

/// RFC 5869 appendix A, test cases 1-3.
///
/// These pin the HKDF to the *published standard* rather than only to
/// MobileCoin's usage of it. RFC 5869's vectors are SHA-256 (and SHA-1); the
/// bridge needs SHA-512. So each case is emitted twice: once with the
/// published SHA-256 OKM, which this generator asserts its HKDF reproduces
/// before writing, and once with the SHA-512 OKM on the same published inputs.
/// The first proves the extract-then-expand construction is right; the second
/// gives the Solidity a value to hit for the hash it actually uses. A
/// SHA-512 HKDF that passes both is standards-conformant, not just
/// self-consistent.
fn rfc5869_section() -> Vec<Value> {
    // (name, ikm, salt, info, L, published SHA-256 okm)
    let cases: Vec<(&str, &str, &str, &str, usize, &str)> = vec![
        (
            "rfc5869-tc1",
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "000102030405060708090a0b0c",
            "f0f1f2f3f4f5f6f7f8f9",
            42,
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        ),
        (
            "rfc5869-tc2",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
             202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f\
             404142434445464748494a4b4c4d4e4f",
            "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f\
             808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f\
             a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
            "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf\
             d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef\
             f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
            82,
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c\
             59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71\
             cc30c58179ec3e87c14c01d5c1f3434f1d87",
        ),
        (
            // Empty salt and empty info: the degenerate path, where HKDF-Extract
            // has to fall back to a HashLen-zero key.
            "rfc5869-tc3",
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "",
            "",
            42,
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
        ),
    ];

    let mut out = Vec::new();
    for (name, ikm_h, salt_h, info_h, len, want_h) in cases {
        let strip = |s: &str| s.split_whitespace().collect::<String>();
        let ikm = hex::decode(strip(ikm_h)).unwrap();
        let salt = hex::decode(strip(salt_h)).unwrap();
        let info = hex::decode(strip(info_h)).unwrap();
        let want = hex::decode(strip(want_h)).unwrap();

        let got = hkdf256(&salt, &ikm, &info, len);
        assert_eq!(
            got, want,
            "{name}: HKDF-SHA256 does not reproduce the published RFC 5869 OKM"
        );
        out.push(hkdf_case(name, "SHA-256", &salt, &ikm, &info, &want));

        let got512 = hkdf512(&salt, &ikm, &info, len);
        out.push(hkdf_case(
            &format!("{name}-sha512"),
            "SHA-512",
            &salt,
            &ikm,
            &info,
            &got512,
        ));
    }
    out
}

// ---------------------------------------------------------------------------
// Sections 1, 2, 6: masked amounts
// ---------------------------------------------------------------------------

struct AmountCase {
    label: &'static str,
    value: u64,
    token_id: u64,
}

/// One masked-amount case, with every intermediate the Solidity walks through.
///
/// The masked amount itself comes from `MaskedAmountV2::new`. The
/// intermediates are recomputed here and each is checked against something the
/// MobileCoin API returned:
///
/// * `amount_shared_secret` -- against `compute_amount_shared_secret`;
/// * the masks -- by XOR-ing them back off `masked_value` / `masked_token_id`
///   and requiring the original value and token id;
/// * the wide blinding bytes -- by reducing them and requiring the scalar
///   `get_value` returned;
/// * the commitment -- by recomputing `value*B_token + blinding*B_blinding`
///   with raw dalek arithmetic and requiring the point in the masked amount.
///
/// The last one is the check the on-chain code must not skip, and it is
/// exercised here in the same shape the Solidity will use it.
fn amount_case(case: usize, c: &AmountCase, rng: &mut ChaCha20Rng) -> Value {
    // Build the shared secret the way a real output does: view private key `a`,
    // tx public key `R`, `S = a*R`. Emitting `a` and `R` lets the JS test chain
    // this fixture onto the recipient check in ristretto.json instead of
    // starting from a shared secret that fell out of the sky.
    let a = rand_scalar(rng);
    let view_private = RistrettoPrivate::from(a);
    let r = rand_scalar(rng);
    let tx_public = RistrettoPublic::from(RistrettoPoint::mul_base(&r));
    let shared_secret = get_tx_out_shared_secret(&view_private, &tx_public);

    let amount = Amount {
        value: c.value,
        token_id: TokenId::from(c.token_id),
    };
    let masked = MaskedAmountV2::new(amount, &shared_secret).expect("masked amount");

    // -- round trip through MobileCoin's own opener --------------------------
    let (opened, blinding) = masked
        .get_value(&shared_secret)
        .expect("MobileCoin failed to open the amount it just created");
    assert_eq!(opened, amount, "case {case}: round trip changed the amount");

    // -- amount shared secret ------------------------------------------------
    let ass = MaskedAmountV2::compute_amount_shared_secret(&shared_secret);

    // -- the three HKDF outputs ----------------------------------------------
    let value_mask_bytes = hkdf512(
        AMOUNT_BLINDING_FACTORS_TAG,
        &ass,
        AMOUNT_VALUE_TAG.as_bytes(),
        8,
    );
    let token_id_mask_bytes = hkdf512(
        AMOUNT_BLINDING_FACTORS_TAG,
        &ass,
        AMOUNT_TOKEN_ID_TAG.as_bytes(),
        8,
    );
    let blinding_wide = hkdf512(
        AMOUNT_BLINDING_FACTORS_TAG,
        &ass,
        AMOUNT_BLINDING_TAG.as_bytes(),
        64,
    );

    let value_mask = u64::from_le_bytes(value_mask_bytes[..].try_into().unwrap());
    let token_id_mask = u64::from_le_bytes(token_id_mask_bytes[..].try_into().unwrap());
    let blinding_rederived =
        Scalar::from_bytes_mod_order_wide(&blinding_wide[..].try_into().unwrap());

    // Each intermediate must reproduce what the API already told us.
    assert_eq!(
        masked.masked_value ^ value_mask,
        c.value,
        "case {case}: value mask does not open masked_value"
    );
    assert_eq!(masked.masked_token_id.len(), 8, "v2 masked token id is 8 bytes");
    let mti = u64::from_le_bytes(masked.masked_token_id[..].try_into().unwrap());
    assert_eq!(
        mti ^ token_id_mask,
        c.token_id,
        "case {case}: token id mask does not open masked_token_id"
    );
    assert_eq!(
        blinding_rederived, blinding,
        "case {case}: wide bytes do not reduce to the blinding get_value returned"
    );

    // -- the commitment relation, from raw curve arithmetic ------------------
    let gens = generators(c.token_id);
    let point = Scalar::from(c.value) * gens.B + blinding * gens.B_blinding;
    assert_eq!(
        CompressedCommitment::from(&point.compress()),
        masked.commitment,
        "case {case}: value*B_token + blinding*B_blinding is not the commitment"
    );

    json!({
        "case": case,
        "label": c.label,
        // inputs a caller may reproduce S from
        "viewPrivateKey": hx(view_private.to_bytes().as_slice()),
        "txPublicKey": hx(&tx_public.to_bytes()),
        // the shared secret S, compressed -- the single input to everything below
        "sharedSecret": hx(&shared_secret.to_bytes()),
        // intermediates, so a failure localises
        "amountSharedSecret": hx(&ass),
        "valueMaskBytes": hx(&value_mask_bytes),
        "valueMask": u64s(value_mask),
        "tokenIdMaskBytes": hx(&token_id_mask_bytes),
        "tokenIdMask": u64s(token_id_mask),
        "blindingWide": hx(&blinding_wide),
        "blinding": hx(blinding.as_bytes()),
        // the masked amount as it appears in the TxOut
        "maskedValue": u64s(masked.masked_value),
        "maskedValueBytes": hx(&masked.masked_value.to_le_bytes()),
        "maskedTokenId": hx(&masked.masked_token_id),
        "commitment": hx(masked.commitment.point.as_bytes()),
        // what it opens to
        "value": u64s(c.value),
        "tokenId": u64s(c.token_id),
    })
}

/// Section 6: cases that MUST be rejected, with the upstream error each one
/// produces.
///
/// Both are checked here by calling MobileCoin's own opener and asserting the
/// exact `AmountError`, so these are not guesses about what upstream would do.
fn amount_rejects(rng: &mut ChaCha20Rng) -> Vec<Value> {
    let mut out = Vec::new();

    // -- (a) a commitment that does not match its value and blinding ---------
    //
    // This is the attack the on-chain commitment check exists to stop: XOR-ing
    // the mask off `masked_value` yields a number bound to nothing, so a sender
    // can pair a LARGE masked value with a commitment to a small one. Here the
    // masked value is replaced with one that unmasks to `forged_value` while
    // the commitment is left committing to `true_value`. Upstream answers
    // InconsistentCommitment; a verifier that skipped the check would pay out
    // `forged_value`.
    {
        let a = rand_scalar(rng);
        let view_private = RistrettoPrivate::from(a);
        let tx_public = RistrettoPublic::from(RistrettoPoint::mul_base(&rand_scalar(rng)));
        let shared_secret = get_tx_out_shared_secret(&view_private, &tx_public);

        let true_value: u64 = 1_000_000;
        let forged_value: u64 = 500_000_000_000;
        let amount = Amount {
            value: true_value,
            token_id: TokenId::from(EUSD_TOKEN_ID),
        };
        let honest = MaskedAmountV2::new(amount, &shared_secret).unwrap();

        let ass = MaskedAmountV2::compute_amount_shared_secret(&shared_secret);
        let value_mask = u64::from_le_bytes(
            hkdf512(
                AMOUNT_BLINDING_FACTORS_TAG,
                &ass,
                AMOUNT_VALUE_TAG.as_bytes(),
                8,
            )[..]
                .try_into()
                .unwrap(),
        );

        let mut forged = honest.clone();
        forged.masked_value = forged_value ^ value_mask;
        assert_ne!(
            forged.masked_value, honest.masked_value,
            "forged case must actually differ"
        );

        // The mask-only step "succeeds" and hands back the attacker's number...
        assert_eq!(forged.masked_value ^ value_mask, forged_value);
        // ...and the commitment check is what refuses it.
        assert_eq!(
            forged.get_value(&shared_secret),
            Err(AmountError::InconsistentCommitment),
            "upstream did not reject a commitment/value mismatch"
        );

        out.push(json!({
            "name": "commitment-does-not-open-to-masked-value",
            "why": "masked_value unmasks to forgedValue but the commitment commits to trueValue; \
                    without the commitment check the verifier pays out forgedValue",
            "sharedSecret": hx(&shared_secret.to_bytes()),
            "amountSharedSecret": hx(&ass),
            "maskedValue": u64s(forged.masked_value),
            "maskedTokenId": hx(&forged.masked_token_id),
            "commitment": hx(forged.commitment.point.as_bytes()),
            "unmasksToValue": u64s(forged_value),
            "commitmentCommitsToValue": u64s(true_value),
            "tokenId": u64s(EUSD_TOKEN_ID),
            "expectedError": "InconsistentCommitment",
        }));
    }

    // -- (b) masked_token_id that is not exactly 8 bytes ---------------------
    //
    // v2 has no legacy short form: any length other than 8 is malformed, and
    // upstream returns InvalidMaskedTokenId rather than zero-extending. A
    // verifier that padded instead would let a caller choose the token id.
    {
        let a = rand_scalar(rng);
        let view_private = RistrettoPrivate::from(a);
        let tx_public = RistrettoPublic::from(RistrettoPoint::mul_base(&rand_scalar(rng)));
        let shared_secret = get_tx_out_shared_secret(&view_private, &tx_public);
        let amount = Amount {
            value: 7,
            token_id: TokenId::from(EUSD_TOKEN_ID),
        };
        let honest = MaskedAmountV2::new(amount, &shared_secret).unwrap();

        for bad_len in [0usize, 4, 7, 9] {
            let mut bad = honest.clone();
            bad.masked_token_id = honest
                .masked_token_id
                .iter()
                .cloned()
                .cycle()
                .take(bad_len)
                .collect();
            assert_eq!(bad.masked_token_id.len(), bad_len);
            assert_eq!(
                bad.get_value(&shared_secret),
                Err(AmountError::InvalidMaskedTokenId),
                "upstream accepted a {bad_len}-byte masked_token_id"
            );

            out.push(json!({
                "name": format!("masked-token-id-length-{bad_len}"),
                "why": "MaskedAmountV2 requires exactly 8 bytes; anything else is malformed",
                "sharedSecret": hx(&shared_secret.to_bytes()),
                "maskedValue": u64s(bad.masked_value),
                "maskedTokenId": hx(&bad.masked_token_id),
                "maskedTokenIdLength": bad_len,
                "commitment": hx(bad.commitment.point.as_bytes()),
                "expectedError": "InvalidMaskedTokenId",
            }));
        }
    }

    // -- (c) a well-formed amount in the WRONG token ------------------------
    //
    // Not an upstream error at all: this opens cleanly. It is a reject for the
    // BRIDGE, whose verifier pins B_token for eusdTokenId and must require the
    // derived token id to equal it. Included so the Solidity has a case that
    // upstream accepts and the contract must still refuse.
    {
        let a = rand_scalar(rng);
        let view_private = RistrettoPrivate::from(a);
        let tx_public = RistrettoPublic::from(RistrettoPoint::mul_base(&rand_scalar(rng)));
        let shared_secret = get_tx_out_shared_secret(&view_private, &tx_public);
        let wrong_token = 1u64;
        assert_ne!(wrong_token, EUSD_TOKEN_ID);
        let amount = Amount {
            value: 123_456,
            token_id: TokenId::from(wrong_token),
        };
        let masked = MaskedAmountV2::new(amount, &shared_secret).unwrap();
        // Upstream is happy with it.
        assert!(masked.get_value(&shared_secret).is_ok());

        out.push(json!({
            "name": "well-formed-but-wrong-token-id",
            "why": "opens cleanly under MobileCoin; the bridge verifier must still reject it \
                    because the token id is not eusdTokenId",
            "sharedSecret": hx(&shared_secret.to_bytes()),
            "maskedValue": u64s(masked.masked_value),
            "maskedTokenId": hx(&masked.masked_token_id),
            "commitment": hx(masked.commitment.point.as_bytes()),
            "opensToTokenId": u64s(wrong_token),
            "opensToValue": u64s(123_456),
            "expectedError": null,
        }));
    }

    out
}

// ---------------------------------------------------------------------------
// Section 5: memos
// ---------------------------------------------------------------------------

/// Raw counter-mode vectors that isolate ONE thing: which bytes of the nonce
/// are the counter.
///
/// MobileCoin uses `Ctr64BE<Aes256>` (transaction/core/src/memo.rs:37). Only
/// bytes 8..16 of the 16-byte nonce increment, big-endian, and they wrap
/// without carrying into bytes 0..8. The obvious implementation -- and what
/// OpenSSL's `aes-256-ctr`, Node's `createCipheriv` and most Solidity AES ports
/// do -- is Ctr128BE, which treats the whole block as one counter.
///
/// The two agree on every real memo, because a memo is five blocks and a wrap
/// needs the OKM's low 64 bits to land within 4 of `u64::MAX`. That is the
/// problem: a Ctr128BE verifier would pass every test built from real memos and
/// still be wrong, with a failure that cannot be found by sampling. So these
/// vectors set the nonce by hand rather than deriving it, and one of them
/// straddles the wrap. `wrapsCounter` marks the case where the two modes must
/// disagree; the generator asserts that they do, so this cannot rot into a
/// vector that proves nothing.
fn memo_cipher_section() -> Value {
    let key: [u8; 32] = *b"amount-fixtures aes ctr key 0001";

    let nonces: [([u8; 16], bool); 3] = [
        // Ordinary: low half far from the wrap.
        (
            hex::decode("000102030405060708090a0b0c0d0e0f")
                .unwrap()
                .try_into()
                .unwrap(),
            false,
        ),
        // Low half is all ones except the last two: blocks 3 and 4 wrap the
        // 64-bit counter back to zero, and Ctr128BE would carry into byte 7.
        (
            hex::decode("a1a2a3a4a5a6a7a8fffffffffffffffd")
                .unwrap()
                .try_into()
                .unwrap(),
            true,
        ),
        // Low half exactly at the wrap boundary.
        (
            hex::decode("00000000000000ffffffffffffffffff")
                .unwrap()
                .try_into()
                .unwrap(),
            true,
        ),
    ];

    let mut cases = Vec::new();
    for (nonce, wraps) in nonces {
        // 80 bytes = 5 full blocks, so every block's counter is observable.
        let mut ks64 = [0u8; 80];
        Ctr64BE::<Aes256>::new(&key.into(), &nonce.into()).apply_keystream(&mut ks64);

        // The same thing under Ctr128BE, computed only so the generator can
        // assert the wrap cases genuinely separate the two. Not published as a
        // target -- it is the WRONG answer.
        let mut ks128 = [0u8; 80];
        ctr::Ctr128BE::<Aes256>::new(&key.into(), &nonce.into()).apply_keystream(&mut ks128);

        if wraps {
            assert_ne!(
                ks64, ks128,
                "case marked wrapsCounter does not actually distinguish Ctr64BE from Ctr128BE"
            );
        } else {
            assert_eq!(
                ks64, ks128,
                "non-wrapping case unexpectedly distinguishes the two counter widths"
            );
        }

        // The five AES input blocks, spelled out.
        let ctr0 = u64::from_be_bytes(nonce[8..16].try_into().unwrap());
        let blocks: Vec<String> = (0..5u64)
            .map(|i| {
                let mut b = nonce;
                b[8..16].copy_from_slice(&ctr0.wrapping_add(i).to_be_bytes());
                hx(&b)
            })
            .collect();

        cases.push(json!({
            "nonce": hx(&nonce),
            "wrapsCounter": wraps,
            "counterBlocks": blocks,
            "keystream": hx(&ks64),
        }));
    }

    json!({
        "mode": "Ctr64BE<Aes256>",
        "note": "bytes 8..16 of the nonce are a big-endian counter; bytes 0..8 are fixed \
                 and take no carry. A Ctr128BE implementation passes the non-wrapping case \
                 and fails the two marked wrapsCounter.",
        "key": hx(&key),
        "cases": cases,
    })
}

/// One memo case: `S`, the 66-byte plaintext, the 66-byte ciphertext, and the
/// 48-byte OKM it is keyed by.
///
/// The ciphertext comes from `MemoPayload::encrypt`. The OKM, key, nonce,
/// counter blocks and keystream are recomputed and asserted to reproduce that
/// ciphertext -- so publishing them is publishing the real decomposition.
///
/// The counter blocks matter and are easy to get wrong: MobileCoin uses
/// `Ctr64BE<Aes256>`, so only the LOW 8 bytes of the 16-byte nonce are the
/// counter and they increment big-endian. 66 bytes is five blocks, and the
/// fifth is truncated to 2 bytes.
fn memo_case(name: &str, memo_type: [u8; 2], memo_data: [u8; 64], rng: &mut ChaCha20Rng) -> Value {
    let view_private = RistrettoPrivate::from(rand_scalar(rng));
    let tx_public = RistrettoPublic::from(RistrettoPoint::mul_base(&rand_scalar(rng)));
    let shared_secret = get_tx_out_shared_secret(&view_private, &tx_public);

    let plaintext = MemoPayload::new(memo_type, memo_data);
    let plaintext_bytes: [u8; 66] = AsRef::<[u8]>::as_ref(&plaintext).try_into().unwrap();

    let encrypted = plaintext.encrypt(&shared_secret);
    let ciphertext_bytes: [u8; 66] = AsRef::<[u8]>::as_ref(&encrypted).try_into().unwrap();

    // Round trip through MobileCoin's own decryptor before anything is written.
    let back = MemoPayload::decrypt_from(&encrypted, &shared_secret);
    assert_eq!(
        AsRef::<[u8]>::as_ref(&back),
        &plaintext_bytes[..],
        "{name}: memo did not round trip"
    );
    assert_eq!(back.get_memo_type(), &memo_type);
    assert_eq!(back.get_memo_data(), &memo_data);

    // -- the decomposition, asserted rather than asserted-to-be-true ---------
    let okm = hkdf512(MEMO_OKM_SALT, &shared_secret.to_bytes(), b"", 48);
    let aes_key: [u8; 32] = okm[0..32].try_into().unwrap();
    let aes_nonce: [u8; 16] = okm[32..48].try_into().unwrap();

    let mut buf = plaintext_bytes;
    let mut cipher = Ctr64BE::<Aes256>::new(&aes_key.into(), &aes_nonce.into());
    cipher.apply_keystream(&mut buf);
    assert_eq!(
        buf, ciphertext_bytes,
        "{name}: recomputed AES-CTR does not reproduce MemoPayload::encrypt"
    );

    // Keystream, as ciphertext XOR plaintext -- and independently as AES-CTR
    // over zeros, so the published keystream is the cipher's, not a subtraction.
    let mut keystream = [0u8; 66];
    let mut cipher = Ctr64BE::<Aes256>::new(&aes_key.into(), &aes_nonce.into());
    cipher.apply_keystream(&mut keystream);
    for i in 0..66 {
        assert_eq!(
            keystream[i],
            plaintext_bytes[i] ^ ciphertext_bytes[i],
            "{name}: keystream byte {i} disagrees"
        );
    }

    // The five AES input blocks. `Ctr64BE` treats bytes 8..16 of the nonce as a
    // big-endian counter and leaves bytes 0..8 fixed.
    let mut counter_blocks = Vec::new();
    let ctr0 = u64::from_be_bytes(aes_nonce[8..16].try_into().unwrap());
    for blk in 0..5u64 {
        let mut b = aes_nonce;
        b[8..16].copy_from_slice(&ctr0.wrapping_add(blk).to_be_bytes());
        counter_blocks.push(hx(&b));
    }

    let mut obj = BTreeMap::new();
    obj.insert("name".to_string(), json!(name));
    obj.insert(
        "viewPrivateKey".to_string(),
        json!(hx(view_private.to_bytes().as_slice())),
    );
    obj.insert("txPublicKey".to_string(), json!(hx(&tx_public.to_bytes())));
    obj.insert(
        "sharedSecret".to_string(),
        json!(hx(&shared_secret.to_bytes())),
    );
    obj.insert("okm".to_string(), json!(hx(&okm)));
    obj.insert("aesKey".to_string(), json!(hx(&aes_key)));
    obj.insert("aesNonce".to_string(), json!(hx(&aes_nonce)));
    obj.insert("counterBlocks".to_string(), json!(counter_blocks));
    obj.insert("keystream".to_string(), json!(hx(&keystream)));
    obj.insert("plaintext".to_string(), json!(hx(&plaintext_bytes)));
    obj.insert("ciphertext".to_string(), json!(hx(&ciphertext_bytes)));
    obj.insert("memoType".to_string(), json!(hx(&memo_type)));
    obj.insert("memoData".to_string(), json!(hx(&memo_data)));
    obj.insert(
        "beneficiary".to_string(),
        json!(hx(&memo_data[0..20])),
    );
    Value::Object(obj.into_iter().collect())
}

// ---------------------------------------------------------------------------

fn main() {
    check_domain_separators();

    let mut rng = ChaCha20Rng::seed_from_u64(0xA0170D);

    let token_ids = [0u64, 1, EUSD_TOKEN_ID, u64::MAX];

    let cases = [
        AmountCase {
            label: "token id 0 (MOB), value 0",
            value: 0,
            token_id: 0,
        },
        AmountCase {
            label: "token id 0 (MOB), value 1",
            value: 1,
            token_id: 0,
        },
        AmountCase {
            label: "eUSD, value 0",
            value: 0,
            token_id: EUSD_TOKEN_ID,
        },
        AmountCase {
            label: "eUSD, value 1",
            value: 1,
            token_id: EUSD_TOKEN_ID,
        },
        AmountCase {
            label: "eUSD, 250000.000000 in 1e-6 base units",
            value: 250_000_000_000,
            token_id: EUSD_TOKEN_ID,
        },
        AmountCase {
            label: "eUSD, u64::MAX -- the largest value expressible",
            value: u64::MAX,
            token_id: EUSD_TOKEN_ID,
        },
        AmountCase {
            label: "token id 1, mid-range value",
            value: 0x0123_4567_89ab_cdef,
            token_id: 1,
        },
        AmountCase {
            label: "token id u64::MAX -- every byte of the id XORed into B",
            value: 4_294_967_296,
            token_id: u64::MAX,
        },
    ];

    let masked_amounts: Vec<Value> = cases
        .iter()
        .enumerate()
        .map(|(i, c)| amount_case(i, c, &mut rng))
        .collect();

    // -- HKDF: the exact calls the constructions make, on a real case --------
    //
    // Taken from case 3 (eUSD, value 1) so the vectors are not free-floating:
    // a JS test can run these four and then walk straight into
    // maskedAmounts[3] / memos[0].
    let sample_ass = hex::decode(
        masked_amounts[3]["amountSharedSecret"]
            .as_str()
            .unwrap()
            .trim_start_matches("0x"),
    )
    .unwrap();
    let mut hkdf_vectors = vec![
        hkdf_case(
            "mc-amount-value-mask",
            "SHA-512",
            AMOUNT_BLINDING_FACTORS_TAG,
            &sample_ass,
            AMOUNT_VALUE_TAG.as_bytes(),
            &hkdf512(
                AMOUNT_BLINDING_FACTORS_TAG,
                &sample_ass,
                AMOUNT_VALUE_TAG.as_bytes(),
                8,
            ),
        ),
        hkdf_case(
            "mc-amount-token-id-mask",
            "SHA-512",
            AMOUNT_BLINDING_FACTORS_TAG,
            &sample_ass,
            AMOUNT_TOKEN_ID_TAG.as_bytes(),
            &hkdf512(
                AMOUNT_BLINDING_FACTORS_TAG,
                &sample_ass,
                AMOUNT_TOKEN_ID_TAG.as_bytes(),
                8,
            ),
        ),
        hkdf_case(
            "mc-amount-blinding",
            "SHA-512",
            AMOUNT_BLINDING_FACTORS_TAG,
            &sample_ass,
            AMOUNT_BLINDING_TAG.as_bytes(),
            &hkdf512(
                AMOUNT_BLINDING_FACTORS_TAG,
                &sample_ass,
                AMOUNT_BLINDING_TAG.as_bytes(),
                64,
            ),
        ),
    ];

    // -- memos ---------------------------------------------------------------
    let mut memo_data_bridge = [0u8; 64];
    // A real Ethereum address, in the position disclosure.rs reads it from.
    memo_data_bridge[0..20].copy_from_slice(
        &hex::decode("d8da6bf26964af9d7eed9e03e53415d37aa96045").unwrap(),
    );
    let mut memo_data_zero = [0u8; 64];
    memo_data_zero[0..20].copy_from_slice(&[0u8; 20]);
    let mut memo_data_ff = [0xffu8; 64];
    memo_data_ff[20..].copy_from_slice(&[0x5au8; 44]);

    let memos = vec![
        memo_case(
            "bridge-return-real-address",
            BRIDGE_RETURN_MEMO_TYPE,
            memo_data_bridge,
            &mut rng,
        ),
        memo_case(
            "bridge-return-zero-address",
            BRIDGE_RETURN_MEMO_TYPE,
            memo_data_zero,
            &mut rng,
        ),
        memo_case(
            "bridge-return-all-ones-beneficiary",
            BRIDGE_RETURN_MEMO_TYPE,
            memo_data_ff,
            &mut rng,
        ),
        // Wrong memo type: decrypts fine, and the verifier must refuse it
        // anyway. The 20 bytes that would be read as a beneficiary are a
        // plausible-looking address, so a contract that forgot the type check
        // would pay them.
        memo_case("wrong-memo-type-0x0100", [0x01, 0x00], memo_data_bridge, &mut rng),
    ];

    // The memo OKM derivation, as a raw HKDF vector keyed on memos[0]'s S.
    {
        let s = hex::decode(
            memos[0]["sharedSecret"]
                .as_str()
                .unwrap()
                .trim_start_matches("0x"),
        )
        .unwrap();
        hkdf_vectors.push(hkdf_case(
            "mc-memo-okm",
            "SHA-512",
            MEMO_OKM_SALT,
            &s,
            b"",
            &hkdf512(MEMO_OKM_SALT, &s, b"", 48),
        ));
    }
    hkdf_vectors.extend(rfc5869_section());

    let out = json!({
        "note": "Generated by tools/amount-fixtures from MobileCoin's own crates \
                 (MaskedAmountV2, generators, MemoPayload) and curve25519-dalek. \
                 Do not hand-edit. Regenerate: cd tools/amount-fixtures && cargo run --offline",
        "eusdTokenId": u64s(EUSD_TOKEN_ID),
        "bridgeReturnMemoType": hx(&BRIDGE_RETURN_MEMO_TYPE),
        "domainSeparators": {
            "amountSharedSecret": AMOUNT_SHARED_SECRET_TAG,
            "amountBlindingFactorsSalt": String::from_utf8(AMOUNT_BLINDING_FACTORS_TAG.to_vec()).unwrap(),
            "amountValueInfo": AMOUNT_VALUE_TAG,
            "amountTokenIdInfo": AMOUNT_TOKEN_ID_TAG,
            "amountBlindingInfo": AMOUNT_BLINDING_TAG,
            "memoOkmSalt": String::from_utf8(MEMO_OKM_SALT.to_vec()).unwrap(),
        },
        "generators": generator_section(&token_ids),
        "hkdf": hkdf_vectors,
        "maskedAmounts": masked_amounts,
        "maskedAmountRejects": amount_rejects(&mut rng),
        "memoCipher": memo_cipher_section(),
        "memos": memos,
    });

    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../contracts/test/fixtures/amount.json");
    std::fs::write(&path, serde_json::to_string_pretty(&out).unwrap() + "\n")
        .expect("write amount.json");
    eprintln!("wrote {}", path.display());
}
