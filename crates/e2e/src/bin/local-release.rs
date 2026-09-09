//! Local-only signing integration. Deterministic test shares and a simulated
//! independent anchor; never a production signer or a MobileCoin submission.
use ceremony::store::{DurableNonceGuard, FileStore, MemoryAnchor};
use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT, scalar::Scalar};
use mc_crypto_hashes::{Blake2b256, Digest};
use mc_crypto_keys::{RistrettoPrivate, RistrettoPublic};
use mc_crypto_ring_signature::{generators, Commitment, CompressedCommitment, ReducedTxOut};
use mc_crypto_ring_signature_signer::{InputSecret, OneTimeKeyDeriveData, SignableInputRing};
use mc_transaction_core::{
    encrypted_fog_hint::EncryptedFogHint,
    onetime_keys::create_shared_secret,
    ring_ct::{InputRing, OutputSecret, SignatureRctBulletproofs, SigningData},
    tx::{TxIn, TxOut, TxPrefix},
    Amount, BlockVersion, MaskedAmount, MemoPayload, PublicAddress,
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde::Deserialize;
use std::{
    io::{self, Read},
    path::PathBuf,
};
use two_cohort::{
    identity::IdentityKey,
    mlsag::{
        self,
        wire::{self, Message},
        MaskSigner, Seat, Session, SessionParams,
    },
    CohortSpec, CompositeSpend, ControlDomain, Gates, Owners,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    chain_id: String,
    escrow: String,
    topics: Vec<String>,
    data: String,
    return_output_digest: String,
    token_id: String,
}
fn bytes<const N: usize>(s: &str) -> Result<[u8; N], String> {
    hex::decode(s.strip_prefix("0x").ok_or("hex prefix")?)
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|_| format!("expected {N} bytes"))
}
fn run() -> Result<(), String> {
    let dir = PathBuf::from(
        std::env::args()
            .nth(1)
            .ok_or("journal directory required")?,
    );
    let mut input = String::new();
    io::stdin()
        .take(16385)
        .read_to_string(&mut input)
        .map_err(|e| e.to_string())?;
    if input.len() > 16384 {
        return Err("oversized request".into());
    }
    let r: Request = serde_json::from_str(&input).map_err(|e| e.to_string())?;
    if r.topics.len() != 4
        || r.topics[0] != "0x7b3f420dafb58e077d56c4160850ae727d598bf03fd39b4e4113e31d43e1fe37"
    {
        return Err("not a Deposited event".into());
    }
    let amount = bytes::<32>(&r.data)?;
    if amount[..24] != [0; 24] {
        return Err("amount exceeds MobileCoin u64".into());
    }
    let value = u64::from_be_bytes(amount[24..].try_into().unwrap());
    if value == 0 {
        return Err("zero release".into());
    }
    let chain_id = bytes::<32>(&r.chain_id)?;
    let escrow = bytes::<20>(&r.escrow)?;
    let deposit_id = bytes::<32>(&r.topics[1])?;
    let sender = bytes::<32>(&r.topics[2])?;
    if sender[..12] != [0; 12] || sender[12..] == [0; 20] {
        return Err("invalid sender".into());
    }
    let destination = bytes::<32>(&r.topics[3])?;
    RistrettoPublic::try_from(&destination[..]).map_err(|_| "invalid destination point")?;
    let output = bytes::<32>(&r.return_output_digest)?;
    let token: u64 = r.token_id.parse().map_err(|_| "invalid token")?;
    if token != 1 {
        return Err("local scenario requires token 1".into());
    }
    // All signing inputs come from the decoded event plus the explicit return
    // association. Its digest is also authenticated inside the release output memo.
    let mut message = b"bridge-local-release-intent-v1".to_vec();
    for b in [
        &chain_id[..],
        &escrow,
        &deposit_id,
        &sender,
        &destination,
        &amount,
        &output,
        &token.to_le_bytes(),
    ] {
        message.extend(b);
    }
    let session_id: [u8; 32] = Blake2b256::digest(&message).into();
    let spend = CompositeSpend::simulate_from_seed(
        42,
        &CohortSpec::<Owners>::sequential(2, 3),
        &CohortSpec::<Gates>::sequential(1, 1),
        7,
    )
    .map_err(|e| e.to_string())?;
    let gens = generators(token);
    let mut rng = ChaCha20Rng::seed_from_u64(99);
    let version = BlockVersion::MAX;
    let fee = Amount::new(1, token.into());
    let input_amount = Amount::new(
        value
            .checked_add(fee.value)
            .ok_or("release plus fee overflow")?,
        token.into(),
    );
    let input_shared = RistrettoPublic::from(RISTRETTO_BASEPOINT_POINT * Scalar::from(12u64));
    let input_masked =
        MaskedAmount::new(version, input_amount, &input_shared).map_err(|e| e.to_string())?;
    let (_, blinding) = input_masked
        .get_value(&input_shared)
        .map_err(|e| e.to_string())?;
    // The event supplies a spend key only. This local scenario uses an explicit
    // test view key; production needs an authenticated full address registry.
    let destination_key = RistrettoPublic::try_from(&destination[..]).unwrap();
    let view = RistrettoPublic::from(destination_key.as_ref() * Scalar::from(11u64));
    let recipient = PublicAddress::new(&destination_key, &view);
    let tx_private = RistrettoPrivate::from(Scalar::from(13u64));
    let shared = create_shared_secret(&view, &tx_private);
    let mut memo = [0u8; 64];
    memo[..32].copy_from_slice(&session_id);
    let release = TxOut::new_with_memo(
        version,
        Amount::new(value, token.into()),
        &recipient,
        &tx_private,
        EncryptedFogHint::fake_onetime_hint(&mut rng),
        |_| Ok(MemoPayload::new([0x80, 0x03], memo)),
    )
    .map_err(|e| e.to_string())?;
    let receiver_shared = create_shared_secret(
        &RistrettoPublic::try_from(&release.public_key).map_err(|e| e.to_string())?,
        &RistrettoPrivate::from(Scalar::from(11u64)),
    );
    if receiver_shared != shared {
        return Err("receiver shared secret mismatch".into());
    }
    if release.decrypt_memo(&receiver_shared) != MemoPayload::new([0x80, 0x03], memo) {
        return Err("receiver release-intent memo mismatch".into());
    }
    let (opened, output_blinding) = release
        .get_masked_amount()
        .map_err(|e| e.to_string())?
        .get_value(&shared)
        .map_err(|e| e.to_string())?;
    if opened != Amount::new(value, token.into()) {
        return Err("release opening mismatch".into());
    }
    let ring: Vec<_> = (0..11)
        .map(|i| ReducedTxOut {
            public_key: spend.tx_public().into(),
            target_key: if i == 5 {
                spend.target().into()
            } else {
                RistrettoPublic::from(RISTRETTO_BASEPOINT_POINT * Scalar::from(i as u64 + 50))
                    .into()
            },
            commitment: CompressedCommitment::from(&Commitment::new(
                input_amount.value,
                blinding,
                &gens,
            )),
        })
        .collect();
    // Synthetic funding ring: no live membership proof or ledger admission is
    // claimed. All prefix outputs, range proofs and fee commitments are real.
    let inputs = ring
        .iter()
        .map(|member| TxOut {
            masked_amount: Some(input_masked.clone()),
            target_key: member.target_key,
            public_key: member.public_key,
            e_fog_hint: EncryptedFogHint::fake_onetime_hint(&mut rng),
            e_memo: None,
        })
        .collect();
    let prefix = TxPrefix::new(
        vec![TxIn {
            ring: inputs,
            proofs: vec![],
            input_rules: None,
        }],
        vec![release],
        fee,
        100,
    );
    let signable = InputRing::Signable(SignableInputRing {
        members: ring.clone(),
        real_input_index: 5,
        input_secret: InputSecret {
            onetime_key_derive_data: OneTimeKeyDeriveData::SubaddressIndex(7),
            amount: input_amount,
            blinding,
        },
    });
    let signing = SigningData::new(
        version,
        &prefix,
        &[signable],
        &[OutputSecret {
            amount: opened,
            blinding: output_blinding,
        }],
        fee,
        true,
        &mut rng,
    )
    .map_err(|e| format!("RCT preparation: {e:?}"))?;
    let message = signing.mlsag_signing_digest.clone();
    let out_blinding = signing.pseudo_output_blindings[0];
    let out_commitment = signing.pseudo_output_commitments[0];
    let params = SessionParams {
        session_id: &session_id,
        message: &message,
        ring: &ring,
        real_index: 5,
        output_commitment: &out_commitment,
    };
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    // A second invocation cannot silently reset a prior signing attempt.
    let mut store = FileStore::create(dir.join("nonces.journal")).map_err(|e| e.to_string())?;
    let mut anchor = MemoryAnchor::default();
    let mut guard = DurableNonceGuard::new(&mut store, &mut anchor).map_err(|e| e.to_string())?;
    let seats = mlsag::quorum_signers(&spend, &[Owners::nth(0), Owners::nth(1)], &[Gates::nth(0)])
        .map_err(|e| e.to_string())?;
    let mut nonces = Vec::new();
    let mut armed = Vec::new();
    let mut keys = Vec::new();
    for (i, signer) in seats.into_iter().enumerate() {
        let key = IdentityKey::from_seed(&[i as u8 + 1; 32]);
        let (nonce, a) = signer
            .commit(&params, &mut guard)
            .map_err(|e| e.to_string())?;
        let packet = wire::encode(
            &key,
            *params.binding().as_bytes(),
            &Message::SpendCommitment(nonce.clone()),
        );
        let Message::SpendCommitment(n) = wire::decode(
            &packet,
            &key.public(),
            *params.binding().as_bytes(),
            Seat::Spend(nonce.role),
            1,
        )
        .map_err(|e| e.to_string())?
        else {
            return Err("wrong packet".into());
        };
        nonces.push(n);
        armed.push(a);
        keys.push(key);
    }
    let key = IdentityKey::from_seed(&[90; 32]);
    let (mask, armed_mask) = MaskSigner::owner_held(&out_blinding, &blinding)
        .commit(&params, &mut guard)
        .map_err(|e| e.to_string())?;
    let packet = wire::encode(
        &key,
        *params.binding().as_bytes(),
        &Message::MaskCommitment(mask),
    );
    let Message::MaskCommitment(mask) = wire::decode(
        &packet,
        &key.public(),
        *params.binding().as_bytes(),
        Seat::Mask,
        1,
    )
    .map_err(|e| e.to_string())?
    else {
        return Err("wrong packet".into());
    };
    let session = Session::open(params, &mut rng).map_err(|e| e.to_string())?;
    session.preflight(&nonces).map_err(|e| e.to_string())?;
    let session = session
        .round_one(&nonces, &mask)
        .map_err(|e| e.to_string())?;
    let transcript = session.round_one_transcript().clone();
    let context = transcript.context_id(&params);
    let mut responses = Vec::new();
    for (a, key) in armed.into_iter().zip(keys) {
        let response = a.respond(&params, &transcript).map_err(|e| e.to_string())?;
        let packet = wire::encode(&key, context, &Message::SpendResponse(response));
        let Message::SpendResponse(response) = wire::decode(
            &packet,
            &key.public(),
            context,
            Seat::Spend(response.role),
            2,
        )
        .map_err(|e| e.to_string())?
        else {
            return Err("wrong packet".into());
        };
        responses.push(response);
    }
    let response = armed_mask
        .respond(&params, &transcript)
        .map_err(|e| e.to_string())?;
    let packet = wire::encode(&key, context, &Message::MaskResponse(response));
    let Message::MaskResponse(response) =
        wire::decode(&packet, &key.public(), context, Seat::Mask, 2).map_err(|e| e.to_string())?
    else {
        return Err("wrong packet".into());
    };
    let signature = session
        .finish(&responses, &response)
        .map_err(|e| e.to_string())?;
    signature
        .verify(&message, &ring, &out_commitment)
        .map_err(|e| format!("stock verifier: {e:?}"))?;
    let mut altered = message.clone();
    *altered.last_mut().unwrap() ^= 1;
    if signature.verify(&altered, &ring, &out_commitment).is_ok() {
        return Err("altered intent verified".into());
    }
    let rct = SignatureRctBulletproofs {
        ring_signatures: vec![signature],
        pseudo_output_commitments: signing.pseudo_output_commitments,
        range_proof_bytes: signing.range_proof_bytes,
        range_proofs: signing.range_proofs,
        pseudo_output_token_ids: signing.pseudo_output_token_ids,
        output_token_ids: signing.output_token_ids,
    };
    let signed_rings = prefix.get_input_rings().map_err(|e| e.to_string())?;
    let commitments: Vec<_> = prefix
        .output_commitments()
        .map_err(|e| e.to_string())?
        .into_iter()
        .copied()
        .collect();
    rct.verify(version, &prefix, &signed_rings, &commitments, fee, &mut rng)
        .map_err(|e| format!("stock RCT verifier: {e:?}"))?;
    // Exercise each independently authenticated component with the original
    // signature, rebuilding prefix-derived verifier inputs after mutation.
    for case in 0..6 {
        let mut bad_prefix = prefix.clone();
        let mut bad_rct = rct.clone();
        let mut bad_fee = fee;
        match case {
            0 => {
                bad_prefix.fee += 1;
                bad_fee.value += 1;
            }
            1 => bad_prefix.tombstone_block += 1,
            2 => bad_prefix.outputs[0].target_key = ring[0].target_key,
            3 => bad_rct.range_proofs[0][0] ^= 1,
            4 => bad_rct.output_token_ids[0] += 1,
            5 => bad_prefix.outputs[0].e_memo = None,
            _ => unreachable!(),
        }
        let bad_commitments: Vec<_> = bad_prefix
            .output_commitments()
            .map_err(|e| e.to_string())?
            .into_iter()
            .copied()
            .collect();
        let bad_rings = bad_prefix.get_input_rings().map_err(|e| e.to_string())?;
        if bad_rct
            .verify(
                version,
                &bad_prefix,
                &bad_rings,
                &bad_commitments,
                bad_fee,
                &mut rng,
            )
            .is_ok()
        {
            return Err(format!("RCT mutation {case} verified"));
        }
    }
    println!(
        "{}",
        serde_json::json!({"amount": value.to_string(), "destination": r.topics[3],
        "deposit_id": r.topics[1], "return_output_digest": r.return_output_digest,
        "session_id": hex::encode(session_id), "stock_mlsag_verified": true,
        "authenticated_packets": 10, "stock_rct_verified": true, "rct_mutations_rejected": 6,
        "scope": "local transaction RCT signature; synthetic funding ring, test view key, no ledger submission"})
    );
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
