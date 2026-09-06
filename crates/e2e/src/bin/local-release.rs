//! Local-only signing integration. Deterministic test shares and a simulated
//! independent anchor; never a production signer or a MobileCoin submission.
use ceremony::store::{DurableNonceGuard, FileStore, MemoryAnchor};
use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT, scalar::Scalar};
use mc_crypto_hashes::{Blake2b256, Digest};
use mc_crypto_keys::RistrettoPublic;
use mc_crypto_ring_signature::{generators, Commitment, CompressedCommitment, ReducedTxOut};
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
    // association. Signing this intent does not validate a full TxPrefix/RCT.
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
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    // A second invocation cannot silently reset a prior signing attempt.
    let mut store = FileStore::create(dir.join("nonces.journal")).map_err(|e| e.to_string())?;
    let mut anchor = MemoryAnchor::default();
    let mut guard = DurableNonceGuard::new(&mut store, &mut anchor).map_err(|e| e.to_string())?;
    let spend = CompositeSpend::simulate_from_seed(
        42,
        &CohortSpec::<Owners>::sequential(2, 3),
        &CohortSpec::<Gates>::sequential(1, 1),
        7,
    )
    .map_err(|e| e.to_string())?;
    let gens = generators(token);
    let blinding = Scalar::from(9u64);
    let out_blinding = Scalar::from(4u64);
    let out_commitment = CompressedCommitment::from(&Commitment::new(value, out_blinding, &gens));
    let ring: Vec<_> = (0..11)
        .map(|i| ReducedTxOut {
            public_key: spend.tx_public().into(),
            target_key: if i == 5 {
                spend.target().into()
            } else {
                RistrettoPublic::from(RISTRETTO_BASEPOINT_POINT * Scalar::from(i as u64 + 50))
                    .into()
            },
            commitment: CompressedCommitment::from(&Commitment::new(value, blinding, &gens)),
        })
        .collect();
    let params = SessionParams {
        session_id: &session_id,
        message: &message,
        ring: &ring,
        real_index: 5,
        output_commitment: &out_commitment,
    };
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
    let mut rng = ChaCha20Rng::seed_from_u64(99);
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
    println!(
        "{}",
        serde_json::json!({"amount": value.to_string(), "destination": r.topics[3],
        "deposit_id": r.topics[1], "return_output_digest": r.return_output_digest,
        "session_id": hex::encode(session_id), "stock_mlsag_verified": true,
        "authenticated_packets": 10, "scope": "local release-intent signature; no MobileCoin transaction submission"})
    );
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
