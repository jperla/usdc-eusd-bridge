//! Bounded, identity-authenticated MLSAG packets. The caller supplies the
//! authenticated roster key, expected seat, session and round context; a packet
//! never selects its own trust root. This is a wire codec, not a network service.
use super::*;
use crate::identity::{IdentityKey, IdentityPublic, IdentitySignature};
use curve25519_dalek::ristretto::CompressedRistretto;
const DOMAIN: &[u8] = b"mc-bridge-mlsag-packet-v2";
#[derive(Debug, Clone, Copy, PartialEq, Eq, ThisError)]
#[error("invalid or unauthenticated MLSAG packet")]
pub struct WireError;
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    SpendCommitment(SpendNonce),
    MaskCommitment(MaskNonce),
    SpendResponse(SpendResponse),
    MaskResponse(MaskResponse),
}
impl Message {
    fn seat(&self) -> Seat {
        match self {
            Self::SpendCommitment(n) => Seat::Spend(n.role),
            Self::SpendResponse(r) => Seat::Spend(r.role),
            _ => Seat::Mask,
        }
    }
    fn phase(&self) -> u8 {
        match self {
            Self::SpendCommitment(_) | Self::MaskCommitment(_) => 1,
            _ => 2,
        }
    }
    fn body(&self) -> Vec<u8> {
        match self {
            Self::SpendCommitment(n) => [
                n.share_public,
                n.image_term,
                n.nonce_public,
                n.nonce_image,
                n.binding_public,
                n.binding_image,
            ]
            .iter()
            .flat_map(|p| p.compress().to_bytes())
            .collect(),
            Self::MaskCommitment(n) => [n.nonce_public, n.binding_public]
                .iter()
                .flat_map(|p| p.compress().to_bytes())
                .collect(),
            Self::SpendResponse(r) => r.response.to_bytes().to_vec(),
            Self::MaskResponse(r) => r.response.to_bytes().to_vec(),
        }
    }
}
/// For round one use session.binding().as_bytes(); for round two use the
/// locally verified RoundOne::context_id(params). These values are signed.
pub fn encode(key: &IdentityKey, context: [u8; 32], message: &Message) -> Vec<u8> {
    let mut out = DOMAIN.to_vec();
    out.push(message.phase());
    out.extend(message.seat().tag());
    out.extend(context);
    out.extend(message.body());
    out.extend(key.sign(&out).0);
    out
}
/// Exact length, canonical encodings, explicit expected phase and seat.
/// Verify before allocating/decoding points; maximum packet size is 321 bytes.
pub fn decode(
    bytes: &[u8],
    key: &IdentityPublic,
    context: [u8; 32],
    seat: Seat,
    phase: u8,
) -> Result<Message, WireError> {
    let body_len = match (phase, seat) {
        (1, Seat::Spend(_)) => 192,
        (1, Seat::Mask) => 64,
        (2, _) => 32,
        _ => return Err(WireError),
    };
    let start = DOMAIN.len() + 1 + 9 + 32;
    if bytes.len() != start + body_len + 64
        || !bytes.starts_with(DOMAIN)
        || bytes[DOMAIN.len()] != phase
        || bytes[DOMAIN.len() + 1..DOMAIN.len() + 10] != seat.tag()
        || bytes[DOMAIN.len() + 10..start] != context
        || key.unusable_reason().is_some()
    {
        return Err(WireError);
    }
    let end = start + body_len;
    let signature = IdentitySignature(bytes[end..].try_into().map_err(|_| WireError)?);
    if !key.verify(&bytes[..end], &signature) {
        return Err(WireError);
    }
    let body = &bytes[start..end];
    let point = |i: usize| -> Result<RistrettoPoint, WireError> {
        CompressedRistretto(
            body[i * 32..(i + 1) * 32]
                .try_into()
                .map_err(|_| WireError)?,
        )
        .decompress()
        .ok_or(WireError)
    };
    Ok(match (phase, seat) {
        (1, Seat::Spend(role)) => Message::SpendCommitment(SpendNonce {
            role,
            share_public: point(0)?,
            image_term: point(1)?,
            nonce_public: point(2)?,
            nonce_image: point(3)?,
            binding_public: point(4)?,
            binding_image: point(5)?,
        }),
        (1, Seat::Mask) => Message::MaskCommitment(MaskNonce {
            nonce_public: point(0)?,
            binding_public: point(1)?,
        }),
        (2, seat) => {
            let response = Option::<Scalar>::from(Scalar::from_canonical_bytes(
                body.try_into().map_err(|_| WireError)?,
            ))
            .ok_or(WireError)?;
            match seat {
                Seat::Spend(role) => Message::SpendResponse(SpendResponse { role, response }),
                Seat::Mask => Message::MaskResponse(MaskResponse { response }),
            }
        }
        _ => return Err(WireError),
    })
}
