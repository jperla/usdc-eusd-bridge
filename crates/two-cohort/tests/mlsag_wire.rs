use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT as G, scalar::Scalar};
use two_cohort::{
    identity::IdentityKey,
    mlsag::{
        wire::{self, Message},
        MaskNonce, MaskResponse, Seat, SpendNonce, SpendResponse, SpendRole,
    },
};
#[test]
fn packets_authenticate_every_byte_and_bind_seat_phase_context_and_key() {
    let key = IdentityKey::from_seed(&[9; 32]);
    let stranger = IdentityKey::from_seed(&[8; 32]);
    let context = [7; 32];
    for (message, seat, phase) in [
        (
            Message::SpendCommitment(SpendNonce {
                role: SpendRole::Owner(1),
                share_public: G,
                image_term: G * Scalar::from(2u64),
                nonce_public: G * Scalar::from(3u64),
                nonce_image: G * Scalar::from(4u64),
                binding_public: G * Scalar::from(5u64),
                binding_image: G * Scalar::from(6u64),
            }),
            Seat::Spend(SpendRole::Owner(1)),
            1,
        ),
        (
            Message::MaskCommitment(MaskNonce {
                nonce_public: G,
                binding_public: G * Scalar::from(2u64),
            }),
            Seat::Mask,
            1,
        ),
        (
            Message::SpendResponse(SpendResponse {
                role: SpendRole::Gate(99),
                response: Scalar::from(7u64),
            }),
            Seat::Spend(SpendRole::Gate(99)),
            2,
        ),
        (
            Message::MaskResponse(MaskResponse {
                response: Scalar::from(8u64),
            }),
            Seat::Mask,
            2,
        ),
    ] {
        let bytes = wire::encode(&key, context, &message);
        assert_eq!(
            wire::decode(&bytes, &key.public(), context, seat, phase).unwrap(),
            message
        );
        for i in 0..bytes.len() {
            let mut bad = bytes.clone();
            bad[i] ^= 1;
            assert!(
                wire::decode(&bad, &key.public(), context, seat, phase).is_err(),
                "byte {i}"
            );
        }
        assert!(wire::decode(&bytes, &stranger.public(), context, seat, phase).is_err());
        assert!(wire::decode(&bytes, &key.public(), [6; 32], seat, phase).is_err());
        assert!(wire::decode(
            &bytes,
            &key.public(),
            context,
            Seat::Spend(SpendRole::View),
            phase
        )
        .is_err());
        assert!(wire::decode(&bytes, &key.public(), context, seat, 3 - phase).is_err());
        for end in 0..bytes.len() {
            assert!(wire::decode(&bytes[..end], &key.public(), context, seat, phase).is_err());
        }
        // Authenticate malformed body bytes with the REAL key, so canonical
        // point/scalar validation is exercised after signature verification.
        let body_len = match (phase, seat) {
            (1, Seat::Spend(_)) => 192, (1, Seat::Mask) => 64, _ => 32,
        };
        let mut malformed = bytes.clone();
        let end = malformed.len() - 64;
        malformed[end-body_len..end-body_len+32].fill(0xff);
        let signature = key.sign(&malformed[..end]);
        malformed[end..].copy_from_slice(&signature.0);
        assert!(key.public().verify(&malformed[..end], &signature));
        assert!(wire::decode(&malformed, &key.public(), context, seat, phase).is_err());
        let mut long = bytes;
        long.push(0);
        assert!(wire::decode(&long, &key.public(), context, seat, phase).is_err());
    }
}
