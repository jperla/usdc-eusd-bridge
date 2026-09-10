//! A faithful recording of the merlin operations behind a MobileCoin digest.
//!
//! Both digests the return leg depends on -- the block id and the block
//! signature digest -- are merlin transcripts, not a hash of a flat byte
//! string. Merlin is STROBE-128 over Keccak-f[1600], and Solidity's `keccak256`
//! is the *sponge*, not the permutation, so an Ethereum verifier that wants to
//! recompute either digest has to drive its own STROBE state machine. Handing
//! it the struct and hoping it re-derives the same call sequence from the Rust
//! `Digestible` derive is exactly the kind of "trust the fixture" step this
//! bundle exists to remove.
//!
//! So we record the operations instead. A `TranscriptScript` is the complete,
//! ordered list of `append_message(label, data)` calls that upstream makes,
//! plus the protocol label the transcript was opened with and the label the
//! digest is squeezed under. Replaying it through a real merlin transcript
//! reproduces the digest byte for byte -- `replay()` does exactly that, and the
//! tests assert it against the value upstream computes. A Solidity verifier
//! that implements STROBE can consume the script directly.

use mc_crypto_digestible::{DigestTranscript, MerlinTranscript};

/// One `merlin::Transcript::append_message` call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TranscriptOp {
    /// The merlin label. Always a string literal upstream, hence `'static`.
    pub label: &'static [u8],
    pub data: Vec<u8>,
}

/// Everything needed to recompute a MobileCoin merlin digest from scratch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TranscriptScript {
    /// Passed to `merlin::Transcript::new`.
    pub protocol_label: &'static [u8],
    pub ops: Vec<TranscriptOp>,
    /// Passed to `challenge_bytes` to squeeze the 32-byte result.
    pub challenge_label: &'static [u8],
}

impl TranscriptScript {
    /// Run the recorded script through a real merlin transcript.
    ///
    /// This is not a reimplementation of the digest: it is the same merlin
    /// crate upstream uses, driven by the recorded calls. If `replay()` and the
    /// upstream digest ever disagree, the recording is wrong -- which is the
    /// failure the tests are looking for.
    pub fn replay(&self) -> [u8; 32] {
        let mut transcript = MerlinTranscript::new(self.protocol_label);
        for op in &self.ops {
            transcript.append_message(op.label, &op.data);
        }
        let mut out = [0u8; 32];
        transcript.challenge_bytes(self.challenge_label, &mut out);
        out
    }
}

/// A `DigestTranscript` that writes down what it is asked to do.
pub struct Recorder {
    protocol_label: &'static [u8],
    ops: Vec<TranscriptOp>,
}

impl Recorder {
    fn with_protocol_label(protocol_label: &'static [u8]) -> Self {
        Self {
            protocol_label,
            ops: Vec::new(),
        }
    }
}

impl DigestTranscript for Recorder {
    /// `MerlinTranscript`'s own `DigestTranscript::new` opens the transcript
    /// with `b"digestible"`; anything reached through `Digestible::digest32`
    /// starts there, so we must too.
    fn new() -> Self {
        Self::with_protocol_label(b"digestible")
    }

    fn append_bytes(&mut self, context: &'static [u8], data: impl AsRef<[u8]>) {
        self.ops.push(TranscriptOp {
            label: context,
            data: data.as_ref().to_vec(),
        });
    }

    /// Present so `Recorder` satisfies the trait, and honest when called: it
    /// replays into real merlin rather than inventing an answer. Recording is
    /// done through [`record`], which keeps the ops.
    fn extract_digest(self, output: &mut [u8; 32]) {
        let script = TranscriptScript {
            protocol_label: self.protocol_label,
            ops: self.ops,
            challenge_label: b"digest32",
        };
        *output = script.replay();
    }
}

/// Record the operations `f` performs against a transcript opened with
/// `protocol_label` and squeezed under `challenge_label`.
pub fn record<F>(
    protocol_label: &'static [u8],
    challenge_label: &'static [u8],
    f: F,
) -> TranscriptScript
where
    F: FnOnce(&mut Recorder),
{
    let mut rec = Recorder::with_protocol_label(protocol_label);
    f(&mut rec);
    TranscriptScript {
        protocol_label,
        ops: rec.ops,
        challenge_label,
    }
}
