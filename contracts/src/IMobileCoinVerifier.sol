// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// A verified MobileCoin return: an eUSD output paid to the bridge's return
/// address `R`, proven to be in a finalized MobileCoin block.
///
/// Every field here is *derived from the proof*. None of it is supplied by the
/// caller in a form the caller controls, which is the property the return leg
/// depends on -- see `Escrow.release`.
struct VerifiedReturn {
    /// The MobileCoin output public key. This is the replay key: one output
    /// can be redeemed exactly once, ever, under any epoch or key-set version.
    bytes32 outputPublicKey;
    /// Beneficiary, DECRYPTED from the output's memo with the bridge's view
    /// key. NOT msg.sender, and not a field of the proof.
    address beneficiary;
    /// Value of the output, in the token's base units. Unmasked from the
    /// output's `masked_value` and then checked against its Pedersen
    /// commitment -- see AmountOpener.
    uint64 amount;
    /// MobileCoin token id, unmasked from the output's `masked_token_id`.
    /// Must be eUSD; the escrow re-checks.
    uint64 tokenId;
    /// Index of the ANCHOR block: the one whose header the quorum signed and
    /// whose TxOut root the membership proof reproduces.
    ///
    /// NOT the block that created the output. MobileCoin's TxOut tree is
    /// cumulative, so every block at or after the originating one has a root
    /// that covers the output, and a submitter may anchor against any of them.
    /// `crates/mc-return` derives the ORIGINATING height from the header
    /// chain's cumulative TxOut counts and publishes that as
    /// `expected.blockIndex`; the two disagree in the fixture (origin 1, anchor
    /// 2) and a consumer that reads this field as an origin will be wrong.
    ///
    /// The anchor is not attacker-chosen in any interesting sense -- it must be
    /// a real, quorum-signed block whose root contains the output -- but it is
    /// chosen, so nothing may depend on it being minimal. Today nothing does:
    /// `Escrow.release` only emits it, and replay is keyed on
    /// `outputPublicKey`.
    uint64 blockIndex;
}

interface IMobileCoinVerifier {
    /// Verify a MobileCoin return proof, or revert.
    ///
    /// Reverting rather than returning a bool is deliberate: a bool return
    /// invites a caller that forgets to check it, and this is the only thing
    /// standing between a relayer and the escrow's USDC.
    function verifyReturn(bytes calldata proof)
        external
        view
        returns (VerifiedReturn memory);
}

/// Whether an output was payable to the bridge: `target_key == Hs(a*R)*G + D`.
///
/// An interface rather than an internal function so that WHICH implementation
/// a deployment uses is a constructor argument visible in the deployment
/// transaction, instead of a detail somebody has to go looking for. That
/// matters because a permissive implementation makes every other check in the
/// return leg pointless: anyone able to get any output into a quorum-signed
/// block could redeem it.
///
/// `RecipientCheck` is the real one, built on Ristretto255 -- MobileCoin uses
/// Ristretto, not raw Ed25519, and substituting Ed25519 decompression here
/// would be wrong in a way that still passes casual tests.
/// `AcceptsAnyRecipient_DO_NOT_DEPLOY` exists only so the escrow's own logic
/// can be tested without the cryptography.
interface IRecipientCheck {
    /// Answer the recipient question AND hand back the shared secret it was
    /// answered with.
    ///
    /// WHY `sharedSecret` COMES OUT OF THIS CALL. `S = compressed([a]R)` is a
    /// by-product of the check: computing `Hs(a*R)` requires `[a]R` and then
    /// throws it away. It is also the single input from which the output's
    /// value, token id and beneficiary are all derived. Returning it turns
    /// three variable-base scalar multiplications into one.
    ///
    /// Returning `(bool, bytes32)` rather than one function that opens
    /// everything keeps the version-specific parts separable: this interface
    /// is about the curve and the address, and `MaskedAmountV2` -- which will
    /// have a V3 one day -- is `AmountOpener`'s business, not this contract's.
    ///
    /// An implementation MUST return the zero secret when the answer is no.
    /// The caller reverts on a no, so the value is unreachable in a correct
    /// caller; zeroing it means a future caller that forgets cannot open an
    /// amount with a secret nobody vouched for.
    function isPayableToBridge(
        bytes32 txOutPublicKey,
        bytes32 txOutTargetKey,
        bytes32 returnSpendPublicKey
    ) external view returns (bool paidToBridge, bytes32 sharedSecret);
}
