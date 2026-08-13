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
    /// Beneficiary, parsed from the output's domain-bound memo. NOT msg.sender.
    address beneficiary;
    /// Value of the output, in the token's base units.
    uint64 amount;
    /// MobileCoin token id. Must be eUSD; the escrow re-checks.
    uint64 tokenId;
    /// Index of the block the output was finalized in.
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
    function isPayableToBridge(
        bytes32 txOutPublicKey,
        bytes32 txOutTargetKey,
        bytes32 returnSpendPublicKey
    ) external view returns (bool);
}
