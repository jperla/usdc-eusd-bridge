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
