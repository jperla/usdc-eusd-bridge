// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {IMobileCoinVerifier, VerifiedReturn, IRecipientCheck} from "./IMobileCoinVerifier.sol";
import {ValidatorRegistry} from "./ValidatorRegistry.sol";
import {Ed25519} from "./Ed25519.sol";
import {MobileCoinBlock} from "./Merlin.sol";
import {Blake2b256} from "./Blake2b256.sol";

/// Verifies that an eUSD output was paid to the bridge's return address and
/// finalized in a MobileCoin block, for the Ethereum side of the return leg.
///
/// The chain of reasoning the contract has to close, in order:
///
///   1. these signatures are over THIS block          (Merlin digest + Ed25519)
///   2. the signers are a real quorum                 (ValidatorRegistry)
///   3. this output is IN that block                  (membership proof)
///   4. this output is payable to US, in eUSD         (recipient + token)
///   5. it names a beneficiary, and only once ever    (memo + escrow replay set)
///
/// Any link left open is a way to take the escrow's USDC, so each is a
/// separate, individually testable step and none is inferred from another.
contract MobileCoinVerifier is IMobileCoinVerifier {
    /// Domain tag MobileCoin signs block digests under.
    bytes constant BLOCK_SIG_DOMAIN = "block-sig";

    /// Domain tag for this bridge's memo schema. Binding the memo to a domain
    /// is what stops a memo written for some other purpose -- or for a
    /// different deployment of this bridge -- from being replayed here as a
    /// redemption instruction.
    bytes32 public immutable memoDomain;

    ValidatorRegistry public immutable registry;

    /// The bridge's MobileCoin return subaddress spend public key, `D`.
    bytes32 public immutable returnSpendPublicKey;

    /// eUSD token id.
    uint64 public immutable eusdTokenId;

    /// See IRecipientCheck. A deployment that passes a permissive
    /// implementation here has NOT closed the return leg.
    IRecipientCheck public immutable recipientCheck;

    struct Proof {
        // --- block header fields, in Digestible order ---
        bytes32 blockId;
        uint32 version;
        bytes32 parentId;
        uint64 index;
        uint64 cumulativeTxoCount;
        uint64 rootRangeFrom;
        uint64 rootRangeTo;
        bytes32 rootHash;
        bytes32 contentsHash;
        // --- quorum ---
        bytes32[] signerKeys;      // ordered by validator entity, ascending
        bytes32[2][] signatures;   // parallel to signerKeys
        // --- the output being redeemed ---
        bytes32 txOutPublicKey;
        bytes32 txOutTargetKey;
        /// The TxOut's own hash, as MobileCoin computes it. The Merkle leaf
        /// covers this, so it is what the membership walk starts from.
        bytes32 txOutHash;
        uint64 amount;
        uint64 tokenId;
        // --- memo, domain-bound ---
        bytes32 memoDomainTag;
        address beneficiary;
        // --- membership ---
        bytes32[] merklePath;
        uint64 merkleIndex;
    }

    error QuorumNotMet();
    error BadSignature(uint256 index);
    error SignerCountMismatch();
    error WrongTokenId(uint64 got, uint64 want);
    error WrongMemoDomain(bytes32 got, bytes32 want);
    error ZeroBeneficiary();
    error NotPayableToBridge();
    error MembershipFailed();
    error BlockIdMismatch(bytes32 claimed, bytes32 recomputed);

    constructor(
        ValidatorRegistry _registry,
        bytes32 _returnSpendPublicKey,
        uint64 _eusdTokenId,
        bytes32 _memoDomain,
        IRecipientCheck _recipientCheck
    ) {
        require(address(_recipientCheck) != address(0), "recipientCheck required");
        recipientCheck = _recipientCheck;
        registry = _registry;
        returnSpendPublicKey = _returnSpendPublicKey;
        eusdTokenId = _eusdTokenId;
        memoDomain = _memoDomain;
    }

    /// The digest MobileCoin validators sign for this block.
    ///
    /// Cross-checked against a Block built and signed by MobileCoin's own
    /// crates -- see `blockSigDigest` in contracts/test/merlin.mjs, which
    /// asserts byte equality against crates/mc-return's fixture. An earlier
    /// version of this function guessed the field framing; guessing is not
    /// good enough here, because a digest that is merely plausible verifies
    /// signatures over a block that does not exist.
    ///
    /// `blockId` is checked rather than trusted: it is a field of the block, so
    /// recomputing it from the same header and requiring a match stops a
    /// relayer from pairing one block's id with another block's contents.
    function blockDigest(Proof memory p) public pure returns (bytes32) {
        bytes32 recomputed = MobileCoinBlock.id(
            p.version, p.parentId, p.index, p.cumulativeTxoCount,
            p.rootRangeFrom, p.rootRangeTo, p.rootHash, p.contentsHash
        );
        if (recomputed != p.blockId) revert BlockIdMismatch(p.blockId, recomputed);

        return MobileCoinBlock.sigDigest(
            p.blockId, p.version, p.parentId, p.index, p.cumulativeTxoCount,
            p.rootRangeFrom, p.rootRangeTo, p.rootHash, p.contentsHash
        );
    }


    /// Step 1 and 2: a real quorum signed this block.
    function verifyQuorum(Proof memory p) public view returns (bytes32 digest) {
        if (p.signerKeys.length != p.signatures.length) {
            revert SignerCountMismatch();
        }
        // Entity-scoped and height-scoped. See ValidatorRegistry for why
        // counting keys instead of entities would be a forgery.
        if (!registry.isQuorum(p.signerKeys, p.index)) revert QuorumNotMet();

        digest = blockDigest(p);
        bytes memory msg32 = abi.encodePacked(digest);
        for (uint256 i = 0; i < p.signerKeys.length; i++) {
            if (!Ed25519.verify(p.signatures[i], p.signerKeys[i], msg32)) {
                revert BadSignature(i);
            }
        }
    }

    /// Step 3: this output is in that block.
    ///
    /// MobileCoin's TxOut Merkle tree hashes with Blake2b-256 under domain
    /// tags, which Ethereum exposes only as the compression function F at
    /// precompile 0x09 (EIP-152), so `Blake2b256` reconstructs the whole hash.
    /// `txOutHash` is the TxOut's own hash as MobileCoin computes it -- the
    /// leaf hashes THAT, not the raw key material.
    function verifyMembership(Proof memory p) public view returns (bool) {
        bytes32 node = Blake2b256.hashLeaf(p.txOutHash);
        uint64 idx = p.merkleIndex;
        for (uint256 i = 0; i < p.merklePath.length; i++) {
            node = (idx & 1 == 0)
                ? Blake2b256.hashNodes(node, p.merklePath[i])
                : Blake2b256.hashNodes(p.merklePath[i], node);
            idx >>= 1;
        }
        return node == p.rootHash;
    }

    /// Steps 4 and 5, then hand the escrow a value it can act on.
    function verifyReturn(bytes calldata proof)
        external
        view
        returns (VerifiedReturn memory)
    {
        Proof memory p = abi.decode(proof, (Proof));

        verifyQuorum(p);

        if (!verifyMembership(p)) revert MembershipFailed();

        if (p.tokenId != eusdTokenId) {
            revert WrongTokenId(p.tokenId, eusdTokenId);
        }
        if (p.memoDomainTag != memoDomain) {
            revert WrongMemoDomain(p.memoDomainTag, memoDomain);
        }
        if (p.beneficiary == address(0)) revert ZeroBeneficiary();

        // The recipient check. See the note on `_payableToBridge`: this is the
        // one link in the chain that is NOT yet closed on-chain.
        if (!_payableToBridge(p)) revert NotPayableToBridge();

        return VerifiedReturn({
            outputPublicKey: p.txOutPublicKey,
            beneficiary: p.beneficiary,
            amount: p.amount,
            tokenId: p.tokenId,
            blockIndex: p.index
        });
    }

    // -------------------------------------------------------------- internal

    function _payableToBridge(Proof memory p) internal view returns (bool) {
        return recipientCheck.isPayableToBridge(
            p.txOutPublicKey, p.txOutTargetKey, returnSpendPublicKey
        );
    }

}
