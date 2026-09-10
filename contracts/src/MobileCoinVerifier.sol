// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {IMobileCoinVerifier, VerifiedReturn, IRecipientCheck} from "./IMobileCoinVerifier.sol";
import {ValidatorRegistry} from "./ValidatorRegistry.sol";
import {Ed25519} from "./Ed25519.sol";
import {MobileCoinBlock, MobileCoinTxOut} from "./Merlin.sol";
import {Blake2b256} from "./Blake2b256.sol";
import {AmountOpener, MemoOpener} from "./AmountOpener.sol";
import {MobileCoinGenerators} from "./MobileCoinGenerators.sol";

/// Verifies that an eUSD output was paid to the bridge's return address and
/// finalized in a MobileCoin block, for the Ethereum side of the return leg.
///
/// The chain of reasoning the contract has to close, in order:
///
///   1. these signatures are over THIS block          (Merlin digest + Ed25519)
///   2. the signers are a real quorum                 (ValidatorRegistry)
///   3. this output is IN that block                  (membership proof)
///   4. this output is payable to US                  (recipient check)
///   5. what it is worth, in which token              (masked amount + commitment)
///   6. who it names, and only once ever              (memo + escrow replay set)
///
/// Any link left open is a way to take the escrow's USDC, so each is a
/// separate, individually testable step and none is inferred from another.
///
/// NOTHING IN THE PAYOUT IS SUPPLIED BY THE CALLER. Steps 5 and 6 used to be
/// three plaintext fields of `Proof` -- the amount, the token id and the
/// beneficiary -- checked against nothing but a constant, which meant one
/// genuine, quorum-signed, provably-included return could be resubmitted
/// naming any payee and any amount up to the escrow's balance. They are now
/// derived from the output's own encrypted fields with the bridge's view key,
/// and the `Proof` struct has no place left to put them.
contract MobileCoinVerifier is IMobileCoinVerifier {
    /// Domain tag MobileCoin signs block digests under.
    bytes constant BLOCK_SIG_DOMAIN = "block-sig";

    /// Memo type for "pay the USDC to this Ethereum address" -- this repo's
    /// schema, `crates/mc-return/src/disclosure.rs`.
    ///
    /// A CONSTANT, and read out of the DECRYPTED memo. It is what actually
    /// binds a memo to this bridge's purpose: only the party who created the
    /// output could have written its memo, so a payload that does not carry
    /// this type is not a redemption instruction and its first 20 bytes are
    /// not an address.
    bytes2 public constant BRIDGE_RETURN_MEMO_TYPE = 0x8002;

    /// Configured namespace, combined with chain id and the CALLING escrow.
    /// The resulting domain is carried inside the quorum-authenticated memo,
    /// not in an editable relayer field. See `redemptionDomain`.
    bytes32 public immutable memoDomain;

    ValidatorRegistry public immutable registry;

    /// The bridge's MobileCoin return subaddress spend public key, `D`.
    bytes32 public immutable returnSpendPublicKey;

    /// eUSD token id.
    uint64 public immutable eusdTokenId;

    /// `B_token` for `eusdTokenId`: the Pedersen value generator, compressed.
    ///
    /// DERIVED, not supplied. The constructor runs MobileCoin's own
    /// construction -- Blake2b-512 over the domain-tagged basepoint XOR the
    /// token id, then the ristretto255 one-way map -- so this getter is a
    /// function of `eusdTokenId` and of nothing a deployer types. See
    /// `MobileCoinGenerators`.
    ///
    /// IT USED TO BE A CONSTRUCTOR ARGUMENT, and that was a fail-open. Nothing
    /// related the point to the id beside it: a verifier deployed with token id
    /// 8192 and `generators(1).B` passes the token-id check and then verifies
    /// commitments in the wrong group, so an amount MobileCoin rejects as
    /// `InconsistentCommitment` is accepted and paid out. The mitigation was a
    /// comment asking whoever deployed to compare two getters by hand. The
    /// argument is gone, so there is nothing left to mispair and nothing left
    /// to check by hand.
    ///
    /// Still public, because a funder reading this getter against MobileCoin's
    /// `generators(eusdTokenId)` is a cheap end-to-end confirmation that the
    /// derivation on this chain agrees with the one on that one.
    bytes32 public immutable eusdValueGenerator;

    /// See IRecipientCheck. A deployment that passes a permissive
    /// implementation here has NOT closed the return leg.
    IRecipientCheck public immutable recipientCheck;

    /// A MobileCoin `TxOut`, exactly the fields its own digest covers.
    struct TxOutFields {
        bytes32 commitment;
        uint64 maskedValue;
        bytes maskedTokenId;
        bytes32 targetKey;
        bytes32 publicKey;
        bytes eFogHint;
        bytes eMemo;
    }

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
        // --- the output being redeemed, in full ---
        //
        // The TxOut's own fields, NOT its hash. Taking the hash directly meant
        // the Merkle path proved that SOME output was in the block while the
        // caller named a different one -- the redeemed public key and amount
        // were unconstrained, so one genuinely included output could be
        // redeemed repeatedly under invented identities. Recomputing the
        // digest from these fields is what makes the proof about the output it
        // claims to be about.
        //
        // THE PAYOUT IS NOT IN HERE. There is deliberately no `amount`, no
        // `tokenId` and no `beneficiary`: those were plaintext claims about
        // what the encrypted fields above open to, and nothing related them to
        // the output the Merkle path proved. They are derived in
        // `verifyReturn` instead. A field that is accepted and then ignored
        // invites someone to start honouring it again, so there is no field.
        TxOutFields txOut;
        // --- membership ---
        bytes32[] merklePath;
        uint64 merkleIndex;
    }

    error QuorumNotMet();
    error BadSignature(uint256 index);
    error SignerCountMismatch();
    error WrongTokenId(uint64 got, uint64 want);
    error WrongMemoDomain(bytes32 got, bytes32 want);
    error WrongMemoType(bytes2 got, bytes2 want);
    error NonzeroMemoReserved(bytes12 got);
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
        // THE ONE PLACE THE TOKEN ID AND THE GENERATOR MEET. Derived from the
        // id assigned on the line above, in the constructor, once. A
        // hash-to-curve is not cheap by EVM standards, but this is not on the
        // redemption path: `verifyReturn` reads the resulting immutable and is
        // unaffected. Paying for it here deletes a parameter and a fail-open.
        eusdValueGenerator = MobileCoinGenerators.valueGenerator(_eusdTokenId);
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
    /// The leaf preimage: recomputed here rather than accepted from the caller.
    function txOutDigest(Proof memory p) public pure returns (bytes32) {
        return MobileCoinTxOut.digest(
            p.txOut.commitment,
            p.txOut.maskedValue,
            p.txOut.maskedTokenId,
            p.txOut.targetKey,
            p.txOut.publicKey,
            p.txOut.eFogHint,
            p.txOut.eMemo
        );
    }

    function verifyMembership(Proof memory p) public view returns (bool) {
        bytes32 node = Blake2b256.hashLeaf(txOutDigest(p));
        uint64 idx = p.merkleIndex;
        for (uint256 i = 0; i < p.merklePath.length; i++) {
            node = (idx & 1 == 0)
                ? Blake2b256.hashNodes(node, p.merklePath[i])
                : Blake2b256.hashNodes(p.merklePath[i], node);
            idx >>= 1;
        }
        // THE INDEX MUST BE FULLY CONSUMED BY THE PATH. Only the low
        // `merklePath.length` bits of `merkleIndex` steer the walk, so without
        // this any index congruent to the real one modulo 2^length -- 11 for a
        // real 3 over a three-level path -- reproduces the same root and is
        // accepted. That makes the claimed global position of the output
        // malleable while the leaf itself stays bound, which is a divergence
        // from upstream: `is_membership_proof_valid` rejects it as
        // `HighestIndexMismatch`
        // (transaction/core/src/membership_proofs/mod.rs). Requiring the
        // residue to be zero costs one comparison and removes the alias class.
        if (idx != 0) return false;
        return node == p.rootHash;
    }

    /// Step 4: was this output paid to the bridge, and what shared secret says
    /// so.
    ///
    /// `S = compressed([a]R)` comes back with the answer because every
    /// remaining step needs it and it costs one scalar multiplication -- see
    /// IRecipientCheck.
    function sharedSecretOf(Proof memory p)
        public
        view
        returns (bytes32 sharedSecret)
    {
        bool paidToBridge;
        // Delegated so the implementation is visible in the deployment
        // transaction rather than being a detail somebody has to go looking
        // for.
        (paidToBridge, sharedSecret) = recipientCheck.isPayableToBridge(
            p.txOut.publicKey, p.txOut.targetKey, returnSpendPublicKey
        );
        if (!paidToBridge) revert NotPayableToBridge();
    }

    /// Step 5: what this output is worth, in which token.
    ///
    /// Public, and taking the shared secret as an argument, for the same
    /// reason `verifyQuorum` and `verifyMembership` are public: every branch
    /// below has to be reachable by a test on the code path production uses,
    /// not on a parallel copy of it. Passing a secret here proves nothing on
    /// its own -- the commitment check is what decides whether it was the
    /// right one.
    function openAmount(bytes32 sharedSecret, TxOutFields memory txOut)
        public
        view
        returns (uint64 amount, uint64 tokenId)
    {
        uint256 blinding;
        (amount, tokenId, blinding) = AmountOpener.unmask(
            sharedSecret, txOut.maskedValue, txOut.maskedTokenId
        );

        // THE TOKEN ID IS CHECKED BEFORE THE COMMITMENT, and that order is
        // load-bearing rather than stylistic. `eusdValueGenerator` is `B_token`
        // for `eusdTokenId` and for no other id; recomputing the commitment
        // with it while the amount is denominated in something else would be
        // comparing against the wrong curve point. Upstream checks the
        // commitment for whatever id came out because it can compute every
        // generator; this contract has one, so it establishes the id first.
        if (tokenId != eusdTokenId) revert WrongTokenId(tokenId, eusdTokenId);

        // And this is what makes `amount` mean anything -- see
        // AmountOpener.InconsistentCommitment. Without it, `amount` is just
        // some number XOR-ed out of a mask, with nothing tying it to the
        // output the membership proof covered.
        AmountOpener.requireCommitment(
            txOut.commitment, amount, blinding, eusdValueGenerator
        );
    }

    /// Domain the sender must put in memo data bytes 20..52 before creating
    /// the MobileCoin output. Distinct escrows (even sharing this verifier),
    /// chains and configured namespaces cannot redeem each other's returns.
    /// An upgrade preserving an escrow and namespace must preserve its replay
    /// registry too. A new escrow requires newly addressed return outputs.
    function redemptionDomain(address escrow) public view returns (bytes32) {
        return keccak256(abi.encode(
            bytes32("mc-bridge-return-v2"), block.chainid, escrow, memoDomain
        ));
    }

    /// Step 6: the beneficiary AND deployment this output names.
    function openMemo(bytes32 sharedSecret, bytes memory eMemo)
        public
        view
        returns (address beneficiary)
    {
        bytes2 memoType;
        bytes32 domain;
        bytes12 reserved;
        (memoType, beneficiary, domain, reserved) = MemoOpener.open(sharedSecret, eMemo);
        if (memoType != BRIDGE_RETURN_MEMO_TYPE) {
            revert WrongMemoType(memoType, BRIDGE_RETURN_MEMO_TYPE);
        }
        if (reserved != bytes12(0)) revert NonzeroMemoReserved(reserved);
        bytes32 expectedDomain = redemptionDomain(msg.sender);
        if (domain != expectedDomain) revert WrongMemoDomain(domain, expectedDomain);
        // A memo of the right type whose first 20 bytes are zero names nobody.
        // The escrow refuses this too; refusing it here as well means the
        // failure is attributable to the proof rather than to the payout.
        if (beneficiary == address(0)) revert ZeroBeneficiary();
    }

    /// The whole chain, then hand the escrow a value it can act on.
    ///
    /// Every field of the returned `VerifiedReturn` is derived: the public key
    /// and block index from the header the quorum signed, the value and token
    /// id from the masked amount, the beneficiary from the memo. The argument
    /// contributes bytes to be checked and nothing that is paid out.
    function verifyReturn(bytes calldata proof)
        external
        view
        returns (VerifiedReturn memory)
    {
        Proof memory p = abi.decode(proof, (Proof));

        verifyQuorum(p);

        if (!verifyMembership(p)) revert MembershipFailed();

        bytes32 sharedSecret = sharedSecretOf(p);
        (uint64 amount, uint64 tokenId) = openAmount(sharedSecret, p.txOut);
        address beneficiary = openMemo(sharedSecret, p.txOut.eMemo);

        return VerifiedReturn({
            outputPublicKey: p.txOut.publicKey,
            beneficiary: beneficiary,
            amount: amount,
            tokenId: tokenId,
            blockIndex: p.index
        });
    }
}
