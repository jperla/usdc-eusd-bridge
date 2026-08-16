// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Ristretto255} from "./Ristretto255.sol";
import {Blake2b} from "./Blake2b256.sol";
import {LE} from "./LE.sol";

/// MobileCoin's Pedersen value generator `B_token`, DERIVED on chain.
///
/// Transcribed from `crypto/ring-signature/src/ring_signature/mod.rs:85`
/// (`generators`):
///
///     let mut buf = RISTRETTO_BASEPOINT_COMPRESSED.to_bytes();
///     for i in 0..8 { buf[i] ^= token_id.to_le_bytes()[i]; }
///     B = RistrettoPoint::from_hash(
///             Blake2b512::new().chain(HASH_TO_POINT_DOMAIN_TAG).chain(buf))
///
/// WHY THIS EXISTS. `B_token` used to be a constructor argument of
/// `MobileCoinVerifier`, next to the token id it belongs to, because deriving
/// it needs hash-to-curve. That pair was a deployment obligation the code could
/// not discharge, and it did not fail closed: a verifier deployed with token id
/// 8192 and `generators(1).B` verifies commitments in the wrong group, so an
/// amount MobileCoin rejects as `InconsistentCommitment` is accepted and paid
/// out. There is no argument left to mispair.
///
/// The cost argument that kept it a parameter does not survive contact with the
/// numbers. The derivation is ONE Blake2b-512 of 60 bytes -- a single call to
/// the F precompile at 12 gas -- and two applications of the ristretto one-way
/// map, each of which is one modexp and a few dozen field multiplications. It
/// runs ONCE, in the constructor. `verifyReturn` does not touch it: it reads
/// the same `bytes32` immutable it always read.
library MobileCoinGenerators {
    /// The derived point is the identity.
    ///
    /// NOT KNOWN TO BE REACHABLE BY ANY TOKEN ID, AND NOT PROVED UNREACHABLE.
    /// This comment used to argue it away -- "the map's output is the identity
    /// only where its `w0` or `w2` vanishes" -- which is a statement about ONE
    /// application of the map and does not bound `MAP(lo) + MAP(hi)`, a SUM of
    /// two of them. Two non-identity points can add to the identity; that is
    /// what being a group means.
    ///
    /// What can honestly be said: arbitrary 64-byte inputs certainly do reach
    /// the identity (two zero halves are one example, and the vanishing
    /// denominator solved for in contracts/test/ristretto.mjs gives others).
    /// Whether any of the 2^64 token-id digests does is unknown. Under the
    /// usual heuristic it is about 2^-252 for a chosen id and about 2^-188 for
    /// some id among all of them -- small enough to deploy against, not a
    /// proof, and not something a fixture can establish either way.
    ///
    /// It is refused because the identity is the one point that makes the
    /// commitment `blinding*G` for EVERY value, which is a silent fail-open
    /// rather than a wrong answer -- the same reason
    /// `AmountOpener.decodeGenerator` refuses it. Note that this is a rule of
    /// THIS bridge, not of the RFC or of MobileCoin: the vendored Rust would
    /// return the identity happily, so if such a token id existed, this
    /// contract would revert where MobileCoin would not. Exact equivalence to
    /// MobileCoin is conditional on the derived generator being non-identity.
    ///
    /// "Refused anyway" is a claim a test can check, and one does:
    /// `fromDigestHalves` below takes its digest as an argument so that
    /// contracts/test/ristretto.mjs can feed it the degenerate one. Before
    /// that split this sentence was unfalsifiable -- deleting the `revert`
    /// left the whole suite green.
    error DegenerateValueGenerator(uint64 tokenId);

    /// The 32 bytes MobileCoin hashes for `tokenId`: the compressed ristretto
    /// basepoint with the id's eight little-endian bytes XOR-ed over bytes 0..8.
    ///
    /// The basepoint encoding is COMPUTED, not written down. `Ristretto255`
    /// already carries the basepoint's coordinates and its encoder, both pinned
    /// against dalek by contracts/test/fixtures/ristretto.json, so spelling the
    /// compressed form out again would be a second constant to get wrong for no
    /// gain -- and a wrong one would produce a plausible point for every token
    /// id.
    ///
    /// Byte 0 of a `bytes32` is its MOST significant byte, so the id's least
    /// significant byte belongs at bit 255. That is what the shift below does.
    function preimage(uint64 tokenId) internal view returns (bytes32) {
        uint256 idBytes;
        unchecked {
            for (uint256 i = 0; i < 8; ++i) {
                idBytes |=
                    uint256(uint8(tokenId >> (8 * i))) << (248 - 8 * i);
            }
        }
        return Ristretto255.encode(Ristretto255.basepoint()) ^ bytes32(idBytes);
    }

    /// `generators(tokenId).B`, compressed -- what the block's Pedersen
    /// commitments are formed over.
    ///
    /// The domain tag is a string literal rather than a `bytes constant` for
    /// the reason spelled out in AmountOpener: solc copies a constant with
    /// MCOPY on a Cancun target, and MCOPY is an invalid opcode on the Shanghai
    /// chains this is meant to run on.
    function valueGenerator(uint64 tokenId)
        internal
        view
        returns (bytes32 encoded)
    {
        uint64[8] memory d = Blake2b.hashWords(
            abi.encodePacked(
                "mc_onetime_key_hash_to_point", preimage(tokenId)
            ),
            64
        );

        // The digest's two 32-BYTE halves, which are words 0..4 and 4..8
        // written back out little-endian -- not the words as numbers. The map
        // reads each half little-endian again, so getting this wrong would
        // cancel out only if both mistakes were the same mistake.
        bytes memory lo = new bytes(32);
        bytes memory hi = new bytes(32);
        uint256 o = 0;
        for (uint256 i = 0; i < 4; ++i) o = LE.put64(lo, o, d[i]);
        o = 0;
        for (uint256 i = 0; i < 4; ++i) o = LE.put64(hi, o, d[4 + i]);

        return fromDigestHalves(tokenId, bytes32(lo), bytes32(hi));
    }

    /// The map and the degeneracy refusal, over a digest supplied by the
    /// CALLER. `valueGenerator` is this function with the digest filled in.
    ///
    /// WHY THE DIGEST IS AN ARGUMENT. No token id is KNOWN to hash to a
    /// degenerate digest -- which is not the same as none existing, see the
    /// error's own note -- so a test that could only call `valueGenerator`
    /// could not make the guard fire, and a guard nothing can fire is a comment
    /// with a keyword in front of it. Splitting the tail out gives
    /// `MobileCoinGeneratorsProbe_DO_NOT_DEPLOY` a way to hand it a digest that
    /// DOES map to the identity -- 32 zero bytes twice, because MAP(0) is the
    /// identity and the identity plus itself is the identity. It is not the
    /// only such digest: any two halves summing to the identity will do, and
    /// contracts/test/ristretto.mjs solves for several from the map's own
    /// arithmetic.
    ///
    /// Deleting the `revert` below turns exactly two tests red, both in
    /// contracts/test/ristretto.mjs: 'a value generator that maps to the
    /// identity is refused', which feeds it the zero digest, and
    /// 'DegenerateValueGenerator is reachable THROUGH the map, not only
    /// through a digest of zeros', which feeds it halves solved from d and i.
    /// Measured, not remembered -- and it was one test until the second was
    /// added, so treat the count as something to re-measure rather than quote.
    ///
    /// Not re-decoded: this is the encoding of a point this library just
    /// computed, so `decode` cannot refuse it and re-running it would buy a
    /// modexp and nothing else. The identity is the one degenerate case, and
    /// it has exactly one encoding.
    ///
    /// NOT COVERED, and stated here rather than left to be discovered: no test
    /// can show that `valueGenerator` still ROUTES through this function. A
    /// rewrite that inlined the map and dropped the call would keep every
    /// generator assertion green, because no published token id reaches the
    /// refusal either way. What the tests do hold is the refusal itself and
    /// the map it guards.
    function fromDigestHalves(uint64 tokenId, bytes32 lo, bytes32 hi)
        internal
        view
        returns (bytes32 encoded)
    {
        encoded =
            Ristretto255.encode(Ristretto255.fromUniformBytes(lo, hi));
        if (encoded == bytes32(0)) revert DegenerateValueGenerator(tokenId);
    }
}

/// TEST ONLY -- NEVER DEPLOY.
///
/// Test wrapper: the library is `internal` and has no ABI of its own.
///
/// It lives in this file, and not in `src/TestMocks.sol` with the other
/// test-only contracts, because a wrapper for `internal` functions has to be
/// compiled against the library that declares them. That is a constraint, not
/// an exemption: `contracts/test/deployables.mjs` enumerates every contract in
/// `src/` and fails unless it is either on the deployable allowlist or marked
/// exactly like this one, so a production contract cannot arrive here unnamed.
///
/// Both steps are exposed separately. `valueGenerator` alone would let a wrong
/// preimage and a wrong map cancel, and the fixture publishes the intermediate
/// preimage precisely so that it does not have to.
contract MobileCoinGeneratorsProbe_DO_NOT_DEPLOY {
    function preimage(uint64 tokenId) external view returns (bytes32) {
        return MobileCoinGenerators.preimage(tokenId);
    }

    function valueGenerator(uint64 tokenId) external view returns (bytes32) {
        return MobileCoinGenerators.valueGenerator(tokenId);
    }

    /// The map and the degeneracy refusal over a digest of the test's
    /// choosing -- the only way to reach `DegenerateValueGenerator`.
    function fromDigestHalves(uint64 tokenId, bytes32 lo, bytes32 hi)
        external
        view
        returns (bytes32)
    {
        return MobileCoinGenerators.fromDigestHalves(tokenId, lo, hi);
    }
}
