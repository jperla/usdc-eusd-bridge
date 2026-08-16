// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Keccak1600} from "./Keccak1600.sol";
import {LE} from "./LE.sol";

/// Merlin transcripts, on-chain.
///
/// MobileCoin does not hash its block headers with a hash function. It runs a
/// Merlin transcript (`mc-crypto-digestible`), which is a STROBE-128 duplex
/// sponge over Keccak-f[1600]. A verifier that wants to check a validator's
/// Ed25519 signature over a block ID has to recompute that transcript byte for
/// byte, so this is a hard requirement rather than a convenience.
///
/// PROVENANCE. Every framing decision below is transcribed from the sources,
/// not inferred from the Merlin specification, because the two differ in
/// places that matter (merlin's STROBE omits the T flag entirely, and its
/// `begin_op` runs F *after* absorbing the two-byte operation header, not
/// before):
///
///   merlin 3.0.0 src/strobe.rs      -- Strobe128::{new, meta_ad, ad, prf},
///                                      run_f, absorb, squeeze, begin_op
///   merlin 3.0.0 src/transcript.rs  -- Transcript::{new, append_message,
///                                      append_u64, challenge_bytes}
///   merlin 3.0.0 src/constants.rs   -- MERLIN_PROTOCOL_LABEL = "Merlin v1.0"
///   mobilecoin 05cb699f crypto/digestible/src/lib.rs
///                                   -- DigestTranscript AST node framing
///
/// merlin 3.0.0 is the version MobileCoin's Cargo.lock pins (checksum
/// 58c38e2799fc0978b65dfff8023ec7843e2330bb462f19198840b34b6582397d).
///
/// NOT IMPLEMENTED: STROBE's KEY operation and merlin's `TranscriptRng`. Those
/// exist to bind a prover's secret witness to synthetic randomness; a verifier
/// never evaluates them. They are absent rather than untested.
library Merlin {
    /// STROBE rate for the 128-bit security level, in bytes. Not 136: the
    /// remaining 34 bytes are capacity plus STROBE's two reserved trailing
    /// positions.
    uint256 private constant R = 166;

    uint256 private constant FLAG_I = 1;
    uint256 private constant FLAG_A = 2;
    uint256 private constant FLAG_C = 4;
    uint256 private constant FLAG_M = 16;
    uint256 private constant FLAG_K = 32;

    /// A live STROBE-128 duplex state plus merlin's book-keeping.
    ///
    /// `st` is the 200-byte sponge state in the lane convention documented on
    /// Keccak1600. `pos` is the byte cursor within the rate, `posBegin` is the
    /// offset at which the current operation started (STROBE's framing
    /// tag), and `curFlags` exists only so that a continued operation can be
    /// checked to be the same operation, exactly as merlin asserts.
    struct Transcript {
        uint256[25] st;
        uint256 pos;
        uint256 posBegin;
        uint256 curFlags;
    }

    error ContinuedOpChangedFlags(uint256 was, uint256 now_);

    // ------------------------------------------------------- state byte access

    function _xorByte(uint256[25] memory st, uint256 i, uint256 b)
        private
        pure
    {
        unchecked {
            st[i >> 3] ^= (b & 0xff) << ((i & 7) << 3);
        }
    }

    // ------------------------------------------------------------ STROBE core

    /// merlin strobe.rs `run_f`. The two padding bytes go at the CURRENT
    /// cursor, not at the end of the rate; that is what makes STROBE's framing
    /// position-dependent and is the first thing an implementation from memory
    /// gets wrong.
    function _runF(Transcript memory t) private pure {
        unchecked {
            _xorByte(t.st, t.pos, t.posBegin);
            _xorByte(t.st, t.pos + 1, 0x04);
            _xorByte(t.st, R + 1, 0x80);
            Keccak1600.f1600(t.st);
            t.pos = 0;
            t.posBegin = 0;
        }
    }

    function _absorb(Transcript memory t, bytes memory data) private pure {
        unchecked {
            for (uint256 i = 0; i < data.length; i++) {
                _xorByte(t.st, t.pos, uint8(data[i]));
                t.pos++;
                if (t.pos == R) _runF(t);
            }
        }
    }

    function _absorbByte(Transcript memory t, uint256 b) private pure {
        unchecked {
            _xorByte(t.st, t.pos, b);
            t.pos++;
            if (t.pos == R) _runF(t);
        }
    }

    /// merlin's `encode_usize_as_u32` -- 4 bytes, LITTLE endian.
    function _absorbU32LE(Transcript memory t, uint256 v) private pure {
        unchecked {
            _absorbByte(t, v);
            _absorbByte(t, v >> 8);
            _absorbByte(t, v >> 16);
            _absorbByte(t, v >> 24);
        }
    }

    function _squeezeInto(
        Transcript memory t,
        bytes memory out,
        uint256 off,
        uint256 len
    ) private pure {
        unchecked {
            for (uint256 k = 0; k < len; k++) {
                uint256 i = off + k;
                uint256 p = t.pos;
                uint256 sh = (p & 7) << 3;
                uint256 lane = t.st[p >> 3];
                out[i] = bytes1(uint8((lane >> sh) & 0xff));
                // STROBE zeroes the squeezed byte in the state.
                t.st[p >> 3] = lane & ~(uint256(0xff) << sh);
                t.pos = p + 1;
                if (t.pos == R) _runF(t);
            }
        }
    }

    /// merlin strobe.rs `begin_op`.
    function _beginOp(Transcript memory t, uint256 flags, bool more)
        private
        pure
    {
        unchecked {
            if (more) {
                if (t.curFlags != flags) {
                    revert ContinuedOpChangedFlags(t.curFlags, flags);
                }
                return;
            }
            uint256 oldBegin = t.posBegin;
            t.posBegin = t.pos + 1;
            t.curFlags = flags;

            _absorbByte(t, oldBegin);
            _absorbByte(t, flags);

            // C and K need a fresh block before they touch the state, but only
            // if the operation header did not already land on a boundary.
            if ((flags & (FLAG_C | FLAG_K)) != 0 && t.pos != 0) _runF(t);
        }
    }

    // ---------------------------------------------------------- transcript API

    /// merlin `Transcript::new`: STROBE-128 init, meta-AD the protocol label,
    /// then append the caller's domain separator as an ordinary message.
    function init(bytes memory label)
        internal
        pure
        returns (Transcript memory t)
    {
        uint256[25] memory st;
        t = Transcript(st, 0, 0, 0);

        // strobe.rs Strobe128::new: the first 18 bytes of the state are a
        // fixed header, then one permutation. Written out byte by byte so it
        // reads as the same six numbers and the same string literal.
        bytes memory hdr = abi.encodePacked(
            uint8(1), uint8(R + 2), uint8(1), uint8(0), uint8(1), uint8(96),
            "STROBEv1.0.2"
        );
        for (uint256 i = 0; i < hdr.length; i++) {
            _xorByte(t.st, i, uint8(hdr[i]));
        }
        Keccak1600.f1600(t.st);

        _metaAd(t, "Merlin v1.0", false); // MERLIN_PROTOCOL_LABEL
        appendMessage(t, "dom-sep", label);
    }

    function _metaAd(Transcript memory t, bytes memory data, bool more)
        private
        pure
    {
        _beginOp(t, FLAG_M | FLAG_A, more);
        _absorb(t, data);
    }

    /// merlin `Transcript::append_message`:
    ///   meta-AD(label); meta-AD(LE32(len), continued); AD(message)
    ///
    /// The length is part of the METADATA operation, not of the message. A
    /// version that framed it as `AD(len || message)` produces a different
    /// state, so this split is load-bearing.
    function appendMessage(
        Transcript memory t,
        bytes memory label,
        bytes memory message
    ) internal pure {
        _metaAd(t, label, false);
        _beginOp(t, FLAG_M | FLAG_A, true);
        _absorbU32LE(t, message.length);
        _beginOp(t, FLAG_A, false);
        _absorb(t, message);
    }

    /// merlin `Transcript::append_u64`: little-endian, 8 bytes.
    function appendU64(Transcript memory t, bytes memory label, uint64 x)
        internal
        pure
    {
        appendMessage(t, label, LE.le64(x));
    }

    /// merlin `Transcript::challenge_bytes`, writing `len` bytes into `buf` at
    /// `off`. This is the primitive form; the other two are wrappers.
    ///
    /// It exists in this shape so a caller producing several challenges can
    /// accumulate them into one buffer. Concatenating afterwards would be a
    /// memory-to-memory copy, which solc compiles to MCOPY, which does not
    /// exist before Cancun.
    function challengeBytesInto(
        Transcript memory t,
        bytes memory label,
        bytes memory buf,
        uint256 off,
        uint256 len
    ) internal pure {
        _metaAd(t, label, false);
        _beginOp(t, FLAG_M | FLAG_A, true);
        // The LENGTH REQUESTED is absorbed, not the buffer's size. Squeezing
        // 32 bytes into a 64-byte buffer must give the same state as squeezing
        // 32 into a 32-byte one.
        _absorbU32LE(t, len);
        _beginOp(t, FLAG_I | FLAG_A | FLAG_C, false);
        _squeezeInto(t, buf, off, len);
    }

    /// merlin's own signature: fill `dest` completely.
    function challengeBytes(
        Transcript memory t,
        bytes memory label,
        bytes memory dest
    ) internal pure {
        challengeBytesInto(t, label, dest, 0, dest.length);
    }

    function challengeBytes(
        Transcript memory t,
        bytes memory label,
        uint256 outLen
    ) internal pure returns (bytes memory out) {
        out = new bytes(outLen);
        challengeBytesInto(t, label, out, 0, outLen);
    }

    // -------------------------------------------------- digestible AST framing

    // mc-crypto-digestible builds a small AST over the transcript. These are
    // the five node types from crypto/digestible/src/lib.rs; the separator
    // strings are its `ast_domain_separators`. Nothing here is a hash -- it is
    // all just more `append_message`, which is the point: the framing is what
    // makes the encoding injective.

    function appendPrimitive(
        Transcript memory t,
        bytes memory context,
        bytes memory typename,
        bytes memory data
    ) internal pure {
        appendMessage(t, context, "prim");
        appendMessage(t, typename, data);
    }

    function appendSeqHeader(
        Transcript memory t,
        bytes memory context,
        uint64 len
    ) internal pure {
        appendMessage(t, context, "seq");
        appendMessage(t, "len", LE.le64(len));
    }

    function appendAggHeader(
        Transcript memory t,
        bytes memory context,
        bytes memory typeName
    ) internal pure {
        appendMessage(t, context, "agg");
        appendMessage(t, "name", typeName);
    }

    function appendAggCloser(
        Transcript memory t,
        bytes memory context,
        bytes memory typeName
    ) internal pure {
        appendMessage(t, context, "agg-end");
        appendMessage(t, "name", typeName);
    }

    function appendVarHeader(
        Transcript memory t,
        bytes memory context,
        bytes memory typeName,
        uint32 which
    ) internal pure {
        appendMessage(t, context, "var");
        appendMessage(t, "name", typeName);
        appendMessage(t, "which", LE.le32(which));
    }

    /// The absence of data. Note the separator is the EMPTY string, so this is
    /// `append_message(context, "")` and not a no-op.
    function appendNone(Transcript memory t, bytes memory context)
        internal
        pure
    {
        appendMessage(t, context, "");
    }

    /// `Digestible::digest32`'s finaliser.
    function extractDigest(Transcript memory t) internal pure returns (bytes32) {
        return bytes32(_word(challengeBytes(t, "digest32", 32)));
    }

    // ----------------------------------------------------------------- helpers

    function _word(bytes memory b) private pure returns (uint256 v) {
        assembly {
            v := mload(add(b, 32))
        }
    }
}

/// MobileCoin's two block digests, recomputed on Ethereum: the block id,
/// and the digest a validator's `BlockSignature` covers.
///
/// Mirrors `compute_block_id` in mobilecoin 05cb699f
/// blockchain/types/src/block.rs, which is
///
///     let mut transcript = MerlinTranscript::new(b"mobilecoin-block-id");
///     version.append_to_transcript(b"version", &mut transcript);
///     parent_id.append_to_transcript(b"parent_id", &mut transcript);
///     index.append_to_transcript(b"index", &mut transcript);
///     cumulative_txo_count.append_to_transcript(b"cumulative_txo_count", ..);
///     root_element.append_to_transcript(b"root_element", &mut transcript);
///     contents_hash.append_to_transcript(b"contents_hash", &mut transcript);
///     transcript.extract_digest(&mut result);
///
/// expanded through the Digestible impls:
///
///   * `u32`/`u64` -> primitive, typename "uint", little-endian bytes
///     (crypto/digestible/src/lib.rs).
///   * `BlockID`, `BlockContentsHash`, `TxOutMembershipHash` are
///     `#[digestible(transparent)]` newtypes over `[u8; 32]`, and `[u8; N]` is
///     `DigestibleAsBytes`, so each collapses to a primitive with typename
///     "bytes" and no wrapper node of its own.
///   * `TxOutMembershipElement` and `Range` are ordinary derived structs, so
///     each is an aggregate node named after the Rust type, with its fields
///     appended under their Rust field names, in declaration order
///     (crypto/digestible/derive/src/lib.rs, `try_digestible_struct`).
///
/// The derive appends struct fields via `append_to_transcript_allow_omit`,
/// which for these field types is identical to `append_to_transcript`: the
/// omit path only fires for empty byte slices, strings and sequences, and a
/// `[u8; 32]` is never empty and a `u64` has no omit path at all. So nothing
/// here is conditional, which is why this function takes plain arguments and
/// has no "was this field present" flags.
library MobileCoinBlock {
    using Merlin for Merlin.Transcript;

    /// `compute_block_id`: the six fields under protocol "mobilecoin-block-id".
    function id(
        uint32 version,
        bytes32 parentId,
        uint64 index,
        uint64 cumulativeTxoCount,
        uint64 rootRangeFrom,
        uint64 rootRangeTo,
        bytes32 rootHash,
        bytes32 contentsHash
    ) internal pure returns (bytes32) {
        Merlin.Transcript memory t = Merlin.init("mobilecoin-block-id");
        _fields(
            t, version, parentId, index, cumulativeTxoCount,
            rootRangeFrom, rootRangeTo, rootHash, contentsHash
        );
        return t.extractDigest();
    }

    /// The digest a validator's `BlockSignature` covers:
    /// `block.digest32::<MerlinTranscript>(b"block-sig")`.
    ///
    /// `digest32` opens a fresh transcript under the generic "digestible"
    /// protocol and appends the whole struct under the caller's context, so
    /// relative to `id` this wraps the same field walk in an aggregate node
    /// ("block-sig" -> Block) and includes the block's own `id` field --
    /// `Block` stores it, so the signature covers it. That embedded id is why
    /// a verifier checking this digest binds the id transitively.
    ///
    /// Every validator signs THIS SAME value. That is what makes this route's
    /// hashing constant in the quorum size, where the metadata route's is
    /// linear: metadata signatures each cover per-node attestation evidence,
    /// so no two validators sign the same bytes.
    function sigDigest(
        bytes32 blockId,
        uint32 version,
        bytes32 parentId,
        uint64 index,
        uint64 cumulativeTxoCount,
        uint64 rootRangeFrom,
        uint64 rootRangeTo,
        bytes32 rootHash,
        bytes32 contentsHash
    ) internal pure returns (bytes32) {
        Merlin.Transcript memory t = Merlin.init("digestible");
        t.appendAggHeader("block-sig", "Block");
        t.appendPrimitive("id", "bytes", abi.encodePacked(blockId));
        _fields(
            t, version, parentId, index, cumulativeTxoCount,
            rootRangeFrom, rootRangeTo, rootHash, contentsHash
        );
        t.appendAggCloser("block-sig", "Block");
        return t.extractDigest();
    }

    /// The field walk both digests share: `Block`'s fields minus `id`, in
    /// declaration order, exactly as the Digestible derive expands them.
    function _fields(
        Merlin.Transcript memory t,
        uint32 version,
        bytes32 parentId,
        uint64 index,
        uint64 cumulativeTxoCount,
        uint64 rootRangeFrom,
        uint64 rootRangeTo,
        bytes32 rootHash,
        bytes32 contentsHash
    ) private pure {
        t.appendPrimitive("version", "uint", LE.le32(version));
        t.appendPrimitive("parent_id", "bytes", abi.encodePacked(parentId));
        t.appendPrimitive("index", "uint", LE.le64(index));
        t.appendPrimitive(
            "cumulative_txo_count", "uint", LE.le64(cumulativeTxoCount)
        );

        t.appendAggHeader("root_element", "TxOutMembershipElement");
        t.appendAggHeader("range", "Range");
        t.appendPrimitive("from", "uint", LE.le64(rootRangeFrom));
        t.appendPrimitive("to", "uint", LE.le64(rootRangeTo));
        t.appendAggCloser("range", "Range");
        t.appendPrimitive("hash", "bytes", abi.encodePacked(rootHash));
        t.appendAggCloser("root_element", "TxOutMembershipElement");

        t.appendPrimitive(
            "contents_hash", "bytes", abi.encodePacked(contentsHash)
        );
    }
}


/// A MobileCoin `TxOut`'s own digest -- the preimage of its Merkle leaf.
///
/// This is what binds a membership proof to a SPECIFIC output. Without it a
/// verifier is told "some output is in this block" by the Merkle path and
/// "here is its public key and value" by the caller, with nothing relating the
/// two: one genuinely included output could then be redeemed repeatedly under
/// invented public keys and amounts. Recomputing the leaf preimage from the
/// output's own fields is what makes the proof about the output it claims.
///
/// Mirrors `TxOut::hash` -> `digest32::<MerlinTranscript>(b"mobilecoin-txout")`
/// in mobilecoin 05cb699f transaction/core/src/tx.rs, expanded through the
/// Digestible derive. `MaskedAmountV2` and `EncryptedMemo` are ordinary derived
/// structs, so each is an aggregate node named after the Rust type; the memo's
/// single tuple field is appended under the context "0".
library MobileCoinTxOut {
    using Merlin for Merlin.Transcript;

    /// `eFogHint` and `eMemo` are fixed-width upstream (84 and 66 bytes) but
    /// are taken as `bytes` so a future block version that resizes them does
    /// not silently truncate here.
    function digest(
        bytes32 commitment,
        uint64 maskedValue,
        bytes memory maskedTokenId,
        bytes32 targetKey,
        bytes32 publicKey,
        bytes memory eFogHint,
        bytes memory eMemo
    ) internal pure returns (bytes32) {
        Merlin.Transcript memory t = Merlin.init("digestible");
        t.appendAggHeader("mobilecoin-txout", "TxOut");

        t.appendAggHeader("amount", "MaskedAmountV2");
        t.appendPrimitive("commitment", "ristretto", abi.encodePacked(commitment));
        t.appendPrimitive("masked_value", "uint", LE.le64(maskedValue));
        t.appendPrimitive("masked_token_id", "bytes", maskedTokenId);
        t.appendAggCloser("amount", "MaskedAmountV2");

        t.appendPrimitive("target_key", "ristretto", abi.encodePacked(targetKey));
        t.appendPrimitive("public_key", "ristretto", abi.encodePacked(publicKey));
        t.appendPrimitive("e_fog_hint", "bytes", eFogHint);

        t.appendAggHeader("e_memo", "EncryptedMemo");
        t.appendPrimitive("0", "bytes", eMemo);
        t.appendAggCloser("e_memo", "EncryptedMemo");

        t.appendAggCloser("mobilecoin-txout", "TxOut");
        return t.extractDigest();
    }
}

/// TEST ONLY -- NEVER DEPLOY.
///
/// It lives in this file, and not in `src/TestMocks.sol` with the other
/// test-only contracts, because a wrapper for `internal` functions has to be
/// compiled against the library that declares them. That is a constraint, not
/// an exemption: `contracts/test/deployables.mjs` enumerates every contract in
/// `src/` and fails unless it is either on the deployable allowlist or marked
/// exactly like this one, so a production contract cannot arrive here unnamed.
///
/// Test-facing surface: a tiny interpreter so a fixture can drive an arbitrary
/// sequence of transcript operations without a bespoke contract per case.
///
/// Script format, all integers BIG endian (this is only the test wire format;
/// the transcript's own encodings are little endian and live in Merlin):
///
///   every op: u8 opcode, u16 ctxLen, ctx
///     0x00 append_message   u32 msgLen, msg
///     0x01 challenge_bytes  u32 outLen           -- appends outLen to output
///     0x02 append_u64       u64 value
///     0x03 append_primitive u16 tnLen, tn, u32 dataLen, data
///     0x04 append_none
///     0x05 append_seq_header u64 len
///     0x06 append_agg_header u16 nameLen, name
///     0x07 append_agg_closer u16 nameLen, name
///     0x08 append_var_header u16 nameLen, name, u32 which
///
/// `run` returns a HASH of the concatenated challenge output rather than the
/// output itself, plus its length and its first 32 bytes for diagnosis. Not a
/// design preference: this repo's test harness runs a Shanghai EVM while solc
/// 0.8.26 targets Cancun, so returning a dynamic `bytes` -- which compiles to
/// MCOPY -- is an invalid opcode there. Comparing keccak256 of the whole
/// output is the same assertion.
contract MerlinProbe_DO_NOT_DEPLOY {
    using Merlin for Merlin.Transcript;

    error BadOpcode(uint8 opcode);
    error OutputTooLong(uint256 need, uint256 cap);

    uint256 private constant OUT_CAP = 4096;

    function run(bytes calldata label, bytes calldata script)
        external
        pure
        returns (bytes32 outHash, uint256 outLen, bytes32 head)
    {
        Merlin.Transcript memory t = Merlin.init(label);
        bytes memory acc = new bytes(OUT_CAP);
        uint256 used = 0;

        uint256 i = 0;
        while (i < script.length) {
            uint8 op = uint8(script[i]);
            i += 1;
            uint256 ctxLen = _be(script, i, 2);
            i += 2;
            bytes memory ctx = script[i:i + ctxLen];
            i += ctxLen;

            if (op == 0x00) {
                uint256 n = _be(script, i, 4);
                i += 4;
                t.appendMessage(ctx, script[i:i + n]);
                i += n;
            } else if (op == 0x01) {
                uint256 n = _be(script, i, 4);
                i += 4;
                if (used + n > OUT_CAP) revert OutputTooLong(used + n, OUT_CAP);
                t.challengeBytesInto(ctx, acc, used, n);
                used += n;
            } else if (op == 0x02) {
                t.appendU64(ctx, uint64(_be(script, i, 8)));
                i += 8;
            } else if (op == 0x03) {
                uint256 tn = _be(script, i, 2);
                i += 2;
                bytes memory typename = script[i:i + tn];
                i += tn;
                uint256 n = _be(script, i, 4);
                i += 4;
                t.appendPrimitive(ctx, typename, script[i:i + n]);
                i += n;
            } else if (op == 0x04) {
                t.appendNone(ctx);
            } else if (op == 0x05) {
                t.appendSeqHeader(ctx, uint64(_be(script, i, 8)));
                i += 8;
            } else if (op == 0x06 || op == 0x07) {
                uint256 n = _be(script, i, 2);
                i += 2;
                bytes memory name = script[i:i + n];
                i += n;
                if (op == 0x06) t.appendAggHeader(ctx, name);
                else t.appendAggCloser(ctx, name);
            } else if (op == 0x08) {
                uint256 n = _be(script, i, 2);
                i += 2;
                bytes memory name = script[i:i + n];
                i += n;
                t.appendVarHeader(ctx, name, uint32(_be(script, i, 4)));
                i += 4;
            } else {
                revert BadOpcode(op);
            }
        }

        outLen = used;
        assembly {
            outHash := keccak256(add(acc, 32), used)
            head := mload(add(acc, 32))
        }
    }

    function blockId(
        uint32 version,
        bytes32 parentId,
        uint64 index,
        uint64 cumulativeTxoCount,
        uint64 rootRangeFrom,
        uint64 rootRangeTo,
        bytes32 rootHash,
        bytes32 contentsHash
    ) external pure returns (bytes32) {
        return MobileCoinBlock.id(
            version,
            parentId,
            index,
            cumulativeTxoCount,
            rootRangeFrom,
            rootRangeTo,
            rootHash,
            contentsHash
        );
    }

    function txOutDigest(
        bytes32 commitment,
        uint64 maskedValue,
        bytes calldata maskedTokenId,
        bytes32 targetKey,
        bytes32 publicKey,
        bytes calldata eFogHint,
        bytes calldata eMemo
    ) external pure returns (bytes32) {
        return MobileCoinTxOut.digest(
            commitment, maskedValue, maskedTokenId,
            targetKey, publicKey, eFogHint, eMemo
        );
    }

    function blockSigDigest(
        bytes32 blockId_,
        uint32 version,
        bytes32 parentId,
        uint64 index,
        uint64 cumulativeTxoCount,
        uint64 rootRangeFrom,
        uint64 rootRangeTo,
        bytes32 rootHash,
        bytes32 contentsHash
    ) external pure returns (bytes32) {
        return MobileCoinBlock.sigDigest(
            blockId_,
            version,
            parentId,
            index,
            cumulativeTxoCount,
            rootRangeFrom,
            rootRangeTo,
            rootHash,
            contentsHash
        );
    }

    function _be(bytes calldata b, uint256 off, uint256 len)
        private
        pure
        returns (uint256 v)
    {
        for (uint256 k = 0; k < len; k++) {
            v = (v << 8) | uint8(b[off + k]);
        }
    }
}
