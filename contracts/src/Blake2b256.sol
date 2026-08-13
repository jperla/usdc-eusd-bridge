// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {LE} from "./LE.sol";

/// Blake2b, built on the EIP-152 compression-function precompile at 0x09.
///
/// MobileCoin hashes its TxOut Merkle tree with Blake2b-256 under domain tags
/// (`mc_tx_out_merkle_leaf`, `mc_tx_out_merkle_node`) and derives one-time key
/// scalars with Blake2b-512, so the Ethereum side has to reproduce Blake2b
/// exactly at two digest lengths. Ethereum does not expose Blake2b as a hash
/// -- 0x09 is only the compression function F -- so the padding, parameter
/// block, counter and final-block flag are all explicit here. That framing is
/// the part that is easy to get subtly wrong, and a wrong Merkle hash means
/// membership proofs can be forged.
///
/// NOT a general Blake2b: unkeyed only. A key needs both a different parameter
/// block and a prepended key block.
///
/// Cheap: F costs 1 gas per round, 12 rounds per block.
library Blake2b {
    error Blake2fFailed();

    /// Blake2b IV, the same constants as SHA-512's.
    function _iv() private pure returns (uint64[8] memory v) {
        v[0] = 0x6a09e667f3bcc908;
        v[1] = 0xbb67ae8584caa73b;
        v[2] = 0x3c6ef372fe94f82b;
        v[3] = 0xa54ff53a5f1d36f1;
        v[4] = 0x510e527fade682d1;
        v[5] = 0x9b05688c2b3e6c1f;
        v[6] = 0x1f83d9abfb41bd6b;
        v[7] = 0x5be0cd19137e2179;
    }

    /// One call to the F precompile.
    ///
    /// The precompile takes big-endian rounds, then h and m as LITTLE-endian
    /// 64-bit words, then the two little-endian counter words, then the final
    /// flag. Getting that endianness wrong produces a plausible-looking hash
    /// that matches nothing.
    function _f(
        uint64[8] memory h,
        uint64[16] memory m,
        uint128 t,
        bool last
    ) private view returns (uint64[8] memory out) {
        bytes memory args = new bytes(213);
        args[3] = 0x0c; // rounds = 12, big-endian uint32
        uint256 off = 4;
        for (uint256 i = 0; i < 8; i++) off = LE.put64(args, off, h[i]);
        for (uint256 i = 0; i < 16; i++) off = LE.put64(args, off, m[i]);
        off = LE.put64(args, off, uint64(t));
        LE.put64(args, off, uint64(t >> 64));
        args[212] = last ? bytes1(0x01) : bytes1(0x00);

        bytes memory ret = new bytes(64);
        bool ok;
        assembly {
            ok := staticcall(gas(), 0x09, add(args, 32), 213, add(ret, 32), 64)
        }
        if (!ok) revert Blake2fFailed();
        for (uint256 i = 0; i < 8; i++) out[i] = LE.get64(ret, i * 8);
    }

    /// Blake2b of `input` with a `digestLen`-byte digest, no key, as the eight
    /// little-endian state words: the digest is the first `digestLen` bytes of
    /// those words written out little-endian, so a 256-bit caller keeps words
    /// 0..3 and a 512-bit caller keeps all eight.
    ///
    /// `digestLen` goes into the parameter block, so the two lengths are
    /// independent functions -- the first half of a 512-bit digest is NOT the
    /// 256-bit digest of the same input.
    function hashWords(bytes memory input, uint256 digestLen)
        internal
        view
        returns (uint64[8] memory h)
    {
        h = _iv();
        // Parameter block: digest length, key length 0, fanout 1, depth 1.
        h[0] ^= 0x01010000 ^ uint64(digestLen);

        uint256 len = input.length;
        uint256 blocks = len == 0 ? 1 : (len + 127) / 128;

        for (uint256 b = 0; b < blocks; b++) {
            uint64[16] memory m;
            uint256 base = b * 128;
            for (uint256 w = 0; w < 16; w++) {
                uint64 word = 0;
                for (uint256 i = 0; i < 8; i++) {
                    uint256 idx = base + w * 8 + i;
                    if (idx < len) {
                        word |= uint64(uint8(input[idx])) << (8 * i);
                    }
                }
                m[w] = word;
            }
            bool last = (b == blocks - 1);
            // The counter is the number of bytes absorbed SO FAR INCLUDING this
            // block -- and for the final block that is the true message length,
            // not a padded multiple of 128.
            uint128 t = last ? uint128(len) : uint128((b + 1) * 128);
            h = _f(h, m, t, last);
        }
    }
}

/// Blake2b-256, and the MobileCoin Merkle hashes built from it.
library Blake2b256 {
    function hash(bytes memory input) internal view returns (bytes32) {
        uint64[8] memory h = Blake2b.hashWords(input, 32);
        bytes memory out = new bytes(32);
        uint256 o = 0;
        for (uint256 i = 0; i < 4; i++) o = LE.put64(out, o, h[i]);
        return bytes32(out);
    }

    // ------------------------------------------------- MobileCoin Merkle tags

    function hashLeaf(bytes32 txOutHash) internal view returns (bytes32) {
        return hash(abi.encodePacked("mc_tx_out_merkle_leaf", txOutHash));
    }

    function hashNodes(bytes32 l, bytes32 r) internal view returns (bytes32) {
        return hash(abi.encodePacked("mc_tx_out_merkle_node", l, r));
    }
}

/// Test wrapper: libraries with internal functions have no ABI of their own.
contract Blake2b256Probe {
    function hash(bytes memory input) external view returns (bytes32) {
        return Blake2b256.hash(input);
    }

    function hashLeaf(bytes32 h) external view returns (bytes32) {
        return Blake2b256.hashLeaf(h);
    }

    function hashNodes(bytes32 l, bytes32 r) external view returns (bytes32) {
        return Blake2b256.hashNodes(l, r);
    }

    /// Blake2b-512 as two halves of the digest, in digest order.
    ///
    /// Exposed so the 512-bit length can be cross-checked against an
    /// independent implementation directly. Nothing else reaches it that way:
    /// MobileCoin's scalar hash reduces the digest mod L, which would hide a
    /// wrong digest behind a plausible scalar.
    function hash512(bytes memory input)
        external
        view
        returns (bytes32 lo, bytes32 hi)
    {
        uint64[8] memory h = Blake2b.hashWords(input, 64);
        bytes memory a = new bytes(32);
        bytes memory b = new bytes(32);
        uint256 o = 0;
        for (uint256 i = 0; i < 4; i++) o = LE.put64(a, o, h[i]);
        o = 0;
        for (uint256 i = 0; i < 4; i++) o = LE.put64(b, o, h[4 + i]);
        return (bytes32(a), bytes32(b));
    }
}
