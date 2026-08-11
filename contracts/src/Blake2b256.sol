// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// Blake2b-256, built on the EIP-152 compression-function precompile at 0x09.
///
/// MobileCoin hashes its TxOut Merkle tree with Blake2b-256 under domain tags
/// (`mc_tx_out_merkle_leaf`, `mc_tx_out_merkle_node`), so an Ethereum-side
/// membership check has to reproduce Blake2b exactly. Ethereum does not expose
/// Blake2b as a hash -- 0x09 is only the compression function F -- so the
/// padding, parameter block, counter and final-block flag are all explicit
/// here. That framing is the part that is easy to get subtly wrong, and a
/// wrong Merkle hash means membership proofs can be forged.
///
/// Cheap: F costs 1 gas per round, 12 rounds per block.
library Blake2b256 {
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
        assembly {
            let p := add(args, 32)
            // rounds: 12, big-endian uint32
            mstore8(add(p, 3), 12)
        }
        uint256 off = 4;
        for (uint256 i = 0; i < 8; i++) off = _putLE64(args, off, h[i]);
        for (uint256 i = 0; i < 16; i++) off = _putLE64(args, off, m[i]);
        off = _putLE64(args, off, uint64(t));
        off = _putLE64(args, off, uint64(t >> 64));
        args[212] = last ? bytes1(0x01) : bytes1(0x00);

        bytes memory ret = new bytes(64);
        bool ok;
        assembly {
            ok := staticcall(gas(), 0x09, add(args, 32), 213, add(ret, 32), 64)
        }
        require(ok, "blake2f");
        for (uint256 i = 0; i < 8; i++) out[i] = _getLE64(ret, i * 8);
    }

    function _putLE64(bytes memory b, uint256 off, uint64 v)
        private
        pure
        returns (uint256)
    {
        for (uint256 i = 0; i < 8; i++) {
            b[off + i] = bytes1(uint8(v >> (8 * i)));
        }
        return off + 8;
    }

    function _getLE64(bytes memory b, uint256 off)
        private
        pure
        returns (uint64 v)
    {
        for (uint256 i = 0; i < 8; i++) {
            v |= uint64(uint8(b[off + i])) << (8 * i);
        }
    }

    /// Blake2b-256 of `input`, no key.
    function hash(bytes memory input) internal view returns (bytes32) {
        uint64[8] memory h = _iv();
        // Parameter block: digest length 32, key length 0, fanout 1, depth 1.
        h[0] ^= 0x01010000 ^ 32;

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

        bytes memory out = new bytes(32);
        uint256 o = 0;
        for (uint256 i = 0; i < 4; i++) o = _putLE64(out, o, h[i]);
        return bytes32(out);
    }

    // ------------------------------------------------- MobileCoin Merkle tags

    function hashLeaf(bytes32 txOutHash) internal view returns (bytes32) {
        return hash(abi.encodePacked("mc_tx_out_merkle_leaf", txOutHash));
    }

    function hashNodes(bytes32 l, bytes32 r) internal view returns (bytes32) {
        return hash(abi.encodePacked("mc_tx_out_merkle_node", l, r));
    }

    function hashNil() internal view returns (bytes32) {
        return hash(abi.encodePacked("mc_tx_out_merkle_nil"));
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
}
