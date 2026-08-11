// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// The raw Keccak-f[1600] permutation.
///
/// The EVM's `keccak256` opcode computes a full hash and does not expose the
/// permutation, so STROBE -- which absorbs and squeezes at byte granularity
/// with its own padding and its own rate (166, not 136) -- cannot be built on
/// top of it. This library exists because MobileCoin digests block headers
/// through Merlin, Merlin is STROBE, and STROBE is this permutation.
///
/// The body is a port of the implementation gated in gas-measurement's
/// Primitives.sol. It is kept structurally identical to that version rather
/// than optimised, because the whole value of a port is that it is the same
/// algorithm. `keccak.mjs` re-tests it here on this repo's compiler settings
/// against FIPS 202 and against the Keccak team's intermediate values, on all
/// 25 lanes -- an earlier version of this permutation elsewhere omitted rho,
/// pi and the round constants and still matched lane 0.
///
/// STATE CONVENTION. A lane is a 64-bit value held in the low bits of a
/// uint256; the high 192 bits of every entry are always zero. Lane i of the
/// 200-byte sponge state is the LITTLE-ENDIAN interpretation of bytes
/// [8i, 8i+8). That is the same convention the Rust `keccak` crate gets from
/// transmuting `[u8; 200]` to `[u64; 25]` on a little-endian target, which is
/// what merlin relies on.
library Keccak1600 {
    uint256 private constant MASK64 = 0xFFFFFFFFFFFFFFFF;

    function _rol(uint256 x, uint256 n) private pure returns (uint256) {
        if (n == 0) return x & MASK64;
        return ((x << n) | ((x & MASK64) >> (64 - n))) & MASK64;
    }

    /// Permute `a` IN PLACE. The return value is the same memory reference,
    /// returned only for call-site convenience; callers that already hold `a`
    /// may ignore it. In-place is deliberate: the STROBE state lives inside a
    /// struct and must not be silently copied out from under it.
    function f1600(uint256[25] memory a)
        internal
        pure
        returns (uint256[25] memory)
    {
        uint8[25] memory rho = [
            uint8(0), 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39,
            41, 45, 15, 21, 8, 18, 2, 61, 56, 14
        ];
        uint64[24] memory rc = [
            uint64(0x0000000000000001), 0x0000000000008082, 0x800000000000808A,
            0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
            0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
            0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
            0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
            0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
            0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
            0x8000000000008080, 0x0000000080000001, 0x8000000080008008
        ];
        uint256[5] memory c;
        uint256[5] memory d;
        uint256[25] memory b;
        for (uint256 r = 0; r < 24; r++) {
            for (uint256 x = 0; x < 5; x++) {
                c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
            }
            for (uint256 x = 0; x < 5; x++) {
                d[x] = c[(x + 4) % 5] ^ _rol(c[(x + 1) % 5], 1);
            }
            for (uint256 x = 0; x < 5; x++) {
                for (uint256 y = 0; y < 25; y += 5) { a[y + x] ^= d[x]; }
            }
            for (uint256 x = 0; x < 5; x++) {
                for (uint256 y = 0; y < 5; y++) {
                    b[((2 * x + 3 * y) % 5) * 5 + y] =
                        _rol(a[y * 5 + x], rho[y * 5 + x]);
                }
            }
            for (uint256 y = 0; y < 25; y += 5) {
                for (uint256 x = 0; x < 5; x++) {
                    a[y + x] = b[y + x] ^
                        ((~b[y + (x + 1) % 5]) & b[y + (x + 2) % 5] & MASK64);
                }
            }
            a[0] ^= rc[r];
        }
        return a;
    }
}

/// Test-facing surface. Lives here rather than in the test directory because
/// the harness compiles `src/` and calls real bytecode; there is no other way
/// to reach an `internal` library function from a test.
contract Keccak1600Probe {
    function f1600(uint256[25] memory a)
        external
        pure
        returns (uint256[25] memory)
    {
        return Keccak1600.f1600(a);
    }
}
