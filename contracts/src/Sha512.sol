// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// SHA-512, per FIPS 180-4.
///
/// Ed25519 is defined over SHA-512 and nothing else -- RFC 8032 fixes the hash
/// as part of the signature scheme, so there is no substituting the cheap
/// keccak256 the EVM already has. Ethereum offers no SHA-512 precompile
/// (SHA-256 at 0x02 is a different function, not a truncation of this one), so
/// the compression function has to be executed in EVM words.
///
/// The 64-bit lanes SHA-512 is built from are the expensive part: every lane
/// operation the spec writes as one instruction becomes a shift, a mask and an
/// or. That cost is inherent, not an artefact of this implementation.
library Sha512 {
    /// Returned as two words rather than a 64-byte `bytes` so that callers who
    /// only need the digest as an integer (Ed25519 needs exactly that) do not
    /// pay for an allocation and a re-read.
    ///
    /// `hi` is digest bytes 0..31, `lo` is bytes 32..63, both big-endian as the
    /// standard emits them.
    function hash(bytes memory message)
        internal
        pure
        returns (bytes32 hi, bytes32 lo)
    {
        return _compress(_pad(bytes32(0), bytes32(0), 0, message));
    }

    /// Digest of `p0 || p1 || message`, without ever materialising the
    /// concatenation.
    ///
    /// Ed25519 hashes R || A || M and nothing else, and `abi.encodePacked`
    /// would allocate a second copy of M to build that. The prefix instead
    /// goes straight into the padded buffer the compression function was
    /// always going to need. Avoiding the compiler's memory-to-memory copy is
    /// also what keeps this runnable pre-Cancun: solc lowers such a copy to
    /// MCOPY, and the EVM the test harness runs is Shanghai.
    function hashPrefixed(bytes32 p0, bytes32 p1, bytes memory message)
        internal
        pure
        returns (bytes32 hi, bytes32 lo)
    {
        return _compress(_pad(p0, p1, 64, message));
    }

    // --------------------------------------------------------------- internal

    function _compress(bytes memory p)
        private
        pure
        returns (bytes32 hi, bytes32 lo)
    {
        // Round constants K[0..79]: the first 64 bits of the fractional parts
        // of the cube roots of the first eighty primes (FIPS 180-4 s4.2.3).
        bytes memory k = hex"428a2f98d728ae227137449123ef65cd"
            hex"b5c0fbcfec4d3b2fe9b5dba58189dbbc3956c25bf348b53859f111f1b605d019"
            hex"923f82a4af194f9bab1c5ed5da6d8118d807aa98a303024212835b0145706fbe"
            hex"243185be4ee4b28c550c7dc3d5ffb4e272be5d74f27b896f80deb1fe3b1696b1"
            hex"9bdc06a725c71235c19bf174cf692694e49b69c19ef14ad2efbe4786384f25e3"
            hex"0fc19dc68b8cd5b5240ca1cc77ac9c652de92c6f592b02754a7484aa6ea6e483"
            hex"5cb0a9dcbd41fbd476f988da831153b5983e5152ee66dfaba831c66d2db43210"
            hex"b00327c898fb213fbf597fc7beef0ee4c6e00bf33da88fc2d5a79147930aa725"
            hex"06ca6351e003826f142929670a0e6e7027b70a8546d22ffc2e1b21385c26c926"
            hex"4d2c6dfc5ac42aed53380d139d95b3df650a73548baf63de766a0abb3c77b2a8"
            hex"81c2c92e47edaee692722c851482353ba2bfe8a14cf10364a81a664bbc423001"
            hex"c24b8b70d0f89791c76c51a30654be30d192e819d6ef5218d69906245565a910"
            hex"f40e35855771202a106aa07032bbd1b819a4c116b8d2d0c81e376c085141ab53"
            hex"2748774cdf8eeb9934b0bcb5e19b48a8391c0cb3c5c95a634ed8aa4ae3418acb"
            hex"5b9cca4f7763e373682e6ff3d6b2b8a3748f82ee5defb2fc78a5636f43172f60"
            hex"84c87814a1f0ab728cc702081a6439ec90befffa23631e28a4506cebde82bde9"
            hex"bef9a3f7b2c67915c67178f2e372532bca273eceea26619cd186b8c721c0c207"
            hex"eada7dd6cde0eb1ef57d4f7fee6ed17806f067aa72176fba0a637dc5a2c898a6"
            hex"113f9804bef90dae1b710b35131c471b28db77f523047d8432caab7b40c72493"
            hex"3c9ebe0a15c9bebc431d67c49c100d4c4cc5d4becb3e42b6597f299cfc657e2a"
            hex"5fcb6fab3ad6faec6c44198c4a475817";

        // Initial state: first 64 bits of the fractional parts of the square
        // roots of the first eight primes (FIPS 180-4 s5.3.5).
        uint64 h0 = 0x6a09e667f3bcc908;
        uint64 h1 = 0xbb67ae8584caa73b;
        uint64 h2 = 0x3c6ef372fe94f82b;
        uint64 h3 = 0xa54ff53a5f1d36f1;
        uint64 h4 = 0x510e527fade682d1;
        uint64 h5 = 0x9b05688c2b3e6c1f;
        uint64 h6 = 0x1f83d9abfb41bd6b;
        uint64 h7 = 0x5be0cd19137e2179;

        // Allocated once and reused across blocks; the schedule is fully
        // overwritten each block, so carrying it over is safe.
        uint64[80] memory w;

        unchecked {
            uint256 nblocks = p.length / 128;
            for (uint256 b = 0; b < nblocks; ++b) {
                uint256 off = b * 128;
                for (uint256 t = 0; t < 16; ++t) {
                    w[t] = _load64(p, off + t * 8);
                }
                for (uint256 t = 16; t < 80; ++t) {
                    uint64 x = w[t - 15];
                    uint64 y = w[t - 2];
                    w[t] = w[t - 16]
                        + (_rotr(x, 1) ^ _rotr(x, 8) ^ (x >> 7))
                        + w[t - 7]
                        + (_rotr(y, 19) ^ _rotr(y, 61) ^ (y >> 6));
                }

                uint64 a = h0;
                uint64 bb = h1;
                uint64 c = h2;
                uint64 d = h3;
                uint64 e = h4;
                uint64 f = h5;
                uint64 g = h6;
                uint64 hh = h7;

                for (uint256 t = 0; t < 80; ++t) {
                    uint64 t1 = hh
                        + (_rotr(e, 14) ^ _rotr(e, 18) ^ _rotr(e, 41))
                        + ((e & f) ^ (~e & g))
                        + _load64(k, t * 8)
                        + w[t];
                    uint64 t2 = (_rotr(a, 28) ^ _rotr(a, 34) ^ _rotr(a, 39))
                        + ((a & bb) ^ (a & c) ^ (bb & c));
                    hh = g;
                    g = f;
                    f = e;
                    e = d + t1;
                    d = c;
                    c = bb;
                    bb = a;
                    a = t1 + t2;
                }

                h0 += a;
                h1 += bb;
                h2 += c;
                h3 += d;
                h4 += e;
                h5 += f;
                h6 += g;
                h7 += hh;
            }
        }

        hi = bytes32(
            (uint256(h0) << 192) | (uint256(h1) << 128) | (uint256(h2) << 64)
                | uint256(h3)
        );
        lo = bytes32(
            (uint256(h4) << 192) | (uint256(h5) << 128) | (uint256(h6) << 64)
                | uint256(h7)
        );
    }

    /// Big-endian 8 bytes at `off` within the data section of `b`.
    function _load64(bytes memory b, uint256 off)
        private
        pure
        returns (uint64 v)
    {
        assembly {
            v := shr(192, mload(add(add(b, 32), off)))
        }
    }

    function _rotr(uint64 x, uint256 n) private pure returns (uint64) {
        // uint64 shifts truncate rather than overflow-check, so the left half
        // needs no explicit mask.
        return (x >> n) | (x << (64 - n));
    }

    /// Lay out `p0 || p1 || m` (the prefix included only when `pre` is 64) and
    /// pad it: 0x80, zero-fill, then the length in bits as a big-endian 128-bit
    /// integer, out to a multiple of the 1024-bit block size.
    function _pad(bytes32 p0, bytes32 p1, uint256 pre, bytes memory m)
        private
        pure
        returns (bytes memory p)
    {
        uint256 len = pre + m.length;
        // len + 1 terminator + 16 length bytes, rounded up to a whole block.
        uint256 total = ((len + 17 + 127) / 128) * 128;
        p = new bytes(total);

        // `pre` is a whole number of words, so the message copy below stays
        // word-aligned in both buffers and the tail analysis is unaffected.
        if (pre == 64) {
            assembly {
                mstore(add(p, 32), p0)
                mstore(add(p, 64), p1)
            }
        }

        uint256 nfull = m.length & ~uint256(31);
        uint256 rem = m.length - nfull;
        assembly {
            let src := add(m, 32)
            let dst := add(add(p, 32), pre)
            for { let i := 0 } lt(i, nfull) { i := add(i, 32) } {
                mstore(add(dst, i), mload(add(src, i)))
            }
            // The tail is written through a mask so the copy cannot spill past
            // the end of `p` into the next allocation. `total - pre - nfull >=
            // 32` always holds, so this store itself is in bounds.
            if rem {
                let mask := not(shr(shl(3, rem), not(0)))
                mstore(add(dst, nfull), and(mload(add(src, nfull)), mask))
            }
        }

        p[len] = 0x80;
        // Bit length. A `bytes` in memory cannot approach 2^64 bytes, so only
        // the low 64 bits of the 128-bit length field can ever be non-zero.
        uint256 bits = len * 8;
        assembly {
            // OR rather than store: the same word can also hold the 0x80
            // terminator when the message ends within 32 bytes of the block
            // boundary. The low 8 bytes are guaranteed zero because the
            // terminator sits at index len <= total - 17.
            let ptr := add(add(p, 32), sub(total, 32))
            mstore(ptr, or(mload(ptr), bits))
        }
    }
}
