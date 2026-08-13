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
/// NOT a hash. There is no padding, no rate and no domain separation here --
/// those belong to whatever sponge wraps this, and omitting them makes the
/// output of `f1600` alone meaningless as a digest.
///
/// TWO IMPLEMENTATIONS, ONE ALGORITHM. `f1600` is hand-written Yul and is the
/// one every caller runs. `f1600Reference` is the straightforward Solidity
/// port that came first: it is kept, called by nothing in `src/`, because the
/// assembly needs something independent to be checked against and because a
/// reader who wants to know what the assembly is supposed to compute should
/// not have to reconstruct it from shift counts. `test/merlin.mjs` runs a
/// differential over random states between the two, on top of the fixed
/// anchors -- FIPS 202 SHA3-256, a length sweep against Ethereum's own
/// keccak256, the Keccak team's intermediate values on all 25 lanes, and
/// byte-for-byte agreement with digests MobileCoin's own crates produced.
/// An earlier version of this permutation elsewhere omitted rho, pi and the
/// round constants and still matched lane 0, which is why the gate is all 25.
///
/// WHY ASSEMBLY. The Solidity version costs 1,281,221 gas per permutation,
/// and `verifyReturn` runs roughly eighteen of them; that alone put the return
/// leg over Ethereum's 30M block limit, where no fee can land it. Nearly all
/// of that was the EVM re-checking bounds on `uint256[25]` and `uint256[5]`
/// indices about two thousand times per call, for indices that are constants
/// of the algorithm. The Yul below is the same sequence of xors, rotations and
/// and-nots with those checks removed and the offsets folded into the code.
///
/// STATE CONVENTION. A lane is a 64-bit value held in the low bits of a
/// uint256; the high 192 bits of every entry are always zero. Lane i of the
/// 200-byte sponge state is the LITTLE-ENDIAN interpretation of bytes
/// [8i, 8i+8). That is the same convention the Rust `keccak` crate gets from
/// transmuting `[u8; 200]` to `[u64; 25]` on a little-endian target, which is
/// what merlin relies on.
library Keccak1600 {
    uint256 private constant MASK64 = 0xFFFFFFFFFFFFFFFF;

    /// Permute `a` IN PLACE. The return value is the same memory reference,
    /// returned only for call-site convenience; callers that already hold `a`
    /// may ignore it. In-place is deliberate: the STROBE state lives inside a
    /// struct and must not be silently copied out from under it.
    ///
    /// The output always obeys the lane convention even if the input did not,
    /// and agrees with `f1600Reference` on such inputs; see the fold below.
    function f1600(uint256[25] memory a)
        internal
        pure
        returns (uint256[25] memory)
    {
        assembly ("memory-safe") {
            // Scratch for the 25-lane B plane and the round-constant table.
            // Solidity counts memory above the free pointer, left un-bumped, as
            // memory-safe temporary space -- and leaving the pointer alone is
            // what lets the few hundred permutations behind one verifyReturn
            // share one region instead of walking memory up through half a
            // megabyte of quadratic expansion cost.
            let sc := mload(0x40)

            // Fold the input to the 64-bit lane convention before anything reads
            // it. Nothing in src/ passes anything else, but the probe is reachable
            // with 256 dirty bits per lane, and the two implementations have to
            // agree on those too or the differential has a carve-out in it.
            //
            // This is not merely defensive, it is exact: the reference rotates via
            // `(x & MASK64) >> (64 - n)`, so every high bit it ever sees is dropped
            // on the first rho, and xor never moves a high bit down into the low
            // 64. Clearing them here therefore reproduces the reference bit for
            // bit, while letting the 24 rounds below rotate without re-masking.
            mstore(a, and(mload(a), 0xffffffffffffffff))
            mstore(add(a, 32), and(mload(add(a, 32)), 0xffffffffffffffff))
            mstore(add(a, 64), and(mload(add(a, 64)), 0xffffffffffffffff))
            mstore(add(a, 96), and(mload(add(a, 96)), 0xffffffffffffffff))
            mstore(add(a, 128), and(mload(add(a, 128)), 0xffffffffffffffff))
            mstore(add(a, 160), and(mload(add(a, 160)), 0xffffffffffffffff))
            mstore(add(a, 192), and(mload(add(a, 192)), 0xffffffffffffffff))
            mstore(add(a, 224), and(mload(add(a, 224)), 0xffffffffffffffff))
            mstore(add(a, 256), and(mload(add(a, 256)), 0xffffffffffffffff))
            mstore(add(a, 288), and(mload(add(a, 288)), 0xffffffffffffffff))
            mstore(add(a, 320), and(mload(add(a, 320)), 0xffffffffffffffff))
            mstore(add(a, 352), and(mload(add(a, 352)), 0xffffffffffffffff))
            mstore(add(a, 384), and(mload(add(a, 384)), 0xffffffffffffffff))
            mstore(add(a, 416), and(mload(add(a, 416)), 0xffffffffffffffff))
            mstore(add(a, 448), and(mload(add(a, 448)), 0xffffffffffffffff))
            mstore(add(a, 480), and(mload(add(a, 480)), 0xffffffffffffffff))
            mstore(add(a, 512), and(mload(add(a, 512)), 0xffffffffffffffff))
            mstore(add(a, 544), and(mload(add(a, 544)), 0xffffffffffffffff))
            mstore(add(a, 576), and(mload(add(a, 576)), 0xffffffffffffffff))
            mstore(add(a, 608), and(mload(add(a, 608)), 0xffffffffffffffff))
            mstore(add(a, 640), and(mload(add(a, 640)), 0xffffffffffffffff))
            mstore(add(a, 672), and(mload(add(a, 672)), 0xffffffffffffffff))
            mstore(add(a, 704), and(mload(add(a, 704)), 0xffffffffffffffff))
            mstore(add(a, 736), and(mload(add(a, 736)), 0xffffffffffffffff))
            mstore(add(a, 768), and(mload(add(a, 768)), 0xffffffffffffffff))

            // Round constants, written once per call rather than rebuilt per
            // round; the loop then costs one mload to reach the next one.
            mstore(add(sc, 800), 0x0000000000000001)
            mstore(add(sc, 832), 0x0000000000008082)
            mstore(add(sc, 864), 0x800000000000808a)
            mstore(add(sc, 896), 0x8000000080008000)
            mstore(add(sc, 928), 0x000000000000808b)
            mstore(add(sc, 960), 0x0000000080000001)
            mstore(add(sc, 992), 0x8000000080008081)
            mstore(add(sc, 1024), 0x8000000000008009)
            mstore(add(sc, 1056), 0x000000000000008a)
            mstore(add(sc, 1088), 0x0000000000000088)
            mstore(add(sc, 1120), 0x0000000080008009)
            mstore(add(sc, 1152), 0x000000008000000a)
            mstore(add(sc, 1184), 0x000000008000808b)
            mstore(add(sc, 1216), 0x800000000000008b)
            mstore(add(sc, 1248), 0x8000000000008089)
            mstore(add(sc, 1280), 0x8000000000008003)
            mstore(add(sc, 1312), 0x8000000000008002)
            mstore(add(sc, 1344), 0x8000000000000080)
            mstore(add(sc, 1376), 0x000000000000800a)
            mstore(add(sc, 1408), 0x800000008000000a)
            mstore(add(sc, 1440), 0x8000000080008081)
            mstore(add(sc, 1472), 0x8000000000008080)
            mstore(add(sc, 1504), 0x0000000080000001)
            mstore(add(sc, 1536), 0x8000000080008008)

            let rcEnd := add(sc, 1568)
            for { let rc := add(sc, 800) } lt(rc, rcEnd) { rc := add(rc, 32) } {
                // theta, then rho and pi folded into the same store: each lane is
                // read once, corrected by its column parity, rotated, and written
                // straight to its permuted home in the scratch plane.
                {
                    let d0 let d1 let d2 let d3 let d4
                    {
                        let c0 := xor(xor(xor(xor(mload(a), mload(add(a, 160))), mload(add(a, 320))), mload(add(a, 480))), mload(add(a, 640)))
                        let c1 := xor(xor(xor(xor(mload(add(a, 32)), mload(add(a, 192))), mload(add(a, 352))), mload(add(a, 512))), mload(add(a, 672)))
                        let c2 := xor(xor(xor(xor(mload(add(a, 64)), mload(add(a, 224))), mload(add(a, 384))), mload(add(a, 544))), mload(add(a, 704)))
                        let c3 := xor(xor(xor(xor(mload(add(a, 96)), mload(add(a, 256))), mload(add(a, 416))), mload(add(a, 576))), mload(add(a, 736)))
                        let c4 := xor(xor(xor(xor(mload(add(a, 128)), mload(add(a, 288))), mload(add(a, 448))), mload(add(a, 608))), mload(add(a, 768)))
                        d0 := xor(c4, and(or(shl(1, c1), shr(63, c1)), 0xffffffffffffffff))
                        d1 := xor(c0, and(or(shl(1, c2), shr(63, c2)), 0xffffffffffffffff))
                        d2 := xor(c1, and(or(shl(1, c3), shr(63, c3)), 0xffffffffffffffff))
                        d3 := xor(c2, and(or(shl(1, c4), shr(63, c4)), 0xffffffffffffffff))
                        d4 := xor(c3, and(or(shl(1, c0), shr(63, c0)), 0xffffffffffffffff))
                    }
                    {
                        let v := xor(mload(a), d0)
                        mstore(sc, and(v, 0xffffffffffffffff))
                    }
                    {
                        let v := xor(mload(add(a, 160)), d0)
                        mstore(add(sc, 512), and(or(shl(36, v), shr(28, v)), 0xffffffffffffffff))
                    }
                    {
                        let v := xor(mload(add(a, 320)), d0)
                        mstore(add(sc, 224), and(or(shl(3, v), shr(61, v)), 0xffffffffffffffff))
                    }
                    {
                        let v := xor(mload(add(a, 480)), d0)
                        mstore(add(sc, 736), and(or(shl(41, v), shr(23, v)), 0xffffffffffffffff))
                    }
                    {
                        let v := xor(mload(add(a, 640)), d0)
                        mstore(add(sc, 448), and(or(shl(18, v), shr(46, v)), 0xffffffffffffffff))
                    }
                    {
                        let v := xor(mload(add(a, 32)), d1)
                        mstore(add(sc, 320), and(or(shl(1, v), shr(63, v)), 0xffffffffffffffff))
                    }
                    {
                        let v := xor(mload(add(a, 192)), d1)
                        mstore(add(sc, 32), and(or(shl(44, v), shr(20, v)), 0xffffffffffffffff))
                    }
                    {
                        let v := xor(mload(add(a, 352)), d1)
                        mstore(add(sc, 544), and(or(shl(10, v), shr(54, v)), 0xffffffffffffffff))
                    }
                    {
                        let v := xor(mload(add(a, 512)), d1)
                        mstore(add(sc, 256), and(or(shl(45, v), shr(19, v)), 0xffffffffffffffff))
                    }
                    {
                        let v := xor(mload(add(a, 672)), d1)
                        mstore(add(sc, 768), and(or(shl(2, v), shr(62, v)), 0xffffffffffffffff))
                    }
                    {
                        let v := xor(mload(add(a, 64)), d2)
                        mstore(add(sc, 640), and(or(shl(62, v), shr(2, v)), 0xffffffffffffffff))
                    }
                    {
                        let v := xor(mload(add(a, 224)), d2)
                        mstore(add(sc, 352), and(or(shl(6, v), shr(58, v)), 0xffffffffffffffff))
                    }
                    {
                        let v := xor(mload(add(a, 384)), d2)
                        mstore(add(sc, 64), and(or(shl(43, v), shr(21, v)), 0xffffffffffffffff))
                    }
                    {
                        let v := xor(mload(add(a, 544)), d2)
                        mstore(add(sc, 576), and(or(shl(15, v), shr(49, v)), 0xffffffffffffffff))
                    }
                    {
                        let v := xor(mload(add(a, 704)), d2)
                        mstore(add(sc, 288), and(or(shl(61, v), shr(3, v)), 0xffffffffffffffff))
                    }
                    {
                        let v := xor(mload(add(a, 96)), d3)
                        mstore(add(sc, 160), and(or(shl(28, v), shr(36, v)), 0xffffffffffffffff))
                    }
                    {
                        let v := xor(mload(add(a, 256)), d3)
                        mstore(add(sc, 672), and(or(shl(55, v), shr(9, v)), 0xffffffffffffffff))
                    }
                    {
                        let v := xor(mload(add(a, 416)), d3)
                        mstore(add(sc, 384), and(or(shl(25, v), shr(39, v)), 0xffffffffffffffff))
                    }
                    {
                        let v := xor(mload(add(a, 576)), d3)
                        mstore(add(sc, 96), and(or(shl(21, v), shr(43, v)), 0xffffffffffffffff))
                    }
                    {
                        let v := xor(mload(add(a, 736)), d3)
                        mstore(add(sc, 608), and(or(shl(56, v), shr(8, v)), 0xffffffffffffffff))
                    }
                    {
                        let v := xor(mload(add(a, 128)), d4)
                        mstore(add(sc, 480), and(or(shl(27, v), shr(37, v)), 0xffffffffffffffff))
                    }
                    {
                        let v := xor(mload(add(a, 288)), d4)
                        mstore(add(sc, 192), and(or(shl(20, v), shr(44, v)), 0xffffffffffffffff))
                    }
                    {
                        let v := xor(mload(add(a, 448)), d4)
                        mstore(add(sc, 704), and(or(shl(39, v), shr(25, v)), 0xffffffffffffffff))
                    }
                    {
                        let v := xor(mload(add(a, 608)), d4)
                        mstore(add(sc, 416), and(or(shl(8, v), shr(56, v)), 0xffffffffffffffff))
                    }
                    {
                        let v := xor(mload(add(a, 768)), d4)
                        mstore(add(sc, 128), and(or(shl(14, v), shr(50, v)), 0xffffffffffffffff))
                    }
                }
                // chi, one row at a time so only five lanes are live at once.
                {
                    let t0 := mload(sc)
                    let t1 := mload(add(sc, 32))
                    let t2 := mload(add(sc, 64))
                    let t3 := mload(add(sc, 96))
                    let t4 := mload(add(sc, 128))
                    mstore(a, xor(t0, and(not(t1), t2)))
                    mstore(add(a, 32), xor(t1, and(not(t2), t3)))
                    mstore(add(a, 64), xor(t2, and(not(t3), t4)))
                    mstore(add(a, 96), xor(t3, and(not(t4), t0)))
                    mstore(add(a, 128), xor(t4, and(not(t0), t1)))
                }
                {
                    let t0 := mload(add(sc, 160))
                    let t1 := mload(add(sc, 192))
                    let t2 := mload(add(sc, 224))
                    let t3 := mload(add(sc, 256))
                    let t4 := mload(add(sc, 288))
                    mstore(add(a, 160), xor(t0, and(not(t1), t2)))
                    mstore(add(a, 192), xor(t1, and(not(t2), t3)))
                    mstore(add(a, 224), xor(t2, and(not(t3), t4)))
                    mstore(add(a, 256), xor(t3, and(not(t4), t0)))
                    mstore(add(a, 288), xor(t4, and(not(t0), t1)))
                }
                {
                    let t0 := mload(add(sc, 320))
                    let t1 := mload(add(sc, 352))
                    let t2 := mload(add(sc, 384))
                    let t3 := mload(add(sc, 416))
                    let t4 := mload(add(sc, 448))
                    mstore(add(a, 320), xor(t0, and(not(t1), t2)))
                    mstore(add(a, 352), xor(t1, and(not(t2), t3)))
                    mstore(add(a, 384), xor(t2, and(not(t3), t4)))
                    mstore(add(a, 416), xor(t3, and(not(t4), t0)))
                    mstore(add(a, 448), xor(t4, and(not(t0), t1)))
                }
                {
                    let t0 := mload(add(sc, 480))
                    let t1 := mload(add(sc, 512))
                    let t2 := mload(add(sc, 544))
                    let t3 := mload(add(sc, 576))
                    let t4 := mload(add(sc, 608))
                    mstore(add(a, 480), xor(t0, and(not(t1), t2)))
                    mstore(add(a, 512), xor(t1, and(not(t2), t3)))
                    mstore(add(a, 544), xor(t2, and(not(t3), t4)))
                    mstore(add(a, 576), xor(t3, and(not(t4), t0)))
                    mstore(add(a, 608), xor(t4, and(not(t0), t1)))
                }
                {
                    let t0 := mload(add(sc, 640))
                    let t1 := mload(add(sc, 672))
                    let t2 := mload(add(sc, 704))
                    let t3 := mload(add(sc, 736))
                    let t4 := mload(add(sc, 768))
                    mstore(add(a, 640), xor(t0, and(not(t1), t2)))
                    mstore(add(a, 672), xor(t1, and(not(t2), t3)))
                    mstore(add(a, 704), xor(t2, and(not(t3), t4)))
                    mstore(add(a, 736), xor(t3, and(not(t4), t0)))
                    mstore(add(a, 768), xor(t4, and(not(t0), t1)))
                }
                mstore(a, xor(mload(a), mload(rc)))
            }
        }
        return a;
    }

    // ---------------------------------------------------------------- reference

    function _rol(uint256 x, uint256 n) private pure returns (uint256) {
        if (n == 0) return x & MASK64;
        return ((x << n) | ((x & MASK64) >> (64 - n))) & MASK64;
    }

    /// REFERENCE IMPLEMENTATION. Not on any production path -- `f1600` is what
    /// callers run. This is the readable statement of the algorithm and the
    /// other side of the differential test; changing it changes what `f1600`
    /// is checked against, so treat it as a specification rather than as code.
    function f1600Reference(uint256[25] memory a)
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

    /// Exposed only so the differential in `test/merlin.mjs` has both sides
    /// running as real bytecode on the same EVM.
    function f1600Reference(uint256[25] memory a)
        external
        pure
        returns (uint256[25] memory)
    {
        return Keccak1600.f1600Reference(a);
    }
}
