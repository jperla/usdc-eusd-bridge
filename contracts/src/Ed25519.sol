// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Sha512} from "./Sha512.sol";

/// Ed25519 signature verification (RFC 8032), in EVM words.
///
/// MobileCoin validators sign block digests with Ed25519. Ethereum has no
/// Ed25519 precompile -- EIP-665 has been stagnant since 2018 -- so the return
/// leg's proof of MobileCoin consensus cannot be checked without this. The
/// only precompile used here is modexp (0x05), for the two exponentiations
/// that decompression needs; everything else is `mulmod`/`addmod` against
/// p = 2^255 - 19.
///
/// Verification is the cofactorless equation [s]B = R + [H(R,A,M)]A of RFC
/// 8032 s5.1.7 -- the equation ref10, libsodium and MobileCoin's own
/// ed25519-dalek `verify` implement.
///
/// LIMITATIONS -- what this library does NOT establish.
///
/// * NO KEY VALIDATION. `verify` accepts any public key that decodes to a
///   curve point, including the identity and the seven other points of order
///   dividing 8. Against the identity, [h]A is the identity for every h, so
///   (R = [r]B, s = r) verifies for ANY message: universal forgery, and the
///   same is true of ed25519-dalek and libsodium. This is pinned by a test
///   rather than left implicit. The caller -- the validator registry -- is
///   what must refuse such keys; this library deliberately does not, because
///   silently filtering keys would make it disagree with the reference
///   implementations.
/// * Cofactorless. The cofactored variant ([8][s]B = [8]R + [8][h]A) accepts a
///   strict superset, so nothing accepted here would be rejected by a
///   cofactored verifier; the converse does not hold. Ed25519 is not strongly
///   binding under either rule, so a signature is not a unique identifier for
///   a message.
/// * STRICTER THAN ref10 on encodings. `decompress` rejects y >= p and the
///   negative-zero form, matching libsodium and noble-ed25519 but not the
///   original ref10, which masks the sign bit and lets some non-canonical y
///   through. The divergence is in the safe direction (this accepts fewer
///   signatures), but it is a divergence: a signature that some other
///   implementation accepts can be rejected here. Untested against ref10
///   directly -- no ref10 oracle is available here -- so this is stated, not
///   demonstrated.
/// * Not constant time, and does not try to be. Every input is public:
///   signatures, public keys and block digests are all on-chain already.
/// * Single signatures only. No batch verification, which is where the real
///   per-signature saving would be for a validator quorum.
library Ed25519 {
    // --------------------------------------------------------------- constants

    /// Field prime, 2^255 - 19.
    uint256 internal constant P =
        57896044618658097711785492504343953926634992332820282019728792003956564819949;

    /// Prime order of the base point, 2^252 + 27742317777372353535851937790883648493.
    uint256 internal constant L =
        7237005577332262213973186563042994240857116359379907606001950938285454250989;

    /// Curve constant d = -121665/121666 mod p.
    uint256 private constant D =
        37095705934669439343138083508754565189542113879843219016388785533085940283555;

    /// 2d, the `k` of the extended-coordinate addition formula.
    uint256 private constant D2 =
        16295367250680780974490674513165176452449235426866156013048779062215315747161;

    /// sqrt(-1) mod p = 2^((p-1)/4). Needed because p = 5 (mod 8) gives a
    /// square-root formula that lands on the right value only up to this factor.
    uint256 private constant SQRT_M1 =
        19681161376707505956807079304988542015446066515923890162744021073123829784752;

    /// (p - 5) / 8, the exponent of that square-root formula.
    uint256 private constant SQRT_EXP =
        7237005577332262213973186563042994240829374041602535252466099000494570602493;

    /// 2^256 mod L, for folding the 512-bit SHA-512 digest into a scalar.
    uint256 private constant TWO_256_MOD_L =
        7237005577332262213973186563042994240413239274941949949428319933631315875101;

    /// Base point B.
    uint256 private constant BX =
        15112221349535400772501151409588531511454012693041857206046113283949847762202;
    uint256 private constant BY =
        46316835694926478169428394003475163141307993866256225615783033603165251855960;

    /// Extended (twisted Edwards) coordinates: x = X/Z, y = Y/Z, T = XY/Z.
    ///
    /// Extended rather than affine because affine addition needs a modular
    /// inversion -- ~250 of them per verification, which is the difference
    /// between a feasible verifier and an impossible one.
    struct Point {
        uint256 x;
        uint256 y;
        uint256 z;
        uint256 t;
    }

    // ------------------------------------------------------------------ verify

    /// `sig[0]` is R, `sig[1]` is S, both as they appear on the wire (the
    /// 64-byte signature split in half, each half little-endian).
    ///
    /// Returns false rather than reverting: a caller aggregating a validator
    /// set needs to count failures, not abort on the first one.
    function verify(bytes32[2] memory sig, bytes32 pubkey, bytes memory message)
        internal
        view
        returns (bool)
    {
        uint256 s = _le(sig[1]);

        // Malleability. Without this, s' = s + L is a second valid encoding of
        // the same signature, and anything that treats the signature bytes as
        // an identifier -- a replay set, a dedup key, an event index -- can be
        // fed two "distinct" signatures over one message.
        if (s >= L) return false;

        (bool okR, uint256 rx, uint256 ry) = decompress(sig[0]);
        if (!okR) return false;
        (bool okA, uint256 ax, uint256 ay) = decompress(pubkey);
        if (!okA) return false;

        uint256 h = _hram(sig[0], pubkey, message);

        // Verify as [s]B + [h](-A) == R rather than [s]B == R + [h]A, so that
        // both scalar multiplications become one joint multiplication. Negating
        // A is free (a coordinate negation); negating h would cost a reduction.
        uint256 nax = ax == 0 ? 0 : P - ax;
        Point memory negA =
            Point({x: nax, y: ay, z: 1, t: mulmod(nax, ay, P)});
        Point memory base =
            Point({x: BX, y: BY, z: 1, t: mulmod(BX, BY, P)});

        Point memory q = _jointMul(h, negA, s, base);

        // R came out of decompress with Z = 1, so projective equality
        // (Xq*Zr == Xr*Zq, Yq*Zr == Yr*Zq) collapses to this.
        return q.x == mulmod(rx, q.z, P) && q.y == mulmod(ry, q.z, P);
    }

    // ------------------------------------------------------------ decompression

    /// Recover the full point from its 32-byte compressed encoding.
    ///
    /// Returns ok = false for every encoding that is not the unique canonical
    /// encoding of a point on the curve: y >= p, a y with no corresponding x,
    /// and the "negative zero" encoding (x = 0 with the sign bit set). That
    /// strictness is what makes the encoding a bijection, which in turn is what
    /// lets `verify` compare decoded points instead of re-encoding.
    function decompress(bytes32 compressed)
        internal
        view
        returns (bool ok, uint256 x, uint256 y)
    {
        uint256 v = _le(compressed);
        uint256 sign = v >> 255;
        y = v & ((uint256(1) << 255) - 1);
        if (y >= P) return (false, 0, 0);

        // Curve: -x^2 + y^2 = 1 + d x^2 y^2, so x^2 = (y^2 - 1)/(d y^2 + 1).
        uint256 y2 = mulmod(y, y, P);
        uint256 u = addmod(y2, P - 1, P);
        uint256 w = addmod(mulmod(D, y2, P), 1, P);

        // p = 5 (mod 8), so there is no single exponent that is a square root.
        // The candidate is x = u w^3 (u w^7)^((p-5)/8); it is either the root,
        // the root times sqrt(-1), or a witness that u/w is not a square.
        uint256 w2 = mulmod(w, w, P);
        uint256 w3 = mulmod(w2, w, P);
        uint256 w7 = mulmod(w3, mulmod(w2, w2, P), P);
        x = mulmod(
            mulmod(u, w3, P), _expmod(mulmod(u, w7, P), SQRT_EXP), P
        );

        uint256 check = mulmod(w, mulmod(x, x, P), P);
        if (check != u) {
            uint256 nu = u == 0 ? 0 : P - u;
            if (check != nu) return (false, 0, 0); // no root: not on the curve
            x = mulmod(x, SQRT_M1, P);
        }

        if (x == 0 && sign == 1) return (false, 0, 0); // non-canonical -0
        if ((x & 1) != sign) x = P - x;
        ok = true;
    }

    // --------------------------------------------------------------- internal

    /// H(R || A || M) as a little-endian 512-bit integer, reduced mod L.
    function _hram(bytes32 r, bytes32 a, bytes memory m)
        private
        pure
        returns (uint256)
    {
        (bytes32 hi, bytes32 lo) = Sha512.hashPrefixed(r, a, m);
        // Little-endian: digest bytes 0..31 are the LOW half of the integer.
        uint256 low = _le(hi);
        uint256 high = _le(lo);
        return addmod(
            mulmod(high % L, TWO_256_MOD_L, L), low % L, L
        );
    }

    /// [e1]p1 + [e2]p2 by Shamir's trick over 2-bit windows.
    ///
    /// One doubling per bit of the exponent, shared by both scalars, and one
    /// addition per window -- against two independent ladders this halves the
    /// doublings and cuts the additions by a factor of four, at the cost of a
    /// 16-entry table built with 2 doublings and 10 additions.
    function _jointMul(
        uint256 e1,
        Point memory p1,
        uint256 e2,
        Point memory p2
    ) private pure returns (Point memory acc) {
        Point[16] memory tbl; // tbl[4j + i] = [i]p1 + [j]p2
        tbl[0].y = 1;
        tbl[0].z = 1;

        _set(tbl[1], p1);
        _set(tbl[2], p1);
        _dbl(tbl[2]);
        _set(tbl[3], tbl[2]);
        _add(tbl[3], p1);

        _set(tbl[4], p2);
        _set(tbl[8], p2);
        _dbl(tbl[8]);
        _set(tbl[12], tbl[8]);
        _add(tbl[12], p2);

        for (uint256 j = 1; j < 4; ++j) {
            for (uint256 i = 1; i < 4; ++i) {
                _set(tbl[4 * j + i], tbl[4 * j]);
                _add(tbl[4 * j + i], tbl[i]);
            }
        }

        acc = Point({x: 0, y: 1, z: 1, t: 0});

        // Both scalars are reduced mod L < 2^253, so bits 255..253 are always
        // zero and the top window can be skipped outright.
        for (uint256 k = 127; k != 0;) {
            unchecked {
                --k;
            }
            _dbl(acc);
            _dbl(acc);
            uint256 shift = k * 2;
            uint256 idx =
                (((e2 >> shift) & 3) << 2) | ((e1 >> shift) & 3);
            if (idx != 0) _add(acc, tbl[idx]);
        }
    }

    function _set(Point memory dst, Point memory src) private pure {
        dst.x = src.x;
        dst.y = src.y;
        dst.z = src.z;
        dst.t = src.t;
    }

    /// dbl-2008-hwcd for a = -1. Does not read T, which is why the table build
    /// can double a point whose T has not been formed yet.
    /// True iff `compressed` decodes to a point of small order -- one of the
    /// eight points killed by the cofactor, including the neutral element.
    ///
    /// Such a key admits universal forgery under RFC 8032 cofactorless
    /// verification: with A neutral, [h]A is neutral for every h, so
    /// (R = [r]B, s = r) verifies against ANY message. `verify` reproduces that
    /// deliberately, because rejecting it there would disagree with
    /// libsodium and ed25519-dalek. Refusing such keys is the job of whatever
    /// decides which keys are admissible -- see ValidatorRegistry.
    ///
    /// A has small order iff [8]A is the neutral element, so this is three
    /// doublings and a comparison rather than a blacklist of encodings that
    /// someone has to keep correct.
    /// Whether `compressed` is admissible as a signing key: it must decode
    /// canonically AND not be small order.
    ///
    /// Two separate rejections, and a caller that checks only one is still
    /// broken. Non-canonical encodings (y >= p) are refused by `decompress`;
    /// small-order points decode perfectly well and are refused here. Callers
    /// deciding which keys may sign want both, so this is the entry point
    /// rather than making each of them remember to compose the two.
    function isAdmissiblePublicKey(bytes32 compressed)
        internal
        view
        returns (bool)
    {
        (bool ok, uint256 x, uint256 y) = decompress(compressed);
        if (!ok) return false;

        Point memory p = Point(x, y, 1, mulmod(x, y, P));
        _dbl(p);
        _dbl(p);
        _dbl(p);
        return p.x != 0;
    }

    function isSmallOrder(bytes32 compressed) internal view returns (bool) {
        (bool ok, uint256 x, uint256 y) = decompress(compressed);
        if (!ok) return false;      // not a point at all; a different rejection

        Point memory p = Point(x, y, 1, mulmod(x, y, P));
        _dbl(p);
        _dbl(p);
        _dbl(p);

        // Neutral in extended coordinates is x == 0 (with z != 0), which is
        // projectively (0 : z : z). Comparing x alone is sufficient: the only
        // points with x == 0 are the neutral element and the order-2 point,
        // and both are small order.
        return p.x == 0;
    }

    function _dbl(Point memory p) private pure {
        uint256 a = mulmod(p.x, p.x, P);
        uint256 b = mulmod(p.y, p.y, P);
        uint256 c = mulmod(2, mulmod(p.z, p.z, P), P);
        uint256 d = P - a; // a*X^2 with a = -1
        uint256 e = addmod(
            mulmod(addmod(p.x, p.y, P), addmod(p.x, p.y, P), P),
            P - addmod(a, b, P),
            P
        );
        uint256 g = addmod(d, b, P);
        uint256 f = addmod(g, P - c, P);
        uint256 h = addmod(d, P - b, P);
        p.x = mulmod(e, f, P);
        p.y = mulmod(g, h, P);
        p.t = mulmod(e, h, P);
        p.z = mulmod(f, g, P);
    }

    /// add-2008-hwcd-3 for a = -1, which is COMPLETE on Ed25519 because d is a
    /// non-square: no special case for the identity, for equal inputs, or for
    /// opposite inputs. Every branch this implementation does not contain is a
    /// branch that cannot be provoked.
    function _add(Point memory p, Point memory q) private pure {
        uint256 a = mulmod(
            addmod(p.y, P - p.x, P), addmod(q.y, P - q.x, P), P
        );
        uint256 b = mulmod(
            addmod(p.y, p.x, P), addmod(q.y, q.x, P), P
        );
        uint256 c = mulmod(mulmod(p.t, D2, P), q.t, P);
        uint256 d = mulmod(2, mulmod(p.z, q.z, P), P);
        uint256 e = addmod(b, P - a, P);
        uint256 f = addmod(d, P - c, P);
        uint256 g = addmod(d, c, P);
        uint256 h = addmod(b, a, P);
        p.x = mulmod(e, f, P);
        p.y = mulmod(g, h, P);
        p.t = mulmod(e, h, P);
        p.z = mulmod(f, g, P);
    }

    /// Byte-reverse: every scalar and coordinate on the Ed25519 wire is
    /// little-endian, and every EVM word is big-endian.
    function _le(bytes32 b) private pure returns (uint256 r) {
        uint256 v = uint256(b);
        unchecked {
            for (uint256 i = 0; i < 32; ++i) {
                r = (r << 8) | (v & 0xff);
                v >>= 8;
            }
        }
    }

    /// base^exp mod p via the modexp precompile. A Solidity square-and-multiply
    /// would be ~250 iterations of loop overhead for the same result.
    function _expmod(uint256 b, uint256 e)
        private
        view
        returns (uint256 r)
    {
        assembly {
            let m := mload(0x40)
            mstore(m, 0x20)
            mstore(add(m, 0x20), 0x20)
            mstore(add(m, 0x40), 0x20)
            mstore(add(m, 0x60), b)
            mstore(add(m, 0x80), e)
            mstore(add(m, 0xa0), P)
            if iszero(staticcall(gas(), 0x05, m, 0xc0, m, 0x20)) {
                revert(0, 0)
            }
            r := mload(m)
        }
    }
}

/// Thin deployed wrapper.
///
/// The library's functions are `internal`, so they inline into whatever calls
/// them; this contract exists so the verifier can also be reached across a
/// call -- both to keep a caller under the 24 KB code limit and to give the
/// tests an external surface with a measurable gas number.
contract Ed25519Verifier {
    function isSmallOrder(bytes32 compressed) external view returns (bool) {
        return Ed25519.isSmallOrder(compressed);
    }

    function isAdmissiblePublicKey(bytes32 compressed)
        external
        view
        returns (bool)
    {
        return Ed25519.isAdmissiblePublicKey(compressed);
    }

    function verify(
        bytes32[2] calldata sig,
        bytes32 pubkey,
        bytes calldata message
    ) external view returns (bool) {
        return Ed25519.verify(sig, pubkey, message);
    }

    function decompress(bytes32 compressed)
        external
        view
        returns (bool ok, uint256 x, uint256 y)
    {
        return Ed25519.decompress(compressed);
    }

    /// Exposed for cross-checking the hash against FIPS 180-4 vectors
    /// independently of the signature path.
    function sha512(bytes calldata message)
        external
        pure
        returns (bytes32 hi, bytes32 lo)
    {
        return Sha512.hash(message);
    }
}
