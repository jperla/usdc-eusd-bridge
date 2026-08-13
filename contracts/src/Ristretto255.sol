// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// ristretto255 point encoding, decoding and arithmetic, in EVM words.
///
/// MobileCoin's keys are ristretto255 points, not Ed25519 points. Ristretto is
/// an encoding layer over Edwards25519 that quotients out the cofactor: the
/// underlying field and curve are identical, so Ed25519's decompression
/// "works" on a ristretto encoding in the sense that it returns a point and
/// never reverts -- it just returns a DIFFERENT point than MobileCoin means,
/// for a different set of inputs than MobileCoin accepts. Substituting it
/// would fail only on the cases nobody tests. That is why this file exists and
/// why it implements its own decode and encode rather than borrowing
/// Ed25519.sol's.
///
/// Two properties the recipient check depends on:
///
/// * The encoding is CANONICAL and injective on the quotient. Each ristretto
///   point has exactly one 32-byte encoding, and each valid encoding one
///   point, so `encode(a) == encode(b)` is point equality and comparing 32
///   bytes is a complete equality test. `decode` therefore has to refuse every
///   near-miss encoding -- non-canonical field elements, negative `s`,
///   non-square results, negative `t`, and `y == 0` -- or that bijection, and
///   with it the comparison, is lost.
/// * Cofactor-free. Ed25519 has eight points of small order; ristretto's
///   quotient makes them all the identity's coset, so there is no small-order
///   or non-prime-order subgroup input to guard against here.
///
/// Follows the reference construction in curve25519-dalek (the implementation
/// MobileCoin itself links), including its SQRT_RATIO_M1 sign conventions.
/// Every constant and every branch below is pinned against that implementation
/// by contracts/test/fixtures/ristretto.json.
///
/// Not constant time, and does not try to be: every input is public. The one
/// secret-shaped input, the return address's view private key, is published by
/// construction -- see RecipientCheck.
library Ristretto255 {
    // --------------------------------------------------------------- constants

    /// Field prime, 2^255 - 19.
    uint256 internal constant P =
        57896044618658097711785492504343953926634992332820282019728792003956564819949;

    /// Prime order of the ristretto255 group, 2^252 + 27742317777372353535851937790883648493.
    uint256 internal constant L =
        7237005577332262213973186563042994240857116359379907606001950938285454250989;

    /// Curve constant d = -121665/121666 mod p.
    uint256 private constant D =
        37095705934669439343138083508754565189542113879843219016388785533085940283555;

    /// 2d, the `k` of the extended-coordinate addition formula.
    uint256 private constant D2 =
        16295367250680780974490674513165176452449235426866156013048779062215315747161;

    /// sqrt(-1) mod p: dalek's SQRT_M1, the non-negative root.
    ///
    /// Which of the two roots this is changes no output, which is worth
    /// recording rather than rediscovering. `_sqrtRatio` normalizes its result
    /// to the non-negative root, and `encode`'s rotated branch scales both
    /// coordinates by it before that same normalization; the roots differ only
    /// in `_sqrtRatio`'s non-square case, whose `r` both callers discard.
    uint256 private constant SQRT_M1 =
        19681161376707505956807079304988542015446066515923890162744021073123829784752;

    /// 1/sqrt(a - d) with a = -1, dalek's INVSQRT_A_MINUS_D. Only the encoder's
    /// rotated branch uses it, where the final |s| makes its sign immaterial.
    uint256 private constant INVSQRT_A_MINUS_D =
        54469307008909316920995813868745141605393597292927456921205312896311721017578;

    /// (p - 5) / 8, the exponent of the square-root candidate formula. p = 5
    /// (mod 8), so no single exponent is a square root and the candidate has to
    /// be corrected by SQRT_M1.
    uint256 private constant SQRT_EXP =
        7237005577332262213973186563042994240829374041602535252466099000494570602493;

    /// 2^256 mod L, for reducing a 512-bit value into a scalar.
    uint256 private constant TWO_256_MOD_L =
        7237005577332262213973186563042994240413239274941949949428319933631315875101;

    /// The ristretto255 basepoint is the Edwards basepoint; only the encoding
    /// of it differs. Its published encoding is asserted in the tests.
    uint256 private constant BX =
        15112221349535400772501151409588531511454012693041857206046113283949847762202;
    uint256 private constant BY =
        46316835694926478169428394003475163141307993866256225615783033603165251855960;

    /// Extended (twisted Edwards) coordinates: x = X/Z, y = Y/Z, T = XY/Z.
    ///
    /// Extended rather than affine because affine addition needs a modular
    /// inversion, and a scalar multiplication would need hundreds of them.
    ///
    /// A `Point` is a representative of a ristretto coset, not a canonical
    /// value: two Points with different coordinates can be the same ristretto
    /// point. Compare with `encode`, never field by field.
    struct Point {
        uint256 x;
        uint256 y;
        uint256 z;
        uint256 t;
    }

    // ------------------------------------------------------------------ decode

    /// Decode a 32-byte ristretto255 encoding.
    ///
    /// Returns ok = false rather than reverting, because the caller is asking
    /// a question about attacker-supplied bytes and "these are not a point" is
    /// an answer, not an error.
    function decode(bytes32 encoded)
        internal
        view
        returns (bool ok, Point memory p)
    {
        uint256 s = _fromLE(encoded);

        // The field element must be canonically encoded. s >= P covers both a
        // set high bit and a value in [P, 2^255): either way some other byte
        // string encodes the same field element, and admitting it would give
        // one point two encodings.
        if (s >= P) return (false, p);
        // Negative s. Its counterpart -s decodes to the same point, so this is
        // the second half of making the encoding injective.
        if (s & 1 == 1) return (false, p);

        uint256 ss = mulmod(s, s, P);
        uint256 u1 = addmod(1, _neg(ss), P); // 1 + a*s^2, a = -1
        uint256 u2 = addmod(1, ss, P); //       1 - a*s^2
        uint256 u2sq = mulmod(u2, u2, P);

        // v = a*d*(1 + a*s^2)^2 - (1 - a*s^2)^2
        uint256 v = addmod(
            mulmod(_neg(D), mulmod(u1, u1, P), P), _neg(u2sq), P
        );

        (bool square, uint256 i) = _sqrtRatio(1, mulmod(v, u2sq, P));
        uint256 dx = mulmod(i, u2, P);
        uint256 dy = mulmod(i, mulmod(dx, v, P), P);

        uint256 x = mulmod(addmod(s, s, P), dx, P);
        if (x & 1 == 1) x = P - x; // x is taken non-negative
        uint256 y = mulmod(u1, dy, P);
        uint256 t = mulmod(x, y, P);

        // `square` false means v*u2^2 is a non-square: the s given is not the
        // encoding of any point. Negative t and y == 0 are the encodings that
        // are on the curve but outside the image of `encode`.
        if (!square || y == 0) return (false, p);

        p = Point({x: x, y: y, z: 1, t: t});
        ok = true;
    }

    // ------------------------------------------------------------------ encode

    /// The unique 32-byte encoding of the coset `p` represents.
    ///
    /// MobileCoin's `hash_to_scalar` hashes the COMPRESSED point, so the
    /// recipient check needs this as much as it needs `decode`.
    function encode(Point memory p) internal view returns (bytes32) {
        uint256 x = p.x;
        uint256 y = p.y;
        uint256 z = p.z;

        uint256 u1 = mulmod(addmod(z, y, P), addmod(z, _neg(y), P), P);
        uint256 u2 = mulmod(x, y, P);

        // Always a square, so the flag is not consulted; for the identity both
        // u1 and u2 are zero and the zero root falls through to s = 0, which is
        // the identity's encoding.
        (, uint256 invsqrt) =
            _sqrtRatio(1, mulmod(u1, mulmod(u2, u2, P), P));

        uint256 i1 = mulmod(invsqrt, u1, P);
        uint256 i2 = mulmod(invsqrt, u2, P);
        uint256 zInv = mulmod(mulmod(i1, i2, P), p.t, P);
        uint256 denInv = i2;

        // Ristretto picks one of two representatives of the coset; which one
        // depends on the sign of t/z, and the other needs the rotated
        // coordinates and the a-d denominator.
        if (mulmod(p.t, zInv, P) & 1 == 1) {
            (x, y) = (mulmod(y, SQRT_M1, P), mulmod(x, SQRT_M1, P));
            denInv = mulmod(i1, INVSQRT_A_MINUS_D, P);
        }
        if (mulmod(x, zInv, P) & 1 == 1) y = _neg(y);

        uint256 s = mulmod(denInv, addmod(z, _neg(y), P), P);
        if (s & 1 == 1) s = P - s; // the encoding is always the non-negative s

        return _toLE(s);
    }

    // -------------------------------------------------------------- arithmetic

    function basepoint() internal pure returns (Point memory) {
        return Point({x: BX, y: BY, z: 1, t: mulmod(BX, BY, P)});
    }

    function add(Point memory p, Point memory q)
        internal
        pure
        returns (Point memory r)
    {
        r = Point({x: p.x, y: p.y, z: p.z, t: p.t});
        _add(r, q);
    }

    function sub(Point memory p, Point memory q)
        internal
        pure
        returns (Point memory r)
    {
        Point memory negQ =
            Point({x: _neg(q.x), y: q.y, z: q.z, t: _neg(q.t)});
        r = Point({x: p.x, y: p.y, z: p.z, t: p.t});
        _add(r, negQ);
    }

    /// [k]p by 4-bit windows: one table of 16 multiples, then four doublings
    /// and at most one addition per window.
    ///
    /// `k` is not required to be reduced; the loop covers all 256 bits, which
    /// costs a few wasted doublings on the leading zero windows of a reduced
    /// scalar and removes a precondition a caller could get wrong.
    function scalarMul(uint256 k, Point memory p)
        internal
        pure
        returns (Point memory acc)
    {
        Point[16] memory tbl; // tbl[i] = [i]p
        tbl[0].y = 1;
        tbl[0].z = 1;
        _set(tbl[1], p);
        for (uint256 i = 2; i < 16; ++i) {
            _set(tbl[i], tbl[i - 1]);
            _add(tbl[i], p);
        }

        acc = Point({x: 0, y: 1, z: 1, t: 0});
        for (uint256 w = 64; w != 0;) {
            unchecked {
                --w;
            }
            _dbl(acc);
            _dbl(acc);
            _dbl(acc);
            _dbl(acc);
            uint256 idx = (k >> (w * 4)) & 15;
            if (idx != 0) _add(acc, tbl[idx]);
        }
    }

    // ------------------------------------------------------------------ scalars

    /// Parse a 32-byte little-endian scalar.
    ///
    /// Rejects s >= L. dalek's canonical `Scalar` encoding is reduced, so an
    /// unreduced encoding is a second encoding of a scalar that already has
    /// one -- the same non-injectivity `decode` refuses for points.
    function scalarFromLE(bytes32 encoded)
        internal
        pure
        returns (bool ok, uint256 s)
    {
        s = _fromLE(encoded);
        if (s >= L) return (false, 0);
        ok = true;
    }

    /// Reduce a 512-bit little-endian value mod L, as dalek's
    /// `Scalar::from_bytes_mod_order_wide` does. `lo` is the low 256 bits.
    function scalarFromWide(uint256 lo, uint256 hi)
        internal
        pure
        returns (uint256)
    {
        return addmod(mulmod(hi % L, TWO_256_MOD_L, L), lo % L, L);
    }

    // ---------------------------------------------------------------- internal

    /// dalek's SQRT_RATIO_M1: returns (u/v is a square and v != 0, r) with
    /// r = sqrt(u/v) when that holds, and r = sqrt(i*u/v) when it does not.
    ///
    /// The returned root is always the non-negative one. Both callers rely on
    /// that: it is what makes the decoded x and the encoded s canonical.
    function _sqrtRatio(uint256 u, uint256 v)
        private
        view
        returns (bool isSquare, uint256 r)
    {
        uint256 v2 = mulmod(v, v, P);
        uint256 v3 = mulmod(v2, v, P);
        uint256 v7 = mulmod(v3, mulmod(v2, v2, P), P);

        // Candidate root u*v^3 * (u*v^7)^((p-5)/8); correct up to a factor of
        // sqrt(-1), which the checks below identify.
        r = mulmod(
            mulmod(u, v3, P), _expmod(mulmod(u, v7, P), SQRT_EXP), P
        );

        uint256 check = mulmod(v, mulmod(r, r, P), P);
        uint256 negU = _neg(u);
        bool correct = check == u;
        bool flipped = check == negU;
        if (flipped || check == mulmod(negU, SQRT_M1, P)) {
            r = mulmod(r, SQRT_M1, P);
        }
        if (r & 1 == 1) r = P - r;

        isSquare = correct || flipped;
    }

    /// Field negation. Written out because P - 0 is P, not 0, and an
    /// unreduced zero would break every equality test downstream.
    function _neg(uint256 x) private pure returns (uint256) {
        return x == 0 ? 0 : P - x;
    }

    function _set(Point memory dst, Point memory src) private pure {
        dst.x = src.x;
        dst.y = src.y;
        dst.z = src.z;
        dst.t = src.t;
    }

    /// dbl-2008-hwcd for a = -1. Does not read T, which is why the table build
    /// can double a point whose T has not been formed yet.
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

    /// add-2008-hwcd-3 for a = -1, COMPLETE on this curve because d is a
    /// non-square: no special case for the identity, for equal inputs, or for
    /// opposite inputs. Every branch this does not contain is a branch that
    /// cannot be provoked.
    function _add(Point memory p, Point memory q) private pure {
        uint256 a = mulmod(
            addmod(p.y, P - p.x, P), addmod(q.y, P - q.x, P), P
        );
        uint256 b =
            mulmod(addmod(p.y, p.x, P), addmod(q.y, q.x, P), P);
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

    /// Byte-reverse: ristretto encodings and scalars are little-endian on the
    /// wire, and every EVM word is big-endian.
    function _fromLE(bytes32 b) private pure returns (uint256 r) {
        uint256 v = uint256(b);
        unchecked {
            for (uint256 i = 0; i < 32; ++i) {
                r = (r << 8) | (v & 0xff);
                v >>= 8;
            }
        }
    }

    function _toLE(uint256 v) private pure returns (bytes32) {
        uint256 r;
        unchecked {
            for (uint256 i = 0; i < 32; ++i) {
                r = (r << 8) | (v & 0xff);
                v >>= 8;
            }
        }
        return bytes32(r);
    }

    /// base^exp mod p via the modexp precompile (0x05). A Solidity
    /// square-and-multiply would be ~250 iterations of loop overhead for the
    /// same result.
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

/// Test wrapper: the library's functions are internal, and points are memory
/// structs no external caller can hold. Everything here takes and returns wire
/// encodings, so a test can only assert what a real caller could observe.
contract Ristretto255Probe {
    function decodes(bytes32 encoded) external view returns (bool ok) {
        (ok,) = Ristretto255.decode(encoded);
    }

    function reencode(bytes32 encoded)
        external
        view
        returns (bool ok, bytes32 out)
    {
        Ristretto255.Point memory p;
        (ok, p) = Ristretto255.decode(encoded);
        if (ok) out = Ristretto255.encode(p);
    }

    function add(bytes32 a, bytes32 b)
        external
        view
        returns (bool ok, bytes32 out)
    {
        (bool okA, Ristretto255.Point memory pa) = Ristretto255.decode(a);
        (bool okB, Ristretto255.Point memory pb) = Ristretto255.decode(b);
        if (!okA || !okB) return (false, out);
        return (true, Ristretto255.encode(Ristretto255.add(pa, pb)));
    }

    function sub(bytes32 a, bytes32 b)
        external
        view
        returns (bool ok, bytes32 out)
    {
        (bool okA, Ristretto255.Point memory pa) = Ristretto255.decode(a);
        (bool okB, Ristretto255.Point memory pb) = Ristretto255.decode(b);
        if (!okA || !okB) return (false, out);
        return (true, Ristretto255.encode(Ristretto255.sub(pa, pb)));
    }

    function mul(bytes32 scalar, bytes32 point)
        external
        view
        returns (bool ok, bytes32 out)
    {
        (bool okS, uint256 k) = Ristretto255.scalarFromLE(scalar);
        (bool okP, Ristretto255.Point memory p) = Ristretto255.decode(point);
        if (!okS || !okP) return (false, out);
        return (true, Ristretto255.encode(Ristretto255.scalarMul(k, p)));
    }

    function mulBase(bytes32 scalar)
        external
        view
        returns (bool ok, bytes32 out)
    {
        (bool okS, uint256 k) = Ristretto255.scalarFromLE(scalar);
        if (!okS) return (false, out);
        return (
            true,
            Ristretto255.encode(
                Ristretto255.scalarMul(k, Ristretto255.basepoint())
            )
        );
    }

    function basepointEncoding() external view returns (bytes32) {
        return Ristretto255.encode(Ristretto255.basepoint());
    }
}
