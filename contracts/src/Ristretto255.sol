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
/// * Cofactor-free. Valid representatives lie in the even Edwards subgroup;
///   quotienting its order-four torsion subgroup yields a prime-order group.
///   Arbitrary Edwards points are not valid ristretto representatives. The
///   public decoder admits no non-identity small-order group element.
///
/// Follows the reference construction in curve25519-dalek (the implementation
/// MobileCoin itself links), including its SQRT_RATIO_M1 sign conventions.
/// Tested against dalek, the RFC 9496 vectors and independent noble fixtures.
/// Finite vectors do not prove correctness for every possible group element.
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

    /// sqrt(-1) mod p: the non-negative root, the exact integer published by
    /// RFC 9496 section 4.1.
    ///
    /// WHICH ROOT THIS IS MATTERS. This comment used to say the opposite --
    /// "changes no output" -- and that was true of the file it was written for
    /// and false as soon as `_map` landed. The old reasoning covered only the
    /// two callers that existed then: `_sqrtRatio` normalizes to the
    /// non-negative root, and `encode`'s rotated branch scales both coordinates
    /// by it before that same normalization, so decode and encode really are
    /// insensitive to the choice.
    ///
    /// `_map` is not. It multiplies by this constant DIRECTLY, in
    /// `r = SQRT_M1 * t^2`, and then consumes `_sqrtRatio`'s non-square result
    /// in the false arm -- the one case the old argument dismissed as
    /// discarded. Writing M_i for the map under root i, the other root gives
    ///
    ///     M_-i(t) = M_i(i*t)
    ///
    /// which is the same FUNCTION over the whole input space and a different
    /// answer for any particular t. At t = 2 the two roots encode to
    /// 5a603cec... and cefca57d..., which are different points. A generator
    /// derived under the wrong root is a wrong `B_token`, silently.
    ///
    /// So the value is forced, and forced by the RFC rather than by dalek: the
    /// oracles corroborate it, they are not the authority for it.
    uint256 private constant SQRT_M1 =
        19681161376707505956807079304988542015446066515923890162744021073123829784752;

    /// 1/sqrt(a - d) with a = -1, dalek's INVSQRT_A_MINUS_D. Only the encoder's
    /// rotated branch uses it, where the final |s| makes its sign immaterial.
    uint256 private constant INVSQRT_A_MINUS_D =
        54469307008909316920995813868745141605393597292927456921205312896311721017578;

    /// 1 - d^2, dalek's ONE_MINUS_EDWARDS_D_SQUARED, RFC 9496's ONE_MINUS_D_SQ.
    ///
    /// It is one minus d SQUARED, not (1 - d) squared. The two names sit next
    /// to each other in the same formula and are different numbers.
    uint256 private constant ONE_MINUS_D_SQ =
        1159843021668779879193775521855586647937357759715417654439879720876111806838;

    /// (d - 1)^2, dalek's EDWARDS_D_MINUS_ONE_SQUARED, RFC 9496's D_MINUS_ONE_SQ.
    uint256 private constant D_MINUS_ONE_SQ =
        40440834346308536858101042469323190826248399146238708352240133220865137265952;

    /// sqrt(a*d - 1) with a = -1, i.e. sqrt(-d - 1): dalek's SQRT_AD_MINUS_ONE.
    ///
    /// WHICH ROOT THIS IS MATTERS. It scales `w1`, and `w1` multiplies both Y
    /// and Z of the map's output, so y = Y/Z survives the swap while x = X/Z
    /// flips sign -- the other root maps every input to the NEGATION of the
    /// right point, quietly and without any error. (Stated precisely: the swap
    /// sends (X,Y,Z,T) to (X,-Y,-Z,T), which is projectively (-X,Y,Z,-T), the
    /// Edwards negation. Identity outputs are unmoved, since 0 = -0.)
    ///
    /// The exact integer is REQUIRED BY RFC 9496 section 4.1 -- it is the
    /// odd/RFC-negative root of -d-1 -- so the choice is forced by the
    /// specification, not by dalek's convention. The oracle corroborates it: p
    /// minus this value reproduces none of amount.json's four `B_token`s, and
    /// this value reproduces all four. That is evidence, not the authority.
    uint256 private constant SQRT_AD_MINUS_ONE =
        25063068953384623474111414158702152701244531502492656460079210482610430750235;

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
        if (!square || t & 1 == 1 || y == 0) return (false, p);

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

        // The flag is not consulted, and the reason is NOT that the ratio is
        // always a square -- it is not. At the identity u1 and u2 are both
        // zero, so this is `_sqrtRatio(1, 0)`, which is the u != 0, v = 0 case
        // and returns (false, 0). Ignoring the flag is still right: the zero
        // root falls through to s = 0, which is the identity's encoding.
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

    // ------------------------------------------------------------ one-way map

    /// The ristretto255 one-way map on a 64-byte uniform string: RFC 9496
    /// section 4.3.4, dalek's `RistrettoPoint::from_uniform_bytes`.
    ///
    /// Each 32-byte half becomes a field element and is mapped separately, and
    /// the two results are ADDED. One application of the map is not surjective
    /// and not uniform; two and a sum are. Halving this to a single map would
    /// still produce a point on the curve for every input, which is exactly why
    /// it has to be pinned against an oracle rather than eyeballed.
    ///
    /// This is `from_hash` over a Blake2b-512 digest -- NOT `decode`. The input
    /// is a hash, not an encoding, and there is no failure case: every 64-byte
    /// string maps to a point.
    ///
    /// `lo` is digest bytes 0..32 and `hi` bytes 32..64, each little-endian.
    function fromUniformBytes(bytes32 lo, bytes32 hi)
        internal
        view
        returns (Point memory)
    {
        return add(_map(_fieldFromLE(lo)), _map(_fieldFromLE(hi)));
    }

    /// dalek's `FieldElement::from_bytes`: the low 255 bits, reduced.
    ///
    /// THE HIGH BIT IS DISCARDED, not rejected and not kept. A 64-byte hash has
    /// no reason to be canonical, so this is not `decode`'s canonicality rule
    /// wearing a different name -- it is what RFC 9496 section 4.3.4 specifies
    /// for the one-way map, and it is deliberately different from section
    /// 4.3.1, which requires `decode` to REJECT a set high bit. The two are
    /// inconsistent only if you forget that one takes an encoding and the other
    /// takes a hash.
    ///
    /// It changes the answer: 2^255 = 19 (mod p), so keeping the bit feeds the
    /// map the field element t + 19 instead of t. NOT "the point 19 further
    /// along" -- the map is not linear, and the output is not a translation of
    /// the right one. It is an unrelated point.
    ///
    /// COVERAGE, STATED HONESTLY. Four of the eight halves the fixture's
    /// generators hash to have this bit set, and contracts/test/ristretto.mjs's
    /// 'the high bit of each half is DISCARDED' requires exactly four rather
    /// than the "at least one" it used to require, which a regenerated fixture
    /// could satisfy while quietly dropping most of the coverage.
    ///
    /// But those four are not spread one per generator, and it matters which:
    ///
    ///     token 0        low half only
    ///     token 1        high half only
    ///     token 8192     NEITHER
    ///     u64::MAX       both
    ///
    /// So an implementation that skipped the mask still reproduces token
    /// 8192 -- eUSD, the only id this bridge actually deploys for -- exactly.
    /// The claim that used to sit here, that skipping the mask "reproduces none
    /// of them", is false, and false precisely where it would be trusted most.
    /// What defends the mask for eUSD is the 62-vector noble cross-check, not
    /// amount.json.
    ///
    /// THE `% P` IS NOT OUTPUT-BEARING, AND IS NOT DEAD CODE. Removing it
    /// leaves the whole suite green -- after masking the value is at most
    /// p + 18, and every use of it in `_map` goes through `mulmod`, which
    /// reduces anyway. It stays because RFC 9496 section 4.3.4 specifies the
    /// reduction and because it is what keeps "this function returns a field
    /// element" true for the next caller, which may not be `mulmod`. Recorded
    /// here because "the tests still pass without it" is exactly the argument
    /// that would delete it.
    function _fieldFromLE(bytes32 b) private pure returns (uint256) {
        return (_fromLE(b) & ((uint256(1) << 255) - 1)) % P;
    }

    /// MAP(t) from RFC 9496 section 4.3.4 -- dalek's
    /// `elligator_ristretto_flavor`. Returns extended coordinates.
    ///
    /// Even: MAP(t) == MAP(-t). `r` depends on t^2 and the only other use of
    /// `t` is inside an absolute value, so the sign of the input cannot reach
    /// the output. Asserted in contracts/test/ristretto.mjs, because dropping
    /// that absolute value is the easiest way to get this function subtly wrong.
    ///
    /// That evenness property used to be the ONLY thing standing over the
    /// absolute value: none of the four `bToken` vectors from MobileCoin's own
    /// crates fails when it is removed. It is now backed by a differential
    /// check against noble-curves 1.9.7 (an implementation that is neither
    /// this file nor the dalek behind the fixtures) over 62 map inputs and 56
    /// token ids, in contracts/test/fixtures/ristretto-noble.json. That check
    /// catches the same deletion at 20 and 21 of them respectively.
    ///
    /// `den` CAN BE ZERO, and must be left alone when it is. It vanishes at
    /// r = -d and r = -1/d, both of which are reached by real field elements
    /// (t^2 = i*d and t^2 = i/d are both squares). There `_sqrtRatio(n, 0)`
    /// takes its u != 0, v = 0 case and returns (false, 0), the false arm sets
    /// s = 0 and c = r, and the result is (0, w1, w1, 0) -- a valid
    /// representation of the identity, satisfying both curve identities. No
    /// input makes Z zero: the quadratics for N = 0 and 1 + s^2 = 0 have
    /// discriminants -4d(d-1)^2 and 4d(d+1)(d-1)^2, both non-squares here.
    ///
    /// So there is nothing to defend against, and defending anyway is the
    /// hazard. Adding `if (den == 0) den = 1;` -- the shape a "this cannot
    /// happen" guard takes -- silently returns a DIFFERENT generator for any
    /// token id whose digest reaches one of those r, and left the whole suite
    /// green until contracts/test/ristretto.mjs grew 'the map's degenerate
    /// branches are REACHED'. Those inputs are solved for from d and i rather
    /// than copied from here, so editing this function cannot move them.
    function _map(uint256 t) private view returns (Point memory) {
        uint256 r = mulmod(SQRT_M1, mulmod(t, t, P), P);
        uint256 n = mulmod(addmod(r, 1, P), ONE_MINUS_D_SQ, P);
        // (c - d*r) * (r + d), with c = -1.
        uint256 den = mulmod(
            addmod(_neg(1), _neg(mulmod(D, r, P)), P), addmod(r, D, P), P
        );

        (bool wasSquare, uint256 s) = _sqrtRatio(n, den);
        uint256 c = _neg(1);
        if (!wasSquare) {
            // s' = -|s*t|, and c becomes r. BOTH substitutions belong to this
            // branch; upstream computes s' unconditionally and assigns it
            // conditionally, which is the same thing without a branch. Two of
            // the fixture's four generators reach this arm, so it is not
            // decoration.
            uint256 sp = mulmod(s, t, P);
            if (sp & 1 == 0) sp = _neg(sp); // negate the non-negative one
            s = sp;
            c = r;
        }

        uint256 nt = addmod(
            mulmod(mulmod(c, addmod(r, _neg(1), P), P), D_MINUS_ONE_SQ, P),
            _neg(den),
            P
        );
        uint256 ss = mulmod(s, s, P);

        // dalek assembles a completed (P1xP1) point here and converts; the
        // conversion is folded into the four products below so nothing has to
        // model a second coordinate system.
        uint256 w0 = mulmod(addmod(s, s, P), den, P);
        uint256 w1 = mulmod(nt, SQRT_AD_MINUS_ONE, P);
        uint256 w2 = addmod(1, _neg(ss), P);
        uint256 w3 = addmod(1, ss, P);

        return Point({
            x: mulmod(w0, w3, P),
            y: mulmod(w2, w1, P),
            z: mulmod(w1, w3, P),
            t: mulmod(w0, w2, P)
        });
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
        // Negation on this curve is a coordinate negation, not a subtraction
        // formula of its own.
        r = add(p, Point({x: _neg(q.x), y: q.y, z: q.z, t: _neg(q.t)}));
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

    /// dalek's SQRT_RATIO_M1, RFC 9496 section 4.2. All four cases the RFC
    /// defines, which "u/v is a square and v != 0" does not quite describe:
    ///
    ///     u = 0, ANY v (including v = 0)  -> (true,  0)
    ///     u != 0, v = 0                   -> (false, 0)
    ///     u/v a non-zero square           -> (true,  +sqrt(u/v))
    ///     u/v a non-zero non-square       -> (false, +sqrt(i*u/v))
    ///
    /// The u = v = 0 case returns TRUE, not false. Both `_map` at a vanishing
    /// denominator and `encode` at the identity reach u != 0, v = 0;
    /// `encode` always supplies u = 1.
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

/// TEST ONLY -- NEVER DEPLOY.
///
/// Test wrapper: the library's functions are internal, and points are memory
/// structs no external caller can hold. The raw-coordinate encoder below is
/// test-only: it checks invariance across equivalent internal representatives,
/// which an encode/decode round trip cannot exercise.
///
/// It lives in this file, and not in `src/TestMocks.sol` with the other
/// test-only contracts, because a wrapper for `internal` functions has to be
/// compiled against the library that declares them. That is a constraint, not
/// an exemption: `contracts/test/deployables.mjs` enumerates every contract in
/// `src/` and fails unless it is either on the deployable allowlist or marked
/// exactly like this one, so a production contract cannot arrive here unnamed.
contract Ristretto255Probe_DO_NOT_DEPLOY {
    /// Inputs must be valid extended coordinates. No production entry point
    /// accepts raw coordinates; this probe lets tests supply independently
    /// generated points, torsion-equivalent representatives and projective
    /// rescalings to the actual encoder.
    function encodeCoordinates(uint256 x, uint256 y, uint256 z, uint256 t)
        external
        view
        returns (bytes32)
    {
        return Ristretto255.encode(Ristretto255.Point(x, y, z, t));
    }

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

    /// The one-way map over a 64-byte string, as an encoding.
    function fromUniformBytes(bytes32 lo, bytes32 hi)
        external
        view
        returns (bytes32)
    {
        return Ristretto255.encode(Ristretto255.fromUniformBytes(lo, hi));
    }

    /// ONE application of MAP, so its evenness can be exercised on a chosen
    /// input instead of only through a digest.
    ///
    /// MAP(0) is the identity, so pairing `t` with a zero half is MAP(t) and
    /// not a sum of two maps. That is asserted by a test rather than taken on
    /// trust here -- if it stopped holding, every use of this probe would be
    /// measuring something else. Feeding the same bytes as BOTH halves would
    /// give [2]MAP(t) and would not do.
    function mapToPoint(bytes32 t) external view returns (bytes32) {
        return Ristretto255.encode(
            Ristretto255.fromUniformBytes(t, bytes32(0))
        );
    }
}
