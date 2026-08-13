// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// Gas measurement for the primitives an Ethereum-side MobileCoin verifier
/// needs. The design left the verifier strategy at "prototype and measure";
/// this measures.
///
/// The dominant unknown is Ed25519 signature verification, because Ethereum
/// has no Ed25519 precompile (EIP-665 is stagnant) and MobileCoin validators
/// sign block IDs with Ed25519. One verification is ~2 scalar multiplications,
/// so `scalarMul` below is the number that decides the strategy.
contract Primitives {
    // Ed25519 field: p = 2^255 - 19
    uint256 constant P =
        0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed;
    // d = -121665/121666 mod p
    uint256 constant D =
        0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3;

    struct Pt { uint256 X; uint256 Y; uint256 Z; uint256 T; }

    /// Extended twisted Edwards doubling, a = -1.
    function _dbl(Pt memory p) internal pure returns (Pt memory r) {
        uint256 A = mulmod(p.X, p.X, P);
        uint256 B = mulmod(p.Y, p.Y, P);
        uint256 C = mulmod(2, mulmod(p.Z, p.Z, P), P);
        uint256 H = addmod(A, B, P);
        uint256 xy = addmod(p.X, p.Y, P);
        uint256 E = addmod(H, P - mulmod(xy, xy, P), P);
        uint256 G = addmod(A, P - B, P);
        uint256 F = addmod(C, G, P);
        r.X = mulmod(E, F, P);
        r.Y = mulmod(G, H, P);
        r.T = mulmod(E, H, P);
        r.Z = mulmod(F, G, P);
    }

    /// Extended twisted Edwards addition, a = -1.
    function _add(Pt memory p, Pt memory q) internal pure returns (Pt memory r) {
        uint256 A = mulmod(addmod(p.Y, P - p.X, P), addmod(q.Y, P - q.X, P), P);
        uint256 B = mulmod(addmod(p.Y, p.X, P), addmod(q.Y, q.X, P), P);
        uint256 C = mulmod(mulmod(p.T, mulmod(2, D, P), P), q.T, P);
        uint256 Dd = mulmod(p.Z, mulmod(2, q.Z, P), P);
        uint256 E = addmod(B, P - A, P);
        uint256 F = addmod(Dd, P - C, P);
        uint256 G = addmod(Dd, C, P);
        uint256 H = addmod(B, A, P);
        r.X = mulmod(E, F, P);
        r.Y = mulmod(G, H, P);
        r.T = mulmod(E, H, P);
        r.Z = mulmod(F, G, P);
    }

    /// One Ed25519 scalar multiplication, double-and-add over 255 bits.
    /// An Ed25519 verification needs roughly two of these.
    function scalarMul(uint256 k, uint256 x, uint256 y)
        external pure returns (uint256, uint256, uint256)
    {
        Pt memory acc = Pt(0, 1, 1, 0);              // identity
        Pt memory base = Pt(x, y, 1, mulmod(x, y, P));
        for (uint256 i = 0; i < 255; i++) {
            if ((k >> i) & 1 == 1) {
                acc = _add(acc, base);
            }
            base = _dbl(base);
        }
        return (acc.X, acc.Y, acc.Z);
    }

    /// Blake2b compression via precompile 0x09 (EIP-152), used by MobileCoin's
    /// TxOut Merkle tree. Cheap: 1 gas per round.
    function blake2bF(uint32 rounds, bytes32[2] memory h, bytes32[4] memory m,
                      bytes8[2] memory t, bool f)
        external view returns (bytes32[2] memory out)
    {
        bytes memory args = abi.encodePacked(rounds, h[0], h[1], m[0], m[1],
                                             m[2], m[3], t[0], t[1], f);
        assembly {
            if iszero(staticcall(not(0), 0x09, add(args, 32), 0xd5, out, 0x40)) {
                revert(0, 0)
            }
        }
    }

    /// FAITHFUL Keccak-f[1600]. The version previously here omitted rho, pi
    /// and the round constants; its cost was not a Keccak cost and was pulled
    /// from the report rather than labelled. Merlin/STROBE -- which MobileCoin
    /// uses to digest BlockMetadataContents before each validator signature --
    /// is built on this permutation, and the `keccak256` opcode computes a
    /// full hash rather than exposing the raw permutation, so it cannot be
    /// reused. Gated on all 25 lanes of the all-zero test vector.
    uint256 constant MASK64 = 0xFFFFFFFFFFFFFFFF;

    function _rol(uint256 x, uint256 n) private pure returns (uint256) {
        if (n == 0) return x & MASK64;
        return ((x << n) | ((x & MASK64) >> (64 - n))) & MASK64;
    }

    function keccakF1600(uint256[25] memory a)
        public pure returns (uint256[25] memory)
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

    /// N permutations in ONE call, so a multi-permutation cost is measured
    /// rather than multiplied out. A Merlin transcript over an S-byte message
    /// needs roughly ceil(S / rate) of these, and MobileCoin runs one
    /// transcript PER VALIDATOR over metadata that includes attestation
    /// evidence -- so nothing amortizes across the quorum.
    function keccakF1600Batch(uint256 n, uint256[25] memory a)
        external pure returns (uint256 acc)
    {
        for (uint256 i = 0; i < n; i++) {
            a = keccakF1600(a);
            acc ^= a[0];
        }
    }

    /// JOINT double-scalar multiplication, [s]B + [k]A, via Shamir's trick:
    /// one doubling per bit for BOTH scalars, adding whichever combination the
    /// bit pair selects. This is what a real Ed25519 verifier evaluates -- NOT
    /// two independent generic multiplications, which is what an earlier
    /// version of this file extrapolated from and which overstates the cost.
    function jointDoubleScalarMul(
        uint256 s1, uint256 x1, uint256 y1,
        uint256 s2, uint256 x2, uint256 y2
    ) public pure returns (uint256, uint256, uint256) {
        Pt memory acc = Pt(0, 1, 1, 0);
        Pt memory p1 = Pt(x1, y1, 1, mulmod(x1, y1, P));
        Pt memory p2 = Pt(x2, y2, 1, mulmod(x2, y2, P));
        Pt memory both = _add(p1, p2);          // precomputed p1+p2
        for (uint256 i = 255; i > 0; i--) {
            acc = _dbl(acc);
            uint256 b1 = (s1 >> (i - 1)) & 1;
            uint256 b2 = (s2 >> (i - 1)) & 1;
            if (b1 == 1 && b2 == 1)      { acc = _add(acc, both); }
            else if (b1 == 1)            { acc = _add(acc, p1);   }
            else if (b2 == 1)            { acc = _add(acc, p2);   }
        }
        return (acc.X, acc.Y, acc.Z);
    }

    /// A QUORUM of joint double-scalar multiplications, measured as one call
    /// so the total is measured rather than multiplied out. Excludes point
    /// decompression, SHA-512 challenge derivation and small-order checks --
    /// see the runner, which says so.
    function quorumEd25519(uint256 n, uint256 s1, uint256 x1, uint256 y1,
                           uint256 s2, uint256 x2, uint256 y2)
        external pure returns (uint256 acc)
    {
        for (uint256 i = 0; i < n; i++) {
            // vary the scalar per validator: the messages genuinely differ
            (uint256 X,,) = jointDoubleScalarMul(s1 + i, x1, y1, s2 + i, x2, y2);
            acc ^= X;
        }
    }

    /// The same quorum shape via ecrecover, measured the same way.
    function quorumEcrecover(uint256 n, bytes32 h, uint8 v, bytes32 r, bytes32 s)
        external pure returns (uint256 acc)
    {
        for (uint256 i = 0; i < n; i++) {
            address a = ecrecover(bytes32(uint256(h) + i), v, r, s);
            acc ^= uint256(uint160(a));
        }
    }

    /// Baseline: an ecrecover, for comparison. This is what a secp256k1
    /// auxiliary block signature would cost instead.
    function ecrecoverCost(bytes32 h, uint8 v, bytes32 r, bytes32 s)
        external pure returns (address)
    {
        return ecrecover(h, v, r, s);
    }
}
