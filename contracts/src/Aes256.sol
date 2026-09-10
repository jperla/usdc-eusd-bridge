// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// AES-256, encryption direction only, in counter mode.
///
/// MobileCoin encrypts a TxOut's 66-byte `e_memo` with AES-256 keyed by an
/// HKDF output derived from the TxOut shared secret
/// (`transaction/core/src/memo.rs`). Recovering the Ethereum beneficiary that
/// this repo's `0x8001` bridge memo carries therefore needs AES on chain, and
/// Ethereum has no AES precompile.
///
/// ENCRYPTION ONLY, ON PURPOSE. Counter mode never invokes the block cipher
/// backwards: both encryption and decryption XOR the plaintext with
/// E_k(counter). There is no InvSubBytes, no InvMixColumns and no inverse key
/// schedule here, and there must not be -- an inverse cipher would be a second
/// implementation of the same table with no test exercising it.
///
/// COUNTER WIDTH IS 64 BITS, ALSO ON PURPOSE. See `keystream`.
///
/// This library has no failure mode and so declares no errors: AES is a
/// permutation on every 128-bit input under every 256-bit key, and the counter
/// is allowed to wrap. An error here could not be reached by any test.
library Aes256 {
    // ---------------------------------------------------------------- tables

    /// The AES S-box (FIPS 197 Figure 7), 256 bytes in index order, packed
    /// eight words at a time.
    ///
    /// These are transcribed constants, so `test/aes.mjs` re-derives the table
    /// from its algebraic definition -- multiplicative inverse in GF(2^8)
    /// modulo x^8 + x^4 + x^3 + x + 1, then the affine transform of FIPS 197
    /// 5.1.1 -- and compares, rather than checking one transcription against
    /// another transcription of the same table.
    uint256 private constant SBOX0 =
        0x637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0;
    uint256 private constant SBOX1 =
        0xb7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275;
    uint256 private constant SBOX2 =
        0x09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf;
    uint256 private constant SBOX3 =
        0xd0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2;
    uint256 private constant SBOX4 =
        0xcd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb;
    uint256 private constant SBOX5 =
        0xe0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08;
    uint256 private constant SBOX6 =
        0xba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e;
    uint256 private constant SBOX7 =
        0xe1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16;

    /// Materialise the S-box as 256 contiguous bytes of memory and return a
    /// pointer to byte 0, so a substitution is one MLOAD instead of a chain of
    /// comparisons against eight constants.
    function _sbox() private pure returns (uint256 p) {
        assembly ("memory-safe") {
            p := mload(0x40)
            // 256 table bytes plus 32 bytes of slack. `_sub` reads a whole
            // 32-byte word starting at the indexed byte, so index 255 reads 31
            // bytes past the table; the slack keeps that read inside this
            // allocation instead of over whatever is allocated next.
            mstore(0x40, add(p, 288))
            mstore(p, SBOX0)
            mstore(add(p, 32), SBOX1)
            mstore(add(p, 64), SBOX2)
            mstore(add(p, 96), SBOX3)
            mstore(add(p, 128), SBOX4)
            mstore(add(p, 160), SBOX5)
            mstore(add(p, 192), SBOX6)
            mstore(add(p, 224), SBOX7)
            mstore(add(p, 256), 0)
        }
    }

    /// S-box lookup. `x` MUST already be masked to 8 bits: an out-of-range
    /// index silently reads past the table rather than reverting. Every call
    /// site below feeds it a `& 0xff` or a `uint8`.
    function _sub(uint256 p, uint256 x) private pure returns (uint256 v) {
        assembly ("memory-safe") {
            v := shr(248, mload(add(p, x)))
        }
    }

    /// xtime: multiply by x (i.e. by 2) in GF(2^8) modulo the AES polynomial
    /// x^8 + x^4 + x^3 + x + 1 = 0x11b (FIPS 197 4.2.1). The reduction fires
    /// exactly when bit 7 was set, which `s >> 7` selects.
    function _x2(uint256 s) private pure returns (uint256) {
        unchecked {
            return ((s << 1) ^ ((s >> 7) * 0x1b)) & 0xff;
        }
    }

    /// Byte `i` of a 16-byte state held as a big-endian 128-bit integer, where
    /// byte 0 is the most significant. FIPS 197 3.4 numbers the input bytes
    /// this way, with state cell a[r][c] at byte index 4c + r.
    function _byteAt(uint256 st, uint256 i) private pure returns (uint256) {
        unchecked {
            return (st >> (8 * (15 - i))) & 0xff;
        }
    }

    // ----------------------------------------------------------- key schedule

    /// SubWord (FIPS 197 5.2): the S-box applied to each of four bytes.
    function _subWord(uint256 p, uint256 w) private pure returns (uint256) {
        unchecked {
            return (_sub(p, (w >> 24) & 0xff) << 24)
                | (_sub(p, (w >> 16) & 0xff) << 16)
                | (_sub(p, (w >> 8) & 0xff) << 8)
                | _sub(p, w & 0xff);
        }
    }

    /// The AES-256 key schedule (FIPS 197 5.2 with Nk = 8, Nr = 14), returned
    /// as the fifteen 128-bit round keys rather than the sixty 32-bit words,
    /// because AddRoundKey wants them a round at a time.
    function _expandKey(uint256 p, bytes32 key)
        private
        pure
        returns (uint256[15] memory rk)
    {
        unchecked {
            // Eight live words instead of the sixty-word array of FIPS 197's
            // pseudocode. w0..w7 always hold w[i-8..i-1] for the next word i
            // to be produced, which is exactly the window the recurrence
            // w[i] = w[i-8] ^ t needs; assigning into w0 both consumes w[i-8]
            // and publishes w[i], because the slot's meaning advances with it.
            uint256 k = uint256(key);
            uint256 w0 = (k >> 224) & 0xffffffff;
            uint256 w1 = (k >> 192) & 0xffffffff;
            uint256 w2 = (k >> 160) & 0xffffffff;
            uint256 w3 = (k >> 128) & 0xffffffff;
            uint256 w4 = (k >> 96) & 0xffffffff;
            uint256 w5 = (k >> 64) & 0xffffffff;
            uint256 w6 = (k >> 32) & 0xffffffff;
            uint256 w7 = k & 0xffffffff;

            // Round key r is w[4r..4r+3]; word 4r+c becomes column c, which is
            // bytes 4c..4c+3 of the state. So each group of eight words is two
            // round keys, and the 256-bit key is round keys 0 and 1 verbatim.
            rk[0] = (w0 << 96) | (w1 << 64) | (w2 << 32) | w3;
            rk[1] = (w4 << 96) | (w5 << 64) | (w6 << 32) | w7;

            uint256 rcon = 0x01;
            for (uint256 g = 1; g <= 7; g++) {
                // i % 8 == 0: RotWord, then SubWord, then Rcon in the high
                // byte.
                w0 ^= _subWord(p, ((w7 << 8) | (w7 >> 24)) & 0xffffffff)
                    ^ (rcon << 24);
                // Rcon[j] = x^(j-1) in GF(2^8). AES-256 uses only j = 1..7,
                // i.e. 0x01 .. 0x40, so the doubling never crosses 0x80 and
                // never needs the 0x1b reduction that AES-128 (j up to 10)
                // does. This library is AES-256 only; a shift is exact here.
                rcon <<= 1;
                w1 ^= w0;
                w2 ^= w1;
                w3 ^= w2;
                rk[2 * g] = (w0 << 96) | (w1 << 64) | (w2 << 32) | w3;

                // Fifteen round keys is sixty words; the last group supplies
                // only its first half, so stop before generating w[60..63].
                if (g == 7) break;

                // i % 8 == 4: a plain SubWord with no rotation and no Rcon.
                // This extra substitution halfway through the group is what
                // makes the 256-bit schedule differ from the 128-bit one.
                w4 ^= _subWord(p, w3);
                w5 ^= w4;
                w6 ^= w5;
                w7 ^= w6;
                rk[2 * g + 1] = (w4 << 96) | (w5 << 64) | (w6 << 32) | w7;
            }
        }
    }

    // ------------------------------------------------------------ block cipher

    // Which state bytes feed each output column, once ShiftRows is folded in.
    //
    // ShiftRows (FIPS 197 5.1.2) sends a[r][c] to a[r][(c - r) mod 4], so
    // output column j is built from a[0][j], a[1][j+1], a[2][j+2], a[3][j+3]
    // with the column index taken mod 4. Byte index of a[r][c] is 4c + r
    // (FIPS 197 3.4), which gives:
    //
    //     column 0:  0,  5, 10, 15
    //     column 1:  4,  9, 14,  3
    //     column 2:  8, 13,  2,  7
    //     column 3: 12,  1,  6, 11
    //
    // -- the familiar AES diagonals. Reading those cells directly performs
    // ShiftRows without a separate pass over the state. They are written out
    // as literals in `_round`/`_lastRound` rather than computed from a loop
    // index, because that lets the compiler fold every shift amount to a
    // constant: measured, 40.2k gas per block with a loop against 28.3k with
    // the indices spelled out.

    /// One full round: SubBytes, ShiftRows and MixColumns fused.
    ///
    /// MixColumns (FIPS 197 5.1.3) multiplies each column by the fixed matrix
    /// [[2,3,1,1],[1,2,3,1],[1,1,2,3],[3,1,1,2]] over GF(2^8). With d = 2s
    /// from `_x2`, the 3s terms are d ^ s.
    function _mixCol(
        uint256 p,
        uint256 st,
        uint256 i0,
        uint256 i1,
        uint256 i2,
        uint256 i3
    ) private pure returns (uint256) {
        unchecked {
            uint256 s0 = _sub(p, _byteAt(st, i0));
            uint256 s1 = _sub(p, _byteAt(st, i1));
            uint256 s2 = _sub(p, _byteAt(st, i2));
            uint256 s3 = _sub(p, _byteAt(st, i3));

            uint256 d0 = _x2(s0);
            uint256 d1 = _x2(s1);
            uint256 d2 = _x2(s2);
            uint256 d3 = _x2(s3);

            return ((d0 ^ d1 ^ s1 ^ s2 ^ s3) << 24) // 2 3 1 1
                | ((s0 ^ d1 ^ d2 ^ s2 ^ s3) << 16) //  1 2 3 1
                | ((s0 ^ s1 ^ d2 ^ d3 ^ s3) << 8) //   1 1 2 3
                | (d0 ^ s0 ^ s1 ^ s2 ^ d3); //         3 1 1 2
        }
    }

    /// The same column, SubBytes and ShiftRows only: the last round omits
    /// MixColumns (FIPS 197 5.1).
    function _subCol(
        uint256 p,
        uint256 st,
        uint256 i0,
        uint256 i1,
        uint256 i2,
        uint256 i3
    ) private pure returns (uint256) {
        unchecked {
            return (_sub(p, _byteAt(st, i0)) << 24)
                | (_sub(p, _byteAt(st, i1)) << 16)
                | (_sub(p, _byteAt(st, i2)) << 8)
                | _sub(p, _byteAt(st, i3));
        }
    }

    function _round(uint256 p, uint256 st) private pure returns (uint256) {
        unchecked {
            // Column j lands in state bytes 4j..4j+3, i.e. at bit 96 - 32j.
            return (_mixCol(p, st, 0, 5, 10, 15) << 96)
                | (_mixCol(p, st, 4, 9, 14, 3) << 64)
                | (_mixCol(p, st, 8, 13, 2, 7) << 32)
                | _mixCol(p, st, 12, 1, 6, 11);
        }
    }

    function _lastRound(uint256 p, uint256 st) private pure returns (uint256) {
        unchecked {
            return (_subCol(p, st, 0, 5, 10, 15) << 96)
                | (_subCol(p, st, 4, 9, 14, 3) << 64)
                | (_subCol(p, st, 8, 13, 2, 7) << 32)
                | _subCol(p, st, 12, 1, 6, 11);
        }
    }

    /// AES-256 Cipher (FIPS 197 5.1): AddRoundKey, then 13 full rounds, then
    /// the truncated final round. `st` and the result are 16-byte blocks held
    /// big-endian in the low 128 bits.
    function _encryptBlock(uint256 p, uint256[15] memory rk, uint256 st)
        private
        pure
        returns (uint256)
    {
        unchecked {
            st ^= rk[0];
            for (uint256 r = 1; r < 14; r++) {
                st = _round(p, st) ^ rk[r];
            }
            return _lastRound(p, st) ^ rk[14];
        }
    }

    /// A single AES-256 block encryption, for known-answer tests against the
    /// FIPS 197 and SP 800-38A ECB vectors. Nothing in the bridge calls it:
    /// production traffic goes through `keystream`/`ctr`, which reach the same
    /// core, so this is a window onto the cipher rather than a second path.
    function encryptBlock(bytes32 key, bytes16 input)
        internal
        pure
        returns (bytes16)
    {
        uint256 p = _sbox();
        uint256[15] memory rk = _expandKey(p, key);
        return bytes16(uint128(_encryptBlock(p, rk, uint256(uint128(input)))));
    }

    // -------------------------------------------------------------------- CTR

    /// `outLen` bytes of AES-256 counter-mode keystream from `key` and
    /// `nonce`.
    ///
    /// THE COUNTER IS 64 BITS WIDE. Only bytes 8..16 of the nonce increment;
    /// bytes 0..8 are fixed and take no carry, so the counter wraps from
    /// 0xffffffffffffffff straight back to zero. That is RustCrypto's
    /// `Ctr64BE<Aes256>`, which is what MobileCoin instantiates in
    /// `transaction/core/src/memo.rs`.
    ///
    /// The near-universal alternative, Ctr128BE, increments the whole block
    /// and agrees with this on every input whose low 64 bits are further than
    /// (blocks - 1) from 2^64 - 1 -- which is every nonce anyone will ever see
    /// derived from a real HKDF output. Sampling real memos cannot tell the two
    /// apart; `test/aes.mjs` uses the fixture's hand-placed wrapping nonces,
    /// which can.
    function keystream(bytes32 key, bytes16 nonce, uint256 outLen)
        internal
        pure
        returns (bytes memory out)
    {
        uint256 p = _sbox();
        uint256[15] memory rk = _expandKey(p, key);
        out = new bytes(outLen);

        uint256 n = uint256(uint128(nonce));
        uint256 hi = n >> 64; // bytes 0..8, never touched
        uint256 ctr = n & 0xffffffffffffffff; // bytes 8..16, the counter

        unchecked {
            for (uint256 off = 0; off < outLen; off += 16) {
                uint256 blk = _encryptBlock(p, rk, (hi << 64) | ctr);
                // 64-bit wrap with no carry into `hi`.
                ctr = (ctr + 1) & 0xffffffffffffffff;

                uint256 take = outLen - off < 16 ? outLen - off : 16;
                for (uint256 i = 0; i < take; i++) {
                    out[off + i] = bytes1(uint8(blk >> (8 * (15 - i))));
                }
            }
        }
    }

    /// `data` XOR-ed with the keystream. Encryption and decryption are the
    /// same operation in CTR, so this both seals and opens a memo.
    function ctr(bytes32 key, bytes16 nonce, bytes memory data)
        internal
        pure
        returns (bytes memory out)
    {
        out = keystream(key, nonce, data.length);
        unchecked {
            for (uint256 i = 0; i < data.length; i++) {
                out[i] = out[i] ^ data[i];
            }
        }
    }

    /// The S-box as 256 bytes in index order, exposed so a test can check the
    /// packed constants against the algebraic definition.
    function sboxTable() internal pure returns (bytes memory t) {
        uint256 p = _sbox();
        t = new bytes(256);
        assembly ("memory-safe") {
            let d := add(t, 32)
            for { let i := 0 } lt(i, 256) { i := add(i, 32) } {
                mstore(add(d, i), mload(add(p, i)))
            }
        }
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
/// Test wrapper: libraries with internal functions have no ABI of their own.
///
/// EVERY VARIABLE-LENGTH RESULT LEAVES THIS CONTRACT AS FIXED WORDS, not as a
/// `bytes`. That is a harness constraint, not a design opinion: solc 0.8.26
/// defaults to the Cancun EVM and ABI-encodes a returned dynamic array with
/// MCOPY (EIP-5656), while the ethereumjs EVM 3.1.1 that `test/harness.mjs`
/// instantiates runs Shanghai, where MCOPY is an invalid opcode. A probe
/// returning `bytes` dies with "invalid opcode" before its first assertion.
///
/// `Aes256` itself is untouched by this and keeps its natural `bytes memory`
/// API for the verifier: it builds its output a byte at a time and emits no
/// MCOPY, which is why `keystreamGas` below runs the real function to
/// completion on the same Shanghai EVM.
contract Aes256Probe_DO_NOT_DEPLOY {
    /// The probe's four-word return cannot hold more than this.
    error ProbeOutputTooLong(uint256 len);
    /// The S-box is eight words wide.
    error ProbeBadIndex(uint256 i);

    /// Left-align a short byte string into four words, zero-filled.
    function _pack(bytes memory x)
        private
        pure
        returns (bytes32 a, bytes32 b, bytes32 c, bytes32 d)
    {
        if (x.length > 128) revert ProbeOutputTooLong(x.length);
        bytes memory z = new bytes(128); // zero-filled by construction
        for (uint256 i = 0; i < x.length; i++) z[i] = x[i];
        assembly ("memory-safe") {
            a := mload(add(z, 32))
            b := mload(add(z, 64))
            c := mload(add(z, 96))
            d := mload(add(z, 128))
        }
    }

    function encryptBlock(bytes32 key, bytes16 input)
        external
        pure
        returns (bytes16)
    {
        return Aes256.encryptBlock(key, input);
    }

    function keystream(bytes32 key, bytes16 nonce, uint256 outLen)
        external
        pure
        returns (bytes32, bytes32, bytes32, bytes32)
    {
        return _pack(Aes256.keystream(key, nonce, outLen));
    }

    function ctr(bytes32 key, bytes16 nonce, bytes memory data)
        external
        pure
        returns (bytes32, bytes32, bytes32, bytes32)
    {
        return _pack(Aes256.ctr(key, nonce, data));
    }

    /// Word `i` of the 256-byte S-box, i in 0..7.
    function sboxWord(uint256 i) external pure returns (bytes32 w) {
        if (i >= 8) revert ProbeBadIndex(i);
        bytes memory t = Aes256.sboxTable();
        assembly ("memory-safe") {
            w := mload(add(add(t, 32), mul(i, 32)))
        }
    }

    /// Gas for the library call alone, without calldata or ABI-return costs.
    ///
    /// The digest of the result is returned as well so the optimizer cannot
    /// decide the keystream is dead and delete the work being measured.
    function keystreamGas(bytes32 key, bytes16 nonce, uint256 outLen)
        external
        view
        returns (uint256 used, bytes32 digest)
    {
        uint256 g0 = gasleft();
        bytes memory ks = Aes256.keystream(key, nonce, outLen);
        used = g0 - gasleft();
        digest = keccak256(ks);
    }

    /// The same measurement for `ctr`, which is the shape the verifier calls:
    /// a keystream plus the XOR pass over the memo.
    function ctrGas(bytes32 key, bytes16 nonce, bytes memory data)
        external
        view
        returns (uint256 used, bytes32 digest)
    {
        uint256 g0 = gasleft();
        bytes memory pt = Aes256.ctr(key, nonce, data);
        used = g0 - gasleft();
        digest = keccak256(pt);
    }
}
