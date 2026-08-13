// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Sha512} from "./Sha512.sol";

/// HMAC-SHA-512 (RFC 2104 / FIPS 198-1) and HKDF-SHA-512 (RFC 5869).
///
/// MobileCoin derives both halves of a TxOut's secret material with this
/// function and no other. The amount blinding factors come from
/// `HKDF-SHA512(salt = "mc_amount_blinding_factors", ikm = amount_shared_secret)`
/// expanded under three different `info` strings, and the memo's AES key and
/// nonce come from `HKDF-SHA512(salt = "mc-memo-okm", ikm = S).expand("", 48)`.
/// Getting either one wrong does not fail loudly -- it yields a well-formed
/// number that opens the wrong amount or decrypts to the wrong beneficiary, so
/// this file is checked against published vectors rather than against itself.
///
/// THE BLOCK SIZE IS 128 BYTES, NOT 64. HMAC pads the key to the *hash's block
/// size*, which for SHA-512 is 1024 bits (FIPS 180-4 s5.1.2) even though the
/// digest is 512 bits. An implementation that pads to 64 bytes computes a
/// perfectly deterministic, perfectly self-consistent, and completely wrong
/// MAC; it would agree with itself in every round trip and disagree with
/// MobileCoin on every real output. RFC 4231's test vectors are the check that
/// catches it, and `test/hkdf.mjs` runs all seven.
library Hkdf {
    /// RFC 5869 s2.3 caps the output at 255 * HashLen; the counter is a single
    /// byte and would silently wrap past that.
    error HkdfOutputTooLong(uint256 length, uint256 max);

    /// SHA-512's message block, in bytes -- see the note above.
    uint256 private constant BLOCK_BYTES = 128;
    /// SHA-512's digest, in bytes.
    uint256 private constant HASH_BYTES = 64;

    bytes32 private constant IPAD =
        0x3636363636363636363636363636363636363636363636363636363636363636;
    bytes32 private constant OPAD =
        0x5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c;

    // -------------------------------------------------------------- HMAC

    /// HMAC-SHA-512 of `message` under `key`.
    ///
    /// Returned as the two halves of the digest rather than a `bytes` because
    /// every consumer here either feeds it straight back in as a key (HKDF's
    /// PRK) or compares it word-wise; materialising 64 bytes on the heap for
    /// that is pure overhead.
    function hmac(bytes memory key, bytes memory message)
        internal
        pure
        returns (bytes32 hi, bytes32 lo)
    {
        // K0: the key resized to exactly one block. Longer keys are hashed
        // first (RFC 2104 s2), shorter ones are right-padded with zeros. One
        // block is exactly four EVM words, which is why this is four values
        // and not a buffer.
        (bytes32 k0, bytes32 k1, bytes32 k2, bytes32 k3) = _blockKey(key);

        // inner = H((K0 ^ ipad) || message)
        bytes memory ibuf = new bytes(BLOCK_BYTES + message.length);
        _storeBlock(ibuf, k0 ^ IPAD, k1 ^ IPAD, k2 ^ IPAD, k3 ^ IPAD);
        _copyInto(ibuf, BLOCK_BYTES, message);
        (bytes32 ihi, bytes32 ilo) = Sha512.hash(ibuf);

        // outer = H((K0 ^ opad) || inner)
        bytes memory obuf = new bytes(BLOCK_BYTES + HASH_BYTES);
        _storeBlock(obuf, k0 ^ OPAD, k1 ^ OPAD, k2 ^ OPAD, k3 ^ OPAD);
        assembly {
            let p := add(obuf, 32)
            mstore(add(p, 128), ihi)
            mstore(add(p, 160), ilo)
        }
        return Sha512.hash(obuf);
    }

    // -------------------------------------------------------------- HKDF

    /// RFC 5869 s2.2. PRK = HMAC(key = salt, message = IKM).
    ///
    /// Note which argument is the key: the SALT is, not the input keying
    /// material. Swapping them yields a PRK that is stable, looks random, and
    /// is not the one MobileCoin computed.
    ///
    /// An empty `salt` is the RFC's "not provided" case and needs no special
    /// handling: the spec substitutes HashLen zero bytes, and HMAC pads both
    /// that and the empty string out to the same all-zero block. RFC 5869 test
    /// case 3 pins this.
    function extract(bytes memory salt, bytes memory ikm)
        internal
        pure
        returns (bytes32 prkHi, bytes32 prkLo)
    {
        return hmac(salt, ikm);
    }

    /// RFC 5869 s2.3. T(i) = HMAC(PRK, T(i-1) || info || i), T(0) = empty,
    /// OKM = the first `length` bytes of T(1) || T(2) || ...
    ///
    /// `info` is allowed to be empty -- the memo path uses exactly that -- and
    /// `length` is allowed to span several blocks; the 64-byte amount blinding
    /// factor does not, but RFC 5869's 82-byte vectors do, and a single-block
    /// implementation passes every MobileCoin call in this repo.
    function expand(
        bytes32 prkHi,
        bytes32 prkLo,
        bytes memory info,
        uint256 length
    ) internal pure returns (bytes memory okm) {
        uint256 max = 255 * HASH_BYTES;
        if (length > max) revert HkdfOutputTooLong(length, max);

        okm = new bytes(length);
        if (length == 0) return okm;

        bytes memory prk = new bytes(HASH_BYTES);
        assembly {
            mstore(add(prk, 32), prkHi)
            mstore(add(prk, 64), prkLo)
        }

        uint256 n = (length + HASH_BYTES - 1) / HASH_BYTES;
        bytes32 thi;
        bytes32 tlo;
        uint256 written = 0;

        unchecked {
            for (uint256 i = 1; i <= n; ++i) {
                // T(0) is the empty string, so the first message omits the
                // feedback entirely rather than prepending 64 zero bytes --
                // those are different messages and give different OKM.
                uint256 pre = i == 1 ? 0 : HASH_BYTES;
                bytes memory m = new bytes(pre + info.length + 1);
                if (pre != 0) {
                    assembly {
                        let p := add(m, 32)
                        mstore(p, thi)
                        mstore(add(p, 32), tlo)
                    }
                }
                _copyInto(m, pre, info);
                // The counter is one byte and starts at 1, not 0.
                m[pre + info.length] = bytes1(uint8(i));

                (thi, tlo) = hmac(prk, m);

                uint256 take = length - written;
                if (take > HASH_BYTES) take = HASH_BYTES;
                _appendTruncated(okm, written, thi, tlo, take);
                written += take;
            }
        }
    }

    /// Extract-then-expand in one call, for the single-output callers.
    function derive(
        bytes memory salt,
        bytes memory ikm,
        bytes memory info,
        uint256 length
    ) internal pure returns (bytes memory) {
        (bytes32 prkHi, bytes32 prkLo) = extract(salt, ikm);
        return expand(prkHi, prkLo, info, length);
    }

    // ---------------------------------------------------------- internal

    /// The key resized to one 128-byte block, as four big-endian words.
    function _blockKey(bytes memory key)
        private
        pure
        returns (bytes32 k0, bytes32 k1, bytes32 k2, bytes32 k3)
    {
        if (key.length > BLOCK_BYTES) {
            // RFC 2104 s2: an over-long key is replaced by its own digest,
            // which is 64 bytes and so occupies only the first two words. The
            // remaining two stay zero -- that is the zero padding, not a
            // truncation.
            (k0, k1) = Sha512.hash(key);
            return (k0, k1, bytes32(0), bytes32(0));
        }
        k0 = _keyWord(key, 0);
        k1 = _keyWord(key, 32);
        k2 = _keyWord(key, 64);
        k3 = _keyWord(key, 96);
    }

    /// Big-endian word `off` of `key`, zero-padded past the end.
    ///
    /// The masking is not cosmetic: `mload` past the end of a `bytes` reads
    /// the allocator's slack, which holds whatever the last allocation left
    /// there. Unmasked, the MAC would depend on unrelated memory and would not
    /// even be a function of its arguments.
    function _keyWord(bytes memory key, uint256 off)
        private
        pure
        returns (bytes32 w)
    {
        uint256 len = key.length;
        if (off >= len) return bytes32(0);
        assembly {
            w := mload(add(add(key, 32), off))
        }
        unchecked {
            uint256 avail = len - off;
            if (avail < 32) {
                w = w & ~(bytes32(type(uint256).max) >> (avail * 8));
            }
        }
    }

    function _storeBlock(
        bytes memory b,
        bytes32 w0,
        bytes32 w1,
        bytes32 w2,
        bytes32 w3
    ) private pure {
        assembly {
            let p := add(b, 32)
            mstore(p, w0)
            mstore(add(p, 32), w1)
            mstore(add(p, 64), w2)
            mstore(add(p, 96), w3)
        }
    }

    /// Copy all of `src` into `dst` starting at `dstOff`, which the callers
    /// keep a multiple of 32 so both sides stay word-aligned.
    ///
    /// Hand-rolled rather than `abi.encodePacked`: solc lowers a
    /// memory-to-memory copy to MCOPY, and the EVM this is tested on (and the
    /// one Sha512.sol was written for) is Shanghai, where that opcode does not
    /// exist.
    function _copyInto(bytes memory dst, uint256 dstOff, bytes memory src)
        private
        pure
    {
        uint256 n = src.length;
        uint256 full = n & ~uint256(31);
        uint256 rem = n - full;
        assembly {
            let s := add(src, 32)
            let d := add(add(dst, 32), dstOff)
            for { let i := 0 } lt(i, full) { i := add(i, 32) } {
                mstore(add(d, i), mload(add(s, i)))
            }
            // The final partial word is merged rather than stored whole, so
            // the copy cannot carry `src`'s allocation slack into `dst`.
            //
            // Honest note: no test here can fail if this merge is replaced by
            // a plain store, and that is a property of the two call sites, not
            // evidence that the merge is unnecessary. Both allocate `dst` so
            // that the surplus lands inside `dst`'s own rounded-up allocation
            // and past `dst.length`, where Sha512 (which pads from the length)
            // never looks. A third caller with a tighter buffer would not be
            // so lucky, so this stays.
            if rem {
                let mask := not(shr(shl(3, rem), not(0)))
                let p := add(d, full)
                mstore(
                    p,
                    or(and(mload(add(s, full)), mask), and(mload(p), not(mask)))
                )
            }
        }
    }

    /// Write the first `take` (1..64) bytes of `hi || lo` into `dst` at `off`.
    ///
    /// The truncation has to happen here rather than by copying 64 bytes and
    /// shortening afterwards: `dst` is allocated to the requested length, and
    /// a full 64-byte store on the last block would run past that allocation
    /// and corrupt whatever memory follows.
    function _appendTruncated(
        bytes memory dst,
        uint256 off,
        bytes32 hi,
        bytes32 lo,
        uint256 take
    ) private pure {
        unchecked {
            if (take >= 32) {
                assembly {
                    mstore(add(add(dst, 32), off), hi)
                }
                if (take > 32) _mergeWord(dst, off + 32, lo, take - 32);
            } else {
                _mergeWord(dst, off, hi, take);
            }
        }
    }

    /// Store the top `n` (1..32) bytes of `v` at `off`, leaving the rest of
    /// that word as it was.
    function _mergeWord(bytes memory dst, uint256 off, bytes32 v, uint256 n)
        private
        pure
    {
        assembly {
            let p := add(add(dst, 32), off)
            let mask := not(shr(shl(3, n), not(0)))
            mstore(p, or(and(v, mask), and(mload(p), not(mask))))
        }
    }
}

/// Test wrapper: a library of `internal` functions has no ABI of its own.
///
/// Nothing here returns a dynamic `bytes`. Encoding one into return data makes
/// solc emit MCOPY, which this repo's Shanghai test EVM rejects outright -- the
/// call fails with "invalid opcode" and looks like a bug in the library rather
/// than in the probe. The OKM comes back as fixed words instead, with the
/// caller slicing to `length`.
contract HkdfProbe {
    /// Up to 128 bytes of OKM as four words, zero-padded past `length`.
    uint256 private constant MAX_WORDS = 4;

    function hmac(bytes memory key, bytes memory message)
        external
        pure
        returns (bytes32 hi, bytes32 lo)
    {
        return Hkdf.hmac(key, message);
    }

    function extract(bytes memory salt, bytes memory ikm)
        external
        pure
        returns (bytes32 hi, bytes32 lo)
    {
        return Hkdf.extract(salt, ikm);
    }

    /// The same HMAC, but under a key whose allocation slack is deliberately
    /// non-zero.
    ///
    /// `_keyWord` reads the key a 32-byte word at a time and masks off the
    /// bytes past its length. Nothing in ordinary use proves that mask is
    /// there: both `new bytes` and solc's ABI decoder hand out zeroed slack,
    /// so an unmasked read picks up zeros and gives the right answer anyway.
    /// This paints the slack with 0xff first, which is what memory looks like
    /// once a contract has been running for a while, and makes the missing
    /// mask change the MAC.
    function hmacDirtyKey(bytes memory key, bytes memory message)
        external
        pure
        returns (bytes32 hi, bytes32 lo)
    {
        uint256 n = key.length;
        bytes memory k = new bytes(n);
        assembly {
            // Paint the whole rounded-up allocation; `new bytes` reserves a
            // multiple of 32, so this stays inside it.
            let words := div(add(n, 31), 32)
            for { let i := 0 } lt(i, words) { i := add(i, 1) } {
                mstore(add(add(k, 32), mul(i, 32)), not(0))
            }
        }
        // Byte-wise, so the 0xff behind the key survives the copy.
        for (uint256 i = 0; i < n; ++i) k[i] = key[i];
        return Hkdf.hmac(k, message);
    }

    function expandWords(
        bytes32 prkHi,
        bytes32 prkLo,
        bytes memory info,
        uint256 length
    ) external pure returns (bytes32[MAX_WORDS] memory out) {
        return _words(Hkdf.expand(prkHi, prkLo, info, length));
    }

    function deriveWords(
        bytes memory salt,
        bytes memory ikm,
        bytes memory info,
        uint256 length
    ) external pure returns (bytes32[MAX_WORDS] memory out) {
        return _words(Hkdf.derive(salt, ikm, info, length));
    }

    /// The OKM's length and keccak256, for lengths past the four-word window.
    ///
    /// keccak256 hashes exactly `okm.length` bytes in place, so this reaches
    /// any output size without ever ABI-encoding a dynamic `bytes` -- and the
    /// length is returned alongside because a digest of the wrong number of
    /// bytes is the failure this is most likely to be hiding.
    function expandDigest(
        bytes32 prkHi,
        bytes32 prkLo,
        bytes memory info,
        uint256 length
    ) external pure returns (uint256 len, bytes32 digest) {
        bytes memory okm = Hkdf.expand(prkHi, prkLo, info, length);
        return (okm.length, keccak256(okm));
    }

    /// Read the OKM back out word-wise, reading each word that the OKM's own
    /// allocation covers -- including the bytes past `length` in the final
    /// word, which `new bytes` left zero.
    ///
    /// Returning those bytes rather than masking them is deliberate. The
    /// obvious wrong `expand` stores each 64-byte block whole and only then
    /// truncates the result; that leaves the block's surplus bytes sitting in
    /// the tail, where a caller reading `okm.length` would never see them but
    /// this comparison does.
    function _words(bytes memory okm)
        private
        pure
        returns (bytes32[MAX_WORDS] memory out)
    {
        uint256 len = okm.length;
        require(len <= MAX_WORDS * 32, "okm too long for probe");
        for (uint256 i = 0; i < MAX_WORDS; ++i) {
            uint256 off = i * 32;
            if (off >= len) continue;
            bytes32 w;
            assembly {
                w := mload(add(add(okm, 32), off))
            }
            out[i] = w;
        }
    }
}
