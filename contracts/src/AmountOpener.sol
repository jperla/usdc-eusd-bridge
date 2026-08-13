// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Ristretto255} from "./Ristretto255.sol";
import {Blake2b} from "./Blake2b256.sol";
import {Hkdf} from "./Hkdf.sol";
import {Aes256} from "./Aes256.sol";
import {LE} from "./LE.sol";

/// Opening a MobileCoin `TxOut`'s ENCRYPTED fields on Ethereum.
///
/// The TxOut digest -- the thing a membership proof binds -- covers only the
/// masked amount (a Pedersen commitment plus a masked value and masked token
/// id) and the encrypted memo. Until those are opened, the value, the token id
/// and the payee are whatever the party submitting the proof says they are,
/// and that is the whole payout. This file turns them into DERIVED values.
///
/// Everything here is keyed on one input: `S`, the compressed TxOut shared
/// secret `[a]R`. `RecipientCheck` already computes `[a]R` to answer whether
/// the output was paid to the bridge, so it returns `S` alongside its yes/no
/// and nothing in this file repeats that scalar multiplication.
///
/// `S` is NOT re-derived here and is not taken on faith either: the commitment
/// check below is what makes a wrong `S` fatal. A shared secret that does not
/// belong to this output yields masks that unmask to a value and blinding
/// whose commitment is not the output's, and `requireCommitment` reverts.
///
/// Read alongside, and pinned against, MobileCoin's own source:
///   * `transaction/types/src/masked_amount/v2.rs` (amount)
///   * `transaction/core/src/memo.rs:159-179` (memo)
///   * `crypto/ring-signature/src/ring_signature/mod.rs:85` (generators)
library AmountOpener {
    /// `MaskedAmountV2` requires exactly 8 bytes. Zero bytes is a V1 amount,
    /// not a V2 one with a default; upstream's `compute_commitment` returns
    /// `InvalidMaskedTokenId` for every other length and so does this.
    error InvalidMaskedTokenId(uint256 length);

    /// The value and blinding that came out of the masks do not reproduce the
    /// commitment the block committed to.
    ///
    /// THIS IS THE CHECK THAT MATTERS. Removing the masks is not evidence of
    /// anything on its own -- XOR is invertible, so any masked value "opens"
    /// to some number under any shared secret. Only the commitment ties that
    /// number to the output the Merkle path proved. Upstream makes the same
    /// comparison at v2.rs:150.
    error InconsistentCommitment(bytes32 recomputed, bytes32 onChain);

    /// `B_token` is not a valid ristretto255 encoding, or is the identity.
    ///
    /// The identity is refused separately from a bad encoding because it is
    /// the one *valid* point that breaks the commitment: with `B_token = 0`
    /// the commitment is `blinding*G` for every value, so the value stops
    /// being committed to at all and any amount verifies.
    error InvalidValueGenerator(bytes32 encoded);

    /// `MaskedAmountV2::masked_token_id`, in bytes. See the error above.
    uint256 internal constant TOKEN_ID_BYTES = 8;

    // ------------------------------------------------------ the amount secret

    /// `Blake2b512("mc_amount_shared_secret" || S)[0..32]`.
    ///
    /// A second secret derived from the first, so that the amount can be
    /// disclosed to a third party without disclosing the memo (MCIP #42). The
    /// domain tag is spelled out as a literal rather than held in a
    /// `bytes constant`: solc lays a constant out in memory and copies it,
    /// which on a Cancun target is an MCOPY, and MCOPY is an invalid opcode on
    /// the Shanghai chains this is meant to run on.
    function amountSharedSecret(bytes32 s)
        internal
        view
        returns (bytes memory ass)
    {
        uint64[8] memory d =
            Blake2b.hashWords(abi.encodePacked("mc_amount_shared_secret", s), 64);
        // The digest's first 32 BYTES, which are its first four words written
        // back out little-endian -- not the first four words as numbers.
        ass = new bytes(32);
        uint256 o = 0;
        for (uint256 i = 0; i < 4; ++i) o = LE.put64(ass, o, d[i]);
    }

    /// The three blinding factors, from one HKDF extraction and three expands.
    ///
    /// Extract once: the PRK depends only on the salt and the amount shared
    /// secret, and one HMAC-SHA-512 is the single most expensive primitive in
    /// this path. Re-extracting per `info` would triple it for no change in
    /// output.
    ///
    /// The blinding is `Scalar::from_bytes_mod_order_wide` over the full 64
    /// bytes -- a wide reduction, not a 32-byte truncation. Truncating gives a
    /// scalar that is well-formed, deterministic and wrong.
    function blindingFactors(bytes memory ass)
        internal
        pure
        returns (uint64 valueMask, uint64 tokenIdMask, uint256 blinding)
    {
        (bytes32 prkHi, bytes32 prkLo) =
            Hkdf.extract(abi.encodePacked("mc_amount_blinding_factors"), ass);

        valueMask = LE.get64(
            Hkdf.expand(prkHi, prkLo, abi.encodePacked("mc_amount_value"), 8), 0
        );
        tokenIdMask = LE.get64(
            Hkdf.expand(prkHi, prkLo, abi.encodePacked("mc_amount_token_id"), 8),
            0
        );
        bytes memory wide =
            Hkdf.expand(prkHi, prkLo, abi.encodePacked("mc_amount_blinding"), 64);
        blinding =
            Ristretto255.scalarFromWide(_le256(wide, 0), _le256(wide, 32));
    }

    // -------------------------------------------------------------- unmasking

    /// The value, token id and blinding behind a `MaskedAmountV2`.
    ///
    /// Nothing is verified here beyond the token id's byte length -- see
    /// `requireCommitment`, which is the step that makes these numbers mean
    /// anything. They are returned together because the blinding is only ever
    /// wanted for that check.
    function unmask(
        bytes32 sharedSecret,
        uint64 maskedValue,
        bytes memory maskedTokenId
    )
        internal
        view
        returns (uint64 value, uint64 tokenId, uint256 blinding)
    {
        if (maskedTokenId.length != TOKEN_ID_BYTES) {
            revert InvalidMaskedTokenId(maskedTokenId.length);
        }
        uint64 valueMask;
        uint64 tokenIdMask;
        (valueMask, tokenIdMask, blinding) =
            blindingFactors(amountSharedSecret(sharedSecret));

        value = maskedValue ^ valueMask;
        tokenId = LE.get64(maskedTokenId, 0) ^ tokenIdMask;
    }

    // ------------------------------------------------------------ the generator

    /// `B_token`, decoded, having refused the two encodings that would make the
    /// commitment check vacuous.
    ///
    /// WHY THIS IS A PARAMETER AND NOT COMPUTED. MobileCoin builds `B_token` by
    /// hashing to the curve -- `RistrettoPoint::from_hash(Blake2b512(tag ||
    /// basepoint-XOR-token-id))`, which is an Elligator map over a 512-bit
    /// digest. Implementing hash-to-curve on chain would be several hundred
    /// lines of untested arithmetic to produce ONE point, because this contract
    /// accepts exactly one token id. So the point is pinned at construction and
    /// the derived token id is required to equal that id. `test/verifier.mjs`
    /// asserts the pinned value is what MobileCoin's own `generators(token_id)`
    /// produces; without that assertion the constant would be unfounded.
    function decodeGenerator(bytes32 encoded)
        internal
        view
        returns (Ristretto255.Point memory p)
    {
        // The identity's encoding, refused before decoding because `decode`
        // accepts it -- it is a perfectly valid point, just a fatal generator.
        if (encoded == bytes32(0)) revert InvalidValueGenerator(encoded);
        bool ok;
        (ok, p) = Ristretto255.decode(encoded);
        if (!ok) revert InvalidValueGenerator(encoded);
    }

    /// Require `commitment == value*B_token + blinding*B_blinding`.
    ///
    /// `B_blinding` is the ristretto255 basepoint -- MobileCoin's `B_BLINDING`
    /// is `RISTRETTO_BASEPOINT_POINT`, so commitments to zero are signed on G
    /// (`ring_signature/mod.rs`). It is therefore not a deployment parameter:
    /// there is nothing to get wrong and nothing to configure.
    ///
    /// The comparison is on the COMPRESSED encodings. Ristretto's encoding is
    /// canonical, so that is exact point equality, and it also disposes of a
    /// `commitment` that is not a valid encoding at all: `encode` never
    /// produces one.
    function requireCommitment(
        bytes32 commitment,
        uint64 value,
        uint256 blinding,
        bytes32 valueGenerator
    ) internal view {
        Ristretto255.Point memory bToken = decodeGenerator(valueGenerator);

        bytes32 recomputed = Ristretto255.encode(
            Ristretto255.add(
                Ristretto255.scalarMul(uint256(value), bToken),
                Ristretto255.scalarMul(blinding, Ristretto255.basepoint())
            )
        );
        if (recomputed != commitment) {
            revert InconsistentCommitment(recomputed, commitment);
        }
    }

    // ---------------------------------------------------------------- internal

    /// 32 little-endian bytes of `b` at `off`, as a number.
    function _le256(bytes memory b, uint256 off)
        private
        pure
        returns (uint256 v)
    {
        unchecked {
            for (uint256 i = 32; i > 0; --i) {
                v = (v << 8) | uint256(uint8(b[off + i - 1]));
            }
        }
    }
}

/// Opening a TxOut's encrypted memo.
///
/// Same shared secret, different KDF: the memo's key and nonce come from
/// `HKDF-SHA512(salt = "mc-memo-okm", ikm = S).expand("", 48)` and the payload
/// is AES-256 in COUNTER mode over the 66-byte `e_memo`. Kept in this file
/// rather than in `MobileCoinVerifier` because it is the same kind of thing --
/// a wire format read out of MobileCoin's source -- and kept in a library of
/// its own because it shares nothing with the amount but `S`.
///
/// This lives beside `AmountOpener` and not inside it because the two are
/// versioned independently upstream: the amount format is `MaskedAmountV2` and
/// would change with a V3; the memo framing has not changed since memos were
/// introduced.
library MemoOpener {
    /// `MemoPayload` is a fixed 66 bytes: 2 of memo type, 64 of data. A TxOut
    /// with no memo at all carries an empty `e_memo`, which is not a memo that
    /// names anybody and must not be read as one.
    error InvalidMemoLength(uint256 length);

    uint256 internal constant MEMO_BYTES = 66;

    /// The AES key and nonce for a TxOut's memo.
    ///
    /// One 48-byte expansion split 32/16, with an EMPTY `info` -- that is the
    /// RFC 5869 "no context" case, not a missing argument.
    function okm(bytes32 s)
        internal
        pure
        returns (bytes32 aesKey, bytes16 aesNonce)
    {
        bytes memory out =
            Hkdf.derive(abi.encodePacked("mc-memo-okm"), abi.encodePacked(s), "", 48);
        assembly {
            aesKey := mload(add(out, 32))
            // Bytes 32..48 of the OKM, left-aligned into a bytes16. The shift
            // pair clears the low half explicitly rather than trusting the
            // allocation's slack to be zero.
            aesNonce := shl(128, shr(128, mload(add(out, 64))))
        }
    }

    /// The memo type and the Ethereum beneficiary it names.
    ///
    /// This repo's schema (`crates/mc-return/src/disclosure.rs`) puts the
    /// beneficiary in the first 20 bytes of the memo DATA, which is bytes 2..22
    /// of the payload. The caller checks the type; returning it rather than
    /// checking it here keeps the policy -- which memo type this bridge honours
    /// -- in the contract that has the rest of the policy.
    ///
    /// The whole payload is decrypted, not just the 22 bytes read. CTR is a
    /// stream cipher so the remaining 44 bytes are three more AES blocks of
    /// keystream (~85k gas out of a multi-million-gas call); computing the same
    /// plaintext MobileCoin does keeps this comparable to upstream by
    /// inspection rather than by argument.
    function open(bytes32 s, bytes memory eMemo)
        internal
        pure
        returns (bytes2 memoType, address beneficiary)
    {
        if (eMemo.length != MEMO_BYTES) revert InvalidMemoLength(eMemo.length);

        (bytes32 aesKey, bytes16 aesNonce) = okm(s);
        bytes memory pt = Aes256.ctr(aesKey, aesNonce, eMemo);

        // Read byte by byte. Slicing a `bytes memory` compiles to a
        // memory-to-memory copy, which solc emits as MCOPY on a Cancun target
        // and which is an invalid opcode on Shanghai.
        memoType = bytes2(
            uint16((uint16(uint8(pt[0])) << 8) | uint16(uint8(pt[1])))
        );
        uint160 a;
        unchecked {
            for (uint256 i = 0; i < 20; ++i) {
                a = (a << 8) | uint160(uint8(pt[2 + i]));
            }
        }
        beneficiary = address(a);
    }
}

/// Test wrapper. Both libraries are `internal`, so nothing above has an ABI of
/// its own and no test could reach a single step in isolation.
///
/// Every function returns fixed-width words. A probe that returns `bytes` dies
/// with "invalid opcode" on the Shanghai EVM the suite runs, because solc
/// 0.8.26 ABI-encodes a returned dynamic array with MCOPY -- which looks like a
/// library bug and is not one.
contract AmountOpenerProbe {
    function amountSharedSecret(bytes32 s) external view returns (bytes32) {
        return bytes32(AmountOpener.amountSharedSecret(s));
    }

    function blindingFactors(bytes32 s)
        external
        view
        returns (uint64 valueMask, uint64 tokenIdMask, bytes32 blindingLE)
    {
        uint256 blinding;
        (valueMask, tokenIdMask, blinding) =
            AmountOpener.blindingFactors(AmountOpener.amountSharedSecret(s));
        blindingLE = _le(blinding);
    }

    function unmask(
        bytes32 s,
        uint64 maskedValue,
        bytes calldata maskedTokenId
    )
        external
        view
        returns (uint64 value, uint64 tokenId, bytes32 blindingLE)
    {
        uint256 blinding;
        (value, tokenId, blinding) =
            AmountOpener.unmask(s, maskedValue, maskedTokenId);
        blindingLE = _le(blinding);
    }

    /// The commitment the opened numbers imply, without the equality check --
    /// so a test can print both sides of a mismatch instead of only the fact
    /// of one.
    function commitmentOf(uint64 value, bytes32 blindingLE, bytes32 valueGenerator)
        external
        view
        returns (bytes32)
    {
        (bool ok, uint256 blinding) = Ristretto255.scalarFromLE(blindingLE);
        require(ok, "blinding not canonical");
        Ristretto255.Point memory bToken =
            AmountOpener.decodeGenerator(valueGenerator);
        return Ristretto255.encode(
            Ristretto255.add(
                Ristretto255.scalarMul(uint256(value), bToken),
                Ristretto255.scalarMul(blinding, Ristretto255.basepoint())
            )
        );
    }

    /// The whole amount path, as `MobileCoinVerifier` runs it.
    function openAmount(
        bytes32 s,
        bytes32 commitment,
        uint64 maskedValue,
        bytes calldata maskedTokenId,
        bytes32 valueGenerator
    ) external view returns (uint64 value, uint64 tokenId) {
        uint256 blinding;
        (value, tokenId, blinding) =
            AmountOpener.unmask(s, maskedValue, maskedTokenId);
        AmountOpener.requireCommitment(
            commitment, value, blinding, valueGenerator
        );
    }

    function bBlinding() external view returns (bytes32) {
        return Ristretto255.encode(Ristretto255.basepoint());
    }

    function decodeGenerator(bytes32 encoded) external view returns (bytes32) {
        return Ristretto255.encode(AmountOpener.decodeGenerator(encoded));
    }

    function memoOkm(bytes32 s)
        external
        pure
        returns (bytes32 aesKey, bytes16 aesNonce)
    {
        return MemoOpener.okm(s);
    }

    function openMemo(bytes32 s, bytes calldata eMemo)
        external
        pure
        returns (bytes2 memoType, address beneficiary)
    {
        return MemoOpener.open(s, eMemo);
    }

    /// A scalar in MobileCoin's little-endian wire form, which is how every
    /// fixture in this repo publishes one.
    function _le(uint256 v) private pure returns (bytes32) {
        uint256 r;
        unchecked {
            for (uint256 i = 0; i < 32; ++i) {
                r = (r << 8) | (v & 0xff);
                v >>= 8;
            }
        }
        return bytes32(r);
    }
}
