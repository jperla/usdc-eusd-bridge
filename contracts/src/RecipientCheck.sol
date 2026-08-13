// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {IRecipientCheck} from "./IMobileCoinVerifier.sol";
import {Ristretto255} from "./Ristretto255.sol";
import {Blake2b} from "./Blake2b256.sol";

/// Is this MobileCoin output payable to the bridge's return address?
///
/// MobileCoin pays a subaddress (C, D) with a one-time key. The sender draws a
/// private r, publishes R = r*D as the output's `tx_public_key`, and sets
///
///     target_key = Hs(r*C)*G + D
///
/// The recipient holds the view private key `a` with C = a*D, so it can
/// recompute the same shared secret from its own side -- a*R = a*r*D = r*C --
/// and recover
///
///     target_key - Hs(a*R)*G == D
///
/// which holds exactly when the output was addressed to (C, D). That is
/// `recover_public_subaddress_spend_key` from mobilecoin's
/// crypto/ring-signature/src/onetime_keys.rs, evaluated on chain.
///
/// WHY THE VIEW KEY IS PUBLIC. `a` is the only secret the check needs and it
/// is a constructor argument in the clear. A view private key confers the
/// ability to RECOGNIZE payments to an address, never to spend them: spending
/// needs the subaddress spend private key, which never touches Ethereum. Every
/// payment to the bridge's return address is meant to be recognizable by
/// anyone -- that is what makes the return leg permissionless -- so publishing
/// `a` gives away nothing that the design did not already give away. What `a`
/// must not be is WRONG, so it is validated as a canonical scalar at
/// construction and exposed as an immutable that any deployment transaction,
/// and any later reader, can check against the published return address.
///
/// Deploying this contract is what closes the recipient link of the return
/// leg; a `MobileCoinVerifier` constructed with any other implementation has
/// not closed it.
contract RecipientCheck is IRecipientCheck {
    /// The bridge return address's view private key `a`, in MobileCoin's
    /// little-endian wire form -- the form an operator can diff against the
    /// published account key.
    bytes32 public immutable viewPrivateKey;

    /// The same key parsed into a scalar. Two immutables rather than a parse
    /// per call; neither costs storage.
    uint256 private immutable _a;

    /// Not a canonical `Scalar` encoding: >= L, or zero. Zero would make the
    /// shared secret Hs(0) for every output, so every output in MobileCoin
    /// would appear payable to whichever spend key matched that one constant.
    error InvalidViewPrivateKey(bytes32 key);

    constructor(bytes32 viewPrivateKeyLE) {
        (bool ok, uint256 a) = Ristretto255.scalarFromLE(viewPrivateKeyLE);
        if (!ok || a == 0) revert InvalidViewPrivateKey(viewPrivateKeyLE);
        viewPrivateKey = viewPrivateKeyLE;
        _a = a;
    }

    /// True iff `txOutTargetKey - Hs(a * txOutPublicKey)*G == returnSpendPublicKey`.
    ///
    /// Returns false, rather than reverting, on any input that is not a valid
    /// ristretto255 encoding: the question asked is about attacker-supplied
    /// bytes, and "these do not describe an output payable to the bridge" is
    /// the answer for a malformed key as much as for a mismatched one.
    function isPayableToBridge(
        bytes32 txOutPublicKey,
        bytes32 txOutTargetKey,
        bytes32 returnSpendPublicKey
    ) external view returns (bool) {
        // D = identity would make the relation solvable by anyone: `a` is
        // public, so an attacker could pick any R, compute h = Hs(a*R) and
        // publish an output with target_key = h*G. Refusing it here means a
        // verifier misconfigured with a zero spend key redeems nothing rather
        // than everything.
        if (returnSpendPublicKey == bytes32(0)) return false;

        (bool okR, Ristretto255.Point memory r) =
            Ristretto255.decode(txOutPublicKey);
        if (!okR) return false;
        (bool okTarget, Ristretto255.Point memory target) =
            Ristretto255.decode(txOutTargetKey);
        if (!okTarget) return false;

        uint256 h = hashToScalarUint(
            Ristretto255.encode(Ristretto255.scalarMul(_a, r))
        );
        Ristretto255.Point memory recovered = Ristretto255.sub(
            target,
            Ristretto255.scalarMul(h, Ristretto255.basepoint())
        );

        // The ristretto encoding is canonical, so comparing 32 bytes IS point
        // equality -- and it costs nothing extra to also refuse a
        // `returnSpendPublicKey` that is not a valid encoding at all, since no
        // encode output can equal one.
        return Ristretto255.encode(recovered) == returnSpendPublicKey;
    }

    /// MobileCoin's `hash_to_scalar`: Blake2b-512 over the domain tag and the
    /// COMPRESSED point, reduced wide mod L.
    ///
    /// Exposed so the hash can be cross-checked against MobileCoin's own
    /// vectors independently of the curve arithmetic. Returns the scalar in
    /// little-endian wire form, as MobileCoin encodes scalars.
    function hashToScalar(bytes32 compressedPoint)
        external
        view
        returns (bytes32)
    {
        uint256 s = hashToScalarUint(compressedPoint);
        uint256 le;
        unchecked {
            for (uint256 i = 0; i < 32; ++i) {
                le = (le << 8) | (s & 0xff);
                s >>= 8;
            }
        }
        return bytes32(le);
    }

    // -------------------------------------------------------------- internal

    function hashToScalarUint(bytes32 compressedPoint)
        private
        view
        returns (uint256)
    {
        // The tag is spelled out inline rather than held in a `bytes constant`
        // on purpose: solc lays a constant out in memory and copies it, which
        // on a Cancun target is an MCOPY, and MCOPY is an invalid opcode on
        // the Shanghai chains this is meant to run on. A literal is written
        // with plain MSTOREs.
        uint64[8] memory d = Blake2b.hashWords(
            abi.encodePacked("mc_onetime_key_hash_to_scalar", compressedPoint),
            64
        );
        // The digest read as a little-endian 512-bit integer: word i carries
        // bytes 8i..8i+7, so word i is the coefficient of 2^(64i).
        uint256 lo = (uint256(d[3]) << 192) | (uint256(d[2]) << 128)
            | (uint256(d[1]) << 64) | uint256(d[0]);
        uint256 hi = (uint256(d[7]) << 192) | (uint256(d[6]) << 128)
            | (uint256(d[5]) << 64) | uint256(d[4]);
        return Ristretto255.scalarFromWide(lo, hi);
    }
}
