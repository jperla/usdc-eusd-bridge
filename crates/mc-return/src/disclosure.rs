//! Turning a MobileCoin output into the five fields `VerifiedReturn` carries.
//!
//! A `TxOut` on the chain is opaque: the value is a Pedersen commitment, the
//! token id is masked, the payout address is inside an encrypted memo, and the
//! recipient is a one-time key that reveals nothing. All four come out with the
//! bridge return address's *view* private key `a` -- which the relayer holds
//! and which is not a spending capability -- via upstream's own recovery
//! functions. This module runs them and re-derives the commitment from what
//! came out, so a disclosure that does not actually match the chain cannot be
//! published.
//!
//! Ethereum independently recovers these fields using the deliberately public
//! return-address view key. The separate release reserve keeps its view key
//! private. The v2 memo binds the beneficiary to a particular redemption
//! domain computed by the target verifier from chain, escrow and namespace.

use mc_crypto_keys::{RistrettoPrivate, RistrettoPublic};
use mc_transaction_core::{
    encrypted_fog_hint::EncryptedFogHint,
    get_tx_out_shared_secret,
    onetime_keys::recover_public_subaddress_spend_key,
    ring_signature::{generators, CompressedCommitment, Scalar},
    tx::TxOut,
    Amount, BlockVersion, MemoPayload, PublicAddress,
};

use crate::error::{Error, Result};

/// Memo type for "this eUSD is going back over the bridge; pay the USDC to
/// this Ethereum address".
///
/// MobileCoin's registered memo types (mcips/pull/3 and the `transaction/extra`
/// crate) occupy 0x00xx through 0x02xx; 0x80xx is unallocated. A collision with
/// some future registration would misrender the memo in a wallet, but it is not
/// a bridge security boundary: the escrow pays out only for an output that the
/// bridge's own view key opens, and only the party who *created* that output
/// could have written its memo. In other words the memo is self-addressed --
/// the person choosing the payout address is the person being paid.
pub const BRIDGE_RETURN_MEMO_TYPE: [u8; 2] = [0x80, 0x02];

/// Versioned, canonical return memo. Obtain `redemption_domain` from the
/// target verifier's `redemptionDomain(escrow)` on the intended chain BEFORE
/// creating the output. Legacy v1 memos cannot be safely upgraded by relayers.
/// Data = beneficiary20 || domain32 || reserved12 (all zero).
pub fn bridge_return_memo(
    beneficiary: [u8; 20],
    redemption_domain: [u8; 32],
) -> Result<MemoPayload> {
    if beneficiary == [0; 20] {
        return Err(Error::ZeroBeneficiary);
    }
    let mut data = [0u8; 64];
    data[..20].copy_from_slice(&beneficiary);
    data[20..52].copy_from_slice(&redemption_domain);
    Ok(MemoPayload::new(BRIDGE_RETURN_MEMO_TYPE, data))
}

/// Construct and encrypt a deployment-bound return using MobileCoin's own
/// TxOut API. This is an output builder, not a transaction submission or proof
/// that it has been included in a ledger.
pub fn create_return_tx_out(
    amount: Amount,
    recipient: &PublicAddress,
    tx_private_key: &RistrettoPrivate,
    fog_hint: EncryptedFogHint,
    beneficiary: [u8; 20],
    redemption_domain: [u8; 32],
) -> Result<TxOut> {
    let memo = bridge_return_memo(beneficiary, redemption_domain)?;
    TxOut::new_with_memo(
        BlockVersion::MAX,
        amount,
        recipient,
        tx_private_key,
        fog_hint,
        |_ctx| Ok(memo),
    )
    .map_err(|e| Error::ReturnOutputConstruction(format!("{e}")))
}

/// The plaintext behind a return output.
#[derive(Clone, Debug)]
pub struct Disclosure {
    /// The bridge return address's view private key `a`.
    ///
    /// Published on purpose. `R`'s view key is public precisely so an Ethereum
    /// contract can recompute `Hs(a*R)` and check an output was paid to us --
    /// which is exactly why the release reserve `F` is a SEPARATE address whose
    /// view key stays private. Holding `a` lets anyone recognise R's outputs
    /// and read their amounts; it does not let them spend, which needs the
    /// subaddress spend private key.
    pub view_private_key: RistrettoPrivate,
    /// `s = a * R`, the TxOut shared secret. Everything else is derived from it.
    pub shared_secret: RistrettoPublic,
    pub amount: Amount,
    /// The Pedersen blinding recovered alongside the value. Published so the
    /// commitment can be re-opened by anyone, not just by us.
    pub blinding: Scalar,
    /// `B_i = P - Hs(a*R)*G`: the subaddress spend public key this output was
    /// actually paid to. Compared against the bridge's published `R` by
    /// [`Disclosure::require_paid_to`].
    pub recovered_subaddress_spend_key: RistrettoPublic,
    pub memo_type: [u8; 2],
    pub memo_data: [u8; 64],
    /// First 20 bytes of the memo data.
    pub beneficiary: [u8; 20],
    /// Bytes 20..52 of the memo data, authenticated by the output digest.
    pub redemption_domain: [u8; 32],
}

impl Disclosure {
    /// Open `tx_out` with the bridge's view private key.
    pub fn open(tx_out: &TxOut, view_private_key: &RistrettoPrivate) -> Result<Self> {
        let public_key = RistrettoPublic::try_from(&tx_out.public_key)
            .map_err(|e| Error::AmountNotRecoverable(format!("{e}")))?;
        let shared_secret = get_tx_out_shared_secret(view_private_key, &public_key);

        let masked_amount = tx_out
            .get_masked_amount()
            .map_err(|e| Error::AmountNotRecoverable(format!("{e}")))?;
        // Upstream's unmasking. For MaskedAmountV2 this already rejects a
        // shared secret that does not reproduce the commitment, so a failure
        // here is also "this output is not ours".
        let (amount, blinding) = masked_amount
            .get_value(&shared_secret)
            .map_err(|e| Error::AmountNotRecoverable(format!("{e}")))?;

        // Re-derive the commitment from the exact numbers that will be
        // published. For MaskedAmountV2 this duplicates a check `get_value`
        // already made and will never fire; it is here for the versions that
        // do not make it -- MaskedAmountV1's `get_value` does not compare
        // commitments -- and for any future variant that forgets to.
        let expected =
            CompressedCommitment::new(amount.value, blinding, &generators(*amount.token_id));
        if &expected != masked_amount.commitment() {
            return Err(Error::CommitmentMismatch);
        }

        let target_key = RistrettoPublic::try_from(&tx_out.target_key)
            .map_err(|e| Error::AmountNotRecoverable(format!("{e}")))?;
        let recovered_subaddress_spend_key =
            recover_public_subaddress_spend_key(view_private_key, &target_key, &public_key);

        let memo = tx_out.decrypt_memo(&shared_secret);
        let memo_type = *memo.get_memo_type();
        let memo_data = *memo.get_memo_data();
        if memo_type != BRIDGE_RETURN_MEMO_TYPE {
            return Err(Error::MemoWrongType {
                got: memo_type,
                want: BRIDGE_RETURN_MEMO_TYPE,
            });
        }
        let mut beneficiary = [0u8; 20];
        beneficiary.copy_from_slice(&memo_data[..20]);
        if memo_data[52..].iter().any(|b| *b != 0) {
            return Err(Error::NonzeroMemoReserved);
        }
        if beneficiary == [0; 20] {
            return Err(Error::ZeroBeneficiary);
        }
        let mut redemption_domain = [0u8; 32];
        redemption_domain.copy_from_slice(&memo_data[20..52]);

        Ok(Self {
            view_private_key: *view_private_key,
            shared_secret,
            amount,
            blinding,
            recovered_subaddress_spend_key,
            memo_type,
            memo_data,
            beneficiary,
            redemption_domain,
        })
    }

    /// The output must have been paid to the bridge's return address, not
    /// merely be openable by a key we hold.
    ///
    /// `get_value` succeeding already means the output was constructed for this
    /// view key. This is the stronger statement: it also pins the *spend* key,
    /// so an output paid to a different subaddress of the same view key -- a
    /// change output, say -- is not accepted as a return.
    pub fn require_paid_to(&self, return_subaddress_spend_public: &RistrettoPublic) -> Result<()> {
        if &self.recovered_subaddress_spend_key != return_subaddress_spend_public {
            return Err(Error::NotPaidToReturnAddress);
        }
        Ok(())
    }

    /// A relayer cannot retarget a signed output to another escrow or chain.
    pub fn require_domain(&self, expected: &[u8; 32]) -> Result<()> {
        if &self.redemption_domain != expected {
            return Err(Error::MemoWrongDomain {
                got: self.redemption_domain,
                want: *expected,
            });
        }
        Ok(())
    }
}
