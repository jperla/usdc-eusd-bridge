//! Value and identifier newtypes.

use core::fmt;
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A quantity of value in USDC base units (6 decimals), the denomination the
/// whole risk model uses.
///
/// eUSD amounts are `u64` base units on MobileCoin and USDC is `uint256` on
/// Ethereum; both are normalised to this type at ingest via the escrow's
/// conversion ratio, so nothing downstream has to remember which side a number
/// came from. `u128` is the width: `uint256` cannot be represented, but a
/// balance beyond `u128` is 10^26 USDC and the arithmetic below saturates
/// rather than wraps, so an out-of-range feed produces a larger bound and a
/// freeze, never a smaller bound and a pass.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Amount(u128);

impl Amount {
    /// Zero value.
    pub const ZERO: Amount = Amount(0);

    /// The saturation point. Reaching it means an input was out of range; the
    /// bound is still sound because saturation is upward.
    pub const MAX: Amount = Amount(u128::MAX);

    /// Wrap a raw count of USDC base units.
    pub const fn from_base_units(v: u128) -> Self {
        Amount(v)
    }

    /// The raw count of USDC base units.
    pub const fn base_units(self) -> u128 {
        self.0
    }

    /// Addition that saturates. An exposure figure that wrapped to a small
    /// number would read as "safe" -- the one failure mode this type must not
    /// have.
    pub const fn saturating_add(self, rhs: Amount) -> Amount {
        Amount(self.0.saturating_add(rhs.0))
    }

    /// Subtraction that saturates at zero.
    pub const fn saturating_sub(self, rhs: Amount) -> Amount {
        Amount(self.0.saturating_sub(rhs.0))
    }

    /// `true` if this is zero.
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }
}

impl fmt::Debug for Amount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Amount({})", self.0)
    }
}

impl fmt::Display for Amount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// Amounts cross process boundaries as JSON. JSON numbers are IEEE doubles in
// most consumers, which silently rounds anything past 2^53 -- for USDC base
// units that is about 9 billion USDC, well inside the range a bridge float can
// reach. Serialising as a decimal string makes the truncation impossible
// instead of merely unlikely.
impl Serialize for Amount {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for Amount {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl Visitor<'_> for V {
            type Value = Amount;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a decimal string of USDC base units")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Amount, E> {
                v.parse::<u128>().map(Amount).map_err(E::custom)
            }
        }
        d.deserialize_str(V)
    }
}

/// A 32-byte opaque identifier: a MobileCoin destination hash, a MobileCoin
/// output public key, an Ethereum transaction hash.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Bytes32(pub [u8; 32]);

/// A 20-byte Ethereum address.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct EthAddress(pub [u8; 20]);

macro_rules! hex_newtype {
    ($t:ty, $n:expr) => {
        impl fmt::Debug for $t {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "0x{}", hex::encode(self.0))
            }
        }
        impl fmt::Display for $t {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "0x{}", hex::encode(self.0))
            }
        }
        impl Serialize for $t {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(&format!("0x{}", hex::encode(self.0)))
            }
        }
        impl<'de> Deserialize<'de> for $t {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let s = String::deserialize(d)?;
                let body = s.strip_prefix("0x").unwrap_or(&s);
                let raw = hex::decode(body).map_err(de::Error::custom)?;
                if raw.len() != $n {
                    return Err(de::Error::custom(format!(
                        "expected {} bytes, got {}",
                        $n,
                        raw.len()
                    )));
                }
                let mut out = [0u8; $n];
                out.copy_from_slice(&raw);
                Ok(Self(out))
            }
        }
    };
}

hex_newtype!(Bytes32, 32);
hex_newtype!(EthAddress, 20);
