//! Secret key type.

use crate::{errors::InvalidLength, PublicKey};
use curve25519_dalek::MontgomeryPoint;
use rand_core::CryptoRngCore;

#[cfg(feature = "serde")]
use serdect::serde::{de, ser, Deserialize, Serialize};

/// [`SecretKey`] that should be kept private.
#[derive(Clone)]
pub struct SecretKey(pub(crate) [u8; Self::BYTES]);

impl SecretKey {
    /// Size in bytes of the [`SecretKey`].
    pub const BYTES: usize = 32;

    /// Generate a new random [`SecretKey`].
    pub fn generate(csprng: &mut impl CryptoRngCore) -> Self {
        let mut bytes = [0u8; Self::BYTES];
        csprng.fill_bytes(&mut bytes);
        bytes.into()
    }

    /// Get the public key that corresponds to this [`SecretKey`].
    pub fn public_key(&self) -> PublicKey {
        PublicKey(MontgomeryPoint::mul_base_clamped(self.0))
    }

    /// Get the bytes serialization of this [`SecretKey`].
    pub fn to_bytes(&self) -> [u8; SecretKey::BYTES] {
        self.0
    }
}

impl From<[u8; SecretKey::BYTES]> for SecretKey {
    fn from(value: [u8; SecretKey::BYTES]) -> Self {
        Self(value)
    }
}

impl TryFrom<&[u8]> for SecretKey {
    type Error = InvalidLength;

    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        slice
            .try_into()
            .map(Self)
            .map_err(|_| InvalidLength::new(Self::BYTES, slice.len()))
    }
}

#[cfg(feature = "serde")]
impl Serialize for SecretKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        serdect::array::serialize_hex_upper_or_bin(&self.0, serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for SecretKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let mut bytes = [0u8; Self::BYTES];
        serdect::array::deserialize_hex_or_bin(&mut bytes, deserializer)?;
        Ok(Self(bytes))
    }
}
