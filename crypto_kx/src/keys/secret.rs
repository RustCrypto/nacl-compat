//! Secret key type.

use crate::errors::InvalidLength;
use rand_core::{CryptoRng, RngCore};

#[cfg(feature = "serde")]
use serdect::serde::{de, ser, Deserialize, Serialize};

/// [`SecretKey`] that should be kept private.
#[derive(Clone)]
pub struct SecretKey(x25519_dalek::StaticSecret);

impl SecretKey {
    /// Size in bytes of the [`SecretKey`].
    pub const BYTES: usize = 32;

    /// Generate a new random [`SecretKey`].
    pub fn generate(mut csprng: impl RngCore + CryptoRng) -> Self {
        let mut bytes = [0u8; Self::BYTES];
        csprng.fill_bytes(&mut bytes);

        let secret = x25519_dalek::StaticSecret::from(bytes);

        Self(secret)
    }

    /// Get the bytes serialization of this [`SecretKey`].
    pub fn to_bytes(&self) -> [u8; SecretKey::BYTES] {
        self.0.to_bytes()
    }

    pub(crate) fn as_dalek(&self) -> &x25519_dalek::StaticSecret {
        &self.0
    }
}

impl From<[u8; SecretKey::BYTES]> for SecretKey {
    fn from(value: [u8; SecretKey::BYTES]) -> Self {
        Self(value.into())
    }
}

impl TryFrom<&[u8]> for SecretKey {
    type Error = InvalidLength;

    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        if slice.len() != Self::BYTES {
            return Err(InvalidLength::new(Self::BYTES, slice.len()));
        }

        let mut array = [0u8; SecretKey::BYTES];
        array.copy_from_slice(slice);

        Ok(Self::from(array))
    }
}

#[cfg(feature = "serde")]
impl Serialize for SecretKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        serdect::array::serialize_hex_upper_or_bin(&self.0.to_bytes(), serializer)
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
        Self::try_from(&bytes[..]).map_err(de::Error::custom)
    }
}
