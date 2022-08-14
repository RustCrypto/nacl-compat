//! Public key type.

use crate::errors::InvalidLength;

#[cfg(feature = "serde")]
use serdect::serde::{de, ser, Deserialize, Serialize};

/// [`PublicKey`] which can be freely shared.
#[derive(Clone, Copy, Hash, PartialEq, Eq)]
pub struct PublicKey(x25519_dalek::PublicKey);

impl PublicKey {
    /// Size in bytes of the [`PublicKey`].
    pub const BYTES: usize = 32;

    pub(crate) fn as_dalek(&self) -> &x25519_dalek::PublicKey {
        &self.0
    }
}

impl AsRef<[u8; PublicKey::BYTES]> for PublicKey {
    fn as_ref(&self) -> &[u8; PublicKey::BYTES] {
        self.0.as_bytes()
    }
}

impl From<[u8; PublicKey::BYTES]> for PublicKey {
    fn from(value: [u8; PublicKey::BYTES]) -> Self {
        Self(value.into())
    }
}

impl TryFrom<&[u8]> for PublicKey {
    type Error = InvalidLength;

    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        if slice.len() != Self::BYTES {
            return Err(InvalidLength::new(Self::BYTES, slice.len()));
        }

        let mut array = [0u8; PublicKey::BYTES];
        array.copy_from_slice(slice);

        Ok(Self::from(array))
    }
}

#[cfg(feature = "serde")]
impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        serdect::array::serialize_hex_upper_or_bin(&self.0.to_bytes(), serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let mut bytes = [0u8; Self::BYTES];
        serdect::array::deserialize_hex_or_bin(&mut bytes, deserializer)?;
        Self::try_from(&bytes[..]).map_err(de::Error::custom)
    }
}
