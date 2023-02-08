//! Public key type.

use crate::errors::InvalidLength;
use curve25519_dalek::MontgomeryPoint;

#[cfg(feature = "serde")]
use serdect::serde::{de, ser, Deserialize, Serialize};

/// [`PublicKey`] which can be freely shared.
#[derive(Clone, Copy, Hash, PartialEq, Eq)]
pub struct PublicKey(pub(crate) MontgomeryPoint);

impl PublicKey {
    /// Size in bytes of the [`PublicKey`].
    pub const BYTES: usize = 32;
}

impl AsRef<[u8; PublicKey::BYTES]> for PublicKey {
    fn as_ref(&self) -> &[u8; PublicKey::BYTES] {
        self.0.as_bytes()
    }
}

impl From<[u8; PublicKey::BYTES]> for PublicKey {
    fn from(value: [u8; PublicKey::BYTES]) -> Self {
        Self(MontgomeryPoint(value))
    }
}

impl TryFrom<&[u8]> for PublicKey {
    type Error = InvalidLength;

    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        slice
            .try_into()
            .map(|bytes| Self(MontgomeryPoint(bytes)))
            .map_err(|_| InvalidLength::new(Self::BYTES, slice.len()))
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
        Ok(bytes.into())
    }
}
