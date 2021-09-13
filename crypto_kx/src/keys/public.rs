use core::convert::TryFrom;

use crate::errors::InvalidLength;

/// [`PublicKey`] which can be freely shared.
#[derive(Clone, Copy, Hash, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(our_serde::Deserialize, our_serde::Serialize)
)]
#[cfg_attr(feature = "serde", serde(crate = "our_serde"))]
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
