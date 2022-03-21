//! `crypto_secretstream` keys.

use crate::errors::InvalidLength;
use rand_core::{CryptoRng, RngCore};

/// Symmetric key used by [`crate::PushStream`] and [`crate::PullStream`].
pub struct Key(chacha20::Key);

impl Key {
    /// Number of bytes used by the serialisation.
    pub const BYTES: usize = 32;

    /// Generate a new random [`Key`].
    pub fn generate(mut csprng: impl RngCore + CryptoRng) -> Self {
        let mut bytes = chacha20::Key::default();
        csprng.fill_bytes(&mut bytes);

        Self(bytes)
    }

    pub(super) fn as_array(&self) -> &chacha20::Key {
        &self.0
    }
}

impl AsRef<[u8; Key::BYTES]> for Key {
    fn as_ref(&self) -> &[u8; Key::BYTES] {
        self.0.as_ref()
    }
}

impl From<[u8; Key::BYTES]> for Key {
    fn from(value: [u8; Key::BYTES]) -> Self {
        Self(value.into())
    }
}

impl TryFrom<&[u8]> for Key {
    type Error = InvalidLength;

    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        if slice.len() != Self::BYTES {
            return Err(InvalidLength::new(Self::BYTES, slice.len()));
        }

        let mut array = [0u8; Self::BYTES];
        array.copy_from_slice(slice);

        Ok(Self::from(array))
    }
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use super::Key;

    #[test]
    fn can_be_constructed_by_serialized() {
        let key = Key::generate(&mut OsRng);

        let reconstructed_key = Key::from(*key.as_ref());

        assert_eq!(key.as_ref(), reconstructed_key.as_ref());
    }
}
