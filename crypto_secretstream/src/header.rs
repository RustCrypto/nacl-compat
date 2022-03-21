//! `crypto_secretstream` headers.

use super::{
    errors::InvalidLength,
    nonce::{HChaCha20Nonce, Nonce},
};
use chacha20::cipher::{
    consts::U24,
    generic_array::{sequence::Split, GenericArray},
};
use rand_core::{CryptoRng, RngCore};

/// Header of the secret stream, can be sent as cleartext.
#[derive(Clone, Copy)]
pub struct Header(GenericArray<u8, U24>);

impl Header {
    /// Number of bytes used by the serialisation.
    pub const BYTES: usize = 24;

    /// Generate a new random [`Header`].
    pub(super) fn generate(mut csprng: impl RngCore + CryptoRng) -> Self {
        let mut bytes = GenericArray::<u8, U24>::default();
        csprng.fill_bytes(&mut bytes);

        Self(bytes)
    }

    /// Extract the contained nonces.
    pub(super) fn split(self) -> (HChaCha20Nonce, Nonce) {
        self.0.split()
    }
}

impl AsRef<[u8; Header::BYTES]> for Header {
    fn as_ref(&self) -> &[u8; Header::BYTES] {
        self.0.as_ref()
    }
}

impl From<[u8; Header::BYTES]> for Header {
    fn from(value: [u8; Header::BYTES]) -> Self {
        Self(value.into())
    }
}

impl TryFrom<&[u8]> for Header {
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

    use super::Header;

    #[test]
    fn can_be_constructed_by_serialized() {
        let header = Header::generate(&mut OsRng);

        let reconstructed_header = Header::from(header);

        assert_eq!(header.as_ref(), reconstructed_header.as_ref());
    }
}
