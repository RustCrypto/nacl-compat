use crate::{SecretKey, KEY_SIZE};
use core::cmp::Ordering;
use curve25519_dalek::MontgomeryPoint;

#[cfg(feature = "serde")]
use serdect::serde::{de, ser, Deserialize, Serialize};

/// A `crypto_box` public key.
///
/// This type can be serialized if the `serde` feature is enabled.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct PublicKey(pub(crate) MontgomeryPoint);

impl PublicKey {
    /// Create a public key from a slice. The bytes of the slice will be copied.
    ///
    /// This function will fail and return `None` if the length of the byte
    /// slice isn't exactly [`KEY_SIZE`].
    pub fn from_slice(slice: &[u8]) -> Option<Self> {
        slice
            .try_into()
            .map(|bytes| PublicKey(MontgomeryPoint(bytes)))
            .ok()
    }

    /// Borrow the public key as bytes.
    pub fn as_bytes(&self) -> &[u8; KEY_SIZE] {
        self.0.as_bytes()
    }

    /// Serialize this public key as bytes.
    pub fn to_bytes(&self) -> [u8; KEY_SIZE] {
        self.0.to_bytes()
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl From<&SecretKey> for PublicKey {
    fn from(secret_key: &SecretKey) -> PublicKey {
        secret_key.public_key()
    }
}

impl From<[u8; KEY_SIZE]> for PublicKey {
    fn from(bytes: [u8; KEY_SIZE]) -> PublicKey {
        PublicKey(MontgomeryPoint(bytes))
    }
}

impl PartialOrd for PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PublicKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_bytes().cmp(other.as_bytes())
    }
}

impl From<MontgomeryPoint> for PublicKey {
    fn from(value: MontgomeryPoint) -> Self {
        PublicKey(value)
    }
}

#[cfg(feature = "serde")]
impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        serdect::array::serialize_hex_upper_or_bin(self.as_bytes(), serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let mut bytes = [0u8; KEY_SIZE];
        serdect::array::deserialize_hex_or_bin(&mut bytes, deserializer)?;
        Ok(PublicKey::from(bytes)) // TODO(tarcieri): validate key
    }
}
