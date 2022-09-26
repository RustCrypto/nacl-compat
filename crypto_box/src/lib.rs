#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![warn(missing_docs, rust_2018_idioms)]

//! ## Usage
//!
#![cfg_attr(all(feature = "getrandom", feature = "std"), doc = "```")]
#![cfg_attr(not(all(feature = "getrandom", feature = "std")), doc = "```ignore")]
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use crypto_box::{
//!     aead::{Aead, AeadCore, OsRng},
//!     SalsaBox, PublicKey, SecretKey
//! };
//!
//! //
//! // Encryption
//! //
//!
//! // Generate a random secret key.
//! // NOTE: The secret key bytes can be accessed by calling `secret_key.as_bytes()`
//! let alice_secret_key = SecretKey::generate(&mut OsRng);
//!
//! // Get the public key for the secret key we just generated
//! let alice_public_key_bytes = alice_secret_key.public_key().as_bytes().clone();
//!
//! // Obtain your recipient's public key.
//! let bob_public_key = PublicKey::from([
//!    0xe8, 0x98, 0xc, 0x86, 0xe0, 0x32, 0xf1, 0xeb,
//!    0x29, 0x75, 0x5, 0x2e, 0x8d, 0x65, 0xbd, 0xdd,
//!    0x15, 0xc3, 0xb5, 0x96, 0x41, 0x17, 0x4e, 0xc9,
//!    0x67, 0x8a, 0x53, 0x78, 0x9d, 0x92, 0xc7, 0x54,
//! ]);
//!
//! // Create a `SalsaBox` by performing Diffie-Hellman key agreement between
//! // the two keys.
//! let alice_box = SalsaBox::new(&bob_public_key, &alice_secret_key);
//!
//! // Get a random nonce to encrypt the message under
//! let nonce = SalsaBox::generate_nonce(&mut OsRng);
//!
//! // Message to encrypt
//! let plaintext = b"Top secret message we're encrypting";
//!
//! // Encrypt the message using the box
//! let ciphertext = alice_box.encrypt(&nonce, &plaintext[..])?;
//!
//! //
//! // Decryption
//! //
//!
//! // Either side can encrypt or decrypt messages under the Diffie-Hellman key
//! // they agree upon. The example below shows Bob's side.
//! let bob_secret_key = SecretKey::from([
//!     0xb5, 0x81, 0xfb, 0x5a, 0xe1, 0x82, 0xa1, 0x6f,
//!     0x60, 0x3f, 0x39, 0x27, 0xd, 0x4e, 0x3b, 0x95,
//!     0xbc, 0x0, 0x83, 0x10, 0xb7, 0x27, 0xa1, 0x1d,
//!     0xd4, 0xe7, 0x84, 0xa0, 0x4, 0x4d, 0x46, 0x1b
//! ]);
//!
//! // Deserialize Alice's public key from bytes
//! let alice_public_key = PublicKey::from(alice_public_key_bytes);
//!
//! // Bob can compute the same `SalsaBox` as Alice by performing the
//! // key agreement operation.
//! let bob_box = SalsaBox::new(&alice_public_key, &bob_secret_key);
//!
//! // Decrypt the message, using the same randomly generated nonce
//! let decrypted_plaintext = bob_box.decrypt(&nonce, &ciphertext[..])?;
//!
//! assert_eq!(&plaintext[..], &decrypted_plaintext[..]);
//! # Ok(())
//! # }
//! ```
//!
//! ## Choosing [`ChaChaBox`] vs [`SalsaBox`]
//!
//! The `crypto_box` construction was originally specified using [`SalsaBox`].
//!
//! However, the newer [`ChaChaBox`] construction is also available, which
//! provides marginally better security and additional features such as
//! additional associated data:
//!
#![cfg_attr(all(feature = "getrandom", feature = "std"), doc = "```")]
#![cfg_attr(not(all(feature = "getrandom", feature = "std")), doc = "```ignore")]
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use crypto_box::{
//!     aead::{Aead, AeadCore, Payload, OsRng},
//!     ChaChaBox, PublicKey, SecretKey
//! };
//!
//! let alice_secret_key = SecretKey::generate(&mut OsRng);
//! let alice_public_key_bytes = alice_secret_key.public_key().as_bytes().clone();
//! let bob_public_key = PublicKey::from([
//!    0xe8, 0x98, 0xc, 0x86, 0xe0, 0x32, 0xf1, 0xeb,
//!    0x29, 0x75, 0x5, 0x2e, 0x8d, 0x65, 0xbd, 0xdd,
//!    0x15, 0xc3, 0xb5, 0x96, 0x41, 0x17, 0x4e, 0xc9,
//!    0x67, 0x8a, 0x53, 0x78, 0x9d, 0x92, 0xc7, 0x54,
//! ]);
//! let alice_box = ChaChaBox::new(&bob_public_key, &alice_secret_key);
//! let nonce = ChaChaBox::generate_nonce(&mut OsRng);
//!
//! // Message to encrypt
//! let plaintext = b"Top secret message we're encrypting".as_ref();
//! let associated_data = b"customized associated data here".as_ref();
//!
//! // Encrypt the message using the box
//! let ciphertext = alice_box.encrypt(&nonce, Payload {
//!   msg: plaintext, // your message to encrypt
//!   aad: associated_data, // not encrypted, but authenticated in tag
//! }).unwrap();
//!
//! //
//! // Decryption
//! //
//!
//! let bob_secret_key = SecretKey::from([
//!     0xb5, 0x81, 0xfb, 0x5a, 0xe1, 0x82, 0xa1, 0x6f,
//!     0x60, 0x3f, 0x39, 0x27, 0xd, 0x4e, 0x3b, 0x95,
//!     0xbc, 0x0, 0x83, 0x10, 0xb7, 0x27, 0xa1, 0x1d,
//!     0xd4, 0xe7, 0x84, 0xa0, 0x4, 0x4d, 0x46, 0x1b
//! ]);
//! let alice_public_key = PublicKey::from(alice_public_key_bytes);
//! let bob_box = ChaChaBox::new(&alice_public_key, &bob_secret_key);
//!
//! // Decrypt the message, using the same randomly generated nonce
//! let decrypted_plaintext = bob_box.decrypt(&nonce, Payload {
//!   msg: &ciphertext,
//!   aad: associated_data, // tag authentication will fail if associated data doesn't match, which fails the decryption
//! }).unwrap();
//!
//! assert_eq!(&plaintext[..], &decrypted_plaintext[..]);
//! # Ok(())
//! # }
//! ```
//!
//! ## In-place Usage (eliminates `alloc` requirement)
//!
//! This crate has an optional `alloc` feature which can be disabled in e.g.
//! microcontroller environments that don't have a heap.
//!
//! The [`AeadInPlace::encrypt_in_place`] and [`AeadInPlace::decrypt_in_place`]
//! methods accept any type that impls the [`aead::Buffer`] trait which
//! contains the plaintext for encryption or ciphertext for decryption.
//!
//! Note that if you enable the `heapless` feature of this crate,
//! you will receive an impl of `aead::Buffer` for [`heapless::Vec`]
//! (re-exported from the `aead` crate as `aead::heapless::Vec`),
//! which can then be passed as the `buffer` parameter to the in-place encrypt
//! and decrypt methods.
//!
//! A `heapless` usage example can be found in the documentation for the
//! `xsalsa20poly1305` crate:
//!
//! <https://docs.rs/xsalsa20poly1305/latest/xsalsa20poly1305/#in-place-usage-eliminates-alloc-requirement>
//!
//! [NaCl]: https://nacl.cr.yp.to/
//! [`crypto_box`]: https://nacl.cr.yp.to/box.html
//! [X25519]: https://cr.yp.to/ecdh.html
//! [XSalsa20Poly1305]: https://nacl.cr.yp.to/secretbox.html
//! [ECIES]: https://en.wikipedia.org/wiki/Integrated_Encryption_Scheme
//! [`heapless::Vec`]: https://docs.rs/heapless/latest/heapless/struct.Vec.html

pub use aead::{self, rand_core};
pub use xsalsa20poly1305::Nonce;

use chacha20::hchacha;
use chacha20poly1305::XChaCha20Poly1305;
use core::fmt::{self, Debug};
use rand_core::{CryptoRng, RngCore};
use salsa20::hsalsa;
use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};
use xsalsa20poly1305::aead::{
    consts::{U0, U10, U16, U24},
    generic_array::GenericArray,
    AeadCore, AeadInPlace, Buffer, Error, KeyInit,
};
use xsalsa20poly1305::XSalsa20Poly1305;
use zeroize::{Zeroize, Zeroizing};

#[cfg(feature = "seal")]
extern crate alloc;

#[cfg(feature = "seal")]
use alloc::vec::Vec;

#[cfg(feature = "serde")]
use serdect::serde::{de, ser, Deserialize, Serialize};

/// Size of a `crypto_box` public or secret key in bytes.
pub const KEY_SIZE: usize = 32;

/// Poly1305 tag.
///
/// Implemented as an alias for [`GenericArray`].
pub type Tag = GenericArray<u8, U16>;
#[cfg(feature = "seal")]
const TAG_SIZE: usize = 16;

/// A `crypto_box` secret key.
#[derive(Clone)]
pub struct SecretKey([u8; KEY_SIZE]);

impl SecretKey {
    /// Generate a random [`SecretKey`].
    pub fn generate<T>(csprng: &mut T) -> Self
    where
        T: RngCore + CryptoRng,
    {
        let mut bytes = [0u8; KEY_SIZE];
        csprng.fill_bytes(&mut bytes);
        SecretKey(bytes)
    }

    /// Get the [`PublicKey`] which corresponds to this [`SecretKey`]
    pub fn public_key(&self) -> PublicKey {
        PublicKey(x25519(self.0, X25519_BASEPOINT_BYTES))
    }

    #[deprecated(note = "use `as_bytes` instead")]
    #[allow(missing_docs)]
    pub fn to_bytes(&self) -> [u8; KEY_SIZE] {
        self.0
    }

    /// Get a slice of the [`SecretKey`] bytes
    pub fn as_bytes(&self) -> &[u8; KEY_SIZE] {
        &self.0
    }
}

impl From<[u8; KEY_SIZE]> for SecretKey {
    fn from(bytes: [u8; KEY_SIZE]) -> SecretKey {
        SecretKey(bytes)
    }
}

impl Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey(...)")
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// A `crypto_box` public key.
///
/// This type can be serialized if the `serde` feature is enabled.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct PublicKey([u8; KEY_SIZE]);

impl PublicKey {
    /// Get a slice of the [`PublicKey`] bytes
    pub fn as_bytes(&self) -> &[u8; KEY_SIZE] {
        &self.0
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<&SecretKey> for PublicKey {
    fn from(secret_key: &SecretKey) -> PublicKey {
        secret_key.public_key()
    }
}

impl From<[u8; KEY_SIZE]> for PublicKey {
    fn from(bytes: [u8; KEY_SIZE]) -> PublicKey {
        PublicKey(bytes)
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        serdect::array::serialize_hex_upper_or_bin(&self.0, serializer)
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
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

macro_rules! impl_aead_in_place {
    ($box:ty, $nonce_size:ty, $tag_size:ty, $ct_overhead:ty) => {
        impl AeadCore for $box {
            type NonceSize = $nonce_size;
            type TagSize = $tag_size;
            type CiphertextOverhead = $ct_overhead;
        }

        impl AeadInPlace for $box {
            fn encrypt_in_place(
                &self,
                nonce: &GenericArray<u8, Self::NonceSize>,
                associated_data: &[u8],
                buffer: &mut dyn Buffer,
            ) -> Result<(), Error> {
                self.0.encrypt_in_place(nonce, associated_data, buffer)
            }

            fn encrypt_in_place_detached(
                &self,
                nonce: &GenericArray<u8, Self::NonceSize>,
                associated_data: &[u8],
                buffer: &mut [u8],
            ) -> Result<Tag, Error> {
                self.0
                    .encrypt_in_place_detached(nonce, associated_data, buffer)
            }

            fn decrypt_in_place(
                &self,
                nonce: &GenericArray<u8, Self::NonceSize>,
                associated_data: &[u8],
                buffer: &mut dyn Buffer,
            ) -> Result<(), Error> {
                self.0.decrypt_in_place(nonce, associated_data, buffer)
            }

            fn decrypt_in_place_detached(
                &self,
                nonce: &GenericArray<u8, Self::NonceSize>,
                associated_data: &[u8],
                buffer: &mut [u8],
                tag: &Tag,
            ) -> Result<(), Error> {
                self.0
                    .decrypt_in_place_detached(nonce, associated_data, buffer, tag)
            }
        }
    };
}

/// Public-key encryption scheme based on the [X25519] Elliptic Curve
/// Diffie-Hellman function and the [XSalsa20Poly1305] authenticated encryption
/// cipher.
///
/// This type impls the [`aead::Aead`] trait, and otherwise functions as a
/// symmetric Authenticated Encryption with Associated Data (AEAD) cipher
/// once instantiated.
///
/// [X25519]: https://cr.yp.to/ecdh.html
/// [XSalsa20Poly1305]: https://github.com/RustCrypto/AEADs/tree/master/xsalsa20poly1305
#[derive(Clone)]
pub struct SalsaBox(XSalsa20Poly1305);

impl SalsaBox {
    /// Create a new [`SalsaBox`], performing X25519 Diffie-Hellman to derive
    /// a shared secret from the provided public and secret keys.
    pub fn new(public_key: &PublicKey, secret_key: &SecretKey) -> Self {
        let shared_secret = Zeroizing::new(x25519(secret_key.0, public_key.0));

        // Use HSalsa20 to create a uniformly random key from the shared secret
        let mut key = hsalsa::<U10>(
            GenericArray::from_slice(&*shared_secret),
            &GenericArray::default(),
        );

        let cipher = XSalsa20Poly1305::new(&key);
        key.zeroize();

        SalsaBox(cipher)
    }
}

impl_aead_in_place!(SalsaBox, U24, U16, U0);

/// Public-key encryption scheme based on the [X25519] Elliptic Curve
/// Diffie-Hellman function and the [XChaCha20Poly1305] authenticated encryption
/// cipher.
///
/// This type impls the [`aead::Aead`] trait, and otherwise functions as a
/// symmetric Authenticated Encryption with Associated Data (AEAD) cipher
/// once instantiated.
///
/// [X25519]: https://cr.yp.to/ecdh.html
/// [XChaCha20Poly1305]: https://github.com/RustCrypto/AEADs/blob/master/chacha20poly1305/
#[derive(Clone)]
pub struct ChaChaBox(XChaCha20Poly1305);

impl ChaChaBox {
    /// Create a new [`ChaChaBox`], performing X25519 Diffie-Hellman to derive
    /// a shared secret from the provided public and secret keys.
    pub fn new(public_key: &PublicKey, secret_key: &SecretKey) -> Self {
        let shared_secret = Zeroizing::new(x25519(secret_key.0, public_key.0));

        // Use HChaCha20 to create a uniformly random key from the shared secret
        let mut key = hchacha::<U10>(
            GenericArray::from_slice(&*shared_secret),
            &GenericArray::default(),
        );

        let cipher = XChaCha20Poly1305::new(&key);
        key.zeroize();

        ChaChaBox(cipher)
    }
}

impl_aead_in_place!(ChaChaBox, U24, U16, U0);

#[cfg(feature = "seal")]
fn get_seal_nonce(ephemeral_pk: &PublicKey, recipient_pk: &PublicKey) -> Nonce {
    use blake2::{Blake2b, Digest};
    let mut hasher = Blake2b::<U24>::new();
    hasher.update(ephemeral_pk.as_bytes());
    hasher.update(recipient_pk.as_bytes());
    hasher.finalize()
}

/// Implementation of `crypto_box_seal` function from [libsodium "sealed boxes"].
///
/// Sealed boxes are designed to anonymously send messages to a recipient given their public key.
///
/// [libsodium "sealed boxes"]: https://doc.libsodium.org/public-key_cryptography/sealed_boxes
#[cfg(feature = "seal")]
#[cfg_attr(docsrs, doc(cfg(feature = "seal")))]
pub fn seal<T>(
    csprng: &mut T,
    recipient_pk: &PublicKey,
    plaintext: &[u8],
) -> Result<Vec<u8>, aead::Error>
where
    T: RngCore + CryptoRng,
{
    let mut out = Vec::with_capacity(KEY_SIZE + TAG_SIZE + plaintext.len());

    let ep_sk = SecretKey::generate(csprng);
    let ep_pk = ep_sk.public_key();

    out.extend_from_slice(ep_pk.as_bytes());

    let nonce = get_seal_nonce(&ep_pk, recipient_pk);

    let salsabox = SalsaBox::new(recipient_pk, &ep_sk);
    let encrypted = aead::Aead::encrypt(&salsabox, &nonce, plaintext)?;

    out.extend_from_slice(&encrypted);

    Ok(out)
}

/// Implementation of `crypto_box_seal_open` function from [libsodium "sealed boxes"].
///
/// Sealed boxes are designed to anonymously send messages to a recipient given their public key.
///
/// [libsodium "sealed boxes"]: https://doc.libsodium.org/public-key_cryptography/sealed_boxes
#[cfg(feature = "seal")]
#[cfg_attr(docsrs, doc(cfg(feature = "seal")))]
pub fn seal_open(recipient_sk: &SecretKey, ciphertext: &[u8]) -> Result<Vec<u8>, aead::Error> {
    if ciphertext.len() <= KEY_SIZE {
        return Err(aead::Error);
    }
    let ep_pk: [u8; KEY_SIZE] = ciphertext[..KEY_SIZE].try_into().unwrap();
    let ep_pk = ep_pk.into();

    let nonce = get_seal_nonce(&ep_pk, &recipient_sk.public_key());

    let salsabox = SalsaBox::new(&ep_pk, recipient_sk);
    aead::Aead::decrypt(&salsabox, &nonce, &ciphertext[KEY_SIZE..])
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "serde")]
    #[test]
    fn test_public_key_serialization() {
        use super::PublicKey;
        use aead::rand_core::RngCore;

        // Random PK bytes
        let mut public_key_bytes = [0; 32];
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut public_key_bytes);

        // Create public key
        let public_key = PublicKey::from(public_key_bytes);

        // Round-trip serialize with bincode
        let serialized = bincode::serialize(&public_key).unwrap();
        let deserialized: PublicKey = bincode::deserialize(&serialized).unwrap();
        assert_eq!(deserialized, public_key,);

        // Round-trip serialize with rmp (msgpack)
        let serialized = rmp_serde::to_vec_named(&public_key).unwrap();
        let deserialized: PublicKey = rmp_serde::from_slice(&serialized).unwrap();
        assert_eq!(deserialized, public_key,);
    }
}
