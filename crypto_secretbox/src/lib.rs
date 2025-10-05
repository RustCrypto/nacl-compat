#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

//! # Usage
//!
#![cfg_attr(all(feature = "os_rng", feature = "std"), doc = "```")]
#![cfg_attr(not(all(feature = "os_rng", feature = "std")), doc = "```ignore")]
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use crypto_secretbox::{
//!     aead::{Aead, AeadCore, KeyInit, rand_core::{OsRng, TryRngCore}},
//!     XSalsa20Poly1305, Nonce
//! };
//!
//! let key = XSalsa20Poly1305::generate_key_with_rng(&mut OsRng.unwrap_err());
//! let cipher = XSalsa20Poly1305::new(&key);
//! let nonce = XSalsa20Poly1305::generate_nonce_with_rng(&mut OsRng.unwrap_err()); // unique per message
//! let ciphertext = cipher.encrypt(&nonce, b"plaintext message".as_ref())?;
//! let plaintext = cipher.decrypt(&nonce, ciphertext.as_ref())?;
//! assert_eq!(&plaintext, b"plaintext message");
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
//! you will receive an impl of [`aead::Buffer`] for `heapless::Vec`
//! (re-exported from the `aead` crate as [`aead::heapless::Vec`]),
//! which can then be passed as the `buffer` parameter to the in-place encrypt
//! and decrypt methods:
//!
#![cfg_attr(
    all(feature = "os_rng", feature = "heapless", feature = "std"),
    doc = "```"
)]
#![cfg_attr(
    not(all(feature = "os_rng", feature = "heapless", feature = "std")),
    doc = "```ignore"
)]
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use crypto_secretbox::{
//!     aead::{AeadCore, AeadInPlace, KeyInit, rand_core::{OsRng, TryRngCore}, heapless::Vec},
//!     XSalsa20Poly1305, Nonce,
//! };
//!
//! let key = XSalsa20Poly1305::generate_key_with_rng(&mut OsRng.unwrap_err());
//! let cipher = XSalsa20Poly1305::new(&key);
//! let nonce = XSalsa20Poly1305::generate_nonce_with_rng(&mut OsRng.unwrap_err()); // unique per message
//!
//! let mut buffer: Vec<u8, 128> = Vec::new(); // Note: buffer needs 16-bytes overhead for auth tag
//! buffer.extend_from_slice(b"plaintext message");
//!
//! // Encrypt `buffer` in-place, replacing the plaintext contents with ciphertext
//! cipher.encrypt_in_place(&nonce, b"", &mut buffer)?;
//!
//! // `buffer` now contains the message ciphertext
//! assert_ne!(&buffer, b"plaintext message");
//!
//! // Decrypt `buffer` in-place, replacing its ciphertext context with the original plaintext
//! cipher.decrypt_in_place(&nonce, b"", &mut buffer)?;
//! assert_eq!(&buffer, b"plaintext message");
//! # Ok(())
//! # }
//! ```
//!
//! [1]: https://nacl.cr.yp.to/secretbox.html
//! [2]: https://en.wikipedia.org/wiki/Authenticated_encryption
//! [3]: https://docs.rs/salsa20
//! [4]: http://docs.rs/chacha20poly1305
//! [5]: https://docs.rs/chacha20poly1305/latest/chacha20poly1305/struct.XChaCha20Poly1305.html
//! [6]: https://tools.ietf.org/html/rfc8439

pub use aead::{self, consts, AeadCore, Error, KeyInit, KeySizeUser};
pub use cipher;

use aead::{
    array::Array,
    consts::{U16, U24, U32, U8},
    inout::InOutBuf,
    AeadInOut,
};
use cipher::{IvSizeUser, KeyIvInit, StreamCipher};
use core::marker::PhantomData;
use poly1305::Poly1305;
use zeroize::{Zeroize, Zeroizing};

#[cfg(feature = "chacha20")]
use chacha20::hchacha;
#[cfg(feature = "chacha20")]
type ChaCha20Legacy = cipher::StreamCipherCoreWrapper<
    chacha20::ChaChaCore<chacha20::R20, chacha20::variants::Legacy>,
>;

#[cfg(feature = "salsa20")]
use salsa20::{hsalsa, Salsa20};

#[cfg(feature = "salsa20")]
use cipher::consts::U10;

/// Key type.
pub type Key = Array<u8, U32>;

/// Nonce type.
pub type Nonce = Array<u8, U24>;

/// Poly1305 tag.
pub type Tag<C> = aead::Tag<SecretBox<C>>;

/// `crypto_secretbox` instantiated with the XChaCha20 stream cipher.
///
/// NOTE: this is a legacy construction which is missing modern features like
/// additional associated data.
///
/// We do not recommend using it in greenfield applications, and instead only
/// using it for interop with legacy applications which require use of the
/// `crypto_secretbox` construction instantiated with XChaCha20.
///
/// For new applications, we recommend using the `AEAD_XChaCha20_Poly1305`
/// construction as described in [`draft-irtf-cfrg-xchacha`]. An implementation
/// of this IETF flavor of XChaCha20Poly1305 can be found in
/// [`chacha20poly1305::XChaCha20Poly1305`].
///
/// [`draft-irtf-cfrg-xchacha`]: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha
/// [`chacha20poly1305::XChaCha20Poly1305`]: https://docs.rs/chacha20poly1305/latest/chacha20poly1305/type.XChaCha20Poly1305.html
#[cfg(feature = "chacha20")]
pub type XChaCha20Poly1305 = SecretBox<ChaCha20Legacy>;

/// `crypto_secretbox` instantiated with the XSalsa20 stream cipher.
#[cfg(feature = "salsa20")]
pub type XSalsa20Poly1305 = SecretBox<Salsa20>;

/// The NaCl `crypto_secretbox` authenticated symmetric encryption primitive,
/// generic
pub struct SecretBox<C> {
    /// Secret key.
    key: Key,

    /// Cipher.
    cipher: PhantomData<C>,
}

impl<C> SecretBox<C> {
    /// Size of an XSalsa20Poly1305 key in bytes
    pub const KEY_SIZE: usize = 32;

    /// Size of an XSalsa20Poly1305 nonce in bytes
    pub const NONCE_SIZE: usize = 24;

    /// Size of a Poly1305 tag in bytes
    pub const TAG_SIZE: usize = 16;
}

impl<C> SecretBox<C>
where
    C: Kdf + KeyIvInit + KeySizeUser<KeySize = U32> + IvSizeUser<IvSize = U8> + StreamCipher,
{
    /// Initialize cipher instance and Poly1305 MAC.
    fn init_cipher_and_mac(&self, nonce: &Nonce) -> (C, Poly1305) {
        let (nonce_prefix, nonce_suffix) = nonce.split::<U16>();

        let subkey = Zeroizing::new(C::kdf(&self.key, &nonce_prefix));
        let mut cipher = C::new(&subkey, &nonce_suffix);

        // Derive Poly1305 key from the first 32-bytes of the keystream.
        let mut mac_key = Zeroizing::new(poly1305::Key::default());
        cipher.apply_keystream(&mut mac_key);

        let mac = Poly1305::new(&mac_key);
        (cipher, mac)
    }
}

// Handwritten instead of derived to avoid `C: Clone` bound
impl<C> Clone for SecretBox<C> {
    fn clone(&self) -> Self {
        Self {
            key: self.key,
            cipher: PhantomData,
        }
    }
}

impl<C> KeySizeUser for SecretBox<C> {
    type KeySize = U32;
}

impl<C> KeyInit for SecretBox<C> {
    fn new(key: &Key) -> Self {
        SecretBox {
            key: *key,
            cipher: PhantomData,
        }
    }
}

impl<C> AeadCore for SecretBox<C> {
    type NonceSize = U24;
    type TagSize = U16;
    const TAG_POSITION: aead::TagPosition = aead::TagPosition::Prefix;
}

impl<C> AeadInOut for SecretBox<C>
where
    C: Kdf + KeyIvInit + KeySizeUser<KeySize = U32> + IvSizeUser<IvSize = U8> + StreamCipher,
{
    fn encrypt_inout_detached(
        &self,
        nonce: &Nonce,
        associated_data: &[u8],
        mut buffer: InOutBuf<'_, '_, u8>,
    ) -> aead::Result<Tag<C>> {
        // AAD unsupported
        if !associated_data.is_empty() {
            return Err(Error);
        }

        let (mut cipher, mac) = self.init_cipher_and_mac(nonce);
        cipher.apply_keystream(buffer.get_out());
        Ok(mac.compute_unpadded(buffer.get_out()))
    }

    fn decrypt_inout_detached(
        &self,
        nonce: &Nonce,
        associated_data: &[u8],
        mut buffer: InOutBuf<'_, '_, u8>,
        tag: &Tag<Self>,
    ) -> aead::Result<()> {
        // AAD unsupported
        if !associated_data.is_empty() {
            return Err(Error);
        }

        let (mut cipher, mac) = self.init_cipher_and_mac(nonce);
        let expected_tag = mac.compute_unpadded(buffer.get_out());

        // This performs a constant-time comparison using the `subtle` crate
        use subtle::ConstantTimeEq;
        if expected_tag.ct_eq(tag).into() {
            cipher.apply_keystream(buffer.get_out());
            Ok(())
        } else {
            Err(Error)
        }
    }
}

impl<C> Drop for SecretBox<C> {
    fn drop(&mut self) {
        self.key.as_mut_slice().zeroize();
    }
}

/// Key derivation function: trait for abstracting over HSalsa20 and HChaCha20.
pub trait Kdf {
    /// Derive a new key from the provided input key and nonce.
    fn kdf(key: &Key, nonce: &Array<u8, U16>) -> Key;
}

impl<C> Kdf for SecretBox<C>
where
    C: Kdf,
{
    fn kdf(key: &Key, nonce: &Array<u8, U16>) -> Key {
        C::kdf(key, nonce)
    }
}

#[cfg(feature = "chacha20")]
impl Kdf for ChaCha20Legacy {
    fn kdf(key: &Key, nonce: &Array<u8, U16>) -> Key {
        hchacha::<chacha20::R20>(key, nonce)
    }
}

#[cfg(feature = "salsa20")]
impl Kdf for Salsa20 {
    fn kdf(key: &Key, nonce: &Array<u8, U16>) -> Key {
        hsalsa::<U10>(key, nonce)
    }
}
