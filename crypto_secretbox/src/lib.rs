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
#![cfg_attr(all(feature = "getrandom", feature = "std"), doc = "```")]
#![cfg_attr(not(all(feature = "getrandom", feature = "std")), doc = "```ignore")]
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use crypto_secretbox::{
//!     aead::{Aead, AeadCore, KeyInit, OsRng},
//!     XSalsa20Poly1305, Nonce
//! };
//!
//! let key = XSalsa20Poly1305::generate_key(&mut OsRng);
//! let cipher = XSalsa20Poly1305::new(&key);
//! let nonce = XSalsa20Poly1305::generate_nonce(&mut OsRng); // unique per message
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
    all(feature = "getrandom", feature = "heapless", feature = "std"),
    doc = "```"
)]
#![cfg_attr(
    not(all(feature = "getrandom", feature = "heapless", feature = "std")),
    doc = "```ignore"
)]
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use crypto_secretbox::{
//!     aead::{AeadCore, AeadInPlace, KeyInit, OsRng, heapless::Vec},
//!     XSalsa20Poly1305, Nonce,
//! };
//!
//! let key = XSalsa20Poly1305::generate_key(&mut OsRng);
//! let cipher = XSalsa20Poly1305::new(&key);
//! let nonce = XSalsa20Poly1305::generate_nonce(&mut OsRng); // unique per message
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
//! ```
//! # #[cfg(feature = "heapless")]
//! # {
//! use crypto_secretbox::XSalsa20Poly1305;
//! use crypto_secretbox::aead::{AeadCore, AeadInPlace, KeyInit, generic_array::GenericArray};
//! use crypto_secretbox::aead::heapless::Vec;
//!
//! let key = GenericArray::from_slice(b"an example very very secret key.");
//! let cipher = XSalsa20Poly1305::new(key);
//!
//! let nonce = GenericArray::from_slice(b"extra long unique nonce!"); // 24-bytes; unique
//!
//! let mut buffer: Vec<u8, 128> = Vec::new();
//! buffer.extend_from_slice(b"plaintext message");
//!
//! // Encrypt `buffer` in-place, replacing the plaintext contents with ciphertext
//! cipher.encrypt_in_place(nonce, b"", &mut buffer).expect("encryption failure!");
//!
//! // `buffer` now contains the message ciphertext
//! assert_ne!(&buffer, b"plaintext message");
//!
//! // Decrypt `buffer` in-place, replacing its ciphertext context with the original plaintext
//! cipher.decrypt_in_place(nonce, b"", &mut buffer).expect("decryption failure!");
//! assert_eq!(&buffer, b"plaintext message");
//! # }
//! ```
//!
//! [1]: https://nacl.cr.yp.to/secretbox.html
//! [2]: https://en.wikipedia.org/wiki/Authenticated_encryption
//! [3]: https://docs.rs/salsa20
//! [4]: http://docs.rs/chacha20poly1305
//! [5]: https://docs.rs/chacha20poly1305/latest/chacha20poly1305/struct.XChaCha20Poly1305.html
//! [6]: https://tools.ietf.org/html/rfc8439

pub use aead::{self, consts, AeadCore, AeadInPlace, Error, KeyInit, KeySizeUser};
pub use salsa20::{Key, XNonce as Nonce};

use aead::{
    consts::{U0, U16, U24, U32},
    generic_array::GenericArray,
    Buffer,
};
use core::marker::PhantomData;
use poly1305::Poly1305;
use salsa20::{
    cipher::{IvSizeUser, KeyIvInit, StreamCipher},
    XSalsa20,
};
use zeroize::Zeroize;

/// Size of an XSalsa20Poly1305 key in bytes
pub const KEY_SIZE: usize = 32;

/// Size of an XSalsa20Poly1305 nonce in bytes
pub const NONCE_SIZE: usize = 24;

/// Size of a Poly1305 tag in bytes
pub const TAG_SIZE: usize = 16;

/// Poly1305 tags
pub type Tag = GenericArray<u8, U16>;

/// `crypto_secretbox` instantiated with the XSalsa20 stream cipher.
pub type XSalsa20Poly1305 = SecretBox<XSalsa20>;

/// The NaCl `crypto_secretbox` authenticated symmetric encryption primitive,
/// generic
pub struct SecretBox<C> {
    /// Secret key.
    key: Key,

    /// Cipher.
    cipher: PhantomData<C>,
}

impl<C> SecretBox<C>
where
    C: KeyIvInit + KeySizeUser<KeySize = U32> + IvSizeUser<IvSize = U24> + StreamCipher,
{
    /// Initialize cipher instance and Poly1305 MAC.
    fn init_cipher_and_mac(&self, nonce: &Nonce) -> (C, Poly1305) {
        let mut cipher = C::new(&self.key, nonce);

        // Derive Poly1305 key from the first 32-bytes of the keystream.
        let mut mac_key = poly1305::Key::default();
        cipher.apply_keystream(&mut mac_key);

        let mac = Poly1305::new(&mac_key);
        mac_key.zeroize();

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
    type CiphertextOverhead = U0;
}

impl<C> AeadInPlace for SecretBox<C>
where
    C: KeyIvInit + KeySizeUser<KeySize = U32> + IvSizeUser<IvSize = U24> + StreamCipher,
{
    fn encrypt_in_place(
        &self,
        nonce: &Nonce,
        associated_data: &[u8],
        buffer: &mut dyn Buffer,
    ) -> Result<(), Error> {
        let pt_len = buffer.len();

        // Make room in the buffer for the tag. It needs to be prepended.
        buffer.extend_from_slice(Tag::default().as_slice())?;

        // TODO(tarcieri): add offset param to `encrypt_in_place_detached`
        buffer.as_mut().copy_within(..pt_len, TAG_SIZE);

        let tag = self.encrypt_in_place_detached(
            nonce,
            associated_data,
            &mut buffer.as_mut()[TAG_SIZE..],
        )?;
        buffer.as_mut()[..TAG_SIZE].copy_from_slice(tag.as_slice());
        Ok(())
    }

    fn encrypt_in_place_detached(
        &self,
        nonce: &Nonce,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<Tag, Error> {
        // AAD unsupported
        if !associated_data.is_empty() {
            return Err(Error);
        }

        let (mut cipher, mac) = self.init_cipher_and_mac(nonce);
        cipher.apply_keystream(buffer);
        Ok(mac.compute_unpadded(buffer))
    }

    fn decrypt_in_place(
        &self,
        nonce: &Nonce,
        associated_data: &[u8],
        buffer: &mut dyn Buffer,
    ) -> Result<(), Error> {
        if buffer.len() < TAG_SIZE {
            return Err(Error);
        }

        let tag = Tag::clone_from_slice(&buffer.as_ref()[..TAG_SIZE]);
        self.decrypt_in_place_detached(
            nonce,
            associated_data,
            &mut buffer.as_mut()[TAG_SIZE..],
            &tag,
        )?;

        let pt_len = buffer.len() - TAG_SIZE;

        // TODO(tarcieri): add offset param to `encrypt_in_place_detached`
        buffer.as_mut().copy_within(TAG_SIZE.., 0);
        buffer.truncate(pt_len);
        Ok(())
    }

    fn decrypt_in_place_detached(
        &self,
        nonce: &Nonce,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &Tag,
    ) -> Result<(), Error> {
        // AAD unsupported
        if !associated_data.is_empty() {
            return Err(Error);
        }

        let (mut cipher, mac) = self.init_cipher_and_mac(nonce);
        let expected_tag = mac.compute_unpadded(buffer);

        // This performs a constant-time comparison using the `subtle` crate
        use subtle::ConstantTimeEq;
        if expected_tag.ct_eq(tag).into() {
            cipher.apply_keystream(buffer);
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
