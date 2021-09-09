//! Pure Rust implementation of the [`crypto_kx`] key exchange
//! from [NaCl]-family libraries (e.g. libsodium, TweetNaCl)
//! which uses [BLAKE2].
//!
//! # Introduction
//!
//! Imagine Alice wants to open a safe channel of communication with Betty,
//! using something like [`crypto_secretstream`], they first need to agree on
//! a shared secret.
//!
//! One such secret can be obtain if each knows the public key of the other.
//! Each uses their secret key and the other public key to generate the same
//! secret without additional communication. No eavesdropper can know what the
//! secret is, as the secret key is, well, secret.
//!
//! Using the same key for sending and receiving might poses cryptographic
//! issues and/or reduce the overall throughput.
//! So when computing the shared secret, you actually get two keys,
//! one for each direction.
//!
//! # Usage
//!
//! ```rust
//! use crypto_kx::*;
//! use rand_core::OsRng;
//!
//! // Each generates a key on their machine.
//! let alice = KeyPair::generate(OsRng);
//! let betty = KeyPair::generate(OsRng);
//!
//! // Then Alice decides to send a message to Betty, so she computes the shared keys.
//! let alice_keys = alice.session_keys_to(betty.public());
//! // Upon connection, Betty computes the same keys on her side.
//! let betty_keys = betty.session_keys_from(alice.public());
//!
//! // By the beauty of math, they have generated the same keys on both side.
//! assert_eq!(alice_keys.tx.as_ref(), betty_keys.rx.as_ref());
//! assert_eq!(alice_keys.rx.as_ref(), betty_keys.tx.as_ref());
//! ```
//!
//! [NaCl]: https://nacl.cr.yp.to/
//! [`crypto_kx`]: https://doc.libsodium.org/key_exchange/
//! [`crypto_secretstream`]: https://github.com/RustCrypto/nacl-compat/tree/master/crypto_secretstream
//! [BLAKE2]: https://github.com/RustCrypto/hashes/tree/master/blake2

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![warn(missing_docs, rust_2018_idioms)]

mod keypair;
mod keys;

pub mod errors;

pub use keypair::KeyPair;
pub use keys::{
    ClientSession as ClientSessionKeys, Public as PublicKey, Secret as SecretKey,
    ServerSession as ServerSessionKeys, Session as SessionKey,
};
