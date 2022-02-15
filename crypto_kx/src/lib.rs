//! Pure Rust implementation of the [`crypto_kx`] key exchange
//! from [NaCl]-family libraries (e.g. libsodium, TweetNaCl)
//! which uses [BLAKE2].
//!
//! # Introduction
//!
//! Imagine Alice wants to open a safe communication channel with Betty,
//! using something like [`crypto_secretstream`]. They first need to agree on
//! a shared secret.
//!
//! To obtain this shared secret, Diffie-Hellman can be used, which works as follows:
//! Suppose both Alice and Betty know the public key of each other.
//! Then they use their private key and the other's public key to generate a
//! secret. This secret is the same for both Alice and Betty, as described by
//! the Diffie-Hellman algorithm.
//! No eavesdropper can know what the secret is, as they only know the public keys, but
//! not the private keys.
//!
//! Using the same key for sending and receiving might pose cryptographic
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
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_root_url = "https://docs.rs/crypto_kx/0.0.2"
)]
#![warn(missing_docs, rust_2018_idioms)]

mod keypair;
mod keys;

pub mod errors;

pub use keypair::KeyPair;
pub use keys::*;
