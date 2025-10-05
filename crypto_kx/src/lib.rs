#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![warn(missing_docs, rust_2018_idioms)]

//! ## Usage
//!
//! ```rust
//! use crypto_kx::*;
//! use rand_core::{OsRng, TryRngCore};
//!
//! // Each generates a key on their machine.
//! let alice = Keypair::generate(&mut OsRng.unwrap_err());
//! let betty = Keypair::generate(&mut OsRng.unwrap_err());
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

#[cfg(not(any(target_pointer_width = "32", target_pointer_width = "64")))]
compile_error!("`crypto-box` requires either a 32-bit or 64-bit target");

mod keypair;
mod keys;

pub mod errors;

pub use keypair::Keypair;
pub use keys::*;
