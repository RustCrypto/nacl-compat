//! Pure Rust implementation of the [`crypto_secretstream`] AEAD
//! from [NaCl]-family libraries (e.g. libsodium, TweetNaCl)
//! which uses [chacha20] and [poly1305].
//!
//! # Introduction
//!
//! Imagine Alice wants to open a safe channel of communication with Bob,
//! one that can't be read or modified by anyone else.
//!
//! One way she can do this is by first agreeing with Bob on a shared secret
//! key (such as one generated via a key exchange protocol), then she opens a
//! normal/unsafe channel of communication and sends her messages, encrypted
//! under this shared key. Then, when Bob receives theses messages, he can
//! decrypt each one and the mere knowledge of this shared key ensures that it
//! was indeed sent by Alice.
//!
//! Under the hood, the first message is postfixed with a random number, called
//! a nonce, generated by Alice, which is taken into account during encryption
//! and decryption. It is then incremented for each new message.
//!
//! It also allows for additional data to be sent with each message.
//! This data is not encrypted but used in the encryption process thus it is
//! needed to be known in advance by the receiver.
//! It can be useful for adding another layer of security, and is not of a
//! fixed size as the key is.
//!
//! # Usage
//!
//! ```rust
//! use crypto_secretstream::*;
//! use rand_core::OsRng;
//!
//! // Generate a key
//! let key = Key::generate(&mut OsRng);
//!
//! // Use some additional data
//! let some_additional_data = b"It needs to be known in advance";
//!
//! //
//! // Send messages
//! //
//!
//! // Create a stream to send messages, receive an header to send to the other
//! // side (it can be known by a thirdparty without security issue).
//! let (header, mut push_stream) = PushStream::init(&mut rand_core::OsRng, &key);
//!
//! // Messages to send
//! let first_plaintext = b"Top secret message we're encrypting";
//! let second_plaintext = b"Which can be followed by other messages";
//!
//! // Encrypt the messages using the stream
//! let first_ciphertext = push_stream.push(first_plaintext, &[], Tag::Message).unwrap();
//! let second_ciphertext = push_stream.push(second_plaintext, some_additional_data, Tag::Final).unwrap();
//!
//! //
//! // Receive messages
//! //
//!
//! // Create a stream to receive messages
//! let mut pull_stream = PullStream::init(header, &key);
//!
//! // Decrypt the ciphertexts using the stream
//! let (first_tag, first_decrypted_plaintext) = pull_stream.pull(&first_ciphertext, &[]).unwrap();
//! let (second_tag, second_decrypted_plaintext) = pull_stream.pull(&second_ciphertext, some_additional_data).unwrap();
//!
//! assert_eq!(&first_plaintext[..], &first_decrypted_plaintext);
//! assert_eq!(first_tag, Tag::Message);
//! assert_eq!(&second_plaintext[..], &second_decrypted_plaintext);
//! assert_eq!(second_tag, Tag::Final);
//! ```
//!
//! [NaCl]: https://nacl.cr.yp.to/
//! [`crypto_secretstream`]: https://doc.libsodium.org/secret-key_cryptography/secretstream
//! [chacha20]: https://github.com/RustCrypto/stream-ciphers/tree/master/chacha20
//! [poly1305]: https://github.com/RustCrypto/universal-hashes/tree/master/poly1305

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![warn(missing_docs, rust_2018_idioms)]

mod header;
mod key;
mod nonce;
mod stream;
mod tags;

pub use header::Header;
pub use key::Key;
pub use stream::{PullStream, PushStream, Stream};
pub use tags::Tag;
