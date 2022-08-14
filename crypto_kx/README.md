# RustCrypto: `crypto_kx`

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]
[![Build Status][build-image]][build-link]

Pure Rust implementation of [libsodium]'s [`crypto_kx`] primitive.

[Documentation][docs-link]

## About

Imagine Alice wants to open a safe communication channel with Betty,
using something like [`crypto_secretstream`]. They first need to agree on
a shared secret.

To obtain this shared secret, Diffie-Hellman can be used, which works as follows:
Suppose both Alice and Betty know the public key of each other.
Then they use their private key and the other's public key to generate a
secret. This secret is the same for both Alice and Betty, as described by
the Diffie-Hellman algorithm.
No eavesdropper can know what the secret is, as they only know the public keys, but
not the private keys.

Using the same key for sending and receiving might pose cryptographic
issues and/or reduce the overall throughput.
So when computing the shared secret, you actually get two keys,
one for each direction.

## License

Licensed under either of:

- [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
- [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[//]: # "badges"
[crate-image]: https://img.shields.io/crates/v/crypto_kx.svg
[crate-link]: https://crates.io/crates/crypto_kx
[docs-image]: https://docs.rs/crypto_kx/badge.svg
[docs-link]: https://docs.rs/crypto_kx/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.56+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260038-AEADs
[build-image]: https://github.com/RustCrypto/nacl-compat/actions/workflows/crypto_kx.yml/badge.svg
[build-link]: https://github.com/RustCrypto/nacl-compat/actions/workflows/crypto_kx.yml

[//]: # "general links"
[libsodium]: https://doc.libsodium.org/
[`crypto_kx`]: https://libsodium.gitbook.io/doc/key_exchange
