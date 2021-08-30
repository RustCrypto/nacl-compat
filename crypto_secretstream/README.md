# RustCrypto: `crypto_secretstream`

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![CodeCov Status][codecov-image]][codecov-link]
[![Project Chat][chat-image]][chat-link]
[![Build Status][build-image]][build-link]

Pure Rust implementation of [libsodium]'s [`crypto_secretstream`] primitive,
providing an [AEAD] using [ChaCha20] and [Poly1305].

It is tested against [sodiumoxide], a Rust [libsodium] bindings.

[Documentation][docs-link]

## License

Licensed under either of:

- [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
- [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

### Caveats

- auto-rekeying on counter overflow is not tested
- `Tag::Final` doesn't actually do anything, as [libsodium] does but not [sodiumoxide]
- `Key` and `Nonce` aren't zeroize, maybe it should
- MAC check in `PullStream` is not constant time

[//]: # "badges"
[crate-image]: https://img.shields.io/crates/v/crypto_secretstream.svg
[crate-link]: https://crates.io/crates/crypto_secretstream
[docs-image]: https://docs.rs/crypto_secretstream/badge.svg
[docs-link]: https://docs.rs/crypto_secretstream/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.49+-blue.svg
[codecov-image]: https://codecov.io/gh/RustCrypto/AEADs/branch/master/graph/badge.svg
[codecov-link]: https://codecov.io/gh/RustCrypto/AEADs
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260038-AEADs
[build-image]: https://github.com/RustCrypto/AEADs/workflows/crypto_secretstream/badge.svg?branch=master&event=push
[build-link]: https://github.com/RustCrypto/AEADs/actions
[//]: # "general links"
[libsodium]: https://doc.libsodium.org/
[`crypto_secretstream`]: https://libsodium.gitbook.io/doc/secret-key_cryptography/secretstream
[aead]: https://en.wikipedia.org/wiki/Authenticated_encryption
[chacha20]: https://github.com/RustCrypto/stream-ciphers/tree/master/chacha20
[poly1305]: https://github.com/RustCrypto/universal-hashes/tree/master/poly1305
[sodiumoxide]: https://github.com/sodiumoxide/sodiumoxide
