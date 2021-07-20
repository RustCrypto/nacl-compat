# RustCrypto: compatibility layer for NaCl-family libraries

[![Project Chat][chat-image]][chat-link]
[![dependency status][deps-image]][deps-link]

Pure Rust implementation of APIs from [NaCl]-family libraries
(e.g. [libsodium], [TweetNaCl]).

## Crates

| Name           | Crates.io | Documentation | MSRV |
|----------------|-----------|---------------|------|
| [`crypto_box`](https://github.com/RustCrypto/nacl-compat/tree/master/crypto_box) | [![crates.io](https://img.shields.io/crates/v/crypto_box.svg)](https://crates.io/crates/crypto_box) | [![Documentation](https://docs.rs/crypto_box/badge.svg)](https://docs.rs/crypto_box) | 1.49 |

## MSRV Policy

Minimum Supported Rust Version (MSRV) can be changed in the future, but it will be
done with a minor version bump.

## License

All crates licensed under either of

 * [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
 * [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[//]: # (badges)

[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#all_messages
[deps-image]: https://deps.rs/repo/github/RustCrypto/nacl-compat/status.svg
[deps-link]: https://deps.rs/repo/github/RustCrypto/nacl-compat

[//]: # (general links)

[NaCl]: http://https://nacl.cr.yp.to
[libsodium]: http://https://doc.libsodium.org
[TweetNaCl]: http://https://tweetnacl.cr.yp.to
