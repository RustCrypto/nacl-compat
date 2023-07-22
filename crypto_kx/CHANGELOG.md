# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.2.1 (2023-07-22)
### Fixed
- docs.rs build (removed bogus `seal` feature)

## 0.2.0 (2023-07-22)
### Changed
- Use `curve25519-dalek`; MSRV 1.60 ([#89], [#130])
- Use `CryptoRngCore` ([#132])

[#89]: https://github.com/RustCrypto/nacl-compat/pull/89
[#130]: https://github.com/RustCrypto/nacl-compat/pull/130
[#132]: https://github.com/RustCrypto/nacl-compat/pull/132

## 0.1.0 (2022-08-13)
### Changed
- Bump `blake2` to v0.10 ([#22])
- Upgrade to Rust 2021 edition; MSRV 1.56 ([#42])
- Use `serdect` crate ([#59])
- Select `x25519-dalek` backend automatically ([#60])

[#22]: https://github.com/RustCrypto/nacl-compat/pull/22
[#42]: https://github.com/RustCrypto/nacl-compat/pull/42
[#59]: https://github.com/RustCrypto/nacl-compat/pull/59
[#60]: https://github.com/RustCrypto/nacl-compat/pull/60

## 0.0.1 (2021-09-13)
- Initial release
