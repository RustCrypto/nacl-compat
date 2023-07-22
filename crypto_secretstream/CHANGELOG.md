# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.2.0 (2023-07-22)
### Added
- Constant corresponding to `crypto_secretstream_xchacha20poly1305_ABYTES` ([#81])

### Changed
- MSRV 1.60 ([#88])

[#81]: https://github.com/RustCrypto/nacl-compat/pull/81
[#88]: https://github.com/RustCrypto/nacl-compat/pull/88

## 0.1.1 (2022-12-01)
### Fixed
- WASM problem with 32-bit usize and `copy_with_slice` expecting 8-bytes ([#76])

[#76]: https://github.com/RustCrypto/nacl-compat/pull/76

## 0.1.0 (2022-08-13)
### Changed
- Bump `chacha20` to v0.9 ([#50])
- Bump `chacha20poly1305` to v0.10 ([#50])
- Upgrade to Rust 2021 edition; MSRV 1.56 ([#42])

[#42]: https://github.com/RustCrypto/nacl-compat/pull/42
[#50]: https://github.com/RustCrypto/nacl-compat/pull/50

## 0.0.1 (2021-08-30)
- Initial release
