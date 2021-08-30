# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.7.0 (2021-08-30)
### Changed
- MSRV 1.51 ([#8])
- Bump `chacha20poly1305` to v0.9 ([#8])
- Bump `xsalsa20poly1305` to v0.8 ([#8])

[#8]: https://github.com/RustCrypto/nacl-compat/pull/8

## 0.6.1 (2021-07-20)
### Changed
- Pin `zeroize` dependency to v1.3

## 0.6.0 (2021-04-29)
### Changed
- Bump `chacha20poly1305` crate dependency to v0.8
- Bump `xsalsa20poly1305` crate dependency to v0.7
- Bump `rand_core` crate dependency to v0.6

### SECURITY
- Fix XChaCha20Poly1305 key derivation

## 0.5.0 (2020-10-16)
### Added
- `ChaChaBox`

### Changed
- Replace `block-cipher`/`stream-cipher` with `cipher` crate
- Bump `xsalsa20poly1305` dependency to v0.6

## 0.4.0 (2020-09-17)
### Added
- Optional `std` feature; disabled by default

### Changed
- Upgrade `xsalsa20poly1305` to v0.5

## 0.3.0 (2020-08-18)
### Changed
- Bump `x25519-dalek` dependency to 1.0

## 0.2.0 (2020-06-06)
### Changed
- Bump `aead` crate dependency to v0.3; MSRV 1.41+
- Bump `xsalsa20poly1305` dependency to v0.4

## 0.1.0 (2020-02-25)
- Initial release
