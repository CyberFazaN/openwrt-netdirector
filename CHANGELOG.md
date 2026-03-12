# Changelog

All notable changes to this project will be documented in this file.

---

## [Unreleased]

### Planned
- future improvements and fixes

---

## [1.0.1] - 2026-03-12

### Breaking Changes
- QUIC handling flags were replaced with `--quic ignore|block`.
  Old profiles using `BLOCK_QUIC` will not enable QUIC blocking anymore.
  Update profiles to use:
  `QUIC_MODE="block"`.

### Changed
- Disabled DNS interception by default (must now be enabled with `--dns on`)

### Improved
- Updated CLI help and usage examples
- Updated README documentation

---

## [1.0.0] - 2026-03-08

### Added
- Initial release of `openwrt-netdirector`
- Transparent HTTP/HTTPS interception using nftables / fw4
- Forced DNS redirection
- Optional QUIC blocking
- Optional IPv6 blocking
- Interface-based filtering
- Client-based filtering
- Profile system for reusable configurations