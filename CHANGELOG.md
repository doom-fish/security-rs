# Changelog

## [0.1.0] - 2026-05-16

### Added

- `Keychain` + `KeychainEntry` wrappers for generic-password CRUD and account enumeration via `SecItem*`.
- `Certificate` + `PublicKey` wrappers for DER import/export, subject summaries, and public-key extraction.
- `Policy` + `Trust` helpers for basic X.509 / SSL trust evaluation through `SecTrustEvaluateWithError`.
- `Code` / `SigningInformation` support for current-process signing metadata, entitlements introspection, and sandbox detection.
- `SecureRandom` wrapper over `SecRandomCopyBytes`.
- Smoke example `examples/01_smoke.rs` covering keychain CRUD + CSPRNG output.
