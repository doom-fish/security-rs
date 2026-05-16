# Changelog

## [0.2.0] - 2026-05-16

### Added

- Swift bridge build pipeline and retained opaque-handle architecture for the safe API.
- Safe Rust wrappers for `Security.framework` logical areas: keychain, identity, certificate, policy, trust, authorization, code, random bytes, transform, SecureTransport, CMS, key derivation, and key agreement.
- `raw-ffi` feature gate for the legacy direct C declarations.
- 13 numbered headless examples, one per logical area.
- Per-area integration smoke tests and reusable certificate / PKCS#12 fixtures.
- `COVERAGE.md` header audit documenting implemented, partial, and skipped APIs.

### Changed

- Replaced the v0.1.0 direct safe wrappers with Swift-bridge-backed safe abstractions.
- Expanded the public prelude and top-level re-exports to cover the new modules.

## [0.1.0] - 2026-05-16

### Added

- `Keychain` + `KeychainEntry` wrappers for generic-password CRUD and account enumeration via `SecItem*`.
- `Certificate` + `PublicKey` wrappers for DER import/export, subject summaries, and public-key extraction.
- `Policy` + `Trust` helpers for basic X.509 / SSL trust evaluation through `SecTrustEvaluateWithError`.
- `Code` / `SigningInformation` support for current-process signing metadata, entitlements introspection, and sandbox detection.
- `SecureRandom` wrapper over `SecRandomCopyBytes`.
- Smoke example `examples/01_smoke.rs` covering keychain CRUD + CSPRNG output.
