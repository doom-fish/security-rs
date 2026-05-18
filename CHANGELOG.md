# Changelog

## [0.4.2] - 2026-05-18

### Changed

- Add one-line rustdoc coverage across the public safe API surface, with Security.framework counterpart references for the documented wrappers.

## [0.4.1] - 2026-05-18

### Changed

- chore: re-export OS primitives (Boolean, OSStatus) from apple-cf

## [0.4.0] - 2026-05-18

### Changed

- Re-export `CFIndex`, `CFTypeID`, and `CFOptionFlags` from `apple_cf::raw` instead of maintaining local duplicate scalar aliases in `src/ffi/mod.rs`.
- Raise the `apple-cf` dependency range to `>=0.9, <0.10` so the shared raw Core Foundation type aliases come from the same source of truth.

## [0.3.0] - 2026-05-18

### Changed

- Re-export the raw `CF*Ref` aliases from `apple_cf::raw` instead of maintaining local duplicate typedefs in `src/ffi/mod.rs`.
- Raise the minimum `apple-cf` dependency to 0.8.0 so the raw Core Foundation ref aliases come from the shared source of truth.

## [0.2.4] - 2026-05-18

- Widen apple-cf version bound to `<0.9` so the 0.8.0 nested-CGRect dep resolves. No source changes.

## [0.2.3] - 2026-05-17

### Added

- Exhaustive safe-wrapper closure for the remaining non-exempt audited `Security.framework` surface in `Authorization.h`, `CMSDecoder.h`, `CMSEncoder.h`, `SecCertificate.h`, `SecCode.h`, `SecRequirement.h`, `SecStaticCode.h`, `SecTask.h`, `SecIdentity.h`, and `SecTrust.h`.
- New public `CmsDecoder` / `CmsEncoder`, `Requirement`, `CodeSigningFlags`, `TrustOptions`, and `TrustResultType` types plus expanded top-level re-exports.
- Smoke coverage for every newly added public API symbol, keeping the full test suite headless and green.

## [0.2.2] - 2026-05-17

### Added

- `EncryptionAlgorithm`, `PublicKey::encrypt`, `PrivateKey::decrypt`, `block_size`, and `external_representation` helpers over the modern `SecKey*` encryption/export APIs.
- `AccessControl::type_id`, `Policy::type_id`, and shared `SecKey` type-ID helpers across the public key wrappers.
- Exhaustive `raw-ffi` coverage for the non-deprecated macOS-available `SecAccessControl.h`, `SecItem.h`, `SecKey.h`, and `SecPolicy.h` symbols.
- `examples/15_key_encrypt_export.rs` plus expanded key / policy / raw-ffi smoke tests.

## [0.2.1] - 2026-05-16

### Added

- `AccessControl`, `AccessControlFlags`, and `AccessControlProtection` over `SecAccessControlCreateWithFlags`.
- `PrivateKey`, `KeyType`, `SignatureAlgorithm`, and `PublicKey::verify_signature` for raw key import and modern signing / verification.
- `Certificate::import_item` / `Certificate::export_item` and `PrivateKey::import_item` for `SecItemImport` / `SecItemExport` coverage.
- `Policy::with_properties` with typed `PolicyIdentifier`, `PolicyName`, and `PolicyProperties` builders.
- `examples/14_key_import_sign_verify.rs`, PKCS#1 DER key fixtures, and new policy / access-control / item-import smoke tests.

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
