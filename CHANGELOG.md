# Changelog

All notable changes to `security-rs` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.0] - 2026-09-24

### Security

- `Code::task()` returned the calling process's own task instead of the code object's, so an
  entitlement check on a peer (`Code::guest_with_attributes(..)?.task()?.entitlement(..)`)
  checked the caller and let every client through. It now creates the task from the audit token
  the code was looked up by, and returns `SecurityError::Unsupported` for code found any other
  way (for example by PID).
- Framework calls that return NULL (`SecTrustCopyKey` for a DSA leaf, `SecPolicyCreateRevocation`
  with rejected flags) were boxed as live handles: `Trust::key()` returned `Some` and later calls
  passed NULL into Security.framework. Such results are now `None` or an error, and every handle
  is type-checked when the bridge unboxes it.
- `signing_information()` crashed (SIGSEGV) for any certificate-signed code, because the bridge
  described CF objects with Swift casts that never check the CF type. Objects are now dispatched
  on `CFGetTypeID`. The same unchecked cast let certificate and private-key imports return an
  item of the wrong type.
- `CmsDecoder::signer_status(.., evaluate_sec_trust: false)` reported certificate verification
  code 0, so a forged self-signed signer looked verified. The report now says the certificate was
  not evaluated and returns the signer's `Trust` for evaluation.
- On macOS 12-14, `Identity::import_pkcs12_first` stored the private key in the login keychain.
  It now returns `SecurityError::Unsupported` before macOS 15, where `kSecImportToMemoryOnly`
  exists.
- `Policy::ssl(_, None)` silently disabled hostname verification. Hostname-less SSL policies now
  require `Policy::ssl_any_hostname`.
- Dropping an `AsyncAuthorization::copy_rights` future and then the `Authorization` freed the
  `AuthorizationRef` while the request still used it; the request now keeps it alive.
- Keychain reads return zeroizing `SecretBytes` with a redacted `Debug`, the bridge wipes its
  copies of secrets, and the keychain example no longer prints the secret.

### Fixed

- `StaticCode::check_validity[_with_errors]` bit-cast static code into `SecCodeCheckValidity` and
  always failed; they now call `SecStaticCodeCheckValidityWithErrors`.
- `Code::signing_information()` reads the running code, so the dynamic status is reported.
- `CodeSigningFlags` no longer aliases information flags onto validation bits.
- `AsyncTrust::evaluate` now starts `SecTrustEvaluateAsyncWithError` on the queue it passes.
- `CmsDecoder::all_certificates()` calls `CMSDecoderCopyAllCerts` instead of always failing.
- A requirement or policy handle that does not unbox is an error instead of being dropped (which
  validated without the requirement) or replaced by basic X.509.
- JSON guest attributes pass `audit` and `hash` values as CFData, and byte arrays with values
  above 255 are rejected instead of truncated.
- Empty CMS input no longer force-unwraps a buffer address; `Cms::decode_all_certificates(&[])`
  is an error.
- Out-of-range certificate, trust and CMS dates are errors instead of panics.
- Authorization right names must be non-empty and free of NUL bytes.
- The build script no longer adds the toolchain's Swift 5.5 back-deployment directory
  (`usr/lib/swift-5.5/macosx`) to the link search path. Its old `libswift_Concurrency.dylib`
  shadowed the SDK's, so a binary that also linked Swift code using newer concurrency APIs (such
  as apple-localauthentication's bridge) failed to link.

### Changed

- **Breaking:** `Keychain::get` and `KeychainEntry::get` return `SecretBytes` instead of
  `String`; `set` accepts any `AsRef<[u8]>`.
- **Breaking:** `Policy::ssl` takes `hostname: &str` (non-empty) instead of `Option<&str>`.
- **Breaking:** `CmsDecoder::signer_status` returns `CmsSignerStatusReport` instead of JSON.
- **Breaking:** `Code::task()` fails for code not looked up by audit token.
- **Breaking:** `Identity::import_pkcs12_first` fails before macOS 15.
- **Breaking:** `Policy::revocation` fails for flags Security.framework rejects (such as 0).
- **Breaking:** `SignatureAlgorithm` has new variants, so exhaustive matches need new arms.
- Items stored without options are created with `kSecAttrAccessibleWhenUnlocked`.
- `AccessControl` holds the retained `SecAccessControlRef` itself instead of a bridge box, so the
  ref can be handed to other frameworks; the keychain bridge type-checks it.
- `rust-version` is 1.82; depends on apple-cf 0.11 and doom-fish-utils 0.4.1.

### Added

- `AuditToken`, `Code::guest_with_audit_token`, `Code::audit_token`, `Code::from_xpc_message`
  (`SecCodeCreateWithXPCMessage`), `Code::check_validity`, `Task::from_audit_token`,
  `CodeStatus` and `SigningInformation::code_status`.
- `CodeSigningFlags::{CHECK_TRUSTED_ANCHORS, NO_NETWORK_ACCESS, ENFORCE_REVOCATION_CHECKS,
  CONSIDER_EXPIRATION}`.
- `AccessControl::as_ptr` (the borrowed `SecAccessControlRef`, which cryptokit-rs Secure Enclave
  key creation and apple-localauthentication's `LAContext::evaluate_access_control` use),
  `AccessControl::protection` and `AccessControl::flags` (the values it was created with), and
  `Clone`, which shares the immutable object.
- `KeychainOptions` (protection class, data protection keychain, access group, synchronizable,
  `AccessControl`, `LAContext` authentication context) and
  `Keychain::{set,get,delete,list_accounts}_with_options`; `SecretBytes`.
- `CmsSignerStatus`, `CmsCertificateVerification`, `CmsSignerStatusReport`.
- `Policy::ssl_any_hostname`, `Authorization::set_destroy_rights_on_drop`,
  `DerivedKey::to_bytes`, SHA-384/SHA-512 and RSA-PSS digest `SignatureAlgorithm` variants.
- `SecurityError::Unsupported`, `status::MISSING_ENTITLEMENT`, `status::UNIMPLEMENTED`.
- `tests/fixtures/README.md` documents the throwaway test identity (password `password`).

### Removed

- **Breaking:** `CodeSigningFlags::{SIGNING_INFORMATION, DYNAMIC_INFORMATION,
  USE_ALL_ARCHITECTURES}`, which aliased `DO_NOT_VALIDATE_EXECUTABLE`, `CHECK_NESTED_CODE` and
  `CHECK_ALL_ARCHITECTURES`.

## [0.5.0] - 2026-05-20

### Added

- `async_api` module behind the `async` feature, providing executor-agnostic async wrappers for `SecTrustEvaluateAsyncWithError` and `AuthorizationCopyRightsAsync`. Uses `doom-fish-utils::completion`.

## [0.4.4] - 2026-05-20

- Added in-`src/` unit tests across `authorization`, `error`, `keychain`, and `trust`, providing fast `cargo test --lib` fail-fast signal alongside the existing integration tests under `tests/`.

## [0.4.3] - 2026-05-19

- Bump MSRV from 1.70 to 1.76 to match fleet baseline.

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
