# security-rs

Safe Rust bindings for Apple's [Security](https://developer.apple.com/documentation/security) framework on macOS.

> **Status:** v0.2.2 adds modern `SecKey` encryption/decryption/export helpers, public CFTypeID accessors, and exhaustive raw FFI coverage for the non-deprecated macOS `SecAccessControl` / `SecItem` / `SecKey` / `SecPolicy` headers.

## Highlights

- Swift bridge over `Security.framework` with retained opaque handles and ergonomic Rust wrappers.
- Raw C FFI preserved behind the `raw-ffi` Cargo feature, now exhaustively covering the non-deprecated macOS `SecAccessControl` / `SecItem` / `SecKey` / `SecPolicy` headers.
- Safe modules for all primary logical areas:
  - `keychain`
  - `identity`
  - `certificate`
  - `key`
  - `policy`
  - `trust`
  - `authorization`
  - `code`
  - `random_bytes`
  - `transform`
  - `secure_transport`
  - `cms`
  - `key_derivation`
  - `key_agreement`
- 15 numbered headless examples plus smoke tests across every area.

## Quick start

```rust,no_run
use security::prelude::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let certificate = Certificate::from_der(&std::fs::read("tests/fixtures/test-cert.der")?)?;
    let policy = Policy::basic_x509()?;
    let mut trust = Trust::new(&certificate, &[policy])?;
    trust.set_anchor_certificates(&[certificate])?;
    trust.set_anchor_certificates_only(true)?;
    trust.evaluate()?;

    let encoded = Transform::encode_base64(b"hello")?;
    assert_eq!(Transform::decode_base64(encoded.as_bytes())?, b"hello");

    let random = SecureRandom::bytes(16)?;
    assert_eq!(random.len(), 16);
    Ok(())
}
```

## Area overview

- **`Keychain`:** generic-password CRUD, service account listing, access-control creation, and `SecAccessControl` type IDs.
- **`Identity`:** PKCS#12 import, certificate access, and private-key attribute inspection.
- **`Certificate`:** DER/PEM loading, Security item import/export, summaries, names, emails, serials, validity dates, and public keys.
- **`Key`:** raw/private-key import, modern signing, RSA encryption/decryption, external representations, block-size inspection, and `SecKey` type IDs.
- **`Policy` / `Trust`:** basic X.509, SSL, revocation, generic property builders, policy type IDs, custom anchors, and evaluated trust results.
- **`Authorization`:** authorization creation and external-form round trips.
- **`Code`:** current-process code objects, static-code inspection, designated requirements, and task entitlements.
- **`RandomBytes`:** `SecRandomCopyBytes` wrappers.
- **`Transform`:** base64 encode/decode using deprecated but still functional `SecTransform` APIs.
- **`SecureTransport`:** minimal context creation, protocol bounds, and state inspection.
- **`CMS`:** certificate-bag encode/decode.
- **`KeyDerivation`:** PBKDF2-style symmetric-key derivation through `SecKeyDeriveFromPassword`.
- **`KeyAgreement`:** ephemeral P-256 key generation and ECDH shared-secret derivation.

## Examples

Run every numbered example:

```bash
for ex in examples/*.rs; do cargo run --example "$(basename "$ex" .rs)"; done
```

Key examples:

- `01_keychain_password`
- `05_trust_evaluate`
- `07_code_signing_info`
- `11_cms_cert_bag`
- `13_key_agreement_shared_secret`
- `14_key_import_sign_verify`
- `15_key_encrypt_export`

## Raw FFI

Enable the legacy raw C declarations when you need direct `Security.framework` symbols. The `raw-ffi` feature now exposes the non-deprecated macOS-available `SecAccessControl.h`, `SecItem.h`, `SecKey.h`, and `SecPolicy.h` surfaces end-to-end:

```bash
cargo test --features raw-ffi
```

The default API path stays on the Swift bridge so Rust code does not call the C-only framework surface directly.

## Coverage notes

See [COVERAGE.md](COVERAGE.md) for the header audit and per-area implementation / partial / skipped status.

## License

Licensed under either of [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT) at your option.
