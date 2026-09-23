# security-rs

Safe Rust bindings for Apple's [Security](https://developer.apple.com/documentation/security) framework on macOS.

## Installation

```toml
[dependencies]
security-rs = "0.6"
```

Requires macOS 12 or later and Rust 1.82 or later. Some APIs need a newer macOS and return an
error on older systems: PKCS#12 import needs macOS 15 (see below), certificate validity dates
need macOS 15, and the `AppleSslServer`/`AppleSslClient`-style policy identifiers need macOS 15.4.

## Highlights

- Swift bridge over `Security.framework` with retained opaque handles and ergonomic Rust wrappers.
- Wrappers for the 158 top-level functions listed as verified in [`COVERAGE_AUDIT.md`](COVERAGE_AUDIT.md). That audit counts a self-selected set of 321 functions from 25 headers (163 marked exempt), not the whole framework or its constants.
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
- 16 numbered headless examples plus integration tests across every area.

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

## Identifying a peer process

Look peers up by audit token, never by PID: a PID can be reused by another process between the
lookup and the check. `Code::task()` only works for code looked up by audit token (or the current
process) and returns `SecurityError::Unsupported` otherwise.

```rust,no_run
use security::{AuditToken, Code, CodeSigningFlags, Requirement};

fn client_is_allowed(token: AuditToken) -> security::Result<bool> {
    let client = Code::guest_with_audit_token(&token)?;
    let requirement = Requirement::from_string(
        "anchor apple generic and certificate leaf[subject.OU] = \"TEAMID1234\"",
    )?;
    client.check_validity(CodeSigningFlags::empty(), Some(&requirement))?;
    Ok(client.task()?.entitlement("com.example.helper-client")?.is_some())
}
```

`Code::from_xpc_message` wraps `SecCodeCreateWithXPCMessage` for a received XPC message.

## Keychain items

Secrets are bytes and come back as `SecretBytes`, which zeroizes its buffer on drop and redacts
`Debug`. Items default to `AccessControlProtection::WhenUnlocked`. `KeychainOptions` selects the
protection class (including the `ThisDeviceOnly` classes), the data protection keychain, an access
group, synchronization, an `AccessControl` (for example user presence), and an `LAContext` from
[localauthentication-rs](https://crates.io/crates/apple-localauthentication)
(`LAContext::as_raw_la_context`) to bind a read to an authentication the user already passed.

```rust,no_run
use security::{AccessControl, AccessControlFlags, AccessControlProtection, Keychain, KeychainOptions};

fn store_token(token: &[u8]) -> security::Result<()> {
    let presence = AccessControl::create(
        AccessControlProtection::WhenUnlockedThisDeviceOnly,
        AccessControlFlags::USER_PRESENCE,
    )?;
    let options = KeychainOptions::default()
        .data_protection_keychain(true)
        .access_control(presence);
    Keychain::set_with_options("api-token", "com.example.app", token, &options)
}
```

The data protection keychain, access groups, synchronizable items and access-controlled items need
a signed process with a keychain access group entitlement; unsigned tools get
`errSecMissingEntitlement` (`security::error::status::MISSING_ENTITLEMENT`).

## Area overview

- **`Keychain`:** generic-password CRUD for binary secrets with protection class, data protection keychain, access group, synchronizable, access-control and authentication-context options; service account listing; access-control creation.
- **`Identity`:** PKCS#12 import, certificate access, identity creation, preference lookup/updates, system-identity management, and private-key attribute inspection. PKCS#12 import needs macOS 15: before that `SecPKCS12Import` always stores the private key in the login keychain, so `import_pkcs12_first` returns `SecurityError::Unsupported` instead.
- **`Certificate`:** DER/PEM loading, Security item import/export, descriptions, values, preferences, summaries, names, emails, serials, validity dates, and public keys.
- **`Key`:** raw/private-key import, modern signing, RSA encryption/decryption, external representations, block-size inspection, and `SecKey` type IDs.
- **`Policy` / `Trust`:** basic X.509, SSL, revocation, generic property builders, policy type IDs, custom anchors, verify dates, exceptions, OCSP / SCT inputs, async evaluation, derived keys, and evaluated trust results. `Policy::ssl(server, hostname)` verifies the hostname; `Policy::ssl_any_hostname` is the explicit opt-out.
- **`Authorization`:** authorization creation, external-form round trips, info inspection, synchronous / async rights acquisition, and destroying shared rights on drop.
- **`Code`:** current-process code objects, audit-token and XPC peer lookup, host / guest lookup, requirements, dynamic and static validation, resource validation, memory mapping, and task entitlement inspection.
- **`RandomBytes`:** `SecRandomCopyBytes` wrappers.
- **`Transform`:** base64 encode/decode using deprecated but still functional `SecTransform` APIs.
- **`SecureTransport`:** minimal context creation, protocol bounds, and state inspection.
- **`CMS`:** certificate-bag helpers plus low-level encoder / decoder access for content, signers, recipients, timestamps, detached payloads, and chain configuration. `CmsDecoder::signer_status` returns a typed report; with `evaluate_sec_trust = false` the signer certificate is reported as not evaluated and the report carries the `Trust` to evaluate.
- **`KeyDerivation`:** PBKDF2-style symmetric-key derivation through `SecKeyDeriveFromPassword`, with the derived bytes available as `SecretBytes`.
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
