# security-rs

Safe Rust bindings for Apple's [Security](https://developer.apple.com/documentation/security) framework on macOS.

> **Status:** v0.1.0 covers the baseline `Security.framework` surface most doom-fish crates need first: generic-password keychain access, certificate parsing, trust evaluation, current-process code-signing inspection, and cryptographically secure random bytes.

## Quick start

```rust,no_run
use security::prelude::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let service = format!("doom-fish-demo-{}", std::process::id());
    let account = "demo";

    let _ = Keychain::delete(account, &service);
    Keychain::set(account, &service, "hunter2")?;
    assert_eq!(Keychain::get(account, &service)?, "hunter2");
    Keychain::delete(account, &service)?;

    let random = SecureRandom::bytes(32)?;
    assert!(random.iter().any(|&byte| byte != 0));
    println!("current signing info: {:?}", Code::current()?.signing_information()?);
    Ok(())
}
```

## Highlights

- `Keychain` + `KeychainEntry` wrappers for `SecItemAdd`, `SecItemCopyMatching`, `SecItemUpdate`, and `SecItemDelete`
- `Certificate::from_der`, `subject_summary`, `der_data`, and `public_key`
- `Policy` + `Trust` wrappers for `SecTrustCreateWithCertificates`, `SecTrustSetPolicies`, and `SecTrustEvaluateWithError`
- `Code::current().signing_information()` for bundle identifier, team identifier, entitlements, status word, and sandbox detection
- `SecureRandom::fill` / `SecureRandom::bytes` over `SecRandomCopyBytes`

## Smoke example

Run the end-to-end smoke test with:

```bash
cargo run --all-features --example 01_smoke
```

It round-trips a unique generic-password keychain item, lists accounts for its service, deletes the item again, and verifies that `SecRandomCopyBytes` returns non-zero output.

## License

Licensed under either of [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT) at your option.
