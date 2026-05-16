mod common;

use security::Identity;

#[test]
fn imports_first_pkcs12_identity() -> security::Result<()> {
    let identity = Identity::import_pkcs12_first(&common::fixture("test-identity.p12"), "password")?;
    assert!(identity.chain_count() >= 1);
    assert!(identity.certificate()?.subject_summary()?.is_some());
    Ok(())
}
