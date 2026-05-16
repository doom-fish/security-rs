use security::Policy;

#[test]
fn creates_policy_variants() -> security::Result<()> {
    assert!(Policy::basic_x509()?.properties()?.is_object());
    assert!(Policy::ssl(true, Some("localhost"))?.properties()?.is_object());
    assert!(Policy::revocation(0)?.properties()?.is_object());
    Ok(())
}
