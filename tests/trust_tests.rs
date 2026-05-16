mod common;

use security::{Certificate, Policy, Trust};

#[test]
fn evaluates_trust_with_custom_anchor() -> security::Result<()> {
    let certificate = Certificate::from_der(&common::fixture("test-cert.der"))?;
    let policy = Policy::basic_x509()?;
    let mut trust = Trust::new(&certificate, &[policy])?;
    trust.set_anchor_certificates(&[certificate])?;
    trust.set_anchor_certificates_only(true)?;
    trust.set_network_fetch_allowed(false)?;
    trust.evaluate()?;
    assert!(!trust.certificate_chain()?.is_empty());
    Ok(())
}
