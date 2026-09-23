mod common;

use security::{Certificate, Policy, SecurityError, Trust};

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

#[test]
fn trust_key_returns_the_leaf_public_key() -> security::Result<()> {
    let certificate = Certificate::from_der(&common::fixture("test-cert.der"))?;
    let trust = Trust::new(&certificate, &[Policy::basic_x509()?])?;
    let key = trust.key()?.expect("RSA leaf key should be extractable");
    assert!(key.block_size() > 0);
    assert_eq!(
        key.external_representation()?,
        certificate.public_key()?.external_representation()?
    );
    Ok(())
}

#[test]
fn trust_key_is_none_when_the_leaf_key_cannot_be_extracted() -> security::Result<()> {
    let certificate = Certificate::from_der(&common::fixture("test-cert-dsa.der"))?;
    let trust = Trust::new(&certificate, &[Policy::basic_x509()?])?;
    assert!(trust.key()?.is_none());
    assert!(certificate.public_key().is_err());
    Ok(())
}

#[test]
fn trust_rejects_self_signed_leaf_without_custom_anchor() -> security::Result<()> {
    let certificate = Certificate::from_der(&common::fixture("test-cert.der"))?;
    let mut trust = Trust::new(&certificate, &[Policy::basic_x509()?])?;
    trust.set_network_fetch_allowed(false)?;
    assert!(matches!(
        trust.evaluate(),
        Err(SecurityError::TrustEvaluationFailed(_))
    ));
    Ok(())
}
