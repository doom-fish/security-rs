mod common;

use security::{
    Certificate, Cms, CmsCertificateVerification, CmsDecoder, CmsSignedAttributes,
    CmsSignerStatus, Identity,
};

fn signed_message() -> security::Result<(Vec<u8>, Certificate)> {
    let identity =
        Identity::import_pkcs12_first(&common::fixture("test-identity.p12"), "password")?;
    let certificate = identity.certificate()?;
    let message = Cms::encode_content(
        &[identity],
        &[],
        None,
        false,
        CmsSignedAttributes::SIGNING_TIME,
        b"security-rs",
    )?;
    Ok((message, certificate))
}

fn decoder_for(message: &[u8]) -> security::Result<CmsDecoder> {
    let mut decoder = Cms::decoder()?;
    decoder.update_message(message)?;
    decoder.finalize_message()?;
    Ok(decoder)
}

#[test]
fn encodes_and_decodes_certificate_bag() -> security::Result<()> {
    let certificate = Certificate::from_der(&common::fixture("test-cert.der"))?;
    let encoded = Cms::encode_supporting_certificates(&[certificate])?;
    let decoded = Cms::decode_all_certificates(&encoded)?;
    assert_eq!(decoded.len(), 1);
    assert_eq!(decoder_for(&encoded)?.all_certificates()?.len(), 1);
    Ok(())
}

#[test]
fn signer_status_without_trust_evaluation_is_not_reported_as_verified() -> security::Result<()> {
    let (message, certificate) = signed_message()?;
    let decoder = decoder_for(&message)?;
    assert_eq!(decoder.num_signers()?, 1);
    assert_eq!(decoder.content()?.as_deref(), Some(&b"security-rs"[..]));

    let report = decoder.signer_status(0, None, false)?;
    assert_eq!(report.signer_status, CmsSignerStatus::Valid);
    assert_eq!(
        report.certificate_verification,
        CmsCertificateVerification::NotEvaluated
    );
    assert!(!report.is_verified());

    let mut trust = report.trust.expect("the signer trust is returned for later evaluation");
    trust.set_network_fetch_allowed(false)?;
    assert!(trust.evaluate().is_err());
    trust.set_anchor_certificates(&[certificate])?;
    trust.set_anchor_certificates_only(true)?;
    trust.evaluate()?;
    Ok(())
}

#[test]
fn signer_status_with_trust_evaluation_rejects_an_untrusted_signer() -> security::Result<()> {
    let (message, _) = signed_message()?;
    let report = decoder_for(&message)?.signer_status(0, None, true)?;
    assert_eq!(report.signer_status, CmsSignerStatus::InvalidCertificate);
    assert!(matches!(
        report.certificate_verification,
        CmsCertificateVerification::Evaluated(code) if code != 0
    ));
    assert!(!report.is_verified());
    assert!(report.trust.is_some());
    Ok(())
}

#[test]
fn signer_status_reports_an_out_of_range_signer() -> security::Result<()> {
    let (message, _) = signed_message()?;
    let decoder = decoder_for(&message)?;
    let status = decoder.signer_status(7, None, false).map(|report| report.signer_status);
    assert!(matches!(
        status,
        Ok(CmsSignerStatus::InvalidIndex) | Err(security::SecurityError::Status(_))
    ));
    Ok(())
}

#[test]
fn empty_cms_input_is_rejected_without_aborting() -> security::Result<()> {
    assert!(Cms::decode_all_certificates(&[]).is_err());
    let mut decoder = Cms::decoder()?;
    decoder.update_message(&[])?;
    let mut encoder = Cms::encoder()?;
    assert!(matches!(
        encoder.update_content(&[]),
        Ok(()) | Err(security::SecurityError::Status(_))
    ));
    Ok(())
}
