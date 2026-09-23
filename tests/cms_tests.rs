mod common;

use security::{Certificate, Cms};

#[test]
fn encodes_and_decodes_certificate_bag() -> security::Result<()> {
    let certificate = Certificate::from_der(&common::fixture("test-cert.der"))?;
    let encoded = Cms::encode_supporting_certificates(&[certificate])?;
    let decoded = Cms::decode_all_certificates(&encoded)?;
    assert_eq!(decoded.len(), 1);
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
