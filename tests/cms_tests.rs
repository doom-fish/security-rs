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
