mod common;

use security::{Certificate, ExternalFormat, ExternalItemType};

#[test]
fn certificate_round_trip() -> security::Result<()> {
    let der = common::fixture("test-cert.der");
    let certificate = Certificate::from_der(&der)?;
    assert_eq!(certificate.der_data()?, der);
    assert!(!certificate.serial_number()?.is_empty());
    Ok(())
}

#[test]
fn imports_and_exports_certificate_items() -> security::Result<()> {
    let imported = Certificate::import_item(
        &common::fixture("test-cert.pem"),
        Some(".pem"),
        ExternalFormat::Unknown,
        ExternalItemType::Certificate,
    )?;
    let exported_pem = imported.export_item(ExternalFormat::X509Certificate, true)?;
    assert!(exported_pem.starts_with(b"-----BEGIN CERTIFICATE-----"));

    let exported_der = imported.export_item(ExternalFormat::X509Certificate, false)?;
    assert_eq!(
        Certificate::from_der(&exported_der)?.der_data()?,
        common::fixture("test-cert.der")
    );
    Ok(())
}
