mod common;

use security::Certificate;

#[test]
fn certificate_round_trip() -> security::Result<()> {
    let der = common::fixture("test-cert.der");
    let certificate = Certificate::from_der(&der)?;
    assert_eq!(certificate.der_data()?, der);
    assert!(!certificate.serial_number()?.is_empty());
    Ok(())
}
