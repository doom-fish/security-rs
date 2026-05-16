mod common;

use security::{Certificate, KeyType, PrivateKey, SignatureAlgorithm};

#[test]
fn signs_and_verifies_private_keys_imported_from_raw_data() -> security::Result<()> {
    let imported = PrivateKey::import_item(
        &common::fixture("test-key.pem"),
        Some(".pem"),
        security::ExternalFormat::Unknown,
        security::ExternalItemType::PrivateKey,
    )?;
    assert!(imported.attributes()?.is_object());

    let raw_key = PrivateKey::from_data(
        &common::fixture("test-key-rsa.pkcs1.der"),
        KeyType::Rsa,
        2048,
    )?;
    assert!(raw_key.attributes()?.is_object());

    let signature = raw_key.sign(
        SignatureAlgorithm::RsaSignatureMessagePkcs1v15Sha256,
        b"security-rs",
    )?;

    let certificate = Certificate::from_pem(&common::fixture("test-cert.pem"))?;
    let public_key = certificate.public_key()?;
    assert!(public_key.verify_signature(
        SignatureAlgorithm::RsaSignatureMessagePkcs1v15Sha256,
        b"security-rs",
        &signature,
    )?);
    assert!(!public_key.verify_signature(
        SignatureAlgorithm::RsaSignatureMessagePkcs1v15Sha256,
        b"tampered",
        &signature,
    )?);
    Ok(())
}
