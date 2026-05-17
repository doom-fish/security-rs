mod common;

use security::{
    Certificate, EncryptionAlgorithm, KeyType, PrivateKey, PublicKey, SignatureAlgorithm,
};

#[test]
fn signs_verifies_encrypts_and_exports_private_keys() -> security::Result<()> {
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
    assert_eq!(PrivateKey::type_id(), PublicKey::type_id());
    assert!(raw_key.attributes()?.is_object());
    assert_eq!(raw_key.block_size(), 256);
    assert!(!raw_key.external_representation()?.is_empty());

    let derived_public_key = raw_key.public_key()?;
    assert_eq!(derived_public_key.block_size(), 256);
    assert!(!derived_public_key.external_representation()?.is_empty());

    let ciphertext =
        derived_public_key.encrypt(EncryptionAlgorithm::RsaEncryptionOaepSha256, b"security-rs")?;
    let plaintext = raw_key.decrypt(EncryptionAlgorithm::RsaEncryptionOaepSha256, &ciphertext)?;
    assert_eq!(plaintext, b"security-rs");

    let signature = raw_key.sign(
        SignatureAlgorithm::RsaSignatureMessagePkcs1v15Sha256,
        b"security-rs",
    )?;

    let certificate = Certificate::from_pem(&common::fixture("test-cert.pem"))?;
    let public_key = certificate.public_key()?;
    assert_eq!(public_key.block_size(), 256);
    assert!(!public_key.external_representation()?.is_empty());
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
