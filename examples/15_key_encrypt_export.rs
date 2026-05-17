mod support;

use security::{Certificate, EncryptionAlgorithm, KeyType, PrivateKey, SignatureAlgorithm};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let private_key = PrivateKey::from_data(
        &std::fs::read("tests/fixtures/test-key-rsa.pkcs1.der")?,
        KeyType::Rsa,
        2048,
    )?;
    let public_key = private_key.public_key()?;

    let ciphertext = public_key.encrypt(
        EncryptionAlgorithm::RsaEncryptionOaepSha256,
        b"security-rs example",
    )?;
    let plaintext =
        private_key.decrypt(EncryptionAlgorithm::RsaEncryptionOaepSha256, &ciphertext)?;
    assert_eq!(plaintext, b"security-rs example");

    let signature = private_key.sign(
        SignatureAlgorithm::RsaSignatureMessagePkcs1v15Sha256,
        b"security-rs example",
    )?;
    let certificate = Certificate::from_pem(&std::fs::read("tests/fixtures/test-cert.pem")?)?;
    assert!(certificate.public_key()?.verify_signature(
        SignatureAlgorithm::RsaSignatureMessagePkcs1v15Sha256,
        b"security-rs example",
        &signature,
    )?);

    println!(
        "key_type_id={} block_size={} exported_private={} exported_public={}",
        PrivateKey::type_id(),
        public_key.block_size(),
        private_key.external_representation()?.len(),
        public_key.external_representation()?.len(),
    );

    Ok(())
}
