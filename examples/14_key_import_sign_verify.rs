#[path = "support/mod.rs"]
mod support;

use security::{Certificate, KeyType, PrivateKey, SignatureAlgorithm};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let raw_key = PrivateKey::from_data(
        &support::fixture("test-key-rsa.pkcs1.der"),
        KeyType::Rsa,
        2048,
    )?;
    let signature = raw_key.sign(
        SignatureAlgorithm::RsaSignatureMessagePkcs1v15Sha256,
        b"security-rs",
    )?;
    let certificate = Certificate::from_pem(&support::fixture("test-cert.pem"))?;
    let verified = certificate.public_key()?.verify_signature(
        SignatureAlgorithm::RsaSignatureMessagePkcs1v15Sha256,
        b"security-rs",
        &signature,
    )?;
    println!("signature_len={} verified={verified}", signature.len());
    Ok(())
}
