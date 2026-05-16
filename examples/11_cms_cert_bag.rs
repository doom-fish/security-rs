#[path = "support/mod.rs"]
mod support;

use security::{Certificate, Cms};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let certificate = Certificate::from_der(&support::fixture("test-cert.der"))?;
    let encoded = Cms::encode_supporting_certificates(&[certificate])?;
    let decoded = Cms::decode_all_certificates(&encoded)?;
    println!("cms_len={} certs={}", encoded.len(), decoded.len());
    Ok(())
}
