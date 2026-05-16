#[path = "support/mod.rs"]
mod support;

use security::{Certificate, Policy, Trust};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let certificate = Certificate::from_der(&support::fixture("test-cert.der"))?;
    let policy = Policy::basic_x509()?;
    let mut trust = Trust::new(&certificate, &[policy])?;
    trust.set_anchor_certificates(&[certificate])?;
    trust.set_anchor_certificates_only(true)?;
    trust.set_network_fetch_allowed(false)?;
    trust.evaluate()?;
    println!("chain_len={}", trust.certificate_chain()?.len());
    Ok(())
}
