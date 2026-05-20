#[path = "support/mod.rs"]
mod support;

#[cfg(feature = "async")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use security::async_api::AsyncTrust;
    use security::{Certificate, Policy, Trust};

    pollster::block_on(async {
        let certificate = Certificate::from_der(&support::fixture("test-cert.der"))?;
        let policy = Policy::basic_x509()?;
        let mut trust = Trust::new(&certificate, &[policy])?;
        trust.set_anchor_certificates(&[certificate])?;
        trust.set_anchor_certificates_only(true)?;
        trust.set_network_fetch_allowed(false)?;

        AsyncTrust::new(&trust).evaluate()?.await?;
        println!("chain_len={}", trust.certificate_chain()?.len());
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}

#[cfg(not(feature = "async"))]
fn main() {}
