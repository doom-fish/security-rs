#[path = "support/mod.rs"]
mod support;

use security::Identity;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let identity = Identity::import_pkcs12_first(&support::fixture("test-identity.p12"), "password")?;
    let certificate = identity.certificate()?;
    println!(
        "label={:?} chain_count={} subject={:?}",
        identity.label()?,
        identity.chain_count(),
        certificate.subject_summary()?
    );
    Ok(())
}
