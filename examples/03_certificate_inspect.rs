#[path = "support/mod.rs"]
mod support;

use security::Certificate;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let certificate = Certificate::from_der(&support::fixture("test-cert.der"))?;
    println!(
        "subject={:?} emails={:?} serial_len={}",
        certificate.subject_summary()?,
        certificate.email_addresses()?,
        certificate.serial_number()?.len()
    );
    Ok(())
}
