#[path = "support/mod.rs"]
mod support;

use security::{Certificate, ExternalFormat, ExternalItemType};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let certificate = Certificate::import_item(
        &support::fixture("test-cert.pem"),
        Some(".pem"),
        ExternalFormat::Unknown,
        ExternalItemType::Certificate,
    )?;
    let exported_pem = certificate.export_item(ExternalFormat::X509Certificate, true)?;
    println!(
        "subject={:?} emails={:?} serial_len={} exported_pem_len={}",
        certificate.subject_summary()?,
        certificate.email_addresses()?,
        certificate.serial_number()?.len(),
        exported_pem.len()
    );
    Ok(())
}
