use security::{Policy, PolicyIdentifier, PolicyName, PolicyProperties};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let basic = Policy::basic_x509()?;
    let ssl = Policy::ssl(true, Some("localhost"))?;
    let custom_ssl = Policy::with_properties(
        PolicyIdentifier::AppleSsl,
        &PolicyProperties {
            name: Some(PolicyName::from("localhost")),
            client: Some(false),
            ..PolicyProperties::default()
        },
    )?;
    let revocation = Policy::revocation(0)?;
    println!(
        "basic={:?} ssl={:?} custom_ssl={:?} revocation={:?}",
        basic.properties()?,
        ssl.properties()?,
        custom_ssl.properties()?,
        revocation.properties()?
    );
    Ok(())
}
