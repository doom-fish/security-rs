use security::Policy;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let basic = Policy::basic_x509()?;
    let ssl = Policy::ssl(true, Some("localhost"))?;
    let revocation = Policy::revocation(0)?;
    println!(
        "basic={:?} ssl={:?} revocation={:?}",
        basic.properties()?,
        ssl.properties()?,
        revocation.properties()?
    );
    Ok(())
}
