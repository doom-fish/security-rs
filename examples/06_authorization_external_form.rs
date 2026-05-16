use security::Authorization;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let authorization = Authorization::new()?;
    let external = authorization.external_form()?;
    let _round_trip = Authorization::from_external_form(&external)?;
    println!("external_form_len={}", external.len());
    Ok(())
}
