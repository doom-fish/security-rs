use security::KeyDerivation;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key = KeyDerivation::derive_pbkdf2_sha256("password", b"salty-salt", 1_000, 256)?;
    let attributes = key.attributes()?;
    println!("derived_key_attrs={attributes:?}");
    Ok(())
}
