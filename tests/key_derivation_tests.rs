use security::KeyDerivation;

#[test]
fn derives_symmetric_key() -> security::Result<()> {
    let key = KeyDerivation::derive_pbkdf2_sha256("password", b"salty-salt", 1_000, 256)?;
    assert!(!key.attributes()?.as_object().unwrap().is_empty());
    Ok(())
}
