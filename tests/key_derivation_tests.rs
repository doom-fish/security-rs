use security::KeyDerivation;

const PBKDF2_SHA256_PASSWORD_SALT_4096_32: [u8; 32] = [
    0xc5, 0xe4, 0x78, 0xd5, 0x92, 0x88, 0xc8, 0x41, 0xaa, 0x53, 0x0d, 0xb6, 0x84, 0x5c, 0x4c, 0x8d,
    0x96, 0x28, 0x93, 0xa0, 0x01, 0xce, 0x4e, 0x11, 0xa4, 0x96, 0x38, 0x73, 0xaa, 0x98, 0x13, 0x4a,
];

#[test]
fn derives_symmetric_key() -> security::Result<()> {
    let key = KeyDerivation::derive_pbkdf2_sha256("password", b"salty-salt", 1_000, 256)?;
    assert!(!key.attributes()?.as_object().unwrap().is_empty());
    let bytes = key.to_bytes()?;
    assert_eq!(bytes.len(), 32);
    assert_eq!(format!("{bytes:?}"), "SecretBytes(<redacted>)");
    Ok(())
}

#[test]
fn derived_key_bytes_match_the_pbkdf2_test_vector() -> security::Result<()> {
    let key = KeyDerivation::derive_pbkdf2_sha256("password", b"salt", 4_096, 256)?;
    assert_eq!(
        key.to_bytes()?.as_bytes(),
        PBKDF2_SHA256_PASSWORD_SALT_4096_32
    );
    Ok(())
}
