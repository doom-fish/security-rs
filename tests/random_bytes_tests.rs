use security::SecureRandom;

#[test]
fn generates_random_bytes() -> security::Result<()> {
    let bytes = SecureRandom::bytes(32)?;
    assert_eq!(bytes.len(), 32);
    assert!(bytes.iter().any(|byte| *byte != 0));
    Ok(())
}
