use security::AgreementPrivateKey;

#[test]
fn computes_matching_shared_secret() -> security::Result<()> {
    let alice = AgreementPrivateKey::generate_p256()?;
    let bob = AgreementPrivateKey::generate_p256()?;
    assert!(alice.is_supported());
    assert!(bob.is_supported());
    let alice_public = alice.public_key()?;
    let bob_public = bob.public_key()?;
    let alice_secret = alice.shared_secret(&bob_public, 32, b"shared-info")?;
    let bob_secret = bob.shared_secret(&alice_public, 32, b"shared-info")?;
    assert_eq!(alice_secret, bob_secret);
    Ok(())
}
