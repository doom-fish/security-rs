use security::AgreementPrivateKey;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let alice = AgreementPrivateKey::generate_p256()?;
    let bob = AgreementPrivateKey::generate_p256()?;
    let alice_public = alice.public_key()?;
    let bob_public = bob.public_key()?;
    let alice_secret = alice.shared_secret(&bob_public, 32, b"shared-info")?;
    let bob_secret = bob.shared_secret(&alice_public, 32, b"shared-info")?;
    println!("shared_secret_match={}", alice_secret == bob_secret);
    Ok(())
}
