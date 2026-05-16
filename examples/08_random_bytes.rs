use security::SecureRandom;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bytes = SecureRandom::bytes(16)?;
    println!("random_len={} first_byte={}", bytes.len(), bytes[0]);
    Ok(())
}
