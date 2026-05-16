use security::Transform;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let encoded = Transform::encode_base64(b"hello")?;
    let decoded = Transform::decode_base64(encoded.as_bytes())?;
    println!("encoded={encoded} decoded={}", String::from_utf8(decoded)?);
    Ok(())
}
