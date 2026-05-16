use security::Transform;

#[test]
fn base64_round_trip() -> security::Result<()> {
    let encoded = Transform::encode_base64(b"hello")?;
    assert_eq!(encoded, "aGVsbG8=");
    assert_eq!(Transform::decode_base64(encoded.as_bytes())?, b"hello");
    Ok(())
}
