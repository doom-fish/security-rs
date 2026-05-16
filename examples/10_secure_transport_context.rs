use security::{ProtocolVersion, SecureTransportContext};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut context = SecureTransportContext::client()?;
    context.set_protocol_min(ProtocolVersion::Tls1_2)?;
    context.set_protocol_max(ProtocolVersion::Tls1_2)?;
    println!("state={:?}", context.state()?);
    Ok(())
}
