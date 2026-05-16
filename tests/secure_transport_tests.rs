use security::{ProtocolVersion, SecureTransportContext};

#[test]
fn creates_and_configures_context() -> security::Result<()> {
    let mut context = SecureTransportContext::client()?;
    context.set_protocol_min(ProtocolVersion::Tls1_2)?;
    context.set_protocol_max(ProtocolVersion::Tls1_2)?;
    let state = context.state()?;
    assert_eq!(state.side, "client");
    assert_eq!(state.session_state, "idle");
    Ok(())
}
