use serde::Deserialize;

use crate::bridge;
use crate::error::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Mirrors Secure Transport protocol-version selectors.
pub enum ProtocolVersion {
    /// Mirrors a Secure Transport protocol-version constant.
    Ssl2,
    /// Mirrors a Secure Transport protocol-version constant.
    Ssl3,
    /// Mirrors a Secure Transport protocol-version constant.
    Tls1_0,
    /// Mirrors a Secure Transport protocol-version constant.
    Tls1_1,
    /// Mirrors a Secure Transport protocol-version constant.
    Tls1_2,
    /// Mirrors a Secure Transport protocol-version constant.
    Dtls1_0,
    /// Mirrors a Secure Transport protocol-version constant.
    Tls1_3,
}

impl ProtocolVersion {
    /// Mirrors the protocol name used by Secure Transport configuration helpers.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ssl2 => "ssl2",
            Self::Ssl3 => "ssl3",
            Self::Tls1_0 => "tls1.0",
            Self::Tls1_1 => "tls1.1",
            Self::Tls1_2 => "tls1.2",
            Self::Dtls1_0 => "dtls1.0",
            Self::Tls1_3 => "tls1.3",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
/// Mirrors state queried from a Secure Transport session.
pub struct SecureTransportState {
    /// Mirrors a field returned by Secure Transport session queries.
    pub side: String,
    #[serde(rename = "sessionState")]
    /// Mirrors a field returned by Secure Transport session queries.
    pub session_state: String,
    #[serde(rename = "minimumProtocol")]
    /// Mirrors a field returned by Secure Transport session queries.
    pub minimum_protocol: String,
    #[serde(rename = "maximumProtocol")]
    /// Mirrors a field returned by Secure Transport session queries.
    pub maximum_protocol: String,
}

#[derive(Debug)]
/// Wraps a Secure Transport `SSLContextRef`.
pub struct SecureTransportContext {
    handle: bridge::Handle,
}

impl SecureTransportContext {
    /// Wraps the corresponding Secure Transport `SSLContextRef` operation.
    pub fn client() -> Result<Self> {
        create_context(bridge::security_secure_transport_create_client)
    }

    /// Wraps the corresponding Secure Transport `SSLContextRef` operation.
    pub fn server() -> Result<Self> {
        create_context(bridge::security_secure_transport_create_server)
    }

    /// Wraps the corresponding Secure Transport `SSLContextRef` operation.
    pub fn set_protocol_min(&mut self, protocol: ProtocolVersion) -> Result<()> {
        let protocol = bridge::cstring(protocol.as_str())?;
        let mut error = std::ptr::null_mut();
        let status = unsafe {
            bridge::security_secure_transport_set_protocol_min(
                self.handle.as_ptr(),
                protocol.as_ptr(),
                &mut error,
            )
        };
        bridge::status_result("security_secure_transport_set_protocol_min", status, error)
    }

    /// Wraps the corresponding Secure Transport `SSLContextRef` operation.
    pub fn set_protocol_max(&mut self, protocol: ProtocolVersion) -> Result<()> {
        let protocol = bridge::cstring(protocol.as_str())?;
        let mut error = std::ptr::null_mut();
        let status = unsafe {
            bridge::security_secure_transport_set_protocol_max(
                self.handle.as_ptr(),
                protocol.as_ptr(),
                &mut error,
            )
        };
        bridge::status_result("security_secure_transport_set_protocol_max", status, error)
    }

    /// Wraps the corresponding Secure Transport `SSLContextRef` operation.
    pub fn state(&self) -> Result<SecureTransportState> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_secure_transport_copy_state(
                self.handle.as_ptr(),
                &mut status,
                &mut error,
            )
        };
        bridge::required_json("security_secure_transport_copy_state", raw, status, error)
    }
}

fn create_context(
    create: unsafe extern "C" fn(*mut i32, *mut *mut std::ffi::c_void) -> *mut std::ffi::c_void,
) -> Result<SecureTransportContext> {
    let mut status = 0;
    let mut error = std::ptr::null_mut();
    let raw = unsafe { create(&mut status, &mut error) };
    bridge::required_handle("security_secure_transport_create", raw, status, error)
        .map(|handle| SecureTransportContext { handle })
}
