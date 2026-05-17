use serde::Deserialize;

use crate::bridge;
use crate::error::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolVersion {
    Ssl2,
    Ssl3,
    Tls1_0,
    Tls1_1,
    Tls1_2,
    Dtls1_0,
    Tls1_3,
}

impl ProtocolVersion {
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
pub struct SecureTransportState {
    pub side: String,
    #[serde(rename = "sessionState")]
    pub session_state: String,
    #[serde(rename = "minimumProtocol")]
    pub minimum_protocol: String,
    #[serde(rename = "maximumProtocol")]
    pub maximum_protocol: String,
}

#[derive(Debug)]
pub struct SecureTransportContext {
    handle: bridge::Handle,
}

impl SecureTransportContext {
    pub fn client() -> Result<Self> {
        create_context(bridge::security_secure_transport_create_client)
    }

    pub fn server() -> Result<Self> {
        create_context(bridge::security_secure_transport_create_server)
    }

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
