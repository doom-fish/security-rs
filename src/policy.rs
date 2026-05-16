use serde_json::Value;

use crate::bridge::{self, Handle};
use crate::error::Result;

pub type RevocationFlags = u32;

#[derive(Debug)]
pub struct Policy {
    handle: Handle,
}

impl Policy {
    pub(crate) fn from_handle(handle: Handle) -> Self {
        Self { handle }
    }

    pub(crate) fn handle(&self) -> &Handle {
        &self.handle
    }

    pub fn basic_x509() -> Result<Self> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe { bridge::security_policy_create_basic_x509(&mut status, &mut error) };
        bridge::required_handle("security_policy_create_basic_x509", raw, status, error)
            .map(Self::from_handle)
    }

    pub fn ssl(server: bool, hostname: Option<&str>) -> Result<Self> {
        let hostname = hostname.map(bridge::cstring).transpose()?;
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_policy_create_ssl(
                server,
                hostname
                    .as_ref()
                    .map_or(std::ptr::null(), |value| value.as_c_str().as_ptr()),
                &mut status,
                &mut error,
            )
        };
        bridge::required_handle("security_policy_create_ssl", raw, status, error)
            .map(Self::from_handle)
    }

    pub fn revocation(flags: RevocationFlags) -> Result<Self> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe { bridge::security_policy_create_revocation(flags, &mut status, &mut error) };
        bridge::required_handle("security_policy_create_revocation", raw, status, error)
            .map(Self::from_handle)
    }

    pub fn properties(&self) -> Result<Value> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_policy_copy_properties(self.handle.as_ptr(), &mut status, &mut error)
        };
        bridge::required_json("security_policy_copy_properties", raw, status, error)
    }
}
