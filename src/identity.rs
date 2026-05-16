use serde_json::Value;

use crate::bridge;
use crate::certificate::Certificate;
use crate::error::Result;

#[derive(Debug)]
pub struct Identity {
    handle: bridge::Handle,
}

impl Identity {
    pub fn import_pkcs12_first(data: &[u8], password: &str) -> Result<Self> {
        let password = bridge::cstring(password)?;
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_identity_import_pkcs12_first(
                data.as_ptr().cast(),
                bridge::len_to_isize(data.len())?,
                password.as_ptr(),
                &mut status,
                &mut error,
            )
        };
        bridge::required_handle("security_identity_import_pkcs12_first", raw, status, error)
            .map(|handle| Self { handle })
    }

    pub fn label(&self) -> Result<Option<String>> {
        let raw = unsafe { bridge::security_identity_copy_label(self.handle.as_ptr()) };
        bridge::optional_string(raw)
    }

    pub fn chain_count(&self) -> usize {
        usize::try_from(unsafe { bridge::security_identity_get_chain_count(self.handle.as_ptr()) })
            .unwrap_or_default()
    }

    pub fn certificate(&self) -> Result<Certificate> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_identity_copy_certificate(self.handle.as_ptr(), &mut status, &mut error)
        };
        bridge::required_handle("security_identity_copy_certificate", raw, status, error)
            .map(Certificate::from_handle)
    }

    pub fn private_key_attributes(&self) -> Result<Value> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_identity_copy_private_key_attributes(
                self.handle.as_ptr(),
                &mut status,
                &mut error,
            )
        };
        bridge::required_json("security_identity_copy_private_key_attributes", raw, status, error)
    }
}
