use serde_json::Value;

use crate::bridge;
use crate::certificate::Certificate;
use crate::error::Result;
use crate::key::PrivateKey;

#[derive(Debug)]
pub struct Identity {
    handle: bridge::Handle,
}

impl Identity {
    pub(crate) fn from_handle(handle: bridge::Handle) -> Self {
        Self { handle }
    }

    pub(crate) fn handle(&self) -> &bridge::Handle {
        &self.handle
    }

    pub fn type_id() -> usize {
        unsafe { bridge::security_identity_get_type_id() }
    }

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
            .map(Self::from_handle)
    }

    pub fn from_certificate_and_private_key(
        certificate: &Certificate,
        private_key: &PrivateKey,
    ) -> Result<Self> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_identity_create(
                certificate.handle().as_ptr(),
                private_key.handle().as_ptr(),
                &mut status,
                &mut error,
            )
        };
        bridge::required_handle("security_identity_create", raw, status, error).map(Self::from_handle)
    }

    pub fn with_certificate(certificate: &Certificate) -> Result<Self> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_identity_create_with_certificate(
                certificate.handle().as_ptr(),
                &mut status,
                &mut error,
            )
        };
        bridge::required_handle("security_identity_create_with_certificate", raw, status, error)
            .map(Self::from_handle)
    }

    pub fn preferred(
        name: &str,
        key_usage: &[&str],
        valid_issuers: &[Vec<u8>],
    ) -> Result<Option<Self>> {
        let name = bridge::cstring(name)?;
        let key_usage = (!key_usage.is_empty())
            .then(|| bridge::json_cstring(&key_usage))
            .transpose()?;
        let valid_issuers = (!valid_issuers.is_empty())
            .then(|| bridge::json_cstring(&valid_issuers))
            .transpose()?;
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_identity_copy_preferred(
                name.as_ptr(),
                key_usage.as_ref().map_or(std::ptr::null(), |value| value.as_ptr()),
                valid_issuers
                    .as_ref()
                    .map_or(std::ptr::null(), |value| value.as_ptr()),
                &mut status,
                &mut error,
            )
        };
        if raw.is_null() && status == 0 {
            Ok(None)
        } else {
            bridge::required_handle("security_identity_copy_preferred", raw, status, error)
                .map(Self::from_handle)
                .map(Some)
        }
    }

    pub fn set_preferred(
        identity: Option<&Self>,
        name: &str,
        key_usage: &[&str],
    ) -> Result<()> {
        let name = bridge::cstring(name)?;
        let key_usage = (!key_usage.is_empty())
            .then(|| bridge::json_cstring(&key_usage))
            .transpose()?;
        let mut error = std::ptr::null_mut();
        let status = unsafe {
            bridge::security_identity_set_preferred(
                identity.map_or(std::ptr::null_mut(), |value| value.handle.as_ptr()),
                name.as_ptr(),
                key_usage.as_ref().map_or(std::ptr::null(), |value| value.as_ptr()),
                &mut error,
            )
        };
        bridge::status_result("security_identity_set_preferred", status, error)
    }

    pub fn copy_system_identity(domain: &str) -> Result<Self> {
        let domain = bridge::cstring(domain)?;
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_identity_copy_system_identity(
                domain.as_ptr(),
                &mut status,
                &mut error,
            )
        };
        bridge::required_handle("security_identity_copy_system_identity", raw, status, error)
            .map(Self::from_handle)
    }

    pub fn set_system_identity(domain: &str, identity: Option<&Self>) -> Result<()> {
        let domain = bridge::cstring(domain)?;
        let mut error = std::ptr::null_mut();
        let status = unsafe {
            bridge::security_identity_set_system_identity(
                domain.as_ptr(),
                identity.map_or(std::ptr::null_mut(), |value| value.handle.as_ptr()),
                &mut error,
            )
        };
        bridge::status_result("security_identity_set_system_identity", status, error)
    }

    pub fn actual_domain(&self) -> Result<Option<String>> {
        let raw = unsafe { bridge::security_identity_copy_actual_domain(self.handle.as_ptr()) };
        bridge::optional_string(raw)
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
