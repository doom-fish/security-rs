use serde_json::Value;

use crate::bridge;
use crate::certificate::Certificate;
use crate::error::{Result, SecurityError};
pub use crate::policy::Policy;

#[derive(Debug)]
pub struct Trust {
    handle: bridge::Handle,
}

impl Trust {
    pub fn new(certificate: &Certificate, policies: &[Policy]) -> Result<Self> {
        Self::from_certificates(std::slice::from_ref(certificate), policies)
    }

    pub fn from_certificates(certificates: &[Certificate], policies: &[Policy]) -> Result<Self> {
        let certificate_handles = certificates.iter().map(Certificate::handle).collect::<Vec<_>>();
        let policy_handles = policies.iter().map(Policy::handle).collect::<Vec<_>>();
        let certificate_pointers = bridge::handle_pointer_array(&certificate_handles);
        let policy_pointers = bridge::handle_pointer_array(&policy_handles);
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_trust_create(
                certificate_pointers.as_ptr(),
                bridge::len_to_isize(certificate_pointers.len())?,
                policy_pointers.as_ptr(),
                bridge::len_to_isize(policy_pointers.len())?,
                &mut status,
                &mut error,
            )
        };
        bridge::required_handle("security_trust_create", raw, status, error).map(|handle| Self {
            handle,
        })
    }

    pub fn set_policies(&mut self, policies: &[Policy]) -> Result<()> {
        let policy_handles = policies.iter().map(Policy::handle).collect::<Vec<_>>();
        let pointers = bridge::handle_pointer_array(&policy_handles);
        let mut error = std::ptr::null_mut();
        let status = unsafe {
            bridge::security_trust_set_policies(
                self.handle.as_ptr(),
                pointers.as_ptr(),
                bridge::len_to_isize(pointers.len())?,
                &mut error,
            )
        };
        bridge::status_result("security_trust_set_policies", status, error)
    }

    pub fn set_anchor_certificates(&mut self, certificates: &[Certificate]) -> Result<()> {
        let certificate_handles = certificates.iter().map(Certificate::handle).collect::<Vec<_>>();
        let pointers = bridge::handle_pointer_array(&certificate_handles);
        let mut error = std::ptr::null_mut();
        let status = unsafe {
            bridge::security_trust_set_anchor_certificates(
                self.handle.as_ptr(),
                pointers.as_ptr(),
                bridge::len_to_isize(pointers.len())?,
                &mut error,
            )
        };
        bridge::status_result("security_trust_set_anchor_certificates", status, error)
    }

    pub fn set_anchor_certificates_only(&mut self, only_anchor_certificates: bool) -> Result<()> {
        let mut error = std::ptr::null_mut();
        let status = unsafe {
            bridge::security_trust_set_anchor_certificates_only(
                self.handle.as_ptr(),
                only_anchor_certificates,
                &mut error,
            )
        };
        bridge::status_result("security_trust_set_anchor_certificates_only", status, error)
    }

    pub fn set_network_fetch_allowed(&mut self, allowed: bool) -> Result<()> {
        let mut error = std::ptr::null_mut();
        let status = unsafe {
            bridge::security_trust_set_network_fetch_allowed(self.handle.as_ptr(), allowed, &mut error)
        };
        bridge::status_result("security_trust_set_network_fetch_allowed", status, error)
    }

    pub fn evaluate(&self) -> Result<()> {
        let mut error = std::ptr::null_mut();
        let trusted = unsafe { bridge::security_trust_evaluate(self.handle.as_ptr(), &mut error) };
        if trusted {
            Ok(())
        } else {
            let message = bridge::optional_string(error)?.unwrap_or_else(|| "trust evaluation failed".to_owned());
            Err(SecurityError::TrustEvaluationFailed(message))
        }
    }

    pub fn result(&self) -> Result<Value> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe { bridge::security_trust_copy_result(self.handle.as_ptr(), &mut status, &mut error) };
        bridge::required_json("security_trust_copy_result", raw, status, error)
    }

    pub fn certificate_chain(&self) -> Result<Vec<Certificate>> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_trust_copy_certificate_chain(self.handle.as_ptr(), &mut status, &mut error)
        };
        let array_handle = bridge::required_handle(
            "security_trust_copy_certificate_chain",
            raw,
            status,
            error,
        )?;
        let count = usize::try_from(unsafe {
            bridge::security_certificate_array_get_count(array_handle.as_ptr())
        })
        .unwrap_or_default();
        let mut certificates = Vec::with_capacity(count);
        for index in 0..count {
            let mut status = 0;
            let mut error = std::ptr::null_mut();
            let raw = unsafe {
                bridge::security_certificate_array_copy_item(
                    array_handle.as_ptr(),
                    bridge::len_to_isize(index)?,
                    &mut status,
                    &mut error,
                )
            };
            let handle = bridge::required_handle(
                "security_certificate_array_copy_item",
                raw,
                status,
                error,
            )?;
            certificates.push(Certificate::from_handle(handle));
        }
        Ok(certificates)
    }
}
