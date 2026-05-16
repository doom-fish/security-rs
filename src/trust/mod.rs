//! `SecPolicy` and `SecTrust` wrappers.

use apple_cf::CFError;

use crate::certificate::Certificate;
use crate::error::{Result, SecurityError};
use crate::ffi;
use crate::private::{cf_array, cf_error_description, cf_string, sec_error_message, OwnedCf};

/// Owned `SecPolicyRef` used to evaluate a certificate chain.
pub struct Policy {
    raw: ffi::SecPolicyRef,
}

impl Policy {
    /// Create Apple's default X.509 trust policy.
    ///
    /// # Errors
    ///
    /// Returns an error if Security.framework cannot allocate the policy object.
    pub fn basic_x509() -> Result<Self> {
        let raw = unsafe { ffi::SecPolicyCreateBasicX509() };
        if raw.is_null() {
            return Err(SecurityError::CoreFoundation(CFError::new(
                "SecPolicyCreateBasicX509",
            )));
        }
        Ok(Self { raw })
    }

    /// Create an SSL policy.
    ///
    /// # Errors
    ///
    /// Returns an error if the hostname contains NUL bytes or Security.framework cannot allocate the policy object.
    pub fn ssl(server: bool, hostname: Option<&str>) -> Result<Self> {
        let hostname = hostname.map(cf_string).transpose()?;
        let raw = unsafe {
            ffi::SecPolicyCreateSSL(
                u8::from(server),
                hostname
                    .as_ref()
                    .map_or(std::ptr::null(), OwnedCf::as_string),
            )
        };
        if raw.is_null() {
            return Err(SecurityError::CoreFoundation(CFError::new(
                "SecPolicyCreateSSL",
            )));
        }
        Ok(Self { raw })
    }

    /// Borrow the raw `SecPolicyRef`.
    #[must_use]
    pub const fn as_raw(&self) -> ffi::SecPolicyRef {
        self.raw
    }
}

impl Drop for Policy {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            unsafe { ffi::CFRelease(self.raw.cast()) };
        }
    }
}

impl core::fmt::Debug for Policy {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Policy").field("raw", &self.raw).finish()
    }
}

/// Owned `SecTrustRef` created from a certificate and one or more policies.
pub struct Trust {
    raw: ffi::SecTrustRef,
}

impl Trust {
    /// Create a trust object from one certificate and one or more policies.
    ///
    /// # Errors
    ///
    /// Returns an error if no policies were supplied or Security.framework rejects the inputs.
    pub fn new(certificate: &Certificate, policies: &[Policy]) -> Result<Self> {
        if policies.is_empty() {
            return Err(SecurityError::InvalidArgument(
                "at least one trust policy is required".to_owned(),
            ));
        }

        let policy_input = policy_input(policies)?;
        let mut trust = std::ptr::null();
        let status = unsafe {
            ffi::SecTrustCreateWithCertificates(
                certificate.as_raw().cast(),
                policy_input.raw,
                &mut trust,
            )
        };
        if status != ffi::status::SUCCESS {
            return Err(SecurityError::from_status(
                "SecTrustCreateWithCertificates",
                status,
                sec_error_message(status),
            ));
        }
        if trust.is_null() {
            return Err(SecurityError::CoreFoundation(CFError::new(
                "SecTrustCreateWithCertificates",
            )));
        }
        Ok(Self { raw: trust })
    }

    /// Replace the policies used by this trust object.
    ///
    /// # Errors
    ///
    /// Returns an error if no policies were supplied or Security.framework rejects the update.
    pub fn set_policies(&mut self, policies: &[Policy]) -> Result<()> {
        if policies.is_empty() {
            return Err(SecurityError::InvalidArgument(
                "at least one trust policy is required".to_owned(),
            ));
        }
        let policy_input = policy_input(policies)?;
        let status = unsafe { ffi::SecTrustSetPolicies(self.raw, policy_input.raw) };
        if status == ffi::status::SUCCESS {
            Ok(())
        } else {
            Err(SecurityError::from_status(
                "SecTrustSetPolicies",
                status,
                sec_error_message(status),
            ))
        }
    }

    /// Evaluate the trust object.
    ///
    /// # Errors
    ///
    /// Returns `SecurityError::TrustEvaluationFailed` when the certificate chain does not satisfy the configured policies.
    pub fn evaluate(&self) -> Result<()> {
        let mut error = std::ptr::null();
        let ok = unsafe { ffi::SecTrustEvaluateWithError(self.raw, &mut error) };
        if ok != 0 {
            Ok(())
        } else {
            Err(SecurityError::TrustEvaluationFailed(cf_error_description(
                error,
            )))
        }
    }

    /// Borrow the raw `SecTrustRef`.
    #[must_use]
    pub const fn as_raw(&self) -> ffi::SecTrustRef {
        self.raw
    }
}

impl Drop for Trust {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            unsafe { ffi::CFRelease(self.raw.cast()) };
        }
    }
}

impl core::fmt::Debug for Trust {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Trust").field("raw", &self.raw).finish()
    }
}

struct PolicyInput {
    raw: ffi::CFTypeRef,
    _array: Option<OwnedCf>,
}

fn policy_input(policies: &[Policy]) -> Result<PolicyInput> {
    if policies.len() == 1 {
        return Ok(PolicyInput {
            raw: policies[0].as_raw().cast(),
            _array: None,
        });
    }

    let policy_refs = policies
        .iter()
        .map(|policy| policy.as_raw().cast())
        .collect::<Vec<_>>();
    let array = cf_array(&policy_refs)?;
    Ok(PolicyInput {
        raw: array.as_ptr(),
        _array: Some(array),
    })
}
