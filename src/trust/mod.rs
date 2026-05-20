use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bitflags::bitflags;
use serde_json::Value;

use crate::bridge;
use crate::certificate::{Certificate, PublicKey};
use crate::error::{Result, SecurityError};
pub use crate::policy::Policy;

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    /// Mirrors `SecTrustOptionFlags`.
    pub struct TrustOptions: u32 {
        /// Mirrors a `SecTrustOptionFlags` bit.
        const ALLOW_EXPIRED = 0x0000_0001;
        /// Mirrors a `SecTrustOptionFlags` bit.
        const LEAF_IS_CA = 0x0000_0002;
        /// Mirrors a `SecTrustOptionFlags` bit.
        const FETCH_ISSUER_FROM_NET = 0x0000_0004;
        /// Mirrors a `SecTrustOptionFlags` bit.
        const ALLOW_EXPIRED_ROOT = 0x0000_0008;
        /// Mirrors a `SecTrustOptionFlags` bit.
        const REQUIRE_REVOCATION_PER_CERT = 0x0000_0010;
        /// Mirrors a `SecTrustOptionFlags` bit.
        const USE_TRUST_SETTINGS = 0x0000_0020;
        /// Mirrors a `SecTrustOptionFlags` bit.
        const IMPLICIT_ANCHORS = 0x0000_0040;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
/// Mirrors `SecTrustResultType`.
pub enum TrustResultType {
    /// Mirrors a `SecTrustResultType` constant.
    Invalid = 0,
    /// Mirrors a `SecTrustResultType` constant.
    Proceed = 1,
    /// Mirrors a `SecTrustResultType` constant.
    Confirm = 2,
    /// Mirrors a `SecTrustResultType` constant.
    Deny = 3,
    /// Mirrors a `SecTrustResultType` constant.
    Unspecified = 4,
    /// Mirrors a `SecTrustResultType` constant.
    RecoverableTrustFailure = 5,
    /// Mirrors a `SecTrustResultType` constant.
    FatalTrustFailure = 6,
    /// Mirrors a `SecTrustResultType` constant.
    OtherError = 7,
}

impl TrustResultType {
    fn from_raw(raw: u32) -> Result<Self> {
        match raw {
            0 => Ok(Self::Invalid),
            1 => Ok(Self::Proceed),
            2 => Ok(Self::Confirm),
            3 => Ok(Self::Deny),
            4 => Ok(Self::Unspecified),
            5 => Ok(Self::RecoverableTrustFailure),
            6 => Ok(Self::FatalTrustFailure),
            7 => Ok(Self::OtherError),
            _ => Err(SecurityError::InvalidArgument(format!(
                "unexpected trust result type: {raw}"
            ))),
        }
    }
}

#[derive(Debug)]
/// Wraps `SecTrustRef`.
pub struct Trust {
    handle: bridge::Handle,
}

impl Trust {
    /// Wraps the corresponding `SecTrustRef` operation.
    pub fn type_id() -> usize {
        unsafe { bridge::security_trust_get_type_id() }
    }

    /// Wraps the corresponding `SecTrustRef` operation.
    pub fn new(certificate: &Certificate, policies: &[Policy]) -> Result<Self> {
        Self::from_certificates(std::slice::from_ref(certificate), policies)
    }

    /// Wraps the corresponding `SecTrustRef` operation.
    pub fn from_certificates(certificates: &[Certificate], policies: &[Policy]) -> Result<Self> {
        let certificate_handles = certificates
            .iter()
            .map(Certificate::handle)
            .collect::<Vec<_>>();
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
        bridge::required_handle("security_trust_create", raw, status, error)
            .map(|handle| Self { handle })
    }

    /// Wraps the corresponding `SecTrustRef` operation.
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

    /// Wraps the corresponding `SecTrustRef` operation.
    pub fn policies(&self) -> Result<Value> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_trust_copy_policies(self.handle.as_ptr(), &mut status, &mut error)
        };
        bridge::required_json("security_trust_copy_policies", raw, status, error)
    }

    /// Wraps the corresponding `SecTrustRef` operation.
    pub fn set_anchor_certificates(&mut self, certificates: &[Certificate]) -> Result<()> {
        let certificate_handles = certificates
            .iter()
            .map(Certificate::handle)
            .collect::<Vec<_>>();
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

    /// Wraps the corresponding `SecTrustRef` operation.
    pub fn custom_anchor_certificates(&self) -> Result<Value> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_trust_copy_custom_anchor_certificates(
                self.handle.as_ptr(),
                &mut status,
                &mut error,
            )
        };
        bridge::required_json(
            "security_trust_copy_custom_anchor_certificates",
            raw,
            status,
            error,
        )
    }

    /// Wraps the corresponding `SecTrustRef` operation.
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

    /// Wraps the corresponding `SecTrustRef` operation.
    pub fn set_network_fetch_allowed(&mut self, allowed: bool) -> Result<()> {
        let mut error = std::ptr::null_mut();
        let status = unsafe {
            bridge::security_trust_set_network_fetch_allowed(
                self.handle.as_ptr(),
                allowed,
                &mut error,
            )
        };
        bridge::status_result("security_trust_set_network_fetch_allowed", status, error)
    }

    /// Wraps the corresponding `SecTrustRef` operation.
    pub fn network_fetch_allowed(&self) -> Result<bool> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let allowed = unsafe {
            bridge::security_trust_get_network_fetch_allowed(
                self.handle.as_ptr(),
                &mut status,
                &mut error,
            )
        };
        if status != 0 {
            return Err(bridge::status_error(
                "security_trust_get_network_fetch_allowed",
                status,
                error,
            )?);
        }
        Ok(allowed)
    }

    /// Wraps the corresponding `SecTrustRef` operation.
    pub fn set_verify_date(&mut self, verify_date: SystemTime) -> Result<()> {
        let mut error = std::ptr::null_mut();
        let status = unsafe {
            bridge::security_trust_set_verify_date(
                self.handle.as_ptr(),
                system_time_to_unix(verify_date),
                &mut error,
            )
        };
        bridge::status_result("security_trust_set_verify_date", status, error)
    }

    /// Wraps the corresponding `SecTrustRef` operation.
    pub fn verify_time(&self) -> Result<Option<SystemTime>> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_trust_get_verify_time(self.handle.as_ptr(), &mut status, &mut error)
        };
        if status != 0 {
            return Err(bridge::status_error(
                "security_trust_get_verify_time",
                status,
                error,
            )?);
        }
        bridge::optional_json::<Value>(raw)?
            .map_or(Ok(None), |value| decode_trust_date(value).map(Some))
    }

    /// Wraps the corresponding `SecTrustRef` operation.
    pub fn evaluate(&self) -> Result<()> {
        let mut error = std::ptr::null_mut();
        let trusted = unsafe { bridge::security_trust_evaluate(self.handle.as_ptr(), &mut error) };
        if trusted {
            Ok(())
        } else {
            let message = bridge::optional_string(error)?
                .unwrap_or_else(|| "trust evaluation failed".to_owned());
            Err(SecurityError::TrustEvaluationFailed(message))
        }
    }

    /// Wraps the corresponding `SecTrustRef` operation.
    pub fn evaluate_async(&self) -> Result<()> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let trusted = unsafe {
            bridge::security_trust_evaluate_async(self.handle.as_ptr(), &mut status, &mut error)
        };
        if status != 0 {
            return Err(bridge::status_error(
                "security_trust_evaluate_async",
                status,
                error,
            )?);
        }
        if trusted {
            Ok(())
        } else {
            let message = bridge::optional_string(error)?
                .unwrap_or_else(|| "trust evaluation failed".to_owned());
            Err(SecurityError::TrustEvaluationFailed(message))
        }
    }

    /// Wraps the corresponding `SecTrustRef` operation.
    pub fn trust_result_type(&self) -> Result<TrustResultType> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_trust_get_trust_result(self.handle.as_ptr(), &mut status, &mut error)
        };
        if status != 0 {
            return Err(bridge::status_error(
                "security_trust_get_trust_result",
                status,
                error,
            )?);
        }
        TrustResultType::from_raw(raw)
    }

    /// Wraps the corresponding `SecTrustRef` operation.
    pub fn result(&self) -> Result<Value> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_trust_copy_result(self.handle.as_ptr(), &mut status, &mut error)
        };
        bridge::required_json("security_trust_copy_result", raw, status, error)
    }

    /// Wraps the corresponding `SecTrustRef` operation.
    pub fn key(&self) -> Result<Option<PublicKey>> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_trust_copy_key(self.handle.as_ptr(), &mut status, &mut error)
        };
        if status != 0 {
            return Err(bridge::status_error(
                "security_trust_copy_key",
                status,
                error,
            )?);
        }
        Ok(bridge::Handle::from_raw(raw).map(PublicKey::from_handle))
    }

    /// Wraps the corresponding `SecTrustRef` operation.
    pub fn certificate_count(&self) -> usize {
        usize::try_from(unsafe {
            bridge::security_trust_get_certificate_count(self.handle.as_ptr())
        })
        .unwrap_or_default()
    }

    /// Wraps the corresponding `SecTrustRef` operation.
    pub fn certificate_chain(&self) -> Result<Vec<Certificate>> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_trust_copy_certificate_chain(
                self.handle.as_ptr(),
                &mut status,
                &mut error,
            )
        };
        let array_handle =
            bridge::required_handle("security_trust_copy_certificate_chain", raw, status, error)?;
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

    /// Wraps the corresponding `SecTrustRef` operation.
    pub fn exceptions(&self) -> Result<Option<Vec<u8>>> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_trust_copy_exceptions(self.handle.as_ptr(), &mut status, &mut error)
        };
        if status != 0 {
            return Err(bridge::status_error(
                "security_trust_copy_exceptions",
                status,
                error,
            )?);
        }
        bridge::optional_data(raw)
    }

    /// Wraps the corresponding `SecTrustRef` operation.
    pub fn set_exceptions(&mut self, exceptions: Option<&[u8]>) -> Result<bool> {
        let mut error = std::ptr::null_mut();
        let accepted = unsafe {
            bridge::security_trust_set_exceptions(
                self.handle.as_ptr(),
                exceptions.map_or(std::ptr::null(), |value| value.as_ptr().cast()),
                exceptions.map_or(Ok(0), |value| bridge::len_to_isize(value.len()))?,
                &mut error,
            )
        };
        if !error.is_null() {
            return Err(bridge::status_error(
                "security_trust_set_exceptions",
                -1,
                error,
            )?);
        }
        Ok(accepted)
    }

    /// Wraps the corresponding `SecTrustRef` operation.
    pub fn set_ocsp_responses(&mut self, responses: &[Vec<u8>]) -> Result<()> {
        let responses = bridge::json_cstring(&responses)?;
        let mut error = std::ptr::null_mut();
        let status = unsafe {
            bridge::security_trust_set_ocsp_response(
                self.handle.as_ptr(),
                responses.as_ptr(),
                &mut error,
            )
        };
        bridge::status_result("security_trust_set_ocsp_response", status, error)
    }

    /// Wraps the corresponding `SecTrustRef` operation.
    pub fn set_signed_certificate_timestamps(&mut self, timestamps: &[Vec<u8>]) -> Result<()> {
        let timestamps = bridge::json_cstring(&timestamps)?;
        let mut error = std::ptr::null_mut();
        let status = unsafe {
            bridge::security_trust_set_signed_certificate_timestamps(
                self.handle.as_ptr(),
                timestamps.as_ptr(),
                &mut error,
            )
        };
        bridge::status_result(
            "security_trust_set_signed_certificate_timestamps",
            status,
            error,
        )
    }

    /// Wraps the corresponding `SecTrustRef` operation.
    pub fn set_options(&mut self, options: TrustOptions) -> Result<()> {
        let mut error = std::ptr::null_mut();
        let status = unsafe {
            bridge::security_trust_set_options(self.handle.as_ptr(), options.bits(), &mut error)
        };
        bridge::status_result("security_trust_set_options", status, error)
    }

    /// Wraps the corresponding `SecTrustRef` operation.
    pub fn system_anchor_certificates() -> Result<Value> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw =
            unsafe { bridge::security_trust_copy_anchor_certificates(&mut status, &mut error) };
        bridge::required_json(
            "security_trust_copy_anchor_certificates",
            raw,
            status,
            error,
        )
    }
}

fn decode_trust_date(value: Value) -> Result<SystemTime> {
    let unix =
        value
            .get("unix")
            .and_then(Value::as_f64)
            .ok_or_else(|| SecurityError::UnexpectedType {
                operation: "security_trust_get_verify_time",
                expected: "date JSON object",
            })?;
    let duration = Duration::from_secs_f64(unix.abs());
    if unix >= 0.0 {
        Ok(UNIX_EPOCH + duration)
    } else {
        UNIX_EPOCH.checked_sub(duration).ok_or_else(|| {
            SecurityError::InvalidArgument(
                "trust verify time preceded UNIX_EPOCH by too much".to_owned(),
            )
        })
    }
}

fn system_time_to_unix(time: SystemTime) -> f64 {
    match time.duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_secs_f64(),
        Err(error) => -error.duration().as_secs_f64(),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn trust_result_type_from_raw_maps_known_values() {
        assert_eq!(
            TrustResultType::from_raw(0).unwrap(),
            TrustResultType::Invalid
        );
        assert_eq!(
            TrustResultType::from_raw(7).unwrap(),
            TrustResultType::OtherError
        );
    }

    #[test]
    fn trust_result_type_from_raw_rejects_unknown_values() {
        assert_eq!(
            TrustResultType::from_raw(99).unwrap_err(),
            SecurityError::InvalidArgument("unexpected trust result type: 99".to_owned())
        );
    }

    #[test]
    fn system_time_to_unix_preserves_times_after_epoch() {
        let time = UNIX_EPOCH + Duration::from_secs_f64(42.5);

        assert!((system_time_to_unix(time) - 42.5).abs() < f64::EPSILON);
    }

    #[test]
    fn system_time_to_unix_preserves_times_before_epoch() {
        let time = UNIX_EPOCH - Duration::from_secs_f64(12.5);

        assert!((system_time_to_unix(time) + 12.5).abs() < f64::EPSILON);
    }

    #[test]
    fn decode_trust_date_parses_positive_unix_seconds() {
        let time = decode_trust_date(json!({ "unix": 42.5 })).unwrap();

        assert_eq!(time, UNIX_EPOCH + Duration::from_secs_f64(42.5));
    }

    #[test]
    fn decode_trust_date_parses_negative_unix_seconds() {
        let time = decode_trust_date(json!({ "unix": -12.5 })).unwrap();

        assert_eq!(time, UNIX_EPOCH - Duration::from_secs_f64(12.5));
    }

    #[test]
    fn decode_trust_date_requires_unix_field() {
        assert!(matches!(
            decode_trust_date(json!({ "seconds": 1 })).unwrap_err(),
            SecurityError::UnexpectedType {
                operation: "security_trust_get_verify_time",
                expected: "date JSON object",
            }
        ));
    }
}
