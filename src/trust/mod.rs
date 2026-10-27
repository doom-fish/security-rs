use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::Value;

use crate::bridge;
use crate::certificate::{Certificate, PublicKey};
use crate::error::{Result, SecurityError};
pub use crate::policy::Policy;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
#[must_use]
/// Mirrors `SecTrustOptionFlags`.
pub struct TrustOptions(u32);

impl TrustOptions {
    /// Mirrors a `SecTrustOptionFlags` bit.
    pub const ALLOW_EXPIRED: Self = Self(0x0000_0001);
    /// Mirrors a `SecTrustOptionFlags` bit.
    pub const LEAF_IS_CA: Self = Self(0x0000_0002);
    /// Mirrors a `SecTrustOptionFlags` bit.
    pub const FETCH_ISSUER_FROM_NET: Self = Self(0x0000_0004);
    /// Mirrors a `SecTrustOptionFlags` bit.
    pub const ALLOW_EXPIRED_ROOT: Self = Self(0x0000_0008);
    /// Mirrors a `SecTrustOptionFlags` bit.
    pub const REQUIRE_REVOCATION_PER_CERT: Self = Self(0x0000_0010);
    /// Mirrors a `SecTrustOptionFlags` bit.
    pub const USE_TRUST_SETTINGS: Self = Self(0x0000_0020);
    /// Mirrors a `SecTrustOptionFlags` bit.
    pub const IMPLICIT_ANCHORS: Self = Self(0x0000_0040);

    pub const fn empty() -> Self {
        Self(0)
    }
    pub const fn all() -> Self {
        Self(0x7f)
    }
    pub const fn bits(self) -> u32 {
        self.0
    }
    pub const fn from_bits(bits: u32) -> Option<Self> {
        if bits & !Self::all().0 == 0 {
            Some(Self(bits))
        } else {
            None
        }
    }
    pub const fn from_bits_retain(bits: u32) -> Self {
        Self(bits)
    }
    pub const fn from_bits_truncate(bits: u32) -> Self {
        Self(bits & Self::all().0)
    }
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
    pub const fn is_all(self) -> bool {
        self.0 & Self::all().0 == Self::all().0
    }
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
    pub const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
    pub const fn intersection(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }
    pub const fn difference(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }
    pub const fn symmetric_difference(self, other: Self) -> Self {
        Self(self.0 ^ other.0)
    }
    pub const fn complement(self) -> Self {
        Self(!self.0 & Self::all().0)
    }
    pub fn insert(&mut self, other: Self) {
        self.0 |= other.0;
    }
    pub fn remove(&mut self, other: Self) {
        self.0 &= !other.0;
    }
    pub fn toggle(&mut self, other: Self) {
        self.0 ^= other.0;
    }
    pub fn set(&mut self, other: Self, value: bool) {
        if value {
            self.0 |= other.0;
        } else {
            self.0 &= !other.0;
        }
    }
}

impl std::ops::BitOr for TrustOptions {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}
impl std::ops::BitAnd for TrustOptions {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
}
impl std::ops::BitXor for TrustOptions {
    type Output = Self;
    fn bitxor(self, rhs: Self) -> Self {
        Self(self.0 ^ rhs.0)
    }
}
impl std::ops::Sub for TrustOptions {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        Self(self.0 & !rhs.0)
    }
}
impl std::ops::Not for TrustOptions {
    type Output = Self;
    fn not(self) -> Self {
        Self(!self.0 & Self::all().0)
    }
}
impl std::ops::BitOrAssign for TrustOptions {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}
impl std::ops::BitAndAssign for TrustOptions {
    fn bitand_assign(&mut self, rhs: Self) {
        self.0 &= rhs.0;
    }
}
impl std::ops::BitXorAssign for TrustOptions {
    fn bitxor_assign(&mut self, rhs: Self) {
        self.0 ^= rhs.0;
    }
}
impl std::ops::SubAssign for TrustOptions {
    fn sub_assign(&mut self, rhs: Self) {
        self.0 &= !rhs.0;
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
    #[cfg(feature = "async")]
    pub(crate) fn as_ptr(&self) -> *mut std::ffi::c_void {
        self.handle.as_ptr()
    }

    pub(crate) fn from_handle(handle: bridge::Handle) -> Self {
        Self { handle }
    }

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
                &raw mut status,
                &raw mut error,
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
                &raw mut error,
            )
        };
        bridge::status_result("security_trust_set_policies", status, error)
    }

    /// Wraps the corresponding `SecTrustRef` operation.
    pub fn policies(&self) -> Result<Value> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_trust_copy_policies(
                self.handle.as_ptr(),
                &raw mut status,
                &raw mut error,
            )
        };
        bridge::required_value("security_trust_copy_policies", raw, status, error)
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
                &raw mut error,
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
                &raw mut status,
                &raw mut error,
            )
        };
        bridge::required_value(
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
                &raw mut error,
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
                &raw mut error,
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
                &raw mut status,
                &raw mut error,
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
                &raw mut error,
            )
        };
        bridge::status_result("security_trust_set_verify_date", status, error)
    }

    /// Wraps the corresponding `SecTrustRef` operation.
    pub fn verify_time(&self) -> Result<Option<SystemTime>> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_trust_get_verify_time(
                self.handle.as_ptr(),
                &raw mut status,
                &raw mut error,
            )
        };
        if status != 0 {
            return Err(bridge::status_error(
                "security_trust_get_verify_time",
                status,
                error,
            )?);
        }
        bridge::optional_value(raw)?.map_or(Ok(None), |value| decode_trust_date(value).map(Some))
    }

    /// Wraps the corresponding `SecTrustRef` operation.
    pub fn evaluate(&self) -> Result<()> {
        let mut error = std::ptr::null_mut();
        let trusted =
            unsafe { bridge::security_trust_evaluate(self.handle.as_ptr(), &raw mut error) };
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
            bridge::security_trust_evaluate_async(
                self.handle.as_ptr(),
                &raw mut status,
                &raw mut error,
            )
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
            bridge::security_trust_get_trust_result(
                self.handle.as_ptr(),
                &raw mut status,
                &raw mut error,
            )
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
            bridge::security_trust_copy_result(
                self.handle.as_ptr(),
                &raw mut status,
                &raw mut error,
            )
        };
        bridge::required_value("security_trust_copy_result", raw, status, error)
    }

    /// Wraps the corresponding `SecTrustRef` operation.
    pub fn key(&self) -> Result<Option<PublicKey>> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_trust_copy_key(self.handle.as_ptr(), &raw mut status, &raw mut error)
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
                &raw mut status,
                &raw mut error,
            )
        };
        let array_handle =
            bridge::required_handle("security_trust_copy_certificate_chain", raw, status, error)?;
        Certificate::from_array_handle(&array_handle)
    }

    /// Wraps the corresponding `SecTrustRef` operation.
    pub fn exceptions(&self) -> Result<Option<Vec<u8>>> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_trust_copy_exceptions(
                self.handle.as_ptr(),
                &raw mut status,
                &raw mut error,
            )
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
                &raw mut error,
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
        let responses = bridge::InputValue::data_array(responses)?;
        let mut error = std::ptr::null_mut();
        let status = unsafe {
            bridge::security_trust_set_ocsp_response(
                self.handle.as_ptr(),
                responses.as_ptr(),
                &raw mut error,
            )
        };
        bridge::status_result("security_trust_set_ocsp_response", status, error)
    }

    /// Wraps the corresponding `SecTrustRef` operation.
    pub fn set_signed_certificate_timestamps(&mut self, timestamps: &[Vec<u8>]) -> Result<()> {
        let timestamps = bridge::InputValue::data_array(timestamps)?;
        let mut error = std::ptr::null_mut();
        let status = unsafe {
            bridge::security_trust_set_signed_certificate_timestamps(
                self.handle.as_ptr(),
                timestamps.as_ptr(),
                &raw mut error,
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
            bridge::security_trust_set_options(self.handle.as_ptr(), options.bits(), &raw mut error)
        };
        bridge::status_result("security_trust_set_options", status, error)
    }

    /// Wraps the corresponding `SecTrustRef` operation.
    pub fn system_anchor_certificates() -> Result<Value> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_trust_copy_anchor_certificates(&raw mut status, &raw mut error)
        };
        bridge::required_value(
            "security_trust_copy_anchor_certificates",
            raw,
            status,
            error,
        )
    }
}

fn decode_trust_date(value: Value) -> Result<SystemTime> {
    let unix = value
        .as_date()
        .ok_or_else(|| SecurityError::UnexpectedType {
            operation: "security_trust_get_verify_time",
            expected: "date",
        })?;
    let out_of_range =
        || SecurityError::InvalidArgument("trust verify time is out of range".to_owned());
    let duration = Duration::try_from_secs_f64(unix.abs()).map_err(|_| out_of_range())?;
    if unix >= 0.0 {
        UNIX_EPOCH.checked_add(duration).ok_or_else(out_of_range)
    } else {
        UNIX_EPOCH.checked_sub(duration).ok_or_else(out_of_range)
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
        let time = decode_trust_date(Value::Date(42.5)).unwrap();

        assert_eq!(time, UNIX_EPOCH + Duration::from_secs_f64(42.5));
    }

    #[test]
    fn decode_trust_date_parses_negative_unix_seconds() {
        let time = decode_trust_date(Value::Date(-12.5)).unwrap();

        assert_eq!(time, UNIX_EPOCH - Duration::from_secs_f64(12.5));
    }

    #[test]
    fn decode_trust_date_requires_unix_field() {
        assert!(matches!(
            decode_trust_date(Value::Integer(1)).unwrap_err(),
            SecurityError::UnexpectedType {
                operation: "security_trust_get_verify_time",
                expected: "date",
            }
        ));
    }
}
