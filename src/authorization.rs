use crate::Value;

use crate::bridge;
use crate::error::{Result, SecurityError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
#[must_use]
/// Mirrors Authorization Services option bits used with `AuthorizationCreate`.
pub struct AuthorizationOptions(u32);

impl AuthorizationOptions {
    /// Mirrors an Authorization Services option bit.
    pub const DEFAULTS: Self = Self(0);
    /// Mirrors an Authorization Services option bit.
    pub const INTERACTION_ALLOWED: Self = Self(1 << 0);
    /// Mirrors an Authorization Services option bit.
    pub const EXTEND_RIGHTS: Self = Self(1 << 1);
    /// Mirrors an Authorization Services option bit.
    pub const PARTIAL_RIGHTS: Self = Self(1 << 2);
    /// Mirrors an Authorization Services option bit.
    pub const DESTROY_RIGHTS: Self = Self(1 << 3);
    /// Mirrors an Authorization Services option bit.
    pub const PREAUTHORIZE: Self = Self(1 << 4);
    /// Mirrors an Authorization Services option bit.
    pub const SKIP_INTERNAL_AUTH: Self = Self(1 << 9);
    /// Mirrors an Authorization Services option bit.
    pub const NO_DATA: Self = Self(1 << 20);

    pub const fn empty() -> Self {
        Self(0)
    }
    pub const fn all() -> Self {
        Self(0x0010_021f)
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

impl std::ops::BitOr for AuthorizationOptions {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}
impl std::ops::BitAnd for AuthorizationOptions {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
}
impl std::ops::BitXor for AuthorizationOptions {
    type Output = Self;
    fn bitxor(self, rhs: Self) -> Self {
        Self(self.0 ^ rhs.0)
    }
}
impl std::ops::Sub for AuthorizationOptions {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        Self(self.0 & !rhs.0)
    }
}
impl std::ops::Not for AuthorizationOptions {
    type Output = Self;
    fn not(self) -> Self {
        Self(!self.0 & Self::all().0)
    }
}
impl std::ops::BitOrAssign for AuthorizationOptions {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}
impl std::ops::BitAndAssign for AuthorizationOptions {
    fn bitand_assign(&mut self, rhs: Self) {
        self.0 &= rhs.0;
    }
}
impl std::ops::BitXorAssign for AuthorizationOptions {
    fn bitxor_assign(&mut self, rhs: Self) {
        self.0 ^= rhs.0;
    }
}
impl std::ops::SubAssign for AuthorizationOptions {
    fn sub_assign(&mut self, rhs: Self) {
        self.0 &= !rhs.0;
    }
}

#[derive(Debug)]
/// Wraps `AuthorizationRef`.
pub struct Authorization {
    handle: bridge::Handle,
}

impl Authorization {
    #[cfg(feature = "async")]
    pub(crate) fn as_ptr(&self) -> *mut std::ffi::c_void {
        self.handle.as_ptr()
    }

    /// Wraps the corresponding Authorization Services operation for `AuthorizationRef`.
    pub fn new() -> Result<Self> {
        Self::with_options(AuthorizationOptions::DEFAULTS)
    }

    /// Wraps the corresponding Authorization Services operation for `AuthorizationRef`.
    pub fn with_options(options: AuthorizationOptions) -> Result<Self> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_authorization_create(options.bits(), &raw mut status, &raw mut error)
        };
        bridge::required_handle("security_authorization_create", raw, status, error)
            .map(|handle| Self { handle })
    }

    pub fn set_destroy_rights_on_drop(&mut self, destroy_rights: bool) {
        unsafe {
            bridge::security_authorization_set_destroy_rights(self.handle.as_ptr(), destroy_rights);
        }
    }

    /// Wraps the corresponding Authorization Services operation for `AuthorizationRef`.
    pub fn external_form(&self) -> Result<Vec<u8>> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_authorization_make_external_form(
                self.handle.as_ptr(),
                &raw mut status,
                &raw mut error,
            )
        };
        bridge::required_data(
            "security_authorization_make_external_form",
            raw,
            status,
            error,
        )
    }

    /// Wraps the corresponding Authorization Services operation for `AuthorizationRef`.
    pub fn from_external_form(external_form: &[u8]) -> Result<Self> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_authorization_create_from_external_form(
                external_form.as_ptr().cast(),
                bridge::len_to_isize(external_form.len())?,
                &raw mut status,
                &raw mut error,
            )
        };
        bridge::required_handle(
            "security_authorization_create_from_external_form",
            raw,
            status,
            error,
        )
        .map(|handle| Self { handle })
    }

    /// Wraps the corresponding Authorization Services operation for `AuthorizationRef`.
    pub fn copy_info(&self, tag: Option<&str>) -> Result<Value> {
        let tag = tag.map(bridge::cstring).transpose()?;
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_authorization_copy_info(
                self.handle.as_ptr(),
                tag.as_ref()
                    .map_or(std::ptr::null(), bridge::BridgeString::as_ptr),
                &raw mut status,
                &raw mut error,
            )
        };
        bridge::required_value("security_authorization_copy_info", raw, status, error)
    }

    /// Wraps the corresponding Authorization Services operation for `AuthorizationRef`.
    pub fn copy_rights(&self, rights: &[&str], options: AuthorizationOptions) -> Result<Value> {
        let rights_value = rights_value(rights)?;
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_authorization_copy_rights(
                self.handle.as_ptr(),
                rights_value.as_ptr(),
                options.bits(),
                &raw mut status,
                &raw mut error,
            )
        };
        bridge::required_value("security_authorization_copy_rights", raw, status, error)
    }

    /// Wraps the corresponding Authorization Services operation for `AuthorizationRef`.
    pub fn copy_rights_async(
        &self,
        rights: &[&str],
        options: AuthorizationOptions,
    ) -> Result<Value> {
        let rights_value = rights_value(rights)?;
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_authorization_copy_rights_async(
                self.handle.as_ptr(),
                rights_value.as_ptr(),
                options.bits(),
                &raw mut status,
                &raw mut error,
            )
        };
        bridge::required_value(
            "security_authorization_copy_rights_async",
            raw,
            status,
            error,
        )
    }
}

pub(crate) fn rights_value(rights: &[&str]) -> Result<bridge::InputValue> {
    if rights.is_empty() {
        return Err(SecurityError::InvalidArgument(
            "at least one authorization right is required".to_owned(),
        ));
    }
    if rights
        .iter()
        .any(|right| right.is_empty() || right.contains('\0'))
    {
        return Err(SecurityError::InvalidArgument(
            "authorization right names must be non-empty and free of NUL bytes".to_owned(),
        ));
    }
    bridge::InputValue::strings(rights)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rights_value_rejects_empty_and_nul_names() {
        assert!(rights_value(&[]).is_err());
        assert!(rights_value(&[""]).is_err());
        assert!(rights_value(&["system.privilege.admin\0other"]).is_err());
        let value = rights_value(&["system.preferences"]).unwrap();
        assert_eq!(
            unsafe { bridge::value_abi::decode(&*value.as_ptr(), 0) }.unwrap(),
            Value::Array(vec![Value::String("system.preferences".to_owned())])
        );
    }

    #[test]
    fn defaults_are_empty() {
        assert!(AuthorizationOptions::DEFAULTS.is_empty());
        assert_eq!(AuthorizationOptions::DEFAULTS.bits(), 0);
    }

    #[test]
    fn authorization_options_round_trip_through_bits() {
        let options = AuthorizationOptions::INTERACTION_ALLOWED
            | AuthorizationOptions::EXTEND_RIGHTS
            | AuthorizationOptions::PREAUTHORIZE;

        assert_eq!(
            AuthorizationOptions::from_bits(options.bits()),
            Some(options)
        );
    }

    #[test]
    fn authorization_options_keep_sparse_bits() {
        let options = AuthorizationOptions::SKIP_INTERNAL_AUTH | AuthorizationOptions::NO_DATA;

        assert!(options.contains(AuthorizationOptions::SKIP_INTERNAL_AUTH));
        assert!(options.contains(AuthorizationOptions::NO_DATA));
        assert_eq!(options.bits(), (1 << 9) | (1 << 20));
    }
}
