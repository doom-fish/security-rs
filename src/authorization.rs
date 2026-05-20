use bitflags::bitflags;
use serde_json::Value;

use crate::bridge;
use crate::error::Result;

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    /// Mirrors Authorization Services option bits used with `AuthorizationCreate`.
    pub struct AuthorizationOptions: u32 {
        /// Mirrors an Authorization Services option bit.
        const DEFAULTS = 0;
        /// Mirrors an Authorization Services option bit.
        const INTERACTION_ALLOWED = 1 << 0;
        /// Mirrors an Authorization Services option bit.
        const EXTEND_RIGHTS = 1 << 1;
        /// Mirrors an Authorization Services option bit.
        const PARTIAL_RIGHTS = 1 << 2;
        /// Mirrors an Authorization Services option bit.
        const DESTROY_RIGHTS = 1 << 3;
        /// Mirrors an Authorization Services option bit.
        const PREAUTHORIZE = 1 << 4;
        /// Mirrors an Authorization Services option bit.
        const SKIP_INTERNAL_AUTH = 1 << 9;
        /// Mirrors an Authorization Services option bit.
        const NO_DATA = 1 << 20;
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
            bridge::security_authorization_create(options.bits(), &mut status, &mut error)
        };
        bridge::required_handle("security_authorization_create", raw, status, error)
            .map(|handle| Self { handle })
    }

    /// Wraps the corresponding Authorization Services operation for `AuthorizationRef`.
    pub fn external_form(&self) -> Result<Vec<u8>> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_authorization_make_external_form(
                self.handle.as_ptr(),
                &mut status,
                &mut error,
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
                &mut status,
                &mut error,
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
                    .map_or(std::ptr::null(), |value| value.as_ptr()),
                &mut status,
                &mut error,
            )
        };
        bridge::required_json("security_authorization_copy_info", raw, status, error)
    }

    /// Wraps the corresponding Authorization Services operation for `AuthorizationRef`.
    pub fn copy_rights(&self, rights: &[&str], options: AuthorizationOptions) -> Result<Value> {
        let rights_json = bridge::json_cstring(&rights)?;
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_authorization_copy_rights(
                self.handle.as_ptr(),
                rights_json.as_ptr(),
                options.bits(),
                &mut status,
                &mut error,
            )
        };
        bridge::required_json("security_authorization_copy_rights", raw, status, error)
    }

    /// Wraps the corresponding Authorization Services operation for `AuthorizationRef`.
    pub fn copy_rights_async(
        &self,
        rights: &[&str],
        options: AuthorizationOptions,
    ) -> Result<Value> {
        let rights_json = bridge::json_cstring(&rights)?;
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_authorization_copy_rights_async(
                self.handle.as_ptr(),
                rights_json.as_ptr(),
                options.bits(),
                &mut status,
                &mut error,
            )
        };
        bridge::required_json(
            "security_authorization_copy_rights_async",
            raw,
            status,
            error,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
