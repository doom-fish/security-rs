use bitflags::bitflags;

use crate::bridge;
use crate::error::Result;

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct AuthorizationOptions: u32 {
        const DEFAULTS = 0;
        const INTERACTION_ALLOWED = 1 << 0;
        const EXTEND_RIGHTS = 1 << 1;
        const PARTIAL_RIGHTS = 1 << 2;
        const DESTROY_RIGHTS = 1 << 3;
        const PREAUTHORIZE = 1 << 4;
        const SKIP_INTERNAL_AUTH = 1 << 9;
        const NO_DATA = 1 << 20;
    }
}

#[derive(Debug)]
pub struct Authorization {
    handle: bridge::Handle,
}

impl Authorization {
    pub fn new() -> Result<Self> {
        Self::with_options(AuthorizationOptions::DEFAULTS)
    }

    pub fn with_options(options: AuthorizationOptions) -> Result<Self> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_authorization_create(options.bits(), &mut status, &mut error)
        };
        bridge::required_handle("security_authorization_create", raw, status, error)
            .map(|handle| Self { handle })
    }

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
        bridge::required_data("security_authorization_make_external_form", raw, status, error)
    }

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
}
