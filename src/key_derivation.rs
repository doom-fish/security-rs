use serde_json::Value;

use crate::bridge;
use crate::error::Result;

#[derive(Debug)]
pub struct DerivedKey {
    handle: bridge::Handle,
}

impl DerivedKey {
    pub fn attributes(&self) -> Result<Value> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_key_copy_attributes(self.handle.as_ptr(), &mut status, &mut error)
        };
        bridge::required_json("security_key_copy_attributes", raw, status, error)
    }
}

pub struct KeyDerivation;

impl KeyDerivation {
    pub fn derive_pbkdf2_sha256(
        password: &str,
        salt: &[u8],
        rounds: u32,
        key_size_bits: usize,
    ) -> Result<DerivedKey> {
        let password = bridge::cstring(password)?;
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_key_derivation_derive_pbkdf2_sha256(
                password.as_ptr(),
                salt.as_ptr().cast(),
                bridge::len_to_isize(salt.len())?,
                isize::try_from(rounds).map_err(|_| {
                    crate::error::SecurityError::InvalidArgument(
                        "round count exceeds bridge size limits".to_owned(),
                    )
                })?,
                bridge::len_to_isize(key_size_bits)?,
                &mut status,
                &mut error,
            )
        };
        bridge::required_handle(
            "security_key_derivation_derive_pbkdf2_sha256",
            raw,
            status,
            error,
        )
        .map(|handle| DerivedKey { handle })
    }
}
