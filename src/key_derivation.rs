use crate::secret::Zeroizing;
use crate::Value;

use crate::bridge;
use crate::error::Result;
use crate::secret::SecretBytes;

#[derive(Debug)]
/// Wraps derived key material backed by `SecKeyRef`.
pub struct DerivedKey {
    handle: bridge::Handle,
}

impl DerivedKey {
    /// Wraps the corresponding derived-key `SecKeyRef` operation.
    pub fn type_id() -> usize {
        crate::key::key_type_id()
    }

    /// Wraps the corresponding derived-key `SecKeyRef` operation.
    pub fn attributes(&self) -> Result<Value> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_key_copy_attributes(
                self.handle.as_ptr(),
                &raw mut status,
                &raw mut error,
            )
        };
        bridge::required_value("security_key_copy_attributes", raw, status, error)
    }

    pub fn to_bytes(&self) -> Result<SecretBytes> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_key_copy_raw_bytes(
                self.handle.as_ptr(),
                &raw mut status,
                &raw mut error,
            )
        };
        bridge::required_secret("security_key_copy_raw_bytes", raw, status, error)
    }
}

/// Wraps password-based key-derivation helpers in Security.framework.
pub struct KeyDerivation;

impl KeyDerivation {
    /// Wraps the corresponding Security.framework key-derivation operation.
    pub fn derive_pbkdf2_sha256(
        password: &str,
        salt: &[u8],
        rounds: u32,
        key_size_bits: usize,
    ) -> Result<DerivedKey> {
        let password = Zeroizing::new(bridge::cstring(password)?.into_bytes_with_nul());
        let password_buffer = bridge::AbiBuffer::new(&password[..password.len() - 1]);
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_key_derivation_derive_pbkdf2_sha256(
                &raw const password_buffer,
                salt.as_ptr().cast(),
                bridge::len_to_isize(salt.len())?,
                isize::try_from(rounds).map_err(|_| {
                    crate::error::SecurityError::InvalidArgument(
                        "round count exceeds bridge size limits".to_owned(),
                    )
                })?,
                bridge::len_to_isize(key_size_bits)?,
                &raw mut status,
                &raw mut error,
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
