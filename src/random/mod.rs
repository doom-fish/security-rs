//! Cryptographically secure random bytes from `SecRandomCopyBytes`.

use crate::error::{Result, SecurityError};
use crate::ffi;
use crate::private::sec_error_message;

/// Stateless wrapper around Apple's default CSPRNG.
pub struct SecureRandom;

impl SecureRandom {
    /// Fill an existing buffer with cryptographically secure random bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if Security.framework rejects the random-byte request.
    pub fn fill(buffer: &mut [u8]) -> Result<()> {
        if buffer.is_empty() {
            return Ok(());
        }
        let status = unsafe {
            ffi::SecRandomCopyBytes(
                ffi::kSecRandomDefault,
                buffer.len(),
                buffer.as_mut_ptr().cast(),
            )
        };
        if status == ffi::status::SUCCESS {
            Ok(())
        } else {
            Err(SecurityError::from_status(
                "SecRandomCopyBytes",
                status,
                sec_error_message(status),
            ))
        }
    }

    /// Allocate a new `Vec<u8>` and fill it with cryptographically secure random bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if Security.framework rejects the random-byte request.
    pub fn bytes(length: usize) -> Result<Vec<u8>> {
        let mut buffer = vec![0_u8; length];
        Self::fill(&mut buffer)?;
        Ok(buffer)
    }
}
