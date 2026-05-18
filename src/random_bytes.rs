use crate::bridge;
use crate::error::Result;

/// Wraps `SecRandomCopyBytes`.
pub struct SecureRandom;

impl SecureRandom {
    /// Wraps the corresponding `SecRandomCopyBytes` operation.
    pub fn fill(buffer: &mut [u8]) -> Result<()> {
        if buffer.is_empty() {
            return Ok(());
        }
        let mut error = std::ptr::null_mut();
        let status = unsafe {
            bridge::security_random_fill(
                buffer.as_mut_ptr().cast(),
                bridge::len_to_isize(buffer.len())?,
                &mut error,
            )
        };
        bridge::status_result("security_random_fill", status, error)
    }

    /// Wraps the corresponding `SecRandomCopyBytes` operation.
    pub fn bytes(length: usize) -> Result<Vec<u8>> {
        let mut bytes = vec![0_u8; length];
        Self::fill(&mut bytes)?;
        Ok(bytes)
    }
}
