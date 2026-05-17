use crate::bridge;
use crate::error::{Result, SecurityError};

pub struct Transform;

impl Transform {
    pub fn encode_base64(input: &[u8]) -> Result<String> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_transform_encode_base64(
                input.as_ptr().cast(),
                bridge::len_to_isize(input.len())?,
                &mut status,
                &mut error,
            )
        };
        let bytes = bridge::required_data("security_transform_encode_base64", raw, status, error)?;
        String::from_utf8(bytes).map_err(|error| {
            SecurityError::Serialization(format!(
                "base64 transform returned invalid UTF-8: {error}"
            ))
        })
    }

    pub fn decode_base64(input: &[u8]) -> Result<Vec<u8>> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_transform_decode_base64(
                input.as_ptr().cast(),
                bridge::len_to_isize(input.len())?,
                &mut status,
                &mut error,
            )
        };
        bridge::required_data("security_transform_decode_base64", raw, status, error)
    }
}
