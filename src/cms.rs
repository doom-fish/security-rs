use crate::bridge;
use crate::certificate::Certificate;
use crate::error::Result;

pub struct Cms;

impl Cms {
    pub fn encode_supporting_certificates(certificates: &[Certificate]) -> Result<Vec<u8>> {
        let handles = certificates.iter().map(Certificate::handle).collect::<Vec<_>>();
        let pointers = bridge::handle_pointer_array(&handles);
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_cms_encode_certificates(
                pointers.as_ptr(),
                bridge::len_to_isize(pointers.len())?,
                &mut status,
                &mut error,
            )
        };
        bridge::required_data("security_cms_encode_certificates", raw, status, error)
    }

    pub fn decode_all_certificates(data: &[u8]) -> Result<Vec<Certificate>> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_cms_decode_all_certificates(
                data.as_ptr().cast(),
                bridge::len_to_isize(data.len())?,
                &mut status,
                &mut error,
            )
        };
        let array_handle = bridge::required_handle(
            "security_cms_decode_all_certificates",
            raw,
            status,
            error,
        )?;
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
}
