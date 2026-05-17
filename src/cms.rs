use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bitflags::bitflags;
use serde_json::Value;

use crate::bridge;
use crate::certificate::Certificate;
use crate::error::{Result, SecurityError};
use crate::identity::Identity;
use crate::policy::Policy;

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct CmsSignedAttributes: u32 {
        const NONE = 0;
        const SMIME_CAPABILITIES = 0x0001;
        const SMIME_ENCRYPTION_KEY_PREFS = 0x0002;
        const SMIME_MS_ENCRYPTION_KEY_PREFS = 0x0004;
        const SIGNING_TIME = 0x0008;
        const APPLE_CODESIGNING_HASH_AGILITY = 0x0010;
        const APPLE_CODESIGNING_HASH_AGILITY_V2 = 0x0020;
        const APPLE_EXPIRATION_TIME = 0x0040;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum CmsCertificateChainMode {
    None = 0,
    SignerOnly = 1,
    Chain = 2,
    ChainWithRoot = 3,
    ChainWithRootOrFail = 4,
}

impl CmsCertificateChainMode {
    fn from_raw(raw: u32) -> Result<Self> {
        match raw {
            0 => Ok(Self::None),
            1 => Ok(Self::SignerOnly),
            2 => Ok(Self::Chain),
            3 => Ok(Self::ChainWithRoot),
            4 => Ok(Self::ChainWithRootOrFail),
            _ => Err(SecurityError::InvalidArgument(format!(
                "unexpected CMS certificate chain mode: {raw}"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CmsDigestAlgorithm {
    Sha1,
    Sha256,
}

impl CmsDigestAlgorithm {
    const fn as_bridge_name(self) -> &'static str {
        match self {
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
        }
    }
}

#[derive(Debug)]
pub struct CmsDecoder {
    handle: bridge::Handle,
}

impl CmsDecoder {
    fn from_handle(handle: bridge::Handle) -> Self {
        Self { handle }
    }

    pub fn type_id() -> usize {
        unsafe { bridge::security_cms_decoder_get_type_id() }
    }

    pub fn update_message(&mut self, data: &[u8]) -> Result<()> {
        let mut error = std::ptr::null_mut();
        let status = unsafe {
            bridge::security_cms_decoder_update_message(
                self.handle.as_ptr(),
                data.as_ptr().cast(),
                bridge::len_to_isize(data.len())?,
                &mut error,
            )
        };
        bridge::status_result("security_cms_decoder_update_message", status, error)
    }

    pub fn finalize_message(&mut self) -> Result<()> {
        let mut error = std::ptr::null_mut();
        let status = unsafe {
            bridge::security_cms_decoder_finalize_message(self.handle.as_ptr(), &mut error)
        };
        bridge::status_result("security_cms_decoder_finalize_message", status, error)
    }

    pub fn set_detached_content(&mut self, data: &[u8]) -> Result<()> {
        let mut error = std::ptr::null_mut();
        let status = unsafe {
            bridge::security_cms_decoder_set_detached_content(
                self.handle.as_ptr(),
                data.as_ptr().cast(),
                bridge::len_to_isize(data.len())?,
                &mut error,
            )
        };
        bridge::status_result("security_cms_decoder_set_detached_content", status, error)
    }

    pub fn detached_content(&self) -> Result<Option<Vec<u8>>> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_cms_decoder_copy_detached_content(
                self.handle.as_ptr(),
                &mut status,
                &mut error,
            )
        };
        if status != 0 {
            return Err(bridge::status_error(
                "security_cms_decoder_copy_detached_content",
                status,
                error,
            )?);
        }
        bridge::optional_data(raw)
    }

    pub fn num_signers(&self) -> Result<usize> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let count = unsafe {
            bridge::security_cms_decoder_get_num_signers(
                self.handle.as_ptr(),
                &mut status,
                &mut error,
            )
        };
        if status != 0 {
            return Err(bridge::status_error(
                "security_cms_decoder_get_num_signers",
                status,
                error,
            )?);
        }
        usize::try_from(count).map_err(|_| {
            SecurityError::Serialization("negative signer count from bridge".to_owned())
        })
    }

    pub fn signer_status(
        &self,
        signer_index: usize,
        policy: Option<&Policy>,
        evaluate_sec_trust: bool,
    ) -> Result<Value> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_cms_decoder_copy_signer_status(
                self.handle.as_ptr(),
                bridge::len_to_isize(signer_index)?,
                policy.map_or(std::ptr::null_mut(), |value| value.handle().as_ptr()),
                evaluate_sec_trust,
                &mut status,
                &mut error,
            )
        };
        bridge::required_json(
            "security_cms_decoder_copy_signer_status",
            raw,
            status,
            error,
        )
    }

    pub fn signer_email_address(&self, signer_index: usize) -> Result<Option<String>> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_cms_decoder_copy_signer_email_address(
                self.handle.as_ptr(),
                bridge::len_to_isize(signer_index)?,
                &mut status,
                &mut error,
            )
        };
        if raw.is_null() && status == 0 {
            Ok(None)
        } else {
            bridge::required_string(
                "security_cms_decoder_copy_signer_email_address",
                raw,
                status,
                error,
            )
            .map(Some)
        }
    }

    pub fn signer_certificate(&self, signer_index: usize) -> Result<Certificate> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_cms_decoder_copy_signer_cert(
                self.handle.as_ptr(),
                bridge::len_to_isize(signer_index)?,
                &mut status,
                &mut error,
            )
        };
        bridge::required_handle("security_cms_decoder_copy_signer_cert", raw, status, error)
            .map(Certificate::from_handle)
    }

    pub fn is_content_encrypted(&self) -> Result<bool> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let encrypted = unsafe {
            bridge::security_cms_decoder_is_content_encrypted(
                self.handle.as_ptr(),
                &mut status,
                &mut error,
            )
        };
        if status != 0 {
            return Err(bridge::status_error(
                "security_cms_decoder_is_content_encrypted",
                status,
                error,
            )?);
        }
        Ok(encrypted)
    }

    pub fn encapsulated_content_type(&self) -> Result<Option<Vec<u8>>> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_cms_decoder_copy_encapsulated_content_type(
                self.handle.as_ptr(),
                &mut status,
                &mut error,
            )
        };
        if status != 0 {
            return Err(bridge::status_error(
                "security_cms_decoder_copy_encapsulated_content_type",
                status,
                error,
            )?);
        }
        bridge::optional_data(raw)
    }

    pub fn content(&self) -> Result<Option<Vec<u8>>> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_cms_decoder_copy_content(self.handle.as_ptr(), &mut status, &mut error)
        };
        if status != 0 {
            return Err(bridge::status_error(
                "security_cms_decoder_copy_content",
                status,
                error,
            )?);
        }
        bridge::optional_data(raw)
    }

    pub fn signer_signing_time(&self, signer_index: usize) -> Result<Option<SystemTime>> {
        decode_optional_cms_date("security_cms_decoder_copy_signer_signing_time", unsafe {
            let mut status = 0;
            let mut error = std::ptr::null_mut();
            let raw = bridge::security_cms_decoder_copy_signer_signing_time(
                self.handle.as_ptr(),
                bridge::len_to_isize(signer_index)?,
                &mut status,
                &mut error,
            );
            (raw, status, error)
        })
    }

    pub fn signer_timestamp(&self, signer_index: usize) -> Result<Option<SystemTime>> {
        decode_optional_cms_date("security_cms_decoder_copy_signer_timestamp", unsafe {
            let mut status = 0;
            let mut error = std::ptr::null_mut();
            let raw = bridge::security_cms_decoder_copy_signer_timestamp(
                self.handle.as_ptr(),
                bridge::len_to_isize(signer_index)?,
                &mut status,
                &mut error,
            );
            (raw, status, error)
        })
    }

    pub fn signer_timestamp_with_policy(
        &self,
        policy: Option<&Policy>,
        signer_index: usize,
    ) -> Result<Option<SystemTime>> {
        decode_optional_cms_date(
            "security_cms_decoder_copy_signer_timestamp_with_policy",
            unsafe {
                let mut status = 0;
                let mut error = std::ptr::null_mut();
                let raw = bridge::security_cms_decoder_copy_signer_timestamp_with_policy(
                    self.handle.as_ptr(),
                    policy.map_or(std::ptr::null_mut(), |value| value.handle().as_ptr()),
                    bridge::len_to_isize(signer_index)?,
                    &mut status,
                    &mut error,
                );
                (raw, status, error)
            },
        )
    }

    pub fn signer_timestamp_certificates(&self, signer_index: usize) -> Result<Value> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_cms_decoder_copy_signer_timestamp_certificates(
                self.handle.as_ptr(),
                bridge::len_to_isize(signer_index)?,
                &mut status,
                &mut error,
            )
        };
        bridge::required_json(
            "security_cms_decoder_copy_signer_timestamp_certificates",
            raw,
            status,
            error,
        )
    }

    pub fn all_certificates(&self) -> Result<Vec<Certificate>> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_cms_decode_all_certificates(
                std::ptr::null(),
                0,
                &mut status,
                &mut error,
            )
        };
        let _ = raw;
        Err(SecurityError::InvalidArgument(
            "CmsDecoder::all_certificates is not available; use Cms::decode_all_certificates"
                .to_owned(),
        ))
    }
}

#[derive(Debug)]
pub struct CmsEncoder {
    handle: bridge::Handle,
}

impl CmsEncoder {
    fn from_handle(handle: bridge::Handle) -> Self {
        Self { handle }
    }

    pub fn type_id() -> usize {
        unsafe { bridge::security_cms_encoder_get_type_id() }
    }

    pub fn set_signer_algorithm(&mut self, algorithm: CmsDigestAlgorithm) -> Result<()> {
        let algorithm = bridge::cstring(algorithm.as_bridge_name())?;
        let mut error = std::ptr::null_mut();
        let status = unsafe {
            bridge::security_cms_encoder_set_signer_algorithm(
                self.handle.as_ptr(),
                algorithm.as_ptr(),
                &mut error,
            )
        };
        bridge::status_result("security_cms_encoder_set_signer_algorithm", status, error)
    }

    pub fn add_signers(&mut self, signers: &[Identity]) -> Result<()> {
        let handles = signers.iter().map(Identity::handle).collect::<Vec<_>>();
        let pointers = bridge::handle_pointer_array(&handles);
        let mut error = std::ptr::null_mut();
        let status = unsafe {
            bridge::security_cms_encoder_add_signers(
                self.handle.as_ptr(),
                pointers.as_ptr(),
                bridge::len_to_isize(pointers.len())?,
                &mut error,
            )
        };
        bridge::status_result("security_cms_encoder_add_signers", status, error)
    }

    pub fn signers(&self) -> Result<Value> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_cms_encoder_copy_signers(self.handle.as_ptr(), &mut status, &mut error)
        };
        bridge::required_json("security_cms_encoder_copy_signers", raw, status, error)
    }

    pub fn add_recipients(&mut self, recipients: &[Certificate]) -> Result<()> {
        let handles = recipients
            .iter()
            .map(Certificate::handle)
            .collect::<Vec<_>>();
        let pointers = bridge::handle_pointer_array(&handles);
        let mut error = std::ptr::null_mut();
        let status = unsafe {
            bridge::security_cms_encoder_add_recipients(
                self.handle.as_ptr(),
                pointers.as_ptr(),
                bridge::len_to_isize(pointers.len())?,
                &mut error,
            )
        };
        bridge::status_result("security_cms_encoder_add_recipients", status, error)
    }

    pub fn recipients(&self) -> Result<Value> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_cms_encoder_copy_recipients(
                self.handle.as_ptr(),
                &mut status,
                &mut error,
            )
        };
        bridge::required_json("security_cms_encoder_copy_recipients", raw, status, error)
    }

    pub fn set_has_detached_content(&mut self, detached_content: bool) -> Result<()> {
        let mut error = std::ptr::null_mut();
        let status = unsafe {
            bridge::security_cms_encoder_set_has_detached_content(
                self.handle.as_ptr(),
                detached_content,
                &mut error,
            )
        };
        bridge::status_result(
            "security_cms_encoder_set_has_detached_content",
            status,
            error,
        )
    }

    pub fn has_detached_content(&self) -> Result<bool> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let detached = unsafe {
            bridge::security_cms_encoder_get_has_detached_content(
                self.handle.as_ptr(),
                &mut status,
                &mut error,
            )
        };
        if status != 0 {
            return Err(bridge::status_error(
                "security_cms_encoder_get_has_detached_content",
                status,
                error,
            )?);
        }
        Ok(detached)
    }

    pub fn set_encapsulated_content_type_oid(&mut self, oid: &str) -> Result<()> {
        let oid = bridge::cstring(oid)?;
        let mut error = std::ptr::null_mut();
        let status = unsafe {
            bridge::security_cms_encoder_set_encapsulated_content_type_oid(
                self.handle.as_ptr(),
                oid.as_ptr(),
                &mut error,
            )
        };
        bridge::status_result(
            "security_cms_encoder_set_encapsulated_content_type_oid",
            status,
            error,
        )
    }

    pub fn encapsulated_content_type(&self) -> Result<Option<Vec<u8>>> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_cms_encoder_copy_encapsulated_content_type(
                self.handle.as_ptr(),
                &mut status,
                &mut error,
            )
        };
        if status != 0 {
            return Err(bridge::status_error(
                "security_cms_encoder_copy_encapsulated_content_type",
                status,
                error,
            )?);
        }
        bridge::optional_data(raw)
    }

    pub fn add_supporting_certificates(&mut self, certificates: &[Certificate]) -> Result<()> {
        let handles = certificates
            .iter()
            .map(Certificate::handle)
            .collect::<Vec<_>>();
        let pointers = bridge::handle_pointer_array(&handles);
        let mut error = std::ptr::null_mut();
        let status = unsafe {
            bridge::security_cms_encoder_add_supporting_certs(
                self.handle.as_ptr(),
                pointers.as_ptr(),
                bridge::len_to_isize(pointers.len())?,
                &mut error,
            )
        };
        bridge::status_result("security_cms_encoder_add_supporting_certs", status, error)
    }

    pub fn supporting_certificates(&self) -> Result<Value> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_cms_encoder_copy_supporting_certs(
                self.handle.as_ptr(),
                &mut status,
                &mut error,
            )
        };
        bridge::required_json(
            "security_cms_encoder_copy_supporting_certs",
            raw,
            status,
            error,
        )
    }

    pub fn add_signed_attributes(&mut self, signed_attributes: CmsSignedAttributes) -> Result<()> {
        let mut error = std::ptr::null_mut();
        let status = unsafe {
            bridge::security_cms_encoder_add_signed_attributes(
                self.handle.as_ptr(),
                signed_attributes.bits(),
                &mut error,
            )
        };
        bridge::status_result("security_cms_encoder_add_signed_attributes", status, error)
    }

    pub fn set_certificate_chain_mode(
        &mut self,
        chain_mode: CmsCertificateChainMode,
    ) -> Result<()> {
        let mut error = std::ptr::null_mut();
        let status = unsafe {
            bridge::security_cms_encoder_set_certificate_chain_mode(
                self.handle.as_ptr(),
                chain_mode as u32,
                &mut error,
            )
        };
        bridge::status_result(
            "security_cms_encoder_set_certificate_chain_mode",
            status,
            error,
        )
    }

    pub fn certificate_chain_mode(&self) -> Result<CmsCertificateChainMode> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let mode = unsafe {
            bridge::security_cms_encoder_get_certificate_chain_mode(
                self.handle.as_ptr(),
                &mut status,
                &mut error,
            )
        };
        if status != 0 {
            return Err(bridge::status_error(
                "security_cms_encoder_get_certificate_chain_mode",
                status,
                error,
            )?);
        }
        CmsCertificateChainMode::from_raw(mode)
    }

    pub fn update_content(&mut self, data: &[u8]) -> Result<()> {
        let mut error = std::ptr::null_mut();
        let status = unsafe {
            bridge::security_cms_encoder_update_content(
                self.handle.as_ptr(),
                data.as_ptr().cast(),
                bridge::len_to_isize(data.len())?,
                &mut error,
            )
        };
        bridge::status_result("security_cms_encoder_update_content", status, error)
    }

    pub fn encoded_content(&self) -> Result<Vec<u8>> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_cms_encoder_copy_encoded_content(
                self.handle.as_ptr(),
                &mut status,
                &mut error,
            )
        };
        bridge::required_data(
            "security_cms_encoder_copy_encoded_content",
            raw,
            status,
            error,
        )
    }

    pub fn signer_timestamp(&self, signer_index: usize) -> Result<Option<SystemTime>> {
        decode_optional_cms_date("security_cms_encoder_copy_signer_timestamp", unsafe {
            let mut status = 0;
            let mut error = std::ptr::null_mut();
            let raw = bridge::security_cms_encoder_copy_signer_timestamp(
                self.handle.as_ptr(),
                bridge::len_to_isize(signer_index)?,
                &mut status,
                &mut error,
            );
            (raw, status, error)
        })
    }

    pub fn signer_timestamp_with_policy(
        &self,
        policy: Option<&Policy>,
        signer_index: usize,
    ) -> Result<Option<SystemTime>> {
        decode_optional_cms_date(
            "security_cms_encoder_copy_signer_timestamp_with_policy",
            unsafe {
                let mut status = 0;
                let mut error = std::ptr::null_mut();
                let raw = bridge::security_cms_encoder_copy_signer_timestamp_with_policy(
                    self.handle.as_ptr(),
                    policy.map_or(std::ptr::null_mut(), |value| value.handle().as_ptr()),
                    bridge::len_to_isize(signer_index)?,
                    &mut status,
                    &mut error,
                );
                (raw, status, error)
            },
        )
    }
}

pub struct Cms;

impl Cms {
    pub fn encoder() -> Result<CmsEncoder> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe { bridge::security_cms_encoder_create(&mut status, &mut error) };
        bridge::required_handle("security_cms_encoder_create", raw, status, error)
            .map(CmsEncoder::from_handle)
    }

    pub fn decoder() -> Result<CmsDecoder> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe { bridge::security_cms_decoder_create(&mut status, &mut error) };
        bridge::required_handle("security_cms_decoder_create", raw, status, error)
            .map(CmsDecoder::from_handle)
    }

    pub fn encode_supporting_certificates(certificates: &[Certificate]) -> Result<Vec<u8>> {
        let mut encoder = Self::encoder()?;
        encoder.add_supporting_certificates(certificates)?;
        encoder.encoded_content()
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
        let array_handle =
            bridge::required_handle("security_cms_decode_all_certificates", raw, status, error)?;
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

    pub fn encode_content(
        signers: &[Identity],
        recipients: &[Certificate],
        encapsulated_content_type_oid: Option<&str>,
        detached_content: bool,
        signed_attributes: CmsSignedAttributes,
        content: &[u8],
    ) -> Result<Vec<u8>> {
        let signer_handles = signers.iter().map(Identity::handle).collect::<Vec<_>>();
        let signer_pointers = bridge::handle_pointer_array(&signer_handles);
        let recipient_handles = recipients
            .iter()
            .map(Certificate::handle)
            .collect::<Vec<_>>();
        let recipient_pointers = bridge::handle_pointer_array(&recipient_handles);
        let encapsulated_content_type_oid = encapsulated_content_type_oid
            .map(bridge::cstring)
            .transpose()?;
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_cms_encode_content(
                signer_pointers.as_ptr(),
                bridge::len_to_isize(signer_pointers.len())?,
                recipient_pointers.as_ptr(),
                bridge::len_to_isize(recipient_pointers.len())?,
                encapsulated_content_type_oid
                    .as_ref()
                    .map_or(std::ptr::null(), |value| value.as_ptr()),
                detached_content,
                signed_attributes.bits(),
                content.as_ptr().cast(),
                bridge::len_to_isize(content.len())?,
                &mut status,
                &mut error,
            )
        };
        bridge::required_data("security_cms_encode_content", raw, status, error)
    }
}

fn decode_optional_cms_date(
    operation: &'static str,
    result: (*mut std::ffi::c_void, i32, *mut std::ffi::c_void),
) -> Result<Option<SystemTime>> {
    let (raw, status, error) = result;
    if status != 0 {
        return Err(bridge::status_error(operation, status, error)?);
    }
    bridge::optional_json::<Value>(raw)?.map_or(Ok(None), |value| {
        decode_cms_date(value, operation).map(Some)
    })
}

fn decode_cms_date(value: Value, operation: &'static str) -> Result<SystemTime> {
    let unix =
        value
            .get("unix")
            .and_then(Value::as_f64)
            .ok_or_else(|| SecurityError::UnexpectedType {
                operation,
                expected: "date JSON object",
            })?;
    let duration = Duration::from_secs_f64(unix.abs());
    if unix >= 0.0 {
        Ok(UNIX_EPOCH + duration)
    } else {
        UNIX_EPOCH.checked_sub(duration).ok_or_else(|| {
            SecurityError::InvalidArgument("CMS date preceded UNIX_EPOCH by too much".to_owned())
        })
    }
}
