use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bitflags::bitflags;
use serde_json::Value;

use crate::bridge;
use crate::certificate::Certificate;
use crate::error::{OsStatus, Result, SecurityError};
use crate::identity::Identity;
use crate::policy::Policy;
use crate::trust::Trust;

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    /// Mirrors signed-attribute bits used by the CMS encoder APIs.
    pub struct CmsSignedAttributes: u32 {
        /// Mirrors a CMS signed-attribute bit.
        const NONE = 0;
        /// Mirrors a CMS signed-attribute bit.
        const SMIME_CAPABILITIES = 0x0001;
        /// Mirrors a CMS signed-attribute bit.
        const SMIME_ENCRYPTION_KEY_PREFS = 0x0002;
        /// Mirrors a CMS signed-attribute bit.
        const SMIME_MS_ENCRYPTION_KEY_PREFS = 0x0004;
        /// Mirrors a CMS signed-attribute bit.
        const SIGNING_TIME = 0x0008;
        /// Mirrors a CMS signed-attribute bit.
        const APPLE_CODESIGNING_HASH_AGILITY = 0x0010;
        /// Mirrors a CMS signed-attribute bit.
        const APPLE_CODESIGNING_HASH_AGILITY_V2 = 0x0020;
        /// Mirrors a CMS signed-attribute bit.
        const APPLE_EXPIRATION_TIME = 0x0040;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
/// Mirrors certificate-chain modes used by `CMSEncoder`.
pub enum CmsCertificateChainMode {
    /// Mirrors a CMS certificate-chain mode constant.
    None = 0,
    /// Mirrors a CMS certificate-chain mode constant.
    SignerOnly = 1,
    /// Mirrors a CMS certificate-chain mode constant.
    Chain = 2,
    /// Mirrors a CMS certificate-chain mode constant.
    ChainWithRoot = 3,
    /// Mirrors a CMS certificate-chain mode constant.
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
/// Mirrors digest selectors used by `CMSEncoderSetSignerAlgorithm`.
pub enum CmsDigestAlgorithm {
    /// Mirrors a CMS digest selector.
    Sha1,
    /// Mirrors a CMS digest selector.
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CmsSignerStatus {
    Unsigned,
    Valid,
    NeedsDetachedContent,
    InvalidSignature,
    InvalidCertificate,
    InvalidIndex,
    Unknown(u32),
}

impl CmsSignerStatus {
    const fn from_raw(raw: u32) -> Self {
        match raw {
            0 => Self::Unsigned,
            1 => Self::Valid,
            2 => Self::NeedsDetachedContent,
            3 => Self::InvalidSignature,
            4 => Self::InvalidCertificate,
            5 => Self::InvalidIndex,
            other => Self::Unknown(other),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CmsCertificateVerification {
    NotEvaluated,
    Evaluated(OsStatus),
}

#[derive(Debug)]
#[non_exhaustive]
pub struct CmsSignerStatusReport {
    pub signer_status: CmsSignerStatus,
    pub certificate_verification: CmsCertificateVerification,
    pub trust: Option<Trust>,
}

impl CmsSignerStatusReport {
    pub fn is_verified(&self) -> bool {
        self.signer_status == CmsSignerStatus::Valid
            && self.certificate_verification == CmsCertificateVerification::Evaluated(0)
    }

    fn from_json(value: &Value, trust: Option<Trust>) -> Result<Self> {
        let unexpected = || SecurityError::UnexpectedType {
            operation: "security_cms_decoder_copy_signer_status",
            expected: "signer status JSON object",
        };
        let signer_status = value
            .get("signerStatus")
            .and_then(Value::as_u64)
            .and_then(|raw| u32::try_from(raw).ok())
            .map(CmsSignerStatus::from_raw)
            .ok_or_else(unexpected)?;
        let evaluated = value
            .get("trustEvaluated")
            .and_then(Value::as_bool)
            .ok_or_else(unexpected)?;
        let certificate_verification = if evaluated {
            value
                .get("certVerifyResultCode")
                .and_then(Value::as_i64)
                .and_then(|raw| OsStatus::try_from(raw).ok())
                .map(CmsCertificateVerification::Evaluated)
                .ok_or_else(unexpected)?
        } else {
            CmsCertificateVerification::NotEvaluated
        };
        Ok(Self {
            signer_status,
            certificate_verification,
            trust,
        })
    }
}

#[derive(Debug)]
/// Wraps Security.framework CMS decoder state.
pub struct CmsDecoder {
    handle: bridge::Handle,
}

impl CmsDecoder {
    fn from_handle(handle: bridge::Handle) -> Self {
        Self { handle }
    }

    /// Wraps the corresponding Security.framework CMS decoder operation.
    pub fn type_id() -> usize {
        unsafe { bridge::security_cms_decoder_get_type_id() }
    }

    /// Wraps the corresponding Security.framework CMS decoder operation.
    pub fn update_message(&mut self, data: &[u8]) -> Result<()> {
        let mut error = std::ptr::null_mut();
        let status = unsafe {
            bridge::security_cms_decoder_update_message(
                self.handle.as_ptr(),
                data.as_ptr().cast(),
                bridge::len_to_isize(data.len())?,
                &raw mut error,
            )
        };
        bridge::status_result("security_cms_decoder_update_message", status, error)
    }

    /// Wraps the corresponding Security.framework CMS decoder operation.
    pub fn finalize_message(&mut self) -> Result<()> {
        let mut error = std::ptr::null_mut();
        let status = unsafe {
            bridge::security_cms_decoder_finalize_message(self.handle.as_ptr(), &raw mut error)
        };
        bridge::status_result("security_cms_decoder_finalize_message", status, error)
    }

    /// Wraps the corresponding Security.framework CMS decoder operation.
    pub fn set_detached_content(&mut self, data: &[u8]) -> Result<()> {
        let mut error = std::ptr::null_mut();
        let status = unsafe {
            bridge::security_cms_decoder_set_detached_content(
                self.handle.as_ptr(),
                data.as_ptr().cast(),
                bridge::len_to_isize(data.len())?,
                &raw mut error,
            )
        };
        bridge::status_result("security_cms_decoder_set_detached_content", status, error)
    }

    /// Wraps the corresponding Security.framework CMS decoder operation.
    pub fn detached_content(&self) -> Result<Option<Vec<u8>>> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_cms_decoder_copy_detached_content(
                self.handle.as_ptr(),
                &raw mut status,
                &raw mut error,
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

    /// Wraps the corresponding Security.framework CMS decoder operation.
    pub fn num_signers(&self) -> Result<usize> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let count = unsafe {
            bridge::security_cms_decoder_get_num_signers(
                self.handle.as_ptr(),
                &raw mut status,
                &raw mut error,
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

    /// Wraps the corresponding Security.framework CMS decoder operation.
    pub fn signer_status(
        &self,
        signer_index: usize,
        policy: Option<&Policy>,
        evaluate_sec_trust: bool,
    ) -> Result<CmsSignerStatusReport> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let mut trust = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_cms_decoder_copy_signer_status(
                self.handle.as_ptr(),
                bridge::len_to_isize(signer_index)?,
                policy.map_or(std::ptr::null_mut(), |value| value.handle().as_ptr()),
                evaluate_sec_trust,
                &raw mut trust,
                &raw mut status,
                &raw mut error,
            )
        };
        let trust = bridge::Handle::from_raw(trust).map(Trust::from_handle);
        let value: Value = bridge::required_json(
            "security_cms_decoder_copy_signer_status",
            raw,
            status,
            error,
        )?;
        CmsSignerStatusReport::from_json(&value, trust)
    }

    /// Wraps the corresponding Security.framework CMS decoder operation.
    pub fn signer_email_address(&self, signer_index: usize) -> Result<Option<String>> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_cms_decoder_copy_signer_email_address(
                self.handle.as_ptr(),
                bridge::len_to_isize(signer_index)?,
                &raw mut status,
                &raw mut error,
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

    /// Wraps the corresponding Security.framework CMS decoder operation.
    pub fn signer_certificate(&self, signer_index: usize) -> Result<Certificate> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_cms_decoder_copy_signer_cert(
                self.handle.as_ptr(),
                bridge::len_to_isize(signer_index)?,
                &raw mut status,
                &raw mut error,
            )
        };
        bridge::required_handle("security_cms_decoder_copy_signer_cert", raw, status, error)
            .map(Certificate::from_handle)
    }

    /// Wraps the corresponding Security.framework CMS decoder operation.
    pub fn is_content_encrypted(&self) -> Result<bool> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let encrypted = unsafe {
            bridge::security_cms_decoder_is_content_encrypted(
                self.handle.as_ptr(),
                &raw mut status,
                &raw mut error,
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

    /// Wraps the corresponding Security.framework CMS decoder operation.
    pub fn encapsulated_content_type(&self) -> Result<Option<Vec<u8>>> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_cms_decoder_copy_encapsulated_content_type(
                self.handle.as_ptr(),
                &raw mut status,
                &raw mut error,
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

    /// Wraps the corresponding Security.framework CMS decoder operation.
    pub fn content(&self) -> Result<Option<Vec<u8>>> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_cms_decoder_copy_content(
                self.handle.as_ptr(),
                &raw mut status,
                &raw mut error,
            )
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

    /// Wraps the corresponding Security.framework CMS decoder operation.
    pub fn signer_signing_time(&self, signer_index: usize) -> Result<Option<SystemTime>> {
        decode_optional_cms_date("security_cms_decoder_copy_signer_signing_time", unsafe {
            let mut status = 0;
            let mut error = std::ptr::null_mut();
            let raw = bridge::security_cms_decoder_copy_signer_signing_time(
                self.handle.as_ptr(),
                bridge::len_to_isize(signer_index)?,
                &raw mut status,
                &raw mut error,
            );
            (raw, status, error)
        })
    }

    /// Wraps the corresponding Security.framework CMS decoder operation.
    pub fn signer_timestamp(&self, signer_index: usize) -> Result<Option<SystemTime>> {
        decode_optional_cms_date("security_cms_decoder_copy_signer_timestamp", unsafe {
            let mut status = 0;
            let mut error = std::ptr::null_mut();
            let raw = bridge::security_cms_decoder_copy_signer_timestamp(
                self.handle.as_ptr(),
                bridge::len_to_isize(signer_index)?,
                &raw mut status,
                &raw mut error,
            );
            (raw, status, error)
        })
    }

    /// Wraps the corresponding Security.framework CMS decoder operation.
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
                    &raw mut status,
                    &raw mut error,
                );
                (raw, status, error)
            },
        )
    }

    /// Wraps the corresponding Security.framework CMS decoder operation.
    pub fn signer_timestamp_certificates(&self, signer_index: usize) -> Result<Value> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_cms_decoder_copy_signer_timestamp_certificates(
                self.handle.as_ptr(),
                bridge::len_to_isize(signer_index)?,
                &raw mut status,
                &raw mut error,
            )
        };
        bridge::required_json(
            "security_cms_decoder_copy_signer_timestamp_certificates",
            raw,
            status,
            error,
        )
    }

    /// Wraps the corresponding Security.framework CMS decoder operation.
    pub fn all_certificates(&self) -> Result<Vec<Certificate>> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_cms_decoder_copy_all_certificates(
                self.handle.as_ptr(),
                &raw mut status,
                &raw mut error,
            )
        };
        let array_handle = bridge::required_handle(
            "security_cms_decoder_copy_all_certificates",
            raw,
            status,
            error,
        )?;
        Certificate::from_array_handle(&array_handle)
    }
}

#[derive(Debug)]
/// Wraps Security.framework CMS encoder state.
pub struct CmsEncoder {
    handle: bridge::Handle,
}

impl CmsEncoder {
    fn from_handle(handle: bridge::Handle) -> Self {
        Self { handle }
    }

    /// Wraps the corresponding Security.framework CMS encoder operation.
    pub fn type_id() -> usize {
        unsafe { bridge::security_cms_encoder_get_type_id() }
    }

    /// Wraps the corresponding Security.framework CMS encoder operation.
    pub fn set_signer_algorithm(&mut self, algorithm: CmsDigestAlgorithm) -> Result<()> {
        let algorithm = bridge::cstring(algorithm.as_bridge_name())?;
        let mut error = std::ptr::null_mut();
        let status = unsafe {
            bridge::security_cms_encoder_set_signer_algorithm(
                self.handle.as_ptr(),
                algorithm.as_ptr(),
                &raw mut error,
            )
        };
        bridge::status_result("security_cms_encoder_set_signer_algorithm", status, error)
    }

    /// Wraps the corresponding Security.framework CMS encoder operation.
    pub fn add_signers(&mut self, signers: &[Identity]) -> Result<()> {
        let handles = signers.iter().map(Identity::handle).collect::<Vec<_>>();
        let pointers = bridge::handle_pointer_array(&handles);
        let mut error = std::ptr::null_mut();
        let status = unsafe {
            bridge::security_cms_encoder_add_signers(
                self.handle.as_ptr(),
                pointers.as_ptr(),
                bridge::len_to_isize(pointers.len())?,
                &raw mut error,
            )
        };
        bridge::status_result("security_cms_encoder_add_signers", status, error)
    }

    /// Wraps the corresponding Security.framework CMS encoder operation.
    pub fn signers(&self) -> Result<Value> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_cms_encoder_copy_signers(
                self.handle.as_ptr(),
                &raw mut status,
                &raw mut error,
            )
        };
        bridge::required_json("security_cms_encoder_copy_signers", raw, status, error)
    }

    /// Wraps the corresponding Security.framework CMS encoder operation.
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
                &raw mut error,
            )
        };
        bridge::status_result("security_cms_encoder_add_recipients", status, error)
    }

    /// Wraps the corresponding Security.framework CMS encoder operation.
    pub fn recipients(&self) -> Result<Value> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_cms_encoder_copy_recipients(
                self.handle.as_ptr(),
                &raw mut status,
                &raw mut error,
            )
        };
        bridge::required_json("security_cms_encoder_copy_recipients", raw, status, error)
    }

    /// Wraps the corresponding Security.framework CMS encoder operation.
    pub fn set_has_detached_content(&mut self, detached_content: bool) -> Result<()> {
        let mut error = std::ptr::null_mut();
        let status = unsafe {
            bridge::security_cms_encoder_set_has_detached_content(
                self.handle.as_ptr(),
                detached_content,
                &raw mut error,
            )
        };
        bridge::status_result(
            "security_cms_encoder_set_has_detached_content",
            status,
            error,
        )
    }

    /// Wraps the corresponding Security.framework CMS encoder operation.
    pub fn has_detached_content(&self) -> Result<bool> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let detached = unsafe {
            bridge::security_cms_encoder_get_has_detached_content(
                self.handle.as_ptr(),
                &raw mut status,
                &raw mut error,
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

    /// Wraps the corresponding Security.framework CMS encoder operation.
    pub fn set_encapsulated_content_type_oid(&mut self, oid: &str) -> Result<()> {
        let oid = bridge::cstring(oid)?;
        let mut error = std::ptr::null_mut();
        let status = unsafe {
            bridge::security_cms_encoder_set_encapsulated_content_type_oid(
                self.handle.as_ptr(),
                oid.as_ptr(),
                &raw mut error,
            )
        };
        bridge::status_result(
            "security_cms_encoder_set_encapsulated_content_type_oid",
            status,
            error,
        )
    }

    /// Wraps the corresponding Security.framework CMS encoder operation.
    pub fn encapsulated_content_type(&self) -> Result<Option<Vec<u8>>> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_cms_encoder_copy_encapsulated_content_type(
                self.handle.as_ptr(),
                &raw mut status,
                &raw mut error,
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

    /// Wraps the corresponding Security.framework CMS encoder operation.
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
                &raw mut error,
            )
        };
        bridge::status_result("security_cms_encoder_add_supporting_certs", status, error)
    }

    /// Wraps the corresponding Security.framework CMS encoder operation.
    pub fn supporting_certificates(&self) -> Result<Value> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_cms_encoder_copy_supporting_certs(
                self.handle.as_ptr(),
                &raw mut status,
                &raw mut error,
            )
        };
        bridge::required_json(
            "security_cms_encoder_copy_supporting_certs",
            raw,
            status,
            error,
        )
    }

    /// Wraps the corresponding Security.framework CMS encoder operation.
    pub fn add_signed_attributes(&mut self, signed_attributes: CmsSignedAttributes) -> Result<()> {
        let mut error = std::ptr::null_mut();
        let status = unsafe {
            bridge::security_cms_encoder_add_signed_attributes(
                self.handle.as_ptr(),
                signed_attributes.bits(),
                &raw mut error,
            )
        };
        bridge::status_result("security_cms_encoder_add_signed_attributes", status, error)
    }

    /// Wraps the corresponding Security.framework CMS encoder operation.
    pub fn set_certificate_chain_mode(
        &mut self,
        chain_mode: CmsCertificateChainMode,
    ) -> Result<()> {
        let mut error = std::ptr::null_mut();
        let status = unsafe {
            bridge::security_cms_encoder_set_certificate_chain_mode(
                self.handle.as_ptr(),
                chain_mode as u32,
                &raw mut error,
            )
        };
        bridge::status_result(
            "security_cms_encoder_set_certificate_chain_mode",
            status,
            error,
        )
    }

    /// Wraps the corresponding Security.framework CMS encoder operation.
    pub fn certificate_chain_mode(&self) -> Result<CmsCertificateChainMode> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let mode = unsafe {
            bridge::security_cms_encoder_get_certificate_chain_mode(
                self.handle.as_ptr(),
                &raw mut status,
                &raw mut error,
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

    /// Wraps the corresponding Security.framework CMS encoder operation.
    pub fn update_content(&mut self, data: &[u8]) -> Result<()> {
        let mut error = std::ptr::null_mut();
        let status = unsafe {
            bridge::security_cms_encoder_update_content(
                self.handle.as_ptr(),
                data.as_ptr().cast(),
                bridge::len_to_isize(data.len())?,
                &raw mut error,
            )
        };
        bridge::status_result("security_cms_encoder_update_content", status, error)
    }

    /// Wraps the corresponding Security.framework CMS encoder operation.
    pub fn encoded_content(&self) -> Result<Vec<u8>> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_cms_encoder_copy_encoded_content(
                self.handle.as_ptr(),
                &raw mut status,
                &raw mut error,
            )
        };
        bridge::required_data(
            "security_cms_encoder_copy_encoded_content",
            raw,
            status,
            error,
        )
    }

    /// Wraps the corresponding Security.framework CMS encoder operation.
    pub fn signer_timestamp(&self, signer_index: usize) -> Result<Option<SystemTime>> {
        decode_optional_cms_date("security_cms_encoder_copy_signer_timestamp", unsafe {
            let mut status = 0;
            let mut error = std::ptr::null_mut();
            let raw = bridge::security_cms_encoder_copy_signer_timestamp(
                self.handle.as_ptr(),
                bridge::len_to_isize(signer_index)?,
                &raw mut status,
                &raw mut error,
            );
            (raw, status, error)
        })
    }

    /// Wraps the corresponding Security.framework CMS encoder operation.
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
                    &raw mut status,
                    &raw mut error,
                );
                (raw, status, error)
            },
        )
    }
}

/// Wraps convenience helpers around Security.framework CMS APIs.
pub struct Cms;

impl Cms {
    /// Wraps the corresponding Security.framework CMS helper.
    pub fn encoder() -> Result<CmsEncoder> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe { bridge::security_cms_encoder_create(&raw mut status, &raw mut error) };
        bridge::required_handle("security_cms_encoder_create", raw, status, error)
            .map(CmsEncoder::from_handle)
    }

    /// Wraps the corresponding Security.framework CMS helper.
    pub fn decoder() -> Result<CmsDecoder> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe { bridge::security_cms_decoder_create(&raw mut status, &raw mut error) };
        bridge::required_handle("security_cms_decoder_create", raw, status, error)
            .map(CmsDecoder::from_handle)
    }

    /// Wraps the corresponding Security.framework CMS helper.
    pub fn encode_supporting_certificates(certificates: &[Certificate]) -> Result<Vec<u8>> {
        let mut encoder = Self::encoder()?;
        encoder.add_supporting_certificates(certificates)?;
        encoder.encoded_content()
    }

    /// Wraps the corresponding Security.framework CMS helper.
    pub fn decode_all_certificates(data: &[u8]) -> Result<Vec<Certificate>> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_cms_decode_all_certificates(
                data.as_ptr().cast(),
                bridge::len_to_isize(data.len())?,
                &raw mut status,
                &raw mut error,
            )
        };
        let array_handle =
            bridge::required_handle("security_cms_decode_all_certificates", raw, status, error)?;
        Certificate::from_array_handle(&array_handle)
    }

    /// Wraps the corresponding Security.framework CMS helper.
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
                &raw mut status,
                &raw mut error,
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
    let out_of_range = || SecurityError::InvalidArgument("CMS date is out of range".to_owned());
    let duration = Duration::try_from_secs_f64(unix.abs()).map_err(|_| out_of_range())?;
    if unix >= 0.0 {
        UNIX_EPOCH.checked_add(duration).ok_or_else(out_of_range)
    } else {
        UNIX_EPOCH.checked_sub(duration).ok_or_else(out_of_range)
    }
}
