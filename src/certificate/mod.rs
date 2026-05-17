use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use serde_json::Value;

use crate::bridge::{self, Handle};
use crate::error::{Result, SecurityError};
use crate::key::{self, EncryptionAlgorithm, ExternalFormat, ExternalItemType, SignatureAlgorithm};

#[derive(Debug)]
pub struct PublicKey {
    handle: Handle,
}

impl PublicKey {
    pub fn type_id() -> usize {
        key::key_type_id()
    }

    pub(crate) fn from_handle(handle: Handle) -> Self {
        Self { handle }
    }

    pub fn attributes(&self) -> Result<Value> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_key_copy_attributes(self.handle.as_ptr(), &mut status, &mut error)
        };
        bridge::required_json("security_key_copy_attributes", raw, status, error)
    }

    pub fn block_size(&self) -> usize {
        key::key_block_size(&self.handle)
    }

    pub fn external_representation(&self) -> Result<Vec<u8>> {
        key::key_external_representation(&self.handle)
    }

    pub fn encrypt(&self, algorithm: EncryptionAlgorithm, plaintext: &[u8]) -> Result<Vec<u8>> {
        key::encrypt_with_public_key(&self.handle, algorithm, plaintext)
    }

    pub fn verify_signature(
        &self,
        algorithm: SignatureAlgorithm,
        signed_data: &[u8],
        signature: &[u8],
    ) -> Result<bool> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let valid = unsafe {
            bridge::security_public_key_verify_signature(
                self.handle.as_ptr(),
                algorithm as u32,
                signed_data.as_ptr().cast(),
                bridge::len_to_isize(signed_data.len())?,
                signature.as_ptr().cast(),
                bridge::len_to_isize(signature.len())?,
                &mut status,
                &mut error,
            )
        };
        if status != 0 {
            return Err(bridge::status_error(
                "security_public_key_verify_signature",
                status,
                error,
            )?);
        }
        Ok(valid)
    }
}

#[derive(Debug)]
pub struct Certificate {
    handle: Handle,
}

impl Certificate {
    pub(crate) fn from_handle(handle: Handle) -> Self {
        Self { handle }
    }

    pub(crate) fn handle(&self) -> &Handle {
        &self.handle
    }

    pub fn type_id() -> usize {
        unsafe { bridge::security_certificate_get_type_id() }
    }

    pub fn from_der(der: &[u8]) -> Result<Self> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_certificate_from_der(
                der.as_ptr().cast(),
                bridge::len_to_isize(der.len())?,
                &mut status,
                &mut error,
            )
        };
        bridge::required_handle("security_certificate_from_der", raw, status, error)
            .map(Self::from_handle)
    }

    pub fn import_item(
        data: &[u8],
        file_name_or_extension: Option<&str>,
        format: ExternalFormat,
        item_type: ExternalItemType,
    ) -> Result<Self> {
        let file_name_or_extension = file_name_or_extension.map(bridge::cstring).transpose()?;
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_certificate_import_item(
                data.as_ptr().cast(),
                bridge::len_to_isize(data.len())?,
                file_name_or_extension
                    .as_ref()
                    .map_or(std::ptr::null(), |value| value.as_ptr()),
                format as u32,
                item_type as u32,
                &mut status,
                &mut error,
            )
        };
        bridge::required_handle("security_certificate_import_item", raw, status, error)
            .map(Self::from_handle)
    }

    pub fn export_item(&self, format: ExternalFormat, pem_armour: bool) -> Result<Vec<u8>> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_certificate_export_item(
                self.handle.as_ptr(),
                format as u32,
                pem_armour,
                &mut status,
                &mut error,
            )
        };
        bridge::required_data("security_certificate_export_item", raw, status, error)
    }

    pub fn from_pem(pem: &[u8]) -> Result<Self> {
        let pem = std::str::from_utf8(pem).map_err(|error| {
            SecurityError::InvalidArgument(format!("PEM input was not valid UTF-8: {error}"))
        })?;
        let base64 = pem
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect::<String>();
        let der = base64::engine::general_purpose::STANDARD
            .decode(base64)
            .map_err(|error| {
                SecurityError::InvalidArgument(format!("invalid PEM body: {error}"))
            })?;
        Self::from_der(&der)
    }

    pub fn subject_summary(&self) -> Result<Option<String>> {
        let raw =
            unsafe { bridge::security_certificate_copy_subject_summary(self.handle.as_ptr()) };
        bridge::optional_string(raw)
    }

    pub fn common_name(&self) -> Result<Option<String>> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_certificate_copy_common_name(
                self.handle.as_ptr(),
                &mut status,
                &mut error,
            )
        };
        if raw.is_null() && status == 0 {
            return Ok(None);
        }
        bridge::required_string("security_certificate_copy_common_name", raw, status, error)
            .map(Some)
    }

    pub fn email_addresses(&self) -> Result<Vec<String>> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_certificate_copy_email_addresses(
                self.handle.as_ptr(),
                &mut status,
                &mut error,
            )
        };
        bridge::required_json(
            "security_certificate_copy_email_addresses",
            raw,
            status,
            error,
        )
    }

    pub fn normalized_subject_sequence(&self) -> Result<Vec<u8>> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_certificate_copy_normalized_subject_sequence(
                self.handle.as_ptr(),
                &mut status,
                &mut error,
            )
        };
        bridge::required_data(
            "security_certificate_copy_normalized_subject_sequence",
            raw,
            status,
            error,
        )
    }

    pub fn normalized_issuer_sequence(&self) -> Result<Vec<u8>> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_certificate_copy_normalized_issuer_sequence(
                self.handle.as_ptr(),
                &mut status,
                &mut error,
            )
        };
        bridge::required_data(
            "security_certificate_copy_normalized_issuer_sequence",
            raw,
            status,
            error,
        )
    }

    pub fn serial_number(&self) -> Result<Vec<u8>> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_certificate_copy_serial_number(
                self.handle.as_ptr(),
                &mut status,
                &mut error,
            )
        };
        bridge::required_data(
            "security_certificate_copy_serial_number",
            raw,
            status,
            error,
        )
    }

    pub fn not_valid_before(&self) -> Result<Option<SystemTime>> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_certificate_copy_not_valid_before(
                self.handle.as_ptr(),
                &mut status,
                &mut error,
            )
        };
        if raw.is_null() && status == 0 {
            return Ok(None);
        }
        let value: Value = bridge::required_json(
            "security_certificate_copy_not_valid_before",
            raw,
            status,
            error,
        )?;
        decode_date(value).map(Some)
    }

    pub fn not_valid_after(&self) -> Result<Option<SystemTime>> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_certificate_copy_not_valid_after(
                self.handle.as_ptr(),
                &mut status,
                &mut error,
            )
        };
        if raw.is_null() && status == 0 {
            return Ok(None);
        }
        let value: Value = bridge::required_json(
            "security_certificate_copy_not_valid_after",
            raw,
            status,
            error,
        )?;
        decode_date(value).map(Some)
    }

    pub fn der_data(&self) -> Result<Vec<u8>> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_certificate_copy_der(self.handle.as_ptr(), &mut status, &mut error)
        };
        bridge::required_data("security_certificate_copy_der", raw, status, error)
    }

    pub fn public_key(&self) -> Result<PublicKey> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_certificate_copy_public_key(
                self.handle.as_ptr(),
                &mut status,
                &mut error,
            )
        };
        bridge::required_handle("security_certificate_copy_public_key", raw, status, error)
            .map(PublicKey::from_handle)
    }

    pub fn add_to_keychain(&self) -> Result<()> {
        let mut error = std::ptr::null_mut();
        let status = unsafe {
            bridge::security_certificate_add_to_keychain(self.handle.as_ptr(), &mut error)
        };
        bridge::status_result("security_certificate_add_to_keychain", status, error)
    }

    pub fn values(&self, keys: &[&str]) -> Result<Value> {
        let keys = (!keys.is_empty())
            .then(|| bridge::json_cstring(&keys))
            .transpose()?;
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_certificate_copy_values(
                self.handle.as_ptr(),
                keys.as_ref()
                    .map_or(std::ptr::null(), |value| value.as_ptr()),
                &mut status,
                &mut error,
            )
        };
        bridge::required_json("security_certificate_copy_values", raw, status, error)
    }

    pub fn long_description(&self) -> Result<String> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_certificate_copy_long_description(
                self.handle.as_ptr(),
                &mut status,
                &mut error,
            )
        };
        bridge::required_string(
            "security_certificate_copy_long_description",
            raw,
            status,
            error,
        )
    }

    pub fn short_description(&self) -> Result<String> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_certificate_copy_short_description(
                self.handle.as_ptr(),
                &mut status,
                &mut error,
            )
        };
        bridge::required_string(
            "security_certificate_copy_short_description",
            raw,
            status,
            error,
        )
    }

    pub fn preferred(name: &str, key_usage: &[&str]) -> Result<Option<Self>> {
        let name = bridge::cstring(name)?;
        let key_usage = (!key_usage.is_empty())
            .then(|| bridge::json_cstring(&key_usage))
            .transpose()?;
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_certificate_copy_preferred(
                name.as_ptr(),
                key_usage
                    .as_ref()
                    .map_or(std::ptr::null(), |value| value.as_ptr()),
                &mut status,
                &mut error,
            )
        };
        if raw.is_null() && status == 0 {
            Ok(None)
        } else {
            bridge::required_handle("security_certificate_copy_preferred", raw, status, error)
                .map(Self::from_handle)
                .map(Some)
        }
    }

    pub fn set_preferred(certificate: Option<&Self>, name: &str, key_usage: &[&str]) -> Result<()> {
        let name = bridge::cstring(name)?;
        let key_usage = (!key_usage.is_empty())
            .then(|| bridge::json_cstring(&key_usage))
            .transpose()?;
        let mut error = std::ptr::null_mut();
        let status = unsafe {
            bridge::security_certificate_set_preferred(
                certificate.map_or(std::ptr::null_mut(), |value| value.handle.as_ptr()),
                name.as_ptr(),
                key_usage
                    .as_ref()
                    .map_or(std::ptr::null(), |value| value.as_ptr()),
                &mut error,
            )
        };
        bridge::status_result("security_certificate_set_preferred", status, error)
    }
}

fn decode_date(value: Value) -> Result<SystemTime> {
    let unix =
        value
            .get("unix")
            .and_then(Value::as_f64)
            .ok_or_else(|| SecurityError::UnexpectedType {
                operation: "security_certificate_copy_not_valid_date",
                expected: "date JSON object",
            })?;
    let duration = Duration::from_secs_f64(unix.abs());
    if unix >= 0.0 {
        Ok(UNIX_EPOCH + duration)
    } else {
        UNIX_EPOCH.checked_sub(duration).ok_or_else(|| {
            SecurityError::InvalidArgument(
                "certificate date preceded UNIX_EPOCH by too much".to_owned(),
            )
        })
    }
}
