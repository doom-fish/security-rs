use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use serde_json::Value;

use crate::bridge::{self, Handle};
use crate::error::{Result, SecurityError};

#[derive(Debug)]
pub struct PublicKey {
    handle: Handle,
}

impl PublicKey {
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
            .map_err(|error| SecurityError::InvalidArgument(format!("invalid PEM body: {error}")))?;
        Self::from_der(&der)
    }

    pub fn subject_summary(&self) -> Result<Option<String>> {
        let raw = unsafe { bridge::security_certificate_copy_subject_summary(self.handle.as_ptr()) };
        bridge::optional_string(raw)
    }

    pub fn common_name(&self) -> Result<Option<String>> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_certificate_copy_common_name(self.handle.as_ptr(), &mut status, &mut error)
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
        bridge::required_json("security_certificate_copy_email_addresses", raw, status, error)
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
        bridge::required_data("security_certificate_copy_serial_number", raw, status, error)
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
            bridge::security_certificate_copy_public_key(self.handle.as_ptr(), &mut status, &mut error)
        };
        bridge::required_handle("security_certificate_copy_public_key", raw, status, error)
            .map(PublicKey::from_handle)
    }
}

fn decode_date(value: Value) -> Result<SystemTime> {
    let unix = value
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
            SecurityError::InvalidArgument("certificate date preceded UNIX_EPOCH by too much".to_owned())
        })
    }
}
