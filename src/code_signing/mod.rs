//! Current-process code-signing inspection.

use std::collections::BTreeMap;

use apple_cf::CFError;

use crate::error::{Result, SecurityError};
use crate::ffi;
use crate::private::{
    cf_boolean_to_bool, cf_data_to_vec, cf_dictionary_entries, cf_dictionary_get_value,
    cf_number_to_i64, cf_string_to_string, cf_type_id, sec_error_message, OwnedCf,
};

/// Simplified snapshot of a Core Foundation value embedded in signing metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SigningValue {
    Boolean(bool),
    Integer(i64),
    String(String),
    Data(Vec<u8>),
    Array(Vec<Self>),
    Dictionary(BTreeMap<String, Self>),
    Unknown(String),
}

/// High-level view of `SecCodeCopySigningInformation` for the current process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningInformation {
    /// Bundle identifier or executable identifier if the process is signed.
    pub identifier: Option<String>,
    /// Team identifier, when the signature contains one.
    pub team_identifier: Option<String>,
    /// Embedded entitlements in dictionary form.
    pub entitlements: BTreeMap<String, SigningValue>,
    /// Whether the entitlements indicate App Sandbox is enabled.
    pub sandboxed: bool,
    /// Dynamic status word from the code-signing subsystem.
    pub status: Option<u32>,
}

impl SigningInformation {
    /// Whether the process appears to be signed.
    #[must_use]
    pub const fn is_signed(&self) -> bool {
        self.identifier.is_some()
    }
}

/// Owned `SecCodeRef` for a running process.
pub struct Code {
    raw: ffi::SecCodeRef,
}

impl Code {
    /// Capture the current process as a `SecCodeRef`.
    ///
    /// # Errors
    ///
    /// Returns an error if Security.framework cannot create the code object.
    pub fn current() -> Result<Self> {
        let mut raw = std::ptr::null();
        let status = unsafe { ffi::SecCodeCopySelf(ffi::kSecCSDefaultFlags, &mut raw) };
        if status != ffi::status::SUCCESS {
            return Err(SecurityError::from_status(
                "SecCodeCopySelf",
                status,
                sec_error_message(status),
            ));
        }
        if raw.is_null() {
            return Err(SecurityError::CoreFoundation(CFError::new(
                "SecCodeCopySelf",
            )));
        }
        Ok(Self { raw })
    }

    /// Fetch signing information for this code object.
    ///
    /// # Errors
    ///
    /// Returns an error if Security.framework rejects the query or returns an unexpected type.
    pub fn signing_information(&self) -> Result<SigningInformation> {
        let mut info = std::ptr::null();
        let flags = ffi::kSecCSSigningInformation | ffi::kSecCSDynamicInformation;
        let status =
            unsafe { ffi::SecCodeCopySigningInformation(self.raw.cast(), flags, &mut info) };
        if status != ffi::status::SUCCESS {
            return Err(SecurityError::from_status(
                "SecCodeCopySigningInformation",
                status,
                sec_error_message(status),
            ));
        }
        if info.is_null() {
            return Err(SecurityError::CoreFoundation(CFError::new(
                "SecCodeCopySigningInformation",
            )));
        }
        let info = OwnedCf::new(info.cast());
        if cf_type_id(info.as_ptr()) != unsafe { ffi::CFDictionaryGetTypeID() } {
            return Err(SecurityError::UnexpectedType {
                operation: "SecCodeCopySigningInformation",
                expected: "CFDictionary",
            });
        }

        let identifier = string_value(info.as_dictionary(), unsafe { ffi::kSecCodeInfoIdentifier });
        let team_identifier =
            string_value(info.as_dictionary(), unsafe { ffi::kSecCodeInfoTeamIdentifier });
        let entitlements =
            dictionary_value(info.as_dictionary(), unsafe { ffi::kSecCodeInfoEntitlementsDict })
                .map(cf_dictionary_to_map)
                .unwrap_or_default();
        let sandboxed = matches!(
            entitlements.get("com.apple.security.app-sandbox"),
            Some(SigningValue::Boolean(true))
        );
        let status = cf_dictionary_get_value(info.as_dictionary(), unsafe { ffi::kSecCodeInfoStatus });
        let status = cf_number_to_i64(status.cast()).and_then(|value| u32::try_from(value).ok());

        Ok(SigningInformation {
            identifier,
            team_identifier,
            entitlements,
            sandboxed,
            status,
        })
    }

    /// Borrow the raw `SecCodeRef`.
    #[must_use]
    pub const fn as_raw(&self) -> ffi::SecCodeRef {
        self.raw
    }
}

impl Drop for Code {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            unsafe { ffi::CFRelease(self.raw.cast()) };
        }
    }
}

impl core::fmt::Debug for Code {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Code").field("raw", &self.raw).finish()
    }
}

fn string_value(dictionary: ffi::CFDictionaryRef, key: ffi::CFStringRef) -> Option<String> {
    let value = cf_dictionary_get_value(dictionary, key);
    if value.is_null() || cf_type_id(value) != unsafe { ffi::CFStringGetTypeID() } {
        return None;
    }
    cf_string_to_string(value.cast())
}

fn dictionary_value(
    dictionary: ffi::CFDictionaryRef,
    key: ffi::CFStringRef,
) -> Option<ffi::CFDictionaryRef> {
    let value = cf_dictionary_get_value(dictionary, key);
    if value.is_null() || cf_type_id(value) != unsafe { ffi::CFDictionaryGetTypeID() } {
        return None;
    }
    Some(value.cast())
}

fn cf_dictionary_to_map(dictionary: ffi::CFDictionaryRef) -> BTreeMap<String, SigningValue> {
    cf_dictionary_entries(dictionary)
        .into_iter()
        .filter_map(|(key, value)| {
            if key.is_null() || cf_type_id(key) != unsafe { ffi::CFStringGetTypeID() } {
                return None;
            }
            let key = cf_string_to_string(key.cast())?;
            Some((key, cf_type_to_value(value.cast())))
        })
        .collect()
}

fn cf_type_to_value(value: ffi::CFTypeRef) -> SigningValue {
    if value.is_null() {
        return SigningValue::Unknown("null".to_owned());
    }

    let type_id = cf_type_id(value);
    if type_id == unsafe { ffi::CFBooleanGetTypeID() } {
        return SigningValue::Boolean(cf_boolean_to_bool(value.cast()));
    }
    if type_id == unsafe { ffi::CFNumberGetTypeID() } {
        return cf_number_to_i64(value.cast()).map_or_else(
            || SigningValue::Unknown("number".to_owned()),
            SigningValue::Integer,
        );
    }
    if type_id == unsafe { ffi::CFStringGetTypeID() } {
        return cf_string_to_string(value.cast()).map_or_else(
            || SigningValue::Unknown("string".to_owned()),
            SigningValue::String,
        );
    }
    if type_id == unsafe { ffi::CFDataGetTypeID() } {
        return SigningValue::Data(cf_data_to_vec(value.cast()));
    }
    if type_id == unsafe { ffi::CFArrayGetTypeID() } {
        let count = unsafe { ffi::CFArrayGetCount(value.cast()) };
        let count = usize::try_from(count).unwrap_or_default();
        let values = (0..count)
            .filter_map(|index| isize::try_from(index).ok())
            .map(|index| unsafe { ffi::CFArrayGetValueAtIndex(value.cast(), index) })
            .filter(|value| !value.is_null())
            .map(|value| cf_type_to_value(value.cast()))
            .collect();
        return SigningValue::Array(values);
    }
    if type_id == unsafe { ffi::CFDictionaryGetTypeID() } {
        return SigningValue::Dictionary(cf_dictionary_to_map(value.cast()));
    }

    SigningValue::Unknown(format!("CFTypeID({type_id})"))
}
