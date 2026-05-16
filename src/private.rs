use std::ffi::CString;
use std::ptr;

use apple_cf::CFError;

use crate::error::{Result, SecurityError};
use crate::ffi;

pub struct OwnedCf {
    raw: ffi::CFTypeRef,
}

impl OwnedCf {
    pub const fn new(raw: ffi::CFTypeRef) -> Self {
        Self { raw }
    }

    pub const fn as_ptr(&self) -> ffi::CFTypeRef {
        self.raw
    }

    pub const fn as_string(&self) -> ffi::CFStringRef {
        self.raw.cast()
    }

    pub const fn as_data(&self) -> ffi::CFDataRef {
        self.raw.cast()
    }

    pub const fn as_array(&self) -> ffi::CFArrayRef {
        self.raw.cast()
    }

    pub const fn as_dictionary(&self) -> ffi::CFDictionaryRef {
        self.raw.cast()
    }

    pub const fn as_mut_dictionary(&self) -> ffi::CFMutableDictionaryRef {
        self.raw.cast_mut()
    }
}

impl Drop for OwnedCf {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            unsafe { ffi::CFRelease(self.raw) };
        }
    }
}

pub fn checked_cf(raw: ffi::CFTypeRef, operation: &'static str) -> Result<OwnedCf> {
    if raw.is_null() {
        return Err(SecurityError::CoreFoundation(CFError::new(operation)));
    }
    Ok(OwnedCf::new(raw))
}

pub fn cf_string(value: &str) -> Result<OwnedCf> {
    let c_string = CString::new(value).map_err(|error| {
        SecurityError::InvalidArgument(format!("string contains interior NUL: {error}"))
    })?;
    let raw = unsafe {
        ffi::CFStringCreateWithCString(
            ffi::kCFAllocatorDefault,
            c_string.as_ptr(),
            ffi::kCFStringEncodingUTF8,
        )
    };
    checked_cf(raw.cast(), "CFStringCreateWithCString")
}

pub fn cf_data(bytes: &[u8]) -> Result<OwnedCf> {
    let length = isize::try_from(bytes.len()).map_err(|_| {
        SecurityError::InvalidArgument("byte slice is too large for CFDataCreate".to_owned())
    })?;
    let raw = unsafe { ffi::CFDataCreate(ffi::kCFAllocatorDefault, bytes.as_ptr(), length) };
    checked_cf(raw.cast(), "CFDataCreate")
}

pub fn cf_array(values: &[ffi::CFTypeRef]) -> Result<OwnedCf> {
    let count = isize::try_from(values.len()).map_err(|_| {
        SecurityError::InvalidArgument("array is too large for CFArrayCreate".to_owned())
    })?;
    let raw = unsafe {
        ffi::CFArrayCreate(
            ffi::kCFAllocatorDefault,
            values.as_ptr().cast(),
            count,
            &raw const ffi::kCFTypeArrayCallBacks,
        )
    };
    checked_cf(raw.cast(), "CFArrayCreate")
}

pub fn cf_mutable_dictionary(capacity: usize) -> Result<OwnedCf> {
    let capacity = isize::try_from(capacity).map_err(|_| {
        SecurityError::InvalidArgument("dictionary capacity exceeds CFIndex".to_owned())
    })?;
    let raw = unsafe {
        ffi::CFDictionaryCreateMutable(
            ffi::kCFAllocatorDefault,
            capacity,
            &raw const ffi::kCFTypeDictionaryKeyCallBacks,
            &raw const ffi::kCFTypeDictionaryValueCallBacks,
        )
    };
    checked_cf(raw.cast(), "CFDictionaryCreateMutable")
}

pub unsafe fn cf_dictionary_set_value(
    dictionary: ffi::CFMutableDictionaryRef,
    key: ffi::CFStringRef,
    value: ffi::CFTypeRef,
) {
    ffi::CFDictionarySetValue(dictionary, key.cast(), value.cast());
}

pub fn cf_dictionary_get_value(
    dictionary: ffi::CFDictionaryRef,
    key: ffi::CFStringRef,
) -> ffi::CFTypeRef {
    unsafe { ffi::CFDictionaryGetValue(dictionary, key.cast()).cast() }
}

pub fn cf_dictionary_entries(
    dictionary: ffi::CFDictionaryRef,
) -> Vec<(ffi::CFTypeRef, ffi::CFTypeRef)> {
    let count = unsafe { ffi::CFDictionaryGetCount(dictionary) };
    let Ok(count) = usize::try_from(count) else {
        return Vec::new();
    };
    let mut keys = vec![ptr::null(); count];
    let mut values = vec![ptr::null(); count];
    unsafe {
        ffi::CFDictionaryGetKeysAndValues(dictionary, keys.as_mut_ptr(), values.as_mut_ptr());
    };
    keys.into_iter().zip(values).collect()
}

pub fn cf_string_to_string(value: ffi::CFStringRef) -> Option<String> {
    if value.is_null() {
        return None;
    }
    let length = unsafe { ffi::CFStringGetLength(value) };
    let length = usize::try_from(length).ok()?;
    let capacity = length.checked_mul(4)?.checked_add(1)?;
    let capacity_index = isize::try_from(capacity).ok()?;
    let mut buffer = vec![0_u8; capacity];
    let ok = unsafe {
        ffi::CFStringGetCString(
            value,
            buffer.as_mut_ptr().cast(),
            capacity_index,
            ffi::kCFStringEncodingUTF8,
        )
    };
    if !ok {
        return None;
    }
    if let Some(end) = buffer.iter().position(|&byte| byte == 0) {
        buffer.truncate(end);
    }
    String::from_utf8(buffer).ok()
}

pub fn cf_data_to_vec(value: ffi::CFDataRef) -> Vec<u8> {
    if value.is_null() {
        return Vec::new();
    }
    let length = unsafe { ffi::CFDataGetLength(value) };
    let Ok(length) = usize::try_from(length) else {
        return Vec::new();
    };
    let bytes = unsafe { ffi::CFDataGetBytePtr(value) };
    if bytes.is_null() {
        return Vec::new();
    }
    unsafe { std::slice::from_raw_parts(bytes, length) }.to_vec()
}

pub fn cf_number_to_i64(value: ffi::CFNumberRef) -> Option<i64> {
    if value.is_null() {
        return None;
    }
    let mut out = 0_i64;
    let ok = unsafe {
        ffi::CFNumberGetValue(
            value,
            ffi::kCFNumberSInt64Type,
            std::ptr::addr_of_mut!(out).cast(),
        )
    };
    ok.then_some(out)
}

pub fn cf_boolean_to_bool(value: ffi::CFBooleanRef) -> bool {
    if value.is_null() {
        return false;
    }
    unsafe { ffi::CFBooleanGetValue(value) }
}

pub fn cf_type_id(value: ffi::CFTypeRef) -> ffi::CFTypeID {
    unsafe { ffi::CFGetTypeID(value) }
}

pub fn sec_error_message(status: ffi::OSStatus) -> String {
    let raw = unsafe { ffi::SecCopyErrorMessageString(status, ptr::null_mut()) };
    if raw.is_null() {
        return format!("OSStatus {status}");
    }
    let owned = OwnedCf::new(raw.cast());
    cf_string_to_string(owned.as_string()).unwrap_or_else(|| format!("OSStatus {status}"))
}

pub fn cf_error_description(error: ffi::CFErrorRef) -> String {
    if error.is_null() {
        return "trust evaluation failed".to_owned();
    }
    let raw = unsafe { ffi::CFErrorCopyDescription(error) };
    let description = if raw.is_null() {
        "trust evaluation failed".to_owned()
    } else {
        let owned = OwnedCf::new(raw.cast());
        cf_string_to_string(owned.as_string())
            .unwrap_or_else(|| "trust evaluation failed".to_owned())
    };
    unsafe { ffi::CFRelease(error.cast()) };
    description
}
