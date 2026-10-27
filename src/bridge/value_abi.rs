use std::collections::BTreeMap;
use std::ffi::c_void;
use std::mem::{offset_of, size_of};
use std::ptr;
use std::slice;

use super::Handle;
use crate::error::{Result, SecurityError};
use crate::Value;

#[derive(Clone, Copy)]
#[repr(C)]
pub(crate) struct AbiBuffer {
    data: *const u8,
    length: usize,
}

impl AbiBuffer {
    pub(crate) fn new(bytes: &[u8]) -> Self {
        Self {
            data: bytes.as_ptr(),
            length: bytes.len(),
        }
    }
}

#[derive(Clone, Copy)]
#[repr(C)]
pub(crate) struct AbiValue {
    tag: u32,
    reserved: u32,
    integer: i64,
    unsigned_integer: u64,
    real: f64,
    bytes: *const u8,
    length: usize,
    values: *const Self,
    entries: *const AbiEntry,
}

#[derive(Clone, Copy)]
#[repr(C)]
struct AbiEntry {
    key: AbiBuffer,
    value: AbiValue,
}

const _: () = assert!(size_of::<AbiBuffer>() == 16);
const _: () = assert!(size_of::<AbiValue>() == 64);
const _: () = assert!(size_of::<AbiEntry>() == 80);
const _: () = assert!(offset_of!(AbiValue, integer) == 8);
const _: () = assert!(offset_of!(AbiValue, bytes) == 32);
const _: () = assert!(offset_of!(AbiValue, entries) == 56);

unsafe extern "C" {
    fn security_value_get(handle: *mut c_void) -> *const AbiValue;
}

impl AbiValue {
    const fn new(tag: u32) -> Self {
        Self {
            tag,
            reserved: 0,
            integer: 0,
            unsigned_integer: 0,
            real: 0.0,
            bytes: ptr::null(),
            length: 0,
            values: ptr::null(),
            entries: ptr::null(),
        }
    }
}

pub(crate) struct InputValue {
    raw: AbiValue,
    bytes: Vec<Vec<u8>>,
    arrays: Vec<Vec<AbiValue>>,
    objects: Vec<Vec<AbiEntry>>,
}

impl InputValue {
    pub(crate) fn new(value: &Value) -> Result<Self> {
        let mut input = Self {
            raw: AbiValue::new(0),
            bytes: Vec::new(),
            arrays: Vec::new(),
            objects: Vec::new(),
        };
        input.raw = input.encode(value, 0)?;
        Ok(input)
    }

    pub(crate) fn strings(values: &[&str]) -> Result<Self> {
        Self::new(&Value::Array(
            values
                .iter()
                .map(|value| Value::String((*value).to_owned()))
                .collect(),
        ))
    }

    pub(crate) fn data_array(values: &[Vec<u8>]) -> Result<Self> {
        Self::new(&Value::Array(
            values.iter().cloned().map(Value::Data).collect(),
        ))
    }

    pub(crate) const fn as_ptr(&self) -> *const AbiValue {
        &raw const self.raw
    }

    fn buffer(&mut self, bytes: &[u8]) -> AbiBuffer {
        let bytes = bytes.to_vec();
        let buffer = AbiBuffer {
            data: bytes.as_ptr(),
            length: bytes.len(),
        };
        self.bytes.push(bytes);
        buffer
    }

    fn encode(&mut self, value: &Value, depth: usize) -> Result<AbiValue> {
        if depth > 128 {
            return Err(SecurityError::InvalidArgument(
                "bridge value exceeds the nesting limit".to_owned(),
            ));
        }
        let mut raw = AbiValue::new(0);
        match value {
            Value::Null => {}
            Value::Bool(value) => {
                raw.tag = 1;
                raw.unsigned_integer = u64::from(*value);
            }
            Value::Integer(value) => {
                raw.tag = 2;
                raw.integer = *value;
            }
            Value::Unsigned(value) => {
                raw.tag = 3;
                raw.unsigned_integer = *value;
            }
            Value::Real(value) | Value::Date(value) => {
                if !value.is_finite() {
                    return Err(SecurityError::InvalidArgument(
                        "bridge numbers must be finite".to_owned(),
                    ));
                }
                raw.tag = 4;
                raw.real = *value;
            }
            Value::String(value) | Value::Url(value) => {
                raw.tag = 5;
                let buffer = self.buffer(value.as_bytes());
                raw.bytes = buffer.data;
                raw.length = buffer.length;
            }
            Value::Data(value) => {
                raw.tag = 6;
                let buffer = self.buffer(value);
                raw.bytes = buffer.data;
                raw.length = buffer.length;
            }
            Value::Array(values) => {
                raw.tag = 9;
                let values = values
                    .iter()
                    .map(|value| self.encode(value, depth + 1))
                    .collect::<Result<Vec<_>>>()?;
                raw.values = values.as_ptr();
                raw.length = values.len();
                self.arrays.push(values);
            }
            Value::Object(values) => {
                raw.tag = 10;
                let entries = values
                    .iter()
                    .map(|(key, value)| {
                        Ok(AbiEntry {
                            key: self.buffer(key.as_bytes()),
                            value: self.encode(value, depth + 1)?,
                        })
                    })
                    .collect::<Result<Vec<_>>>()?;
                raw.entries = entries.as_ptr();
                raw.length = entries.len();
                self.objects.push(entries);
            }
        }
        raw.tag = match value {
            Value::Date(_) => 7,
            Value::Url(_) => 8,
            _ => raw.tag,
        };
        Ok(raw)
    }
}

pub(crate) fn read_value(handle: &Handle) -> Result<Value> {
    let pointer = unsafe { security_value_get(handle.as_ptr()) };
    if pointer.is_null() || !pointer.is_aligned() {
        return Err(invalid_value());
    }
    unsafe { decode(&*pointer, 0) }
}

fn invalid_value() -> SecurityError {
    SecurityError::Serialization("invalid binary bridge value".to_owned())
}

unsafe fn checked_slice<'a, T>(pointer: *const T, length: usize) -> Result<&'a [T]> {
    if length == 0 {
        return Ok(&[]);
    }
    if pointer.is_null()
        || !pointer.is_aligned()
        || length > isize::MAX.unsigned_abs() / size_of::<T>()
    {
        return Err(invalid_value());
    }
    Ok(unsafe { slice::from_raw_parts(pointer, length) })
}

pub(crate) unsafe fn decode(raw: &AbiValue, depth: usize) -> Result<Value> {
    if depth > 128 || raw.reserved != 0 {
        return Err(invalid_value());
    }
    Ok(match raw.tag {
        0 => Value::Null,
        1 if raw.unsigned_integer <= 1 => Value::Bool(raw.unsigned_integer != 0),
        2 => Value::Integer(raw.integer),
        3 => Value::Unsigned(raw.unsigned_integer),
        4 => Value::Real(raw.real),
        5 | 8 => {
            let bytes = unsafe { checked_slice(raw.bytes, raw.length)? };
            let text = std::str::from_utf8(bytes)
                .map_err(|_| invalid_value())?
                .to_owned();
            if raw.tag == 5 {
                Value::String(text)
            } else {
                Value::Url(text)
            }
        }
        6 => Value::Data(unsafe { checked_slice(raw.bytes, raw.length)? }.to_vec()),
        7 => Value::Date(raw.real),
        9 => {
            let values = unsafe { checked_slice(raw.values, raw.length)? };
            Value::Array(
                values
                    .iter()
                    .map(|value| unsafe { decode(value, depth + 1) })
                    .collect::<Result<_>>()?,
            )
        }
        10 => {
            let entries = unsafe { checked_slice(raw.entries, raw.length)? };
            let mut values = BTreeMap::new();
            for entry in entries {
                let bytes = unsafe { checked_slice(entry.key.data, entry.key.length)? };
                let key = std::str::from_utf8(bytes).map_err(|_| invalid_value())?;
                values.insert(key.to_owned(), unsafe { decode(&entry.value, depth + 1)? });
            }
            Value::Object(values)
        }
        _ => return Err(invalid_value()),
    })
}
