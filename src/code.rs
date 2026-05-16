use base64::Engine;
use std::collections::BTreeMap;
use std::path::PathBuf;

use serde_json::Value;

use crate::bridge;
use crate::error::Result;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningInformation {
    pub identifier: Option<String>,
    pub team_identifier: Option<String>,
    pub entitlements: BTreeMap<String, SigningValue>,
    pub sandboxed: bool,
    pub status: Option<u32>,
}

impl SigningInformation {
    pub const fn is_signed(&self) -> bool {
        self.identifier.is_some()
    }
}

#[derive(Debug)]
pub struct Code {
    handle: bridge::Handle,
}

impl Code {
    pub fn current() -> Result<Self> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe { bridge::security_code_copy_self(&mut status, &mut error) };
        bridge::required_handle("security_code_copy_self", raw, status, error).map(|handle| Self {
            handle,
        })
    }

    pub fn static_code(&self) -> Result<StaticCode> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_code_copy_static_code(self.handle.as_ptr(), &mut status, &mut error)
        };
        bridge::required_handle("security_code_copy_static_code", raw, status, error)
            .map(StaticCode::from_handle)
    }

    pub fn signing_information(&self) -> Result<SigningInformation> {
        self.static_code()?.signing_information()
    }

    pub fn task(&self) -> Result<Task> {
        Task::current()
    }
}

#[derive(Debug)]
pub struct StaticCode {
    handle: bridge::Handle,
}

impl StaticCode {
    fn from_handle(handle: bridge::Handle) -> Self {
        Self { handle }
    }

    pub fn check_validity(&self) -> Result<()> {
        let mut error = std::ptr::null_mut();
        let status = unsafe {
            bridge::security_static_code_check_validity(self.handle.as_ptr(), &mut error)
        };
        bridge::status_result("security_static_code_check_validity", status, error)
    }

    pub fn path(&self) -> Result<PathBuf> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_static_code_copy_path(self.handle.as_ptr(), &mut status, &mut error)
        };
        bridge::required_string("security_static_code_copy_path", raw, status, error)
            .map(PathBuf::from)
    }

    pub fn designated_requirement(&self) -> Result<String> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_static_code_copy_designated_requirement(
                self.handle.as_ptr(),
                &mut status,
                &mut error,
            )
        };
        bridge::required_string(
            "security_static_code_copy_designated_requirement",
            raw,
            status,
            error,
        )
    }

    pub fn signing_information(&self) -> Result<SigningInformation> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_static_code_copy_signing_information(
                self.handle.as_ptr(),
                &mut status,
                &mut error,
            )
        };
        let value: Value = bridge::required_json(
            "security_static_code_copy_signing_information",
            raw,
            status,
            error,
        )?;
        Ok(SigningInformation {
            identifier: find_string(&value, &["identifier", "Identifier"]),
            team_identifier: find_string(&value, &["teamid", "TeamIdentifier", "teamIdentifier"]),
            entitlements: find_object(
                &value,
                &[
                    "entitlements-dict",
                    "EntitlementsDict",
                    "entitlements",
                    "Entitlements",
                ],
            )
            .map(json_object_to_map)
            .unwrap_or_default(),
            sandboxed: matches!(
                find_object(
                    &value,
                    &[
                        "entitlements-dict",
                        "EntitlementsDict",
                        "entitlements",
                        "Entitlements",
                    ],
                )
                .and_then(|value| value.get("com.apple.security.app-sandbox")),
                Some(Value::Bool(true))
            ),
            status: find_integer(&value, &["status", "Status"]).and_then(|value| u32::try_from(value).ok()),
        })
    }
}

#[derive(Debug)]
pub struct Task {
    handle: bridge::Handle,
}

impl Task {
    pub fn current() -> Result<Self> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe { bridge::security_task_create_from_self(&mut status, &mut error) };
        bridge::required_handle("security_task_create_from_self", raw, status, error).map(|handle| Self {
            handle,
        })
    }

    pub fn signing_identifier(&self) -> Result<Option<String>> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_task_copy_signing_identifier(self.handle.as_ptr(), &mut status, &mut error)
        };
        if raw.is_null() && status == 0 {
            Ok(None)
        } else {
            bridge::required_string("security_task_copy_signing_identifier", raw, status, error)
                .map(Some)
        }
    }

    pub fn entitlement(&self, entitlement: &str) -> Result<Option<Value>> {
        let entitlement = bridge::cstring(entitlement)?;
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_task_copy_value_for_entitlement(
                self.handle.as_ptr(),
                entitlement.as_ptr(),
                &mut status,
                &mut error,
            )
        };
        if raw.is_null() && status == 0 {
            return Ok(None);
        }
        let value: Value = bridge::required_json(
            "security_task_copy_value_for_entitlement",
            raw,
            status,
            error,
        )?;
        Ok(Some(value))
    }
}

fn find_object<'a>(value: &'a Value, keys: &[&str]) -> Option<&'a serde_json::Map<String, Value>> {
    keys.iter()
        .find_map(|key| value.get(*key))
        .and_then(Value::as_object)
}

fn find_string(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| value.get(*key))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

fn find_integer(value: &Value, keys: &[&str]) -> Option<i64> {
    keys.iter()
        .find_map(|key| value.get(*key))
        .and_then(Value::as_i64)
}

fn json_object_to_map(object: &serde_json::Map<String, Value>) -> BTreeMap<String, SigningValue> {
    object
        .iter()
        .map(|(key, value)| (key.clone(), signing_value(value)))
        .collect()
}

fn signing_value(value: &Value) -> SigningValue {
    match value {
        Value::Bool(value) => SigningValue::Boolean(*value),
        Value::Number(value) => value
            .as_i64()
            .map_or_else(|| SigningValue::Unknown(value.to_string()), SigningValue::Integer),
        Value::String(value) => SigningValue::String(value.clone()),
        Value::Array(values) => {
            if let Some(data) = data_from_wrapped_json(value) {
                SigningValue::Data(data)
            } else {
                SigningValue::Array(values.iter().map(signing_value).collect())
            }
        }
        Value::Object(object) => {
            if let Some(data) = data_from_wrapped_json(value) {
                SigningValue::Data(data)
            } else {
                SigningValue::Dictionary(json_object_to_map(object))
            }
        }
        Value::Null => SigningValue::Unknown("null".to_owned()),
    }
}

fn data_from_wrapped_json(value: &Value) -> Option<Vec<u8>> {
    let object = value.as_object()?;
    if object.get("_type")?.as_str()? != "data" {
        return None;
    }
    let base64 = object.get("base64")?.as_str()?;
    base64::engine::general_purpose::STANDARD.decode(base64).ok()
}
