use base64::Engine;
use bitflags::bitflags;
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::bridge;
use crate::error::Result;

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct CodeSigningFlags: u32 {
        const CHECK_ALL_ARCHITECTURES = 1 << 0;
        const DO_NOT_VALIDATE_EXECUTABLE = 1 << 1;
        const DO_NOT_VALIDATE_RESOURCES = 1 << 2;
        const BASIC_VALIDATE_ONLY = Self::DO_NOT_VALIDATE_EXECUTABLE.bits() | Self::DO_NOT_VALIDATE_RESOURCES.bits();
        const CHECK_NESTED_CODE = 1 << 3;
        const STRICT_VALIDATE = 1 << 4;
        const FULL_REPORT = 1 << 5;
        const CHECK_GATEKEEPER_ARCHITECTURES = (1 << 6) | Self::CHECK_ALL_ARCHITECTURES.bits();
        const RESTRICT_SYMLINKS = 1 << 7;
        const RESTRICT_TO_APP_LIKE = 1 << 8;
        const RESTRICT_SIDEBAND_DATA = 1 << 9;
        const USE_SOFTWARE_SIGNING_CERT = 1 << 10;
        const VALIDATE_PEH = 1 << 11;
        const SINGLE_THREADED = 1 << 12;
        const ALLOW_NETWORK_ACCESS = 1 << 16;
        const FAST_EXECUTABLE_VALIDATION = 1 << 17;

        const SIGNING_INFORMATION = 1 << 1;
        const DYNAMIC_INFORMATION = 1 << 3;
        const USE_ALL_ARCHITECTURES = 1 << 0;
    }
}

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
    pub fn type_id() -> usize {
        unsafe { bridge::security_code_get_type_id() }
    }

    pub fn current() -> Result<Self> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe { bridge::security_code_copy_self(&mut status, &mut error) };
        bridge::required_handle("security_code_copy_self", raw, status, error).map(|handle| Self {
            handle,
        })
    }

    pub fn host(&self) -> Result<Self> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_code_copy_host(self.handle.as_ptr(), &mut status, &mut error)
        };
        bridge::required_handle("security_code_copy_host", raw, status, error).map(|handle| Self {
            handle,
        })
    }

    pub fn guest_with_attributes(
        host: Option<&Self>,
        attributes: Option<&Value>,
        flags: CodeSigningFlags,
    ) -> Result<Self> {
        let attributes = attributes.map(bridge::json_cstring).transpose()?;
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_code_copy_guest_with_attributes(
                host.map_or(std::ptr::null_mut(), |value| value.handle.as_ptr()),
                attributes.as_ref().map_or(std::ptr::null(), |value| value.as_ptr()),
                flags.bits(),
                &mut status,
                &mut error,
            )
        };
        bridge::required_handle(
            "security_code_copy_guest_with_attributes",
            raw,
            status,
            error,
        )
        .map(|handle| Self { handle })
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
pub struct Requirement {
    handle: bridge::Handle,
}

impl Requirement {
    fn from_handle(handle: bridge::Handle) -> Self {
        Self { handle }
    }

    fn handle(&self) -> &bridge::Handle {
        &self.handle
    }

    pub fn type_id() -> usize {
        unsafe { bridge::security_requirement_get_type_id() }
    }

    pub fn from_data(data: &[u8]) -> Result<Self> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_requirement_create_with_data(
                data.as_ptr().cast(),
                bridge::len_to_isize(data.len())?,
                &mut status,
                &mut error,
            )
        };
        bridge::required_handle("security_requirement_create_with_data", raw, status, error)
            .map(Self::from_handle)
    }

    pub fn from_string(text: &str) -> Result<Self> {
        let text = bridge::cstring(text)?;
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_requirement_create_with_string(text.as_ptr(), &mut status, &mut error)
        };
        bridge::required_handle("security_requirement_create_with_string", raw, status, error)
            .map(Self::from_handle)
    }

    pub fn from_string_with_errors(text: &str) -> Result<Self> {
        let text = bridge::cstring(text)?;
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_requirement_create_with_string_and_errors(
                text.as_ptr(),
                &mut status,
                &mut error,
            )
        };
        bridge::required_handle(
            "security_requirement_create_with_string_and_errors",
            raw,
            status,
            error,
        )
        .map(Self::from_handle)
    }

    pub fn data(&self) -> Result<Vec<u8>> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_requirement_copy_data(self.handle.as_ptr(), &mut status, &mut error)
        };
        bridge::required_data("security_requirement_copy_data", raw, status, error)
    }

    pub fn string(&self) -> Result<String> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_requirement_copy_string(self.handle.as_ptr(), &mut status, &mut error)
        };
        bridge::required_string("security_requirement_copy_string", raw, status, error)
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

    pub fn type_id() -> usize {
        unsafe { bridge::security_static_code_get_type_id() }
    }

    pub fn from_path(path: impl AsRef<Path>) -> Result<Self> {
        let path = bridge::cstring(&path.as_ref().to_string_lossy())?;
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_static_code_create_with_path(path.as_ptr(), &mut status, &mut error)
        };
        bridge::required_handle("security_static_code_create_with_path", raw, status, error)
            .map(Self::from_handle)
    }

    pub fn from_path_with_attributes(path: impl AsRef<Path>, attributes: &Value) -> Result<Self> {
        let path = bridge::cstring(&path.as_ref().to_string_lossy())?;
        let attributes = bridge::json_cstring(attributes)?;
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_static_code_create_with_path_and_attributes(
                path.as_ptr(),
                attributes.as_ptr(),
                &mut status,
                &mut error,
            )
        };
        bridge::required_handle(
            "security_static_code_create_with_path_and_attributes",
            raw,
            status,
            error,
        )
        .map(Self::from_handle)
    }

    pub fn check_validity(&self) -> Result<()> {
        let mut error = std::ptr::null_mut();
        let status = unsafe {
            bridge::security_static_code_check_validity(self.handle.as_ptr(), &mut error)
        };
        bridge::status_result("security_static_code_check_validity", status, error)
    }

    pub fn check_validity_with_errors(
        &self,
        flags: CodeSigningFlags,
        requirement: Option<&Requirement>,
    ) -> Result<()> {
        let mut error = std::ptr::null_mut();
        let status = unsafe {
            bridge::security_static_code_check_validity_with_errors(
                self.handle.as_ptr(),
                flags.bits(),
                requirement.map_or(std::ptr::null_mut(), |value| value.handle().as_ptr()),
                &mut error,
            )
        };
        bridge::status_result(
            "security_static_code_check_validity_with_errors",
            status,
            error,
        )
    }

    pub fn check_static_validity(
        &self,
        flags: CodeSigningFlags,
        requirement: Option<&Requirement>,
    ) -> Result<()> {
        let mut error = std::ptr::null_mut();
        let status = unsafe {
            bridge::security_static_code_check_static_validity(
                self.handle.as_ptr(),
                flags.bits(),
                requirement.map_or(std::ptr::null_mut(), |value| value.handle().as_ptr()),
                &mut error,
            )
        };
        bridge::status_result("security_static_code_check_static_validity", status, error)
    }

    pub fn check_static_validity_with_errors(
        &self,
        flags: CodeSigningFlags,
        requirement: Option<&Requirement>,
    ) -> Result<()> {
        let mut error = std::ptr::null_mut();
        let status = unsafe {
            bridge::security_static_code_check_static_validity_with_errors(
                self.handle.as_ptr(),
                flags.bits(),
                requirement.map_or(std::ptr::null_mut(), |value| value.handle().as_ptr()),
                &mut error,
            )
        };
        bridge::status_result(
            "security_static_code_check_static_validity_with_errors",
            status,
            error,
        )
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

    pub fn validate_file_resource(
        &self,
        relative_path: &str,
        data: &[u8],
        flags: CodeSigningFlags,
    ) -> Result<()> {
        let relative_path = bridge::cstring(relative_path)?;
        let mut error = std::ptr::null_mut();
        let status = unsafe {
            bridge::security_static_code_validate_file_resource(
                self.handle.as_ptr(),
                relative_path.as_ptr(),
                data.as_ptr().cast(),
                bridge::len_to_isize(data.len())?,
                flags.bits(),
                &mut error,
            )
        };
        bridge::status_result("security_static_code_validate_file_resource", status, error)
    }

    pub fn map_memory(&self, flags: CodeSigningFlags) -> Result<()> {
        let mut error = std::ptr::null_mut();
        let status = unsafe {
            bridge::security_static_code_map_memory(self.handle.as_ptr(), flags.bits(), &mut error)
        };
        bridge::status_result("security_static_code_map_memory", status, error)
    }
}

#[derive(Debug)]
pub struct Task {
    handle: bridge::Handle,
}

impl Task {
    pub fn type_id() -> usize {
        unsafe { bridge::security_task_get_type_id() }
    }

    pub fn current() -> Result<Self> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe { bridge::security_task_create_from_self(&mut status, &mut error) };
        bridge::required_handle("security_task_create_from_self", raw, status, error).map(|handle| Self {
            handle,
        })
    }

    pub fn current_with_audit_token() -> Result<Self> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_task_create_from_current_audit_token(&mut status, &mut error)
        };
        bridge::required_handle(
            "security_task_create_from_current_audit_token",
            raw,
            status,
            error,
        )
        .map(|handle| Self { handle })
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

    pub fn entitlements(&self, entitlements: &[&str]) -> Result<Value> {
        let entitlements = bridge::json_cstring(&entitlements)?;
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_task_copy_values_for_entitlements(
                self.handle.as_ptr(),
                entitlements.as_ptr(),
                &mut status,
                &mut error,
            )
        };
        bridge::required_json(
            "security_task_copy_values_for_entitlements",
            raw,
            status,
            error,
        )
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
