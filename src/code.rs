use crate::Value;
use std::collections::BTreeMap;
use std::ffi::c_void;
use std::path::{Path, PathBuf};

use crate::bridge;
use crate::error::{Result, SecurityError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
#[must_use]
/// Mirrors `SecCSFlags`.
pub struct CodeSigningFlags(u32);

impl CodeSigningFlags {
    /// Mirrors a `SecCSFlags` bit.
    pub const CHECK_ALL_ARCHITECTURES: Self = Self(1 << 0);
    /// Mirrors a `SecCSFlags` bit.
    pub const DO_NOT_VALIDATE_EXECUTABLE: Self = Self(1 << 1);
    /// Mirrors a `SecCSFlags` bit.
    pub const DO_NOT_VALIDATE_RESOURCES: Self = Self(1 << 2);
    /// Mirrors a `SecCSFlags` bit.
    pub const BASIC_VALIDATE_ONLY: Self =
        Self(Self::DO_NOT_VALIDATE_EXECUTABLE.0 | Self::DO_NOT_VALIDATE_RESOURCES.0);
    /// Mirrors a `SecCSFlags` bit.
    pub const CHECK_NESTED_CODE: Self = Self(1 << 3);
    /// Mirrors a `SecCSFlags` bit.
    pub const STRICT_VALIDATE: Self = Self(1 << 4);
    /// Mirrors a `SecCSFlags` bit.
    pub const FULL_REPORT: Self = Self(1 << 5);
    /// Mirrors a `SecCSFlags` bit.
    pub const CHECK_GATEKEEPER_ARCHITECTURES: Self =
        Self((1 << 6) | Self::CHECK_ALL_ARCHITECTURES.0);
    /// Mirrors a `SecCSFlags` bit.
    pub const RESTRICT_SYMLINKS: Self = Self(1 << 7);
    /// Mirrors a `SecCSFlags` bit.
    pub const RESTRICT_TO_APP_LIKE: Self = Self(1 << 8);
    /// Mirrors a `SecCSFlags` bit.
    pub const RESTRICT_SIDEBAND_DATA: Self = Self(1 << 9);
    /// Mirrors a `SecCSFlags` bit.
    pub const USE_SOFTWARE_SIGNING_CERT: Self = Self(1 << 10);
    /// Mirrors a `SecCSFlags` bit.
    pub const VALIDATE_PEH: Self = Self(1 << 11);
    /// Mirrors a `SecCSFlags` bit.
    pub const SINGLE_THREADED: Self = Self(1 << 12);
    /// Mirrors a `SecCSFlags` bit.
    pub const ALLOW_NETWORK_ACCESS: Self = Self(1 << 16);
    /// Mirrors a `SecCSFlags` bit.
    pub const FAST_EXECUTABLE_VALIDATION: Self = Self(1 << 17);
    pub const CHECK_TRUSTED_ANCHORS: Self = Self(1 << 27);
    pub const NO_NETWORK_ACCESS: Self = Self(1 << 29);
    pub const ENFORCE_REVOCATION_CHECKS: Self = Self(1 << 30);
    pub const CONSIDER_EXPIRATION: Self = Self(1 << 31);

    pub const fn empty() -> Self {
        Self(0)
    }
    pub const fn all() -> Self {
        Self(0xe803_1fff)
    }
    pub const fn bits(self) -> u32 {
        self.0
    }
    pub const fn from_bits(bits: u32) -> Option<Self> {
        if bits & !Self::all().0 == 0 {
            Some(Self(bits))
        } else {
            None
        }
    }
    pub const fn from_bits_retain(bits: u32) -> Self {
        Self(bits)
    }
    pub const fn from_bits_truncate(bits: u32) -> Self {
        Self(bits & Self::all().0)
    }
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
    pub const fn is_all(self) -> bool {
        self.0 & Self::all().0 == Self::all().0
    }
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
    pub const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
    pub const fn intersection(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }
    pub const fn difference(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }
    pub const fn symmetric_difference(self, other: Self) -> Self {
        Self(self.0 ^ other.0)
    }
    pub const fn complement(self) -> Self {
        Self(!self.0 & Self::all().0)
    }
    pub fn insert(&mut self, other: Self) {
        self.0 |= other.0;
    }
    pub fn remove(&mut self, other: Self) {
        self.0 &= !other.0;
    }
    pub fn toggle(&mut self, other: Self) {
        self.0 ^= other.0;
    }
    pub fn set(&mut self, other: Self, value: bool) {
        if value {
            self.0 |= other.0;
        } else {
            self.0 &= !other.0;
        }
    }
}

impl std::ops::BitOr for CodeSigningFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}
impl std::ops::BitAnd for CodeSigningFlags {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
}
impl std::ops::BitXor for CodeSigningFlags {
    type Output = Self;
    fn bitxor(self, rhs: Self) -> Self {
        Self(self.0 ^ rhs.0)
    }
}
impl std::ops::Sub for CodeSigningFlags {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        Self(self.0 & !rhs.0)
    }
}
impl std::ops::Not for CodeSigningFlags {
    type Output = Self;
    fn not(self) -> Self {
        Self(!self.0 & Self::all().0)
    }
}
impl std::ops::BitOrAssign for CodeSigningFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}
impl std::ops::BitAndAssign for CodeSigningFlags {
    fn bitand_assign(&mut self, rhs: Self) {
        self.0 &= rhs.0;
    }
}
impl std::ops::BitXorAssign for CodeSigningFlags {
    fn bitxor_assign(&mut self, rhs: Self) {
        self.0 ^= rhs.0;
    }
}
impl std::ops::SubAssign for CodeSigningFlags {
    fn sub_assign(&mut self, rhs: Self) {
        self.0 &= !rhs.0;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
#[must_use]
pub struct CodeStatus(u32);

impl CodeStatus {
    pub const VALID: Self = Self(0x0000_0001);
    pub const HARD: Self = Self(0x0000_0100);
    pub const KILL: Self = Self(0x0000_0200);
    pub const PLATFORM: Self = Self(0x0400_0000);
    pub const DEBUGGED: Self = Self(0x1000_0000);

    pub const fn empty() -> Self {
        Self(0)
    }
    pub const fn all() -> Self {
        Self(0x1400_0301)
    }
    pub const fn bits(self) -> u32 {
        self.0
    }
    pub const fn from_bits(bits: u32) -> Option<Self> {
        if bits & !Self::all().0 == 0 {
            Some(Self(bits))
        } else {
            None
        }
    }
    pub const fn from_bits_retain(bits: u32) -> Self {
        Self(bits)
    }
    pub const fn from_bits_truncate(bits: u32) -> Self {
        Self(bits & Self::all().0)
    }
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
    pub const fn is_all(self) -> bool {
        self.0 & Self::all().0 == Self::all().0
    }
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
    pub const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
    pub const fn intersection(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }
    pub const fn difference(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }
    pub const fn symmetric_difference(self, other: Self) -> Self {
        Self(self.0 ^ other.0)
    }
    pub const fn complement(self) -> Self {
        Self(!self.0 & Self::all().0)
    }
    pub fn insert(&mut self, other: Self) {
        self.0 |= other.0;
    }
    pub fn remove(&mut self, other: Self) {
        self.0 &= !other.0;
    }
    pub fn toggle(&mut self, other: Self) {
        self.0 ^= other.0;
    }
    pub fn set(&mut self, other: Self, value: bool) {
        if value {
            self.0 |= other.0;
        } else {
            self.0 &= !other.0;
        }
    }
}

impl std::ops::BitOr for CodeStatus {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}
impl std::ops::BitAnd for CodeStatus {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
}
impl std::ops::BitXor for CodeStatus {
    type Output = Self;
    fn bitxor(self, rhs: Self) -> Self {
        Self(self.0 ^ rhs.0)
    }
}
impl std::ops::Sub for CodeStatus {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        Self(self.0 & !rhs.0)
    }
}
impl std::ops::Not for CodeStatus {
    type Output = Self;
    fn not(self) -> Self {
        Self(!self.0 & Self::all().0)
    }
}
impl std::ops::BitOrAssign for CodeStatus {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}
impl std::ops::BitAndAssign for CodeStatus {
    fn bitand_assign(&mut self, rhs: Self) {
        self.0 &= rhs.0;
    }
}
impl std::ops::BitXorAssign for CodeStatus {
    fn bitxor_assign(&mut self, rhs: Self) {
        self.0 ^= rhs.0;
    }
}
impl std::ops::SubAssign for CodeStatus {
    fn sub_assign(&mut self, rhs: Self) {
        self.0 &= !rhs.0;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AuditToken([u32; 8]);

impl AuditToken {
    pub const LEN: usize = 32;

    pub const fn from_raw(values: [u32; 8]) -> Self {
        Self(values)
    }

    pub const fn to_raw(self) -> [u32; 8] {
        self.0
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != Self::LEN {
            return Err(SecurityError::InvalidArgument(format!(
                "an audit token is {} bytes, got {}",
                Self::LEN,
                bytes.len()
            )));
        }
        let mut values = [0_u32; 8];
        for (value, chunk) in values.iter_mut().zip(bytes.chunks_exact(4)) {
            *value = u32::from_ne_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        Ok(Self(values))
    }

    pub fn to_bytes(self) -> [u8; 32] {
        let mut bytes = [0_u8; 32];
        for (chunk, value) in bytes.chunks_exact_mut(4).zip(self.0) {
            chunk.copy_from_slice(&value.to_ne_bytes());
        }
        bytes
    }

    pub fn current() -> Result<Self> {
        let mut values = [0_u32; 8];
        if unsafe { bridge::security_audit_token_copy_current(values.as_mut_ptr()) } {
            Ok(Self(values))
        } else {
            Err(SecurityError::InvalidArgument(
                "task_info(TASK_AUDIT_TOKEN) failed for the current task".to_owned(),
            ))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
/// Mirrors values returned by `SecCodeCopySigningInformation`.
pub enum SigningValue {
    /// Mirrors a value decoded from `SecCodeCopySigningInformation`.
    Boolean(bool),
    /// Mirrors a value decoded from `SecCodeCopySigningInformation`.
    Integer(i64),
    /// Mirrors a value decoded from `SecCodeCopySigningInformation`.
    String(String),
    /// Mirrors a value decoded from `SecCodeCopySigningInformation`.
    Data(Vec<u8>),
    /// Mirrors a value decoded from `SecCodeCopySigningInformation`.
    Array(Vec<Self>),
    /// Mirrors a value decoded from `SecCodeCopySigningInformation`.
    Dictionary(BTreeMap<String, Self>),
    /// Mirrors a value decoded from `SecCodeCopySigningInformation`.
    Unknown(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Mirrors structured data returned by `SecCodeCopySigningInformation`.
pub struct SigningInformation {
    /// Mirrors a field returned by `SecCodeCopySigningInformation`.
    pub identifier: Option<String>,
    /// Mirrors a field returned by `SecCodeCopySigningInformation`.
    pub team_identifier: Option<String>,
    /// Mirrors a field returned by `SecCodeCopySigningInformation`.
    pub entitlements: BTreeMap<String, SigningValue>,
    /// Mirrors a field returned by `SecCodeCopySigningInformation`.
    pub sandboxed: bool,
    /// Mirrors a field returned by `SecCodeCopySigningInformation`.
    pub status: Option<u32>,
}

impl SigningInformation {
    /// Wraps the corresponding Security.framework operation for `SigningInformation`.
    pub const fn is_signed(&self) -> bool {
        self.identifier.is_some()
    }

    pub fn code_status(&self) -> Option<CodeStatus> {
        self.status.map(CodeStatus::from_bits_retain)
    }

    fn from_value(value: &Value) -> Self {
        let entitlements = find_object(
            value,
            &[
                "entitlements-dict",
                "EntitlementsDict",
                "entitlements",
                "Entitlements",
            ],
        );
        Self {
            identifier: find_string(value, &["identifier", "Identifier"]),
            team_identifier: find_string(value, &["teamid", "TeamIdentifier", "teamIdentifier"]),
            entitlements: entitlements.map(signing_dictionary).unwrap_or_default(),
            sandboxed: matches!(
                entitlements.and_then(|value| value.get("com.apple.security.app-sandbox")),
                Some(Value::Bool(true))
            ),
            status: find_integer(value, &["status", "Status"])
                .and_then(|value| u32::try_from(value).ok()),
        }
    }
}

#[derive(Debug)]
/// Wraps `SecCodeRef`.
pub struct Code {
    handle: bridge::Handle,
}

impl Code {
    /// Wraps the corresponding `SecCodeRef` operation.
    pub fn type_id() -> usize {
        unsafe { bridge::security_code_get_type_id() }
    }

    /// Wraps the corresponding `SecCodeRef` operation.
    pub fn current() -> Result<Self> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe { bridge::security_code_copy_self(&raw mut status, &raw mut error) };
        bridge::required_handle("security_code_copy_self", raw, status, error)
            .map(|handle| Self { handle })
    }

    /// Wraps the corresponding `SecCodeRef` operation.
    pub fn host(&self) -> Result<Self> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_code_copy_host(self.handle.as_ptr(), &raw mut status, &raw mut error)
        };
        bridge::required_handle("security_code_copy_host", raw, status, error)
            .map(|handle| Self { handle })
    }

    /// Wraps the corresponding `SecCodeRef` operation.
    pub fn guest_with_attributes(
        host: Option<&Self>,
        attributes: Option<&Value>,
        flags: CodeSigningFlags,
    ) -> Result<Self> {
        let attributes = attributes.map(bridge::InputValue::new).transpose()?;
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_code_copy_guest_with_attributes(
                host.map_or(std::ptr::null_mut(), |value| value.handle.as_ptr()),
                attributes
                    .as_ref()
                    .map_or(std::ptr::null(), bridge::InputValue::as_ptr),
                flags.bits(),
                &raw mut status,
                &raw mut error,
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

    /// Wraps the corresponding `SecCodeRef` operation.
    pub fn static_code(&self) -> Result<StaticCode> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_code_copy_static_code(
                self.handle.as_ptr(),
                &raw mut status,
                &raw mut error,
            )
        };
        bridge::required_handle("security_code_copy_static_code", raw, status, error)
            .map(StaticCode::from_handle)
    }

    pub fn guest_with_audit_token(audit_token: &AuditToken) -> Result<Self> {
        let values = audit_token.to_raw();
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_code_copy_guest_with_audit_token(
                values.as_ptr(),
                &raw mut status,
                &raw mut error,
            )
        };
        bridge::required_handle(
            "security_code_copy_guest_with_audit_token",
            raw,
            status,
            error,
        )
        .map(|handle| Self { handle })
    }

    #[allow(clippy::missing_safety_doc)]
    pub unsafe fn from_xpc_message(message: *mut c_void) -> Result<Self> {
        if message.is_null() {
            return Err(SecurityError::InvalidArgument(
                "an XPC message object is required".to_owned(),
            ));
        }
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_code_create_with_xpc_message(message, &raw mut status, &raw mut error)
        };
        bridge::required_handle("security_code_create_with_xpc_message", raw, status, error)
            .map(|handle| Self { handle })
    }

    pub fn audit_token(&self) -> Option<AuditToken> {
        let mut values = [0_u32; 8];
        unsafe { bridge::security_code_copy_audit_token(self.handle.as_ptr(), values.as_mut_ptr()) }
            .then_some(AuditToken(values))
    }

    pub fn check_validity(
        &self,
        flags: CodeSigningFlags,
        requirement: Option<&Requirement>,
    ) -> Result<()> {
        let mut error = std::ptr::null_mut();
        let status = unsafe {
            bridge::security_code_check_validity(
                self.handle.as_ptr(),
                flags.bits(),
                requirement.map_or(std::ptr::null_mut(), |value| value.handle().as_ptr()),
                &raw mut error,
            )
        };
        bridge::status_result("security_code_check_validity", status, error)
    }

    /// Wraps the corresponding `SecCodeRef` operation.
    pub fn signing_information(&self) -> Result<SigningInformation> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_code_copy_signing_information(
                self.handle.as_ptr(),
                &raw mut status,
                &raw mut error,
            )
        };
        let value: Value =
            bridge::required_value("security_code_copy_signing_information", raw, status, error)?;
        Ok(SigningInformation::from_value(&value))
    }

    /// Wraps the corresponding `SecCodeRef` operation.
    pub fn task(&self) -> Result<Task> {
        let audit_token = self.audit_token().ok_or_else(|| {
            SecurityError::Unsupported(
                "this code object was not looked up by audit token, so its task cannot be \
                 identified without a PID race; use Code::guest_with_audit_token"
                    .to_owned(),
            )
        })?;
        Task::from_audit_token(&audit_token)
    }
}

#[derive(Debug)]
/// Wraps `SecRequirementRef`.
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

    /// Wraps the corresponding `SecRequirementRef` operation.
    pub fn type_id() -> usize {
        unsafe { bridge::security_requirement_get_type_id() }
    }

    /// Wraps the corresponding `SecRequirementRef` operation.
    pub fn from_data(data: &[u8]) -> Result<Self> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_requirement_create_with_data(
                data.as_ptr().cast(),
                bridge::len_to_isize(data.len())?,
                &raw mut status,
                &raw mut error,
            )
        };
        bridge::required_handle("security_requirement_create_with_data", raw, status, error)
            .map(Self::from_handle)
    }

    /// Wraps the corresponding `SecRequirementRef` operation.
    pub fn from_string(text: &str) -> Result<Self> {
        let text = bridge::cstring(text)?;
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_requirement_create_with_string(
                text.as_ptr(),
                &raw mut status,
                &raw mut error,
            )
        };
        bridge::required_handle(
            "security_requirement_create_with_string",
            raw,
            status,
            error,
        )
        .map(Self::from_handle)
    }

    /// Wraps the corresponding `SecRequirementRef` operation.
    pub fn from_string_with_errors(text: &str) -> Result<Self> {
        let text = bridge::cstring(text)?;
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_requirement_create_with_string_and_errors(
                text.as_ptr(),
                &raw mut status,
                &raw mut error,
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

    /// Wraps the corresponding `SecRequirementRef` operation.
    pub fn data(&self) -> Result<Vec<u8>> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_requirement_copy_data(
                self.handle.as_ptr(),
                &raw mut status,
                &raw mut error,
            )
        };
        bridge::required_data("security_requirement_copy_data", raw, status, error)
    }

    /// Wraps the corresponding `SecRequirementRef` operation.
    pub fn string(&self) -> Result<String> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_requirement_copy_string(
                self.handle.as_ptr(),
                &raw mut status,
                &raw mut error,
            )
        };
        bridge::required_string("security_requirement_copy_string", raw, status, error)
    }
}

#[derive(Debug)]
/// Wraps `SecStaticCodeRef`.
pub struct StaticCode {
    handle: bridge::Handle,
}

impl StaticCode {
    fn from_handle(handle: bridge::Handle) -> Self {
        Self { handle }
    }

    /// Wraps the corresponding `SecStaticCodeRef` operation.
    pub fn type_id() -> usize {
        unsafe { bridge::security_static_code_get_type_id() }
    }

    /// Wraps the corresponding `SecStaticCodeRef` operation.
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self> {
        let path = bridge::cstring(&path.as_ref().to_string_lossy())?;
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_static_code_create_with_path(
                path.as_ptr(),
                &raw mut status,
                &raw mut error,
            )
        };
        bridge::required_handle("security_static_code_create_with_path", raw, status, error)
            .map(Self::from_handle)
    }

    /// Wraps the corresponding `SecStaticCodeRef` operation.
    pub fn from_path_with_attributes(path: impl AsRef<Path>, attributes: &Value) -> Result<Self> {
        let path = bridge::cstring(&path.as_ref().to_string_lossy())?;
        let attributes = bridge::InputValue::new(attributes)?;
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_static_code_create_with_path_and_attributes(
                path.as_ptr(),
                attributes.as_ptr(),
                &raw mut status,
                &raw mut error,
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

    /// Wraps the corresponding `SecStaticCodeRef` operation.
    pub fn check_validity(&self) -> Result<()> {
        let mut error = std::ptr::null_mut();
        let status = unsafe {
            bridge::security_static_code_check_static_validity_with_errors(
                self.handle.as_ptr(),
                CodeSigningFlags::empty().bits(),
                std::ptr::null_mut(),
                &raw mut error,
            )
        };
        bridge::status_result(
            "security_static_code_check_static_validity_with_errors",
            status,
            error,
        )
    }

    /// Wraps the corresponding `SecStaticCodeRef` operation.
    pub fn check_validity_with_errors(
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
                &raw mut error,
            )
        };
        bridge::status_result(
            "security_static_code_check_static_validity_with_errors",
            status,
            error,
        )
    }

    /// Wraps the corresponding `SecStaticCodeRef` operation.
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
                &raw mut error,
            )
        };
        bridge::status_result("security_static_code_check_static_validity", status, error)
    }

    /// Wraps the corresponding `SecStaticCodeRef` operation.
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
                &raw mut error,
            )
        };
        bridge::status_result(
            "security_static_code_check_static_validity_with_errors",
            status,
            error,
        )
    }

    /// Wraps the corresponding `SecStaticCodeRef` operation.
    pub fn path(&self) -> Result<PathBuf> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_static_code_copy_path(
                self.handle.as_ptr(),
                &raw mut status,
                &raw mut error,
            )
        };
        bridge::required_string("security_static_code_copy_path", raw, status, error)
            .map(PathBuf::from)
    }

    /// Wraps the corresponding `SecStaticCodeRef` operation.
    pub fn designated_requirement(&self) -> Result<String> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_static_code_copy_designated_requirement(
                self.handle.as_ptr(),
                &raw mut status,
                &raw mut error,
            )
        };
        bridge::required_string(
            "security_static_code_copy_designated_requirement",
            raw,
            status,
            error,
        )
    }

    /// Wraps the corresponding `SecStaticCodeRef` operation.
    pub fn signing_information(&self) -> Result<SigningInformation> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_static_code_copy_signing_information(
                self.handle.as_ptr(),
                &raw mut status,
                &raw mut error,
            )
        };
        let value: Value = bridge::required_value(
            "security_static_code_copy_signing_information",
            raw,
            status,
            error,
        )?;
        Ok(SigningInformation::from_value(&value))
    }

    /// Wraps the corresponding `SecStaticCodeRef` operation.
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
                &raw mut error,
            )
        };
        bridge::status_result("security_static_code_validate_file_resource", status, error)
    }

    /// Wraps the corresponding `SecStaticCodeRef` operation.
    pub fn map_memory(&self, flags: CodeSigningFlags) -> Result<()> {
        let mut error = std::ptr::null_mut();
        let status = unsafe {
            bridge::security_static_code_map_memory(
                self.handle.as_ptr(),
                flags.bits(),
                &raw mut error,
            )
        };
        bridge::status_result("security_static_code_map_memory", status, error)
    }
}

#[derive(Debug)]
/// Wraps `SecTaskRef`.
pub struct Task {
    handle: bridge::Handle,
}

impl Task {
    /// Wraps the corresponding `SecTaskRef` operation.
    pub fn type_id() -> usize {
        unsafe { bridge::security_task_get_type_id() }
    }

    /// Wraps the corresponding `SecTaskRef` operation.
    pub fn current() -> Result<Self> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw =
            unsafe { bridge::security_task_create_from_self(&raw mut status, &raw mut error) };
        bridge::required_handle("security_task_create_from_self", raw, status, error)
            .map(|handle| Self { handle })
    }

    pub fn from_audit_token(audit_token: &AuditToken) -> Result<Self> {
        let values = audit_token.to_raw();
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_task_create_with_audit_token(
                values.as_ptr(),
                &raw mut status,
                &raw mut error,
            )
        };
        bridge::required_handle("security_task_create_with_audit_token", raw, status, error)
            .map(|handle| Self { handle })
    }

    /// Wraps the corresponding `SecTaskRef` operation.
    pub fn current_with_audit_token() -> Result<Self> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_task_create_from_current_audit_token(&raw mut status, &raw mut error)
        };
        bridge::required_handle(
            "security_task_create_from_current_audit_token",
            raw,
            status,
            error,
        )
        .map(|handle| Self { handle })
    }

    /// Wraps the corresponding `SecTaskRef` operation.
    pub fn signing_identifier(&self) -> Result<Option<String>> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_task_copy_signing_identifier(
                self.handle.as_ptr(),
                &raw mut status,
                &raw mut error,
            )
        };
        if raw.is_null() && status == 0 {
            Ok(None)
        } else {
            bridge::required_string("security_task_copy_signing_identifier", raw, status, error)
                .map(Some)
        }
    }

    /// Wraps the corresponding `SecTaskRef` operation.
    pub fn entitlement(&self, entitlement: &str) -> Result<Option<Value>> {
        let entitlement = bridge::cstring(entitlement)?;
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_task_copy_value_for_entitlement(
                self.handle.as_ptr(),
                entitlement.as_ptr(),
                &raw mut status,
                &raw mut error,
            )
        };
        if raw.is_null() && status == 0 {
            return Ok(None);
        }
        let value: Value = bridge::required_value(
            "security_task_copy_value_for_entitlement",
            raw,
            status,
            error,
        )?;
        Ok(Some(value))
    }

    /// Wraps the corresponding `SecTaskRef` operation.
    pub fn entitlements(&self, entitlements: &[&str]) -> Result<Value> {
        let entitlements = bridge::InputValue::strings(entitlements)?;
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_task_copy_values_for_entitlements(
                self.handle.as_ptr(),
                entitlements.as_ptr(),
                &raw mut status,
                &raw mut error,
            )
        };
        bridge::required_value(
            "security_task_copy_values_for_entitlements",
            raw,
            status,
            error,
        )
    }
}

fn find_object<'a>(value: &'a Value, keys: &[&str]) -> Option<&'a BTreeMap<String, Value>> {
    keys.iter()
        .find_map(|key| value.get(key))
        .and_then(Value::as_object)
}

fn find_string(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| value.get(key))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

fn find_integer(value: &Value, keys: &[&str]) -> Option<i64> {
    keys.iter()
        .find_map(|key| value.get(key))
        .and_then(Value::as_i64)
}

fn signing_dictionary(object: &BTreeMap<String, Value>) -> BTreeMap<String, SigningValue> {
    object
        .iter()
        .map(|(key, value)| (key.clone(), signing_value(value)))
        .collect()
}

#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::float_cmp
)]
fn signing_value(value: &Value) -> SigningValue {
    match value {
        Value::Bool(value) => SigningValue::Boolean(*value),
        Value::Integer(value) => SigningValue::Integer(*value),
        Value::Unsigned(value) => i64::try_from(*value).map_or_else(
            |_| SigningValue::Unknown(value.to_string()),
            SigningValue::Integer,
        ),
        Value::Real(value) => {
            let integer = *value as i64;
            if *value < 9_223_372_036_854_775_808.0 && integer as f64 == *value {
                SigningValue::Integer(integer)
            } else {
                SigningValue::Unknown(value.to_string())
            }
        }
        Value::Date(value) => SigningValue::Dictionary(BTreeMap::from([
            ("_type".to_owned(), SigningValue::String("date".to_owned())),
            ("unix".to_owned(), signing_value(&Value::Real(*value))),
        ])),
        Value::String(value) => SigningValue::String(value.clone()),
        Value::Url(value) => SigningValue::Dictionary(BTreeMap::from([
            ("_type".to_owned(), SigningValue::String("url".to_owned())),
            ("value".to_owned(), SigningValue::String(value.clone())),
        ])),
        Value::Data(value) => SigningValue::Data(value.clone()),
        Value::Array(values) => SigningValue::Array(values.iter().map(signing_value).collect()),
        Value::Object(object) => SigningValue::Dictionary(signing_dictionary(object)),
        Value::Null => SigningValue::Unknown("null".to_owned()),
    }
}
