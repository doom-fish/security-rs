use std::ffi::c_void;

use crate::bridge::{self, CoreFoundationHandle, Handle};
use crate::error::{Result, SecurityError};
use crate::secret::SecretBytes;
use crate::Value;

mod internet_password;
pub use internet_password::{InternetCredential, InternetPassword};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
#[must_use]
/// Mirrors `SecAccessControlCreateFlags`.
pub struct AccessControlFlags(u64);

impl AccessControlFlags {
    /// Mirrors a `SecAccessControlCreateFlags` bit.
    pub const DEFAULTS: Self = Self(0);
    /// Mirrors a `SecAccessControlCreateFlags` bit.
    pub const USER_PRESENCE: Self = Self(1 << 0);
    /// Mirrors a `SecAccessControlCreateFlags` bit.
    pub const BIOMETRY_ANY: Self = Self(1 << 1);
    /// Mirrors a `SecAccessControlCreateFlags` bit.
    pub const BIOMETRY_CURRENT_SET: Self = Self(1 << 3);
    /// Mirrors a `SecAccessControlCreateFlags` bit.
    pub const DEVICE_PASSCODE: Self = Self(1 << 4);
    /// Mirrors a `SecAccessControlCreateFlags` bit.
    pub const COMPANION: Self = Self(1 << 5);
    /// Mirrors a `SecAccessControlCreateFlags` bit.
    pub const OR: Self = Self(1 << 14);
    /// Mirrors a `SecAccessControlCreateFlags` bit.
    pub const AND: Self = Self(1 << 15);
    /// Mirrors a `SecAccessControlCreateFlags` bit.
    pub const PRIVATE_KEY_USAGE: Self = Self(1 << 30);
    /// Mirrors a `SecAccessControlCreateFlags` bit.
    pub const APPLICATION_PASSWORD: Self = Self(1 << 31);

    pub const fn empty() -> Self {
        Self(0)
    }
    pub const fn all() -> Self {
        Self(0xc000_c03b)
    }
    pub const fn bits(self) -> u64 {
        self.0
    }
    pub const fn from_bits(bits: u64) -> Option<Self> {
        if bits & !Self::all().0 == 0 {
            Some(Self(bits))
        } else {
            None
        }
    }
    pub const fn from_bits_retain(bits: u64) -> Self {
        Self(bits)
    }
    pub const fn from_bits_truncate(bits: u64) -> Self {
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

impl std::ops::BitOr for AccessControlFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}
impl std::ops::BitAnd for AccessControlFlags {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
}
impl std::ops::BitXor for AccessControlFlags {
    type Output = Self;
    fn bitxor(self, rhs: Self) -> Self {
        Self(self.0 ^ rhs.0)
    }
}
impl std::ops::Sub for AccessControlFlags {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        Self(self.0 & !rhs.0)
    }
}
impl std::ops::Not for AccessControlFlags {
    type Output = Self;
    fn not(self) -> Self {
        Self(!self.0 & Self::all().0)
    }
}
impl std::ops::BitOrAssign for AccessControlFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}
impl std::ops::BitAndAssign for AccessControlFlags {
    fn bitand_assign(&mut self, rhs: Self) {
        self.0 &= rhs.0;
    }
}
impl std::ops::BitXorAssign for AccessControlFlags {
    fn bitxor_assign(&mut self, rhs: Self) {
        self.0 ^= rhs.0;
    }
}
impl std::ops::SubAssign for AccessControlFlags {
    fn sub_assign(&mut self, rhs: Self) {
        self.0 &= !rhs.0;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
/// Mirrors protection classes used by `SecAccessControlCreateWithFlags`.
pub enum AccessControlProtection {
    /// Mirrors a `SecAccessControl` protection-class constant.
    #[default]
    WhenUnlocked,
    /// Mirrors a `SecAccessControl` protection-class constant.
    AfterFirstUnlock,
    /// Mirrors a `SecAccessControl` protection-class constant.
    WhenPasscodeSetThisDeviceOnly,
    /// Mirrors a `SecAccessControl` protection-class constant.
    WhenUnlockedThisDeviceOnly,
    /// Mirrors a `SecAccessControl` protection-class constant.
    AfterFirstUnlockThisDeviceOnly,
}

impl AccessControlProtection {
    const fn as_bridge_name(self) -> &'static str {
        match self {
            Self::WhenUnlocked => "when_unlocked",
            Self::AfterFirstUnlock => "after_first_unlock",
            Self::WhenPasscodeSetThisDeviceOnly => "when_passcode_set_this_device_only",
            Self::WhenUnlockedThisDeviceOnly => "when_unlocked_this_device_only",
            Self::AfterFirstUnlockThisDeviceOnly => "after_first_unlock_this_device_only",
        }
    }
}

#[derive(Debug, Clone)]
/// Wraps `SecAccessControlRef`.
pub struct AccessControl {
    object: CoreFoundationHandle,
    protection: AccessControlProtection,
    flags: AccessControlFlags,
}

impl AccessControl {
    /// Wraps the corresponding `SecAccessControlRef` operation.
    pub fn type_id() -> usize {
        unsafe { bridge::security_access_control_get_type_id() }
    }

    /// Wraps the corresponding `SecAccessControlRef` operation.
    pub fn create(protection: AccessControlProtection, flags: AccessControlFlags) -> Result<Self> {
        let protection_name = bridge::cstring(protection.as_bridge_name())?;
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_access_control_create(
                protection_name.as_ptr(),
                flags.bits(),
                &raw mut status,
                &raw mut error,
            )
        };
        let Some(object) = CoreFoundationHandle::from_raw(raw) else {
            return Err(bridge::status_error(
                "security_access_control_create",
                status,
                error,
            )?);
        };
        Ok(Self {
            object,
            protection,
            flags,
        })
    }

    /// Wraps the corresponding `SecAccessControlRef` operation.
    pub fn is_valid(&self) -> bool {
        !self.object.as_ptr().is_null()
    }

    pub const fn protection(&self) -> AccessControlProtection {
        self.protection
    }

    pub const fn flags(&self) -> AccessControlFlags {
        self.flags
    }

    pub const fn as_ptr(&self) -> *mut c_void {
        self.object.as_ptr()
    }
}

#[derive(Debug, Default)]
pub struct KeychainOptions {
    accessibility: AccessControlProtection,
    access_control: Option<AccessControl>,
    access_group: Option<String>,
    synchronizable: bool,
    data_protection_keychain: bool,
    authentication_context: Option<Handle>,
}

impl KeychainOptions {
    #[must_use]
    pub fn accessibility(mut self, accessibility: AccessControlProtection) -> Self {
        self.accessibility = accessibility;
        self
    }

    #[must_use]
    pub fn access_control(mut self, access_control: AccessControl) -> Self {
        self.access_control = Some(access_control);
        self
    }

    #[must_use]
    pub fn access_group(mut self, access_group: impl Into<String>) -> Self {
        self.access_group = Some(access_group.into());
        self
    }

    #[must_use]
    pub fn synchronizable(mut self, synchronizable: bool) -> Self {
        self.synchronizable = synchronizable;
        self
    }

    #[must_use]
    pub fn data_protection_keychain(mut self, data_protection_keychain: bool) -> Self {
        self.data_protection_keychain = data_protection_keychain;
        self
    }

    #[allow(clippy::missing_safety_doc)]
    pub unsafe fn authentication_context(mut self, la_context: *mut c_void) -> Result<Self> {
        let raw = unsafe { bridge::security_authentication_context_retain(la_context) };
        let handle = Handle::from_raw(raw).ok_or_else(|| {
            SecurityError::InvalidArgument("authentication context must be an LAContext".to_owned())
        })?;
        self.authentication_context = Some(handle);
        Ok(self)
    }

    fn bridge_value(&self) -> Value {
        let mut options = std::collections::BTreeMap::from([
            (
                "accessibility".to_owned(),
                Value::String(self.accessibility.as_bridge_name().to_owned()),
            ),
            (
                "synchronizable".to_owned(),
                Value::Bool(self.synchronizable),
            ),
            (
                "data_protection_keychain".to_owned(),
                Value::Bool(self.data_protection_keychain),
            ),
        ]);
        if let Some(access_group) = &self.access_group {
            options.insert(
                "access_group".to_owned(),
                Value::String(access_group.clone()),
            );
        }
        Value::Object(options)
    }

    fn access_control_ptr(&self) -> *mut c_void {
        self.access_control
            .as_ref()
            .map_or(std::ptr::null_mut(), AccessControl::as_ptr)
    }

    fn authentication_context_ptr(&self) -> *mut c_void {
        self.authentication_context
            .as_ref()
            .map_or(std::ptr::null_mut(), Handle::as_ptr)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
/// Wraps a generic-password identity used with `SecItem` queries.
pub struct KeychainEntry {
    account: String,
    service: String,
}

impl KeychainEntry {
    /// Wraps the corresponding generic-password operation built on `SecItem`.
    pub fn new(account: impl Into<String>, service: impl Into<String>) -> Self {
        Self {
            account: account.into(),
            service: service.into(),
        }
    }

    /// Wraps the corresponding generic-password operation built on `SecItem`.
    pub fn account(&self) -> &str {
        &self.account
    }

    /// Wraps the corresponding generic-password operation built on `SecItem`.
    pub fn service(&self) -> &str {
        &self.service
    }

    /// Wraps the corresponding generic-password operation built on `SecItem`.
    pub fn set(&self, secret: impl AsRef<[u8]>) -> Result<()> {
        Keychain::set(&self.account, &self.service, secret)
    }

    /// Wraps the corresponding generic-password operation built on `SecItem`.
    pub fn get(&self) -> Result<SecretBytes> {
        Keychain::get(&self.account, &self.service)
    }

    /// Wraps the corresponding generic-password operation built on `SecItem`.
    pub fn delete(&self) -> Result<()> {
        Keychain::delete(&self.account, &self.service)
    }
}

/// Wraps generic-password operations built on `SecItem` APIs.
pub struct Keychain;

impl Keychain {
    /// Wraps the corresponding generic-password `SecItem` operation.
    pub fn entry(account: impl Into<String>, service: impl Into<String>) -> KeychainEntry {
        KeychainEntry::new(account, service)
    }

    /// Wraps the corresponding generic-password `SecItem` operation.
    pub fn set(account: &str, service: &str, secret: impl AsRef<[u8]>) -> Result<()> {
        Self::set_with_options(account, service, secret, &KeychainOptions::default())
    }

    /// Wraps the corresponding generic-password `SecItem` operation.
    pub fn get(account: &str, service: &str) -> Result<SecretBytes> {
        Self::get_with_options(account, service, &KeychainOptions::default())
    }

    /// Wraps the corresponding generic-password `SecItem` operation.
    pub fn delete(account: &str, service: &str) -> Result<()> {
        Self::delete_with_options(account, service, &KeychainOptions::default())
    }

    /// Wraps the corresponding generic-password `SecItem` operation.
    pub fn list_accounts(service: &str) -> Result<Vec<String>> {
        Self::list_accounts_with_options(service, &KeychainOptions::default())
    }

    pub fn set_with_options(
        account: &str,
        service: &str,
        secret: impl AsRef<[u8]>,
        options: &KeychainOptions,
    ) -> Result<()> {
        let secret = secret.as_ref();
        let account = bridge::cstring(account)?;
        let service = bridge::cstring(service)?;
        let options_value = bridge::InputValue::new(&options.bridge_value())?;
        let mut error = std::ptr::null_mut();
        let status = unsafe {
            bridge::security_keychain_set_item(
                account.as_ptr(),
                service.as_ptr(),
                secret.as_ptr().cast(),
                bridge::len_to_isize(secret.len())?,
                options_value.as_ptr(),
                options.access_control_ptr(),
                options.authentication_context_ptr(),
                &raw mut error,
            )
        };
        bridge::status_result("security_keychain_set_item", status, error)
    }

    pub fn get_with_options(
        account: &str,
        service: &str,
        options: &KeychainOptions,
    ) -> Result<SecretBytes> {
        let account = bridge::cstring(account)?;
        let service = bridge::cstring(service)?;
        let options_value = bridge::InputValue::new(&options.bridge_value())?;
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_keychain_copy_item(
                account.as_ptr(),
                service.as_ptr(),
                options_value.as_ptr(),
                options.authentication_context_ptr(),
                &raw mut status,
                &raw mut error,
            )
        };
        bridge::required_secret("security_keychain_copy_item", raw, status, error)
    }

    pub fn delete_with_options(
        account: &str,
        service: &str,
        options: &KeychainOptions,
    ) -> Result<()> {
        let account = bridge::cstring(account)?;
        let service = bridge::cstring(service)?;
        let options_value = bridge::InputValue::new(&options.bridge_value())?;
        let mut error = std::ptr::null_mut();
        let status = unsafe {
            bridge::security_keychain_delete_item(
                account.as_ptr(),
                service.as_ptr(),
                options_value.as_ptr(),
                options.authentication_context_ptr(),
                &raw mut error,
            )
        };
        bridge::status_result("security_keychain_delete_item", status, error)
    }

    pub fn list_accounts_with_options(
        service: &str,
        options: &KeychainOptions,
    ) -> Result<Vec<String>> {
        let service = bridge::cstring(service)?;
        let options_value = bridge::InputValue::new(&options.bridge_value())?;
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_keychain_list_accounts(
                service.as_ptr(),
                options_value.as_ptr(),
                options.authentication_context_ptr(),
                &raw mut status,
                &raw mut error,
            )
        };
        bridge::required_value("security_keychain_list_accounts", raw, status, error)?
            .into_strings("security_keychain_list_accounts")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_control_protection_base_bridge_names_are_stable() {
        assert_eq!(
            AccessControlProtection::WhenUnlocked.as_bridge_name(),
            "when_unlocked"
        );
        assert_eq!(
            AccessControlProtection::AfterFirstUnlock.as_bridge_name(),
            "after_first_unlock"
        );
    }

    #[test]
    fn access_control_protection_device_only_bridge_names_are_stable() {
        assert_eq!(
            AccessControlProtection::WhenPasscodeSetThisDeviceOnly.as_bridge_name(),
            "when_passcode_set_this_device_only"
        );
        assert_eq!(
            AccessControlProtection::WhenUnlockedThisDeviceOnly.as_bridge_name(),
            "when_unlocked_this_device_only"
        );
        assert_eq!(
            AccessControlProtection::AfterFirstUnlockThisDeviceOnly.as_bridge_name(),
            "after_first_unlock_this_device_only"
        );
    }

    #[test]
    fn access_control_flags_round_trip_through_bits() {
        let flags = AccessControlFlags::USER_PRESENCE
            | AccessControlFlags::PRIVATE_KEY_USAGE
            | AccessControlFlags::APPLICATION_PASSWORD;

        assert_eq!(AccessControlFlags::from_bits(flags.bits()), Some(flags));
    }

    #[test]
    fn default_options_protect_items_when_unlocked() {
        let value = KeychainOptions::default().bridge_value();
        assert_eq!(
            value.get("accessibility").and_then(Value::as_str),
            Some("when_unlocked")
        );
        assert_eq!(
            value.get("synchronizable").and_then(Value::as_bool),
            Some(false)
        );
        assert_eq!(
            value
                .get("data_protection_keychain")
                .and_then(Value::as_bool),
            Some(false)
        );
        assert!(value.get("access_group").is_none());
        assert_eq!(
            AccessControlProtection::default(),
            AccessControlProtection::WhenUnlocked
        );
    }

    #[test]
    fn options_serialize_every_selected_control() {
        let options = KeychainOptions::default()
            .accessibility(AccessControlProtection::WhenUnlockedThisDeviceOnly)
            .access_group("TEAMID.group")
            .synchronizable(true)
            .data_protection_keychain(true);
        let value = options.bridge_value();
        assert_eq!(
            value.get("accessibility").and_then(Value::as_str),
            Some("when_unlocked_this_device_only")
        );
        assert_eq!(
            value.get("access_group").and_then(Value::as_str),
            Some("TEAMID.group")
        );
        assert_eq!(
            value.get("synchronizable").and_then(Value::as_bool),
            Some(true)
        );
        assert_eq!(
            value
                .get("data_protection_keychain")
                .and_then(Value::as_bool),
            Some(true)
        );
        assert!(options.access_control_ptr().is_null());
        assert!(options.authentication_context_ptr().is_null());
    }

    #[test]
    fn keychain_entry_new_preserves_account_and_service() {
        let entry = KeychainEntry::new("alice", "security-rs.tests");

        assert_eq!(entry.account(), "alice");
        assert_eq!(entry.service(), "security-rs.tests");
    }

    #[test]
    fn keychain_entry_convenience_constructor_matches_new() {
        let entry = Keychain::entry("alice", "security-rs.tests");

        assert_eq!(entry, KeychainEntry::new("alice", "security-rs.tests"));
    }
}
