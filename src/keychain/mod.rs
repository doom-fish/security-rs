use std::ffi::{c_void, CString};

use bitflags::bitflags;
use serde_json::json;

use crate::bridge::{self, Handle};
use crate::error::{Result, SecurityError};
use crate::secret::SecretBytes;

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    /// Mirrors `SecAccessControlCreateFlags`.
    pub struct AccessControlFlags: u64 {
        /// Mirrors a `SecAccessControlCreateFlags` bit.
        const DEFAULTS = 0;
        /// Mirrors a `SecAccessControlCreateFlags` bit.
        const USER_PRESENCE = 1 << 0;
        /// Mirrors a `SecAccessControlCreateFlags` bit.
        const BIOMETRY_ANY = 1 << 1;
        /// Mirrors a `SecAccessControlCreateFlags` bit.
        const BIOMETRY_CURRENT_SET = 1 << 3;
        /// Mirrors a `SecAccessControlCreateFlags` bit.
        const DEVICE_PASSCODE = 1 << 4;
        /// Mirrors a `SecAccessControlCreateFlags` bit.
        const COMPANION = 1 << 5;
        /// Mirrors a `SecAccessControlCreateFlags` bit.
        const OR = 1 << 14;
        /// Mirrors a `SecAccessControlCreateFlags` bit.
        const AND = 1 << 15;
        /// Mirrors a `SecAccessControlCreateFlags` bit.
        const PRIVATE_KEY_USAGE = 1 << 30;
        /// Mirrors a `SecAccessControlCreateFlags` bit.
        const APPLICATION_PASSWORD = 1 << 31;
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

#[derive(Debug)]
/// Wraps `SecAccessControlRef`.
pub struct AccessControl {
    handle: Handle,
}

impl AccessControl {
    /// Wraps the corresponding `SecAccessControlRef` operation.
    pub fn type_id() -> usize {
        unsafe { bridge::security_access_control_get_type_id() }
    }

    /// Wraps the corresponding `SecAccessControlRef` operation.
    pub fn create(protection: AccessControlProtection, flags: AccessControlFlags) -> Result<Self> {
        let protection = bridge::cstring(protection.as_bridge_name())?;
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_access_control_create(
                protection.as_ptr(),
                flags.bits(),
                &raw mut status,
                &raw mut error,
            )
        };
        bridge::required_handle("security_access_control_create", raw, status, error)
            .map(|handle| Self { handle })
    }

    /// Wraps the corresponding `SecAccessControlRef` operation.
    pub fn is_valid(&self) -> bool {
        !self.handle.as_ptr().is_null()
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

    fn bridge_json(&self) -> Result<CString> {
        let mut options = json!({
            "accessibility": self.accessibility.as_bridge_name(),
            "synchronizable": self.synchronizable,
            "data_protection_keychain": self.data_protection_keychain,
        });
        if let Some(access_group) = &self.access_group {
            options["access_group"] = json!(access_group);
        }
        bridge::json_cstring(&options)
    }

    fn access_control_ptr(&self) -> *mut c_void {
        self.access_control
            .as_ref()
            .map_or(std::ptr::null_mut(), |value| value.handle.as_ptr())
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
        let options_json = options.bridge_json()?;
        let mut error = std::ptr::null_mut();
        let status = unsafe {
            bridge::security_keychain_set_item(
                account.as_ptr(),
                service.as_ptr(),
                secret.as_ptr().cast(),
                bridge::len_to_isize(secret.len())?,
                options_json.as_ptr(),
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
        let options_json = options.bridge_json()?;
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_keychain_copy_item(
                account.as_ptr(),
                service.as_ptr(),
                options_json.as_ptr(),
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
        let options_json = options.bridge_json()?;
        let mut error = std::ptr::null_mut();
        let status = unsafe {
            bridge::security_keychain_delete_item(
                account.as_ptr(),
                service.as_ptr(),
                options_json.as_ptr(),
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
        let options_json = options.bridge_json()?;
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_keychain_list_accounts(
                service.as_ptr(),
                options_json.as_ptr(),
                options.authentication_context_ptr(),
                &raw mut status,
                &raw mut error,
            )
        };
        bridge::required_json("security_keychain_list_accounts", raw, status, error)
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
        let json = KeychainOptions::default().bridge_json().unwrap();
        let value: serde_json::Value = serde_json::from_str(json.to_str().unwrap()).unwrap();
        assert_eq!(value["accessibility"], "when_unlocked");
        assert_eq!(value["synchronizable"], false);
        assert_eq!(value["data_protection_keychain"], false);
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
        let json = options.bridge_json().unwrap();
        let value: serde_json::Value = serde_json::from_str(json.to_str().unwrap()).unwrap();
        assert_eq!(value["accessibility"], "when_unlocked_this_device_only");
        assert_eq!(value["access_group"], "TEAMID.group");
        assert_eq!(value["synchronizable"], true);
        assert_eq!(value["data_protection_keychain"], true);
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
