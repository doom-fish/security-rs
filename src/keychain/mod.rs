use bitflags::bitflags;

use crate::bridge::{self, Handle};
use crate::error::Result;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
/// Mirrors protection classes used by `SecAccessControlCreateWithFlags`.
pub enum AccessControlProtection {
    /// Mirrors a `SecAccessControl` protection-class constant.
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
                &mut status,
                &mut error,
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
    pub fn set(&self, password: &str) -> Result<()> {
        Keychain::set(&self.account, &self.service, password)
    }

    /// Wraps the corresponding generic-password operation built on `SecItem`.
    pub fn get(&self) -> Result<String> {
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
    pub fn set(account: &str, service: &str, password: &str) -> Result<()> {
        let account = bridge::cstring(account)?;
        let service = bridge::cstring(service)?;
        let password = bridge::cstring(password)?;
        let mut error = std::ptr::null_mut();
        let status = unsafe {
            bridge::security_keychain_set_password(
                account.as_ptr(),
                service.as_ptr(),
                password.as_ptr(),
                &mut error,
            )
        };
        bridge::status_result("security_keychain_set_password", status, error)
    }

    /// Wraps the corresponding generic-password `SecItem` operation.
    pub fn get(account: &str, service: &str) -> Result<String> {
        let account = bridge::cstring(account)?;
        let service = bridge::cstring(service)?;
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_keychain_get_password(
                account.as_ptr(),
                service.as_ptr(),
                &mut status,
                &mut error,
            )
        };
        bridge::required_string("security_keychain_get_password", raw, status, error)
    }

    /// Wraps the corresponding generic-password `SecItem` operation.
    pub fn delete(account: &str, service: &str) -> Result<()> {
        let account = bridge::cstring(account)?;
        let service = bridge::cstring(service)?;
        let mut error = std::ptr::null_mut();
        let status = unsafe {
            bridge::security_keychain_delete_password(
                account.as_ptr(),
                service.as_ptr(),
                &mut error,
            )
        };
        bridge::status_result("security_keychain_delete_password", status, error)
    }

    /// Wraps the corresponding generic-password `SecItem` operation.
    pub fn list_accounts(service: &str) -> Result<Vec<String>> {
        let service = bridge::cstring(service)?;
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_keychain_list_accounts(service.as_ptr(), &mut status, &mut error)
        };
        bridge::required_json("security_keychain_list_accounts", raw, status, error)
    }
}
