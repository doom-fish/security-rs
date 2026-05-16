use bitflags::bitflags;

use crate::bridge::{self, Handle};
use crate::error::Result;

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct AccessControlFlags: u64 {
        const DEFAULTS = 0;
        const USER_PRESENCE = 1 << 0;
        const BIOMETRY_ANY = 1 << 1;
        const BIOMETRY_CURRENT_SET = 1 << 3;
        const DEVICE_PASSCODE = 1 << 4;
        const COMPANION = 1 << 5;
        const OR = 1 << 14;
        const AND = 1 << 15;
        const PRIVATE_KEY_USAGE = 1 << 30;
        const APPLICATION_PASSWORD = 1 << 31;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AccessControlProtection {
    WhenUnlocked,
    AfterFirstUnlock,
    WhenPasscodeSetThisDeviceOnly,
    WhenUnlockedThisDeviceOnly,
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
pub struct AccessControl {
    handle: Handle,
}

impl AccessControl {
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

    pub fn is_valid(&self) -> bool {
        !self.handle.as_ptr().is_null()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeychainEntry {
    account: String,
    service: String,
}

impl KeychainEntry {
    pub fn new(account: impl Into<String>, service: impl Into<String>) -> Self {
        Self {
            account: account.into(),
            service: service.into(),
        }
    }

    pub fn account(&self) -> &str {
        &self.account
    }

    pub fn service(&self) -> &str {
        &self.service
    }

    pub fn set(&self, password: &str) -> Result<()> {
        Keychain::set(&self.account, &self.service, password)
    }

    pub fn get(&self) -> Result<String> {
        Keychain::get(&self.account, &self.service)
    }

    pub fn delete(&self) -> Result<()> {
        Keychain::delete(&self.account, &self.service)
    }
}

pub struct Keychain;

impl Keychain {
    pub fn entry(account: impl Into<String>, service: impl Into<String>) -> KeychainEntry {
        KeychainEntry::new(account, service)
    }

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
