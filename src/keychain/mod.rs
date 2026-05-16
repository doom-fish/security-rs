use crate::bridge;
use crate::error::Result;

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
            bridge::security_keychain_delete_password(account.as_ptr(), service.as_ptr(), &mut error)
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
