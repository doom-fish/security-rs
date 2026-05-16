//! Generic-password keychain wrappers built on top of `SecItem*`.

use crate::error::{Result, SecurityError};
use crate::ffi;
use crate::private::{
    cf_data, cf_data_to_vec, cf_dictionary_get_value, cf_dictionary_set_value,
    cf_mutable_dictionary, cf_string, cf_string_to_string, sec_error_message, OwnedCf,
};

fn generic_password_query(account: Option<&str>, service: &str) -> Result<OwnedCf> {
    let dictionary = cf_mutable_dictionary(3)?;
    let service = cf_string(service)?;
    unsafe {
        cf_dictionary_set_value(
            dictionary.as_mut_dictionary(),
            ffi::kSecClass,
            ffi::kSecClassGenericPassword.cast(),
        );
        cf_dictionary_set_value(
            dictionary.as_mut_dictionary(),
            ffi::kSecAttrService,
            service.as_ptr(),
        );
    }

    if let Some(account) = account {
        let account = cf_string(account)?;
        unsafe {
            cf_dictionary_set_value(
                dictionary.as_mut_dictionary(),
                ffi::kSecAttrAccount,
                account.as_ptr(),
            );
        }
    }

    Ok(dictionary)
}

/// Typed generic-password keychain entry identified by `(account, service)`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeychainEntry {
    account: String,
    service: String,
}

impl KeychainEntry {
    /// Create a typed generic-password keychain entry.
    #[must_use]
    pub fn new(account: impl Into<String>, service: impl Into<String>) -> Self {
        Self {
            account: account.into(),
            service: service.into(),
        }
    }

    /// Account name stored in the keychain item.
    #[must_use]
    pub fn account(&self) -> &str {
        &self.account
    }

    /// Service name stored in the keychain item.
    #[must_use]
    pub fn service(&self) -> &str {
        &self.service
    }

    /// Upsert the password for this keychain entry.
    ///
    /// # Errors
    ///
    /// Returns an error if Security.framework rejects the item or the strings contain NUL bytes.
    pub fn set(&self, password: &str) -> Result<()> {
        Keychain::set(&self.account, &self.service, password)
    }

    /// Fetch the password for this keychain entry.
    ///
    /// # Errors
    ///
    /// Returns an error if the item does not exist or Security.framework rejects the query.
    pub fn get(&self) -> Result<String> {
        Keychain::get(&self.account, &self.service)
    }

    /// Delete this keychain entry.
    ///
    /// # Errors
    ///
    /// Returns an error if Security.framework rejects the delete request.
    pub fn delete(&self) -> Result<()> {
        Keychain::delete(&self.account, &self.service)
    }
}

/// Stateless entry point for generic-password keychain operations.
pub struct Keychain;

impl Keychain {
    /// Build a typed keychain entry for `(account, service)`.
    #[must_use]
    pub fn entry(account: impl Into<String>, service: impl Into<String>) -> KeychainEntry {
        KeychainEntry::new(account, service)
    }

    /// Upsert a generic-password keychain item.
    ///
    /// # Errors
    ///
    /// Returns an error if Security.framework rejects the item or the strings contain NUL bytes.
    pub fn set(account: &str, service: &str, password: &str) -> Result<()> {
        let search_query = generic_password_query(Some(account), service)?;
        let add_query = generic_password_query(Some(account), service)?;
        let password_data = cf_data(password.as_bytes())?;
        unsafe {
            cf_dictionary_set_value(
                add_query.as_mut_dictionary(),
                ffi::kSecValueData,
                password_data.as_ptr(),
            );
        }

        let status = unsafe { ffi::SecItemAdd(add_query.as_dictionary(), std::ptr::null_mut()) };
        match status {
            ffi::status::SUCCESS => Ok(()),
            ffi::status::DUPLICATE_ITEM => {
                let attributes = cf_mutable_dictionary(1)?;
                unsafe {
                    cf_dictionary_set_value(
                        attributes.as_mut_dictionary(),
                        ffi::kSecValueData,
                        password_data.as_ptr(),
                    );
                }
                let status = unsafe {
                    ffi::SecItemUpdate(search_query.as_dictionary(), attributes.as_dictionary())
                };
                if status == ffi::status::SUCCESS {
                    Ok(())
                } else {
                    Err(SecurityError::from_status(
                        "SecItemUpdate",
                        status,
                        sec_error_message(status),
                    ))
                }
            }
            _ => Err(SecurityError::from_status(
                "SecItemAdd",
                status,
                sec_error_message(status),
            )),
        }
    }

    /// Fetch a generic-password keychain item as UTF-8 text.
    ///
    /// # Errors
    ///
    /// Returns an error if the item does not exist, the stored bytes are not UTF-8, or Security.framework rejects the query.
    pub fn get(account: &str, service: &str) -> Result<String> {
        let query = generic_password_query(Some(account), service)?;
        unsafe {
            cf_dictionary_set_value(
                query.as_mut_dictionary(),
                ffi::kSecReturnData,
                ffi::kCFBooleanTrue.cast(),
            );
            cf_dictionary_set_value(
                query.as_mut_dictionary(),
                ffi::kSecMatchLimit,
                ffi::kSecMatchLimitOne.cast(),
            );
        }

        let mut result = std::ptr::null();
        let status = unsafe { ffi::SecItemCopyMatching(query.as_dictionary(), &mut result) };
        if status != ffi::status::SUCCESS {
            let context = format!(
                "generic password {account:?} @ {service:?}: {}",
                sec_error_message(status)
            );
            return Err(SecurityError::from_status(
                "SecItemCopyMatching",
                status,
                context,
            ));
        }

        let data = OwnedCf::new(result);
        if crate::private::cf_type_id(data.as_ptr()) != unsafe { ffi::CFDataGetTypeID() } {
            return Err(SecurityError::UnexpectedType {
                operation: "SecItemCopyMatching",
                expected: "CFData",
            });
        }

        String::from_utf8(cf_data_to_vec(data.as_data())).map_err(|error| {
            SecurityError::InvalidArgument(format!("keychain password is not valid UTF-8: {error}"))
        })
    }

    /// Delete a generic-password keychain item.
    ///
    /// Missing items are treated as success to make cleanup ergonomic.
    ///
    /// # Errors
    ///
    /// Returns an error if Security.framework rejects the delete request for another reason.
    pub fn delete(account: &str, service: &str) -> Result<()> {
        let query = generic_password_query(Some(account), service)?;
        let status = unsafe { ffi::SecItemDelete(query.as_dictionary()) };
        match status {
            ffi::status::SUCCESS | ffi::status::ITEM_NOT_FOUND => Ok(()),
            _ => Err(SecurityError::from_status(
                "SecItemDelete",
                status,
                sec_error_message(status),
            )),
        }
    }

    /// List all account names for the given generic-password service.
    ///
    /// # Errors
    ///
    /// Returns an error if Security.framework rejects the query.
    pub fn list_accounts(service: &str) -> Result<Vec<String>> {
        let query = generic_password_query(None, service)?;
        unsafe {
            cf_dictionary_set_value(
                query.as_mut_dictionary(),
                ffi::kSecReturnAttributes,
                ffi::kCFBooleanTrue.cast(),
            );
            cf_dictionary_set_value(
                query.as_mut_dictionary(),
                ffi::kSecMatchLimit,
                ffi::kSecMatchLimitAll.cast(),
            );
        }

        let mut result = std::ptr::null();
        let status = unsafe { ffi::SecItemCopyMatching(query.as_dictionary(), &mut result) };
        if status == ffi::status::ITEM_NOT_FOUND {
            return Ok(Vec::new());
        }
        if status != ffi::status::SUCCESS {
            return Err(SecurityError::from_status(
                "SecItemCopyMatching",
                status,
                sec_error_message(status),
            ));
        }

        let result = OwnedCf::new(result);
        let dictionary_type = unsafe { ffi::CFDictionaryGetTypeID() };
        let array_type = unsafe { ffi::CFArrayGetTypeID() };
        let result_type = crate::private::cf_type_id(result.as_ptr());
        let mut accounts = Vec::new();

        if result_type == dictionary_type {
            if let Some(account) = account_from_attributes(result.as_dictionary()) {
                accounts.push(account);
            }
        } else if result_type == array_type {
            let count = unsafe { ffi::CFArrayGetCount(result.as_array()) };
            let count = usize::try_from(count).unwrap_or_default();
            for index in 0..count {
                let Ok(index) = isize::try_from(index) else {
                    continue;
                };
                let value = unsafe { ffi::CFArrayGetValueAtIndex(result.as_array(), index) };
                if value.is_null() {
                    continue;
                }
                if let Some(account) = account_from_attributes(value.cast()) {
                    accounts.push(account);
                }
            }
        } else {
            return Err(SecurityError::UnexpectedType {
                operation: "SecItemCopyMatching",
                expected: "CFDictionary or CFArray",
            });
        }

        accounts.sort();
        accounts.dedup();
        Ok(accounts)
    }
}

fn account_from_attributes(dictionary: ffi::CFDictionaryRef) -> Option<String> {
    let value = cf_dictionary_get_value(dictionary, unsafe { ffi::kSecAttrAccount });
    if value.is_null() || crate::private::cf_type_id(value) != unsafe { ffi::CFStringGetTypeID() } {
        return None;
    }
    cf_string_to_string(value.cast())
}
