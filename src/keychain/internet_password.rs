use std::ffi::c_void;

use crate::bridge::{self, Handle};
use crate::error::{status, OsStatus, Result, SecurityError, StatusError};
use crate::secret::SecretBytes;

#[derive(Debug)]
pub struct InternetCredential {
    pub account: String,
    pub secret: SecretBytes,
}

pub struct InternetPassword;

impl InternetPassword {
    pub fn set(server: &str, account: &str, secret: impl AsRef<[u8]>) -> Result<()> {
        let server = bridge::cstring(server)?;
        let account = bridge::cstring(account)?;
        let secret = secret.as_ref();
        let secret_len = bridge::len_to_isize(secret.len())?;
        let mut failed_operation = 0;
        let mut error = std::ptr::null_mut();
        let status_code = unsafe {
            bridge::security_internet_password_set_item(
                server.as_ptr(),
                account.as_ptr(),
                secret.as_ptr().cast(),
                secret_len,
                &raw mut failed_operation,
                &raw mut error,
            )
        };
        if status_code == status::SUCCESS {
            return Ok(());
        }

        let operation = match failed_operation {
            1 => "SecItemUpdate",
            2 => "SecItemAdd",
            _ => "security_internet_password_set_item",
        };
        Err(item_status_error(operation, status_code, error)?)
    }

    pub fn get(server: &str) -> Result<Option<InternetCredential>> {
        let server = bridge::cstring(server)?;
        let mut account = std::ptr::null_mut();
        let mut status_code = status::SUCCESS;
        let mut error = std::ptr::null_mut();
        let secret = unsafe {
            bridge::security_internet_password_copy_item(
                server.as_ptr(),
                &raw mut account,
                &raw mut status_code,
                &raw mut error,
            )
        };
        match status_code {
            status::ITEM_NOT_FOUND | status::USER_CANCELED => Ok(None),
            status::SUCCESS => {
                let (Some(account), Some(secret)) =
                    (Handle::from_raw(account), Handle::from_raw(secret))
                else {
                    return Err(SecurityError::UnexpectedType {
                        operation: "SecItemCopyMatching",
                        expected: "dictionary with string kSecAttrAccount and data kSecValueData",
                    });
                };
                Ok(Some(InternetCredential {
                    account: bridge::read_string(&account)?,
                    secret: bridge::read_secret(&secret, "SecItemCopyMatching")?,
                }))
            }
            _ => Err(item_status_error(
                "SecItemCopyMatching",
                status_code,
                error,
            )?),
        }
    }

    pub fn delete(server: &str) -> Result<()> {
        let server = bridge::cstring(server)?;
        let mut error = std::ptr::null_mut();
        let status_code = unsafe {
            bridge::security_internet_password_delete_item(server.as_ptr(), &raw mut error)
        };
        if status_code == status::SUCCESS {
            Ok(())
        } else {
            Err(item_status_error("SecItemDelete", status_code, error)?)
        }
    }
}

fn item_status_error(
    operation: &'static str,
    status_code: OsStatus,
    error: *mut c_void,
) -> Result<SecurityError> {
    let message =
        bridge::optional_string(error)?.unwrap_or_else(|| format!("OSStatus {status_code}"));
    Ok(SecurityError::Status(StatusError {
        operation,
        status: status_code,
        message,
    }))
}
