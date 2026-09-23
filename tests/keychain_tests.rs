mod common;

use std::ffi::{c_char, c_void};

use security::error::status;
use security::{
    AccessControl, AccessControlFlags, AccessControlProtection, Keychain, KeychainOptions,
    SecurityError,
};

#[link(name = "LocalAuthentication", kind = "framework")]
extern "C" {}

extern "C" {
    fn objc_getClass(name: *const c_char) -> *mut c_void;
    fn sel_registerName(name: *const c_char) -> *mut c_void;
    fn objc_msgSend();
}

unsafe fn send(receiver: *mut c_void, selector: &std::ffi::CStr) -> *mut c_void {
    let message: unsafe extern "C" fn(*mut c_void, *mut c_void) -> *mut c_void =
        unsafe { std::mem::transmute(objc_msgSend as unsafe extern "C" fn()) };
    unsafe { message(receiver, sel_registerName(selector.as_ptr())) }
}

unsafe fn new_object(class: &std::ffi::CStr) -> *mut c_void {
    unsafe { send(objc_getClass(class.as_ptr()), c"new") }
}

fn assert_needs_data_protection_entitlement_or(result: security::Result<()>) -> bool {
    match result {
        Ok(()) => true,
        Err(error) => {
            assert_eq!(error.code(), Some(status::MISSING_ENTITLEMENT), "{error}");
            false
        }
    }
}

#[test]
fn generic_password_round_trip() -> security::Result<()> {
    let account = "integration-account";
    let service = common::unique_service("keychain");
    Keychain::set(account, &service, "secret")?;
    let secret = Keychain::get(account, &service)?;
    assert_eq!(secret.as_str()?, "secret");
    assert_eq!(format!("{secret:?}"), "SecretBytes(<redacted>)");

    Keychain::set(account, &service, "rotated")?;
    assert_eq!(Keychain::get(account, &service)?.as_bytes(), b"rotated");
    assert!(Keychain::list_accounts(&service)?.contains(&account.to_owned()));

    Keychain::delete(account, &service)?;
    assert!(matches!(
        Keychain::get(account, &service),
        Err(SecurityError::ItemNotFound(_))
    ));
    Ok(())
}

#[test]
fn stores_binary_secrets_with_a_device_only_protection_class() -> security::Result<()> {
    let account = "binary-account";
    let service = common::unique_service("keychain-binary");
    let secret = [0_u8, 0x9f, 0x92, 0x96, 0xff, 0x00, 0x01];
    let options = KeychainOptions::default()
        .accessibility(AccessControlProtection::WhenUnlockedThisDeviceOnly);
    Keychain::set_with_options(account, &service, secret, &options)?;
    let stored = Keychain::get_with_options(account, &service, &options)?;
    assert_eq!(stored.as_bytes(), secret);
    assert!(stored.as_str().is_err());
    assert_eq!(
        Keychain::list_accounts_with_options(&service, &options)?,
        vec![account.to_owned()]
    );
    Keychain::delete_with_options(account, &service, &options)?;
    assert!(Keychain::get_with_options(account, &service, &options).is_err());
    Ok(())
}

#[test]
fn keychain_entry_reads_back_secrets() -> security::Result<()> {
    let service = common::unique_service("keychain-entry");
    let entry = Keychain::entry("entry-account", service.as_str());
    entry.set(b"entry-secret")?;
    assert_eq!(entry.get()?.as_bytes(), b"entry-secret");
    entry.delete()?;
    Ok(())
}

#[test]
fn data_protection_keychain_is_requested() -> security::Result<()> {
    let account = "dp-account";
    let service = common::unique_service("keychain-dp");
    let options = KeychainOptions::default().data_protection_keychain(true);
    if assert_needs_data_protection_entitlement_or(Keychain::set_with_options(
        account, &service, b"secret", &options,
    )) {
        assert_eq!(
            Keychain::get_with_options(account, &service, &options)?.as_bytes(),
            b"secret"
        );
        Keychain::delete_with_options(account, &service, &options)?;
    }
    Ok(())
}

#[test]
fn access_groups_and_synchronizable_items_are_requested() -> security::Result<()> {
    let service = common::unique_service("keychain-sync");
    for (account, options) in [
        (
            "group-account",
            KeychainOptions::default()
                .data_protection_keychain(true)
                .access_group("security-rs.tests.group"),
        ),
        (
            "sync-account",
            KeychainOptions::default().synchronizable(true),
        ),
    ] {
        if assert_needs_data_protection_entitlement_or(Keychain::set_with_options(
            account, &service, b"secret", &options,
        )) {
            Keychain::delete_with_options(account, &service, &options)?;
        }
    }
    Ok(())
}

#[test]
fn access_control_is_attached_to_the_item() -> security::Result<()> {
    let account = "access-control-account";
    let service = common::unique_service("keychain-acl");
    let access_control = AccessControl::create(
        AccessControlProtection::WhenUnlockedThisDeviceOnly,
        AccessControlFlags::USER_PRESENCE,
    )?;
    let options = KeychainOptions::default().access_control(access_control);
    if assert_needs_data_protection_entitlement_or(Keychain::set_with_options(
        account, &service, b"secret", &options,
    )) {
        Keychain::delete_with_options(account, &service, &options)?;
    }
    assert!(Keychain::get(account, &service).is_err());
    Ok(())
}

#[test]
fn authentication_context_accepts_only_la_contexts() -> security::Result<()> {
    unsafe {
        let context = new_object(c"LAContext");
        assert!(!context.is_null());
        let options = KeychainOptions::default().authentication_context(context)?;
        send(context, c"release");

        let account = "context-account";
        let service = common::unique_service("keychain-context");
        if assert_needs_data_protection_entitlement_or(Keychain::set_with_options(
            account, &service, b"secret", &options,
        )) {
            assert_eq!(
                Keychain::get_with_options(account, &service, &options)?.as_bytes(),
                b"secret"
            );
            Keychain::delete_with_options(account, &service, &options)?;
        }

        let not_a_context = new_object(c"NSObject");
        assert!(KeychainOptions::default()
            .authentication_context(not_a_context)
            .is_err());
        send(not_a_context, c"release");
        assert!(KeychainOptions::default()
            .authentication_context(std::ptr::null_mut())
            .is_err());
    }
    Ok(())
}

#[test]
fn creates_access_control() -> security::Result<()> {
    assert!(AccessControl::type_id() > 0);
    let access_control = AccessControl::create(
        AccessControlProtection::WhenUnlocked,
        AccessControlFlags::PRIVATE_KEY_USAGE,
    )?;
    assert!(access_control.is_valid());
    Ok(())
}
