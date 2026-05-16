mod common;

use security::{AccessControl, AccessControlFlags, AccessControlProtection, Keychain};

#[test]
fn generic_password_round_trip() -> security::Result<()> {
    let account = "integration-account";
    let service = common::unique_service("keychain");
    Keychain::set(account, &service, "secret")?;
    assert_eq!(Keychain::get(account, &service)?, "secret");
    assert!(Keychain::list_accounts(&service)?.contains(&account.to_owned()));
    Keychain::delete(account, &service)?;
    Ok(())
}

#[test]
fn creates_access_control() -> security::Result<()> {
    let access_control = AccessControl::create(
        AccessControlProtection::WhenUnlocked,
        AccessControlFlags::PRIVATE_KEY_USAGE,
    )?;
    assert!(access_control.is_valid());
    Ok(())
}
