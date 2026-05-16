mod common;

use security::Keychain;

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
