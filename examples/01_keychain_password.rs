#[path = "support/mod.rs"]
mod support;

use security::{AccessControl, AccessControlFlags, AccessControlProtection, Keychain};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let account = "example-account";
    let service = support::unique_service("keychain");
    let access_control = AccessControl::create(
        AccessControlProtection::WhenUnlocked,
        AccessControlFlags::PRIVATE_KEY_USAGE,
    )?;
    Keychain::set(account, &service, "secret-password")?;
    let password = Keychain::get(account, &service)?;
    let accounts = Keychain::list_accounts(&service)?;
    Keychain::delete(account, &service)?;
    println!(
        "password={password} accounts={accounts:?} access_control_created={}",
        access_control.is_valid()
    );
    Ok(())
}
