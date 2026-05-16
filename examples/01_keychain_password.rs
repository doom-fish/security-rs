#[path = "support/mod.rs"]
mod support;

use security::Keychain;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let account = "example-account";
    let service = support::unique_service("keychain");
    Keychain::set(account, &service, "secret-password")?;
    let password = Keychain::get(account, &service)?;
    let accounts = Keychain::list_accounts(&service)?;
    Keychain::delete(account, &service)?;
    println!("password={password} accounts={accounts:?}");
    Ok(())
}
