use security::prelude::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let account = "doom-fish-smoke";
    let service = format!("doom-fish-smoke-test-{}", std::process::id());

    let _ = Keychain::delete(account, &service);
    Keychain::set(account, &service, "hunter2")?;

    let value = Keychain::get(account, &service)?;
    assert_eq!(value, "hunter2");

    let accounts = Keychain::list_accounts(&service)?;
    assert!(accounts.iter().any(|candidate| candidate == account));

    Keychain::delete(account, &service)?;

    let random = SecureRandom::bytes(32)?;
    assert!(random.iter().any(|&byte| byte != 0));

    println!("✅ security keychain + RNG OK");
    Ok(())
}
