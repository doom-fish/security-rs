#[path = "support/mod.rs"]
mod support;

use security::InternetPassword;

struct RemoveOnDrop<'a>(&'a str);

impl Drop for RemoveOnDrop<'_> {
    fn drop(&mut self) {
        let _ = InternetPassword::delete(self.0);
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let server = support::unique_service("internet-password");
    let _cleanup = RemoveOnDrop(&server);
    InternetPassword::set(&server, "example-account", b"secret-password")?;
    let credential = InternetPassword::get(&server)?.expect("stored internet password");
    println!(
        "account={} round_trip_ok={}",
        credential.account,
        credential.secret.as_bytes() == b"secret-password"
    );
    InternetPassword::delete(&server)?;
    Ok(())
}
