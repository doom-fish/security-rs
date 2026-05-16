use security::{Code, Task};

#[test]
fn inspects_current_process() -> security::Result<()> {
    let code = Code::current()?;
    let static_code = code.static_code()?;
    assert!(static_code.path()?.exists());
    let _ = static_code.check_validity();
    let _ = code.signing_information()?;
    let _ = Task::current()?.signing_identifier()?;
    Ok(())
}
