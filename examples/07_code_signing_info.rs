use security::{Code, Task};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let code = Code::current()?;
    let static_code = code.static_code()?;
    let signing = code.signing_information()?;
    let task = Task::current()?;
    println!(
        "path={:?} signed={} task_identifier={:?} validity_ok={}",
        static_code.path()?.display(),
        signing.is_signed(),
        task.signing_identifier()?,
        static_code.check_validity().is_ok()
    );
    Ok(())
}
