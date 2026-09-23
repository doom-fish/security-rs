use std::ffi::c_void;
use std::process::{Child, Command};

use security::{
    AuditToken, Code, CodeSigningFlags, CodeStatus, Requirement, SecurityError, StaticCode, Task,
};
use serde_json::json;

extern "C" {
    static mach_task_self_: u32;
    fn task_name_for_pid(target: u32, pid: i32, name: *mut u32) -> i32;
    fn task_info(task: u32, flavor: u32, info: *mut i32, count: *mut u32) -> i32;
    fn mach_port_deallocate(task: u32, name: u32) -> i32;
    fn xpc_dictionary_create(
        keys: *const *const i8,
        values: *const *mut c_void,
        count: usize,
    ) -> *mut c_void;
    fn xpc_release(object: *mut c_void);
}

const TASK_AUDIT_TOKEN: u32 = 15;

struct Peer(Child);

impl Peer {
    fn spawn() -> Self {
        Self(
            Command::new("/bin/sleep")
                .arg("60")
                .spawn()
                .expect("spawn /bin/sleep"),
        )
    }

    fn pid(&self) -> i32 {
        i32::try_from(self.0.id()).expect("pid fits in i32")
    }

    fn audit_token(&self) -> AuditToken {
        let mut name = 0_u32;
        let mut values = [0_u32; 8];
        let mut count = 8_u32;
        unsafe {
            assert_eq!(task_name_for_pid(mach_task_self_, self.pid(), &raw mut name), 0);
            let status = task_info(
                name,
                TASK_AUDIT_TOKEN,
                values.as_mut_ptr().cast(),
                &raw mut count,
            );
            mach_port_deallocate(mach_task_self_, name);
            assert_eq!(status, 0);
        }
        AuditToken::from_raw(values)
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn inspects_current_process() -> security::Result<()> {
    let code = Code::current()?;
    let static_code = code.static_code()?;
    assert!(static_code.path()?.exists());
    static_code.check_validity()?;
    static_code.check_validity_with_errors(CodeSigningFlags::empty(), None)?;
    code.check_validity(CodeSigningFlags::empty(), None)?;

    let dynamic = code.signing_information()?;
    assert!(dynamic.is_signed());
    assert!(dynamic
        .code_status()
        .is_some_and(|status| status.contains(CodeStatus::VALID)));
    assert_eq!(static_code.signing_information()?.status, None);

    assert!(Task::current()?.signing_identifier()?.is_some());
    Ok(())
}

#[test]
fn reads_signing_information_of_certificate_signed_code() -> security::Result<()> {
    let static_code = StaticCode::from_path("/bin/sleep")?;
    static_code.check_validity()?;
    let information = static_code.signing_information()?;
    assert_eq!(information.identifier.as_deref(), Some("com.apple.sleep"));
    assert_eq!(information.status, None);
    Ok(())
}

#[test]
fn validity_checks_enforce_requirements() -> security::Result<()> {
    let code = Code::current()?;
    let static_code = code.static_code()?;
    let never = Requirement::from_string("identifier \"security-rs.no-such-identifier\"")?;
    assert!(code
        .check_validity(CodeSigningFlags::empty(), Some(&never))
        .is_err());
    assert!(static_code
        .check_validity_with_errors(CodeSigningFlags::empty(), Some(&never))
        .is_err());
    assert!(static_code
        .check_static_validity(CodeSigningFlags::empty(), Some(&never))
        .is_err());
    Ok(())
}

#[test]
fn current_code_task_is_the_current_task() -> security::Result<()> {
    let code = Code::current()?;
    assert_eq!(code.audit_token(), Some(AuditToken::current()?));
    assert_eq!(
        code.task()?.signing_identifier()?,
        Task::current()?.signing_identifier()?
    );
    Ok(())
}

#[test]
fn pid_lookup_never_reports_the_callers_own_task() -> security::Result<()> {
    let peer = Peer::spawn();
    let code = Code::guest_with_attributes(
        None,
        Some(&json!({ "pid": peer.pid() })),
        CodeSigningFlags::empty(),
    )?;
    assert_eq!(code.audit_token(), None);
    assert!(matches!(code.task(), Err(SecurityError::Unsupported(_))));
    assert_eq!(
        code.signing_information()?.identifier.as_deref(),
        Some("com.apple.sleep")
    );
    Ok(())
}

#[test]
fn audit_token_lookup_identifies_the_peer() -> security::Result<()> {
    let peer = Peer::spawn();
    let token = peer.audit_token();

    let code = Code::guest_with_audit_token(&token)?;
    assert_eq!(code.audit_token(), Some(token));
    code.check_validity(CodeSigningFlags::empty(), None)?;
    assert_eq!(
        code.signing_information()?.identifier.as_deref(),
        Some("com.apple.sleep")
    );

    let task = code.task()?;
    assert_eq!(
        task.signing_identifier()?.as_deref(),
        Some("com.apple.sleep")
    );
    assert_ne!(
        task.signing_identifier()?,
        Task::current()?.signing_identifier()?
    );
    assert_eq!(
        Task::from_audit_token(&token)?.signing_identifier()?.as_deref(),
        Some("com.apple.sleep")
    );

    let from_json = Code::guest_with_attributes(
        None,
        Some(&json!({ "audit": token.to_bytes().to_vec() })),
        CodeSigningFlags::empty(),
    )?;
    assert_eq!(from_json.audit_token(), Some(token));
    Ok(())
}

#[test]
fn audit_token_bytes_round_trip() -> security::Result<()> {
    let token = AuditToken::current()?;
    assert_eq!(AuditToken::from_bytes(&token.to_bytes())?, token);
    assert_eq!(AuditToken::from_raw(token.to_raw()), token);
    assert!(AuditToken::from_bytes(&[0_u8; 31]).is_err());
    Ok(())
}

#[test]
fn xpc_message_without_a_sender_is_rejected() {
    unsafe {
        assert!(Code::from_xpc_message(std::ptr::null_mut()).is_err());
        let message = xpc_dictionary_create(std::ptr::null(), std::ptr::null(), 0);
        assert!(!message.is_null());
        assert!(Code::from_xpc_message(message).is_err());
        xpc_release(message);
    }
}

#[test]
fn validation_flags_do_not_alias_information_flags() {
    assert_eq!(CodeSigningFlags::CHECK_TRUSTED_ANCHORS.bits(), 1 << 27);
    assert_eq!(CodeSigningFlags::NO_NETWORK_ACCESS.bits(), 1 << 29);
    assert_eq!(CodeSigningFlags::ENFORCE_REVOCATION_CHECKS.bits(), 1 << 30);
    assert_eq!(CodeSigningFlags::CONSIDER_EXPIRATION.bits(), 1 << 31);
    assert_eq!(
        CodeSigningFlags::from_bits(1 << 1),
        Some(CodeSigningFlags::DO_NOT_VALIDATE_EXECUTABLE)
    );
    assert_eq!(
        CodeSigningFlags::from_bits(1 << 3),
        Some(CodeSigningFlags::CHECK_NESTED_CODE)
    );
}
