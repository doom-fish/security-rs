#![cfg(feature = "async")]

mod common;

use security::async_api::{AsyncAuthorization, AsyncTrust};
use security::{Authorization, AuthorizationOptions, Certificate, Policy, SecurityError, Trust};

#[test]
fn async_trust_evaluation_reports_both_outcomes() -> security::Result<()> {
    let certificate = Certificate::from_der(&common::fixture("test-cert.der"))?;
    let mut trust = Trust::new(&certificate, &[Policy::basic_x509()?])?;
    trust.set_network_fetch_allowed(false)?;
    assert!(matches!(
        pollster::block_on(AsyncTrust::new(&trust).evaluate()?),
        Err(SecurityError::TrustEvaluationFailed(_))
    ));

    trust.set_anchor_certificates(&[certificate])?;
    trust.set_anchor_certificates_only(true)?;
    pollster::block_on(AsyncTrust::new(&trust).evaluate()?)?;
    trust.evaluate_async()?;
    Ok(())
}

#[test]
fn async_rights_request_without_interaction_fails_without_ui() -> security::Result<()> {
    let authorization = Authorization::new()?;
    let request = AsyncAuthorization::new(&authorization).copy_rights(
        &["system.privilege.admin"],
        AuthorizationOptions::EXTEND_RIGHTS,
    )?;
    assert!(pollster::block_on(request).is_err());
    assert!(AsyncAuthorization::new(&authorization)
        .copy_rights(&[], AuthorizationOptions::EXTEND_RIGHTS)
        .is_err());
    Ok(())
}

#[test]
fn dropping_the_authorization_while_a_request_is_in_flight_is_safe() -> security::Result<()> {
    for _ in 0..16 {
        let authorization = Authorization::new()?;
        let request = AsyncAuthorization::new(&authorization).copy_rights(
            &["system.privilege.admin"],
            AuthorizationOptions::EXTEND_RIGHTS,
        )?;
        drop(request);
        drop(authorization);
    }
    std::thread::sleep(std::time::Duration::from_millis(500));

    let authorization = Authorization::new()?;
    let request = AsyncAuthorization::new(&authorization).copy_rights(
        &["system.privilege.admin"],
        AuthorizationOptions::EXTEND_RIGHTS,
    )?;
    assert!(pollster::block_on(request).is_err());
    Ok(())
}
