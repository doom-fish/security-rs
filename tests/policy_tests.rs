mod common;

use std::time::{Duration, UNIX_EPOCH};

use security::{
    Certificate, Policy, PolicyIdentifier, PolicyName, PolicyProperties, SecurityError, Trust,
};

fn tls_trust(policy: Policy) -> security::Result<Trust> {
    let ca_der = common::fixture("test-tls-ca.der");
    let chain = [
        Certificate::from_der(&common::fixture("test-tls-localhost.der"))?,
        Certificate::from_der(&ca_der)?,
    ];
    let mut trust = Trust::from_certificates(&chain, &[policy])?;
    trust.set_anchor_certificates(&[Certificate::from_der(&ca_der)?])?;
    trust.set_anchor_certificates_only(true)?;
    trust.set_network_fetch_allowed(false)?;
    trust.set_verify_date(UNIX_EPOCH + Duration::from_secs(1_790_263_001))?;
    Ok(trust)
}

#[test]
fn creates_policy_variants() -> security::Result<()> {
    assert!(Policy::type_id() > 0);
    assert!(Policy::basic_x509()?.properties()?.is_object());
    assert!(Policy::ssl(true, "localhost")?.properties()?.is_object());
    assert!(Policy::revocation(3)?.properties()?.is_object());
    Ok(())
}

#[test]
fn revocation_policy_rejects_flags_the_framework_refuses() {
    assert!(Policy::revocation(0).is_err());
}

#[test]
fn creates_policy_with_properties() -> security::Result<()> {
    let policy = Policy::with_properties(
        PolicyIdentifier::AppleSsl,
        &PolicyProperties {
            name: Some(PolicyName::from("localhost")),
            client: Some(false),
            ..PolicyProperties::default()
        },
    )?;
    let properties = policy.properties()?;
    assert_eq!(
        properties
            .get("SecPolicyName")
            .and_then(serde_json::Value::as_str),
        Some("localhost")
    );
    Ok(())
}

#[test]
fn ssl_policy_verifies_the_hostname() -> security::Result<()> {
    tls_trust(Policy::ssl(true, "localhost")?)?.evaluate()?;
    assert!(matches!(
        tls_trust(Policy::ssl(true, "attacker.example")?)?.evaluate(),
        Err(SecurityError::TrustEvaluationFailed(_))
    ));
    Ok(())
}

#[test]
fn ssl_policy_without_hostname_must_be_requested_explicitly() -> security::Result<()> {
    assert!(matches!(
        Policy::ssl(true, ""),
        Err(SecurityError::InvalidArgument(_))
    ));
    let any_hostname = Policy::ssl_any_hostname(true)?;
    assert!(any_hostname.properties()?.get("SecPolicyName").is_none());
    assert_eq!(
        Policy::ssl(true, "localhost")?
            .properties()?
            .get("SecPolicyName")
            .and_then(serde_json::Value::as_str),
        Some("localhost")
    );
    tls_trust(any_hostname)?.evaluate()?;
    Ok(())
}
