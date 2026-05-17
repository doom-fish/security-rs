use security::{Policy, PolicyIdentifier, PolicyName, PolicyProperties};

#[test]
fn creates_policy_variants() -> security::Result<()> {
    assert!(Policy::type_id() > 0);
    assert!(Policy::basic_x509()?.properties()?.is_object());
    assert!(Policy::ssl(true, Some("localhost"))?
        .properties()?
        .is_object());
    assert!(Policy::revocation(0)?.properties()?.is_object());
    Ok(())
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
