use security::Authorization;

#[test]
fn externalizes_and_rehydrates() -> security::Result<()> {
    let authorization = Authorization::new()?;
    let external = authorization.external_form()?;
    assert!(!external.is_empty());
    let _round_trip = Authorization::from_external_form(&external)?;
    Ok(())
}
