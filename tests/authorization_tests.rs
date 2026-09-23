use security::{Authorization, AuthorizationOptions};

#[test]
fn externalizes_and_rehydrates() -> security::Result<()> {
    let authorization = Authorization::new()?;
    let external = authorization.external_form()?;
    assert_eq!(external.len(), 32);
    let round_trip = Authorization::from_external_form(&external)?;
    assert_eq!(round_trip.external_form()?.len(), 32);
    assert!(Authorization::from_external_form(&external[..31]).is_err());
    Ok(())
}

#[test]
fn destroying_rights_on_drop_leaves_shared_references_usable() -> security::Result<()> {
    let mut authorization = Authorization::new()?;
    authorization.copy_rights(&["system.hdd.smart"], AuthorizationOptions::EXTEND_RIGHTS)?;
    let external = authorization.external_form()?;
    let shared = Authorization::from_external_form(&external)?;
    authorization.set_destroy_rights_on_drop(true);
    drop(authorization);
    assert!(shared.copy_info(None)?.is_array());
    assert_eq!(shared.external_form()?.len(), 32);
    Ok(())
}

#[test]
fn rights_requests_reject_invalid_names_before_calling_the_framework() -> security::Result<()> {
    let authorization = Authorization::new()?;
    assert!(authorization
        .copy_rights(&["bad\0name"], AuthorizationOptions::DEFAULTS)
        .is_err());
    assert!(authorization
        .copy_rights(&[], AuthorizationOptions::DEFAULTS)
        .is_err());
    Ok(())
}
