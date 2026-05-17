# Security.framework coverage audit

Legend:

- ✅ implemented
- 🟡 partial
- ⏭️ skipped

The safe API defaults to the Swift bridge. Direct raw C declarations remain available behind the `raw-ffi` Cargo feature, which now exhaustively covers the non-deprecated macOS-available `SecAccessControl.h`, `SecItem.h`, `SecKey.h`, and `SecPolicy.h` surfaces. The audited non-exempt function surface in [`COVERAGE_AUDIT.md`](COVERAGE_AUDIT.md) is now fully closed.

| Area | API / header surface | Status | Notes |
| --- | --- | --- | --- |
| Keychain | `SecItemAdd`, `SecItemCopyMatching`, `SecItemUpdate`, `SecItemDelete` | ✅ | Exposed through `Keychain` / `KeychainEntry`. |
| Keychain | Generic-password account enumeration (`kSecReturnAttributes`, `kSecMatchLimitAll`) | ✅ | Exposed through `Keychain::list_accounts`. |
| Keychain | `SecItemImport`, `SecItemExport` | 🟡 | Covered indirectly through identity / CMS flows; not exposed as generic item import/export yet. |
| Keychain | `SecAccessControlCreateWithFlags`, `SecAccessControlGetTypeID` | ✅ | Exposed through `AccessControl::create` / `AccessControl::type_id`. |
| Keychain | Non-deprecated macOS `SecItem.h` raw constants | ✅ | Exposed through the exhaustive `raw-ffi` surface. |
| Keychain | Legacy `SecKeychain*` manager APIs | ⏭️ | Deprecated macOS-only keychain-manager surface; intentionally left out of the safe bridge. |
| Identity | `SecIdentityCopyCertificate`, `SecIdentityCreate`, `SecIdentityCreateWithCertificate` | ✅ | Exposed through `Identity::certificate`, `from_certificate_and_private_key`, and `with_certificate`. |
| Identity | `SecIdentityCopyPreferred`, `SecIdentitySetPreferred` | ✅ | Exposed through `Identity::preferred` / `set_preferred`. |
| Identity | `SecIdentityCopySystemIdentity`, `SecIdentitySetSystemIdentity`, `SecIdentityGetTypeID` | ✅ | Exposed through `copy_system_identity`, `set_system_identity`, `actual_domain`, and `type_id`. |
| Identity | `SecIdentityCopyPrivateKey` | ✅ | Exposed through `Identity::private_key_attributes`. |
| Identity | `SecPKCS12Import` (`SecImportExport.h`) | ✅ | Exposed through `Identity::import_pkcs12_first`. |
| Identity | `kSecImportToMemoryOnly` | ✅ | Used when available to keep tests headless and side-effect-light. |
| Certificate | `SecCertificateCreateWithData` | ✅ | Exposed through `Certificate::from_der` and `from_pem`. |
| Certificate | `SecCertificateCopyData` | ✅ | Exposed through `Certificate::der_data`. |
| Certificate | `SecCertificateCopySubjectSummary` | ✅ | Exposed through `Certificate::subject_summary`. |
| Certificate | `SecCertificateCopyCommonName` | ✅ | Exposed through `Certificate::common_name`. |
| Certificate | `SecCertificateCopyEmailAddresses` | ✅ | Exposed through `Certificate::email_addresses`. |
| Certificate | `SecCertificateCopyNormalizedSubjectSequence` | ✅ | Exposed through `Certificate::normalized_subject_sequence`. |
| Certificate | `SecCertificateCopyNormalizedIssuerSequence` | ✅ | Exposed through `Certificate::normalized_issuer_sequence`. |
| Certificate | `SecCertificateCopyKey` | ✅ | Exposed through `Certificate::public_key`. |
| Certificate | `SecCertificateCopySerialNumberData` | ✅ | Exposed through `Certificate::serial_number`. |
| Certificate | `SecCertificateCopyNotValidBeforeDate`, `SecCertificateCopyNotValidAfterDate` | ✅ | Exposed through `Certificate::not_valid_before` / `not_valid_after` with runtime availability checks. |
| Certificate | `SecCertificateCopyValues`, descriptions, preferences, and type IDs | ✅ | Exposed through `Certificate::values`, `long_description`, `short_description`, `preferred`, `set_preferred`, and `type_id`. |
| Certificate | `SecCertificateAddToKeychain` | ✅ | Exposed through `Certificate::add_to_keychain`. |
| Certificate | Deprecated infer-label helpers | ⏭️ | Deprecated legacy APIs, superseded by `SecItem*` and modern certificate accessors. |
| Key | `SecKeyCreateWithData`, `SecKeyCopyPublicKey`, `SecKeyCreateSignature`, `SecKeyVerifySignature` | ✅ | Exposed through `PrivateKey`, `PublicKey`, and signature helpers. |
| Key | `SecKeyCreateEncryptedData`, `SecKeyCreateDecryptedData` | ✅ | Exposed through `PublicKey::encrypt` / `PrivateKey::decrypt`. |
| Key | `SecKeyCopyExternalRepresentation`, `SecKeyGetBlockSize`, `SecKeyGetTypeID` | ✅ | Exposed through `external_representation`, `block_size`, and `type_id` helpers. |
| Key | Non-deprecated macOS `SecKey.h` raw constants and modern functions | ✅ | Exposed through the exhaustive `raw-ffi` surface. |
| Policy | `SecPolicyCreateBasicX509` | ✅ | Exposed through `Policy::basic_x509`. |
| Policy | `SecPolicyCreateSSL` | ✅ | Exposed through `Policy::ssl`. |
| Policy | `SecPolicyCreateRevocation` | ✅ | Exposed through `Policy::revocation`. |
| Policy | `SecPolicyCopyProperties` | ✅ | Exposed through `Policy::properties`. |
| Policy | `SecPolicyCreateWithProperties` | ✅ | Exposed through `Policy::with_properties`. |
| Policy | `SecPolicyGetTypeID` | ✅ | Exposed through `Policy::type_id`. |
| Policy | Non-deprecated macOS `SecPolicy.h` raw constants | ✅ | Exposed through the exhaustive `raw-ffi` surface. |
| Policy | Deprecated `SecPolicySearch*` APIs | ⏭️ | Deprecated legacy search APIs. |
| Trust | `SecTrustCreateWithCertificates` | ✅ | Exposed through `Trust::new` / `Trust::from_certificates`. |
| Trust | `SecTrustSetPolicies`, `SecTrustCopyPolicies` | ✅ | Exposed through `Trust::set_policies` / `policies`. |
| Trust | `SecTrustSetAnchorCertificates`, `SecTrustCopyCustomAnchorCertificates`, `SecTrustCopyAnchorCertificates` | ✅ | Exposed through `set_anchor_certificates`, `custom_anchor_certificates`, and `system_anchor_certificates`. |
| Trust | `SecTrustSetAnchorCertificatesOnly` | ✅ | Exposed through `Trust::set_anchor_certificates_only`. |
| Trust | `SecTrustSetNetworkFetchAllowed`, `SecTrustGetNetworkFetchAllowed` | ✅ | Exposed through `set_network_fetch_allowed` / `network_fetch_allowed`. |
| Trust | `SecTrustSetVerifyDate`, `SecTrustGetVerifyTime`, `SecTrustSetOptions` | ✅ | Exposed through `set_verify_date`, `verify_time`, and `set_options`. |
| Trust | `SecTrustEvaluateWithError`, `SecTrustEvaluateAsyncWithError`, `SecTrustGetTrustResult` | ✅ | Exposed through `evaluate`, `evaluate_async`, and `trust_result_type`. |
| Trust | `SecTrustCopyResult`, `SecTrustCopyKey`, `SecTrustGetCertificateCount`, `SecTrustCopyCertificateChain` | ✅ | Exposed through `result`, `key`, `certificate_count`, and `certificate_chain`. |
| Trust | `SecTrustCopyExceptions`, `SecTrustSetExceptions`, `SecTrustSetOCSPResponse`, `SecTrustSetSignedCertificateTimestamps`, `SecTrustGetTypeID` | ✅ | Exposed through `exceptions`, `set_exceptions`, `set_ocsp_responses`, `set_signed_certificate_timestamps`, and `type_id`. |
| Trust | Deprecated `SecTrustEvaluate`, `SecTrustGetResult`, `SecTrustGetCertificateAtIndex` | ⏭️ | Deprecated pre-modern-evaluation APIs. |
| Authorization | `AuthorizationCreate` | ✅ | Exposed through `Authorization::new` / `with_options`. |
| Authorization | `AuthorizationFree` | ✅ | Freed via `Drop` on the Swift-side authorization box. |
| Authorization | `AuthorizationMakeExternalForm` | ✅ | Exposed through `Authorization::external_form`. |
| Authorization | `AuthorizationCreateFromExternalForm` | ✅ | Exposed through `Authorization::from_external_form`. |
| Authorization | `AuthorizationCopyInfo`, `AuthorizationCopyRights`, `AuthorizationCopyRightsAsync`, `AuthorizationFreeItemSet` | ✅ | Exposed through `copy_info`, `copy_rights`, and `copy_rights_async`, with bridge-side item-set cleanup. |
| Code | `SecCodeCopySelf`, `SecCodeGetTypeID` | ✅ | Exposed through `Code::current` / `type_id`. |
| Code | `SecCodeCopyStaticCode` | ✅ | Exposed through `Code::static_code`. |
| Code | `SecCodeCheckValidity`, `SecCodeCheckValidityWithErrors` | ✅ | Exposed through `StaticCode::check_validity` / `check_validity_with_errors`. |
| Code | `SecCodeCopyPath`, `SecCodeCopyDesignatedRequirement`, `SecCodeCopySigningInformation` | ✅ | Exposed through `StaticCode::path`, `designated_requirement`, and signing-information helpers. |
| Code | `SecCodeCopyHost`, `SecCodeCopyGuestWithAttributes` | ✅ | Exposed through `Code::host` / `guest_with_attributes`. |
| Code | `SecCodeValidateFileResource`, `SecCodeMapMemory` | ✅ | Exposed through `StaticCode::validate_file_resource` / `map_memory`. |
| Code | `SecRequirementCreateWithData`, `SecRequirementCreateWithString`, `SecRequirementCreateWithStringAndErrors`, `SecRequirementCopyData`, `SecRequirementCopyString`, `SecRequirementGetTypeID` | ✅ | Exposed through `Requirement` parsing / serialization helpers and `type_id`. |
| Code | `SecStaticCodeCreateWithPath`, `SecStaticCodeCreateWithPathAndAttributes`, `SecStaticCodeCheckValidity`, `SecStaticCodeCheckValidityWithErrors`, `SecStaticCodeGetTypeID` | ✅ | Exposed through `StaticCode::from_path`, `from_path_with_attributes`, static-validation helpers, and `type_id`. |
| Code | `SecTaskCreateFromSelf`, `SecTaskCreateWithAuditToken`, `SecTaskGetTypeID` | ✅ | Exposed through `Task::current`, `current_with_audit_token`, and `type_id`. |
| Code | `SecTaskCopySigningIdentifier`, `SecTaskCopyValueForEntitlement`, `SecTaskCopyValuesForEntitlements` | ✅ | Exposed through `Task::signing_identifier`, `entitlement`, and `entitlements`. |
| Code | `SecCodeCreateWithXPCMessage` | ⏭️ | Requires an inbound `xpc_object_t` message with sender context; intentionally excluded from the safe surface. |
| RandomBytes | `SecRandomCopyBytes` | ✅ | Exposed through `SecureRandom::fill` / `bytes`. |
| Transform | `SecEncodeTransformCreate` | ✅ | Exposed for base64 encode. |
| Transform | `SecDecodeTransformCreate` | ✅ | Exposed for base64 decode. |
| Transform | `SecTransformSetAttribute`, `SecTransformExecute` | ✅ | Used internally by the base64 helpers. |
| Transform | Other encode/decode transform families | 🟡 | Header audited; only the headless base64 path is wrapped today. |
| Transform | Remaining `SecTransform*` pipeline APIs | ⏭️ | Deprecated, callback-heavy, and broader than the crate's current focused wrappers. |
| SecureTransport | `SSLCreateContext` | ✅ | Exposed through `SecureTransportContext::client` / `server`. |
| SecureTransport | `SSLSetProtocolVersionMin`, `SSLSetProtocolVersionMax` | ✅ | Exposed through protocol min/max setters. |
| SecureTransport | `SSLGetSessionState` | ✅ | Exposed through `SecureTransportContext::state`. |
| SecureTransport | I/O callbacks, `SSLHandshake`, `SSLRead`, `SSLWrite` | ⏭️ | Deprecated and callback-heavy; omitted from the headless bridge surface. |
| SecureTransport | Session-option and peer-certificate configuration | 🟡 | Header audited; not yet surfaced because the current wrapper focuses on context creation and state inspection. |
| CMS | `CMSEncoderCreate`, `CMSEncoderGetTypeID` | ✅ | Exposed through `Cms::encoder` and `CmsEncoder::type_id`. |
| CMS | `CMSEncoderAddSupportingCerts`, `CMSEncoderCopyEncodedContent` | ✅ | Exposed through `Cms::encode_supporting_certificates` and `CmsEncoder::encoded_content`. |
| CMS | `CMSEncodeContent`, signers, recipients, content-type, detached-content, chain-mode, signer-algorithm, signed-attributes, timestamps | ✅ | Exposed through `Cms::encode_content` and the full `CmsEncoder` API surface. |
| CMS | `CMSDecoderCreate`, `CMSDecoderGetTypeID` | ✅ | Exposed through `Cms::decoder` and `CmsDecoder::type_id`. |
| CMS | `CMSDecoderUpdateMessage`, `CMSDecoderFinalizeMessage`, `CMSDecoderCopyAllCerts` | ✅ | Exposed through `Cms::decode_all_certificates` and direct decoder helpers. |
| CMS | Content, detached content, signer status, signer metadata, timestamps, and encryption state | ✅ | Exposed through the full `CmsDecoder` API surface. |
| KeyDerivation | `SecKeyDeriveFromPassword` | ✅ | Exposed through `KeyDerivation::derive_pbkdf2_sha256`. |
| KeyDerivation | `SecKeyCopyAttributes` on derived key | ✅ | Exposed through `DerivedKey::attributes`. |
| KeyDerivation | Legacy wrap / unwrap symmetric-key APIs | ⏭️ | Deprecated follow-on APIs not required for the current headless KDF wrapper. |
| KeyAgreement | `SecKeyCreateRandomKey` | ✅ | Exposed through `AgreementPrivateKey::generate_p256`. |
| KeyAgreement | `SecKeyCopyPublicKey` | ✅ | Exposed through `AgreementPrivateKey::public_key`. |
| KeyAgreement | `SecKeyCopyAttributes` | ✅ | Exposed through key attribute inspection. |
| KeyAgreement | `SecKeyIsAlgorithmSupported` | ✅ | Exposed through `AgreementPrivateKey::is_supported`. |
| KeyAgreement | `SecKeyCopyKeyExchangeResult` | ✅ | Exposed through `AgreementPrivateKey::shared_secret`. |
| KeyAgreement | Other `SecKey` signature / encryption algorithms | ⏭️ | Outside the scoped key-agreement wrapper; the crate focuses on ECDH shared-secret derivation here. |
| Legacy / admin | `AuthorizationDB.h`, `AuthorizationPlugin.h`, `SecAccess*`, `SecACL*`, CSSM headers | ⏭️ | Administrative, plug-in, or deprecated legacy surfaces outside the safe bridge scope. |
