# Security.framework coverage audit

Legend:

- ✅ implemented
- 🟡 partial
- ⏭️ skipped

The safe API defaults to the Swift bridge. Direct raw C declarations remain available behind the `raw-ffi` Cargo feature, which now exhaustively covers the non-deprecated macOS-available `SecAccessControl.h`, `SecItem.h`, `SecKey.h`, and `SecPolicy.h` surfaces.

| Area | API / header surface | Status | Notes |
| --- | --- | --- | --- |
| Keychain | `SecItemAdd`, `SecItemCopyMatching`, `SecItemUpdate`, `SecItemDelete` | ✅ | Exposed through `Keychain` / `KeychainEntry`. |
| Keychain | Generic-password account enumeration (`kSecReturnAttributes`, `kSecMatchLimitAll`) | ✅ | Exposed through `Keychain::list_accounts`. |
| Keychain | `SecItemImport`, `SecItemExport` | 🟡 | Covered indirectly through identity / CMS flows; not exposed as generic item import/export yet. |
| Keychain | `SecAccessControlCreateWithFlags`, `SecAccessControlGetTypeID` | ✅ | Exposed through `AccessControl::create` / `AccessControl::type_id`. |
| Keychain | Non-deprecated macOS `SecItem.h` raw constants | ✅ | Exposed through the exhaustive `raw-ffi` surface. |
| Keychain | Legacy `SecKeychain*` manager APIs | ⏭️ | Deprecated macOS-only keychain-manager surface; intentionally left out of the safe bridge. |
| Identity | `SecIdentityCopyCertificate` | ✅ | Exposed through `Identity::certificate`. |
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
| Certificate | Deprecated add-to-keychain / infer-label helpers | ⏭️ | Deprecated legacy APIs, superseded by `SecItem*` and modern certificate accessors. |
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
| Trust | `SecTrustSetPolicies` | ✅ | Exposed through `Trust::set_policies`. |
| Trust | `SecTrustSetAnchorCertificates` | ✅ | Exposed through `Trust::set_anchor_certificates`. |
| Trust | `SecTrustSetAnchorCertificatesOnly` | ✅ | Exposed through `Trust::set_anchor_certificates_only`. |
| Trust | `SecTrustSetNetworkFetchAllowed` | ✅ | Exposed through `Trust::set_network_fetch_allowed`. |
| Trust | `SecTrustEvaluateWithError` | ✅ | Exposed through `Trust::evaluate`. |
| Trust | `SecTrustCopyResult` | ✅ | Exposed through `Trust::result`. |
| Trust | `SecTrustCopyCertificateChain` | ✅ | Exposed through `Trust::certificate_chain`. |
| Trust | Deprecated `SecTrustEvaluate`, `SecTrustGetResult`, `SecTrustGetCertificateAtIndex` | ⏭️ | Deprecated pre-modern-evaluation APIs. |
| Authorization | `AuthorizationCreate` | ✅ | Exposed through `Authorization::new` / `with_options`. |
| Authorization | `AuthorizationFree` | ✅ | Freed via `Drop` on the Swift-side authorization box. |
| Authorization | `AuthorizationMakeExternalForm` | ✅ | Exposed through `Authorization::external_form`. |
| Authorization | `AuthorizationCreateFromExternalForm` | ✅ | Exposed through `Authorization::from_external_form`. |
| Authorization | `AuthorizationCopyInfo` | 🟡 | Header audited; not yet surfaced because sideband item-set decoding is not needed for the current headless workflows. |
| Authorization | `AuthorizationCopyRights`, async rights APIs | ⏭️ | UI / rights-prompt heavy; skipped for the headless crate surface. |
| Code | `SecCodeCopySelf` | ✅ | Exposed through `Code::current`. |
| Code | `SecCodeCopyStaticCode` | ✅ | Exposed through `Code::static_code`. |
| Code | `SecCodeCheckValidity` | ✅ | Exposed through `StaticCode::check_validity`. |
| Code | `SecCodeCopyPath` | ✅ | Exposed through `StaticCode::path`. |
| Code | `SecCodeCopyDesignatedRequirement` | ✅ | Exposed through `StaticCode::designated_requirement`. |
| Code | `SecCodeCopySigningInformation` | ✅ | Exposed through `StaticCode::signing_information` / `Code::signing_information`. |
| Code | `SecRequirementCopyString` | ✅ | Used internally to serialize requirement values. |
| Code | `SecRequirementCreateWithString` | 🟡 | Header audited; parsing custom requirements is not yet exposed. |
| Code | `SecTaskCreateFromSelf` | ✅ | Exposed through `Task::current`. |
| Code | `SecTaskCopySigningIdentifier` | ✅ | Exposed through `Task::signing_identifier`. |
| Code | `SecTaskCopyValueForEntitlement` | ✅ | Exposed through `Task::entitlement`. |
| Code | Guest-code / hosting-chain / static-code creation-by-path APIs | ⏭️ | Useful but outside the current self-inspection-focused crate surface. |
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
| CMS | `CMSEncoderCreate` | ✅ | Used by `Cms::encode_supporting_certificates`. |
| CMS | `CMSEncoderAddSupportingCerts` | ✅ | Exposed through certificate-bag encoding. |
| CMS | `CMSEncoderCopyEncodedContent` | ✅ | Exposed through certificate-bag encoding. |
| CMS | `CMSDecoderCreate` | ✅ | Used by `Cms::decode_all_certificates`. |
| CMS | `CMSDecoderUpdateMessage` | ✅ | Used by certificate-bag decoding. |
| CMS | `CMSDecoderFinalizeMessage` | ✅ | Used by certificate-bag decoding. |
| CMS | `CMSDecoderCopyAllCerts` | ✅ | Exposed through `Cms::decode_all_certificates`. |
| CMS | Signers, recipients, detached content, signer status | 🟡 | Header audited; signing / enveloped-data workflows are not yet wrapped. |
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
