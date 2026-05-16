# security-rs coverage audit (vs MacOSX26.2.sdk)

SDK_PUBLIC_SYMBOLS: 321
VERIFIED: 65
GAPS: 93
EXEMPT: 163
COVERAGE_PCT: 41.14%

> **Sample scope.** Security.framework is far larger than this crate’s safe surface. To keep the audit reviewable, this file covers the full callable public surface (321 top-level functions) from 25 app-facing headers, rather than the much larger `kSec*` constant/key space. It also excludes the legacy CSSM / plug-in / admin / keychain-manager headers and does **not** count the optional `raw-ffi` feature as verified coverage.

> Deprecated and unavailable APIs remain listed below as **EXEMPT**, per the audit instructions.

## 🟢 VERIFIED
| Symbol | Kind | Header | Wrapped by |
| --- | --- | --- | --- |
| AuthorizationCreate | function | Authorization.h | Authorization::new, Authorization::with_options |
| AuthorizationCreateFromExternalForm | function | Authorization.h | Authorization::from_external_form |
| AuthorizationFree | function | Authorization.h | Authorization (Drop) |
| AuthorizationMakeExternalForm | function | Authorization.h | Authorization::external_form |
| CMSDecoderCopyAllCerts | function | CMSDecoder.h | Cms::decode_all_certificates |
| CMSDecoderCreate | function | CMSDecoder.h | Cms::decode_all_certificates |
| CMSDecoderFinalizeMessage | function | CMSDecoder.h | Cms::decode_all_certificates |
| CMSDecoderUpdateMessage | function | CMSDecoder.h | Cms::decode_all_certificates |
| CMSEncoderAddSupportingCerts | function | CMSEncoder.h | Cms::encode_supporting_certificates |
| CMSEncoderCopyEncodedContent | function | CMSEncoder.h | Cms::encode_supporting_certificates |
| CMSEncoderCreate | function | CMSEncoder.h | Cms::encode_supporting_certificates |
| SecAccessControlCreateWithFlags | function | SecAccessControl.h | AccessControl::create |
| SecCopyErrorMessageString | function | SecBase.h | SecurityError / StatusError message formatting |
| SecCertificateCopyCommonName | function | SecCertificate.h | Certificate::common_name |
| SecCertificateCopyData | function | SecCertificate.h | Certificate::der_data |
| SecCertificateCopyEmailAddresses | function | SecCertificate.h | Certificate::email_addresses |
| SecCertificateCopyKey | function | SecCertificate.h | Certificate::public_key |
| SecCertificateCopyNormalizedIssuerSequence | function | SecCertificate.h | Certificate::normalized_issuer_sequence |
| SecCertificateCopyNormalizedSubjectSequence | function | SecCertificate.h | Certificate::normalized_subject_sequence |
| SecCertificateCopyNotValidAfterDate | function | SecCertificate.h | Certificate::not_valid_after |
| SecCertificateCopyNotValidBeforeDate | function | SecCertificate.h | Certificate::not_valid_before |
| SecCertificateCopySerialNumberData | function | SecCertificate.h | Certificate::serial_number |
| SecCertificateCopySubjectSummary | function | SecCertificate.h | Certificate::subject_summary |
| SecCertificateCreateWithData | function | SecCertificate.h | Certificate::from_der, Certificate::from_pem |
| SecCodeCheckValidity | function | SecCode.h | StaticCode::check_validity |
| SecCodeCopyDesignatedRequirement | function | SecCode.h | StaticCode::designated_requirement |
| SecCodeCopyPath | function | SecCode.h | StaticCode::path |
| SecCodeCopySelf | function | SecCode.h | Code::current |
| SecCodeCopySigningInformation | function | SecCode.h | Code::signing_information, StaticCode::signing_information |
| SecCodeCopyStaticCode | function | SecCode.h | Code::static_code |
| SecIdentityCopyCertificate | function | SecIdentity.h | Identity::certificate |
| SecIdentityCopyPrivateKey | function | SecIdentity.h | Identity::private_key_attributes |
| SecPKCS12Import | function | SecImportExport.h | Identity::import_pkcs12_first |
| SecItemAdd | function | SecItem.h | Keychain::set, KeychainEntry::set |
| SecItemCopyMatching | function | SecItem.h | Keychain::get, Keychain::list_accounts, KeychainEntry::get |
| SecItemDelete | function | SecItem.h | Keychain::delete, KeychainEntry::delete |
| SecItemExport | function | SecImportExport.h | Certificate::export_item |
| SecItemImport | function | SecImportExport.h | Certificate::import_item, PrivateKey::import_item |
| SecItemUpdate | function | SecItem.h | Keychain::set, KeychainEntry::set |
| SecKeyCopyAttributes | function | SecKey.h | PublicKey::attributes, AgreementPrivateKey::attributes, AgreementPublicKey::attributes, DerivedKey::attributes, Identity::private_key_attributes |
| SecKeyCopyKeyExchangeResult | function | SecKey.h | AgreementPrivateKey::shared_secret |
| SecKeyCopyPublicKey | function | SecKey.h | Certificate::public_key, AgreementPrivateKey::public_key, PrivateKey::public_key |
| SecKeyCreateRandomKey | function | SecKey.h | AgreementPrivateKey::generate_p256 |
| SecKeyCreateSignature | function | SecKey.h | PrivateKey::sign |
| SecKeyCreateWithData | function | SecKey.h | PrivateKey::from_data |
| SecKeyIsAlgorithmSupported | function | SecKey.h | AgreementPrivateKey::is_supported |
| SecKeyVerifySignature | function | SecKey.h | PublicKey::verify_signature |
| SecPolicyCopyProperties | function | SecPolicy.h | Policy::properties |
| SecPolicyCreateBasicX509 | function | SecPolicy.h | Policy::basic_x509 |
| SecPolicyCreateWithProperties | function | SecPolicy.h | Policy::with_properties |
| SecPolicyCreateRevocation | function | SecPolicy.h | Policy::revocation |
| SecPolicyCreateSSL | function | SecPolicy.h | Policy::ssl |
| SecRandomCopyBytes | function | SecRandom.h | SecureRandom::fill, SecureRandom::bytes |
| SecRequirementCopyString | function | SecRequirement.h | StaticCode::designated_requirement, SigningValue::Requirement |
| SecTaskCopySigningIdentifier | function | SecTask.h | Task::signing_identifier |
| SecTaskCopyValueForEntitlement | function | SecTask.h | Task::entitlement |
| SecTaskCreateFromSelf | function | SecTask.h | Task::current |
| SecTrustCopyCertificateChain | function | SecTrust.h | Trust::certificate_chain |
| SecTrustCopyResult | function | SecTrust.h | Trust::result |
| SecTrustCreateWithCertificates | function | SecTrust.h | Trust::new, Trust::from_certificates |
| SecTrustEvaluateWithError | function | SecTrust.h | Trust::evaluate |
| SecTrustSetAnchorCertificates | function | SecTrust.h | Trust::set_anchor_certificates |
| SecTrustSetAnchorCertificatesOnly | function | SecTrust.h | Trust::set_anchor_certificates_only |
| SecTrustSetNetworkFetchAllowed | function | SecTrust.h | Trust::set_network_fetch_allowed |
| SecTrustSetPolicies | function | SecTrust.h | Trust::set_policies |

## 🔴 GAPS
| Symbol | Kind | Header | Notes |
| --- | --- | --- | --- |
| AuthorizationCopyInfo | function | Authorization.h | No wrapper for AuthorizationCopyInfo metadata. |
| AuthorizationCopyRights | function | Authorization.h | No wrapper for authorization-right acquisition / prompting. |
| AuthorizationCopyRightsAsync | function | Authorization.h | No async authorization-right acquisition wrapper. |
| AuthorizationFreeItemSet | function | Authorization.h | Rights / info / privileged-exec APIs are not exposed. |
| CMSDecoderCopyContent | function | CMSDecoder.h | No CMS content extraction wrapper. |
| CMSDecoderCopyDetachedContent | function | CMSDecoder.h | CMS decoder features beyond certificate-bag extraction are not exposed. |
| CMSDecoderCopyEncapsulatedContentType | function | CMSDecoder.h | CMS decoder features beyond certificate-bag extraction are not exposed. |
| CMSDecoderCopySignerCert | function | CMSDecoder.h | No signer-certificate wrapper. |
| CMSDecoderCopySignerEmailAddress | function | CMSDecoder.h | CMS decoder features beyond certificate-bag extraction are not exposed. |
| CMSDecoderCopySignerSigningTime | function | CMSDecoder.h | CMS decoder features beyond certificate-bag extraction are not exposed. |
| CMSDecoderCopySignerStatus | function | CMSDecoder.h | No signer-status wrapper. |
| CMSDecoderCopySignerTimestamp | function | CMSDecoder.h | CMS decoder features beyond certificate-bag extraction are not exposed. |
| CMSDecoderCopySignerTimestampCertificates | function | CMSDecoder.h | CMS decoder features beyond certificate-bag extraction are not exposed. |
| CMSDecoderCopySignerTimestampWithPolicy | function | CMSDecoder.h | CMS decoder features beyond certificate-bag extraction are not exposed. |
| CMSDecoderGetNumSigners | function | CMSDecoder.h | CMS decoder features beyond certificate-bag extraction are not exposed. |
| CMSDecoderGetTypeID | function | CMSDecoder.h | No public CFTypeID helper in the safe API. |
| CMSDecoderIsContentEncrypted | function | CMSDecoder.h | CMS decoder features beyond certificate-bag extraction are not exposed. |
| CMSDecoderSetDetachedContent | function | CMSDecoder.h | CMS decoder features beyond certificate-bag extraction are not exposed. |
| CMSEncodeContent | function | CMSEncoder.h | CMS signing / recipient / content-configuration APIs are not exposed. |
| CMSEncoderAddRecipients | function | CMSEncoder.h | No CMS enveloped-data wrapper. |
| CMSEncoderAddSignedAttributes | function | CMSEncoder.h | CMS signing / recipient / content-configuration APIs are not exposed. |
| CMSEncoderAddSigners | function | CMSEncoder.h | No CMS signing wrapper. |
| CMSEncoderCopyEncapsulatedContentType | function | CMSEncoder.h | CMS signing / recipient / content-configuration APIs are not exposed. |
| CMSEncoderCopyRecipients | function | CMSEncoder.h | CMS signing / recipient / content-configuration APIs are not exposed. |
| CMSEncoderCopySignerTimestamp | function | CMSEncoder.h | CMS signing / recipient / content-configuration APIs are not exposed. |
| CMSEncoderCopySignerTimestampWithPolicy | function | CMSEncoder.h | CMS signing / recipient / content-configuration APIs are not exposed. |
| CMSEncoderCopySigners | function | CMSEncoder.h | CMS signing / recipient / content-configuration APIs are not exposed. |
| CMSEncoderCopySupportingCerts | function | CMSEncoder.h | CMS signing / recipient / content-configuration APIs are not exposed. |
| CMSEncoderGetCertificateChainMode | function | CMSEncoder.h | CMS signing / recipient / content-configuration APIs are not exposed. |
| CMSEncoderGetHasDetachedContent | function | CMSEncoder.h | CMS signing / recipient / content-configuration APIs are not exposed. |
| CMSEncoderGetTypeID | function | CMSEncoder.h | No public CFTypeID helper in the safe API. |
| CMSEncoderSetCertificateChainMode | function | CMSEncoder.h | CMS signing / recipient / content-configuration APIs are not exposed. |
| CMSEncoderSetEncapsulatedContentTypeOID | function | CMSEncoder.h | CMS signing / recipient / content-configuration APIs are not exposed. |
| CMSEncoderSetHasDetachedContent | function | CMSEncoder.h | CMS signing / recipient / content-configuration APIs are not exposed. |
| CMSEncoderSetSignerAlgorithm | function | CMSEncoder.h | CMS signing / recipient / content-configuration APIs are not exposed. |
| CMSEncoderUpdateContent | function | CMSEncoder.h | CMS signing / recipient / content-configuration APIs are not exposed. |
| SecAccessControlGetTypeID | function | SecAccessControl.h | No public CFTypeID helper in the safe API. |
| SecCertificateAddToKeychain | function | SecCertificate.h | Additional certificate introspection / preference APIs are not exposed. |
| SecCertificateCopyLongDescription | function | SecCertificate.h | Additional certificate introspection / preference APIs are not exposed. |
| SecCertificateCopyPreferred | function | SecCertificate.h | Additional certificate introspection / preference APIs are not exposed. |
| SecCertificateCopyShortDescription | function | SecCertificate.h | Additional certificate introspection / preference APIs are not exposed. |
| SecCertificateCopyValues | function | SecCertificate.h | No structured certificate-values wrapper. |
| SecCertificateGetTypeID | function | SecCertificate.h | No public CFTypeID helper in the safe API. |
| SecCertificateSetPreferred | function | SecCertificate.h | Additional certificate introspection / preference APIs are not exposed. |
| SecCodeCheckValidityWithErrors | function | SecCode.h | No error-reporting validity-check wrapper. |
| SecCodeCopyGuestWithAttributes | function | SecCode.h | No guest-code lookup / host inspection wrapper. |
| SecCodeCopyHost | function | SecCode.h | Guest / host / XPC / resource-validation code-signing APIs are not exposed. |
| SecCodeCreateWithXPCMessage | function | SecCode.h | Guest / host / XPC / resource-validation code-signing APIs are not exposed. |
| SecCodeGetTypeID | function | SecCode.h | No public CFTypeID helper in the safe API. |
| SecCodeMapMemory | function | SecCode.h | Guest / host / XPC / resource-validation code-signing APIs are not exposed. |
| SecCodeValidateFileResource | function | SecCode.h | Guest / host / XPC / resource-validation code-signing APIs are not exposed. |
| SecIdentityCopyPreferred | function | SecIdentity.h | Identity preference / system-identity management is not exposed. |
| SecIdentityCopySystemIdentity | function | SecIdentity.h | Identity preference / system-identity management is not exposed. |
| SecIdentityCreate | function | SecIdentity.h | Identity preference / system-identity management is not exposed. |
| SecIdentityCreateWithCertificate | function | SecIdentity.h | Identity preference / system-identity management is not exposed. |
| SecIdentityGetTypeID | function | SecIdentity.h | No public CFTypeID helper in the safe API. |
| SecIdentitySetPreferred | function | SecIdentity.h | Identity preference / system-identity management is not exposed. |
| SecIdentitySetSystemIdentity | function | SecIdentity.h | Identity preference / system-identity management is not exposed. |
| SecKeyCopyExternalRepresentation | function | SecKey.h | Only key agreement, random-key generation, public-key extraction, and attribute inspection are exposed. |
| SecKeyCreateDecryptedData | function | SecKey.h | No public-key decryption wrapper. |
| SecKeyCreateEncryptedData | function | SecKey.h | No public-key encryption wrapper. |
| SecKeyGetBlockSize | function | SecKey.h | Only key agreement, random-key generation, public-key extraction, and attribute inspection are exposed. |
| SecKeyGetTypeID | function | SecKey.h | No public CFTypeID helper in the safe API. |
| SecPolicyGetTypeID | function | SecPolicy.h | No public CFTypeID helper in the safe API. |
| SecRequirementCopyData | function | SecRequirement.h | Requirement parsing / serialization APIs are not exposed. |
| SecRequirementCreateWithData | function | SecRequirement.h | Requirement parsing / serialization APIs are not exposed. |
| SecRequirementCreateWithString | function | SecRequirement.h | No custom requirement-parser wrapper. |
| SecRequirementCreateWithStringAndErrors | function | SecRequirement.h | No error-reporting requirement-parser wrapper. |
| SecRequirementGetTypeID | function | SecRequirement.h | No public CFTypeID helper in the safe API. |
| SecStaticCodeCheckValidity | function | SecStaticCode.h | Static-code creation / validation variants are not exposed. |
| SecStaticCodeCheckValidityWithErrors | function | SecStaticCode.h | Static-code creation / validation variants are not exposed. |
| SecStaticCodeCreateWithPath | function | SecStaticCode.h | No path-based static-code constructor. |
| SecStaticCodeCreateWithPathAndAttributes | function | SecStaticCode.h | No path+attributes static-code constructor. |
| SecStaticCodeGetTypeID | function | SecStaticCode.h | No public CFTypeID helper in the safe API. |
| SecTaskCopyValuesForEntitlements | function | SecTask.h | No bulk-entitlement wrapper. |
| SecTaskCreateWithAuditToken | function | SecTask.h | No external task inspection wrapper. |
| SecTaskGetTypeID | function | SecTask.h | No public CFTypeID helper in the safe API. |
| SecTrustCopyAnchorCertificates | function | SecTrust.h | Advanced trust customization / async / exception APIs are not exposed. |
| SecTrustCopyCustomAnchorCertificates | function | SecTrust.h | Advanced trust customization / async / exception APIs are not exposed. |
| SecTrustCopyExceptions | function | SecTrust.h | No trust-exceptions extraction wrapper. |
| SecTrustCopyKey | function | SecTrust.h | No trust-derived key accessor. |
| SecTrustCopyPolicies | function | SecTrust.h | Advanced trust customization / async / exception APIs are not exposed. |
| SecTrustEvaluateAsyncWithError | function | SecTrust.h | No async trust-evaluation wrapper. |
| SecTrustGetCertificateCount | function | SecTrust.h | Advanced trust customization / async / exception APIs are not exposed. |
| SecTrustGetNetworkFetchAllowed | function | SecTrust.h | Advanced trust customization / async / exception APIs are not exposed. |
| SecTrustGetTrustResult | function | SecTrust.h | Advanced trust customization / async / exception APIs are not exposed. |
| SecTrustGetTypeID | function | SecTrust.h | No public CFTypeID helper in the safe API. |
| SecTrustGetVerifyTime | function | SecTrust.h | Advanced trust customization / async / exception APIs are not exposed. |
| SecTrustSetExceptions | function | SecTrust.h | No trust-exceptions management wrapper. |
| SecTrustSetOCSPResponse | function | SecTrust.h | Advanced trust customization / async / exception APIs are not exposed. |
| SecTrustSetOptions | function | SecTrust.h | Advanced trust customization / async / exception APIs are not exposed. |
| SecTrustSetSignedCertificateTimestamps | function | SecTrust.h | Advanced trust customization / async / exception APIs are not exposed. |
| SecTrustSetVerifyDate | function | SecTrust.h | Advanced trust customization / async / exception APIs are not exposed. |

## ⏭️ EXEMPT
| Symbol | Kind | Header | Reason | SDK attribute |
| --- | --- | --- | --- | --- |
| AuthorizationCopyPrivilegedReference | function | Authorization.h | Deprecated API; excluded from coverage. | __OSX_AVAILABLE_BUT_DEPRECATED(__MAC_10_1,__MAC_10_7,__IPHONE_NA,__IPHONE_NA); |
| AuthorizationExecuteWithPrivileges | function | Authorization.h | Deprecated API; excluded from coverage. | __OSX_AVAILABLE_BUT_DEPRECATED(__MAC_10_1,__MAC_10_7,__IPHONE_NA,__IPHONE_NA); |
| CMSDecoderSetSearchKeychain | function | CMSDecoder.h | Deprecated API; excluded from coverage. | API_DEPRECATED_WITH_REPLACEMENT("SecKeychainSetSearchList",macos(10.5, 10.13)) API_UNAVAILABLE(ios, watchos, tvos, macCatalyst); |
| CMSEncode | function | CMSEncoder.h | Deprecated API; excluded from coverage. | API_DEPRECATED_WITH_REPLACEMENT("CMSEncodeContent", macos(10.5, 10.7)) API_UNAVAILABLE(ios, watchos, tvos, macCatalyst); |
| CMSEncoderSetEncapsulatedContentType | function | CMSEncoder.h | Deprecated API; excluded from coverage. | API_DEPRECATED_WITH_REPLACEMENT("CMSEncoderSetEncapsulatedContentTypeOID", macos(10.5, 10.7)) API_UNAVAILABLE(ios, watchos, tvos, macCatalyst); |
| SecCertificateCopyNormalizedIssuerContent | function | SecCertificate.h | Deprecated API; excluded from coverage. | __OSX_AVAILABLE_BUT_DEPRECATED_MSG(__MAC_10_7, __MAC_10_12_4, __IPHONE_NA, __IPHONE_NA, "SecCertificateCopyNormalizedIssuerContent is deprecated. Use SecCertificateCopyNormalizedIssuerSequence instead."); |
| SecCertificateCopyNormalizedSubjectContent | function | SecCertificate.h | Deprecated API; excluded from coverage. | __OSX_AVAILABLE_BUT_DEPRECATED_MSG(__MAC_10_7, __MAC_10_12_4, __IPHONE_NA, __IPHONE_NA, "SecCertificateCopyNormalizedSubjectContent is deprecated. Use SecCertificateCopyNormalizedSubjectSequence instead."); |
| SecCertificateCopyPreference | function | SecCertificate.h | Deprecated API; excluded from coverage. | deprecated |
| SecCertificateCopyPublicKey | function | SecCertificate.h | Deprecated and unavailable on macOS; excluded from coverage. | API_DEPRECATED_WITH_REPLACEMENT("SecCertificateCopyKey", ios(10.3, 12.0)) API_UNAVAILABLE(macos, macCatalyst); |
| SecCertificateCopySerialNumber | function | SecCertificate.h | Deprecated and unavailable on macOS; excluded from coverage. | API_DEPRECATED_WITH_REPLACEMENT("SecCertificateCopySerialNumberData", ios(10.3, 11.0)) API_UNAVAILABLE(macos, macCatalyst); |
| SecCertificateCreateFromData | function | SecCertificate.h | Deprecated API; excluded from coverage. | deprecated |
| SecCertificateGetAlgorithmID | function | SecCertificate.h | Deprecated API; excluded from coverage. | deprecated |
| SecCertificateGetCLHandle | function | SecCertificate.h | Deprecated API; excluded from coverage. | deprecated |
| SecCertificateGetData | function | SecCertificate.h | Deprecated API; excluded from coverage. | deprecated |
| SecCertificateGetIssuer | function | SecCertificate.h | Deprecated API; excluded from coverage. | deprecated |
| SecCertificateGetSubject | function | SecCertificate.h | Deprecated API; excluded from coverage. | deprecated |
| SecCertificateGetType | function | SecCertificate.h | Deprecated API; excluded from coverage. | deprecated |
| SecCertificateSetPreference | function | SecCertificate.h | Deprecated API; excluded from coverage. | deprecated |
| SecHostCreateGuest | function | SecCodeHost.h | Deprecated API; excluded from coverage. | deprecated |
| SecHostRemoveGuest | function | SecCodeHost.h | Deprecated API; excluded from coverage. | deprecated |
| SecHostSelectGuest | function | SecCodeHost.h | Deprecated API; excluded from coverage. | deprecated |
| SecHostSelectedGuest | function | SecCodeHost.h | Deprecated API; excluded from coverage. | deprecated |
| SecHostSetGuestStatus | function | SecCodeHost.h | Deprecated API; excluded from coverage. | deprecated |
| SecHostSetHostingPort | function | SecCodeHost.h | Deprecated API; excluded from coverage. | deprecated |
| SecTranformCustomGetAttribute | function | SecCustomTransform.h | Deprecated transform API family; excluded from coverage. | deprecated |
| SecTransformCreate | function | SecCustomTransform.h | Deprecated transform API family; excluded from coverage. | API_DEPRECATED("SecTransform is no longer supported", macos(10.7, 13.0)) API_UNAVAILABLE(ios, tvos, watchos, macCatalyst); |
| SecTransformCustomGetAttribute | function | SecCustomTransform.h | Deprecated transform API family; excluded from coverage. | API_DEPRECATED("SecTransform is no longer supported", macos(10.7, 13.0)) API_UNAVAILABLE(ios, tvos, watchos, macCatalyst); |
| SecTransformCustomSetAttribute | function | SecCustomTransform.h | Deprecated transform API family; excluded from coverage. | API_DEPRECATED("SecTransform is no longer supported", macos(10.7, 13.0)) API_UNAVAILABLE(ios, tvos, watchos, macCatalyst); |
| SecTransformNoData | function | SecCustomTransform.h | Deprecated transform API family; excluded from coverage. | API_DEPRECATED("SecTransform is no longer supported", macos(10.7, 13.0)) API_UNAVAILABLE(ios, tvos, watchos, macCatalyst); |
| SecTransformPushbackAttribute | function | SecCustomTransform.h | Deprecated transform API family; excluded from coverage. | API_DEPRECATED("SecTransform is no longer supported", macos(10.7, 13.0)) API_UNAVAILABLE(ios, tvos, watchos, macCatalyst); |
| SecTransformRegister | function | SecCustomTransform.h | Deprecated transform API family; excluded from coverage. | API_DEPRECATED("SecTransform is no longer supported", macos(10.7, 13.0)) API_UNAVAILABLE(ios, tvos, watchos, macCatalyst); |
| SecTransformSetAttributeAction | function | SecCustomTransform.h | Deprecated transform API family; excluded from coverage. | API_DEPRECATED("SecTransform is no longer supported", macos(10.7, 13.0)) API_UNAVAILABLE(ios, tvos, watchos, macCatalyst); |
| SecTransformSetDataAction | function | SecCustomTransform.h | Deprecated transform API family; excluded from coverage. | API_DEPRECATED("SecTransform is no longer supported", macos(10.7, 13.0)) API_UNAVAILABLE(ios, tvos, watchos, macCatalyst); |
| SecTransformSetTransformAction | function | SecCustomTransform.h | Deprecated transform API family; excluded from coverage. | API_DEPRECATED("SecTransform is no longer supported", macos(10.7, 13.0)) API_UNAVAILABLE(ios, tvos, watchos, macCatalyst); |
| SecDecodeTransformCreate | function | SecDecodeTransform.h | Deprecated transform API; security-rs uses it for Transform::decode_base64, but deprecated surface is excluded from coverage. | API_DEPRECATED("SecTransform is no longer supported", macos(10.7, 13.0)) API_UNAVAILABLE(ios, tvos, watchos, macCatalyst); |
| SecDigestTransformCreate | function | SecDigestTransform.h | Deprecated transform API family; excluded from coverage. | API_DEPRECATED("SecTransform is no longer supported", macos(10.7, 13.0)) API_UNAVAILABLE(ios, tvos, watchos, macCatalyst); |
| SecDigestTransformGetTypeID | function | SecDigestTransform.h | Deprecated transform API family; excluded from coverage. | API_DEPRECATED("SecTransform is no longer supported", macos(10.7, 13.0)) API_UNAVAILABLE(ios, tvos, watchos, macCatalyst); |
| SecEncodeTransformCreate | function | SecEncodeTransform.h | Deprecated transform API; security-rs uses it for Transform::encode_base64, but deprecated surface is excluded from coverage. | API_DEPRECATED("SecTransform is no longer supported", macos(10.7, 13.0)) API_UNAVAILABLE(ios, tvos, watchos, macCatalyst); |
| SecDecryptTransformCreate | function | SecEncryptTransform.h | Deprecated transform API family; excluded from coverage. | API_DEPRECATED("SecTransform is no longer supported", macos(10.7, 13.0)) API_UNAVAILABLE(ios, tvos, watchos, macCatalyst); |
| SecDecryptTransformGetTypeID | function | SecEncryptTransform.h | Deprecated transform API family; excluded from coverage. | API_DEPRECATED("SecTransform is no longer supported", macos(10.7, 13.0)) API_UNAVAILABLE(ios, tvos, watchos, macCatalyst); |
| SecEncryptTransformCreate | function | SecEncryptTransform.h | Deprecated transform API family; excluded from coverage. | API_DEPRECATED("SecTransform is no longer supported", macos(10.7, 13.0)) API_UNAVAILABLE(ios, tvos, watchos, macCatalyst); |
| SecEncryptTransformGetTypeID | function | SecEncryptTransform.h | Deprecated transform API family; excluded from coverage. | API_DEPRECATED("SecTransform is no longer supported", macos(10.7, 13.0)) API_UNAVAILABLE(ios, tvos, watchos, macCatalyst); |
| SecIdentityCopyPreference | function | SecIdentity.h | Deprecated API; excluded from coverage. | deprecated |
| SecIdentitySetPreference | function | SecIdentity.h | Deprecated API; excluded from coverage. | deprecated |
| SecKeychainItemExport | function | SecImportExport.h | Deprecated API; excluded from coverage. | API_DEPRECATED_WITH_REPLACEMENT("SecItemExport", macos(10.0, 10.7)) API_UNAVAILABLE(ios, watchos, tvos, macCatalyst); |
| SecKeychainItemImport | function | SecImportExport.h | Deprecated API; excluded from coverage. | API_DEPRECATED_WITH_REPLACEMENT("SecItemImport", macos(10.0, 10.7)) API_UNAVAILABLE(ios, watchos, tvos, macCatalyst); |
| SecKeyCreateFromData | function | SecKey.h | Deprecated API; excluded from coverage. | API_DEPRECATED("No longer supported", macos(10.7, 12.0)); |
| SecKeyCreatePair | function | SecKey.h | Deprecated API; excluded from coverage. | CSSM_DEPRECATED; |
| SecKeyDecrypt | function | SecKey.h | Deprecated API; excluded from coverage. | API_DEPRECATED("Use SecKeyCreateDecryptedData", ios(2.0, 15.0), tvos(4.0, 15.0), watchos(1.0, 8.0)); |
| SecKeyDeriveFromPassword | function | SecKey.h | Deprecated KDF API; security-rs still uses it for KeyDerivation::derive_pbkdf2_sha256, but deprecated surface is excluded from coverage. | API_DEPRECATED("No longer supported", macos(10.7, 12.0)); |
| SecKeyEncrypt | function | SecKey.h | Deprecated API; excluded from coverage. | API_DEPRECATED("Use SecKeyCreateEncryptedData", ios(2.0, 15.0), tvos(4.0, 15.0), watchos(1.0, 8.0)); |
| SecKeyGenerate | function | SecKey.h | Deprecated API; excluded from coverage. | CSSM_DEPRECATED; |
| SecKeyGeneratePair | function | SecKey.h | Deprecated API; excluded from coverage. | API_DEPRECATED("Use SecKeyCreateRandomKey", macos(10.7, 12.0), ios(2.0, 15.0), tvos(4.0, 15.0), watchos(1.0, 8.0)); |
| SecKeyGeneratePairAsync | function | SecKey.h | Deprecated API; excluded from coverage. | API_DEPRECATED("No longer supported", macos(10.7, 12.0)); |
| SecKeyGenerateSymmetric | function | SecKey.h | Deprecated API; excluded from coverage. | API_DEPRECATED("No longer supported", macos(10.7, 12.0)); |
| SecKeyGetCSPHandle | function | SecKey.h | Deprecated API; excluded from coverage. | deprecated |
| SecKeyGetCSSMKey | function | SecKey.h | Deprecated API; excluded from coverage. | deprecated |
| SecKeyGetCredentials | function | SecKey.h | Deprecated API; excluded from coverage. | deprecated |
| SecKeyRawSign | function | SecKey.h | Deprecated API; excluded from coverage. | API_DEPRECATED("Use SecKeyCreateSignature", ios(2.0, 15.0), tvos(4.0, 15.0), watchos(1.0, 8.0)); |
| SecKeyRawVerify | function | SecKey.h | Deprecated API; excluded from coverage. | API_DEPRECATED("Use SecKeyVerifySignature", ios(2.0, 15.0), tvos(4.0, 15.0), watchos(1.0, 8.0)); |
| SecKeyUnwrapSymmetric | function | SecKey.h | Deprecated API; excluded from coverage. | API_DEPRECATED("No longer supported", macos(10.7, 12.0)); |
| SecKeyWrapSymmetric | function | SecKey.h | Deprecated API; excluded from coverage. | API_DEPRECATED("No longer supported", macos(10.7, 12.0)); |
| SecPolicyCreateWithOID | function | SecPolicy.h | Deprecated API; excluded from coverage. | __OSX_AVAILABLE_BUT_DEPRECATED(__MAC_10_7, __MAC_10_9, __IPHONE_NA, __IPHONE_NA); |
| SecPolicyGetOID | function | SecPolicy.h | Deprecated API; excluded from coverage. | __OSX_AVAILABLE_BUT_DEPRECATED(__MAC_10_2, __MAC_10_7, __IPHONE_NA, __IPHONE_NA); |
| SecPolicyGetTPHandle | function | SecPolicy.h | Deprecated API; excluded from coverage. | __OSX_AVAILABLE_BUT_DEPRECATED(__MAC_10_2, __MAC_10_7, __IPHONE_NA, __IPHONE_NA); |
| SecPolicyGetValue | function | SecPolicy.h | Deprecated API; excluded from coverage. | __OSX_AVAILABLE_BUT_DEPRECATED(__MAC_10_2, __MAC_10_7, __IPHONE_NA, __IPHONE_NA); |
| SecPolicySetProperties | function | SecPolicy.h | Deprecated API; excluded from coverage. | __OSX_AVAILABLE_BUT_DEPRECATED(__MAC_10_7, __MAC_10_9, __IPHONE_NA, __IPHONE_NA); |
| SecPolicySetValue | function | SecPolicy.h | Deprecated API; excluded from coverage. | __OSX_AVAILABLE_BUT_DEPRECATED(__MAC_10_2, __MAC_10_7, __IPHONE_NA, __IPHONE_NA); |
| SecTaskGetCodeSignStatus | function | SecTask.h | Unavailable on macOS; excluded from coverage. | API_AVAILABLE(ios(10.0), watchos(3.0), tvos(10.0), macCatalyst(11.0)) API_UNAVAILABLE(macos); |
| SecGroupTransformGetTypeID | function | SecTransform.h | Deprecated transform API family; excluded from coverage. | API_DEPRECATED("SecTransform is no longer supported", macos(10.7, 12.0)) API_UNAVAILABLE(ios, tvos, watchos, macCatalyst); |
| SecTransformConnectTransforms | function | SecTransform.h | Deprecated transform API family; excluded from coverage. | API_DEPRECATED("SecTransform is no longer supported", macos(10.7, 12.0)) API_UNAVAILABLE(ios, tvos, watchos, macCatalyst); |
| SecTransformCopyExternalRepresentation | function | SecTransform.h | Deprecated transform API family; excluded from coverage. | API_DEPRECATED("SecTransform is no longer supported", macos(10.7, 12.0)) API_UNAVAILABLE(ios, tvos, watchos, macCatalyst); |
| SecTransformCreateFromExternalRepresentation | function | SecTransform.h | Deprecated transform API family; excluded from coverage. | API_DEPRECATED("SecTransform is no longer supported", macos(10.7, 12.0)) API_UNAVAILABLE(ios, tvos, watchos, macCatalyst); |
| SecTransformCreateGroupTransform | function | SecTransform.h | Deprecated transform API family; excluded from coverage. | API_DEPRECATED("SecTransform is no longer supported", macos(10.7, 12.0)) API_UNAVAILABLE(ios, tvos, watchos, macCatalyst); |
| SecTransformExecute | function | SecTransform.h | Deprecated transform API; security-rs uses it for Transform base64 helpers, but deprecated surface is excluded from coverage. | API_DEPRECATED("SecTransform is no longer supported", macos(10.7, 12.0)) API_UNAVAILABLE(ios, tvos, watchos, macCatalyst); |
| SecTransformExecuteAsync | function | SecTransform.h | Deprecated transform API family; excluded from coverage. | API_DEPRECATED("SecTransform is no longer supported", macos(10.7, 12.0)) API_UNAVAILABLE(ios, tvos, watchos, macCatalyst); |
| SecTransformFindByName | function | SecTransform.h | Deprecated transform API family; excluded from coverage. | API_DEPRECATED("SecTransform is no longer supported", macos(10.7, 12.0)) API_UNAVAILABLE(ios, tvos, watchos, macCatalyst); |
| SecTransformGetAttribute | function | SecTransform.h | Deprecated transform API family; excluded from coverage. | API_DEPRECATED("SecTransform is no longer supported", macos(10.7, 12.0)) API_UNAVAILABLE(ios, tvos, watchos, macCatalyst); |
| SecTransformGetTypeID | function | SecTransform.h | Deprecated transform API family; excluded from coverage. | API_DEPRECATED("SecTransform is no longer supported", macos(10.7, 12.0)) API_UNAVAILABLE(ios, tvos, watchos, macCatalyst); |
| SecTransformSetAttribute | function | SecTransform.h | Deprecated transform API; security-rs uses it for Transform base64 helpers, but deprecated surface is excluded from coverage. | API_DEPRECATED("SecTransform is no longer supported", macos(10.7, 12.0)) API_UNAVAILABLE(ios, tvos, watchos, macCatalyst); |
| SecTrustCopyProperties | function | SecTrust.h | Deprecated API; excluded from coverage. | API_DEPRECATED_WITH_REPLACEMENT("SecTrustEvaluateWithError", macos(10.7, 12.0), ios(2.0, 15.0), watchos(1.0, 8.0), tvos(9.0, 15.0)) API_UNAVAILABLE(macCatalyst); |
| SecTrustCopyPublicKey | function | SecTrust.h | Deprecated API; excluded from coverage. | API_DEPRECATED_WITH_REPLACEMENT("SecTrustCopyKey", macos(10.7, 11.0), ios(2.0, 14.0), watchos(1.0, 7.0), tvos(9.0, 14.0)); |
| SecTrustEvaluate | function | SecTrust.h | Deprecated API; excluded from coverage. | API_DEPRECATED_WITH_REPLACEMENT("SecTrustEvaluateWithError", macos(10.3, 10.15), ios(2.0, 13.0), watchos(1.0, 6.0), tvos(2.0, 13.0)); |
| SecTrustEvaluateAsync | function | SecTrust.h | Deprecated API; excluded from coverage. | API_DEPRECATED_WITH_REPLACEMENT("SecTrustEvaluateAsyncWithError", macos(10.7, 10.15), ios(7.0, 13.0), watchos(1.0, 6.0), tvos(7.0, 13.0)); |
| SecTrustGetCertificateAtIndex | function | SecTrust.h | Deprecated API; excluded from coverage. | API_DEPRECATED_WITH_REPLACEMENT("SecTrustCopyCertificateChain", macos(10.7, 12.0), ios(2.0, 15.0), watchos(1.0, 8.0), tvos(9.0, 15.0)); |
| SecTrustGetCssmResult | function | SecTrust.h | Deprecated API; excluded from coverage. | __OSX_AVAILABLE_BUT_DEPRECATED(__MAC_10_2, __MAC_10_7, __IPHONE_NA, __IPHONE_NA); |
| SecTrustGetCssmResultCode | function | SecTrust.h | Deprecated API; excluded from coverage. | __OSX_AVAILABLE_BUT_DEPRECATED(__MAC_10_2, __MAC_10_7, __IPHONE_NA, __IPHONE_NA); |
| SecTrustGetResult | function | SecTrust.h | Deprecated API; excluded from coverage. | __OSX_AVAILABLE_BUT_DEPRECATED(__MAC_10_2, __MAC_10_7, __IPHONE_NA, __IPHONE_NA); |
| SecTrustGetTPHandle | function | SecTrust.h | Deprecated API; excluded from coverage. | __OSX_AVAILABLE_BUT_DEPRECATED(__MAC_10_2, __MAC_10_7, __IPHONE_NA, __IPHONE_NA); |
| SecTrustSetKeychains | function | SecTrust.h | Deprecated API; excluded from coverage. | __OSX_AVAILABLE_BUT_DEPRECATED(__MAC_10_3, __MAC_10_13, __IPHONE_NA, __IPHONE_NA); |
| SecTrustSetParameters | function | SecTrust.h | Deprecated API; excluded from coverage. | __OSX_AVAILABLE_BUT_DEPRECATED(__MAC_10_2, __MAC_10_7, __IPHONE_NA, __IPHONE_NA); |
| SSLAddDistinguishedName | function | SecureTransport.h | Deprecated SecureTransport API; excluded from coverage. | __SECURETRANSPORT_API_DEPRECATED(macos(10.4, 10.15), ios(5.0, 13.0)); |
| SSLClose | function | SecureTransport.h | Deprecated SecureTransport API; excluded from coverage. | __SECURETRANSPORT_API_DEPRECATED(macos(10.2, 10.15), ios(5.0, 13.0)); |
| SSLContextGetTypeID | function | SecureTransport.h | Deprecated SecureTransport API; excluded from coverage. | __SECURETRANSPORT_API_DEPRECATED(macos(10.8, 10.15), ios(5.0, 13.0)); |
| SSLCopyALPNProtocols | function | SecureTransport.h | Deprecated SecureTransport API; excluded from coverage. | __SECURETRANSPORT_API_DEPRECATED(macos(10.13, 10.15), ios(11.0, 13.0)); |
| SSLCopyCertificateAuthorities | function | SecureTransport.h | Deprecated SecureTransport API; excluded from coverage. | __SECURETRANSPORT_API_DEPRECATED(macos(10.5, 10.15)); |
| SSLCopyDistinguishedNames | function | SecureTransport.h | Deprecated SecureTransport API; excluded from coverage. | __SECURETRANSPORT_API_DEPRECATED(macos(10.5, 10.15), ios(5.0, 13.0)); |
| SSLCopyPeerCertificates | function | SecureTransport.h | Deprecated SecureTransport API; excluded from coverage. | __SECURETRANSPORT_API_DEPRECATED(macos(10.5, 10.9)); |
| SSLCopyPeerTrust | function | SecureTransport.h | Deprecated SecureTransport API; excluded from coverage. | __SECURETRANSPORT_API_DEPRECATED(macos(10.6, 10.15), ios(5.0, 13.0)); |
| SSLCopyRequestedPeerName | function | SecureTransport.h | Deprecated SecureTransport API; excluded from coverage. | __SECURETRANSPORT_API_DEPRECATED(macos(10.11, 10.15), ios(9.0, 13.0)); |
| SSLCopyRequestedPeerNameLength | function | SecureTransport.h | Deprecated SecureTransport API; excluded from coverage. | __SECURETRANSPORT_API_DEPRECATED(macos(10.11, 10.15), ios(9.0, 13.0)); |
| SSLCopyTrustedRoots | function | SecureTransport.h | Deprecated SecureTransport API; excluded from coverage. | __SECURETRANSPORT_API_DEPRECATED(macos(10.5, 10.9)); |
| SSLCreateContext | function | SecureTransport.h | Deprecated SecureTransport API; security-rs exposes a minimal SecureTransportContext wrapper, but deprecated surface is excluded from coverage. | __SECURETRANSPORT_API_DEPRECATED(macos(10.8, 10.15), ios(5.0, 13.0)); |
| SSLDisposeContext | function | SecureTransport.h | Deprecated SecureTransport API; excluded from coverage. | __SECURETRANSPORT_API_DEPRECATED(macos(10.2, 10.9)); |
| SSLGetAllowsAnyRoot | function | SecureTransport.h | Deprecated SecureTransport API; excluded from coverage. | __SECURETRANSPORT_API_DEPRECATED(macos(10.2, 10.9)); |
| SSLGetAllowsExpiredCerts | function | SecureTransport.h | Deprecated SecureTransport API; excluded from coverage. | __SECURETRANSPORT_API_DEPRECATED(macos(10.2, 10.9)); |
| SSLGetAllowsExpiredRoots | function | SecureTransport.h | Deprecated SecureTransport API; excluded from coverage. | __SECURETRANSPORT_API_DEPRECATED(macos(10.2, 10.9)); |
| SSLGetBufferedReadSize | function | SecureTransport.h | Deprecated SecureTransport API; excluded from coverage. | __SECURETRANSPORT_API_DEPRECATED(macos(10.2, 10.15), ios(5.0, 13.0)); |
| SSLGetClientCertificateState | function | SecureTransport.h | Deprecated SecureTransport API; excluded from coverage. | __SECURETRANSPORT_API_DEPRECATED(macos(10.3, 10.15), ios(5.0, 13.0)); |
| SSLGetConnection | function | SecureTransport.h | Deprecated SecureTransport API; excluded from coverage. | __SECURETRANSPORT_API_DEPRECATED(macos(10.2, 10.15), ios(5.0, 13.0)); |
| SSLGetDatagramWriteSize | function | SecureTransport.h | Deprecated SecureTransport API; excluded from coverage. | __SECURETRANSPORT_API_DEPRECATED(macos(10.8, 10.15), ios(5.0, 13.0)); |
| SSLGetDiffieHellmanParams | function | SecureTransport.h | Deprecated SecureTransport API; excluded from coverage. | __SECURETRANSPORT_API_DEPRECATED(macos(10.2, 10.15)); |
| SSLGetEnableCertVerify | function | SecureTransport.h | Deprecated SecureTransport API; excluded from coverage. | __SECURETRANSPORT_API_DEPRECATED(macos(10.2, 10.9)); |
| SSLGetEnabledCiphers | function | SecureTransport.h | Deprecated SecureTransport API; excluded from coverage. | __SECURETRANSPORT_API_DEPRECATED(macos(10.2, 10.15), ios(5.0, 13.0)); |
| SSLGetMaxDatagramRecordSize | function | SecureTransport.h | Deprecated SecureTransport API; excluded from coverage. | __SECURETRANSPORT_API_DEPRECATED(macos(10.8, 10.15), ios(5.0, 13.0)); |
| SSLGetNegotiatedCipher | function | SecureTransport.h | Deprecated SecureTransport API; excluded from coverage. | __SECURETRANSPORT_API_DEPRECATED(macos(10.2, 10.15), ios(5.0, 13.0)); |
| SSLGetNegotiatedProtocolVersion | function | SecureTransport.h | Deprecated SecureTransport API; excluded from coverage. | __SECURETRANSPORT_API_DEPRECATED(macos(10.2, 10.15), ios(5.0, 13.0)); |
| SSLGetNumberEnabledCiphers | function | SecureTransport.h | Deprecated SecureTransport API; excluded from coverage. | __SECURETRANSPORT_API_DEPRECATED(macos(10.2, 10.15), ios(5.0, 13.0)); |
| SSLGetNumberSupportedCiphers | function | SecureTransport.h | Deprecated SecureTransport API; excluded from coverage. | __SECURETRANSPORT_API_DEPRECATED(macos(10.2, 10.15), ios(5.0, 13.0)); |
| SSLGetPeerDomainName | function | SecureTransport.h | Deprecated SecureTransport API; excluded from coverage. | __SECURETRANSPORT_API_DEPRECATED(macos(10.2, 10.15), ios(5.0, 13.0)); |
| SSLGetPeerDomainNameLength | function | SecureTransport.h | Deprecated SecureTransport API; excluded from coverage. | __SECURETRANSPORT_API_DEPRECATED(macos(10.2, 10.15), ios(5.0, 13.0)); |
| SSLGetPeerID | function | SecureTransport.h | Deprecated SecureTransport API; excluded from coverage. | __SECURETRANSPORT_API_DEPRECATED(macos(10.2, 10.15), ios(5.0, 13.0)); |
| SSLGetProtocolVersion | function | SecureTransport.h | Deprecated SecureTransport API; excluded from coverage. | __SECURETRANSPORT_API_DEPRECATED(macos(10.2, 10.8)); |
| SSLGetProtocolVersionEnabled | function | SecureTransport.h | Deprecated SecureTransport API; excluded from coverage. | __SECURETRANSPORT_API_DEPRECATED(macos(10.2, 10.9)); |
| SSLGetProtocolVersionMax | function | SecureTransport.h | Deprecated SecureTransport API; excluded from coverage. | __SECURETRANSPORT_API_DEPRECATED(macos(10.8, 10.15), ios(5.0, 13.0)); |
| SSLGetProtocolVersionMin | function | SecureTransport.h | Deprecated SecureTransport API; excluded from coverage. | __SECURETRANSPORT_API_DEPRECATED(macos(10.8, 10.15), ios(5.0, 13.0)); |
| SSLGetRsaBlinding | function | SecureTransport.h | Deprecated SecureTransport API; excluded from coverage. | __SECURETRANSPORT_API_DEPRECATED(macos(10.2, 10.9)); |
| SSLGetSessionOption | function | SecureTransport.h | Deprecated SecureTransport API; excluded from coverage. | __SECURETRANSPORT_API_DEPRECATED(macos(10.6, 10.15), ios(5.0, 13.0)); |
| SSLGetSessionState | function | SecureTransport.h | Deprecated SecureTransport API; security-rs exposes SecureTransportContext::state, but deprecated surface is excluded from coverage. | __SECURETRANSPORT_API_DEPRECATED(macos(10.2, 10.15), ios(5.0, 13.0)); |
| SSLGetSupportedCiphers | function | SecureTransport.h | Deprecated SecureTransport API; excluded from coverage. | __SECURETRANSPORT_API_DEPRECATED(macos(10.2, 10.15), ios(5.0, 13.0)); |
| SSLHandshake | function | SecureTransport.h | Deprecated SecureTransport API; excluded from coverage. | __SECURETRANSPORT_API_DEPRECATED(macos(10.2, 10.15), ios(5.0, 13.0)); |
| SSLNewContext | function | SecureTransport.h | Deprecated SecureTransport API; excluded from coverage. | __SECURETRANSPORT_API_DEPRECATED(macos(10.2, 10.9)); |
| SSLReHandshake | function | SecureTransport.h | Deprecated SecureTransport API; excluded from coverage. | __SECURETRANSPORT_API_DEPRECATED(macos(10.12, 10.15), ios(10.0, 13.0)); |
| SSLRead | function | SecureTransport.h | Deprecated SecureTransport API; excluded from coverage. | __SECURETRANSPORT_API_DEPRECATED(macos(10.2, 10.15), ios(5.0, 13.0)); |
| SSLSetALPNProtocols | function | SecureTransport.h | Deprecated SecureTransport API; excluded from coverage. | __SECURETRANSPORT_API_DEPRECATED(macos(10.13, 10.15), ios(11.0, 13.0)); |
| SSLSetAllowsAnyRoot | function | SecureTransport.h | Deprecated SecureTransport API; excluded from coverage. | __SECURETRANSPORT_API_DEPRECATED(macos(10.2, 10.9)); |
| SSLSetAllowsExpiredCerts | function | SecureTransport.h | Deprecated SecureTransport API; excluded from coverage. | __SECURETRANSPORT_API_DEPRECATED(macos(10.2, 10.9)); |
| SSLSetAllowsExpiredRoots | function | SecureTransport.h | Deprecated SecureTransport API; excluded from coverage. | __SECURETRANSPORT_API_DEPRECATED(macos(10.2, 10.9)); |
| SSLSetCertificate | function | SecureTransport.h | Deprecated SecureTransport API; excluded from coverage. | __SECURETRANSPORT_API_DEPRECATED(macos(10.2, 10.15), ios(5.0, 13.0)); |
| SSLSetCertificateAuthorities | function | SecureTransport.h | Deprecated SecureTransport API; excluded from coverage. | __SECURETRANSPORT_API_DEPRECATED(macos(10.5, 10.15)); |
| SSLSetClientSideAuthenticate | function | SecureTransport.h | Deprecated SecureTransport API; excluded from coverage. | __SECURETRANSPORT_API_DEPRECATED(macos(10.2, 10.15), ios(5.0, 13.0)); |
| SSLSetConnection | function | SecureTransport.h | Deprecated SecureTransport API; excluded from coverage. | __SECURETRANSPORT_API_DEPRECATED(macos(10.2, 10.15), ios(5.0, 13.0)); |
| SSLSetDatagramHelloCookie | function | SecureTransport.h | Deprecated SecureTransport API; excluded from coverage. | __SECURETRANSPORT_API_DEPRECATED(macos(10.8, 10.15), ios(5.0, 13.0)); |
| SSLSetDiffieHellmanParams | function | SecureTransport.h | Deprecated SecureTransport API; excluded from coverage. | __SECURETRANSPORT_API_DEPRECATED(macos(10.2, 10.15)); |
| SSLSetEnableCertVerify | function | SecureTransport.h | Deprecated SecureTransport API; excluded from coverage. | __SECURETRANSPORT_API_DEPRECATED(macos(10.2, 10.9)); |
| SSLSetEnabledCiphers | function | SecureTransport.h | Deprecated SecureTransport API; excluded from coverage. | __SECURETRANSPORT_API_DEPRECATED(macos(10.2, 10.15), ios(5.0, 13.0)); |
| SSLSetEncryptionCertificate | function | SecureTransport.h | Deprecated SecureTransport API; excluded from coverage. | __SECURETRANSPORT_API_DEPRECATED(macos(10.2, 10.11), ios(5.0, 9.0)); |
| SSLSetError | function | SecureTransport.h | Deprecated SecureTransport API; excluded from coverage. | __SECURETRANSPORT_API_DEPRECATED(macos(10.13, 10.15), ios(11.0, 13.0)); |
| SSLSetIOFuncs | function | SecureTransport.h | Deprecated SecureTransport API; excluded from coverage. | __SECURETRANSPORT_API_DEPRECATED(macos(10.2, 10.15), ios(5.0, 13.0)); |
| SSLSetMaxDatagramRecordSize | function | SecureTransport.h | Deprecated SecureTransport API; excluded from coverage. | __SECURETRANSPORT_API_DEPRECATED(macos(10.8, 10.15), ios(5.0, 13.0)); |
| SSLSetOCSPResponse | function | SecureTransport.h | Deprecated SecureTransport API; excluded from coverage. | __SECURETRANSPORT_API_DEPRECATED(macos(10.13, 10.15), ios(11.0, 13.0)); |
| SSLSetPeerDomainName | function | SecureTransport.h | Deprecated SecureTransport API; excluded from coverage. | __SECURETRANSPORT_API_DEPRECATED(macos(10.2, 10.15), ios(5.0, 13.0)); |
| SSLSetPeerID | function | SecureTransport.h | Deprecated SecureTransport API; excluded from coverage. | __SECURETRANSPORT_API_DEPRECATED(macos(10.2, 10.15), ios(5.0, 13.0)); |
| SSLSetProtocolVersion | function | SecureTransport.h | Deprecated SecureTransport API; excluded from coverage. | __SECURETRANSPORT_API_DEPRECATED(macos(10.2, 10.8)); |
| SSLSetProtocolVersionEnabled | function | SecureTransport.h | Deprecated SecureTransport API; excluded from coverage. | __SECURETRANSPORT_API_DEPRECATED(macos(10.2, 10.9)); |
| SSLSetProtocolVersionMax | function | SecureTransport.h | Deprecated SecureTransport API; security-rs exposes SecureTransportContext::set_protocol_max, but deprecated surface is excluded from coverage. | __SECURETRANSPORT_API_DEPRECATED(macos(10.8, 10.15), ios(5.0, 13.0)); |
| SSLSetProtocolVersionMin | function | SecureTransport.h | Deprecated SecureTransport API; security-rs exposes SecureTransportContext::set_protocol_min, but deprecated surface is excluded from coverage. | __SECURETRANSPORT_API_DEPRECATED(macos(10.8, 10.15), ios(5.0, 13.0)); |
| SSLSetRsaBlinding | function | SecureTransport.h | Deprecated SecureTransport API; excluded from coverage. | __SECURETRANSPORT_API_DEPRECATED(macos(10.2, 10.9)); |
| SSLSetSessionConfig | function | SecureTransport.h | Deprecated SecureTransport API; excluded from coverage. | __SECURETRANSPORT_API_DEPRECATED(macos(10.12, 10.15), ios(10.0, 13.0)); |
| SSLSetSessionOption | function | SecureTransport.h | Deprecated SecureTransport API; excluded from coverage. | __SECURETRANSPORT_API_DEPRECATED(macos(10.6, 10.15), ios(5.0, 13.0)); |
| SSLSetSessionTicketsEnabled | function | SecureTransport.h | Deprecated SecureTransport API; excluded from coverage. | __SECURETRANSPORT_API_DEPRECATED(macos(10.13, 10.15), ios(11.0, 13.0)); |
| SSLSetTrustedRoots | function | SecureTransport.h | Deprecated SecureTransport API; excluded from coverage. | __SECURETRANSPORT_API_DEPRECATED(macos(10.2, 10.9)); |
| SSLWrite | function | SecureTransport.h | Deprecated SecureTransport API; excluded from coverage. | __SECURETRANSPORT_API_DEPRECATED(macos(10.2, 10.15), ios(5.0, 13.0)); |
