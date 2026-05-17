# security-rs coverage audit (vs MacOSX26.2.sdk)

SDK_PUBLIC_SYMBOLS: 321
VERIFIED: 157
GAPS: 0
EXEMPT: 164
COVERAGE_PCT: 100.00%

> **Sample scope.** Security.framework is far larger than this crate’s safe surface. To keep the audit reviewable, this file covers the full callable public surface (321 top-level functions) from 25 app-facing headers, rather than the much larger `kSec*` constant/key space. It also excludes the legacy CSSM / plug-in / admin / keychain-manager headers and does **not** count the optional `raw-ffi` feature as verified coverage.

> Deprecated and unavailable APIs remain listed below as **EXEMPT**, per the audit instructions.

> The `raw-ffi` feature now exhaustively covers the non-deprecated macOS-available `SecAccessControl.h`, `SecItem.h`, `SecKey.h`, and `SecPolicy.h` surfaces. The table below still counts only safe-wrapper coverage for the broader framework audit.

## 🟢 VERIFIED
| Symbol | Kind | Header | Wrapped by |
| --- | --- | --- | --- |
| AuthorizationCopyInfo | function | Authorization.h | Authorization::copy_info |
| AuthorizationCopyRights | function | Authorization.h | Authorization::copy_rights |
| AuthorizationCopyRightsAsync | function | Authorization.h | Authorization::copy_rights_async |
| AuthorizationCreate | function | Authorization.h | Authorization::new, Authorization::with_options |
| AuthorizationCreateFromExternalForm | function | Authorization.h | Authorization::from_external_form |
| AuthorizationFree | function | Authorization.h | Authorization (Drop) |
| AuthorizationFreeItemSet | function | Authorization.h | Authorization::copy_info, Authorization::copy_rights, Authorization::copy_rights_async (bridge cleanup) |
| AuthorizationMakeExternalForm | function | Authorization.h | Authorization::external_form |
| CMSDecoderCopyAllCerts | function | CMSDecoder.h | Cms::decode_all_certificates |
| CMSDecoderCopyContent | function | CMSDecoder.h | CmsDecoder::content |
| CMSDecoderCopyDetachedContent | function | CMSDecoder.h | CmsDecoder::detached_content |
| CMSDecoderCopyEncapsulatedContentType | function | CMSDecoder.h | CmsDecoder::encapsulated_content_type |
| CMSDecoderCopySignerCert | function | CMSDecoder.h | CmsDecoder::signer_certificate |
| CMSDecoderCopySignerEmailAddress | function | CMSDecoder.h | CmsDecoder::signer_email_address |
| CMSDecoderCopySignerSigningTime | function | CMSDecoder.h | CmsDecoder::signer_signing_time |
| CMSDecoderCopySignerStatus | function | CMSDecoder.h | CmsDecoder::signer_status |
| CMSDecoderCopySignerTimestamp | function | CMSDecoder.h | CmsDecoder::signer_timestamp |
| CMSDecoderCopySignerTimestampCertificates | function | CMSDecoder.h | CmsDecoder::signer_timestamp_certificates |
| CMSDecoderCopySignerTimestampWithPolicy | function | CMSDecoder.h | CmsDecoder::signer_timestamp_with_policy |
| CMSDecoderCreate | function | CMSDecoder.h | Cms::decode_all_certificates |
| CMSDecoderFinalizeMessage | function | CMSDecoder.h | Cms::decode_all_certificates |
| CMSDecoderGetNumSigners | function | CMSDecoder.h | CmsDecoder::num_signers |
| CMSDecoderGetTypeID | function | CMSDecoder.h | CmsDecoder::type_id |
| CMSDecoderIsContentEncrypted | function | CMSDecoder.h | CmsDecoder::is_content_encrypted |
| CMSDecoderSetDetachedContent | function | CMSDecoder.h | CmsDecoder::set_detached_content |
| CMSDecoderUpdateMessage | function | CMSDecoder.h | Cms::decode_all_certificates |
| CMSEncodeContent | function | CMSEncoder.h | Cms::encode_content |
| CMSEncoderAddRecipients | function | CMSEncoder.h | CmsEncoder::add_recipients, Cms::encode_content |
| CMSEncoderAddSignedAttributes | function | CMSEncoder.h | CmsEncoder::add_signed_attributes, Cms::encode_content |
| CMSEncoderAddSigners | function | CMSEncoder.h | CmsEncoder::add_signers, Cms::encode_content |
| CMSEncoderAddSupportingCerts | function | CMSEncoder.h | Cms::encode_supporting_certificates |
| CMSEncoderCopyEncapsulatedContentType | function | CMSEncoder.h | CmsEncoder::encapsulated_content_type |
| CMSEncoderCopyEncodedContent | function | CMSEncoder.h | Cms::encode_supporting_certificates |
| CMSEncoderCopyRecipients | function | CMSEncoder.h | CmsEncoder::recipients |
| CMSEncoderCopySignerTimestamp | function | CMSEncoder.h | CmsEncoder::signer_timestamp |
| CMSEncoderCopySignerTimestampWithPolicy | function | CMSEncoder.h | CmsEncoder::signer_timestamp_with_policy |
| CMSEncoderCopySigners | function | CMSEncoder.h | CmsEncoder::signers |
| CMSEncoderCopySupportingCerts | function | CMSEncoder.h | CmsEncoder::supporting_certificates |
| CMSEncoderCreate | function | CMSEncoder.h | Cms::encode_supporting_certificates |
| CMSEncoderGetCertificateChainMode | function | CMSEncoder.h | CmsEncoder::certificate_chain_mode |
| CMSEncoderGetHasDetachedContent | function | CMSEncoder.h | CmsEncoder::has_detached_content |
| CMSEncoderGetTypeID | function | CMSEncoder.h | CmsEncoder::type_id |
| CMSEncoderSetCertificateChainMode | function | CMSEncoder.h | CmsEncoder::set_certificate_chain_mode, Cms::encode_content |
| CMSEncoderSetEncapsulatedContentTypeOID | function | CMSEncoder.h | CmsEncoder::set_encapsulated_content_type_oid, Cms::encode_content |
| CMSEncoderSetHasDetachedContent | function | CMSEncoder.h | CmsEncoder::set_has_detached_content, Cms::encode_content |
| CMSEncoderSetSignerAlgorithm | function | CMSEncoder.h | CmsEncoder::set_signer_algorithm |
| CMSEncoderUpdateContent | function | CMSEncoder.h | CmsEncoder::update_content |
| SecAccessControlCreateWithFlags | function | SecAccessControl.h | AccessControl::create |
| SecAccessControlGetTypeID | function | SecAccessControl.h | AccessControl::type_id |
| SecCertificateAddToKeychain | function | SecCertificate.h | Certificate::add_to_keychain |
| SecCertificateCopyCommonName | function | SecCertificate.h | Certificate::common_name |
| SecCertificateCopyData | function | SecCertificate.h | Certificate::der_data |
| SecCertificateCopyEmailAddresses | function | SecCertificate.h | Certificate::email_addresses |
| SecCertificateCopyKey | function | SecCertificate.h | Certificate::public_key |
| SecCertificateCopyLongDescription | function | SecCertificate.h | Certificate::long_description |
| SecCertificateCopyNormalizedIssuerSequence | function | SecCertificate.h | Certificate::normalized_issuer_sequence |
| SecCertificateCopyNormalizedSubjectSequence | function | SecCertificate.h | Certificate::normalized_subject_sequence |
| SecCertificateCopyNotValidAfterDate | function | SecCertificate.h | Certificate::not_valid_after |
| SecCertificateCopyNotValidBeforeDate | function | SecCertificate.h | Certificate::not_valid_before |
| SecCertificateCopyPreferred | function | SecCertificate.h | Certificate::preferred |
| SecCertificateCopySerialNumberData | function | SecCertificate.h | Certificate::serial_number |
| SecCertificateCopyShortDescription | function | SecCertificate.h | Certificate::short_description |
| SecCertificateCopySubjectSummary | function | SecCertificate.h | Certificate::subject_summary |
| SecCertificateCopyValues | function | SecCertificate.h | Certificate::values |
| SecCertificateCreateWithData | function | SecCertificate.h | Certificate::from_der, Certificate::from_pem |
| SecCertificateGetTypeID | function | SecCertificate.h | Certificate::type_id |
| SecCertificateSetPreferred | function | SecCertificate.h | Certificate::set_preferred |
| SecCodeCheckValidity | function | SecCode.h | StaticCode::check_validity |
| SecCodeCheckValidityWithErrors | function | SecCode.h | StaticCode::check_validity_with_errors |
| SecCodeCopyDesignatedRequirement | function | SecCode.h | StaticCode::designated_requirement |
| SecCodeCopyGuestWithAttributes | function | SecCode.h | Code::guest_with_attributes |
| SecCodeCopyHost | function | SecCode.h | Code::host |
| SecCodeCopyPath | function | SecCode.h | StaticCode::path |
| SecCodeCopySelf | function | SecCode.h | Code::current |
| SecCodeCopySigningInformation | function | SecCode.h | Code::signing_information, StaticCode::signing_information |
| SecCodeCopyStaticCode | function | SecCode.h | Code::static_code |
| SecCodeGetTypeID | function | SecCode.h | Code::type_id |
| SecCodeMapMemory | function | SecCode.h | StaticCode::map_memory |
| SecCodeValidateFileResource | function | SecCode.h | StaticCode::validate_file_resource |
| SecCopyErrorMessageString | function | SecBase.h | SecurityError / StatusError message formatting |
| SecIdentityCopyCertificate | function | SecIdentity.h | Identity::certificate |
| SecIdentityCopyPreferred | function | SecIdentity.h | Identity::preferred |
| SecIdentityCopyPrivateKey | function | SecIdentity.h | Identity::private_key_attributes |
| SecIdentityCopySystemIdentity | function | SecIdentity.h | Identity::copy_system_identity |
| SecIdentityCreate | function | SecIdentity.h | Identity::from_certificate_and_private_key |
| SecIdentityCreateWithCertificate | function | SecIdentity.h | Identity::with_certificate |
| SecIdentityGetTypeID | function | SecIdentity.h | Identity::type_id |
| SecIdentitySetPreferred | function | SecIdentity.h | Identity::set_preferred |
| SecIdentitySetSystemIdentity | function | SecIdentity.h | Identity::set_system_identity |
| SecItemAdd | function | SecItem.h | Keychain::set, KeychainEntry::set |
| SecItemCopyMatching | function | SecItem.h | Keychain::get, Keychain::list_accounts, KeychainEntry::get |
| SecItemDelete | function | SecItem.h | Keychain::delete, KeychainEntry::delete |
| SecItemExport | function | SecImportExport.h | Certificate::export_item |
| SecItemImport | function | SecImportExport.h | Certificate::import_item, PrivateKey::import_item |
| SecItemUpdate | function | SecItem.h | Keychain::set, KeychainEntry::set |
| SecKeyCopyAttributes | function | SecKey.h | PublicKey::attributes, AgreementPrivateKey::attributes, AgreementPublicKey::attributes, DerivedKey::attributes, Identity::private_key_attributes |
| SecKeyCopyExternalRepresentation | function | SecKey.h | PublicKey::external_representation, PrivateKey::external_representation |
| SecKeyCopyKeyExchangeResult | function | SecKey.h | AgreementPrivateKey::shared_secret |
| SecKeyCopyPublicKey | function | SecKey.h | Certificate::public_key, AgreementPrivateKey::public_key, PrivateKey::public_key |
| SecKeyCreateDecryptedData | function | SecKey.h | PrivateKey::decrypt |
| SecKeyCreateEncryptedData | function | SecKey.h | PublicKey::encrypt |
| SecKeyCreateRandomKey | function | SecKey.h | AgreementPrivateKey::generate_p256 |
| SecKeyCreateSignature | function | SecKey.h | PrivateKey::sign |
| SecKeyCreateWithData | function | SecKey.h | PrivateKey::from_data |
| SecKeyGetBlockSize | function | SecKey.h | PublicKey::block_size, PrivateKey::block_size |
| SecKeyGetTypeID | function | SecKey.h | PublicKey::type_id, PrivateKey::type_id, AgreementPrivateKey::type_id, AgreementPublicKey::type_id, DerivedKey::type_id |
| SecKeyIsAlgorithmSupported | function | SecKey.h | AgreementPrivateKey::is_supported |
| SecKeyVerifySignature | function | SecKey.h | PublicKey::verify_signature |
| SecPKCS12Import | function | SecImportExport.h | Identity::import_pkcs12_first |
| SecPolicyCopyProperties | function | SecPolicy.h | Policy::properties |
| SecPolicyCreateBasicX509 | function | SecPolicy.h | Policy::basic_x509 |
| SecPolicyCreateRevocation | function | SecPolicy.h | Policy::revocation |
| SecPolicyCreateSSL | function | SecPolicy.h | Policy::ssl |
| SecPolicyCreateWithProperties | function | SecPolicy.h | Policy::with_properties |
| SecPolicyGetTypeID | function | SecPolicy.h | Policy::type_id |
| SecRandomCopyBytes | function | SecRandom.h | SecureRandom::fill, SecureRandom::bytes |
| SecRequirementCopyData | function | SecRequirement.h | Requirement::data |
| SecRequirementCopyString | function | SecRequirement.h | StaticCode::designated_requirement, SigningValue::Requirement |
| SecRequirementCreateWithData | function | SecRequirement.h | Requirement::from_data |
| SecRequirementCreateWithString | function | SecRequirement.h | Requirement::from_string |
| SecRequirementCreateWithStringAndErrors | function | SecRequirement.h | Requirement::from_string_with_errors |
| SecRequirementGetTypeID | function | SecRequirement.h | Requirement::type_id |
| SecStaticCodeCheckValidity | function | SecStaticCode.h | StaticCode::check_static_validity |
| SecStaticCodeCheckValidityWithErrors | function | SecStaticCode.h | StaticCode::check_static_validity_with_errors |
| SecStaticCodeCreateWithPath | function | SecStaticCode.h | StaticCode::from_path |
| SecStaticCodeCreateWithPathAndAttributes | function | SecStaticCode.h | StaticCode::from_path_with_attributes |
| SecStaticCodeGetTypeID | function | SecStaticCode.h | StaticCode::type_id |
| SecTaskCopySigningIdentifier | function | SecTask.h | Task::signing_identifier |
| SecTaskCopyValueForEntitlement | function | SecTask.h | Task::entitlement |
| SecTaskCopyValuesForEntitlements | function | SecTask.h | Task::entitlements |
| SecTaskCreateFromSelf | function | SecTask.h | Task::current |
| SecTaskCreateWithAuditToken | function | SecTask.h | Task::current_with_audit_token |
| SecTaskGetTypeID | function | SecTask.h | Task::type_id |
| SecTrustCopyAnchorCertificates | function | SecTrust.h | Trust::system_anchor_certificates |
| SecTrustCopyCertificateChain | function | SecTrust.h | Trust::certificate_chain |
| SecTrustCopyCustomAnchorCertificates | function | SecTrust.h | Trust::custom_anchor_certificates |
| SecTrustCopyExceptions | function | SecTrust.h | Trust::exceptions |
| SecTrustCopyKey | function | SecTrust.h | Trust::key |
| SecTrustCopyPolicies | function | SecTrust.h | Trust::policies |
| SecTrustCopyResult | function | SecTrust.h | Trust::result |
| SecTrustCreateWithCertificates | function | SecTrust.h | Trust::new, Trust::from_certificates |
| SecTrustEvaluateAsyncWithError | function | SecTrust.h | Trust::evaluate_async |
| SecTrustEvaluateWithError | function | SecTrust.h | Trust::evaluate |
| SecTrustGetCertificateCount | function | SecTrust.h | Trust::certificate_count |
| SecTrustGetNetworkFetchAllowed | function | SecTrust.h | Trust::network_fetch_allowed |
| SecTrustGetTrustResult | function | SecTrust.h | Trust::trust_result_type |
| SecTrustGetTypeID | function | SecTrust.h | Trust::type_id |
| SecTrustGetVerifyTime | function | SecTrust.h | Trust::verify_time |
| SecTrustSetAnchorCertificates | function | SecTrust.h | Trust::set_anchor_certificates |
| SecTrustSetAnchorCertificatesOnly | function | SecTrust.h | Trust::set_anchor_certificates_only |
| SecTrustSetExceptions | function | SecTrust.h | Trust::set_exceptions |
| SecTrustSetNetworkFetchAllowed | function | SecTrust.h | Trust::set_network_fetch_allowed |
| SecTrustSetOCSPResponse | function | SecTrust.h | Trust::set_ocsp_responses |
| SecTrustSetOptions | function | SecTrust.h | Trust::set_options |
| SecTrustSetPolicies | function | SecTrust.h | Trust::set_policies |
| SecTrustSetSignedCertificateTimestamps | function | SecTrust.h | Trust::set_signed_certificate_timestamps |
| SecTrustSetVerifyDate | function | SecTrust.h | Trust::set_verify_date |

## 🔴 GAPS
| Symbol | Kind | Header | Notes |
| --- | --- | --- | --- |
| _None_ | - | - | Exhaustive coverage achieved for the non-exempt macOS Security.framework surface audited here. |

## ⏭️ EXEMPT
| Symbol | Kind | Header | Reason | SDK attribute |
| --- | --- | --- | --- | --- |
| AuthorizationCopyPrivilegedReference | function | Authorization.h | Deprecated API; excluded from coverage. | __OSX_AVAILABLE_BUT_DEPRECATED(__MAC_10_1,__MAC_10_7,__IPHONE_NA,__IPHONE_NA); |
| AuthorizationExecuteWithPrivileges | function | Authorization.h | Deprecated API; excluded from coverage. | __OSX_AVAILABLE_BUT_DEPRECATED(__MAC_10_1,__MAC_10_7,__IPHONE_NA,__IPHONE_NA); |
| CMSDecoderSetSearchKeychain | function | CMSDecoder.h | Deprecated API; excluded from coverage. | API_DEPRECATED_WITH_REPLACEMENT("SecKeychainSetSearchList",macos(10.5, 10.13)) API_UNAVAILABLE(ios, watchos, tvos, macCatalyst); |
| CMSEncode | function | CMSEncoder.h | Deprecated API; excluded from coverage. | API_DEPRECATED_WITH_REPLACEMENT("CMSEncodeContent", macos(10.5, 10.7)) API_UNAVAILABLE(ios, watchos, tvos, macCatalyst); |
| CMSEncoderSetEncapsulatedContentType | function | CMSEncoder.h | Deprecated API; excluded from coverage. | API_DEPRECATED_WITH_REPLACEMENT("CMSEncoderSetEncapsulatedContentTypeOID", macos(10.5, 10.7)) API_UNAVAILABLE(ios, watchos, tvos, macCatalyst); |
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
| SecCodeCreateWithXPCMessage | function | SecCode.h | Requires an inbound xpc_object_t message with an attached sender audit token; the safe crate intentionally avoids exposing raw XPC message objects. | TARGET_OS_OSX; xpc_object_t sender-context API. |
| SecDecodeTransformCreate | function | SecDecodeTransform.h | Deprecated transform API; security-rs uses it for Transform::decode_base64, but deprecated surface is excluded from coverage. | API_DEPRECATED("SecTransform is no longer supported", macos(10.7, 13.0)) API_UNAVAILABLE(ios, tvos, watchos, macCatalyst); |
| SecDecryptTransformCreate | function | SecEncryptTransform.h | Deprecated transform API family; excluded from coverage. | API_DEPRECATED("SecTransform is no longer supported", macos(10.7, 13.0)) API_UNAVAILABLE(ios, tvos, watchos, macCatalyst); |
| SecDecryptTransformGetTypeID | function | SecEncryptTransform.h | Deprecated transform API family; excluded from coverage. | API_DEPRECATED("SecTransform is no longer supported", macos(10.7, 13.0)) API_UNAVAILABLE(ios, tvos, watchos, macCatalyst); |
| SecDigestTransformCreate | function | SecDigestTransform.h | Deprecated transform API family; excluded from coverage. | API_DEPRECATED("SecTransform is no longer supported", macos(10.7, 13.0)) API_UNAVAILABLE(ios, tvos, watchos, macCatalyst); |
| SecDigestTransformGetTypeID | function | SecDigestTransform.h | Deprecated transform API family; excluded from coverage. | API_DEPRECATED("SecTransform is no longer supported", macos(10.7, 13.0)) API_UNAVAILABLE(ios, tvos, watchos, macCatalyst); |
| SecEncodeTransformCreate | function | SecEncodeTransform.h | Deprecated transform API; security-rs uses it for Transform::encode_base64, but deprecated surface is excluded from coverage. | API_DEPRECATED("SecTransform is no longer supported", macos(10.7, 13.0)) API_UNAVAILABLE(ios, tvos, watchos, macCatalyst); |
| SecEncryptTransformCreate | function | SecEncryptTransform.h | Deprecated transform API family; excluded from coverage. | API_DEPRECATED("SecTransform is no longer supported", macos(10.7, 13.0)) API_UNAVAILABLE(ios, tvos, watchos, macCatalyst); |
| SecEncryptTransformGetTypeID | function | SecEncryptTransform.h | Deprecated transform API family; excluded from coverage. | API_DEPRECATED("SecTransform is no longer supported", macos(10.7, 13.0)) API_UNAVAILABLE(ios, tvos, watchos, macCatalyst); |
| SecGroupTransformGetTypeID | function | SecTransform.h | Deprecated transform API family; excluded from coverage. | API_DEPRECATED("SecTransform is no longer supported", macos(10.7, 12.0)) API_UNAVAILABLE(ios, tvos, watchos, macCatalyst); |
| SecHostCreateGuest | function | SecCodeHost.h | Deprecated API; excluded from coverage. | deprecated |
| SecHostRemoveGuest | function | SecCodeHost.h | Deprecated API; excluded from coverage. | deprecated |
| SecHostSelectGuest | function | SecCodeHost.h | Deprecated API; excluded from coverage. | deprecated |
| SecHostSelectedGuest | function | SecCodeHost.h | Deprecated API; excluded from coverage. | deprecated |
| SecHostSetGuestStatus | function | SecCodeHost.h | Deprecated API; excluded from coverage. | deprecated |
| SecHostSetHostingPort | function | SecCodeHost.h | Deprecated API; excluded from coverage. | deprecated |
| SecIdentityCopyPreference | function | SecIdentity.h | Deprecated API; excluded from coverage. | deprecated |
| SecIdentitySetPreference | function | SecIdentity.h | Deprecated API; excluded from coverage. | deprecated |
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
| SecKeychainItemExport | function | SecImportExport.h | Deprecated API; excluded from coverage. | API_DEPRECATED_WITH_REPLACEMENT("SecItemExport", macos(10.0, 10.7)) API_UNAVAILABLE(ios, watchos, tvos, macCatalyst); |
| SecKeychainItemImport | function | SecImportExport.h | Deprecated API; excluded from coverage. | API_DEPRECATED_WITH_REPLACEMENT("SecItemImport", macos(10.0, 10.7)) API_UNAVAILABLE(ios, watchos, tvos, macCatalyst); |
| SecPolicyCreateWithOID | function | SecPolicy.h | Deprecated API; excluded from coverage. | __OSX_AVAILABLE_BUT_DEPRECATED(__MAC_10_7, __MAC_10_9, __IPHONE_NA, __IPHONE_NA); |
| SecPolicyGetOID | function | SecPolicy.h | Deprecated API; excluded from coverage. | __OSX_AVAILABLE_BUT_DEPRECATED(__MAC_10_2, __MAC_10_7, __IPHONE_NA, __IPHONE_NA); |
| SecPolicyGetTPHandle | function | SecPolicy.h | Deprecated API; excluded from coverage. | __OSX_AVAILABLE_BUT_DEPRECATED(__MAC_10_2, __MAC_10_7, __IPHONE_NA, __IPHONE_NA); |
| SecPolicyGetValue | function | SecPolicy.h | Deprecated API; excluded from coverage. | __OSX_AVAILABLE_BUT_DEPRECATED(__MAC_10_2, __MAC_10_7, __IPHONE_NA, __IPHONE_NA); |
| SecPolicySetProperties | function | SecPolicy.h | Deprecated API; excluded from coverage. | __OSX_AVAILABLE_BUT_DEPRECATED(__MAC_10_7, __MAC_10_9, __IPHONE_NA, __IPHONE_NA); |
| SecPolicySetValue | function | SecPolicy.h | Deprecated API; excluded from coverage. | __OSX_AVAILABLE_BUT_DEPRECATED(__MAC_10_2, __MAC_10_7, __IPHONE_NA, __IPHONE_NA); |
| SecTaskGetCodeSignStatus | function | SecTask.h | Unavailable on macOS; excluded from coverage. | API_AVAILABLE(ios(10.0), watchos(3.0), tvos(10.0), macCatalyst(11.0)) API_UNAVAILABLE(macos); |
| SecTranformCustomGetAttribute | function | SecCustomTransform.h | Deprecated transform API family; excluded from coverage. | deprecated |
| SecTransformConnectTransforms | function | SecTransform.h | Deprecated transform API family; excluded from coverage. | API_DEPRECATED("SecTransform is no longer supported", macos(10.7, 12.0)) API_UNAVAILABLE(ios, tvos, watchos, macCatalyst); |
| SecTransformCopyExternalRepresentation | function | SecTransform.h | Deprecated transform API family; excluded from coverage. | API_DEPRECATED("SecTransform is no longer supported", macos(10.7, 12.0)) API_UNAVAILABLE(ios, tvos, watchos, macCatalyst); |
| SecTransformCreate | function | SecCustomTransform.h | Deprecated transform API family; excluded from coverage. | API_DEPRECATED("SecTransform is no longer supported", macos(10.7, 13.0)) API_UNAVAILABLE(ios, tvos, watchos, macCatalyst); |
| SecTransformCreateFromExternalRepresentation | function | SecTransform.h | Deprecated transform API family; excluded from coverage. | API_DEPRECATED("SecTransform is no longer supported", macos(10.7, 12.0)) API_UNAVAILABLE(ios, tvos, watchos, macCatalyst); |
| SecTransformCreateGroupTransform | function | SecTransform.h | Deprecated transform API family; excluded from coverage. | API_DEPRECATED("SecTransform is no longer supported", macos(10.7, 12.0)) API_UNAVAILABLE(ios, tvos, watchos, macCatalyst); |
| SecTransformCustomGetAttribute | function | SecCustomTransform.h | Deprecated transform API family; excluded from coverage. | API_DEPRECATED("SecTransform is no longer supported", macos(10.7, 13.0)) API_UNAVAILABLE(ios, tvos, watchos, macCatalyst); |
| SecTransformCustomSetAttribute | function | SecCustomTransform.h | Deprecated transform API family; excluded from coverage. | API_DEPRECATED("SecTransform is no longer supported", macos(10.7, 13.0)) API_UNAVAILABLE(ios, tvos, watchos, macCatalyst); |
| SecTransformExecute | function | SecTransform.h | Deprecated transform API; security-rs uses it for Transform base64 helpers, but deprecated surface is excluded from coverage. | API_DEPRECATED("SecTransform is no longer supported", macos(10.7, 12.0)) API_UNAVAILABLE(ios, tvos, watchos, macCatalyst); |
| SecTransformExecuteAsync | function | SecTransform.h | Deprecated transform API family; excluded from coverage. | API_DEPRECATED("SecTransform is no longer supported", macos(10.7, 12.0)) API_UNAVAILABLE(ios, tvos, watchos, macCatalyst); |
| SecTransformFindByName | function | SecTransform.h | Deprecated transform API family; excluded from coverage. | API_DEPRECATED("SecTransform is no longer supported", macos(10.7, 12.0)) API_UNAVAILABLE(ios, tvos, watchos, macCatalyst); |
| SecTransformGetAttribute | function | SecTransform.h | Deprecated transform API family; excluded from coverage. | API_DEPRECATED("SecTransform is no longer supported", macos(10.7, 12.0)) API_UNAVAILABLE(ios, tvos, watchos, macCatalyst); |
| SecTransformGetTypeID | function | SecTransform.h | Deprecated transform API family; excluded from coverage. | API_DEPRECATED("SecTransform is no longer supported", macos(10.7, 12.0)) API_UNAVAILABLE(ios, tvos, watchos, macCatalyst); |
| SecTransformNoData | function | SecCustomTransform.h | Deprecated transform API family; excluded from coverage. | API_DEPRECATED("SecTransform is no longer supported", macos(10.7, 13.0)) API_UNAVAILABLE(ios, tvos, watchos, macCatalyst); |
| SecTransformPushbackAttribute | function | SecCustomTransform.h | Deprecated transform API family; excluded from coverage. | API_DEPRECATED("SecTransform is no longer supported", macos(10.7, 13.0)) API_UNAVAILABLE(ios, tvos, watchos, macCatalyst); |
| SecTransformRegister | function | SecCustomTransform.h | Deprecated transform API family; excluded from coverage. | API_DEPRECATED("SecTransform is no longer supported", macos(10.7, 13.0)) API_UNAVAILABLE(ios, tvos, watchos, macCatalyst); |
| SecTransformSetAttribute | function | SecTransform.h | Deprecated transform API; security-rs uses it for Transform base64 helpers, but deprecated surface is excluded from coverage. | API_DEPRECATED("SecTransform is no longer supported", macos(10.7, 12.0)) API_UNAVAILABLE(ios, tvos, watchos, macCatalyst); |
| SecTransformSetAttributeAction | function | SecCustomTransform.h | Deprecated transform API family; excluded from coverage. | API_DEPRECATED("SecTransform is no longer supported", macos(10.7, 13.0)) API_UNAVAILABLE(ios, tvos, watchos, macCatalyst); |
| SecTransformSetDataAction | function | SecCustomTransform.h | Deprecated transform API family; excluded from coverage. | API_DEPRECATED("SecTransform is no longer supported", macos(10.7, 13.0)) API_UNAVAILABLE(ios, tvos, watchos, macCatalyst); |
| SecTransformSetTransformAction | function | SecCustomTransform.h | Deprecated transform API family; excluded from coverage. | API_DEPRECATED("SecTransform is no longer supported", macos(10.7, 13.0)) API_UNAVAILABLE(ios, tvos, watchos, macCatalyst); |
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
