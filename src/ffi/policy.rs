//! Additional raw `SecPolicy.h` declarations.

use super::{CFDictionaryRef, CFOptionFlags, CFStringRef, CFTypeID, CFTypeRef, SecPolicyRef};

pub const kSecRevocationOCSPMethod: CFOptionFlags = 1 << 0;
pub const kSecRevocationCRLMethod: CFOptionFlags = 1 << 1;
pub const kSecRevocationPreferCRL: CFOptionFlags = 1 << 2;
pub const kSecRevocationRequirePositiveResponse: CFOptionFlags = 1 << 3;
pub const kSecRevocationNetworkAccessDisabled: CFOptionFlags = 1 << 4;
pub const kSecRevocationUseAnyAvailableMethod: CFOptionFlags =
    kSecRevocationOCSPMethod | kSecRevocationCRLMethod;

extern "C" {
    pub static kSecPolicyAppleX509Basic: CFStringRef;
    pub static kSecPolicyAppleSSL: CFStringRef;
    pub static kSecPolicyAppleSMIME: CFStringRef;
    pub static kSecPolicyAppleEAP: CFStringRef;
    pub static kSecPolicyAppleIPsec: CFStringRef;
    pub static kSecPolicyApplePKINITClient: CFStringRef;
    pub static kSecPolicyApplePKINITServer: CFStringRef;
    pub static kSecPolicyAppleCodeSigning: CFStringRef;
    pub static kSecPolicyMacAppStoreReceipt: CFStringRef;
    pub static kSecPolicyAppleIDValidation: CFStringRef;
    pub static kSecPolicyAppleTimeStamping: CFStringRef;
    pub static kSecPolicyAppleRevocation: CFStringRef;
    pub static kSecPolicyApplePassbookSigning: CFStringRef;
    pub static kSecPolicyApplePayIssuerEncryption: CFStringRef;
    pub static kSecPolicyAppleSSLServer: CFStringRef;
    pub static kSecPolicyAppleSSLClient: CFStringRef;
    pub static kSecPolicyAppleEAPServer: CFStringRef;
    pub static kSecPolicyAppleEAPClient: CFStringRef;
    pub static kSecPolicyAppleIPSecServer: CFStringRef;
    pub static kSecPolicyAppleIPSecClient: CFStringRef;
    pub static kSecPolicyOid: CFStringRef;
    pub static kSecPolicyName: CFStringRef;
    pub static kSecPolicyClient: CFStringRef;
    pub static kSecPolicyRevocationFlags: CFStringRef;
    pub static kSecPolicyTeamIdentifier: CFStringRef;
    pub static kSecPolicyKU_DigitalSignature: CFStringRef;
    pub static kSecPolicyKU_NonRepudiation: CFStringRef;
    pub static kSecPolicyKU_KeyEncipherment: CFStringRef;
    pub static kSecPolicyKU_DataEncipherment: CFStringRef;
    pub static kSecPolicyKU_KeyAgreement: CFStringRef;
    pub static kSecPolicyKU_KeyCertSign: CFStringRef;
    pub static kSecPolicyKU_CRLSign: CFStringRef;
    pub static kSecPolicyKU_EncipherOnly: CFStringRef;
    pub static kSecPolicyKU_DecipherOnly: CFStringRef;
    pub fn SecPolicyGetTypeID() -> CFTypeID;
    pub fn SecPolicyCopyProperties(policy_ref: SecPolicyRef) -> CFDictionaryRef;
    pub fn SecPolicyCreateRevocation(revocation_flags: CFOptionFlags) -> SecPolicyRef;
    pub fn SecPolicyCreateWithProperties(
        policy_identifier: CFTypeRef,
        properties: CFDictionaryRef,
    ) -> SecPolicyRef;
}
