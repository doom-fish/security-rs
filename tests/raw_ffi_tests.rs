#![cfg(feature = "raw-ffi")]

#[test]
fn raw_ffi_exposes_targeted_security_symbols() {
    unsafe {
        assert!(security::ffi::SecAccessControlGetTypeID() > 0);
        assert!(security::ffi::SecKeyGetTypeID() > 0);
        assert!(security::ffi::SecPolicyGetTypeID() > 0);

        assert!(!security::ffi::kSecAttrAccessControl.is_null());
        assert!(!security::ffi::kSecUseAuthenticationContext.is_null());
        assert!(!security::ffi::kSecKeyAlgorithmRSAEncryptionOAEPSHA256.is_null());
        assert!(!security::ffi::kSecKeyKeyExchangeParameterSharedInfo.is_null());
        assert!(!security::ffi::kSecPolicyAppleSSL.is_null());
        assert!(!security::ffi::kSecPolicyRevocationFlags.is_null());
    }
}
