//! Additional raw `SecKey.h` declarations.

use libc::size_t;

use super::{
    Boolean, CFDataRef, CFDictionaryRef, CFErrorRef, CFIndex, CFStringRef, CFTypeID, SecKeyRef,
};

pub type SecKeyAlgorithm = CFStringRef;
pub type SecKeyKeyExchangeParameter = CFStringRef;
pub type SecKeyOperationType = CFIndex;

pub const kSecKeyOperationTypeSign: SecKeyOperationType = 0;
pub const kSecKeyOperationTypeVerify: SecKeyOperationType = 1;
pub const kSecKeyOperationTypeEncrypt: SecKeyOperationType = 2;
pub const kSecKeyOperationTypeDecrypt: SecKeyOperationType = 3;
pub const kSecKeyOperationTypeKeyExchange: SecKeyOperationType = 4;

extern "C" {
    pub static kSecPrivateKeyAttrs: CFStringRef;
    pub static kSecPublicKeyAttrs: CFStringRef;
    pub static kSecKeyAlgorithmRSASignatureRaw: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmRSASignatureDigestPKCS1v15Raw: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA1: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA224: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA384: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA512: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA1: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA224: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA384: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA512: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmRSASignatureDigestPSSSHA1: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmRSASignatureDigestPSSSHA224: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmRSASignatureDigestPSSSHA256: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmRSASignatureDigestPSSSHA384: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmRSASignatureDigestPSSSHA512: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmRSASignatureMessagePSSSHA1: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmRSASignatureMessagePSSSHA224: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmRSASignatureMessagePSSSHA256: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmRSASignatureMessagePSSSHA384: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmRSASignatureMessagePSSSHA512: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECDSASignatureDigestX962: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECDSASignatureDigestX962SHA1: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECDSASignatureDigestX962SHA224: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECDSASignatureDigestX962SHA256: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECDSASignatureDigestX962SHA384: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECDSASignatureDigestX962SHA512: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECDSASignatureMessageX962SHA1: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECDSASignatureMessageX962SHA224: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECDSASignatureMessageX962SHA256: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECDSASignatureMessageX962SHA384: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECDSASignatureMessageX962SHA512: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECDSASignatureDigestRFC4754: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECDSASignatureDigestRFC4754SHA1: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECDSASignatureDigestRFC4754SHA224: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECDSASignatureDigestRFC4754SHA256: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECDSASignatureDigestRFC4754SHA384: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECDSASignatureDigestRFC4754SHA512: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECDSASignatureMessageRFC4754SHA1: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECDSASignatureMessageRFC4754SHA224: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECDSASignatureMessageRFC4754SHA256: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECDSASignatureMessageRFC4754SHA384: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECDSASignatureMessageRFC4754SHA512: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmRSAEncryptionRaw: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmRSAEncryptionPKCS1: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmRSAEncryptionOAEPSHA1: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmRSAEncryptionOAEPSHA224: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmRSAEncryptionOAEPSHA256: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmRSAEncryptionOAEPSHA384: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmRSAEncryptionOAEPSHA512: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmRSAEncryptionOAEPSHA1AESGCM: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmRSAEncryptionOAEPSHA224AESGCM: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmRSAEncryptionOAEPSHA256AESGCM: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmRSAEncryptionOAEPSHA384AESGCM: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmRSAEncryptionOAEPSHA512AESGCM: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECIESEncryptionStandardX963SHA1AESGCM: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECIESEncryptionStandardX963SHA224AESGCM: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECIESEncryptionStandardX963SHA256AESGCM: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECIESEncryptionStandardX963SHA384AESGCM: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECIESEncryptionStandardX963SHA512AESGCM: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECIESEncryptionCofactorX963SHA1AESGCM: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECIESEncryptionCofactorX963SHA224AESGCM: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECIESEncryptionCofactorX963SHA384AESGCM: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECIESEncryptionCofactorX963SHA512AESGCM: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA224AESGCM: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA256AESGCM: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA384AESGCM: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA512AESGCM: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA224AESGCM: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA384AESGCM: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA512AESGCM: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECDHKeyExchangeStandard: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA1: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA224: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA256: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA384: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA512: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECDHKeyExchangeCofactor: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECDHKeyExchangeCofactorX963SHA1: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECDHKeyExchangeCofactorX963SHA224: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECDHKeyExchangeCofactorX963SHA256: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECDHKeyExchangeCofactorX963SHA384: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECDHKeyExchangeCofactorX963SHA512: SecKeyAlgorithm;
    pub static kSecKeyKeyExchangeParameterRequestedSize: SecKeyKeyExchangeParameter;
    pub static kSecKeyKeyExchangeParameterSharedInfo: SecKeyKeyExchangeParameter;
    pub fn SecKeyGetTypeID() -> CFTypeID;
    pub fn SecKeyCreateRandomKey(parameters: CFDictionaryRef, error: *mut CFErrorRef) -> SecKeyRef;
    pub fn SecKeyCreateWithData(
        key_data: CFDataRef,
        attributes: CFDictionaryRef,
        error: *mut CFErrorRef,
    ) -> SecKeyRef;
    pub fn SecKeyGetBlockSize(key: SecKeyRef) -> size_t;
    pub fn SecKeyCopyExternalRepresentation(key: SecKeyRef, error: *mut CFErrorRef) -> CFDataRef;
    pub fn SecKeyCopyAttributes(key: SecKeyRef) -> CFDictionaryRef;
    pub fn SecKeyCopyPublicKey(key: SecKeyRef) -> SecKeyRef;
    pub fn SecKeyCreateSignature(
        key: SecKeyRef,
        algorithm: SecKeyAlgorithm,
        data_to_sign: CFDataRef,
        error: *mut CFErrorRef,
    ) -> CFDataRef;
    pub fn SecKeyVerifySignature(
        key: SecKeyRef,
        algorithm: SecKeyAlgorithm,
        signed_data: CFDataRef,
        signature: CFDataRef,
        error: *mut CFErrorRef,
    ) -> Boolean;
    pub fn SecKeyCreateEncryptedData(
        key: SecKeyRef,
        algorithm: SecKeyAlgorithm,
        plaintext: CFDataRef,
        error: *mut CFErrorRef,
    ) -> CFDataRef;
    pub fn SecKeyCreateDecryptedData(
        key: SecKeyRef,
        algorithm: SecKeyAlgorithm,
        ciphertext: CFDataRef,
        error: *mut CFErrorRef,
    ) -> CFDataRef;
    pub fn SecKeyCopyKeyExchangeResult(
        private_key: SecKeyRef,
        algorithm: SecKeyAlgorithm,
        public_key: SecKeyRef,
        parameters: CFDictionaryRef,
        error: *mut CFErrorRef,
    ) -> CFDataRef;
    pub fn SecKeyIsAlgorithmSupported(
        key: SecKeyRef,
        operation: SecKeyOperationType,
        algorithm: SecKeyAlgorithm,
    ) -> Boolean;
}
