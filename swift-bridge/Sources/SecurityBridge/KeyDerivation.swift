import Foundation
import Security

@_cdecl("security_key_derivation_derive_pbkdf2_sha256")
public func securityKeyDerivationDerivePBKDF2SHA256(
    _ passwordPointer: UnsafePointer<CChar>?,
    _ saltPointer: UnsafeRawPointer?,
    _ saltLength: Int,
    _ rounds: Int,
    _ keySizeBits: Int,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard let password = stringFromCString(passwordPointer),
          let salt = dataFromPointer(saltPointer, length: saltLength),
          rounds > 0,
          keySizeBits > 0
    else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "password, salt, rounds, and key size are required")
        return nil
    }

    let parameters: [CFString: Any] = [
        kSecAttrSalt: salt,
        kSecAttrPRF: kSecAttrPRFHmacAlgSHA256,
        kSecAttrRounds: rounds,
        kSecAttrKeySizeInBits: keySizeBits,
        kSecAttrKeyType: kSecAttrKeyTypeAES,
    ]

    var error: Unmanaged<CFError>?
    guard let key = SecKeyDeriveFromPassword(password as CFString, parameters as CFDictionary, &error) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, error)
        return nil
    }

    return retain(key)
}
