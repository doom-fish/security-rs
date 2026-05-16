import Foundation
import Security

@_cdecl("security_key_agreement_generate_p256_private_key")
public func securityKeyAgreementGenerateP256PrivateKey(
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    let parameters: [CFString: Any] = [
        kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits: 256,
    ]

    var error: Unmanaged<CFError>?
    guard let privateKey = SecKeyCreateRandomKey(parameters as CFDictionary, &error) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, error)
        return nil
    }

    return retain(privateKey)
}

@_cdecl("security_key_copy_public_key")
public func securityKeyCopyPublicKey(
    _ keyPointer: UnsafeMutableRawPointer?,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard let key = unbox(keyPointer, as: SecKey.self) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "key handle is required")
        return nil
    }

    guard let publicKey = SecKeyCopyPublicKey(key) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "SecKeyCopyPublicKey returned nil")
        return nil
    }

    return retain(publicKey)
}

@_cdecl("security_key_agreement_is_supported")
public func securityKeyAgreementIsSupported(_ keyPointer: UnsafeMutableRawPointer?) -> Bool {
    guard let key = unbox(keyPointer, as: SecKey.self) else {
        return false
    }

    return SecKeyIsAlgorithmSupported(key, .keyExchange, .ecdhKeyExchangeStandardX963SHA256)
}

@_cdecl("security_key_agreement_compute_shared_secret")
public func securityKeyAgreementComputeSharedSecret(
    _ privateKeyPointer: UnsafeMutableRawPointer?,
    _ publicKeyPointer: UnsafeMutableRawPointer?,
    _ requestedSize: Int,
    _ sharedInfoPointer: UnsafeRawPointer?,
    _ sharedInfoLength: Int,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard let privateKey = unbox(privateKeyPointer, as: SecKey.self),
          let publicKey = unbox(publicKeyPointer, as: SecKey.self),
          requestedSize > 0
    else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "private key, public key, and requested size are required")
        return nil
    }

    var parameters: [CFString: Any] = [
        SecKeyKeyExchangeParameter.requestedSize.rawValue: NSNumber(value: requestedSize),
    ]

    if let sharedInfo = dataFromPointer(sharedInfoPointer, length: sharedInfoLength), !sharedInfo.isEmpty {
        parameters[SecKeyKeyExchangeParameter.sharedInfo.rawValue] = sharedInfo
    }

    var error: Unmanaged<CFError>?
    guard let sharedSecret = SecKeyCopyKeyExchangeResult(
        privateKey,
        .ecdhKeyExchangeStandardX963SHA256,
        publicKey,
        parameters as CFDictionary,
        &error
    ) as Data?
    else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, error)
        return nil
    }

    return dataHandle(sharedSecret)
}
