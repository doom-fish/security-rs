import Foundation
import Security

private func keyTypeConstant(_ rawValue: UInt32) -> CFString? {
    switch rawValue {
    case 0:
        return kSecAttrKeyTypeRSA
    case 1:
        return kSecAttrKeyTypeECSECPrimeRandom
    default:
        return nil
    }
}

private func signatureAlgorithm(_ rawValue: UInt32) -> SecKeyAlgorithm? {
    switch rawValue {
    case 0:
        return .rsaSignatureMessagePKCS1v15SHA256
    case 1:
        return .rsaSignatureDigestPKCS1v15SHA256
    case 2:
        return .rsaSignatureMessagePSSSHA256
    case 3:
        return .ecdsaSignatureMessageX962SHA256
    case 4:
        return .ecdsaSignatureDigestX962SHA256
    default:
        return nil
    }
}

private func encryptionAlgorithm(_ rawValue: UInt32) -> SecKeyAlgorithm? {
    switch rawValue {
    case 0:
        return .rsaEncryptionRaw
    case 1:
        return .rsaEncryptionPKCS1
    case 2:
        return .rsaEncryptionOAEPSHA1
    case 3:
        return .rsaEncryptionOAEPSHA224
    case 4:
        return .rsaEncryptionOAEPSHA256
    case 5:
        return .rsaEncryptionOAEPSHA384
    case 6:
        return .rsaEncryptionOAEPSHA512
    case 7:
        return .rsaEncryptionOAEPSHA1AESGCM
    case 8:
        return .rsaEncryptionOAEPSHA224AESGCM
    case 9:
        return .rsaEncryptionOAEPSHA256AESGCM
    case 10:
        return .rsaEncryptionOAEPSHA384AESGCM
    case 11:
        return .rsaEncryptionOAEPSHA512AESGCM
    default:
        return nil
    }
}

@_cdecl("security_key_get_type_id")
public func securityKeyGetTypeID() -> UInt {
    SecKeyGetTypeID()
}

@_cdecl("security_private_key_create_with_data")
public func securityPrivateKeyCreateWithData(
    _ dataPointer: UnsafeRawPointer?,
    _ dataLength: Int,
    _ keyTypeRawValue: UInt32,
    _ keySizeBits: Int,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard let keyData = dataFromPointer(dataPointer, length: dataLength),
          let keyType = keyTypeConstant(keyTypeRawValue),
          keySizeBits > 0
    else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "key data, key type, and key size are required")
        return nil
    }

    let attributes: [CFString: Any] = [
        kSecAttrKeyType: keyType,
        kSecAttrKeyClass: kSecAttrKeyClassPrivate,
        kSecAttrKeySizeInBits: NSNumber(value: keySizeBits),
    ]

    var error: Unmanaged<CFError>?
    guard let key = SecKeyCreateWithData(keyData as CFData, attributes as CFDictionary, &error) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, error)
        return nil
    }

    return retain(key)
}

@_cdecl("security_private_key_import_item")
public func securityPrivateKeyImportItem(
    _ dataPointer: UnsafeRawPointer?,
    _ dataLength: Int,
    _ fileNamePointer: UnsafePointer<CChar>?,
    _ formatRawValue: UInt32,
    _ itemTypeRawValue: UInt32,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard let importedData = dataFromPointer(dataPointer, length: dataLength),
          var inputFormat = SecExternalFormat(rawValue: formatRawValue),
          var itemType = SecExternalItemType(rawValue: itemTypeRawValue)
    else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "import data, format, and item type are required")
        return nil
    }

    let fileName = stringFromCString(fileNamePointer) as CFString?
    var items: CFArray?
    let status = SecItemImport(
        importedData as CFData,
        fileName,
        &inputFormat,
        &itemType,
        SecItemImportExportFlags(),
        nil,
        nil,
        &items
    )
    guard status == errSecSuccess else {
        setStatus(statusOut, status)
        setError(errorOut, "SecItemImport failed: \(statusMessage(status))")
        return nil
    }

    guard let importedItems = items as? [SecKey],
          let privateKey = importedItems.first
    else {
        setStatus(statusOut, errSecItemNotFound)
        setError(errorOut, "SecItemImport returned no SecKey result")
        return nil
    }

    return retain(privateKey)
}

@_cdecl("security_private_key_create_signature")
public func securityPrivateKeyCreateSignature(
    _ keyPointer: UnsafeMutableRawPointer?,
    _ algorithmRawValue: UInt32,
    _ dataPointer: UnsafeRawPointer?,
    _ dataLength: Int,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard let key = unbox(keyPointer, as: SecKey.self),
          let algorithm = signatureAlgorithm(algorithmRawValue),
          let data = dataFromPointer(dataPointer, length: dataLength)
    else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "private key, signature algorithm, and data are required")
        return nil
    }

    guard SecKeyIsAlgorithmSupported(key, .sign, algorithm) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "SecKeyCreateSignature algorithm is not supported by this key")
        return nil
    }

    var error: Unmanaged<CFError>?
    guard let signature = SecKeyCreateSignature(key, algorithm, data as CFData, &error) as Data? else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, error)
        return nil
    }

    return dataHandle(signature)
}

@_cdecl("security_public_key_verify_signature")
public func securityPublicKeyVerifySignature(
    _ keyPointer: UnsafeMutableRawPointer?,
    _ algorithmRawValue: UInt32,
    _ signedDataPointer: UnsafeRawPointer?,
    _ signedDataLength: Int,
    _ signaturePointer: UnsafeRawPointer?,
    _ signatureLength: Int,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> Bool {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard let key = unbox(keyPointer, as: SecKey.self),
          let algorithm = signatureAlgorithm(algorithmRawValue),
          let signedData = dataFromPointer(signedDataPointer, length: signedDataLength),
          let signature = dataFromPointer(signaturePointer, length: signatureLength)
    else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "public key, signature algorithm, signed data, and signature are required")
        return false
    }

    guard SecKeyIsAlgorithmSupported(key, .verify, algorithm) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "SecKeyVerifySignature algorithm is not supported by this key")
        return false
    }

    var error: Unmanaged<CFError>?
    let isValid = SecKeyVerifySignature(key, algorithm, signedData as CFData, signature as CFData, &error)
    if !isValid, let error {
        _ = error.takeRetainedValue()
    }
    return isValid
}

@_cdecl("security_key_get_block_size")
public func securityKeyGetBlockSize(_ keyPointer: UnsafeMutableRawPointer?) -> Int {
    guard let key = unbox(keyPointer, as: SecKey.self) else {
        return 0
    }

    return SecKeyGetBlockSize(key)
}

@_cdecl("security_key_copy_external_representation")
public func securityKeyCopyExternalRepresentation(
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

    var error: Unmanaged<CFError>?
    guard let representation = SecKeyCopyExternalRepresentation(key, &error) as Data? else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, error)
        return nil
    }

    return dataHandle(representation)
}

@_cdecl("security_public_key_create_encrypted_data")
public func securityPublicKeyCreateEncryptedData(
    _ keyPointer: UnsafeMutableRawPointer?,
    _ algorithmRawValue: UInt32,
    _ dataPointer: UnsafeRawPointer?,
    _ dataLength: Int,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard let key = unbox(keyPointer, as: SecKey.self),
          let algorithm = encryptionAlgorithm(algorithmRawValue),
          let plaintext = dataFromPointer(dataPointer, length: dataLength)
    else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "public key, encryption algorithm, and plaintext are required")
        return nil
    }

    guard SecKeyIsAlgorithmSupported(key, .encrypt, algorithm) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "SecKeyCreateEncryptedData algorithm is not supported by this key")
        return nil
    }

    var error: Unmanaged<CFError>?
    guard let ciphertext = SecKeyCreateEncryptedData(key, algorithm, plaintext as CFData, &error) as Data? else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, error)
        return nil
    }

    return dataHandle(ciphertext)
}

@_cdecl("security_private_key_create_decrypted_data")
public func securityPrivateKeyCreateDecryptedData(
    _ keyPointer: UnsafeMutableRawPointer?,
    _ algorithmRawValue: UInt32,
    _ dataPointer: UnsafeRawPointer?,
    _ dataLength: Int,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard let key = unbox(keyPointer, as: SecKey.self),
          let algorithm = encryptionAlgorithm(algorithmRawValue),
          let ciphertext = dataFromPointer(dataPointer, length: dataLength)
    else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "private key, decryption algorithm, and ciphertext are required")
        return nil
    }

    guard SecKeyIsAlgorithmSupported(key, .decrypt, algorithm) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "SecKeyCreateDecryptedData algorithm is not supported by this key")
        return nil
    }

    var error: Unmanaged<CFError>?
    guard let plaintext = SecKeyCreateDecryptedData(key, algorithm, ciphertext as CFData, &error) as Data? else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, error)
        return nil
    }

    return dataHandle(plaintext)
}
