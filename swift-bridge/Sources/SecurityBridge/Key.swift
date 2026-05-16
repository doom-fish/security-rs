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
