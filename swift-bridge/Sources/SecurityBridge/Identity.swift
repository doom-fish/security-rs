import Foundation
import Security

private struct IdentityRecord {
    let identity: SecIdentity
    let label: String?
    let chainCount: Int
}

@_cdecl("security_identity_import_pkcs12_first")
public func securityIdentityImportPkcs12First(
    _ dataPointer: UnsafeRawPointer?,
    _ dataLength: Int,
    _ passwordPointer: UnsafePointer<CChar>?,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard let pkcs12Data = dataFromPointer(dataPointer, length: dataLength),
          let password = stringFromCString(passwordPointer)
    else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "PKCS#12 data and password are required")
        return nil
    }

    var options: [CFString: Any] = [
        kSecImportExportPassphrase: password,
    ]
    if #available(macOS 15.0, *) {
        options[kSecImportToMemoryOnly] = true
    }

    var items: CFArray?
    let status = SecPKCS12Import(pkcs12Data as CFData, options as CFDictionary, &items)
    guard status == errSecSuccess else {
        setStatus(statusOut, status)
        setError(errorOut, "SecPKCS12Import failed: \(statusMessage(status))")
        return nil
    }

    guard let importedItems = items as? [[String: Any]],
          let firstItem = importedItems.first,
          let identityValue = firstItem[kSecImportItemIdentity as String]
    else {
        setStatus(statusOut, errSecItemNotFound)
        setError(errorOut, "no SecIdentity found in PKCS#12 container")
        return nil
    }

    let identity = identityValue as! SecIdentity
    let label = firstItem[kSecImportItemLabel as String] as? String
    let chainCount = (firstItem[kSecImportItemCertChain as String] as? [Any])?.count ?? 0
    return retain(IdentityRecord(identity: identity, label: label, chainCount: chainCount))
}

@_cdecl("security_identity_copy_label")
public func securityIdentityCopyLabel(_ identityPointer: UnsafeMutableRawPointer?) -> UnsafeMutableRawPointer? {
    unbox(identityPointer, as: IdentityRecord.self).flatMap { stringHandle($0.label) }
}

@_cdecl("security_identity_get_chain_count")
public func securityIdentityGetChainCount(_ identityPointer: UnsafeMutableRawPointer?) -> Int {
    unbox(identityPointer, as: IdentityRecord.self)?.chainCount ?? 0
}

@_cdecl("security_identity_copy_certificate")
public func securityIdentityCopyCertificate(
    _ identityPointer: UnsafeMutableRawPointer?,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard let identity = unbox(identityPointer, as: IdentityRecord.self)?.identity else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "identity handle is required")
        return nil
    }

    var certificate: SecCertificate?
    let status = SecIdentityCopyCertificate(identity, &certificate)
    guard status == errSecSuccess, let certificate else {
        setStatus(statusOut, status)
        setError(errorOut, "SecIdentityCopyCertificate failed: \(statusMessage(status))")
        return nil
    }

    return retain(certificate)
}

@_cdecl("security_identity_copy_private_key_attributes")
public func securityIdentityCopyPrivateKeyAttributes(
    _ identityPointer: UnsafeMutableRawPointer?,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard let identity = unbox(identityPointer, as: IdentityRecord.self)?.identity else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "identity handle is required")
        return nil
    }

    var privateKey: SecKey?
    let status = SecIdentityCopyPrivateKey(identity, &privateKey)
    guard status == errSecSuccess, let privateKey else {
        setStatus(statusOut, status)
        setError(errorOut, "SecIdentityCopyPrivateKey failed: \(statusMessage(status))")
        return nil
    }

    guard let attributes = SecKeyCopyAttributes(privateKey) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "SecKeyCopyAttributes returned nil")
        return nil
    }

    return jsonHandle(attributes)
}
