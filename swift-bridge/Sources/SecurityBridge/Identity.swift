import Foundation
import Security

struct IdentityRecord {
    let identity: SecIdentity
    let label: String?
    let chainCount: Int
    let actualDomain: String?
}

func retainIdentityRecord(
    _ identity: SecIdentity,
    label: String? = nil,
    chainCount: Int = 0,
    actualDomain: String? = nil
) -> UnsafeMutableRawPointer {
    retain(IdentityRecord(identity: identity, label: label, chainCount: chainCount, actualDomain: actualDomain))
}

func identityFromPointer(_ pointer: UnsafeMutableRawPointer?) -> SecIdentity? {
    unbox(pointer, as: IdentityRecord.self)?.identity
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
    return retainIdentityRecord(identity, label: label, chainCount: chainCount)
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

    guard let identity = identityFromPointer(identityPointer) else {
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

    guard let identity = identityFromPointer(identityPointer) else {
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

@_cdecl("security_identity_get_type_id")
public func securityIdentityGetTypeID() -> UInt {
    SecIdentityGetTypeID()
}

@_cdecl("security_identity_create")
public func securityIdentityCreate(
    _ certificatePointer: UnsafeMutableRawPointer?,
    _ privateKeyPointer: UnsafeMutableRawPointer?,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard let certificate = unbox(certificatePointer, as: SecCertificate.self),
          let privateKey = unbox(privateKeyPointer, as: SecKey.self)
    else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "certificate and private key handles are required")
        return nil
    }

    guard let identity = SecIdentityCreate(nil, certificate, privateKey) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "SecIdentityCreate returned nil")
        return nil
    }

    return retainIdentityRecord(identity)
}

@_cdecl("security_identity_create_with_certificate")
public func securityIdentityCreateWithCertificate(
    _ certificatePointer: UnsafeMutableRawPointer?,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard let certificate = unbox(certificatePointer, as: SecCertificate.self) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "certificate handle is required")
        return nil
    }

    var identity: SecIdentity?
    let status = SecIdentityCreateWithCertificate(nil, certificate, &identity)
    guard status == errSecSuccess, let identity else {
        setStatus(statusOut, status)
        setError(errorOut, "SecIdentityCreateWithCertificate failed: \(statusMessage(status))")
        return nil
    }

    return retainIdentityRecord(identity)
}

@_cdecl("security_identity_copy_preferred")
public func securityIdentityCopyPreferred(
    _ namePointer: UnsafePointer<CChar>?,
    _ keyUsagePointer: UnsafePointer<CChar>?,
    _ validIssuersPointer: UnsafePointer<CChar>?,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard let name = stringFromCString(namePointer) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "identity preference name is required")
        return nil
    }

    guard keyUsagePointer == nil || keyUsageArray(fromCString: keyUsagePointer) != nil else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "identity preference key usage JSON was invalid")
        return nil
    }
    guard validIssuersPointer == nil || jsonDataArray(fromCString: validIssuersPointer) != nil else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "identity preference valid issuers JSON was invalid")
        return nil
    }

    let keyUsage = keyUsageArray(fromCString: keyUsagePointer)
    let validIssuers = jsonDataArray(fromCString: validIssuersPointer)
    guard let identity = SecIdentityCopyPreferred(
        name as CFString,
        keyUsage as CFArray?,
        validIssuers as CFArray?
    ) else {
        return nil
    }

    return retainIdentityRecord(identity)
}

@_cdecl("security_identity_set_preferred")
public func securityIdentitySetPreferred(
    _ identityPointer: UnsafeMutableRawPointer?,
    _ namePointer: UnsafePointer<CChar>?,
    _ keyUsagePointer: UnsafePointer<CChar>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> Int32 {
    clearError(errorOut)

    guard let name = stringFromCString(namePointer) else {
        setError(errorOut, "identity preference name is required")
        return errSecParam
    }

    guard keyUsagePointer == nil || keyUsageArray(fromCString: keyUsagePointer) != nil else {
        setError(errorOut, "identity preference key usage JSON was invalid")
        return errSecParam
    }

    let status = SecIdentitySetPreferred(
        identityFromPointer(identityPointer),
        name as CFString,
        keyUsageArray(fromCString: keyUsagePointer) as CFArray?
    )
    if status != errSecSuccess {
        setError(errorOut, "SecIdentitySetPreferred failed: \(statusMessage(status))")
    }
    return status
}

@_cdecl("security_identity_copy_system_identity")
public func securityIdentityCopySystemIdentity(
    _ domainPointer: UnsafePointer<CChar>?,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard let domain = stringFromCString(domainPointer) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "system identity domain is required")
        return nil
    }

    var identity: SecIdentity?
    var actualDomain: CFString?
    let status = SecIdentityCopySystemIdentity(domain as CFString, &identity, &actualDomain)
    guard status == errSecSuccess, let identity else {
        setStatus(statusOut, status)
        setError(errorOut, "SecIdentityCopySystemIdentity failed: \(statusMessage(status))")
        return nil
    }

    return retainIdentityRecord(identity, actualDomain: actualDomain as String?)
}

@_cdecl("security_identity_copy_actual_domain")
public func securityIdentityCopyActualDomain(_ identityPointer: UnsafeMutableRawPointer?) -> UnsafeMutableRawPointer? {
    unbox(identityPointer, as: IdentityRecord.self).flatMap { stringHandle($0.actualDomain) }
}

@_cdecl("security_identity_set_system_identity")
public func securityIdentitySetSystemIdentity(
    _ domainPointer: UnsafePointer<CChar>?,
    _ identityPointer: UnsafeMutableRawPointer?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> Int32 {
    clearError(errorOut)

    guard let domain = stringFromCString(domainPointer) else {
        setError(errorOut, "system identity domain is required")
        return errSecParam
    }

    let status = SecIdentitySetSystemIdentity(domain as CFString, identityFromPointer(identityPointer))
    if status != errSecSuccess {
        setError(errorOut, "SecIdentitySetSystemIdentity failed: \(statusMessage(status))")
    }
    return status
}
