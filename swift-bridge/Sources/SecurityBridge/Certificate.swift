import Foundation
import Security

@_cdecl("security_certificate_from_der")
public func securityCertificateFromDer(
    _ dataPointer: UnsafeRawPointer?,
    _ dataLength: Int,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard let certificateData = dataFromPointer(dataPointer, length: dataLength) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "DER certificate bytes are required")
        return nil
    }

    guard let certificate = SecCertificateCreateWithData(nil, certificateData as CFData) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "invalid DER-encoded X.509 certificate")
        return nil
    }

    return retain(certificate)
}

@_cdecl("security_certificate_import_item")
public func securityCertificateImportItem(
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

    guard let importedItems = items as? [SecCertificate],
          let certificate = importedItems.first
    else {
        setStatus(statusOut, errSecItemNotFound)
        setError(errorOut, "SecItemImport returned no SecCertificate result")
        return nil
    }

    return retain(certificate)
}

@_cdecl("security_certificate_export_item")
public func securityCertificateExportItem(
    _ certificatePointer: UnsafeMutableRawPointer?,
    _ formatRawValue: UInt32,
    _ pemArmour: Bool,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard let certificate = unbox(certificatePointer, as: SecCertificate.self),
          let outputFormat = SecExternalFormat(rawValue: formatRawValue)
    else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "certificate handle and export format are required")
        return nil
    }

    let flags = pemArmour ? SecItemImportExportFlags(rawValue: 1) : SecItemImportExportFlags()
    var exportedData: CFData?
    let status = SecItemExport(certificate, outputFormat, flags, nil, &exportedData)
    guard status == errSecSuccess, let exportedData else {
        setStatus(statusOut, status)
        setError(errorOut, "SecItemExport failed: \(statusMessage(status))")
        return nil
    }

    return dataHandle(exportedData as Data)
}

@_cdecl("security_certificate_copy_der")
public func securityCertificateCopyDer(
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

    return dataHandle(SecCertificateCopyData(certificate) as Data)
}

@_cdecl("security_certificate_copy_subject_summary")
public func securityCertificateCopySubjectSummary(_ certificatePointer: UnsafeMutableRawPointer?) -> UnsafeMutableRawPointer? {
    guard let certificate = unbox(certificatePointer, as: SecCertificate.self) else {
        return nil
    }

    return stringHandle(SecCertificateCopySubjectSummary(certificate) as String?)
}

@_cdecl("security_certificate_copy_common_name")
public func securityCertificateCopyCommonName(
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

    var commonName: CFString?
    let status = SecCertificateCopyCommonName(certificate, &commonName)
    guard status == errSecSuccess else {
        setStatus(statusOut, status)
        setError(errorOut, "SecCertificateCopyCommonName failed: \(statusMessage(status))")
        return nil
    }

    return stringHandle(commonName as String?)
}

@_cdecl("security_certificate_copy_email_addresses")
public func securityCertificateCopyEmailAddresses(
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

    var emailAddresses: CFArray?
    let status = SecCertificateCopyEmailAddresses(certificate, &emailAddresses)
    guard status == errSecSuccess else {
        setStatus(statusOut, status)
        setError(errorOut, "SecCertificateCopyEmailAddresses failed: \(statusMessage(status))")
        return nil
    }

    let values = emailAddresses as? [String] ?? []
    return jsonHandle(values)
}

@_cdecl("security_certificate_copy_normalized_subject_sequence")
public func securityCertificateCopyNormalizedSubjectSequence(
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

    return dataHandle(SecCertificateCopyNormalizedSubjectSequence(certificate) as Data?)
}

@_cdecl("security_certificate_copy_normalized_issuer_sequence")
public func securityCertificateCopyNormalizedIssuerSequence(
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

    return dataHandle(SecCertificateCopyNormalizedIssuerSequence(certificate) as Data?)
}

@_cdecl("security_certificate_copy_serial_number")
public func securityCertificateCopySerialNumber(
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

    var error: Unmanaged<CFError>?
    guard let serial = SecCertificateCopySerialNumberData(certificate, &error) as Data? else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, error)
        return nil
    }

    return dataHandle(serial)
}

@_cdecl("security_certificate_copy_not_valid_before")
public func securityCertificateCopyNotValidBefore(
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

    if #available(macOS 15.0, *) {
        if let date = SecCertificateCopyNotValidBeforeDate(certificate) as Date? {
            return jsonHandle(date)
        }
        return nil
    }

    setStatus(statusOut, errSecUnimplemented)
    setError(errorOut, "SecCertificateCopyNotValidBeforeDate requires macOS 15.0")
    return nil
}

@_cdecl("security_certificate_copy_not_valid_after")
public func securityCertificateCopyNotValidAfter(
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

    if #available(macOS 15.0, *) {
        if let date = SecCertificateCopyNotValidAfterDate(certificate) as Date? {
            return jsonHandle(date)
        }
        return nil
    }

    setStatus(statusOut, errSecUnimplemented)
    setError(errorOut, "SecCertificateCopyNotValidAfterDate requires macOS 15.0")
    return nil
}

@_cdecl("security_certificate_copy_public_key")
public func securityCertificateCopyPublicKey(
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

    guard let key = SecCertificateCopyKey(certificate) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "SecCertificateCopyKey returned nil")
        return nil
    }

    return retain(key)
}

@_cdecl("security_certificate_array_get_count")
public func securityCertificateArrayGetCount(_ arrayPointer: UnsafeMutableRawPointer?) -> Int {
    unbox(arrayPointer, as: [SecCertificate].self)?.count ?? 0
}

@_cdecl("security_certificate_array_copy_item")
public func securityCertificateArrayCopyItem(
    _ arrayPointer: UnsafeMutableRawPointer?,
    _ index: Int,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard let certificates = unbox(arrayPointer, as: [SecCertificate].self),
          certificates.indices.contains(index)
    else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "certificate array index out of bounds")
        return nil
    }

    return retain(certificates[index])
}

@_cdecl("security_certificate_get_type_id")
public func securityCertificateGetTypeID() -> UInt {
    SecCertificateGetTypeID()
}

@_cdecl("security_certificate_add_to_keychain")
public func securityCertificateAddToKeychain(
    _ certificatePointer: UnsafeMutableRawPointer?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> Int32 {
    clearError(errorOut)

    guard let certificate = unbox(certificatePointer, as: SecCertificate.self) else {
        setError(errorOut, "certificate handle is required")
        return errSecParam
    }

    let status = SecCertificateAddToKeychain(certificate, nil)
    if status != errSecSuccess {
        setError(errorOut, "SecCertificateAddToKeychain failed: \(statusMessage(status))")
    }
    return status
}

@_cdecl("security_certificate_copy_values")
public func securityCertificateCopyValues(
    _ certificatePointer: UnsafeMutableRawPointer?,
    _ keysPointer: UnsafePointer<CChar>?,
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
    guard keysPointer == nil || jsonStringArray(fromCString: keysPointer) != nil else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "certificate OID key JSON was invalid")
        return nil
    }

    var error: Unmanaged<CFError>?
    guard let values = SecCertificateCopyValues(
        certificate,
        jsonStringArray(fromCString: keysPointer) as CFArray?,
        &error
    ) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, error)
        return nil
    }
    return jsonHandle(values)
}

@_cdecl("security_certificate_copy_long_description")
public func securityCertificateCopyLongDescription(
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

    var error: Unmanaged<CFError>?
    guard let description = SecCertificateCopyLongDescription(nil, certificate, &error) as String? else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, error)
        return nil
    }
    return stringHandle(description)
}

@_cdecl("security_certificate_copy_short_description")
public func securityCertificateCopyShortDescription(
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

    var error: Unmanaged<CFError>?
    guard let description = SecCertificateCopyShortDescription(nil, certificate, &error) as String? else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, error)
        return nil
    }
    return stringHandle(description)
}

@_cdecl("security_certificate_copy_preferred")
public func securityCertificateCopyPreferred(
    _ namePointer: UnsafePointer<CChar>?,
    _ keyUsagePointer: UnsafePointer<CChar>?,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard let name = stringFromCString(namePointer) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "certificate preference name is required")
        return nil
    }
    guard keyUsagePointer == nil || keyUsageArray(fromCString: keyUsagePointer) != nil else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "certificate preference key usage JSON was invalid")
        return nil
    }

    guard let certificate = SecCertificateCopyPreferred(name as CFString, keyUsageArray(fromCString: keyUsagePointer) as CFArray?) else {
        return nil
    }
    return retain(certificate)
}

@_cdecl("security_certificate_set_preferred")
public func securityCertificateSetPreferred(
    _ certificatePointer: UnsafeMutableRawPointer?,
    _ namePointer: UnsafePointer<CChar>?,
    _ keyUsagePointer: UnsafePointer<CChar>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> Int32 {
    clearError(errorOut)

    guard let name = stringFromCString(namePointer) else {
        setError(errorOut, "certificate preference name is required")
        return errSecParam
    }
    guard keyUsagePointer == nil || keyUsageArray(fromCString: keyUsagePointer) != nil else {
        setError(errorOut, "certificate preference key usage JSON was invalid")
        return errSecParam
    }

    let status = SecCertificateSetPreferred(
        unbox(certificatePointer, as: SecCertificate.self),
        name as CFString,
        keyUsageArray(fromCString: keyUsagePointer) as CFArray?
    )
    if status != errSecSuccess {
        setError(errorOut, "SecCertificateSetPreferred failed: \(statusMessage(status))")
    }
    return status
}
