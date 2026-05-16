import Foundation
import Security

@_cdecl("security_cms_encode_certificates")
public func securityCmsEncodeCertificates(
    _ certificatePointers: UnsafePointer<UnsafeMutableRawPointer?>?,
    _ certificateCount: Int,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    let certificates = handleArray(certificatePointers, count: certificateCount, as: SecCertificate.self)
    guard !certificates.isEmpty else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "at least one certificate is required")
        return nil
    }

    var encoder: CMSEncoder?
    var status = CMSEncoderCreate(&encoder)
    guard status == errSecSuccess, let encoder else {
        setStatus(statusOut, status)
        setError(errorOut, "CMSEncoderCreate failed: \(statusMessage(status))")
        return nil
    }

    status = CMSEncoderAddSupportingCerts(encoder, certificates as CFArray)
    guard status == errSecSuccess else {
        setStatus(statusOut, status)
        setError(errorOut, "CMSEncoderAddSupportingCerts failed: \(statusMessage(status))")
        return nil
    }

    var encodedContent: CFData?
    status = CMSEncoderCopyEncodedContent(encoder, &encodedContent)
    guard status == errSecSuccess else {
        setStatus(statusOut, status)
        setError(errorOut, "CMSEncoderCopyEncodedContent failed: \(statusMessage(status))")
        return nil
    }

    return dataHandle(encodedContent as Data?)
}

@_cdecl("security_cms_decode_all_certificates")
public func securityCmsDecodeAllCertificates(
    _ dataPointer: UnsafeRawPointer?,
    _ dataLength: Int,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard let message = dataFromPointer(dataPointer, length: dataLength) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "CMS data are required")
        return nil
    }

    var decoder: CMSDecoder?
    var status = CMSDecoderCreate(&decoder)
    guard status == errSecSuccess, let decoder else {
        setStatus(statusOut, status)
        setError(errorOut, "CMSDecoderCreate failed: \(statusMessage(status))")
        return nil
    }

    status = message.withUnsafeBytes { bytes in
        CMSDecoderUpdateMessage(decoder, bytes.baseAddress!, bytes.count)
    }
    guard status == errSecSuccess else {
        setStatus(statusOut, status)
        setError(errorOut, "CMSDecoderUpdateMessage failed: \(statusMessage(status))")
        return nil
    }

    status = CMSDecoderFinalizeMessage(decoder)
    guard status == errSecSuccess else {
        setStatus(statusOut, status)
        setError(errorOut, "CMSDecoderFinalizeMessage failed: \(statusMessage(status))")
        return nil
    }

    var certificates: CFArray?
    status = CMSDecoderCopyAllCerts(decoder, &certificates)
    guard status == errSecSuccess else {
        setStatus(statusOut, status)
        setError(errorOut, "CMSDecoderCopyAllCerts failed: \(statusMessage(status))")
        return nil
    }

    let values = certificates as? [SecCertificate] ?? []
    return retain(values)
}
