import Foundation
import Security

private func cmsDateHandle(_ absoluteTime: CFAbsoluteTime) -> UnsafeMutableRawPointer? {
    jsonHandle(Date(timeIntervalSinceReferenceDate: absoluteTime))
}

private func cmsPolicy(_ policyPointer: UnsafeMutableRawPointer?) -> CFTypeRef {
    if let policy = unbox(policyPointer, as: SecPolicy.self) {
        return policy
    }
    return SecPolicyCreateBasicX509()
}

private func cmsSigners(
    _ identityPointers: UnsafePointer<UnsafeMutableRawPointer?>?,
    count: Int
) -> [SecIdentity] {
    handleArray(identityPointers, count: count, as: IdentityRecord.self).map(\.identity)
}

private func cmsCertificates(
    _ certificatePointers: UnsafePointer<UnsafeMutableRawPointer?>?,
    count: Int
) -> [SecCertificate] {
    handleArray(certificatePointers, count: count, as: SecCertificate.self)
}

@_cdecl("security_cms_encode_certificates")
public func securityCmsEncodeCertificates(
    _ certificatePointers: UnsafePointer<UnsafeMutableRawPointer?>?,
    _ certificateCount: Int,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    let certificates = cmsCertificates(certificatePointers, count: certificateCount)
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

@_cdecl("security_cms_decoder_get_type_id")
public func securityCmsDecoderGetTypeID() -> UInt {
    CMSDecoderGetTypeID()
}

@_cdecl("security_cms_decoder_create")
public func securityCmsDecoderCreate(
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    var decoder: CMSDecoder?
    let status = CMSDecoderCreate(&decoder)
    guard status == errSecSuccess, let decoder else {
        setStatus(statusOut, status)
        setError(errorOut, "CMSDecoderCreate failed: \(statusMessage(status))")
        return nil
    }
    return retain(decoder)
}

@_cdecl("security_cms_decoder_update_message")
public func securityCmsDecoderUpdateMessage(
    _ pointer: UnsafeMutableRawPointer?,
    _ dataPointer: UnsafeRawPointer?,
    _ dataLength: Int,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> Int32 {
    clearError(errorOut)

    guard let decoder = unbox(pointer, as: CMSDecoder.self),
          let data = dataFromPointer(dataPointer, length: dataLength)
    else {
        setError(errorOut, "decoder handle and message bytes are required")
        return errSecParam
    }

    let status = data.withUnsafeBytes { bytes in
        CMSDecoderUpdateMessage(decoder, bytes.baseAddress!, bytes.count)
    }
    if status != errSecSuccess {
        setError(errorOut, "CMSDecoderUpdateMessage failed: \(statusMessage(status))")
    }
    return status
}

@_cdecl("security_cms_decoder_finalize_message")
public func securityCmsDecoderFinalizeMessage(
    _ pointer: UnsafeMutableRawPointer?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> Int32 {
    clearError(errorOut)

    guard let decoder = unbox(pointer, as: CMSDecoder.self) else {
        setError(errorOut, "decoder handle is required")
        return errSecParam
    }

    let status = CMSDecoderFinalizeMessage(decoder)
    if status != errSecSuccess {
        setError(errorOut, "CMSDecoderFinalizeMessage failed: \(statusMessage(status))")
    }
    return status
}

@_cdecl("security_cms_decoder_set_detached_content")
public func securityCmsDecoderSetDetachedContent(
    _ pointer: UnsafeMutableRawPointer?,
    _ dataPointer: UnsafeRawPointer?,
    _ dataLength: Int,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> Int32 {
    clearError(errorOut)

    guard let decoder = unbox(pointer, as: CMSDecoder.self),
          let data = dataFromPointer(dataPointer, length: dataLength)
    else {
        setError(errorOut, "decoder handle and detached content are required")
        return errSecParam
    }

    let status = CMSDecoderSetDetachedContent(decoder, data as CFData)
    if status != errSecSuccess {
        setError(errorOut, "CMSDecoderSetDetachedContent failed: \(statusMessage(status))")
    }
    return status
}

@_cdecl("security_cms_decoder_copy_detached_content")
public func securityCmsDecoderCopyDetachedContent(
    _ pointer: UnsafeMutableRawPointer?,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard let decoder = unbox(pointer, as: CMSDecoder.self) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "decoder handle is required")
        return nil
    }

    var detachedContent: CFData?
    let status = CMSDecoderCopyDetachedContent(decoder, &detachedContent)
    guard status == errSecSuccess else {
        setStatus(statusOut, status)
        setError(errorOut, "CMSDecoderCopyDetachedContent failed: \(statusMessage(status))")
        return nil
    }

    return dataHandle(detachedContent as Data?)
}

@_cdecl("security_cms_decoder_get_num_signers")
public func securityCmsDecoderGetNumSigners(
    _ pointer: UnsafeMutableRawPointer?,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> Int {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard let decoder = unbox(pointer, as: CMSDecoder.self) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "decoder handle is required")
        return 0
    }

    var signerCount = 0
    let status = CMSDecoderGetNumSigners(decoder, &signerCount)
    guard status == errSecSuccess else {
        setStatus(statusOut, status)
        setError(errorOut, "CMSDecoderGetNumSigners failed: \(statusMessage(status))")
        return 0
    }

    return signerCount
}

@_cdecl("security_cms_decoder_copy_signer_status")
public func securityCmsDecoderCopySignerStatus(
    _ pointer: UnsafeMutableRawPointer?,
    _ signerIndex: Int,
    _ policyPointer: UnsafeMutableRawPointer?,
    _ evaluateSecTrust: Bool,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard let decoder = unbox(pointer, as: CMSDecoder.self) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "decoder handle is required")
        return nil
    }

    var signerStatus = CMSSignerStatus(rawValue: 0)!
    var secTrust: SecTrust?
    var verifyResult = errSecSuccess
    let status = CMSDecoderCopySignerStatus(
        decoder,
        signerIndex,
        cmsPolicy(policyPointer),
        evaluateSecTrust,
        &signerStatus,
        &secTrust,
        &verifyResult
    )
    guard status == errSecSuccess else {
        setStatus(statusOut, status)
        setError(errorOut, "CMSDecoderCopySignerStatus failed: \(statusMessage(status))")
        return nil
    }

    var result: [String: Any] = [
        "certVerifyResultCode": verifyResult,
        "signerStatus": signerStatus.rawValue,
    ]
    if let secTrust, let trustResult = SecTrustCopyResult(secTrust) {
        result["trustResult"] = trustResult
    }
    return jsonHandle(result)
}

@_cdecl("security_cms_decoder_copy_signer_email_address")
public func securityCmsDecoderCopySignerEmailAddress(
    _ pointer: UnsafeMutableRawPointer?,
    _ signerIndex: Int,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard let decoder = unbox(pointer, as: CMSDecoder.self) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "decoder handle is required")
        return nil
    }

    var signerEmail: CFString?
    let status = CMSDecoderCopySignerEmailAddress(decoder, signerIndex, &signerEmail)
    guard status == errSecSuccess else {
        setStatus(statusOut, status)
        setError(errorOut, "CMSDecoderCopySignerEmailAddress failed: \(statusMessage(status))")
        return nil
    }
    return stringHandle(signerEmail as String?)
}

@_cdecl("security_cms_decoder_copy_signer_cert")
public func securityCmsDecoderCopySignerCert(
    _ pointer: UnsafeMutableRawPointer?,
    _ signerIndex: Int,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard let decoder = unbox(pointer, as: CMSDecoder.self) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "decoder handle is required")
        return nil
    }

    var signerCertificate: SecCertificate?
    let status = CMSDecoderCopySignerCert(decoder, signerIndex, &signerCertificate)
    guard status == errSecSuccess, let signerCertificate else {
        setStatus(statusOut, status)
        setError(errorOut, "CMSDecoderCopySignerCert failed: \(statusMessage(status))")
        return nil
    }
    return retain(signerCertificate)
}

@_cdecl("security_cms_decoder_is_content_encrypted")
public func securityCmsDecoderIsContentEncrypted(
    _ pointer: UnsafeMutableRawPointer?,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> Bool {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard let decoder = unbox(pointer, as: CMSDecoder.self) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "decoder handle is required")
        return false
    }

    var encrypted = DarwinBoolean(false)
    let status = CMSDecoderIsContentEncrypted(decoder, &encrypted)
    guard status == errSecSuccess else {
        setStatus(statusOut, status)
        setError(errorOut, "CMSDecoderIsContentEncrypted failed: \(statusMessage(status))")
        return false
    }
    return encrypted.boolValue
}

@_cdecl("security_cms_decoder_copy_encapsulated_content_type")
public func securityCmsDecoderCopyEncapsulatedContentType(
    _ pointer: UnsafeMutableRawPointer?,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard let decoder = unbox(pointer, as: CMSDecoder.self) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "decoder handle is required")
        return nil
    }

    var contentType: CFData?
    let status = CMSDecoderCopyEncapsulatedContentType(decoder, &contentType)
    guard status == errSecSuccess else {
        setStatus(statusOut, status)
        setError(errorOut, "CMSDecoderCopyEncapsulatedContentType failed: \(statusMessage(status))")
        return nil
    }
    return dataHandle(contentType as Data?)
}

@_cdecl("security_cms_decoder_copy_content")
public func securityCmsDecoderCopyContent(
    _ pointer: UnsafeMutableRawPointer?,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard let decoder = unbox(pointer, as: CMSDecoder.self) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "decoder handle is required")
        return nil
    }

    var content: CFData?
    let status = CMSDecoderCopyContent(decoder, &content)
    guard status == errSecSuccess else {
        setStatus(statusOut, status)
        setError(errorOut, "CMSDecoderCopyContent failed: \(statusMessage(status))")
        return nil
    }
    return dataHandle(content as Data?)
}

@_cdecl("security_cms_decoder_copy_signer_signing_time")
public func securityCmsDecoderCopySignerSigningTime(
    _ pointer: UnsafeMutableRawPointer?,
    _ signerIndex: Int,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard let decoder = unbox(pointer, as: CMSDecoder.self) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "decoder handle is required")
        return nil
    }

    var signingTime: CFAbsoluteTime = 0
    let status = CMSDecoderCopySignerSigningTime(decoder, signerIndex, &signingTime)
    guard status == errSecSuccess else {
        setStatus(statusOut, status)
        setError(errorOut, "CMSDecoderCopySignerSigningTime failed: \(statusMessage(status))")
        return nil
    }
    return cmsDateHandle(signingTime)
}

@_cdecl("security_cms_decoder_copy_signer_timestamp")
public func securityCmsDecoderCopySignerTimestamp(
    _ pointer: UnsafeMutableRawPointer?,
    _ signerIndex: Int,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard let decoder = unbox(pointer, as: CMSDecoder.self) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "decoder handle is required")
        return nil
    }

    var timestamp: CFAbsoluteTime = 0
    let status = CMSDecoderCopySignerTimestamp(decoder, signerIndex, &timestamp)
    guard status == errSecSuccess else {
        setStatus(statusOut, status)
        setError(errorOut, "CMSDecoderCopySignerTimestamp failed: \(statusMessage(status))")
        return nil
    }
    return cmsDateHandle(timestamp)
}

@_cdecl("security_cms_decoder_copy_signer_timestamp_with_policy")
public func securityCmsDecoderCopySignerTimestampWithPolicy(
    _ pointer: UnsafeMutableRawPointer?,
    _ policyPointer: UnsafeMutableRawPointer?,
    _ signerIndex: Int,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard let decoder = unbox(pointer, as: CMSDecoder.self) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "decoder handle is required")
        return nil
    }

    var timestamp: CFAbsoluteTime = 0
    let status = CMSDecoderCopySignerTimestampWithPolicy(decoder, cmsPolicy(policyPointer), signerIndex, &timestamp)
    guard status == errSecSuccess else {
        setStatus(statusOut, status)
        setError(errorOut, "CMSDecoderCopySignerTimestampWithPolicy failed: \(statusMessage(status))")
        return nil
    }
    return cmsDateHandle(timestamp)
}

@_cdecl("security_cms_decoder_copy_signer_timestamp_certificates")
public func securityCmsDecoderCopySignerTimestampCertificates(
    _ pointer: UnsafeMutableRawPointer?,
    _ signerIndex: Int,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard let decoder = unbox(pointer, as: CMSDecoder.self) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "decoder handle is required")
        return nil
    }

    var certificates: CFArray?
    let status = CMSDecoderCopySignerTimestampCertificates(decoder, signerIndex, &certificates)
    guard status == errSecSuccess else {
        setStatus(statusOut, status)
        setError(errorOut, "CMSDecoderCopySignerTimestampCertificates failed: \(statusMessage(status))")
        return nil
    }
    return jsonHandle(certificates as Any? ?? [])
}

@_cdecl("security_cms_encoder_get_type_id")
public func securityCmsEncoderGetTypeID() -> UInt {
    CMSEncoderGetTypeID()
}

@_cdecl("security_cms_encoder_create")
public func securityCmsEncoderCreate(
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    var encoder: CMSEncoder?
    let status = CMSEncoderCreate(&encoder)
    guard status == errSecSuccess, let encoder else {
        setStatus(statusOut, status)
        setError(errorOut, "CMSEncoderCreate failed: \(statusMessage(status))")
        return nil
    }
    return retain(encoder)
}

@_cdecl("security_cms_encoder_set_signer_algorithm")
public func securityCmsEncoderSetSignerAlgorithm(
    _ pointer: UnsafeMutableRawPointer?,
    _ algorithmPointer: UnsafePointer<CChar>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> Int32 {
    clearError(errorOut)

    guard let encoder = unbox(pointer, as: CMSEncoder.self),
          let algorithm = stringFromCString(algorithmPointer)
    else {
        setError(errorOut, "encoder handle and digest algorithm are required")
        return errSecParam
    }

    let digestAlgorithm: CFString
    switch algorithm {
    case "sha1":
        digestAlgorithm = kCMSEncoderDigestAlgorithmSHA1
    case "sha256":
        digestAlgorithm = kCMSEncoderDigestAlgorithmSHA256
    default:
        setError(errorOut, "unsupported CMS digest algorithm: \(algorithm)")
        return errSecParam
    }

    let status = CMSEncoderSetSignerAlgorithm(encoder, digestAlgorithm)
    if status != errSecSuccess {
        setError(errorOut, "CMSEncoderSetSignerAlgorithm failed: \(statusMessage(status))")
    }
    return status
}

@_cdecl("security_cms_encoder_add_signers")
public func securityCmsEncoderAddSigners(
    _ pointer: UnsafeMutableRawPointer?,
    _ identityPointers: UnsafePointer<UnsafeMutableRawPointer?>?,
    _ identityCount: Int,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> Int32 {
    clearError(errorOut)

    guard let encoder = unbox(pointer, as: CMSEncoder.self) else {
        setError(errorOut, "encoder handle is required")
        return errSecParam
    }

    let identities = cmsSigners(identityPointers, count: identityCount)
    guard !identities.isEmpty else {
        setError(errorOut, "at least one signer identity is required")
        return errSecParam
    }

    let signerInput: CFTypeRef = identities.count == 1 ? identities[0] : identities as CFArray
    let status = CMSEncoderAddSigners(encoder, signerInput)
    if status != errSecSuccess {
        setError(errorOut, "CMSEncoderAddSigners failed: \(statusMessage(status))")
    }
    return status
}

@_cdecl("security_cms_encoder_copy_signers")
public func securityCmsEncoderCopySigners(
    _ pointer: UnsafeMutableRawPointer?,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard let encoder = unbox(pointer, as: CMSEncoder.self) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "encoder handle is required")
        return nil
    }

    var signers: CFArray?
    let status = CMSEncoderCopySigners(encoder, &signers)
    guard status == errSecSuccess else {
        setStatus(statusOut, status)
        setError(errorOut, "CMSEncoderCopySigners failed: \(statusMessage(status))")
        return nil
    }
    return jsonHandle(signers as Any? ?? [])
}

@_cdecl("security_cms_encoder_add_recipients")
public func securityCmsEncoderAddRecipients(
    _ pointer: UnsafeMutableRawPointer?,
    _ certificatePointers: UnsafePointer<UnsafeMutableRawPointer?>?,
    _ certificateCount: Int,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> Int32 {
    clearError(errorOut)

    guard let encoder = unbox(pointer, as: CMSEncoder.self) else {
        setError(errorOut, "encoder handle is required")
        return errSecParam
    }

    let certificates = cmsCertificates(certificatePointers, count: certificateCount)
    guard !certificates.isEmpty else {
        setError(errorOut, "at least one recipient certificate is required")
        return errSecParam
    }

    let recipientInput: CFTypeRef = certificates.count == 1 ? certificates[0] : certificates as CFArray
    let status = CMSEncoderAddRecipients(encoder, recipientInput)
    if status != errSecSuccess {
        setError(errorOut, "CMSEncoderAddRecipients failed: \(statusMessage(status))")
    }
    return status
}

@_cdecl("security_cms_encoder_copy_recipients")
public func securityCmsEncoderCopyRecipients(
    _ pointer: UnsafeMutableRawPointer?,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard let encoder = unbox(pointer, as: CMSEncoder.self) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "encoder handle is required")
        return nil
    }

    var recipients: CFArray?
    let status = CMSEncoderCopyRecipients(encoder, &recipients)
    guard status == errSecSuccess else {
        setStatus(statusOut, status)
        setError(errorOut, "CMSEncoderCopyRecipients failed: \(statusMessage(status))")
        return nil
    }
    return jsonHandle(recipients as Any? ?? [])
}

@_cdecl("security_cms_encoder_set_has_detached_content")
public func securityCmsEncoderSetHasDetachedContent(
    _ pointer: UnsafeMutableRawPointer?,
    _ detachedContent: Bool,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> Int32 {
    clearError(errorOut)

    guard let encoder = unbox(pointer, as: CMSEncoder.self) else {
        setError(errorOut, "encoder handle is required")
        return errSecParam
    }

    let status = CMSEncoderSetHasDetachedContent(encoder, detachedContent)
    if status != errSecSuccess {
        setError(errorOut, "CMSEncoderSetHasDetachedContent failed: \(statusMessage(status))")
    }
    return status
}

@_cdecl("security_cms_encoder_get_has_detached_content")
public func securityCmsEncoderGetHasDetachedContent(
    _ pointer: UnsafeMutableRawPointer?,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> Bool {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard let encoder = unbox(pointer, as: CMSEncoder.self) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "encoder handle is required")
        return false
    }

    var detachedContent = DarwinBoolean(false)
    let status = CMSEncoderGetHasDetachedContent(encoder, &detachedContent)
    guard status == errSecSuccess else {
        setStatus(statusOut, status)
        setError(errorOut, "CMSEncoderGetHasDetachedContent failed: \(statusMessage(status))")
        return false
    }
    return detachedContent.boolValue
}

@_cdecl("security_cms_encoder_set_encapsulated_content_type_oid")
public func securityCmsEncoderSetEncapsulatedContentTypeOID(
    _ pointer: UnsafeMutableRawPointer?,
    _ oidPointer: UnsafePointer<CChar>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> Int32 {
    clearError(errorOut)

    guard let encoder = unbox(pointer, as: CMSEncoder.self),
          let oid = stringFromCString(oidPointer)
    else {
        setError(errorOut, "encoder handle and encapsulated content type OID are required")
        return errSecParam
    }

    let status = CMSEncoderSetEncapsulatedContentTypeOID(encoder, oid as CFString)
    if status != errSecSuccess {
        setError(errorOut, "CMSEncoderSetEncapsulatedContentTypeOID failed: \(statusMessage(status))")
    }
    return status
}

@_cdecl("security_cms_encoder_copy_encapsulated_content_type")
public func securityCmsEncoderCopyEncapsulatedContentType(
    _ pointer: UnsafeMutableRawPointer?,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard let encoder = unbox(pointer, as: CMSEncoder.self) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "encoder handle is required")
        return nil
    }

    var contentType: CFData?
    let status = CMSEncoderCopyEncapsulatedContentType(encoder, &contentType)
    guard status == errSecSuccess else {
        setStatus(statusOut, status)
        setError(errorOut, "CMSEncoderCopyEncapsulatedContentType failed: \(statusMessage(status))")
        return nil
    }
    return dataHandle(contentType as Data?)
}

@_cdecl("security_cms_encoder_add_supporting_certs")
public func securityCmsEncoderAddSupportingCerts(
    _ pointer: UnsafeMutableRawPointer?,
    _ certificatePointers: UnsafePointer<UnsafeMutableRawPointer?>?,
    _ certificateCount: Int,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> Int32 {
    clearError(errorOut)

    guard let encoder = unbox(pointer, as: CMSEncoder.self) else {
        setError(errorOut, "encoder handle is required")
        return errSecParam
    }

    let certificates = cmsCertificates(certificatePointers, count: certificateCount)
    guard !certificates.isEmpty else {
        setError(errorOut, "at least one supporting certificate is required")
        return errSecParam
    }

    let certificateInput: CFTypeRef = certificates.count == 1 ? certificates[0] : certificates as CFArray
    let status = CMSEncoderAddSupportingCerts(encoder, certificateInput)
    if status != errSecSuccess {
        setError(errorOut, "CMSEncoderAddSupportingCerts failed: \(statusMessage(status))")
    }
    return status
}

@_cdecl("security_cms_encoder_copy_supporting_certs")
public func securityCmsEncoderCopySupportingCerts(
    _ pointer: UnsafeMutableRawPointer?,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard let encoder = unbox(pointer, as: CMSEncoder.self) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "encoder handle is required")
        return nil
    }

    var certificates: CFArray?
    let status = CMSEncoderCopySupportingCerts(encoder, &certificates)
    guard status == errSecSuccess else {
        setStatus(statusOut, status)
        setError(errorOut, "CMSEncoderCopySupportingCerts failed: \(statusMessage(status))")
        return nil
    }
    return jsonHandle(certificates as Any? ?? [])
}

@_cdecl("security_cms_encoder_add_signed_attributes")
public func securityCmsEncoderAddSignedAttributes(
    _ pointer: UnsafeMutableRawPointer?,
    _ signedAttributes: UInt32,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> Int32 {
    clearError(errorOut)

    guard let encoder = unbox(pointer, as: CMSEncoder.self) else {
        setError(errorOut, "encoder handle is required")
        return errSecParam
    }

    let status = CMSEncoderAddSignedAttributes(encoder, CMSSignedAttributes(rawValue: signedAttributes))
    if status != errSecSuccess {
        setError(errorOut, "CMSEncoderAddSignedAttributes failed: \(statusMessage(status))")
    }
    return status
}

@_cdecl("security_cms_encoder_set_certificate_chain_mode")
public func securityCmsEncoderSetCertificateChainMode(
    _ pointer: UnsafeMutableRawPointer?,
    _ chainMode: UInt32,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> Int32 {
    clearError(errorOut)

    guard let encoder = unbox(pointer, as: CMSEncoder.self),
          let chainMode = CMSCertificateChainMode(rawValue: chainMode)
    else {
        setError(errorOut, "encoder handle and chain mode are required")
        return errSecParam
    }

    let status = CMSEncoderSetCertificateChainMode(encoder, chainMode)
    if status != errSecSuccess {
        setError(errorOut, "CMSEncoderSetCertificateChainMode failed: \(statusMessage(status))")
    }
    return status
}

@_cdecl("security_cms_encoder_get_certificate_chain_mode")
public func securityCmsEncoderGetCertificateChainMode(
    _ pointer: UnsafeMutableRawPointer?,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UInt32 {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard let encoder = unbox(pointer, as: CMSEncoder.self) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "encoder handle is required")
        return 0
    }

    var chainMode = CMSCertificateChainMode.none
    let status = CMSEncoderGetCertificateChainMode(encoder, &chainMode)
    guard status == errSecSuccess else {
        setStatus(statusOut, status)
        setError(errorOut, "CMSEncoderGetCertificateChainMode failed: \(statusMessage(status))")
        return 0
    }
    return chainMode.rawValue
}

@_cdecl("security_cms_encoder_update_content")
public func securityCmsEncoderUpdateContent(
    _ pointer: UnsafeMutableRawPointer?,
    _ dataPointer: UnsafeRawPointer?,
    _ dataLength: Int,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> Int32 {
    clearError(errorOut)

    guard let encoder = unbox(pointer, as: CMSEncoder.self),
          let data = dataFromPointer(dataPointer, length: dataLength)
    else {
        setError(errorOut, "encoder handle and content bytes are required")
        return errSecParam
    }

    let status = data.withUnsafeBytes { bytes in
        CMSEncoderUpdateContent(encoder, bytes.baseAddress!, bytes.count)
    }
    if status != errSecSuccess {
        setError(errorOut, "CMSEncoderUpdateContent failed: \(statusMessage(status))")
    }
    return status
}

@_cdecl("security_cms_encoder_copy_encoded_content")
public func securityCmsEncoderCopyEncodedContent(
    _ pointer: UnsafeMutableRawPointer?,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard let encoder = unbox(pointer, as: CMSEncoder.self) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "encoder handle is required")
        return nil
    }

    var encodedContent: CFData?
    let status = CMSEncoderCopyEncodedContent(encoder, &encodedContent)
    guard status == errSecSuccess else {
        setStatus(statusOut, status)
        setError(errorOut, "CMSEncoderCopyEncodedContent failed: \(statusMessage(status))")
        return nil
    }
    return dataHandle(encodedContent as Data?)
}

@_cdecl("security_cms_encode_content")
public func securityCmsEncodeContent(
    _ identityPointers: UnsafePointer<UnsafeMutableRawPointer?>?,
    _ identityCount: Int,
    _ certificatePointers: UnsafePointer<UnsafeMutableRawPointer?>?,
    _ certificateCount: Int,
    _ econtentTypeOIDPointer: UnsafePointer<CChar>?,
    _ detachedContent: Bool,
    _ signedAttributes: UInt32,
    _ dataPointer: UnsafeRawPointer?,
    _ dataLength: Int,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard let data = dataFromPointer(dataPointer, length: dataLength) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "CMS content bytes are required")
        return nil
    }

    let signers = cmsSigners(identityPointers, count: identityCount)
    let recipients = cmsCertificates(certificatePointers, count: certificateCount)
    let signerInput: CFTypeRef?
    if signers.isEmpty {
        signerInput = nil
    } else if signers.count == 1 {
        signerInput = signers[0]
    } else {
        signerInput = signers as CFArray
    }

    let recipientInput: CFTypeRef?
    if recipients.isEmpty {
        recipientInput = nil
    } else if recipients.count == 1 {
        recipientInput = recipients[0]
    } else {
        recipientInput = recipients as CFArray
    }
    let econtentTypeOID = stringFromCString(econtentTypeOIDPointer) as CFString?

    var encodedContent: CFData?
    let status = data.withUnsafeBytes { bytes in
        CMSEncodeContent(
            signerInput,
            recipientInput,
            econtentTypeOID,
            detachedContent,
            CMSSignedAttributes(rawValue: signedAttributes),
            bytes.baseAddress ?? UnsafeRawPointer(bitPattern: 1)!,
            bytes.count,
            &encodedContent
        )
    }
    guard status == errSecSuccess else {
        setStatus(statusOut, status)
        setError(errorOut, "CMSEncodeContent failed: \(statusMessage(status))")
        return nil
    }
    return dataHandle(encodedContent as Data?)
}

@_cdecl("security_cms_encoder_copy_signer_timestamp")
public func securityCmsEncoderCopySignerTimestamp(
    _ pointer: UnsafeMutableRawPointer?,
    _ signerIndex: Int,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard let encoder = unbox(pointer, as: CMSEncoder.self) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "encoder handle is required")
        return nil
    }

    var timestamp: CFAbsoluteTime = 0
    let status = CMSEncoderCopySignerTimestamp(encoder, signerIndex, &timestamp)
    guard status == errSecSuccess else {
        setStatus(statusOut, status)
        setError(errorOut, "CMSEncoderCopySignerTimestamp failed: \(statusMessage(status))")
        return nil
    }
    return cmsDateHandle(timestamp)
}

@_cdecl("security_cms_encoder_copy_signer_timestamp_with_policy")
public func securityCmsEncoderCopySignerTimestampWithPolicy(
    _ pointer: UnsafeMutableRawPointer?,
    _ policyPointer: UnsafeMutableRawPointer?,
    _ signerIndex: Int,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard let encoder = unbox(pointer, as: CMSEncoder.self) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "encoder handle is required")
        return nil
    }

    var timestamp: CFAbsoluteTime = 0
    let status = CMSEncoderCopySignerTimestampWithPolicy(encoder, cmsPolicy(policyPointer), signerIndex, &timestamp)
    guard status == errSecSuccess else {
        setStatus(statusOut, status)
        setError(errorOut, "CMSEncoderCopySignerTimestampWithPolicy failed: \(statusMessage(status))")
        return nil
    }
    return cmsDateHandle(timestamp)
}
