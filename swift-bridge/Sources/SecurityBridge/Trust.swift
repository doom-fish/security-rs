import Dispatch
import Foundation
import Security

@_cdecl("security_trust_get_type_id")
public func securityTrustGetTypeID() -> UInt {
    SecTrustGetTypeID()
}

private func trustErrorMessage(_ error: CFError?) -> String {
    guard let error else {
        return "trust evaluation failed"
    }

    return (error as Error).localizedDescription
}

private func trustJSONArray(_ value: Any?) -> UnsafeMutableRawPointer? {
    jsonHandle(value ?? [])
}

@_cdecl("security_trust_create")
public func securityTrustCreate(
    _ certificatePointers: UnsafePointer<UnsafeMutableRawPointer?>?,
    _ certificateCount: Int,
    _ policyPointers: UnsafePointer<UnsafeMutableRawPointer?>?,
    _ policyCount: Int,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    let certificates = handleArray(certificatePointers, count: certificateCount, as: SecCertificate.self)
    let policies = handleArray(policyPointers, count: policyCount, as: SecPolicy.self)

    guard !certificates.isEmpty else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "at least one certificate is required")
        return nil
    }
    guard !policies.isEmpty else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "at least one policy is required")
        return nil
    }

    let certificateInput: CFTypeRef = certificates.count == 1 ? certificates[0] : certificates as CFArray
    let policyInput: CFTypeRef = policies.count == 1 ? policies[0] : policies as CFArray

    var trust: SecTrust?
    let status = SecTrustCreateWithCertificates(certificateInput, policyInput, &trust)
    guard status == errSecSuccess, let trust else {
        setStatus(statusOut, status)
        setError(errorOut, "SecTrustCreateWithCertificates failed: \(statusMessage(status))")
        return nil
    }

    return retain(trust)
}

@_cdecl("security_trust_set_policies")
public func securityTrustSetPolicies(
    _ trustPointer: UnsafeMutableRawPointer?,
    _ policyPointers: UnsafePointer<UnsafeMutableRawPointer?>?,
    _ policyCount: Int,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> Int32 {
    clearError(errorOut)

    guard let trust = unbox(trustPointer, as: SecTrust.self) else {
        setError(errorOut, "trust handle is required")
        return errSecParam
    }

    let policies = handleArray(policyPointers, count: policyCount, as: SecPolicy.self)
    guard !policies.isEmpty else {
        setError(errorOut, "at least one policy is required")
        return errSecParam
    }

    let input: CFTypeRef = policies.count == 1 ? policies[0] : policies as CFArray
    let status = SecTrustSetPolicies(trust, input)
    if status != errSecSuccess {
        setError(errorOut, "SecTrustSetPolicies failed: \(statusMessage(status))")
    }
    return status
}

@_cdecl("security_trust_copy_policies")
public func securityTrustCopyPolicies(
    _ trustPointer: UnsafeMutableRawPointer?,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard let trust = unbox(trustPointer, as: SecTrust.self) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "trust handle is required")
        return nil
    }

    var policies: CFArray?
    let status = SecTrustCopyPolicies(trust, &policies)
    guard status == errSecSuccess else {
        setStatus(statusOut, status)
        setError(errorOut, "SecTrustCopyPolicies failed: \(statusMessage(status))")
        return nil
    }

    return trustJSONArray(policies)
}

@_cdecl("security_trust_set_anchor_certificates")
public func securityTrustSetAnchorCertificates(
    _ trustPointer: UnsafeMutableRawPointer?,
    _ certificatePointers: UnsafePointer<UnsafeMutableRawPointer?>?,
    _ certificateCount: Int,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> Int32 {
    clearError(errorOut)

    guard let trust = unbox(trustPointer, as: SecTrust.self) else {
        setError(errorOut, "trust handle is required")
        return errSecParam
    }

    let certificates = handleArray(certificatePointers, count: certificateCount, as: SecCertificate.self)
    guard !certificates.isEmpty else {
        setError(errorOut, "at least one certificate is required")
        return errSecParam
    }

    let status = SecTrustSetAnchorCertificates(trust, certificates as CFArray)
    if status != errSecSuccess {
        setError(errorOut, "SecTrustSetAnchorCertificates failed: \(statusMessage(status))")
    }
    return status
}

@_cdecl("security_trust_copy_custom_anchor_certificates")
public func securityTrustCopyCustomAnchorCertificates(
    _ trustPointer: UnsafeMutableRawPointer?,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard let trust = unbox(trustPointer, as: SecTrust.self) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "trust handle is required")
        return nil
    }

    var anchors: CFArray?
    let status = SecTrustCopyCustomAnchorCertificates(trust, &anchors)
    guard status == errSecSuccess else {
        setStatus(statusOut, status)
        setError(errorOut, "SecTrustCopyCustomAnchorCertificates failed: \(statusMessage(status))")
        return nil
    }

    return trustJSONArray(anchors)
}

@_cdecl("security_trust_set_anchor_certificates_only")
public func securityTrustSetAnchorCertificatesOnly(
    _ trustPointer: UnsafeMutableRawPointer?,
    _ onlyAnchorCertificates: Bool,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> Int32 {
    clearError(errorOut)

    guard let trust = unbox(trustPointer, as: SecTrust.self) else {
        setError(errorOut, "trust handle is required")
        return errSecParam
    }

    let status = SecTrustSetAnchorCertificatesOnly(trust, onlyAnchorCertificates)
    if status != errSecSuccess {
        setError(errorOut, "SecTrustSetAnchorCertificatesOnly failed: \(statusMessage(status))")
    }
    return status
}

@_cdecl("security_trust_set_network_fetch_allowed")
public func securityTrustSetNetworkFetchAllowed(
    _ trustPointer: UnsafeMutableRawPointer?,
    _ allowed: Bool,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> Int32 {
    clearError(errorOut)

    guard let trust = unbox(trustPointer, as: SecTrust.self) else {
        setError(errorOut, "trust handle is required")
        return errSecParam
    }

    let status = SecTrustSetNetworkFetchAllowed(trust, allowed)
    if status != errSecSuccess {
        setError(errorOut, "SecTrustSetNetworkFetchAllowed failed: \(statusMessage(status))")
    }
    return status
}

@_cdecl("security_trust_get_network_fetch_allowed")
public func securityTrustGetNetworkFetchAllowed(
    _ trustPointer: UnsafeMutableRawPointer?,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> Bool {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard let trust = unbox(trustPointer, as: SecTrust.self) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "trust handle is required")
        return false
    }

    var allowed = DarwinBoolean(false)
    let status = SecTrustGetNetworkFetchAllowed(trust, &allowed)
    guard status == errSecSuccess else {
        setStatus(statusOut, status)
        setError(errorOut, "SecTrustGetNetworkFetchAllowed failed: \(statusMessage(status))")
        return false
    }
    return allowed.boolValue
}

@_cdecl("security_trust_set_verify_date")
public func securityTrustSetVerifyDate(
    _ trustPointer: UnsafeMutableRawPointer?,
    _ unixSeconds: Double,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> Int32 {
    clearError(errorOut)

    guard let trust = unbox(trustPointer, as: SecTrust.self) else {
        setError(errorOut, "trust handle is required")
        return errSecParam
    }

    let status = SecTrustSetVerifyDate(trust, Date(timeIntervalSince1970: unixSeconds) as CFDate)
    if status != errSecSuccess {
        setError(errorOut, "SecTrustSetVerifyDate failed: \(statusMessage(status))")
    }
    return status
}

@_cdecl("security_trust_get_verify_time")
public func securityTrustGetVerifyTime(
    _ trustPointer: UnsafeMutableRawPointer?,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard let trust = unbox(trustPointer, as: SecTrust.self) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "trust handle is required")
        return nil
    }

    let verifyTime = SecTrustGetVerifyTime(trust)
    guard verifyTime != 0 else {
        return nil
    }
    return jsonHandle(Date(timeIntervalSinceReferenceDate: verifyTime))
}

@_cdecl("security_trust_evaluate")
public func securityTrustEvaluate(
    _ trustPointer: UnsafeMutableRawPointer?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> Bool {
    clearError(errorOut)

    guard let trust = unbox(trustPointer, as: SecTrust.self) else {
        setError(errorOut, "trust handle is required")
        return false
    }

    var error: CFError?
    let trusted = SecTrustEvaluateWithError(trust, &error)
    if !trusted {
        setError(errorOut, trustErrorMessage(error))
    }
    return trusted
}

@_cdecl("security_trust_evaluate_async")
public func securityTrustEvaluateAsync(
    _ trustPointer: UnsafeMutableRawPointer?,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> Bool {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard let trust = unbox(trustPointer, as: SecTrust.self) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "trust handle is required")
        return false
    }

    let queue = DispatchQueue(label: "security-rs.trust.evaluate")
    let semaphore = DispatchSemaphore(value: 0)
    var callbackResult = false
    var callbackError: CFError?
    var status = errSecSuccess
    queue.sync {
        status = SecTrustEvaluateAsyncWithError(trust, queue) { _, trusted, error in
            callbackResult = trusted
            callbackError = error
            semaphore.signal()
        }
    }
    guard status == errSecSuccess else {
        setStatus(statusOut, status)
        setError(errorOut, "SecTrustEvaluateAsyncWithError failed: \(statusMessage(status))")
        return false
    }

    semaphore.wait()
    if !callbackResult {
        setError(errorOut, trustErrorMessage(callbackError))
    }
    return callbackResult
}

@_cdecl("security_trust_get_trust_result")
public func securityTrustGetTrustResult(
    _ trustPointer: UnsafeMutableRawPointer?,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UInt32 {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard let trust = unbox(trustPointer, as: SecTrust.self) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "trust handle is required")
        return 0
    }

    var result = SecTrustResultType.invalid
    let status = SecTrustGetTrustResult(trust, &result)
    guard status == errSecSuccess else {
        setStatus(statusOut, status)
        setError(errorOut, "SecTrustGetTrustResult failed: \(statusMessage(status))")
        return 0
    }
    return UInt32(result.rawValue)
}

@_cdecl("security_trust_copy_result")
public func securityTrustCopyResult(
    _ trustPointer: UnsafeMutableRawPointer?,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard let trust = unbox(trustPointer, as: SecTrust.self) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "trust handle is required")
        return nil
    }

    guard let result = SecTrustCopyResult(trust) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "SecTrustCopyResult returned nil")
        return nil
    }

    return jsonHandle(result)
}

@_cdecl("security_trust_copy_key")
public func securityTrustCopyKey(
    _ trustPointer: UnsafeMutableRawPointer?,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard let trust = unbox(trustPointer, as: SecTrust.self) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "trust handle is required")
        return nil
    }

    return retain(SecTrustCopyKey(trust))
}

@_cdecl("security_trust_get_certificate_count")
public func securityTrustGetCertificateCount(_ trustPointer: UnsafeMutableRawPointer?) -> Int {
    guard let trust = unbox(trustPointer, as: SecTrust.self) else {
        return 0
    }
    return SecTrustGetCertificateCount(trust)
}

@_cdecl("security_trust_copy_certificate_chain")
public func securityTrustCopyCertificateChain(
    _ trustPointer: UnsafeMutableRawPointer?,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard let trust = unbox(trustPointer, as: SecTrust.self) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "trust handle is required")
        return nil
    }

    let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate] ?? []
    return retain(chain)
}

@_cdecl("security_trust_copy_exceptions")
public func securityTrustCopyExceptions(
    _ trustPointer: UnsafeMutableRawPointer?,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard let trust = unbox(trustPointer, as: SecTrust.self) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "trust handle is required")
        return nil
    }

    return dataHandle(SecTrustCopyExceptions(trust) as Data?)
}

@_cdecl("security_trust_set_exceptions")
public func securityTrustSetExceptions(
    _ trustPointer: UnsafeMutableRawPointer?,
    _ dataPointer: UnsafeRawPointer?,
    _ dataLength: Int,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> Bool {
    clearError(errorOut)

    guard let trust = unbox(trustPointer, as: SecTrust.self) else {
        setError(errorOut, "trust handle is required")
        return false
    }

    let data = dataFromPointer(dataPointer, length: dataLength)
    return SecTrustSetExceptions(trust, data as CFData?)
}

@_cdecl("security_trust_set_ocsp_response")
public func securityTrustSetOCSPResponse(
    _ trustPointer: UnsafeMutableRawPointer?,
    _ responsesPointer: UnsafePointer<CChar>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> Int32 {
    clearError(errorOut)

    guard let trust = unbox(trustPointer, as: SecTrust.self) else {
        setError(errorOut, "trust handle is required")
        return errSecParam
    }

    let responseObject = jsonObject(fromCString: responsesPointer)
    let responseInput: CFTypeRef?
    if responsesPointer == nil {
        responseInput = nil
    } else if let responseData = jsonData(fromJSONObject: responseObject) {
        responseInput = responseData as CFData
    } else if let responseItems = responseObject as? [Any] {
        let responses = responseItems.compactMap(jsonData(fromJSONObject:))
        guard responses.count == responseItems.count else {
            setError(errorOut, "OCSP response JSON was invalid")
            return errSecParam
        }
        responseInput = responses as CFArray
    } else {
        setError(errorOut, "OCSP response JSON was invalid")
        return errSecParam
    }

    let status = SecTrustSetOCSPResponse(trust, responseInput)
    if status != errSecSuccess {
        setError(errorOut, "SecTrustSetOCSPResponse failed: \(statusMessage(status))")
    }
    return status
}

@_cdecl("security_trust_set_signed_certificate_timestamps")
public func securityTrustSetSignedCertificateTimestamps(
    _ trustPointer: UnsafeMutableRawPointer?,
    _ timestampsPointer: UnsafePointer<CChar>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> Int32 {
    clearError(errorOut)

    guard let trust = unbox(trustPointer, as: SecTrust.self) else {
        setError(errorOut, "trust handle is required")
        return errSecParam
    }
    guard timestampsPointer == nil || jsonDataArray(fromCString: timestampsPointer) != nil else {
        setError(errorOut, "signed certificate timestamp JSON was invalid")
        return errSecParam
    }

    let status = SecTrustSetSignedCertificateTimestamps(trust, jsonDataArray(fromCString: timestampsPointer) as CFArray?)
    if status != errSecSuccess {
        setError(errorOut, "SecTrustSetSignedCertificateTimestamps failed: \(statusMessage(status))")
    }
    return status
}

@_cdecl("security_trust_set_options")
public func securityTrustSetOptions(
    _ trustPointer: UnsafeMutableRawPointer?,
    _ options: UInt32,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> Int32 {
    clearError(errorOut)

    guard let trust = unbox(trustPointer, as: SecTrust.self) else {
        setError(errorOut, "trust handle is required")
        return errSecParam
    }

    let status = SecTrustSetOptions(trust, SecTrustOptionFlags(rawValue: options))
    if status != errSecSuccess {
        setError(errorOut, "SecTrustSetOptions failed: \(statusMessage(status))")
    }
    return status
}

@_cdecl("security_trust_copy_anchor_certificates")
public func securityTrustCopyAnchorCertificates(
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    var anchors: CFArray?
    let status = SecTrustCopyAnchorCertificates(&anchors)
    guard status == errSecSuccess else {
        setStatus(statusOut, status)
        setError(errorOut, "SecTrustCopyAnchorCertificates failed: \(statusMessage(status))")
        return nil
    }
    return trustJSONArray(anchors)
}
