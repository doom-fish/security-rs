import Foundation
import Security

private func trustErrorMessage(_ error: CFError?) -> String {
    guard let error else {
        return "trust evaluation failed"
    }

    return (error as Error).localizedDescription
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
