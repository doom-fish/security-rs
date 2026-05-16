import Foundation
import Security

@_cdecl("security_policy_create_basic_x509")
public func securityPolicyCreateBasicX509(
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)
    return retain(SecPolicyCreateBasicX509())
}

@_cdecl("security_policy_create_ssl")
public func securityPolicyCreateSSL(
    _ server: Bool,
    _ hostnamePointer: UnsafePointer<CChar>?,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)
    let hostname = stringFromCString(hostnamePointer) as CFString?
    return retain(SecPolicyCreateSSL(server, hostname))
}

@_cdecl("security_policy_create_revocation")
public func securityPolicyCreateRevocation(
    _ flags: UInt32,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)
    return retain(SecPolicyCreateRevocation(CFOptionFlags(flags)))
}

@_cdecl("security_policy_copy_properties")
public func securityPolicyCopyProperties(
    _ policyPointer: UnsafeMutableRawPointer?,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard let policy = unbox(policyPointer, as: SecPolicy.self) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "policy handle is required")
        return nil
    }

    guard let properties = SecPolicyCopyProperties(policy) else {
        return jsonHandle([:])
    }

    return jsonHandle(properties)
}
