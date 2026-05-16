import Foundation
import Security

private func policyIdentifier(_ name: String) -> CFTypeRef? {
    switch name {
    case "apple_x509_basic":
        return kSecPolicyAppleX509Basic
    case "apple_ssl":
        return kSecPolicyAppleSSL
    case "apple_smime":
        return kSecPolicyAppleSMIME
    case "apple_eap":
        return kSecPolicyAppleEAP
    case "apple_ipsec":
        return kSecPolicyAppleIPsec
    case "apple_pkinit_client":
        return kSecPolicyApplePKINITClient
    case "apple_pkinit_server":
        return kSecPolicyApplePKINITServer
    case "apple_code_signing":
        return kSecPolicyAppleCodeSigning
    case "mac_app_store_receipt":
        return kSecPolicyMacAppStoreReceipt
    case "apple_id_validation":
        return kSecPolicyAppleIDValidation
    case "apple_time_stamping":
        return kSecPolicyAppleTimeStamping
    case "apple_revocation":
        return kSecPolicyAppleRevocation
    case "apple_passbook_signing":
        return kSecPolicyApplePassbookSigning
    case "apple_pay_issuer_encryption":
        return kSecPolicyApplePayIssuerEncryption
    case "apple_ssl_server":
        if #available(macOS 15.4, *) {
            return kSecPolicyAppleSSLServer
        }
        return nil
    case "apple_ssl_client":
        if #available(macOS 15.4, *) {
            return kSecPolicyAppleSSLClient
        }
        return nil
    case "apple_eap_server":
        if #available(macOS 15.4, *) {
            return kSecPolicyAppleEAPServer
        }
        return nil
    case "apple_eap_client":
        if #available(macOS 15.4, *) {
            return kSecPolicyAppleEAPClient
        }
        return nil
    case "apple_ipsec_server":
        if #available(macOS 15.4, *) {
            return kSecPolicyAppleIPSecServer
        }
        return nil
    case "apple_ipsec_client":
        if #available(macOS 15.4, *) {
            return kSecPolicyAppleIPSecClient
        }
        return nil
    default:
        return nil
    }
}

private func policyProperties(jsonString: String) -> [CFString: Any]? {
    guard let data = jsonString.data(using: .utf8),
          let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
    else {
        return nil
    }

    var properties: [CFString: Any] = [:]
    if let name = object["name"] {
        if let name = name as? String {
            properties[kSecPolicyName] = name
        } else if let names = name as? [String] {
            properties[kSecPolicyName] = names
        } else {
            return nil
        }
    }
    if let client = object["client"] as? Bool {
        properties[kSecPolicyClient] = client
    }
    if let revocationFlags = object["revocation_flags"] as? NSNumber {
        properties[kSecPolicyRevocationFlags] = revocationFlags
    }
    if let teamIdentifier = object["team_identifier"] as? String {
        properties[kSecPolicyTeamIdentifier] = teamIdentifier
    }
    return properties
}

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

@_cdecl("security_policy_create_with_properties")
public func securityPolicyCreateWithProperties(
    _ identifierPointer: UnsafePointer<CChar>?,
    _ propertiesPointer: UnsafePointer<CChar>?,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard let identifierName = stringFromCString(identifierPointer),
          let identifier = policyIdentifier(identifierName)
    else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "policy identifier is required")
        return nil
    }

    let properties: [CFString: Any]?
    if let propertiesString = stringFromCString(propertiesPointer) {
        guard let decodedProperties = policyProperties(jsonString: propertiesString) else {
            setStatus(statusOut, errSecParam)
            setError(errorOut, "policy properties JSON was invalid")
            return nil
        }
        properties = decodedProperties
    } else {
        properties = nil
    }

    guard let policy = SecPolicyCreateWithProperties(identifier, properties as CFDictionary?) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "SecPolicyCreateWithProperties returned nil")
        return nil
    }

    return retain(policy)
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
