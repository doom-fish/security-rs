import CoreFoundation
import Foundation
import Security

private final class SecureTransportRecord {
    let context: SSLContext
    let side: String
    var minProtocol: String?
    var maxProtocol: String?

    init(context: SSLContext, side: String) {
        self.context = context
        self.side = side
    }

}

private func protocolName(_ value: SSLProtocol) -> String {
    switch value {
    case .sslProtocol2:
        return "ssl2"
    case .sslProtocol3:
        return "ssl3"
    case .tlsProtocol1:
        return "tls1.0"
    case .tlsProtocol11:
        return "tls1.1"
    case .tlsProtocol12:
        return "tls1.2"
    case .dtlsProtocol1:
        return "dtls1.0"
    case .tlsProtocol13:
        return "tls1.3"
    default:
        return "unknown"
    }
}

private func protocolFromName(_ name: String) -> SSLProtocol? {
    switch name.lowercased() {
    case "ssl2":
        return .sslProtocol2
    case "ssl3":
        return .sslProtocol3
    case "tls1", "tls1.0", "tls10":
        return .tlsProtocol1
    case "tls1.1", "tls11":
        return .tlsProtocol11
    case "tls1.2", "tls12":
        return .tlsProtocol12
    case "dtls1", "dtls1.0":
        return .dtlsProtocol1
    case "tls1.3", "tls13":
        return .tlsProtocol13
    default:
        return nil
    }
}

private func sessionStateName(_ state: SSLSessionState) -> String {
    switch state {
    case .idle:
        return "idle"
    case .handshake:
        return "handshake"
    case .connected:
        return "connected"
    case .closed:
        return "closed"
    case .aborted:
        return "aborted"
    @unknown default:
        return "unknown"
    }
}

private func createContext(
    side: SSLProtocolSide,
    label: String,
    statusOut: UnsafeMutablePointer<Int32>?,
    errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard let context = SSLCreateContext(nil, side, .streamType) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "SSLCreateContext returned nil")
        return nil
    }

    return retain(SecureTransportRecord(context: context, side: label))
}

@_cdecl("security_secure_transport_create_client")
public func securitySecureTransportCreateClient(
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    createContext(side: .clientSide, label: "client", statusOut: statusOut, errorOut: errorOut)
}

@_cdecl("security_secure_transport_create_server")
public func securitySecureTransportCreateServer(
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    createContext(side: .serverSide, label: "server", statusOut: statusOut, errorOut: errorOut)
}

@_cdecl("security_secure_transport_set_protocol_min")
public func securitySecureTransportSetProtocolMin(
    _ recordPointer: UnsafeMutableRawPointer?,
    _ protocolPointer: UnsafePointer<CChar>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> Int32 {
    clearError(errorOut)

    guard let record = unbox(recordPointer, as: SecureTransportRecord.self),
          let name = stringFromCString(protocolPointer),
          let value = protocolFromName(name)
    else {
        setError(errorOut, "valid secure transport handle and protocol name are required")
        return errSecParam
    }

    let status = SSLSetProtocolVersionMin(record.context, value)
    if status == errSecSuccess {
        record.minProtocol = protocolName(value)
    } else {
        setError(errorOut, "SSLSetProtocolVersionMin failed: \(statusMessage(status))")
    }
    return status
}

@_cdecl("security_secure_transport_set_protocol_max")
public func securitySecureTransportSetProtocolMax(
    _ recordPointer: UnsafeMutableRawPointer?,
    _ protocolPointer: UnsafePointer<CChar>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> Int32 {
    clearError(errorOut)

    guard let record = unbox(recordPointer, as: SecureTransportRecord.self),
          let name = stringFromCString(protocolPointer),
          let value = protocolFromName(name)
    else {
        setError(errorOut, "valid secure transport handle and protocol name are required")
        return errSecParam
    }

    let status = SSLSetProtocolVersionMax(record.context, value)
    if status == errSecSuccess {
        record.maxProtocol = protocolName(value)
    } else {
        setError(errorOut, "SSLSetProtocolVersionMax failed: \(statusMessage(status))")
    }
    return status
}

@_cdecl("security_secure_transport_copy_state")
public func securitySecureTransportCopyState(
    _ recordPointer: UnsafeMutableRawPointer?,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard let record = unbox(recordPointer, as: SecureTransportRecord.self) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "secure transport handle is required")
        return nil
    }

    var sessionState = SSLSessionState.idle
    let status = SSLGetSessionState(record.context, &sessionState)
    guard status == errSecSuccess else {
        setStatus(statusOut, status)
        setError(errorOut, "SSLGetSessionState failed: \(statusMessage(status))")
        return nil
    }

    return jsonHandle([
        "side": record.side,
        "sessionState": sessionStateName(sessionState),
        "minimumProtocol": record.minProtocol ?? "default",
        "maximumProtocol": record.maxProtocol ?? "default",
    ])
}
