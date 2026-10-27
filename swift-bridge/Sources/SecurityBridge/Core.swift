import Darwin
import Foundation
import Security
import SecurityBridgeABI

final class Box<T> {
    let value: T

    init(_ value: T) {
        self.value = value
    }
}

final class AuthorizationBox {
    let value: AuthorizationRef
    var freeFlags: AuthorizationFlags

    init(_ value: AuthorizationRef, freeFlags: AuthorizationFlags = AuthorizationFlags()) {
        self.value = value
        self.freeFlags = freeFlags
    }

    deinit {
        AuthorizationFree(value, freeFlags)
    }
}

final class SecretBox {
    let bytes: UnsafeMutableRawBufferPointer
    let count: Int

    init(copying data: CFData) {
        let length = CFDataGetLength(data)
        bytes = UnsafeMutableRawBufferPointer.allocate(byteCount: max(length, 1), alignment: 1)
        if length > 0, let source = CFDataGetBytePtr(data) {
            bytes.baseAddress?.copyMemory(from: source, byteCount: length)
        }
        count = max(length, 0)
    }

    deinit {
        if let baseAddress = bytes.baseAddress {
            _ = memset_s(baseAddress, bytes.count, 0, bytes.count)
        }
        bytes.deallocate()
    }
}

func retainSecret(_ data: CFData) -> UnsafeMutableRawPointer {
    Unmanaged.passRetained(SecretBox(copying: data)).toOpaque()
}

func retain<T>(_ value: T) -> UnsafeMutableRawPointer {
    Unmanaged.passRetained(Box(value)).toOpaque()
}

func retain<T>(_ value: T?) -> UnsafeMutableRawPointer? {
    guard let value else {
        return nil
    }

    return Unmanaged.passRetained(Box(value)).toOpaque()
}

func retainAuthorization(_ value: AuthorizationRef) -> UnsafeMutableRawPointer {
    Unmanaged.passRetained(AuthorizationBox(value)).toOpaque()
}

func unbox<T>(_ pointer: UnsafeMutableRawPointer?, as _: T.Type) -> T? {
    guard let pointer else {
        return nil
    }

    return (Unmanaged<AnyObject>.fromOpaque(pointer).takeUnretainedValue() as? Box<T>)?.value
}

func authorizationBox(_ pointer: UnsafeMutableRawPointer?) -> AuthorizationBox? {
    guard let pointer else {
        return nil
    }

    return Unmanaged<AnyObject>.fromOpaque(pointer).takeUnretainedValue() as? AuthorizationBox
}

func unboxAuthorization(_ pointer: UnsafeMutableRawPointer?) -> AuthorizationRef? {
    authorizationBox(pointer)?.value
}

func setStatus(_ statusOut: UnsafeMutablePointer<Int32>?, _ status: OSStatus) {
    statusOut?.pointee = status
}

func clearError(_ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?) {
    errorOut?.pointee = nil
}

func setError(_ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?, _ message: String) {
    errorOut?.pointee = retain(message)
}

func setError(_ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?, _ error: Error) {
    setError(errorOut, error.localizedDescription)
}

func setError(_ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?, _ error: Unmanaged<CFError>?) {
    if let error {
        let retained = error.takeRetainedValue()
        setError(errorOut, (retained as Error).localizedDescription)
    }
}

func statusMessage(_ status: OSStatus) -> String {
    if let message = SecCopyErrorMessageString(status, nil) as String? {
        return message
    }

    return "OSStatus \(status)"
}

func stringFromBuffer(_ pointer: UnsafePointer<SecurityBridgeBuffer>?) -> String? {
    guard let buffer = pointer?.pointee,
          let length = Int(exactly: buffer.length),
          length >= 0,
          length == 0 || buffer.data != nil
    else {
        return nil
    }

    return String(bytes: UnsafeBufferPointer(start: buffer.data, count: length), encoding: .utf8)
}

func dataFromPointer(_ bytes: UnsafeRawPointer?, length: Int) -> Data? {
    guard let bytes, length >= 0 else {
        return nil
    }

    return Data(bytes: bytes, count: length)
}

func valueData(from object: Any?) -> Data? {
    switch object {
    case let data as Data:
        return data
    case let values as [UInt8]:
        return Data(values)
    case let values as [NSNumber]:
        let bytes = values.compactMap { UInt8(exactly: $0) }
        return bytes.count == values.count ? Data(bytes) : nil
    default:
        return nil
    }
}

func handleArray<T>(_ pointer: UnsafePointer<UnsafeMutableRawPointer?>?, count: Int, as type: T.Type) -> [T] {
    guard let pointer, count > 0 else {
        return []
    }

    let buffer = UnsafeBufferPointer(start: pointer, count: count)
    return buffer.compactMap { unbox($0, as: type) }
}

func requirementString(_ requirement: SecRequirement) -> String {
    var requirementText: CFString?
    let status = SecRequirementCopyString(requirement, SecCSFlags(), &requirementText)
    guard status == errSecSuccess, let requirementText else {
        return statusMessage(status)
    }

    return requirementText as String
}

func securityObjectValue(_ object: AnyObject) -> Any? {
    switch CFGetTypeID(object) {
    case SecRequirementGetTypeID():
        return [
            "_type": "requirement",
            "value": requirementString(unsafeDowncast(object, to: SecRequirement.self)),
        ]
    case SecCertificateGetTypeID():
        let certificate = unsafeDowncast(object, to: SecCertificate.self)
        let summary = SecCertificateCopySubjectSummary(certificate) as String? ?? "certificate"
        return [
            "_type": "certificate",
            "subjectSummary": summary,
        ]
    case SecKeyGetTypeID():
        return [
            "_type": "key",
            "description": String(describing: object),
        ]
    case SecPolicyGetTypeID():
        if let properties = SecPolicyCopyProperties(unsafeDowncast(object, to: SecPolicy.self)) {
            return properties
        }
        return [
            "_type": "policy",
            "description": String(describing: object),
        ]
    case SecIdentityGetTypeID():
        var certificate: SecCertificate?
        if SecIdentityCopyCertificate(unsafeDowncast(object, to: SecIdentity.self), &certificate) == errSecSuccess,
           let certificate
        {
            let summary = SecCertificateCopySubjectSummary(certificate) as String? ?? "identity"
            return [
                "_type": "identity",
                "subjectSummary": summary,
            ]
        }
        return [
            "_type": "identity",
            "description": String(describing: object),
        ]
    default:
        return nil
    }
}

func stringHandle(_ value: String?) -> UnsafeMutableRawPointer? {
    guard let value else {
        return nil
    }

    return retain(value)
}

func dataHandle(_ value: Data?) -> UnsafeMutableRawPointer? {
    guard let value else {
        return nil
    }

    return retain(value)
}

@_cdecl("security_release_handle")
public func securityReleaseHandle(_ pointer: UnsafeMutableRawPointer?) {
    guard let pointer else {
        return
    }

    Unmanaged<AnyObject>.fromOpaque(pointer).release()
}

@_cdecl("security_string_len")
public func securityStringLen(_ pointer: UnsafeMutableRawPointer?) -> Int {
    unbox(pointer, as: String.self)?.lengthOfBytes(using: .utf8) ?? 0
}

@_cdecl("security_string_copy_utf8")
public func securityStringCopyUtf8(
    _ pointer: UnsafeMutableRawPointer?,
    _ buffer: UnsafeMutablePointer<CChar>?,
    _ capacity: Int
) -> Int {
    guard let string = unbox(pointer, as: String.self), let buffer, capacity > 0 else {
        return 0
    }

    let bytes = Array(string.utf8)
    let count = min(bytes.count, capacity - 1)
    memset(buffer, 0, capacity)
    for index in 0 ..< count {
        buffer[index] = CChar(bitPattern: bytes[index])
    }

    return count
}

@_cdecl("security_secret_len")
public func securitySecretLen(_ pointer: UnsafeMutableRawPointer?) -> Int {
    guard let pointer,
          let secret = Unmanaged<AnyObject>.fromOpaque(pointer).takeUnretainedValue() as? SecretBox
    else {
        return -1
    }
    return secret.count
}

@_cdecl("security_secret_copy_bytes")
public func securitySecretCopyBytes(
    _ pointer: UnsafeMutableRawPointer?,
    _ buffer: UnsafeMutableRawPointer?,
    _ capacity: Int
) -> Int {
    guard let pointer,
          let secret = Unmanaged<AnyObject>.fromOpaque(pointer).takeUnretainedValue() as? SecretBox,
          let buffer,
          capacity >= secret.count
    else {
        return -1
    }
    if secret.count > 0, let source = secret.bytes.baseAddress {
        buffer.copyMemory(from: source, byteCount: secret.count)
    }
    return secret.count
}

@_cdecl("security_data_len")
public func securityDataLen(_ pointer: UnsafeMutableRawPointer?) -> Int {
    unbox(pointer, as: Data.self)?.count ?? 0
}

@_cdecl("security_data_copy_bytes")
public func securityDataCopyBytes(
    _ pointer: UnsafeMutableRawPointer?,
    _ buffer: UnsafeMutableRawPointer?,
    _ capacity: Int
) -> Int {
    guard let data = unbox(pointer, as: Data.self), let buffer, capacity > 0 else {
        return 0
    }

    let count = min(data.count, capacity)
    data.copyBytes(to: buffer.assumingMemoryBound(to: UInt8.self), count: count)
    return count
}

@_cdecl("security_key_copy_attributes")
public func securityKeyCopyAttributes(
    _ keyPointer: UnsafeMutableRawPointer?,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard let key = unbox(keyPointer, as: SecKey.self) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "key handle is required")
        return nil
    }

    guard let attributes = SecKeyCopyAttributes(key) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "SecKeyCopyAttributes returned nil")
        return nil
    }

    return valueHandle(attributes)
}
