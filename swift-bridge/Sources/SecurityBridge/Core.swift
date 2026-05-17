import Darwin
import Foundation
import Security

final class Box<T> {
    let value: T

    init(_ value: T) {
        self.value = value
    }
}

final class AuthorizationBox {
    let value: AuthorizationRef
    let freeFlags: AuthorizationFlags

    init(_ value: AuthorizationRef, freeFlags: AuthorizationFlags = AuthorizationFlags()) {
        self.value = value
        self.freeFlags = freeFlags
    }

    deinit {
        AuthorizationFree(value, freeFlags)
    }
}

func retain<T>(_ value: T) -> UnsafeMutableRawPointer {
    Unmanaged.passRetained(Box(value)).toOpaque()
}

func retainAuthorization(_ value: AuthorizationRef) -> UnsafeMutableRawPointer {
    Unmanaged.passRetained(AuthorizationBox(value)).toOpaque()
}

func unbox<T>(_ pointer: UnsafeMutableRawPointer?, as _: T.Type) -> T? {
    guard let pointer else {
        return nil
    }

    return Unmanaged<Box<T>>.fromOpaque(pointer).takeUnretainedValue().value
}

func unboxAuthorization(_ pointer: UnsafeMutableRawPointer?) -> AuthorizationRef? {
    guard let pointer else {
        return nil
    }

    return Unmanaged<AuthorizationBox>.fromOpaque(pointer).takeUnretainedValue().value
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

func stringFromCString(_ pointer: UnsafePointer<CChar>?) -> String? {
    guard let pointer else {
        return nil
    }

    return String(cString: pointer)
}

func dataFromPointer(_ bytes: UnsafeRawPointer?, length: Int) -> Data? {
    guard let bytes, length >= 0 else {
        return nil
    }

    return Data(bytes: bytes, count: length)
}

func jsonObject(fromCString pointer: UnsafePointer<CChar>?) -> Any? {
    guard let json = stringFromCString(pointer),
          let data = json.data(using: .utf8)
    else {
        return nil
    }

    return try? JSONSerialization.jsonObject(with: data)
}

func jsonStringArray(fromCString pointer: UnsafePointer<CChar>?) -> [String]? {
    jsonObject(fromCString: pointer) as? [String]
}

func jsonData(fromJSONObject object: Any?) -> Data? {
    switch object {
    case let data as Data:
        return data
    case let values as [UInt8]:
        return Data(values)
    case let values as [NSNumber]:
        return Data(values.map(\.uint8Value))
    case let base64 as String:
        return Data(base64Encoded: base64)
    default:
        return nil
    }
}

func jsonDataArray(fromCString pointer: UnsafePointer<CChar>?) -> [Data]? {
    guard let values = jsonObject(fromCString: pointer) as? [Any] else {
        return nil
    }
    return values.compactMap(jsonData(fromJSONObject:))
}

func keyUsageArray(fromCString pointer: UnsafePointer<CChar>?) -> [CFString]? {
    guard let keyUsageNames = jsonStringArray(fromCString: pointer) else {
        return nil
    }

    let usages = keyUsageNames.compactMap { keyUsageName -> CFString? in
        switch keyUsageName {
        case "can_encrypt":
            return kSecAttrCanEncrypt
        case "can_decrypt":
            return kSecAttrCanDecrypt
        case "can_derive":
            return kSecAttrCanDerive
        case "can_sign":
            return kSecAttrCanSign
        case "can_verify":
            return kSecAttrCanVerify
        case "can_wrap":
            return kSecAttrCanWrap
        case "can_unwrap":
            return kSecAttrCanUnwrap
        default:
            return nil
        }
    }
    return usages.count == keyUsageNames.count ? usages : nil
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

func jsonValue(_ value: Any) -> Any {
    switch value {
    case is NSNull:
        return NSNull()
    case let value as String:
        return value
    case let value as NSString:
        return value as String
    case let value as NSNumber:
        if CFGetTypeID(value) == CFBooleanGetTypeID() {
            return value.boolValue
        }
        let doubleValue = value.doubleValue
        let intValue = value.int64Value
        if Double(intValue) == doubleValue {
            return intValue
        }
        return doubleValue
    case let value as Data:
        return [
            "_type": "data",
            "base64": value.base64EncodedString(),
        ]
    case let value as Date:
        return [
            "_type": "date",
            "unix": value.timeIntervalSince1970,
        ]
    case let value as URL:
        return [
            "_type": "url",
            "value": value.absoluteString,
        ]
    case let value as [Any]:
        return value.map(jsonValue)
    case let value as NSDictionary:
        var result: [String: Any] = [:]
        for case let (key as AnyHashable, item) in value {
            result[String(describing: key)] = jsonValue(item)
        }
        return result
    case let value as SecRequirement:
        return [
            "_type": "requirement",
            "value": requirementString(value),
        ]
    case let value as SecCertificate:
        let summary = SecCertificateCopySubjectSummary(value) as String? ?? "certificate"
        return [
            "_type": "certificate",
            "subjectSummary": summary,
        ]
    case let value as SecKey:
        return [
            "_type": "key",
            "description": String(describing: value),
        ]
    case let value as SecPolicy:
        if let properties = SecPolicyCopyProperties(value) {
            return jsonValue(properties)
        }
        return [
            "_type": "policy",
            "description": String(describing: value),
        ]
    case let value as SecIdentity:
        var certificate: SecCertificate?
        if SecIdentityCopyCertificate(value, &certificate) == errSecSuccess,
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
            "description": String(describing: value),
        ]
    default:
        return String(describing: value)
    }
}

func jsonHandle(_ value: Any) -> UnsafeMutableRawPointer? {
    let json = jsonValue(value)
    guard JSONSerialization.isValidJSONObject(json),
          let data = try? JSONSerialization.data(withJSONObject: json, options: [.sortedKeys]),
          let string = String(data: data, encoding: .utf8)
    else {
        return nil
    }

    return retain(string)
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

    return jsonHandle(attributes)
}
