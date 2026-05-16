import Foundation
import Security

private func executeTransform(
    _ transform: SecTransform,
    input: Data,
    statusOut: UnsafeMutablePointer<Int32>?,
    errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    var error: Unmanaged<CFError>?
    guard SecTransformSetAttribute(transform, kSecTransformInputAttributeName, input as CFData, &error) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, error)
        return nil
    }

    let result = SecTransformExecute(transform, &error)
    if let error {
        setStatus(statusOut, errSecParam)
        setError(errorOut, error)
        return nil
    }

    if let data = result as? Data {
        return dataHandle(data)
    }
    if let string = result as? String {
        return dataHandle(Data(string.utf8))
    }

    setStatus(statusOut, errSecParam)
    setError(errorOut, "SecTransformExecute returned unsupported result type")
    return nil
}

@_cdecl("security_transform_encode_base64")
public func securityTransformEncodeBase64(
    _ dataPointer: UnsafeRawPointer?,
    _ dataLength: Int,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard let input = dataFromPointer(dataPointer, length: dataLength) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "input bytes are required")
        return nil
    }

    var error: Unmanaged<CFError>?
    guard let transform = SecEncodeTransformCreate(kSecBase64Encoding, &error) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, error)
        return nil
    }

    return executeTransform(transform, input: input, statusOut: statusOut, errorOut: errorOut)
}

@_cdecl("security_transform_decode_base64")
public func securityTransformDecodeBase64(
    _ dataPointer: UnsafeRawPointer?,
    _ dataLength: Int,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard let input = dataFromPointer(dataPointer, length: dataLength) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "input bytes are required")
        return nil
    }

    var error: Unmanaged<CFError>?
    guard let transform = SecDecodeTransformCreate(kSecBase64Encoding, &error) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, error)
        return nil
    }

    return executeTransform(transform, input: input, statusOut: statusOut, errorOut: errorOut)
}
