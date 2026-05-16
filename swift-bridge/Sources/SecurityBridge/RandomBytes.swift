import Foundation
import Security

@_cdecl("security_random_fill")
public func securityRandomFill(
    _ buffer: UnsafeMutableRawPointer?,
    _ length: Int,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> Int32 {
    clearError(errorOut)

    guard let buffer, length >= 0 else {
        setError(errorOut, "buffer and length are required")
        return errSecParam
    }

    let status = SecRandomCopyBytes(kSecRandomDefault, length, buffer)
    if status != errSecSuccess {
        setError(errorOut, "SecRandomCopyBytes failed: \(statusMessage(status))")
    }
    return status
}
