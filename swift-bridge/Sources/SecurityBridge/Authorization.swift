import Foundation
import Security

@_cdecl("security_authorization_create")
public func securityAuthorizationCreate(
    _ flags: UInt32,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errAuthorizationSuccess)

    var authorization: AuthorizationRef?
    let status = AuthorizationCreate(nil, nil, AuthorizationFlags(rawValue: flags), &authorization)
    guard status == errAuthorizationSuccess, let authorization else {
        setStatus(statusOut, status)
        setError(errorOut, "AuthorizationCreate failed: \(statusMessage(status))")
        return nil
    }

    return retainAuthorization(authorization)
}

@_cdecl("security_authorization_make_external_form")
public func securityAuthorizationMakeExternalForm(
    _ authorizationPointer: UnsafeMutableRawPointer?,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errAuthorizationSuccess)

    guard let authorization = unboxAuthorization(authorizationPointer) else {
        setStatus(statusOut, errAuthorizationInvalidRef)
        setError(errorOut, "authorization handle is required")
        return nil
    }

    var externalForm = AuthorizationExternalForm()
    let status = AuthorizationMakeExternalForm(authorization, &externalForm)
    guard status == errAuthorizationSuccess else {
        setStatus(statusOut, status)
        setError(errorOut, "AuthorizationMakeExternalForm failed: \(statusMessage(status))")
        return nil
    }

    let data = withUnsafeBytes(of: externalForm) { Data($0) }
    return dataHandle(data)
}

@_cdecl("security_authorization_create_from_external_form")
public func securityAuthorizationCreateFromExternalForm(
    _ dataPointer: UnsafeRawPointer?,
    _ dataLength: Int,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errAuthorizationSuccess)

    guard let data = dataFromPointer(dataPointer, length: dataLength),
          data.count == MemoryLayout<AuthorizationExternalForm>.size
    else {
        setStatus(statusOut, errAuthorizationInvalidPointer)
        setError(errorOut, "authorization external form must be \(MemoryLayout<AuthorizationExternalForm>.size) bytes")
        return nil
    }

    var externalForm = AuthorizationExternalForm()
    _ = withUnsafeMutableBytes(of: &externalForm) { destination in
        data.copyBytes(to: destination)
    }

    var authorization: AuthorizationRef?
    let status = AuthorizationCreateFromExternalForm(&externalForm, &authorization)
    guard status == errAuthorizationSuccess, let authorization else {
        setStatus(statusOut, status)
        setError(errorOut, "AuthorizationCreateFromExternalForm failed: \(statusMessage(status))")
        return nil
    }

    return retainAuthorization(authorization)
}
