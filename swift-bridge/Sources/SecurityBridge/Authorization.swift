import Dispatch
import Foundation
import Security

private func authorizationItemSetJSON(_ itemSet: UnsafePointer<AuthorizationItemSet>?) -> [[String: Any]] {
    guard let itemSet else {
        return []
    }

    let items = UnsafeBufferPointer(start: itemSet.pointee.items, count: Int(itemSet.pointee.count))
    return items.map { item in
        var json: [String: Any] = [
            "flags": UInt32(item.flags),
            "name": String(cString: item.name),
        ]
        if let value = item.value, item.valueLength > 0 {
            json["value"] = Data(bytes: value, count: Int(item.valueLength))
        }
        return json
    }
}

private func releaseAuthorizationItemSet(_ itemSet: UnsafeMutablePointer<AuthorizationItemSet>?) {
    if let itemSet {
        _ = AuthorizationFreeItemSet(itemSet)
    }
}

private func withAuthorizationRights<T>(
    _ rights: [String],
    _ body: (UnsafePointer<AuthorizationRights>) -> T
) -> T {
    precondition(!rights.isEmpty)

    let names = rights.map { strdup($0)! }
    defer {
        for name in names {
            free(name)
        }
    }

    var items = names.map {
        AuthorizationItem(name: UnsafePointer($0), valueLength: 0, value: nil, flags: 0)
    }
    return items.withUnsafeMutableBufferPointer { buffer in
        var authorizationRights = AuthorizationRights(count: UInt32(buffer.count), items: buffer.baseAddress)
        return withUnsafePointer(to: &authorizationRights, body)
    }
}

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

@_cdecl("security_authorization_copy_info")
public func securityAuthorizationCopyInfo(
    _ authorizationPointer: UnsafeMutableRawPointer?,
    _ tagPointer: UnsafePointer<CChar>?,
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

    var info: UnsafeMutablePointer<AuthorizationItemSet>?
    let status = AuthorizationCopyInfo(authorization, tagPointer, &info)
    guard status == errAuthorizationSuccess else {
        setStatus(statusOut, status)
        setError(errorOut, "AuthorizationCopyInfo failed: \(statusMessage(status))")
        return nil
    }

    defer { releaseAuthorizationItemSet(info) }
    return jsonHandle(authorizationItemSetJSON(UnsafePointer(info)))
}

@_cdecl("security_authorization_copy_rights")
public func securityAuthorizationCopyRights(
    _ authorizationPointer: UnsafeMutableRawPointer?,
    _ rightsPointer: UnsafePointer<CChar>?,
    _ flags: UInt32,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errAuthorizationSuccess)

    guard let authorization = unboxAuthorization(authorizationPointer),
          let rightNames = jsonStringArray(fromCString: rightsPointer),
          !rightNames.isEmpty
    else {
        setStatus(statusOut, errAuthorizationInvalidSet)
        setError(errorOut, "authorization rights are required")
        return nil
    }

    var authorizedRights: UnsafeMutablePointer<AuthorizationRights>?
    let status = withAuthorizationRights(rightNames) { rights in
        AuthorizationCopyRights(authorization, rights, nil, AuthorizationFlags(rawValue: flags), &authorizedRights)
    }
    guard status == errAuthorizationSuccess else {
        setStatus(statusOut, status)
        setError(errorOut, "AuthorizationCopyRights failed: \(statusMessage(status))")
        return nil
    }

    defer { releaseAuthorizationItemSet(UnsafeMutablePointer(authorizedRights)) }
    return jsonHandle(authorizationItemSetJSON(UnsafePointer(authorizedRights)))
}

@_cdecl("security_authorization_copy_rights_async")
public func securityAuthorizationCopyRightsAsync(
    _ authorizationPointer: UnsafeMutableRawPointer?,
    _ rightsPointer: UnsafePointer<CChar>?,
    _ flags: UInt32,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errAuthorizationSuccess)

    guard let authorization = unboxAuthorization(authorizationPointer),
          let rightNames = jsonStringArray(fromCString: rightsPointer),
          !rightNames.isEmpty
    else {
        setStatus(statusOut, errAuthorizationInvalidSet)
        setError(errorOut, "authorization rights are required")
        return nil
    }

    let semaphore = DispatchSemaphore(value: 0)
    var callbackStatus = errAuthorizationSuccess
    var authorizedRights: UnsafeMutablePointer<AuthorizationRights>?
    withAuthorizationRights(rightNames) { rights in
        AuthorizationCopyRightsAsync(
            authorization,
            rights,
            nil,
            AuthorizationFlags(rawValue: flags)
        ) { status, callbackAuthorizedRights in
            callbackStatus = status
            authorizedRights = callbackAuthorizedRights
            semaphore.signal()
        }
    }
    semaphore.wait()

    guard callbackStatus == errAuthorizationSuccess else {
        setStatus(statusOut, callbackStatus)
        setError(errorOut, "AuthorizationCopyRightsAsync failed: \(statusMessage(callbackStatus))")
        return nil
    }

    defer { releaseAuthorizationItemSet(UnsafeMutablePointer(authorizedRights)) }
    return jsonHandle(authorizationItemSetJSON(UnsafePointer(authorizedRights)))
}
