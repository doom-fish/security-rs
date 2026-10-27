import Foundation
import Security
import SecurityBridgeABI

private func internetPasswordQuery(server: String) -> [CFString: Any] {
    [
        kSecClass: kSecClassInternetPassword,
        kSecAttrServer: server,
    ]
}

@_cdecl("security_internet_password_set_item")
public func securityInternetPasswordSetItem(
    _ serverPointer: UnsafePointer<SecurityBridgeBuffer>?,
    _ accountPointer: UnsafePointer<SecurityBridgeBuffer>?,
    _ dataPointer: UnsafeRawPointer?,
    _ dataLength: Int,
    _ failedOperationOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> Int32 {
    clearError(errorOut)
    failedOperationOut?.pointee = 0

    guard let server = stringFromBuffer(serverPointer),
          let account = stringFromBuffer(accountPointer),
          dataLength >= 0,
          dataPointer != nil || dataLength == 0,
          let secret = NSMutableData(length: dataLength)
    else {
        setError(errorOut, "server, account and secret data are required")
        return errSecParam
    }
    if let dataPointer, dataLength > 0 {
        secret.replaceBytes(in: NSRange(location: 0, length: dataLength), withBytes: dataPointer)
    }
    defer {
        if secret.length > 0 {
            _ = memset_s(secret.mutableBytes, secret.length, 0, secret.length)
        }
    }

    let query = internetPasswordQuery(server: server)
    let attributes: [CFString: Any] = [
        kSecAttrAccount: account,
        kSecValueData: secret,
    ]
    failedOperationOut?.pointee = 1
    let updateStatus = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
    if updateStatus == errSecSuccess {
        return errSecSuccess
    }
    if updateStatus != errSecItemNotFound {
        setError(errorOut, "SecItemUpdate failed: \(statusMessage(updateStatus))")
        return updateStatus
    }

    failedOperationOut?.pointee = 2
    let addQuery = query.merging(attributes) { $1 }
    let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
    if addStatus != errSecSuccess {
        setError(errorOut, "SecItemAdd failed: \(statusMessage(addStatus))")
    }
    return addStatus
}

@_cdecl("security_internet_password_copy_item")
public func securityInternetPasswordCopyItem(
    _ serverPointer: UnsafePointer<SecurityBridgeBuffer>?,
    _ accountOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    accountOut?.pointee = nil
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard let server = stringFromBuffer(serverPointer) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "server is required")
        return nil
    }

    var query = internetPasswordQuery(server: server)
    query[kSecReturnAttributes] = true
    query[kSecReturnData] = true

    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    guard status == errSecSuccess else {
        setStatus(statusOut, status)
        if status != errSecItemNotFound && status != errSecUserCanceled {
            setError(errorOut, "SecItemCopyMatching failed: \(statusMessage(status))")
        }
        return nil
    }

    guard let result,
          CFGetTypeID(result) == CFDictionaryGetTypeID(),
          let dictionary = result as? [String: Any],
          let account = dictionary[kSecAttrAccount as String] as? String,
          let secret = dictionary[kSecValueData as String] as? Data
    else {
        return nil
    }

    accountOut?.pointee = retain(account)
    return retainSecret(secret as CFData)
}

@_cdecl("security_internet_password_delete_item")
public func securityInternetPasswordDeleteItem(
    _ serverPointer: UnsafePointer<SecurityBridgeBuffer>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> Int32 {
    clearError(errorOut)

    guard let server = stringFromBuffer(serverPointer) else {
        setError(errorOut, "server is required")
        return errSecParam
    }

    let status = SecItemDelete(internetPasswordQuery(server: server) as CFDictionary)
    if status != errSecSuccess {
        setError(errorOut, "SecItemDelete failed: \(statusMessage(status))")
    }
    return status
}
