import Foundation
import Security

private func genericPasswordQuery(account: String?, service: String) -> [CFString: Any] {
    var query: [CFString: Any] = [
        kSecClass: kSecClassGenericPassword,
        kSecAttrService: service,
    ]

    if let account {
        query[kSecAttrAccount] = account
    }

    return query
}

private func accessControlProtection(_ name: String) -> CFTypeRef? {
    switch name {
    case "when_unlocked":
        return kSecAttrAccessibleWhenUnlocked
    case "after_first_unlock":
        return kSecAttrAccessibleAfterFirstUnlock
    case "when_passcode_set_this_device_only":
        return kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
    case "when_unlocked_this_device_only":
        return kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    case "after_first_unlock_this_device_only":
        return kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    default:
        return nil
    }
}

@_cdecl("security_access_control_create")
public func securityAccessControlCreate(
    _ protectionPointer: UnsafePointer<CChar>?,
    _ flags: UInt64,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard let protectionName = stringFromCString(protectionPointer),
          let protection = accessControlProtection(protectionName)
    else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "access-control protection is required")
        return nil
    }

    var error: Unmanaged<CFError>?
    guard let accessControl = SecAccessControlCreateWithFlags(
        nil,
        protection,
        SecAccessControlCreateFlags(rawValue: CFOptionFlags(flags)),
        &error
    ) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, error)
        return nil
    }

    return retain(accessControl)
}

@_cdecl("security_keychain_set_password")
public func securityKeychainSetPassword(
    _ accountPointer: UnsafePointer<CChar>?,
    _ servicePointer: UnsafePointer<CChar>?,
    _ passwordPointer: UnsafePointer<CChar>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> Int32 {
    clearError(errorOut)

    guard let account = stringFromCString(accountPointer),
          let service = stringFromCString(servicePointer),
          let password = stringFromCString(passwordPointer)
    else {
        setError(errorOut, "account, service, and password are required")
        return errSecParam
    }

    let searchQuery = genericPasswordQuery(account: account, service: service)
    var addQuery = searchQuery
    addQuery[kSecValueData] = Data(password.utf8)

    let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
    if addStatus == errSecSuccess {
        return errSecSuccess
    }

    if addStatus != errSecDuplicateItem {
        setError(errorOut, "SecItemAdd failed: \(statusMessage(addStatus))")
        return addStatus
    }

    let updateStatus = SecItemUpdate(
        searchQuery as CFDictionary,
        [kSecValueData: Data(password.utf8)] as CFDictionary
    )
    if updateStatus != errSecSuccess {
        setError(errorOut, "SecItemUpdate failed: \(statusMessage(updateStatus))")
    }

    return updateStatus
}

@_cdecl("security_keychain_get_password")
public func securityKeychainGetPassword(
    _ accountPointer: UnsafePointer<CChar>?,
    _ servicePointer: UnsafePointer<CChar>?,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard let account = stringFromCString(accountPointer),
          let service = stringFromCString(servicePointer)
    else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "account and service are required")
        return nil
    }

    var query = genericPasswordQuery(account: account, service: service)
    query[kSecReturnData] = true
    query[kSecMatchLimit] = kSecMatchLimitOne

    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    guard status == errSecSuccess else {
        setStatus(statusOut, status)
        setError(errorOut, "SecItemCopyMatching failed: \(statusMessage(status))")
        return nil
    }

    guard let data = result as? Data else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "SecItemCopyMatching returned non-data result")
        return nil
    }

    guard let password = String(data: data, encoding: .utf8) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "keychain item is not valid UTF-8")
        return nil
    }

    return stringHandle(password)
}

@_cdecl("security_keychain_delete_password")
public func securityKeychainDeletePassword(
    _ accountPointer: UnsafePointer<CChar>?,
    _ servicePointer: UnsafePointer<CChar>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> Int32 {
    clearError(errorOut)

    guard let account = stringFromCString(accountPointer),
          let service = stringFromCString(servicePointer)
    else {
        setError(errorOut, "account and service are required")
        return errSecParam
    }

    let status = SecItemDelete(genericPasswordQuery(account: account, service: service) as CFDictionary)
    if status == errSecSuccess || status == errSecItemNotFound {
        return errSecSuccess
    }

    setError(errorOut, "SecItemDelete failed: \(statusMessage(status))")
    return status
}

@_cdecl("security_keychain_list_accounts")
public func securityKeychainListAccounts(
    _ servicePointer: UnsafePointer<CChar>?,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard let service = stringFromCString(servicePointer) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "service is required")
        return nil
    }

    var query = genericPasswordQuery(account: nil, service: service)
    query[kSecReturnAttributes] = true
    query[kSecMatchLimit] = kSecMatchLimitAll

    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    if status == errSecItemNotFound {
        return jsonHandle([])
    }
    guard status == errSecSuccess else {
        setStatus(statusOut, status)
        setError(errorOut, "SecItemCopyMatching failed: \(statusMessage(status))")
        return nil
    }

    var accounts: [String] = []
    if let dictionary = result as? [String: Any], let account = dictionary[kSecAttrAccount as String] as? String {
        accounts.append(account)
    } else if let array = result as? [[String: Any]] {
        accounts.append(contentsOf: array.compactMap { $0[kSecAttrAccount as String] as? String })
    }

    accounts.sort()
    accounts = Array(Set(accounts)).sorted()
    return jsonHandle(accounts)
}
