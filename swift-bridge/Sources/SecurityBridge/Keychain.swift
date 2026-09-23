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

@_cdecl("security_access_control_get_type_id")
public func securityAccessControlGetTypeID() -> UInt {
    SecAccessControlGetTypeID()
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

private struct KeychainQueryOptions {
    var accessibility: CFTypeRef = kSecAttrAccessibleWhenUnlocked
    var accessGroup: String?
    var synchronizable = false
    var dataProtectionKeychain = false
}

private func keychainQueryOptions(_ pointer: UnsafePointer<CChar>?) -> KeychainQueryOptions? {
    var options = KeychainQueryOptions()
    guard let pointer else {
        return options
    }
    guard let object = jsonObject(fromCString: pointer) as? [String: Any] else {
        return nil
    }
    if let value = object["accessibility"] {
        guard let name = value as? String, let accessibility = accessControlProtection(name) else {
            return nil
        }
        options.accessibility = accessibility
    }
    if let value = object["access_group"] {
        guard let accessGroup = value as? String else {
            return nil
        }
        options.accessGroup = accessGroup
    }
    if let value = object["synchronizable"] {
        guard let synchronizable = value as? Bool else {
            return nil
        }
        options.synchronizable = synchronizable
    }
    if let value = object["data_protection_keychain"] {
        guard let dataProtectionKeychain = value as? Bool else {
            return nil
        }
        options.dataProtectionKeychain = dataProtectionKeychain
    }
    return options
}

struct AuthenticationContextRecord {
    let context: NSObject
}

private func keychainQuery(
    account: String?,
    service: String,
    options: KeychainQueryOptions,
    authenticationContext: NSObject?
) -> [CFString: Any] {
    var query = genericPasswordQuery(account: account, service: service)
    if options.dataProtectionKeychain {
        query[kSecUseDataProtectionKeychain] = true
    }
    if let accessGroup = options.accessGroup {
        query[kSecAttrAccessGroup] = accessGroup
    }
    if options.synchronizable {
        query[kSecAttrSynchronizable] = true
    }
    if let authenticationContext {
        query[kSecUseAuthenticationContext] = authenticationContext
    }
    return query
}

private enum KeychainInputError: Error {
    case invalid(String)
}

private func keychainInputs(
    service servicePointer: UnsafePointer<CChar>?,
    options optionsPointer: UnsafePointer<CChar>?,
    authenticationContext authenticationContextPointer: UnsafeMutableRawPointer?
) throws -> (String, KeychainQueryOptions, NSObject?) {
    guard let service = stringFromCString(servicePointer) else {
        throw KeychainInputError.invalid("service is required")
    }
    guard let options = keychainQueryOptions(optionsPointer) else {
        throw KeychainInputError.invalid("keychain options JSON was invalid")
    }
    let authenticationContext = unbox(authenticationContextPointer, as: AuthenticationContextRecord.self)?.context
    guard authenticationContextPointer == nil || authenticationContext != nil else {
        throw KeychainInputError.invalid("authentication context handle is invalid")
    }
    return (service, options, authenticationContext)
}

private func keychainInputMessage(_ error: Error) -> String {
    if case let KeychainInputError.invalid(message) = error {
        return message
    }
    return "invalid keychain input"
}

@_cdecl("security_authentication_context_retain")
public func securityAuthenticationContextRetain(_ contextPointer: UnsafeMutableRawPointer?) -> UnsafeMutableRawPointer? {
    guard let contextPointer,
          let contextClass = NSClassFromString("LAContext"),
          let context = Unmanaged<AnyObject>.fromOpaque(contextPointer).takeUnretainedValue() as? NSObject,
          context.isKind(of: contextClass)
    else {
        return nil
    }
    return retain(AuthenticationContextRecord(context: context))
}

@_cdecl("security_keychain_set_item")
public func securityKeychainSetItem(
    _ accountPointer: UnsafePointer<CChar>?,
    _ servicePointer: UnsafePointer<CChar>?,
    _ dataPointer: UnsafeRawPointer?,
    _ dataLength: Int,
    _ optionsPointer: UnsafePointer<CChar>?,
    _ accessControlPointer: UnsafeMutableRawPointer?,
    _ authenticationContextPointer: UnsafeMutableRawPointer?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> Int32 {
    clearError(errorOut)

    let inputs: (String, KeychainQueryOptions, NSObject?)
    do {
        inputs = try keychainInputs(
            service: servicePointer,
            options: optionsPointer,
            authenticationContext: authenticationContextPointer
        )
    } catch {
        setError(errorOut, keychainInputMessage(error))
        return errSecParam
    }
    let (service, options, authenticationContext) = inputs
    guard let account = stringFromCString(accountPointer), dataLength >= 0, dataPointer != nil || dataLength == 0 else {
        setError(errorOut, "account and secret data are required")
        return errSecParam
    }
    let accessControl = unbox(accessControlPointer, as: SecAccessControl.self)
    guard accessControlPointer == nil || accessControl != nil else {
        setError(errorOut, "access control handle is invalid")
        return errSecParam
    }

    let secret = NSMutableData(length: dataLength) ?? NSMutableData()
    if let dataPointer, dataLength > 0 {
        secret.replaceBytes(in: NSRange(location: 0, length: dataLength), withBytes: dataPointer)
    }
    defer {
        if secret.length > 0 {
            _ = memset_s(secret.mutableBytes, secret.length, 0, secret.length)
        }
    }

    var protection: [CFString: Any] = [:]
    if let accessControl {
        protection[kSecAttrAccessControl] = accessControl
    } else {
        protection[kSecAttrAccessible] = options.accessibility
    }

    let searchQuery = keychainQuery(
        account: account,
        service: service,
        options: options,
        authenticationContext: authenticationContext
    )
    var addQuery = searchQuery.merging(protection) { $1 }
    addQuery[kSecValueData] = secret

    let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
    if addStatus == errSecSuccess {
        return errSecSuccess
    }

    if addStatus != errSecDuplicateItem {
        setError(errorOut, "SecItemAdd failed: \(statusMessage(addStatus))")
        return addStatus
    }

    var update = protection
    update[kSecValueData] = secret
    let updateStatus = SecItemUpdate(searchQuery as CFDictionary, update as CFDictionary)
    if updateStatus != errSecSuccess {
        setError(errorOut, "SecItemUpdate failed: \(statusMessage(updateStatus))")
    }

    return updateStatus
}

@_cdecl("security_keychain_copy_item")
public func securityKeychainCopyItem(
    _ accountPointer: UnsafePointer<CChar>?,
    _ servicePointer: UnsafePointer<CChar>?,
    _ optionsPointer: UnsafePointer<CChar>?,
    _ authenticationContextPointer: UnsafeMutableRawPointer?,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    let inputs: (String, KeychainQueryOptions, NSObject?)
    do {
        inputs = try keychainInputs(
            service: servicePointer,
            options: optionsPointer,
            authenticationContext: authenticationContextPointer
        )
    } catch {
        setStatus(statusOut, errSecParam)
        setError(errorOut, keychainInputMessage(error))
        return nil
    }
    let (service, options, authenticationContext) = inputs
    guard let account = stringFromCString(accountPointer) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "account is required")
        return nil
    }

    var query = keychainQuery(
        account: account,
        service: service,
        options: options,
        authenticationContext: authenticationContext
    )
    query[kSecReturnData] = true
    query[kSecMatchLimit] = kSecMatchLimitOne

    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    guard status == errSecSuccess else {
        setStatus(statusOut, status)
        setError(errorOut, "SecItemCopyMatching failed: \(statusMessage(status))")
        return nil
    }

    guard let result, CFGetTypeID(result) == CFDataGetTypeID() else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "SecItemCopyMatching returned non-data result")
        return nil
    }

    return retainSecret(unsafeDowncast(result, to: CFData.self))
}

@_cdecl("security_keychain_delete_item")
public func securityKeychainDeleteItem(
    _ accountPointer: UnsafePointer<CChar>?,
    _ servicePointer: UnsafePointer<CChar>?,
    _ optionsPointer: UnsafePointer<CChar>?,
    _ authenticationContextPointer: UnsafeMutableRawPointer?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> Int32 {
    clearError(errorOut)

    let inputs: (String, KeychainQueryOptions, NSObject?)
    do {
        inputs = try keychainInputs(
            service: servicePointer,
            options: optionsPointer,
            authenticationContext: authenticationContextPointer
        )
    } catch {
        setError(errorOut, keychainInputMessage(error))
        return errSecParam
    }
    let (service, options, authenticationContext) = inputs
    guard let account = stringFromCString(accountPointer) else {
        setError(errorOut, "account is required")
        return errSecParam
    }

    let query = keychainQuery(
        account: account,
        service: service,
        options: options,
        authenticationContext: authenticationContext
    )
    let status = SecItemDelete(query as CFDictionary)
    if status == errSecSuccess || status == errSecItemNotFound {
        return errSecSuccess
    }

    setError(errorOut, "SecItemDelete failed: \(statusMessage(status))")
    return status
}

@_cdecl("security_keychain_list_accounts")
public func securityKeychainListAccounts(
    _ servicePointer: UnsafePointer<CChar>?,
    _ optionsPointer: UnsafePointer<CChar>?,
    _ authenticationContextPointer: UnsafeMutableRawPointer?,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    let inputs: (String, KeychainQueryOptions, NSObject?)
    do {
        inputs = try keychainInputs(
            service: servicePointer,
            options: optionsPointer,
            authenticationContext: authenticationContextPointer
        )
    } catch {
        setStatus(statusOut, errSecParam)
        setError(errorOut, keychainInputMessage(error))
        return nil
    }
    let (service, options, authenticationContext) = inputs

    var query = keychainQuery(
        account: nil,
        service: service,
        options: options,
        authenticationContext: authenticationContext
    )
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

    accounts = Array(Set(accounts)).sorted()
    return jsonHandle(accounts)
}
