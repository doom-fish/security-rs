import Darwin
import Foundation
import Security

private func requirementText(_ requirement: SecRequirement?) -> UnsafeMutableRawPointer? {
    guard let requirement else {
        return nil
    }
    return stringHandle(requirementString(requirement))
}

private func codeGuestAttributeKey(_ key: String) -> CFString {
    switch key {
    case "canonical", "kSecGuestAttributeCanonical": return kSecGuestAttributeCanonical
    case "hash", "kSecGuestAttributeHash": return kSecGuestAttributeHash
    case "mach_port", "machPort", "kSecGuestAttributeMachPort": return kSecGuestAttributeMachPort
    case "pid", "kSecGuestAttributePid": return kSecGuestAttributePid
    case "audit", "kSecGuestAttributeAudit": return kSecGuestAttributeAudit
    case "dynamic_code", "dynamicCode", "kSecGuestAttributeDynamicCode": return kSecGuestAttributeDynamicCode
    case "dynamic_code_info_plist", "dynamicCodeInfoPlist", "kSecGuestAttributeDynamicCodeInfoPlist":
        return kSecGuestAttributeDynamicCodeInfoPlist
    case "architecture", "kSecGuestAttributeArchitecture": return kSecGuestAttributeArchitecture
    case "subarchitecture", "kSecGuestAttributeSubarchitecture": return kSecGuestAttributeSubarchitecture
    default: return key as CFString
    }
}

private func staticCodeAttributeKey(_ key: String) -> CFString {
    switch key {
    case "architecture", "kSecCodeAttributeArchitecture": return kSecCodeAttributeArchitecture
    case "subarchitecture", "kSecCodeAttributeSubarchitecture": return kSecCodeAttributeSubarchitecture
    case "universal_file_offset", "universalFileOffset", "kSecCodeAttributeUniversalFileOffset":
        return kSecCodeAttributeUniversalFileOffset
    case "bundle_version", "bundleVersion", "kSecCodeAttributeBundleVersion": return kSecCodeAttributeBundleVersion
    default: return key as CFString
    }
}

private func codeAttributes(
    from jsonPointer: UnsafePointer<CChar>?,
    keyMapper: (String) -> CFString
) -> CFDictionary? {
    guard let object = jsonObject(fromCString: jsonPointer) else {
        return nil
    }
    guard let dictionary = object as? [String: Any] else {
        return nil
    }

    var mapped: [CFString: Any] = [:]
    for (key, value) in dictionary {
        mapped[keyMapper(key)] = value
    }
    return mapped as CFDictionary
}

private func currentAuditToken() -> audit_token_t? {
    var token = audit_token_t()
    var count = mach_msg_type_number_t(MemoryLayout<audit_token_t>.size / MemoryLayout<natural_t>.size)
    let status = withUnsafeMutablePointer(to: &token) { tokenPointer in
        tokenPointer.withMemoryRebound(to: integer_t.self, capacity: Int(count)) { integerPointer in
            task_info(mach_task_self_, task_flavor_t(TASK_AUDIT_TOKEN), integerPointer, &count)
        }
    }
    return status == KERN_SUCCESS ? token : nil
}

@_cdecl("security_code_copy_self")
public func securityCodeCopySelf(
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    var code: SecCode?
    let status = SecCodeCopySelf(SecCSFlags(), &code)
    guard status == errSecSuccess, let code else {
        setStatus(statusOut, status)
        setError(errorOut, "SecCodeCopySelf failed: \(statusMessage(status))")
        return nil
    }

    return retain(code)
}

@_cdecl("security_code_copy_static_code")
public func securityCodeCopyStaticCode(
    _ codePointer: UnsafeMutableRawPointer?,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard let code = unbox(codePointer, as: SecCode.self) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "code handle is required")
        return nil
    }

    var staticCode: SecStaticCode?
    let status = SecCodeCopyStaticCode(code, SecCSFlags(), &staticCode)
    guard status == errSecSuccess, let staticCode else {
        setStatus(statusOut, status)
        setError(errorOut, "SecCodeCopyStaticCode failed: \(statusMessage(status))")
        return nil
    }

    return retain(staticCode)
}

@_cdecl("security_static_code_check_validity")
public func securityStaticCodeCheckValidity(
    _ staticCodePointer: UnsafeMutableRawPointer?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> Int32 {
    clearError(errorOut)

    guard let staticCode = unbox(staticCodePointer, as: SecStaticCode.self) else {
        setError(errorOut, "static code handle is required")
        return errSecParam
    }

    let status = SecCodeCheckValidity(unsafeBitCast(staticCode, to: SecCode.self), SecCSFlags(), nil)
    if status != errSecSuccess {
        setError(errorOut, "SecCodeCheckValidity failed: \(statusMessage(status))")
    }
    return status
}

@_cdecl("security_static_code_copy_path")
public func securityStaticCodeCopyPath(
    _ staticCodePointer: UnsafeMutableRawPointer?,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard let staticCode = unbox(staticCodePointer, as: SecStaticCode.self) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "static code handle is required")
        return nil
    }

    var url: CFURL?
    let status = SecCodeCopyPath(staticCode, SecCSFlags(), &url)
    guard status == errSecSuccess else {
        setStatus(statusOut, status)
        setError(errorOut, "SecCodeCopyPath failed: \(statusMessage(status))")
        return nil
    }

    return stringHandle((url as URL?)?.path)
}

@_cdecl("security_static_code_copy_designated_requirement")
public func securityStaticCodeCopyDesignatedRequirement(
    _ staticCodePointer: UnsafeMutableRawPointer?,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard let staticCode = unbox(staticCodePointer, as: SecStaticCode.self) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "static code handle is required")
        return nil
    }

    var requirement: SecRequirement?
    let status = SecCodeCopyDesignatedRequirement(staticCode, SecCSFlags(), &requirement)
    guard status == errSecSuccess, let requirement else {
        setStatus(statusOut, status)
        setError(errorOut, "SecCodeCopyDesignatedRequirement failed: \(statusMessage(status))")
        return nil
    }

    return stringHandle(requirementString(requirement))
}

@_cdecl("security_static_code_copy_signing_information")
public func securityStaticCodeCopySigningInformation(
    _ staticCodePointer: UnsafeMutableRawPointer?,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard let staticCode = unbox(staticCodePointer, as: SecStaticCode.self) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "static code handle is required")
        return nil
    }

    let flags = SecCSFlags(rawValue: kSecCSSigningInformation | kSecCSDynamicInformation)
    var information: CFDictionary?
    let status = SecCodeCopySigningInformation(staticCode, flags, &information)
    guard status == errSecSuccess, let information else {
        setStatus(statusOut, status)
        setError(errorOut, "SecCodeCopySigningInformation failed: \(statusMessage(status))")
        return nil
    }

    return jsonHandle(information)
}

@_cdecl("security_task_create_from_self")
public func securityTaskCreateFromSelf(
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard let task = SecTaskCreateFromSelf(nil) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "SecTaskCreateFromSelf returned nil")
        return nil
    }

    return retain(task)
}

@_cdecl("security_task_copy_signing_identifier")
public func securityTaskCopySigningIdentifier(
    _ taskPointer: UnsafeMutableRawPointer?,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard let task = unbox(taskPointer, as: SecTask.self) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "task handle is required")
        return nil
    }

    var error: Unmanaged<CFError>?
    let identifier = SecTaskCopySigningIdentifier(task, &error) as String?
    if identifier == nil, error != nil {
        setStatus(statusOut, errSecParam)
        setError(errorOut, error)
    }
    return stringHandle(identifier)
}

@_cdecl("security_task_copy_value_for_entitlement")
public func securityTaskCopyValueForEntitlement(
    _ taskPointer: UnsafeMutableRawPointer?,
    _ entitlementPointer: UnsafePointer<CChar>?,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard let task = unbox(taskPointer, as: SecTask.self),
          let entitlement = stringFromCString(entitlementPointer)
    else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "task handle and entitlement name are required")
        return nil
    }

    var error: Unmanaged<CFError>?
    let value = SecTaskCopyValueForEntitlement(task, entitlement as CFString, &error)
    if value == nil, error != nil {
        setStatus(statusOut, errSecParam)
        setError(errorOut, error)
    }
    guard let value else {
        return nil
    }

    return jsonHandle(value)
}

@_cdecl("security_code_get_type_id")
public func securityCodeGetTypeID() -> UInt {
    SecCodeGetTypeID()
}

@_cdecl("security_static_code_get_type_id")
public func securityStaticCodeGetTypeID() -> UInt {
    SecStaticCodeGetTypeID()
}

@_cdecl("security_requirement_get_type_id")
public func securityRequirementGetTypeID() -> UInt {
    SecRequirementGetTypeID()
}

@_cdecl("security_task_get_type_id")
public func securityTaskGetTypeID() -> UInt {
    SecTaskGetTypeID()
}

@_cdecl("security_requirement_create_with_data")
public func securityRequirementCreateWithData(
    _ dataPointer: UnsafeRawPointer?,
    _ dataLength: Int,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard let data = dataFromPointer(dataPointer, length: dataLength) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "requirement data is required")
        return nil
    }

    var requirement: SecRequirement?
    let status = SecRequirementCreateWithData(data as CFData, SecCSFlags(), &requirement)
    guard status == errSecSuccess, let requirement else {
        setStatus(statusOut, status)
        setError(errorOut, "SecRequirementCreateWithData failed: \(statusMessage(status))")
        return nil
    }
    return retain(requirement)
}

@_cdecl("security_requirement_create_with_string")
public func securityRequirementCreateWithString(
    _ textPointer: UnsafePointer<CChar>?,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard let text = stringFromCString(textPointer) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "requirement string is required")
        return nil
    }

    var requirement: SecRequirement?
    let status = SecRequirementCreateWithString(text as CFString, SecCSFlags(), &requirement)
    guard status == errSecSuccess, let requirement else {
        setStatus(statusOut, status)
        setError(errorOut, "SecRequirementCreateWithString failed: \(statusMessage(status))")
        return nil
    }
    return retain(requirement)
}

@_cdecl("security_requirement_create_with_string_and_errors")
public func securityRequirementCreateWithStringAndErrors(
    _ textPointer: UnsafePointer<CChar>?,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard let text = stringFromCString(textPointer) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "requirement string is required")
        return nil
    }

    var requirement: SecRequirement?
    var error: Unmanaged<CFError>?
    let status = SecRequirementCreateWithStringAndErrors(text as CFString, SecCSFlags(), &error, &requirement)
    guard status == errSecSuccess, let requirement else {
        setStatus(statusOut, status)
        if let error {
            setError(errorOut, error)
        } else {
            setError(errorOut, "SecRequirementCreateWithStringAndErrors failed: \(statusMessage(status))")
        }
        return nil
    }
    return retain(requirement)
}

@_cdecl("security_requirement_copy_data")
public func securityRequirementCopyData(
    _ requirementPointer: UnsafeMutableRawPointer?,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard let requirement = unbox(requirementPointer, as: SecRequirement.self) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "requirement handle is required")
        return nil
    }

    var data: CFData?
    let status = SecRequirementCopyData(requirement, SecCSFlags(), &data)
    guard status == errSecSuccess, let data else {
        setStatus(statusOut, status)
        setError(errorOut, "SecRequirementCopyData failed: \(statusMessage(status))")
        return nil
    }
    return dataHandle(data as Data)
}

@_cdecl("security_requirement_copy_string")
public func securityRequirementCopyString(
    _ requirementPointer: UnsafeMutableRawPointer?,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard let requirement = unbox(requirementPointer, as: SecRequirement.self) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "requirement handle is required")
        return nil
    }

    var text: CFString?
    let status = SecRequirementCopyString(requirement, SecCSFlags(), &text)
    guard status == errSecSuccess, let text else {
        setStatus(statusOut, status)
        setError(errorOut, "SecRequirementCopyString failed: \(statusMessage(status))")
        return nil
    }
    return stringHandle(text as String)
}

@_cdecl("security_static_code_create_with_path")
public func securityStaticCodeCreateWithPath(
    _ pathPointer: UnsafePointer<CChar>?,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard let path = stringFromCString(pathPointer) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "static code path is required")
        return nil
    }

    var staticCode: SecStaticCode?
    let status = SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, SecCSFlags(), &staticCode)
    guard status == errSecSuccess, let staticCode else {
        setStatus(statusOut, status)
        setError(errorOut, "SecStaticCodeCreateWithPath failed: \(statusMessage(status))")
        return nil
    }
    return retain(staticCode)
}

@_cdecl("security_static_code_create_with_path_and_attributes")
public func securityStaticCodeCreateWithPathAndAttributes(
    _ pathPointer: UnsafePointer<CChar>?,
    _ attributesPointer: UnsafePointer<CChar>?,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard let path = stringFromCString(pathPointer) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "static code path is required")
        return nil
    }
    guard attributesPointer == nil || codeAttributes(from: attributesPointer, keyMapper: staticCodeAttributeKey) != nil else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "static code attributes JSON was invalid")
        return nil
    }

    var staticCode: SecStaticCode?
    let status = SecStaticCodeCreateWithPathAndAttributes(
        URL(fileURLWithPath: path) as CFURL,
        SecCSFlags(),
        codeAttributes(from: attributesPointer, keyMapper: staticCodeAttributeKey) ?? [:] as CFDictionary,
        &staticCode
    )
    guard status == errSecSuccess, let staticCode else {
        setStatus(statusOut, status)
        setError(errorOut, "SecStaticCodeCreateWithPathAndAttributes failed: \(statusMessage(status))")
        return nil
    }
    return retain(staticCode)
}

@_cdecl("security_static_code_check_validity_with_errors")
public func securityStaticCodeCheckValidityWithErrors(
    _ staticCodePointer: UnsafeMutableRawPointer?,
    _ flags: UInt32,
    _ requirementPointer: UnsafeMutableRawPointer?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> Int32 {
    clearError(errorOut)

    guard let staticCode = unbox(staticCodePointer, as: SecStaticCode.self) else {
        setError(errorOut, "static code handle is required")
        return errSecParam
    }

    var error: Unmanaged<CFError>?
    let status = SecCodeCheckValidityWithErrors(
        unsafeBitCast(staticCode, to: SecCode.self),
        SecCSFlags(rawValue: flags),
        unbox(requirementPointer, as: SecRequirement.self),
        &error
    )
    if status != errSecSuccess {
        if let error {
            setError(errorOut, error)
        } else {
            setError(errorOut, "SecCodeCheckValidityWithErrors failed: \(statusMessage(status))")
        }
    }
    return status
}

@_cdecl("security_static_code_check_static_validity")
public func securityStaticCodeCheckStaticValidity(
    _ staticCodePointer: UnsafeMutableRawPointer?,
    _ flags: UInt32,
    _ requirementPointer: UnsafeMutableRawPointer?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> Int32 {
    clearError(errorOut)

    guard let staticCode = unbox(staticCodePointer, as: SecStaticCode.self) else {
        setError(errorOut, "static code handle is required")
        return errSecParam
    }

    let status = SecStaticCodeCheckValidity(
        staticCode,
        SecCSFlags(rawValue: flags),
        unbox(requirementPointer, as: SecRequirement.self)
    )
    if status != errSecSuccess {
        setError(errorOut, "SecStaticCodeCheckValidity failed: \(statusMessage(status))")
    }
    return status
}

@_cdecl("security_static_code_check_static_validity_with_errors")
public func securityStaticCodeCheckStaticValidityWithErrors(
    _ staticCodePointer: UnsafeMutableRawPointer?,
    _ flags: UInt32,
    _ requirementPointer: UnsafeMutableRawPointer?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> Int32 {
    clearError(errorOut)

    guard let staticCode = unbox(staticCodePointer, as: SecStaticCode.self) else {
        setError(errorOut, "static code handle is required")
        return errSecParam
    }

    var error: Unmanaged<CFError>?
    let status = SecStaticCodeCheckValidityWithErrors(
        staticCode,
        SecCSFlags(rawValue: flags),
        unbox(requirementPointer, as: SecRequirement.self),
        &error
    )
    if status != errSecSuccess {
        if let error {
            setError(errorOut, error)
        } else {
            setError(errorOut, "SecStaticCodeCheckValidityWithErrors failed: \(statusMessage(status))")
        }
    }
    return status
}

@_cdecl("security_code_copy_host")
public func securityCodeCopyHost(
    _ codePointer: UnsafeMutableRawPointer?,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard let code = unbox(codePointer, as: SecCode.self) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "code handle is required")
        return nil
    }

    var host: SecCode?
    let status = SecCodeCopyHost(code, SecCSFlags(), &host)
    guard status == errSecSuccess, let host else {
        setStatus(statusOut, status)
        setError(errorOut, "SecCodeCopyHost failed: \(statusMessage(status))")
        return nil
    }
    return retain(host)
}

@_cdecl("security_code_copy_guest_with_attributes")
public func securityCodeCopyGuestWithAttributes(
    _ hostPointer: UnsafeMutableRawPointer?,
    _ attributesPointer: UnsafePointer<CChar>?,
    _ flags: UInt32,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard attributesPointer == nil || codeAttributes(from: attributesPointer, keyMapper: codeGuestAttributeKey) != nil else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "guest attribute JSON was invalid")
        return nil
    }

    var guest: SecCode?
    let status = SecCodeCopyGuestWithAttributes(
        unbox(hostPointer, as: SecCode.self),
        codeAttributes(from: attributesPointer, keyMapper: codeGuestAttributeKey),
        SecCSFlags(rawValue: flags),
        &guest
    )
    guard status == errSecSuccess, let guest else {
        setStatus(statusOut, status)
        setError(errorOut, "SecCodeCopyGuestWithAttributes failed: \(statusMessage(status))")
        return nil
    }
    return retain(guest)
}

@_cdecl("security_static_code_validate_file_resource")
public func securityStaticCodeValidateFileResource(
    _ staticCodePointer: UnsafeMutableRawPointer?,
    _ relativePathPointer: UnsafePointer<CChar>?,
    _ dataPointer: UnsafeRawPointer?,
    _ dataLength: Int,
    _ flags: UInt32,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> Int32 {
    clearError(errorOut)

    guard let staticCode = unbox(staticCodePointer, as: SecStaticCode.self),
          let relativePath = stringFromCString(relativePathPointer),
          let data = dataFromPointer(dataPointer, length: dataLength)
    else {
        setError(errorOut, "static code handle, relative path, and file data are required")
        return errSecParam
    }

    let status = SecCodeValidateFileResource(
        staticCode,
        relativePath as CFString,
        data as CFData,
        SecCSFlags(rawValue: flags)
    )
    if status != errSecSuccess {
        setError(errorOut, "SecCodeValidateFileResource failed: \(statusMessage(status))")
    }
    return status
}

@_cdecl("security_static_code_map_memory")
public func securityStaticCodeMapMemory(
    _ staticCodePointer: UnsafeMutableRawPointer?,
    _ flags: UInt32,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> Int32 {
    clearError(errorOut)

    guard let staticCode = unbox(staticCodePointer, as: SecStaticCode.self) else {
        setError(errorOut, "static code handle is required")
        return errSecParam
    }

    let status = SecCodeMapMemory(staticCode, SecCSFlags(rawValue: flags))
    if status != errSecSuccess {
        setError(errorOut, "SecCodeMapMemory failed: \(statusMessage(status))")
    }
    return status
}

@_cdecl("security_task_create_from_current_audit_token")
public func securityTaskCreateFromCurrentAuditToken(
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard let token = currentAuditToken(), let task = SecTaskCreateWithAuditToken(nil, token) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "SecTaskCreateWithAuditToken failed")
        return nil
    }
    return retain(task)
}

@_cdecl("security_task_copy_values_for_entitlements")
public func securityTaskCopyValuesForEntitlements(
    _ taskPointer: UnsafeMutableRawPointer?,
    _ entitlementsPointer: UnsafePointer<CChar>?,
    _ statusOut: UnsafeMutablePointer<Int32>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> UnsafeMutableRawPointer? {
    clearError(errorOut)
    setStatus(statusOut, errSecSuccess)

    guard let task = unbox(taskPointer, as: SecTask.self) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "task handle is required")
        return nil
    }
    guard let entitlements = jsonStringArray(fromCString: entitlementsPointer) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, "entitlement name JSON was invalid")
        return nil
    }

    var error: Unmanaged<CFError>?
    guard let values = SecTaskCopyValuesForEntitlements(task, entitlements as CFArray, &error) else {
        setStatus(statusOut, errSecParam)
        setError(errorOut, error)
        return nil
    }
    return jsonHandle(values)
}
