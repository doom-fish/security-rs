import Foundation
import Security

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
