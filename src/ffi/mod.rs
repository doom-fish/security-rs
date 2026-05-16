//! Raw FFI declarations for the subset of `Security.framework` used by this crate.

#![allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    missing_docs
)]

use libc::{c_char, c_void, size_t};

pub type CFTypeRef = *const c_void;
pub type CFAllocatorRef = *const c_void;
pub type CFStringRef = *const c_void;
pub type CFDataRef = *const c_void;
pub type CFArrayRef = *const c_void;
pub type CFDictionaryRef = *const c_void;
pub type CFMutableDictionaryRef = *mut c_void;
pub type CFBooleanRef = *const c_void;
pub type CFNumberRef = *const c_void;
pub type CFErrorRef = *const c_void;
pub type CFIndex = isize;
pub type CFTypeID = usize;
pub type OSStatus = i32;
pub type Boolean = u8;
pub type SecRandomRef = *const c_void;
pub type SecCertificateRef = *const c_void;
pub type SecKeyRef = *const c_void;
pub type SecPolicyRef = *const c_void;
pub type SecTrustRef = *const c_void;
pub type SecCodeRef = *const c_void;
pub type SecStaticCodeRef = *const c_void;
pub type SecCSFlags = u32;

pub const kCFStringEncodingUTF8: u32 = 0x0800_0100;
pub const kCFNumberSInt64Type: i64 = 4;

pub const kSecCSDefaultFlags: SecCSFlags = 0;
pub const kSecCSSigningInformation: SecCSFlags = 1 << 1;
pub const kSecCSDynamicInformation: SecCSFlags = 1 << 3;

pub mod status {
    use super::OSStatus;

    pub const SUCCESS: OSStatus = 0;
    pub const DUPLICATE_ITEM: OSStatus = -25299;
    pub const ITEM_NOT_FOUND: OSStatus = -25300;
    pub const INTERACTION_NOT_ALLOWED: OSStatus = -25308;
}

extern "C" {
    pub static kCFAllocatorDefault: CFAllocatorRef;
    pub static kCFBooleanTrue: CFBooleanRef;
    pub static kCFTypeDictionaryKeyCallBacks: c_void;
    pub static kCFTypeDictionaryValueCallBacks: c_void;
    pub static kCFTypeArrayCallBacks: c_void;

    pub fn CFRelease(cf: CFTypeRef);
    pub fn CFGetTypeID(cf: CFTypeRef) -> CFTypeID;

    pub fn CFStringCreateWithCString(
        alloc: CFAllocatorRef,
        c_str: *const c_char,
        encoding: u32,
    ) -> CFStringRef;
    pub fn CFStringGetLength(string: CFStringRef) -> CFIndex;
    pub fn CFStringGetCString(
        string: CFStringRef,
        buffer: *mut c_char,
        buffer_size: CFIndex,
        encoding: u32,
    ) -> bool;
    pub fn CFStringGetTypeID() -> CFTypeID;

    pub fn CFDataCreate(alloc: CFAllocatorRef, bytes: *const u8, length: CFIndex) -> CFDataRef;
    pub fn CFDataGetLength(data: CFDataRef) -> CFIndex;
    pub fn CFDataGetBytePtr(data: CFDataRef) -> *const u8;
    pub fn CFDataGetTypeID() -> CFTypeID;

    pub fn CFArrayCreate(
        allocator: CFAllocatorRef,
        values: *const *const c_void,
        num_values: CFIndex,
        call_backs: *const c_void,
    ) -> CFArrayRef;
    pub fn CFArrayGetCount(array: CFArrayRef) -> CFIndex;
    pub fn CFArrayGetValueAtIndex(array: CFArrayRef, index: CFIndex) -> *const c_void;
    pub fn CFArrayGetTypeID() -> CFTypeID;

    pub fn CFDictionaryCreateMutable(
        allocator: CFAllocatorRef,
        capacity: CFIndex,
        key_call_backs: *const c_void,
        value_call_backs: *const c_void,
    ) -> CFMutableDictionaryRef;
    pub fn CFDictionarySetValue(
        dictionary: CFMutableDictionaryRef,
        key: *const c_void,
        value: *const c_void,
    );
    pub fn CFDictionaryGetValue(dictionary: CFDictionaryRef, key: *const c_void) -> *const c_void;
    pub fn CFDictionaryGetCount(dictionary: CFDictionaryRef) -> CFIndex;
    pub fn CFDictionaryGetKeysAndValues(
        dictionary: CFDictionaryRef,
        keys: *mut *const c_void,
        values: *mut *const c_void,
    );
    pub fn CFDictionaryGetTypeID() -> CFTypeID;

    pub fn CFBooleanGetValue(boolean: CFBooleanRef) -> bool;
    pub fn CFBooleanGetTypeID() -> CFTypeID;

    pub fn CFNumberGetValue(number: CFNumberRef, number_type: i64, value_ptr: *mut c_void) -> bool;
    pub fn CFNumberGetTypeID() -> CFTypeID;

    pub fn CFErrorCopyDescription(err: CFErrorRef) -> CFStringRef;

    pub fn SecCopyErrorMessageString(status: OSStatus, reserved: *mut c_void) -> CFStringRef;

    pub static kSecClass: CFStringRef;
    pub static kSecClassGenericPassword: CFStringRef;
    pub static kSecAttrAccount: CFStringRef;
    pub static kSecAttrService: CFStringRef;
    pub static kSecValueData: CFStringRef;
    pub static kSecReturnData: CFStringRef;
    pub static kSecReturnAttributes: CFStringRef;
    pub static kSecMatchLimit: CFStringRef;
    pub static kSecMatchLimitOne: CFStringRef;
    pub static kSecMatchLimitAll: CFStringRef;

    pub fn SecItemCopyMatching(query: CFDictionaryRef, result: *mut CFTypeRef) -> OSStatus;
    pub fn SecItemAdd(attributes: CFDictionaryRef, result: *mut CFTypeRef) -> OSStatus;
    pub fn SecItemUpdate(query: CFDictionaryRef, attributes_to_update: CFDictionaryRef)
        -> OSStatus;
    pub fn SecItemDelete(query: CFDictionaryRef) -> OSStatus;

    pub fn SecCertificateCreateWithData(
        allocator: CFAllocatorRef,
        data: CFDataRef,
    ) -> SecCertificateRef;
    pub fn SecCertificateCopySubjectSummary(certificate: SecCertificateRef) -> CFStringRef;
    pub fn SecCertificateCopyData(certificate: SecCertificateRef) -> CFDataRef;
    pub fn SecCertificateCopyKey(certificate: SecCertificateRef) -> SecKeyRef;

    pub fn SecPolicyCreateBasicX509() -> SecPolicyRef;
    pub fn SecPolicyCreateSSL(server: Boolean, hostname: CFStringRef) -> SecPolicyRef;

    pub fn SecTrustCreateWithCertificates(
        certificates: CFTypeRef,
        policies: CFTypeRef,
        trust: *mut SecTrustRef,
    ) -> OSStatus;
    pub fn SecTrustSetPolicies(trust: SecTrustRef, policies: CFTypeRef) -> OSStatus;
    pub fn SecTrustEvaluateWithError(trust: SecTrustRef, error: *mut CFErrorRef) -> Boolean;

    pub fn SecCodeCopySelf(flags: SecCSFlags, self_code: *mut SecCodeRef) -> OSStatus;
    pub static kSecCodeInfoIdentifier: CFStringRef;
    pub static kSecCodeInfoTeamIdentifier: CFStringRef;
    pub static kSecCodeInfoEntitlementsDict: CFStringRef;
    pub static kSecCodeInfoStatus: CFStringRef;
    pub fn SecCodeCopySigningInformation(
        code: SecStaticCodeRef,
        flags: SecCSFlags,
        information: *mut CFDictionaryRef,
    ) -> OSStatus;

    pub static kSecRandomDefault: SecRandomRef;
    pub fn SecRandomCopyBytes(rnd: SecRandomRef, count: size_t, bytes: *mut c_void) -> i32;
}
