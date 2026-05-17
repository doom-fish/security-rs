//! Additional raw `SecAccessControl.h` declarations.

use super::{CFAllocatorRef, CFErrorRef, CFOptionFlags, CFTypeID, CFTypeRef, SecAccessControlRef};

pub type SecAccessControlCreateFlags = CFOptionFlags;

pub const kSecAccessControlUserPresence: SecAccessControlCreateFlags = 1 << 0;
pub const kSecAccessControlBiometryAny: SecAccessControlCreateFlags = 1 << 1;
pub const kSecAccessControlBiometryCurrentSet: SecAccessControlCreateFlags = 1 << 3;
pub const kSecAccessControlDevicePasscode: SecAccessControlCreateFlags = 1 << 4;
pub const kSecAccessControlCompanion: SecAccessControlCreateFlags = 1 << 5;
pub const kSecAccessControlOr: SecAccessControlCreateFlags = 1 << 14;
pub const kSecAccessControlAnd: SecAccessControlCreateFlags = 1 << 15;
pub const kSecAccessControlPrivateKeyUsage: SecAccessControlCreateFlags = 1 << 30;
pub const kSecAccessControlApplicationPassword: SecAccessControlCreateFlags = 1 << 31;

extern "C" {
    pub fn SecAccessControlGetTypeID() -> CFTypeID;
    pub fn SecAccessControlCreateWithFlags(
        allocator: CFAllocatorRef,
        protection: CFTypeRef,
        flags: SecAccessControlCreateFlags,
        error: *mut CFErrorRef,
    ) -> SecAccessControlRef;
}
