//! `SecCertificate` and `SecKey` wrappers.

use crate::error::{Result, SecurityError};
use crate::ffi;
use crate::private::{cf_data, cf_data_to_vec, cf_string_to_string, checked_cf, OwnedCf};

/// Owned `SecKeyRef` extracted from a certificate.
pub struct PublicKey {
    raw: ffi::SecKeyRef,
}

impl PublicKey {
    /// Borrow the raw `SecKeyRef`.
    #[must_use]
    pub const fn as_raw(&self) -> ffi::SecKeyRef {
        self.raw
    }
}

impl Drop for PublicKey {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            unsafe { ffi::CFRelease(self.raw.cast()) };
        }
    }
}

impl core::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PublicKey").field("raw", &self.raw).finish()
    }
}

/// Owned DER-backed `SecCertificateRef`.
pub struct Certificate {
    raw: ffi::SecCertificateRef,
}

impl Certificate {
    /// Create a certificate from DER-encoded bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes are not a valid DER-encoded X.509 certificate.
    pub fn from_der(der: &[u8]) -> Result<Self> {
        let der = cf_data(der)?;
        let raw =
            unsafe { ffi::SecCertificateCreateWithData(ffi::kCFAllocatorDefault, der.as_data()) };
        if raw.is_null() {
            return Err(SecurityError::InvalidArgument(
                "invalid DER-encoded X.509 certificate".to_owned(),
            ));
        }
        Ok(Self { raw })
    }

    /// Borrow the raw `SecCertificateRef`.
    #[must_use]
    pub const fn as_raw(&self) -> ffi::SecCertificateRef {
        self.raw
    }

    /// Return the subject-summary string, when Security.framework can derive one.
    #[must_use]
    pub fn subject_summary(&self) -> Option<String> {
        let raw = unsafe { ffi::SecCertificateCopySubjectSummary(self.raw) };
        if raw.is_null() {
            return None;
        }
        let owned = OwnedCf::new(raw.cast());
        cf_string_to_string(owned.as_string())
    }

    /// Export the certificate back to DER.
    ///
    /// # Errors
    ///
    /// Returns an error if Security.framework cannot serialize the certificate.
    pub fn der_data(&self) -> Result<Vec<u8>> {
        let raw = unsafe { ffi::SecCertificateCopyData(self.raw) };
        let data = checked_cf(raw.cast(), "SecCertificateCopyData")?;
        Ok(cf_data_to_vec(data.as_data()))
    }

    /// Copy the certificate's public key.
    ///
    /// # Errors
    ///
    /// Returns an error if the certificate's public key cannot be extracted.
    pub fn public_key(&self) -> Result<PublicKey> {
        let raw = unsafe { ffi::SecCertificateCopyKey(self.raw) };
        if raw.is_null() {
            return Err(SecurityError::CoreFoundation(apple_cf::CFError::new(
                "SecCertificateCopyKey",
            )));
        }
        Ok(PublicKey { raw })
    }
}

impl Drop for Certificate {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            unsafe { ffi::CFRelease(self.raw.cast()) };
        }
    }
}

impl core::fmt::Debug for Certificate {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Certificate")
            .field("subject_summary", &self.subject_summary())
            .finish()
    }
}
