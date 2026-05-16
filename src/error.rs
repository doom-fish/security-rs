//! Errors returned by the `security-rs` bindings.

use core::fmt;

use apple_cf::CFError;

use crate::ffi;

/// Convenient result alias used throughout this crate.
pub type Result<T, E = SecurityError> = std::result::Result<T, E>;

/// Structured `OSStatus` error returned by `Security.framework`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusError {
    /// API name that returned the status code.
    pub operation: &'static str,
    /// Raw `OSStatus` numeric code.
    pub status: ffi::OSStatus,
    /// Human-readable description when available.
    pub message: String,
}

impl fmt::Display for StatusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} failed with OSStatus {}: {}",
            self.operation, self.status, self.message
        )
    }
}

impl std::error::Error for StatusError {}

/// Top-level error type returned by this crate.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SecurityError {
    /// Invalid input crossed the FFI boundary.
    InvalidArgument(String),
    /// A requested keychain item was missing.
    ItemNotFound(String),
    /// A duplicate keychain item already existed.
    DuplicateItem(String),
    /// Authentication UI was suppressed or otherwise unavailable.
    InteractionNotAllowed(String),
    /// Trust evaluation failed and Security.framework provided a reason.
    TrustEvaluationFailed(String),
    /// A Core Foundation creation call returned a null pointer.
    CoreFoundation(CFError),
    /// Security.framework returned an unexpected Core Foundation type.
    UnexpectedType {
        /// API name being decoded.
        operation: &'static str,
        /// Expected Core Foundation family.
        expected: &'static str,
    },
    /// Security.framework returned an `OSStatus` not covered by a more specific variant.
    Status(StatusError),
}

impl SecurityError {
    /// Numeric `OSStatus`, when this error originated from one.
    #[must_use]
    pub const fn code(&self) -> Option<ffi::OSStatus> {
        match self {
            Self::ItemNotFound(_) => Some(ffi::status::ITEM_NOT_FOUND),
            Self::DuplicateItem(_) => Some(ffi::status::DUPLICATE_ITEM),
            Self::InteractionNotAllowed(_) => Some(ffi::status::INTERACTION_NOT_ALLOWED),
            Self::Status(error) => Some(error.status),
            _ => None,
        }
    }

    pub(crate) const fn from_status(
        operation: &'static str,
        status: ffi::OSStatus,
        message: String,
    ) -> Self {
        match status {
            ffi::status::ITEM_NOT_FOUND => Self::ItemNotFound(message),
            ffi::status::DUPLICATE_ITEM => Self::DuplicateItem(message),
            ffi::status::INTERACTION_NOT_ALLOWED => Self::InteractionNotAllowed(message),
            _ => Self::Status(StatusError {
                operation,
                status,
                message,
            }),
        }
    }
}

impl fmt::Display for SecurityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidArgument(message) => write!(f, "invalid argument: {message}"),
            Self::ItemNotFound(message) => write!(f, "item not found: {message}"),
            Self::DuplicateItem(message) => write!(f, "duplicate item: {message}"),
            Self::InteractionNotAllowed(message) => write!(f, "interaction not allowed: {message}"),
            Self::TrustEvaluationFailed(message) => write!(f, "trust evaluation failed: {message}"),
            Self::CoreFoundation(error) => write!(f, "{error}"),
            Self::UnexpectedType {
                operation,
                expected,
            } => write!(
                f,
                "{operation} returned an unexpected Core Foundation type (expected {expected})"
            ),
            Self::Status(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for SecurityError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::CoreFoundation(error) => Some(error),
            Self::Status(error) => Some(error),
            _ => None,
        }
    }
}
