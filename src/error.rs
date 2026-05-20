//! Errors returned by the `security-rs` bindings.

use core::fmt;

use apple_cf::CFError;

/// Convenient result alias used throughout this crate.
pub type Result<T, E = SecurityError> = std::result::Result<T, E>;

/// Raw `OSStatus` code returned by Security.framework.
pub type OsStatus = i32;

/// Common status-code constants surfaced by the safe bridge.
pub mod status {
    use super::OsStatus;

    /// Mirrors a common `OSStatus` value from Security.framework.
    pub const SUCCESS: OsStatus = 0;
    /// Mirrors a common `OSStatus` value from Security.framework.
    pub const DUPLICATE_ITEM: OsStatus = -25_299;
    /// Mirrors a common `OSStatus` value from Security.framework.
    pub const ITEM_NOT_FOUND: OsStatus = -25_300;
    /// Mirrors a common `OSStatus` value from Security.framework.
    pub const INTERACTION_NOT_ALLOWED: OsStatus = -25_308;
}

/// Structured `OSStatus` error returned by `Security.framework`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusError {
    /// API name that returned the status code.
    pub operation: &'static str,
    /// Raw `OSStatus` numeric code.
    pub status: OsStatus,
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
    /// Security.framework returned an unexpected Core Foundation type.
    UnexpectedType {
        /// API name being decoded.
        operation: &'static str,
        /// Expected Core Foundation family.
        expected: &'static str,
    },
    /// JSON serialization or deserialization failed.
    Serialization(String),
    /// A Core Foundation creation call returned a null pointer.
    CoreFoundation(CFError),
    /// Security.framework returned an unexpected `OSStatus`.
    Status(StatusError),
}

impl SecurityError {
    #[must_use]
    /// Returns the underlying `OSStatus` when Security.framework provided one.
    pub const fn code(&self) -> Option<OsStatus> {
        match self {
            Self::ItemNotFound(_) => Some(status::ITEM_NOT_FOUND),
            Self::DuplicateItem(_) => Some(status::DUPLICATE_ITEM),
            Self::InteractionNotAllowed(_) => Some(status::INTERACTION_NOT_ALLOWED),
            Self::Status(error) => Some(error.status),
            _ => None,
        }
    }

    pub(crate) fn from_status(operation: &'static str, status: OsStatus, message: String) -> Self {
        match status {
            status::ITEM_NOT_FOUND => Self::ItemNotFound(message),
            status::DUPLICATE_ITEM => Self::DuplicateItem(message),
            status::INTERACTION_NOT_ALLOWED => Self::InteractionNotAllowed(message),
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
            Self::TrustEvaluationFailed(message) => {
                write!(f, "trust evaluation failed: {message}")
            }
            Self::UnexpectedType {
                operation,
                expected,
            } => write!(
                f,
                "{operation} returned an unexpected value (expected {expected})"
            ),
            Self::Serialization(message) => write!(f, "serialization error: {message}"),
            Self::CoreFoundation(error) => write!(f, "{error}"),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_error_display_includes_operation_status_and_message() {
        let error = StatusError {
            operation: "security_op",
            status: -50,
            message: "bad input".to_owned(),
        };

        assert_eq!(
            error.to_string(),
            "security_op failed with OSStatus -50: bad input"
        );
    }

    #[test]
    fn from_status_maps_known_codes_to_specialized_variants() {
        assert_eq!(
            SecurityError::from_status("op", status::ITEM_NOT_FOUND, "missing".to_owned()),
            SecurityError::ItemNotFound("missing".to_owned())
        );
        assert_eq!(
            SecurityError::from_status("op", status::DUPLICATE_ITEM, "duplicate".to_owned()),
            SecurityError::DuplicateItem("duplicate".to_owned())
        );
        assert_eq!(
            SecurityError::from_status(
                "op",
                status::INTERACTION_NOT_ALLOWED,
                "suppressed".to_owned(),
            ),
            SecurityError::InteractionNotAllowed("suppressed".to_owned())
        );
    }

    #[test]
    fn from_status_wraps_unknown_codes_in_status_error() {
        let error = SecurityError::from_status("security_op", -1_234, "unexpected".to_owned());

        assert_eq!(
            error,
            SecurityError::Status(StatusError {
                operation: "security_op",
                status: -1_234,
                message: "unexpected".to_owned(),
            })
        );
        assert_eq!(error.code(), Some(-1_234));
    }

    #[test]
    fn code_reports_expected_status_values() {
        let status_error = SecurityError::Status(StatusError {
            operation: "security_op",
            status: -42,
            message: "boom".to_owned(),
        });

        assert_eq!(
            SecurityError::ItemNotFound("missing".to_owned()).code(),
            Some(status::ITEM_NOT_FOUND)
        );
        assert_eq!(
            SecurityError::DuplicateItem("duplicate".to_owned()).code(),
            Some(status::DUPLICATE_ITEM)
        );
        assert_eq!(
            SecurityError::InteractionNotAllowed("suppressed".to_owned()).code(),
            Some(status::INTERACTION_NOT_ALLOWED)
        );
        assert_eq!(status_error.code(), Some(-42));
        assert_eq!(
            SecurityError::InvalidArgument("bad".to_owned()).code(),
            None
        );
    }

    #[test]
    fn security_error_display_and_source_follow_wrapped_status() {
        let wrapped = StatusError {
            operation: "security_op",
            status: -42,
            message: "boom".to_owned(),
        };
        let error = SecurityError::Status(wrapped.clone());
        let serialization = SecurityError::Serialization("invalid json".to_owned());

        assert_eq!(error.to_string(), wrapped.to_string());
        assert_eq!(
            std::error::Error::source(&error).unwrap().to_string(),
            wrapped.to_string()
        );
        assert!(std::error::Error::source(&serialization).is_none());
    }
}
