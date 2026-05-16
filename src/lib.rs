#![doc = include_str!("../README.md")]
//!
//! ---
//!
//! # API documentation
//!
//! Safe Rust bindings for Apple's `Security.framework` on macOS.

#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod certificate;
pub mod code_signing;
pub mod error;
pub mod ffi;
pub mod keychain;
mod private;
pub mod random;
pub mod trust;

pub use certificate::{Certificate, PublicKey};
pub use code_signing::{Code, SigningInformation, SigningValue};
pub use error::{Result, SecurityError, StatusError};
pub use keychain::{Keychain, KeychainEntry};
pub use random::SecureRandom;
pub use trust::{Policy, Trust};

/// Common imports for users of this crate.
pub mod prelude {
    pub use crate::certificate::{Certificate, PublicKey};
    pub use crate::code_signing::{Code, SigningInformation, SigningValue};
    pub use crate::error::{Result, SecurityError, StatusError};
    pub use crate::keychain::{Keychain, KeychainEntry};
    pub use crate::random::SecureRandom;
    pub use crate::trust::{Policy, Trust};
}
