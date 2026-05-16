#![doc = include_str!("../README.md")]
//!
//! ---
//!
//! # API documentation
//!
//! Safe Rust bindings for Apple's `Security.framework` on macOS.

#![cfg_attr(docsrs, feature(doc_cfg))]
#![allow(
    clippy::missing_const_for_fn,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::needless_pass_by_value,
    clippy::option_if_let_else,
    clippy::redundant_pub_crate,
    clippy::unnecessary_lazy_evaluations
)]

pub mod authorization;
mod bridge;
pub mod certificate;
pub mod cms;
pub mod code;
pub mod code_signing;
pub mod error;
#[cfg(feature = "raw-ffi")]
#[cfg_attr(docsrs, doc(cfg(feature = "raw-ffi")))]
pub mod ffi;
pub mod identity;
pub mod key;
pub mod key_agreement;
pub mod key_derivation;
pub mod keychain;
pub mod policy;
pub mod random;
pub mod random_bytes;
pub mod secure_transport;
pub mod transform;
pub mod trust;

pub use authorization::{Authorization, AuthorizationOptions};
pub use certificate::{Certificate, PublicKey};
pub use cms::Cms;
pub use code::{Code, SigningInformation, SigningValue, StaticCode, Task};
pub use error::{OsStatus, Result, SecurityError, StatusError};
pub use identity::Identity;
pub use key::{ExternalFormat, ExternalItemType, KeyType, PrivateKey, SignatureAlgorithm};
pub use key_agreement::{AgreementPrivateKey, AgreementPublicKey};
pub use key_derivation::{DerivedKey, KeyDerivation};
pub use keychain::{
    AccessControl, AccessControlFlags, AccessControlProtection, Keychain, KeychainEntry,
};
pub use policy::{Policy, PolicyIdentifier, PolicyName, PolicyProperties, RevocationFlags};
pub use random_bytes::SecureRandom;
pub use secure_transport::{ProtocolVersion, SecureTransportContext, SecureTransportState};
pub use transform::Transform;
pub use trust::Trust;

/// Common imports for users of this crate.
pub mod prelude {
    pub use crate::authorization::{Authorization, AuthorizationOptions};
    pub use crate::certificate::{Certificate, PublicKey};
    pub use crate::cms::Cms;
    pub use crate::code::{Code, SigningInformation, SigningValue, StaticCode, Task};
    pub use crate::error::{OsStatus, Result, SecurityError, StatusError};
    pub use crate::identity::Identity;
    pub use crate::key::{
        ExternalFormat, ExternalItemType, KeyType, PrivateKey, SignatureAlgorithm,
    };
    pub use crate::key_agreement::{AgreementPrivateKey, AgreementPublicKey};
    pub use crate::key_derivation::{DerivedKey, KeyDerivation};
    pub use crate::keychain::{
        AccessControl, AccessControlFlags, AccessControlProtection, Keychain, KeychainEntry,
    };
    pub use crate::policy::{
        Policy, PolicyIdentifier, PolicyName, PolicyProperties, RevocationFlags,
    };
    pub use crate::random_bytes::SecureRandom;
    pub use crate::secure_transport::{
        ProtocolVersion, SecureTransportContext, SecureTransportState,
    };
    pub use crate::transform::Transform;
    pub use crate::trust::Trust;
}
