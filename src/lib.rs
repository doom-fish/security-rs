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

/// Safe wrappers for Authorization Services APIs in Security.framework.
pub mod authorization;
mod bridge;
/// Safe wrappers for `SecCertificateRef` and public-key APIs in Security.framework.
pub mod certificate;
/// Safe wrappers for CMS encoder and decoder APIs in Security.framework.
pub mod cms;
/// Safe wrappers for code-signing APIs such as `SecCodeRef` and `SecTaskRef`.
pub mod code;
/// Re-exports code-signing wrappers built on Security.framework.
pub mod code_signing;
/// Error types used by the Security.framework wrappers.
pub mod error;
#[cfg(feature = "raw-ffi")]
#[cfg_attr(docsrs, doc(cfg(feature = "raw-ffi")))]
pub mod ffi;
/// Safe wrappers for `SecIdentityRef`.
pub mod identity;
/// Safe wrappers for `SecKeyRef` algorithms and private-key APIs.
pub mod key;
/// Safe wrappers for `SecKeyRef` key-agreement APIs.
pub mod key_agreement;
/// Safe wrappers for password-based key-derivation APIs in Security.framework.
pub mod key_derivation;
/// Safe wrappers for keychain and access-control APIs in Security.framework.
pub mod keychain;
/// Safe wrappers for `SecPolicyRef` and policy configuration APIs.
pub mod policy;
/// Re-exports secure-random wrappers built on `SecRandomCopyBytes`.
pub mod random;
/// Safe wrappers for `SecRandomCopyBytes`.
pub mod random_bytes;
/// Safe wrappers for Secure Transport session APIs in Security.framework.
pub mod secure_transport;
/// Safe wrappers for Security Transforms APIs.
pub mod transform;
/// Safe wrappers for `SecTrustRef` and trust-evaluation APIs.
pub mod trust;

pub use authorization::{Authorization, AuthorizationOptions};
pub use certificate::{Certificate, PublicKey};
pub use cms::{
    Cms, CmsCertificateChainMode, CmsDecoder, CmsDigestAlgorithm, CmsEncoder, CmsSignedAttributes,
};
pub use code::{
    Code, CodeSigningFlags, Requirement, SigningInformation, SigningValue, StaticCode, Task,
};
pub use error::{OsStatus, Result, SecurityError, StatusError};
pub use identity::Identity;
pub use key::{
    EncryptionAlgorithm, ExternalFormat, ExternalItemType, KeyType, PrivateKey, SignatureAlgorithm,
};
pub use key_agreement::{AgreementPrivateKey, AgreementPublicKey};
pub use key_derivation::{DerivedKey, KeyDerivation};
pub use keychain::{
    AccessControl, AccessControlFlags, AccessControlProtection, Keychain, KeychainEntry,
};
pub use policy::{Policy, PolicyIdentifier, PolicyName, PolicyProperties, RevocationFlags};
pub use random_bytes::SecureRandom;
pub use secure_transport::{ProtocolVersion, SecureTransportContext, SecureTransportState};
pub use transform::Transform;
pub use trust::{Trust, TrustOptions, TrustResultType};

/// Common imports for users of this crate.
pub mod prelude {
    pub use crate::authorization::{Authorization, AuthorizationOptions};
    pub use crate::certificate::{Certificate, PublicKey};
    pub use crate::cms::{
        Cms, CmsCertificateChainMode, CmsDecoder, CmsDigestAlgorithm, CmsEncoder,
        CmsSignedAttributes,
    };
    pub use crate::code::{
        Code, CodeSigningFlags, Requirement, SigningInformation, SigningValue, StaticCode, Task,
    };
    pub use crate::error::{OsStatus, Result, SecurityError, StatusError};
    pub use crate::identity::Identity;
    pub use crate::key::{
        EncryptionAlgorithm, ExternalFormat, ExternalItemType, KeyType, PrivateKey,
        SignatureAlgorithm,
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
    pub use crate::trust::{Trust, TrustOptions, TrustResultType};
}
