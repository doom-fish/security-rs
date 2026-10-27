use crate::Value;

use crate::bridge::{self, Handle};
use crate::error::{Result, SecurityError};

/// Mirrors `SecRevocationFlags`.
pub type RevocationFlags = u32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
/// Mirrors named `SecPolicyCreate*` policy selectors.
pub enum PolicyIdentifier {
    /// Mirrors a named `SecPolicyCreate*` selector.
    AppleX509Basic,
    /// Mirrors a named `SecPolicyCreate*` selector.
    AppleSsl,
    /// Mirrors a named `SecPolicyCreate*` selector.
    AppleSmime,
    /// Mirrors a named `SecPolicyCreate*` selector.
    AppleEap,
    /// Mirrors a named `SecPolicyCreate*` selector.
    AppleIpsec,
    /// Mirrors a named `SecPolicyCreate*` selector.
    ApplePkinitClient,
    /// Mirrors a named `SecPolicyCreate*` selector.
    ApplePkinitServer,
    /// Mirrors a named `SecPolicyCreate*` selector.
    AppleCodeSigning,
    /// Mirrors a named `SecPolicyCreate*` selector.
    MacAppStoreReceipt,
    /// Mirrors a named `SecPolicyCreate*` selector.
    AppleIdValidation,
    /// Mirrors a named `SecPolicyCreate*` selector.
    AppleTimeStamping,
    /// Mirrors a named `SecPolicyCreate*` selector.
    AppleRevocation,
    /// Mirrors a named `SecPolicyCreate*` selector.
    ApplePassbookSigning,
    /// Mirrors a named `SecPolicyCreate*` selector.
    ApplePayIssuerEncryption,
    /// Mirrors a named `SecPolicyCreate*` selector.
    AppleSslServer,
    /// Mirrors a named `SecPolicyCreate*` selector.
    AppleSslClient,
    /// Mirrors a named `SecPolicyCreate*` selector.
    AppleEapServer,
    /// Mirrors a named `SecPolicyCreate*` selector.
    AppleEapClient,
    /// Mirrors a named `SecPolicyCreate*` selector.
    AppleIpsecServer,
    /// Mirrors a named `SecPolicyCreate*` selector.
    AppleIpsecClient,
}

impl PolicyIdentifier {
    const fn as_bridge_name(self) -> &'static str {
        match self {
            Self::AppleX509Basic => "apple_x509_basic",
            Self::AppleSsl => "apple_ssl",
            Self::AppleSmime => "apple_smime",
            Self::AppleEap => "apple_eap",
            Self::AppleIpsec => "apple_ipsec",
            Self::ApplePkinitClient => "apple_pkinit_client",
            Self::ApplePkinitServer => "apple_pkinit_server",
            Self::AppleCodeSigning => "apple_code_signing",
            Self::MacAppStoreReceipt => "mac_app_store_receipt",
            Self::AppleIdValidation => "apple_id_validation",
            Self::AppleTimeStamping => "apple_time_stamping",
            Self::AppleRevocation => "apple_revocation",
            Self::ApplePassbookSigning => "apple_passbook_signing",
            Self::ApplePayIssuerEncryption => "apple_pay_issuer_encryption",
            Self::AppleSslServer => "apple_ssl_server",
            Self::AppleSslClient => "apple_ssl_client",
            Self::AppleEapServer => "apple_eap_server",
            Self::AppleEapClient => "apple_eap_client",
            Self::AppleIpsecServer => "apple_ipsec_server",
            Self::AppleIpsecClient => "apple_ipsec_client",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Mirrors name inputs passed to `SecPolicyCreateWithProperties`.
pub enum PolicyName {
    /// Mirrors a name form accepted by `SecPolicyCreateWithProperties`.
    Single(String),
    /// Mirrors a name form accepted by `SecPolicyCreateWithProperties`.
    Multiple(Vec<String>),
}

impl From<String> for PolicyName {
    fn from(value: String) -> Self {
        Self::Single(value)
    }
}

impl From<&str> for PolicyName {
    fn from(value: &str) -> Self {
        Self::Single(value.to_owned())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
/// Mirrors the property dictionary passed to `SecPolicyCreateWithProperties`.
pub struct PolicyProperties {
    /// Mirrors a property accepted by `SecPolicyCreateWithProperties`.
    pub name: Option<PolicyName>,
    /// Mirrors a property accepted by `SecPolicyCreateWithProperties`.
    pub client: Option<bool>,
    /// Mirrors a property accepted by `SecPolicyCreateWithProperties`.
    pub revocation_flags: Option<RevocationFlags>,
    /// Mirrors a property accepted by `SecPolicyCreateWithProperties`.
    pub team_identifier: Option<String>,
}

impl PolicyProperties {
    const fn is_empty(&self) -> bool {
        self.name.is_none()
            && self.client.is_none()
            && self.revocation_flags.is_none()
            && self.team_identifier.is_none()
    }
}

#[derive(Debug)]
/// Wraps `SecPolicyRef`.
pub struct Policy {
    handle: Handle,
}

impl Policy {
    /// Wraps the corresponding `SecPolicyRef` operation.
    pub fn type_id() -> usize {
        unsafe { bridge::security_policy_get_type_id() }
    }

    pub(crate) fn from_handle(handle: Handle) -> Self {
        Self { handle }
    }

    pub(crate) fn handle(&self) -> &Handle {
        &self.handle
    }

    /// Wraps the corresponding `SecPolicyRef` operation.
    pub fn basic_x509() -> Result<Self> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw =
            unsafe { bridge::security_policy_create_basic_x509(&raw mut status, &raw mut error) };
        bridge::required_handle("security_policy_create_basic_x509", raw, status, error)
            .map(Self::from_handle)
    }

    /// Wraps `SecPolicyCreateSSL` and requires the leaf certificate to be valid for `hostname`.
    pub fn ssl(server: bool, hostname: &str) -> Result<Self> {
        if hostname.is_empty() {
            return Err(SecurityError::InvalidArgument(
                "an SSL policy needs a hostname; Policy::ssl_any_hostname skips the check"
                    .to_owned(),
            ));
        }
        let hostname = bridge::cstring(hostname)?;
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_policy_create_ssl(
                server,
                hostname.as_ptr(),
                &raw mut status,
                &raw mut error,
            )
        };
        bridge::required_handle("security_policy_create_ssl", raw, status, error)
            .map(Self::from_handle)
    }

    pub fn ssl_any_hostname(server: bool) -> Result<Self> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_policy_create_ssl(
                server,
                std::ptr::null(),
                &raw mut status,
                &raw mut error,
            )
        };
        bridge::required_handle("security_policy_create_ssl", raw, status, error)
            .map(Self::from_handle)
    }

    /// Wraps the corresponding `SecPolicyRef` operation.
    pub fn revocation(flags: RevocationFlags) -> Result<Self> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_policy_create_revocation(flags, &raw mut status, &raw mut error)
        };
        bridge::required_handle("security_policy_create_revocation", raw, status, error)
            .map(Self::from_handle)
    }

    /// Wraps the corresponding `SecPolicyRef` operation.
    pub fn with_properties(
        identifier: PolicyIdentifier,
        properties: &PolicyProperties,
    ) -> Result<Self> {
        let identifier = bridge::cstring(identifier.as_bridge_name())?;
        let properties = if properties.is_empty() {
            None
        } else {
            let mut values = std::collections::BTreeMap::new();
            if let Some(name) = &properties.name {
                let name = match name {
                    PolicyName::Single(value) => Value::String(value.clone()),
                    PolicyName::Multiple(values) => {
                        Value::Array(values.iter().cloned().map(Value::String).collect())
                    }
                };
                values.insert("name".to_owned(), name);
            }
            if let Some(client) = properties.client {
                values.insert("client".to_owned(), Value::Bool(client));
            }
            if let Some(flags) = properties.revocation_flags {
                values.insert(
                    "revocation_flags".to_owned(),
                    Value::Unsigned(u64::from(flags)),
                );
            }
            if let Some(identifier) = &properties.team_identifier {
                values.insert(
                    "team_identifier".to_owned(),
                    Value::String(identifier.clone()),
                );
            }
            Some(bridge::InputValue::new(&Value::Object(values))?)
        };
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_policy_create_with_properties(
                identifier.as_ptr(),
                properties
                    .as_ref()
                    .map_or(std::ptr::null(), bridge::InputValue::as_ptr),
                &raw mut status,
                &raw mut error,
            )
        };
        bridge::required_handle("security_policy_create_with_properties", raw, status, error)
            .map(Self::from_handle)
    }

    /// Wraps the corresponding `SecPolicyRef` operation.
    pub fn properties(&self) -> Result<Value> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_policy_copy_properties(
                self.handle.as_ptr(),
                &raw mut status,
                &raw mut error,
            )
        };
        bridge::required_value("security_policy_copy_properties", raw, status, error)
    }
}
