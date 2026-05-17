use serde::Serialize;
use serde_json::Value;

use crate::bridge::{self, Handle};
use crate::error::{Result, SecurityError};

pub type RevocationFlags = u32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PolicyIdentifier {
    AppleX509Basic,
    AppleSsl,
    AppleSmime,
    AppleEap,
    AppleIpsec,
    ApplePkinitClient,
    ApplePkinitServer,
    AppleCodeSigning,
    MacAppStoreReceipt,
    AppleIdValidation,
    AppleTimeStamping,
    AppleRevocation,
    ApplePassbookSigning,
    ApplePayIssuerEncryption,
    AppleSslServer,
    AppleSslClient,
    AppleEapServer,
    AppleEapClient,
    AppleIpsecServer,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum PolicyName {
    Single(String),
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

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
pub struct PolicyProperties {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<PolicyName>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_flags: Option<RevocationFlags>,
    #[serde(skip_serializing_if = "Option::is_none")]
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
pub struct Policy {
    handle: Handle,
}

impl Policy {
    pub fn type_id() -> usize {
        unsafe { bridge::security_policy_get_type_id() }
    }

    pub(crate) fn from_handle(handle: Handle) -> Self {
        Self { handle }
    }

    pub(crate) fn handle(&self) -> &Handle {
        &self.handle
    }

    pub fn basic_x509() -> Result<Self> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe { bridge::security_policy_create_basic_x509(&mut status, &mut error) };
        bridge::required_handle("security_policy_create_basic_x509", raw, status, error)
            .map(Self::from_handle)
    }

    pub fn ssl(server: bool, hostname: Option<&str>) -> Result<Self> {
        let hostname = hostname.map(bridge::cstring).transpose()?;
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_policy_create_ssl(
                server,
                hostname
                    .as_ref()
                    .map_or(std::ptr::null(), |value| value.as_c_str().as_ptr()),
                &mut status,
                &mut error,
            )
        };
        bridge::required_handle("security_policy_create_ssl", raw, status, error)
            .map(Self::from_handle)
    }

    pub fn revocation(flags: RevocationFlags) -> Result<Self> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw =
            unsafe { bridge::security_policy_create_revocation(flags, &mut status, &mut error) };
        bridge::required_handle("security_policy_create_revocation", raw, status, error)
            .map(Self::from_handle)
    }

    pub fn with_properties(
        identifier: PolicyIdentifier,
        properties: &PolicyProperties,
    ) -> Result<Self> {
        let identifier = bridge::cstring(identifier.as_bridge_name())?;
        let properties = if properties.is_empty() {
            None
        } else {
            let json = serde_json::to_string(properties).map_err(|error| {
                SecurityError::Serialization(format!("policy properties JSON failed: {error}"))
            })?;
            Some(bridge::cstring(&json)?)
        };
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_policy_create_with_properties(
                identifier.as_ptr(),
                properties
                    .as_ref()
                    .map_or(std::ptr::null(), |value| value.as_c_str().as_ptr()),
                &mut status,
                &mut error,
            )
        };
        bridge::required_handle("security_policy_create_with_properties", raw, status, error)
            .map(Self::from_handle)
    }

    pub fn properties(&self) -> Result<Value> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_policy_copy_properties(self.handle.as_ptr(), &mut status, &mut error)
        };
        bridge::required_json("security_policy_copy_properties", raw, status, error)
    }
}
