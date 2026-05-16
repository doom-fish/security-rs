use serde_json::Value;

use crate::bridge;
use crate::error::Result;

#[derive(Debug)]
pub struct AgreementPublicKey {
    handle: bridge::Handle,
}

impl AgreementPublicKey {
    fn from_handle(handle: bridge::Handle) -> Self {
        Self { handle }
    }

    pub fn attributes(&self) -> Result<Value> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_key_copy_attributes(self.handle.as_ptr(), &mut status, &mut error)
        };
        bridge::required_json("security_key_copy_attributes", raw, status, error)
    }
}

#[derive(Debug)]
pub struct AgreementPrivateKey {
    handle: bridge::Handle,
}

impl AgreementPrivateKey {
    pub fn generate_p256() -> Result<Self> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_key_agreement_generate_p256_private_key(&mut status, &mut error)
        };
        bridge::required_handle(
            "security_key_agreement_generate_p256_private_key",
            raw,
            status,
            error,
        )
        .map(|handle| Self { handle })
    }

    pub fn public_key(&self) -> Result<AgreementPublicKey> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_key_copy_public_key(self.handle.as_ptr(), &mut status, &mut error)
        };
        bridge::required_handle("security_key_copy_public_key", raw, status, error)
            .map(AgreementPublicKey::from_handle)
    }

    pub fn is_supported(&self) -> bool {
        unsafe { bridge::security_key_agreement_is_supported(self.handle.as_ptr()) }
    }

    pub fn shared_secret(
        &self,
        peer_public_key: &AgreementPublicKey,
        requested_size: usize,
        shared_info: &[u8],
    ) -> Result<Vec<u8>> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_key_agreement_compute_shared_secret(
                self.handle.as_ptr(),
                peer_public_key.handle.as_ptr(),
                bridge::len_to_isize(requested_size)?,
                shared_info.as_ptr().cast(),
                bridge::len_to_isize(shared_info.len())?,
                &mut status,
                &mut error,
            )
        };
        bridge::required_data(
            "security_key_agreement_compute_shared_secret",
            raw,
            status,
            error,
        )
    }
}
