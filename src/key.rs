use serde_json::Value;

use crate::bridge::{self, Handle};
use crate::certificate::PublicKey;
use crate::error::Result;

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExternalFormat {
    Unknown = 0,
    OpenSsl = 1,
    Ssh = 2,
    Bsafe = 3,
    RawKey = 4,
    WrappedPkcs8 = 5,
    WrappedOpenSsl = 6,
    WrappedSsh = 7,
    WrappedLsh = 8,
    X509Certificate = 9,
    PemSequence = 10,
    Pkcs7 = 11,
    Pkcs12 = 12,
    NetscapeCertificateSequence = 13,
    SshV2 = 14,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExternalItemType {
    Unknown = 0,
    PrivateKey = 1,
    PublicKey = 2,
    SessionKey = 3,
    Certificate = 4,
    Aggregate = 5,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyType {
    Rsa = 0,
    EcSecPrimeRandom = 1,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignatureAlgorithm {
    RsaSignatureMessagePkcs1v15Sha256 = 0,
    RsaSignatureDigestPkcs1v15Sha256 = 1,
    RsaSignatureMessagePssSha256 = 2,
    EcdsaSignatureMessageX962Sha256 = 3,
    EcdsaSignatureDigestX962Sha256 = 4,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EncryptionAlgorithm {
    RsaEncryptionRaw = 0,
    RsaEncryptionPkcs1 = 1,
    RsaEncryptionOaepSha1 = 2,
    RsaEncryptionOaepSha224 = 3,
    RsaEncryptionOaepSha256 = 4,
    RsaEncryptionOaepSha384 = 5,
    RsaEncryptionOaepSha512 = 6,
    RsaEncryptionOaepSha1AesGcm = 7,
    RsaEncryptionOaepSha224AesGcm = 8,
    RsaEncryptionOaepSha256AesGcm = 9,
    RsaEncryptionOaepSha384AesGcm = 10,
    RsaEncryptionOaepSha512AesGcm = 11,
}

pub(crate) fn key_type_id() -> usize {
    unsafe { bridge::security_key_get_type_id() }
}

pub(crate) fn key_block_size(handle: &Handle) -> usize {
    usize::try_from(unsafe { bridge::security_key_get_block_size(handle.as_ptr()) })
        .unwrap_or_default()
}

pub(crate) fn key_external_representation(handle: &Handle) -> Result<Vec<u8>> {
    let mut status = 0;
    let mut error = std::ptr::null_mut();
    let raw = unsafe {
        bridge::security_key_copy_external_representation(handle.as_ptr(), &mut status, &mut error)
    };
    bridge::required_data("security_key_copy_external_representation", raw, status, error)
}

pub(crate) fn encrypt_with_public_key(
    handle: &Handle,
    algorithm: EncryptionAlgorithm,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let mut status = 0;
    let mut error = std::ptr::null_mut();
    let raw = unsafe {
        bridge::security_public_key_create_encrypted_data(
            handle.as_ptr(),
            algorithm as u32,
            plaintext.as_ptr().cast(),
            bridge::len_to_isize(plaintext.len())?,
            &mut status,
            &mut error,
        )
    };
    bridge::required_data("security_public_key_create_encrypted_data", raw, status, error)
}

pub(crate) fn decrypt_with_private_key(
    handle: &Handle,
    algorithm: EncryptionAlgorithm,
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let mut status = 0;
    let mut error = std::ptr::null_mut();
    let raw = unsafe {
        bridge::security_private_key_create_decrypted_data(
            handle.as_ptr(),
            algorithm as u32,
            ciphertext.as_ptr().cast(),
            bridge::len_to_isize(ciphertext.len())?,
            &mut status,
            &mut error,
        )
    };
    bridge::required_data("security_private_key_create_decrypted_data", raw, status, error)
}

#[derive(Debug)]
pub struct PrivateKey {
    handle: Handle,
}

impl PrivateKey {
    pub fn type_id() -> usize {
        key_type_id()
    }

    pub(crate) fn from_handle(handle: Handle) -> Self {
        Self { handle }
    }

    pub(crate) fn handle(&self) -> &Handle {
        &self.handle
    }

    pub fn from_data(data: &[u8], key_type: KeyType, key_size_bits: usize) -> Result<Self> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_private_key_create_with_data(
                data.as_ptr().cast(),
                bridge::len_to_isize(data.len())?,
                key_type as u32,
                bridge::len_to_isize(key_size_bits)?,
                &mut status,
                &mut error,
            )
        };
        bridge::required_handle("security_private_key_create_with_data", raw, status, error)
            .map(Self::from_handle)
    }

    pub fn import_item(
        data: &[u8],
        file_name_or_extension: Option<&str>,
        format: ExternalFormat,
        item_type: ExternalItemType,
    ) -> Result<Self> {
        let file_name_or_extension = file_name_or_extension.map(bridge::cstring).transpose()?;
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_private_key_import_item(
                data.as_ptr().cast(),
                bridge::len_to_isize(data.len())?,
                file_name_or_extension
                    .as_ref()
                    .map_or(std::ptr::null(), |value| value.as_ptr()),
                format as u32,
                item_type as u32,
                &mut status,
                &mut error,
            )
        };
        bridge::required_handle("security_private_key_import_item", raw, status, error)
            .map(Self::from_handle)
    }

    pub fn import_pem(pem: &[u8]) -> Result<Self> {
        Self::import_item(
            pem,
            Some(".pem"),
            ExternalFormat::Unknown,
            ExternalItemType::PrivateKey,
        )
    }

    pub fn public_key(&self) -> Result<PublicKey> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_key_copy_public_key(self.handle.as_ptr(), &mut status, &mut error)
        };
        bridge::required_handle("security_key_copy_public_key", raw, status, error)
            .map(PublicKey::from_handle)
    }

    pub fn attributes(&self) -> Result<Value> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_key_copy_attributes(self.handle.as_ptr(), &mut status, &mut error)
        };
        bridge::required_json("security_key_copy_attributes", raw, status, error)
    }

    pub fn block_size(&self) -> usize {
        key_block_size(&self.handle)
    }

    pub fn external_representation(&self) -> Result<Vec<u8>> {
        key_external_representation(&self.handle)
    }

    pub fn sign(&self, algorithm: SignatureAlgorithm, data: &[u8]) -> Result<Vec<u8>> {
        let mut status = 0;
        let mut error = std::ptr::null_mut();
        let raw = unsafe {
            bridge::security_private_key_create_signature(
                self.handle.as_ptr(),
                algorithm as u32,
                data.as_ptr().cast(),
                bridge::len_to_isize(data.len())?,
                &mut status,
                &mut error,
            )
        };
        bridge::required_data("security_private_key_create_signature", raw, status, error)
    }

    pub fn decrypt(
        &self,
        algorithm: EncryptionAlgorithm,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        decrypt_with_private_key(&self.handle, algorithm, ciphertext)
    }
}
