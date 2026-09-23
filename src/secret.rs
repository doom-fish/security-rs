use core::fmt;

use zeroize::Zeroizing;

use crate::error::{Result, SecurityError};

pub struct SecretBytes(Zeroizing<Vec<u8>>);

impl SecretBytes {
    pub(crate) fn new(bytes: Zeroizing<Vec<u8>>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn as_str(&self) -> Result<&str> {
        std::str::from_utf8(&self.0)
            .map_err(|_| SecurityError::InvalidArgument("secret is not valid UTF-8".to_owned()))
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl AsRef<[u8]> for SecretBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBytes(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_output_never_contains_the_secret() {
        let secret = SecretBytes::new(Zeroizing::new(b"hunter2".to_vec()));
        let rendered = format!("{secret:?} {secret:#?}");
        assert!(!rendered.contains("hunter2"));
        assert!(!rendered.contains("104"));
        assert_eq!(rendered, "SecretBytes(<redacted>) SecretBytes(<redacted>)");
    }

    #[test]
    fn exposes_bytes_and_utf8_views() {
        let secret = SecretBytes::new(Zeroizing::new(vec![0xff, 0x00]));
        assert_eq!(secret.as_bytes(), &[0xff, 0x00]);
        assert_eq!(secret.len(), 2);
        assert!(!secret.is_empty());
        assert!(secret.as_str().is_err());
        let text = SecretBytes::new(Zeroizing::new(b"secret".to_vec()));
        assert_eq!(text.as_str().unwrap(), "secret");
    }
}
