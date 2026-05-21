use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use thiserror::Error;

use crate::util::from_env::FromEnv;
use super::config::EncryptConfig;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SignError {
    #[error("invalid base64 signature")]
    InvalidBase64,

    #[error("signature does not match")]
    InvalidSignature,
}

/// HMAC-SHA256 signer for producing and verifying message authentication codes.
///
/// # Example
///
/// ```rust,ignore
/// use rok_crypto::encrypt::{EncryptConfig, Signer};
///
/// let signer = Signer::from_config(&EncryptConfig::new("my-secret"));
/// let sig = signer.sign("some data");
/// assert!(signer.verify("some data", &sig));
/// ```
#[derive(Clone)]
pub struct Signer {
    pub(crate) key: Vec<u8>,
}

impl Signer {
    pub fn new(key: impl AsRef<str>) -> Self {
        Self {
            key: key.as_ref().as_bytes().to_vec(),
        }
    }

    pub fn from_config(config: &EncryptConfig) -> Self {
        Self::new(&config.key)
    }

    /// Produce a URL-safe base64-encoded HMAC-SHA256 signature of `data`.
    pub fn sign(&self, data: &str) -> String {
        let mut mac =
            HmacSha256::new_from_slice(&self.key).expect("HMAC accepts keys of any length");
        mac.update(data.as_bytes());
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    }

    /// Return `true` if `signature` is a valid HMAC-SHA256 of `data`.
    ///
    /// Silently returns `false` for invalid base64 or mismatched signatures.
    /// Use [`try_verify`](Self::try_verify) to distinguish the two cases.
    pub fn verify(&self, data: &str, signature: &str) -> bool {
        self.try_verify(data, signature).unwrap_or(false)
    }

    /// Return `Ok(true)` if valid, `Err(SignError)` if invalid base64 or mismatch.
    pub fn try_verify(&self, data: &str, signature: &str) -> Result<bool, SignError> {
        let sig_bytes = URL_SAFE_NO_PAD
            .decode(signature)
            .map_err(|_| SignError::InvalidBase64)?;
        let mut mac =
            HmacSha256::new_from_slice(&self.key).expect("HMAC accepts keys of any length");
        mac.update(data.as_bytes());
        Ok(mac.verify_slice(&sig_bytes).is_ok())
    }
}

impl FromEnv for Signer {
    type Error = String;

    fn from_env() -> Result<Self, Self::Error> {
        let key = std::env::var("SIGN_KEY")
            .or_else(|_| std::env::var("ENCRYPT_KEY"))
            .map_err(|_| "missing SIGN_KEY or ENCRYPT_KEY environment variable".to_string())?;
        Ok(Self::new(key))
    }
}

#[cfg(feature = "zeroize")]
impl zeroize::Zeroize for Signer {
    fn zeroize(&mut self) {
        self.key.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl zeroize::ZeroizeOnDrop for Signer {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify() {
        let s = Signer::new("my-key");
        let sig = s.sign("some data");
        assert!(s.verify("some data", &sig));
    }

    #[test]
    fn try_verify_ok() {
        let s = Signer::new("key");
        let sig = s.sign("data");
        assert_eq!(s.try_verify("data", &sig), Ok(true));
    }

    #[test]
    fn try_verify_wrong_data() {
        let s = Signer::new("key");
        let sig = s.sign("original");
        assert_eq!(s.try_verify("tampered", &sig), Ok(false));
    }

    #[test]
    fn try_verify_invalid_base64() {
        let s = Signer::new("key");
        assert!(matches!(s.try_verify("data", "!!!invalid!!!"), Err(SignError::InvalidBase64)));
    }

    #[test]
    fn verify_wrong_key() {
        let s1 = Signer::new("key-1");
        let s2 = Signer::new("key-2");
        let sig = s1.sign("data");
        assert!(!s2.verify("data", &sig));
    }
}
