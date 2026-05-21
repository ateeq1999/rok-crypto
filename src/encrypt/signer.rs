use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::config::EncryptConfig;

type HmacSha256 = Hmac<Sha256>;

/// HMAC-SHA256 signer for producing and verifying message authentication codes.
///
/// # Example
///
/// ```rust,ignore
/// use rok_encrypt::{EncryptConfig, Signer};
///
/// let signer = Signer::from_config(&EncryptConfig::new("my-secret"));
/// let sig = signer.sign("some data");
/// assert!(signer.verify("some data", &sig));
/// ```
#[derive(Clone)]
pub struct Signer {
    key: Vec<u8>,
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
    pub fn verify(&self, data: &str, signature: &str) -> bool {
        let Ok(sig_bytes) = URL_SAFE_NO_PAD.decode(signature) else {
            return false;
        };
        let mut mac =
            HmacSha256::new_from_slice(&self.key).expect("HMAC accepts keys of any length");
        mac.update(data.as_bytes());
        mac.verify_slice(&sig_bytes).is_ok()
    }
}
