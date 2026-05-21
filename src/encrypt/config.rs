/// Configuration for [`Encrypter`](crate::encrypt::Encrypter) and [`Signer`](crate::encrypt::Signer).
#[derive(Debug, Clone)]
pub struct EncryptConfig {
    /// Primary encryption / signing key.
    ///
    /// Derived to a 256-bit AES key via SHA-256.  Must not be empty.
    pub key: String,

    /// Previous keys used for decryption-only (key rotation).
    ///
    /// Encryption always uses `key`; decryption falls back to each `old_key`
    /// in order if the primary key fails.
    pub old_keys: Vec<String>,
}

impl EncryptConfig {
    pub fn new(key: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            old_keys: Vec::new(),
        }
    }

    pub fn with_old_keys(mut self, old_keys: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.old_keys = old_keys.into_iter().map(|k| k.into()).collect();
        self
    }

    /// Build from `ENCRYPT_KEY` env var, optionally `ENCRYPT_OLD_KEYS` (comma-separated).
    pub fn from_env() -> Result<Self, super::EncryptError> {
        let key = std::env::var("ENCRYPT_KEY")
            .map_err(|_| super::EncryptError::invalid_format("missing ENCRYPT_KEY env var"))?;
        let old_keys = std::env::var("ENCRYPT_OLD_KEYS")
            .ok()
            .filter(|s| !s.is_empty())
            .map(|s| s.split(',').map(|k| k.trim().to_string()).collect())
            .unwrap_or_default();
        Ok(Self { key, old_keys })
    }
}
