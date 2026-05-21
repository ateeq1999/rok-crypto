#[cfg(feature = "hash")]
use crate::util::from_env::FromEnv;

/// A unified crypto provider bundling all primitives.
///
/// Constructed once at application startup and shared via `Arc` or clone.
///
/// # Example
///
/// ```rust,ignore
/// use rok_crypto::provider::CryptoProvider;
///
/// let provider = CryptoProvider::from_env().unwrap();
///
/// let hash = provider.hash_make("password")?;
/// assert!(provider.hash_verify("password", &hash)?);
///
/// let token = provider.encrypt_seal("sensitive");
/// assert_eq!(provider.encrypt_open(&token).unwrap(), "sensitive");
/// ```
#[derive(Clone)]
pub struct CryptoProvider {
    #[cfg(feature = "hash")]
    hasher: crate::hash::Hasher,
    #[cfg(feature = "encrypt")]
    encrypter: crate::encrypt::Encrypter,
    #[cfg(feature = "encrypt")]
    signer: crate::encrypt::Signer,
}

impl CryptoProvider {
    /// Build a provider with hasher only.
    #[cfg(feature = "hash")]
    pub fn new_hash(hasher: crate::hash::Hasher) -> Self {
        Self {
            hasher,
            #[cfg(feature = "encrypt")]
            encrypter: crate::encrypt::Encrypter::from_config(
                crate::encrypt::EncryptConfig::new("change-me"),
            ),
            #[cfg(feature = "encrypt")]
            signer: crate::encrypt::Signer::new("change-me"),
        }
    }

    /// Build a provider with encrypt primitives only.
    #[cfg(feature = "encrypt")]
    pub fn new_encrypt(
        encrypter: crate::encrypt::Encrypter,
        signer: crate::encrypt::Signer,
    ) -> Self {
        Self {
            #[cfg(feature = "hash")]
            hasher: crate::hash::Hasher::from_config(crate::hash::HashConfig::default()),
            encrypter,
            signer,
        }
    }

    /// Build a provider with all primitives.
    #[cfg(all(feature = "hash", feature = "encrypt"))]
    pub fn new(
        hasher: crate::hash::Hasher,
        encrypter: crate::encrypt::Encrypter,
        signer: crate::encrypt::Signer,
    ) -> Self {
        Self {
            hasher,
            encrypter,
            signer,
        }
    }

    /// Build from environment variables.
    ///
    /// Requires:
    /// - `HASH_DRIVER`, `HASH_MEMORY_KIB`, `HASH_ITERATIONS`, `HASH_PARALLELISM` (hash feature)
    /// - `ENCRYPT_KEY` (encrypt feature)
    #[cfg(feature = "hash")]
    pub fn from_env() -> Result<Self, String> {
        let hasher = crate::hash::Hasher::from_env()?;
        Ok(Self {
            hasher,
            #[cfg(feature = "encrypt")]
            encrypter: crate::encrypt::Encrypter::from_env()
                .map_err(|e| e.to_string())?,
            #[cfg(feature = "encrypt")]
            signer: crate::encrypt::Signer::from_env()?,
        })
    }

    /// Access the hasher.
    #[cfg(feature = "hash")]
    pub fn hasher(&self) -> &crate::hash::Hasher {
        &self.hasher
    }

    /// Access the encrypter.
    #[cfg(feature = "encrypt")]
    pub fn encrypter(&self) -> &crate::encrypt::Encrypter {
        &self.encrypter
    }

    /// Access the signer.
    #[cfg(feature = "encrypt")]
    pub fn signer(&self) -> &crate::encrypt::Signer {
        &self.signer
    }

    // ── Delegated hash methods ───────────────────────────────────────────────

    #[cfg(feature = "hash")]
    pub fn hash_make(&self, password: &str) -> Result<String, crate::hash::HashError> {
        self.hasher.make(password)
    }

    #[cfg(feature = "hash")]
    pub fn hash_verify(&self, password: &str, hash: &str) -> Result<bool, crate::hash::HashError> {
        self.hasher.verify(password, hash)
    }

    #[cfg(feature = "hash")]
    pub fn hash_needs_rehash(&self, hash: &str) -> bool {
        self.hasher.needs_rehash(hash)
    }

    // ── Delegated encrypt methods ────────────────────────────────────────────

    #[cfg(feature = "encrypt")]
    pub fn encrypt_seal(&self, value: &str) -> String {
        self.encrypter.seal(value)
    }

    #[cfg(feature = "encrypt")]
    pub fn encrypt_open(&self, token: &str) -> Result<String, crate::encrypt::EncryptError> {
        self.encrypter.open(token)
    }

    #[cfg(feature = "encrypt")]
    pub fn sign_data(&self, data: &str) -> String {
        self.signer.sign(data)
    }

    #[cfg(feature = "encrypt")]
    pub fn verify_signature(&self, data: &str, signature: &str) -> bool {
        self.signer.verify(data, signature)
    }
}
