mod config;
mod error;
mod signer;

pub use config::EncryptConfig;
pub use error::EncryptError;
pub use signer::Signer;

use std::time::Duration;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ── internal token payload ────────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
struct Payload {
    /// The user-supplied value.
    v: String,
    /// Optional purpose tag — set by [`Encrypter::seal_for`].
    #[serde(skip_serializing_if = "Option::is_none")]
    p: Option<String>,
    /// Optional Unix expiry timestamp — set by [`Encrypter::seal_expiring`].
    #[serde(skip_serializing_if = "Option::is_none")]
    e: Option<i64>,
}

// ── key derivation ────────────────────────────────────────────────────────────

fn derive_key(secret: &str) -> [u8; 32] {
    Sha256::digest(secret.as_bytes()).into()
}

// ── Encrypter ─────────────────────────────────────────────────────────────────

/// AES-256-GCM encryption façade with purpose-binding, token expiry, and key
/// rotation.
///
/// # Token format
///
/// Tokens are URL-safe base64 strings: `base64url(nonce[12] || ciphertext)`.
/// The plaintext is a compact JSON payload containing the value and optional
/// metadata.
///
/// # Example
///
/// ```rust,ignore
/// use std::time::Duration;
/// use rok_crypto::encrypt::{EncryptConfig, Encrypter};
///
/// let enc = Encrypter::from_config(EncryptConfig::new("my-app-secret"));
///
/// // Basic round-trip
/// let token = enc.seal("hello");
/// assert_eq!(enc.open(&token).unwrap(), "hello");
///
/// // Purpose-bound (e.g. password-reset tokens)
/// let token = enc.seal_for("pw-reset", "user@example.com");
/// assert!(enc.open_for("pw-reset", &token).is_ok());
/// assert!(enc.open_for("invite",   &token).is_err()); // wrong purpose
///
/// // Expiring token
/// let token = enc.seal_expiring("data", Duration::from_secs(3600));
/// assert!(enc.open(&token).is_ok());
/// ```
#[derive(Clone)]
pub struct Encrypter {
    primary_key: [u8; 32],
    old_keys: Vec<[u8; 32]>,
}

impl Encrypter {
    /// Build an `Encrypter` from `config`.
    pub fn from_config(config: EncryptConfig) -> Self {
        Self {
            primary_key: derive_key(&config.key),
            old_keys: config.old_keys.iter().map(|k| derive_key(k)).collect(),
        }
    }

    // ── internal helpers ──────────────────────────────────────────────────────

    fn cipher(key: &[u8; 32]) -> Aes256Gcm {
        Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key))
    }

    fn encrypt_payload(&self, payload: &Payload) -> String {
        let json = serde_json::to_vec(payload).expect("Payload is always serialisable");
        let nonce_bytes: [u8; 12] = rand::random();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let mut ct = Self::cipher(&self.primary_key)
            .encrypt(nonce, json.as_slice())
            .expect("AES-256-GCM encryption is infallible for valid keys");
        let mut out = nonce_bytes.to_vec();
        out.append(&mut ct);
        URL_SAFE_NO_PAD.encode(out)
    }

    fn decrypt_token(&self, token: &str) -> Result<Payload, EncryptError> {
        let bytes = URL_SAFE_NO_PAD
            .decode(token)
            .map_err(|_| EncryptError::InvalidFormat)?;
        if bytes.len() <= 12 {
            return Err(EncryptError::InvalidFormat);
        }
        let (nonce_bytes, ciphertext) = bytes.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        // Try primary key, then old keys (key rotation).
        let keys = std::iter::once(&self.primary_key).chain(self.old_keys.iter());
        for key in keys {
            if let Ok(plaintext) = Self::cipher(key).decrypt(nonce, ciphertext) {
                return serde_json::from_slice(&plaintext).map_err(|_| EncryptError::InvalidFormat);
            }
        }
        Err(EncryptError::DecryptionFailed)
    }

    fn check_expiry(payload: &Payload) -> Result<(), EncryptError> {
        if let Some(exp) = payload.e {
            if chrono::Utc::now().timestamp() > exp {
                return Err(EncryptError::Expired);
            }
        }
        Ok(())
    }

    // ── public API ────────────────────────────────────────────────────────────

    /// Encrypt `value` and return a self-contained token.
    pub fn seal(&self, value: &str) -> String {
        self.encrypt_payload(&Payload {
            v: value.to_string(),
            p: None,
            e: None,
        })
    }

    /// Decrypt `token` and return the original value.
    ///
    /// Returns `Err(Expired)` if the token carries an expiry that has passed.
    pub fn open(&self, token: &str) -> Result<String, EncryptError> {
        let payload = self.decrypt_token(token)?;
        Self::check_expiry(&payload)?;
        Ok(payload.v)
    }

    /// Like [`open`](Self::open) but returns `None` instead of an error.
    pub fn try_open(&self, token: &str) -> Option<String> {
        self.open(token).ok()
    }

    // ── purpose-bound ─────────────────────────────────────────────────────────

    /// Encrypt `value` bound to `purpose`.
    ///
    /// The resulting token can only be opened with the same `purpose` via
    /// [`open_for`](Self::open_for).
    pub fn seal_for(&self, purpose: &str, value: &str) -> String {
        self.encrypt_payload(&Payload {
            v: value.to_string(),
            p: Some(purpose.to_string()),
            e: None,
        })
    }

    /// Decrypt a purpose-bound token, verifying that its purpose matches
    /// `expected_purpose`.
    ///
    /// Returns `Err(WrongPurpose)` on a mismatch, `Err(Expired)` if expired.
    pub fn open_for(&self, expected_purpose: &str, token: &str) -> Result<String, EncryptError> {
        let payload = self.decrypt_token(token)?;
        let actual = payload.p.as_deref().unwrap_or("(none)");
        if actual != expected_purpose {
            return Err(EncryptError::WrongPurpose {
                expected: expected_purpose.to_string(),
                actual: actual.to_string(),
            });
        }
        Self::check_expiry(&payload)?;
        Ok(payload.v)
    }

    // ── expiring tokens ───────────────────────────────────────────────────────

    /// Encrypt `value` with an expiry of `ttl` from now.
    ///
    /// Opening the token after `ttl` has elapsed returns `Err(Expired)`.
    pub fn seal_expiring(&self, value: &str, ttl: Duration) -> String {
        let expires_at = chrono::Utc::now().timestamp() + ttl.as_secs() as i64;
        self.encrypt_payload(&Payload {
            v: value.to_string(),
            p: None,
            e: Some(expires_at),
        })
    }

    /// Encrypt `value` bound to `purpose` with an expiry of `ttl` from now.
    pub fn seal_for_expiring(&self, purpose: &str, value: &str, ttl: Duration) -> String {
        let expires_at = chrono::Utc::now().timestamp() + ttl.as_secs() as i64;
        self.encrypt_payload(&Payload {
            v: value.to_string(),
            p: Some(purpose.to_string()),
            e: Some(expires_at),
        })
    }
}
