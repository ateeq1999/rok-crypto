use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hmac::{Hmac, Mac};
use serde::{de::DeserializeOwned, Serialize};
use sha2::Sha256;
use thiserror::Error;

type HmacSha256 = Hmac<Sha256>;

/// Minimal HS256 JWT signer and verifier.
///
/// Produces compact JWT tokens (header.payload.signature) using HMAC-SHA256.
///
/// # Example
///
/// ```rust
/// use serde::{Serialize, Deserialize};
/// use rok_crypto::jwt::JwtSigner;
///
/// #[derive(Debug, Serialize, Deserialize)]
/// struct Claims {
///     sub: String,
///     exp: u64,
/// }
///
/// let signer = JwtSigner::new(b"my-secret-key");
/// let token = signer.encode(&Claims { sub: "user-1".into(), exp: 9999999999 }).unwrap();
///
/// let decoded: Claims = signer.decode(&token).unwrap();
/// assert_eq!(decoded.sub, "user-1");
/// ```
#[derive(Debug, Clone)]
pub struct JwtSigner {
    key: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum JwtError {
    #[error("JWT serialization failed: {0}")]
    Serialization(String),
    #[error("JWT deserialization failed: {0}")]
    Deserialization(String),
    #[error("invalid JWT format: expected 3 parts, got {0}")]
    InvalidFormat(usize),
    #[error("invalid base64 encoding")]
    InvalidBase64,
    #[error("signature verification failed")]
    InvalidSignature,
    #[error("token has expired")]
    Expired,
}

impl JwtSigner {
    pub fn new(key: &[u8]) -> Self {
        Self { key: key.to_vec() }
    }

    /// Encode claims into a signed JWT string.
    pub fn encode<T: Serialize>(&self, claims: &T) -> Result<String, JwtError> {
        let header = r#"{"alg":"HS256","typ":"JWT"}"#;
        let b64_header = URL_SAFE_NO_PAD.encode(header);

        let payload = serde_json::to_string(claims)
            .map_err(|e| JwtError::Serialization(e.to_string()))?;
        let b64_payload = URL_SAFE_NO_PAD.encode(payload);

        let signing_input = format!("{}.{}", b64_header, b64_payload);
        let signature = self.sign(&signing_input);

        Ok(format!("{}.{}", signing_input, signature))
    }

    /// Decode and verify a JWT token, returning the claims.
    pub fn decode<T: DeserializeOwned>(&self, token: &str) -> Result<T, JwtError> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(JwtError::InvalidFormat(parts.len()));
        }

        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let expected_sig = self.sign(&signing_input);

        if !constant_time_eq(expected_sig.as_bytes(), parts[2].as_bytes()) {
            return Err(JwtError::InvalidSignature);
        }

        let payload_bytes = URL_SAFE_NO_PAD
            .decode(parts[1])
            .map_err(|_| JwtError::InvalidBase64)?;

        serde_json::from_slice(&payload_bytes)
            .map_err(|e| JwtError::Deserialization(e.to_string()))
    }

    /// Decode without verifying signature (for debugging/reading only).
    pub fn decode_unverified<T: DeserializeOwned>(&self, token: &str) -> Result<T, JwtError> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(JwtError::InvalidFormat(parts.len()));
        }

        let payload_bytes = URL_SAFE_NO_PAD
            .decode(parts[1])
            .map_err(|_| JwtError::InvalidBase64)?;

        serde_json::from_slice(&payload_bytes)
            .map_err(|e| JwtError::Deserialization(e.to_string()))
    }

    fn sign(&self, data: &str) -> String {
        let mut mac = HmacSha256::new_from_slice(&self.key)
            .expect("HMAC accepts keys of any length");
        mac.update(data.as_bytes());
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut r = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        r |= x ^ y;
    }
    r == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct TestClaims {
        sub: String,
        role: String,
    }

    #[test]
    fn encode_decode_roundtrip() {
        let signer = JwtSigner::new(b"secret");
        let claims = TestClaims {
            sub: "user-1".into(),
            role: "admin".into(),
        };
        let token = signer.encode(&claims).unwrap();
        let decoded: TestClaims = signer.decode(&token).unwrap();
        assert_eq!(decoded, claims);
    }

    #[test]
    fn invalid_signature_rejected() {
        let s1 = JwtSigner::new(b"key1");
        let s2 = JwtSigner::new(b"key2");
        let claims = TestClaims {
            sub: "user".into(),
            role: "user".into(),
        };
        let token = s1.encode(&claims).unwrap();
        assert!(s2.decode::<TestClaims>(&token).is_err());
    }

    #[test]
    fn decode_unverified_works() {
        let signer = JwtSigner::new(b"secret");
        let claims = TestClaims {
            sub: "test".into(),
            role: "viewer".into(),
        };
        let token = signer.encode(&claims).unwrap();
        let decoded: TestClaims = signer.decode_unverified(&token).unwrap();
        assert_eq!(decoded, claims);
    }

    #[test]
    fn invalid_format() {
        let signer = JwtSigner::new(b"secret");
        assert!(signer.decode::<TestClaims>("bad").is_err());
        assert!(signer.decode::<TestClaims>("a.b").is_err());
        assert!(signer.decode::<TestClaims>("a.b.c.d").is_err());
    }
}
