use hmac::{Hmac, Mac};
use sha2::Sha256;

use thiserror::Error;

type HmacSha256 = Hmac<Sha256>;

const TOTP_DEFAULT_INTERVAL: u64 = 30;

/// Time-based One-Time Password (RFC 6238).
///
/// Generates 6-digit codes from a shared secret, using HMAC-SHA256
/// truncated to 31 bits.
///
/// # Example
///
/// ```rust
/// use rok_crypto::totp::TOTP;
///
/// let totp = TOTP::new(b"supersecretkey", 30);
/// let code = totp.generate(0);
/// assert_eq!(code.len(), 6);
/// assert!(code.chars().all(|c| c.is_ascii_digit()));
///
/// // Verify a code at the same counter
/// assert!(totp.verify(&code, 0));
/// ```
#[derive(Debug, Clone)]
pub struct TOTP {
    secret: Vec<u8>,
    interval: u64,
}

#[derive(Debug, Error)]
pub enum TOTPError {
    #[error("invalid code length: expected 6 digits, got {0}")]
    InvalidLength(usize),
    #[error("code contains non-digit characters")]
    NonDigit,
}

impl TOTP {
    /// Create a new TOTP generator.
    ///
    /// - `secret`: shared secret key (at least 16 bytes recommended).
    /// - `interval`: time step in seconds (typically 30).
    pub fn new(secret: &[u8], interval: u64) -> Self {
        Self {
            secret: secret.to_vec(),
            interval,
        }
    }

    /// Generate a 6-digit TOTP code for the given `counter`.
    pub fn generate(&self, counter: u64) -> String {
        let mut mac = HmacSha256::new_from_slice(&self.secret)
            .expect("HMAC accepts keys of any length");
        mac.update(&counter.to_be_bytes());
        let result = mac.finalize().into_bytes();

        // Dynamic truncation (RFC 4226 §5.3)
        let offset = (result[31] & 0x0F) as usize;
        let code = ((result[offset] & 0x7F) as u32) << 24
            | ((result[offset + 1] as u32) << 16)
            | ((result[offset + 2] as u32) << 8)
            | (result[offset + 3] as u32);
        let otp = code % 1_000_000;
        format!("{:06}", otp)
    }

    /// Verify a 6-digit code against the given `counter`.
    pub fn verify(&self, code: &str, counter: u64) -> bool {
        let Ok(expected) = self.parse_code(code) else {
            return false;
        };
        let actual = self.generate(counter);
        actual == expected
    }

    /// Verify a code with a given drift window.
    ///
    /// Checks `counter - drift .. counter + drift` to tolerate clock skew.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rok_crypto::totp::TOTP;
    ///
    /// let totp = TOTP::new(b"secret", 30);
    /// let counter = 1_000_000u64;
    /// let code = totp.generate(counter);
    /// assert!(totp.verify_drift(&code, counter, 1));
    /// ```
    pub fn verify_drift(&self, code: &str, counter: u64, drift: u64) -> bool {
        let Ok(_) = self.parse_code(code) else {
            return false;
        };
        let mut low = counter.saturating_sub(drift);
        let high = counter.saturating_add(drift);
        while low <= high {
            if self.generate(low) == code {
                return true;
            }
            low += 1;
        }
        false
    }

    /// Current time counter: `now / interval`.
    pub fn now(&self) -> u64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time went backwards")
            .as_secs();
        now / self.interval
    }

    fn parse_code(&self, code: &str) -> Result<String, TOTPError> {
        if code.len() != 6 {
            return Err(TOTPError::InvalidLength(code.len()));
        }
        if !code.chars().all(|c| c.is_ascii_digit()) {
            return Err(TOTPError::NonDigit);
        }
        Ok(code.to_string())
    }
}

impl Default for TOTP {
    fn default() -> Self {
        Self {
            secret: b"change-me-change-me-change-me!".to_vec(),
            interval: TOTP_DEFAULT_INTERVAL,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_returns_six_digits() {
        let totp = TOTP::new(b"secret", 30);
        let code = totp.generate(0);
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn verify_own_code() {
        let totp = TOTP::new(b"supersecret", 30);
        let code = totp.generate(42);
        assert!(totp.verify(&code, 42));
        assert!(!totp.verify(&code, 43));
    }

    #[test]
    fn verify_drift_tolerates_skew() {
        let totp = TOTP::new(b"secret", 30);
        let code = totp.generate(100);
        assert!(totp.verify_drift(&code, 101, 2)); // drift of 2
        assert!(!totp.verify_drift(&code, 200, 1));
    }

    #[test]
    fn verify_invalid_code_returns_false() {
        let totp = TOTP::new(b"secret", 30);
        assert!(!totp.verify("abc123", 0));
        assert!(!totp.verify("12345", 0));   // 5 digits
        assert!(!totp.verify("1234567", 0));  // 7 digits
    }

    #[test]
    fn codes_are_deterministic() {
        let totp = TOTP::new(b"test", 30);
        assert_eq!(totp.generate(0), totp.generate(0));
        assert_eq!(totp.generate(999), totp.generate(999));
    }

    #[test]
    fn now_returns_current_counter() {
        let totp = TOTP::new(b"secret", 30);
        let code_now = totp.generate(totp.now());
        assert_eq!(code_now.len(), 6);
    }
}
