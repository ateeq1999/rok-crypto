use thiserror::Error;

/// Validates passwords against configurable rules.
///
/// # Example
///
/// ```rust
/// use rok_crypto::password_policy::{PasswordPolicy, PasswordPolicyError};
///
/// let policy = PasswordPolicy::default();
/// assert!(policy.validate("CorrectHorseBatteryStaple!42").is_ok());
/// assert!(matches!(
///     policy.validate("short"),
///     Err(PasswordPolicyError::TooShort { .. })
/// ));
/// ```
#[derive(Debug, Clone)]
pub struct PasswordPolicy {
    pub min_length: usize,
    pub max_length: usize,
    pub require_uppercase: bool,
    pub require_lowercase: bool,
    pub require_digit: bool,
    pub require_special: bool,
    pub max_consecutive: usize,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            min_length: 8,
            max_length: 128,
            require_uppercase: true,
            require_lowercase: true,
            require_digit: true,
            require_special: false,
            max_consecutive: 0,
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PasswordPolicyError {
    #[error("password too short: minimum {min}, got {len}")]
    TooShort { min: usize, len: usize },
    #[error("password too long: maximum {max}, got {len}")]
    TooLong { max: usize, len: usize },
    #[error("password must contain at least one uppercase letter")]
    NoUppercase,
    #[error("password must contain at least one lowercase letter")]
    NoLowercase,
    #[error("password must contain at least one digit")]
    NoDigit,
    #[error("password must contain at least one special character")]
    NoSpecial,
    #[error("password contains {count} consecutive repeated characters (max {max})")]
    Consecutive { count: usize, max: usize },
}

impl PasswordPolicy {
    /// Default strict policy for high-security environments.
    pub fn strict() -> Self {
        Self {
            min_length: 12,
            max_length: 128,
            require_uppercase: true,
            require_lowercase: true,
            require_digit: true,
            require_special: true,
            max_consecutive: 2,
        }
    }

    /// Relaxed policy — length 6+, no complexity requirements.
    pub fn relaxed() -> Self {
        Self {
            min_length: 6,
            max_length: 256,
            require_uppercase: false,
            require_lowercase: false,
            require_digit: false,
            require_special: false,
            max_consecutive: 0,
        }
    }

    /// Validate `password` against this policy.
    pub fn validate(&self, password: &str) -> Result<(), PasswordPolicyError> {
        let len = password.len();

        if len < self.min_length {
            return Err(PasswordPolicyError::TooShort {
                min: self.min_length,
                len,
            });
        }

        if len > self.max_length {
            return Err(PasswordPolicyError::TooLong {
                max: self.max_length,
                len,
            });
        }

        if self.require_uppercase && !password.chars().any(|c| c.is_uppercase()) {
            return Err(PasswordPolicyError::NoUppercase);
        }

        if self.require_lowercase && !password.chars().any(|c| c.is_lowercase()) {
            return Err(PasswordPolicyError::NoLowercase);
        }

        if self.require_digit && !password.chars().any(|c| c.is_ascii_digit()) {
            return Err(PasswordPolicyError::NoDigit);
        }

        if self.require_special && !password.chars().any(|c| !c.is_alphanumeric()) {
            return Err(PasswordPolicyError::NoSpecial);
        }

        if self.max_consecutive > 0 {
            let mut max_run = 1usize;
            let mut run = 1usize;
            let mut prev: Option<char> = None;
            for c in password.chars() {
                if Some(c) == prev {
                    run += 1;
                    max_run = max_run.max(run);
                } else {
                    run = 1;
                }
                prev = Some(c);
            }
            if max_run > self.max_consecutive {
                return Err(PasswordPolicyError::Consecutive {
                    count: max_run,
                    max: self.max_consecutive,
                });
            }
        }

        Ok(())
    }

    /// Estimate password strength on a scale of 0–4 (like zxcvbn categories).
    ///
    /// Considers length, character variety, and consecutive runs.
    pub fn strength(&self, password: &str) -> u8 {
        let len = password.len();
        if len < 6 {
            return 0;
        }

        let has_upper = password.chars().any(|c| c.is_uppercase());
        let has_lower = password.chars().any(|c| c.is_lowercase());
        let has_digit = password.chars().any(|c| c.is_ascii_digit());
        let has_special = password.chars().any(|c| !c.is_alphanumeric());
        let variety = [has_upper, has_lower, has_digit, has_special]
            .iter()
            .filter(|&&v| v)
            .count() as u8;

        match (len, variety) {
            (l, _) if l >= 16 && variety >= 3 => 4,
            (l, _) if l >= 12 && variety >= 2 => 3,
            (l, _) if l >= 8 && variety >= 1 => 2,
            _ => 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_accepts_valid() {
        let p = PasswordPolicy::default();
        assert!(p.validate("HelloWorld42").is_ok());
    }

    #[test]
    fn default_policy_rejects_short() {
        let p = PasswordPolicy::default();
        assert_eq!(
            p.validate("Ab1"),
            Err(PasswordPolicyError::TooShort {
                min: 8,
                len: 3
            })
        );
    }

    #[test]
    fn default_policy_rejects_no_uppercase() {
        let p = PasswordPolicy::default();
        assert_eq!(p.validate("lowercase42"), Err(PasswordPolicyError::NoUppercase));
    }

    #[test]
    fn strict_policy() {
        let p = PasswordPolicy::strict();
        assert!(p.validate("A!bCdef1ghiJklM").is_ok());
        assert!(p.validate("aaa").is_err());
    }

    #[test]
    fn relaxed_policy_accepts_weak() {
        let p = PasswordPolicy::relaxed();
        assert!(p.validate("abcdef").is_ok());
    }

    #[test]
    fn consecutive_characters_rejected() {
        let p = PasswordPolicy {
            max_consecutive: 2,
            ..PasswordPolicy::default()
        };
        assert!(p.validate("Abcd!234").is_ok());
        assert!(p.validate("Abcd!!!234").is_err());
    }

    #[test]
    fn strength_estimator() {
        let p = PasswordPolicy::default();
        assert_eq!(p.strength("a"), 0);
        assert_eq!(p.strength("abcdef"), 1);
        assert_eq!(p.strength("Abcdef12"), 2);
        assert_eq!(p.strength("Abcdef12!xyz"), 3);
        assert_eq!(p.strength("Abcdef12!xyzLONG"), 4);
    }
}
