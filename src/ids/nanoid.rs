use std::fmt;
use std::str::FromStr;

use rand::RngCore;
use serde::{Deserialize, Serialize};

use super::IdError;

pub const DEFAULT_ALPHABET: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
pub const DEFAULT_SIZE: usize = 21;

/// Generate a NanoID string with custom alphabet and length.
///
/// Uses rejection sampling to guarantee uniform distribution.
pub fn generate_nanoid_custom(alphabet: &[u8], size: usize) -> String {
    assert!(!alphabet.is_empty(), "nanoid: alphabet must not be empty");
    assert!(
        alphabet.len() <= 256,
        "nanoid: alphabet too large (max 256)"
    );

    let mut rng = rand::thread_rng();
    let alen = alphabet.len();

    // Smallest bitmask that covers alphabet indices
    let mask = {
        let mut m = 1usize;
        while m < alen {
            m = (m << 1) | 1;
        }
        m
    };

    let mut result = Vec::with_capacity(size);
    let mut buf = [0u8; 256];

    while result.len() < size {
        rng.fill_bytes(&mut buf);
        for &b in &buf {
            let idx = (b as usize) & mask;
            if idx < alen {
                result.push(alphabet[idx]);
                if result.len() == size {
                    break;
                }
            }
        }
    }

    String::from_utf8(result).expect("nanoid alphabet must be ASCII")
}

/// A NanoID — short, URL-safe, configurable-length random identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NanoId(String);

impl NanoId {
    /// Generate a 21-char NanoID using the default URL-safe alphabet.
    pub fn generate() -> Self {
        Self(generate_nanoid_custom(DEFAULT_ALPHABET, DEFAULT_SIZE))
    }

    /// Generate a NanoID with a custom size (default alphabet).
    pub fn with_size(size: usize) -> Self {
        Self(generate_nanoid_custom(DEFAULT_ALPHABET, size))
    }

    /// Generate a NanoID with a custom alphabet and size.
    pub fn custom(alphabet: &[u8], size: usize) -> Self {
        Self(generate_nanoid_custom(alphabet, size))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for NanoId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for NanoId {
    type Err = IdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err(IdError::InvalidFormat("nanoid", "must not be empty"));
        }
        Ok(Self(s.to_owned()))
    }
}

impl AsRef<str> for NanoId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(feature = "sqlx-postgres")]
mod sqlx_impl {
    use super::NanoId;
    use sqlx::{
        encode::IsNull,
        error::BoxDynError,
        postgres::{PgArgumentBuffer, PgTypeInfo, PgValueRef},
    };

    impl sqlx::Type<sqlx::Postgres> for NanoId {
        fn type_info() -> PgTypeInfo {
            <String as sqlx::Type<sqlx::Postgres>>::type_info()
        }
    }

    impl<'q> sqlx::Encode<'q, sqlx::Postgres> for NanoId {
        fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> Result<IsNull, BoxDynError> {
            <String as sqlx::Encode<'q, sqlx::Postgres>>::encode_by_ref(&self.0, buf)
        }
    }

    impl<'r> sqlx::Decode<'r, sqlx::Postgres> for NanoId {
        fn decode(value: PgValueRef<'r>) -> Result<Self, BoxDynError> {
            let s = <String as sqlx::Decode<sqlx::Postgres>>::decode(value)?;
            Ok(Self(s))
        }
    }
}
