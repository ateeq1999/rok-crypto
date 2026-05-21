use sha3::{Digest, Sha3_256};
use std::fmt;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::IdError;

const LENGTH: usize = 24;
const ALPHABET: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz";
const LETTERS: &[u8] = b"abcdefghijklmnopqrstuvwxyz";

static COUNTER: AtomicU64 = AtomicU64::new(0);
static FINGERPRINT: OnceLock<[u8; 32]> = OnceLock::new();

fn fingerprint() -> &'static [u8; 32] {
    FINGERPRINT.get_or_init(|| {
        let pid = std::process::id();
        let mut rnd = [0u8; 24];
        rand::thread_rng().fill_bytes(&mut rnd);
        let mut h = Sha3_256::new();
        h.update(pid.to_le_bytes());
        h.update(rnd);
        let out = h.finalize();
        let mut fp = [0u8; 32];
        fp.copy_from_slice(&out);
        fp
    })
}

fn encode_base36_fixed(n: u128, length: usize) -> Vec<u8> {
    let mut digits = vec![b'0'; length];
    let mut n = n;
    for i in (0..length).rev() {
        digits[i] = ALPHABET[(n % 36) as usize];
        n /= 36;
    }
    digits
}

/// A CUID2 identifier — 24-char, SHA-3 fingerprinted, URL-safe.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Cuid2(String);

impl Cuid2 {
    pub fn generate() -> Self {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time went backwards")
            .as_millis();

        let count = COUNTER.fetch_add(1, Ordering::Relaxed);

        let mut rnd = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut rnd);

        let mut h = Sha3_256::new();
        h.update(ts.to_be_bytes());
        h.update(count.to_be_bytes());
        h.update(fingerprint());
        h.update(rnd);
        let hash = h.finalize();

        let n = u128::from_be_bytes(hash[..16].try_into().unwrap());
        let body = encode_base36_fixed(n, LENGTH - 1);

        let prefix = LETTERS[(hash[16] % 26) as usize] as char;
        Self(format!("{}{}", prefix, String::from_utf8(body).unwrap()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Cuid2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for Cuid2 {
    type Err = IdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != LENGTH {
            return Err(IdError::InvalidFormat("cuid2", "expected 24 chars"));
        }
        let first = s.chars().next().unwrap();
        if !first.is_ascii_alphabetic() {
            return Err(IdError::InvalidFormat("cuid2", "must start with a letter"));
        }
        if !s
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        {
            return Err(IdError::InvalidFormat(
                "cuid2",
                "only lowercase letters and digits",
            ));
        }
        Ok(Self(s.to_owned()))
    }
}

impl AsRef<str> for Cuid2 {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(feature = "sqlx-postgres")]
mod sqlx_impl {
    use super::Cuid2;
    use sqlx::{
        encode::IsNull,
        error::BoxDynError,
        postgres::{PgArgumentBuffer, PgTypeInfo, PgValueRef},
    };

    impl sqlx::Type<sqlx::Postgres> for Cuid2 {
        fn type_info() -> PgTypeInfo {
            <String as sqlx::Type<sqlx::Postgres>>::type_info()
        }
    }

    impl<'q> sqlx::Encode<'q, sqlx::Postgres> for Cuid2 {
        fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> Result<IsNull, BoxDynError> {
            <String as sqlx::Encode<'q, sqlx::Postgres>>::encode_by_ref(&self.0, buf)
        }
    }

    impl<'r> sqlx::Decode<'r, sqlx::Postgres> for Cuid2 {
        fn decode(value: PgValueRef<'r>) -> Result<Self, BoxDynError> {
            let s = <String as sqlx::Decode<sqlx::Postgres>>::decode(value)?;
            Ok(Self(s))
        }
    }
}
