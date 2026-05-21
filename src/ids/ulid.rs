use std::fmt;
use std::str::FromStr;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::IdError;

const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const CROCKFORD_DECODE: [i8; 128] = build_decode_table();

const fn build_decode_table() -> [i8; 128] {
    let mut table = [-1i8; 128];
    let alpha = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let mut i = 0usize;
    while i < 32 {
        table[alpha[i] as usize] = i as i8;
        // also accept lowercase
        if alpha[i].is_ascii_uppercase() {
            table[(alpha[i] + 32) as usize] = i as i8;
        }
        i += 1;
    }
    table
}

fn encode_ulid(ts_ms: u64, random: &[u8; 10]) -> [u8; 26] {
    let mut chars = [0u8; 26];

    // 48-bit timestamp into 10 chars (50-bit slot, 2 MSBs always 0)
    chars[0] = CROCKFORD[((ts_ms >> 45) & 0x1F) as usize];
    chars[1] = CROCKFORD[((ts_ms >> 40) & 0x1F) as usize];
    chars[2] = CROCKFORD[((ts_ms >> 35) & 0x1F) as usize];
    chars[3] = CROCKFORD[((ts_ms >> 30) & 0x1F) as usize];
    chars[4] = CROCKFORD[((ts_ms >> 25) & 0x1F) as usize];
    chars[5] = CROCKFORD[((ts_ms >> 20) & 0x1F) as usize];
    chars[6] = CROCKFORD[((ts_ms >> 15) & 0x1F) as usize];
    chars[7] = CROCKFORD[((ts_ms >> 10) & 0x1F) as usize];
    chars[8] = CROCKFORD[((ts_ms >> 5) & 0x1F) as usize];
    chars[9] = CROCKFORD[(ts_ms & 0x1F) as usize];

    // 80-bit randomness into 16 chars
    let mut r: u128 = 0;
    for &b in random.iter() {
        r = (r << 8) | b as u128;
    }
    for i in 0..16usize {
        chars[25 - i] = CROCKFORD[((r >> (5 * i)) & 0x1F) as usize];
    }

    chars
}

struct MonotonicState {
    last_ms: u64,
    last_random: [u8; 10],
}

static MONOTONIC: Mutex<Option<MonotonicState>> = Mutex::new(None);

/// A ULID — 26-char Crockford base32, lexicographically sortable by time.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Ulid(String);

impl Ulid {
    /// Generate a new ULID using the current timestamp and random bits.
    pub fn generate() -> Self {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time went backwards")
            .as_millis() as u64;

        let mut rnd = [0u8; 10];
        rand::thread_rng().fill_bytes(&mut rnd);

        let chars = encode_ulid(ts, &rnd);
        Self(String::from_utf8(chars.to_vec()).unwrap())
    }

    /// Generate a monotonically increasing ULID: within the same millisecond
    /// the random component is incremented instead of re-randomised.
    pub fn monotonic() -> Self {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time went backwards")
            .as_millis() as u64;

        let mut guard = MONOTONIC.lock().unwrap();
        let random = match &mut *guard {
            Some(state) if state.last_ms == ts => {
                // increment least-significant byte of random part
                let mut i = 9usize;
                loop {
                    let (val, overflow) = state.last_random[i].overflowing_add(1);
                    state.last_random[i] = val;
                    if !overflow {
                        break;
                    }
                    if i == 0 {
                        // full overflow — just randomise again
                        rand::thread_rng().fill_bytes(&mut state.last_random);
                        break;
                    }
                    i -= 1;
                }
                state.last_random
            }
            _ => {
                let mut rnd = [0u8; 10];
                rand::thread_rng().fill_bytes(&mut rnd);
                *guard = Some(MonotonicState {
                    last_ms: ts,
                    last_random: rnd,
                });
                rnd
            }
        };

        let chars = encode_ulid(ts, &random);
        Self(String::from_utf8(chars.to_vec()).unwrap())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Extract the timestamp component in milliseconds.
    pub fn timestamp_ms(&self) -> u64 {
        let bytes = self.0.as_bytes();
        let mut ts: u64 = 0;
        for &byte in bytes.iter().take(10) {
            let ch = byte as usize;
            let v = if ch < 128 { CROCKFORD_DECODE[ch] } else { -1 };
            ts = (ts << 5) | v as u64;
        }
        ts
    }
}

impl fmt::Display for Ulid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for Ulid {
    type Err = IdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != 26 {
            return Err(IdError::InvalidFormat("ulid", "expected 26 chars"));
        }
        for ch in s.chars() {
            let idx = ch as usize;
            if idx >= 128 || CROCKFORD_DECODE[idx] < 0 {
                return Err(IdError::InvalidFormat(
                    "ulid",
                    "invalid Crockford base32 char",
                ));
            }
        }
        Ok(Self(s.to_ascii_uppercase()))
    }
}

impl AsRef<str> for Ulid {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(feature = "sqlx-postgres")]
mod sqlx_impl {
    use super::Ulid;
    use sqlx::{
        encode::IsNull,
        error::BoxDynError,
        postgres::{PgArgumentBuffer, PgTypeInfo, PgValueRef},
    };

    impl sqlx::Type<sqlx::Postgres> for Ulid {
        fn type_info() -> PgTypeInfo {
            <String as sqlx::Type<sqlx::Postgres>>::type_info()
        }
    }

    impl<'q> sqlx::Encode<'q, sqlx::Postgres> for Ulid {
        fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> Result<IsNull, BoxDynError> {
            <String as sqlx::Encode<'q, sqlx::Postgres>>::encode_by_ref(&self.0, buf)
        }
    }

    impl<'r> sqlx::Decode<'r, sqlx::Postgres> for Ulid {
        fn decode(value: PgValueRef<'r>) -> Result<Self, BoxDynError> {
            let s = <String as sqlx::Decode<sqlx::Postgres>>::decode(value)?;
            Ok(Self(s))
        }
    }
}
