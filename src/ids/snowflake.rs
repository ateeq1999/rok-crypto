use std::fmt;
use std::str::FromStr;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use super::IdError;

// Epoch: 2020-01-01 00:00:00 UTC
const DEFAULT_EPOCH_MS: u64 = 1_577_836_800_000;
const WORKER_BITS: u8 = 10;
const SEQUENCE_BITS: u8 = 12;
const MAX_WORKER: u16 = (1 << WORKER_BITS) - 1; // 1023
const MAX_SEQUENCE: u16 = (1 << SEQUENCE_BITS) - 1; // 4095

/// Configuration for the Snowflake generator.
#[derive(Debug, Clone)]
pub struct SnowflakeConfig {
    /// Worker ID (0–1023). Set from SNOWFLAKE_WORKER_ID env var or default 0.
    pub worker_id: u16,
    /// Custom epoch in milliseconds since Unix epoch. Defaults to 2020-01-01.
    pub epoch_ms: u64,
}

impl Default for SnowflakeConfig {
    fn default() -> Self {
        let worker_id: u16 = std::env::var("SNOWFLAKE_WORKER_ID")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        Self {
            worker_id: worker_id & MAX_WORKER,
            epoch_ms: DEFAULT_EPOCH_MS,
        }
    }
}

struct GeneratorState {
    last_ts: i64,
    sequence: u16,
}

static STATE: OnceLock<Mutex<GeneratorState>> = OnceLock::new();

fn state() -> &'static Mutex<GeneratorState> {
    STATE.get_or_init(|| {
        Mutex::new(GeneratorState {
            last_ts: -1,
            sequence: 0,
        })
    })
}

fn current_ts(epoch_ms: u64) -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards")
        .as_millis() as i64
        - epoch_ms as i64
}

/// A Snowflake ID — 64-bit integer composed of timestamp + worker_id + sequence.
///
/// Layout (MSB → LSB):
/// ```text
/// [0][41-bit timestamp ms][10-bit worker][12-bit sequence]
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Snowflake(i64);

impl Snowflake {
    pub fn generate(config: &SnowflakeConfig) -> Self {
        let mut guard = state().lock().unwrap();

        let mut ts = current_ts(config.epoch_ms);

        if ts == guard.last_ts {
            guard.sequence = (guard.sequence + 1) & MAX_SEQUENCE;
            if guard.sequence == 0 {
                // Sequence exhausted — spin until the next millisecond
                while ts <= guard.last_ts {
                    ts = current_ts(config.epoch_ms);
                }
            }
        } else {
            guard.sequence = 0;
        }

        guard.last_ts = ts;
        let seq = guard.sequence as i64;
        drop(guard);

        let id = (ts << (WORKER_BITS + SEQUENCE_BITS) as i64)
            | ((config.worker_id as i64 & MAX_WORKER as i64) << SEQUENCE_BITS as i64)
            | seq;

        Self(id)
    }

    /// Generate with the default config (reads SNOWFLAKE_WORKER_ID env var once).
    pub fn new() -> Self {
        static CFG: OnceLock<SnowflakeConfig> = OnceLock::new();
        Self::generate(CFG.get_or_init(SnowflakeConfig::default))
    }

    pub fn value(&self) -> i64 {
        self.0
    }

    pub fn timestamp_ms(&self, config: &SnowflakeConfig) -> u64 {
        let ts = self.0 >> (WORKER_BITS + SEQUENCE_BITS) as i64;
        (ts as u64) + config.epoch_ms
    }

    pub fn worker_id(&self) -> u16 {
        ((self.0 >> SEQUENCE_BITS as i64) & MAX_WORKER as i64) as u16
    }

    pub fn sequence(&self) -> u16 {
        (self.0 & MAX_SEQUENCE as i64) as u16
    }
}

impl Default for Snowflake {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for Snowflake {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for Snowflake {
    type Err = IdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let n: i64 = s
            .parse()
            .map_err(|_| IdError::InvalidFormat("snowflake", "expected integer"))?;
        if n < 0 {
            return Err(IdError::InvalidFormat("snowflake", "must be non-negative"));
        }
        Ok(Self(n))
    }
}

impl From<i64> for Snowflake {
    fn from(n: i64) -> Self {
        Self(n)
    }
}

impl From<Snowflake> for i64 {
    fn from(s: Snowflake) -> i64 {
        s.0
    }
}

#[cfg(feature = "sqlx-postgres")]
mod sqlx_impl {
    use super::Snowflake;
    use sqlx::{
        encode::IsNull,
        error::BoxDynError,
        postgres::{PgArgumentBuffer, PgTypeInfo, PgValueRef},
    };

    impl sqlx::Type<sqlx::Postgres> for Snowflake {
        fn type_info() -> PgTypeInfo {
            <i64 as sqlx::Type<sqlx::Postgres>>::type_info()
        }
    }

    impl<'q> sqlx::Encode<'q, sqlx::Postgres> for Snowflake {
        fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> Result<IsNull, BoxDynError> {
            <i64 as sqlx::Encode<'q, sqlx::Postgres>>::encode_by_ref(&self.0, buf)
        }
    }

    impl<'r> sqlx::Decode<'r, sqlx::Postgres> for Snowflake {
        fn decode(value: PgValueRef<'r>) -> Result<Self, BoxDynError> {
            let n = <i64 as sqlx::Decode<sqlx::Postgres>>::decode(value)?;
            Ok(Self(n))
        }
    }
}
