use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use uuid::{NoContext, Timestamp, Uuid};

use super::IdError;

/// A UUID version 7 — time-ordered, 36-char hyphenated string representation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UuidV7(Uuid);

impl UuidV7 {
    pub fn generate() -> Self {
        let ts = Timestamp::now(NoContext);
        Self(Uuid::new_v7(ts))
    }

    pub fn as_uuid(&self) -> &Uuid {
        &self.0
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        self.0.as_bytes()
    }
}

impl fmt::Display for UuidV7 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl FromStr for UuidV7 {
    type Err = IdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let uuid = Uuid::parse_str(s)
            .map_err(|_| IdError::InvalidFormat("uuid_v7", "invalid UUID format"))?;
        if uuid.get_version_num() != 7 {
            return Err(IdError::InvalidFormat("uuid_v7", "not a v7 UUID"));
        }
        Ok(Self(uuid))
    }
}

impl From<Uuid> for UuidV7 {
    fn from(u: Uuid) -> Self {
        Self(u)
    }
}

impl AsRef<Uuid> for UuidV7 {
    fn as_ref(&self) -> &Uuid {
        &self.0
    }
}

#[cfg(feature = "sqlx-postgres")]
mod sqlx_impl {
    use super::UuidV7;
    use sqlx::{
        encode::IsNull,
        error::BoxDynError,
        postgres::{PgArgumentBuffer, PgTypeInfo, PgValueRef},
    };
    use uuid::Uuid;

    impl sqlx::Type<sqlx::Postgres> for UuidV7 {
        fn type_info() -> PgTypeInfo {
            <Uuid as sqlx::Type<sqlx::Postgres>>::type_info()
        }
    }

    impl<'q> sqlx::Encode<'q, sqlx::Postgres> for UuidV7 {
        fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> Result<IsNull, BoxDynError> {
            <Uuid as sqlx::Encode<'q, sqlx::Postgres>>::encode_by_ref(&self.0, buf)
        }
    }

    impl<'r> sqlx::Decode<'r, sqlx::Postgres> for UuidV7 {
        fn decode(value: PgValueRef<'r>) -> Result<Self, BoxDynError> {
            let uuid = <Uuid as sqlx::Decode<sqlx::Postgres>>::decode(value)?;
            Ok(Self(uuid))
        }
    }
}
