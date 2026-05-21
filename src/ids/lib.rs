pub mod cuid2;
pub mod nanoid;
pub mod snowflake;
pub mod ulid;
pub mod uuid_v7;

pub use cuid2::Cuid2;
pub use nanoid::NanoId;
pub use snowflake::{Snowflake, SnowflakeConfig};
pub use ulid::Ulid;
pub use uuid_v7::UuidV7;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum IdError {
    #[error("{0}: {1}")]
    InvalidFormat(&'static str, &'static str),
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    // ── CUID2 ─────────────────────────────────────────────────────────────────

    #[test]
    fn cuid2_length() {
        let id = Cuid2::generate();
        assert_eq!(id.as_str().len(), 24, "CUID2 must be 24 chars");
    }

    #[test]
    fn cuid2_starts_with_letter() {
        for _ in 0..20 {
            let id = Cuid2::generate();
            assert!(
                id.as_str().chars().next().unwrap().is_ascii_alphabetic(),
                "CUID2 first char must be a letter"
            );
        }
    }

    #[test]
    fn cuid2_uniqueness() {
        let ids: HashSet<String> = (0..1000).map(|_| Cuid2::generate().to_string()).collect();
        assert_eq!(ids.len(), 1000, "CUID2 collisions detected");
    }

    #[test]
    fn cuid2_roundtrip() {
        let id = Cuid2::generate();
        let s = id.to_string();
        let parsed: Cuid2 = s.parse().unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn cuid2_serde() {
        let id = Cuid2::generate();
        let json = serde_json::to_string(&id).unwrap();
        let back: Cuid2 = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }

    // ── ULID ──────────────────────────────────────────────────────────────────

    #[test]
    fn ulid_length() {
        let id = Ulid::generate();
        assert_eq!(id.as_str().len(), 26, "ULID must be 26 chars");
    }

    #[test]
    fn ulid_uniqueness() {
        let ids: HashSet<String> = (0..1000).map(|_| Ulid::generate().to_string()).collect();
        assert_eq!(ids.len(), 1000, "ULID collisions detected");
    }

    #[test]
    fn ulid_sorted_by_time() {
        // Generate ULIDs with a small sleep to ensure different ms buckets
        let a = Ulid::generate();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let b = Ulid::generate();
        assert!(
            a.to_string() < b.to_string(),
            "ULIDs must be lexicographically ordered"
        );
    }

    #[test]
    fn ulid_timestamp_roundtrip() {
        let before = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let id = Ulid::generate();
        let after = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let ts = id.timestamp_ms();
        assert!(ts >= before && ts <= after, "ULID timestamp out of range");
    }

    #[test]
    fn ulid_monotonic_within_ms() {
        let mut prev = Ulid::monotonic();
        for _ in 0..50 {
            let next = Ulid::monotonic();
            assert!(
                prev.to_string() < next.to_string(),
                "monotonic ULIDs must be strictly increasing"
            );
            prev = next;
        }
    }

    #[test]
    fn ulid_roundtrip() {
        let id = Ulid::generate();
        let s = id.to_string();
        let parsed: Ulid = s.parse().unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn ulid_serde() {
        let id = Ulid::generate();
        let json = serde_json::to_string(&id).unwrap();
        let back: Ulid = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }

    // ── UUID v7 ───────────────────────────────────────────────────────────────

    #[test]
    fn uuid_v7_version() {
        let id = UuidV7::generate();
        assert_eq!(id.as_uuid().get_version_num(), 7);
    }

    #[test]
    fn uuid_v7_uniqueness() {
        let ids: HashSet<String> = (0..1000).map(|_| UuidV7::generate().to_string()).collect();
        assert_eq!(ids.len(), 1000, "UUID v7 collisions detected");
    }

    #[test]
    fn uuid_v7_ordered() {
        let a = UuidV7::generate();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let b = UuidV7::generate();
        assert!(a.to_string() < b.to_string());
    }

    #[test]
    fn uuid_v7_roundtrip() {
        let id = UuidV7::generate();
        let s = id.to_string();
        let parsed: UuidV7 = s.parse().unwrap();
        assert_eq!(id, parsed);
    }

    // ── Snowflake ─────────────────────────────────────────────────────────────

    #[test]
    fn snowflake_positive() {
        let id = Snowflake::new();
        assert!(id.value() > 0);
    }

    #[test]
    fn snowflake_monotonic() {
        let cfg = SnowflakeConfig::default();
        let mut prev = Snowflake::generate(&cfg);
        for _ in 0..100 {
            let next = Snowflake::generate(&cfg);
            assert!(
                next.value() > prev.value(),
                "Snowflake IDs must be monotonically increasing"
            );
            prev = next;
        }
    }

    #[test]
    fn snowflake_worker_id() {
        let cfg = SnowflakeConfig {
            worker_id: 42,
            epoch_ms: 1_577_836_800_000,
        };
        let id = Snowflake::generate(&cfg);
        assert_eq!(id.worker_id(), 42);
    }

    #[test]
    fn snowflake_roundtrip() {
        let id = Snowflake::new();
        let s = id.to_string();
        let parsed: Snowflake = s.parse().unwrap();
        assert_eq!(id, parsed);
    }

    // ── NanoID ────────────────────────────────────────────────────────────────

    #[test]
    fn nanoid_default_length() {
        let id = NanoId::generate();
        assert_eq!(id.as_str().len(), 21);
    }

    #[test]
    fn nanoid_custom_size() {
        let id = NanoId::with_size(36);
        assert_eq!(id.as_str().len(), 36);
    }

    #[test]
    fn nanoid_custom_alphabet() {
        let alpha = b"0123456789";
        let id = NanoId::custom(alpha, 10);
        assert!(id.as_str().chars().all(|c| c.is_ascii_digit()));
        assert_eq!(id.as_str().len(), 10);
    }

    #[test]
    fn nanoid_uniqueness() {
        let ids: HashSet<String> = (0..1000).map(|_| NanoId::generate().to_string()).collect();
        assert_eq!(ids.len(), 1000, "NanoID collisions detected");
    }

    #[test]
    fn nanoid_serde() {
        let id = NanoId::generate();
        let json = serde_json::to_string(&id).unwrap();
        let back: NanoId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }
}
