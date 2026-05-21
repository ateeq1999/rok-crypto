# rok-crypto

[![crates.io](https://img.shields.io/crates/v/rok-crypto.svg)](https://crates.io/crates/rok-crypto)
[![docs.rs](https://img.shields.io/docsrs/rok-crypto)](https://docs.rs/rok-crypto)
[![MIT](https://img.shields.io/crates/l/rok-crypto)](LICENSE)

Cryptographic primitives for the **Rok ecosystem** — three modules in one crate:

| Module | What | Dependencies |
|--------|------|-------------|
| [`ids`](#-id-generation) | CUID2, ULID, UUID v7, NanoID, Snowflake | minimal |
| [`hash`](#-password-hashing) | Argon2id, Bcrypt, Scrypt password hashing | per-driver |
| [`encrypt`](#-encryption) | AES-256-GCM encryption + HMAC-SHA256 signing | aes-gcm, hmac |

All modules share `serde`, `thiserror`, and common conventions — one crate, one version, zero duplication.

---

## Installation

```toml
[dependencies]
rok-crypto = "0.4"
```

Default features enable all three modules with safe defaults:

| Feature | Includes | Description |
|---------|----------|-------------|
| `ids` | `cuid2`, `ulid`, `uuid-v7`, `nanoid` | Collision-resistant ID generators |
| `hash` | `argon2` | Argon2id password hashing |
| `encrypt` | — | AES-256-GCM + HMAC-SHA256 |

### Full feature set

```toml
rok-crypto = { version = "0.4", features = ["full"] }
```

The `full` feature enables everything including optional drivers and `sqlx-postgres`.

---

## Feature Flags

| Flag | Enables | Default |
|------|---------|---------|
| **ID generators** | | |
| `ids` | All ID generators (cuid2, ulid, uuid-v7, nanoid) | ✅ |
| `snowflake` | Snowflake ID generator | |
| **Password hashing** | | |
| `hash` | Password hashing with Argon2id (default driver) | ✅ |
| `argon2` | Argon2id driver (memory-hard, OWASP-recommended) | ✅ (with `hash`) |
| `bcrypt` | Bcrypt driver (legacy, widely-deployed) | |
| `scrypt` | Scrypt driver (memory-hard alternative) | |
| **Encryption** | | |
| `encrypt` | AES-256-GCM + HMAC-SHA256 | ✅ |
| **Database** | | |
| `sqlx-postgres` | `sqlx::Type`, `Encode`, `Decode` for all ID types | |
| **Bundles** | | |
| `full` | All of the above | |

### Minimal dependency examples

```toml
# Only ID generation (CUID2 + ULID + UUIDv7 + NanoID)
rok-crypto = { version = "0.4", default-features = false, features = ["ids"] }

# Only encryption + signing
rok-crypto = { version = "0.4", default-features = false, features = ["encrypt"] }

# Password hashing with Bcrypt instead of Argon2id
rok-crypto = { version = "0.4", default-features = false, features = ["bcrypt"] }

# All ID types including Snowflake + PostgreSQL support
rok-crypto = { version = "0.4", features = ["snowflake", "sqlx-postgres"] }

# Everything
rok-crypto = { version = "0.4", features = ["full"] }
```

---

## ID Generation

```rust
use rok_crypto::ids::*;

// CUID2 — secure, collision-resistant, 24-char default
let id = Cuid2::new();
assert_eq!(id.as_str().len(), 24);

// ULID — lexicographically sortable, 26-char Crockford base32
let id = Ulid::new();
let monotonic = Ulid::monotonic(); // guaranteed increasing within same ms

// UUID v7 — time-ordered UUID (RFC 9562)
let id = UuidV7::new();
assert_eq!(id.as_uuid().get_version_num(), 7);

// NanoID — compact, URL-safe, configurable length/alphabet
let id = NanoId::new();                     // 21 chars
let short = NanoId::with_size(10);          // 10 chars
let hex = NanoId::custom(b"0123456789abcdef", 16);

// Snowflake — 64-bit time-ordered integer (requires `snowflake` feature)
let id = Snowflake::new(1);                 // machine_id = 1
```

All ID types implement `Display`, `FromStr`, `Serialize`, `Deserialize`, `AsRef<str>`, and `Ord`/`PartialOrd` (for sortable types).

### SQLx PostgreSQL support

With the `sqlx-postgres` feature, all ID types implement `sqlx::Type`, `Encode`, and `Decode` for PostgreSQL:

```rust
use rok_crypto::ids::Cuid2;
use sqlx::FromRow;

#[derive(Debug, FromRow)]
pub struct Post {
    pub id:    Cuid2,     // TEXT column
    pub title: String,
}

sqlx::query("INSERT INTO posts (id, title) VALUES ($1, $2)")
    .bind(&Cuid2::new())
    .bind("Hello")
    .execute(&pool)
    .await?;
```

### Which ID to use?

| ID | Sortable | DB Column | Length | Best For |
|---|---|---|---|---|
| CUID2 | no | TEXT | 24 | General purpose public IDs |
| ULID | yes | TEXT/CHAR(26) | 26 | Time-ordered, Cassandra-style |
| UUID v7 | yes | UUID | 36 | Standard UUID columns, time-ordered |
| NanoID | no | TEXT | 21 | Short URL-safe tokens |
| Snowflake | yes | BIGINT | 8 (i64) | Ultra-high write throughput |

---

## Password Hashing

```rust
use rok_crypto::hash::{HashConfig, Hasher};

// Argon2id (OWASP-recommended, enabled by default)
let hasher = Hasher::from_config(HashConfig::default());

// Hash a password (sync — runs on `spawn_blocking` in async apps)
let hash = hasher.make("correct-horse-battery-staple")?;

// Verify
assert!(hasher.verify("correct-horse-battery-staple", &hash)?);
assert!(!hasher.verify("wrong", &hash)?);

// Rehash detection — upgrade cost params over time
if hasher.needs_rehash(&hash) {
    let new_hash = hasher.make("correct-horse-battery-staple")?;
    // persist new_hash
}
```

### Pluggable drivers

```rust
// Bcrypt (requires `bcrypt` feature)
use rok_crypto::hash::{BcryptConfig, Driver, HashConfig, Hasher};

let hasher = Hasher::from_config(HashConfig {
    driver: Driver::Bcrypt,
    bcrypt: BcryptConfig { cost: 12 },
    ..HashConfig::default()
});

// Scrypt (requires `scrypt` feature)
use rok_crypto::hash::ScryptConfig;

let hasher = Hasher::from_config(HashConfig {
    driver: Driver::Scrypt,
    scrypt: ScryptConfig { log_n: 17, r: 8, p: 1 },
    ..HashConfig::default()
});
```

### Integration with model types

```rust
use rok_crypto::hash::AuthFinder;

struct User { password_hash: String }

impl AuthFinder for User {
    fn get_auth_password(&self) -> &str { &self.password_hash }
}

// Works directly with Hasher
let user = User { password_hash: hash };
assert!(hasher.verify_for("password", &user)?);
```

### Custom cost parameters

```rust
use rok_crypto::hash::Argon2Config;

let hasher = Hasher::from_config(HashConfig {
    driver: Driver::Argon2,
    argon2: Argon2Config {
        memory_kib: 131_072,   // 128 MiB
        iterations: 3,
        parallelism: 4,
    },
    ..HashConfig::default()
});
```

---

## Encryption

```rust
use std::time::Duration;
use rok_crypto::encrypt::{EncryptConfig, Encrypter};

let enc = Encrypter::from_config(EncryptConfig::new("my-master-key"));

// Basic round-trip
let token = enc.seal("sensitive data");
assert_eq!(enc.open(&token)?, "sensitive data");

// Purpose-bound tokens — prevent cross-context replay
let token = enc.seal_for("password-reset", "user@example.com");
assert!(enc.open_for("password-reset", &token).is_ok());
assert!(enc.open_for("email-verify", &token).is_err()); // wrong purpose

// Expiring tokens
let token = enc.seal_expiring("data", Duration::from_secs(3600));
assert_eq!(enc.open(&token)?, "data");   // within TTL → ok
// after 1 hour: enc.open(&token) → Err(EncryptError::Expired)

// Purpose-bound + expiring
let token = enc.seal_for_expiring("invite", "user@test.com", Duration::from_secs(86400));

// Non-fallible open (returns Option)
assert_eq!(enc.try_open("garbage"), None);
```

### Key rotation

```rust
// Old tokens encrypted with "old-key" can still be decrypted
let enc = Encrypter::from_config(
    EncryptConfig::new("new-key")
        .with_old_keys(["old-key"])
);

// New tokens use the primary key
let new_token = enc.seal("new data");    // encrypted with "new-key"
let old_token = /* from previous deployment */;
assert_eq!(enc.open(old_token)?, "legacy data"); // falls back to "old-key"
```

### HMAC-SHA256 signing

```rust
use rok_crypto::encrypt::Signer;

let signer = Signer::new("my-hmac-secret");
let sig = signer.sign("payload");
assert!(signer.verify("payload", &sig));
assert!(!signer.verify("tampered", &sig));
```

---

## Module structure

```
rok-crypto
├── ids/          # Feature-gated ID generators
│   ├── cuid2     # CUID2 — secure collision-resistant IDs
│   ├── ulid      # ULID — lexicographically sortable
│   ├── uuid_v7   # UUID v7 — time-ordered UUIDs
│   ├── nanoid    # NanoID — compact, configurable
│   └── snowflake # Snowflake — 64-bit distributed IDs
├── hash/         # Password hashing with pluggable drivers
│   ├── config    # HashConfig, Driver enum, per-driver configs
│   ├── driver    # HashDriver trait (internal)
│   ├── drivers   # Argon2, Bcrypt, Scrypt implementations
│   │   ├── argon2
│   │   ├── bcrypt
│   │   └── scrypt
│   ├── error     # HashError
│   └── auth_finder # AuthFinder trait for model integration
└── encrypt/      # AES-256-GCM + HMAC-SHA256
    ├── config    # EncryptConfig with key rotation
    ├── error     # EncryptError
    └── signer    # HMAC-SHA256 Signer
```

All imports go through `rok_crypto::module::*` — no deep internal paths.

---

## Development

```bash
# Test default features
cargo test

# Test with all features
cargo test --features full

# Test individual modules
cargo test --no-default-features --features ids
cargo test --no-default-features --features hash,bcrypt,scrypt
cargo test --no-default-features --features encrypt

# Check minimal builds
cargo check --no-default-features
```

---

## License

MIT
