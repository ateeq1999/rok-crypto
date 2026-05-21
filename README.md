# rok-crypto

[![crates.io](https://img.shields.io/crates/v/rok-crypto.svg)](https://crates.io/crates/rok-crypto)
[![docs.rs](https://img.shields.io/docsrs/rok-crypto)](https://docs.rs/rok-crypto)
[![MIT](https://img.shields.io/crates/l/rok-crypto)](LICENSE)

Pure cryptographic primitives for the **Rok ecosystem** — one crate, zero duplication.

| Module | What | Dependencies |
|--------|------|-------------|
| [`ids`](#-id-generation) | CUID2, ULID, UUID v7, NanoID, Snowflake | minimal |
| [`hash`](#-password-hashing) | Argon2id, Bcrypt, Scrypt password hashing | per-driver |
| [`encrypt`](#-encryption) | AES-256-GCM encryption + HMAC-SHA256 signing | aes-gcm, hmac |
| [`totp`](#-totp) | RFC 6238 time-based one-time passwords | hmac, sha2 |
| [`jwt`](#-jwt) | HS256 JSON Web Token sign/verify | hmac, sha2, serde_json |
| `password-policy` | Password validation + strength estimator | (none) |
| `provider` | Unified `CryptoProvider` facade | hash or encrypt |

---

## Installation

```toml
[dependencies]
rok-crypto = "0.6"
```

Default features enable all core modules:

| Feature | Includes | Description |
|---------|----------|-------------|
| `ids` | `cuid2`, `ulid`, `uuid-v7`, `nanoid` | Collision-resistant ID generators |
| `hash` | `argon2` | Argon2id password hashing |
| `encrypt` | — | AES-256-GCM + HMAC-SHA256 |

### Full feature set

```toml
rok-crypto = { version = "0.6", features = ["full"] }
```

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
| **Services** | | |
| `totp` | TOTP (RFC 6238) — HMAC-SHA256, 6-digit codes | |
| `jwt` | HS256 JWT signer / verifier | |
| `password-policy` | Password validation, strength estimation | |
| **Security** | | |
| `zeroize` | `ZeroizeOnDrop` for `Encrypter`, `Signer`, `SecretKey` | |
| `tokio` | Async hash methods (`make_async`, `verify_async`) | |
| **Bundles** | | |
| `full` | All of the above | |

### Minimal dependency examples

```toml
# Only ID generation
rok-crypto = { version = "0.6", default-features = false, features = ["ids"] }

# Only encryption + signing
rok-crypto = { version = "0.6", default-features = false, features = ["encrypt"] }

# Password hashing with Bcrypt
rok-crypto = { version = "0.6", default-features = false, features = ["bcrypt"] }

# Everything
rok-crypto = { version = "0.6", features = ["full"] }
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

// Snowflake — 64-bit time-ordered integer (requires `snowflake`)
let id = Snowflake::new(1);                 // worker_id = 1
```

All ID types implement `Display`, `FromStr`, `Serialize`, `Deserialize`, `AsRef<str>`, `Ord`/`PartialOrd`, `Default`, and `new()`.

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

// Builder-style config
let hasher = Hasher::from_config(
    HashConfig::argon2(131_072, 3, 4)   // 128 MiB, 3 iterations, 4 parallel
);

// Hash a password
let hash = hasher.make("correct-horse-battery-staple")?;

// Verify
assert!(hasher.verify("correct-horse-battery-staple", &hash)?);

// Rehash detection — upgrade cost params over time
if hasher.needs_rehash(&hash) {
    let new_hash = hasher.make("correct-horse-battery-staple")?;
}
```

### Pluggable drivers

```rust
use rok_crypto::hash::{HashConfig, Hasher};

// Bcrypt (requires `bcrypt` feature)
let hasher = Hasher::from_config(HashConfig::bcrypt(12));

// Scrypt (requires `scrypt` feature)
let hasher = Hasher::from_config(HashConfig::scrypt(17, 8, 1));
```

### Integration with model types

```rust
use rok_crypto::hash::AuthFinder;

struct User { password_hash: String }

impl AuthFinder for User {
    fn get_auth_password(&self) -> &str { &self.password_hash }
}

let user = User { password_hash: hash };
assert!(hasher.verify_for("password", &user)?);
```

### Async support (requires `tokio` feature)

```rust
let hash = hasher.make_async("password").await?;
assert!(hasher.verify_async("password", &hash).await?);
```

### Environment-driven config (requires `hash` feature)

```rust
use rok_crypto::util::from_env::FromEnv;

let hasher = Hasher::from_env()?;
// Reads: HASH_DRIVER, HASH_MEMORY_KIB, HASH_ITERATIONS,
//        HASH_PARALLELISM, HASH_COST, HASH_LOG_N, HASH_R, HASH_P
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
assert!(enc.open_for("email-verify", &token).is_err());

// Expiring tokens
let token = enc.seal_expiring("data", Duration::from_secs(3600));
assert_eq!(enc.open(&token)?, "data");

// Non-fallible open
assert_eq!(enc.try_open("garbage"), None);
```

### Key rotation

```rust
let enc = Encrypter::from_config(
    EncryptConfig::new("new-key").with_old_keys(["old-key"])
);

let new_token = enc.seal("new data");     // encrypted with "new-key"
let old_token = /* from previous deployment */;
assert_eq!(enc.open(old_token)?, "legacy data"); // falls back to "old-key"
```

### HMAC-SHA256 signing

```rust
use rok_crypto::encrypt::{Signer, SignError};

let signer = Signer::new("my-hmac-secret");
let sig = signer.sign("payload");
assert!(signer.verify("payload", &sig));

// Fallible verification with explicit error type
assert_eq!(signer.try_verify("payload", &sig), Ok(true));
assert_eq!(signer.try_verify("tampered", &sig), Ok(false));
assert!(matches!(
    signer.try_verify("payload", "invalid-base64!!"),
    Err(SignError::InvalidBase64)
));
```

### Environment-driven config (requires `encrypt` feature)

```rust
let enc = Encrypter::from_env()?;
let signer = Signer::from_env()?;
// Reads: ENCRYPT_KEY, ENCRYPT_OLD_KEYS, SIGN_KEY (or falls back to ENCRYPT_KEY)
```

---

## TOTP

RFC 6238 time-based one-time passwords. HMAC-SHA256, 6-digit codes, configurable interval and drift tolerance.

```rust
use rok_crypto::totp::TOTP;

let totp = TOTP::new(b"shared-secret-key", 30);

// Generate a code at counter 0
let code = totp.generate(0);
assert_eq!(code.len(), 6);

// Verify within a time window
assert!(totp.verify(&code, 0));
assert!(!totp.verify(&code, 1)); // different counter

// Get the current time counter
let now = totp.now();
let current = totp.generate(now);
assert!(totp.verify(&current, now));

// Drift-tolerant verification (±1 window)
assert!(totp.verify_drift(&current, now + 30, 1));
assert!(totp.verify_drift(&current, now - 30, 1));
assert!(!totp.verify_drift(&current, now + 90, 1));
```

---

## JWT

Minimal HS256 (HMAC-SHA256) JSON Web Token signer and verifier.

```rust
use serde::{Serialize, Deserialize};
use rok_crypto::jwt::JwtSigner;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    role: String,
    exp: u64,
}

let signer = JwtSigner::new(b"my-secret-key");

// Encode
let token = signer.encode(&Claims {
    sub: "user-1".into(),
    role: "admin".into(),
    exp: 9999999999,
}).unwrap();

// Decode and verify
let decoded: Claims = signer.decode(&token).unwrap();
assert_eq!(decoded.sub, "user-1");

// Unverified decode (for debugging only)
let decoded: Claims = signer.decode_unverified(&token).unwrap();
```

---

## Password Policy

Configurable password validation with strength estimation.

```rust
use rok_crypto::password_policy::{PasswordPolicy, PasswordStrength};

let policy = PasswordPolicy::default();

// Validate
assert!(policy.validate("StrongPass1!").is_ok());

// Reject weak passwords
assert!(policy.validate("short").is_err());
assert!(policy.validate("nouppercase1!").is_err());
assert!(policy.validate("NOLOWERCASE1!").is_err());

// Strength estimation (0-4)
match policy.strength("HelloWorld1!") {
    PasswordStrength::Strong => println!("👍"),
    _ => println!("needs improvement"),
}

// Custom policy
let strict = PasswordPolicy::new(12, 64, 2, 2, 2, 2);
```

Default policy: min 8, max 128, at least 1 uppercase, 1 lowercase, 1 digit, 1 special character, no 3+ consecutive identical characters.

---

## CryptoProvider

Unified facade bundling hasher, encrypter, and signer.

```rust
use rok_crypto::provider::CryptoProvider;
use rok_crypto::util::from_env::FromEnv;

let provider = CryptoProvider::from_env()?;

// Hash (requires `hash` feature)
let hash = provider.hash_make("password")?;
assert!(provider.hash_verify("password", &hash)?);

// Encrypt (requires `encrypt` feature)
let token = provider.encrypt_seal("sensitive");
assert_eq!(provider.encrypt_open(&token).unwrap(), "sensitive");

// Sign (requires `encrypt` feature)
let sig = provider.sign_data("payload");
assert!(provider.verify_signature("payload", &sig));
```

---

## Secure Utilities

### Random helpers (requires `ids` or `encrypt` feature)

```rust
use rok_crypto::util::rand;

// Secure random hex string
let hex = rand::hex(32);       // 64 chars, 32 bytes of entropy

// Secure random alphanumeric
let tok = rand::alphanumeric(32); // URL-safe, 32 chars

// Constant-time comparison
assert!(rand::constant_time_eq(b"abc", b"abc"));
assert!(!rand::constant_time_eq(b"abc", b"def"));
```

### Secret management (requires `zeroize` feature)

```rust
use rok_crypto::util::secret::{Redacted, SecretKey};

// Redacted displays as "***" — safe for logging
let secret = Redacted::new("my-api-key".to_string());
assert_eq!(secret.to_string(), "***");
let key: String = secret.into_inner(); // extract when needed

// Fixed-size key that zeroizes on drop
let key = SecretKey::<32>::new([0u8; 32]);
assert_eq!(key.len(), 32);
```

### FromEnv trait

```rust
use rok_crypto::util::from_env::FromEnv;

// Implement on your own types
struct MyConfig { key: String }

impl FromEnv for MyConfig {
    type Error = String;
    fn from_env() -> Result<Self, Self::Error> {
        Ok(Self {
            key: std::env::var("MY_KEY").map_err(|e| e.to_string())?,
        })
    }
}
```

### Macros

```rust
use rok_crypto::{constant_time_eq, declare_id};

// Constant-time comparison macro
assert!(constant_time_eq!(b"abc", b"abc"));

// Generate Display/FromStr/AsRef/Ord for newtype IDs
struct MyId(String);
declare_id!(MyId, "myid", 16);
```

---

## Error Handling

All fallible operations return `Result` with typed errors:

| Error | Module | Variants |
|-------|--------|----------|
| `HashError` | `hash` | `HashFailed`, `InvalidParams`, `UnsupportedDriver` |
| `EncryptError` | `encrypt` | `DecryptionFailed`, `InvalidFormat`, `Expired`, `WrongPurpose` |
| `SignError` | `encrypt::Signer` | `InvalidBase64` |
| `JwtError` | `jwt` | `Serialization`, `Deserialization`, `InvalidFormat`, `InvalidBase64`, `InvalidSignature`, `Expired` |
| `TOTPError` | `totp` | (currently unused, reserved) |

---

## Module Structure

```
rok-crypto
├── ids/              # Feature-gated ID generators
│   ├── cuid2
│   ├── ulid
│   ├── uuid_v7
│   ├── nanoid
│   └── snowflake
├── hash/             # Password hashing
│   ├── config        # HashConfig, Driver, per-driver configs
│   ├── driver        # HashDriver trait (internal)
│   ├── drivers/      # argon2, bcrypt, scrypt
│   ├── error         # HashError
│   └── auth_finder   # AuthFinder trait
├── encrypt/          # AES-256-GCM + HMAC-SHA256
│   ├── config        # EncryptConfig with key rotation
│   ├── error         # EncryptError
│   └── signer        # Signer, SignError
├── util/             # Shared utilities
│   ├── from_env      # FromEnv trait
│   ├── rand          # hex, alphanumeric, constant_time_eq
│   ├── secret        # Redacted, SecretKey (zeroize-gated)
│   └── mod.rs        # declare_id!, constant_time_eq! macros
├── provider.rs       # CryptoProvider (hash + encrypt facade)
├── totp.rs           # TOTP (RFC 6238)
├── jwt.rs            # HS256 JWT signer
└── password_policy.rs# Password validation + strength
```

---

## Development

```bash
# Quick test (default features)
cargo test

# Full suite
cargo test --features full

# Single module
cargo test --no-default-features --features encrypt
cargo test --no-default-features --features ids

# Lint
cargo clippy --all-targets --features full

# Publish checklist
cargo test --features full
cargo clippy --all-targets --features full
# bump version, then:
cargo publish
```

---

## License

MIT
