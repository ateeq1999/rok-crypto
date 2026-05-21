# Agent Guide: rok-crypto

Consolidated cryptographic primitives crate. Three modules, one crate, feature-gated.

## Crate structure

```
src/
├── lib.rs              # Feature-gated module declarations
├── ids/                # rok_crypto::ids — ID generators
│   ├── mod.rs          # Re-exports Cuid2, Ulid, UuidV7, NanoId, Snowflake
│   ├── cuid2.rs        # SHA-3 fingerprinted, 24-char, URL-safe
│   ├── ulid.rs         # Crockford base32, monotonic mode
│   ├── uuid_v7.rs      # Wrapper around uuid::Uuid::new_v7
│   ├── nanoid.rs       # Configurable alphabet/length, rejection sampling
│   └── snowflake.rs    # 64-bit timestamp+worker+sequence
├── hash/               # rok_crypto::hash — password hashing
│   ├── mod.rs          # Hasher façade, re-exports
│   ├── config.rs       # HashConfig, Driver enum, per-driver configs
│   ├── driver.rs       # HashDriver trait (pub(crate))
│   ├── drivers/        # Per-algorithm implementations
│   │   ├── mod.rs      # Feature-gated submodule declarations
│   │   ├── argon2.rs   # Argon2id via argon2 crate
│   │   ├── bcrypt.rs   # Via bcrypt crate
│   │   └── scrypt.rs   # Via scrypt crate
│   ├── error.rs        # HashError enum
│   └── auth_finder.rs  # AuthFinder trait
└── encrypt/            # rok_crypto::encrypt — encryption + signing
    ├── mod.rs          # Encrypter, re-exports
    ├── config.rs       # EncryptConfig with key rotation
    ├── error.rs        # EncryptError enum
    └── signer.rs       # HMAC-SHA256 Signer
tests/
├── hash.rs             # Integration tests (feature-gated)
└── encrypt.rs          # Integration tests (feature-gated)
```

## Feature flag rules

- **`ids`** activates `cuid2`, `ulid`, `uuid-v7`, `nanoid` — all need `dep:rand` except `uuid-v7` (needs `dep:uuid`)
- **`snowflake`** is standalone (no extra deps beyond `serde`)
- **`hash`** implies `argon2` (always-on driver)
- **`bcrypt`** and **`scrypt`** are optional — their driver modules are `#[cfg(feature = "...")]` gated
- **`encrypt`** activates aes-gcm, hmac, base64, sha2, serde_json, chrono, rand

### When adding a new file

1. Add `#[cfg(feature = "xxx")]` to the `mod` declaration in the parent module
2. Gate all `use` imports from optional deps with the same feature
3. If adding a new driver to `hash/`, add a `#[cfg]` match arm + a `#[cfg(not)]` panic arm in `Hasher::from_config`
4. Add `#[cfg(feature = "xxx")]` to each integration test function

### When adding a new dependency

1. Add `dep:xxx` to the relevant `[features]` entry in `Cargo.toml`
2. Add the dep as `optional = true` in `[dependencies]`
3. Gate all `use` imports behind `#[cfg(feature = "xxx")]`

## Public API conventions

- Top-level re-exports go through `rok_crypto::module::TypeName`
- No `pub use` at `rok_crypto::TypeName` — always namespaced
- All error types are `thiserror` enums
- All ID types implement: `Display`, `FromStr`, `Serialize`, `Deserialize`, `AsRef<str>`
- SQLx impls live in `#[cfg(feature = "sqlx-postgres")] mod sqlx_impl { }` blocks within each ID file

## Testing

```bash
# Quick: default features (ids + hash/argon2 + encrypt)
cargo test

# Full suite
cargo test --features full

# Single module
cargo test --no-default-features --features encrypt
cargo test -p rok-crypto --test encrypt
```

## Publishing checklist

1. `cargo test --features full`
2. `cargo clippy --all-targets --features full`
3. Bump version in `Cargo.toml`
4. `cargo publish`
