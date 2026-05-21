#[cfg(feature = "hash")]
#[cfg(feature = "hash")]
use rok_crypto::hash::{Argon2Config, AuthFinder, Driver, HashConfig, Hasher};

#[cfg(feature = "bcrypt")]
use rok_crypto::hash::BcryptConfig;

#[cfg(feature = "scrypt")]
use rok_crypto::hash::ScryptConfig;

// ── fast test configs ─────────────────────────────────────────────────────────

#[cfg(feature = "argon2")]
fn argon2_config() -> HashConfig {
    HashConfig {
        driver: Driver::Argon2,
        argon2: Argon2Config {
            memory_kib: 1024, // 1 MiB
            iterations: 1,
            parallelism: 1,
        },
        ..HashConfig::default()
    }
}

#[cfg(feature = "bcrypt")]
fn bcrypt_config() -> HashConfig {
    HashConfig {
        driver: Driver::Bcrypt,
        bcrypt: BcryptConfig { cost: 4 },
        ..HashConfig::default()
    }
}

#[cfg(feature = "scrypt")]
fn scrypt_config() -> HashConfig {
    HashConfig {
        driver: Driver::Scrypt,
        scrypt: ScryptConfig {
            log_n: 4,
            r: 8,
            p: 1,
        },
        ..HashConfig::default()
    }
}

// ── AuthFinder test model ─────────────────────────────────────────────────────

#[cfg(feature = "hash")]
struct FakeUser {
    password_hash: String,
}

#[cfg(feature = "hash")]
impl AuthFinder for FakeUser {
    fn get_auth_password(&self) -> &str {
        &self.password_hash
    }
}

// ── Argon2 ────────────────────────────────────────────────────────────────────

#[cfg(feature = "argon2")]
#[test]
fn argon2_make_and_verify() {
    let h = Hasher::from_config(argon2_config());
    let hash = h.make("s3cr3t").unwrap();
    assert!(hash.starts_with("$argon2"), "PHC prefix: {hash}");
    assert!(h.verify("s3cr3t", &hash).unwrap());
    assert!(!h.verify("wrong", &hash).unwrap());
}

#[cfg(feature = "argon2")]
#[test]
fn argon2_does_not_need_rehash_with_same_params() {
    let h = Hasher::from_config(argon2_config());
    let hash = h.make("pass").unwrap();
    assert!(!h.needs_rehash(&hash));
}

#[cfg(feature = "argon2")]
#[test]
fn argon2_needs_rehash_after_config_upgrade() {
    let low = Hasher::from_config(argon2_config());
    let hash = low.make("pass").unwrap();

    let high = Hasher::from_config(HashConfig {
        driver: Driver::Argon2,
        argon2: Argon2Config {
            memory_kib: 4096,
            iterations: 2,
            parallelism: 1,
        },
        ..HashConfig::default()
    });
    assert!(high.needs_rehash(&hash));
}

#[cfg(feature = "argon2")]
#[test]
fn argon2_needs_rehash_with_invalid_format() {
    let h = Hasher::from_config(argon2_config());
    assert!(h.needs_rehash("not-a-valid-hash"));
}

#[cfg(feature = "argon2")]
#[test]
fn argon2_unique_hashes_per_call() {
    let h = Hasher::from_config(argon2_config());
    let a = h.make("same_password").unwrap();
    let b = h.make("same_password").unwrap();
    assert_ne!(a, b, "each hash should use a fresh random salt");
}

// ── Bcrypt ────────────────────────────────────────────────────────────────────

#[cfg(feature = "bcrypt")]
#[test]
fn bcrypt_make_and_verify() {
    let h = Hasher::from_config(bcrypt_config());
    let hash = h.make("password").unwrap();
    assert!(hash.starts_with("$2"), "bcrypt prefix: {hash}");
    assert!(h.verify("password", &hash).unwrap());
    assert!(!h.verify("wrong", &hash).unwrap());
}

#[cfg(feature = "bcrypt")]
#[test]
fn bcrypt_does_not_need_rehash_with_same_cost() {
    let h = Hasher::from_config(bcrypt_config());
    let hash = h.make("pass").unwrap();
    assert!(!h.needs_rehash(&hash));
}

#[cfg(feature = "bcrypt")]
#[test]
fn bcrypt_needs_rehash_after_cost_increase() {
    let low = Hasher::from_config(bcrypt_config());
    let hash = low.make("pass").unwrap();

    let high = Hasher::from_config(HashConfig {
        driver: Driver::Bcrypt,
        bcrypt: BcryptConfig { cost: 8 },
        ..HashConfig::default()
    });
    assert!(high.needs_rehash(&hash));
}

#[cfg(feature = "bcrypt")]
#[test]
fn bcrypt_unique_hashes_per_call() {
    let h = Hasher::from_config(bcrypt_config());
    let a = h.make("same").unwrap();
    let b = h.make("same").unwrap();
    assert_ne!(a, b);
}

// ── Scrypt ────────────────────────────────────────────────────────────────────

#[cfg(feature = "scrypt")]
#[test]
fn scrypt_make_and_verify() {
    let h = Hasher::from_config(scrypt_config());
    let hash = h.make("hunter2").unwrap();
    assert!(hash.starts_with("$scrypt"), "PHC prefix: {hash}");
    assert!(h.verify("hunter2", &hash).unwrap());
    assert!(!h.verify("wrong", &hash).unwrap());
}

#[cfg(feature = "scrypt")]
#[test]
fn scrypt_does_not_need_rehash_with_same_params() {
    let h = Hasher::from_config(scrypt_config());
    let hash = h.make("pass").unwrap();
    assert!(!h.needs_rehash(&hash));
}

#[cfg(feature = "scrypt")]
#[test]
fn scrypt_needs_rehash_after_log_n_increase() {
    let low = Hasher::from_config(scrypt_config());
    let hash = low.make("pass").unwrap();

    let high = Hasher::from_config(HashConfig {
        driver: Driver::Scrypt,
        scrypt: ScryptConfig {
            log_n: 6,
            r: 8,
            p: 1,
        },
        ..HashConfig::default()
    });
    assert!(high.needs_rehash(&hash));
}

// ── Default config ────────────────────────────────────────────────────────────

#[cfg(feature = "hash")]
#[test]
fn default_config_uses_argon2() {
    let h = Hasher::from_config(HashConfig::default());
    let hash = h.make("pass").unwrap();
    assert!(
        hash.contains("argon2id"),
        "default driver is Argon2: {hash}"
    );
    assert!(h.verify("pass", &hash).unwrap());
}

// ── AuthFinder helpers ────────────────────────────────────────────────────────

#[cfg(feature = "hash")]
#[test]
fn verify_for_and_needs_rehash_for() {
    let h = Hasher::from_config(argon2_config());
    let hash = h.make("secret").unwrap();
    let user = FakeUser {
        password_hash: hash,
    };

    assert!(h.verify_for("secret", &user).unwrap());
    assert!(!h.verify_for("wrong", &user).unwrap());
    assert!(!h.needs_rehash_for(&user));
}

// ── Hasher::clone ─────────────────────────────────────────────────────────────

#[cfg(feature = "hash")]
#[test]
fn hasher_is_clone() {
    let h1 = Hasher::from_config(argon2_config());
    let h2 = h1.clone();
    let hash = h1.make("pw").unwrap();
    assert!(h2.verify("pw", &hash).unwrap());
}
