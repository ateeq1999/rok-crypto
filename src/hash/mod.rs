mod auth_finder;
mod config;
mod driver;
mod drivers;
mod error;

pub use auth_finder::AuthFinder;
pub use config::{Argon2Config, BcryptConfig, Driver, HashConfig, ScryptConfig};
pub use error::HashError;

use std::sync::Arc;

use driver::HashDriver;
#[cfg(feature = "argon2")]
use drivers::argon2::Argon2Driver;
#[cfg(feature = "bcrypt")]
use drivers::bcrypt::BcryptDriver;
#[cfg(feature = "scrypt")]
use drivers::scrypt::ScryptDriver;

use crate::util::from_env::FromEnv;

/// Password-hashing façade with pluggable drivers.
///
/// Constructed once (usually at startup) and shared via `Arc`.
///
/// # Example
///
/// ```rust,ignore
/// use rok_crypto::hash::{HashConfig, Hasher};
///
/// let hasher = Hasher::from_config(HashConfig::default());
///
/// let hash = hasher.make("hunter2").unwrap();
/// assert!(hasher.verify("hunter2", &hash).unwrap());
/// assert!(!hasher.needs_rehash(&hash));
/// ```
pub struct Hasher {
    inner: Arc<dyn HashDriver>,
}

impl Hasher {
    pub fn from_config(config: HashConfig) -> Self {
        let inner: Arc<dyn HashDriver> = match config.driver {
            Driver::Argon2 => Arc::new(Argon2Driver::new(config.argon2)),
            #[cfg(feature = "bcrypt")]
            Driver::Bcrypt => Arc::new(BcryptDriver::new(config.bcrypt)),
            #[cfg(not(feature = "bcrypt"))]
            Driver::Bcrypt => panic!("Bcrypt support not enabled (enable feature 'bcrypt')"),
            #[cfg(feature = "scrypt")]
            Driver::Scrypt => Arc::new(ScryptDriver::new(config.scrypt)),
            #[cfg(not(feature = "scrypt"))]
            Driver::Scrypt => panic!("Scrypt support not enabled (enable feature 'scrypt')"),
        };
        Self { inner }
    }

    pub fn make(&self, password: &str) -> Result<String, HashError> {
        self.inner.hash(password)
    }

    /// Non-blocking hash — runs on `tokio::task::spawn_blocking`.
    ///
    /// Requires the `tokio` feature.
    #[cfg(feature = "tokio")]
    pub async fn make_async(&self, password: String) -> Result<String, HashError> {
        let this = self.inner.clone();
        tokio::task::spawn_blocking(move || this.hash(&password))
            .await
            .map_err(|e| HashError::HashFailed(e.to_string()))?
    }

    pub fn verify(&self, password: &str, hash: &str) -> Result<bool, HashError> {
        self.inner.verify(password, hash)
    }

    /// Non-blocking verify — runs on `tokio::task::spawn_blocking`.
    #[cfg(feature = "tokio")]
    pub async fn verify_async(&self, password: String, hash: String) -> Result<bool, HashError> {
        let this = self.inner.clone();
        tokio::task::spawn_blocking(move || this.verify(&password, &hash))
            .await
            .map_err(|e| HashError::HashFailed(e.to_string()))?
    }

    pub fn needs_rehash(&self, hash: &str) -> bool {
        self.inner.needs_rehash(hash)
    }

    pub fn verify_for<U: AuthFinder>(&self, password: &str, user: &U) -> Result<bool, HashError> {
        self.verify(password, user.get_auth_password())
    }

    pub fn needs_rehash_for<U: AuthFinder>(&self, user: &U) -> bool {
        self.needs_rehash(user.get_auth_password())
    }
}

impl FromEnv for Hasher {
    type Error = String;

    fn from_env() -> Result<Self, Self::Error> {
        let driver = std::env::var("HASH_DRIVER")
            .unwrap_or_else(|_| "argon2".into());

        let config = match driver.as_str() {
            "argon2" => {
                let mem = std::env::var("HASH_MEMORY_KIB")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(19_456);
                let iters = std::env::var("HASH_ITERATIONS")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(2);
                let par = std::env::var("HASH_PARALLELISM")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(1);
                HashConfig::argon2(mem, iters, par)
            }
            "bcrypt" => {
                let cost = std::env::var("HASH_COST")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(12);
                HashConfig::bcrypt(cost)
            }
            "scrypt" => {
                let log_n = std::env::var("HASH_LOG_N")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(17u8);
                let r = std::env::var("HASH_R")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(8);
                let p = std::env::var("HASH_P")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(1);
                HashConfig::scrypt(log_n, r, p)
            }
            _ => return Err(format!("unknown HASH_DRIVER: {}", driver)),
        };

        Ok(Self::from_config(config))
    }
}

impl Clone for Hasher {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}
