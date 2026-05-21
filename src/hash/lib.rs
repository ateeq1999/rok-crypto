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
use drivers::{argon2::Argon2Driver, bcrypt::BcryptDriver, scrypt::ScryptDriver};

/// Password-hashing façade with pluggable drivers.
///
/// Constructed once (usually at startup) and shared via `Arc`.
///
/// # Example
///
/// ```rust,ignore
/// use rok_hash::{HashConfig, Hasher};
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
    /// Create a `Hasher` from `config`, selecting and initialising the
    /// appropriate driver.
    pub fn from_config(config: HashConfig) -> Self {
        let inner: Arc<dyn HashDriver> = match config.driver {
            Driver::Argon2 => Arc::new(Argon2Driver::new(config.argon2)),
            Driver::Bcrypt => Arc::new(BcryptDriver::new(config.bcrypt)),
            Driver::Scrypt => Arc::new(ScryptDriver::new(config.scrypt)),
        };
        Self { inner }
    }

    /// Hash `password` using the configured driver.
    ///
    /// The returned string is self-describing (PHC or bcrypt format) and can
    /// be stored directly in the database.
    pub fn make(&self, password: &str) -> Result<String, HashError> {
        self.inner.hash(password)
    }

    /// Return `true` if `password` matches `hash`.
    ///
    /// The algorithm and parameters are read from the `hash` string itself,
    /// so this works even if the driver configuration was changed since the
    /// hash was created.
    pub fn verify(&self, password: &str, hash: &str) -> Result<bool, HashError> {
        self.inner.verify(password, hash)
    }

    /// Return `true` if `hash` was produced with parameters weaker than the
    /// current configuration.
    ///
    /// Call this after a successful [`verify`](Self::verify) and rehash if
    /// `true` is returned, then persist the new hash.
    pub fn needs_rehash(&self, hash: &str) -> bool {
        self.inner.needs_rehash(hash)
    }

    // ── AuthFinder helpers ────────────────────────────────────────────────────

    /// Verify `password` against the hash stored on `user`.
    pub fn verify_for<U: AuthFinder>(&self, password: &str, user: &U) -> Result<bool, HashError> {
        self.verify(password, user.get_auth_password())
    }

    /// `true` if the hash stored on `user` should be rehashed.
    pub fn needs_rehash_for<U: AuthFinder>(&self, user: &U) -> bool {
        self.needs_rehash(user.get_auth_password())
    }
}

impl Clone for Hasher {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}
