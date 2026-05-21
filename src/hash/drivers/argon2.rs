use argon2::{Algorithm, Argon2, Params, Version};
use password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString};

use crate::{config::Argon2Config, driver::HashDriver, HashError};

pub(crate) struct Argon2Driver {
    config: Argon2Config,
}

impl Argon2Driver {
    pub(crate) fn new(config: Argon2Config) -> Self {
        Self { config }
    }

    fn argon2(&self) -> Result<Argon2<'static>, HashError> {
        let params = Params::new(
            self.config.memory_kib,
            self.config.iterations,
            self.config.parallelism,
            None,
        )
        .map_err(|e| HashError::InvalidParams(e.to_string()))?;
        Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
    }
}

impl HashDriver for Argon2Driver {
    fn hash(&self, password: &str) -> Result<String, HashError> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = self.argon2()?;
        argon2
            .hash_password(password.as_bytes(), &salt)
            .map(|h| h.to_string())
            .map_err(|e| HashError::HashFailed(e.to_string()))
    }

    fn verify(&self, password: &str, hash: &str) -> Result<bool, HashError> {
        let parsed = PasswordHash::new(hash).map_err(|_| HashError::InvalidFormat)?;
        Ok(Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok())
    }

    fn needs_rehash(&self, hash: &str) -> bool {
        let Ok(parsed) = PasswordHash::new(hash) else {
            return true;
        };
        if parsed.algorithm.as_str() != "argon2id" {
            return true;
        }
        let mut m = 0u32;
        let mut t = 0u32;
        let mut p = 0u32;
        for (key, val) in parsed.params.iter() {
            match key.as_str() {
                "m" => {
                    if let Ok(n) = val.decimal() {
                        m = n;
                    }
                }
                "t" => {
                    if let Ok(n) = val.decimal() {
                        t = n;
                    }
                }
                "p" => {
                    if let Ok(n) = val.decimal() {
                        p = n;
                    }
                }
                _ => {}
            }
        }
        m < self.config.memory_kib || t < self.config.iterations || p < self.config.parallelism
    }
}
