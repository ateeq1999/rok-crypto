use password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use scrypt::{Params, Scrypt};

use super::super::{config::ScryptConfig, driver::HashDriver, HashError};

pub(crate) struct ScryptDriver {
    config: ScryptConfig,
}

impl ScryptDriver {
    pub(crate) fn new(config: ScryptConfig) -> Self {
        Self { config }
    }

    fn params(&self) -> Result<Params, HashError> {
        Params::new(
            self.config.log_n,
            self.config.r,
            self.config.p,
            Params::RECOMMENDED_LEN,
        )
        .map_err(|e| HashError::invalid_params(e.to_string()))
    }
}

impl HashDriver for ScryptDriver {
    fn hash(&self, password: &str) -> Result<String, HashError> {
        let params = self.params()?;
        let salt = SaltString::generate(&mut OsRng);
        let hash = Scrypt
            .hash_password_customized(password.as_bytes(), None, None, params, &salt)
            .map_err(|e| HashError::hash_failed(e.to_string()))?;
        Ok(hash.to_string())
    }

    fn verify(&self, password: &str, hash: &str) -> Result<bool, HashError> {
        let parsed = PasswordHash::new(hash).map_err(|_| HashError::InvalidFormat)?;
        Ok(Scrypt.verify_password(password.as_bytes(), &parsed).is_ok())
    }

    fn needs_rehash(&self, hash: &str) -> bool {
        let Ok(parsed) = PasswordHash::new(hash) else {
            return true;
        };
        if parsed.algorithm.as_str() != "scrypt" {
            return true;
        }
        let mut ln = 0u32;
        let mut r = 0u32;
        let mut p = 0u32;
        for (key, val) in parsed.params.iter() {
            match key.as_str() {
                "ln" => if let Ok(n) = val.decimal() { ln = n; }
                "r"  => if let Ok(n) = val.decimal() { r = n; }
                "p"  => if let Ok(n) = val.decimal() { p = n; }
                _ => {}
            }
        }
        (ln as u8) < self.config.log_n || r < self.config.r || p < self.config.p
    }
}
