use super::super::{config::BcryptConfig, driver::HashDriver, HashError};

pub(crate) struct BcryptDriver {
    config: BcryptConfig,
}

impl BcryptDriver {
    pub(crate) fn new(config: BcryptConfig) -> Self {
        Self { config }
    }
}

impl HashDriver for BcryptDriver {
    fn hash(&self, password: &str) -> Result<String, HashError> {
        bcrypt::hash(password, self.config.cost).map_err(|e| HashError::HashFailed(e.to_string()))
    }

    fn verify(&self, password: &str, hash: &str) -> Result<bool, HashError> {
        bcrypt::verify(password, hash).map_err(|e| HashError::HashFailed(e.to_string()))
    }

    fn needs_rehash(&self, hash: &str) -> bool {
        // bcrypt format: $2b$12$<22-char-salt><31-char-hash>
        // Splitting "$2b$12$..." on '$' gives ["", "2b", "12", "..."]
        let mut parts = hash.splitn(4, '$');
        parts.next(); // leading empty string
        parts.next(); // version (2a / 2b / 2y)
        let stored_cost: u32 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
        stored_cost < self.config.cost
    }
}
