use super::HashError;

/// Internal hashing contract implemented by each driver.
pub(crate) trait HashDriver: Send + Sync + 'static {
    /// Hash `password` and return the encoded string (PHC or native format).
    fn hash(&self, password: &str) -> Result<String, HashError>;

    /// Return `true` if `password` matches the previously-hashed `hash`.
    fn verify(&self, password: &str, hash: &str) -> Result<bool, HashError>;

    /// Return `true` if `hash` was produced with weaker parameters than the
    /// current configuration, meaning it should be rehashed on next login.
    fn needs_rehash(&self, hash: &str) -> bool;
}
