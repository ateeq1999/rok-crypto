/// Trait for types that can be constructed from environment variables.
///
/// # Example
///
/// ```rust,ignore
/// use rok_crypto::util::from_env::FromEnv;
/// use rok_crypto::hash::Hasher;
///
/// let hasher = Hasher::from_env().expect("HASH_DRIVER and HASH_* vars");
/// ```
pub trait FromEnv: Sized {
    type Error;

    /// Build from environment variables.
    fn from_env() -> Result<Self, Self::Error>;
}
