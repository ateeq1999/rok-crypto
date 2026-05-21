/// Which hashing algorithm the [`Hasher`](crate::Hasher) will use.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Driver {
    /// Argon2id — recommended default; memory-hard, resistant to GPU attacks.
    #[default]
    Argon2,
    /// Bcrypt — widely deployed legacy choice; simpler cost parameter.
    Bcrypt,
    /// Scrypt — memory-hard alternative to Argon2.
    Scrypt,
}

/// Argon2 tuning parameters.
#[derive(Debug, Clone)]
pub struct Argon2Config {
    /// Memory usage in KiB (default: 19 456 = 19 MiB).
    pub memory_kib: u32,
    /// Number of passes over memory (default: 2).
    pub iterations: u32,
    /// Degree of parallelism / number of lanes (default: 1).
    pub parallelism: u32,
}

impl Default for Argon2Config {
    fn default() -> Self {
        Self {
            memory_kib: 19_456,
            iterations: 2,
            parallelism: 1,
        }
    }
}

/// Bcrypt tuning parameters.
#[derive(Debug, Clone)]
pub struct BcryptConfig {
    /// Work factor, 2^cost iterations (default: 12).
    pub cost: u32,
}

impl Default for BcryptConfig {
    fn default() -> Self {
        Self { cost: 12 }
    }
}

/// Scrypt tuning parameters.
#[derive(Debug, Clone)]
pub struct ScryptConfig {
    /// CPU/memory cost parameter as a power-of-two exponent (default: 17 → N=131072).
    pub log_n: u8,
    /// Block size (default: 8).
    pub r: u32,
    /// Parallelisation factor (default: 1).
    pub p: u32,
}

impl Default for ScryptConfig {
    fn default() -> Self {
        Self {
            log_n: 17,
            r: 8,
            p: 1,
        }
    }
}

/// Top-level configuration for [`Hasher`](crate::Hasher).
#[derive(Debug, Clone, Default)]
pub struct HashConfig {
    /// Active hashing driver.
    pub driver: Driver,
    /// Argon2 parameters (used when `driver == Driver::Argon2`).
    pub argon2: Argon2Config,
    /// Bcrypt parameters (used when `driver == Driver::Bcrypt`).
    pub bcrypt: BcryptConfig,
    /// Scrypt parameters (used when `driver == Driver::Scrypt`).
    pub scrypt: ScryptConfig,
}
