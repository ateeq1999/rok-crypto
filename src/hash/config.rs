#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Driver {
    #[default]
    Argon2,
    Bcrypt,
    Scrypt,
}

#[derive(Debug, Clone)]
pub struct Argon2Config {
    pub memory_kib: u32,
    pub iterations: u32,
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

impl Argon2Config {
    pub fn new(memory_kib: u32, iterations: u32, parallelism: u32) -> Self {
        Self {
            memory_kib,
            iterations,
            parallelism,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BcryptConfig {
    pub cost: u32,
}

impl Default for BcryptConfig {
    fn default() -> Self {
        Self { cost: 12 }
    }
}

impl BcryptConfig {
    pub fn new(cost: u32) -> Self {
        Self { cost }
    }
}

#[derive(Debug, Clone)]
pub struct ScryptConfig {
    pub log_n: u8,
    pub r: u32,
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

impl ScryptConfig {
    pub fn new(log_n: u8, r: u32, p: u32) -> Self {
        Self { log_n, r, p }
    }
}

#[derive(Debug, Clone, Default)]
pub struct HashConfig {
    pub driver: Driver,
    pub argon2: Argon2Config,
    pub bcrypt: BcryptConfig,
    pub scrypt: ScryptConfig,
}

impl HashConfig {
    pub fn argon2(memory_kib: u32, iterations: u32, parallelism: u32) -> Self {
        Self {
            driver: Driver::Argon2,
            argon2: Argon2Config::new(memory_kib, iterations, parallelism),
            ..Self::default()
        }
    }

    pub fn bcrypt(cost: u32) -> Self {
        Self {
            driver: Driver::Bcrypt,
            bcrypt: BcryptConfig::new(cost),
            ..Self::default()
        }
    }

    pub fn scrypt(log_n: u8, r: u32, p: u32) -> Self {
        Self {
            driver: Driver::Scrypt,
            scrypt: ScryptConfig::new(log_n, r, p),
            ..Self::default()
        }
    }

    pub fn with_driver(mut self, driver: Driver) -> Self {
        self.driver = driver;
        self
    }

    pub fn with_argon2(mut self, cfg: Argon2Config) -> Self {
        self.argon2 = cfg;
        self
    }

    pub fn with_bcrypt(mut self, cfg: BcryptConfig) -> Self {
        self.bcrypt = cfg;
        self
    }

    pub fn with_scrypt(mut self, cfg: ScryptConfig) -> Self {
        self.scrypt = cfg;
        self
    }
}
