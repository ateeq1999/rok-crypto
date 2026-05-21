use std::fmt;
use std::str::FromStr;

use rand::RngCore;
use serde::{Deserialize, Serialize};

use super::IdError;

pub const DEFAULT_ALPHABET: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
pub const DEFAULT_SIZE: usize = 21;

pub fn generate_nanoid_custom(alphabet: &[u8], size: usize) -> String {
    assert!(!alphabet.is_empty(), "nanoid: alphabet must not be empty");
    assert!(
        alphabet.len() <= 256,
        "nanoid: alphabet too large (max 256)"
    );

    let mut rng = rand::thread_rng();
    let alen = alphabet.len();

    let mask = {
        let mut m = 1usize;
        while m < alen {
            m = (m << 1) | 1;
        }
        m
    };

    let mut result = Vec::with_capacity(size);
    let mut buf = [0u8; 256];

    while result.len() < size {
        rng.fill_bytes(&mut buf);
        for &b in &buf {
            let idx = (b as usize) & mask;
            if idx < alen {
                result.push(alphabet[idx]);
                if result.len() == size {
                    break;
                }
            }
        }
    }

    String::from_utf8(result).expect("nanoid alphabet must be ASCII")
}

/// A NanoID — short, URL-safe, configurable-length random identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct NanoId(String);

impl NanoId {
    pub fn generate() -> Self {
        Self(generate_nanoid_custom(DEFAULT_ALPHABET, DEFAULT_SIZE))
    }

    pub fn new() -> Self {
        Self::generate()
    }

    pub fn with_size(size: usize) -> Self {
        Self(generate_nanoid_custom(DEFAULT_ALPHABET, size))
    }

    pub fn custom(alphabet: &[u8], size: usize) -> Self {
        Self(generate_nanoid_custom(alphabet, size))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for NanoId {
    fn default() -> Self {
        Self::generate()
    }
}

impl fmt::Display for NanoId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for NanoId {
    type Err = IdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err(IdError::InvalidFormat("nanoid", "must not be empty"));
        }
        Ok(Self(s.to_owned()))
    }
}

impl AsRef<str> for NanoId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}
