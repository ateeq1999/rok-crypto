use std::fmt;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum HashError {
    #[error("hashing failed: {0}")]
    HashFailed(String),

    #[error("invalid hash format")]
    InvalidFormat,

    #[error("invalid parameters: {0}")]
    InvalidParams(String),
}

impl HashError {
    pub(crate) fn hash_failed(msg: impl fmt::Display) -> Self {
        Self::HashFailed(msg.to_string())
    }

    pub(crate) fn invalid_params(msg: impl fmt::Display) -> Self {
        Self::InvalidParams(msg.to_string())
    }
}
