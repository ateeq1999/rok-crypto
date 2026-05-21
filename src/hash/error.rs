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
