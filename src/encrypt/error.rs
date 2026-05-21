use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EncryptError {
    #[error("decryption failed")]
    DecryptionFailed,

    #[error("invalid token format: {0}")]
    InvalidFormat(String),

    #[error("token has expired")]
    Expired,

    #[error("wrong purpose: expected `{expected}`, got `{actual}`")]
    WrongPurpose { expected: String, actual: String },
}

impl EncryptError {
    pub(crate) fn invalid_format(msg: impl std::fmt::Display) -> Self {
        Self::InvalidFormat(msg.to_string())
    }
}
