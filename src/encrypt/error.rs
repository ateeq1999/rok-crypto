use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EncryptError {
    #[error("decryption failed")]
    DecryptionFailed,

    #[error("invalid token format")]
    InvalidFormat,

    #[error("token has expired")]
    Expired,

    #[error("wrong purpose: expected `{expected}`, got `{actual}`")]
    WrongPurpose { expected: String, actual: String },
}
