use thiserror::Error;

#[derive(Error, Debug)]
pub enum MessageError {
    #[error("JWT Error: {0}")]
    JwtError(#[from] jsonwebtoken::errors::Error),
    #[error("SerdeJson Error: {0}")]
    SerdeJsonError(#[from] serde_json::Error),
}
