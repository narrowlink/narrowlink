use thiserror::Error;

#[derive(Error, Debug)]
pub enum CertificateError {
    #[error("Invalid {0}")]
    Invalid(&'static str),
    #[error("Private key not found")]
    PrivateKeyNotFound,
}

