use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum CertificateError {
    #[error("Invalid {0}")]
    Invalid(&'static str),
    #[error("Private key not found")]
    PrivateKeyNotFound,
    #[error("Certificate not found")]
    CertificateNotFound,
    #[error("Invalid PEM")]
    InvalidPem(#[from] pem::PemError),
    #[error("Certificate expired")]
    CertificateExpired,
}
