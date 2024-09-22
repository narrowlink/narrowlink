use thiserror::Error;

#[derive(Error, Debug)]
pub enum NetworkError {
    #[error("Invalid Socket: {0}")]
    InvalidSocket(std::io::Error),
    #[error("Invalid TLS Error: {0}")]
    TlsError(std::io::Error),
}
