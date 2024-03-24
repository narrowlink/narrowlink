mod certificate;
pub use certificate::CertificateError;
mod network;
pub use network::NetworkError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum GatewayError {
    #[error("Invalid {0}")]
    Invalid(&'static str),
    #[error("ACME Error: {0}")]
    ACMEError(#[from] instant_acme::Error),
    #[error("Certificate Error: {0}")]
    CertificateError(#[from] CertificateError),
    #[error("Network Error: {0}")]
    NetworkError(#[from] NetworkError),
    #[error("IO Error: {0}")]
    IOError(#[from] std::io::Error),
}

// impl std::cmp::PartialEq<CertificateError> for GatewayError {
//     fn eq(&self, other: &CertificateError) -> bool {
//         match self {
//             GatewayError::CertificateError(e) => e == other,
//             _ => false,
//         }
//     }
// }
