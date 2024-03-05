mod certificate;
use thiserror::Error;
pub use certificate::CertificateError;

#[derive(Error, Debug)]
pub enum GatewayError {
    #[error("Invalid {0}")]
    Invalid(&'static str),
    #[error("ACME Error: {0}")]
    ACMEError(#[from] instant_acme::Error),
    #[error("Certificate Error: {0}")]
    CertificateError(#[from] certificate::CertificateError),
}

// impl std::cmp::PartialEq<CertificateError> for GatewayError {
//     fn eq(&self, other: &CertificateError) -> bool {
//         match self {
//             GatewayError::CertificateError(e) => e == other,
//             _ => false,
//         }
//     }
// }
