use thiserror::Error;

#[derive(Error, Debug)]
pub enum ClientError {
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
