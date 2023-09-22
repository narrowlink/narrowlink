use narrowlink_network::error::NetworkError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum GatewayError {
    #[error("Network Error: {0}")]
    NetworkError(#[from] NetworkError),
    #[error("IO Error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("YAML Deserialization Error: {0}")]
    YamlDeError(#[from] serde_yaml::Error),
    #[error("ACME Error: {0}")]
    ACMEError(#[from] instant_acme::Error),
    #[error("Rustls Error: {0}")]
    RustlsError(#[from] rustls::Error),
    #[error("Rcgen Error: {0}")]
    RcgenError(#[from] rcgen::RcgenError),
    #[error("PEM Error: {0}")]
    PEMError(#[from] pem::PemError),
    #[error("Hyper Error: {0}")]
    HyperError(#[from] hyper::Error),
    #[error("Json serialization Error: {0}")]
    SerdeJsonError(#[from] serde_json::Error),
    #[error("Validation Error: {0}")]
    ValidationError(#[from] validator::ValidationErrors),
    #[error("Command Not Found")]
    CommandNotFound,
    #[error("Error: argument {0} is required")]
    RequiredValue(&'static str),
    #[error("Error: illegal character\nTry 'narrowlink-gateway --help' for more information.")]
    Encoding,
    #[error("Config Not Found")]
    ConfigNotFound,
    #[error("Invalid Config Path")]
    InvalidConfigPath,
    #[error("Invalid Config")]
    InvalidConfig,
    #[error("ACME is not enabled")]
    ACMEIsDisabled,
    #[error("ACME failed")]
    ACMEFailed,
    #[error("ACME Challenge Not Found")]
    ACMEChallengeNotFound,
    #[error("ACME Order Not Found")]
    ACMEOrderNotAvailable,
    #[error("ACME Verification Timeout")]
    ACMEVerificationTimeOut,
    #[error("ACME Verification Failed")]
    ACMEVerificationFailed,
    #[error("ACME Pending")]
    ACMEPending,
    #[error("Certificate Not Found")]
    CertificateNotFound,
    #[error("Certificate Renewal Required")]
    CertificateRenewalRequired,
    #[error("Invalid {0}")]
    Invalid(&'static str),
    #[error("Other: {0}")]
    Other(&'static str),
}

// impl fmt::Debug for GatewayError {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//         let mut e = f.debug_struct("GatewayError");
//         e.field("error_type", &self.to_string());
//         if let Some(source) = self.source().as_ref() {
//             e.field("source", source);
//         }
//         e.finish()
//     }
// }

// impl Error for GatewayError {
//     fn source(&self) -> Option<&(dyn Error + 'static)> {
//         match self {
//             Self::NetworkError(e) => Some(e),
//             Self::IoError(e) => Some(e),
//             Self::YamlDeError(e) => Some(e),
//             Self::ACMEError(e) => Some(e),
//             Self::RustlsError(e) => Some(e),
//             Self::RcgenError(e) => Some(e),
//             Self::PEMError(e) => Some(e),
//             Self::HyperError(e) => Some(e),
//             Self::SerdeJsonError(e) => Some(e),
//             _ => None,
//         }
//     }
// }

// impl fmt::Display for GatewayError {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//         match self {
//             GatewayError::NetworkError(source) => write!(f, "Network Error: {}", source),
//             GatewayError::IoError(source) => write!(f, "IO Error: {}", source),
//             GatewayError::YamlDeError(source) => {
//                 write!(f, "YAML Deserialization Error: {}", source)
//             }
//             GatewayError::ACMEError(source) => write!(f, "ACME Error: {}", source),
//             GatewayError::RustlsError(source) => write!(f, "Rustls Error: {}", source),
//             GatewayError::RcgenError(source) => write!(f, "Rcgen Error: {}", source),
//             GatewayError::PEMError(source) => write!(f, "PEM Error: {}", source),
//             GatewayError::HyperError(source) => write!(f, "Hyper Error: {}", source),
//             GatewayError::SerdeJsonError(source) => {
//                 write!(f, "Json serialization Error: {}", source)
//             }
//             GatewayError::ValidationError(source) => write!(f, "Validation Error: {}", source),
//             GatewayError::RequiredValue(arg) => {
//                 write!(f, "Error: argument \"{}\" is required", arg)
//             }
//             GatewayError::Encoding => write!(
//                 f,
//                 "Error: illegal character\nTry 'narrowlink-gateway --help' for more information."
//             ),
//             GatewayError::CommandNotFound => write!(f, "Command Not Found"),
//             GatewayError::ConfigNotFound => write!(f, "Config Not Found"),
//             GatewayError::InvalidConfigPath => write!(f, "Invalid Config Path"),
//             GatewayError::InvalidConfig => write!(f, "Invalid Config"),
//             GatewayError::ACMEIsDisabled => write!(f, "ACME is not enabled"),
//             GatewayError::ACMEFailed => write!(f, "ACME failed"),
//             GatewayError::ACMEChallengeNotFound => write!(f, "ACME Challenge Not Found"),
//             GatewayError::ACMEOrderNotAvailable => write!(f, "ACME Order Not Found"),
//             GatewayError::ACMEVerificationTimeOut => write!(f, "ACME Verification Timeout"),
//             GatewayError::ACMEVerificationFailed => write!(f, "ACME Verification Failed"),
//             GatewayError::ACMEPending => write!(f, "ACME Pending"),
//             GatewayError::CertificateNotFound => write!(f, "Certificate Not Found"),
//             GatewayError::CertificateRenewalRequired => write!(f, "Certificate Renewal Required"),
//             GatewayError::Invalid(msg) => write!(f, "Invalid {}", msg),
//             GatewayError::Other(msg) => write!(f, "Other: {}", msg),
//         }
//     }
// }

// impl From<std::io::Error> for GatewayError {
//     fn from(err: std::io::Error) -> Self {
//         Self::IoError(err)
//     }
// }
// impl From<serde_yaml::Error> for GatewayError {
//     fn from(err: serde_yaml::Error) -> Self {
//         Self::YamlDeError(err)
//     }
// }

// impl From<rustls::Error> for GatewayError {
//     fn from(err: rustls::Error) -> Self {
//         Self::RustlsError(err)
//     }
// }
// impl From<pem::PemError> for GatewayError {
//     fn from(err: pem::PemError) -> Self {
//         Self::PEMError(err)
//     }
// }

// impl From<rcgen::RcgenError> for GatewayError {
//     fn from(err: rcgen::RcgenError) -> Self {
//         Self::RcgenError(err)
//     }
// }

// impl From<instant_acme::Error> for GatewayError {
//     fn from(err: instant_acme::Error) -> Self {
//         Self::ACMEError(err)
//     }
// }

// impl From<serde_json::Error> for GatewayError {
//     fn from(err: serde_json::Error) -> Self {
//         Self::SerdeJsonError(err)
//     }
// }

// impl From<validator::ValidationErrors> for GatewayError {
//     fn from(err: validator::ValidationErrors) -> Self {
//         Self::ValidationError(err)
//     }
// }

// impl From<NetworkError> for GatewayError {
//     fn from(err: NetworkError) -> Self {
//         Self::NetworkError(err)
//     }
// }

// impl From<hyper::Error> for GatewayError {
//     fn from(err: hyper::Error) -> Self {
//         Self::HyperError(err)
//     }
// }
