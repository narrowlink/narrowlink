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
