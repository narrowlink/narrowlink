use thiserror::Error;

#[derive(Error, Debug)]
pub enum GatewayError {
    #[error("Invalid {0}")]
    Invalid(&'static str),
    #[error("ACME Error: {0}")]
    ACMEError(#[from] instant_acme::Error),
}
