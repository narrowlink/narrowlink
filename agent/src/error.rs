use narrowlink_network::error::NetworkError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AgentError {
    #[error("IO Error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Network Error: {0}")]
    NetworkError(#[from] NetworkError),
    #[error("Error: argument {0} is required")]
    RequiredValue(&'static str),
    #[error("Error: illegal character\nTry 'narrowlink-agent --help' for more information")]
    Encoding,
    #[error("Command Not Found")]
    CommandNotFound,
    #[error("Invalid Config Path")]
    InvalidConfigPath,
    #[error("Access Denied")]
    AccessDenied,
    #[error("Key Not Found")]
    KeyNotFound,
    #[error("Config Not Found")]
    ConfigNotFound,
    #[error("Invalid Config")]
    InvalidConfig,
    #[error("Unable To Resolve")]
    UnableToResolve,
}