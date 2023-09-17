use core::fmt;

use narrowlink_network::error::NetworkError;

pub enum AgentError {
    IoError(std::io::Error),
    NetworkError(NetworkError),
    RequiredValue(&'static str),
    Encoding,
    CommandNotFound,
    InvalidConfigPath,
    AccessDenied,
    KeyNotFound,
    ConfigNotFound,
    InvalidConfig,
    InvalidToken,
    UnableToResolve,
    // Invalid(&'static str),
}

impl core::fmt::Debug for AgentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AgentError")
            .field("error_type", &self.to_string())
            // .field("source", &self.source)
            .finish()
    }
}

impl fmt::Display for AgentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AgentError::IoError(source) => write!(f, "IO Error: {}", source),
            AgentError::NetworkError(source) => write!(f, "Network Error: {}", source),
            AgentError::RequiredValue(arg) => write!(f, "Error: argument \"{}\" is required", arg),
            AgentError::Encoding => write!(
                f,
                "Error: illegal character\nTry 'narrowlink-agent --help' for more information."
            ),
            AgentError::CommandNotFound => write!(f, "Command Not Found"),
            AgentError::InvalidConfigPath => write!(f, "Invalid Config Path"),
            AgentError::AccessDenied => write!(f, "Access Denied"),
            AgentError::KeyNotFound => write!(f, "Key Not Found"),
            AgentError::InvalidConfig => write!(f, "Invalid Config"),
            AgentError::ConfigNotFound => write!(f, "Config Not Found"),
            AgentError::InvalidToken => write!(f, "Invalid Token"),
            AgentError::UnableToResolve => write!(f, "Unable To Resolve"),
            // AgentError::Invalid(msg) => write!(f, "Invalid {}", msg),
        }
    }
}

impl From<std::io::Error> for AgentError {
    fn from(err: std::io::Error) -> Self {
        Self::IoError(err)
    }
}

impl From<NetworkError> for AgentError {
    fn from(err: NetworkError) -> Self {
        Self::NetworkError(err)
    }
}
