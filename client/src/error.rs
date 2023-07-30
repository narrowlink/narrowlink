use std::{error::Error, fmt::Display};

use narrowlink_network::error::NetworkError;

#[allow(dead_code)]
#[derive(Debug)]
pub enum ClientError {
    InvalidAddress,
    InvalidPort,
    AgentNotFound,
    CommandNotFound,
    InvalidLocalAddress,
    AuthRequired,
    Encoding,
    ConfigNotFound,
    InvalidConfig,
    InvalidConfigPath,
    RequiredValue(&'static str),
    UnableToBind,
    UnableToConnect,
    NetworkError(NetworkError),
    InternalError(u32),
    IoError(std::io::Error),
}

impl ClientError {}

impl Error for ClientError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            ClientError::NetworkError(e) => Some(e),
            ClientError::IoError(e) => Some(e),
            _ => None,
        }
    }
}

impl Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::InvalidAddress => write!(f, "Invalid Address"),
            ClientError::InvalidPort => write!(f, "Invalid Port"),
            ClientError::AgentNotFound => write!(f, "Agent Not Found"),
            ClientError::ConfigNotFound => write!(f, "Config Not Found"),
            ClientError::InvalidConfig => write!(f, "Invalid Config"),
            ClientError::InvalidConfigPath => write!(f, "Invalid Config Path"),
            ClientError::CommandNotFound => write!(f, "Command Not Found"),
            ClientError::InvalidLocalAddress => write!(f, "Invalid Local Address"),
            ClientError::AuthRequired => write!(f, "Auth Required"),
            ClientError::Encoding => write!(
                f,
                "Error: illegal character\nTry 'narrowlink --help' for more information."
            ),
            ClientError::RequiredValue(arg) => write!(f, "Error: argument \"{}\" is required", arg),
            ClientError::UnableToBind => write!(f, "Unable To Bind"),
            ClientError::UnableToConnect => write!(f, "Unable To Connect"),
            ClientError::NetworkError(e) => write!(f, "Network Error: {}", e),
            ClientError::InternalError(eid) => write!(f, "STOP: #{:#10x}", eid),
            ClientError::IoError(e) => write!(f, "IO Error: {}", e),
        }
    }
}

impl From<NetworkError> for ClientError {
    fn from(e: NetworkError) -> Self {
        ClientError::NetworkError(e)
    }
}
impl From<std::io::Error> for ClientError {
    fn from(e: std::io::Error) -> Self {
        ClientError::IoError(e)
    }
}
