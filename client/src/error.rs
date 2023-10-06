use narrowlink_network::error::NetworkError;
use thiserror::Error;

#[allow(dead_code)]
#[derive(Error, Debug)]
pub enum ClientError {
    #[error("Invalid Address")]
    InvalidAddress,
    #[error("Invalid Port")]
    InvalidPort,
    #[error("Agent Not Found")]
    AgentNotFound,
    #[error("Command Not Found")]
    CommandNotFound,
    #[error("Invalid Local Address")]
    InvalidLocalAddress,
    #[error("Auth Required")]
    AuthRequired,
    #[error("Error: illegal character\nTry 'narrowlink --help' for more information.")]
    Encoding,
    #[error("Config Not Found")]
    ConfigNotFound,
    #[error("Invalid Config")]
    InvalidConfig,
    #[error("Invalid Config Path")]
    InvalidConfigPath,
    #[error("Error: argument {0} is required")]
    RequiredValue(&'static str),
    #[error("Unable To Bind")]
    UnableToBind,
    #[error("Unable To Connect")]
    UnableToConnect,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[error("Unable To Create Tun: {0}")]
    UnableToCreateTun(#[from] tun::Error),
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[error("Unable To Create Net Stack: {0}")]
    UnableToCreaateNetStack(#[from] netstack_lwip::Error),
    #[error("Network Error: {0}")]
    NetworkError(#[from] NetworkError),
    #[error("STOP: #{0:#10x}")]
    InternalError(u32),
    #[error("IO Error: {0}")]
    IoError(#[from] std::io::Error),
}
