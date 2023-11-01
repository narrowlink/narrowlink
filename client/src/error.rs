use narrowlink_network::error::NetworkError;
use thiserror::Error;

#[allow(dead_code)]
#[derive(Error, Debug)]
pub enum ClientError {
    #[error("Invalid Address")]
    InvalidAddress,
    #[error("Invalid Map")]
    InvalidMap,
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
    #[error("Connection Closed")]
    ConnectionClosed,
    #[cfg(not(target_family = "windows"))]
    #[error("Unable To Create Tun: {0}")]
    UnableToCreateTun(#[from] tun::Error),
    // #[error("Unable To Create Net Stack: {0}")]
    // UnableToCreateNetStack(#[from] netstack_lwip::Error),
    #[error("Network Error: {0}")]
    NetworkError(#[from] NetworkError),
    #[error("STOP: #{0:#10x}")]
    Unexpected(u32),
    #[error("IO Error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Direct Channel Not Ready")]
    DirectChannelNotAvailable,
    #[error("Relay Channel Not Ready")]
    RelayChannelNotAvailable,
    #[error("Unable To Open Quic Bi Stream")]
    UnableToOpenQuicBiStream,
    #[error("Unable To Communicate With Quic Bi Stream")]
    UnableToCommunicateWithQuicBiStream,
    #[error("Invalid Direct Request")]
    InvalidDirectRequest,
    #[error("Invalid Direct Response")]
    InvalidDirectResponse,
    #[error("Access Control Denied: {0}:{1}")]
    ACLDenied(String, u16),
    #[error("Unable To Resolve: {0}")]
    UnableToResolve(String),
    #[error("Connection to {0}:{1} Failed")]
    DirectConnectionFailed(String, u16),
    #[error("Unable To Connect To Relay")]
    UnableToConnectToRelay,
    #[error("Invalid Socks Request")]
    InvalidSocksRequest,
    #[error("Access Denied")]
    AccessDenied,
    #[error("Control Channel Not Connected")]
    ControlChannelNotConnected,
    #[error("IpStack Error: {0}")]
    IpStackError(#[from] ipstack::IpStackError),
}
