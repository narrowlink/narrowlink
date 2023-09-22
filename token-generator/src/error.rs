use thiserror::Error;

#[derive(Error, Debug)]
pub enum TokenGeneratorError {
    #[error("Invalid Config")]
    InvalidConfig,
    #[error("Config Not Found")]
    ConfigNotFound,
    #[error("Invalid Config Path")]
    InvalidConfigPath,
    #[error("Command Not Found")]
    CommandNotFound,
    #[error("Error: argument {0} is required")]
    RequiredValue(&'static str),
    #[error(
        "Error: illegal character\nTry 'narrowlink-token-generator --help' for more information."
    )]
    Encoding,
    #[error("Token Generation Error")]
    TokenGenerationError,
    #[error("IO Error: {0}")]
    IoError(#[from] std::io::Error),
}
