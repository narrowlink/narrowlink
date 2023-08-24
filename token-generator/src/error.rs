use std::{error::Error, fmt::Display};

#[derive(Debug)]
pub enum TokenGeneratorError {
    InvalidConfig,
    ConfigNotFound,
    InvalidConfigPath,
    CommandNotFound,
    RequiredValue(&'static str),
    Encoding,
    TokenGenerationError,
    IoError(std::io::Error),
}

impl TokenGeneratorError {}

impl Error for TokenGeneratorError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            TokenGeneratorError::IoError(e) => Some(e),
            _ => None,
        }
    }
}

impl Display for TokenGeneratorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TokenGeneratorError::InvalidConfig => write!(f, "Invalid Config"),
            TokenGeneratorError::ConfigNotFound => write!(f, "Config Not Found"),
            TokenGeneratorError::InvalidConfigPath => write!(f, "Invalid Config Path"),
            TokenGeneratorError::CommandNotFound => write!(f, "Command Not Found"),
            TokenGeneratorError::RequiredValue(v) => write!(f, "Required Value: {}", v),
            TokenGeneratorError::Encoding => write!(f, "Encoding Error"),
            TokenGeneratorError::TokenGenerationError => write!(f, "Token Generation Error"),
            TokenGeneratorError::IoError(e) => write!(f, "IO Error: {}", e),
        }
    }
}

impl From<std::io::Error> for TokenGeneratorError {
    fn from(e: std::io::Error) -> Self {
        TokenGeneratorError::IoError(e)
    }
}
