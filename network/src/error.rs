use core::fmt;
use std::error::Error;

pub enum NetworkError {
    IoError(std::io::Error),
    HttpError(hyper::http::Error),
    HyperError(hyper::Error),
    Tungstenite(tungstenite::Error),
    TlsError,
    UnableToUpgrade(u16),
    RequestCanceled,
    QuicError,
    P2PInvalidCommand,
    P2PInvalidDomain,
    JsonSerializationError(serde_json::Error),
    XChaCha20Poly1305(chacha20poly1305::Error),
    Invalid(&'static str),
}

impl Error for NetworkError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            NetworkError::IoError(e) => Some(e),
            NetworkError::HttpError(e) => Some(e),
            NetworkError::HyperError(e) => Some(e),
            NetworkError::Tungstenite(e) => Some(e),
            NetworkError::JsonSerializationError(e) => Some(e),
            _ => None,
        }
    }
}

impl core::fmt::Debug for NetworkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NetworkError")
            .field("error_type", &self.to_string())
            // .field("source", &self.source)
            .finish()
    }
}

impl fmt::Display for NetworkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetworkError::IoError(e) => write!(f, "E-Io:{}", e),
            NetworkError::HttpError(e) => write!(f, "E-Hyper:{}", e),
            NetworkError::HyperError(e) => write!(f, "E-Hyper:{}", e),
            NetworkError::Tungstenite(e) => write!(f, "E-Tungstenite:{}", e),
            NetworkError::TlsError => write!(f, "E-Tls"),
            NetworkError::UnableToUpgrade(code) => write!(f, "E-UnableToUpgrade, Error({})", code),
            NetworkError::RequestCanceled => write!(f, "E-RequestCanceled::Error"),
            NetworkError::QuicError => write!(f, "E-QuicError::Error"),
            NetworkError::P2PInvalidCommand => write!(f, "E-P2PInvalidCommand::Error"),
            NetworkError::P2PInvalidDomain => write!(f, "E-P2PInvalidDomain::Error"),
            NetworkError::JsonSerializationError(e) => {
                write!(f, "E-JsonSerialization:{}", e)
            }
            NetworkError::XChaCha20Poly1305(e) => write!(f, "Cryptography Failure :{}", e),
            NetworkError::Invalid(msg) => write!(f, "Invalid {}", msg),
        }
    }
}

impl From<std::io::Error> for NetworkError {
    fn from(err: std::io::Error) -> Self {
        Self::IoError(err)
    }
}
impl From<tungstenite::Error> for NetworkError {
    fn from(err: tungstenite::Error) -> Self {
        Self::Tungstenite(err)
    }
}
impl From<hyper::http::Error> for NetworkError {
    fn from(err: hyper::http::Error) -> Self {
        Self::HttpError(err)
    }
}
impl From<hyper::Error> for NetworkError {
    fn from(err: hyper::Error) -> Self {
        Self::HyperError(err)
    }
}
impl From<serde_json::Error> for NetworkError {
    fn from(err: serde_json::Error) -> Self {
        Self::JsonSerializationError(err)
    }
}

impl From<chacha20poly1305::Error> for NetworkError {
    fn from(err: chacha20poly1305::Error) -> Self {
        Self::XChaCha20Poly1305(err)
    }
}

/*
use core::fmt;
use std::io;

#[derive(Debug)]
pub enum NetworkErrorType {
    IO,
    HyperError,
    Tungstenite,
    TlsError,
    RequestCanceled,
    SerializationError,
}

impl fmt::Display for NetworkErrorType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        dbg!(self);
        match self {
            NetworkErrorType::IO => write!(f, "E-io::Error"),
            NetworkErrorType::HyperError => write!(f, "E-HyperError::Error"),
            NetworkErrorType::Tungstenite => write!(f, "E-Tungstenite::Error"),
            NetworkErrorType::TlsError => write!(f, "E-TlsError::Error"),
            NetworkErrorType::RequestCanceled => write!(f, "E-RequestCanceled::Error"),
            NetworkErrorType::SerializationError => write!(f, "E-SerializationError::Error"),

        }
    }
}

#[derive(Debug)]
pub struct NetworkError {
    error_type: NetworkErrorType,
    source: Option<Box<(dyn std::error::Error + Send)>>,
    #[cfg(debug_assertions)]
    caller: &'static std::panic::Location<'static>,
}

impl std::error::Error for NetworkError {}

impl fmt::Display for NetworkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        #[cfg(debug_assertions)]
        match self.source.as_ref() {
            Some(s) => write!(
                f,
                "{}:{} | {} -> {}",
                self.caller.file(),
                self.caller.line(),
                self.error_type.to_string(),
                s.to_string()
            ),
            None => write!(
                f,
                "{}:{} | {}",
                self.caller.file(),
                self.caller.line(),
                self.error_type.to_string()
            ),
        }

        #[cfg(not(debug_assertions))]
        match self.source.as_ref() {
            Some(s) => write!(f, "{} -> {}", self.error_type.to_string(), s.to_string()),
            None => write!(f, "{}", self.error_type.to_string()),
        }
    }
}

impl NetworkError {
    #[cfg(debug_assertions)]
    #[track_caller]
    pub fn new(error_type: NetworkErrorType) -> Self {
        Self {
            error_type,
            source: None,
            #[cfg(debug_assertions)]
            caller: std::panic::Location::caller(),
        }
    }

    #[cfg(not(debug_assertions))]
    pub fn new(error_type: NetworkErrorType) -> Self {
        Self {
            error_type,
            source: None,
            #[cfg(debug_assertions)]
            caller: std::panic::Location::caller(),
        }
    }
}

impl From<hyper::http::Error> for NetworkError {
    #[cfg(debug_assertions)]
    #[track_caller]
    fn from(err: hyper::http::Error) -> Self {
        Self {
            error_type: NetworkErrorType::HyperError,
            source: Some(Box::new(err)),
            #[cfg(debug_assertions)]
            caller: std::panic::Location::caller(),
        }
    }

    #[cfg(not(debug_assertions))]
    fn from(err: hyper::http::Error) -> Self {
        Self {
            error_type: NetworkErrorType::HyperError,
            source: Some(Box::new(err)),
            #[cfg(debug_assertions)]
            caller: std::panic::Location::caller(),
        }
    }
}

impl From<hyper::Error> for NetworkError {
    #[cfg(debug_assertions)]
    #[track_caller]
    fn from(err: hyper::Error) -> Self {
        Self {
            error_type: NetworkErrorType::HyperError,
            source: Some(Box::new(err)),
            #[cfg(debug_assertions)]
            caller: std::panic::Location::caller(),
        }
    }

    #[cfg(not(debug_assertions))]
    fn from(err: hyper::Error) -> Self {
        Self {
            error_type: NetworkErrorType::HyperError,
            source: Some(Box::new(err)),
            #[cfg(debug_assertions)]
            caller: std::panic::Location::caller(),
        }
    }
}

impl From<io::Error> for NetworkError {
    #[cfg(debug_assertions)]
    #[track_caller]
    fn from(err: io::Error) -> Self {
        Self {
            error_type: NetworkErrorType::IO,
            source: Some(Box::new(err)),
            #[cfg(debug_assertions)]
            caller: std::panic::Location::caller(),
        }
    }

    #[cfg(not(debug_assertions))]
    fn from(err: io::Error) -> Self {
        Self {
            error_type: NetworkErrorType::IO,
            source: Some(Box::new(err)),
            #[cfg(debug_assertions)]
            caller: std::panic::Location::caller(),
        }
    }
}

impl From<tungstenite::Error> for NetworkError {
    #[cfg(debug_assertions)]
    #[track_caller]
    fn from(err: tungstenite::Error) -> Self {
        Self {
            error_type: NetworkErrorType::Tungstenite,
            source: Some(Box::new(err)),
            #[cfg(debug_assertions)]
            caller: std::panic::Location::caller(),
        }
    }

    #[cfg(not(debug_assertions))]
    fn from(err: tungstenite::Error) -> Self {
        Self {
            error_type: NetworkErrorType::Tungstenite,
            source: Some(Box::new(err)),
            #[cfg(debug_assertions)]
            caller: std::panic::Location::caller(),
        }
    }
}


impl From<serde_json::Error> for NetworkError {
    #[cfg(debug_assertions)]
    #[track_caller]
    fn from(err: serde_json::Error) -> Self {
        Self {
            error_type: NetworkErrorType::SerializationError,
            source: Some(Box::new(err)),
            #[cfg(debug_assertions)]
            caller: std::panic::Location::caller(),
        }
    }

    #[cfg(not(debug_assertions))]
    fn from(err: serde_json::Error) -> Self {
        Self {
            error_type: NetworkErrorType::SerializationError,
            source: Some(Box::new(err)),
            #[cfg(debug_assertions)]
            caller: std::panic::Location::caller(),
        }
    }
}

*/
