use core::fmt;

pub enum MessageError {
    JwtError(jsonwebtoken::errors::Error),
    SerdeJsonError(serde_json::Error),
    // ValidationErrors(),
}

impl core::fmt::Debug for MessageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MessageError")
            .field("error_type", &self.to_string())
            // .field("source", &self.source)
            .finish()
    }
}

impl fmt::Display for MessageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MessageError::JwtError(e) => write!(f, "E-Jwt: {}", e),
            MessageError::SerdeJsonError(e) => write!(f, "E-SerdeJson: {}", e),
        }
    }
}

impl From<jsonwebtoken::errors::Error> for MessageError {
    fn from(err: jsonwebtoken::errors::Error) -> Self {
        Self::JwtError(err)
    }
}
// impl From<toml::de::Error> for GatewayError {
//     fn from(err: toml::de::Error) -> Self {
//         Self::TomlDeError(err)
//     }
// }

// impl From<rustls::Error> for GatewayError {
//     fn from(err: rustls::Error) -> Self {
//         Self::RustlsError(err)
//     }
// }impl From<pem::PemError> for GatewayError {
//     fn from(err: pem::PemError) -> Self {
//         Self::PEMError(err)
//     }
// }

// impl From<rcgen::RcgenError> for GatewayError {
//     fn from(err: rcgen::RcgenError) -> Self {
//         Self::RcgenError(err)
//     }
// }

// impl From<instant_acme::Error> for GatewayError {
//     fn from(err: instant_acme::Error) -> Self {
//         Self::ACMEError(err)
//     }
// }

impl From<serde_json::Error> for MessageError {
    fn from(err: serde_json::Error) -> Self {
        Self::SerdeJsonError(err)
    }
}

// #[derive(Debug)]
// pub struct MessageError {
//     error_type: MessageErrorType,
//     source: Option<Box<(dyn std::error::Error + Send)>>,
//     #[cfg(debug_assertions)]
//     caller: &'static std::panic::Location<'static>,
// }

// impl std::error::Error for MessageError {}

// impl fmt::Display for MessageError {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//         #[cfg(debug_assertions)]
//         match self.source.as_ref() {
//             Some(s) => write!(
//                 f,
//                 "{}:{} | {} -> {}",
//                 self.caller.file(),
//                 self.caller.line(),
//                 self.error_type.to_string(),
//                 s.to_string()
//             ),
//             None => write!(
//                 f,
//                 "{}:{} | {}",
//                 self.caller.file(),
//                 self.caller.line(),
//                 self.error_type.to_string()
//             ),
//         }

//         #[cfg(not(debug_assertions))]
//         match self.source.as_ref() {
//             Some(s) => write!(f, "{} -> {}", self.error_type.to_string(), s.to_string()),
//             None => write!(f, "{}", self.error_type.to_string()),
//         }
//     }
// }

// impl MessageError {
//     #[cfg(debug_assertions)]
//     #[track_caller]
//     pub fn new(error_type: MessageErrorType) -> Self {
//         Self {
//             error_type,
//             source: None,
//             #[cfg(debug_assertions)]
//             caller: std::panic::Location::caller(),
//         }
//     }

//     #[cfg(not(debug_assertions))]
//     pub fn new(error_type: MessageErrorType) -> Self {
//         Self {
//             error_type,
//             source: None,
//             #[cfg(debug_assertions)]
//             caller: std::panic::Location::caller(),
//         }
//     }
// }

// impl From<serde_json::Error> for MessageError {
//     #[cfg(debug_assertions)]
//     #[track_caller]
//     fn from(err: serde_json::Error) -> Self {
//         Self {
//             error_type: MessageErrorType::SerdeError,
//             source: Some(Box::new(err)),
//             #[cfg(debug_assertions)]
//             caller: std::panic::Location::caller(),
//         }
//     }

//     #[cfg(not(debug_assertions))]
//     fn from(err: serde_json::Error) -> Self {
//         Self {
//             error_type: MessageErrorType::SerdeError,
//             source: Some(Box::new(err)),
//             #[cfg(debug_assertions)]
//             caller: std::panic::Location::caller(),
//         }
//     }
// }

// impl From<jsonwebtoken::errors::Error> for MessageError {
//     #[cfg(debug_assertions)]
//     #[track_caller]
//     fn from(err: jsonwebtoken::errors::Error) -> Self {
//         Self {
//             error_type: MessageErrorType::JWTError,
//             source: Some(Box::new(err)),
//             #[cfg(debug_assertions)]
//             caller: std::panic::Location::caller(),
//         }
//     }

//     #[cfg(not(debug_assertions))]
//     fn from(err: jsonwebtoken::errors::Error) -> Self {
//         Self {
//             error_type: MessageErrorType::JWTError,
//             source: Some(Box::new(err)),
//             #[cfg(debug_assertions)]
//             caller: std::panic::Location::caller(),
//         }
//     }
// }
