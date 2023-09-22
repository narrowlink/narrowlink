use thiserror::Error;

#[derive(Error, Debug)]
pub enum NetworkError {
    #[error("IO Error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Network Error: {0}")]
    HttpError(#[from] hyper::http::Error),
    #[error("Network Error: {0}")]
    HyperError(#[from] hyper::Error),
    #[error("Network Error: {0}")]
    Tungstenite(#[from] tungstenite::Error),
    #[error("TLS Error")]
    TlsError,
    #[error("Unable To Upgrade: {0}")]
    UnableToUpgrade(u16),
    #[error("Request Canceled")]
    RequestCanceled,
    #[error("Quic Error")]
    QuicError,
    #[error("P2P Invalid Command")]
    P2PInvalidCommand,
    #[error("P2P Invalid Domain")]
    P2PInvalidDomain,
    #[error("P2P Invalid Crypto")]
    P2PInvalidCrypto,
    #[error("P2P Timeout")]
    P2PTimeout,
    #[error("P2P Failed")]
    P2PFailed,
    #[error("Json Serialization Error: {0}")]
    JsonSerializationError(#[from] serde_json::Error),
    #[error("Cryptography Failure: {0}")]
    XChaCha20Poly1305(chacha20poly1305::Error),
    #[error("Invalid: {0}")]
    Invalid(&'static str),
}

impl From<chacha20poly1305::Error> for NetworkError {
    fn from(err: chacha20poly1305::Error) -> Self {
        Self::XChaCha20Poly1305(err)
    }
}
