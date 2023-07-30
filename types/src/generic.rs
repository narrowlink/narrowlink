use chrono;
use hmac::Hmac;
use serde::{Deserialize, Serialize};
use sha3::Sha3_256;
use std::{net::SocketAddr, str::FromStr};

pub type HmacSha256 = Hmac<Sha3_256>;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum CryptographicAlgorithm {
    XChaCha20Poly1305([u8; 24]), //IV
}
#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum SigningAlgorithm {
    HmacSha256([u8; 32]), //IV
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Connect {
    pub host: String,
    pub port: u16,
    pub protocol: Protocol,
    pub cryptography: Option<CryptographicAlgorithm>,
    pub sign: Option<SigningAlgorithm>,
}
impl Connect {
    pub fn set_cryptography_nonce(&mut self, nonce: [u8; 24]) {
        self.cryptography = Some(CryptographicAlgorithm::XChaCha20Poly1305(nonce));
    }
    pub fn get_cryptography_nonce(&self) -> Option<[u8; 24]> {
        if let Some(CryptographicAlgorithm::XChaCha20Poly1305(n)) = self.cryptography {
            Some(n)
        } else {
            None
        }
    }
    pub fn set_sign(&mut self, sign: [u8; 32]) {
        self.sign = Some(SigningAlgorithm::HmacSha256(sign));
    }
    pub fn get_sign(&self) -> Option<[u8; 32]> {
        if let Some(SigningAlgorithm::HmacSha256(n)) = self.sign {
            Some(n)
        } else {
            None
        }
    }
    pub fn from_schemaed_string(addr: &str) -> Option<Self> {
        let separator = addr.find("://")? + 3;
        let protocol = Protocol::from_schemaed_string(&addr[..separator])?;
        let address = SocketAddr::from_str(&addr[separator..]).ok()?;
        Some(Connect {
            host: address.ip().to_string(),
            port: address.port(),
            protocol,
            cryptography: None,
            sign: None,
        })
    }
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub enum Protocol {
    TCP,
    UDP,
    HTTP,
    TLS,
    DTLS,
    HTTPS,
    QUIC,
}

impl Protocol {
    pub fn from_schemaed_string(addr: &str) -> Option<Self> {
        match addr.to_lowercase().as_str() {
            "tcp://" => Some(Protocol::TCP),
            "udp://" => Some(Protocol::UDP),
            "http://" => Some(Protocol::HTTP),
            "https://" => Some(Protocol::HTTPS),
            "tls://" => Some(Protocol::TLS),
            "dtls://" => Some(Protocol::DTLS),
            "quic://" => Some(Protocol::QUIC),
            _ => None,
        }
    }
}
impl FromStr for Protocol {
    type Err = serde_json::Error;
    fn from_str(s: &str) -> Result<Self, <Self as FromStr>::Err> {
        serde_json::from_str(s)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SystemInfo {
    pub loadavg: f64,
    pub cpus: u8,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AgentInfo {
    pub name: String,
    pub socket_addr: String,
    pub forward_addr: Option<String>,
    pub system_info: Option<SystemInfo>,
    pub since: u64,
    pub ping: u16,
}

impl std::fmt::Debug for AgentInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug = f.debug_struct("AgentInfo");
        debug.field("name", &self.name);
        debug.field("socket_addr", &self.socket_addr);
        if let Some(forward_addr) = &self.forward_addr {
            debug.field("forward_addr", forward_addr);
        }
        if let Some(system_info) = &self.system_info {
            debug.field("system_info", system_info);
        }
        if let Some(since) = &chrono::NaiveDateTime::from_timestamp_opt(self.since as i64, 0) {
            let datetime: chrono::DateTime<chrono::Local> =
                chrono::DateTime::from_utc(*since, *chrono::Local::now().offset());
            debug.field("since", &datetime);
        }
        debug.field("ping", &self.ping);
        debug.finish()
    }
}

impl FromStr for Connect {
    type Err = serde_json::Error;
    fn from_str(s: &str) -> Result<Self, <Self as FromStr>::Err> {
        serde_json::from_str(s)
    }
}
