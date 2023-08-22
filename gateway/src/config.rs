use serde::{Deserialize, Serialize};
use std::{env, fmt::Debug, fs, io::Read, net::SocketAddr, path::PathBuf};
use tracing::{debug, trace};
use validator::{Validate, ValidationError};

use crate::{error::GatewayError, service::certificate::ACMEChallengeType};

#[derive(Deserialize, Validate)]
#[validate(schema(function = "Self::verify"))]
pub struct Config {
    pub name: String,
    #[validate(length(min = 8))]
    pub secret: Vec<u8>,
    pub services: Vec<Service>,
}

impl Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("name", &self.name)
            .field("secret", &"XXXX")
            .field("services", &self.services)
            .finish()
    }
}

impl Config {
    pub fn verify(&self) -> Result<(), ValidationError> {
        trace!("verifying config");
        let mut http_port_80 = false;
        let mut is_http01_enabled = false;
        for service in &self.services {
            debug!("checking service: {:?}", service);
            match service {
                Service::Ws(s) => {
                    trace!("checking ws service: {:?}", s);
                    if s.listen_addr.port() == 80 {
                        http_port_80 = true;
                    }
                }
                Service::Wss(s) => {
                    trace!("checking wss service: {:?}", s);
                    if let TlsConfig::Acme(acme) = &s.tls_config {
                        trace!("checking acme config: {:?}", acme);
                        match acme.challenge_type {
                            ACMEChallengeType::Http01 => {
                                is_http01_enabled = true;
                            }
                            ACMEChallengeType::TlsAlpn01 => {
                                if s.listen_addr.port() == 443 {
                                    return Ok(());
                                } else {
                                    return Err(ValidationError::new(
                                        "To use TLS-SNI-01, the server must be listening on port 443",
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        }
        if is_http01_enabled && !http_port_80 {
            trace!("checking http-01");
            return Err(ValidationError::new(
                "To use the HTTP-01, the WS service must be enabled and listening on port 80",
            ));
        }
        trace!("config successfully verified");
        Ok(())
    }
    pub fn load(path: Option<String>) -> Result<Self, GatewayError> {
        trace!("loading config");
        let custom_path = if let Some(path) = path {
            debug!("loading config from custom path: {:?}", path);
            let path = PathBuf::from(path);
            Some(
                if let Some(stripped_path) = path.strip_prefix("~/").ok().filter(|_| !cfg!(windows))
                {
                    debug!("stripped path: {:?}", stripped_path);
                    let home_dir = dirs::home_dir().ok_or(GatewayError::InvalidConfigPath)?;
                    home_dir.join(stripped_path)
                } else {
                    debug!("path: {:?}", path);
                    path
                },
            )
        } else {
            None
        };

        trace!("loading config from default paths");
        let current_dir = env::current_dir()
            .map(|mut d| {
                d.push("gateway");
                d.set_extension("yaml");
                d
            })
            .ok()
            .filter(|f| f.is_file());
        trace!(
            "config file in current dir: {}",
            if current_dir.is_some() {
                "found"
            } else {
                "not found"
            }
        );
        let config_dir = dirs::config_dir()
            .map(|mut d| {
                d.push("narrowlink");
                d.push("gateway");
                d.set_extension("yaml");
                d
            })
            .filter(|f| f.is_file());
        trace!(
            "config file in config dir: {}",
            if config_dir.is_some() {
                "found"
            } else {
                "not found"
            }
        );
        let home_dir = dirs::home_dir()
            .map(|mut d| {
                d.push(".narrowlink");
                d.push("gateway");
                d.set_extension("yaml");
                d
            })
            .filter(|f| f.is_file());
        trace!(
            "config file in home dir: {}",
            if home_dir.is_some() {
                "found"
            } else {
                "not found"
            }
        );
        let etc = if cfg!(target_os = "linux") {
            Some(PathBuf::from("/etc/narrowlink/gateway.yaml"))
        } else {
            None
        }
        .filter(|f| f.is_file());
        #[cfg(target_os = "linux")]
        trace!(
            "config file in etc dir: {}",
            if etc.is_some() { "found" } else { "not found" }
        );
        let path = custom_path
            .or(current_dir)
            .or(config_dir)
            .or(home_dir)
            .or(etc)
            .ok_or(GatewayError::ConfigNotFound)?;
        debug!("loading config file: {:?}", path);
        let mut file = fs::File::open(path)?;
        trace!("reading config file");
        let mut configuration_data = String::new();
        file.read_to_string(&mut configuration_data)?;
        trace!("parsing config file");
        serde_yaml::from_str(&configuration_data).or(Err(GatewayError::InvalidConfig))
    }
    pub fn services(&self) -> &Vec<Service> {
        &self.services
    }
    pub fn tls_config(&self) -> Option<TlsConfig> {
        for service in &self.services {
            if let Service::Wss(s) = service {
                return Some(s.tls_config.clone());
            }
        }
        None
    }
}

#[derive(Debug, Deserialize)]
pub enum Service {
    Ws(WsService),
    Wss(WsSecureService),
}

#[derive(Deserialize, Serialize, Debug)]
pub struct WsService {
    pub domains: Vec<String>,
    pub listen_addr: SocketAddr,
}

#[derive(Deserialize, Debug)]
pub struct WsSecureService {
    pub domains: Vec<String>,
    pub listen_addr: SocketAddr,
    pub tls_config: TlsConfig,
}

#[derive(Deserialize, Debug, Clone)]
pub enum TlsConfig {
    Acme(Acme),
    File(File),
}

#[derive(Deserialize, Debug, Validate, Clone)]
pub struct Acme {
    #[validate(email)]
    pub email: String,
    #[serde(default)]
    pub challenge_type: ACMEChallengeType,
    #[serde(default = "_default_acme_directory_url")]
    #[validate(url)]
    pub directory_url: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct File {
    pub domains: Vec<String>,
    pub cert_path: String,
}

pub fn _default_acme_directory_url() -> String {
    "https://acme-v02.api.letsencrypt.org/directory".to_string()
}
