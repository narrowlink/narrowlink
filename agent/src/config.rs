use base64::Engine;
use narrowlink_types::{token::AgentToken, ServiceType};
use serde::{Deserialize, Serialize};
use std::{env, fs::File, io::Read, path::PathBuf, vec};
use tracing::warn;

use crate::error::AgentError;

#[derive(Deserialize, Serialize, Default, PartialEq, Clone, Copy)]
pub enum KeyPolicy {
    #[default]
    Lax,
    Strict,
}
#[derive(Deserialize, Serialize)]
pub struct SelfHosted {
    pub gateway: String,
    pub token: String,
    pub publish: Option<Vec<String>>,
    #[serde(default = "ServiceType::default")]
    pub protocol: ServiceType,
}

#[derive(Deserialize, Serialize)]
pub enum Endpoint {
    // Platform(Platform),
    // Cloud(Cloud),
    SelfHosted(SelfHosted),
}

#[derive(Deserialize, Serialize, Clone)]
pub struct PassPhrase {
    pub phrase: String,
    #[serde(default = "KeyPolicy::default")]
    pub policy: KeyPolicy,
}

#[derive(Deserialize, Serialize, Clone)]
pub enum E2EE {
    PassPhrase(PassPhrase),
}

#[derive(Deserialize, Serialize)]
pub struct Config {
    pub endpoints: Vec<Endpoint>,
    #[serde(default = "Vec::new")]
    pub e2ee: Vec<E2EE>,
}

#[derive(Deserialize)]
pub struct OldConfig {
    pub gateway: String,
    pub token: String,
    pub publish: Option<String>,
    pub key: Option<String>,
    #[serde(default = "KeyPolicy::default")]
    pub key_policy: KeyPolicy,
    #[serde(default = "ServiceType::default")]
    pub service_type: ServiceType,
}

impl Config {
    pub fn load(path: Option<String>) -> Result<Self, AgentError> {
        let custom_path = if let Some(path) = path {
            let path = PathBuf::from(path);
            Some(
                if let Some(stripped_path) = path.strip_prefix("~/").ok().filter(|_| !cfg!(windows))
                {
                    let home_dir = dirs::home_dir().ok_or(AgentError::InvalidConfigPath)?;
                    home_dir.join(stripped_path)
                } else {
                    path
                },
            )
        } else {
            None
        };

        let current_dir = env::current_dir()
            .map(|mut d| {
                d.push("agent");
                d.set_extension("yaml");
                d
            })
            .ok()
            .filter(|f| f.is_file());
        let config_dir = dirs::config_dir()
            .map(|mut d| {
                d.push("narrowlink");
                d.push("agent");
                d.set_extension("yaml");
                d
            })
            .filter(|f| f.is_file());

        let home_dir = dirs::home_dir()
            .map(|mut d| {
                d.push(".narrowlink");
                d.push("agent");
                d.set_extension("yaml");
                d
            })
            .filter(|f| f.is_file());

        let etc = if cfg!(target_os = "linux") {
            Some(PathBuf::from("/etc/narrowlink/agent.yaml"))
        } else {
            None
        }
        .filter(|f| f.is_file());

        let path = custom_path
            .or(current_dir)
            .or(config_dir)
            .or(home_dir)
            .or(etc)
            .ok_or(AgentError::ConfigNotFound)?;

        let mut file = File::open(path)?;
        let mut configuration_data = String::new();
        file.read_to_string(&mut configuration_data)?;
        serde_yaml::from_str(&configuration_data)
            .or(Err(AgentError::InvalidConfig))
            .or_else(|e| {
                let old_config =
                    serde_yaml::from_str::<OldConfig>(&configuration_data).or(Err(e))?;
                warn!("Update your config file; old format will be deprecated in the next release");
                Ok(Config {
                    endpoints: vec![Endpoint::SelfHosted(SelfHosted {
                        gateway: old_config.gateway,
                        token: old_config.token,
                        publish: old_config.publish.map(|p| vec![p]),
                        protocol: old_config.service_type,
                    })],
                    e2ee: old_config
                        .key
                        .map(|k| {
                            vec![E2EE::PassPhrase(PassPhrase {
                                phrase: k,
                                policy: old_config.key_policy,
                            })]
                        })
                        .unwrap_or(vec![]),
                })
            })
    }
}

impl SelfHosted {
    pub fn get_agent_name(&self) -> Result<String, AgentError> {
        self.token
            .split('.')
            .nth(1)
            .and_then(|c| {
                base64::engine::general_purpose::STANDARD_NO_PAD
                    .decode(c)
                    .ok()
            })
            .and_then(|v| serde_json::from_slice::<AgentToken>(&v).ok())
            .ok_or(AgentError::InvalidToken)
            .map(|t| t.name)
    }
}
