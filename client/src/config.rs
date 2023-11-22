use narrowlink_types::ServiceType;
use serde::{Deserialize, Serialize};
use std::{env, fs::File, io::Read, path::PathBuf};

use crate::error::ClientError;

#[derive(Deserialize, Serialize)]
pub struct SelfHosted {
    #[serde(default = "Option::default")]
    pub namespace: Option<String>,
    pub gateway: String,
    pub token: String,
    #[serde(default = "Vec::new")]
    pub acl: Vec<String>,
    #[serde(default = "ServiceType::default")]
    pub protocol: ServiceType,
}

#[derive(Deserialize, Serialize)]
pub enum Endpoint {
    // Platform(Platform),
    // Cloud(Cloud),
    SelfHosted(SelfHosted),
}
#[derive(Deserialize, Serialize)]
pub struct Config {
    pub endpoints: Vec<Endpoint>,
}

impl Config {
    pub fn load(path: Option<String>) -> Result<Self, ClientError> {
        let custom_path = if let Some(path) = path {
            let path = PathBuf::from(path);
            Some(
                if let Some(stripped_path) = path.strip_prefix("~/").ok().filter(|_| !cfg!(windows))
                {
                    let home_dir = dirs::home_dir().ok_or(ClientError::InvalidConfigPath)?;
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
                d.push("client");
                d.set_extension("yaml");
                d
            })
            .ok()
            .filter(|f| f.is_file());
        let config_dir = dirs::config_dir()
            .map(|mut d| {
                d.push("narrowlink");
                d.push("client");
                d.set_extension("yaml");
                d
            })
            .filter(|f| f.is_file());

        let home_dir = dirs::home_dir()
            .map(|mut d| {
                d.push(".narrowlink");
                d.push("client");
                d.set_extension("yaml");
                d
            })
            .filter(|f| f.is_file());

        let etc = if cfg!(target_os = "linux") {
            Some(PathBuf::from("/etc/narrowlink/client.yaml"))
        } else {
            None
        }
        .filter(|f| f.is_file());

        let path = custom_path
            .or(current_dir)
            .or(config_dir)
            .or(home_dir)
            .or(etc)
            .ok_or(ClientError::ConfigNotFound)?;

        let mut file = File::open(path)?;
        let mut configuration_data = String::new();
        file.read_to_string(&mut configuration_data)?;
        serde_yaml::from_str(&configuration_data).or(Err(ClientError::InvalidConfig))
    }
}
