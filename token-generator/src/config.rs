use narrowlink_types::token::{AgentPublishToken, AgentToken, ClientToken,PolicyToken};
use serde::{Deserialize, Serialize};
use std::{env, fs::File, io::Read, path::PathBuf};

use crate::error::TokenGeneratorError;

#[derive(Deserialize, Debug, Serialize)]
pub enum TokenType {
    Client(ClientToken),
    ClientPolicy(PolicyToken),
    Agent(AgentToken),
    AgentPublish(AgentPublishToken),
}

#[derive(Deserialize, Debug, Serialize)]
pub struct Config {
    pub secret: Vec<u8>,
    pub tokens: Vec<TokenType>,
}

impl Config {
    pub fn load(path: Option<String>) -> Result<Self, TokenGeneratorError> {
        let custom_path = if let Some(path) = path {
            let path = PathBuf::from(path);
            Some(
                if let Some(stripped_path) = path.strip_prefix("~/").ok().filter(|_| !cfg!(windows))
                {
                    let home_dir =
                        dirs::home_dir().ok_or(TokenGeneratorError::InvalidConfigPath)?;
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
                d.push("token-generator");
                d.set_extension("yaml");
                d
            })
            .ok()
            .filter(|f| f.is_file());
        let config_dir = dirs::config_dir()
            .map(|mut d| {
                d.push("narrowlink");
                d.push("token-generator");
                d.set_extension("yaml");
                d
            })
            .filter(|f| f.is_file());

        let home_dir = dirs::home_dir()
            .map(|mut d| {
                d.push(".narrowlink");
                d.push("token-generator");
                d.set_extension("yaml");
                d
            })
            .filter(|f| f.is_file());

        let path = custom_path
            .or(current_dir)
            .or(config_dir)
            .or(home_dir)
            .ok_or(TokenGeneratorError::ConfigNotFound)?;

        let mut file = File::open(path)?;
        let mut configuration_data = String::new();
        file.read_to_string(&mut configuration_data)?;
        serde_yaml::from_str(&configuration_data).or(Err(TokenGeneratorError::InvalidConfig))
    }
}
