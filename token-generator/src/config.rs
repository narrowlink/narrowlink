use narrowlink_types::token::{AgentPublishToken, AgentToken, ClientToken, PolicyToken};
use serde::{Deserialize, Serialize};
use std::{env, fs::File, io::Read, path::PathBuf};

use crate::error::TokenGeneratorError;

const CONFIG_PATH_ENV: &str = "NARROWLINK_TOKEN_GENERATOR_CONFIG";

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
        let custom_path = if let Some(path) = path.or_else(|| {
            env::var(CONFIG_PATH_ENV)
                .ok()
                .filter(|path| !path.is_empty())
        }) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        path::Path,
        sync::{
            atomic::{AtomicU64, Ordering},
            Mutex,
        },
    };

    static ENV_LOCK: Mutex<()> = Mutex::new(());
    static NEXT_PATH_ID: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn load_uses_environment_config_path_when_cli_path_is_missing(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let _guard = ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let path = TestConfigFile::write(
            r#"secret: [1, 2, 3, 4]
tokens: []
"#,
        )?;

        let _env = EnvVarGuard::set(&path.path);
        let config = Config::load(None)?;

        assert_eq!(config.secret, vec![1, 2, 3, 4]);
        Ok(())
    }

    #[test]
    fn cli_config_path_takes_precedence_over_environment() -> Result<(), Box<dyn std::error::Error>>
    {
        let _guard = ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let env_path = TestConfigFile::write(
            r#"secret: [1, 2, 3, 4]
tokens: []
"#,
        )?;
        let cli_path = TestConfigFile::write(
            r#"secret: [5, 6, 7, 8]
tokens: []
"#,
        )?;

        let _env = EnvVarGuard::set(&env_path.path);
        let config = Config::load(Some(cli_path.path.to_string_lossy().into_owned()))?;
        assert_eq!(config.secret, vec![5, 6, 7, 8]);
        Ok(())
    }

    fn temp_config_path() -> PathBuf {
        env::temp_dir().join(format!(
            "narrowlink-token-generator-{}-{}.yaml",
            std::process::id(),
            NEXT_PATH_ID.fetch_add(1, Ordering::Relaxed)
        ))
    }

    struct TestConfigFile {
        path: PathBuf,
    }

    impl TestConfigFile {
        fn write(contents: &str) -> Result<Self, std::io::Error> {
            let path = temp_config_path();
            fs::write(&path, contents)?;
            Ok(Self { path })
        }
    }

    impl Drop for TestConfigFile {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.path);
        }
    }

    struct EnvVarGuard {
        previous: Option<std::ffi::OsString>,
    }

    impl EnvVarGuard {
        fn set(path: &Path) -> Self {
            let previous = env::var_os(CONFIG_PATH_ENV);
            env::set_var(CONFIG_PATH_ENV, path);
            Self { previous }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            if let Some(previous) = &self.previous {
                env::set_var(CONFIG_PATH_ENV, previous);
            } else {
                env::remove_var(CONFIG_PATH_ENV);
            }
        }
    }
}
