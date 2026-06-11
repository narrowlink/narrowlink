use narrowlink_types::ServiceType;
use serde::{Deserialize, Serialize};
use std::{env, fs::File, io::Read, path::PathBuf};

use crate::error::AgentError;

const CONFIG_PATH_ENV: &str = "NARROWLINK_AGENT_CONFIG";

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

impl Config {
    pub fn load(path: Option<String>) -> Result<Self, AgentError> {
        let custom_path = if let Some(path) = path.or_else(|| {
            env::var(CONFIG_PATH_ENV)
                .ok()
                .filter(|path| !path.is_empty())
        }) {
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
        serde_yaml::from_str(&configuration_data).or(Err(AgentError::InvalidConfig))
    }
}

// impl SelfHosted {
//     pub fn get_agent_name(&self) -> Result<String, AgentError> {
//         self.token
//             .split('.')
//             .nth(1)
//             .and_then(|c| {
//                 base64::engine::general_purpose::STANDARD_NO_PAD
//                     .decode(c)
//                     .ok()
//             })
//             .and_then(|v| serde_json::from_slice::<AgentToken>(&v).ok())
//             .ok_or(AgentError::InvalidToken)
//             .map(|t| t.name)
//     }
// }

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
            r#"endpoints:
  - !SelfHosted
    gateway: env.gateway:443
    token: env-token
e2ee: []
"#,
        )?;

        let _env = EnvVarGuard::set(&path.path);
        let config = Config::load(None)?;

        match &config.endpoints[0] {
            Endpoint::SelfHosted(endpoint) => assert_eq!(endpoint.gateway, "env.gateway:443"),
        }
        Ok(())
    }

    #[test]
    fn cli_config_path_takes_precedence_over_environment() -> Result<(), Box<dyn std::error::Error>>
    {
        let _guard = ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let env_path = TestConfigFile::write(
            r#"endpoints:
  - !SelfHosted
    gateway: env.gateway:443
    token: env-token
e2ee: []
"#,
        )?;
        let cli_path = TestConfigFile::write(
            r#"endpoints:
  - !SelfHosted
    gateway: cli.gateway:443
    token: cli-token
e2ee: []
"#,
        )?;

        let _env = EnvVarGuard::set(&env_path.path);
        let config = Config::load(Some(cli_path.path.to_string_lossy().into_owned()))?;
        match &config.endpoints[0] {
            Endpoint::SelfHosted(endpoint) => assert_eq!(endpoint.gateway, "cli.gateway:443"),
        }
        Ok(())
    }

    fn temp_config_path() -> PathBuf {
        env::temp_dir().join(format!(
            "narrowlink-agent-{}-{}.yaml",
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
