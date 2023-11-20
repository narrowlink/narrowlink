use tracing::{debug, instrument, trace};

use crate::error::GatewayError;

use std::process;

static HELP: &str = include_str!("../main.help.arg");
static BRIEF_LICENCE: &str =
    "This program is licensed under the GNU Affero General Public License v3.0.";
pub struct Args {
    pub config_path: Option<String>,
}

impl Args {
    #[instrument(name = "args::parse")]
    pub fn parse(
        raw: impl IntoIterator<Item = impl Into<std::ffi::OsString>> + std::fmt::Debug,
    ) -> Result<Self, GatewayError> {
        trace!("parsing args");
        let raw = clap_lex::RawArgs::new(raw);
        let mut cursor = raw.cursor();
        raw.next(&mut cursor);
        let mut config_path = None;
        loop {
            let Some(arg) = raw.next(&mut cursor) else {
                break;
            };
            if let Some((long, value)) = arg.to_long() {
                match long {
                    Ok("config") => {
                        trace!("config arg found");
                        config_path = Some(
                            value
                                .ok_or(GatewayError::RequiredValue("config"))?
                                .to_str()
                                .ok_or(GatewayError::Encoding)?
                                .to_owned(),
                        );
                        debug!("config path: {:?}", config_path);
                        continue;
                    }
                    Ok("help") => {
                        trace!("help arg found");
                        print!("{}", HELP);
                        process::exit(0x0);
                    }
                    Ok("version") => {
                        trace!("version arg found");
                        println!("Narrowlink Gateway, version {}", env!("CARGO_PKG_VERSION"));
                        println!("{}", BRIEF_LICENCE);
                        process::exit(0x0);
                    }
                    _ => {
                        return Err(GatewayError::CommandNotFound);
                    }
                }
            } else if let Some(mut shorts) = arg.to_short() {
                while let Some(short) = shorts.next_flag() {
                    match short {
                        Ok('c') => {
                            trace!("config arg found");
                            config_path = if let Some(v) = shorts.next_value_os() {
                                v.to_str().map(|s| s.to_string())
                            } else if let Some(v) = raw.next_os(&mut cursor) {
                                v.to_str()
                                    .filter(|v| !v.is_empty() && v.find('-') != Some(0))
                                    .map(|v| v.to_string())
                            } else {
                                return Err(GatewayError::RequiredValue("config"));
                            };
                            debug!("config path: {:?}", config_path);
                        }
                        Ok('h') => {
                            trace!("help arg found");
                            print!("{}", HELP);
                            process::exit(0x0);
                        }
                        _ => {}
                    }
                }
                continue;
            }

            break;
        }
        trace!("args successfully parsed");
        Ok(Self { config_path })
    }
}
