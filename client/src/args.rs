use crate::error::ClientError;

use regex::Regex;
use std::{collections::HashMap, net::SocketAddr, process};

#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::net::{IpAddr, Ipv4Addr};

static HELP: &str = include_str!("../main.help.arg");
static LIST_HELP: &str = include_str!("../list.help.arg");
static FORWARD_HELP: &str = include_str!("../forward.help.arg");
static PROXY_HELP: &str = include_str!("../proxy.help.arg");
static CONNECT_HELP: &str = include_str!("../connect.help.arg");
#[cfg(any(target_os = "linux", target_os = "macos"))]
static TUN_HELP: &str = include_str!("../tun.help.arg");

pub fn extract_addr(addr: &str, local: bool) -> Result<(String, u16), ClientError> {
    match addr.parse::<SocketAddr>() {
        Ok(addr) => Ok((addr.ip().to_string(), addr.port())),
        Err(_) => {
            let mut v: Vec<&str> = addr.rsplitn(2, ':').collect();
            let address = v
                .pop()
                .filter(|addr| !addr.is_empty() || local)
                .filter(|addr| {
                    Regex::new(r"^[a-zA-Z0-9]((\.|-)?[a-zA-Z0-9])*$")
                        .map(|re| re.is_match(addr))
                        .unwrap_or(false)
                })
                .ok_or(ClientError::InvalidAddress)?;

            let port = v
                .pop()
                .and_then(|port| port.parse::<u16>().ok())
                .filter(|port| *port != 0)
                .ok_or(ClientError::InvalidPort)?;

            Ok((address.to_string(), port))
        }
    }
}

#[derive(Debug)]
pub struct ListArgs {
    pub verbose: bool, //a verbose
}

#[derive(Debug, Clone)]
pub struct ForwardArgs {
    pub direct: bool,                 //d direct
    pub relay: bool,                  //r relay
    pub udp: bool,                    //u udp
    pub agent_name: String,           //i name
    pub cryptography: Option<String>, //k key
    pub local_addr: (String, u16),    //l local
    pub remote_addr: (String, u16),   //<Remote>
}

#[derive(Debug, Clone)]
pub struct ProxyArgs {
    pub direct: bool,                 //d direct
    pub relay: bool,                  //r relay
    pub agent_name: String,           //i name
    pub cryptography: Option<String>, //k key
    pub local_addr: (String, u16),    //<Local>
}

#[derive(Debug, Clone)]
pub struct ConnectArgs {
    pub direct: bool,                 //d direct
    pub relay: bool,                  //r relay
    pub udp: bool,                    //u udp
    pub agent_name: String,           //i name
    pub cryptography: Option<String>, //k key
    pub remote_addr: (String, u16),   //<Local>
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug, Clone)]
pub struct TunArgs {
    pub gateway: bool,                //g gateway
    pub direct: bool,                 //d direct
    pub relay: bool,                  //r relay
    pub agent_name: String,           //i name
    pub cryptography: Option<String>, //k key
    pub local_addr: IpAddr,           //l local
    pub map_addr: Option<IpAddr>,     //m map
}

#[derive(Debug)]
enum SubCommands {
    Forward,
    List,
    Connect,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    Tun,
    Proxy,
}

impl SubCommands {
    pub fn new(arg: &str) -> Result<Self, ClientError> {
        let mut types: HashMap<&str, usize> = HashMap::from([
            ("forward", 0),
            ("list", 0),
            ("proxy", 0),
            ("connect", 0),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            ("tun", 0),
        ]);
        for (i, c) in arg.chars().enumerate() {
            for (type_name, type_value) in types.iter_mut() {
                if *type_value == i && arg.len() <= type_name.len() {
                    if type_name.chars().nth(i) == Some(c) {
                        *type_value += 1;
                    } else {
                        *type_value = 0;
                    }
                }
            }
        }
        match types
            .iter()
            .filter(|(_, value)| **value != 0usize)
            .max_by(|(_, x_type_value), (_, y_type_value)| {
                x_type_value
                    .partial_cmp(y_type_value)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|(name, _)| *name)
            .ok_or(ClientError::CommandNotFound)?
        {
            "forward" => Ok(Self::Forward),
            "list" => Ok(Self::List),
            "connect" => Ok(Self::Connect),
            "proxy" => Ok(Self::Proxy),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            "tun" => Ok(Self::Tun),
            _ => Err(ClientError::CommandNotFound),
        }
    }
}

#[derive(Debug)]
pub struct Args {
    pub config_path: Option<String>,
    pub arg_commands: ArgCommands,
}

impl Args {
    pub fn parse(
        raw: impl IntoIterator<Item = impl Into<std::ffi::OsString>>,
    ) -> Result<Self, ClientError> {
        let raw = clap_lex::RawArgs::new(raw);
        let mut cursor = raw.cursor();
        raw.next(&mut cursor);
        let mut config_path = None;
        let command_arg = loop {
            let Some(arg) = raw.next(&mut cursor) else {
                print!("{}", HELP);
                process::exit(0x0);
            };
            if let Some((long, value)) = arg.to_long() {
                match long {
                    Ok("config") => {
                        config_path = Some(
                            value
                                .ok_or(ClientError::RequiredValue("config"))?
                                .to_str()
                                .ok_or(ClientError::Encoding)?
                                .to_owned(),
                        );
                        continue;
                    }
                    Ok("help") => {
                        print!("{}", HELP);
                        process::exit(0x0);
                    }
                    Ok("version") => {
                        print!("{}", env!("CARGO_PKG_VERSION"));
                        process::exit(0x0);
                    }
                    _ => {}
                }
            } else if let Some(mut shorts) = arg.to_short() {
                while let Some(short) = shorts.next_flag() {
                    match short {
                        Ok('c') => {
                            config_path = if let Some(v) = shorts.next_value_os() {
                                v.to_str().map(|s| s.to_string())
                            } else if let Some(v) = raw.next_os(&mut cursor) {
                                v.to_str()
                                    .filter(|v| !v.is_empty() && v.find('-') != Some(0))
                                    .map(|v| v.to_string())
                            } else {
                                return Err(ClientError::RequiredValue("config"));
                            };
                        }
                        Ok('h') => {
                            print!("{}", HELP);
                            process::exit(0x0);
                        }
                        _ => {}
                    }
                }
                continue;
            }

            break arg;
        };
        let arg_command =
            match SubCommands::new(command_arg.to_value().or(Err(ClientError::Encoding))?)? {
                SubCommands::List => {
                    let mut sub = ListArgs { verbose: false };
                    while let Some(arg) = raw.next(&mut cursor) {
                        if let Some((long, _value)) = arg.to_long() {
                            match long {
                                Ok("verbose") => {
                                    sub.verbose = true;
                                }
                                Ok("help") => {
                                    print!("{}", LIST_HELP);
                                    process::exit(0x0);
                                }
                                _ => {}
                            }
                        } else if let Some(mut shorts) = arg.to_short() {
                            while let Some(short) = shorts.next_flag() {
                                match short {
                                    Ok('v') => {
                                        sub.verbose = true;
                                    }
                                    Ok('h') => {
                                        print!("{}", LIST_HELP);
                                        process::exit(0x0);
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                    Ok(ArgCommands::List(sub))
                }
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                SubCommands::Tun => {
                    let mut sub = TunArgs {
                        agent_name: String::new(),
                        cryptography: None,
                        direct: false,
                        gateway: false,
                        relay: false,
                        local_addr: IpAddr::V4(Ipv4Addr::new(10, 10, 10, 10)),
                        map_addr: None,
                    };
                    while let Some(arg) = raw.next(&mut cursor) {
                        if let Some((long, value)) = arg.to_long() {
                            match long {
                                Ok("direct") => {
                                    sub.direct = true;
                                }
                                Ok("gateway") => {
                                    sub.gateway = true;
                                }
                                Ok("relay") => {
                                    sub.relay = true;
                                }
                                Ok("name") => {
                                    sub.agent_name = value
                                        .ok_or(ClientError::RequiredValue("name"))?
                                        .to_str()
                                        .ok_or(ClientError::Encoding)?
                                        .to_string();
                                }
                                Ok("key") => {
                                    sub.cryptography = Some(
                                        value
                                            .ok_or(ClientError::RequiredValue("key"))?
                                            .to_str()
                                            .ok_or(ClientError::Encoding)?
                                            .to_string(),
                                    );
                                }
                                Ok("local") => {
                                    sub.local_addr = value
                                        .ok_or(ClientError::RequiredValue("local"))?
                                        .to_str()
                                        .ok_or(ClientError::Encoding)?
                                        .parse::<IpAddr>()
                                        .map_err(|_| ClientError::InvalidAddress)?;
                                }
                                Ok("map") => {
                                    sub.map_addr = Some(
                                        value
                                            .ok_or(ClientError::RequiredValue("map"))?
                                            .to_str()
                                            .ok_or(ClientError::Encoding)?
                                            .parse::<IpAddr>()
                                            .map_err(|_| ClientError::InvalidAddress)?,
                                    );
                                }
                                Ok("help") => {
                                    print!("{}", TUN_HELP);
                                    process::exit(0x0);
                                }
                                _ => {}
                            }
                        } else if let Some(mut shorts) = arg.to_short() {
                            while let Some(short) = shorts.next_flag() {
                                match short {
                                    Ok('n') => {
                                        sub.agent_name = if let Some(v) = shorts.next_value_os() {
                                            v.to_str()
                                        } else if let Some(v) = raw.next_os(&mut cursor) {
                                            v.to_str().and_then(|v| {
                                                if v.is_empty() || v.find('-') == Some(0) {
                                                    None
                                                } else {
                                                    Some(v)
                                                }
                                            })
                                        } else {
                                            None
                                        }
                                        .ok_or(ClientError::Encoding)?
                                        .to_string();
                                    }
                                    Ok('d') => {
                                        sub.direct = true;
                                    }
                                    Ok('r') => {
                                        sub.relay = true;
                                    }
                                    Ok('g') => {
                                        sub.gateway = true;
                                    }
                                    Ok('k') => {
                                        let next_value = if let Some(v) = shorts.next_value_os() {
                                            v.to_str()
                                        } else if let Some(v) = raw.next_os(&mut cursor) {
                                            v.to_str().and_then(|v| {
                                                if v.is_empty() || v.find('-') == Some(0) {
                                                    None
                                                } else {
                                                    Some(v)
                                                }
                                            })
                                        } else {
                                            None
                                        };

                                        sub.cryptography = Some(
                                            next_value
                                                .ok_or(ClientError::RequiredValue("key"))?
                                                .to_string(),
                                        );
                                    }
                                    Ok('l') => {
                                        let next_value = if let Some(v) = shorts.next_value_os() {
                                            v.to_str()
                                        } else if let Some(v) = raw.next_os(&mut cursor) {
                                            v.to_str().and_then(|v| {
                                                if v.is_empty() || v.find('-') == Some(0) {
                                                    None
                                                } else {
                                                    Some(v)
                                                }
                                            })
                                        } else {
                                            None
                                        };
                                        sub.local_addr = next_value
                                            .ok_or(ClientError::RequiredValue("local"))?
                                            .parse::<IpAddr>()
                                            .map_err(|_| ClientError::InvalidAddress)?;
                                    }
                                    Ok('m') => {
                                        let next_value = if let Some(v) = shorts.next_value_os() {
                                            v.to_str()
                                        } else if let Some(v) = raw.next_os(&mut cursor) {
                                            v.to_str().and_then(|v| {
                                                if v.is_empty() || v.find('-') == Some(0) {
                                                    None
                                                } else {
                                                    Some(v)
                                                }
                                            })
                                        } else {
                                            None
                                        };

                                        sub.map_addr = Some(
                                            next_value
                                                .ok_or(ClientError::RequiredValue("map"))?
                                                .parse::<IpAddr>()
                                                .map_err(|_| ClientError::InvalidAddress)?,
                                        );
                                    }
                                    Ok('h') => {
                                        print!("{}", TUN_HELP);
                                        process::exit(0x0);
                                    }
                                    _ => {}
                                }
                            }
                        } else {
                            // sub.remote_addr = extract_addr(
                            //     arg.to_value_os()
                            //         .to_str()
                            //         .and_then(|v| {
                            //             if v.is_empty() || v.find('-') == Some(0) {
                            //                 None
                            //             } else {
                            //                 Some(v)
                            //             }
                            //         })
                            //         .ok_or(ClientError::Encoding)?,
                            //     false,
                            // )?;
                        }
                    }
                    Ok(ArgCommands::Tun(sub))
                    // if sub.remote_addr.0.is_empty() {
                    //     Err(ClientError::RequiredValue("remote"))
                    // } else {
                    //     // if sub.agent_name.is_empty() {
                    //     //     sub.agent_name = lookup_one(gateway_address.clone(), token.clone()).await?
                    //     // }
                    //     Ok(ArgCommands::Tun(sub))
                    // }
                }
                SubCommands::Forward => {
                    let mut sub = ForwardArgs {
                        agent_name: String::new(),
                        local_addr: ("127.0.0.1".to_string(), 0),
                        cryptography: None,
                        udp: false,
                        direct: false,
                        relay: false,
                        remote_addr: ("".to_string(), 0),
                    };
                    while let Some(arg) = raw.next(&mut cursor) {
                        if let Some((long, value)) = arg.to_long() {
                            match long {
                                Ok("udp") => {
                                    sub.udp = true;
                                }
                                Ok("direct") => {
                                    sub.direct = true;
                                }
                                Ok("relay") => {
                                    sub.relay = true;
                                }
                                Ok("name") => {
                                    sub.agent_name = value
                                        .ok_or(ClientError::RequiredValue("name"))?
                                        .to_str()
                                        .ok_or(ClientError::Encoding)?
                                        .to_string();
                                    // sub.agent_name = lookup_by_name(
                                    //     gateway_address.clone(),
                                    //     token.clone(),
                                    //     value
                                    //         .ok_or(ClientError::RequiredValue("name"))?
                                    //         .to_str()
                                    //         .ok_or(ClientError::Encoding)?,
                                    // )
                                    // .await?;
                                    // sub.agent_name = Some(
                                    //     value
                                    //         .ok_or(ArgsErrorTypes::RequiredValue("name"))?
                                    //         .to_str()
                                    //         .ok_or(ArgsErrorTypes::Encoding)?
                                    //         .to_string(),
                                    // );
                                }
                                Ok("local") => {
                                    sub.local_addr = extract_addr(
                                        value
                                            .ok_or(ClientError::RequiredValue("local"))?
                                            .to_str()
                                            .ok_or(ClientError::Encoding)?,
                                        true,
                                    )?;
                                }
                                Ok("key") => {
                                    sub.cryptography = Some(
                                        value
                                            .ok_or(ClientError::RequiredValue("key"))?
                                            .to_str()
                                            .ok_or(ClientError::Encoding)?
                                            .to_string(),
                                    );
                                }
                                Ok("help") => {
                                    print!("{}", FORWARD_HELP);
                                    process::exit(0x0);
                                }
                                _ => {}
                            }
                        } else if let Some(mut shorts) = arg.to_short() {
                            while let Some(short) = shorts.next_flag() {
                                match short {
                                    Ok('u') => {
                                        sub.udp = true;
                                    }
                                    Ok('d') => {
                                        sub.direct = true;
                                    }
                                    Ok('r') => {
                                        sub.relay = true;
                                    }

                                    Ok('n') => {
                                        sub.agent_name = if let Some(v) = shorts.next_value_os() {
                                            v.to_str()
                                        } else if let Some(v) = raw.next_os(&mut cursor) {
                                            v.to_str().and_then(|v| {
                                                if v.is_empty() || v.find('-') == Some(0) {
                                                    None
                                                } else {
                                                    Some(v)
                                                }
                                            })
                                        } else {
                                            None
                                        }
                                        .ok_or(ClientError::Encoding)?
                                        .to_string();
                                    }
                                    Ok('l') => {
                                        let next_value = if let Some(v) = shorts.next_value_os() {
                                            v.to_str()
                                        } else if let Some(v) = raw.next_os(&mut cursor) {
                                            v.to_str().and_then(|v| {
                                                if v.is_empty() || v.find('-') == Some(0) {
                                                    None
                                                } else {
                                                    Some(v)
                                                }
                                            })
                                        } else {
                                            None
                                        };

                                        sub.local_addr = extract_addr(
                                            next_value
                                                .ok_or(ClientError::RequiredValue("local"))?,
                                            true,
                                        )?;
                                    }
                                    Ok('k') => {
                                        let next_value = if let Some(v) = shorts.next_value_os() {
                                            v.to_str()
                                        } else if let Some(v) = raw.next_os(&mut cursor) {
                                            v.to_str().and_then(|v| {
                                                if v.is_empty() || v.find('-') == Some(0) {
                                                    None
                                                } else {
                                                    Some(v)
                                                }
                                            })
                                        } else {
                                            None
                                        };

                                        sub.cryptography = Some(
                                            next_value
                                                .ok_or(ClientError::RequiredValue("key"))?
                                                .to_string(),
                                        );
                                    }

                                    Ok('h') => {
                                        print!("{}", FORWARD_HELP);
                                        process::exit(0x0);
                                    }
                                    _ => {}
                                }
                            }
                        } else {
                            sub.remote_addr = extract_addr(
                                arg.to_value_os()
                                    .to_str()
                                    .and_then(|v| {
                                        if v.is_empty() || v.find('-') == Some(0) {
                                            None
                                        } else {
                                            Some(v)
                                        }
                                    })
                                    .ok_or(ClientError::Encoding)?,
                                false,
                            )?;
                        }
                    }
                    if sub.remote_addr.0.is_empty() {
                        Err(ClientError::RequiredValue("remote"))
                    } else {
                        // if sub.agent_name.is_empty() {
                        //     sub.agent_name = lookup_one(gateway_address.clone(), token.clone()).await?
                        // }
                        Ok(ArgCommands::Forward(sub))
                    }
                }
                SubCommands::Connect => {
                    // let token = if let Some(token) = token {
                    //     token
                    // } else {
                    //     return Err(ClientError::AuthRequired);
                    // };
                    let mut sub = ConnectArgs {
                        agent_name: String::new(),
                        cryptography: None,
                        udp: false,
                        direct: false,
                        remote_addr: ("".to_string(), 0),
                        relay: false,
                    };
                    while let Some(arg) = raw.next(&mut cursor) {
                        if let Some((long, value)) = arg.to_long() {
                            match long {
                                Ok("udp") => {
                                    sub.udp = true;
                                }
                                Ok("direct") => {
                                    sub.direct = true;
                                }
                                Ok("relay") => {
                                    sub.relay = true;
                                }
                                Ok("name") => {
                                    // sub.agent_name = lookup_by_name(
                                    //     gateway_address.clone(),
                                    //     token.clone(),
                                    //     value
                                    //         .ok_or(ClientError::RequiredValue("name"))?
                                    //         .to_str()
                                    //         .ok_or(ClientError::Encoding)?,
                                    // )
                                    // .await?;
                                    if sub.agent_name.is_empty() {
                                        sub.agent_name = value
                                            .ok_or(ClientError::RequiredValue("name"))?
                                            .to_str()
                                            .ok_or(ClientError::Encoding)?
                                            .to_string();
                                    }
                                    // sub.agent_name = Some(
                                    //     value
                                    //         .ok_or(ArgsErrorTypes::RequiredValue("name"))?
                                    //         .to_str()
                                    //         .ok_or(ArgsErrorTypes::Encoding)?
                                    //         .to_string(),
                                    // );
                                }
                                Ok("key") => {
                                    sub.cryptography = Some(
                                        value
                                            .ok_or(ClientError::RequiredValue("key"))?
                                            .to_str()
                                            .ok_or(ClientError::Encoding)?
                                            .to_string(),
                                    );
                                }
                                Ok("help") => {
                                    print!("{}", CONNECT_HELP);
                                    process::exit(0x0);
                                }
                                _ => {}
                            }
                        } else if let Some(mut shorts) = arg.to_short() {
                            while let Some(short) = shorts.next_flag() {
                                match short {
                                    Ok('u') => {
                                        sub.udp = true;
                                    }
                                    Ok('d') => {
                                        sub.direct = true;
                                    }
                                    Ok('r') => {
                                        sub.relay = true;
                                    }
                                    Ok('n') => {
                                        sub.agent_name = if let Some(v) = shorts.next_value_os() {
                                            v.to_str()
                                        } else if let Some(v) = raw.next_os(&mut cursor) {
                                            v.to_str().and_then(|v| {
                                                if v.is_empty() || v.find('-') == Some(0) {
                                                    None
                                                } else {
                                                    Some(v)
                                                }
                                            })
                                        } else {
                                            None
                                        }
                                        .ok_or(ClientError::Encoding)?
                                        .to_string();

                                        // let next_value = if let Some(v) = shorts.next_value_os() {
                                        //     v.to_str()
                                        // } else if let Some(v) = raw.next_os(&mut cursor) {
                                        //     v.to_str().and_then(|v| {
                                        //         if v.is_empty() || v.find('-') == Some(0) {
                                        //             None
                                        //         } else {
                                        //             Some(v)
                                        //         }
                                        //     })
                                        // } else {
                                        //     None
                                        // };
                                        // if sub.agent_name.is_empty() {
                                        //     sub.agent_name = lookup_by_name(
                                        //         gateway_address.clone(),
                                        //         token.clone(),
                                        //         next_value.ok_or(ClientError::RequiredValue("name"))?,
                                        //     )
                                        //     .await?;
                                        // }
                                    }
                                    Ok('k') => {
                                        let next_value = if let Some(v) = shorts.next_value_os() {
                                            v.to_str()
                                        } else if let Some(v) = raw.next_os(&mut cursor) {
                                            v.to_str().and_then(|v| {
                                                if v.is_empty() || v.find('-') == Some(0) {
                                                    None
                                                } else {
                                                    Some(v)
                                                }
                                            })
                                        } else {
                                            None
                                        };

                                        sub.cryptography = Some(
                                            next_value
                                                .ok_or(ClientError::RequiredValue("key"))?
                                                .to_string(),
                                        );
                                    }

                                    Ok('h') => {
                                        print!("{}", CONNECT_HELP);
                                        process::exit(0x0);
                                    }
                                    _ => {}
                                }
                            }
                        } else {
                            sub.remote_addr = extract_addr(
                                arg.to_value_os()
                                    .to_str()
                                    .and_then(|v| {
                                        if v.is_empty() || v.find('-') == Some(0) {
                                            None
                                        } else {
                                            Some(v)
                                        }
                                    })
                                    .ok_or(ClientError::Encoding)?,
                                false,
                            )?;
                        }
                    }
                    if sub.remote_addr.0.is_empty() {
                        Err(ClientError::RequiredValue("remote"))
                    } else {
                        // if sub.agent_name.is_empty() {
                        //     sub.agent_name = lookup_one(gateway_address.clone(), token.clone()).await?
                        // }

                        Ok(ArgCommands::Connect(sub))
                    }
                }
                SubCommands::Proxy => {
                    // let token = if let Some(token) = token {
                    //     token
                    // } else {
                    //     return Err(ClientError::AuthRequired);
                    // };
                    let mut sub = ProxyArgs {
                        agent_name: String::new(),
                        cryptography: None,
                        relay: false,
                        direct: false,
                        local_addr: ("".to_string(), 0),
                    };
                    while let Some(arg) = raw.next(&mut cursor) {
                        if let Some((long, value)) = arg.to_long() {
                            match long {
                                Ok("name") => {
                                    if sub.agent_name.is_empty() {
                                        sub.agent_name = value
                                            .ok_or(ClientError::RequiredValue("name"))?
                                            .to_str()
                                            .ok_or(ClientError::Encoding)?
                                            .to_string();
                                    }
                                    // sub.agent_name = lookup_by_name(
                                    //     gateway_address.clone(),
                                    //     token.clone(),
                                    //     value
                                    //         .ok_or(ClientError::RequiredValue("name"))?
                                    //         .to_str()
                                    //         .ok_or(ClientError::Encoding)?,
                                    // )
                                    // .await?;
                                }
                                Ok("direct") => {
                                    sub.direct = true;
                                }
                                Ok("relay") => {
                                    sub.relay = true;
                                }
                                Ok("key") => {
                                    sub.cryptography = Some(
                                        value
                                            .ok_or(ClientError::RequiredValue("key"))?
                                            .to_str()
                                            .ok_or(ClientError::Encoding)?
                                            .to_string(),
                                    );
                                }
                                Ok("help") => {
                                    print!("{}", PROXY_HELP);
                                    process::exit(0x0);
                                }
                                _ => {}
                            }
                        } else if let Some(mut shorts) = arg.to_short() {
                            while let Some(short) = shorts.next_flag() {
                                match short {
                                    Ok('d') => {
                                        sub.direct = true;
                                    }
                                    Ok('r') => {
                                        sub.relay = true;
                                    }
                                    Ok('n') => {
                                        sub.agent_name = if let Some(v) = shorts.next_value_os() {
                                            v.to_str()
                                        } else if let Some(v) = raw.next_os(&mut cursor) {
                                            v.to_str().and_then(|v| {
                                                if v.is_empty() || v.find('-') == Some(0) {
                                                    None
                                                } else {
                                                    Some(v)
                                                }
                                            })
                                        } else {
                                            None
                                        }
                                        .ok_or(ClientError::Encoding)?
                                        .to_string();
                                    }
                                    Ok('k') => {
                                        let next_value = if let Some(v) = shorts.next_value_os() {
                                            v.to_str()
                                        } else if let Some(v) = raw.next_os(&mut cursor) {
                                            v.to_str().and_then(|v| {
                                                if v.is_empty() || v.find('-') == Some(0) {
                                                    None
                                                } else {
                                                    Some(v)
                                                }
                                            })
                                        } else {
                                            None
                                        };

                                        sub.cryptography = Some(
                                            next_value
                                                .ok_or(ClientError::RequiredValue("key"))?
                                                .to_string(),
                                        );
                                    }
                                    Ok('h') => {
                                        print!("{}", PROXY_HELP);
                                        process::exit(0x0);
                                    }
                                    _ => {}
                                }
                            }
                        } else {
                            sub.local_addr = extract_addr(
                                arg.to_value_os()
                                    .to_str()
                                    .and_then(|v| {
                                        if v.is_empty() || v.find('-') == Some(0) {
                                            None
                                        } else {
                                            Some(v)
                                        }
                                    })
                                    .ok_or(ClientError::Encoding)?,
                                false,
                            )?;
                        }
                    }
                    if sub.local_addr.0.is_empty() {
                        Err(ClientError::RequiredValue("local"))
                    } else {
                        // if sub.agent_name.is_empty() {
                        //     sub.agent_name = lookup_one(gateway_address, token.clone()).await?
                        // }

                        Ok(ArgCommands::Proxy(sub))
                    }
                }
            };
        Ok(Self {
            config_path,
            arg_commands: arg_command?,
        })
    }
    pub fn take_conf_path(&mut self) -> Option<String> {
        self.config_path.take()
    }
}

#[derive(Debug)]
pub enum ArgCommands {
    Forward(ForwardArgs),
    List(ListArgs),
    Proxy(ProxyArgs),
    Connect(ConnectArgs),
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    Tun(TunArgs),
}

impl ArgCommands {
    pub fn agent_name(&self) -> Option<String> {
        match self {
            ArgCommands::Forward(args) => Some(&args.agent_name),
            ArgCommands::Proxy(args) => Some(&args.agent_name),
            ArgCommands::Connect(args) => Some(&args.agent_name),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            ArgCommands::Tun(args) => Some(&args.agent_name),
            _ => None,
        }
        .cloned()
    }
    pub fn verbose(&self) -> bool {
        match self {
            ArgCommands::List(args) => args.verbose,
            _ => false,
        }
    }
    pub fn relay(&self) -> bool {
        match self {
            ArgCommands::Forward(args) => args.relay,
            ArgCommands::Proxy(args) => args.relay,
            ArgCommands::Connect(args) => args.relay,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            ArgCommands::Tun(args) => args.relay,
            _ => false,
        }
    }
    pub fn direct(&self) -> bool {
        match self {
            ArgCommands::Forward(args) => args.direct,
            ArgCommands::Proxy(args) => args.direct,
            ArgCommands::Connect(args) => args.direct,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            ArgCommands::Tun(args) => args.direct,
            _ => false,
        }
    }
    pub fn cryptography(&self) -> Option<String> {
        match self {
            ArgCommands::Forward(args) => args.cryptography.clone(),
            ArgCommands::Proxy(args) => args.cryptography.clone(),
            ArgCommands::Connect(args) => args.cryptography.clone(),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            ArgCommands::Tun(args) => args.cryptography.clone(),
            _ => None,
        }
    }
}
