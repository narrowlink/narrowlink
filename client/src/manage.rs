use futures_util::StreamExt;
use rand::Rng;
use std::{
    collections::HashMap,
    net::SocketAddr,
    process,
    sync::{
        atomic::{AtomicU8, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{select, time};
use tracing::{debug, error, info, trace, warn};
use uuid::Uuid;

use narrowlink_network::{
    error::NetworkError,
    event::{NarrowEvent, NarrowEventRequest},
    ws::WsConnection,
};
use narrowlink_types::{
    client::EventInBound as ClientEventInBound,
    client::EventOutBound as ClientEventOutBound,
    client::EventRequest as ClientEventRequest,
    client::{Peer2PeerInstruction, Peer2PeerRequest},
    generic::AgentInfo,
    GetResponse, ServiceType,
};

use crate::{
    args::{ArgCommands, ListArgs},
    config::{self, Config},
    error::ClientError,
    transport::{DirectTunnelStatus, TransportInstruction},
    tunnel::TunnelInstruction,
};

pub enum ControlMsg {
    ConnectionError(Uuid, String),
    Peer2Peer(Peer2PeerInstruction),
}

pub struct ControlFactory {
    gateway: Arc<String>,
    token: Arc<String>,
    acl: Option<String>,
    protocol: ServiceType,
    pub control: Option<ControlInfo>,
    pub active_connections: futures_util::stream::FuturesOrdered<
        tokio::task::JoinHandle<Result<std::option::Option<std::string::String>, ClientError>>,
    >,
    pub direct_tunnel_status: Arc<AtomicU8>,
}

#[derive(Clone)]
pub struct RelayInfo {
    pub protocol: ServiceType,
    pub gateway: String,
    pub token: String,
    pub session_id: String,
}

pub struct ControlInfo {
    // local_addr: SocketAddr,
    pub address: SocketAddr,
    // session_id: String,
    request: NarrowEventRequest<ClientEventOutBound, ClientEventInBound>,
    agents: Vec<AgentInfo>,
    msg_receiver: tokio::sync::mpsc::UnboundedReceiver<ControlMsg>,
    task: tokio::task::JoinHandle<()>,
}

impl ControlFactory {
    pub fn new(conf: Config) -> Result<Self, ClientError> {
        let Some(config::Endpoint::SelfHosted(conf)) = conf.endpoints.first() else {
            return Err(ClientError::InvalidConfig);
        };
        Ok(Self {
            gateway: Arc::new(conf.gateway.clone()),
            token: Arc::new(conf.token.clone()),
            acl: if conf.acl.is_empty() {
                None
            } else {
                serde_json::to_string(&conf.acl).ok()
            },
            protocol: conf.protocol.clone(),
            control: None,
            active_connections: futures_util::stream::FuturesOrdered::new(),
            direct_tunnel_status: Arc::new(AtomicU8::new(DirectTunnelStatus::Uninitialized as u8)),
        })
    }

    pub async fn connect(&mut self, quiet: bool) -> Result<RelayInfo, ClientError> {
        if !quiet {
            info!("Connecting to gateway: {}", self.gateway);
        }

        let headers = if let Some(acl) = self.acl.as_ref() {
            HashMap::from([
                ("NL-ACL", acl.to_string()),
                ("NL-TOKEN", self.token.to_string()),
            ])
        } else {
            HashMap::from([("NL-TOKEN", self.token.to_string())])
        };
        if let Some(c) = self.control.take() {
            c.task.abort();
        }
        let mut sleep_time = 0;
        let connection = loop {
            match WsConnection::new(&self.gateway, &headers, &self.protocol).await {
                Ok(con) => break con,
                Err(e) => {
                    if let NetworkError::UnableToUpgrade(status) = e {
                        match status {
                            401 => {
                                error!("Authentication failed");
                                return Err(e)?;
                            }
                            403 => {
                                error!("Access denied");
                                return Err(e)?;
                            }
                            _ => {}
                        }
                    };
                    error!("Unable to connect to the gateway: {}", e.to_string());
                    if sleep_time == 0 {
                        info!("Try again");
                    } else if sleep_time >= 35 {
                        error!("Unable to connect");
                        info!("Exit");
                        return Err(e)?;
                    } else {
                        info!("Try again in {} secs", sleep_time);
                    }
                    time::sleep(Duration::from_secs(sleep_time)).await;
                    sleep_time += 5;
                    continue;
                }
            }
        };

        let session_id = connection
            .get_header("NL-SESSION")
            .ok_or(ClientError::UnableToConnect)?
            .to_string();

        let local_addr = connection.local_addr();
        let address = connection.peer_addr();

        let mut stream: NarrowEvent<ClientEventOutBound, ClientEventInBound> =
            NarrowEvent::new(connection);
        let request = stream.get_request();
        let (msg_sender, msg_receiver) = tokio::sync::mpsc::unbounded_channel();
        let task = tokio::spawn(async move {
            loop {
                let Some(msg) = stream.next().await else {
                    break;
                };
                match msg {
                    Ok(narrowlink_types::client::EventInBound::ConnectionError(
                        connection_id,
                        msg,
                    )) => {
                        debug!("Connection error: {}:{}", connection_id, msg);
                        let _ = msg_sender.send(ControlMsg::ConnectionError(connection_id, msg));
                    }
                    Ok(narrowlink_types::client::EventInBound::Peer2Peer(p2p)) => {
                        debug!("Peer2Peer: {:?}", p2p);
                        let _ = msg_sender.send(ControlMsg::Peer2Peer(p2p));
                    }
                    Ok(_) => {
                        debug!("Unhandled message: {:?}", msg);
                    }
                    Err(e) => {
                        debug!("Error: {:?}", e);
                        break;
                    }
                }
            }
        });

        let Some(narrowlink_types::client::EventResponse::ActiveAgents(agents)) = request
            .request(ClientEventOutBound::Request(
                0,
                ClientEventRequest::ListOfAgents,
            ))
            .await?
            .response()
        else {
            return Err(ClientError::UnableToConnect);
        };

        request
            .request(ClientEventOutBound::Request(
                0,
                ClientEventRequest::UpdateConstantSysInfo(
                    narrowlink_types::client::ConstSystemInfo { local_addr },
                ),
            ))
            .await?;

        self.control = Some(ControlInfo {
            // local_addr,
            address,
            // session_id: session_id.clone(),
            request,
            agents,
            msg_receiver,
            task,
        });
        if !quiet {
            info!("Connection to gateway successful");
        }
        Ok(RelayInfo {
            protocol: self.protocol.clone(),
            gateway: self.gateway.to_string(),
            token: self.token.to_string(),
            session_id,
        })
    }
    pub fn add_connection(
        &mut self,
        task: tokio::task::JoinHandle<
            Result<std::option::Option<std::string::String>, ClientError>,
        >,
    ) {
        self.active_connections.push_back(task);
    }
    pub async fn accept_msg(&mut self) -> Result<ControlMsg, ClientError> {
        if let Some(control) = self.control.as_mut() {
            loop {
                select! {
                    msg = control.msg_receiver.recv() => {
                        match msg{
                            Some(msg) => {
                                return Ok(msg);
                            }
                            None => {
                                return Err(ClientError::Unexpected(0));
                            }
                        }
                    }
                    Some(connection_result) = self.active_connections.next() => {
                        match connection_result {
                            Ok(Err(e)) => {
                                if matches!(e, ClientError::UnableToConnectToRelay) {
                                    return Err(ClientError::ConnectionClosed);
                                }else if matches!(e, ClientError::AgentNotFound) || matches!(e, ClientError::AuthRequired) {
                                    return Err(e);
                                }
                            }
                            _ => {
                                continue;
                            }
                        }
                    }
                    _ = &mut control.task => {
                        warn!("Control connection closed");
                        return Err(ClientError::ConnectionClosed);
                    }
                }
            }
        }
        Err(ClientError::ControlChannelNotConnected)
    }

    pub async fn manage(&self, manage: &ManageInstruction) -> Result<(), ClientError> {
        match manage {
            ManageInstruction::AgentList(verbose) => {
                trace!("List of agents");
                let Some(agents) = self.control.as_ref().map(|c| c.agents.clone()) else {
                    println!("Agent not found");
                    return Ok(());
                };
                if agents.is_empty() {
                    println!("Agent not found");
                }
                for agent in agents.iter() {
                    println!("{}:", agent.name);
                    println!("\tAddress: {}", agent.socket_addr);

                    if let Some(forward_addr) = &agent.forward_addr {
                        println!("\tForward Address: {}", forward_addr);
                    }
                    if let Some(system_info) = &agent.system_info.as_ref().filter(|_| *verbose) {
                        println!("\tSystem Info:");
                        println!("\t\tLocal Address: {}", system_info.constant.local_addr);
                        println!("\t\tLoad Avarage: {}", system_info.dynamic.loadavg);
                        println!("\t\tCPU Cores: {}", system_info.constant.cpus);
                    }
                    if *verbose {
                        if !agent.publish_info.is_empty() {
                            println!("\tPublish Info:");
                            for agent_publish_info in &agent.publish_info {
                                println!("\t\t{}", agent_publish_info.to_string());
                            }
                        }
                        if let Some(since) =
                            &chrono::NaiveDateTime::from_timestamp_opt(agent.since as i64, 0)
                        {
                            let datetime: chrono::DateTime<chrono::Local> =
                                chrono::DateTime::from_naive_utc_and_offset(
                                    *since,
                                    *chrono::Local::now().offset(),
                                );
                            println!("\tConnection Time: {}", datetime);
                        }
                    }

                    println!("\tConnection Ping: {}ms\r\n", agent.ping);
                }
                process::exit(0);
            }
            ManageInstruction::Peer2Peer(p2p) => {
                if self
                    .control
                    .as_ref()
                    .and_then(|c| c.agents.iter().find(|a| a.name == p2p.agent_name))
                    .is_none()
                {
                    return Err(ClientError::AgentNotFound);
                }
                if !self.direct_tunnel_status.load(Ordering::Relaxed)
                    == (DirectTunnelStatus::Uninitialized as u8)
                {
                    // debug!("Direct tunnel already initialized");
                    return Ok(());
                };
                let Some(control) = self.control.as_ref() else {
                    return Err(ClientError::ConnectionClosed);
                };
                if control
                    .request
                    .request(ClientEventOutBound::Request(
                        0,
                        ClientEventRequest::Peer2Peer(p2p.clone()),
                    ))
                    .await
                    .is_err()
                {
                    warn!("Unable to send Peer2Peer request");
                    return Err(ClientError::ConnectionClosed);
                }
                Ok(())
            }
            ManageInstruction::AgentCheck(agent_name) => {
                if self
                    .control
                    .as_ref()
                    .and_then(|c| c.agents.iter().find(|a| &a.name == agent_name))
                    .is_none()
                {
                    return Err(ClientError::AgentNotFound);
                }
                Ok(())
            }
        }
    }
}
pub struct Instruction {
    pub tunnel: TunnelInstruction,
    pub transport: TransportInstruction,
    pub manage: ManageInstruction,
}

pub enum ManageInstruction {
    Peer2Peer(Peer2PeerRequest),
    AgentList(bool),
    AgentCheck(String),
}

impl ManageInstruction {
    fn default_p2p(agent_name: String) -> Self {
        Self::Peer2Peer(Peer2PeerRequest {
            agent_name,
            easy_seed_port: rand::thread_rng().gen_range((49152 + 2)..(65535 - 2)),
            easy_seq: 2,
            hard_seed_port: rand::thread_rng().gen_range((49152 + 255)..(65535 - 255)),
            hard_seq: 255,
        })
    }
}

impl From<&ArgCommands> for Instruction {
    fn from(cmd: &ArgCommands) -> Self {
        match cmd {
            ArgCommands::Forward(a) => Self {
                tunnel: TunnelInstruction::Forward(a.udp, a.local_addr, a.remote_addr.clone()),
                transport: TransportInstruction::determine(
                    a.direct,
                    a.relay,
                    a.cryptography.clone(),
                    a.agent_name.clone(),
                    false,
                ),
                manage: if a.direct {
                    ManageInstruction::default_p2p(a.agent_name.clone())
                } else {
                    ManageInstruction::AgentCheck(a.agent_name.clone())
                },
            },
            ArgCommands::List(ListArgs { verbose }) => Self {
                tunnel: TunnelInstruction::None,
                transport: TransportInstruction::None,
                manage: ManageInstruction::AgentList(*verbose),
            },
            ArgCommands::Proxy(a) => Self {
                tunnel: TunnelInstruction::Proxy(a.local_addr),
                transport: TransportInstruction::determine(
                    a.direct,
                    a.relay,
                    a.cryptography.clone(),
                    a.agent_name.clone(),
                    false,
                ),
                manage: if a.direct || a.relay == a.direct {
                    ManageInstruction::default_p2p(a.agent_name.clone())
                } else {
                    ManageInstruction::AgentCheck(a.agent_name.clone())
                },
            },
            ArgCommands::Connect(a) => Self {
                tunnel: TunnelInstruction::Connect(a.udp, a.remote_addr.clone()),
                transport: TransportInstruction::determine(
                    a.direct,
                    a.relay,
                    a.cryptography.clone(),
                    a.agent_name.clone(),
                    true,
                ),
                manage: if a.direct || a.relay == a.direct {
                    ManageInstruction::default_p2p(a.agent_name.clone())
                } else {
                    ManageInstruction::AgentCheck(a.agent_name.clone())
                },
            },
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            ArgCommands::Tun(a) => Self {
                tunnel: TunnelInstruction::Tun(a.gateway, a.local_addr, a.map_addr),
                transport: TransportInstruction::determine(
                    a.direct,
                    a.relay,
                    a.cryptography.clone(),
                    a.agent_name.clone(),
                    false,
                ),
                manage: if a.direct || a.relay == a.direct {
                    ManageInstruction::default_p2p(a.agent_name.clone())
                } else {
                    ManageInstruction::AgentCheck(a.agent_name.clone())
                },
            },
        }
    }
}
