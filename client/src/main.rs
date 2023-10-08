mod args;
mod config;
mod error;
mod input_stream;
use args::{ArgCommands, Args};
use config::Config;
use error::ClientError;
use futures_util::{FutureExt, Stream, StreamExt};
use narrowlink_network::{
    async_forward,
    event::{NarrowEvent, NarrowEventRequest},
    ws::{WsConnection, WsConnectionBinary},
    AsyncSocket,
};
use narrowlink_types::{
    client::{Peer2PeerInstruction, Peer2PeerRequest},
    generic::{AgentInfo, Connect},
    ServiceType,
};
use proxy_stream::ProxyStream;
use rand::Rng;
use std::{
    collections::HashMap,
    env,
    io::{self, IsTerminal},
    net::{IpAddr, SocketAddr},
    process,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::{net::TcpListener, select, sync::Notify};
use tracing::{debug, error, info, span, trace, warn, Level};
use uuid::Uuid;

use narrowlink_types::{
    client::DataOutBound as ClientDataOutBound, client::EventInBound as ClientEventInBound,
    client::EventOutBound as ClientEventOutBound, client::EventRequest as ClientEventRequest,
    generic, GetResponse,
};
use tracing_subscriber::{
    filter::{LevelFilter, Targets},
    fmt::writer::MakeWriterExt,
    prelude::__tracing_subscriber_SubscriberExt,
    util::SubscriberInitExt,
    Layer,
};

use crate::args::ListArgs;

pub fn main() -> Result<(), ClientError> {
    let args = Args::parse(env::args())?;

    let (stdout, _stdout_guard) = if 1 == 1 {
        tracing_appender::non_blocking(io::stderr())
    } else {
        tracing_appender::non_blocking(io::stdout())
    };
    let (stderr, _stderr_guard) = tracing_appender::non_blocking(io::stderr());

    let cmd = tracing_subscriber::fmt::layer()
        .with_ansi(
            if 1 == 1 {
                true
            } else {
                io::stdout().is_terminal()
            } && io::stderr().is_terminal(),
        )
        .compact()
        // .with_target(false)
        .with_writer(
            stdout
                .with_min_level(Level::WARN)
                .and(stderr.with_max_level(Level::ERROR)),
        )
        .with_filter(
            env::var("RUST_LOG")
                .ok()
                .and_then(|e| e.parse::<Targets>().ok())
                .unwrap_or(Targets::new().with_default(LevelFilter::INFO)),
        );

    // let debug_file =
    //     tracing_appender::rolling::minutely("log", "debug").with_min_level(Level::DEBUG);
    // let log_file =
    //     tracing_appender::rolling::daily("log", "info").with_max_level(Level::INFO);

    // let file = tracing_subscriber::fmt::layer()
    //     .with_writer(log_file)
    //     .json();

    tracing_subscriber::registry()
        .with(cmd)
        // .with(file)
        .init();

    match start(args) {
        Ok(_) => (),
        Err(e) => error!("Error: {}", e),
    }
    Ok(())
}

#[tokio::main]
async fn start(mut args: Args) -> Result<(), ClientError> {
    let conf = config::Config::load(args.take_conf_path())?;
    let mut control = ControlFactory::new(conf)?;
    let instruction = Instruction::from(&args.arg_commands);
    let mut transport = TransportFactory::new(instruction.transport);
    let mut tunnel = TunnelFactory::new(instruction.tunnel);

    loop {
        tokio::select! {
            msg = control.accept_msg() => {
                match msg {
                    Some(ControlMsg::ConnectionError(connection_id, msg)) => {
                        debug!("Connection error: {}:{}", connection_id, msg);
                    }
                    Some(ControlMsg::Peer2Peer(p2p)) => {
                        debug!("Peer2Peer: {:?}", p2p);
                    }
                    None => {
                        tunnel.stop();
                        let relay_info = control.connect().await?; // todo: reconnect
                        transport.set_relay(relay_info);
                        // if let Some(manage) = manage.take() {
                            control.manage(&instruction.manage);
                        //     break;
                        // }else{
                            tunnel.start().await;
                        // }

                    }
                }
            }
            msg = tunnel.accept() => {
                let x = msg.unwrap();
                transport.connect(x.0,x.1).await;
                // dbg!(msg.unwrap().1);

            }
        }
    }

    Ok(())
}

struct TunnelFactory {
    i: TunnelInstruction,
    listener: Option<TunnelListener>,
    wait: Option<Arc<Notify>>,
}

pub enum TunnelListener {
    Proxy(TcpListener),
}

impl TunnelFactory {
    fn new(i: TunnelInstruction) -> Self {
        Self {
            i,
            listener: None,
            wait: Some(Arc::new(Notify::new())),
        }
    }
    async fn start(&mut self) {
        match &self.i {
            TunnelInstruction::Connect(udp, (dst_addr, dst_port)) => todo!(),
            TunnelInstruction::Forward(udp, local, endpoint) => todo!(),
            TunnelInstruction::Proxy(endpoint) => {
                let listener = TcpListener::bind(endpoint).await.unwrap();
                self.listener = Some(TunnelListener::Proxy(listener));
            }
            TunnelInstruction::Tun(default_gateway, addr, map) => todo!(),
            TunnelInstruction::None => todo!(),
        };
        self.wait.take().unwrap().notify_waiters();
    }
    fn stop(&mut self) {
        self.wait = Some(Arc::new(Notify::new()));
    }
    async fn socks_accept(
        listener: &mut TcpListener,
    ) -> Result<(impl AsyncSocket, generic::Connect), ClientError> {
        let proxy_stream = ProxyStream::new(proxy_stream::ProxyType::SOCKS5);
        let (socket, _local_addr) = listener.accept().await?;
        let interrupted_stream = match proxy_stream.accept(socket).await {
            Ok(s) => s,
            Err(_) => todo!(),
        };
        let addr: (String, u16) = interrupted_stream.addr().into();
        let protocol = if interrupted_stream.command() == proxy_stream::Command::UdpAssociate {
            generic::Protocol::UDP
        } else {
            generic::Protocol::TCP
        };
        let s = interrupted_stream.connect().await.unwrap();
        Ok((
            s,
            generic::Connect {
                host: addr.0,
                port: addr.1,
                protocol,
                cryptography: None,
                sign: None,
            },
        ))
    }
    async fn accept(&mut self) -> Result<(impl AsyncSocket, generic::Connect), ClientError> {
        if let Some(wait) = self.wait.as_ref() {
            wait.notified().await;
        };
        match &mut self.listener {
            Some(TunnelListener::Proxy(l)) => {
                let (socket, _local_addr) = l.accept().await.unwrap();
                let interrupted_stream = match ProxyStream::new(proxy_stream::ProxyType::SOCKS5)
                    .accept(socket)
                    .await
                {
                    Ok(s) => s,
                    Err(_) => todo!(),
                };
                let addr: (String, u16) = interrupted_stream.addr().into();
                let protocol =
                    if interrupted_stream.command() == proxy_stream::Command::UdpAssociate {
                        generic::Protocol::UDP
                    } else {
                        generic::Protocol::TCP
                    };
                let s = interrupted_stream.connect().await.unwrap();
                Ok((
                    s,
                    generic::Connect {
                        host: addr.0,
                        port: addr.1,
                        protocol,
                        cryptography: None,
                        sign: None,
                    },
                ))
            }
            None => Err(ClientError::UnableToConnect),
        }
    }
}

struct RelayInfo {
    protocol: ServiceType,
    gateway: String,
    token: String,
    session_id: String,
}

struct TransportFactory {
    i: TransportInstruction,
    direct: Option<()>,
    relay: Option<RelayInfo>,
}

impl TransportFactory {
    fn new(i: TransportInstruction) -> Self {
        Self {
            i,
            direct: None,
            relay: None,
        }
    }
    fn set_relay(&mut self, relays: RelayInfo) {
        self.relay = Some(relays);
    }
    fn unset_relay(&mut self) {
        self.relay = None;
    }
    async fn connect(
        &mut self,
        socket: impl AsyncSocket,
        connect: Connect,
    ) -> Result<(), ClientError> {
        let (connection, connection_id, e2ee) = match &self.i {
            TransportInstruction::Direct(e2ee, agent_name) => {
                todo!()
            }
            TransportInstruction::Mixed(e2ee, agent_name)
            | TransportInstruction::Relay(e2ee, agent_name) => {
                let Some(relay) = self.relay.as_ref() else {
                    todo!();
                    return Err(ClientError::UnableToConnect); // todo: change
                };
                let Ok(cmd) = serde_json::to_string(&ClientDataOutBound::Connect(
                    agent_name.clone(),
                    connect.clone(),
                )) else {
                    error!("Unable to serialize connect command"); // unreachable
                    return Err(ClientError::UnableToConnect); // todo: change
                };
                let connection = match WsConnectionBinary::new(
                    &relay.gateway,
                    HashMap::from([
                        ("NL-TOKEN", relay.token.to_owned()),
                        ("NL-SESSION", relay.session_id.to_owned()),
                        ("NL-COMMAND", cmd),
                    ]),
                    &relay.protocol,
                )
                .await
                {
                    Ok(c) => c,
                    Err(e) => {
                        dbg!(e.to_string());
                        todo!()
                    }
                };
                let connection_id = connection
                    .get_header("NL-CONNECTION")
                    .map(|c| c.to_string());
                (connection, connection_id, e2ee)
            }
            TransportInstruction::Mixed(e2ee, agent_name) => {
                todo!()
            }
            TransportInstruction::None => todo!(),
        };
        async_forward(socket, connection).await.unwrap();
        Ok(())
    }
}

struct ControlFactory {
    gateway: Arc<String>,
    token: Arc<String>,
    acl: Option<Arc<String>>,
    protocol: ServiceType,
    agents: Vec<u8>,
    control: Option<ControlInfo>,
}

impl ControlFactory {
    fn new(conf: Config) -> Result<Self, ClientError> {
        let Some(config::Endpoint::SelfHosted(conf)) = conf.endpoints.first() else {
            return Err(ClientError::InvalidConfig);
        };
        Ok(Self {
            gateway: Arc::new(conf.gateway.clone()),
            token: Arc::new(conf.token.clone()),
            acl: if conf.acl.is_empty() {
                None
            } else {
                serde_json::to_string(&conf.acl).ok().map(Arc::new)
            },
            protocol: conf.protocol.clone(),
            agents: Vec::new(),
            control: None,
        })
    }
    // fn get_relay_info(&self) -> RelayInfo {
    //     RelayInfo {
    //         protocol: self.protocol.clone(),
    //     }
    // }
    async fn connect(&mut self) -> Result<RelayInfo, ClientError> {
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
        let connection = WsConnection::new(&self.gateway, headers, &self.protocol).await?;

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
                    continue;
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
                ClientEventRequest::ListOfAgents(true), // todo: remove verbose
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
            local_addr,
            address,
            session_id: session_id.clone(),
            request,
            agents,
            msg_receiver,
            task,
        });

        Ok(RelayInfo {
            protocol: self.protocol.clone(),
            gateway: self.gateway.to_string(),
            token: self.token.to_string(),
            session_id,
        })
    }
    pub async fn accept_msg(&mut self) -> Option<ControlMsg> {
        if let Some(control) = self.control.as_mut() {
            select! {
                msg = control.msg_receiver.recv() => {
                    return msg;
                }
                _ = &mut control.task => {
                    return None;
                }
            }
        }
        None
    }

    fn manage(&self, manage: &ManageInstruction) {
        match manage {
            ManageInstruction::AgentList(verbose) => {
                trace!("List of agents");
                let Some(agents) = self.control.as_ref().map(|c| c.agents.clone()) else {
                    println!("Agent not found");
                    return;
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
                    if let Some(system_info) = &agent.system_info {
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
                // req.shutdown().await;
                // break;
            }
            ManageInstruction::Peer2Peer(p2p) => {
                // trace!("Peer2Peer");
                // let Some(req) = self.control.as_ref().map(|c| c.request.clone()) else {
                //     println!("Agent not found");
                //     return;
                // };
                // req.request(ClientEventOutBound::Request(
                //     0,
                //     ClientEventRequest::Peer2Peer(p2p.clone()),
                // ))
                // .await;
            }
            ManageInstruction::None => (),
        }
    }
}

pub enum ControlMsg {
    ConnectionError(Uuid, String),
    Peer2Peer(Peer2PeerInstruction),
}

pub struct ControlInfo {
    local_addr: SocketAddr,
    address: SocketAddr,
    session_id: String,
    request: NarrowEventRequest<ClientEventOutBound, ClientEventInBound>,
    agents: Vec<AgentInfo>,
    msg_receiver: tokio::sync::mpsc::UnboundedReceiver<ControlMsg>,
    task: tokio::task::JoinHandle<()>,
}

pub struct Instruction {
    tunnel: TunnelInstruction,
    transport: TransportInstruction,
    manage: ManageInstruction,
}
pub enum TunnelInstruction {
    Connect(bool, (String, u16)),             // udp, endpoint
    Forward(bool, SocketAddr, (String, u16)), // udp, local, endpoint
    Proxy(SocketAddr),                        // endpoint
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    Tun(bool, IpAddr, Option<IpAddr>), // default_gateway, addr, map
    None,
}

impl TunnelInstruction {
    fn is_proxy(&self) -> bool {
        match self {
            TunnelInstruction::Proxy(_) => true,
            _ => false,
        }
    }
}
pub enum TransportInstruction {
    Direct(Option<String>, String),
    Relay(Option<String>, String),
    Mixed(Option<String>, String),
    None,
}

impl TransportInstruction {
    fn determine(direct: bool, relay: bool, e2ee: Option<String>, agent_name: String) -> Self {
        match (direct, relay) {
            (false, false) | (true, true) => Self::Mixed(e2ee, agent_name),
            (true, false) => Self::Direct(e2ee, agent_name),
            (false, true) => Self::Relay(e2ee, agent_name),
        }
    }
}

pub enum ManageInstruction {
    Peer2Peer(Peer2PeerRequest),
    AgentList(bool),
    None,
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
                tunnel: TunnelInstruction::Forward(
                    a.udp,
                    a.local_addr.clone(),
                    a.remote_addr.clone(),
                ),
                transport: TransportInstruction::determine(
                    a.direct,
                    a.relay,
                    a.cryptography.clone(),
                    a.agent_name.clone(),
                ),
                manage: if a.direct {
                    ManageInstruction::default_p2p(a.agent_name.clone())
                } else {
                    ManageInstruction::None
                },
            },
            ArgCommands::List(ListArgs { verbose }) => Self {
                tunnel: TunnelInstruction::None,
                transport: TransportInstruction::None,
                manage: ManageInstruction::AgentList(*verbose),
            },
            ArgCommands::Proxy(a) => Self {
                tunnel: TunnelInstruction::Proxy(a.local_addr.clone()),
                transport: TransportInstruction::determine(
                    a.direct,
                    a.relay,
                    a.cryptography.clone(),
                    a.agent_name.clone(),
                ),
                manage: if a.direct {
                    ManageInstruction::default_p2p(a.agent_name.clone())
                } else {
                    ManageInstruction::None
                },
            },
            ArgCommands::Connect(a) => Self {
                tunnel: TunnelInstruction::Connect(a.udp, a.remote_addr.clone()),
                transport: TransportInstruction::determine(
                    a.direct,
                    a.relay,
                    a.cryptography.clone(),
                    a.agent_name.clone(),
                ),
                manage: if a.direct {
                    ManageInstruction::default_p2p(a.agent_name.clone())
                } else {
                    ManageInstruction::None
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
                ),
                manage: if a.direct {
                    ManageInstruction::default_p2p(a.agent_name.clone())
                } else {
                    ManageInstruction::None
                },
            },
        }
    }
}
