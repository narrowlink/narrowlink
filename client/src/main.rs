mod args;
mod config;
mod control;
mod error;
mod input_stream;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod tun;
use args::{ArgCommands, Args};
use config::Config;
use either::Either;
use error::ClientError;
use futures_util::{
    future::{pending, Ready},
    stream::{self, Once},
    StreamExt,
};
use input_stream::InputStream;
use narrowlink_network::{
    async_forward,
    event::{NarrowEvent, NarrowEventRequest},
    p2p::QuicStream,
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
use sha3::{Digest, Sha3_256};
use udp_stream::UdpListener;

use std::{
    collections::{HashMap, HashSet},
    env,
    io::{self, IsTerminal},
    net::{IpAddr, SocketAddr},
    process,
    sync::{
        atomic::{AtomicU8, Ordering},
        Arc,
    },
};
use tokio::{
    net::TcpListener,
    select,
    sync::{Notify, RwLock},
};
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

#[cfg(any(target_os = "linux", target_os = "macos"))]
use tun::{RouteCommand, TunListener, TunStream};

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
                        let t = transport.clone();
                        let direct_tunnel_status = control.direct_tunnel_status.clone();
                        tunnel.add_host(p2p.peer_ip); // todo del_host
                        tokio::spawn(async move{
                            t.create_direct(p2p,direct_tunnel_status).await.unwrap();
                        });

                    }
                    None => {
                        tunnel.stop();
                        let relay_info = control.connect().await?; // todo: reconnect
                        if let Some(addr) = control.control.as_ref().map(|c| c.address.ip()) {
                            tunnel.add_host(addr);
                        }
                        transport.set_relay(relay_info);
                        // if let Some(manage) = manage.take() {
                            control.manage(&instruction.manage).await;
                        //     break;
                        // }else{
                            tunnel.start().await;
                        // }

                    }
                }
            }
            msg = tunnel.accept() => {
                let t = transport.clone();
                tokio::spawn(async move{
                    let x = msg.unwrap();
                    t.connect(x.0,x.1).await;
                });
                // dbg!(msg.unwrap().1);

            }
        }
    }

    Ok(())
}

pub enum DirectTunnelStatus {
    Uninitialized = 0x0,
    Success = 0x1,
    Pending = 0x2,
    Closed = 0x3,
    Failed = 0xff,
}

struct TunnelFactory {
    i: TunnelInstruction,
    listener: Option<TunnelListener>,
    wait: Option<Arc<Notify>>,
    hosts: HashSet<IpAddr>,
}

pub enum TunnelListener {
    Connect(Once<Ready<InputStream>>, bool, (String, u16)),
    Forward(Either<TcpListener, UdpListener>, (String, u16)),
    Proxy(TcpListener),
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    Tun(TunListener),
}

impl TunnelFactory {
    fn new(i: TunnelInstruction) -> Self {
        Self {
            i,
            listener: None,
            wait: Some(Arc::new(Notify::new())),
            hosts: HashSet::new(),
        }
    }
    async fn start(&mut self) -> Result<(), ClientError> {
        match &self.i {
            TunnelInstruction::Connect(udp, (dst_addr, dst_port)) => {
                self.listener = Some(TunnelListener::Connect(
                    stream::once(futures_util::future::ready(InputStream::default())),
                    *udp,
                    (dst_addr.clone(), dst_port.clone()),
                ));
            }
            TunnelInstruction::Forward(udp, local, endpoint) => {
                let listener = if *udp {
                    either::Right(UdpListener::bind(local.clone()).await?)
                } else {
                    either::Left(TcpListener::bind(local).await?)
                };
                self.listener = Some(TunnelListener::Forward(listener, endpoint.clone()));
            }
            TunnelInstruction::Proxy(endpoint) => {
                let listener = TcpListener::bind(endpoint).await?;
                self.listener = Some(TunnelListener::Proxy(listener));
            }
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            TunnelInstruction::Tun(default_gateway, addr, map) => {
                let tun = TunListener::new(*addr, *map).await?;
                if let Some(s) = tun.route_sender() {
                    for ip in self.hosts.iter() {
                        s.send(RouteCommand::Add(*ip)).unwrap();
                    }
                }
                tun.my_routes(*default_gateway);
                self.listener = Some(TunnelListener::Tun(tun));
            }
            TunnelInstruction::None => Err(ClientError::Unexpected(0))?,
        };
        if let Some(wait) = self.wait.take() {
            wait.notify_waiters();
        }
        Ok(())
    }
    fn stop(&mut self) {
        self.wait = Some(Arc::new(Notify::new()));
        self.listener.take();
    }
    async fn accept(&mut self) -> Result<(Box<dyn AsyncSocket>, generic::Connect), ClientError> {
        if let Some(wait) = self.wait.as_ref() {
            wait.notified().await;
        };
        match &mut self.listener {
            Some(TunnelListener::Connect(stream, udp, (dst_addr, dst_port))) => {
                let s = match stream.next().await {
                    Some(s) => s,
                    None => pending().await,
                };
                Ok((
                    Box::new(s),
                    generic::Connect {
                        host: dst_addr.clone(),
                        port: dst_port.clone(),
                        protocol: if *udp {
                            generic::Protocol::UDP
                        } else {
                            generic::Protocol::TCP
                        },
                        cryptography: None,
                        sign: None,
                    },
                ))
            }
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
                    Box::new(s),
                    generic::Connect {
                        host: addr.0,
                        port: addr.1,
                        protocol,
                        cryptography: None,
                        sign: None,
                    },
                ))
            }
            Some(TunnelListener::Forward(listener, end_point)) => {
                let (socket, protocol): (Box<dyn AsyncSocket>, generic::Protocol) = match listener {
                    either::Left(tcp_listener) => {
                        let (socket, _local_addr) = tcp_listener.accept().await?;
                        (Box::new(socket), generic::Protocol::UDP)
                    }
                    either::Right(udp_listener) => {
                        let (socket, _local_addr) = udp_listener.accept().await?;
                        (Box::new(socket), generic::Protocol::TCP)
                    }
                };
                let addr: (String, u16) = end_point.clone();
                Ok((
                    Box::new(socket),
                    generic::Connect {
                        host: addr.0,
                        port: addr.1,
                        protocol,
                        cryptography: None,
                        sign: None,
                    },
                ))
            }
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            Some(TunnelListener::Tun(tun_listener)) => {
                let (stream, addr) = tun_listener.accept().await.unwrap();
                let (stream, udp): (Box<dyn AsyncSocket>, bool) = match stream {
                    TunStream::Tcp(tcp) => (Box::new(tcp), false),
                    TunStream::Udp(udp) => (Box::new(udp), true),
                };
                Ok((
                    stream,
                    generic::Connect {
                        host: addr.ip().to_string(),
                        port: addr.port(),
                        protocol: if udp {
                            generic::Protocol::UDP
                        } else {
                            generic::Protocol::TCP
                        },
                        cryptography: None,
                        sign: None,
                    },
                ))
            }
            None => Err(ClientError::UnableToConnect),
        }
    }
    fn add_host(&mut self, ip: IpAddr) {
        self.hosts.insert(ip);
        if let Some(TunnelListener::Tun(tun)) = self.listener.as_ref() {
            if let Some(s) = tun.route_sender() {
                let _ = s.send(RouteCommand::Add(ip));
            };
        }
    }
    fn del_host(&mut self, ip: IpAddr) {
        self.hosts.remove(&ip);
        if let Some(TunnelListener::Tun(tun)) = self.listener.as_ref() {
            if let Some(s) = tun.route_sender() {
                let _ = s.send(RouteCommand::Del(ip));
            };
        }
    }
}

#[derive(Clone)]
struct RelayInfo {
    protocol: ServiceType,
    gateway: String,
    token: String,
    session_id: String,
}

#[derive(Clone)]
struct TransportFactory {
    i: TransportInstruction,
    direct: Arc<RwLock<Option<QuicStream>>>,
    notify_direct: Arc<RwLock<Option<Arc<Notify>>>>,
    relay: Option<RelayInfo>,
}

// impl From<&ArgCommands> for Instruction {

// }
impl TransportFactory {
    fn new(i: TransportInstruction) -> Self {
        Self {
            i,
            direct: Arc::new(RwLock::new(None)),
            notify_direct: Arc::new(RwLock::new(Some(Arc::new(Notify::new())))),
            relay: None,
        }
    }
    fn set_relay(&mut self, relays: RelayInfo) {
        self.relay = Some(relays);
    }
    fn unset_relay(&mut self) {
        self.relay = None;
    }
    async fn create_direct(
        &self,
        direct_instruction: Peer2PeerInstruction,
        direct_tunnel_status: Arc<AtomicU8>,
    ) -> Result<(), ClientError> {
        direct_tunnel_status.store(DirectTunnelStatus::Pending as u8, Ordering::Relaxed);
        info!("Trying to create a direct (peer-to-peer) channel");
        let res = 'res: {
            let (socket, peer) = match narrowlink_network::p2p::udp_punched_socket(
                (&direct_instruction).into(),
                &Sha3_256::digest(&direct_instruction.cert)[0..6],
                true,
                false,
            )
            .await
            {
                Ok((socket, peer)) => (socket, peer),
                Err(e) => {
                    break 'res (Err(e), DirectTunnelStatus::Failed);
                }
            };
            let quic_stream =
                match QuicStream::new_client(peer, socket, direct_instruction.cert).await {
                    Ok(qs) => qs,
                    Err(e) => {
                        break 'res (Err(e), DirectTunnelStatus::Closed);
                    }
                };
            info!("The direct channel has just been established");
            self.direct.write().await.replace(quic_stream);
            (Ok(()), DirectTunnelStatus::Success)
        };

        if let Some(notify) = self.notify_direct.write().await.take() {
            notify.notify_waiters();
        }
        direct_tunnel_status.store(res.1 as u8, Ordering::Relaxed);
        Ok(res.0?)
    }
    async fn connect_direct(
        &self,
        _agent_name: &str,
        connect: &Connect,
        wait_for_tunnel: bool,
    ) -> Result<(impl AsyncSocket, Option<String>), ClientError> {
        let notify = self.notify_direct.read().await.clone();
        if let Some(notify) = notify.filter(|_| wait_for_tunnel) {
            info!("Waiting to create a direct (peer-to-peer) channel");
            notify.notified().await;
        }
        let qs = self.direct.read().await;
        let Some(direct) = qs.as_ref() else {
            return Err(ClientError::DirectChannelNotAvailable);
        };

        let Ok(mut quic_socket) = direct.open_bi().await else {
            self.direct.write().await.take();
            self.notify_direct
                .write()
                .await
                .replace(Arc::new(Notify::new()));
            return Err(ClientError::UnableToOpenQuicBiStream);
        };

        narrowlink_network::p2p::Request::from(connect)
            .write(&mut quic_socket)
            .await
            .map_err(|_| ClientError::UnableToCommunicateWithQuicBiStream)?;
        match narrowlink_network::p2p::Response::read(&mut quic_socket)
            .await
            .map_err(|e| {
                if matches!(
                    e,
                    narrowlink_network::error::NetworkError::P2PInvalidCommand
                ) {
                    ClientError::InvalidDirectResponse
                } else {
                    ClientError::UnableToCommunicateWithQuicBiStream
                }
            })? {
            narrowlink_network::p2p::Response::Success => {}
            narrowlink_network::p2p::Response::InvalidRequest => todo!(),
            narrowlink_network::p2p::Response::AccessDenied => todo!(),
            narrowlink_network::p2p::Response::UnableToResolve => todo!(),
            narrowlink_network::p2p::Response::Failed => todo!(),
        }

        Ok((quic_socket, None))
    }
    async fn connect_relay(
        &self,
        agent_name: &str,
        connect: &Connect,
    ) -> Result<(impl AsyncSocket, Option<String>), ClientError> {
        let Some(relay) = self.relay.as_ref() else {
            return Err(ClientError::RelayChannelNotAvailable);
        };
        let cmd = serde_json::to_string(&ClientDataOutBound::Connect(
            agent_name.to_owned(),
            connect.clone(),
        ))
        .map_err(|_| ClientError::Unexpected(0))?;
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
        Ok((connection, connection_id))
    }

    async fn connect(
        &self,
        socket: impl AsyncSocket,
        connect: Connect,
    ) -> Result<Option<String>, ClientError> {
        let (connection, connection_id, e2ee): (
            Box<dyn AsyncSocket>,
            Option<String>,
            &Option<String>,
        ) = match &self.i {
            TransportInstruction::Direct(e2ee, agent_name) => {
                let (connection, connection_id) =
                    self.connect_direct(agent_name, &connect, true).await?;
                (Box::new(connection), connection_id, e2ee)
            }
            TransportInstruction::Relay(e2ee, agent_name) => {
                let (connection, connection_id) = self.connect_relay(agent_name, &connect).await?;
                (Box::new(connection), connection_id, e2ee)
            }
            TransportInstruction::Mixed(e2ee, agent_name, wait) => {
                match self.connect_direct(agent_name, &connect, *wait).await {
                    Ok((connection, connection_id)) => (Box::new(connection), connection_id, e2ee),
                    Err(_) => {
                        let (connection, connection_id) =
                            self.connect_relay(agent_name, &connect).await?;
                        (Box::new(connection), connection_id, e2ee)
                    }
                }
            }
            TransportInstruction::None => return Err(ClientError::Unexpected(0)),
        };

        Ok(async_forward(socket, connection)
            .await
            .map(|_| connection_id)?)
    }
}

struct ControlFactory {
    gateway: Arc<String>,
    token: Arc<String>,
    acl: Option<Arc<String>>,
    protocol: ServiceType,
    agents: Vec<u8>,
    control: Option<ControlInfo>,
    pub direct_tunnel_status: Arc<AtomicU8>,
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
            direct_tunnel_status: Arc::new(AtomicU8::new(DirectTunnelStatus::Uninitialized as u8)),
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

    async fn manage(&self, manage: &ManageInstruction) {
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
                if !self.direct_tunnel_status.load(Ordering::Relaxed)
                    == (DirectTunnelStatus::Uninitialized as u8)
                {
                    // debug!("Direct tunnel already initialized");
                    return;
                };
                let Some(control) = self.control.as_ref() else {
                    todo!()
                };
                control
                    .request
                    .request(ClientEventOutBound::Request(
                        0,
                        ClientEventRequest::Peer2Peer(p2p.clone()),
                    ))
                    .await
                    .unwrap();
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

#[derive(Clone)]
pub enum TransportInstruction {
    Direct(Option<String>, String),
    Relay(Option<String>, String),
    Mixed(Option<String>, String, bool),
    None,
}

impl TransportInstruction {
    fn determine(
        direct: bool,
        relay: bool,
        e2ee: Option<String>,
        agent_name: String,
        wait_for_direct_tunnel: bool,
    ) -> Self {
        match (direct, relay) {
            (false, false) | (true, true) => Self::Mixed(e2ee, agent_name, wait_for_direct_tunnel),
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
                    false,
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
                    false,
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
                    true,
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
                    false,
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
