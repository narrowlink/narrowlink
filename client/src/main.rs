mod args;
mod config;
mod error;
mod input_stream;
use args::{ArgCommands, Args};
use config::Config;
use error::ClientError;
use futures_util::{FutureExt, Stream, StreamExt};
use narrowlink_network::{
    event::{NarrowEvent, NarrowEventRequest},
    ws::WsConnection,
};
use narrowlink_types::{client::Peer2PeerInstruction, generic::AgentInfo, ServiceType};
use std::{
    collections::HashMap,
    env,
    io::{self, IsTerminal},
    net::{SocketAddr, TcpListener},
    sync::Arc,
    task::{Context, Poll}, process,
};
use tokio::select;
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
    let transport = TransportFactory::new(instruction.transport);
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
                        control.connect().await?; // todo: reconnect
                        // if let Some(manage) = manage.take() {
                            control.manage(&instruction.manage);
                        //     break;
                        // }else{
                        //     tunnel.start();
                        // }

                    }
                }
            }
            msg = tunnel.next() => {

            }
        }
    }

    Ok(())
}

struct TunnelFactory {
    i: TunnelInstruction,
    listener: Option<TunnelListener>,
}

pub enum TunnelListener {
    Proxy(TcpListener),
}

impl TunnelFactory {
    fn new(i: TunnelInstruction) -> Self {
        Self { i, listener: None }
    }
    fn start(&self) {}
    fn stop(&self) {}
}

impl Stream for TunnelFactory {
    type Item = Result<(), ClientError>;
    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        Poll::Pending
    }
}

struct TransportFactory {
    i: TransportInstruction,
}

impl TransportFactory {
    fn new(i: TransportInstruction) -> Self {
        Self { i }
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
    async fn connect(&mut self) -> Result<(), ClientError> {
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
            session_id,
            request,
            agents,
            msg_receiver,
            task,
        });

        Ok(())
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
    None,
}

pub enum TransportInstruction {
    None,
}

pub enum ManageInstruction {
    AgentList(bool),
    None,
}

impl From<&ArgCommands> for Instruction {
    fn from(cmd: &ArgCommands) -> Self {
        match cmd {
            ArgCommands::Forward(_) => Self {
                tunnel: TunnelInstruction::None,
                transport: TransportInstruction::None,
                manage: ManageInstruction::None,
            },
            ArgCommands::List(ListArgs { verbose }) => Self {
                tunnel: TunnelInstruction::None,
                transport: TransportInstruction::None,
                manage: ManageInstruction::AgentList(*verbose),
            },
            ArgCommands::Proxy(_) => Self {
                tunnel: TunnelInstruction::None,
                transport: TransportInstruction::None,
                manage: ManageInstruction::None,
            },
            ArgCommands::Connect(_) => Self {
                tunnel: TunnelInstruction::None,
                transport: TransportInstruction::None,
                manage: ManageInstruction::None,
            },
            ArgCommands::Tun(_) => Self {
                tunnel: TunnelInstruction::None,
                transport: TransportInstruction::None,
                manage: ManageInstruction::None,
            },
        }
    }
}
