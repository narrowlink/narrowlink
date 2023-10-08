use core::{
    pin::Pin,
    task::{Context, Poll},
};
use std::{
    collections::HashMap,
    env,
    io::{self, IsTerminal},
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    process,
    sync::{
        atomic::{AtomicBool, AtomicU8, Ordering},
        Arc,
    },
    time::Duration,
};

mod args;
mod error;
use args::{ArgCommands, Args};
mod config;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod tun;
use error::ClientError;
use futures_util::stream::StreamExt;
use hmac::Mac;
use narrowlink_network::{
    async_forward,
    error::NetworkError,
    event::{NarrowEvent, NarrowEventRequest},
    p2p::QuicStream,
    ws::{WsConnection, WsConnectionBinary},
    AsyncSocket, AsyncSocketCrypt,
};

use narrowlink_types::{
    client::DataOutBound as ClientDataOutBound, client::EventInBound as ClientEventInBound,
    client::EventOutBound as ClientEventOutBound, client::EventRequest as ClientEventRequest,
    generic, GetResponse,
};

use proxy_stream::ProxyStream;
use rand::Rng;
use sha3::{Digest, Sha3_256};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpListener,
    sync::{Mutex, RwLock},
    time,
};
use tracing::{debug, error, info, span, trace, warn, Level};
use tracing_subscriber::{
    filter::{LevelFilter, Targets},
    fmt::writer::MakeWriterExt,
    prelude::__tracing_subscriber_SubscriberExt,
    util::SubscriberInitExt,
    Layer,
};
use udp_stream::UdpListener;

#[cfg(any(target_os = "linux", target_os = "macos"))]
use tun::{RouteCommand, TunListener, TunStream};

pub enum P2PStatus {
    Uninitialized = 0x0,
    Success = 0x1,
    Pending = 0x2,
    Closed = 0x3,
    Failed = 0xff,
}

pub enum Listener {
    None,
    Tcp(TcpListener),
    Udp(UdpListener),
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    Tun(TunListener),
}

#[tokio::main]
async fn main() -> Result<(), ClientError> {
    let args = Args::parse(env::args())?;
    let direct = args.arg_commands.direct();
    let relay = args.arg_commands.relay();
    let is_connect = matches!(args.arg_commands.as_ref(), ArgCommands::Connect(_));
    let (stdout, _stdout_guard) = if is_connect {
        tracing_appender::non_blocking(io::stderr())
    } else {
        tracing_appender::non_blocking(io::stdout())
    };
    let (stderr, _stderr_guard) = tracing_appender::non_blocking(io::stderr());

    let cmd = tracing_subscriber::fmt::layer()
        .with_ansi(
            if is_connect {
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

    let span = span!(Level::TRACE, "main", args= ?args);

    let conf = match config::Config::load(args.config_path)
        .and_then(|mut conf| match conf.endpoints.pop() {
            Some(config::Endpoint::SelfHosted(conf)) => Ok(conf),
            _ => Err(ClientError::InvalidConfig),
        })
        .map(Arc::new)
    {
        Ok(conf) => conf,
        Err(e) => {
            error!("Unable to load config: {}", e);
            return Ok(());
        }
    };

    span.in_scope(|| trace!("config successfully read"));

    let mut session: Option<(
        String,
        NarrowEventRequest<
            narrowlink_types::client::EventOutBound,
            narrowlink_types::client::EventInBound,
        >,
        tokio::task::JoinHandle<()>,
    )> = None;
    let mut socket_listener = Listener::None;
    let arg_commands = args.arg_commands.clone();
    let mut p2p = false;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let mut route_sender = None;

    match arg_commands.as_ref() {
        ArgCommands::List(_) => {}
        ArgCommands::Connect(connect_args) => {
            p2p = connect_args.direct;
        }
        ArgCommands::Forward(forward_args) => {
            p2p = forward_args.direct;
            let local_addr = SocketAddr::new(
                forward_args
                    .local_addr
                    .0
                    .parse::<IpAddr>()
                    .map_err(|_| ClientError::InvalidLocalAddress)?,
                forward_args.local_addr.1,
            );
            let (listener, _local_addr) = if forward_args.udp {
                let (local_addr, listener) = UdpListener::bind(local_addr)
                    .await
                    .and_then(|listener| Ok((listener.local_addr()?, listener)))
                    .map_err(|_| ClientError::UnableToBind)?;
                (Listener::Udp(listener), local_addr)
            } else {
                let (local_addr, listener) = TcpListener::bind(local_addr)
                    .await
                    .and_then(|listener| Ok((listener.local_addr()?, listener)))
                    .map_err(|_| ClientError::UnableToBind)?;
                (Listener::Tcp(listener), local_addr)
            };

            socket_listener = listener;
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        ArgCommands::Tun(tunnel_args) => {
            p2p = tunnel_args.direct;
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            {
                let tun = TunListener::new(tunnel_args.local_addr, tunnel_args.map_addr).await?;
                route_sender = tun.route_sender();
                socket_listener = Listener::Tun(tun);
            }
            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
            {
                socket_listener = Listener::None
            }
        }
        ArgCommands::Proxy(proxy_args) => {
            p2p = proxy_args.direct;
            let local_addr = SocketAddr::new(
                proxy_args
                    .local_addr
                    .0
                    .parse::<IpAddr>()
                    .map_err(|_| ClientError::InvalidLocalAddress)?,
                proxy_args.local_addr.1,
            );
            socket_listener = Listener::Tcp(
                TcpListener::bind(local_addr)
                    .await
                    .map_err(|_| ClientError::UnableToBind)?,
            );
        }
    };
    // span.in_scope(|| {
    //     trace!(
    //         "Listen address: {:?}",
    //         socket_listener.as_ref().map(|l| match l {
    //             Either::Left(l) => l.local_addr(),
    //             Either::Right(l) => l.local_addr(),
    //         })
    //     )
    // });

    let mut agents = Vec::new();
    let list_of_agents_refresh_required = Arc::new(AtomicBool::new(true));
    let mut sleep_time = 0;
    let arg_commands = args.arg_commands.clone();
    let connections = Arc::new(Mutex::new(HashMap::new()));
    let p2p_stream = Arc::new(RwLock::new(None::<QuicStream>));
    let p2p_status = Arc::new(AtomicU8::new(P2PStatus::Uninitialized as u8));
    
    let acl = if conf.acl.is_empty() {
        None
    } else {
        serde_json::to_string(&conf.acl).ok()
    };
    loop {
        let arg_commands = arg_commands.clone();
        let conf = conf.clone();
        let token = conf.token.clone();
        let p2p_stream = p2p_stream.clone();
        let p2p_status = p2p_status.clone();

        if let Some((session_id, req, _)) = session
            .as_ref()
            .filter(|(_, _, event_stream_task)| !event_stream_task.is_finished())
        {
            trace!("Session: {:?}", session_id);
            if agents.is_empty() || list_of_agents_refresh_required.load(Ordering::Relaxed) {
                trace!("List of agents refresh required");
                let Ok(Ok(list_of_agents_request)) = tokio::time::timeout(
                    Duration::from_secs(5),
                    req.request(ClientEventOutBound::Request(
                        0,
                        ClientEventRequest::ListOfAgents(arg_commands.verbose()),
                    )),
                )
                .await
                else {
                    #[cfg(any(target_os = "linux", target_os = "macos"))]
                    if matches!(args.arg_commands.as_ref(), ArgCommands::Tun(_)) {
                        if let Listener::Tun(ref tun) = socket_listener {
                            tun.my_routes(false);
                        }
                    }
                    error!("Unable to get list the agents, looks like connection lost");
                    session = None;
                    continue;
                };
                let Some(narrowlink_types::client::EventResponse::ActiveAgents(list_of_agents)) =
                    list_of_agents_request.response()
                else {
                    error!("Unable to get list the agents");
                    break;
                };
                debug!("List of agents request: {:?}", list_of_agents_request);
                agents = list_of_agents;
                debug!("Agents: {:?}", agents);
                list_of_agents_refresh_required.store(false, Ordering::Relaxed);
            }

            let (mut socket, agent_name, _addr, _is_tcp) =
                if let ArgCommands::List(list_args) = arg_commands.as_ref() {
                    trace!("List of agents");
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
                        if list_args.verbose {
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
                    req.shutdown().await;
                    break;
                } else {
                    trace!("Network connection to agent");
                    // dbg!(&arg_commands);
                    let Some(agent_name) = arg_commands
                        .agent_name()
                        .clone()
                        .filter(|name| agents.iter().any(|agent| &agent.name == name))
                    else {
                        error!("Agent not found");
                        return Ok(());
                    };

                    if p2p_stream.read().await.is_none()
                        && (p2p_status.load(Ordering::Relaxed) == P2PStatus::Uninitialized as u8)
                        && p2p
                    {
                        let _ = req
                            .request(ClientEventOutBound::Request(
                                0,
                                ClientEventRequest::Peer2Peer(
                                    narrowlink_types::client::Peer2PeerRequest {
                                        agent_name: agent_name.clone(),
                                        easy_seed_port: rand::thread_rng()
                                            .gen_range((49152 + 2)..(65535 - 2)),
                                        easy_seq: 2,
                                        hard_seed_port: rand::thread_rng()
                                            .gen_range((49152 + 255)..(65535 - 255)),
                                        hard_seq: 255,
                                    },
                                ),
                            ))
                            .await;
                    }
                    let (socket, addr, is_tcp): (Box<dyn AsyncSocket>, SocketAddr, bool) =
                        match socket_listener {
                            Listener::Udp(ref udp_listen) => {
                                let (s, a) = udp_listen.accept().await?;
                                (Box::new(s), a, false)
                            }
                            Listener::Tcp(ref tcp_listen) => {
                                let (s, a) = tcp_listen.accept().await?;
                                (Box::new(s), a, false)
                            }
                            #[cfg(any(target_os = "linux", target_os = "macos"))]
                            Listener::Tun(ref mut tun_listen) => {
                                tun_listen.my_routes(true);
                                let (s, a) = tun_listen.accept().await?;
                                match s {
                                    TunStream::Tcp(socket) => (Box::new(socket), a, true),
                                    TunStream::Udp(socket) => (Box::new(socket), a, false),
                                }
                            }
                            Listener::None => (
                                Box::<InputStream>::default(),
                                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
                                false,
                            ),
                        };
                    (socket, agent_name, addr, is_tcp)
                    // if let Some(ref listener) = socket_listener {
                    //     trace!("Accept connection");
                    //     let socket: Box<dyn AsyncSocket> = match listener {
                    //         Listener::Udp(ref udp_listen) => Box::new(udp_listen.accept().await?.0),
                    //         Listener::Tcp(ref tcp_listen) => Box::new(tcp_listen.accept().await?.0),
                    //         // Listener::Tun(ref tun_listen) => match tun_listen.accept().await.unwrap(){
                    //         //     TunStream::Tcp(socket, ) => Box::new(socket),
                    //         // },
                    //         _ => unreachable!(),
                    //     };
                    //     debug!("Connection accepted");
                    //     (socket, agent_name)
                    // } else {
                    //     trace!("Stdin/Stdout connection");
                    //     (
                    //         Box::<InputStream>::default() as Box<dyn AsyncSocket>,
                    //         agent_name,
                    //     )
                    // }
                };

            // let agent_name: String = args
            //     .agent_name()
            //     .clone()
            //     .filter(|name| agents.iter().any(|agent| &agent.name == name))
            //     .ok_or(ClientError::AgentNotFound)?;

            let session_id = session_id.clone();
            let list_of_agents_refresh_required = list_of_agents_refresh_required.clone();
            if (direct && !relay) || is_connect {
                for i in 0..120 {
                    if p2p_status.load(Ordering::Relaxed) == P2PStatus::Success as u8 {
                        break;
                    } else {
                        if p2p_status.load(Ordering::Relaxed) == P2PStatus::Failed as u8 {
                            if relay {
                                warn!("The peer-to-peer channel has failed. Using normal mode");
                                break;
                            } else {
                                error!("Unable to establish a peer-to-peer channel, you can try again with the --relay option");
                                #[cfg(any(target_os = "linux", target_os = "macos"))]
                                if matches!(args.arg_commands.as_ref(), ArgCommands::Tun(_)) {
                                    if let Listener::Tun(ref tun) = socket_listener {
                                        tun.my_routes(false);
                                        tokio::time::sleep(Duration::from_secs(1)).await;
                                    }
                                }
                                process::exit(0);
                            }
                        }
                        if i % 4 == 0 {
                            info!(
                                "The peer-to-peer channel has not been established yet. Please wait."
                            );
                        }
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                }
            };

            let task = tokio::spawn({
                debug!("Make a data stream to agent: {}", agent_name);
                let arg_commands = arg_commands.clone();
                let connections = connections.clone();
                async move {
                    let mut connect = match arg_commands.as_ref() {
                        ArgCommands::List(_) => {
                            unreachable!()
                        }
                        #[cfg(any(target_os = "linux", target_os = "macos"))]
                        ArgCommands::Tun(_) => generic::Connect {
                            host: _addr.ip().to_string(), //addr.ip().to_string()
                            port: _addr.port(),
                            protocol: if _is_tcp {
                                generic::Protocol::TCP
                            } else {
                                generic::Protocol::UDP
                            },
                            cryptography: None,
                            sign: None,
                        },
                        ArgCommands::Connect(connect_args) => generic::Connect {
                            host: connect_args.remote_addr.0.clone(),
                            port: connect_args.remote_addr.1,
                            protocol: if connect_args.udp {
                                generic::Protocol::UDP
                            } else {
                                generic::Protocol::TCP
                            },
                            cryptography: None,
                            sign: None,
                        },
                        ArgCommands::Forward(forward_args) => generic::Connect {
                            host: forward_args.remote_addr.0.clone(),
                            port: forward_args.remote_addr.1,
                            protocol: if forward_args.udp {
                                generic::Protocol::UDP
                            } else {
                                generic::Protocol::TCP
                            },
                            cryptography: None,
                            sign: None,
                        },
                        ArgCommands::Proxy(_) => {
                            let proxy_stream = ProxyStream::new(proxy_stream::ProxyType::SOCKS5);
                            let interrupted_stream = match proxy_stream.accept(socket).await {
                                Ok(interrupted_stream) => interrupted_stream,
                                Err(e) => {
                                    debug!("Proxy error: {}", e.to_string());
                                    return;
                                }
                            };
                            let addr: (String, u16) = interrupted_stream.addr().into();
                            let protocol = if interrupted_stream.command()
                                == proxy_stream::Command::UdpAssociate
                            {
                                generic::Protocol::UDP
                            } else {
                                generic::Protocol::TCP
                            };
                            socket = match interrupted_stream.connect().await {
                                Ok(s) => Box::new(s),
                                Err(e) => {
                                    debug!("Proxy error: {}", e.to_string());
                                    return;
                                }
                            };

                            generic::Connect {
                                host: addr.0,
                                port: addr.1,
                                protocol,
                                cryptography: None,
                                sign: None,
                            }
                        }
                    };

                    let (key, nonce): (Option<[u8; 32]>, Option<[u8; 24]>) =
                        match arg_commands.cryptography() {
                            Some(ck) => {
                                trace!("Cryptography required");
                                let n = rand::random::<[u8; 24]>();
                                connect.set_cryptography_nonce(n);
                                let k = Sha3_256::digest(
                                    ck.as_bytes()
                                        .iter()
                                        .zip(n.iter().cycle())
                                        .map(|(n, s)| n ^ s)
                                        .collect::<Vec<u8>>(),
                                );
                                let Ok(mut mac) = generic::HmacSha256::new_from_slice(&k) else {
                                    error!("Unable to create hmac"); // unreachable
                                    return;
                                };
                                mac.update(
                                    &[
                                        format!(
                                            "{}:{}:{}",
                                            &connect.host,
                                            &connect.port,
                                            connect.protocol.clone() as u32
                                        )
                                        .as_bytes(),
                                        &n,
                                    ]
                                    .concat(),
                                );
                                connect.set_sign(mac.finalize().into_bytes().into());
                                (Some(k.into()), Some(n))
                            }
                            None => (None, None),
                        };
                    debug!("Connect to: {:?}", connect);

                    let gateway_address = conf.gateway.clone();

                    if p2p_status.load(Ordering::Relaxed) == P2PStatus::Closed as u8 {
                        p2p_stream.write().await.take();
                        p2p_status.store(P2PStatus::Uninitialized as u8, Ordering::Relaxed);
                    }

                    if let Some(stream) = p2p_stream.read().await.as_ref() {
                        if let Ok(mut quic_socket) = stream
                            .open_bi()
                            .await
                            .map(|v| Box::new(v) as Box<dyn AsyncSocket>)
                        {
                            if narrowlink_network::p2p::Request::from(&connect)
                                .write(&mut quic_socket)
                                .await
                                .is_ok()
                            {
                                match narrowlink_network::p2p::Response::read(&mut quic_socket)
                                    .await
                                {
                                    Ok(narrowlink_network::p2p::Response::Success) => {
                                        trace!("P2P connection established");
                                        if let (Some(k), Some(n)) = (key, nonce) {
                                            trace!("Creating cryptography stream");
                                            quic_socket = Box::new(
                                                AsyncSocketCrypt::new(
                                                    k,
                                                    n,
                                                    Box::new(quic_socket),
                                                    true,
                                                )
                                                .await,
                                            );
                                        }
                                        if let Err(_e) = async_forward(quic_socket, socket).await {
                                            debug!("connection closed {}", _e);
                                        }
                                        return;
                                    }
                                    Ok(status) => {
                                        warn!(
                                            "P2P connection to {}:{} failed: {}",
                                            connect.host,
                                            connect.port,
                                            status.to_string()
                                        );
                                        return;
                                    }
                                    Err(e) => {
                                        if e.to_string() == "E-Io:connection lost" {
                                            warn!("P2P connection lost, switch to normal mode");
                                            p2p_status
                                                .store(P2PStatus::Closed as u8, Ordering::Relaxed);
                                        } else {
                                            warn!(
                                            "Unable to read the peer-to-peer response: {}, try with normal mode",
                                            e
                                        );
                                        }
                                    }
                                };
                            }
                        } else {
                            warn!("Unable to open QUIC stream, close the peer-to-peer channel");
                            p2p_status.store(P2PStatus::Closed as u8, Ordering::Relaxed);
                        }
                    }

                    let Ok(cmd) = serde_json::to_string(&ClientDataOutBound::Connect(
                        agent_name,
                        connect.clone(),
                    )) else {
                        error!("Unable to serialize connect command"); // unreachable
                        return;
                    };
                    let (mut data_stream, connection_id): (Box<dyn AsyncSocket>, Option<String>) =
                        match WsConnectionBinary::new(
                            &gateway_address,
                            HashMap::from([
                                ("NL-TOKEN", token.clone()),
                                ("NL-SESSION", session_id.clone()),
                                ("NL-COMMAND", cmd.clone()),
                            ]),
                            conf.protocol.clone(),
                        )
                        .await
                        {
                            Ok(data_stream) => {
                                trace!("Connection successful");
                                let connection_id = data_stream
                                    .get_header("NL-CONNECTION")
                                    .map(|c| c.to_string());

                                (Box::new(data_stream), connection_id)
                            }
                            Err(_e) => {
                                warn!("Unable to connect server: {}", _e);
                                list_of_agents_refresh_required.store(true, Ordering::Relaxed);
                                return;
                            }
                        };
                    if let (Some(k), Some(n)) = (key, nonce) {
                        trace!("Creating cryptography stream");
                        data_stream =
                            Box::new(AsyncSocketCrypt::new(k, n, data_stream, true).await);
                    }

                    if let Err(e) = async_forward(data_stream, socket).await {
                        if let Some(connection_id) = connection_id {
                            // Change 0.2: make connection_id mandatory
                            let reason = connections.lock().await.remove(&connection_id);
                            if let Some(reason) = reason {
                                warn!("{} : {}:{}", reason, connect.host, connect.port);
                                return;
                            }
                        }
                        debug!("connection closed {}:{} {}", connect.host, connect.port, e);
                    };
                }
            });
            if let ArgCommands::Connect(_) = arg_commands.as_ref() {
                let _ = task.await;
                return Ok(());
            }
        } else {
            trace!("Session not found, create new event stream");

            if !matches!(args.arg_commands.as_ref(), ArgCommands::List(_)) {
                info!("Connecting to gateway: {}", conf.gateway);
            }
            let headers = if let Some(acl) = acl.as_ref() {
                HashMap::from([("NL-ACL", acl.clone()), ("NL-TOKEN", token.clone())])
            } else {
                HashMap::from([("NL-TOKEN", token.clone())])
            };
            let event_stream =
                match WsConnection::new(&conf.gateway, headers, conf.protocol.clone()).await {
                    Ok(es) => {
                        if !matches!(args.arg_commands.as_ref(), ArgCommands::List(_)) {
                            info!("Connection successful");
                        }

                        sleep_time = 0;
                        es
                    }
                    Err(e) => {
                        if let NetworkError::UnableToUpgrade(status) = e {
                            match status {
                                401 => {
                                    error!("Authentication failed");
                                    break;
                                }
                                403 => {
                                    error!("Access denied");
                                }
                                _ => {}
                            }
                        };
                        error!("Unable to connect to the gateway: {}", e.to_string());
                        if sleep_time == 0 {
                            info!("Try again");
                        } else if sleep_time == 35 {
                            error!("Unable to connect");
                            info!("Exit");
                            break;
                        } else {
                            info!("Try again in {} secs", sleep_time);
                        }
                        time::sleep(Duration::from_secs(sleep_time)).await;
                        sleep_time += 5;

                        continue;
                    }
                };
            let local_addr = event_stream.local_addr();
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            if let Some(r) = route_sender.as_ref() {
                r.send(RouteCommand::Add(event_stream.peer_addr().ip()))
                    .unwrap();
            };
            // gateway_ip = Some(event_stream.peer_addr());
            let session_id = event_stream
                .get_header("NL-SESSION")
                .ok_or(ClientError::InvalidConfig)?
                .to_string();
            debug!("Connection successful, Session ID: {}", session_id);
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            if let Listener::Tun(ref tun) = socket_listener {
                if relay {
                    tun.my_routes(true);
                }
            }
            let event: NarrowEvent<ClientEventOutBound, ClientEventInBound> =
                NarrowEvent::new(event_stream);
            let req = event.get_request();
            let sys_req = event.get_request();
            let (_event_tx, mut event_rx) = event.split();
            let connections = connections.clone();
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            let route_sender = route_sender.clone();
            let event_stream_task = tokio::spawn(async move {
                while let Some(Ok(msg)) = event_rx.next().await {
                    debug!("Event: {:?}", msg);
                    match msg {
                        narrowlink_types::client::EventInBound::ConnectionError(
                            connection_id,
                            msg,
                        ) => {
                            debug!("Connection Error: {}", msg);
                            connections
                                .lock()
                                .await
                                .insert(connection_id.to_string(), msg);
                        }
                        narrowlink_types::client::EventInBound::Peer2Peer(p2p) => {
                            #[cfg(any(target_os = "linux", target_os = "macos"))]
                            if let Some(r) = route_sender.as_ref() {
                                r.send(RouteCommand::Add(p2p.peer_ip)).unwrap();
                            };
                            let p2p_status = p2p_status.clone();
                            let p2p_stream = p2p_stream.clone();

                            tokio::spawn(async move {
                                if is_connect && !relay {
                                    info!("Trying to create a peer-to-peer channel, please wait");
                                } else {
                                    info!("Trying to create a peer-to-peer channel");
                                    info!("Your client uses normal mode until the peer-to-peer is established");
                                }

                                p2p_status.store(P2PStatus::Pending as u8, Ordering::Relaxed);
                                let (socket, peer) =
                                    match narrowlink_network::p2p::udp_punched_socket(
                                        (&p2p).into(),
                                        &Sha3_256::digest(&p2p.cert)[0..6],
                                        true,
                                        false,
                                    )
                                    .await
                                    {
                                        Ok(s) => s,
                                        Err(e) => {
                                            warn!(
                                                "Unable to establish a peer-to-peer channel: {}",
                                                e
                                            );
                                            if relay {
                                                info!(
                                                    "Your connection continues to use normal mode"
                                                );
                                            }

                                            p2p_status
                                                .store(P2PStatus::Failed as u8, Ordering::Relaxed);
                                            return;
                                        }
                                    };
                                info!("A peer-to-peer channel has just been established");

                                if let Ok(qs) = QuicStream::new_client(peer, socket, p2p.cert).await
                                {
                                    p2p_stream.write().await.replace(qs);
                                    p2p_status.store(P2PStatus::Success as u8, Ordering::Relaxed);
                                } else {
                                    p2p_status.store(P2PStatus::Failed as u8, Ordering::Relaxed);
                                    warn!("Unable to create QUIC stream");
                                };
                            });
                        }
                        _ => {
                            continue;
                        }
                    }
                }
            });
            let _ = sys_req
                .request(ClientEventOutBound::Request(
                    0,
                    ClientEventRequest::UpdateConstantSysInfo(
                        narrowlink_types::client::ConstSystemInfo { local_addr },
                    ),
                ))
                .await;

            session = Some((session_id, req, event_stream_task));
        }
    }

    Ok(())
}

pub struct InputStream {
    stdin: tokio::io::Stdin,
    stdout: tokio::io::Stdout,
}

impl Default for InputStream {
    fn default() -> Self {
        InputStream {
            stdin: tokio::io::stdin(),
            stdout: tokio::io::stdout(),
        }
    }
}

impl AsyncRead for InputStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.stdin).poll_read(ctx, buf)
    }
}

impl AsyncWrite for InputStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.stdout).poll_write(ctx, buf)
    }
    fn poll_flush(
        mut self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.stdout).poll_flush(ctx)
    }
    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.stdout).poll_shutdown(ctx)
    }
}
