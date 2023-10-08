use std::{
    collections::HashMap,
    env,
    io::{self, IsTerminal},
    net::SocketAddr,
    str::FromStr,
    time::Duration,
};
mod args;
use args::Args;
use config::KeyPolicy;
use error::AgentError;
use futures_util::{SinkExt, StreamExt};
use hmac::Mac;
use narrowlink_network::{
    async_forward,
    error::NetworkError,
    event::NarrowEvent,
    p2p::QuicStream,
    transport::{StreamType, TlsConfiguration, UnifiedSocket},
    ws::{WsConnection, WsConnectionBinary},
    AsyncSocket, AsyncSocketCrypt,
};
use narrowlink_types::{
    agent::{
        ConstSystemInfo, DynSystemInfo, EventInBound as AgentEventInBound,
        EventOutBound as AgentEventOutBound, EventRequest as AgentEventRequest,
    },
    generic::{self, Connect},
    policy::Policy,
    ServiceType,
};
use sha3::{Digest, Sha3_256};
use sysinfo::SystemExt;
use tokio::{
    net::{lookup_host, TcpStream},
    time,
};
use tracing::{debug, error, info, trace};
use tracing::{warn, Level};
use tracing_subscriber::{
    filter::{LevelFilter, Targets},
    fmt::writer::MakeWriterExt,
    prelude::__tracing_subscriber_SubscriberExt,
    util::SubscriberInitExt,
    Layer,
};
use udp_stream::UdpStream;
use uuid::Uuid;

mod config;
mod error;

fn main() -> Result<(), AgentError> {
    let (stdout, _stdout_guard) = tracing_appender::non_blocking(io::stdout());
    let (stderr, _stderr_guard) = tracing_appender::non_blocking(io::stderr());

    let cmd = tracing_subscriber::fmt::layer()
        .with_ansi(io::stdout().is_terminal() && io::stderr().is_terminal())
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

    let args = Args::parse(env::args())?;

    #[cfg(unix)]
    if args.daemon {
        use daemonize::Daemonize;
        let stdout = std::fs::File::create("/tmp/narrowlink-agent.out")?;
        let stderr = std::fs::File::create("/tmp/narrowlink-agent.err")?;
        let daemonize = Daemonize::new()
            .pid_file("/tmp/narrowlink-agent.pid")
            .working_directory("/tmp/")
            .stdout(stdout)
            .stderr(stderr);
        if let Err(e) = daemonize.start() {
            error!("Unable to daemonize: {}", e.to_string());
            return Ok(());
        }
    }
    start(args)
}

#[tokio::main]
async fn start(args: Args) -> Result<(), AgentError> {
    let mut conf = match config::Config::load(args.config_path) {
        Ok(c) => c,
        Err(e) => {
            error!("Unable to load config: {}", e.to_string());
            return Ok(());
        }
    };

    let Some(config::Endpoint::SelfHosted(self_hosted_config)) = conf.endpoints.pop() else {
        error!("Invalid config, endpoint not found");
        return Ok(());
    };
    let service_type = &self_hosted_config.protocol;
    let token = &self_hosted_config.token;
    let mut event_headers = HashMap::from([("NL-TOKEN", token.clone())]);
    if let Some(publish_token) = self_hosted_config
        .publish
        .and_then(|p| serde_json::to_string(&p).ok())
    {
        event_headers.insert("NL-PUBLISH", publish_token.to_owned());
    }
    let mut event_connection = None;
    let mut sleep_time = 0;
    loop {
        let Some(event) = event_connection.as_mut() else {
            info!("Connecting to gateway: {}", self_hosted_config.gateway);
            match WsConnection::new(
                &self_hosted_config.gateway,
                event_headers.clone(),
                &service_type,
            )
            .await
            {
                Ok(event_stream) => {
                    sleep_time = 0;
                    let local_addr = event_stream.local_addr();
                    let event: NarrowEvent<AgentEventOutBound, AgentEventInBound> =
                        NarrowEvent::new(event_stream);
                    let req = event.get_request();
                    event_connection = Some(event);
                    info!("Connection successful");
                    tokio::spawn(async move {
                        let mut s = sysinfo::System::new_all();
                        let _ = req
                            .request(AgentEventOutBound::Request(
                                0,
                                AgentEventRequest::UpdateConstantSysInfo(ConstSystemInfo {
                                    cpus: s.cpus().len() as u8,
                                    local_addr,
                                }),
                            ))
                            .await;
                        loop {
                            s.refresh_all();
                            let _ = req
                                .request(AgentEventOutBound::Request(
                                    0,
                                    AgentEventRequest::UpdateDynamicSysInfo(DynSystemInfo {
                                        loadavg: s.load_average().one,
                                    }),
                                ))
                                .await;
                            trace!("SysInfo Update");
                            time::sleep(Duration::from_secs(40)).await;
                        }
                    });
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
                    } else if sleep_time == 70 {
                        error!("Unable to connect");
                        info!("Exit");
                        break;
                    } else {
                        info!("Try again in {} secs", sleep_time);
                    }
                    time::sleep(Duration::from_secs(sleep_time)).await;
                    sleep_time += 10;
                }
            };
            continue;
        };

        let service_type = service_type.clone();
        let event_sender = event.get_sender();
        let token = token.clone();
        let gateway = self_hosted_config.gateway.clone();
        let key = if let Some(config::E2EE::PassPhrase(e2ee)) = conf.e2ee.first() {
            Some((e2ee.phrase.to_owned(), e2ee.policy))
        } else {
            None
        };
        // let key = conf.e2ee.clone().map(|k| (k, k.policy));
        let service_type = service_type.clone();
        trace!("Waiting for event");
        match event.next().await {
            Some(Ok(AgentEventInBound::Connect(connection, connect, ip_policies))) => {
                debug!("Connection to {:?} received", connect);
                tokio::spawn(async move {
                    if let Err(e) = data_connect(
                        &gateway,
                        token.clone(),
                        // session,
                        connection,
                        connect,
                        ip_policies,
                        key.as_ref(),
                        service_type,
                    )
                    .await
                    {
                        let _ =
                            event_sender.send(AgentEventOutBound::Error(connection, e.to_string()));
                    };
                });
                continue;
            }
            Some(Ok(AgentEventInBound::Peer2Peer(p2p))) => {
                tokio::spawn({
                    async move {
                        let (socket, _) = match narrowlink_network::p2p::udp_punched_socket(
                            (&p2p).into(),
                            &Sha3_256::digest(&p2p.cert)[0..6],
                            false,
                            false,
                        )
                        .await
                        {
                            Ok(s) => s,
                            Err(e) => {
                                warn!("Unable to create peer to peer channel: {}", e);
                                return;
                            }
                        };
                        info!("Peer to peer channel created");
                        let Ok(con) = QuicStream::new_server(socket, p2p.cert, p2p.key).await
                        else {
                            warn!("Unable to create peer to peer channel");
                            return;
                        };
                        let policies = p2p.policies;
                        loop {
                            let policies = policies.clone();
                            let mut s = match con
                                .accept_bi()
                                .await
                                .map(|s| Box::new(s) as Box<dyn AsyncSocket>)
                            {
                                Ok(s) => s,
                                Err(e) => {
                                    warn!("Unable to accept peer to peer channel: {}", e);
                                    break;
                                }
                            };
                            let key = key.clone();
                            tokio::spawn(async move {
                                let Ok(r) = narrowlink_network::p2p::Request::read(&mut s).await
                                else {
                                    warn!("Unable to read request");
                                    return;
                                };
                                let con = Into::<Connect>::into(&r);

                                if !policies.is_empty()
                                    && !policies.into_iter().any(|p| p.permit(&con))
                                {
                                    // todo: verify
                                    warn!(
                                        "Access denied to {}:{}, peer: {}",
                                        con.host, con.port, p2p.peer_ip
                                    );
                                    if narrowlink_network::p2p::Response::write(
                                        &narrowlink_network::p2p::Response::AccessDenied,
                                        &mut s,
                                    )
                                    .await
                                    .is_err()
                                    {
                                        warn!("Unable to write response");
                                    }
                                    return;
                                }
                                let nonce: Option<[u8; 24]> = con.get_cryptography_nonce();
                                if (nonce.is_some() && key.is_none())
                                    || nonce.is_none()
                                        && key
                                            .as_ref()
                                            .filter(|(_, policy)| &KeyPolicy::Strict == policy)
                                            .is_some()
                                {
                                    warn!(
                                            "Access denied to {}:{}, peer: {} - Encryption is enforced, but request is not encrypted or key not found",
                                            con.host, con.port, p2p.peer_ip
                                        );
                                    if narrowlink_network::p2p::Response::write(
                                        &narrowlink_network::p2p::Response::AccessDenied,
                                        &mut s,
                                    )
                                    .await
                                    .is_err()
                                    {
                                        warn!("Unable to write response");
                                    }
                                    return;
                                }

                                let (k, n): (Option<[u8; 32]>, Option<[u8; 24]>) =
                                    if let (Some((k, _)), Some(n)) = (key.as_ref(), nonce) {
                                        let k = Sha3_256::digest(
                                            k.as_bytes()
                                                .iter()
                                                .zip(n.iter().cycle())
                                                .map(|(n, s)| n ^ s)
                                                .collect::<Vec<u8>>(),
                                        );
                                        let Ok(mut mac) = generic::HmacSha256::new_from_slice(&k)
                                        else {
                                            warn!("Unable to create HMAC");
                                            if narrowlink_network::p2p::Response::write(
                                                &narrowlink_network::p2p::Response::AccessDenied,
                                                &mut s,
                                            )
                                            .await
                                            .is_err()
                                            {
                                                warn!("Unable to write response");
                                            }
                                            return;
                                        };
                                        mac.update(
                                            &[
                                                format!(
                                                    "{}:{}:{}",
                                                    &con.host,
                                                    &con.port,
                                                    con.protocol.clone() as u32
                                                )
                                                .as_bytes(),
                                                &n,
                                            ]
                                            .concat(),
                                        );

                                        if (con.get_sign().and_then(|s| mac.verify_slice(&s).ok()))
                                            .is_none()
                                        {
                                            warn!(
                                                "Request signature verification failed, peer: {}",
                                                p2p.peer_ip
                                            );
                                            if narrowlink_network::p2p::Response::write(
                                                &narrowlink_network::p2p::Response::AccessDenied,
                                                &mut s,
                                            )
                                            .await
                                            .is_err()
                                            {
                                                warn!("Unable to write response");
                                            }
                                            return;
                                        };

                                        (Some(k.into()), Some(n))
                                    } else {
                                        (None, None)
                                    };
                                // dbg!(&con);
                                trace!("Connecting to {}", con.host);
                                let Some(remote_addr) =
                                    tokio::net::lookup_host(&format!("{}:{}", con.host, con.port))
                                        .await
                                        .ok()
                                        .and_then(|mut s| s.next())
                                else {
                                    if narrowlink_network::p2p::Response::write(
                                        &narrowlink_network::p2p::Response::UnableToResolve,
                                        &mut s,
                                    )
                                    .await
                                    .is_err()
                                    {
                                        warn!("Unable to write response");
                                        return;
                                    }
                                    warn!("Unable to resolve {}", con.host);
                                    return;
                                };

                                let socket = if matches!(con.protocol, generic::Protocol::UDP) {
                                    UdpStream::connect(remote_addr)
                                        .await
                                        .map(|s| Box::new(s) as Box<dyn AsyncSocket>)
                                } else {
                                    TcpStream::connect(remote_addr)
                                        .await
                                        .map(|s| Box::new(s) as Box<dyn AsyncSocket>)
                                };

                                let stream = match socket {
                                    Ok(stream) => {
                                        if narrowlink_network::p2p::Response::write(
                                            &narrowlink_network::p2p::Response::Success,
                                            &mut s,
                                        )
                                        .await
                                        .is_err()
                                        {
                                            warn!("Unable to write response");
                                            return;
                                        }
                                        stream
                                    }
                                    Err(_e) => {
                                        warn!("Unable to connect to {}", _e);
                                        if narrowlink_network::p2p::Response::write(
                                            &narrowlink_network::p2p::Response::Failed,
                                            &mut s,
                                        )
                                        .await
                                        .is_err()
                                        {
                                            warn!("Unable to write response");
                                        }
                                        return;
                                    }
                                };
                                if let (Some(k), Some(n)) = (k, n) {
                                    s = Box::new(AsyncSocketCrypt::new(k, n, s, false).await);
                                }
                                if let Err(_e) = async_forward(s, stream).await {
                                    trace!("Data channel closed: {}", _e.to_string());
                                }
                            });
                        }
                    }
                });
            }
            Some(Ok(AgentEventInBound::IsReachable(connection, connect))) => {
                let res = match is_ready(connect).await {
                    Ok(true) => AgentEventOutBound::Ready(connection),
                    Ok(false) => AgentEventOutBound::NotSure(connection),
                    Err(e) => AgentEventOutBound::Error(connection, e.to_string()),
                };
                if let Err(e) = event.send(res).await {
                    error!("Gateway connection dropped: {}", e.to_string());
                    event_connection = None;
                };
                continue;
            }
            Some(Ok(AgentEventInBound::Response(_, _))) => continue,
            Some(Ok(narrowlink_types::agent::EventInBound::Ping(ping_time))) => {
                let _ = event_sender.send(AgentEventOutBound::Pong(ping_time));
            }
            Some(Ok(narrowlink_types::agent::EventInBound::Shutdown)) => {
                info!("Gateway requested shutdown");
                break;
            }
            Some(Err(e)) => {
                error!("Gateway connection dropped: {}", e.to_string());
                event_connection = None;
                continue;
            }
            None => {
                break;
            }
        }
    }
    Ok(())
}

async fn data_connect(
    gateway_addr: &str,
    token: String,
    // session: Uuid,
    connection: Uuid,
    req: generic::Connect,
    ip_policies: Vec<Policy>,
    key: Option<&(String, KeyPolicy)>,
    service_type: ServiceType,
) -> Result<(), AgentError> {
    let addr = format!("{}:{}", req.host, req.port);
    let address = match SocketAddr::from_str(&addr) {
        Ok(addr) => addr,
        Err(_e) => match lookup_host(&addr).await?.next() {
            Some(addr) => addr,
            None => return Err(AgentError::UnableToResolve),
        },
    };

    let mut connect = req.clone();
    connect.host = address.ip().to_string();
    connect.port = req.port;

    if !ip_policies.is_empty() && !ip_policies.into_iter().any(|p| p.permit(&connect)) {
        trace!("IP policies denied");
        return Err(AgentError::AccessDenied);
    }

    let protocol = req.protocol.clone();

    let nonce: Option<[u8; 24]> = req.get_cryptography_nonce();
    if nonce.is_some() && key.is_none() {
        trace!("Key not found");
        return Err(AgentError::KeyNotFound);
    } else if nonce.is_none()
        && key
            .as_ref()
            .filter(|(_, policy)| &KeyPolicy::Strict == policy)
            .is_some()
    {
        trace!("Encryption is enforced, but request is not encrypted");
        return Err(AgentError::AccessDenied);
    }

    let (k, n): (Option<[u8; 32]>, Option<[u8; 24]>) = if let (Some((k, _)), Some(n)) = (key, nonce)
    {
        let k = Sha3_256::digest(
            k.as_bytes()
                .iter()
                .zip(n.iter().cycle())
                .map(|(n, s)| n ^ s)
                .collect::<Vec<u8>>(),
        );
        let Ok(mut mac) = generic::HmacSha256::new_from_slice(&k) else {
            trace!("Unable to create HMAC");
            return Err(AgentError::AccessDenied);
        };
        mac.update(
            &[
                format!(
                    "{}:{}:{}",
                    &req.host,
                    &req.port,
                    req.protocol.clone() as u32
                )
                .as_bytes(),
                &n,
            ]
            .concat(),
        );

        if (req.get_sign().and_then(|s| mac.verify_slice(&s).ok())).is_none() {
            trace!("Request signature verification failed");
            return Err(AgentError::AccessDenied);
        };

        (Some(k.into()), Some(n))
    } else {
        (None, None)
    };

    let (socket, peer_address): (Box<dyn AsyncSocket>, Option<String>) = match protocol {
        generic::Protocol::HTTP | generic::Protocol::TCP => {
            trace!("Connecting to {} (TCP)", address);
            let stream = TcpStream::connect(address).await?;
            let peer_address = stream.peer_addr().map(|sa| format!("TCP://{}", sa)).ok();
            (Box::new(stream), peer_address)
        }
        generic::Protocol::UDP | generic::Protocol::QUIC | generic::Protocol::DTLS => {
            trace!("Connecting to {} (UDP)", address);
            let stream = UdpStream::connect(address).await?;

            let peer_address = stream.peer_addr().map(|sa| format!("UDP://{}", sa)).ok();
            (Box::new(stream), peer_address)
        }
        generic::Protocol::TLS | generic::Protocol::HTTPS => {
            trace!("Connecting to {} (TLS)", address);
            let stream = UnifiedSocket::new(
                &addr,
                StreamType::Tls(TlsConfiguration { sni: addr.clone() }),
            )
            .await?;
            let peer_address = Some(format!("TLS://{}", stream.peer_addr()));

            (Box::new(stream), peer_address)
        }
    };

    let mut headers = HashMap::from([
        ("NL-TOKEN", token),
        ("NL-CONNECTION", connection.to_string()),
    ]);
    if let Some(peer_address) = peer_address {
        headers.insert("NL-CONNECTING-ADDRESS", peer_address);
    }
    trace!("Connecting to gateway for Data channel: {}", gateway_addr);
    let mut data_stream: Box<dyn AsyncSocket> =
        Box::new(WsConnectionBinary::new(gateway_addr, headers, service_type).await?);
    trace!("Connected to gateway for Data channel");
    if let (Some(k), Some(n)) = (k, n) {
        data_stream = Box::new(AsyncSocketCrypt::new(k, n, data_stream, false).await);
    }

    if let Err(_e) = async_forward(data_stream, socket).await {
        trace!("Data channel closed: {}", _e.to_string());
        // dbg!(e);
    };

    Ok(())
}

pub async fn is_ready(command: generic::Connect) -> Result<bool, std::io::Error> {
    debug!("Checking if {:?} is ready", command);
    match command.protocol {
        generic::Protocol::HTTPS
        | generic::Protocol::TLS
        | generic::Protocol::TCP
        | generic::Protocol::HTTP => {
            let addr = format!("{}:{}", command.host, command.port);
            match TcpStream::connect(addr).await {
                Ok(_) => Ok(true),
                Err(e) => Err(e),
            }
        }
        generic::Protocol::QUIC | generic::Protocol::DTLS | generic::Protocol::UDP => Ok(false),
    }
}
