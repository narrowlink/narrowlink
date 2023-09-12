use std::{
    collections::HashMap,
    env,
    io::{self, IsTerminal},
    net::SocketAddr,
    str::FromStr,
    time::Duration,
    vec,
};
mod args;
use args::Args;
use config::KeyPolicy;
use error::AgentError;
use futures_util::{SinkExt, StreamExt};
use hmac::Mac;
use narrowlink_network::{
    error::NetworkError,
    event::NarrowEvent,
    p2p::QuicBiSocket,
    stream_forward,
    transport::{StreamType, TlsConfiguration, UnifiedSocket},
    ws::{WsConnection, WsConnectionBinary},
    AsyncSocket, AsyncToStream, StreamCrypt, UniversalStream,
};
use narrowlink_types::{
    agent::{
        ConstSystemInfo, DynSystemInfo, EventInBound as AgentEventInBound,
        EventOutBound as AgentEventOutBound, EventRequest as AgentEventRequest,
    },
    generic::{self, Connect},
    policy::Policies,
    ServiceType,
};
use quinn::{default_runtime, Endpoint, EndpointConfig};
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
    let conf = config::Config::load(args.config_path)?;

    let service_type = conf.service_type;
    let token = conf.token;
    let mut event_headers = HashMap::from([("NL-TOKEN", token.clone())]);
    if let Some(publish_token) = conf.publish {
        event_headers.insert("NL-PUBLISH", publish_token);
    }
    let mut event_connection = None;
    let mut sleep_time = 0;
    loop {
        let Some(event) = event_connection.as_mut() else {
            info!("Connecting to gateway: {}", conf.gateway);
            match WsConnection::new(&conf.gateway, event_headers.clone(), service_type.clone())
                .await
            {
                Ok((event_stream, local_addr)) => {
                    sleep_time = 0;
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
        let gateway = conf.gateway.clone();
        let key = conf.key.clone().map(|k| (k, conf.key_policy));
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
                let (s, _) = match narrowlink_network::p2p::udp_punched_socket(
                    &p2p,
                    &Sha3_256::digest(&p2p.cert)[0..6],
                    true,
                    false,
                )
                .await
                {
                    Ok(s) => s,
                    Err(e) => {
                        warn!("Unable to create peer to peer channel: {}", e);
                        continue;
                    }
                };
                let (server_config, _) = configure_server(p2p.cert, p2p.key).unwrap();
                let runtime = default_runtime().unwrap();
                let end = Endpoint::new(
                    EndpointConfig::default(),
                    Some(server_config),
                    s.into_std().unwrap(),
                    runtime,
                )
                .unwrap();
                let con = end.accept().await.unwrap().await.unwrap();
                loop {
                    let Ok(mut s) = QuicBiSocket::accept(&con).await else {
                        dbg!("accept failed");
                        continue;
                    };
                    tokio::spawn(async {
                        // let mut buf = vec![0u8; 5];
                        // s.read(&mut buf).await.unwrap();
                        let r = narrowlink_network::p2p::Request::read(&mut s)
                            .await
                            .unwrap();
                        let con = Into::<Connect>::into(&r);
                        narrowlink_network::p2p::Response::write(
                            &narrowlink_network::p2p::Response::Success,
                            &mut s,
                        )
                        .await
                        .unwrap();
                        dbg!(&con);
                        let stream = TcpStream::connect((con.host, con.port)).await.unwrap();
                        if let Err(_e) =
                            stream_forward(AsyncToStream::new(stream), AsyncToStream::new(s)).await
                        {
                            dbg!(_e);
                        }
                    });
                }
                // s.write(&buf).await.unwrap();
                // let _c = con.accept_bi().await.unwrap();

                // c.1.read(buf);
                // dbg!(con.remote_address());
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
    ip_policies: Option<Policies>,
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
    if let Some(p) = ip_policies {
        trace!("Checking IP policies");
        let mut connect = req.clone();
        connect.host = address.ip().to_string();
        connect.port = req.port;
        if !p.permit(None, &connect) {
            trace!("IP policies denied");
            return Err(AgentError::AccessDenied);
        }
    }

    let protocol = req.protocol.clone();
    let nonce: Option<[u8; 24]> = req.get_cryptography_nonce();
    if nonce.is_some() && key.is_none() {
        trace!("Key not found");
        return Err(AgentError::KeyNotFound);
    } else if nonce.is_none()
        && key
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
    let mut data_stream: Box<dyn UniversalStream<Vec<u8>, NetworkError>> =
        Box::new(WsConnectionBinary::new(gateway_addr, headers, service_type).await?);
    trace!("Connected to gateway for Data channel");
    if let (Some(k), Some(n)) = (k, n) {
        data_stream = Box::new(StreamCrypt::new(k, n, data_stream));
    }

    if let Err(_e) = stream_forward(data_stream, AsyncToStream::new(socket)).await {
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

fn configure_server(
    cert: Vec<u8>,
    key: Vec<u8>,
) -> Result<(quinn::ServerConfig, Vec<u8>), Box<dyn std::error::Error>> {
    let priv_key = rustls::PrivateKey(key);
    let cert_chain = vec![rustls::Certificate(cert.clone())];

    let mut server_config = quinn::ServerConfig::with_single_cert(cert_chain, priv_key)?;
    let transport_config = std::sync::Arc::get_mut(&mut server_config.transport).unwrap();
    transport_config.max_concurrent_uni_streams(0_u8.into());
    // todo!()
    Ok((server_config, cert))
}
