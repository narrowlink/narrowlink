use std::{collections::HashMap, env, net::SocketAddr, str::FromStr, time::Duration};
mod args;
use args::Args;
use config::KeyPolicy;
use error::AgentError;
use futures_util::{SinkExt, StreamExt};
use hmac::Mac;
use log::{error, info};
use narrowlink_network::{
    error::NetworkError,
    event::NarrowEvent,
    stream_forward,
    transport::{StreamType, TlsConfiguration, UnifiedSocket},
    ws::{WsConnection, WsConnectionBinary},
    AsyncSocket, AsyncToStream, StreamCrypt, UniversalStream,
};
use narrowlink_types::{
    agent::{
        EventInBound as AgentEventInBound, EventOutBound as AgentEventOutBound,
        EventRequest as AgentEventRequest,
    },
    generic::{self, SystemInfo},
    policy::Policies,
    ServiceType,
};
use sha3::{Digest, Sha3_256};
use sysinfo::SystemExt;
use tokio::{
    net::{lookup_host, TcpStream},
    time,
};
use udp_stream::UdpStream;
use uuid::Uuid;

mod config;
mod error;

#[tokio::main]
async fn main() -> Result<(), AgentError> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args = Args::parse(env::args())?;
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
                Ok(event_stream) => {
                    sleep_time = 0;
                    let event: NarrowEvent<AgentEventOutBound, AgentEventInBound> =
                        NarrowEvent::new(event_stream);
                    let req = event.get_request();
                    event_connection = Some(event);
                    info!("Connection successful");
                    tokio::spawn({
                        // let req = req.clone();
                        let mut s = sysinfo::System::new_all();
                        async move {
                            loop {
                                s.refresh_all();
                                let _ = req
                                    .request(AgentEventOutBound::Request(
                                        0,
                                        AgentEventRequest::SysInfo(SystemInfo {
                                            loadavg: s.load_average().one,
                                            cpus: s.cpus().len() as u8,
                                        }),
                                    ))
                                    .await;
                                time::sleep(Duration::from_secs(40)).await;
                            }
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

        match event.next().await {
            Some(Ok(AgentEventInBound::Connect(connection, connect, ip_policies))) => {
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
        let mut connect = req.clone();
        connect.host = address.ip().to_string();
        connect.port = req.port;
        if !p.permit(None, &connect) {
            return Err(AgentError::AccessDenied);
        }
    }

    let protocol = req.protocol.clone();
    let nonce: Option<[u8; 24]> = req.get_cryptography_nonce();
    if nonce.is_some() && key.is_none() {
        return Err(AgentError::KeyNotFound);
    } else if nonce.is_none()
        && key
            .filter(|(_, policy)| &KeyPolicy::Strict == policy)
            .is_some()
    {
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
            return Err(AgentError::AccessDenied);
        };

        (Some(k.into()), Some(n))
    } else {
        (None, None)
    };

    let (socket, peer_address): (Box<dyn AsyncSocket>, Option<String>) = match protocol {
        generic::Protocol::HTTP | generic::Protocol::TCP => {
            let stream = TcpStream::connect(address).await?;
            let peer_address = stream.peer_addr().map(|sa| format!("TCP://{}", sa)).ok();
            (Box::new(stream), peer_address)
        }
        generic::Protocol::UDP | generic::Protocol::QUIC | generic::Protocol::DTLS => {
            let stream = UdpStream::connect(address).await?;

            let peer_address = stream.peer_addr().map(|sa| format!("UDP://{}", sa)).ok();
            (Box::new(stream), peer_address)
        }
        generic::Protocol::TLS | generic::Protocol::HTTPS => {
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
    let mut data_stream: Box<dyn UniversalStream<Vec<u8>, NetworkError>> =
        Box::new(WsConnectionBinary::new(gateway_addr, headers, service_type).await?);

    if let (Some(k), Some(n)) = (k, n) {
        data_stream = Box::new(StreamCrypt::new(k, n, data_stream));
    }

    if let Err(_e) = stream_forward(data_stream, AsyncToStream::new(socket)).await {
        // dbg!(e);
    };

    Ok(())
}

pub async fn is_ready(command: generic::Connect) -> Result<bool, std::io::Error> {
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
