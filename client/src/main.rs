use std::{
    collections::HashMap,
    env,
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
mod args;
mod error;
use args::{ArgCommands, Args};
mod config;
use either::Either;
use error::ClientError;
use futures_util::stream::StreamExt;
use hmac::Mac;
use log::{error, info, warn};
use narrowlink_network::{
    error::NetworkError,
    event::{NarrowEvent, NarrowEventRequest},
    stream_forward,
    ws::{WsConnection, WsConnectionBinary},
    AsyncSocket, AsyncToStream, StreamCrypt, UniversalStream,
};
use narrowlink_types::{
    client::DataOutBound as ClientDataOutBound,
    client::EventInBound as ClientEventInBound,
    client::EventOutBound as ClientEventOutBound,
    client::EventRequest as ClientEventRequest,
    generic::{self, Protocol},
    GetResponse,
};
use sha3::{Digest, Sha3_256};
use socks5_protocol::{
    AuthMethod, AuthRequest, AuthResponse, Command, CommandRequest, CommandResponse, Version,
};
use tokio::{net::TcpListener, time};
use udp_stream::UdpListener;

use env_logger::Env;

#[tokio::main]
async fn main() -> Result<(), ClientError> {
    env_logger::Builder::from_env(Env::default().default_filter_or("warn")).init();
    let args = Args::parse(env::args())?;
    let conf = Arc::new(config::Config::load(args.config_path)?);

    let mut session: Option<(
        String,
        NarrowEventRequest<
            narrowlink_types::client::EventOutBound,
            narrowlink_types::client::EventInBound,
        >,
        tokio::task::JoinHandle<()>,
    )> = None;
    let mut socket_listener = None;
    let arg_commands = args.arg_commands.clone();
    match arg_commands.as_ref() {
        ArgCommands::List(_) | ArgCommands::Connect(_) => {}
        ArgCommands::Forward(forward_args) => {
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
                (Either::Left(listener), local_addr)
            } else {
                let (local_addr, listener) = TcpListener::bind(local_addr)
                    .await
                    .and_then(|listener| Ok((listener.local_addr()?, listener)))
                    .map_err(|_| ClientError::UnableToBind)?;
                (Either::Right(listener), local_addr)
            };

            socket_listener = Some(listener);
        }
        ArgCommands::Proxy(proxy_args) => {
            let local_addr = SocketAddr::new(
                proxy_args
                    .local_addr
                    .0
                    .parse::<IpAddr>()
                    .map_err(|_| ClientError::InvalidLocalAddress)?,
                proxy_args.local_addr.1,
            );
            socket_listener = Some(Either::Right(
                TcpListener::bind(local_addr)
                    .await
                    .map_err(|_| ClientError::UnableToBind)?,
            ));
        }
    };

    let mut agents = Vec::new();
    let list_of_agents_refresh_required = Arc::new(AtomicBool::new(true));
    let mut sleep_time = 0;
    let arg_commands = args.arg_commands.clone();

    loop {
        let arg_commands = arg_commands.clone();
        let conf = conf.clone();
        let token = conf.token.clone();

        if let Some((session_id, req, _)) = session
            .as_ref()
            .filter(|(_, _, event_stream_task)| !event_stream_task.is_finished())
        {
            if agents.is_empty() || list_of_agents_refresh_required.load(Ordering::Relaxed) {
                let Ok(list_of_agents_request) = req
                .request(ClientEventOutBound::Request(
                    0,
                    ClientEventRequest::ListOfAgents(arg_commands.verbose()),
                ))
                .await else {
                    session= None;
                    continue;
                };
                let Some(narrowlink_types::client::EventResponse::ActiveAgents(list_of_agents)) = list_of_agents_request.response() else{
                    error!("Unable to get list the agents");
                    break;
                };
                agents = list_of_agents;
                list_of_agents_refresh_required.store(false, Ordering::Relaxed);
            }

            let (mut socket, agent_name) = if let ArgCommands::List(list_args) =
                arg_commands.as_ref()
            {
                if agents.is_empty(){
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
                        println!("\t\tLoad Avarage: {}", system_info.loadavg);
                        println!("\t\tCPU Cores: {}", system_info.cpus);
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
                                chrono::DateTime::from_utc(*since, *chrono::Local::now().offset());
                            println!("\tConnection Time: {}", datetime);
                        }
                    }

                    println!("\tConnection Ping: {}ms\r\n", agent.ping);
                }
                req.shutdown().await;
                break;
            } else {
                let agent_name: String = arg_commands
                    .agent_name()
                    .clone()
                    .filter(|name| agents.iter().any(|agent| &agent.name == name))
                    .ok_or(ClientError::AgentNotFound)?;

                if let Some(ref listener) = socket_listener {
                    let socket: Box<dyn AsyncSocket> = match listener {
                        Either::Left(ref udp_listen) => Box::new(udp_listen.accept().await?.0),
                        Either::Right(ref tcp_listen) => Box::new(tcp_listen.accept().await?.0),
                    };
                    (socket, agent_name)
                } else {
                    (
                        Box::new(InputStream::new()) as Box<dyn AsyncSocket>,
                        agent_name,
                    )
                }
            };
            // let agent_name: String = args
            //     .agent_name()
            //     .clone()
            //     .filter(|name| agents.iter().any(|agent| &agent.name == name))
            //     .ok_or(ClientError::AgentNotFound)?;

            let session_id = session_id.clone();
            let list_of_agents_refresh_required = list_of_agents_refresh_required.clone();
            let task = tokio::spawn({
                let arg_commands = arg_commands.clone();
                async move {
                    let mut connect = match arg_commands.as_ref() {
                        ArgCommands::List(_) => {
                            unreachable!()
                        }
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
                            let (socks_socket, connect) = match self::from(socket, false).await {
                                Ok((socket, addr, protocol)) => {
                                    // connect.addr = addr;

                                    (
                                        socket,
                                        generic::Connect {
                                            host: addr.0,
                                            port: addr.1,
                                            protocol,
                                            cryptography: None,
                                            sign: None,
                                        },
                                    )
                                }
                                Err(e) => {
                                    warn!("{}", e.to_string());
                                    return;
                                }
                            };
                            socket = socks_socket;
                            connect
                        }
                    };

                    let (key, nonce): (Option<[u8; 32]>, Option<[u8; 24]>) =
                        match arg_commands.cryptography() {
                            Some(ck) => {
                                let n = rand::random::<[u8; 24]>();
                                connect.set_cryptography_nonce(n);
                                let k = Sha3_256::digest(
                                    ck.as_bytes()
                                        .iter()
                                        .zip(n.iter().cycle())
                                        .map(|(n, s)| n ^ s)
                                        .collect::<Vec<u8>>(),
                                );
                                let mut mac = generic::HmacSha256::new_from_slice(&k).unwrap();
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

                    let gateway_address = conf.gateway.clone();

                    let cmd =
                        serde_json::to_string(&ClientDataOutBound::Connect(agent_name, connect))
                            .unwrap();
                    let mut data_stream: Box<dyn UniversalStream<Vec<u8>, NetworkError>> =
                        match WsConnectionBinary::new(
                            &gateway_address,
                            HashMap::from([
                                ("NL-TOKEN", token.clone()),
                                ("NL-SESSION", session_id.clone()),
                                ("NL-COMMAND", cmd.clone()),
                            ]),
                            conf.service_type.clone(),
                        )
                        .await
                        {
                            Ok(data_stream) => Box::new(data_stream),
                            Err(_e) => {
                                warn!("Unable to connect server: {}", _e);
                                list_of_agents_refresh_required.store(true, Ordering::Relaxed);
                                return;
                            }
                        };
                    if let (Some(k), Some(n)) = (key, nonce) {
                        data_stream = Box::new(StreamCrypt::new(k, n, data_stream));
                    }

                    if let Err(_e) = stream_forward(data_stream, AsyncToStream::new(socket)).await {
                        warn!("{}", _e);
                    };
                }
            });
            if let ArgCommands::Connect(_) = arg_commands.as_ref() {
                task.await.unwrap();
                return Ok(());
            }
        } else {
            let event_stream = match WsConnection::new(
                &conf.gateway,
                HashMap::from([("NL-TOKEN", token.clone())]),
                conf.service_type.clone(),
            )
            .await
            {
                Ok(es) => {
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

            let session_id = event_stream
                .get_header("NL-SESSION")
                .ok_or(ClientError::InvalidConfig)?
                .to_string();
            let event: NarrowEvent<ClientEventOutBound, ClientEventInBound> =
                NarrowEvent::new(event_stream);
            let req = event.get_request();
            let (_event_tx, mut event_rx) = event.split();
            let event_stream_task = tokio::spawn(async move {
                while (event_rx.next().await).is_some() {
                    continue;
                }
            });

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
        Self::new()
    }
}

use tokio::io::AsyncRead as TAsyncRead;
use tokio::io::AsyncWrite as TAsyncWrite;
impl InputStream {
    pub fn new() -> Self {
        InputStream {
            stdin: tokio::io::stdin(),
            stdout: tokio::io::stdout(),
        }
    }
}
use core::pin::Pin;
use core::task::{Context, Poll};
impl TAsyncRead for InputStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.stdin).poll_read(ctx, buf)
    }
}

impl TAsyncWrite for InputStream {
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

pub async fn from<S: 'static>(
    stream: S,
    _client: bool,
) -> Result<(Box<dyn AsyncSocket>, (String, u16), Protocol), socks5_protocol::Error>
where
    S: TAsyncRead + TAsyncWrite + std::marker::Unpin + std::marker::Send,
{
    let mut stream = stream;
    let version = Version::read(&mut stream).await?;
    let _ = AuthRequest::read(&mut stream).await?;
    version.write(&mut stream).await?;
    let respond = AuthResponse::new(AuthMethod::Noauth);
    respond.write(&mut stream).await?;
    let request = CommandRequest::read(&mut stream).await?;
    let protocol = if let Command::UdpAssociate = request.command {
        generic::Protocol::UDP
    } else {
        generic::Protocol::TCP
    };
    // dbg!(request.command);
    let addr = match &request.address {
        socks5_protocol::Address::SocketAddr(addr) => (addr.ip().to_string(), addr.port()),
        socks5_protocol::Address::Domain(addr, port) => (addr.clone(), *port),
    };

    CommandResponse::success(request.address)
        .write(&mut stream)
        .await?;

    Ok((Box::new(stream), addr, protocol))
}
