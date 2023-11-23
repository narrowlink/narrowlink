use hmac::Mac;
use narrowlink_network::{
    async_forward, error::NetworkError, p2p::QuicStream, ws::WsConnectionBinary, AsyncSocket,
    AsyncSocketCrypt,
};
use narrowlink_types::{
    client::DataOutBound as ClientDataOutBound,
    client::Peer2PeerInstruction,
    generic::{self, Connect},
};
use std::{
    collections::HashMap,
    sync::{
        atomic::{self, AtomicU8},
        Arc,
    },
};
use tokio::sync::{Notify, RwLock};
use tracing::{error, info, trace};

use sha3::{Digest, Sha3_256};

use crate::{error::ClientError, manage::RelayInfo};

pub enum DirectTunnelStatus {
    Uninitialized = 0x0,
    Success = 0x1,
    Pending = 0x2,
    Closed = 0x3,
    Failed = 0xff,
}

#[derive(Clone)]
pub enum TransportInstruction {
    Direct(Option<String>, String),
    Relay(Option<String>, String),
    Mixed(Option<String>, String, bool),
    None,
}

impl TransportInstruction {
    pub fn determine(
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

#[derive(Clone)]
pub struct TransportFactory {
    i: TransportInstruction,
    direct: Arc<RwLock<Option<QuicStream>>>,
    notify_direct: Arc<RwLock<Option<Arc<Notify>>>>,
    relay: Option<RelayInfo>,
}

impl TransportFactory {
    pub fn new(i: TransportInstruction) -> Self {
        Self {
            i,
            direct: Arc::new(RwLock::new(None)),
            notify_direct: Arc::new(RwLock::new(Some(Arc::new(Notify::new())))),
            relay: None,
        }
    }
    pub fn set_relay(&mut self, relays: RelayInfo) {
        self.relay = Some(relays);
    }
    #[allow(dead_code)]
    pub fn unset_relay(&mut self) {
        self.relay = None;
    }
    pub async fn create_direct(
        &self,
        direct_instruction: Peer2PeerInstruction,
        direct_tunnel_status: Arc<AtomicU8>,
    ) -> Result<(), ClientError> {
        direct_tunnel_status.store(DirectTunnelStatus::Pending as u8, atomic::Ordering::Relaxed);
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
        direct_tunnel_status.store(res.1 as u8, atomic::Ordering::Relaxed);
        Ok(res.0?)
    }
    async fn connect_direct(
        &self,
        _agent_name: &str,
        mut connect: Connect,
        wait_for_tunnel: bool,
        e2ee: &Option<String>,
    ) -> Result<(Box<dyn AsyncSocket>, Option<String>), ClientError> {
        let notify = self.notify_direct.read().await.clone();
        if let Some(notify) = notify.filter(|_| wait_for_tunnel) {
            let protocol = if connect.protocol == generic::Protocol::UDP {
                "udp://"
            } else if connect.protocol == generic::Protocol::TCP {
                "tcp://"
            } else {
                ""
            };
            info!(
                "{}{}:{} is on hold and waiting to create the direct channel",
                protocol, connect.host, connect.port
            );
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
        let e2ee_params: Option<([u8; 32], [u8; 24])> = match e2ee {
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
                    return Err(ClientError::Unexpected(0));
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
                Some((k.into(), n))
            }
            None => None,
        };

        narrowlink_network::p2p::Request::from(&connect)
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
            narrowlink_network::p2p::Response::Success => {
                trace!(
                    "Direct connection established to {}:{}",
                    connect.host,
                    connect.port
                );
            }
            narrowlink_network::p2p::Response::InvalidRequest => {
                return Err(ClientError::InvalidDirectRequest)
            }
            narrowlink_network::p2p::Response::AccessDenied => {
                return Err(ClientError::ACLDenied(connect.host, connect.port))
            }
            narrowlink_network::p2p::Response::UnableToResolve => {
                return Err(ClientError::UnableToResolve(connect.host))
            }
            narrowlink_network::p2p::Response::Failed => {
                return Err(ClientError::DirectConnectionFailed(
                    connect.host,
                    connect.port,
                ))
            }
        }

        if let Some((key, nonce)) = e2ee_params {
            Ok((
                Box::new(AsyncSocketCrypt::new(key, nonce, Box::new(quic_socket)).await),
                None,
            ))
        } else {
            Ok((Box::new(quic_socket), None))
        }
    }
    pub async fn is_direct_required_and_unavailable(&self) -> bool {
        matches!(self.i, TransportInstruction::Direct(_, _)) && self.direct.read().await.is_none()
    }
    async fn connect_relay(
        &self,
        agent_name: &str,
        mut connect: Connect,
        e2ee: &Option<String>,
    ) -> Result<(Box<dyn AsyncSocket>, Option<String>), ClientError> {
        let Some(relay) = self.relay.as_ref() else {
            return Err(ClientError::RelayChannelNotAvailable);
        };

        let e2ee_params: Option<([u8; 32], [u8; 24])> = match e2ee {
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
                    return Err(ClientError::Unexpected(0));
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
                Some((k.into(), n))
            }
            None => None,
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
                if matches!(e, NetworkError::UnableToUpgrade(401)) {
                    return Err(ClientError::AuthRequired);
                } else if matches!(e, NetworkError::UnableToUpgrade(403)) {
                    return Err(ClientError::AccessDenied);
                } else if matches!(e, NetworkError::UnableToUpgrade(404)) {
                    return Err(ClientError::AgentNotFound);
                } else {
                    return Err(ClientError::UnableToConnectToRelay);
                }
            }
        };
        let connection_id = connection
            .get_header("NL-CONNECTION")
            .map(|c| c.to_string());

        if let Some((key, nonce)) = e2ee_params {
            Ok((
                Box::new(AsyncSocketCrypt::new(key, nonce, Box::new(connection)).await),
                connection_id,
            ))
        } else {
            Ok((Box::new(connection), connection_id))
        }
    }
    pub async fn connect(
        &self,
        socket: impl AsyncSocket,
        connect: Connect,
    ) -> Result<Option<String>, ClientError> {
        let (connection, connection_id): (Box<dyn AsyncSocket>, Option<String>) = match &self.i {
            TransportInstruction::Direct(e2ee, agent_name) => {
                self.connect_direct(agent_name, connect, true, e2ee).await?
            }
            TransportInstruction::Relay(e2ee, agent_name) => {
                self.connect_relay(agent_name, connect, e2ee).await?
            }
            TransportInstruction::Mixed(e2ee, agent_name, wait) => {
                match self
                    .connect_direct(agent_name, connect.clone(), *wait, e2ee)
                    .await
                {
                    Ok((connection, connection_id)) => (connection, connection_id),
                    Err(_) => self.connect_relay(agent_name, connect, e2ee).await?,
                }
            }
            TransportInstruction::None => return Err(ClientError::Unexpected(0)),
        };

        Ok(async_forward(socket, connection)
            .await
            .map(|_| connection_id)?)
    }
}
