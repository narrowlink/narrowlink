mod event;
use core::fmt::Display;
use std::net::SocketAddr;

pub use event::InBound as EventInBound;
pub use event::OutBound as EventOutBound;
pub use event::Peer2PeerInstruction;
pub use event::Request as EventRequest;
pub use event::Response as EventResponse;
use serde::Deserialize;
use serde::Serialize;

use crate::generic::Connect;
use crate::generic::Protocol;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SystemInfo {
    pub dynamic: DynSystemInfo,
    pub constant: ConstSystemInfo,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DynSystemInfo {
    pub loadavg: f64,
}

impl Default for DynSystemInfo {
    fn default() -> Self {
        Self { loadavg: 0.0 }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ConstSystemInfo {
    pub cpus: u8,
    pub local_addr: SocketAddr,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AgentPublishInfo {
    src_host: String,
    src_port: u16,
    dst_host: String,
    dst_port: u16,
    protocol: Protocol,
}

impl Display for AgentPublishInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{}->{}://{}:{}",
            self.src_host,
            if self.src_port == 0 {
                "any".to_owned()
            } else {
                self.src_port.to_string()
            },
            self.protocol,
            self.dst_host,
            self.dst_port
        )
    }
}

impl AgentPublishInfo {
    pub fn from_connect(host: String, src_port: u16, connect: &Connect) -> Self {
        Self {
            src_host: host,
            src_port,
            dst_host: connect.host.clone(),
            dst_port: connect.port,
            protocol: connect.protocol.clone(),
        }
    }
}
