use std::{net::IpAddr, str::FromStr};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    error::MessageError,
    generic::Connect,
    policy::{self, Policy},
    GetResponse, NatType,
};

use super::{ConstSystemInfo, DynSystemInfo};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum InBound {
    Connect(Uuid, Connect, Vec<Policy>),
    IsReachable(Uuid, Connect),
    Response(usize, Response),
    Ping(u64),
    Peer2Peer(Peer2PeerInstruction),
    Shutdown,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum OutBound {
    Pong(u64),
    Ready(Uuid),
    NotSure(Uuid),
    Error(Uuid, String),
    Request(usize, Request),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum Request {
    UpdateDynamicSysInfo(DynSystemInfo),
    UpdateConstantSysInfo(ConstSystemInfo),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum Response {
    Ok,
}

impl FromStr for OutBound {
    type Err = MessageError;
    fn from_str(s: &str) -> Result<Self, <Self as FromStr>::Err> {
        Ok(serde_json::from_str(s)?)
    }
}

impl From<InBound> for Result<String, MessageError> {
    fn from(inbound: InBound) -> Self {
        serde_json::to_string(&inbound).map_err(|e| e.into())
    }
}

impl GetResponse for InBound {
    type Item = Response;

    fn response(&self) -> Option<Self::Item> {
        if let InBound::Response(_, response) = self {
            Some(response.to_owned())
        } else {
            None
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Peer2PeerInstruction {
    // Todo: policy
    pub peer_ip: IpAddr,
    pub seed_port: u16,
    pub seq: u16,
    pub peer_nat: NatType, // peer nat type
    pub nat: NatType,      // nat type
    pub cert: Vec<u8>,
    pub key: Vec<u8>,
    pub policies: Vec<policy::Policy>,
}

impl From<&Peer2PeerInstruction> for crate::Peer2PeerInstruction {
    fn from(instruction: &Peer2PeerInstruction) -> Self {
        crate::Peer2PeerInstruction {
            peer_ip: instruction.peer_ip,
            seed_port: instruction.seed_port,
            seq: instruction.seq,
            peer_nat: instruction.peer_nat,
            nat: instruction.nat,
        }
    }
}
