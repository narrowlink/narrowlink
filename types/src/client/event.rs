use std::{net::IpAddr, str::FromStr};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{error::MessageError, generic::AgentInfo, GetResponse, NatType};

use super::ConstSystemInfo;

#[derive(Debug, Serialize, Deserialize)]
pub enum OutBound {
    Request(usize, Request),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum InBound {
    Response(usize, Response),
    ConnectionError(Uuid, String),
    Peer2Peer(Peer2PeerInstruction),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Request {
    ListOfAgents(bool), // verbose
    UpdateConstantSysInfo(ConstSystemInfo),
    Peer2Peer(Peer2PeerRequest), // agent_name
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Response {
    ActiveAgents(Vec<AgentInfo>),
    Ok,
    Failed,
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
        #[allow(irrefutable_let_patterns)]
        let InBound::Response(_, response) = self
        else {
            return None;
        };
        Some(response.to_owned())
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Peer2PeerRequest {
    pub agent_name: String,
    pub easy_seed_port: u16,
    pub easy_seq: u16,
    pub hard_seed_port: u16,
    pub hard_seq: u16,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Peer2PeerInstruction {
    pub peer_ip: IpAddr,
    pub seed_port: u16,
    pub seq: u16,
    pub peer_nat: NatType, // peer nat type
    pub nat: NatType,      // nat type
    pub cert: Vec<u8>,
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
