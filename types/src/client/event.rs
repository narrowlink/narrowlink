use std::{net::IpAddr, str::FromStr};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{error::MessageError, generic::AgentInfo, GetResponse};

use super::ConstSystemInfo;

#[derive(Debug, Serialize, Deserialize)]
pub enum OutBound {
    Request(usize, Request),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum InBound {
    Response(usize, Response),
    ConnectionError(Uuid, String),
    Peer2Peer(IpAddr, u16, u8, bool, bool), // peer ip, seed port, sequences, client_hard, agent_hard
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Request {
    ListOfAgents(bool), // verbose
    UpdateConstantSysInfo(ConstSystemInfo),
    Peer2Peer(String), // agent_name
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
