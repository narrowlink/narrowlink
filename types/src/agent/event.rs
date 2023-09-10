use std::{net::IpAddr, str::FromStr};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{error::MessageError, generic::Connect, policy::Policies, GetResponse};

use super::{ConstSystemInfo, DynSystemInfo};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum InBound {
    Connect(Uuid, Connect, Option<Policies>),
    IsReachable(Uuid, Connect),
    Response(usize, Response),
    Ping(u64),
    Peer2Peer(IpAddr, u16, u8, bool, bool), // peer ip, seed port, sequences, client_hard, agent_hard
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
