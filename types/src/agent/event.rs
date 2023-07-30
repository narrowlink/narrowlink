use std::str::FromStr;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    error::MessageError,
    generic::{Connect, SystemInfo},
    policy::Policies,
    GetResponse,
};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum InBound {
    Connect(Uuid, Connect, Option<Policies>),
    IsReachable(Uuid, Connect),
    Response(usize, Response),
    Ping(u64),
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
    SysInfo(SystemInfo),
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
