use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::generic::{AgentInfo, Connect};

#[derive(Debug, Serialize, Deserialize)]
pub enum InBound {
    ActiveAgents(Vec<AgentInfo>),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum OutBound {
    IsReachable(Uuid, Connect),
    ListOfAgents,
}
