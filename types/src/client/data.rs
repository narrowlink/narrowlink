use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::generic::Connect;

#[derive(Debug, Serialize, Deserialize)]
pub enum OutBound {
    Connect(String, Connect),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum InBound {}

impl FromStr for OutBound {
    type Err = serde_json::Error;
    fn from_str(s: &str) -> Result<Self, <Self as FromStr>::Err> {
        serde_json::from_str(s)
    }
}
