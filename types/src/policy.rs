use std::net::IpAddr;

use regex_lite::Regex;
use serde::{Deserialize, Serialize};
use validator::{Validate, ValidationError, ValidationErrors};
use wildmatch::WildMatch;

use crate::generic::{Connect, Protocol};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum Target {
    Any,
    Agent(String),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum PolicyItem {
    Domain(Target, String, u16, Protocol),
    Ip(Target, ipnet::IpNet, u16, Protocol),
}
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum PolicyType {
    BlackList,
    WhiteList,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Policy {
    #[serde(rename = "type")]
    pub policy_type: PolicyType,
    pub policies: Vec<PolicyItem>,
}

impl Policy {
    pub fn permit(&self, con: &Connect) -> bool {
        let contains = self.policies.iter().any(|p| p.contains(con));
        match self.policy_type {
            PolicyType::BlackList => !contains,
            PolicyType::WhiteList => contains,
        }
    }
    pub fn is_agent_visible(&self, peer_agent_name: &str) -> bool {
        self.policies.iter().any(|p| {
            let target = match p {
                PolicyItem::Domain(t, _, _, _) => t,
                PolicyItem::Ip(t, _, _, _) => t,
            };
            target == &Target::Any || target == &Target::Agent(peer_agent_name.to_string())
        })
    }
    pub fn retain_ip(&mut self) {
        self.policies
            .retain(|p| matches!(p, PolicyItem::Ip(_, _, _, _)));
    }
    pub fn agent_policies(&self, peer_agent_name: &str) -> Self {
        Self {
            policy_type: self.policy_type.clone(),
            policies: self
                .policies
                .iter()
                .filter(|p| {
                    let target = match p {
                        PolicyItem::Domain(t, _, _, _) => t,
                        PolicyItem::Ip(t, _, _, _) => t,
                    };
                    target == &Target::Any || target == &Target::Agent(peer_agent_name.to_string())
                })
                .cloned()
                .collect(),
        }
    }
}

impl Validate for Policy {
    fn validate(&self) -> Result<(), ValidationErrors> {
        for policy in self.policies.iter() {
            policy.validate()?;
        }
        Ok(())
    }
}

impl PolicyItem {
    pub fn contains(&self, con: &Connect) -> bool {
        let (address_status, policy_port, protocol) = match self {
            Self::Domain(_, domain, policy_port, protocol) => (
                // todo: check ip address of domain
                WildMatch::new(domain).matches(&con.host),
                policy_port,
                protocol,
            ),
            Self::Ip(_, ip, port, protocol) => (
                if let Ok(state) = con.host.parse::<IpAddr>().map(|addr| ip.contains(&addr)) {
                    state
                } else {
                    false
                },
                port,
                protocol,
            ),
        };

        address_status
            && (policy_port == &con.port || policy_port == &0)
            && protocol == &con.protocol
    }
}

impl Validate for PolicyItem {
    fn validate(&self) -> Result<(), ValidationErrors> {
        if let PolicyItem::Domain(_agent_id, addr, _port, _protocol) = self {
            if let Ok(re) = Regex::new(r"^[^.][a-z0-9-.*?]{1,256}$") {
                if re.is_match(addr) {
                    return Ok(());
                }
            }
            let mut err = ValidationErrors::new();
            err.add("Domain", ValidationError::new("Invalid Domain Name"));
            return Err(err);
        }
        Ok(())
    }
}
