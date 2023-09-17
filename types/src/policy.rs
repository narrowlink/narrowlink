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

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Policy {
    pub permit: bool,
    pub policies: Vec<PolicyItem>,
}

impl Policy {
    pub fn permit(&self, peer_agent_name: &str, con: &Connect) -> bool {
        if self
            .policies
            .iter()
            .any(|p| p.contains(peer_agent_name, con))
        {
            self.permit
        } else {
            !self.permit
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
    pub fn contains(&self, peer_agent_name: &str, con: &Connect) -> bool {
        // let (addr, port) = &con.addr;
        let (target, address_status, policy_port, protocol) = match self {
            // Self::Any(agent_name, policy_type) => {
            //     if peer_agent_name == agent_name.as_ref().map(|an| an.as_str())
            //         || agent_name.is_none()
            //     {
            //         return *policy_type;
            //     } else {
            //         return false;
            //     }
            // }
            Self::Domain(target, domain, policy_port, protocol) => (
                target,
                WildMatch::new(domain).matches(domain),
                policy_port,
                protocol,
            ),
            Self::Ip(target, ip, port, protocol) => (
                target,
                if let Ok(state) = con.host.parse::<IpAddr>().map(|addr| ip.contains(&addr)) {
                    state
                } else {
                    false
                },
                port,
                protocol,
            ),
        };

        (target == &Target::Any || target == &Target::Agent(peer_agent_name.to_string()))
            && address_status
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
