use std::net::IpAddr;

use regex::Regex;
use serde::{Deserialize, Serialize};
use validator::{Validate, ValidationError, ValidationErrors};
use wildmatch::WildMatch;

use crate::generic::{Connect, Protocol};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum Policy {
    Any(Option<String>, bool),
    Domain(Option<String>, String, u16, Protocol),
    Ip(Option<String>, ipnet::IpNet, u16, Protocol),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Policies {
    pub permit: bool,
    pub policies: Vec<Policy>,
}

impl Policies {
    pub fn permit(&self, peer_agent_name: Option<&str>, con: &Connect) -> bool {
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
    pub fn retain_ip(&mut self) {
        self.policies
            .retain(|p| matches!(p, Policy::Ip(_, _, _, _)));
    }
}

impl Validate for Policies {
    fn validate(&self) -> Result<(), ValidationErrors> {
        for policy in self.policies.iter() {
            policy.validate()?;
        }
        Ok(())
    }
}

impl Policy {
    pub fn contains(&self, peer_agent_name: Option<&str>, con: &Connect) -> bool {
        // let (addr, port) = &con.addr;
        let (agent_name, address_status, policy_port, protocol) = match self {
            Self::Any(agent_name, policy_type) => {
                if peer_agent_name == agent_name.as_ref().map(|an| an.as_str())
                    || agent_name.is_none()
                {
                    return *policy_type;
                } else {
                    return false;
                }
            }
            Self::Domain(agent_name, domain, policy_port, protocol) => (
                agent_name,
                WildMatch::new(domain).matches(domain),
                policy_port,
                protocol,
            ),
            Self::Ip(agent_name, ip, port, protocol) => (
                agent_name,
                if let Ok(state) = con.host.parse::<IpAddr>().map(|addr| ip.contains(&addr)) {
                    state
                } else {
                    false
                },
                port,
                protocol,
            ),
        };

        (peer_agent_name == agent_name.as_ref().map(|an| an.as_str()) || agent_name.is_none())
            && address_status
            && (policy_port == &con.port || policy_port == &0)
            && protocol == &con.protocol
    }
}

impl Validate for Policy {
    fn validate(&self) -> Result<(), ValidationErrors> {
        if let Policy::Domain(_agent_id, addr, _port, _protocol) = self {
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
