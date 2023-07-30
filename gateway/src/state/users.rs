use std::collections::HashMap;

use narrowlink_types::{
    generic::{AgentInfo, Connect},
    policy::Policies,
};
use uuid::Uuid;

use super::{agent::Agent, client::Client, connection::Connection};

pub struct User {
    agents: HashMap<String, Agent>,
    clients: HashMap<Uuid, Client>,
    connections: HashMap<Uuid, Connection>,
}

impl User {
    pub fn new() -> Self {
        Self {
            agents: HashMap::new(),
            clients: HashMap::new(),
            connections: HashMap::new(),
        }
    }
    pub fn add_agent(&mut self, agent: Agent) -> Option<Agent> {
        self.agents.insert(agent.name(), agent)
    }
    pub fn add_client(&mut self, client: Client) -> Option<Client> {
        self.clients.insert(client.get_session_id(), client)
    }
    pub fn add_connection(&mut self, connection: Connection) -> Option<Connection> {
        self.connections.insert(connection.get_id(), connection)
    }
    pub fn del_agent(&mut self, agent_name: &str) -> Option<Agent> {
        self.agents.remove(agent_name)
    }
    pub fn del_client(&mut self, client_id: Uuid) -> Option<Client> {
        self.clients.remove(&client_id)
    }
    pub fn del_connection(&mut self, connection_id: Uuid) -> Option<Connection> {
        self.connections.remove(&connection_id)
    }
    pub fn get_mut_agent(&mut self, agent_name: String) -> Option<&mut Agent> {
        self.agents.get_mut(&agent_name)
    }
    pub fn get_mut_client(&mut self, client_id: Uuid) -> Option<&mut Client> {
        self.clients.get_mut(&client_id)
    }
    pub fn get_client(&self, client_id: Uuid) -> Option<&Client> {
        self.clients.get(&client_id)
    }
    pub fn get_mut_connection(&mut self, connection_id: Uuid) -> Option<Connection> {
        self.connections.remove(&connection_id)
    }
    pub fn is_empty(&self) -> bool {
        self.agents.is_empty()
    }
    pub fn get_mut_agent_by_domain(
        &mut self,
        domain_name: &str,
        port: u16,
    ) -> Option<(&mut Agent, Connect)> {
        let port = if self
            .agents
            .values()
            .any(|agent| agent.domain(domain_name, port).is_some())
        {
            port
        } else {
            0
        };

        self.agents
            .values_mut()
            .filter(|agent| agent.domain(domain_name, port).is_some())
            .min_by(|x, y| {
                if let (Some(l), Some(r)) = (x.system_info.as_ref(), y.system_info.as_ref()) {
                    (l.loadavg / l.cpus as f64)
                        .partial_cmp(&(r.loadavg / r.cpus as f64))
                        .unwrap_or(std::cmp::Ordering::Equal)
                } else {
                    std::cmp::Ordering::Equal
                }
            })
            .and_then(|agent| {
                let connect = agent
                    .domain(domain_name, port)
                    .or(agent.domain(domain_name, 0))?;
                Some((agent, connect))
            })
    }
}

pub struct Users {
    users: HashMap<Uuid, User>,
    domains: HashMap<String, HashMap<u16, Uuid>>,
}

impl Users {
    pub fn new() -> Self {
        Self {
            users: HashMap::new(),
            domains: HashMap::new(),
        }
    }
    pub fn add_user(&mut self, user_id: Uuid, user: User) -> Option<User> {
        self.users.insert(user_id, user)
    }
    pub fn add_agent(&mut self, user_id: Uuid, agent: Agent) -> Option<Agent> {
        for (domain_name, pub_info) in &agent.publish_map {
            for port in pub_info.keys() {
                self.domains
                    .entry(domain_name.clone())
                    .or_insert_with(HashMap::new)
                    .insert(*port, user_id);
                // self.domains.entry(domain_name.to_owned()).
            }
        }

        match self.users.get_mut(&user_id) {
            Some(user) => user.add_agent(agent),
            None => {
                let mut user = User::new();
                user.add_agent(agent);
                self.add_user(user_id, user);
                None
            }
        }
    }
    pub fn add_client(&mut self, user_id: Uuid, client: Client) -> Option<Client> {
        match self.users.get_mut(&user_id) {
            Some(user) => user.add_client(client),
            None => {
                let mut user = User::new();
                user.add_client(client);
                self.add_user(user_id, user);
                None
            }
        }
    }
    pub fn add_connection(&mut self, user_id: Uuid, connection: Connection) -> Option<Connection> {
        match self.users.get_mut(&user_id) {
            Some(user) => user.add_connection(connection),
            None => {
                let mut user = User::new();
                user.add_connection(connection);
                self.add_user(user_id, user);
                None
            }
        }
    }
    pub fn get_mut_agent(&mut self, user_id: Uuid, agent_name: String) -> Option<&mut Agent> {
        self.users
            .get_mut(&user_id)
            .and_then(|a| a.get_mut_agent(agent_name))
    }
    pub fn get_mut_agent_by_domain(
        &mut self,
        domain_name: &str,
        port: u16,
    ) -> Option<Result<(Uuid, &mut Agent, Connect), ()>> {
        let agent_pairs = self.domains.get(domain_name)?;
        let user_id = agent_pairs.get(&port).or(agent_pairs.get(&0))?; // 0 is default port
        let user = self.users.get_mut(user_id)?;

        Some(
            if let Some((agent, connect)) = user.get_mut_agent_by_domain(domain_name, port) {
                Ok((*user_id, agent, connect))
            } else {
                Err(())
            },
        )
    }

    pub fn get_mut_client(&mut self, user_id: Uuid, client_id: Uuid) -> Option<&mut Client> {
        self.users
            .get_mut(&user_id)
            .and_then(|u| u.get_mut_client(client_id))
    }

    pub fn get_mut_connection(&mut self, user_id: Uuid, connection_id: Uuid) -> Option<Connection> {
        self.users
            .get_mut(&user_id)
            .and_then(|u| u.get_mut_connection(connection_id))
    }

    pub fn del_agent(&mut self, user_id: Uuid, agent_name: &str) -> Option<Agent> {
        let user = self.users.get_mut(&user_id)?;
        let agent = user.del_agent(agent_name)?;
        for (domain_name, pub_info) in &agent.publish_map {
            for port in pub_info.keys() {
                if user.get_mut_agent_by_domain(domain_name, *port).is_none() {
                    let agent_pairs = self.domains.get_mut(domain_name)?;
                    let _ = agent_pairs.remove(port);
                    if agent_pairs.is_empty() {
                        let _ = self.domains.remove(domain_name);
                    }
                    // let _ = self.domains.remove(&(domain_name.clone(), *port));
                }
            }
        }
        // for domain in agent.domains.keys() {
        //     if user.get_mut_agent_by_domain(domain).is_none() {
        //         let _ = self.domains.remove(domain);
        //     }
        // }
        if user.is_empty() {
            let _ = self.users.remove(&user_id);
        };
        Some(agent)
    }

    pub fn del_client(&mut self, user_id: Uuid, client_id: Uuid) -> Option<Client> {
        let user = self.users.get_mut(&user_id)?;
        let client = user.del_client(client_id)?;

        if user.is_empty() {
            let _ = self.users.remove(&user_id);
        };
        Some(client)
    }

    pub fn del_connection(&mut self, user_id: Uuid, connection_id: Uuid) -> Option<Connection> {
        let user = self.users.get_mut(&user_id)?;
        let res = user.del_connection(connection_id);
        if user.is_empty() {
            let _ = self.users.remove(&user_id);
        };
        res
    }
    // pub fn len(&self) -> usize {
    //     self.users.len()
    // }
    pub fn get_agents_info(&self, user_id: Uuid, verbose: bool) -> Vec<AgentInfo> {
        let mut ret = Vec::new();
        if let Some(user) = self.users.get(&user_id) {
            let agents = user.agents.values();
            for agent in agents {
                ret.push(AgentInfo {
                    name: agent.name.clone(),
                    socket_addr: agent.socket_addr.to_string(),
                    forward_addr: agent.forward_addr.clone(),
                    system_info: agent.system_info.as_ref().filter(|_| verbose).cloned(),
                    since: agent.since,
                    ping: agent.ping,
                })
            }
        }
        ret
    }
    pub fn get_client_policy(&self, user_id: Uuid, session: Uuid) -> Option<Policies> {
        self.users
            .get(&user_id)
            .and_then(|u| u.get_client(session))
            .map(|c| c.get_policy())
    }
    // pub fn check_client_policy(
    //     &self,
    //     user_id: Uuid,
    //     session: Uuid,
    //     agent_name: &str,
    //     connection: &Connect,
    // ) -> bool {
    //     // let Ok(session) = Uuid::from_str(&session) else{
    //     //     return false
    //     // };
    //     let Some(client) = self.users
    //     .get(&user_id)
    //     .and_then(|u| u.get_client(session))else{return false};
    //     let policies = client.get_policy();
    //     policies.permit(&Some(agent_name.to_owned()), connection)
    // }
}
