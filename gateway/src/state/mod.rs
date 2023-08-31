use futures_util::StreamExt;
use std::{net::SocketAddr, str::FromStr};
use uuid::Uuid;
mod agent;
mod client;
mod connection;
mod users;
use crate::{
    service::{ServiceDataRequest, ServiceEventRequest},
    state::connection::AgentConnection,
    CONNECTION_ORIANTED,
};
use narrowlink_network::{error::NetworkError, event::NarrowEvent, UniversalStream};
use narrowlink_types::token::{AgentPublishToken, AgentToken, ClientToken};
use narrowlink_types::{
    agent::{
        EventInBound as AgentEventInBound, EventOutBound as AgentEventOutBound,
        EventRequest as AgentEventRequest, EventResponse as AgentEventResponse,
    },
    client::{
        DataOutBound as ClientDataOutBound, EventInBound as ClientEventInBound,
        EventOutBound as ClientEventOutBound, EventRequest as ClientEventRequest,
        EventResponse as ClientEventResponse,
    },
};
use tokio::{
    io::AsyncWriteExt,
    net::TcpStream,
    select,
    sync::{
        mpsc::{self, UnboundedReceiver, UnboundedSender},
        oneshot,
    },
};
use tracing::{debug, info, instrument, trace, Instrument};

pub struct State {
    #[allow(dead_code)]
    name: String,
    client_token: Vec<u8>,
    agent_token: Vec<u8>,
    message_receiver: UnboundedReceiver<InBound>,
    message_sender: UnboundedSender<InBound>,
    certificate_manager: std::option::Option<
        UnboundedSender<crate::service::certificate::manager::CertificateServiceMessage>,
    >,
}

pub enum InBound {
    EventRequest(
        ServiceEventRequest,
        oneshot::Receiver<Box<dyn UniversalStream<String, NetworkError>>>,
        SocketAddr,
        Option<String>, // Forward address
        oneshot::Sender<Result<ResponseHeaders, ResponseErrors>>,
    ),
    DataRequest(
        ServiceDataRequest,
        oneshot::Receiver<Box<dyn UniversalStream<Vec<u8>, NetworkError>>>,
        SocketAddr,
        Option<String>, // Forward address
        oneshot::Sender<Result<ResponseHeaders, ResponseErrors>>,
    ),
    HttpTransparent(
        String,                                                                //domain_name
        hyper::Request<hyper::Body>,                                           //request
        SocketAddr,                                                            //peer_addr
        oneshot::Sender<Result<hyper::Response<hyper::Body>, ResponseErrors>>, //response
        u16,                                                                   // service port
    ),
    TlsTransparent(
        String,    //sni
        TcpStream, //stream
        u16,       // service port
    ),
}
pub struct ResponseHeaders {
    pub(crate) session: Option<Uuid>,
    pub(crate) connection: Option<Uuid>,
}

#[derive(Debug)]
pub enum ResponseErrors {
    Unauthorized,
    Forbidden,
    NotAcceptable(Option<&'static str>),
    NotFound(Option<&'static str>),
}

impl State {
    #[instrument(name = "state::run", skip(self))]
    pub async fn run(&mut self) {
        trace!("state running");
        let mut users = users::Users::new();
        let mut client_types = futures_util::stream::SelectAll::new();
        let mut agent_types = futures_util::stream::SelectAll::new();
        let certificate_manager = self.certificate_manager.take();
        loop {
            select! (
                Some(client_types) = client_types.next()=>{
                    let (uid, session, msg): (Uuid,Uuid,Result<ClientEventOutBound, NetworkError>) = client_types;
                    let client_event_message_span = tracing::span!(tracing::Level::TRACE, "client_message", user_id = uid.to_string(), client_session = session.to_string());
                    let _agent_data_gaurd = client_event_message_span.enter();

                    match msg{
                        Ok(ClientEventOutBound::Request(request_id,req))=>{
                            debug!("Client Message {}: {:?}", request_id, req);
                            match req {
                                ClientEventRequest::ListOfAgents(verbose)=>{
                                    let agents = users.get_agents_info(uid,verbose);
                                    if let Some(client) = users.get_mut_client(uid,session){
                                        let _ = client.send(ClientEventInBound::Response(request_id,ClientEventResponse::ActiveAgents(agents))).await;
                                    }
                                }
                            }
                        }
                        Err(_e)=>{
                            users.del_client(uid,session);
                            info!("Client {}:{} disconnected", uid, session);
                            // dbg!((e as NetworkError).to_string());
                        }
                    }
                },
                Some(agent_types) = agent_types.next()=>{
                    let (uid, name, msg, peer_socket_addr): (Uuid, String, Result<narrowlink_types::agent::EventOutBound, NetworkError>, std::net::SocketAddr) = agent_types;
                    let client_event_message_span = tracing::span!(tracing::Level::TRACE, "agent_message", user_id = uid.to_string(), agent_name = name);
                    let _agent_data_gaurd = client_event_message_span.enter();
                    trace!("Agent Message Received: {:?}", msg);
                    match msg{
                        Ok(AgentEventOutBound::Ready(_id))=>{},
                        Ok(AgentEventOutBound::NotSure(_id))=>{},
                        Ok(AgentEventOutBound::Error(id, err))=>{
                            if let Some(client) = users.del_connection(uid,id).and_then(|c|c.session_id).and_then(|s|users.get_mut_client(uid, s)) {
                                client.send(ClientEventInBound::ConnectionError(id,err.to_string())).await.ok();
                            }
                        },
                        Ok(AgentEventOutBound::Request(request_id, request))=>{
                            if let Some(agent) = users.get_mut_agent(uid,name){
                                match request{
                                    AgentEventRequest::SysInfo(load)=>{
                                        if let Ok(ts) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH){
                                            let _ = agent.send(AgentEventInBound::Ping(ts.as_millis() as u64)).await;
                                        }
                                        agent.sysupdate(load);
                                        let _ = agent.send(AgentEventInBound::Response(request_id,AgentEventResponse::Ok)).await;
                                        continue
                                    }
                                }
                            }
                        },
                        Ok(AgentEventOutBound::Pong(v)) =>{
                            let Ok(ping_time) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|now|now.saturating_sub(std::time::Duration::from_millis(v)).as_millis() as u16) else{
                                continue
                            };
                            if let Some(agent) = users.get_mut_agent(uid,name){
                                agent.pingupdate(ping_time)
                            }
                        },
                        Err(e)=>{
                            if let Some(agent) = users.del_agent(uid,&name){
                                if agent.socket_addr != peer_socket_addr{
                                    users.add_agent(uid, agent);
                                    continue
                                }
                            }
                            info!("Agent {}:{} disconnected",uid, name);
                            debug!("Agent disconnected due to {}",(e as NetworkError).to_string());
                            if let Some(cm_sender) = certificate_manager.as_ref() {
                                let _ = cm_sender.send(crate::service::certificate::manager::CertificateServiceMessage::Unload(uid.to_string(),name));
                            }
                        }
                    }
                },
                message = self.message_receiver.recv() =>{
                    match message{
                        Some(InBound::EventRequest(
                            ServiceEventRequest {
                                token,
                                publish,
                            },
                            stream_receiver,
                            peer_socket_addr,
                            peer_forward_addr,
                            response,
                        )) => {
                            let event_span = tracing::span!(tracing::Level::TRACE, "event", peer_addr = %peer_socket_addr, peer_forward_addr = ?peer_forward_addr);
                            let _event_gaurd = event_span.enter();
                            trace!("Event Request Received");
                            // debug!("Client Event Received");
                            //Client Event
                            //todo client request acl
                            if let Ok(client_token) = ClientToken::from_str(&token, &self.client_token) {
                                let client_event_span = tracing::span!(tracing::Level::TRACE, "client", user_id = %client_token.uid, client_name = %client_token.name);
                                let _client_event_gaurd = client_event_span.enter();
                                trace!("Client Token Verification Success");
                                let Some(policies) = client_token.policies else
                                {
                                    trace!("client token does not have any policy");
                                    let _ = response.send(Err(ResponseErrors::Unauthorized));
                                    continue
                                };

                                let session = Uuid::new_v4();
                                client_event_span.record("session_id", session.to_string());
                                if response.send(Ok(ResponseHeaders{session:Some(session),connection:None})).is_err(){
                                    continue
                                }
                                trace!("Waiting for client event stream");
                                let Ok(stream) = stream_receiver.await else{
                                    continue
                                };
                                let stream:NarrowEvent<ClientEventInBound,ClientEventOutBound> = NarrowEvent::from(stream);
                                let (sender, receiver) = stream.split();

                                //policy todo
                                info!("Client {}:{}:{} ({}) added", client_token.uid, client_token.name, session,peer_socket_addr);
                                users.add_client(client_token.uid,client::Client::new(client_token.name, session,policies, sender));
                                client_types.push(receiver.map(move |f| (client_token.uid, session, f)));

                            } else {
                                debug!("Agent Event Received");
                                //Agent Event
                                // TOKEN.read().map_err(|_| ()).and_then(|t| {
                                //     AgentToken::from_str(token, &t.clone().into_iter().rev().collect::<Vec<u8>>())
                                //         .map_err(|_| ())
                                // }) else{

                                let Ok(agent_token) =
                                AgentToken::from_str(&token, &self.agent_token) else
                                {
                                    let _ = response.send(Err(ResponseErrors::Unauthorized));
                                    continue
                                };
                                let agent_event_span = tracing::span!(tracing::Level::TRACE, "agent", user_id = %agent_token.uid, agent_name = %agent_token.name);
                                let _agent_event_gaurd = agent_event_span.enter();

                                if response.send(Ok(ResponseHeaders{session:None,connection:None})).is_err(){
                                    continue
                                }
                                trace!("Waiting for agent event stream");
                                let Ok(stream) = stream_receiver.await else{
                                    continue
                                };
                                let stream:NarrowEvent<AgentEventInBound,AgentEventOutBound> = NarrowEvent::from(stream);
                                let (sender, receiver) = stream.split();


                                let mut publish_hosts = Vec::new();

                                if let Some(publish_token) = publish.and_then(|publish_token| {
                                    AgentPublishToken::from_str(&publish_token, &self.agent_token).ok()
                                }) {
                                    trace!("Publish Token Verification");
                                    if publish_token.uid == agent_token.uid && publish_token.name == agent_token.name{
                                        trace!("Publish Token Verification Success");
                                        debug!("Publish token address {:?}",publish_token.publish_hosts);
                                        publish_hosts.extend(publish_token.publish_hosts);
                                    }
                                };
                                if !publish_hosts.is_empty() {
                                    if let Some(cm_sender) = certificate_manager.as_ref() {
                                        let cert_required_connect = publish_hosts.iter().filter(|ph|matches!(ph.connect.protocol, narrowlink_types::generic::Protocol::HTTP | narrowlink_types::generic::Protocol::HTTPS | narrowlink_types::generic::Protocol::QUIC));
                                        // cert_required_connect.map(|ph|ph.host);
                                        let hosts = cert_required_connect.map(|ph|ph.host.clone());
                                        info!("Loading new certificate for {:?}",hosts);
                                        let _ = cm_sender.send(crate::service::certificate::manager::CertificateServiceMessage::Load(
                                            agent_token.uid.to_string(),
                                            agent_token.name.to_owned(),
                                            Vec::from_iter(hosts),
                                        ));
                                    }
                                }
                                let agent_name = agent_token.name.clone();
                                agent_types.push(receiver.map(move |f| (agent_token.uid, agent_name.to_owned(), f,peer_socket_addr)));
                                if let Some(mut privous_agent) = users.add_agent(agent_token.uid,agent::Agent::new(agent_token.name.to_owned(),publish_hosts,peer_socket_addr,peer_forward_addr,sender)) {
                                    info!("Previous agent {}:{} ({}) disconnected",agent_token.uid,privous_agent.name,peer_socket_addr);
                                    let _ = privous_agent.send(AgentEventInBound::Shutdown).await;
                                }

                                info!("Agent {}:{} ({}) added",agent_token.uid,agent_token.name,peer_socket_addr);
                            }
                        }
                        Some(InBound::DataRequest(
                            ServiceDataRequest {
                                token,
                                command,
                                session,
                                connection,
                                connecting_address
                            },
                            socket_receiver,
                            peer_socket_addr,
                            forward_address,
                            response
                        )) => {
                            let data_span = tracing::span!(tracing::Level::TRACE, "data", peer_addr = %peer_socket_addr, forward_addr = ?forward_address);
                            let _data_gaurd = data_span.enter();
                            trace!("Data Request Received");
                            if let Some(command) = command {
                                //Client Data
                                let Ok(client_token) =
                                ClientToken::from_str(&token, &self.client_token) else
                                {
                                    let _ = response.send(Err(ResponseErrors::Unauthorized));
                                    continue
                                };
                                let client_data_span = tracing::span!(tracing::Level::TRACE, "client", user_id = %client_token.uid, client_name = %client_token.name);
                                let _client_data_gaurd = client_data_span.enter();
                                let Some(session) = session.and_then(|s|Uuid::from_str(&s).ok())else{
                                    let _ = response.send(Err(ResponseErrors::NotAcceptable(None)));
                                    continue
                                };
                                client_data_span.record("session_id", session.to_string());
                                let Ok(ClientDataOutBound::Connect(agent_name, connect)) = ClientDataOutBound::from_str(&command) else {
                                    debug!("command is not valid: {}",command);
                                    let _ = response.send(Err(ResponseErrors::NotAcceptable(None)));
                                    continue
                                };
                                let connection_id = Uuid::new_v4();
                                client_data_span.record("connection_id", connection_id.to_string());

                                let Some(client_policy) = users.get_client_policy(client_token.uid,session) else
                                {
                                    let _ = response.send(Err(ResponseErrors::NotAcceptable(Some("Event connection is lost"))));
                                    continue
                                };

                                if client_policy.permit(Some(&agent_name), &connect){
                                    debug!("Client {}:{} connect to {}:{:?} forbidden",client_token.uid,session,agent_name,connect);
                                    debug!("{:?}",client_policy);
                                    let _ = response.send(Err(ResponseErrors::Forbidden));
                                    continue
                                };
                                debug!("Client policy: {:?}",client_policy);

                                let Some(agent) = users.get_mut_agent(client_token.uid,agent_name.clone()) else{
                                    debug!("Agent {}:{} not found",client_token.uid,agent_name);
                                    let _ = response.send(Err(ResponseErrors::NotFound(Some("The requested agent could not be found"))));
                                    continue
                                };

                                let response = if CONNECTION_ORIANTED {
                                    if response.send(Ok(ResponseHeaders{session:Some(session),connection:Some(connection_id)})).is_err(){
                                            continue
                                        }
                                    None
                                }else{
                                    Some(response)
                                };


                                let connection = connection::Connection::new(connection_id, Some(session), Some(connection::ClientConnection::Client(response,socket_receiver)), None,Some(client_policy));

                                debug!("Connection to {}:{} with agent {} added to pool",connect.host,connect.port, agent_name);
                                let _ = agent.send(AgentEventInBound::Connect(connection_id, connect, None)).await;
                                users.add_connection(client_token.uid,connection);
                            } else {
                                //Agent Data
                                let Ok(agent_token) =
                                AgentToken::from_str(&token, &self.agent_token) else
                                {
                                    let _ = response.send(Err(ResponseErrors::Unauthorized));
                                    continue
                                };
                                let Some(connected_address) = connecting_address.as_ref().and_then(|addr|narrowlink_types::generic::Connect::from_schemaed_string(addr)) else {
                                    debug!("connecting address is not valid: {:?}",connecting_address);
                                    let _ = response.send(Err(ResponseErrors::NotAcceptable(None)));
                                    continue
                                };
                                let agent_data_span = tracing::span!(tracing::Level::TRACE, "agent", user_id = %agent_token.uid, agent_name = %agent_token.name, connected_address = ?connected_address);
                                let _agent_data_gaurd = agent_data_span.enter();

                                let Some(connection) = connection.as_ref().and_then(|c|Uuid::from_str(c).ok())else{
                                    debug!("connection id is not valid: {:?}",connection);
                                    let _ = response.send(Err(ResponseErrors::NotAcceptable(None)));
                                    continue
                                };
                                agent_data_span.record("connection_id", connection.to_string());

                                let Some(mut requested_connection) = users.get_mut_connection(agent_token.uid,connection)else{
                                    debug!("Connection {}:{} not found",agent_token.uid,connection);
                                    let _ = response.send(Err(ResponseErrors::NotFound(Some("The requested connection could not be found"))));
                                    continue
                                };
                                if let Some(policy) = requested_connection.take_policy(){
                                    debug!("Connection policy: {:?}",policy);
                                    if !policy.permit(Some(&agent_token.name), &connected_address){
                                        let _ = response.send(Err(ResponseErrors::Forbidden));
                                        if let Some(client_response) = requested_connection.take_client_socket(){
                                            let _ = client_response.send(Err(ResponseErrors::Forbidden));
                                        }
                                        trace!("Access denied due to policy violation");
                                        //todo client event notify
                                        continue
                                    }
                                }
                                let response = if CONNECTION_ORIANTED {
                                    if response.send(Ok(ResponseHeaders{session:requested_connection.session_id,connection:Some(connection)})).is_err(){
                                            continue
                                        }
                                    None
                                }else{
                                    Some(response)
                                };
                                // requested_connection.session_id;
                                debug!("Connection to client with session id {:?} added to pool",requested_connection.session_id);
                                requested_connection.set_agent_socket(AgentConnection::Agent(response,socket_receiver));
                                tokio::spawn(async move {
                                    trace!("Connection forwading started");
                                    requested_connection.data.serve().in_current_span().await.unwrap_or_else(|e| {
                                        debug!("Connection Error: {}", e);
                                    });
                                }.in_current_span());
                            }
                        }
                        Some(InBound::HttpTransparent(domain_name,request,peer_addr,response,service_port))=>{
                            match users.get_mut_agent_by_domain(&domain_name,service_port){ //todo
                                Some(Ok((user_id,agent,connect)))=>{
                                    let connection = Uuid::new_v4();
                                    debug!("HttpTransparent Connection ({}) Request to {} with {} address Received", connection,domain_name,peer_addr);
                                    let _ = agent.send(AgentEventInBound::Connect(connection, connect, None)).await;
                                    users.add_connection(user_id, connection::Connection::new(connection,None,Some(connection::ClientConnection::HttpTransparent(request,peer_addr,response)),None,None));
                                }
                                None | Some(Err(()))=>{
                                    debug!("Unoccupied HttpTransparent Connection Request to {} with {} address Rejected", domain_name,peer_addr);
                                    let _ = response.send(Err(ResponseErrors::NotFound(None)));
                                }
                            }
                        }
                        Some(InBound::TlsTransparent(sni,mut stream,service_port))  =>{
                            if let Some(Ok((user_id,agent,connect))) = users.get_mut_agent_by_domain(&sni,service_port){ //todo
                                if connect.protocol == narrowlink_types::generic::Protocol::TCP{
                                    let connection = Uuid::new_v4();
                                    debug!("TlsTransparent Connection ({}) Request to {} with {:?} address Received", connection,sni,stream.peer_addr());
                                    let _ = agent.send(AgentEventInBound::Connect(connection, connect, None)).await;
                                    users.add_connection(user_id, connection::Connection::new(connection,None,Some(connection::ClientConnection::TlsTransparent(stream)),None,None));
                                    continue
                                }
                            }
                            debug!("Unoccupied TlsTransparent Connection Request to {} with {:?} address Rejected", sni,stream.peer_addr());
                            stream.shutdown().await.ok();
                        }
                        None => todo!(),

                    }
                }
            );
        }
    }
    pub fn get_sender(&self) -> UnboundedSender<InBound> {
        self.message_sender.clone()
    }
    pub fn from(
        conf: &crate::config::Config,
        certificate_manager: std::option::Option<
            UnboundedSender<crate::service::certificate::manager::CertificateServiceMessage>,
        >,
    ) -> Self {
        let (message_sender, message_receiver) = mpsc::unbounded_channel::<InBound>();
        Self {
            name: conf.name.to_owned(),
            client_token: conf.secret.clone(),
            agent_token: conf.secret.clone().into_iter().rev().collect::<Vec<u8>>(),
            message_receiver,
            message_sender,
            certificate_manager,
        }
    }
}

// pub enum StateQuery {
//     SNIProxy(String),
// }
// pub enum StateAsnwer {

// }
// struct StateQueryManager {
//     sender: UnboundedSender<(StateQuery, oneshot::Sender<StateAsnwer>)>,
// }

// impl StateQueryManager {
//     fn new() -> (
//         Self,
//         UnboundedReceiver<(StateQuery, oneshot::Sender<StateAsnwer>)>,
//     ) {
//         let (sender, receiver) =
//             mpsc::unbounded_channel::<(StateQuery, oneshot::Sender<StateAsnwer>)>();
//         (Self { sender }, receiver)
//     }
//     async fn query(&self, state_query: StateQuery) -> StateAsnwer {
//         let (sender, receiver) = oneshot::channel();
//         let _ = self.sender.send((state_query, sender));
//         receiver.await.unwrap()
//     }
// }

// impl From<&crate::config::Config> for State {
//     fn from(conf: &crate::config::Config,certificate_manage:u8) -> Self {
//         let (message_sender, message_receiver) = mpsc::unbounded_channel::<InBound>();
//         Self {
//             name: conf.name.to_owned(),
//             client_token: conf.secret.clone(),
//             agent_token: conf.secret.clone().into_iter().rev().collect::<Vec<u8>>(),
//             message_receiver,
//             message_sender,
//         }
//     }
// }
