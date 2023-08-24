use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Duration,
};

use instant_acme::Account;
use rustls::{PrivateKey, ServerConfig};
use tracing::{debug, error, instrument, span, trace, Instrument, Span};

use tokio::{
    sync::{
        mpsc::{self, UnboundedSender},
        RwLock,
    },
    time,
};

use super::{
    acme::{ACMEChallenge, Acme},
    ACMEChallengeType, Certificate, CertificateStorage,
};
use crate::error::GatewayError;

pub enum CertificateServiceMessage {
    Load(String, String, Vec<String>),
    Unload(String, String),
}

pub struct CertificateStore {
    certificates: HashMap<(String, String), Certificate>,
    domain_map: HashMap<String, HashSet<(String, String)>>,
}

impl CertificateStore {
    pub fn new() -> Self {
        Self {
            certificates: HashMap::new(),
            domain_map: HashMap::new(),
        }
    }
    pub fn insert(
        &mut self,
        uid: String,
        agent_name: String,
        domains: &Vec<String>,
        certificate: Certificate,
    ) {
        self.certificates
            .insert((uid.clone(), agent_name.clone()), certificate);
        for domain in domains {
            if let Some(agent_set) = self.domain_map.get_mut(domain) {
                agent_set.insert((uid.clone(), agent_name.clone()));
            } else {
                let mut agent_set = HashSet::new();
                agent_set.insert((uid.clone(), agent_name.clone()));
                self.domain_map.insert(domain.to_string(), agent_set);
            }
        }
    }
    pub fn remove(&mut self, uid: String, agent_name: String) {
        let _ = self.certificates.remove(&(uid.clone(), agent_name.clone()));
        for (_, agent_set) in self.domain_map.iter_mut() {
            let _ = agent_set.remove(&(uid.clone(), agent_name.clone()));
        }
        self.domain_map.retain(|_, v| !v.is_empty());
        trace!("domain map: {:?}", self.domain_map);
    }
    pub fn get_config(&self, domain: &str) -> Option<Arc<ServerConfig>> {
        Some(
            self.certificates
                .get(self.domain_map.get(domain)?.iter().next()?)?
                .config
                .clone(),
        )
    }
    pub fn renew_needed(&self) -> Vec<(String, String, Vec<String>)> {
        let mut list_of_agents = Vec::new();
        for ((uid, agent_name), cert) in self.certificates.iter() {
            if cert.renew_needed() {
                if let Some(domains) = cert.domains() {
                    list_of_agents.push((uid.to_owned(), agent_name.to_owned(), domains));
                }
            }
        }
        list_of_agents
    }
}

pub struct CertificateManager {
    certificate_store: Arc<RwLock<CertificateStore>>,
    acme_configurations: Arc<RwLock<HashMap<String, ACMEChallenge>>>,
    acme_type: Option<ACMEChallengeType>,
    acme_account: Option<Account>,
    storage: Arc<dyn CertificateStorage + Sync + Send>,
    sender: UnboundedSender<CertificateServiceMessage>,
    handler: Option<tokio::task::JoinHandle<()>>,
}

impl Clone for CertificateManager {
    fn clone(&self) -> Self {
        Self {
            certificate_store: self.certificate_store.clone(),
            // configurations: self.configurations.clone(),
            acme_configurations: self.acme_configurations.clone(),
            acme_type: self.acme_type.clone(),
            acme_account: self.acme_account.clone(),
            storage: self.storage.clone(),
            sender: self.sender.clone(),
            handler: None,
        }
    }
}

impl CertificateManager {
    #[instrument(name = "certificate_manager::new", skip(storage))]
    pub async fn new(
        storage: Arc<dyn CertificateStorage + Sync + Send>,
        acme_info: Option<(String, ACMEChallengeType, String)>,
    ) -> Result<Self, GatewayError> {
        let certificate_store = Arc::new(RwLock::new(CertificateStore::new()));
        let acme_configurations = Arc::new(RwLock::new(HashMap::new()));
        let (sender, mut receiver) = mpsc::unbounded_channel::<CertificateServiceMessage>();

        let mut res = if let Some(acme_info) = acme_info {
            if !validator::validate_email(&acme_info.0) {
                trace!("invalid email");
                return Err(GatewayError::Invalid("email"));
            }
            let account = if let Ok(account) = storage.get_default_account().await {
                trace!("default account found");
                account
            } else {
                trace!("crate new ACME account");
                let (acme, account_credentials) = Acme::new(&acme_info.0, &acme_info.2).await?;
                storage
                    .set_default_account_credentials(account_credentials)
                    .await?;
                acme.account
            };
            Self {
                certificate_store,
                acme_configurations,
                acme_type: Some(acme_info.1),
                acme_account: Some(account),
                storage,
                sender: sender.clone(),
                handler: None,
            }
        } else {
            Self {
                certificate_store,
                acme_configurations,
                acme_type: None,
                acme_account: None,
                storage,
                sender: sender.clone(),
                handler: None,
            }
        };
        let cm = res.clone();
        res.handler = Some(tokio::spawn(
            async move {
                let sender: UnboundedSender<CertificateServiceMessage> = sender.clone();
                let mut interval = time::interval(Duration::from_secs(60 * 60 * 6)); // every six hours
                loop {
                    tokio::select! {
                        Some(msg) = receiver.recv() =>{
                            match msg {
                                CertificateServiceMessage::Load(uid, agent_name, domains) => {
                                    let span = span!(tracing::Level::TRACE, "load_certificate", uid = %uid, agent_name = %agent_name, domains = ?domains);
                                    if cm
                                        .load_to_memory(&uid, &agent_name, &domains).instrument(span.clone())
                                        .await
                                        .is_err()
                                        && cm.is_acme_enabled()
                                    {
                                        if let Err(e) =
                                            cm.issue(&uid, &agent_name, &domains, None).instrument(span.clone()).await
                                        {
                                            error!(
                                                "unable to issue certificate for: {:?} : {}",
                                                &domains,
                                                e.to_string()
                                            );
                                        }
                                        trace!("load certificate to memory");
                                        let _ = cm.load_to_memory(&uid, &agent_name, &domains).instrument(span.clone()).await;
                                    }
                                },
                                CertificateServiceMessage::Unload(uid, agent_name) => {
                                    let span = span!(tracing::Level::TRACE, "unload_certificate", uid = %uid, agent_name = %agent_name);
                                    trace!("unload certificate from memory");
                                    cm.unload_from_memory(&uid, &agent_name).instrument(span).await;
                                }
                            }
                        }
                        _ = interval.tick() =>{
                            for (uid,agent_name,domains) in cm.certificate_store.read().await.renew_needed(){
                                debug!("renew required for certificate {:?} in agent {}:{}", &domains, uid, agent_name);
                                let _ = sender.send(CertificateServiceMessage::Load(uid,agent_name,domains));
                            }
                        }
                    }
                }
            }.in_current_span()
        ));

        Ok(res)
    }
    pub fn is_acme_enabled(&self) -> bool {
        self.acme_type.is_some()
    }
    pub fn acme_type(&self) -> Option<ACMEChallengeType> {
        self.acme_type.clone()
    }
    pub fn get_service_sender(&self) -> UnboundedSender<CertificateServiceMessage> {
        self.sender.clone()
    }
    #[instrument(name = "issue_acme_certificate", skip(self))]
    pub async fn issue(
        &self,
        uid: &str,
        agent_name: &str,
        domains: &Vec<String>,
        suggested_private_key: Option<PrivateKey>,
    ) -> Result<(), GatewayError> {
        debug!("start to issue acme certificate for {:?}", &domains);
        // we can create acme account for each agent later
        let (Some(acme_account), Some(challenge_type)) = (
            self.storage
                .get_acme_account(uid, agent_name)
                .await
                .ok()
                .or(self.acme_account.clone()),
            self.acme_type.clone(),
        ) else {
            trace!("acme is disabled");
            return Err(GatewayError::ACMEIsDisabled);
        };

        let mut acme = Acme::from_account(acme_account.clone())?;
        trace!("place order");
        if let Some(pem) = acme
            .new_order(
                domains.iter().map(|d| d.to_string()).collect(),
                suggested_private_key.as_ref(),
            )
            .in_current_span()
            .await?
        {
            trace!("order placed, withouth challenge");
            self.storage.put(uid, agent_name, None, pem).await?;
            return Ok(());
        }
        trace!("order placed, require challenge");

        let challenges = match challenge_type {
            ACMEChallengeType::Http01 => acme.get_http_01_certificate_challenges()?,
            ACMEChallengeType::TlsAlpn01 => acme.get_tls_alpn_01_certificate_challenges()?,
        };
        let mut challenge_domains = Vec::new();

        for challenge in challenges.iter() {
            {
                self.acme_configurations
                    .write()
                    .await
                    .insert(challenge.domain.clone(), challenge.challenge.clone());
            }
            challenge_domains.push(challenge.domain.clone());
        }

        let uid = uid.to_owned();
        let agent_name = agent_name.to_owned();
        let success = 'status: {
            trace!("check challenge status");
            let Ok(pem) = acme
                .check_challenge(challenges, 5, 10 * 1000, suggested_private_key.as_ref())
                .in_current_span()
                .await
            else {
                break 'status false;
            };
            if self
                .storage
                .put(&uid, &agent_name, None, pem)
                .await
                .is_err()
            {
                break 'status false;
            };

            true
        };

        {
            let mut acme_configurations = self.acme_configurations.write().await;
            for challenge_domain in challenge_domains {
                let _acme_challenge = acme_configurations.remove(&challenge_domain);
            }
        }

        if success {
            Ok(())
        } else {
            Err(GatewayError::ACMEFailed)
        }
    }

    pub async fn load_to_memory(
        &self,
        uid: &str,
        agent_name: &str,
        domains: &Vec<String>,
    ) -> Result<(), GatewayError> {
        let (cert, _) = self.storage.get(uid, agent_name).await?;
        if cert.renew_needed() {
            trace!("certificate renewal required");
            return Err(GatewayError::CertificateRenewalRequired);
        }

        {
            self.certificate_store.write().await.insert(
                uid.to_owned(),
                agent_name.to_owned(),
                domains,
                cert,
            );
        }
        Ok(())
    }

    pub async fn unload_from_memory(&self, uid: &str, agent_name: &str) {
        debug!("unload certificate");
        self.certificate_store
            .write()
            .await
            .remove(uid.to_owned(), agent_name.to_owned());
    }

    pub async fn get(&self, domain: &str) -> Result<Arc<ServerConfig>, GatewayError> {
        self.certificate_store
            .read()
            .await
            .get_config(domain)
            .ok_or(GatewayError::CertificateNotFound)
    }
    #[instrument(name = "get_acme_tls_challenge", skip(self))]
    pub async fn get_acme_tls_challenge(
        &self,
        domain: &str,
    ) -> Result<Arc<ServerConfig>, GatewayError> {
        trace!("get acme tls challenge");
        self.acme_configurations
            .read()
            .await
            .get(domain)
            .ok_or({
                trace!("acme http challenge for this domain not found");
                GatewayError::CertificateNotFound
            })
            .and_then(|challenge_info| {
                if let ACMEChallenge::TlsAlpn01(conf) = challenge_info {
                    trace!("acme http challenge found");
                    Ok(conf)
                } else {
                    trace!("acme http challenge not found for this challenge not found");
                    Err(GatewayError::CertificateNotFound)
                    // improve error
                }
            })
            .cloned()
    }
    #[instrument(name = "get_acme_http_challenge", skip(self))]
    pub async fn get_acme_http_challenge(
        &self,
        domain: &str,
    ) -> Result<(String, String), GatewayError> {
        Span::current().record("challenge_domain", domain);
        trace!("get acme http challenge");
        self.acme_configurations
            .read()
            .await
            .get(domain)
            .ok_or({
                trace!("acme http challenge for this domain not found");
                GatewayError::ACMEChallengeNotFound
            })
            .and_then(|challenge_info| {
                if let ACMEChallenge::Http01(token, key_authorization) = challenge_info {
                    trace!("acme http challenge found");
                    Ok((token.to_owned(), key_authorization.to_owned()))
                } else {
                    trace!("acme http challenge not found for this challenge not found");
                    Err(GatewayError::ACMEChallengeNotFound)
                }
            })
    }
}
