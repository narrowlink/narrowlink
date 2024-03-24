use std::{
    collections::HashMap,
    sync::{mpsc::Receiver, Arc},
    time::Duration,
};

use dashmap::DashMap;
use futures::{
    future::{select, SelectAll},
    stream::futures_unordered,
    StreamExt,
};
use instant_acme::{
    Account, AccountCredentials, Authorization, Challenge, ChallengeType, Identifier,
    KeyAuthorization, NewAccount, NewOrder, Order, OrderStatus,
};
use log::debug;
use rcgen::{Certificate, CertificateParams, DistinguishedName, DnType};
use rustls::{crypto, sign::CertifiedKey, CertificateError};
use tokio::{
    sync::{
        mpsc::{self, UnboundedReceiver, UnboundedSender},
        oneshot,
    },
    time::sleep,
};

use crate::{
    error::{CertificateError as GWCertificateError, GatewayError},
    transport_services::certificate::{
        CertificateCache, CertificateResolver, CertificateStorage, DashMapCache,
    },
};

use super::{CertificateIssue, CertificateIssueStatus};

pub struct AcmeService {
    storage: Arc<dyn CertificateStorage + 'static + Send + Sync>,
    challenges: Arc<DashMap<(String, String), Arc<AcmeKeyAuthorization>>>, // (user, domain) -> challenges
    cache: Arc<dyn CertificateCache + Send + Sync>,
    default_account: Account,
}

// impl !Send for AcmeService<'_> {}

impl AcmeService {
    pub async fn new(
        storage: Arc<impl CertificateStorage + 'static + Send + Sync>,
        email: &str,
        server_url: Option<&str>,
    ) -> Result<Self, GatewayError> {
        let server_url =
            server_url.unwrap_or("https://acme-staging-v02.api.letsencrypt.org/directory");
        let account = match storage
            .get_default_account_credentials()
            .await
            .and_then(|s| {
                serde_json::from_str::<AccountCredentials>(&s)
                    .map_err(|_| GWCertificateError::InvalidAccount.into())
            }) {
            Ok(account_credentials) => Account::from_credentials(account_credentials)
                .await
                .unwrap(),
            Err(_) => {
                let (account, account_credentials) = Account::create(
                    &NewAccount {
                        contact: &[&format!("mailto:{}", email)],
                        terms_of_service_agreed: true,
                        only_return_existing: false,
                    },
                    server_url,
                    None,
                )
                .await
                .unwrap();

                storage
                    .set_default_account_credentials(
                        &serde_json::to_string(&account_credentials).unwrap(),
                    )
                    .await
                    .unwrap();
                account
            }
        };

        Ok(Self {
            storage,
            challenges: Default::default(),
            cache: Arc::new(DashMapCache::default()),
            default_account: account,
        })
    }
}

impl CertificateIssue for AcmeService {
    fn issue(&self, account: &str, domain: &str) -> Option<()> {
        debug!("issue certificate for {}@{}", account, domain);
        if self
            .challenges
            .contains_key(&(domain.to_owned(), account.to_owned()))
        {
            return None;
        }
        let default_account = self.default_account.clone();
        let domain = domain.to_owned();
        let account = account.to_owned();
        let challenges = self.challenges.clone();
        let storage = self.storage.clone();
        let cache = self.cache.clone();
        // task to issue certificate
        let task = tokio::spawn(async move {
            let identifier = Identifier::Dns(domain.clone());
            let mut order = default_account
                .new_order(&NewOrder {
                    identifiers: &[identifier],
                })
                .await
                .unwrap();
            dbg!(order.state());
            // let x = order.key_authorization(challenge);
            if matches!(order.state().status, OrderStatus::Pending) {
                storage.set_pending(&account, &domain).await.unwrap();
            }
            // tokio_stream::wrappers::ReceiverStream::new();
            let mut status_receiver = futures::stream::SelectAll::new();
            let authorizations = order.authorizations().await.unwrap();
            for authorization in authorizations {
                let Identifier::Dns(dns_identifier) = authorization.identifier;
                if dns_identifier != domain {
                    storage.set_failed(&account, &domain).await.unwrap();
                    return;
                }
                let (acme_key_authorization, receiver) = AcmeKeyAuthorization::new(
                    authorization
                        .challenges
                        .iter()
                        .map(|c| (order.key_authorization(c), c.token.clone(), c.r#type))
                        .collect::<Vec<_>>(),
                );
                status_receiver.push(tokio_stream::wrappers::UnboundedReceiverStream::new(
                    receiver,
                ));
                challenges.insert(
                    (account.clone(), domain.clone()),
                    Arc::new(acme_key_authorization),
                );

                for c in &authorization.challenges {
                    if c.r#type != ChallengeType::TlsAlpn01 {
                        continue;
                    }
                    dbg!(&c);
                    order.set_challenge_ready(&c.url).await;
                }
            }
            let mut tries = 1u8;
            let mut delay = Duration::from_millis(250);
            loop {
                dbg!("looping");
                if matches!(
                    select(status_receiver.select_next_some(), Box::pin(sleep(delay))).await,
                    futures::future::Either::Right(_)
                ) {
                    // delay *= 2;
                    tries += 1;
                }
                dbg!("refreshing");
                let state = order.refresh().await.unwrap();
                dbg!(state);

                if let OrderStatus::Ready | OrderStatus::Invalid = state.status {
                    break;
                }
                if tries > 5 {
                    {
                        todo!();
                        return;
                    }
                }
            }
            challenges.remove(&(account.clone(), domain.clone()));
            if order.state().status != OrderStatus::Ready {
                storage.set_failed(&account, &domain).await.unwrap();
                return;
            }
            let mut params = CertificateParams::new(vec![domain.clone()]);
            params.distinguished_name = DistinguishedName::new();
            let cert = Certificate::from_params(params).unwrap();
            let csr = cert.serialize_request_der().unwrap();
            order.finalize(&csr).await.unwrap();
            let cert_chain_pem = loop {
                match order.certificate().await.unwrap() {
                    Some(cert_chain_pem) => break cert_chain_pem,
                    None => sleep(Duration::from_secs(1)).await,
                }
            };

            let pem = pem::parse_many(cert_chain_pem)
                .and_then(|mut c| {
                    pem::parse(cert.get_key_pair().serialize_pem()).map(|p| {
                        c.push(p);
                        c
                    })
                })
                .unwrap();
            storage.put_pem(&account, &domain, None, pem).await.unwrap();
            let certificate_key = storage
                .get_certificate_key(&account, &domain)
                .await
                .unwrap();
            cache.put(&account, &domain, certificate_key);
        });
        None
    }
    fn challenge(&self, account: &str, domain: &str) -> Option<Arc<AcmeKeyAuthorization>> {
        self.challenges
            .get(&(account.to_owned(), domain.to_owned()))
            .map(|c| c.clone())
    }
    fn remove_from_cache(&self,account: &str,domain: &str) -> Option<CertifiedKey> {
        self.cache.remove(account, domain)
    }
    fn storage(&self) -> Arc<dyn CertificateStorage> {
        self.storage.clone()
    }
}

pub struct AcmeKeyAuthorization {
    key_authorization: Vec<(KeyAuthorization, String, ChallengeType)>,
    sender: mpsc::UnboundedSender<()>,
}

impl AcmeKeyAuthorization {
    fn new(
        key_authorization: Vec<(KeyAuthorization, String, ChallengeType)>,
    ) -> (Self, mpsc::UnboundedReceiver<()>) {
        let (sender, receiver) = mpsc::unbounded_channel();
        (
            Self {
                key_authorization,
                sender,
            },
            receiver,
        )
    }
    pub fn get_tls_challenge(&self, domain: &str) -> Option<CertifiedKey> {
        for (key_authorization, token, challenge_type) in &self.key_authorization {
            if *challenge_type == ChallengeType::TlsAlpn01 {
                let mut params = rcgen::CertificateParams::new(vec![domain.to_owned()]);
                let mut dn = DistinguishedName::new();
                dn.push(DnType::OrganizationName, "narrowlink");
                params.distinguished_name = dn;
                params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
                params.custom_extensions = vec![rcgen::CustomExtension::new_acme_identifier(
                    key_authorization.digest().as_ref(),
                )];
                let cert = rcgen::Certificate::from_params(params).unwrap();
                let signer = crypto::ring::sign::any_supported_type(
                    &rustls::pki_types::PrivateKeyDer::from(
                        rustls::pki_types::PrivatePkcs8KeyDer::from(
                            cert.serialize_private_key_der(),
                        ),
                    ),
                )
                .unwrap();
                let certified_key = CertifiedKey::new(
                    vec![rustls::pki_types::CertificateDer::from(
                        cert.serialize_der().unwrap(),
                    )],
                    signer,
                );
                self.sender.send(());
                return Some(certified_key);
            }
        }
        None
    }
    // fn get_http_key_authorization(&self) -> Option<HashMap<String, String>> {
    //     let mut map = HashMap::new();
    //     for (key_authorization, challenge_type) in &self.key_authorization {
    //         if *challenge_type == ChallengeType::Http01 {
    //             map.insert(
    //                 key_authorization.digest().to_string(),
    //                 key_authorization.to_string(),
    //             );
    //         }
    //     }
    //     Some(map)
    // }
}
