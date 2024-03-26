use std::{sync::Arc, time::Duration};

use dashmap::DashMap;
use instant_acme::{
    Account, AccountCredentials, Challenge, ChallengeType, Identifier, NewAccount, NewOrder, Order,
    OrderStatus,
};
use log::debug;
use rcgen::{Certificate, CertificateParams, DistinguishedName, DnType};
use rustls::{crypto, sign::CertifiedKey};
use tokio::time::sleep;

use crate::{
    error::{GatewayCertificateError, GatewayError},
    transport_services::certificate::{cache::DashMapCache, CertificateCache, CertificateStorage},
};

use super::CertificateIssue;

pub struct AcmeService {
    storage: Arc<dyn CertificateStorage + 'static + Send + Sync>,
    challenges: Arc<DashMap<(String, String), Arc<AcmeChallenges>>>, // (user, domain) -> challenges
    cache: Arc<dyn CertificateCache + Send + Sync>,
    supported_challenges: Vec<ChallengeType>,
    default_account: Account,
}

impl AcmeService {
    pub async fn new(
        storage: Arc<impl CertificateStorage + 'static + Send + Sync>,
        email: &str,
        server_url: Option<&str>,
    ) -> Result<Self, GatewayError> {
        let server_url =
            server_url.unwrap_or("https://acme-staging-v02.api.letsencrypt.org/directory");
        let default_account = match storage
            .get_default_account_credentials()
            .await
            .and_then(|s| {
                serde_json::from_str::<AccountCredentials>(&s)
                    .or(Err(GatewayCertificateError::InvalidAccount))
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
            cache: Arc::<DashMapCache>::default(),
            default_account,
            supported_challenges: vec![ChallengeType::Http01, ChallengeType::TlsAlpn01],
        })
    }
}

impl CertificateIssue for AcmeService {
    fn issue(&self, uid: &str, domain: &str, private_key: Option<Vec<u8>>) -> Option<()> {
        debug!("issue certificate for {}@{}", uid, domain);
        if self
            .challenges
            .contains_key(&(domain.to_owned(), uid.to_owned()))
        {
            return None;
        }

        let default_acme_account = self.default_account.clone();
        let supported_challenges = self.supported_challenges.clone();
        let domain = domain.to_owned();
        let uid = uid.to_owned();
        let challenges = self.challenges.clone();
        let storage = self.storage.clone();
        let cache = self.cache.clone();
        // task to issue certificate
        let _task = tokio::spawn(async move {
            let identifier = Identifier::Dns(domain.clone());
            let mut order = default_acme_account
                .new_order(&NewOrder {
                    identifiers: &[identifier],
                })
                .await
                .unwrap();
            dbg!(order.state());
            // let x = order.key_authorization(challenge);
            if matches!(order.state().status, OrderStatus::Pending) {
                storage.set_pending(&uid, &domain).await.unwrap();
            }
            // tokio_stream::wrappers::ReceiverStream::new();
            let authorizations = order.authorizations().await.unwrap();
            for authorization in authorizations {
                let Identifier::Dns(dns_identifier) = authorization.identifier;
                if dns_identifier != domain {
                    storage.set_failed(&uid, &domain).await.unwrap();
                    return;
                }
                let authorization_challenges = authorization
                    .challenges
                    .into_iter()
                    .filter(|c| supported_challenges.contains(&c.r#type))
                    .collect::<Vec<_>>();

                let acme_key_authorization =
                    AcmeChallenges::new(&domain, &order, &authorization_challenges);

                challenges.insert(
                    (uid.clone(), domain.clone()),
                    Arc::new(acme_key_authorization),
                );

                for c in authorization_challenges {
                    order.set_challenge_ready(&c.url).await;
                }
            }
            let mut tries = 1u8;
            let mut delay = Duration::from_millis(250);
            loop {
                dbg!("looping");
                Box::pin(sleep(delay)).await;
                delay *= 2;
                tries += 1;

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
            challenges.remove(&(uid.clone(), domain.clone()));
            if order.state().status != OrderStatus::Ready {
                storage.set_failed(&uid, &domain).await.unwrap();
                return;
            }
            let mut params = CertificateParams::new(vec![domain.clone()]);
            params.key_pair = private_key.and_then(|k| rcgen::KeyPair::from_der(&k).ok());
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
            storage.put_pem(&uid, &domain, pem).await.unwrap();
            let certificate_key = storage.get_certified_key(&uid, &domain).await.unwrap();
            cache.put(&uid, &domain, certificate_key);
        });
        None
    }
    fn challenge(&self, account: &str, domain: &str) -> Option<Arc<AcmeChallenges>> {
        self.challenges
            .get(&(account.to_owned(), domain.to_owned()))
            .map(|c| c.clone())
    }
    fn remove_from_cache(&self, account: &str, domain: &str) -> Option<CertifiedKey> {
        self.cache.remove(account, domain)
    }
    fn storage(&self) -> Arc<dyn CertificateStorage> {
        self.storage.clone()
    }
}

pub struct AcmeChallenges {
    http_challenge: Option<(String, String)>,
    tls_challenge: Option<CertifiedKey>,
    dns_challenge: Option<String>,
}

impl AcmeChallenges {
    fn new(domain: &str, order: &Order, challenges: &Vec<Challenge>) -> Self {
        let mut ret = Self {
            http_challenge: None,
            tls_challenge: None,
            dns_challenge: None,
        };

        for challenge in challenges {
            match challenge.r#type {
                ChallengeType::Http01 => {
                    let token = challenge.token.clone();
                    let key_authorization = order.key_authorization(challenge);
                    ret.http_challenge = Some((token, key_authorization.as_str().to_owned()));
                }
                ChallengeType::Dns01 => {
                    ret.dns_challenge =
                        Some(order.key_authorization(challenge).as_str().to_owned());
                }
                ChallengeType::TlsAlpn01 => {
                    let key_authorization = order.key_authorization(challenge);
                    let mut params = rcgen::CertificateParams::new(vec![domain.to_owned()]);
                    let mut dn = DistinguishedName::new();
                    dn.push(DnType::OrganizationName, "narrowlink");
                    params.distinguished_name = dn;
                    params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
                    params.custom_extensions = vec![rcgen::CustomExtension::new_acme_identifier(
                        key_authorization.digest().as_ref(),
                    )];
                    let cert = rcgen::Certificate::from_params(params).unwrap_or_else(|e| {
                        panic!("ACME TLS challenge certificate creation for {domain} failed - {e}")
                    });
                    let signer = crypto::ring::sign::any_supported_type(
                        &rustls::pki_types::PrivateKeyDer::from(
                            rustls::pki_types::PrivatePkcs8KeyDer::from(
                                cert.serialize_private_key_der(),
                            ),
                        ),
                    )
                    .unwrap_or_else(|e| {
                        panic!("ACME TLS challenge certificate signer creation failed - {e}")
                    });

                    let certified_key = CertifiedKey::new(
                        vec![rustls::pki_types::CertificateDer::from(
                            cert.serialize_der().unwrap_or_else(|e| {
                                panic!("ACME TLS challenge certificate serialization failed - {e}")
                            }),
                        )],
                        signer,
                    );
                    ret.tls_challenge = Some(certified_key);
                }
            }
        }
        ret
    }
    pub fn get_tls_challenge(&self) -> Option<CertifiedKey> {
        self.tls_challenge.clone()
    }
    pub fn get_http_challenge(&self) -> Option<(String, String)> {
        self.http_challenge.clone()
    }
    #[allow(dead_code)]
    pub fn get_dns_challenge(&self) -> Option<String> {
        self.dns_challenge.clone()
    }
}
