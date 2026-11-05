use std::sync::Arc;

use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, NewAccount,
    NewOrder, Order, OrderStatus,
};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use rustls::{ServerConfig, pki_types::PrivatePkcs8KeyDer};
type PrivateKey = PrivatePkcs8KeyDer<'static>;
use serde::Deserialize;
use tokio::time;
use tracing::{debug, instrument, trace};

use crate::error::GatewayError;

pub struct Acme {
    pub account: Account,
    challenges: Vec<(String, String, ChallengeType, String, Vec<u8>, String)>,
    order: Option<Order>,
    domains: Vec<String>,
}

impl Clone for Acme {
    fn clone(&self) -> Self {
        Self {
            account: self.account.clone(),
            challenges: Vec::new(),
            order: None,
            domains: Vec::new(),
        }
    }
}

#[derive(Debug)]
pub struct ChallengeInfo {
    pub verification_url: String,
    pub domain: String,
    pub challenge: ACMEChallenge,
}
#[allow(dead_code)]
#[derive(Debug, Clone, Hash, PartialEq, Eq, Deserialize, Default)]
pub enum ACMEChallengeType {
    #[default]
    Http01,
    TlsAlpn01,
}

#[derive(Debug, Clone)]
pub enum ACMEChallenge {
    Http01(String, String),
    TlsAlpn01(Arc<ServerConfig>),
    // Dns01(String),
}

impl Acme {
    pub async fn new(
        email: &str,
        directory: &str,
    ) -> Result<(Self, AccountCredentials), GatewayError> {
        let (account, account_credentials) = Account::builder()?
            .create(
                &NewAccount {
                    contact: &[&format!("mailto:{}", email)],
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                },
                directory.to_string(),
                None,
            )
            .await?;
        Ok((
            Self {
                account,
                challenges: Vec::new(),
                order: None,
                domains: Vec::new(),
            },
            account_credentials,
        ))
    }
    pub fn from_account(account: Account) -> Result<Self, GatewayError> {
        Ok(Self {
            account,
            challenges: Vec::new(),
            order: None,
            domains: Vec::new(),
        })
    }
    #[instrument(name = "acme::new_order", skip(self))]
    pub async fn new_order(
        &mut self,
        domains: Vec<String>,
        suggested_private_key: Option<&PrivateKey>,
    ) -> Result<Option<Vec<pem::Pem>>, GatewayError> {
        debug!("place new acme order for {:?}", &domains);
        let identifiers = domains
            .iter()
            .map(|name| Identifier::Dns(name.into()))
            .collect::<Vec<_>>();

        let mut order = self.account.new_order(&NewOrder::new(&identifiers)).await?;
        debug!("new acme order placed for {:?}", &domains);
        // let state = order.state();
        let mut challenges = Vec::new();
        let mut all_valid = true;
        {
            for kind in [ChallengeType::Http01, ChallengeType::TlsAlpn01] {
                let mut authorizations = order.authorizations();
                while let Some(authorization) = authorizations.next().await {
                    let mut authorization = authorization?;
                    if !matches!(
                        authorization.status,
                        AuthorizationStatus::Pending | AuthorizationStatus::Valid
                    ) {
                        return Err(GatewayError::ACMEFailed);
                    }
                    if authorization.status == AuthorizationStatus::Valid {
                        continue;
                    }
                    all_valid = false;
                    let domain = authorization.identifier().to_string();
                    if let Some(challenge) = authorization.challenge(kind.clone()) {
                        let key = challenge.key_authorization();
                        challenges.push((
                            challenge.url.clone(),
                            domain.clone(),
                            kind.clone(),
                            key.as_str().to_string(),
                            key.digest().as_ref().to_vec(),
                            challenge.token.clone(),
                        ));
                    }
                }
            }
        }
        if all_valid {
            return Ok(Some(
                finalize_order(&mut order, domains, suggested_private_key).await?,
            ));
        }
        self.challenges = challenges;
        self.domains = domains;
        self.order = Some(order);
        Ok(None)
    }

    pub fn get_tls_alpn_01_certificate_challenges(
        &self,
    ) -> Result<Vec<ChallengeInfo>, GatewayError> {
        if self.order.is_none() {
            return Err(GatewayError::ACMEOrderNotAvailable);
        }
        let mut cert_tuple = Vec::new();
        for (verification_url, domain, kind, _, digest, _) in &self.challenges {
            if *kind != ChallengeType::TlsAlpn01 {
                continue;
            }
            let mut params = rcgen::CertificateParams::new(vec![domain.to_owned()])?;
            let mut dn = DistinguishedName::new();
            dn.push(DnType::OrganizationName, "narrowlink");
            params.distinguished_name = dn;
            params.custom_extensions = vec![rcgen::CustomExtension::new_acme_identifier(digest)];
            let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
            let cert = params.self_signed(&key)?;
            let mut server_config = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(
                    vec![cert.der().clone()],
                    rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
                )?;
            server_config
                .alpn_protocols
                .push(crate::service::certificate::ACME_TLS_ALPN_NAME.to_vec());
            cert_tuple.push(ChallengeInfo {
                verification_url: verification_url.clone(),
                domain: domain.clone(),
                challenge: ACMEChallenge::TlsAlpn01(Arc::new(server_config)),
            });
        }
        Ok(cert_tuple)
    }

    pub fn get_http_01_certificate_challenges(&self) -> Result<Vec<ChallengeInfo>, GatewayError> {
        if self.order.is_none() {
            return Err(GatewayError::ACMEOrderNotAvailable);
        }
        let cert_tuple = self
            .challenges
            .iter()
            .filter(|(_, _, kind, _, _, _)| *kind == ChallengeType::Http01)
            .map(|(url, domain, _, key, _, token)| ChallengeInfo {
                verification_url: url.clone(),
                domain: domain.clone(),
                challenge: ACMEChallenge::Http01(token.clone(), key.clone()),
            })
            .collect();
        Ok(cert_tuple)
    }

    pub async fn check_challenge(
        &mut self,
        challenges: Vec<ChallengeInfo>,
        tries: u8,
        delay: u64,
        suggested_private_key: Option<&PrivateKey>,
    ) -> Result<Vec<pem::Pem>, GatewayError> {
        let order = self
            .order
            .as_mut()
            .ok_or(GatewayError::ACMEOrderNotAvailable)?;
        let domains = self.domains.clone();
        {
            for kind in [ChallengeType::Http01, ChallengeType::TlsAlpn01] {
                let mut authorizations = order.authorizations();
                while let Some(authorization) = authorizations.next().await {
                    let mut authorization = authorization?;
                    if let Some(mut handle) = authorization.challenge(kind.clone())
                        && let Some(challenge) =
                            challenges.iter().find(|c| c.verification_url == handle.url)
                    {
                        handle.set_ready().await?;
                        let _ = challenge;
                    }
                }
            }
        }
        let mut tries_counter = 1;
        let mut delay = std::time::Duration::from_millis(delay);

        let state = loop {
            trace!("waiting for acme verification");
            time::sleep(delay).await;
            let state = order.refresh().await?;

            if let OrderStatus::Ready | OrderStatus::Invalid = state.status {
                // dbg!("order state: {:#?}", &state);
                break state;
            }

            delay *= 2;
            tries_counter += 1;
            if tries_counter > tries {
                trace!("acme verification timeout");
                return Err(GatewayError::ACMEVerificationTimeOut);
            }
        };
        if state.status == OrderStatus::Invalid {
            trace!("acme verification failed");
            return Err(GatewayError::ACMEVerificationFailed);
        }
        trace!("acme verification successful");
        finalize_order(order, domains, suggested_private_key).await
    }
}

async fn finalize_order(
    order: &mut Order,
    domains: Vec<String>,
    suggested_private_key: Option<&PrivateKey>,
) -> Result<Vec<pem::Pem>, GatewayError> {
    let mut params = CertificateParams::new(domains)?;
    params.distinguished_name = DistinguishedName::new();
    let key = match suggested_private_key.and_then(|key| KeyPair::try_from(key).ok()) {
        Some(key) => key,
        None => KeyPair::generate()?,
    };
    let csr = params.serialize_request(&key)?;
    order.finalize_csr(csr.der()).await?;
    let cert_chain_pem = loop {
        match order.certificate().await? {
            Some(chain) => break chain,
            None => tokio::time::sleep(tokio::time::Duration::from_secs(1)).await,
        }
    };
    let mut chain = pem::parse_many(cert_chain_pem)?;
    chain.push(pem::parse(key.serialize_pem())?);
    Ok(chain)
}
