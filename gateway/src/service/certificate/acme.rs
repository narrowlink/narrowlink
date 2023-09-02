use std::sync::Arc;

use instant_acme::{
    Account, AccountCredentials, Authorization, AuthorizationStatus, ChallengeType, Identifier,
    NewAccount, NewOrder, Order, OrderStatus,
};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use rustls::{PrivateKey, sign::{CertifiedKey, any_supported_type}};
use serde::Deserialize;
use tokio::time;
use tracing::{debug, instrument, trace};

use crate::error::GatewayError;

pub struct Acme {
    pub account: Account,
    authorizations: Vec<Authorization>,
    order: Option<Order>,
}

impl Clone for Acme {
    fn clone(&self) -> Self {
        Self {
            account: self.account.clone(),
            authorizations: Vec::new(),
            order: None,
        }
    }
}

pub struct ChallengeInfo {
    pub verification_url: String,
    pub domain: String,
    pub challenge: ACMEChallenge,
}
#[allow(dead_code)]
#[derive(Debug, Clone, Hash, PartialEq, Eq, Deserialize)]
pub enum ACMEChallengeType {
    Http01,
    TlsAlpn01,
}

impl Default for ACMEChallengeType {
    fn default() -> Self {
        Self::Http01
    }
}

#[derive(Clone)]
pub enum ACMEChallenge {
    Http01(String, String),
    TlsAlpn01(Arc<CertifiedKey>),
    // Dns01(String),
}

impl Acme {
    pub async fn new(
        email: &str,
        directory: &str,
    ) -> Result<(Self, AccountCredentials), GatewayError> {
        let (account, account_credentials) = Account::create(
            &NewAccount {
                contact: &[&format!("mailto:{}", email)],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            directory,
            None,
        )
        .await?;
        Ok((
            Self {
                account,
                authorizations: Vec::new(),
                order: None,
            },
            account_credentials,
        ))
    }
    pub fn from_account(account: Account) -> Result<Self, GatewayError> {
        Ok(Self {
            account,
            authorizations: Vec::new(),
            order: None,
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

        let mut order = self
            .account
            .new_order(&NewOrder {
                identifiers: &identifiers,
            })
            .await?;
        debug!("new acme order placed for {:?}", &domains);
        // let state = order.state();
        let authorizations = order.authorizations().await?;
        debug!("get acme authorization orders for {:?}", &domains);
        if authorizations.iter().any(|a| {
            !matches!(
                a.status,
                AuthorizationStatus::Pending | AuthorizationStatus::Valid
            )
        }) {
            return Err(GatewayError::ACMEFailed);
        }
        trace!("{:?}", &authorizations);
        if authorizations
            .iter()
            .any(|authorization| matches!(authorization.status, AuthorizationStatus::Valid))
        {
            let mut params = CertificateParams::new(domains);
            params.key_pair = suggested_private_key
                .and_then(|private_key| KeyPair::from_der(&private_key.0).ok());
            params.distinguished_name = DistinguishedName::new();
            let cert = rcgen::Certificate::from_params(params)?;
            let csr = cert.serialize_request_der()?;
            order.finalize(&csr).await?;
            let cert_chain_pem = loop {
                // todo
                match order.certificate().await? {
                    Some(cert_chain_pem) => break cert_chain_pem,
                    None => tokio::time::sleep(tokio::time::Duration::from_secs(1)).await,
                }
            };

            // let mut certificates = Vec::new();
            // for pem in x509_parser::prelude::Pem::iter_from_buffer(&cert_chain_pem.as_bytes()) {
            //     certificates.push(rustls::Certificate(pem?.contents));
            // }
            // let private_key = rustls::PrivateKey(cert.get_key_pair().serialize_der());
            // return Ok(Some((private_key, certificates)));
            return Ok(Some(pem::parse_many(cert_chain_pem).and_then(
                |mut c| {
                    pem::parse(cert.get_key_pair().serialize_pem()).map(|p| {
                        c.push(p);
                        c
                    })
                },
            )?));
        }

        self.order = Some(order);
        self.authorizations = authorizations;
        Ok(None)
    }

    pub fn get_tls_alpn_01_certificate_challenges(
        &self,
    ) -> Result<Vec<ChallengeInfo>, GatewayError> {
        let order = self
            .order
            .as_ref()
            .ok_or(GatewayError::ACMEOrderNotAvailable)?;
        let mut cert_tuple = Vec::new();
        trace!("{:?}", &self.authorizations);
        let challenges = self
            .authorizations
            .iter()
            .filter(|authorization| {
                matches!(
                    authorization.status,
                    AuthorizationStatus::Pending | AuthorizationStatus::Valid
                )
            })
            .flat_map(|authorization| {
                let Identifier::Dns(identifier) = &authorization.identifier;

                authorization
                    .challenges
                    .iter()
                    .filter(|challenge| challenge.r#type == ChallengeType::TlsAlpn01)
                    .map(move |challenge| {
                        (
                            &challenge.url,
                            identifier,
                            order
                                .key_authorization(challenge)
                                .digest()
                                .as_ref()
                                .to_vec(),
                        )
                    })
            })
            .collect::<Vec<(&String, &String, Vec<u8>)>>();

        for (verification_url, domain, digest) in challenges {
            trace!("{}", domain);
            let mut params = rcgen::CertificateParams::new(vec![domain.to_owned()]);
            let mut dn = DistinguishedName::new();
            dn.push(DnType::OrganizationName, "narrowlink");
            params.distinguished_name = dn;
            params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
            params.custom_extensions = vec![rcgen::CustomExtension::new_acme_identifier(&digest)];
            let cert = rcgen::Certificate::from_params(params)?;

            // let mut server_config = rustls::ServerConfig::builder()
            //     .with_safe_defaults()
            //     .with_no_client_auth()
            //     .with_single_cert(
            //         vec![rustls::Certificate(cert.serialize_der()?)],
            //         rustls::PrivateKey(cert.get_key_pair().serialize_der()),
            //     )?;
            // server_config
            //     .alpn_protocols
            //     .push(crate::service::certificate::ACME_TLS_ALPN_NAME.to_vec());
            let Ok(key) = any_supported_type(&rustls::PrivateKey(cert.get_key_pair().serialize_der()))else{
                return Err(GatewayError::Invalid("Invalid private key from rcgen"));
            };

            
            cert_tuple.push(ChallengeInfo {
                verification_url: verification_url.to_string(),
                domain: domain.to_string(),
                challenge: ACMEChallenge::TlsAlpn01(Arc::new(CertifiedKey::new(vec![rustls::Certificate(cert.serialize_der()?)], key))),
            });
        }

        Ok(cert_tuple)
    }

    pub fn get_http_01_certificate_challenges(&self) -> Result<Vec<ChallengeInfo>, GatewayError> {
        let order = self
            .order
            .as_ref()
            .ok_or(GatewayError::ACMEOrderNotAvailable)?;
        let mut cert_tuple = Vec::new();
        let challenges = self
            .authorizations
            .iter()
            .filter(|authorization| matches!(authorization.status, AuthorizationStatus::Pending))
            .flat_map(|authorization| {
                let Identifier::Dns(identifier) = &authorization.identifier;
                authorization
                    .challenges
                    .iter()
                    .filter(|challenge| challenge.r#type == ChallengeType::Http01)
                    .map(move |challenge| {
                        (
                            &challenge.url,
                            identifier,
                            ACMEChallenge::Http01(
                                challenge.token.clone(),
                                order.key_authorization(challenge).as_str().to_string(),
                            ),
                        )
                    })
            })
            .collect::<Vec<(&String, &String, ACMEChallenge)>>();

        for (verification_url, domain, challenge) in challenges {
            cert_tuple.push(ChallengeInfo {
                verification_url: verification_url.to_string(),
                domain: domain.to_string(),
                challenge,
            });
        }
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
        let mut domain = Vec::new();
        for challenge in challenges {
            order
                .set_challenge_ready(&challenge.verification_url)
                .await?;
            domain.push(challenge.domain.clone());
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
        let mut params = CertificateParams::new(domain);
        params.key_pair =
            suggested_private_key.and_then(|private_key| KeyPair::from_der(&private_key.0).ok());
        params.distinguished_name = DistinguishedName::new();
        let cert = rcgen::Certificate::from_params(params)?;
        let csr = cert.serialize_request_der()?;
        order.finalize(&csr).await?;
        trace!("acme certificate finalized");
        let cert_chain_pem = loop {
            match order.certificate().await? {
                Some(cert_chain_pem) => break cert_chain_pem,
                None => tokio::time::sleep(tokio::time::Duration::from_secs(1)).await,
            }
        };
        trace!("acme certificate received");

        Ok(pem::parse_many(cert_chain_pem).and_then(|mut c| {
            pem::parse(cert.get_key_pair().serialize_pem()).map(|p| {
                c.push(p);
                c
            })
        })?)
        // for pem in x509_parser::prelude::Pem::iter_from_buffer(&cert_chain_pem.as_bytes()) {
        //     certificates.push(rustls::Certificate(pem?.contents));
        // }
        // let private_key = rustls::PrivateKey(cert.get_key_pair().serialize_der());
        // Ok((private_key, certificates))
    }
}
