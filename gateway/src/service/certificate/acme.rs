use std::sync::Arc;

use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, Identifier, NewOrder, Order, OrderStatus,
};
use rcgen::{CertificateParams, DistinguishedName};
use rustls::ServerConfig;
use serde::Deserialize;
use tokio::time;
use tracing::{debug, instrument, trace};

use crate::error::GatewayError;

pub struct Acme {
    pub account: Account,
    challenges: Vec<ChallengeInfo>,
    order: Option<Order>,
}

impl Clone for Acme {
    fn clone(&self) -> Self {
        Self {
            account: self.account.clone(),
            challenges: Vec::new(),
            order: None,
        }
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
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
#[allow(dead_code)]
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
        let contact = format!("mailto:{}", email);
        let (account, account_credentials) = instant_acme::Account::builder()
            .map_err(|e| {
                tracing::error!("ACME Error: {:?}", e);
                GatewayError::ACMEFailed
            })?
            .create(
                &instant_acme::NewAccount {
                    contact: &[&contact],
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                },
                directory.to_string(),
                None,
            )
            .await
            .map_err(|e| {
                tracing::error!("ACME Error: {:?}", e);
                GatewayError::ACMEFailed
            })?;
        Ok((
            Self {
                account,
                challenges: Vec::new(),
                order: None,
            },
            account_credentials,
        ))
    }
    pub fn from_account(account: Account) -> Result<Self, GatewayError> {
        Ok(Self {
            account,
            challenges: Vec::new(),
            order: None,
        })
    }
    #[instrument(name = "acme::new_order", skip(self))]
    pub async fn new_order(
        &mut self,
        domains: Vec<String>,
        suggested_private_key: Option<&rustls::pki_types::PrivateKeyDer<'_>>,
        challenge_type: &super::ACMEChallengeType,
    ) -> Result<Option<Vec<pem::Pem>>, GatewayError> {
        debug!("place new acme order for {:?}", &domains);
        let identifiers = domains
            .iter()
            .map(|name| Identifier::Dns(name.into()))
            .collect::<Vec<_>>();

        let mut order = self.account.new_order(&NewOrder::new(&identifiers)).await?;
        debug!("new acme order placed for {:?}", &domains);
        let mut has_invalid = false;
        let mut any_valid = false;
        let mut challenges = Vec::new();

        {
            let mut auths_stream = order.authorizations();
            while let Some(auth) = auths_stream.next().await {
                let mut auth = auth.map_err(|e| {
                    tracing::error!("ACME Error: {:?}", e);
                    GatewayError::ACMEFailed
                })?;
                if !matches!(
                    auth.status,
                    AuthorizationStatus::Pending | AuthorizationStatus::Valid
                ) {
                    has_invalid = true;
                }
                if matches!(auth.status, AuthorizationStatus::Valid) {
                    any_valid = true;
                } else {
                    let identifier = auth.identifier().to_string();
                    let has_tls = auth
                        .challenges
                        .iter()
                        .any(|c| c.r#type == instant_acme::ChallengeType::TlsAlpn01);
                    let has_http = auth
                        .challenges
                        .iter()
                        .any(|c| c.r#type == instant_acme::ChallengeType::Http01);

                    if *challenge_type == super::ACMEChallengeType::TlsAlpn01 && has_tls {
                        let challenge = auth
                            .challenge(instant_acme::ChallengeType::TlsAlpn01)
                            .ok_or_else(|| {
                                tracing::error!("ACME Error: Option was None");
                                GatewayError::ACMEFailed
                            })?;
                        let key_auth_str = challenge.key_authorization().as_str().to_string();
                        let url = challenge.url.clone();
                        let digest =
                            ring::digest::digest(&ring::digest::SHA256, key_auth_str.as_bytes());
                        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
                            .map_err(|e| {
                                tracing::error!("ACME Error: {:?}", e);
                                GatewayError::ACMEFailed
                            })?;
                        let mut params = rcgen::CertificateParams::new(vec![identifier.clone()])
                            .map_err(|e| {
                                tracing::error!("ACME Error: {:?}", e);
                                GatewayError::ACMEFailed
                            })?;
                        let mut dn = rcgen::DistinguishedName::new();
                        dn.push(rcgen::DnType::OrganizationName, "narrowlink");
                        params.distinguished_name = dn;
                        params.custom_extensions =
                            vec![rcgen::CustomExtension::new_acme_identifier(digest.as_ref())];

                        let cert = params.self_signed(&key_pair).map_err(|e| {
                            tracing::error!("ACME Error: {:?}", e);
                            GatewayError::ACMEFailed
                        })?;
                        let cert_der = cert.der().to_vec();
                        let key_der = key_pair.serialize_der();

                        #[derive(Debug)]
                        struct AcmeCertResolver {
                            key: std::sync::Arc<rustls::sign::CertifiedKey>,
                        }
                        impl rustls::server::ResolvesServerCert for AcmeCertResolver {
                            fn resolve(
                                &self,
                                _client_hello: rustls::server::ClientHello,
                            ) -> Option<std::sync::Arc<rustls::sign::CertifiedKey>>
                            {
                                Some(self.key.clone())
                            }
                        }
                        let provider =
                            rustls::crypto::CryptoProvider::get_default().ok_or_else(|| {
                                tracing::error!("CryptoProvider error");
                                GatewayError::ACMEFailed
                            })?;
                        let priv_key = rustls::pki_types::PrivateKeyDer::try_from(key_der)
                            .map_err(|e| {
                                tracing::error!("PrivateKey error: {:?}", e);
                                GatewayError::ACMEFailed
                            })?;
                        let signing_key = provider
                            .key_provider
                            .load_private_key(priv_key)
                            .map_err(|e| {
                                tracing::error!("SigningKey error: {:?}", e);
                                GatewayError::ACMEFailed
                            })?;
                        let certified_key = rustls::sign::CertifiedKey::new(
                            vec![rustls::pki_types::CertificateDer::from(cert_der).into_owned()],
                            signing_key,
                        );
                        let mut server_config = rustls::ServerConfig::builder()
                            .with_no_client_auth()
                            .with_cert_resolver(std::sync::Arc::new(AcmeCertResolver {
                                key: std::sync::Arc::new(certified_key),
                            }));

                        server_config
                            .alpn_protocols
                            .push(crate::service::certificate::ACME_TLS_ALPN_NAME.to_vec());

                        challenges.push(ChallengeInfo {
                            verification_url: url,
                            domain: identifier.to_owned(),
                            challenge: ACMEChallenge::TlsAlpn01(Arc::new(server_config)),
                        });
                    } else if *challenge_type == super::ACMEChallengeType::Http01 && has_http {
                        let challenge = auth
                            .challenge(instant_acme::ChallengeType::Http01)
                            .ok_or_else(|| {
                                tracing::error!("ACME Error: Option was None");
                                GatewayError::ACMEFailed
                            })?;
                        let key_auth_str = challenge.key_authorization().as_str().to_string();
                        let url = challenge.url.clone();
                        let digest = key_auth_str;
                        let token = digest.split('.').next().unwrap_or_default().to_string();
                        challenges.push(ChallengeInfo {
                            verification_url: url,
                            domain: identifier.to_owned(),
                            challenge: ACMEChallenge::Http01(token, digest),
                        });
                    } else {
                        tracing::error!("requested challenge type not offered by Let's Encrypt");
                        return Err(GatewayError::ACMEFailed);
                    }
                }
            }
        }

        if has_invalid {
            return Err(GatewayError::ACMEFailed);
        }

        if any_valid {
            let key_pair = suggested_private_key
                .and_then(|private_key| rcgen::KeyPair::try_from(private_key.secret_der()).ok())
                .unwrap_or_else(|| {
                    rcgen::KeyPair::generate().expect("Failed to generate key pair")
                });
            let mut params = rcgen::CertificateParams::new(domains.clone()).map_err(|e| {
                tracing::error!("ACME Error: {:?}", e);
                GatewayError::ACMEFailed
            })?;
            params.distinguished_name = rcgen::DistinguishedName::new();
            let csr = params
                .serialize_request(&key_pair)
                .map_err(|e| {
                    tracing::error!("ACME Error: {:?}", e);
                    GatewayError::ACMEFailed
                })?
                .der()
                .to_vec();
            order.finalize_csr(&csr).await.map_err(|e| {
                tracing::error!("ACME Error: {:?}", e);
                GatewayError::ACMEFailed
            })?;
            let cert_chain_pem = loop {
                match order.certificate().await.map_err(|e| {
                    tracing::error!("ACME Error: {:?}", e);
                    GatewayError::ACMEFailed
                })? {
                    Some(cert_chain_pem) => break cert_chain_pem,
                    None => tokio::time::sleep(tokio::time::Duration::from_secs(1)).await,
                }
            };

            return pem::parse_many(cert_chain_pem)
                .map_err(|_| GatewayError::ACMEFailed)
                .and_then(|mut c| {
                    pem::parse(key_pair.serialize_pem())
                        .map_err(|_| GatewayError::ACMEFailed)
                        .map(|p| {
                            c.push(p);
                            Some(c)
                        })
                });
        }

        self.challenges = challenges;
        self.order = Some(order);
        Ok(None)
    }

    pub fn get_tls_alpn_01_certificate_challenges(
        &self,
    ) -> Result<Vec<ChallengeInfo>, GatewayError> {
        Ok(self
            .challenges
            .iter()
            .filter(|c| matches!(c.challenge, ACMEChallenge::TlsAlpn01(_)))
            .cloned()
            .collect())
    }

    pub fn get_http_01_certificate_challenges(&self) -> Result<Vec<ChallengeInfo>, GatewayError> {
        Ok(self
            .challenges
            .iter()
            .filter(|c| matches!(c.challenge, ACMEChallenge::Http01(_, _)))
            .cloned()
            .collect())
    }

    pub async fn check_challenge(
        &mut self,
        challenges: Vec<ChallengeInfo>,
        tries: u8,
        delay: u64,
        suggested_private_key: Option<&rustls::pki_types::PrivateKeyDer<'_>>,
    ) -> Result<Vec<pem::Pem>, GatewayError> {
        let order = self
            .order
            .as_mut()
            .ok_or(GatewayError::ACMEOrderNotAvailable)?;
        let mut domain = Vec::new();
        // Collect the verification URLs from the passed-in challenges so we only
        // mark those specific challenges as ready (matching old set_challenge_ready behavior)
        let challenge_urls: std::collections::HashSet<String> = challenges
            .iter()
            .map(|c| c.verification_url.clone())
            .collect();
        {
            let mut auths_stream = order.authorizations();
            while let Some(auth) = auths_stream.next().await {
                let mut auth = auth.map_err(|e| {
                    tracing::error!("ACME Error: {:?}", e);
                    GatewayError::ACMEFailed
                })?;
                // Only set_ready for challenge types whose URL matches one we were given
                let has_matching_tls = auth.challenges.iter().any(|c| {
                    c.r#type == instant_acme::ChallengeType::TlsAlpn01
                        && challenge_urls.contains(&c.url)
                });
                let has_matching_http = auth.challenges.iter().any(|c| {
                    c.r#type == instant_acme::ChallengeType::Http01
                        && challenge_urls.contains(&c.url)
                });

                if has_matching_tls {
                    auth.challenge(instant_acme::ChallengeType::TlsAlpn01)
                        .ok_or_else(|| {
                            tracing::error!("ACME Error: Option was None");
                            GatewayError::ACMEFailed
                        })?
                        .set_ready()
                        .await
                        .map_err(|e| {
                            tracing::error!("ACME Error: {:?}", e);
                            GatewayError::ACMEFailed
                        })?;
                } else if has_matching_http {
                    auth.challenge(instant_acme::ChallengeType::Http01)
                        .ok_or_else(|| {
                            tracing::error!("ACME Error: Option was None");
                            GatewayError::ACMEFailed
                        })?
                        .set_ready()
                        .await
                        .map_err(|e| {
                            tracing::error!("ACME Error: {:?}", e);
                            GatewayError::ACMEFailed
                        })?;
                }
            }
        }
        for challenge in challenges {
            domain.push(challenge.domain.clone());
        }
        let mut tries_counter = 1;
        let mut delay = std::time::Duration::from_millis(delay);

        let state = loop {
            trace!("waiting for acme verification");
            time::sleep(delay).await;
            let state = order.refresh().await.map_err(|e| {
                tracing::error!("ACME Error: {:?}", e);
                GatewayError::ACMEFailed
            })?;

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
            let mut auths = order.authorizations();
            while let Some(Ok(auth)) = auths.next().await {
                for challenge in &auth.challenges {
                    if let Some(err) = &challenge.error {
                        tracing::error!("ACME Challenge error: {:?}", err);
                    }
                }
            }
            trace!("acme verification failed");
            return Err(GatewayError::ACMEVerificationFailed);
        }
        trace!("acme verification successful");
        let key_pair = suggested_private_key
            .and_then(|private_key| rcgen::KeyPair::try_from(private_key.secret_der()).ok())
            .unwrap_or_else(|| rcgen::KeyPair::generate().expect("Failed to generate key pair"));
        let mut params = CertificateParams::new(domain).map_err(|e| {
            tracing::error!("ACME Error: {:?}", e);
            GatewayError::ACMEFailed
        })?;
        params.distinguished_name = DistinguishedName::new();
        let csr = params
            .serialize_request(&key_pair)
            .map_err(|e| {
                tracing::error!("ACME Error: {:?}", e);
                GatewayError::ACMEFailed
            })?
            .der()
            .to_vec();
        order.finalize_csr(&csr).await.map_err(|e| {
            tracing::error!("ACME Error: {:?}", e);
            GatewayError::ACMEFailed
        })?;
        trace!("acme certificate finalized");
        let cert_chain_pem = loop {
            match order.certificate().await.map_err(|e| {
                tracing::error!("ACME Error: {:?}", e);
                GatewayError::ACMEFailed
            })? {
                Some(cert_chain_pem) => break cert_chain_pem,
                None => tokio::time::sleep(tokio::time::Duration::from_secs(1)).await,
            }
        };
        trace!("acme certificate received");

        pem::parse_many(cert_chain_pem)
            .map_err(|_| GatewayError::ACMEFailed)
            .and_then(|mut c| {
                pem::parse(key_pair.serialize_pem())
                    .map_err(|_| GatewayError::ACMEFailed)
                    .map(|p| {
                        c.push(p);
                        c
                    })
            })
    }
}
