use std::{collections::HashMap, sync::Arc};

use instant_acme::{Account, AccountCredentials, Authorization, ChallengeType, NewAccount, Order};
use rustls::CertificateError;

use crate::{
    error::{CertificateError as GWCertificateError, GatewayError},
    transport_services::certificate::{
        CertificateCache, CertificateResolver, CertificateStorage, DashMapCache,
    },
};

use super::{CertificateIssue, CertificateIssueStatus};

pub const ACME_TLS_ALPN_NAME: &[u8] = b"acme-tls/1";

pub struct AcmeService {
    storage: Arc<dyn CertificateStorage + 'static + Send + Sync>,
    challenges: HashMap<(String, ChallengeType), String>, // (domain, challenge_type) -> token
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
            challenges: HashMap::new(),
            default_account: account,
        })
    }
}

impl CertificateIssue for AcmeService {
    fn issue(&self, account: &str, domain: &str) -> Option<()> {
        async {
            let account = self
                .storage()
                .get_default_account_credentials()
                .await
                .unwrap();
        };
        unimplemented!()
    }
    fn status(&self, account: &str, domain: &str) -> CertificateIssueStatus {
        unimplemented!()
    }
    fn storage(&self) -> &dyn CertificateStorage {
        unimplemented!()
    }
}

pub struct AcmeChallenge {
    pub account: Account,
    authorizations: Vec<Authorization>,
    order: Option<Order>,
}

impl AcmeChallenge {
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
}
