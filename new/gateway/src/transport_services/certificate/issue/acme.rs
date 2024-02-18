use std::sync::Arc;

use instant_acme::{Account, AccountCredentials, Authorization, NewAccount, Order};

use crate::{
    error::GatewayError,
    transport_services::certificate::{
        CertificateCache, CertificateResolver, CertificateStorage, DashMapCache,
    },
};

use super::{CertificateIssue, CertificateIssueStatus};

pub const ACME_TLS_ALPN_NAME: &[u8] = b"acme-tls/1";

pub struct AcmeService {
    storage: Arc<dyn CertificateStorage + 'static + Send + Sync>,
    cache: Box<dyn CertificateCache + Send + Sync>,
    default_account: Account,
}

// impl !Send for AcmeService<'_> {}

impl AcmeService {
    pub async fn new(
        storage: Arc<impl CertificateStorage + 'static + Send + Sync>,
        email: &str,
        server_url: impl Into<Option<&str>>,
    ) -> Result<Self, GatewayError> {
        let server_url = server_url
            .into()
            .unwrap_or("https://acme-staging-v02.api.letsencrypt.org/directory");
        let default_account_credentials = storage.get_default_account_credentials().await.unwrap();
        serde_json::from_str::<AccountCredentials>(&default_account_credentials).unwrap();
        let (account, account_credentials) = Account::create(
            &NewAccount {
                contact: &[&format!("mailto:{}", email)],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            server_url, //"https://acme-staging-v02.api.letsencrypt.org/directory",
            None,
        )
        .await
        .unwrap();
        storage
            .set_default_account_credentials(&serde_json::to_string(&account_credentials).unwrap())
            .await
            .unwrap();
        Ok(Self {
            storage,
            cache: Box::<DashMapCache>::default(),
            default_account: account,
        })
    }
}

impl CertificateIssue for AcmeService {
    fn issue(&self, account: &str, domain: &str) -> Option<()> {
        unimplemented!()
    }
    fn status(&self, account: &str, domain: &str) -> CertificateIssueStatus {
        unimplemented!()
    }
    fn storage(&self) -> &dyn CertificateStorage {
        unimplemented!()
    }
}

pub struct Acme {
    pub account: Account,
    authorizations: Vec<Authorization>,
    order: Option<Order>,
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
}
