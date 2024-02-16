use instant_acme::{Account, AccountCredentials, Authorization, NewAccount, Order};

use crate::{
    error::GatewayError,
    transport_services::certificate::{CertificateCache, CertificateResolver, DashMapCache},
};

pub const ACME_TLS_ALPN_NAME: &[u8] = b"acme-tls/1";

pub struct AcmeService<'a> {
    resolver: &'a CertificateResolver,
    cache: Box<dyn CertificateCache + Send + Sync>,
    default_account: Account,
}

impl<'a> AcmeService<'a> {
    pub async fn new(
        resolver: &'a CertificateResolver,
        email: &str,
        server_url: &str,
    ) -> Result<Self, GatewayError> {
        let default_account_credentials = resolver
            .storage
            .get_default_account_credentials()
            .await
            .unwrap();
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
        resolver
            .storage
            .set_default_account_credentials(&serde_json::to_string(&account_credentials).unwrap())
            .await
            .unwrap();
        Ok(Self {
            resolver,
            cache: Box::<DashMapCache>::default(),
            default_account: account,
        })
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
