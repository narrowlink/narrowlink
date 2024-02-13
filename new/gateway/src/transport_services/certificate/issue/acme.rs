use instant_acme::{Account, AccountCredentials, Authorization, NewAccount, Order};

use crate::{
    error::GatewayError,
    transport_services::certificate::{CertificateCache, CertificateResolver, DashMapCache},
};

pub const ACME_TLS_ALPN_NAME: &[u8] = b"acme-tls/1";

pub struct AcmeConfig<'a> {
    storage: &'a CertificateResolver,
    cache: Box<dyn CertificateCache + Send + Sync>,
}

impl<'a> AcmeConfig<'a> {
    pub fn new(storage: &'a CertificateResolver) -> Self {
        Self {
            storage,
            cache: Box::new(DashMapCache::default()),
        }
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
