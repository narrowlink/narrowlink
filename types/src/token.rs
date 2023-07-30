use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{error::MessageError, policy::Policies, publish::PublishHost};

#[derive(Debug, Serialize, Deserialize)]
pub struct ClientToken {
    pub uid: Uuid,
    pub name: String,
    pub exp: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub policies: Option<Policies>,
}
//Todo: replace to from/into if possible//Todo: replace to from/into if possible
impl ClientToken {
    pub fn from_str(s: &str, token: &[u8]) -> Result<ClientToken, MessageError> {
        Ok(jsonwebtoken::decode::<ClientToken>(
            s,
            &DecodingKey::from_secret(token),
            &Validation::new(Algorithm::default()),
        )?
        .claims)
    }

    pub fn to_string(&self, token: &[u8]) -> Result<String, MessageError> {
        Ok(jsonwebtoken::encode(
            &Header::new(Algorithm::default()),
            self,
            &EncodingKey::from_secret(token),
        )?)
    }
}

impl Policies {
    pub fn from_str(s: &str, token: &[u8]) -> Result<Policies, MessageError> {
        Ok(jsonwebtoken::decode::<Policies>(
            s,
            &DecodingKey::from_secret(token),
            &Validation::new(Algorithm::default()),
        )?
        .claims)
    }

    pub fn to_string(&self, token: &[u8]) -> Result<String, MessageError> {
        Ok(jsonwebtoken::encode(
            &Header::new(Algorithm::default()),
            self,
            &EncodingKey::from_secret(token),
        )?)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AgentToken {
    pub uid: Uuid,
    pub name: String,
    pub exp: usize,
}

impl AgentToken {
    pub fn from_str(s: &str, token: &[u8]) -> Result<AgentToken, MessageError> {
        Ok(jsonwebtoken::decode::<AgentToken>(
            s,
            &DecodingKey::from_secret(token),
            &Validation::new(Algorithm::default()),
        )?
        .claims)
    }

    pub fn to_string(&self, token: &[u8]) -> Result<String, MessageError> {
        Ok(jsonwebtoken::encode(
            &Header::new(Algorithm::default()),
            self,
            &EncodingKey::from_secret(token),
        )?)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AgentPublishToken {
    pub uid: Uuid,
    pub name: String,
    pub exp: usize,
    pub publish_hosts: Vec<PublishHost>,
}

impl AgentPublishToken {
    pub fn from_str(s: &str, token: &[u8]) -> Result<AgentPublishToken, MessageError> {
        Ok(jsonwebtoken::decode::<AgentPublishToken>(
            s,
            &DecodingKey::from_secret(token),
            &Validation::new(Algorithm::default()),
        )?
        .claims)
    }

    pub fn to_string(&self, token: &[u8]) -> Result<String, MessageError> {
        Ok(jsonwebtoken::encode(
            &Header::new(Algorithm::default()),
            self,
            &EncodingKey::from_secret(token),
        )?)
    }
}
