mod config;
mod error;
use std::env;
mod args;
use args::Args;
use config::TokenType;
use error::TokenGeneratorError;
use jsonwebtoken::{Algorithm, EncodingKey, Header};

fn main() -> Result<(), TokenGeneratorError> {
    let args = Args::parse(env::args())?;
    let config = config::Config::load(args.config_path)?;
    for (i, token) in config.tokens.into_iter().enumerate() {
        if i > 0 {
            println!("---");
        }
        match token {
            TokenType::Client(client) => {
                let Ok(ct) = jsonwebtoken::encode(
                    &Header::new(Algorithm::default()),
                    &client,
                    &EncodingKey::from_secret(&config.secret),
                ) else {
                    return Err(TokenGeneratorError::TokenGenerationError); // unreachable
                };
                println!("Client Token: {}:{}\r\n{}", client.uid, client.name, ct);
            }
            TokenType::ClientPolicy(policy) => {
                if policy.pid < 1024 {
                    return Err(TokenGeneratorError::InvalidPolicyId);
                }
                let Ok(ct) = jsonwebtoken::encode(
                    &Header::new(Algorithm::default()),
                    &policy,
                    &EncodingKey::from_secret(&config.secret),
                ) else {
                    return Err(TokenGeneratorError::TokenGenerationError); // unreachable
                };
                println!(
                    "Policy Token: {}:{}:{}\r\n{}",
                    policy.uid, policy.name, policy.pid, ct
                );
            }
            TokenType::Agent(agent) => {
                let Ok(at) = jsonwebtoken::encode(
                    &Header::new(Algorithm::default()),
                    &agent,
                    &EncodingKey::from_secret(
                        &config.secret.clone().into_iter().rev().collect::<Vec<u8>>(),
                    ),
                ) else {
                    return Err(TokenGeneratorError::TokenGenerationError); // unreachable
                };
                println!("Agent Token: {}:{}\r\n{}", agent.uid, agent.name, at);
            }
            TokenType::AgentPublish(publish_token) => {
                let Ok(pt) = jsonwebtoken::encode(
                    &Header::new(Algorithm::default()),
                    &publish_token,
                    &EncodingKey::from_secret(
                        &config.secret.clone().into_iter().rev().collect::<Vec<u8>>(),
                    ),
                ) else {
                    return Err(TokenGeneratorError::TokenGenerationError); // unreachable
                };
                println!(
                    "Publish Token: {}:{}\r\n{}",
                    publish_token.uid, publish_token.name, pt
                );
            }
        }
    }
    Ok(())
}
