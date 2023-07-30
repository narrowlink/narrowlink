use std::env;

use error::GatewayError;
use futures_util::{stream::FuturesUnordered, StreamExt};
use log::{debug, info, trace};
use state::State;
use validator::Validate;

use crate::{args::Args, service::Service};
mod args;
mod config;
mod error;
mod service;
mod state;

const CONNECTION_ORIANTED: bool = true;

#[tokio::main]
async fn main() -> Result<(), GatewayError> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args = Args::parse(env::args())?;

    let conf = config::Config::load(args.config_path)?;
    conf.validate()?;
    debug!("config successfully read");
    trace!("config: {:?}", &conf);

    let cm = if let Some(tls_config) = conf.tls_config() {
        debug!("setting up tls config");
        let tls_engine = service::wss::TlsEngine::new(tls_config).await?;
        debug!("tls config successfully created");
        Some(tls_engine)
    } else {
        debug!("tls config in not required");
        None
    };

    let mut state = State::from(
        &conf,
        cm.clone().and_then(|cm| match cm {
            service::wss::TlsEngine::Acme(cm) => Some(cm.get_service_sender()),
            _ => None,
        }),
    );
    let services = FuturesUnordered::new();
    for service in conf.services() {
        match service {
            config::Service::Ws(ws) => {
                info!("Ws service added");
                services.push(service::ws::Ws::from(ws, state.get_sender(), cm.clone()).run());
            }
            config::Service::Wss(wss) => {
                if let Some(cm) = &cm {
                    info!("Wss service added");
                    services
                        .push(service::wss::Wss::from(wss, state.get_sender(), cm.clone()).run());
                }
            }
        }
    }
    tokio::join!(
        state.run(),
        services.for_each(|_s| {
            log::error!("{:?}", _s);
            std::future::ready(())
        })
    );
    Ok(())
}
