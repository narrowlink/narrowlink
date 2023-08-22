use std::env;

use error::GatewayError;
use futures_util::{stream::FuturesUnordered, StreamExt};
use state::State;
use tracing::{debug, error, info, trace, Level};
use tracing_subscriber::{
    filter::LevelFilter, fmt::writer::MakeWriterExt, prelude::__tracing_subscriber_SubscriberExt,
    util::SubscriberInitExt, EnvFilter, Layer,
};
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
    let (stdout, _stdout_guard) = tracing_appender::non_blocking(std::io::stdout());
    let (stderr, _stderr_guard) = tracing_appender::non_blocking(std::io::stderr());

    let cmd = EnvFilter::builder()
        .with_default_directive(LevelFilter::TRACE.into())
        .with_env_var("LOG")
        .from_env()
        .map(|filter| {
            tracing_subscriber::fmt::layer()
                // .compact()
                .with_test_writer()
                .with_writer(
                    stdout
                        .with_min_level(Level::WARN)
                        .and(stderr.with_max_level(Level::ERROR)),
                )
                .with_filter(filter)
        })
        .map_err(|_| GatewayError::Invalid("Invalid Log Filter Format"))?;

    // let debug_file =
    //     tracing_appender::rolling::minutely("log", "debug").with_min_level(Level::DEBUG);
    // let log_file =
    //     tracing_appender::rolling::daily("log", "info").with_max_level(Level::INFO);

    // let file = tracing_subscriber::fmt::layer()
    //     .with_writer(log_file)
    //     .json();

    tracing_subscriber::registry()
        .with(cmd)
        // .with(file)
        .init();

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
                info!("Ws service added: {:?}", ws);
                services.push(service::ws::Ws::from(ws, state.get_sender(), cm.clone()).run());
            }
            config::Service::Wss(wss) => {
                if let Some(cm) = &cm {
                    info!("Wss service added: {:?}", wss);
                    services
                        .push(service::wss::Wss::from(wss, state.get_sender(), cm.clone()).run());
                }
            }
        }
    }
    tokio::join!(
        state.run(),
        services.for_each(|_s| {
            error!("{:?}", _s);
            std::future::ready(())
        })
    );
    Ok(())
}
