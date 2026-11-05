type HttpBody = http_body_util::combinators::BoxBody<bytes::Bytes, hyper::Error>;

fn full_body(data: impl Into<bytes::Bytes>) -> HttpBody {
    use http_body_util::BodyExt;
    http_body_util::Full::new(data.into())
        .map_err(|never| match never {})
        .boxed()
}

use std::{
    env,
    io::{self, IsTerminal},
};

use error::GatewayError;
use futures_util::{StreamExt, stream::FuturesUnordered};
use state::State;
use tracing::{Instrument, Level, debug, error, info, span, trace};
use tracing_subscriber::{
    Layer,
    filter::{LevelFilter, Targets},
    fmt::writer::MakeWriterExt,
    prelude::__tracing_subscriber_SubscriberExt,
    util::SubscriberInitExt,
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
    let (stdout, _stdout_guard) = tracing_appender::non_blocking(io::stdout());
    let (stderr, _stderr_guard) = tracing_appender::non_blocking(io::stderr());

    let cmd = tracing_subscriber::fmt::layer()
        .with_ansi(io::stdout().is_terminal() && io::stderr().is_terminal())
        .compact()
        // .with_target(false)
        .with_writer(
            stdout
                .with_min_level(Level::WARN)
                .and(stderr.with_max_level(Level::ERROR)),
        )
        .with_filter(
            env::var("RUST_LOG")
                .ok()
                .and_then(|e| e.parse::<Targets>().ok())
                .unwrap_or(Targets::new().with_default(LevelFilter::INFO)),
        );

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
    let span = span!(Level::TRACE, "main");
    let _gaurd = span.enter();
    let args = Args::parse(env::args())?;
    let conf = config::Config::load(args.config_path)?;

    trace!("config successfully read");
    conf.validate()?;
    trace!("config successfully validated");
    debug!("config: {:?}", &conf);
    drop(_gaurd);
    let cm = if let Some(tls_config) = conf.tls_config() {
        span.in_scope(|| trace!("setting up tls engine"));
        let tls_engine = service::wss::TlsEngine::new(tls_config)
            .instrument(span.clone())
            .await?;
        span.in_scope(|| trace!("tls engine successfully created"));
        Some(tls_engine)
    } else {
        span.in_scope(|| trace!("tls engine in not required"));
        None
    };

    let mut state = State::from(
        &conf,
        cm.clone().and_then(|cm| match cm {
            service::wss::TlsEngine::Acme(cm) => Some(cm.get_service_sender()),
            _ => None,
        }),
    );
    span.in_scope(|| trace!("state successfully created"));
    let services = FuturesUnordered::new();

    for service in conf.services() {
        match service {
            config::Service::Ws(ws) => {
                services.push(
                    service::ws::Ws::from(ws, state.get_sender(), cm.clone())
                        .run()
                        .instrument(span.clone()),
                );
                span.in_scope(|| {
                    info!("Ws service added: {}", ws.listen_addr);
                    debug!("Ws service added: {:?}", ws)
                });
            }
            config::Service::Wss(wss) => {
                if let Some(cm) = &cm {
                    services.push(
                        service::wss::Wss::from(wss, state.get_sender(), cm.clone())
                            .run()
                            .instrument(span.clone()),
                    );
                    span.in_scope(|| {
                        info!("Wss service added: {}", wss.listen_addr);
                        debug!("Wss service added: {:?}", wss)
                    });
                }
            }
        }
    }

    tokio::join!(
        state.run().instrument(span.clone()),
        services.for_each(|_s| {
            error!("{:?}", _s);
            std::future::ready(())
        })
    );
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod quic_tests {
    use narrowlink_network::p2p::QuicStream;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::UdpSocket,
        time::{Duration, timeout},
    };

    #[tokio::test]
    async fn quic_transfers_data_with_pinned_certificate() {
        timeout(Duration::from_secs(5), async {
            let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
            let cert_der = cert.cert.der().to_vec();
            let key_der = cert.signing_key.serialize_der();
            let server_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let server_addr = server_socket.local_addr().unwrap();
            let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let server_cert = cert_der.clone();
            let (done_tx, done_rx) = tokio::sync::oneshot::channel();
            let server = tokio::spawn(async move {
                let connection = QuicStream::new_server(server_socket, server_cert, key_der)
                    .await
                    .unwrap();
                let mut stream = connection.accept_bi().await.unwrap();
                let mut message = [0; 4];
                stream.read_exact(&mut message).await.unwrap();
                assert_eq!(&message, b"ping");
                stream.write_all(b"pong").await.unwrap();
                stream.shutdown().await.unwrap();
                let _ = done_rx.await;
            });
            let client = QuicStream::new_client(server_addr, client_socket, cert_der)
                .await
                .unwrap();
            let mut stream = client.open_bi().await.unwrap();
            stream.write_all(b"ping").await.unwrap();
            let mut message = [0; 4];
            stream.read_exact(&mut message).await.unwrap();
            assert_eq!(&message, b"pong");
            let _ = done_tx.send(());
            server.await.unwrap();
        })
        .await
        .expect("QUIC exchange timed out");
    }
}
