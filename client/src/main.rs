mod args;
mod config;
mod error;
mod manage;
mod transport;
mod tunnel;
use args::Args;
use error::ClientError;
use manage::{ControlFactory, ControlMsg, Instruction};
use std::{
    env,
    io::{self, IsTerminal},
};
use tracing::{debug, error, warn, Level};
use transport::TransportFactory;
use tunnel::TunnelFactory;

use tracing_subscriber::{
    filter::{LevelFilter, Targets},
    fmt::writer::MakeWriterExt,
    prelude::__tracing_subscriber_SubscriberExt,
    util::SubscriberInitExt,
    Layer,
};

use crate::manage::ControlStatus;
// todo: Fix exit if p2p connection not available
pub fn main() -> Result<(), ClientError> {
    let args = Args::parse(env::args())?;

    let (stdout, _stdout_guard) = if matches!(args.arg_commands, args::ArgCommands::Connect(_)) {
        tracing_appender::non_blocking(io::stderr())
    } else {
        tracing_appender::non_blocking(io::stdout())
    };
    let (stderr, _stderr_guard) = tracing_appender::non_blocking(io::stderr());

    let cmd = tracing_subscriber::fmt::layer()
        .with_ansi(
            if matches!(args.arg_commands, args::ArgCommands::Connect(_)) {
                true
            } else {
                io::stdout().is_terminal()
            } && io::stderr().is_terminal(),
        )
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

    match start(args) {
        Ok(_) => (),
        Err(e) => error!("Error: {}", e),
    }
    Ok(())
}

#[tokio::main]
async fn start(mut args: Args) -> Result<(), ClientError> {
    let conf = config::Config::load(args.take_conf_path())?;
    let instruction = Instruction::from(&args.arg_commands);
    let mut control = ControlFactory::new(conf, instruction.is_direct_only())?;
    let mut transport = TransportFactory::new(instruction.transport);
    let mut tunnel = TunnelFactory::new(instruction.tunnel);

    loop {
        tokio::select! {
            msg = control.accept_msg() => {
                match msg {
                    Ok(ControlMsg::ConnectionError(connection_id, msg)) => {
                        debug!("Connection error: {}:{}", connection_id, msg);
                    }
                    Ok(ControlMsg::Peer2Peer(p2p)) => {
                        debug!("Peer2Peer: {:?}", p2p);
                        let t = transport.clone();
                        let direct_tunnel_status = control.direct_tunnel_status.clone();
                        tunnel.add_host(p2p.peer_ip); // todo del_host
                        let system_status_sender = control.get_status_sender();
                        tokio::spawn(async move{
                            _ = system_status_sender.send(ControlStatus::P2PRequest(t.create_direct(p2p,direct_tunnel_status).await));
                        });
                    }
                    Ok(ControlMsg::Shutdown(err)) => {
                        tunnel.stop().await;
                        return Err(err);
                    }
                    Err(e) => {
                        if transport.is_direct_required_and_unavailable().await {
                            tunnel.stop().await;
                        }
                        if !(matches!(e, ClientError::ControlChannelNotConnected) || matches!(e, ClientError::ConnectionClosed)) {
                            return Err(e);
                        }

                        let relay_info = control.connect(matches!(args.arg_commands, args::ArgCommands::List(_))).await?;
                        if let Some(addr) = control.control.as_ref().map(|c| c.address.ip()) {
                            tunnel.add_host(addr);
                        }
                        transport.set_relay(relay_info);
                        tunnel.start().await?;

                        if let Err(e) = control.manage(&instruction.manage).await{
                            if !matches!(e, ClientError::ConnectionClosed) {

                                return Err(e);
                            }
                            warn!("{}",e);
                        }

                    }
                }
            }
            msg = tunnel.accept() => {
                let t = transport.clone();
                control.add_connection(tokio::spawn(async move{
                    let (socket,connect) = msg?;
                    t.connect(socket,connect).await
                }));

            }
        }
    }
}
