mod args;
mod config;
mod control;
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
use tracing::{debug, error, Level};
use transport::TransportFactory;
use tunnel::TunnelFactory;

use tracing_subscriber::{
    filter::{LevelFilter, Targets},
    fmt::writer::MakeWriterExt,
    prelude::__tracing_subscriber_SubscriberExt,
    util::SubscriberInitExt,
    Layer,
};

pub fn main() -> Result<(), ClientError> {
    let args = Args::parse(env::args())?;

    let (stdout, _stdout_guard) = if 1 == 1 {
        tracing_appender::non_blocking(io::stderr())
    } else {
        tracing_appender::non_blocking(io::stdout())
    };
    let (stderr, _stderr_guard) = tracing_appender::non_blocking(io::stderr());

    let cmd = tracing_subscriber::fmt::layer()
        .with_ansi(
            if 1 == 1 {
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
    let mut control = ControlFactory::new(conf)?;
    let instruction = Instruction::from(&args.arg_commands);
    let mut transport = TransportFactory::new(instruction.transport);
    let mut tunnel = TunnelFactory::new(instruction.tunnel);

    loop {
        tokio::select! {
            msg = control.accept_msg() => {
                match msg {
                    Some(ControlMsg::ConnectionError(connection_id, msg)) => {
                        debug!("Connection error: {}:{}", connection_id, msg);
                    }
                    Some(ControlMsg::Peer2Peer(p2p)) => {
                        debug!("Peer2Peer: {:?}", p2p);
                        let t = transport.clone();
                        let direct_tunnel_status = control.direct_tunnel_status.clone();
                        tunnel.add_host(p2p.peer_ip); // todo del_host
                        tokio::spawn(async move{
                            t.create_direct(p2p,direct_tunnel_status).await.unwrap();
                        });

                    }
                    None => {
                        tunnel.stop();
                        let relay_info = control.connect().await?; // todo: reconnect
                        if let Some(addr) = control.control.as_ref().map(|c| c.address.ip()) {
                            tunnel.add_host(addr);
                        }
                        transport.set_relay(relay_info);
                        // if let Some(manage) = manage.take() {
                            control.manage(&instruction.manage).await;
                        //     break;
                        // }else{
                            tunnel.start().await;
                        // }

                    }
                }
            }
            msg = tunnel.accept() => {
                let t = transport.clone();
                tokio::spawn(async move{
                    let (socket,connect) = msg.unwrap();
                    t.connect(socket,connect).await;
                });
                // dbg!(msg.unwrap().1);

            }
        }
    }
}
