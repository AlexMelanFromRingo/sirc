//! SIRC Server - Secure IRC Server with Federation

mod server;
mod client;
mod channel;
mod federation;

use anyhow::Result;
use clap::Parser;
use tracing::{info, Level};
use tracing_subscriber;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Host to bind to
    #[arg(long, default_value = "0.0.0.0")]
    host: String,

    /// Port to listen on
    #[arg(long, default_value = "6667")]
    port: u16,

    /// Server name
    #[arg(long, default_value = "sirc.local")]
    name: String,

    /// Enable federation
    #[arg(long)]
    federate: bool,

    /// Peer servers to connect to (format: host:port)
    #[arg(long)]
    peers: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .init();

    let args = Args::parse();

    info!(
        "Starting SIRC server {} on {}:{}",
        args.name, args.host, args.port
    );

    let server = server::Server::new(args.name, args.host, args.port);

    if args.federate && !args.peers.is_empty() {
        info!("Federation enabled with peers: {:?}", args.peers);
        // TODO: Connect to peers
    }

    server.run().await?;

    Ok(())
}
