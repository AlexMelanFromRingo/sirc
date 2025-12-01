//! SIRC Server - Secure IRC Server with Federation

mod server;
mod client;
mod channel;
mod federation;
mod tls;

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

    /// Port to listen on for clients
    #[arg(long, default_value = "6667")]
    port: u16,

    /// Port for federation connections
    #[arg(long, default_value = "7000")]
    fed_port: u16,

    /// Server name
    #[arg(long, default_value = "sirc.local")]
    name: String,

    /// Enable federation
    #[arg(long)]
    federate: bool,

    /// Enable TLS for federation (requires --federate)
    #[arg(long)]
    tls: bool,

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
        "Starting SIRC server '{}' on {}:{}",
        args.name, args.host, args.port
    );

    let mut server = server::Server::new(args.name.clone(), args.host, args.port);

    if args.federate {
        info!("Federation mode enabled");
        info!("Federation port: {}", args.fed_port);
        if args.tls {
            info!("TLS enabled for federation");
        }

        // Enable federation
        server = server.with_federation(args.fed_port, args.tls)?;

        // Start federation listener
        server.start_federation(args.fed_port).await?;

        // Connect to peers if specified
        if !args.peers.is_empty() {
            info!("Connecting to {} peer(s): {:?}", args.peers.len(), args.peers);
            server.connect_to_peers(&args.peers).await?;
        } else {
            info!("No peers specified, waiting for incoming connections");
        }
    }

    info!("Server startup complete, accepting connections");
    server.run().await?;

    Ok(())
}
