//! SIRC Server - Secure IRC Server with Federation

mod server;
mod client;
mod channel;
mod federation;
mod tls;
mod metrics;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing::{info, Level};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    // ---- "serve" args, also accepted at top-level for backwards compat ----
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

#[derive(Subcommand, Debug)]
enum Command {
    /// Run the SIRC server (default).
    Serve(ServeArgs),
    /// Manage the federation Certificate Revocation List.
    Crl {
        /// Server name whose CRL to manage (defaults to sirc.local).
        #[arg(long, default_value = "sirc.local")]
        name: String,
        /// Override CRL path (default: ~/.sirc/certs/revoked.crl).
        #[arg(long)]
        crl_path: Option<PathBuf>,
        #[command(subcommand)]
        op: CrlOp,
    },
    /// Print this server's certificate fingerprint.
    Fingerprint {
        #[arg(long, default_value = "sirc.local")]
        name: String,
    },
}

#[derive(Parser, Debug)]
struct ServeArgs {
    #[arg(long, default_value = "0.0.0.0")]
    host: String,
    #[arg(long, default_value = "6667")]
    port: u16,
    #[arg(long, default_value = "7000")]
    fed_port: u16,
    #[arg(long, default_value = "sirc.local")]
    name: String,
    #[arg(long)]
    federate: bool,
    #[arg(long)]
    tls: bool,
    #[arg(long)]
    peers: Vec<String>,
}

#[derive(Subcommand, Debug)]
enum CrlOp {
    /// List all revoked certificate fingerprints.
    List,
    /// Revoke a certificate by fingerprint.
    Revoke { fingerprint: String },
    /// Remove a certificate from the revocation list.
    Unrevoke { fingerprint: String },
    /// Check whether a fingerprint is revoked. Exit code 0 = revoked, 1 = not.
    IsRevoked { fingerprint: String },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_max_level(Level::INFO).init();
    let cli = Cli::parse();

    match cli.command {
        Some(Command::Crl { name, crl_path, op }) => run_crl(&name, crl_path, op),
        Some(Command::Fingerprint { name }) => run_fingerprint(&name),
        Some(Command::Serve(args)) => run_serve(args).await,
        None => run_serve(ServeArgs {
            host: cli.host,
            port: cli.port,
            fed_port: cli.fed_port,
            name: cli.name,
            federate: cli.federate,
            tls: cli.tls,
            peers: cli.peers,
        }).await,
    }
}

fn run_crl(server_name: &str, crl_path_override: Option<PathBuf>, op: CrlOp) -> Result<()> {
    use tls::{CertificateRevocationList, TlsManager};

    let mgr = TlsManager::new(server_name);
    // The TlsManager initialised with `server_name` already loads the CRL from
    // the standard location; honour the override only when explicitly given.
    let crl = match crl_path_override {
        Some(path) => std::sync::Arc::new(CertificateRevocationList::new(path)),
        None => mgr.crl(),
    };

    match op {
        CrlOp::List => {
            for fp in mgr.list_revoked_certificates() {
                println!("{}", fp);
            }
            // Also surface any fingerprints from the explicit-path CRL if used.
            if !std::sync::Arc::ptr_eq(&crl, &mgr.crl()) {
                for fp in crl.list_revoked() {
                    println!("{}", fp);
                }
            }
        }
        CrlOp::Revoke { fingerprint } => {
            mgr.revoke_certificate(fingerprint.clone())?;
            println!("Revoked: {}", fingerprint);
        }
        CrlOp::Unrevoke { fingerprint } => {
            mgr.unrevoke_certificate(&fingerprint)?;
            println!("Unrevoked: {}", fingerprint);
        }
        CrlOp::IsRevoked { fingerprint } => {
            let revoked = mgr.is_certificate_revoked(&fingerprint);
            if revoked {
                println!("revoked");
                std::process::exit(0);
            } else {
                println!("not revoked");
                std::process::exit(1);
            }
        }
    }
    Ok(())
}

fn run_fingerprint(server_name: &str) -> Result<()> {
    let mgr = tls::TlsManager::new(server_name);
    mgr.load_or_generate(server_name)?;
    println!("{}", mgr.fingerprint()?);
    Ok(())
}

async fn run_serve(args: ServeArgs) -> Result<()> {
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

        server = server.with_federation(args.fed_port, args.tls)?;
        server.start_federation(args.fed_port).await?;

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
