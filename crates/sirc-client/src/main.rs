//! SIRC Client - Secure IRC Client with TUI

mod client;
mod ui;

use anyhow::Result;
use clap::Parser;
use tracing::Level;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// IRC server address
    #[arg(long, default_value = "localhost:6667")]
    server: String,

    /// Nickname
    #[arg(long)]
    nick: String,

    /// Username (defaults to nick)
    #[arg(long)]
    username: Option<String>,

    /// Real name
    #[arg(long, default_value = "SIRC User")]
    realname: String,

    /// Enable encryption
    #[arg(long)]
    encrypt: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .init();

    let args = Args::parse();

    let username = args.username.clone().unwrap_or_else(|| args.nick.clone());

    let mut client = client::Client::new(
        args.server,
        args.nick,
        username,
        args.realname,
        args.encrypt,
    );

    client.run().await?;

    Ok(())
}
