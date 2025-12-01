//! Main server implementation

use crate::client::ClientHandler;
use anyhow::Result;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tracing::{error, info};

pub struct Server {
    name: String,
    host: String,
    port: u16,
    state: Arc<ServerState>,
}

pub struct ServerState {
    pub name: String,
    pub channels: RwLock<std::collections::HashMap<String, crate::channel::Channel>>,
    pub clients: RwLock<std::collections::HashMap<String, Arc<crate::client::Client>>>,
}

impl Server {
    pub fn new(name: String, host: String, port: u16) -> Self {
        let state = Arc::new(ServerState {
            name: name.clone(),
            channels: RwLock::new(std::collections::HashMap::new()),
            clients: RwLock::new(std::collections::HashMap::new()),
        });

        Self {
            name,
            host,
            port,
            state,
        }
    }

    pub async fn run(self) -> Result<()> {
        let addr = format!("{}:{}", self.host, self.port);
        let listener = TcpListener::bind(&addr).await?;

        info!("SIRC server listening on {}", addr);
        info!("Server name: {}", self.name);

        loop {
            match listener.accept().await {
                Ok((socket, addr)) => {
                    info!("New connection from {}", addr);
                    let state = Arc::clone(&self.state);

                    tokio::spawn(async move {
                        let handler = ClientHandler::new(socket, addr, state);
                        if let Err(e) = handler.handle().await {
                            error!("Client handler error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("Failed to accept connection: {}", e);
                }
            }
        }
    }
}
