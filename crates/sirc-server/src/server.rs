//! Main server implementation

use crate::client::ClientHandler;
use crate::federation::FederationManager;
use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tracing::{error, info};

pub struct Server {
    name: String,
    host: String,
    port: u16,
    state: Arc<ServerState>,
    federation: Option<Arc<FederationManager>>,
}

pub struct ServerState {
    pub name: String,
    pub channels: RwLock<std::collections::HashMap<String, crate::channel::Channel>>,
    pub clients: Arc<RwLock<std::collections::HashMap<String, Arc<crate::client::Client>>>>,
    pub federation: Option<Arc<FederationManager>>,
}

impl Server {
    pub fn new(name: String, host: String, port: u16) -> Self {
        let state = Arc::new(ServerState {
            name: name.clone(),
            channels: RwLock::new(std::collections::HashMap::new()),
            clients: Arc::new(RwLock::new(std::collections::HashMap::new())),
            federation: None,
        });

        Self {
            name,
            host,
            port,
            state,
            federation: None,
        }
    }

    /// Enable federation and return self for chaining
    pub fn with_federation(mut self, _fed_port: u16, enable_tls: bool) -> Result<Self> {
        // Reuse the clients HashMap from the existing state
        let clients = Arc::clone(&self.state.clients);

        let federation_mgr = FederationManager::new(
            self.name.clone(),
            Arc::clone(&clients),
        );
        let federation_mgr = federation_mgr.with_tls(enable_tls)?;
        let federation = Arc::new(federation_mgr);

        // Update state with federation reference
        let state = Arc::new(ServerState {
            name: self.state.name.clone(),
            channels: RwLock::new(std::collections::HashMap::new()),
            clients,
            federation: Some(Arc::clone(&federation)),
        });

        self.state = state;
        self.federation = Some(federation);
        Ok(self)
    }

    /// Start federation listener
    pub async fn start_federation(&self, fed_port: u16) -> Result<()> {
        if let Some(ref federation) = self.federation {
            let addr = format!("{}:{}", self.host, fed_port)
                .parse::<SocketAddr>()?;
            federation.listen(addr).await?;
            info!("Federation enabled on port {}", fed_port);

            // Start central router task
            federation.start_router_task().await;
            info!("Federation router task started");

            // Start keepalive task
            Arc::clone(federation).start_keepalive_task();
            info!("Keepalive task started (30s interval)");

            // Start auto-reconnect task
            Arc::clone(federation).start_reconnect_task();
            info!("Auto-reconnect task started (5s check interval)");

            // Start split brain detection
            Arc::clone(federation).start_split_brain_detection();
            info!("Split brain detection started (60s check interval)");

            // Start metrics reporting
            Arc::clone(federation).start_metrics_reporting();
            info!("Performance metrics reporting started (5min interval)");
        }
        Ok(())
    }

    /// Connect to peer servers
    pub async fn connect_to_peers(&self, peers: &[String]) -> Result<()> {
        if let Some(ref federation) = self.federation {
            for peer in peers {
                info!("Connecting to peer: {}", peer);
                if let Err(e) = federation.connect_to_peer(peer).await {
                    error!("Failed to connect to peer {}: {}", peer, e);
                } else {
                    info!("Successfully connected to peer {}", peer);
                }
            }
        }
        Ok(())
    }

    pub async fn run(self) -> Result<()> {
        let addr = format!("{}:{}", self.host, self.port);
        let listener = TcpListener::bind(&addr).await?;

        info!("SIRC server listening on {}", addr);
        info!("Server name: {}", self.name);

        if self.federation.is_some() {
            info!("Federation mode ENABLED");
        }

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
