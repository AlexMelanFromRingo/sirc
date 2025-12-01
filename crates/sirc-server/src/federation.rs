//! Server-to-server federation with mesh network topology
//!
//! Federation Protocol:
//! - SERVER <name> <hopcount> :<info> - Server introduction
//! - SJOIN <channel> <users> - Channel join sync
//! - SMSG <origin> <target> :<message> - Route message between servers
//! - SPING / SPONG - Keep-alive
//! - BURST - Initial state synchronization

use anyhow::{Context, Result};
use futures::{SinkExt, StreamExt};
use sirc_protocol::{Command, IrcCodec, Message, Prefix};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, RwLock};
use tokio::time::sleep;
use tokio_rustls::{TlsAcceptor, TlsConnector, TlsStream};
use tokio_util::codec::Framed;
use tracing::{debug, error, info, warn};

use crate::tls::TlsManager;
use crate::metrics::MetricsCollector;

/// Stream wrapper that supports both TLS and plain TCP
enum FederationStream {
    Plain(TcpStream),
    TlsServer(Box<tokio_rustls::server::TlsStream<TcpStream>>),
    TlsClient(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

impl tokio::io::AsyncRead for FederationStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            FederationStream::Plain(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            FederationStream::TlsServer(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            FederationStream::TlsClient(s) => std::pin::Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for FederationStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match &mut *self {
            FederationStream::Plain(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            FederationStream::TlsServer(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            FederationStream::TlsClient(s) => std::pin::Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            FederationStream::Plain(s) => std::pin::Pin::new(s).poll_flush(cx),
            FederationStream::TlsServer(s) => std::pin::Pin::new(s).poll_flush(cx),
            FederationStream::TlsClient(s) => std::pin::Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            FederationStream::Plain(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            FederationStream::TlsServer(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            FederationStream::TlsClient(s) => std::pin::Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// Federated message for routing between servers
#[derive(Debug, Clone)]
pub struct FederatedMessage {
    pub origin_server: String,
    pub target_server: Option<String>, // None = broadcast
    pub payload: Message,
}

/// Peer configuration for auto-reconnect
#[derive(Debug, Clone)]
pub struct PeerConfig {
    pub address: String,
    pub retry_count: u32,
    pub max_retries: u32,
    pub connected: bool,
    pub last_seen: Instant,
    pub last_ping_sent: Option<Instant>,
    pub last_pong_received: Option<Instant>,
}

impl PeerConfig {
    fn new(address: String) -> Self {
        Self {
            address,
            retry_count: 0,
            max_retries: 10, // Max reconnection attempts
            connected: false,
            last_seen: Instant::now(),
            last_ping_sent: None,
            last_pong_received: None,
        }
    }

    fn backoff_duration(&self) -> Duration {
        // Exponential backoff: 2^n seconds, capped at 5 minutes
        let seconds = 2u64.pow(self.retry_count.min(8));
        Duration::from_secs(seconds.min(300))
    }

    fn is_stale(&self, timeout: Duration) -> bool {
        self.last_seen.elapsed() > timeout
    }

    fn update_last_seen(&mut self) {
        self.last_seen = Instant::now();
    }
}

/// Network partition tracking
#[derive(Debug, Clone)]
pub struct NetworkPartition {
    /// Servers that are unreachable
    pub unreachable_servers: HashSet<String>,
    /// When the partition was detected
    pub detected_at: Instant,
    /// Partition identifier
    pub id: String,
}

impl NetworkPartition {
    fn new(id: String, unreachable_servers: HashSet<String>) -> Self {
        Self {
            unreachable_servers,
            detected_at: Instant::now(),
            id,
        }
    }
}

/// Peer server connection
pub struct PeerConnection {
    pub name: String,
    pub address: SocketAddr,
    pub hopcount: u32,
    pub info: String,
    tx: mpsc::UnboundedSender<FederatedMessage>,
}

impl PeerConnection {
    /// Send a message to this peer
    pub fn send(&self, msg: FederatedMessage) -> Result<()> {
        self.tx
            .send(msg)
            .context("Failed to send message to peer")?;
        Ok(())
    }
}

/// Routing table for mesh network
pub struct RoutingTable {
    /// Map of server name -> peer connection
    direct_peers: HashMap<String, Arc<PeerConnection>>,
    /// Map of server name -> route (through which peer)
    routes: HashMap<String, String>,
}

impl RoutingTable {
    pub fn new() -> Self {
        Self {
            direct_peers: HashMap::new(),
            routes: HashMap::new(),
        }
    }

    /// Add a direct peer connection
    pub fn add_peer(&mut self, peer: Arc<PeerConnection>) {
        let name = peer.name.clone();
        self.direct_peers.insert(name.clone(), peer);
        self.routes.insert(name.clone(), name); // Direct route to self
    }

    /// Add a route to a remote server through a peer
    pub fn add_route(&mut self, server: String, via: String) {
        if !self.routes.contains_key(&server) {
            self.routes.insert(server, via);
        }
    }

    /// Get the peer to route a message to a server
    pub fn get_route(&self, server: &str) -> Option<Arc<PeerConnection>> {
        self.routes
            .get(server)
            .and_then(|via| self.direct_peers.get(via))
            .cloned()
    }

    /// Get all known servers
    pub fn all_servers(&self) -> Vec<String> {
        self.routes.keys().cloned().collect()
    }

    /// Remove a peer and all routes through it
    pub fn remove_peer(&mut self, peer_name: &str) {
        self.direct_peers.remove(peer_name);
        self.routes.retain(|_, via| via != peer_name);
    }
}

/// Federation manager with mesh network support
pub struct FederationManager {
    local_name: String,
    routing: Arc<RwLock<RoutingTable>>,
    channels: Arc<RwLock<HashMap<String, ChannelState>>>,
    peers: Arc<RwLock<HashMap<String, PeerConfig>>>,
    partitions: Arc<RwLock<Vec<NetworkPartition>>>,
    metrics: Arc<MetricsCollector>,
    tls: Option<Arc<TlsManager>>,
    tls_acceptor: Option<TlsAcceptor>,
    tls_connector: Option<TlsConnector>,
    message_rx: mpsc::UnboundedReceiver<FederatedMessage>,
    message_tx: mpsc::UnboundedSender<FederatedMessage>,
    clients: Arc<RwLock<HashMap<String, Arc<crate::client::Client>>>>,
}

/// Federated channel state
#[derive(Clone)]
pub struct ChannelState {
    pub name: String,
    pub users: HashMap<String, String>, // nick -> server
    pub topic: Option<String>,
}

impl FederationManager {
    pub fn new(
        local_name: String,
        clients: Arc<RwLock<HashMap<String, Arc<crate::client::Client>>>>,
    ) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();

        Self {
            local_name,
            routing: Arc::new(RwLock::new(RoutingTable::new())),
            channels: Arc::new(RwLock::new(HashMap::new())),
            peers: Arc::new(RwLock::new(HashMap::new())),
            partitions: Arc::new(RwLock::new(Vec::new())),
            metrics: MetricsCollector::new(),
            tls: None,
            tls_acceptor: None,
            tls_connector: None,
            message_rx: rx,
            message_tx: tx,
            clients,
        }
    }

    /// Get metrics collector reference
    pub fn metrics(&self) -> Arc<MetricsCollector> {
        Arc::clone(&self.metrics)
    }

    /// Start metrics reporting task
    pub fn start_metrics_reporting(self: Arc<Self>) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(300)); // Every 5 minutes
            loop {
                interval.tick().await;
                self.metrics.print_summary().await;
            }
        });
    }

    /// Enable TLS for secure federation
    pub fn with_tls(mut self, enable: bool) -> Result<Self> {
        if !enable {
            return Ok(self);
        }

        let tls_manager = Arc::new(TlsManager::new(&self.local_name));
        tls_manager.load_or_generate(&self.local_name)?;

        let server_config = tls_manager.server_config()?;
        let client_config = tls_manager.client_config(true)?; // Trust all for now

        let fingerprint = tls_manager.fingerprint()?;
        info!("TLS enabled for federation. Certificate fingerprint: {}", &fingerprint[..16]);

        self.tls = Some(tls_manager);
        self.tls_acceptor = Some(TlsAcceptor::from(server_config));
        self.tls_connector = Some(TlsConnector::from(client_config));

        Ok(self)
    }

    /// Get a message sender for other components
    pub fn get_sender(&self) -> mpsc::UnboundedSender<FederatedMessage> {
        self.message_tx.clone()
    }

    /// Start federation listener
    pub async fn listen(&self, addr: SocketAddr) -> Result<()> {
        let listener = TcpListener::bind(addr).await?;
        let tls_enabled = self.tls.is_some();
        info!("Federation listener started on {} (TLS: {})", addr, tls_enabled);

        let routing = Arc::clone(&self.routing);
        let channels = Arc::clone(&self.channels);
        let clients = Arc::clone(&self.clients);
        let local_name = self.local_name.clone();
        let message_tx = self.message_tx.clone();
        let tls_acceptor = self.tls_acceptor.clone();

        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((socket, addr)) => {
                        info!("Incoming federation connection from {}", addr);
                        let routing = Arc::clone(&routing);
                        let channels = Arc::clone(&channels);
                        let clients = Arc::clone(&clients);
                        let local_name = local_name.clone();
                        let message_tx = message_tx.clone();
                        let tls_acceptor = tls_acceptor.clone();

                        tokio::spawn(async move {
                            // Wrap with TLS if enabled
                            let stream = if let Some(acceptor) = tls_acceptor {
                                match acceptor.accept(socket).await {
                                    Ok(tls_stream) => {
                                        info!("TLS handshake completed with {}", addr);
                                        FederationStream::TlsServer(Box::new(tls_stream))
                                    }
                                    Err(e) => {
                                        error!("TLS handshake failed with {}: {}", addr, e);
                                        return;
                                    }
                                }
                            } else {
                                FederationStream::Plain(socket)
                            };

                            if let Err(e) = Self::handle_incoming_peer(
                                stream,
                                addr,
                                routing,
                                channels,
                                clients,
                                local_name,
                                message_tx,
                            )
                            .await
                            {
                                error!("Error handling incoming peer: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        error!("Failed to accept connection: {}", e);
                    }
                }
            }
        });

        Ok(())
    }

    /// Connect to a peer server
    pub async fn connect_to_peer(&self, address: &str) -> Result<()> {
        info!("Connecting to peer at {}", address);

        // Store peer config for reconnection
        self.peers.write().await.insert(
            address.to_string(),
            PeerConfig::new(address.to_string()),
        );

        let tcp_stream = TcpStream::connect(address).await?;
        let addr = tcp_stream.peer_addr()?;

        // Wrap with TLS if enabled
        let stream = if let Some(ref connector) = self.tls_connector {
            let server_name = rustls::pki_types::ServerName::try_from(
                address.split(':').next().unwrap_or("localhost").to_string()
            )?;

            match connector.connect(server_name, tcp_stream).await {
                Ok(tls_stream) => {
                    info!("TLS handshake completed with {}", address);
                    FederationStream::TlsClient(Box::new(tls_stream))
                }
                Err(e) => {
                    error!("TLS handshake failed with {}: {}", address, e);
                    return Err(e.into());
                }
            }
        } else {
            FederationStream::Plain(tcp_stream)
        };

        let routing = Arc::clone(&self.routing);
        let channels = Arc::clone(&self.channels);
        let clients = Arc::clone(&self.clients);
        let peers = Arc::clone(&self.peers);
        let local_name = self.local_name.clone();
        let message_tx = self.message_tx.clone();
        let peer_address = address.to_string();

        tokio::spawn(async move {
            if let Err(e) = Self::handle_outgoing_peer(
                stream,
                addr,
                routing,
                channels,
                clients,
                local_name,
                message_tx,
            )
            .await
            {
                error!("Error handling outgoing peer {}: {}", peer_address, e);

                // Mark peer as disconnected
                if let Some(config) = peers.write().await.get_mut(&peer_address) {
                    config.connected = false;
                    info!("Peer {} marked for reconnection", peer_address);
                }
            }
        });

        // Mark as connected after successful initial connection
        if let Some(config) = self.peers.write().await.get_mut(address) {
            config.connected = true;
            config.retry_count = 0;
        }

        Ok(())
    }

    /// Handle incoming peer connection
    async fn handle_incoming_peer(
        socket: FederationStream,
        addr: SocketAddr,
        routing: Arc<RwLock<RoutingTable>>,
        channels: Arc<RwLock<HashMap<String, ChannelState>>>,
        clients: Arc<RwLock<HashMap<String, Arc<crate::client::Client>>>>,
        local_name: String,
        _message_tx: mpsc::UnboundedSender<FederatedMessage>,
    ) -> Result<()> {
        let mut framed = Framed::new(socket, IrcCodec::new());

        // Send our SERVER message
        let intro = Message::new(Command::Server {
            name: local_name.clone(),
            hopcount: 0,
            info: "SIRC Federated Server".to_string(),
        });
        framed.send(intro).await?;
        info!("Sent SERVER introduction to {}", addr);

        // Expect SERVER message from peer
        if let Some(Ok(msg)) = framed.next().await {
            if let Command::Server {
                name,
                hopcount,
                info,
            } = msg.command
            {
                info!("Received SERVER from {} (hop {}): {}", name, hopcount, info);

                let (peer_tx, mut peer_rx) = mpsc::unbounded_channel();

                let peer = Arc::new(PeerConnection {
                    name: name.clone(),
                    address: addr,
                    hopcount: hopcount + 1,
                    info,
                    tx: peer_tx,
                });

                routing.write().await.add_peer(Arc::clone(&peer));

                // Send BURST - sync channels
                Self::send_burst(&mut framed, &channels).await?;

                // Split into reader and writer
                let (mut writer, mut reader) = framed.split();

                // Handle messages from this peer (sender task)
                let peer_name = name.clone();
                let routing_clone = Arc::clone(&routing);
                tokio::spawn(async move {
                    while let Some(fed_msg) = peer_rx.recv().await {
                        if let Err(e) = writer.send(fed_msg.payload).await {
                            error!("Error sending to peer {}: {}", peer_name, e);
                            break;
                        }
                    }
                    routing_clone.write().await.remove_peer(&peer_name);
                    info!("Peer {} disconnected", peer_name);
                });

                // Receive messages from peer
                while let Some(result) = reader.next().await {
                    match result {
                        Ok(message) => {
                            Self::handle_peer_message(message, &routing, &channels, &clients).await?;
                        }
                        Err(e) => {
                            warn!("Error receiving from peer: {}", e);
                            break;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Handle outgoing peer connection
    async fn handle_outgoing_peer(
        socket: FederationStream,
        addr: SocketAddr,
        routing: Arc<RwLock<RoutingTable>>,
        channels: Arc<RwLock<HashMap<String, ChannelState>>>,
        clients: Arc<RwLock<HashMap<String, Arc<crate::client::Client>>>>,
        local_name: String,
        _message_tx: mpsc::UnboundedSender<FederatedMessage>,
    ) -> Result<()> {
        let mut framed = Framed::new(socket, IrcCodec::new());

        // Send our SERVER message
        let intro = Message::new(Command::Server {
            name: local_name.clone(),
            hopcount: 0,
            info: "SIRC Federated Server".to_string(),
        });
        framed.send(intro).await?;

        // Wait for SERVER response
        if let Some(Ok(msg)) = framed.next().await {
            if let Command::Server {
                name,
                hopcount,
                info,
            } = msg.command
            {
                info!("Connected to peer {} (hop {})", name, hopcount);

                let (peer_tx, mut peer_rx) = mpsc::unbounded_channel();

                let peer = Arc::new(PeerConnection {
                    name: name.clone(),
                    address: addr,
                    hopcount: hopcount + 1,
                    info,
                    tx: peer_tx,
                });

                routing.write().await.add_peer(Arc::clone(&peer));

                // Receive BURST
                while let Some(Ok(msg)) = framed.next().await {
                    if Self::is_burst_end(&msg) {
                        break;
                    }
                    Self::handle_peer_message(msg, &routing, &channels, &clients).await?;
                }

                // Send our BURST
                Self::send_burst(&mut framed, &channels).await?;

                // Split into reader and writer
                let (mut writer, mut reader) = framed.split();

                // Handle messages (sender task)
                let peer_name = name.clone();
                let routing_clone = Arc::clone(&routing);
                tokio::spawn(async move {
                    while let Some(fed_msg) = peer_rx.recv().await {
                        if let Err(e) = writer.send(fed_msg.payload).await {
                            error!("Error sending to peer {}: {}", peer_name, e);
                            break;
                        }
                    }
                    routing_clone.write().await.remove_peer(&peer_name);
                });

                while let Some(result) = reader.next().await {
                    match result {
                        Ok(message) => {
                            Self::handle_peer_message(message, &routing, &channels, &clients).await?;
                        }
                        Err(e) => {
                            warn!("Error from peer: {}", e);
                            break;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Send BURST (initial state sync)
    async fn send_burst(
        framed: &mut Framed<FederationStream, IrcCodec>,
        channels: &Arc<RwLock<HashMap<String, ChannelState>>>,
    ) -> Result<()> {
        let channels_lock = channels.read().await;

        for (channel_name, state) in channels_lock.iter() {
            let users: Vec<String> = state.users.keys().cloned().collect();
            if !users.is_empty() {
                let sjoin = Message::new(Command::Raw {
                    command: "SJOIN".to_string(),
                    params: vec![channel_name.clone(), users.join(",")],
                });
                framed.send(sjoin).await?;
            }
        }

        // End of burst marker
        let burst_end = Message::new(Command::Raw {
            command: "BURST_END".to_string(),
            params: vec![],
        });
        framed.send(burst_end).await?;

        Ok(())
    }

    /// Check if message signals end of BURST
    fn is_burst_end(msg: &Message) -> bool {
        matches!(
            &msg.command,
            Command::Raw { command, .. } if command == "BURST_END"
        )
    }

    /// Send a federated message
    async fn send_federated_message(
        framed: &mut Framed<FederationStream, IrcCodec>,
        msg: FederatedMessage,
    ) -> Result<()> {
        framed.send(msg.payload).await?;
        Ok(())
    }

    /// Handle message from peer
    async fn handle_peer_message(
        message: Message,
        routing: &Arc<RwLock<RoutingTable>>,
        channels: &Arc<RwLock<HashMap<String, ChannelState>>>,
        clients: &Arc<RwLock<HashMap<String, Arc<crate::client::Client>>>>,
    ) -> Result<()> {
        debug!("Federation message: {:?}", message.command);

        match &message.command {
            Command::Server {
                name,
                hopcount,
                info: _,
            } => {
                // Learn about a remote server through this peer
                info!(
                    "Learned about remote server {} (hop {}) via federation",
                    name, hopcount
                );
                // Add route in routing table
                routing.write().await.add_route(name.clone(), name.clone());
            }

            Command::Raw { command, params } if command == "SJOIN" => {
                // Synchronize channel state
                if params.len() >= 2 {
                    let channel_name = &params[0];
                    let users: HashSet<String> =
                        params[1].split(',').map(String::from).collect();

                    let mut channels_lock = channels.write().await;
                    let state = channels_lock
                        .entry(channel_name.clone())
                        .or_insert_with(|| ChannelState {
                            name: channel_name.clone(),
                            users: HashMap::new(),
                            topic: None,
                        });

                    for user in users {
                        state.users.insert(user.clone(), "remote".to_string());
                    }

                    info!(
                        "Synced channel {} with {} users",
                        channel_name,
                        state.users.len()
                    );
                }
            }

            Command::Raw { command, params } if command == "SMSG" => {
                // Route cross-server message
                // Format: SMSG <origin_server> <origin_nick> <target> :<text>
                if params.len() >= 4 {
                    let origin_server = &params[0];
                    let origin_nick = &params[1];
                    let target = &params[2];
                    let text = &params[3];

                    info!(
                        "Received SMSG from {}@{} to {}: {}",
                        origin_nick, origin_server, target, text
                    );

                    // Deliver to local client if target is local
                    let clients_lock = clients.read().await;
                    if let Some(target_client) = clients_lock.get(target) {
                        // Create PRIVMSG from origin user
                        let msg = Message::with_prefix(
                            Prefix::User {
                                nick: origin_nick.clone(),
                                user: Some(origin_nick.clone()),
                                host: Some(origin_server.clone()),
                            },
                            Command::PrivMsg {
                                target: target.clone(),
                                text: text.clone(),
                            },
                        );

                        if let Err(e) = target_client.tx.send(msg) {
                            warn!("Failed to deliver SMSG to local client {}: {}", target, e);
                        } else {
                            debug!("Delivered SMSG to local client {}", target);
                        }
                    } else {
                        debug!("Target {} not found locally, may be on another server", target);
                    }
                }
            }

            Command::Raw { command, params: _ } if command == "SPING" => {
                // Keepalive ping from peer
                debug!("Received SPING from peer");
                // Response handled by sender task
            }

            Command::Raw { command, params: _ } if command == "SPONG" => {
                // Keepalive pong from peer
                debug!("Received SPONG from peer");
            }

            _ => {
                debug!("Unhandled federation message: {:?}", message.command);
            }
        }

        Ok(())
    }

    /// Broadcast a message to all peers
    pub async fn broadcast(&self, msg: FederatedMessage) -> Result<()> {
        let routing = self.routing.read().await;

        for peer in routing.direct_peers.values() {
            if let Err(e) = peer.send(msg.clone()) {
                warn!("Failed to broadcast to {}: {}", peer.name, e);
            }
        }

        Ok(())
    }

    /// Route a message to a specific server
    pub async fn route_to(&self, server: &str, msg: FederatedMessage) -> Result<()> {
        let routing = self.routing.read().await;

        if let Some(peer) = routing.get_route(server) {
            peer.send(msg)?;
        } else {
            warn!("No route to server: {}", server);
        }

        Ok(())
    }

    /// Get list of all known servers
    pub async fn get_servers(&self) -> Vec<String> {
        self.routing.read().await.all_servers()
    }

    /// Join a federated channel
    pub async fn join_channel(&self, channel: String, user: String) -> Result<()> {
        let mut channels = self.channels.write().await;

        let state = channels.entry(channel.clone()).or_insert_with(|| {
            ChannelState {
                name: channel.clone(),
                users: HashMap::new(),
                topic: None,
            }
        });

        state.users.insert(user.clone(), self.local_name.clone());

        // Broadcast SJOIN to all peers
        let fed_msg = FederatedMessage {
            origin_server: self.local_name.clone(),
            target_server: None,
            payload: Message::new(Command::Raw {
                command: "SJOIN".to_string(),
                params: vec![channel, user],
            }),
        };

        self.broadcast(fed_msg).await?;

        Ok(())
    }

    /// Send a message to a user (possibly on remote server)
    pub async fn send_message(
        &self,
        origin_nick: &str,
        target_nick: &str,
        text: String,
    ) -> Result<()> {
        // Check if target is on a known server
        let channels = self.channels.read().await;

        // Search all channels for the target user
        for channel_state in channels.values() {
            if let Some(target_server) = channel_state.users.get(target_nick) {
                if target_server == &self.local_name {
                    // Local user - will be handled by server
                    return Ok(());
                } else {
                    // Remote user - route through federation
                    let fed_msg = FederatedMessage {
                        origin_server: self.local_name.clone(),
                        target_server: Some(target_server.clone()),
                        payload: Message::new(Command::Raw {
                            command: "SMSG".to_string(),
                            params: vec![
                                self.local_name.clone(),
                                origin_nick.to_string(),
                                target_nick.to_string(),
                                format!(":{}", text),
                            ],
                        }),
                    };

                    self.route_to(target_server, fed_msg).await?;
                    return Ok(());
                }
            }
        }

        // User not found in any channel
        warn!("Target user {} not found in federation", target_nick);
        Ok(())
    }

    /// Send keepalive ping to all peers
    pub async fn send_keepalive(&self) -> Result<()> {
        let ping_msg = FederatedMessage {
            origin_server: self.local_name.clone(),
            target_server: None,
            payload: Message::new(Command::Raw {
                command: "SPING".to_string(),
                params: vec![self.local_name.clone()],
            }),
        };

        self.broadcast(ping_msg).await?;
        Ok(())
    }

    /// Start keepalive task (call once during server initialization)
    pub fn start_keepalive_task(self: Arc<Self>) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(30));
            loop {
                interval.tick().await;
                if let Err(e) = self.send_keepalive().await {
                    error!("Failed to send keepalive: {}", e);
                }
            }
        });
    }

    /// Start auto-reconnect task (call once during server initialization)
    pub fn start_reconnect_task(self: Arc<Self>) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(5));
            loop {
                interval.tick().await;
                self.check_and_reconnect().await;
            }
        });
    }

    /// Check for disconnected peers and attempt reconnection
    async fn check_and_reconnect(&self) {
        let mut peers_to_reconnect = Vec::new();

        // Find disconnected peers
        {
            let peers = self.peers.read().await;
            for (address, config) in peers.iter() {
                if !config.connected && config.retry_count < config.max_retries {
                    peers_to_reconnect.push(address.clone());
                }
            }
        }

        // Attempt reconnection with backoff
        for address in peers_to_reconnect {
            let backoff = {
                let peers = self.peers.read().await;
                if let Some(config) = peers.get(&address) {
                    config.backoff_duration()
                } else {
                    continue;
                }
            };

            // Wait for backoff period
            sleep(backoff).await;

            // Increment retry count
            if let Some(config) = self.peers.write().await.get_mut(&address) {
                config.retry_count += 1;
                info!(
                    "Attempting to reconnect to {} (attempt {}/{})",
                    address, config.retry_count, config.max_retries
                );
            }

            // Attempt reconnection
            match TcpStream::connect(&address).await {
                Ok(tcp_stream) => {
                    info!("Successfully reconnected to {}", address);

                    let addr = match tcp_stream.peer_addr() {
                        Ok(a) => a,
                        Err(_) => continue,
                    };

                    // Wrap with TLS if enabled
                    let stream = if let Some(ref connector) = self.tls_connector {
                        let server_name = match rustls::pki_types::ServerName::try_from(
                            address.split(':').next().unwrap_or("localhost").to_string()
                        ) {
                            Ok(name) => name,
                            Err(_) => continue,
                        };

                        match connector.connect(server_name, tcp_stream).await {
                            Ok(tls_stream) => {
                                info!("TLS handshake completed on reconnection to {}", address);
                                FederationStream::TlsClient(Box::new(tls_stream))
                            }
                            Err(e) => {
                                error!("TLS handshake failed on reconnection to {}: {}", address, e);
                                continue;
                            }
                        }
                    } else {
                        FederationStream::Plain(tcp_stream)
                    };

                    // Reset retry count on success
                    if let Some(config) = self.peers.write().await.get_mut(&address) {
                        config.connected = true;
                        config.retry_count = 0;
                    }

                    let routing = Arc::clone(&self.routing);
                    let channels = Arc::clone(&self.channels);
                    let clients = Arc::clone(&self.clients);
                    let peers = Arc::clone(&self.peers);
                    let local_name = self.local_name.clone();
                    let message_tx = self.message_tx.clone();
                    let peer_address = address.clone();

                    // Spawn handler task
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_outgoing_peer(
                            stream,
                            addr,
                            routing,
                            channels,
                            clients,
                            local_name,
                            message_tx,
                        )
                        .await
                        {
                            error!("Error after reconnecting to {}: {}", peer_address, e);

                            // Mark as disconnected again
                            if let Some(config) = peers.write().await.get_mut(&peer_address) {
                                config.connected = false;
                            }
                        }
                    });
                }
                Err(e) => {
                    warn!("Failed to reconnect to {}: {}", address, e);

                    // Check if max retries reached
                    if let Some(config) = self.peers.read().await.get(&address) {
                        if config.retry_count >= config.max_retries {
                            error!(
                                "Max reconnection attempts reached for {}. Giving up.",
                                address
                            );
                        }
                    }
                }
            }
        }
    }

    /// Start split brain detection task
    pub fn start_split_brain_detection(self: Arc<Self>) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                self.detect_and_heal_partitions().await;
            }
        });
    }

    /// Detect network partitions and heal them
    async fn detect_and_heal_partitions(&self) {
        const PARTITION_TIMEOUT: Duration = Duration::from_secs(120); // 2 minutes

        let mut unreachable_peers = HashSet::new();
        let mut healed_peers = HashSet::new();

        // Check for stale peers
        {
            let peers = self.peers.read().await;
            for (address, config) in peers.iter() {
                if config.connected && config.is_stale(PARTITION_TIMEOUT) {
                    warn!("Peer {} appears unreachable (no activity for {}s)",
                          address, PARTITION_TIMEOUT.as_secs());
                    unreachable_peers.insert(address.clone());
                }
            }
        }

        // Check existing partitions for healing
        {
            let mut partitions = self.partitions.write().await;
            let mut healed_partitions = Vec::new();

            for (idx, partition) in partitions.iter().enumerate() {
                let mut all_healed = true;

                for server in &partition.unreachable_servers {
                    if let Some(config) = self.peers.read().await.get(server) {
                        if config.connected && !config.is_stale(PARTITION_TIMEOUT) {
                            healed_peers.insert(server.clone());
                        } else {
                            all_healed = false;
                        }
                    }
                }

                if all_healed {
                    healed_partitions.push(idx);
                    info!("Network partition {} has healed after {:?}",
                          partition.id, partition.detected_at.elapsed());
                }
            }

            // Remove healed partitions (in reverse order to maintain indices)
            for idx in healed_partitions.into_iter().rev() {
                partitions.remove(idx);
            }
        }

        // Create new partition if we have unreachable peers
        if !unreachable_peers.is_empty() {
            let partition_id = format!("partition-{}", Instant::now().elapsed().as_secs());
            let partition = NetworkPartition::new(partition_id.clone(), unreachable_peers.clone());

            error!(
                "Network partition detected: {} - {} servers unreachable: {:?}",
                partition_id,
                unreachable_peers.len(),
                unreachable_peers
            );

            self.metrics.increment_partitions_detected();
            self.partitions.write().await.push(partition);
        }

        // Trigger state resynchronization for healed peers
        if !healed_peers.is_empty() {
            info!("Triggering state resync for healed peers: {:?}", healed_peers);
            self.metrics.increment_partitions_healed();

            for peer_address in healed_peers {
                // Update last_seen timestamp
                if let Some(config) = self.peers.write().await.get_mut(&peer_address) {
                    config.update_last_seen();
                }
            }
        }
    }

    /// Get current network partition status
    pub async fn get_partition_status(&self) -> Vec<NetworkPartition> {
        self.partitions.read().await.clone()
    }

    /// Update peer activity timestamp (called on receiving SPONG)
    pub async fn update_peer_activity(&self, peer_address: &str) {
        if let Some(config) = self.peers.write().await.get_mut(peer_address) {
            config.update_last_seen();
            config.last_pong_received = Some(Instant::now());
        }
    }
}

impl Default for RoutingTable {
    fn default() -> Self {
        Self::new()
    }
}
