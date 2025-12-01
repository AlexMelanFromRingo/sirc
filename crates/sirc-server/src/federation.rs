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
use sirc_protocol::{Command, IrcCodec, Message};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, RwLock};
use tokio_util::codec::Framed;
use tracing::{debug, error, info, warn};

/// Federated message for routing between servers
#[derive(Debug, Clone)]
pub struct FederatedMessage {
    pub origin_server: String,
    pub target_server: Option<String>, // None = broadcast
    pub payload: Message,
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
    message_rx: mpsc::UnboundedReceiver<FederatedMessage>,
    message_tx: mpsc::UnboundedSender<FederatedMessage>,
}

/// Federated channel state
#[derive(Clone)]
pub struct ChannelState {
    pub name: String,
    pub users: HashMap<String, String>, // nick -> server
    pub topic: Option<String>,
}

impl FederationManager {
    pub fn new(local_name: String) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();

        Self {
            local_name,
            routing: Arc::new(RwLock::new(RoutingTable::new())),
            channels: Arc::new(RwLock::new(HashMap::new())),
            message_rx: rx,
            message_tx: tx,
        }
    }

    /// Get a message sender for other components
    pub fn get_sender(&self) -> mpsc::UnboundedSender<FederatedMessage> {
        self.message_tx.clone()
    }

    /// Start federation listener
    pub async fn listen(&self, addr: SocketAddr) -> Result<()> {
        let listener = TcpListener::bind(addr).await?;
        info!("Federation listener started on {}", addr);

        let routing = Arc::clone(&self.routing);
        let channels = Arc::clone(&self.channels);
        let local_name = self.local_name.clone();
        let message_tx = self.message_tx.clone();

        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((socket, addr)) => {
                        info!("Incoming federation connection from {}", addr);
                        let routing = Arc::clone(&routing);
                        let channels = Arc::clone(&channels);
                        let local_name = local_name.clone();
                        let message_tx = message_tx.clone();

                        tokio::spawn(async move {
                            if let Err(e) = Self::handle_incoming_peer(
                                socket,
                                addr,
                                routing,
                                channels,
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

        let stream = TcpStream::connect(address).await?;
        let addr = stream.peer_addr()?;

        let routing = Arc::clone(&self.routing);
        let channels = Arc::clone(&self.channels);
        let local_name = self.local_name.clone();
        let message_tx = self.message_tx.clone();

        tokio::spawn(async move {
            if let Err(e) = Self::handle_outgoing_peer(
                stream,
                addr,
                routing,
                channels,
                local_name,
                message_tx,
            )
            .await
            {
                error!("Error handling outgoing peer: {}", e);
            }
        });

        Ok(())
    }

    /// Handle incoming peer connection
    async fn handle_incoming_peer(
        socket: TcpStream,
        addr: SocketAddr,
        routing: Arc<RwLock<RoutingTable>>,
        channels: Arc<RwLock<HashMap<String, ChannelState>>>,
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
                            Self::handle_peer_message(message, &routing, &channels).await?;
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
        socket: TcpStream,
        addr: SocketAddr,
        routing: Arc<RwLock<RoutingTable>>,
        channels: Arc<RwLock<HashMap<String, ChannelState>>>,
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
                    Self::handle_peer_message(msg, &routing, &channels).await?;
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
                            Self::handle_peer_message(message, &routing, &channels).await?;
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
        framed: &mut Framed<TcpStream, IrcCodec>,
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
        framed: &mut Framed<TcpStream, IrcCodec>,
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
}

impl Default for RoutingTable {
    fn default() -> Self {
        Self::new()
    }
}
