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
use tokio_rustls::{TlsAcceptor, TlsConnector};
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

/// Link-state advertisement: a server's view of its directly-connected
/// peers, broadcast periodically so every other server can build the full
/// graph and run Dijkstra. Edges carry observed `latency_ms` so the chosen
/// route is the *fastest*, not just the *fewest hops*.
#[derive(Debug, Clone)]
pub struct LinkStateAd {
    pub origin: String,
    /// `peer_name -> last observed RTT in ms`. `None` = unknown (cost = 50).
    pub neighbors: HashMap<String, Option<f64>>,
}

/// Routing table for mesh network with Dijkstra-based shortest-path
/// resolution.
pub struct RoutingTable {
    pub direct_peers: HashMap<String, Arc<PeerConnection>>,
    /// LSAs from every server we've heard from (including ourselves). Used
    /// as the link-state graph for Dijkstra.
    lsas: HashMap<String, LinkStateAd>,
    /// `target_server -> direct_peer_name` mapping. Recomputed whenever
    /// the LSA database changes.
    routes: HashMap<String, String>,
    /// Local server name; needed to root Dijkstra.
    local_name: String,
}

impl RoutingTable {
    pub fn new() -> Self { Self::new_named(String::new()) }

    pub fn new_named(local_name: String) -> Self {
        Self {
            direct_peers: HashMap::new(),
            lsas: HashMap::new(),
            routes: HashMap::new(),
            local_name,
        }
    }

    #[allow(dead_code)] // exposed for tests / future server-rename use cases.
    pub fn set_local_name(&mut self, name: String) {
        self.local_name = name;
        self.refresh_self_lsa();
    }

    pub fn add_peer(&mut self, peer: Arc<PeerConnection>) {
        let name = peer.name.clone();
        self.direct_peers.insert(name.clone(), peer);
        self.routes.insert(name.clone(), name); // direct route to self
        self.refresh_self_lsa();
        self.recompute_routes();
    }

    /// Legacy single-hop hint. Real routing comes from `recompute_routes()`
    /// over the LSA graph; kept so existing callers compile.
    pub fn add_route(&mut self, server: String, via: String) {
        self.routes.entry(server).or_insert(via);
    }

    /// Update the latency estimate for a directly-connected peer. Triggers
    /// LSA refresh + route recompute.
    pub fn update_peer_latency(&mut self, peer: &str, rtt_ms: f64) {
        if !self.direct_peers.contains_key(peer) { return; }
        let local = self.local_name.clone();
        let lsa = self.lsas.entry(local.clone()).or_insert_with(|| LinkStateAd {
            origin: local,
            neighbors: HashMap::new(),
        });
        lsa.neighbors.insert(peer.to_string(), Some(rtt_ms));
        self.recompute_routes();
    }

    /// Apply a remote server's link-state advertisement and rebuild routes.
    pub fn apply_lsa(&mut self, lsa: LinkStateAd) {
        self.lsas.insert(lsa.origin.clone(), lsa);
        self.recompute_routes();
    }

    fn refresh_self_lsa(&mut self) {
        if self.local_name.is_empty() { return; }
        let mut ns: HashMap<String, Option<f64>> = HashMap::new();
        for n in self.direct_peers.keys() {
            let prev = self.lsas
                .get(&self.local_name)
                .and_then(|l| l.neighbors.get(n))
                .copied()
                .flatten();
            ns.insert(n.clone(), prev);
        }
        self.lsas.insert(self.local_name.clone(), LinkStateAd {
            origin: self.local_name.clone(),
            neighbors: ns,
        });
    }

    /// Build server → next-hop map from the LSA graph via Dijkstra.
    /// Edge cost = observed latency_ms (default 50.0 when unknown).
    fn recompute_routes(&mut self) {
        if self.local_name.is_empty() { return; }
        use std::cmp::Ordering;
        use std::collections::BinaryHeap;

        #[derive(PartialEq)]
        struct Node { cost: f64, name: String, first_hop: Option<String> }
        impl Eq for Node {}
        impl PartialOrd for Node { fn partial_cmp(&self, o: &Self) -> Option<Ordering> { Some(self.cmp(o)) } }
        impl Ord for Node {
            fn cmp(&self, o: &Self) -> Ordering {
                o.cost.partial_cmp(&self.cost).unwrap_or(Ordering::Equal)
            }
        }

        let mut routes: HashMap<String, String> = HashMap::new();
        let mut visited: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut heap = BinaryHeap::new();
        heap.push(Node { cost: 0.0, name: self.local_name.clone(), first_hop: None });

        while let Some(Node { cost, name, first_hop }) = heap.pop() {
            if !visited.insert(name.clone()) { continue; }
            if let Some(hop) = first_hop.clone() {
                routes.insert(name.clone(), hop);
            }
            if let Some(lsa) = self.lsas.get(&name) {
                for (nbr, latency) in &lsa.neighbors {
                    if visited.contains(nbr) { continue; }
                    let edge = latency.unwrap_or(50.0).max(1.0);
                    let next_hop = first_hop.clone().or_else(|| Some(nbr.clone()));
                    heap.push(Node { cost: cost + edge, name: nbr.clone(), first_hop: next_hop });
                }
            }
        }

        self.routes = routes;
        for n in self.direct_peers.keys() {
            self.routes.insert(n.clone(), n.clone());
        }
    }

    pub fn get_route(&self, server: &str) -> Option<Arc<PeerConnection>> {
        self.routes
            .get(server)
            .and_then(|via| self.direct_peers.get(via))
            .cloned()
    }

    pub fn all_servers(&self) -> Vec<String> {
        let mut s: std::collections::HashSet<String> = self.routes.keys().cloned().collect();
        s.extend(self.lsas.keys().cloned());
        let mut v: Vec<String> = s.into_iter().collect();
        v.sort_unstable();
        v
    }

    /// Snapshot of our own LSA, for periodic broadcast to peers.
    pub fn self_lsa(&self) -> Option<&LinkStateAd> {
        self.lsas.get(&self.local_name)
    }

    pub fn remove_peer(&mut self, peer_name: &str) {
        self.direct_peers.remove(peer_name);
        if let Some(lsa) = self.lsas.get_mut(&self.local_name) {
            lsa.neighbors.remove(peer_name);
        }
        self.recompute_routes();
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
    /// Wrapped in `Mutex<Option<...>>` because the receiver must be moved
    /// into the router task once. After `start_router_task` runs, this is `None`.
    message_rx: tokio::sync::Mutex<Option<mpsc::UnboundedReceiver<FederatedMessage>>>,
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
            local_name: local_name.clone(),
            routing: Arc::new(RwLock::new(RoutingTable::new_named(local_name))),
            channels: Arc::new(RwLock::new(HashMap::new())),
            peers: Arc::new(RwLock::new(HashMap::new())),
            partitions: Arc::new(RwLock::new(Vec::new())),
            metrics: MetricsCollector::new(),
            tls: None,
            tls_acceptor: None,
            tls_connector: None,
            message_rx: tokio::sync::Mutex::new(Some(rx)),
            message_tx: tx,
            clients,
        }
    }

    /// Get metrics collector reference
    pub fn metrics(&self) -> Arc<MetricsCollector> {
        Arc::clone(&self.metrics)
    }

    /// Start the central router task. Must be called once during startup;
    /// subsequent calls are no-ops. The router consumes `FederatedMessage`
    /// values produced via `get_sender()` and dispatches them based on
    /// `origin_server` / `target_server` (broadcast or unicast through
    /// `route_to`). This lets non-federation code (e.g. server admin
    /// hooks) inject federated traffic without holding the routing mutex.
    pub async fn start_router_task(self: &Arc<Self>) {
        let mut guard = self.message_rx.lock().await;
        let rx = match guard.take() {
            Some(r) => r,
            None => return, // already started
        };
        drop(guard);
        let me = Arc::clone(self);
        tokio::spawn(async move {
            let mut rx = rx;
            while let Some(msg) = rx.recv().await {
                me.metrics.increment_messages_routed();
                debug!(
                    "router: dispatching message from {} target={:?}",
                    msg.origin_server, msg.target_server
                );
                match &msg.target_server {
                    None => {
                        if let Err(e) = me.broadcast(msg).await {
                            warn!("router broadcast failed: {}", e);
                        }
                    }
                    Some(server) => {
                        let server = server.clone();
                        if let Err(e) = me.route_to(&server, msg).await {
                            warn!("router route_to({}) failed: {}", server, e);
                        }
                    }
                }
            }
            warn!("federation router task exiting (sender closed)");
        });
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

    /// Start federation listener
    pub async fn listen(&self, addr: SocketAddr) -> Result<()> {
        let listener = TcpListener::bind(addr).await?;
        let tls_enabled = self.tls.is_some();
        info!("Federation listener started on {} (TLS: {})", addr, tls_enabled);

        let routing = Arc::clone(&self.routing);
        let channels = Arc::clone(&self.channels);
        let clients = Arc::clone(&self.clients);
        let peers = Arc::clone(&self.peers);
        let metrics = Arc::clone(&self.metrics);
        let local_name = self.local_name.clone();
        let message_tx = self.message_tx.clone();
        let tls_acceptor = self.tls_acceptor.clone();

        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((socket, addr)) => {
                        info!("Incoming federation connection from {}", addr);
                        metrics.increment_active_connections();
                        let routing = Arc::clone(&routing);
                        let channels = Arc::clone(&channels);
                        let clients = Arc::clone(&clients);
                        let peers = Arc::clone(&peers);
                        let metrics_inner = Arc::clone(&metrics);
                        let local_name = local_name.clone();
                        let message_tx = message_tx.clone();
                        let tls_acceptor = tls_acceptor.clone();

                        tokio::spawn(async move {
                            // Wrap with TLS if enabled
                            let stream = if let Some(acceptor) = tls_acceptor {
                                match acceptor.accept(socket).await {
                                    Ok(tls_stream) => {
                                        info!("TLS handshake completed with {}", addr);
                                        metrics_inner.increment_tls_success();
                                        FederationStream::TlsServer(Box::new(tls_stream))
                                    }
                                    Err(e) => {
                                        error!("TLS handshake failed with {}: {}", addr, e);
                                        metrics_inner.increment_tls_failed();
                                        metrics_inner.decrement_active_connections();
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
                                peers,
                                Arc::clone(&metrics_inner),
                                local_name,
                                message_tx,
                            )
                            .await
                            {
                                error!("Error handling incoming peer: {}", e);
                            }
                            metrics_inner.decrement_active_connections();
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

        let tcp_stream = match TcpStream::connect(address).await {
            Ok(s) => s,
            Err(e) => {
                self.metrics.increment_failed_connections();
                return Err(e.into());
            }
        };
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
                    self.metrics.increment_tls_failed();
                    self.metrics.increment_failed_connections();
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
        let metrics = Arc::clone(&self.metrics);
        let local_name = self.local_name.clone();
        let message_tx = self.message_tx.clone();
        let peer_address = address.to_string();

        self.metrics.increment_active_connections();
        if self.tls_connector.is_some() {
            self.metrics.increment_tls_success();
        }

        tokio::spawn({
            let peers_outer = Arc::clone(&peers);
            let metrics_outer = Arc::clone(&metrics);
            async move {
                if let Err(e) = Self::handle_outgoing_peer(
                    stream,
                    addr,
                    routing,
                    channels,
                    clients,
                    peers,
                    metrics,
                    local_name,
                    message_tx,
                )
                .await
                {
                    error!("Error handling outgoing peer {}: {}", peer_address, e);
                    if let Some(config) = peers_outer.write().await.get_mut(&peer_address) {
                        config.connected = false;
                        info!("Peer {} marked for reconnection", peer_address);
                    }
                }
                metrics_outer.decrement_active_connections();
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
        peers: Arc<RwLock<HashMap<String, PeerConfig>>>,
        metrics: Arc<MetricsCollector>,
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
                            Self::handle_peer_message(message, addr, &routing, &channels, &clients, &peers, &metrics).await?;
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
        peers: Arc<RwLock<HashMap<String, PeerConfig>>>,
        metrics: Arc<MetricsCollector>,
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
                    Self::handle_peer_message(msg, addr, &routing, &channels, &clients, &peers, &metrics).await?;
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
                            Self::handle_peer_message(message, addr, &routing, &channels, &clients, &peers, &metrics).await?;
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

        for (_, state) in channels_lock.iter() {
            // Iterate by ChannelState so the per-channel topic comes along too.
            let users: Vec<String> = state.users.keys().cloned().collect();
            if !users.is_empty() {
                let sjoin = Message::new(Command::Raw {
                    command: "SJOIN".to_string(),
                    params: vec![state.name.clone(), users.join(",")],
                });
                framed.send(sjoin).await?;
            }
            if let Some(ref topic) = state.topic {
                let stopic = Message::new(Command::Raw {
                    command: "STOPIC".to_string(),
                    params: vec![state.name.clone(), topic.clone()],
                });
                framed.send(stopic).await?;
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

    /// Handle message from peer
    async fn handle_peer_message(
        message: Message,
        peer_addr: SocketAddr,
        routing: &Arc<RwLock<RoutingTable>>,
        channels: &Arc<RwLock<HashMap<String, ChannelState>>>,
        clients: &Arc<RwLock<HashMap<String, Arc<crate::client::Client>>>>,
        peers: &Arc<RwLock<HashMap<String, PeerConfig>>>,
        metrics: &Arc<MetricsCollector>,
    ) -> Result<()> {
        debug!("Federation message: {:?}", message.command);
        metrics.increment_messages_received();

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

            Command::Raw { command, params } if command == "STOPIC" => {
                if params.len() >= 2 {
                    let channel_name = &params[0];
                    let topic = params[1].clone();
                    let mut chans = channels.write().await;
                    let st = chans
                        .entry(channel_name.clone())
                        .or_insert_with(|| ChannelState {
                            name: channel_name.clone(),
                            users: HashMap::new(),
                            topic: None,
                        });
                    st.topic = Some(topic);
                    info!("Federation: topic for {} synced", st.name);
                }
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
                // Keepalive ping from peer — record activity.
                debug!("Received SPING from peer {}", peer_addr);
                let mut peers_w = peers.write().await;
                if let Some(cfg) = peers_w.get_mut(&peer_addr.to_string()) {
                    cfg.update_last_seen();
                    cfg.last_ping_sent = Some(Instant::now());
                }
            }

            Command::Raw { command, params: _ } if command == "SPONG" => {
                // Keepalive pong — peer is alive; refresh activity + feed
                // observed RTT into the routing table for Dijkstra weighting.
                debug!("Received SPONG from peer {}", peer_addr);
                let mut peers_w = peers.write().await;
                let mut peer_name: Option<String> = None;
                let mut latency_ms: Option<f64> = None;
                if let Some(cfg) = peers_w.get_mut(&peer_addr.to_string()) {
                    cfg.update_last_seen();
                    cfg.last_pong_received = Some(Instant::now());
                    if let (Some(sent), Some(recvd)) = (cfg.last_ping_sent, cfg.last_pong_received) {
                        let l = recvd.saturating_duration_since(sent).as_secs_f64() * 1000.0;
                        latency_ms = Some(l);
                        let mc = Arc::clone(metrics);
                        tokio::spawn(async move { mc.record_latency(l).await; });
                    }
                }
                drop(peers_w);
                // Resolve peer's name from the routing table to update its
                // edge weight. The routing table is keyed by server name,
                // not address, so we look up via direct_peers iteration.
                if latency_ms.is_some() {
                    let routing_r = routing.read().await;
                    for (name, p) in &routing_r.direct_peers {
                        if p.address == peer_addr { peer_name = Some(name.clone()); break; }
                    }
                    drop(routing_r);
                }
                if let (Some(name), Some(rtt)) = (peer_name, latency_ms) {
                    routing.write().await.update_peer_latency(&name, rtt);
                }
            }

            Command::Raw { command, params } if command == "LSA" => {
                // Link-state advertisement. Format:
                //   LSA <origin> <neighbor1[:rtt]> <neighbor2[:rtt]> ...
                // RTT is "?" when unknown.
                if let Some(origin) = params.first() {
                    let mut neighbors: HashMap<String, Option<f64>> = HashMap::new();
                    for n in params.iter().skip(1) {
                        if let Some((name, rtt)) = n.split_once(':') {
                            let r = if rtt == "?" { None } else { rtt.parse().ok() };
                            neighbors.insert(name.to_string(), r);
                        } else {
                            neighbors.insert(n.clone(), None);
                        }
                    }
                    let lsa = LinkStateAd { origin: origin.clone(), neighbors };
                    routing.write().await.apply_lsa(lsa);
                    debug!("Federation: applied LSA from {}", origin);
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
        let mut sent = 0u64;
        for peer in routing.direct_peers.values() {
            if let Err(e) = peer.send(msg.clone()) {
                warn!("Failed to broadcast to {}: {}", peer.name, e);
            } else {
                sent += 1;
            }
        }
        for _ in 0..sent {
            self.metrics.increment_messages_sent();
        }
        Ok(())
    }

    /// Route a message to a specific server
    pub async fn route_to(&self, server: &str, msg: FederatedMessage) -> Result<()> {
        let routing = self.routing.read().await;
        if let Some(peer) = routing.get_route(server) {
            peer.send(msg)?;
            self.metrics.increment_messages_sent();
        } else {
            warn!("No route to server: {}", server);
        }
        Ok(())
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

    /// Route a private message to a user that may live on a remote server.
    /// Returns `Ok(true)` if the user was found in the federated state and the
    /// message was dispatched (locally or via SMSG), `Ok(false)` if no server
    /// in the routing table claims this nick.
    pub async fn send_message(
        &self,
        origin_nick: &str,
        target_nick: &str,
        text: String,
    ) -> Result<bool> {
        let channels = self.channels.read().await;
        for channel_state in channels.values() {
            if let Some(target_server) = channel_state.users.get(target_nick) {
                if target_server == &self.local_name {
                    // Caller's local lookup already failed — the federated
                    // ChannelState says "local" but client isn't connected.
                    return Ok(false);
                }
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
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Public read-only access to the routing table for diagnostics
    /// (`/STATS`, admin tooling). Returns `(direct_peers, all_known_servers)`.
    pub async fn route_summary(&self) -> (Vec<String>, Vec<String>) {
        let routing = self.routing.read().await;
        let direct: Vec<String> = routing.direct_peers.keys().cloned().collect();
        let all = routing.all_servers();
        (direct, all)
    }

    /// Diagnostic info about a peer connection (address, hopcount, info).
    pub async fn peer_info(&self, name: &str) -> Option<(SocketAddr, u32, String)> {
        let routing = self.routing.read().await;
        routing
            .direct_peers
            .get(name)
            .map(|p| (p.address, p.hopcount, p.info.clone()))
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

    /// Build and broadcast a link-state advertisement so every other server
    /// can rebuild the link-state graph and run Dijkstra over it.
    pub async fn send_lsa(&self) -> Result<()> {
        let routing = self.routing.read().await;
        let lsa = match routing.self_lsa() {
            Some(l) if !l.neighbors.is_empty() => l.clone(),
            _ => return Ok(()), // no peers to advertise
        };
        drop(routing);
        let mut params = vec![lsa.origin];
        for (n, rtt) in lsa.neighbors {
            let s = match rtt {
                Some(ms) => format!("{}:{:.2}", n, ms),
                None => format!("{}:?", n),
            };
            params.push(s);
        }
        let msg = FederatedMessage {
            origin_server: self.local_name.clone(),
            target_server: None,
            payload: Message::new(Command::Raw { command: "LSA".to_string(), params }),
        };
        self.broadcast(msg).await
    }

    /// Periodic LSA broadcast — every 60 s. Allows the cluster to converge
    /// on shortest-path routes within a couple of intervals.
    pub fn start_lsa_broadcast_task(self: Arc<Self>) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                if let Err(e) = self.send_lsa().await {
                    warn!("LSA broadcast failed: {}", e);
                }
            }
        });
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
            self.metrics.increment_reconnection_attempt();

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
                    let metrics = Arc::clone(&self.metrics);
                    let local_name = self.local_name.clone();
                    let message_tx = self.message_tx.clone();
                    let peer_address = address.clone();

                    metrics.increment_reconnection_success();
                    metrics.increment_active_connections();
                    if self.tls_connector.is_some() {
                        metrics.increment_tls_success();
                    }

                    // Spawn handler task
                    let peers_outer = Arc::clone(&peers);
                    let metrics_outer = Arc::clone(&metrics);
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_outgoing_peer(
                            stream,
                            addr,
                            routing,
                            channels,
                            clients,
                            peers,
                            metrics,
                            local_name,
                            message_tx,
                        )
                        .await
                        {
                            error!("Error after reconnecting to {}: {}", peer_address, e);

                            // Mark as disconnected again
                            if let Some(config) = peers_outer.write().await.get_mut(&peer_address) {
                                config.connected = false;
                            }
                        }
                        metrics_outer.decrement_active_connections();
                    });
                }
                Err(e) => {
                    warn!("Failed to reconnect to {}: {}", address, e);
                    self.metrics.increment_failed_connections();

                    // Check if max retries reached
                    if let Some(config) = self.peers.read().await.get(&address) {
                        if config.retry_count >= config.max_retries {
                            error!(
                                "Max reconnection attempts reached for {}. Giving up.",
                                address
                            );
                            info!(
                                "Giving up on peer with stored address {}",
                                config.address
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

}

impl Default for RoutingTable {
    fn default() -> Self {
        Self::new()
    }
}
