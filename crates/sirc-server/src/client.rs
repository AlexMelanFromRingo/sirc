//! Client connection handling

use crate::server::ServerState;
use anyhow::Result;
use futures::{SinkExt, StreamExt};
use sirc_crypto::EncryptedSession;
use sirc_protocol::{Command, IrcCodec, Message, Prefix};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, RwLock};
use tokio_util::codec::Framed;
use tracing::{debug, info, warn};

/// Pending message awaiting acknowledgment
#[derive(Debug, Clone)]
struct PendingMessage {
    message_id: String,
    message: Message,
    sent_at: Instant,
    retry_count: u32,
    target: String,
}

impl PendingMessage {
    fn new(message_id: String, message: Message, target: String) -> Self {
        Self {
            message_id,
            message,
            sent_at: Instant::now(),
            retry_count: 0,
            target,
        }
    }

    fn is_expired(&self, timeout: Duration) -> bool {
        self.sent_at.elapsed() > timeout
    }
}

/// Delivery confirmation tracker
pub struct DeliveryTracker {
    pending: RwLock<HashMap<String, PendingMessage>>,
    next_id: RwLock<u64>,
    ack_timeout: Duration,
    max_retries: u32,
}

impl DeliveryTracker {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            pending: RwLock::new(HashMap::new()),
            next_id: RwLock::new(0),
            ack_timeout: Duration::from_secs(5),
            max_retries: 3,
        })
    }

    async fn generate_id(&self) -> String {
        let mut id = self.next_id.write().await;
        *id += 1;
        format!("msg-{}", *id)
    }

    async fn track_message(&self, message_id: String, message: Message, target: String) {
        let pending = PendingMessage::new(message_id.clone(), message, target);
        self.pending.write().await.insert(message_id, pending);
    }

    async fn confirm(&self, message_id: &str) -> bool {
        self.pending.write().await.remove(message_id).is_some()
    }

    async fn check_timeouts(&self) -> Vec<PendingMessage> {
        let mut expired = Vec::new();
        let mut pending = self.pending.write().await;

        let mut to_remove = Vec::new();
        for (id, msg) in pending.iter_mut() {
            if msg.is_expired(self.ack_timeout) {
                if msg.retry_count < self.max_retries {
                    msg.retry_count += 1;
                    msg.sent_at = Instant::now();
                    expired.push(msg.clone());
                } else {
                    warn!("Message {} to {} failed after {} retries",
                          id, msg.target, self.max_retries);
                    to_remove.push(id.clone());
                }
            }
        }

        for id in to_remove {
            pending.remove(&id);
        }

        expired
    }

    async fn pending_count(&self) -> usize {
        self.pending.read().await.len()
    }
}

pub struct Client {
    pub nick: RwLock<Option<String>>,
    pub username: RwLock<Option<String>>,
    pub realname: RwLock<Option<String>>,
    pub session: RwLock<EncryptedSession>,
    pub tx: mpsc::UnboundedSender<Message>,
    pub delivery_tracker: Arc<DeliveryTracker>,
}

impl Client {
    pub fn new(tx: mpsc::UnboundedSender<Message>) -> Arc<Self> {
        Arc::new(Self {
            nick: RwLock::new(None),
            username: RwLock::new(None),
            realname: RwLock::new(None),
            session: RwLock::new(EncryptedSession::new()),
            tx,
            delivery_tracker: DeliveryTracker::new(),
        })
    }
}

pub struct ClientHandler {
    socket: TcpStream,
    addr: SocketAddr,
    state: Arc<ServerState>,
}

impl ClientHandler {
    pub fn new(socket: TcpStream, addr: SocketAddr, state: Arc<ServerState>) -> Self {
        Self {
            socket,
            addr,
            state,
        }
    }

    pub async fn handle(self) -> Result<()> {
        let ClientHandler {
            socket,
            addr,
            state,
        } = self;

        let (tx, mut rx) = mpsc::unbounded_channel();
        let client_with_channel = Client::new(tx);

        let mut framed = Framed::new(socket, IrcCodec::new());

        // Send welcome
        Self::send_welcome_msg(&mut framed, &state.name).await?;

        // Timeout checker interval
        let mut timeout_interval = tokio::time::interval(Duration::from_secs(1));

        loop {
            tokio::select! {
                // Handle incoming messages from client
                result = framed.next() => {
                    match result {
                        Some(Ok(message)) => {
                            debug!("Received: {:?}", message);
                            if let Err(e) =
                                Self::handle_message(&mut framed, message, &client_with_channel, &state).await
                            {
                                warn!("Error handling message: {}", e);
                            }
                        }
                        Some(Err(e)) => {
                            warn!("Error decoding message: {}", e);
                            break;
                        }
                        None => break,
                    }
                }
                // Handle outgoing messages to client
                Some(msg) = rx.recv() => {
                    let nick = client_with_channel.nick.read().await.clone().unwrap_or_else(|| "<unknown>".to_string());
                    info!("→ [{}] Received message from mpsc channel, delivering to client: {:?}", nick, msg);
                    if let Err(e) = framed.send(msg).await {
                        warn!("✗ [{}] Error sending message to client: {}", nick, e);
                        break;
                    }
                    info!("✓ [{}] Message successfully sent to client", nick);
                }
                // Check for message timeouts and retry
                _ = timeout_interval.tick() => {
                    let expired = client_with_channel.delivery_tracker.check_timeouts().await;
                    for pending in expired {
                        info!("Retrying message {} to {} (attempt {})",
                              pending.message_id, pending.target, pending.retry_count);

                        // Resend MSGID
                        let msgid_cmd = Message::new(Command::Raw {
                            command: "MSGID".to_string(),
                            params: vec![pending.message_id.clone()],
                        });
                        if let Err(e) = framed.send(msgid_cmd).await {
                            warn!("Failed to resend MSGID: {}", e);
                            continue;
                        }

                        // Resend message
                        if let Err(e) = framed.send(pending.message).await {
                            warn!("Failed to resend message: {}", e);
                        }
                    }
                }
            }
        }

        // Cleanup: remove client from state
        if let Some(nick) = client_with_channel.nick.read().await.clone() {
            state.clients.write().await.remove(&nick);
        }

        info!("Client {} disconnected", addr);
        Ok(())
    }

    async fn send_welcome_msg(
        framed: &mut Framed<TcpStream, IrcCodec>,
        server_name: &str,
    ) -> Result<()> {
        let welcome = Message::with_prefix(
            Prefix::Server(server_name.to_string()),
            Command::Notice {
                target: "*".to_string(),
                text: "Welcome to SIRC - Secure IRC Server".to_string(),
            },
        );
        framed.send(welcome).await?;
        Ok(())
    }

    async fn handle_message(
        framed: &mut Framed<TcpStream, IrcCodec>,
        message: Message,
        client: &Arc<Client>,
        state: &Arc<ServerState>,
    ) -> Result<()> {
        match message.command {
            Command::Nick(nick) => {
                Self::handle_nick(framed, nick, client, state).await?;
            }
            Command::User { username, realname } => {
                Self::handle_user(framed, username, realname, client, state).await?;
            }
            Command::Ping(server) => {
                let pong = Message::new(Command::Pong(server));
                framed.send(pong).await?;
            }
            Command::Join(channels) => {
                Self::handle_join(framed, channels, client, state).await?;
            }
            Command::Part { channels, message } => {
                Self::handle_part(framed, channels, message, client, state).await?;
            }
            Command::Topic { channel, topic } => {
                Self::handle_topic(framed, channel, topic, client, state).await?;
            }
            Command::Kick { channel, user, comment } => {
                Self::handle_kick(framed, channel, user, comment, client, state).await?;
            }
            Command::Names(channels) => {
                Self::handle_names(framed, channels, client, state).await?;
            }
            Command::PrivMsg { target, text } => {
                Self::handle_privmsg(framed, target, text, client, state).await?;
            }
            Command::Quit(msg) => {
                info!("Client quit: {:?}", msg);
                return Err(anyhow::anyhow!("Client quit"));
            }
            Command::EKey(pubkey_hex) => {
                Self::handle_key_exchange(framed, pubkey_hex, client).await?;
            }
            Command::EMsg {
                target,
                encrypted_data,
            } => {
                Self::handle_encrypted_msg(framed, target, encrypted_data, client, state).await?;
            }
            Command::Ack { message_id } => {
                Self::handle_ack(message_id, client).await?;
            }
            Command::Raw { command, params: _ } if command == "STATS" => {
                Self::handle_stats(framed, client, state).await?;
            }
            Command::Raw { command, params } if command == "MSGID" => {
                // Automatically send ACK for received message ID
                if let Some(msg_id) = params.first() {
                    let ack = Message::new(Command::Ack {
                        message_id: msg_id.clone(),
                    });
                    framed.send(ack).await?;
                    debug!("Sent ACK for message {}", msg_id);
                }
            }
            _ => {
                debug!("Unhandled command: {:?}", message.command);
            }
        }
        Ok(())
    }

    async fn handle_nick(
        framed: &mut Framed<TcpStream, IrcCodec>,
        nick: String,
        client: &Arc<Client>,
        state: &Arc<ServerState>,
    ) -> Result<()> {
        *client.nick.write().await = Some(nick.clone());

        // Add client to state
        state.clients.write().await.insert(nick.clone(), Arc::clone(client));
        info!("Registered client '{}' in state.clients", nick);

        let response = Message::with_prefix(
            Prefix::Server(state.name.clone()),
            Command::Notice {
                target: nick.clone(),
                text: format!("Nick set to {}", nick),
            },
        );
        framed.send(response).await?;

        // Send RPL_WELCOME if user is also set
        if client.username.read().await.is_some() {
            Self::send_registration_complete(framed, client, state).await?;
        }

        Ok(())
    }

    async fn handle_user(
        framed: &mut Framed<TcpStream, IrcCodec>,
        username: String,
        realname: String,
        client: &Arc<Client>,
        state: &Arc<ServerState>,
    ) -> Result<()> {
        *client.username.write().await = Some(username);
        *client.realname.write().await = Some(realname);

        // Send RPL_WELCOME if nick is also set
        if client.nick.read().await.is_some() {
            Self::send_registration_complete(framed, client, state).await?;
        }

        Ok(())
    }

    async fn send_registration_complete(
        framed: &mut Framed<TcpStream, IrcCodec>,
        client: &Arc<Client>,
        state: &Arc<ServerState>,
    ) -> Result<()> {
        let nick = client.nick.read().await.clone().unwrap_or_default();

        // RPL_WELCOME (001)
        let welcome = Message::with_prefix(
            Prefix::Server(state.name.clone()),
            Command::Numeric {
                code: 001,
                params: vec![nick.clone(), format!("Welcome to SIRC {}", nick)],
            },
        );
        framed.send(welcome).await?;

        Ok(())
    }

    async fn handle_join(
        framed: &mut Framed<TcpStream, IrcCodec>,
        channels: Vec<String>,
        client: &Arc<Client>,
        state: &Arc<ServerState>,
    ) -> Result<()> {
        let nick = client.nick.read().await.clone().unwrap_or_default();

        for channel_name in channels {
            info!("Client '{}' joining channel '{}'", nick, channel_name);

            // Create channel if it doesn't exist
            let mut channels = state.channels.write().await;
            let channel = channels
                .entry(channel_name.clone())
                .or_insert_with(|| crate::channel::Channel::new(channel_name.clone()));

            // Add user to channel
            channel.add_member(nick.clone());

            info!("Channel '{}' now has {} members: {:?}",
                  channel.name(), channel.members.len(), channel.members);
            drop(channels);

            // Notify federation if enabled
            if let Some(ref federation) = state.federation {
                if let Err(e) = federation
                    .join_channel(channel_name.clone(), nick.clone())
                    .await
                {
                    warn!("Failed to federate channel join: {}", e);
                }
            }

            // Send JOIN confirmation
            let join_msg = Message::with_prefix(
                Prefix::User {
                    nick: nick.clone(),
                    user: client.username.read().await.clone(),
                    host: Some("localhost".to_string()),
                },
                Command::Join(vec![channel_name.clone()]),
            );
            framed.send(join_msg).await?;

            // Send topic (none for now)
            let topic_msg = Message::with_prefix(
                Prefix::Server(state.name.clone()),
                Command::Numeric {
                    code: 331, // RPL_NOTOPIC
                    params: vec![nick.clone(), channel_name.clone(), "No topic set".to_string()],
                },
            );
            framed.send(topic_msg).await?;
        }

        Ok(())
    }

    async fn handle_part(
        framed: &mut Framed<TcpStream, IrcCodec>,
        channels: Vec<String>,
        message: Option<String>,
        client: &Arc<Client>,
        state: &Arc<ServerState>,
    ) -> Result<()> {
        let nick = client.nick.read().await.clone().unwrap_or_default();
        let prefix = Prefix::User {
            nick: nick.clone(),
            user: client.username.read().await.clone(),
            host: Some("localhost".to_string()),
        };

        for channel_name in channels {
            let mut chans = state.channels.write().await;
            let channel = match chans.get_mut(&channel_name) {
                Some(c) => c,
                None => {
                    drop(chans);
                    let err = Message::with_prefix(
                        Prefix::Server(state.name.clone()),
                        Command::Numeric {
                            code: 403, // ERR_NOSUCHCHANNEL
                            params: vec![nick.clone(), channel_name.clone(), "No such channel".to_string()],
                        },
                    );
                    framed.send(err).await?;
                    continue;
                }
            };
            if !channel.has_member(&nick) {
                drop(chans);
                let err = Message::with_prefix(
                    Prefix::Server(state.name.clone()),
                    Command::Numeric {
                        code: 442, // ERR_NOTONCHANNEL
                        params: vec![nick.clone(), channel_name.clone(), "You're not on that channel".to_string()],
                    },
                );
                framed.send(err).await?;
                continue;
            }
            channel.remove_member(&nick);
            let members: Vec<String> = channel.members.iter().cloned().collect();
            let channel_empty = members.is_empty();
            if channel_empty {
                chans.remove(&channel_name);
            }
            drop(chans);

            // Echo PART to every remaining member, including the parting user.
            let part_msg = Message::with_prefix(
                prefix.clone(),
                Command::Part {
                    channels: vec![channel_name.clone()],
                    message: message.clone(),
                },
            );
            framed.send(part_msg.clone()).await?;
            let clients = state.clients.read().await;
            for member_nick in &members {
                if let Some(c) = clients.get(member_nick) {
                    let _ = c.tx.send(part_msg.clone());
                }
            }

            info!("Client '{}' parted channel '{}'", nick, channel_name);
        }
        Ok(())
    }

    async fn handle_topic(
        framed: &mut Framed<TcpStream, IrcCodec>,
        channel: String,
        topic: Option<String>,
        client: &Arc<Client>,
        state: &Arc<ServerState>,
    ) -> Result<()> {
        let nick = client.nick.read().await.clone().unwrap_or_default();
        let mut chans = state.channels.write().await;
        let chan = match chans.get_mut(&channel) {
            Some(c) => c,
            None => {
                drop(chans);
                let err = Message::with_prefix(
                    Prefix::Server(state.name.clone()),
                    Command::Numeric {
                        code: 403,
                        params: vec![nick, channel, "No such channel".to_string()],
                    },
                );
                framed.send(err).await?;
                return Ok(());
            }
        };
        if !chan.has_member(&nick) {
            drop(chans);
            let err = Message::with_prefix(
                Prefix::Server(state.name.clone()),
                Command::Numeric {
                    code: 442,
                    params: vec![nick, channel, "You're not on that channel".to_string()],
                },
            );
            framed.send(err).await?;
            return Ok(());
        }

        match topic {
            // Read-back: return current topic.
            None => {
                let resp = match &chan.topic {
                    Some(t) => Message::with_prefix(
                        Prefix::Server(state.name.clone()),
                        Command::Numeric {
                            code: 332, // RPL_TOPIC
                            params: vec![nick.clone(), channel.clone(), t.clone()],
                        },
                    ),
                    None => Message::with_prefix(
                        Prefix::Server(state.name.clone()),
                        Command::Numeric {
                            code: 331, // RPL_NOTOPIC
                            params: vec![nick.clone(), channel.clone(), "No topic is set".to_string()],
                        },
                    ),
                };
                drop(chans);
                framed.send(resp).await?;
            }
            Some(new_topic) => {
                let new = if new_topic.is_empty() { None } else { Some(new_topic) };
                chan.set_topic(new.clone());
                let members: Vec<String> = chan.members.iter().cloned().collect();
                drop(chans);

                let topic_msg = Message::with_prefix(
                    Prefix::User {
                        nick: nick.clone(),
                        user: client.username.read().await.clone(),
                        host: Some("localhost".to_string()),
                    },
                    Command::Topic { channel: channel.clone(), topic: new },
                );
                framed.send(topic_msg.clone()).await?;
                let clients = state.clients.read().await;
                for m in &members {
                    if m == &nick { continue; }
                    if let Some(c) = clients.get(m) {
                        let _ = c.tx.send(topic_msg.clone());
                    }
                }
                info!("Client '{}' set topic for '{}'", nick, channel);
            }
        }
        Ok(())
    }

    async fn handle_kick(
        framed: &mut Framed<TcpStream, IrcCodec>,
        channel: String,
        user: String,
        comment: Option<String>,
        client: &Arc<Client>,
        state: &Arc<ServerState>,
    ) -> Result<()> {
        let nick = client.nick.read().await.clone().unwrap_or_default();
        let mut chans = state.channels.write().await;
        let chan = match chans.get_mut(&channel) {
            Some(c) => c,
            None => {
                drop(chans);
                let err = Message::with_prefix(
                    Prefix::Server(state.name.clone()),
                    Command::Numeric {
                        code: 403,
                        params: vec![nick, channel, "No such channel".to_string()],
                    },
                );
                framed.send(err).await?;
                return Ok(());
            }
        };
        if !chan.has_member(&nick) {
            drop(chans);
            let err = Message::with_prefix(
                Prefix::Server(state.name.clone()),
                Command::Numeric {
                    code: 442,
                    params: vec![nick, channel, "You're not on that channel".to_string()],
                },
            );
            framed.send(err).await?;
            return Ok(());
        }
        if !chan.has_member(&user) {
            drop(chans);
            let err = Message::with_prefix(
                Prefix::Server(state.name.clone()),
                Command::Numeric {
                    code: 441, // ERR_USERNOTINCHANNEL
                    params: vec![nick, user, channel, "They aren't on that channel".to_string()],
                },
            );
            framed.send(err).await?;
            return Ok(());
        }
        chan.remove_member(&user);
        let members: Vec<String> = chan.members.iter().cloned().collect();
        let channel_empty = members.is_empty();
        if channel_empty {
            chans.remove(&channel);
        }
        drop(chans);

        let kick_msg = Message::with_prefix(
            Prefix::User {
                nick: nick.clone(),
                user: client.username.read().await.clone(),
                host: Some("localhost".to_string()),
            },
            Command::Kick { channel: channel.clone(), user: user.clone(), comment: comment.clone() },
        );
        framed.send(kick_msg.clone()).await?;
        let clients = state.clients.read().await;
        for m in &members {
            if let Some(c) = clients.get(m) {
                let _ = c.tx.send(kick_msg.clone());
            }
        }
        // Inform the kicked user too.
        if let Some(c) = clients.get(&user) {
            let _ = c.tx.send(kick_msg.clone());
        }
        info!("Client '{}' kicked '{}' from '{}'", nick, user, channel);
        Ok(())
    }

    async fn handle_names(
        framed: &mut Framed<TcpStream, IrcCodec>,
        channels: Vec<String>,
        client: &Arc<Client>,
        state: &Arc<ServerState>,
    ) -> Result<()> {
        let nick = client.nick.read().await.clone().unwrap_or_default();
        let chans = state.channels.read().await;

        // If no channels specified, list all known channels.
        let names_to_query: Vec<String> = if channels.is_empty() {
            chans.keys().cloned().collect()
        } else {
            channels
        };

        for channel_name in names_to_query {
            if let Some(chan) = chans.get(&channel_name) {
                let members: Vec<String> = chan.members.iter().cloned().collect();
                let names_line = members.join(" ");
                let reply = Message::with_prefix(
                    Prefix::Server(state.name.clone()),
                    Command::Numeric {
                        code: 353, // RPL_NAMREPLY
                        params: vec![nick.clone(), "=".to_string(), channel_name.clone(), names_line],
                    },
                );
                framed.send(reply).await?;
            }
            let end = Message::with_prefix(
                Prefix::Server(state.name.clone()),
                Command::Numeric {
                    code: 366, // RPL_ENDOFNAMES
                    params: vec![nick.clone(), channel_name, "End of /NAMES list".to_string()],
                },
            );
            framed.send(end).await?;
        }
        Ok(())
    }

    async fn handle_stats(
        framed: &mut Framed<TcpStream, IrcCodec>,
        client: &Arc<Client>,
        state: &Arc<ServerState>,
    ) -> Result<()> {
        let nick = client.nick.read().await.clone().unwrap_or_default();
        let server_name = state.name.clone();

        // Collect all lines first, then send — sidesteps borrow-checker issues
        // with mixing &mut framed and async state reads in the same expression.
        let mut lines: Vec<String> = Vec::new();

        let local_clients = state.clients.read().await.len();
        let local_channels = state.channels.read().await.len();
        lines.push(format!(
            "server {} clients={} channels={}",
            server_name, local_clients, local_channels
        ));

        let pending = client.delivery_tracker.pending_count().await;
        lines.push(format!("self pending_acks={}", pending));

        if let Some(ref federation) = state.federation {
            let (direct, all) = federation.route_summary().await;
            lines.push(format!(
                "federation direct={} known_servers={}",
                direct.len(),
                all.len()
            ));
            for peer in &direct {
                if let Some((addr, hop, info)) = federation.peer_info(peer).await {
                    lines.push(format!(
                        "peer {} addr={} hop={} info={:?}",
                        peer, addr, hop, info
                    ));
                }
            }
            // Network partitions and live performance metrics.
            let partitions = federation.get_partition_status().await;
            lines.push(format!("partitions active={}", partitions.len()));
            for p in &partitions {
                lines.push(format!(
                    "partition {} unreachable={} detected_at_age_secs={}",
                    p.id,
                    p.unreachable_servers.len(),
                    p.detected_at.elapsed().as_secs()
                ));
            }
            let snap = federation.metrics().snapshot().await;
            lines.push(format!(
                "metrics msgs_sent={} msgs_recv={} msgs_routed={} encrypted={} active_conn={} tls_ok={} tls_fail={} reconn_ok={}",
                snap.messages_sent,
                snap.messages_received,
                snap.messages_routed,
                snap.encrypted_messages,
                snap.active_connections,
                snap.tls_handshakes_success,
                snap.tls_handshakes_failed,
                snap.reconnections_successful,
            ));
            lines.push(format!(
                "latency_ms avg={:.2} min={:.2} max={:.2}",
                snap.avg_latency_ms, snap.min_latency_ms, snap.max_latency_ms
            ));
        }

        // 211 RPL_STATSLINKINFO + 219 RPL_ENDOFSTATS — IRC convention.
        for line in lines {
            let msg = Message::with_prefix(
                Prefix::Server(server_name.clone()),
                Command::Numeric {
                    code: 211,
                    params: vec![nick.clone(), "L".to_string(), line],
                },
            );
            framed.send(msg).await?;
        }
        let end = Message::with_prefix(
            Prefix::Server(server_name),
            Command::Numeric {
                code: 219,
                params: vec![nick, "L".to_string(), "End of /STATS report".to_string()],
            },
        );
        framed.send(end).await?;
        Ok(())
    }

    async fn handle_privmsg(
        framed: &mut Framed<TcpStream, IrcCodec>,
        target: String,
        text: String,
        client: &Arc<Client>,
        state: &Arc<ServerState>,
    ) -> Result<()> {
        let nick = client.nick.read().await.clone().unwrap_or_default();

        info!("PRIVMSG from {} to {}: {}", nick, target, text);

        // Generate message ID for delivery confirmation
        let message_id = client.delivery_tracker.generate_id().await;

        // Send MSGID header to all recipients
        let msgid_cmd = Message::new(Command::Raw {
            command: "MSGID".to_string(),
            params: vec![message_id.clone()],
        });

        // Build the message to broadcast
        let msg = Message::with_prefix(
            Prefix::User {
                nick: nick.clone(),
                user: client.username.read().await.clone(),
                host: Some("localhost".to_string()),
            },
            Command::PrivMsg {
                target: target.clone(),
                text: text.clone(),
            },
        );

        // Check if target is a channel
        if target.starts_with('#') {
            info!("Sending message to channel '{}'", target);

            // Send to all members of the channel
            let channels = state.channels.read().await;
            if let Some(channel) = channels.get(&target) {
                // Sender must be a member (no external messages).
                if !channel.has_member(&nick) {
                    drop(channels);
                    let err = Message::with_prefix(
                        Prefix::Server(state.name.clone()),
                        Command::Numeric {
                            code: 404, // ERR_CANNOTSENDTOCHAN
                            params: vec![nick.clone(), target.clone(), "Cannot send to channel (not a member)".to_string()],
                        },
                    );
                    framed.send(err).await?;
                    return Ok(());
                }
                let members = channel.members.clone();
                let has_recipients = !members.is_empty();

                info!("Channel '{}' has {} members: {:?}", target, members.len(), members);
                drop(channels);

                let clients = state.clients.read().await;
                info!("Total clients registered in server: {}", clients.len());
                info!("Registered client nicks: {:?}", clients.keys().collect::<Vec<_>>());

                for member_nick in members {
                    // Don't send to the sender
                    if member_nick == nick {
                        continue;
                    }

                    info!("Looking for client '{}' in registry", member_nick);
                    if let Some(member_client) = clients.get(&member_nick) {
                        info!("Found client '{}' in registry, sending MSGID and message", member_nick);

                        // Send MSGID first
                        info!("Attempting to send MSGID {} to {}", msgid_cmd.to_string(), member_nick);
                        match member_client.tx.send(msgid_cmd.clone()) {
                            Ok(_) => info!("MSGID sent successfully to {}", member_nick),
                            Err(e) => {
                                warn!("Failed to send MSGID to {}: {}", member_nick, e);
                                continue;
                            }
                        }

                        // Then send the actual message
                        info!("Attempting to send message to {}: {:?}", member_nick, msg);
                        match member_client.tx.send(msg.clone()) {
                            Ok(_) => info!("✓ Message successfully queued for delivery to {}", member_nick),
                            Err(e) => warn!("✗ Failed to send to {}: {}", member_nick, e),
                        }
                    } else {
                        warn!("Client '{}' not found in registry!", member_nick);
                    }
                }

                // Track message for confirmation (from first recipient)
                if has_recipients {
                    client.delivery_tracker.track_message(
                        message_id,
                        msg.clone(),
                        target.clone()
                    ).await;
                }
            } else {
                // Channel doesn't exist
                let error = Message::with_prefix(
                    Prefix::Server(state.name.clone()),
                    Command::Numeric {
                        code: 403, // ERR_NOSUCHCHANNEL
                        params: vec![nick, target, "No such channel".to_string()],
                    },
                );
                framed.send(error).await?;
            }
        } else {
            // Send to specific user
            let clients = state.clients.read().await;
            if let Some(target_client) = clients.get(&target) {
                // Send MSGID first
                if let Err(e) = target_client.tx.send(msgid_cmd) {
                    warn!("Failed to send MSGID to {}: {}", target, e);
                } else {
                    // Then send the actual message
                    if let Err(e) = target_client.tx.send(msg.clone()) {
                        warn!("Failed to send to {}: {}", target, e);
                    } else {
                        // Track message for confirmation
                        client.delivery_tracker.track_message(
                            message_id,
                            msg,
                            target.clone()
                        ).await;
                    }
                }
            } else {
                // Local user not found — try federation routing.
                let mut routed = false;
                if let Some(ref federation) = state.federation {
                    match federation.send_message(&nick, &target, text.clone()).await {
                        Ok(true) => {
                            info!("PRIVMSG {}→{} routed via federation", nick, target);
                            routed = true;
                        }
                        Ok(false) => { /* not on any known server */ }
                        Err(e) => warn!("Federation routing failed for {}: {}", target, e),
                    }
                }
                if !routed {
                    let error = Message::with_prefix(
                        Prefix::Server(state.name.clone()),
                        Command::Numeric {
                            code: 401, // ERR_NOSUCHNICK
                            params: vec![nick, target, "No such nick".to_string()],
                        },
                    );
                    framed.send(error).await?;
                }
            }
        }

        Ok(())
    }

    async fn handle_key_exchange(
        framed: &mut Framed<TcpStream, IrcCodec>,
        pubkey_hex: String,
        client: &Arc<Client>,
    ) -> Result<()> {
        info!("Key exchange initiated");

        // Parse remote public key
        let pubkey_bytes = hex::decode(&pubkey_hex)?;
        if pubkey_bytes.len() != 32 {
            return Err(anyhow::anyhow!("Invalid public key length"));
        }

        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&pubkey_bytes);
        let remote_key = x25519_dalek::PublicKey::from(key_array);

        // Set remote key in session
        let mut session = client.session.write().await;
        session.set_remote_key(remote_key);

        // Send our public key back
        let our_pubkey = hex::encode(session.public_key().as_bytes());
        let response = Message::new(Command::EKey(our_pubkey));
        framed.send(response).await?;

        info!("Encryption session established");
        Ok(())
    }

    async fn handle_encrypted_msg(
        _framed: &mut Framed<TcpStream, IrcCodec>,
        target: String,
        encrypted_data: String,
        client: &Arc<Client>,
        state: &Arc<ServerState>,
    ) -> Result<()> {
        let nick = client.nick.read().await.clone().unwrap_or_default();

        info!("Routing encrypted message from {} to {}", nick, target);
        if let Some(ref federation) = state.federation {
            federation.metrics().increment_encrypted_messages();
        }

        // For true E2E encryption, server should NOT decrypt
        // Simply route the encrypted message to the target client
        let msg = Message::with_prefix(
            Prefix::User {
                nick: nick.clone(),
                user: client.username.read().await.clone(),
                host: Some("localhost".to_string()),
            },
            Command::EMsg {
                target: target.clone(),
                encrypted_data,
            },
        );

        // Route to target client
        let clients = state.clients.read().await;
        if let Some(target_client) = clients.get(&target) {
            if let Err(e) = target_client.tx.send(msg) {
                warn!("Failed to route encrypted message to {}: {}", target, e);
            } else {
                debug!("Routed encrypted message from {} to {}", nick, target);
            }
        } else {
            // Target not found
            warn!("Encrypted message target {} not found", target);
        }

        Ok(())
    }

    async fn handle_ack(
        message_id: String,
        client: &Arc<Client>,
    ) -> Result<()> {
        if client.delivery_tracker.confirm(&message_id).await {
            debug!("Message {} acknowledged", message_id);
        } else {
            warn!("Received ACK for unknown message: {}", message_id);
        }
        Ok(())
    }
}
