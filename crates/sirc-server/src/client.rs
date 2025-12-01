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
                    if let Err(e) = framed.send(msg).await {
                        warn!("Error sending message: {}", e);
                        break;
                    }
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
            // Create channel if it doesn't exist
            let mut channels = state.channels.write().await;
            let channel = channels
                .entry(channel_name.clone())
                .or_insert_with(|| crate::channel::Channel::new(channel_name.clone()));

            // Add user to channel
            channel.add_member(nick.clone());
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
            // Send to all members of the channel
            let channels = state.channels.read().await;
            if let Some(channel) = channels.get(&target) {
                let members = channel.members.clone();
                let has_recipients = !members.is_empty();
                drop(channels);

                let clients = state.clients.read().await;
                for member_nick in members {
                    // Don't send to the sender
                    if member_nick == nick {
                        continue;
                    }

                    if let Some(member_client) = clients.get(&member_nick) {
                        // Send MSGID first
                        if let Err(e) = member_client.tx.send(msgid_cmd.clone()) {
                            warn!("Failed to send MSGID to {}: {}", member_nick, e);
                            continue;
                        }
                        // Then send the actual message
                        if let Err(e) = member_client.tx.send(msg.clone()) {
                            warn!("Failed to send to {}: {}", member_nick, e);
                        }
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
                // User not found
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
