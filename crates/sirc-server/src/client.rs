//! Client connection handling

use crate::server::ServerState;
use anyhow::Result;
use futures::{SinkExt, StreamExt};
use sirc_crypto::{EncryptedSession, EncryptedMessage};
use sirc_protocol::{Command, IrcCodec, Message, Prefix};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use tokio_util::codec::Framed;
use tracing::{debug, info, warn};

pub struct Client {
    pub nick: RwLock<Option<String>>,
    pub username: RwLock<Option<String>>,
    pub realname: RwLock<Option<String>>,
    pub session: RwLock<EncryptedSession>,
}

impl Client {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            nick: RwLock::new(None),
            username: RwLock::new(None),
            realname: RwLock::new(None),
            session: RwLock::new(EncryptedSession::new()),
        })
    }
}

pub struct ClientHandler {
    socket: TcpStream,
    addr: SocketAddr,
    state: Arc<ServerState>,
    client: Arc<Client>,
}

impl ClientHandler {
    pub fn new(socket: TcpStream, addr: SocketAddr, state: Arc<ServerState>) -> Self {
        Self {
            socket,
            addr,
            state,
            client: Client::new(),
        }
    }

    pub async fn handle(self) -> Result<()> {
        let ClientHandler {
            socket,
            addr,
            state,
            client,
        } = self;

        let mut framed = Framed::new(socket, IrcCodec::new());

        // Send welcome
        Self::send_welcome_msg(&mut framed, &state.name).await?;

        while let Some(result) = framed.next().await {
            match result {
                Ok(message) => {
                    debug!("Received: {:?}", message);
                    if let Err(e) =
                        Self::handle_message(&mut framed, message, &client, &state).await
                    {
                        warn!("Error handling message: {}", e);
                    }
                }
                Err(e) => {
                    warn!("Error decoding message: {}", e);
                    break;
                }
            }
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
                Self::handle_encrypted_msg(framed, target, encrypted_data, client).await?;
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

        // Echo back for now (TODO: route to actual target)
        let response = Message::with_prefix(
            Prefix::Server(state.name.clone()),
            Command::Notice {
                target: nick,
                text: format!("Message to {} delivered (echo)", target),
            },
        );
        framed.send(response).await?;

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
        framed: &mut Framed<TcpStream, IrcCodec>,
        target: String,
        encrypted_data: String,
        client: &Arc<Client>,
    ) -> Result<()> {
        let session = client.session.read().await;

        if !session.is_ready() {
            warn!("Encryption session not ready");
            return Ok(());
        }

        // Decrypt message
        let encrypted_msg = EncryptedMessage::from_base64(&encrypted_data)?;
        let plaintext = session.decrypt(&encrypted_msg)?;
        let text = String::from_utf8(plaintext)?;

        info!("Decrypted message to {}: {}", target, text);

        // Echo back encrypted (TODO: route to actual target)
        let nick = client.nick.read().await.clone().unwrap_or_default();
        let response_text = format!("Encrypted message received: {}", text);
        let encrypted_response = session.encrypt(response_text.as_bytes())?;
        let encoded = encrypted_response.to_base64()?;

        let response = Message::new(Command::EMsg {
            target: nick,
            encrypted_data: encoded,
        });
        framed.send(response).await?;

        Ok(())
    }
}
