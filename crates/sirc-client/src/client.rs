//! Client connection and message handling

use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    ExecutableCommand,
};
use futures::{SinkExt, StreamExt};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Terminal,
};
use sirc_crypto::EncryptedSession;
use sirc_protocol::{Command, IrcCodec, Message};
use std::io::stdout;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_util::codec::Framed;
use tracing::{error, info};

pub struct Client {
    server: String,
    nick: String,
    username: String,
    realname: String,
    encrypt: bool,
    session: EncryptedSession,
}

impl Client {
    pub fn new(
        server: String,
        nick: String,
        username: String,
        realname: String,
        encrypt: bool,
    ) -> Self {
        Self {
            server,
            nick,
            username,
            realname,
            encrypt,
            session: EncryptedSession::new(),
        }
    }

    pub async fn run(&mut self) -> Result<()> {
        info!("Connecting to {}", self.server);

        let stream = TcpStream::connect(&self.server).await?;
        let mut framed = Framed::new(stream, IrcCodec::new());

        // Send registration
        framed.send(Message::new(Command::Nick(self.nick.clone()))).await?;
        framed
            .send(Message::new(Command::User {
                username: self.username.clone(),
                realname: self.realname.clone(),
            }))
            .await?;

        // If encryption enabled, initiate key exchange
        if self.encrypt {
            let pubkey = hex::encode(self.session.public_key().as_bytes());
            framed.send(Message::new(Command::EKey(pubkey))).await?;
            info!("Sent public key for encryption");
        }

        // Start TUI
        enable_raw_mode()?;
        stdout().execute(EnterAlternateScreen)?;
        let backend = CrosstermBackend::new(stdout());
        let mut terminal = Terminal::new(backend)?;

        let (tx, mut rx) = mpsc::channel::<String>(100);
        let mut messages: Vec<String> = Vec::new();
        let mut input = String::new();

        loop {
            // Draw UI
            terminal.draw(|f| {
                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([
                        Constraint::Min(1),
                        Constraint::Length(3),
                    ])
                    .split(f.area());

                // Messages area
                let items: Vec<ListItem> = messages
                    .iter()
                    .map(|m| {
                        ListItem::new(Line::from(Span::raw(m)))
                    })
                    .collect();

                let messages_list = List::new(items)
                    .block(Block::default().borders(Borders::ALL).title("Messages"));
                f.render_widget(messages_list, chunks[0]);

                // Input area
                let input_widget = Paragraph::new(input.as_str())
                    .style(Style::default().fg(Color::Yellow))
                    .block(Block::default().borders(Borders::ALL).title("Input"));
                f.render_widget(input_widget, chunks[1]);
            })?;

            // Handle events
            if event::poll(std::time::Duration::from_millis(100))? {
                if let Event::Key(key) = event::read()? {
                    if key.kind == KeyEventKind::Press {
                        match key.code {
                            KeyCode::Char('c') if key.modifiers.contains(event::KeyModifiers::CONTROL) => {
                                break;
                            }
                            KeyCode::Char(c) => {
                                input.push(c);
                            }
                            KeyCode::Backspace => {
                                input.pop();
                            }
                            KeyCode::Enter => {
                                if !input.is_empty() {
                                    let msg = input.clone();
                                    input.clear();
                                    tx.send(msg).await?;
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }

            // Check for messages to send
            if let Ok(msg) = rx.try_recv() {
                self.handle_input(&mut framed, &msg, &mut messages).await?;
            }

            // Check for incoming messages
            if let Ok(Some(result)) = tokio::time::timeout(
                std::time::Duration::from_millis(10),
                framed.next(),
            )
            .await
            {
                match result {
                    Ok(message) => {
                        self.handle_message(&message, &mut messages).await?;
                    }
                    Err(e) => {
                        error!("Error receiving message: {}", e);
                        break;
                    }
                }
            }
        }

        // Cleanup
        disable_raw_mode()?;
        stdout().execute(LeaveAlternateScreen)?;

        Ok(())
    }

    async fn handle_input(
        &mut self,
        framed: &mut Framed<TcpStream, IrcCodec>,
        input: &str,
        messages: &mut Vec<String>,
    ) -> Result<()> {
        if input.starts_with('/') {
            // Command
            let parts: Vec<&str> = input[1..].split_whitespace().collect();
            match parts.get(0) {
                Some(&"join") => {
                    if let Some(channel) = parts.get(1) {
                        framed.send(Message::new(Command::Join(vec![channel.to_string()]))).await?;
                        messages.push(format!("→ Joining {}", channel));
                    }
                }
                Some(&"quit") => {
                    framed.send(Message::new(Command::Quit(Some("Goodbye".to_string())))).await?;
                    messages.push("→ Disconnecting...".to_string());
                }
                Some(&"msg") => {
                    if parts.len() >= 3 {
                        let target = parts[1];
                        let text = parts[2..].join(" ");

                        if self.encrypt && self.session.is_ready() {
                            // Send encrypted
                            let encrypted = self.session.encrypt(text.as_bytes())?;
                            let encoded = encrypted.to_base64()?;
                            framed
                                .send(Message::new(Command::EMsg {
                                    target: target.to_string(),
                                    encrypted_data: encoded,
                                }))
                                .await?;
                            messages.push(format!("→ [ENCRYPTED] to {}: {}", target, text));
                        } else {
                            // Send plaintext
                            framed
                                .send(Message::new(Command::PrivMsg {
                                    target: target.to_string(),
                                    text: text.clone(),
                                }))
                                .await?;
                            messages.push(format!("→ to {}: {}", target, text));
                        }
                    }
                }
                _ => {
                    messages.push(format!("→ Unknown command: {}", input));
                }
            }
        } else {
            messages.push(format!("→ {}", input));
        }

        Ok(())
    }

    async fn handle_message(
        &mut self,
        message: &Message,
        messages: &mut Vec<String>,
    ) -> Result<()> {
        match &message.command {
            Command::Notice { target: _, text } => {
                messages.push(format!("*** {}", text));
            }
            Command::PrivMsg { target: _, text } => {
                if let Some(ref prefix) = message.prefix {
                    messages.push(format!("<{}> {}", prefix, text));
                } else {
                    messages.push(format!("< {}", text));
                }
            }
            Command::Ping(server) => {
                // Auto-respond to PING
                messages.push(format!("← PING {}", server));
            }
            Command::EKey(pubkey_hex) => {
                // Received remote public key
                let pubkey_bytes = hex::decode(pubkey_hex)?;
                if pubkey_bytes.len() == 32 {
                    let mut key_array = [0u8; 32];
                    key_array.copy_from_slice(&pubkey_bytes);
                    let remote_key = x25519_dalek::PublicKey::from(key_array);
                    self.session.set_remote_key(remote_key);
                    messages.push("*** Encryption enabled".to_string());
                }
            }
            Command::EMsg {
                target: _,
                encrypted_data,
            } => {
                if self.session.is_ready() {
                    let encrypted_msg = sirc_crypto::EncryptedMessage::from_base64(encrypted_data)?;
                    let plaintext = self.session.decrypt(&encrypted_msg)?;
                    let text = String::from_utf8(plaintext)?;
                    messages.push(format!("[ENCRYPTED] {}", text));
                } else {
                    messages.push("*** Received encrypted message but session not ready".to_string());
                }
            }
            Command::Numeric { code, params } => {
                messages.push(format!("[{}] {}", code, params.join(" ")));
            }
            _ => {
                messages.push(format!("← {:?}", message.command));
            }
        }

        // Limit messages
        if messages.len() > 1000 {
            messages.drain(0..100);
        }

        Ok(())
    }
}
