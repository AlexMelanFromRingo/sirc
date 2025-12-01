//! IRC message types and parsing

use crate::{ProtocolError, Result};
use serde::{Deserialize, Serialize};
use std::fmt;

/// IRC message prefix (server or user)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Prefix {
    Server(String),
    User {
        nick: String,
        user: Option<String>,
        host: Option<String>,
    },
}

impl fmt::Display for Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Prefix::Server(s) => write!(f, "{}", s),
            Prefix::User { nick, user, host } => {
                write!(f, "{}", nick)?;
                if let Some(u) = user {
                    write!(f, "!{}", u)?;
                }
                if let Some(h) = host {
                    write!(f, "@{}", h)?;
                }
                Ok(())
            }
        }
    }
}

/// IRC commands (traditional + encrypted extensions)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Command {
    // Connection registration
    Nick(String),
    User {
        username: String,
        realname: String,
    },
    Pass(String),
    Quit(Option<String>),

    // Channel operations
    Join(Vec<String>),
    Part {
        channels: Vec<String>,
        message: Option<String>,
    },
    Topic {
        channel: String,
        topic: Option<String>,
    },
    Names(Vec<String>),
    List(Option<Vec<String>>),
    Kick {
        channel: String,
        user: String,
        comment: Option<String>,
    },

    // Messaging
    PrivMsg {
        target: String,
        text: String,
    },
    Notice {
        target: String,
        text: String,
    },

    // Server queries
    Motd,
    Version,
    Ping(String),
    Pong(String),

    // SIRC encrypted extensions
    /// Exchange public key
    EKey(String),
    /// Encrypted message
    EMsg {
        target: String,
        encrypted_data: String,
    },
    /// Message delivery acknowledgment
    Ack {
        message_id: String,
    },
    /// Server federation
    Server {
        name: String,
        hopcount: u32,
        info: String,
    },

    // Numeric replies
    Numeric {
        code: u16,
        params: Vec<String>,
    },

    // Unknown/Raw
    Raw {
        command: String,
        params: Vec<String>,
    },
}

/// Complete IRC message
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Message {
    pub prefix: Option<Prefix>,
    pub command: Command,
}

impl Message {
    /// Create a new message without prefix
    pub fn new(command: Command) -> Self {
        Self {
            prefix: None,
            command,
        }
    }

    /// Create a new message with prefix
    pub fn with_prefix(prefix: Prefix, command: Command) -> Self {
        Self {
            prefix: Some(prefix),
            command,
        }
    }

    /// Parse IRC message from string
    pub fn parse(line: &str) -> Result<Self> {
        let line = line.trim_end_matches("\r\n");
        let mut parts = line.split_whitespace().peekable();

        // Check for prefix
        let prefix = if line.starts_with(':') {
            let prefix_str = parts
                .next()
                .ok_or(ProtocolError::InvalidFormat)?
                .trim_start_matches(':');
            Some(Self::parse_prefix(prefix_str)?)
        } else {
            None
        };

        // Parse command
        let cmd_str = parts.next().ok_or(ProtocolError::InvalidFormat)?;
        let command = Self::parse_command(cmd_str, &mut parts)?;

        Ok(Self { prefix, command })
    }

    fn parse_prefix(s: &str) -> Result<Prefix> {
        if s.contains('!') || s.contains('@') {
            let mut nick = s.to_string();
            let mut user = None;
            let mut host = None;

            if let Some(idx) = s.find('!') {
                nick = s[..idx].to_string();
                let rest = &s[idx + 1..];
                if let Some(idx2) = rest.find('@') {
                    user = Some(rest[..idx2].to_string());
                    host = Some(rest[idx2 + 1..].to_string());
                } else {
                    user = Some(rest.to_string());
                }
            } else if let Some(idx) = s.find('@') {
                nick = s[..idx].to_string();
                host = Some(s[idx + 1..].to_string());
            }

            Ok(Prefix::User { nick, user, host })
        } else {
            Ok(Prefix::Server(s.to_string()))
        }
    }

    fn parse_command<'a>(
        cmd: &str,
        params: &mut impl Iterator<Item = &'a str>,
    ) -> Result<Command> {
        let cmd_upper = cmd.to_uppercase();

        match cmd_upper.as_str() {
            "NICK" => {
                let nick = params
                    .next()
                    .ok_or(ProtocolError::MissingParameter)?
                    .to_string();
                Ok(Command::Nick(nick))
            }
            "USER" => {
                let username = params
                    .next()
                    .ok_or(ProtocolError::MissingParameter)?
                    .to_string();
                let _mode = params.next();
                let _unused = params.next();
                let realname = params
                    .collect::<Vec<_>>()
                    .join(" ")
                    .trim_start_matches(':')
                    .to_string();
                Ok(Command::User { username, realname })
            }
            "PASS" => {
                let pass = params
                    .next()
                    .ok_or(ProtocolError::MissingParameter)?
                    .to_string();
                Ok(Command::Pass(pass))
            }
            "QUIT" => {
                let message = params
                    .collect::<Vec<_>>()
                    .join(" ")
                    .trim_start_matches(':')
                    .to_string();
                Ok(Command::Quit(if message.is_empty() {
                    None
                } else {
                    Some(message)
                }))
            }
            "JOIN" => {
                let channels = params
                    .next()
                    .ok_or(ProtocolError::MissingParameter)?
                    .split(',')
                    .map(String::from)
                    .collect();
                Ok(Command::Join(channels))
            }
            "PART" => {
                let channels = params
                    .next()
                    .ok_or(ProtocolError::MissingParameter)?
                    .split(',')
                    .map(String::from)
                    .collect();
                let message = params
                    .collect::<Vec<_>>()
                    .join(" ")
                    .trim_start_matches(':')
                    .to_string();
                Ok(Command::Part {
                    channels,
                    message: if message.is_empty() {
                        None
                    } else {
                        Some(message)
                    },
                })
            }
            "PRIVMSG" => {
                let target = params
                    .next()
                    .ok_or(ProtocolError::MissingParameter)?
                    .to_string();
                let text = params
                    .collect::<Vec<_>>()
                    .join(" ")
                    .trim_start_matches(':')
                    .to_string();
                Ok(Command::PrivMsg { target, text })
            }
            "NOTICE" => {
                let target = params
                    .next()
                    .ok_or(ProtocolError::MissingParameter)?
                    .to_string();
                let text = params
                    .collect::<Vec<_>>()
                    .join(" ")
                    .trim_start_matches(':')
                    .to_string();
                Ok(Command::Notice { target, text })
            }
            "PING" => {
                let server = params
                    .next()
                    .ok_or(ProtocolError::MissingParameter)?
                    .trim_start_matches(':')
                    .to_string();
                Ok(Command::Ping(server))
            }
            "PONG" => {
                let server = params
                    .next()
                    .ok_or(ProtocolError::MissingParameter)?
                    .trim_start_matches(':')
                    .to_string();
                Ok(Command::Pong(server))
            }
            // SIRC extensions
            "EKEY" => {
                let pubkey = params
                    .next()
                    .ok_or(ProtocolError::MissingParameter)?
                    .to_string();
                Ok(Command::EKey(pubkey))
            }
            "EMSG" => {
                let target = params
                    .next()
                    .ok_or(ProtocolError::MissingParameter)?
                    .to_string();
                let encrypted_data = params
                    .collect::<Vec<_>>()
                    .join(" ")
                    .trim_start_matches(':')
                    .to_string();
                Ok(Command::EMsg {
                    target,
                    encrypted_data,
                })
            }
            "ACK" => {
                let message_id = params
                    .next()
                    .ok_or(ProtocolError::MissingParameter)?
                    .to_string();
                Ok(Command::Ack { message_id })
            }
            "SERVER" => {
                let name = params
                    .next()
                    .ok_or(ProtocolError::MissingParameter)?
                    .to_string();
                let hopcount = params
                    .next()
                    .ok_or(ProtocolError::MissingParameter)?
                    .parse()
                    .map_err(|_| ProtocolError::InvalidFormat)?;
                let info = params
                    .collect::<Vec<_>>()
                    .join(" ")
                    .trim_start_matches(':')
                    .to_string();
                Ok(Command::Server {
                    name,
                    hopcount,
                    info,
                })
            }
            _ => {
                // Check if numeric
                if let Ok(code) = cmd.parse::<u16>() {
                    let params = params.map(String::from).collect();
                    Ok(Command::Numeric { code, params })
                } else {
                    let params = params.map(String::from).collect();
                    Ok(Command::Raw {
                        command: cmd.to_string(),
                        params,
                    })
                }
            }
        }
    }

    /// Serialize message to IRC protocol format
    pub fn to_string(&self) -> String {
        let mut result = String::new();

        if let Some(ref prefix) = self.prefix {
            result.push(':');
            result.push_str(&prefix.to_string());
            result.push(' ');
        }

        match &self.command {
            Command::Nick(nick) => {
                result.push_str("NICK ");
                result.push_str(nick);
            }
            Command::User { username, realname } => {
                result.push_str(&format!("USER {} 0 * :{}", username, realname));
            }
            Command::Pass(pass) => {
                result.push_str("PASS ");
                result.push_str(pass);
            }
            Command::Quit(msg) => {
                result.push_str("QUIT");
                if let Some(m) = msg {
                    result.push_str(" :");
                    result.push_str(m);
                }
            }
            Command::Join(channels) => {
                result.push_str("JOIN ");
                result.push_str(&channels.join(","));
            }
            Command::Part { channels, message } => {
                result.push_str("PART ");
                result.push_str(&channels.join(","));
                if let Some(m) = message {
                    result.push_str(" :");
                    result.push_str(m);
                }
            }
            Command::PrivMsg { target, text } => {
                result.push_str(&format!("PRIVMSG {} :{}", target, text));
            }
            Command::Notice { target, text } => {
                result.push_str(&format!("NOTICE {} :{}", target, text));
            }
            Command::Ping(server) => {
                result.push_str("PING :");
                result.push_str(server);
            }
            Command::Pong(server) => {
                result.push_str("PONG :");
                result.push_str(server);
            }
            Command::EKey(key) => {
                result.push_str("EKEY ");
                result.push_str(key);
            }
            Command::EMsg {
                target,
                encrypted_data,
            } => {
                result.push_str(&format!("EMSG {} :{}", target, encrypted_data));
            }
            Command::Ack { message_id } => {
                result.push_str(&format!("ACK {}", message_id));
            }
            Command::Server {
                name,
                hopcount,
                info,
            } => {
                result.push_str(&format!("SERVER {} {} :{}", name, hopcount, info));
            }
            Command::Numeric { code, params } => {
                result.push_str(&format!("{:03}", code));
                for param in params {
                    result.push(' ');
                    if param.contains(' ') {
                        result.push(':');
                    }
                    result.push_str(param);
                }
            }
            Command::Raw { command, params } => {
                result.push_str(command);
                for param in params {
                    result.push(' ');
                    if param.contains(' ') {
                        result.push(':');
                    }
                    result.push_str(param);
                }
            }
            _ => {
                // Add other commands as needed
                result.push_str(&format!("{:?}", self.command));
            }
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_nick() {
        let msg = Message::parse("NICK TestUser").unwrap();
        assert_eq!(msg.command, Command::Nick("TestUser".to_string()));
    }

    #[test]
    fn test_parse_privmsg() {
        let msg = Message::parse("PRIVMSG #channel :Hello world").unwrap();
        match msg.command {
            Command::PrivMsg { target, text } => {
                assert_eq!(target, "#channel");
                assert_eq!(text, "Hello world");
            }
            _ => panic!("Wrong command type"),
        }
    }

    #[test]
    fn test_parse_with_prefix() {
        let msg = Message::parse(":nick!user@host PRIVMSG #chan :test").unwrap();
        assert!(msg.prefix.is_some());
        match msg.prefix.unwrap() {
            Prefix::User { nick, user, host } => {
                assert_eq!(nick, "nick");
                assert_eq!(user, Some("user".to_string()));
                assert_eq!(host, Some("host".to_string()));
            }
            _ => panic!("Wrong prefix type"),
        }
    }

    #[test]
    fn test_serialize_message() {
        let msg = Message::new(Command::PrivMsg {
            target: "#test".to_string(),
            text: "Hello".to_string(),
        });
        let serialized = msg.to_string();
        assert_eq!(serialized, "PRIVMSG #test :Hello");
    }

    #[test]
    fn test_encrypted_key_exchange() {
        let msg = Message::parse("EKEY abc123def456").unwrap();
        assert!(matches!(msg.command, Command::EKey(_)));
    }
}
