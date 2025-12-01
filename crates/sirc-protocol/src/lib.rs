//! SIRC Protocol Implementation
//!
//! Extends traditional IRC protocol with encrypted message types.

pub mod codec;
pub mod message;

pub use codec::IrcCodec;
pub use message::{Command, Message, Prefix};

use thiserror::Error;

#[derive(Error, Debug)]
pub enum ProtocolError {
    #[error("Invalid message format")]
    InvalidFormat,

    #[error("Missing required parameter")]
    MissingParameter,

    #[error("Invalid command: {0}")]
    InvalidCommand(String),

    #[error("UTF-8 encoding error")]
    Utf8Error(#[from] std::str::Utf8Error),

    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, ProtocolError>;
