//! Example of encrypted communication

use anyhow::Result;
use futures::{SinkExt, StreamExt};
use sirc_crypto::EncryptedSession;
use sirc_protocol::{Command, IrcCodec, Message};
use tokio::net::TcpStream;
use tokio_util::codec::Framed;

#[tokio::main]
async fn main() -> Result<()> {
    println!("Connecting with encryption...");

    let stream = TcpStream::connect("localhost:6667").await?;
    let mut framed = Framed::new(stream, IrcCodec::new());
    let mut session = EncryptedSession::new();

    // Register
    framed
        .send(Message::new(Command::Nick("crypto_bot".to_string())))
        .await?;
    framed
        .send(Message::new(Command::User {
            username: "cryptobot".to_string(),
            realname: "Crypto Bot".to_string(),
        }))
        .await?;

    // Initiate key exchange
    let pubkey = hex::encode(session.public_key().as_bytes());
    framed.send(Message::new(Command::EKey(pubkey))).await?;
    println!("Sent public key");

    // Wait for server's public key
    while let Some(Ok(msg)) = framed.next().await {
        println!("Received: {:?}", msg.command);

        if let Command::EKey(pubkey_hex) = msg.command {
            let pubkey_bytes = hex::decode(&pubkey_hex)?;
            if pubkey_bytes.len() == 32 {
                let mut key_array = [0u8; 32];
                key_array.copy_from_slice(&pubkey_bytes);
                let remote_key = x25519_dalek::PublicKey::from(key_array);
                session.set_remote_key(remote_key);
                println!("Encryption established!");
                break;
            }
        }

        // Respond to PING
        if let Command::Ping(server) = msg.command {
            framed.send(Message::new(Command::Pong(server))).await?;
        }
    }

    // Send encrypted message
    if session.is_ready() {
        let plaintext = b"This is a secret message!";
        let encrypted = session.encrypt(plaintext)?;
        let encoded = encrypted.to_base64()?;

        framed
            .send(Message::new(Command::EMsg {
                target: "server".to_string(),
                encrypted_data: encoded,
            }))
            .await?;
        println!("Sent encrypted message");
    }

    // Receive response
    for _ in 0..5 {
        if let Some(Ok(msg)) = framed.next().await {
            if let Command::EMsg {
                target: _,
                encrypted_data,
            } = msg.command
            {
                let encrypted_msg = sirc_crypto::EncryptedMessage::from_base64(&encrypted_data)?;
                let plaintext = session.decrypt(&encrypted_msg)?;
                let text = String::from_utf8(plaintext)?;
                println!("Decrypted response: {}", text);
            }
        }
    }

    Ok(())
}
