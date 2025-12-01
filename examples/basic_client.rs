//! Basic SIRC client example without TUI

use anyhow::Result;
use futures::{SinkExt, StreamExt};
use sirc_protocol::{Command, IrcCodec, Message};
use tokio::net::TcpStream;
use tokio_util::codec::Framed;

#[tokio::main]
async fn main() -> Result<()> {
    println!("Connecting to localhost:6667...");

    let stream = TcpStream::connect("localhost:6667").await?;
    let mut framed = Framed::new(stream, IrcCodec::new());

    // Send NICK
    framed
        .send(Message::new(Command::Nick("example_bot".to_string())))
        .await?;
    println!("Sent NICK");

    // Send USER
    framed
        .send(Message::new(Command::User {
            username: "examplebot".to_string(),
            realname: "Example Bot".to_string(),
        }))
        .await?;
    println!("Sent USER");

    // Join channel
    framed
        .send(Message::new(Command::Join(vec!["#test".to_string()])))
        .await?;
    println!("Sent JOIN");

    // Send message
    framed
        .send(Message::new(Command::PrivMsg {
            target: "#test".to_string(),
            text: "Hello from basic client!".to_string(),
        }))
        .await?;
    println!("Sent PRIVMSG");

    // Receive messages
    for _ in 0..10 {
        if let Some(Ok(msg)) = framed.next().await {
            println!("Received: {}", msg.to_string());

            // Respond to PING
            if let Command::Ping(server) = msg.command {
                framed.send(Message::new(Command::Pong(server))).await?;
            }
        }
    }

    // Quit
    framed
        .send(Message::new(Command::Quit(Some(
            "Goodbye!".to_string(),
        ))))
        .await?;

    Ok(())
}
