//! Tokio codec for IRC messages

use crate::{Message, ProtocolError, Result};
use bytes::{BufMut, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

/// IRC message codec for Tokio
pub struct IrcCodec {
    max_line_length: usize,
}

impl IrcCodec {
    pub fn new() -> Self {
        Self {
            max_line_length: 512, // IRC protocol limit
        }
    }

    pub fn with_max_length(max_length: usize) -> Self {
        Self {
            max_line_length: max_length,
        }
    }
}

impl Default for IrcCodec {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder for IrcCodec {
    type Item = Message;
    type Error = ProtocolError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>> {
        // Look for CRLF
        let line_end = src
            .iter()
            .enumerate()
            .find(|(_, &b)| b == b'\n')
            .map(|(i, _)| i);

        if let Some(end) = line_end {
            if end > self.max_line_length {
                return Err(ProtocolError::InvalidFormat);
            }

            let line = src.split_to(end + 1);
            let line_str = std::str::from_utf8(&line)?;
            let message = Message::parse(line_str)?;
            Ok(Some(message))
        } else {
            // Not enough data yet
            if src.len() > self.max_line_length {
                return Err(ProtocolError::InvalidFormat);
            }
            Ok(None)
        }
    }
}

impl Encoder<Message> for IrcCodec {
    type Error = ProtocolError;

    fn encode(&mut self, item: Message, dst: &mut BytesMut) -> Result<()> {
        let line = item.to_string();
        let bytes = line.as_bytes();

        if bytes.len() > self.max_line_length - 2 {
            return Err(ProtocolError::InvalidFormat);
        }

        dst.reserve(bytes.len() + 2);
        dst.put_slice(bytes);
        dst.put_slice(b"\r\n");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Command;

    #[test]
    fn test_decode_message() {
        let mut codec = IrcCodec::new();
        let mut buf = BytesMut::from("NICK test\r\n");

        let msg = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(msg.command, Command::Nick("test".to_string()));
    }

    #[test]
    fn test_encode_message() {
        let mut codec = IrcCodec::new();
        let mut buf = BytesMut::new();

        let msg = Message::new(Command::Nick("test".to_string()));
        codec.encode(msg, &mut buf).unwrap();

        assert_eq!(&buf[..], b"NICK test\r\n");
    }

    #[test]
    fn test_partial_message() {
        let mut codec = IrcCodec::new();
        let mut buf = BytesMut::from("NICK te");

        let result = codec.decode(&mut buf).unwrap();
        assert!(result.is_none());
    }
}
