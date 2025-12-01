# SIRC - Secure IRC

Modern, secure IRC implementation with end-to-end encryption and federated architecture.

## Features

- 🔐 **End-to-End Encryption**: Uses X25519 (ECDH) + ChaCha20-Poly1305 (AEAD)
- 🌐 **Federated Architecture**: Decentralized mesh network of servers
- 🚀 **Modern Implementation**: Written in Rust with async/await
- 💬 **IRC Compatible**: Works with existing IRC concepts (channels, private messages)
- 🛡️ **Security First**: Memory-safe Rust, secure key exchange, forward secrecy

## Architecture

### Components

- **sirc-server**: Federated IRC server with encryption support
- **sirc-client**: Terminal UI client with encrypted messaging
- **sirc-crypto**: Cryptographic primitives and key exchange
- **sirc-protocol**: IRC protocol parser and message types

### Cryptography

SIRC uses modern cryptographic primitives:

- **Key Exchange**: X25519 Elliptic Curve Diffie-Hellman
- **Encryption**: ChaCha20-Poly1305 AEAD cipher
- **Hashing**: BLAKE3 for key derivation
- **Memory Safety**: Automatic zeroization of secrets

### Federation

Servers form a mesh network where:
- Each server maintains connections to peer servers
- Messages are routed through the network
- Servers can join/leave dynamically
- No single point of failure

## Quick Start

### Build

```bash
cargo build --release
```

### Run Server

```bash
cargo run --bin sirc-server -- --host 0.0.0.0 --port 6667
```

### Run Client

```bash
cargo run --bin sirc-client -- --server localhost:6667 --nick YourNick
```

## Protocol

SIRC extends traditional IRC with encrypted message types:

```
# Traditional IRC commands (plaintext)
NICK username
JOIN #channel
PRIVMSG #channel :Hello world

# Encrypted extensions
EKEY <pubkey>          # Exchange public keys
EMSG <encrypted_data>  # Encrypted message
```

## Development Status

🚧 **Work in Progress** - This is an experimental implementation for educational purposes.

## Security Notice

This implementation is for learning and experimentation. Do not use for sensitive communications without a thorough security audit.

## License

MIT OR Apache-2.0
