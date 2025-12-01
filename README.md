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

### Run Single Server

```bash
cargo run --bin sirc-server -- --host 0.0.0.0 --port 6667
```

### Run Federated Network

```bash
# Easy setup - run the test script
./test_federation.sh

# Or manually:
# Server 1
cargo run --bin sirc-server -- --name alpha.sirc --port 6667 --fed-port 7000 --federate

# Server 2 (connects to Server 1)
cargo run --bin sirc-server -- --name beta.sirc --port 6668 --fed-port 7001 --federate --peers localhost:7000

# Server 3 (full mesh)
cargo run --bin sirc-server -- --name gamma.sirc --port 6669 --fed-port 7002 --federate --peers localhost:7000,localhost:7001
```

### Run Client

```bash
cargo run --bin sirc-client -- --server localhost:6667 --nick YourNick

# With encryption
cargo run --bin sirc-client -- --server localhost:6667 --nick YourNick --encrypt
```

## Protocol

SIRC extends traditional IRC with encrypted and federation message types:

```
# Traditional IRC commands
NICK username
JOIN #channel
PRIVMSG #channel :Hello world

# Encryption extensions
EKEY <pubkey>                    # Exchange public keys
EMSG <target> :<encrypted_data>  # Encrypted message

# Federation extensions
SERVER <name> <hop> :<info>      # Server introduction
SJOIN <channel> <users>          # Channel sync
BURST / BURST_END                # State synchronization
```

## Documentation

- **[FEDERATION.md](FEDERATION.md)** - Complete mesh federation guide
- **[ARCHITECTURE.md](ARCHITECTURE.md)** - System architecture and design
- **[USAGE.md](USAGE.md)** - Detailed usage instructions
- **examples/** - Example code for basic and encrypted clients

## Features Status

### ✅ Implemented
- [x] End-to-end encryption (X25519 + ChaCha20-Poly1305)
- [x] IRC protocol support (JOIN, PRIVMSG, NICK, etc.)
- [x] Terminal UI client with ratatui
- [x] Server-to-server federation
- [x] Mesh network topology
- [x] Channel state synchronization
- [x] Automatic routing

### 🚧 In Development
- [ ] Perfect Forward Secrecy (key rotation)
- [ ] Cross-server private messaging
- [ ] Server authentication
- [ ] Encrypted server links
- [ ] Persistent key storage
- [ ] Mobile/web clients

## Development Status

🚧 **Work in Progress** - This is an experimental implementation for educational purposes.

### What Works
- Single server IRC with multiple clients ✅
- End-to-end encryption between clients ✅
- 3+ server federation mesh network ✅
- Channel synchronization across servers ✅
- TUI client with real-time messaging ✅

### What's Next
- User-to-user cross-server messaging
- Server authentication and TLS
- Advanced routing algorithms
- Performance optimization

## Testing

### Test Single Server
```bash
# Terminal 1: Start server
cargo run --bin sirc-server

# Terminal 2: Client 1
cargo run --bin sirc-client -- --server localhost:6667 --nick alice --encrypt

# Terminal 3: Client 2
cargo run --bin sirc-client -- --server localhost:6667 --nick bob --encrypt
```

### Test Federation
```bash
# Run the federation test script
./test_federation.sh

# Then connect clients to different servers and join the same channel
```

## Security Notice

This implementation is for learning and experimentation. Do not use for sensitive communications without a thorough security audit.

**Known limitations:**
- No Perfect Forward Secrecy yet
- Server-to-server links not encrypted
- No server authentication
- Keys not persisted between sessions

## License

MIT OR Apache-2.0
