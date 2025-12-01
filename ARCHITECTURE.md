# SIRC Architecture

## Overview

SIRC (Secure IRC) is a modern IRC implementation with end-to-end encryption and federated architecture, built in Rust.

## Components

### 1. sirc-crypto

The cryptography module provides secure end-to-end encryption primitives.

**Key Features:**
- **X25519 ECDH**: Elliptic Curve Diffie-Hellman for key exchange
- **ChaCha20-Poly1305**: AEAD cipher for message encryption
- **BLAKE3**: Fast key derivation function
- **Automatic zeroization**: Memory-safe secret handling

**Flow:**
```
Alice                           Bob
  |                              |
  |-- Generate KeyPair ---------|
  |-- Send PublicKey ---------->|
  |                              |-- Generate KeyPair
  |<--------- Send PublicKey ---|
  |                              |
  |-- Derive SharedSecret ------|-- Derive SharedSecret
  |                              |
  |-- Encrypt(message) -------->|-- Decrypt(message)
```

### 2. sirc-protocol

IRC protocol implementation with encrypted extensions.

**Traditional IRC Commands:**
- `NICK`, `USER`, `JOIN`, `PART`, `PRIVMSG`, `NOTICE`
- `PING`, `PONG`, `QUIT`

**SIRC Extensions:**
- `EKEY <pubkey>`: Exchange public keys for E2EE
- `EMSG <target> :<encrypted_data>`: Send encrypted message

**Message Format:**
```
[:prefix] COMMAND [params] [:trailing]
```

### 3. sirc-server

Asynchronous IRC server with federation support.

**Architecture:**
- **Async I/O**: Built on Tokio runtime
- **Concurrent connections**: Each client runs in separate task
- **Channel management**: Shared state with RwLock
- **Encryption sessions**: Per-client encrypted sessions

**Server State:**
```rust
ServerState {
    channels: HashMap<String, Channel>,
    clients: HashMap<String, Client>,
}
```

### 4. sirc-client

Terminal UI client with encryption support.

**Features:**
- **TUI**: Built with ratatui and crossterm
- **Commands**:
  - `/join #channel`
  - `/msg <target> <text>`
  - `/quit`
- **Automatic encryption**: When enabled, all messages encrypted

## Security Design

### Key Exchange

SIRC uses Diffie-Hellman key exchange with X25519:

1. Both parties generate ephemeral keypairs
2. Public keys are exchanged via `EKEY` command
3. Shared secret derived using ECDH
4. Encryption key derived from shared secret using BLAKE3

### Message Encryption

Messages encrypted with ChaCha20-Poly1305 AEAD:

1. Generate random 96-bit nonce
2. Encrypt plaintext with key + nonce
3. Authenticate ciphertext with Poly1305 MAC
4. Encode as base64 for transmission
5. Decode and verify on receipt

### Memory Safety

- All secrets use `Zeroize` trait for automatic memory clearing
- Rust's ownership system prevents memory leaks
- No unsafe code in crypto module

## Federation (Future)

SIRC servers can form federated networks:

```
Server A <----> Server B <----> Server C
   |               |
Client 1       Client 2
```

- Mesh topology for redundancy
- Message routing through server network
- Shared channel state across federation

## Protocol Examples

### Connection & Registration

```
C: NICK alice
S: :sirc.local NOTICE alice :Nick set to alice
C: USER alice 0 * :Alice User
S: :sirc.local 001 alice :Welcome to SIRC alice
```

### Key Exchange

```
C: EKEY a1b2c3d4e5f6...
S: EKEY f6e5d4c3b2a1...
```

### Encrypted Messaging

```
C: EMSG bob :SGVsbG8gV29ybGQ=...
S: EMSG alice :SGVsbG8gQWxpY2U=...
```

### Channel Operations

```
C: JOIN #secure
S: :alice!alice@localhost JOIN #secure
S: :sirc.local 331 alice #secure :No topic set
C: PRIVMSG #secure :Hello everyone
```

## Performance Considerations

- **Async I/O**: Non-blocking, scales to thousands of connections
- **Zero-copy**: Bytes crate for efficient buffer management
- **Lightweight crypto**: ChaCha20 faster than AES on many platforms
- **Minimal allocations**: Reuse buffers where possible

## Future Enhancements

1. **Perfect Forward Secrecy (PFS)**: Rotate keys periodically
2. **Multi-device support**: Sync keys across devices
3. **File transfer**: Encrypted file sharing
4. **Voice/Video**: WebRTC integration
5. **Mobile clients**: Native iOS/Android apps
6. **Web client**: WebAssembly + WebSocket
