# SIRC Federation - Mesh Network Guide

## Overview

SIRC implements a **mesh federation** model where servers form a decentralized network. Unlike traditional hub-and-spoke IRC networks, SIRC's mesh topology provides better fault tolerance and no single point of failure.

## Architecture

### Mesh Topology

```
    Server A <-----> Server B
       ^                ^
       |                |
       v                v
    Server C <-----> Server D
```

- Each server can connect to multiple peers
- Messages are routed through the network
- Automatic discovery of remote servers
- No central hub required

### Federation Protocol

#### SERVER Message
```
SERVER <name> <hopcount> :<info>
```
Introduces a server to the network. Hopcount tracks distance in the mesh.

#### SJOIN - Channel Join Sync
```
SJOIN <channel> <users>
```
Synchronizes channel membership across servers.

#### BURST - Initial State Sync
When servers connect, they exchange BURST messages containing current state:
- All channels and their users
- BURST_END marker signals completion

#### Message Routing
- Direct messages to users on connected servers
- Broadcast to all peers for channel messages
- Routing table prevents loops

## Usage

### Starting a Federated Network

#### Server 1 (Hub)

```bash
cargo run --bin sirc-server -- \
  --name server1.sirc \
  --port 6667 \
  --fed-port 7000 \
  --federate
```

This starts a server that:
- Accepts clients on port 6667
- Accepts federation connections on port 7000
- Waits for peer servers to connect

#### Server 2 (Connect to Server 1)

```bash
cargo run --bin sirc-server -- \
  --name server2.sirc \
  --port 6668 \
  --fed-port 7001 \
  --federate \
  --peers localhost:7000
```

Server 2 will:
- Accept clients on port 6668
- Accept federation on port 7001
- Connect to Server 1 at localhost:7000
- Sync state via BURST

#### Server 3 (Complete the Mesh)

```bash
cargo run --bin sirc-server -- \
  --name server3.sirc \
  --port 6669 \
  --fed-port 7002 \
  --federate \
  --peers localhost:7000,localhost:7001
```

Server 3 connects to both Server 1 and Server 2, forming a full mesh.

## Testing Federation

### 3-Server Test Setup

**Terminal 1 - Server 1**
```bash
cargo run --bin sirc-server -- --name alpha.sirc --port 6667 --fed-port 7000 --federate
```

**Terminal 2 - Server 2**
```bash
cargo run --bin sirc-server -- --name beta.sirc --port 6668 --fed-port 7001 --federate --peers localhost:7000
```

**Terminal 3 - Server 3**
```bash
cargo run --bin sirc-server -- --name gamma.sirc --port 6669 --fed-port 7002 --federate --peers localhost:7000,localhost:7001
```

**Terminal 4 - Client on Server 1**
```bash
cargo run --bin sirc-client -- --server localhost:6667 --nick alice
```

**Terminal 5 - Client on Server 2**
```bash
cargo run --bin sirc-client -- --server localhost:6668 --nick bob
```

**Terminal 6 - Client on Server 3**
```bash
cargo run --bin sirc-client -- --server localhost:6669 --nick charlie
```

### Observing Federation

1. **Server Logs**: Watch federation connections establish:
   ```
   INFO sirc_server::federation: Incoming federation connection from 127.0.0.1:xxxxx
   INFO sirc_server::federation: Received SERVER from beta.sirc (hop 0)
   INFO sirc_server::federation: Connected to peer alpha.sirc (hop 0)
   ```

2. **Channel Sync**: Join same channel from different servers:
   ```
   Alice (on Server 1): /join #global
   Bob (on Server 2): /join #global
   Charlie (on Server 3): /join #global
   ```

   Server logs will show SJOIN synchronization:
   ```
   INFO sirc_server::federation: Synced channel #global with 3 users
   ```

3. **Cross-Server Messaging**: Users on different servers can communicate

## Protocol Details

### Connection Handshake

```
Peer A                          Peer B
  |                                |
  |--- SERVER A 0 :Info --------->|
  |<-- SERVER B 0 :Info -----------|
  |                                |
  |--- BURST Start -------------->|
  |--- SJOIN #chan user1,user2 -->|
  |--- BURST_END ---------------->|
  |                                |
  |<-- BURST Start ----------------|
  |<-- SJOIN #foo user3 -----------|
  |<-- BURST_END ------------------|
  |                                |
  [Normal operation]
```

### Routing Table

Each server maintains:
- **Direct Peers**: Servers directly connected
- **Routes**: How to reach remote servers
- **Hopcount**: Distance to each server

Example:
```
Server A knows:
  - B (direct, hop 1)
  - C (via B, hop 2)
  - D (via B, hop 2)
```

### Loop Prevention

- Hopcount tracking
- Message origin tracking
- Servers don't relay back to source

## Features

### ✅ Implemented

- [x] Server-to-server connections
- [x] SERVER introduction protocol
- [x] BURST state synchronization
- [x] SJOIN channel sync
- [x] Routing table management
- [x] Mesh topology support
- [x] Automatic peer discovery
- [x] Channel state federation
- [x] **Cross-server messaging (SMSG)**
- [x] **Keepalive mechanism (SPING/SPONG)**
- [x] **Persistent key storage**
- [x] **Automatic reconnection after disconnect** (exponential backoff)
- [x] **Server authentication (TLS certificates)**
- [x] **Encrypted server-to-server links (TLS 1.3)**
- [x] **Split brain detection and healing** (120s timeout, automatic resync)
- [x] **Performance metrics** (messages, connections, latency, partitions)

### 🚧 In Development

- [ ] Message delivery confirmations
- [ ] Certificate revocation (CRL/OCSP)
- [ ] Advanced routing optimization

## Advanced Configuration

### Multi-Region Setup

**US Server**
```bash
sirc-server --name us.sirc.net --fed-port 7000 --federate
```

**EU Server**
```bash
sirc-server --name eu.sirc.net --fed-port 7000 --federate --peers us.sirc.net:7000
```

**Asia Server**
```bash
sirc-server --name asia.sirc.net --fed-port 7000 --federate --peers us.sirc.net:7000,eu.sirc.net:7000
```

### Performance Tuning

- **Optimal mesh size**: 3-10 servers
- **Max hopcount**: 3 recommended
- **Latency**: <100ms between peers ideal
- **Bandwidth**: ~1KB/s per active channel

## Troubleshooting

### Servers Won't Connect

```
ERROR: Failed to connect to peer localhost:7000: Connection refused
```

**Solution**: Ensure peer server is running and federation port is correct

### BURST Timeout

```
WARN: Error from peer: Timeout waiting for BURST_END
```

**Solution**: Check network connectivity, increase timeout if needed

### Split Network

```
INFO: Peer alpha.sirc disconnected
```

**Solution**: Servers will automatically try to reconnect (future feature)

## Security Considerations

1. **No Authentication**: Current implementation has no server auth
2. **Plaintext**: Server-to-server links are not encrypted
3. **Trust Model**: All servers in federation are fully trusted

**Future improvements:**
- TLS for server links
- Server authentication with certificates
- ACLs for server connections

## Comparison with Traditional IRC

| Feature | Traditional IRC | SIRC Mesh |
|---------|----------------|-----------|
| Topology | Hub & Spoke | Full Mesh |
| SPOF | Hub server | None |
| Latency | 1-2 hops | 1-N hops |
| Resilience | Low | High |
| Setup | Complex | Simple |

## Example: 5-Server Mesh

```bash
# Start all servers
for i in {1..5}; do
  cargo run --bin sirc-server -- \
    --name server$i.sirc \
    --port $((6666 + i)) \
    --fed-port $((6999 + i)) \
    --federate \
    --peers $(for j in {1..$((i-1))}; do echo -n "localhost:$((6999 + j)),"; done) &
done
```

This creates a complete mesh of 5 servers, each connected to all others.

## Monitoring Federation

### Check Connected Peers

```rust
// Future API
let peers = federation_manager.get_servers().await;
println!("Connected to {} servers", peers.len());
```

### Statistics

Future features will include:
- Messages routed per second
- Average hopcount
- Server uptime
- Channel distribution
- User count per server

## Contributing

Federation is a work in progress! Areas needing help:
- Server authentication
- TLS/encryption
- Split detection and healing
- Performance optimization
- Load balancing
