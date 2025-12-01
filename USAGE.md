# SIRC Usage Guide

## Installation

### Build from Source

```bash
git clone https://github.com/AlexMelanFromRingo/sirc.git
cd sirc
cargo build --release
```

Binaries will be in `target/release/`:
- `sirc-server` - IRC server
- `sirc-client` - Terminal client

## Running the Server

### Basic Server

Start a server on default port (6667):

```bash
./target/release/sirc-server
```

### Custom Configuration

```bash
./target/release/sirc-server \
  --host 0.0.0.0 \
  --port 6667 \
  --name my-sirc-server
```

### With Federation

```bash
./target/release/sirc-server \
  --federate \
  --peers peer1.example.com:6667,peer2.example.com:6667
```

## Running the Client

### Basic Connection

```bash
./target/release/sirc-client --server localhost:6667 --nick alice
```

### With Encryption

```bash
./target/release/sirc-client \
  --server localhost:6667 \
  --nick alice \
  --encrypt
```

### Full Options

```bash
./target/release/sirc-client \
  --server irc.example.com:6667 \
  --nick alice \
  --username alice_user \
  --realname "Alice Wonderland" \
  --encrypt
```

## Client Commands

Once connected, you can use these commands in the TUI:

### Join a Channel

```
/join #general
```

### Send a Message

```
/msg bob Hello, how are you?
```

### Send to Channel

Just type your message (if you've joined a channel):

```
Hello everyone!
```

### Quit

```
/quit
```

Or press `Ctrl+C`

## Example Session

### Server Terminal

```bash
$ ./target/release/sirc-server --name sirc.local
2024-12-01T00:00:00Z INFO sirc_server: Starting SIRC server sirc.local on 0.0.0.0:6667
2024-12-01T00:00:01Z INFO sirc_server: SIRC server listening on 0.0.0.0:6667
2024-12-01T00:00:05Z INFO sirc_server: New connection from 127.0.0.1:54321
2024-12-01T00:00:05Z INFO sirc_server::client: PRIVMSG from alice to #general: Hello!
```

### Client Terminal (Alice)

```bash
$ ./target/release/sirc-client --server localhost:6667 --nick alice --encrypt
*** Welcome to SIRC - Secure IRC Server
*** Nick set to alice
[001] alice Welcome to SIRC alice
/join #general
→ Joining #general
← JOIN #general
*** Encryption enabled
/msg bob Secret message
→ [ENCRYPTED] to bob: Secret message
[ENCRYPTED] Response from Bob
```

### Client Terminal (Bob)

```bash
$ ./target/release/sirc-client --server localhost:6667 --nick bob --encrypt
*** Welcome to SIRC - Secure IRC Server
*** Nick set to bob
[001] bob Welcome to SIRC bob
/join #general
→ Joining #general
[ENCRYPTED] Secret message
```

## Testing Encryption

### Terminal 1: Start Server

```bash
cargo run --bin sirc-server
```

### Terminal 2: Alice

```bash
cargo run --bin sirc-client -- --server localhost:6667 --nick alice --encrypt
```

Wait for "Encryption enabled" message, then:

```
/msg bob This is encrypted!
```

### Terminal 3: Bob

```bash
cargo run --bin sirc-client -- --server localhost:6667 --nick bob --encrypt
```

You should see Alice's encrypted message decrypted.

## Configuration

### Server Config (Future)

```toml
# server.toml
[server]
name = "sirc.local"
host = "0.0.0.0"
port = 6667

[federation]
enabled = true
peers = ["peer1.example.com:6667"]

[security]
require_encryption = false
max_connections = 1000
```

### Client Config (Future)

```toml
# client.toml
[defaults]
server = "localhost:6667"
nick = "alice"
username = "alice"
realname = "Alice"
encrypt = true

[keybindings]
quit = "Ctrl+Q"
```

## Troubleshooting

### Connection Refused

```
Error: Connection refused (os error 111)
```

**Solution**: Make sure server is running on the specified host/port.

### Encryption Not Working

```
*** Received encrypted message but session not ready
```

**Solution**: Make sure both clients have `--encrypt` flag enabled.

### Port Already in Use

```
Error: Address already in use (os error 98)
```

**Solution**: Another process is using port 6667. Either:
1. Stop the other process
2. Use a different port: `--port 6668`

## Performance Tips

1. **Use release builds**: `cargo build --release` is ~10x faster
2. **Limit message history**: Client keeps last 1000 messages
3. **Enable encryption only when needed**: Adds ~0.1ms latency per message

## Security Notes

1. This is an **educational project** - not audited for production use
2. Keys are not persisted - regenerated on each connection
3. No forward secrecy - compromise of session keys reveals all messages
4. Server can see unencrypted metadata (who talks to whom, when)

For production use, consider:
- Adding Perfect Forward Secrecy (PFS)
- Implementing key persistence and rotation
- Adding server-to-server encryption
- Getting a professional security audit
