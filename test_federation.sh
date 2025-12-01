#!/bin/bash
# SIRC Federation Test Script
#
# This script starts 3 federated SIRC servers for testing
#
# Usage: ./test_federation.sh
# Stop: Press Ctrl+C or run: pkill -f sirc-server

set -e

echo "=== SIRC Federation Test Setup ==="
echo ""
echo "Starting 3 federated servers..."
echo ""

# Build first
echo "Building SIRC..."
cargo build --release

# Kill any existing instances
pkill -f sirc-server || true
sleep 1

# Start Server 1 (Alpha)
echo "Starting Server 1: alpha.sirc (port 6667, fed 7000)"
cargo run --release --bin sirc-server -- \
  --name alpha.sirc \
  --port 6667 \
  --fed-port 7000 \
  --federate \
  > /tmp/sirc-alpha.log 2>&1 &

ALPHA_PID=$!
sleep 2

# Start Server 2 (Beta)
echo "Starting Server 2: beta.sirc (port 6668, fed 7001)"
cargo run --release --bin sirc-server -- \
  --name beta.sirc \
  --port 6668 \
  --fed-port 7001 \
  --federate \
  --peers localhost:7000 \
  > /tmp/sirc-beta.log 2>&1 &

BETA_PID=$!
sleep 2

# Start Server 3 (Gamma)
echo "Starting Server 3: gamma.sirc (port 6669, fed 7002)"
cargo run --release --bin sirc-server -- \
  --name gamma.sirc \
  --port 6669 \
  --fed-port 7002 \
  --federate \
  --peers localhost:7000,localhost:7001 \
  > /tmp/sirc-gamma.log 2>&1 &

GAMMA_PID=$!
sleep 2

echo ""
echo "=== Federation Network Started ==="
echo ""
echo "Servers running:"
echo "  1. alpha.sirc  - localhost:6667 (federation: 7000) [PID: $ALPHA_PID]"
echo "  2. beta.sirc   - localhost:6668 (federation: 7001) [PID: $BETA_PID]"
echo "  3. gamma.sirc  - localhost:6669 (federation: 7002) [PID: $GAMMA_PID]"
echo ""
echo "Logs:"
echo "  tail -f /tmp/sirc-alpha.log"
echo "  tail -f /tmp/sirc-beta.log"
echo "  tail -f /tmp/sirc-gamma.log"
echo ""
echo "Connect clients:"
echo "  cargo run --bin sirc-client -- --server localhost:6667 --nick alice"
echo "  cargo run --bin sirc-client -- --server localhost:6668 --nick bob"
echo "  cargo run --bin sirc-client -- --server localhost:6669 --nick charlie"
echo ""
echo "Test federation:"
echo "  1. Join #global from all clients: /join #global"
echo "  2. Check logs to see SJOIN synchronization"
echo "  3. Send messages and observe federation"
echo ""
echo "Stop servers: pkill -f sirc-server"
echo ""
echo "Press Enter to stop all servers..."

# Wait for user input or Ctrl+C
read

# Cleanup
echo "Stopping servers..."
kill $ALPHA_PID $BETA_PID $GAMMA_PID 2>/dev/null || true
echo "Servers stopped."
