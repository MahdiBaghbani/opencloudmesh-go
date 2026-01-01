#!/bin/bash
# Two-instance development runner for opencloudmesh-go
# Starts sender (port 9200) and receiver (port 9201) for local federation testing

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

cd "$REPO_ROOT"

echo "Building opencloudmesh-go..."
go build -o bin/opencloudmesh-go ./cmd/opencloudmesh-go

echo ""
echo "Starting two instances for local federation testing..."
echo "  Sender:   http://localhost:9200"
echo "  Receiver: http://localhost:9201"
echo ""
echo "Press Ctrl+C to stop both instances."
echo ""

# Trap to kill both processes on exit
cleanup() {
    echo ""
    echo "Stopping instances..."
    kill $SENDER_PID $RECEIVER_PID 2>/dev/null || true
    wait $SENDER_PID $RECEIVER_PID 2>/dev/null || true
    echo "Done."
}
trap cleanup EXIT INT TERM

# Start sender
./bin/opencloudmesh-go \
    --listen ":9200" \
    --external-origin "http://localhost:9200" \
    --external-base-path "" \
    2>&1 | sed 's/^/[SENDER] /' &
SENDER_PID=$!

# Start receiver
./bin/opencloudmesh-go \
    --listen ":9201" \
    --external-origin "http://localhost:9201" \
    --external-base-path "" \
    2>&1 | sed 's/^/[RECEIVER] /' &
RECEIVER_PID=$!

# Wait for both to exit
wait $SENDER_PID $RECEIVER_PID
