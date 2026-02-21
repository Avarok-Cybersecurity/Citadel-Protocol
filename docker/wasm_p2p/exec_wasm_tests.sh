#!/usr/bin/env bash
set -e

# Wait for server to be ready on the WebSocket port
echo "Waiting for server on 127.0.0.1:25522..."
for i in $(seq 1 30); do
  if nc -z 127.0.0.1 25522 2>/dev/null; then
    echo "Server is ready!"
    break
  fi
  if [ "$i" -eq 30 ]; then
    echo "ERROR: Server not ready after 30 seconds"
    exit 1
  fi
  sleep 1
done

echo "Running WASM P2P integration tests in headless Chrome..."
cd /usr/src/app/citadel_sdk
RUSTFLAGS='--cfg getrandom_backend="wasm_js"' \
  wasm-pack test --headless --chrome --release \
  -- --features=wasm --no-default-features --test wasm_p2p_connect
echo "WASM P2P integration tests passed!"
