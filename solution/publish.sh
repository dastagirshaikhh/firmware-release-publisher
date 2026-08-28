#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

mkdir -p /app/publisher
cp "${SCRIPT_DIR}/release-publisher.mjs" /app/publisher/release-publisher.mjs

cd /app/distribution-gateway
node server.js >/tmp/gateway.log 2>&1 &
GATEWAY_PID=$!

cleanup() {
    kill "$GATEWAY_PID" 2>/dev/null || true
    wait "$GATEWAY_PID" 2>/dev/null || true
}

trap cleanup EXIT

for _ in $(seq 1 20); do
    if node -e "fetch('http://127.0.0.1:7070/healthz').then(r => { if (!r.ok) process.exit(1) }).catch(() => process.exit(1))"; then
        break
    fi

    if ! kill -0 "$GATEWAY_PID" 2>/dev/null; then
        echo "Distribution gateway exited before becoming healthy." >&2
        cat /tmp/gateway.log >&2 || true
        exit 1
    fi

    sleep 0.25
done

if ! node -e "fetch('http://127.0.0.1:7070/healthz').then(r => { if (!r.ok) process.exit(1) }).catch(() => process.exit(1))"; then
    echo "Distribution gateway failed to become healthy." >&2
    cat /tmp/gateway.log >&2 || true
    exit 1
fi

cd /app
node /app/publisher/release-publisher.mjs --report