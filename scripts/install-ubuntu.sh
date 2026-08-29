#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# Transparent Proxy Gateway (tproxy) - Ubuntu Installation & Setup Script
# ==============================================================================

if [ "$(id -u)" -ne 0 ]; then
    echo "[ERROR] This script must be run as root (or with sudo)." >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"

echo "=================================================================="
echo "  Installing Transparent Proxy Gateway (tproxy) on Ubuntu..."
echo "=================================================================="

# 1. Ensure iptables is installed
if ! command -v iptables &> /dev/null; then
    echo "[1/4] Installing iptables..."
    apt-get update -qq && apt-get install -y -qq iptables
else
    echo "[1/4] iptables is already installed."
fi

# 2. Build or copy tproxy binary
echo "[2/4] Installing tproxy binary to /usr/local/bin/tproxy..."
if [ -f "$REPO_DIR/tproxy" ]; then
    cp "$REPO_DIR/tproxy" /usr/local/bin/tproxy
    chmod +x /usr/local/bin/tproxy
elif command -v go &> /dev/null; then
    echo "      Building tproxy binary from source..."
    cd "$REPO_DIR"
    go build -ldflags="-s -w" -o /usr/local/bin/tproxy ./cmd/tproxy
    chmod +x /usr/local/bin/tproxy
else
    echo "[ERROR] Neither pre-built 'tproxy' binary nor 'go' compiler was found." >&2
    exit 1
fi

# 3. Setup configuration directory
echo "[3/4] Setting up /etc/tproxy/config.json..."
mkdir -p /etc/tproxy
if [ ! -f /etc/tproxy/config.json ]; then
    if [ -f "$REPO_DIR/config.json" ]; then
        cp "$REPO_DIR/config.json" /etc/tproxy/config.json
    elif [ -f "$REPO_DIR/config.json.sample" ]; then
        cp "$REPO_DIR/config.json.sample" /etc/tproxy/config.json
    fi
    echo "      Configuration created at /etc/tproxy/config.json"
else
    echo "      Existing /etc/tproxy/config.json preserved."
fi

# 4. Install and enable systemd service
echo "[4/4] Registering and starting systemd service (tproxy.service)..."
if [ -f "$SCRIPT_DIR/tproxy.service" ]; then
    cp "$SCRIPT_DIR/tproxy.service" /etc/systemd/system/tproxy.service
    systemctl daemon-reload
    systemctl enable tproxy.service
    systemctl restart tproxy.service
    echo "      tproxy.service is now active and running!"
fi

echo "=================================================================="
echo "  Installation completed successfully!"
echo "  - Service status: sudo systemctl status tproxy"
echo "  - Live logs:      sudo journalctl -u tproxy -f"
echo "  - Config file:    /etc/tproxy/config.json"
echo "=================================================================="
