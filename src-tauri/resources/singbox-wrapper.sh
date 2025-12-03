#!/bin/bash
# CrabSock sing-box wrapper - runs with root via pkexec
# This allows sing-box auto_route to work without additional password prompts

set -e

SINGBOX_BIN="$1"
CONFIG_PATH="$2"

if [ -z "$SINGBOX_BIN" ] || [ -z "$CONFIG_PATH" ]; then
    echo "Usage: $0 <singbox_binary> <config_path>"
    exit 1
fi

if [ ! -f "$SINGBOX_BIN" ]; then
    echo "Error: sing-box binary not found: $SINGBOX_BIN"
    exit 1
fi

if [ ! -f "$CONFIG_PATH" ]; then
    echo "Error: config file not found: $CONFIG_PATH"
    exit 1
fi

echo "[WRAPPER] Starting sing-box with auto_route..."
echo "[WRAPPER] Binary: $SINGBOX_BIN"
echo "[WRAPPER] Config: $CONFIG_PATH"

# Run sing-box with provided config
# Since this script runs via pkexec, sing-box inherits root privileges
# and can perform auto_route operations (TUN creation, routing, DNS) without additional prompts
exec "$SINGBOX_BIN" run -c "$CONFIG_PATH" --disable-color

