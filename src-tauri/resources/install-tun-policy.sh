#!/bin/bash
# install-tun-policy.sh
# Installs sudoers rules for passwordless TUN mode in CrabSock

set -e

SUDOERS_FILE="$1"
WRAPPER_SCRIPT="$2"
SUDOERS_INSTALL_PATH="/etc/sudoers.d/crabsock"
WRAPPER_SYMLINK="/usr/local/bin/crabsock-tun-wrapper"

if [ -z "$SUDOERS_FILE" ]; then
  echo "Usage: $0 <sudoers_file_path> <wrapper_script_path>"
  exit 1
fi

if [ ! -f "$SUDOERS_FILE" ]; then
  echo "Error: Sudoers file not found: $SUDOERS_FILE"
  exit 1
fi

# Validate sudoers file syntax before installing
echo "Validating sudoers syntax..."
if ! visudo -c -f "$SUDOERS_FILE" > /dev/null 2>&1; then
  echo "Error: Invalid sudoers syntax!"
  exit 1
fi

# Create symlink to wrapper script in /usr/local/bin
if [ -n "$WRAPPER_SCRIPT" ] && [ -f "$WRAPPER_SCRIPT" ]; then
  echo "Creating symlink: $WRAPPER_SYMLINK -> $WRAPPER_SCRIPT"
  ln -sf "$WRAPPER_SCRIPT" "$WRAPPER_SYMLINK"
  chmod +x "$WRAPPER_SYMLINK"
  chmod +x "$WRAPPER_SCRIPT"
fi

# Copy sudoers file
echo "Installing CrabSock sudoers rules to $SUDOERS_INSTALL_PATH"
cp "$SUDOERS_FILE" "$SUDOERS_INSTALL_PATH"
chmod 440 "$SUDOERS_INSTALL_PATH"
chown root:root "$SUDOERS_INSTALL_PATH"

echo "Sudoers rules installed successfully!"
echo "TUN mode will no longer require password."
echo ""
echo "Commands allowed without password:"
echo "  - sudo /usr/local/bin/crabsock-tun-wrapper <sing-box> <config>"
echo "  - sudo killall sing-box"
exit 0

