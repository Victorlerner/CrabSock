#!/bin/bash
# install-openvpn-helper.sh
# Installs crabsock-root-helper with setuid root so that OpenVPN can create TUN
# without requiring sudo from the user on every connection.
#
# Usage (as root, usually via pkexec):
#   install-openvpn-helper.sh /path/to/crabsock-root-helper

set -euo pipefail

HELPER_SRC="${1:-}"
HELPER_DST="/usr/local/bin/crabsock-root-helper"

if [[ -z "${HELPER_SRC}" ]]; then
  echo "Usage: $0 <helper_binary_path>" >&2
  exit 1
fi

if [[ ! -f "${HELPER_SRC}" ]]; then
  echo "Error: helper binary not found: ${HELPER_SRC}" >&2
  exit 1
fi

echo "[INSTALL] Installing crabsock-root-helper from ${HELPER_SRC} to ${HELPER_DST}"

cp "${HELPER_SRC}" "${HELPER_DST}"
chown root:root "${HELPER_DST}"
chmod 4755 "${HELPER_DST}"

echo "[INSTALL] crabsock-root-helper installed with setuid root."
echo "[INSTALL] System OpenVPN binary will be used (from PATH)."

exit 0


