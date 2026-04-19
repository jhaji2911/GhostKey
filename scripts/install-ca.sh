#!/usr/bin/env bash
# install-ca.sh — Install the GhostKey CA certificate into the system trust store.
#
# Usage: ./scripts/install-ca.sh [cert-path]
# Default cert path: ~/.ghostkey/ca.crt

set -euo pipefail

CERT_PATH="${1:-$HOME/.ghostkey/ca.crt}"

if [[ ! -f "$CERT_PATH" ]]; then
  echo "ERROR: CA cert not found at $CERT_PATH"
  echo "Run 'ghostkey start' once to auto-generate the CA, then re-run this script."
  exit 1
fi

OS="$(uname -s)"

case "$OS" in
  Darwin)
    echo "Installing GhostKey CA into macOS System Keychain..."
    sudo security add-trusted-cert \
      -d -r trustRoot \
      -k /Library/Keychains/System.keychain \
      "$CERT_PATH"
    echo "Done. Chrome and Safari will trust GhostKey immediately."
    echo "Firefox requires manual import: Preferences → Privacy → View Certificates → Import."
    ;;
  Linux)
    if [[ -f /etc/debian_version ]]; then
      echo "Installing CA on Debian/Ubuntu..."
      sudo cp "$CERT_PATH" /usr/local/share/ca-certificates/ghostkey.crt
      sudo update-ca-certificates
    elif [[ -f /etc/redhat-release ]]; then
      echo "Installing CA on RHEL/Fedora..."
      sudo cp "$CERT_PATH" /etc/pki/ca-trust/source/anchors/ghostkey.crt
      sudo update-ca-trust
    else
      echo "Unknown Linux distribution. Copying to /usr/local/share/ca-certificates/ghostkey.crt"
      sudo cp "$CERT_PATH" /usr/local/share/ca-certificates/ghostkey.crt
      echo "Run 'sudo update-ca-certificates' or your distro's equivalent."
    fi
    ;;
  *)
    echo "Automatic install not supported on $OS."
    echo "Manually import $CERT_PATH into your browser/OS trust store."
    ;;
esac

echo ""
echo "=== Environment Variables ==="
echo "Add these to your agent's environment (or shell profile):"
echo ""
echo "  export HTTPS_PROXY=http://127.0.0.1:9876"
echo "  export HTTP_PROXY=http://127.0.0.1:9876"
echo "  export NO_PROXY=localhost,127.0.0.1"
echo ""
echo "Then set your API keys to ghost tokens, e.g.:"
echo "  export OPENAI_API_KEY=GHOST::openai-prod"
echo ""
