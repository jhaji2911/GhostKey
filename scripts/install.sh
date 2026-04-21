#!/usr/bin/env sh
# GhostKey installer — https://ghostkey.sh
# Usage: curl -fsSL https://ghostkey.sh/install | sh
set -e

GHOSTKEY_VERSION="v0.1.4"
GHOSTKEY_REPO="jhaji2911/GhostKey"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="$HOME/.ghostkey"
PROXY_PORT="9876"

# ── 1. Detect OS and architecture ─────────────────────────────────────────────

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$ARCH" in
  x86_64)  ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) echo "  ✗ Unsupported architecture: $ARCH" && exit 1 ;;
esac

case "$OS" in
  linux|darwin) ;;
  *) echo "  ✗ Unsupported OS: $OS. Use the Windows installer at https://ghostkey.sh/windows" && exit 1 ;;
esac

BINARY="ghostkey-${OS}-${ARCH}"
DOWNLOAD_URL="https://github.com/${GHOSTKEY_REPO}/releases/download/${GHOSTKEY_VERSION}/${BINARY}"

# ── 2. Download binary ────────────────────────────────────────────────────────

echo ""
echo "  👻 GhostKey Installer"
echo "  ─────────────────────────────────────────"
echo ""
echo "  → Downloading ghostkey ${GHOSTKEY_VERSION} for ${OS}/${ARCH}..."

TMP_DIR="$(mktemp -d)"
TMP_BINARY="${TMP_DIR}/ghostkey"

if command -v curl >/dev/null 2>&1; then
  curl -fsSL --progress-bar "$DOWNLOAD_URL" -o "$TMP_BINARY"
elif command -v wget >/dev/null 2>&1; then
  wget -q --show-progress "$DOWNLOAD_URL" -O "$TMP_BINARY"
else
  echo "  ✗ Neither curl nor wget found. Install one and retry."
  exit 1
fi

chmod +x "$TMP_BINARY"

# ── 3. Verify SHA256 ──────────────────────────────────────────────────────────

echo "  → Verifying checksum..."
SUMS_URL="https://github.com/${GHOSTKEY_REPO}/releases/download/${GHOSTKEY_VERSION}/SHA256SUMS"
ACTUAL_SUM=""
EXPECTED_SUM=""

if command -v curl >/dev/null 2>&1; then
  EXPECTED_SUM="$(curl -fsSL "$SUMS_URL" 2>/dev/null | grep "$BINARY" | awk '{print $1}')"
else
  EXPECTED_SUM="$(wget -qO- "$SUMS_URL" 2>/dev/null | grep "$BINARY" | awk '{print $1}')"
fi

if command -v sha256sum >/dev/null 2>&1; then
  ACTUAL_SUM="$(sha256sum "$TMP_BINARY" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
  ACTUAL_SUM="$(shasum -a 256 "$TMP_BINARY" | awk '{print $1}')"
else
  echo "  ⚠ Cannot verify checksum (sha256sum/shasum not found). Proceeding anyway."
fi

if [ -n "$ACTUAL_SUM" ] && [ -n "$EXPECTED_SUM" ] && [ "$ACTUAL_SUM" != "$EXPECTED_SUM" ]; then
  echo "  ✗ Checksum mismatch!"
  echo "    Expected: $EXPECTED_SUM"
  echo "    Got:      $ACTUAL_SUM"
  echo "    This may indicate download corruption or a security issue. Aborting."
  rm -rf "$TMP_DIR"
  exit 1
fi

if [ -n "$ACTUAL_SUM" ]; then
  echo "  ✓ Checksum verified"
fi

# ── 4. Install binary ─────────────────────────────────────────────────────────

echo "  → Installing to ${INSTALL_DIR}/ghostkey..."

if [ -w "$INSTALL_DIR" ]; then
  mv "$TMP_BINARY" "${INSTALL_DIR}/ghostkey"
else
  echo "  (sudo required to write to ${INSTALL_DIR})"
  sudo mv "$TMP_BINARY" "${INSTALL_DIR}/ghostkey"
fi

echo "  ✓ Binary installed"

# ── 5. Write default config ───────────────────────────────────────────────────
# Config MUST exist before we call any ghostkey subcommand that reads it.

mkdir -p "$CONFIG_DIR"

if [ ! -f "${CONFIG_DIR}/ghostkey.yaml" ]; then
  cat > "${CONFIG_DIR}/ghostkey.yaml" << EOF
proxy:
  listen_addr: "127.0.0.1:${PROXY_PORT}"
  read_timeout: 30
  write_timeout: 30

vault:
  backend: file
  file_path: "${CONFIG_DIR}/secrets.yaml"
  watch_file: true

audit:
  enabled: true
  file_path: "${CONFIG_DIR}/audit.ndjson"
  format: json

ca:
  cert_file: "${CONFIG_DIR}/ca.crt"
  key_file: "${CONFIG_DIR}/ca.key"
EOF
fi

touch "${CONFIG_DIR}/secrets.yaml"
echo "  ✓ Config written to ${CONFIG_DIR}/ghostkey.yaml"

# ── 6. Generate CA + install into system trust store ─────────────────────────

echo ""
echo "  ─────────────────────────────────────────"
echo "  CA Certificate Setup"
echo "  ─────────────────────────────────────────"
echo ""
echo "  GhostKey needs to install a local CA certificate to inspect"
echo "  HTTPS traffic from your AI agents. This certificate:"
echo ""
echo "    • Is generated fresh on YOUR machine right now"
echo "    • Only affects processes that use GhostKey's proxy"
echo "    • Can be removed anytime with: ghostkey ca uninstall"
echo "    • Source code: github.com/jhaji2911/GhostKey"
echo ""
echo "  This is the same technique used by Charles Proxy, Burp Suite,"
echo "  and corporate HTTPS inspection proxies."
echo ""

# ghostkey ca install generates the CA keypair on first run (if absent)
# and adds it to the system trust store — no need to run `ghostkey start` first.
ghostkey ca install
echo "  ✓ CA certificate trusted"

# ── 7. Detect shell and inject env vars ──────────────────────────────────────

detect_shell_rc() {
  case "$SHELL" in
    */zsh)  echo "$HOME/.zshrc" ;;
    */bash)
      if [ -f "$HOME/.bash_profile" ]; then
        echo "$HOME/.bash_profile"
      else
        echo "$HOME/.bashrc"
      fi
      ;;
    */fish) echo "$HOME/.config/fish/config.fish" ;;
    *)      echo "$HOME/.profile" ;;
  esac
}

SHELL_RC="$(detect_shell_rc)"
PROXY_EXPORT="export GHOSTKEY_ACTIVE=1"

if ! grep -q "GHOSTKEY_ACTIVE" "$SHELL_RC" 2>/dev/null; then
  echo "" >> "$SHELL_RC"
  echo "# GhostKey — added by installer $(date '+%Y-%m-%d')" >> "$SHELL_RC"
  echo "$PROXY_EXPORT" >> "$SHELL_RC"
fi

echo "  ✓ Shell configured (${SHELL_RC})"

# ── 7. Install as system service (auto-start on login) ───────────────────────

ghostkey service install

# ── 8. Run ghostkey doctor to verify everything ───────────────────────────────

echo ""
echo "  ─────────────────────────────────────────"
echo "  Verifying installation..."
echo "  ─────────────────────────────────────────"
ghostkey doctor

# ── 9. Print next steps ───────────────────────────────────────────────────────

echo ""
echo "  ─────────────────────────────────────────"
echo "  ✓ GhostKey is installed and running"
echo "  ─────────────────────────────────────────"
echo ""
echo "  Add your first credential:"
echo ""
echo "    ghostkey vault add GHOST::openai"
echo "    ghostkey vault add GHOST::github"
echo ""
echo "  Run your agent:"
echo ""
echo "    ghostkey wrap -- claude"
echo "    ghostkey wrap -- python agent.py"
echo "    ghostkey wrap -- aider"
echo ""
echo "  View live audit log:"
echo ""
echo "    ghostkey audit tail"
echo ""
echo "  Docs: https://ghostkey.sh"
echo ""

rm -rf "$TMP_DIR"
