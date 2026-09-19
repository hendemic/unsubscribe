#!/usr/bin/env bash
set -euo pipefail

REPO="hendemic/unsubscribe"
BINARY="unsubscribe"
PRE=false

for arg in "$@"; do
    case "$arg" in
        --pre) PRE=true ;;
    esac
done

# Detect OS
OS="$(uname -s)"
case "$OS" in
    Linux)  OS_TAG="linux" ;;
    Darwin) OS_TAG="macos" ;;
    *)      echo "Unsupported OS: $OS"; exit 1 ;;
esac

# Detect architecture
ARCH="$(uname -m)"
case "$ARCH" in
    x86_64)        ARCH_TAG="x86_64" ;;
    aarch64|arm64) ARCH_TAG="aarch64" ;;
    *)             echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

ASSET="${BINARY}-${OS_TAG}-${ARCH_TAG}"

INSTALL_DIR="${HOME}/.local/bin"

echo "Installing ${BINARY} (${OS_TAG}-${ARCH_TAG})..."

# Get release download URL
if [ "$PRE" = true ]; then
    RELEASE_URL="https://api.github.com/repos/${REPO}/releases"
    RELEASE_JSON=$(curl -sL "$RELEASE_URL")
    DOWNLOAD_URL=$(echo "$RELEASE_JSON" | grep "browser_download_url.*${ASSET}\"" | head -1 | cut -d '"' -f 4)
else
    RELEASE_URL="https://api.github.com/repos/${REPO}/releases/latest"
    RELEASE_JSON=$(curl -sL "$RELEASE_URL")
    DOWNLOAD_URL=$(echo "$RELEASE_JSON" | grep "browser_download_url.*${ASSET}\"" | head -1 | cut -d '"' -f 4)
fi

if [ -z "$DOWNLOAD_URL" ]; then
    echo "Error: Could not find binary for ${OS_TAG}-${ARCH_TAG}"
    echo "Check https://github.com/${REPO}/releases for available builds."
    exit 1
fi

TMP=$(mktemp)
curl -sL "$DOWNLOAD_URL" -o "$TMP"
chmod +x "$TMP"

mkdir -p "$INSTALL_DIR"
mv "$TMP" "${INSTALL_DIR}/${BINARY}"

echo "Installed to ${INSTALL_DIR}/${BINARY}"

# Check if install dir is in PATH
if ! echo "$PATH" | tr ':' '\n' | grep -qx "$INSTALL_DIR"; then
    echo ""
    echo "Note: ${INSTALL_DIR} is not in your PATH."
    echo "Add it with: export PATH=\"${INSTALL_DIR}:\$PATH\""
fi
