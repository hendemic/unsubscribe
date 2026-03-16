#!/usr/bin/env bash
set -euo pipefail

echo "Building unsubscribe for macOS..."
cargo build --release

BINARY="target/release/unsubscribe"
echo "Built: ${BINARY}"
echo "Size: $(du -h "$BINARY" | cut -f1)"

if [ "${1:-}" = "--install" ]; then
    INSTALL_DIR="${HOME}/.local/bin"
    mkdir -p "$INSTALL_DIR"
    cp "$BINARY" "${INSTALL_DIR}/unsubscribe"
    echo "Installed to ${INSTALL_DIR}/unsubscribe"
fi
