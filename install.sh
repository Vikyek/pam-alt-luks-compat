#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== Installing PAM Alternative Password & LUKS Compatibility Toolset ==="

if [ "$EUID" -ne 0 ]; then
    echo "Elevating privileges with sudo to run make install..."
    sudo make -C "${SCRIPT_DIR}" install
else
    make -C "${SCRIPT_DIR}" install
fi

echo "Installation complete!"
