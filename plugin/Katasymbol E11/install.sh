#!/bin/sh
set -eu

command -v gcc >/dev/null 2>&1 || { echo "gcc not found" >&2; exit 1; }
command -v pkg-config >/dev/null 2>&1 || { echo "pkg-config not found" >&2; exit 1; }

PKGS="gtk+-3.0 gio-2.0 gmodule-2.0 pangocairo liblzma"
if ! pkg-config --exists $PKGS; then
    echo "Missing C development dependencies." >&2
    echo "Debian/Ubuntu:" >&2
    echo "  sudo apt install build-essential pkg-config libgtk-3-dev libglib2.0-dev liblzma-dev bluez fonts-dejavu-core" >&2
    exit 1
fi

make clean
make
make install

echo "Installed: $HOME/.diskpass/plugins/e11_printer.so"
echo "No Python packages are required."
echo "Restart DiskPass and open Plugins -> Katasymbol E11 Native C Printer."
