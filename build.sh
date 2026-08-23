#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
SRC_FILE="${1:-$SCRIPT_DIR/diskpass.c}"
ICON_FILE="${2:-$SCRIPT_DIR/disk-icon.png}"

APP_NAME="diskpass"
BIN_DIR="$HOME/.local/bin"
DATA_DIR="$HOME/.local/share/$APP_NAME"
ICON_THEME_DIR="$HOME/.local/share/icons/hicolor"
DESKTOP_DIR="$HOME/.local/share/applications"

log() { printf '\033[1;34m[*]\033[0m %s\n' "$1"; }
ok() { printf '\033[1;32m[ok]\033[0m %s\n' "$1"; }
err() { printf '\033[1;31m[!]\033[0m %s\n' "$1" >&2; }

if [[ ! -f "$SRC_FILE" ]]; then
    err "Source file not found: $SRC_FILE"
    exit 1
fi
if [[ ! -f "$ICON_FILE" ]]; then
    err "Icon file not found: $ICON_FILE"
    exit 1
fi

for tool in gcc pkg-config; do
    if ! command -v "$tool" &>/dev/null; then
        err "'$tool' not found"
        exit 1
    fi
done

check_pkg() {
    if ! pkg-config --exists "$1"; then
        err "Dev package for '$1' not found"
        return 1
    fi
}

missing=0
check_pkg gtk+-3.0 || missing=1
check_pkg gpgme || missing=1
check_pkg libsodium || missing=1

CJSON_CFLAGS=""
CJSON_LIBS="-lcjson"
if pkg-config --exists libcjson 2>/dev/null; then
    CJSON_CFLAGS="$(pkg-config --cflags libcjson)"
    CJSON_LIBS="$(pkg-config --libs libcjson)"
elif [[ ! -f /usr/include/cjson/cJSON.h && ! -f /usr/local/include/cjson/cJSON.h ]]; then
    err "Header cjson/cJSON.h not found"
    missing=1
fi

if [[ "$missing" -ne 0 ]]; then
    err "Install missing dev packages and retry"
    exit 1
fi
ok "All dependencies are in place"

log "Compiling diskpass..."
BUILD_DIR="$(mktemp -d)"
trap 'rm -rf "$BUILD_DIR"' EXIT

gcc -O2 -Wall -Wextra -Wformat -Wformat-security \
    -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
    -fPIE -pie -fvisibility=hidden \
    -Werror=implicit-function-declaration \
    -Werror=incompatible-pointer-types \
    $(pkg-config --cflags gtk+-3.0 gpgme libsodium) $CJSON_CFLAGS \
    -o "$BUILD_DIR/$APP_NAME" "$SRC_FILE" \
    $(pkg-config --libs gtk+-3.0 gpgme libsodium) $CJSON_LIBS \
    -Wl,-z,relro,-z,now -Wl,-z,noexecstack

ok "Build completed"

log "Installing binary..."
mkdir -p "$BIN_DIR"
install -m 0755 "$BUILD_DIR/$APP_NAME" "$BIN_DIR/$APP_NAME"

log "Installing icon..."
mkdir -p "$DATA_DIR"
install -m 0644 "$ICON_FILE" "$DATA_DIR/disk-icon.png"

if command -v convert &>/dev/null; then
    for size in 16 24 32 48 64 128 256 512; do
        dir="$ICON_THEME_DIR/${size}x${size}/apps"
        mkdir -p "$dir"
        convert "$ICON_FILE" -resize "${size}x${size}" "$dir/$APP_NAME.png"
    done
    ok "Icon installed for multiple sizes"
else
    dir="$ICON_THEME_DIR/256x256/apps"
    mkdir -p "$dir"
    install -m 0644 "$ICON_FILE" "$dir/$APP_NAME.png"
    log "ImageMagick not found — icon installed at 256x256 only"
fi

log "Registering application..."
mkdir -p "$DESKTOP_DIR"
cat > "$DESKTOP_DIR/$APP_NAME.desktop" <<EOF
[Desktop Entry]
Name=DiskPass
Comment=Secure password storage for disks
Exec=$BIN_DIR/$APP_NAME %F
Icon=$APP_NAME
Type=Application
Terminal=false
Categories=System;Security;Utility;
MimeType=application/x-diskpass;
EOF

if command -v update-desktop-database &>/dev/null; then
    update-desktop-database "$DESKTOP_DIR" 2>/dev/null || true
fi
if command -v gtk-update-icon-cache &>/dev/null; then
    gtk-update-icon-cache -f -t "$ICON_THEME_DIR" 2>/dev/null || true
fi

ok "Done!"
echo "DiskPass installed: $BIN_DIR/$APP_NAME"
