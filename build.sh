#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
APP_SRC_DIR="${1:-$SCRIPT_DIR/diskpass}"
PLUGIN_SRC_DIR="${2:-$SCRIPT_DIR/e11_plugin}"
ICON_FILE="${3:-$SCRIPT_DIR/disk-icon.png}"

APP_NAME="diskpass"
PLUGIN_NAME="e11_printer.so"
BIN_DIR="$HOME/.local/bin"
DOT_DIR="$HOME/.diskpass"
PLUGIN_DIR="$DOT_DIR/plugins"
LANG_DIR="$DOT_DIR/lang"
DATA_DIR="$HOME/.local/share/$APP_NAME"
ICON_THEME_DIR="$HOME/.local/share/icons/hicolor"
DESKTOP_DIR="$HOME/.local/share/applications"

log() { printf '\033[1;34m[*]\033[0m %s\n' "$1"; }
ok() { printf '\033[1;32m[ok]\033[0m %s\n' "$1"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$1" >&2; }
err() { printf '\033[1;31m[!]\033[0m %s\n' "$1" >&2; }

if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
    err "Do not run this installer with sudo/root. DiskPass plugins must belong to your user."
    exit 1
fi

for path in \
    "$APP_SRC_DIR/diskpass_main.c" \
    "$APP_SRC_DIR/diskpass_core.c" \
    "$APP_SRC_DIR/diskpass_crypto_tags.c" \
    "$APP_SRC_DIR/diskpass_i18n.c" \
    "$APP_SRC_DIR/diskpass_ui.c" \
    "$APP_SRC_DIR/diskpass.h" \
    "$APP_SRC_DIR/Makefile"; do
    if [[ ! -f "$path" ]]; then
        err "DiskPass source file not found: $path"
        exit 1
    fi
done

for path in \
    "$PLUGIN_SRC_DIR/e11_plugin.c" \
    "$PLUGIN_SRC_DIR/diskpass.h" \
    "$PLUGIN_SRC_DIR/Makefile"; do
    if [[ ! -f "$path" ]]; then
        err "E11 plugin source file not found: $path"
        exit 1
    fi
done

if [[ ! -f "$ICON_FILE" ]]; then
    err "Icon file not found: $ICON_FILE"
    err "Place the icon at '$SCRIPT_DIR/disk-icon.png' or pass it as the third argument."
    exit 1
fi

for tool in gcc make pkg-config install; do
    if ! command -v "$tool" &>/dev/null; then
        err "Required tool not found: $tool"
        exit 1
    fi
done

APP_PKGS=(gtk+-3.0 gio-2.0 gmodule-2.0 gpgme libsodium libcjson)
PLUGIN_PKGS=(gtk+-3.0 gio-2.0 gmodule-2.0 pangocairo liblzma)
missing=0

for pkg in "${APP_PKGS[@]}" "${PLUGIN_PKGS[@]}"; do
    if ! pkg-config --exists "$pkg" 2>/dev/null; then
        err "Development package not found for pkg-config module: $pkg"
        missing=1
    fi
done

if [[ "$missing" -ne 0 ]]; then
    printf '\nDebian/Ubuntu packages usually required:\n' >&2
    printf '  sudo apt install build-essential pkg-config libgtk-3-dev libglib2.0-dev libgpgme-dev libsodium-dev libcjson-dev libpango1.0-dev liblzma-dev bluez fonts-dejavu-core\n' >&2
    exit 1
fi

if ! cmp -s "$APP_SRC_DIR/diskpass.h" "$PLUGIN_SRC_DIR/diskpass.h"; then
    err "diskpass.h differs between the application and E11 plugin."
    err "Use matching sources so the Plugin ABI is identical."
    exit 1
fi

ok "Dependencies and Plugin ABI headers are valid"

log "Building DiskPass..."
make -C "$APP_SRC_DIR" clean
make -C "$APP_SRC_DIR" all
[[ -x "$APP_SRC_DIR/diskpass" ]] || { err "DiskPass binary was not produced"; exit 1; }
ok "DiskPass build completed"

log "Building E11 plugin..."
make -C "$PLUGIN_SRC_DIR" clean
make -C "$PLUGIN_SRC_DIR" all
[[ -f "$PLUGIN_SRC_DIR/$PLUGIN_NAME" ]] || { err "E11 plugin was not produced"; exit 1; }
ok "E11 plugin build completed"

log "Preparing user directories..."
install -d -m 0700 "$DOT_DIR"
install -d -m 0700 "$PLUGIN_DIR"
install -d -m 0700 "$LANG_DIR"
install -d -m 0755 "$BIN_DIR"
install -d -m 0755 "$DATA_DIR"
install -d -m 0755 "$DESKTOP_DIR"

log "Installing DiskPass..."
install -m 0755 "$APP_SRC_DIR/diskpass" "$BIN_DIR/$APP_NAME"

log "Installing E11 plugin..."
install -m 0755 "$PLUGIN_SRC_DIR/$PLUGIN_NAME" "$PLUGIN_DIR/$PLUGIN_NAME"

owner_uid="$(stat -c '%u' "$PLUGIN_DIR/$PLUGIN_NAME")"
current_uid="$(id -u)"
plugin_mode="$(stat -c '%a' "$PLUGIN_DIR/$PLUGIN_NAME")"
if [[ "$owner_uid" != "$current_uid" ]]; then
    err "Installed plugin has the wrong owner"
    exit 1
fi
if (( (8#$plugin_mode & 0022) != 0 )); then
    err "Installed plugin is writable by group/others and DiskPass will reject it"
    exit 1
fi
ok "Plugin ownership and permissions are safe"

log "Installing application icon..."
install -m 0644 "$ICON_FILE" "$DOT_DIR/disk-icon.png"
install -m 0644 "$ICON_FILE" "$DATA_DIR/disk-icon.png"

if command -v magick &>/dev/null; then
    for size in 16 24 32 48 64 128 256 512; do
        dir="$ICON_THEME_DIR/${size}x${size}/apps"
        install -d -m 0755 "$dir"
        magick "$ICON_FILE" -resize "${size}x${size}" "$dir/$APP_NAME.png"
        chmod 0644 "$dir/$APP_NAME.png"
    done
    ok "Icon installed in multiple sizes with ImageMagick"
elif command -v convert &>/dev/null; then
    for size in 16 24 32 48 64 128 256 512; do
        dir="$ICON_THEME_DIR/${size}x${size}/apps"
        install -d -m 0755 "$dir"
        convert "$ICON_FILE" -resize "${size}x${size}" "$dir/$APP_NAME.png"
        chmod 0644 "$dir/$APP_NAME.png"
    done
    ok "Icon installed in multiple sizes with ImageMagick"
else
    dir="$ICON_THEME_DIR/256x256/apps"
    install -d -m 0755 "$dir"
    install -m 0644 "$ICON_FILE" "$dir/$APP_NAME.png"
    warn "ImageMagick not found; only the original icon was installed into the 256x256 theme directory"
fi

if [[ -d "$SCRIPT_DIR/docs" ]]; then
    rm -rf "$DATA_DIR/docs"
    cp -a "$SCRIPT_DIR/docs" "$DATA_DIR/docs"
    find "$DATA_DIR/docs" -type d -exec chmod 0755 {} +
    find "$DATA_DIR/docs" -type f -exec chmod 0644 {} +
fi

if [[ -f "$SCRIPT_DIR/examples/language-pack.example.ini" ]]; then
    install -m 0644 "$SCRIPT_DIR/examples/language-pack.example.ini" "$DATA_DIR/language-pack.example.ini"
fi

log "Registering desktop application..."
cat > "$DESKTOP_DIR/$APP_NAME.desktop" <<EOF_DESKTOP
[Desktop Entry]
Version=1.0
Type=Application
Name=DiskPass
Comment=Secure encrypted disk password and label manager
Exec=$BIN_DIR/$APP_NAME
Icon=$APP_NAME
Terminal=false
Categories=Utility;System;Security;
Keywords=Disk;Password;Encryption;OpenPGP;Security;
StartupNotify=true
EOF_DESKTOP
chmod 0644 "$DESKTOP_DIR/$APP_NAME.desktop"

if command -v update-desktop-database &>/dev/null; then
    update-desktop-database "$DESKTOP_DIR" 2>/dev/null || true
fi
if command -v gtk-update-icon-cache &>/dev/null; then
    gtk-update-icon-cache -f -t "$ICON_THEME_DIR" 2>/dev/null || true
fi

if command -v bluetoothctl &>/dev/null; then
    if command -v systemctl &>/dev/null && ! systemctl is-active --quiet bluetooth.service 2>/dev/null; then
        warn "BlueZ is installed, but bluetooth.service is not active; E11 auto-detection will not work until Bluetooth is enabled"
    fi
else
    warn "bluetoothctl was not found; install BlueZ if you want to use the E11 printer"
fi

printf '\n'
ok "DiskPass installation completed"
printf 'Binary:       %s\n' "$BIN_DIR/$APP_NAME"
printf 'Plugin:       %s\n' "$PLUGIN_DIR/$PLUGIN_NAME"
printf 'Config root:  %s\n' "$DOT_DIR"
printf 'Languages:    %s\n' "$LANG_DIR"
printf 'Desktop file: %s\n' "$DESKTOP_DIR/$APP_NAME.desktop"
printf '\nRun with:\n  %s\n' "$BIN_DIR/$APP_NAME"
