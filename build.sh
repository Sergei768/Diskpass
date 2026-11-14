#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
APP_SRC_DIR="$SCRIPT_DIR"
PLUGIN_SRC_DIR="$SCRIPT_DIR/plugin/Katasymbol E11"
ICON_FILE="$SCRIPT_DIR/diskpass-icon.svg"

APP_NAME="diskpass"
BIN_DIR="$HOME/.local/bin"
DOT_DIR="$HOME/.diskpass"
PLUGIN_DIR="$DOT_DIR/plugins"
LANG_DIR="$DOT_DIR/lang"
CACHE_DIR="$DOT_DIR/cache"
ICON_THEME_DIR="$HOME/.local/share/icons/hicolor"
DESKTOP_DIR="$HOME/.local/share/applications"

log() { printf '\033[1;34m[*]\033[0m %s\n' "$1"; }
ok()  { printf '\033[1;32m[ok]\033[0m %s\n' "$1"; }
err() { printf '\033[1;31m[!]\033[0m %s\n' "$1" >&2; }

if [[ ${EUID:-$(id -u)} -eq 0 ]]; then
    err "Do not run this installer with sudo/root."
    err "Run it as your normal user: ./build.sh"
    exit 1
fi

required_app_files=(
    "$APP_SRC_DIR/diskpass_main.c"
    "$APP_SRC_DIR/diskpass_core.c"
    "$APP_SRC_DIR/diskpass_stego_lossy.c"
    "$APP_SRC_DIR/diskpass_crypto_tags.c"
    "$APP_SRC_DIR/diskpass_i18n.c"
    "$APP_SRC_DIR/diskpass_ui.c"
    "$APP_SRC_DIR/diskpass.h"
    "$APP_SRC_DIR/calculator/diskpass_icon.c"
    "$APP_SRC_DIR/calculator/diskpass_icon.h"
    "$APP_SRC_DIR/calculator/diskpass_calculator.c"
    "$APP_SRC_DIR/calculator/diskpass_calculator.h"
    "$APP_SRC_DIR/calculator/calculator-widget.c"
    "$APP_SRC_DIR/calculator/calculator-widget.h"
    "$APP_SRC_DIR/calculator/calc-eval.c"
    "$APP_SRC_DIR/calculator/calc-eval.h"
    "$APP_SRC_DIR/calculator/calc-units.c"
    "$APP_SRC_DIR/calculator/calc-units.h"
    "$APP_SRC_DIR/calculator/calculator-css.h"
)

for f in "${required_app_files[@]}"; do
    if [[ ! -f "$f" ]]; then
        err "DiskPass source file not found: $f"
        exit 1
    fi
done

if [[ ! -f "$PLUGIN_SRC_DIR/e11_plugin.c" ]]; then
    err "E11 plugin source not found: $PLUGIN_SRC_DIR/e11_plugin.c"
    exit 1
fi

if [[ ! -f "$PLUGIN_SRC_DIR/diskpass.h" ]]; then
    err "E11 plugin header not found: $PLUGIN_SRC_DIR/diskpass.h"
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
for pkg in gtk+-3.0 gio-2.0 gmodule-2.0 gpgme libsodium libcjson libjpeg libwebp; do
    check_pkg "$pkg" || missing=1
done
for pkg in pangocairo liblzma; do
    check_pkg "$pkg" || missing=1
done

if [[ "$missing" -ne 0 ]]; then
    err "Install missing dev packages and retry."
    echo
    echo "Debian/Ubuntu:"
    echo "  sudo apt install build-essential pkg-config libgtk-3-dev libglib2.0-dev libgpgme-dev libsodium-dev libcjson-dev libjpeg-dev libwebp-dev libpango1.0-dev liblzma-dev imagemagick bluez fonts-dejavu-core"
    exit 1
fi
if ! pkg-config --atleast-version=1.24.1 gpgme; then
    echo "ERROR: gpgme >= 1.24.1 is required (ML-KEM/Kyber support); found $(pkg-config --modversion gpgme)" >&2
    exit 1
fi
ok "All dependencies are in place"

if ! cmp -s "$APP_SRC_DIR/diskpass.h" "$PLUGIN_SRC_DIR/diskpass.h"; then
    err "diskpass.h in the plugin differs from the application header."
    err "Copy the current header before building:"
    err "  cp '$APP_SRC_DIR/diskpass.h' '$PLUGIN_SRC_DIR/diskpass.h'"
    exit 1
fi
ok "Plugin ABI header matches"

BUILD_DIR="$(mktemp -d)"
trap 'rm -rf "$BUILD_DIR"' EXIT

HARDENING_FLAGS=()
for flag in -fcf-protection=full -fstack-clash-protection; do
    if gcc -Werror "$flag" -x c -c /dev/null -o "$BUILD_DIR/flag-probe.o" >/dev/null 2>&1; then
        HARDENING_FLAGS+=("$flag")
    fi
done
rm -f "$BUILD_DIR/flag-probe.o"

log "Compiling DiskPass..."


gcc -std=c11 -O2 -Wall -Wextra -Wpedantic -Werror -Wformat=2 -Wformat-security -Werror=format \
    -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
    -fPIE -fvisibility=hidden \
    "${HARDENING_FLAGS[@]}" \
    -Werror=implicit-function-declaration \
    -Werror=incompatible-pointer-types \
    $(pkg-config --cflags gtk+-3.0 gio-2.0 gmodule-2.0 gpgme libsodium libcjson libjpeg libwebp) \
    -o "$BUILD_DIR/$APP_NAME" \
    "$APP_SRC_DIR/diskpass_main.c" \
    "$APP_SRC_DIR/calculator/diskpass_icon.c" \
    "$APP_SRC_DIR/calculator/diskpass_calculator.c" \
    "$APP_SRC_DIR/calculator/calculator-widget.c" \
    "$APP_SRC_DIR/calculator/calc-eval.c" \
    "$APP_SRC_DIR/calculator/calc-units.c" \
    $(pkg-config --libs gtk+-3.0 gio-2.0 gmodule-2.0 gpgme libsodium libcjson libjpeg libwebp) \
    -lm \
    -Wl,-z,relro,-z,now -Wl,-z,noexecstack -pie
ok "DiskPass build completed"

log "Compiling Katasymbol E11 plugin..."

gcc -std=c11 -O2 -Wall -Wextra -Wpedantic -Werror -Wformat=2 -Wformat-security -Werror=format \
    -fPIC -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
    -fvisibility=hidden "${HARDENING_FLAGS[@]}" \
    -Werror=implicit-function-declaration \
    -Werror=incompatible-pointer-types \
    -I"$APP_SRC_DIR" \
    $(pkg-config --cflags gtk+-3.0 gio-2.0 gmodule-2.0 pangocairo liblzma) \
    -shared "$PLUGIN_SRC_DIR/e11_plugin.c" \
    -o "$BUILD_DIR/e11_printer.so" \
    $(pkg-config --libs gtk+-3.0 gio-2.0 gmodule-2.0 pangocairo liblzma) \
    -Wl,-z,relro,-z,now -Wl,-z,noexecstack
ok "E11 plugin build completed"


for dir in "$DOT_DIR" "$PLUGIN_DIR" "$LANG_DIR" "$CACHE_DIR"; do
    if [[ -L "$dir" || ( -e "$dir" && ( ! -d "$dir" || ! -O "$dir" ) ) ]]; then
        err "Private path must be a real directory owned by you: $dir"
        exit 1
    fi
done
for file in "$DOT_DIR/diskpass-icon.svg" "$PLUGIN_DIR/e11_printer.so"; do
    if [[ -L "$file" || ( -e "$file" && ( ! -f "$file" || ! -O "$file" ) ) ]]; then
        err "Unsafe existing private file: $file"
        exit 1
    fi
done

log "Creating user directories..."
install -d -m 0700 "$DOT_DIR" "$PLUGIN_DIR" "$LANG_DIR" "$CACHE_DIR"
install -d -m 0755 "$BIN_DIR" "$DESKTOP_DIR"

log "Installing DiskPass..."
install -m 0755 "$BUILD_DIR/$APP_NAME" "$BIN_DIR/$APP_NAME"

log "E11 plugin is compiled but NOT installed:"
log "the host loader is disabled (diskpass_main.c: native plugins"
log "are disabled). Install manually only after an authenticated"
log "enable flow exists in the app."

plugin_uid="$(id -u)"
if [[ -e "$PLUGIN_DIR/e11_printer.so" || -L "$PLUGIN_DIR/e11_printer.so" ]]; then
    plugin_uid="$(stat -c '%u' "$PLUGIN_DIR/e11_printer.so")"
    if [[ "$plugin_uid" != "$(id -u)" ]]; then
        err "Existing plugin has the wrong owner."
        exit 1
    fi
    if [[ -L "$PLUGIN_DIR/e11_printer.so" ]]; then
        err "Existing plugin unexpectedly became a symlink."
        exit 1
    fi
    ok "Existing plugin ownership and file type are safe"
fi

log "Installing scalable application icon..."
install -d -m 0755 "$ICON_THEME_DIR/scalable/apps"
install -m 0644 "$ICON_FILE" "$ICON_THEME_DIR/scalable/apps/$APP_NAME.svg"
install -m 0644 "$ICON_FILE" "$DOT_DIR/diskpass-icon.svg"

desktop_exec_path(){
    local value="$1"
    [[ "$value" != *$'\n'* && "$value" != *$'\r'* ]] || { err "Newlines are not supported in the executable path"; return 1; }
    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    value="${value//\$/\\\$}"
    value="${value//\`/\\\`}"
    value="${value//%/%%}"

    value="${value//\\/\\\\}"
    printf '"%s"' "$value"
}
DESKTOP_EXEC="$(desktop_exec_path "$BIN_DIR/$APP_NAME")"
log "Registering desktop application..."
cat > "$DESKTOP_DIR/$APP_NAME.desktop" <<EOF_DESKTOP
[Desktop Entry]
Name=DiskPass
Comment=Secure disk password and label manager
Exec=$DESKTOP_EXEC
Icon=$APP_NAME
Type=Application
Terminal=false
Categories=System;Security;Utility;
StartupNotify=true
EOF_DESKTOP
chmod 0644 "$DESKTOP_DIR/$APP_NAME.desktop"

if command -v update-desktop-database &>/dev/null; then
    update-desktop-database "$DESKTOP_DIR" 2>/dev/null || true
fi
if command -v gtk-update-icon-cache &>/dev/null; then
    gtk-update-icon-cache -f -t "$ICON_THEME_DIR" 2>/dev/null || true
fi

if ! command -v bluetoothctl &>/dev/null; then
    log "bluetoothctl not found; install BlueZ if you want to use the E11 printer"
fi

ok "Installation completed"
printf '\nDiskPass: %s\n' "$BIN_DIR/$APP_NAME"
printf 'Plugins:  %s\n' "$PLUGIN_DIR"
printf 'E11:      %s\n' "$PLUGIN_DIR/e11_printer.so"
printf 'Languages:%s\n' "$LANG_DIR"
