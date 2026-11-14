# Katasymbol E11 Native C plugin for DiskPass 2.4

The plugin is implemented entirely in C. It uses BlueZ/GDBus for BLE, GTK/Pango/Cairo for UI and text rendering, and liblzma for E11 print data.

Features:

- automatic E11 discovery and confirmed MAC persistence;
- printing arbitrary text;
- printing the currently selected DiskPass disk label;
- background printing with status in the DiskPass top bar;
- persistent font size, tape width, label length, density, speed and auto-detect settings;
- host-provided localization, including custom DiskPass language packs;
- label text itself is never persisted.

DiskPass host app_version 5 enables host localization. Disk-label access and top-bar status require app_version 4 or newer.

## Dependencies

```bash
sudo apt install build-essential pkg-config libgtk-3-dev libglib2.0-dev liblzma-dev bluez fonts-dejavu-core
```

## Build and install

```bash
make clean
make
make install
```

or:

```bash
./install.sh
```

Plugin path:

```text
~/.diskpass/plugins/e11_printer.so
```

Settings path:

```text
~/.diskpass/e11-printer.conf
```

Only trusted native plugins should be installed because `.so` plugins run inside the DiskPass process.


### Explicit plugin loading

Open and unlock a database, then select Plugins → Загрузить доверенные плагины… and confirm trust. Installation alone does not load the plugin. The action appears immediately after loading. Native plugins are not sandboxed and remain loaded until exit. Restart before loading an updated binary.

The installer works from any directory and requires Python 3. It uses the absolute DISKPASS_PRIVATE_DIR override, otherwise ~/.diskpass; both the base and plugins directories must be owned by the current user with private permissions (0700).
