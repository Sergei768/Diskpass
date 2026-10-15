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
