<p align="center">
  <img src="docs/assets/logo.svg" width="100%" alt="DiskPass — encrypted physical media archive"/>
</p>

**Documentation / Languages:** **English** · [Русский](docs/README.ru.md) · [Українська](docs/README.uk.md) · [Беларуская](docs/README.be.md) · [Қазақша](docs/README.kk.md) · [简体中文](docs/README.zh_CN.md) · [繁體中文（台灣）](docs/README.zh_TW.md) · [日本語](docs/README.ja.md) · [한국어](docs/README.ko.md) · [Français](docs/README.fr.md) · [Deutsch](docs/README.de.md) · [Español](docs/README.es.md)

# Diskpass

A generator of cryptographically protected physical tags for storage media.

Diskpass addresses a specific problem: you have an archive containing dozens of physical devices (HDDs, SSDs, LTO tapes, flash drives) and need to label each one without printing its contents, encryption method or password on the device.

The application generates a short tag such as `HK-T1R-BAM-LK-XYQ` for attachment to the media. With access to the encrypted database, its owner can find the corresponding drive type, capacity, description, encryption method and stored password. To an outside observer, the tag is a sequence of compact codes.

**Contents:** [Features](#key-features) · [Tag format](#tag-format) · [Database encryption](#database-encryption) · [Steganography](#steganography) · [Architecture](#architecture-and-implementation) · [Build](#build-and-installation) · [Threat model](#threat-model-and-security-scope)

## Key Features

- **Physical tag generation:** five components describe the device type, capacity, content label, encryption method and per-device salt.
- **Per-database schema:** the five components are randomly permuted at initialization (`5! = 120` possible orders), and that order is retained for the database.
- **Drive registration:** choose a connected device or enter one manually, with capacity options matched to its type and an interface for looking up the internal codes.
- **Protected storage:** the local `.dpdb` file stores tags, passwords, notes and device mappings using OpenPGP/GPGME and XChaCha20-Poly1305.
- **Archive search:** file indexes and directory snapshots support searches even when the device is disconnected; SMART snapshots are available with `smartctl`.
- **Access management:** GnuPG/pinentry handles private-key access; the application also provides time-based locking and clipboard clearing.
- **Extensions:** native plugins, including a Bluetooth LE label-printing module for the Katasymbol E11; the user interface is based on GTK3 for Xorg and Wayland.

## Tag Format

A tag comprises five hyphen-separated blocks. Their order is determined by a schema generated separately for each database.

<img src="docs/diagrams/tags.svg" width="100%" alt="Diskpass physical tag generation">

| # | Component | Meaning |
|---|---|---|
| 1 | `type` | Physical media type: HDD, SSD, USB, LTO, etc. |
| 2 | `size` | Media capacity represented by an internal code |
| 3 | `content_tag` | User-defined content label |
| 4 | `cipher` | Encryption method used on the media |
| 5 | `dsalt` | Random value assigned to the individual medium |

Each block follows the structure **`[CODE][CHECK_CHARACTER]`**. The final character is computed using **BLAKE2b** and the database secrets `noise_key` and `salt`; it is a check character rather than encryption of the block.

### Tag Generation Algorithm

1. **Database schema:** select a random permutation of five components when initializing the database and retain it for subsequent records.
2. **Data encoding:** convert the drive type, capacity, content label and encryption method into short internal codes using Diskpass dictionaries.
3. **Disk salt:** generate a separate random `dsalt` for each registered device.
4. **Check characters:** compute a single-character suffix for each coded block using the database's secret parameters.
5. **Assembly:** arrange the blocks according to the schema and join them with hyphens.

### Example

Tag `HK-T1R-BAM-LK-XYQ` for the order `type-size-content-cipher-dsalt`:

| Block | Code | Check character | Interpretation |
|:---:|:---:|:---:|---|
| `HK` | `H` | `K` | Media type: **HDD** |
| `T1R` | `T1` | `R` | Capacity: **1 TB** |
| `BAM` | `BA` | `M` | User-defined label: **Backup** |
| `LK` | `L` | `K` | Encryption method: **LUKS** |
| `XYQ` | `XY` | `Q` | Per-disk salt: **XY** |

### Encoding Schemes

**Media type (`type`):** one character. `H` — HDD, `S` — SSD, `U` — USB, `M` — M.2, `D` — SD, `C` — CF, `O` — OPTICAL, `X` — OTHER. LTO generations use digits `1`–`9`, with capacity options matched to each tape generation.

**Cipher (`cipher`):** `L` — LUKS, `V` — VeraCrypt, `B` — BitLocker, `7` — 7-Zip, `A` — Age, `G` — GPG, `N` — NONE.

Tags provide compact identifiers. Full descriptions, passwords and their mappings are stored in the separately encrypted database.

## Database Encryption

<img src="docs/diagrams/encryption.svg" width="100%" alt="DPENV5 encrypted database pipeline">

The `.dpdb` file stores device records, tags, passwords, notes, schema parameters and saved file indexes. When saving, Diskpass serializes the data and stores it in an encrypted **DPENV5 binary container**.

1. **Serialization:** `cJSON` is used to assemble the record structure.
2. **Symmetric encryption:** **XChaCha20-Poly1305** provides authenticated encryption (AEAD). The outer header is covered by AAD, with a unique nonce and authenticated padding.
3. **Key envelope:** **OpenPGP/GPGME** protects the key material and delegates private-key operations to GnuPG and pinentry. Compatible GnuPG engines can support the **ML-KEM/Kyber** key profile.
4. **Signature:** DPENV5 binds its OpenPGP signature to a **BLAKE2b-256 hash of the padded plaintext**. Opening includes verification of the signature, recipient policy, metadata and AEAD authentication.
5. **Version integrity:** version chaining and local *anti-rollback* state help detect restoration of an obsolete database snapshot.

**Argon2id** is used separately to hash the calculator-mode access code and protect local settings. It does not replace OpenPGP or XChaCha20-Poly1305 for `.dpdb` storage.

Using ML-KEM requires **GPGME ≥ 1.24.1** and a compatible GnuPG engine. Changing the OpenPGP key re-encrypts the current database; older backups remain tied to the previous key.

## Steganography

<img src="docs/diagrams/steganography.svg" width="100%" alt="Diskpass steganographic database storage">

Diskpass can embed an **already encrypted `.dpdb`** into a media file. It identifies the carrier type, checks capacity, embeds the payload in a separate file, and can later extract the encrypted database for normal OpenPGP-based unlocking.

| Carrier | Embedding technique |
|---|---|
| PNG, BMP, TIFF, lossless WebP and certain other images | Least significant bits of RGB pixels (LSB) |
| JPEG | Parity of selected quantized AC DCT coefficients |
| WAV (integer PCM) | One least significant bit per PCM sample |
| MP3 | Existing APIC cover art (ID3v2); audio frames remain unchanged |
| FLAC | Embedded PICTURE artwork; audio frames remain unchanged |

Newer carrier formats derive a **bootstrap seed** from stable carrier data. This permits locating and extracting the encrypted container before the database itself is unlocked; the OpenPGP key is still needed to read the contents.

When editing a database opened directly from a stego carrier, Diskpass uses a temporary encrypted `.dpdb` and embeds the updated copy after a successful save. Capacity is controlled by `DISKPASS_STEGO_MAX_PERCENT`: **1–40** is allowed, with **20%** as the default.

## Architecture and Implementation

Diskpass is written in **C11** and uses:

- **libsodium** for random generation, protected allocations and clearing sensitive buffers;
- **GPGME / GnuPG** for OpenPGP key management, key envelopes and signatures;
- **cJSON** for database serialization;
- **GTK3 / GLib** for the interface and system integration;
- **libjpeg / libwebp** for image processing in the steganography subsystem.

**Diskpass Plugin ABI v1** provides an extension interface for actions in the application menu. For example, the **Katasymbol E11** plugin uses BlueZ/Bluetooth LE to print labels. Native `.so` modules are loaded after unlocking and explicitly confirming trust.

## Build and Installation

**Debian / Ubuntu — dependencies:**

```bash
sudo apt install build-essential pkg-config libgtk-3-dev libglib2.0-dev \
  libgpgme-dev libsodium-dev libcjson-dev libjpeg-dev libwebp-dev
```

**Build without installing:**

```bash
git clone https://github.com/Sergei768/Diskpass.git
cd Diskpass
make -j2
./diskpass
```

**Install for the current user:**

```bash
# Additional tools may be needed by the installer and printer plugin:
sudo apt install libpango1.0-dev liblzma-dev imagemagick bluez fonts-dejavu-core
./build.sh
```

Run `build.sh` **as your regular user**, not with `sudo`. `make debug` and `make clean` are available. The separate `diskpass-package.sh` script supports DEB, RPM, Arch, AppImage, tar and BSD artifacts when suitable tools are installed.

## Threat Model and Security Scope

Diskpass is designed for archives of physical media carrying compact labels. The **considered adversary** is a passive observer who has access to the media and tags but not the database secrets or private OpenPGP key. They can compare tags, inspect repetitions and perform structural analysis.

**Security properties:** short internal codes and a per-database component order reduce directly readable information on labels. A BLAKE2b-derived check character can be verified using the database parameters. **Passwords and detailed descriptions remain confidential through `.dpdb` encryption**, not through the tag alone.

**Boundaries:**

- A physical tag contains pseudonymized metadata, **not ciphertext**; repeated values and block lengths may reveal patterns to frequency analysis.
- Diskpass does not encrypt the contents of HDDs, SSDs or tapes; that requires separate software such as LUKS or VeraCrypt.
- GnuPG/pinentry manages key access. Whether a passphrase is requested again on every opening depends on agent configuration and caching.
- Steganography is not a guarantee of undetectability: LSB and DCT embedding may leave statistical traces, and media conversion may damage the payload.
- A compromised workstation or private OpenPGP key is beyond the application's protection; native plugins execute without a sandbox.
- DPENV5 may expose OpenPGP recipient IDs. Older DPENV4 and current DPENV5 databases have different signature-verification and migration properties.

**Licensing:** Diskpass's original code is BSD-3-Clause (`LICENSE`); the combined application includes a GPL-3.0-or-later calculator (`calculator/COPYING`). Redistribution must comply with the applicable license obligations.

