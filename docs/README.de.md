<p align="center">
  <img src="assets/logo.svg" width="100%" alt="DiskPass — encrypted physical media archive"/>
</p>

**Documentation / Languages:** [English](../README.md) · [Русский](README.ru.md) · [Українська](README.uk.md) · [Беларуская](README.be.md) · [Қазақша](README.kk.md) · [简体中文](README.zh_CN.md) · [繁體中文（台灣）](README.zh_TW.md) · [日本語](README.ja.md) · [한국어](README.ko.md) · [Français](README.fr.md) · **Deutsch** · [Español](README.es.md)

# Diskpass

Generator physischer Kennzeichnungen für Speichermedien und lokale, verschlüsselte Datenbank zur Verwaltung eines Medienarchivs.

Mit Diskpass lassen sich große Bestände von HDDs, SSDs, USB-Sticks und LTO-Bändern verwalten, ohne Inhalt, Verschlüsselungsverfahren oder Passwörter auf die Medien zu schreiben. Die Anwendung erzeugt kurze Kennzeichnungen wie `HK-T1R-BAM-LK-XYQ`. Die zugehörigen Informationen liegen in einer verschlüsselten `.dpdb`-Datenbank; die Kennzeichnung selbst enthält nur kompakt kodierte Metadaten und kein Passwort.

## Funktionen

- **Physische Kennzeichnungen:** fünf Bestandteile beschreiben Medientyp, Kapazität, Inhaltsbezeichnung, Verschlüsselungsverfahren und einen zufälligen Wert je Medium.
- **Datenbankspezifisches Schema:** beim Anlegen der Datenbank wird die Reihenfolge der fünf Felder zufällig festgelegt (`5! = 120` mögliche Permutationen).
- **Archivverwaltung:** Medienregistrierung, Passwörter, Notizen, Verzeichnis-Snapshots, Dateisuche für nicht angeschlossene Medien und SMART-Messwerte.
- **Geschützte Speicherung:** DPENV5, XChaCha20-Poly1305 und OpenPGP/GPGME; für ML-KEM wird eine kompatible GnuPG-Version benötigt.
- **Weitere Funktionen:** Steganografie, automatische Sperre, Zwischenablagebereinigung, Rechnermodus und vertrauenswürdige native Plugins.

## Erzeugung physischer Kennzeichnungen

<img src="diagrams/tags.svg" width="100%" alt="Ablauf der Kennzeichnungserzeugung"/>

Eine Kennzeichnung besteht aus fünf durch Bindestriche getrennten Blöcken. Jeder Block hat das Format **`[CODE][PRÜFZEICHEN]`**. Das letzte Zeichen wird mit **BLAKE2b** aus dem Blockwert und den Datenbankparametern `noise_key` und `salt` berechnet.

| Bestandteil | Bedeutung |
|---|---|
| `type` | Medientyp: HDD, SSD, USB, LTO usw. |
| `size` | Kurzer interner Kapazitätscode |
| `content_tag` | Benutzerdefinierte Inhaltsbezeichnung |
| `cipher` | Verschlüsselungsverfahren des Mediums |
| `dsalt` | Zufallswert für das einzelne Medium |

**Ablauf:** Feldreihenfolge festlegen → Werte kodieren → `dsalt` erzeugen → Prüfzeichen je Block berechnen → Blöcke in Schema-Reihenfolge verbinden. In der Standardreihenfolge steht `HK-T1R-BAM-LK-XYQ` für HDD, 1 TB, Backup, LUKS und den Wert `XY`.

## Verschlüsselung der `.dpdb`-Datenbank

<img src="diagrams/encryption.svg" width="100%" alt="DPENV5-Datenbankverschlüsselung"/>

Diskpass speichert Passwörter, Zuordnungen der Kennzeichnungen, Notizen, Schemaparameter und Dateiindizes in einem lokalen **DPENV5-Binärcontainer**.

1. **Serialisierung:** `cJSON` strukturiert die Datensätze.
2. **Authentifizierte Verschlüsselung:** **XChaCha20-Poly1305** schützt die Daten; der äußere Header wird als AAD authentifiziert.
3. **Schlüsselumschlag:** **OpenPGP/GPGME** schützt das Schlüsselmaterial, GnuPG/pinentry verwaltet den Zugriff auf den privaten Schlüssel.
4. **Signatur und Hash:** Ein **BLAKE2b-256**-Digest bindet die DPENV5-Signatur an den aufgefüllten Klartext.
5. **Versionskontrolle:** Versionsverkettung und lokaler Anti-Rollback-Zustand helfen, ältere Datenbankkopien zu erkennen.

**ML-KEM/Kyber** setzt eine kompatible GnuPG/OpenPGP-Engine voraus. **Argon2id** wird separat für den Zugriffscode des Rechnermodus und den Schutz lokaler Einstellungen verwendet; es ersetzt nicht die `.dpdb`-Verschlüsselung.

## Steganografie

<img src="diagrams/steganography.svg" width="100%" alt="Einbetten und Extrahieren der verschlüsselten Datenbank"/>

Diskpass kann eine **bereits verschlüsselte `.dpdb`** in einer Mediendatei unterbringen. Nach dem Extrahieren ist weiterhin der passende private OpenPGP-Schlüssel erforderlich.

| Trägerformat | Einbettungsverfahren |
|---|---|
| PNG, BMP, TIFF, verlustfreies WebP und ähnliche Bilder | Niederwertige Bits der RGB-Pixel (LSB) |
| JPEG | Parität ausgewählter quantisierter AC-DCT-Koeffizienten |
| WAV mit ganzzahligem PCM | Ein niederwertiges Bit je Sample |
| MP3 | Bereits vorhandenes APIC-Cover in ID3v2 |
| FLAC | Eingebettetes PICTURE-Cover |

Neue Formate leiten einen *Bootstrap-Seed* aus stabilen Trägerdaten ab; damit ist der verschlüsselte Container schon vor dem Entsperren auffindbar. `DISKPASS_STEGO_MAX_PERCENT` begrenzt die Belegung auf standardmäßig **20 %** (zulässige Werte **1–40**).

## Architektur und Build

Diskpass ist in **C11** implementiert. **GTK3/GLib** stellt die Oberfläche bereit, **libsodium** verwaltet Zufallswerte und sensible Speicherbereiche, **GPGME/GnuPG** bietet OpenPGP, **cJSON** serialisiert Daten und **libjpeg/libwebp** verarbeitet Bilder. ABI-v1-Plugins ergänzen Menüfunktionen; das Katasymbol-E11-Modul druckt Etiketten über Bluetooth LE.

**Debian / Ubuntu:**

```bash
sudo apt install build-essential pkg-config libgtk-3-dev libglib2.0-dev \
  libgpgme-dev libsodium-dev libcjson-dev libjpeg-dev libwebp-dev

git clone https://github.com/Sergei768/Diskpass.git
cd Diskpass
make -j2
./diskpass
```

Für eine benutzerspezifische Installation `./build.sh` als normaler Benutzer ausführen (**nicht mit `sudo`**). `diskpass-package.sh` benötigt die jeweiligen Werkzeuge für die Paketformate.

## Bedrohungsmodell und Lizenzen

Angenommen wird ein passiver Beobachter, der Medien und Etiketten sehen kann, aber keine Datenbankgeheimnisse oder privaten OpenPGP-Schlüssel besitzt. Eine Kennzeichnung enthält **pseudonymisierte Metadaten, keinen Chiffretext**; wiederkehrende Werte und Blocklängen können Muster erkennen lassen. Diskpass verschlüsselt nicht die Dateien auf den Datenträgern, garantiert keine Unentdeckbarkeit der Steganografie und schützt keine kompromittierten Rechner oder privaten Schlüssel. Native Plugins laufen ohne Sandbox.

Der eigene Diskpass-Code steht unter **BSD-3-Clause**. Die kombinierte Anwendung enthält außerdem einen Rechner unter **GPL-3.0-or-later** (`calculator/COPYING`).
