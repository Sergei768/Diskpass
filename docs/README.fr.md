<p align="center">
  <img src="assets/logo.svg" width="100%" alt="DiskPass — encrypted physical media archive"/>
</p>

**Documentation / Languages:** [English](../README.md) · [Русский](README.ru.md) · [Українська](README.uk.md) · [Беларуская](README.be.md) · [Қазақша](README.kk.md) · [简体中文](README.zh_CN.md) · [繁體中文（台灣）](README.zh_TW.md) · [日本語](README.ja.md) · [한국어](README.ko.md) · **Français** · [Deutsch](README.de.md) · [Español](README.es.md)

# Diskpass

Générateur d'étiquettes physiques pour supports de stockage et gestionnaire d'archives avec base de données locale chiffrée.

Diskpass permet de cataloguer des dizaines de HDD, SSD, clés USB ou bandes LTO sans inscrire sur chaque support son contenu, sa méthode de chiffrement ou son mot de passe. Le programme génère une étiquette courte, par exemple `HK-T1R-BAM-LK-XYQ`, à associer au support. Les informations détaillées restent dans une base `.dpdb` chiffrée ; l'étiquette elle-même contient des métadonnées codées, pas de mot de passe.

## Fonctionnalités principales

- **Étiquettes physiques :** cinq composants décrivent le type de support, la capacité, le contenu, la méthode de chiffrement et un sel propre au support.
- **Schéma par base :** l'ordre des cinq composants est fixé aléatoirement à la création de la base (`5! = 120` permutations possibles).
- **Gestion de l'archive :** enregistrement des lecteurs, mots de passe, notes, instantanés de répertoires, recherche de fichiers sur des supports déconnectés et relevés SMART.
- **Stockage protégé :** conteneur DPENV5, XChaCha20-Poly1305 et OpenPGP/GPGME ; ML-KEM nécessite un moteur GnuPG compatible.
- **Fonctions complémentaires :** stéganographie, verrouillage automatique, effacement du presse-papiers, mode calculatrice et plugins natifs approuvés.

## Génération des étiquettes

<img src="diagrams/tags.svg" width="100%" alt="Schéma de génération d'une étiquette physique"/>

Une étiquette comporte cinq blocs séparés par des tirets. Chaque bloc suit le format **`[CODE][CARACTÈRE_DE_CONTRÔLE]`** ; le dernier caractère est calculé à l'aide de **BLAKE2b** et des paramètres `noise_key` et `salt` de la base.

| Composant | Description |
|---|---|
| `type` | Type de support : HDD, SSD, USB, LTO, etc. |
| `size` | Code interne court de la capacité |
| `content_tag` | Nom défini par l'utilisateur pour le contenu |
| `cipher` | Méthode de chiffrement du support |
| `dsalt` | Valeur aléatoire propre au support |

**Étapes :** tirer un ordre des cinq champs → encoder leurs valeurs → générer `dsalt` → calculer un caractère de contrôle par bloc → assembler les blocs. Dans l'ordre usuel, `HK-T1R-BAM-LK-XYQ` correspond à HDD, 1 To, Backup, LUKS et au sel `XY`.

## Chiffrement de la base `.dpdb`

<img src="diagrams/encryption.svg" width="100%" alt="Chaîne de chiffrement DPENV5"/>

Diskpass conserve les mots de passe, associations d'étiquettes, notes, paramètres du schéma et index de fichiers dans un **conteneur binaire DPENV5** local.

1. **Sérialisation :** `cJSON` construit les enregistrements.
2. **Chiffrement authentifié :** **XChaCha20-Poly1305** protège les données ; l'en-tête externe est inclus dans les données associées (AAD).
3. **Enveloppe de clé :** **OpenPGP/GPGME** protège les clés, tandis que GnuPG/pinentry gère l'accès à la clé privée.
4. **Signature et empreinte :** un condensat **BLAKE2b-256** lie la signature DPENV5 au texte en clair complété par du remplissage.
5. **Contrôle des versions :** la chaîne de générations et l'état anti-rollback local aident à détecter une ancienne copie de la base.

**ML-KEM/Kyber** requiert un moteur GnuPG/OpenPGP compatible. **Argon2id** sert séparément à protéger le code du mode calculatrice et les paramètres locaux ; il ne remplace pas le chiffrement de `.dpdb`.

## Stéganographie

<img src="diagrams/steganography.svg" width="100%" alt="Insertion et extraction de la base chiffrée"/>

Diskpass peut incorporer une **base `.dpdb` déjà chiffrée** à un fichier multimédia. Après extraction, la clé privée OpenPGP reste nécessaire pour déverrouiller les données.

| Support | Technique |
|---|---|
| PNG, BMP, TIFF, WebP sans perte et images similaires | Bits de poids faible des pixels RGB (LSB) |
| JPEG | Parité de coefficients AC DCT quantifiés sélectionnés |
| WAV PCM entier | Un bit de poids faible par échantillon |
| MP3 | Pochette APIC déjà présente dans ID3v2 |
| FLAC | Pochette PICTURE intégrée |

Dans les nouveaux formats, un *bootstrap seed* dérivé des données stables du support permet de retrouver le conteneur chiffré avant d'ouvrir la base. `DISKPASS_STEGO_MAX_PERCENT` définit la limite d'occupation : **20 %** par défaut, valeurs autorisées **1–40**.

## Architecture et compilation

Développé en **C11**, Diskpass utilise **GTK3/GLib** pour l'interface, **libsodium** pour l'aléatoire et la mémoire sensible, **GPGME/GnuPG** pour OpenPGP, **cJSON** pour la sérialisation, ainsi que **libjpeg/libwebp** pour les images. Les plugins ABI v1 ajoutent des actions au menu ; le module Katasymbol E11 imprime des étiquettes via Bluetooth LE.

**Debian / Ubuntu :**

```bash
sudo apt install build-essential pkg-config libgtk-3-dev libglib2.0-dev \
  libgpgme-dev libsodium-dev libcjson-dev libjpeg-dev libwebp-dev

git clone https://github.com/Sergei768/Diskpass.git
cd Diskpass
make -j2
./diskpass
```

Pour une installation utilisateur, lancez `./build.sh` **sans `sudo`** ; des dépendances supplémentaires peuvent être nécessaires. `diskpass-package.sh` crée des paquets avec les outils adaptés à la plateforme.

## Modèle de menace et licences

Le modèle considère un observateur passif ayant accès aux supports et aux étiquettes, mais pas aux secrets de la base ni à la clé privée OpenPGP. Une étiquette contient des **métadonnées pseudonymisées, pas un texte chiffré** : des répétitions ou longueurs de blocs peuvent révéler des régularités. Diskpass ne chiffre pas les fichiers présents sur les disques, ne garantit pas l'indétectabilité des données stéganographiques et ne protège pas un ordinateur ou une clé privée compromis. Les plugins natifs s'exécutent sans bac à sable.

Le code propre à Diskpass est sous **BSD-3-Clause** ; l'application combinée contient également une calculatrice sous **GPL-3.0-or-later** (`calculator/COPYING`).
