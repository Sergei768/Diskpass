<p align="center">
  <img src="assets/logo.svg" width="100%" alt="DiskPass — encrypted physical media archive"/>
</p>

**Documentation / Languages:** [English](../README.md) · [Русский](README.ru.md) · [Українська](README.uk.md) · [Беларуская](README.be.md) · [Қазақша](README.kk.md) · [简体中文](README.zh_CN.md) · [繁體中文（台灣）](README.zh_TW.md) · [日本語](README.ja.md) · [한국어](README.ko.md) · [Français](README.fr.md) · [Deutsch](README.de.md) · **Español**

# Diskpass

Generador de etiquetas físicas para medios de almacenamiento y gestor de archivos con una base de datos local cifrada.

Diskpass ayuda a organizar colecciones de HDD, SSD, memorias USB y cintas LTO sin escribir directamente en cada soporte su contenido, método de cifrado o contraseña. El programa genera una etiqueta corta como `HK-T1R-BAM-LK-XYQ`; el propietario consulta los datos completos en la base cifrada `.dpdb`. La etiqueta contiene metadatos codificados, no la contraseña.

## Funciones principales

- **Etiquetas físicas:** cinco componentes para el tipo de soporte, capacidad, descripción del contenido, método de cifrado y sal aleatoria del dispositivo.
- **Esquema exclusivo por base:** al crear la base se fija una permutación aleatoria de los cinco campos (`5! = 120` órdenes posibles).
- **Gestión del archivo:** registro de dispositivos, contraseñas y notas, instantáneas de directorios, búsqueda de archivos en medios desconectados y datos SMART guardados.
- **Almacenamiento protegido:** DPENV5, XChaCha20-Poly1305 y OpenPGP/GPGME; ML-KEM requiere un motor GnuPG compatible.
- **Herramientas adicionales:** esteganografía, bloqueo automático, limpieza del portapapeles, modo calculadora y complementos nativos de confianza.

## Generación de etiquetas físicas

<img src="diagrams/tags.svg" width="100%" alt="Diagrama de generación de etiquetas físicas"/>

Cada etiqueta contiene cinco bloques separados por guiones. Un bloque tiene el formato **`[CÓDIGO][CARÁCTER_DE_CONTROL]`**; su último carácter se calcula con **BLAKE2b** y los parámetros `noise_key` y `salt` de la base.

| Componente | Función |
|---|---|
| `type` | Tipo de soporte: HDD, SSD, USB, LTO, etc. |
| `size` | Código interno corto de capacidad |
| `content_tag` | Etiqueta de contenido definida por el usuario |
| `cipher` | Método de cifrado del soporte |
| `dsalt` | Valor aleatorio para cada soporte |

**Proceso:** elegir el orden de los campos → codificar valores → generar `dsalt` → calcular el carácter de control de cada bloque → unir los bloques. Con el orden habitual, `HK-T1R-BAM-LK-XYQ` representa HDD, 1 TB, Backup, LUKS y la sal `XY`.

## Cifrado de la base `.dpdb`

<img src="diagrams/encryption.svg" width="100%" alt="Proceso de cifrado DPENV5"/>

Diskpass almacena contraseñas, correspondencias de etiquetas, notas, parámetros del esquema e índices de archivos en un **contenedor binario DPENV5** local.

1. **Serialización:** `cJSON` construye la estructura de registros.
2. **Cifrado autenticado:** **XChaCha20-Poly1305** protege el contenido y autentica la cabecera externa como AAD.
3. **Sobre de claves:** **OpenPGP/GPGME** protege el material criptográfico y GnuPG/pinentry gestiona el acceso a la clave privada.
4. **Firma y resumen:** el hash **BLAKE2b-256** vincula la firma de DPENV5 con el texto en claro rellenado.
5. **Control de versiones:** la cadena de generaciones y el estado anti-rollback local ayudan a detectar una copia antigua.

**ML-KEM/Kyber** necesita un motor GnuPG/OpenPGP compatible. **Argon2id** se usa por separado para el código de acceso del modo calculadora y las preferencias locales; no sustituye al cifrado de `.dpdb`.

## Esteganografía

<img src="diagrams/steganography.svg" width="100%" alt="Inserción y extracción de la base cifrada"/>

Diskpass puede insertar una **base `.dpdb` previamente cifrada** en un archivo multimedia. Tras extraerla sigue siendo necesaria la clave privada OpenPGP para leer su contenido.

| Soporte | Técnica de inserción |
|---|---|
| PNG, BMP, TIFF, WebP sin pérdidas y otras imágenes | Bits menos significativos de píxeles RGB (LSB) |
| JPEG | Paridad de coeficientes AC DCT cuantizados seleccionados |
| WAV PCM entero | Un bit menos significativo por muestra |
| MP3 | Portada APIC existente en ID3v2 |
| FLAC | Portada PICTURE integrada |

En los formatos nuevos se obtiene una semilla de arranque (*bootstrap seed*) de los datos estables del soporte. Esto permite localizar el contenedor cifrado antes de abrir la base. `DISKPASS_STEGO_MAX_PERCENT` limita la ocupación: **20 %** por defecto, valores permitidos **1–40**.

## Arquitectura y compilación

Diskpass está escrito en **C11**. **GTK3/GLib** ofrece la interfaz; **libsodium**, los valores aleatorios y la memoria sensible; **GPGME/GnuPG**, OpenPGP; **cJSON**, la serialización; y **libjpeg/libwebp**, el procesamiento de imágenes. Los plugins ABI v1 añaden acciones al menú; el módulo Katasymbol E11 imprime etiquetas mediante Bluetooth LE.

**Debian / Ubuntu:**

```bash
sudo apt install build-essential pkg-config libgtk-3-dev libglib2.0-dev \
  libgpgme-dev libsodium-dev libcjson-dev libjpeg-dev libwebp-dev

git clone https://github.com/Sergei768/Diskpass.git
cd Diskpass
make -j2
./diskpass
```

Para la instalación de usuario, ejecute `./build.sh` como usuario normal (**sin `sudo`**). `diskpass-package.sh` precisa las herramientas de empaquetado correspondientes a cada plataforma.

## Modelo de amenazas y licencias

El modelo contempla a un observador pasivo con acceso a los soportes y etiquetas, pero sin los secretos de la base ni la clave privada OpenPGP. Una etiqueta contiene **metadatos seudonimizados, no texto cifrado**; las repeticiones y longitudes de bloques pueden revelar patrones. Diskpass no cifra los archivos de los discos, no garantiza que la esteganografía sea indetectable ni protege un equipo o una clave privada comprometidos. Los plugins nativos se ejecutan sin aislamiento por sandbox.

El código propio de Diskpass usa **BSD-3-Clause**; la aplicación combinada incluye también una calculadora bajo **GPL-3.0-or-later** (`calculator/COPYING`).
