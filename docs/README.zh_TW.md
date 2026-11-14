<p align="center">
  <img src="assets/logo.svg" width="100%" alt="DiskPass — encrypted physical media archive"/>
</p>

**Documentation / Languages:** [English](../README.md) · [Русский](README.ru.md) · [Українська](README.uk.md) · [Беларуская](README.be.md) · [Қазақша](README.kk.md) · [简体中文](README.zh_CN.md) · **繁體中文（台灣）** · [日本語](README.ja.md) · [한국어](README.ko.md) · [Français](README.fr.md) · [Deutsch](README.de.md) · [Español](README.es.md)

# Diskpass

實體儲存媒體標籤產生器，以及管理本機加密儲存檔案庫的工具。

當您擁有大量 HDD、SSD、隨身碟或 LTO 磁帶時，Diskpass 可以建立簡短標籤，不必在設備上直接寫出內容、加密方法或密碼。標籤例如 `HK-T1R-BAM-LK-XYQ`。完整的媒體資料記錄於加密的 `.dpdb` 資料庫；標籤本身只有精簡編碼的中繼資料，並不包含密碼。

## 主要功能

- **實體標籤：**包含媒體類型、容量、內容識別、加密方式，以及每台設備的隨機鹽值。
- **資料庫專屬配置：**建立資料庫時隨機排列五個欄位，共有 `5! = 120` 種排列方式。
- **檔案庫管理：**登錄儲存媒體、保管密碼與筆記、建立目錄快照、搜尋未連接媒體的檔案索引，以及儲存 SMART 資訊快照。
- **加密儲存：**使用 DPENV5、XChaCha20-Poly1305 與 OpenPGP/GPGME；ML-KEM 需有相容的 GnuPG。
- **其他功能：**隱寫術、自動鎖定、剪貼簿清除、計算機模式以及受信任的原生外掛。

## 產生實體標籤

<img src="diagrams/tags.svg" width="100%" alt="實體標籤的產生流程"/>

一個標籤由五個以連字號分隔的區塊組成，每個區塊的格式為 **`[編碼][檢查字元]`**。末尾字元由 **BLAKE2b**、資料庫的 `noise_key` 和 `salt` 計算。

| 欄位 | 說明 |
|---|---|
| `type` | HDD、SSD、USB、LTO 等媒體類型 |
| `size` | 容量的內部短碼 |
| `content_tag` | 使用者自訂的內容標籤 |
| `cipher` | 媒體所使用的加密方法 |
| `dsalt` | 為個別媒體產生的隨機值 |

**流程：**決定欄位隨機順序 → 編碼各項資料 → 產生 `dsalt` → 計算各區塊的檢查字元 → 依照配置組成標籤。依預設欄位順序，`HK-T1R-BAM-LK-XYQ` 代表 HDD、1 TB、Backup、LUKS 與鹽值 `XY`。

## `.dpdb` 資料庫加密

<img src="diagrams/encryption.svg" width="100%" alt="DPENV5 資料庫保護流程"/>

Diskpass 將密碼、標籤對應、筆記、欄位配置及檔案索引儲存在本機的 **DPENV5 二進位容器**。

1. **序列化：**透過 `cJSON` 建立紀錄結構。
2. **驗證式加密：****XChaCha20-Poly1305** 保護資料，並將外部標頭納入 AAD。
3. **金鑰信封：****OpenPGP/GPGME** 保護金鑰資料；GnuPG/pinentry 處理私密金鑰存取。
4. **簽章與雜湊：****BLAKE2b-256** 摘要讓 DPENV5 簽章與填充後的明文內容建立關聯。
5. **版本防護：**版本鏈及本機 anti-rollback 狀態有助於發現舊版資料庫副本。

**ML-KEM/Kyber** 需要相容的 GnuPG/OpenPGP 引擎。**Argon2id** 另外用來保護計算機模式存取碼與本機設定，並非用來取代 `.dpdb` 加密。

## 隱寫術

<img src="diagrams/steganography.svg" width="100%" alt="加密資料庫的嵌入與擷取"/>

Diskpass 可以將**已經加密的 `.dpdb`** 嵌入媒體檔案。即使成功擷取該容器，仍需要 OpenPGP 私密金鑰才能開啟資料庫。

| 載體 | 嵌入方式 |
|---|---|
| PNG、BMP、TIFF、無損 WebP 等影像 | RGB 像素的最低有效位元（LSB） |
| JPEG | 指定量化 AC DCT 係數的奇偶性 |
| 整數 PCM WAV | 每個取樣值的一個最低有效位元 |
| MP3 | 現有的 ID3v2 APIC 封面圖 |
| FLAC | 內嵌的 PICTURE 封面圖 |

新格式的 bootstrap-seed 會從載體穩定的資料推導，無須先解鎖資料庫即可定位加密容器。`DISKPASS_STEGO_MAX_PERCENT` 控制容量占用量，預設 **20%**，允許 **1–40**。

## 架構與建置

程式以 **C11** 撰寫：**GTK3/GLib** 提供介面，**libsodium** 負責隨機資料與敏感記憶體，**GPGME/GnuPG** 提供 OpenPGP，**cJSON** 負責序列化，**libjpeg/libwebp** 處理影像。ABI v1 外掛可增加選單功能，例如透過 Bluetooth LE 使用 Katasymbol E11 列印標籤。

**Debian / Ubuntu：**

```bash
sudo apt install build-essential pkg-config libgtk-3-dev libglib2.0-dev \
  libgpgme-dev libsodium-dev libcjson-dev libjpeg-dev libwebp-dev

git clone https://github.com/Sergei768/Diskpass.git
cd Diskpass
make -j2
./diskpass
```

使用者層級安裝可執行 `./build.sh`（請**不要**使用 `sudo`）。`diskpass-package.sh` 需要各發行版對應的封裝工具。

## 威脅模型與授權

此模型考慮看得到實體設備與標籤、但沒有資料庫秘密參數及 OpenPGP 私密金鑰的被動觀察者。標籤是**假名化的中繼資料，不是密文**；重複編碼與區塊長度仍可能呈現統計規律。Diskpass 不負責加密磁碟上的實際內容，隱寫術也不保證無法偵測；當電腦或私密金鑰遭入侵時，保護範圍有限。原生外掛在同一程序內執行，沒有沙箱隔離。

Diskpass 原創程式碼採 **BSD-3-Clause**；內含的計算機程式碼使用 **GPL-3.0-or-later**（`calculator/COPYING`）。
