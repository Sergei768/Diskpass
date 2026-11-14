<p align="center">
  <img src="assets/logo.svg" width="100%" alt="DiskPass — encrypted physical media archive"/>
</p>

**Documentation / Languages:** [English](../README.md) · [Русский](README.ru.md) · [Українська](README.uk.md) · [Беларуская](README.be.md) · [Қазақша](README.kk.md) · **简体中文** · [繁體中文（台灣）](README.zh_TW.md) · [日本語](README.ja.md) · [한국어](README.ko.md) · [Français](README.fr.md) · [Deutsch](README.de.md) · [Español](README.es.md)

# Diskpass

用于实体存储介质的标签生成器，以及管理本地加密存储档案的工具。

当您有大量 HDD、SSD、U 盘或 LTO 磁带时，Diskpass 可以为它们制作短标签，而不必把内容、加密方式或密码直接写在设备上。标签示例为 `HK-T1R-BAM-LK-XYQ`。所有详细记录保存在加密的 `.dpdb` 数据库中；标签本身只包含简短编码的元数据，不包含密码。

## 主要功能

- **实体标签：**由介质类型、容量、内容标识、加密方式和单个设备的随机盐组成。
- **数据库专属布局：**创建数据库时随机排列五个字段，共有 `5! = 120` 种排列顺序。
- **档案管理：**登记存储设备、保存密码和备注、建立目录快照、搜索已断开连接设备的文件索引，并记录 SMART 快照。
- **加密存储：**采用 DPENV5、XChaCha20-Poly1305 和 OpenPGP/GPGME；ML-KEM 取决于 GnuPG 的兼容性。
- **扩展功能：**隐写术、自动锁定、剪贴板清理、计算器模式以及受信任的本地插件。

## 实体标签的生成

<img src="diagrams/tags.svg" width="100%" alt="实体标签生成流程"/>

一个标签由五个通过连字符连接的区块构成。每个区块的格式为 **`[编码][校验字符]`**；末尾字符根据 **BLAKE2b**、数据库的 `noise_key` 和 `salt` 计算。

| 字段 | 含义 |
|---|---|
| `type` | HDD、SSD、USB、LTO 等介质类型 |
| `size` | 容量对应的简短内部编码 |
| `content_tag` | 用户定义的内容标识 |
| `cipher` | 该介质使用的加密方式 |
| `dsalt` | 为单个介质生成的随机值 |

**流程：**随机确定数据库字段排列 → 对字段值编码 → 生成 `dsalt` → 计算每个区块的校验字符 → 根据排列组合标签。按标准顺序，`HK-T1R-BAM-LK-XYQ` 表示 HDD、1 TB、Backup、LUKS 和盐值 `XY`。

## `.dpdb` 数据库加密

<img src="diagrams/encryption.svg" width="100%" alt="DPENV5 数据库加密流程"/>

Diskpass 将密码、标签映射、备注、字段排列和文件索引保存在本地 **DPENV5 二进制容器**中。

1. **序列化：**使用 `cJSON` 组织数据库记录。
2. **认证加密：****XChaCha20-Poly1305** 保护内容；外部头部作为 AAD 参与认证。
3. **密钥封装：****OpenPGP/GPGME** 保护密钥材料，GnuPG/pinentry 负责访问私钥。
4. **签名与摘要：****BLAKE2b-256** 摘要将 DPENV5 签名绑定到填充后的明文内容。
5. **版本保护：**版本链与本地 anti-rollback 状态用于发现过期的数据库副本。

**ML-KEM/Kyber** 需要兼容的 GnuPG/OpenPGP 引擎。**Argon2id** 另用于计算器模式的访问码和本地配置保护，并不替代 `.dpdb` 的加密机制。

## 隐写术

<img src="diagrams/steganography.svg" width="100%" alt="加密数据库的嵌入与提取"/>

Diskpass 可以将**已经加密的 `.dpdb`** 嵌入媒体文件。即使成功提取该容器，仍需要相应的 OpenPGP 私钥才能读取数据库内容。

| 载体 | 嵌入方式 |
|---|---|
| PNG、BMP、TIFF、无损 WebP 等图像 | RGB 像素的最低有效位（LSB） |
| JPEG | 所选量化 AC DCT 系数的奇偶性 |
| 整数 PCM WAV | 每个采样值的一个最低有效位 |
| MP3 | 已有的 ID3v2 APIC 封面图 |
| FLAC | 内嵌 PICTURE 封面图 |

新版本的 bootstrap-seed 从载体的稳定数据推导，因此无需先解锁数据库即可定位加密容器。`DISKPASS_STEGO_MAX_PERCENT` 控制可用空间占用量：默认 **20%**，允许 **1–40**。

## 架构与构建

Diskpass 由 **C11** 编写：**GTK3/GLib** 提供界面，**libsodium** 处理随机数与敏感内存，**GPGME/GnuPG** 提供 OpenPGP，**cJSON** 进行序列化，**libjpeg/libwebp** 处理图像。ABI v1 插件可以增加菜单操作，例如通过 Bluetooth LE 使用 Katasymbol E11 打印标签。

**Debian / Ubuntu：**

```bash
sudo apt install build-essential pkg-config libgtk-3-dev libglib2.0-dev \
  libgpgme-dev libsodium-dev libcjson-dev libjpeg-dev libwebp-dev

git clone https://github.com/Sergei768/Diskpass.git
cd Diskpass
make -j2
./diskpass
```

用户级安装可运行 `./build.sh`（**不要**通过 `sudo` 执行）；`diskpass-package.sh` 可在相应构建工具已安装时生成发行包。

## 威胁模型与许可证

主要考虑能够观察实体介质及标签、却无法获得数据库秘密参数和 OpenPGP 私钥的被动攻击者。标签只是**经过假名化的元数据，并非密文**；重复编码和区块长度仍可能泄漏统计规律。Diskpass 不负责加密磁盘上的实际文件，隐写术也不保证不可检测；主机被攻陷或私钥泄露时，软件无法提供相同保护。本地插件在进程内运行，没有沙箱隔离。

Diskpass 原创代码采用 **BSD-3-Clause**；打包的计算器代码采用 **GPL-3.0-or-later**（`calculator/COPYING`）。
