<p align="center">
  <img src="assets/logo.svg" width="100%" alt="DiskPass — encrypted physical media archive"/>
</p>

**Documentation / Languages:** [English](../README.md) · [Русский](README.ru.md) · [Українська](README.uk.md) · [Беларуская](README.be.md) · [Қазақша](README.kk.md) · [简体中文](README.zh_CN.md) · [繁體中文（台灣）](README.zh_TW.md) · [日本語](README.ja.md) · **한국어** · [Français](README.fr.md) · [Deutsch](README.de.md) · [Español](README.es.md)

# Diskpass

물리적 저장 매체용 식별 태그 생성기이자 암호화된 로컬 아카이브 관리 도구입니다.

HDD, SSD, USB 드라이브, LTO 테이프가 많은 경우 Diskpass는 매체에 내용, 암호화 방식, 비밀번호를 직접 적지 않고 식별할 수 있도록 돕습니다. `HK-T1R-BAM-LK-XYQ` 같은 짧은 태그를 부착하고 상세 기록은 암호화된 `.dpdb` 데이터베이스에서 확인합니다. 태그에는 비밀번호가 포함되지 않습니다.

## 주요 기능

- **물리적 태그:** 매체 유형, 용량, 내용 레이블, 암호화 방식, 매체별 임의 솔트의 다섯 요소로 구성됩니다.
- **데이터베이스별 구성:** 생성 시 다섯 요소의 순서를 임의로 정하며 가능한 배열은 `5! = 120`개입니다.
- **아카이브 관리:** 장치 등록, 비밀번호와 메모, 디렉터리 스냅샷, 연결되지 않은 장치의 파일 검색, SMART 정보 보관을 지원합니다.
- **암호화 저장:** DPENV5, XChaCha20-Poly1305, OpenPGP/GPGME를 사용하며 ML-KEM은 GnuPG 호환성에 따라 지원됩니다.
- **추가 기능:** 스테가노그래피, 자동 잠금, 클립보드 지우기, 계산기 모드, 신뢰할 수 있는 네이티브 플러그인을 제공합니다.

## 물리적 태그 생성

<img src="diagrams/tags.svg" width="100%" alt="물리적 태그 생성 흐름도"/>

태그는 하이픈으로 구분된 다섯 블록으로 구성됩니다. 각 블록은 **`[코드][검사 문자]`** 구조이며 마지막 문자는 **BLAKE2b**, `noise_key`, 데이터베이스의 `salt`를 이용해 계산됩니다.

| 요소 | 의미 |
|---|---|
| `type` | HDD, SSD, USB, LTO 등의 매체 유형 |
| `size` | 용량을 나타내는 짧은 내부 코드 |
| `content_tag` | 사용자가 지정하는 내용 레이블 |
| `cipher` | 매체에 적용된 암호화 방식 |
| `dsalt` | 매체마다 생성되는 임의 값 |

**절차:** 요소 순서 선택 → 데이터 인코딩 → `dsalt` 생성 → 각 블록의 검사 문자 계산 → 정해진 순서로 연결. 기본 순서에서 `HK-T1R-BAM-LK-XYQ`는 HDD, 1 TB, Backup, LUKS, 솔트 `XY`를 뜻합니다.

## `.dpdb` 데이터베이스 암호화

<img src="diagrams/encryption.svg" width="100%" alt="DPENV5 데이터베이스 암호화 흐름도"/>

Diskpass는 비밀번호, 태그 매핑, 메모, 구성 매개변수와 파일 색인을 로컬 **DPENV5 바이너리 컨테이너**에 저장합니다.

1. **직렬화:**`cJSON`으로 기록 구조를 만듭니다.
2. **인증 암호화:****XChaCha20-Poly1305**가 내용을 보호하고 외부 헤더는 AAD에 포함됩니다.
3. **키 엔벌로프:****OpenPGP/GPGME**가 키 자료를 보호하며 GnuPG/pinentry가 개인 키 접근을 처리합니다.
4. **서명과 해시:****BLAKE2b-256** 다이제스트는 DPENV5 서명을 패딩된 평문 내용에 연결합니다.
5. **버전 검증:** 세대 체인과 로컬 anti-rollback 상태로 과거 데이터베이스 사본을 감지할 수 있습니다.

**ML-KEM/Kyber**에는 호환되는 GnuPG/OpenPGP 엔진이 필요합니다. **Argon2id**는 계산기 모드 접근 코드 및 설정 보호에 별도로 사용되며 `.dpdb` 암호화를 대체하지 않습니다.

## 스테가노그래피

<img src="diagrams/steganography.svg" width="100%" alt="암호화된 데이터베이스의 삽입과 추출"/>

Diskpass는 **이미 암호화된 `.dpdb`**를 미디어 파일 안에 삽입할 수 있습니다. 추출한 뒤에도 내용 확인에는 OpenPGP 개인 키가 필요합니다.

| 매체 형식 | 삽입 방식 |
|---|---|
| PNG, BMP, TIFF, 무손실 WebP 등의 이미지 | RGB 픽셀의 최하위 비트(LSB) |
| JPEG | 선택한 양자화 AC DCT 계수의 홀짝성 |
| 정수 PCM WAV | 샘플당 최하위 비트 하나 |
| MP3 | 기존 ID3v2 APIC 커버 이미지 |
| FLAC | 포함된 PICTURE 커버 이미지 |

새 형식에서는 매체의 안정적인 데이터로 bootstrap-seed를 계산하여 데이터베이스를 잠금 해제하기 전에 암호화 컨테이너를 찾습니다. `DISKPASS_STEGO_MAX_PERCENT`의 기본값은 **20%**이며 범위는 **1–40**입니다.

## 아키텍처와 빌드

프로그램은 **C11**로 작성되었습니다. **GTK3/GLib**는 UI, **libsodium**은 난수와 민감한 메모리, **GPGME/GnuPG**는 OpenPGP, **cJSON**은 직렬화, **libjpeg/libwebp**는 이미지 처리를 담당합니다. ABI v1 플러그인은 메뉴 기능을 추가하며 Katasymbol E11 플러그인은 Bluetooth LE를 통해 레이블을 인쇄합니다.

**Debian / Ubuntu:**

```bash
sudo apt install build-essential pkg-config libgtk-3-dev libglib2.0-dev \
  libgpgme-dev libsodium-dev libcjson-dev libjpeg-dev libwebp-dev

git clone https://github.com/Sergei768/Diskpass.git
cd Diskpass
make -j2
./diskpass
```

사용자 설치에는 `./build.sh`를 일반 사용자로 실행하십시오(`sudo` 사용 금지). `diskpass-package.sh`는 배포판별 패키지 빌드 도구가 있어야 동작합니다.

## 위협 모델과 라이선스

이 프로그램은 매체와 태그를 볼 수 있지만 데이터베이스 비밀값이나 OpenPGP 개인 키는 없는 수동적 관찰자를 고려합니다. 태그는 **가명화된 메타데이터이지 암호문이 아닙니다**. 반복 코드와 블록 길이에서 패턴이 드러날 수 있습니다. Diskpass는 디스크 안의 파일 자체를 암호화하지 않고 스테가노그래피의 탐지 불가능성을 보장하지 않으며, 침해된 시스템이나 유출된 개인 키를 보호하지 못합니다. 네이티브 플러그인은 샌드박스 없이 실행됩니다.

Diskpass 고유 코드는 **BSD-3-Clause**, 포함된 계산기는 **GPL-3.0-or-later**(`calculator/COPYING`) 라이선스를 따릅니다.
