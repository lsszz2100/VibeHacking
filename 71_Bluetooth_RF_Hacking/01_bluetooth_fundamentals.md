> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 블루투스 보안 기초

## 0. 초보자를 위한 개념 이해

### 블루투스란 무엇인가?

블루투스를 처음 배우는 분을 위한 비유: **블루투스는 집 안에서만 쓰는 무선 전화기**입니다. WiFi가 건물 전체에 퍼지는 방송국 라디오라면, 블루투스는 "나랑 1~10m 안에 있는 기기끼리만 대화하자"는 개인 채널입니다.

```
무선 통신 범위 비교:

  WiFi        ──────────────────────────── 100m+
  블루투스    ───────── 10~100m
  BLE         ─────── 10~50m (저전력)
  NFC         ─ 0~10cm
  Zigbee      ────── 10~75m

  → 블루투스/BLE는 "근거리 개인 통신"에 특화
```

**왜 보안적으로 중요한가:**
- 스마트폰, 이어폰, 스마트워치, 의료기기, 자동차까지 수십억 대 기기에 탑재
- "근거리니까 안전하겠지"라는 착각 → 실제로는 카페에서도 공격 가능
- 블루투스 취약점 = 물리적 접근 없이도 기기 장악 가능

---

## 1. 블루투스 vs BLE: 두 종류가 있다

### 클래식 블루투스 (BR/EDR)

```
클래식 블루투스:
  - 정식 명칭: Bluetooth Basic Rate / Enhanced Data Rate
  - 주파수: 2.4 GHz ISM 대역
  - 속도: 1~3 Mbps
  - 용도: 오디오 스트리밍, 파일 전송, 헤드셋
  - 페어링: PIN 코드 또는 SSP(Secure Simple Pairing)
  - 거리: 보통 10~30m (Class 1은 100m)
```

### BLE (Bluetooth Low Energy)

```
BLE (블루투스 4.0 이상):
  - 정식 명칭: Bluetooth Low Energy
  - 주파수: 2.4 GHz (40개 채널)
  - 속도: 125 Kbps ~ 2 Mbps
  - 소비전력: 클래식 대비 10~100분의 1
  - 용도: 심박 센서, 스마트 자물쇠, 위치 태그, IoT 센서
  - 페어링: Just Works / Passkey / OOB / Numeric Comparison
  - 핵심: "연결보다 브로드캐스트 위주" → 배터리 수명 수년
```

### 핵심 차이표

```
특성              클래식 블루투스    BLE
─────────────────────────────────────────
배터리 소모        높음              매우 낮음
연결 속도          느림              빠름 (수ms)
데이터 전송량      많음              적음
주요 용도          오디오, 파일      센서, 비콘
보안 취약점        BlueSnarfing      인증 없는 쓰기
페어링 없이 통신   불가              가능 (Advertisement)
```

---

## 2. 블루투스 스택 구조

스택이란 "레고 블록처럼 쌓인 기능 층"입니다. 아래에서 위로 갈수록 사용자에게 가까워집니다.

```
┌─────────────────────────────────┐
│  애플리케이션 (앱, 게임, 의료앱) │  ← 우리가 쓰는 앱
├─────────────────────────────────┤
│  프로파일 (A2DP, HFP, GATT)    │  ← "어떤 목적으로 쓸지"
├─────────────────────────────────┤
│  L2CAP / ATT / SMP             │  ← 데이터 분할, 암호화
├─────────────────────────────────┤
│  HCI (Host Controller Interface)│  ← 소프트웨어↔하드웨어 경계
├─────────────────────────────────┤
│  LMP / LL (링크 레이어)         │  ← 연결 관리, 채널 호핑
├─────────────────────────────────┤
│  RF (라디오 물리층)              │  ← 실제 전파 송수신
└─────────────────────────────────┘

공격자 시각:
  - RF층 → 재밍, 신호 도청
  - 링크층 → 페어링 도청, MitM
  - SMP층 → 암호화 취약점
  - 프로파일층 → GATT 인증 우회
  - 앱층 → 취약한 BLE 앱 로직
```

---

## 3. 페어링 과정 이해

### 페어링이란?

페어링 = "나 이 기기야, 믿어도 돼"라는 **처음 만남의 악수**입니다.

### 클래식 블루투스: PIN 기반

```
PIN 코드 페어링 (구형, 취약):

  기기A ──── "페어링하자!" ────→ 기기B
  기기A ←─── "PIN 입력해" ─────  기기B
  기기A ────  "1234" 입력  ────→ 기기B
  기기A ←─── "OK, 연결됨" ─────  기기B

  문제점:
  - PIN이 짧으면 (4자리) 브루트포스 가능
  - 페어링 과정 자체를 도청하면 PIN 추출 가능
  - 레거시 PIN 방식은 Bluetooth 2.0 이전 기기에서 사용
```

### SSP (Secure Simple Pairing): 현대 방식

```
SSP 4가지 방법:

1. Just Works (취약!)
   - PIN 없이 자동 연결
   - 사용 예: 이어폰, 키보드 일부
   - 위험: 중간자 공격(MitM) 가능

2. Passkey Entry (보통)
   - 한쪽이 6자리 숫자 표시 → 다른쪽 입력
   - 사용 예: 키보드↔PC

3. Numeric Comparison (강함)
   - 양쪽 기기에 같은 6자리 표시 → 사용자가 "같음" 확인
   - MitM 방어 효과적

4. OOB (Out-of-Band, 강함)
   - NFC나 QR코드로 키 교환 후 블루투스 연결
   - 가장 안전하지만 불편
```

---

## 4. 주요 공격 분류

### BlueSnarfing (데이터 절도)

```
공격 시나리오:
  대상: 블루투스가 "discoverable" 상태인 구형 폰
  공격: OBEX 프로토콜 취약점으로 연락처, SMS, 사진 무단 복사
  조건: 페어링 없이도 가능 (구형 펌웨어)
  현재: 최신 기기는 패치됨, 구형 기기/IoT는 여전히 취약

블루스나핑 원리:
  폰 ─── OBEX Push/Pull 요청 ──→ 대상폰
        (인증 없이 파일 접근 가능)
  폰 ←── 연락처 데이터 ─────── 대상폰
```

### BlueJacking (스팸 전송)

```
공격 시나리오:
  - OBEX 프로토콜로 이름에 메시지를 담아 "연락처 카드" 전송
  - 대상은 낯선 "연락처 추가 요청" 팝업을 봄
  - 실제 피해보다 성가심에 가까움
  - 사회공학: "이 링크 클릭하면 경품 당첨"
```

### Bluebugging (기기 장악)

```
공격 시나리오:
  대상: 취약한 블루투스 펌웨어의 헤드셋/폰
  공격: AT 명령어로 전화 발신, SMS 전송, 마이크 활성화
  피해: 도청, 무단 전화, 데이터 절도

  공격자폰 ─── "AT+CLAC?" ──→ 취약 기기
            ←── AT 명령 목록 ─
            ─── "ATA" (통화 받기) ──→
            (피해자 통화 도청 가능)
```

### KNOB 공격 (Key Negotiation of Bluetooth)

```
CVE-2019-9506:
  - 블루투스 암호화 키 길이를 1바이트로 강제
  - 페어링 중 키 협상 과정 조작
  - 영향: 거의 모든 블루투스 기기 (패치 전)
  - 2019년 공개, 현재는 대부분 패치됨
```

---

## 5. 초보자용 실습 도구 소개

### 하드웨어 도구

```
도구              가격    용도
──────────────────────────────────────────
Ubertooth One    $120    블루투스 패킷 캡처/분석
CSR8510 동글     $5~10   리눅스 BLE 스캔
RTL-SDR          $25     RF 신호 분석 (블루투스 대역 모니터)
Raspberry Pi     $35+    블루투스 공격 플랫폼
HackRF One       $300    넓은 주파수 RF 해킹
```

**추천 입문 장비**: CSR8510 USB 동글 (저렴, 리눅스 호환) + 소프트웨어로 시작

### 소프트웨어 도구

```
도구              설치              용도
────────────────────────────────────────────────────
bluetoothctl      내장(BlueZ)       블루투스 스캔/연결
hcitool           bluez-utils 패키지 기기 탐색
btlejuice         Node.js           BLE MitM 프록시
bleak             pip install bleak BLE Python 라이브러리
gatttool          bluez             GATT 특성 탐색
bettercap         apt install       종합 네트워크 공격
```

### 유용한 링크

- 블루투스 공식 보안 가이드: https://www.bluetooth.com/learn-about-bluetooth/key-attributes/bluetooth-security/
- Ubertooth 프로젝트 (블루투스 모니터링 하드웨어): https://github.com/greatscottgadgets/ubertooth

---

## 6. 실습: 주변 블루투스 기기 스캔

### 6-1. 시스템 준비

```bash
# 블루투스 스택 설치 (Ubuntu/Kali)
sudo apt update && sudo apt install -y bluez bluez-tools

# 블루투스 인터페이스 확인
hciconfig -a

# 예상 출력:
# hci0:   Type: Primary  Bus: USB
#         BD Address: AA:BB:CC:DD:EE:FF  ACL MTU: 1021:4  SCO MTU: 255:12
#         UP RUNNING

# 인터페이스 활성화 (꺼져있을 때)
sudo hciconfig hci0 up
```

### 6-2. 블루투스 스캔 (CLI)

```bash
# 고전적인 장치 탐색 (discoverable 기기만)
sudo hcitool scan

# BLE 장치 스캔
sudo hcitool lescan

# bluetoothctl 로 대화형 스캔
bluetoothctl
  [bluetoothctl] power on
  [bluetoothctl] agent on
  [bluetoothctl] scan on
  # 10초 기다리면 주변 기기 출력됨
  [bluetoothctl] scan off
  [bluetoothctl] quit
```

### 6-3. Python으로 블루투스 정보 수집

```python
#!/usr/bin/env python3
"""
bluetooth_scanner.py — 주변 블루투스 기기 탐색 스크립트
사용법: sudo python3 bluetooth_scanner.py --timeout 10
"""

import subprocess
import argparse
import re
import sys
from dataclasses import dataclass


@dataclass
class BluetoothDevice:
    address: str
    name: str
    device_type: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="블루투스 기기 스캐너 (클래식 + BLE)"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="스캔 시간(초), 기본값: 10"
    )
    parser.add_argument(
        "--interface",
        type=str,
        default="hci0",
        help="블루투스 인터페이스, 기본값: hci0"
    )
    return parser.parse_args()


def scan_classic_bluetooth(timeout: int) -> list[BluetoothDevice]:
    """클래식 블루투스 기기 스캔 (hcitool scan)"""
    devices: list[BluetoothDevice] = []
    try:
        result = subprocess.run(
            ["hcitool", "scan", "--flush"],
            capture_output=True,
            text=True,
            timeout=timeout + 5,
        )
        lines = result.stdout.strip().splitlines()
        for line in lines[1:]:  # 첫 줄은 헤더
            parts = line.strip().split("\t")
            if len(parts) >= 2:
                addr, name = parts[0], parts[1] if len(parts) > 1 else "Unknown"
                devices.append(
                    BluetoothDevice(address=addr, name=name, device_type="Classic")
                )
    except subprocess.TimeoutExpired:
        print("[!] 클래식 스캔 타임아웃")
    except FileNotFoundError:
        print("[!] hcitool 없음. bluez 설치 필요: sudo apt install bluez")
    except Exception as e:
        print(f"[!] 클래식 스캔 오류: {e}")
    return devices


def scan_ble(timeout: int) -> list[BluetoothDevice]:
    """BLE 기기 스캔 (hcitool lescan)"""
    devices: list[BluetoothDevice] = []
    seen: set[str] = set()
    try:
        proc = subprocess.Popen(
            ["hcitool", "lescan"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        import time
        start = time.time()
        while time.time() - start < timeout:
            line = proc.stdout.readline() if proc.stdout else ""
            if not line:
                break
            # 형식: "AA:BB:CC:DD:EE:FF DeviceName"
            match = re.match(
                r"([0-9A-Fa-f:]{17})\s+(.*)", line.strip()
            )
            if match:
                addr, name = match.group(1), match.group(2)
                if addr not in seen and name != "(unknown)":
                    seen.add(addr)
                    devices.append(
                        BluetoothDevice(
                            address=addr,
                            name=name if name else "Unknown",
                            device_type="BLE",
                        )
                    )
        proc.terminate()
    except FileNotFoundError:
        print("[!] hcitool 없음. sudo apt install bluez")
    except PermissionError:
        print("[!] 권한 부족. sudo 로 실행하세요.")
    except Exception as e:
        print(f"[!] BLE 스캔 오류: {e}")
    return devices


def print_results(devices: list[BluetoothDevice]) -> None:
    if not devices:
        print("  발견된 기기 없음")
        return
    print(f"  {'주소':<20} {'유형':<10} 이름")
    print(f"  {'-'*20} {'-'*10} {'-'*20}")
    for dev in devices:
        print(f"  {dev.address:<20} {dev.device_type:<10} {dev.name}")


def main() -> None:
    args = parse_args()
    print(f"[*] 블루투스 스캔 시작 (인터페이스: {args.interface}, 시간: {args.timeout}초)")
    print()

    print("[+] 클래식 블루투스 기기 스캔 중...")
    classic_devices = scan_classic_bluetooth(args.timeout)
    print(f"    발견: {len(classic_devices)}개")
    print_results(classic_devices)
    print()

    print("[+] BLE 기기 스캔 중...")
    ble_devices = scan_ble(args.timeout)
    print(f"    발견: {len(ble_devices)}개")
    print_results(ble_devices)
    print()

    total = len(classic_devices) + len(ble_devices)
    print(f"[*] 총 {total}개 기기 발견")
    print("[!] 교육 목적으로만 사용하세요. 타인 기기 무단 접근은 불법입니다.")


if __name__ == "__main__":
    main()
```

### 6-4. 실행 및 예상 출력

```bash
# 루트 권한 필요 (BLE 스캔)
sudo python3 bluetooth_scanner.py --timeout 15

# 예상 출력:
# [*] 블루투스 스캔 시작 (인터페이스: hci0, 시간: 15초)
#
# [+] 클래식 블루투스 기기 스캔 중...
#     발견: 2개
#   주소                 유형       이름
#   -------------------- ---------- --------------------
#   AA:BB:CC:11:22:33    Classic    갤럭시 버즈2
#   44:55:66:DD:EE:FF    Classic    내 노트북
#
# [+] BLE 기기 스캔 중...
#     발견: 5개
#   주소                 유형       이름
#   -------------------- ---------- --------------------
#   11:22:33:AA:BB:CC    BLE        Mi Band 6
#   ...
```

---

## 7. 법적/윤리적 주의사항

```
합법적 사용:
  ✓ 자신이 소유한 기기 테스트
  ✓ 명시적 허가를 받은 환경
  ✓ CTF/실습 랩 환경
  ✓ 취약점 연구 후 책임감 있는 공개

불법 행위:
  ✗ 타인 기기 무단 스캔/접근
  ✗ 동의 없이 데이터 수집
  ✗ 블루투스 재밍/방해
```

---

<!-- detect-validate-71 -->
## 8. 공격 탐지와 방어 검증

앞의 공격 분류(4장)는 "무엇을 막아야 하는가"를 알려주지만, 실무에서는 **그 공격이 실제로 일어났는지 탐지**하고 **내 방어가 정말 작동하는지 검증**하는 단계가 빠지기 쉽습니다.

### 공격 → 계층 → 통제 → 탐지 신호

| 공격 | 노리는 계층 | 1차 통제(예방) | 탐지 신호 |
|---|---|---|---|
| BlueSnarfing | OBEX/프로파일 | 미인증 OBEX 거부, 페어링 강제 | hcidump에 미인증 OBEX GET/PUT |
| Bluebugging | RFCOMM/AT 명령 | AT 명령 채널 인증·비활성화 | 비정상 AT 명령 시퀀스 |
| KNOB | 키 협상(엔트로피) | 최소 엔트로피 강제 | 1~3바이트 키 길이 협상 시도 |
| BlueJacking | 디바이스 검색/푸시 | 비검색 모드, 미요청 푸시 차단 | 다수 미요청 OBEX 푸시 |

### 방어 검증 (직접 확인)

```bash
# KNOB 내성 확인: 내 기기가 낮은 엔트로피 키 협상을 거부하는지
# 페어링 중 LMP 'encryption key size' 협상을 관찰
sudo hcidump -X | grep -i "key size"
# 정상: 협상된 key size가 정책 최소값(예: 16바이트) 이상
# 취약: 1~3바이트로 합의되면 KNOB에 노출됨
```

> 검증은 반드시 **소유한 기기·통제된 환경**에서만 수행합니다. 방어를 켜 두는 것과 방어가 실제로 동작하는지는 다릅니다 — 알려진 다운그레이드(KNOB)·미인증 접근을 재현해 거부되는지 확인해야 신뢰할 수 있습니다([[68_Purple_Team]]).

**최신 기법·통제 (2025–2026):**
- BLE 5.x·BR/EDR 공존 환경에서 페어링/본딩 취약점이 잔존 — LE Secure Connections(LESC) 강제·MITM보호가 실제 협상되는지 확인
- SDR(HackRF 등)로 프로토콜 관찰이 보편화 — 분석은 소유기기·허가된 RF 실험만 수행([[27_IoT_Hacking]])

---

<a name="english"></a>

# Bluetooth Security Fundamentals

## 0. Beginner Concepts

### What Is Bluetooth?

Think of Bluetooth as a **personal walkie-talkie**. While WiFi is a radio station broadcasting to an entire building, Bluetooth says "let's only talk to devices within 1–10 meters of me." This short range is exactly what makes it personal — and also what makes attackers underestimate it.

```
Wireless Range Comparison:

  WiFi        ──────────────────────────── 100m+
  Bluetooth   ───────── 10~100m
  BLE         ─────── 10~50m (low power)
  NFC         ─ 0~10cm
  Zigbee      ────── 10~75m
```

**Why it matters for security:**
- Billions of devices (phones, earbuds, medical gear, cars) rely on it
- The "it's short range, so it's safe" myth gets people hacked in coffee shops
- Bluetooth vulnerabilities can compromise devices without physical contact

---

## 1. Classic Bluetooth vs BLE

### Classic Bluetooth (BR/EDR)

```
Classic Bluetooth:
  - Full name: Basic Rate / Enhanced Data Rate
  - Frequency: 2.4 GHz ISM band
  - Speed: 1–3 Mbps
  - Uses: Audio streaming, file transfer, headsets
  - Pairing: PIN code or SSP (Secure Simple Pairing)
  - Range: ~10–30 m (Class 1 up to 100 m)
```

### BLE (Bluetooth Low Energy)

```
BLE (Bluetooth 4.0+):
  - Frequency: 2.4 GHz (40 channels)
  - Speed: 125 Kbps – 2 Mbps
  - Power: 10–100× less than Classic
  - Uses: Heart-rate sensors, smart locks, location tags, IoT sensors
  - Pairing: Just Works / Passkey / OOB / Numeric Comparison
  - Key trait: Broadcast-first design → battery life measured in years
```

---

## 2. Bluetooth Stack Structure

```
┌─────────────────────────────────┐
│  Application (apps, medical)    │  ← What users interact with
├─────────────────────────────────┤
│  Profiles (A2DP, HFP, GATT)    │  ← "What is this connection for?"
├─────────────────────────────────┤
│  L2CAP / ATT / SMP             │  ← Data segmentation, encryption
├─────────────────────────────────┤
│  HCI (Host Controller Interface)│  ← Software ↔ hardware boundary
├─────────────────────────────────┤
│  LMP / LL (Link Layer)         │  ← Connection management, hopping
├─────────────────────────────────┤
│  RF (Physical Layer)            │  ← Actual radio transmission
└─────────────────────────────────┘

Attacker's view:
  - RF layer   → jamming, passive eavesdropping
  - Link layer → pairing intercept, MitM
  - SMP layer  → encryption key weaknesses
  - Profile    → GATT auth bypass
  - App layer  → vulnerable BLE app logic
```

---

## 3. Pairing Process

### Classic Bluetooth: PIN-based

```
PIN Pairing (legacy, vulnerable):

  DeviceA ── "Let's pair!" ──→ DeviceB
  DeviceA ←─ "Enter PIN"  ──  DeviceB
  DeviceA ──  "1234"      ──→ DeviceB
  DeviceA ←─ "Connected"  ──  DeviceB

  Weaknesses:
  - Short PINs (4 digits) are brute-forceable
  - Eavesdropping during pairing can reveal the PIN
```

### SSP (Secure Simple Pairing)

```
SSP Methods:

1. Just Works (VULNERABLE)
   - Connects without any PIN — used for earbuds
   - Risk: MitM attack possible

2. Passkey Entry (Moderate)
   - One device shows 6-digit code → user types it on other device

3. Numeric Comparison (Strong)
   - Both devices display same 6-digit code → user confirms match

4. OOB (Out-of-Band, Strongest)
   - Keys exchanged via NFC or QR before Bluetooth connects
```

---

## 4. Attack Categories

### BlueSnarfing — Data Theft

```
Attack: Exploit OBEX protocol on "discoverable" legacy devices
Steal: Contacts, SMS, photos — without pairing
Status: Patched on modern devices; legacy IoT still vulnerable
```

### BlueJacking — Spam Delivery

```
Attack: Send a "contact card" with a crafted name containing a message
Effect: Target sees unsolicited pop-up (more annoying than harmful)
Risk: Social engineering — "click for prize"
```

### Bluebugging — Device Takeover

```
Attack: Send AT commands to vulnerable firmware
Result: Unauthorized calls, SMS, microphone activation (eavesdropping)
```

### KNOB Attack (CVE-2019-9506)

```
Attack: Force encryption key negotiation to 1 byte during pairing
Effect: Brute-force the session key in milliseconds
Status: Patched in most devices; unpatched legacy gear still at risk
```

---

## 5. Tools for Beginners

### Hardware

```
Tool              Price   Purpose
────────────────────────────────────────────
Ubertooth One    $120    BT packet capture / analysis
CSR8510 dongle   $5–10   Linux BLE scanning
RTL-SDR          $25     RF signal monitoring
Raspberry Pi     $35+    BT attack platform
HackRF One       $300    Wideband RF hacking
```

**Recommended starter**: CSR8510 USB dongle + software tools

### Software

```
Tool             Install             Purpose
─────────────────────────────────────────────────
bluetoothctl     built-in (BlueZ)   Scan / connect
hcitool          bluez-utils        Device discovery
bleak            pip install bleak  BLE Python library
gatttool         bluez              GATT attribute explorer
bettercap        apt install        Comprehensive network attack
```

### Useful Links

- Official Bluetooth Security Guide: https://www.bluetooth.com/learn-about-bluetooth/key-attributes/bluetooth-security/
- Ubertooth (open-source BT monitor hardware): https://github.com/greatscottgadgets/ubertooth

---

## 6. Lab: Scan Nearby Bluetooth Devices

### Setup

```bash
# Install BlueZ stack (Ubuntu/Kali)
sudo apt update && sudo apt install -y bluez bluez-tools

# Check interface
hciconfig -a

# Bring interface up
sudo hciconfig hci0 up
```

### CLI Scanning

```bash
# Classic Bluetooth (discoverable devices only)
sudo hcitool scan

# BLE devices
sudo hcitool lescan

# Interactive scan with bluetoothctl
bluetoothctl
  [bluetoothctl] power on
  [bluetoothctl] agent on
  [bluetoothctl] scan on
  # wait ~10 seconds
  [bluetoothctl] scan off
  [bluetoothctl] quit
```

### Python Scanner

See the Korean section for the full Python 3.10+ scanner script (`bluetooth_scanner.py`). Run it as:

```bash
sudo python3 bluetooth_scanner.py --timeout 15
```

---

## 7. Legal and Ethical Notice

```
Legal uses:
  ✓ Testing devices you own
  ✓ Environments with explicit written permission
  ✓ CTF / lab environments
  ✓ Responsible vulnerability disclosure

Illegal actions:
  ✗ Unauthorized scanning or accessing others' devices
  ✗ Collecting data without consent
  ✗ Bluetooth jamming / interference
```

## 8. Attack Detection and Defense Validation

The attack taxonomy (section 4) tells you *what* to block, but in practice two steps get skipped: **detecting that an attack actually happened** and **verifying your defense really works**.

### Attack -> layer -> control -> detection signal

| Attack | Target layer | Primary control (prevention) | Detection signal |
|---|---|---|---|
| BlueSnarfing | OBEX/profile | Reject unauthenticated OBEX, force pairing | Unauthenticated OBEX GET/PUT in hcidump |
| Bluebugging | RFCOMM/AT commands | Authenticate/disable AT command channel | Abnormal AT command sequences |
| KNOB | Key negotiation (entropy) | Enforce minimum entropy | Negotiation attempts of 1-3 byte keys |
| BlueJacking | Discovery/push | Non-discoverable mode, block unsolicited push | Many unsolicited OBEX pushes |

### Defense validation (verify yourself)

```bash
# KNOB resistance: does your device reject low-entropy key negotiation?
# Observe the LMP 'encryption key size' negotiation during pairing
sudo hcidump -X | grep -i "key size"
# OK:    negotiated key size >= policy minimum (e.g., 16 bytes)
# Weak:  if it settles at 1-3 bytes, you are exposed to KNOB
```

> Run validation only on **devices you own, in a controlled environment**. Having a defense enabled is not the same as it working - reproduce a known downgrade (KNOB) and unauthenticated access to confirm they are rejected (see [[68_Purple_Team]]).
