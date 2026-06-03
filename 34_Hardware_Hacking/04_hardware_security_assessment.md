> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 하드웨어 보안 평가 — 디바이스 감사·물리 보안·탬퍼 방지

## 0. 초보자를 위한 개념 이해

### 하드웨어 보안 평가란?

하드웨어 보안 평가(Hardware Security Assessment)는 IoT 기기, 임베디드 시스템, 산업용 장치 등의 물리적 하드웨어를 체계적으로 분석해 보안 취약점을 찾고 개선 방안을 제시하는 전문 보안 활동이다. 단순히 기기를 분해하는 것이 아니라 위협 모델링, 인터페이스 분석, 펌웨어 추출, 암호화 검증, 탬퍼 저항성 평가 등을 종합적으로 수행한다. 소프트웨어 패치로 고칠 수 없는 하드웨어 수준의 취약점을 찾아내는 것이 핵심 가치다.

**왜 배우는가:**
```
[하드웨어 보안 평가가 필요한 이유]

  네트워크 방화벽  →  우회 가능 (물리 접근 시)
  소프트웨어 패치  →  하드웨어 결함은 패치 불가
  원격 모니터링   →  물리 공격은 로그 없음

  [실제 취약 사례]
  공유기 → UART 포트 개방 → 부트로더 인터럽트 → root 쉘
  스마트 잠금장치 → JTAG → 펌웨어 추출 → 마스터 PIN 발견
  의료기기 → 디버그 포트 → 환자 데이터 접근
  ATM → 물리 포트 → 악성 코드 설치
```

### 핵심 개념 정리

```
[하드웨어 보안 평가 5단계 프레임워크]

1. 정보 수집 (Reconnaissance)
   - FCC ID 조회 → 내부 사진 공개 확인
   - 제조사 데이터시트, 특허 문서 검색
   - 기존 CVE 및 보안 연구 논문 조사

2. 비파괴 분석 (Non-destructive Analysis)
   - PCB 시각 검사 및 칩 식별
   - 디버그 포트(UART/JTAG) 위치 탐색
   - 전자기 방사 측정 (EM 분석)

3. 인터페이스 공략 (Interface Exploitation)
   - UART: 부트 로그 수집, 인터럽트 시도
   - JTAG: 메모리 덤프, 실행 중단
   - SPI/I2C: 플래시 직접 읽기

4. 펌웨어 분석 (Firmware Analysis)
   - binwalk로 파일시스템 추출
   - 하드코딩 자격증명, 취약 라이브러리 검색

5. 보고 및 개선 (Reporting)
   - CVSS 점수 부여, 영향도 평가
   - 탬퍼 저항, 보안 부팅 등 대응책 제안
```

### 필요한 도구 및 환경
- **하드웨어**: USB-UART 어댑터, JTAG 디버거(J-Link, Bus Pirate), SPI 클립
- **소프트웨어**: binwalk, OpenOCD, flashrom, Ghidra
- **측정 장비**: 멀티미터, 논리 분석기, 오실로스코프

### 기초 실습 예제
```python
import subprocess
import json
from pathlib import Path

def hardware_recon_checklist(device_name: str, fcc_id: str = None):
    """하드웨어 보안 평가 초기 정보 수집 체크리스트를 생성한다."""

    checklist = {
        "대상 기기": device_name,
        "FCC ID": fcc_id or "미확인",
        "수집 항목": {
            "데이터시트": False,
            "FCC 내부 사진": False,
            "기존 CVE 조회": False,
            "보안 연구 논문": False,
            "펌웨어 다운로드": False,
        },
        "인터페이스 탐색": {
            "UART 포트": "미확인",
            "JTAG/SWD 포트": "미확인",
            "SPI 플래시": "미확인",
            "USB 포트": "미확인",
            "네트워크 인터페이스": "미확인",
        },
        "예상 공격 표면": []
    }

    if fcc_id:
        print(f"[*] FCC ID 조회: https://fccid.io/{fcc_id}")
        print("    → 내부 사진, 테스트 보고서 공개 여부 확인")

    print(f"\n[*] {device_name} 평가 체크리스트:")
    print(json.dumps(checklist, ensure_ascii=False, indent=2))
    return checklist

# 사용 예시
# checklist = hardware_recon_checklist("ASUS RT-AX88U 공유기", "MSQRTAX88U")
```

---

## 이것이 무엇인가?

하드웨어 보안 평가(Hardware Security Assessment)란 임베디드 기기, IoT 디바이스, 산업용 컨트롤러 등의 **물리적 하드웨어를 직접 분석하여 취약점을 찾는** 작업이다.

**비유**: 소프트웨어 보안이 "자물쇠 암호를 해독"하는 것이라면, 하드웨어 보안은 "자물쇠 자체를 분해하여 내부 구조를 분석"하는 것이다.

현대 사이버 공격의 상당수는 소프트웨어가 아닌 하드웨어 수준에서 시작된다:
- 공유기의 UART 포트로 부트로더에 접근
- JTAG로 펌웨어 추출 → 취약점 오프라인 분석
- SPI 플래시 직독으로 암호화 키 추출
- 전력 분석(Power Analysis)으로 암호화 알고리즘 우회

---

## 왜 중요한가?

| 일반 소프트웨어 보안 | 하드웨어 보안 |
|--------------------|-------------|
| 네트워크 방화벽으로 차단 가능 | 물리적 접근 시 방화벽 우회 |
| 패치로 빠르게 수정 | 하드웨어 교체 비용 큼 |
| 원격 공격 | 물리적 접근 필요 (하지만 한번이면 충분) |
| 로그로 감지 | 물리 공격은 흔적 없음 |

특히 IoT 기기, 의료기기, 자동차, 산업제어시스템(ICS/SCADA)은 하드웨어 보안이 중요하다.

---

## 1. 하드웨어 보안 평가 방법론

### 평가 단계 개요

```
단계 1: 정보 수집 및 계획
    │  - 데이터시트, FCC ID, 특허 문서 수집
    │  - 위협 모델링
    │  - 평가 범위 정의
    ▼
단계 2: 외부 분석 (비파괴적)
    │  - PCB 육안 검사
    │  - 칩 식별 (제조사, 모델)
    │  - 인터페이스 핀 확인 (UART, JTAG, SPI 등)
    │  - FCC ID로 내부 사진 검색
    ▼
단계 3: 인터페이스 통신 시도
    │  - UART 연결 → 부트로더/셸 접근
    │  - JTAG 연결 → 디버그 접근, 메모리 덤프
    │  - SPI/I2C → 플래시 읽기/쓰기
    ▼
단계 4: 펌웨어 분석
    │  - 바이너리 추출
    │  - 파일시스템 언패킹 (binwalk)
    │  - 비밀키, 하드코딩된 자격증명 탐색
    │  - 취약한 함수 호출 분석 (Ghidra, IDA)
    ▼
단계 5: 사이드채널 분석 (고급)
    │  - 전력 분석 (ChipWhisperer)
    │  - 타이밍 공격
    │  - 전자기 분석 (EM)
    ▼
단계 6: 보고서 작성
         발견 취약점, 위험도, 권고사항
```

---

## 2. PCB 검사 체크리스트

### 2.1 육안 검사 항목

```
PCB (인쇄 회로 기판) 검사 시 확인할 것:

칩 식별:
[ ] 주 프로세서 제조사 및 모델 (예: Broadcom BCM2837)
[ ] 플래시 메모리 칩 (예: Winbond W25Q128)
[ ] RAM 칩 종류 (DRAM, SRAM)
[ ] 무선 모듈 (WiFi, BT, Zigbee 칩)
[ ] 보안 칩 (TPM, SE, HSM)
[ ] EEPROM (설정 저장용 소형 플래시)

인터페이스 탐색:
[ ] 테스트 포인트 (TP1, TP2, GND, VCC 등 레이블)
[ ] 미납땜 헤더 핀 (4핀, 6핀, 10핀 패드)
[ ] UART 패드 (보통 TX, RX, GND, VCC 4핀)
[ ] JTAG 패드 (보통 TDI, TDO, TCK, TMS, GND)
[ ] SPI 패드 (CLK, MISO, MOSI, CS, GND)
[ ] USB 디버그 커넥터

탬퍼 방지 확인:
[ ] 에폭시 충진 (칩 위에 검은/투명 수지)
[ ] 메시 쉴드 (탬퍼 감지 그물망)
[ ] 능동형 탬퍼 감지 회로
[ ] 케이스 나사 봉인 스티커
[ ] 볼 그리드 어레이(BGA) 패키지 (분리 어려움)
```

### 2.2 칩 식별 방법

```
칩 식별 순서:
1. 칩 표면의 텍스트 읽기 (확대경 또는 현미경 필요)
2. Google로 "칩모델 datasheet" 검색
3. datasheet.live, alldatasheet.com 활용
4. FCC ID 검색: fccid.io (내부 사진 포함)
5. 칩 로고로 제조사 식별

일반적인 칩 로고:
  Broadcom: "BRCM" 또는 곰 모양
  Qualcomm: "Q" 로고
  MediaTek: "MT" 접두사
  NXP: NXP 텍스트
  STMicroelectronics: "ST" 로고
  Renesas: "R" 로고
  Winbond: "W" 로고 (플래시 메모리)
  Microchip: "M" 로고
```

---

## 3. 디버그 인터페이스 시각적 식별 가이드

### 3.1 UART 핀 찾기

UART(Universal Asynchronous Receiver/Transmitter)는 임베디드 기기에서 가장 흔히 발견되는 디버그 인터페이스다.

```
UART 핀 배열 (일반적인 4핀):
┌─────┬─────┬─────┬─────┐
│ VCC │ GND │  TX │  RX │
│ 3.3V│  0V │출력 │입력 │
└─────┴─────┴─────┴─────┘

시각적 단서:
- PCB에 "CON1", "J1", "DEBUG" 레이블
- 4개의 미납땜 패드가 일렬로
- TX/RX/GND/VCC 실크스크린 텍스트
- 보통 프로세서 근처에 위치

전압 측정으로 핀 식별:
1. GND: 멀티미터로 0V 측정
2. VCC: 3.3V 또는 5V 측정
3. TX: 부팅 중 전압 변동 (데이터 전송)
4. RX: 고정 HIGH (3.3V) 또는 변동

UART-to-USB 변환기 연결 방법:
  PC USB → CH340/CP2102 모듈 → 대상 기기
  모듈 TX → 기기 RX
  모듈 RX → 기기 TX
  모듈 GND → 기기 GND
  (VCC는 선택적 — 기기가 이미 전원이 있으면 연결 불필요)
```

### 3.2 JTAG 핀 찾기

JTAG(Joint Test Action Group)는 프로세서 직접 제어, 메모리 덤프, 브레이크포인트 설정이 가능한 강력한 디버그 인터페이스다.

```
JTAG 핀 (최소 5개):
┌─────┬─────┬─────┬─────┬─────┐
│ TDI │ TDO │ TCK │ TMS │ GND │
│입력 │출력 │클럭 │모드 │접지 │
└─────┴─────┴─────┴─────┴─────┘

추가 핀: TRST (선택적 리셋), RTCK (리턴 클럭)

일반적인 JTAG 커넥터 형태:
10핀 ARM JTAG (0.1" 간격):
  1─VCC  2─TMS
  3─GND  4─TCK
  5─GND  6─TDO
  7─KEY  8─TDI
  9─GND  10─TRST/SRST

20핀 ARM 표준 JTAG:
  (Arm Cortex-M 시리즈에서 일반적)

찾는 방법:
1. JTAGulator (전용 하드웨어) 사용
   → 자동으로 JTAG 핀 식별
2. 멀티미터로 풀업 저항 핀 찾기
3. OpenOCD + 다양한 설정 파일 시도

SWD (Serial Wire Debug, ARM Cortex-M 전용):
  2핀으로 JTAG와 동등한 기능:
  SWDIO + SWDCLK + GND
```

### 3.3 SPI 플래시 찾기

SPI(Serial Peripheral Interface) 플래시는 펌웨어가 저장된 메모리 칩이다.

```
SPI 플래시 칩 외형:
- 8핀 SOIC 또는 DIP 패키지
- "25Qxxx" 또는 "25Fxxx" 모델명 (예: W25Q128)
- 보통 프로세서 근처 또는 하단에 위치

8핀 SPI 플래시 핀아웃:
┌─────┬─────────────────┬─────┐
│ /CS │   SO(MISO)      │ VCC │  ← 핀 1~4
│ /WP │   GND           │     │
├─────┼─────────────────┼─────┤
│ /HOLD│  SI(MOSI)      │ CLK │  ← 핀 5~8
└─────┴─────────────────┴─────┘

핀 1 식별: 칩 모서리의 작은 점 또는 노치

직접 읽기 방법:
Option A: 클립으로 전원 켜진 상태에서 읽기 (In-circuit)
  flashrom -p linux_spi:dev=/dev/spidev0.0 -r firmware.bin

Option B: 칩 탈착 후 읽기 (더 안전)
  소켓 어댑터 + 프로그래머 사용 (CH341A, 약 $5)
```

---

## 4. 임베디드 기기 위협 모델링

### 4.1 STRIDE 적용

```
위협 유형별 하드웨어 공격 예시:

S — Spoofing (신원 위조)
  - 클론된 기기로 정품 행세
  - 위조 펌웨어 서명

T — Tampering (변조)
  - 플래시 메모리 직접 수정
  - 악성 펌웨어 플래싱
  - 하드웨어 백도어 설치

R — Repudiation (부인)
  - 로그 삭제 (플래시 직접 수정)
  - 시계 조작으로 감사 추적 왜곡

I — Information Disclosure (정보 누출)
  - UART로 부트 로그 열람
  - SPI 플래시에서 키 추출
  - JTAG로 RAM 덤프

D — Denial of Service (서비스 거부)
  - 전압 글리칭으로 충돌
  - EM 펄스로 리셋
  - 탬퍼 감지 강제 트리거

E — Elevation of Privilege (권한 상승)
  - 부트로더에서 루트 셸 획득
  - JTAG로 권한 검사 우회
  - 볼타지 폴트 인젝션으로 보안 검사 건너뛰기
```

### 4.2 공격 트리 예시 (도어락)

```
[목표: 스마트 도어락 무단 개방]
│
├── 소프트웨어 공격
│   ├── 모바일 앱 취약점 분석
│   ├── BLE 프로토콜 스니핑
│   └── 클라우드 API 취약점
│
└── 하드웨어 공격
    ├── UART 접근
    │   ├── 부트로더 인터럽트
    │   └── 루트 셸 획득 → 인증 로직 수정
    │
    ├── 펌웨어 추출
    │   ├── SPI 플래시 직접 읽기
    │   └── 취약점 오프라인 분석
    │
    └── 전압 글리칭
        └── 인증 코드 CPU 실행 건너뛰기
```

---

## 5. 하드웨어 인터페이스 자동 탐지 도구

```python
#!/usr/bin/env python3
"""hw_assess.py — 하드웨어 보안 평가 자동화 CLI.

Usage:
    python hw_assess.py scan
    python hw_assess.py uart --port /dev/ttyUSB0
    python hw_assess.py jtag --interface ft232r --target stm32f1x
    python hw_assess.py serial-enum
    python hw_assess.py report -o report.json
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class InterfaceResult:
    interface_type: str
    port: str
    detected: bool
    baud_rate: int | None = None
    protocol: str | None = None
    notes: str = ""


@dataclass
class AssessmentReport:
    timestamp: str
    uart_ports: list[dict]
    usb_devices: list[dict]
    spi_flash: dict
    jtag_result: dict
    i2c_devices: list[dict]
    summary: list[str]


# ---------------------------------------------------------------------------
# UART detection
# ---------------------------------------------------------------------------

def detect_uart_ports() -> list[InterfaceResult]:
    """Detect available UART/serial ports on Linux."""
    uart_paths = (
        list(Path("/dev").glob("ttyUSB*"))
        + list(Path("/dev").glob("ttyACM*"))
        + list(Path("/dev").glob("ttyS[0-9]"))
    )
    results = []
    for port in uart_paths:
        results.append(InterfaceResult(
            interface_type="UART",
            port=str(port),
            detected=True,
            notes="Serial port present — attempt baud detection",
        ))
    return results


def probe_uart_baud(port: str, bauds: list[int] | None = None) -> int | None:
    """Auto-detect UART baud rate by checking printable character ratio."""
    if bauds is None:
        bauds = [9600, 19200, 38400, 57600, 115200, 230400, 460800]

    try:
        import serial  # pyserial
    except ImportError:
        print("[!] pyserial 없음: pip install pyserial", file=sys.stderr)
        return None

    for baud in bauds:
        try:
            with serial.Serial(port, baud, timeout=1) as ser:
                data = ser.read(64)
                if not data:
                    continue
                printable = sum(
                    1 for b in data if 0x20 <= b <= 0x7E or b in (0x0A, 0x0D)
                )
                if printable / len(data) > 0.7:
                    return baud
        except Exception:
            pass
    return None


def enumerate_serial_ports() -> list[dict]:
    """Use pyserial to list all serial ports with metadata."""
    try:
        from serial.tools import list_ports
        return [
            {
                "device": p.device,
                "description": p.description,
                "hwid": p.hwid,
                "vid": hex(p.vid) if p.vid else None,
                "pid": hex(p.pid) if p.pid else None,
                "manufacturer": p.manufacturer,
            }
            for p in list_ports.comports()
        ]
    except ImportError:
        return [{"error": "pyserial not installed — pip install pyserial"}]


# ---------------------------------------------------------------------------
# JTAG detection via OpenOCD
# ---------------------------------------------------------------------------

def detect_jtag(interface_cfg: str, target_cfg: str) -> dict:
    """Probe JTAG via OpenOCD; requires openocd on PATH."""
    interface_map = {
        "ft232r":    "interface/ftdi/ft232r.cfg",
        "ft2232h":   "interface/ftdi/ft2232h.cfg",
        "jlink":     "interface/jlink.cfg",
        "stlink":    "interface/stlink.cfg",
        "raspberrypi": "interface/raspberrypi-native.cfg",
    }
    target_map = {
        "stm32f1x": "target/stm32f1x.cfg",
        "stm32f4x": "target/stm32f4x.cfg",
        "lpc1768":  "target/lpc1768.cfg",
        "esp32":    "target/esp32.cfg",
        "rpi":      "target/bcm2837.cfg",
    }

    iface = interface_map.get(interface_cfg, interface_cfg)
    tgt   = target_map.get(target_cfg, target_cfg)

    try:
        result = subprocess.run(
            ["openocd", "-f", iface, "-f", tgt, "-c", "init; scan_chain; exit"],
            capture_output=True, text=True, timeout=10,
        )
        out = result.stdout + result.stderr
        detected = "tap/device found" in out.lower() or "idcode" in out.lower()
        return {"detected": detected, "interface": iface, "target": tgt, "output": out[:500]}
    except FileNotFoundError:
        return {"detected": False, "error": "openocd not installed"}
    except subprocess.TimeoutExpired:
        return {"detected": False, "error": "timeout — check wiring"}


# ---------------------------------------------------------------------------
# USB devices
# ---------------------------------------------------------------------------

def scan_usb_devices() -> list[dict]:
    """List connected USB devices via lsusb."""
    devices: list[dict] = []
    try:
        result = subprocess.run(["lsusb"], capture_output=True, text=True, timeout=5)
        for line in result.stdout.splitlines():
            parts = line.split(maxsplit=6)
            if len(parts) >= 6:
                devices.append({
                    "bus": parts[1],
                    "device": parts[3].rstrip(":"),
                    "id": parts[5],
                    "name": parts[6] if len(parts) > 6 else "",
                })
    except FileNotFoundError:
        devices.append({"error": "lsusb not found (Linux only)"})
    return devices


# ---------------------------------------------------------------------------
# SPI flash
# ---------------------------------------------------------------------------

def check_spi_flash(device: str = "/dev/spidev0.0") -> dict:
    """Check SPI flash presence and attempt chip identification."""
    result: dict = {"device": device, "accessible": Path(device).exists()}
    if not result["accessible"]:
        result["notes"] = "Device not present — may need kernel module: modprobe spi_bcm2835"
        return result
    try:
        probe = subprocess.run(
            ["flashrom", "-p", f"linux_spi:dev={device}", "--flash-name"],
            capture_output=True, text=True, timeout=15,
        )
        result["chip"] = probe.stdout.strip()
        result["detected"] = probe.returncode == 0
        if not result["detected"]:
            result["stderr"] = probe.stderr[:200]
    except FileNotFoundError:
        result["error"] = "flashrom not installed — apt install flashrom"
    return result


# ---------------------------------------------------------------------------
# I2C device scan
# ---------------------------------------------------------------------------

def scan_i2c_devices(bus: int = 1) -> list[dict]:
    """Use i2cdetect to find I2C devices."""
    devices: list[dict] = []
    try:
        result = subprocess.run(
            ["i2cdetect", "-y", str(bus)],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines()[1:]:
                parts = line.split()
                if len(parts) > 1:
                    row_prefix = int(parts[0].rstrip(":"), 16)
                    for col, val in enumerate(parts[1:]):
                        if val not in ("--", "UU"):
                            addr = row_prefix + col
                            devices.append({"bus": bus, "address": hex(addr), "raw": val})
    except FileNotFoundError:
        devices.append({"error": "i2cdetect not found — apt install i2c-tools"})
    return devices


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def generate_report(results: dict, output: Path | None) -> None:
    print("\n" + "=" * 60)
    print("하드웨어 인터페이스 보안 평가 결과")
    print("=" * 60)

    uart_ports = results.get("uart_ports", [])
    print(f"\n[UART] {len(uart_ports)}개 포트 발견")
    for p in uart_ports:
        icon = "[+]" if p.get("detected") else "[-]"
        baud = f"  보레이트: {p['baud_rate']}" if p.get("baud_rate") else ""
        print(f"  {icon} {p['port']}{baud}")
        if p.get("notes"):
            print(f"      {p['notes']}")

    serial_ports = results.get("serial_ports", [])
    print(f"\n[시리얼 포트 상세] {len(serial_ports)}개")
    for sp in serial_ports:
        if "error" not in sp:
            print(f"  {sp['device']} — {sp['description']} [{sp.get('manufacturer', 'N/A')}]")

    usb_devices = results.get("usb_devices", [])
    print(f"\n[USB 디바이스] {len(usb_devices)}개")
    for dev in usb_devices[:8]:
        if "error" not in dev:
            print(f"  {dev.get('id', '')} — {dev.get('name', '')}")

    spi = results.get("spi_flash", {})
    if spi.get("detected"):
        print(f"\n[SPI 플래시] 탐지: {spi.get('chip', '알 수 없음')}")
        print("  [!] 주의: 플래시를 직접 읽을 수 있음 — 암호화 여부 확인 필요")
    elif spi.get("accessible"):
        print(f"\n[SPI 플래시] 장치 접근 가능하나 칩 미탐지")
    else:
        print(f"\n[SPI 플래시] {spi.get('device', '/dev/spidev0.0')} 없음")

    i2c = results.get("i2c_devices", [])
    if i2c and "error" not in i2c[0]:
        print(f"\n[I2C] {len(i2c)}개 디바이스 발견")
        for dev in i2c:
            print(f"  버스 {dev['bus']}, 주소 {dev['address']}")

    jtag = results.get("jtag_result", {})
    if jtag.get("detected"):
        print(f"\n[JTAG] 탐지됨!")
        print("  [!] 경고: JTAG 활성화 — 디버그 비활성화 권고")
    elif jtag.get("error"):
        print(f"\n[JTAG] {jtag['error']}")

    print("\n" + "=" * 60)
    print("권고사항:")
    summary = results.get("summary", [])
    for item in summary:
        print(f"  {item}")

    if output:
        output.write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"\n[+] 결과 저장: {output}")


def build_summary(results: dict) -> list[str]:
    items = []
    if results.get("uart_ports"):
        items.append("[!] UART 포트 발견 — 물리적 접근 시 루트 셸 위험")
    if results.get("spi_flash", {}).get("detected"):
        items.append("[!] SPI 플래시 직접 접근 가능 — 펌웨어 암호화 확인")
    if results.get("jtag_result", {}).get("detected"):
        items.append("[!] JTAG 활성화 — 프로덕션 기기에서 비활성화 필수")
    if not items:
        items.append("[+] 명백한 디버그 인터페이스 미발견 (심층 분석 권고)")
    return items


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="하드웨어 보안 평가 자동화 (Linux)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
사용 예시:
  python hw_assess.py scan                          # 전체 스캔
  python hw_assess.py uart --port /dev/ttyUSB0      # UART 보레이트 탐지
  python hw_assess.py serial-enum                   # 시리얼 포트 상세 목록
  python hw_assess.py jtag --interface jlink        # JTAG 탐지
  python hw_assess.py i2c --bus 1                   # I2C 스캔
  python hw_assess.py report -o hw_report.json      # 보고서 생성
        """,
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("scan", help="전체 인터페이스 빠른 스캔").add_argument(
        "-o", "--output", type=Path
    )

    p_uart = sub.add_parser("uart", help="UART 포트 보레이트 자동 탐지")
    p_uart.add_argument("--port", required=True, help="포트 (예: /dev/ttyUSB0)")
    p_uart.add_argument(
        "--bauds", nargs="+", type=int,
        default=[9600, 19200, 38400, 57600, 115200, 230400],
    )

    sub.add_parser("serial-enum", help="pyserial로 시리얼 포트 상세 열거")

    p_jtag = sub.add_parser("jtag", help="OpenOCD로 JTAG 탐지")
    p_jtag.add_argument("--interface", default="ft232r",
                        help="인터페이스 프리셋 또는 .cfg 경로")
    p_jtag.add_argument("--target", default="stm32f1x",
                        help="타깃 프리셋 또는 .cfg 경로")

    p_i2c = sub.add_parser("i2c", help="I2C 버스 디바이스 스캔")
    p_i2c.add_argument("--bus", type=int, default=1)

    p_report = sub.add_parser("report", help="전체 평가 보고서 생성")
    p_report.add_argument("-o", "--output", type=Path)

    args = parser.parse_args()

    match args.cmd:
        case "scan":
            uart_ports = [asdict(r) for r in detect_uart_ports()]
            results = {
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "uart_ports": uart_ports,
                "serial_ports": enumerate_serial_ports(),
                "usb_devices": scan_usb_devices(),
                "spi_flash": check_spi_flash(),
                "jtag_result": {},
                "i2c_devices": scan_i2c_devices(),
                "summary": [],
            }
            results["summary"] = build_summary(results)
            generate_report(results, getattr(args, "output", None))

        case "uart":
            print(f"[*] {args.port} 보레이트 탐지 중 (시도: {args.bauds})...")
            baud = probe_uart_baud(args.port, args.bauds)
            if baud:
                print(f"[+] 보레이트: {baud} bps")
                print(f"    접속: minicom -D {args.port} -b {baud}")
                print(f"          screen {args.port} {baud}")
            else:
                print("[-] 보레이트 탐지 실패 (기기가 조용하거나 전압 불일치)")

        case "serial-enum":
            ports = enumerate_serial_ports()
            print(f"[*] 시리얼 포트 {len(ports)}개:")
            for p in ports:
                if "error" in p:
                    print(f"  [!] {p['error']}")
                else:
                    print(f"  {p['device']}")
                    print(f"      설명: {p['description']}")
                    print(f"      제조사: {p.get('manufacturer', 'N/A')}")
                    if p.get("vid"):
                        print(f"      VID:PID = {p['vid']}:{p.get('pid', 'N/A')}")

        case "jtag":
            print(f"[*] JTAG 탐지 중: {args.interface} / {args.target}")
            result = detect_jtag(args.interface, args.target)
            if result.get("detected"):
                print("[+] JTAG 디바이스 탐지!")
                print(f"    인터페이스: {result['interface']}")
                print(f"    타깃: {result['target']}")
            else:
                print(f"[-] JTAG 미탐지: {result.get('error', ''[:100])}")
                if result.get("output"):
                    print(f"    출력: {result['output'][:200]}")

        case "i2c":
            print(f"[*] I2C 버스 {args.bus} 스캔 중...")
            devices = scan_i2c_devices(args.bus)
            if devices and "error" not in devices[0]:
                print(f"[+] {len(devices)}개 I2C 디바이스:")
                for dev in devices:
                    print(f"  버스 {dev['bus']}, 주소 {dev['address']}")
            elif devices:
                print(f"[!] {devices[0]['error']}")
            else:
                print("[-] I2C 디바이스 미발견")

        case "report":
            uart_ports = [asdict(r) for r in detect_uart_ports()]
            results = {
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "uart_ports": uart_ports,
                "serial_ports": enumerate_serial_ports(),
                "usb_devices": scan_usb_devices(),
                "spi_flash": check_spi_flash(),
                "jtag_result": {},
                "i2c_devices": scan_i2c_devices(),
                "summary": [],
            }
            results["summary"] = build_summary(results)
            generate_report(results, args.output)


if __name__ == "__main__":
    main()
```

---

## 6. TPM/HSM 보안 점검

```bash
# TPM 존재 및 버전 확인
ls /dev/tpm* 2>/dev/null && echo "TPM 존재" || echo "TPM 없음"
cat /sys/class/tpm/tpm0/tpm_version_major 2>/dev/null
tpm2_getcap properties-fixed 2>/dev/null | head -20

# TPM 제조사·펌웨어 정보
tpm2_getcap properties-fixed 2>/dev/null | grep -E "TPM2_PT_(MANUFACTURER|VENDOR|FIRMWARE)"

# Secure Boot 상태
mokutil --sb-state 2>/dev/null
efivar --list 2>/dev/null | grep -i secure

# 부팅 체인 검증
dmesg | grep -i "secure boot\|tpm\|measured boot"

# 디스크 암호화 상태
lsblk -f | grep -E "crypto_LUKS|BitLocker"
```

---

## 7. 평가 보고서 템플릿

```markdown
# 하드웨어 보안 평가 보고서

**평가 대상**: [기기명 및 모델]
**평가 일자**: [날짜]
**평가자**: [이름]
**분류**: [기밀/내부용/공개]

---

## 요약

[2~3문장으로 전체 평가 결과 요약]

심각도: [Critical / High / Medium / Low]
주요 발견사항 수: [숫자]

---

## 평가 범위

- 대상 기기: [모델, 펌웨어 버전]
- 평가 방법: 외부 검사, 인터페이스 분석, 펌웨어 추출
- 제외 항목: [범위 밖 항목]

---

## 발견사항

### [ID]-001: UART 디버그 포트 활성화
**심각도**: High
**위치**: J4 커넥터, PCB 하단
**설명**: 115200 bps UART 포트를 통해 루트 셸 접근 가능
**증거**: [스크린샷 또는 출력 로그]
**권고사항**: 프로덕션 빌드에서 UART 비활성화 또는 제거

### [ID]-002: SPI 플래시 미암호화
**심각도**: High  
**설명**: 펌웨어가 평문으로 SPI 플래시에 저장됨
**권고사항**: AES-128 이상으로 펌웨어 암호화

---

## 기술적 세부사항

[기술적 증거, PCB 사진, 통신 로그 등]

---

## 권고사항 요약

| 우선순위 | 항목 | 예상 난이도 |
|---------|------|-----------|
| 즉시 | UART 비활성화 | 낮음 |
| 단기 | 펌웨어 서명 | 중간 |
| 중기 | 펌웨어 암호화 | 높음 |

---

## 참고 자료

- OWASP IoT Security Testing Guide
- NIST SP 800-193 (Platform Firmware Resiliency Guidelines)
```

---

## 8. 하드웨어 보안 평가 체크리스트

| 항목 | 점검 방법 | 통과 기준 |
|------|-----------|-----------|
| JTAG/UART 비활성화 | 핀 물리 점검 + 통신 시도 | 응답 없음 |
| 펌웨어 서명 | 서명 파일 + 공개키 검증 | RSA/EC 서명 확인 |
| 부팅 체인 | Secure Boot 상태 확인 | Secure Boot 활성화 |
| 디버그 포트 | JTAG/SWD 전압 측정 | 핀 비활성 또는 제거 |
| 탬퍼 감지 | 물리 검사 | 에폭시/메시 존재 |
| 민감 키 저장 | 소스 코드 분석 | HSM/TPM 사용 |
| SPI 플래시 | flashrom 읽기 시도 | 암호화 또는 읽기 불가 |
| 사이드채널 | ChipWhisperer 분석 | 마스킹 적용 확인 |
| 기본 자격증명 | UART/웹 인터페이스 로그인 | 기본값 없음 |
| 펌웨어 업데이트 | OTA 패킷 캡처 | 서명 + 암호화 검증 |

---

---

<a name="english"></a>

# Hardware Security Assessment — Device Auditing, Physical Security, and Tamper Protection

## What Is This?

A Hardware Security Assessment is the process of **directly analyzing embedded devices, IoT hardware, industrial controllers, and similar physical hardware to find vulnerabilities**.

**Analogy**: If software security is "deciphering a lock's combination," hardware security is "disassembling the lock itself and analyzing its internal structure."

A significant portion of modern cyberattacks starts at the hardware level, not software:
- Accessing the bootloader via a router's UART port
- Extracting firmware through JTAG for offline vulnerability analysis
- Reading SPI flash directly to extract cryptographic keys
- Bypassing cryptographic algorithms via Power Analysis (Side-Channel)

---

## Why Does It Matter?

| General Software Security | Hardware Security |
|--------------------------|-------------------|
| Blockable by network firewall | Physical access bypasses firewalls |
| Quickly fixed with patches | Hardware replacement is expensive |
| Remote attacks | Physical access required (but once is enough) |
| Detectable via logs | Physical attacks leave no traces |

Hardware security is especially critical for IoT devices, medical equipment, automobiles, and industrial control systems (ICS/SCADA).

---

## 1. Hardware Security Assessment Methodology

### Phase Overview

```
Phase 1: Intelligence Gathering and Planning
    │  - Collect datasheets, FCC ID, patent documents
    │  - Threat modeling
    │  - Define assessment scope
    ▼
Phase 2: External Analysis (Non-destructive)
    │  - Visual PCB inspection
    │  - Chip identification (vendor, model)
    │  - Interface pin identification (UART, JTAG, SPI, etc.)
    │  - FCC ID internal photo search
    ▼
Phase 3: Interface Communication Attempts
    │  - UART connection → bootloader/shell access
    │  - JTAG connection → debug access, memory dump
    │  - SPI/I2C → flash read/write
    ▼
Phase 4: Firmware Analysis
    │  - Binary extraction
    │  - Filesystem unpacking (binwalk)
    │  - Secret keys, hardcoded credential search
    │  - Vulnerable function call analysis (Ghidra, IDA)
    ▼
Phase 5: Side-Channel Analysis (Advanced)
    │  - Power analysis (ChipWhisperer)
    │  - Timing attacks
    │  - Electromagnetic analysis (EM)
    ▼
Phase 6: Report Writing
         Found vulnerabilities, risk ratings, recommendations
```

---

## 2. PCB Inspection Checklist

### 2.1 Visual Inspection Items

```
What to check when inspecting a PCB (Printed Circuit Board):

Chip Identification:
[ ] Main processor vendor and model (e.g., Broadcom BCM2837)
[ ] Flash memory chip (e.g., Winbond W25Q128)
[ ] RAM chip type (DRAM, SRAM)
[ ] Wireless module (WiFi, BT, Zigbee chip)
[ ] Security chip (TPM, SE, HSM)
[ ] EEPROM (small flash for configuration storage)

Interface Discovery:
[ ] Test points (TP1, TP2, GND, VCC labels, etc.)
[ ] Unpopulated header pins (4-pin, 6-pin, 10-pin pads)
[ ] UART pads (typically TX, RX, GND, VCC — 4 pins)
[ ] JTAG pads (typically TDI, TDO, TCK, TMS, GND)
[ ] SPI pads (CLK, MISO, MOSI, CS, GND)
[ ] USB debug connector

Tamper Protection Verification:
[ ] Epoxy potting (black/clear resin over chips)
[ ] Mesh shielding (tamper detection wire mesh)
[ ] Active tamper detection circuit
[ ] Case screw tamper-evident stickers
[ ] Ball Grid Array (BGA) packages (difficult to remove)
```

---

## 3. Debug Interface Visual Identification Guide

### 3.1 Finding UART Pins

UART (Universal Asynchronous Receiver/Transmitter) is the most commonly found debug interface on embedded devices.

```
UART Pin Layout (typical 4-pin):
┌─────┬─────┬─────┬─────┐
│ VCC │ GND │  TX │  RX │
│3.3V │  0V │Out  │ In  │
└─────┴─────┴─────┴─────┘

Visual clues:
- "CON1", "J1", "DEBUG" labels on PCB
- 4 unpopulated pads in a row
- TX/RX/GND/VCC silkscreen text
- Usually located near the processor

Identifying pins with a multimeter:
1. GND: Measure 0V
2. VCC: Measure 3.3V or 5V
3. TX: Voltage fluctuates during boot (data transmission)
4. RX: Fixed HIGH (3.3V) or variable

UART-to-USB adapter connection:
  PC USB → CH340/CP2102 module → target device
  Module TX → Device RX
  Module RX → Device TX
  Module GND → Device GND
  (VCC is optional — skip if device has its own power)
```

### 3.2 Finding JTAG Pins

JTAG (Joint Test Action Group) is a powerful debug interface enabling direct processor control, memory dumps, and breakpoints.

```
JTAG Pins (minimum 5):
┌─────┬─────┬─────┬─────┬─────┐
│ TDI │ TDO │ TCK │ TMS │ GND │
│ In  │ Out │Clock│Mode │GND  │
└─────┴─────┴─────┴─────┴─────┘

Additional pins: TRST (optional reset), RTCK (return clock)

Common JTAG connector form:
10-pin ARM JTAG (0.1" pitch):
  1─VCC  2─TMS
  3─GND  4─TCK
  5─GND  6─TDO
  7─KEY  8─TDI
  9─GND  10─TRST/SRST

Finding methods:
1. JTAGulator (dedicated hardware) — auto-identifies JTAG pins
2. Multimeter to find pull-up resistor pins
3. Try OpenOCD with various config files

SWD (Serial Wire Debug, ARM Cortex-M only):
  Equivalent to JTAG with only 2 signal pins:
  SWDIO + SWDCLK + GND
```

### 3.3 Finding SPI Flash

SPI (Serial Peripheral Interface) flash is the memory chip where firmware is stored.

```
SPI flash chip appearance:
- 8-pin SOIC or DIP package
- Model name like "25Qxxx" or "25Fxxx" (e.g., W25Q128)
- Usually located near or under the processor

8-pin SPI flash pinout:
  Pin 1: /CS (Chip Select)
  Pin 2: SO/MISO (data output)
  Pin 3: /WP (Write Protect)
  Pin 4: GND
  Pin 5: /HOLD
  Pin 6: SI/MOSI (data input)
  Pin 7: CLK
  Pin 8: VCC

Pin 1 identification: small dot or notch on chip corner

Reading methods:
Option A: In-circuit read (with power on)
  flashrom -p linux_spi:dev=/dev/spidev0.0 -r firmware.bin

Option B: Desolder and read (safer)
  Socket adapter + programmer (CH341A, ~$5)
```

---

## 4. Embedded Device Threat Modeling

### 4.1 STRIDE Applied to Hardware

```
Threat type → Hardware attack examples:

S — Spoofing
  - Cloned device impersonating legitimate one
  - Forged firmware signatures

T — Tampering
  - Direct flash memory modification
  - Malicious firmware flashing
  - Hardware backdoor installation

R — Repudiation
  - Log deletion (direct flash modification)
  - Clock manipulation to distort audit trails

I — Information Disclosure
  - Reading boot logs via UART
  - Extracting keys from SPI flash
  - RAM dump via JTAG

D — Denial of Service
  - Crash via voltage glitching
  - Reset via EM pulse
  - Force-triggering tamper detection

E — Elevation of Privilege
  - Root shell from bootloader via UART
  - Bypassing privilege checks via JTAG
  - Skipping security checks via voltage fault injection
```

---

## 5. Automated Hardware Interface Detection Tool

```python
#!/usr/bin/env python3
"""hw_assess.py — Hardware security assessment automation CLI (Linux).

Usage:
    python hw_assess.py scan
    python hw_assess.py uart --port /dev/ttyUSB0
    python hw_assess.py serial-enum
    python hw_assess.py jtag --interface jlink --target stm32f4x
    python hw_assess.py i2c --bus 1
    python hw_assess.py report -o hw_report.json
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass
class InterfaceResult:
    interface_type: str
    port: str
    detected: bool
    baud_rate: int | None = None
    notes: str = ""


def detect_uart_ports() -> list[InterfaceResult]:
    uart_paths = (
        list(Path("/dev").glob("ttyUSB*"))
        + list(Path("/dev").glob("ttyACM*"))
        + list(Path("/dev").glob("ttyS[0-9]"))
    )
    return [
        InterfaceResult("UART", str(p), True, notes="Serial port present")
        for p in uart_paths
    ]


def probe_uart_baud(port: str, bauds: list[int] | None = None) -> int | None:
    if bauds is None:
        bauds = [9600, 19200, 38400, 57600, 115200, 230400, 460800]
    try:
        import serial
    except ImportError:
        print("[!] pip install pyserial", file=sys.stderr)
        return None
    for baud in bauds:
        try:
            with serial.Serial(port, baud, timeout=1) as ser:
                data = ser.read(64)
                if data:
                    printable = sum(1 for b in data if 0x20 <= b <= 0x7E or b in (0x0A, 0x0D))
                    if printable / len(data) > 0.7:
                        return baud
        except Exception:
            pass
    return None


def enumerate_serial_ports() -> list[dict]:
    try:
        from serial.tools import list_ports
        return [
            {"device": p.device, "description": p.description,
             "manufacturer": p.manufacturer, "vid": hex(p.vid) if p.vid else None}
            for p in list_ports.comports()
        ]
    except ImportError:
        return [{"error": "pip install pyserial"}]


def scan_usb_devices() -> list[dict]:
    try:
        r = subprocess.run(["lsusb"], capture_output=True, text=True, timeout=5)
        devices = []
        for line in r.stdout.splitlines():
            parts = line.split(maxsplit=6)
            if len(parts) >= 6:
                devices.append({"id": parts[5], "name": parts[6] if len(parts) > 6 else ""})
        return devices
    except FileNotFoundError:
        return [{"error": "lsusb not available"}]


def check_spi_flash(device: str = "/dev/spidev0.0") -> dict:
    result: dict = {"device": device, "accessible": Path(device).exists()}
    if not result["accessible"]:
        return result
    try:
        probe = subprocess.run(
            ["flashrom", "-p", f"linux_spi:dev={device}", "--flash-name"],
            capture_output=True, text=True, timeout=15,
        )
        result["chip"] = probe.stdout.strip()
        result["detected"] = probe.returncode == 0
    except FileNotFoundError:
        result["error"] = "flashrom not installed"
    return result


def scan_i2c_devices(bus: int = 1) -> list[dict]:
    devices: list[dict] = []
    try:
        r = subprocess.run(["i2cdetect", "-y", str(bus)], capture_output=True, text=True, timeout=10)
        if r.returncode == 0:
            for line in r.stdout.splitlines()[1:]:
                parts = line.split()
                if len(parts) > 1:
                    row = int(parts[0].rstrip(":"), 16)
                    for col, val in enumerate(parts[1:]):
                        if val not in ("--", "UU"):
                            devices.append({"bus": bus, "address": hex(row + col)})
    except FileNotFoundError:
        devices.append({"error": "i2cdetect not found — apt install i2c-tools"})
    return devices


def detect_jtag(interface: str, target: str) -> dict:
    iface_map = {
        "ft232r": "interface/ftdi/ft232r.cfg",
        "jlink": "interface/jlink.cfg",
        "stlink": "interface/stlink.cfg",
    }
    tgt_map = {
        "stm32f1x": "target/stm32f1x.cfg",
        "stm32f4x": "target/stm32f4x.cfg",
        "esp32": "target/esp32.cfg",
    }
    iface = iface_map.get(interface, interface)
    tgt = tgt_map.get(target, target)
    try:
        r = subprocess.run(
            ["openocd", "-f", iface, "-f", tgt, "-c", "init; scan_chain; exit"],
            capture_output=True, text=True, timeout=10,
        )
        out = r.stdout + r.stderr
        detected = "tap/device found" in out.lower() or "idcode" in out.lower()
        return {"detected": detected, "interface": iface, "target": tgt, "output": out[:400]}
    except FileNotFoundError:
        return {"detected": False, "error": "openocd not installed"}
    except subprocess.TimeoutExpired:
        return {"detected": False, "error": "timeout — check wiring"}


def main() -> None:
    ap = argparse.ArgumentParser(description="Hardware Security Assessment (Linux)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_scan = sub.add_parser("scan", help="Quick interface scan")
    p_scan.add_argument("-o", "--output", type=Path)

    p_uart = sub.add_parser("uart", help="UART baud rate detection")
    p_uart.add_argument("--port", required=True)
    p_uart.add_argument("--bauds", nargs="+", type=int)

    sub.add_parser("serial-enum", help="Enumerate serial ports via pyserial")

    p_jtag = sub.add_parser("jtag", help="JTAG detection via OpenOCD")
    p_jtag.add_argument("--interface", default="ft232r")
    p_jtag.add_argument("--target", default="stm32f1x")

    p_i2c = sub.add_parser("i2c", help="Scan I2C bus")
    p_i2c.add_argument("--bus", type=int, default=1)

    p_rep = sub.add_parser("report", help="Full assessment report")
    p_rep.add_argument("-o", "--output", type=Path)

    args = ap.parse_args()

    match args.cmd:
        case "scan" | "report":
            results = {
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "uart_ports": [asdict(r) for r in detect_uart_ports()],
                "serial_ports": enumerate_serial_ports(),
                "usb_devices": scan_usb_devices(),
                "spi_flash": check_spi_flash(),
                "i2c_devices": scan_i2c_devices(),
                "jtag_result": {},
            }
            print(json.dumps(results, indent=2, ensure_ascii=False))
            if getattr(args, "output", None):
                args.output.write_text(
                    json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8"
                )
                print(f"[+] Report saved: {args.output}")

        case "uart":
            baud = probe_uart_baud(args.port, args.bauds)
            if baud:
                print(f"[+] Baud rate: {baud}")
                print(f"    Connect: minicom -D {args.port} -b {baud}")
            else:
                print("[-] Baud rate not detected")

        case "serial-enum":
            for p in enumerate_serial_ports():
                print(json.dumps(p, indent=2))

        case "jtag":
            result = detect_jtag(args.interface, args.target)
            if result.get("detected"):
                print("[+] JTAG device found!")
            else:
                print(f"[-] No JTAG: {result.get('error', result.get('output', ''))[:200]}")

        case "i2c":
            for dev in scan_i2c_devices(args.bus):
                print(dev)


if __name__ == "__main__":
    main()
```

---

## 6. TPM/HSM Security Inspection

```bash
# Check TPM presence and version
ls /dev/tpm* 2>/dev/null && echo "TPM present" || echo "No TPM"
cat /sys/class/tpm/tpm0/tpm_version_major 2>/dev/null
tpm2_getcap properties-fixed 2>/dev/null | head -20

# TPM manufacturer and firmware info
tpm2_getcap properties-fixed 2>/dev/null | grep -E "TPM2_PT_(MANUFACTURER|VENDOR|FIRMWARE)"

# Secure Boot status
mokutil --sb-state 2>/dev/null
efivar --list 2>/dev/null | grep -i secure

# Boot chain validation
dmesg | grep -i "secure boot\|tpm\|measured boot"

# Disk encryption status
lsblk -f | grep -E "crypto_LUKS|BitLocker"
```

---

## 7. Hardware Security Assessment Checklist

| Item | Test Method | Pass Criteria |
|------|-------------|---------------|
| JTAG/UART disabled | Physical pin inspection + communication attempt | No response |
| Firmware signature | Signature file + public key verification | RSA/EC signature confirmed |
| Boot chain | Secure Boot status check | Secure Boot enabled |
| Debug ports | JTAG/SWD voltage measurement | Pins inactive or removed |
| Tamper detection | Physical inspection | Epoxy/mesh present |
| Sensitive key storage | Source code analysis | HSM/TPM in use |
| SPI flash | flashrom read attempt | Encrypted or unreadable |
| Side-channel | ChipWhisperer analysis | Masking applied confirmed |
| Default credentials | UART/web interface login test | No default credentials |
| Firmware update | OTA packet capture | Signature + encryption verified |

---

## 8. Assessment Report Template

```markdown
# Hardware Security Assessment Report

Target Device: [Device name and model]
Assessment Date: [Date]
Assessor: [Name]
Classification: [Confidential / Internal / Public]

---

## Executive Summary

[2-3 sentences summarizing overall assessment results]

Overall Severity: [Critical / High / Medium / Low]
Findings Count: [Number]

---

## Scope

- Target: [Model, firmware version]
- Methods: External inspection, interface analysis, firmware extraction
- Exclusions: [Out-of-scope items]

---

## Findings

### [ID]-001: Active UART Debug Port
Severity: High
Location: J4 connector, PCB bottom
Description: Root shell accessible via 115200 bps UART port
Evidence: [Screenshot or log output]
Recommendation: Disable or remove UART in production builds

### [ID]-002: Unencrypted SPI Flash
Severity: High
Description: Firmware stored in plaintext on SPI flash
Recommendation: Encrypt firmware with AES-128 or stronger

---

## Remediation Priority

| Priority | Item | Effort |
|----------|------|--------|
| Immediate | Disable UART | Low |
| Short-term | Firmware signing | Medium |
| Mid-term | Firmware encryption | High |
```
