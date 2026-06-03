> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇴🇸 English](#english)

---

<a name="한국어"></a>

# OT/ICS 보안 기초 심화

## 0. 초보자를 위한 개념 이해

### OT와 ICS란?

```
IT (Information Technology, 정보 기술):
  컴퓨터, 서버, 네트워크, 소프트웨어
  → 정보를 처리하고 저장

OT (Operational Technology, 운영 기술):
  공장 기계, 발전소 터빈, 댐 수문
  → 물리적 장치를 제어하고 모니터링

ICS (Industrial Control System, 산업 제어 시스템):
  OT의 핵심 시스템
  → PLC, SCADA, DCS 등으로 구성
```

### 실생활에서 OT/ICS가 있는 곳

```
전력 인프라:
  발전소 터빈 제어 → ICS
  변전소 차단기 제어 → SCADA
  
수자원 인프라:
  정수 처리 (염소 농도 조절) → PLC
  댐 수문 제어 → ICS
  
제조업:
  자동차 조립 로봇 → PLC
  반도체 공정 제어 → DCS
  
빌딩 자동화:
  냉난방 시스템 → BMS
  엘리베이터 제어 → ICS
```

### OT 장비의 특수성

```
PLC (Programmable Logic Controller, 프로그래머블 논리 제어기):
  - 공장 자동화의 핵심 장치
  - 실시간으로 센서 데이터를 읽고 액추에이터 제어
  - 예: 온도가 100도 이상이면 냉각 펌프 가동
  
  보안 특성:
    수명: 20~30년 (패치 거의 불가)
    인증: 없거나 매우 약함
    프로토콜: Modbus, PROFIBUS 등 구형 프로토콜

SCADA (Supervisory Control And Data Acquisition):
  - 원거리 PLC를 원격으로 모니터링/제어
  - 수도 시설, 전력망, 가스관 등에 사용
  - 중앙에서 수백 개의 현장 장치를 관리

DCS (Distributed Control System, 분산 제어 시스템):
  - 대규모 공정 자동화 (석유화학, 제지 공장)
  - PLC보다 규모가 크고 복잡
```

---

## OT vs IT 보안 패러다임

```
IT 보안 우선순위          OT 보안 우선순위
1. 기밀성 (C)            1. 가용성 (A)
2. 무결성 (I)            2. 무결성 (I)
3. 가용성 (A)            3. 기밀성 (C)

→ OT는 시스템 중단이 물리적 재해로 이어질 수 있음
  (폭발, 환경 오염, 인명 피해)
```

## OT/ICS 아키텍처

### Purdue 참조 모델 (ISA-99)
```
레벨 5 — 인터넷 (외부)
레벨 4 — 엔터프라이즈 네트워크 (ERP, 이메일)
──────── DMZ (비무장지대) ────────
레벨 3 — 운영 네트워크 (MES, 히스토리안)
레벨 2 — 감독 제어 (SCADA, HMI, 엔지니어링 워크스테이션)
레벨 1 — 기본 제어 (PLC, RTU, DCS)
레벨 0 — 프로세스 (센서, 액추에이터, 물리 프로세스)
```

### 핵심 구성 요소
```
PLC (Programmable Logic Controller)
├── 래더 로직 실행
├── I/O 모듈 제어
├── 실시간 운영 (결정론적)
└── 취약: 원격 접근, 펌웨어 업데이트

RTU (Remote Terminal Unit)
├── 원거리 장치 모니터링
├── SCADA와 통신
└── 취약: 암호화 없는 통신

DCS (Distributed Control System)
├── 연속 공정 제어 (화학, 정유)
├── 중앙 집중 vs. 분산 아키텍처
└── 취약: 레거시 OS, 패치 어려움

HMI (Human Machine Interface)
├── 운영자 인터페이스
├── 공정 시각화
└── 취약: Windows XP/7, VNC, RDP
```

## OT 통신 프로토콜

### 산업용 프로토콜 개요
```
프로토콜      계층    특성                보안
Modbus       L7     단순, 광범위 사용   인증 없음
DNP3         L2-7   전력/수도 분야     취약한 인증
IEC 61850    L7     변전소 자동화      일부 암호화
OPC-UA       L7     현대적, 보안 내장  TLS/인증 지원
EtherNet/IP  L7     Rockwell 표준     제한적 보안
PROFINET     L2     Siemens 표준      제한적 보안
Modbus TCP   L7     IP 기반 Modbus   인증 없음
BACnet       L7     빌딩 자동화       취약한 보안
```

### Modbus 프로토콜 심화
```
기능 코드
0x01 — 코일 읽기 (디지털 출력)
0x02 — 입력 읽기 (디지털 입력)
0x03 — 보유 레지스터 읽기 (아날로그 출력)
0x04 — 입력 레지스터 읽기 (아날로그 입력)
0x05 — 단일 코일 쓰기
0x06 — 단일 레지스터 쓰기
0x0F — 다중 코일 쓰기
0x10 — 다중 레지스터 쓰기

취약점:
- 인증 없음 → 누구나 PLC 제어 가능
- 암호화 없음 → 도청/변조 가능
- 요청 검증 없음 → 범위 밖 값 쓰기 가능
```

## 주요 OT 사이버 공격 사례

```
Stuxnet (2010)
├── 이란 나탄즈 핵시설
├── Siemens S7-315/S7-417 PLC 공격
├── 원심분리기 RPM 변조 (안전 범위 초과)
└── HMI에는 정상으로 표시 → 탐지 회피

Ukraine Power Grid (2015/2016)
├── BlackEnergy/Industroyer 악성코드
├── SCADA HMI 통해 차단기 조작
└── 약 225,000 가정 정전

Colonial Pipeline (2021)
├── IT 네트워크 랜섬웨어 감염
├── OT 네트워크 직접 침해 아님
└── 예방 목적으로 파이프라인 자체 중단

Triton/TRISIS (2017)
├── 사우디 석유화학 시설
├── Schneider Electric Triconex SIS 공격
└── 안전 계장 시스템 (SIS) 비활성화 시도
```

## OT 자산 발견

```python
#!/usr/bin/env python3
"""OT/ICS 네트워크 자산 발견 도구."""

import argparse
import socket
import struct
import ipaddress
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass


@dataclass
class OTDevice:
    ip: str
    port: int
    protocol: str
    banner: str
    device_info: dict


OT_PORTS = {
    102:  "S7comm (Siemens)",
    502:  "Modbus TCP",
    503:  "Modbus TLS",
    789:  "Red Lion Controls",
    1089: "FF Annunciation",
    1090: "FF Fieldbus",
    1091: "FF System Management",
    1911: "Niagara Fox",
    2404: "IEC 60870-5-104",
    4000: "Emerson DeltaV",
    4840: "OPC-UA",
    9600: "OMRON FINS",
    18245: "GE EGD",
    20000: "DNP3",
    44818: "EtherNet/IP",
    47808: "BACnet",
}


def grab_banner(ip: str, port: int, timeout: float = 2.0) -> str:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                return s.recv(256).decode(errors="replace").strip()
            except TimeoutError:
                return "(연결 성공, 배너 없음)"
    except Exception:
        return ""


def probe_modbus(ip: str, port: int = 502) -> dict | None:
    """Modbus TCP 장치 탐지."""
    # Modbus TCP 요청: Read Device Identification (FC 43)
    request = struct.pack(">HHHBBBB",
        0x0001,  # Transaction ID
        0x0000,  # Protocol ID
        0x0006,  # Length
        0x01,    # Unit ID
    ) + bytes([0x2B, 0x0E, 0x01, 0x00])  # MEI, Device ID

    try:
        with socket.create_connection((ip, port), timeout=2.0) as s:
            s.send(request)
            data = s.recv(256)
            if data and len(data) >= 8:
                return {
                    "protocol": "Modbus TCP",
                    "unit_id": data[6] if len(data) > 6 else "?",
                    "raw": data.hex(),
                }
    except Exception:
        pass

    # 기본 FC03 (레지스터 읽기)으로 재시도
    basic = struct.pack(">HHHHBBHH",
        0x0001, 0x0000, 0x0006, 0x0001,
        0x01,   # Unit ID
        0x03,   # FC03
        0x0000, # 시작 주소
        0x0001, # 수량
    )
    try:
        with socket.create_connection((ip, port), timeout=2.0) as s:
            s.send(basic)
            data = s.recv(64)
            if data:
                return {"protocol": "Modbus TCP", "raw": data.hex()}
    except Exception:
        pass
    return None


def probe_s7(ip: str, port: int = 102) -> dict | None:
    """Siemens S7 장치 탐지 (COTP + S7comm)."""
    # COTP Connection Request
    cotp_cr = bytes([
        0x03, 0x00, 0x00, 0x16,  # TPKT
        0x11, 0xE0, 0x00, 0x00,  # COTP CR
        0x00, 0x01, 0x00,
        0xC0, 0x01, 0x0A,
        0xC1, 0x02, 0x01, 0x00,
        0xC2, 0x02, 0x01, 0x02,
    ])
    try:
        s = socket.create_connection((ip, port), timeout=2.0)
        s.send(cotp_cr)
        resp = s.recv(256)
        if resp and resp[5] == 0xD0:  # COTP CC
            # S7 통신 설정
            s7_setup = bytes([
                0x03, 0x00, 0x00, 0x19,
                0x02, 0xF0, 0x80,
                0x32, 0x01, 0x00, 0x00,
                0x04, 0x00, 0x00, 0x08,
                0x00, 0x00, 0xF0, 0x00,
                0x00, 0x01, 0x00, 0x01,
                0x01, 0xE0,
            ])
            s.send(s7_setup)
            s7_resp = s.recv(256)
            s.close()
            return {
                "protocol": "S7comm",
                "raw": s7_resp.hex() if s7_resp else "",
            }
        s.close()
    except Exception:
        pass
    return None


def scan_host(ip: str) -> OTDevice | None:
    """단일 호스트 OT 포트 스캔."""
    for port, protocol in OT_PORTS.items():
        try:
            with socket.create_connection((ip, port), timeout=1.0):
                banner = grab_banner(ip, port)
                device_info: dict = {}

                if port == 502:
                    info = probe_modbus(ip, port)
                    if info:
                        device_info = info
                elif port == 102:
                    info = probe_s7(ip, port)
                    if info:
                        device_info = info

                return OTDevice(
                    ip=ip,
                    port=port,
                    protocol=protocol,
                    banner=banner[:80],
                    device_info=device_info,
                )
        except (ConnectionRefusedError, TimeoutError, OSError):
            continue
    return None


def scan_network(
    network: str,
    max_workers: int = 50,
) -> list[OTDevice]:
    net = ipaddress.ip_network(network, strict=False)
    hosts = list(net.hosts())
    devices: list[OTDevice] = []

    print(f"[*] 스캔: {network} ({len(hosts)} 호스트)")
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(scan_host, str(h)): h for h in hosts}
        for i, fut in enumerate(as_completed(futures), 1):
            device = fut.result()
            if device:
                devices.append(device)
                print(f"  [+] {device.ip}:{device.port} — {device.protocol}")
            if i % 50 == 0:
                print(f"  진행: {i}/{len(hosts)}", end="\r")
    return devices


def main() -> None:
    parser = argparse.ArgumentParser(description="OT/ICS 자산 발견 도구")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--host", help="단일 호스트")
    group.add_argument("--network", help="CIDR 네트워크 (예: 192.168.1.0/24)")
    parser.add_argument("-w", "--workers", type=int, default=30)
    args = parser.parse_args()

    if args.host:
        device = scan_host(args.host)
        if device:
            print(f"\n[+] OT 장치 발견:")
            print(f"  IP       : {device.ip}")
            print(f"  포트     : {device.port}")
            print(f"  프로토콜 : {device.protocol}")
            print(f"  배너     : {device.banner}")
            if device.device_info:
                print(f"  정보     : {device.device_info}")
        else:
            print(f"[-] OT 서비스 미발견: {args.host}")
    else:
        devices = scan_network(args.network, args.workers)
        print(f"\n[+] 발견된 OT 장치: {len(devices)}개")
        for d in devices:
            print(f"  {d.ip}:{d.port} [{d.protocol}]")


if __name__ == "__main__":
    main()
```

## 핵심 보안 도전과제

```
레거시 시스템
├── Windows XP/2003/7 HMI (패치 불가)
├── 수명 10~30년 장치 (교체 어려움)
└── 재부팅/업데이트 불가 (24/7 운영)

에어갭 신화
├── 진정한 에어갭은 드물다
├── USB, 컨설턴트 랩탑, OEM 원격접속
└── Stuxnet: 에어갭 극복 사례

공급망 위협
├── 제조 단계 백도어
├── 취약한 펌웨어 업데이트
└── 악성 엔지니어링 소프트웨어
```

다음 파일에서 SCADA 공격 기법을 다룬다.

---

<a name="english"></a>

# OT/ICS Security Fundamentals (Advanced)

## OT vs IT Security Paradigm

```
IT Security Priorities        OT Security Priorities
1. Confidentiality (C)       1. Availability (A)
2. Integrity (I)             2. Integrity (I)
3. Availability (A)          3. Confidentiality (C)

→ In OT, system outages can lead to physical disasters
  (explosions, environmental contamination, loss of life)
```

## OT/ICS Architecture

### Purdue Reference Model (ISA-99)
```
Level 5 — Internet (External)
Level 4 — Enterprise Network (ERP, Email)
──────── DMZ (Demilitarized Zone) ────────
Level 3 — Operations Network (MES, Historian)
Level 2 — Supervisory Control (SCADA, HMI, Engineering Workstation)
Level 1 — Basic Control (PLC, RTU, DCS)
Level 0 — Process (Sensors, Actuators, Physical Process)
```

### Key Components
```
PLC (Programmable Logic Controller)
├── Executes ladder logic
├── Controls I/O modules
├── Real-time operation (deterministic)
└── Vulnerabilities: remote access, firmware updates

RTU (Remote Terminal Unit)
├── Monitors remote devices
├── Communicates with SCADA
└── Vulnerabilities: unencrypted communications

DCS (Distributed Control System)
├── Continuous process control (chemical, refinery)
├── Centralized vs. distributed architecture
└── Vulnerabilities: legacy OS, difficulty patching

HMI (Human Machine Interface)
├── Operator interface
├── Process visualization
└── Vulnerabilities: Windows XP/7, VNC, RDP
```

## OT Communication Protocols

### Industrial Protocol Overview
```
Protocol      Layer   Characteristics          Security
Modbus        L7      Simple, widely used      No authentication
DNP3          L2-7    Power/water sector       Weak authentication
IEC 61850     L7      Substation automation    Partial encryption
OPC-UA        L7      Modern, built-in security TLS/auth support
EtherNet/IP   L7      Rockwell standard        Limited security
PROFINET      L2      Siemens standard         Limited security
Modbus TCP    L7      IP-based Modbus          No authentication
BACnet        L7      Building automation      Weak security
```

### Modbus Protocol In-Depth
```
Function Codes
0x01 — Read Coils (digital outputs)
0x02 — Read Discrete Inputs (digital inputs)
0x03 — Read Holding Registers (analog outputs)
0x04 — Read Input Registers (analog inputs)
0x05 — Write Single Coil
0x06 — Write Single Register
0x0F — Write Multiple Coils
0x10 — Write Multiple Registers

Vulnerabilities:
- No authentication → anyone can control the PLC
- No encryption → eavesdropping/tampering possible
- No request validation → out-of-range values can be written
```

## Major OT Cyber Attack Case Studies

```
Stuxnet (2010)
├── Iran's Natanz nuclear facility
├── Targeted Siemens S7-315/S7-417 PLCs
├── Manipulated centrifuge RPM (exceeding safe range)
└── Displayed normal readings on HMI → evaded detection

Ukraine Power Grid (2015/2016)
├── BlackEnergy/Industroyer malware
├── Manipulated circuit breakers via SCADA HMI
└── Approximately 225,000 homes lost power

Colonial Pipeline (2021)
├── Ransomware infected the IT network
├── OT network was not directly compromised
└── Pipeline voluntarily shut down as a precaution

Triton/TRISIS (2017)
├── Saudi petrochemical facility
├── Attacked Schneider Electric Triconex SIS
└── Attempted to disable the Safety Instrumented System (SIS)
```

## OT Asset Discovery

```python
#!/usr/bin/env python3
"""OT/ICS network asset discovery tool."""

import argparse
import socket
import struct
import ipaddress
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass


@dataclass
class OTDevice:
    ip: str
    port: int
    protocol: str
    banner: str
    device_info: dict


OT_PORTS = {
    102:  "S7comm (Siemens)",
    502:  "Modbus TCP",
    503:  "Modbus TLS",
    789:  "Red Lion Controls",
    1089: "FF Annunciation",
    1090: "FF Fieldbus",
    1091: "FF System Management",
    1911: "Niagara Fox",
    2404: "IEC 60870-5-104",
    4000: "Emerson DeltaV",
    4840: "OPC-UA",
    9600: "OMRON FINS",
    18245: "GE EGD",
    20000: "DNP3",
    44818: "EtherNet/IP",
    47808: "BACnet",
}


def grab_banner(ip: str, port: int, timeout: float = 2.0) -> str:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                return s.recv(256).decode(errors="replace").strip()
            except TimeoutError:
                return "(connected, no banner)"
    except Exception:
        return ""


def probe_modbus(ip: str, port: int = 502) -> dict | None:
    """Detect Modbus TCP device."""
    # Modbus TCP request: Read Device Identification (FC 43)
    request = struct.pack(">HHHBBBB",
        0x0001,  # Transaction ID
        0x0000,  # Protocol ID
        0x0006,  # Length
        0x01,    # Unit ID
    ) + bytes([0x2B, 0x0E, 0x01, 0x00])  # MEI, Device ID

    try:
        with socket.create_connection((ip, port), timeout=2.0) as s:
            s.send(request)
            data = s.recv(256)
            if data and len(data) >= 8:
                return {
                    "protocol": "Modbus TCP",
                    "unit_id": data[6] if len(data) > 6 else "?",
                    "raw": data.hex(),
                }
    except Exception:
        pass

    # Retry with basic FC03 (read registers)
    basic = struct.pack(">HHHHBBHH",
        0x0001, 0x0000, 0x0006, 0x0001,
        0x01,   # Unit ID
        0x03,   # FC03
        0x0000, # Start address
        0x0001, # Quantity
    )
    try:
        with socket.create_connection((ip, port), timeout=2.0) as s:
            s.send(basic)
            data = s.recv(64)
            if data:
                return {"protocol": "Modbus TCP", "raw": data.hex()}
    except Exception:
        pass
    return None


def probe_s7(ip: str, port: int = 102) -> dict | None:
    """Detect Siemens S7 device (COTP + S7comm)."""
    # COTP Connection Request
    cotp_cr = bytes([
        0x03, 0x00, 0x00, 0x16,  # TPKT
        0x11, 0xE0, 0x00, 0x00,  # COTP CR
        0x00, 0x01, 0x00,
        0xC0, 0x01, 0x0A,
        0xC1, 0x02, 0x01, 0x00,
        0xC2, 0x02, 0x01, 0x02,
    ])
    try:
        s = socket.create_connection((ip, port), timeout=2.0)
        s.send(cotp_cr)
        resp = s.recv(256)
        if resp and resp[5] == 0xD0:  # COTP CC
            # S7 communication setup
            s7_setup = bytes([
                0x03, 0x00, 0x00, 0x19,
                0x02, 0xF0, 0x80,
                0x32, 0x01, 0x00, 0x00,
                0x04, 0x00, 0x00, 0x08,
                0x00, 0x00, 0xF0, 0x00,
                0x00, 0x01, 0x00, 0x01,
                0x01, 0xE0,
            ])
            s.send(s7_setup)
            s7_resp = s.recv(256)
            s.close()
            return {
                "protocol": "S7comm",
                "raw": s7_resp.hex() if s7_resp else "",
            }
        s.close()
    except Exception:
        pass
    return None


def scan_host(ip: str) -> OTDevice | None:
    """Scan a single host for OT ports."""
    for port, protocol in OT_PORTS.items():
        try:
            with socket.create_connection((ip, port), timeout=1.0):
                banner = grab_banner(ip, port)
                device_info: dict = {}

                if port == 502:
                    info = probe_modbus(ip, port)
                    if info:
                        device_info = info
                elif port == 102:
                    info = probe_s7(ip, port)
                    if info:
                        device_info = info

                return OTDevice(
                    ip=ip,
                    port=port,
                    protocol=protocol,
                    banner=banner[:80],
                    device_info=device_info,
                )
        except (ConnectionRefusedError, TimeoutError, OSError):
            continue
    return None


def scan_network(
    network: str,
    max_workers: int = 50,
) -> list[OTDevice]:
    net = ipaddress.ip_network(network, strict=False)
    hosts = list(net.hosts())
    devices: list[OTDevice] = []

    print(f"[*] Scanning: {network} ({len(hosts)} hosts)")
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(scan_host, str(h)): h for h in hosts}
        for i, fut in enumerate(as_completed(futures), 1):
            device = fut.result()
            if device:
                devices.append(device)
                print(f"  [+] {device.ip}:{device.port} — {device.protocol}")
            if i % 50 == 0:
                print(f"  Progress: {i}/{len(hosts)}", end="\r")
    return devices


def main() -> None:
    parser = argparse.ArgumentParser(description="OT/ICS asset discovery tool")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--host", help="Single host")
    group.add_argument("--network", help="CIDR network (e.g., 192.168.1.0/24)")
    parser.add_argument("-w", "--workers", type=int, default=30)
    args = parser.parse_args()

    if args.host:
        device = scan_host(args.host)
        if device:
            print(f"\n[+] OT device found:")
            print(f"  IP       : {device.ip}")
            print(f"  Port     : {device.port}")
            print(f"  Protocol : {device.protocol}")
            print(f"  Banner   : {device.banner}")
            if device.device_info:
                print(f"  Info     : {device.device_info}")
        else:
            print(f"[-] No OT service found: {args.host}")
    else:
        devices = scan_network(args.network, args.workers)
        print(f"\n[+] OT devices found: {len(devices)}")
        for d in devices:
            print(f"  {d.ip}:{d.port} [{d.protocol}]")


if __name__ == "__main__":
    main()
```

## Key Security Challenges

```
Legacy Systems
├── Windows XP/2003/7 HMIs (cannot be patched)
├── Devices with 10–30 year lifespans (difficult to replace)
└── Cannot reboot/update (24/7 operations)

The Air Gap Myth
├── True air gaps are rare
├── USB drives, consultant laptops, OEM remote access
└── Stuxnet: a prime example of defeating an air gap

Supply Chain Threats
├── Backdoors implanted during manufacturing
├── Vulnerable firmware updates
└── Malicious engineering software
```

The next file covers SCADA attack techniques.
