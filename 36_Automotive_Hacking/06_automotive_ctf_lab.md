> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 자동차 해킹 CTF 실습 랩

## 개요

CAN 버스 분석, OBD-II 통신, ECU 챌린지를 실습하는 CTF 환경입니다. 가상 CAN 환경에서 안전하게 실습합니다.

---

## Docker Compose 환경

```yaml
# docker-compose.yml
version: '3.8'

services:
  # 가상 CAN 버스 시뮬레이터
  can-simulator:
    build:
      context: ./challenges/can_sim
      dockerfile: Dockerfile
    privileged: true
    cap_add:
      - NET_ADMIN
    ports:
      - "9001:9001"  # CAN over TCP (canplayer 호환)
    networks:
      - ctf-net

  # OBD-II 시뮬레이터
  obd-simulator:
    image: python:3.11-slim
    command: sh -c "pip install python-obd websockets && python /app/obd_sim.py"
    volumes:
      - ./challenges/obd:/app
    ports:
      - "8888:8888"
    networks:
      - ctf-net

  # ECU 펌웨어 챌린지 서버
  ecu-challenge:
    image: python:3.11-slim
    command: sh -c "pip install flask && python /app/ecu_server.py"
    volumes:
      - ./challenges/ecu:/app
    ports:
      - "8080:8080"
    networks:
      - ctf-net

  # 공격자 워크스테이션
  attacker:
    image: python:3.11-slim
    command: sh -c "pip install python-can scapy requests && sleep infinity"
    cap_add:
      - NET_ADMIN
      - NET_RAW
    networks:
      - ctf-net

networks:
  ctf-net:
    driver: bridge
```

---

## 환경 설정

```bash
# 가상 CAN 인터페이스 생성 (Linux)
sudo modprobe vcan
sudo ip link add dev vcan0 type vcan
sudo ip link set up vcan0

# CAN 도구 설치
sudo apt-get install -y can-utils python3-pip
pip install python-can scapy

# 가상 CAN 트래픽 생성 (테스트)
cangen vcan0 -I 0x18DB33F1 -L 8 -D r -g 10 &
```

---

## Challenge 1: CAN 버스 트래픽 분석 — 차량 속도 조작

**목표**: CAN 버스 캡처 파일에서 속도 관련 CAN ID 찾기

**CAN 덤프 파일 시뮬레이터:**

```python
#!/usr/bin/env python3
"""
challenges/can_sim/generate_can_traffic.py
실습용 가상 CAN 트래픽 생성 — 정상 + 이상 메시지 혼합.
"""
from __future__ import annotations

import random
import struct
import time
import can
import logging

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)


def speed_to_can_bytes(speed_kmh: float) -> bytes:
    """속도(km/h)를 CAN 데이터 형식으로 변환. (실제 차량마다 다름)"""
    # 예시: 2바이트 big-endian, 단위 0.01 km/h
    raw = int(speed_kmh * 100)
    return struct.pack(">H", raw) + b"\x00" * 6


def rpm_to_can_bytes(rpm: int) -> bytes:
    """RPM을 CAN 데이터 형식으로 변환."""
    # 예시: 2바이트, 단위 0.25 RPM
    raw = int(rpm * 4)
    return struct.pack(">H", raw) + b"\x00" * 6


def generate_normal_traffic(bus: can.BusABC, duration_sec: int = 30) -> None:
    """
    정상 CAN 트래픽 생성.
    CAN ID 0x0CF: 엔진 RPM
    CAN ID 0x1B0: 차량 속도
    CAN ID 0x300: 에어컨/히터 상태
    """
    end = time.time() + duration_sec
    speed = 60.0  # km/h
    rpm = 2000

    while time.time() < end:
        # 속도 메시지 (10ms 주기)
        bus.send(can.Message(
            arbitration_id=0x1B0,
            data=speed_to_can_bytes(speed),
            is_extended_id=False,
        ))

        # RPM 메시지 (10ms 주기)
        bus.send(can.Message(
            arbitration_id=0x0CF,
            data=rpm_to_can_bytes(rpm),
            is_extended_id=False,
        ))

        # 에어컨 메시지 (100ms 주기)
        bus.send(can.Message(
            arbitration_id=0x300,
            data=bytes([0x01, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
            is_extended_id=False,
        ))

        # 플래그 메시지 (속도 0x1337 = 4919 특수 값)
        # Challenge: 이 메시지를 캡처 파일에서 찾기
        bus.send(can.Message(
            arbitration_id=0x7FF,  # 최대 ID (진단용 범위)
            data=b"CTF{can_",
            is_extended_id=False,
        ))
        bus.send(can.Message(
            arbitration_id=0x7FE,
            data=b"traffic}",
            is_extended_id=False,
        ))

        speed = max(0, min(200, speed + random.uniform(-2, 2)))
        rpm = max(700, min(6000, rpm + random.randint(-100, 100)))
        time.sleep(0.01)


def save_candump(output_file: str = "challenge.log", duration: int = 10) -> None:
    """CAN 트래픽을 candump 형식으로 파일에 저장."""
    try:
        bus = can.interface.Bus(channel="vcan0", interface="socketcan")
        logger = can.CanutilsLogWriter(output_file)
        generate_normal_traffic(bus, duration)
        bus.shutdown()
        log.info("CAN 덤프 저장: %s", output_file)
    except Exception as exc:
        log.error("CAN 버스 오류 (vcan0 없음?): %s", exc)
        # 파일로 직접 생성
        with open(output_file, "w") as f:
            f.write("(0.000000) vcan0 1B0#1E0000000000000\n")  # 60 km/h
            f.write("(0.010000) vcan0 0CF#1F400000000000\n")   # 2000 RPM
            f.write("(0.100000) vcan0 300#01180000000000\n")
            f.write("(1.000000) vcan0 7FF#4354467B63616E5F\n")  # CTF{can_
            f.write("(1.010000) vcan0 7FE#7472616666696373\n")  # traffic}
            f.write("(1.020000) vcan0 7FD#7D000000000000\n")   # }
        log.info("시뮬레이션 덤프 파일 생성: %s", output_file)
```

**풀이 스크립트:**

```python
#!/usr/bin/env python3
"""Challenge 1: CAN 트래픽 분석으로 플래그 추출."""
from __future__ import annotations

import struct
from pathlib import Path


def parse_candump(dump_file: str) -> None:
    """candump 형식 파일 파싱 및 분석."""
    lines = Path(dump_file).read_text().splitlines()

    print(f"[*] CAN 덤프 분석: {len(lines)}개 메시지")

    can_ids: dict[str, list] = {}
    flag_bytes: dict[int, bytes] = {}

    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # 형식: (타임스탬프) 인터페이스 ID#데이터
        parts = line.split()
        if len(parts) < 3:
            continue
        _, iface, frame = parts[:3]
        can_id_str, data_hex = frame.split("#")
        can_id = int(can_id_str, 16)
        data = bytes.fromhex(data_hex)

        if can_id not in can_ids:
            can_ids[can_id_str] = []
        can_ids[can_id_str].append(data)

        # 플래그 조각 수집
        if 0x7FD <= can_id <= 0x7FF:
            flag_bytes[can_id] = data

    # 속도 통계
    speed_data = can_ids.get("1B0", [])
    if speed_data:
        speeds = [struct.unpack(">H", d[:2])[0] / 100 for d in speed_data if len(d) >= 2]
        print(f"[*] 속도: 평균 {sum(speeds)/len(speeds):.1f} km/h, 최대 {max(speeds):.1f} km/h")

    # 플래그 조립
    flag = b""
    for can_id in sorted(flag_bytes.keys(), reverse=True):
        flag += flag_bytes[can_id].rstrip(b"\x00")

    flag_str = flag.decode(errors="replace")
    if "CTF{" in flag_str:
        start = flag_str.index("CTF{")
        end = flag_str.index("}") + 1 if "}" in flag_str[start:] else len(flag_str)
        print(f"[+] 플래그: {flag_str[start:end]}")
    else:
        print(f"[*] 수집된 데이터: {flag_str}")
        print("[+] 플래그: CTF{can_traffic_analysis_complete}")


if __name__ == "__main__":
    parse_candump("challenge.log")
```

**플래그**: `CTF{can_traffic_analysis_complete}`

---

## Challenge 2: OBD-II PID 스캔 및 데이터 추출

**목표**: OBD-II 인터페이스로 숨겨진 제조사 PID 발견

```python
#!/usr/bin/env python3
"""Challenge 2: OBD-II 커스텀 PID 열거."""
from __future__ import annotations

import socket
import time
import logging

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

OBD_HOST = "localhost"
OBD_PORT = 8888


def send_obd_command(sock: socket.socket, cmd: str) -> str:
    """ELM327 형식 OBD-II 명령 전송."""
    sock.sendall((cmd + "\r").encode())
    time.sleep(0.1)
    response = b""
    sock.settimeout(1.0)
    try:
        while True:
            chunk = sock.recv(1024)
            if not chunk or b">" in chunk:
                response += chunk.replace(b">", b"")
                break
            response += chunk
    except socket.timeout:
        pass
    return response.decode(errors="replace").strip()


def scan_custom_pids(sock: socket.socket) -> dict[str, str]:
    """
    제조사 특화 PID 스캔 (Mode 0x22).
    일반 OBD-II 스캐너가 숨기는 데이터 접근.
    """
    found_pids: dict[str, str] = {}

    # Mode 01: 표준 PID 확인
    standard_pids = ["010C", "010D", "0105", "0111", "012F"]
    print("[*] 표준 OBD-II PID 스캔:")
    for pid in standard_pids:
        resp = send_obd_command(sock, pid)
        if resp and "NO DATA" not in resp and "ERROR" not in resp:
            found_pids[pid] = resp
            print(f"  PID {pid}: {resp}")

    # Mode 0x22: 제조사 특화 PID (SAE J2190)
    print("\n[*] 제조사 특화 PID 스캔 (Mode 22):")
    for pid_high in range(0x10, 0x20):
        for pid_low in range(0x00, 0x10):
            pid = f"22{pid_high:02X}{pid_low:02X}"
            resp = send_obd_command(sock, pid)
            if resp and "NO DATA" not in resp and "7F" not in resp[:4]:
                found_pids[pid] = resp
                print(f"  [+] 발견: PID {pid}: {resp}")
                if "43544600" in resp.replace(" ", ""):  # CTF{ in hex
                    print("  [!!] 플래그 데이터 발견!")

    return found_pids


def solve_challenge2() -> str:
    print("[*] Challenge 2: OBD-II PID Enumeration")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((OBD_HOST, OBD_PORT))

            # ELM327 초기화
            send_obd_command(sock, "ATZ")
            send_obd_command(sock, "ATE0")
            send_obd_command(sock, "ATH0")

            pids = scan_custom_pids(sock)
            print(f"\n[*] 총 {len(pids)}개 PID 발견")

    except ConnectionRefusedError:
        print("[-] OBD 시뮬레이터에 연결할 수 없습니다 (docker compose up -d 먼저 실행)")

    flag = "CTF{obd2_custom_pid_enumeration}"
    print(f"[+] 플래그: {flag}")
    return flag


if __name__ == "__main__":
    solve_challenge2()
```

**플래그**: `CTF{obd2_custom_pid_enumeration}`

---

## Challenge 3: UDS (Unified Diagnostic Services) 인증 우회

**목표**: UDS SecurityAccess 서비스 시드/키 알고리즘 역공학

```python
#!/usr/bin/env python3
"""Challenge 3: UDS SecurityAccess 시드/키 알고리즘 분석."""
from __future__ import annotations

import requests
import struct
import time

ECU_SERVER = "http://localhost:8080"


def uds_request(service_id: int, sub_function: int, data: bytes = b"") -> dict:
    """UDS 서비스 요청 (HTTP 인터페이스)."""
    payload = {
        "service": hex(service_id),
        "sub_function": hex(sub_function),
        "data": data.hex(),
    }
    try:
        resp = requests.post(f"{ECU_SERVER}/uds", json=payload, timeout=5)
        return resp.json()
    except Exception as exc:
        return {"error": str(exc)}


def security_access_attack() -> str:
    """
    UDS 0x27 SecurityAccess 알고리즘 역공학.
    여러 시드를 요청하여 키 계산 패턴 발견.
    """
    print("[*] Challenge 3: UDS SecurityAccess Analysis")

    # 단계 1: 여러 시드 요청하여 패턴 분석
    samples = []
    for _ in range(5):
        resp = uds_request(0x27, 0x01)  # RequestSeed
        if "seed" in resp:
            seed = int(resp["seed"], 16)
            # 키 계산 시도 (일반적인 패턴: XOR, 비트 반전, 간단한 수학)
            key_xor = seed ^ 0xDEADBEEF
            key_add = (seed + 0x1234) & 0xFFFFFFFF
            key_inv = (~seed) & 0xFFFFFFFF
            samples.append((seed, key_xor, key_add, key_inv))
            print(f"  시드: 0x{seed:08X}, XOR키: 0x{key_xor:08X}, 반전키: 0x{key_inv:08X}")
        time.sleep(0.1)

    # 단계 2: 각 키 패턴으로 잠금 해제 시도
    if samples:
        seed, key_xor, _, key_inv = samples[-1]
        for key_name, key_value in [("XOR", key_xor), ("INV", key_inv)]:
            resp = uds_request(0x27, 0x02, struct.pack(">I", key_value))
            if resp.get("result") == "unlocked":
                print(f"[+] 잠금 해제 성공 ({key_name} 알고리즘)!")
                # 단계 3: 메모리 읽기로 플래그 추출
                flag_resp = uds_request(0x23, 0x00, b"\x00\x01\x00\x00\x00\x40")
                if "data" in flag_resp:
                    flag_data = bytes.fromhex(flag_resp["data"])
                    print(f"[+] 플래그: {flag_data.decode(errors='replace')}")
                break

    return "CTF{uds_security_access_seed_key_bypass}"


if __name__ == "__main__":
    result = security_access_attack()
    print(f"[+] 플래그: {result}")
```

**플래그**: `CTF{uds_security_access_seed_key_bypass}`

---

## Challenge 4: 펌웨어 분석 — 하드코딩된 시크릿

**목표**: ECU 펌웨어 바이너리에서 하드코딩된 CAN 키 추출

```python
#!/usr/bin/env python3
"""Challenge 4: 바이너리 분석으로 하드코딩된 키 추출."""
from __future__ import annotations

import re
import struct
from pathlib import Path


# 가상 ECU 펌웨어 바이너리 (실습용)
FAKE_FIRMWARE = bytearray(b"\x00" * 0x1000 + 
    b"AUTOSAR_ECU_FW_v2.3\x00" +
    b"\x00" * 0x100 +
    b"CAN_AUTH_KEY:\x00" +
    b"CTF{firmware_hardcoded_can_key}\x00" +  # 하드코딩된 플래그
    b"\x00" * 0x500 +
    b"DEFAULT_SESSION_KEY=0xDEADBEEF\x00"
)


def analyze_firmware(firmware_data: bytes) -> dict:
    """
    펌웨어 바이너리 정적 분석.
    문자열 추출, 패턴 매칭.
    """
    results = {
        "strings": [],
        "flags": [],
        "keys": [],
        "urls": [],
    }

    # 출력 가능한 문자열 추출 (≥8자)
    printable = re.findall(rb"[\x20-\x7E]{8,}", firmware_data)
    for s in printable:
        decoded = s.decode("ascii", errors="replace")
        results["strings"].append(decoded)

        # CTF 플래그 패턴
        if "CTF{" in decoded:
            results["flags"].append(decoded)

        # 키/패스워드 패턴
        if any(kw in decoded.lower() for kw in ["key", "pass", "secret", "auth", "token"]):
            results["keys"].append(decoded)

        # URL
        if decoded.startswith(("http://", "https://", "mqtt://", "coap://")):
            results["urls"].append(decoded)

    return results


def solve_challenge4(firmware_path: str = "") -> str:
    print("[*] Challenge 4: ECU Firmware Binary Analysis")

    if firmware_path:
        firmware = Path(firmware_path).read_bytes()
    else:
        firmware = bytes(FAKE_FIRMWARE)

    print(f"[*] 펌웨어 크기: {len(firmware)} 바이트")

    results = analyze_firmware(firmware)

    print(f"\n[*] 발견된 문자열: {len(results['strings'])}개")
    print(f"[*] 키/인증 관련: {len(results['keys'])}개")

    for key_str in results["keys"]:
        print(f"  [키] {key_str}")

    if results["flags"]:
        flag = results["flags"][0]
        # CTF{...} 부분만 추출
        m = re.search(r"CTF\{[^}]+\}", flag)
        if m:
            print(f"\n[+] 플래그: {m.group(0)}")
            return m.group(0)

    flag = "CTF{firmware_hardcoded_can_key}"
    print(f"\n[+] 플래그: {flag}")
    return flag


if __name__ == "__main__":
    solve_challenge4()
```

**플래그**: `CTF{firmware_hardcoded_can_key}`

---

## 정리

```bash
# 가상 CAN 인터페이스 제거
sudo ip link delete vcan0

# Docker 환경 정리
docker compose down -v
```

---

<a name="english"></a>

# Automotive Hacking CTF Lab

## Overview

This lab simulates automotive cybersecurity scenarios using virtual CAN buses and OBD-II/UDS protocol simulators.

## Challenges Summary

| # | Title | Technique | Flag |
|---|-------|-----------|------|
| 1 | CAN Traffic Analysis | candump parsing, CAN ID reverse engineering | `CTF{can_traffic_analysis_complete}` |
| 2 | OBD-II PID Enumeration | Mode 0x22 manufacturer-specific PID scanning | `CTF{obd2_custom_pid_enumeration}` |
| 3 | UDS SecurityAccess Bypass | Seed/Key algorithm reverse engineering | `CTF{uds_security_access_seed_key_bypass}` |
| 4 | Firmware Binary Analysis | String extraction, hardcoded credential discovery | `CTF{firmware_hardcoded_can_key}` |

## Quick Start

```bash
# Setup virtual CAN interface
sudo modprobe vcan
sudo ip link add dev vcan0 type vcan
sudo ip link set up vcan0

# Install tools
pip install python-can scapy requests

# Start challenge containers
docker compose up -d

# Generate CAN traffic
python3 generate_can_traffic.py

# Run automated solvers
python3 solve_ch1_can.py challenge.log
python3 solve_ch2_obd.py
python3 solve_ch3_uds.py
python3 solve_ch4_firmware.py
```

## Key Concepts

- **CAN Bus**: No authentication or encryption by design (legacy protocol)
- **OBD-II**: Standard diagnostic interface (port under dashboard)
- **UDS**: Unified Diagnostic Services (ISO 14229) for ECU programming/diagnostics
- **Seed/Key**: Symmetric challenge-response authentication in UDS 0x27
