> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# CAN 버스 해킹

## can-utils 기초

```bash
# vcan0 가상 인터페이스 설정 (테스트 환경)
sudo modprobe vcan
sudo ip link add dev vcan0 type vcan
sudo ip link set up vcan0

# 실제 CAN 인터페이스 (USBtin, CANable, PEAK PCAN)
sudo ip link set can0 up type can bitrate 500000
sudo ip link set can0 txqueuelen 1000

# 버스 스니핑
candump vcan0                      # 실시간 덤프
candump vcan0 -l                   # 로그 파일로 저장
candump -ta any                    # 타임스탬프 + 모든 인터페이스

# 메시지 전송
cansend vcan0 123#DEADBEEF         # ID=0x123, 데이터=DEADBEEF
cansend vcan0 7DF#0200010000000000 # OBD-II 요청 (RPM)

# 로그 재생
canplayer -I can_dump.log vcan0
canplayer -I can_dump.log -l 10 vcan0  # 10회 반복
```

## OBD-II 진단 프로토콜

### 서비스 ID
```
서비스 0x01 — 현재 데이터 (실시간 파라미터)
서비스 0x02 — 동결 프레임 데이터
서비스 0x03 — 저장된 DTC (진단 오류 코드)
서비스 0x04 — DTC 삭제
서비스 0x09 — 차량 정보 (VIN)
서비스 0x22 — 제조사별 데이터 (UDS)
서비스 0x27 — 보안 접근 (UDS SecurityAccess)
```

### OBD-II 쿼리 예시
```bash
# OBD-II CAN ID
# 0x7DF — 기능 주소 (모든 ECU)
# 0x7E0~0x7E7 — 특정 ECU 주소
# 0x7E8~0x7EF — ECU 응답 주소

# RPM 조회 (PID 0x0C)
cansend can0 7DF#0201 0C00000000

# 응답: 7E8#04 41 0C XX XX
# RPM = (XXXX * 256 + XXXX) / 4

# VIN 조회
cansend can0 7DF#0209020000000000

# 차량 속도 (PID 0x0D)
cansend can0 7DF#02010D0000000000
# 응답: 7E8#03 41 0D XX (XX km/h)
```

## CAN 버스 역공학

```python
#!/usr/bin/env python3
"""CAN 버스 트래픽 분석 및 역공학 도구."""

import argparse
import can
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Iterator


@dataclass
class CANMessage:
    timestamp: float
    arbitration_id: int
    data: bytes
    is_extended: bool = False


@dataclass
class IDStats:
    arb_id: int
    count: int = 0
    last_seen: float = 0.0
    data_samples: list[bytes] = field(default_factory=list)
    byte_changes: list[set[int]] = field(default_factory=list)

    def update(self, msg: CANMessage) -> None:
        self.count += 1
        self.last_seen = msg.timestamp

        if len(self.data_samples) < 100:
            self.data_samples.append(msg.data)

        if len(self.byte_changes) == 0:
            self.byte_changes = [set() for _ in range(len(msg.data))]
        for i, byte_val in enumerate(msg.data):
            if i < len(self.byte_changes):
                self.byte_changes[i].add(byte_val)


def sniff_can(
    interface: str,
    duration: float = 10.0,
    filter_id: int | None = None,
) -> Iterator[CANMessage]:
    """CAN 버스 스니핑 제너레이터."""
    bus = can.interface.Bus(interface, interface="socketcan")
    end = time.time() + duration

    try:
        while time.time() < end:
            msg = bus.recv(timeout=0.1)
            if msg is None:
                continue
            if filter_id and msg.arbitration_id != filter_id:
                continue
            yield CANMessage(
                timestamp=msg.timestamp,
                arbitration_id=msg.arbitration_id,
                data=bytes(msg.data),
                is_extended=msg.is_extended_id,
            )
    finally:
        bus.shutdown()


def analyze_traffic(messages: list[CANMessage]) -> dict[int, IDStats]:
    stats: dict[int, IDStats] = {}

    for msg in messages:
        arb_id = msg.arbitration_id
        if arb_id not in stats:
            stats[arb_id] = IDStats(arb_id=arb_id)
        stats[arb_id].update(msg)

    return stats


def find_changing_bytes(stats: dict[int, IDStats]) -> list[dict]:
    """액션 수행 시 변화하는 바이트 위치를 찾는다."""
    interesting: list[dict] = []
    for arb_id, stat in stats.items():
        if not stat.byte_changes:
            continue
        changing = [
            {"byte": i, "values": sorted(vals)}
            for i, vals in enumerate(stat.byte_changes)
            if len(vals) > 1
        ]
        if changing:
            interesting.append({
                "id": f"0x{arb_id:03X}",
                "count": stat.count,
                "changing_bytes": changing,
            })
    return interesting


def detect_obd_responses(messages: list[CANMessage]) -> list[dict]:
    """OBD-II 응답 메시지 탐지 및 파싱."""
    obd_responses: list[dict] = []
    for msg in messages:
        if 0x7E8 <= msg.arbitration_id <= 0x7EF:
            if len(msg.data) >= 3 and msg.data[1] == 0x41:
                pid = msg.data[2]
                value = parse_obd_pid(pid, msg.data[3:])
                if value:
                    obd_responses.append({
                        "ecu": f"0x{msg.arbitration_id:03X}",
                        "pid": f"0x{pid:02X}",
                        "value": value,
                    })
    return obd_responses


def parse_obd_pid(pid: int, data: bytes) -> str | None:
    match pid:
        case 0x0C:  # RPM
            if len(data) >= 2:
                rpm = (data[0] * 256 + data[1]) / 4
                return f"{rpm:.0f} RPM"
        case 0x0D:  # 속도
            if data:
                return f"{data[0]} km/h"
        case 0x05:  # 냉각수 온도
            if data:
                return f"{data[0] - 40}°C"
        case 0x04:  # 엔진 부하
            if data:
                return f"{data[0] * 100 / 255:.1f}%"
        case 0x11:  # 스로틀 위치
            if data:
                return f"{data[0] * 100 / 255:.1f}%"
    return None


def replay_attack(
    interface: str,
    messages: list[CANMessage],
    repeat: int = 1,
    delay: float = 0.0,
) -> None:
    """캡처한 메시지 리플레이 공격."""
    bus = can.interface.Bus(interface, interface="socketcan")
    try:
        for _ in range(repeat):
            for msg in messages:
                frame = can.Message(
                    arbitration_id=msg.arbitration_id,
                    data=msg.data,
                    is_extended_id=msg.is_extended,
                )
                bus.send(frame)
                if delay > 0:
                    time.sleep(delay)
    finally:
        bus.shutdown()


def fuzz_can_id(
    interface: str,
    target_id: int,
    byte_index: int,
    start: int = 0,
    end: int = 255,
    interval: float = 0.1,
) -> None:
    """특정 CAN ID의 바이트 퍼징."""
    bus = can.interface.Bus(interface, interface="socketcan")
    print(f"[*] CAN 퍼징: ID=0x{target_id:03X} byte[{byte_index}] {start}~{end}")
    try:
        for val in range(start, end + 1):
            data = bytearray(8)
            data[byte_index] = val
            frame = can.Message(
                arbitration_id=target_id,
                data=bytes(data),
                is_extended_id=False,
            )
            bus.send(frame)
            print(f"\r  전송: {val:3d}/255", end="")
            time.sleep(interval)
    finally:
        bus.shutdown()
        print()


def main() -> None:
    parser = argparse.ArgumentParser(description="CAN 버스 분석 도구")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sniff_p = sub.add_parser("sniff", help="CAN 트래픽 스니핑")
    sniff_p.add_argument("interface")
    sniff_p.add_argument("-t", "--time", type=float, default=10.0)
    sniff_p.add_argument("--id", type=lambda x: int(x, 16))

    analyze_p = sub.add_parser("analyze", help="캡처 파일 분석")
    analyze_p.add_argument("interface")
    analyze_p.add_argument("-t", "--time", type=float, default=30.0)

    fuzz_p = sub.add_parser("fuzz", help="CAN ID 퍼징")
    fuzz_p.add_argument("interface")
    fuzz_p.add_argument("id", type=lambda x: int(x, 16))
    fuzz_p.add_argument("byte_index", type=int)
    fuzz_p.add_argument("--interval", type=float, default=0.05)

    args = parser.parse_args()

    if args.cmd == "sniff":
        print(f"[*] 스니핑: {args.interface} ({args.time}초)")
        count = 0
        for msg in sniff_can(args.interface, args.time, args.id):
            count += 1
            data_hex = msg.data.hex().upper()
            print(f"  [{msg.timestamp:.3f}] "
                  f"0x{msg.arbitration_id:03X}#{data_hex}")
        print(f"\n[+] 캡처: {count}개 메시지")

    elif args.cmd == "analyze":
        print(f"[*] 분석 중... ({args.time}초 캡처)")
        messages = list(sniff_can(args.interface, args.time))
        print(f"[+] {len(messages)}개 메시지 캡처")

        stats = analyze_traffic(messages)
        print(f"\n[*] 감지된 CAN ID: {len(stats)}개")

        interesting = find_changing_bytes(stats)
        print(f"\n[!] 변화 바이트 있는 ID ({len(interesting)}개):")
        for item in sorted(interesting, key=lambda x: -len(x["changing_bytes"]))[:20]:
            print(f"  ID {item['id']:8s} | 횟수:{item['count']:5d} | "
                  f"변화 바이트: {[b['byte'] for b in item['changing_bytes']]}")

        obd = detect_obd_responses(messages)
        if obd:
            print(f"\n[+] OBD-II 응답:")
            for r in obd:
                print(f"  ECU {r['ecu']} PID {r['pid']}: {r['value']}")

    elif args.cmd == "fuzz":
        fuzz_can_id(args.interface, args.id, args.byte_index,
                    interval=args.interval)


if __name__ == "__main__":
    main()
```

## UDS (Unified Diagnostic Services)

```bash
# UDS 서비스 코드
0x10 — DiagnosticSessionControl    (세션 전환)
0x11 — ECUReset                     (ECU 리셋)
0x14 — ClearDiagnosticInformation  (DTC 삭제)
0x19 — ReadDTCInformation           (DTC 읽기)
0x22 — ReadDataByIdentifier         (데이터 읽기)
0x27 — SecurityAccess               (보안 접근)
0x2E — WriteDataByIdentifier        (데이터 쓰기)
0x31 — RoutineControl               (루틴 실행)
0x34 — RequestDownload              (다운로드 요청)
0x36 — TransferData                 (데이터 전송)
0x3E — TesterPresent                (연결 유지)

# UDS 세션 전환 (프로그래밍 모드)
cansend can0 7DF#0210020000000000

# SecurityAccess — 시드 요청
cansend can0 7E0#022701000000000000

# TesterPresent — 세션 유지
cansend can0 7DF#023E000000000000
```

## 스마트키 릴레이 공격

```
공격 원리:
1. 공격자 A — 차 근처 (안테나 감도 증폭)
2. 공격자 B — 집 안 열쇠 근처 (릴레이 신호)
3. 실제 열쇠처럼 신호 전달 → 차 문 열림

방어:
- UWB (Ultra-Wideband) 거리 측정
- 동작 감지 내장 열쇠
- PIN-to-Drive 기능
- Faraday 케이스 (열쇠 보관)
```

다음 파일에서 ECU 분석 기법을 다룬다.

---

<a name="english"></a>

# CAN Bus Hacking

## can-utils Basics

```bash
# Set up vcan0 virtual interface (test environment)
sudo modprobe vcan
sudo ip link add dev vcan0 type vcan
sudo ip link set up vcan0

# Real CAN interface (USBtin, CANable, PEAK PCAN)
sudo ip link set can0 up type can bitrate 500000
sudo ip link set can0 txqueuelen 1000

# Bus sniffing
candump vcan0                      # Real-time dump
candump vcan0 -l                   # Save to log file
candump -ta any                    # Timestamp + all interfaces

# Send messages
cansend vcan0 123#DEADBEEF         # ID=0x123, data=DEADBEEF
cansend vcan0 7DF#0200010000000000 # OBD-II request (RPM)

# Log replay
canplayer -I can_dump.log vcan0
canplayer -I can_dump.log -l 10 vcan0  # Repeat 10 times
```

## OBD-II Diagnostic Protocol

### Service IDs
```
Service 0x01 — Current data (real-time parameters)
Service 0x02 — Freeze frame data
Service 0x03 — Stored DTCs (Diagnostic Trouble Codes)
Service 0x04 — Clear DTCs
Service 0x09 — Vehicle information (VIN)
Service 0x22 — Manufacturer-specific data (UDS)
Service 0x27 — Security access (UDS SecurityAccess)
```

### OBD-II Query Examples
```bash
# OBD-II CAN IDs
# 0x7DF — Functional address (all ECUs)
# 0x7E0~0x7E7 — Specific ECU addresses
# 0x7E8~0x7EF — ECU response addresses

# RPM query (PID 0x0C)
cansend can0 7DF#0201 0C00000000

# Response: 7E8#04 41 0C XX XX
# RPM = (XXXX * 256 + XXXX) / 4

# VIN query
cansend can0 7DF#0209020000000000

# Vehicle speed (PID 0x0D)
cansend can0 7DF#02010D0000000000
# Response: 7E8#03 41 0D XX (XX km/h)
```

## CAN Bus Reverse Engineering

```python
#!/usr/bin/env python3
"""CAN bus traffic analysis and reverse engineering tool."""

import argparse
import can
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Iterator


@dataclass
class CANMessage:
    timestamp: float
    arbitration_id: int
    data: bytes
    is_extended: bool = False


@dataclass
class IDStats:
    arb_id: int
    count: int = 0
    last_seen: float = 0.0
    data_samples: list[bytes] = field(default_factory=list)
    byte_changes: list[set[int]] = field(default_factory=list)

    def update(self, msg: CANMessage) -> None:
        self.count += 1
        self.last_seen = msg.timestamp
        if len(self.data_samples) < 100:
            self.data_samples.append(msg.data)
        if len(self.byte_changes) == 0:
            self.byte_changes = [set() for _ in range(len(msg.data))]
        for i, byte_val in enumerate(msg.data):
            if i < len(self.byte_changes):
                self.byte_changes[i].add(byte_val)


def sniff_can(interface: str, duration: float = 10.0, filter_id: int | None = None) -> Iterator[CANMessage]:
    """CAN bus sniffing generator."""
    bus = can.interface.Bus(interface, interface="socketcan")
    end = time.time() + duration
    try:
        while time.time() < end:
            msg = bus.recv(timeout=0.1)
            if msg is None:
                continue
            if filter_id and msg.arbitration_id != filter_id:
                continue
            yield CANMessage(
                timestamp=msg.timestamp,
                arbitration_id=msg.arbitration_id,
                data=bytes(msg.data),
                is_extended=msg.is_extended_id,
            )
    finally:
        bus.shutdown()


def analyze_traffic(messages: list[CANMessage]) -> dict[int, IDStats]:
    stats: dict[int, IDStats] = {}
    for msg in messages:
        arb_id = msg.arbitration_id
        if arb_id not in stats:
            stats[arb_id] = IDStats(arb_id=arb_id)
        stats[arb_id].update(msg)
    return stats


def find_changing_bytes(stats: dict[int, IDStats]) -> list[dict]:
    """Find byte positions that change when performing actions."""
    interesting: list[dict] = []
    for arb_id, stat in stats.items():
        if not stat.byte_changes:
            continue
        changing = [
            {"byte": i, "values": sorted(vals)}
            for i, vals in enumerate(stat.byte_changes)
            if len(vals) > 1
        ]
        if changing:
            interesting.append({"id": f"0x{arb_id:03X}", "count": stat.count, "changing_bytes": changing})
    return interesting


def parse_obd_pid(pid: int, data: bytes) -> str | None:
    match pid:
        case 0x0C:
            if len(data) >= 2:
                return f"{(data[0] * 256 + data[1]) / 4:.0f} RPM"
        case 0x0D:
            if data:
                return f"{data[0]} km/h"
        case 0x05:
            if data:
                return f"{data[0] - 40}°C"
        case 0x04:
            if data:
                return f"{data[0] * 100 / 255:.1f}%"
        case 0x11:
            if data:
                return f"{data[0] * 100 / 255:.1f}%"
    return None


def fuzz_can_id(interface: str, target_id: int, byte_index: int,
                start: int = 0, end: int = 255, interval: float = 0.1) -> None:
    """Fuzz bytes at a specific CAN ID."""
    bus = can.interface.Bus(interface, interface="socketcan")
    print(f"[*] CAN fuzzing: ID=0x{target_id:03X} byte[{byte_index}] {start}~{end}")
    try:
        for val in range(start, end + 1):
            data = bytearray(8)
            data[byte_index] = val
            frame = can.Message(arbitration_id=target_id, data=bytes(data), is_extended_id=False)
            bus.send(frame)
            print(f"\r  Sending: {val:3d}/255", end="")
            time.sleep(interval)
    finally:
        bus.shutdown()
        print()


def main() -> None:
    parser = argparse.ArgumentParser(description="CAN bus analysis tool")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sniff_p = sub.add_parser("sniff", help="Sniff CAN traffic")
    sniff_p.add_argument("interface")
    sniff_p.add_argument("-t", "--time", type=float, default=10.0)
    sniff_p.add_argument("--id", type=lambda x: int(x, 16))

    analyze_p = sub.add_parser("analyze", help="Analyze captured traffic")
    analyze_p.add_argument("interface")
    analyze_p.add_argument("-t", "--time", type=float, default=30.0)

    fuzz_p = sub.add_parser("fuzz", help="Fuzz CAN ID")
    fuzz_p.add_argument("interface")
    fuzz_p.add_argument("id", type=lambda x: int(x, 16))
    fuzz_p.add_argument("byte_index", type=int)
    fuzz_p.add_argument("--interval", type=float, default=0.05)

    args = parser.parse_args()

    if args.cmd == "sniff":
        print(f"[*] Sniffing: {args.interface} ({args.time}s)")
        count = 0
        for msg in sniff_can(args.interface, args.time, args.id):
            count += 1
            print(f"  [{msg.timestamp:.3f}] 0x{msg.arbitration_id:03X}#{msg.data.hex().upper()}")
        print(f"\n[+] Captured: {count} messages")

    elif args.cmd == "analyze":
        print(f"[*] Analyzing... ({args.time}s capture)")
        messages = list(sniff_can(args.interface, args.time))
        print(f"[+] {len(messages)} messages captured")
        stats = analyze_traffic(messages)
        print(f"\n[*] Detected CAN IDs: {len(stats)}")
        interesting = find_changing_bytes(stats)
        print(f"\n[!] IDs with changing bytes ({len(interesting)}):")
        for item in sorted(interesting, key=lambda x: -len(x["changing_bytes"]))[:20]:
            print(f"  ID {item['id']:8s} | count:{item['count']:5d} | "
                  f"changing bytes: {[b['byte'] for b in item['changing_bytes']]}")

    elif args.cmd == "fuzz":
        fuzz_can_id(args.interface, args.id, args.byte_index, interval=args.interval)


if __name__ == "__main__":
    main()
```

## UDS (Unified Diagnostic Services)

```bash
# UDS service codes
0x10 — DiagnosticSessionControl    (Session switch)
0x11 — ECUReset                     (ECU reset)
0x14 — ClearDiagnosticInformation  (Clear DTCs)
0x19 — ReadDTCInformation           (Read DTCs)
0x22 — ReadDataByIdentifier         (Read data)
0x27 — SecurityAccess               (Security access)
0x2E — WriteDataByIdentifier        (Write data)
0x31 — RoutineControl               (Execute routine)
0x34 — RequestDownload              (Request download)
0x36 — TransferData                 (Transfer data)
0x3E — TesterPresent                (Keep connection alive)

# UDS session switch (programming mode)
cansend can0 7DF#0210020000000000

# SecurityAccess — seed request
cansend can0 7E0#022701000000000000

# TesterPresent — maintain session
cansend can0 7DF#023E000000000000
```

## Smart Key Relay Attack

```
Attack principle:
1. Attacker A — near the vehicle (amplify antenna sensitivity)
2. Attacker B — near the key inside house (relay signal)
3. Signal transmitted as if real key → car door opens

Defense:
- UWB (Ultra-Wideband) distance measurement
- Motion sensor built into key
- PIN-to-Drive feature
- Faraday case (for key storage)
```

The next file covers ECU analysis techniques.
