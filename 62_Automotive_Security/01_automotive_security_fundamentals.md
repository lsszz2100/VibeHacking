# 자동차 보안 기초

## 자동차 사이버보안 개요

현대 자동차는 100개 이상의 ECU(Electronic Control Unit)와 수천만 줄의 코드를 포함하는 복잡한 사이버물리 시스템이다. 자동차 해킹은 안전과 직결되므로 윤리적·법적 책임이 특히 중요하다.

## 자동차 아키텍처

### 네트워크 토폴로지
```
외부 인터페이스
├── OBD-II 포트 (CAN 버스 직접 접근)
├── 텔레매틱스 유닛 (4G/5G)
├── Wi-Fi / 블루투스 (인포테인먼트)
├── USB 포트
└── V2X (Vehicle-to-Everything)

내부 네트워크
├── CAN (Controller Area Network)  — 가장 흔한 차량 버스
├── LIN (Local Interconnect Network) — 저속 센서
├── MOST (Media Oriented Systems Transport) — 멀티미디어
├── FlexRay — 안전 임계 시스템 (X-by-Wire)
└── Automotive Ethernet — 신형 고속 통신
```

### 도메인 분리
```
파워트레인 도메인 — 엔진, 변속기 ECU
샤시 도메인     — ABS, ESC, 스티어링
ADAS 도메인     — 자율주행, 충돌 회피
인포테인먼트    — 내비게이션, 블루투스
텔레매틱스      — OTA, 원격 진단
```

## ECU (Electronic Control Unit)

### 주요 ECU 유형
```
ECU명          기능                     공격 영향도
ECM/PCM       — 엔진 제어              매우 높음
BCM           — 바디 기능 (잠금, 조명) 높음
ADAS          — 자율주행               매우 높음 (생명)
TCU           — 텔레매틱스             높음 (원격 접근)
IVI/HU        — 인포테인먼트           중간 (진입점)
GW            — 게이트웨이 ECU         매우 높음 (허브)
```

### ECU 소프트웨어 스택
```
AUTOSAR 표준
├── 응용 레이어 — 제어 알고리즘
├── RTE (Runtime Environment)
├── 기초 소프트웨어 (BSW)
│   ├── 서비스 레이어 (OS, 진단)
│   ├── ECU 추상화 레이어
│   └── 마이크로컨트롤러 추상화
└── 마이크로컨트롤러 하드웨어
```

## CAN 버스 기초

### CAN 프레임 구조
```
SOF  ID(11/29비트)  RTR  IDE  r0  DLC  DATA(0-8B)  CRC  ACK  EOF
 1       11/29       1    1   1   4      0-64       15   2    7  비트
```

### CAN 특성과 취약점
```
특성
├── CSMA/CR — 충돌 시 우선순위 중재
├── 멀티마스터 — 모든 노드가 송신 가능
├── 브로드캐스트 — 버스의 모든 노드가 수신
└── 인증 없음 — ID만으로 메시지 구분

취약점
├── 스푸핑 — 임의 ID로 메시지 전송
├── 도청 — 버스 스니핑
├── 서비스 거부 — 높은 우선순위 메시지 플러딩
└── 리플레이 — 캡처한 메시지 재전송
```

## OBD-II 포트

```
OBD-II 핀아웃 (DB-9 형태, 16핀)
 1 — 제조사 선택
 4 — 차체 GND
 5 — 신호 GND
 6 — CAN 하이 (J-2284)
 7 — ISO 9141-2 K-Line
 9 — 제조사 선택
14 — CAN 로우 (J-2284)
15 — ISO 9141-2 L-Line
16 — 배터리 전원 (12V)

→ CAN 버스에 직접 접근 가능 (보안 없음!)
```

## 공격 표면

```
원격 공격 표면
├── 텔레매틱스 (OTA 업데이트, 원격 진단)
├── V2X 통신 (V2V, V2I)
├── 인포테인먼트 (Wi-Fi, 블루투스, DAB)
└── 모바일 앱 ↔ 차량 통신

근거리 공격 표면
├── 블루투스 BLE (스마트키, 앱 연동)
├── Wi-Fi (핫스팟, 업데이트)
└── TPMS (타이어 압력 모니터링)

물리 공격 표면
├── OBD-II 포트 (직접 CAN 접근)
├── USB 포트 (미디어, 업데이트)
├── JTAG/UART (ECU 디버그)
└── 스마트키 릴레이 공격
```

## 법적·윤리적 고려사항

```
⚠️ 자동차 보안 연구 시 주의사항

1. 인증받은 환경에서만 테스트 (자신 소유 차량, 테스트 벤치)
2. 공공 도로에서 절대 공격 시도 금지 (인명 위험)
3. 취약점 발견 시 제조사에 책임 있는 공개
4. 관련 법규 준수 (CFAA, 각국 사이버보안 법)
5. 자동차 제조사 버그바운티 프로그램 활용

주요 법규
- 미국: CFAA (Computer Fraud and Abuse Act)
- 유럽: UN-ECE WP.29 Regulation (R155/R156)
- 한국: 자동차관리법, 정보통신망법
```

## 자동차 보안 표준

```
ISO/SAE 21434 — 자동차 사이버보안 엔지니어링
UN R155        — 사이버보안 관리 시스템 (CSMS)
UN R156        — 소프트웨어 업데이트 관리 (SUMS)
ISO 26262      — 기능 안전 (ASIL)
AUTOSAR        — 소프트웨어 아키텍처 표준

TARA (Threat Analysis and Risk Assessment)
├── 자산 식별
├── 위협 시나리오 도출
├── 영향도 평가 (안전/재정/개인정보/운영)
└── 리스크 기반 보안 대책 수립
```

## 연구 환경 구성

```python
#!/usr/bin/env python3
"""자동차 보안 연구 환경 설정 확인 도구."""

import subprocess
import shutil
import sys
from dataclasses import dataclass


@dataclass
class ToolStatus:
    name: str
    available: bool
    version: str


def check_tool(name: str, version_arg: str = "--version") -> ToolStatus:
    if not shutil.which(name):
        return ToolStatus(name=name, available=False, version="미설치")
    result = subprocess.run(
        [name, version_arg], capture_output=True, text=True
    )
    version = (result.stdout or result.stderr).split("\n")[0][:50]
    return ToolStatus(name=name, available=True, version=version)


REQUIRED_TOOLS = [
    ("python3",       "--version"),
    ("can-utils",     None),        # candump, cansend 등
    ("wireshark",     "--version"),
    ("openssl",       "version"),
    ("r2",            "-version"),  # radare2
]

PYTHON_LIBS = [
    "can",          # python-can
    "scapy",
    "pwntools",
    "requests",
]


def check_python_lib(lib: str) -> ToolStatus:
    try:
        import importlib
        mod = importlib.import_module(lib)
        version = getattr(mod, "__version__", "unknown")
        return ToolStatus(name=lib, available=True, version=version)
    except ImportError:
        return ToolStatus(name=lib, available=False, version="미설치")


def main() -> None:
    print("자동차 보안 연구 환경 점검")
    print("=" * 50)

    print("\n[시스템 도구]")
    for name, varg in REQUIRED_TOOLS:
        if name == "can-utils":
            status = ToolStatus(
                name="can-utils",
                available=bool(shutil.which("candump")),
                version="(candump, cansend, canplayer 등)",
            )
        else:
            status = check_tool(name, varg or "--version")
        icon = "✓" if status.available else "✗"
        print(f"  {icon} {status.name:20s} {status.version}")

    print("\n[Python 라이브러리]")
    for lib in PYTHON_LIBS:
        status = check_python_lib(lib)
        icon = "✓" if status.available else "✗"
        print(f"  {icon} {lib:20s} {status.version}")

    print("\n[CAN 인터페이스]")
    result = subprocess.run(
        ["ip", "link", "show"], capture_output=True, text=True
    )
    can_ifaces = [
        line.split(":")[1].strip() for line in result.stdout.splitlines()
        if "can" in line.lower() or "vcan" in line.lower()
    ]
    if can_ifaces:
        print(f"  발견된 CAN 인터페이스: {', '.join(can_ifaces)}")
    else:
        print("  CAN 인터페이스 없음 (vcan0 설정 권장)")
        print("  설정 명령: sudo modprobe vcan && sudo ip link add dev vcan0 type vcan")
        print("             sudo ip link set up vcan0")

    print("\n[설치 명령]")
    print("  sudo apt install can-utils python3-can wireshark")
    print("  pip3 install python-can scapy pwntools")


if __name__ == "__main__":
    main()
```

다음 파일에서 CAN 버스 해킹 실전 기법을 다룬다.
