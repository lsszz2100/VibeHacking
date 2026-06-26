> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 자동차 보안 기초

## 0. 초보자를 위한 개념 이해

### 자동차 보안이란?

자동차 보안(Automotive Security)은 현대 차량에 내장된 수십~수백 개의 컴퓨터(ECU)와 차량 내부 네트워크, 무선 통신 인터페이스를 사이버 공격으로부터 보호하는 분야이다. 2015년 Charlie Miller와 Chris Valasek이 주행 중인 지프 체로키를 원격으로 해킹하여 브레이크와 조향을 제어한 사건은 자동차 보안의 중요성을 전 세계에 알렸다.

**왜 배우는가:**
```
[현대 자동차 = 바퀴 달린 컴퓨터 네트워크]

외부 공격 진입점:
  인터넷 ── OTA 업데이트 서버
  Bluetooth ── 인포테인먼트 시스템
  Wi-Fi ── 테슬라 스타일 커넥티드카
  셀룰러 ── 원격 진단, 텔레매틱스
  USB ── 충전 포트, 오디오
  OBD-II ── 정비소 진단 포트

내부 네트워크 (CAN 버스):
  인포테인먼트 ─┐
  ADAS ECU    ─┤─ CAN 버스 ─── 엔진 ECU
  브레이크 ECU ─┤            ── 조향 ECU
  도어 ECU    ─┘

위험: 인포테인먼트 침해 → CAN 버스 접근 → 브레이크/엔진 제어
```

### 핵심 개념 정리

```
주요 용어:
- ECU(Electronic Control Unit): 차량 내 특정 기능을 제어하는 소형 컴퓨터
- CAN 버스: 차량 내 ECU들이 통신하는 기본 내부 네트워크 프로토콜
- OBD-II: 표준 차량 진단 포트 (대부분 운전석 아래에 있음)
- V2X(Vehicle-to-Everything): 차량과 다른 차량/인프라/보행자 간 무선 통신
- TARA(Threat Analysis and Risk Assessment): 자동차 보안 위협 분석 방법론
- ISO/SAE 21434: 자동차 사이버보안 국제 표준 (2021년 발효)
- UN Regulation 155: 커넥티드카 사이버보안 강제 규정 (유럽, 2022년 적용)
```

### 필요한 도구 및 환경
- **Linux VM + can-utils**: 가상 CAN 인터페이스(vcan0)로 실습
- **Python 3.10+**: python-can 라이브러리
- **ICSim (ICSim Car Simulator)**: CAN 버스 시뮬레이터 (실제 차량 불필요)
- **Wireshark**: CAN 패킷 캡처 및 분석

### 기초 실습 예제
```python
# pip install python-can
# Linux에서 가상 CAN 인터페이스 설정:
# sudo modprobe vcan
# sudo ip link add dev vcan0 type vcan
# sudo ip link set up vcan0

import struct
from dataclasses import dataclass

@dataclass
class CANFrame:
    """CAN 버스 프레임 구조"""
    arbitration_id: int   # 메시지 ID (11비트 또는 29비트)
    data: bytes           # 데이터 페이로드 (최대 8바이트)
    is_extended: bool = False

    def __str__(self):
        return (f"CAN Frame: ID=0x{self.arbitration_id:03X} "
                f"Data={self.data.hex().upper()} "
                f"({'확장' if self.is_extended else '표준'})")

def simulate_can_traffic():
    """
    자동차 CAN 버스 트래픽 시뮬레이션
    실제 차량의 CAN 메시지 패턴을 Python으로 재현
    """
    print("=== CAN 버스 트래픽 시뮬레이션 ===\n")

    # 일반적인 자동차 CAN 메시지 예시
    sample_messages = [
        # 엔진 RPM (ID: 0x0C9, 2바이트)
        # 값 = (바이트1 * 256 + 바이트2) / 4
        CANFrame(0x0C9, bytes([0x0F, 0xA0])),  # 1000 RPM

        # 차속 (ID: 0x0D0, 1바이트)
        # 값 = 바이트1 km/h
        CANFrame(0x0D0, bytes([0x3C])),         # 60 km/h

        # 가속 페달 위치 (ID: 0x147, 1바이트)
        # 값 = 바이트1 / 255 * 100 %
        CANFrame(0x147, bytes([0x4D])),         # 약 30%

        # 조향각 (ID: 0x002, 2바이트)
        # 값 = (바이트1 * 256 + 바이트2 - 4096) / 10 도
        CANFrame(0x002, bytes([0x10, 0x00])),   # 0도 (직진)

        # 브레이크 압력 (ID: 0x0F0, 1바이트)
        CANFrame(0x0F0, bytes([0x00])),         # 브레이크 안 밟음
    ]

    print("수신된 CAN 메시지:")
    for frame in sample_messages:
        print(f"  {frame}")

    # CAN 메시지 디코딩 시연
    print("\n=== CAN 메시지 디코딩 ===")
    rpm_frame = sample_messages[0]
    rpm = (rpm_frame.data[0] * 256 + rpm_frame.data[1]) / 4
    speed = sample_messages[1].data[0]
    accel = sample_messages[2].data[0] / 255 * 100

    print(f"  엔진 RPM: {rpm:.0f}")
    print(f"  차속: {speed} km/h")
    print(f"  가속 페달: {accel:.1f}%")

    # python-can으로 실제 vcan0 전송 (선택)
    print("\n=== 실제 vcan0 전송 예시 (python-can) ===")
    print("import can")
    print("bus = can.Bus(channel='vcan0', bustype='socketcan')")
    print("msg = can.Message(arbitration_id=0x0C9, data=[0x0F, 0xA0])")
    print("bus.send(msg)  # CAN 메시지 전송")
    print("# candump vcan0 으로 수신 확인 가능")

simulate_can_traffic()
```

---

## 자동차 사이버보안 개요

현대 자동차는 100개 이상의 ECU(Electronic Control Unit)와 수천만 줄의 코드를 포함하는 복잡한 사이버물리 시스템이다. 자동차 해킹은 안전과 직결되므로 윤리적·법적 책임이 특히 중요하다.

현실 세계 비유: 현대 자동차는 바퀴 달린 컴퓨터 네트워크다. 엔진 ECU, 브레이크 ECU, 인포테인먼트 시스템이 각각 독립된 컴퓨터처럼 작동하면서 내부 네트워크(CAN 버스)로 서로 통신한다. 인터넷에 연결된 네트워크와 마찬가지로, 이 통신 경로에 취약점이 있으면 해커가 원격으로 차량을 제어할 수 있다.

---

## 1. 현대 자동차 ECU 아키텍처

### 1.1 전체 시스템 다이어그램

```
┌─────────────────────────────────────────────────────────────────┐
│                  현대 차량 전자 아키텍처                          │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                    외부 연결                               │   │
│  │  [스마트폰 앱] [OTA 업데이트] [원격진단] [V2X 통신]       │   │
│  └─────────────────────┬────────────────────────────────────┘   │
│                         │ 4G/5G / WiFi / Bluetooth               │
│  ┌──────────────────────▼───────────────────────────────────┐   │
│  │                 텔레매틱스 도메인                           │   │
│  │    [TCU - 텔레매틱스 제어 유닛]  [GPS 수신기]             │   │
│  └──────────────────────┬───────────────────────────────────┘   │
│                          │ Automotive Ethernet / CAN              │
│  ┌───────────────────────▼──────────────────────────────────┐   │
│  │              중앙 게이트웨이 ECU (GW)                      │   │
│  │           도메인 간 통신 필터링 및 라우팅                  │   │
│  └───────┬─────────┬──────────┬──────────┬──────────────────┘   │
│          │         │          │           │                       │
│  ┌───────▼──┐ ┌───▼────┐ ┌──▼─────┐ ┌──▼──────┐               │
│  │파워트레인 │ │  샤시  │ │  ADAS  │ │인포테인먼│               │
│  │도메인    │ │ 도메인  │ │ 도메인  │ │  트      │               │
│  │          │ │        │ │        │ │          │               │
│  │ECM/PCM   │ │ABS ECU │ │카메라   │ │IVI 헤드  │               │
│  │변속기ECU │ │ESC ECU │ │레이더   │ │유닛      │               │
│  │연료 시스템│ │조향ECU │ │라이다   │ │블루투스  │               │
│  └──────────┘ └────────┘ └────────┘ └──────────┘               │
│                                                                  │
│  물리적 접근:  [OBD-II 포트] → CAN 버스 직접 접근              │
└─────────────────────────────────────────────────────────────────┘
```

### 1.2 도메인별 ECU 상세

```
파워트레인 도메인 (Powertrain Domain):
  ECM (Engine Control Module)      — 엔진 연료 분사, 점화 제어
  PCM (Powertrain Control Module)  — 엔진 + 변속기 통합 제어
  TCM (Transmission Control Module)— 변속 타이밍 제어
  공격 영향: 매우 높음 (엔진 정지, 급가속 유발 가능)

샤시 도메인 (Chassis Domain):
  ABS ECU  — 잠금 방지 브레이크
  ESC ECU  — 전자식 안정화 제어 (스핀 방지)
  EPS ECU  — 전동식 파워 스티어링
  SAS      — 조향 각도 센서
  공격 영향: 매우 높음 (브레이크, 조향 제어 가능)

ADAS 도메인 (Advanced Driver Assistance):
  카메라 ECU   — 차선 인식, 표지판 인식
  레이더 ECU   — 전방 충돌 경고, 크루즈 컨트롤
  라이다 ECU   — 3D 환경 인식 (자율주행 차량)
  퓨전 ECU     — 센서 데이터 융합
  공격 영향: 생명 직결 (긴급 제동, 자율주행 우회)

바디 도메인 (Body Domain):
  BCM (Body Control Module) — 도어 잠금, 조명, 경고등
  PEPS — 수동 없는 시동 및 출입 시스템 (스마트 키)
  공격 영향: 높음 (원격 잠금 해제, 도어 개방)
```

---

## 2. 차량 내부 통신 프로토콜 비교

### 2.1 CAN vs LIN vs FlexRay vs Automotive Ethernet

| 특성 | CAN | LIN | FlexRay | Automotive Ethernet |
|------|-----|-----|---------|-------------------|
| 속도 | 1 Mbps | 20 Kbps | 10 Mbps | 100 Mbps ~ 10 Gbps |
| 토폴로지 | 버스 | 단일마스터/다중슬레이브 | 버스/스타 | 스타/링 |
| 결정성 | 비결정적 | 비결정적 | 결정적 | 결정적 (TSN) |
| 오류 검출 | CRC, 비트 스터핑 | 체크섬 | CRC, 이중채널 | 이더넷 프레임 |
| 비용 | 낮음 | 매우 낮음 | 높음 | 중간~높음 |
| 주요 용도 | 대부분의 ECU 통신 | 저속 센서/액추에이터 | X-by-Wire | ADAS, 카메라 |
| 보안 | 없음 | 없음 | 기본적 | TLS 가능 |
| 대표 적용 | 엔진, 브레이크 ECU | 시트 모터, 미러 | 에어백, 스티어링 | 카메라 스트림 |

### 2.2 CAN 버스 상세

```
CAN 프레임 구조 (표준 11비트 ID):

 SOF  Arbitration  Control       Data          CRC   ACK  EOF
  │       Field     Field        Field         Field  │    │
  1b    11b+1b=12b  6b         0~64b           15+1b  2b   7b

상세:
┌───┬───────────────────┬────────┬──────────────┬────────┬───┬───┐
│SOF│ ID (11b) │RTR(1b) │ IDE r0 │ DLC (4b)     │ DATA   │CRC│ACK│
│ 1 │   11     │   1    │  1  1  │ 4 (0-8 바이트)│ 0~64b  │16 │ 2 │
└───┴──────────┴────────┴────────┴──────────────┴────────┴───┴───┘

SOF: Start Of Frame (항상 0)
ID:  11비트 식별자 (낮을수록 높은 우선순위)
RTR: Remote Transmission Request
DLC: Data Length Code
CRC: 15비트 Cyclic Redundancy Check

CAN 취약점:
1. 인증 없음 — ID만으로 메시지 구분
2. 암호화 없음 — 평문 전송
3. 브로드캐스트 — 모든 노드가 모든 메시지 수신
4. 우선순위 홍수 공격 — ID=0x000 메시지 반복으로 DoS 가능
```

### 2.3 LIN 버스 상세

```
LIN (Local Interconnect Network):
  용도: 저속, 저비용 센서 및 액추에이터
  예: 창문 모터, 시트 조절, 미러 조절, 온도 센서

LIN 프레임:
  [Break] [Sync] [ID] [Data 1~8B] [Checksum]

특징:
  - 단일 마스터 (BCM 또는 메인 ECU)
  - 슬레이브: 최대 16개 노드
  - 12V 단선 통신 (SCI/UART 기반)
  - 보안 없음 → ID 스푸핑 쉬움
```

### 2.4 FlexRay 버스 상세

```
FlexRay:
  용도: 안전 임계 시스템 (X-by-Wire)
  예: 브레이크-by-Wire, 조향-by-Wire, 에어백

특징:
  - 이중 채널 (채널 A + B) — 결함 허용
  - 시간 분할 다중화 (TDMA) — 결정적 전송
  - 10 Mbps 각 채널 (최대 20 Mbps)
  - 동기화된 클럭 — 정확한 타이밍 보장

FlexRay 사이클:
┌────────────────────────────────┐
│ Static Segment │ Dynamic Segment│
│  (고정 슬롯)    │  (동적 슬롯)  │
│  결정적 전송    │  이벤트 기반  │
└────────────────────────────────┘
```

---

## 3. 공격 표면 개요 (Attack Surface Overview)

### 3.1 원격 공격 표면

```
┌─────────────────────────────────────────────────────────────┐
│                    원격 공격 표면                             │
│                                                              │
│  OTA 업데이트 (Over-The-Air)                                │
│  ├── 가짜 업데이트 서버 → 악성 펌웨어 설치                  │
│  ├── 무결성 검증 없는 업데이트 → 임의 코드 실행              │
│  └── 중간자 공격 (MITM) → 업데이트 내용 변조                │
│                                                              │
│  텔레매틱스 (Telematics)                                    │
│  ├── 취약한 API → 원격 명령 실행                             │
│  ├── 인증 없는 원격 진단 포트                                │
│  └── 클라우드 백엔드 취약점 → 차량 제어                     │
│                                                              │
│  V2X (Vehicle-to-Everything)                               │
│  ├── V2V: 차량 간 가짜 위험 메시지 주입                     │
│  ├── V2I: 가짜 신호등 신호로 비상 제동 유발                 │
│  └── V2N: 네트워크 통신 도청/변조                           │
│                                                              │
│  모바일 앱 연동                                             │
│  ├── 취약한 BLE 페어링 → 차량 잠금 해제                     │
│  └── 앱 계정 탈취 → 원격 위치 추적, 엔진 시동              │
└─────────────────────────────────────────────────────────────┘
```

### 3.2 근거리 공격 표면

```
블루투스 (Bluetooth/BLE):
  - 스마트 키 BLE 신호 릴레이 공격
  - BLE 페어링 취약점 (BLESA 등)
  - HID 스푸핑으로 인포테인먼트 제어

Wi-Fi:
  - 인포테인먼트 Wi-Fi 핫스팟 취약점
  - WPA2 핸드쉐이크 캡처 → 오프라인 크래킹
  - 가짜 AP로 OTA 업데이트 우회

TPMS (타이어 압력 모니터링):
  - 315MHz/433MHz 신호 스푸핑
  - 가짜 타이어 압력 경고 → 운전자 조작 유도
  - 차량 추적 (고유 TPMS ID 이용)
```

### 3.3 물리 공격 표면

```
OBD-II 포트 (가장 위험):
  - CAN 버스 직접 접근 (보안 없음)
  - 진단 세션으로 ECU 매개변수 변경
  - 악성 OBD 동글 설치 → 원격 접근 백도어

USB 포트:
  - 악성 USB 드라이브 → 인포테인먼트 취약점 익스플로잇
  - BadUSB 공격
  - 펌웨어 업데이트 경로로 악용

JTAG/UART/SPI (물리 해킹):
  - ECU 기판의 디버그 핀 → 펌웨어 덤프
  - OpenOCD로 메모리 직접 읽기
  - UART 콘솔 → 부트로더 접근
```

---

## 4. TARA (Threat Analysis and Risk Assessment)

### 4.1 TARA 개요

TARA는 ISO/SAE 21434에서 요구하는 자동차 사이버보안 위험 분석 방법론이다.

```
TARA 프로세스:

단계 1: 자산 식별 (Asset Identification)
  ├── 차량 기능 목록화 (브레이크, 조향, 원격 시동 등)
  ├── 해당 ECU 및 네트워크 식별
  └── 보호 대상 데이터 식별 (위치, 사용자 정보 등)

단계 2: 위협 시나리오 도출 (Threat Scenario Analysis)
  ├── STRIDE 모델 적용
  │   ├── Spoofing: CAN 메시지 위조
  │   ├── Tampering: 펌웨어 변조
  │   ├── Repudiation: 로그 삭제
  │   ├── Information Disclosure: 위치 데이터 노출
  │   ├── Denial of Service: CAN 버스 DoS
  │   └── Elevation of Privilege: 게이트웨이 우회
  └── 공격 경로 (Attack Path) 도출

단계 3: 영향도 평가 (Impact Assessment)
  영향 카테고리:
  ├── 안전 (Safety): 탑승자/보행자 사망, 부상
  ├── 재정 (Financial): 차량 도난, 보험 사기
  ├── 개인정보 (Privacy): 위치 추적, 개인 데이터
  └── 운영 (Operational): 차량 기능 중단

단계 4: 리스크 평가 (Risk Assessment)
  리스크 = 공격 가능성 × 영향도
  
  공격 가능성 요소:
  ├── 공격 경로 (원격 vs 물리적)
  ├── 필요 전문성 수준
  ├── 알려진 취약점 여부
  └── 공격 윈도우 (노출 시간)

단계 5: 보안 대책 수립 (Security Controls)
  ├── 리스크 회피 (Avoid): 기능 제거
  ├── 리스크 완화 (Mitigate): 보안 제어 추가
  ├── 리스크 전가 (Transfer): 보험
  └── 리스크 수용 (Accept): 낮은 리스크
```

### 4.2 TARA 예시: 원격 엔진 시동 시스템

```
자산: 원격 엔진 시동 기능

위협 시나리오:
  T1: 공격자가 모바일 API를 통해 타인 차량 원격 시동
  T2: BLE 릴레이 공격으로 스마트 키 신호 복제
  T3: OTA 업데이트 서버 탈취 → 악성 스타트 로직 삽입

영향도 (T1):
  안전: 낮음 (차량 정지 상태에서 시동, 직접 위험 없음)
  재정: 높음 (차량 도난 가능)
  개인정보: 중간 (위치 노출)

공격 가능성 (T1):
  경로: 원격 (높은 노출)
  전문성: 중간 (API 분석 필요)
  → 전체 리스크: HIGH

보안 대책 (T1):
  M1: API 인증 강화 (OAuth 2.0 + MFA)
  M2: 속도 제한 (Rate Limiting)
  M3: 이상 탐지 (비정상 위치에서 시동 시도)
  M4: 사용자 알림 (모든 원격 시동 시 푸시 알림)
```

---

## 5. ISO/SAE 21434 사이버보안 표준 개요

### 5.1 표준 구조

```
ISO/SAE 21434:2021 — 자동차 사이버보안 엔지니어링

섹션 구조:
  4. 일반 고려사항
  5. 조직의 사이버보안 관리
  6. 프로젝트 의존적 사이버보안 관리
  7. 분산된 사이버보안 활동
  8. 지속적인 사이버보안 활동
  9. 컨셉 단계
  10. 제품 개발
  11. 사이버보안 검증
  12. 생산
  13. 운용 및 유지보수
  14. 폐기

핵심 요구사항:
  ├── TARA 수행 의무화
  ├── 사이버보안 문화 및 역량 구축
  ├── 공급망 보안 관리
  ├── 취약점 모니터링 및 대응 (PSIRT 운영)
  └── 사고 대응 계획 수립
```

### 5.2 ISO 21434 vs UN R155 비교

| 항목 | ISO/SAE 21434 | UN Regulation R155 |
|------|---------------|-------------------|
| 유형 | 기술 표준 (how-to) | 법규 (규제) |
| 적용 | 자동차 OEM/Tier 1 공급사 | 유럽 시장 판매 차량 |
| 요구사항 | 사이버보안 엔지니어링 프로세스 | CSMS (사이버보안관리시스템) 인증 |
| 발효 | 2021년 8월 | 2022년 7월 (신차), 2024년 (전차) |
| 관계 | R155 준수를 위한 기술적 기반 | 21434 이행으로 준수 가능 |

---

## 6. 실제 자동차 해킹 사례 타임라인

### 6.1 주요 사례 연표

```
2010년:
  카이런 등 연구진 — CAN 버스 최초 학술 공격 증명
  "Experimental Security Analysis of a Modern Automobile"

2011년:
  Sam Checkoway 등 — 원격 공격 경로 확장 연구
  텔레매틱스, 블루투스, CD 플레이어를 통한 CAN 접근

2013년:
  Charlie Miller & Chris Valasek
  — Toyota Prius, Ford Escape 물리적 해킹
  — 브레이크, 조향 제어 시연

2015년 (Jeep Cherokee 해킹):
  Miller & Valasek — 가장 유명한 원격 자동차 해킹
  ├── Uconnect 텔레매틱스 시스템 원격 익스플로잇
  ├── Sprint 셀룰러 네트워크를 통해 접근
  ├── 에어컨, 라디오, 와이퍼 원격 제어
  ├── 고속도로에서 변속기 중립 전환 (속도 감소)
  └── 크라이슬러, 140만 대 리콜 → 패치 배포

2016년:
  Tesla Model S 원격 해킹 (Keen Security Lab)
  ├── 브레이크 원격 작동
  ├── 자동 주차 기능 오작동 유발
  └── Tesla: OTA 패치 10일 만에 배포

2019년:
  BMW 취약점 14개 발견 (Keen Security Lab)
  ├── OBD-II, TCU, 인포테인먼트 통해 접근
  ├── 원격 코드 실행 가능
  └── BMW 30개국 100만+ 대 소프트웨어 업데이트

2020년:
  Tencent Keen — Tesla Model X 키리스 공격
  차량 잠금 해제, 운전 시스템 접근

2022년:
  David Colombo — Tesla 25개국 25대 동시 제어
  (제3자 로깅 앱 취약점 악용, 사용자 실수)

2023년:
  다수 OEM의 API 취약점 발견
  (Kia, Honda, Infiniti, Nissan 등)
  → 차량 위치 추적, 원격 잠금/잠금해제
```

### 6.2 Jeep Cherokee 해킹 심층 분석

```
공격 경로:
  인터넷 → Sprint 셀룰러망 → Uconnect 텔레매틱스
          → CAN 버스 → 목표 ECU

기술적 단계:
  1. Uconnect 시스템의 D-Bus 서비스 취약점 발견
  2. V850 칩 펌웨어 재프로그래밍 (CAN 버스 접근 경로)
  3. CAN 메시지로 브레이크, 조향, 변속기 제어

시사점:
  - 인포테인먼트 시스템이 CAN 버스에 직접 연결
  - 도메인 분리 (게이트웨이) 부재
  - 텔레매틱스 시스템 인증 미흡
  - OTA 업데이트 메커니즘 없어 물리적 리콜 필요

이후 변화:
  - 업계 전체 도메인 분리 아키텍처 채택 가속
  - OTA 업데이트 인프라 구축 의무화
  - NHTSA 사이버보안 가이드라인 발표
```

---

## 7. Python-CAN 입문 가이드

### 7.1 설치 및 기본 설정

```bash
# 설치
pip install python-can

# 가상 CAN 인터페이스 설정 (Linux)
sudo modprobe vcan
sudo ip link add dev vcan0 type vcan
sudo ip link set up vcan0

# 확인
ip link show vcan0

# can-utils 설치 (도구 세트)
sudo apt install can-utils

# 터미널 1: CAN 메시지 수신
candump vcan0

# 터미널 2: CAN 메시지 전송
cansend vcan0 123#DEADBEEF
```

### 7.2 Python-CAN 기본 사용법

```python
#!/usr/bin/env python3
"""python-can 기본 사용 예제 — 초보자용 단계별 가이드."""

import can
import time

# ─────────────────────────────────────────────────────
# 1단계: 버스 연결
# ─────────────────────────────────────────────────────
# 가상 CAN (테스트용)
bus = can.interface.Bus(channel='vcan0', interface='socketcan')

# 실제 하드웨어 (PCAN USB 동글)
# bus = can.interface.Bus(channel='PCAN_USBBUS1', interface='pcan')

# Peak PCAN 대안: Kvaser
# bus = can.interface.Bus(channel=0, interface='kvaser')

# ─────────────────────────────────────────────────────
# 2단계: 메시지 전송
# ─────────────────────────────────────────────────────
# 기본 메시지 전송
msg = can.Message(
    arbitration_id=0x123,      # CAN ID (11비트: 0x000 ~ 0x7FF)
    data=[0xDE, 0xAD, 0xBE, 0xEF],  # 데이터 (0~8 바이트)
    is_extended_id=False,       # 11비트 ID 사용
)
bus.send(msg)
print(f"전송: ID={msg.arbitration_id:#05x}, 데이터={msg.data.hex()}")

# 확장 ID 메시지 (29비트)
msg_ext = can.Message(
    arbitration_id=0x1FFFFFFF,
    data=[0x01, 0x02, 0x03],
    is_extended_id=True,
)
bus.send(msg_ext)

# ─────────────────────────────────────────────────────
# 3단계: 메시지 수신
# ─────────────────────────────────────────────────────
# 단일 메시지 수신 (타임아웃)
received = bus.recv(timeout=1.0)
if received:
    print(f"수신: ID={received.arbitration_id:#05x}, "
          f"데이터={bytes(received.data).hex()}, "
          f"시간={received.timestamp:.3f}")

# 지속적인 수신 (루프)
print("\n[CAN 스니핑 시작 — Ctrl+C로 종료]")
try:
    while True:
        msg = bus.recv(timeout=0.5)
        if msg:
            data_hex = bytes(msg.data).hex(' ')
            print(f"  [{msg.timestamp:.3f}] "
                  f"ID={msg.arbitration_id:#05x} "
                  f"DLC={msg.dlc} "
                  f"DATA={data_hex}")
except KeyboardInterrupt:
    print("\n[종료]")
finally:
    bus.shutdown()
```

### 7.3 CAN 버스 분석 도구

```python
#!/usr/bin/env python3
"""
CAN Bus Analyzer — 초보자용 CAN 버스 분석 CLI
사용법:
  python3 can_analyzer.py --interface vcan0 sniff
  python3 can_analyzer.py --interface vcan0 send --id 0x7E0 --data 02100301
  python3 can_analyzer.py --interface vcan0 replay --logfile candump.log
"""

import argparse
import time
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

try:
    import can
except ImportError:
    print("[-] python-can 미설치: pip install python-can")
    sys.exit(1)


@dataclass
class CANStats:
    """CAN 버스 통계."""
    total_messages: int = 0
    unique_ids: set = field(default_factory=set)
    messages_per_id: dict = field(default_factory=lambda: defaultdict(int))
    data_samples: dict = field(default_factory=lambda: defaultdict(list))


def sniff_can(interface: str, duration: float = 10.0, verbose: bool = False) -> CANStats:
    """CAN 버스 스니핑 및 통계 수집."""
    stats = CANStats()

    try:
        bus = can.interface.Bus(channel=interface, interface='socketcan')
    except Exception as e:
        print(f"[-] CAN 인터페이스 연결 실패: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] {interface} 스니핑 시작 ({duration}초)")
    print(f"    {'시간':>10} {'ID':>8} {'DLC':>4} {'데이터':<24} {'ASCII'}")
    print(f"    {'-'*60}")

    end_time = time.time() + duration
    try:
        while time.time() < end_time:
            msg = bus.recv(timeout=0.1)
            if not msg:
                continue

            stats.total_messages += 1
            stats.unique_ids.add(msg.arbitration_id)
            stats.messages_per_id[msg.arbitration_id] += 1

            data_bytes = bytes(msg.data)
            # 최근 5개 샘플만 유지
            samples = stats.data_samples[msg.arbitration_id]
            samples.append(data_bytes.hex())
            if len(samples) > 5:
                samples.pop(0)

            if verbose:
                ascii_repr = ''.join(
                    chr(b) if 32 <= b < 127 else '.'
                    for b in data_bytes
                )
                ext_flag = 'E' if msg.is_extended_id else 'S'
                print(f"    {msg.timestamp:>10.3f} "
                      f"{msg.arbitration_id:#010x if msg.is_extended_id else msg.arbitration_id:#06x}"
                      f"[{ext_flag}] "
                      f"{msg.dlc:>3}  "
                      f"{data_bytes.hex():24}  {ascii_repr}")

    except KeyboardInterrupt:
        print("\n[!] 사용자 중단")
    finally:
        bus.shutdown()

    return stats


def print_stats(stats: CANStats) -> None:
    """수집된 통계 출력."""
    print(f"\n{'='*60}")
    print(f"CAN 버스 분석 결과")
    print(f"{'='*60}")
    print(f"  총 메시지:    {stats.total_messages}개")
    print(f"  고유 ID:      {len(stats.unique_ids)}개")

    if stats.messages_per_id:
        print(f"\n  메시지 빈도 (상위 10개):")
        sorted_ids = sorted(
            stats.messages_per_id.items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]
        for can_id, count in sorted_ids:
            rate = count / max(sum(stats.messages_per_id.values()), 1) * 100
            samples = stats.data_samples.get(can_id, [])
            latest = samples[-1] if samples else "없음"
            print(f"    ID {can_id:#06x}: {count:>5}회 ({rate:>5.1f}%)  최신={latest}")


def send_can_message(interface: str, can_id: int, data: bytes) -> None:
    """CAN 메시지 전송."""
    try:
        bus = can.interface.Bus(channel=interface, interface='socketcan')
        msg = can.Message(
            arbitration_id=can_id,
            data=data,
            is_extended_id=False,
        )
        bus.send(msg)
        print(f"[+] 전송 완료: ID={can_id:#06x}, 데이터={data.hex()}")
        bus.shutdown()
    except Exception as e:
        print(f"[-] 전송 실패: {e}", file=sys.stderr)
        sys.exit(1)


def replay_log(interface: str, logfile: Path) -> None:
    """candump 로그 파일 재생."""
    try:
        bus = can.interface.Bus(channel=interface, interface='socketcan')
    except Exception as e:
        print(f"[-] CAN 인터페이스 연결 실패: {e}", file=sys.stderr)
        sys.exit(1)

    sent = 0
    try:
        with logfile.open() as f:
            prev_ts: float | None = None
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                # 형식: (1234567890.123456) vcan0 123#DEADBEEF
                try:
                    parts = line.split()
                    ts_str = parts[0].strip('()')
                    ts = float(ts_str)
                    id_data = parts[2].split('#')
                    can_id = int(id_data[0], 16)
                    data = bytes.fromhex(id_data[1]) if len(id_data) > 1 else b''

                    if prev_ts is not None:
                        delay = ts - prev_ts
                        if 0 < delay < 1.0:
                            time.sleep(delay)
                    prev_ts = ts

                    msg = can.Message(arbitration_id=can_id, data=data, is_extended_id=False)
                    bus.send(msg)
                    sent += 1
                except (ValueError, IndexError):
                    continue
    finally:
        bus.shutdown()
        print(f"[+] {sent}개 메시지 재생 완료")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="CAN Bus Analyzer — 초보자용 CAN 분석 도구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
사전 조건:
  pip install python-can
  sudo modprobe vcan && sudo ip link add dev vcan0 type vcan && sudo ip link set up vcan0

사용 예시:
  python3 can_analyzer.py --interface vcan0 sniff --duration 30
  python3 can_analyzer.py --interface vcan0 sniff --verbose
  python3 can_analyzer.py --interface vcan0 send --id 0x7E0 --data 0210030100000000
  python3 can_analyzer.py --interface vcan0 replay --logfile capture.log
        """,
    )
    parser.add_argument("--interface", default="vcan0", help="CAN 인터페이스 이름")

    sub = parser.add_subparsers(dest="cmd", required=True)

    # 스니핑 서브커맨드
    sniff_p = sub.add_parser("sniff", help="CAN 버스 스니핑")
    sniff_p.add_argument("--duration", type=float, default=10.0, help="수집 시간 (초)")
    sniff_p.add_argument("--verbose", action="store_true", help="실시간 메시지 출력")

    # 전송 서브커맨드
    send_p = sub.add_parser("send", help="CAN 메시지 전송")
    send_p.add_argument("--id", type=lambda x: int(x, 16), required=True, help="CAN ID (16진수, 예: 0x123)")
    send_p.add_argument("--data", required=True, help="데이터 (16진수, 예: DEADBEEF)")

    # 재생 서브커맨드
    replay_p = sub.add_parser("replay", help="candump 로그 재생")
    replay_p.add_argument("--logfile", type=Path, required=True, help="candump 로그 파일")

    args = parser.parse_args()

    match args.cmd:
        case "sniff":
            stats = sniff_can(args.interface, args.duration, args.verbose)
            print_stats(stats)

        case "send":
            try:
                data = bytes.fromhex(args.data)
            except ValueError:
                print("[-] 데이터 형식 오류. 16진수 문자열을 입력하세요 (예: DEADBEEF)")
                sys.exit(1)
            send_can_message(args.interface, args.id, data)

        case "replay":
            if not args.logfile.exists():
                print(f"[-] 파일 없음: {args.logfile}", file=sys.stderr)
                sys.exit(1)
            replay_log(args.interface, args.logfile)


if __name__ == "__main__":
    main()
```

---

## 8. 연구 환경 구성

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
        icon = "v" if status.available else "x"
        print(f"  [{icon}] {status.name:20s} {status.version}")

    print("\n[Python 라이브러리]")
    for lib in PYTHON_LIBS:
        status = check_python_lib(lib)
        icon = "v" if status.available else "x"
        print(f"  [{icon}] {lib:20s} {status.version}")

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


<!-- detect-validate-62 -->
## 차량 격리 검증 — 도메인 분리가 실제로 트래픽을 막는가

차량 보안 아키텍처는 *도메인을 나눴다*가 아니라 **중앙 게이트웨이가 안전계(파워트레인·섀시)와 인포테인먼트 간 트래픽을 실제로 격리하고, 외부 인터페이스(텔레매틱스)에서 안전계로 가는 경로가 차단되는가**로 판정한다. 검증은 **소유 차량·벤치**에서만.

### 항목 → 실패 모드 → 검증 방법 → 양호 신호

| 항목 | 실패 모드 | 검증 방법 | 양호 신호 |
|---|---|---|---|
| 도메인 분리 | 평면 버스 | 버스 간 도달성 점검 | 안전계 격리 |
| 게이트웨이 필터 | 무필터 포워딩 | 메시지 라우팅 확인 | 화이트리스트 라우팅 |
| 외부 인터페이스 | 직접 안전계 접근 | 텔레매틱스→CAN 경로 | 경로 차단됨 |
| 디버그 포트 | OBD 무제한 | 진단 접근 점검 | 인증된 진단만 |

### 방어 검증 (직접 확인)

```bash
# 1) 인포테인먼트 버스에서 안전계 ID가 실제로 보이는지(보이면 격리 실패) — 소유 벤치에서만
candump can0 2>/dev/null | awk '{print $2}' | sort -u | head -20   # 도메인 경계 밖 ID 노출 확인
# 2) 게이트웨이가 특정 ID만 포워딩하는지(라우팅 화이트리스트 추정)
candump -n 200 can0 2>/dev/null | awk '{print $2}' | sort | uniq -c | sort -rn | head
```

> 검증은 반드시 **소유 차량·벤치**에서만 한다. 공도/타인 차량 금지. "도메인을 나눴다"와 "트래픽이 실제 격리된다"는 다르다 — 버스 간 도달성으로 직접 확인한다([[37_ICS_SCADA]], [[24_Network_Infrastructure_Security]]).

---

<a name="english"></a>

# Automotive Security Fundamentals

## Overview of Automotive Cybersecurity

Modern vehicles are complex cyber-physical systems containing over 100 ECUs (Electronic Control Units) and tens of millions of lines of code. Because automotive hacking is directly tied to physical safety, ethical and legal responsibilities are especially critical.

Real-world analogy: A modern vehicle is essentially a computer network on wheels. The engine ECU, brake ECU, and infotainment system each operate like independent computers, communicating with each other over an internal network (CAN bus). Just like an internet-connected network, vulnerabilities in these communication pathways can allow hackers to remotely control the vehicle.

---

## 1. Modern Vehicle ECU Architecture

### 1.1 Full System Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│              Modern Vehicle Electronic Architecture              │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                    External Connectivity                   │   │
│  │  [Smartphone App] [OTA Updates] [Remote Diagnostics] [V2X]│   │
│  └─────────────────────┬────────────────────────────────────┘   │
│                         │ 4G/5G / WiFi / Bluetooth               │
│  ┌──────────────────────▼───────────────────────────────────┐   │
│  │                 Telematics Domain                          │   │
│  │    [TCU - Telematics Control Unit]  [GPS Receiver]        │   │
│  └──────────────────────┬───────────────────────────────────┘   │
│                          │ Automotive Ethernet / CAN              │
│  ┌───────────────────────▼──────────────────────────────────┐   │
│  │              Central Gateway ECU (GW)                      │   │
│  │        Filters and routes inter-domain communication       │   │
│  └───────┬─────────┬──────────┬──────────┬──────────────────┘   │
│          │         │          │           │                       │
│  ┌───────▼──┐ ┌───▼────┐ ┌──▼─────┐ ┌──▼──────────┐           │
│  │Powertrain│ │Chassis │ │  ADAS  │ │Infotainment │           │
│  │Domain    │ │Domain  │ │Domain  │ │             │           │
│  │          │ │        │ │        │ │             │           │
│  │ECM/PCM   │ │ABS ECU │ │Camera  │ │IVI Head     │           │
│  │Trans ECU │ │ESC ECU │ │Radar   │ │Unit         │           │
│  │Fuel Sys  │ │EPS ECU │ │LiDAR   │ │Bluetooth    │           │
│  └──────────┘ └────────┘ └────────┘ └─────────────┘           │
│                                                                  │
│  Physical Access:  [OBD-II Port] → Direct CAN bus access        │
└─────────────────────────────────────────────────────────────────┘
```

### 1.2 Domain-Specific ECU Details

```
Powertrain Domain:
  ECM (Engine Control Module)      — Fuel injection, ignition control
  PCM (Powertrain Control Module)  — Integrated engine + transmission
  TCM (Transmission Control Module)— Shift timing control
  Attack impact: Very high (engine shutoff, sudden acceleration)

Chassis Domain:
  ABS ECU  — Anti-lock braking
  ESC ECU  — Electronic stability control (anti-spin)
  EPS ECU  — Electric power steering
  SAS      — Steering angle sensor
  Attack impact: Very high (brake, steering control)

ADAS Domain:
  Camera ECU  — Lane recognition, sign recognition
  Radar ECU   — Forward collision warning, cruise control
  LiDAR ECU   — 3D environment sensing (autonomous vehicles)
  Fusion ECU  — Sensor data fusion
  Attack impact: Life-critical (emergency braking, autonomous bypass)

Body Domain:
  BCM (Body Control Module) — Door locks, lights, warnings
  PEPS — Passive Entry / Passive Start (smart key)
  Attack impact: High (remote unlock, door opening)
```

---

## 2. In-Vehicle Communication Protocol Comparison

### 2.1 CAN vs LIN vs FlexRay vs Automotive Ethernet

| Property | CAN | LIN | FlexRay | Automotive Ethernet |
|----------|-----|-----|---------|-------------------|
| Speed | 1 Mbps | 20 Kbps | 10 Mbps | 100 Mbps ~ 10 Gbps |
| Topology | Bus | Single master/multi-slave | Bus/Star | Star/Ring |
| Determinism | Non-deterministic | Non-deterministic | Deterministic | Deterministic (TSN) |
| Error detection | CRC, bit stuffing | Checksum | CRC, dual channel | Ethernet frame |
| Cost | Low | Very low | High | Medium~High |
| Primary use | Most ECU communication | Low-speed sensors/actuators | X-by-Wire | ADAS, cameras |
| Security | None | None | Basic | TLS possible |
| Examples | Engine, brake ECUs | Seat motor, mirrors | Airbags, steering | Camera streams |

### 2.2 CAN Bus Detail

```
CAN Frame Structure (Standard 11-bit ID):

 SOF  Arbitration  Control       Data          CRC   ACK  EOF
  │       Field     Field        Field         Field  │    │
  1b    11b+1b=12b  6b         0~64b           15+1b  2b   7b

Detail:
┌───┬──────────────────┬────────┬──────────────┬────────┬───┬───┐
│SOF│ ID (11b) │RTR(1b)│ IDE r0 │ DLC (4b)     │ DATA   │CRC│ACK│
│ 1 │   11     │   1   │  1  1  │ 4 (0-8 bytes)│ 0~64b  │16 │ 2 │
└───┴──────────┴───────┴────────┴──────────────┴────────┴───┴───┘

SOF: Start Of Frame (always 0)
ID:  11-bit identifier (lower = higher priority)
RTR: Remote Transmission Request
DLC: Data Length Code
CRC: 15-bit Cyclic Redundancy Check

CAN Vulnerabilities:
1. No authentication — messages differentiated by ID only
2. No encryption — plaintext transmission
3. Broadcast — all nodes receive all messages
4. Priority flooding — ID=0x000 message repetition causes DoS
```

---

## 3. Attack Surface Overview

### 3.1 Remote Attack Surface

```
┌─────────────────────────────────────────────────────────────┐
│                    Remote Attack Surface                      │
│                                                              │
│  OTA Updates (Over-The-Air)                                 │
│  ├── Fake update server → install malicious firmware         │
│  ├── No integrity verification → arbitrary code execution    │
│  └── Man-in-the-Middle → tamper update content              │
│                                                              │
│  Telematics                                                 │
│  ├── Vulnerable API → remote command execution               │
│  ├── Unauthenticated remote diagnostic ports                 │
│  └── Cloud backend vulnerabilities → vehicle control        │
│                                                              │
│  V2X (Vehicle-to-Everything)                               │
│  ├── V2V: inject fake hazard messages between vehicles      │
│  ├── V2I: fake traffic signal triggers emergency braking    │
│  └── V2N: eavesdrop/tamper network communications          │
│                                                              │
│  Mobile App Integration                                     │
│  ├── Vulnerable BLE pairing → unlock vehicle               │
│  └── Account takeover → remote location tracking, engine   │
└─────────────────────────────────────────────────────────────┘
```

### 3.2 Short-Range Attack Surface

```
Bluetooth (Bluetooth/BLE):
  - Smart key BLE signal relay attack
  - BLE pairing vulnerabilities (BLESA, etc.)
  - HID spoofing for infotainment control

Wi-Fi:
  - Infotainment Wi-Fi hotspot vulnerabilities
  - WPA2 handshake capture → offline cracking
  - Fake AP to bypass OTA updates

TPMS (Tire Pressure Monitoring):
  - 315MHz/433MHz signal spoofing
  - Fake tire pressure warnings → driver manipulation
  - Vehicle tracking (using unique TPMS IDs)
```

### 3.3 Physical Attack Surface

```
OBD-II Port (most dangerous):
  - Direct CAN bus access (no security)
  - Diagnostic sessions to modify ECU parameters
  - Install malicious OBD dongle → remote access backdoor

USB Port:
  - Malicious USB drive → exploit infotainment vulnerabilities
  - BadUSB attacks
  - Abuse as firmware update pathway

JTAG/UART/SPI (physical hacking):
  - Debug pins on ECU board → firmware dump
  - Direct memory read with OpenOCD
  - UART console → bootloader access
```

---

## 4. TARA (Threat Analysis and Risk Assessment)

### 4.1 TARA Process Overview

```
TARA Process (required by ISO/SAE 21434):

Step 1: Asset Identification
  ├── List vehicle functions (braking, steering, remote start, etc.)
  ├── Identify associated ECUs and networks
  └── Identify protected data (location, user info, etc.)

Step 2: Threat Scenario Analysis
  ├── Apply STRIDE model
  │   ├── Spoofing: CAN message forgery
  │   ├── Tampering: firmware modification
  │   ├── Repudiation: log deletion
  │   ├── Information Disclosure: location data exposure
  │   ├── Denial of Service: CAN bus DoS
  │   └── Elevation of Privilege: gateway bypass
  └── Derive attack paths

Step 3: Impact Assessment
  Impact categories:
  ├── Safety: occupant/pedestrian death or injury
  ├── Financial: vehicle theft, insurance fraud
  ├── Privacy: location tracking, personal data
  └── Operational: vehicle function disruption

Step 4: Risk Assessment
  Risk = Attack Likelihood x Impact
  
  Attack likelihood factors:
  ├── Attack path (remote vs. physical)
  ├── Required expertise level
  ├── Known vulnerabilities present
  └── Attack window (exposure duration)

Step 5: Security Controls
  ├── Risk avoidance (Avoid): remove functionality
  ├── Risk mitigation (Mitigate): add security controls
  ├── Risk transfer (Transfer): insurance
  └── Risk acceptance (Accept): low risks
```

---

## 5. ISO/SAE 21434 Cybersecurity Standard Overview

### 5.1 Standard Structure

```
ISO/SAE 21434:2021 — Automotive Cybersecurity Engineering

Section Structure:
  4.  General considerations
  5.  Organizational cybersecurity management
  6.  Project-dependent cybersecurity management
  7.  Distributed cybersecurity activities
  8.  Continuous cybersecurity activities
  9.  Concept phase
  10. Product development
  11. Cybersecurity validation
  12. Production
  13. Operations and maintenance
  14. End of cybersecurity support / decommissioning

Key Requirements:
  ├── Mandatory TARA performance
  ├── Build cybersecurity culture and competencies
  ├── Supply chain security management
  ├── Vulnerability monitoring and response (PSIRT operation)
  └── Incident response planning
```

### 5.2 ISO 21434 vs UN R155 Comparison

| Item | ISO/SAE 21434 | UN Regulation R155 |
|------|---------------|-------------------|
| Type | Technical standard (how-to) | Regulation (legal) |
| Applies to | Automotive OEM/Tier 1 suppliers | Vehicles sold in European market |
| Requirements | Cybersecurity engineering process | CSMS certification |
| Effective | August 2021 | July 2022 (new types), 2024 (all) |
| Relationship | Technical foundation for R155 compliance | 21434 implementation enables compliance |

---

## 6. Real-World Automotive Hacking Timeline

### 6.1 Key Events

```
2010:
  Koscher et al. — first academic CAN bus attack demonstration
  "Experimental Security Analysis of a Modern Automobile"

2011:
  Sam Checkoway et al. — expanded remote attack surface research
  CAN access via telematics, Bluetooth, CD player

2013:
  Charlie Miller & Chris Valasek
  — Physical hacking of Toyota Prius, Ford Escape
  — Demonstrated brake and steering control

2015 (Jeep Cherokee hack):
  Miller & Valasek — most famous remote automotive hack
  ├── Remote exploit of Uconnect telematics system
  ├── Access via Sprint cellular network
  ├── Remote control of A/C, radio, windshield wipers
  ├── Transmission neutral on highway (speed reduction)
  └── Chrysler: 1.4 million vehicle recall → patch distribution

2016:
  Tesla Model S remote hack (Keen Security Lab)
  ├── Remote brake activation
  ├── Auto-park function manipulation
  └── Tesla: OTA patch deployed within 10 days

2019:
  14 BMW vulnerabilities discovered (Keen Security Lab)
  ├── Access via OBD-II, TCU, infotainment
  ├── Remote code execution possible
  └── BMW software update for 1M+ vehicles in 30 countries

2022:
  David Colombo — simultaneous control of 25 Teslas in 25 countries
  (exploited third-party logging app vulnerability, user error)

2023:
  API vulnerabilities discovered across multiple OEMs
  (Kia, Honda, Infiniti, Nissan, etc.)
  → Vehicle location tracking, remote lock/unlock
```

### 6.2 Jeep Cherokee Hack Deep Dive

```
Attack Path:
  Internet → Sprint cellular → Uconnect telematics
           → CAN bus → target ECU

Technical Steps:
  1. Discovered D-Bus service vulnerability in Uconnect system
  2. Reprogrammed V850 chip firmware (CAN bus access pathway)
  3. Controlled brakes, steering, transmission via CAN messages

Lessons Learned:
  - Infotainment directly connected to CAN bus
  - Lack of domain separation (gateway)
  - Inadequate telematics authentication
  - No OTA update mechanism → physical recall required

Industry Changes After:
  - Accelerated adoption of domain separation architecture
  - Mandatory OTA update infrastructure
  - NHTSA cybersecurity guidance publication
```

---

## 7. Python-CAN Beginner's Guide

### 7.1 Installation and Basic Setup

```bash
# Install python-can
pip install python-can

# Set up virtual CAN interface (Linux)
sudo modprobe vcan
sudo ip link add dev vcan0 type vcan
sudo ip link set up vcan0

# Verify
ip link show vcan0

# Install can-utils (tool suite)
sudo apt install can-utils

# Terminal 1: receive CAN messages
candump vcan0

# Terminal 2: send CAN messages
cansend vcan0 123#DEADBEEF
```

### 7.2 Python-CAN Basic Usage

```python
#!/usr/bin/env python3
"""python-can basic usage examples — step-by-step guide for beginners."""

import can
import time

# ─────────────────────────────────────────────────────
# Step 1: Bus connection
# ─────────────────────────────────────────────────────
# Virtual CAN (for testing)
bus = can.interface.Bus(channel='vcan0', interface='socketcan')

# Real hardware (PCAN USB dongle)
# bus = can.interface.Bus(channel='PCAN_USBBUS1', interface='pcan')

# ─────────────────────────────────────────────────────
# Step 2: Send message
# ─────────────────────────────────────────────────────
msg = can.Message(
    arbitration_id=0x123,           # CAN ID (11-bit: 0x000 ~ 0x7FF)
    data=[0xDE, 0xAD, 0xBE, 0xEF], # Data (0~8 bytes)
    is_extended_id=False,            # Use 11-bit ID
)
bus.send(msg)
print(f"Sent: ID={msg.arbitration_id:#05x}, data={msg.data.hex()}")

# ─────────────────────────────────────────────────────
# Step 3: Receive message
# ─────────────────────────────────────────────────────
# Single message receive (with timeout)
received = bus.recv(timeout=1.0)
if received:
    print(f"Received: ID={received.arbitration_id:#05x}, "
          f"data={bytes(received.data).hex()}, "
          f"time={received.timestamp:.3f}")

# Continuous receive (loop)
print("\n[CAN sniffing started — Ctrl+C to stop]")
try:
    while True:
        msg = bus.recv(timeout=0.5)
        if msg:
            data_hex = bytes(msg.data).hex(' ')
            print(f"  [{msg.timestamp:.3f}] "
                  f"ID={msg.arbitration_id:#05x} "
                  f"DLC={msg.dlc} "
                  f"DATA={data_hex}")
except KeyboardInterrupt:
    print("\n[Stopped]")
finally:
    bus.shutdown()
```

---

## 8. Setting Up a Research Environment

```python
#!/usr/bin/env python3
"""Automotive security research environment setup verification tool."""

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
        return ToolStatus(name=name, available=False, version="not installed")
    result = subprocess.run(
        [name, version_arg], capture_output=True, text=True
    )
    version = (result.stdout or result.stderr).split("\n")[0][:50]
    return ToolStatus(name=name, available=True, version=version)


REQUIRED_TOOLS = [
    ("python3",       "--version"),
    ("can-utils",     None),
    ("wireshark",     "--version"),
    ("openssl",       "version"),
    ("r2",            "-version"),
]

PYTHON_LIBS = [
    "can",
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
        return ToolStatus(name=lib, available=False, version="not installed")


def main() -> None:
    print("Automotive Security Research Environment Check")
    print("=" * 50)

    print("\n[System Tools]")
    for name, varg in REQUIRED_TOOLS:
        if name == "can-utils":
            status = ToolStatus(
                name="can-utils",
                available=bool(shutil.which("candump")),
                version="(candump, cansend, canplayer, etc.)",
            )
        else:
            status = check_tool(name, varg or "--version")
        icon = "v" if status.available else "x"
        print(f"  [{icon}] {status.name:20s} {status.version}")

    print("\n[Python Libraries]")
    for lib in PYTHON_LIBS:
        status = check_python_lib(lib)
        icon = "v" if status.available else "x"
        print(f"  [{icon}] {lib:20s} {status.version}")

    print("\n[CAN Interfaces]")
    result = subprocess.run(
        ["ip", "link", "show"], capture_output=True, text=True
    )
    can_ifaces = [
        line.split(":")[1].strip() for line in result.stdout.splitlines()
        if "can" in line.lower() or "vcan" in line.lower()
    ]
    if can_ifaces:
        print(f"  Detected CAN interfaces: {', '.join(can_ifaces)}")
    else:
        print("  No CAN interfaces found (recommend setting up vcan0)")
        print("  Setup: sudo modprobe vcan && sudo ip link add dev vcan0 type vcan")
        print("         sudo ip link set up vcan0")

    print("\n[Installation Commands]")
    print("  sudo apt install can-utils python3-can wireshark")
    print("  pip3 install python-can scapy pwntools")


if __name__ == "__main__":
    main()
```

The next file covers practical CAN bus hacking techniques.

<!-- detect-validate-62 -->
## Vehicle-Isolation Validation — Does Domain Separation Actually Block Traffic?

Vehicle security architecture is judged not by *having split domains* but by **whether the central gateway actually isolates traffic between safety domains (powertrain/chassis) and infotainment, and blocks any path from external interfaces (telematics) into safety domains**. Validate only on **owned vehicles / benches**.

### Item -> Failure mode -> Validation method -> Healthy signal

| Item | Failure mode | Validation method | Healthy signal |
|---|---|---|---|
| Domain separation | Flat bus | Check cross-bus reach | Safety domain isolated |
| Gateway filter | Unfiltered forward | Inspect message routing | Whitelist routing |
| External interface | Direct safety access | Telematics->CAN path | Path blocked |
| Debug port | Unrestricted OBD | Check diagnostic access | Authenticated diag only |

### Defense validation (verify directly)

```bash
# 1) Whether safety-domain IDs appear on the infotainment bus (if so, isolation failed) — owned bench only
candump can0 2>/dev/null | awk '{print $2}' | sort -u | head -20   # check for IDs leaking past the domain boundary
# 2) Whether the gateway forwards only specific IDs (inferring routing whitelist)
candump -n 200 can0 2>/dev/null | awk '{print $2}' | sort | uniq -c | sort -rn | head
```

> Validate only on **owned vehicles / benches** — never on public roads or others' vehicles. "Split the domains" differs from "traffic is actually isolated" — confirm directly via cross-bus reachability ([[37_ICS_SCADA]], [[24_Network_Infrastructure_Security]]).
