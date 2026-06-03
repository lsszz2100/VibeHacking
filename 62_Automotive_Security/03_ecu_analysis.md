> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# ECU 분석 및 펌웨어 해킹

## 0. 초보자를 위한 개념 이해

### ECU 분석이란?

**ECU(Electronic Control Unit) 분석**은 자동차의 엔진, 브레이크, 전송 장치를 제어하는 컴퓨터 모듈의 펌웨어를 역공학해 취약점을 찾거나 동작 원리를 이해하는 연구입니다.

**왜 배우는가:**
```
ECU 분석의 목적:

보안 연구:
  - 취약한 ECU → 차량 안전에 직결
  - 원격 코드 실행 → 브레이크·스티어링 제어

튜닝 연구:
  - ECU 리매핑 → 엔진 성능 최적화
  - 연비 개선, 출력 향상

사고 조사:
  - EDR (Event Data Recorder) 분석
  - 사고 직전 차량 데이터 복구

취약점 예시:
  - 텔레매틱스 ECU 버퍼 오버플로
  - OBD-II 진단 명령 처리 취약점
  - 펌웨어 업데이트 서명 미검증
```

### ECU 분석 접근 방법

```
하드웨어 인터페이스:
  OBD-II 포트     → 진단 데이터, 일부 ECU 접근
  JTAG/SWD 디버그 → 펌웨어 직접 읽기
  UART/CAN 분해   → 직접 통신

펌웨어 추출:
  1. OBD-II 재프로그래밍 모드 → 공식 경로
  2. JTAG 프로브 연결 → 메모리 덤프
  3. 플래시 칩 직접 탈착 → 솔더링 필요

분석 흐름:
  펌웨어 획득 → binwalk 분석 → 파일시스템 추출
  → 문자열 검색 → 함수 분석 (Ghidra)
  → CAN ID 매핑 → 취약점 발견
```

### 필요한 도구
- **binwalk**: 펌웨어 분석·추출
- **Ghidra / IDA Pro**: 펌웨어 역공학
- **J2534 어댑터**: OBD-II 프로그래밍 인터페이스

### 기초 실습 예제
```bash
# 펌웨어 기본 분석 (binwalk)
binwalk -e ecu_firmware.bin    # 내장 파일시스템 추출
binwalk -E ecu_firmware.bin    # 엔트로피 분석 (압축/암호화 감지)

# 문자열 추출
strings ecu_firmware.bin | grep -i "password\|key\|secret"

# CAN ID 매핑 데이터 검색
strings ecu_firmware.bin | grep -E "0x[0-9A-F]{3}" | head -20
```

---

## 학습 목표

이 문서를 마치면 다음을 할 수 있어야 한다:

1. **ECU가 무엇인지** 비전공자에게 설명할 수 있다 — 현대 자동차에 왜 수십~수백 개의 ECU가 있는지 포함.
2. **ECU 내부 구조**를 파악한다 — MCU, Flash, EEPROM, CAN 트랜시버의 역할.
3. **펌웨어 추출 방법** 세 가지 이상을 이해한다 — JTAG, OBD/UDS, SPI Flash 직접 읽기.
4. **UDS 프로토콜의 기본 구조**를 이해하고, 서비스 ID와 세션 타입을 구분한다.
5. **시드-키 인증** 메커니즘의 원리와 취약점을 설명한다.
6. **Ghidra/IDA Pro로 ECU 펌웨어를 리버싱**하는 접근 방법을 안다.
7. **실제 취약점 사례**를 통해 ECU 보안의 중요성을 이해한다.

---

## ECU 기초 — 완전 초보자용

### ECU(Electronic Control Unit)란?

ECU를 한 마디로 설명하면: **자동차의 뇌**다. 단, 뇌가 하나가 아니라 수십~수백 개가 있다는 점이 다르다.

옛날 자동차는 엔진이나 브레이크 같은 핵심 기능을 전부 기계적으로 제어했다. 지금은 거의 모든 기능이 소형 컴퓨터(ECU)에 의해 전자적으로 제어된다.

```
운전자가 가속 페달을 밟는다
    │
    ▼
페달 위치 센서 → ECU (Engine Control Unit)
    │
    ├─ 인젝터: 연료를 얼마나 분사할까?
    ├─ 점화 시스템: 언제 점화할까?
    ├─ 터보 부스트: 압력을 얼마로 할까?
    └─ 변속기 ECU에게 신호 전달 → 적절한 기어 선택
```

비유하자면, ECU는 **작은 스마트 컨트롤러**다. 우리 몸으로 치면 척수나 뇌간처럼 특정 기능을 전담하는 하위 뇌에 해당한다. "심장 박동"을 담당하는 뉴런 집단이 있듯이, 자동차에는 "엔진 제어"를 담당하는 ECU, "브레이크 제어"를 담당하는 ECU, "에어백 제어"를 담당하는 ECU가 따로 있다.

### 현대 자동차의 ECU 수

- **소형 경제차**: 보통 30~50개의 ECU
- **일반 세단/SUV**: 보통 50~100개의 ECU
- **고급 전기차 (Tesla, BMW 7 Series 등)**: 100~150개 이상

BMW 7 Series의 경우 약 150개, 현대 제네시스 G90은 약 100개의 ECU가 탑재되어 있다고 알려져 있다. 이들 ECU는 **차량 내 네트워크(CAN bus, LIN bus, Ethernet)**를 통해 서로 통신한다.

### 주요 ECU 유형

| ECU 이름 | 약어 | 담당 기능 |
|----------|------|-----------|
| Engine Control Module | ECM / PCM | 엔진 연료 분사, 점화, 배기가스 제어 |
| Transmission Control Module | TCM | 변속 시점, 클러치 제어 |
| Body Control Module | BCM | 창문, 도어락, 조명, 경적 |
| Anti-lock Braking System ECU | ABS ECU | 제동 시 바퀴 잠김 방지 |
| Airbag Control Unit | ACU / SRS | 충돌 감지, 에어백 전개 |
| Electronic Stability Control | ESC / ESC ECU | 미끄러짐 방지, 차체 안정성 |
| Gateway ECU | GW | 네트워크 간 메시지 중계 및 필터링 |
| Telematics Control Unit | TCU | 원격 통신, 내비게이션 서버 연결 |
| ADAS ECU | - | 자율 주행 보조 (크루즈 컨트롤, 차선 유지) |

### ECU 내부 구조

```
ECU 보드 구성
├── MCU/CPU (마이크로컨트롤러)
│   ├── 프로세서 코어 (32-bit: ARM, TriCore, RH850, SPC56x 등)
│   ├── 내장 플래시 (0.5~4MB, 소형 ECU용)
│   ├── 내장 RAM (수십~수백 KB)
│   └── 주변장치: ADC, PWM, CAN 컨트롤러, SPI, I2C, UART
│
├── 외장 플래시 메모리 (1~32MB)
│   └── 펌웨어, 캘리브레이션 데이터, 진단 코드
│
├── EEPROM (수 KB~수십 KB)
│   └── 설정값, 주행 기록, 고장 코드(DTC) 누적 기록
│
├── CAN 트랜시버
│   └── MCU의 논리 신호(0/1)를 CAN bus 전기 신호(차동전압)로 변환
│
├── LIN 트랜시버 (선택 — 간단한 센서/액추에이터용)
│
└── 전원 관리 IC
    └── 차량 배터리 전압(12V)을 MCU용 3.3V/5V로 변환
```

**비유**: MCU는 노트북의 CPU, 플래시는 SSD, EEPROM은 USB 드라이브(작고 내구성 좋음), CAN 트랜시버는 LAN 카드(네트워크 인터페이스)에 해당한다.

---

## ECU 펌웨어란?

### 임베디드 소프트웨어 개념

**펌웨어(Firmware)**는 ECU 플래시 메모리에 저장된 소프트웨어다. 컴퓨터의 운영체제(OS)와 비슷하지만, 특정 하드웨어를 제어하는 데 특화되어 있으며 하드웨어와 매우 밀접하게 연결되어 있다.

- **크기**: 일반적으로 수백 KB ~ 수십 MB
- **언어**: 주로 C (C89/C90), 일부 어셈블리
- **RTOS**: AUTOSAR OS, FreeRTOS, OSEK/VDX 등 실시간 운영체제 사용
- **업데이트 방식**: OBD-II 포트를 통한 UDS 플래시 프로그래밍, 무선(OTA) 업데이트

### 펌웨어 분석이 왜 중요한가?

1. **보안 취약점 발견**: 버퍼 오버플로우, 하드코딩된 키, 취약한 인증 로직
2. **역공학 (Reverse Engineering)**: 제조사가 공개하지 않은 기능 파악
3. **튜닝 (Chip Tuning)**: 연료 맵, 점화 타이밍 수정 (합법성은 국가/지역마다 다름)
4. **포렌식**: 사고 차량 ECU 데이터에서 충돌 전 속도, 제동 정보 추출
5. **표준 준수 확인**: ISO 26262 (기능 안전), UNECE WP.29 (사이버보안 규제)

### 펌웨어 추출 방법 개요

```
방법 1: UDS/OBD를 통한 추출
  장점: 비파괴적, 추가 장비 불필요 (OBD-II 어댑터만 있으면 됨)
  단점: 보안 접근(Security Access)이 필요할 수 있음, 일부 ECU는 읽기 불가

방법 2: JTAG/SWD 디버그 인터페이스
  장점: 전체 메모리 덤프 가능, 실행 중 디버깅
  단점: 하드웨어 접근 필요, JTAG 핀 식별 필요, 일부 ECU는 JTAG 잠금

방법 3: SPI Flash 칩 직접 읽기
  장점: 가장 신뢰성 높음, JTAG 잠금 우회 가능
  단점: 납땜 기술 필요, 칩 손상 위험, 장비 필요 (flashrom, SPI 클립)

방법 4: 부트로더 익스플로잇
  장점: 특별한 하드웨어 불필요할 수 있음
  단점: 특정 모델/버전에만 적용 가능
```

---

## ECU 하드웨어 분석

### 일반적인 ECU 아키텍처

```
ECU 보드 구성
├── 마이크로컨트롤러 (MCU)
│   ├── Renesas RH850, RL78
│   ├── NXP S32K, MPC57xx
│   ├── Infineon TC2xx, TC3xx (TriCore)
│   └── STMicroelectronics SPC5xx
├── 플래시 메모리 (1~32MB)
├── EEPROM (설정 저장)
├── CAN 트랜시버
├── LIN 트랜시버 (선택)
└── 전원 관리 IC
```

### 물리적 접근 방법

```bash
# 1. JTAG/SWD 디버그 인터페이스
#    — JTAG 핀 탐색: 로직 분석기나 멀티미터로 보드 스캔
#    — 일반적인 JTAG 핀: TDI, TDO, TCK, TMS, TRST, GND
#    — OpenOCD로 연결하여 halt, 메모리 덤프, 실행 재개
#    — SWD (Serial Wire Debug): ARM Cortex용 2핀 디버그 인터페이스

# 2. 부트로더 모드 진입
#    — BOOT 핀을 특정 레벨로 설정 (보통 GND 또는 VCC)
#    — CAN/LIN/FlexRay 부트로더 프로토콜로 플래시 재프로그래밍
#    — 제조사 진단 장비 없이 부트로더에 직접 접근 시도

# 3. 플래시 칩 직접 읽기
#    — SPI Flash 칩 식별: SOIC8, WSON8 패키지
#    — 칩 탈납(desoldering) 또는 SOIC 클립으로 연결
#    — flashrom으로 읽기: flashrom -p ft2232_spi:type=232H -r firmware.bin

# 4. 진단 포트 접근 (CAN via OBD-II)
#    — UDS 프로토콜 활용 (서비스 0x23: ReadMemoryByAddress)
#    — 보안 접근(Security Access) 필요 여부 확인
```

---

## ECU 통신 프로토콜

### OBD-II와 UDS의 관계

먼저 용어를 정리하자:

- **OBD-II**: 차량 진단 포트 표준. "어디에 꽂느냐"를 정의 (물리 커넥터, 핀 배치).
- **CAN bus**: 차량 내부 통신 네트워크. "어떤 전선으로 연결되어 있느냐".
- **UDS (ISO 14229)**: 진단 서비스 프로토콜. "어떤 언어로 ECU와 대화하느냐".

비유: OBD-II 포트는 USB 포트, CAN bus는 USB 케이블 내부 전선, UDS는 USB 프로토콜(USB 3.0 규격 등)에 해당한다.

### UDS(Unified Diagnostic Services)

UDS는 ECU와 진단 장비 사이의 "표준 대화 언어"다. ISO 14229로 표준화되어 있으며, 자동차 제조사, 딜러십 진단 장비, 애프터마켓 스캐너 모두 이 프로토콜을 사용한다.

#### UDS 세션 타입

UDS에는 세 가지 주요 세션이 있다. 마치 컴퓨터의 "일반 모드", "관리자 모드", "유지보수 모드"와 같다:

```
Default Session (0x01)
└─ 누구나 접근 가능
└─ 기본 진단 정보 읽기 (DTC 코드 등)

Extended Diagnostic Session (0x03)
└─ 추가 진단 기능 활성화
└─ 더 많은 DID 읽기, 설정 변경 가능
└─ 보안 접근 없이 일부 기능 사용 가능

Programming Session (0x02)
└─ 펌웨어 업데이트 전용
└─ 반드시 Security Access 필요
└─ 잘못 사용하면 ECU 벽돌화(brick) 위험!
```

#### 주요 UDS 서비스 ID

```
서비스 ID | 이름                  | 설명
0x10      | DiagnosticSessionControl | 세션 전환
0x11      | ECUReset               | ECU 재설정
0x22      | ReadDataByIdentifier   | DID로 데이터 읽기
0x23      | ReadMemoryByAddress    | 메모리 주소로 직접 읽기
0x27      | SecurityAccess         | 시드-키 인증
0x2E      | WriteDataByIdentifier  | DID에 데이터 쓰기
0x34      | RequestDownload        | 데이터 다운로드 요청 (플래시 업데이트)
0x36      | TransferData           | 데이터 전송
0x37      | RequestTransferExit    | 전송 종료
0x3D      | WriteMemoryByAddress   | 메모리 주소에 직접 쓰기
0x3E      | TesterPresent          | "나 아직 연결 중" 유지 신호
```

### 보안 접근(Security Access) — 시드-키 인증

UDS의 Security Access (서비스 0x27)는 ECU의 잠금 해제 메커니즘이다. 은행 금고의 조합 자물쇠와 비슷하다:

```
1단계: 진단 장비가 ECU에게 요청
  요청: [0x27] [0x01]  (레벨 1 시드 요청)

2단계: ECU가 시드(Seed) 값 응답
  응답: [0x67] [0x01] [시드: AA BB CC DD]
  — 매번 다른 4바이트 난수

3단계: 진단 장비가 시드로 키(Key) 계산
  키 = 제조사 고유 알고리즘(시드)
  — XOR, CRC, AES 등 다양한 방식

4단계: 진단 장비가 키를 ECU에 전송
  요청: [0x27] [0x02] [키: 계산된 값]

5단계: ECU가 키 검증 후 잠금 해제
  일치: [0x67] [0x02] → 성공! 추가 서비스 이용 가능
  불일치: [0x7F] [0x27] [0x35] (NRC: invalidKey)
```

**취약점**: 제조사가 간단한 알고리즘(예: XOR, 단순 덧셈)을 사용하거나, 시드가 충분히 무작위적이지 않으면 역공학으로 키 알고리즘을 알아낼 수 있다.

### OBD-II PIDs

OBD-II PID(Parameter ID)는 차량 실시간 데이터를 읽는 표준 방법이다:

```
모드 01: 현재 데이터
  PID 0x0C: 엔진 RPM
  PID 0x0D: 차속 (km/h)
  PID 0x05: 냉각수 온도 (°C)
  PID 0x11: 스로틀 위치 (%)
  PID 0x0B: 흡기 매니폴드 압력

모드 03: 저장된 고장 코드 (DTC)
모드 04: DTC 초기화
모드 09: 차량 정보 (VIN 번호 등)
```

---

## 펌웨어 덤프

### JTAG를 통한 덤프

```bash
# OpenOCD 설정 (Renesas RH850 예시)
# FTDI FT2232H 기반 JTAG 어댑터 사용
cat > openocd.cfg <<'EOF'
interface ftdi
ftdi_device_desc "FTDI USB Serial"
ftdi_vid_pid 0x0403 0x6010

# JTAG 속도 (MHz) — 너무 빠르면 신호 오류 발생
adapter_khz 1000

set CHIP_NAME R7F701035
source [find target/renesas_rh850.cfg]
EOF

# OpenOCD 시작
openocd -f openocd.cfg

# 다른 터미널에서 telnet으로 OpenOCD CLI 접속
telnet localhost 4444

# OpenOCD 명령어
> halt                                       # CPU 실행 정지
> dump_image ecu_firmware.bin 0x00000000 0x200000  # 시작주소 0x0에서 2MB 덤프
> resume                                     # CPU 재시작
> exit
```

### SPI Flash 직접 읽기

```bash
# flashrom으로 SPI Flash 덤프
# 하드웨어: Bus Pirate, CH341A, FT2232H 등

# CH341A 사용 예시
flashrom -p ch341a_spi -r firmware.bin

# FT2232H 사용 예시
flashrom -p ft2232_spi:type=232H,port=A -r firmware.bin

# 읽기 후 파일 정보 확인
file firmware.bin
# ELF binary, SREC, raw binary, 또는 알 수 없는 포맷

# 바이너리 엔트로피 확인 (높은 엔트로피 = 압축 또는 암호화)
binwalk -E firmware.bin

# 알려진 헤더/구조 탐색
binwalk firmware.bin

# 파일 시스템이나 압축 데이터 추출
binwalk -e firmware.bin
```

### UDS 메모리 읽기

```python
#!/usr/bin/env python3
"""UDS 프로토콜을 통한 ECU 데이터 읽기.

사용 예:
    python3 ecu_analysis.py vcan0 session
    python3 ecu_analysis.py vcan0 security --level 1
    python3 ecu_analysis.py vcan0 enum-did --start 0xF100 --end 0xF1FF
    python3 ecu_analysis.py vcan0 read-did 0xF190
"""

import argparse
import can
import time
import sys
from dataclasses import dataclass


# ===== UDS 서비스 ID (ISO 14229) =====
# 각 서비스는 특정 기능에 해당하는 1바이트 코드
SID_DIAG_SESSION    = 0x10  # 진단 세션 전환 (Default/Extended/Programming)
SID_ECU_RESET       = 0x11  # ECU 재설정
SID_CLEAR_DTC       = 0x14  # 고장 코드 초기화
SID_READ_DTC        = 0x19  # 고장 코드 읽기
SID_READ_DATA       = 0x22  # DID(Data Identifier)로 데이터 읽기
SID_READ_MEMORY     = 0x23  # 메모리 주소로 직접 읽기 (취약점 분석에 유용)
SID_SECURITY_ACCESS = 0x27  # 시드-키 보안 인증
SID_COMM_CONTROL    = 0x28  # 통신 제어 (CAN 메시지 활성화/비활성화)
SID_WRITE_DATA      = 0x2E  # DID에 데이터 쓰기
SID_IO_CONTROL      = 0x2F  # I/O 강제 제어 (액추에이터 직접 구동)
SID_ROUTINE_CONTROL = 0x31  # 루틴(함수) 실행
SID_REQUEST_DL      = 0x34  # 펌웨어 다운로드 요청
SID_TRANSFER_DATA   = 0x36  # 펌웨어 데이터 전송
SID_REQUEST_TX_EXIT = 0x37  # 전송 종료
SID_TESTER_PRESENT  = 0x3E  # 진단 세션 유지 (keepalive)

# ===== UDS 세션 타입 =====
SESSION_DEFAULT     = 0x01  # 기본: 일반 진단
SESSION_PROGRAMMING = 0x02  # 프로그래밍: 펌웨어 업데이트 (위험!)
SESSION_EXTENDED    = 0x03  # 확장: 추가 진단 기능

# ===== Negative Response Code (오류 코드) =====
NRC_CODES: dict[int, str] = {
    0x10: "generalReject",                           # 일반 거부
    0x11: "serviceNotSupported",                     # 서비스 미지원
    0x12: "subFunctionNotSupported",                 # 서브함수 미지원
    0x13: "incorrectMessageLengthOrInvalidFormat",   # 메시지 길이/형식 오류
    0x22: "conditionsNotCorrect",                    # 조건 불충족 (세션 오류 등)
    0x24: "requestSequenceError",                    # 요청 순서 오류
    0x31: "requestOutOfRange",                       # 범위 초과
    0x33: "securityAccessDenied",                    # 보안 접근 거부
    0x35: "invalidKey",                              # 잘못된 키
    0x36: "exceededNumberOfAttempts",                # 시도 횟수 초과 (잠금!)
    0x37: "requiredTimeDelayNotExpired",             # 대기 시간 미충족
    0x70: "uploadDownloadNotAccepted",               # 업로드/다운로드 거부
    0x72: "generalProgrammingFailure",               # 플래시 프로그래밍 실패
    0x7E: "subFunctionNotSupportedInActiveSession",  # 현재 세션에서 서브함수 미지원
    0x7F: "serviceNotSupportedInActiveSession",      # 현재 세션에서 서비스 미지원
}


@dataclass
class UDSResponse:
    """UDS 응답 패킷을 파싱한 결과."""
    service_id: int      # 응답 서비스 ID (요청 ID + 0x40)
    data: bytes          # 페이로드 데이터
    is_positive: bool    # True: 긍정 응답, False: 부정 응답 (0x7F)
    nrc: int = 0         # Negative Response Code (부정 응답 시 오류 코드)


def send_uds(
    bus: can.Bus,
    tx_id: int,
    rx_id: int,
    request: bytes,
    timeout: float = 2.0,
) -> UDSResponse | None:
    """UDS 요청 전송 및 응답 수신.

    단일 프레임(7바이트 이하) ISO 15765-2 (CAN TP) 전송만 지원.
    멀티프레임 전송이 필요한 경우 python-isotp 라이브러리 사용 권장.

    Args:
        bus: python-can Bus 인스턴스
        tx_id: 전송 CAN ID (진단 장비 → ECU, 보통 0x7E0)
        rx_id: 수신 CAN ID (ECU → 진단 장비, 보통 0x7E8)
        request: UDS 요청 바이트 (서비스 ID + 파라미터)
        timeout: 응답 대기 시간 (초)

    Returns:
        UDSResponse 인스턴스, 또는 타임아웃 시 None
    """
    if len(request) <= 7:
        # ISO 15765-2 단일 프레임: [0x0N] [데이터N바이트] [패딩]
        # 첫 바이트: 상위 4비트 = 프레임 타입(0x0=단일), 하위 4비트 = 길이
        frame_data = bytes([len(request)]) + request + bytes(7 - len(request))
        frame = can.Message(
            arbitration_id=tx_id,
            data=frame_data,
            is_extended_id=False,  # 표준 11비트 CAN ID 사용
        )
        bus.send(frame)
    else:
        print("[!] 멀티프레임 미지원 — python-isotp 라이브러리 사용 권장", file=sys.stderr)
        return None

    # 응답 수신 (타임아웃 내)
    deadline = time.time() + timeout
    while time.time() < deadline:
        msg = bus.recv(timeout=0.1)
        if msg and msg.arbitration_id == rx_id:
            data = bytes(msg.data)
            length = data[0] & 0x0F   # 하위 4비트 = 실제 데이터 길이
            payload = data[1:1 + length]

            if payload and payload[0] == 0x7F:
                # 부정 응답: [0x7F] [서비스ID] [NRC]
                nrc = payload[2] if len(payload) > 2 else 0
                nrc_desc = NRC_CODES.get(nrc, f"Unknown(0x{nrc:02X})")
                print(f"  [NRC] {nrc_desc}", file=sys.stderr)
                return UDSResponse(
                    service_id=payload[1] if len(payload) > 1 else 0,
                    data=payload,
                    is_positive=False,
                    nrc=nrc,
                )
            return UDSResponse(
                service_id=payload[0] if payload else 0,
                data=payload[1:] if len(payload) > 1 else b"",
                is_positive=True,
            )
    return None


def change_session(bus: can.Bus, tx_id: int, rx_id: int, session: int) -> bool:
    """UDS 진단 세션 전환 (0x10 서비스).

    Args:
        session: SESSION_DEFAULT, SESSION_EXTENDED, SESSION_PROGRAMMING 중 하나
    """
    resp = send_uds(bus, tx_id, rx_id, bytes([SID_DIAG_SESSION, session]))
    if resp is None or not resp.is_positive:
        return False
    return True


def keep_alive(bus: can.Bus, tx_id: int, rx_id: int) -> None:
    """TesterPresent 전송으로 진단 세션 유지.

    Extended/Programming 세션은 일정 시간(보통 5초) 동안 요청이 없으면
    자동으로 Default 세션으로 복귀한다. 이 함수로 세션을 유지한다.
    """
    send_uds(bus, tx_id, rx_id, bytes([SID_TESTER_PRESENT, 0x00]))


def security_access(bus: can.Bus, tx_id: int, rx_id: int, level: int) -> bool:
    """시드-키 보안 접근 (0x27 서비스).

    실제 ECU의 키 알고리즘은 제조사마다 다르다. 여기서는 분석용으로
    간단한 XOR 예시를 사용하지만, 실제 분석에서는 펌웨어 리버싱을 통해
    알고리즘을 파악해야 한다.

    Args:
        level: 보안 접근 레벨 (홀수: 시드 요청, 짝수: 키 전송)
               레벨 1: 일반 접근
               레벨 3: 고급 접근 (제조사별 상이)
    """
    # Step 1: 시드 요청 (홀수 레벨)
    print(f"[*] 보안 접근 레벨 {level} 시드 요청 중...")
    resp = send_uds(bus, tx_id, rx_id, bytes([SID_SECURITY_ACCESS, level]))

    if not resp or not resp.is_positive:
        print("[!] 시드 요청 실패")
        return False

    if len(resp.data) < 4:
        print(f"[!] 시드 응답이 너무 짧음: {resp.data.hex()}")
        return False

    seed = resp.data[:4]
    print(f"[*] 시드 수신: {seed.hex().upper()}")

    # Step 2: 키 계산 (이 부분은 제조사별로 다름 — 펌웨어 리버싱 필요)
    # 예시: 단순 비트 반전 (XOR 0xFF) — 대부분의 실제 ECU에는 적용 안 됨
    key = bytes(b ^ 0xFF for b in seed)
    print(f"[*] 키 계산 (예시 알고리즘): {key.hex().upper()}")
    print(f"    [!] 실제 알고리즘은 펌웨어 리버싱으로 파악 필요")

    # Step 3: 키 전송 (짝수 레벨 = 홀수 + 1)
    resp2 = send_uds(
        bus, tx_id, rx_id,
        bytes([SID_SECURITY_ACCESS, level + 1]) + key,
    )

    if resp2 and resp2.is_positive:
        print("[+] 보안 접근 성공!")
        return True

    nrc = resp2.nrc if resp2 else 0
    nrc_desc = NRC_CODES.get(nrc, f"Unknown")
    print(f"[-] 보안 접근 실패: {nrc_desc} (NRC: 0x{nrc:02X})")

    if nrc == 0x36:
        print("[!] 경고: 시도 횟수 초과 — ECU가 잠겼을 수 있음!")
        print("[!] 일정 시간 대기 후 재시도 (보통 10분~1시간)")

    return False


def read_data_by_id(bus: can.Bus, tx_id: int, rx_id: int, did: int) -> bytes | None:
    """데이터 식별자(DID)로 ECU 데이터 읽기 (0x22 서비스).

    DID(Data IDentifier)는 2바이트 ID로 ECU 내의 특정 데이터를 참조한다.
    표준 DID (0xF1xx): 제조사 정보, VIN, 소프트웨어 버전 등
    제조사 DID: 모델마다 다른 ECU 고유 데이터
    """
    request = bytes([SID_READ_DATA, (did >> 8) & 0xFF, did & 0xFF])
    resp = send_uds(bus, tx_id, rx_id, request)

    if resp and resp.is_positive:
        # 응답: [DID 상위] [DID 하위] [실제 데이터...]
        return resp.data[2:] if len(resp.data) > 2 else resp.data
    return None


def read_memory_by_address(
    bus: can.Bus,
    tx_id: int,
    rx_id: int,
    address: int,
    length: int,
    addr_len: int = 4,
) -> bytes | None:
    """메모리 주소로 직접 읽기 (0x23 서비스).

    ECU 펌웨어 추출 시 사용. 보안 접근이 필요한 경우가 많다.

    Args:
        address: 읽을 메모리 주소 (예: 0x00000000 플래시 시작)
        length: 읽을 바이트 수
        addr_len: 주소 바이트 수 (보통 4)
    """
    # AddressAndLengthFormatIdentifier: 상위 4비트 = 길이 크기, 하위 4비트 = 주소 크기
    addr_format = (1 << 4) | addr_len  # 1바이트 길이 + N바이트 주소

    addr_bytes = address.to_bytes(addr_len, "big")
    len_bytes = length.to_bytes(1, "big")

    request = bytes([SID_READ_MEMORY, addr_format]) + addr_bytes + len_bytes
    resp = send_uds(bus, tx_id, rx_id, request)

    if resp and resp.is_positive:
        return resp.data
    return None


def enumerate_dids(
    bus: can.Bus,
    tx_id: int,
    rx_id: int,
    start: int = 0xF100,
    end: int = 0xF1FF,
) -> dict[int, bytes]:
    """DID 열거 — 제조사 데이터 발견.

    0xF1xx 범위: ISO 15031-6 표준 DID (VIN, ECU 소프트웨어 버전 등)
    제조사 전용 DID는 0x0100~0xEFFF 범위에 있을 수 있음.

    Args:
        start: 열거 시작 DID
        end: 열거 종료 DID

    Returns:
        {DID: 데이터} 딕셔너리
    """
    found: dict[int, bytes] = {}
    print(f"[*] DID 열거 시작: 0x{start:04X} ~ 0x{end:04X} ({end - start + 1}개)")

    for did in range(start, end + 1):
        data = read_data_by_id(bus, tx_id, rx_id, did)
        if data:
            found[did] = data
            # 프린트 가능한 문자만 출력, 나머지는 '.'으로 표시
            printable = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
            print(f"  [+] DID 0x{did:04X}: {data.hex()} | {printable}")

        # ECU 과부하 방지를 위해 약간의 지연
        time.sleep(0.05)

    return found


def fuzz_services(bus: can.Bus, tx_id: int, rx_id: int) -> list[int]:
    """지원되는 UDS 서비스 ID 퍼징으로 발견.

    ECU가 어떤 서비스를 지원하는지 확인하기 위해
    0x00~0xFF 범위의 모든 서비스 ID를 시도한다.
    """
    supported: list[int] = []
    print("[*] UDS 서비스 퍼징 시작...")

    for sid in range(0x10, 0xFF):
        resp = send_uds(bus, tx_id, rx_id, bytes([sid]), timeout=0.5)

        if resp is None:
            continue  # 응답 없음

        # NRC 0x11(serviceNotSupported)이 아닌 응답 = 서비스가 존재함
        if resp.is_positive or (not resp.is_positive and resp.nrc != 0x11):
            supported.append(sid)
            status = "OK" if resp.is_positive else f"NRC 0x{resp.nrc:02X}"
            print(f"  [+] SID 0x{sid:02X}: {status}")

    return supported


def main() -> None:
    parser = argparse.ArgumentParser(
        description="UDS ECU 분석 도구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
예시:
  %(prog)s vcan0 session                    # 세션 전환 테스트
  %(prog)s vcan0 security --level 1         # 보안 접근 테스트
  %(prog)s vcan0 enum-did                   # 표준 DID 열거
  %(prog)s vcan0 enum-did --start 0x0100 --end 0x02FF  # 제조사 DID
  %(prog)s vcan0 read-did 0xF190            # VIN 읽기
  %(prog)s vcan0 fuzz                       # 서비스 퍼징
        """,
    )
    parser.add_argument("interface", help="CAN 인터페이스 (예: vcan0, can0)")
    parser.add_argument(
        "--tx-id",
        type=lambda x: int(x, 16),
        default=0x7E0,
        help="전송 CAN ID (기본: 0x7E0 — 범용 진단)",
    )
    parser.add_argument(
        "--rx-id",
        type=lambda x: int(x, 16),
        default=0x7E8,
        help="수신 CAN ID (기본: 0x7E8 — 범용 진단 응답)",
    )

    sub = parser.add_subparsers(dest="cmd", required=True)

    # 세션 전환 테스트
    sub.add_parser("session", help="3가지 세션 전환 테스트 (Default/Extended/Programming)")

    # 보안 접근 테스트
    sec_p = sub.add_parser("security", help="시드-키 보안 접근 테스트")
    sec_p.add_argument(
        "--level",
        type=int,
        default=1,
        help="보안 접근 레벨 (기본: 1)",
    )

    # DID 열거
    enum_p = sub.add_parser("enum-did", help="DID 범위 열거")
    enum_p.add_argument(
        "--start",
        type=lambda x: int(x, 16),
        default=0xF100,
        help="시작 DID (기본: 0xF100)",
    )
    enum_p.add_argument(
        "--end",
        type=lambda x: int(x, 16),
        default=0xF1FF,
        help="종료 DID (기본: 0xF1FF)",
    )

    # 개별 DID 읽기
    read_p = sub.add_parser("read-did", help="개별 DID 읽기")
    read_p.add_argument("did", type=lambda x: int(x, 16), help="읽을 DID (예: 0xF190)")

    # 메모리 직접 읽기
    mem_p = sub.add_parser("read-mem", help="메모리 주소 직접 읽기 (0x23)")
    mem_p.add_argument("address", type=lambda x: int(x, 16), help="시작 주소")
    mem_p.add_argument("length", type=int, help="읽을 바이트 수")

    # 서비스 퍼징
    sub.add_parser("fuzz", help="지원 서비스 ID 퍼징으로 발견")

    args = parser.parse_args()

    # CAN 버스 초기화
    try:
        bus = can.interface.Bus(args.interface, interface="socketcan")
    except Exception as e:
        print(f"[!] CAN 인터페이스 열기 실패: {e}", file=sys.stderr)
        print(f"[!] vcan 사용: sudo modprobe vcan && sudo ip link add dev vcan0 type vcan && sudo ip link set up vcan0")
        sys.exit(1)

    try:
        match args.cmd:
            case "session":
                print("[*] 세션 전환 테스트")
                for session_name, session_id in [
                    ("Default", SESSION_DEFAULT),
                    ("Extended", SESSION_EXTENDED),
                    ("Programming", SESSION_PROGRAMMING),
                ]:
                    ok = change_session(bus, args.tx_id, args.rx_id, session_id)
                    print(f"  세션 {session_name} (0x{session_id:02X}): {'성공' if ok else '실패'}")
                    time.sleep(0.1)

            case "security":
                # 보안 접근 전 Extended 세션 필요
                print("[*] Extended 세션으로 전환...")
                if not change_session(bus, args.tx_id, args.rx_id, SESSION_EXTENDED):
                    print("[!] Extended 세션 전환 실패")
                    sys.exit(1)
                security_access(bus, args.tx_id, args.rx_id, args.level)

            case "enum-did":
                print("[*] Extended 세션으로 전환...")
                change_session(bus, args.tx_id, args.rx_id, SESSION_EXTENDED)
                found = enumerate_dids(
                    bus, args.tx_id, args.rx_id, args.start, args.end
                )
                print(f"\n[+] 발견된 DID: {len(found)}개")

            case "read-did":
                change_session(bus, args.tx_id, args.rx_id, SESSION_EXTENDED)
                data = read_data_by_id(bus, args.tx_id, args.rx_id, args.did)
                if data:
                    printable = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
                    print(f"[+] DID 0x{args.did:04X}: {data.hex()} | {printable}")
                else:
                    print(f"[-] DID 0x{args.did:04X}: 응답 없음 또는 지원 안 됨")

            case "read-mem":
                change_session(bus, args.tx_id, args.rx_id, SESSION_EXTENDED)
                data = read_memory_by_address(
                    bus, args.tx_id, args.rx_id, args.address, args.length
                )
                if data:
                    print(f"[+] 주소 0x{args.address:08X}: {data.hex()}")
                else:
                    print(f"[-] 읽기 실패 (보안 접근 필요할 수 있음)")

            case "fuzz":
                supported = fuzz_services(bus, args.tx_id, args.rx_id)
                print(f"\n[+] 지원 서비스: {len(supported)}개")
                for sid in supported:
                    print(f"  SID 0x{sid:02X}")
    finally:
        bus.shutdown()


if __name__ == "__main__":
    main()
```

---

## 펌웨어 리버싱

### 왜 리버싱이 필요한가?

ECU 펌웨어에서 취약점을 찾으려면 바이너리 수준에서 코드를 분석해야 한다. 소스 코드가 공개되지 않기 때문이다.

주요 목표:
- **키 알고리즘 복구**: Security Access의 시드→키 변환 알고리즘 역공학
- **취약점 탐색**: 버퍼 오버플로우, 포맷 스트링, 정수 오버플로우
- **숨겨진 기능 발견**: 제조사 전용 진단 명령, 백도어
- **캘리브레이션 구조 파악**: 연료 맵, 점화 타이밍 테이블 위치

### Ghidra로 ECU 펌웨어 분석

```bash
# Ghidra 설치 (https://ghidra-sre.org)
# 무료, NSA 개발, TriCore/RH850/ARM 모두 지원

# 1단계: 새 프로젝트 생성 후 펌웨어 바이너리 임포트
# File > Import File > firmware.bin
# 형식: Raw Binary
# 언어: 대상 MCU에 맞게 선택
#   - Infineon TriCore: Processors > Tricore:LE:32:TC29x
#   - Renesas RH850: Processors > RH850
#   - NXP S32K (ARM): Processors > ARM:LE:32:v7

# 2단계: 메모리 맵 설정 (매우 중요!)
# Window > Memory Map
# 플래시 시작 주소 설정 (MCU 데이터시트 참조)
# 예: TriCore TC299 — 플래시: 0x80000000, RAM: 0xD0000000

# 3단계: 인터럽트 벡터 테이블 분석
# ECU 펌웨어의 시작점: 인터럽트 벡터 테이블
# 각 인터럽트 핸들러 함수로 크로스 레퍼런스

# 4단계: UDS 서비스 디스패처 찾기
# CAN 수신 인터럽트 핸들러 → ISO 15765-2 파서 → UDS 디스패처
# 서비스 ID(0x27 등)를 상수로 검색

# 키 알고리즘 역공학
grep -r "SecurityAccess\|0x27\|SID_27" ghidra_export/ 2>/dev/null

# 5단계: Ghidra Script로 자동화
# Window > Script Manager > 새 스크립트 작성
```

```python
# Ghidra Python 스크립트 예시: UDS 서비스 핸들러 자동 탐지
# (Ghidra Script Manager에서 실행)

# 서비스 ID 상수를 참조하는 함수 찾기
from ghidra.program.model.symbol import RefType

TARGET_SIDS = [0x27, 0x23, 0x34, 0x36]  # 보안-관련 서비스 ID

for sid in TARGET_SIDS:
    # 현재 프로그램에서 해당 값을 참조하는 모든 위치 탐색
    refs = getReferencesTo(toAddr(sid))
    if refs:
        print(f"SID 0x{sid:02X} 참조 위치:")
        for ref in refs:
            print(f"  {ref.getFromAddress()}: {ref.getReferenceType()}")
```

### IDA Pro로 RH850 분석

```bash
# IDA Pro 7.x 이상 (상용 도구)
# Renesas RH850 프로세서 모듈 설치 후

# 분석 포인트
# 1. 인터럽트 벡터 테이블
#    — 첫 256바이트: 각 인터럽트의 핸들러 주소
#    — CAN0_RxHandler 등 찾기

# 2. CAN 수신 핸들러
#    — CAN 프레임 파싱 코드
#    — Arbitration ID 비교 구문 (0x7E0, 0x7DF 등)

# 3. UDS 서비스 디스패처
#    — 서비스 ID에 따른 switch-case 또는 if-else 구조
#    — 각 서비스 핸들러 함수로의 점프 테이블

# 4. SecurityAccess 핸들러 (0x27)
#    — SeedGenerate() 함수: 시드 생성
#    — KeyCalculate() 함수: 키 계산 (역공학 대상!)
#    — KeyVerify() 함수: 키 비교

# 디컴파일 결과 예시 (HexRays 플러그인)
# int SecurityAccessHandler(uint8_t *request, uint32_t len) {
#     if (request[1] == 0x01) {  // 시드 요청
#         seed = GenerateSeed();
#         gCurrentSeed = seed;
#         SendPositiveResponse(0x27, 0x01, &seed, 4);
#     } else if (request[1] == 0x02) {  // 키 전송
#         key_received = *(uint32_t*)(&request[2]);
#         key_expected = CalculateKey(gCurrentSeed);  // ← 이 함수 역공학!
#         if (key_received == key_expected) {
#             gSecurityLevel = 1;
#             SendPositiveResponse(0x27, 0x02, NULL, 0);
#         }
#     }
# }
```

---

## 취약점 분석 방법론

### 전체 분석 흐름

```
1. 펌웨어 추출
   └─ JTAG / SPI / UDS 중 가능한 방법 선택

2. 정적 분석 (실행 없이)
   ├─ binwalk: 헤더, 파일시스템, 알려진 패턴 탐색
   ├─ strings: 문자열 추출 (URL, 패스워드, 에러 메시지)
   └─ Ghidra/IDA: 디스어셈블 → 디컴파일 → 코드 분석

3. 동적 분석 (실행하면서)
   ├─ JTAG 디버거: 브레이크포인트, 메모리 읽기/쓰기
   ├─ QEMU: 일부 ECU 아키텍처 에뮬레이션
   └─ Frida: 함수 후킹 (Cortex-M 등)

4. 퍼징 (Fuzzing)
   ├─ UDS 서비스에 비정상 입력 전송
   ├─ CAN 메시지 퍼징 (python-can + 자체 퍼저)
   └─ 응답 패턴으로 충돌/이상 동작 탐지

5. 취약점 검증
   └─ PoC 개발 및 실제 ECU에서 검증
```

### 퍼징 (Fuzzing) 예시

```python
#!/usr/bin/env python3
"""ECU UDS 서비스 기초 퍼저.

비정상적인 입력을 보내 ECU의 예상치 못한 동작을 유발하거나
오류 응답 패턴을 분석한다.
"""

import can
import time
import random
import sys
from dataclasses import dataclass, field


@dataclass
class FuzzResult:
    """퍼징 결과 기록."""
    sid: int
    payload: bytes
    response: bytes | None
    nrc: int = 0
    timeout: bool = False


def fuzz_uds_service(
    bus: can.Bus,
    tx_id: int,
    rx_id: int,
    sid: int,
    iterations: int = 100,
) -> list[FuzzResult]:
    """단일 UDS 서비스에 대한 무작위 퍼징.

    랜덤한 길이와 내용의 페이로드를 생성하여 전송하고
    ECU의 응답을 기록한다.
    """
    results: list[FuzzResult] = []

    for i in range(iterations):
        # 랜덤 페이로드 생성 (1~6바이트)
        payload_len = random.randint(1, 6)
        payload = bytes([sid]) + bytes([random.randint(0, 255) for _ in range(payload_len)])

        # 전송
        frame_data = bytes([len(payload)]) + payload + bytes(7 - len(payload))
        frame = can.Message(arbitration_id=tx_id, data=frame_data, is_extended_id=False)
        bus.send(frame)

        # 응답 수신
        deadline = time.time() + 0.5
        response = None
        while time.time() < deadline:
            msg = bus.recv(timeout=0.1)
            if msg and msg.arbitration_id == rx_id:
                response = bytes(msg.data)
                break

        result = FuzzResult(
            sid=sid,
            payload=payload,
            response=response,
            timeout=(response is None),
        )

        if response and response[1] == 0x7F and len(response) > 3:
            result.nrc = response[3]

        results.append(result)

        # 진행 상황 출력
        if response is None:
            print(f"  [{i:3d}] {payload.hex()} → TIMEOUT")
        elif response[1] != 0x7F:
            print(f"  [{i:3d}] {payload.hex()} → POSITIVE: {response.hex()}")

        time.sleep(0.02)  # ECU 과부하 방지

    return results
```

---

## 실제 취약점 사례

### 사례 1: 취약한 ECU 업데이트 메커니즘

**배경**: 일부 초기 세대 OTA(무선 업데이트) 시스템을 가진 차량에서 펌웨어 이미지에 서명 검증이 없었던 사례.

**공격 시나리오**:
```
1. 공격자가 정상 펌웨어 이미지를 OTA 채널로 가로채거나 수정
2. 악성 코드가 포함된 펌웨어 이미지 생성
3. RequestDownload(0x34) → TransferData(0x36) → RequestTransferExit(0x37)
4. ECU가 서명 없이 펌웨어를 수락하고 플래시에 기록
5. 재부팅 후 악성 코드 실행
```

**근본 원인**: 펌웨어 이미지에 암호학적 서명(ECDSA, RSA 등) 검증 로직 부재.

**대응책**: AUTOSAR SecOC, 부트로더에서 서명 검증, Secure Boot 구현.

### 사례 2: 진단 서비스 악용

**배경**: 특정 차량 모델의 BCM(Body Control Module)에서 WriteDataByIdentifier(0x2E)를 통해 보안 접근 없이 중요 설정을 변경할 수 있었던 사례.

**공격 시나리오**:
```bash
# OBD-II 포트에 접근 (물리적 접근 필요 또는 CAN 인터페이스 설치)

# 1. Extended 세션 전환
python3 ecu_analysis.py can0 session

# 2. BCM DID 열거 (어떤 DID를 쓸 수 있는지 파악)
python3 ecu_analysis.py can0 enum-did --start 0x4000 --end 0x40FF

# 3. 도어락 제어 DID 쓰기 (예시)
# [0x2E] [DID_HIGH] [DID_LOW] [데이터]
# python-can으로 직접 전송
```

**근본 원인**: Security Access 없이 쓰기 서비스(0x2E)가 허용됨.

**대응책**: 쓰기 서비스는 반드시 Security Access 이후에만 허용, Diagnostic Authentication (UDS 2020 추가 기능) 도입.

### 사례 3: 시드-키 알고리즘 취약성

**배경**: 특정 제조사의 ECU에서 Security Access 키 알고리즘이 간단한 XOR 연산으로 구현된 사례.

```python
# 취약한 알고리즘 (역공학으로 파악):
# key = seed XOR 0xCAFEBABE

seed_bytes = bytes.fromhex("A1B2C3D4")
seed_int = int.from_bytes(seed_bytes, "big")
key_int = seed_int ^ 0xCAFEBABE
key_bytes = key_int.to_bytes(4, "big")

print(f"시드: {seed_bytes.hex()}")
print(f"키:   {key_bytes.hex()}")
# 이제 Programming Session에 접근하여 펌웨어 수정 가능
```

**근본 원인**: 알고리즘이 단순하고 펌웨어 리버싱 후 쉽게 재구현 가능.

**대응책**: AES-based CMAC, AUTOSAR SecOC, HSM(Hardware Security Module) 내에서 키 연산 수행.

---

<a name="english"></a>

# ECU Analysis and Firmware Hacking

## Learning Objectives

By the end of this document you should be able to:

1. **Explain what an ECU is** to a non-technical audience — including why a modern car has dozens to hundreds of them.
2. **Understand ECU internal architecture** — the roles of MCU, Flash, EEPROM, and CAN transceiver.
3. **Describe three or more firmware extraction methods** — JTAG, OBD/UDS, and direct SPI Flash reading.
4. **Understand the basic structure of UDS protocol** and distinguish between service IDs and session types.
5. **Explain the seed-key authentication mechanism**, including its principle and vulnerabilities.
6. **Know the approach to reversing ECU firmware** with Ghidra or IDA Pro.
7. **Understand the importance of ECU security** through real-world vulnerability examples.

---

## ECU Basics — For Complete Beginners

### What Is an ECU (Electronic Control Unit)?

In one sentence: an ECU is the **brain of a car**. The difference from a human brain is that a car has not one but dozens to hundreds of these brains.

Older cars controlled all critical functions — engine, brakes — entirely through mechanical linkages. Today, nearly every function is controlled electronically by small computers called ECUs.

```
Driver presses the accelerator pedal
    |
    v
Pedal position sensor → ECU (Engine Control Unit)
    |
    +-- Injectors: how much fuel to inject?
    +-- Ignition system: when to fire?
    +-- Turbo boost: how much pressure?
    +-- Signal to Transmission ECU → choose the appropriate gear
```

Think of each ECU as a **small smart controller**. In biological terms, they are like the spinal cord or brainstem — sub-brains dedicated to specific functions. Just as specific neurons handle heartbeat, a car has an ECU dedicated to engine control, one for brake control, one for airbag control, and so on.

### How Many ECUs Are in a Modern Car?

- **Small economy car**: typically 30–50 ECUs
- **Regular sedan/SUV**: typically 50–100 ECUs
- **Premium electric vehicle (Tesla, BMW 7 Series, etc.)**: 100–150 or more

A BMW 7 Series is reported to contain approximately 150 ECUs, while a Hyundai Genesis G90 has approximately 100. These ECUs communicate with each other via the **in-vehicle network (CAN bus, LIN bus, Automotive Ethernet)**.

### Main ECU Types

| ECU Name | Abbreviation | Function |
|----------|-------------|----------|
| Engine Control Module | ECM / PCM | Fuel injection, ignition, emissions control |
| Transmission Control Module | TCM | Shift timing, clutch control |
| Body Control Module | BCM | Windows, door locks, lighting, horn |
| Anti-lock Braking System ECU | ABS ECU | Preventing wheel lock-up during braking |
| Airbag Control Unit | ACU / SRS | Crash detection, airbag deployment |
| Electronic Stability Control | ESC ECU | Anti-skid, vehicle stability |
| Gateway ECU | GW | Message routing and filtering between networks |
| Telematics Control Unit | TCU | Remote communications, navigation server connection |
| ADAS ECU | — | Autonomous driving assistance (cruise control, lane keeping) |

### ECU Internal Architecture

```
ECU Board Components
├── MCU/CPU (Microcontroller)
│   ├── Processor core (32-bit: ARM, TriCore, RH850, SPC56x, etc.)
│   ├── Embedded flash (0.5–4 MB for small ECUs)
│   ├── Embedded RAM (tens to hundreds of KB)
│   └── Peripherals: ADC, PWM, CAN controller, SPI, I2C, UART
│
├── External flash memory (1–32 MB)
│   └── Firmware, calibration data, diagnostic trouble codes
│
├── EEPROM (a few KB to tens of KB)
│   └── Configuration values, mileage records, accumulated fault codes (DTC)
│
├── CAN transceiver
│   └── Converts MCU logic signals (0/1) to CAN bus electrical signals (differential voltage)
│
├── LIN transceiver (optional — for simple sensors/actuators)
│
└── Power management IC
    └── Steps down vehicle battery voltage (12 V) to MCU supply (3.3 V / 5 V)
```

**Analogy**: The MCU is the laptop's CPU, flash is the SSD, EEPROM is a USB drive (small and durable), and the CAN transceiver is the network card (network interface).

---

## What Is ECU Firmware?

### The Embedded Software Concept

**Firmware** is software stored in the ECU's flash memory. It is similar to a computer's operating system but is highly specialized for controlling specific hardware and is tightly coupled to that hardware.

- **Size**: typically hundreds of KB to tens of MB
- **Language**: mainly C (C89/C90), some assembly
- **RTOS**: real-time operating systems such as AUTOSAR OS, FreeRTOS, OSEK/VDX
- **Update method**: UDS flash programming via OBD-II port, or over-the-air (OTA) updates

### Why Firmware Analysis Matters

1. **Security vulnerability discovery**: buffer overflows, hardcoded keys, weak authentication logic
2. **Reverse engineering**: understanding undocumented features the manufacturer does not publish
3. **Tuning (chip tuning)**: modifying fuel maps, ignition timing (legality varies by country/region)
4. **Forensics**: extracting pre-collision speed and braking data from accident vehicles
5. **Standards compliance verification**: ISO 26262 (functional safety), UNECE WP.29 (cybersecurity regulation)

### Firmware Extraction Method Overview

```
Method 1: Extraction via UDS/OBD
  Advantages: non-destructive, no extra hardware needed (OBD-II adapter only)
  Disadvantages: may require Security Access; some ECUs block readback

Method 2: JTAG/SWD debug interface
  Advantages: full memory dump possible, live debugging during execution
  Disadvantages: requires hardware access, JTAG pin identification, some ECUs have JTAG locked

Method 3: Direct SPI Flash chip reading
  Advantages: most reliable, can bypass JTAG lock
  Disadvantages: requires soldering skills, risk of chip damage, hardware needed (flashrom, SPI clip)

Method 4: Bootloader exploit
  Advantages: may not require special hardware
  Disadvantages: applicable only to specific models/versions
```

---

## ECU Hardware Analysis

### Common ECU Architecture

```
ECU Board Components
├── Microcontroller (MCU)
│   ├── Renesas RH850, RL78
│   ├── NXP S32K, MPC57xx
│   ├── Infineon TC2xx, TC3xx (TriCore)
│   └── STMicroelectronics SPC5xx
├── Flash memory (1–32 MB)
├── EEPROM (configuration storage)
├── CAN transceiver
├── LIN transceiver (optional)
└── Power management IC
```

### Physical Access Methods

```bash
# 1. JTAG/SWD debug interface
#    — Pin discovery: scan the board with a logic analyzer or multimeter
#    — Typical JTAG pins: TDI, TDO, TCK, TMS, TRST, GND
#    — Connect with OpenOCD to halt, dump memory, resume execution
#    — SWD (Serial Wire Debug): 2-pin debug interface for ARM Cortex

# 2. Bootloader mode entry
#    — Set BOOT pin to a specific level (usually GND or VCC)
#    — Re-flash via CAN/LIN/FlexRay bootloader protocol
#    — Attempt direct bootloader access without manufacturer diagnostic tools

# 3. Direct flash chip reading
#    — Identify SPI flash chip: SOIC8, WSON8 packages
#    — Connect by desoldering the chip or using a SOIC clip
#    — Read with flashrom: flashrom -p ft2232_spi:type=232H -r firmware.bin

# 4. Diagnostic port access (CAN via OBD-II)
#    — Use UDS protocol (service 0x23: ReadMemoryByAddress)
#    — Check whether Security Access is required
```

---

## ECU Communication Protocols

### The Relationship Between OBD-II and UDS

First, let us clarify the terminology:

- **OBD-II**: Vehicle diagnostic port standard. Defines *where to plug in* (physical connector, pin layout).
- **CAN bus**: In-vehicle communication network. Defines *which wires connect things*.
- **UDS (ISO 14229)**: Diagnostic service protocol. Defines *what language you use to talk to an ECU*.

Analogy: OBD-II port is a USB port, CAN bus is the wires inside the USB cable, and UDS is the USB protocol specification (like USB 3.0).

### UDS (Unified Diagnostic Services)

UDS is the "standard language of conversation" between ECUs and diagnostic equipment. Standardized as ISO 14229, it is used by vehicle manufacturers, dealership diagnostic tools, and aftermarket scanners alike.

#### UDS Session Types

UDS has three main session types — similar to a computer's "normal mode," "administrator mode," and "maintenance mode":

```
Default Session (0x01)
└─ Accessible to anyone
└─ Read basic diagnostic information (DTC codes, etc.)

Extended Diagnostic Session (0x03)
└─ Additional diagnostic functions enabled
└─ Read more DIDs, change some settings
└─ Some features usable without Security Access

Programming Session (0x02)
└─ Firmware update only
└─ Security Access always required
└─ Incorrect use can brick the ECU!
```

#### Key UDS Service IDs

```
Service ID | Name                   | Description
0x10       | DiagnosticSessionControl | Session switching
0x11       | ECUReset                | ECU reset
0x22       | ReadDataByIdentifier    | Read data by DID
0x23       | ReadMemoryByAddress     | Read directly by memory address
0x27       | SecurityAccess          | Seed-key authentication
0x2E       | WriteDataByIdentifier   | Write data by DID
0x34       | RequestDownload         | Request data download (flash update)
0x36       | TransferData            | Transfer data
0x37       | RequestTransferExit     | End transfer
0x3D       | WriteMemoryByAddress    | Write directly to memory address
0x3E       | TesterPresent           | "I'm still connected" keepalive signal
```

### Security Access — Seed-Key Authentication

UDS Security Access (service 0x27) is the ECU unlock mechanism. It works like a combination lock on a safe:

```
Step 1: Diagnostic tool requests seed from ECU
  Request: [0x27] [0x01]  (level 1 seed request)

Step 2: ECU responds with seed value
  Response: [0x67] [0x01] [seed: AA BB CC DD]
  — A different 4-byte random value each time

Step 3: Diagnostic tool calculates key from seed
  key = manufacturer-proprietary algorithm(seed)
  — Various methods: XOR, CRC, AES, etc.

Step 4: Diagnostic tool sends key to ECU
  Request: [0x27] [0x02] [key: calculated value]

Step 5: ECU verifies key and unlocks
  Match: [0x67] [0x02] → Success! Additional services now available
  Mismatch: [0x7F] [0x27] [0x35] (NRC: invalidKey)
```

**Vulnerability**: If a manufacturer uses a simple algorithm (e.g., XOR, simple addition) or if the seed is not sufficiently random, reverse engineering the firmware can reveal the key algorithm.

### OBD-II PIDs

OBD-II PID (Parameter ID) is the standard method for reading real-time vehicle data:

```
Mode 01: Current data
  PID 0x0C: Engine RPM
  PID 0x0D: Vehicle speed (km/h)
  PID 0x05: Coolant temperature (°C)
  PID 0x11: Throttle position (%)
  PID 0x0B: Intake manifold pressure

Mode 03: Stored diagnostic trouble codes (DTC)
Mode 04: Clear DTCs
Mode 09: Vehicle information (VIN number, etc.)
```

---

## Firmware Dump

### JTAG Dump

```bash
# OpenOCD configuration (Renesas RH850 example)
# Using FTDI FT2232H-based JTAG adapter
cat > openocd.cfg <<'EOF'
interface ftdi
ftdi_device_desc "FTDI USB Serial"
ftdi_vid_pid 0x0403 0x6010

# JTAG speed in kHz — too fast can cause signal errors
adapter_khz 1000

set CHIP_NAME R7F701035
source [find target/renesas_rh850.cfg]
EOF

openocd -f openocd.cfg

# From another terminal, connect to OpenOCD CLI via telnet
telnet localhost 4444

# OpenOCD commands
> halt                                       # Stop CPU execution
> dump_image ecu_firmware.bin 0x00000000 0x200000  # Dump 2 MB from address 0x0
> resume                                     # Resume CPU
> exit
```

### Direct SPI Flash Reading

```bash
# Dump SPI flash with flashrom
# Hardware: Bus Pirate, CH341A, FT2232H, etc.

# Example with CH341A
flashrom -p ch341a_spi -r firmware.bin

# Example with FT2232H
flashrom -p ft2232_spi:type=232H,port=A -r firmware.bin

# Check file type after reading
file firmware.bin
# ELF binary, SREC, raw binary, or unknown format

# Check binary entropy (high entropy = compressed or encrypted)
binwalk -E firmware.bin

# Search for known headers/structures
binwalk firmware.bin

# Extract filesystems or compressed data
binwalk -e firmware.bin
```

### UDS Memory Read

```python
#!/usr/bin/env python3
"""ECU data reading via UDS protocol.

Usage:
    python3 ecu_analysis.py vcan0 session
    python3 ecu_analysis.py vcan0 security --level 1
    python3 ecu_analysis.py vcan0 enum-did --start 0xF100 --end 0xF1FF
    python3 ecu_analysis.py vcan0 read-did 0xF190
"""

import argparse
import can
import time
import sys
from dataclasses import dataclass


# ===== UDS Service IDs (ISO 14229) =====
# Each service is a 1-byte code corresponding to a specific function
SID_DIAG_SESSION    = 0x10  # Diagnostic session control (Default/Extended/Programming)
SID_ECU_RESET       = 0x11  # ECU reset
SID_CLEAR_DTC       = 0x14  # Clear diagnostic trouble codes
SID_READ_DTC        = 0x19  # Read diagnostic trouble codes
SID_READ_DATA       = 0x22  # Read data by DID (Data Identifier)
SID_READ_MEMORY     = 0x23  # Read directly by memory address (useful for firmware extraction)
SID_SECURITY_ACCESS = 0x27  # Seed-key security authentication
SID_COMM_CONTROL    = 0x28  # Communication control (enable/disable CAN messages)
SID_WRITE_DATA      = 0x2E  # Write data by DID
SID_IO_CONTROL      = 0x2F  # Force I/O control (directly drive actuators)
SID_ROUTINE_CONTROL = 0x31  # Execute routine (function)
SID_REQUEST_DL      = 0x34  # Request firmware download
SID_TRANSFER_DATA   = 0x36  # Transfer firmware data
SID_REQUEST_TX_EXIT = 0x37  # End transfer
SID_TESTER_PRESENT  = 0x3E  # Keep diagnostic session alive (keepalive)

# ===== UDS Session Types =====
SESSION_DEFAULT     = 0x01  # Default: standard diagnostics
SESSION_PROGRAMMING = 0x02  # Programming: firmware update (dangerous!)
SESSION_EXTENDED    = 0x03  # Extended: additional diagnostic functions

# ===== Negative Response Codes =====
NRC_CODES: dict[int, str] = {
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
    0x70: "uploadDownloadNotAccepted",
    0x72: "generalProgrammingFailure",
    0x7E: "subFunctionNotSupportedInActiveSession",
    0x7F: "serviceNotSupportedInActiveSession",
}


@dataclass
class UDSResponse:
    """Parsed result of a UDS response packet."""
    service_id: int      # Response service ID (request ID + 0x40)
    data: bytes          # Payload data
    is_positive: bool    # True: positive response; False: negative response (0x7F)
    nrc: int = 0         # Negative Response Code (error code for negative responses)


def send_uds(
    bus: can.Bus,
    tx_id: int,
    rx_id: int,
    request: bytes,
    timeout: float = 2.0,
) -> UDSResponse | None:
    """Send a UDS request and receive the response.

    Supports single-frame (up to 7 bytes) ISO 15765-2 (CAN TP) transmission only.
    For multi-frame transmission, use the python-isotp library.

    Args:
        bus: python-can Bus instance
        tx_id: Transmit CAN ID (tester → ECU, typically 0x7E0)
        rx_id: Receive CAN ID (ECU → tester, typically 0x7E8)
        request: UDS request bytes (service ID + parameters)
        timeout: Response wait time in seconds

    Returns:
        UDSResponse instance, or None on timeout
    """
    if len(request) <= 7:
        # ISO 15765-2 single frame: [0x0N] [N bytes of data] [padding]
        # First byte: upper 4 bits = frame type (0x0 = single), lower 4 bits = length
        frame_data = bytes([len(request)]) + request + bytes(7 - len(request))
        frame = can.Message(
            arbitration_id=tx_id,
            data=frame_data,
            is_extended_id=False,  # Use standard 11-bit CAN ID
        )
        bus.send(frame)
    else:
        print("[!] Multi-frame not supported — use python-isotp library", file=sys.stderr)
        return None

    # Receive response within timeout
    deadline = time.time() + timeout
    while time.time() < deadline:
        msg = bus.recv(timeout=0.1)
        if msg and msg.arbitration_id == rx_id:
            data = bytes(msg.data)
            length = data[0] & 0x0F   # Lower 4 bits = actual data length
            payload = data[1:1 + length]

            if payload and payload[0] == 0x7F:
                # Negative response: [0x7F] [service ID] [NRC]
                nrc = payload[2] if len(payload) > 2 else 0
                nrc_desc = NRC_CODES.get(nrc, f"Unknown(0x{nrc:02X})")
                print(f"  [NRC] {nrc_desc}", file=sys.stderr)
                return UDSResponse(
                    service_id=payload[1] if len(payload) > 1 else 0,
                    data=payload,
                    is_positive=False,
                    nrc=nrc,
                )
            return UDSResponse(
                service_id=payload[0] if payload else 0,
                data=payload[1:] if len(payload) > 1 else b"",
                is_positive=True,
            )
    return None


def change_session(bus: can.Bus, tx_id: int, rx_id: int, session: int) -> bool:
    """Switch UDS diagnostic session (service 0x10).

    Args:
        session: One of SESSION_DEFAULT, SESSION_EXTENDED, SESSION_PROGRAMMING
    """
    resp = send_uds(bus, tx_id, rx_id, bytes([SID_DIAG_SESSION, session]))
    return resp is not None and resp.is_positive


def keep_alive(bus: can.Bus, tx_id: int, rx_id: int) -> None:
    """Send TesterPresent to maintain the diagnostic session.

    Extended/Programming sessions automatically revert to the Default session
    after a period of inactivity (typically 5 seconds). This function keeps
    the session alive.
    """
    send_uds(bus, tx_id, rx_id, bytes([SID_TESTER_PRESENT, 0x00]))


def security_access(bus: can.Bus, tx_id: int, rx_id: int, level: int) -> bool:
    """Seed-key security access (service 0x27).

    The actual key algorithm differs by manufacturer. This example uses
    a simple XOR for demonstration. In real analysis the algorithm must
    be recovered through firmware reverse engineering.

    Args:
        level: Security access level (odd: seed request, even: key send)
               Level 1: standard access
               Level 3: advanced access (varies by manufacturer)
    """
    # Step 1: Request seed (odd level)
    print(f"[*] Requesting seed for security access level {level}...")
    resp = send_uds(bus, tx_id, rx_id, bytes([SID_SECURITY_ACCESS, level]))

    if not resp or not resp.is_positive:
        print("[!] Seed request failed")
        return False

    if len(resp.data) < 4:
        print(f"[!] Seed response too short: {resp.data.hex()}")
        return False

    seed = resp.data[:4]
    print(f"[*] Seed received: {seed.hex().upper()}")

    # Step 2: Calculate key (this part varies by manufacturer — requires firmware reversing)
    # Example: simple bit inversion (XOR 0xFF) — does not apply to most real ECUs
    key = bytes(b ^ 0xFF for b in seed)
    print(f"[*] Key calculated (example algorithm): {key.hex().upper()}")
    print(f"    [!] Real algorithm must be determined through firmware reverse engineering")

    # Step 3: Send key (even level = odd level + 1)
    resp2 = send_uds(
        bus, tx_id, rx_id,
        bytes([SID_SECURITY_ACCESS, level + 1]) + key,
    )

    if resp2 and resp2.is_positive:
        print("[+] Security access successful!")
        return True

    nrc = resp2.nrc if resp2 else 0
    nrc_desc = NRC_CODES.get(nrc, "Unknown")
    print(f"[-] Security access failed: {nrc_desc} (NRC: 0x{nrc:02X})")

    if nrc == 0x36:
        print("[!] Warning: attempt count exceeded — ECU may be locked!")
        print("[!] Wait before retrying (typically 10 minutes to 1 hour)")

    return False


def read_data_by_id(bus: can.Bus, tx_id: int, rx_id: int, did: int) -> bytes | None:
    """Read ECU data by Data Identifier (service 0x22).

    DID (Data IDentifier) is a 2-byte ID referencing specific data within the ECU.
    Standard DIDs (0xF1xx): manufacturer info, VIN, software version, etc.
    Manufacturer DIDs: ECU-specific data that varies by model.
    """
    request = bytes([SID_READ_DATA, (did >> 8) & 0xFF, did & 0xFF])
    resp = send_uds(bus, tx_id, rx_id, request)

    if resp and resp.is_positive:
        # Response: [DID high byte] [DID low byte] [actual data...]
        return resp.data[2:] if len(resp.data) > 2 else resp.data
    return None


def read_memory_by_address(
    bus: can.Bus,
    tx_id: int,
    rx_id: int,
    address: int,
    length: int,
    addr_len: int = 4,
) -> bytes | None:
    """Read directly by memory address (service 0x23).

    Used for firmware extraction. Security access is often required.

    Args:
        address: Memory address to read (e.g., 0x00000000 for flash start)
        length: Number of bytes to read
        addr_len: Address byte count (typically 4)
    """
    # AddressAndLengthFormatIdentifier: upper 4 bits = length size, lower 4 bits = address size
    addr_format = (1 << 4) | addr_len  # 1-byte length + N-byte address

    addr_bytes = address.to_bytes(addr_len, "big")
    len_bytes = length.to_bytes(1, "big")

    request = bytes([SID_READ_MEMORY, addr_format]) + addr_bytes + len_bytes
    resp = send_uds(bus, tx_id, rx_id, request)

    if resp and resp.is_positive:
        return resp.data
    return None


def enumerate_dids(
    bus: can.Bus,
    tx_id: int,
    rx_id: int,
    start: int = 0xF100,
    end: int = 0xF1FF,
) -> dict[int, bytes]:
    """DID enumeration — discover manufacturer data.

    0xF1xx range: ISO 15031-6 standard DIDs (VIN, ECU software version, etc.)
    Manufacturer-proprietary DIDs may exist in the 0x0100–0xEFFF range.

    Args:
        start: Starting DID
        end: Ending DID

    Returns:
        Dictionary of {DID: data}
    """
    found: dict[int, bytes] = {}
    print(f"[*] DID enumeration: 0x{start:04X} ~ 0x{end:04X} ({end - start + 1} DIDs)")

    for did in range(start, end + 1):
        data = read_data_by_id(bus, tx_id, rx_id, did)
        if data:
            found[did] = data
            # Show printable chars only; replace others with '.'
            printable = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
            print(f"  [+] DID 0x{did:04X}: {data.hex()} | {printable}")

        # Small delay to avoid overloading the ECU
        time.sleep(0.05)

    return found


def fuzz_services(bus: can.Bus, tx_id: int, rx_id: int) -> list[int]:
    """Discover supported UDS service IDs through fuzzing.

    Tries all service IDs in the range 0x10–0xFF to determine which
    services the ECU supports.
    """
    supported: list[int] = []
    print("[*] Starting UDS service fuzzing...")

    for sid in range(0x10, 0xFF):
        resp = send_uds(bus, tx_id, rx_id, bytes([sid]), timeout=0.5)

        if resp is None:
            continue  # No response

        # Any response other than NRC 0x11 (serviceNotSupported) means the service exists
        if resp.is_positive or (not resp.is_positive and resp.nrc != 0x11):
            supported.append(sid)
            status = "OK" if resp.is_positive else f"NRC 0x{resp.nrc:02X}"
            print(f"  [+] SID 0x{sid:02X}: {status}")

    return supported


def main() -> None:
    parser = argparse.ArgumentParser(
        description="UDS ECU analysis tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s vcan0 session                    # Test session switching
  %(prog)s vcan0 security --level 1         # Test security access
  %(prog)s vcan0 enum-did                   # Enumerate standard DIDs
  %(prog)s vcan0 enum-did --start 0x0100 --end 0x02FF  # Manufacturer DIDs
  %(prog)s vcan0 read-did 0xF190            # Read VIN
  %(prog)s vcan0 fuzz                       # Fuzz for supported services
        """,
    )
    parser.add_argument("interface", help="CAN interface (e.g., vcan0, can0)")
    parser.add_argument(
        "--tx-id",
        type=lambda x: int(x, 16),
        default=0x7E0,
        help="Transmit CAN ID (default: 0x7E0 — generic diagnostic)",
    )
    parser.add_argument(
        "--rx-id",
        type=lambda x: int(x, 16),
        default=0x7E8,
        help="Receive CAN ID (default: 0x7E8 — generic diagnostic response)",
    )

    sub = parser.add_subparsers(dest="cmd", required=True)

    # Session switching test
    sub.add_parser("session", help="Test all three session types (Default/Extended/Programming)")

    # Security access test
    sec_p = sub.add_parser("security", help="Seed-key security access test")
    sec_p.add_argument(
        "--level",
        type=int,
        default=1,
        help="Security access level (default: 1)",
    )

    # DID enumeration
    enum_p = sub.add_parser("enum-did", help="Enumerate a DID range")
    enum_p.add_argument(
        "--start",
        type=lambda x: int(x, 16),
        default=0xF100,
        help="Starting DID (default: 0xF100)",
    )
    enum_p.add_argument(
        "--end",
        type=lambda x: int(x, 16),
        default=0xF1FF,
        help="Ending DID (default: 0xF1FF)",
    )

    # Read individual DID
    read_p = sub.add_parser("read-did", help="Read a single DID")
    read_p.add_argument("did", type=lambda x: int(x, 16), help="DID to read (e.g., 0xF190)")

    # Direct memory read
    mem_p = sub.add_parser("read-mem", help="Read directly by memory address (0x23)")
    mem_p.add_argument("address", type=lambda x: int(x, 16), help="Starting address")
    mem_p.add_argument("length", type=int, help="Number of bytes to read")

    # Service fuzzing
    sub.add_parser("fuzz", help="Discover supported service IDs through fuzzing")

    args = parser.parse_args()

    # Initialize CAN bus
    try:
        bus = can.interface.Bus(args.interface, interface="socketcan")
    except Exception as e:
        print(f"[!] Failed to open CAN interface: {e}", file=sys.stderr)
        print(f"[!] For vcan: sudo modprobe vcan && sudo ip link add dev vcan0 type vcan && sudo ip link set up vcan0")
        sys.exit(1)

    try:
        match args.cmd:
            case "session":
                print("[*] Testing session switching")
                for session_name, session_id in [
                    ("Default", SESSION_DEFAULT),
                    ("Extended", SESSION_EXTENDED),
                    ("Programming", SESSION_PROGRAMMING),
                ]:
                    ok = change_session(bus, args.tx_id, args.rx_id, session_id)
                    print(f"  Session {session_name} (0x{session_id:02X}): {'OK' if ok else 'FAIL'}")
                    time.sleep(0.1)

            case "security":
                # Extended session required before security access
                print("[*] Switching to Extended session...")
                if not change_session(bus, args.tx_id, args.rx_id, SESSION_EXTENDED):
                    print("[!] Failed to enter Extended session")
                    sys.exit(1)
                security_access(bus, args.tx_id, args.rx_id, args.level)

            case "enum-did":
                print("[*] Switching to Extended session...")
                change_session(bus, args.tx_id, args.rx_id, SESSION_EXTENDED)
                found = enumerate_dids(
                    bus, args.tx_id, args.rx_id, args.start, args.end
                )
                print(f"\n[+] DIDs found: {len(found)}")

            case "read-did":
                change_session(bus, args.tx_id, args.rx_id, SESSION_EXTENDED)
                data = read_data_by_id(bus, args.tx_id, args.rx_id, args.did)
                if data:
                    printable = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
                    print(f"[+] DID 0x{args.did:04X}: {data.hex()} | {printable}")
                else:
                    print(f"[-] DID 0x{args.did:04X}: No response or not supported")

            case "read-mem":
                change_session(bus, args.tx_id, args.rx_id, SESSION_EXTENDED)
                data = read_memory_by_address(
                    bus, args.tx_id, args.rx_id, args.address, args.length
                )
                if data:
                    print(f"[+] Address 0x{args.address:08X}: {data.hex()}")
                else:
                    print(f"[-] Read failed (Security Access may be required)")

            case "fuzz":
                supported = fuzz_services(bus, args.tx_id, args.rx_id)
                print(f"\n[+] Supported services: {len(supported)}")
                for sid in supported:
                    print(f"  SID 0x{sid:02X}")
    finally:
        bus.shutdown()


if __name__ == "__main__":
    main()
```

---

## Firmware Reversing

### Why Reversing Is Necessary

To find vulnerabilities in ECU firmware, code must be analyzed at the binary level because the source code is not publicly available.

Key goals:
- **Key algorithm recovery**: reverse-engineer the seed-to-key transformation in Security Access
- **Vulnerability search**: buffer overflows, format strings, integer overflows
- **Undocumented feature discovery**: manufacturer-specific diagnostic commands, backdoors
- **Calibration structure mapping**: location of fuel maps, ignition timing tables

### Analyzing ECU Firmware with Ghidra

```bash
# Ghidra (https://ghidra-sre.org)
# Free, developed by NSA, supports TriCore/RH850/ARM

# Step 1: Create a new project and import the firmware binary
# File > Import File > firmware.bin
# Format: Raw Binary
# Language: match to target MCU
#   - Infineon TriCore: Processors > Tricore:LE:32:TC29x
#   - Renesas RH850: Processors > RH850
#   - NXP S32K (ARM): Processors > ARM:LE:32:v7

# Step 2: Set up memory map (critical!)
# Window > Memory Map
# Set flash base address (refer to MCU datasheet)
# Example: TriCore TC299 — Flash: 0x80000000, RAM: 0xD0000000

# Step 3: Analyze the interrupt vector table
# ECU firmware entry point: interrupt vector table
# Cross-reference to each interrupt handler function

# Step 4: Find the UDS service dispatcher
# CAN receive interrupt handler → ISO 15765-2 parser → UDS dispatcher
# Search for service ID constants (0x27, etc.)

# Reverse-engineer the key algorithm
grep -r "SecurityAccess\|0x27\|SID_27" ghidra_export/ 2>/dev/null

# Step 5: Automate with Ghidra scripts
# Window > Script Manager > write new script
```

```python
# Ghidra Python script example: auto-detect UDS service handlers
# (Run from Ghidra Script Manager)

# Find functions referencing service ID constants
TARGET_SIDS = [0x27, 0x23, 0x34, 0x36]  # Security-related service IDs

for sid in TARGET_SIDS:
    refs = getReferencesTo(toAddr(sid))
    if refs:
        print(f"SID 0x{sid:02X} referenced at:")
        for ref in refs:
            print(f"  {ref.getFromAddress()}: {ref.getReferenceType()}")
```

### Analyzing RH850 with IDA Pro

```bash
# IDA Pro 7.x or later (commercial tool)
# After installing Renesas RH850 processor module

# Analysis focal points
# 1. Interrupt vector table
#    — First 256 bytes: handler addresses for each interrupt
#    — Look for CAN0_RxHandler, etc.

# 2. CAN receive handler
#    — CAN frame parsing code
#    — Arbitration ID comparisons (0x7E0, 0x7DF, etc.)

# 3. UDS service dispatcher
#    — switch-case or if-else structure based on service ID
#    — Jump table to each service handler function

# 4. SecurityAccess handler (0x27)
#    — SeedGenerate() function: seed generation
#    — KeyCalculate() function: key calculation (target for reverse engineering!)
#    — KeyVerify() function: key comparison

# Example decompiled output (HexRays plugin)
# int SecurityAccessHandler(uint8_t *request, uint32_t len) {
#     if (request[1] == 0x01) {  // Seed request
#         seed = GenerateSeed();
#         gCurrentSeed = seed;
#         SendPositiveResponse(0x27, 0x01, &seed, 4);
#     } else if (request[1] == 0x02) {  // Key submission
#         key_received = *(uint32_t*)(&request[2]);
#         key_expected = CalculateKey(gCurrentSeed);  // <- reverse-engineer this function!
#         if (key_received == key_expected) {
#             gSecurityLevel = 1;
#             SendPositiveResponse(0x27, 0x02, NULL, 0);
#         }
#     }
# }
```

---

## Vulnerability Analysis Methodology

### Full Analysis Workflow

```
1. Firmware extraction
   └─ Choose the feasible method: JTAG, SPI, or UDS

2. Static analysis (without executing)
   ├─ binwalk: scan for headers, filesystems, known patterns
   ├─ strings: extract strings (URLs, passwords, error messages)
   └─ Ghidra/IDA: disassemble → decompile → analyze code

3. Dynamic analysis (while executing)
   ├─ JTAG debugger: breakpoints, memory read/write
   ├─ QEMU: emulate some ECU architectures
   └─ Frida: function hooking (Cortex-M, etc.)

4. Fuzzing
   ├─ Send abnormal inputs to UDS services
   ├─ CAN message fuzzing (python-can + custom fuzzer)
   └─ Detect crashes/anomalies from response patterns

5. Vulnerability validation
   └─ Develop PoC and validate on a real ECU
```

### Fuzzing Example

```python
#!/usr/bin/env python3
"""Basic ECU UDS service fuzzer.

Sends abnormal inputs to trigger unexpected ECU behavior
or analyze error response patterns.
"""

import can
import time
import random
import sys
from dataclasses import dataclass, field


@dataclass
class FuzzResult:
    """Record of a single fuzzing attempt."""
    sid: int
    payload: bytes
    response: bytes | None
    nrc: int = 0
    timeout: bool = False


def fuzz_uds_service(
    bus: can.Bus,
    tx_id: int,
    rx_id: int,
    sid: int,
    iterations: int = 100,
) -> list[FuzzResult]:
    """Randomly fuzz a single UDS service.

    Generates payloads of random length and content, sends them,
    and records the ECU's responses.
    """
    results: list[FuzzResult] = []

    for i in range(iterations):
        # Generate a random payload (1–6 bytes)
        payload_len = random.randint(1, 6)
        payload = bytes([sid]) + bytes([random.randint(0, 255) for _ in range(payload_len)])

        # Send the frame
        frame_data = bytes([len(payload)]) + payload + bytes(7 - len(payload))
        frame = can.Message(arbitration_id=tx_id, data=frame_data, is_extended_id=False)
        bus.send(frame)

        # Receive response
        deadline = time.time() + 0.5
        response = None
        while time.time() < deadline:
            msg = bus.recv(timeout=0.1)
            if msg and msg.arbitration_id == rx_id:
                response = bytes(msg.data)
                break

        result = FuzzResult(
            sid=sid,
            payload=payload,
            response=response,
            timeout=(response is None),
        )

        if response and len(response) > 3 and response[1] == 0x7F:
            result.nrc = response[3]

        results.append(result)

        # Print progress
        if response is None:
            print(f"  [{i:3d}] {payload.hex()} -> TIMEOUT")
        elif len(response) > 1 and response[1] != 0x7F:
            print(f"  [{i:3d}] {payload.hex()} -> POSITIVE: {response.hex()}")

        time.sleep(0.02)  # Prevent ECU overload

    return results
```

---

## Real-World Vulnerability Cases

### Case 1: Weak ECU Update Mechanism

**Background**: Some early-generation OTA (over-the-air update) vehicles had no signature verification on firmware images.

**Attack scenario**:
```
1. Attacker intercepts or modifies a legitimate firmware image from the OTA channel
2. Creates a firmware image containing malicious code
3. RequestDownload (0x34) → TransferData (0x36) → RequestTransferExit (0x37)
4. ECU accepts the firmware without signature verification and writes it to flash
5. Malicious code executes after reboot
```

**Root cause**: No cryptographic signature (ECDSA, RSA, etc.) verification logic on firmware images.

**Mitigations**: AUTOSAR SecOC, signature verification in bootloader, Secure Boot implementation.

### Case 2: Diagnostic Service Abuse

**Background**: In a specific vehicle model, the BCM (Body Control Module) allowed changing critical settings via WriteDataByIdentifier (0x2E) without Security Access.

**Attack scenario**:
```bash
# Requires physical access to OBD-II port (or a pre-installed CAN interface)

# 1. Switch to Extended session
python3 ecu_analysis.py can0 session

# 2. Enumerate BCM DIDs (determine which DIDs are writable)
python3 ecu_analysis.py can0 enum-did --start 0x4000 --end 0x40FF

# 3. Write to door-lock control DID (example)
# [0x2E] [DID_HIGH] [DID_LOW] [data]
# Send directly via python-can
```

**Root cause**: Write service (0x2E) allowed without Security Access.

**Mitigations**: Write services must only be permitted after Security Access; adopt Diagnostic Authentication (added in UDS 2020).

### Case 3: Weak Seed-Key Algorithm

**Background**: A specific manufacturer's ECU implemented the Security Access key algorithm using simple XOR.

```python
# Vulnerable algorithm (recovered through reverse engineering):
# key = seed XOR 0xCAFEBABE

seed_bytes = bytes.fromhex("A1B2C3D4")
seed_int = int.from_bytes(seed_bytes, "big")
key_int = seed_int ^ 0xCAFEBABE
key_bytes = key_int.to_bytes(4, "big")

print(f"Seed: {seed_bytes.hex()}")
print(f"Key:  {key_bytes.hex()}")
# Now possible to access Programming Session and modify firmware
```

**Root cause**: Algorithm is too simple and can be easily reimplemented after firmware reversing.

**Mitigations**: AES-based CMAC, AUTOSAR SecOC, perform key operations inside an HSM (Hardware Security Module).
