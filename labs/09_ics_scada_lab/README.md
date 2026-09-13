# 🧪 Lab 09: ICS/SCADA & OT Security Lab (산업제어시스템/SCADA 실습 랩)

산업용 제어 시스템(ICS)과 운영 기술(OT) 환경을 모의하는 가상 PLC 및 HMI 감시 제어 대시보드 실습 환경입니다.  
Purdue 모델 Level 1~2 영역의 Modbus/TCP(포트 5020) 제어 프로토콜을 분석하고, 비인가 코일 조작, 텔레메트리 센서 기만(False Data Injection), 안전 계장 시스템(SIS) 비상 트립 유발까지 4단계 실전 사이버 물리 공격을 실습합니다.

---

## 📋 실습 랩 개요

| 항목 | 내용 |
|------|------|
| **난이도** | ★★★ (중급) |
| **HMI 웹 포트** | `http://localhost:8089` |
| **Modbus/TCP 포트** | `localhost:5020` |
| **관련 이론 섹션** | `37_ICS_SCADA`, `63_OT_ICS_Advanced` |
| **소요 시간** | 약 30분 ~ 1시간 |
| **실행 방식** | `python3 vhack.py lab start 09` |

---

## 🚀 빠른 시작

```bash
# 1. 랩 실행
python3 vhack.py lab start 09

# 2. 브라우저 접속 (HMI 실시간 감시 대시보드)
# http://localhost:8089

# 3. 실습 공격 도구 실행
cd labs/09_ics_scada_lab/app
python3 exploit_modbus.py --status

# 4. 실습 종료
python3 vhack.py lab stop 09
```

---

## 🏭 공정 아키텍처 및 Modbus 메모리 맵

석유화학 플랜트의 **수소첨가분해 반응로(Hydrocracker Train #2)** 공정을 시뮬레이션합니다.

### 1. 코일(Coil) 메모리 (1-bit Output)
| 주소 (Address) | 명칭 | 기본 상태 | 기능 설명 |
|:---:|:---:|:---:|:---|
| `0` | **ESD** | `0 (READY)` | 비상 공정 정지 (Emergency Shutdown) |
| `1` | **Cooling Pump** | `1 (RUNNING)` | 반응로 순환 냉각수 펌프 (0으로 조작 시 급격한 과열 발생) |
| `2` | **Safety Interlock** | `1 (ARMED)` | 하드웨어 안전 인터록 플랩 |
| `3` | **Emergency Vent** | `0 (CLOSED)` | 긴급 압력 방출 플레어 밸브 |

### 2. 홀딩 레지스터(Holding Register) (16-bit Word)
| 주소 (Address) | 명칭 | 정상 범위 | 단위 | 설명 |
|:---:|:---:|:---:|:---:|:---|
| `0` | **Core Temperature** | 50 ~ 120 | °C | 반응로 내부 온도 (150°C 초과 시 비상 차단) |
| `1` | **Vessel Pressure** | 200 ~ 450 | PSI | 배관 및 용기 압력 (600 PSI 초과 시 폭발 위험) |
| `2` | **Coolant Flow** | 100 ~ 130 | L/min | 냉각수 유량 |
| `3` | **Temp Setpoint** | 70 ~ 90 | °C | 반응 공정 목표 운전 온도 |
| `100` | **Secret Diagnostic** | - | - | 숨겨진 공정 진단 플래그 레지스터 |

---

## 🎯 실습 시나리오 & 플래그 공략 (Walkthrough)

### 챌린지 1: Modbus 정찰 및 비밀 레지스터 조회 (Reconnaissance)
- **공격 목표**: Modbus/TCP 포트가 노출된 제어기에서 Function Code 03(Read Holding Registers)을 전송하여 비인가 레지스터 `100번`의 값을 읽어내기
- **공격 명령**:
  ```bash
  python3 exploit_modbus.py --recon
  ```
- **해설**: Modbus는 기본적으로 암호화나 세션 인증이 없어 누구나 제어기 내부 메모리를 질의할 수 있습니다.
- **플래그**: `FLAG{MODBUS_RECON_REG100_LEAK}`

---

### 챌린지 2: 불법 코일 쓰기를 통한 냉각 펌프 차단 (Unauthorized Coil Write)
- **공격 목표**: Function Code 05(Write Single Coil)를 전송하여 가동 중인 반응로 냉각수 펌프(`Coil 1`)를 강제 `0(OFF)`으로 조작
- **공격 명령**:
  ```bash
  python3 exploit_modbus.py --kill-pump
  ```
- **해설**: 냉각 펌프가 정지되면 유량이 0이 되며 코어 온도가 매초 6.5°C씩 급상승합니다. HMI 대시보드에서 펌프가 빨간색(STOPPED)으로 바뀌고 온도가 치솟는 것을 확인합니다.
- **플래그**: `FLAG{MODBUS_COIL_PUMP_TRIP_SUCCESS}`

---

### 챌린지 3: 거짓 데이터 주입 및 센서 텔레메트리 기만 (False Data Injection)
- **공격 목표**: 펌프 중단으로 실제 압력이 위험 수위(480 PSI 초과)로 상승할 때, 제어기 레지스터 1(Pressure)을 300 PSI로 지속 덮어써 HMI 상에서 과압 상승을 은폐
- **공격 명령**:
  ```bash
  python3 exploit_modbus.py --spoof-pressure 300
  ```
- **해설**: 센서와 HMI 사이의 텔레메트리를 스푸핑하면 운영자는 계기판이 정상을 가리키고 있다고 믿어 수동 긴급 조치를 취하지 못하게 됩니다 (Stuxnet 유사 기법).
- **플래그**: `FLAG{FDI_PRESSURE_SPOOF_INJECTED}`

---

### 챌린지 4: 안전 계장 시스템(SIS) 긴급 안전 트립 유발 (Emergency Safety Trip)
- **공격 목표**: 목표 운전 온도(Reg 3)를 250°C로 극대화하고 냉각을 차단하여 코어 온도가 150°C를 돌파하도록 유도, 안전 계장(SIS)의 비상 하드웨어 트립 발동시키기
- **공격 명령**:
  ```bash
  python3 exploit_modbus.py --trigger-trip
  ```
- **해설**: 공정 변수가 물리적 한계선에 도달하면 안전 시스템이 개입하여 긴급 벤트 밸브(`Coil 3`)를 열고 공정을 비상 정지시킵니다.
- **플래그**: `FLAG{ICS_CRITICAL_OVERHEAT_TRIPPED}`

---

## 🛡️ 방어 및 완화 대책 (Defensive Strategies)

1. **산업 전용 심층 패킷 검사(DPI) 방화벽**:
   - Level 1-2 경계에서 Modbus 프로토콜을 페이로드 수준까지 검사하여 FC01/FC03(읽기)만 허용하고 외부 워크스테이션에서의 FC05/FC06(쓰기) 명령을 원천 차단
2. **물리적 모드 키스위치(Keyswitch) 관리**:
   - PLC 전면부의 스위치를 `RUN` 모드로 고정하고 열쇠를 회수하여 네트워크를 통한 원격 로직/코일 강제 조작 방지
3. **독립된 안전 계장 시스템(SIS) 격리**:
   - 기본 공정 제어망(BPCS)과 SIS 제어기 간 물리적 망분리 및 Data Diode 적용
