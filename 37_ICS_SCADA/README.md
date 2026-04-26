# 37 — ICS/SCADA 보안

## 섹션 개요

산업 제어 시스템(ICS)과 SCADA(Supervisory Control and Data Acquisition)는 발전소, 정유 시설, 수처리 플랜트, 철도, 제조 라인 등 핵심 인프라를 제어하는 OT(Operational Technology) 환경의 핵심 요소다. 이 섹션은 ICS/SCADA 환경에 대한 공격 기법과 방어 전략을 실전 중심으로 다룬다.

전통적인 IT 보안과 달리 OT 보안은 **가용성(Availability) > 무결성(Integrity) > 기밀성(Confidentiality)** 순서의 우선순위를 가진다. 시스템이 멈추는 것이 데이터 유출보다 훨씬 위험한 결과를 초래하기 때문이다. Stuxnet, TRITON, Industroyer 같은 실제 사이버 무기들은 이 환경을 정밀하게 타격하도록 설계되었다.

---

## ICS/OT 환경 구성 요소

### PLC (Programmable Logic Controller)
- 물리적 장비(모터, 밸브, 센서 등)를 직접 제어하는 현장 장치
- 래더 다이어그램(Ladder Diagram), 구조적 텍스트(ST), 기능 블록 다이어그램(FBD) 등으로 프로그래밍
- 주요 제조사: Siemens(S7-300/400/1200/1500), Allen-Bradley(ControlLogix, MicroLogix), Schneider Electric(Modicon), Rockwell, Mitsubishi
- 통신 프로토콜: Modbus RTU/TCP, EtherNet/IP, PROFINET, DeviceNet, S7comm

### RTU (Remote Terminal Unit)
- 원격 현장에 설치되어 센서/액추에이터를 제어하고 SCADA 마스터와 통신
- PLC보다 단순하며 직렬 통신(RS-232/485) 및 무선(GPRS, 위성) 지원
- DNP3, IEC 60870-5-101/104 프로토콜 주로 사용
- 취약점: 인증 없는 DNP3, 암호화 없는 직렬 통신, 물리적 접근 용이성

### HMI (Human-Machine Interface)
- 운전원이 시스템 상태를 모니터링하고 제어 명령을 입력하는 인터페이스
- Windows 기반 소프트웨어 (Wonderware, iFIX, Ignition, WinCC)
- 취약점: 구버전 Windows OS, 패치되지 않은 소프트웨어, USB 포트 노출
- 공격 시나리오: HMI 장악 후 PLC 명령 전송, 화면 조작으로 운전원 기만

### DCS (Distributed Control System)
- 대규모 공정(정유, 화학, 발전)을 분산 아키텍처로 제어
- 중앙 집중식 SCADA와 달리 제어 기능을 현장에 분산
- 주요 제조사: Honeywell(Experion), Emerson(DeltaV), ABB(800xA), Yokogawa(CENTUM)
- 취약점: 독점 프로토콜 취약점, 오래된 OS (Windows XP/2003), 내부 네트워크 신뢰 관계

### SCADA 마스터 서버
- 여러 RTU/PLC로부터 데이터를 수집하고 전체 시스템을 감시
- 히스토리안 서버(OSIsoft PI, Historian)와 연동하여 공정 데이터 저장
- DNP3, IEC 61850, OPC DA/UA를 통해 현장 장치와 통신

---

## 실습 환경 구성

### GNS3 + OpenPLC 환경

```bash
# GNS3 설치 (Ubuntu 22.04)
sudo add-apt-repository ppa:gns3/ppa
sudo apt update
sudo apt install gns3-gui gns3-server

# OpenPLC Runtime 설치
git clone https://github.com/thiagoralves/OpenPLC_v3.git
cd OpenPLC_v3
./install.sh linux

# OpenPLC 웹 인터페이스 접근 (기본 포트 8080)
# http://localhost:8080 (admin/openplc)

# Modbus TCP 시뮬레이터
pip install pymodbus
python3 -c "
from pymodbus.server import StartTcpServer
from pymodbus.datastore import ModbusSlaveContext, ModbusServerContext
from pymodbus.datastore import ModbusSequentialDataBlock
store = ModbusSlaveContext(
    di=ModbusSequentialDataBlock(0, [0]*100),
    co=ModbusSequentialDataBlock(0, [0]*100),
    hr=ModbusSequentialDataBlock(0, [0]*100),
    ir=ModbusSequentialDataBlock(0, [0]*100))
context = ModbusServerContext(slaves=store, single=True)
StartTcpServer(context, address=('0.0.0.0', 502))
"
```

### ScadaBR 설치

```bash
# Java 환경 준비
sudo apt install openjdk-11-jdk

# ScadaBR 다운로드 및 실행
wget https://github.com/ScadaBR/ScadaBR/releases/download/1.1CE/ScadaBR_1.1CE.zip
unzip ScadaBR_1.1CE.zip
cd ScadaBR_1.1CE
./startup.sh

# 접근: http://localhost:8080/ScadaBR (admin/admin)
# Modbus 데이터소스 추가 → OpenPLC와 연동
```

### 가상 ICS 네트워크 토폴로지

```
[인터넷] — [방화벽] — [기업 네트워크 (레벨 4-5)]
                          |
                    [DMZ / 히스토리안]
                          |
                    [제어 네트워크 (레벨 3)]
                    [엔지니어링 워크스테이션]
                    [SCADA 서버]
                          |
                    [프로세스 네트워크 (레벨 2)]
                    [HMI, DCS 서버]
                          |
                    [현장 네트워크 (레벨 1)]
                    [PLC, RTU, 드라이브]
                          |
                    [현장 장치 (레벨 0)]
                    [센서, 액추에이터, 밸브]
```

---

## Purdue 모델 (ICS 계층 아키텍처)

Purdue 참조 모델(PERA)은 ICS 환경의 네트워크 계층화를 정의한다:

| 레벨 | 명칭 | 구성 요소 | 보안 고려사항 |
|------|------|-----------|--------------|
| 레벨 5 | 기업 네트워크 | ERP, 이메일, 인터넷 | IT 보안 표준 적용 |
| 레벨 4 | 사이트 비즈니스 계획 | 생산 스케줄링, 물류 | IT/OT 경계 방화벽 |
| 레벨 3 | 사이트 운영 관리 | SCADA 서버, 히스토리안 | DMZ, 패치 관리 |
| 레벨 2 | 영역 감독 제어 | HMI, 엔지니어링 워크스테이션 | 화이트리스트 |
| 레벨 1 | 기본 제어 | PLC, RTU, DCS 컨트롤러 | 물리적 보안, 프로토콜 필터링 |
| 레벨 0 | 현장 | 센서, 액추에이터, 모터 | 물리적 접근 통제 |

---

## 주요 ICS 사이버 공격 분석

### Stuxnet (2010)
- **대상**: 이란 나탄즈 우라늄 농축 시설의 Siemens S7-315/417 PLC
- **핵심 기법**: 4개의 Windows 제로데이 취약점 동시 활용, Step 7 프로젝트 파일 감염
- **PLC 공격**: 원심분리기 회전 속도를 정상(1,064Hz) ↔ 이상(1,410Hz/2Hz)으로 교번 변조
- **은폐**: 정상 작동처럼 HMI 화면에 가짜 데이터 표시
- **영향**: 이란 원심분리기 1,000여 대 파괴, 핵 프로그램 수년 지연

### TRITON/TRISIS (2017)
- **대상**: 중동 석유화학 플랜트의 Schneider Electric Triconex SIS(Safety Instrumented System)
- **목표**: 안전 시스템을 무력화하여 물리적 폭발/재앙 유발
- **기법**: Triconex 전용 TriStation 프로토콜 리버스 엔지니어링, SIS 컨트롤러에 맞춤형 악성코드 주입
- **결과**: 버그로 인해 SIS가 안전 상태로 종료되며 발각 — 의도한 대로 작동했다면 대규모 사상자 발생 가능
- **CVE**: CVE-2018-7515, CVE-2018-7514 (Triconex 취약점)

### Industroyer/Crashoverride (2016)
- **대상**: 우크라이나 키이우 전력망 (프리카르파티아오블레네르고 2015년 공격의 후속)
- **기법**: IEC 60870-5-101/104, IEC 61850, OPC DA 네이티브 프로토콜 구현으로 변전소 차단기 제어
- **구성**: 런처 모듈 + 4개 프로토콜 페이로드 + 와이퍼 + DoS 모듈
- **영향**: 키이우 북부 지역 1시간 정전, 시스템 복구 수일 소요

---

## 파일 목록

| 파일 | 내용 |
|------|------|
| `01_ics_protocols_and_recon.md` | ICS 프로토콜 심화(Modbus/DNP3/IEC 61850/EtherNet/IP), Shodan 정찰, 멀티프로토콜 스캐너 |
| `02_scada_exploitation.md` | HMI/Historian/PLC 취약점, TRITON·INDUSTROYER 분석, SCADA 취약점 스캐너 |
| `03_ot_network_attacks.md` | Purdue 계층별 공격, IT→OT 횡이동, 무선 OT 공격, OT 토폴로지 매퍼 |

---

## 관련 CVE 빠른 참조

| CVE | 대상 | 설명 |
|-----|------|------|
| CVE-2010-2568 | Windows Shell (.lnk) | Stuxnet 전파 벡터 |
| CVE-2010-2729 | Windows Print Spooler | Stuxnet 네트워크 전파 |
| CVE-2017-9697 | Triconex TriStation | TRITON 취약점 |
| CVE-2018-10952 | Schneider Modicon | 인증 우회 |
| CVE-2019-13945 | Siemens S7-1500 | 임의 코드 실행 |
| CVE-2020-7547 | Schneider EcoStruxure | 원격 코드 실행 |
| CVE-2022-37300 | Emerson DeltaV | 임의 명령 실행 |

---

## 법적 고지

이 자료는 공인된 침투 테스트, CTF, 연구 목적으로만 사용한다. 실제 ICS/SCADA 시스템에 대한 무단 공격은 중요 인프라 파괴 관련 법률(미국 CFAA, 한국 정보통신기반보호법 등)에 따라 중형에 처해질 수 있다.
