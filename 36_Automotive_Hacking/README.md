# 36 Automotive Hacking

## 섹션 개요

자동차 해킹은 현대 차량에 내장된 수십~수백 개의 ECU(Electronic Control Unit)와 이들을 연결하는 다양한 네트워크 버스, 무선 통신 인터페이스를 대상으로 하는 공격 및 분석 기법을 다룬다. 2015년 Jeep Cherokee 원격 제어 시연 이후 자동차 사이버보안은 ISO/SAE 21434, UN ECE R155/R156 등 국제 규제로 이어졌으며, 현재는 자율주행·커넥티드카 확산으로 공격 표면이 급격히 확대되고 있다.

이 섹션에서는 차량 내부 네트워크 프로토콜부터 ECU 펌웨어 익스플로잇, 무선 채널 공격, 텔레매틱스 원격 접근까지 전체 공격 체인을 실습 중심으로 다룬다.

---

## 자동차 네트워크 아키텍처

### CAN (Controller Area Network)

ISO 11898 표준. 1986년 Bosch 개발, 현재 대부분 차량의 기본 버스. 2-wire 차동 신호(CAN_H/CAN_L), 최대 1 Mbit/s. 마스터 없는 멀티-마스터 구조, 메시지 ID 기반 중재(arbitration). 엔진·변속기·ABS 등 파워트레인 도메인에서 주로 사용.

- **CAN FD (Flexible Data-Rate)**: ISO 11898-1:2015. 데이터 페이즈 최대 8 Mbit/s, 페이로드 64바이트까지 확장. AUTOSAR Adaptive 플랫폼과 함께 확산.
- **보안 취약점**: 인증 없음, 암호화 없음, 브로드캐스트 특성으로 버스 접근 시 모든 메시지 수신 가능.

### LIN (Local Interconnect Network)

ISO 17987. 단선 UART 기반, 최대 20 kbit/s. 마스터-슬레이브 구조. 창문·시트·거울 등 저속 액추에이터에 사용. CAN 대비 저비용. 슬레이브 노드는 마스터 요청에만 응답하므로 공격 시 마스터 권한 탈취가 핵심.

### FlexRay

ISO 17458. 최대 10 Mbit/s, 이중 채널(A/B), 결정론적 타이밍(TDMA). BMW, Mercedes의 섀시 제어(스티어링, 서스펜션)에 사용. 시간 슬롯 기반 통신으로 CAN보다 복잡한 공격 구조 필요.

### Automotive Ethernet

IEEE 802.3bw (100BASE-T1), 802.3bp (1000BASE-T1). BroadR-Reach PHY, UTP 1쌍 케이블. ADAS·인포테인먼트·카메라 대용량 데이터 전송. SOME/IP, DDS 등 서비스 지향 미들웨어. 기존 IT 네트워크 공격 기법 직접 적용 가능.

### 도메인 구조와 게이트웨이

```
[OBD-II Port] ──── CAN Bus (Powertrain)
                        │
                   [Gateway ECU]
                   /     |      \
         CAN Bus  /   FlexRay   \ Automotive Ethernet
       (Body/HVAC)  (Chassis)    (ADAS/Infotainment)
                                      │
                               [TCU/Telematics]
                                      │
                              [Cellular / V2X / WiFi / BT]
```

게이트웨이 ECU는 도메인 간 메시지 라우팅을 담당하며, 방화벽 역할도 수행한다. 그러나 대부분의 구형 게이트웨이는 필터링이 취약하거나 없어 인포테인먼트에서 파워트레인 도메인으로의 메시지 주입이 가능하다.

---

## 실습 환경

### CANalyzer / CANoe (Vector)

상용 CAN 분석 도구. LIN·FlexRay·Ethernet 지원. 실차 개발 환경에서 표준. 학습용 라이선스(CANalyzer Student Edition) 제공.

### python-can

```bash
pip install python-can
```

지원 인터페이스: SocketCAN(Linux), PCAN-USB, IXXAT, Vector, Kvaser, USB2CAN 등.

### 가상 CAN (SocketCAN vcan) 설정

```bash
# 커널 모듈 로드
sudo modprobe vcan

# 가상 인터페이스 생성
sudo ip link add dev vcan0 type vcan
sudo ip link set up vcan0

# 실제 USB-CAN 어댑터 (PCAN-USB 예시)
sudo modprobe peak_usb
sudo ip link set can0 type can bitrate 500000
sudo ip link set up can0

# can-utils 설치
sudo apt install can-utils

# 패킷 캡처
candump vcan0

# 패킷 송신 (ID 0x7DF, 데이터 8바이트)
cansend vcan0 7DF#0201050000000000

# 재생 (log file)
canplayer -I candump.log vcan0=vcan0
```

### cantools — DBC 파일 파싱

```bash
pip install cantools
```

DBC(Database CAN) 파일은 메시지 ID와 신호 정의를 담은 텍스트 포맷. OEM·공급사 내부 파일이나 GitHub 오픈 DBC 프로젝트(comma.ai opendbc 등)에서 확보 가능.

### 하드웨어 권장 목록

| 장치 | 용도 | 가격대 |
|------|------|--------|
| PCAN-USB (Peak) | CAN 분석·주입 | ~$300 |
| CANtact / candleLight | SocketCAN USB | ~$50 |
| ELM327 OBD-II | OBD-II 스캔 | ~$10 |
| HackRF One | Sub-GHz / V2X RF | ~$300 |
| Proxmark3 | RFID/NFC (키리스) | ~$350 |
| JTAG 디버거 (J-Link) | ECU 펌웨어 추출 | ~$400 |

---

## 관련 CVE 및 실제 공격 사례

### CVE-2015-5611 — Jeep Cherokee 원격 익스플로잇

연구자: Charlie Miller, Chris Valasek (2015 DEF CON / Black Hat)

Uconnect 인포테인먼트 시스템(Sprint 셀룰러 네트워크 연결)의 D-Bus 서비스와 QNX RTOS 취약점을 연계. 포트 6667(mitmproxy 프로세스)를 통한 원격 코드 실행. 이후 CAN 버스 주입으로 핸들·브레이크·변속기 제어. FCA 140만 대 리콜.

- 공격 체인: 인터넷 → 셀룰러 → Uconnect D-Bus RCE → iptables 수정 → V850 칩(CAN 게이트웨이) 재프로그래밍 → CAN 주입

### CVE-2016-9337 / 관련 — Tesla Model S 원격 익스플로잇

연구자: Keen Security Lab (2016, 2017)

WiFi/웹브라우저 취약점 체인으로 게이트웨이 ECU 접근, CAN 버스 제어권 획득. 주행 중 핸드브레이크 작동 실증. Tesla OTA 패치 대응.

### CVE-2022-28078 — Honda Civic BLE 취약점

Rolling PWN 공격: 혼다 롤링 코드 키리스 시스템의 코드 윈도우 재사용 취약점. 캡처된 과거 코드로 현재 잠금 해제 가능. 2012~2022년 혼다 다수 차종 영향.

### CVE-2019-9493 — Mazda CMU 인포테인먼트

USB 자동마운트 및 스크립트 실행 취약점. 악성 USB 꽂으면 루트 셸 획득.

### 기타 주요 연구

- **OBD-II 악성 도나글**: Progressive Snapshot 등 보험사 OBD 동글의 CAN 버스 연결을 악용한 무선 공격(Corey Thuen, 2015)
- **BMW ConnectedDrive**: 인증 없는 HTTP 통신으로 차문 원격 개방(ADAC, 2015, 2.2M 대)
- **Volkswagen Immobilizer**: Megamos Crypto 알고리즘 역분석으로 점화 우회(Bono et al., 2016, USENIX)
- **자율주행 LiDAR/카메라 스푸핑**: 물리 계층 센서 기만으로 자율주행 판단 오류 유발(여러 학술 논문)

---

## 파일 목록

| 파일 | 내용 |
|------|------|
| `01_can_bus_analysis.md` | CAN 프로토콜 심화, SocketCAN, OBD-II/UDS, Python CAN 분석 도구 |
| `02_ecu_exploitation.md` | ECU 펌웨어 추출, UDS 인증 우회, 리프로그래밍 공격 |
| `03_wireless_attacks.md` | 키리스 릴레이/RollJam, V2X 취약점, 인포테인먼트 무선 공격 |
| `04_telematics_and_remote_attack.md` | TCU 원격 공격, Jeep Cherokee 분석, OTA 취약점, 포트 스캐너 |

---

## 법적 고지

이 자료의 기법은 **허가된 차량 또는 테스트 벤치 환경에서만** 적용해야 한다. 실차에 대한 무단 CAN 주입·원격 접근은 형사 처벌 대상이다. 연구 목적 시 차량 소유자 동의, 격리 환경(배터리 연결, 주행 불가 상태), 데이터 복구 계획을 갖춰야 한다.
