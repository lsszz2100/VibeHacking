# 34 — Hardware Hacking

## 섹션 개요

임베디드 장치·IoT 기기·산업 제어 시스템의 하드웨어 레이어를 직접 공략하는 기술을 다룬다.
소프트웨어 취약점만으로 접근 불가능한 대상에 대해 물리적 인터페이스(UART, JTAG, SPI, I2C)를 통해
펌웨어를 추출하고, 사이드채널 신호를 분석하며, 결함 주입으로 보안 부팅을 우회하는 전 과정을 실습 중심으로 구성한다.

---

## 디렉터리 트리

```
34_Hardware_Hacking/
├── README.md                              ← 섹션 개요 (이 파일)
├── 01_hardware_recon_and_interfaces.md    ← UART/SPI/I2C/JTAG 인터페이스 식별 및 펌웨어 덤프
├── 02_firmware_analysis.md               ← binwalk 심화, Ghidra/r2 스크립팅, 크리덴셜 탐지
├── 03_side_channel_and_fault_injection.md ← SPA/DPA 전력 분석, 전압 글리칭, 타이밍 공격
└── 04_embedded_exploitation.md           ← RTOS CVE, 임베디드 리눅스 권한상승, Flipper Zero
```

---

## 실습 환경

### Raspberry Pi 4 (공격자 워크스테이션 겸 타깃 시뮬레이터)

| 역할 | 설정 |
|------|------|
| UART 연결 | GPIO 14(TX) / 15(RX) — `/dev/ttyS0` |
| SPI 버스 | GPIO 10(MOSI) / 9(MISO) / 11(SCLK) / 8(CS0) |
| I2C 버스 | GPIO 2(SDA) / 3(SCL) — `i2c-1` |
| JTAG | OpenOCD + Raspberry Pi GPIO bitbang |
| 전원 제어 | GPIO 기반 릴레이 모듈 (글리칭용) |

```bash
# Raspberry Pi 준비
sudo apt update && sudo apt install -y \
  minicom picocom screen \
  openocd flashrom binwalk \
  python3-serial python3-numpy \
  i2c-tools spi-tools

# UART 활성화
sudo raspi-config nonint do_serial 1   # 로그인 셸 비활성화
sudo raspi-config nonint do_serial_hw 0 # 하드웨어 UART 활성화
```

### Bus Pirate v4

```bash
# USB 연결 후 장치 확인
ls /dev/ttyUSB*

# UART 모드 진입 (115200 bps)
screen /dev/ttyUSB0 115200
# Bus Pirate 프롬프트에서: m -> 3 (UART) -> 설정

# SPI 모드 플래시 덤프 예시
# m -> 5 (SPI) -> 속도 설정 후 read 명령
```

### Flipper Zero

```
펌웨어: https://github.com/flipperdevices/flipperzero-firmware
qFlipper (데스크톱 관리 도구): https://flipperzero.one/update

주요 기능 모듈:
├── Sub-GHz     : 300~928 MHz RF 송수신, 리모컨 리플레이
├── NFC         : 13.56 MHz, MIFARE Classic/Ultralight 읽기·쓰기·에뮬레이션
├── 125kHz RFID : HID Prox, EM4100 카드 복제
├── Infrared    : IR 신호 기록·재전송
├── BadUSB      : USB HID 디바이스 에뮬레이션 (Rubber Ducky 페이로드)
├── UART 터미널 : GPIO를 통한 시리얼 콘솔 접근
└── iButton     : Dallas/Maxim 1-Wire 키 복제
```

### Logic Analyzer (Saleae Logic / sigrok)

```bash
# sigrok-cli 설치
sudo apt install -y sigrok sigrok-cli pulseview

# 8채널 동시 캡처 (24MHz, 100만 샘플)
sigrok-cli -d fx2lafw --config samplerate=24m \
  --samples 1000000 -o capture.sr

# UART 디코딩
sigrok-cli -i capture.sr \
  -P uart:baudrate=115200:rx=D0:tx=D1 \
  --protocol-decoder-samplenum

# SPI 디코딩
sigrok-cli -i capture.sr \
  -P spi:clk=D0:mosi=D1:miso=D2:cs=D3
```

### ChipWhisperer Lite (사이드채널 / 글리칭)

```python
import chipwhisperer as cw

# 장치 연결
scope = cw.scope()
scope.default_setup()

target = cw.target(scope, cw.targets.SimpleSerial)
target.baud = 38400

# 전력 파형 캡처 기본 설정
scope.adc.samples     = 5000
scope.adc.offset      = 0
scope.adc.basic_mode  = "rising_edge"
scope.clock.clkgen_freq = 7370000
scope.clock.adc_src   = "clkgen_x4"
```

---

## 관련 CVE 매핑

| CVE | 장치 유형 | 취약점 분류 | 파일 |
|-----|-----------|-------------|------|
| CVE-2019-16920 | D-Link 라우터 | 인증 없는 RCE (UART 접근 후 확인) | 01, 04 |
| CVE-2021-35395 | Realtek SDK | 스택 오버플로 (펌웨어 분석 발견) | 02, 04 |
| CVE-2020-9054 | Zyxel NAS | 하드코딩 크리덴셜 (`zyfwp`/`PrOw!aN_fXp`) | 02 |
| CVE-2022-27255 | Realtek eCos SDK | 스택 오버플로 (UDP) | 02, 04 |
| CVE-2021-38297 | FreeRTOS | 힙 오버플로 (TCP/IP 스택) | 04 |
| CVE-2021-31571 | Zephyr RTOS | HTTP 파서 스택 오버플로 | 04 |
| CVE-2023-27217 | Belkin WeMo | 커맨드 인젝션 (UPnP SOAP) | 04 |
| CVE-2017-9481 | Cisco SB | UART 부트로더 무인증 셸 | 01 |
| CVE-2020-3580 | Cisco ASA | 부트로더 비밀번호 우회 (ROMMON 글리칭) | 03 |
| CVE-2021-44228 (Log4Shell) | 다수 임베디드 | 펌웨어 내 Log4j 탑재 확인 | 02 |
| CVE-2024-3400 | Palo Alto PAN-OS | 커맨드 인젝션 (하드웨어 어플라이언스) | 04 |
| CVE-2019-11477 | Linux 커널 (SACK) | TCP SACK 패닉 (임베디드 리눅스) | 04 |

---

## 학습 로드맵

```
1단계: 인터페이스 식별 (01)
   ↓
2단계: 펌웨어 획득 · 분석 (01 → 02)
   ↓
3단계: 취약점 탐색 (02 → 04)
   ↓
4단계: 사이드채널 / 글리칭으로 보호 우회 (03)
   ↓
5단계: 임베디드 익스플로잇 (04)
```

---

## 필수 도구 목록

```bash
# 패키지 관리자
sudo apt install -y binwalk flashrom openocd minicom picocom \
  i2c-tools python3-serial python3-numpy radare2

# Python 라이브러리
pip3 install pyserial numpy scipy matplotlib \
  capstone unicorn keystone-engine

# Ghidra (별도 다운로드)
# https://ghidra-sre.org — JDK 17+ 필요

# binwalk 최신 버전
pip3 install binwalk

# Firmware Analysis Toolkit
git clone https://github.com/attify/firmware-analysis-toolkit
```

---

## 법적 고지

물리적 장치 접근, 펌웨어 추출, RF 신호 재전송은 **자신이 소유하거나 명시적 서면 허가를 받은 장치**에 한해 수행해야 한다.
무선 신호 재전송은 국가별 전파법 규정을 준수해야 하며, 인가받지 않은 장치에 대한 실습은 컴퓨터보안 침해 및 전파법 위반으로 처벌받을 수 있다.
