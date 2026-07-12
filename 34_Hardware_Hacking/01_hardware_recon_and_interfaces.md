> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 01 — Hardware Recon & Interfaces

## 0. 초보자를 위한 개념 이해

### 하드웨어 정찰 및 인터페이스란?

하드웨어 정찰(Hardware Recon)은 분석 대상 기기의 PCB(회로기판), 칩, 디버그 포트 등 물리적 구성 요소를 파악하는 과정이다. 인터페이스(Interface)는 해당 하드웨어와 통신하기 위한 프로토콜(UART, JTAG, SPI, I2C 등)을 의미한다. 이 두 가지를 이해해야 펌웨어 추출, 취약점 분석, 디버그 접근 등 하드웨어 해킹의 모든 후속 작업이 가능하다.

**왜 배우는가:**
```
[하드웨어 해킹 전체 흐름]

 물리 정찰                 인터페이스 식별
(PCB 촬영·칩 마킹)  →  (UART/JTAG/SPI/I2C 포트 위치)
        ↓                        ↓
 칩 데이터시트 조회          논리 분석기 연결
        ↓                        ↓
 핀아웃 확인              통신 시작 (쉘 접근 or 펌웨어 덤프)
        ↓                        ↓
  취약점 분석              익스플로잇 or 보안 평가 보고서
```

### 핵심 개념 정리

```
[주요 하드웨어 인터페이스 비교]

UART (범용 비동기 송수신)
  - 용도: 시리얼 콘솔, 부트 로그, 루트 쉘 접근
  - 핀: TX, RX, GND (3선)
  - 속도: 9600 ~ 115200 baud
  - 특징: 암호화 없음, 부트로더 인터럽트 가능

JTAG (Joint Test Action Group)
  - 용도: CPU 디버깅, 플래시 읽기/쓰기, 브레이크포인트
  - 핀: TDI, TDO, TCK, TMS, TRST (4~5선)
  - 특징: 깊은 수준의 접근, 메모리 직접 접근 가능

SPI (Serial Peripheral Interface)
  - 용도: 플래시 메모리 직접 읽기 (펌웨어 추출)
  - 핀: MOSI, MISO, SCK, CS (4선)
  - 특징: 빠른 속도, NOR/NAND 플래시에 주로 사용

I2C (Inter-Integrated Circuit)
  - 용도: EEPROM, 센서, 소형 설정값 저장 칩
  - 핀: SDA, SCL (2선 + GND)
  - 특징: 저속, 주소 기반 다중 장치 연결
```

### 필요한 도구 및 환경
- **논리 분석기(Logic Analyzer)**: Saleae Logic, 저가형 8채널 USB 분석기
- **USB-UART 어댑터**: CH340, CP2102, FT232 기반 (3.3V/5V 주의)
- **멀티미터**: 핀 아웃 확인, 전압 측정
- **PuTTY / minicom / screen**: UART 터미널 접속
- **flashrom**: SPI 플래시 읽기/쓰기 CLI 도구

### 기초 실습 예제
```python
import serial  # pip install pyserial

def uart_connect(port: str = '/dev/ttyUSB0', baudrate: int = 115200):
    """UART 포트에 연결해 부트 로그를 수집한다."""
    # 일반적인 보드레이트: 9600, 19200, 38400, 57600, 115200
    common_baudrates = [9600, 19200, 38400, 57600, 115200]

    for baud in common_baudrates:
        try:
            ser = serial.Serial(
                port=port,
                baudrate=baud,
                bytesize=8,       # 8비트 데이터
                parity='N',       # 패리티 없음
                stopbits=1,       # 스톱비트 1
                timeout=2         # 2초 대기
            )
            # 데이터 수신 시도
            data = ser.read(100)
            if data and any(32 <= b < 127 for b in data):
                print(f"[+] 보드레이트 {baud}에서 가독성 있는 데이터 수신!")
                print(f"    수신 데이터: {data[:50]}")
                return ser
            ser.close()
        except serial.SerialException as e:
            print(f"[-] {baud} baud 연결 실패: {e}")

    print("[-] 유효한 보드레이트를 찾지 못함")
    return None

# 사용 예시 (실제 하드웨어 연결 후)
# conn = uart_connect('/dev/ttyUSB0')
```

---

## 1. 물리적 정찰 (Physical Recon)

### 1.1 PCB 분석 절차

```bash
# 장치 분해 전 체크리스트
# 1) 케이스 나사 유형 확인 — 특수 나사(Torx, Pentalobe, Tri-wing) 식별
# 2) 접착 케이스 — 히트건 50~60°C 로 글루 연화
# 3) PCB 마킹 사진 촬영 — 뒤집기 전 양면 고해상도 촬영
```

### 1.2 칩 마킹 독해

칩 상단 인쇄 형식:

```
[제조사 로고]
[파트넘버]
[제조 날짜 코드: YYWW]
[원산지]
```

주요 칩 식별:

| 마킹 패턴 | 기능 |
|-----------|------|
| `25Q128` / `W25Q128` | SPI NOR Flash (Winbond, 128Mbit) |
| `MX25L` | SPI NOR Flash (Macronix) |
| `S25FL` | SPI NOR Flash (Spansion) |
| `MT29F` | NAND Flash (Micron) |
| `BCM63xx` | Broadcom SoC (라우터) |
| `RTL8xxx` | Realtek SoC (라우터/NAS) |
| `MT7621` | MediaTek SoC |
| `AR9xxx` / `QCA9xxx` | Qualcomm Atheros SoC |
| `STM32` | STMicroelectronics ARM Cortex-M MCU |
| `ESP32` / `ESP8266` | Espressif Wi-Fi SoC |

### 1.3 테스트 포인트 (TP) 식별

PCB에서 디버그 패드를 찾는 방법:

```
1. 실크스크린 라벨: TP1~TPx, RX, TX, GND, VCC, TDI, TDO, TCK, TMS, TRST
2. 직렬로 늘어선 4~6개 패드 → JTAG 헤더 가능성 높음
3. 3개 패드 (TX, RX, GND) → UART 가능성 높음
4. 저항으로 연결된 패드 → 시리즈 저항 보호된 JTAG/UART
5. 다차원 저항값 측정:
   - GND 대비 0Ω  → 그라운드
   - 3.3V / 1.8V  → 전원
   - 풀업 저항 후 VCC 값 → TX (UART 아이들 HIGH)
```

멀티미터 활용:

```bash
# 도통 테스트로 GND 패드 식별
# GND → 큰 구리 영역(히트싱크, 실드 캔)과 도통 확인

# UART TX 식별: 오실로스코프로 부팅 시 신호 패턴 관찰
# - 아이들 상태: HIGH (3.3V)
# - 데이터 전송 시: 펄스 패턴

# 전압 레벨 확인 (중요: 5V 시스템에 3.3V 어댑터 연결 시 손상)
```

---

## 2. UART 인터페이스

### 2.1 UART 프로토콜 기초

```
프레임 구조: [START(1)] [DATA(5-9)] [PARITY(0-1)] [STOP(1-2)]

일반적인 설정:
- 8N1: 8 데이터 비트, No parity, 1 stop bit
- 보레이트: 9600 / 19200 / 38400 / 57600 / 115200 / 230400 / 460800 / 921600

신호 레벨:
- 표준 UART: 0V = 논리 0, 3.3V/5V = 논리 1
- RS-232: ±3~15V (레벨 변환 필수)
```

### 2.2 UART 연결 방법

```bash
# Bus Pirate → 타깃 UART 연결
# Bus Pirate TX  → 타깃 RX
# Bus Pirate RX  → 타깃 TX
# Bus Pirate GND → 타깃 GND
# (전원 공급 불필요 시 VCC 연결 생략)

# Bus Pirate 설정
screen /dev/ttyUSB0 115200
# HiZ> m
# 1. HiZ
# 2. 1-WIRE
# 3. UART   ← 선택
# 4. I2C
# ...
# Baud rate: 115200
# Data bits: 8
# Parity: None
# Stop bits: 1
# Receive polarity: Idle 1
# (1)>(2)... Macro

# Raspberry Pi UART 연결
# RPi GPIO 14(TX) → 타깃 RX
# RPi GPIO 15(RX) → 타깃 TX
# 공통 GND 연결

# 터미널 클라이언트
minicom -b 115200 -D /dev/ttyS0
# 또는
picocom -b 115200 /dev/ttyS0

# screen 사용
screen /dev/ttyS0 115200
# 종료: Ctrl+A → K
```

### 2.3 UART 부트로더 인터럽트

```bash
# 장치 전원 투입 즉시 스페이스바 / Ctrl+C / Ctrl+B 입력 시도
# U-Boot 인터럽트:
# "Hit any key to stop autoboot:" 메시지 출력 시 Enter 키 연타

# U-Boot 셸에서 환경변수 확인
printenv

# 환경변수에서 부팅 명령 확인
# bootcmd=tftp 0x80000000 uImage; bootm
# bootargs=console=ttyS0,115200 root=/dev/mtdblock2 rootfstype=squashfs

# U-Boot에서 플래시 덤프
md.b 0xBF000000 0x1000000   # 메모리 16MB 덤프
# 또는 TFTP 서버로 전송
tftpput 0x80000000 0x1000000 192.168.1.100:flash_dump.bin

# U-Boot busybox 셸 접근 시도
# init=/bin/sh 커널 파라미터 추가
setenv bootargs "console=ttyS0,115200 root=/dev/mtdblock2 init=/bin/sh"
boot
```

---

## 3. SPI 인터페이스

### 3.1 SPI 핀 배열

```
표준 SPI 신호:
- MOSI (Master Out Slave In) — 마스터 → 슬레이브 데이터
- MISO (Master In Slave Out) — 슬레이브 → 마스터 데이터
- SCLK (Serial Clock)        — 클럭
- CS/CE (Chip Select)        — 액티브 LOW

SPI NOR Flash 핀아웃 (SOIC-8):
Pin 1: CS#    Pin 8: VCC
Pin 2: DO     Pin 7: HOLD#/RESET#
Pin 3: WP#    Pin 6: CLK
Pin 4: GND    Pin 5: DI
```

### 3.2 flashrom으로 SPI 플래시 덤프

```bash
# Raspberry Pi SPI 활성화
sudo raspi-config nonint do_spi 0

# flashrom 칩 탐지
sudo flashrom -p linux_spi:dev=/dev/spidev0.0,spispeed=4000 --flash-name

# 펌웨어 읽기 (3회 반복하여 무결성 확인)
for i in 1 2 3; do
  sudo flashrom -p linux_spi:dev=/dev/spidev0.0,spispeed=2000 \
    -r "dump_${i}.bin"
done

# MD5 비교로 덤프 신뢰성 확인
md5sum dump_1.bin dump_2.bin dump_3.bin

# 동일하면 하나를 최종 덤프로 사용
cp dump_1.bin firmware_original.bin

# Bus Pirate로 SPI 플래시 읽기
flashrom -p buspirate_spi:dev=/dev/ttyUSB0,spispeed=1M \
  -r firmware.bin

# CH341A 프로그래머 사용 시 (저렴한 USB SPI 프로그래머)
flashrom -p ch341a_spi -r firmware.bin
```

### 3.3 SOIC Clip을 이용한 인-시스템 프로그래밍

```bash
# 칩 탈착 없이 SOIC-8 클립으로 덤프 (In-System Programming)
# 주의: SoC가 켜진 상태에서 버스 충돌 발생 가능
# → 타깃 전원 OFF 후 클립 연결, flashrom 실행 중 전원 ON 금지

# 타깃 SoC가 SPI 버스를 점유하는 경우:
# 1. CS# 핀에 풀업 저항 추가하거나
# 2. SoC 리셋 핀을 LOW로 유지하면서 덤프
# 3. 또는 칩을 PCB에서 탈착 후 소켓/프로그래머 사용

# W25Q128 (128Mbit = 16MB) 전체 읽기
sudo flashrom -p linux_spi:dev=/dev/spidev0.0,spispeed=2000 \
  -c "W25Q128.V" -r firmware_16mb.bin

# 특정 영역만 읽기 (레이아웃 파일 사용)
cat > layout.txt << 'EOF'
00000000:0007ffff bootloader
00080000:007fffff firmware
EOF
sudo flashrom -p linux_spi:dev=/dev/spidev0.0 \
  -l layout.txt -i firmware -r firmware_only.bin
```

---

## 4. I2C 인터페이스

### 4.1 I2C 버스 스캔

```bash
# i2c-tools 설치
sudo apt install -y i2c-tools

# 버스 목록 확인
i2cdetect -l

# 버스 0 스캔 (주소 0x00~0x7F)
sudo i2cdetect -y 0
sudo i2cdetect -y 1   # Raspberry Pi 기본 I2C 버스

# 출력 예시:
#      0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f
# 00:          -- -- -- -- -- -- -- -- -- -- -- -- --
# 10: -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --
# 20: -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --
# 30: -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --
# 40: -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --
# 50: 50 -- -- -- -- -- -- -- -- -- -- -- -- -- -- --
# 60: -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --
# 70: -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --
# 0x50 → 24CXX EEPROM

# 레지스터 읽기
sudo i2cget -y 1 0x50 0x00    # 버스1, 주소0x50, 레지스터0
sudo i2cdump -y 1 0x50        # 전체 레지스터 덤프

# I2C EEPROM 전체 읽기 (at24 드라이버 사용)
echo "24c256 0x50" | sudo tee /sys/bus/i2c/devices/i2c-1/new_device
sudo cat /sys/bus/i2c/devices/1-0050/eeprom > eeprom_dump.bin
```

### 4.2 I2C EEPROM에서 크리덴셜 추출

```bash
# 일반 EEPROM 구조 분석
hexdump -C eeprom_dump.bin | head -50

# 문자열 추출
strings eeprom_dump.bin

# 일반적으로 저장된 데이터:
# - MAC 주소
# - 시리얼 넘버
# - Wi-Fi 기본 비밀번호
# - 디바이스 설정 파라미터
# - 보정 데이터 (calibration)
```

---

## 5. JTAG 인터페이스

### 5.1 JTAG 핀 식별

```
JTAG 신호:
- TDI  (Test Data In)      — 데이터 입력
- TDO  (Test Data Out)     — 데이터 출력
- TCK  (Test Clock)        — 클럭
- TMS  (Test Mode Select)  — TAP 상태 머신 제어
- TRST (Test Reset)        — 선택적 리셋 (액티브 LOW)
- RTCK (Return TCK)        — 선택적 적응형 클럭

표준 헤더 배열:
20핀 ARM JTAG:
 1: VTref   2: Vsupply
 3: nTRST   4: GND
 5: TDI     6: GND
 7: TMS     8: GND
 9: TCK    10: GND
11: RTCK   12: GND
13: TDO    14: GND
15: RESET  16: GND
17: DBGRQ  18: GND
19: DBGACK 20: GND

10핀 ARM SWD/JTAG:
 1: VTref   2: Vsupply
 3: nTRST   4: GND
 5: TDI     6: GND
 7: TMS     8: GND
 9: TCK    10: GND
```

### 5.2 JTAGulator로 핀 자동 탐지

```bash
# JTAGulator (PIC32 기반 전용 도구)
screen /dev/ttyUSB0 115200

# JTAGulator 메뉴
# J → JTAG
# B → 전압 설정 (3.3V)
# D → 핀 탐지 시작
# 채널 범위: 0-7 입력
# IDCODE scan 선택
```

### 5.3 OpenOCD로 JTAG 연결

```bash
# Raspberry Pi GPIO bitbang JTAG
# openocd 설정 파일 생성
cat > /tmp/rpi_jtag.cfg << 'EOF'
# Raspberry Pi GPIO JTAG adapter
interface bcm2835gpio
bcm2835gpio_peripheral_base 0xFE000000
bcm2835gpio_speed_coeffs 236181 60

# 핀 번호 (BCM 기준)
bcm2835gpio_jtag_nums 11 25 10 9
# TCK=GPIO11, TMS=GPIO25, TDI=GPIO10, TDO=GPIO9

adapter_khz 1000
EOF

# 타깃 설정 (예: STM32F4)
cat > /tmp/target.cfg << 'EOF'
source [find target/stm32f4x.cfg]
reset_config srst_only
EOF

# OpenOCD 실행
sudo openocd -f /tmp/rpi_jtag.cfg -f /tmp/target.cfg

# 다른 터미널에서 telnet 연결
telnet localhost 4444

# OpenOCD 명령
> halt
> flash banks
> dump_image /tmp/firmware.bin 0x08000000 0x100000
> resume
```

### 5.4 GDB + OpenOCD 디버깅

```bash
# gdb-multiarch 설치
sudo apt install -y gdb-multiarch

# GDB 연결 (OpenOCD 실행 중)
gdb-multiarch -q
(gdb) target extended-remote localhost:3333
(gdb) monitor halt
(gdb) info registers
(gdb) x/20x $sp           # 스택 내용 확인
(gdb) x/s 0x08001234      # 특정 주소 문자열 출력

# 브레이크포인트 설정 후 크리덴셜 검색
(gdb) watch *0x20001000    # 특정 메모리 주소 감시
(gdb) continue
```

---

## 6. Bus Pirate 실전 활용

### 6.1 Bus Pirate 모드 전환

```
Bus Pirate 터미널 명령 요약:
m        - 모드 선택 메뉴
?        - 도움말
~        - 자가진단
=X       - 16진수 변환
i        - 장치 정보
W/w      - 전원 ON/OFF (3.3V, 5V)
P/p      - 풀업 저항 ON/OFF
v        - 전압 측정
f        - 주파수 측정

UART 모드 전송:
>        - 프롬프트 (입력 대기)
[데이터] - 전송
(숫자)   - 반복 횟수
```

### 6.2 Bus Pirate SPI 플래시 수동 읽기

```
# SPI 모드 진입 후
# CS LOW, WREN, 주소 전송

> {0x03 0x00 0x00 0x00 r:256}
# 0x03 = READ 명령
# 0x000000 = 시작 주소
# r:256 = 256 바이트 읽기

# 플래시 지우기 (칩 전체)
> {0x06}     # Write Enable
> {0xC7}     # Chip Erase
# 소거 완료까지 대기 (~30초)

# 섹터 읽기 (4KB 단위)
> {0x03 0x00 0x10 0x00 r:4096}
```

---

## 7. Flipper Zero UART 활용

### 7.1 GPIO UART 터미널

```
Flipper Zero → 타깃 UART 연결:
- Pin 13 (TX)  → 타깃 RX
- Pin 14 (RX)  → 타깃 TX
- Pin 18 (GND) → 타깃 GND
- Pin 1  (3V3) → 타깃 VCC (필요 시)

Flipper Zero 메뉴:
GPIO → USB-UART Bridge
보레이트 설정 후 연결
```

### 7.2 qFlipper CLI 연동

```bash
# Flipper Zero를 USB로 PC에 연결 후
# /dev/ttyACM0 으로 접근 가능

# Flipper Zero CLI
screen /dev/ttyACM0 230400

# Flipper CLI 명령
>: help
>: log          # 시스템 로그
>: gpio mode 13 OUTPUT   # 핀 모드 설정
>: gpio write 13 1       # 핀 출력
>: gpio read 14          # 핀 읽기
```

---

## 8. Logic Analyzer로 프로토콜 캡처

### 8.1 sigrok 고급 설정

```bash
# 사용 가능한 드라이버 목록
sigrok-cli --scan

# Cypress FX2 기반 로직 애널라이저 (Saleae 호환)
sigrok-cli -d fx2lafw --config samplerate=24m \
  --continuous -o /tmp/capture.sr &

# 실시간 UART 디코딩
sigrok-cli -d fx2lafw \
  --config samplerate=24m \
  --samples 50000000 \
  -P uart:baudrate=115200:rx=D0 \
  --protocol-decoder-annotation all

# SPI + UART 동시 디코딩
sigrok-cli -d fx2lafw \
  --config samplerate=24m \
  --samples 10000000 \
  -P spi:clk=D0:mosi=D1:miso=D2:cs=D3,uart:baudrate=115200:rx=D4

# 캡처 파일에서 오프라인 분석
sigrok-cli -i capture.sr \
  -P i2c:scl=D0:sda=D1 \
  --protocol-decoder-samplenum \
  -A i2c=data-read,data-write
```

### 8.2 PulseView GUI 활용

```bash
# GUI 실행
pulseview &

# 캡처 후 프로토콜 디코더 추가:
# Decoders → I2C → 채널 할당 → 디코드 실행

# 저장 포맷
# .sr  : sigrok 네이티브
# .csv : 타임스탬프 + 샘플값
# .vcd : Value Change Dump (GTKWave 호환)
```

---

## 9. 펌웨어 덤프 — binwalk 초기 분석

```bash
# 기본 분석
binwalk firmware.bin

# 서명 스캔 + 엔트로피 계산
binwalk -B -E firmware.bin

# 자동 추출
binwalk -e firmware.bin
binwalk -Me firmware.bin   # 재귀 추출

# 출력 예시:
# DECIMAL   HEXADECIMAL   DESCRIPTION
# 0         0x0           TRX firmware header
# 28        0x1C          LZMA compressed data
# 1048576   0x100000      Squashfs filesystem, little endian
# 2097152   0x200000      JFFS2 filesystem data

# 특정 오프셋 추출
dd if=firmware.bin of=squashfs.bin bs=1 skip=1048576 count=1048576

# squashfs 마운트
sudo unsquashfs squashfs.bin
ls squashfs-root/
```

---

## 10. Python 도구 — UART 브루트포스 Baud Rate 스캐너

```python
#!/usr/bin/env python3
"""
UART Baud Rate Brute-force Scanner

Usage:
    python3 uart_baud_scanner.py -p /dev/ttyUSB0
    python3 uart_baud_scanner.py -p /dev/ttyUSB0 -b 115200 9600 38400
    python3 uart_baud_scanner.py -p /dev/ttyUSB0 --all --output results.json
    python3 uart_baud_scanner.py -p /dev/ttyUSB0 --trigger-string "login:"
"""

import argparse
import concurrent.futures
import json
import logging
import sys
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

try:
    import serial
    import serial.tools.list_ports
except ImportError:
    print("[!] pyserial 미설치: pip3 install pyserial", file=sys.stderr)
    sys.exit(1)


COMMON_BAUD_RATES: list[int] = [
    300, 600, 1200, 2400, 4800, 9600, 14400, 19200,
    28800, 38400, 57600, 115200, 230400, 460800, 921600,
]

ALL_BAUD_RATES: list[int] = COMMON_BAUD_RATES + [
    1800, 7200, 56000, 76800, 153600, 500000, 576000, 1000000,
    1152000, 1500000, 2000000, 2500000, 3000000, 3500000, 4000000,
]

PRINTABLE_RATIO_THRESHOLD: float = 0.4
ASCII_INDICATORS: list[bytes] = [
    b"login", b"Login", b"password", b"Password",
    b"root", b"admin", b"#", b"$", b">",
    b"Boot", b"boot", b"U-Boot", b"OpenWrt",
    b"BusyBox", b"Linux", b"kernel",
]


@dataclass
class ScanResult:
    port: str
    baud_rate: int
    data_bits: int
    parity: str
    stop_bits: float
    received_bytes: int
    printable_ratio: float
    matched_indicators: list[str]
    raw_sample: str
    is_promising: bool
    scan_duration_ms: float
    error: Optional[str] = None


@dataclass
class ScanReport:
    port: str
    scan_time: str
    total_tested: int
    promising_results: list[ScanResult] = field(default_factory=list)
    all_results: list[ScanResult] = field(default_factory=list)


def list_serial_ports() -> list[str]:
    ports = serial.tools.list_ports.comports()
    return [p.device for p in ports]


def calculate_printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    printable = sum(
        1 for b in data
        if 0x20 <= b <= 0x7E or b in (0x09, 0x0A, 0x0D)
    )
    return printable / len(data)


def find_matched_indicators(data: bytes) -> list[str]:
    matched: list[str] = []
    data_lower = data.lower()
    for indicator in ASCII_INDICATORS:
        if indicator.lower() in data_lower:
            matched.append(indicator.decode("ascii", errors="replace"))
    return matched


def probe_baud_rate(
    port: str,
    baud_rate: int,
    data_bits: int = 8,
    parity: str = "N",
    stop_bits: float = 1.0,
    timeout: float = 1.5,
    read_bytes: int = 256,
    send_newlines: bool = True,
) -> ScanResult:
    start_ts = time.monotonic()
    error_msg: Optional[str] = None
    received = b""

    try:
        with serial.Serial(
            port=port,
            baudrate=baud_rate,
            bytesize=data_bits,
            parity=parity,
            stopbits=stop_bits,
            timeout=timeout,
            xonxoff=False,
            rtscts=False,
            dsrdtr=False,
        ) as ser:
            ser.reset_input_buffer()
            ser.reset_output_buffer()

            if send_newlines:
                ser.write(b"\r\n")
                time.sleep(0.05)

            time.sleep(timeout * 0.6)
            waiting = ser.in_waiting
            if waiting > 0:
                received = ser.read(min(waiting, read_bytes))
            else:
                received = ser.read(read_bytes)

    except serial.SerialException as exc:
        error_msg = str(exc)
    except Exception as exc:
        error_msg = f"unexpected: {exc}"

    elapsed_ms = (time.monotonic() - start_ts) * 1000
    ratio = calculate_printable_ratio(received)
    indicators = find_matched_indicators(received)

    is_promising = (
        len(received) > 4
        and (ratio >= PRINTABLE_RATIO_THRESHOLD or len(indicators) > 0)
        and error_msg is None
    )

    raw_sample = received[:128].decode("ascii", errors="replace").strip()

    return ScanResult(
        port=port,
        baud_rate=baud_rate,
        data_bits=data_bits,
        parity=parity,
        stop_bits=stop_bits,
        received_bytes=len(received),
        printable_ratio=round(ratio, 3),
        matched_indicators=indicators,
        raw_sample=raw_sample,
        is_promising=is_promising,
        scan_duration_ms=round(elapsed_ms, 1),
        error=error_msg,
    )


def scan_port(
    port: str,
    baud_rates: list[int],
    workers: int = 1,
    verbose: bool = False,
    trigger_string: Optional[str] = None,
) -> ScanReport:
    import datetime

    report = ScanReport(
        port=port,
        scan_time=datetime.datetime.now().isoformat(),
        total_tested=0,
    )

    logger = logging.getLogger(__name__)
    logger.info("스캔 시작: %s (%d 보레이트)", port, len(baud_rates))

    # UART는 동시 접근 불가 → 순차 실행이 기본
    # workers > 1 은 여러 포트 동시 스캔 시 사용
    for baud in baud_rates:
        result = probe_baud_rate(port, baud)
        report.total_tested += 1
        report.all_results.append(result)

        status_char = "[+]" if result.is_promising else "[ ]"
        if verbose or result.is_promising:
            print(
                f"{status_char} {port} @ {baud:>7} bps | "
                f"recv={result.received_bytes:>4}B | "
                f"printable={result.printable_ratio:.1%} | "
                f"indicators={result.matched_indicators}"
            )
            if result.raw_sample and result.is_promising:
                preview = result.raw_sample[:80].replace("\n", "\\n")
                print(f"         샘플: {preview!r}")

        if result.is_promising:
            report.promising_results.append(result)

        if trigger_string and trigger_string.encode() in (
            result.raw_sample.encode()
        ):
            logger.info(
                "트리거 문자열 발견! 보레이트=%d", baud
            )
            print(f"\n[!] 트리거 '{trigger_string}' 발견: {baud} bps")
            break

    return report


def scan_multiple_ports(
    ports: list[str],
    baud_rates: list[int],
    workers: int = 4,
    verbose: bool = False,
) -> list[ScanReport]:
    reports: list[ScanReport] = []

    def scan_one(port: str) -> ScanReport:
        return scan_port(port, baud_rates, verbose=verbose)

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        future_map = {executor.submit(scan_one, p): p for p in ports}
        for future in concurrent.futures.as_completed(future_map):
            port = future_map[future]
            try:
                reports.append(future.result())
            except Exception as exc:
                logging.getLogger(__name__).error(
                    "포트 %s 스캔 실패: %s", port, exc
                )

    return reports


def print_summary(report: ScanReport) -> None:
    print("\n" + "=" * 60)
    print(f"  스캔 결과 요약: {report.port}")
    print("=" * 60)
    print(f"  테스트한 보레이트: {report.total_tested}")
    print(f"  유망한 결과: {len(report.promising_results)}")

    if report.promising_results:
        print("\n  [+] 유망한 보레이트:")
        for r in sorted(
            report.promising_results,
            key=lambda x: x.printable_ratio,
            reverse=True,
        ):
            print(
                f"      {r.baud_rate:>8} bps | "
                f"printable={r.printable_ratio:.1%} | "
                f"recv={r.received_bytes}B"
            )
            if r.matched_indicators:
                print(f"      인디케이터: {r.matched_indicators}")
            if r.raw_sample:
                preview = r.raw_sample[:100].replace("\n", "\\n")
                print(f"      샘플: {preview!r}")
    else:
        print("\n  [-] 유망한 결과 없음. 다음을 확인하라:")
        print("      - TX/RX 선 교차 여부")
        print("      - 전압 레벨 (3.3V vs 5V)")
        print("      - 타깃 장치 전원 ON 여부")
        print("      - 논리 극성 (inverted UART)")
    print("=" * 60)


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="UART Baud Rate Brute-force Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
예시:
  %(prog)s -p /dev/ttyUSB0
  %(prog)s -p /dev/ttyUSB0 -b 9600 115200 460800
  %(prog)s -p /dev/ttyUSB0 --all -v
  %(prog)s -p /dev/ttyUSB0 --all --output results.json
  %(prog)s --list-ports
  %(prog)s -p /dev/ttyUSB0 /dev/ttyUSB1 -w 2
  %(prog)s -p /dev/ttyUSB0 --trigger-string "login:"
        """,
    )
    parser.add_argument(
        "-p", "--port",
        nargs="+",
        metavar="PORT",
        help="시리얼 포트 경로 (예: /dev/ttyUSB0). 여러 개 가능",
    )
    parser.add_argument(
        "-b", "--baud-rates",
        nargs="+",
        type=int,
        metavar="BAUD",
        default=COMMON_BAUD_RATES,
        help=f"테스트할 보레이트 목록 (기본: 일반적인 {len(COMMON_BAUD_RATES)}개)",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help=f"모든 보레이트 테스트 ({len(ALL_BAUD_RATES)}개)",
    )
    parser.add_argument(
        "-w", "--workers",
        type=int,
        default=1,
        metavar="N",
        help="동시 작업 수 (여러 포트 스캔 시, 기본: 1)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="모든 결과 출력 (유망하지 않은 것 포함)",
    )
    parser.add_argument(
        "--output",
        metavar="FILE",
        help="결과를 JSON 파일로 저장",
    )
    parser.add_argument(
        "--trigger-string",
        metavar="STR",
        help="이 문자열 발견 시 스캔 중단 (예: 'login:')",
    )
    parser.add_argument(
        "--list-ports",
        action="store_true",
        help="시스템의 시리얼 포트 목록 출력 후 종료",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=1.5,
        metavar="SEC",
        help="각 보레이트별 응답 대기 시간 (기본: 1.5초)",
    )
    parser.add_argument(
        "--read-bytes",
        type=int,
        default=256,
        metavar="N",
        help="각 시도당 최대 읽기 바이트 수 (기본: 256)",
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="WARNING",
        help="로그 레벨 (기본: WARNING)",
    )
    return parser


def main() -> int:
    parser = build_argument_parser()
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    if args.list_ports:
        ports = list_serial_ports()
        if ports:
            print("감지된 시리얼 포트:")
            for p in ports:
                print(f"  {p}")
        else:
            print("감지된 시리얼 포트 없음")
        return 0

    if not args.port:
        parser.error("-p/--port 또는 --list-ports 가 필요합니다")

    baud_rates = ALL_BAUD_RATES if args.all else args.baud_rates
    baud_rates = sorted(set(baud_rates))

    print(f"[*] 대상 포트: {args.port}")
    print(f"[*] 테스트 보레이트: {len(baud_rates)}개")
    print(f"[*] 각 시도 타임아웃: {args.timeout}초")
    print()

    all_reports: list[ScanReport] = []

    if len(args.port) == 1:
        report = scan_port(
            port=args.port[0],
            baud_rates=baud_rates,
            verbose=args.verbose,
            trigger_string=args.trigger_string,
        )
        all_reports.append(report)
        print_summary(report)
    else:
        all_reports = scan_multiple_ports(
            ports=args.port,
            baud_rates=baud_rates,
            workers=args.workers,
            verbose=args.verbose,
        )
        for report in all_reports:
            print_summary(report)

    if args.output:
        output_path = Path(args.output)
        serializable = [
            {
                "port": r.port,
                "scan_time": r.scan_time,
                "total_tested": r.total_tested,
                "promising": [asdict(p) for p in r.promising_results],
                "all_results": [asdict(p) for p in r.all_results],
            }
            for r in all_reports
        ]
        output_path.write_text(
            json.dumps(serializable, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        print(f"\n[+] 결과 저장: {output_path}")

    # 유망한 결과가 있으면 exit code 0, 없으면 1
    has_promising = any(r.promising_results for r in all_reports)
    return 0 if has_promising else 1


if __name__ == "__main__":
    sys.exit(main())
```

---

## 11. JTAG 브루트포스 — UrJTAG 활용

```bash
# UrJTAG 설치
sudo apt install -y jtag

# UrJTAG 인터랙티브 셸
jtag
jtag> cable UsbBlaster
jtag> detect
jtag> discovery
jtag> print chain

# JTAG 경계 스캔으로 디바이스 ID 확인
jtag> detectflash 0x00000000

# OpenOCD를 이용한 MIPS 타깃 (라우터 SoC)
cat > /tmp/mips_jtag.cfg << 'EOF'
interface jlink
transport select jtag
set _CHIPNAME mips
set _CPUID 0x00000001
jtag newtap $_CHIPNAME cpu -irlen 5 -expected-id $_CPUID
target create $_CHIPNAME.cpu mips_m4k -chain-position $_CHIPNAME.cpu
EOF

openocd -f /tmp/mips_jtag.cfg
```

---

## 12. 인터페이스 식별 치트시트

```
전압 레벨별 접근 방법:
┌─────────┬──────────────────┬────────────────────────┐
│ 전압    │ 직접 연결        │ 필요 변환              │
├─────────┼──────────────────┼────────────────────────┤
│ 5V UART │ Bus Pirate (5V)  │ 3.3V 시스템 → 레벨시프터│
│ 3.3V    │ RPi, Flipper     │ 5V 시스템 → 레벨시프터  │
│ 1.8V    │ -                │ 레벨시프터 필수         │
│ 1.2V    │ -                │ 전용 레벨시프터 필요    │
└─────────┴──────────────────┴────────────────────────┘

인터페이스 식별 우선순위:
1. UART (3핀: TX, RX, GND) → 로그/셸 접근
2. JTAG (4~5핀)            → 완전한 디버그/덤프
3. SPI Flash (8핀 SOIC)    → 펌웨어 직접 덤프
4. I2C EEPROM              → 설정/키 추출
```

---

<!-- detect-validate-34 -->
## 디버그 인터페이스 노출 탐지와 하드닝 검증

하드웨어 정찰은 *UART 콘솔·JTAG·SPI 플래시·I2C EEPROM* 같은 노출된 디버그 인터페이스로 셸·펌웨어·키를 얻는다. 방어자는 **출하 기기에서 디버그 포트가 비활성/잠금됐는지**를 검증해야 한다. 검증은 **소유 기기/개발 보드**에서만.

### 공격 → 노리는 약점 → 1차 통제(방어자) → 탐지 신호

| 기법 | 노리는 약점 | 1차 통제(방어자) | 탐지 신호 |
|---|---|---|---|
| UART 콘솔 | 활성 시리얼 셸 | 콘솔 비활성·인증 | 부팅 시 셸 프롬프트 |
| JTAG/SWD | 잠금 안 된 디버그 | 퓨즈로 영구 비활성 | IDCODE 응답 |
| SPI 플래시 덤프 | 외부 플래시 평문 | 플래시 암호화 | 덤프 엔트로피 낮음 |
| I2C EEPROM | 평문 설정/키 | 보안 요소로 이전 | EEPROM에 평문 키 |

### 방어 검증 (직접 확인)

```bash
# 1) 소유 기기 펌웨어 덤프의 디버그 인터페이스 흔적 — 활성 콘솔/getty 참조
strings -n 8 owned_firmware.bin 2>/dev/null | grep -iE 'ttyS|getty|/bin/sh|console=' | head
# 2) 추출한 SPI 플래시 이미지 암호화 여부 — 엔트로피 < 7.0 이면 평문(미암호화) 신호
python3 -c "import sys,math,collections;d=open('flash.bin','rb').read();c=collections.Counter(d);e=-sum(n/len(d)*math.log2(n/len(d)) for n in c.values());print(f'entropy={e:.2f}')" 2>/dev/null
```

> 하드웨어 하드닝은 *디버그 표면이 닫혀 있는가*다 — "기능은 동작한다"와 "JTAG가 퓨즈로 잠기고 콘솔에 셸이 안 뜨며 플래시가 암호화됐다"는 다르다. 소유 기기/개발 보드에서 노출 인터페이스를 직접 확인한다([[61_Firmware_Hacking]], [[27_IoT_Hacking]], [[04_Reverse_Engineering]]).

**최신 기법·통제 (2025–2026):**
- UART/JTAG/SWD·SPI 플래시 노출이 진입점 — 디버그 비활성·글리치 방어로 대응. 검증: 프로덕션에서 디버그 인터페이스가 잠기는지 확인(소유 기기)([[27_IoT_Hacking]])
- 분석은 소유 하드웨어 한정 — 합법성 통제

---

<a name="english"></a>

# 01 — Hardware Recon & Interfaces

## 1. Physical Reconnaissance

### 1.1 PCB Analysis Procedure

```bash
# Pre-disassembly checklist
# 1) Identify case screw types — identify special screws (Torx, Pentalobe, Tri-wing)
# 2) Adhesive cases — soften glue with heat gun at 50~60°C
```

## Key Interface Overview

Hardware hacking starts with identifying debug interfaces on the PCB. The most common interfaces are:

- **UART**: Most commonly exposed debug console (serial output, often shell access)
- **JTAG**: Full chip-level debug/dump capability, requires pin identification
- **SPI Flash**: Direct flash memory dump, 8-pin SOIC package
- **I2C EEPROM**: Configuration/key extraction

## Interface Voltage Reference

| Voltage | Logic Level | Notes |
|---------|------------|-------|
| 3.3V    | TTL/CMOS   | Most common |
| 5V      | TTL        | Older devices |
| 1.8V    | -          | Level shifter required |
| 1.2V    | -          | Dedicated level shifter needed |

Interface Identification Priority:
1. UART (3 pins: TX, RX, GND) → Log/shell access
2. JTAG (4~5 pins)            → Full debug/dump
3. SPI Flash (8-pin SOIC)     → Direct firmware dump
4. I2C EEPROM                 → Configuration/key extraction


<!-- detect-validate-34 -->
## Debug Interface Exposure Detection and Hardening Validation

Hardware recon obtains shell, firmware, or keys via exposed debug interfaces like *UART console, JTAG, SPI flash, and I2C EEPROM*. Defenders must verify **whether debug ports are disabled/locked on shipped devices**. Validate only on **owned devices/dev boards**.

### Attack -> Targeted weakness -> Primary control (defender) -> Detection signal

| Technique | Targeted weakness | Primary control (defender) | Detection signal |
|---|---|---|---|
| UART console | Active serial shell | Disable console, auth | Shell prompt at boot |
| JTAG/SWD | Unlocked debug | Permanently fuse off | IDCODE responds |
| SPI flash dump | Plaintext external flash | Encrypt flash | Low dump entropy |
| I2C EEPROM | Plaintext config/keys | Move to secure element | Plaintext key in EEPROM |

### Defense validation (verify directly)

```bash
# 1) Debug-interface traces in owned firmware dump — active console/getty references
strings -n 8 owned_firmware.bin 2>/dev/null | grep -iE 'ttyS|getty|/bin/sh|console=' | head
# 2) Whether extracted SPI flash image is encrypted — entropy < 7.0 signals plaintext (unencrypted)
python3 -c "import sys,math,collections;d=open('flash.bin','rb').read();c=collections.Counter(d);e=-sum(n/len(d)*math.log2(n/len(d)) for n in c.values());print(f'entropy={e:.2f}')" 2>/dev/null
```

> Hardware hardening is *whether the debug surface is closed* -- "the feature works" differs from "JTAG is fuse-locked, no shell appears on the console, and flash is encrypted". Confirm the exposed interfaces on owned devices/dev boards directly ([[61_Firmware_Hacking]], [[27_IoT_Hacking]], [[04_Reverse_Engineering]]).
