> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# RF/Zigbee/Z-Wave IoT 무선 프로토콜 공격

## 0. 초보자를 위한 개념 이해

### 무선 IoT 프로토콜 보안이란?

IoT 기기의 상당수는 Wi-Fi가 아닌 전용 무선 프로토콜(RF 433MHz, Zigbee, Z-Wave)로 통신한다. 스마트 도어락, 차고 문, 무선 센서, 스마트홈 허브 등이 이 범주에 속한다. 이 프로토콜들은 저전력·저비용을 우선시하다 보니 보안이 취약한 경우가 많다. SDR(소프트웨어 정의 라디오)을 사용하면 전파를 직접 캡처하고 분석할 수 있다.

**왜 배우는가:**
```
무선 IoT 공격이 위험한 이유

[433MHz 리모컨 (차고문, 게이트)]
  정적 코드: 항상 동일한 신호 → 한 번 녹음하면 무한 재전송
  SDR로 신호 캡처 → 파일 저장 → 재전송 → 문 열림

[Zigbee (스마트홈 기기)]
  S0 키 교환 취약점: 네트워크 가입 시 키가 평문으로 전송
  → 주변에서 스니핑하면 키 획득 → 전체 Zigbee 네트워크 제어

[Z-Wave S0]
  키 교환 중 키를 브로드캐스트로 전송
  → 스니핑 시 네트워크 진입 가능
```

### 핵심 개념 정리

```
무선 프로토콜 비교

프로토콜   주파수     용도                  주요 취약점
──────────────────────────────────────────────────────────
433MHz RF  433.92MHz  리모컨, 센서          정적 코드 재전송(Replay)
Zigbee     2.4GHz     스마트홈, 산업용 IoT  S0 키 노출, 패킷 스니핑
Z-Wave     868/915MHz 스마트홈              S0 키 전송 취약점
Bluetooth  2.4GHz     근거리 기기           BLE 스캔, MITM
```

### 필요한 도구 및 환경
- **RTL-SDR**: 약 2~3만원, USB 동글형 소프트웨어 정의 라디오
- **GNU Radio / SDR#**: SDR 수신 소프트웨어
- **KillerBee**: Zigbee 분석 (`pip install killerbee`)
- **Flipper Zero**: 433MHz/NFC/IR 올인원 테스트 도구

### 기초 실습 예제
```bash
# 1. RTL-SDR 설치 및 테스트
sudo apt install rtl-sdr
rtl_test -t               # 장치 인식 확인

# 2. 433MHz 신호 수신 (라디오 주파수 스캔)
rtl_433 -f 433920000 -g 40   # 433.92MHz 자동 디코딩
# rtl_433은 수백 가지 기기 프로토콜 자동 인식

# 3. 원시 신호 녹화 (IQ 파일로 저장)
rtl_sdr -f 433920000 -s 250000 -g 40 signal_capture.iq

# 4. Zigbee 채널 스캔 (KillerBee, USB Zigbee 어댑터 필요)
zbstumbler               # 주변 Zigbee 네트워크 탐색
zbdump -c 11 -w cap.pcap # 채널 11 패킷 덤프
```

---

## 학습 목표

이 실습을 마치면 다음을 할 수 있다:

1. **무선 통신의 기초 원리** — 주파수, 파장, 변조 방식을 평이한 언어로 설명한다
2. **SDR(Software Defined Radio)**의 작동 원리를 이해하고 RTL-SDR을 설정한다
3. **433MHz 리플레이 공격**의 원리와 정적 코드 vs 롤링 코드의 차이를 설명한다
4. **Zigbee 네트워크 구조**를 이해하고 KillerBee로 패킷을 캡처·분석한다
5. **Z-Wave S0 취약점**이 왜 발생하는지 설명한다
6. **Flipper Zero**의 주요 공격 기능을 활용한다
7. **방어 방법**을 프로토콜별로 구체적으로 적용한다

---

## 무선 통신 기초 — 완전 초보자를 위한 설명

### 주파수란?

전파(radio wave)는 공기 중을 이동하는 눈에 보이지 않는 파동이다.

```
주파수(Frequency) = 1초에 파동이 몇 번 진동하는가

단위: Hz (헤르츠)
  1 Hz = 1초에 1번 진동
  1 kHz = 1초에 1,000번 진동  (kilo)
  1 MHz = 1초에 1,000,000번 진동  (mega)
  1 GHz = 1초에 1,000,000,000번 진동  (giga)

예:
  FM 라디오: 88~108 MHz
  433MHz 리모컨: 433.92 MHz
  WiFi: 2.4 GHz 또는 5 GHz
  블루투스: 2.4 GHz
```

**실생활 비유:** 줄넘기를 생각해보자. 느리게 흔들면 큰 파도(저주파), 빠르게 흔들면 작은 파도(고주파)가 생긴다.

---

### 파장과 주파수의 관계

```
저주파 (낮은 숫자) = 긴 파장 = 멀리 도달, 장애물 통과력 좋음
고주파 (높은 숫자) = 짧은 파장 = 근거리, 더 많은 데이터 전송 가능

예:
  433 MHz → 파장 약 69cm → 수백 미터 도달 가능
  2.4 GHz → 파장 약 12.5cm → 수십 미터, 벽 통과 잘 됨
  5 GHz   → 파장 약 6cm → 더 빠르지만 도달 거리 짧음
  60 GHz  → 파장 약 5mm → 매우 빠르지만 벽 통과 거의 안 됨

IoT 보안 관점:
  저주파(433MHz, 868MHz): 범위가 넓어서 멀리서도 공격 가능
  고주파(2.4GHz WiFi): 짧은 거리지만 속도 빠름
```

---

### 변조 방식 — 어떻게 0과 1을 전파에 담는가?

디지털 데이터(0과 1)를 전파에 실으려면 **변조(Modulation)**가 필요하다.

**OOK (On-Off Keying) — 전구 방식**

```
신호를 켜고(On) 끄는(Off) 방식으로 0과 1을 표현

 1 = 신호 있음  ████
 0 = 신호 없음      
              
시간: ─────────────────────>
신호: ████    ████████    ████
비트:  1   0   1  1   0   1

사용: 433MHz 리모컨, 차고문 열림장치
장점: 단순, 구현 쉬움
단점: 보안 약함 (쉽게 캡처/재전송)
```

**FSK (Frequency Shift Keying) — 주파수 변화 방식**

```
두 개의 주파수를 써서 0과 1을 표현
  f1 = 433.90 MHz → 0
  f2 = 433.94 MHz → 1

시간: ─────────────────────>
주파수: f1  f2  f1  f1  f2  f2
비트:    0   1   0   0   1   1

사용: Zigbee, Z-Wave, 많은 ISM 대역 장치
장점: 노이즈에 강함
```

**GFSK (Gaussian FSK) — 부드러운 주파수 변화**

```
FSK와 같지만 주파수 전환이 갑작스럽지 않고 부드럽게 변함
→ 전파 간섭을 줄임

사용: Bluetooth, Zigbee
```

---

### ISM 대역 — 누구나 자유롭게 쓸 수 있는 주파수

ISM(Industrial, Scientific, Medical) 대역은 **면허 없이 자유롭게 사용 가능**한 주파수 범위다.

```
주요 ISM 대역:
  433.05~434.79 MHz  → 리모컨, 도어락, 날씨 센서 (유럽/아시아)
  902~928 MHz        → 미국 ISM (Z-Wave 미국 버전)
  868.0~868.6 MHz    → 유럽 ISM (Z-Wave 유럽 버전)
  2.400~2.4835 GHz   → WiFi, Bluetooth, Zigbee, 전자레인지

왜 중요한가?
  - 허가 없이 수신 가능 → SDR로 모니터링 합법
  - 많은 IoT 기기가 ISM 대역 사용 → 공격 표면이 넓음
  - 기기들이 서로 같은 주파수를 씀 → 간섭/혼신 가능
```

---

## IoT 무선 프로토콜 비교표

| 프로토콜 | 주파수 | 범위 | 전력 소비 | 데이터 속도 | 보안 | 주요 용도 |
|---------|--------|------|----------|------------|------|---------|
| **433MHz** | 433.92MHz | 50~300m | 낮음 | 1~10kbps | 없음/약함 | 리모컨, 도어벨, 날씨센서 |
| **Z-Wave** | 908/868MHz | 30~100m | 매우낮음 | 9.6~100kbps | S0(약)/S2(강) | 스마트홈 자동화 |
| **Zigbee** | 2.4GHz | 10~100m | 매우낮음 | 250kbps | AES-128 | 스마트조명, 센서 |
| **Bluetooth** | 2.4GHz | 10~100m | 낮음 | 1~3Mbps | AES-128 | 웨어러블, 오디오 |
| **WiFi** | 2.4/5GHz | 50~100m | 높음 | 수백Mbps | WPA2/3 | 스마트TV, 카메라 |
| **LoRa** | 433/868/915MHz | 1~15km | 매우낮음 | 0.3~50kbps | AES-128 | 농업, 스마트시티 |
| **Thread** | 2.4GHz | 10~100m | 매우낮음 | 250kbps | AES-128 + TLS | Matter 기기 |

**보안 관점 핵심 정리:**
- 433MHz: 암호화 없음 → 가장 쉬운 공격 대상
- Z-Wave S0: 키 교환 취약점 → 페어링 시 공격 가능
- Zigbee: 기본 키 문제 → 잘못 구성되면 취약
- LoRa: 낮은 대역폭 → 리플레이 공격 가능성

---

## SDR(Software Defined Radio) 개요

### SDR이란?

전통적인 무선 수신기는 특정 주파수와 변조 방식에 **고정된 하드웨어 회로**를 사용한다. SDR은 이 회로를 **소프트웨어로 대체**한다.

```
전통적인 라디오:
  안테나 → [하드웨어 필터] → [하드웨어 복조기] → 오디오
  (특정 주파수만 받을 수 있음, 변경 불가)

SDR:
  안테나 → [ADC 변환기] → 컴퓨터 소프트웨어 → 원하는 모든 처리
  (소프트웨어를 바꾸면 다른 주파수/변조 방식 처리 가능)
```

**보안 연구자에게 왜 중요한가?**
- 하나의 SDR 장치로 433MHz 리모컨도, 900MHz Z-Wave도, 2.4GHz Zigbee도 분석 가능
- 소프트웨어를 바꾸는 것만으로 다른 프로토콜 지원
- 새로운 알 수 없는 프로토콜도 직접 디코딩 가능

---

### IQ 샘플링 — SDR의 핵심 원리

SDR은 신호를 **IQ 샘플(In-phase/Quadrature)**로 표현한다.

```
I (In-phase):  신호의 "실수" 성분
Q (Quadrature): 신호의 "허수" 성분 (I와 90도 위상 차이)

비유: 시계의 시침과 분침
  시침(I): 12시 방향 기준
  분침(Q): 3시 방향 기준 (90도 차이)
  두 값을 알면 시계가 몇 시인지 (= 신호의 위상) 정확히 알 수 있음

RTL-SDR IQ 데이터:
  8비트 unsigned 정수로 저장
  I: 0~255 (실제 값 = 원래값 - 128, 즉 -128~+127)
  Q: 0~255
  한 샘플 = 2바이트 (I 1바이트 + Q 1바이트)
  IQ 데이터를 주파수 분석하면 어떤 신호가 있는지 알 수 있음
```

**소프트웨어 라디오 vs 하드웨어 라디오 차이:**

| 항목 | 하드웨어 라디오 | SDR |
|------|--------------|-----|
| 지원 주파수 | 고정 | 소프트웨어로 변경 가능 |
| 변조 방식 | 내장된 것만 | 소프트웨어로 추가 |
| 가격 | 프로토콜별로 구매 | 하나로 모두 대응 |
| 유연성 | 낮음 | 매우 높음 |
| 성능 | 최적화됨 | 약간 떨어질 수 있음 |

---

### 주요 SDR 하드웨어

| 장비 | 주파수 범위 | 가격 | 용도 |
|------|------------|------|------|
| RTL-SDR v3 | 500kHz~1.75GHz | ~$30 | 입문, 수신 전용 |
| HackRF One | 1MHz~6GHz | ~$300 | 송수신 가능 |
| YARD Stick One | Sub-1GHz | ~$100 | 433/868/915MHz 전용 |
| USRP B210 | 70MHz~6GHz | ~$1,500 | 연구용 고성능 |
| Flipper Zero | Sub-1GHz + NFC | ~$170 | 올인원 보안 도구 |

---

### SDR 소프트웨어

```bash
# GNU Radio 설치 (신호 처리 프레임워크 — 다양한 블록을 조합해 신호 처리 파이프라인 구성)
sudo apt install gnuradio

# RTL-SDR 드라이버 (RTL-SDR 하드웨어 지원)
sudo apt install rtl-sdr

# SDR++ (GUI 스펙트럼 분석기 — 실시간으로 주파수 시각화)
# https://github.com/AlexandreRouma/SDRPlusPlus

# GQRX (GNU Radio 기반 GUI — 초보자에게 친숙한 인터페이스)
sudo apt install gqrx-sdr

# URH (Universal Radio Hacker) - 프로토콜 분석 (가장 강력한 프로토콜 분석 도구)
pip install urh
```

---

## RTL-SDR 실습 가이드 — 단계별 설정

### 1단계: 하드웨어 연결 확인

```bash
# RTL-SDR USB 장치를 컴퓨터에 연결한 후:

# 장치 감지 확인
rtl_test -t

# 정상 출력 예시:
# Found 1 device(s):
#   0:  Realtek, RTL2838UHIDIR, SN: 00000001
# Using device 0: Generic RTL2832U OEM
# Found Rafael Micro R820T tuner

# 오류가 나면 드라이버 설치:
sudo apt install rtl-sdr librtlsdr-dev
# udev 규칙 추가 (USB 권한):
sudo cp /usr/lib/udev/rules.d/rtl-sdr.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules
sudo udevadm trigger
# 재로그인 후 다시 시도
```

### 2단계: 첫 번째 수신 테스트 — FM 라디오

```bash
# FM 라디오 수신 (지역 FM 방송 주파수 입력)
# 이것이 성공하면 RTL-SDR이 올바르게 작동하는 것
rtl_fm -f 89.1M -M wbfm -s 200000 -r 48000 - | aplay -r 48000 -f S16_LE

# -f 89.1M : 89.1 MHz 수신 (지역 FM 방송 주파수)
# -M wbfm  : Wide-band FM 복조 방식
# -s 200000: 샘플레이트 200kHz
# -r 48000 : 오디오 출력 샘플레이트 48kHz
# | aplay   : 결과를 스피커로 출력
```

### 3단계: IQ 샘플 캡처

```bash
# 433MHz 대역 원시 IQ 데이터 캡처 (5초간)
rtl_sdr -f 433.92M -s 2000000 -n 10000000 capture.bin

# -f 433.92M : 433.92 MHz 중심 주파수
# -s 2000000 : 샘플레이트 2MHz (초당 2,000,000 샘플)
# -n 10000000: 캡처할 샘플 수 (5초 = 10,000,000 / 2,000,000)
# capture.bin: 저장 파일명

# 파일 크기 확인 (10,000,000 샘플 × 2바이트 = ~20MB)
ls -lh capture.bin
```

### 4단계: 스펙트럼 분석

```bash
# 430~440MHz 범위를 25kHz 간격으로 전력 스캔
# 1번 스캔 후 종료 (-1 플래그)
rtl_power -f 430M:440M:25k -g 50 -i 1 -1 power.csv

# -f 430M:440M:25k : 430~440MHz를 25kHz 간격으로
# -g 50           : 게인 50 (신호 증폭)
# -i 1            : 1초 간격으로 측정
# -1              : 1번만 실행

# CSV 결과 확인
cat power.csv | head -5
```

### 5단계: SDR++ GUI로 시각 분석

```
SDR++를 열면:
  위 화면(Waterfall): 시간에 따른 주파수별 신호 강도
    빨강/노랑 = 강한 신호
    파랑/검정 = 약하거나 없는 신호
  아래 화면(Spectrum): 현재 주파수별 신호 강도 그래프

433.92 MHz로 이동하면:
  리모컨 버튼을 누를 때마다 Waterfall에 줄이 생김
  → 이것이 리모컨 신호다
```

---

## 433MHz/915MHz 리플레이 공격

### 차고문과 자동차 키 — 정적 코드 vs 롤링 코드

**정적 코드 (Static Code) — 취약한 방식**

```
오래된 차고문 열림장치:
  리모컨을 누를 때마다 항상 같은 코드를 전송
  
  예: 버튼 누름 → 전송 → "10110011 00101100 11001010"
      버튼 누름 → 전송 → "10110011 00101100 11001010"  (동일!)
      버튼 누름 → 전송 → "10110011 00101100 11001010"  (동일!)

리플레이 공격:
  1. 공격자가 이 신호를 한 번 캡처
  2. 나중에 같은 신호를 다시 전송
  3. 차고문이 열림
  
현황: 오래된 433MHz 도어락, 리모컨, 차고문 열림장치에 여전히 존재
```

**롤링 코드 (Rolling Code / Hopping Code) — 강화된 방식**

```
현대 자동차 키, 보안 차고문:
  매번 다른 코드를 생성
  
  버튼 누름 1 → "A3F2B1C9"
  버튼 누름 2 → "7D4E8A3F"  (완전히 다름)
  버튼 누름 3 → "9B2C5E71"  (매번 다름)

작동 원리 (KeeLoq):
  리모컨과 수신기가 동일한 비밀 키 공유
  버튼을 누를 때마다 카운터를 1 증가
  카운터 + 비밀 키를 암호화해서 코드 생성
  수신기는 같은 계산을 해서 코드가 맞는지 확인
  이전 코드는 다시 사용 불가 (이미 사용된 카운터)

KeeLoq 기본 취약점:
  - 2008년: 비밀 키를 2^{32} 계산으로 크래킹 가능
  - 같은 키를 사용하는 제조사의 모든 차에 영향
  - 최신 구현은 개선되었지만 오래된 차는 여전히 취약
```

**리플레이 공격 흐름 다이어그램:**

```
[정적 코드 리플레이 공격]

  1. 정상 상황:
     차주 ──[버튼]──> 리모컨 ──(코드: A1B2)──> 수신기 ──> 문 열림

  2. 공격자 캡처:
     차주 ──[버튼]──> 리모컨 ──(코드: A1B2)──> 수신기
                                      ↓
                               공격자(SDR) 캡처

  3. 공격자 재전송 (나중에):
     공격자 ──(코드: A1B2)──> 수신기 ──> 문 열림 ← 취약점!

[롤링 코드의 방어]

  1. 차주 버튼 1회:
     리모컨 ──(코드: A1B2, 카운터:42)──> 수신기 ──> 문 열림
                                                수신기: 카운터 42 기록

  2. 공격자 재전송 시도:
     공격자 ──(코드: A1B2, 카운터:42)──> 수신기
     수신기: "카운터 42는 이미 사용됨" → 거부!

  3. 차주 버튼 2회:
     리모컨 ──(코드: D5E6, 카운터:43)──> 수신기 ──> 문 열림
```

### 도어락, 차고문, 리모컨 공격 실습

```bash
# rfcat으로 신호 캡처 (YARD Stick One 장치 필요)
rfcat -r   # 인터랙티브 셸 진입

# rfcat 내에서 수신 설정:
d.setFreq(433920000)          # 433.92MHz 설정
d.setMdmModulation(MOD_ASK_OOK)  # OOK 변조 방식 설정
d.setMdmDRate(4800)           # 데이터 레이트 4800bps
d.RFrecv()                    # 수신 시작 (리모컨 버튼 누르면 데이터 수신)

# 신호 재전송 (리플레이)
# 위에서 캡처한 data를 그대로 전송
d.RFxmit(data)
```

### URH로 프로토콜 분석

```bash
# URH 실행 (GUI 모드)
urh

# 커맨드라인으로 캡처 + 분석
urh -f 433.92e6 -s 2e6 --capture 5 -o capture.complex

# 캡처된 파일 분석 (자동 비트 경계 감지)
urh capture.complex

# URH에서 할 수 있는 것:
#   1. 자동 변조 방식 감지 (OOK? FSK? ASK?)
#   2. 비트 경계 자동 감지
#   3. 프로토콜 구조 파악 (프리앰블, 페이로드, 체크섬)
#   4. 두 신호 비교 (정적 코드인지 확인)
```

### Python + rtl-sdr 스펙트럼 스캐너

```python
#!/usr/bin/env python3
"""
RF Spectrum Scanner — 특정 대역 신호 탐지 도구.

RTL-SDR 하드웨어를 사용해 무선 신호를 캡처하고 분석한다.
IQ 샘플을 수집해 신호 세기(dBm)를 계산하고 임계값 초과 시 알림을 출력한다.

사용 예시:
  python3 rf_scanner.py --freq 433.92 --monitor
  python3 rf_scanner.py --scan 433.0 433.5 434.0 868.0 915.0
  python3 rf_scanner.py --freq 433.92 --capture 5 --output capture.bin

RTL-SDR 하드웨어가 없으면 실행은 가능하지만 rtl_sdr 명령이 실패한다.
"""

import argparse
import math
import struct
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path


def capture_samples(
    freq_hz: float,
    sample_rate: int,
    duration_sec: float,
    gain: int = 40,
) -> bytes:
    """
    RTL-SDR에서 IQ 샘플을 캡처해 반환.

    Args:
        freq_hz:     중심 주파수 (Hz 단위, 예: 433_920_000)
        sample_rate: 샘플레이트 (초당 샘플 수, 예: 2_000_000)
        duration_sec: 캡처 시간 (초)
        gain:        RF 게인 (0~49, 높을수록 멀리서 오는 신호 감지)

    Returns:
        IQ 샘플 바이트 데이터 (I, Q 교대로 저장된 unsigned 8-bit 값)
    """
    num_samples = int(sample_rate * duration_sec)
    cmd = [
        "rtl_sdr",
        "-f", str(int(freq_hz)),      # 중심 주파수
        "-s", str(sample_rate),        # 샘플레이트
        "-g", str(gain),               # 게인
        "-n", str(num_samples),        # 캡처할 샘플 수
        "-",                           # 표준 출력으로 내보냄
    ]
    result = subprocess.run(cmd, capture_output=True, timeout=duration_sec + 5)
    return result.stdout


def compute_power_db(samples: bytes) -> float:
    """
    IQ 샘플에서 신호 세기(dB) 계산.

    RTL-SDR은 IQ 샘플을 unsigned 8-bit로 저장한다.
    실제 값으로 변환하려면 128을 빼야 한다 (범위: -128 ~ +127).
    신호 세기 = 10 * log10(평균(I² + Q²))

    Args:
        samples: capture_samples()에서 반환된 IQ 바이트 데이터

    Returns:
        신호 세기 (dB, 높을수록 강한 신호)
    """
    if len(samples) < 2:
        return -100.0

    values = list(samples)

    # RTL-SDR IQ 포맷: I와 Q가 번갈아 저장됨
    # samples[0] = I[0], samples[1] = Q[0], samples[2] = I[1], ...
    i_vals = [v - 128 for v in values[0::2]]  # 홀수 인덱스: I 값
    q_vals = [v - 128 for v in values[1::2]]  # 짝수 인덱스: Q 값

    # 평균 전력 = mean(I² + Q²)
    power = sum(i**2 + q**2 for i, q in zip(i_vals, q_vals))
    avg_power = power / max(len(i_vals), 1)

    # dB 변환: 10 * log10(power)
    return 10 * math.log10(avg_power + 1e-10)


def scan_frequencies(
    frequencies_mhz: list[float],
    sample_rate: int = 2_000_000,
    duration: float = 0.5,
) -> dict[float, float]:
    """
    여러 주파수를 병렬로 스캔해 각각의 신호 세기를 반환.

    최대 3개 주파수를 동시에 측정해 시간을 절약한다.

    Args:
        frequencies_mhz: 스캔할 주파수 목록 (MHz 단위)
        sample_rate:     각 주파수의 샘플레이트
        duration:        각 주파수 측정 시간 (초)

    Returns:
        {주파수(MHz): 신호세기(dB)} 딕셔너리
    """
    results: dict[float, float] = {}

    def measure(freq: float) -> tuple[float, float]:
        """단일 주파수 측정."""
        samples = capture_samples(freq * 1e6, sample_rate, duration)
        power = compute_power_db(samples)
        return freq, power

    # ThreadPoolExecutor로 최대 3개 주파수 동시 측정
    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = {executor.submit(measure, f): f for f in frequencies_mhz}
        for future in futures:
            freq, power = future.result()
            results[freq] = power

    return results


def monitor_frequency(
    freq_mhz: float,
    threshold_db: float = 30.0,
    sample_rate: int = 2_000_000,
) -> None:
    """
    단일 주파수를 실시간으로 모니터링. 신호가 임계값을 초과하면 알림 출력.

    먼저 1초간 기저 노이즈를 측정한 후, 이보다 threshold_db dB 이상
    높은 신호가 감지되면 "신호 탐지!" 메시지를 출력한다.

    실용적 용도:
      - 리모컨 버튼이 언제 눌리는지 탐지
      - 특정 주파수의 신호 활동 모니터링
      - 도청 탐지 (비정상 RF 방출)

    Args:
        freq_mhz:     모니터링할 주파수 (MHz)
        threshold_db: 기저 노이즈 대비 탐지 임계값 (dB)
        sample_rate:  샘플레이트
    """
    print(f"[*] {freq_mhz}MHz 모니터링 시작 (임계값: {threshold_db}dB)")
    print("[*] Ctrl+C로 중지")

    # 기저 노이즈 측정 (정상적인 배경 잡음 수준)
    baseline_samples = capture_samples(freq_mhz * 1e6, sample_rate, 1.0)
    baseline_power = compute_power_db(baseline_samples)
    print(f"[*] 기저 노이즈: {baseline_power:.1f}dB")

    try:
        while True:
            samples = capture_samples(freq_mhz * 1e6, sample_rate, 0.2)
            power = compute_power_db(samples)
            delta = power - baseline_power

            if delta > threshold_db:
                timestamp = time.strftime("%H:%M:%S")
                print(f"[!] {timestamp} — 신호 탐지! {power:.1f}dB (+{delta:.1f}dB)")
            else:
                # 같은 줄 덮어쓰기로 화면 깔끔하게 유지
                print(f"\r[*] {power:.1f}dB ({delta:+.1f}dB)", end="", flush=True)

            time.sleep(0.1)
    except KeyboardInterrupt:
        print("\n[*] 모니터링 중지")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="RF Spectrum Scanner (RTL-SDR 필요)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
사용 예시:
  python3 rf_scanner.py --freq 433.92 --monitor
  python3 rf_scanner.py --scan 433.0 433.5 434.0 868.0 915.0
  python3 rf_scanner.py --freq 433.92 --capture 5 --output capture.bin
        """,
    )
    parser.add_argument("--freq", type=float, help="중심 주파수 (MHz)")
    parser.add_argument("--scan", nargs="+", type=float, help="스캔할 주파수 목록 (MHz)")
    parser.add_argument("--monitor", action="store_true", help="실시간 모니터링")
    parser.add_argument("--capture", type=float, help="캡처 시간 (초)")
    parser.add_argument("--output", type=Path, help="캡처 파일 저장 경로")
    parser.add_argument("--threshold", type=float, default=20.0, help="탐지 임계값 (dB, 기본:20)")
    parser.add_argument("--sample-rate", type=int, default=2_000_000, help="샘플레이트 (기본:2MHz)")

    args = parser.parse_args()

    if args.scan:
        print(f"[*] {len(args.scan)}개 주파수 스캔 중...")
        results = scan_frequencies(args.scan, args.sample_rate)
        print("\n주파수별 신호 세기:")
        for freq in sorted(results):
            power = results[freq]
            bar = "█" * int(max(0, power) / 5)
            print(f"  {freq:8.3f} MHz: {power:6.1f} dB  {bar}")
    elif args.freq and args.monitor:
        monitor_frequency(args.freq, args.threshold, args.sample_rate)
    elif args.freq and args.capture:
        samples = capture_samples(
            args.freq * 1e6, args.sample_rate, args.capture
        )
        if args.output:
            args.output.write_bytes(samples)
            print(f"[+] 캡처 완료: {len(samples)} bytes → {args.output}")
        else:
            print(f"[+] 캡처: {len(samples)} bytes")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
```

---

## Zigbee 프로토콜 구조

### Zigbee란?

Zigbee는 **저전력·저비용 IoT 장치**를 위한 무선 프로토콜이다. 스마트 전구, 온도 센서, 스마트 도어락 등에 널리 사용된다.

### Zigbee 네트워크 토폴로지 (ASCII 다이어그램)

```
PAN ID: 0x1234  (네트워크 식별자 — 여러 Zigbee 네트워크 구분)
채널: 11~26 (2.4GHz 대역의 16개 채널)

                    [코디네이터 - Coordinator]
                         PAN ID: 0x1234
                         주소: 0x0000
                         역할: 네트워크 생성 및 관리
                        /         |         \
                       /          |          \
              [라우터]         [라우터]      [라우터]
              0x1234          0x5678        0x9ABC
              (신호 중계)     (신호 중계)   (신호 중계)
             /      \             |
            /        \            |
    [엔드 디바이스] [엔드 디바이스] [엔드 디바이스]
    전구 0xAAAA     센서 0xBBBB    잠금 0xCCCC
    (배터리 절약)   (배터리 절약)  (배터리 절약)

역할 설명:
  코디네이터: 네트워크를 처음 만드는 중앙 장치 (보통 허브)
              PAN ID를 할당하고 다른 장치의 참가를 허용
  라우터:     전원이 연결된 장치 (콘센트에 꽂는 스마트플러그 등)
              메시지를 코디네이터까지 중계
  엔드 디바이스: 배터리로 동작, 자주 잠들어 전력 절약
                메시지를 직접 라우팅하지 못함
```

### Zigbee 보안 레이어

```
Zigbee 보안은 두 가지 키를 사용:

  네트워크 키 (Network Key):
    - AES-128 키
    - 네트워크의 모든 장치가 공유
    - 새 장치가 참가할 때 코디네이터가 전송
    
  링크 키 (Link Key):
    - 두 장치 사이의 개인 키
    - 더 강력한 보안

취약점:
  - 많은 기기가 기본 키 사용: 0x00000000 00000000 00000000 00000000
  - 일부 기기가 Trust Center Link Key를 평문으로 전송
  - 페어링(조인) 과정에서 키가 전송 — 이 시점을 캡처하면 네트워크 키 획득
```

### KillerBee 프레임워크

```bash
# 설치
pip install killerbee

# 지원 하드웨어: RZUSBSTICK, ApiMote, ATUSB

# Zigbee 채널 스캔 (채널 11~26 — 2.4GHz 대역의 16개 채널)
# 어떤 채널에서 네트워크가 활동하는지 찾음
zbstumbler -i /dev/ttyUSB0

# 특정 채널에서 패킷 캡처 (채널 11)
zbdump -i /dev/ttyUSB0 -c 11 -w capture.pcap

# 네트워크 키 없이 패킷 구조 분석
zbdecode -r capture.pcap

# 리플레이 공격 (캡처한 패킷을 다시 전송)
# 예: 캡처한 "전구 켜기" 명령을 나중에 다시 전송
zbreplay -r capture.pcap -i /dev/ttyUSB0

# 키 크래킹 (Zigbee 2006/2007 TP-Link 기본 키 시도)
zbkey -r capture.pcap
```

### Wireshark로 Zigbee 분석

```bash
# Zigbee 패킷 캡처 후 Wireshark에서 분석
# Edit → Preferences → Protocols → ZigBee → Security Keys에 키 추가
# 키를 알고 있으면 암호화된 Zigbee 패킷도 복호화해서 볼 수 있음

# tshark로 커맨드라인 분석 (패킷의 출발지, 목적지, 프레임 유형 추출)
tshark -r zigbee.pcap \
  -Y "zbee_nwk" \
  -T fields \
  -e zbee_nwk.src \
  -e zbee_nwk.dst \
  -e zbee_nwk.frame_type
```

---

## Z-Wave 취약점

### Z-Wave 프로토콜 개요

```
주파수: 908.42MHz (미국), 868.42MHz (유럽)
범위: 30m (실내), 100m (실외)
보안 모드:
  - S0: 전송 중 키 교환 (취약) — 2013년 이전 장치
  - S2: ECDH 기반 키 교환 (2017+) — 현재 권장
```

### Z-Wave S0 취약점 — 평이한 설명

S0(Security 0)은 Z-Wave의 첫 번째 보안 계층이다. 설계에 치명적 약점이 있다.

```
S0 키 교환 과정 (취약):

  1. 새 장치가 네트워크에 참가 요청
  2. 코디네이터(허브): "이 임시 키로 통신하자"
     임시 키(Temporary Key): 0x00000000 00000000  ← 모든 S0 장치가 동일!
  3. 임시 키로 암호화해서 실제 네트워크 키 전송
     실제 키가 거의 평문으로 전달되는 것과 같음
  4. 이후 실제 키로 통신

왜 취약한가?
  - 임시 키가 모든 Z-Wave S0 장치에서 동일 (0x00)
  - 페어링 과정을 캡처하면 실제 네트워크 키를 복호화 가능
  - OWL+ 같은 스니퍼로 페어링 트래픽 캡처 후 복호화

S2와의 차이:
  S2는 ECDH(타원곡선 디피-헬만) 키 교환을 사용
  → 임시 키 없이 수학적으로 안전하게 키 합의
  → 페어링 트래픽을 캡처해도 키를 알 수 없음
  → QR 코드나 PIN으로 장치 인증 추가
```

```bash
# z-wave-js 기반 스니핑 (HackRF 필요)
# OWL+: Z-Wave 스니퍼 하드웨어 필요

# S0 네트워크 키는 페어링 시 일반 텍스트로 전송
# 페어링 과정을 캡처하면 네트워크 키 획득 가능

# z-wave-js-server로 로컬 Z-Wave 네트워크 분석
# npm install -g z-wave-js
```

---

## Flipper Zero 상세 활용 가이드

Flipper Zero는 **올인원 휴대용 보안 연구 도구**다. 크기는 스마트폰보다 약간 크고, 가격은 약 $170이다.

### Sub-GHz 기능 (433/868/915MHz 공격)

```
Flipper Zero의 Sub-GHz 메뉴:

1. [주파수 분석 (Frequency Analyzer)]
   - 근처에서 어떤 주파수가 활동하는지 스캔
   - 리모컨이 사용하는 정확한 주파수 찾기
   - 실시간 신호 강도 표시

2. [신호 캡처 (Read RAW)]
   - 리모컨 버튼을 누르면 신호 캡처
   - 내부 메모리에 저장
   - 나중에 재전송 가능

3. [신호 재전송 (Send RAW)]
   - 캡처한 신호를 그대로 재전송
   - 정적 코드 리플레이 공격

4. [신호 분석 (Read)]
   - 알려진 프로토콜 자동 인식
   - CAME, Nice, Chamberlain 등 차고문 프로토콜
   - 분석된 코드 저장 및 재사용

실제 사용 흐름 (차고문 테스트):
   a. Sub-GHz → Frequency Analyzer
   b. 차고문 리모컨 버튼 누름 → 주파수 확인 (보통 433.92MHz)
   c. Sub-GHz → Read RAW → 433.92MHz 설정
   d. 리모컨 버튼 누름 → 신호 캡처 → 저장
   e. Sub-GHz → Saved → 저장된 신호 → Send
   f. 차고문이 열리면 정적 코드 취약점 확인 완료

주의: 자신이 소유하거나 명시적 허가를 받은 장치에만 사용
```

### NFC/RFID 기능

```
Flipper Zero의 NFC 메뉴:

1. [카드 읽기 (Read)]
   - 근처 NFC/RFID 카드 자동 감지
   - MIFARE Classic: 공용 섹터 읽기
   - MIFARE Ultralight: 전체 읽기 가능
   - EM4100: 125kHz 카드 UID 읽기

2. [카드 시뮬레이션 (Emulate)]
   - 읽은 카드를 Flipper Zero가 흉내냄
   - 취약한 RFID 접근통제 시스템 우회

3. [카드 복제 (Clone)]
   - 쓰기 가능한 빈 카드에 복사

MIFARE Classic 취약점:
   - 암호화 알고리즘 Crypto1 취약 (2008년 크래킹)
   - 기본 키 A: 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF
   - 기본 키 B: 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF
   - 많은 오래된 사무실 출입카드가 기본 키 사용
```

### IR (적외선) 기능

```
범위: TV, 에어컨, 프로젝터 등의 IR 리모컨

1. IR 신호 학습: 기존 리모컨의 신호를 복사
2. IR 신호 재전송: TV 끄기, 채널 변경 등
3. 만능 리모컨 데이터베이스: 미리 내장된 TV/에어컨 코드
```

---

## 스마트홈 공격 시나리오

### 시나리오: 스마트 도어락 공격

```
공격 시나리오 (교육 목적):

1. 433MHz 도어락 리모컨 신호 캡처
   도구: RTL-SDR 또는 Flipper Zero
   주파수: 433.92MHz (대부분의 저가 도어락)

2. 신호 분석 (OOK 변조, 2400bps)
   도구: URH 또는 SDR++
   확인: 버튼 누를 때마다 같은 코드? 다른 코드?

3. URH에서 비트 패턴 식별
   - 프리앰블 (동기화 패턴) 찾기
   - 실제 데이터 페이로드 위치 파악
   - 체크섬 위치 파악

4. YARD Stick One 또는 Flipper Zero로 동일 신호 재전송

5. 도어락 열림 확인

방어 방법:
   - 롤링 코드(Hopping Code) 사용 여부 확인
   - 롤링 코드: 매번 다른 코드 (KeeLoq 등) → 리플레이 공격 불가
   - 정적 코드: 항상 같은 코드 → 취약
   - 구매 전 제품 설명서에서 "rolling code" 또는 "hopping code" 확인
```

---

## 실습 환경 구성 — 안전한 홈 랩 설정

### 필요한 하드웨어

```
최소 구성 (약 $30):
  - RTL-SDR v3 USB 동글 (수신 전용)
  - SMA 안테나 (433MHz 대역 안테나 선택)
  용도: 신호 수신, 분석, 모니터링

권장 구성 (약 $200):
  - RTL-SDR v3 (수신)
  - YARD Stick One (송수신, Sub-1GHz)
  - Flipper Zero (올인원)
  용도: 완전한 리플레이 공격 테스트

연구 구성 (약 $500+):
  - HackRF One (1MHz~6GHz 송수신)
  - ApiMote 또는 RZUSBSTICK (Zigbee 분석)
  용도: 모든 프로토콜 공격/분석
```

### 소프트웨어 설치 (Ubuntu/Debian)

```bash
# 기본 패키지 설치
sudo apt update
sudo apt install -y \
  rtl-sdr \           # RTL-SDR 드라이버
  gnuradio \          # 신호 처리 프레임워크
  gqrx-sdr \          # GNU Radio 기반 GUI
  wireshark \         # 패킷 분석기
  python3-pip

# Python 도구
pip3 install urh killerbee

# SDR++ (최신 버전 권장)
# https://github.com/AlexandreRouma/SDRPlusPlus/releases 에서 다운로드

# HackRF 도구 (HackRF One 사용 시)
sudo apt install hackrf

# RTL-SDR blacklist 설정 (기본 드라이버 비활성화)
echo "blacklist dvb_usb_rtl28xxu" | sudo tee /etc/modprobe.d/blacklist-rtl.conf
sudo modprobe -r dvb_usb_rtl28xxu 2>/dev/null || true
```

### 합법적 테스트 대상

```
안전하게 테스트할 수 있는 것:
  1. 자신이 소유한 리모컨, 도어락, 차고문
  2. 직접 구매한 저가 433MHz 장치 (중고 마켓 활용)
  3. SDR로 FM 라디오, ADS-B(항공기 추적) 같은 공개 신호 수신
  4. 자신의 스마트홈 허브에 연결된 자신의 Zigbee 기기

절대 하면 안 되는 것:
  - 타인의 차량, 주택, 사무실 시스템 테스트
  - 허가 없는 RF 신호 전송 (법적 제재 가능)
  - 공공 인프라(교통신호, 의료기기) 주파수 간섭
```

---

## 방어 체크리스트

| 취약점 | 영향 | 방어 방법 |
|--------|------|-----------|
| **433MHz 정적 코드** | 리플레이 공격으로 도어락/차고문 열림 | 롤링 코드(KeeLoq) 또는 암호화 프로토콜 사용 |
| **Zigbee 기본 키** | 네트워크 전체 트래픽 복호화 | 장치 페어링 시 고유 키 생성, 기본 키 변경 |
| **Z-Wave S0** | 페어링 도청으로 네트워크 키 획득 | Z-Wave S2 지원 장치로 교체, S2로 페어링 |
| **미암호화 통신** | 명령어 도청 및 재전송 | AES-128 이상 암호화 필수 |
| **디폴트 키** | 공개된 기본 키로 즉시 침투 | 페어링 시 고유 키 생성, 하드코딩 키 금지 |
| **신호 재밍** | 스마트홈 기능 마비 (DoS) | 재밍 탐지 및 알림, 이중화 통신 경로 |
| **Zigbee 조인 개방** | 허가 없는 장치가 네트워크 참가 | 조인 기간 최소화, 화이트리스트 기반 인증 |
| **OTA 업데이트 무검증** | 펌웨어 변조 공격 | 서명된 펌웨어만 적용, 업데이트 채널 암호화 |

---

<!-- detect-validate-27 -->
## 무선 IoT 프로토콜 공격 탐지와 방어 검증

Zigbee/Z-Wave/RF는 *조인 시 평문 키·리플레이·롤링코드 결함·재밍*을 노린다. 방어자는 **자체 무선 메시가 캡처/리플레이에 견디는가**를 검증해야 한다. 검증은 **소유 장비/주파수**에서만.

### 공격 → 노리는 약점 → 1차 통제(방어자) → 탐지 신호

| 기법 | 노리는 약점 | 1차 통제(방어자) | 탐지 신호 |
|---|---|---|---|
| 키 캡처(조인 시) | 평문 TC 링크키 | 사전설치 키·짧은 조인창 | 조인 중 키 교환 캡처 |
| 리플레이 공격 | 프레임 카운터 부재 | 카운터 검증 | 동일 프레임 재전송 |
| 롤링코드 결함 | 예측 가능 시드 | 강한 PRNG·동기 | 코드 예측 성공 |
| 재밍/디어소 | 가용성 | 채널 호핑·탐지 | 비정상 RSSI/노이즈 |

### 방어 검증 (직접 확인)

```bash
# 1) 자체 메시 캡처로 평문 키 교환/리플레이 표면 점검(소유 장비, killerbee)
zbdump -f 11 -w mesh.pcap 2>/dev/null & sleep 10; kill %1 2>/dev/null; ls -la mesh.pcap
# 2) 동일 프레임 재전송(리플레이) 신호 — 시퀀스 번호 중복
tshark -r mesh.pcap -Y "zbee_nwk" -T fields -e zbee_nwk.seqno 2>/dev/null | sort | uniq -d | head
```

> 무선 IoT 방어는 *캡처/리플레이에 견디는가*다 — "Zigbee 메시 동작한다"와 "조인 시 키가 안 새고 재전송 프레임이 거부된다"는 다르다. 소유 장비에서 키 교환·카운터 중복을 직접 확인한다([[15_WiFi_Hacking]], [[71_Bluetooth_RF_Hacking]], [[13_SOC_Blue_Team]]).

---

<a name="english"></a>

# RF/Zigbee/Z-Wave IoT Wireless Protocol Attacks

---

## Learning Objectives

After completing this lab, you will be able to:

1. **Explain radio frequency basics** — frequency, wavelength, and modulation — in plain language
2. **Understand how SDR works** and set up RTL-SDR hardware
3. **Explain the difference** between static code and rolling code, and how a 433MHz replay attack works
4. **Understand Zigbee network structure** and capture/analyze packets with KillerBee
5. **Explain why Z-Wave S0 is vulnerable** in plain terms
6. **Use Flipper Zero's** key attack features
7. **Apply protocol-specific defenses** concretely

---

## Wireless Communication Basics — For Complete Beginners

### What is Frequency?

Radio waves are invisible waves that travel through the air.

```
Frequency = how many times the wave oscillates per second

Unit: Hz (Hertz)
  1 Hz    = 1 oscillation per second
  1 kHz   = 1,000 oscillations per second  (kilo)
  1 MHz   = 1,000,000 oscillations per second  (mega)
  1 GHz   = 1,000,000,000 oscillations per second  (giga)

Examples:
  FM radio:         88~108 MHz
  433MHz remote:    433.92 MHz
  WiFi:             2.4 GHz or 5 GHz
  Bluetooth:        2.4 GHz
```

**Real-world analogy:** Think of a jump rope. Swing it slowly and you get big slow waves (low frequency). Swing it fast and you get small fast waves (high frequency).

---

### Wavelength and Frequency Relationship

```
Low frequency (lower number) = long wavelength = longer range, good obstacle penetration
High frequency (higher number) = short wavelength = shorter range, can carry more data

Examples:
  433 MHz → wavelength ~69cm → can reach hundreds of meters
  2.4 GHz → wavelength ~12.5cm → tens of meters, passes through walls
  5 GHz   → wavelength ~6cm → faster but shorter range
  60 GHz  → wavelength ~5mm → very fast but barely penetrates walls

IoT security perspective:
  Low frequency (433MHz, 868MHz): wide range — can attack from a distance
  High frequency (2.4GHz WiFi): shorter range but faster throughput
```

---

### Modulation — How Do We Put 0s and 1s Into Radio Waves?

To carry digital data (0s and 1s) over radio waves, you need **modulation**.

**OOK (On-Off Keying) — The light switch method**

```
Represent 1 and 0 by turning the signal On and Off

 1 = signal present  ████
 0 = no signal
              
Time:   ─────────────────────>
Signal: ████    ████████    ████
Bits:    1   0   1  1   0   1

Used by: 433MHz remotes, garage door openers
Pros: Simple, easy to implement
Cons: Weak security (easy to capture and replay)
```

**FSK (Frequency Shift Keying) — The pitch change method**

```
Use two frequencies to represent 0 and 1
  f1 = 433.90 MHz → 0
  f2 = 433.94 MHz → 1

Time:      ─────────────────────>
Frequency: f1  f2  f1  f1  f2  f2
Bits:       0   1   0   0   1   1

Used by: Zigbee, Z-Wave, many ISM-band devices
Pros: More noise-resistant
```

**GFSK (Gaussian FSK) — Smooth frequency shifting**

```
Same as FSK but frequency transitions are gradual instead of abrupt
→ Reduces radio interference

Used by: Bluetooth, Zigbee
```

---

### ISM Bands — Frequency Anyone Can Use Freely

ISM (Industrial, Scientific, Medical) bands are frequency ranges that can be **used without a license**.

```
Key ISM bands:
  433.05~434.79 MHz  → remotes, door locks, weather sensors (Europe/Asia)
  902~928 MHz        → US ISM band (Z-Wave US version)
  868.0~868.6 MHz    → European ISM band (Z-Wave EU version)
  2.400~2.4835 GHz   → WiFi, Bluetooth, Zigbee, microwave ovens

Why it matters:
  - Can receive without a license → legal to monitor with SDR
  - Many IoT devices use ISM bands → large attack surface
  - Devices share the same frequencies → can cause interference
```

---

## IoT Wireless Protocol Comparison

| Protocol | Frequency | Range | Power | Data Rate | Security | Use Cases |
|----------|-----------|-------|-------|-----------|----------|-----------|
| **433MHz** | 433.92MHz | 50~300m | Low | 1~10kbps | None/Weak | Remotes, doorbells, weather sensors |
| **Z-Wave** | 908/868MHz | 30~100m | Very low | 9.6~100kbps | S0(weak)/S2(strong) | Smart home automation |
| **Zigbee** | 2.4GHz | 10~100m | Very low | 250kbps | AES-128 | Smart lighting, sensors |
| **Bluetooth** | 2.4GHz | 10~100m | Low | 1~3Mbps | AES-128 | Wearables, audio |
| **WiFi** | 2.4/5GHz | 50~100m | High | Hundreds Mbps | WPA2/3 | Smart TVs, cameras |
| **LoRa** | 433/868/915MHz | 1~15km | Very low | 0.3~50kbps | AES-128 | Agriculture, smart city |
| **Thread** | 2.4GHz | 10~100m | Very low | 250kbps | AES-128 + TLS | Matter devices |

**Security key takeaways:**
- 433MHz: No encryption → easiest attack target
- Z-Wave S0: Key exchange vulnerability → can attack during pairing
- Zigbee: Default key issues → vulnerable if misconfigured
- LoRa: Low bandwidth → replay attack potential

---

## SDR (Software Defined Radio) Overview

### What is SDR?

Traditional radio receivers use **fixed hardware circuits** for specific frequencies and modulation types. SDR **replaces those circuits with software**.

```
Traditional radio:
  Antenna → [Hardware filter] → [Hardware demodulator] → Audio
  (only receives one frequency; cannot change)

SDR:
  Antenna → [ADC converter] → Computer software → Any processing desired
  (change the software to handle different frequencies/modulation)
```

**Why does it matter for security researchers?**
- One SDR device can analyze 433MHz remotes, 900MHz Z-Wave, and 2.4GHz Zigbee
- Switch protocols just by changing software
- Can decode novel unknown protocols from scratch

---

### IQ Sampling — The Core Principle of SDR

SDR represents signals as **IQ samples (In-phase/Quadrature)**.

```
I (In-phase):  the "real" component of the signal
Q (Quadrature): the "imaginary" component (90 degrees out of phase with I)

Analogy: a clock with hour and minute hands
  Hour hand (I): reference at 12 o'clock
  Minute hand (Q): reference at 3 o'clock (90 degree offset)
  Knowing both values tells you exactly what time it is (= signal phase)

RTL-SDR IQ data format:
  Stored as unsigned 8-bit integers
  I: 0~255 (actual value = raw value - 128, i.e., -128~+127)
  Q: 0~255
  One sample = 2 bytes (1 byte I + 1 byte Q)
  Frequency-analyzing IQ data reveals what signals are present
```

**Software radio vs hardware radio:**

| Item | Hardware Radio | SDR |
|------|---------------|-----|
| Supported frequencies | Fixed | Changeable via software |
| Modulation types | Only built-in ones | Add via software |
| Cost | Buy per protocol | One device covers all |
| Flexibility | Low | Very high |
| Performance | Optimized | Slightly lower |

---

### Key SDR Hardware

| Device | Frequency Range | Price | Use Case |
|--------|----------------|-------|----------|
| RTL-SDR v3 | 500kHz~1.75GHz | ~$30 | Beginner, receive only |
| HackRF One | 1MHz~6GHz | ~$300 | Transmit and receive |
| YARD Stick One | Sub-1GHz | ~$100 | 433/868/915MHz dedicated |
| USRP B210 | 70MHz~6GHz | ~$1,500 | Research-grade high performance |
| Flipper Zero | Sub-1GHz + NFC | ~$170 | All-in-one security tool |

---

### SDR Software

```bash
# GNU Radio (signal processing framework — connect blocks to build processing pipelines)
sudo apt install gnuradio

# RTL-SDR drivers
sudo apt install rtl-sdr

# SDR++ (GUI spectrum analyzer — real-time frequency visualization)
# https://github.com/AlexandreRouma/SDRPlusPlus

# GQRX (GNU Radio-based GUI — beginner-friendly interface)
sudo apt install gqrx-sdr

# URH (Universal Radio Hacker) — most powerful protocol analysis tool
pip install urh
```

---

## RTL-SDR Practical Setup Guide — Step by Step

### Step 1: Verify Hardware Connection

```bash
# After connecting RTL-SDR USB dongle to computer:

# Check device detection
rtl_test -t

# Expected output:
# Found 1 device(s):
#   0:  Realtek, RTL2838UHIDIR, SN: 00000001
# Using device 0: Generic RTL2832U OEM
# Found Rafael Micro R820T tuner

# If it fails, install drivers:
sudo apt install rtl-sdr librtlsdr-dev
# Add udev rules (USB permissions):
sudo cp /usr/lib/udev/rules.d/rtl-sdr.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules && sudo udevadm trigger
# Re-login and try again
```

### Step 2: First Reception Test — FM Radio

```bash
# Receive FM radio (enter a local FM frequency)
# If this succeeds, your RTL-SDR is working correctly
rtl_fm -f 89.1M -M wbfm -s 200000 -r 48000 - | aplay -r 48000 -f S16_LE

# -f 89.1M  : tune to 89.1 MHz (replace with a local FM station)
# -M wbfm   : wide-band FM demodulation
# -s 200000 : sample rate 200kHz
# -r 48000  : audio output sample rate 48kHz
# | aplay   : pipe output to speakers
```

### Step 3: Capture IQ Samples

```bash
# Capture raw IQ data from 433MHz band (5 seconds)
rtl_sdr -f 433.92M -s 2000000 -n 10000000 capture.bin

# -f 433.92M  : center frequency 433.92 MHz
# -s 2000000  : sample rate 2 MHz (2,000,000 samples/second)
# -n 10000000 : number of samples (5s = 10,000,000 / 2,000,000)
# capture.bin : output filename

# Check file size (~20 MB for 10,000,000 samples × 2 bytes)
ls -lh capture.bin
```

### Step 4: Spectrum Analysis

```bash
# Scan 430~440 MHz at 25 kHz intervals, one pass
rtl_power -f 430M:440M:25k -g 50 -i 1 -1 power.csv

# -f 430M:440M:25k : scan 430~440 MHz at 25 kHz steps
# -g 50            : gain 50 (signal amplification)
# -i 1             : measure every 1 second
# -1               : run only once

# Check CSV output
head -5 power.csv
```

### Step 5: Visual Analysis with SDR++

```
When you open SDR++:
  Top panel (Waterfall): signal strength per frequency over time
    Red/yellow = strong signal
    Blue/black = weak or no signal
  Bottom panel (Spectrum): current signal strength graph per frequency

Navigate to 433.92 MHz:
  Each press of a remote button creates a horizontal streak in the Waterfall
  → That streak IS the remote's signal
```

---

## 433MHz/915MHz Replay Attacks

### Garage Doors and Car Key Fobs — Static Code vs Rolling Code

**Static Code — The vulnerable approach**

```
Old garage door openers:
  The same code is transmitted every time the button is pressed

  Button press → transmit → "10110011 00101100 11001010"
  Button press → transmit → "10110011 00101100 11001010"  (identical!)
  Button press → transmit → "10110011 00101100 11001010"  (identical!)

Replay attack:
  1. Attacker captures the signal once
  2. Replays the same signal later
  3. Garage door opens

Current state: still found in older 433MHz door locks, remotes, garage openers
```

**Rolling Code — The stronger approach**

```
Modern car key fobs, secure garage doors:
  A different code is generated each time

  Button press 1 → "A3F2B1C9"
  Button press 2 → "7D4E8A3F"  (completely different)
  Button press 3 → "9B2C5E71"  (changes every time)

How it works (KeeLoq):
  Remote and receiver share the same secret key
  Each button press increments a counter by 1
  Code = encrypt(counter + secret key)
  Receiver performs the same calculation to verify the code
  Previously used codes cannot be reused (counter already consumed)

KeeLoq fundamental vulnerabilities:
  - 2008: Secret key crackable with 2^{32} computations
  - Affected all cars from manufacturers using the same key
  - Newer implementations are improved, but old cars remain vulnerable
```

**Replay Attack Flow Diagram:**

```
[Static code replay attack]

  1. Normal operation:
     Owner ──[button]──> Remote ──(code: A1B2)──> Receiver ──> Door opens

  2. Attacker captures:
     Owner ──[button]──> Remote ──(code: A1B2)──> Receiver
                                        ↓
                                Attacker (SDR) captures

  3. Attacker replays (later):
     Attacker ──(code: A1B2)──> Receiver ──> Door opens ← Vulnerability!

[Rolling code defense]

  1. Owner presses button once:
     Remote ──(code: A1B2, counter:42)──> Receiver ──> Door opens
                                                  Receiver records counter 42

  2. Attacker attempts replay:
     Attacker ──(code: A1B2, counter:42)──> Receiver
     Receiver: "Counter 42 already used" → rejected!

  3. Owner presses button again:
     Remote ──(code: D5E6, counter:43)──> Receiver ──> Door opens
```

### Practical Attack on Door Locks and Remotes

```bash
# Capture signal with rfcat (requires YARD Stick One hardware)
rfcat -r   # enter interactive shell

# Inside rfcat shell, configure reception:
d.setFreq(433920000)           # set to 433.92 MHz
d.setMdmModulation(MOD_ASK_OOK)  # set OOK modulation
d.setMdmDRate(4800)            # data rate 4800 bps
d.RFrecv()                     # start receiving (press remote button)

# Replay the signal
# Transmit the captured data back
d.RFxmit(data)
```

### Protocol Analysis with URH

```bash
# Launch URH (GUI mode)
urh

# Command-line capture and analysis
urh -f 433.92e6 -s 2e6 --capture 5 -o capture.complex

# Analyze captured file (auto bit-boundary detection)
urh capture.complex

# What URH can do:
#   1. Auto-detect modulation type (OOK? FSK? ASK?)
#   2. Auto-detect bit boundaries
#   3. Identify protocol structure (preamble, payload, checksum)
#   4. Compare two signals (check if static code)
```

### Python + rtl-sdr Spectrum Scanner

```python
#!/usr/bin/env python3
"""
RF Spectrum Scanner — signal detection tool for specific frequency bands.

Uses RTL-SDR hardware to capture and analyze radio signals.
Collects IQ samples, calculates signal strength (dBm), and prints
an alert when the threshold is exceeded.

Usage:
  python3 rf_scanner.py --freq 433.92 --monitor
  python3 rf_scanner.py --scan 433.0 433.5 434.0 868.0 915.0
  python3 rf_scanner.py --freq 433.92 --capture 5 --output capture.bin

Without RTL-SDR hardware the script runs but the rtl_sdr command will fail.
"""

import argparse
import math
import struct
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path


def capture_samples(
    freq_hz: float,
    sample_rate: int,
    duration_sec: float,
    gain: int = 40,
) -> bytes:
    """
    Capture IQ samples from RTL-SDR and return them.

    Args:
        freq_hz:      Center frequency in Hz (e.g. 433_920_000)
        sample_rate:  Samples per second (e.g. 2_000_000)
        duration_sec: How long to capture (seconds)
        gain:         RF gain (0~49; higher = detect weaker/farther signals)

    Returns:
        IQ sample bytes (alternating unsigned 8-bit I and Q values)
    """
    num_samples = int(sample_rate * duration_sec)
    cmd = [
        "rtl_sdr",
        "-f", str(int(freq_hz)),
        "-s", str(sample_rate),
        "-g", str(gain),
        "-n", str(num_samples),
        "-",           # write to stdout
    ]
    result = subprocess.run(cmd, capture_output=True, timeout=duration_sec + 5)
    return result.stdout


def compute_power_db(samples: bytes) -> float:
    """
    Compute signal strength (dB) from IQ samples.

    RTL-SDR stores IQ samples as unsigned 8-bit integers.
    Subtract 128 to convert to signed values (range: -128 to +127).
    Signal power = 10 * log10(mean(I^2 + Q^2))

    Args:
        samples: IQ byte data returned by capture_samples()

    Returns:
        Signal strength in dB (higher = stronger signal)
    """
    if len(samples) < 2:
        return -100.0

    values = list(samples)

    # RTL-SDR IQ format: I and Q values alternate
    # samples[0]=I[0], samples[1]=Q[0], samples[2]=I[1], ...
    i_vals = [v - 128 for v in values[0::2]]   # even indices: I values
    q_vals = [v - 128 for v in values[1::2]]   # odd indices: Q values

    # Average power = mean(I^2 + Q^2)
    power = sum(i**2 + q**2 for i, q in zip(i_vals, q_vals))
    avg_power = power / max(len(i_vals), 1)

    # Convert to dB: 10 * log10(power)
    return 10 * math.log10(avg_power + 1e-10)


def scan_frequencies(
    frequencies_mhz: list[float],
    sample_rate: int = 2_000_000,
    duration: float = 0.5,
) -> dict[float, float]:
    """
    Scan multiple frequencies in parallel and return signal strength for each.

    Measures up to 3 frequencies simultaneously to save time.

    Args:
        frequencies_mhz: List of frequencies to scan (in MHz)
        sample_rate:     Sample rate for each frequency
        duration:        Measurement duration per frequency (seconds)

    Returns:
        Dictionary of {frequency_mhz: signal_strength_db}
    """
    results: dict[float, float] = {}

    def measure(freq: float) -> tuple[float, float]:
        """Measure a single frequency."""
        samples = capture_samples(freq * 1e6, sample_rate, duration)
        power = compute_power_db(samples)
        return freq, power

    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = {executor.submit(measure, f): f for f in frequencies_mhz}
        for future in futures:
            freq, power = future.result()
            results[freq] = power

    return results


def monitor_frequency(
    freq_mhz: float,
    threshold_db: float = 30.0,
    sample_rate: int = 2_000_000,
) -> None:
    """
    Monitor a single frequency in real time; print an alert when signal exceeds threshold.

    First measures baseline noise for 1 second, then alerts whenever the
    signal is more than threshold_db above the baseline.

    Practical uses:
      - Detect when a remote control button is pressed
      - Monitor signal activity on a specific frequency
      - Detect unusual RF emissions (bug detection)

    Args:
        freq_mhz:     Frequency to monitor (MHz)
        threshold_db: Detection threshold above baseline noise (dB)
        sample_rate:  Sample rate
    """
    print(f"[*] Monitoring {freq_mhz} MHz (threshold: {threshold_db} dB above baseline)")
    print("[*] Press Ctrl+C to stop")

    # Measure baseline noise (normal background noise level)
    baseline_samples = capture_samples(freq_mhz * 1e6, sample_rate, 1.0)
    baseline_power = compute_power_db(baseline_samples)
    print(f"[*] Baseline noise: {baseline_power:.1f} dB")

    try:
        while True:
            samples = capture_samples(freq_mhz * 1e6, sample_rate, 0.2)
            power = compute_power_db(samples)
            delta = power - baseline_power

            if delta > threshold_db:
                timestamp = time.strftime("%H:%M:%S")
                print(f"[!] {timestamp} — Signal detected! {power:.1f} dB (+{delta:.1f} dB)")
            else:
                print(f"\r[*] {power:.1f} dB ({delta:+.1f} dB)", end="", flush=True)

            time.sleep(0.1)
    except KeyboardInterrupt:
        print("\n[*] Monitoring stopped")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="RF Spectrum Scanner (requires RTL-SDR hardware)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Usage examples:
  python3 rf_scanner.py --freq 433.92 --monitor
  python3 rf_scanner.py --scan 433.0 433.5 434.0 868.0 915.0
  python3 rf_scanner.py --freq 433.92 --capture 5 --output capture.bin
        """,
    )
    parser.add_argument("--freq", type=float, help="Center frequency (MHz)")
    parser.add_argument("--scan", nargs="+", type=float, help="Frequencies to scan (MHz)")
    parser.add_argument("--monitor", action="store_true", help="Real-time monitoring mode")
    parser.add_argument("--capture", type=float, help="Capture duration (seconds)")
    parser.add_argument("--output", type=Path, help="Path to save captured samples")
    parser.add_argument("--threshold", type=float, default=20.0,
                        help="Detection threshold in dB above baseline (default: 20)")
    parser.add_argument("--sample-rate", type=int, default=2_000_000,
                        help="Sample rate in Hz (default: 2,000,000)")

    args = parser.parse_args()

    if args.scan:
        print(f"[*] Scanning {len(args.scan)} frequencies...")
        results = scan_frequencies(args.scan, args.sample_rate)
        print("\nSignal strength by frequency:")
        for freq in sorted(results):
            power = results[freq]
            bar = "█" * int(max(0, power) / 5)
            print(f"  {freq:8.3f} MHz: {power:6.1f} dB  {bar}")
    elif args.freq and args.monitor:
        monitor_frequency(args.freq, args.threshold, args.sample_rate)
    elif args.freq and args.capture:
        samples = capture_samples(
            args.freq * 1e6, args.sample_rate, args.capture
        )
        if args.output:
            args.output.write_bytes(samples)
            print(f"[+] Capture complete: {len(samples)} bytes → {args.output}")
        else:
            print(f"[+] Captured: {len(samples)} bytes")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
```

---

## Zigbee Protocol Structure

### What is Zigbee?

Zigbee is a wireless protocol for **low-power, low-cost IoT devices** — smart bulbs, temperature sensors, smart door locks, and more.

### Zigbee Network Topology (ASCII Diagram)

```
PAN ID: 0x1234  (network identifier — distinguishes multiple Zigbee networks)
Channel: 11~26 (16 channels in the 2.4 GHz band)

                     [Coordinator]
                      PAN ID: 0x1234
                      Address: 0x0000
                      Role: Creates and manages the network
                     /         |         \
                    /          |          \
             [Router]       [Router]     [Router]
             0x1234         0x5678       0x9ABC
             (relay)        (relay)      (relay)
            /      \             |
           /        \            |
   [End Device]  [End Device]  [End Device]
   Bulb 0xAAAA   Sensor 0xBBBB  Lock 0xCCCC
   (battery saver)(battery saver)(battery saver)

Role explanation:
  Coordinator: central device that creates the network (usually the hub)
               Assigns PAN ID and permits other devices to join
  Router:      mains-powered device (smart plug, etc.)
               Relays messages toward the coordinator
  End Device:  battery-powered, sleeps frequently to conserve power
               Cannot independently route messages
```

### Zigbee Security Layers

```
Zigbee security uses two types of keys:

  Network Key:
    - AES-128 key
    - Shared by all devices on the network
    - Sent by the coordinator when a new device joins

  Link Key:
    - Private key between two specific devices
    - Stronger security

Vulnerabilities:
  - Many devices use the default key: 0x00000000 00000000 00000000 00000000
  - Some devices send Trust Center Link Key in plaintext
  - Key is transmitted during the join (pairing) process —
    capturing this moment gives the attacker the network key
```

### KillerBee Framework

```bash
# Install
pip install killerbee

# Supported hardware: RZUSBSTICK, ApiMote, ATUSB

# Scan Zigbee channels (11~26 — 16 channels in the 2.4 GHz band)
# Finds which channels have active networks
zbstumbler -i /dev/ttyUSB0

# Capture packets on channel 11
zbdump -i /dev/ttyUSB0 -c 11 -w capture.pcap

# Analyze packet structure without the network key
zbdecode -r capture.pcap

# Replay attack (retransmit captured packets)
# e.g., replay a captured "turn bulb on" command
zbreplay -r capture.pcap -i /dev/ttyUSB0

# Key cracking (try TP-Link default Zigbee 2006/2007 key)
zbkey -r capture.pcap
```

### Wireshark Zigbee Analysis

```bash
# After capturing Zigbee packets, analyze in Wireshark
# Edit → Preferences → Protocols → ZigBee → Security Keys → add your key
# If you know the key, you can decrypt encrypted Zigbee packets

# Command-line analysis with tshark (extract source, destination, frame type)
tshark -r zigbee.pcap \
  -Y "zbee_nwk" \
  -T fields \
  -e zbee_nwk.src \
  -e zbee_nwk.dst \
  -e zbee_nwk.frame_type
```

---

## Z-Wave Vulnerabilities

### Z-Wave Protocol Overview

```
Frequency: 908.42 MHz (USA), 868.42 MHz (Europe)
Range: 30m (indoor), 100m (outdoor)
Security modes:
  - S0: key exchange during transmission (vulnerable) — devices before 2013
  - S2: ECDH-based key exchange (2017+) — currently recommended
```

### Z-Wave S0 Vulnerability — Plain Language Explanation

S0 (Security 0) was Z-Wave's first security layer. It has a fatal design flaw.

```
S0 key exchange process (vulnerable):

  1. New device requests to join the network
  2. Coordinator (hub): "Let's communicate with this temporary key"
     Temporary key: 0x00000000 00000000  ← SAME for ALL S0 devices!
  3. The actual network key is sent encrypted with this temporary key
     This is effectively the same as sending the key in plaintext
  4. Subsequent communication uses the actual key

Why is it vulnerable?
  - The temporary key is identical across all Z-Wave S0 devices (all zeros)
  - Capture the pairing traffic → decrypt and recover the actual network key
  - Sniffers like OWL+ can capture pairing traffic and decrypt it

Difference with S2:
  S2 uses ECDH (Elliptic Curve Diffie-Hellman) key exchange
  → Keys are agreed upon mathematically without a fixed temporary key
  → Capturing pairing traffic does NOT reveal the key
  → QR code or PIN adds additional device authentication
```

```bash
# z-wave-js based sniffing (requires HackRF)
# OWL+: dedicated Z-Wave sniffer hardware required

# S0 network key is transmitted in near-plaintext during pairing
# Capturing the pairing process yields the network key

# Analyze local Z-Wave network with z-wave-js-server
# npm install -g z-wave-js
```

---

## Flipper Zero Detailed Guide

Flipper Zero is an **all-in-one portable security research tool** — slightly larger than a smartphone, priced around $170.

### Sub-GHz Features (433/868/915 MHz Attacks)

```
Flipper Zero Sub-GHz menu:

1. [Frequency Analyzer]
   - Scan which frequencies are active nearby
   - Find the exact frequency a remote uses
   - Real-time signal strength display

2. [Read RAW]
   - Captures the signal when a remote button is pressed
   - Stored in internal memory
   - Can be replayed later

3. [Send RAW]
   - Retransmits captured signal as-is
   - Static code replay attack

4. [Read]
   - Auto-recognizes known protocols
   - CAME, Nice, Chamberlain garage door protocols
   - Save and reuse analyzed codes

Real usage flow (garage door test):
   a. Sub-GHz → Frequency Analyzer
   b. Press garage door remote → identify frequency (usually 433.92 MHz)
   c. Sub-GHz → Read RAW → configure for 433.92 MHz
   d. Press remote button → capture signal → save
   e. Sub-GHz → Saved → select saved signal → Send
   f. If the door opens: static code vulnerability confirmed

WARNING: Only use on devices you own or have explicit written permission to test
```

### NFC/RFID Features

```
Flipper Zero NFC menu:

1. [Read]
   - Auto-detect nearby NFC/RFID cards
   - MIFARE Classic: read public sectors
   - MIFARE Ultralight: full read possible
   - EM4100: read 125 kHz card UID

2. [Emulate]
   - Flipper Zero impersonates the read card
   - Bypasses vulnerable RFID access control systems

3. [Clone]
   - Copy to a writable blank card

MIFARE Classic vulnerability:
   - Crypto1 encryption algorithm broken (cracked in 2008)
   - Default key A: 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF
   - Default key B: 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF
   - Many old office access cards still use the default key
```

### IR (Infrared) Features

```
Range: TVs, air conditioners, projectors, etc.

1. IR signal learning: copy signals from an existing remote
2. IR signal replay: turn off TVs, change channels, etc.
3. Universal remote database: pre-loaded TV/AC codes
```

---

## Smart Home Attack Scenario

### Scenario: Smart Door Lock Attack

```
Attack scenario (educational purposes only):

1. Capture the 433 MHz door lock remote signal
   Tool: RTL-SDR or Flipper Zero
   Frequency: 433.92 MHz (most low-cost door locks)

2. Analyze the signal (OOK modulation, 2400 bps)
   Tool: URH or SDR++
   Check: is the same code sent each time the button is pressed?

3. Identify bit pattern in URH
   - Find the preamble (synchronization pattern)
   - Locate the actual data payload
   - Identify checksum location

4. Retransmit the same signal using YARD Stick One or Flipper Zero

5. Confirm door lock opens

Defenses:
   - Check whether rolling code (hopping code) is used
   - Rolling code: different code each time (KeeLoq etc.) → replay fails
   - Static code: same code every time → vulnerable
   - Before buying: check product specs for "rolling code" or "hopping code"
```

---

## Lab Setup — Safe Home Lab Configuration

### Required Hardware

```
Minimum setup (~$30):
  - RTL-SDR v3 USB dongle (receive only)
  - SMA antenna (choose one rated for 433 MHz band)
  Use: signal reception, analysis, monitoring

Recommended setup (~$200):
  - RTL-SDR v3 (receive)
  - YARD Stick One (transmit/receive, Sub-1GHz)
  - Flipper Zero (all-in-one)
  Use: full replay attack testing

Research setup (~$500+):
  - HackRF One (1 MHz~6 GHz transmit/receive)
  - ApiMote or RZUSBSTICK (Zigbee analysis)
  Use: all protocols, attack and analysis
```

### Software Installation (Ubuntu/Debian)

```bash
# Install base packages
sudo apt update
sudo apt install -y \
  rtl-sdr \        # RTL-SDR drivers
  gnuradio \       # signal processing framework
  gqrx-sdr \       # GNU Radio-based GUI
  wireshark \      # packet analyzer
  python3-pip

# Python tools
pip3 install urh killerbee

# SDR++ (latest release recommended)
# Download from https://github.com/AlexandreRouma/SDRPlusPlus/releases

# HackRF tools (if using HackRF One)
sudo apt install hackrf

# Blacklist default RTL-SDR kernel driver
echo "blacklist dvb_usb_rtl28xxu" | sudo tee /etc/modprobe.d/blacklist-rtl.conf
sudo modprobe -r dvb_usb_rtl28xxu 2>/dev/null || true
```

### Legal Test Targets

```
Things you can safely test:
  1. Remotes, door locks, and garage doors you own
  2. Inexpensive 433 MHz devices you bought for testing (second-hand market)
  3. Receiving public signals with SDR: FM radio, ADS-B (aircraft tracking)
  4. Your own Zigbee devices connected to your own smart home hub

Things you must never do:
  - Test other people's vehicles, homes, or office systems
  - Transmit RF signals without authorization (legal penalties possible)
  - Interfere with public infrastructure (traffic signals, medical devices)
```

---

## Defense Checklist

| Vulnerability | Impact | Defense |
|--------------|--------|---------|
| **433 MHz static code** | Replay attack opens door lock/garage | Use rolling code (KeeLoq) or encrypted protocol |
| **Zigbee default key** | Decrypt entire network traffic | Generate unique key per device during pairing; change default keys |
| **Z-Wave S0** | Eavesdrop pairing to obtain network key | Replace with Z-Wave S2 devices; pair using S2 |
| **Unencrypted communication** | Eavesdrop and replay commands | Require AES-128 encryption minimum |
| **Default keys** | Immediate intrusion with published default keys | Generate unique keys at pairing; prohibit hardcoded keys |
| **Signal jamming** | Smart home features rendered inoperable (DoS) | Jamming detection and alerting; redundant communication paths |
| **Zigbee open join** | Unauthorized devices join the network | Minimize join window; whitelist-based authentication |
| **Unsigned OTA updates** | Firmware tampering attack | Only apply signed firmware; encrypt update channel |

<!-- detect-validate-27 -->
## Wireless IoT Protocol Attack Detection and Defense Validation

Zigbee/Z-Wave/RF are targeted via *plaintext keys at join, replay, rolling-code flaws, and jamming*. Defenders must verify **whether their wireless mesh resists capture/replay**. Validate only on **owned equipment/frequencies**.

### Attack -> Targeted weakness -> Primary control (defender) -> Detection signal

| Technique | Targeted weakness | Primary control (defender) | Detection signal |
|---|---|---|---|
| Key capture (at join) | Plaintext TC link key | Pre-installed keys, short join window | Key exchange captured at join |
| Replay attack | No frame counter | Counter validation | Same frame retransmitted |
| Rolling-code flaw | Predictable seed | Strong PRNG, sync | Successful code prediction |
| Jamming/deauth | Availability | Channel hopping, detection | Abnormal RSSI/noise |

### Defense validation (verify directly)

```bash
# 1) Capture your own mesh to check plaintext key-exchange/replay surface (owned gear, killerbee)
zbdump -f 11 -w mesh.pcap 2>/dev/null & sleep 10; kill %1 2>/dev/null; ls -la mesh.pcap
# 2) Replay signal (same-frame retransmission) — duplicate sequence numbers
tshark -r mesh.pcap -Y "zbee_nwk" -T fields -e zbee_nwk.seqno 2>/dev/null | sort | uniq -d | head
```

> Wireless-IoT defense is *whether it resists capture/replay* -- "the Zigbee mesh works" differs from "keys don't leak at join and replayed frames are rejected". Confirm key exchange and counter duplication on owned gear directly ([[15_WiFi_Hacking]], [[71_Bluetooth_RF_Hacking]], [[13_SOC_Blue_Team]]).
