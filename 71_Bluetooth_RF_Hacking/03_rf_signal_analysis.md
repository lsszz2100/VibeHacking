> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# RF 신호 분석 및 SDR 해킹

## 0. 초보자를 위한 개념 이해

### 라디오 주파수(RF)란?

RF를 처음 배우는 분을 위한 비유: **공기 중의 보이지 않는 고속도로**입니다. AM/FM 라디오, 리모컨, 자동차 키, 무선 마우스, 블루투스 - 이 모든 것이 서로 다른 주파수 차선을 사용해 신호를 보내고 받습니다. SDR은 이 고속도로를 모니터링하는 **레이더카메라**입니다.

```
주파수 스펙트럼 (사용 예시):

  Hz          kHz          MHz           GHz
  ────────────────────────────────────────────────→
  ELF   AM라디오  FM라디오  항공  WiFi  5G
  (잠수함)  0.5MHz  87-108MHz   VHF  2.4GHz  60GHz
                          
  주요 관심 주파수:
  315 MHz    → 구형 자동차 키, 차고 도어
  433 MHz    → 무선 온도계, 스마트홈 센서
  868/915 MHz → Zigbee, LoRa IoT
  2.4 GHz    → WiFi, 블루투스, Zigbee
  5.8 GHz    → WiFi ac/ax, 드론 조종
```

---

## 1. SDR(소프트웨어 정의 라디오) 개념

### SDR이란?

```
전통 라디오 수신기:
  안테나 → [하드웨어 필터] → [하드웨어 복조기] → 소리
  → 특정 용도로 고정 제작, 다른 주파수/방식 사용 불가

SDR (Software Defined Radio):
  안테나 → [ADC 변환 칩] → PC/소프트웨어에서 처리
  → 소프트웨어만 바꾸면 FM라디오, 항공 트래픽, 자동차 키 모두 수신 가능!
  → "만능 라디오 수신기"
```

### RTL-SDR: 입문용 저가 도구

```
RTL-SDR 스펙:
  - 원래 목적: 유럽 DVB-T (디지털 TV) 수신 USB 동글
  - 해킹 발견 (2012년): 원시 IQ 샘플 스트리밍 가능
  - 가격: $25~35 (아마존/알리익스프레스)
  - 수신 범위: 24 MHz ~ 1,766 MHz
  - 분해능: 8비트 ADC (저가 대비 충분)
  - 소프트웨어: SDR#, GQRX, GNU Radio 등과 연동

  RTL-SDR 블로그 / 가이드: https://github.com/rtlsdrblog/rtl-sdr-blog
```

### 상위 SDR 장비 비교

```
장비             가격      TX(송신)  주파수 범위       용도
─────────────────────────────────────────────────────────────
RTL-SDR          $25      없음      24M ~ 1.7GHz     입문, 수신 전용
HackRF One       $300     있음      1M ~ 6GHz        중급 해킹
USRP B200        $900+    있음      70M ~ 6GHz       전문 연구
LimeSDR Mini     $150     있음      10M ~ 3.5GHz     중급 균형

입문자 추천: RTL-SDR로 시작 → 필요하면 HackRF
```

---

## 2. GNU Radio 기초

### GNU Radio란?

```
GNU Radio = SDR을 위한 시각적 신호 처리 플랫폼

  블록 다이어그램으로 신호 처리 파이프라인 구성:

  [RTL-SDR 소스] → [저역통과 필터] → [FM 복조] → [오디오 출력]

  각 블록 = Python/C++ 신호 처리 함수
  블록을 연결 = 신호 흐름 정의

설치:
  sudo apt install gnuradio gqrx-sdr
```

### 실습: GQRX로 FM 라디오 수신

```bash
# RTL-SDR 드라이버 설치
sudo apt install rtl-sdr

# RTL-SDR 인식 확인
rtl_test -t

# 예상 출력:
# Found 1 device(s):
#   0:  Realtek, RTL2838UHIDIR, SN: 00000001

# GQRX 실행 (GUI)
gqrx

# 설정:
# - Device: RTL-SDR
# - Frequency: 100.7 MHz (지역 FM 방송국)
# - Mode: WFM (Wide FM)
# → 라디오 청취 성공!
```

---

## 3. 주파수 분석 실습

### 3-1. RTL-SDR 설치 및 기본 사용

```bash
# 설치 (Ubuntu/Kali)
sudo apt update
sudo apt install rtl-sdr sox

# 기본 수신 테스트 (102.1 MHz FM 방송)
rtl_fm -f 102.1e6 -M wbfm -s 200000 -r 48000 - | aplay -r 48000 -f S16_LE

# 특정 주파수 스펙트럼 캡처
rtl_power -f 430e6:440e6:1000 -g 50 -i 1 -e 60s output.csv

# CSV 데이터 시각화
heatmap.py output.csv output.png
```

### 3-2. Python으로 RF 신호 분석

```python
#!/usr/bin/env python3
"""
rf_analyzer.py — RTL-SDR로 RF 신호 분석 (SciPy 기반)
사용법:
  python3 rf_analyzer.py --freq 433.92e6 --duration 5
  python3 rf_analyzer.py --freq 315e6 --duration 3 --save capture.iq
"""

import argparse
import sys
import struct
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="RTL-SDR RF 신호 분석기")
    parser.add_argument(
        "--freq",
        type=float,
        default=433.92e6,
        help="중심 주파수 (Hz), 기본값: 433.92MHz (무선 센서 대역)"
    )
    parser.add_argument(
        "--duration",
        type=float,
        default=5.0,
        help="캡처 시간(초), 기본값: 5"
    )
    parser.add_argument(
        "--gain",
        type=float,
        default=30.0,
        help="RF 이득(dB), 기본값: 30"
    )
    parser.add_argument(
        "--sample-rate",
        type=float,
        default=2.048e6,
        help="샘플링 레이트, 기본값: 2.048 MHz"
    )
    parser.add_argument(
        "--save",
        type=str,
        default=None,
        help="IQ 데이터 저장 파일명 (.iq)"
    )
    parser.add_argument(
        "--analyze",
        type=str,
        default=None,
        help="저장된 .iq 파일 분석"
    )
    return parser.parse_args()


def check_dependencies() -> bool:
    """필수 라이브러리 확인"""
    missing = []
    try:
        import numpy  # noqa: F401
    except ImportError:
        missing.append("numpy")
    try:
        import scipy  # noqa: F401
    except ImportError:
        missing.append("scipy")
    try:
        import matplotlib  # noqa: F401
    except ImportError:
        missing.append("matplotlib")
    if missing:
        print(f"[!] 미설치 패키지: {', '.join(missing)}")
        print(f"    설치: pip install {' '.join(missing)}")
        return False
    return True


def capture_iq_data(
    freq: float,
    sample_rate: float,
    duration: float,
    gain: float,
) -> "list[complex] | None":
    """RTL-SDR로 IQ 데이터 캡처"""
    try:
        import rtlsdr  # pip install pyrtlsdr
        sdr = rtlsdr.RtlSdr()
        sdr.sample_rate = sample_rate
        sdr.center_freq = freq
        sdr.gain = gain

        num_samples = int(sample_rate * duration)
        print(f"[*] {freq/1e6:.3f} MHz 에서 {duration}초 캡처 중...")
        samples = sdr.read_samples(num_samples)
        sdr.close()
        print(f"[+] {len(samples):,}개 샘플 캡처 완료")
        return list(samples)

    except ImportError:
        print("[!] pyrtlsdr 미설치: pip install pyrtlsdr")
        print("    또는 rtl_sdr 명령줄 도구 사용:")
        print(f"    rtl_sdr -f {freq:.0f} -s {sample_rate:.0f} -n {int(sample_rate*duration)} capture.bin")
        return None
    except Exception as e:
        print(f"[!] SDR 캡처 오류: {e}")
        print("    RTL-SDR 연결 및 드라이버 확인 필요")
        return None


def analyze_spectrum(samples: "list[complex]", sample_rate: float, freq: float) -> None:
    """주파수 스펙트럼 분석 및 시각화"""
    import numpy as np
    from scipy import signal
    import matplotlib.pyplot as plt

    samples_np = np.array(samples)
    print(f"[*] FFT 분석 시작...")

    # 전력 스펙트럼 밀도 계산
    freqs, psd = signal.welch(
        samples_np,
        fs=sample_rate,
        nperseg=4096,
        return_onesided=False,
    )
    freqs_shifted = np.fft.fftshift(freqs) + freq

    # 피크 주파수 찾기
    peak_idx = np.argmax(psd)
    peak_freq = freqs_shifted[peak_idx]
    peak_power = 10 * np.log10(psd[peak_idx])

    print(f"[+] 가장 강한 신호: {peak_freq/1e6:.4f} MHz ({peak_power:.1f} dB)")
    print(f"[+] 신호 범위: {freqs_shifted[0]/1e6:.3f} ~ {freqs_shifted[-1]/1e6:.3f} MHz")

    # 시각화
    plt.figure(figsize=(12, 6))
    plt.subplot(2, 1, 1)
    plt.plot(freqs_shifted / 1e6, 10 * np.log10(psd + 1e-12))
    plt.xlabel("주파수 (MHz)")
    plt.ylabel("전력 (dB)")
    plt.title(f"RF 스펙트럼 분석 - 중심: {freq/1e6:.3f} MHz")
    plt.grid(True)
    plt.axvline(x=peak_freq / 1e6, color="r", linestyle="--", label=f"피크: {peak_freq/1e6:.4f} MHz")
    plt.legend()

    plt.subplot(2, 1, 2)
    t = np.arange(len(samples_np)) / sample_rate
    plt.plot(t[:4096], np.abs(samples_np[:4096]))
    plt.xlabel("시간 (초)")
    plt.ylabel("진폭")
    plt.title("시간 도메인 신호 (처음 4096샘플)")
    plt.grid(True)

    plt.tight_layout()
    plt.savefig("spectrum_analysis.png", dpi=150)
    print("[+] spectrum_analysis.png 저장됨")
    plt.show()


def save_iq(samples: "list[complex]", filename: str) -> None:
    """IQ 데이터를 바이너리 파일로 저장"""
    import numpy as np
    data = np.array(samples, dtype=np.complex64)
    data.tofile(filename)
    size_mb = Path(filename).stat().st_size / 1024 / 1024
    print(f"[+] IQ 데이터 저장: {filename} ({size_mb:.1f} MB)")


def load_and_analyze(filename: str, sample_rate: float, freq: float) -> None:
    """저장된 IQ 파일 불러와서 분석"""
    import numpy as np
    print(f"[*] {filename} 불러오는 중...")
    try:
        samples = np.fromfile(filename, dtype=np.complex64)
        print(f"[+] {len(samples):,}개 샘플 로드")
        analyze_spectrum(list(samples), sample_rate, freq)
    except FileNotFoundError:
        print(f"[!] 파일 없음: {filename}")
    except Exception as e:
        print(f"[!] 파일 읽기 오류: {e}")


def main() -> None:
    args = parse_args()

    if not check_dependencies():
        sys.exit(1)

    if args.analyze:
        load_and_analyze(args.analyze, args.sample_rate, args.freq)
        return

    samples = capture_iq_data(args.freq, args.sample_rate, args.duration, args.gain)
    if samples is None:
        sys.exit(1)

    if args.save:
        save_iq(samples, args.save)

    analyze_spectrum(samples, args.sample_rate, args.freq)
    print("\n[!] 교육 목적으로만 사용. 무허가 주파수 송신은 불법입니다.")


if __name__ == "__main__":
    main()
```

### 3-3. 실행 방법

```bash
# 의존성 설치
pip install numpy scipy matplotlib pyrtlsdr

# RTL-SDR 없이도 저장된 IQ 파일 분석 가능
# 공개 IQ 샘플 다운로드:
# https://www.sigidwiki.com 에서 다양한 신호 샘플 제공

# 433 MHz 대역 캡처 및 분석
python3 rf_analyzer.py --freq 433.92e6 --duration 10 --save wireless_sensor.iq

# 저장된 파일 분석
python3 rf_analyzer.py --analyze wireless_sensor.iq --freq 433.92e6
```

---

## 4. 자동차 키 리플레이 공격 개념

### 어떻게 작동하나?

```
정상 동작:
  사용자 → [키 버튼 누름] → [키 발신 315/433 MHz 신호] → [차량 수신 → 잠금 해제]

  중요: 매번 다른 코드 사용 (Rolling Code = 롤링 코드)
  → 이전 캡처한 코드는 재사용 불가 (원칙적으로)

리플레이 공격 (구형 시스템, 고정 코드):
  공격자 → [신호 캡처] → [나중에 재전송] → [차량 잠금 해제]
  → 현재 대부분 롤링 코드로 방어됨

RollJam 공격 (고급, 개념 이해용):
  1. 공격자가 재밍 장비 + 수신기 동시 운용
  2. 피해자가 키 버튼 누름 → 신호 잼 (차 안 열림)
  3. 공격자가 코드 1 캡처 (피해자는 차가 안 열려서 다시 누름)
  4. 피해자 두번째 누름 → 코드 2 캡처, 코드 1 전송 (차 열림)
  5. 공격자는 코드 2 보유 → 나중에 사용

  법적 주의: 실제 차량에 적용은 불법
```

### 관련 도구 (교육용)

```
rpitx       → 라즈베리 파이로 RF 송신 (면허 필요)
Universal Radio Hacker (URH) → RF 신호 분석/디코딩 GUI
SDRangel    → SDR 신호 분석 플랫폼
inspectrum  → IQ 파일 시각화
```

---

## 5. 합법적 실습 환경

```
안전한 실습 방법:
  1. 자신 소유 기기 테스트 (집 차고 리모컨, 자신의 차)
  2. 패러데이 케이지 사용 (신호 차폐 박스)
     → 알루미늄 호일 박스로 간이 제작 가능
  3. 시뮬레이터 사용 (실제 신호 없이 소프트웨어로 연습)
  4. 합법적 아마추어 무선 면허 취득 후 지정 주파수 사용
```

---

<a name="english"></a>

# RF Signal Analysis and SDR Hacking

## 0. Beginner Concepts

### What Is RF?

Think of RF as **invisible highways in the air**. AM/FM radio, car remotes, wireless mice, and Bluetooth all use different frequency lanes to send and receive signals. SDR is a **traffic monitoring camera** for those highways.

```
Frequency Spectrum (examples):

  Hz         kHz           MHz            GHz
  ────────────────────────────────────────────────→
  ELF   AM Radio   FM Radio  Aviat.  WiFi  5G
             0.5MHz  87-108MHz        2.4GHz 60GHz

  Key attack frequencies:
  315 / 433 MHz → car keys, garage doors, wireless sensors
  868 / 915 MHz → Zigbee, LoRa IoT
  2.4 GHz       → WiFi, Bluetooth, Zigbee
```

---

## 1. SDR (Software-Defined Radio)

```
Traditional receiver:
  Antenna → [Hardware filter] → [Hardware demodulator] → Audio
  → Fixed to one purpose; can't switch protocols

SDR:
  Antenna → [ADC chip] → PC processes signal in software
  → Change the software → receive FM radio, aircraft transponders,
    car keys, or anything else!
```

### RTL-SDR: Beginner Hardware

```
RTL-SDR facts:
  - Originally: European DVB-T digital TV USB dongle
  - Discovered (2012): can stream raw IQ samples to PC
  - Price: $25–35
  - Receive range: 24 MHz – 1,766 MHz
  - Software: SDR#, GQRX, GNU Radio

  RTL-SDR blog / guides: https://github.com/rtlsdrblog/rtl-sdr-blog
```

### SDR Hardware Comparison

```
Device           Price   TX?   Frequency Range     Use Case
─────────────────────────────────────────────────────────────
RTL-SDR          $25    No    24M – 1.7 GHz        Beginner, RX only
HackRF One       $300   Yes   1M – 6 GHz           Mid-level hacking
USRP B200        $900+  Yes   70M – 6 GHz          Professional research
LimeSDR Mini     $150   Yes   10M – 3.5 GHz        Balanced mid-level
```

---

## 2. GNU Radio Basics

```bash
# Install
sudo apt install gnuradio gqrx-sdr

# Test RTL-SDR
rtl_test -t

# Listen to FM radio (quick test)
rtl_fm -f 102.1e6 -M wbfm -s 200000 -r 48000 - | aplay -r 48000 -f S16_LE
```

---

## 3. Lab: Python RF Signal Analyzer

### Dependencies

```bash
pip install numpy scipy matplotlib pyrtlsdr
```

### Usage

```bash
# Capture 433 MHz band (wireless sensors)
python3 rf_analyzer.py --freq 433.92e6 --duration 10 --save sensor.iq

# Analyze saved IQ file
python3 rf_analyzer.py --analyze sensor.iq --freq 433.92e6
```

See the Korean section for the complete Python 3.10+ script with spectrum visualization.

The script:
1. Captures IQ samples from RTL-SDR at a given frequency
2. Computes power spectral density via Welch's method
3. Identifies peak signal frequency
4. Plots spectrum + time-domain waveform
5. Saves results as `spectrum_analysis.png`

---

## 4. Car Key Replay Attack Concept

```
Normal operation:
  User → [Key button] → [315/433 MHz signal] → [Car receives → unlocks]
  Modern systems use Rolling Codes → each button press sends a NEW code

Replay attack (legacy fixed-code systems only):
  Attacker captures signal → replays later → car unlocks
  (Patched in all modern vehicles)

RollJam attack (educational concept):
  1. Attacker jams + receives simultaneously
  2. Victim presses key → car does NOT open (jammed)
  3. Attacker captures Code 1; victim presses again
  4. Code 2 captured; Code 1 forwarded → car opens
  5. Attacker now holds Code 2 for later use

  Legal warning: Applying this to real vehicles is illegal.
```

---

## 5. Legal Practice Environments

```
Safe lab options:
  1. Test your own devices (own car remote, own garage door)
  2. Use a Faraday cage (shielded box to contain signals)
     → DIY: aluminum foil box works for basic isolation
  3. Use signal simulators (software-only practice)
  4. Obtain amateur radio license for designated frequencies
```
