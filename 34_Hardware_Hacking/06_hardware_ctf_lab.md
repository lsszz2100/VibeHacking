> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 하드웨어 해킹 CTF 실습 랩

## 실습 환경 준비

### 필요 장비 (실물 실습)

```
- USB 로직 분석기 (Saleae Logic, DSLogic 등)
- CH341A SPI 플래시 프로그래머
- USB-to-Serial 어댑터 (CP2102, CH340)
- 점퍼 와이어
- 빵판(브레드보드)
- 대상 하드웨어 (라우터, IoT 장치 등)
```

### 소프트웨어 설치

```bash
# 로직 분석기 소프트웨어
# Sigrok / PulseView
sudo apt install -y sigrok pulseview

# SPI 플래시 도구
sudo apt install -y flashrom

# JTAG/디버깅
sudo apt install -y openocd gdb-multiarch

# Python 시리얼 통신
pip install pyserial

# 파형 분석
pip install sigrok-cli
```

### 시뮬레이션 환경 (Docker)

```yaml
# docker-compose.yml
version: "3.9"

services:
  logic-sim:
    image: python:3.11-slim
    container_name: logic-sim
    command: >
      sh -c "pip install pyserial -q && sleep infinity"
    volumes:
      - ./lab:/lab

  spi-sim:
    image: python:3.11-slim
    container_name: spi-sim
    command: sleep infinity
    volumes:
      - ./spi-data:/data
```

---

## 실습 1: SPI 플래시 메모리 덤프 분석

### 목표

SPI 플래시 메모리 덤프 파일을 분석하여 저장된 비밀번호와 플래그를 추출한다.

**플래그 형식**: `CTF{spi_flash_<secret_type>_dumped}`

### 시나리오

IoT 장치의 SPI 플래시 칩(W25Q64)에서 덤프한 8MB 이미지 파일이 제공됐다. 파일시스템과 설정 파일을 분석하여 관리자 자격증명과 플래그를 추출하라.

### SPI 플래시 덤프 생성

```python
#!/usr/bin/env python3
"""CTF용 가상 SPI 플래시 덤프 생성기"""

import gzip
import os
import struct
from pathlib import Path


def create_jffs2_like_filesystem() -> bytes:
    """JFFS2 유사 파일시스템 시뮬레이션"""
    # JFFS2 매직 번호
    JFFS2_MAGIC = b"\x85\x19"

    fs_data = b""

    # 디렉토리 엔트리 시뮬레이션
    entries = {
        "/etc/passwd": (
            b"root:x:0:0:root:/root:/bin/sh\n"
            b"admin:x:1000:1000::/home/admin:/bin/sh\n"
        ),
        "/etc/config": (
            b"[auth]\n"
            b"admin_user=admin\n"
            b"admin_pass=CTF{spi_flash_config_password_dumped}\n"
            b"backup_pass=backup_secret_2024\n"
            b"\n"
            b"[network]\n"
            b"ip=192.168.1.1\n"
            b"subnet=255.255.255.0\n"
        ),
        "/etc/ssl/device.key": (
            b"-----BEGIN RSA PRIVATE KEY-----\n"
            b"MIIEowIBAAKCAQEA...(truncated for CTF)\n"
            b"CTF_PRIVATE_KEY_EMBEDDED\n"
            b"-----END RSA PRIVATE KEY-----\n"
        ),
        "/tmp/flag": b"CTF{spi_flash_hidden_flag_dumped}\n",
    }

    for filepath, content in entries.items():
        # 파일명 인코딩
        name_bytes = filepath.encode() + b"\x00"
        # 파일 헤더 (간략화)
        header = JFFS2_MAGIC + struct.pack(">HI", 0xE001, len(content))
        header += struct.pack(">H", len(name_bytes))
        fs_data += header + name_bytes + content + b"\xff" * (4 - (len(content) % 4) % 4)

    return fs_data


def create_spi_flash_dump(output_path: str, size_mb: int = 8) -> None:
    """가상 SPI 플래시 덤프 생성"""
    flash_size = size_mb * 1024 * 1024

    # 부트로더 영역 (첫 256KB)
    bootloader = b"U-Boot 2021.10\x00" + b"\x00" * (256 * 1024 - 16)

    # 커널 영역 (다음 2MB) - gzip 압축 커널 시뮬레이션
    kernel_content = b"Linux-5.15-ctf-router\x00" + b"\x00" * 100
    kernel = gzip.compress(kernel_content).ljust(2 * 1024 * 1024, b"\xff")

    # 루트 파일시스템 영역 (다음 4MB)
    rootfs = create_jffs2_like_filesystem()
    rootfs = rootfs.ljust(4 * 1024 * 1024, b"\xff")

    # 나머지는 0xFF (비어있음)
    remaining = flash_size - len(bootloader) - len(kernel) - len(rootfs)
    remaining_data = b"\xff" * max(0, remaining)

    flash_data = bootloader + kernel + rootfs + remaining_data
    flash_data = flash_data[:flash_size]  # 크기 맞춤

    with open(output_path, "wb") as f:
        f.write(flash_data)

    print(f"[+] SPI 플래시 덤프 생성: {output_path} ({size_mb}MB)")


if __name__ == "__main__":
    Path("spi-data").mkdir(exist_ok=True)
    create_spi_flash_dump("spi-data/flash_dump.bin", size_mb=1)
```

### 풀이

```python
#!/usr/bin/env python3
"""SPI 플래시 덤프 분석 도구"""

import argparse
import re
import struct
from pathlib import Path


FILESYSTEM_SIGNATURES = {
    b"\x85\x19": "JFFS2",
    b"hsqs": "SquashFS (little-endian)",
    b"sqsh": "SquashFS (big-endian)",
    b"1sqdB": "SquashFS v1",
    b"\x68\x73\x71\x73": "SquashFS",
    b"U-Boot": "U-Boot bootloader",
    b"\x1f\x8b": "gzip compressed data",
    b"\xfd7zXZ": "XZ compressed",
    b"BZh": "bzip2 compressed",
}

INTERESTING_STRINGS_PATTERNS = [
    (rb"CTF\{[^}]+\}", "CTF 플래그"),
    (rb"(?i)password\s*=\s*(\S+)", "패스워드"),
    (rb"(?i)admin[_-]?pass\s*=\s*(\S+)", "관리자 패스워드"),
    (rb"-----BEGIN (?:RSA )?PRIVATE KEY-----", "개인 키"),
    (rb"(?:AKIA[0-9A-Z]{16})", "AWS 액세스 키"),
    (rb"(?i)secret\s*=\s*(\S{8,})", "시크릿"),
]


def find_filesystem_offsets(data: bytes) -> list[dict]:
    """파일시스템 오프셋 탐색"""
    findings: list[dict] = []

    for sig, name in FILESYSTEM_SIGNATURES.items():
        offset = 0
        while True:
            idx = data.find(sig, offset)
            if idx == -1:
                break
            findings.append({
                "offset": idx,
                "offset_hex": hex(idx),
                "type": name,
                "signature": sig.hex(),
            })
            offset = idx + 1

    return sorted(findings, key=lambda x: x["offset"])


def extract_strings(data: bytes, min_len: int = 8) -> list[str]:
    """바이너리에서 ASCII 문자열 추출"""
    pattern = re.compile(rb"[ -~]{" + str(min_len).encode() + rb",}")
    return [m.group().decode("ascii", errors="ignore") for m in pattern.finditer(data)]


def find_secrets(data: bytes) -> list[dict]:
    """민감한 정보 탐색"""
    findings: list[dict] = []

    for pattern, label in INTERESTING_STRINGS_PATTERNS:
        for m in re.finditer(pattern, data, re.IGNORECASE):
            findings.append({
                "label": label,
                "offset": hex(m.start()),
                "value": m.group().decode("utf-8", errors="replace")[:100],
            })

    return findings


def analyze_spi_dump(dump_path: str) -> None:
    path = Path(dump_path)
    if not path.exists():
        print(f"[-] 파일 없음: {dump_path}")
        return

    print(f"[*] SPI 플래시 덤프 분석: {path.name}")
    print(f"    크기: {path.stat().st_size:,} bytes ({path.stat().st_size // 1024}KB)")

    with open(path, "rb") as f:
        data = f.read()

    # 파일시스템 탐색
    fs_offsets = find_filesystem_offsets(data)
    print(f"\n=== 파일시스템/시그니처 탐지 ({len(fs_offsets)}개) ===")
    for fs in fs_offsets[:10]:
        print(f"  {fs['offset_hex']:10s} | {fs['type']}")

    # 비밀 정보 탐색
    secrets = find_secrets(data)
    print(f"\n=== 비밀 정보 탐지 ({len(secrets)}개) ===")
    flags: list[str] = []
    for s in secrets:
        print(f"  [{s['label']}] {s['offset']}: {s['value'][:80]}")
        if s["label"] == "CTF 플래그":
            flags.append(s["value"])

    if flags:
        print(f"\n[+] 플래그:")
        for flag in set(flags):
            print(f"    {flag}")

    # 유용한 문자열
    strings = extract_strings(data)
    config_strings = [s for s in strings if any(
        kw in s.lower() for kw in ["password", "passwd", "secret", "admin", "config"]
    )]
    if config_strings:
        print(f"\n=== 설정 관련 문자열 ({len(config_strings)}개) ===")
        for s in config_strings[:10]:
            print(f"  {s}")


def main() -> None:
    parser = argparse.ArgumentParser(description="SPI 플래시 덤프 분석 도구")
    parser.add_argument("dump", help="분석할 플래시 덤프 파일")
    parser.add_argument("--strings-only", action="store_true", help="문자열만 출력")
    args = parser.parse_args()

    if args.strings_only:
        with open(args.dump, "rb") as f:
            data = f.read()
        for s in extract_strings(data):
            print(s)
    else:
        analyze_spi_dump(args.dump)


if __name__ == "__main__":
    main()
```

---

## 실습 2: 로직 분석기 챌린지 - UART 데이터 디코딩

### 목표

로직 분석기로 캡처한 파형 데이터를 분석하여 UART 통신에서 플래그를 추출한다.

**플래그 형식**: `CTF{logic_analyzer_uart_<baud_rate>_decoded}`

### UART 파형 시뮬레이터

```python
#!/usr/bin/env python3
"""UART 파형 시뮬레이터 및 디코더"""

import struct
from dataclasses import dataclass
from typing import Iterator


@dataclass
class UARTFrame:
    timestamp_us: float
    bit_value: int


def encode_uart_byte(
    byte_val: int,
    baud_rate: int = 115200,
    start_time_us: float = 0.0,
) -> list[UARTFrame]:
    """단일 바이트를 UART 파형으로 인코딩"""
    bit_period_us = 1_000_000 / baud_rate
    frames: list[UARTFrame] = []
    current_time = start_time_us

    # 스타트 비트 (LOW)
    frames.append(UARTFrame(current_time, 0))
    current_time += bit_period_us

    # 데이터 비트 (LSB first)
    for bit_pos in range(8):
        bit = (byte_val >> bit_pos) & 1
        frames.append(UARTFrame(current_time, bit))
        current_time += bit_period_us

    # 스톱 비트 (HIGH)
    frames.append(UARTFrame(current_time, 1))
    current_time += bit_period_us

    return frames


def encode_uart_string(
    text: str,
    baud_rate: int = 115200,
    start_time_us: float = 0.0,
) -> list[UARTFrame]:
    """문자열을 UART 파형으로 인코딩"""
    all_frames: list[UARTFrame] = []
    current_time = start_time_us

    # 아이들 상태 (HIGH)
    all_frames.append(UARTFrame(current_time, 1))
    current_time += 100 / baud_rate * 1_000_000

    for char in text:
        byte_frames = encode_uart_byte(ord(char), baud_rate, current_time)
        all_frames.extend(byte_frames)
        current_time = byte_frames[-1].timestamp_us + (1_000_000 / baud_rate)

    return all_frames


def decode_uart_frames(
    frames: list[UARTFrame],
    baud_rate: int = 115200,
) -> str:
    """UART 파형에서 데이터 디코딩"""
    bit_period_us = 1_000_000 / baud_rate
    decoded = []
    i = 0

    while i < len(frames):
        frame = frames[i]

        # 스타트 비트 찾기 (HIGH→LOW 전이)
        if i > 0 and frames[i - 1].bit_value == 1 and frame.bit_value == 0:
            # 스타트 비트 발견 - 데이터 비트 샘플링
            bits = []
            start_time = frame.timestamp_us

            for bit_num in range(8):
                sample_time = start_time + bit_period_us * (bit_num + 1.5)
                # 가장 가까운 샘플 찾기
                closest = min(frames, key=lambda f: abs(f.timestamp_us - sample_time))
                bits.append(closest.bit_value)

            # LSB first -> 바이트 변환
            byte_val = sum(bit << pos for pos, bit in enumerate(bits))
            if 32 <= byte_val <= 126:  # 출력 가능 문자
                decoded.append(chr(byte_val))

        i += 1

    return "".join(decoded)


def save_waveform_csv(frames: list[UARTFrame], output_path: str) -> None:
    """파형 데이터를 CSV로 저장 (Sigrok/PulseView 호환)"""
    with open(output_path, "w") as f:
        f.write("Time [us],Channel 0\n")
        for frame in frames:
            f.write(f"{frame.timestamp_us:.3f},{frame.bit_value}\n")
    print(f"[+] 파형 저장: {output_path}")


def create_uart_challenge(output_path: str, baud_rate: int = 9600) -> None:
    """UART 챌린지 파형 생성"""
    secret_message = (
        f"Boot sequence started\r\n"
        f"Device: CTF-Router-001\r\n"
        f"Baud: {baud_rate}\r\n"
        f"Flag: CTF{{logic_analyzer_uart_{baud_rate}_decoded}}\r\n"
        f"Login: admin\r\n"
    )

    frames = encode_uart_string(secret_message, baud_rate)
    save_waveform_csv(frames, output_path)
    print(f"[+] UART 챌린지 생성: {baud_rate} baud, {len(frames)} 샘플")


def analyze_waveform(csv_path: str, baud_rate: int) -> None:
    """CSV 파형 파일 분석"""
    import re

    frames: list[UARTFrame] = []

    with open(csv_path) as f:
        for line in f:
            line = line.strip()
            if line.startswith("Time") or not line:
                continue
            try:
                time_us, bit = line.split(",")
                frames.append(UARTFrame(float(time_us), int(bit)))
            except ValueError:
                pass

    print(f"[*] 파형 샘플: {len(frames)}개")
    print(f"[*] 보드레이트: {baud_rate}")

    decoded = decode_uart_frames(frames, baud_rate)
    print(f"\n=== 디코딩된 데이터 ===")
    print(decoded)

    flags = re.findall(r"CTF\{[^}]+\}", decoded)
    if flags:
        print(f"\n[+] 플래그: {flags[0]}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="UART 파형 분석 도구")
    parser.add_argument("--create", help="챌린지 파형 생성 (출력 파일명)")
    parser.add_argument("--analyze", help="CSV 파형 분석")
    parser.add_argument("--baud", type=int, default=9600, help="보드레이트")
    args = parser.parse_args()

    if args.create:
        create_uart_challenge(args.create, args.baud)
    elif args.analyze:
        analyze_waveform(args.analyze, args.baud)
    else:
        parser.print_help()
```

---

## 실습 3: 하드웨어 토큰 우회

### 목표

하드웨어 보안 토큰의 인증 로직을 분석하고, 타이밍 사이드채널 공격으로 비밀 PIN을 추출한다.

**플래그 형식**: `CTF{hardware_token_timing_attack_pin_<pin_code>}`

### 풀이

```python
#!/usr/bin/env python3
"""하드웨어 토큰 타이밍 공격 시뮬레이터"""

import argparse
import time
import statistics
from dataclasses import dataclass


@dataclass
class TimingResult:
    pin_attempt: str
    elapsed_ns: float
    correct: bool


# 취약한 PIN 비교 함수 (타이밍 취약점)
SECRET_PIN = "4729"


def vulnerable_pin_check(input_pin: str, secret: str = SECRET_PIN) -> bool:
    """타이밍 취약 PIN 검증 (초기 일치 문자에서 더 오래 걸림)"""
    if len(input_pin) != len(secret):
        return False

    for i, (a, b) in enumerate(zip(input_pin, secret)):
        # 취약점: 문자 비교 후 실제 처리 시간 차이
        if a != b:
            return False
        time.sleep(0.001)  # 일치 시 마다 1ms 추가 지연

    return True


def timing_attack_single_digit(
    position: int,
    known_prefix: str,
    digits: str = "0123456789",
    num_trials: int = 10,
) -> tuple[str, float]:
    """단일 자리 타이밍 공격"""
    timings: dict[str, list[float]] = {}

    for digit in digits:
        candidate = known_prefix + digit + "0" * (4 - len(known_prefix) - 1)
        trial_times: list[float] = []

        for _ in range(num_trials):
            start = time.perf_counter_ns()
            vulnerable_pin_check(candidate)
            elapsed = time.perf_counter_ns() - start
            trial_times.append(elapsed)

        # 노이즈 제거를 위해 중앙값 사용
        timings[digit] = trial_times

    # 가장 오래 걸린 자리 = 올바른 자리
    median_times = {d: statistics.median(t) for d, t in timings.items()}
    best_digit = max(median_times, key=lambda d: median_times[d])
    best_time = median_times[best_digit]

    return best_digit, best_time


def run_timing_attack(pin_length: int = 4) -> str:
    print("[*] 타이밍 사이드채널 공격 시작")
    print(f"[*] PIN 길이: {pin_length}자리")

    recovered_pin = ""

    for pos in range(pin_length):
        print(f"\n[*] 자리 {pos+1} 분석 중...")
        digit, timing = timing_attack_single_digit(pos, recovered_pin)
        recovered_pin += digit
        print(f"  [+] 자리 {pos+1}: {digit} (타이밍: {timing/1e6:.3f}ms)")

    print(f"\n[+] 복구된 PIN: {recovered_pin}")

    if vulnerable_pin_check(recovered_pin):
        flag = f"CTF{{hardware_token_timing_attack_pin_{recovered_pin}}}"
        print(f"[+] 플래그: {flag}")
        return recovered_pin
    else:
        print("[-] 복구 실패 - 노이즈 영향. 재시도 필요")
        return ""


def demonstrate_timing_difference() -> None:
    """타이밍 차이 시각화"""
    print("=== 타이밍 차이 시연 ===\n")
    test_pins = ["0000", "4000", "4700", "4720", "4729"]

    for pin in test_pins:
        trials = []
        for _ in range(5):
            start = time.perf_counter_ns()
            vulnerable_pin_check(pin)
            trials.append(time.perf_counter_ns() - start)

        median_ms = statistics.median(trials) / 1e6
        correct = pin == SECRET_PIN
        marker = " ← 정답!" if correct else ""
        print(f"  PIN {pin}: {median_ms:.2f}ms{marker}")


def main() -> None:
    parser = argparse.ArgumentParser(description="하드웨어 토큰 타이밍 공격")
    parser.add_argument("--attack", action="store_true", help="타이밍 공격 실행")
    parser.add_argument("--demo", action="store_true", help="타이밍 차이 시연")
    parser.add_argument("--pin-length", type=int, default=4, help="PIN 길이")
    args = parser.parse_args()

    if args.demo:
        demonstrate_timing_difference()
    elif args.attack:
        run_timing_attack(args.pin_length)
    else:
        print("[*] --demo 로 타이밍 차이 확인, --attack 으로 공격 실행")
        demonstrate_timing_difference()


if __name__ == "__main__":
    main()
```

---

<a name="english"></a>

# Hardware Hacking CTF Practice Lab

## Lab Environment Setup

```bash
# Software tools
pip install pyserial
sudo apt install -y sigrok pulseview flashrom openocd

# Optional hardware
# - Logic analyzer (Saleae Logic, DSLogic)
# - CH341A SPI programmer
# - USB-to-Serial adapter
```

---

## Challenge 1: SPI Flash Memory Dump Analysis

### Objective

Analyze a SPI flash memory dump to extract stored passwords and the hidden flag.

**Flag format**: `CTF{spi_flash_<secret_type>_dumped}`

### Solution Steps

```bash
# Generate sample flash dump
python3 spi_dump_creator.py
# Creates spi-data/flash_dump.bin

# Analyze dump
python3 spi_analyzer.py spi-data/flash_dump.bin
# Finds: CTF{spi_flash_config_password_dumped}
#        CTF{spi_flash_hidden_flag_dumped}

# Manual analysis
strings spi-data/flash_dump.bin | grep -E "CTF|password|passwd"
binwalk spi-data/flash_dump.bin
binwalk -e spi-data/flash_dump.bin
find _flash_dump.bin.extracted/ -type f | xargs grep -l "CTF"

# Physical SPI dump (real hardware)
flashrom -p ch341a_spi -r flash_dump.bin
```

### Physical Setup (Real Hardware)

```
SPI Flash Chip Pinout (SOIC-8):
Pin 1: CS#  → CH341A CS
Pin 2: DO   → CH341A SO
Pin 3: WP#  → VCC (3.3V)
Pin 4: GND  → GND
Pin 5: DI   → CH341A SI
Pin 6: CLK  → CH341A CLK
Pin 7: HOLD#→ VCC (3.3V)
Pin 8: VCC  → 3.3V
```

---

## Challenge 2: Logic Analyzer - UART Decoding

### Objective

Analyze a logic analyzer capture file to decode UART communication and extract the flag.

**Flag format**: `CTF{logic_analyzer_uart_<baud_rate>_decoded}`

### Solution Steps

```bash
# Create challenge waveform
python3 uart_analyzer.py --create uart_challenge.csv --baud 9600

# Decode the waveform
python3 uart_analyzer.py --analyze uart_challenge.csv --baud 9600
# Decodes: CTF{logic_analyzer_uart_9600_decoded}

# Using PulseView/Sigrok (real capture)
# 1. Open .sr file in PulseView
# 2. Add UART decoder: Protocol Decoders → UART
# 3. Set baud rate, start bit, stop bit
# 4. Read decoded data in annotation view

# Sigrok CLI
sigrok-cli -i capture.sr -P uart:baudrate=9600:rx=D0 -A uart=rx-data
```

### Baud Rate Detection

```python
# If baud rate is unknown, calculate from shortest pulse:
# shortest_pulse_duration = 1 / baud_rate
# e.g., 104.17µs → 1/104.17µs ≈ 9600 baud
```

---

## Challenge 3: Hardware Token Timing Attack

### Objective

Exploit a timing side-channel vulnerability in a hardware token PIN verification to recover the secret PIN.

**Flag format**: `CTF{hardware_token_timing_attack_pin_<pin_code>}`

### Solution Steps

```bash
# Demonstrate timing differences
python3 timing_attack.py --demo
# Shows: PIN "4000" takes longer than "0000" (more matching chars)

# Run automated timing attack
python3 timing_attack.py --attack --pin-length 4
# Recovers: PIN = 4729
# Flag: CTF{hardware_token_timing_attack_pin_4729}
```

### How the Attack Works

```
Position 0: Test 0000-9000
  "4000" takes longest → digit 0 = "4"

Position 1: Test 4000-4900
  "4700" takes longest → digit 1 = "7"

Position 2: Test 4700-4790
  "4720" takes longest → digit 2 = "2"

Position 3: Test 4720-4729
  "4729" takes longest → digit 3 = "9"

Recovered PIN: 4729
```

### Real-World Countermeasures

```python
# Constant-time comparison (secure)
import hmac
def secure_pin_check(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())
```
