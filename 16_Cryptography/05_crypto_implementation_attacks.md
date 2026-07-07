> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 암호화 구현 취약점 공격 — 패딩 오라클·타이밍 공격·약한 난수

## 0. 초보자를 위한 개념 이해

### 암호화 구현 취약점이란?

암호화 알고리즘 자체는 안전해도, 잘못된 구현 방식이 공격 경로를 만들어냅니다. 패딩 오라클 공격은 서버의 패딩 에러 응답을 이용해 암호문을 바이트 단위로 복호화합니다. 타이밍 공격은 비밀값 비교 시 조기 종료로 인한 실행 시간 차이를 이용해 비밀을 추측합니다. 약한 난수 생성기는 예측 가능한 키를 만들어 전체 암호 체계를 무력화합니다.

**왜 배우는가:**
```
구현 취약점이 실제로 발생하는 이유:

  패딩 오라클
    → "복호화 성공/패딩 오류" 에러를 다르게 반환
    → ASP.NET ViewState 취약점 (CVE-2010-3332)
    → POODLE, ROBOT 공격의 핵심 원리

  타이밍 공격
    → "abcd" vs "abce" 비교 시 3번째 문자에서 차이 발생
    → 원격으로도 μs 단위 측정 가능 (통계적 방법)
    → JWT, HMAC, OAuth 토큰 검증에서 발견

  약한 난수 (Mersenne Twister)
    → Python random, Java Random의 기본 PRNG
    → 624개 출력 관찰 → 전체 상태 복원 가능
    → 세션 토큰, OTP, 암호키 생성에 사용 시 위험
```

### 핵심 개념 정리

```
공격 유형별 요약:

  패딩 오라클 공격
    대상: AES-CBC 복호화 시 패딩 에러 노출
    원리: 마지막 바이트 변조 → 패딩 OK/Fail 오라클
    결과: 암호문을 평문으로 바이트 단위 복원
    방어: 암호화-후-인증(Encrypt-then-MAC), AES-GCM 사용

  타이밍 공격
    대상: 문자열 직접 비교 (== 연산자)
    원리: 첫 불일치에서 조기 종료 → 시간 차이
    결과: 비밀 토큰/키의 각 바이트 추측 가능
    방어: hmac.compare_digest() 사용 (상수 시간 비교)

  약한 난수
    대상: 암호화 비적합 PRNG (random 모듈)
    원리: 내부 상태(624개 32bit) 관찰로 복원
    결과: 미래 난수 예측 → 세션/토큰 위조
    방어: secrets 모듈 또는 os.urandom() 사용
```

### 필요한 도구 및 환경
- **pycryptodome**: AES-CBC 암호화 구현 및 공격 실습
- **requests**: 패딩 오라클 공격 HTTP 오라클 요청
- **padbuster**: 패딩 오라클 자동화 도구
- **python-mersenne**: Mersenne Twister 상태 복원 도구

### 기초 실습 예제
```python
#!/usr/bin/env python3
"""타이밍 공격 취약점과 방어 — 상수 시간 비교 실습."""

import hmac
import time
import secrets
import statistics


def vulnerable_compare(secret: str, user_input: str) -> bool:
    """취약한 비교: 첫 불일치에서 즉시 반환 (타이밍 공격에 취약)."""
    if len(secret) != len(user_input):
        return False
    for a, b in zip(secret, user_input):
        if a != b:
            return False  # 조기 종료 → 시간 차이 발생
    return True


def secure_compare(secret: str, user_input: str) -> bool:
    """안전한 비교: 상수 시간 비교 (타이밍 공격 방어)."""
    return hmac.compare_digest(secret.encode(), user_input.encode())


def measure_timing(compare_fn, secret: str, test_input: str, trials: int = 1000) -> float:
    """비교 함수의 평균 실행 시간을 측정합니다."""
    times: list[float] = []
    for _ in range(trials):
        start = time.perf_counter_ns()
        compare_fn(secret, test_input)
        times.append(time.perf_counter_ns() - start)
    return statistics.mean(times)


if __name__ == "__main__":
    secret_token = secrets.token_hex(16)  # 32자 16진수 토큰
    wrong_first_char = "0" + secret_token[1:]  # 첫 글자만 다름
    wrong_all = "0" * len(secret_token)          # 전부 다름

    print("[취약한 비교 - 타이밍 차이 측정]")
    t1 = measure_timing(vulnerable_compare, secret_token, wrong_all)
    t2 = measure_timing(vulnerable_compare, secret_token, wrong_first_char)
    print(f"  전부 틀림:   {t1:.0f} ns")
    print(f"  첫자만 틀림: {t2:.0f} ns  (차이: {abs(t2-t1):.0f} ns)")

    print("\n[안전한 비교 - 상수 시간]")
    t3 = measure_timing(secure_compare, secret_token, wrong_all)
    t4 = measure_timing(secure_compare, secret_token, wrong_first_char)
    print(f"  전부 틀림:   {t3:.0f} ns")
    print(f"  첫자만 틀림: {t4:.0f} ns  (차이: {abs(t4-t3):.0f} ns)")
```

---

## 1. 암호화 구현 취약점 분류

```
암호화 구현 취약점
    │
    ├── 패딩 오라클 공격
    │     - CBC 모드 패딩 검증 오류 노출
    │     - 바이트 단위 평문 복구
    │
    ├── 타이밍 공격
    │     - 비밀값 비교 시 조기 종료
    │     - 실행 시간 차이로 정보 유출
    │
    ├── 약한 난수 생성기
    │     - Mersenne Twister 상태 복구
    │     - 시드 예측 (타임스탬프 기반)
    │
    └── 재사용 IV/Nonce
          - CTR/GCM 모드 논스 재사용
          - 평문 XOR로 두 메시지 복구
```

---

## 2. 패딩 오라클 공격

```python
#!/usr/bin/env python3
"""CBC 패딩 오라클 공격 구현."""

import os
from typing import Callable

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


class PaddingOracleAttack:
    """CBC 패딩 오라클 공격 — 바이트별 평문 복구."""

    def __init__(self, oracle: Callable[[bytes, bytes], bool], block_size: int = 16) -> None:
        self.oracle = oracle
        self.block_size = block_size

    def decrypt_block(self, prev_block: bytes, curr_block: bytes) -> bytes:
        """단일 블록 복호화."""
        bs = self.block_size
        intermediate = bytearray(bs)

        for byte_pos in range(bs - 1, -1, -1):
            pad_byte = bs - byte_pos
            crafted = bytearray(bs)

            # 이미 알고 있는 바이트로 패딩 구성
            for k in range(byte_pos + 1, bs):
                crafted[k] = intermediate[k] ^ pad_byte

            found = False
            for guess in range(256):
                crafted[byte_pos] = guess
                if self.oracle(bytes(crafted), curr_block):
                    intermediate[byte_pos] = guess ^ pad_byte
                    found = True
                    break

            if not found:
                raise ValueError(f"바이트 {byte_pos} 복호화 실패")

        # 평문 = intermediate XOR 원래 이전 블록
        return bytes(intermediate[i] ^ prev_block[i] for i in range(bs))

    def decrypt(self, iv: bytes, ciphertext: bytes) -> bytes:
        """전체 암호문 복호화."""
        bs = self.block_size
        blocks = [iv] + [ciphertext[i:i+bs] for i in range(0, len(ciphertext), bs)]
        plaintext = b""

        for i in range(1, len(blocks)):
            plaintext += self.decrypt_block(blocks[i-1], blocks[i])

        # PKCS#7 패딩 제거
        pad_len = plaintext[-1]
        if 1 <= pad_len <= bs:
            plaintext = plaintext[:-pad_len]
        return plaintext


def simulate_oracle(key: bytes) -> Callable[[bytes, bytes], bool]:
    """테스트용 패딩 오라클 생성."""
    def oracle(iv: bytes, ciphertext: bytes) -> bool:
        try:
            cipher = AES.new(key, AES.MODE_CBC, iv)
            unpad(cipher.decrypt(ciphertext), 16)
            return True
        except ValueError:
            return False
    return oracle


if __name__ == "__main__":
    key = os.urandom(16)
    iv  = os.urandom(16)

    message = b"Secret: admin=true"
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(message, 16))

    oracle = simulate_oracle(key)
    attack = PaddingOracleAttack(oracle)
    recovered = attack.decrypt(iv, ct)

    print(f"원본:   {message}")
    print(f"복호화: {recovered}")
    assert recovered == message
    print("[+] 패딩 오라클 공격 성공!")
```

---

## 3. 타이밍 공격

```python
#!/usr/bin/env python3
"""타이밍 공격 — 비밀 비교 함수의 시간 차이 측정."""

import hmac
import statistics
import time


def measure_response_time(func, *args, rounds: int = 100) -> float:
    """함수 실행 시간 통계 측정."""
    times = []
    for _ in range(rounds):
        start = time.perf_counter_ns()
        func(*args)
        end = time.perf_counter_ns()
        times.append(end - start)
    return statistics.median(times)


def vulnerable_compare(a: bytes, b: bytes) -> bool:
    """취약한 비교 — 조기 종료 (타이밍 공격에 취약)."""
    if len(a) != len(b):
        return False
    for x, y in zip(a, b):
        if x != y:
            return False  # 첫 불일치 즉시 반환
    return True


def safe_compare(a: bytes, b: bytes) -> bool:
    """안전한 비교 — hmac.compare_digest 사용."""
    return hmac.compare_digest(a, b)


def timing_attack_local(
    secret: bytes,
    candidate_fn: callable,
    charset: bytes = b"0123456789abcdef",
    rounds: int = 200,
) -> bytes:
    """
    타이밍 공격으로 비밀 값 복구.
    candidate_fn(guess) → bool: 취약한 비교 함수
    """
    recovered = b""
    for pos in range(len(secret)):
        best_char = b"\x00"
        best_time = 0.0

        for char in charset:
            guess = recovered + bytes([char]) + b"\x00" * (len(secret) - pos - 1)
            elapsed = measure_response_time(candidate_fn, guess, rounds=rounds)

            if elapsed > best_time:
                best_time = elapsed
                best_char = bytes([char])

        recovered += best_char
        print(f"[*] 위치 {pos}: {best_char.decode()} (시간: {best_time:.1f}ns)")

    return recovered


def detect_timing_vulnerability(
    compare_fn: callable,
    test_secret: bytes = b"test_secret_12345",
    rounds: int = 500,
) -> bool:
    """타이밍 취약점 존재 여부 탐지."""
    # 첫 바이트 일치 vs 불일치 시간 비교
    correct_first = test_secret[:1] + b"\x00" * (len(test_secret) - 1)
    wrong_first   = b"\xff" + b"\x00" * (len(test_secret) - 1)

    time_correct = measure_response_time(compare_fn, test_secret, correct_first, rounds=rounds)
    time_wrong   = measure_response_time(compare_fn, test_secret, wrong_first, rounds=rounds)

    diff = abs(time_correct - time_wrong)
    print(f"  첫 바이트 일치 시간:   {time_correct:.1f}ns")
    print(f"  첫 바이트 불일치 시간: {time_wrong:.1f}ns")
    print(f"  시간 차이:             {diff:.1f}ns")

    return diff > 500  # 500ns 이상 차이 → 취약


if __name__ == "__main__":
    secret = b"deadbeef"
    print("=== 취약한 비교 함수 ===")
    vuln = detect_timing_vulnerability(vulnerable_compare, secret)
    print(f"  취약점 탐지: {'예' if vuln else '아니오'}\n")

    print("=== 안전한 비교 함수 ===")
    safe = detect_timing_vulnerability(safe_compare, secret)
    print(f"  취약점 탐지: {'예' if safe else '아니오'}")
```

---

## 4. Mersenne Twister 상태 복구

```python
#!/usr/bin/env python3
"""MT19937 난수 생성기 상태 복구 및 예측."""

import random
import struct


def untemper(y: int) -> int:
    """MT19937 템퍼링 역변환."""
    # 역변환 상수
    # y ^= y >> 18
    y ^= y >> 18
    # y ^= (y << 15) & 0xEFC60000
    y ^= (y << 15) & 0xEFC60000
    # y ^= (y << 7) & 0x9D2C5680 — 여러 단계 필요
    tmp = y
    for _ in range(4):
        tmp = y ^ ((tmp << 7) & 0x9D2C5680)
    y = tmp
    # y ^= y >> 11 — 여러 단계 필요
    tmp = y
    for _ in range(3):
        tmp = y ^ (tmp >> 11)
    return tmp


def clone_mt19937(outputs: list[int]) -> random.Random:
    """624개 출력으로 MT 상태 복제."""
    if len(outputs) < 624:
        raise ValueError("624개 이상의 출력 필요")

    state = [untemper(v) for v in outputs[:624]]

    # random.Random 객체에 상태 주입
    rng = random.Random()
    rng.setstate((3, tuple(state + [0]), None))
    return rng


def crack_mt19937_seed_time(target_output: int, time_window: int = 1000) -> int | None:
    """
    타임스탬프 시드 크래킹.
    현재 시간 기준 ±time_window 초 범위에서 시드 탐색.
    """
    import time
    now = int(time.time())

    for seed in range(now - time_window, now + time_window):
        rng = random.Random(seed)
        if rng.getrandbits(32) == target_output:
            return seed
    return None


if __name__ == "__main__":
    # MT 상태 복제 시연
    rng = random.Random()
    outputs = [rng.getrandbits(32) for _ in range(624)]

    cloned = clone_mt19937(outputs)
    next_original = rng.getrandbits(32)
    next_cloned   = cloned.getrandbits(32)

    print(f"원본 다음 값:  {next_original}")
    print(f"복제된 다음 값: {next_cloned}")
    assert next_original == next_cloned
    print("[+] MT19937 상태 복제 성공!")
```

---

## 5. 취약점 요약 표

| 취약점 | 원인 | 탐지 방법 | 방어 대책 |
|--------|------|-----------|-----------|
| 패딩 오라클 | CBC 패딩 에러 노출 | 응답 내용/시간 차이 | AEAD 모드 사용 (GCM) |
| 타이밍 공격 | 조기 종료 비교 | 시간 통계 분석 | hmac.compare_digest |
| MT 예측 | 624개 출력으로 상태 복구 | 출력 수집 | secrets 모듈 사용 |
| 시드 예측 | 타임스탬프 시드 | 브루트포스 | os.urandom() |
| Nonce 재사용 | CTR/GCM IV 중복 | 암호문 XOR | 랜덤 12바이트 nonce |

---

## 5.5 포스트퀀텀 하이브리드 암호 다운그레이드 공격

TLS 1.3에 도입 중인 하이브리드 키 교환(X25519 + ML-KEM/Kyber)은 양자 컴퓨터가 등장해도 안전하도록 고전 알고리즘과 포스트퀀텀 알고리즘의 결과를 함께 섞는다. 그런데 클라이언트·서버가 하이브리드와 순수 고전 알고리즘을 **둘 다 지원**하면, 중간자가 `ClientHello`의 `supported_groups` 확장에서 하이브리드 그룹을 제거해 순수 X25519로 강제 다운그레이드시킬 수 있다 — TLS 자체엔 무결성 보호가 있지만, 하이브리드를 지원하지 않는 레거시 미들박스가 많아 다운그레이드 방지가 항상 강제되진 않는다.

```python
#!/usr/bin/env python3
"""ClientHello의 supported_groups에서 PQ 하이브리드 그룹 존재 여부 점검."""
from scapy.all import rdpcap, TLSClientHello  # scapy-ssl_tls 또는 scapy-tls 확장 필요

HYBRID_GROUP_IDS = {
    0x11EC: "X25519MLKEM768",   # IANA 임시 코드포인트 (초안 버전에 따라 변동)
    0x6399: "X25519Kyber768Draft00",
}


def check_pcap(path: str) -> None:
    packets = rdpcap(path)
    for pkt in packets:
        if not pkt.haslayer(TLSClientHello):
            continue
        hello = pkt[TLSClientHello]
        groups = getattr(hello, "supported_groups", []) or []
        hybrid_present = [HYBRID_GROUP_IDS[g] for g in groups if g in HYBRID_GROUP_IDS]
        if hybrid_present:
            print(f"[+] 하이브리드 PQ 그룹 제안됨: {hybrid_present}")
        else:
            print("[!] 하이브리드 PQ 그룹 없음 — 순수 고전 알고리즘만 제안 (다운그레이드 여지)")


if __name__ == "__main__":
    check_pcap("client_hello_capture.pcap")
```

**탐지/방어**: 서버 측에서는 정책으로 하이브리드 그룹이 없는 `ClientHello`를 거부하거나 경고 로그를 남기도록 설정하고(Chrome/BoringSSL은 2024년부터 X25519Kyber768을 기본 제안), 조직 내부 트래픽 모니터링에서는 시간에 따라 하이브리드 그룹 사용 비율이 갑자기 떨어지는 구간을 다운그레이드 공격 또는 중간 프록시 장비 문제의 신호로 본다.

---

<!-- detect-validate-16 -->
## 암호 구현 취약점 탐지와 방어 검증

구현 공격은 *오류 오라클·타이밍 차·예측 가능 PRNG·IV 재사용*을 노린다. 방어자는 **AEAD·상수시간 비교·CSPRNG·랜덤 IV 가 실제 코드에 적용됐는가**를 검증해야 한다. 실습은 **소유 코드·시스템**에서만.

### 공격 → 노리는 약점 → 1차 통제(방어자) → 탐지 신호

| 기법 | 노리는 약점 | 1차 통제(방어자) | 탐지 신호 |
|---|---|---|---|
| 패딩 오라클 | 오류 구분 가능 | AEAD(GCM)·일정 응답 | 동일 길이 대량 변조 요청 |
| 타이밍 사이드채널 | 비교 시간 차 | 상수시간 비교(compare_digest) | 응답시간이 입력과 상관 |
| 약한 PRNG(MT19937) 상태복구 | 예측 가능 출력 | CSPRNG(secrets) | 예측 가능·연속 토큰 |
| 논스/IV 재사용 | 고정 IV | 랜덤 IV·카운터 모드 | 동일 IV 반복 |

### 방어 검증 (직접 확인)

```python
# 토큰 비교에 상수시간 함수를 쓰는지 + 예측 가능 PRNG 미사용 확인(소유 코드)
import re, pathlib

src = pathlib.Path("app.py").read_text()
if re.search(r"\brandom\.(random|randint|getrandbits|choice)\b", src):
    print("경고: 보안 토큰에 예측 가능 PRNG(random) 사용 의심 → secrets 모듈로 교체")
if "==" in src and "compare_digest" not in src:
    print("경고: 상수시간 비교(hmac.compare_digest) 미사용 의심 → 타이밍 공격 표면")
```

> 구현 방어는 *코드가 실제로 무엇을 호출하는가*에 달려 있다 — "안전하게 짰다"와 "AEAD·상수시간 비교·CSPRNG 를 실제로 쓴다"는 다르다. 소유 코드를 정적으로 점검하고 통제 환경에서 패딩/타이밍 PoC 로 회귀를 막는다([[08_Python_Hacking]], [[04_Reverse_Engineering]], [[68_Purple_Team]]).

---

<a name="english"></a>

# Crypto Implementation Attacks — Padding Oracle, Timing Attacks, Weak RNG

## 1. Cryptographic Implementation Vulnerability Classification

```
Crypto Implementation Vulnerabilities
    │
    ├── Padding Oracle Attack
    │     - Leaking CBC mode padding validation errors
    │     - Byte-by-byte plaintext recovery
    │
    ├── Timing Attack
    │     - Early termination during secret comparison
    │     - Information leakage via execution time differences
    │
    ├── Weak Random Number Generator
    │     - Mersenne Twister state recovery
    │     - Seed prediction (timestamp-based)
    │
    └── IV/Nonce Reuse
          - CTR/GCM mode nonce reuse
          - Recovering two messages via XOR of plaintexts
```

---

## 2. Padding Oracle Attack

```python
#!/usr/bin/env python3
"""CBC padding oracle attack implementation."""

import os
from typing import Callable

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


class PaddingOracleAttack:
    """CBC Padding Oracle Attack — byte-by-byte plaintext recovery."""

    def __init__(self, oracle: Callable[[bytes, bytes], bool], block_size: int = 16) -> None:
        self.oracle = oracle
        self.block_size = block_size

    def decrypt_block(self, prev_block: bytes, curr_block: bytes) -> bytes:
        """Decrypt a single block."""
        bs = self.block_size
        intermediate = bytearray(bs)

        for byte_pos in range(bs - 1, -1, -1):
            pad_byte = bs - byte_pos
            crafted = bytearray(bs)

            # Build padding using already-known bytes
            for k in range(byte_pos + 1, bs):
                crafted[k] = intermediate[k] ^ pad_byte

            found = False
            for guess in range(256):
                crafted[byte_pos] = guess
                if self.oracle(bytes(crafted), curr_block):
                    intermediate[byte_pos] = guess ^ pad_byte
                    found = True
                    break

            if not found:
                raise ValueError(f"Failed to decrypt byte {byte_pos}")

        # Plaintext = intermediate XOR original previous block
        return bytes(intermediate[i] ^ prev_block[i] for i in range(bs))

    def decrypt(self, iv: bytes, ciphertext: bytes) -> bytes:
        """Decrypt the full ciphertext."""
        bs = self.block_size
        blocks = [iv] + [ciphertext[i:i+bs] for i in range(0, len(ciphertext), bs)]
        plaintext = b""

        for i in range(1, len(blocks)):
            plaintext += self.decrypt_block(blocks[i-1], blocks[i])

        # Remove PKCS#7 padding
        pad_len = plaintext[-1]
        if 1 <= pad_len <= bs:
            plaintext = plaintext[:-pad_len]
        return plaintext


def simulate_oracle(key: bytes) -> Callable[[bytes, bytes], bool]:
    """Create a padding oracle for testing."""
    def oracle(iv: bytes, ciphertext: bytes) -> bool:
        try:
            cipher = AES.new(key, AES.MODE_CBC, iv)
            unpad(cipher.decrypt(ciphertext), 16)
            return True
        except ValueError:
            return False
    return oracle


if __name__ == "__main__":
    key = os.urandom(16)
    iv  = os.urandom(16)

    message = b"Secret: admin=true"
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(message, 16))

    oracle = simulate_oracle(key)
    attack = PaddingOracleAttack(oracle)
    recovered = attack.decrypt(iv, ct)

    print(f"Original:  {message}")
    print(f"Decrypted: {recovered}")
    assert recovered == message
    print("[+] Padding oracle attack successful!")
```

---

## 3. Timing Attack

```python
#!/usr/bin/env python3
"""Timing attack — measuring time differences in secret comparison functions."""

import hmac
import statistics
import time


def measure_response_time(func, *args, rounds: int = 100) -> float:
    """Measure function execution time statistics."""
    times = []
    for _ in range(rounds):
        start = time.perf_counter_ns()
        func(*args)
        end = time.perf_counter_ns()
        times.append(end - start)
    return statistics.median(times)


def vulnerable_compare(a: bytes, b: bytes) -> bool:
    """Vulnerable comparison — early termination (susceptible to timing attacks)."""
    if len(a) != len(b):
        return False
    for x, y in zip(a, b):
        if x != y:
            return False  # Return immediately on first mismatch
    return True


def safe_compare(a: bytes, b: bytes) -> bool:
    """Safe comparison — uses hmac.compare_digest."""
    return hmac.compare_digest(a, b)


def timing_attack_local(
    secret: bytes,
    candidate_fn: callable,
    charset: bytes = b"0123456789abcdef",
    rounds: int = 200,
) -> bytes:
    """
    Recover secret value via timing attack.
    candidate_fn(guess) → bool: vulnerable comparison function
    """
    recovered = b""
    for pos in range(len(secret)):
        best_char = b"\x00"
        best_time = 0.0

        for char in charset:
            guess = recovered + bytes([char]) + b"\x00" * (len(secret) - pos - 1)
            elapsed = measure_response_time(candidate_fn, guess, rounds=rounds)

            if elapsed > best_time:
                best_time = elapsed
                best_char = bytes([char])

        recovered += best_char
        print(f"[*] Position {pos}: {best_char.decode()} (time: {best_time:.1f}ns)")

    return recovered


def detect_timing_vulnerability(
    compare_fn: callable,
    test_secret: bytes = b"test_secret_12345",
    rounds: int = 500,
) -> bool:
    """Detect whether a timing vulnerability exists."""
    # Compare timing: first byte match vs mismatch
    correct_first = test_secret[:1] + b"\x00" * (len(test_secret) - 1)
    wrong_first   = b"\xff" + b"\x00" * (len(test_secret) - 1)

    time_correct = measure_response_time(compare_fn, test_secret, correct_first, rounds=rounds)
    time_wrong   = measure_response_time(compare_fn, test_secret, wrong_first, rounds=rounds)

    diff = abs(time_correct - time_wrong)
    print(f"  First byte match time:    {time_correct:.1f}ns")
    print(f"  First byte mismatch time: {time_wrong:.1f}ns")
    print(f"  Time difference:          {diff:.1f}ns")

    return diff > 500  # Difference > 500ns → vulnerable


if __name__ == "__main__":
    secret = b"deadbeef"
    print("=== Vulnerable comparison function ===")
    vuln = detect_timing_vulnerability(vulnerable_compare, secret)
    print(f"  Vulnerability detected: {'Yes' if vuln else 'No'}\n")

    print("=== Safe comparison function ===")
    safe = detect_timing_vulnerability(safe_compare, secret)
    print(f"  Vulnerability detected: {'Yes' if safe else 'No'}")
```

---

## 4. Mersenne Twister State Recovery

```python
#!/usr/bin/env python3
"""MT19937 RNG state recovery and prediction."""

import random
import struct


def untemper(y: int) -> int:
    """Reverse the MT19937 tempering transformation."""
    # Reverse y ^= y >> 18
    y ^= y >> 18
    # Reverse y ^= (y << 15) & 0xEFC60000
    y ^= (y << 15) & 0xEFC60000
    # Reverse y ^= (y << 7) & 0x9D2C5680 — requires multiple steps
    tmp = y
    for _ in range(4):
        tmp = y ^ ((tmp << 7) & 0x9D2C5680)
    y = tmp
    # Reverse y ^= y >> 11 — requires multiple steps
    tmp = y
    for _ in range(3):
        tmp = y ^ (tmp >> 11)
    return tmp


def clone_mt19937(outputs: list[int]) -> random.Random:
    """Clone MT state from 624 outputs."""
    if len(outputs) < 624:
        raise ValueError("Need at least 624 outputs")

    state = [untemper(v) for v in outputs[:624]]

    # Inject state into random.Random object
    rng = random.Random()
    rng.setstate((3, tuple(state + [0]), None))
    return rng


def crack_mt19937_seed_time(target_output: int, time_window: int = 1000) -> int | None:
    """
    Crack timestamp-based seed.
    Search for seed in ±time_window seconds from current time.
    """
    import time
    now = int(time.time())

    for seed in range(now - time_window, now + time_window):
        rng = random.Random(seed)
        if rng.getrandbits(32) == target_output:
            return seed
    return None


if __name__ == "__main__":
    # Demonstrate MT state cloning
    rng = random.Random()
    outputs = [rng.getrandbits(32) for _ in range(624)]

    cloned = clone_mt19937(outputs)
    next_original = rng.getrandbits(32)
    next_cloned   = cloned.getrandbits(32)

    print(f"Original next value: {next_original}")
    print(f"Cloned next value:   {next_cloned}")
    assert next_original == next_cloned
    print("[+] MT19937 state cloning successful!")
```

---

## 5. Vulnerability Summary Table

| Vulnerability | Cause | Detection Method | Countermeasure |
|---------------|-------|-----------------|----------------|
| Padding oracle | CBC padding error exposure | Response content/time difference | Use AEAD mode (GCM) |
| Timing attack | Early termination comparison | Statistical time analysis | hmac.compare_digest |
| MT prediction | State recovery from 624 outputs | Collect outputs | Use secrets module |
| Seed prediction | Timestamp-based seed | Brute force | os.urandom() |
| Nonce reuse | CTR/GCM IV duplication | XOR of ciphertexts | Random 12-byte nonce |

---

## 5.5 Post-Quantum Hybrid Cryptography Downgrade Attacks

The hybrid key exchange being rolled out in TLS 1.3 (X25519 + ML-KEM/Kyber) mixes a classical and a post-quantum algorithm's outputs so the connection stays safe even once quantum computers arrive. But when a client and server both support hybrid *and* pure-classical groups, a man-in-the-middle can strip the hybrid group out of the `ClientHello`'s `supported_groups` extension and force a downgrade to plain X25519 — TLS itself has integrity protection, but many legacy middleboxes don't understand hybrid groups yet, so downgrade prevention isn't always enforced end to end.

```python
#!/usr/bin/env python3
"""Check whether a ClientHello's supported_groups actually proposes a PQ hybrid group."""
from scapy.all import rdpcap, TLSClientHello  # requires scapy-ssl_tls / scapy-tls extension

HYBRID_GROUP_IDS = {
    0x11EC: "X25519MLKEM768",   # IANA provisional codepoint (varies by draft version)
    0x6399: "X25519Kyber768Draft00",
}


def check_pcap(path: str) -> None:
    packets = rdpcap(path)
    for pkt in packets:
        if not pkt.haslayer(TLSClientHello):
            continue
        hello = pkt[TLSClientHello]
        groups = getattr(hello, "supported_groups", []) or []
        hybrid_present = [HYBRID_GROUP_IDS[g] for g in groups if g in HYBRID_GROUP_IDS]
        if hybrid_present:
            print(f"[+] Hybrid PQ group proposed: {hybrid_present}")
        else:
            print("[!] No hybrid PQ group — only classical algorithms proposed (downgrade risk)")


if __name__ == "__main__":
    check_pcap("client_hello_capture.pcap")
```

**Detection/Defense**: on the server side, enforce a policy that rejects or at least logs a warning for any `ClientHello` missing a hybrid group (Chrome/BoringSSL has proposed X25519Kyber768 by default since 2024). In network monitoring, treat a sudden drop in the proportion of hybrid-group connections over time as a signal of either a downgrade attack or a misbehaving middlebox on the path.

---

<!-- detect-validate-16 -->
## Cryptographic Implementation Vulnerability Detection and Defense Validation

Implementation attacks target *error oracles, timing differences, predictable PRNGs, and IV reuse*. Defenders must verify **whether AEAD, constant-time comparison, CSPRNG, and random IVs are actually in the code**. Practice only on **owned code/systems**.

### Attack -> Targeted weakness -> Primary control (defender) -> Detection signal

| Technique | Targeted weakness | Primary control (defender) | Detection signal |
|---|---|---|---|
| Padding oracle | Distinguishable errors | AEAD (GCM), constant response | Mass equal-length mutated requests |
| Timing side channel | Comparison time difference | Constant-time compare (compare_digest) | Response time correlates with input |
| Weak PRNG (MT19937) state recovery | Predictable output | CSPRNG (secrets) | Predictable/sequential tokens |
| Nonce/IV reuse | Fixed IV | Random IV, counter mode | Same IV repeated |

### Defense validation (verify directly)

```python
# Check that token comparison uses a constant-time function + no predictable PRNG (own code)
import re, pathlib

src = pathlib.Path("app.py").read_text()
if re.search(r"\brandom\.(random|randint|getrandbits|choice)\b", src):
    print("Warning: predictable PRNG (random) suspected for security tokens -> switch to secrets")
if "==" in src and "compare_digest" not in src:
    print("Warning: constant-time compare (hmac.compare_digest) not used -> timing-attack surface")
```

> Implementation defense depends on *what the code actually calls* -- "we wrote it safely" differs from "we actually use AEAD, constant-time compare, and CSPRNG". Statically inspect owned code and use padding/timing PoCs in a controlled environment to prevent regressions ([[08_Python_Hacking]], [[04_Reverse_Engineering]], [[68_Purple_Team]]).
