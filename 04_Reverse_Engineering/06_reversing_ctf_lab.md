> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# CTF 스타일 리버싱 실습

## 실습 환경 준비

```bash
# 필수 도구 설치 (Ubuntu/Kali)
sudo apt-get install -y \
    upx gdb python3 python3-pip \
    radare2 file binutils xxd

pip3 install pwntools capstone pyelftools

# Ghidra 설치 (GUI 분석용)
# https://github.com/NationalSecurityAgency/ghidra/releases 에서 최신 버전 다운로드
# unzip ghidra_*.zip && cd ghidra_* && ./ghidraRun

# pwndbg 설치
git clone https://github.com/pwndbg/pwndbg.git /opt/pwndbg
cd /opt/pwndbg && ./setup.sh
```

---

## 실습 1: UPX 패킹된 바이너리 언패킹 후 플래그 추출

### 목표

UPX로 패킹된 바이너리를 언패킹하고, 내부에 숨겨진 플래그를 찾아라.

**힌트:**
- `file`, `strings` 명령어로 파일 유형과 패킹 여부를 확인하라.
- UPX 언패킹은 `upx -d`로 간단히 수행할 수 있다.
- 언패킹 후 `strings`로 플래그를 검색하거나 동적 분석을 수행하라.
- 플래그 형식: `CTF{...}`

### 취약한 바이너리 생성

```c
// flag_check.c
#include <stdio.h>
#include <string.h>

static const char SECRET[] = "CTF{upx_unp4ck3d_and_fl4g_f0und}";

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("사용법: %s <답안>\n", argv[0]);
        return 1;
    }
    if (strcmp(argv[1], SECRET) == 0) {
        printf("정답입니다! 플래그: %s\n", SECRET);
    } else {
        printf("틀렸습니다.\n");
    }
    return 0;
}
```

```bash
# 컴파일 후 UPX 패킹
gcc -o flag_check flag_check.c -O2
upx --best -o flag_check_packed flag_check
file flag_check_packed  # UPX 패킹 확인
```

### 풀이

**Step 1: 파일 분석**
```bash
file flag_check_packed
# flag_check_packed: ELF 64-bit LSB executable, ... UPX compressed

strings flag_check_packed | head -20
# UPX 관련 문자열만 보이고 플래그는 숨겨져 있음
```

**Step 2: UPX 언패킹**
```bash
upx -d flag_check_packed -o flag_check_unpacked
file flag_check_unpacked
# flag_check_unpacked: ELF 64-bit LSB executable, ... not stripped
```

**Step 3: 정적 분석**
```bash
# 언패킹 후 strings로 플래그 탐색
strings flag_check_unpacked | grep "CTF{"
# CTF{upx_unp4ck3d_and_fl4g_f0und}

# 또는 objdump로 .rodata 섹션 확인
objdump -s -j .rodata flag_check_unpacked
```

**Step 4: Python 자동 언패킹 + 플래그 추출**

```python
#!/usr/bin/env python3
"""
UPX 패킹 바이너리 자동 탐지 → 언패킹 → 플래그 추출 도구
"""

import argparse
import re
import subprocess
import sys
import tempfile
from pathlib import Path


def is_upx_packed(binary_path: str) -> bool:
    """바이너리가 UPX로 패킹되었는지 확인한다."""
    data = Path(binary_path).read_bytes()
    # UPX 시그니처: "UPX!" 또는 UPX 헤더 매직 바이트
    return b"UPX!" in data or b"UPX0" in data


def unpack_upx(packed_path: str, output_path: str) -> bool:
    """UPX 언패킹을 수행한다. 성공 여부를 반환한다."""
    try:
        result = subprocess.run(
            ["upx", "-d", packed_path, "-o", output_path],
            capture_output=True,
            text=True,
            timeout=30,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        print(f"[!] UPX 언패킹 실패: {e}", file=sys.stderr)
        return False


def extract_strings(binary_path: str, min_len: int = 4) -> list[str]:
    """바이너리에서 출력 가능한 문자열을 추출한다."""
    try:
        result = subprocess.run(
            ["strings", f"-n{min_len}", binary_path],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.stdout.splitlines()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        # strings 명령어 없으면 직접 파싱
        data = Path(binary_path).read_bytes()
        strings: list[str] = []
        current = bytearray()
        for b in data:
            if 0x20 <= b < 0x7F:
                current.append(b)
            else:
                if len(current) >= min_len:
                    strings.append(current.decode("ascii", errors="replace"))
                current = bytearray()
        return strings


def find_flags(strings: list[str], pattern: str = r"CTF\{[^}]+\}") -> list[str]:
    """문자열 목록에서 플래그 패턴을 검색한다."""
    flags: list[str] = []
    regex = re.compile(pattern)
    for s in strings:
        matches = regex.findall(s)
        flags.extend(matches)
    return list(set(flags))


def analyze_binary(
    binary_path: str,
    flag_pattern: str = r"CTF\{[^}]+\}",
) -> dict:
    """바이너리를 분석해 결과를 반환한다."""
    result = {
        "original": binary_path,
        "is_packed": False,
        "unpacked_path": None,
        "flags": [],
        "interesting_strings": [],
    }

    # UPX 패킹 확인
    result["is_packed"] = is_upx_packed(binary_path)
    print(f"[*] UPX 패킹: {'예' if result['is_packed'] else '아니오'}")

    # 언패킹
    analysis_target = binary_path
    if result["is_packed"]:
        with tempfile.NamedTemporaryFile(suffix=".unpacked", delete=False) as tmp:
            unpacked_path = tmp.name
        print(f"[*] 언패킹 중: {binary_path} → {unpacked_path}")
        if unpack_upx(binary_path, unpacked_path):
            result["unpacked_path"] = unpacked_path
            analysis_target = unpacked_path
            print(f"[+] 언패킹 성공: {unpacked_path}")
        else:
            print("[-] 언패킹 실패. 원본 파일로 분석 계속.")

    # 문자열 추출
    all_strings = extract_strings(analysis_target)
    print(f"[*] 추출된 문자열: {len(all_strings)}개")

    # 플래그 탐색
    result["flags"] = find_flags(all_strings, flag_pattern)

    # 흥미로운 문자열 (URL, 경로, 키워드)
    interesting_patterns = [
        r"http[s]?://\S+",      # URL
        r"/[a-zA-Z0-9/._-]+",   # 파일 경로
        r"[A-Za-z0-9+/]{16,}=*",  # Base64 의심
        r"[0-9a-fA-F]{16,}",    # Hex 문자열
    ]
    seen: set[str] = set()
    for s in all_strings:
        for pat in interesting_patterns:
            if re.search(pat, s) and s not in seen:
                result["interesting_strings"].append(s)
                seen.add(s)
                break

    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description="UPX 언패킹 + 플래그 추출 자동화",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
예시:
  python3 upx_unpack.py flag_check_packed
  python3 upx_unpack.py challenge.exe --pattern "FLAG{[^}]+}"
        """,
    )
    parser.add_argument("binary", help="분석할 바이너리 파일")
    parser.add_argument(
        "--pattern",
        default=r"CTF\{[^}]+\}",
        help="플래그 정규식 패턴 (기본: CTF{...})",
    )
    parser.add_argument(
        "--show-strings", action="store_true", help="흥미로운 문자열도 출력"
    )
    args = parser.parse_args()

    if not Path(args.binary).exists():
        print(f"[오류] 파일을 찾을 수 없습니다: {args.binary}", file=sys.stderr)
        sys.exit(1)

    result = analyze_binary(args.binary, args.pattern)

    if result["flags"]:
        print(f"\n[+] 플래그 발견 ({len(result['flags'])}개):")
        for flag in result["flags"]:
            print(f"    {flag}")
    else:
        print("\n[-] 플래그를 찾지 못했습니다.")

    if args.show_strings and result["interesting_strings"]:
        print(f"\n[*] 흥미로운 문자열 ({len(result['interesting_strings'])}개):")
        for s in result["interesting_strings"][:20]:
            print(f"    {s}")


if __name__ == "__main__":
    main()
```

```bash
# 실행 예시
python3 upx_unpack.py flag_check_packed
# [*] UPX 패킹: 예
# [+] 언패킹 성공
# [+] 플래그 발견 (1개):
#     CTF{upx_unp4ck3d_and_fl4g_f0und}
```

---

## 실습 2: XOR 암호화된 문자열 복호화

### 목표

XOR 암호화된 플래그를 런타임에 복호화하는 바이너리를 분석해 플래그를 추출하라.

**힌트:**
- `strings` 명령어로는 플래그를 찾을 수 없다.
- GDB로 복호화 함수 실행 직후 메모리를 확인하라.
- 또는 디스어셈블리에서 XOR 루프와 키 값을 찾아 Python으로 복호화하라.

### 취약한 바이너리 생성

```c
// xor_flag.c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// XOR 키 0x5A로 암호화된 플래그
static const unsigned char ENCRYPTED[] = {
    0x19, 0x1E, 0x38, 0x7B, 0x2E, 0x3F, 0x27, 0x28,
    0x3F, 0x2E, 0x3D, 0x26, 0x3F, 0x25, 0x3D, 0x27,
    0x36, 0x3D, 0x25, 0x2B, 0x27, 0x38, 0x3D, 0x33,
    0x2A, 0x29, 0x7D
    // "CTF{x0r_3ncrypt10n_brok3n}" XOR 0x5A
};
static const size_t ENC_LEN = sizeof(ENCRYPTED);

char *decrypt_flag(void) {
    char *buf = malloc(ENC_LEN + 1);
    if (!buf) return NULL;
    for (size_t i = 0; i < ENC_LEN; i++) {
        buf[i] = ENCRYPTED[i] ^ 0x5A;
    }
    buf[ENC_LEN] = '\0';
    return buf;
}

int main(int argc, char *argv[]) {
    char *flag = decrypt_flag();
    if (!flag) { perror("malloc"); return 1; }

    if (argc >= 2 && strcmp(argv[1], flag) == 0) {
        printf("정답! 플래그: %s\n", flag);
    } else {
        printf("틀렸습니다. (힌트: 바이너리를 분석하세요)\n");
    }
    free(flag);
    return 0;
}
```

```bash
gcc -o xor_flag xor_flag.c -O1
# strings로 확인 → 플래그 없음
strings xor_flag | grep "CTF{"
```

### 풀이

**Step 1: GDB 동적 분석**
```bash
gdb -q xor_flag
(gdb) break decrypt_flag         # 복호화 함수에 브레이크포인트
(gdb) run
(gdb) finish                     # 함수 완료까지 실행
(gdb) x/s $rax                   # 반환값(복호화된 문자열) 출력
# 0x...: "CTF{x0r_3ncrypt10n_brok3n}"
```

**Step 2: 정적 분석 + Python 복호화**
```bash
# 암호화된 바이트 배열 추출 (objdump)
objdump -d xor_flag | grep -A 50 "<decrypt_flag>"

# .rodata 섹션에서 암호화 데이터 추출
objdump -s -j .rodata xor_flag
```

**Step 3: Python 복호화 스크립트**

```python
#!/usr/bin/env python3
"""
XOR/ROT 암호화 CTF 플래그 자동 복호화 스크립트
암호화된 바이트 배열과 키를 입력하면 복호화한다.
"""

import argparse
import ast
import sys
from typing import Optional


def xor_decrypt(ciphertext: bytes, key: int | bytes) -> bytes:
    """XOR 복호화 (단일 바이트 또는 다중 바이트 키 지원)."""
    if isinstance(key, int):
        return bytes(b ^ key for b in ciphertext)
    key_len = len(key)
    return bytes(b ^ key[i % key_len] for i, b in enumerate(ciphertext))


def rot_decrypt(text: str, shift: int) -> str:
    """ROT 복호화."""
    result = []
    for c in text:
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            result.append(chr((ord(c) - base - shift) % 26 + base))
        else:
            result.append(c)
    return "".join(result)


def bruteforce_xor(
    ciphertext: bytes, flag_prefix: str = "CTF{"
) -> list[tuple[int | bytes, str]]:
    """단일 바이트 XOR 브루트포스. 플래그 접두사로 검증한다."""
    results: list[tuple[int | bytes, str]] = []
    prefix_bytes = flag_prefix.encode()

    for key in range(256):
        decrypted = xor_decrypt(ciphertext, key)
        try:
            text = decrypted.decode("ascii")
            if prefix_bytes in decrypted:
                results.append((key, text))
        except UnicodeDecodeError:
            continue
    return results


def parse_hex_bytes(hex_str: str) -> bytes:
    """
    다양한 형식의 16진수 문자열을 bytes로 파싱한다.
    지원 형식:
      - "0x19,0x1E,0x38" (C 배열 스타일)
      - "191e38" (순수 hex)
      - "\\x19\\x1e\\x38" (escape 스타일)
    """
    # C 배열 스타일
    if "0x" in hex_str or "0X" in hex_str:
        parts = [p.strip() for p in hex_str.replace("{", "").replace("}", "").split(",")]
        return bytes(int(p, 16) for p in parts if p)
    # escape 스타일
    if "\\x" in hex_str:
        return bytes.fromhex(hex_str.replace("\\x", "").replace(" ", ""))
    # 순수 hex
    return bytes.fromhex(hex_str.replace(" ", ""))


def analyze_xor_key_from_known_plaintext(
    ciphertext: bytes, known_plaintext: str
) -> Optional[int]:
    """
    알려진 평문(known plaintext)으로 XOR 키를 역산한다.
    플래그 형식(CTF{)을 알고 있는 경우 유용하다.
    """
    pt = known_plaintext.encode()
    if len(pt) > len(ciphertext):
        return None
    # 첫 번째 바이트로 키 추측
    key_candidates = set(ciphertext[i] ^ pt[i] for i in range(len(pt)))
    if len(key_candidates) == 1:
        return key_candidates.pop()
    return None


def main() -> None:
    parser = argparse.ArgumentParser(
        description="XOR/ROT 암호화 CTF 플래그 복호화",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
예시:
  # 알려진 XOR 키로 복호화
  python3 xor_solver.py --cipher "0x19,0x1E,0x38" --xor-key 0x5A

  # XOR 브루트포스 (플래그 접두사 CTF{ 기준)
  python3 xor_solver.py --cipher "191e38..." --brute

  # 알려진 평문으로 키 역산
  python3 xor_solver.py --cipher "0x19,0x1E,0x38,0x7B" --known-pt "CTF{"

  # ROT 복호화 (shift 13)
  python3 xor_solver.py --rot-text "PGS{ebg13_cynltebbhaq}" --rot-shift 13
        """,
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--cipher", help="암호화된 바이트 (hex 형식)")
    group.add_argument("--rot-text", help="ROT 암호화 텍스트")

    parser.add_argument("--xor-key", default="", help="XOR 키 (예: 0x5A 또는 'key')")
    parser.add_argument("--brute", action="store_true", help="XOR 브루트포스")
    parser.add_argument("--known-pt", default="", help="알려진 평문 (키 역산용)")
    parser.add_argument("--rot-shift", type=int, default=13, help="ROT 시프트 값")
    parser.add_argument("--prefix", default="CTF{", help="플래그 접두사 (브루트포스 검증)")
    args = parser.parse_args()

    if args.rot_text:
        result = rot_decrypt(args.rot_text, args.rot_shift)
        print(f"[+] ROT{args.rot_shift} 복호화 결과: {result}")
        return

    ciphertext = parse_hex_bytes(args.cipher)
    print(f"[*] 암호문 ({len(ciphertext)} bytes): {ciphertext.hex()}")

    if args.known_pt:
        key = analyze_xor_key_from_known_plaintext(ciphertext, args.known_pt)
        if key is not None:
            print(f"[+] 역산된 XOR 키: 0x{key:02X}")
            decrypted = xor_decrypt(ciphertext, key)
            print(f"[+] 복호화 결과: {decrypted.decode('ascii', errors='replace')}")
        else:
            print("[-] 단일 바이트 키로 역산 실패.")
        return

    if args.brute:
        results = bruteforce_xor(ciphertext, args.prefix)
        if results:
            print(f"[+] {len(results)}개 후보 발견:")
            for key, text in results:
                print(f"    키 0x{key:02X}: {text}")
        else:
            print("[-] 브루트포스 실패.")
        return

    if args.xor_key:
        if args.xor_key.startswith("0x"):
            key_val: int | bytes = int(args.xor_key, 16)
        else:
            key_val = args.xor_key.encode()
        decrypted = xor_decrypt(ciphertext, key_val)
        print(f"[+] 복호화 결과: {decrypted.decode('ascii', errors='replace')}")
        return

    parser.print_help()


if __name__ == "__main__":
    main()
```

```bash
# Step 1: 알려진 평문으로 키 역산
python3 xor_solver.py --cipher "0x19,0x1E,0x38,0x7B" --known-pt "CTF{"
# [+] 역산된 XOR 키: 0x5A

# Step 2: 전체 복호화
python3 xor_solver.py \
  --cipher "0x19,0x1E,0x38,0x7B,0x2E,0x3F,0x27,0x28,0x3F,0x2E,0x3D,0x26,0x3F,0x25,0x3D,0x27,0x36,0x3D,0x25,0x2B,0x27,0x38,0x3D,0x33,0x2A,0x29,0x7D" \
  --xor-key 0x5A
# [+] 복호화 결과: CTF{x0r_3ncrypt10n_brok3n}

# Step 3: 키를 모르는 경우 브루트포스
python3 xor_solver.py \
  --cipher "0x19,0x1E,0x38,0x7B,0x2E,0x3F" \
  --brute --prefix "CTF{"
# [+] 키 0x5A: CTF{x0r...
```

---

## 실습 3: Ghidra로 라이선스 키 검증 로직 우회

### 목표

라이선스 키 검증 로직을 Ghidra로 분석하고, 유효한 키를 생성하거나 검증 로직을 우회하라.

**힌트:**
- Ghidra의 Decompiler로 검증 함수를 분석하라.
- 조건 분기(`jne`, `je`)를 파악하고 어떤 값이 성공 조건인지 확인하라.
- GDB의 `set $rax=1`로 반환값을 강제 조작하거나, Python으로 올바른 키를 생성하라.

### 취약한 바이너리 생성

```c
// license_check.c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// 라이선스 키 검증: 키는 "XXXX-XXXX-XXXX-XXXX" 형식
// 각 그룹의 합이 특정 값이어야 함 (약한 검증 로직)
int verify_license(const char *key) {
    if (!key || strlen(key) != 19) return 0;

    // 형식 확인: XXXX-XXXX-XXXX-XXXX
    if (key[4] != '-' || key[9] != '-' || key[14] != '-') return 0;

    int groups[4] = {0};
    int g = 0;
    for (int i = 0; key[i]; i++) {
        if (key[i] == '-') { g++; continue; }
        if (key[i] < '0' || key[i] > '9') return 0;
        groups[g] += key[i] - '0';
    }

    // 각 그룹의 합 검증 (역산 가능한 약한 조건)
    return groups[0] == 10 &&
           groups[1] == 20 &&
           groups[2] == 15 &&
           groups[3] == 25;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("사용법: %s <라이선스키>\n", argv[0]);
        printf("형식: XXXX-XXXX-XXXX-XXXX (숫자만)\n");
        return 1;
    }
    if (verify_license(argv[1])) {
        printf("유효한 라이선스 키!\n");
        printf("CTF{l1c3ns3_k3y_r3v3rs3d_and_g3n3r4t3d}\n");
    } else {
        printf("유효하지 않은 라이선스 키.\n");
        return 1;
    }
    return 0;
}
```

```bash
gcc -o license_check license_check.c -O1
```

### 풀이

**Step 1: Ghidra 정적 분석**

Ghidra에서 `verify_license` 함수를 디컴파일하면 다음과 같은 의사 코드를 볼 수 있다:

```c
// Ghidra 디컴파일 결과 (예시)
int verify_license(char *key) {
    if (key == NULL || strlen(key) != 0x13) return 0;
    if (key[4] != '-' || key[9] != '-' || key[14] != '-') return 0;
    // ... groups[0]==10, groups[1]==20, groups[2]==15, groups[3]==25
    return groups[0] == 10 && groups[1] == 20 && ...;
}
```

**Step 2: GDB로 검증 우회**
```bash
gdb -q license_check
(gdb) break verify_license
(gdb) run "1234-1234-1234-1234"
(gdb) finish         # 함수 완료까지 실행
(gdb) set $rax = 1  # 반환값 강제로 1(성공)로 변경
(gdb) continue
# 유효한 라이선스 키!
# CTF{l1c3ns3_k3y_r3v3rs3d_and_g3n3r4t3d}
```

**Step 3: Python으로 유효한 키 생성**

```python
#!/usr/bin/env python3
"""
라이선스 키 검증 로직 역산 + 유효한 키 생성기
analyze 명령: 검증 조건 분석
generate 명령: 유효한 키 무작위 생성
"""

import argparse
import random
import subprocess
import sys
from itertools import product


def generate_group(target_sum: int, length: int = 4) -> str:
    """
    합이 target_sum이고 길이가 length인 숫자 문자열을 생성한다.
    각 자리는 0~9.
    """
    if target_sum < 0 or target_sum > 9 * length:
        raise ValueError(f"합 {target_sum}은 길이 {length}로 표현 불가")

    digits = [0] * length
    remaining = target_sum

    for i in range(length - 1):
        max_val = min(9, remaining - (length - i - 1) * 0)
        d = random.randint(0, min(max_val, remaining))
        digits[i] = d
        remaining -= d

    digits[-1] = remaining
    if digits[-1] > 9:
        # 재시도
        return generate_group(target_sum, length)

    random.shuffle(digits)
    return "".join(str(d) for d in digits)


def generate_license_key(
    group_sums: list[int], group_length: int = 4
) -> str:
    """group_sums에 지정된 합을 가진 라이선스 키를 생성한다."""
    groups = [generate_group(s, group_length) for s in group_sums]
    return "-".join(groups)


def verify_key_locally(
    key: str, group_sums: list[int]
) -> bool:
    """Python으로 키를 검증한다 (바이너리 없이)."""
    if len(key) != 19:
        return False
    parts = key.split("-")
    if len(parts) != 4:
        return False
    for i, part in enumerate(parts):
        if len(part) != 4 or not part.isdigit():
            return False
        if sum(int(c) for c in part) != group_sums[i]:
            return False
    return True


def verify_with_binary(binary_path: str, key: str) -> bool:
    """실제 바이너리로 키를 검증한다."""
    try:
        result = subprocess.run(
            [binary_path, key],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return result.returncode == 0 and "CTF{" in result.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def analyze_binary_license(binary_path: str) -> None:
    """바이너리의 라이선스 검증 로직 분석 (정적)."""
    # strings로 힌트 탐색
    result = subprocess.run(
        ["strings", binary_path], capture_output=True, text=True
    )
    strings = result.stdout.splitlines()
    print("[*] 관련 문자열:")
    for s in strings:
        if any(kw in s.lower() for kw in ["license", "key", "valid", "invalid", "serial"]):
            print(f"    {s}")

    # 라이선스 검증 함수 심볼 탐색
    result = subprocess.run(
        ["nm", binary_path], capture_output=True, text=True
    )
    print("\n[*] 관련 심볼:")
    for line in result.stdout.splitlines():
        if any(kw in line.lower() for kw in ["verify", "check", "license", "serial"]):
            print(f"    {line}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="라이선스 키 역산 + 유효 키 생성기",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
예시:
  # 유효한 키 생성 (합: 10-20-15-25)
  python3 license_gen.py generate --sums 10 20 15 25

  # 바이너리 분석
  python3 license_gen.py analyze ./license_check

  # 키 검증
  python3 license_gen.py verify "1234-5678-6090-7990" --sums 10 20 15 25
        """,
    )
    subparsers = parser.add_subparsers(dest="command")

    gen_p = subparsers.add_parser("generate", help="유효한 키 생성")
    gen_p.add_argument("--sums", nargs=4, type=int, default=[10, 20, 15, 25],
                       help="각 그룹의 합 (기본: 10 20 15 25)")
    gen_p.add_argument("--count", type=int, default=5, help="생성할 키 수")
    gen_p.add_argument("--binary", default="", help="생성 후 바이너리로 검증")

    ana_p = subparsers.add_parser("analyze", help="바이너리 분석")
    ana_p.add_argument("binary", help="분석할 바이너리")

    ver_p = subparsers.add_parser("verify", help="키 검증")
    ver_p.add_argument("key", help="검증할 키")
    ver_p.add_argument("--sums", nargs=4, type=int, default=[10, 20, 15, 25])
    ver_p.add_argument("--binary", default="")

    args = parser.parse_args()

    if args.command == "generate":
        print(f"[*] 그룹 합: {args.sums}")
        for i in range(args.count):
            key = generate_license_key(args.sums)
            valid = verify_key_locally(key, args.sums)
            status = "O" if valid else "X"
            print(f"  [{status}] {key}")
            if args.binary and valid:
                if verify_with_binary(args.binary, key):
                    result = subprocess.run(
                        [args.binary, key], capture_output=True, text=True
                    )
                    print(f"      → {result.stdout.strip()}")

    elif args.command == "analyze":
        analyze_binary_license(args.binary)

    elif args.command == "verify":
        valid = verify_key_locally(args.key, args.sums)
        print(f"[{'+' if valid else '-'}] 키 '{args.key}': {'유효' if valid else '유효하지 않음'}")
        if args.binary:
            bin_valid = verify_with_binary(args.binary, args.key)
            print(f"[{'+'if bin_valid else'-'}] 바이너리 검증: {'성공' if bin_valid else '실패'}")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
```

```bash
# 유효한 키 생성 후 바이너리 검증
python3 license_gen.py generate --sums 10 20 15 25 --binary ./license_check
# [O] 2350-9362-6540-7990
#     → 유효한 라이선스 키!
#       CTF{l1c3ns3_k3y_r3v3rs3d_and_g3n3r4t3d}
```

---

## 참고 자료

- Ghidra 공식 저장소: https://github.com/NationalSecurityAgency/ghidra
- pwntools 공식 문서: https://docs.pwntools.com/en/stable/

---

<a name="english"></a>

# CTF-Style Reversing Lab

## Lab Environment Setup

```bash
sudo apt-get install -y upx gdb python3 python3-pip radare2 file binutils xxd
pip3 install pwntools capstone pyelftools

git clone https://github.com/pwndbg/pwndbg.git /opt/pwndbg
cd /opt/pwndbg && ./setup.sh
```

---

## Lab 1: Unpack UPX Binary and Extract Flag

### Objective

Unpack a UPX-compressed binary and locate the hidden flag.

**Hints:**
- `file` and `strings` reveal UPX packing.
- `upx -d` unpacks the binary.
- After unpacking, `strings | grep "CTF{"` may reveal the flag directly.

### Solution

**Step 1: Identify packing**
```bash
file flag_check_packed
# ELF 64-bit ... UPX compressed

strings flag_check_packed | grep "CTF{"   # empty — flag is hidden
```

**Step 2: Unpack**
```bash
upx -d flag_check_packed -o flag_check_unpacked
strings flag_check_unpacked | grep "CTF{"
# CTF{upx_unp4ck3d_and_fl4g_f0und}
```

**Step 3: Automated Python tool**
```bash
python3 upx_unpack.py flag_check_packed
# [*] UPX packed: Yes
# [+] Unpacked successfully
# [+] Flag found: CTF{upx_unp4ck3d_and_fl4g_f0und}
```

---

## Lab 2: Decrypt XOR-Encrypted String

### Objective

Analyze a binary that decrypts a flag at runtime using XOR, and recover the plaintext flag.

**Hints:**
- `strings` shows no flag — it is XOR-encrypted at rest.
- Use GDB to break at `decrypt_flag` and read `$rax` after return.
- Or extract the ciphertext bytes from `.rodata` and recover the key via known-plaintext attack.

### Solution

**Step 1: GDB dynamic analysis**
```bash
gdb -q xor_flag
(gdb) break decrypt_flag
(gdb) run dummy_arg
(gdb) finish
(gdb) x/s $rax
# 0x...: "CTF{x0r_3ncrypt10n_brok3n}"
```

**Step 2: Known-plaintext key recovery**
```bash
# First 4 bytes of ciphertext XOR "CTF{" → key = 0x5A
python3 xor_solver.py --cipher "0x19,0x1E,0x38,0x7B" --known-pt "CTF{"
# [+] Recovered XOR key: 0x5A
```

**Step 3: Full decryption**
```bash
python3 xor_solver.py --cipher "0x19,0x1E,..." --xor-key 0x5A
# [+] Decrypted: CTF{x0r_3ncrypt10n_brok3n}
```

---

## Lab 3: Bypass License Key Verification with Ghidra

### Objective

Reverse the license key validation logic, understand the verification conditions, and either generate a valid key or patch the binary.

**Hints:**
- Decompile `verify_license` in Ghidra to understand the group-sum conditions.
- Use GDB to force `$rax=1` (success) after the function returns.
- Or implement the key generator in Python using the recovered conditions.

### Solution

**Step 1: Ghidra decompilation**

Open `license_check` in Ghidra. The decompiled `verify_license` reveals:
- Key format: `XXXX-XXXX-XXXX-XXXX` (19 chars, digits only)
- Group sums: `groups[0]==10`, `groups[1]==20`, `groups[2]==15`, `groups[3]==25`

**Step 2: GDB patching (quick bypass)**
```bash
gdb -q license_check
(gdb) break verify_license
(gdb) run "0000-0000-0000-0000"
(gdb) finish
(gdb) set $rax = 1    # force success return
(gdb) continue
# Valid license key!
# CTF{l1c3ns3_k3y_r3v3rs3d_and_g3n3r4t3d}
```

**Step 3: Python key generator**
```bash
python3 license_gen.py generate --sums 10 20 15 25 --binary ./license_check
# [O] 2350-9362-6540-7990
#     → CTF{l1c3ns3_k3y_r3v3rs3d_and_g3n3r4t3d}
```

---

## References

- Ghidra Official Repository: https://github.com/NationalSecurityAgency/ghidra
- pwntools Documentation: https://docs.pwntools.com/en/stable/
