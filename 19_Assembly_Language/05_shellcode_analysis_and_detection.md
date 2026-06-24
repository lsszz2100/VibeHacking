> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 셸코드 분석 및 탐지 — 정적·동적 분석·시그니처 생성

## 0. 초보자를 위한 개념 이해

### 셸코드 분석 및 탐지란?

**셸코드 분석**은 발견된 기계어 페이로드가 무엇을 하는지 역분석하는 작업입니다. **탐지**는 IDS/EDR 시스템이 악성 셸코드를 식별하는 방법입니다. 공격자와 방어자 모두 이 기술이 필요합니다.

**왜 배우는가:**
```
침해 사고 대응:
  메모리에서 의심스러운 바이트 발견
    → 셸코드인가? 무엇을 하는가?
    → 어떤 공격 그룹이 사용하는 기법인가?

보안 제품 개발:
  EDR/AV → 셸코드 패턴 등록 → 탐지
    → 셸코드 분석 없이는 시그니처 작성 불가
```

### 핵심 개념 정리

```
셸코드 분석 방법:

1. 정적 분석
   - sctest: libemu 기반 에뮬레이션
   - ndisasm: 헥스 → 어셈블리 변환
   - 주요 패턴 식별:
     syscall (0x0f 0x05) → 시스템 콜
     int 0x80             → 32bit 시스템 콜
     /bin/sh 문자열       → 쉘 실행

2. 동적 분석
   - GDB로 단계별 실행
   - strace로 시스템 콜 추적
   - 샌드박스에서 실행 + API 모니터

탐지 기법:
  시그니처 기반: 알려진 셸코드 패턴 비교
  행동 기반: 비정상 메모리 실행 감지
  YARA 룰: 바이트 패턴 + 조건으로 탐지
```

### 필요한 도구
- **GDB + pwndbg**: 셸코드 동적 실행 분석
- **YARA**: 바이너리 패턴 매칭 룰 작성
- **scdbg**: 셸코드 에뮬레이터
- **CyberChef**: 인코딩된 셸코드 디코딩

### 기초 실습 예제
```python
# 셸코드 기본 분석 - 의심 바이트 확인
shellcode_hex = "31c050682f2f7368682f62696e89e3505389e1b00bcd80"
shellcode = bytes.fromhex(shellcode_hex)

# NULL 바이트 확인
null_positions = [i for i, b in enumerate(shellcode) if b == 0]
print(f"셸코드 크기: {len(shellcode)} bytes")
print(f"NULL 바이트 위치: {null_positions}")

# 시스템 콜 패턴 탐색
syscall_patterns = [b'\x0f\x05', b'\xcd\x80', b'\x0f\x34']
for pat in syscall_patterns:
    if pat in shellcode:
        print(f"시스템 콜 패턴 발견: {pat.hex()}")

# /bin/sh 문자열 탐색
if b'/bin/sh' in shellcode or b'/bin//sh' in shellcode:
    print("⚠ /bin/sh 실행 시도 감지")
```

---

## 1. 셸코드 분석 접근법

```
셸코드 분석
    │
    ├── 정적 분석
    │     - 바이트 패턴 식별 (syscall, int 0x80)
    │     - 인코딩/디코딩 루프 탐지
    │     - 문자열 추출
    │
    ├── 동적 분석
    │     - 샌드박스 실행 (libemu, unicorn)
    │     - 메모리 트레이스
    │     - 시스템 콜 추적
    │
    └── 시그니처 생성
          - 바이트 패턴 → YARA 룰
          - 엔트로피 분석
          - 구조적 특징 추출
```

---

## 2. 셸코드 정적 분석기

```python
#!/usr/bin/env python3
"""셸코드 정적 분석 — 바이트 패턴·syscall·인코딩 탐지."""

import argparse
import math
import struct
from collections import Counter
from pathlib import Path


# Linux x86-64 syscall 번호 → 이름
LINUX_SYSCALLS_X64: dict[int, str] = {
    0: "read", 1: "write", 2: "open", 3: "close",
    59: "execve", 60: "exit", 39: "getpid",
    56: "clone", 57: "fork", 33: "dup2",
    41: "socket", 42: "connect", 43: "accept",
    49: "bind", 50: "listen",
    105: "setuid", 106: "getuid",
    231: "exit_group",
}

# 의심 바이트 시퀀스
SUSPICIOUS_PATTERNS: list[tuple[bytes, str]] = [
    (b"\x0f\x05", "syscall (x86-64)"),
    (b"\xcd\x80", "int 0x80 (x86)"),
    (b"\x0f\x34", "sysenter"),
    (b"\xff\xe4", "jmp rsp"),
    (b"\xff\xe0", "jmp rax"),
    (b"\x90\x90\x90\x90", "NOP sled"),
    (b"\x31\xc0", "xor eax,eax"),
    (b"\x48\x31\xc0", "xor rax,rax"),
    (b"\x2f\x62\x69\x6e\x2f\x73\x68", "/bin/sh"),
    (b"\x2f\x62\x69\x6e\x2f\x62\x61\x73\x68", "/bin/bash"),
    (b"\xeb\xfe", "infinite loop (jmp -2)"),
]


def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    entropy = 0.0
    for count in counts.values():
        prob = count / total
        if prob > 0:
            entropy -= prob * math.log2(prob)
    return entropy


def detect_encoding(data: bytes) -> list[str]:
    """XOR·ROT13·Base64 인코딩 탐지."""
    detected = []

    # XOR 인코딩 — 반복 키 패턴 탐지
    for key_len in range(1, 5):
        if len(data) < key_len * 4:
            continue
        key = data[:key_len]
        decoded = bytes(b ^ key[i % key_len] for i, b in enumerate(data))
        # 디코딩 후 null 바이트 비율이 낮으면 XOR 의심
        null_count = decoded.count(0)
        if null_count < len(decoded) * 0.1 and key != bytes(key_len):
            detected.append(f"XOR (키 길이 {key_len}: {key.hex()})")

    # 높은 엔트로피 → 암호화/인코딩 가능성
    entropy = calculate_entropy(data)
    if entropy > 7.0:
        detected.append(f"높은 엔트로피 ({entropy:.2f}/8.0) — 암호화 가능성")

    return detected


def extract_syscalls_x64(data: bytes) -> list[dict]:
    """x86-64 syscall 명령어 앞의 rax 값 추출."""
    syscalls = []
    for i in range(len(data) - 1):
        if data[i:i+2] == b"\x0f\x05":
            # 앞 몇 바이트에서 rax 설정 패턴 탐지
            context_start = max(0, i - 10)
            context = data[context_start:i]

            # mov rax, imm 패턴 (48 c7 c0 XX 00 00 00)
            rax_val = None
            for j in range(len(context) - 6):
                if context[j:j+3] == b"\x48\xc7\xc0":
                    rax_val = struct.unpack_from("<I", context, j + 3)[0]
                    break

            syscalls.append({
                "offset": hex(i),
                "syscall_num": rax_val,
                "syscall_name": LINUX_SYSCALLS_X64.get(rax_val, "unknown") if rax_val is not None else "unknown",
                "context_hex": context.hex(),
            })

    return syscalls


def analyze_shellcode(data: bytes) -> dict:
    result: dict = {
        "size": len(data),
        "entropy": round(calculate_entropy(data), 3),
        "null_bytes": data.count(0),
        "null_free": data.count(0) == 0,
        "patterns": [],
        "syscalls": [],
        "encoding_suspects": [],
        "strings": [],
    }

    # 의심 패턴 탐지
    for pattern, description in SUSPICIOUS_PATTERNS:
        offset = 0
        while True:
            idx = data.find(pattern, offset)
            if idx == -1:
                break
            result["patterns"].append({
                "offset": hex(idx),
                "pattern": pattern.hex(),
                "description": description,
            })
            offset = idx + 1

    # syscall 추출
    result["syscalls"] = extract_syscalls_x64(data)

    # 인코딩 탐지
    result["encoding_suspects"] = detect_encoding(data)

    # 문자열 추출 (4자 이상 ASCII)
    current = []
    for byte in data:
        if 0x20 <= byte <= 0x7e:
            current.append(chr(byte))
        else:
            if len(current) >= 4:
                result["strings"].append("".join(current))
            current = []

    return result


def generate_yara_rule(data: bytes, rule_name: str) -> str:
    """분석된 셸코드에서 YARA 룰 자동 생성."""
    patterns = []

    # 고유한 4바이트 시퀀스 추출
    for i in range(0, min(len(data) - 4, 100), 4):
        chunk = data[i:i+4]
        if chunk.count(0) < 3:  # null이 적은 청크
            patterns.append(chunk.hex())

    yara = [
        f"rule {rule_name} {{",
        "    meta:",
        f'        description = "자동 생성된 셸코드 탐지 룰"',
        f'        size = "{len(data)}"',
        "    strings:",
    ]

    for i, pattern in enumerate(patterns[:5]):
        pairs = " ".join(pattern[j:j+2] for j in range(0, len(pattern), 2))
        yara.append(f'        $s{i} = {{ {pairs} }}')

    yara += [
        "    condition:",
        f"        3 of ($s*) and filesize < {len(data) * 10}",
        "}",
    ]

    return "\n".join(yara)


def main() -> None:
    parser = argparse.ArgumentParser(description="셸코드 정적 분석기")
    sub = parser.add_subparsers(dest="cmd", required=True)

    analyze_p = sub.add_parser("analyze", help="바이너리 파일 분석")
    analyze_p.add_argument("file", type=Path)
    analyze_p.add_argument("--hex", help="hex 문자열로 직접 입력")

    yara_p = sub.add_parser("yara", help="YARA 룰 생성")
    yara_p.add_argument("file", type=Path)
    yara_p.add_argument("--name", default="shellcode_detection")
    yara_p.add_argument("-o", "--output", type=Path)

    args = parser.parse_args()

    match args.cmd:
        case "analyze":
            if hasattr(args, "hex") and args.hex:
                data = bytes.fromhex(args.hex)
            else:
                data = args.file.read_bytes()

            result = analyze_shellcode(data)

            print(f"=== 셸코드 분석 ({result['size']} bytes) ===")
            print(f"엔트로피: {result['entropy']} / 8.0")
            print(f"Null 프리: {'예' if result['null_free'] else '아니오'}")

            if result["patterns"]:
                print(f"\n의심 패턴 {len(result['patterns'])}개:")
                for p in result["patterns"]:
                    print(f"  {p['offset']}: {p['description']}")

            if result["syscalls"]:
                print(f"\nsyscall {len(result['syscalls'])}개:")
                for s in result["syscalls"]:
                    print(f"  {s['offset']}: {s['syscall_name']} (#{s['syscall_num']})")

            if result["encoding_suspects"]:
                print(f"\n인코딩 의심:")
                for e in result["encoding_suspects"]:
                    print(f"  {e}")

            if result["strings"]:
                print(f"\n문자열:")
                for s in result["strings"][:10]:
                    print(f"  {repr(s)}")

        case "yara":
            data = args.file.read_bytes()
            rule = generate_yara_rule(data, args.name)
            if args.output:
                args.output.write_text(rule)
                print(f"[+] YARA 룰 저장: {args.output}")
            else:
                print(rule)


if __name__ == "__main__":
    main()
```

---

## 3. Unicorn Engine 셸코드 에뮬레이션

```python
#!/usr/bin/env python3
"""Unicorn Engine으로 셸코드 안전 에뮬레이션 — syscall 추적."""

import argparse
import struct
from pathlib import Path

try:
    from unicorn import *
    from unicorn.x86_const import *
    UNICORN_AVAILABLE = True
except ImportError:
    UNICORN_AVAILABLE = False


BASE_ADDR = 0x400000
STACK_ADDR = 0x700000
STACK_SIZE = 0x10000
MAX_INSNS = 10000


def emulate_shellcode(shellcode: bytes) -> list[dict]:
    if not UNICORN_AVAILABLE:
        print("unicorn 설치 필요: pip install unicorn")
        return []

    mu = Uc(UC_ARCH_X86, UC_MODE_64)

    # 메모리 맵핑
    mu.mem_map(BASE_ADDR, 0x100000)
    mu.mem_map(STACK_ADDR, STACK_SIZE)

    # 셸코드 로드
    mu.mem_write(BASE_ADDR, shellcode)

    # 레지스터 초기화
    mu.reg_write(UC_X86_REG_RSP, STACK_ADDR + STACK_SIZE // 2)
    mu.reg_write(UC_X86_REG_RIP, BASE_ADDR)

    syscall_log: list[dict] = []

    def hook_syscall(mu, user_data):
        rax = mu.reg_read(UC_X86_REG_RAX)
        rdi = mu.reg_read(UC_X86_REG_RDI)
        rsi = mu.reg_read(UC_X86_REG_RSI)
        rdx = mu.reg_read(UC_X86_REG_RDX)
        rip = mu.reg_read(UC_X86_REG_RIP)

        from unicorn.x86_const import UC_X86_INS_SYSCALL
        LINUX_SYSCALLS = {
            59: "execve", 60: "exit", 1: "write", 2: "open",
            41: "socket", 42: "connect", 0: "read",
        }
        name = LINUX_SYSCALLS.get(rax, f"syscall_{rax}")
        entry = {
            "rip": hex(rip),
            "syscall": name,
            "rax": rax,
            "rdi": hex(rdi),
            "rsi": hex(rsi),
            "rdx": hex(rdx),
        }
        syscall_log.append(entry)
        print(f"  [syscall] {name}(rdi={hex(rdi)}, rsi={hex(rsi)}, rdx={hex(rdx)})")

        # execve 탐지 시 에뮬레이션 중단
        if rax == 59:
            mu.emu_stop()

    mu.hook_add(UC_HOOK_INSN, hook_syscall, None, 1, 0, UC_X86_INS_SYSCALL)

    try:
        mu.emu_start(BASE_ADDR, BASE_ADDR + len(shellcode), count=MAX_INSNS)
    except UcError as e:
        print(f"[에뮬레이션 오류] {e}")

    return syscall_log


def main() -> None:
    parser = argparse.ArgumentParser(description="셸코드 안전 에뮬레이션")
    parser.add_argument("file", type=Path, help="셸코드 바이너리")
    args = parser.parse_args()

    data = args.file.read_bytes()
    print(f"[*] {args.file.name} ({len(data)} bytes) 에뮬레이션 시작")
    print("[!] 주의: 에뮬레이션이므로 실제 시스템에 영향 없음\n")

    syscalls = emulate_shellcode(data)
    print(f"\n총 syscall {len(syscalls)}개 탐지")
    if any(s["syscall"] == "execve" for s in syscalls):
        print("[!] execve 호출 탐지 — 셸 실행 시도")


if __name__ == "__main__":
    main()
```

---

## 4. 셸코드 탐지 시그니처

| 패턴 | 설명 | YARA 조건 |
|------|------|-----------|
| `\x0f\x05` | x86-64 syscall | 빈번한 syscall |
| `\xcd\x80` | x86 int 0x80 | 구형 셸코드 |
| `\x90` * N | NOP sled | 10개 이상 연속 |
| `/bin/sh` 문자열 | execve 인자 | 문자열 존재 |
| `\xff\xe4` | jmp rsp | 스택 피벗 |
| 엔트로피 > 7.5 | 암호화/인코딩 | 고엔트로피 |
| Null 없음 | Null-free 셸코드 | 네트워크 페이로드 |

---

<!-- detect-validate-19 -->
## 셸코드 탐지 검증과 회귀

이 섹션은 이미 셸코드 *탐지*를 다루므로, 검증의 초점은 **탐지기가 변종을 잡으면서 굿웨어 오탐을 내지 않는가**다. 정적 시그니처·에뮬레이션·syscall 추출을 라벨된 코퍼스로 회귀 테스트해야 한다. 검증은 **소유·격리 환경**에서만.

### 검증 항목 → 질문 → 측정 신호 → 함정

| 검증 항목 | 질문 | 측정 신호 | 함정 |
|---|---|---|---|
| 정적 시그니처 | 인코딩 변종도 잡는가 | 변형 셸코드 탐지율 | 굿웨어 오탐(FP) |
| 에뮬레이션(Unicorn) | 디코더 스텁을 풀어내는가 | 에뮬 후 syscall 식별 | 자기수정 미처리 |
| NOP-sled 탐지 | sled 변형도 잡는가 | 다양 sled 바이트 탐지 | 단일 0x90 가정 |
| syscall 추출 | 실제 행위를 식별하는가 | 추출된 execve/connect | 정적만, 동적 행위 누락 |

### 방어 검증 (직접 확인)

```python
# 셸코드 탐지기를 알려진 셸코드 + 굿웨어로 회귀 검증 — 탐지율과 오탐을 동시 측정
import pathlib

samples = {"known_shellcode.bin": True, "goodware_blob.bin": False}  # 라벨된 코퍼스
for name, is_mal in samples.items():
    flagged = detect(pathlib.Path(name).read_bytes())  # 사용자 정의 탐지 함수
    tag = "TP" if (flagged and is_mal) else "FP" if flagged else "FN" if is_mal else "TN"
    print(f"{name}: flagged={flagged} -> {tag}")  # FP/FN 0 을 목표로 시그니처 조정
```

> 탐지 검증은 *잡는가*만이 아니라 *오탐 없이 잡는가*다 — "룰 추가했다"와 "변종을 잡고 굿웨어를 통과시킨다"는 다르다. 소유·격리 환경에서 라벨된 코퍼스로 TP/FP/FN 을 측정하고 회귀를 막는다([[06_Malware_Analysis]], [[13_SOC_Blue_Team]], [[68_Purple_Team]]).

---

<a name="english"></a>

# Shellcode Analysis and Detection — Static/Dynamic Analysis and Signature Generation

## 1. Shellcode Analysis Approaches

```
Shellcode Analysis
    │
    ├── Static Analysis
    │     - Byte pattern identification (syscall, int 0x80)
    │     - Encoding/decoding loop detection
    │     - String extraction
    │
    ├── Dynamic Analysis
    │     - Sandbox execution (libemu, unicorn)
    │     - Memory tracing
    │     - System call tracing
    │
    └── Signature Generation
          - Byte patterns → YARA rules
          - Entropy analysis
          - Structural feature extraction
```

---

## 2. Shellcode Static Analyzer

```python
#!/usr/bin/env python3
"""Shellcode static analysis — byte pattern, syscall, and encoding detection."""

import argparse
import math
import struct
from collections import Counter
from pathlib import Path


# Linux x86-64 syscall number → name
LINUX_SYSCALLS_X64: dict[int, str] = {
    0: "read", 1: "write", 2: "open", 3: "close",
    59: "execve", 60: "exit", 39: "getpid",
    56: "clone", 57: "fork", 33: "dup2",
    41: "socket", 42: "connect", 43: "accept",
    49: "bind", 50: "listen",
    105: "setuid", 106: "getuid",
    231: "exit_group",
}

# Suspicious byte sequences
SUSPICIOUS_PATTERNS: list[tuple[bytes, str]] = [
    (b"\x0f\x05", "syscall (x86-64)"),
    (b"\xcd\x80", "int 0x80 (x86)"),
    (b"\x0f\x34", "sysenter"),
    (b"\xff\xe4", "jmp rsp"),
    (b"\xff\xe0", "jmp rax"),
    (b"\x90\x90\x90\x90", "NOP sled"),
    (b"\x31\xc0", "xor eax,eax"),
    (b"\x48\x31\xc0", "xor rax,rax"),
    (b"\x2f\x62\x69\x6e\x2f\x73\x68", "/bin/sh"),
    (b"\x2f\x62\x69\x6e\x2f\x62\x61\x73\x68", "/bin/bash"),
    (b"\xeb\xfe", "infinite loop (jmp -2)"),
]


def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    entropy = 0.0
    for count in counts.values():
        prob = count / total
        if prob > 0:
            entropy -= prob * math.log2(prob)
    return entropy


def detect_encoding(data: bytes) -> list[str]:
    """Detect XOR, ROT13, Base64 encoding."""
    detected = []

    # XOR encoding — detect repeating key pattern
    for key_len in range(1, 5):
        if len(data) < key_len * 4:
            continue
        key = data[:key_len]
        decoded = bytes(b ^ key[i % key_len] for i, b in enumerate(data))
        # If null byte ratio is low after decoding, suspect XOR
        null_count = decoded.count(0)
        if null_count < len(decoded) * 0.1 and key != bytes(key_len):
            detected.append(f"XOR (key length {key_len}: {key.hex()})")

    # High entropy → possible encryption/encoding
    entropy = calculate_entropy(data)
    if entropy > 7.0:
        detected.append(f"High entropy ({entropy:.2f}/8.0) — possible encryption")

    return detected


def extract_syscalls_x64(data: bytes) -> list[dict]:
    """Extract rax value before x86-64 syscall instructions."""
    syscalls = []
    for i in range(len(data) - 1):
        if data[i:i+2] == b"\x0f\x05":
            # Detect rax setup pattern in preceding bytes
            context_start = max(0, i - 10)
            context = data[context_start:i]

            # mov rax, imm pattern (48 c7 c0 XX 00 00 00)
            rax_val = None
            for j in range(len(context) - 6):
                if context[j:j+3] == b"\x48\xc7\xc0":
                    rax_val = struct.unpack_from("<I", context, j + 3)[0]
                    break

            syscalls.append({
                "offset": hex(i),
                "syscall_num": rax_val,
                "syscall_name": LINUX_SYSCALLS_X64.get(rax_val, "unknown") if rax_val is not None else "unknown",
                "context_hex": context.hex(),
            })

    return syscalls


def analyze_shellcode(data: bytes) -> dict:
    result: dict = {
        "size": len(data),
        "entropy": round(calculate_entropy(data), 3),
        "null_bytes": data.count(0),
        "null_free": data.count(0) == 0,
        "patterns": [],
        "syscalls": [],
        "encoding_suspects": [],
        "strings": [],
    }

    # Detect suspicious patterns
    for pattern, description in SUSPICIOUS_PATTERNS:
        offset = 0
        while True:
            idx = data.find(pattern, offset)
            if idx == -1:
                break
            result["patterns"].append({
                "offset": hex(idx),
                "pattern": pattern.hex(),
                "description": description,
            })
            offset = idx + 1

    # Extract syscalls
    result["syscalls"] = extract_syscalls_x64(data)

    # Detect encoding
    result["encoding_suspects"] = detect_encoding(data)

    # Extract strings (4+ ASCII characters)
    current = []
    for byte in data:
        if 0x20 <= byte <= 0x7e:
            current.append(chr(byte))
        else:
            if len(current) >= 4:
                result["strings"].append("".join(current))
            current = []

    return result


def generate_yara_rule(data: bytes, rule_name: str) -> str:
    """Automatically generate YARA rule from analyzed shellcode."""
    patterns = []

    # Extract unique 4-byte sequences
    for i in range(0, min(len(data) - 4, 100), 4):
        chunk = data[i:i+4]
        if chunk.count(0) < 3:  # chunks with few nulls
            patterns.append(chunk.hex())

    yara = [
        f"rule {rule_name} {{",
        "    meta:",
        f'        description = "Auto-generated shellcode detection rule"',
        f'        size = "{len(data)}"',
        "    strings:",
    ]

    for i, pattern in enumerate(patterns[:5]):
        pairs = " ".join(pattern[j:j+2] for j in range(0, len(pattern), 2))
        yara.append(f'        $s{i} = {{ {pairs} }}')

    yara += [
        "    condition:",
        f"        3 of ($s*) and filesize < {len(data) * 10}",
        "}",
    ]

    return "\n".join(yara)


def main() -> None:
    parser = argparse.ArgumentParser(description="Shellcode static analyzer")
    sub = parser.add_subparsers(dest="cmd", required=True)

    analyze_p = sub.add_parser("analyze", help="Analyze binary file")
    analyze_p.add_argument("file", type=Path)
    analyze_p.add_argument("--hex", help="Direct input as hex string")

    yara_p = sub.add_parser("yara", help="Generate YARA rule")
    yara_p.add_argument("file", type=Path)
    yara_p.add_argument("--name", default="shellcode_detection")
    yara_p.add_argument("-o", "--output", type=Path)

    args = parser.parse_args()

    match args.cmd:
        case "analyze":
            if hasattr(args, "hex") and args.hex:
                data = bytes.fromhex(args.hex)
            else:
                data = args.file.read_bytes()

            result = analyze_shellcode(data)

            print(f"=== Shellcode Analysis ({result['size']} bytes) ===")
            print(f"Entropy: {result['entropy']} / 8.0")
            print(f"Null-free: {'Yes' if result['null_free'] else 'No'}")

            if result["patterns"]:
                print(f"\nSuspicious patterns ({len(result['patterns'])}):")
                for p in result["patterns"]:
                    print(f"  {p['offset']}: {p['description']}")

            if result["syscalls"]:
                print(f"\nSyscalls ({len(result['syscalls'])}):")
                for s in result["syscalls"]:
                    print(f"  {s['offset']}: {s['syscall_name']} (#{s['syscall_num']})")

            if result["encoding_suspects"]:
                print(f"\nEncoding suspects:")
                for e in result["encoding_suspects"]:
                    print(f"  {e}")

            if result["strings"]:
                print(f"\nStrings:")
                for s in result["strings"][:10]:
                    print(f"  {repr(s)}")

        case "yara":
            data = args.file.read_bytes()
            rule = generate_yara_rule(data, args.name)
            if args.output:
                args.output.write_text(rule)
                print(f"[+] YARA rule saved: {args.output}")
            else:
                print(rule)


if __name__ == "__main__":
    main()
```

---

## 3. Unicorn Engine Shellcode Emulation

```python
#!/usr/bin/env python3
"""Safe shellcode emulation with Unicorn Engine — syscall tracing."""

import argparse
import struct
from pathlib import Path

try:
    from unicorn import *
    from unicorn.x86_const import *
    UNICORN_AVAILABLE = True
except ImportError:
    UNICORN_AVAILABLE = False


BASE_ADDR = 0x400000
STACK_ADDR = 0x700000
STACK_SIZE = 0x10000
MAX_INSNS = 10000


def emulate_shellcode(shellcode: bytes) -> list[dict]:
    if not UNICORN_AVAILABLE:
        print("unicorn required: pip install unicorn")
        return []

    mu = Uc(UC_ARCH_X86, UC_MODE_64)

    # Memory mapping
    mu.mem_map(BASE_ADDR, 0x100000)
    mu.mem_map(STACK_ADDR, STACK_SIZE)

    # Load shellcode
    mu.mem_write(BASE_ADDR, shellcode)

    # Initialize registers
    mu.reg_write(UC_X86_REG_RSP, STACK_ADDR + STACK_SIZE // 2)
    mu.reg_write(UC_X86_REG_RIP, BASE_ADDR)

    syscall_log: list[dict] = []

    def hook_syscall(mu, user_data):
        rax = mu.reg_read(UC_X86_REG_RAX)
        rdi = mu.reg_read(UC_X86_REG_RDI)
        rsi = mu.reg_read(UC_X86_REG_RSI)
        rdx = mu.reg_read(UC_X86_REG_RDX)
        rip = mu.reg_read(UC_X86_REG_RIP)

        from unicorn.x86_const import UC_X86_INS_SYSCALL
        LINUX_SYSCALLS = {
            59: "execve", 60: "exit", 1: "write", 2: "open",
            41: "socket", 42: "connect", 0: "read",
        }
        name = LINUX_SYSCALLS.get(rax, f"syscall_{rax}")
        entry = {
            "rip": hex(rip),
            "syscall": name,
            "rax": rax,
            "rdi": hex(rdi),
            "rsi": hex(rsi),
            "rdx": hex(rdx),
        }
        syscall_log.append(entry)
        print(f"  [syscall] {name}(rdi={hex(rdi)}, rsi={hex(rsi)}, rdx={hex(rdx)})")

        # Stop emulation when execve is detected
        if rax == 59:
            mu.emu_stop()

    mu.hook_add(UC_HOOK_INSN, hook_syscall, None, 1, 0, UC_X86_INS_SYSCALL)

    try:
        mu.emu_start(BASE_ADDR, BASE_ADDR + len(shellcode), count=MAX_INSNS)
    except UcError as e:
        print(f"[Emulation error] {e}")

    return syscall_log


def main() -> None:
    parser = argparse.ArgumentParser(description="Safe shellcode emulation")
    parser.add_argument("file", type=Path, help="Shellcode binary")
    args = parser.parse_args()

    data = args.file.read_bytes()
    print(f"[*] Starting emulation: {args.file.name} ({len(data)} bytes)")
    print("[!] Note: emulation only — no impact on real system\n")

    syscalls = emulate_shellcode(data)
    print(f"\nTotal syscalls detected: {len(syscalls)}")
    if any(s["syscall"] == "execve" for s in syscalls):
        print("[!] execve call detected — shell execution attempted")


if __name__ == "__main__":
    main()
```

---

## 4. Shellcode Detection Signatures

| Pattern | Description | YARA Condition |
|---------|-------------|----------------|
| `\x0f\x05` | x86-64 syscall | Frequent syscall |
| `\xcd\x80` | x86 int 0x80 | Legacy shellcode |
| `\x90` * N | NOP sled | 10+ consecutive |
| `/bin/sh` string | execve argument | String present |
| `\xff\xe4` | jmp rsp | Stack pivot |
| Entropy > 7.5 | Encryption/encoding | High entropy |
| No nulls | Null-free shellcode | Network payload |

<!-- detect-validate-19 -->
## Shellcode Detection Validation and Regression

This section already covers shellcode *detection*, so the validation focus is **whether the detector catches variants without false positives on goodware**. Regression-test static signatures, emulation, and syscall extraction against a labeled corpus. Validate only in **owned/isolated environments**.

### Check -> Question -> Signal -> Pitfall

| Check | Question | Signal | Pitfall |
|---|---|---|---|
| Static signature | Catches encoded variants too | mutated-shellcode detection rate | goodware false positive (FP) |
| Emulation (Unicorn) | Unrolls the decoder stub | syscalls identified after emulation | self-modification unhandled |
| NOP-sled detection | Catches sled variants | varied sled-byte detection | assumes single 0x90 |
| syscall extraction | Identifies real behavior | extracted execve/connect | static only, misses dynamic behavior |

### Defense validation (verify directly)

```python
# Regress the shellcode detector on known shellcode + goodware -- measure rate and FP together
import pathlib

samples = {"known_shellcode.bin": True, "goodware_blob.bin": False}  # labeled corpus
for name, is_mal in samples.items():
    flagged = detect(pathlib.Path(name).read_bytes())  # user-defined detection function
    tag = "TP" if (flagged and is_mal) else "FP" if flagged else "FN" if is_mal else "TN"
    print(f"{name}: flagged={flagged} -> {tag}")  # tune signatures toward zero FP/FN
```

> Detection validation is not only *does it catch* but *does it catch without false positives* -- "we added a rule" differs from "it catches variants and lets goodware through". Measure TP/FP/FN on a labeled corpus in owned/isolated environments and prevent regressions ([[06_Malware_Analysis]], [[13_SOC_Blue_Team]], [[68_Purple_Team]]).
