> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 고급 언패킹 및 난독화 해제

## 1. 패킹 탐지

패킹(Packing)은 실행 파일을 압축하거나 암호화해 분석을 방해하는 기법이다. 패킹된 파일은 실행 시 메모리에서 원본 코드를 복원(언패킹)한다.

### 1.1 패킹 여부 초기 탐지

```bash
# 엔트로피 확인 (패킹된 파일은 높은 엔트로피를 가짐)
python3 -c "
import math, sys

def entropy(data):
    if not data:
        return 0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    n = len(data)
    return -sum(c/n * math.log2(c/n) for c in freq.values())

with open(sys.argv[1], 'rb') as f:
    data = f.read()
e = entropy(data)
print(f'엔트로피: {e:.4f}')
print(f'판정: {\"패킹 의심\" if e > 6.8 else \"정상 범위\"}')
" target_binary

# PEiD / DIE (Detect-It-Easy) 대안: strings로 패커 시그니처 확인
strings target_binary | grep -iE "(upx|mpress|aspack|petite|themida|vmprotect|peid)"

# readelf로 섹션 이름 확인 (UPX는 UPX0, UPX1 섹션 사용)
readelf -S target_binary | grep -iE "(upx|pack|.text|.data)"
```

### 1.2 UPX 탐지 및 언패킹

UPX(Ultimate Packer for eXecutables)는 가장 널리 사용되는 오픈소스 패커다.

```bash
# UPX 시그니처 확인
strings target_binary | grep "UPX!"
# 또는
hexdump -C target_binary | grep "55 50 58 21"  # "UPX!"

# UPX 언패킹 (UPX가 설치된 경우)
upx -d packed_binary -o unpacked_binary
file unpacked_binary  # ELF/PE 헤더가 복원되었는지 확인

# 언패킹 후 검증
strings unpacked_binary | head -50
```

### 1.3 MPRESS 탐지

```bash
# MPRESS 시그니처 확인
strings target_binary | grep -iE "(mpress|.MPRESS)"
readelf -S target_binary 2>/dev/null | grep -i mpress
# 또는 PE 파일의 경우:
# PEview/pe-bear로 섹션 이름 확인
```

### 1.4 커스텀 패커 탐지

```bash
# 섹션 수가 비정상적으로 적음 (2~3개)
readelf -S target_binary | grep -c "\[.*\]"

# 진입점(OEP 이전 지점)이 .text 섹션이 아닌 경우 의심
readelf -h target_binary | grep "Entry point"

# Import 테이블이 매우 빈약한 경우 패킹 의심
objdump -d target_binary | grep -c "plt>"
```

---

## 2. 동적 언패킹 기법

패커가 실행되면 메모리에 원본 코드를 복원한다. 이 시점에 메모리를 덤프하면 언패킹된 코드를 얻을 수 있다.

### 2.1 OEP(Original Entry Point) 찾기

OEP는 언패킹 루틴이 끝나고 원본 프로그램이 시작되는 지점이다.

**GDB를 이용한 OEP 탐지:**
```bash
gdb -q target_binary
# 1. 언패킹 루틴이 완료된 후 원본 .text 섹션으로 점프하는 패턴 탐지
(gdb) set follow-fork-mode child
(gdb) catch syscall mprotect      # 메모리 권한 변경 시 중단
(gdb) run
# mprotect 호출 후 레지스터 확인
(gdb) info registers eip rip
(gdb) x/20i $rip                 # 현재 위치의 명령어 확인
```

**ESP 트릭 (Stack Pointer 방법):**
```bash
# 패커는 일반적으로 원래 스택 포인터를 저장했다가 OEP에서 복원한다
gdb -q target_binary
(gdb) break *0x$(readelf -h target_binary | grep Entry | awk '{print $NF}')
(gdb) run
(gdb) info registers esp rsp
# 현재 스택 포인터 주소에 하드웨어 브레이크포인트 설정
(gdb) watch -l *(int*)($rsp)    # 스택 값 변경 감시
(gdb) continue                   # OEP에서 중단
```

### 2.2 메모리 덤프

```bash
# Linux: /proc/<pid>/maps + /proc/<pid>/mem으로 덤프
gdb -q target_binary
(gdb) run &
# 별도 터미널에서:
cat /proc/$(pgrep target)/maps

# GDB에서 메모리 덤프
(gdb) dump memory /tmp/dump.bin 0x400000 0x401000

# pmap으로 메모리 레이아웃 확인
pmap -x $(pgrep target_binary)
```

**Python으로 자동 메모리 덤프:**
```python
#!/usr/bin/env python3
"""Linux 프로세스 메모리 덤프 도구."""

import argparse
import os
import sys
from pathlib import Path


def get_memory_maps(pid: int) -> list[dict]:
    """프로세스의 메모리 맵을 파싱한다."""
    maps: list[dict] = []
    maps_path = Path(f"/proc/{pid}/maps")
    if not maps_path.exists():
        raise FileNotFoundError(f"PID {pid} 프로세스를 찾을 수 없습니다.")

    for line in maps_path.read_text().splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        addr_range, perms = parts[0], parts[1]
        start_str, end_str = addr_range.split("-")
        maps.append({
            "start": int(start_str, 16),
            "end": int(end_str, 16),
            "perms": perms,
            "name": parts[5] if len(parts) > 5 else "",
        })
    return maps


def dump_region(pid: int, start: int, end: int) -> bytes:
    """프로세스 메모리의 특정 영역을 읽어 반환한다."""
    mem_path = f"/proc/{pid}/mem"
    try:
        with open(mem_path, "rb") as f:
            f.seek(start)
            return f.read(end - start)
    except (OSError, OverflowError) as e:
        return b""


def dump_executable_regions(pid: int, output_dir: str) -> list[str]:
    """실행 권한이 있는 메모리 영역을 덤프한다."""
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    maps = get_memory_maps(pid)
    dumped: list[str] = []

    for region in maps:
        if "x" not in region["perms"]:
            continue
        size = region["end"] - region["start"]
        if size <= 0 or size > 100 * 1024 * 1024:  # 100MB 초과 스킵
            continue

        data = dump_region(pid, region["start"], region["end"])
        if not data:
            continue

        fname = f"dump_{region['start']:016x}_{region['end']:016x}.bin"
        fpath = Path(output_dir) / fname
        fpath.write_bytes(data)
        dumped.append(str(fpath))
        print(f"  [+] 덤프: {region['start']:#x}-{region['end']:#x} "
              f"({len(data):,} bytes) → {fname}")

    return dumped


def main() -> None:
    parser = argparse.ArgumentParser(description="프로세스 메모리 덤프 도구")
    parser.add_argument("pid", type=int, help="대상 프로세스 PID")
    parser.add_argument("-o", "--output", default="/tmp/memdump", help="덤프 저장 디렉토리")
    parser.add_argument("--all", action="store_true", help="실행 권한 없는 영역도 덤프")
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("[!] root 권한 필요 (sudo python3 memdump.py ...)", file=sys.stderr)

    print(f"[*] PID {args.pid} 메모리 덤프 → {args.output}")
    dumped = dump_executable_regions(args.pid, args.output)
    print(f"[+] 완료: {len(dumped)}개 영역 덤프")


if __name__ == "__main__":
    main()
```

---

## 3. 코드 난독화 패턴 분석

### 3.1 제어 흐름 평탄화(Control Flow Flattening)

제어 흐름 평탄화는 원래의 if-else, 루프 구조를 하나의 거대한 switch 문으로 변환해 분석을 어렵게 만든다.

**탐지 특징:**
- 함수 내에 거대한 switch-case 존재
- 모든 기본 블록이 같은 디스패처로 돌아옴
- `state` 또는 `selector` 변수가 분기를 결정

```bash
# Ghidra에서 제어 흐름 평탄화 탐지
# 1. 함수의 기본 블록 수 확인 (정상보다 훨씬 많음)
# 2. Decompiler에서 switch(state) 패턴 확인
# 3. 모든 case가 동일한 점프 대상으로 수렴
```

### 3.2 문자열 암호화

악성코드는 문자열(URL, 명령어, 키)을 XOR, ROT, AES로 암호화해 저장한다.

```bash
# strings로 평문 문자열 없는 경우 암호화 의심
strings suspicious_binary | wc -l  # 매우 적으면 의심

# floss(FireEye)로 동적 문자열 추출
floss suspicious_binary

# Ghidra에서 XOR 복호화 루프 탐지:
# - 루프 내에서 XOR 연산
# - 상수 키 값 사용
# - 결과를 배열에 저장
```

### 3.3 가상화 난독화(VM-based Obfuscation)

Themida, VMProtect 등은 원래 코드를 가상 머신 바이트코드로 변환한다.

**탐지 및 분석:**
```bash
# 섹션 이름으로 탐지
strings binary | grep -iE "(themida|vmprotect|vmp|obsidium)"

# 가상화된 코드 특징:
# - 정상 x86 명령어가 거의 없음
# - 디스어셈블리가 의미 없는 코드로 가득함
# - 인터프리터 루프 존재 (fetch-decode-execute)
```

---

## 4. Ghidra 스크립트로 자동 디옵스케이션

### 4.1 Ghidra Java 스크립트

```java
// DeobfuscateXorStrings.java
// Ghidra Script: XOR 암호화 문자열 자동 복호화
// Script -> Run Script 메뉴에서 실행

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;

public class DeobfuscateXorStrings extends GhidraScript {

    @Override
    public void run() throws Exception {
        println("XOR 문자열 복호화 시작...");

        // 프로그램 메모리에서 XOR 루프 패턴 탐지
        // (실제 구현은 바이너리별로 커스터마이징 필요)
        Memory mem = currentProgram.getMemory();
        AddressSetView executableSet = mem.getExecuteSet();

        // 데이터 섹션에서 암호화된 배열 검색
        MemoryBlock dataBlock = mem.getBlock(".data");
        if (dataBlock == null) {
            println(".data 섹션을 찾지 못했습니다.");
            return;
        }

        // XOR 키 0x41로 복호화 시도 (예시)
        byte xorKey = 0x41;
        byte[] encryptedData = new byte[(int) dataBlock.getSize()];
        dataBlock.getBytes(dataBlock.getStart(), encryptedData);

        StringBuilder decrypted = new StringBuilder();
        for (byte b : encryptedData) {
            char c = (char) (b ^ xorKey);
            if (c >= 0x20 && c < 0x7F) {
                decrypted.append(c);
            } else {
                if (decrypted.length() > 4) {
                    println("복호화 문자열: " + decrypted.toString());
                }
                decrypted = new StringBuilder();
            }
        }
        println("완료.");
    }
}
```

### 4.2 Ghidra Python 스크립트 (Jython)

```python
# auto_rename_functions.py
# Ghidra Script: 알려진 패턴으로 함수 자동 이름 변경

from ghidra.program.model.listing import Function
from ghidra.app.decompiler import DecompInterface

def decompile_function(func):
    """함수를 디컴파일해 C 코드 문자열을 반환한다."""
    decomp = DecompInterface()
    decomp.openProgram(currentProgram)
    result = decomp.decompileFunction(func, 30, monitor)
    if result.decompileCompleted():
        return result.getDecompiledFunction().getC()
    return ""

def rename_crypto_functions():
    """암호화 관련 함수 패턴을 탐지해 이름을 변경한다."""
    fm = currentProgram.getFunctionManager()
    renamed = 0

    for func in fm.getFunctions(True):
        # 디컴파일 코드에서 XOR 루프 패턴 탐지
        code = decompile_function(func)
        if not code:
            continue

        if "^ 0x" in code and "for" in code and func.getName().startswith("FUN_"):
            new_name = "xor_decrypt_" + func.getName()[4:]
            func.setName(new_name, ghidra.program.model.symbol.SourceType.USER_DEFINED)
            print(f"이름 변경: {func.getName()} → {new_name}")
            renamed += 1

    print(f"완료: {renamed}개 함수 이름 변경")

rename_crypto_functions()
```

---

## 5. Python XOR/ROT 문자열 복호화 자동화

```python
#!/usr/bin/env python3
"""
바이너리 파일에서 XOR/ROT 암호화 문자열을 자동으로 복호화하는 도구.
알려지지 않은 키에 대해 브루트포스를 수행하고 출력 가능한 문자열만 선별한다.
"""

import argparse
import sys
from pathlib import Path
from typing import Optional


def xor_decode(data: bytes, key: int | bytes) -> bytes:
    """XOR 복호화. key는 단일 바이트 또는 다중 바이트 키."""
    if isinstance(key, int):
        return bytes(b ^ key for b in data)
    # 다중 바이트 XOR
    key_len = len(key)
    return bytes(b ^ key[i % key_len] for i, b in enumerate(data))


def rot_decode(data: bytes, shift: int) -> bytes:
    """ROT 복호화 (알파벳 문자에만 적용)."""
    result = bytearray()
    for b in data:
        if 65 <= b <= 90:   # 대문자
            result.append((b - 65 - shift) % 26 + 65)
        elif 97 <= b <= 122: # 소문자
            result.append((b - 97 - shift) % 26 + 97)
        else:
            result.append(b)
    return bytes(result)


def is_printable_string(data: bytes, min_len: int = 4, threshold: float = 0.7) -> bool:
    """바이트 배열이 출력 가능한 ASCII 문자열인지 확인한다."""
    if len(data) < min_len:
        return False
    printable_count = sum(0x20 <= b < 0x7F or b in (0x09, 0x0A, 0x0D) for b in data)
    return (printable_count / len(data)) >= threshold


def extract_strings(data: bytes, min_len: int = 4) -> list[str]:
    """바이트 배열에서 연속된 출력 가능 문자열을 추출한다."""
    strings: list[str] = []
    current = bytearray()

    for b in data:
        if 0x20 <= b < 0x7F:
            current.append(b)
        else:
            if len(current) >= min_len:
                strings.append(current.decode("ascii", errors="replace"))
            current = bytearray()

    if len(current) >= min_len:
        strings.append(current.decode("ascii", errors="replace"))
    return strings


def bruteforce_xor_single(
    data: bytes, min_len: int = 4
) -> list[tuple[int, list[str]]]:
    """0x01~0xFF의 단일 바이트 XOR 키를 브루트포스한다."""
    results: list[tuple[int, list[str]]] = []

    for key in range(1, 256):
        decoded = xor_decode(data, key)
        if is_printable_string(decoded, min_len, threshold=0.5):
            strings = extract_strings(decoded, min_len)
            if strings:
                results.append((key, strings))

    return results


def bruteforce_xor_multi(
    data: bytes, key_length: int = 4, min_len: int = 4
) -> list[tuple[bytes, list[str]]]:
    """다중 바이트 XOR 키를 빈도 분석으로 추측한다."""
    # 각 위치별 가장 흔한 바이트 = XOR 키 후보 (0x20 기준)
    key_guess = bytearray()
    for i in range(key_length):
        chunk = bytes(data[j] for j in range(i, len(data), key_length))
        if not chunk:
            key_guess.append(0x20)
            continue
        freq: dict[int, int] = {}
        for b in chunk:
            freq[b] = freq.get(b, 0) + 1
        most_common = max(freq, key=lambda x: freq[x])
        key_guess.append(most_common ^ 0x20)  # 공백 문자(0x20) 기준

    key = bytes(key_guess)
    decoded = xor_decode(data, key)
    strings = extract_strings(decoded, min_len)
    return [(key, strings)] if strings else []


def analyze_section(
    file_path: str,
    section_offset: int = 0,
    section_size: Optional[int] = None,
) -> bytes:
    """파일의 특정 섹션 데이터를 읽어 반환한다."""
    data = Path(file_path).read_bytes()
    end = section_offset + section_size if section_size else len(data)
    return data[section_offset:end]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="바이너리 XOR/ROT 문자열 복호화 자동화",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
예시:
  # 단일 바이트 XOR 브루트포스
  python3 deobfuscate.py binary.exe --method xor-brute

  # 알려진 XOR 키로 복호화
  python3 deobfuscate.py binary.exe --method xor --key 0x41

  # ROT 복호화 (모든 시프트 시도)
  python3 deobfuscate.py binary.exe --method rot-brute

  # 다중 바이트 XOR (키 길이 4)
  python3 deobfuscate.py binary.exe --method xor-multi --key-len 4
        """,
    )
    parser.add_argument("file", help="분석할 바이너리 파일")
    parser.add_argument(
        "--method",
        choices=["xor", "xor-brute", "xor-multi", "rot", "rot-brute"],
        default="xor-brute",
        help="복호화 방법 (기본: xor-brute)",
    )
    parser.add_argument("--key", default="", help="XOR 키 (단일: 0x41, 문자열: 'key')")
    parser.add_argument("--key-len", type=int, default=4, help="다중 바이트 XOR 키 길이")
    parser.add_argument("--offset", type=int, default=0, help="파일 오프셋")
    parser.add_argument("--size", type=int, default=0, help="분석 크기 (0=전체)")
    parser.add_argument("--min-len", type=int, default=4, help="최소 문자열 길이")
    args = parser.parse_args()

    data = analyze_section(
        args.file, args.offset, args.size if args.size else None
    )
    print(f"[*] 분석 크기: {len(data):,} bytes  방법: {args.method}")

    if args.method == "xor":
        key_val = int(args.key, 16) if args.key.startswith("0x") else ord(args.key[0]) if args.key else 0
        decoded = xor_decode(data, key_val)
        strings = extract_strings(decoded, args.min_len)
        print(f"[+] XOR 0x{key_val:02X} → {len(strings)}개 문자열:")
        for s in strings[:30]:
            print(f"    {s}")

    elif args.method == "xor-brute":
        results = bruteforce_xor_single(data, args.min_len)
        print(f"[+] {len(results)}개 키 후보 발견:")
        for key, strings in results[:5]:  # 상위 5개만 출력
            print(f"\n  키: 0x{key:02X}")
            for s in strings[:10]:
                print(f"    {s}")

    elif args.method == "xor-multi":
        results = bruteforce_xor_multi(data, args.key_len, args.min_len)
        for key, strings in results:
            print(f"[+] 추정 키: {key.hex()} ({key!r})")
            for s in strings[:20]:
                print(f"    {s}")

    elif args.method == "rot":
        shift = int(args.key) if args.key else 13
        decoded = rot_decode(data, shift)
        strings = extract_strings(decoded, args.min_len)
        print(f"[+] ROT{shift} → {len(strings)}개 문자열:")
        for s in strings[:30]:
            print(f"    {s}")

    elif args.method == "rot-brute":
        print("[*] ROT 0~25 전체 시도:")
        for shift in range(1, 26):
            decoded = rot_decode(data, shift)
            strings = extract_strings(decoded, args.min_len)
            if strings:
                print(f"  ROT{shift:2d}: {strings[:3]}")


if __name__ == "__main__":
    main()
```

**사용 예시:**
```bash
# 단일 XOR 브루트포스 (가장 일반적)
python3 deobfuscate.py malware.bin --method xor-brute

# 알려진 키 0x41로 복호화
python3 deobfuscate.py malware.bin --method xor --key 0x41

# ROT13 복호화
python3 deobfuscate.py malware.bin --method rot --key 13

# 다중 바이트 XOR (키 길이 8)
python3 deobfuscate.py malware.bin --method xor-multi --key-len 8
```

---

## 6. 상용 가상화 패커(VMProtect/Themida) 대응 개요

UPX 같은 일반 패커는 "압축 해제 후 원본 코드로 점프"하는 단순 구조라 OEP(Original Entry Point)만 찾으면 덤프할 수 있다. 반면 **VMProtect**·**Themida**는 원본 x86 코드를 자체 **바이트코드**로 변환하고, 그 바이트코드를 해석하는 **커스텀 가상 머신**을 실행 파일 안에 심어둔다. 디스어셈블러에는 실제 로직 대신 VM 인터프리터의 반복적인 디스패치 루프만 보이므로, 정적 분석만으로는 원본 로직을 알 수 없다.

```
[VM 기반 패커 판별 신호]
- 디스어셈블에 반복적인 "handler dispatch" 패턴(큰 switch/점프 테이블)이 지배적
- 실제 API 호출이 거의 안 보이고 대신 알 수 없는 커스텀 스택 조작이 대부분
- 엔트로피 스캔(예: `die`, `detect-it-easy`) 결과 VMProtect/Themida 시그니처 매칭
- 문자열 섹션이 거의 비어있음 (원본 문자열도 VM 바이트코드에 숨겨짐)

[일반적 대응 전략]
1. 정적 디스어셈블 대신 동적 트레이싱(예: Intel Pin, x64dbg의 TitanEngine,
   또는 QEMU 기반 전체 명령어 트레이스)으로 실행 흐름 자체를 로그로 남긴다.
2. 트레이스에서 "VM 핸들러 진입/이탈" 경계를 식별해 핸들러별로 원본 연산
   (add, mov, cmp 등)에 대응시키는 매핑을 구축한다 (devirtualization).
3. 완전 자동 devirtualization은 매우 어렵고 버전마다 깨지므로, 실전에서는
   "관심 있는 특정 함수(예: 라이선스 체크, 문자열 복호화 루틴)만" 타겟 트레이싱하는
   것이 현실적이다.
```

```bash
# 패커 판별 (Detect It Easy, CLI)
diec malware.exe

# 동적 트레이스 예시 (x64dbg 스크립팅 또는 Frida로 특정 함수 진입/이탈 후킹)
# frida -f malware.exe -l trace_vm_calls.js --no-pause
```

**참고**: 완전한 VM devirtualization은 이 문서의 범위를 넘는 전문 영역이다(공개 도구로 `NoVmp`, `VMPvivisect` 등이 있으나 VM 버전에 따라 동작이 자주 깨진다). 실무에서는 전체 역공학보다 **동적 분석으로 최종 판단 결과(라이선스 통과/실패, 복호화된 문자열 등)만 훅으로 가로채는** 것이 훨씬 효율적인 경우가 많다.

---

## 참고 자료

- Ghidra 공식 저장소: https://github.com/NationalSecurityAgency/ghidra
- UPX 공식 저장소: https://github.com/upx/upx

---

<!-- detect-validate-04 -->
## 언패킹 결과 검증

언패킹·난독화 해제는 *원본 코드를 복원*하지만, 잘못 덤프하면 OEP·임포트가 깨진 채 분석을 이어가게 된다. 분석자는 **덤프가 실제로 완전 복원됐는가**를 검증해야 한다 — "덤프했다 ≠ 복원됐다".

### 기만 기법 → 노리는 분석 단계 → 분석자 대응 → 관찰 신호

| 단계 | 검증 질문 | 측정 신호 | 함정 |
|---|---|---|---|
| OEP 도달 | 진짜 진입점인가? | 텐션 점프 후 정상 prologue | 너무 이른 덤프(미해제 구간) |
| 임포트 복원 | IAT 가 재구성됐나? | 정상 임포트 테이블 | 빈/깨진 IAT |
| 섹션 정규화 | 엔트로피 정상화? | 코드섹션 <6.5 | 여전한 고엔트로피 |
| 재실행 가능 | 덤프가 동작하나? | 샌드박스 정상 구동 | 깨진 재배치/리소스 |

### 분석 검증 (직접 확인)

```bash
# 언패킹 덤프가 실제로 복원됐는지 검증(소유/샌드박스) — 패커 시그니처 소멸 + IAT 재구성 확인
die ./unpacked.bin 2>/dev/null || rabin2 -I ./unpacked.bin   # 패커 시그니처가 사라졌는지
rabin2 -i ./unpacked.bin 2>/dev/null | head                 # 임포트(IAT) 비었으면 미복원
python3 -c "import pefile,math;from collections import Counter as C;\
p=pefile.PE('unpacked.bin');\
print([(s.Name.decode(errors='ignore').rstrip(chr(0)), round(-sum((n/len(s.get_data()))*math.log2(n/len(s.get_data())) for n in C(s.get_data()).values()),2)) for s in p.sections if s.get_data()])"
```

> 분석은 반드시 **소유/통제된 샌드박스**에서만. 덤프를 떴다고 복원이 끝난 게 아니다 — 패커 시그니처 소멸, IAT 재구성, 엔트로피 정규화, 재실행 가능성을 확인해야 신뢰할 수 있다([[65_Reverse_Engineering_Advanced]], [[72_Malware_Sandbox_Analysis]]).

---

<a name="english"></a>

# Advanced Unpacking and Deobfuscation

## 1. Packing Detection

Packing compresses or encrypts an executable to hinder analysis. The packer stub decompresses/decrypts the original code at runtime.

### 1.1 Initial Detection

```bash
# Check entropy (packed files have high entropy ≈ 7.0–8.0)
python3 -c "
import math, sys
def entropy(data):
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    n = len(data)
    return -sum(c/n * math.log2(c/n) for c in freq.values())
with open(sys.argv[1], 'rb') as f:
    data = f.read()
e = entropy(data)
print(f'Entropy: {e:.4f} — {\"Packed (suspicious)\" if e > 6.8 else \"Normal\"}')
" target_binary

# Look for packer signatures in strings
strings target_binary | grep -iE "(upx|mpress|aspack|petite|themida|vmprotect)"

# Check section names (UPX uses UPX0, UPX1)
readelf -S target_binary | grep -iE "(upx|pack)"
```

### 1.2 UPX Unpacking

```bash
# Verify UPX signature
strings target_binary | grep "UPX!"

# Unpack
upx -d packed_binary -o unpacked_binary
file unpacked_binary
```

### 1.3 Custom Packer Detection

```bash
# Suspicious: very few sections
readelf -S target_binary | grep -c "\[.*\]"

# Entry point outside .text section
readelf -h target_binary | grep "Entry point"

# Very sparse import table
objdump -d target_binary | grep -c "plt>"
```

---

## 2. Dynamic Unpacking Techniques

### 2.1 Finding the OEP (Original Entry Point)

The OEP is where the original program code begins after the unpacking stub finishes.

**GDB approach:**
```bash
gdb -q target_binary
(gdb) catch syscall mprotect    # break when memory permissions change
(gdb) run
(gdb) info registers rip
(gdb) x/20i $rip               # inspect instructions at current position
```

**ESP trick:**
```bash
gdb -q target_binary
(gdb) break *<entry_point>
(gdb) run
(gdb) watch -l *(int*)($rsp)   # watch the saved stack pointer value
(gdb) continue                  # stops at OEP
```

### 2.2 Memory Dumping

```bash
# GDB memory dump
(gdb) dump memory /tmp/dump.bin 0x400000 0x401000

# Check memory layout
pmap -x $(pgrep target_binary)
```

Use the Python `memdump.py` script (see Korean section) to automatically dump all executable memory regions of a running process.

---

## 3. Code Obfuscation Pattern Analysis

### 3.1 Control Flow Flattening

Transforms if-else and loop structures into a single large switch dispatcher.

**Detection signs:**
- Abnormally large number of basic blocks in one function
- `switch(state)` pattern in decompiler output
- All basic blocks converge to a single dispatcher node

### 3.2 String Encryption

Malware encrypts strings (URLs, commands, keys) using XOR, ROT, or AES.

```bash
# Too few strings = likely encrypted
strings suspicious_binary | wc -l

# FLOSS: dynamic string extraction
floss suspicious_binary
```

### 3.3 VM-based Obfuscation (Themida / VMProtect)

Converts original code into proprietary VM bytecode interpreted at runtime.

**Detection:**
```bash
strings binary | grep -iE "(themida|vmprotect|vmp|obsidium)"
# Characteristics: no meaningful x86 instructions, fetch-decode-execute loop
```

---

## 4. Ghidra Scripting for Automated Deobfuscation

### 4.1 Java Script (String Decryption)

The Java script `DeobfuscateXorStrings.java` (see Korean section):
- Reads the `.data` section bytes
- Applies XOR with a known key byte
- Extracts printable strings and prints them to the Ghidra console

### 4.2 Python Script (Function Renaming)

The Jython script `auto_rename_functions.py`:
- Decompiles each function using the Ghidra Decompiler API
- Detects XOR loop patterns (`^ 0x` + `for`)
- Renames matching functions from `FUN_xxxxxxxx` to `xor_decrypt_xxxxxxxx`

---

## 5. Python XOR/ROT String Decryption Automation

The `deobfuscate.py` script provides:

- **`xor`**: Single-byte XOR with a known key
- **`xor-brute`**: Brute-force all 255 single-byte XOR keys, filter printable results
- **`xor-multi`**: Frequency analysis to guess multi-byte XOR keys
- **`rot`**: ROT cipher with a specific shift value
- **`rot-brute`**: Try all 25 ROT shifts and show matches

```bash
# Brute-force unknown single-byte XOR key
python3 deobfuscate.py malware.bin --method xor-brute

# Decrypt with known key 0x41
python3 deobfuscate.py malware.bin --method xor --key 0x41

# Multi-byte XOR frequency analysis
python3 deobfuscate.py malware.bin --method xor-multi --key-len 8

# Analyze only a specific region
python3 deobfuscate.py malware.bin --method xor-brute --offset 4096 --size 2048
```

---

## 6. Dealing with Commercial VM-Based Packers (VMProtect/Themida) — Overview

A typical packer like UPX simply "decompresses and jumps to the original code," so finding the OEP (Original Entry Point) is enough to dump it. **VMProtect** and **Themida**, on the other hand, translate the original x86 code into their own **bytecode** and embed a **custom virtual machine** in the executable to interpret it. A disassembler only shows the VM interpreter's repetitive dispatch loop instead of the real logic, so static analysis alone cannot recover the original behavior.

```
[Signals that a VM-based packer is in play]
- Disassembly is dominated by a repeating "handler dispatch" pattern (a large switch/jump table)
- Almost no real API calls are visible; instead, mostly unrecognizable custom stack manipulation
- Entropy/signature scanners (e.g. `die`, Detect It Easy) match VMProtect/Themida signatures
- The strings section is nearly empty (original strings are hidden inside the VM bytecode too)

[General strategy]
1. Instead of static disassembly, use dynamic tracing (e.g. Intel Pin, x64dbg's
   TitanEngine, or a full instruction trace under QEMU) to log the actual execution flow.
2. From the trace, identify the "VM handler enter/exit" boundaries and build a mapping
   from each handler back to the original operation it implements (add, mov, cmp, etc.)
   — this is devirtualization.
3. Fully automated devirtualization is very hard and breaks across VM versions, so in
   practice it's more realistic to trace only the specific function you actually care
   about (e.g. a license check or a string-decryption routine).
```

```bash
# Packer identification (Detect It Easy, CLI)
diec malware.exe

# Dynamic trace example (x64dbg scripting, or Frida hooking a specific function's entry/exit)
# frida -f malware.exe -l trace_vm_calls.js --no-pause
```

**Note**: Full VM devirtualization is a specialized area beyond this document's scope (public tools like `NoVmp` and `VMPvivisect` exist, but they frequently break across VM versions). In practice, it's often far more efficient to skip full reverse engineering and **hook the final decision point via dynamic analysis** — e.g., the license pass/fail result or the decrypted string — rather than reconstruct the entire VM logic.

---

## References

- Ghidra Official Repository: https://github.com/NationalSecurityAgency/ghidra
- UPX Official Repository: https://github.com/upx/upx

<!-- detect-validate-04 -->
## Unpacking Result Validation

Unpacking/deobfuscation *recovers original code*, but a bad dump leaves OEP/imports broken while analysis continues on it. The analyst must verify **whether the dump is actually fully reconstructed** — "dumped != reconstructed".

### Deception -> Targeted analysis stage -> Analyst response -> Observable signal

| Stage | Validation question | Measured signal | Pitfall |
|---|---|---|---|
| OEP reached | Is it the real entry? | Tail jump then normal prologue | Too-early dump (still-packed region) |
| Import recovery | Is the IAT rebuilt? | Normal import table | Empty/broken IAT |
| Section normalization | Entropy normalized? | Code section <6.5 | Still high entropy |
| Re-executable | Does the dump run? | Runs in sandbox | Broken relocations/resources |

### Analysis validation (verify directly)

```bash
# Verify the unpacked dump is actually reconstructed (owned/sandbox) — packer signature gone + IAT rebuilt
die ./unpacked.bin 2>/dev/null || rabin2 -I ./unpacked.bin   # has the packer signature disappeared?
rabin2 -i ./unpacked.bin 2>/dev/null | head                 # empty imports (IAT) = not reconstructed
python3 -c "import pefile,math;from collections import Counter as C;\
p=pefile.PE('unpacked.bin');\
print([(s.Name.decode(errors='ignore').rstrip(chr(0)), round(-sum((n/len(s.get_data()))*math.log2(n/len(s.get_data())) for n in C(s.get_data()).values()),2)) for s in p.sections if s.get_data()])"
```

> Analyze only in **owned/controlled sandboxes**. A dump does not mean reconstruction is done — confirm packer signature is gone, IAT rebuilt, entropy normalized, and the dump re-executes ([[65_Reverse_Engineering_Advanced]], [[72_Malware_Sandbox_Analysis]]).
