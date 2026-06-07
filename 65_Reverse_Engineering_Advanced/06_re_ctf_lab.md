> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 고급 역공학 CTF 실습 랩

## 실습 개요

이 랩은 안티디버깅 우회, 패킹 해제, 심볼릭 실행, 난독화 복원 등 고급 역공학 기술을 CTF 형식으로 훈련합니다. 각 챌린지는 실제 CTF 대회에서 자주 출제되는 패턴을 기반으로 하며, 단계별 힌트와 도구 명령어를 제공합니다. 참고 프로젝트: [angr](https://github.com/angr/angr)

---

## 챌린지 목록

| 번호 | 이름 | 난이도 | 설명 |
|------|------|--------|------|
| C01 | DebugMe Not | ★☆☆ | `IsDebuggerPresent` 패치로 안티디버깅 우회 후 플래그 추출 |
| C02 | UPX Unboxer | ★★☆ | UPX 패킹된 바이너리 해제 후 숨겨진 문자열 추출 |
| C03 | Symbolic Gatekeeper | ★★☆ | angr 심볼릭 실행으로 복잡한 조건문 우회 |
| C04 | Obfuscation Nightmare | ★★★ | 다중 난독화가 적용된 바이너리에서 실제 로직 복원 |

---

## 챌린지 상세

### C01 — DebugMe Not (★☆☆)

**시나리오**

바이너리를 실행하면 "Debugger detected! Exiting." 메시지가 출력되고 종료됩니다. `IsDebuggerPresent` API 호출이 디버거를 감지하고 있으며, 이를 패치하여 플래그를 얻어야 합니다.

**학습 목표**
- `IsDebuggerPresent` 동작 원리 이해
- x64dbg 또는 GDB를 사용한 런타임 패치
- NOP 패치 기법

**힌트**
1. `strings ./debugme` 로 감지 메시지 확인
2. `objdump -d ./debugme | grep -A 5 "IsDebugger"` 로 호출 위치 파악
3. x64dbg에서 해당 `call` 명령을 `NOP`(0x90)으로 패치하거나 반환값을 0으로 강제 설정

**도구 명령어 예시**

```bash
# 바이너리 분석
strings ./debugme | grep -i "flag\|debug\|CTF"
objdump -d ./debugme | grep -B 2 "IsDebuggerPresent"

# GDB로 런타임 패치
gdb ./debugme
(gdb) break *main
(gdb) run
(gdb) set {unsigned char}0x<IsDebuggerPresent_call_addr> = 0x31  # xor eax,eax 효과
(gdb) set {unsigned char}0x<IsDebuggerPresent_call_addr+1> = 0xc0
(gdb) continue

# radare2로 정적 패치
r2 -w ./debugme
[0x00000000]> aaa
[0x00000000]> afl~IsDebugger
[0x00000000]> s 0x<call_addr>
[0x00000000]> wa nop; nop; nop; nop; nop
```

---

### C02 — UPX Unboxer (★★☆)

**시나리오**

바이너리를 실행하면 아무것도 출력되지 않습니다. `file` 명령으로 확인하면 UPX로 패킹되어 있음을 알 수 있습니다. 패킹을 해제하고 숨겨진 문자열에서 플래그를 추출하세요.

**학습 목표**
- UPX 패킹 구조 이해
- 자동/수동 언패킹 기법
- 엔트로피 분석으로 패킹 구간 식별

**힌트**
1. `file ./packed` 로 패킹 여부 확인
2. `upx -d ./packed -o ./unpacked` 로 자동 언패킹 시도
3. 자동 언패킹 실패 시: OEP(Original Entry Point)를 찾아 메모리 덤프
4. `strings ./unpacked | grep -E "CTF{|flag{"` 로 플래그 검색

**도구 명령어 예시**

```bash
# 패킹 확인
file ./packed
readelf -h ./packed | grep "Entry point"
python3 -c "
import math, collections
data = open('./packed','rb').read()
freq = collections.Counter(data)
entropy = -sum((c/len(data))*math.log2(c/len(data)) for c in freq.values())
print(f'Entropy: {entropy:.2f}')  # 7.5+ 이면 패킹 가능성 높음
"

# UPX 자동 언패킹
upx -d ./packed -o ./unpacked

# 수동 언패킹: x64dbg에서 OEP 찾기
# 1. ESP 값 기록 후 Hardware Breakpoint on memory access 설정
# 2. F9(run) → OEP에서 중단
# 3. Scylla 플러그인으로 IAT 복구 및 덤프

# 언패킹 후 분석
strings ./unpacked | grep -E "CTF\{|flag\{"
rabin2 -z ./unpacked | grep -i flag
```

---

### C03 — Symbolic Gatekeeper (★★☆)

**시나리오**

바이너리는 입력값을 받아 복잡한 수학적 조건문(15개 이상의 중첩 if)을 통과해야 플래그를 출력합니다. 수동 분석은 불가능하며, angr를 사용한 심볼릭 실행으로 조건을 통과하는 입력을 찾아야 합니다.

**학습 목표**
- angr 기본 사용법
- 심볼릭 실행의 개념 (구체값 대신 기호값으로 분기 탐색)
- 성공/실패 주소 기반 탐색 전략

**힌트**
1. `objdump -d ./gatekeeper | grep "puts\|printf"` 로 출력 위치 파악
2. Ghidra로 성공 분기(`"Correct!"` 출력)와 실패 분기 주소 확인
3. `angr.Project` + `state.posix.stdin` 으로 심볼릭 입력 설정
4. `simgr.explore(find=success_addr, avoid=fail_addr)` 로 탐색

**도구 명령어 예시**

```bash
# angr 설치
pip install angr

# 성공/실패 주소 확인
objdump -d ./gatekeeper | grep -A 2 "Correct\|Wrong"
# 또는 Ghidra/Binary Ninja에서 확인

# angr 기본 실행
python3 << 'EOF'
import angr, claripy

proj = angr.Project('./gatekeeper', auto_load_libs=False)
flag_chars = [claripy.BVS(f'flag_{i}', 8) for i in range(20)]
flag = claripy.Concat(*flag_chars)

state = proj.factory.full_init_state(
    stdin=claripy.Concat(*flag_chars, claripy.BVV(b'\n'))
)
for ch in flag_chars:
    state.solver.add(ch >= 0x20)
    state.solver.add(ch <= 0x7e)

simgr = proj.factory.simulation_manager(state)
simgr.explore(find=0x<success_addr>, avoid=0x<fail_addr>)

if simgr.found:
    s = simgr.found[0]
    result = s.solver.eval(flag, cast_to=bytes)
    print(f"Flag: {result.decode()}")
EOF
```

---

### C04 — Obfuscation Nightmare (★★★)

**시나리오**

상용 난독화 도구(LLVM obfuscator 수준)가 적용된 바이너리입니다. Control Flow Flattening, 불투명 술어(Opaque Predicates), 가짜 코드 삽입이 모두 적용되어 있습니다. 실제 플래그 검증 로직을 복원하고 플래그를 추출하세요.

**학습 목표**
- Control Flow Flattening 인식 및 복원 기법
- 불투명 술어 제거
- 동적 + 정적 분석 혼합 전략

**힌트**
1. Ghidra 또는 Binary Ninja로 CFG 시각화 → 비정상적으로 큰 switch 문 확인
2. `strace ./obf` 로 시스템 콜 흐름 확인 → 실제 로직이 어디서 발생하는지 추적
3. Frida로 함수 후킹: `strcmp`, `memcmp`, `strncmp` 호출 시 인자 로깅
4. DBI(Dynamic Binary Instrumentation)로 실행된 기본 블록 기록 → 핫 경로 식별

**도구 명령어 예시**

```bash
# 정적 분석: CFG 복잡도 확인
python3 -c "
import subprocess
out = subprocess.check_output(['objdump','-d','./obf']).decode()
funcs = [l for l in out.split('\n') if l.strip().endswith('>:')]
print(f'Functions: {len(funcs)}')
"

# Frida로 비교 함수 후킹
frida-trace -i "strcmp" -i "memcmp" -i "strncmp" ./obf

# 커스텀 Frida 스크립트
cat > hook.js << 'EOF'
Interceptor.attach(Module.findExportByName(null, 'strcmp'), {
    onEnter(args) {
        const s1 = args[0].readUtf8String();
        const s2 = args[1].readUtf8String();
        if (s1 && s2 && (s1.length > 4 || s2.length > 4)) {
            console.log(`strcmp("${s1}", "${s2}")`);
        }
    }
});
EOF
frida -l hook.js ./obf

# angr로 불투명 술어 제거 후 분석
python3 -c "
import angr
proj = angr.Project('./obf', auto_load_libs=False)
cfg = proj.analyses.CFGFast()
print(f'Nodes: {len(cfg.graph.nodes())}')
print(f'Edges: {len(cfg.graph.edges())}')
"
```

---

## CTF 스크립트

```python
#!/usr/bin/env python3
"""
고급 역공학 CTF 시뮬레이터
섹션 65 - Reverse Engineering Advanced

사용법:
  python3 06_re_ctf_lab.py --list
  python3 06_re_ctf_lab.py --challenge C01
  python3 06_re_ctf_lab.py --challenge C01 --submit CTF{your_flag_here}
  python3 06_re_ctf_lab.py --hint C03
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from dataclasses import dataclass, field


@dataclass
class Challenge:
    id: str
    name: str
    difficulty: str
    description: str
    hints: list[str]
    flag_sha256: str          # 실제 플래그의 SHA-256 해시
    scenario: str
    tools: list[str]


CHALLENGES: dict[str, Challenge] = {
    "C01": Challenge(
        id="C01",
        name="DebugMe Not",
        difficulty="★☆☆",
        description="IsDebuggerPresent 패치로 안티디버깅 우회 후 플래그 추출",
        hints=[
            "Hint 1: strings ./debugme 로 바이너리 내 문자열을 확인하세요.",
            "Hint 2: objdump -d ./debugme | grep IsDebuggerPresent 로 호출 위치를 찾으세요.",
            "Hint 3: GDB에서 'set {unsigned char}0xADDR = 0x31' 로 반환값을 0으로 패치하세요.",
            "Hint 4: r2 -w ./debugme → wa nop 으로 정적 패치도 가능합니다.",
        ],
        flag_sha256="a3f5c2e8d1b4a7f9c6e3d0b2a8f5c1e7d4b0a6f3c9e2d8b5a1f7c4e0d6b3a9f2",
        scenario="디버거 감지 후 즉시 종료하는 바이너리에서 플래그를 추출하세요.",
        tools=["gdb", "x64dbg", "radare2", "objdump"],
    ),
    "C02": Challenge(
        id="C02",
        name="UPX Unboxer",
        difficulty="★★☆",
        description="UPX 패킹된 바이너리 해제 후 숨겨진 문자열 추출",
        hints=[
            "Hint 1: file ./packed 로 패킹 형식을 확인하세요.",
            "Hint 2: upx -d ./packed -o ./unpacked 로 자동 언패킹을 시도하세요.",
            "Hint 3: 자동 실패 시 x64dbg + Scylla로 OEP에서 메모리 덤프하세요.",
            "Hint 4: strings ./unpacked | grep -E 'CTF{' 로 플래그를 검색하세요.",
        ],
        flag_sha256="b7e4d1a8f5c2b9e6d3a0f7c4e1d8b5a2f9c6d3b0a7e4f1c8d5b2a9e6f3c0d7b4",
        scenario="UPX로 패킹된 바이너리를 언패킹하고 숨겨진 플래그를 찾으세요.",
        tools=["upx", "strings", "x64dbg", "Scylla", "rabin2"],
    ),
    "C03": Challenge(
        id="C03",
        name="Symbolic Gatekeeper",
        difficulty="★★☆",
        description="angr 심볼릭 실행으로 복잡한 조건문 우회",
        hints=[
            "Hint 1: pip install angr 로 angr를 설치하세요.",
            "Hint 2: Ghidra에서 'Correct!' 문자열 참조로 성공 주소를 찾으세요.",
            "Hint 3: claripy.BVS로 심볼릭 입력을 만들고 state.solver.add()로 제약을 추가하세요.",
            "Hint 4: simgr.explore(find=success_addr, avoid=fail_addr) 로 탐색을 시작하세요.",
        ],
        flag_sha256="c9f6d3a0e7b4c1f8d5a2e9f6c3d0b7e4a1f8d5c2b9e6a3f0c7d4b1e8f5a2c9d6",
        scenario="15개 이상의 중첩 조건문을 통과하는 입력값을 angr로 찾으세요.",
        tools=["angr", "Ghidra", "Binary Ninja", "claripy"],
    ),
    "C04": Challenge(
        id="C04",
        name="Obfuscation Nightmare",
        difficulty="★★★",
        description="다중 난독화가 적용된 바이너리에서 실제 로직 복원",
        hints=[
            "Hint 1: Ghidra CFG 뷰에서 비정상적으로 큰 switch 구조를 찾으세요 (CFF 특징).",
            "Hint 2: frida-trace -i strcmp -i memcmp ./obf 로 비교 함수 인자를 로깅하세요.",
            "Hint 3: strace ./obf 2>&1 | grep -E 'read|write' 로 I/O 흐름을 추적하세요.",
            "Hint 4: angr CFGFast로 기본 블록 수를 확인하고 핫 경로를 식별하세요.",
        ],
        flag_sha256="d1a8e5c2f9b6d3a0e7c4f1d8b5a2e9c6f3d0b7e4a1f8c5d2b9e6c3a0f7d4b1e8",
        scenario="CFF, 불투명 술어, 가짜 코드가 모두 적용된 바이너리의 로직을 복원하세요.",
        tools=["Ghidra", "Frida", "angr", "strace", "Binary Ninja"],
    ),
}


def list_challenges() -> None:
    print("\n고급 역공학 CTF 실습 랩 — 챌린지 목록\n")
    print(f"{'번호':<6} {'이름':<22} {'난이도':<8} 설명")
    print("-" * 72)
    for ch in CHALLENGES.values():
        print(f"{ch.id:<6} {ch.name:<22} {ch.difficulty:<8} {ch.description}")
    print()


def show_challenge(challenge_id: str) -> None:
    ch = CHALLENGES.get(challenge_id.upper())
    if ch is None:
        print(f"[오류] 존재하지 않는 챌린지: {challenge_id}")
        sys.exit(1)
    print(f"\n{'='*60}")
    print(f"  [{ch.id}] {ch.name}  {ch.difficulty}")
    print(f"{'='*60}")
    print(f"\n시나리오\n  {ch.scenario}")
    print(f"\n권장 도구\n  {', '.join(ch.tools)}")
    print(f"\n힌트 확인: python3 06_re_ctf_lab.py --hint {ch.id}")
    print(f"플래그 제출: python3 06_re_ctf_lab.py --challenge {ch.id} --submit CTF{{your_flag}}\n")


def show_hint(challenge_id: str) -> None:
    ch = CHALLENGES.get(challenge_id.upper())
    if ch is None:
        print(f"[오류] 존재하지 않는 챌린지: {challenge_id}")
        sys.exit(1)
    print(f"\n[{ch.id}] {ch.name} — 힌트\n")
    for i, hint in enumerate(ch.hints, 1):
        print(f"  {hint}")
    print()


def submit_flag(challenge_id: str, flag: str) -> None:
    ch = CHALLENGES.get(challenge_id.upper())
    if ch is None:
        print(f"[오류] 존재하지 않는 챌린지: {challenge_id}")
        sys.exit(1)

    flag_hash = hashlib.sha256(flag.strip().encode()).hexdigest()

    print(f"\n[{ch.id}] {ch.name} — 플래그 검증")
    print(f"  제출: {flag.strip()}")
    print(f"  해시: {flag_hash[:16]}...")

    if flag_hash == ch.flag_sha256:
        print(f"\n  정답입니다! 챌린지 [{ch.id}] 클리어!\n")
    else:
        print(f"\n  오답입니다. 힌트를 참고하세요: python3 06_re_ctf_lab.py --hint {ch.id}\n")


def simulate_analysis(challenge_id: str) -> None:
    """각 챌린지별 분석 시뮬레이션을 출력합니다."""
    ch = CHALLENGES.get(challenge_id.upper())
    if ch is None:
        print(f"[오류] 존재하지 않는 챌린지: {challenge_id}")
        sys.exit(1)

    simulations: dict[str, list[str]] = {
        "C01": [
            "[*] 바이너리 분석 시작: debugme",
            "[*] strings 실행 중...",
            "    >> 'Debugger detected! Exiting.'",
            "    >> 'Correct! Flag: CTF{...'  (암호화됨)",
            "[*] IsDebuggerPresent 호출 위치: 0x00401234",
            "[*] GDB 패치 적용: set {unsigned char}0x401234 = 0x31",
            "[*] 패치 후 실행...",
            "[+] 플래그 출력 성공!",
        ],
        "C02": [
            "[*] 바이너리 확인: packed",
            "[*] file ./packed → 'UPX compressed'",
            "[*] 엔트로피 분석: 7.84 (매우 높음, 패킹 확인)",
            "[*] upx -d ./packed -o ./unpacked 실행 중...",
            "[+] 언패킹 성공: ./unpacked 생성",
            "[*] strings ./unpacked | grep CTF 실행 중...",
            "[+] 플래그 발견!",
        ],
        "C03": [
            "[*] 바이너리 분석: gatekeeper",
            "[*] Ghidra 분석 완료 → 성공 주소: 0x00401abc",
            "[*] 실패 주소: 0x00401def",
            "[*] angr 프로젝트 초기화 중...",
            "[*] 심볼릭 입력 20바이트 생성",
            "[*] simgr.explore() 실행 중... (수십 초 소요)",
            "[+] 해 발견! 심볼릭 솔버 실행 중...",
            "[+] 입력값 복원 완료 → 플래그 획득!",
        ],
        "C04": [
            "[*] 바이너리 분석: obf",
            "[*] angr CFGFast → Nodes: 1,247, Edges: 3,891 (비정상적으로 많음)",
            "[*] CFF(Control Flow Flattening) 패턴 감지됨",
            "[*] Frida 후킹 시작: strcmp, memcmp, strncmp",
            "[*] strcmp('CTF{', user_input[:4]) 호출 감지",
            "[*] memcmp(flag_buf, user_input, 32) 호출 감지",
            "[+] 비교 대상 복원 완료 → 플래그 획득!",
        ],
    }

    steps = simulations.get(challenge_id.upper(), [])
    print(f"\n[시뮬레이션] {ch.id} — {ch.name}\n")
    for step in steps:
        print(f"  {step}")
    print()


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="06_re_ctf_lab.py",
        description="고급 역공학 CTF 실습 시뮬레이터 (섹션 65)",
    )
    parser.add_argument("--list", action="store_true", help="챌린지 목록 출력")
    parser.add_argument("--challenge", metavar="ID", help="챌린지 상세 정보 (예: C01)")
    parser.add_argument("--hint", metavar="ID", help="힌트 출력 (예: C01)")
    parser.add_argument("--submit", metavar="FLAG", help="플래그 제출 (--challenge 와 함께 사용)")
    parser.add_argument("--simulate", metavar="ID", help="분석 시뮬레이션 출력 (예: C01)")

    args = parser.parse_args()

    if args.list:
        list_challenges()
    elif args.hint:
        show_hint(args.hint)
    elif args.simulate:
        simulate_analysis(args.simulate)
    elif args.challenge and args.submit:
        submit_flag(args.challenge, args.submit)
    elif args.challenge:
        show_challenge(args.challenge)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
```

---

<a name="english"></a>

# Advanced Reverse Engineering CTF Lab

## Lab Overview

This lab trains advanced reverse engineering skills — anti-debugging bypass, unpacking, symbolic execution, and deobfuscation — in CTF format. Each challenge is based on patterns commonly seen in real CTF competitions and includes step-by-step hints and tool commands. Reference project: [angr](https://github.com/angr/angr)

---

## Challenge List

| No. | Name | Difficulty | Description |
|-----|------|------------|-------------|
| C01 | DebugMe Not | ★☆☆ | Patch `IsDebuggerPresent` to bypass anti-debugging and extract the flag |
| C02 | UPX Unboxer | ★★☆ | Unpack a UPX-packed binary and extract the hidden string |
| C03 | Symbolic Gatekeeper | ★★☆ | Use angr symbolic execution to bypass complex conditionals |
| C04 | Obfuscation Nightmare | ★★★ | Recover real logic from a multiply-obfuscated binary |

---

## Challenge Details

### C01 — DebugMe Not (★☆☆)

**Scenario**

Running the binary prints "Debugger detected! Exiting." and terminates. An `IsDebuggerPresent` API call is detecting the debugger. Patch it to retrieve the flag.

**Learning Goals**
- Understand how `IsDebuggerPresent` works
- Runtime patching with x64dbg or GDB
- NOP patching technique

**Hints**
1. Use `strings ./debugme` to view embedded strings
2. `objdump -d ./debugme | grep -A 5 "IsDebugger"` to locate the call
3. In x64dbg patch the `call` to `NOP` (0x90), or force the return value to 0

**Tool Commands**

```bash
strings ./debugme | grep -i "flag\|debug\|CTF"
objdump -d ./debugme | grep -B 2 "IsDebuggerPresent"

gdb ./debugme
(gdb) break *main
(gdb) run
(gdb) set {unsigned char}0x<addr> = 0x31
(gdb) set {unsigned char}0x<addr+1> = 0xc0
(gdb) continue

r2 -w ./debugme
[0x00000000]> aaa
[0x00000000]> s 0x<call_addr>
[0x00000000]> wa nop; nop; nop; nop; nop
```

---

### C02 — UPX Unboxer (★★☆)

**Scenario**

The binary produces no output. The `file` command reveals it is UPX-packed. Unpack it and extract the flag from the hidden strings.

**Hints**
1. `file ./packed` to confirm packing format
2. `upx -d ./packed -o ./unpacked` for automatic unpacking
3. On failure, find the OEP in x64dbg and dump memory with Scylla
4. `strings ./unpacked | grep -E "CTF{|flag{"` to search for the flag

**Tool Commands**

```bash
file ./packed
upx -d ./packed -o ./unpacked
strings ./unpacked | grep -E "CTF\{|flag\{"
rabin2 -z ./unpacked | grep -i flag
```

---

### C03 — Symbolic Gatekeeper (★★☆)

**Scenario**

The binary accepts input and passes it through 15+ nested conditionals before printing the flag. Manual analysis is impractical. Use angr symbolic execution to find the correct input.

**Hints**
1. `pip install angr`
2. Find the success address ("Correct!" string reference) in Ghidra
3. Create symbolic input with `claripy.BVS` and add ASCII constraints
4. `simgr.explore(find=success_addr, avoid=fail_addr)`

**Tool Commands**

```bash
pip install angr

python3 << 'EOF'
import angr, claripy
proj = angr.Project('./gatekeeper', auto_load_libs=False)
flag_chars = [claripy.BVS(f'flag_{i}', 8) for i in range(20)]
flag = claripy.Concat(*flag_chars)
state = proj.factory.full_init_state(
    stdin=claripy.Concat(*flag_chars, claripy.BVV(b'\n'))
)
for ch in flag_chars:
    state.solver.add(ch >= 0x20)
    state.solver.add(ch <= 0x7e)
simgr = proj.factory.simulation_manager(state)
simgr.explore(find=0x<success_addr>, avoid=0x<fail_addr>)
if simgr.found:
    result = simgr.found[0].solver.eval(flag, cast_to=bytes)
    print(f"Flag: {result.decode()}")
EOF
```

---

### C04 — Obfuscation Nightmare (★★★)

**Scenario**

A binary protected with Control Flow Flattening, Opaque Predicates, and junk code insertion. Recover the real flag-validation logic and extract the flag.

**Hints**
1. Visualize the CFG in Ghidra — look for an abnormally large switch dispatcher (CFF signature)
2. `frida-trace -i strcmp -i memcmp ./obf` to log comparison arguments
3. `strace ./obf` to follow system-call flow
4. Use `angr.analyses.CFGFast` to count basic blocks and identify hot paths

**Tool Commands**

```bash
frida-trace -i "strcmp" -i "memcmp" -i "strncmp" ./obf

cat > hook.js << 'EOF'
Interceptor.attach(Module.findExportByName(null, 'strcmp'), {
    onEnter(args) {
        const s1 = args[0].readUtf8String();
        const s2 = args[1].readUtf8String();
        if (s1 && s2 && (s1.length > 4 || s2.length > 4))
            console.log(`strcmp("${s1}", "${s2}")`);
    }
});
EOF
frida -l hook.js ./obf
```

---

## CTF Script

See the Korean section above for the full Python 3.10+ CTF simulator script (`06_re_ctf_lab.py`). Usage:

```bash
python3 06_re_ctf_lab.py --list
python3 06_re_ctf_lab.py --challenge C03
python3 06_re_ctf_lab.py --hint C03
python3 06_re_ctf_lab.py --simulate C03
python3 06_re_ctf_lab.py --challenge C03 --submit CTF{your_flag_here}
```
