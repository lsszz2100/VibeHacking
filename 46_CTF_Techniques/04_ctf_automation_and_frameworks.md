# CTF 자동화와 프레임워크

pwntools 고급 기능, angr 심볼릭 실행, Frida 동적 계측, 포렌식 자동화 파이프라인, CTFd API 자동화까지 CTF를 체계적으로 공략하는 자동화 기법을 다룬다.

---

## 1. pwntools 고급 기능

### 1.1 DynELF — 런타임 libc 심볼 해결

```python
from pwn import *


def exploit_dynefl(io: tube, leak_function) -> None:
    """DynELF: 메모리 유출 함수로 libc 심볼 동적 탐색"""
    
    # leak_function: 주소를 받아 해당 주소의 내용을 반환하는 함수
    def leak(addr: int) -> bytes:
        return leak_function(io, addr)
    
    d = DynELF(leak, elf=ELF('./binary'))
    system_addr = d.lookup('system', 'libc')
    log.success(f"system @ 0x{system_addr:016x}")
    
    bin_sh_addr = d.lookup('/bin/sh', 'libc')
    log.success(f"/bin/sh @ 0x{bin_sh_addr:016x}")
    
    return system_addr, bin_sh_addr


# 실제 사용 예시 (printf 유출)
def printf_leak(io: tube, addr: int) -> bytes:
    """printf를 이용한 주소 유출"""
    io.sendlineafter(b"> ", b"leak " + p64(addr))
    return io.recv(8)
```

### 1.2 gdb.attach() 디버깅 통합

```python
from pwn import *

context.terminal = ['tmux', 'splitw', '-h']  # tmux 분할 창

io = process('./binary')

# GDB 첨부 (즉시 브레이크)
gdb.attach(io, gdbscript="""
    # 브레이크포인트 설정
    b *0x401234
    b *main+42
    
    # 메모리 감시
    watch *0x404000
    
    # 자동 실행
    continue
    
    # 특정 조건 브레이크
    b vuln
    commands
    info registers rsp rip rbp
    x/20gx $rsp
    continue
    end
""")

io.sendline(b"payload")
io.interactive()
```

### 1.3 ROP 클래스 고급 활용

```python
from pwn import *

elf = ELF('./binary')
libc = ELF('./libc.so.6')
rop = ROP([elf, libc])

# 자동 ROP 체인 구성
# 1. mprotect로 스택 실행 가능하게 만들기
rop.mprotect(0x404000, 0x1000, 7)  # rwx

# 2. 특정 함수 호출
rop.call('puts', [elf.got['read']])

# 3. 가젯 직접 지정
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
rop.raw(pop_rdi)
rop.raw(next(libc.search(b'/bin/sh')))
rop.call(libc.sym['system'])

print(rop.dump())

# 체인 내보내기
chain = rop.chain()
payload = b'A' * 72 + chain
```

---

## 2. angr 심볼릭 실행 자동화

### 2.1 함수 탐색 패턴

```python
#!/usr/bin/env python3
"""angr CTF 자동화 프레임워크"""

import angr
import claripy
import sys
from typing import Callable


def find_flag(
    binary: str,
    find_condition: Callable | int,
    avoid_condition: Callable | int | None = None,
    flag_length: int = 32,
    flag_prefix: str = "CTF{",
    stdin_mode: bool = True,
) -> bytes | None:
    """범용 CTF 플래그 탐색"""
    
    proj = angr.Project(binary, auto_load_libs=False)
    
    # 심볼릭 플래그 생성
    flag_sym = claripy.BVS('flag', flag_length * 8)
    
    state = proj.factory.full_init_state()
    
    if stdin_mode:
        state = proj.factory.full_init_state(
            stdin=angr.SimFile(content=flag_sym, seekable=True)
        )
    
    # 출력 가능한 ASCII 제약
    for i in range(flag_length):
        byte = flag_sym.get_byte(i)
        state.solver.add(claripy.And(byte >= 0x20, byte <= 0x7E))
    
    # 플래그 형식 제약 (있을 경우)
    if flag_prefix:
        for i, c in enumerate(flag_prefix):
            state.solver.add(flag_sym.get_byte(i) == ord(c))
    
    # 탐색 실행
    sm = proj.factory.simulation_manager(state, veritesting=True)
    
    if callable(find_condition):
        sm.explore(find=find_condition, avoid=avoid_condition)
    else:
        sm.explore(
            find=find_condition,
            avoid=avoid_condition if avoid_condition else [],
        )
    
    if sm.found:
        found = sm.found[0]
        flag_bytes = found.solver.eval(flag_sym, cast_to=bytes)
        return flag_bytes
    
    return None


def binary_analysis(binary: str) -> dict:
    """바이너리 기본 분석"""
    proj = angr.Project(binary, auto_load_libs=False)
    cfg = proj.analyses.CFGFast()
    
    # 흥미로운 함수 탐색
    interesting = []
    for func in cfg.kb.functions.values():
        name = func.name
        if any(kw in name.lower() for kw in ['win', 'flag', 'correct', 'success', 'backdoor']):
            interesting.append((func.addr, name))
    
    return {
        'entry': proj.entry,
        'interesting_functions': interesting,
        'function_count': len(cfg.kb.functions),
    }


def solve_password_check(binary: str, flag_length: int = 20) -> bytes | None:
    """비밀번호 검사 함수 자동 우회"""
    proj = angr.Project(binary, auto_load_libs=False)
    
    flag_chars = [claripy.BVS(f'c{i}', 8) for i in range(flag_length)]
    flag = claripy.Concat(*flag_chars)
    
    state = proj.factory.entry_state(
        args=[binary],
        add_options={angr.options.LAZY_SOLVES},
    )
    
    # stdin에 플래그 주입
    state.posix.stdin.content = flag
    
    # 제약 추가
    for c in flag_chars:
        state.solver.add(c >= 0x20, c <= 0x7E)
    
    sm = proj.factory.simulation_manager(state)
    sm.explore(
        find=lambda s: b'Correct' in s.posix.dumps(1) or b'Success' in s.posix.dumps(1),
        avoid=lambda s: b'Wrong' in s.posix.dumps(1) or b'Fail' in s.posix.dumps(1),
        num_find=1,
    )
    
    if sm.found:
        s = sm.found[0]
        return s.solver.eval(flag, cast_to=bytes)
    
    return None


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="angr CTF 자동화")
    parser.add_argument("binary")
    parser.add_argument("--length", type=int, default=32)
    parser.add_argument("--prefix", default="")
    parser.add_argument("--find-addr", type=lambda x: int(x, 16), help="탐색 주소 (hex)")
    parser.add_argument("--avoid-addr", type=lambda x: int(x, 16), help="회피 주소 (hex)")
    parser.add_argument("--analyze", action="store_true", help="바이너리 분석만")
    
    args = parser.parse_args()
    
    if args.analyze:
        info = binary_analysis(args.binary)
        print(f"진입점: 0x{info['entry']:x}")
        print(f"함수 수: {info['function_count']}")
        if info['interesting_functions']:
            print("흥미로운 함수:")
            for addr, name in info['interesting_functions']:
                print(f"  0x{addr:x}: {name}")
        return
    
    print(f"[*] angr 분석 시작: {args.binary}")
    result = find_flag(
        args.binary,
        find_condition=args.find_addr,
        avoid_condition=args.avoid_addr,
        flag_length=args.length,
        flag_prefix=args.prefix,
    )
    
    if result:
        print(f"[+] 플래그: {result.decode('latin-1', errors='replace')}")
    else:
        print("[-] 플래그를 찾지 못함")


if __name__ == "__main__":
    main()
```

---

## 3. Frida 동적 계측

### 3.1 Android CTF Frida 스크립트

```javascript
// Frida 스크립트: Android CTF 자동화
// 사용: frida -U -l script.js com.ctf.challenge

Java.perform(function() {
    // 비교 함수 후킹 (strcmp 계열)
    var libc = Module.findBaseAddress("libc.so");
    var strcmp_ptr = Module.findExportByName("libc.so", "strcmp");
    
    if (strcmp_ptr) {
        Interceptor.attach(strcmp_ptr, {
            onEnter: function(args) {
                var s1 = args[0].readUtf8String(32);
                var s2 = args[1].readUtf8String(32);
                if (s1 && s1.includes("CTF") || s2 && s2.includes("CTF")) {
                    console.log("[strcmp] " + s1 + " vs " + s2);
                }
            }
        });
    }
    
    // 특정 클래스 메서드 후킹
    var TargetClass = Java.use("com.ctf.challenge.MainActivity");
    
    TargetClass.checkFlag.implementation = function(input) {
        console.log("[*] checkFlag 호출됨: " + input);
        var result = this.checkFlag(input);
        console.log("[*] 결과: " + result);
        // 강제로 true 반환
        return true;
    };
    
    // 암호화 함수 후킹
    var Cipher = Java.use("javax.crypto.Cipher");
    Cipher.doFinal.overload("[B").implementation = function(input) {
        console.log("[Cipher.doFinal] 입력: " + 
            Java.use("android.util.Base64")
                .encodeToString(input, 0));
        var result = this.doFinal(input);
        console.log("[Cipher.doFinal] 출력: " + 
            Java.use("android.util.Base64")
                .encodeToString(result, 0));
        return result;
    };
});
```

```bash
# Frida 사용법
# Android 장치에서
frida-server &  # frida-server 실행 (루팅 필요)

# PC에서
frida -U -l script.js com.ctf.challenge
frida-trace -U -i "strcmp" com.ctf.challenge  # 함수 추적
```

---

## 4. 포렌식 자동화 파이프라인

```python
#!/usr/bin/env python3
"""CTF 포렌식 자동화 파이프라인"""

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path


# 플래그 형식 패턴 (대회별로 수정)
FLAG_PATTERNS = [
    re.compile(rb'CTF\{[^}]+\}'),
    re.compile(rb'flag\{[^}]+\}', re.IGNORECASE),
    re.compile(rb'[A-Z0-9]{4,6}\{[a-zA-Z0-9_]+\}'),
    re.compile(rb'[A-Fa-f0-9]{32,64}'),  # 해시 형태
]


def run_tool(cmd: list[str], timeout: int = 30) -> str:
    """외부 도구 실행 후 출력 반환"""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return f"[타임아웃: {timeout}초]"
    except FileNotFoundError:
        return f"[도구 없음: {cmd[0]}]"


def search_flags(data: bytes) -> list[str]:
    """바이너리 데이터에서 플래그 패턴 탐색"""
    found = set()
    for pat in FLAG_PATTERNS:
        for m in pat.finditer(data):
            found.add(m.group().decode('latin-1', errors='replace'))
    return list(found)


def analyze_file(filepath: str) -> dict:
    """파일 종합 분석"""
    path = Path(filepath)
    if not path.exists():
        return {"error": f"파일 없음: {filepath}"}
    
    data = path.read_bytes()
    results = {
        "filename": path.name,
        "size": len(data),
        "file_type": "",
        "magic": data[:16].hex(),
        "flags_found": [],
        "tools_output": {},
    }
    
    # file 명령
    results["file_type"] = run_tool(["file", filepath]).strip()
    
    # strings (긴 문자열 추출)
    strings_out = run_tool(["strings", "-n", "8", filepath])
    flags = search_flags(strings_out.encode())
    if flags:
        results["flags_found"].extend(flags)
    
    # 파일 유형별 분석
    file_type = results["file_type"].lower()
    
    if "image" in file_type or "png" in file_type or "jpeg" in file_type:
        # 이미지: exiftool + steghide
        results["tools_output"]["exiftool"] = run_tool(["exiftool", filepath])[:500]
        results["tools_output"]["steghide"] = run_tool(
            ["steghide", "extract", "-sf", filepath, "-p", ""], timeout=5
        )
        # zsteg (PNG)
        if "png" in file_type:
            zsteg_out = run_tool(["zsteg", filepath])
            flags = search_flags(zsteg_out.encode())
            results["flags_found"].extend(flags)
            results["tools_output"]["zsteg"] = zsteg_out[:500]
    
    elif "audio" in file_type or "wav" in file_type or "mp3" in file_type:
        # 오디오: DeepSound, 스펙트로그램 힌트
        results["tools_output"]["hint"] = (
            "스펙트로그램 분석: Audacity → View → Spectogram\n"
            "또는: Python + matplotlib + scipy.io.wavfile"
        )
    
    elif "zip" in file_type or "compressed" in file_type:
        # 압축: binwalk 재귀 추출
        results["tools_output"]["binwalk"] = run_tool(
            ["binwalk", "-e", "--depth=3", filepath]
        )[:500]
    
    elif "pcap" in file_type or "network" in file_type:
        results["tools_output"]["tshark"] = run_tool(
            ["tshark", "-r", filepath, "-Y", "http.request", "-T", "fields",
             "-e", "http.host", "-e", "http.request.uri"]
        )[:500]
    
    # 바이너리에서 직접 플래그 검색
    flags = search_flags(data)
    results["flags_found"].extend(flags)
    results["flags_found"] = list(set(results["flags_found"]))
    
    return results


def print_analysis(results: dict) -> None:
    print(f"\n{'='*55}")
    print(f"파일: {results.get('filename', 'N/A')} ({results.get('size', 0):,} bytes)")
    print(f"유형: {results.get('file_type', 'N/A')[:80]}")
    print(f"Magic: {results.get('magic', 'N/A')}")
    
    flags = results.get("flags_found", [])
    if flags:
        print(f"\n[플래그 후보 {len(flags)}개]")
        for f in flags:
            print(f"  ★ {f}")
    
    for tool, output in results.get("tools_output", {}).items():
        if output and not output.startswith("["):
            print(f"\n[{tool}]")
            print(output[:300])


def main() -> None:
    parser = argparse.ArgumentParser(description="CTF 포렌식 자동화 파이프라인")
    parser.add_argument("files", nargs="+", help="분석할 파일들")
    parser.add_argument("--recursive", action="store_true", help="디렉토리 재귀 분석")
    
    args = parser.parse_args()
    
    for filepath in args.files:
        path = Path(filepath)
        if path.is_dir() and args.recursive:
            for f in path.rglob("*"):
                if f.is_file():
                    results = analyze_file(str(f))
                    print_analysis(results)
        else:
            results = analyze_file(filepath)
            print_analysis(results)


if __name__ == "__main__":
    main()
```

---

## 5. CTFd API 자동화

```python
#!/usr/bin/env python3
"""CTFd 플랫폼 API 자동화 클라이언트"""

import argparse
import json
import sys
from dataclasses import dataclass
from typing import Optional
import requests


@dataclass
class CTFdClient:
    base_url: str
    token: str
    session: requests.Session = None

    def __post_init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Token {self.token}",
            "Content-Type": "application/json",
        })

    def get(self, endpoint: str) -> dict:
        r = self.session.get(f"{self.base_url}/api/v1/{endpoint}")
        r.raise_for_status()
        return r.json()

    def post(self, endpoint: str, data: dict) -> dict:
        r = self.session.post(f"{self.base_url}/api/v1/{endpoint}", json=data)
        r.raise_for_status()
        return r.json()

    def list_challenges(self) -> list[dict]:
        data = self.get("challenges")
        return data.get("data", [])

    def get_challenge(self, challenge_id: int) -> dict:
        data = self.get(f"challenges/{challenge_id}")
        return data.get("data", {})

    def submit_flag(self, challenge_id: int, flag: str) -> bool:
        result = self.post("challenges/attempt", {
            "challenge_id": challenge_id,
            "submission": flag,
        })
        status = result.get("data", {}).get("status", "")
        return status == "correct"

    def get_scoreboard(self, count: int = 10) -> list[dict]:
        data = self.get(f"scoreboard?count={count}")
        return data.get("data", [])

    def show_progress(self) -> None:
        """미풀이 챌린지 현황 출력"""
        challenges = self.list_challenges()
        solved = sum(1 for c in challenges if c.get('solved_by_me'))
        total = len(challenges)

        print(f"\n[CTFd 현황] {self.base_url}")
        print(f"풀이: {solved}/{total} ({solved/total*100:.0f}%)")
        print(f"\n[미풀이 챌린지]")

        unsolved = [c for c in challenges if not c.get('solved_by_me')]
        by_cat: dict[str, list] = {}
        for c in unsolved:
            by_cat.setdefault(c.get('category', 'misc'), []).append(c)

        for cat, chals in sorted(by_cat.items()):
            print(f"\n  [{cat}]")
            for c in sorted(chals, key=lambda x: x.get('value', 0)):
                print(f"    □ {c['name']} ({c.get('value', 0)}pt) — {c.get('solves', 0)} solves")


def main() -> None:
    parser = argparse.ArgumentParser(description="CTFd API 클라이언트")
    parser.add_argument("--url", required=True, help="CTFd URL (https://ctf.example.com)")
    parser.add_argument("--token", required=True, help="API 토큰")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("status", help="미풀이 챌린지 현황")
    sub.add_parser("scoreboard", help="스코어보드")

    submit_p = sub.add_parser("submit", help="플래그 제출")
    submit_p.add_argument("challenge_id", type=int)
    submit_p.add_argument("flag")

    args = parser.parse_args()
    client = CTFdClient(args.url, args.token)

    if args.command == "status":
        client.show_progress()

    elif args.command == "scoreboard":
        board = client.get_scoreboard()
        print("\n[스코어보드]")
        for i, team in enumerate(board, 1):
            print(f"  {i:2d}. {team.get('name', '?'):<30} {team.get('score', 0)}pt")

    elif args.command == "submit":
        if client.submit_flag(args.challenge_id, args.flag):
            print(f"[+] 정답! 플래그 제출 성공: {args.flag}")
        else:
            print(f"[-] 오답")


if __name__ == "__main__":
    main()
```

---

## 6. 팀 협업 워크플로우

```bash
# CTF 팀 표준 워크플로우

# 1. 환경 준비
git clone [ctf-notes-repo] ctf-2026-hackathon
cd ctf-2026-hackathon

# 2. 챌린지별 디렉토리
mkdir -p web/login_bypass pwn/overflow crypto/rsa forensics/pcap1

# 3. 작업 분담 (README 업데이트)
# web/login_bypass/README.md: 담당자, 진행상황, 힌트

# 4. 쉘 공유 (tmux)
tmux new-session -s ctf -d
tmux send-keys -t ctf "ssh team@ctf-server" Enter

# 5. 플래그 공유 채널
# Discord/Slack 웹훅으로 자동 제출 알림
curl -X POST $DISCORD_WEBHOOK \
    -H "Content-Type: application/json" \
    -d '{"content": "🚩 **login_bypass** 풀이 완료!\nCTF{flag_here}"}'
```
