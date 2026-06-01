> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# CTF 방법론과 도구 체계

CTF(Capture The Flag)는 실제 보안 기술을 경쟁 형식으로 연습하는 최고의 방법이다. Jeopardy 스타일 CTF에서 다양한 보안 분야의 문제를 풀며 실전 기술을 쌓는다.

---

## 1. CTF 대회 유형

| 유형 | 설명 | 특징 |
|------|------|------|
| Jeopardy | 분야별 문제 풀기 | 가장 일반적, 개인·팀 참가 |
| Attack-Defense | 내 서비스 방어 + 상대 서버 공격 | 실시간 공방, 패치 전략 중요 |
| King of the Hill | 서버 점령·유지 | 지속적 익스플로잇 유지 |
| Boot2Root (CTF+HTB) | 처음부터 루트까지 | 실제 침투 테스트 시뮬레이션 |

---

## 2. 분야별 핵심 도구

### 2.1 PWN (바이너리 익스플로잇)

```bash
# 환경 설정
pip install pwntools
sudo apt install gdb gdb-multiarch

# GDB 플러그인 (택일)
# pwndbg: https://github.com/pwndbg/pwndbg
git clone https://github.com/pwndbg/pwndbg && cd pwndbg && ./setup.sh

# GEF (GDB Enhanced Features)
bash -c "$(curl -fsSL https://gef.blah.cat/sh)"

# 보호 기법 확인
checksec --file=./binary
checksec binary  # pwntools CLI

# 핵심 도구
# pwntools    - 익스플로잇 프레임워크
# ROPgadget   - ROP 가젯 탐색
# ropper      - ROP 체인 생성
# one_gadget  - libc one-gadget RCE 탐색
# LibcSearcher / libc-database - libc 버전 식별
```

### 2.2 REV (리버스 엔지니어링)

```bash
# 정적 분석
ghidra          # 강력한 무료 역어셈블러 (NSA)
cutter          # Radare2 GUI 프론트엔드
binary ninja    # 상업용, 스크립팅 친화적
objdump -d binary   # 빠른 역어셈블

# 동적 분석
gdb -q ./binary
strace ./binary       # 시스템콜 추적
ltrace ./binary       # 라이브러리 콜 추적
frida-trace -i "strcmp" ./binary  # 함수 추적

# 심볼릭 실행
angr            # Python 기반 심볼릭 실행
z3              # SMT 솔버 (파이썬 바인딩)
manticore       # 이더리움/바이너리 심볼릭 실행

# 패킹/난독화 해제
upx -d packed_binary
python pyinstxtractor.py packed.exe  # PyInstaller 언패킹
```

### 2.3 WEB

```bash
# HTTP 분석
burpsuite       # 주 HTTP 프록시
caido           # 현대적 Burp 대안 (Rust)
ffuf            # 퍼징 (디렉토리/파라미터)
sqlmap          # SQL 인젝션 자동화
nuclei          # 취약점 스캐너 (템플릿 기반)

# 특화 도구
jwt_tool        # JWT 분석·공격
python-jwt      # JWT 생성·파싱
hashcat         # 해시 크래킹
flask-unsign    # Flask 세션 쿠키 공격

# 개발 도구
python requests + BeautifulSoup  # 자동화 스크립트
```

### 2.4 CRYPTO (암호학)

```bash
pip install pycryptodome gmpy2 sympy

# 온라인 도구
# CyberChef: https://gchq.github.io/CyberChef/
# FactorDB:  http://factordb.com/
# Alpertron: https://www.alpertron.com.ar/ECM.HTM (인수분해)

# RSA 취약 키 탐지
python -c "from Crypto.PublicKey import RSA; k=RSA.import_key(open('key.pem').read()); print(k.n, k.e)"

# 해시 식별
hash-identifier [hash]
hashid [hash]
```

### 2.5 FORENSICS

```bash
# 파일 분석
file suspicious_file     # 파일 유형
xxd file | head          # 헥스덤프
binwalk -e image.bin     # 파일 추출
foremost -i disk.img     # 파일 카빙

# 이미지 스테가노그래피
steghide extract -sf image.jpg
zsteg image.png          # LSB 탐지
stegsolve                # GUI 스테가노그래피 분석

# 메모리 포렌식
volatility3 -f memory.raw windows.pslist.PsList
volatility3 -f memory.raw linux.bash.Bash

# 네트워크
wireshark dump.pcap
tshark -r dump.pcap -Y "http" -T fields -e http.request.uri
```

### 2.6 MISC

```bash
# QR코드/바코드
zbar-tools: zbarimg image.png

# 오디오 스테가노그래피
sonic-visualiser    # 스펙트로그램 분석
deepsound           # 오디오 숨김 탐지
audacity            # 역재생, 스펙트럼 분석

# 인코딩 분석
CyberChef "Magic" 모드  # 자동 인코딩 탐지
```

---

## 3. Docker Pwnbox 환경 구성

```dockerfile
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive TZ=Asia/Seoul

RUN apt-get update && apt-get install -y \
    python3 python3-pip python3-dev \
    gdb gdb-multiarch \
    gcc gcc-multilib g++ \
    nasm binutils \
    git curl wget vim \
    patchelf ltrace strace \
    netcat-openbsd socat \
    libssl-dev libffi-dev \
    file binwalk foremost \
    && rm -rf /var/lib/apt/lists/*

# pwntools, pycryptodome, gmpy2
RUN pip3 install pwntools pycryptodome gmpy2 sympy z3-solver angr

# pwndbg
RUN git clone https://github.com/pwndbg/pwndbg /opt/pwndbg && \
    cd /opt/pwndbg && bash setup.sh

# ROPgadget, one_gadget
RUN pip3 install ROPgadget && gem install one_gadget

# Ghidra
RUN wget -q https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.0_build/ghidra_11.0_PUBLIC_20240110.zip \
    -O /tmp/ghidra.zip && \
    unzip -q /tmp/ghidra.zip -d /opt/ && \
    rm /tmp/ghidra.zip

WORKDIR /ctf
CMD ["/bin/bash"]
```

```bash
# 빌드 및 실행
docker build -t pwnbox .
docker run -it --cap-add=SYS_PTRACE --security-opt seccomp=unconfined pwnbox
```

---

## 4. CTF 노트 자동화 CLI

```python
#!/usr/bin/env python3
"""CTF 진행상황 추적 및 플래그 기록 CLI"""

import argparse
import json
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path


CTF_DB_PATH = Path.home() / ".ctf_notes.json"

CATEGORIES = ["pwn", "rev", "web", "crypto", "forensics", "misc", "osint"]


@dataclass
class Challenge:
    name: str
    category: str
    points: int
    status: str      # "unsolved", "in_progress", "solved"
    flag: str = ""
    notes: str = ""
    solved_at: str = ""
    tags: list[str] = field(default_factory=list)


@dataclass
class CTFEvent:
    name: str
    url: str = ""
    start_time: str = ""
    end_time: str = ""
    team: str = ""
    challenges: list[Challenge] = field(default_factory=list)


def load_db() -> dict:
    if CTF_DB_PATH.exists():
        return json.loads(CTF_DB_PATH.read_text())
    return {"events": {}}


def save_db(db: dict) -> None:
    CTF_DB_PATH.write_text(json.dumps(db, ensure_ascii=False, indent=2))


def add_event(name: str, url: str = "", team: str = "") -> None:
    db = load_db()
    if name in db["events"]:
        print(f"[!] 이벤트 '{name}'이 이미 존재합니다.")
        return
    db["events"][name] = {
        "url": url, "team": team,
        "created_at": datetime.now().isoformat(),
        "challenges": {}
    }
    save_db(db)
    print(f"[+] CTF 이벤트 추가: {name}")


def add_challenge(event: str, name: str, category: str, points: int = 0) -> None:
    db = load_db()
    if event not in db["events"]:
        print(f"[!] 이벤트 '{event}'를 먼저 추가하세요.")
        return
    db["events"][event]["challenges"][name] = {
        "category": category, "points": points,
        "status": "unsolved", "flag": "", "notes": "", "tags": [],
        "created_at": datetime.now().isoformat(),
    }
    save_db(db)
    print(f"[+] 챌린지 추가: [{category}] {name} ({points}pt)")


def solve_challenge(event: str, name: str, flag: str, notes: str = "") -> None:
    db = load_db()
    challenges = db["events"].get(event, {}).get("challenges", {})
    if name not in challenges:
        print(f"[!] 챌린지 '{name}'를 찾을 수 없습니다.")
        return
    challenges[name].update({
        "status": "solved", "flag": flag, "notes": notes,
        "solved_at": datetime.now().isoformat(),
    })
    save_db(db)
    print(f"[+] 풀이 완료: {name}")
    print(f"    플래그: {flag}")


def show_status(event: str) -> None:
    db = load_db()
    ev = db["events"].get(event)
    if not ev:
        print(f"[!] 이벤트 없음: {event}")
        return

    challenges = ev["challenges"]
    total = len(challenges)
    solved = sum(1 for c in challenges.values() if c["status"] == "solved")
    total_pts = sum(c["points"] for c in challenges.values() if c["status"] == "solved")

    print(f"\n{'='*55}")
    print(f"CTF: {event} | 팀: {ev.get('team', 'N/A')}")
    print(f"진행: {solved}/{total} 풀이 | 점수: {total_pts}pt")
    print(f"{'='*55}")

    by_cat: dict[str, list] = {}
    for name, c in challenges.items():
        by_cat.setdefault(c["category"], []).append((name, c))

    for cat in CATEGORIES:
        if cat not in by_cat:
            continue
        chs = by_cat[cat]
        print(f"\n  [{cat.upper()}]")
        for name, c in chs:
            icon = "✓" if c["status"] == "solved" else "○" if c["status"] == "in_progress" else "□"
            pts = f"{c['points']}pt" if c["points"] else ""
            flag_preview = f" → {c['flag'][:30]}" if c.get("flag") else ""
            print(f"    {icon} {name} {pts}{flag_preview}")


def main() -> None:
    parser = argparse.ArgumentParser(description="CTF 노트 관리 CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    ev_p = sub.add_parser("event", help="이벤트 추가")
    ev_p.add_argument("name"), ev_p.add_argument("--url", default=""), ev_p.add_argument("--team", default="")

    add_p = sub.add_parser("add", help="챌린지 추가")
    add_p.add_argument("event"), add_p.add_argument("name")
    add_p.add_argument("--cat", choices=CATEGORIES, default="misc")
    add_p.add_argument("--pts", type=int, default=0)

    solve_p = sub.add_parser("solve", help="챌린지 풀이 기록")
    solve_p.add_argument("event"), solve_p.add_argument("name")
    solve_p.add_argument("flag"), solve_p.add_argument("--notes", default="")

    status_p = sub.add_parser("status", help="진행 상황")
    status_p.add_argument("event")

    args = parser.parse_args()

    if args.command == "event":
        add_event(args.name, args.url, args.team)
    elif args.command == "add":
        add_challenge(args.event, args.name, args.cat, args.pts)
    elif args.command == "solve":
        solve_challenge(args.event, args.name, args.flag, args.notes)
    elif args.command == "status":
        show_status(args.event)


if __name__ == "__main__":
    main()
```

---

## 5. 주요 CTF 플랫폼

| 플랫폼 | URL | 특징 |
|--------|-----|------|
| DreamHack | dreamhack.io | 한국어, 강의+CTF 통합 |
| pwnable.kr | pwnable.kr | 한국, PWN 특화 |
| picoCTF | picoctf.org | 초보자 친화, 상시 |
| Hack The Box | hackthebox.com | 실제 머신, 연중 |
| CTFtime | ctftime.org | 대회 일정·순위 종합 |
| OverTheWire | overthewire.org | Linux 워게임 |
| CryptoHack | cryptohack.org | 암호학 특화 |
| pwn.college | pwn.college | PWN 단계별 학습 |

---

<a name="english"></a>

# CTF Methodology and Tool System

CTF (Capture The Flag) is the best way to practice real security skills in a competitive format. By solving problems across various security domains in Jeopardy-style CTFs, you build hands-on skills.

---

## 1. CTF Competition Types

| Type | Description | Characteristics |
|------|-------------|-----------------|
| Jeopardy | Solve problems by category | Most common, individual/team participation |
| Attack-Defense | Defend your own service + attack opponent's server | Real-time offense/defense, patching strategy critical |
| King of the Hill | Capture and hold a server | Maintain persistent exploits |
| Boot2Root (CTF+HTB) | From initial access to root | Real penetration test simulation |

---

## 2. Core Tools by Category

### 2.1 PWN (Binary Exploitation)

```bash
# Setup
pip install pwntools
sudo apt install gdb gdb-multiarch

# GDB plugins (choose one)
# pwndbg: https://github.com/pwndbg/pwndbg
git clone https://github.com/pwndbg/pwndbg && cd pwndbg && ./setup.sh

# GEF (GDB Enhanced Features)
bash -c "$(curl -fsSL https://gef.blah.cat/sh)"

# Check binary protections
checksec --file=./binary
checksec binary  # pwntools CLI

# Core tools
# pwntools    - exploit framework
# ROPgadget   - ROP gadget finder
# ropper      - ROP chain builder
# one_gadget  - libc one-gadget RCE finder
# LibcSearcher / libc-database - libc version identification
```

### 2.2 REV (Reverse Engineering)

```bash
# Static analysis
ghidra          # Powerful free disassembler (NSA)
cutter          # Radare2 GUI frontend
binary ninja    # Commercial, scripting-friendly
objdump -d binary   # Quick disassembly

# Dynamic analysis
gdb -q ./binary
strace ./binary       # System call tracing
ltrace ./binary       # Library call tracing
frida-trace -i "strcmp" ./binary  # Function tracing

# Symbolic execution
angr            # Python-based symbolic execution
z3              # SMT solver (Python bindings)
manticore       # Ethereum/binary symbolic execution

# Unpacking/deobfuscation
upx -d packed_binary
python pyinstxtractor.py packed.exe  # PyInstaller unpacking
```

### 2.3 WEB

```bash
# HTTP analysis
burpsuite       # Primary HTTP proxy
caido           # Modern Burp alternative (Rust)
ffuf            # Fuzzing (directories/parameters)
sqlmap          # SQL injection automation
nuclei          # Vulnerability scanner (template-based)

# Specialized tools
jwt_tool        # JWT analysis and attacks
python-jwt      # JWT creation and parsing
hashcat         # Hash cracking
flask-unsign    # Flask session cookie attacks

# Development tools
python requests + BeautifulSoup  # Automation scripts
```

### 2.4 CRYPTO (Cryptography)

```bash
pip install pycryptodome gmpy2 sympy

# Online tools
# CyberChef: https://gchq.github.io/CyberChef/
# FactorDB:  http://factordb.com/
# Alpertron: https://www.alpertron.com.ar/ECM.HTM (factorization)

# RSA weak key detection
python -c "from Crypto.PublicKey import RSA; k=RSA.import_key(open('key.pem').read()); print(k.n, k.e)"

# Hash identification
hash-identifier [hash]
hashid [hash]
```

### 2.5 FORENSICS

```bash
# File analysis
file suspicious_file     # File type
xxd file | head          # Hex dump
binwalk -e image.bin     # File extraction
foremost -i disk.img     # File carving

# Image steganography
steghide extract -sf image.jpg
zsteg image.png          # LSB detection
stegsolve                # GUI steganography analysis

# Memory forensics
volatility3 -f memory.raw windows.pslist.PsList
volatility3 -f memory.raw linux.bash.Bash

# Network
wireshark dump.pcap
tshark -r dump.pcap -Y "http" -T fields -e http.request.uri
```

### 2.6 MISC

```bash
# QR code/barcode
zbar-tools: zbarimg image.png

# Audio steganography
sonic-visualiser    # Spectrogram analysis
deepsound           # Audio hiding detection
audacity            # Reverse playback, spectrum analysis

# Encoding analysis
CyberChef "Magic" mode  # Automatic encoding detection
```

---

## 3. Docker Pwnbox Environment Setup

```dockerfile
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive TZ=Asia/Seoul

RUN apt-get update && apt-get install -y \
    python3 python3-pip python3-dev \
    gdb gdb-multiarch \
    gcc gcc-multilib g++ \
    nasm binutils \
    git curl wget vim \
    patchelf ltrace strace \
    netcat-openbsd socat \
    libssl-dev libffi-dev \
    file binwalk foremost \
    && rm -rf /var/lib/apt/lists/*

# pwntools, pycryptodome, gmpy2
RUN pip3 install pwntools pycryptodome gmpy2 sympy z3-solver angr

# pwndbg
RUN git clone https://github.com/pwndbg/pwndbg /opt/pwndbg && \
    cd /opt/pwndbg && bash setup.sh

# ROPgadget, one_gadget
RUN pip3 install ROPgadget && gem install one_gadget

# Ghidra
RUN wget -q https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.0_build/ghidra_11.0_PUBLIC_20240110.zip \
    -O /tmp/ghidra.zip && \
    unzip -q /tmp/ghidra.zip -d /opt/ && \
    rm /tmp/ghidra.zip

WORKDIR /ctf
CMD ["/bin/bash"]
```

```bash
# Build and run
docker build -t pwnbox .
docker run -it --cap-add=SYS_PTRACE --security-opt seccomp=unconfined pwnbox
```

---

## 4. CTF Note Automation CLI

The Python CLI above tracks CTF progress, records flags, and shows status by category. Key commands:
- `event` — add a new CTF event
- `add` — add a challenge to an event
- `solve` — record a solved challenge with its flag
- `status` — display current solve progress for an event

---

## 5. Major CTF Platforms

| Platform | URL | Features |
|----------|-----|----------|
| DreamHack | dreamhack.io | Korean, integrated courses + CTF |
| pwnable.kr | pwnable.kr | Korean, PWN-focused |
| picoCTF | picoctf.org | Beginner-friendly, always-on |
| Hack The Box | hackthebox.com | Real machines, year-round |
| CTFtime | ctftime.org | Competition schedule and rankings |
| OverTheWire | overthewire.org | Linux wargames |
| CryptoHack | cryptohack.org | Cryptography-focused |
| pwn.college | pwn.college | Structured PWN learning |
