#!/usr/bin/env python3
"""
vhack — VibeHacking CLI
사이버보안 학습 자료 탐색 + Docker 실습 환경 관리 도구

사용법:
  python3 vhack.py list                  # 전체 섹션 목록
  python3 vhack.py study 05             # 웹 해킹 섹션 파일 목록
  python3 vhack.py study 05 1           # 01_owasp_top10.md 열기
  python3 vhack.py lab ls               # 실습 환경 목록
  python3 vhack.py lab start 01         # 웹 해킹 랩 시작
  python3 vhack.py lab status           # 실행 중인 컨테이너 확인
  python3 vhack.py search "SQL 인젝션"   # 전체 MD 검색
  python3 vhack.py alias install        # 쉘 alias 자동 등록 → vhack 으로 바로 사용
  python3 vhack.py update               # 최신 버전으로 업데이트
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import textwrap
from pathlib import Path

# ── 색상 코드 (터미널 지원 여부 자동 감지) ──────────────────────────────────
_HAS_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None

def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _HAS_COLOR else text

def bold(t: str) -> str:    return _c("1", t)
def cyan(t: str) -> str:    return _c("36", t)
def green(t: str) -> str:   return _c("32", t)
def yellow(t: str) -> str:  return _c("33", t)
def red(t: str) -> str:     return _c("31", t)
def dim(t: str) -> str:     return _c("2", t)
def blue(t: str) -> str:    return _c("34", t)

# ── 경로 설정 ────────────────────────────────────────────────────────────────
REPO_ROOT = Path(__file__).parent.resolve()
LABS_DIR  = REPO_ROOT / "labs"

# ── 섹션 메타데이터 ──────────────────────────────────────────────────────────
SECTIONS: dict[int, dict] = {
    1:  {"name": "Linux_Basics",               "ko": "리눅스 기초",              "emoji": "🐧"},
    2:  {"name": "Network_Hacking",             "ko": "네트워크 해킹",            "emoji": "🌐"},
    3:  {"name": "System_Hacking",              "ko": "시스템 해킹",              "emoji": "💻"},
    4:  {"name": "Reverse_Engineering",         "ko": "리버스 엔지니어링",        "emoji": "🔬"},
    5:  {"name": "Web_Hacking",                 "ko": "웹 해킹",                 "emoji": "🕷️"},
    6:  {"name": "Malware_Analysis",            "ko": "악성코드 분석",            "emoji": "🦠"},
    7:  {"name": "Digital_Forensics",           "ko": "디지털 포렌식",            "emoji": "🔍"},
    8:  {"name": "Python_Hacking",              "ko": "파이썬 해킹",              "emoji": "🐍"},
    9:  {"name": "Exploit_Techniques",          "ko": "익스플로잇 기법",          "emoji": "💥"},
    10: {"name": "Pentest_Methodology",         "ko": "침투 테스트 방법론",       "emoji": "🗺️"},
    11: {"name": "AI_Powered_Security",         "ko": "AI 보안",                 "emoji": "🤖"},
    12: {"name": "Bug_Bounty",                  "ko": "버그 바운티",              "emoji": "💰"},
    13: {"name": "SOC_Blue_Team",               "ko": "SOC/블루팀",              "emoji": "🛡️"},
    14: {"name": "Cloud_Security",              "ko": "클라우드 보안",            "emoji": "☁️"},
    15: {"name": "WiFi_Hacking",                "ko": "WiFi 해킹",               "emoji": "📡"},
    16: {"name": "Cryptography",                "ko": "암호학",                  "emoji": "🔐"},
    17: {"name": "Red_Team_Operations",         "ko": "레드팀 작전",              "emoji": "🎯"},
    18: {"name": "DevSecOps",                   "ko": "데브섹옵스",              "emoji": "⚙️"},
    19: {"name": "Assembly_Language",           "ko": "어셈블리 언어",            "emoji": "⚙️"},
    20: {"name": "Shell_Scripting",             "ko": "셸 스크립팅",              "emoji": "📜"},
    21: {"name": "Windows_Exploitation",        "ko": "윈도우 익스플로잇",        "emoji": "🪟"},
    22: {"name": "Password_Cracking",           "ko": "비밀번호 크래킹",          "emoji": "🔑"},
    23: {"name": "Database_Hacking",            "ko": "데이터베이스 해킹",        "emoji": "🗄️"},
    24: {"name": "Network_Infrastructure_Security","ko":"네트워크 인프라 보안",  "emoji": "🏗️"},
    25: {"name": "Threat_Intelligence",         "ko": "위협 인텔리전스",          "emoji": "🕵️"},
    26: {"name": "Linux_Hardening",             "ko": "리눅스 하드닝",            "emoji": "🔒"},
    27: {"name": "IoT_Hacking",                 "ko": "IoT 해킹",                "emoji": "📟"},
    28: {"name": "Mobile_Hacking",              "ko": "모바일 해킹",              "emoji": "📱"},
    29: {"name": "Container_Kubernetes_Security","ko":"컨테이너/쿠버네티스",     "emoji": "🐳"},
    30: {"name": "Vulnerability_Research",      "ko": "취약점 연구",              "emoji": "🔭"},
    31: {"name": "AI_ML_Security",              "ko": "AI/ML 보안",              "emoji": "🧠"},
    32: {"name": "Network_Device_Hacking",      "ko": "네트워크 장비 해킹",      "emoji": "📦"},
    33: {"name": "OSINT_Social_Engineering",    "ko": "OSINT/사회공학",          "emoji": "👁️"},
    34: {"name": "Hardware_Hacking",            "ko": "하드웨어 해킹",            "emoji": "🔧"},
    35: {"name": "Supply_Chain_Attacks",        "ko": "공급망 공격",              "emoji": "⛓️"},
    36: {"name": "Automotive_Hacking",          "ko": "자동차 해킹",              "emoji": "🚗"},
    37: {"name": "ICS_SCADA",                   "ko": "ICS/SCADA 보안",          "emoji": "🏭"},
    38: {"name": "Cloud_Native_Security",       "ko": "클라우드 네이티브 보안",  "emoji": "🌩️"},
    39: {"name": "Zero_Trust_Architecture",     "ko": "제로 트러스트",            "emoji": "🚫"},
    40: {"name": "Threat_Hunting",              "ko": "위협 헌팅",               "emoji": "🎣"},
    41: {"name": "Korean_Certifications",       "ko": "한국 정보보안 자격증",    "emoji": "📜"},
    42: {"name": "Blockchain_Web3_Security",    "ko": "블록체인/Web3 보안",      "emoji": "⛓️"},
    43: {"name": "Physical_Security_Pentesting","ko": "물리 보안 침투 테스트",   "emoji": "🚪"},
    44: {"name": "Incident_Response_DFIR",      "ko": "사고 대응/DFIR",          "emoji": "🚨"},
    45: {"name": "Malware_Development",         "ko": "악성코드 개발(방어학습)", "emoji": "⚗️"},
    46: {"name": "CTF_Techniques",              "ko": "CTF 기법",                "emoji": "🚩"},
    47: {"name": "Mobile_Forensics",            "ko": "모바일 포렌식",            "emoji": "📲"},
    48: {"name": "Threat_Modeling",             "ko": "위협 모델링",              "emoji": "🗂️"},
    49: {"name": "Red_Team_Infrastructure",     "ko": "레드팀 인프라",            "emoji": "🏰"},
    50: {"name": "Game_Hacking",                "ko": "게임 해킹",               "emoji": "🎮"},
    51: {"name": "Browser_Extension_Security",  "ko": "브라우저 확장 보안",      "emoji": "🧩"},
    52: {"name": "API_Security",                "ko": "API 보안",                "emoji": "🔌"},
    53: {"name": "Serverless_Security",         "ko": "서버리스 보안",            "emoji": "⚡"},
    54: {"name": "Active_Directory_Attacks",    "ko": "액티브 디렉토리 공격",    "emoji": "🏢"},
    55: {"name": "Evasion_Techniques",          "ko": "탐지 우회 기법",           "emoji": "👻"},
    56: {"name": "AI_Red_Teaming",              "ko": "AI 레드팀",               "emoji": "🤺"},
    57: {"name": "Quantum_Cryptography",        "ko": "양자 암호학",              "emoji": "⚛️"},
    58: {"name": "Cloud_IR",                    "ko": "클라우드 사고 대응",       "emoji": "🌤️"},
    59: {"name": "Supply_Chain_Security",       "ko": "공급망 보안",              "emoji": "🔗"},
    60: {"name": "Browser_Security",            "ko": "브라우저 보안",            "emoji": "🌍"},
    61: {"name": "Firmware_Hacking",            "ko": "펌웨어 해킹",              "emoji": "💾"},
    62: {"name": "Automotive_Security",         "ko": "자동차 보안",              "emoji": "🚙"},
    63: {"name": "OT_ICS_Advanced",             "ko": "OT/ICS 고급",             "emoji": "⚙️"},
    64: {"name": "Threat_Intel_Platform",       "ko": "위협 인텔 플랫폼",        "emoji": "📊"},
}

# ── 실습 환경 메타데이터 ─────────────────────────────────────────────────────
LABS: dict[str, dict] = {
    "01": {
        "name": "웹 해킹 랩",
        "dir":  "01_web_hacking_lab",
        "desc": "DVWA · Juice Shop · WebGoat — SQLi, XSS, IDOR, 인증 우회",
        "url":  "http://localhost:8080",
        "difficulty": "★★☆",
        "related": [5, 12, 23],
    },
    "02": {
        "name": "바이너리 익스플로잇 랩",
        "dir":  "02_pwn_lab",
        "desc": "BOF · ret2libc · ROP · fmtstr · tcache heap",
        "url":  "nc localhost 10001~10005",
        "difficulty": "★★★",
        "related": [9, 19, 3],
    },
    "03": {
        "name": "네트워크 해킹 랩",
        "dir":  "03_network_lab",
        "desc": "SSH · FTP · DNS zone transfer · SMTP relay · 피벗",
        "url":  "docker exec -it net_lab_attacker bash",
        "difficulty": "★★☆",
        "related": [2, 24, 10],
    },
    "04": {
        "name": "클라우드/컨테이너 보안 랩",
        "dir":  "04_cloud_container_lab",
        "desc": "AWS IMDS · SSRF → 자격증명 탈취 · K8s 탈출 · 컨테이너 탈출",
        "url":  "http://localhost:8080 (SSRF target)",
        "difficulty": "★★★",
        "related": [14, 29, 38],
    },
    "05": {
        "name": "전체 시나리오 통합 랩",
        "dir":  "05_full_scenario_lab",
        "desc": "APT 체인 · 외부 웹 → 내부망 이동 → DB 침투 → 데이터 탈취",
        "url":  "http://localhost:8888",
        "difficulty": "★★★★",
        "related": [10, 17, 44],
    },
}

# ── 배너 ─────────────────────────────────────────────────────────────────────
BANNER = r"""
 __   ___  _                 _    _            _    _
 \ \ / / || |               | |  | |          | |  (_)
  \ V /| || |__   __ _  ___| | _| |__   __ _| |  _ _ __   __ _
   > < |__   _ \ / _` |/ __| |/ / '_ \ / _` | | | | '_ \ / _` |
  / . \   | |_) | (_| | (__|   <| | | | (_| | |_| | | | | (_| |
 /_/ \_\  |_.__/ \__,_|\___|_|\_\_| |_|\__,_|_(_)_|_| |_|\__, |
                                                             __/ |
  사이버보안 학습 플랫폼 · 64개 섹션 · 5개 실습 환경       |___/
"""

# ── 유틸 ─────────────────────────────────────────────────────────────────────
def section_dir(num: int) -> Path | None:
    """섹션 번호 → 디렉토리 경로"""
    meta = SECTIONS.get(num)
    if not meta:
        return None
    pattern = f"{num:02d}_{meta['name']}"
    path = REPO_ROOT / pattern
    if path.exists():
        return path
    # 디렉토리 이름이 약간 다를 수 있으므로 glob 검색
    matches = list(REPO_ROOT.glob(f"{num:02d}_*"))
    return matches[0] if matches else None


def _run_compose(lab_dir: Path, *args: str) -> int:
    """docker compose 또는 docker-compose 실행"""
    for cmd in (["docker", "compose"], ["docker-compose"]):
        try:
            result = subprocess.run(
                [*cmd, *args],
                cwd=lab_dir,
                check=False,
            )
            return result.returncode
        except FileNotFoundError:
            continue
    print(red("✗ docker compose / docker-compose 를 찾을 수 없습니다."))
    print(yellow("  → https://docs.docker.com/compose/install/ 참조"))
    return 1


def _check_docker() -> bool:
    try:
        subprocess.run(["docker", "info"], capture_output=True, check=True)
        return True
    except (FileNotFoundError, subprocess.CalledProcessError):
        print(red("✗ Docker가 실행 중이지 않거나 설치되지 않았습니다."))
        print(yellow("  → https://docs.docker.com/get-docker/ 참조"))
        return False


# ── 명령어: list ──────────────────────────────────────────────────────────────
def cmd_list(args: argparse.Namespace) -> None:
    keyword = (args.search or "").lower()
    print(bold(cyan("\n📚 VibeHacking 섹션 목록\n")))
    print(f"  {'#':>3}  {'섹션명':<42} {'한국어 설명'}")
    print("  " + "─" * 70)

    count = 0
    for num, meta in SECTIONS.items():
        if keyword and keyword not in meta["ko"].lower() and keyword not in meta["name"].lower():
            continue
        icon = meta["emoji"]
        name = f"{num:02d}_{meta['name']}"
        ko   = meta["ko"]
        sdir = section_dir(num)
        file_count = len(list(sdir.glob("0[1-9]_*.md"))) if sdir else 0
        fc = dim(f"[{file_count}파일]") if file_count else dim("[?]")
        print(f"  {num:>3}  {icon} {name:<40} {ko} {fc}")
        count += 1

    print(f"\n  {dim(f'총 {count}개 섹션')}\n")
    print(f"  {dim('사용법:')} {cyan('vhack study <번호>')}  {dim('예:')} {cyan('vhack study 5')}\n")


# ── 명령어: study ─────────────────────────────────────────────────────────────
def cmd_study(args: argparse.Namespace) -> None:
    num = args.section
    meta = SECTIONS.get(num)
    if not meta:
        print(red(f"✗ 섹션 번호 {num}은 존재하지 않습니다. (1~{max(SECTIONS)})"))
        sys.exit(1)

    sdir = section_dir(num)
    if not sdir:
        print(red(f"✗ 섹션 디렉토리를 찾을 수 없습니다: {num:02d}_{meta['name']}"))
        sys.exit(1)

    # 파일 목록만 표시
    if args.file is None:
        files = sorted(sdir.glob("0[1-9]_*.md"))
        ctf_files = sorted(sdir.glob("0[6-9]_*.md")) + sorted(sdir.glob("[1-9][0-9]_*.md"))
        print(bold(cyan(f"\n{meta['emoji']} 섹션 {num:02d}: {meta['ko']} ({meta['name']})\n")))
        print(f"  {'#':>3}  파일명")
        print("  " + "─" * 60)
        for i, f in enumerate(files, 1):
            size = f.stat().st_size
            sz = f"{size // 1024}KB" if size >= 1024 else f"{size}B"
            # 초보자 섹션 있는지 확인
            has_beginner = "## 0. 초보자를 위한 개념 이해" in f.read_text(encoding="utf-8", errors="ignore")[:2000]
            badge = green("●") if has_beginner else dim("○")
            print(f"  {i:>3}  {badge} {f.name:<50} {dim(sz)}")
        print(f"\n  {dim('● = 초보자 가이드 포함')}\n")
        print(f"  {dim('사용법:')} {cyan(f'vhack study {num} <파일번호>')}  {dim('예:')} {cyan(f'vhack study {num} 1')}\n")
        return

    # 특정 파일 표시
    files = sorted(sdir.glob("0[1-9]_*.md"))
    if args.file < 1 or args.file > len(files):
        print(red(f"✗ 파일 번호 {args.file}는 범위를 벗어납니다. (1~{len(files)})"))
        sys.exit(1)

    target = files[args.file - 1]
    _display_md(target)


def _display_md(path: Path) -> None:
    """마크다운 파일을 터미널에서 읽기 좋게 표시"""
    text = path.read_text(encoding="utf-8", errors="ignore")

    # 이중 언어 파일: 한국어 섹션만 추출
    if '<a name="english">' in text:
        text = text.split('<a name="english">')[0]
    # 언어 토글 헤더 제거
    text = re.sub(r'^> 🌐.*\n', '', text, flags=re.MULTILINE)

    lines = text.splitlines()
    output: list[str] = []
    in_code = False
    code_lang = ""

    for line in lines:
        # 코드 블록
        if line.startswith("```"):
            if not in_code:
                in_code = True
                code_lang = line[3:].strip()
                output.append(dim(f"  ┌─ {code_lang or 'code'} " + "─" * 30))
            else:
                in_code = False
                output.append(dim("  └" + "─" * 37))
            continue
        if in_code:
            output.append(dim("  │ ") + cyan(line))
            continue

        # 헤딩
        if line.startswith("# "):
            output.append("\n" + bold(cyan("═" * 60)))
            output.append(bold(cyan(f"  {line[2:]}")))
            output.append(bold(cyan("═" * 60)))
        elif line.startswith("## 0. 초보자"):
            output.append("\n" + bold(green(f"  {line}")))
        elif line.startswith("## "):
            output.append("\n" + bold(yellow(f"  {line}")))
        elif line.startswith("### "):
            output.append("\n" + bold(blue(f"    {line}")))
        elif line.startswith("#### "):
            output.append(bold(f"      {line}"))
        # 강조
        elif line.startswith("> "):
            output.append(yellow(f"  ▌ {line[2:]}"))
        # 체크리스트
        elif re.match(r"\s*[-*] \[[ x]\]", line):
            output.append("  " + line)
        # 일반 목록
        elif re.match(r"^\s*[-*] ", line):
            output.append("  " + line)
        elif re.match(r"^\s*\d+\. ", line):
            output.append("  " + line)
        elif line.strip() == "---":
            output.append(dim("  " + "─" * 50))
        else:
            output.append("  " + line)

    # 페이지 단위 표시
    content = "\n".join(output)
    _pager(content)


def _pager(content: str) -> None:
    """터미널 크기에 맞춰 페이지 단위로 출력"""
    try:
        cols = os.get_terminal_size().columns
        rows = os.get_terminal_size().lines - 3
    except OSError:
        cols, rows = 80, 24

    lines = content.splitlines()
    page: list[str] = []

    for i, line in enumerate(lines):
        page.append(line)
        if len(page) >= rows:
            print("\n".join(page))
            page = []
            try:
                key = input(dim("  -- Enter: 다음 페이지 | q: 종료 -- "))
                if key.lower() == "q":
                    return
            except (EOFError, KeyboardInterrupt):
                print()
                return

    if page:
        print("\n".join(page))


# ── 명령어: lab ───────────────────────────────────────────────────────────────
def cmd_lab(args: argparse.Namespace) -> None:
    sub = args.lab_cmd

    if sub == "ls":
        _lab_ls()
    elif sub == "start":
        _lab_start(args.lab_id)
    elif sub == "stop":
        _lab_stop(args.lab_id, getattr(args, "all", False))
    elif sub == "status":
        _lab_status()
    elif sub == "logs":
        _lab_logs(args.lab_id)
    else:
        print(red(f"✗ 알 수 없는 lab 서브명령: {sub}"))
        sys.exit(1)


def _lab_ls() -> None:
    print(bold(cyan("\n🔬 실습 환경 목록\n")))
    print(f"  {'#':>4}  {'이름':<25} {'난이도':>6}  설명")
    print("  " + "─" * 75)
    for lab_id, meta in LABS.items():
        rel = ", ".join(str(r) for r in meta["related"])
        print(
            f"  {lab_id:>4}  {meta['emoji'] if 'emoji' in meta else '🧪'}"
            f" {meta['name']:<23} {meta['difficulty']:>6}  "
            f"{meta['desc']}"
        )
        print(f"  {'':>5}  {dim('URL:')} {cyan(meta['url'])}  {dim('관련 섹션:')} {rel}")
    print(f"\n  {dim('사용법:')} {cyan('vhack lab start 01')}  {cyan('vhack lab stop 01')}  {cyan('vhack lab status')}\n")


def _lab_start(lab_id: str | None) -> None:
    if not lab_id:
        print(red("✗ 랩 번호를 지정하세요.  예: vhack lab start 01"))
        sys.exit(1)
    meta = LABS.get(lab_id)
    if not meta:
        print(red(f"✗ 랩 '{lab_id}'이 존재하지 않습니다. (01~05)"))
        sys.exit(1)

    if not _check_docker():
        sys.exit(1)

    lab_path = LABS_DIR / meta["dir"]
    if not lab_path.exists():
        print(red(f"✗ 랩 디렉토리가 없습니다: {lab_path}"))
        sys.exit(1)

    print(bold(f"\n🚀 {meta['name']} 시작 중..."))
    print(dim(f"   경로: {lab_path}"))
    rc = _run_compose(lab_path, "up", "-d", "--build")
    if rc == 0:
        print(green(f"\n✓ {meta['name']} 시작 완료!"))
        print(f"  접근: {cyan(meta['url'])}")
        print(f"  로그: {cyan(f'vhack lab logs {lab_id}')}")
        print(f"  종료: {cyan(f'vhack lab stop {lab_id}')}\n")
    else:
        print(red(f"\n✗ 시작 실패 (exit code {rc})"))
        print(yellow("  docker compose logs 로 오류를 확인하세요."))
        sys.exit(1)


def _lab_stop(lab_id: str | None, stop_all: bool = False) -> None:
    if not _check_docker():
        sys.exit(1)

    targets = list(LABS.keys()) if stop_all else ([lab_id] if lab_id else [])
    if not targets:
        print(red("✗ 랩 번호를 지정하거나 --all 을 사용하세요."))
        sys.exit(1)

    for lid in targets:
        meta = LABS.get(lid)
        if not meta:
            print(yellow(f"  ⚠ 랩 '{lid}' 미등록, 건너뜀"))
            continue
        lab_path = LABS_DIR / meta["dir"]
        if not lab_path.exists():
            continue
        print(f"  🛑 {meta['name']} 종료 중...")
        _run_compose(lab_path, "down")

    print(green("\n✓ 완료\n"))


def _lab_status() -> None:
    if not _check_docker():
        sys.exit(1)
    print(bold(cyan("\n📊 실행 중인 랩 컨테이너\n")))
    try:
        result = subprocess.run(
            ["docker", "ps", "--format",
             "table {{.Names}}\t{{.Status}}\t{{.Ports}}"],
            capture_output=True, text=True, check=True,
        )
        lines = result.stdout.strip().splitlines()
        if len(lines) <= 1:
            print(dim("  실행 중인 컨테이너 없음\n"))
        else:
            for line in lines:
                print("  " + line)
            print()
    except subprocess.CalledProcessError:
        print(red("  docker ps 실패"))


def _lab_logs(lab_id: str | None) -> None:
    if not lab_id:
        print(red("✗ 랩 번호를 지정하세요.  예: vhack lab logs 01"))
        sys.exit(1)
    meta = LABS.get(lab_id)
    if not meta:
        print(red(f"✗ 랩 '{lab_id}'이 존재하지 않습니다."))
        sys.exit(1)
    if not _check_docker():
        sys.exit(1)
    lab_path = LABS_DIR / meta["dir"]
    _run_compose(lab_path, "logs", "-f", "--tail=50")


# ── 명령어: search ────────────────────────────────────────────────────────────
def cmd_search(args: argparse.Namespace) -> None:
    keyword = args.keyword
    print(bold(cyan(f"\n🔎 '{keyword}' 검색 중...\n")))

    found = 0
    pattern = re.compile(re.escape(keyword), re.IGNORECASE)

    for num, meta in SECTIONS.items():
        sdir = section_dir(num)
        if not sdir:
            continue
        for md in sorted(sdir.glob("0[1-9]_*.md")):
            text = md.read_text(encoding="utf-8", errors="ignore")
            matches = pattern.findall(text)
            if not matches:
                continue
            # 매칭 줄 추출
            lines = text.splitlines()
            hit_lines = [
                (i + 1, line.strip())
                for i, line in enumerate(lines)
                if pattern.search(line)
            ]
            rel = md.relative_to(REPO_ROOT)
            print(bold(f"  📄 {rel}"))
            for lineno, line in hit_lines[:5]:
                highlighted = pattern.sub(lambda m: bold(yellow(m.group())), line)
                print(f"     {dim(str(lineno) + ':')} {highlighted[:100]}")
            if len(hit_lines) > 5:
                print(dim(f"     ... 및 {len(hit_lines) - 5}개 더"))
            print()
            found += 1

    if found == 0:
        print(yellow(f"  '{keyword}'에 대한 결과를 찾지 못했습니다.\n"))
    else:
        print(dim(f"  총 {found}개 파일에서 발견\n"))


# ── 명령어: info ──────────────────────────────────────────────────────────────
def cmd_info(args: argparse.Namespace) -> None:
    num = args.section
    meta = SECTIONS.get(num)
    if not meta:
        print(red(f"✗ 섹션 {num}이 존재하지 않습니다."))
        sys.exit(1)

    sdir = section_dir(num)
    files = sorted(sdir.glob("0[1-9]_*.md")) if sdir else []
    total_bytes = sum(f.stat().st_size for f in files)
    total_lines = sum(
        len(f.read_text(encoding="utf-8", errors="ignore").splitlines())
        for f in files
    )

    print(bold(cyan(f"\n{meta['emoji']} 섹션 {num:02d}: {meta['ko']}\n")))
    print(f"  이름 (영어): {meta['name']}")
    print(f"  파일 수:     {len(files)}개")
    print(f"  총 라인:     {total_lines:,}줄")
    print(f"  총 크기:     {total_bytes // 1024:,} KB")

    if files:
        print(f"\n  {'파일 목록':}")
        for i, f in enumerate(files, 1):
            sz = f.stat().st_size // 1024
            print(f"    {i}. {f.name}  {dim(str(sz)+'KB')}")

    # 연관된 실습 랩 찾기
    related_labs = [lid for lid, lm in LABS.items() if num in lm["related"]]
    if related_labs:
        print(f"\n  연관 실습 환경:")
        for lid in related_labs:
            lm = LABS[lid]
            print(f"    → Lab {lid}: {lm['name']}  {cyan(f'vhack lab start {lid}')}")
    print()


# ── 명령어: alias ────────────────────────────────────────────────────────────
_ALIAS_TAG    = "# vhack-alias"                       # 설치 마커 (삭제 시 기준)
_SCRIPT_PATH  = Path(__file__).resolve()              # vhack.py 절대 경로
_PYTHON       = "python3"


def _alias_line(shell: str) -> str:
    """셸 종류에 맞는 alias 한 줄 반환."""
    if shell == "fish":
        return f'alias vhack "{_PYTHON} {_SCRIPT_PATH}"  {_ALIAS_TAG}'
    if shell == "powershell":
        return f'function vhack {{ {_PYTHON} "{_SCRIPT_PATH}" @args }}  {_ALIAS_TAG}'
    # bash / zsh / sh 공통
    return f'alias vhack="{_PYTHON} {_SCRIPT_PATH}"  {_ALIAS_TAG}'


def _reload_hint(profile: Path, shell: str) -> str:
    """설치 후 reload 안내 문자열."""
    if shell == "fish":
        return f"source {profile}"
    if shell == "powershell":
        return f". $PROFILE"
    return f"source {profile}"


def _detect_profiles() -> list[tuple[Path, str]]:
    """
    현재 환경에서 유효한 (셸 프로파일 경로, 셸 이름) 목록을 반환.

    우선순위:
      1. $SHELL 환경 변수 기반 → 활성 셸의 주요 RC 파일
      2. 홈 디렉토리에 존재하는 다른 RC 파일
      3. fish / PowerShell 보조 탐지
    최소 1개는 항상 반환 (기본: ~/.bashrc).
    """
    home = Path.home()
    active_shell = Path(os.environ.get("SHELL", "")).stem  # "bash", "zsh", "fish", ""

    # (경로, 셸이름, 우선도) — 낮을수록 우선
    candidates: list[tuple[Path, str, int]] = [
        (home / ".bashrc",                           "bash",       1 if active_shell == "bash" else 3),
        (home / ".zshrc",                            "zsh",        1 if active_shell == "zsh"  else 3),
        (home / ".bash_profile",                     "bash",       4),
        (home / ".profile",                          "sh",         5),
        (home / ".config" / "fish" / "config.fish",  "fish",       1 if active_shell == "fish" else 6),
    ]

    # PowerShell 프로파일 (Windows / pwsh on Linux)
    ps_profile = _powershell_profile()
    if ps_profile:
        pri = 1 if active_shell in ("pwsh", "powershell") else 6
        candidates.append((ps_profile, "powershell", pri))

    # 실제로 파일이 존재하는 것만, 우선도 순 정렬
    existing = [(p, s) for p, s, _ in sorted(candidates, key=lambda x: x[2]) if p.exists()]

    # 아무것도 없으면 기본값 ~/.bashrc 반환 (생성 예정)
    return existing or [(home / ".bashrc", "bash")]


def _powershell_profile() -> Path | None:
    """PowerShell 프로파일 경로 탐지. 없으면 None."""
    # pwsh (Linux/macOS) / Windows PowerShell
    for cmd in (["pwsh", "-NoProfile", "-Command", "echo $PROFILE"],
                ["powershell", "-NoProfile", "-Command", "echo $PROFILE"]):
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=3).stdout.strip()
            if out:
                return Path(out)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
    return None


def _is_installed(profile: Path) -> bool:
    """해당 프로파일에 alias가 이미 설치되어 있는지 확인."""
    if not profile.exists():
        return False
    return _ALIAS_TAG in profile.read_text(encoding="utf-8", errors="ignore")


def _do_install(profile: Path, shell: str) -> bool:
    """
    profile 파일에 alias 줄 추가.
    이미 설치된 경우 False, 새로 설치한 경우 True.
    """
    if _is_installed(profile):
        return False

    line = _alias_line(shell)
    # 파일이 없으면 생성 (부모 디렉토리도 함께)
    profile.parent.mkdir(parents=True, exist_ok=True)
    with profile.open("a", encoding="utf-8") as f:
        f.write(f"\n{line}\n")
    return True


def _do_remove(profile: Path) -> bool:
    """
    profile 파일에서 alias 줄 제거.
    제거한 경우 True, 없었으면 False.
    """
    if not profile.exists() or not _is_installed(profile):
        return False

    lines = profile.read_text(encoding="utf-8", errors="ignore").splitlines(keepends=True)
    new_lines = [ln for ln in lines if _ALIAS_TAG not in ln]
    # 연속 공백 줄 2개 이상 → 1개로 압축
    cleaned: list[str] = []
    prev_blank = False
    for ln in new_lines:
        is_blank = ln.strip() == ""
        if is_blank and prev_blank:
            continue
        cleaned.append(ln)
        prev_blank = is_blank

    profile.write_text("".join(cleaned), encoding="utf-8")
    return True


def cmd_alias(args: argparse.Namespace) -> None:
    sub = args.alias_cmd

    if sub == "install":
        _alias_cmd_install(getattr(args, "profile", None))
    elif sub == "remove":
        _alias_cmd_remove()
    elif sub == "status":
        _alias_cmd_status()
    else:
        print(red(f"✗ 알 수 없는 alias 서브명령: {sub}"))
        sys.exit(1)


def _alias_cmd_install(target_profile: str | None) -> None:
    print(bold(cyan("\n🔗 vhack alias 설치\n")))

    if target_profile:
        # 사용자가 직접 파일 지정
        profiles = [(Path(target_profile).expanduser(), _guess_shell(Path(target_profile)))]
    else:
        profiles = _detect_profiles()

    installed_any = False
    reload_hints: list[str] = []

    for profile, shell in profiles:
        tag = f"[{shell}]"
        if _is_installed(profile):
            print(f"  {yellow('⚠')} {tag} 이미 설치됨: {dim(str(profile))}")
            continue

        if _do_install(profile, shell):
            print(f"  {green('✓')} {tag} 설치 완료: {cyan(str(profile))}")
            print(f"      {dim('추가된 줄:')} {dim(_alias_line(shell))}")
            reload_hints.append((profile, shell))
            installed_any = True

    if not installed_any:
        print(yellow("\n  모든 대상 프로파일에 이미 설치되어 있습니다.\n"))
        print(f"  확인: {cyan('vhack alias status')}")
        print(f"  제거: {cyan('vhack alias remove')}\n")
        return

    print(bold(green("\n✓ 설치 완료!")))
    print("\n  지금 바로 적용하려면 아래 명령어를 실행하세요:\n")
    for profile, shell in reload_hints:
        hint = _reload_hint(profile, shell)
        print(f"    {cyan(hint)}")
    print(f"\n  이후 새 터미널에서 {bold(cyan('vhack'))} 으로 바로 사용 가능합니다.\n")


def _alias_cmd_remove() -> None:
    print(bold(cyan("\n🗑️  vhack alias 제거\n")))

    profiles = _detect_profiles()
    # 설치된 모든 파일 탐색 (detect_profiles 외의 파일에도 있을 수 있음)
    extra = [
        Path.home() / ".bashrc",
        Path.home() / ".zshrc",
        Path.home() / ".bash_profile",
        Path.home() / ".profile",
        Path.home() / ".config" / "fish" / "config.fish",
    ]
    all_candidates = {p for p, _ in profiles} | set(extra)

    removed_any = False
    for profile in sorted(all_candidates):
        if _do_remove(profile):
            print(f"  {green('✓')} 제거 완료: {cyan(str(profile))}")
            removed_any = True

    if not removed_any:
        print(yellow("  설치된 alias를 찾지 못했습니다.\n"))
    else:
        print(bold(green("\n✓ 제거 완료!")))
        print(dim("  새 터미널을 열거나 source <프로파일>을 실행하면 적용됩니다.\n"))


def _alias_cmd_status() -> None:
    print(bold(cyan("\n📋 vhack alias 설치 현황\n")))

    candidates = [
        Path.home() / ".bashrc",
        Path.home() / ".zshrc",
        Path.home() / ".bash_profile",
        Path.home() / ".profile",
        Path.home() / ".config" / "fish" / "config.fish",
    ]
    ps_profile = _powershell_profile()
    if ps_profile:
        candidates.append(ps_profile)

    found_any = False
    for profile in candidates:
        if not profile.exists():
            continue
        if _is_installed(profile):
            print(f"  {green('●')} {cyan(str(profile))}  {green('설치됨')}")
            # 실제 alias 줄 표시
            for ln in profile.read_text(encoding="utf-8", errors="ignore").splitlines():
                if _ALIAS_TAG in ln:
                    print(f"      {dim(ln.strip())}")
            found_any = True
        else:
            print(f"  {dim('○')} {dim(str(profile))}  {dim('미설치')}")

    if not found_any:
        print(yellow("  설치된 alias가 없습니다.\n"))
        print(f"  설치: {cyan('python3 vhack.py alias install')}\n")
    else:
        print()
        # 현재 세션에서 vhack 명령 사용 가능한지 확인
        which = subprocess.run(["which", "vhack"], capture_output=True, text=True)
        if which.returncode == 0:
            print(f"  {green('✓')} 현재 세션에서 사용 가능: {cyan(which.stdout.strip())}\n")
        else:
            print(f"  {yellow('⚠')} 현재 세션 미적용 — 터미널을 재시작하거나 아래를 실행하세요:")
            for profile in candidates:
                if profile.exists() and _is_installed(profile):
                    shell = _guess_shell(profile)
                    print(f"    {cyan(_reload_hint(profile, shell))}")
            print()


def _guess_shell(profile: Path) -> str:
    """파일명으로 셸 종류 추측."""
    name = profile.name
    if "zsh" in name:    return "zsh"
    if "fish" in name or "fish" in str(profile): return "fish"
    if "powershell" in name.lower() or name.endswith(".ps1"): return "powershell"
    return "bash"


# ── 명령어: update ────────────────────────────────────────────────────────────
def cmd_update(args: argparse.Namespace) -> None:
    print(bold(cyan("\n🔄 최신 버전으로 업데이트 중...\n")))
    try:
        result = subprocess.run(
            ["git", "pull", "origin", "main"],
            cwd=REPO_ROOT, capture_output=False, check=True,
        )
        print(green("\n✓ 업데이트 완료!\n"))
    except subprocess.CalledProcessError as e:
        print(red(f"\n✗ 업데이트 실패: {e}\n"))
        sys.exit(1)
    except FileNotFoundError:
        print(red("\n✗ git이 설치되어 있지 않습니다.\n"))
        sys.exit(1)


# ── 명령어: quick ─────────────────────────────────────────────────────────────
def cmd_quick(args: argparse.Namespace) -> None:
    """초보자를 위한 빠른 시작 가이드"""
    print(bold(cyan(BANNER)))
    print(bold("🚀 빠른 시작 가이드\n"))

    steps = [
        ("1단계: 학습 섹션 둘러보기",
         f"  {cyan('python3 vhack.py list')}  — 64개 섹션 목록 표시\n"
         f"  {cyan('python3 vhack.py study 5')}  — 웹 해킹 섹션 파일 목록\n"
         f"  {cyan('python3 vhack.py study 5 1')}  — OWASP Top 10 문서 읽기"),
        ("2단계: 실습 환경 시작 (Docker 필요)",
         f"  {cyan('python3 vhack.py lab ls')}  — 실습 환경 목록\n"
         f"  {cyan('python3 vhack.py lab start 01')}  — 웹 해킹 랩 시작\n"
         f"  브라우저에서 {cyan('http://localhost:8080')} 접속"),
        ("3단계: 검색 활용",
         f"  {cyan('python3 vhack.py search \"SQL 인젝션\"')}  — 전체 문서 검색"),
        ("4단계: 업데이트",
         f"  {cyan('python3 vhack.py update')}  — 최신 내용 반영"),
    ]

    for title, desc in steps:
        print(bold(yellow(f"  {title}")))
        print(f"{desc}\n")


# ── 메인 파서 ─────────────────────────────────────────────────────────────────
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vhack",
        description="VibeHacking CLI — 보안 학습 + 실습 환경 관리",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
        예시:
          python3 vhack.py list               섹션 목록
          python3 vhack.py list --search web  "web" 포함 섹션 검색
          python3 vhack.py study 5            웹 해킹 섹션 파일 목록
          python3 vhack.py study 5 1          첫 번째 파일 읽기
          python3 vhack.py lab ls             실습 환경 목록
          python3 vhack.py lab start 01       웹 해킹 랩 시작
          python3 vhack.py lab stop 01        웹 해킹 랩 종료
          python3 vhack.py lab stop --all     모든 랩 종료
          python3 vhack.py lab status         실행 중인 컨테이너
          python3 vhack.py lab logs 01        랩 로그 보기
          python3 vhack.py search "Kerberos"  전체 문서 검색
          python3 vhack.py info 54            섹션 상세 정보
          python3 vhack.py alias install      쉘 alias 자동 등록
          python3 vhack.py alias remove       alias 제거
          python3 vhack.py alias status       설치 현황 확인
          python3 vhack.py update             git pull
        """),
    )
    sub = p.add_subparsers(dest="command", metavar="<명령어>")

    # list
    p_list = sub.add_parser("list", help="전체 섹션 목록 표시")
    p_list.add_argument("--search", metavar="키워드", help="섹션명 필터링")

    # study
    p_study = sub.add_parser("study", help="섹션 학습 (파일 목록 또는 내용 표시)")
    p_study.add_argument("section", type=int, metavar="섹션번호", help="1~64")
    p_study.add_argument("file", nargs="?", type=int, metavar="파일번호",
                         help="1~ (생략 시 파일 목록 표시)")

    # lab
    p_lab = sub.add_parser("lab", help="실습 환경 관리")
    lab_sub = p_lab.add_subparsers(dest="lab_cmd", metavar="<서브명령>")
    lab_sub.add_parser("ls", help="실습 환경 목록")
    p_start = lab_sub.add_parser("start", help="실습 환경 시작")
    p_start.add_argument("lab_id", metavar="랩번호", help="01~05")
    p_stop = lab_sub.add_parser("stop", help="실습 환경 종료")
    p_stop.add_argument("lab_id", nargs="?", metavar="랩번호", help="01~05")
    p_stop.add_argument("--all", action="store_true", help="모든 랩 종료")
    lab_sub.add_parser("status", help="실행 중인 컨테이너 확인")
    p_logs = lab_sub.add_parser("logs", help="랩 로그 보기")
    p_logs.add_argument("lab_id", metavar="랩번호", help="01~05")

    # search
    p_search = sub.add_parser("search", help="전체 문서에서 키워드 검색")
    p_search.add_argument("keyword", metavar="키워드", help="검색어")

    # info
    p_info = sub.add_parser("info", help="섹션 상세 정보")
    p_info.add_argument("section", type=int, metavar="섹션번호", help="1~64")

    # alias
    p_alias = sub.add_parser("alias", help="쉘 alias 자동 등록/제거/확인")
    alias_sub = p_alias.add_subparsers(dest="alias_cmd", metavar="<서브명령>")
    p_ai = alias_sub.add_parser("install", help="alias 설치 (vhack 으로 바로 사용)")
    p_ai.add_argument(
        "--profile", metavar="파일경로",
        help="설치할 프로파일 직접 지정 (기본: 현재 셸 자동 감지)",
    )
    alias_sub.add_parser("remove", help="설치된 alias 제거")
    alias_sub.add_parser("status", help="설치 현황 확인")

    # update
    sub.add_parser("update", help="git pull로 최신 버전 업데이트")

    return p


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command is None:
        print(bold(cyan(BANNER)))
        parser.print_help()
        return

    dispatch = {
        "list":   cmd_list,
        "study":  cmd_study,
        "lab":    cmd_lab,
        "search": cmd_search,
        "info":   cmd_info,
        "alias":  cmd_alias,
        "update": cmd_update,
    }

    handler = dispatch.get(args.command)
    if handler:
        handler(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
