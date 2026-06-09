> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# CTF 스타일 네트워크 해킹 실습

## 실습 환경 준비

### Docker Compose 환경

아래 `docker-compose.yml`을 사용해 실습 환경을 구성한다.

```yaml
# docker-compose.yml
version: "3.9"

services:
  # 실습 1: 패킷 캡처 분석용 HTTP 서버
  flag-web:
    image: python:3.11-slim
    container_name: flag-web
    networks:
      ctf-net:
        ipv4_address: 10.10.10.10
    command: >
      sh -c "mkdir -p /app &&
             echo 'CTF{p4ck3t_4n4lys1s_m4st3r}' > /app/secret.txt &&
             python3 -m http.server 80 --directory /app"
    ports:
      - "8080:80"

  # 실습 2: 버전 탐지용 서비스 서버
  multi-service:
    image: instrumentisto/nmap
    container_name: multi-service
    networks:
      ctf-net:
        ipv4_address: 10.10.10.20
    command: sleep infinity

  # 실습 3: SMB 시뮬레이션 (Samba)
  smb-server:
    image: dperson/samba
    container_name: smb-server
    networks:
      ctf-net:
        ipv4_address: 10.10.10.30
    environment:
      - USERID=1000
      - GROUPID=1000
    command: >
      -u "ctfuser;password123"
      -s "share;/share;yes;no;no;ctfuser"
      -p
    volumes:
      - ./smb-share:/share
    ports:
      - "445:445"
      - "139:139"

  # 공격자 워크스테이션
  attacker:
    image: kalilinux/kali-rolling
    container_name: attacker
    networks:
      ctf-net:
        ipv4_address: 10.10.10.100
    command: sleep infinity
    tty: true

networks:
  ctf-net:
    driver: bridge
    ipam:
      config:
        - subnet: 10.10.10.0/24
```

**환경 시작:**
```bash
# smb-share 디렉토리 생성 및 플래그 파일 배치
mkdir -p smb-share
echo "CTF{smb_3xpl01t_succ3ss}" > smb-share/flag.txt

# 환경 시작
docker compose up -d

# 공격자 컨테이너 접속
docker exec -it attacker bash

# 내부: 필요한 도구 설치
apt-get update -q && apt-get install -y -q \
    nmap wireshark-cli tcpdump smbclient ncat python3
```

---

## 실습 1: Wireshark로 패킷에서 플래그 추출

### 목표

HTTP 트래픽을 캡처하여 숨겨진 플래그를 찾아라.

**힌트:**
- `tcpdump` 또는 `tshark`로 네트워크 트래픽을 캡처한다.
- HTTP GET 요청 응답 본문을 살펴보라.
- 플래그 형식: `CTF{...}`

### 풀이

**Step 1: 트래픽 생성 (별도 터미널)**
```bash
# 공격자 컨테이너에서 HTTP 요청 반복 전송
docker exec attacker sh -c \
  "for i in \$(seq 1 10); do curl -s http://10.10.10.10/secret.txt; sleep 1; done"
```

**Step 2: 패킷 캡처**
```bash
# tshark으로 실시간 캡처 (공격자 컨테이너 내부)
tshark -i eth0 -f "tcp port 80" -w /tmp/capture.pcap

# 또는 호스트에서 직접 캡처
tcpdump -i docker0 -f "tcp port 8080" -w capture.pcap
```

**Step 3: 패킷 분석**
```bash
# HTTP 응답 본문만 추출
tshark -r /tmp/capture.pcap \
  -Y "http.response" \
  -T fields -e http.file_data

# 플래그 패턴 검색
tshark -r /tmp/capture.pcap \
  -Y "data contains \"CTF{\"" \
  -T fields -e data.data | xxd -r -p
```

**Step 4: Python으로 pcap 파싱 (scapy 활용)**
```python
#!/usr/bin/env python3
"""pcap 파일에서 HTTP 페이로드를 추출해 플래그를 찾는다."""

import argparse
import re
import sys

try:
    from scapy.all import rdpcap, TCP, Raw
except ImportError:
    print("[!] scapy 필요: pip install scapy", file=sys.stderr)
    sys.exit(1)


def extract_flags(pcap_path: str, pattern: str = r"CTF\{[^}]+\}") -> list[str]:
    """pcap에서 플래그 패턴과 일치하는 문자열을 반환한다."""
    packets = rdpcap(pcap_path)
    flags: list[str] = []

    for pkt in packets:
        if not (pkt.haslayer(TCP) and pkt.haslayer(Raw)):
            continue
        try:
            payload = pkt[Raw].load.decode("utf-8", errors="replace")
            found = re.findall(pattern, payload)
            flags.extend(found)
        except Exception:
            continue

    return list(set(flags))


def main() -> None:
    parser = argparse.ArgumentParser(description="pcap에서 플래그 추출")
    parser.add_argument("pcap", help="분석할 .pcap 파일 경로")
    parser.add_argument(
        "--pattern",
        default=r"CTF\{[^}]+\}",
        help="플래그 정규식 패턴 (기본: CTF{...})",
    )
    args = parser.parse_args()

    flags = extract_flags(args.pcap, args.pattern)
    if flags:
        print(f"[+] 플래그 발견 ({len(flags)}개):")
        for f in flags:
            print(f"    {f}")
    else:
        print("[-] 플래그를 찾지 못했습니다.")


if __name__ == "__main__":
    main()
```

```bash
# 사용 예시
python3 extract_flags.py capture.pcap
# [+] 플래그 발견 (1개):
#     CTF{p4ck3t_4n4lys1s_m4st3r}
```

---

## 실습 2: Nmap 고급 스캔으로 서비스 버전 탐지

### 목표

대상 호스트의 열린 포트와 서비스 버전 정보를 수집하고, 취약한 서비스를 식별하라.

**힌트:**
- Nmap의 `-sV` (버전 탐지)와 `-sC` (기본 스크립트) 옵션을 활용하라.
- 서비스 배너에서 버전 정보를 추출하라.
- NSE(Nmap Scripting Engine) 스크립트를 활용하라.

### 풀이

**Step 1: 기본 포트 스캔**
```bash
# SYN 스캔 (가장 일반적)
nmap -sS -T4 10.10.10.0/24

# 호스트 발견 없이 스캔 (컨테이너 환경에서 유용)
nmap -Pn -sS -T4 10.10.10.0/24
```

**Step 2: 서비스 버전 탐지**
```bash
# 버전 탐지 + 기본 NSE 스크립트
nmap -sV -sC -p- -T4 10.10.10.10

# 상세 버전 탐지 (강도 9)
nmap -sV --version-intensity 9 -p 1-1000 10.10.10.10
```

**Step 3: NSE 취약점 스크립트**
```bash
# 모든 취약점 스크립트 실행
nmap --script vuln -p 80,445,22 10.10.10.0/24

# SMB 관련 스크립트만 실행
nmap -p 445 --script "smb-*" 10.10.10.30

# HTTP 헤더 및 타이틀 수집
nmap -p 80,8080,443 --script "http-title,http-headers,http-server-header" 10.10.10.10
```

**Step 4: 결과 XML 파싱 (Python)**
```python
#!/usr/bin/env python3
"""Nmap XML 결과에서 서비스 정보를 추출한다."""

import argparse
import xml.etree.ElementTree as ET
from dataclasses import dataclass


@dataclass
class PortInfo:
    port: int
    protocol: str
    state: str
    service: str
    product: str
    version: str
    extra_info: str

    def __str__(self) -> str:
        ver = f" {self.version}" if self.version else ""
        prod = f"{self.product}{ver}" if self.product else self.service
        return f"  {self.port:5d}/{self.protocol}  {self.state:<8}  {prod}"


def parse_nmap_xml(xml_path: str) -> dict[str, list[PortInfo]]:
    """nmap -oX 출력 XML을 파싱해 호스트별 포트 정보를 반환한다."""
    tree = ET.parse(xml_path)
    root = tree.getroot()
    result: dict[str, list[PortInfo]] = {}

    for host in root.findall("host"):
        addr_elem = host.find("address[@addrtype='ipv4']")
        if addr_elem is None:
            continue
        ip = addr_elem.get("addr", "unknown")
        ports_info: list[PortInfo] = []

        ports_elem = host.find("ports")
        if ports_elem is None:
            continue
        for port in ports_elem.findall("port"):
            state_elem = port.find("state")
            service_elem = port.find("service")
            if state_elem is None:
                continue

            ports_info.append(
                PortInfo(
                    port=int(port.get("portid", 0)),
                    protocol=port.get("protocol", "tcp"),
                    state=state_elem.get("state", ""),
                    service=service_elem.get("name", "") if service_elem is not None else "",
                    product=service_elem.get("product", "") if service_elem is not None else "",
                    version=service_elem.get("version", "") if service_elem is not None else "",
                    extra_info=service_elem.get("extrainfo", "") if service_elem is not None else "",
                )
            )

        if ports_info:
            result[ip] = ports_info

    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Nmap XML 결과 파싱")
    parser.add_argument("xml_file", help="nmap -oX 출력 파일")
    parser.add_argument("--open-only", action="store_true", help="열린 포트만 표시")
    args = parser.parse_args()

    hosts = parse_nmap_xml(args.xml_file)
    for ip, ports in hosts.items():
        print(f"\n[+] {ip}")
        for p in ports:
            if args.open_only and p.state != "open":
                continue
            print(p)


if __name__ == "__main__":
    main()
```

```bash
# Nmap 결과를 XML로 저장 후 파싱
nmap -sV -sC -oX scan_result.xml 10.10.10.0/24
python3 parse_nmap.py scan_result.xml --open-only
```

---

## 실습 3: SMB 익스플로잇 시뮬레이션 (EternalBlue 개념)

### 목표

SMB 서버를 대상으로 취약점을 탐지하고, 인증을 우회해 공유 파일에서 플래그를 추출하라.

**힌트:**
- SMB 공유 목록을 열거하라.
- 익명(anonymous) 또는 기본 자격증명으로 접근을 시도하라.
- 공유에 접근 가능하다면 파일 목록을 확인하라.

### 풀이

**Step 1: SMB 서비스 탐지**
```bash
# SMB 서비스 및 버전 탐지
nmap -p 139,445 -sV --script smb-protocols 10.10.10.30

# 공유 열거 (익명)
nmap -p 445 --script smb-enum-shares 10.10.10.30
```

**Step 2: SMB 공유 접근**
```bash
# smbclient로 공유 목록 확인
smbclient -L //10.10.10.30 -N              # 익명 접근 시도
smbclient -L //10.10.10.30 -U ctfuser%password123  # 자격증명 사용

# 공유에 접속해 파일 목록 확인
smbclient //10.10.10.30/share -U ctfuser%password123
# smb: \> ls
# smb: \> get flag.txt
# smb: \> exit
```

**Step 3: EternalBlue 취약점 개념 및 Metasploit 시뮬레이션**

> **주의:** 실제 EternalBlue 익스플로잇은 허가된 시스템에서만 사용해야 한다. 아래는 교육용 시뮬레이션이다.

```bash
# Metasploit으로 MS17-010 취약점 스캔 (탐지만)
msfconsole -q -x "
use auxiliary/scanner/smb/smb_ms17_010;
set RHOSTS 10.10.10.30;
run;
exit
"

# Nmap으로 MS17-010 탐지
nmap -p 445 --script smb-vuln-ms17-010 10.10.10.30
```

**Step 4: Python SMB 자동화**
```python
#!/usr/bin/env python3
"""
SMB 공유 열거 및 파일 다운로드 자동화
impacket 라이브러리 사용
"""

import argparse
import sys
from pathlib import Path

try:
    from impacket.smbconnection import SMBConnection
    from impacket import smb
except ImportError:
    print("[!] impacket 필요: pip install impacket", file=sys.stderr)
    sys.exit(1)


def enum_shares(
    host: str, username: str = "", password: str = ""
) -> list[str]:
    """SMB 공유 목록을 반환한다."""
    conn = SMBConnection(host, host)
    try:
        conn.login(username, password)
        shares = conn.listShares()
        return [s["shi1_netname"].rstrip("\x00") for s in shares]
    finally:
        conn.logoff()


def download_files(
    host: str,
    share: str,
    remote_path: str,
    local_dir: str,
    username: str = "",
    password: str = "",
) -> list[str]:
    """SMB 공유의 지정 경로에서 파일을 다운로드한다."""
    conn = SMBConnection(host, host)
    downloaded: list[str] = []
    try:
        conn.login(username, password)
        files = conn.listPath(share, remote_path + "/*")
        for f in files:
            name = f.get_longname()
            if name in (".", ".."):
                continue
            local_path = Path(local_dir) / name
            with open(local_path, "wb") as fp:
                conn.getFile(share, f"{remote_path}/{name}", fp.write)
            downloaded.append(str(local_path))
    finally:
        conn.logoff()
    return downloaded


def search_flags(local_dir: str, pattern: str = "CTF{") -> list[str]:
    """로컬 디렉토리에서 플래그를 검색한다."""
    flags: list[str] = []
    for path in Path(local_dir).rglob("*"):
        if not path.is_file():
            continue
        try:
            content = path.read_text(errors="replace")
            if pattern in content:
                start = content.index(pattern)
                end = content.index("}", start) + 1
                flags.append(content[start:end])
        except Exception:
            continue
    return flags


def main() -> None:
    parser = argparse.ArgumentParser(description="SMB 공유 열거 및 파일 다운로드")
    parser.add_argument("host", help="대상 SMB 서버 IP")
    parser.add_argument("-u", "--username", default="", help="사용자명 (기본: 익명)")
    parser.add_argument("-p", "--password", default="", help="패스워드")
    parser.add_argument("-s", "--share", default="", help="접근할 공유 이름")
    parser.add_argument(
        "-o", "--output", default="/tmp/smb_loot", help="다운로드 경로"
    )
    args = parser.parse_args()

    Path(args.output).mkdir(parents=True, exist_ok=True)

    print(f"[*] {args.host} SMB 공유 열거 중...")
    shares = enum_shares(args.host, args.username, args.password)
    print(f"[+] 발견된 공유: {shares}")

    target_share = args.share or (shares[0] if shares else "")
    if not target_share:
        print("[-] 접근 가능한 공유가 없습니다.")
        return

    print(f"[*] '{target_share}' 공유에서 파일 다운로드 중...")
    downloaded = download_files(
        args.host, target_share, "\\",
        args.output, args.username, args.password
    )
    print(f"[+] 다운로드된 파일: {downloaded}")

    flags = search_flags(args.output)
    if flags:
        print(f"[+] 플래그 발견: {flags}")
    else:
        print("[-] 플래그를 찾지 못했습니다.")


if __name__ == "__main__":
    main()
```

```bash
# 사용 예시
python3 smb_enum.py 10.10.10.30 -u ctfuser -p password123
# [+] 발견된 공유: ['share', 'IPC$']
# [+] 다운로드된 파일: ['/tmp/smb_loot/flag.txt']
# [+] 플래그 발견: ['CTF{smb_3xpl01t_succ3ss}']
```

---

## 환경 정리

```bash
# 실습 완료 후 컨테이너 종료
docker compose down -v
```

---

## 참고 자료

- Nmap 공식 문서: https://nmap.org/book/
- Wireshark 공식 문서: https://www.wireshark.org/docs/

---

<a name="english"></a>

# CTF-Style Network Hacking Lab

## Lab Environment Setup

Use the Docker Compose configuration above (see Korean section) to spin up three target services on a `10.10.10.0/24` bridge network.

```bash
mkdir -p smb-share
echo "CTF{smb_3xpl01t_succ3ss}" > smb-share/flag.txt
docker compose up -d
docker exec -it attacker bash
apt-get update -q && apt-get install -y -q nmap wireshark-cli tcpdump smbclient python3
```

---

## Lab 1: Extract Flag from Packets Using Wireshark/tshark

### Objective

Capture HTTP traffic between the attacker and `10.10.10.10` and extract the hidden flag from the packet payload.

**Hints:**
- Use `tshark` or `tcpdump` to capture traffic.
- Inspect HTTP response bodies.
- Flag format: `CTF{...}`

### Solution

```bash
# Step 1: Generate traffic
docker exec attacker sh -c \
  "for i in \$(seq 1 10); do curl -s http://10.10.10.10/secret.txt; sleep 1; done" &

# Step 2: Capture packets
tshark -i eth0 -f "tcp port 80" -w /tmp/capture.pcap

# Step 3: Extract flag
tshark -r /tmp/capture.pcap -Y "http.response" -T fields -e http.file_data
```

Use the Python script in the Korean section to parse the pcap programmatically:

```bash
python3 extract_flags.py capture.pcap
# [+] Flag found: CTF{p4ck3t_4n4lys1s_m4st3r}
```

---

## Lab 2: Advanced Nmap Scanning for Service Version Detection

### Objective

Discover all open ports on the lab network and identify services with their exact version numbers, then find any vulnerable services.

**Hints:**
- Use `-sV` for version detection and `-sC` for default scripts.
- Run vulnerability NSE scripts against discovered services.
- Save results to XML for programmatic parsing.

### Solution

```bash
# Step 1: Host discovery
nmap -Pn -sS -T4 10.10.10.0/24

# Step 2: Version detection
nmap -sV -sC -p- -T4 10.10.10.10

# Step 3: Vulnerability scripts
nmap --script vuln -p 80,445,22 10.10.10.0/24

# Step 4: Save and parse XML
nmap -sV -sC -oX scan_result.xml 10.10.10.0/24
python3 parse_nmap.py scan_result.xml --open-only
```

---

## Lab 3: SMB Exploit Simulation (EternalBlue Concept)

### Objective

Enumerate SMB shares on `10.10.10.30`, authenticate using discovered credentials, and retrieve the flag file.

**Hints:**
- Use `smbclient -L` to list shares.
- Try anonymous access first, then default credentials.
- Once connected, list files and download the flag.

### Solution

```bash
# Step 1: Detect SMB
nmap -p 139,445 -sV --script smb-protocols 10.10.10.30

# Step 2: Enumerate shares
smbclient -L //10.10.10.30 -U ctfuser%password123

# Step 3: Download flag
smbclient //10.10.10.30/share -U ctfuser%password123 -c "get flag.txt /tmp/flag.txt"
cat /tmp/flag.txt
# CTF{smb_3xpl01t_succ3ss}
```

Use the Python automation script:
```bash
python3 smb_enum.py 10.10.10.30 -u ctfuser -p password123
# [+] Flag found: ['CTF{smb_3xpl01t_succ3ss}']
```

---

## Cleanup

```bash
docker compose down -v
```

---

## References

- Nmap Official Documentation: https://nmap.org/book/
- Wireshark Official Documentation: https://www.wireshark.org/docs/
