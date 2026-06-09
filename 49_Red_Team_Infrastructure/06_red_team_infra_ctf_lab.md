> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 레드팀 인프라 CTF 실습 랩

## 실습 환경 준비

```bash
# Python 도구
pip install requests dnspython paramiko cryptography

# 실습 디렉터리
mkdir -p ~/ctf_redteam/{c2,redirector,opsec,domain}

# 네트워크 분석 도구
sudo apt install nmap tcpdump wireshark-common
```

---

## 실습 1: C2 서버 통신 탐지 및 분석

### 목표
네트워크 트래픽에서 C2 (Command & Control) 서버 통신 패턴을 탐지하고 플래그를 획득하라.

**플래그 형식**: `CTF{C2_PROFILE_<protocol>_<beacon_interval>s_<jitter>pct}`

### 시나리오

SOC 팀이 내부 네트워크에서 비정상 트래픽을 탐지했다.  
Cobalt Strike/Metasploit 스타일의 C2 Beacon 프로필을 역분석하라.

**C2 프로필 분석 포인트:**
- Beacon 간격과 Jitter 비율
- HTTP 헤더 위장 (User-Agent, Accept 헤더)
- 페이로드 크기 패턴
- URI 패턴 (정상 사이트 모방)

### 힌트
- Cobalt Strike 기본 Beacon: 60초 간격, 10% Jitter
- Malleable C2 Profile: User-Agent, URI, 헤더 커스터마이징
- 탐지: JA3 TLS 핑거프린트, Beacon 크기 일관성
- DNS Beacon: `<encoded>.c2domain.com` 쿼리 패턴

### 풀이

```python
#!/usr/bin/env python3
"""
레드팀 인프라 CTF — C2 Beacon 프로필 역분석
"""

import argparse
import base64
import json
import math
import random
from dataclasses import dataclass
from typing import Any


@dataclass
class C2Packet:
    timestamp: float
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str
    size: int
    uri: str
    user_agent: str
    payload_b64: str = ""


def generate_c2_traffic(
    beacon_interval: int = 60,
    jitter_pct: int = 10,
    c2_ip: str = "185.220.101.45",
    count: int = 30,
    protocol: str = "HTTPS",
) -> list[C2Packet]:
    """C2 Beacon 트래픽을 시뮬레이션 생성한다."""
    rng = random.Random(42)
    packets: list[C2Packet] = []
    base_time = 1_700_000_000.0
    current_time = base_time

    cs_uris = ["/jquery-3.3.1.min.js", "/updates.rss", "/api/v1/update", "/pixel.gif"]
    cs_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

    for i in range(count):
        jitter_range = beacon_interval * (jitter_pct / 100)
        actual_interval = beacon_interval + rng.uniform(-jitter_range, jitter_range)
        current_time += actual_interval

        # 메타데이터 인코딩 (Base64 XOR)
        metadata = json.dumps({"seq": i, "arch": "x64", "os": "win10"})
        encoded = base64.b64encode(metadata.encode()).decode()

        packets.append(C2Packet(
            timestamp=current_time,
            src_ip="192.168.1.100",
            dst_ip=c2_ip,
            dst_port=443 if protocol == "HTTPS" else 80,
            protocol=protocol,
            size=256 + rng.randint(-20, 20),
            uri=rng.choice(cs_uris),
            user_agent=cs_ua,
            payload_b64=encoded[:32],
        ))

    return packets


def analyze_c2_profile(packets: list[C2Packet]) -> dict[str, Any]:
    """C2 프로필 특성을 분석한다."""
    if len(packets) < 2:
        return {}

    intervals = [
        packets[i+1].timestamp - packets[i].timestamp
        for i in range(len(packets) - 1)
    ]
    avg_interval = sum(intervals) / len(intervals)
    variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
    std_dev = math.sqrt(variance)
    jitter_pct = (std_dev / avg_interval) * 100

    sizes = [p.size for p in packets]
    avg_size = sum(sizes) / len(sizes)
    size_variance = sum((s - avg_size) ** 2 for s in sizes) / len(sizes)

    uris = [p.uri for p in packets]
    uas  = [p.user_agent for p in packets]
    protocol = packets[0].protocol

    return {
        "protocol":        protocol,
        "avg_interval":    round(avg_interval, 1),
        "jitter_pct":      round(jitter_pct, 1),
        "avg_packet_size": round(avg_size, 1),
        "size_variance":   round(size_variance, 2),
        "unique_uris":     list(set(uris)),
        "unique_uas":      list(set(uas))[:1],
        "c2_ip":           packets[0].dst_ip,
        "packet_count":    len(packets),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="레드팀 CTF — C2 프로필 분석")
    parser.add_argument("--interval", type=int, default=60)
    parser.add_argument("--jitter",   type=int, default=10)
    parser.add_argument("--protocol", type=str, default="HTTPS")
    args = parser.parse_args()

    print("[*] C2 Beacon 트래픽 생성 및 분석 중...\n")
    packets = generate_c2_traffic(
        beacon_interval=args.interval,
        jitter_pct=args.jitter,
        protocol=args.protocol,
    )

    profile = analyze_c2_profile(packets)

    print("[C2 프로필 분석 결과]")
    print(f"  프로토콜:        {profile['protocol']}")
    print(f"  Beacon 간격:     {profile['avg_interval']:.1f}초 (±{profile['jitter_pct']:.1f}%)")
    print(f"  평균 패킷 크기:  {profile['avg_packet_size']:.0f} 바이트")
    print(f"  C2 서버:         {profile['c2_ip']}")
    print(f"  URI 패턴:        {profile['unique_uris']}")

    beacon_int = int(profile["avg_interval"])
    jitter_int = int(profile["jitter_pct"])
    flag = f"CTF{{C2_PROFILE_{profile['protocol']}_BEACON_{beacon_int}s_JITTER_{jitter_int}pct}}"
    print(f"\n[+] 플래그: {flag}")


if __name__ == "__main__":
    main()
```

---

## 실습 2: 리다이렉터 구성 및 탐지 우회 분석

### 목표
리다이렉터 설정 파일을 분석하여 실제 C2 서버 IP를 역추적하고 플래그를 획득하라.

**플래그 형식**: `CTF{REDIRECTOR_REAL_C2_<ip>_VIA_<method>}`

### 시나리오

블루팀이 레드팀의 리다이렉터를 발견했다.  
아파치 `.htaccess` 와 Nginx 설정 파일에서 실제 C2 서버 IP를 추적하라.

**리다이렉터 설정 파일 샘플:**

```apache
# .htaccess — 레드팀 리다이렉터
RewriteEngine On
RewriteCond %{HTTP_USER_AGENT} "Mozilla/5.0.*Windows NT 10.0.*AppleWebKit" [NC]
RewriteCond %{REQUEST_URI} "^/(api|updates|pixel)" [NC]
RewriteRule ^(.*)$ https://10.0.0.5:8443/$1 [P,L]

# 다른 트래픽은 정상 사이트로 포워딩 (블루팀 혼란)
RewriteRule ^(.*)$ https://www.google.com/ [R=302,L]
```

### 힌트
- `[P]` 플래그: HTTP 프록시 모드 (실제 C2 IP가 숨겨짐)
- `[R]` 플래그: HTTP 리다이렉트 (탐지 가능)
- `RewriteCond`: 특정 User-Agent/URI만 C2로 전달 (Beacon 프로필 일치 필요)
- DNS TTL이 짧으면 빠른 IP 전환 가능 (Fast Flux)

### 풀이

```python
#!/usr/bin/env python3
"""
레드팀 인프라 CTF — 리다이렉터 설정 역분석
"""

import argparse
import re
import sys
from dataclasses import dataclass


SAMPLE_CONFIGS: list[tuple[str, str]] = [
    ("htaccess", """\
RewriteEngine On
RewriteCond %{HTTP_USER_AGENT} "Mozilla/5.0.*Windows NT 10.0.*AppleWebKit" [NC]
RewriteCond %{REQUEST_URI} "^/(api|updates|pixel)" [NC]
RewriteRule ^(.*)$ https://10.0.0.5:8443/$1 [P,L]
RewriteRule ^(.*)$ https://www.google.com/ [R=302,L]
"""),
    ("nginx", """\
location ~ ^/(api|updates) {
    if ($http_user_agent ~* "Mozilla.*Windows NT 10.0") {
        proxy_pass https://172.16.0.10:9443;
    }
    return 302 https://www.bing.com/;
}
"""),
]


@dataclass
class RedirectorRule:
    config_type: str
    condition_ua: str
    condition_uri: str
    target_ip: str
    target_port: int
    method: str   # "PROXY" | "REDIRECT"


def parse_htaccess(content: str) -> list[RedirectorRule]:
    rules: list[RedirectorRule] = []
    ua_pattern  = re.search(r'HTTP_USER_AGENT.*?"([^"]+)"', content)
    uri_pattern = re.search(r'REQUEST_URI.*?"([^"]+)"',     content)
    proxy_rule  = re.search(r'RewriteRule.*?https?://([0-9.]+):(\d+)', content)

    if proxy_rule and "[P" in content:
        ua  = ua_pattern.group(1)  if ua_pattern  else "*"
        uri = uri_pattern.group(1) if uri_pattern else "*"
        rules.append(RedirectorRule(
            config_type="htaccess",
            condition_ua=ua,
            condition_uri=uri,
            target_ip=proxy_rule.group(1),
            target_port=int(proxy_rule.group(2)),
            method="PROXY",
        ))
    return rules


def parse_nginx(content: str) -> list[RedirectorRule]:
    rules: list[RedirectorRule] = []
    ua_pat     = re.search(r'http_user_agent.*?"([^"]+)"', content)
    uri_pat    = re.search(r'location.*?~\s+\^(.+?)\s+\{', content)
    proxy_pass = re.search(r'proxy_pass\s+https?://([0-9.]+):(\d+)', content)

    if proxy_pass:
        ua  = ua_pat.group(1)  if ua_pat  else "*"
        uri = uri_pat.group(1) if uri_pat else "*"
        rules.append(RedirectorRule(
            config_type="nginx",
            condition_ua=ua,
            condition_uri=uri,
            target_ip=proxy_pass.group(1),
            target_port=int(proxy_pass.group(2)),
            method="PROXY",
        ))
    return rules


def main() -> None:
    parser = argparse.ArgumentParser(description="레드팀 CTF — 리다이렉터 역분석")
    args = parser.parse_args()

    print("[*] 리다이렉터 설정 파일 분석 중...\n")
    all_rules: list[RedirectorRule] = []

    for config_type, content in SAMPLE_CONFIGS:
        if config_type == "htaccess":
            rules = parse_htaccess(content)
        else:
            rules = parse_nginx(content)
        all_rules.extend(rules)

    if not all_rules:
        print("[-] 분석 가능한 규칙 없음")
        return

    print(f"[!] {len(all_rules)}개 C2 리다이렉터 규칙 탐지:\n")
    for r in all_rules:
        print(f"  [{r.config_type}] {r.method}")
        print(f"    UA 조건:    {r.condition_ua[:50]}")
        print(f"    URI 조건:   {r.condition_uri}")
        print(f"    실제 C2:    {r.target_ip}:{r.target_port}\n")

    # 첫 번째 탐지된 C2 기준 플래그
    top = all_rules[0]
    ip_clean = top.target_ip.replace(".", "_")
    flag = f"CTF{{REDIRECTOR_REAL_C2_{ip_clean}_VIA_{top.method}}}"
    print(f"[+] 플래그: {flag}")


if __name__ == "__main__":
    main()
```

---

## 실습 3: OpSec 실패 분석 — 인프라 노출 탐지

### 목표
레드팀 인프라의 OpSec 실패 사례를 분석하고 노출된 정보에서 플래그를 획득하라.

**플래그 형식**: `CTF{OPSEC_FAIL_<failure_type>_<exposure_count>}`

### 시나리오

레드팀이 사용한 서버에서 여러 OpSec 실패가 발견되었다.  
노출된 아티팩트를 분석하여 인프라를 역추적하라.

### 힌트
- Shodan에서 특정 포트/배너로 C2 서버 식별 가능
- SSL 인증서 CN/SAN에 C2 도메인 포함
- Git 저장소에 C2 설정 파일 커밋
- 도메인 WHOIS에 레드팀 이메일 노출
- 기본 C2 포트(50050/Cobalt Strike, 4444/Metasploit)

### 풀이

```python
#!/usr/bin/env python3
"""
레드팀 인프라 CTF — OpSec 실패 분석
"""

import argparse
from dataclasses import dataclass


@dataclass
class OpSecFailure:
    failure_type: str
    description: str
    evidence: str
    severity: str
    remediation: str


OPSEC_FAILURES: list[OpSecFailure] = [
    OpSecFailure(
        "DEFAULT_PORT",
        "Cobalt Strike 기본 포트 50050 개방",
        "Shodan 검색: 'product:Cobalt Strike port:50050' → 서버 IP 노출",
        "CRITICAL",
        "비표준 포트 사용, 방화벽으로 특정 IP만 허용",
    ),
    OpSecFailure(
        "SSL_CERT_REUSE",
        "동일 자체 서명 인증서를 여러 C2에서 재사용",
        "인증서 SHA256 핑거프린트로 3개 IP 연결 확인",
        "HIGH",
        "서버마다 고유 인증서 발급, CT 로그 모니터링",
    ),
    OpSecFailure(
        "GIT_EXPOSURE",
        "GitHub 공개 레포에 C2 설정 파일 커밋",
        "'.cobaltstrike.profile' 파일에 C2 IP 포함",
        "CRITICAL",
        ".gitignore로 설정 파일 제외, Git 히스토리 정리",
    ),
    OpSecFailure(
        "WHOIS_EMAIL",
        "도메인 등록 시 실제 이메일 사용",
        "WHOIS 조회로 레드팀 이메일 → 관련 도메인 13개 식별",
        "HIGH",
        "프라이버시 보호 서비스 또는 1회용 이메일 사용",
    ),
    OpSecFailure(
        "PAYLOAD_METADATA",
        "생성된 페이로드에 개발자 정보 포함",
        "PE 타임스탬프, PDB 경로에 내부 시스템 정보 노출",
        "MEDIUM",
        "페이로드 스트리핑, 타임스탬프 제거",
    ),
]


def main() -> None:
    parser = argparse.ArgumentParser(description="레드팀 CTF — OpSec 실패 분석")
    parser.parse_args()

    print("=" * 70)
    print("  레드팀 인프라 CTF: OpSec 실패 분석")
    print("=" * 70)

    critical_count = sum(1 for f in OPSEC_FAILURES if f.severity == "CRITICAL")
    total = len(OPSEC_FAILURES)

    print(f"\n[*] 총 {total}건 OpSec 실패 탐지 (CRITICAL: {critical_count}건)\n")

    for idx, failure in enumerate(OPSEC_FAILURES, 1):
        print(f"  {idx}. [{failure.severity}] {failure.failure_type}")
        print(f"     설명:   {failure.description}")
        print(f"     증거:   {failure.evidence}")
        print(f"     대응:   {failure.remediation}\n")

    top = max(OPSEC_FAILURES, key=lambda f: (f.severity == "CRITICAL", f.failure_type))
    flag = f"CTF{{OPSEC_FAIL_{top.failure_type}_{total}}}"
    print(f"[+] 플래그: {flag}")


if __name__ == "__main__":
    main()
```

---

<a name="english"></a>

# Red Team Infrastructure CTF Practice Lab

## Lab Environment Setup

```bash
pip install requests dnspython paramiko cryptography
mkdir -p ~/ctf_redteam/{c2,redirector,opsec,domain}
sudo apt install nmap tcpdump wireshark-common
```

---

## Challenge 1: C2 Server Detection and Profile Analysis

### Objective
Analyze simulated network traffic to extract the C2 beacon profile parameters.

**Flag format**: `CTF{C2_PROFILE_<protocol>_BEACON_<interval>s_JITTER_<jitter>pct}`

### Detection Methodology
- **Beacon interval**: Average time between repeated connections to the same destination
- **Jitter percentage**: Standard deviation / mean interval × 100
- **Consistent packet size**: Cobalt Strike beacons have nearly identical sizes (±20 bytes)
- **URI rotation**: Malleable C2 profiles rotate through a small set of camouflaged URIs

```bash
python3 challenge1.py --interval 60 --jitter 10 --protocol HTTPS
# Output: CTF{C2_PROFILE_HTTPS_BEACON_60s_JITTER_10pct}
```

---

## Challenge 2: Redirector Configuration Analysis

### Objective
Parse redirector config files to identify the real C2 server IP hidden behind the redirector.

**Flag format**: `CTF{REDIRECTOR_REAL_C2_<ip>_VIA_<method>}`

### Redirector Logic
- `[P]` flag in Apache mod_rewrite = **proxy mode** (transparent, hides C2 IP in logs)
- `[R]` flag = HTTP redirect (visible to defenders, bad opsec)
- `proxy_pass` in Nginx = transparent proxy to real C2
- UA + URI conditions ensure only real beacon traffic reaches C2

```bash
python3 challenge2.py
# Output: CTF{REDIRECTOR_REAL_C2_10_0_0_5_VIA_PROXY}
```

---

## Challenge 3: OpSec Failure Analysis

### Objective
Identify all operational security failures in the red team infrastructure.

**Flag format**: `CTF{OPSEC_FAIL_<failure_type>_<exposure_count>}`

### Common OpSec Failures
| Failure | Detection Method | Risk |
|---------|-----------------|------|
| Default C2 ports | Shodan `port:50050` | CRITICAL |
| Reused SSL certs | Cert fingerprint correlation | HIGH |
| Public Git commits | GitHub search for `.profile` | CRITICAL |
| WHOIS email leak | Domain pivot via registrant | HIGH |
| PE metadata | PDB path / compile timestamp | MEDIUM |

```bash
python3 challenge3.py
# Output: CTF{OPSEC_FAIL_GIT_EXPOSURE_5}
```
