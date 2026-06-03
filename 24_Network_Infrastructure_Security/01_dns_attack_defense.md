> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# DNS 공격과 방어

## 0. 초보자를 위한 개념 이해

### DNS란 무엇인가?

DNS(Domain Name System)는 인터넷의 "전화번호부"다. 우리가 브라우저에 `google.com`을 입력하면, DNS가 이를 실제 IP 주소(예: 142.250.206.46)로 변환해준다. 컴퓨터는 IP 주소로 통신하지만 사람은 숫자보다 이름이 기억하기 쉽기 때문에 DNS가 필요하다. DNS 공격은 이 변환 과정을 조작하여 사용자를 가짜 사이트로 유도하거나, 내부 네트워크 정보를 유출하는 데 사용된다.

**왜 배우는가:**
```
DNS 공격이 위험한 이유

정상 흐름:
  사용자 → DNS 조회 → 올바른 IP → 진짜 서버

DNS 캐시 포이즈닝 공격:
  사용자 → DNS 조회 → 조작된 IP → 공격자 서버
              (캐시에 가짜 응답 주입)

Zone Transfer 공격:
  외부 공격자 → DNS 서버에 전체 레코드 요청 → 내부 인프라 맵 노출
  (방화벽 안의 호스트 이름, IP, 서브도메인 전부 유출)
```

### 핵심 개념 정리

```
DNS 주요 레코드와 공격 표면

레코드  의미                 관련 공격
──────────────────────────────────────────────────
A      도메인 → IPv4         캐시 포이즈닝
MX     메일 서버             스푸핑, 메일 인터셉트
NS     네임서버              서브도메인 탈취
TXT    SPF/DKIM/기타         정보 수집
AXFR   전체 영역 전송        Zone Transfer → 내부 맵 유출
CNAME  별칭                  서브도메인 탈취 (위임 레코드 방치)
```

### 필요한 도구 및 환경
- **dig**: DNS 조회 (`apt install dnsutils`)
- **nslookup**: 기본 DNS 조회 도구
- **dnsx / subfinder**: 서브도메인 열거
- **dnsmasq**: 로컬 DNS 서버 실습용

### 기초 실습 예제
```bash
# 1. 기본 DNS 조회
dig A example.com           # A 레코드 (IPv4)
dig MX example.com          # 메일 서버
dig NS example.com          # 네임서버
dig TXT example.com         # TXT 레코드 (SPF 등)

# 2. Zone Transfer 시도 (취약한 서버에서만 성공)
dig axfr example.com @ns1.example.com
# 성공하면: 전체 DNS 레코드 목록이 반환됨 (취약!)
# 실패하면: "Transfer failed." (올바른 보안 설정)

# 3. 역방향 DNS 조회 (IP → 도메인)
dig -x 8.8.8.8

# 4. 특정 DNS 서버에 직접 조회
dig @8.8.8.8 example.com A  # Google DNS에 직접 물어보기
```

---

## 1. DNS 기초 및 공격 표면

```
DNS 레코드 유형:
  A      → 도메인 → IPv4
  AAAA   → 도메인 → IPv6
  MX     → 메일 서버
  NS     → 네임서버
  CNAME  → 별칭
  TXT    → SPF, DKIM, DMARC 등
  SOA    → Zone 권한 정보
  PTR    → 역방향 조회

공격 표면:
  ┌─────────────────────────────────────┐
  │ Zone Transfer (AXFR) — 내부 맵 유출 │
  │ DNS Cache Poisoning — 응답 위조      │
  │ DNS Rebinding — SOP 우회            │
  │ Subdomain Takeover — 위임 악용      │
  │ DNS Tunneling — C2 통신 은닉        │
  │ DNS Amplification — DDoS 증폭       │
  └─────────────────────────────────────┘
```

---

## 2. Zone Transfer 공격 (AXFR)

### 2-1. Zone Transfer 시도


DNS 공격 시나리오 테스트 명령어입니다. Zone Transfer 취약점 확인(`dig axfr`), 서브도메인 열거, DNS 캐시 상태 확인 등 DNS 보안 점검의 기본 명령어들입니다.

```bash
# 기본 AXFR 시도
dig axfr example.com @ns1.example.com
dig axfr example.com @8.8.8.8

# host 명령
host -t axfr example.com ns1.example.com

# nmap으로 zone transfer 탐지
nmap --script dns-zone-transfer --script-args \
  dns-zone-transfer.domain=example.com <ns-ip>

# fierce — NS 서버 자동 발견 후 AXFR 시도
fierce --domain example.com
```

### 2-2. Zone Transfer로 수집 가능한 정보

```
성공 시 획득 데이터:
  - 모든 서브도메인 (내부 서버 포함)
  - 내부 IP 대역 매핑
  - 메일 서버, 백업 서버 위치
  - 개발/스테이징 환경 도메인
  - 관리자 명명 규칙 파악

예시 출력:
  dev.example.com.        A    192.168.1.10
  staging.example.com.    A    192.168.1.20
  vpn.example.com.        A    203.0.113.5
  admin.example.com.      A    10.0.0.1
  mail.example.com.       MX   10 mail1.example.com.
```

### 2-3. 방어 — Zone Transfer 제한


BIND DNS 서버 보안 설정입니다. Zone Transfer를 슬레이브 서버 IP로만 제한하고, 재귀 쿼리를 내부 네트워크로만 허용하며, DNSSEC를 활성화하여 DNS 스푸핑을 방어합니다.

```bash
# BIND named.conf — 특정 IP만 허용
zone "example.com" {
    type master;
    file "/etc/bind/db.example.com";
    allow-transfer { 192.168.1.2; };  # 슬레이브 NS만 허용
    also-notify    { 192.168.1.2; };
};

# 전역 제한 (모든 zone)
options {
    allow-transfer { none; };  # 기본 차단
};

# 테스트
dig axfr example.com @ns1.example.com
# Transfer failed. → 올바르게 차단됨
```

---

## 3. DNS Cache Poisoning (카마진스키 공격)

```
공격 원리:
  1. 공격자가 타깃 레졸버에 존재하지 않는 도메인 다량 쿼리
  2. 실제 권한 NS가 응답하기 전에 위조 응답 주입
  3. 트랜잭션 ID(16비트) + 출발지 포트 예측 (Birthday Attack)
  4. 캐시에 위조 레코드 저장 → 모든 사용자가 공격자 서버로 이동

카마진스키(2008) 개선점:
  - NXDOMAIN 응답의 글루 레코드 위조
  - 쿼리 한 번에 전체 zone 캐시 오염 가능

방어:
  □ DNSSEC 배포 (응답 서명 검증)
  □ 출발지 포트 무작위화 (0~65535)
  □ 0x20 인코딩 (대소문자 무작위화로 트랜잭션 엔트로피 증가)
  □ BIND/Unbound 최신 버전 유지
```

### DNSSEC 설정 (BIND)

DNSSEC(DNS 보안 확장)을 설정합니다. Zone에 디지털 서명을 추가하여 DNS 응답의 무결성을 보장하고 DNS 스푸핑을 방지합니다.

```bash
# Zone 서명 키 생성
dnssec-keygen -a RSASHA256 -b 2048 -n ZONE example.com     # ZSK
dnssec-keygen -a RSASHA256 -b 4096 -n ZONE -f KSK example.com  # KSK

# Zone 파일 서명
dnssec-signzone -A -3 $(head -c 16 /dev/urandom | xxd -p) \
  -N INCREMENT -o example.com -t db.example.com

# named.conf에 서명된 zone 사용
zone "example.com" {
    type master;
    file "/etc/bind/db.example.com.signed";
    auto-dnssec maintain;
    inline-signing yes;
};

# DS 레코드를 상위 registrar에 등록
dnssec-dsfromkey Kexample.com.+008+XXXXX.key
```

---

## 4. DNS Tunneling (C2 은닉 통신)

```
원리:
  데이터를 DNS 쿼리/응답에 인코딩하여 방화벽 우회
  공격자 도메인(attacker.com)의 권한 NS를 공격자가 직접 운영

데이터 흐름:
  피해자 → [base32 인코딩 데이터].attacker.com 쿼리 → 공격자 NS
  공격자 NS → TXT 레코드에 명령 인코딩 → 피해자로 응답

대표 도구:
  iodine   — IP over DNS
  dnscat2  — C2 채널
  dns2tcp  — TCP over DNS
```

### DNS Tunneling 탐지 및 차단

DNS 터널링을 탐지하는 Python 스크립트입니다. 비정상적으로 긴 DNS 쿼리, 높은 쿼리 빈도, 비표준 레코드 타입을 모니터링합니다.

```python
import dns.resolver
import re
import argparse
from collections import Counter
from pathlib import Path

# DNS 터널링 특징: 매우 긴 서브도메인, 높은 엔트로피, 비정상 빈도
def shannon_entropy(s: str) -> float:
    from math import log2
    freq = Counter(s.lower())
    total = len(s)
    return -sum((c/total) * log2(c/total) for c in freq.values())

def analyze_dns_log(log_path: str) -> None:
    """DNS 쿼리 로그 분석 — 터널링 패턴 탐지"""
    pattern = re.compile(r'query: (\S+) IN (A|AAAA|TXT|MX|CNAME)')
    domain_counter: Counter = Counter()
    suspicious: list[tuple] = []

    for line in Path(log_path).read_text().splitlines():
        m = pattern.search(line)
        if not m:
            continue
        qname, qtype = m.group(1), m.group(2)
        parts = qname.rstrip('.').split('.')
        if not parts:
            continue

        subdomain = '.'.join(parts[:-2]) if len(parts) > 2 else ''
        domain = '.'.join(parts[-2:]) if len(parts) >= 2 else qname

        domain_counter[domain] += 1

        # 터널링 징후
        flags = []
        if len(subdomain) > 40:
            flags.append(f"긴 서브도메인({len(subdomain)}자)")
        if subdomain and shannon_entropy(subdomain) > 3.8:
            flags.append(f"높은 엔트로피({shannon_entropy(subdomain):.2f})")
        if qtype == "TXT" and subdomain:
            flags.append("TXT 쿼리 (데이터 반환 용도)")

        if flags:
            suspicious.append((qname, qtype, flags))

    print(f"\n[*] 상위 쿼리 도메인:")
    for domain, cnt in domain_counter.most_common(10):
        print(f"  {cnt:6d}회  {domain}")

    if suspicious:
        print(f"\n[!] 의심 DNS 쿼리 {len(suspicious)}건:")
        for qname, qtype, flags in suspicious[:20]:
            print(f"  [{qtype}] {qname[:80]}")
            for f in flags:
                print(f"       → {f}")

def main() -> None:
    parser = argparse.ArgumentParser(description="DNS 터널링 탐지")
    parser.add_argument("log", help="DNS 쿼리 로그 파일 (named.log 등)")
    args = parser.parse_args()
    analyze_dns_log(args.log)

if __name__ == "__main__":
    main()
```

---

## 5. Subdomain Takeover

```
발생 조건:
  1. DNS에 서브도메인 CNAME 레코드 존재
  2. CNAME이 가리키는 외부 서비스(S3, GitHub Pages, Heroku 등) 계정 삭제
  3. 공격자가 해당 외부 서비스에 동일 이름으로 계정 생성
  4. → 공격자가 피해자 도메인의 서브도메인 제어

취약한 서비스 예:
  *.s3.amazonaws.com
  *.github.io
  *.herokuapp.com
  *.azurewebsites.net
  *.cloudfront.net
```

```bash
# Subjack으로 서브도메인 탈취 취약점 자동 탐지
go install github.com/haccer/subjack@latest
subjack -w subdomains.txt -t 100 -timeout 30 \
  -o results.txt -ssl -c fingerprints.json

# nuclei 템플릿
nuclei -l subdomains.txt -t technologies/subdomain-takeover/

# 수동 확인
dig CNAME sub.example.com
curl -I https://sub.example.com
# NXDOMAIN 또는 404 + 외부 플랫폼 응답 → 탈취 가능
```

---

## 6. DNS 정보 수집 자동화

Python dnspython으로 DNS 정보 수집을 자동화합니다. 서브도메인 브루트포스, 레코드 타입별 조회, Zone Transfer 시도를 자동화합니다.

```python
import dns.resolver
import dns.zone
import dns.query
import socket
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]
COMMON_SUBS  = ["www", "mail", "ftp", "vpn", "dev", "staging",
                "api", "admin", "test", "beta", "shop", "blog",
                "remote", "portal", "git", "jenkins", "jira"]

def query_record(domain: str, rtype: str) -> list[str]:
    try:
        answers = dns.resolver.resolve(domain, rtype, lifetime=3)
        return [str(r) for r in answers]
    except Exception:
        return []

def try_axfr(domain: str, ns: str) -> list[str]:
    try:
        z = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=5))
        return [f"{n}.{domain}" for n in z.nodes.keys() if n != dns.name.empty]
    except Exception:
        return []

def bruteforce_subs(domain: str) -> list[str]:
    found = []
    def check(sub: str):
        fqdn = f"{sub}.{domain}"
        try:
            socket.gethostbyname(fqdn)
            return fqdn
        except socket.gaierror:
            return None

    with ThreadPoolExecutor(max_workers=30) as ex:
        futures = {ex.submit(check, s): s for s in COMMON_SUBS}
        for f in as_completed(futures):
            result = f.result()
            if result:
                found.append(result)
    return found

def recon(domain: str) -> None:
    print(f"\n{'='*50}")
    print(f"[*] DNS 정보 수집: {domain}")

    for rtype in RECORD_TYPES:
        records = query_record(domain, rtype)
        if records:
            print(f"\n  [{rtype}]")
            for r in records:
                print(f"    {r}")

    ns_records = query_record(domain, "NS")
    for ns in ns_records:
        ns_clean = ns.rstrip('.')
        print(f"\n[*] Zone Transfer 시도: {ns_clean}")
        records = try_axfr(domain, ns_clean)
        if records:
            print(f"[!] AXFR 성공! {len(records)}개 레코드")
            for r in records[:20]:
                print(f"    {r}")
        else:
            print("    → 차단됨")

    print(f"\n[*] 서브도메인 브루트포스")
    subs = bruteforce_subs(domain)
    for s in subs:
        print(f"  [발견] {s}")

def main() -> None:
    parser = argparse.ArgumentParser(description="DNS 정보 수집")
    parser.add_argument("domain")
    args = parser.parse_args()
    recon(args.domain)

if __name__ == "__main__":
    main()
```

---

<a name="english"></a>

# DNS Attack and Defense

## 1. DNS Fundamentals and Attack Surface

```
DNS Record Types:
  A      → Domain → IPv4
  AAAA   → Domain → IPv6
  MX     → Mail server
  NS     → Name server
  CNAME  → Alias
  TXT    → SPF, DKIM, DMARC, etc.
  SOA    → Zone authority information
  PTR    → Reverse lookup

Attack Surface:
  ┌─────────────────────────────────────────────┐
  │ Zone Transfer (AXFR) — Internal map leakage │
  │ DNS Cache Poisoning — Response forgery       │
  │ DNS Rebinding — SOP bypass                  │
  │ Subdomain Takeover — Delegation abuse       │
  │ DNS Tunneling — C2 communication hiding     │
  │ DNS Amplification — DDoS amplification      │
  └─────────────────────────────────────────────┘
```

---

## 2. Zone Transfer Attack (AXFR)

### 2-1. Zone Transfer Attempts

These are commands for testing DNS attack scenarios. They cover checking Zone Transfer vulnerabilities (`dig axfr`), subdomain enumeration, DNS cache status verification, and other fundamental DNS security inspection commands.

```bash
# Basic AXFR attempt
dig axfr example.com @ns1.example.com
dig axfr example.com @8.8.8.8

# host command
host -t axfr example.com ns1.example.com

# Detect zone transfer with nmap
nmap --script dns-zone-transfer --script-args \
  dns-zone-transfer.domain=example.com <ns-ip>

# fierce — auto-discovers NS servers then attempts AXFR
fierce --domain example.com
```

### 2-2. Information Collectable via Zone Transfer

```
Data obtained on success:
  - All subdomains (including internal servers)
  - Internal IP range mapping
  - Mail server and backup server locations
  - Development/staging environment domains
  - Administrator naming convention patterns

Example output:
  dev.example.com.        A    192.168.1.10
  staging.example.com.    A    192.168.1.20
  vpn.example.com.        A    203.0.113.5
  admin.example.com.      A    10.0.0.1
  mail.example.com.       MX   10 mail1.example.com.
```

### 2-3. Defense — Restricting Zone Transfers

This is the BIND DNS server security configuration. It restricts Zone Transfers to slave server IPs only, limits recursive queries to internal networks, and enables DNSSEC to defend against DNS spoofing.

```bash
# BIND named.conf — allow specific IPs only
zone "example.com" {
    type master;
    file "/etc/bind/db.example.com";
    allow-transfer { 192.168.1.2; };  # Allow slave NS only
    also-notify    { 192.168.1.2; };
};

# Global restriction (all zones)
options {
    allow-transfer { none; };  # Block by default
};

# Test
dig axfr example.com @ns1.example.com
# Transfer failed. → Correctly blocked
```

---

## 3. DNS Cache Poisoning (Kaminsky Attack)

```
Attack Principle:
  1. Attacker sends large volumes of queries for non-existent domains to the target resolver
  2. Injects forged responses before the authoritative NS can reply
  3. Predicts Transaction ID (16-bit) + source port (Birthday Attack)
  4. Stores forged records in cache → all users redirected to attacker's server

Kaminsky (2008) Improvement:
  - Forges glue records in NXDOMAIN responses
  - Can poison an entire zone's cache with a single query

Defense:
  □ Deploy DNSSEC (verify response signatures)
  □ Source port randomization (0~65535)
  □ 0x20 encoding (randomize case to increase transaction entropy)
  □ Keep BIND/Unbound updated to latest version
```

### DNSSEC Configuration (BIND)

This configures DNSSEC (DNS Security Extensions). It adds digital signatures to zones to ensure the integrity of DNS responses and prevent DNS spoofing.

```bash
# Generate zone signing keys
dnssec-keygen -a RSASHA256 -b 2048 -n ZONE example.com     # ZSK
dnssec-keygen -a RSASHA256 -b 4096 -n ZONE -f KSK example.com  # KSK

# Sign zone file
dnssec-signzone -A -3 $(head -c 16 /dev/urandom | xxd -p) \
  -N INCREMENT -o example.com -t db.example.com

# Use signed zone in named.conf
zone "example.com" {
    type master;
    file "/etc/bind/db.example.com.signed";
    auto-dnssec maintain;
    inline-signing yes;
};

# Register DS record with upstream registrar
dnssec-dsfromkey Kexample.com.+008+XXXXX.key
```

---

## 4. DNS Tunneling (Covert C2 Communication)

```
Principle:
  Encode data inside DNS queries/responses to bypass firewalls
  Attacker directly operates the authoritative NS for their domain (attacker.com)

Data Flow:
  Victim → query [base32-encoded data].attacker.com → Attacker's NS
  Attacker's NS → encode commands in TXT records → respond to victim

Common Tools:
  iodine   — IP over DNS
  dnscat2  — C2 channel
  dns2tcp  — TCP over DNS
```

### DNS Tunneling Detection and Blocking

This is a Python script that detects DNS tunneling. It monitors for abnormally long DNS queries, high query frequency, and non-standard record types.

```python
import dns.resolver
import re
import argparse
from collections import Counter
from pathlib import Path

# DNS tunneling indicators: very long subdomains, high entropy, abnormal frequency
def shannon_entropy(s: str) -> float:
    from math import log2
    freq = Counter(s.lower())
    total = len(s)
    return -sum((c/total) * log2(c/total) for c in freq.values())

def analyze_dns_log(log_path: str) -> None:
    """Analyze DNS query logs — detect tunneling patterns"""
    pattern = re.compile(r'query: (\S+) IN (A|AAAA|TXT|MX|CNAME)')
    domain_counter: Counter = Counter()
    suspicious: list[tuple] = []

    for line in Path(log_path).read_text().splitlines():
        m = pattern.search(line)
        if not m:
            continue
        qname, qtype = m.group(1), m.group(2)
        parts = qname.rstrip('.').split('.')
        if not parts:
            continue

        subdomain = '.'.join(parts[:-2]) if len(parts) > 2 else ''
        domain = '.'.join(parts[-2:]) if len(parts) >= 2 else qname

        domain_counter[domain] += 1

        # Tunneling indicators
        flags = []
        if len(subdomain) > 40:
            flags.append(f"Long subdomain ({len(subdomain)} chars)")
        if subdomain and shannon_entropy(subdomain) > 3.8:
            flags.append(f"High entropy ({shannon_entropy(subdomain):.2f})")
        if qtype == "TXT" and subdomain:
            flags.append("TXT query (used for data exfiltration)")

        if flags:
            suspicious.append((qname, qtype, flags))

    print(f"\n[*] Top queried domains:")
    for domain, cnt in domain_counter.most_common(10):
        print(f"  {cnt:6d} times  {domain}")

    if suspicious:
        print(f"\n[!] {len(suspicious)} suspicious DNS queries:")
        for qname, qtype, flags in suspicious[:20]:
            print(f"  [{qtype}] {qname[:80]}")
            for f in flags:
                print(f"       → {f}")

def main() -> None:
    parser = argparse.ArgumentParser(description="DNS Tunneling Detection")
    parser.add_argument("log", help="DNS query log file (named.log, etc.)")
    args = parser.parse_args()
    analyze_dns_log(args.log)

if __name__ == "__main__":
    main()
```

---

## 5. Subdomain Takeover

```
Conditions for Occurrence:
  1. A subdomain CNAME record exists in DNS
  2. The external service account (S3, GitHub Pages, Heroku, etc.) the CNAME points to is deleted
  3. Attacker creates an account on that external service with the same name
  4. → Attacker gains control of the victim's subdomain

Examples of Vulnerable Services:
  *.s3.amazonaws.com
  *.github.io
  *.herokuapp.com
  *.azurewebsites.net
  *.cloudfront.net
```

```bash
# Auto-detect subdomain takeover vulnerabilities with Subjack
go install github.com/haccer/subjack@latest
subjack -w subdomains.txt -t 100 -timeout 30 \
  -o results.txt -ssl -c fingerprints.json

# nuclei templates
nuclei -l subdomains.txt -t technologies/subdomain-takeover/

# Manual verification
dig CNAME sub.example.com
curl -I https://sub.example.com
# NXDOMAIN or 404 + external platform response → takeover possible
```

---

## 6. Automated DNS Reconnaissance

This automates DNS information gathering using Python dnspython. It automates subdomain brute-forcing, record type querying, and Zone Transfer attempts.

```python
import dns.resolver
import dns.zone
import dns.query
import socket
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]
COMMON_SUBS  = ["www", "mail", "ftp", "vpn", "dev", "staging",
                "api", "admin", "test", "beta", "shop", "blog",
                "remote", "portal", "git", "jenkins", "jira"]

def query_record(domain: str, rtype: str) -> list[str]:
    try:
        answers = dns.resolver.resolve(domain, rtype, lifetime=3)
        return [str(r) for r in answers]
    except Exception:
        return []

def try_axfr(domain: str, ns: str) -> list[str]:
    try:
        z = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=5))
        return [f"{n}.{domain}" for n in z.nodes.keys() if n != dns.name.empty]
    except Exception:
        return []

def bruteforce_subs(domain: str) -> list[str]:
    found = []
    def check(sub: str):
        fqdn = f"{sub}.{domain}"
        try:
            socket.gethostbyname(fqdn)
            return fqdn
        except socket.gaierror:
            return None

    with ThreadPoolExecutor(max_workers=30) as ex:
        futures = {ex.submit(check, s): s for s in COMMON_SUBS}
        for f in as_completed(futures):
            result = f.result()
            if result:
                found.append(result)
    return found

def recon(domain: str) -> None:
    print(f"\n{'='*50}")
    print(f"[*] DNS Reconnaissance: {domain}")

    for rtype in RECORD_TYPES:
        records = query_record(domain, rtype)
        if records:
            print(f"\n  [{rtype}]")
            for r in records:
                print(f"    {r}")

    ns_records = query_record(domain, "NS")
    for ns in ns_records:
        ns_clean = ns.rstrip('.')
        print(f"\n[*] Zone Transfer attempt: {ns_clean}")
        records = try_axfr(domain, ns_clean)
        if records:
            print(f"[!] AXFR successful! {len(records)} records")
            for r in records[:20]:
                print(f"    {r}")
        else:
            print("    → Blocked")

    print(f"\n[*] Subdomain brute-force")
    subs = bruteforce_subs(domain)
    for s in subs:
        print(f"  [Found] {s}")

def main() -> None:
    parser = argparse.ArgumentParser(description="DNS Reconnaissance")
    parser.add_argument("domain")
    args = parser.parse_args()
    recon(args.domain)

if __name__ == "__main__":
    main()
```
