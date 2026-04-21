# OSINT — 위협 인텔리전스를 위한 오픈소스 정보 수집

## 1. OSINT 수집 체계

```
OSINT 소스:
  ┌──────────────────────────────────────────┐
  │ 인터넷 스캔 데이터: Shodan, Censys, FOFA │
  │ 패시브 DNS: PassiveTotal, SecurityTrails  │
  │ 악성코드 DB: VirusTotal, MalwareBazaar    │
  │ 다크웹 포럼: Tor 기반 인텔리전스 피드      │
  │ 소셜 미디어: Twitter/X, Telegram 채널     │
  │ 코드 저장소: GitHub, GitLab 유출 정보     │
  │ 인증서 투명성: crt.sh, Censys             │
  └──────────────────────────────────────────┘
```

---

## 2. Shodan — 인터넷 노출 자산 탐색

Shodan CLI로 인터넷에 노출된 기기와 서비스를 탐색합니다. 특정 취약점을 가진 서버, 기본 비밀번호를 사용하는 장치 등을 검색합니다.

```bash
# Shodan CLI 설치
pip install shodan
shodan init YOUR_API_KEY

# 기본 검색
shodan search "apache 2.4"
shodan search 'product:"Apache httpd" port:443 country:"KR"'

# 특정 취약점 노출 자산
shodan search 'vuln:CVE-2021-44228'   # Log4Shell
shodan search 'vuln:CVE-2024-21762'   # Fortinet RCE

# 조직별 노출 자산
shodan search 'org:"Company Name"'
shodan search 'ssl.cert.subject.cn:"*.example.com"'

# IP 정보
shodan host 203.0.113.5

# 도메인의 서브도메인 열거
shodan domain example.com

# Cobalt Strike C2 탐지 (Beacon 설정 특징)
shodan search 'product:"Cobalt Strike Beacon"'
shodan search 'ssl.jarm:07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1'
```

Shodan API로 Cobalt Strike C2 서버를 탐지합니다. 비콘 설정의 특징적인 응답 패턴으로 악성 인프라를 식별합니다.

```python
import shodan
import argparse
import json

def scan_org_exposure(api_key: str, org: str) -> None:
    api = shodan.Shodan(api_key)
    try:
        results = api.search(f'org:"{org}"', limit=100)
        print(f"[*] {org} — 노출 자산 {results['total']}개")

        port_count: dict[int, int] = {}
        cve_count:  dict[str, int] = {}
        services:   list[dict]    = []

        for match in results["matches"]:
            port = match["port"]
            port_count[port] = port_count.get(port, 0) + 1

            for vuln in match.get("vulns", {}).keys():
                cve_count[vuln] = cve_count.get(vuln, 0) + 1

            services.append({
                "ip":      match["ip_str"],
                "port":    port,
                "product": match.get("product", ""),
                "version": match.get("version", ""),
            })

        print("\n상위 노출 포트:")
        for port, cnt in sorted(port_count.items(), key=lambda x: -x[1])[:10]:
            print(f"  {port:5d}/tcp — {cnt}개")

        if cve_count:
            print("\n발견된 CVE:")
            for cve, cnt in sorted(cve_count.items(), key=lambda x: -x[1])[:10]:
                print(f"  {cve} — {cnt}개 자산")

    except shodan.APIError as e:
        print(f"오류: {e}")

def main() -> None:
    parser = argparse.ArgumentParser(description="Shodan 조직 노출 분석")
    parser.add_argument("--key", required=True)
    parser.add_argument("--org", required=True)
    args = parser.parse_args()
    scan_org_exposure(args.key, args.org)

if __name__ == "__main__":
    main()
```

---

## 3. 패시브 DNS 및 인증서 투명성

패시브 DNS와 인증서 투명성(CT) 로그를 활용하여 도메인 히스토리와 서브도메인을 수집합니다. SecurityTrails, Censys 등 서비스를 활용합니다.

```bash
# SecurityTrails — 패시브 DNS, 서브도메인 이력
curl -H "apikey: YOUR_KEY" \
  "https://api.securitytrails.com/v1/domain/example.com/subdomains"

# crt.sh — 인증서 투명성으로 서브도메인 발견
curl "https://crt.sh/?q=%.example.com&output=json" \
  | jq '.[].name_value' | sort -u

# Amass — 종합 서브도메인 열거
amass enum -d example.com -passive -o subs.txt
amass enum -d example.com -active -brute -min-for-recursive 2

# theHarvester — 이메일/도메인/IP 종합 수집
theHarvester -d example.com -b all -f results.html
```

```python
import requests
import json
import re
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed

def crtsh_subdomains(domain: str) -> set[str]:
    try:
        resp = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=15
        )
        entries = resp.json()
        subs = set()
        for entry in entries:
            for name in entry.get("name_value", "").split("\n"):
                name = name.strip().lstrip("*.")
                if name.endswith(domain) and name != domain:
                    subs.add(name)
        return subs
    except Exception as e:
        print(f"crt.sh 오류: {e}")
        return set()

def securitytrails_subdomains(domain: str, api_key: str) -> set[str]:
    try:
        resp = requests.get(
            f"https://api.securitytrails.com/v1/domain/{domain}/subdomains",
            headers={"apikey": api_key},
            timeout=10
        )
        data = resp.json()
        return {f"{s}.{domain}" for s in data.get("subdomains", [])}
    except Exception as e:
        print(f"SecurityTrails 오류: {e}")
        return set()

def passive_dns_lookup(domain: str, api_key: str = "") -> set[str]:
    results: set[str] = set()
    results |= crtsh_subdomains(domain)
    if api_key:
        results |= securitytrails_subdomains(domain, api_key)
    return results

def main() -> None:
    parser = argparse.ArgumentParser(description="패시브 DNS 서브도메인 수집")
    parser.add_argument("domain")
    parser.add_argument("--st-key", default="", help="SecurityTrails API 키")
    args = parser.parse_args()

    print(f"[*] {args.domain} 서브도메인 수집 중...")
    subs = passive_dns_lookup(args.domain, args.st_key)
    print(f"[+] {len(subs)}개 발견:")
    for s in sorted(subs):
        print(f"  {s}")

if __name__ == "__main__":
    main()
```

---

## 4. 악성코드 데이터베이스 활용

```bash
# MalwareBazaar — 악성코드 샘플 수집
curl -X POST https://mb-api.abuse.ch/api/v1/ \
  -d "query=get_recent&selector=time" | jq '.data[:5]'

# URLhaus — 악성 URL 피드
curl https://urlhaus-api.abuse.ch/v1/urls/recent/ \
  | jq '.urls[] | select(.tags | contains(["Cobalt Strike"]))'

# ThreatFox — IOC 피드
curl -X POST https://threatfox-api.abuse.ch/api/v1/ \
  -H "Content-Type: application/json" \
  -d '{"query":"get_iocs","days":1}'
```

ThreatFox API로 최신 IOC 피드를 수집합니다. IP, 도메인, URL, 해시 등의 IOC를 자동으로 가져와 방어 시스템에 적용합니다.

```python
import requests
import argparse

ABUSE_CH_IOC_FEEDS = {
    "threatfox": "https://threatfox-api.abuse.ch/api/v1/",
    "urlhaus":   "https://urlhaus-api.abuse.ch/v1/",
    "bazaar":    "https://mb-api.abuse.ch/api/v1/",
}

def get_recent_iocs(days: int = 1) -> list[dict]:
    resp = requests.post(
        ABUSE_CH_IOC_FEEDS["threatfox"],
        json={"query": "get_iocs", "days": days},
        timeout=15
    )
    data = resp.json()
    return data.get("data", [])

def check_hash(sha256: str) -> dict:
    resp = requests.post(
        ABUSE_CH_IOC_FEEDS["bazaar"],
        data={"query": "get_info", "hash": sha256},
        timeout=10
    )
    return resp.json()

def check_url(url: str) -> dict:
    resp = requests.post(
        ABUSE_CH_IOC_FEEDS["urlhaus"],
        data={"url": url},
        timeout=10
    )
    return resp.json()

def main() -> None:
    parser = argparse.ArgumentParser(description="abuse.ch IOC 조회")
    parser.add_argument("--recent-iocs", type=int, metavar="DAYS")
    parser.add_argument("--hash")
    parser.add_argument("--url")
    args = parser.parse_args()

    if args.recent_iocs:
        iocs = get_recent_iocs(args.recent_iocs)
        print(f"[+] 최근 {args.recent_iocs}일 IOC {len(iocs)}건")
        for ioc in iocs[:10]:
            print(f"  [{ioc.get('ioc_type')}] {ioc.get('ioc')} — {ioc.get('malware')}")

    if args.hash:
        result = check_hash(args.hash)
        print(f"[해시] {args.hash}: {result.get('query_status')}")
        if result.get("data"):
            d = result["data"][0]
            print(f"  악성코드: {d.get('signature')}, 태그: {d.get('tags')}")

    if args.url:
        result = check_url(args.url)
        print(f"[URL] {args.url}: {result.get('query_status')}")

if __name__ == "__main__":
    main()
```

---

## 5. C2 인프라 추적

Cobalt Strike, Metasploit 등 C2 프레임워크의 특징적인 네트워크 패턴을 분석합니다. Malleable C2 프로필과 비콘 응답으로 공격 인프라를 추적합니다.

```bash
# Cobalt Strike Beacon 프로파일 분석
# JARM 핑거프린트로 C2 서버 식별
pip install jarm

# 특정 IP JARM 측정
python3 jarm.py 203.0.113.5 443

# Shodan에서 알려진 JARM으로 검색
# Cobalt Strike: 07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1
shodan search "ssl.jarm:07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1"

# Metasploit C2: 07d14d16d21d21d00042d43d00041d2aa5ce6a70de7ba95aef77a77b00a0af
# Covenant: 29d29d15d29d29d21c29d29d29d29dea1d44b09b7b1b1b1e6b0a0b1b2b3b4b5
```

```python
import asyncio
import ssl
import hashlib
import struct
import argparse

async def jarm_fingerprint(host: str, port: int) -> str:
    """간략화된 JARM 핑거프린트 (실전에서는 jarm 라이브러리 사용)"""
    fingerprints = []
    tls_versions = [
        ssl.TLSVersion.TLSv1_2,
        ssl.TLSVersion.TLSv1_3,
    ]
    for ver in tls_versions:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.minimum_version = ver
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx), timeout=5
            )
            cert = writer.get_extra_info("ssl_object").getpeercert(binary_form=True)
            fp = hashlib.sha256(cert).hexdigest()[:16] if cert else "0" * 16
            fingerprints.append(fp)
            writer.close()
        except Exception:
            fingerprints.append("0" * 16)

    return "|".join(fingerprints)

async def scan_c2_candidates(ips: list[str]) -> None:
    KNOWN_C2_JARMS = {
        "07d14d16d21d21d0": "Cobalt Strike",
        "29d29d15d29d29d2": "Covenant",
    }
    for ip in ips:
        fp = await jarm_fingerprint(ip, 443)
        label = "알 수 없음"
        for sig, name in KNOWN_C2_JARMS.items():
            if sig in fp:
                label = f"[!] {name} C2 의심"
                break
        print(f"  {ip}: {fp[:32]}... — {label}")

def main() -> None:
    parser = argparse.ArgumentParser(description="C2 인프라 탐지")
    parser.add_argument("ips", nargs="+", help="조사할 IP 목록")
    args = parser.parse_args()
    asyncio.run(scan_c2_candidates(args.ips))

if __name__ == "__main__":
    main()
```

---

## 6. 다크웹 인텔리전스 (합법적 수집)

```
접근 방법:
  Tor Browser → 다크웹 포럼/마켓 모니터링
  합법적 CTI 서비스: Recorded Future, Intel 471, Flashpoint

주요 모니터링 대상:
  - 자사 크레덴셜 판매 게시물
  - 자사 인프라 취약점 판매
  - 타깃 공격 예고
  - 신규 익스플로잇 킷 거래

자동화 (Tor 경유 크롤링):
```

Tor 프록시를 통해 다크웹에서 위협 인텔리전스를 합법적으로 수집합니다. 유출된 자격증명이나 조직 관련 데이터를 모니터링합니다.

```python
import requests
import argparse

def search_via_tor(query: str, timeout: int = 30) -> str:
    """Tor SOCKS5 프록시 경유 검색 (Tor 데몬 실행 필요)"""
    proxies = {
        "http":  "socks5h://127.0.0.1:9050",
        "https": "socks5h://127.0.0.1:9050",
    }
    # Ahmia.fi — 다크웹 검색엔진 (합법적 서비스)
    resp = requests.get(
        "https://ahmia.fi/search/",
        params={"q": query},
        proxies=proxies,
        timeout=timeout
    )
    return resp.text

def check_credential_leak(email_domain: str) -> None:
    """Have I Been Pwned API로 도메인 크레덴셜 유출 확인"""
    resp = requests.get(
        f"https://haveibeenpwned.com/api/v3/breachesaccount/{email_domain}",
        headers={"hibp-api-key": "YOUR_API_KEY"},
        timeout=10
    )
    if resp.status_code == 200:
        breaches = resp.json()
        print(f"[!] {email_domain} 유출 이력 {len(breaches)}건:")
        for b in breaches:
            print(f"  {b['Name']} ({b['BreachDate']}) — {', '.join(b['DataClasses'][:3])}")
    elif resp.status_code == 404:
        print(f"[+] {email_domain} 유출 이력 없음")

def main() -> None:
    parser = argparse.ArgumentParser(description="다크웹 및 크레덴셜 인텔리전스")
    parser.add_argument("--domain", help="유출 확인할 도메인")
    args = parser.parse_args()
    if args.domain:
        check_credential_leak(args.domain)

if __name__ == "__main__":
    main()
```
