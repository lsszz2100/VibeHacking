> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 버그바운티 CTF 실습 랩: 직접 해보는 취약점 탐지

## 이 랩을 사용하는 방법

이 문서는 실제 버그바운티 시나리오를 모방한 3개의 실습 문제를 제공합니다. 각 실습은 Docker 환경에서 실행 가능하며, 목표 → 힌트 → 상세 풀이 순서로 구성되어 있습니다.

**주의**: 모든 실습은 본인이 직접 만들고 통제하는 환경에서만 수행하세요. 실제 서비스에 무단으로 테스트하는 것은 불법입니다.

---

## 실습 환경 구성 (Docker)

```bash
# 전체 랩 환경 구성
# 아래 docker-compose.yml을 생성한 후 실행
docker compose up -d

# 서비스 확인
docker compose ps

# 랩 종료
docker compose down -v
```

```yaml
# docker-compose.yml
version: "3.9"

services:
  # 실습 1: 서브도메인 테이크오버 모의 환경
  subdomain-takeover-lab:
    image: nginx:alpine
    container_name: subdomain_lab
    ports:
      - "8081:80"
    volumes:
      - ./lab1_config/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./lab1_config/html:/usr/share/nginx/html:ro

  # 실습 2: Nuclei 스캔 대상 취약한 앱
  vulnerable-app:
    image: python:3.11-slim
    container_name: vuln_app
    ports:
      - "8082:8000"
    volumes:
      - ./lab2_app:/app
    working_dir: /app
    command: python server.py
    environment:
      - FLASK_ENV=development

  # 실습 3: IDOR 취약한 REST API
  idor-api:
    image: python:3.11-slim
    container_name: idor_api
    ports:
      - "8083:8000"
    volumes:
      - ./lab3_api:/app
    working_dir: /app
    command: python api.py

  # 공통 데이터베이스
  db:
    image: postgres:15-alpine
    container_name: lab_db
    environment:
      POSTGRES_DB: labdb
      POSTGRES_USER: labuser
      POSTGRES_PASSWORD: labpass123
    volumes:
      - lab_db_data:/var/lib/postgresql/data
      - ./init.sql:/docker-entrypoint-initdb.d/init.sql

volumes:
  lab_db_data:
```

### Docker 실습 앱 소스코드 설정

```python
# lab2_app/server.py — 실습 2용 취약한 Flask 앱
"""
의도적으로 취약하게 만든 실습용 앱입니다.
절대 실제 서비스에 배포하지 마세요.
"""
import os
from flask import Flask, request, jsonify

app = Flask(__name__)

# 취약점 1: Debug 모드 활성화 → /console 엔드포인트 노출
# 취약점 2: 버전 정보 노출 헤더
# 취약점 3: 취약한 서버사이드 템플릿 (SSTI)
# 취약점 4: 에러 메시지에 스택 트레이스 노출

@app.after_request
def add_security_headers(response):
    # 의도적으로 보안 헤더 미설정 (취약점)
    response.headers['X-Powered-By'] = 'Python/3.11 Flask/2.3'
    response.headers['Server'] = 'Werkzeug/2.3.0'
    return response

@app.route('/search')
def search():
    query = request.args.get('q', '')
    # 취약점: SQL Injection (실습 목적)
    import sqlite3
    conn = sqlite3.connect(':memory:')
    conn.execute("CREATE TABLE products (id INTEGER, name TEXT)")
    conn.execute("INSERT INTO products VALUES (1, 'Widget'), (2, 'Gadget')")
    try:
        results = conn.execute(f"SELECT * FROM products WHERE name LIKE '%{query}%'").fetchall()
        return jsonify({"results": results})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@app.route('/health')
def health():
    return jsonify({
        "status": "ok",
        "version": "1.0.0",
        "debug": app.debug,
        "env": dict(os.environ)  # 취약점: 환경변수 노출
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=True)
```

```python
# lab3_api/api.py — 실습 3용 IDOR 취약한 API
"""
의도적으로 취약하게 만든 IDOR 실습 API입니다.
"""
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

# 실습용 가짜 데이터베이스
USERS = {
    "1": {"id": 1, "name": "Alice", "email": "alice@example.com", "ssn": "123-45-6789"},
    "2": {"id": 2, "name": "Bob",   "email": "bob@example.com",   "ssn": "987-65-4321"},
    "3": {"id": 3, "name": "Carol", "email": "carol@example.com", "ssn": "111-22-3333"},
}

ORDERS = {
    "101": {"id": 101, "user_id": 1, "item": "Widget", "price": 29.99},
    "102": {"id": 102, "user_id": 2, "item": "Gadget", "price": 49.99},
    "103": {"id": 103, "user_id": 1, "item": "Doohickey", "price": 9.99},
}


class IDORHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # 로그 억제

    def send_json(self, data: dict, status: int = 200) -> None:
        body = json.dumps(data, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        parts = parsed.path.strip("/").split("/")

        # GET /api/users/<id>
        if len(parts) == 3 and parts[0] == "api" and parts[1] == "users":
            user_id = parts[2]
            # 취약점: 인증/권한 검사 없이 user_id만으로 데이터 반환 (IDOR)
            user = USERS.get(user_id)
            if user:
                self.send_json(user)
            else:
                self.send_json({"error": "User not found"}, 404)

        # GET /api/orders/<id>
        elif len(parts) == 3 and parts[0] == "api" and parts[1] == "orders":
            order_id = parts[2]
            # 취약점: 요청자가 해당 주문의 소유자인지 확인하지 않음 (IDOR)
            order = ORDERS.get(order_id)
            if order:
                self.send_json(order)
            else:
                self.send_json({"error": "Order not found"}, 404)

        else:
            self.send_json({"error": "Not found"}, 404)


if __name__ == '__main__':
    server = HTTPServer(('0.0.0.0', 8000), IDORHandler)
    print("IDOR 실습 API 시작: http://localhost:8000")
    server.serve_forever()
```

---

## 실습 1: 서브도메인 테이크오버 탐지

### 목표
`staging.example-lab.com`이 더 이상 존재하지 않는 외부 서비스를 CNAME으로 가리키고 있습니다. 이를 탐지하고, 테이크오버가 가능한지 확인하세요.

### 배경 지식
서브도메인 테이크오버(Subdomain Takeover)는 다음과 같이 발생합니다:
1. 기업이 `cdn.example.com CNAME someservice.third-party.io`를 설정
2. `someservice.third-party.io` 계정을 삭제하거나 만료
3. 공격자가 third-party에서 같은 이름으로 새 계정 생성 → `cdn.example.com` 탈취

### 힌트
```
힌트 1: CNAME 체인을 확인하세요. dig cdn.example.com CNAME
힌트 2: 최종 CNAME 목적지가 "NoSuchBucket", "There is no app here" 같은 메시지를 반환하는지 확인
힌트 3: 취약한 제3자 서비스 목록: https://github.com/EdOverflow/can-i-take-over-xyz
```

### 자동 탐지 코드

```python
#!/usr/bin/env python3
"""
subdomain_takeover.py — 서브도메인 테이크오버 취약점 탐지

사용법:
    python subdomain_takeover.py -l subdomains.txt
    python subdomain_takeover.py -d example.com --check-cname
"""

from __future__ import annotations

import argparse
import socket
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path


# 테이크오버 가능한 서비스의 특징적인 응답 문자열
FINGERPRINTS: dict[str, list[str]] = {
    "AWS S3": ["NoSuchBucket", "The specified bucket does not exist"],
    "GitHub Pages": ["There isn't a GitHub Pages site here"],
    "Heroku": ["No such app", "herokucdn.com/error-pages/no-such-app.html"],
    "Shopify": ["Sorry, this shop is currently unavailable"],
    "Fastly": ["Fastly error: unknown domain"],
    "Pantheon": ["404 error unknown site"],
    "Ghost": ["The thing you were looking for is no longer here"],
    "Tumblr": ["Whatever you were looking for doesn't live here anymore"],
    "Zendesk": ["Help Center Closed"],
    "Surge.sh": ["project not found"],
    "Readme.io": ["Project doesnt exist"],
}


@dataclass
class TakeoverResult:
    subdomain: str
    cname: str = ""
    service: str = ""
    vulnerable: bool = False
    fingerprint: str = ""
    error: str = ""


def get_cname(hostname: str) -> str:
    """DNS CNAME 레코드를 조회합니다."""
    try:
        result = subprocess.run(
            ["dig", "+short", "CNAME", hostname],
            capture_output=True,
            text=True,
            timeout=10,
        )
        cname = result.stdout.strip().rstrip(".")
        return cname
    except (subprocess.TimeoutExpired, FileNotFoundError):
        try:
            # dig가 없는 경우 nslookup 시도
            result = subprocess.run(
                ["nslookup", "-type=CNAME", hostname],
                capture_output=True, text=True, timeout=10,
            )
            for line in result.stdout.splitlines():
                if "canonical name" in line.lower():
                    return line.split("=")[-1].strip().rstrip(".")
        except Exception:
            pass
    return ""


def check_dns_resolution(hostname: str) -> bool:
    """호스트가 DNS로 해석되는지 확인합니다."""
    try:
        socket.gethostbyname(hostname)
        return True
    except socket.gaierror:
        return False


def check_http_fingerprint(url: str) -> tuple[str, str]:
    """
    HTTP 응답에서 테이크오버 가능 서비스의 지문을 확인합니다.

    Returns:
        (서비스 이름, 매칭된 지문) 또는 ("", "")
    """
    for scheme in ["https", "http"]:
        try:
            full_url = f"{scheme}://{url}" if not url.startswith("http") else url
            req = urllib.request.Request(
                full_url,
                headers={"User-Agent": "Mozilla/5.0"},
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                body = resp.read(4096).decode("utf-8", errors="ignore")
                for service, patterns in FINGERPRINTS.items():
                    for pattern in patterns:
                        if pattern.lower() in body.lower():
                            return service, pattern
        except urllib.error.HTTPError as exc:
            body = exc.read(4096).decode("utf-8", errors="ignore")
            for service, patterns in FINGERPRINTS.items():
                for pattern in patterns:
                    if pattern.lower() in body.lower():
                        return service, pattern
        except Exception:
            continue
    return "", ""


def analyze_subdomain(subdomain: str) -> TakeoverResult:
    """단일 서브도메인의 테이크오버 취약성을 분석합니다."""
    result = TakeoverResult(subdomain=subdomain)
    subdomain = subdomain.strip()

    # CNAME 확인
    cname = get_cname(subdomain)
    if not cname:
        return result  # CNAME 없음 → 테이크오버 대상 아님

    result.cname = cname

    # DNS 해석 불가 → 잠재적 테이크오버
    if not check_dns_resolution(cname):
        result.vulnerable = True
        result.error = f"CNAME {cname}이 DNS로 해석되지 않음 (댕글링 DNS)"
        return result

    # HTTP 지문 확인
    service, fingerprint = check_http_fingerprint(subdomain)
    if service:
        result.service = service
        result.fingerprint = fingerprint
        result.vulnerable = True

    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="서브도메인 테이크오버 탐지")
    parser.add_argument("-l", "--list", help="서브도메인 목록 파일")
    parser.add_argument("-d", "--domain", help="단일 서브도메인")
    parser.add_argument("-o", "--output", help="결과 파일 (기본: 화면 출력)")
    args = parser.parse_args()

    subdomains: list[str] = []
    if args.list:
        path = Path(args.list)
        if not path.exists():
            print(f"오류: 파일 없음 {path}")
            sys.exit(1)
        subdomains = [l.strip() for l in path.read_text().splitlines() if l.strip()]
    elif args.domain:
        subdomains = [args.domain]
    else:
        parser.error("-l 또는 -d 옵션이 필요합니다.")

    print(f"총 {len(subdomains)}개 서브도메인 분석 중...\n")
    vulnerable_count = 0

    for sub in subdomains:
        result = analyze_subdomain(sub)
        if result.cname:
            status = "[취약]" if result.vulnerable else "[안전]"
            print(f"{status} {sub} → CNAME: {result.cname}")
            if result.vulnerable:
                vulnerable_count += 1
                if result.service:
                    print(f"       서비스: {result.service}")
                    print(f"       지문:   {result.fingerprint}")
                if result.error:
                    print(f"       오류:   {result.error}")

    print(f"\n결과: {vulnerable_count}/{len(subdomains)} 취약 가능성 있음")


if __name__ == "__main__":
    main()
```

### 풀이
```
1. subfinder로 example-lab.com 서브도메인 열거
2. python subdomain_takeover.py -l subdomains.txt 실행
3. CNAME이 존재하지만 DNS 해석 안 되는 서브도메인 찾기
4. 해당 서비스(GitHub Pages, S3 등)에서 같은 이름으로 생성 가능한지 확인
5. 리포트 작성: 영향 = 피싱/세션 쿠키 탈취/악성코드 배포 가능
```

---

## 실습 2: Nuclei로 취약한 엔드포인트 발견

### 목표
`http://localhost:8082`에서 실행 중인 취약한 앱에서 Nuclei와 커스텀 템플릿을 사용하여 취약점을 발견하세요.

### 힌트
```
힌트 1: /health 엔드포인트에서 무엇이 노출되나요?
힌트 2: /search?q= 파라미터에 SQL 특수문자를 넣어보세요
힌트 3: nuclei -u http://localhost:8082 -tags debug,exposure,sqli
```

### 실습 명령어

```bash
# 기본 Nuclei 스캔
nuclei -u http://localhost:8082 -severity info,low,medium,high,critical

# 특정 태그만
nuclei -u http://localhost:8082 -tags debug,exposure,config

# 커스텀 템플릿 적용
nuclei -u http://localhost:8082 -t ./custom_templates/

# 결과를 JSON으로 저장
nuclei -u http://localhost:8082 -json -o lab2_results.json
```

### 커스텀 템플릿 작성

```yaml
# custom_templates/env-disclosure.yaml
id: environment-variable-disclosure

info:
  name: Environment Variables Disclosed via /health
  severity: high
  description: |
    /health 엔드포인트에서 서버 환경변수가 노출됩니다.
    API 키, 데이터베이스 비밀번호 등이 포함될 수 있습니다.
  tags: exposure,config,misconfig

http:
  - method: GET
    path:
      - "{{BaseURL}}/health"

    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200

      - type: word
        words:
          - "\"env\""
          - "PATH"
        part: body
        condition: and
```

### 풀이
```
취약점 1: /health에서 환경변수 노출 → Severity: High
취약점 2: /search의 SQL Injection → Severity: High
취약점 3: Debug 모드 활성화 → /console 접근 가능 → Severity: Critical
취약점 4: 보안 헤더 미설정 (X-Frame-Options, CSP) → Severity: Info/Low
```

---

## 실습 3: IDOR 취약점 탐지 자동화

### 목표
`http://localhost:8083`의 REST API에서 IDOR 취약점을 발견하고, Python 코드로 자동화하세요.

### 힌트
```
힌트 1: GET /api/users/1 에 인증 없이 접근해보세요
힌트 2: user_id를 1부터 10까지 바꿔가며 요청해보세요
힌트 3: 응답에 어떤 민감한 정보가 포함되어 있나요?
```

### IDOR 자동 탐지 코드

```python
#!/usr/bin/env python3
"""
idor_detector.py — IDOR 취약점 자동 탐지

사용법:
    python idor_detector.py -u http://localhost:8083/api/users/FUZZ --range 1-20
    python idor_detector.py -u http://localhost:8083/api/orders/FUZZ --range 100-110
    python idor_detector.py -u http://target.com/api -c config.json
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any


FUZZ_MARKER = "FUZZ"

# 응답에서 PII(개인식별정보)를 나타내는 키 패턴
PII_KEYS = {
    "ssn", "social_security", "password", "passwd", "secret",
    "token", "credit_card", "card_number", "cvv", "dob", "birth",
    "passport", "license", "bank_account", "routing_number",
}

# 민감한 정보를 나타내는 응답 패턴
SENSITIVE_PATTERNS = [
    r"\d{3}-\d{2}-\d{4}",  # SSN 패턴
    r"\d{4}[- ]\d{4}[- ]\d{4}[- ]\d{4}",  # 신용카드 패턴
]


@dataclass
class IDORFinding:
    id_value: str
    url: str
    status_code: int
    response_body: dict[str, Any]
    pii_keys_found: list[str]
    is_idor: bool
    notes: str = ""


def fetch_resource(url: str, auth_cookie: str = "") -> tuple[int, dict | None]:
    """
    URL에 GET 요청을 보내고 (상태코드, JSON 파싱 결과)를 반환합니다.
    """
    headers: dict[str, str] = {"User-Agent": "Mozilla/5.0"}
    if auth_cookie:
        headers["Cookie"] = auth_cookie

    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read().decode("utf-8", errors="ignore")
            try:
                return resp.status, json.loads(body)
            except json.JSONDecodeError:
                return resp.status, {"raw": body}
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read().decode("utf-8", errors="ignore")
            return exc.code, json.loads(body) if body else None
        except Exception:
            return exc.code, None
    except Exception:
        return -1, None


def detect_pii_in_response(body: dict) -> list[str]:
    """
    응답 본문에서 PII 가능성이 있는 키를 탐지합니다.

    Args:
        body: JSON 파싱된 응답 딕셔너리

    Returns:
        PII 관련 키 목록
    """
    found: list[str] = []

    def _check(obj: Any, path: str = "") -> None:
        if isinstance(obj, dict):
            for key, value in obj.items():
                full_path = f"{path}.{key}" if path else key
                if any(pii_key in key.lower() for pii_key in PII_KEYS):
                    found.append(full_path)
                _check(value, full_path)
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                _check(item, f"{path}[{i}]")

    _check(body)
    return found


def run_idor_test(
    url_template: str,
    id_values: list[str],
    auth_cookie: str = "",
    own_id: str = "",
    delay: float = 0.2,
) -> list[IDORFinding]:
    """
    IDOR 테스트를 실행합니다.

    Args:
        url_template: FUZZ 마커 포함 URL 템플릿
        id_values: 테스트할 ID 값 목록
        auth_cookie: 인증 쿠키 (선택)
        own_id: 현재 사용자의 ID (이것 외의 접근 = IDOR)
        delay: 요청 간 지연 (초)

    Returns:
        IDOR 발견 목록
    """
    findings: list[IDORFinding] = []
    total = len(id_values)

    print(f"IDOR 테스트 시작: {total}개 ID 값, URL: {url_template}")

    for i, id_val in enumerate(id_values, 1):
        url = url_template.replace(FUZZ_MARKER, str(id_val))
        status, body = fetch_resource(url, auth_cookie)

        if i % 10 == 0 or i == total:
            print(f"  진행: {i}/{total} ({len(findings)}개 발견)", end="\r")

        # 200 OK 이외의 응답은 건너뜀
        if status != 200 or body is None:
            if delay:
                time.sleep(delay)
            continue

        # PII 탐지
        pii_keys = detect_pii_in_response(body)

        # 자신의 ID가 아닌 리소스에 접근 성공 = IDOR
        is_idor = own_id and str(id_val) != str(own_id)
        if not own_id:
            # own_id를 모르는 경우: 응답이 있으면 모두 잠재적 IDOR
            is_idor = True

        if is_idor or pii_keys:
            finding = IDORFinding(
                id_value=str(id_val),
                url=url,
                status_code=status,
                response_body=body,
                pii_keys_found=pii_keys,
                is_idor=is_idor,
                notes=(
                    f"PII 키 발견: {', '.join(pii_keys)}" if pii_keys
                    else "접근 허용됨"
                ),
            )
            findings.append(finding)

        if delay:
            time.sleep(delay)

    print(f"\n완료: {len(findings)}개 IDOR 의심 발견")
    return findings


def main() -> None:
    parser = argparse.ArgumentParser(
        description="IDOR 취약점 자동 탐지",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
예시:
  python idor_detector.py -u http://localhost:8083/api/users/FUZZ --range 1-20
  python idor_detector.py -u http://localhost:8083/api/orders/FUZZ --range 100-110 --own-id 101
  python idor_detector.py -u http://example.com/api/profile/FUZZ --range 1-100 \\
      --cookie "session=abc123" --own-id 50
        """,
    )
    parser.add_argument("-u", "--url", required=True,
                        help="FUZZ 마커 포함 URL (예: http://example.com/api/user/FUZZ)")
    parser.add_argument("--range", dest="num_range", required=True,
                        help="테스트할 숫자 범위 (예: 1-100)")
    parser.add_argument("--own-id", default="",
                        help="현재 사용자 ID (이것 외의 접근 = IDOR)")
    parser.add_argument("--cookie", default="", help="인증 쿠키")
    parser.add_argument("-d", "--delay", type=float, default=0.2,
                        help="요청 간 지연 (초, 기본: 0.2)")
    parser.add_argument("-o", "--output", default="idor_findings.json",
                        help="결과 저장 파일")
    args = parser.parse_args()

    if FUZZ_MARKER not in args.url:
        parser.error(f"URL에 {FUZZ_MARKER} 마커가 필요합니다.")

    # 숫자 범위 파싱
    try:
        start_s, end_s = args.num_range.split("-")
        id_values = [str(i) for i in range(int(start_s), int(end_s) + 1)]
    except ValueError:
        parser.error("범위 형식 오류: 'start-end' 형식으로 입력하세요 (예: 1-100)")
        return

    findings = run_idor_test(
        url_template=args.url,
        id_values=id_values,
        auth_cookie=args.cookie,
        own_id=args.own_id,
        delay=args.delay,
    )

    # 결과 저장
    output_data = [
        {
            "id_value": f.id_value,
            "url": f.url,
            "status_code": f.status_code,
            "pii_keys_found": f.pii_keys_found,
            "is_idor": f.is_idor,
            "notes": f.notes,
            "response_preview": str(f.response_body)[:500],
        }
        for f in findings
    ]

    output_path = Path(args.output)
    output_path.write_text(json.dumps(output_data, indent=2, ensure_ascii=False))

    # 결과 출력
    if findings:
        print(f"\n[발견된 IDOR 취약점 {len(findings)}개]")
        for f in findings[:10]:  # 최대 10개만 출력
            print(f"\n  ID: {f.id_value}")
            print(f"  URL: {f.url}")
            print(f"  PII 키: {f.pii_keys_found}")
            print(f"  참고: {f.notes}")
        print(f"\n전체 결과: {output_path.absolute()}")
    else:
        print("\nIDOR 취약점이 발견되지 않았습니다.")


if __name__ == "__main__":
    main()
```

### 풀이
```
1. Docker 환경 시작: docker compose up -d
2. IDOR 탐지 실행:
   python idor_detector.py -u http://localhost:8083/api/users/FUZZ --range 1-10
3. 모든 사용자(1~3)의 정보가 노출됨 → ssn 필드 포함 → Severity: High
4. 주문 정보 IDOR:
   python idor_detector.py -u http://localhost:8083/api/orders/FUZZ --range 100-110
5. 리포트 작성:
   - 취약점: IDOR in GET /api/users/{id}
   - 영향: 모든 사용자의 SSN, 이메일 접근 가능
   - 수정: 세션에서 사용자 ID를 가져와 path parameter와 일치하는지 검증
```

---

## 실습 완료 후 체크리스트

```
실습 1 (서브도메인 테이크오버):
  [ ] CNAME 댕글링 탐지 스크립트 실행
  [ ] 최소 하나의 취약한 서브도메인 발견
  [ ] HackerOne 형식의 리포트 초안 작성

실습 2 (Nuclei 스캔):
  [ ] 기본 Nuclei 스캔 실행
  [ ] 커스텀 템플릿 1개 직접 작성 및 적용
  [ ] /health 엔드포인트 환경변수 노출 확인

실습 3 (IDOR 자동화):
  [ ] idor_detector.py로 API 스캔
  [ ] SSN 포함 IDOR 발견
  [ ] CVSS 점수 계산 (7.0 이상 예상)
```

---

<a name="english"></a>

# Bug Bounty CTF Lab: Hands-On Vulnerability Detection

## How to Use This Lab

This document provides three practice challenges modeled on real-world bug bounty scenarios. Each runs in Docker and is structured as Goal → Hints → Solution.

**Warning**: Only perform these exercises in environments you own and control. Unauthorized testing against real services is illegal.

---

## Lab Environment Setup (Docker)

The `docker-compose.yml` in the Korean section sets up all three lab services:

| Port | Service | Purpose |
|------|---------|---------|
| 8081 | nginx | Lab 1: Subdomain takeover simulation |
| 8082 | Flask app | Lab 2: Vulnerable app for Nuclei scanning |
| 8083 | Python HTTP server | Lab 3: IDOR-vulnerable REST API |

```bash
# Start the lab
docker compose up -d

# Verify all services are running
docker compose ps

# Stop and clean up
docker compose down -v
```

---

## Lab 1: Detecting Subdomain Takeover

### Goal
`staging.example-lab.com` has a CNAME record pointing to an external service that no longer exists. Detect this and determine whether a takeover is possible.

### Background
Subdomain takeover occurs when:
1. A company sets `cdn.example.com CNAME someservice.third-party.io`
2. The `someservice.third-party.io` account is deleted or expires
3. An attacker creates a new account with the same name → hijacks `cdn.example.com`

### Hints
```
Hint 1: Check the CNAME chain: dig staging.example-lab.com CNAME
Hint 2: Does the final CNAME target return "NoSuchBucket" or "There is no app here"?
Hint 3: Reference takeover fingerprints: https://github.com/EdOverflow/can-i-take-over-xyz
```

### Running the Detector
```bash
# Enumerate subdomains first
subfinder -d example-lab.com -o subdomains.txt

# Run the takeover detector
python subdomain_takeover.py -l subdomains.txt
```

The full `subdomain_takeover.py` implementation (Korean section) checks:
1. CNAME existence via `dig`
2. Whether the CNAME target resolves in DNS
3. HTTP response fingerprinting against 10+ known vulnerable services (AWS S3, GitHub Pages, Heroku, Shopify, etc.)

### Solution
```
1. Run subfinder on example-lab.com
2. Run subdomain_takeover.py -l subdomains.txt
3. Find subdomains with CNAME pointing to non-resolving hosts
4. Check if you can claim that name at the third-party service
5. Report impact: phishing, cookie theft, malware delivery via trusted domain
```

---

## Lab 2: Finding Vulnerable Endpoints with Nuclei

### Goal
Use Nuclei and a custom template against `http://localhost:8082` to find all vulnerabilities in the intentionally insecure Flask app.

### Hints
```
Hint 1: What does /health expose?
Hint 2: Try special SQL characters in the /search?q= parameter
Hint 3: nuclei -u http://localhost:8082 -tags debug,exposure,sqli
```

### Lab Commands
```bash
# Full scan
nuclei -u http://localhost:8082 -severity info,low,medium,high,critical

# Scan by tag
nuclei -u http://localhost:8082 -tags debug,exposure,config

# Save as JSON for parsing
nuclei -u http://localhost:8082 -json -o lab2_results.json

# Apply custom template
nuclei -u http://localhost:8082 -t ./custom_templates/env-disclosure.yaml
```

### Solution
```
Vulnerability 1: /health exposes env vars          → Severity: High
Vulnerability 2: SQL Injection in /search          → Severity: High
Vulnerability 3: Debug mode + /console exposed     → Severity: Critical
Vulnerability 4: Missing security headers (CSP, X-Frame-Options) → Info/Low
```

---

## Lab 3: Automated IDOR Detection

### Goal
Use the IDOR detector against `http://localhost:8083` to find authorization bypass vulnerabilities in the REST API.

### Hints
```
Hint 1: Try GET /api/users/1 without any authentication
Hint 2: Iterate user IDs from 1 to 10 and observe responses
Hint 3: What sensitive fields appear in the response?
```

### Running the Detector
```bash
# Test /api/users endpoint
python idor_detector.py \
  -u http://localhost:8083/api/users/FUZZ \
  --range 1-10

# Test /api/orders endpoint
python idor_detector.py \
  -u http://localhost:8083/api/orders/FUZZ \
  --range 100-110 \
  --own-id 101
```

The `idor_detector.py` script (full implementation in Korean section) provides:
- Numeric ID range testing (standard IDOR pattern)
- PII key detection in JSON responses (`ssn`, `password`, `credit_card`, etc.)
- Own-ID comparison to identify unauthorized access
- Per-finding JSON output with response previews

### Solution
```
1. docker compose up -d
2. python idor_detector.py -u http://localhost:8083/api/users/FUZZ --range 1-10
3. All 3 users' data is returned including the ssn field → High severity IDOR
4. python idor_detector.py -u http://localhost:8083/api/orders/FUZZ --range 100-110
5. Write report:
   - Vulnerability: IDOR in GET /api/users/{id} and /api/orders/{id}
   - Impact: Any unauthenticated user can access all other users' SSNs, emails, and orders
   - Fix: Validate that request.session.user_id == path parameter before returning data
   - CVSS estimate: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N = 7.5 (High)
```

---

## Post-Lab Checklist

```
Lab 1 (Subdomain Takeover):
  [ ] Ran the CNAME dangling detection script
  [ ] Found at least one vulnerable subdomain
  [ ] Drafted a HackerOne-format report

Lab 2 (Nuclei Scanning):
  [ ] Ran a full Nuclei scan
  [ ] Wrote and applied one custom template
  [ ] Confirmed env var disclosure via /health

Lab 3 (IDOR Automation):
  [ ] Ran idor_detector.py against the API
  [ ] Found SSN-leaking IDOR
  [ ] Calculated CVSS score (expecting 7.0 or higher)
```

---

## Reference Links

- EdOverflow Subdomain Takeover Reference: https://github.com/EdOverflow/can-i-take-over-xyz
- OWASP IDOR Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
