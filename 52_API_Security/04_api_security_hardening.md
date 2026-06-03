> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# API 보안 강화 — 게이트웨이·OAuth2·자동화 감사

## 0. 초보자를 위한 개념 이해

### API 보안 강화란?

**API 보안 강화(Hardening)**는 API를 공격으로부터 보호하기 위한 체계적인 보안 조치를 적용하는 것입니다.

```
API의 보안 레이어:

Layer 1: 외부 경계
  - CDN/DDoS 방어 (Cloudflare, AWS Shield)
  - 웹 방화벽(WAF) - 악성 요청 패턴 차단
  
Layer 2: API 게이트웨이
  - Rate Limiting (초당 요청 수 제한)
  - 인증 검증 (JWT, API Key)
  - TLS 종단 (HTTPS)
  
Layer 3: 애플리케이션 코드
  - 입력 검증 및 파싱
  - 비즈니스 로직 인가
  
Layer 4: 데이터 계층
  - 암호화 (저장, 전송)
  - 접근 제어
```

### API 게이트웨이란?

**API 게이트웨이**는 모든 API 요청을 중앙에서 처리하는 리버스 프록시입니다.

```
API 게이트웨이 없을 때:
  클라이언트 → 직접 마이크로서비스A (8001)
  클라이언트 → 직접 마이크로서비스B (8002)
  → 각 서비스가 인증/인가를 각자 처리
  → 중복 코드, 보안 설정 불일치
  
API 게이트웨이 있을 때:
  클라이언트 → 게이트웨이(443) → 마이크로서비스A
                               → 마이크로서비스B
  → 게이트웨이에서 중앙화된 인증/인가
  → Rate Limiting, WAF, 로깅 일괄 처리
```

**주요 API 게이트웨이 솔루션:**
```
오픈소스: Kong, Traefik, Nginx (with modules)
상용: AWS API Gateway, Google Cloud Apigee, Azure APIM
  
선택 기준:
  소규모 스타트업 → Kong (무료 오픈소스)
  AWS 환경 → AWS API Gateway (서버리스와 연동)
  대기업 → Apigee (고급 분석, 개발자 포털)
```

### OAuth2와 JWT의 차이

```
OAuth2:
  인증 프레임워크 (어떻게 권한을 부여할지의 규약)
  - 사용자 대신 앱이 다른 서비스에 접근하는 방법
  
JWT (JSON Web Token):
  토큰 형식 (데이터를 어떻게 담을지)
  - 서버가 발급, 클라이언트가 보관
  - 서버가 DB 조회 없이 토큰만으로 검증 가능
  
실제 사용:
  OAuth2로 로그인 과정 → JWT로 토큰 발급 → API 호출 시 JWT 사용
```

---

## 1. API 보안 아키텍처

```
Client
  │
  ▼
[API Gateway] ─── Rate Limiting / DDoS 방어
  │              ─── 인증·인가 (OAuth2/JWT)
  │              ─── WAF / 입력 검증
  │              ─── TLS 종단
  ▼
[Backend Services]
  │
  ▼
[Service Mesh] ─── mTLS (서비스 간 암호화)
  │             ─── 내부 인가 (RBAC/ABAC)
  ▼
[Database] ─── 최소 권한 계정
```

---

## 2. OAuth2 / OIDC 보안

### 2.1 일반적인 OAuth2 취약점

| 취약점 | 설명 | 공격 |
|--------|------|------|
| State 파라미터 미검증 | CSRF 공격 가능 | 조작된 콜백 URL로 코드 탈취 |
| 오픈 리다이렉트 | redirect_uri 검증 부재 | `redirect_uri=https://attacker.com` |
| 암시적 플로우 | 토큰이 URL 프래그먼트에 노출 | 브라우저 히스토리·Referer 헤더 |
| 코드 재사용 | Authorization Code 단일 사용 미강제 | 탈취된 코드 재사용 |
| PKCE 미적용 | SPA/모바일 앱에서 코드 가로채기 | 인터셉트 공격 |

### 2.2 PKCE 구현 (Python)

```python
#!/usr/bin/env python3
"""OAuth2 PKCE 플로우 구현 — 인가 코드 플로우 보안 강화."""

import hashlib
import base64
import os
import secrets
import urllib.parse
import argparse
import httpx


def generate_pkce_pair() -> tuple[str, str]:
    """code_verifier와 code_challenge 생성."""
    verifier = base64.urlsafe_b64encode(os.urandom(40)).rstrip(b"=").decode()
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()
    return verifier, challenge


def build_auth_url(
    auth_endpoint: str,
    client_id: str,
    redirect_uri: str,
    scopes: list[str],
    code_challenge: str,
    state: str | None = None,
) -> str:
    if state is None:
        state = secrets.token_urlsafe(32)

    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": " ".join(scopes),
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    return f"{auth_endpoint}?{urllib.parse.urlencode(params)}"


def exchange_code(
    token_endpoint: str,
    code: str,
    verifier: str,
    client_id: str,
    redirect_uri: str,
) -> dict:
    with httpx.Client() as client:
        resp = client.post(
            token_endpoint,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "code_verifier": verifier,
            },
        )
        return resp.json()


def main() -> None:
    parser = argparse.ArgumentParser(description="OAuth2 PKCE 플로우")
    sub = parser.add_subparsers(dest="cmd", required=True)

    init_p = sub.add_parser("init", help="인증 URL 생성")
    init_p.add_argument("--auth-url", required=True)
    init_p.add_argument("--client-id", required=True)
    init_p.add_argument("--redirect-uri", required=True)
    init_p.add_argument("--scopes", default="openid profile email")

    exchange_p = sub.add_parser("exchange", help="코드 → 토큰 교환")
    exchange_p.add_argument("--token-url", required=True)
    exchange_p.add_argument("--code", required=True)
    exchange_p.add_argument("--verifier", required=True)
    exchange_p.add_argument("--client-id", required=True)
    exchange_p.add_argument("--redirect-uri", required=True)

    args = parser.parse_args()

    match args.cmd:
        case "init":
            verifier, challenge = generate_pkce_pair()
            url = build_auth_url(
                args.auth_url, args.client_id, args.redirect_uri,
                args.scopes.split(), challenge,
            )
            print(f"인증 URL:\n{url}")
            print(f"\ncode_verifier (보관):\n{verifier}")

        case "exchange":
            import json
            tokens = exchange_code(
                args.token_url, args.code, args.verifier,
                args.client_id, args.redirect_uri,
            )
            print(json.dumps(tokens, indent=2))


if __name__ == "__main__":
    main()
```

---

## 3. Rate Limiting 구현 (FastAPI)

```python
#!/usr/bin/env python3
"""FastAPI 기반 API Rate Limiting 미들웨어."""

import time
from collections import defaultdict
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse

app = FastAPI()

# 토큰 버킷 구현
class TokenBucket:
    def __init__(self, rate: float, capacity: int) -> None:
        self.rate = rate          # 초당 충전량
        self.capacity = capacity  # 최대 토큰
        self.tokens = capacity
        self.last_refill = time.monotonic()

    def consume(self, tokens: int = 1) -> bool:
        now = time.monotonic()
        elapsed = now - self.last_refill
        self.tokens = min(
            self.capacity,
            self.tokens + elapsed * self.rate,
        )
        self.last_refill = now

        if self.tokens >= tokens:
            self.tokens -= tokens
            return True
        return False


buckets: dict[str, TokenBucket] = defaultdict(lambda: TokenBucket(rate=10, capacity=60))


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    client_ip = request.client.host if request.client else "unknown"
    token = request.headers.get("Authorization", "")
    identifier = token if token else client_ip

    if not buckets[identifier].consume():
        return JSONResponse(
            status_code=429,
            content={"error": "Too Many Requests"},
            headers={
                "Retry-After": "60",
                "X-RateLimit-Limit": "60",
                "X-RateLimit-Remaining": "0",
            },
        )
    return await call_next(request)
```

---

## 4. API 보안 감사 자동화 CLI

```python
#!/usr/bin/env python3
"""API 보안 감사 자동화 — 헤더·TLS·인증·응답 검증."""

import argparse
import json
import ssl
import socket
from dataclasses import dataclass, field
from pathlib import Path

import httpx


@dataclass
class AuditResult:
    endpoint: str
    checks: dict[str, bool] = field(default_factory=dict)
    issues: list[str] = field(default_factory=list)


SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cache-Control",
]


def check_tls(hostname: str, port: int = 443) -> dict[str, bool | str]:
    result: dict[str, bool | str] = {}
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.create_connection((hostname, port)), server_hostname=hostname) as sock:
            cert = sock.getpeercert()
            result["tls_valid"] = True
            result["tls_version"] = sock.version()
            result["cipher"] = sock.cipher()[0] if sock.cipher() else "unknown"
    except ssl.SSLError as e:
        result["tls_valid"] = False
        result["tls_error"] = str(e)
    return result


def audit_endpoint(url: str, token: str | None = None) -> AuditResult:
    result = AuditResult(endpoint=url)
    headers: dict[str, str] = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        with httpx.Client(verify=True, follow_redirects=True) as client:
            resp = client.get(url, headers=headers, timeout=15)

        # 보안 헤더 확인
        for header in SECURITY_HEADERS:
            present = header in resp.headers
            result.checks[f"header_{header}"] = present
            if not present:
                result.issues.append(f"보안 헤더 누락: {header}")

        # HTTPS 강제 확인
        result.checks["https"] = url.startswith("https://")
        if not result.checks["https"]:
            result.issues.append("HTTPS 미사용")

        # 응답에 민감 정보 노출 확인
        import re
        body = resp.text
        sensitive_patterns = {
            "stack_trace": r"Traceback|at \w+\.\w+\(",
            "internal_path": r"/var/www|/home/\w+|C:\\",
            "sql_error": r"SQL syntax|mysql_error|ORA-\d+",
            "debug_info": r'"debug":\s*true|DEBUG=True',
        }
        for name, pattern in sensitive_patterns.items():
            if re.search(pattern, body, re.IGNORECASE):
                result.checks[f"no_{name}"] = False
                result.issues.append(f"응답에 {name} 노출됨")
            else:
                result.checks[f"no_{name}"] = True

        # 불필요한 HTTP 메서드 확인
        options_resp = client.options(url, headers=headers, timeout=10)
        allow_header = options_resp.headers.get("Allow", "")
        dangerous_methods = {"TRACE", "CONNECT", "DEBUG"}
        exposed = dangerous_methods & set(allow_header.split(", "))
        if exposed:
            result.issues.append(f"위험 HTTP 메서드 허용: {exposed}")

    except httpx.RequestError as e:
        result.issues.append(f"연결 오류: {e}")

    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="API 보안 감사")
    parser.add_argument("targets", nargs="+", help="감사할 엔드포인트 URL 목록")
    parser.add_argument("-t", "--token", help="인증 토큰")
    parser.add_argument("-o", "--output", type=Path, help="결과 저장 경로")
    args = parser.parse_args()

    all_results = []
    for url in args.targets:
        print(f"[*] 감사 중: {url}")
        result = audit_endpoint(url, args.token)
        all_results.append(result)

        passed = sum(v for v in result.checks.values() if isinstance(v, bool))
        total = len(result.checks)
        print(f"  체크: {passed}/{total} 통과")
        for issue in result.issues:
            print(f"  [!] {issue}")

    if args.output:
        args.output.write_text(
            json.dumps(
                [{"endpoint": r.endpoint, "checks": r.checks, "issues": r.issues} for r in all_results],
                indent=2, ensure_ascii=False,
            )
        )
        print(f"\n결과 저장: {args.output}")


if __name__ == "__main__":
    main()
```

---

## 5. API 게이트웨이 보안 설정

### 5.1 Kong Gateway 설정

```yaml
# kong.yml — API 보안 플러그인 설정
services:
  - name: api-service
    url: http://backend:8080
    plugins:
      # JWT 인증
      - name: jwt
        config:
          claims_to_verify: ["exp", "nbf"]
          key_claim_name: "iss"

      # Rate Limiting
      - name: rate-limiting
        config:
          minute: 100
          hour: 1000
          policy: redis
          redis_host: redis
          redis_port: 6379

      # 요청 크기 제한
      - name: request-size-limiting
        config:
          allowed_payload_size: 10  # MB

      # CORS
      - name: cors
        config:
          origins: ["https://app.example.com"]
          methods: ["GET", "POST", "PUT", "DELETE"]
          headers: ["Authorization", "Content-Type"]
          credentials: true
          max_age: 3600

      # 봇 탐지
      - name: bot-detection
        config:
          allow: []
          deny: ["bot", "spider", "crawler"]
```

### 5.2 NGINX API Gateway 설정

```nginx
# /etc/nginx/conf.d/api-gateway.conf
upstream backend {
    server backend:8080;
    keepalive 32;
}

server {
    listen 443 ssl http2;
    server_name api.example.com;

    ssl_certificate /etc/ssl/certs/api.crt;
    ssl_certificate_key /etc/ssl/private/api.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-CHACHA20-POLY1305;

    # 보안 헤더
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Content-Security-Policy "default-src 'none'" always;

    # Rate Limiting (zone은 http 블록에서 정의)
    limit_req zone=api_limit burst=20 nodelay;
    limit_req_status 429;

    # 요청 크기 제한
    client_max_body_size 10m;

    location /api/ {
        proxy_pass http://backend;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_hide_header X-Powered-By;
        proxy_hide_header Server;
    }
}
```

---

## 6. API 보안 체크리스트

| 항목 | 구현 방법 |
|------|-----------|
| HTTPS 강제 | HSTS + HTTP→HTTPS 리다이렉트 |
| 인증 | OAuth2 + PKCE / API Key 해시 저장 |
| 인가 | RBAC/ABAC + 객체 수준 권한 |
| Rate Limiting | 토큰 버킷 / 슬라이딩 윈도우 |
| 입력 검증 | JSON Schema / Pydantic 모델 |
| 출력 인코딩 | 응답 직렬화 시 타입 고정 |
| 에러 처리 | 스택 트레이스·내부 정보 숨기기 |
| 로깅 | 요청/응답 감사 로그 (민감 데이터 마스킹) |
| 버전 관리 | 구형 버전 명시적 폐기 일정 |
| 의존성 관리 | `pip audit` / `safety check` 자동화 |

---

<a name="english"></a>

# API Security Hardening — Gateway, OAuth2, and Automated Auditing

## 1. API Security Architecture

```
Client
  │
  ▼
[API Gateway] ─── Rate Limiting / DDoS Defense
  │              ─── Authentication & Authorization (OAuth2/JWT)
  │              ─── WAF / Input Validation
  │              ─── TLS Termination
  ▼
[Backend Services]
  │
  ▼
[Service Mesh] ─── mTLS (inter-service encryption)
  │             ─── Internal authorization (RBAC/ABAC)
  ▼
[Database] ─── Least privilege accounts
```

---

## 2. OAuth2 / OIDC Security

### 2.1 Common OAuth2 Vulnerabilities

| Vulnerability | Description | Attack |
|---------------|-------------|--------|
| State parameter not validated | CSRF attack possible | Code theft via manipulated callback URL |
| Open redirect | Missing redirect_uri validation | `redirect_uri=https://attacker.com` |
| Implicit flow | Token exposed in URL fragment | Browser history, Referer header |
| Code reuse | Authorization Code single-use not enforced | Reusing stolen code |
| PKCE not applied | Code interception in SPA/mobile apps | Intercept attack |

### 2.2 PKCE Implementation (Python)

```python
#!/usr/bin/env python3
"""OAuth2 PKCE flow implementation — enhanced security for authorization code flow."""

import hashlib
import base64
import os
import secrets
import urllib.parse
import argparse
import httpx


def generate_pkce_pair() -> tuple[str, str]:
    """Generate code_verifier and code_challenge."""
    verifier = base64.urlsafe_b64encode(os.urandom(40)).rstrip(b"=").decode()
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()
    return verifier, challenge


def build_auth_url(
    auth_endpoint: str,
    client_id: str,
    redirect_uri: str,
    scopes: list[str],
    code_challenge: str,
    state: str | None = None,
) -> str:
    if state is None:
        state = secrets.token_urlsafe(32)

    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": " ".join(scopes),
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    return f"{auth_endpoint}?{urllib.parse.urlencode(params)}"


def exchange_code(
    token_endpoint: str,
    code: str,
    verifier: str,
    client_id: str,
    redirect_uri: str,
) -> dict:
    with httpx.Client() as client:
        resp = client.post(
            token_endpoint,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "code_verifier": verifier,
            },
        )
        return resp.json()


def main() -> None:
    parser = argparse.ArgumentParser(description="OAuth2 PKCE flow")
    sub = parser.add_subparsers(dest="cmd", required=True)

    init_p = sub.add_parser("init", help="Generate authorization URL")
    init_p.add_argument("--auth-url", required=True)
    init_p.add_argument("--client-id", required=True)
    init_p.add_argument("--redirect-uri", required=True)
    init_p.add_argument("--scopes", default="openid profile email")

    exchange_p = sub.add_parser("exchange", help="Exchange code for token")
    exchange_p.add_argument("--token-url", required=True)
    exchange_p.add_argument("--code", required=True)
    exchange_p.add_argument("--verifier", required=True)
    exchange_p.add_argument("--client-id", required=True)
    exchange_p.add_argument("--redirect-uri", required=True)

    args = parser.parse_args()

    match args.cmd:
        case "init":
            verifier, challenge = generate_pkce_pair()
            url = build_auth_url(
                args.auth_url, args.client_id, args.redirect_uri,
                args.scopes.split(), challenge,
            )
            print(f"Authorization URL:\n{url}")
            print(f"\ncode_verifier (save this):\n{verifier}")

        case "exchange":
            import json
            tokens = exchange_code(
                args.token_url, args.code, args.verifier,
                args.client_id, args.redirect_uri,
            )
            print(json.dumps(tokens, indent=2))


if __name__ == "__main__":
    main()
```

---

## 3. Rate Limiting Implementation (FastAPI)

```python
#!/usr/bin/env python3
"""FastAPI-based API Rate Limiting middleware."""

import time
from collections import defaultdict
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse

app = FastAPI()

# Token bucket implementation
class TokenBucket:
    def __init__(self, rate: float, capacity: int) -> None:
        self.rate = rate          # Refill rate per second
        self.capacity = capacity  # Maximum tokens
        self.tokens = capacity
        self.last_refill = time.monotonic()

    def consume(self, tokens: int = 1) -> bool:
        now = time.monotonic()
        elapsed = now - self.last_refill
        self.tokens = min(
            self.capacity,
            self.tokens + elapsed * self.rate,
        )
        self.last_refill = now

        if self.tokens >= tokens:
            self.tokens -= tokens
            return True
        return False


buckets: dict[str, TokenBucket] = defaultdict(lambda: TokenBucket(rate=10, capacity=60))


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    client_ip = request.client.host if request.client else "unknown"
    token = request.headers.get("Authorization", "")
    identifier = token if token else client_ip

    if not buckets[identifier].consume():
        return JSONResponse(
            status_code=429,
            content={"error": "Too Many Requests"},
            headers={
                "Retry-After": "60",
                "X-RateLimit-Limit": "60",
                "X-RateLimit-Remaining": "0",
            },
        )
    return await call_next(request)
```

---

## 4. Automated API Security Audit CLI

```python
#!/usr/bin/env python3
"""Automated API security audit — headers, TLS, authentication, and response validation."""

import argparse
import json
import ssl
import socket
from dataclasses import dataclass, field
from pathlib import Path

import httpx


@dataclass
class AuditResult:
    endpoint: str
    checks: dict[str, bool] = field(default_factory=dict)
    issues: list[str] = field(default_factory=list)


SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cache-Control",
]


def check_tls(hostname: str, port: int = 443) -> dict[str, bool | str]:
    result: dict[str, bool | str] = {}
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.create_connection((hostname, port)), server_hostname=hostname) as sock:
            cert = sock.getpeercert()
            result["tls_valid"] = True
            result["tls_version"] = sock.version()
            result["cipher"] = sock.cipher()[0] if sock.cipher() else "unknown"
    except ssl.SSLError as e:
        result["tls_valid"] = False
        result["tls_error"] = str(e)
    return result


def audit_endpoint(url: str, token: str | None = None) -> AuditResult:
    result = AuditResult(endpoint=url)
    headers: dict[str, str] = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        with httpx.Client(verify=True, follow_redirects=True) as client:
            resp = client.get(url, headers=headers, timeout=15)

        # Check security headers
        for header in SECURITY_HEADERS:
            present = header in resp.headers
            result.checks[f"header_{header}"] = present
            if not present:
                result.issues.append(f"Missing security header: {header}")

        # Check HTTPS enforcement
        result.checks["https"] = url.startswith("https://")
        if not result.checks["https"]:
            result.issues.append("HTTPS not in use")

        # Check for sensitive info in response
        import re
        body = resp.text
        sensitive_patterns = {
            "stack_trace": r"Traceback|at \w+\.\w+\(",
            "internal_path": r"/var/www|/home/\w+|C:\\",
            "sql_error": r"SQL syntax|mysql_error|ORA-\d+",
            "debug_info": r'"debug":\s*true|DEBUG=True',
        }
        for name, pattern in sensitive_patterns.items():
            if re.search(pattern, body, re.IGNORECASE):
                result.checks[f"no_{name}"] = False
                result.issues.append(f"{name} exposed in response")
            else:
                result.checks[f"no_{name}"] = True

        # Check for unnecessary HTTP methods
        options_resp = client.options(url, headers=headers, timeout=10)
        allow_header = options_resp.headers.get("Allow", "")
        dangerous_methods = {"TRACE", "CONNECT", "DEBUG"}
        exposed = dangerous_methods & set(allow_header.split(", "))
        if exposed:
            result.issues.append(f"Dangerous HTTP methods allowed: {exposed}")

    except httpx.RequestError as e:
        result.issues.append(f"Connection error: {e}")

    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="API security audit")
    parser.add_argument("targets", nargs="+", help="List of endpoint URLs to audit")
    parser.add_argument("-t", "--token", help="Authentication token")
    parser.add_argument("-o", "--output", type=Path, help="Result save path")
    args = parser.parse_args()

    all_results = []
    for url in args.targets:
        print(f"[*] Auditing: {url}")
        result = audit_endpoint(url, args.token)
        all_results.append(result)

        passed = sum(v for v in result.checks.values() if isinstance(v, bool))
        total = len(result.checks)
        print(f"  Checks: {passed}/{total} passed")
        for issue in result.issues:
            print(f"  [!] {issue}")

    if args.output:
        args.output.write_text(
            json.dumps(
                [{"endpoint": r.endpoint, "checks": r.checks, "issues": r.issues} for r in all_results],
                indent=2, ensure_ascii=False,
            )
        )
        print(f"\nResults saved: {args.output}")


if __name__ == "__main__":
    main()
```

---

## 5. API Gateway Security Configuration

### 5.1 Kong Gateway Configuration

```yaml
# kong.yml — API security plugin configuration
services:
  - name: api-service
    url: http://backend:8080
    plugins:
      # JWT authentication
      - name: jwt
        config:
          claims_to_verify: ["exp", "nbf"]
          key_claim_name: "iss"

      # Rate Limiting
      - name: rate-limiting
        config:
          minute: 100
          hour: 1000
          policy: redis
          redis_host: redis
          redis_port: 6379

      # Request size limiting
      - name: request-size-limiting
        config:
          allowed_payload_size: 10  # MB

      # CORS
      - name: cors
        config:
          origins: ["https://app.example.com"]
          methods: ["GET", "POST", "PUT", "DELETE"]
          headers: ["Authorization", "Content-Type"]
          credentials: true
          max_age: 3600

      # Bot detection
      - name: bot-detection
        config:
          allow: []
          deny: ["bot", "spider", "crawler"]
```

### 5.2 NGINX API Gateway Configuration

```nginx
# /etc/nginx/conf.d/api-gateway.conf
upstream backend {
    server backend:8080;
    keepalive 32;
}

server {
    listen 443 ssl http2;
    server_name api.example.com;

    ssl_certificate /etc/ssl/certs/api.crt;
    ssl_certificate_key /etc/ssl/private/api.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-CHACHA20-POLY1305;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Content-Security-Policy "default-src 'none'" always;

    # Rate Limiting (zone defined in http block)
    limit_req zone=api_limit burst=20 nodelay;
    limit_req_status 429;

    # Request size limit
    client_max_body_size 10m;

    location /api/ {
        proxy_pass http://backend;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_hide_header X-Powered-By;
        proxy_hide_header Server;
    }
}
```

---

## 6. API Security Checklist

| Item | Implementation Method |
|------|-----------------------|
| HTTPS enforcement | HSTS + HTTP→HTTPS redirect |
| Authentication | OAuth2 + PKCE / Hashed API Key storage |
| Authorization | RBAC/ABAC + object-level permissions |
| Rate Limiting | Token bucket / sliding window |
| Input validation | JSON Schema / Pydantic models |
| Output encoding | Fixed types during response serialization |
| Error handling | Hide stack traces and internal information |
| Logging | Request/response audit logs (sensitive data masking) |
| Version management | Explicit deprecation schedule for legacy versions |
| Dependency management | `pip audit` / `safety check` automation |
