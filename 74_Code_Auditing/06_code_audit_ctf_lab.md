> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# CTF 스타일 코드 감사 실습 랩

## 개요

이 랩은 CTF(Capture The Flag) 방식으로 실제 취약점을 발견하고 분석하는 실습입니다. 세 가지 시나리오를 통해 코드 감사의 전체 흐름 — 취약한 코드 발견 → 분석 → 패치 → 검증 — 을 경험합니다.

**실습 환경:** Docker + Python Flask

---

## Docker 환경 설정

```dockerfile
# Dockerfile — 취약한 실습용 Flask 앱
FROM python:3.11-slim

WORKDIR /app

# 의존성 설치
RUN pip install flask==3.0.3 \
                requests==2.31.0 \
                pyyaml==6.0.1

# 취약한 앱 복사 (아래 실습 코드를 저장)
COPY vulnerable_app.py .
COPY setup_db.py .

# DB 초기화
RUN python setup_db.py

EXPOSE 5000
CMD ["python", "vulnerable_app.py"]
```

```yaml
# docker-compose.yml
version: "3.9"
services:
  vuln-app:
    build: .
    ports:
      - "5000:5000"
    environment:
      - FLASK_ENV=development
      - SECRET_KEY=super_secret_hardcoded_key_12345  # 의도적 취약점
    volumes:
      - ./data:/app/data
```

```bash
# 환경 실행
docker compose up -d

# 로그 확인
docker compose logs -f

# 컨테이너 접속 (분석용)
docker compose exec vuln-app bash
```

---

## 실습 1: SQL Injection 발견 및 패치

### 취약한 앱 코드 (setup_db.py)

```python
#!/usr/bin/env python3
"""데이터베이스 초기화 스크립트"""

import sqlite3

conn = sqlite3.connect("products.db")
cursor = conn.cursor()

cursor.executescript("""
    CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        price INTEGER NOT NULL,
        category TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT DEFAULT 'user'
    );

    INSERT OR IGNORE INTO products VALUES
        (1, 'Laptop', 1500000, 'electronics'),
        (2, 'Mouse', 30000, 'electronics'),
        (3, 'Keyboard', 80000, 'electronics'),
        (4, 'Monitor', 350000, 'electronics');

    INSERT OR IGNORE INTO users VALUES
        (1, 'admin', 'adminpass123', 'admin'),
        (2, 'alice', 'alice123', 'user'),
        (3, 'bob', 'bob456', 'user');
""")

conn.commit()
conn.close()
print("[+] 데이터베이스 초기화 완료")
```

### 취약한 앱 코드 (vulnerable_app.py)

```python
#!/usr/bin/env python3
"""
취약한 Flask 앱 — 코드 감사 실습용
경고: 이 코드는 의도적으로 취약합니다. 실제 환경에서 사용 금지!
"""

import sqlite3
import subprocess
import os
import pickle
import base64
from flask import Flask, request, render_template_string, jsonify

app = Flask(__name__)

# 취약점 1: 하드코딩된 시크릿 키
app.secret_key = "super_secret_hardcoded_key_12345"


def get_db():
    return sqlite3.connect("products.db")


# ──────────────────────────────────────────
# 취약점 2: SQL Injection
# 엔드포인트: GET /search?q=<keyword>
# ──────────────────────────────────────────
@app.route("/search")
def search():
    keyword = request.args.get("q", "")

    # 취약: f-string으로 SQL 구성
    conn = get_db()
    query = f"SELECT id, name, price FROM products WHERE name LIKE '%{keyword}%'"
    try:
        results = conn.execute(query).fetchall()
    except sqlite3.OperationalError as e:
        return jsonify({"error": str(e)}), 500  # 오류 메시지도 노출!

    return jsonify({"results": [{"id": r[0], "name": r[1], "price": r[2]} for r in results]})


# ──────────────────────────────────────────
# 취약점 3: Command Injection
# 엔드포인트: GET /ping?host=<host>
# ──────────────────────────────────────────
@app.route("/ping")
def ping():
    host = request.args.get("host", "8.8.8.8")

    # 취약: shell=True + 사용자 입력 직접 삽입
    result = subprocess.run(
        f"ping -c 2 {host}",
        shell=True,
        capture_output=True,
        timeout=10,
    )
    return result.stdout.decode() + result.stderr.decode()


# ──────────────────────────────────────────
# 취약점 4: 역직렬화 (pickle)
# 엔드포인트: POST /load-profile
# ──────────────────────────────────────────
@app.route("/load-profile", methods=["POST"])
def load_profile():
    encoded_data = request.json.get("data", "")
    try:
        # 취약: 신뢰할 수 없는 데이터를 pickle로 역직렬화
        profile = pickle.loads(base64.b64decode(encoded_data))
        return jsonify({"username": profile.get("username", "")})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# ──────────────────────────────────────────
# 취약점 5: 시크릿 키 노출 (환경 변수)
# 엔드포인트: GET /debug
# ──────────────────────────────────────────
@app.route("/debug")
def debug():
    # 취약: 환경 변수 전체 노출
    return jsonify(dict(os.environ))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
```

---

### 감사 스크립트: SQL Injection 자동 검증

```python
#!/usr/bin/env python3
"""
실습 1: SQL Injection 발견 및 검증 스크립트
취약한 앱에 대해 다양한 페이로드를 테스트합니다.
Python 3.10+, 타입 힌트, argparse 포함
"""

import argparse
import sys
import time
from dataclasses import dataclass

try:
    import requests
except ImportError:
    print("[-] requests 모듈이 필요합니다: pip install requests")
    sys.exit(1)


@dataclass
class TestResult:
    payload: str
    expected: str
    response_snippet: str
    vulnerable: bool


SQL_PAYLOADS: list[tuple[str, str]] = [
    ("' OR '1'='1", "모든 제품 반환 (인증 우회 패턴)"),
    ("'; DROP TABLE products; --", "오류 메시지로 SQLite 실행 여부 확인"),
    ("' UNION SELECT 1,username,password FROM users--", "사용자 테이블 데이터 추출"),
    ("' AND 1=2--", "거짓 조건 — 결과 없어야 함"),
    ("Laptop", "정상 검색 — 기준선"),
]


def test_sqli(base_url: str, path: str = "/search", param: str = "q") -> list[TestResult]:
    """SQL Injection 테스트 실행"""
    results: list[TestResult] = []
    target_url = f"{base_url.rstrip('/')}{path}"

    for payload, description in SQL_PAYLOADS:
        try:
            response = requests.get(
                target_url,
                params={param: payload},
                timeout=5,
            )
            response_text = response.text[:300]

            # 취약점 징후: 다른 테이블 데이터, 오류 메시지 포함 여부
            is_vulnerable = any([
                "adminpass" in response_text,
                "alice123" in response_text,
                "OperationalError" in response_text,
                "syntax error" in response_text.lower(),
            ])

            results.append(
                TestResult(
                    payload=payload,
                    expected=description,
                    response_snippet=response_text,
                    vulnerable=is_vulnerable,
                )
            )
            time.sleep(0.5)  # 서버 부하 방지

        except requests.RequestException as e:
            print(f"[!] 요청 실패 ({payload[:20]}): {e}", file=sys.stderr)

    return results


def print_results(results: list[TestResult]) -> None:
    found_vulns = [r for r in results if r.vulnerable]
    print(f"\n[*] SQL Injection 테스트 결과: {len(found_vulns)}/{len(results)} 취약점 확인\n")

    for result in results:
        status = "[취약!]" if result.vulnerable else "[정상]"
        print(f"{status} 페이로드: {result.payload[:50]}")
        print(f"         목적: {result.expected}")
        if result.vulnerable:
            print(f"         응답: {result.response_snippet[:100]}")
        print()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SQL Injection 취약점 검증기 (실습용)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="예시: python3 test_sqli.py --url http://localhost:5000",
    )
    parser.add_argument(
        "--url",
        default="http://localhost:5000",
        help="대상 앱 URL (기본: http://localhost:5000)",
    )
    parser.add_argument(
        "--path",
        default="/search",
        help="검색 엔드포인트 경로 (기본: /search)",
    )
    parser.add_argument(
        "--param",
        default="q",
        help="쿼리 파라미터 이름 (기본: q)",
    )
    args = parser.parse_args()

    print(f"[*] SQL Injection 테스트 시작: {args.url}{args.path}")
    results = test_sqli(args.url, args.path, args.param)
    print_results(results)


if __name__ == "__main__":
    main()
```

---

## 실습 2: Semgrep으로 시크릿 키 노출 탐지

```python
#!/usr/bin/env python3
"""
실습 2: 하드코딩된 시크릿 탐지기
정규식 기반으로 소스코드에서 시크릿을 탐지합니다.
Python 3.10+, 타입 힌트, argparse 포함
"""

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass
class SecretFinding:
    file: str
    line_number: int
    matched_pattern: str
    line_content: str
    secret_type: str


# 탐지할 시크릿 패턴 (정규식, 타입)
SECRET_PATTERNS: list[tuple[str, str]] = [
    (r'(?i)(secret[_-]?key|secretkey)\s*=\s*["\'][\w\-!@#$%^&*]{8,}', "Secret Key"),
    (r'(?i)(password|passwd|pwd)\s*=\s*["\'][\w\-!@#$%^&*]{4,}', "Hardcoded Password"),
    (r'(?i)(api[_-]?key|apikey)\s*=\s*["\'][A-Za-z0-9_\-]{16,}', "API Key"),
    (r'(?i)(token)\s*=\s*["\'][A-Za-z0-9._\-]{20,}', "Token"),
    (r'AWS_ACCESS_KEY_ID\s*=\s*["\']AKIA[A-Z0-9]{16}', "AWS Access Key"),
    (r'["\']AKIA[A-Z0-9]{16}["\']', "AWS Access Key (inline)"),
    (r'(?i)database_url\s*=\s*["\'].*://.+:.+@', "Database URL with credentials"),
]


def scan_file_for_secrets(file_path: Path) -> list[SecretFinding]:
    """단일 파일에서 시크릿 패턴 탐색"""
    findings: list[SecretFinding] = []
    try:
        lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return []

    for line_num, line in enumerate(lines, start=1):
        # 주석 라인 스킵 (완벽하지 않지만 FP 감소)
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith("//"):
            continue

        for pattern, secret_type in SECRET_PATTERNS:
            if re.search(pattern, line):
                findings.append(
                    SecretFinding(
                        file=str(file_path),
                        line_number=line_num,
                        matched_pattern=pattern[:50] + "...",
                        line_content=line.strip(),
                        secret_type=secret_type,
                    )
                )
                break  # 한 줄에 하나의 패턴만 매칭

    return findings


def generate_semgrep_rule(findings: list[SecretFinding]) -> str:
    """발견된 패턴에서 Semgrep 규칙 생성"""
    if not findings:
        return ""

    unique_types = {f.secret_type for f in findings}
    rules = []
    for secret_type in unique_types:
        rule_id = secret_type.lower().replace(" ", "-")
        rules.append(f"""  - id: detected-{rule_id}
    message: "하드코딩된 {secret_type}이 감지되었습니다."
    severity: ERROR
    languages: [python]
    pattern: $VAR = "..."
    metadata:
      category: security
      detected_by: secret-scanner""")

    return "rules:\n" + "\n".join(rules)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="하드코딩된 시크릿 탐지기",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("path", help="스캔할 파일 또는 디렉토리")
    parser.add_argument(
        "--generate-semgrep",
        metavar="FILE",
        help="발견된 패턴 기반 Semgrep 규칙 생성",
    )
    parser.add_argument(
        "--extensions",
        nargs="+",
        default=[".py", ".js", ".ts", ".env", ".yaml", ".yml", ".json"],
        help="스캔할 파일 확장자",
    )
    args = parser.parse_args()

    target = Path(args.path)
    if not target.exists():
        print(f"[-] 경로를 찾을 수 없습니다: {target}", file=sys.stderr)
        sys.exit(1)

    all_findings: list[SecretFinding] = []

    if target.is_file():
        all_findings = scan_file_for_secrets(target)
    else:
        for ext in args.extensions:
            for file_path in target.rglob(f"*{ext}"):
                all_findings.extend(scan_file_for_secrets(file_path))

    print(f"\n[*] 시크릿 스캔 완료: {len(all_findings)}개 발견\n")

    for finding in all_findings:
        print(f"[!] {finding.secret_type}")
        print(f"    파일: {finding.file}:{finding.line_number}")
        print(f"    코드: {finding.line_content[:100]}")
        print()

    if args.generate_semgrep and all_findings:
        semgrep_rules = generate_semgrep_rule(all_findings)
        semgrep_path = Path(args.generate_semgrep)
        semgrep_path.write_text(semgrep_rules, encoding="utf-8")
        print(f"[+] Semgrep 규칙 생성: {semgrep_path}")


if __name__ == "__main__":
    main()
```

---

## 실습 3: 인증 우회 패턴 수동 탐지

```python
#!/usr/bin/env python3
"""
실습 3: 인증 우회 취약점 패턴 분석기
AST를 분석하여 인증 검사가 누락된 엔드포인트를 찾습니다.
Python 3.10+, 타입 힌트, argparse 포함
"""

import ast
import argparse
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Endpoint:
    function_name: str
    decorators: list[str]
    line_number: int
    has_auth_check: bool
    auth_patterns_found: list[str]


# 인증 확인으로 간주할 패턴 (함수 호출 이름)
AUTH_FUNCTION_PATTERNS = {
    "login_required",
    "require_auth",
    "check_auth",
    "verify_token",
    "authenticate",
    "current_user",
    "get_jwt_identity",
    "jwt_required",
    "permission_required",
}

# Flask 라우트 데코레이터 패턴
ROUTE_PATTERNS = {"route", "get", "post", "put", "delete", "patch"}


class EndpointAnalyzer(ast.NodeVisitor):
    """Flask 엔드포인트와 인증 패턴을 분석합니다."""

    def __init__(self, source: str) -> None:
        self.source_lines = source.splitlines()
        self.endpoints: list[Endpoint] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        decorators = self._extract_decorators(node)
        is_endpoint = any(
            any(rp in d for rp in ROUTE_PATTERNS) for d in decorators
        )

        if is_endpoint:
            auth_patterns = self._find_auth_patterns(node)
            self.endpoints.append(
                Endpoint(
                    function_name=node.name,
                    decorators=decorators,
                    line_number=node.lineno,
                    has_auth_check=len(auth_patterns) > 0,
                    auth_patterns_found=auth_patterns,
                )
            )

        self.generic_visit(node)

    def _extract_decorators(self, node: ast.FunctionDef) -> list[str]:
        """함수 데코레이터 목록 추출"""
        result: list[str] = []
        for dec in node.decorator_list:
            match dec:
                case ast.Name(id=name):
                    result.append(name)
                case ast.Call(func=ast.Name(id=name)):
                    result.append(name)
                case ast.Call(func=ast.Attribute(attr=attr)):
                    result.append(attr)
                case ast.Attribute(attr=attr):
                    result.append(attr)
        return result

    def _find_auth_patterns(self, node: ast.FunctionDef) -> list[str]:
        """함수 본문에서 인증 패턴 탐색"""
        found: list[str] = []

        class AuthChecker(ast.NodeVisitor):
            def visit_Name(self, inner_node: ast.Name) -> None:
                if inner_node.id in AUTH_FUNCTION_PATTERNS:
                    found.append(inner_node.id)

            def visit_Attribute(self, inner_node: ast.Attribute) -> None:
                if inner_node.attr in AUTH_FUNCTION_PATTERNS:
                    found.append(inner_node.attr)
                self.generic_visit(inner_node)

        AuthChecker().visit(node)
        return list(set(found))


def analyze_flask_auth(file_path: Path) -> list[Endpoint]:
    """Flask 앱 파일에서 인증 없는 엔드포인트 분석"""
    try:
        source = file_path.read_text(encoding="utf-8")
        tree = ast.parse(source)
    except (OSError, SyntaxError) as e:
        print(f"[!] 파싱 실패 {file_path}: {e}", file=sys.stderr)
        return []

    analyzer = EndpointAnalyzer(source)
    analyzer.visit(tree)
    return analyzer.endpoints


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Flask 인증 우회 패턴 탐지기",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="예시: python3 auth_analyzer.py vulnerable_app.py",
    )
    parser.add_argument("path", help="분석할 Flask 앱 파일 또는 디렉토리")
    parser.add_argument(
        "--show-all",
        action="store_true",
        help="인증이 있는 엔드포인트도 출력",
    )
    args = parser.parse_args()

    target = Path(args.path)
    if not target.exists():
        print(f"[-] 경로를 찾을 수 없습니다: {target}", file=sys.stderr)
        sys.exit(1)

    files = [target] if target.is_file() else list(target.rglob("*.py"))
    all_endpoints: list[tuple[Path, Endpoint]] = []

    for fp in files:
        for ep in analyze_flask_auth(fp):
            all_endpoints.append((fp, ep))

    unprotected = [(fp, ep) for fp, ep in all_endpoints if not ep.has_auth_check]
    protected = [(fp, ep) for fp, ep in all_endpoints if ep.has_auth_check]

    print(f"\n[*] 분석 완료")
    print(f"  전체 엔드포인트: {len(all_endpoints)}")
    print(f"  인증 없음 (위험): {len(unprotected)}")
    print(f"  인증 있음 (안전): {len(protected)}")

    print(f"\n{'='*60}")
    print("[!] 인증 없는 엔드포인트 (수동 검토 필요)")
    print(f"{'='*60}")

    for file_path, ep in unprotected:
        print(f"\n함수: {ep.function_name}() — {file_path}:{ep.line_number}")
        print(f"  데코레이터: {', '.join(ep.decorators) or '없음'}")
        print(f"  판정: 인증 검사 미발견 — 접근 제어 취약점 가능성 높음")

    if args.show_all and protected:
        print(f"\n{'='*60}")
        print("[+] 인증 있는 엔드포인트")
        print(f"{'='*60}")
        for file_path, ep in protected:
            print(f"\n함수: {ep.function_name}() — {file_path}:{ep.line_number}")
            print(f"  인증 패턴: {', '.join(ep.auth_patterns_found)}")


if __name__ == "__main__":
    main()
```

---

## 취약점 → 패치 요약

| 취약점 | 발견 방법 | 패치 |
|--------|----------|------|
| SQL Injection | f-string SQL 패턴 검색 | 파라미터화된 쿼리 |
| Command Injection | subprocess + shell=True | 리스트 인자 방식 |
| Pickle RCE | pickle.loads() 탐색 | JSON 사용 |
| 하드코딩 시크릿 | 정규식 시크릿 스캐너 | 환경 변수 + .env |
| 인증 미적용 | AST 기반 데코레이터 분석 | @login_required 추가 |

---

## 참고 자료

- Semgrep GitHub: https://github.com/semgrep/semgrep
- OWASP Code Review Guide: https://owasp.org/www-project-code-review-guide/

---

<a name="english"></a>

# CTF-Style Code Audit Lab

## Overview

This lab teaches code auditing through a CTF (Capture The Flag) approach — finding, analyzing, and patching real vulnerabilities. Three scenarios walk you through the complete cycle: discover the vulnerable code → analyze → patch → verify.

**Lab environment:** Docker + Python Flask

---

## Docker Environment Setup

```dockerfile
# Dockerfile — Intentionally vulnerable Flask app for practice
FROM python:3.11-slim

WORKDIR /app

RUN pip install flask==3.0.3 \
                requests==2.31.0 \
                pyyaml==6.0.1

COPY vulnerable_app.py .
COPY setup_db.py .

RUN python setup_db.py

EXPOSE 5000
CMD ["python", "vulnerable_app.py"]
```

```yaml
# docker-compose.yml
version: "3.9"
services:
  vuln-app:
    build: .
    ports:
      - "5000:5000"
    environment:
      - FLASK_ENV=development
      - SECRET_KEY=super_secret_hardcoded_key_12345
    volumes:
      - ./data:/app/data
```

```bash
docker compose up -d
docker compose logs -f
docker compose exec vuln-app bash
```

---

## Lab 1: SQL Injection — Discovery and Patch

### Vulnerable App Code

```python
#!/usr/bin/env python3
"""
Vulnerable Flask app — for code audit practice.
WARNING: This code is intentionally insecure. Never use in production!
"""

import sqlite3
import subprocess
import os
import pickle
import base64
from flask import Flask, request, jsonify

app = Flask(__name__)
# Vuln 1: Hardcoded secret key
app.secret_key = "super_secret_hardcoded_key_12345"


def get_db():
    return sqlite3.connect("products.db")


# Vuln 2: SQL Injection — GET /search?q=<keyword>
@app.route("/search")
def search():
    keyword = request.args.get("q", "")
    conn = get_db()
    # Vulnerable: f-string SQL construction
    query = f"SELECT id, name, price FROM products WHERE name LIKE '%{keyword}%'"
    try:
        results = conn.execute(query).fetchall()
    except sqlite3.OperationalError as e:
        return jsonify({"error": str(e)}), 500  # Error message leaked!
    return jsonify({"results": [{"id": r[0], "name": r[1], "price": r[2]} for r in results]})


# Vuln 3: Command Injection — GET /ping?host=<host>
@app.route("/ping")
def ping():
    host = request.args.get("host", "8.8.8.8")
    # Vulnerable: shell=True with user input
    result = subprocess.run(f"ping -c 2 {host}", shell=True, capture_output=True, timeout=10)
    return result.stdout.decode() + result.stderr.decode()


# Vuln 4: Insecure Deserialization — POST /load-profile
@app.route("/load-profile", methods=["POST"])
def load_profile():
    encoded_data = request.json.get("data", "")
    try:
        # Vulnerable: pickle.loads on untrusted data — RCE possible!
        profile = pickle.loads(base64.b64decode(encoded_data))
        return jsonify({"username": profile.get("username", "")})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
```

### SQL Injection Test Script

```python
#!/usr/bin/env python3
"""
Lab 1: SQL Injection discovery and verification script.
Tests the vulnerable app with various payloads.
Python 3.10+, with type hints and argparse.
"""

import argparse
import sys
import time
from dataclasses import dataclass

try:
    import requests
except ImportError:
    print("[-] requests required: pip install requests")
    sys.exit(1)


@dataclass
class TestResult:
    payload: str
    description: str
    response_snippet: str
    vulnerable: bool


SQL_PAYLOADS: list[tuple[str, str]] = [
    ("' OR '1'='1", "Return all products (auth bypass pattern)"),
    ("'; DROP TABLE products; --", "Check for error messages revealing SQLite"),
    ("' UNION SELECT 1,username,password FROM users--", "Extract user table data"),
    ("' AND 1=2--", "False condition — should return no results"),
    ("Laptop", "Normal search — baseline"),
]


def test_sqli(base_url: str, path: str = "/search", param: str = "q") -> list[TestResult]:
    results: list[TestResult] = []
    target_url = f"{base_url.rstrip('/')}{path}"

    for payload, description in SQL_PAYLOADS:
        try:
            response = requests.get(target_url, params={param: payload}, timeout=5)
            response_text = response.text[:300]
            is_vulnerable = any([
                "adminpass" in response_text,
                "alice123" in response_text,
                "OperationalError" in response_text,
                "syntax error" in response_text.lower(),
            ])
            results.append(TestResult(payload, description, response_text, is_vulnerable))
            time.sleep(0.5)
        except requests.RequestException as e:
            print(f"[!] Request failed ({payload[:20]}): {e}", file=sys.stderr)

    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="SQL Injection verifier (for lab use)")
    parser.add_argument("--url", default="http://localhost:5000", help="Target app URL")
    parser.add_argument("--path", default="/search")
    parser.add_argument("--param", default="q")
    args = parser.parse_args()

    print(f"[*] Testing SQL Injection: {args.url}{args.path}")
    results = test_sqli(args.url, args.path, args.param)

    found = [r for r in results if r.vulnerable]
    print(f"\n[*] Results: {len(found)}/{len(results)} vulnerable\n")

    for result in results:
        status = "[VULN]" if result.vulnerable else "[OK]  "
        print(f"{status} Payload: {result.payload[:50]}")
        print(f"       Goal: {result.description}")
        if result.vulnerable:
            print(f"       Response: {result.response_snippet[:100]}")
        print()


if __name__ == "__main__":
    main()
```

---

## Lab 2: Secret Key Detection with Semgrep

```python
#!/usr/bin/env python3
"""
Lab 2: Hardcoded secret detector using regex patterns.
Python 3.10+, with type hints and argparse.
"""

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass
class SecretFinding:
    file: str
    line_number: int
    line_content: str
    secret_type: str


SECRET_PATTERNS: list[tuple[str, str]] = [
    (r'(?i)(secret[_-]?key|secretkey)\s*=\s*["\'][\w\-!@#$%^&*]{8,}', "Secret Key"),
    (r'(?i)(password|passwd)\s*=\s*["\'][\w\-!@#$%^&*]{4,}', "Hardcoded Password"),
    (r'(?i)(api[_-]?key)\s*=\s*["\'][A-Za-z0-9_\-]{16,}', "API Key"),
    (r'AWS_ACCESS_KEY_ID\s*=\s*["\']AKIA[A-Z0-9]{16}', "AWS Access Key"),
]


def scan_for_secrets(file_path: Path) -> list[SecretFinding]:
    findings: list[SecretFinding] = []
    try:
        lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return []

    for line_num, line in enumerate(lines, start=1):
        if line.strip().startswith(("#", "//")):
            continue
        for pattern, secret_type in SECRET_PATTERNS:
            if re.search(pattern, line):
                findings.append(SecretFinding(str(file_path), line_num, line.strip(), secret_type))
                break
    return findings


def main() -> None:
    parser = argparse.ArgumentParser(description="Hardcoded secret detector")
    parser.add_argument("path", help="File or directory to scan")
    args = parser.parse_args()

    target = Path(args.path)
    if not target.exists():
        print(f"[-] Path not found: {target}", file=sys.stderr)
        sys.exit(1)

    findings: list[SecretFinding] = []
    if target.is_file():
        findings = scan_for_secrets(target)
    else:
        for fp in target.rglob("*"):
            if fp.is_file() and fp.suffix in {".py", ".js", ".env", ".yaml", ".json"}:
                findings.extend(scan_for_secrets(fp))

    print(f"\n[*] Secret scan complete: {len(findings)} findings\n")
    for f in findings:
        print(f"[!] {f.secret_type}")
        print(f"    File: {f.file}:{f.line_number}")
        print(f"    Code: {f.line_content[:100]}\n")


if __name__ == "__main__":
    main()
```

---

## Lab 3: Authentication Bypass — Manual Pattern Detection

```python
#!/usr/bin/env python3
"""
Lab 3: Flask authentication bypass analyzer.
Uses Python AST to find endpoints missing auth checks.
Python 3.10+, with type hints and argparse.
"""

import ast
import argparse
import sys
from dataclasses import dataclass
from pathlib import Path


AUTH_PATTERNS = {
    "login_required", "require_auth", "check_auth",
    "jwt_required", "permission_required", "verify_token",
}

ROUTE_PATTERNS = {"route", "get", "post", "put", "delete", "patch"}


@dataclass
class Endpoint:
    function_name: str
    decorators: list[str]
    line_number: int
    has_auth_check: bool
    auth_patterns_found: list[str]


class EndpointAnalyzer(ast.NodeVisitor):
    def __init__(self) -> None:
        self.endpoints: list[Endpoint] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        decorators = self._get_decorators(node)
        if any(any(rp in d for rp in ROUTE_PATTERNS) for d in decorators):
            auth = self._find_auth(node)
            self.endpoints.append(
                Endpoint(node.name, decorators, node.lineno, bool(auth), auth)
            )
        self.generic_visit(node)

    def _get_decorators(self, node: ast.FunctionDef) -> list[str]:
        result: list[str] = []
        for dec in node.decorator_list:
            match dec:
                case ast.Name(id=name): result.append(name)
                case ast.Call(func=ast.Name(id=name)): result.append(name)
                case ast.Call(func=ast.Attribute(attr=attr)): result.append(attr)
                case ast.Attribute(attr=attr): result.append(attr)
        return result

    def _find_auth(self, node: ast.FunctionDef) -> list[str]:
        found: list[str] = []
        for child in ast.walk(node):
            match child:
                case ast.Name(id=name) if name in AUTH_PATTERNS:
                    found.append(name)
                case ast.Attribute(attr=attr) if attr in AUTH_PATTERNS:
                    found.append(attr)
        return list(set(found))


def main() -> None:
    parser = argparse.ArgumentParser(description="Flask auth bypass detector")
    parser.add_argument("path", help="Flask app file or directory")
    parser.add_argument("--show-all", action="store_true", help="Show protected endpoints too")
    args = parser.parse_args()

    target = Path(args.path)
    if not target.exists():
        print(f"[-] Path not found: {target}", file=sys.stderr)
        sys.exit(1)

    files = [target] if target.is_file() else list(target.rglob("*.py"))
    all_endpoints: list[tuple[Path, Endpoint]] = []

    for fp in files:
        try:
            source = fp.read_text(encoding="utf-8")
            tree = ast.parse(source)
            analyzer = EndpointAnalyzer()
            analyzer.visit(tree)
            for ep in analyzer.endpoints:
                all_endpoints.append((fp, ep))
        except (OSError, SyntaxError):
            continue

    unprotected = [(fp, ep) for fp, ep in all_endpoints if not ep.has_auth_check]

    print(f"\n[*] Analysis complete")
    print(f"  Total endpoints:    {len(all_endpoints)}")
    print(f"  Unprotected (risk): {len(unprotected)}")
    print(f"  Protected (safe):   {len(all_endpoints) - len(unprotected)}")

    print(f"\n{'='*55}")
    print("[!] Endpoints missing auth checks (review required)")
    print(f"{'='*55}")

    for file_path, ep in unprotected:
        print(f"\nFunction: {ep.function_name}() — {file_path}:{ep.line_number}")
        print(f"  Decorators: {', '.join(ep.decorators) or 'none'}")
        print(f"  Verdict: No auth pattern found — possible access control vulnerability")


if __name__ == "__main__":
    main()
```

---

## Vulnerability → Patch Summary

| Vulnerability | Discovery Method | Patch |
|--------------|-----------------|-------|
| SQL Injection | f-string SQL pattern search | Parameterized queries |
| Command Injection | subprocess + shell=True | List args, shell=False |
| Pickle RCE | pickle.loads() AST scan | Use JSON instead |
| Hardcoded Secret | Regex secret scanner | Environment variables + .env |
| Missing Auth | AST decorator analysis | Add @login_required |

---

## References

- Semgrep GitHub: https://github.com/semgrep/semgrep
- OWASP Code Review Guide: https://owasp.org/www-project-code-review-guide/
