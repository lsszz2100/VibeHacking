> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 수동 코드 리뷰 기법

## 수동 리뷰가 필요한 이유

정적 분석 도구는 강력하지만 한계가 있습니다. 비즈니스 로직 취약점, 접근 제어 오류, 복잡한 다단계 인증 우회 같은 문제는 도구가 잘 잡지 못합니다. 사람의 눈과 추론이 필요한 이유입니다.

수동 코드 리뷰는 두 가지 방향으로 진행합니다.

```
정방향: 소스(Source) → 싱크(Sink)
  "외부 입력이 어디로 흘러가는가?"
  사용자 입력 → 변환/검증? → DB 쿼리/OS 명령/파일/응답

역방향: 싱크(Sink) → 소스(Source)
  "위험한 함수는 어디서 데이터를 받는가?"
  cursor.execute() → 어디서 왔나? → 사용자 입력인가?
```

---

## 소스(Source)와 싱크(Sink) 개념

**소스(Source):** 외부 데이터가 프로그램으로 들어오는 지점
```
- HTTP 요청 파라미터: request.args.get(), request.form[], request.json
- 쿠키/헤더: request.cookies, request.headers
- 파일 업로드: request.files
- 환경 변수: os.environ.get()
- 데이터베이스 읽기 (다른 사용자가 넣은 데이터)
- 설정 파일 읽기
```

**싱크(Sink):** 입력이 실행되거나 출력되는 위험한 지점
```
- SQL 실행: cursor.execute(), query()
- OS 명령: os.system(), subprocess.run()
- 파일 작업: open(), Path.write()
- HTML 렌더링: render_template() — XSS 가능
- 역직렬화: pickle.loads(), yaml.load()
- 외부 요청: requests.get(), urllib.open()
- 이메일 전송: smtplib.sendmail()
```

---

## 데이터 흐름 분석 실습

다음 코드를 수동으로 분석해봅시다.

```python
# 분석 대상 Flask 앱 (취약한 코드)
from flask import Flask, request, render_template_string
import sqlite3
import subprocess

app = Flask(__name__)

@app.route("/search")
def search():
    # [소스] 사용자 입력
    keyword = request.args.get("q", "")

    # [변환 없음! 검증 없음!]

    # [싱크 1] SQL Injection 취약점
    conn = sqlite3.connect("products.db")
    query = f"SELECT name, price FROM products WHERE name LIKE '%{keyword}%'"
    results = conn.execute(query).fetchall()

    # [싱크 2] XSS 취약점 — render_template_string에 직접 삽입
    template = f"""
    <h1>검색 결과: {keyword}</h1>
    <ul>
    {"".join(f"<li>{r[0]} - {r[1]}원</li>" for r in results)}
    </ul>
    """
    return render_template_string(template)  # XSS!


@app.route("/ping")
def ping():
    # [소스] 사용자 입력
    host = request.args.get("host", "")

    # [싱크 3] Command Injection 취약점
    result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True)
    return result.stdout.decode()
```

### 분석 결과 매핑

```
취약점 1: SQL Injection (심각도: HIGH)
  소스: request.args.get("q")
  경로: keyword → f-string 삽입
  싱크: conn.execute(query)
  패치: 파라미터화된 쿼리 사용

취약점 2: XSS (심각도: HIGH)
  소스: request.args.get("q")
  경로: keyword → f-string 삽입 → render_template_string
  싱크: HTTP 응답 본문
  패치: html.escape() 또는 {{ keyword | e }} 사용

취약점 3: Command Injection (심각도: CRITICAL)
  소스: request.args.get("host")
  경로: host → f-string 삽입
  싱크: subprocess.run(..., shell=True)
  패치: 리스트 인자 방식 + shell=False
```

---

## 역방향 추적 (Sink-First Analysis)

역방향 분석은 위험한 함수에서 시작하여 데이터 출처를 역추적합니다.

```python
#!/usr/bin/env python3
"""
코드에서 위험 싱크 함수의 호출 경로를 역추적하는 도우미
Python 3.10+, 타입 힌트, argparse 포함
"""

import ast
import argparse
import sys
from pathlib import Path
from dataclasses import dataclass


# 추적할 싱크 함수/메서드 목록
SINK_PATTERNS: dict[str, str] = {
    "execute": "SQL 실행 (SQL Injection 가능)",
    "system": "OS 명령 실행 (Command Injection 가능)",
    "loads": "역직렬화 (RCE 가능)",
    "render_template_string": "템플릿 렌더링 (SSTI/XSS 가능)",
    "open": "파일 작업 (Path Traversal 가능)",
    "eval": "코드 실행 (RCE)",
    "exec": "코드 실행 (RCE)",
}


@dataclass
class SinkCall:
    function_name: str
    line_number: int
    col_offset: int
    source_line: str
    risk: str


class SinkFinder(ast.NodeVisitor):
    """AST를 순회하여 싱크 함수 호출을 탐색합니다."""

    def __init__(self, source_lines: list[str]) -> None:
        self.source_lines = source_lines
        self.findings: list[SinkCall] = []

    def visit_Call(self, node: ast.Call) -> None:
        func_name = self._get_func_name(node)
        if func_name in SINK_PATTERNS:
            line_content = ""
            if 0 < node.lineno <= len(self.source_lines):
                line_content = self.source_lines[node.lineno - 1].strip()

            self.findings.append(
                SinkCall(
                    function_name=func_name,
                    line_number=node.lineno,
                    col_offset=node.col_offset,
                    source_line=line_content,
                    risk=SINK_PATTERNS[func_name],
                )
            )
        self.generic_visit(node)

    def _get_func_name(self, node: ast.Call) -> str:
        """함수 호출 노드에서 함수 이름 추출"""
        match node.func:
            case ast.Name(id=name):
                return name
            case ast.Attribute(attr=attr):
                return attr
            case _:
                return ""


def analyze_file(file_path: Path) -> list[SinkCall]:
    """Python 파일의 싱크 호출 분석"""
    try:
        source = file_path.read_text(encoding="utf-8")
        tree = ast.parse(source)
    except (OSError, SyntaxError) as e:
        print(f"[!] 분석 실패 {file_path}: {e}", file=sys.stderr)
        return []

    finder = SinkFinder(source.splitlines())
    finder.visit(tree)
    return finder.findings


def main() -> None:
    parser = argparse.ArgumentParser(
        description="역방향 데이터 흐름 분석 — 위험 싱크 탐색기",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="예시:\n  python3 sink_finder.py app.py\n  python3 sink_finder.py ./src",
    )
    parser.add_argument("path", help="분석할 파일 또는 디렉토리")
    parser.add_argument(
        "--sink",
        help="특정 싱크 함수만 검색 (예: execute)",
    )
    args = parser.parse_args()

    target = Path(args.path)
    if not target.exists():
        print(f"[-] 경로를 찾을 수 없습니다: {target}", file=sys.stderr)
        sys.exit(1)

    all_findings: list[tuple[Path, SinkCall]] = []

    if target.is_file():
        files = [target]
    else:
        files = list(target.rglob("*.py"))

    for file_path in files:
        findings = analyze_file(file_path)
        for f in findings:
            if args.sink is None or args.sink == f.function_name:
                all_findings.append((file_path, f))

    print(f"\n[*] 싱크 탐색 완료 — {len(files)}개 파일, {len(all_findings)}개 위험 호출 발견\n")

    for file_path, finding in all_findings:
        print(f"[!] {finding.risk}")
        print(f"    파일: {file_path}:{finding.line_number}")
        print(f"    코드: {finding.source_line}")
        print()


if __name__ == "__main__":
    main()
```

---

## 코드 리뷰 체크리스트

### 웹 애플리케이션

```
입력 검증
  □ 모든 사용자 입력에 대한 서버 측 검증 존재?
  □ 화이트리스트 방식의 입력 검증 사용?
  □ 파일 업로드 시 MIME 타입 및 확장자 검증?

인증 (Authentication)
  □ 패스워드 bcrypt/Argon2로 해싱? (MD5/SHA1 금지)
  □ 기본 계정(admin/admin) 존재하지 않음?
  □ 비밀번호 재설정 토큰의 만료 시간 설정?
  □ 다단계 인증(MFA) 구현 여부?

인가 (Authorization)
  □ 모든 엔드포인트에 인증 확인?
  □ 수평적 권한 상승 방지 (다른 사용자 데이터 접근)?
  □ 수직적 권한 상승 방지 (관리자 기능 접근)?

세션 관리
  □ 세션 ID가 암호학적으로 안전한 난수?
  □ 로그인 후 세션 ID 재생성?
  □ 세션 만료 시간 설정?
  □ HttpOnly, Secure, SameSite 쿠키 속성?
```

### API 보안

```
□ API 키/토큰이 헤더로 전달되는가? (URL 쿼리 파라미터 금지)
□ Rate Limiting 구현?
□ 민감한 데이터가 응답에 불필요하게 포함되지 않는가?
□ CORS 정책이 와일드카드(*)가 아닌가?
□ JWT 서명 알고리즘이 "none"을 허용하지 않는가?
```

### 암호화

```
□ 전송 중 암호화: TLS 1.2+ 사용?
□ 저장 시 암호화: AES-256 또는 동급?
□ 하드코딩된 키/비밀이 없는가?
□ 랜덤 값 생성 시 secrets 모듈 사용 (random 금지)?
□ 취약한 알고리즘(DES, RC4, MD5) 사용 금지?
```

---

<!-- validate-74 -->
## 발견의 익스플로잇 가능성 확인

수동 리뷰로 의심 지점을 찾았다면, **"이론적으로 위험"과 "실제로 악용 가능"을 구분**해야 합니다. full data-flow를 추적해 방어가 없는지 확인하는 단계입니다.

| 확인 | 방법 | 판정 |
|---|---|---|
| 전체 경로 | source→...→sink 변수 추적 | 경로가 이어지는가 |
| 가드 | 중간 검증/권한 체크 유무 | 막는 게 없으면 위험 |
| 전제 조건 | 인증·역할·특정 입력 필요? | 현실적 도달성 |
| 영향 | 성공 시 무엇이 가능? | 심각도 산정 |

### 익스플로잇 가능성 검증 (직접)

```text
수동 발견 확정 절차:
  □ 미신뢰 입력에서 sink까지 변수 흐름을 끝까지 그렸는가?
  □ 경로상 검증/이스케이프/권한체크가 정말 없는가?
  □ 악용에 필요한 전제(로그인 등)가 현실적인가?
  □ 가능하면 통제된 환경에서 무해한 PoC로 재현했는가?
```

> 핵심: 수동 리뷰의 강점은 도구가 못 보는 맥락이지만, **그 발견도 데이터 흐름으로 검증**해야 합니다. "위험해 보임"에서 멈추지 말고 도달성과 방어 부재를 확인해 이론과 실증을 가르세요([[68_Purple_Team]]).

---

## 참고 자료

- OWASP Code Review Guide: https://owasp.org/www-project-code-review-guide/

---

<a name="english"></a>

# Manual Code Review Techniques

## Why Manual Review is Necessary

Static analysis tools are powerful but limited. Business logic flaws, access control errors, and complex multi-step authentication bypasses often escape automated tools. Human reasoning is indispensable.

Manual code review proceeds in two directions.

```
Forward: Source → Sink
  "Where does external input flow?"
  User input → transform/validate? → DB query / OS command / file / response

Backward: Sink → Source
  "Where does a dangerous function receive its data?"
  cursor.execute() → where does data come from? → is it user input?
```

---

## Source and Sink Concepts

**Sources:** Points where external data enters the program
```
- HTTP request params: request.args.get(), request.form[], request.json
- Cookies/Headers: request.cookies, request.headers
- File uploads: request.files
- Environment variables: os.environ.get()
- Database reads (data another user inserted)
```

**Sinks:** Dangerous points where input is executed or output
```
- SQL execution: cursor.execute(), query()
- OS commands: os.system(), subprocess.run()
- File operations: open(), Path.write()
- HTML rendering: render_template() — XSS possible
- Deserialization: pickle.loads(), yaml.load()
- External requests: requests.get()
```

---

## Data Flow Analysis Example

```python
# Vulnerable Flask app for analysis
from flask import Flask, request, render_template_string
import sqlite3
import subprocess

app = Flask(__name__)

@app.route("/search")
def search():
    # [SOURCE] User input — no validation
    keyword = request.args.get("q", "")

    # [SINK 1] SQL Injection
    conn = sqlite3.connect("products.db")
    query = f"SELECT name, price FROM products WHERE name LIKE '%{keyword}%'"
    results = conn.execute(query).fetchall()

    # [SINK 2] XSS — keyword inserted directly into template
    template = f"<h1>Results for: {keyword}</h1>"
    return render_template_string(template)

@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    # [SINK 3] Command Injection
    result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True)
    return result.stdout.decode()
```

### Vulnerability Map

```
Vuln 1: SQL Injection (Severity: HIGH)
  Source: request.args.get("q")
  Path:   keyword → f-string interpolation
  Sink:   conn.execute(query)
  Fix:    Use parameterized queries

Vuln 2: XSS (Severity: HIGH)
  Source: request.args.get("q")
  Path:   keyword → f-string → render_template_string
  Sink:   HTTP response body
  Fix:    html.escape() or Jinja2 auto-escape

Vuln 3: Command Injection (Severity: CRITICAL)
  Source: request.args.get("host")
  Path:   host → f-string
  Sink:   subprocess.run(..., shell=True)
  Fix:    List args + shell=False
```

---

## Sink-First (Backward) Analysis Tool

```python
#!/usr/bin/env python3
"""
Backward data-flow analysis — finds dangerous sink function calls
in Python source code using the AST.
Python 3.10+, with type hints and argparse
"""

import ast
import argparse
import sys
from pathlib import Path
from dataclasses import dataclass


SINK_PATTERNS: dict[str, str] = {
    "execute": "SQL execution (SQL Injection risk)",
    "system": "OS command (Command Injection risk)",
    "loads": "Deserialization (RCE risk)",
    "render_template_string": "Template rendering (SSTI/XSS risk)",
    "eval": "Code execution (RCE)",
    "exec": "Code execution (RCE)",
}


@dataclass
class SinkCall:
    function_name: str
    line_number: int
    source_line: str
    risk: str


class SinkFinder(ast.NodeVisitor):
    def __init__(self, source_lines: list[str]) -> None:
        self.source_lines = source_lines
        self.findings: list[SinkCall] = []

    def visit_Call(self, node: ast.Call) -> None:
        func_name = self._get_func_name(node)
        if func_name in SINK_PATTERNS:
            line_content = ""
            if 0 < node.lineno <= len(self.source_lines):
                line_content = self.source_lines[node.lineno - 1].strip()
            self.findings.append(
                SinkCall(func_name, node.lineno, line_content, SINK_PATTERNS[func_name])
            )
        self.generic_visit(node)

    def _get_func_name(self, node: ast.Call) -> str:
        match node.func:
            case ast.Name(id=name):
                return name
            case ast.Attribute(attr=attr):
                return attr
            case _:
                return ""


def analyze_file(file_path: Path) -> list[SinkCall]:
    try:
        source = file_path.read_text(encoding="utf-8")
        tree = ast.parse(source)
    except (OSError, SyntaxError) as e:
        print(f"[!] Failed to analyze {file_path}: {e}", file=sys.stderr)
        return []
    finder = SinkFinder(source.splitlines())
    finder.visit(tree)
    return finder.findings


def main() -> None:
    parser = argparse.ArgumentParser(description="Backward data-flow sink finder")
    parser.add_argument("path", help="File or directory to analyze")
    parser.add_argument("--sink", help="Filter by specific sink function name")
    args = parser.parse_args()

    target = Path(args.path)
    if not target.exists():
        print(f"[-] Path not found: {target}", file=sys.stderr)
        sys.exit(1)

    files = [target] if target.is_file() else list(target.rglob("*.py"))
    all_findings: list[tuple[Path, SinkCall]] = []

    for fp in files:
        for finding in analyze_file(fp):
            if args.sink is None or args.sink == finding.function_name:
                all_findings.append((fp, finding))

    print(f"\n[*] Scanned {len(files)} files — {len(all_findings)} dangerous sink calls found\n")
    for file_path, finding in all_findings:
        print(f"[!] {finding.risk}")
        print(f"    File: {file_path}:{finding.line_number}")
        print(f"    Code: {finding.source_line}\n")


if __name__ == "__main__":
    main()
```

---

## Code Review Checklist

### Web Application

```
Input Validation
  □ Server-side validation for all user inputs?
  □ Whitelist-based input validation?
  □ File uploads validated by MIME type and extension?

Authentication
  □ Passwords hashed with bcrypt/Argon2? (MD5/SHA1 forbidden)
  □ No default credentials (admin/admin)?
  □ Password reset tokens have expiry?

Authorization
  □ Authentication check on all endpoints?
  □ Horizontal privilege escalation prevented?
  □ Vertical privilege escalation prevented?

Session Management
  □ Session IDs generated with cryptographically secure randomness?
  □ Session ID regenerated after login?
  □ HttpOnly, Secure, SameSite cookie flags set?
```

### API Security

```
□ API keys/tokens sent in headers (not URL params)?
□ Rate limiting implemented?
□ Sensitive data not unnecessarily included in responses?
□ CORS not set to wildcard (*)?
□ JWT signature algorithm does not allow "none"?
```

### Cryptography

```
□ TLS 1.2+ for data in transit?
□ AES-256 or equivalent for data at rest?
□ No hardcoded keys or secrets?
□ Python secrets module used for random values (not random module)?
□ Weak algorithms (DES, RC4, MD5) avoided?
```

---

## References

- OWASP Code Review Guide: https://owasp.org/www-project-code-review-guide/

## Confirming the Exploitability of a Finding

Once manual review flags a suspect spot, you must **separate "theoretically risky" from "actually exploitable"** by tracing the full data flow and confirming no defense exists.

| Check | Method | Verdict |
|---|---|---|
| Full path | Trace variables source->...->sink | Does the path connect? |
| Guards | Any intermediate validation/authz | If nothing blocks, risky |
| Preconditions | Auth/role/specific input needed? | Realistic reachability |
| Impact | What's possible on success? | Severity rating |

### Exploitability validation (do it yourself)

```text
Confirming a manual finding:
  [ ] Did you draw the variable flow from untrusted input all the way to the sink?
  [ ] Is there really no validation/escaping/authz on the path?
  [ ] Are the preconditions for exploitation (login, etc.) realistic?
  [ ] If possible, reproduced with a harmless PoC in a controlled environment?
```

> Core: manual review's strength is context the tools miss, but **that finding must also be validated by data flow**. Don't stop at "looks risky" — confirm reachability and the absence of defenses to separate theory from proof (see [[68_Purple_Team]]).
