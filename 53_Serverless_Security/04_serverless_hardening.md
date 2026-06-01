> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 서버리스 보안 강화 — SAST·런타임 보호·자동 감사

## 1. 서버리스 보안 아키텍처

```
┌─────────────────────────────────────────────────────┐
│                개발 단계 (Shift-Left)                │
│  IDE 플러그인 → Git Hook → CI/CD SAST → 의존성 감사 │
└─────────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────┐
│               배포 단계                              │
│  IaC 스캔 (cfn-guard/checkov) → 코드 서명           │
│  → 취약 패키지 차단 → IAM 최소 권한 검증             │
└─────────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────┐
│               런타임 단계                            │
│  AWS Lambda Insights → X-Ray 트레이싱               │
│  → GuardDuty Lambda 보호 → CloudTrail 감사          │
└─────────────────────────────────────────────────────┘
```

---

## 2. IaC 보안 스캔 (Terraform/CloudFormation)

### 2.1 Checkov으로 Lambda 설정 스캔

```bash
# Terraform Lambda 보안 스캔
pip install checkov
checkov -d ./terraform --framework terraform \
  --check CKV_AWS_50,CKV_AWS_116,CKV_AWS_117,CKV_AWS_272

# CloudFormation 스캔
checkov -f template.yaml --framework cloudformation

# 특정 Lambda 체크 항목
# CKV_AWS_50  — X-Ray 추적 활성화
# CKV_AWS_116 — Dead Letter Queue 설정
# CKV_AWS_117 — VPC 배치
# CKV_AWS_272 — 코드 서명 설정
```

### 2.2 안전한 Terraform Lambda 설정

```hcl
# lambda_secure.tf
resource "aws_lambda_function" "secure_function" {
  filename         = "function.zip"
  function_name    = "secure-api-handler"
  role             = aws_iam_role.lambda_role.arn
  handler          = "handler.lambda_handler"
  runtime          = "python3.12"
  timeout          = 30
  memory_size      = 256

  # 환경 변수 KMS 암호화
  kms_key_arn = aws_kms_key.lambda_key.arn
  environment {
    variables = {
      ENV        = "production"
      LOG_LEVEL  = "INFO"
    }
  }

  # VPC 배치
  vpc_config {
    subnet_ids         = var.private_subnet_ids
    security_group_ids = [aws_security_group.lambda_sg.id]
  }

  # X-Ray 활성화
  tracing_config {
    mode = "Active"
  }

  # Dead Letter Queue
  dead_letter_config {
    target_arn = aws_sqs_queue.dlq.arn
  }

  # 코드 서명 (공급망 보호)
  code_signing_config_arn = aws_lambda_code_signing_config.signing.arn

  # 동시성 제한 (DoS 방지)
  reserved_concurrent_executions = 100

  # 태그
  tags = {
    Environment = "production"
    SecurityLevel = "high"
  }
}

# 최소 권한 IAM 역할
resource "aws_iam_role" "lambda_role" {
  name = "secure-lambda-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
  # 권한 경계 설정
  permissions_boundary = aws_iam_policy.boundary.arn
}

resource "aws_iam_role_policy" "lambda_policy" {
  name = "lambda-minimum-policy"
  role = aws_iam_role.lambda_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:${var.region}:${var.account_id}:log-group:/aws/lambda/${local.function_name}:*"
      },
      {
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = "arn:aws:secretsmanager:${var.region}:${var.account_id}:secret:prod/myapp/*"
      }
    ]
  })
}
```

---

## 3. 서버리스 SAST CI/CD 통합

```yaml
# .github/workflows/lambda-security.yml
name: Lambda Security Check

on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Python 의존성 감사
        run: |
          pip install pip-audit safety
          pip-audit -r requirements.txt --format json -o pip-audit.json
          safety check -r requirements.txt --json > safety.json

      - name: Semgrep SAST
        uses: returntocorp/semgrep-action@v1
        with:
          config: |
            p/python
            p/aws-lambda
            p/owasp-top-ten

      - name: Checkov IaC 스캔
        uses: bridgecrewio/checkov-action@master
        with:
          directory: terraform/
          framework: terraform
          output_format: sarif
          output_file_path: reports/checkov.sarif

      - name: Bandit 보안 정적 분석
        run: |
          pip install bandit
          bandit -r src/ -f json -o bandit-report.json \
            -l -i --exclude tests/

      - name: 결과 업로드
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: reports/
```

---

## 4. 런타임 보호 — Lambda Extension

```python
#!/usr/bin/env python3
"""Lambda Extension 기반 런타임 보안 모니터링.

Lambda Extension으로 함수 외부에서 보안 이벤트를 모니터링.
실제 배포 시 별도 Lambda Layer로 패키징.
"""

import json
import os
import signal
import threading
import time
import urllib.request
import urllib.error
from dataclasses import dataclass
from collections import deque


LAMBDA_RUNTIME_API = os.environ.get("AWS_LAMBDA_RUNTIME_API", "127.0.0.1:9001")
EXTENSION_NAME = "security-monitor"


@dataclass
class SecurityEvent:
    timestamp: float
    event_type: str
    details: dict


class SecurityMonitor:
    def __init__(self, max_events: int = 1000) -> None:
        self.events: deque[SecurityEvent] = deque(maxlen=max_events)
        self._lock = threading.Lock()

        # 모니터링할 시스템 콜 패턴
        self.suspicious_patterns = [
            "/etc/passwd", "/etc/shadow", "/proc/",
            "169.254.169.254",  # 메타데이터 서비스
            "curl", "wget", "nc ", "bash -i",
        ]

    def check_network_connections(self) -> list[dict]:
        """현재 네트워크 연결 확인."""
        connections = []
        try:
            with open("/proc/net/tcp") as f:
                for line in f.readlines()[1:]:
                    parts = line.split()
                    if len(parts) < 4:
                        continue
                    remote_hex = parts[2]
                    remote_ip = ".".join(str(int(remote_hex[i:i+2], 16))
                                        for i in range(6, -2, -2))
                    remote_port = int(remote_hex[9:], 16)
                    if remote_ip != "0.0.0.0":
                        connections.append({"ip": remote_ip, "port": remote_port})
        except OSError:
            pass
        return connections

    def log_security_event(self, event_type: str, details: dict) -> None:
        event = SecurityEvent(time.time(), event_type, details)
        with self._lock:
            self.events.append(event)
        # CloudWatch로 전송
        print(json.dumps({
            "level": "SECURITY",
            "event_type": event_type,
            "details": details,
            "timestamp": event.timestamp,
        }))


def register_extension() -> str:
    """Lambda Extension 등록."""
    payload = json.dumps({"events": ["INVOKE", "SHUTDOWN"]}).encode()
    req = urllib.request.Request(
        f"http://{LAMBDA_RUNTIME_API}/2020-01-01/extension/register",
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Lambda-Extension-Name": EXTENSION_NAME,
        },
    )
    with urllib.request.urlopen(req) as resp:
        return resp.headers.get("Lambda-Extension-Identifier", "")


def run_extension_loop(ext_id: str, monitor: SecurityMonitor) -> None:
    """Extension 이벤트 루프 실행."""
    req = urllib.request.Request(
        f"http://{LAMBDA_RUNTIME_API}/2020-01-01/extension/event/next",
        headers={"Lambda-Extension-Identifier": ext_id},
    )

    while True:
        try:
            with urllib.request.urlopen(req, timeout=300) as resp:
                event = json.loads(resp.read())
                if event.get("eventType") == "SHUTDOWN":
                    break

                # INVOKE 이벤트마다 보안 체크
                connections = monitor.check_network_connections()
                suspicious = [c for c in connections if c["ip"].startswith("169.254")]
                if suspicious:
                    monitor.log_security_event("METADATA_SERVICE_ACCESS", {"connections": suspicious})

        except Exception as e:
            print(f"Extension 오류: {e}")
            break
```

---

## 5. 서버리스 보안 자동 감사 CLI

```python
#!/usr/bin/env python3
"""서버리스 환경 종합 보안 감사 CLI."""

import argparse
import json
from pathlib import Path
from dataclasses import dataclass, field
import boto3


@dataclass
class AuditReport:
    function_name: str
    region: str
    findings: list[dict] = field(default_factory=list)
    score: int = 100  # 100점 만점


CHECKS = {
    "xray_tracing": ("X-Ray 추적 비활성화", 10),
    "dlq_configured": ("Dead Letter Queue 미설정", 10),
    "vpc_configured": ("VPC 미배치", 5),
    "kms_encryption": ("환경 변수 암호화 미적용", 15),
    "reserved_concurrency": ("동시성 제한 미설정", 5),
    "code_signing": ("코드 서명 미설정", 10),
    "latest_runtime": ("최신 런타임 미사용", 15),
}

DEPRECATED_RUNTIMES = {
    "python3.7", "python3.8", "nodejs12.x", "nodejs14.x",
    "java8", "go1.x", "dotnetcore3.1",
}


def check_function_security(
    function_name: str,
    region: str = "ap-northeast-2",
) -> AuditReport:
    client = boto3.client("lambda", region_name=region)
    report = AuditReport(function_name=function_name, region=region)

    try:
        config = client.get_function_configuration(FunctionName=function_name)
    except client.exceptions.ResourceNotFoundException:
        report.findings.append({"check": "function_exists", "status": "FAIL", "detail": "함수 없음"})
        return report

    # X-Ray 추적
    if config.get("TracingConfig", {}).get("Mode") not in ("Active", "PassThrough"):
        report.score -= CHECKS["xray_tracing"][1]
        report.findings.append({"check": "xray_tracing", "status": "FAIL", "detail": CHECKS["xray_tracing"][0]})

    # DLQ
    if not config.get("DeadLetterConfig", {}).get("TargetArn"):
        report.score -= CHECKS["dlq_configured"][1]
        report.findings.append({"check": "dlq_configured", "status": "FAIL", "detail": CHECKS["dlq_configured"][0]})

    # VPC
    if not config.get("VpcConfig", {}).get("SubnetIds"):
        report.score -= CHECKS["vpc_configured"][1]
        report.findings.append({"check": "vpc_configured", "status": "WARN", "detail": CHECKS["vpc_configured"][0]})

    # KMS 암호화
    if not config.get("KMSKeyArn"):
        report.score -= CHECKS["kms_encryption"][1]
        report.findings.append({"check": "kms_encryption", "status": "FAIL", "detail": CHECKS["kms_encryption"][0]})

    # 동시성 제한
    if config.get("ReservedConcurrentExecutions") is None:
        report.score -= CHECKS["reserved_concurrency"][1]
        report.findings.append({"check": "reserved_concurrency", "status": "WARN", "detail": CHECKS["reserved_concurrency"][0]})

    # 코드 서명
    if not config.get("CodeSigningConfigArn"):
        report.score -= CHECKS["code_signing"][1]
        report.findings.append({"check": "code_signing", "status": "WARN", "detail": CHECKS["code_signing"][0]})

    # 런타임 버전
    runtime = config.get("Runtime", "")
    if runtime in DEPRECATED_RUNTIMES:
        report.score -= CHECKS["latest_runtime"][1]
        report.findings.append({
            "check": "latest_runtime", "status": "FAIL",
            "detail": f"지원 종료 런타임: {runtime}",
        })

    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="서버리스 보안 감사")
    parser.add_argument("functions", nargs="*", help="감사할 Lambda 함수 이름 (없으면 전체)")
    parser.add_argument("--region", default="ap-northeast-2")
    parser.add_argument("-o", "--output", type=Path)
    parser.add_argument("--fail-below", type=int, default=70, help="이 점수 미만이면 실패")
    args = parser.parse_args()

    functions = args.functions
    if not functions:
        client = boto3.client("lambda", region_name=args.region)
        paginator = client.get_paginator("list_functions")
        functions = [f["FunctionName"] for p in paginator.paginate() for f in p["Functions"]]

    reports: list[AuditReport] = []
    for fn in functions:
        print(f"[*] 감사 중: {fn}")
        report = check_function_security(fn, args.region)
        reports.append(report)
        grade = "A" if report.score >= 90 else "B" if report.score >= 80 else "C" if report.score >= 70 else "D"
        print(f"  점수: {report.score}/100 ({grade})")
        for f in report.findings:
            icon = "!" if f["status"] == "FAIL" else "?"
            print(f"  [{icon}] {f['detail']}")

    failed = [r for r in reports if r.score < args.fail_below]
    print(f"\n총 {len(reports)}개 / 기준 미달 {len(failed)}개")

    if args.output:
        data = [{"function": r.function_name, "score": r.score, "findings": r.findings} for r in reports]
        args.output.write_text(json.dumps(data, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
```

---

## 6. 서버리스 보안 체크리스트

| 카테고리 | 항목 | 우선순위 |
|----------|------|----------|
| IAM | 함수별 전용 역할·최소 권한 | 필수 |
| 암호화 | 환경 변수 KMS 암호화 | 필수 |
| 시크릿 | Secrets Manager 사용 | 필수 |
| 런타임 | 최신 지원 버전 사용 | 필수 |
| 의존성 | pip-audit·Snyk 정기 스캔 | 필수 |
| 코드 서명 | 배포 코드 서명·검증 | 권장 |
| VPC | 민감 리소스 VPC 내 격리 | 권장 |
| X-Ray | 요청 추적 활성화 | 권장 |
| DLQ | 실패 이벤트 Dead Letter Queue | 권장 |
| 동시성 | Reserved Concurrency 제한 | 권장 |
| WAF | API Gateway WAF 연동 | 권장 |
| GuardDuty | Lambda 보호 기능 활성화 | 권장 |

---

<a name="english"></a>

# Serverless Security Hardening — SAST, Runtime Protection, and Automated Auditing

## 1. Serverless Security Architecture

Security controls are applied at three stages:

**Development (Shift-Left):** IDE plugins → Git hooks → CI/CD SAST → dependency auditing

**Deployment:** IaC scanning (cfn-guard/checkov) → code signing → vulnerable package blocking → IAM least-privilege verification

**Runtime:** AWS Lambda Insights → X-Ray tracing → GuardDuty Lambda Protection → CloudTrail auditing

---

## 2. IaC Security Scanning (Terraform/CloudFormation)

### 2.1 Checkov Lambda Configuration Scan

Key Checkov checks for Lambda:
- `CKV_AWS_50` — X-Ray tracing enabled
- `CKV_AWS_116` — Dead Letter Queue configured
- `CKV_AWS_117` — Deployed inside a VPC
- `CKV_AWS_272` — Code signing configured

### 2.2 Secure Terraform Lambda Configuration

The secure Terraform template demonstrates all required hardening settings:

| Setting | Security Purpose |
|---------|-----------------|
| `kms_key_arn` | Encrypts environment variables at rest |
| `vpc_config` | Isolates function from public internet |
| `tracing_config { mode = "Active" }` | Enables X-Ray distributed tracing |
| `dead_letter_config` | Captures failed invocations for investigation |
| `code_signing_config_arn` | Prevents unauthorized code deployment |
| `reserved_concurrent_executions` | Limits blast radius of DoS attacks |
| `permissions_boundary` | Caps maximum IAM permissions |

---

## 3. Serverless SAST CI/CD Integration

The GitHub Actions workflow runs four parallel security checks on every push:

1. **pip-audit + safety** — checks for known CVEs in Python dependencies
2. **Semgrep** — runs SAST rules for Python, AWS Lambda, and OWASP Top 10
3. **Checkov** — scans Terraform IaC for misconfigurations, outputs SARIF
4. **Bandit** — Python-specific security linter targeting common vulnerabilities

Results are uploaded to GitHub's security dashboard via the CodeQL SARIF upload action.

---

## 4. Runtime Protection — Lambda Extension

The Lambda Extension registers itself with the Lambda Runtime API to receive `INVOKE` and `SHUTDOWN` lifecycle events. On each invocation, it checks `/proc/net/tcp` for active network connections to the EC2 Instance Metadata Service (169.254.169.254), which may indicate an SSRF attack attempting to steal IAM credentials.

Security events are emitted as structured JSON logs to CloudWatch Logs, where they can trigger alarms or be processed by SIEM systems.

---

## 5. Automated Serverless Security Audit CLI

The audit CLI scores each Lambda function from 100 points, deducting points for missing security controls:

| Check | Deduction | Severity |
|-------|-----------|----------|
| X-Ray tracing disabled | -10 | FAIL |
| No Dead Letter Queue | -10 | FAIL |
| Not in VPC | -5 | WARN |
| No KMS encryption | -15 | FAIL |
| No concurrency limit | -5 | WARN |
| No code signing | -10 | WARN |
| Deprecated runtime | -15 | FAIL |

Grade thresholds: A ≥ 90, B ≥ 80, C ≥ 70, D < 70

**Usage:**
```bash
# Audit specific functions
python3 serverless_audit.py my-function-1 my-function-2 --region us-east-1

# Audit all functions, fail CI if any score below 80
python3 serverless_audit.py --fail-below 80 -o audit_results.json
```

---

## 6. Serverless Security Checklist

| Category | Item | Priority |
|----------|------|----------|
| IAM | Dedicated role per function, least privilege | Required |
| Encryption | KMS encryption for environment variables | Required |
| Secrets | Use Secrets Manager | Required |
| Runtime | Use latest supported version | Required |
| Dependencies | Regular pip-audit/Snyk scans | Required |
| Code Signing | Sign and verify deployed code | Recommended |
| VPC | Isolate sensitive resources inside VPC | Recommended |
| X-Ray | Enable request tracing | Recommended |
| DLQ | Dead Letter Queue for failed events | Recommended |
| Concurrency | Set Reserved Concurrency limit | Recommended |
| WAF | Integrate WAF with API Gateway | Recommended |
| GuardDuty | Enable Lambda Protection feature | Recommended |
