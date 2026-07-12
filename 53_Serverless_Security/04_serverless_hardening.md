> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 서버리스 보안 강화 — SAST·런타임 보호·자동 감사

## 0. 초보자를 위한 개념 이해

### 보안 강화(Hardening)란?

**Hardening**은 시스템의 공격 가능한 취약점을 제거하고, 불필요한 기능을 비활성화하며, 최소한의 권한만 허용해 보안을 높이는 과정입니다.

**비유:** 집의 보안을 강화하는 것과 같습니다:
- 문에 자물쇠 달기 → IAM 최소 권한
- 필요 없는 창문 막기 → 불필요한 트리거/엔드포인트 비활성화
- 방범창 설치 → VPC 격리
- CCTV 설치 → CloudTrail/GuardDuty 모니터링
- 화재 감지기 → Dead Letter Queue + 알림

### 서버리스 보안이 일반 서버와 다른 점

| 항목 | 일반 서버 | 서버리스 |
|------|-----------|----------|
| 서버 패치 | 직접 해야 함 | AWS가 처리 |
| OS 보안 | 직접 설정 | AWS 관리 |
| 네트워크 격리 | 방화벽 규칙 직접 | Security Group / VPC |
| IAM 권한 | OS 사용자 권한 | IAM Role 세밀하게 제어 |
| 코드 보안 | 직접 관리 | 코드 서명으로 검증 가능 |
| 실행 환경 | 고정 서버 | 함수마다 독립 환경 |

### Shift-Left 보안이란?

```
전통적 보안:
개발 → 테스트 → 스테이징 → 배포 → 운영 → [보안 검사]
                                          ↑ 너무 늦음!

Shift-Left 보안:
개발 → 테스트 → 스테이징 → 배포 → 운영
 ↑
[보안 검사 시작] ← 개발 단계부터 보안 확인
```

**왜 중요한가?** 코드가 이미 운영에 배포된 뒤에 취약점을 발견하면 수정 비용이 100배 이상 높아집니다.

---

## 1. 서버리스 보안 아키텍처

```
┌─────────────────────────────────────────────────────┐
│                개발 단계 (Shift-Left)                │
│  IDE 플러그인 → Git Hook → CI/CD SAST → 의존성 감사 │
│  (코딩 중)    (커밋 시)   (PR 시)      (자동 실행)  │
└────────────────────────┬────────────────────────────┘
                         │ 모든 검사 통과 시만 배포
                         ▼
┌─────────────────────────────────────────────────────┐
│               배포 단계                              │
│  IaC 스캔 (cfn-guard/checkov)                       │
│  → Terraform/CloudFormation 보안 설정 검증           │
│  → 코드 서명 (변조 방지)                             │
│  → 취약 패키지 차단                                  │
│  → IAM 최소 권한 검증                               │
└────────────────────────┬────────────────────────────┘
                         │ 안전성 검증 후 배포
                         ▼
┌─────────────────────────────────────────────────────┐
│               런타임 단계                            │
│  AWS Lambda Insights → X-Ray 트레이싱               │
│  (성능 모니터링)        (요청 경로 추적)             │
│  → GuardDuty Lambda 보호 (AI 기반 이상 탐지)        │
│  → CloudTrail 감사 (모든 API 호출 기록)             │
└─────────────────────────────────────────────────────┘
```

**각 단계 설명:**
- **개발 단계**: 코드 작성 중에 보안 문제를 발견 (가장 저렴한 시점)
- **배포 단계**: 인프라 설정이 안전한지 확인 후 배포
- **런타임 단계**: 실제 운영 중 이상 징후 탐지 및 대응

---

## 2. IaC 보안 스캔 (Terraform/CloudFormation)

### IaC(Infrastructure as Code)란?

**IaC**는 서버, 네트워크, 데이터베이스 등의 인프라를 코드로 정의하는 방법입니다. AWS 콘솔 대신 코드로 인프라를 만들고 관리합니다.

```
IaC 없이:
  개발자 A가 AWS 콘솔에서 수동 설정 → 실수 가능, 기록 없음

IaC 사용:
  코드로 인프라 정의 → 버전 관리 → 자동 배포 → 보안 스캔 가능
```

**도구:**
- **Terraform**: HashiCorp의 IaC 도구 (`.tf` 파일)
- **CloudFormation**: AWS 전용 IaC (`.yaml` 또는 `.json`)
- **Checkov**: IaC 보안 스캔 도구 (Terraform/CloudFormation/Kubernetes 지원)

### 2.1 Checkov으로 Lambda 설정 스캔

```bash
# Checkov 설치
pip install checkov

# Terraform Lambda 보안 스캔
# -d: 디렉터리 지정
# --framework: 스캔 대상 형식
# --check: 특정 규칙 ID만 검사
checkov -d ./terraform --framework terraform \
  --check CKV_AWS_50,CKV_AWS_116,CKV_AWS_117,CKV_AWS_272

# CloudFormation 스캔
checkov -f template.yaml --framework cloudformation

# 모든 검사 실행 (권장)
checkov -d . --framework all

# SARIF 형식으로 결과 저장 (GitHub Security와 통합 가능)
checkov -d . --output sarif --output-file-path results.sarif
```

**주요 Lambda 보안 검사 규칙:**
| 규칙 ID | 검사 내용 | 왜 중요한가 |
|---------|-----------|------------|
| `CKV_AWS_50` | X-Ray 추적 활성화 | 공격 경로 추적 가능 |
| `CKV_AWS_116` | Dead Letter Queue 설정 | 실패 이벤트 유실 방지, 나중에 분석 가능 |
| `CKV_AWS_117` | VPC 배치 | 공개 인터넷 접근 차단 |
| `CKV_AWS_272` | 코드 서명 설정 | 허가되지 않은 코드 배포 방지 |

### 2.2 안전한 Terraform Lambda 설정 (모든 보안 옵션 포함)

```hcl
# lambda_secure.tf
# 이 파일은 Lambda 함수의 모든 보안 설정을 포함한 예시입니다.
# 각 설정의 보안 목적을 주석으로 설명합니다.

resource "aws_lambda_function" "secure_function" {
  filename         = "function.zip"
  function_name    = "secure-api-handler"
  role             = aws_iam_role.lambda_role.arn
  handler          = "handler.lambda_handler"
  runtime          = "python3.12"  # 항상 최신 지원 버전 사용
  timeout          = 30            # 짧게 설정 (긴 실행 시간은 공격 신호)
  memory_size      = 256

  # [보안] 환경 변수를 KMS로 암호화
  # KMS 없으면 AWS 콘솔에서 환경 변수가 평문으로 노출됨
  kms_key_arn = aws_kms_key.lambda_key.arn
  environment {
    variables = {
      ENV       = "production"
      LOG_LEVEL = "INFO"
      # 절대 여기에 비밀번호, API 키 넣지 말 것!
      # 대신 Secrets Manager ARN을 넣고 런타임에 가져오기
    }
  }

  # [보안] VPC 배치: 공개 인터넷 차단, 사설 서브넷에서 실행
  # VPC 없으면 Lambda가 인터넷에 직접 노출됨
  vpc_config {
    subnet_ids         = var.private_subnet_ids
    security_group_ids = [aws_security_group.lambda_sg.id]
  }

  # [보안] X-Ray 추적 활성화
  # 요청이 어떤 경로로 처리됐는지 추적 가능
  # 침해 발생 시 공격 경로 재구성에 필수
  tracing_config {
    mode = "Active"  # "Active" = 모든 요청 샘플링 / "PassThrough" = 부모 결정
  }

  # [보안] Dead Letter Queue 설정
  # 처리 실패한 이벤트를 보존해서 나중에 분석 가능
  # DLQ 없으면 실패 이벤트가 영구 유실됨
  dead_letter_config {
    target_arn = aws_sqs_queue.dlq.arn
  }

  # [보안] 코드 서명: 공급망 보호
  # 서명된 코드만 배포 가능 → 악성 코드 삽입 방지
  code_signing_config_arn = aws_lambda_code_signing_config.signing.arn

  # [보안] 동시성 제한: DoS 공격 피해 범위 제한
  # 무한 동시 실행을 막아 비용 폭탄과 DoS 방지
  reserved_concurrent_executions = 100

  tags = {
    Environment  = "production"
    SecurityLevel = "high"
    DataClass    = "confidential"  # 데이터 분류 태그
  }
}

# [보안] 최소 권한 IAM 역할
# Lambda 함수에 필요한 최소 권한만 부여
resource "aws_iam_role" "lambda_role" {
  name = "secure-lambda-role"
  
  # Lambda 서비스만 이 역할 사용 가능
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
  
  # [보안] 권한 경계(Permissions Boundary): 역할이 가질 수 있는 최대 권한 제한
  # 실수로 관리자 권한 부여해도 경계 범위를 초과할 수 없음
  permissions_boundary = aws_iam_policy.boundary.arn
}

# [보안] 최소 권한 정책: 필요한 작업만 허용
resource "aws_iam_role_policy" "lambda_policy" {
  name = "lambda-minimum-policy"
  role = aws_iam_role.lambda_role.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # CloudWatch Logs: 이 함수의 로그 그룹만 접근 가능
        # "logs:*"나 "*:*" 금지 — 다른 함수 로그에 접근 불가
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:${var.region}:${var.account_id}:log-group:/aws/lambda/${local.function_name}:*"
      },
      {
        # Secrets Manager: 특정 경로의 시크릿만 접근 가능
        # "secretsmanager:*"나 "*" 금지 — 모든 시크릿 접근 불가
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = "arn:aws:secretsmanager:${var.region}:${var.account_id}:secret:prod/myapp/*"
      }
    ]
  })
}

# [보안] KMS 키: 환경 변수 암호화용
resource "aws_kms_key" "lambda_key" {
  description             = "Lambda 환경 변수 암호화 키"
  deletion_window_in_days = 30  # 키 삭제 전 30일 대기
  enable_key_rotation     = true  # 1년마다 자동 키 교체
  
  tags = {
    Purpose = "lambda-encryption"
  }
}

# [보안] Dead Letter Queue
resource "aws_sqs_queue" "dlq" {
  name                      = "lambda-dlq"
  message_retention_seconds = 1209600  # 14일 보존
  
  # DLQ도 암호화
  kms_master_key_id = aws_kms_key.lambda_key.id
}
```

---

## 3. 서버리스 SAST CI/CD 통합

### CI/CD란?

- **CI (Continuous Integration)**: 코드를 자주 통합하고 자동으로 빌드/테스트
- **CD (Continuous Deployment)**: 테스트 통과 시 자동으로 배포

**보안 게이트 (Security Gate):**
코드가 배포되기 전에 반드시 통과해야 하는 보안 검사 관문입니다.

```yaml
# .github/workflows/lambda-security.yml
# GitHub Actions를 이용한 Lambda 보안 검사 자동화
# 모든 push와 PR에서 실행됨

name: Lambda Security Check

on:
  push:
    branches: [main, develop]  # main, develop 브랜치 push 시 실행
  pull_request:
    branches: [main]           # main으로의 PR 시 실행

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4  # 코드 체크아웃

      # 1단계: Python 의존성 취약점 감사
      # pip-audit: PyPA 공식 감사 도구 (CVE 데이터베이스 기반)
      # safety: Snyk의 파이썬 보안 DB 사용
      - name: Python 의존성 감사
        run: |
          pip install pip-audit safety
          pip-audit -r requirements.txt --format json -o pip-audit.json
          safety check -r requirements.txt --json > safety.json
        # 알려진 취약점이 있는 패키지 사용 시 빌드 실패

      # 2단계: Semgrep 정적 분석
      # p/python: 파이썬 일반 규칙
      # p/aws-lambda: Lambda 특화 규칙
      # p/owasp-top-ten: OWASP Top 10 규칙
      - name: Semgrep SAST
        uses: returntocorp/semgrep-action@v1
        with:
          config: |
            p/python
            p/aws-lambda
            p/owasp-top-ten

      # 3단계: Checkov IaC 스캔
      # Terraform 설정의 보안 오류 탐지
      - name: Checkov IaC 스캔
        uses: bridgecrewio/checkov-action@master
        with:
          directory: terraform/
          framework: terraform
          output_format: sarif            # GitHub Security Dashboard용 형식
          output_file_path: reports/checkov.sarif

      # 4단계: Bandit Python 보안 정적 분석
      # -l: 낮은 심각도 이상만 보고
      # -i: 낮은 신뢰도 이상만 보고
      # --exclude tests/: 테스트 코드 제외
      - name: Bandit 보안 정적 분석
        run: |
          pip install bandit
          bandit -r src/ -f json -o bandit-report.json \
            -l -i --exclude tests/

      # 결과를 GitHub Security Dashboard에 업로드
      # Pull Request에서 인라인으로 보안 경고 표시됨
      - name: 결과 업로드
        uses: github/codeql-action/upload-sarif@v3
        if: always()  # 이전 단계 실패해도 항상 업로드
        with:
          sarif_file: reports/
```

**각 도구의 역할:**
| 도구 | 탐지 대상 | 속도 |
|------|-----------|------|
| pip-audit | 알려진 CVE 있는 패키지 | 빠름 |
| safety | 보안 취약점 있는 패키지 | 빠름 |
| Semgrep | 코드 패턴 (OWASP, Lambda) | 중간 |
| Checkov | IaC 보안 오설정 | 중간 |
| Bandit | Python 특화 보안 패턴 | 빠름 |

---

## 4. 런타임 보호 — Lambda Extension

### Lambda Extension이란?

Lambda Extension은 Lambda 함수와 함께 실행되는 **사이드카 프로세스**입니다. 함수 코드를 수정하지 않고도 모니터링, 로깅, 보안 검사를 추가할 수 있습니다.

**비유:** 경호원이 함께 다니는 것처럼, Extension이 Lambda 함수의 모든 실행을 감시합니다.

```
Lambda 실행 환경:
  ┌─────────────────────────────────┐
  │  Lambda 함수 코드 (실제 로직)    │
  │  (handler.py)                   │
  │  + Extension (보안 모니터)       │
  │  (security_monitor.py)          │
  └─────────────────────────────────┘
  ↓
  Extension이 네트워크 연결, 시스템 콜 등을 모니터링
```

```python
#!/usr/bin/env python3
"""Lambda Extension 기반 런타임 보안 모니터링.

Lambda Extension으로 함수 외부에서 보안 이벤트를 모니터링.
실제 배포 시 별도 Lambda Layer로 패키징.

작동 방식:
1. Extension이 Lambda Runtime API에 등록
2. INVOKE 이벤트마다 보안 체크 실행
3. 이상 탐지 시 CloudWatch에 보안 이벤트 로깅
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


# Lambda Runtime API 주소: Lambda 환경 내부 통신용
LAMBDA_RUNTIME_API = os.environ.get("AWS_LAMBDA_RUNTIME_API", "127.0.0.1:9001")
EXTENSION_NAME = "security-monitor"


@dataclass
class SecurityEvent:
    """보안 이벤트 데이터 클래스."""
    timestamp: float
    event_type: str
    details: dict


class SecurityMonitor:
    """Lambda 함수 런타임 보안 모니터.
    
    - 네트워크 연결 모니터링 (SSRF, C2 통신 탐지)
    - EC2 메타데이터 서비스 접근 탐지
    - 의심스러운 시스템 활동 로깅
    """
    
    def __init__(self, max_events: int = 1000) -> None:
        # deque: 최대 크기 초과 시 오래된 항목 자동 제거 (메모리 안전)
        self.events: deque[SecurityEvent] = deque(maxlen=max_events)
        self._lock = threading.Lock()

        # 모니터링할 의심 패턴들
        self.suspicious_patterns = [
            "/etc/passwd", "/etc/shadow", "/proc/",
            "169.254.169.254",  # AWS EC2 메타데이터 서비스 IP
            "curl", "wget", "nc ",  # 네트워크 도구
            "bash -i",  # 리버스 쉘 패턴
        ]

    def check_network_connections(self) -> list[dict]:
        """/proc/net/tcp에서 현재 네트워크 연결 확인.
        
        169.254.169.254 연결 = IMDSv1 자격증명 탈취 시도 (SSRF)
        알 수 없는 외부 IP = 데이터 유출 또는 C2 통신
        """
        connections = []
        try:
            with open("/proc/net/tcp") as f:
                for line in f.readlines()[1:]:  # 헤더 줄 건너뜀
                    parts = line.split()
                    if len(parts) < 4:
                        continue
                    # /proc/net/tcp의 원격 주소: 16진수 리틀엔디안 형식
                    remote_hex = parts[2]
                    # IP 주소 변환: hex → decimal (바이트 역순)
                    remote_ip = ".".join(str(int(remote_hex[i:i+2], 16))
                                        for i in range(6, -2, -2))
                    remote_port = int(remote_hex[9:], 16)
                    if remote_ip != "0.0.0.0":
                        connections.append({"ip": remote_ip, "port": remote_port})
        except OSError:
            pass
        return connections

    def log_security_event(self, event_type: str, details: dict) -> None:
        """보안 이벤트를 메모리와 CloudWatch에 기록."""
        event = SecurityEvent(time.time(), event_type, details)
        with self._lock:
            self.events.append(event)
        # CloudWatch에 구조화된 JSON으로 로깅
        # SIEM 시스템이 이 로그를 파싱해서 알림 발생 가능
        print(json.dumps({
            "level": "SECURITY",
            "event_type": event_type,
            "details": details,
            "timestamp": event.timestamp,
        }))


def register_extension() -> str:
    """Lambda Extension 등록.
    
    Extension은 Lambda 함수가 시작될 때 Runtime API에 등록해야 합니다.
    등록 후 받은 Extension ID로 이후 통신합니다.
    """
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
    """Extension 이벤트 루프 실행.
    
    Lambda 함수 호출(INVOKE)마다 보안 검사 실행.
    SHUTDOWN 이벤트 수신 시 종료.
    """
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

                # 매 호출마다 보안 체크 실행
                connections = monitor.check_network_connections()
                
                # 169.254.x.x = AWS 메타데이터 서비스 접근 시도
                # IMDSv1 SSRF 공격으로 IAM 자격증명 탈취 시도 신호
                suspicious = [c for c in connections if c["ip"].startswith("169.254")]
                if suspicious:
                    monitor.log_security_event(
                        "METADATA_SERVICE_ACCESS",
                        {"connections": suspicious, "severity": "HIGH"}
                    )

        except Exception as e:
            print(f"Extension 오류: {e}")
            break
```

**Extension 패키징 및 배포:**
```bash
# Lambda Layer로 패키징
mkdir -p extensions
cp security_monitor.py extensions/
chmod +x extensions/security_monitor.py

zip -r security_extension.zip extensions/

# AWS CLI로 Layer 생성
aws lambda publish-layer-version \
  --layer-name security-monitor \
  --zip-file fileb://security_extension.zip \
  --compatible-runtimes python3.12

# 함수에 Layer 추가
aws lambda update-function-configuration \
  --function-name my-function \
  --layers arn:aws:lambda:ap-northeast-2:123456789:layer:security-monitor:1
```

---

## 5. 서버리스 보안 자동 감사 CLI

### 보안 점수 시스템 이해하기

각 Lambda 함수를 100점 만점으로 채점해서 보안 수준을 정량화합니다. 이를 통해 어떤 함수가 가장 위험한지, 어떤 설정이 빠져 있는지 파악할 수 있습니다.

```python
#!/usr/bin/env python3
"""서버리스 환경 종합 보안 감사 CLI.

Lambda 함수들의 보안 설정을 자동으로 감사하고 점수를 매깁니다.
CI/CD 파이프라인에 통합하거나 정기 감사에 활용합니다.
"""

import argparse
import json
from pathlib import Path
from dataclasses import dataclass, field
import boto3


@dataclass
class AuditReport:
    """Lambda 함수 보안 감사 결과."""
    function_name: str
    region: str
    findings: list[dict] = field(default_factory=list)
    score: int = 100  # 100점에서 시작, 문제 발견 시 감점


# 검사 항목 및 배점
# (설명, 감점)
CHECKS = {
    "xray_tracing":         ("X-Ray 추적 비활성화", 10),
    "dlq_configured":       ("Dead Letter Queue 미설정", 10),
    "vpc_configured":       ("VPC 미배치", 5),
    "kms_encryption":       ("환경 변수 암호화 미적용", 15),
    "reserved_concurrency": ("동시성 제한 미설정", 5),
    "code_signing":         ("코드 서명 미설정", 10),
    "latest_runtime":       ("최신 런타임 미사용", 15),
}

# 지원 종료된 런타임 목록
# 이 런타임은 보안 패치를 받지 못함
DEPRECATED_RUNTIMES = {
    "python3.7", "python3.8", "nodejs12.x", "nodejs14.x",
    "java8", "go1.x", "dotnetcore3.1",
}


def check_function_security(
    function_name: str,
    region: str = "ap-northeast-2",
) -> AuditReport:
    """Lambda 함수 보안 설정 감사."""
    client = boto3.client("lambda", region_name=region)
    report = AuditReport(function_name=function_name, region=region)

    try:
        config = client.get_function_configuration(FunctionName=function_name)
    except client.exceptions.ResourceNotFoundException:
        report.findings.append({"check": "function_exists", "status": "FAIL", "detail": "함수 없음"})
        return report

    # X-Ray 추적 확인
    # Active = 모든 요청 추적, PassThrough = 부모 샘플링 따름
    if config.get("TracingConfig", {}).get("Mode") not in ("Active", "PassThrough"):
        report.score -= CHECKS["xray_tracing"][1]
        report.findings.append({
            "check": "xray_tracing",
            "status": "FAIL",
            "detail": CHECKS["xray_tracing"][0],
            "recommendation": "X-Ray 추적을 Active로 설정하세요"
        })

    # Dead Letter Queue 확인
    if not config.get("DeadLetterConfig", {}).get("TargetArn"):
        report.score -= CHECKS["dlq_configured"][1]
        report.findings.append({
            "check": "dlq_configured",
            "status": "FAIL",
            "detail": CHECKS["dlq_configured"][0],
            "recommendation": "SQS DLQ를 설정해 실패 이벤트를 보존하세요"
        })

    # VPC 배치 확인
    if not config.get("VpcConfig", {}).get("SubnetIds"):
        report.score -= CHECKS["vpc_configured"][1]
        report.findings.append({
            "check": "vpc_configured",
            "status": "WARN",
            "detail": CHECKS["vpc_configured"][0],
            "recommendation": "민감 리소스 접근 시 VPC 내 배치를 권장합니다"
        })

    # KMS 환경 변수 암호화 확인
    if not config.get("KMSKeyArn"):
        report.score -= CHECKS["kms_encryption"][1]
        report.findings.append({
            "check": "kms_encryption",
            "status": "FAIL",
            "detail": CHECKS["kms_encryption"][0],
            "recommendation": "환경 변수 암호화를 위해 KMS 키를 설정하세요"
        })

    # 동시성 제한 확인
    if config.get("ReservedConcurrentExecutions") is None:
        report.score -= CHECKS["reserved_concurrency"][1]
        report.findings.append({
            "check": "reserved_concurrency",
            "status": "WARN",
            "detail": CHECKS["reserved_concurrency"][0],
            "recommendation": "DoS 방지를 위해 동시성 제한을 설정하세요"
        })

    # 코드 서명 확인
    if not config.get("CodeSigningConfigArn"):
        report.score -= CHECKS["code_signing"][1]
        report.findings.append({
            "check": "code_signing",
            "status": "WARN",
            "detail": CHECKS["code_signing"][0],
            "recommendation": "공급망 보호를 위해 코드 서명을 설정하세요"
        })

    # 런타임 버전 확인
    runtime = config.get("Runtime", "")
    if runtime in DEPRECATED_RUNTIMES:
        report.score -= CHECKS["latest_runtime"][1]
        report.findings.append({
            "check": "latest_runtime",
            "status": "FAIL",
            "detail": f"지원 종료 런타임: {runtime}",
            "recommendation": f"python3.12, nodejs20.x 등 최신 런타임으로 업그레이드하세요"
        })

    return report


def format_grade(score: int) -> str:
    """점수를 등급으로 변환."""
    if score >= 90:
        return "A (우수)"
    elif score >= 80:
        return "B (양호)"
    elif score >= 70:
        return "C (개선 필요)"
    else:
        return "D (위험)"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="서버리스 보안 감사",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
예시:
  # 특정 함수 감사
  python3 serverless_audit.py my-function-1 my-function-2

  # 모든 함수 감사 (전체 리전)
  python3 serverless_audit.py --region ap-northeast-2

  # 70점 미만 함수 있으면 CI 실패 처리
  python3 serverless_audit.py --fail-below 70 -o results.json
        """
    )
    parser.add_argument("functions", nargs="*", help="감사할 Lambda 함수 이름 (없으면 전체)")
    parser.add_argument("--region", default="ap-northeast-2", help="AWS 리전")
    parser.add_argument("-o", "--output", type=Path, help="결과 JSON 저장 경로")
    parser.add_argument("--fail-below", type=int, default=70, help="이 점수 미만이면 프로세스 비정상 종료 (CI 실패)")
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
        
        grade = format_grade(report.score)
        print(f"  점수: {report.score}/100 ({grade})")
        for f in report.findings:
            icon = "❌" if f["status"] == "FAIL" else "⚠️"
            print(f"  {icon} {f['detail']}")
            if "recommendation" in f:
                print(f"     → {f['recommendation']}")

    failed = [r for r in reports if r.score < args.fail_below]
    print(f"\n총 {len(reports)}개 감사 / 기준({args.fail_below}점) 미달 {len(failed)}개")

    if args.output:
        data = [{
            "function": r.function_name,
            "score": r.score,
            "grade": format_grade(r.score),
            "findings": r.findings
        } for r in reports]
        args.output.write_text(json.dumps(data, indent=2, ensure_ascii=False))
        print(f"[+] 결과 저장: {args.output}")

    # CI/CD에서 사용: 기준 미달 시 exit code 1 (빌드 실패)
    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
```

---

## 6. 서버리스 보안 체크리스트

### 우선순위별 체크리스트

**필수 (배포 전 반드시 확인)**

| # | 카테고리 | 항목 | 확인 방법 |
|---|----------|------|-----------|
| 1 | IAM | 함수별 전용 역할 생성 (공용 역할 금지) | IAM 콘솔 확인 |
| 2 | IAM | 최소 권한 원칙 적용 (`*` 권한 금지) | IAM Access Analyzer |
| 3 | 암호화 | 환경 변수 KMS 암호화 | Lambda 설정 확인 |
| 4 | 시크릿 | 코드/환경변수에 하드코딩된 비밀번호 없음 | Secrets Manager 사용 |
| 5 | 런타임 | 최신 지원 버전 사용 | AWS 런타임 지원 정책 확인 |
| 6 | 의존성 | pip-audit·Snyk 스캔 통과 | CI/CD에 통합 |

**권장 (보안 수준 향상)**

| # | 카테고리 | 항목 | 장점 |
|---|----------|------|------|
| 7 | 코드 서명 | 배포 코드 서명·검증 | 공급망 공격 방지 |
| 8 | 네트워크 | 민감 리소스 VPC 내 격리 | 공개 접근 차단 |
| 9 | 모니터링 | X-Ray 요청 추적 활성화 | 공격 경로 추적 |
| 10 | 가용성 | Dead Letter Queue 설정 | 실패 이벤트 보존 |
| 11 | 비용 | Reserved Concurrency 제한 | DoS 비용 방지 |
| 12 | 웹 방화벽 | API Gateway WAF 연동 | 웹 공격 차단 |
| 13 | 위협 탐지 | GuardDuty Lambda 보호 | AI 기반 이상 탐지 |

**고급 (추가적인 보안 강화)**

| # | 카테고리 | 항목 | 설명 |
|---|----------|------|------|
| 14 | 네트워크 | IMDSv2 강제 적용 | SSRF 공격으로 자격증명 탈취 방지 |
| 15 | 모니터링 | Lambda Extension 보안 모니터 | 런타임 이상 행위 실시간 탐지 |
| 16 | 감사 | CloudTrail + 이상 탐지 알림 | 코드 변경, 권한 변경 즉시 알림 |
| 17 | 취약점 관리 | AWS Inspector 연동 | 컨테이너 이미지 취약점 자동 스캔 |

---

## 7. 자주 하는 실수 및 해결법

### 실수 1: 환경 변수에 비밀번호 저장

```python
# ❌ 잘못된 방법
import os
DB_PASSWORD = os.environ.get("DB_PASSWORD", "hardcoded_fallback")

# ✅ 올바른 방법
import boto3
import json

def get_secret(secret_name: str) -> dict:
    """AWS Secrets Manager에서 시크릿 가져오기."""
    client = boto3.client("secretsmanager")
    response = client.get_secret_value(SecretId=secret_name)
    return json.loads(response["SecretString"])

# 사용법
secrets = get_secret("prod/myapp/database")
db_password = secrets["password"]
```

### 실수 2: 너무 넓은 IAM 권한

```json
// ❌ 잘못된 방법: 모든 S3 접근 허용
{
  "Effect": "Allow",
  "Action": "s3:*",
  "Resource": "*"
}

// ✅ 올바른 방법: 특정 버킷의 특정 작업만 허용
{
  "Effect": "Allow",
  "Action": ["s3:GetObject", "s3:PutObject"],
  "Resource": "arn:aws:s3:::my-specific-bucket/*"
}
```

### 실수 3: 오류 메시지에 내부 정보 노출

```python
# ❌ 잘못된 방법: 스택 트레이스 클라이언트에 노출
def handler(event, context):
    try:
        result = process(event)
        return {"statusCode": 200, "body": json.dumps(result)}
    except Exception as e:
        return {"statusCode": 500, "body": str(e)}  # 위험!

# ✅ 올바른 방법: 내부 오류 로깅, 클라이언트엔 일반 메시지
import logging
logger = logging.getLogger()

def handler(event, context):
    try:
        result = process(event)
        return {"statusCode": 200, "body": json.dumps(result)}
    except Exception as e:
        logger.exception("처리 중 오류 발생")  # 내부 로그
        return {
            "statusCode": 500,
            "body": json.dumps({"error": "Internal server error"})  # 일반 메시지
        }
```

---

<!-- detect-validate-53 -->
## 서버리스 보안 강화 검증 (설정됨 ≠ 작동함)

서버리스 강화는 *IaC 보안 스캔·SAST CI 통합·런타임 보호(Lambda Extension)·자동 감사*로 구성된다. "스캐너를 붙였다"는 설정과 "취약 구성이 실제로 차단되는가"는 다르다 — 각 통제를 소유 계정/리포에서 검증한다.

### 검증 항목 → 확인 질문 → 측정 신호 → 함정

| 검증 항목 | 확인 질문 | 측정 신호 | 함정 |
|---|---|---|---|
| IaC 스캔 | 위험 구성 막나? | 취약 IaC 빌드 실패 | 리포트만 |
| SAST 게이트 | 코드 취약 차단? | 임계 시 비0 종료 | 비차단 경고 |
| 런타임 보호 | 이상 탐지? | 비정상 호출 알람 | 미배포 |
| 최소권한 | 와일드카드 0? | "*" 액션 0 | 광역 역할 |

### 방어 검증 (직접 확인)

```bash
# 1) 소유 IaC가 게이트로 취약 구성을 막는지 — checkov/tfsec 취약 시 비0 종료여야
checkov -d . --compact 2>/dev/null | grep -E 'FAILED|Passed'; echo "exit=$?"
# 2) 실행 역할 와일드카드 점검(최소권한) — 정책에 "*" 액션이 있으면 과대권한 신호
grep -rIn '"Action"\s*:\s*"\*"\|"\*"' *.tf template.yaml 2>/dev/null | head
```

> 서버리스 강화는 *통제가 강제되는가*다 — "스캐너가 있다"와 "취약 IaC가 빌드를 막고 와일드카드 권한이 0이며 런타임 보호가 발화한다"는 다르다. 각 통제를 소유 계정/리포에서 직접 검증한다([[18_DevSecOps]], [[14_Cloud_Security]], [[38_Cloud_Native_Security]]).

**최신 기법·통제 (2025–2026):**
- 최소권한·런타임 보호·의존성 스캔·SBOM이 표준 — 검증: 취약 의존성이 배포 게이트에서 차단되는가([[18_DevSecOps]])
- 이벤트 검증·격리 — 강제되는지 확인

---

<a name="english"></a>

# Serverless Security Hardening — SAST, Runtime Protection, and Automated Auditing

## 0. Beginner Concepts

### What is Security Hardening?

**Hardening** is the process of removing attack-exploitable vulnerabilities, disabling unnecessary features, and granting only minimum required permissions to improve security.

**Analogy:** Think of it as securing your house:
- Installing locks → IAM least privilege
- Covering unnecessary windows → Disabling unused triggers/endpoints
- Adding security bars → VPC isolation
- Installing CCTV → CloudTrail/GuardDuty monitoring
- Smoke detectors → Dead Letter Queue + alerts

### What is Shift-Left Security?

```
Traditional security:
  Develop → Test → Staging → Deploy → Operations → [Security check]
                                                  ↑ Too late!

Shift-Left security:
  Develop → Test → Staging → Deploy → Operations
    ↑
  [Security checks start here] ← From the development stage
```

Security issues found in development cost 100× less to fix than issues found in production.

---

## 1. Serverless Security Architecture

Security controls are applied at three stages:

**Development (Shift-Left):** IDE plugins → Git hooks → CI/CD SAST → dependency auditing
(During coding) → (On commit) → (On PR) → (Automated)

**Deployment:** IaC scanning (cfn-guard/checkov) → code signing → vulnerable package blocking → IAM least-privilege verification

**Runtime:** AWS Lambda Insights → X-Ray tracing → GuardDuty Lambda Protection → CloudTrail auditing

---

## 2. IaC Security Scanning (Terraform/CloudFormation)

### What is IaC?

**Infrastructure as Code (IaC)** means defining servers, networks, and databases as code instead of clicking through the AWS console. This enables version control, automated deployment, and security scanning of your infrastructure configuration.

### 2.1 Checkov Lambda Configuration Scan

Key Checkov checks for Lambda:
- `CKV_AWS_50` — X-Ray tracing enabled (attack path reconstruction)
- `CKV_AWS_116` — Dead Letter Queue configured (failed event preservation)
- `CKV_AWS_117` — Deployed inside a VPC (public internet isolation)
- `CKV_AWS_272` — Code signing configured (unauthorized deployment prevention)

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
| `permissions_boundary` | Caps maximum IAM permissions — even if someone accidentally grants admin access, the boundary prevents it from taking effect |

---

## 3. Serverless SAST CI/CD Integration

### What is CI/CD?

- **CI (Continuous Integration)**: Frequently merge code and automatically build/test
- **CD (Continuous Deployment)**: Automatically deploy when tests pass

A **Security Gate** is a mandatory checkpoint that code must pass before deployment.

The GitHub Actions workflow runs four parallel security checks on every push:

1. **pip-audit + safety** — checks for known CVEs in Python dependencies
2. **Semgrep** — runs SAST rules for Python, AWS Lambda, and OWASP Top 10
3. **Checkov** — scans Terraform IaC for misconfigurations, outputs SARIF
4. **Bandit** — Python-specific security linter targeting common vulnerabilities

Results are uploaded to GitHub's security dashboard via the CodeQL SARIF upload action, appearing as inline comments on Pull Requests.

---

## 4. Runtime Protection — Lambda Extension

### What is a Lambda Extension?

A Lambda Extension is a **sidecar process** that runs alongside your Lambda function. It can add monitoring, logging, and security checks without modifying your function code.

**Analogy:** Like a security guard who watches everything the function does.

The Lambda Extension registers itself with the Lambda Runtime API to receive `INVOKE` and `SHUTDOWN` lifecycle events. On each invocation, it checks `/proc/net/tcp` for active network connections to the EC2 Instance Metadata Service (169.254.169.254), which may indicate an SSRF attack attempting to steal IAM credentials.

Security events are emitted as structured JSON logs to CloudWatch Logs, where they can trigger alarms or be processed by SIEM systems.

---

## 5. Automated Serverless Security Audit CLI

The audit CLI scores each Lambda function from 100 points, deducting points for missing security controls:

| Check | Deduction | Severity | Why It Matters |
|-------|-----------|----------|----------------|
| X-Ray tracing disabled | -10 | FAIL | Can't trace attack paths |
| No Dead Letter Queue | -10 | FAIL | Failed events lost forever |
| Not in VPC | -5 | WARN | Exposed to public internet |
| No KMS encryption | -15 | FAIL | Env vars visible in console |
| No concurrency limit | -5 | WARN | Vulnerable to DoS cost explosion |
| No code signing | -10 | WARN | Supply chain attacks possible |
| Deprecated runtime | -15 | FAIL | No security patches |

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

**Required (must verify before deployment)**

| Category | Item | Priority |
|----------|------|----------|
| IAM | Dedicated role per function (no shared roles) | Required |
| IAM | Least privilege (`*` actions forbidden) | Required |
| Encryption | KMS encryption for environment variables | Required |
| Secrets | No hardcoded passwords in code/env vars | Required |
| Runtime | Use latest supported version | Required |
| Dependencies | Regular pip-audit/Snyk scans | Required |

**Recommended (improves security posture)**

| Category | Item | Benefit |
|----------|------|---------|
| Code Signing | Sign and verify deployed code | Supply chain protection |
| VPC | Isolate sensitive resources inside VPC | Block public access |
| X-Ray | Enable request tracing | Attack path reconstruction |
| DLQ | Dead Letter Queue for failed events | Evidence preservation |
| Concurrency | Set Reserved Concurrency limit | DoS cost protection |
| WAF | Integrate WAF with API Gateway | Web attack blocking |
| GuardDuty | Enable Lambda Protection feature | AI-based anomaly detection |

---

## 7. Common Mistakes and Fixes

### Mistake 1: Storing Secrets in Environment Variables

```python
# ❌ Wrong: visible in AWS console and logs
DB_PASSWORD = os.environ.get("DB_PASSWORD")

# ✅ Correct: fetch from Secrets Manager at runtime
def get_secret(secret_name: str) -> dict:
    client = boto3.client("secretsmanager")
    response = client.get_secret_value(SecretId=secret_name)
    return json.loads(response["SecretString"])
```

### Mistake 2: Overly Broad IAM Permissions

```json
// ❌ Wrong: allows all S3 actions on all buckets
{ "Action": "s3:*", "Resource": "*" }

// ✅ Correct: only specific actions on specific bucket
{ "Action": ["s3:GetObject", "s3:PutObject"],
  "Resource": "arn:aws:s3:::my-specific-bucket/*" }
```

### Mistake 3: Leaking Internal Error Details

```python
# ❌ Wrong: returns stack trace to client
except Exception as e:
    return {"statusCode": 500, "body": str(e)}

# ✅ Correct: log internally, return generic message
except Exception as e:
    logger.exception("Processing error")
    return {"statusCode": 500, "body": '{"error": "Internal server error"}'}
```

<!-- detect-validate-53 -->
## Serverless Hardening Validation (Configured != Working)

Serverless hardening comprises *IaC security scanning, SAST CI integration, runtime protection (Lambda Extension), and automated audit*. "We attached a scanner" differs from "vulnerable configs are actually blocked" -- validate each control on owned accounts/repos.

### Validation item -> Question -> Measured signal -> Pitfall

| Validation item | Question | Measured signal | Pitfall |
|---|---|---|---|
| IaC scan | Block risky config? | Vulnerable IaC build fails | Report only |
| SAST gate | Block code vulns? | Non-zero exit on threshold | Non-blocking warning |
| Runtime protection | Detect anomaly? | Alarm on abnormal call | Not deployed |
| Least privilege | 0 wildcards? | 0 "*" actions | Broad role |

### Defense validation (verify directly)

```bash
# 1) Whether owned IaC gates vulnerable configs — checkov/tfsec should exit non-zero on a vuln
checkov -d . --compact 2>/dev/null | grep -E 'FAILED|Passed'; echo "exit=$?"
# 2) Execution-role wildcard check (least privilege) — a "*" action in policy signals over-privilege
grep -rIn '"Action"\s*:\s*"\*"\|"\*"' *.tf template.yaml 2>/dev/null | head
```

> Serverless hardening is *whether controls are enforced* -- "we have a scanner" differs from "vulnerable IaC blocks the build, there are 0 wildcard permissions, and runtime protection fires". Validate each control on owned accounts/repos directly ([[18_DevSecOps]], [[14_Cloud_Security]], [[38_Cloud_Native_Security]]).
