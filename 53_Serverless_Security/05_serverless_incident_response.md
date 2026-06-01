> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 서버리스 사고 대응

AWS Lambda, Azure Functions, GCP Cloud Functions 환경의 보안 사고 대응은 기존 서버와 다른 접근이 필요하다. 로그 수집, 함수 코드 분석, 환경 변수 노출 탐지, 자동화된 격리 절차를 정리한다.

---

## 1. 서버리스 보안 사고 특성

### 1.1 전통적 IR vs 서버리스 IR

```
전통 서버:
  ✓ 메모리 덤프 가능
  ✓ 파일시스템 포렌식
  ✓ 프로세스 목록 확인
  ✗ 인프라 유지 비용

서버리스:
  ✗ 함수 실행 후 환경 소멸 (포렌식 어려움)
  ✗ 에페머럴 실행 환경
  ✓ 로그가 CloudWatch/Stackdriver에 보존
  ✓ API Gateway 접근 로그 완전 수집 가능
  ✓ IAM 권한 분석으로 피해 범위 파악
```

### 1.2 공격 벡터 분류

```
코드 인젝션:
  - 이벤트 파라미터를 통한 명령어 인젝션
  - 역직렬화 취약점
  - 의존성 취약점 (npm, pip 패키지)

권한 오남용:
  - 과도한 IAM 권한 (Lambda 실행 역할)
  - SSRF로 IMDSv1 자격증명 탈취
  - 환경 변수에 저장된 시크릿 노출

공급망:
  - 악성 레이어 (Lambda Layer)
  - 취약한 컨테이너 이미지
  - 3rd party 의존성 포이즈닝
```

---

## 2. AWS Lambda 사고 대응

### 2.1 초동 분석 자동화

```python
#!/usr/bin/env python3
"""AWS Lambda 보안 사고 자동 분석"""
import argparse
import json
from datetime import datetime, timezone, timedelta
from typing import Optional

import boto3


class LambdaIncidentResponder:
    def __init__(self, region: str = "ap-northeast-2", profile: Optional[str] = None) -> None:
        session = boto3.Session(profile_name=profile)
        self.lambda_client = session.client("lambda", region_name=region)
        self.logs_client = session.client("logs", region_name=region)
        self.iam_client = session.client("iam")
        self.region = region

    def list_suspicious_functions(self) -> list[dict]:
        """최근 수정된 함수 및 이상 설정 탐지"""
        suspicious = []
        paginator = self.lambda_client.get_paginator("list_functions")

        for page in paginator.paginate():
            for func in page["Functions"]:
                flags = []

                # VPC 외부 실행 (민감 리소스 격리 없음)
                if not func.get("VpcConfig", {}).get("VpcId"):
                    flags.append("VPC 미적용")

                # 긴 타임아웃 (장기 실행 가능)
                if func.get("Timeout", 0) > 300:
                    flags.append(f"긴 타임아웃: {func['Timeout']}초")

                # 환경 변수에 민감 정보 확인 필요
                if func.get("Environment", {}).get("Variables"):
                    env_keys = list(func["Environment"]["Variables"].keys())
                    suspicious_keys = [
                        k for k in env_keys
                        if any(s in k.lower() for s in ["secret", "key", "password", "token", "credential"])
                    ]
                    if suspicious_keys:
                        flags.append(f"민감 환경변수: {suspicious_keys}")

                # 공개 함수 URL
                try:
                    url_config = self.lambda_client.get_function_url_config(
                        FunctionName=func["FunctionName"]
                    )
                    if url_config.get("AuthType") == "NONE":
                        flags.append("인증 없는 함수 URL (공개 접근 가능)")
                except Exception:
                    pass

                if flags:
                    suspicious.append({
                        "function_name": func["FunctionName"],
                        "runtime": func.get("Runtime", ""),
                        "role": func.get("Role", ""),
                        "last_modified": func.get("LastModified", ""),
                        "flags": flags,
                    })

        return suspicious

    def get_cloudwatch_logs(
        self,
        function_name: str,
        hours_back: int = 24,
        filter_pattern: str = "ERROR",
    ) -> list[dict]:
        log_group = f"/aws/lambda/{function_name}"
        start_time = int((datetime.now(timezone.utc) - timedelta(hours=hours_back)).timestamp() * 1000)
        end_time = int(datetime.now(timezone.utc).timestamp() * 1000)

        events = []
        try:
            response = self.logs_client.filter_log_events(
                logGroupName=log_group,
                startTime=start_time,
                endTime=end_time,
                filterPattern=filter_pattern,
            )
            events = response.get("events", [])
        except self.logs_client.exceptions.ResourceNotFoundException:
            print(f"[-] 로그 그룹 없음: {log_group}")

        return events

    def analyze_iam_role(self, role_arn: str) -> dict:
        """Lambda 실행 역할의 과도한 권한 분석"""
        role_name = role_arn.split("/")[-1]

        findings = {
            "role_name": role_name,
            "overprivileged": [],
            "dangerous_actions": [],
        }

        try:
            policies = self.iam_client.list_attached_role_policies(RoleName=role_name)
            inline_policies = self.iam_client.list_role_policies(RoleName=role_name)

            dangerous_actions = [
                "iam:*", "s3:*", "ec2:*", "sts:AssumeRole",
                "secretsmanager:*", "ssm:*", "lambda:*",
            ]

            for policy in policies["AttachedPolicies"]:
                if policy["PolicyName"] in ("AdministratorAccess", "AmazonS3FullAccess",
                                             "IAMFullAccess", "PowerUserAccess"):
                    findings["overprivileged"].append(f"과도한 관리형 정책: {policy['PolicyName']}")

            for action in dangerous_actions:
                findings["dangerous_actions"].append(action)

        except Exception as e:
            findings["error"] = str(e)

        return findings

    def isolate_function(self, function_name: str) -> dict:
        """의심 Lambda 함수 격리"""
        actions_taken = []

        # 1. 예약 동시성을 0으로 설정 (새 호출 차단)
        try:
            self.lambda_client.put_function_concurrency(
                FunctionName=function_name,
                ReservedConcurrentExecutions=0,
            )
            actions_taken.append("동시성 0으로 설정 (새 호출 차단)")
        except Exception as e:
            actions_taken.append(f"동시성 설정 실패: {e}")

        # 2. 트리거 비활성화 (EventSourceMapping)
        try:
            mappings = self.lambda_client.list_event_source_mappings(
                FunctionName=function_name
            )
            for mapping in mappings["EventSourceMappings"]:
                self.lambda_client.update_event_source_mapping(
                    UUID=mapping["UUID"],
                    Enabled=False,
                )
            actions_taken.append(f"{len(mappings['EventSourceMappings'])}개 트리거 비활성화")
        except Exception as e:
            actions_taken.append(f"트리거 비활성화 실패: {e}")

        # 3. 함수 코드 스냅샷 (포렌식용)
        try:
            config = self.lambda_client.get_function(FunctionName=function_name)
            code_url = config["Code"].get("Location", "")
            actions_taken.append(f"코드 URL 기록: {code_url[:80]}")
        except Exception as e:
            actions_taken.append(f"코드 스냅샷 실패: {e}")

        return {
            "function": function_name,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "actions": actions_taken,
        }

    def search_exfiltration_patterns(self, function_name: str) -> list[str]:
        """로그에서 데이터 유출 패턴 탐지"""
        suspicious_patterns = [
            "curl.*http",
            "wget.*http",
            "requests\\.post",
            "subprocess\\.run",
            "os\\.system",
            "eval\\(",
            "__import__",
            "base64\\.b64decode",
            "exec\\(",
        ]

        findings = []
        pattern_str = "|".join(suspicious_patterns)
        events = self.get_cloudwatch_logs(function_name, hours_back=72, filter_pattern=pattern_str)

        for event in events[:20]:
            findings.append({
                "timestamp": datetime.fromtimestamp(event["timestamp"] / 1000).isoformat(),
                "message": event["message"][:200],
            })

        return findings


def main() -> None:
    parser = argparse.ArgumentParser(description="Lambda 사고 대응")
    parser.add_argument("--region", default="ap-northeast-2")
    parser.add_argument("--profile", default=None)
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("audit", help="전체 함수 보안 감사")

    logs_p = subparsers.add_parser("logs", help="CloudWatch 로그 분석")
    logs_p.add_argument("function_name")
    logs_p.add_argument("--hours", type=int, default=24)

    isolate_p = subparsers.add_parser("isolate", help="함수 격리")
    isolate_p.add_argument("function_name")

    args = parser.parse_args()
    responder = LambdaIncidentResponder(args.region, args.profile)

    if args.command == "audit":
        suspicious = responder.list_suspicious_functions()
        print(f"[+] 의심 함수: {len(suspicious)}개")
        for f in suspicious:
            print(f"  [!] {f['function_name']}: {', '.join(f['flags'])}")

    elif args.command == "logs":
        events = responder.get_cloudwatch_logs(args.function_name, args.hours)
        print(f"[+] {len(events)}개 로그 이벤트")
        for e in events[:20]:
            print(f"  {e.get('message', '')[:150]}")

    elif args.command == "isolate":
        result = responder.isolate_function(args.function_name)
        print(f"[+] 격리 완료: {args.function_name}")
        for action in result["actions"]:
            print(f"  [*] {action}")


if __name__ == "__main__":
    main()
```

---

## 3. SSRF를 통한 IMDSv1 자격증명 탈취 탐지

```python
#!/usr/bin/env python3
"""서버리스 SSRF/IMDSv1 공격 탐지"""
import re
from dataclasses import dataclass


IMDS_PATTERNS = [
    r"169\.254\.169\.254",                    # AWS IMDSv1
    r"metadata\.google\.internal",             # GCP 메타데이터
    r"169\.254\.169\.254.*latest/meta-data",  # AWS 메타데이터 경로
    r"169\.254\.169\.254.*iam/security-credentials",  # 자격증명 경로
]

SSRF_TRIGGER_PATTERNS = [
    r"url=https?://",
    r"redirect=https?://",
    r"next=https?://",
    r"callback=https?://",
    r"fetch=https?://",
    r"proxy=https?://",
]


def analyze_lambda_event(event: dict) -> list[str]:
    """Lambda 이벤트 파라미터에서 SSRF 시도 탐지"""
    findings = []
    event_str = str(event)

    for pattern in IMDS_PATTERNS:
        if re.search(pattern, event_str, re.IGNORECASE):
            findings.append(f"IMDS 접근 시도 탐지: {pattern}")

    for pattern in SSRF_TRIGGER_PATTERNS:
        matches = re.findall(pattern, event_str, re.IGNORECASE)
        if matches:
            findings.append(f"SSRF 트리거 파라미터: {matches[0]}")

    return findings


# Lambda 핸들러에 적용 예시
def secure_lambda_handler(event: dict, context) -> dict:
    ssrf_findings = analyze_lambda_event(event)
    if ssrf_findings:
        print(f"[SECURITY ALERT] SSRF 시도: {ssrf_findings}")
        return {"statusCode": 400, "body": "Invalid request"}

    # 정상 처리
    return {"statusCode": 200, "body": "OK"}
```

---

## 4. 서버리스 보안 모니터링

### 4.1 CloudTrail 이상 탐지

```python
#!/usr/bin/env python3
"""CloudTrail에서 Lambda 관련 이상 행위 탐지"""
import argparse
import json
from datetime import datetime, timedelta, timezone

import boto3


def detect_lambda_anomalies(region: str, hours_back: int = 24) -> list[dict]:
    ct = boto3.client("cloudtrail", region_name=region)
    start_time = datetime.now(timezone.utc) - timedelta(hours=hours_back)

    suspicious_actions = [
        "UpdateFunctionCode",          # 함수 코드 변경
        "AddPermission",               # 권한 추가
        "CreateEventSourceMapping",    # 새 트리거 추가
        "PutFunctionConcurrency",      # 동시성 변경
        "DeleteFunction",              # 함수 삭제
        "TagResource",                 # 리소스 태깅
    ]

    findings = []
    for action in suspicious_actions:
        try:
            resp = ct.lookup_events(
                LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": action}],
                StartTime=start_time,
            )
            for event in resp["Events"]:
                record = json.loads(event.get("CloudTrailEvent", "{}"))
                source_ip = record.get("sourceIPAddress", "")
                user = record.get("userIdentity", {})
                user_name = user.get("userName", user.get("principalId", "unknown"))

                # 외부 IP에서의 변경은 의심
                if not source_ip.startswith(("10.", "172.", "192.168.", "127.")):
                    findings.append({
                        "action": action,
                        "time": event["EventTime"].isoformat(),
                        "user": user_name,
                        "source_ip": source_ip,
                        "resource": event.get("Resources", [{}])[0].get("ResourceName", ""),
                        "risk": "HIGH" if action in ("UpdateFunctionCode", "AddPermission") else "MEDIUM",
                    })
        except Exception:
            continue

    return findings


def main() -> None:
    parser = argparse.ArgumentParser(description="Lambda CloudTrail 감사")
    parser.add_argument("--region", default="ap-northeast-2")
    parser.add_argument("--hours", type=int, default=24)
    args = parser.parse_args()

    findings = detect_lambda_anomalies(args.region, args.hours)
    print(f"[+] 의심 활동: {len(findings)}건")
    for f in findings:
        print(f"  [{f['risk']}] {f['action']} by {f['user']} from {f['source_ip']} — {f['resource']}")


if __name__ == "__main__":
    main()
```

---

## 5. 서버리스 IR 플레이북

```
P1: 데이터 유출 의심
  1. CloudWatch Logs에서 외부 HTTP 요청 패턴 검색
  2. VPC Flow Logs에서 비정상 아웃바운드 확인
  3. 의심 함수 동시성 0 설정 (새 호출 차단)
  4. CloudTrail에서 환경 변수 변경 이력 확인
  5. Secrets Manager 접근 로그 확인

P2: 코드 변조 의심
  1. CloudTrail UpdateFunctionCode 이벤트 확인
  2. 함수 코드 다운로드 (포렌식 스냅샷)
  3. 이전 버전과 diff 비교
  4. 배포 파이프라인 무결성 확인
  5. IAM 권한 감사

P3: 자격증명 탈취 의심
  1. IMDSv2 적용 여부 확인
  2. CloudTrail AssumeRole 이상 접근 탐지
  3. 탈취된 자격증명 즉시 무효화 (키 회전)
  4. 관련 IAM 역할 임시 비활성화
  5. 피해 범위 산정 (어떤 서비스에 접근했나)
```

| 위협 | 탐지 방법 | 대응 |
|------|---------|------|
| IMDSv1 SSRF | CloudTrail + IMDSv2 강제 | IMDSv2 활성화 |
| 환경 변수 시크릿 | 코드 검토 + Secrets Manager 전환 | Secrets Manager/SSM 사용 |
| 과도한 IAM | IAM Access Analyzer | 최소 권한 원칙 |
| 함수 코드 변조 | CloudTrail 모니터링 | CI/CD 서명 적용 |
| 의존성 취약점 | AWS Inspector | 정기 패치 |

---

<a name="english"></a>

# Serverless Incident Response

Security incident response in AWS Lambda, Azure Functions, and GCP Cloud Functions environments requires a fundamentally different approach from traditional server IR. This document covers log collection, function code analysis, environment variable exposure detection, and automated isolation procedures.

---

## 1. Serverless Security Incident Characteristics

### 1.1 Traditional IR vs Serverless IR

| Capability | Traditional Server | Serverless |
|------------|-------------------|------------|
| Memory dump | Yes | No — execution environment destroyed after invocation |
| Filesystem forensics | Yes | No — ephemeral environment |
| Process listing | Yes | No |
| Infrastructure cost | High (always running) | No |
| Log preservation | Manual setup | Automatic (CloudWatch/Stackdriver) |
| Access log completeness | Varies | Full API Gateway access logs available |
| Blast radius assessment | Complex | IAM permission analysis gives clear picture |

### 1.2 Attack Vector Classification

**Code Injection:**
- Command injection via event parameters
- Deserialization vulnerabilities
- Dependency vulnerabilities (npm, pip packages)

**Privilege Abuse:**
- Excessive IAM permissions on Lambda execution role
- SSRF to steal IMDSv1 credentials
- Secrets exposed in environment variables

**Supply Chain:**
- Malicious Lambda Layers
- Vulnerable container images
- Third-party dependency poisoning

---

## 2. AWS Lambda Incident Response

### 2.1 Initial Response Automation

The `LambdaIncidentResponder` class provides four key capabilities:

**`list_suspicious_functions()`** — Scans all Lambda functions for suspicious configurations:
- Missing VPC configuration (no network isolation)
- Timeout > 300 seconds (allows long-running exfiltration)
- Environment variable keys containing "secret", "key", "password", "token", or "credential"
- Function URLs with `AuthType = "NONE"` (publicly accessible)

**`get_cloudwatch_logs()`** — Fetches and filters CloudWatch Logs for a specific function over a configurable time window with CloudWatch filter patterns.

**`isolate_function()`** — Implements the isolation playbook:
1. Sets `ReservedConcurrentExecutions = 0` to block all new invocations
2. Disables all EventSourceMappings (SQS, Kinesis, DynamoDB triggers)
3. Records the function code download URL for forensic snapshot

**`search_exfiltration_patterns()`** — Searches 72 hours of logs for data exfiltration indicators: outbound HTTP calls, subprocess execution, eval usage, base64 decoding.

**Usage:**
```bash
# Audit all functions
python3 lambda_ir.py --region us-east-1 audit

# Analyze logs for specific function
python3 lambda_ir.py logs my-function --hours 48

# Isolate suspicious function
python3 lambda_ir.py isolate compromised-function
```

---

## 3. SSRF / IMDSv1 Credential Theft Detection

The SSRF detector checks every Lambda event for patterns indicating an attempt to access the EC2 Instance Metadata Service (169.254.254.254) or GCP metadata endpoint, which would allow an attacker to steal IAM role credentials.

It also detects common SSRF trigger parameters (`url=`, `redirect=`, `callback=`, `proxy=`, etc.) that might be exploited to reach internal services.

Any detected SSRF attempt returns HTTP 400 immediately and logs a security alert.

---

## 4. Serverless Security Monitoring

### 4.1 CloudTrail Anomaly Detection

The CloudTrail monitor tracks six high-risk Lambda API calls and flags any that originate from non-RFC1918 IP addresses (public internet):

| Action | Risk | Concern |
|--------|------|---------|
| `UpdateFunctionCode` | HIGH | Backdoor insertion |
| `AddPermission` | HIGH | Unauthorized trigger addition |
| `CreateEventSourceMapping` | MEDIUM | New trigger from untrusted source |
| `PutFunctionConcurrency` | MEDIUM | DoS attack setup |
| `DeleteFunction` | MEDIUM | Evidence destruction |
| `TagResource` | MEDIUM | Evasion / resource manipulation |

---

## 5. Serverless IR Playbook

**P1: Suspected Data Exfiltration**
1. Search CloudWatch Logs for outbound HTTP request patterns
2. Check VPC Flow Logs for abnormal outbound traffic
3. Set suspect function concurrency to 0 (block new invocations)
4. Check CloudTrail for environment variable modification history
5. Review Secrets Manager access logs

**P2: Suspected Code Tampering**
1. Review CloudTrail `UpdateFunctionCode` events
2. Download function code (forensic snapshot)
3. Diff against previous version
4. Verify deployment pipeline integrity
5. Audit IAM permissions

**P3: Suspected Credential Theft**
1. Verify IMDSv2 enforcement
2. Detect anomalous `AssumeRole` calls in CloudTrail
3. Immediately rotate stolen credentials (key rotation)
4. Temporarily disable affected IAM roles
5. Assess blast radius (which services were accessed)

| Threat | Detection | Response |
|--------|-----------|---------|
| IMDSv1 SSRF | CloudTrail + force IMDSv2 | Enable IMDSv2 |
| Secrets in env vars | Code review + Secrets Manager migration | Use Secrets Manager/SSM |
| Excessive IAM | IAM Access Analyzer | Apply least privilege |
| Function code tampering | CloudTrail monitoring | Apply CI/CD signing |
| Dependency vulnerabilities | AWS Inspector | Regular patching |
