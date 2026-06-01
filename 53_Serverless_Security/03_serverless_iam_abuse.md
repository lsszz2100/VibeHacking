> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 서버리스 IAM 권한 남용 — 역할 체인·권한 상승·분석 CLI

## 1. 서버리스 IAM 위협 모델

Lambda 함수에 과도한 IAM 권한이 부여되면 함수 코드 취약점 하나로 전체 AWS 계정을 장악할 수 있다.

| 공격 시나리오 | 영향 |
|-------------|------|
| Lambda → S3 전체 권한 | 모든 버킷 데이터 탈취 |
| Lambda → IAM 관리 권한 | 새 관리자 계정 생성 |
| Lambda → EC2 권한 | 인스턴스 생성·인스턴스 프로파일 탈취 |
| Lambda → Secrets Manager | 모든 시크릿 탈취 |
| Lambda → STS AssumeRole | 다른 역할 체인으로 권한 상승 |

---

## 2. IAM 역할 분석

```python
#!/usr/bin/env python3
"""Lambda IAM 역할 권한 분석 — 과다 권한 탐지 CLI."""

import argparse
import json
from dataclasses import dataclass, field
from typing import Any
import boto3


DANGEROUS_ACTIONS = {
    # 권한 상승 가능 액션
    "iam:CreateUser", "iam:AttachUserPolicy", "iam:AttachRolePolicy",
    "iam:CreateAccessKey", "iam:CreateLoginProfile",
    "iam:PutUserPolicy", "iam:PutRolePolicy", "iam:SetDefaultPolicyVersion",
    "iam:PassRole", "iam:CreatePolicyVersion",
    "sts:AssumeRole",
    # 데이터 탈취 가능 액션
    "s3:GetObject", "s3:ListAllMyBuckets", "s3:GetBucketPolicy",
    "secretsmanager:GetSecretValue", "ssm:GetParameter", "kms:Decrypt",
    # 실행 관련
    "lambda:InvokeFunction", "lambda:UpdateFunctionCode",
    "ec2:DescribeInstances", "ec2:RunInstances",
    # 로그 조작
    "cloudtrail:DeleteTrail", "cloudtrail:StopLogging",
    "logs:DeleteLogGroup", "logs:DeleteLogStream",
}

WILDCARD_RISK = {"*", "iam:*", "s3:*", "ec2:*", "lambda:*", "sts:*"}


@dataclass
class PolicyFinding:
    function_name: str
    role_arn: str
    policy_name: str
    dangerous_actions: list[str] = field(default_factory=list)
    wildcard_actions: list[str] = field(default_factory=list)
    risk_level: str = "LOW"


def get_lambda_role_policies(function_name: str) -> tuple[str, list[dict]]:
    lambda_client = boto3.client("lambda")
    iam_client = boto3.client("iam")

    # Lambda 역할 ARN 가져오기
    config = lambda_client.get_function_configuration(FunctionName=function_name)
    role_arn = config["Role"]
    role_name = role_arn.split("/")[-1]

    policies = []

    # 인라인 정책
    inline_policies = iam_client.list_role_policies(RoleName=role_name)
    for policy_name in inline_policies["PolicyNames"]:
        doc = iam_client.get_role_policy(RoleName=role_name, PolicyName=policy_name)
        policies.append({"name": policy_name, "document": doc["PolicyDocument"], "type": "inline"})

    # 관리형 정책
    attached = iam_client.list_attached_role_policies(RoleName=role_name)
    for policy in attached["AttachedPolicies"]:
        policy_doc = iam_client.get_policy_version(
            PolicyArn=policy["PolicyArn"],
            VersionId=iam_client.get_policy(PolicyArn=policy["PolicyArn"])["Policy"]["DefaultVersionId"],
        )
        policies.append({
            "name": policy["PolicyName"],
            "document": policy_doc["PolicyVersion"]["Document"],
            "type": "managed",
        })

    return role_arn, policies


def analyze_policy(policy_doc: dict) -> tuple[list[str], list[str]]:
    dangerous: list[str] = []
    wildcards: list[str] = []

    for statement in policy_doc.get("Statement", []):
        if statement.get("Effect") != "Allow":
            continue
        actions = statement.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]

        for action in actions:
            if action in WILDCARD_RISK or action == "*":
                wildcards.append(action)
            elif action in DANGEROUS_ACTIONS:
                dangerous.append(action)

    return dangerous, wildcards


def audit_function(function_name: str) -> PolicyFinding | None:
    try:
        role_arn, policies = get_lambda_role_policies(function_name)
    except Exception as e:
        print(f"오류: {function_name} — {e}")
        return None

    finding = PolicyFinding(function_name=function_name, role_arn=role_arn, policy_name="combined")

    for policy in policies:
        dangerous, wildcards = analyze_policy(policy["document"])
        finding.dangerous_actions.extend(dangerous)
        finding.wildcard_actions.extend(wildcards)

    if finding.wildcard_actions:
        finding.risk_level = "CRITICAL"
    elif len(finding.dangerous_actions) >= 3:
        finding.risk_level = "HIGH"
    elif finding.dangerous_actions:
        finding.risk_level = "MEDIUM"

    return finding


def audit_all_functions(region: str = "ap-northeast-2") -> list[PolicyFinding]:
    lambda_client = boto3.client("lambda", region_name=region)
    findings: list[PolicyFinding] = []

    paginator = lambda_client.get_paginator("list_functions")
    for page in paginator.paginate():
        for func in page["Functions"]:
            finding = audit_function(func["FunctionName"])
            if finding:
                findings.append(finding)

    return findings


def main() -> None:
    parser = argparse.ArgumentParser(description="Lambda IAM 권한 감사")
    sub = parser.add_subparsers(dest="cmd", required=True)

    func_p = sub.add_parser("function", help="특정 함수 감사")
    func_p.add_argument("name", help="Lambda 함수 이름")

    all_p = sub.add_parser("all", help="모든 함수 감사")
    all_p.add_argument("--region", default="ap-northeast-2")
    all_p.add_argument("--min-risk", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"], default="MEDIUM")

    parser.add_argument("-o", "--output", help="결과 JSON 저장 경로")
    args = parser.parse_args()

    risk_levels = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

    if args.cmd == "function":
        findings = [audit_function(args.name)]
    else:
        findings = audit_all_functions(args.region)
        min_level = risk_levels[args.min_risk]
        findings = [f for f in findings if f and risk_levels[f.risk_level] >= min_level]

    for f in findings:
        if not f:
            continue
        print(f"\n[{f.risk_level}] {f.function_name}")
        print(f"  역할: {f.role_arn}")
        if f.wildcard_actions:
            print(f"  와일드카드: {f.wildcard_actions}")
        if f.dangerous_actions:
            print(f"  위험 권한: {f.dangerous_actions}")

    print(f"\n총 {len([f for f in findings if f])}개 함수 분석 완료")

    if hasattr(args, "output") and args.output:
        with open(args.output, "w") as fp:
            json.dump(
                [vars(f) for f in findings if f],
                fp, indent=2, ensure_ascii=False,
            )


if __name__ == "__main__":
    main()
```

---

## 3. STS AssumeRole 체인 공격

```python
#!/usr/bin/env python3
"""IAM 역할 체인을 통한 권한 상승 경로 탐색 (교육용)."""

import boto3
import json
from typing import Optional


def assume_role_chain(
    role_arns: list[str],
    session_name: str = "audit-session",
) -> dict | None:
    """여러 역할을 체인으로 연결해 최종 자격증명 획득."""
    sts = boto3.client("sts")
    current_creds = None

    for role_arn in role_arns:
        kwargs: dict = {
            "RoleArn": role_arn,
            "RoleSessionName": session_name,
        }

        if current_creds:
            sts = boto3.client(
                "sts",
                aws_access_key_id=current_creds["AccessKeyId"],
                aws_secret_access_key=current_creds["SecretAccessKey"],
                aws_session_token=current_creds["SessionToken"],
            )

        try:
            response = sts.assume_role(**kwargs)
            current_creds = response["Credentials"]
            print(f"[+] AssumeRole 성공: {role_arn}")
        except Exception as e:
            print(f"[-] AssumeRole 실패: {role_arn} — {e}")
            return None

    return current_creds


def enumerate_assumable_roles(
    target_account_id: str,
    current_arn: str,
) -> list[str]:
    """현재 역할에서 AssumeRole 가능한 역할 목록."""
    iam = boto3.client("iam")
    assumable: list[str] = []

    paginator = iam.get_paginator("list_roles")
    for page in paginator.paginate():
        for role in page["Roles"]:
            trust_doc = role["AssumeRolePolicyDocument"]
            for stmt in trust_doc.get("Statement", []):
                principal = stmt.get("Principal", {})
                if isinstance(principal, dict):
                    aws_principal = principal.get("AWS", "")
                elif isinstance(principal, str):
                    aws_principal = principal
                else:
                    continue

                if current_arn in str(aws_principal) or "*" in str(aws_principal):
                    assumable.append(role["Arn"])

    return assumable
```

---

## 4. Lambda 역할 최소 권한 자동 생성

```python
#!/usr/bin/env python3
"""Lambda 함수 코드에서 필요한 AWS 서비스를 분석해 최소 권한 정책 생성."""

import ast
import re
import json
from pathlib import Path
import argparse


# boto3 클라이언트/리소스 호출 → AWS 서비스 매핑
SERVICE_ACTION_MAP = {
    "s3": {
        "get_object": "s3:GetObject",
        "put_object": "s3:PutObject",
        "delete_object": "s3:DeleteObject",
        "list_objects": "s3:ListBucket",
        "list_buckets": "s3:ListAllMyBuckets",
    },
    "dynamodb": {
        "get_item": "dynamodb:GetItem",
        "put_item": "dynamodb:PutItem",
        "delete_item": "dynamodb:DeleteItem",
        "query": "dynamodb:Query",
        "scan": "dynamodb:Scan",
        "update_item": "dynamodb:UpdateItem",
    },
    "secretsmanager": {
        "get_secret_value": "secretsmanager:GetSecretValue",
        "create_secret": "secretsmanager:CreateSecret",
        "delete_secret": "secretsmanager:DeleteSecret",
    },
    "sqs": {
        "send_message": "sqs:SendMessage",
        "receive_message": "sqs:ReceiveMessage",
        "delete_message": "sqs:DeleteMessage",
    },
    "sns": {
        "publish": "sns:Publish",
    },
}


def extract_boto3_calls(filepath: Path) -> set[str]:
    """코드에서 boto3 AWS API 호출 추출."""
    source = filepath.read_text()
    tree = ast.parse(source)
    actions: set[str] = set()

    # boto3.client('service') 패턴 찾기
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not (isinstance(node.func, ast.Attribute) and
                isinstance(node.func.value, ast.Name) and
                node.func.value.id == "boto3" and
                node.func.attr in ("client", "resource")):
            continue
        if not node.args:
            continue
        if not isinstance(node.args[0], ast.Constant):
            continue
        service = node.args[0].value.lower()

        # 해당 서비스의 메서드 호출 찾기 (단순 패턴 매칭)
        service_methods = SERVICE_ACTION_MAP.get(service, {})
        for method, action in service_methods.items():
            if method in source:
                actions.add(action)

    return actions


def generate_least_privilege_policy(
    lambda_path: Path,
    account_id: str = "*",
    region: str = "*",
) -> dict:
    """최소 권한 IAM 정책 생성."""
    actions: set[str] = set()

    files = list(lambda_path.rglob("*.py")) if lambda_path.is_dir() else [lambda_path]
    for f in files:
        actions.update(extract_boto3_calls(f))

    # 기본 Lambda 실행 권한
    actions.update(["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"])

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": sorted(actions),
                "Resource": "*",  # 실제로는 리소스 ARN 특정 권장
            }
        ],
    }
    return policy


def main() -> None:
    parser = argparse.ArgumentParser(description="Lambda 최소 권한 정책 생성")
    parser.add_argument("path", type=Path, help="Lambda 코드 경로")
    parser.add_argument("-o", "--output", type=Path, help="정책 저장 경로")
    args = parser.parse_args()

    policy = generate_least_privilege_policy(args.path)
    output = json.dumps(policy, indent=2, ensure_ascii=False)

    if args.output:
        args.output.write_text(output)
        print(f"정책 저장: {args.output}")
    else:
        print(output)


if __name__ == "__main__":
    main()
```

---

## 5. IAM 보안 모범 사례

| 원칙 | 구현 |
|------|------|
| 최소 권한 | 함수별 전용 역할 — 공유 역할 금지 |
| 리소스 ARN 특정 | `arn:aws:s3:::my-bucket/*` 형식 사용 |
| 조건 키 활용 | `aws:SourceAccount`, `aws:SourceArn` 조건 추가 |
| 권한 경계 | Permission Boundary로 최대 권한 캡 설정 |
| 역할 세션 태깅 | 감사 추적을 위한 세션 태그 부착 |
| 임시 자격증명 | 장기 자격증명 대신 STS 임시 토큰 |
| SCP | AWS Organization SCP로 계정 레벨 가드레일 |
| Access Analyzer | IAM Access Analyzer로 외부 접근 탐지 |

---

<a name="english"></a>

# Serverless IAM Privilege Abuse — Role Chaining, Privilege Escalation, and Analysis CLI

## 1. Serverless IAM Threat Model

When Lambda functions are granted excessive IAM permissions, a single code vulnerability can lead to full AWS account compromise.

| Attack Scenario | Impact |
|----------------|--------|
| Lambda → Full S3 access | Exfiltrate all bucket data |
| Lambda → IAM management | Create new administrator accounts |
| Lambda → EC2 access | Launch instances, steal instance profiles |
| Lambda → Secrets Manager | Steal all secrets |
| Lambda → STS AssumeRole | Chain roles for privilege escalation |

---

## 2. IAM Role Analysis

The Lambda IAM auditor connects to AWS and examines each Lambda function's execution role for dangerous permissions.

**Risk classification:**
- **CRITICAL**: Wildcard actions (`*`, `iam:*`, `s3:*`, etc.)
- **HIGH**: 3 or more dangerous individual actions
- **MEDIUM**: 1–2 dangerous individual actions
- **LOW**: No dangerous actions detected

**Dangerous actions monitored** include privilege escalation actions (IAM user/policy manipulation, `iam:PassRole`), data exfiltration actions (`s3:GetObject`, `secretsmanager:GetSecretValue`, `kms:Decrypt`), and log tampering actions (`cloudtrail:DeleteTrail`, `logs:DeleteLogGroup`).

**Usage:**
```bash
# Audit specific function
python3 iam_auditor.py function my-lambda-function

# Audit all functions (HIGH+ risk only)
python3 iam_auditor.py all --region us-east-1 --min-risk HIGH -o findings.json
```

---

## 3. STS AssumeRole Chain Attack

Role chaining is a privilege escalation technique where an attacker uses one role to assume another role with higher privileges. The `assume_role_chain()` function demonstrates chaining through multiple roles sequentially, using each set of credentials to assume the next role.

The `enumerate_assumable_roles()` function discovers which roles the current identity can assume by examining each role's trust policy document for principal entries matching the current ARN or wildcard principals.

---

## 4. Automated Least Privilege Policy Generation

The policy generator parses Lambda function Python source code using the `ast` module to identify `boto3.client()` and `boto3.resource()` calls, then maps the detected service names and method calls to the minimum required IAM actions.

**Example output:**
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "dynamodb:GetItem",
      "dynamodb:PutItem",
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "s3:GetObject",
      "secretsmanager:GetSecretValue"
    ],
    "Resource": "*"
  }]
}
```

**Usage:**
```bash
python3 policy_generator.py ./lambda_src/ -o minimum_policy.json
```

---

## 5. IAM Security Best Practices

| Principle | Implementation |
|-----------|---------------|
| Least Privilege | Dedicated role per function — no shared roles |
| Specific Resource ARNs | Use `arn:aws:s3:::my-bucket/*` format |
| Condition Keys | Add `aws:SourceAccount`, `aws:SourceArn` conditions |
| Permission Boundaries | Cap maximum permissions with Permission Boundary |
| Role Session Tagging | Attach session tags for audit trail |
| Temporary Credentials | Use STS temporary tokens instead of long-term credentials |
| SCP | Use AWS Organization SCPs as account-level guardrails |
| Access Analyzer | Use IAM Access Analyzer to detect external access |
