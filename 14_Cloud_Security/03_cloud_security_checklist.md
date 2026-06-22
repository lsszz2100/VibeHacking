> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 클라우드 보안 체크리스트 & 아키텍처

## 0. 초보자를 위한 개념 이해

### 클라우드 보안 체크리스트란?

클라우드 보안 체크리스트는 AWS/Azure/GCP 환경에서 흔히 발생하는 보안 설정 오류를 체계적으로 점검하는 목록입니다. "공동 책임 모델(Shared Responsibility Model)"에서 클라우드 제공자는 인프라를 보호하지만, 데이터·IAM·네트워크 설정은 사용자가 책임집니다. 체크리스트 기반의 정기적 감사는 설정 오류로 인한 침해를 사전에 예방하는 핵심 보안 활동입니다.

**왜 배우는가:**
```
클라우드 보안 사고의 80%는 예방 가능한 설정 오류:

  공개된 S3 버킷         → 수백만 고객 데이터 유출 사례 다수
  MFA 미설정 루트 계정   → 전체 AWS 계정 탈취
  과도한 IAM 권한        → 권한 상승으로 전체 인프라 장악
  기본 VPC 보안 그룹     → 내부 서비스 인터넷 노출
  API 키 코드에 하드코딩 → GitHub 공개 즉시 악용

  체크리스트 정기 감사 → 위 사고 대부분 예방 가능
```

### 핵심 개념 정리

```
AWS 보안 핵심 체크 항목:

  계정 보안
    □ 루트 계정 MFA (하드웨어 토큰 권장)
    □ 루트 접근 키 삭제 (절대 사용하지 않음)
    □ IAM 최소 권한 원칙 적용

  네트워크 보안
    □ 기본 VPC 사용 금지 (별도 VPC 구성)
    □ 보안 그룹: 0.0.0.0/0 인바운드 규칙 없음
    □ CloudTrail 전체 리전 활성화

  스토리지 보안
    □ S3 버킷 퍼블릭 액세스 차단
    □ S3 버킷 정책 검토 (와일드카드 금지)
    □ S3 서버 측 암호화 활성화

  탐지 및 대응
    □ GuardDuty 활성화 (AI 기반 위협 탐지)
    □ AWS Config 규칙 설정
    □ CloudWatch 알람 구성
```

### 필요한 도구 및 환경
- **AWS Trusted Advisor**: AWS 공식 보안 권고 도구
- **ScoutSuite**: 오픈소스 멀티 클라우드 감사 도구
- **Prowler**: AWS CIS 벤치마크 자동 점검 도구
- **AWS Security Hub**: 통합 보안 상태 관리

### 기초 실습 예제
```python
#!/usr/bin/env python3
"""AWS 기본 보안 설정 감사 — S3 퍼블릭 접근 및 MFA 확인."""

import boto3
from botocore.exceptions import ClientError


def audit_s3_public_access(session: boto3.Session) -> list[dict]:
    """모든 S3 버킷의 퍼블릭 접근 차단 설정을 확인합니다."""
    s3_client = session.client("s3")
    results: list[dict] = []

    try:
        buckets = s3_client.list_buckets()["Buckets"]
    except ClientError as e:
        return [{"error": str(e)}]

    for bucket in buckets:
        name = bucket["Name"]
        try:
            pab = s3_client.get_public_access_block(Bucket=name)
            config = pab["PublicAccessBlockConfiguration"]
            is_safe = all([
                config.get("BlockPublicAcls", False),
                config.get("BlockPublicPolicy", False),
                config.get("IgnorePublicAcls", False),
                config.get("RestrictPublicBuckets", False),
            ])
            results.append({"bucket": name, "public_access_blocked": is_safe})
        except ClientError:
            results.append({"bucket": name, "public_access_blocked": False, "note": "설정 없음"})

    return results


if __name__ == "__main__":
    session = boto3.Session()
    print("[S3 퍼블릭 접근 감사]")
    for item in audit_s3_public_access(session):
        status = "안전" if item.get("public_access_blocked") else "위험!"
        print(f"  [{status}] {item['bucket']}")
```

---

## 클라우드 보안 책임 모델


AWS CLI를 활용한 클라우드 환경 침투 테스트 명령어입니다. 잘못 설정된 S3 버킷, 과도한 IAM 권한, 공개된 메타데이터 서비스(SSRF 취약점) 등이 주요 공격 벡터입니다.

```
                    고객 책임    AWS 책임
────────────────────────────────────────
데이터               ████████
ID/접근 관리         ████████
OS/네트워크/방화벽    ████████
서버 측 암호화        ████████
클라이언트 암호화     ████████
네트워크 트래픽 보호  ████████
컴퓨팅                           ████████
스토리지                          ████████
데이터베이스                      ████████
네트워킹                          ████████
하드웨어/AZ/리전                  ████████
글로벌 인프라                     ████████
────────────────────────────────────────
```

---

## 1. AWS 완전 보안 체크리스트

### 계정 수준 보안

```
루트 계정:
  □ 루트 계정 MFA 활성화 (하드웨어 토큰 권장)
  □ 루트 접근 키 삭제
  □ 루트 계정 일상 사용 금지
  □ 루트 접근 시 SNS 알림 설정

IAM 정책:
  □ 최소 권한 원칙 (Principle of Least Privilege)
  □ IAM 비밀번호 정책:
    - 최소 14자
    - 대소문자 + 숫자 + 특수문자
    - 90일 주기 변경
    - 이전 24개 비밀번호 재사용 금지
  □ 모든 IAM 사용자 MFA 강제 활성화
  □ 90일 이상 미사용 자격증명 비활성화
  □ IAM Access Analyzer 활성화
  □ 서비스 역할에 신뢰 정책 최소화
```

### 네트워크 보안

```
VPC 설정:
  □ 기본 VPC 미사용 (전용 VPC 생성)
  □ 퍼블릭/프라이빗 서브넷 분리
  □ 인터넷 게이트웨이 최소화
  □ NAT 게이트웨이로 아웃바운드 제어
  □ VPC 플로우 로그 활성화

보안 그룹:
  □ 0.0.0.0/0 인바운드 규칙 최소화
  □ SSH(22)/RDP(3389) 특정 IP만 허용
  □ 보안 그룹 설명 필수 기재
  □ 미사용 보안 그룹 정리

네트워크 ACL:
  □ 명시적 거부 규칙 추가
  □ 관리 포트 비표준 포트 사용 고려
  □ 임시 포트 범위 최소화

AWS WAF:
  □ CloudFront/ALB에 WAF 연결
  □ OWASP 규칙 세트 활성화
  □ 속도 제한 규칙 설정
  □ 지역별 차단 (필요 시)
```

### 데이터 보안


AWS CLI를 활용한 클라우드 환경 침투 테스트 명령어입니다. 잘못 설정된 S3 버킷, 과도한 IAM 권한, 공개된 메타데이터 서비스(SSRF 취약점) 등이 주요 공격 벡터입니다.

```
S3:
  □ 계정 수준 퍼블릭 접근 차단
  □ 버킷별 퍼블릭 접근 차단
  □ 서버 측 암호화 (SSE-KMS)
  □ 버전 관리 활성화
  □ 중요 버킷 MFA Delete
  □ S3 액세스 로그 활성화
  □ HTTPS 전용 버킷 정책
  □ 교차 계정 접근 최소화

RDS:
  □ 암호화 활성화 (저장 데이터)
  □ TLS 연결 강제
  □ 자동 백업 활성화 (7일 이상)
  □ 다중 AZ 배포
  □ 퍼블릭 접근 비활성화
  □ 인증서 교체 자동화

KMS:
  □ 고객 관리 키(CMK) 사용
  □ 키 교체 자동화 (연간)
  □ 키 접근 최소화
  □ CloudHSM 고려 (규정 준수)
```

### 모니터링 및 감사

```
CloudTrail:
  □ 전체 리전 다중 리전 추적 활성화
  □ 로그 파일 검증 활성화
  □ S3 로그 무결성 보호
  □ CloudWatch Logs 통합
  □ 관리 이벤트 + 데이터 이벤트 기록

CloudWatch:
  □ 루트 사용 알림
  □ 콘솔 로그인 실패 알림
  □ 보안 그룹 변경 알림
  □ IAM 정책 변경 알림
  □ CloudTrail 비활성화 알림
  □ 인터넷 게이트웨이 변경 알림

AWS Config:
  □ 활성화 (전체 리전)
  □ 컴플라이언스 규칙 설정:
    - MFA 활성화 여부
    - S3 공개 접근 차단
    - CloudTrail 활성화
    - RDS 암호화
    - IAM 비밀번호 정책

Security Hub:
  □ 활성화
  □ AWS Foundational Security Best Practices
  □ CIS AWS Foundations Benchmark
  □ PCI DSS (해당 시)
```

---

## 2. 멀티 계정 AWS 아키텍처

### AWS Organizations 보안 구조

```
Master Account
    │
    ├── Security Account (보안 도구 중앙화)
    │     ├── GuardDuty (전체 계정 통합)
    │     ├── Security Hub (전체 계정)
    │     └── CloudTrail (전체 계정 로그 수집)
    │
    ├── Log Archive Account (로그 보관)
    │     └── S3 (모든 계정의 로그 집중)
    │
    ├── Production Account
    ├── Staging Account
    ├── Development Account
    └── Shared Services Account
```

### Service Control Policy (SCP) 예시

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyLeaveOrganization",
      "Effect": "Deny",
      "Action": "organizations:LeaveOrganization",
      "Resource": "*"
    },
    {
      "Sid": "DenyRootAccess",
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "StringLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:root"
        }
      }
    },
    {
      "Sid": "DenyDisableCloudTrail",
      "Effect": "Deny",
      "Action": [
        "cloudtrail:StopLogging",
        "cloudtrail:DeleteTrail",
        "cloudtrail:UpdateTrail"
      ],
      "Resource": "*"
    },
    {
      "Sid": "DenyDisableGuardDuty",
      "Effect": "Deny",
      "Action": [
        "guardduty:DeleteDetector",
        "guardduty:DisassociateFromMasterAccount"
      ],
      "Resource": "*"
    },
    {
      "Sid": "EnforceIMDSv2",
      "Effect": "Deny",
      "Action": "ec2:RunInstances",
      "Resource": "arn:aws:ec2:*:*:instance/*",
      "Condition": {
        "StringNotEquals": {
          "ec2:MetadataHttpTokens": "required"
        }
      }
    },
    {
      "Sid": "DenyNonApprovedRegions",
      "Effect": "Deny",
      "NotAction": [
        "iam:*",
        "sts:*",
        "s3:*",
        "cloudfront:*",
        "route53:*",
        "waf:*",
        "budgets:*",
        "support:*",
        "organizations:*"
      ],
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "aws:RequestedRegion": [
            "ap-northeast-2",
            "us-east-1"
          ]
        }
      }
    }
  ]
}
```

---

## 3. Terraform으로 보안 인프라 코드화

```hcl
# security_baseline.tf
# AWS 보안 기준선 자동 설정

# GuardDuty 활성화
resource "aws_guardduty_detector" "main" {
  enable = true
  
  datasources {
    s3_logs { enable = true }
    kubernetes { audit_logs { enable = true } }
    malware_protection {
      scan_ec2_instance_with_findings { 
        ebs_volumes { enable = true } 
      }
    }
  }
}

# CloudTrail 활성화
resource "aws_cloudtrail" "main" {
  name                          = "company-cloudtrail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail.bucket
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  
  event_selector {
    read_write_type           = "All"
    include_management_events = true
    
    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::"]
    }
  }
  
  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail_cw.arn
}

# S3 버킷 공개 차단
resource "aws_s3_account_public_access_block" "main" {
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# IAM 비밀번호 정책
resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length        = 14
  require_uppercase_characters   = true
  require_lowercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  allow_users_to_change_password = true
  password_reuse_prevention      = 24
  max_password_age               = 90
  hard_expiry                    = false
}

# Security Hub 활성화
resource "aws_securityhub_account" "main" {}

resource "aws_securityhub_standards_subscription" "cis" {
  depends_on    = [aws_securityhub_account.main]
  standards_arn = "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0"
}

resource "aws_securityhub_standards_subscription" "aws_best_practices" {
  depends_on    = [aws_securityhub_account.main]
  standards_arn = "arn:aws:securityhub:ap-northeast-2::standards/aws-foundational-security-best-practices/v/1.0.0"
}

# CloudWatch 알람 - 루트 계정 사용
resource "aws_cloudwatch_metric_alarm" "root_usage" {
  alarm_name          = "root-account-usage"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "RootAccountUsage"
  namespace           = "CloudTrailMetrics"
  period              = "60"
  statistic           = "Sum"
  threshold           = "1"
  alarm_description   = "Root account has been used"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
}

# IMDSv2 강제를 위한 기본 메타데이터 옵션
resource "aws_launch_template" "secure_baseline" {
  name = "secure-baseline"
  
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"  # IMDSv2 강제
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "enabled"
  }
}
```

---

## 4. 컨테이너 보안 체크리스트 (Kubernetes)

YAML 설정 파일입니다. 쿠버네티스, CI/CD 파이프라인, 보안 도구 설정에 널리 사용되며 잘못된 설정이 보안 취약점으로 이어질 수 있습니다.

```yaml
# pod-security-policy.yaml
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: restricted
spec:
  privileged: false
  allowPrivilegeEscalation: false
  requiredDropCapabilities:
    - ALL
  volumes:
    - 'configMap'
    - 'emptyDir'
    - 'projected'
    - 'secret'
    - 'downwardAPI'
    - 'persistentVolumeClaim'
  hostNetwork: false
  hostIPC: false
  hostPID: false
  runAsUser:
    rule: 'MustRunAsNonRoot'
  seLinux:
    rule: 'RunAsAny'
  supplementalGroups:
    rule: 'MustRunAs'
    ranges:
      - min: 1
        max: 65535
  fsGroup:
    rule: 'MustRunAs'
    ranges:
      - min: 1
        max: 65535
  readOnlyRootFilesystem: true
---
# network-policy.yaml - 기본 거부 정책
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: production
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
---
# resource-limits.yaml
apiVersion: v1
kind: LimitRange
metadata:
  name: default-limits
spec:
  limits:
    - type: Container
      default:
        memory: 256Mi
        cpu: 100m
      defaultRequest:
        memory: 128Mi
        cpu: 50m
      max:
        memory: 1Gi
        cpu: 1000m
```

### Kubernetes 보안 감사 도구

```bash
# kube-bench (CIS 기준 점검)
kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job.yaml
kubectl logs job/kube-bench

# trivy (컨테이너 취약점 스캔)
trivy image nginx:latest
trivy k8s --report=all cluster

# kubesec (YAML 보안 분석)
kubesec scan pod.yaml

# falco (런타임 보안)
helm install falco falcosecurity/falco

# polaris (정책 검사)
polaris audit --format=json --output-file=results.json
```

### Kubernetes RBAC 취약점 자동 분석

```python
#!/usr/bin/env python3
"""
Kubernetes RBAC 과잉 권한 및 취약점 자동 분석 CLI
사용: python3 k8s_rbac_audit.py [--kubeconfig ~/.kube/config] [--namespace all] [--json]
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from typing import Optional

try:
    from kubernetes import client, config as k8s_config
    from kubernetes.client.exceptions import ApiException
    HAS_K8S = True
except ImportError:
    HAS_K8S = False


# ------------------------------------------------------------------ #
#  위험 권한 정의 (CIS Kubernetes Benchmark 기반)
# ------------------------------------------------------------------ #
_CRITICAL_VERBS = {"*"}
_CRITICAL_RESOURCES = {
    "*", "secrets", "nodes", "pods/exec",
    "clusterroles", "clusterrolebindings",
    "roles", "rolebindings",
}
_DANGEROUS_VERBS = {"create", "update", "patch", "delete", "deletecollection"}
_SENSITIVE_RESOURCES = {
    "secrets", "serviceaccounts/token", "pods/exec",
    "pods/portforward", "nodes", "namespaces",
}

# 클러스터 관리자 수준 권한 조합
_WILDCARD_FULL = {"verbs": "*", "resources": "*", "apiGroups": "*"}


@dataclass
class RBACFinding:
    severity: str
    kind: str          # Role | ClusterRole
    name: str
    namespace: str
    subject_kind: Optional[str] = None   # ServiceAccount | User | Group
    subject_name: Optional[str] = None
    title: str = ""
    detail: str = ""
    remediation: str = ""

    def to_dict(self) -> dict:
        return {
            "severity": self.severity,
            "kind": self.kind,
            "name": self.name,
            "namespace": self.namespace,
            "subject": f"{self.subject_kind}/{self.subject_name}" if self.subject_kind else "",
            "title": self.title,
            "detail": self.detail,
            "remediation": self.remediation,
        }


# ------------------------------------------------------------------ #
#  분석 로직
# ------------------------------------------------------------------ #
class K8sRBACAuditor:
    def __init__(self, kubeconfig: Optional[str] = None) -> None:
        if not HAS_K8S:
            raise RuntimeError("kubernetes 라이브러리 필요: pip install kubernetes")
        if kubeconfig:
            k8s_config.load_kube_config(config_file=kubeconfig)
        else:
            try:
                k8s_config.load_kube_config()
            except Exception:
                k8s_config.load_incluster_config()

        self.rbac = client.RbacAuthorizationV1Api()
        self.core = client.CoreV1Api()
        self.findings: list[RBACFinding] = []

    # ── 규칙 평가 ─────────────────────────────────────────────────────
    @staticmethod
    def _rule_is_dangerous(rule) -> tuple[bool, str]:
        verbs = set(getattr(rule, "verbs", []) or [])
        resources = set(getattr(rule, "resources", []) or [])
        api_groups = set(getattr(rule, "api_groups", []) or [])

        # 와일드카드 전체 허용
        if "*" in verbs and "*" in resources:
            return True, "모든 리소스에 대한 와일드카드 권한 (사실상 클러스터 관리자)"

        # 민감 리소스에 위험 동사
        dangerous_combo = (verbs & _DANGEROUS_VERBS) and (resources & _SENSITIVE_RESOURCES)
        if dangerous_combo:
            return True, (
                f"민감 리소스({resources & _SENSITIVE_RESOURCES})에 위험 동사"
                f"({verbs & _DANGEROUS_VERBS}) 허용"
            )

        # 시크릿 읽기
        if "secrets" in resources and ("get" in verbs or "list" in verbs or "watch" in verbs):
            return True, "secrets 리소스 읽기 권한 (자격증명 탈취 위험)"

        # pods/exec
        if "pods/exec" in resources or "pods" in resources and "create" in verbs:
            return True, "pods/exec 접근 또는 Pod 생성 권한 (컨테이너 탈출 가능)"

        return False, ""

    def _analyze_role_rules(
        self,
        role_kind: str,
        role_name: str,
        namespace: str,
        rules: list,
        subject_kind: Optional[str] = None,
        subject_name: Optional[str] = None,
    ) -> None:
        for rule in rules or []:
            is_dangerous, reason = self._rule_is_dangerous(rule)
            if is_dangerous:
                verbs = list(getattr(rule, "verbs", []) or [])
                resources = list(getattr(rule, "resources", []) or [])
                severity = "CRITICAL" if ("*" in verbs and "*" in resources) else "HIGH"
                self.findings.append(RBACFinding(
                    severity=severity,
                    kind=role_kind,
                    name=role_name,
                    namespace=namespace,
                    subject_kind=subject_kind,
                    subject_name=subject_name,
                    title=f"과잉 권한: {role_kind}/{role_name}",
                    detail=f"{reason} | verbs={verbs} resources={resources}",
                    remediation="최소 권한 원칙 적용 — 필요한 리소스/동사만 허용",
                ))

    # ── ClusterRole 분석 ──────────────────────────────────────────────
    def audit_cluster_roles(self) -> None:
        try:
            roles = self.rbac.list_cluster_role()
        except ApiException as exc:
            print(f"[경고] ClusterRole 조회 실패: {exc}", file=sys.stderr)
            return

        # ClusterRoleBinding 수집
        bindings_map: dict[str, list[tuple]] = {}
        try:
            crbs = self.rbac.list_cluster_role_binding()
            for crb in crbs.items:
                ref = crb.role_ref
                if ref.kind == "ClusterRole":
                    for subj in crb.subjects or []:
                        bindings_map.setdefault(ref.name, []).append((subj.kind, subj.name))
        except ApiException:
            pass

        for role in roles.items:
            name = role.metadata.name
            subjects = bindings_map.get(name, [(None, None)])
            for sk, sn in subjects:
                self._analyze_role_rules(
                    "ClusterRole", name, "cluster-wide",
                    role.rules, sk, sn,
                )

    # ── 네임스페이스 Role 분석 ─────────────────────────────────────────
    def audit_namespaced_roles(self, namespace: str = "") -> None:
        ns_arg = namespace if namespace and namespace != "all" else None
        try:
            if ns_arg:
                roles = self.rbac.list_namespaced_role(namespace=ns_arg)
            else:
                roles = self.rbac.list_role_for_all_namespaces()
        except ApiException as exc:
            print(f"[경고] Role 조회 실패: {exc}", file=sys.stderr)
            return

        for role in roles.items:
            ns = role.metadata.namespace
            name = role.metadata.name
            self._analyze_role_rules("Role", name, ns, role.rules)

    # ── default ServiceAccount 권한 확인 ────────────────────────────
    def check_default_sa(self) -> None:
        """default ServiceAccount에 ClusterRoleBinding 연결 여부"""
        try:
            crbs = self.rbac.list_cluster_role_binding()
            for crb in crbs.items:
                for subj in crb.subjects or []:
                    if subj.kind == "ServiceAccount" and subj.name == "default":
                        self.findings.append(RBACFinding(
                            severity="HIGH",
                            kind="ClusterRoleBinding",
                            name=crb.metadata.name,
                            namespace=subj.namespace or "all",
                            subject_kind="ServiceAccount",
                            subject_name="default",
                            title="default ServiceAccount에 ClusterRole 바인딩",
                            detail=f"ClusterRole '{crb.role_ref.name}'이 default SA에 바인딩",
                            remediation="전용 ServiceAccount 생성 후 최소 권한 Role 바인딩",
                        ))
        except ApiException:
            pass

    def run(self, namespace: str = "all") -> list[RBACFinding]:
        print("[*] ClusterRole 분석...", file=sys.stderr)
        self.audit_cluster_roles()
        print("[*] Namespaced Role 분석...", file=sys.stderr)
        self.audit_namespaced_roles(namespace)
        print("[*] default ServiceAccount 점검...", file=sys.stderr)
        self.check_default_sa()
        return sorted(
            self.findings,
            key=lambda f: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}.get(f.severity, 9),
        )


# ------------------------------------------------------------------ #
#  출력
# ------------------------------------------------------------------ #
def print_report(findings: list[RBACFinding], as_json: bool = False) -> None:
    if as_json:
        print(json.dumps([f.to_dict() for f in findings], ensure_ascii=False, indent=2))
        return

    _C = {"CRITICAL": "\033[91m", "HIGH": "\033[93m", "MEDIUM": "\033[94m"}
    _R = "\033[0m"

    print(f"\n{'='*65}")
    print(f"RBAC 취약 항목: {len(findings)}개")
    for sev in ("CRITICAL", "HIGH", "MEDIUM"):
        cnt = sum(1 for f in findings if f.severity == sev)
        if cnt:
            print(f"  {_C.get(sev,'')}{sev}{_R}: {cnt}개")

    print()
    for f in findings:
        c = _C.get(f.severity, "")
        subj = f" ← {f.subject_kind}/{f.subject_name}" if f.subject_kind else ""
        print(f"[{c}{f.severity}{_R}] {f.kind}/{f.name} [{f.namespace}]{subj}")
        print(f"  {f.title}")
        print(f"  상세  : {f.detail}")
        print(f"  조치  : {f.remediation}\n")


# ------------------------------------------------------------------ #
#  CLI
# ------------------------------------------------------------------ #
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Kubernetes RBAC 과잉 권한 분석 도구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="예시:\n"
               "  python3 k8s_rbac_audit.py\n"
               "  python3 k8s_rbac_audit.py --namespace production\n"
               "  python3 k8s_rbac_audit.py --kubeconfig ~/.kube/prod --json",
    )
    parser.add_argument("--kubeconfig", metavar="FILE", help="kubeconfig 파일 경로")
    parser.add_argument("--namespace", default="all", help="분석할 네임스페이스 (기본: all)")
    parser.add_argument("--json", action="store_true", help="JSON 형식 출력")
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if not HAS_K8S:
        print("kubernetes 라이브러리 필요: pip install kubernetes", file=sys.stderr)
        sys.exit(1)

    try:
        auditor = K8sRBACAuditor(kubeconfig=args.kubeconfig)
        findings = auditor.run(namespace=args.namespace)
        print_report(findings, as_json=args.json)
    except RuntimeError as exc:
        print(f"[-] 오류: {exc}", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        print(f"[-] 예상치 못한 오류: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
```

---

## 5. GCP/Azure 공통 체크리스트

```
GCP 보안 체크리스트:
  □ 조직 수준 정책 제약 설정
  □ VPC 서비스 제어 활성화
  □ Cloud Audit Logs 활성화
  □ Cloud Security Command Center 활성화
  □ IAM 조건부 접근 사용
  □ 서비스 계정 키 최소화 (Workload Identity)
  □ Container Analysis 활성화
  □ Binary Authorization 설정
  □ Cloud Armor WAF 설정

Azure 보안 체크리스트:
  □ Azure AD 조건부 접근 정책
  □ Azure Defender for Cloud 활성화
  □ Azure Sentinel SIEM 연동
  □ 모든 사용자 MFA 강제
  □ Privileged Identity Management (PIM) 활용
  □ 관리 계정 Just-in-Time 접근
  □ Azure Policy 컴플라이언스 규칙
  □ Key Vault 사용 (시크릿 중앙화)
  □ DDoS Protection Standard 활성화
  □ Network Watcher 플로우 로그
```

---

## 6. 클라우드 보안 사고 대응


AWS CLI를 활용한 클라우드 환경 침투 테스트 명령어입니다. 잘못 설정된 S3 버킷, 과도한 IAM 권한, 공개된 메타데이터 서비스(SSRF 취약점) 등이 주요 공격 벡터입니다.

```bash
# AWS 계정 침해 시 즉각 조치
# 1. 의심스러운 자격증명 즉시 비활성화
aws iam update-access-key \
    --access-key-id COMPROMISED_KEY \
    --status Inactive

# 2. 활성 세션 강제 종료
aws iam delete-user-policy --user-name compromised-user --policy-name *
aws iam delete-login-profile --user-name compromised-user

# 3. 영향받은 리소스 스냅샷 생성
aws ec2 create-snapshot \
    --volume-id vol-xxx \
    --description "Forensic snapshot - incident-2024-01-15"

# 4. 모든 보안 그룹 인바운드 차단
aws ec2 revoke-security-group-ingress \
    --group-id sg-xxx \
    --ip-permissions '[{"IpProtocol":"-1","IpRanges":[{"CidrIp":"0.0.0.0/0"}]}]'

# 5. CloudTrail 로그에서 공격자 행위 추출
aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=COMPROMISED_KEY \
    --start-time "2024-01-15T00:00:00Z" \
    --end-time "2024-01-16T00:00:00Z" \
    --output json
```

---

<!-- detect-validate-14 -->
## 클라우드 통제의 적용 검증

이 문서는 체크리스트·아키텍처를 다루므로, 여기서는 *무엇을 설정해야 하는가*를 넘어 **각 통제가 실제 계정에 적용됐는가**와 **드리프트하지 않는가**를 검증하는 데 집중한다. "체크리스트 통과 ≠ 런타임 적용"이다.

### 검증 항목 → 질문 → 측정 신호 → 함정

| 검증 항목 | 질문 | 측정 신호 | 함정 |
|---|---|---|---|
| 루트 계정 보호 | MFA 켜졌나? | AccountMFAEnabled=1 | 루트 키 잔존 |
| 퍼블릭 노출 | 공개 버킷 없나? | 퍼블릭 ACL/정책 0 | 신규 버킷 드리프트 |
| 감사 로깅 | 전 지역 켜졌나? | CloudTrail multi-region | 일부 지역 누락 |
| 키 수명 | 장기 키 없나? | 90일+ 키 0 | 미회전 서비스 키 |

### 검증 (직접 확인)

```bash
# 체크리스트가 실제 적용됐는지 검증(소유 계정) — 루트 MFA·퍼블릭 버킷·멀티리전 감사
aws iam get-account-summary --query 'SummaryMap.AccountMFAEnabled'   # 1 이어야(루트 MFA)
aws cloudtrail describe-trails --query 'trailList[].IsMultiRegionTrail'  # true 포함이어야
aws s3api get-bucket-policy-status --bucket my-bucket \
  --query 'PolicyStatus.IsPublic' 2>/dev/null   # false 여야(퍼블릭 아님)
```

> 검증은 **소유한 클라우드 계정·통제 환경**에서만. 체크리스트 항목 존재가 적용을 의미하지 않는다 — API 로 직접 조회해 기준 충족을 확인하고, CSPM/정기 점검으로 드리프트를 막는다([[58_Cloud_IR]], [[39_Zero_Trust_Architecture]]).

---

<a name="english"></a>

# Cloud Security Checklist & Architecture

## Cloud Security Responsibility Model

These are penetration testing commands for cloud environments using the AWS CLI. Misconfigured S3 buckets, excessive IAM permissions, and exposed metadata services (SSRF vulnerabilities) are the primary attack vectors.

```
                    Customer         AWS
                    Responsibility   Responsibility
────────────────────────────────────────────────────
Data                ████████
Identity/Access Mgmt ████████
OS/Network/Firewall ████████
Server-side Encrypt ████████
Client-side Encrypt ████████
Network Traffic     ████████
Compute                              ████████
Storage                              ████████
Database                             ████████
Networking                           ████████
Hardware/AZ/Regions                  ████████
Global Infrastructure                ████████
────────────────────────────────────────────────────
```

---

## 1. AWS Complete Security Checklist

### Account-Level Security

```
Root Account:
  □ Enable MFA on root account (hardware token recommended)
  □ Delete root access keys
  □ Prohibit daily use of root account
  □ Set up SNS alerts for root account access

IAM Policies:
  □ Principle of Least Privilege
  □ IAM Password Policy:
    - Minimum 14 characters
    - Uppercase + lowercase + numbers + special characters
    - Rotation every 90 days
    - Prevent reuse of last 24 passwords
  □ Enforce MFA for all IAM users
  □ Disable credentials unused for 90+ days
  □ Enable IAM Access Analyzer
  □ Minimize trust policies on service roles
```

### Network Security

```
VPC Configuration:
  □ Do not use the default VPC (create dedicated VPCs)
  □ Separate public/private subnets
  □ Minimize internet gateways
  □ Control outbound traffic with NAT Gateway
  □ Enable VPC Flow Logs

Security Groups:
  □ Minimize 0.0.0.0/0 inbound rules
  □ Restrict SSH (22)/RDP (3389) to specific IPs only
  □ Require descriptions on all security groups
  □ Clean up unused security groups

Network ACLs:
  □ Add explicit deny rules
  □ Consider using non-standard ports for management
  □ Minimize ephemeral port ranges

AWS WAF:
  □ Attach WAF to CloudFront/ALB
  □ Enable OWASP rule sets
  □ Configure rate limiting rules
  □ Geo-blocking (where necessary)
```

### Data Security

These are penetration testing commands for cloud environments using the AWS CLI. Misconfigured S3 buckets, excessive IAM permissions, and exposed metadata services (SSRF vulnerabilities) are the primary attack vectors.

```
S3:
  □ Block public access at account level
  □ Block public access per bucket
  □ Server-side encryption (SSE-KMS)
  □ Enable versioning
  □ Enable MFA Delete for critical buckets
  □ Enable S3 access logging
  □ HTTPS-only bucket policy
  □ Minimize cross-account access

RDS:
  □ Enable encryption (data at rest)
  □ Enforce TLS connections
  □ Enable automated backups (7+ days)
  □ Multi-AZ deployment
  □ Disable public access
  □ Automate certificate rotation

KMS:
  □ Use Customer Managed Keys (CMK)
  □ Automate key rotation (annual)
  □ Minimize key access
  □ Consider CloudHSM (for compliance)
```

### Monitoring and Auditing

```
CloudTrail:
  □ Enable multi-region trail for all regions
  □ Enable log file validation
  □ Protect S3 log integrity
  □ Integrate with CloudWatch Logs
  □ Record management events + data events

CloudWatch:
  □ Alert on root account usage
  □ Alert on console login failures
  □ Alert on security group changes
  □ Alert on IAM policy changes
  □ Alert on CloudTrail disabling
  □ Alert on internet gateway changes

AWS Config:
  □ Enable (all regions)
  □ Configure compliance rules:
    - MFA enablement
    - S3 public access blocking
    - CloudTrail enabled
    - RDS encryption
    - IAM password policy

Security Hub:
  □ Enable
  □ AWS Foundational Security Best Practices
  □ CIS AWS Foundations Benchmark
  □ PCI DSS (if applicable)
```

---

## 2. Multi-Account AWS Architecture

### AWS Organizations Security Structure

```
Master Account
    │
    ├── Security Account (centralized security tools)
    │     ├── GuardDuty (aggregated across all accounts)
    │     ├── Security Hub (all accounts)
    │     └── CloudTrail (log collection for all accounts)
    │
    ├── Log Archive Account (log storage)
    │     └── S3 (centralized logs from all accounts)
    │
    ├── Production Account
    ├── Staging Account
    ├── Development Account
    └── Shared Services Account
```

### Service Control Policy (SCP) Example

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyLeaveOrganization",
      "Effect": "Deny",
      "Action": "organizations:LeaveOrganization",
      "Resource": "*"
    },
    {
      "Sid": "DenyRootAccess",
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "StringLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:root"
        }
      }
    },
    {
      "Sid": "DenyDisableCloudTrail",
      "Effect": "Deny",
      "Action": [
        "cloudtrail:StopLogging",
        "cloudtrail:DeleteTrail",
        "cloudtrail:UpdateTrail"
      ],
      "Resource": "*"
    },
    {
      "Sid": "DenyDisableGuardDuty",
      "Effect": "Deny",
      "Action": [
        "guardduty:DeleteDetector",
        "guardduty:DisassociateFromMasterAccount"
      ],
      "Resource": "*"
    },
    {
      "Sid": "EnforceIMDSv2",
      "Effect": "Deny",
      "Action": "ec2:RunInstances",
      "Resource": "arn:aws:ec2:*:*:instance/*",
      "Condition": {
        "StringNotEquals": {
          "ec2:MetadataHttpTokens": "required"
        }
      }
    },
    {
      "Sid": "DenyNonApprovedRegions",
      "Effect": "Deny",
      "NotAction": [
        "iam:*",
        "sts:*",
        "s3:*",
        "cloudfront:*",
        "route53:*",
        "waf:*",
        "budgets:*",
        "support:*",
        "organizations:*"
      ],
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "aws:RequestedRegion": [
            "ap-northeast-2",
            "us-east-1"
          ]
        }
      }
    }
  ]
}
```

---

## 3. Codifying Security Infrastructure with Terraform

```hcl
# security_baseline.tf
# Automated AWS security baseline configuration

# Enable GuardDuty
resource "aws_guardduty_detector" "main" {
  enable = true
  
  datasources {
    s3_logs { enable = true }
    kubernetes { audit_logs { enable = true } }
    malware_protection {
      scan_ec2_instance_with_findings { 
        ebs_volumes { enable = true } 
      }
    }
  }
}

# Enable CloudTrail
resource "aws_cloudtrail" "main" {
  name                          = "company-cloudtrail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail.bucket
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  
  event_selector {
    read_write_type           = "All"
    include_management_events = true
    
    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::"]
    }
  }
  
  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail_cw.arn
}

# Block S3 bucket public access
resource "aws_s3_account_public_access_block" "main" {
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# IAM password policy
resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length        = 14
  require_uppercase_characters   = true
  require_lowercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  allow_users_to_change_password = true
  password_reuse_prevention      = 24
  max_password_age               = 90
  hard_expiry                    = false
}

# Enable Security Hub
resource "aws_securityhub_account" "main" {}

resource "aws_securityhub_standards_subscription" "cis" {
  depends_on    = [aws_securityhub_account.main]
  standards_arn = "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0"
}

resource "aws_securityhub_standards_subscription" "aws_best_practices" {
  depends_on    = [aws_securityhub_account.main]
  standards_arn = "arn:aws:securityhub:ap-northeast-2::standards/aws-foundational-security-best-practices/v/1.0.0"
}

# CloudWatch alarm - root account usage
resource "aws_cloudwatch_metric_alarm" "root_usage" {
  alarm_name          = "root-account-usage"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "RootAccountUsage"
  namespace           = "CloudTrailMetrics"
  period              = "60"
  statistic           = "Sum"
  threshold           = "1"
  alarm_description   = "Root account has been used"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
}

# Default metadata options to enforce IMDSv2
resource "aws_launch_template" "secure_baseline" {
  name = "secure-baseline"
  
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"  # Enforce IMDSv2
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "enabled"
  }
}
```

---

## 4. Container Security Checklist (Kubernetes)

YAML configuration files are widely used in Kubernetes, CI/CD pipelines, and security tool setups. Misconfigurations can lead to security vulnerabilities.

```yaml
# pod-security-policy.yaml
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: restricted
spec:
  privileged: false
  allowPrivilegeEscalation: false
  requiredDropCapabilities:
    - ALL
  volumes:
    - 'configMap'
    - 'emptyDir'
    - 'projected'
    - 'secret'
    - 'downwardAPI'
    - 'persistentVolumeClaim'
  hostNetwork: false
  hostIPC: false
  hostPID: false
  runAsUser:
    rule: 'MustRunAsNonRoot'
  seLinux:
    rule: 'RunAsAny'
  supplementalGroups:
    rule: 'MustRunAs'
    ranges:
      - min: 1
        max: 65535
  fsGroup:
    rule: 'MustRunAs'
    ranges:
      - min: 1
        max: 65535
  readOnlyRootFilesystem: true
---
# network-policy.yaml - default deny policy
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: production
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
---
# resource-limits.yaml
apiVersion: v1
kind: LimitRange
metadata:
  name: default-limits
spec:
  limits:
    - type: Container
      default:
        memory: 256Mi
        cpu: 100m
      defaultRequest:
        memory: 128Mi
        cpu: 50m
      max:
        memory: 1Gi
        cpu: 1000m
```

### Kubernetes Security Auditing Tools

```bash
# kube-bench (CIS benchmark checks)
kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job.yaml
kubectl logs job/kube-bench

# trivy (container vulnerability scanning)
trivy image nginx:latest
trivy k8s --report=all cluster

# kubesec (YAML security analysis)
kubesec scan pod.yaml

# falco (runtime security)
helm install falco falcosecurity/falco

# polaris (policy checks)
polaris audit --format=json --output-file=results.json
```

### Automated Kubernetes RBAC Vulnerability Analysis

```python
#!/usr/bin/env python3
"""
Kubernetes RBAC over-privilege and vulnerability automated analysis CLI
Usage: python3 k8s_rbac_audit.py [--kubeconfig ~/.kube/config] [--namespace all] [--json]
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from typing import Optional

try:
    from kubernetes import client, config as k8s_config
    from kubernetes.client.exceptions import ApiException
    HAS_K8S = True
except ImportError:
    HAS_K8S = False


# ------------------------------------------------------------------ #
#  Dangerous permission definitions (based on CIS Kubernetes Benchmark)
# ------------------------------------------------------------------ #
_CRITICAL_VERBS = {"*"}
_CRITICAL_RESOURCES = {
    "*", "secrets", "nodes", "pods/exec",
    "clusterroles", "clusterrolebindings",
    "roles", "rolebindings",
}
_DANGEROUS_VERBS = {"create", "update", "patch", "delete", "deletecollection"}
_SENSITIVE_RESOURCES = {
    "secrets", "serviceaccounts/token", "pods/exec",
    "pods/portforward", "nodes", "namespaces",
}

# Cluster-admin level permission combinations
_WILDCARD_FULL = {"verbs": "*", "resources": "*", "apiGroups": "*"}


@dataclass
class RBACFinding:
    severity: str
    kind: str          # Role | ClusterRole
    name: str
    namespace: str
    subject_kind: Optional[str] = None   # ServiceAccount | User | Group
    subject_name: Optional[str] = None
    title: str = ""
    detail: str = ""
    remediation: str = ""

    def to_dict(self) -> dict:
        return {
            "severity": self.severity,
            "kind": self.kind,
            "name": self.name,
            "namespace": self.namespace,
            "subject": f"{self.subject_kind}/{self.subject_name}" if self.subject_kind else "",
            "title": self.title,
            "detail": self.detail,
            "remediation": self.remediation,
        }


# ------------------------------------------------------------------ #
#  Analysis logic
# ------------------------------------------------------------------ #
class K8sRBACAuditor:
    def __init__(self, kubeconfig: Optional[str] = None) -> None:
        if not HAS_K8S:
            raise RuntimeError("kubernetes library required: pip install kubernetes")
        if kubeconfig:
            k8s_config.load_kube_config(config_file=kubeconfig)
        else:
            try:
                k8s_config.load_kube_config()
            except Exception:
                k8s_config.load_incluster_config()

        self.rbac = client.RbacAuthorizationV1Api()
        self.core = client.CoreV1Api()
        self.findings: list[RBACFinding] = []

    # ── Rule evaluation ────────────────────────────────────────────────
    @staticmethod
    def _rule_is_dangerous(rule) -> tuple[bool, str]:
        verbs = set(getattr(rule, "verbs", []) or [])
        resources = set(getattr(rule, "resources", []) or [])
        api_groups = set(getattr(rule, "api_groups", []) or [])

        # Wildcard full access
        if "*" in verbs and "*" in resources:
            return True, "Wildcard permission on all resources (effectively cluster-admin)"

        # Dangerous verbs on sensitive resources
        dangerous_combo = (verbs & _DANGEROUS_VERBS) and (resources & _SENSITIVE_RESOURCES)
        if dangerous_combo:
            return True, (
                f"Dangerous verbs ({verbs & _DANGEROUS_VERBS}) allowed on"
                f" sensitive resources ({resources & _SENSITIVE_RESOURCES})"
            )

        # Secret read access
        if "secrets" in resources and ("get" in verbs or "list" in verbs or "watch" in verbs):
            return True, "Read access to secrets resource (credential theft risk)"

        # pods/exec
        if "pods/exec" in resources or "pods" in resources and "create" in verbs:
            return True, "pods/exec access or Pod creation permission (container escape possible)"

        return False, ""

    def _analyze_role_rules(
        self,
        role_kind: str,
        role_name: str,
        namespace: str,
        rules: list,
        subject_kind: Optional[str] = None,
        subject_name: Optional[str] = None,
    ) -> None:
        for rule in rules or []:
            is_dangerous, reason = self._rule_is_dangerous(rule)
            if is_dangerous:
                verbs = list(getattr(rule, "verbs", []) or [])
                resources = list(getattr(rule, "resources", []) or [])
                severity = "CRITICAL" if ("*" in verbs and "*" in resources) else "HIGH"
                self.findings.append(RBACFinding(
                    severity=severity,
                    kind=role_kind,
                    name=role_name,
                    namespace=namespace,
                    subject_kind=subject_kind,
                    subject_name=subject_name,
                    title=f"Excessive privilege: {role_kind}/{role_name}",
                    detail=f"{reason} | verbs={verbs} resources={resources}",
                    remediation="Apply principle of least privilege — allow only necessary resources/verbs",
                ))

    # ── ClusterRole analysis ───────────────────────────────────────────
    def audit_cluster_roles(self) -> None:
        try:
            roles = self.rbac.list_cluster_role()
        except ApiException as exc:
            print(f"[WARNING] Failed to list ClusterRoles: {exc}", file=sys.stderr)
            return

        # Collect ClusterRoleBindings
        bindings_map: dict[str, list[tuple]] = {}
        try:
            crbs = self.rbac.list_cluster_role_binding()
            for crb in crbs.items:
                ref = crb.role_ref
                if ref.kind == "ClusterRole":
                    for subj in crb.subjects or []:
                        bindings_map.setdefault(ref.name, []).append((subj.kind, subj.name))
        except ApiException:
            pass

        for role in roles.items:
            name = role.metadata.name
            subjects = bindings_map.get(name, [(None, None)])
            for sk, sn in subjects:
                self._analyze_role_rules(
                    "ClusterRole", name, "cluster-wide",
                    role.rules, sk, sn,
                )

    # ── Namespaced Role analysis ───────────────────────────────────────
    def audit_namespaced_roles(self, namespace: str = "") -> None:
        ns_arg = namespace if namespace and namespace != "all" else None
        try:
            if ns_arg:
                roles = self.rbac.list_namespaced_role(namespace=ns_arg)
            else:
                roles = self.rbac.list_role_for_all_namespaces()
        except ApiException as exc:
            print(f"[WARNING] Failed to list Roles: {exc}", file=sys.stderr)
            return

        for role in roles.items:
            ns = role.metadata.namespace
            name = role.metadata.name
            self._analyze_role_rules("Role", name, ns, role.rules)

    # ── Check default ServiceAccount permissions ─────────────────────
    def check_default_sa(self) -> None:
        """Check whether ClusterRoleBinding is attached to default ServiceAccount"""
        try:
            crbs = self.rbac.list_cluster_role_binding()
            for crb in crbs.items:
                for subj in crb.subjects or []:
                    if subj.kind == "ServiceAccount" and subj.name == "default":
                        self.findings.append(RBACFinding(
                            severity="HIGH",
                            kind="ClusterRoleBinding",
                            name=crb.metadata.name,
                            namespace=subj.namespace or "all",
                            subject_kind="ServiceAccount",
                            subject_name="default",
                            title="ClusterRole bound to default ServiceAccount",
                            detail=f"ClusterRole '{crb.role_ref.name}' is bound to default SA",
                            remediation="Create a dedicated ServiceAccount and bind a minimal privilege Role",
                        ))
        except ApiException:
            pass

    def run(self, namespace: str = "all") -> list[RBACFinding]:
        print("[*] Analyzing ClusterRoles...", file=sys.stderr)
        self.audit_cluster_roles()
        print("[*] Analyzing Namespaced Roles...", file=sys.stderr)
        self.audit_namespaced_roles(namespace)
        print("[*] Checking default ServiceAccount...", file=sys.stderr)
        self.check_default_sa()
        return sorted(
            self.findings,
            key=lambda f: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}.get(f.severity, 9),
        )


# ------------------------------------------------------------------ #
#  Output
# ------------------------------------------------------------------ #
def print_report(findings: list[RBACFinding], as_json: bool = False) -> None:
    if as_json:
        print(json.dumps([f.to_dict() for f in findings], ensure_ascii=False, indent=2))
        return

    _C = {"CRITICAL": "\033[91m", "HIGH": "\033[93m", "MEDIUM": "\033[94m"}
    _R = "\033[0m"

    print(f"\n{'='*65}")
    print(f"RBAC vulnerable items: {len(findings)}")
    for sev in ("CRITICAL", "HIGH", "MEDIUM"):
        cnt = sum(1 for f in findings if f.severity == sev)
        if cnt:
            print(f"  {_C.get(sev,'')}{sev}{_R}: {cnt}")

    print()
    for f in findings:
        c = _C.get(f.severity, "")
        subj = f" <- {f.subject_kind}/{f.subject_name}" if f.subject_kind else ""
        print(f"[{c}{f.severity}{_R}] {f.kind}/{f.name} [{f.namespace}]{subj}")
        print(f"  {f.title}")
        print(f"  Detail      : {f.detail}")
        print(f"  Remediation : {f.remediation}\n")


# ------------------------------------------------------------------ #
#  CLI
# ------------------------------------------------------------------ #
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Kubernetes RBAC over-privilege analysis tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
               "  python3 k8s_rbac_audit.py\n"
               "  python3 k8s_rbac_audit.py --namespace production\n"
               "  python3 k8s_rbac_audit.py --kubeconfig ~/.kube/prod --json",
    )
    parser.add_argument("--kubeconfig", metavar="FILE", help="Path to kubeconfig file")
    parser.add_argument("--namespace", default="all", help="Namespace to analyze (default: all)")
    parser.add_argument("--json", action="store_true", help="Output in JSON format")
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if not HAS_K8S:
        print("kubernetes library required: pip install kubernetes", file=sys.stderr)
        sys.exit(1)

    try:
        auditor = K8sRBACAuditor(kubeconfig=args.kubeconfig)
        findings = auditor.run(namespace=args.namespace)
        print_report(findings, as_json=args.json)
    except RuntimeError as exc:
        print(f"[-] Error: {exc}", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        print(f"[-] Unexpected error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
```

---

## 5. GCP/Azure Common Checklist

```
GCP Security Checklist:
  □ Configure organization-level policy constraints
  □ Enable VPC Service Controls
  □ Enable Cloud Audit Logs
  □ Enable Cloud Security Command Center
  □ Use IAM Conditional Access
  □ Minimize service account keys (use Workload Identity)
  □ Enable Container Analysis
  □ Configure Binary Authorization
  □ Configure Cloud Armor WAF

Azure Security Checklist:
  □ Azure AD Conditional Access Policies
  □ Enable Azure Defender for Cloud
  □ Integrate Azure Sentinel SIEM
  □ Enforce MFA for all users
  □ Use Privileged Identity Management (PIM)
  □ Just-in-Time access for admin accounts
  □ Azure Policy compliance rules
  □ Use Key Vault (centralize secrets)
  □ Enable DDoS Protection Standard
  □ Network Watcher flow logs
```

---

## 6. Cloud Security Incident Response

These are penetration testing commands for cloud environments using the AWS CLI. Misconfigured S3 buckets, excessive IAM permissions, and exposed metadata services (SSRF vulnerabilities) are the primary attack vectors.

```bash
# Immediate response to AWS account compromise
# 1. Immediately disable suspicious credentials
aws iam update-access-key \
    --access-key-id COMPROMISED_KEY \
    --status Inactive

# 2. Forcibly terminate active sessions
aws iam delete-user-policy --user-name compromised-user --policy-name *
aws iam delete-login-profile --user-name compromised-user

# 3. Create snapshots of affected resources
aws ec2 create-snapshot \
    --volume-id vol-xxx \
    --description "Forensic snapshot - incident-2024-01-15"

# 4. Block all security group inbound traffic
aws ec2 revoke-security-group-ingress \
    --group-id sg-xxx \
    --ip-permissions '[{"IpProtocol":"-1","IpRanges":[{"CidrIp":"0.0.0.0/0"}]}]'

# 5. Extract attacker activity from CloudTrail logs
aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=COMPROMISED_KEY \
    --start-time "2024-01-15T00:00:00Z" \
    --end-time "2024-01-16T00:00:00Z" \
    --output json
```

<!-- detect-validate-14 -->
## Validating Cloud Control Application

Since this document covers checklists/architecture, here we go beyond *what should be configured* to verify **whether each control is actually applied to the account** and **does not drift**. "Checklist passed != applied at runtime."

### Element -> Question -> Measured signal -> Pitfall

| Element | Question | Measured signal | Pitfall |
|---|---|---|---|
| Root account protection | MFA on? | AccountMFAEnabled=1 | Root keys remain |
| Public exposure | No public buckets? | 0 public ACL/policy | New-bucket drift |
| Audit logging | All regions on? | CloudTrail multi-region | Some regions missing |
| Key lifetime | No long-lived keys? | 0 keys 90+ days | Unrotated service keys |

### Validation (verify directly)

```bash
# Verify checklist items are actually applied (own account) — root MFA, public buckets, multi-region audit
aws iam get-account-summary --query 'SummaryMap.AccountMFAEnabled'   # must be 1 (root MFA)
aws cloudtrail describe-trails --query 'trailList[].IsMultiRegionTrail'  # must include true
aws s3api get-bucket-policy-status --bucket my-bucket \
  --query 'PolicyStatus.IsPublic' 2>/dev/null   # must be false (not public)
```

> Validate only on **owned cloud accounts / controlled environments**. A checklist item's existence does not mean it is applied — query via API to confirm baselines and prevent drift with CSPM/periodic checks ([[58_Cloud_IR]], [[39_Zero_Trust_Architecture]]).
