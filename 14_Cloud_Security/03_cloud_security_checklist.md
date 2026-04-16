# 클라우드 보안 체크리스트 & 아키텍처

## 클라우드 보안 책임 모델

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
