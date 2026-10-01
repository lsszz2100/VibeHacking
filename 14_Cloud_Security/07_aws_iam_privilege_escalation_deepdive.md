# 14-07. AWS IAM Privilege Escalation & Cloud Governance Deepdive: PassRole Exploitation, STS AssumeRole Lateral Movement & SCP Enforcement
# 14-07. AWS IAM 권한 상승 및 클라우드 거버넌스 심층 분석: PassRole 익스플로잇, STS AssumeRole 횡적이동 및 SCP 하드닝

> **핵심 키워드**: AWS IAM Policy Evaluation Logic, Rhino Security Labs 21 Escalation Methods, `iam:PassRole`, `ec2:RunInstances`, AWS STS `AssumeRole`, Wildcard Principal (`*`), Confused Deputy Attack, AWS Organizations Service Control Policies (SCP), IAM Permission Boundary, Attribute-Based Access Control (ABAC), CloudTrail & GuardDuty Telemetry.

---

## 1. 개요 및 클라우드 아이덴티티 위협 모델 (Executive Summary & Threat Landscape)

### 1.1 배경 및 문제 정의 (Context & Problem Definition)
클라우드 인프라(AWS)의 보안 경계(Security Perimeter)는 물리적 방화벽이나 IP 네트워크 대역이 아니라 **아이덴티티(Identity & Access Management, IAM)**입니다. 현대 클라우드 침해 사고의 80% 이상은 취약한 웹 애플리케이션의 SSRF, 개발자의 API 키 유출, 또는 깃허브 공개 리포지토리 노출로 인한 **초기 저권한 IAM 자격증명 획득**에서 시작됩니다.

공격자는 일단 저권한 사용자나 임시 세션을 확보하면, 클라우드 환경 내에 산재된 정책 설정 오류(Misconfigurations)를 결합하여 단시간 내에 **`AdministratorAccess`** 권한으로 수직 상승(Privilege Escalation)하거나, 다른 계정으로 수평 횡적이동(Lateral Movement)합니다.

```
 [ Initial Compromise ]
 (Intern Developer / SSRF)
           │
           │  1. iam:PassRole + ec2:RunInstances
           ▼
 ┌───────────────────────────────────────────────┐
 │ Escalated Compute Instance (Metadata Service) │
 │ Role: CloudSecAdminRole (AdministratorAccess) │
 └───────────────────────────────────────────────┘
           │
           │  2. sts:AssumeRole (Wildcard Trust)
           ▼
 ┌───────────────────────────────────────────────┐
 │ Target Enterprise Account Audit Role          │
 │ Role: CrossAccountAuditRole                   │
 └───────────────────────────────────────────────┘
           │
           │  3. Hardening Defense
           ▼
 ┌───────────────────────────────────────────────┐
 │ AWS Organizations SCP + Permission Boundary   │
 │ Result: Explicit Deny Blocks All Abuse        │
 └───────────────────────────────────────────────┘
```

---

## 2. AWS IAM 정책 평가 로직 심층 분석 (Policy Evaluation Architecture)

### 2.1 6단계 권한 결정 트리 (The 6-Layer Decision Logic)
AWS 요청이 발생하면 PDP(Policy Decision Point)는 다음 순서로 엄격하게 권한을 평가합니다:

1. **명시적 거부 (Explicit Deny)**: 어떤 정책에서든 `"Effect": "Deny"`가 일치하면 즉각 거부 (최우선권).
2. **조직 서비스 제어 정책 (Organizations SCP)**: 계정 수준의 최대 허용 권한 경계를 정의. SCP에서 허용되지 않은 액션은 차단됨.
3. **리소스 기반 정책 (Resource-based Policy)**: S3 버킷 정책, KMS 키 정책 등. Principal과 Resource 간 직접 허용 여부 판정.
4. **권한 경계 (Permission Boundary)**: IAM 사용자/역할에 설정된 최대 권한 한도.
5. **세션 정책 (Session Policy)**: `AssumeRole` 시 추가로 전달된 축소 정책.
6. **아이덴티티 기반 정책 (Identity-based Policy)**: 인라인 정책 및 관리형 정책의 `"Effect": "Allow"`. 기본값은 암시적 거부(Implicit Deny).

```
   [ Request Received ]
            │
            ▼
    Is there an Explicit DENY? ────(YES)───> [ Access DENIED ]
            │ (NO)
            ▼
   Allowed by Organizations SCP? ──(NO)────> [ Access DENIED ]
            │ (YES)
            ▼
   Allowed by Resource Policy OR Identity Policy?
            │ (NO)
            ▼
    [ Access DENIED (Implicit) ]
            │ (YES)
            ▼
   Within Permission Boundary? ────(NO)────> [ Access DENIED ]
            │ (YES)
            ▼
       [ Access ALLOWED ]
```

---

## 3. 대표적 IAM 권한 상승 벡터 (Known Escalation Techniques)

Rhino Security Labs의 21가지 공격 분류 중 실무에서 가장 빈번하게 악용되는 핵심 기법을 분석합니다:

### 3.1 `iam:PassRole` + `ec2:RunInstances` (컴퓨트 인스턴스 위임)
- **원리**: 사용자가 `ec2:RunInstances` 권한과 `iam:PassRole` 권한을 함께 보유한 경우, 자신보다 훨씬 높은 권한(예: `AdministratorAccess`)을 가진 인스턴스 프로파일을 EC2에 연결하여 기동할 수 있습니다.
- **익스플로잇**: EC2 인스턴스의 UserData 스크립트에 리버스 쉘이나 IMDSv1 자격증명 추출 명령(`curl http://169.254.169.254/...`)을 주입하여 최고 관리자 임시 키를 회수합니다.

### 3.2 `iam:CreatePolicyVersion` / `SetDefaultPolicyVersion`
- **원리**: 정책 수정 권한이 있는 사용자가 기존 정책에 새로운 버전(`v2`)을 생성하면서 `"Action": "*", "Resource": "*"`를 선언하고 이를 기본 버전으로 활성화.

### 3.3 `sts:AssumeRole` 크로스 어카운트 와일드카드 신뢰 악용
- **원리**: 다른 계정이나 서드파티 벤더의 접근을 위해 생성된 역할의 신뢰 정책(Trust Policy)에 `"Principal": {"AWS": "*"}` 또는 외부 ID 검증(`sts:ExternalId`)이 누락된 경우, 임의의 외부 공격자가 해당 역할을 탈취(Confused Deputy 취약점).

---

## 4. Lab 35 (CloudPwnLab) 실전 워크스루 (Lab 35 Step-by-Step Walkthrough)

### 4.1 Step 1: `iam:PassRole`을 통한 EC2 관리자 역할 위임 및 자격증명 탈취
- **목표**: 저권한 `intern-developer` 신분으로 `CloudSecAdminRole`을 위임하여 인스턴스를 기동하고 마스터 관리자 키를 탈취.
- **요청 PoC**:
  ```bash
  curl -s -X POST http://localhost:8035/api/cloud/iam/passrole \
    -H "Content-Type: application/json" \
    -d '{"target_role": "CloudSecAdminRole", "service_type": "ec2"}' | jq .
  ```
- **획득 플래그**: `FLAG{CLOUD_IAM_PASSROLE_EC2_PRIV_ESCALATED_1120}`

### 4.2 Step 2: `sts:AssumeRole` 와일드카드 신뢰 관계 익스플로잇
- **목표**: `CrossAccountAuditRole`의 취약한 신뢰 정책을 악용하여 STS 임시 자격증명 발급.
- **요청 PoC**:
  ```bash
  curl -s -X POST http://localhost:8035/api/cloud/iam/assumerole \
    -H "Content-Type: application/json" \
    -d '{"role_arn": "arn:aws:iam::123456789012:role/CrossAccountAuditRole", "role_session_name": "attacker-audit"}' | jq .
  ```
- **획득 플래그**: `FLAG{CLOUD_STS_ASSUMEROLE_TRUST_POLICY_PWNED_2231}`

### 4.3 Step 3: 다계층 클라우드 거버넌스 하드닝 (SCP & Permission Boundary)
- **목표**: 조직 SCP 명시적 Deny 및 태그 기반 PassRole 제한을 활성화하여 모든 공격 벡터를 영구 무력화.
- **요청 PoC**:
  ```bash
  curl -s -X POST http://localhost:8035/api/cloud/iam/scp/harden \
    -H "Content-Type: application/json" \
    -d '{"enforce_scp": true, "enforce_permission_boundary": true, "restrict_passrole_resources": true}' | jq .
  ```
- **획득 플래그**: `FLAG{CLOUD_ORG_SCP_PERMISSION_BOUNDARY_ENFORCED_3342}`

---

## 5. 엔터프라이즈 방어 및 거버넌스 아키텍처 (Enterprise Defense Architecture)

1. **태그 기반 리소스 제약 (Tag-based PassRole Restriction)**:
   ```json
   {
     "Effect": "Allow",
     "Action": "iam:PassRole",
     "Resource": "arn:aws:iam::123456789012:role/app-scoped-*",
     "Condition": {
       "StringEquals": {
         "iam:PassedToService": "ec2.amazonaws.com"
       }
     }
   }
   ```
2. **조직 차원의 SCP 가드레일 (Service Control Policy)**:
   - 루트 또는 OU 수준에서 `iam:CreatePolicyVersion`, `iam:AttachUserPolicy` 등 민감 액션에 대한 명시적 Deny 적용.
   - `aws:PrincipalOrgID` 조건을 강제하여 외부 계정에서의 비인가 `sts:AssumeRole` 전면 차단.
3. **IAM 권한 경계 (Permission Boundary) 강제**:
   - 모든 신규 IAM 역할 생성 시 정해진 권한 경계가 첨부되지 않으면 생성을 거부하는 정책(`iam:PermissionsBoundary`) 수립.
4. **CloudTrail & GuardDuty 이상 징후 실전 탐지**:
   - `EventName: RunInstances`에 평소 사용되지 않는 고권한 인스턴스 프로파일이 지정된 이벤트 감시.
   - GuardDuty `PrivilegeEscalation:IAMUser/AnomalousPolicyModification` 실시간 경보 연동.
