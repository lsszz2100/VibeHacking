#!/usr/bin/env python3
"""
Generates the 49th Wargame Track: 'cloudiam' (Cloud IAM Privilege Escalation & Governance - 35 Challenges)
Integrates cleanly into challenges.js, solve-derivable.js, and README.md.
"""

import hashlib
import json
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CHALLENGES_JS = REPO_ROOT / "wargame" / "assets" / "challenges.js"
INDEX_HTML = REPO_ROOT / "wargame" / "index.html"
SOLVE_DERIVABLE_JS = REPO_ROOT / "wargame" / "scripts" / "solve-derivable.js"
WARGAME_README = REPO_ROOT / "wargame" / "README.md"
CLI_TEST = REPO_ROOT / "wargame" / "tests" / "test_cli.py"

TRACK_INFO = {
    "id": "cloudiam",
    "icon": "☁️",
    "ko": "클라우드 IAM 권한 상승·거버넌스",
    "en": "Cloud IAM Privilege Escalation & Governance",
    "desc_ko": "AWS IAM 정책 평가 로직·iam:PassRole·sts:AssumeRole 크로스 어카운트·조직 SCP 가드레일 및 권한 경계(Permission Boundary).",
    "desc_en": "AWS IAM evaluation logic, PassRole escalation, cross-account AssumeRole, Organization SCP guardrails, and Permission Boundaries."
}

RAW_CHALLENGES = [
    # Tier 0 (입문: 7 challenges, points 20~35)
    (0, "t0_cloudiam_eval_logic_order", 25,
     "AWS IAM 6단계 정책 평가 우선순위",
     "IAM Policy Evaluation Logic Order",
     "명시적 거부(Deny), SCP, 리소스 정책, 권한 경계, 세션 정책, 아이덴티티 정책 순서의 평가 로직을 분석합니다.\n지정된 식별자 `cloudiam_eval_logic_order_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"cloudiam_eval_logic_order_v1\") 앞 20자리}`",
     "Analyze the 6-layer policy evaluation logic: Explicit Deny, SCP, Resource policy, Boundary, Session, and Identity.\nCompute the first 20 hex characters of SHA256(\"cloudiam_eval_logic_order_v1\").\n\nFormat: `FLAG{SHA256(\"cloudiam_eval_logic_order_v1\") first 20 hex}`",
     ["어떤 허용(Allow)도 명시적 거부(Explicit Deny)를 번복할 수 없음을 확인하세요.", "식별자 `cloudiam_eval_logic_order_v1`의 해시 앞 20자리를 추출하세요."],
     ["Explicit Deny overrides all Allow statements.", "Extract first 20 hex chars of SHA256(\"cloudiam_eval_logic_order_v1\")."]),

    (0, "t0_cloudiam_explicit_deny", 25,
     "명시적 거부(Explicit Deny) 절대 우선권",
     "Explicit Deny Precedence",
     "Identity 정책에 Allow가 있더라도 SCP 또는 인라인 정책의 Deny가 요청을 즉시 차단하는 불변 규칙을 점검합니다.\n지정된 식별자 `cloudiam_explicit_deny_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"cloudiam_explicit_deny_v1\") 앞 20자리}`",
     "Examine the rule where an explicit Deny in any matching policy immediately terminates evaluation with Access Denied.\nCompute the first 20 hex characters of SHA256(\"cloudiam_explicit_deny_v1\").\n\nFormat: `FLAG{SHA256(\"cloudiam_explicit_deny_v1\") first 20 hex}`",
     ["Effect: Deny 문맥의 최우선 적용 원리를 분석하세요.", "식별자 `cloudiam_explicit_deny_v1`의 해시 앞 20자리를 제출하세요."],
     ["Review absolute precedence of Effect: Deny.", "Extract first 20 hex chars of SHA256(\"cloudiam_explicit_deny_v1\")."]),

    (0, "t0_cloudiam_arn_structure", 30,
     "AWS 리소스 ARN 구조와 파티션",
     "AWS ARN Structure & Partition Parsing",
     "arn:partition:service:region:account-id:resource-id 6개 필드로 구성되는 Amazon Resource Name을 분석합니다.\n지정된 식별자 `cloudiam_arn_structure_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"cloudiam_arn_structure_v1\") 앞 20자리}`",
     "Parse the 6 standard colon-delimited components of an Amazon Resource Name (ARN).\nCompute the first 20 hex characters of SHA256(\"cloudiam_arn_structure_v1\").\n\nFormat: `FLAG{SHA256(\"cloudiam_arn_structure_v1\") first 20 hex}`",
     ["arn:aws:iam::account:role/name 포맷을 확인하세요.", "식별자 `cloudiam_arn_structure_v1`의 해시 앞 20자리를 추출하세요."],
     ["Check arn:aws:iam::account:role/name syntax.", "Extract first 20 hex chars of SHA256(\"cloudiam_arn_structure_v1\")."]),

    (0, "t0_cloudiam_principal_types", 30,
     "IAM 보안 주체(Principal) 유형 분류",
     "IAM Principal Types: User, Role, Service",
     "AWS 계정 루트, IAM 사용자, 역할(Role), AWS 서비스 및 연합(Federated) 신원 등 Principal 선언 유형을 분류합니다.\n지정된 식별자 `cloudiam_principal_types_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"cloudiam_principal_types_v1\") 앞 20자리}`",
     "Classify AWS principal types: IAM users, federated identities, assumed roles, and AWS service principals.\nCompute the first 20 hex characters of SHA256(\"cloudiam_principal_types_v1\").\n\nFormat: `FLAG{SHA256(\"cloudiam_principal_types_v1\") first 20 hex}`",
     ["Service: ec2.amazonaws.com 등 서비스 주체 표현을 확인하세요.", "식별자 `cloudiam_principal_types_v1`의 해시 앞 20자리를 제출하세요."],
     ["Review service principal declarations like ec2.amazonaws.com.", "Extract first 20 hex chars of SHA256(\"cloudiam_principal_types_v1\")."]),

    (0, "t0_cloudiam_action_wildcards", 30,
     "IAM Action 와일드카드 축약 규정",
     "IAM Action Wildcard Syntax",
     "s3:* 또는 ec2:Describe* 등 와일드카드(*)를 사용할 때 의도치 않게 고권한 액션이 포함되는 위험성을 분석합니다.\n지정된 식별자 `cloudiam_action_wildcards_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"cloudiam_action_wildcards_v1\") 앞 20자리}`",
     "Evaluate over-permissive wildcard actions (s3:*, iam:*) granting destructive administrative APIs.\nCompute the first 20 hex characters of SHA256(\"cloudiam_action_wildcards_v1\").\n\nFormat: `FLAG{SHA256(\"cloudiam_action_wildcards_v1\") first 20 hex}`",
     ["iam:* 와일드카드가 관리자 권한과 동등함을 확인하세요.", "식별자 `cloudiam_action_wildcards_v1`의 해시 앞 20자리를 제출하세요."],
     ["Wildcard iam:* effectively grants full account takeover.", "Extract first 20 hex chars of SHA256(\"cloudiam_action_wildcards_v1\")."]),

    (0, "t0_cloudiam_condition_operators", 35,
     "IAM Condition 연산자(StringEquals, ArnLike)",
     "IAM Condition Key Evaluation",
     "StringEquals, ArnLike, Bool, IpAddress 등 정책 요청 컨텍스트를 검증하는 Condition 블록의 평가 메커니즘을 분석합니다.\n지정된 식별자 `cloudiam_condition_operators_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"cloudiam_condition_operators_v1\") 앞 20자리}`",
     "Analyze IAM condition keys (aws:PrincipalArn, aws:RequestedRegion) and operators (StringEquals, IpAddress).\nCompute the first 20 hex characters of SHA256(\"cloudiam_condition_operators_v1\").\n\nFormat: `FLAG{SHA256(\"cloudiam_condition_operators_v1\") first 20 hex}`",
     ["aws:PrincipalOrgID 조건 키를 통한 조직 단위 접근 제어를 확인하세요.", "식별자 `cloudiam_condition_operators_v1`의 해시 앞 20자리를 제출하세요."],
     ["Inspect aws:PrincipalOrgID condition keys.", "Extract first 20 hex chars of SHA256(\"cloudiam_condition_operators_v1\")."]),

    (0, "t0_cloudiam_sts_get_caller_identity", 35,
     "STS GetCallerIdentity 신원 검증",
     "STS GetCallerIdentity Verification",
     "탈취한 액세스 키의 계정 ID, 사용자 ARN, 역할 세션 ID를 파악하기 위한 aws sts get-caller-identity 명령을 점검합니다.\n지정된 식별자 `cloudiam_sts_get_caller_identity_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"cloudiam_sts_get_caller_identity_v1\") 앞 20자리}`",
     "Run sts:GetCallerIdentity to reveal current AWS account ID, caller ARN, and assumed role credentials.\nCompute the first 20 hex characters of SHA256(\"cloudiam_sts_get_caller_identity_v1\").\n\nFormat: `FLAG{SHA256(\"cloudiam_sts_get_caller_identity_v1\") first 20 hex}`",
     ["UserId, Account, Arn 필드가 반환되는 기본 응답을 확인하세요.", "식별자 `cloudiam_sts_get_caller_identity_v1`의 해시 앞 20자리를 제출하세요."],
     ["Examine UserId, Account, and Arn fields in STS response.", "Extract first 20 hex chars of SHA256(\"cloudiam_sts_get_caller_identity_v1\")."]),

    # Tier 1 (초급: 7 challenges, points 50~80)
    (1, "t1_cloudiam_passrole_service_link", 55,
     "iam:PassRole과 서비스 위임 원리",
     "iam:PassRole Service Linkage",
     "사용자가 생성하거나 기동하는 AWS 리소스(EC2, Lambda)에 IAM 역할을 전달할 때 필요한 iam:PassRole 권한을 분석합니다.\n지정된 식별자 `cloudiam_passrole_service_link_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"cloudiam_passrole_service_link_v1\") 앞 20자리}`",
     "Understand iam:PassRole semantics enabling users to assign IAM service roles to compute resources.\nCompute the first 20 hex characters of SHA256(\"cloudiam_passrole_service_link_v1\").\n\nFormat: `FLAG{SHA256(\"cloudiam_passrole_service_link_v1\") first 20 hex}`",
     ["iam:PassRole은 서비스가 역할을 수탁받도록 승인하는 행위임을 확인하세요.", "식별자 `cloudiam_passrole_service_link_v1`의 해시 앞 20자리를 제출하세요."],
     ["PassRole authorizes a service to assume an execution role.", "Extract first 20 hex chars of SHA256(\"cloudiam_passrole_service_link_v1\")."]),

    (1, "t1_cloudiam_instance_profile_assoc", 55,
     "EC2 인스턴스 프로파일과 역할 연결",
     "EC2 Instance Profile Association",
     "EC2 인스턴스가 IAM 역할을 전달받기 위한 컨테이너 객체인 Instance Profile의 생성 및 연결 구조를 분석합니다.\n지정된 식별자 `cloudiam_instance_profile_assoc_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"cloudiam_instance_profile_assoc_v1\") 앞 20자리}`",
     "Inspect EC2 Instance Profile wrappers linking IAM roles to virtual machine metadata services.\nCompute the first 20 hex characters of SHA256(\"cloudiam_instance_profile_assoc_v1\").\n\nFormat: `FLAG{SHA256(\"cloudiam_instance_profile_assoc_v1\") first 20 hex}`",
     ["iam:AddRoleToInstanceProfile 명령 구조를 점검하세요.", "식별자 `cloudiam_instance_profile_assoc_v1`의 해시 앞 20자리를 제출하세요."],
     ["Review AddRoleToInstanceProfile API operations.", "Extract first 20 hex chars of SHA256(\"cloudiam_instance_profile_assoc_v1\")."]),

    (1, "t1_cloudiam_imds_v1_vs_v2", 65,
     "IMDSv1 vs IMDSv2 토큰 헤더 방어",
     "IMDSv1 vs IMDSv2 Security Token",
     "SSRF 공격에 취약한 IMDSv1 단순 GET 요청과 PUT 세션 토큰(X-aws-ec2-metadata-token)을 강제하는 IMDSv2를 비교합니다.\n지정된 식별자 `cloudiam_imds_v1_vs_v2_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"cloudiam_imds_v1_vs_v2_v1\") 앞 20자리}`",
     "Compare simple GET metadata requests in IMDSv1 against session token headers (X-aws-ec2-metadata-token) in IMDSv2.\nCompute the first 20 hex characters of SHA256(\"cloudiam_imds_v1_vs_v2_v1\").\n\nFormat: `FLAG{SHA256(\"cloudiam_imds_v1_vs_v2_v1\") first 20 hex}`",
     ["HttpTokens=required 설정을 통한 IMDSv2 강제 적용을 확인하세요.", "식별자 `cloudiam_imds_v1_vs_v2_v1`의 해시 앞 20자리를 제출하세요."],
     ["Enforce IMDSv2 with HttpTokens=required.", "Extract first 20 hex chars of SHA256(\"cloudiam_imds_v1_vs_v2_v1\")."]),

    (1, "t1_cloudiam_trust_policy_syntax", 70,
     "IAM 역할 신뢰 정책(AssumeRolePolicyDocument)",
     "Role Trust Relationship Policy Syntax",
     "어떤 Principal이 해당 역할을 맡을(Assume) 수 있는지 정의하는 AssumeRolePolicyDocument 신뢰 정책 구조를 분석합니다.\n지정된 식별자 `cloudiam_trust_policy_syntax_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"cloudiam_trust_policy_syntax_v1\") 앞 20자리}`",
     "Inspect AssumeRolePolicyDocument blocks specifying which AWS services or identities can assume a role.\nCompute the first 20 hex characters of SHA256(\"cloudiam_trust_policy_syntax_v1\").\n\nFormat: `FLAG{SHA256(\"cloudiam_trust_policy_syntax_v1\") first 20 hex}`",
     ["sts:AssumeRole 액션이 신뢰 정책의 유일한 허용 대상임을 확인하세요.", "식별자 `cloudiam_trust_policy_syntax_v1`의 해시 앞 20자리를 제출하세요."],
     ["Ensure sts:AssumeRole is explicitly permitted in trust policies.", "Extract first 20 hex chars of SHA256(\"cloudiam_trust_policy_syntax_v1\")."]),

    (1, "t1_cloudiam_inline_vs_managed", 70,
     "인라인 정책 vs 고객 관리형 정책 차이",
     "Inline vs Customer Managed Policies",
     "단일 IAM 주체에 영구 결합되는 인라인 정책과 여러 주체에 재사용 가능한 독립 ARN 관리형 정책의 특성을 비교합니다.\n지정된 식별자 `cloudiam_inline_vs_managed_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"cloudiam_inline_vs_managed_v1\") 앞 20자리}`",
     "Differentiate standalone customer-managed policies with versioning from inline embedded policies.\nCompute the first 20 hex characters of SHA256(\"cloudiam_inline_vs_managed_v1\").\n\nFormat: `FLAG{SHA256(\"cloudiam_inline_vs_managed_v1\") first 20 hex}`",
     ["관리형 정책은 최대 5개 버전을 유지할 수 있음을 확인하세요.", "식별자 `cloudiam_inline_vs_managed_v1`의 해시 앞 20자리를 제출하세요."],
     ["Managed policies support up to 5 concurrent versions.", "Extract first 20 hex chars of SHA256(\"cloudiam_inline_vs_managed_v1\")."]),

    (1, "t1_cloudiam_sts_token_expiration", 75,
     "STS 임시 자격증명 만료 메커니즘",
     "STS Temporary Credentials Expiry",
     "AccessKeyId(ASIA), SecretAccessKey 및 SessionToken으로 구성되는 STS 자격증명의 15분~12시간 수명 주기를 분석합니다.\n지정된 식별자 `cloudiam_sts_token_expiration_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"cloudiam_sts_token_expiration_v1\") 앞 20자리}`",
     "Analyze lifetime constraints (15 minutes to 12 hours) and rotation mechanics of ASIA-prefixed session tokens.\nCompute the first 20 hex characters of SHA256(\"cloudiam_sts_token_expiration_v1\").\n\nFormat: `FLAG{SHA256(\"cloudiam_sts_token_expiration_v1\") first 20 hex}`",
     ["임시 키의 접두사가 ASIA로 시작함을 확인하세요.", "식별자 `cloudiam_sts_token_expiration_v1`의 해시 앞 20자리를 제출하세요."],
     ["Temporary session credentials use the ASIA prefix.", "Extract first 20 hex chars of SHA256(\"cloudiam_sts_token_expiration_v1\")."]),

    (1, "t1_cloudiam_confused_deputy_problem", 80,
     "대리인 혼동(Confused Deputy) 문제",
     "Confused Deputy Problem & sts:ExternalId",
     "서드파티 SaaS 연동 시 다른 고객의 권한을 대리 행사하게 되는 취약점과 sts:ExternalId 방어 검증을 점검합니다.\n지정된 식별자 `cloudiam_confused_deputy_problem_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"cloudiam_confused_deputy_problem_v1\") 앞 20자리}`",
     "Prevent confused deputy exploitation across multi-tenant SaaS vendors by mandating sts:ExternalId conditions.\nCompute the first 20 hex characters of SHA256(\"cloudiam_confused_deputy_problem_v1\").\n\nFormat: `FLAG{SHA256(\"cloudiam_confused_deputy_problem_v1\") first 20 hex}`",
     ["sts:ExternalId 일치 조건을 통해 대리인 혼동을 차단하세요.", "식별자 `cloudiam_confused_deputy_problem_v1`의 해시 앞 20자리를 제출하세요."],
     ["Validate sts:ExternalId in trust policy condition blocks.", "Extract first 20 hex chars of SHA256(\"cloudiam_confused_deputy_problem_v1\")."]),

    # Tier 2 (중급: 7 challenges, points 100~140)
    (2, "t2_cloudiam_ec2_runinstances_passrole", 110,
     "ec2:RunInstances + iam:PassRole 결합 권한 상승",
     "EC2 RunInstances PassRole Escalation",
     "ec2:RunInstances 실행 시 고권한 역할을 인스턴스에 넘겨 UserData 스크립트로 관리자 키를 추출하는 1단계 공격을 분석합니다.\n지정된 식별자 `cloudiam_ec2_runinstances_passrole_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"cloudiam_ec2_runinstances_passrole_v1\") 앞 20자리}`",
     "Combine ec2:RunInstances with iam:PassRole to launch an instance with CloudSecAdminRole and carve admin tokens.\nCompute the first 20 hex characters of SHA256(\"cloudiam_ec2_runinstances_passrole_v1\").\n\nFormat: `FLAG{SHA256(\"cloudiam_ec2_runinstances_passrole_v1\") first 20 hex}`",
     ["Lab 35의 Step 1 PassRole 공격 흐름을 확인하세요.", "식별자 `cloudiam_ec2_runinstances_passrole_v1`의 해시 앞 20자리를 제출하세요."],
     ["Review Step 1 of Lab 35.", "Extract first 20 hex chars of SHA256(\"cloudiam_ec2_runinstances_passrole_v1\")."]),

    (2, "t2_cloudiam_lambda_create_passrole", 115,
     "lambda:CreateFunction을 통한 임의 코드 실행",
     "Lambda CreateFunction PassRole Execution",
     "lambda:CreateFunction 및 iam:PassRole 권한으로 고권한 실행 역할을 주입한 뒤 Invoke하여 플래그를 회수합니다.\n지정된 식별자 `cloudiam_lambda_create_passrole_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"cloudiam_lambda_create_passrole_v1\") 앞 20자리}`",
     "Deploy a serverless function with high-privilege execution roles using lambda:CreateFunction and iam:PassRole.\nCompute the first 20 hex characters of SHA256(\"cloudiam_lambda_create_passrole_v1\").\n\nFormat: `FLAG{SHA256(\"cloudiam_lambda_create_passrole_v1\") first 20 hex}`",
     ["람다 핸들러 환경변수 및 STS 세션을 확인하세요.", "식별자 `cloudiam_lambda_create_passrole_v1`의 해시 앞 20자리를 제출하세요."],
     ["Invoke custom Lambda payloads to exfiltrate execution role credentials.", "Extract first 20 hex chars of SHA256(\"cloudiam_lambda_create_passrole_v1\")."]),

    (2, "t2_cloudiam_create_policy_version", 120,
     "iam:CreatePolicyVersion 기본 버전 변경 상승",
     "IAM CreatePolicyVersion Escalation",
     "iam:CreatePolicyVersion 권한으로 Action:* Resource:* 관리자 정책을 v2로 생성하고 set-as-default를 적용합니다.\n지정된 식별자 `cloudiam_create_policy_version_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"cloudiam_create_policy_version_v1\") 앞 20자리}`",
     "Escalate permissions by publishing a new default policy version containing full administrator privileges.\nCompute the first 20 hex characters of SHA256(\"cloudiam_create_policy_version_v1\").\n\nFormat: `FLAG{SHA256(\"cloudiam_create_policy_version_v1\") first 20 hex}`",
     ["set-as-default 플래그를 통한 즉시 활성화를 점검하세요.", "식별자 `cloudiam_create_policy_version_v1`의 해시 앞 20자리를 제출하세요."],
     ["Pass --set-as-default to instantly activate escalated policy versions.", "Extract first 20 hex chars of SHA256(\"cloudiam_create_policy_version_v1\")."]),

    (2, "t2_cloudiam_attach_user_policy", 125,
     "iam:AttachUserPolicy 관리자 정책 직접 연결",
     "IAM AttachUserPolicy Direct Escalation",
     "iam:AttachUserPolicy 권한을 가진 사용자가 자신의 계정에 AdministratorAccess 관리형 정책을 직접 첨부합니다.\n지정된 식별자 `cloudiam_attach_user_policy_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"cloudiam_attach_user_policy_v1\") 앞 20자리}`",
     "Attach AWS managed AdministratorAccess policy directly to the caller using iam:AttachUserPolicy.\nCompute the first 20 hex characters of SHA256(\"cloudiam_attach_user_policy_v1\").\n\nFormat: `FLAG{SHA256(\"cloudiam_attach_user_policy_v1\") first 20 hex}`",
     ["arn:aws:iam::aws:policy/AdministratorAccess ARN을 확인하세요.", "식별자 `cloudiam_attach_user_policy_v1`의 해시 앞 20자리를 제출하세요."],
     ["Target arn:aws:iam::aws:policy/AdministratorAccess.", "Extract first 20 hex chars of SHA256(\"cloudiam_attach_user_policy_v1\")."]),

    (2, "t2_cloudiam_put_role_policy", 130,
     "iam:PutRolePolicy 역할 인라인 정책 주입",
     "IAM PutRolePolicy Inline Injection",
     "호출자가 맡을 수 있는 대상 역할에 iam:PutRolePolicy로 와일드카드 관리 권한 인라인 정책을 주입합니다.\n지정된 식별자 `cloudiam_put_role_policy_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"cloudiam_put_role_policy_v1\") 앞 20자리}`",
     "Inject arbitrary inline policy documents into an existing role using iam:PutRolePolicy.\nCompute the first 20 hex characters of SHA256(\"cloudiam_put_role_policy_v1\").\n\nFormat: `FLAG{SHA256(\"cloudiam_put_role_policy_v1\") first 20 hex}`",
     ["역할의 인라인 정책 문서에 Action:*을 추가하세요.", "식별자 `cloudiam_put_role_policy_v1`의 해시 앞 20자리를 제출하세요."],
     ["Inject wildcard permissions into target role inline policies.", "Extract first 20 hex chars of SHA256(\"cloudiam_put_role_policy_v1\")."]),

    (2, "t2_cloudiam_update_assume_role_policy", 135,
     "역할 신뢰 관계 변조(UpdateAssumeRolePolicy)",
     "UpdateAssumeRolePolicy Backdoor",
     "iam:UpdateAssumeRolePolicy를 실행하여 고권한 역할의 신뢰 정책에 공격자의 IAM 사용자 ARN을 주입합니다.\n지정된 식별자 `cloudiam_update_assume_role_policy_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"cloudiam_update_assume_role_policy_v1\") 앞 20자리}`",
     "Backdoor a high-privilege role by rewriting its trust policy to include attacker identity ARN via UpdateAssumeRolePolicy.\nCompute the first 20 hex characters of SHA256(\"cloudiam_update_assume_role_policy_v1\").\n\nFormat: `FLAG{SHA256(\"cloudiam_update_assume_role_policy_v1\") first 20 hex}`",
     ["신뢰 관계에 Principal AWS: caller_arn을 추가하세요.", "식별자 `cloudiam_update_assume_role_policy_v1`의 해시 앞 20자리를 제출하세요."],
     ["Add caller ARN to role trust relationship.", "Extract first 20 hex chars of SHA256(\"cloudiam_update_assume_role_policy_v1\")."]),

    (2, "t2_cloudiam_glue_dev_endpoint", 140,
     "glue:CreateDevEndpoint SSH 키 주입 상승",
     "AWS Glue DevEndpoint PassRole Escalation",
     "glue:CreateDevEndpoint API와 iam:PassRole을 결합하여 고권한 Glue 서비스 인스턴스에 SSH 공용키를 주입합니다.\n지정된 식별자 `cloudiam_glue_dev_endpoint_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"cloudiam_glue_dev_endpoint_v1\") 앞 20자리}`",
     "Exploit glue:CreateDevEndpoint to pass an administrative service role and attach an attacker SSH public key.\nCompute the first 20 hex characters of SHA256(\"cloudiam_glue_dev_endpoint_v1\").\n\nFormat: `FLAG{SHA256(\"cloudiam_glue_dev_endpoint_v1\") first 20 hex}`",
     ["PublicKey 파라미터를 통한 원격 접속 획득을 점검하세요.", "식별자 `cloudiam_glue_dev_endpoint_v1`의 해시 앞 20자리를 제출하세요."],
     ["Inspect SSH PublicKey parameter injection in Glue DevEndpoints.", "Extract first 20 hex chars of SHA256(\"cloudiam_glue_dev_endpoint_v1\")."]),

    # Tier 3 (고급: 7 challenges, points 160~220)
    (3, "t3_cloudiam_cross_account_wildcard_assume", 175,
     "와일드카드 Principal(*) 크로스 어카운트 장악",
     "Cross-Account Wildcard AssumeRole Takeover",
     "신뢰 정책 내 Principal: {'AWS': '*'} 설정 오류를 악용하여 외부 계정에서 감사 역할을 인수(AssumeRole)합니다.\n지정된 식별자 `cloudiam_cross_account_wildcard_assume_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"cloudiam_cross_account_wildcard_assume_v1\") 앞 20자리}`",
     "Abuse open wildcard Principals in cross-account trust policies to assume CrossAccountAuditRole from outside.\nCompute the first 20 hex characters of SHA256(\"cloudiam_cross_account_wildcard_assume_v1\").\n\nFormat: `FLAG{SHA256(\"cloudiam_cross_account_wildcard_assume_v1\") first 20 hex}`",
     ["Lab 35의 Step 2 AssumeRole 공격 흐름을 확인하세요.", "식별자 `cloudiam_cross_account_wildcard_assume_v1`의 해시 앞 20자리를 제출하세요."],
     ["Review Step 2 of Lab 35.", "Extract first 20 hex chars of SHA256(\"cloudiam_cross_account_wildcard_assume_v1\")."]),

    (3, "t3_cloudiam_cloudtrail_stop_logging", 185,
     "cloudtrail:StopLogging 침해 흔적 은폐",
     "CloudTrail StopLogging Defense Evasion",
     "관리자 권한을 획득한 공격자가 감사 로깅을 중지(cloudtrail:StopLogging)하여 사후 포렌식을 방해하는 행위를 분석합니다.\n지정된 식별자 `cloudiam_cloudtrail_stop_logging_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"cloudiam_cloudtrail_stop_logging_v1\") 앞 20자리}`",
     "Analyze defense evasion tactics stopping CloudTrail logging streams via StopLogging and DeleteTrail APIs.\nCompute the first 20 hex characters of SHA256(\"cloudiam_cloudtrail_stop_logging_v1\").\n\nFormat: `FLAG{SHA256(\"cloudiam_cloudtrail_stop_logging_v1\") first 20 hex}`",
     ["SCP를 통해 CloudTrail 설정 수정을 금지해야 함을 확인하세요.", "식별자 `cloudiam_cloudtrail_stop_logging_v1`의 해시 앞 20자리를 제출하세요."],
     ["Use SCPs to disallow StopLogging across all accounts.", "Extract first 20 hex chars of SHA256(\"cloudiam_cloudtrail_stop_logging_v1\")."]),

    (3, "t3_cloudiam_kms_decrypt_secrets", 195,
     "kms:Decrypt 권한을 악용한 SSM 시크릿 탈취",
     "SSM Parameter Decryption via KMS",
     "SSM Parameter Store에 SecureString으로 암호화된 데이터베이스 자격증명을 kms:Decrypt 권한으로 복호화합니다.\n지정된 식별자 `cloudiam_kms_decrypt_secrets_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"cloudiam_kms_decrypt_secrets_v1\") 앞 20자리}`",
     "Extract and decrypt sensitive database passwords stored in AWS SSM Parameter Store using kms:Decrypt.\nCompute the first 20 hex characters of SHA256(\"cloudiam_kms_decrypt_secrets_v1\").\n\nFormat: `FLAG{SHA256(\"cloudiam_kms_decrypt_secrets_v1\") first 20 hex}`",
     ["WithDecryption=true 파라미터 요청 구조를 확인하세요.", "식별자 `cloudiam_kms_decrypt_secrets_v1`의 해시 앞 20자리를 제출하세요."],
     ["Execute GetParameter with WithDecryption=true.", "Extract first 20 hex chars of SHA256(\"cloudiam_kms_decrypt_secrets_v1\")."]),

    (3, "t3_cloudiam_session_policy_restriction", 200,
     "STS AssumeRole 세션 정책 다운그레이드",
     "STS Session Policy Downscoping",
     "AssumeRole 호출 시 인라인 세션 정책을 전달하여 역할이 가진 기존 권한을 최소 권한 세션으로 축소 격리합니다.\n지정된 식별자 `cloudiam_session_policy_restriction_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"cloudiam_session_policy_restriction_v1\") 앞 20자리}`",
     "Pass session policies during sts:AssumeRole calls to intersect and downscope maximum permissions.\nCompute the first 20 hex characters of SHA256(\"cloudiam_session_policy_restriction_v1\").\n\nFormat: `FLAG{SHA256(\"cloudiam_session_policy_restriction_v1\") first 20 hex}`",
     ["역할 정책과 세션 정책의 교집합(Intersection) 원리를 점검하세요.", "식별자 `cloudiam_session_policy_restriction_v1`의 해시 앞 20자리를 제출하세요."],
     ["Effective permissions evaluate as the intersection of role and session policies.", "Extract first 20 hex chars of SHA256(\"cloudiam_session_policy_restriction_v1\")."]),

    (3, "t3_cloudiam_permission_boundary_bypass", 205,
     "권한 경계 미부착 신규 사용자 생성 우회",
     "IAM Permission Boundary Circumvention",
     "iam:CreateUser에 permissions-boundary 강제 조건문이 결여되었을 때 경계 없는 관리자 계정을 생성하는 기법을 분석합니다.\n지정된 식별자 `cloudiam_permission_boundary_bypass_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"cloudiam_permission_boundary_bypass_v1\") 앞 20자리}`",
     "Circumvent permission boundaries if CreateUser lacks the iam:PermissionsBoundary condition key.\nCompute the first 20 hex characters of SHA256(\"cloudiam_permission_boundary_bypass_v1\").\n\nFormat: `FLAG{SHA256(\"cloudiam_permission_boundary_bypass_v1\") first 20 hex}`",
     ["iam:PermissionsBoundary 조건문 누락 여부를 확인하세요.", "식별자 `cloudiam_permission_boundary_bypass_v1`의 해시 앞 20자리를 제출하세요."],
     ["Check for missing PermissionsBoundary policy condition checks.", "Extract first 20 hex chars of SHA256(\"cloudiam_permission_boundary_bypass_v1\")."]),

    (3, "t3_cloudiam_cloudformation_create_stack", 215,
     "CloudFormation CAPABILITY_IAM 스택 배포",
     "CloudFormation PassRole Stack Escalation",
     "cloudformation:CreateStack 실행 시 CAPABILITY_IAM을 선언하여 스택 템플릿 내에 관리자 IAM 역할을 생성합니다.\n지정된 식별자 `cloudiam_cloudformation_create_stack_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"cloudiam_cloudformation_create_stack_v1\") 앞 20자리}`",
     "Escalate permissions by orchestrating new administrator roles through CloudFormation CAPABILITY_IAM stacks.\nCompute the first 20 hex characters of SHA256(\"cloudiam_cloudformation_create_stack_v1\").\n\nFormat: `FLAG{SHA256(\"cloudiam_cloudformation_create_stack_v1\") first 20 hex}`",
     ["템플릿 내 AWS::IAM::Role 리소스 정의를 점검하세요.", "식별자 `cloudiam_cloudformation_create_stack_v1`의 해시 앞 20자리를 제출하세요."],
     ["Inspect AWS::IAM::Role declarations in CloudFormation templates.", "Extract first 20 hex chars of SHA256(\"cloudiam_cloudformation_create_stack_v1\")."]),

    (3, "t3_cloudiam_codebuild_start_build", 220,
     "CodeBuild 빌드 환경변수 자격증명 추출",
     "CodeBuild Environment Variable Key Carving",
     "codebuild:StartBuild 권한으로 빌드 스펙(buildspec) 오버라이드를 전달하여 빌드 러너의 IAM 자격증명을 C2로 유출합니다.\n지정된 식별자 `cloudiam_codebuild_start_build_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"cloudiam_codebuild_start_build_v1\") 앞 20자리}`",
     "Override CodeBuild buildspec commands to exfiltrate build-runner IAM role credentials to external listeners.\nCompute the first 20 hex characters of SHA256(\"cloudiam_codebuild_start_build_v1\").\n\nFormat: `FLAG{SHA256(\"cloudiam_codebuild_start_build_v1\") first 20 hex}`",
     ["buildspecOverride 파라미터 주입을 확인하세요.", "식별자 `cloudiam_codebuild_start_build_v1`의 해시 앞 20자리를 제출하세요."],
     ["Review buildspecOverride parameter execution.", "Extract first 20 hex chars of SHA256(\"cloudiam_codebuild_start_build_v1\")."]),

    # Tier 4 (마스터: 7 challenges, points 260~380)
    (4, "t4_cloudiam_capstone_full_pwn", 300,
     "PassRole 및 AssumeRole 종합 권한 상승 캡스톤",
     "Full IAM Escalation & Lateral Movement Capstone",
     "저권한 사용자 침투, EC2 PassRole 권한 상승, 크로스 어카운트 AssumeRole 횡적이동 및 거버넌스 하드닝을 완성합니다.\n지정된 식별자 `cloudiam_capstone_full_pwn_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"cloudiam_capstone_full_pwn_v1\") 앞 20자리}`",
     "Synthesize end-to-end cloud IAM privilege escalation, cross-account lateral movement, and SCP governance.\nCompute the first 20 hex characters of SHA256(\"cloudiam_capstone_full_pwn_v1\").\n\nFormat: `FLAG{SHA256(\"cloudiam_capstone_full_pwn_v1\") first 20 hex}`",
     ["Lab 35의 3단계 전체 공격 및 하드닝 과정을 완료하세요.", "식별자 `cloudiam_capstone_full_pwn_v1`의 해시 앞 20자리를 제출하세요."],
     ["Complete all 3 stages of Lab 35.", "Extract first 20 hex chars of SHA256(\"cloudiam_capstone_full_pwn_v1\")."]),

    (4, "t4_cloudiam_org_scp_deny_guardrails", 320,
     "AWS Organizations SCP 중앙 Deny 가드레일",
     "Organization SCP Multi-Account Governance",
     "조직 최상위 루트 또는 OU 수준에서 민감 IAM 수정 및 비인가 PassRole을 원천 차단하는 SCP 거버넌스 아키텍처를 설계합니다.\n지정된 식별자 `cloudiam_org_scp_deny_guardrails_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"cloudiam_org_scp_deny_guardrails_v1\") 앞 20자리}`",
     "Architect AWS Organizations Service Control Policies (SCPs) establishing explicit DENY perimeters across all member accounts.\nCompute the first 20 hex characters of SHA256(\"cloudiam_org_scp_deny_guardrails_v1\").\n\nFormat: `FLAG{SHA256(\"cloudiam_org_scp_deny_guardrails_v1\") first 20 hex}`",
     ["SCP의 계정 관리자 통제 무력화 방지 기능을 확인하세요.", "식별자 `cloudiam_org_scp_deny_guardrails_v1`의 해시 앞 20자리를 제출하세요."],
     ["SCPs constrain even account root users.", "Extract first 20 hex chars of SHA256(\"cloudiam_org_scp_deny_guardrails_v1\")."]),

    (4, "t4_cloudiam_permission_boundary_enforcement", 330,
     "모든 IAM 주체 권한 경계(Boundary) 강제",
     "Enforcing Organization Permission Boundaries",
     "개발자가 역할을 생성할 때 승인된 권한 경계 정책을 반드시 첨부하도록 강제하여 권한 확장을 원천 봉쇄합니다.\n지정된 식별자 `cloudiam_permission_boundary_enforcement_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"cloudiam_permission_boundary_enforcement_v1\") 앞 20자리}`",
     "Mandate IAM Permission Boundaries on all role creations to ensure delegated developers cannot elevate beyond scope.\nCompute the first 20 hex characters of SHA256(\"cloudiam_permission_boundary_enforcement_v1\").\n\nFormat: `FLAG{SHA256(\"cloudiam_permission_boundary_enforcement_v1\") first 20 hex}`",
     ["iam:PermissionsBoundary 조건 키 필수 적용을 검토하세요.", "식별자 `cloudiam_permission_boundary_enforcement_v1`의 해시 앞 20자리를 제출하세요."],
     ["Enforce iam:PermissionsBoundary conditions on IAM delegation.", "Extract first 20 hex chars of SHA256(\"cloudiam_permission_boundary_enforcement_v1\")."]),

    (4, "t4_cloudiam_abac_tag_based_passrole", 340,
     "태그 기반 속성 접근 제어(ABAC) PassRole 제약",
     "ABAC Tag-Scoped PassRole Security",
     "iam:PassedToService 태그 및 aws:ResourceTag 조건을 결합하여 승인된 애플리케이션 역할만 전달하도록 제한합니다.\n지정된 식별자 `cloudiam_abac_tag_based_passrole_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"cloudiam_abac_tag_based_passrole_v1\") 앞 20자리}`",
     "Constrain iam:PassRole using Attribute-Based Access Control (ABAC) matching aws:ResourceTag project metadata.\nCompute the first 20 hex characters of SHA256(\"cloudiam_abac_tag_based_passrole_v1\").\n\nFormat: `FLAG{SHA256(\"cloudiam_abac_tag_based_passrole_v1\") first 20 hex}`",
     ["태그 불일치 시 PassRole 거부 조건을 분석하세요.", "식별자 `cloudiam_abac_tag_based_passrole_v1`의 해시 앞 20자리를 제출하세요."],
     ["Validate ABAC tags preventing unauthorized cross-project role passing.", "Extract first 20 hex chars of SHA256(\"cloudiam_abac_tag_based_passrole_v1\")."]),

    (4, "t4_cloudiam_guardduty_iam_threat_detection", 350,
     "GuardDuty 실시간 IAM 이상 탐지 자동화",
     "Automated GuardDuty IAM Threat Response",
     "PrivilegeEscalation:IAMUser/AnomalousPolicyModification 발견 시 해당 키를 즉각 비활성화하는 자동화 람다를 배포합니다.\n지정된 식별자 `cloudiam_guardduty_iam_threat_detection_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"cloudiam_guardduty_iam_threat_detection_v1\") 앞 20자리}`",
     "Deploy automated event-driven incident response revoking exposed credentials upon GuardDuty IAM finding generation.\nCompute the first 20 hex characters of SHA256(\"cloudiam_guardduty_iam_threat_detection_v1\").\n\nFormat: `FLAG{SHA256(\"cloudiam_guardduty_iam_threat_detection_v1\") first 20 hex}`",
     ["EventBridge와 결합된 UpdateAccessKey(Inactive) 자동화 로직을 확인하세요.", "식별자 `cloudiam_guardduty_iam_threat_detection_v1`의 해시 앞 20자리를 제출하세요."],
     ["Automate AccessKey deactivation via EventBridge rules.", "Extract first 20 hex chars of SHA256(\"cloudiam_guardduty_iam_threat_detection_v1\")."]),

    (4, "t4_cloudiam_iam_access_analyzer_audit", 360,
     "IAM Access Analyzer 기반 미사용 권한 회수",
     "Automated IAM Access Analyzer Least Privilege",
     "CloudTrail 실행 이력을 바탕으로 실제로 사용된 서비스 액션만 남기고 불필요한 과다 권한을 자동 회수하는 체계를 구축합니다.\n지정된 식별자 `cloudiam_iam_access_analyzer_audit_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"cloudiam_iam_access_analyzer_audit_v1\") 앞 20자리}`",
     "Generate least-privilege fine-grained IAM policies from observed CloudTrail telemetry via IAM Access Analyzer.\nCompute the first 20 hex characters of SHA256(\"cloudiam_iam_access_analyzer_audit_v1\").\n\nFormat: `FLAG{SHA256(\"cloudiam_iam_access_analyzer_audit_v1\") first 20 hex}`",
     ["Access Analyzer 정책 생성 기능을 점검하세요.", "식별자 `cloudiam_iam_access_analyzer_audit_v1`의 해시 앞 20자리를 제출하세요."],
     ["Generate least-privilege policies from CloudTrail logs.", "Extract first 20 hex chars of SHA256(\"cloudiam_iam_access_analyzer_audit_v1\")."]),

    (4, "t4_cloudiam_zero_trust_temporary_credentials", 380,
     "정적 장기 자격증명 완전 폐기 아키텍처",
     "Zero Standing Privileges IAM Architecture",
     "정적 IAM 사용자 액세스 키를 전면 퇴출하고 IAM Identity Center(SSO) 및 단기 임시 자격증명(STS)만을 허용하는 제로스탠딩 권한 체계를 설계합니다.\n지정된 식별자 `cloudiam_zero_trust_temporary_credentials_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"cloudiam_zero_trust_temporary_credentials_v1\") 앞 20자리}`",
     "Eliminate static long-term IAM access keys across the enterprise in favor of Zero Standing Privileges (ZSP) and temporary STS sessions.\nCompute the first 20 hex characters of SHA256(\"cloudiam_zero_trust_temporary_credentials_v1\").\n\nFormat: `FLAG{SHA256(\"cloudiam_zero_trust_temporary_credentials_v1\") first 20 hex}`",
     ["정적 액세스 키 비활성화 및 IAM Identity Center 도입을 검토하세요.", "식별자 `cloudiam_zero_trust_temporary_credentials_v1`의 해시 앞 20자리를 제출하세요."],
     ["Transition to AWS IAM Identity Center and short-lived STS credentials.", "Extract first 20 hex chars of SHA256(\"cloudiam_zero_trust_temporary_credentials_v1\")."]),
]

def build_challenges():
    challenges = []
    ids = []
    for tier, cid, pts, title_ko, title_en, prompt_ko, prompt_en, hints_ko, hints_en in RAW_CHALLENGES:
        ident = f"{cid.replace('t0_', '').replace('t1_', '').replace('t2_', '').replace('t3_', '').replace('t4_', '')}_v1"
        flag = f"FLAG{{{hashlib.sha256(ident.encode('utf-8')).hexdigest()[:20]}}}"
        h = hashlib.sha256(flag.encode('utf-8')).hexdigest()
        ch = {
            "id": cid,
            "tier": tier,
            "cat": "cloudiam",
            "track": "cloudiam",
            "points": pts,
            "ci": False,
            "fmt": "FLAG{...}",
            "title": {"ko": title_ko, "en": title_en},
            "prompt": {"ko": prompt_ko, "en": prompt_en},
            "hints": {"ko": hints_ko, "en": hints_en},
            "hash": h
        }
        challenges.append(ch)
        ids.append(cid)
    return challenges, ids

def main():
    print("[*] Generating 35 Cloud IAM track challenges...")
    challenges, ids = build_challenges()
    print(f"  ✓ Built {len(challenges)} challenges.")

    # 1. Update challenges.js
    with open(CHALLENGES_JS, "r", encoding="utf-8") as f:
        content = f.read()

    pos_tracks_end = content.find("const CHALLENGES =")
    if pos_tracks_end == -1:
        raise ValueError("Could not find `const CHALLENGES =` in challenges.js")
    bracket_pos = content.rfind("];", 0, pos_tracks_end)
    if bracket_pos == -1:
        raise ValueError("Could not find closing bracket for TRACKS")

    # Check if cloudiam track is already present
    if '"id": "cloudiam"' not in content[:pos_tracks_end]:
        prev_chunk = content[:bracket_pos].rstrip()
        if not prev_chunk.endswith(","):
            prev_chunk += ","
        content = prev_chunk + "\n  " + json.dumps(TRACK_INFO, ensure_ascii=False, indent=2).replace("\n", "\n  ") + "\n" + content[bracket_pos:]
        print("  ✓ Inserted 'cloudiam' into TRACKS.")

    # Add challenges before final ];
    final_bracket = content.rfind("];")
    if final_bracket == -1:
        raise ValueError("Could not find final `];` in challenges.js")

    if '"id": "t0_cloudiam_eval_logic_order"' not in content:
        rendered_chals = []
        for c in challenges:
            rendered = json.dumps(c, ensure_ascii=False, indent=2)
            rendered_chals.append(rendered)

        chals_str = ",\n" + ",\n".join(rendered_chals) + "\n"
        content = content[:final_bracket] + chals_str + content[final_bracket:]
        print("  ✓ Appended 35 challenges to CHALLENGES.")

    with open(CHALLENGES_JS, "w", encoding="utf-8") as f:
        f.write(content)

    # 2. Update solve-derivable.js
    with open(SOLVE_DERIVABLE_JS, "r", encoding="utf-8") as f:
        sd_content = f.read()

    marker = '"t4_osint_threat_actor_infrastructure_tracking"'
    if marker in sd_content and f'"{ids[0]}"' not in sd_content:
        pos = sd_content.find(marker)
        insert_ids_str = ',\n' + ',\n'.join(f'  "{cid}"' for cid in ids)
        sd_content = sd_content[:pos + len(marker)] + insert_ids_str + sd_content[pos + len(marker):]
        with open(SOLVE_DERIVABLE_JS, "w", encoding="utf-8") as f:
            f.write(sd_content)
        print("  ✓ Updated solve-derivable.js with 35 Cloud IAM IDs.")

    print("[+] Cloud IAM track generation completed!")

if __name__ == "__main__":
    main()
