> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 클라우드 사고 대응(IR) 기초

## 1. 온프레미스 vs 클라우드 IR 비교

클라우드 환경에서의 사고 대응은 전통적인 온프레미스 환경과 근본적으로 다른 접근 방식을 요구한다. 물리적 장비에 직접 접근할 수 없고, 인프라 제어권이 클라우드 사업자와 분리되며, 증거가 API 호출과 로그 스트림 형태로 존재한다는 점이 핵심 차이다.

| 구분 | 온프레미스 IR | 클라우드 IR |
|------|-------------|------------|
| 물리적 접근 | 직접 서버실 접근 가능 | 물리적 접근 불가, API/콘솔 경유 |
| 증거 수집 | 디스크 이미징, 메모리 덤프 직접 수행 | 스냅샷, 로그 API 활용 |
| 증거 보존 기간 | 시스템 보존 시 영구 | 기본 설정에 따라 자동 삭제(90일~1년) |
| 네트워크 포렌식 | 전체 패킷 캡처 가능 | VPC 플로우 로그(메타데이터만) |
| 휘발성 데이터 | RAM 직접 덤프 | 인스턴스 종료 시 즉시 소실 |
| 타임라인 구성 | 파일시스템 타임스탬프 | API 호출 이벤트 타임스탬프 |
| 관할권 | 단일 물리 위치 | 멀티 리전, 다국적 법적 관할 복잡 |
| 비용 | 하드웨어 비용 고정 | 로그 저장/조회 비용 발생 |
| 확장성 | 수동 확장 | 오토스케일링으로 인한 증거 소실 위험 |
| 인증/접근 | 로컬 계정, AD | IAM, 페더레이션, 임시 자격증명 |

---

## 2. 공유 책임 모델과 IR 범위

클라우드 서비스 모델별로 사업자와 고객의 IR 책임이 달라진다. 사고 발생 시 어느 레이어에서 침해가 발생했는지 신속히 파악해야 조사 범위와 증거 수집 방향이 결정된다.

### 2.1 서비스 모델별 책임 분리

| 레이어 | IaaS(EC2/VM) | PaaS(RDS/AppSvc) | SaaS(Office365/Workspace) |
|--------|-------------|-----------------|--------------------------|
| 물리 인프라 | CSP | CSP | CSP |
| 하이퍼바이저 | CSP | CSP | CSP |
| 운영체제 | 고객 | CSP | CSP |
| 런타임/미들웨어 | 고객 | CSP | CSP |
| 애플리케이션 | 고객 | 고객 | CSP |
| 데이터 | 고객 | 고객 | 고객 |
| 신원/접근 관리 | 고객 | 고객 | 고객 |
| 네트워크 설정 | 고객 | 일부 고객 | CSP |

### 2.2 IR 범위 결정 원칙

- **CSP 관할 레이어 침해**: 클라우드 사업자에 사고 신고 및 지원 요청, 사업자 포렌식 팀 협업
- **고객 관할 레이어 침해**: 자체 IR 팀 또는 외부 DFIR 업체 투입
- **IAM 침해**: 두 레이어 공통, 자격증명 즉시 비활성화 후 CloudTrail/Activity Log 분석
- **데이터 유출**: 고객 책임이나 CSP 지원 도구(Macie, DLP) 활용 가능

---

## 3. 클라우드 증거 수집의 특수성

### 3.1 휘발성 데이터 우선 수집 원칙

클라우드에서도 휘발성 높은 데이터부터 수집하는 원칙은 동일하지만, 대상 목록이 다르다.

| 우선순위 | 온프레미스 | 클라우드 |
|---------|-----------|---------|
| 1순위 | RAM 내용 | 실행 중인 프로세스 정보(SSM 세션) |
| 2순위 | 네트워크 연결 상태 | VPC 플로우 로그(실시간) |
| 3순위 | 파일시스템 타임스탬프 | CloudTrail/Activity Log 현재 세션 |
| 4순위 | 로그 파일 | 임시 자격증명 세션 토큰 목록 |
| 5순위 | 디스크 이미지 | EBS/디스크 스냅샷 |

### 3.2 로그 보존 기간 주의사항

| 서비스 | 기본 보존 기간 | 최대 보존 | 비고 |
|--------|--------------|---------|------|
| AWS CloudTrail | 90일(Event History) | S3 보관 시 무제한 | Trail 미설정 시 90일 후 삭제 |
| AWS VPC Flow Log | 없음(자동 삭제) | CloudWatch/S3 설정 필요 | 기본값: 보존 없음 |
| AWS GuardDuty | 90일 | - | 내보내기 설정 권장 |
| Azure Activity Log | 90일 | Log Analytics 연동 시 2년 | Diagnostic Settings 필수 |
| Azure AD Sign-in | 30일(P1/P2) | Storage 연동 | Free tier 7일 |
| GCP Cloud Audit | 400일(Admin) | Cloud Storage 연동 | Data Access 기본 비활성 |
| GCP VPC Flow | 없음 | BigQuery/Storage | 명시적 활성화 필요 |

### 3.3 증거 무결성 보장 방법

```
1. 로그 수집 시 타임스탬프 기록 (UTC 기준)
2. 수집된 로그 파일 SHA-256 해시값 산출
3. 변경 불가 저장소(S3 Object Lock, Azure Immutable Storage) 이관
4. 보관 로그의 접근 이력 별도 기록
5. 법적 효력을 위한 Chain of Custody 문서 작성
```

---

## 4. 클라우드 공격 킬체인 단계

| 단계 | 설명 | 클라우드 특화 기법 | 탐지 지표 |
|------|------|----------------|---------|
| 정찰 (Reconnaissance) | 공개 정보 수집 | S3 버킷 열거, 퍼블릭 AMI 조회 | 비인증 API 호출 급증 |
| 초기 접근 (Initial Access) | 첫 진입점 확보 | 자격증명 탈취, 퍼블릭 인스턴스 취약점 | 비정상 지역 로그인 |
| 실행 (Execution) | 악성코드/명령 실행 | Lambda 함수 악용, SSM 명령 실행 | 비정상 Lambda 호출 패턴 |
| 지속성 (Persistence) | 재접근 기반 마련 | 백도어 IAM 사용자 생성, 액세스키 발급 | CreateUser, CreateAccessKey 이벤트 |
| 권한 에스컬레이션 | 상위 권한 획득 | IAM 정책 연결, 역할 가정 | AttachUserPolicy, AssumeRole 이벤트 |
| 방어 우회 | 탐지 회피 | CloudTrail 비활성화, GuardDuty 삭제 | StopLogging, DeleteDetector 이벤트 |
| 자격증명 접근 | 추가 자격증명 탈취 | Secrets Manager 조회, 환경변수 접근 | GetSecretValue 대량 호출 |
| 횡이동 (Lateral Movement) | 내부 이동 | 역할 전환, 교차 계정 접근 | AssumeRole 체인 |
| 수집 (Collection) | 데이터 수집 | S3 버킷 목록화, RDS 스냅샷 생성 | ListBuckets, CreateDBSnapshot |
| 유출 (Exfiltration) | 데이터 외부 전송 | S3 복사, 퍼블릭 스냅샷 공유 | S3 GetObject 대량, ModifySnapshotAttribute |
| 영향 (Impact) | 파괴/랜섬 | 인스턴스 삭제, 암호화 | TerminateInstances, KMS 키 삭제 |

---

## 5. Python CLI: 클라우드 IR 체크리스트 생성기

```python
#!/usr/bin/env python3
"""
클라우드 IR 체크리스트 생성기
- 클라우드 제공자와 사고 유형에 따른 맞춤형 체크리스트를 생성한다.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


# ── 데이터 구조 정의 ──────────────────────────────────────────────────────────

@dataclass
class ChecklistItem:
    """체크리스트 단일 항목"""
    id: str
    phase: str
    action: str
    priority: str          # HIGH / MEDIUM / LOW
    tools: list[str]
    notes: str
    completed: bool = False

    def to_markdown_row(self) -> str:
        checkbox = "- [x]" if self.completed else "- [ ]"
        priority_badge = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}.get(self.priority, "⚪")
        tools_str = ", ".join(f"`{t}`" for t in self.tools) if self.tools else "-"
        return (
            f"{checkbox} **[{self.id}]** {priority_badge} {self.action}\n"
            f"  - 도구: {tools_str}\n"
            f"  - 메모: {self.notes}\n"
        )


@dataclass
class ChecklistTemplate:
    """체크리스트 템플릿 전체 구조"""
    provider: str
    incident_type: str
    version: str
    phases: list[str]
    items: list[ChecklistItem] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict) -> "ChecklistTemplate":
        items = [
            ChecklistItem(**item)
            for item in data.get("items", [])
        ]
        return cls(
            provider=data["provider"],
            incident_type=data["incident_type"],
            version=data.get("version", "1.0"),
            phases=data.get("phases", []),
            items=items,
        )


# ── 기본 내장 템플릿 ──────────────────────────────────────────────────────────

BUILTIN_TEMPLATES: dict[str, dict] = {
    "aws:credential_compromise": {
        "provider": "AWS",
        "incident_type": "credential_compromise",
        "version": "1.0",
        "phases": ["식별", "봉쇄", "박멸", "복구", "사후조치"],
        "items": [
            {
                "id": "AWS-CC-001",
                "phase": "식별",
                "action": "영향받은 IAM 사용자/역할 식별",
                "priority": "HIGH",
                "tools": ["aws iam list-users", "CloudTrail"],
                "notes": "비정상 로그인 IP, 시간대 확인",
                "completed": False,
            },
            {
                "id": "AWS-CC-002",
                "phase": "식별",
                "action": "CloudTrail에서 해당 자격증명 활동 조회",
                "priority": "HIGH",
                "tools": ["aws cloudtrail lookup-events", "Athena"],
                "notes": "최근 7일 이벤트 우선 확인",
                "completed": False,
            },
            {
                "id": "AWS-CC-003",
                "phase": "식별",
                "action": "비정상 리소스 생성 여부 확인",
                "priority": "HIGH",
                "tools": ["aws ec2 describe-instances", "aws s3 ls"],
                "notes": "알 수 없는 리전 포함 전체 리전 확인",
                "completed": False,
            },
            {
                "id": "AWS-CC-004",
                "phase": "봉쇄",
                "action": "침해된 액세스키 즉시 비활성화",
                "priority": "HIGH",
                "tools": ["aws iam update-access-key --status Inactive"],
                "notes": "삭제 전 비활성화로 추가 증거 보존",
                "completed": False,
            },
            {
                "id": "AWS-CC-005",
                "phase": "봉쇄",
                "action": "영향받은 IAM 엔티티에 Deny All 정책 연결",
                "priority": "HIGH",
                "tools": ["aws iam put-user-policy"],
                "notes": "인라인 정책으로 즉시 적용",
                "completed": False,
            },
            {
                "id": "AWS-CC-006",
                "phase": "봉쇄",
                "action": "공격자 생성 IAM 리소스 목록화",
                "priority": "HIGH",
                "tools": ["aws iam list-users", "aws iam list-roles"],
                "notes": "생성 시각 기준 사고 발생 이후 항목 집중",
                "completed": False,
            },
            {
                "id": "AWS-CC-007",
                "phase": "박멸",
                "action": "공격자 생성 IAM 사용자/역할/정책 삭제",
                "priority": "HIGH",
                "tools": ["aws iam delete-user", "aws iam delete-role"],
                "notes": "연결된 정책 먼저 분리 후 삭제",
                "completed": False,
            },
            {
                "id": "AWS-CC-008",
                "phase": "박멸",
                "action": "공격자 생성 리소스 종료 및 삭제",
                "priority": "HIGH",
                "tools": ["aws ec2 terminate-instances"],
                "notes": "스냅샷 생성 후 종료 권장",
                "completed": False,
            },
            {
                "id": "AWS-CC-009",
                "phase": "복구",
                "action": "신규 액세스키 발급 및 안전한 배포",
                "priority": "MEDIUM",
                "tools": ["aws iam create-access-key"],
                "notes": "Secrets Manager 연동 권장",
                "completed": False,
            },
            {
                "id": "AWS-CC-010",
                "phase": "사후조치",
                "action": "CloudTrail 다중 리전 Trail 설정 확인",
                "priority": "MEDIUM",
                "tools": ["aws cloudtrail describe-trails"],
                "notes": "S3 로그 파일 검증 활성화",
                "completed": False,
            },
            {
                "id": "AWS-CC-011",
                "phase": "사후조치",
                "action": "GuardDuty 활성화 및 알림 설정",
                "priority": "MEDIUM",
                "tools": ["aws guardduty create-detector"],
                "notes": "모든 리전에 활성화 권장",
                "completed": False,
            },
            {
                "id": "AWS-CC-012",
                "phase": "사후조치",
                "action": "MFA 미적용 IAM 사용자 전수 검토",
                "priority": "HIGH",
                "tools": ["aws iam generate-credential-report"],
                "notes": "콘솔 접근 계정은 MFA 필수",
                "completed": False,
            },
        ],
    },
    "aws:data_exfiltration": {
        "provider": "AWS",
        "incident_type": "data_exfiltration",
        "version": "1.0",
        "phases": ["식별", "봉쇄", "박멸", "복구", "사후조치"],
        "items": [
            {
                "id": "AWS-DE-001",
                "phase": "식별",
                "action": "S3 버킷 퍼블릭 접근 설정 전수 확인",
                "priority": "HIGH",
                "tools": ["aws s3api get-bucket-acl", "Access Analyzer"],
                "notes": "퍼블릭 버킷 즉시 격리",
                "completed": False,
            },
            {
                "id": "AWS-DE-002",
                "phase": "식별",
                "action": "S3 서버 접근 로그에서 대량 다운로드 이벤트 탐지",
                "priority": "HIGH",
                "tools": ["Athena", "CloudTrail S3 Data Events"],
                "notes": "GetObject 이벤트 집계 분석",
                "completed": False,
            },
            {
                "id": "AWS-DE-003",
                "phase": "봉쇄",
                "action": "영향받은 S3 버킷 퍼블릭 접근 차단",
                "priority": "HIGH",
                "tools": ["aws s3api put-public-access-block"],
                "notes": "계정 레벨 퍼블릭 차단도 병행",
                "completed": False,
            },
            {
                "id": "AWS-DE-004",
                "phase": "식별",
                "action": "Macie로 민감 데이터 포함 버킷 식별",
                "priority": "HIGH",
                "tools": ["Amazon Macie"],
                "notes": "PII, 자격증명 패턴 감지",
                "completed": False,
            },
        ],
    },
    "azure:credential_compromise": {
        "provider": "Azure",
        "incident_type": "credential_compromise",
        "version": "1.0",
        "phases": ["식별", "봉쇄", "박멸", "복구", "사후조치"],
        "items": [
            {
                "id": "AZ-CC-001",
                "phase": "식별",
                "action": "Azure AD 로그인 로그에서 Impossible Travel 탐지",
                "priority": "HIGH",
                "tools": ["Azure AD Sign-in Logs", "Microsoft Sentinel"],
                "notes": "단시간 내 지리적 불가능 로그인",
                "completed": False,
            },
            {
                "id": "AZ-CC-002",
                "phase": "식별",
                "action": "조건부 액세스 정책 우회 시도 확인",
                "priority": "HIGH",
                "tools": ["Azure AD Conditional Access", "Sign-in Logs"],
                "notes": "레거시 프로토콜 사용 여부 확인",
                "completed": False,
            },
            {
                "id": "AZ-CC-003",
                "phase": "봉쇄",
                "action": "침해된 계정 즉시 비활성화",
                "priority": "HIGH",
                "tools": ["Azure Portal", "az ad user update --account-enabled false"],
                "notes": "모든 세션 즉시 취소",
                "completed": False,
            },
            {
                "id": "AZ-CC-004",
                "phase": "봉쇄",
                "action": "침해된 계정의 모든 활성 세션 취소",
                "priority": "HIGH",
                "tools": ["az ad user revoke-sign-in-sessions"],
                "notes": "리프레시 토큰 포함 전체 취소",
                "completed": False,
            },
        ],
    },
    "gcp:credential_compromise": {
        "provider": "GCP",
        "incident_type": "credential_compromise",
        "version": "1.0",
        "phases": ["식별", "봉쇄", "박멸", "복구", "사후조치"],
        "items": [
            {
                "id": "GCP-CC-001",
                "phase": "식별",
                "action": "Cloud Audit Log에서 비정상 서비스 계정 활동 확인",
                "priority": "HIGH",
                "tools": ["gcloud logging read", "Cloud Audit Logs"],
                "notes": "serviceAccountTokenCreator 역할 부여 이벤트 주목",
                "completed": False,
            },
            {
                "id": "GCP-CC-002",
                "phase": "봉쇄",
                "action": "침해된 서비스 계정 키 즉시 비활성화",
                "priority": "HIGH",
                "tools": ["gcloud iam service-accounts keys disable"],
                "notes": "키 ID 확인 후 비활성화",
                "completed": False,
            },
        ],
    },
}


# ── 핵심 기능 ─────────────────────────────────────────────────────────────────

def load_template(
    provider: str,
    incident_type: str,
    custom_path: Path | None,
) -> ChecklistTemplate:
    """템플릿 로드 - 커스텀 파일 우선, 없으면 내장 템플릿 사용"""
    key = f"{provider.lower()}:{incident_type.lower()}"

    if custom_path is not None:
        if not custom_path.exists():
            print(f"[오류] 지정된 체크리스트 파일을 찾을 수 없습니다: {custom_path}", file=sys.stderr)
            sys.exit(1)
        try:
            data = json.loads(custom_path.read_text(encoding="utf-8"))
            print(f"[정보] 커스텀 템플릿 로드: {custom_path}")
            return ChecklistTemplate.from_dict(data)
        except json.JSONDecodeError as exc:
            print(f"[오류] JSON 파싱 실패: {exc}", file=sys.stderr)
            sys.exit(1)

    if key in BUILTIN_TEMPLATES:
        print(f"[정보] 내장 템플릿 사용: {key}")
        return ChecklistTemplate.from_dict(BUILTIN_TEMPLATES[key])

    # 제공자만 일치하는 템플릿이 있으면 첫 번째 사용
    matches = [k for k in BUILTIN_TEMPLATES if k.startswith(f"{provider.lower()}:")]
    if matches:
        print(f"[경고] '{key}' 템플릿 없음. 유사 템플릿 사용: {matches[0]}", file=sys.stderr)
        return ChecklistTemplate.from_dict(BUILTIN_TEMPLATES[matches[0]])

    print(
        f"[오류] 사용 가능한 템플릿 없음. "
        f"지원 목록: {', '.join(BUILTIN_TEMPLATES.keys())}",
        file=sys.stderr,
    )
    sys.exit(1)


def generate_markdown_report(template: ChecklistTemplate) -> str:
    """체크리스트 마크다운 보고서 생성"""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines: list[str] = []

    lines.append(f"# 클라우드 IR 체크리스트 — {template.provider} / {template.incident_type}")
    lines.append(f"\n> 생성일시: {now}  |  버전: {template.version}\n")

    # 통계 요약
    total = len(template.items)
    high_cnt = sum(1 for i in template.items if i.priority == "HIGH")
    med_cnt = sum(1 for i in template.items if i.priority == "MEDIUM")
    low_cnt = sum(1 for i in template.items if i.priority == "LOW")

    lines.append("## 요약")
    lines.append(f"\n| 항목 | 수량 |")
    lines.append(f"|------|------|")
    lines.append(f"| 전체 항목 | {total} |")
    lines.append(f"| 높은 우선순위 | {high_cnt} |")
    lines.append(f"| 중간 우선순위 | {med_cnt} |")
    lines.append(f"| 낮은 우선순위 | {low_cnt} |\n")

    # 단계별 출력
    for phase in template.phases:
        phase_items = [i for i in template.items if i.phase == phase]
        if not phase_items:
            continue
        lines.append(f"## {phase}")
        lines.append("")
        for item in phase_items:
            lines.append(item.to_markdown_row())

    lines.append("\n---")
    lines.append(f"*본 체크리스트는 {template.provider} 환경의 {template.incident_type} 사고 대응을 위해 생성되었습니다.*")
    return "\n".join(lines)


def list_available_templates() -> None:
    """사용 가능한 내장 템플릿 목록 출력"""
    print("\n사용 가능한 내장 템플릿:")
    print(f"{'키':40s} {'제공자':10s} {'사고유형'}")
    print("-" * 70)
    for key, tpl in BUILTIN_TEMPLATES.items():
        print(f"{key:40s} {tpl['provider']:10s} {tpl['incident_type']}")
    print()


# ── CLI 진입점 ────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cloud_ir_checklist",
        description="클라우드 IR 체크리스트 생성기 — 제공자/사고유형별 맞춤 체크리스트를 마크다운으로 출력한다.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
사용 예:
  %(prog)s --provider aws --incident-type credential_compromise
  %(prog)s --provider azure --incident-type credential_compromise --output report.md
  %(prog)s --provider aws --incident-type data_exfiltration --output aws_de.md
  %(prog)s --list-templates
        """,
    )
    parser.add_argument(
        "--provider", "-p",
        choices=["aws", "azure", "gcp"],
        help="클라우드 제공자 (aws / azure / gcp)",
    )
    parser.add_argument(
        "--incident-type", "-t",
        dest="incident_type",
        default="credential_compromise",
        help="사고 유형 (기본값: credential_compromise)",
    )
    parser.add_argument(
        "--template-file",
        dest="template_file",
        type=Path,
        default=None,
        help="커스텀 JSON 체크리스트 파일 경로 (없으면 내장 템플릿 사용)",
    )
    parser.add_argument(
        "--output", "-o",
        type=Path,
        default=None,
        help="출력 마크다운 파일 경로 (미지정 시 표준출력)",
    )
    parser.add_argument(
        "--list-templates",
        action="store_true",
        help="사용 가능한 내장 템플릿 목록 출력 후 종료",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.list_templates:
        list_available_templates()
        return

    if not args.provider:
        parser.error("--provider 옵션이 필요합니다. (--list-templates로 목록 확인)")

    template = load_template(args.provider, args.incident_type, args.template_file)
    report = generate_markdown_report(template)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(report, encoding="utf-8")
        print(f"[완료] 체크리스트 저장: {args.output}")
        item_count = len(template.items)
        print(f"       총 {item_count}개 항목, {len(template.phases)}개 단계")
    else:
        print(report)


if __name__ == "__main__":
    main()
```

### 사용 방법

```bash
# AWS 자격증명 침해 체크리스트 생성 (표준출력)
python cloud_ir_checklist.py --provider aws --incident-type credential_compromise

# Azure 자격증명 침해 체크리스트를 파일로 저장
python cloud_ir_checklist.py --provider azure --incident-type credential_compromise --output azure_cc_checklist.md

# GCP 체크리스트 생성
python cloud_ir_checklist.py --provider gcp --incident-type credential_compromise

# 사용 가능한 내장 템플릿 목록 확인
python cloud_ir_checklist.py --list-templates

# 커스텀 JSON 체크리스트 파일 사용
python cloud_ir_checklist.py --provider aws --incident-type custom --template-file my_checklist.json --output result.md
```

### 커스텀 JSON 형식

```json
{
    "provider": "AWS",
    "incident_type": "ransomware",
    "version": "1.0",
    "phases": ["식별", "봉쇄", "박멸", "복구"],
    "items": [
        {
            "id": "CUSTOM-001",
            "phase": "식별",
            "action": "암호화된 파일 범위 확인",
            "priority": "HIGH",
            "tools": ["aws s3 ls", "CloudTrail"],
            "notes": "S3 버킷별 암호화 이벤트 확인",
            "completed": false
        }
    ]
}
```

---

## 6. 클라우드 IR 조직 구성

| 역할 | 책임 | 필요 권한 |
|------|------|---------|
| IR 리더 | 전체 대응 조율, 의사결정 | 읽기 전용 + 에스컬레이션 |
| 클라우드 포렌식 분석가 | 증거 수집, 로그 분석 | CloudTrail/로그 읽기 |
| 클라우드 엔지니어 | 봉쇄 조치 실행 | 제한된 쓰기 권한 |
| 보안 엔지니어 | 탐지 규칙, SIEM 연동 | 보안 서비스 관리 |
| 법무/컴플라이언스 | 법적 요건, 규제 신고 | 문서 접근 |
| CSP 지원 | 플랫폼 레이어 지원 | CSP 내부 시스템 |

> **핵심 원칙**: 사고 대응 계정은 평소에 비활성화 상태로 유지하고, 실제 사고 발생 시 Break Glass 절차에 따라 활성화한다. 모든 접근은 별도 로그로 기록한다.

---

<a name="english"></a>

# Cloud Incident Response (IR) Fundamentals

## 1. On-Premises vs Cloud IR Comparison

Incident response in cloud environments requires a fundamentally different approach from traditional on-premises environments. The key differences are that you cannot physically access hardware, infrastructure control is divided between the cloud provider and the customer, and evidence exists in the form of API calls and log streams.

| Aspect | On-Premises IR | Cloud IR |
|--------|---------------|---------|
| Physical Access | Direct access to server room | No physical access; via API/console only |
| Evidence Collection | Direct disk imaging, memory dumps | Snapshots, log APIs |
| Evidence Retention Period | Permanent while system is preserved | Auto-deleted by default settings (90 days–1 year) |
| Network Forensics | Full packet capture possible | VPC flow logs (metadata only) |
| Volatile Data | Direct RAM dump | Lost immediately upon instance termination |
| Timeline Construction | Filesystem timestamps | API call event timestamps |
| Jurisdiction | Single physical location | Multi-region, complex multinational legal jurisdiction |
| Cost | Fixed hardware cost | Log storage/query costs incurred |
| Scalability | Manual scaling | Auto-scaling creates risk of evidence loss |
| Authentication/Access | Local accounts, AD | IAM, federation, temporary credentials |

---

## 2. Shared Responsibility Model and IR Scope

IR responsibilities differ by cloud service model between provider and customer. Upon an incident, quickly identifying which layer was breached determines the scope of investigation and direction of evidence collection.

### 2.1 Responsibility Separation by Service Model

| Layer | IaaS (EC2/VM) | PaaS (RDS/AppSvc) | SaaS (Office365/Workspace) |
|-------|--------------|------------------|---------------------------|
| Physical Infrastructure | CSP | CSP | CSP |
| Hypervisor | CSP | CSP | CSP |
| Operating System | Customer | CSP | CSP |
| Runtime/Middleware | Customer | CSP | CSP |
| Application | Customer | Customer | CSP |
| Data | Customer | Customer | Customer |
| Identity/Access Management | Customer | Customer | Customer |
| Network Configuration | Customer | Partial customer | CSP |

### 2.2 IR Scope Determination Principles

- **CSP-layer breach**: Report incident to cloud provider, request support, collaborate with provider's forensics team
- **Customer-layer breach**: Deploy internal IR team or external DFIR firm
- **IAM breach**: Common to both layers; immediately disable credentials, then analyze CloudTrail/Activity Log
- **Data exfiltration**: Customer responsibility, but CSP support tools (Macie, DLP) can be leveraged

---

## 3. Special Characteristics of Cloud Evidence Collection

### 3.1 Volatile Data First Collection Principle

The principle of collecting the most volatile data first applies in the cloud too, but the target list is different.

| Priority | On-Premises | Cloud |
|----------|-------------|-------|
| 1st | RAM contents | Running process info (SSM session) |
| 2nd | Network connection state | VPC flow logs (real-time) |
| 3rd | Filesystem timestamps | CloudTrail/Activity Log current session |
| 4th | Log files | Temporary credential session token list |
| 5th | Disk image | EBS/disk snapshot |

### 3.2 Log Retention Period Cautions

| Service | Default Retention | Max Retention | Notes |
|---------|-------------------|---------------|-------|
| AWS CloudTrail | 90 days (Event History) | Unlimited in S3 | Deleted after 90 days if Trail not configured |
| AWS VPC Flow Log | None (auto-deleted) | Requires CloudWatch/S3 setup | Default: no retention |
| AWS GuardDuty | 90 days | — | Export settings recommended |
| Azure Activity Log | 90 days | 2 years with Log Analytics | Diagnostic Settings required |
| Azure AD Sign-in | 30 days (P1/P2) | Storage integration | Free tier: 7 days |
| GCP Cloud Audit | 400 days (Admin) | Cloud Storage integration | Data Access disabled by default |
| GCP VPC Flow | None | BigQuery/Storage | Explicit activation required |

### 3.3 Evidence Integrity Assurance Methods

```
1. Record timestamp at log collection (UTC)
2. Compute SHA-256 hash of collected log files
3. Transfer to immutable storage (S3 Object Lock, Azure Immutable Storage)
4. Log access history of archived logs separately
5. Create Chain of Custody document for legal validity
```

---

## 4. Cloud Attack Kill Chain Stages

| Stage | Description | Cloud-Specific Techniques | Detection Indicators |
|-------|-------------|--------------------------|---------------------|
| Reconnaissance | Public information gathering | S3 bucket enumeration, public AMI lookup | Surge in unauthenticated API calls |
| Initial Access | Establish first entry point | Credential theft, public instance vulnerabilities | Logins from abnormal regions |
| Execution | Execute malicious code/commands | Lambda function abuse, SSM command execution | Abnormal Lambda invocation patterns |
| Persistence | Establish re-access mechanism | Create backdoor IAM user, issue access keys | CreateUser, CreateAccessKey events |
| Privilege Escalation | Gain higher privileges | Attach IAM policy, assume role | AttachUserPolicy, AssumeRole events |
| Defense Evasion | Avoid detection | Disable CloudTrail, delete GuardDuty | StopLogging, DeleteDetector events |
| Credential Access | Steal additional credentials | Query Secrets Manager, access env vars | Bulk GetSecretValue calls |
| Lateral Movement | Move within environment | Role switching, cross-account access | AssumeRole chains |
| Collection | Gather data | Enumerate S3 buckets, create RDS snapshots | ListBuckets, CreateDBSnapshot |
| Exfiltration | Transfer data externally | Copy to S3, share public snapshots | Bulk S3 GetObject, ModifySnapshotAttribute |
| Impact | Destroy/ransom | Delete instances, encrypt | TerminateInstances, KMS key deletion |

---

## 5. Python CLI: Cloud IR Checklist Generator

See the Korean section for the full Python code listing.

### Usage

```bash
# Generate AWS credential compromise checklist (stdout)
python cloud_ir_checklist.py --provider aws --incident-type credential_compromise

# Save Azure credential compromise checklist to file
python cloud_ir_checklist.py --provider azure --incident-type credential_compromise --output azure_cc_checklist.md

# Generate GCP checklist
python cloud_ir_checklist.py --provider gcp --incident-type credential_compromise

# List available built-in templates
python cloud_ir_checklist.py --list-templates

# Use custom JSON checklist file
python cloud_ir_checklist.py --provider aws --incident-type custom --template-file my_checklist.json --output result.md
```

---

## 6. Cloud IR Organizational Structure

| Role | Responsibility | Required Access |
|------|----------------|-----------------|
| IR Lead | Coordinate overall response, decision-making | Read-only + escalation |
| Cloud Forensics Analyst | Evidence collection, log analysis | CloudTrail/log read access |
| Cloud Engineer | Execute containment measures | Limited write access |
| Security Engineer | Detection rules, SIEM integration | Security service management |
| Legal/Compliance | Legal requirements, regulatory reporting | Document access |
| CSP Support | Platform layer support | CSP internal systems |

> **Key Principle**: Keep incident response accounts disabled at all times, and activate them via Break Glass procedures only during actual incidents. All access must be logged separately.
