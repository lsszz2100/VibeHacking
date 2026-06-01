> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# Azure 포렌식

## 1. Azure 로그 소스

Azure 환경에서 포렌식 조사를 수행할 때 활용 가능한 주요 로그 소스는 다음과 같다. Azure는 Microsoft Sentinel을 중심으로 다양한 보안 신호를 통합 관리하는 구조를 갖추고 있다.

| 로그 소스 | 기록 내용 | 기본 보존 | 주요 활용 목적 |
|----------|---------|---------|-------------|
| Azure Activity Log | 구독 레벨 관리 작업 | 90일 | 리소스 생성/삭제, RBAC 변경 |
| Azure AD Sign-in Log | 사용자/서비스 주체 로그인 | 30일(P1/P2) | 인증 이상 탐지 |
| Azure AD Audit Log | 디렉터리 변경 이력 | 30일 | 그룹/역할/사용자 변경 |
| Azure AD Risky Sign-in | 위험 로그인 이벤트 | 30일 | ID 보호 이벤트 |
| Resource Diagnostic Log | 리소스별 운영 로그 | 리소스 의존 | 서비스별 세부 동작 |
| NSG Flow Log | 네트워크 플로우 메타데이터 | Storage 설정 | 네트워크 이동 추적 |
| Storage Access Log | 스토리지 계정 접근 | 선택적 | 데이터 유출 추적 |
| Microsoft Sentinel | 통합 SIEM 분석/경보 | 90일(기본) | 상관 분석, 헌팅 |
| Microsoft Defender for Cloud | 보안 권고 및 알림 | 6개월 | 취약점/위협 가시성 |
| Key Vault Log | 키/시크릿/인증서 접근 | Diagnostic 설정 | 자격증명 접근 추적 |
| Azure Firewall Log | 방화벽 허용/차단 | Storage 설정 | 외부 통신 탐지 |
| App Service Log | 웹앱 HTTP 요청 | Diagnostic 설정 | 웹 공격 분석 |

### 1.1 Azure Activity Log 이벤트 구조

```json
{
    "time": "2024-01-15T09:23:11.456Z",
    "operationName": {
        "value": "Microsoft.Authorization/roleAssignments/write",
        "localizedValue": "Create role assignment"
    },
    "status": {"value": "Succeeded"},
    "caller": "attacker@contoso.com",
    "claims": {
        "ipaddr": "203.0.113.42",
        "oid": "00000000-0000-0000-0000-000000000001"
    },
    "subscriptionId": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    "resourceGroupName": "production-rg",
    "resourceId": "/subscriptions/.../roleAssignments/...",
    "properties": {
        "roleDefinitionId": "/subscriptions/.../roleDefinitions/8e3af657-...",
        "principalId": "00000000-0000-0000-0000-000000000002"
    }
}
```

---

## 2. Azure AD 침해 지표

Azure AD(Entra ID) 침해 시 관찰되는 주요 지표와 탐지 방법을 정리한다.

### 2.1 Impossible Travel (불가능 이동)

같은 사용자 계정이 물리적으로 이동 불가능한 짧은 시간 내에 서로 다른 지리적 위치에서 로그인하는 패턴이다.

| 탐지 조건 | 설명 | 위험도 |
|---------|------|--------|
| 이동 속도 > 비행기 속도 | 두 로그인 사이 이동 거리/시간 비율 | HIGH |
| 다른 대륙 동시 접근 | 수 분 내 유럽-아시아 전환 | CRITICAL |
| 알 수 없는 국가 로그인 | 조직 활동 국가 외 접근 | HIGH |
| Tor/VPN 연결 후 로그인 | 익명화 프록시 사용 | MEDIUM |

### 2.2 MFA 우회 기법

| 우회 기법 | 설명 | 탐지 방법 |
|---------|------|---------|
| MFA 피로 공격(MFA Fatigue) | 반복 MFA 요청으로 사용자 승인 유도 | 단시간 다수 MFA 요청 탐지 |
| 레거시 프로토콜 악용 | IMAP/POP3/SMTP는 MFA 미적용 | 레거시 프로토콜 로그인 탐지 |
| 조건부 액세스 갭 | 미적용 앱 대상 로그인 | 조건부 액세스 미적용 로그인 |
| 토큰 도용 | 액세스 토큰 직접 재사용 | 동일 토큰 다수 IP 사용 |
| Pass-the-Cookie | 브라우저 세션 쿠키 탈취 | 세션 고정 이상 탐지 |
| Adversary-in-the-Middle | 역프록시로 인증 가로채기 | 비정상 User-Agent/IP |

### 2.3 Azure AD 침해 확인 명령어

```bash
# 위험 사용자 목록 조회
az ad signin-log list \
    --filter "riskLevel eq 'high'" \
    --query "[].{user:userPrincipalName, ip:ipAddress, time:createdDateTime}"

# 최근 역할 할당 변경
az role assignment list --all \
    --query "[?contains(to_string(createdOn), '2024-01')].{role:roleDefinitionName, principal:principalName}"

# 게스트 사용자 목록
az ad user list --filter "userType eq 'Guest'" \
    --query "[].{upn:userPrincipalName, created:createdDateTime}"
```

---

## 3. Azure RBAC 에스컬레이션 경로

| 에스컬레이션 경로 | 필요 초기 권한 | 획득 권한 | 탐지 이벤트 |
|---------------|------------|---------|-----------|
| 역할 할당 추가 | Microsoft.Authorization/roleAssignments/write | 구독 기여자/소유자 | roleAssignments/write |
| 커스텀 역할 생성 | Microsoft.Authorization/roleDefinitions/write | 임의 권한 조합 | roleDefinitions/write |
| 관리 그룹 역할 | 관리 그룹 소유자 | 모든 하위 구독 접근 | 관리 그룹 역할 할당 |
| 서비스 주체 시크릿 | Application.ReadWrite.All | 앱 자격증명 탈취 | addPassword |
| PIM 활성화 남용 | 대상 역할 자격 대상 | 시간 제한 고권한 | PIM 역할 활성화 |
| Managed Identity 남용 | VM/함수 실행 권한 | MI에 할당된 권한 | 토큰 요청 이벤트 |
| Azure DevOps SVC | DevOps 프로젝트 접근 | CI/CD 파이프라인 | SVC 연결 사용 |

### 3.1 RBAC 에스컬레이션 탐지 쿼리 (KQL)

```kusto
AzureActivity
| where OperationNameValue in (
    "Microsoft.Authorization/roleAssignments/write",
    "Microsoft.Authorization/roleDefinitions/write",
    "Microsoft.Authorization/elevateAccess/action"
)
| where ActivityStatusValue == "Succeeded"
| project TimeGenerated, Caller, OperationNameValue, ResourceGroup, Properties
| order by TimeGenerated desc
```

---

## 4. Python CLI: Azure Activity Log 분석기

```python
#!/usr/bin/env python3
"""
Azure Activity Log 분석기
- JSON 형식의 Azure Activity Log를 파싱하여 위험 작업을 분류한다.
- 결과를 CSV와 마크다운 형식으로 동시에 출력한다.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# ── 위험 작업 분류 규칙 ───────────────────────────────────────────────────────

@dataclass
class RiskRule:
    """위험 작업 분류 규칙"""
    rule_id: str
    name: str
    operation_patterns: list[str]   # operationName에 포함될 문자열 패턴
    severity: str                    # CRITICAL / HIGH / MEDIUM / LOW
    category: str                    # 공격 카테고리
    description: str


RISK_RULES: list[RiskRule] = [
    RiskRule(
        rule_id="AZ-001",
        name="RBAC 역할 할당 추가",
        operation_patterns=["roleAssignments/write"],
        severity="HIGH",
        category="privilege_escalation",
        description="Azure RBAC 역할 직접 할당. 권한 에스컬레이션 가능성.",
    ),
    RiskRule(
        rule_id="AZ-002",
        name="커스텀 RBAC 역할 생성/수정",
        operation_patterns=["roleDefinitions/write"],
        severity="HIGH",
        category="privilege_escalation",
        description="커스텀 역할 정의 생성 또는 수정. 임의 권한 조합 가능.",
    ),
    RiskRule(
        rule_id="AZ-003",
        name="Key Vault 시크릿/키 접근",
        operation_patterns=["vaults/secrets", "vaults/keys", "vaults/certificates"],
        severity="HIGH",
        category="credential_access",
        description="Key Vault 내 시크릿/키/인증서 접근. 자격증명 탈취 가능성.",
    ),
    RiskRule(
        rule_id="AZ-004",
        name="네트워크 보안 그룹 규칙 변경",
        operation_patterns=["networkSecurityGroups/securityRules/write"],
        severity="MEDIUM",
        category="defense_evasion",
        description="NSG 규칙 추가/변경. 방화벽 우회 경로 생성 가능성.",
    ),
    RiskRule(
        rule_id="AZ-005",
        name="진단 설정 삭제",
        operation_patterns=["diagnosticSettings/delete"],
        severity="CRITICAL",
        category="defense_evasion",
        description="진단 설정 삭제로 로깅 중단. 증거 인멸 시도.",
    ),
    RiskRule(
        rule_id="AZ-006",
        name="가상 머신 확장/스크립트 실행",
        operation_patterns=[
            "virtualMachines/extensions/write",
            "virtualMachines/runCommand/action",
        ],
        severity="HIGH",
        category="execution",
        description="VM 확장 설치 또는 명령 실행. 악성코드 배포 가능성.",
    ),
    RiskRule(
        rule_id="AZ-007",
        name="스토리지 계정 접근 키 조회",
        operation_patterns=["storageAccounts/listKeys/action"],
        severity="HIGH",
        category="credential_access",
        description="스토리지 계정 접근 키 조회. 데이터 유출 선행 단계.",
    ),
    RiskRule(
        rule_id="AZ-008",
        name="서비스 주체 자격증명 추가",
        operation_patterns=["applications/addPassword", "servicePrincipals/addPassword"],
        severity="CRITICAL",
        category="persistence",
        description="앱/서비스 주체에 새 자격증명 추가. 백도어 지속성 확보.",
    ),
    RiskRule(
        rule_id="AZ-009",
        name="VM 스냅샷/디스크 내보내기",
        operation_patterns=["snapshots/write", "disks/write", "disks/beginGetAccess"],
        severity="HIGH",
        category="exfiltration",
        description="VM 스냅샷 생성 또는 디스크 접근 URL 생성. 데이터 유출 시도.",
    ),
    RiskRule(
        rule_id="AZ-010",
        name="리소스 그룹 삭제",
        operation_patterns=["resourceGroups/delete"],
        severity="CRITICAL",
        category="impact",
        description="리소스 그룹 전체 삭제. 서비스 파괴 또는 증거 인멸.",
    ),
    RiskRule(
        rule_id="AZ-011",
        name="Automation 계정/Runbook 조작",
        operation_patterns=[
            "automationAccounts/runbooks/write",
            "automationAccounts/jobs/write",
        ],
        severity="HIGH",
        category="execution",
        description="Automation Runbook 생성/실행. 자동화를 이용한 악성 작업 실행.",
    ),
    RiskRule(
        rule_id="AZ-012",
        name="구독 레벨 권한 상승",
        operation_patterns=["elevateAccess/action"],
        severity="CRITICAL",
        category="privilege_escalation",
        description="Azure AD 글로벌 관리자의 구독 접근 권한 상승.",
    ),
    RiskRule(
        rule_id="AZ-013",
        name="퍼블릭 IP 주소 생성",
        operation_patterns=["publicIPAddresses/write"],
        severity="LOW",
        category="initial_access",
        description="퍼블릭 IP 생성. 외부 노출 리소스 추가 가능성.",
    ),
    RiskRule(
        rule_id="AZ-014",
        name="Logic App / Function 생성",
        operation_patterns=[
            "workflows/write",
            "sites/write",
            "functionApp/write",
        ],
        severity="MEDIUM",
        category="persistence",
        description="Logic App 또는 Function App 생성. 지속성 기반 구축 가능.",
    ),
]


# ── 데이터 구조 ───────────────────────────────────────────────────────────────

@dataclass
class ActivityLogEvent:
    """파싱된 Azure Activity Log 이벤트"""
    event_time: datetime
    operation_name: str
    status: str
    caller: str
    source_ip: str
    subscription_id: str
    resource_group: str
    resource_id: str
    tenant_id: str
    correlation_id: str
    level: str
    properties: dict[str, Any]
    raw: dict[str, Any]

    @classmethod
    def from_dict(cls, record: dict[str, Any]) -> "ActivityLogEvent":
        # operationName은 객체 또는 문자열
        op_name = record.get("operationName", {})
        if isinstance(op_name, dict):
            op_name = op_name.get("value", "")

        status = record.get("status", {})
        if isinstance(status, dict):
            status = status.get("value", "")

        claims = record.get("claims", {})
        source_ip = claims.get("ipaddr", record.get("httpRequest", {}).get("clientIpAddress", ""))

        time_str = record.get("time", record.get("eventTimestamp", ""))
        try:
            event_time = datetime.fromisoformat(time_str.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            event_time = datetime.now(timezone.utc)

        return cls(
            event_time=event_time,
            operation_name=op_name,
            status=str(status),
            caller=record.get("caller", ""),
            source_ip=source_ip,
            subscription_id=record.get("subscriptionId", ""),
            resource_group=record.get("resourceGroupName", ""),
            resource_id=record.get("resourceId", ""),
            tenant_id=record.get("tenantId", ""),
            correlation_id=record.get("correlationId", ""),
            level=record.get("level", ""),
            properties=record.get("properties", {}) or {},
            raw=record,
        )


@dataclass
class RiskEvent:
    """탐지된 위험 이벤트"""
    event: ActivityLogEvent
    rule: RiskRule

    def to_csv_row(self) -> list[str]:
        return [
            self.event.event_time.strftime("%Y-%m-%d %H:%M:%S UTC"),
            self.rule.rule_id,
            self.rule.severity,
            self.rule.category,
            self.rule.name,
            self.event.operation_name,
            self.event.status,
            self.event.caller,
            self.event.source_ip,
            self.event.resource_group,
            self.event.subscription_id,
        ]

    def to_markdown_row(self) -> str:
        ts = self.event.event_time.strftime("%Y-%m-%d %H:%M:%S")
        sev_badge = {
            "CRITICAL": "**CRITICAL**",
            "HIGH":     "HIGH",
            "MEDIUM":   "MEDIUM",
            "LOW":      "LOW",
        }.get(self.rule.severity, self.rule.severity)
        return (
            f"| {ts} "
            f"| {self.rule.rule_id} "
            f"| {sev_badge} "
            f"| {self.rule.name} "
            f"| {self.event.caller} "
            f"| {self.event.source_ip} "
            f"| {self.event.resource_group} |"
        )


# ── 핵심 기능 ─────────────────────────────────────────────────────────────────

def parse_activity_log(path: Path) -> list[ActivityLogEvent]:
    """Azure Activity Log JSON 파일 파싱 (배열 또는 단일 객체)"""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[오류] JSON 파싱 실패: {exc}", file=sys.stderr)
        sys.exit(1)

    records: list[dict] = []
    if isinstance(raw, list):
        records = raw
    elif isinstance(raw, dict):
        # Azure Monitor Export 형식: {"value": [...]}
        records = raw.get("value", [raw])

    events: list[ActivityLogEvent] = []
    for rec in records:
        try:
            events.append(ActivityLogEvent.from_dict(rec))
        except Exception as exc:
            print(f"[경고] 레코드 건너뜀: {exc}", file=sys.stderr)
    return events


def filter_events(
    events: list[ActivityLogEvent],
    subscription_id: str | None,
    operation_filter: list[str] | None,
) -> list[ActivityLogEvent]:
    """구독 ID, 작업명 필터 적용"""
    result = events
    if subscription_id:
        result = [e for e in result if subscription_id in e.subscription_id]
    if operation_filter:
        of_lower = [f.lower() for f in operation_filter]
        result = [
            e for e in result
            if any(pat in e.operation_name.lower() for pat in of_lower)
        ]
    return result


def classify_risks(events: list[ActivityLogEvent]) -> list[RiskEvent]:
    """위험 작업 분류 규칙 적용"""
    risk_events: list[RiskEvent] = []
    for event in events:
        op_lower = event.operation_name.lower()
        for rule in RISK_RULES:
            if any(pat.lower() in op_lower for pat in rule.operation_patterns):
                risk_events.append(RiskEvent(event=event, rule=rule))
                break  # 첫 번째 매칭 규칙만 적용
    risk_events.sort(key=lambda r: (
        {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(r.rule.severity, 9),
        r.event.event_time,
    ))
    return risk_events


def write_csv(risk_events: list[RiskEvent], output_path: Path) -> None:
    """CSV 파일 출력"""
    headers = [
        "이벤트시각(UTC)", "규칙ID", "심각도", "카테고리", "규칙명",
        "작업명", "상태", "호출자", "소스IP", "리소스그룹", "구독ID",
    ]
    try:
        with output_path.open("w", newline="", encoding="utf-8-sig") as fh:
            writer = csv.writer(fh)
            writer.writerow(headers)
            for re_ in risk_events:
                writer.writerow(re_.to_csv_row())
        print(f"[완료] CSV 저장: {output_path} ({len(risk_events)}건)")
    except OSError as exc:
        print(f"[오류] CSV 저장 실패: {exc}", file=sys.stderr)


def write_markdown(
    risk_events: list[RiskEvent],
    all_events: list[ActivityLogEvent],
    output_path: Path,
) -> None:
    """마크다운 보고서 출력"""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines: list[str] = []

    lines.append("# Azure Activity Log 위험 작업 분석 보고서")
    lines.append(f"\n> 생성일시: {now}\n")

    # 요약 통계
    sev_counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for re_ in risk_events:
        sev_counts[re_.rule.severity] = sev_counts.get(re_.rule.severity, 0) + 1

    lines.append("## 요약")
    lines.append(f"\n| 항목 | 수치 |")
    lines.append(f"|------|------|")
    lines.append(f"| 전체 이벤트 | {len(all_events):,} |")
    lines.append(f"| 위험 이벤트 | {len(risk_events):,} |")
    for sev, cnt in sev_counts.items():
        lines.append(f"| {sev} | {cnt:,} |")
    lines.append("")

    # 카테고리별 집계
    cat_counts: dict[str, int] = {}
    for re_ in risk_events:
        cat_counts[re_.rule.category] = cat_counts.get(re_.rule.category, 0) + 1

    if cat_counts:
        lines.append("## 카테고리별 탐지")
        lines.append("\n| 카테고리 | 건수 |")
        lines.append("|---------|------|")
        for cat, cnt in sorted(cat_counts.items(), key=lambda x: -x[1]):
            lines.append(f"| {cat} | {cnt} |")
        lines.append("")

    # 탐지 이벤트 테이블
    if risk_events:
        lines.append("## 탐지된 위험 작업 목록")
        lines.append(
            "\n| 시각(UTC) | 규칙ID | 심각도 | 규칙명 | 호출자 | 소스IP | 리소스그룹 |"
        )
        lines.append(
            "|----------|--------|--------|--------|--------|--------|-----------|"
        )
        for re_ in risk_events:
            lines.append(re_.to_markdown_row())
        lines.append("")

    # 주요 호출자 분석
    caller_counts: dict[str, int] = {}
    for re_ in risk_events:
        caller_counts[re_.event.caller] = caller_counts.get(re_.event.caller, 0) + 1

    if caller_counts:
        lines.append("## 주요 호출자")
        lines.append("\n| 호출자 | 위험 이벤트 수 |")
        lines.append("|--------|--------------|")
        for caller, cnt in sorted(caller_counts.items(), key=lambda x: -x[1])[:10]:
            lines.append(f"| {caller} | {cnt} |")
        lines.append("")

    lines.append("---")
    lines.append("*본 보고서는 자동 생성된 분석 결과이며, 전문가 검토가 필요합니다.*")

    try:
        output_path.write_text("\n".join(lines), encoding="utf-8")
        print(f"[완료] 마크다운 저장: {output_path} ({len(risk_events)}건)")
    except OSError as exc:
        print(f"[오류] 마크다운 저장 실패: {exc}", file=sys.stderr)


def print_console_summary(
    risk_events: list[RiskEvent],
    all_events: list[ActivityLogEvent],
) -> None:
    """콘솔 요약 출력"""
    print(f"\n{'=' * 80}")
    print(f" Azure Activity Log 분석 결과")
    print(f"{'=' * 80}")
    print(f"  전체 이벤트:   {len(all_events):,}")
    print(f"  위험 이벤트:   {len(risk_events):,}")

    for re_ in risk_events:
        sev_icon = {
            "CRITICAL": "[!!!]",
            "HIGH":     "[ ! ]",
            "MEDIUM":   "[ * ]",
            "LOW":      "[ - ]",
        }.get(re_.rule.severity, "[ ? ]")
        ts = re_.event.event_time.strftime("%Y-%m-%d %H:%M:%S")
        print(
            f"\n  {sev_icon} {ts} | {re_.rule.rule_id} {re_.rule.name}\n"
            f"         작업: {re_.event.operation_name}\n"
            f"         호출자: {re_.event.caller} | IP: {re_.event.source_ip}\n"
            f"         RG: {re_.event.resource_group} | 상태: {re_.event.status}"
        )
    print()


# ── CLI 진입점 ────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="azure_activity_log_analyzer",
        description="Azure Activity Log 분석기 — 위험 작업을 분류하고 CSV+마크다운으로 출력한다.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
사용 예:
  %(prog)s --input-json activity_log.json
  %(prog)s --input-json activity_log.json --subscription-id aaaa-bbbb-cccc
  %(prog)s --input-json activity_log.json --operation-filter roleAssignments
  %(prog)s --input-json activity_log.json --output-dir ./reports
        """,
    )
    parser.add_argument(
        "--input-json", "-i",
        dest="input_json",
        type=Path,
        required=True,
        help="Azure Activity Log JSON 파일 경로",
    )
    parser.add_argument(
        "--subscription-id", "-s",
        dest="subscription_id",
        default=None,
        help="특정 구독 ID 필터 (부분 일치)",
    )
    parser.add_argument(
        "--operation-filter", "-o",
        dest="operation_filter",
        nargs="+",
        default=None,
        help="작업명 필터 (공백으로 구분, 부분 일치)",
    )
    parser.add_argument(
        "--output-dir",
        dest="output_dir",
        type=Path,
        default=None,
        help="CSV/마크다운 저장 디렉토리 (미지정 시 콘솔 출력만)",
    )
    parser.add_argument(
        "--min-severity",
        dest="min_severity",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        default="LOW",
        help="최소 심각도 필터 (기본값: LOW = 전체)",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if not args.input_json.exists():
        print(f"[오류] 파일 없음: {args.input_json}", file=sys.stderr)
        sys.exit(1)

    print(f"[정보] 파일 로드: {args.input_json}")
    events = parse_activity_log(args.input_json)
    print(f"[정보] {len(events):,}개 이벤트 로드")

    filtered = filter_events(events, args.subscription_id, args.operation_filter)
    if len(filtered) != len(events):
        print(f"[정보] 필터 후: {len(filtered):,}개")

    risk_events = classify_risks(filtered)

    # 심각도 필터
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    min_order = sev_order.get(args.min_severity, 3)
    risk_events = [
        re_ for re_ in risk_events
        if sev_order.get(re_.rule.severity, 9) <= min_order
    ]

    print_console_summary(risk_events, filtered)

    if args.output_dir:
        args.output_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

        csv_path = args.output_dir / f"azure_risk_events_{timestamp}.csv"
        md_path = args.output_dir / f"azure_risk_report_{timestamp}.md"

        write_csv(risk_events, csv_path)
        write_markdown(risk_events, filtered, md_path)


if __name__ == "__main__":
    main()
```

### 사용 방법

```bash
# 기본 분석 (콘솔 출력)
python azure_activity_log_analyzer.py --input-json activity_log.json

# 특정 구독 필터 + 결과 저장
python azure_activity_log_analyzer.py \
    --input-json activity_log.json \
    --subscription-id aaaa-bbbb-cccc \
    --output-dir ./azure_reports

# 역할 할당 관련 작업만 분석
python azure_activity_log_analyzer.py \
    --input-json activity_log.json \
    --operation-filter roleAssignments roleDefinitions

# CRITICAL 이상만 출력
python azure_activity_log_analyzer.py \
    --input-json activity_log.json \
    --min-severity CRITICAL \
    --output-dir ./critical_only
```

---

## 5. Azure 포렌식 추가 참고사항

### 5.1 Entra ID(Azure AD) 포렌식 로그 수집

```bash
# 최근 로그인 실패 이력
az rest --method GET \
    --url "https://graph.microsoft.com/v1.0/auditLogs/signIns?\$filter=status/errorCode ne 0" \
    --headers "Content-Type=application/json"

# 디렉터리 감사 로그 (역할 변경)
az rest --method GET \
    --url "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?\$filter=category eq 'RoleManagement'"
```

### 5.2 Microsoft Sentinel KQL 헌팅 쿼리

```kusto
// 불가능 이동 탐지
SigninLogs
| where TimeGenerated > ago(1d)
| project UserPrincipalName, IPAddress, Location, TimeGenerated
| sort by UserPrincipalName, TimeGenerated
| extend PrevIP = prev(IPAddress, 1),
         PrevTime = prev(TimeGenerated, 1),
         PrevUser = prev(UserPrincipalName, 1)
| where UserPrincipalName == PrevUser
| where IPAddress != PrevIP
| where datetime_diff("minute", TimeGenerated, PrevTime) < 30
```

---

<a name="english"></a>

# Azure Forensics

## 1. Azure Log Sources

The key log sources available when conducting forensic investigations in an Azure environment are listed below. Azure is structured around Microsoft Sentinel to centrally manage various security signals.

| Log Source | Recorded Content | Default Retention | Primary Purpose |
|----------|---------|---------|-------------|
| Azure Activity Log | Subscription-level management operations | 90 days | Resource creation/deletion, RBAC changes |
| Azure AD Sign-in Log | User/service principal logins | 30 days (P1/P2) | Authentication anomaly detection |
| Azure AD Audit Log | Directory change history | 30 days | Group/role/user changes |
| Azure AD Risky Sign-in | Risky login events | 30 days | Identity protection events |
| Resource Diagnostic Log | Per-resource operational logs | Resource-dependent | Detailed per-service behavior |
| NSG Flow Log | Network flow metadata | Storage configuration | Network movement tracking |
| Storage Access Log | Storage account access | Optional | Data exfiltration tracking |
| Microsoft Sentinel | Integrated SIEM analysis/alerting | 90 days (default) | Correlation analysis, hunting |
| Microsoft Defender for Cloud | Security recommendations and alerts | 6 months | Vulnerability/threat visibility |
| Key Vault Log | Key/secret/certificate access | Diagnostic configuration | Credential access tracking |
| Azure Firewall Log | Firewall allow/block | Storage configuration | External communication detection |
| App Service Log | Web app HTTP requests | Diagnostic configuration | Web attack analysis |

### 1.1 Azure Activity Log Event Structure

```json
{
    "time": "2024-01-15T09:23:11.456Z",
    "operationName": {
        "value": "Microsoft.Authorization/roleAssignments/write",
        "localizedValue": "Create role assignment"
    },
    "status": {"value": "Succeeded"},
    "caller": "attacker@contoso.com",
    "claims": {
        "ipaddr": "203.0.113.42",
        "oid": "00000000-0000-0000-0000-000000000001"
    },
    "subscriptionId": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    "resourceGroupName": "production-rg",
    "resourceId": "/subscriptions/.../roleAssignments/...",
    "properties": {
        "roleDefinitionId": "/subscriptions/.../roleDefinitions/8e3af657-...",
        "principalId": "00000000-0000-0000-0000-000000000002"
    }
}
```

---

## 2. Azure AD Compromise Indicators

Key indicators observed during Azure AD (Entra ID) compromise and detection methods are summarized below.

### 2.1 Impossible Travel

A pattern where the same user account logs in from geographically different locations within a timeframe that is physically impossible to travel.

| Detection Condition | Description | Risk Level |
|---------|------|--------|
| Travel speed exceeds aircraft speed | Distance/time ratio between two logins | HIGH |
| Simultaneous access from different continents | Europe-Asia switch within minutes | CRITICAL |
| Login from unknown country | Access from outside the organization's operating countries | HIGH |
| Login after Tor/VPN connection | Use of anonymization proxy | MEDIUM |

### 2.2 MFA Bypass Techniques

| Bypass Technique | Description | Detection Method |
|---------|------|---------|
| MFA Fatigue Attack | Repeated MFA requests to induce user approval | Detect numerous MFA requests in short timeframe |
| Legacy Protocol Abuse | IMAP/POP3/SMTP do not enforce MFA | Detect logins via legacy protocols |
| Conditional Access Gap | Login targeting apps without policy applied | Detect logins not covered by Conditional Access |
| Token Theft | Direct reuse of access tokens | Detect same token used from multiple IPs |
| Pass-the-Cookie | Theft of browser session cookies | Detect session fixation anomalies |
| Adversary-in-the-Middle | Intercepting authentication via reverse proxy | Detect abnormal User-Agent/IP |

### 2.3 Azure AD Compromise Verification Commands

```bash
# Query list of risky users
az ad signin-log list \
    --filter "riskLevel eq 'high'" \
    --query "[].{user:userPrincipalName, ip:ipAddress, time:createdDateTime}"

# Recent role assignment changes
az role assignment list --all \
    --query "[?contains(to_string(createdOn), '2024-01')].{role:roleDefinitionName, principal:principalName}"

# Guest user list
az ad user list --filter "userType eq 'Guest'" \
    --query "[].{upn:userPrincipalName, created:createdDateTime}"
```

---

## 3. Azure RBAC Escalation Paths

| Escalation Path | Required Initial Permission | Permissions Gained | Detection Event |
|---------------|------------|---------|-----------|
| Add role assignment | Microsoft.Authorization/roleAssignments/write | Subscription Contributor/Owner | roleAssignments/write |
| Create custom role | Microsoft.Authorization/roleDefinitions/write | Arbitrary permission combination | roleDefinitions/write |
| Management group role | Management group Owner | Access to all child subscriptions | Management group role assignment |
| Service principal secret | Application.ReadWrite.All | App credential theft | addPassword |
| PIM activation abuse | Eligible for target role | Time-limited elevated privileges | PIM role activation |
| Managed Identity abuse | VM/function execution permission | Permissions assigned to MI | Token request event |
| Azure DevOps SVC | DevOps project access | CI/CD pipeline | SVC connection usage |

### 3.1 RBAC Escalation Detection Query (KQL)

```kusto
AzureActivity
| where OperationNameValue in (
    "Microsoft.Authorization/roleAssignments/write",
    "Microsoft.Authorization/roleDefinitions/write",
    "Microsoft.Authorization/elevateAccess/action"
)
| where ActivityStatusValue == "Succeeded"
| project TimeGenerated, Caller, OperationNameValue, ResourceGroup, Properties
| order by TimeGenerated desc
```

---

## 4. Python CLI: Azure Activity Log Analyzer

```python
#!/usr/bin/env python3
"""
Azure Activity Log Analyzer
- Parses Azure Activity Logs in JSON format to classify risky operations.
- Simultaneously outputs results in CSV and Markdown formats.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# ── Risk Operation Classification Rules ───────────────────────────────────────

@dataclass
class RiskRule:
    """Risk operation classification rule"""
    rule_id: str
    name: str
    operation_patterns: list[str]   # String patterns to match within operationName
    severity: str                    # CRITICAL / HIGH / MEDIUM / LOW
    category: str                    # Attack category
    description: str


RISK_RULES: list[RiskRule] = [
    RiskRule(
        rule_id="AZ-001",
        name="RBAC Role Assignment Added",
        operation_patterns=["roleAssignments/write"],
        severity="HIGH",
        category="privilege_escalation",
        description="Azure RBAC role directly assigned. Possible privilege escalation.",
    ),
    RiskRule(
        rule_id="AZ-002",
        name="Custom RBAC Role Created/Modified",
        operation_patterns=["roleDefinitions/write"],
        severity="HIGH",
        category="privilege_escalation",
        description="Custom role definition created or modified. Arbitrary permission combinations possible.",
    ),
    RiskRule(
        rule_id="AZ-003",
        name="Key Vault Secret/Key Accessed",
        operation_patterns=["vaults/secrets", "vaults/keys", "vaults/certificates"],
        severity="HIGH",
        category="credential_access",
        description="Secret/key/certificate accessed in Key Vault. Possible credential theft.",
    ),
    RiskRule(
        rule_id="AZ-004",
        name="Network Security Group Rule Changed",
        operation_patterns=["networkSecurityGroups/securityRules/write"],
        severity="MEDIUM",
        category="defense_evasion",
        description="NSG rule added/changed. Possible creation of firewall bypass path.",
    ),
    RiskRule(
        rule_id="AZ-005",
        name="Diagnostic Setting Deleted",
        operation_patterns=["diagnosticSettings/delete"],
        severity="CRITICAL",
        category="defense_evasion",
        description="Logging stopped by deleting diagnostic settings. Evidence destruction attempt.",
    ),
    RiskRule(
        rule_id="AZ-006",
        name="Virtual Machine Extension/Script Executed",
        operation_patterns=[
            "virtualMachines/extensions/write",
            "virtualMachines/runCommand/action",
        ],
        severity="HIGH",
        category="execution",
        description="VM extension installed or command executed. Possible malware deployment.",
    ),
    RiskRule(
        rule_id="AZ-007",
        name="Storage Account Access Key Retrieved",
        operation_patterns=["storageAccounts/listKeys/action"],
        severity="HIGH",
        category="credential_access",
        description="Storage account access key retrieved. Precursor step to data exfiltration.",
    ),
    RiskRule(
        rule_id="AZ-008",
        name="Service Principal Credential Added",
        operation_patterns=["applications/addPassword", "servicePrincipals/addPassword"],
        severity="CRITICAL",
        category="persistence",
        description="New credential added to app/service principal. Backdoor persistence established.",
    ),
    RiskRule(
        rule_id="AZ-009",
        name="VM Snapshot/Disk Exported",
        operation_patterns=["snapshots/write", "disks/write", "disks/beginGetAccess"],
        severity="HIGH",
        category="exfiltration",
        description="VM snapshot created or disk access URL generated. Data exfiltration attempt.",
    ),
    RiskRule(
        rule_id="AZ-010",
        name="Resource Group Deleted",
        operation_patterns=["resourceGroups/delete"],
        severity="CRITICAL",
        category="impact",
        description="Entire resource group deleted. Service destruction or evidence destruction.",
    ),
    RiskRule(
        rule_id="AZ-011",
        name="Automation Account/Runbook Manipulated",
        operation_patterns=[
            "automationAccounts/runbooks/write",
            "automationAccounts/jobs/write",
        ],
        severity="HIGH",
        category="execution",
        description="Automation Runbook created/executed. Malicious operations executed via automation.",
    ),
    RiskRule(
        rule_id="AZ-012",
        name="Subscription-Level Privilege Elevated",
        operation_patterns=["elevateAccess/action"],
        severity="CRITICAL",
        category="privilege_escalation",
        description="Azure AD global administrator elevated subscription access.",
    ),
    RiskRule(
        rule_id="AZ-013",
        name="Public IP Address Created",
        operation_patterns=["publicIPAddresses/write"],
        severity="LOW",
        category="initial_access",
        description="Public IP created. Possible addition of externally exposed resources.",
    ),
    RiskRule(
        rule_id="AZ-014",
        name="Logic App / Function Created",
        operation_patterns=[
            "workflows/write",
            "sites/write",
            "functionApp/write",
        ],
        severity="MEDIUM",
        category="persistence",
        description="Logic App or Function App created. Possible persistence infrastructure establishment.",
    ),
]


# ── Data Structures ───────────────────────────────────────────────────────────

@dataclass
class ActivityLogEvent:
    """Parsed Azure Activity Log event"""
    event_time: datetime
    operation_name: str
    status: str
    caller: str
    source_ip: str
    subscription_id: str
    resource_group: str
    resource_id: str
    tenant_id: str
    correlation_id: str
    level: str
    properties: dict[str, Any]
    raw: dict[str, Any]

    @classmethod
    def from_dict(cls, record: dict[str, Any]) -> "ActivityLogEvent":
        # operationName can be an object or a string
        op_name = record.get("operationName", {})
        if isinstance(op_name, dict):
            op_name = op_name.get("value", "")

        status = record.get("status", {})
        if isinstance(status, dict):
            status = status.get("value", "")

        claims = record.get("claims", {})
        source_ip = claims.get("ipaddr", record.get("httpRequest", {}).get("clientIpAddress", ""))

        time_str = record.get("time", record.get("eventTimestamp", ""))
        try:
            event_time = datetime.fromisoformat(time_str.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            event_time = datetime.now(timezone.utc)

        return cls(
            event_time=event_time,
            operation_name=op_name,
            status=str(status),
            caller=record.get("caller", ""),
            source_ip=source_ip,
            subscription_id=record.get("subscriptionId", ""),
            resource_group=record.get("resourceGroupName", ""),
            resource_id=record.get("resourceId", ""),
            tenant_id=record.get("tenantId", ""),
            correlation_id=record.get("correlationId", ""),
            level=record.get("level", ""),
            properties=record.get("properties", {}) or {},
            raw=record,
        )


@dataclass
class RiskEvent:
    """Detected risk event"""
    event: ActivityLogEvent
    rule: RiskRule

    def to_csv_row(self) -> list[str]:
        return [
            self.event.event_time.strftime("%Y-%m-%d %H:%M:%S UTC"),
            self.rule.rule_id,
            self.rule.severity,
            self.rule.category,
            self.rule.name,
            self.event.operation_name,
            self.event.status,
            self.event.caller,
            self.event.source_ip,
            self.event.resource_group,
            self.event.subscription_id,
        ]

    def to_markdown_row(self) -> str:
        ts = self.event.event_time.strftime("%Y-%m-%d %H:%M:%S")
        sev_badge = {
            "CRITICAL": "**CRITICAL**",
            "HIGH":     "HIGH",
            "MEDIUM":   "MEDIUM",
            "LOW":      "LOW",
        }.get(self.rule.severity, self.rule.severity)
        return (
            f"| {ts} "
            f"| {self.rule.rule_id} "
            f"| {sev_badge} "
            f"| {self.rule.name} "
            f"| {self.event.caller} "
            f"| {self.event.source_ip} "
            f"| {self.event.resource_group} |"
        )


# ── Core Functions ────────────────────────────────────────────────────────────

def parse_activity_log(path: Path) -> list[ActivityLogEvent]:
    """Parse Azure Activity Log JSON file (array or single object)"""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[ERROR] JSON parsing failed: {exc}", file=sys.stderr)
        sys.exit(1)

    records: list[dict] = []
    if isinstance(raw, list):
        records = raw
    elif isinstance(raw, dict):
        # Azure Monitor Export format: {"value": [...]}
        records = raw.get("value", [raw])

    events: list[ActivityLogEvent] = []
    for rec in records:
        try:
            events.append(ActivityLogEvent.from_dict(rec))
        except Exception as exc:
            print(f"[WARN] Skipping record: {exc}", file=sys.stderr)
    return events


def filter_events(
    events: list[ActivityLogEvent],
    subscription_id: str | None,
    operation_filter: list[str] | None,
) -> list[ActivityLogEvent]:
    """Apply subscription ID and operation name filters"""
    result = events
    if subscription_id:
        result = [e for e in result if subscription_id in e.subscription_id]
    if operation_filter:
        of_lower = [f.lower() for f in operation_filter]
        result = [
            e for e in result
            if any(pat in e.operation_name.lower() for pat in of_lower)
        ]
    return result


def classify_risks(events: list[ActivityLogEvent]) -> list[RiskEvent]:
    """Apply risk operation classification rules"""
    risk_events: list[RiskEvent] = []
    for event in events:
        op_lower = event.operation_name.lower()
        for rule in RISK_RULES:
            if any(pat.lower() in op_lower for pat in rule.operation_patterns):
                risk_events.append(RiskEvent(event=event, rule=rule))
                break  # Apply only the first matching rule
    risk_events.sort(key=lambda r: (
        {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(r.rule.severity, 9),
        r.event.event_time,
    ))
    return risk_events


def write_csv(risk_events: list[RiskEvent], output_path: Path) -> None:
    """Write CSV file output"""
    headers = [
        "EventTime(UTC)", "RuleID", "Severity", "Category", "RuleName",
        "OperationName", "Status", "Caller", "SourceIP", "ResourceGroup", "SubscriptionID",
    ]
    try:
        with output_path.open("w", newline="", encoding="utf-8-sig") as fh:
            writer = csv.writer(fh)
            writer.writerow(headers)
            for re_ in risk_events:
                writer.writerow(re_.to_csv_row())
        print(f"[DONE] CSV saved: {output_path} ({len(risk_events)} events)")
    except OSError as exc:
        print(f"[ERROR] CSV save failed: {exc}", file=sys.stderr)


def write_markdown(
    risk_events: list[RiskEvent],
    all_events: list[ActivityLogEvent],
    output_path: Path,
) -> None:
    """Write Markdown report"""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines: list[str] = []

    lines.append("# Azure Activity Log Risk Operation Analysis Report")
    lines.append(f"\n> Generated: {now}\n")

    # Summary statistics
    sev_counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for re_ in risk_events:
        sev_counts[re_.rule.severity] = sev_counts.get(re_.rule.severity, 0) + 1

    lines.append("## Summary")
    lines.append(f"\n| Item | Count |")
    lines.append(f"|------|-------|")
    lines.append(f"| Total Events | {len(all_events):,} |")
    lines.append(f"| Risk Events | {len(risk_events):,} |")
    for sev, cnt in sev_counts.items():
        lines.append(f"| {sev} | {cnt:,} |")
    lines.append("")

    # Category aggregation
    cat_counts: dict[str, int] = {}
    for re_ in risk_events:
        cat_counts[re_.rule.category] = cat_counts.get(re_.rule.category, 0) + 1

    if cat_counts:
        lines.append("## Detections by Category")
        lines.append("\n| Category | Count |")
        lines.append("|---------|-------|")
        for cat, cnt in sorted(cat_counts.items(), key=lambda x: -x[1]):
            lines.append(f"| {cat} | {cnt} |")
        lines.append("")

    # Detected events table
    if risk_events:
        lines.append("## List of Detected Risk Operations")
        lines.append(
            "\n| Time(UTC) | RuleID | Severity | Rule Name | Caller | Source IP | Resource Group |"
        )
        lines.append(
            "|----------|--------|----------|-----------|--------|-----------|----------------|"
        )
        for re_ in risk_events:
            lines.append(re_.to_markdown_row())
        lines.append("")

    # Top callers analysis
    caller_counts: dict[str, int] = {}
    for re_ in risk_events:
        caller_counts[re_.event.caller] = caller_counts.get(re_.event.caller, 0) + 1

    if caller_counts:
        lines.append("## Top Callers")
        lines.append("\n| Caller | Risk Event Count |")
        lines.append("|--------|-----------------|")
        for caller, cnt in sorted(caller_counts.items(), key=lambda x: -x[1])[:10]:
            lines.append(f"| {caller} | {cnt} |")
        lines.append("")

    lines.append("---")
    lines.append("*This report is auto-generated and requires expert review.*")

    try:
        output_path.write_text("\n".join(lines), encoding="utf-8")
        print(f"[DONE] Markdown saved: {output_path} ({len(risk_events)} events)")
    except OSError as exc:
        print(f"[ERROR] Markdown save failed: {exc}", file=sys.stderr)


def print_console_summary(
    risk_events: list[RiskEvent],
    all_events: list[ActivityLogEvent],
) -> None:
    """Print console summary"""
    print(f"\n{'=' * 80}")
    print(f" Azure Activity Log Analysis Results")
    print(f"{'=' * 80}")
    print(f"  Total events:  {len(all_events):,}")
    print(f"  Risk events:   {len(risk_events):,}")

    for re_ in risk_events:
        sev_icon = {
            "CRITICAL": "[!!!]",
            "HIGH":     "[ ! ]",
            "MEDIUM":   "[ * ]",
            "LOW":      "[ - ]",
        }.get(re_.rule.severity, "[ ? ]")
        ts = re_.event.event_time.strftime("%Y-%m-%d %H:%M:%S")
        print(
            f"\n  {sev_icon} {ts} | {re_.rule.rule_id} {re_.rule.name}\n"
            f"         Operation: {re_.event.operation_name}\n"
            f"         Caller: {re_.event.caller} | IP: {re_.event.source_ip}\n"
            f"         RG: {re_.event.resource_group} | Status: {re_.event.status}"
        )
    print()


# ── CLI Entry Point ────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="azure_activity_log_analyzer",
        description="Azure Activity Log Analyzer — Classifies risky operations and outputs CSV+Markdown.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --input-json activity_log.json
  %(prog)s --input-json activity_log.json --subscription-id aaaa-bbbb-cccc
  %(prog)s --input-json activity_log.json --operation-filter roleAssignments
  %(prog)s --input-json activity_log.json --output-dir ./reports
        """,
    )
    parser.add_argument(
        "--input-json", "-i",
        dest="input_json",
        type=Path,
        required=True,
        help="Azure Activity Log JSON file path",
    )
    parser.add_argument(
        "--subscription-id", "-s",
        dest="subscription_id",
        default=None,
        help="Filter by specific subscription ID (partial match)",
    )
    parser.add_argument(
        "--operation-filter", "-o",
        dest="operation_filter",
        nargs="+",
        default=None,
        help="Operation name filter (space-separated, partial match)",
    )
    parser.add_argument(
        "--output-dir",
        dest="output_dir",
        type=Path,
        default=None,
        help="Directory for CSV/Markdown output (console only if not specified)",
    )
    parser.add_argument(
        "--min-severity",
        dest="min_severity",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        default="LOW",
        help="Minimum severity filter (default: LOW = all)",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if not args.input_json.exists():
        print(f"[ERROR] File not found: {args.input_json}", file=sys.stderr)
        sys.exit(1)

    print(f"[INFO] Loading file: {args.input_json}")
    events = parse_activity_log(args.input_json)
    print(f"[INFO] {len(events):,} events loaded")

    filtered = filter_events(events, args.subscription_id, args.operation_filter)
    if len(filtered) != len(events):
        print(f"[INFO] After filter: {len(filtered):,} events")

    risk_events = classify_risks(filtered)

    # Severity filter
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    min_order = sev_order.get(args.min_severity, 3)
    risk_events = [
        re_ for re_ in risk_events
        if sev_order.get(re_.rule.severity, 9) <= min_order
    ]

    print_console_summary(risk_events, filtered)

    if args.output_dir:
        args.output_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

        csv_path = args.output_dir / f"azure_risk_events_{timestamp}.csv"
        md_path = args.output_dir / f"azure_risk_report_{timestamp}.md"

        write_csv(risk_events, csv_path)
        write_markdown(risk_events, filtered, md_path)


if __name__ == "__main__":
    main()
```

### Usage

```bash
# Basic analysis (console output)
python azure_activity_log_analyzer.py --input-json activity_log.json

# Filter by specific subscription + save results
python azure_activity_log_analyzer.py \
    --input-json activity_log.json \
    --subscription-id aaaa-bbbb-cccc \
    --output-dir ./azure_reports

# Analyze only role assignment-related operations
python azure_activity_log_analyzer.py \
    --input-json activity_log.json \
    --operation-filter roleAssignments roleDefinitions

# Output CRITICAL and above only
python azure_activity_log_analyzer.py \
    --input-json activity_log.json \
    --min-severity CRITICAL \
    --output-dir ./critical_only
```

---

## 5. Additional Azure Forensics Reference

### 5.1 Entra ID (Azure AD) Forensic Log Collection

```bash
# Recent login failure history
az rest --method GET \
    --url "https://graph.microsoft.com/v1.0/auditLogs/signIns?\$filter=status/errorCode ne 0" \
    --headers "Content-Type=application/json"

# Directory audit logs (role changes)
az rest --method GET \
    --url "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?\$filter=category eq 'RoleManagement'"
```

### 5.2 Microsoft Sentinel KQL Hunting Queries

```kusto
// Impossible Travel Detection
SigninLogs
| where TimeGenerated > ago(1d)
| project UserPrincipalName, IPAddress, Location, TimeGenerated
| sort by UserPrincipalName, TimeGenerated
| extend PrevIP = prev(IPAddress, 1),
         PrevTime = prev(TimeGenerated, 1),
         PrevUser = prev(UserPrincipalName, 1)
| where UserPrincipalName == PrevUser
| where IPAddress != PrevIP
| where datetime_diff("minute", TimeGenerated, PrevTime) < 30
```
