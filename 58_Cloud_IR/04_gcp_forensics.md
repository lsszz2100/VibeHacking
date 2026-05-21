# GCP 포렌식

## 1. GCP 로그 소스

Google Cloud Platform(GCP) 환경에서 포렌식 조사에 활용할 수 있는 주요 로그 소스를 정리한다. GCP는 Cloud Logging을 중심으로 모든 로그를 통합 관리하며, BigQuery와 연동하여 대용량 로그 분석이 가능하다.

| 로그 소스 | 로그 유형 | 기본 활성화 | 보존 기간 | 주요 포렌식 용도 |
|----------|---------|-----------|---------|-------------|
| Cloud Audit Log - Admin Activity | 관리 작업 로그 | 예 | 400일 | IAM 변경, 리소스 조작 |
| Cloud Audit Log - Data Access | 데이터 접근 로그 | 아니오 | 30일 | GCS/BigQuery 접근 추적 |
| Cloud Audit Log - System Event | 시스템 이벤트 | 예 | 400일 | GCP 내부 자동화 이벤트 |
| Cloud Audit Log - Policy Denied | 정책 거부 이벤트 | 예 | 30일 | 비인가 접근 시도 |
| VPC Flow Logs | 네트워크 플로우 | 아니오 | 30일(기본) | 횡이동, C2 통신 |
| Firewall Rules Logging | 방화벽 허용/거부 | 아니오 | 30일 | 네트워크 접근 패턴 |
| Cloud IDS | 침입 탐지 이벤트 | 아니오 | - | 네트워크 레벨 공격 탐지 |
| GKE Audit Log | Kubernetes 감사 | 예(GKE) | 400일 | 컨테이너 환경 조사 |
| Cloud DNS Log | DNS 쿼리 | 아니오 | 30일 | C2 도메인 접근 |
| Cloud Storage Access Log | GCS 객체 접근 | 아니오 | Data Access 활성화 | 데이터 유출 추적 |
| BigQuery Audit Log | BQ 쿼리/접근 | Data Access 설정 | 30일 | 대용량 데이터 조회 추적 |
| Secret Manager Audit | 시크릿 접근 | Data Access 설정 | 30일 | 자격증명 접근 탐지 |

### 1.1 Cloud Audit Log JSON Lines 형식

GCP 로그는 Cloud Logging API 또는 Cloud Storage 내보내기를 통해 JSON Lines(.jsonl) 형식으로 수집할 수 있다.

```json
{
    "logName": "projects/my-project/logs/cloudaudit.googleapis.com%2Factivity",
    "timestamp": "2024-01-15T09:23:11.456Z",
    "severity": "NOTICE",
    "resource": {
        "type": "service_account",
        "labels": {"project_id": "my-project", "unique_id": "1234567890"}
    },
    "protoPayload": {
        "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
        "serviceName": "iam.googleapis.com",
        "methodName": "google.iam.admin.v1.CreateServiceAccountKey",
        "authenticationInfo": {
            "principalEmail": "attacker@my-project.iam.gserviceaccount.com"
        },
        "requestMetadata": {
            "callerIp": "203.0.113.42",
            "callerSuppliedUserAgent": "python-requests/2.28.0"
        },
        "resourceName": "projects/my-project/serviceAccounts/target-sa@my-project.iam.gserviceaccount.com",
        "status": {}
    },
    "insertId": "unique-log-entry-id"
}
```

---

## 2. GCP IAM 권한 분석

GCP의 IAM은 AWS와 다른 계층 구조를 가진다. 조직(Organization) > 폴더(Folder) > 프로젝트(Project) > 리소스 순서로 권한이 상속되며, 상위 레벨의 권한이 하위 레벨에 모두 적용된다.

### 2.1 GCP IAM 에스컬레이션 패턴

| 에스컬레이션 기법 | 필요 초기 권한 | 획득 가능 권한 | 탐지 이벤트 |
|---------------|------------|------------|-----------|
| 서비스 계정 키 생성 | iam.serviceAccountKeys.create | 서비스 계정 권한 | CreateServiceAccountKey |
| 서비스 계정 토큰 생성 | iam.serviceAccounts.actAs | 대상 SA 권한 | GenerateAccessToken |
| IAM 바인딩 추가 | resourcemanager.projects.setIamPolicy | 임의 역할 부여 | SetIamPolicy |
| 조직 정책 수정 | orgpolicy.policy.set | 제약 해제 | SetOrgPolicy |
| 워크로드 ID 연동 | iam.workloadIdentityPoolProviders.create | 외부 ID로 GCP 접근 | CreateWorkloadIdentityPoolProvider |
| 커스텀 역할 생성 | iam.roles.create | 임의 권한 조합 | CreateRole |
| Cloud Functions 배포 | cloudfunctions.functions.create + actAs | 함수 실행 SA 권한 | CreateFunction |
| Cloud Build 악용 | cloudbuild.builds.create + actAs | Cloud Build SA 권한 | CreateBuild |

### 2.2 서비스 계정 분석 명령어

```bash
# 프로젝트 내 모든 서비스 계정 목록
gcloud iam service-accounts list --project=my-project

# 특정 서비스 계정의 키 목록 (오래된 키 탐지)
gcloud iam service-accounts keys list \
    --iam-account=sa@my-project.iam.gserviceaccount.com \
    --managed-by=user

# 서비스 계정에 부여된 역할 확인
gcloud projects get-iam-policy my-project \
    --flatten="bindings[].members" \
    --format="table(bindings.role, bindings.members)" \
    --filter="bindings.members:serviceAccount:target-sa@*"

# 조직 레벨 IAM 정책 분석
gcloud organizations get-iam-policy ORGANIZATION_ID \
    --format=json | jq '.bindings[] | select(.role | contains("admin"))'
```

---

## 3. BigQuery 데이터 유출 탐지

BigQuery는 대규모 데이터를 저장하는 경우가 많아 데이터 유출의 주요 대상이 된다. Data Access 감사 로그를 활성화하면 모든 쿼리와 데이터 접근을 추적할 수 있다.

### 3.1 BigQuery 데이터 유출 패턴

| 유출 기법 | 설명 | 탐지 지표 |
|---------|------|---------|
| SELECT * 대량 쿼리 | 전체 테이블 스캔 | 비정상적으로 큰 scannedBytes |
| 외부 테이블 export | BQ 데이터를 GCS로 내보내기 | EXPORT DATA 쿼리 실행 |
| 데이터셋 복사 | 다른 프로젝트로 데이터셋 복사 | DatasetService.CopyDataset |
| 공개 데이터셋 설정 | IAM을 allUsers로 변경 | SetIamPolicy (allUsers) |
| BQ Storage API | 고속 병렬 읽기 | bigquerystorage.ReadRows |

### 3.2 BigQuery 유출 탐지 쿼리 (Cloud Logging)

```bash
# 대용량 쿼리 탐지 (1GB 이상 스캔)
gcloud logging read \
    'protoPayload.serviceName="bigquery.googleapis.com"
     AND protoPayload.methodName="jobservice.jobcompleted"
     AND protoPayload.serviceData.jobCompletedEvent.job.jobStatistics.totalBilledBytes > 1073741824' \
    --project=my-project \
    --format=json \
    --freshness=7d
```

---

## 4. Python CLI: GCP Cloud Audit Log 파서

```python
#!/usr/bin/env python3
"""
GCP Cloud Audit Log 파서
- JSON Lines 형식의 GCP Cloud Audit Log를 파싱하여 서비스 계정 이상 행동을 탐지한다.
- 심각도별 집계 리포트를 생성한다.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# ── 탐지 규칙 ─────────────────────────────────────────────────────────────────

@dataclass
class GCPDetectionRule:
    """GCP 탐지 규칙"""
    rule_id: str
    name: str
    method_patterns: list[str]     # protoPayload.methodName 패턴
    service_patterns: list[str]    # protoPayload.serviceName 패턴 (빈 목록 = 모든 서비스)
    severity: str                   # CRITICAL / HIGH / MEDIUM / LOW
    category: str
    description: str
    sa_only: bool = False           # True면 서비스 계정 호출에만 적용


GCP_RULES: list[GCPDetectionRule] = [
    GCPDetectionRule(
        rule_id="GCP-001",
        name="서비스 계정 키 생성",
        method_patterns=["CreateServiceAccountKey"],
        service_patterns=["iam.googleapis.com"],
        severity="HIGH",
        category="credential_access",
        description="서비스 계정 외부 키 생성. 장기 자격증명 탈취 가능성.",
    ),
    GCPDetectionRule(
        rule_id="GCP-002",
        name="IAM 정책 직접 변경",
        method_patterns=["SetIamPolicy"],
        service_patterns=[],
        severity="HIGH",
        category="privilege_escalation",
        description="IAM 정책 직접 수정. 권한 에스컬레이션 가능성.",
    ),
    GCPDetectionRule(
        rule_id="GCP-003",
        name="조직 정책 수정",
        method_patterns=["SetOrgPolicy", "CreateOrgPolicy", "DeleteOrgPolicy"],
        service_patterns=["cloudresourcemanager.googleapis.com"],
        severity="CRITICAL",
        category="defense_evasion",
        description="조직 레벨 제약 정책 수정. 보안 제어 우회 가능성.",
    ),
    GCPDetectionRule(
        rule_id="GCP-004",
        name="Cloud Logging 수집기 삭제",
        method_patterns=["DeleteSink", "UpdateSink"],
        service_patterns=["logging.googleapis.com"],
        severity="CRITICAL",
        category="defense_evasion",
        description="로그 내보내기 수집기 삭제/수정. 증거 인멸 시도.",
    ),
    GCPDetectionRule(
        rule_id="GCP-005",
        name="커스텀 IAM 역할 생성/수정",
        method_patterns=["CreateRole", "UpdateRole"],
        service_patterns=["iam.googleapis.com"],
        severity="HIGH",
        category="privilege_escalation",
        description="커스텀 IAM 역할 생성 또는 수정.",
    ),
    GCPDetectionRule(
        rule_id="GCP-006",
        name="Cloud Function 생성/배포",
        method_patterns=["CreateFunction", "UpdateFunction"],
        service_patterns=["cloudfunctions.googleapis.com"],
        severity="MEDIUM",
        category="execution",
        description="Cloud Function 생성/수정. 악성 코드 실행 가능성.",
    ),
    GCPDetectionRule(
        rule_id="GCP-007",
        name="GCS 버킷 IAM 공개 설정",
        method_patterns=["SetIamPolicy"],
        service_patterns=["storage.googleapis.com"],
        severity="HIGH",
        category="exfiltration",
        description="GCS 버킷 IAM 정책 변경. allUsers 공개 설정 가능성.",
    ),
    GCPDetectionRule(
        rule_id="GCP-008",
        name="서비스 계정 역할 사칭",
        method_patterns=["GenerateAccessToken", "SignBlob", "SignJwt"],
        service_patterns=["iamcredentials.googleapis.com"],
        severity="HIGH",
        category="privilege_escalation",
        description="서비스 계정 토큰 생성 또는 서명. 권한 상승 가능성.",
        sa_only=True,
    ),
    GCPDetectionRule(
        rule_id="GCP-009",
        name="워크로드 ID 연동 풀 생성",
        method_patterns=["CreateWorkloadIdentityPool", "CreateWorkloadIdentityPoolProvider"],
        service_patterns=["iam.googleapis.com"],
        severity="HIGH",
        category="persistence",
        description="외부 ID 제공자 연동 설정. 외부 공격자 지속성 확보 가능.",
    ),
    GCPDetectionRule(
        rule_id="GCP-010",
        name="Secret Manager 시크릿 접근",
        method_patterns=["AccessSecretVersion"],
        service_patterns=["secretmanager.googleapis.com"],
        severity="HIGH",
        category="credential_access",
        description="시크릿 버전 접근. 자격증명 탈취 가능성.",
    ),
    GCPDetectionRule(
        rule_id="GCP-011",
        name="Compute 인스턴스 삭제",
        method_patterns=["delete", "v1.compute.instances.delete"],
        service_patterns=["compute.googleapis.com"],
        severity="HIGH",
        category="impact",
        description="VM 인스턴스 삭제. 서비스 파괴 또는 증거 인멸.",
    ),
    GCPDetectionRule(
        rule_id="GCP-012",
        name="BigQuery 대용량 Export",
        method_patterns=["jobservice.jobcompleted"],
        service_patterns=["bigquery.googleapis.com"],
        severity="MEDIUM",
        category="exfiltration",
        description="BigQuery 작업 완료. 대용량 EXPORT DATA 쿼리 확인 필요.",
    ),
    GCPDetectionRule(
        rule_id="GCP-013",
        name="GKE 클러스터 자격증명 조회",
        method_patterns=["GetCluster"],
        service_patterns=["container.googleapis.com"],
        severity="MEDIUM",
        category="credential_access",
        description="GKE 클러스터 정보 조회. kubeconfig 획득 가능성.",
    ),
    GCPDetectionRule(
        rule_id="GCP-014",
        name="Cloud Build 빌드 생성",
        method_patterns=["CreateBuild"],
        service_patterns=["cloudbuild.googleapis.com"],
        severity="MEDIUM",
        category="execution",
        description="Cloud Build 실행. CI/CD 파이프라인 악용 가능성.",
    ),
]

# 메서드명 → 규칙 인덱스
_METHOD_INDEX: dict[str, list[GCPDetectionRule]] = defaultdict(list)
for _rule in GCP_RULES:
    for _method in _rule.method_patterns:
        _METHOD_INDEX[_method.lower()].append(_rule)


# ── 데이터 구조 ───────────────────────────────────────────────────────────────

@dataclass
class GCPAuditEvent:
    """파싱된 GCP Cloud Audit Log 이벤트"""
    timestamp: datetime
    log_name: str
    severity: str
    service_name: str
    method_name: str
    principal_email: str
    caller_ip: str
    caller_user_agent: str
    resource_name: str
    resource_type: str
    project_id: str
    status_code: int               # 0 = 성공
    status_message: str
    request_metadata: dict[str, Any]
    raw: dict[str, Any]

    @classmethod
    def from_dict(cls, record: dict[str, Any]) -> "GCPAuditEvent":
        proto = record.get("protoPayload", {})
        req_meta = proto.get("requestMetadata", {})
        resource = record.get("resource", {})
        labels = resource.get("labels", {})

        status = proto.get("status", {})
        status_code = status.get("code", 0) if isinstance(status, dict) else 0
        status_message = status.get("message", "") if isinstance(status, dict) else str(status)

        auth_info = proto.get("authenticationInfo", {})
        principal = auth_info.get("principalEmail", "")

        ts_str = record.get("timestamp", record.get("receiveTimestamp", ""))
        try:
            timestamp = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            timestamp = datetime.now(timezone.utc)

        project_id = (
            labels.get("project_id", "")
            or record.get("logName", "").split("/")[1]
            if "projects/" in record.get("logName", "")
            else ""
        )

        return cls(
            timestamp=timestamp,
            log_name=record.get("logName", ""),
            severity=record.get("severity", ""),
            service_name=proto.get("serviceName", ""),
            method_name=proto.get("methodName", ""),
            principal_email=principal,
            caller_ip=req_meta.get("callerIp", ""),
            caller_user_agent=req_meta.get("callerSuppliedUserAgent", ""),
            resource_name=proto.get("resourceName", ""),
            resource_type=resource.get("type", ""),
            project_id=project_id,
            status_code=status_code,
            status_message=status_message,
            request_metadata=req_meta,
            raw=record,
        )

    @property
    def is_service_account(self) -> bool:
        return self.principal_email.endswith(".gserviceaccount.com")

    @property
    def is_success(self) -> bool:
        return self.status_code == 0

    @property
    def short_method(self) -> str:
        """메서드명의 마지막 부분 (점 구분자 기준)"""
        return self.method_name.split(".")[-1] if self.method_name else ""


@dataclass
class GCPDetectionHit:
    """GCP 탐지 결과"""
    event: GCPAuditEvent
    rule: GCPDetectionRule

    def to_report_line(self) -> str:
        sev_icon = {
            "CRITICAL": "[!!!]",
            "HIGH":     "[ ! ]",
            "MEDIUM":   "[ * ]",
            "LOW":      "[ - ]",
        }.get(self.rule.severity, "[ ? ]")
        ts = self.event.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
        sa_flag = " [SA]" if self.event.is_service_account else ""
        err_flag = f" [오류 {self.event.status_code}]" if not self.event.is_success else ""
        return (
            f"{ts} {sev_icon} [{self.rule.rule_id}] {self.rule.name}\n"
            f"  메서드: {self.event.method_name}\n"
            f"  주체: {self.event.principal_email}{sa_flag} | IP: {self.event.caller_ip}{err_flag}\n"
            f"  리소스: {self.event.resource_name}\n"
            f"  설명: {self.rule.description}"
        )


# ── 통계 집계 ─────────────────────────────────────────────────────────────────

@dataclass
class AuditLogStats:
    """감사 로그 통계"""
    total_events: int = 0
    by_severity: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    by_service: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    by_principal: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    by_method: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    sa_events: int = 0
    error_events: int = 0
    detection_hits: int = 0

    def add_event(self, event: GCPAuditEvent) -> None:
        self.total_events += 1
        self.by_severity[event.severity] += 1
        self.by_service[event.service_name] += 1
        self.by_principal[event.principal_email] += 1
        self.by_method[event.short_method] += 1
        if event.is_service_account:
            self.sa_events += 1
        if not event.is_success:
            self.error_events += 1

    def print_report(self, hits: list[GCPDetectionHit]) -> None:
        print(f"\n{'=' * 80}")
        print(f" GCP Cloud Audit Log 분석 리포트")
        print(f"{'=' * 80}")
        print(f"\n  전체 이벤트:       {self.total_events:,}")
        print(f"  서비스 계정 이벤트: {self.sa_events:,}")
        print(f"  오류 이벤트:        {self.error_events:,}")
        print(f"  탐지 이벤트:        {len(hits):,}")

        print(f"\n  심각도별 GCP 로그 레벨:")
        for sev, cnt in sorted(self.by_severity.items(), key=lambda x: -x[1]):
            print(f"    {sev:15s}: {cnt:,}")

        print(f"\n  상위 서비스 (Top 8):")
        for svc, cnt in sorted(self.by_service.items(), key=lambda x: -x[1])[:8]:
            print(f"    {svc:50s}: {cnt:,}")

        print(f"\n  상위 주체 (Top 8):")
        for principal, cnt in sorted(self.by_principal.items(), key=lambda x: -x[1])[:8]:
            sa_tag = " [SA]" if principal.endswith(".gserviceaccount.com") else ""
            print(f"    {principal:60s}: {cnt:,}{sa_tag}")

        print(f"\n  상위 메서드 (Top 10):")
        for method, cnt in sorted(self.by_method.items(), key=lambda x: -x[1])[:10]:
            print(f"    {method:50s}: {cnt:,}")

        # 탐지 결과 심각도별 집계
        if hits:
            print(f"\n  탐지 결과 심각도별:")
            hit_sev: dict[str, int] = defaultdict(int)
            for hit in hits:
                hit_sev[hit.rule.severity] += 1
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                if hit_sev[sev]:
                    print(f"    {sev:10s}: {hit_sev[sev]:,}건")
        print()


# ── 핵심 기능 ─────────────────────────────────────────────────────────────────

def parse_jsonl_file(path: Path) -> list[GCPAuditEvent]:
    """JSON Lines 형식 GCP 로그 파일 파싱"""
    events: list[GCPAuditEvent] = []
    try:
        content = path.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"[오류] 파일 읽기 실패: {exc}", file=sys.stderr)
        sys.exit(1)

    for line_no, line in enumerate(content.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
            events.append(GCPAuditEvent.from_dict(record))
        except json.JSONDecodeError as exc:
            print(f"[경고] {line_no}번째 줄 파싱 실패: {exc}", file=sys.stderr)
        except Exception as exc:
            print(f"[경고] {line_no}번째 줄 처리 오류: {exc}", file=sys.stderr)
    return events


def parse_json_array_file(path: Path) -> list[GCPAuditEvent]:
    """JSON 배열 형식 파일 파싱 (Cloud Logging Export 등)"""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[오류] JSON 파싱 실패: {exc}", file=sys.stderr)
        sys.exit(1)

    records = raw if isinstance(raw, list) else raw.get("entries", [raw])
    events: list[GCPAuditEvent] = []
    for rec in records:
        try:
            events.append(GCPAuditEvent.from_dict(rec))
        except Exception as exc:
            print(f"[경고] 레코드 처리 오류: {exc}", file=sys.stderr)
    return events


def load_log_file(path: Path) -> list[GCPAuditEvent]:
    """파일 형식 자동 감지 후 파싱"""
    content_start = path.read_bytes()[:2]
    if content_start == b"[{" or content_start == b"{\n"[:2]:
        # JSON 배열 또는 단일 JSON 객체 → 먼저 JSON Lines 시도
        pass

    # JSON Lines 우선 시도
    events = parse_jsonl_file(path)
    if not events:
        print("[정보] JSON Lines 파싱 실패, JSON 배열 형식으로 재시도...")
        events = parse_json_array_file(path)
    return events


def filter_events(
    events: list[GCPAuditEvent],
    project_id: str | None,
    severity_filter: list[str] | None,
) -> list[GCPAuditEvent]:
    """프로젝트 ID, GCP 심각도 필터 적용"""
    result = events
    if project_id:
        result = [
            e for e in result
            if project_id in e.project_id or project_id in e.log_name
        ]
    if severity_filter:
        sf_upper = [s.upper() for s in severity_filter]
        result = [e for e in result if e.severity.upper() in sf_upper]
    return result


def detect_anomalies(events: list[GCPAuditEvent]) -> list[GCPDetectionHit]:
    """이상 행동 탐지 규칙 적용"""
    hits: list[GCPDetectionHit] = []
    for event in events:
        method_lower = event.method_name.lower()
        short_method_lower = event.short_method.lower()
        service_lower = event.service_name.lower()

        for rule in GCP_RULES:
            # SA 전용 규칙 검증
            if rule.sa_only and not event.is_service_account:
                continue

            # 서비스 패턴 검증
            if rule.service_patterns:
                if not any(sp.lower() in service_lower for sp in rule.service_patterns):
                    continue

            # 메서드 패턴 매칭
            method_matched = False
            for pattern in rule.method_patterns:
                pat_lower = pattern.lower()
                if pat_lower in method_lower or pat_lower in short_method_lower:
                    method_matched = True
                    break

            if method_matched:
                hits.append(GCPDetectionHit(event=event, rule=rule))
                break

    hits.sort(key=lambda h: (
        {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(h.rule.severity, 9),
        h.event.timestamp,
    ))
    return hits


def detect_sa_anomalies(events: list[GCPAuditEvent]) -> None:
    """서비스 계정 이상 행동 별도 분석"""
    sa_events = [e for e in events if e.is_service_account]
    if not sa_events:
        return

    print(f"\n{'=' * 80}")
    print(f" 서비스 계정 이상 행동 분석 (총 {len(sa_events)}건)")
    print(f"{'=' * 80}")

    # SA별 활동 집계
    sa_activity: dict[str, list[GCPAuditEvent]] = defaultdict(list)
    for e in sa_events:
        sa_activity[e.principal_email].append(e)

    # SA별 고유 IP 수 (다수 IP = 키 유출 가능성)
    print(f"\n  서비스 계정별 소스 IP 다양성:")
    for sa, evts in sorted(sa_activity.items()):
        unique_ips = {e.caller_ip for e in evts if e.caller_ip}
        unique_methods = {e.short_method for e in evts}
        if len(unique_ips) > 1:
            print(
                f"    {sa}\n"
                f"      이벤트: {len(evts)}건 | 고유 IP: {len(unique_ips)}개 | "
                f"메서드: {len(unique_methods)}종\n"
                f"      IP 목록: {', '.join(sorted(unique_ips))}"
            )
    print()


# ── CLI 진입점 ────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gcp_audit_parser",
        description="GCP Cloud Audit Log 파서 — JSON Lines 로그를 파싱하고 이상 행동을 탐지한다.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
사용 예:
  %(prog)s --log-file audit.jsonl
  %(prog)s --log-file audit.jsonl --project-id my-project
  %(prog)s --log-file audit.jsonl --severity-filter NOTICE WARNING ERROR
  %(prog)s --log-file audit.jsonl --no-sa-analysis
        """,
    )
    parser.add_argument(
        "--log-file", "-f",
        dest="log_file",
        type=Path,
        required=True,
        help="GCP Cloud Audit Log 파일 경로 (.jsonl 또는 .json)",
    )
    parser.add_argument(
        "--project-id", "-p",
        dest="project_id",
        default=None,
        help="특정 프로젝트 ID 필터",
    )
    parser.add_argument(
        "--severity-filter", "-s",
        dest="severity_filter",
        nargs="+",
        default=None,
        help="GCP 로그 심각도 필터 (예: NOTICE WARNING ERROR CRITICAL)",
    )
    parser.add_argument(
        "--no-sa-analysis",
        action="store_true",
        help="서비스 계정 이상 행동 분석 건너뜀",
    )
    parser.add_argument(
        "--min-detection-severity",
        dest="min_detection_severity",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        default="LOW",
        help="탐지 결과 최소 심각도 필터 (기본: LOW = 전체)",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if not args.log_file.exists():
        print(f"[오류] 파일 없음: {args.log_file}", file=sys.stderr)
        sys.exit(1)

    print(f"[정보] 로그 파일 로드: {args.log_file}")
    events = load_log_file(args.log_file)

    if not events:
        print("[오류] 파싱된 이벤트가 없습니다.", file=sys.stderr)
        sys.exit(1)

    print(f"[정보] {len(events):,}개 이벤트 로드 완료")

    filtered = filter_events(events, args.project_id, args.severity_filter)
    if len(filtered) != len(events):
        print(f"[정보] 필터 후: {len(filtered):,}개 이벤트")

    # 통계 집계
    stats = AuditLogStats()
    for event in filtered:
        stats.add_event(event)

    # 탐지 실행
    hits = detect_anomalies(filtered)

    # 탐지 심각도 필터
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    min_order = sev_order.get(args.min_detection_severity, 3)
    hits = [
        h for h in hits
        if sev_order.get(h.rule.severity, 9) <= min_order
    ]

    # 탐지 결과 출력
    if hits:
        print(f"\n{'=' * 80}")
        print(f" 탐지된 이상 행동 (총 {len(hits)}건)")
        print(f"{'=' * 80}\n")
        for hit in hits:
            print(hit.to_report_line())
            print()

    # 서비스 계정 분석
    if not args.no_sa_analysis:
        detect_sa_anomalies(filtered)

    # 통계 리포트
    stats.print_report(hits)


if __name__ == "__main__":
    main()
```

### 사용 방법

```bash
# 기본 분석
python gcp_audit_parser.py --log-file audit.jsonl

# 특정 프로젝트 필터
python gcp_audit_parser.py --log-file audit.jsonl --project-id my-prod-project

# WARNING 이상 GCP 심각도만
python gcp_audit_parser.py --log-file audit.jsonl --severity-filter WARNING ERROR CRITICAL

# 탐지 결과 HIGH 이상만
python gcp_audit_parser.py --log-file audit.jsonl --min-detection-severity HIGH

# SA 분석 건너뜀
python gcp_audit_parser.py --log-file audit.jsonl --no-sa-analysis
```

---

## 5. GCP 증거 수집 추가 참고사항

### 5.1 Cloud Storage를 이용한 로그 수집

```bash
# 최근 7일 Admin Activity 로그 내보내기
gcloud logging read \
    'logName="projects/my-project/logs/cloudaudit.googleapis.com%2Factivity"' \
    --project=my-project \
    --format=json \
    --freshness=7d > admin_activity_7d.json

# 특정 서비스 계정 관련 이벤트만 수집
gcloud logging read \
    'protoPayload.authenticationInfo.principalEmail="suspect-sa@my-project.iam.gserviceaccount.com"' \
    --project=my-project \
    --format=json > sa_activity.json
```

### 5.2 BigQuery를 활용한 대용량 로그 분석

```sql
-- 최근 30일 SetIamPolicy 이벤트 분석
SELECT
    timestamp,
    protopayload_auditlog.authenticationinfo.principalemail AS caller,
    protopayload_auditlog.requestmetadata.callerip AS source_ip,
    protopayload_auditlog.resourcename AS resource,
    protopayload_auditlog.methodname AS method
FROM
    `my-project.my_dataset.cloudaudit_googleapis_com_activity_*`
WHERE
    _TABLE_SUFFIX BETWEEN FORMAT_DATE('%Y%m%d', DATE_SUB(CURRENT_DATE(), INTERVAL 30 DAY))
        AND FORMAT_DATE('%Y%m%d', CURRENT_DATE())
    AND protopayload_auditlog.methodname LIKE '%SetIamPolicy%'
ORDER BY timestamp DESC
LIMIT 1000;
```
