> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# AWS 포렌식

## 1. AWS 주요 로그 소스

AWS 환경에서 포렌식 조사를 수행할 때 가장 중요한 로그 소스는 다음과 같다. 각 서비스는 다른 레이어의 활동을 기록하므로, 사고 유형에 따라 적절한 로그를 조합해야 완전한 타임라인을 구성할 수 있다.

| 로그 소스 | 기록 내용 | 기본 활성화 | 보존 기간 | 주요 포렌식 용도 |
|----------|---------|-----------|---------|--------------|
| CloudTrail | API 호출 (관리 이벤트) | 예 (Event History 90일) | S3 설정 시 무제한 | IAM 변경, 리소스 조작 추적 |
| CloudTrail Data Events | S3/Lambda 데이터 레벨 | 아니오 (별도 설정) | Trail 설정에 따름 | S3 객체 접근, Lambda 실행 추적 |
| VPC Flow Logs | 네트워크 플로우 메타데이터 | 아니오 | CloudWatch/S3 | 횡이동, C2 통신 탐지 |
| S3 Server Access Log | S3 버킷 HTTP 요청 | 아니오 | S3 보관 시 무제한 | 데이터 유출 경로 추적 |
| ELB Access Log | 로드밸런서 요청 | 아니오 | S3 보관 | 웹 공격 경로 분석 |
| CloudFront Log | CDN 요청 로그 | 아니오 | S3 보관 | 공격자 IP 추적 |
| GuardDuty Findings | AI 기반 위협 탐지 결과 | 아니오 (활성화 필요) | 90일 | 즉시 위협 알림 |
| AWS Config | 리소스 구성 변경 이력 | 아니오 | S3 보관 | 설정 변경 타임라인 |
| Route53 Resolver Query Log | DNS 쿼리 기록 | 아니오 | CloudWatch/S3 | C2 도메인 접근 탐지 |
| SSM Session Manager Log | 원격 세션 활동 | 선택적 | S3/CloudWatch | 명령 실행 이력 |
| WAF Log | 웹 방화벽 탐지/차단 로그 | 아니오 | S3/CloudWatch | 웹 공격 패턴 분석 |
| Macie Findings | 민감 데이터 탐지 결과 | 아니오 | 90일 | 개인정보 유출 식별 |

### 1.1 CloudTrail 이벤트 구조

```json
{
    "eventVersion": "1.08",
    "userIdentity": {
        "type": "IAMUser",
        "principalId": "AIDAXXXXXXXXXXXXXXXXX",
        "arn": "arn:aws:iam::123456789012:user/attacker",
        "accountId": "123456789012",
        "userName": "attacker"
    },
    "eventTime": "2024-01-15T09:23:11Z",
    "eventSource": "iam.amazonaws.com",
    "eventName": "CreateAccessKey",
    "awsRegion": "us-east-1",
    "sourceIPAddress": "203.0.113.42",
    "userAgent": "aws-cli/2.x Python/3.x",
    "requestParameters": {"userName": "backdoor-user"},
    "responseElements": {"accessKey": {"accessKeyId": "AKIAXXXXXXXXXX"}},
    "errorCode": null,
    "errorMessage": null
}
```

---

## 2. IAM 권한 에스컬레이션 패턴

IAM 권한 에스컬레이션은 AWS 침해 사고에서 가장 자주 관찰되는 공격 기법이다. 공격자는 초기 접근 후 낮은 권한에서 시작해 관리자 권한까지 에스컬레이션을 시도한다.

| 에스컬레이션 기법 | 필요 초기 권한 | 획득 권한 | 탐지 이벤트 |
|---------------|------------|---------|-----------|
| AttachUserPolicy | iam:AttachUserPolicy | 임의 정책 연결 | AttachUserPolicy |
| CreatePolicyVersion | iam:CreatePolicyVersion | 기존 정책 수정 | CreatePolicyVersion |
| SetDefaultPolicyVersion | iam:SetDefaultPolicyVersion | 이전 버전으로 롤백 | SetDefaultPolicyVersion |
| CreateAccessKey | iam:CreateAccessKey | 타 사용자 키 생성 | CreateAccessKey |
| CreateLoginProfile | iam:CreateLoginProfile | 콘솔 접근 추가 | CreateLoginProfile |
| UpdateLoginProfile | iam:UpdateLoginProfile | 타 사용자 비밀번호 변경 | UpdateLoginProfile |
| AssumeRole (OIDC) | sts:AssumeRoleWithWebIdentity | 역할 권한 획득 | AssumeRoleWithWebIdentity |
| PassRole + Lambda | iam:PassRole, lambda:* | Lambda 실행 역할 권한 | CreateFunction, InvokeFunction |
| PassRole + EC2 | iam:PassRole, ec2:RunInstances | 인스턴스 프로파일 권한 | RunInstances |
| UpdateAssumeRolePolicy | iam:UpdateAssumeRolePolicy | 역할 신뢰 정책 수정 | UpdateAssumeRolePolicy |

### 2.1 에스컬레이션 탐지를 위한 핵심 쿼리 패턴

```
탐지 대상 API 이벤트:
- iam:CreateUser + iam:AttachUserPolicy (백도어 계정 생성)
- iam:CreateAccessKey (타 계정 키 발급)
- sts:AssumeRole (역할 가정, 특히 교차 계정)
- iam:PutUserPolicy / iam:PutRolePolicy (인라인 정책 추가)
- iam:AddUserToGroup (권한 있는 그룹 추가)
```

---

## 3. EC2 메모리 덤프 절차

EC2 인스턴스에서 메모리를 덤프하는 것은 온프레미스보다 복잡하다. 하이퍼바이저에 직접 접근할 수 없으므로 운영체제 내부에서 수행하거나, 하이버네이션 기능을 활용해야 한다.

### 3.1 SSM을 통한 인스턴스 내부 메모리 수집 (Linux)

```bash
# 1. SSM 세션 시작 (별도 포렌식 역할 사용)
aws ssm start-session --target i-0123456789abcdef0 \
    --profile forensics-readonly

# 2. LiME 커널 모듈로 메모리 덤프 (인스턴스 내부)
sudo insmod lime-$(uname -r).ko \
    "path=/tmp/memory.lime format=lime"

# 3. 덤프 파일 S3 업로드
aws s3 cp /tmp/memory.lime \
    s3://forensics-bucket/evidence/i-0123456789/memory.lime \
    --sse aws:kms

# 4. 해시값 산출 및 기록
sha256sum /tmp/memory.lime | tee /tmp/memory.lime.sha256
```

### 3.2 하이버네이션을 이용한 메모리 보존

```bash
# 1. 실행 중인 인스턴스 격리 (네트워크 차단)
aws ec2 modify-instance-attribute \
    --instance-id i-0123456789abcdef0 \
    --groups sg-forensics-isolated

# 2. EBS 스냅샷 생성 (현재 상태 보존)
aws ec2 create-snapshot \
    --volume-id vol-0123456789abcdef0 \
    --description "forensics-$(date +%Y%m%d-%H%M%S)" \
    --tag-specifications 'ResourceType=snapshot,Tags=[{Key=Purpose,Value=forensics}]'

# 3. 스냅샷 완료 대기
aws ec2 wait snapshot-completed \
    --snapshot-ids snap-0123456789abcdef0
```

### 3.3 포렌식 분석 인스턴스에 볼륨 연결

```bash
# 1. 스냅샷으로 새 볼륨 생성 (원본 수정 금지)
aws ec2 create-volume \
    --snapshot-id snap-0123456789abcdef0 \
    --availability-zone us-east-1a \
    --volume-type gp3

# 2. 포렌식 분석 인스턴스에 연결
aws ec2 attach-volume \
    --volume-id vol-new \
    --instance-id i-forensics \
    --device /dev/xvdf

# 3. 읽기 전용 마운트 (쓰기 방지)
sudo mount -o ro,noexec /dev/xvdf /mnt/evidence
```

---

## 4. Python CLI: AWS CloudTrail 로그 분석기

```python
#!/usr/bin/env python3
"""
AWS CloudTrail 로그 분석기
- gzip 압축 JSON 형식의 CloudTrail 로그를 파싱하여 의심 API 호출을 탐지한다.
- 타임라인 형식으로 결과를 출력한다.
"""

from __future__ import annotations

import argparse
import gzip
import json
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# ── 탐지 규칙 정의 ────────────────────────────────────────────────────────────

@dataclass
class DetectionRule:
    """단일 탐지 규칙"""
    rule_id: str
    name: str
    event_names: list[str]
    severity: str          # CRITICAL / HIGH / MEDIUM / LOW
    description: str
    tags: list[str]


DETECTION_RULES: list[DetectionRule] = [
    DetectionRule(
        rule_id="CT-001",
        name="백도어 IAM 사용자 생성",
        event_names=["CreateUser"],
        severity="CRITICAL",
        description="새로운 IAM 사용자가 생성됨. 공격자의 지속성 확보 시도 가능성.",
        tags=["persistence", "iam"],
    ),
    DetectionRule(
        rule_id="CT-002",
        name="IAM 사용자 액세스키 생성",
        event_names=["CreateAccessKey"],
        severity="HIGH",
        description="IAM 액세스키 생성. 타 사용자 계정에 키를 생성하는 경우 특히 위험.",
        tags=["persistence", "credential_access"],
    ),
    DetectionRule(
        rule_id="CT-003",
        name="IAM 정책 연결",
        event_names=["AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy"],
        severity="HIGH",
        description="IAM 엔티티에 정책 연결. 권한 에스컬레이션 시도 가능성.",
        tags=["privilege_escalation", "iam"],
    ),
    DetectionRule(
        rule_id="CT-004",
        name="역할 가정 (AssumeRole)",
        event_names=["AssumeRole", "AssumeRoleWithWebIdentity", "AssumeRoleWithSAML"],
        severity="MEDIUM",
        description="IAM 역할 가정. 교차 계정 또는 비정상 역할 가정 시 위험.",
        tags=["lateral_movement", "iam"],
    ),
    DetectionRule(
        rule_id="CT-005",
        name="CloudTrail 비활성화",
        event_names=["StopLogging", "DeleteTrail", "UpdateTrail"],
        severity="CRITICAL",
        description="CloudTrail 로깅 중단 또는 삭제. 증거 인멸 시도.",
        tags=["defense_evasion"],
    ),
    DetectionRule(
        rule_id="CT-006",
        name="GuardDuty 비활성화",
        event_names=["DeleteDetector", "DisassociateFromMasterAccount", "UpdateDetector"],
        severity="CRITICAL",
        description="GuardDuty 탐지 비활성화. 탐지 우회 시도.",
        tags=["defense_evasion"],
    ),
    DetectionRule(
        rule_id="CT-007",
        name="S3 버킷 퍼블릭 공개",
        event_names=["PutBucketAcl", "DeletePublicAccessBlock", "PutBucketPolicy"],
        severity="HIGH",
        description="S3 버킷 접근 제어 변경. 데이터 유출 경로 생성 가능성.",
        tags=["exfiltration", "s3"],
    ),
    DetectionRule(
        rule_id="CT-008",
        name="보안 그룹 인바운드 규칙 변경",
        event_names=["AuthorizeSecurityGroupIngress"],
        severity="MEDIUM",
        description="보안 그룹 인바운드 규칙 추가. 0.0.0.0/0 허용 시 특히 위험.",
        tags=["defense_evasion", "initial_access"],
    ),
    DetectionRule(
        rule_id="CT-009",
        name="Secrets Manager 시크릿 조회",
        event_names=["GetSecretValue"],
        severity="HIGH",
        description="시크릿 값 조회. 자격증명 탈취 시도 가능성.",
        tags=["credential_access"],
    ),
    DetectionRule(
        rule_id="CT-010",
        name="인스턴스 종료",
        event_names=["TerminateInstances"],
        severity="HIGH",
        description="EC2 인스턴스 강제 종료. 증거 인멸 또는 서비스 방해 가능성.",
        tags=["impact"],
    ),
    DetectionRule(
        rule_id="CT-011",
        name="KMS 키 삭제/비활성화",
        event_names=["ScheduleKeyDeletion", "DisableKey"],
        severity="CRITICAL",
        description="KMS 암호화 키 삭제 예약 또는 비활성화. 랜섬웨어 시도 가능성.",
        tags=["impact"],
    ),
    DetectionRule(
        rule_id="CT-012",
        name="루트 계정 활동",
        event_names=["*"],
        severity="HIGH",
        description="루트 계정으로 API 호출 발생. 일반 운영에서는 사용 자제 권장.",
        tags=["iam", "root"],
    ),
    DetectionRule(
        rule_id="CT-013",
        name="인라인 IAM 정책 추가",
        event_names=["PutUserPolicy", "PutRolePolicy", "PutGroupPolicy"],
        severity="HIGH",
        description="인라인 IAM 정책 직접 추가. 관리형 정책보다 추적이 어려움.",
        tags=["privilege_escalation", "iam"],
    ),
    DetectionRule(
        rule_id="CT-014",
        name="콘솔 로그인 프로파일 생성",
        event_names=["CreateLoginProfile", "UpdateLoginProfile"],
        severity="HIGH",
        description="IAM 사용자 콘솔 접근 비밀번호 설정. 타 사용자에 대한 설정 시 위험.",
        tags=["persistence", "iam"],
    ),
]

# 이벤트명 → 규칙 빠른 조회 인덱스
_RULE_INDEX: dict[str, list[DetectionRule]] = {}
for _rule in DETECTION_RULES:
    for _event in _rule.event_names:
        _RULE_INDEX.setdefault(_event, []).append(_rule)


# ── 데이터 구조 ───────────────────────────────────────────────────────────────

@dataclass
class CloudTrailEvent:
    """파싱된 CloudTrail 이벤트"""
    event_time: datetime
    event_name: str
    event_source: str
    user_type: str
    user_arn: str
    user_name: str
    account_id: str
    source_ip: str
    user_agent: str
    aws_region: str
    error_code: str | None
    error_message: str | None
    request_parameters: dict[str, Any]
    response_elements: dict[str, Any]
    raw: dict[str, Any]

    @classmethod
    def from_dict(cls, record: dict[str, Any]) -> "CloudTrailEvent":
        identity = record.get("userIdentity", {})
        return cls(
            event_time=datetime.fromisoformat(
                record["eventTime"].replace("Z", "+00:00")
            ),
            event_name=record.get("eventName", ""),
            event_source=record.get("eventSource", ""),
            user_type=identity.get("type", ""),
            user_arn=identity.get("arn", ""),
            user_name=identity.get("userName", identity.get("principalId", "")),
            account_id=identity.get("accountId", record.get("recipientAccountId", "")),
            source_ip=record.get("sourceIPAddress", ""),
            user_agent=record.get("userAgent", ""),
            aws_region=record.get("awsRegion", ""),
            error_code=record.get("errorCode"),
            error_message=record.get("errorMessage"),
            request_parameters=record.get("requestParameters") or {},
            response_elements=record.get("responseElements") or {},
            raw=record,
        )

    @property
    def is_root(self) -> bool:
        return self.user_type == "Root"

    @property
    def is_error(self) -> bool:
        return self.error_code is not None


@dataclass
class DetectionHit:
    """탐지된 의심 이벤트"""
    event: CloudTrailEvent
    rule: DetectionRule

    def to_timeline_line(self) -> str:
        severity_icon = {
            "CRITICAL": "[!!!]",
            "HIGH":     "[ ! ]",
            "MEDIUM":   "[ * ]",
            "LOW":      "[ - ]",
        }.get(self.rule.severity, "[ ? ]")
        ts = self.event.event_time.strftime("%Y-%m-%d %H:%M:%S UTC")
        user = self.event.user_name or self.event.user_arn
        error_info = f" [오류: {self.event.error_code}]" if self.event.is_error else ""
        return (
            f"{ts} {severity_icon} [{self.rule.rule_id}] {self.rule.name}\n"
            f"           이벤트: {self.event.event_name} | "
            f"사용자: {user} | IP: {self.event.source_ip} | "
            f"리전: {self.event.aws_region}{error_info}\n"
            f"           설명: {self.rule.description}"
        )


# ── 파싱 및 분석 함수 ─────────────────────────────────────────────────────────

def parse_cloudtrail_file(path: Path) -> list[CloudTrailEvent]:
    """CloudTrail 로그 파일(gzip JSON 또는 일반 JSON) 파싱"""
    try:
        if path.suffix == ".gz":
            with gzip.open(path, "rt", encoding="utf-8") as fh:
                data = json.load(fh)
        else:
            data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, gzip.BadGzipFile) as exc:
        print(f"[오류] 파일 파싱 실패 ({path.name}): {exc}", file=sys.stderr)
        return []

    # CloudTrail 표준 형식: {"Records": [...]}
    records = data.get("Records", []) if isinstance(data, dict) else data
    events: list[CloudTrailEvent] = []
    for rec in records:
        try:
            events.append(CloudTrailEvent.from_dict(rec))
        except (KeyError, ValueError) as exc:
            print(f"[경고] 레코드 파싱 건너뜀: {exc}", file=sys.stderr)
    return events


def apply_filters(
    events: list[CloudTrailEvent],
    user_filter: str | None,
    start_time: datetime | None,
    end_time: datetime | None,
    event_filter: list[str] | None,
) -> list[CloudTrailEvent]:
    """사용자, 시간, 이벤트명 필터 적용"""
    result = events
    if user_filter:
        uf = user_filter.lower()
        result = [
            e for e in result
            if uf in e.user_name.lower() or uf in e.user_arn.lower()
        ]
    if start_time:
        result = [e for e in result if e.event_time >= start_time]
    if end_time:
        result = [e for e in result if e.event_time <= end_time]
    if event_filter:
        ef_lower = [f.lower() for f in event_filter]
        result = [e for e in result if e.event_name.lower() in ef_lower]
    return result


def detect_suspicious_events(events: list[CloudTrailEvent]) -> list[DetectionHit]:
    """탐지 규칙 매칭"""
    hits: list[DetectionHit] = []
    for event in events:
        matched_rules: list[DetectionRule] = []

        # 이벤트명 기반 매칭
        if event.event_name in _RULE_INDEX:
            matched_rules.extend(_RULE_INDEX[event.event_name])

        # 루트 계정 활동 (CT-012)
        if event.is_root:
            root_rule = next((r for r in DETECTION_RULES if r.rule_id == "CT-012"), None)
            if root_rule and root_rule not in matched_rules:
                matched_rules.append(root_rule)

        for rule in matched_rules:
            hits.append(DetectionHit(event=event, rule=rule))

    # 시간 순 정렬
    hits.sort(key=lambda h: h.event.event_time)
    return hits


def print_timeline(hits: list[DetectionHit], show_all: bool = False) -> None:
    """타임라인 형식 출력"""
    if not hits:
        print("\n[정보] 탐지된 의심 이벤트가 없습니다.")
        return

    print(f"\n{'=' * 80}")
    print(f" CloudTrail 의심 이벤트 타임라인  (총 {len(hits)}건)")
    print(f"{'=' * 80}\n")

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    if not show_all:
        hits = [h for h in hits if h.rule.severity in ("CRITICAL", "HIGH")]

    for hit in hits:
        print(hit.to_timeline_line())
        print()


def print_statistics(
    all_events: list[CloudTrailEvent],
    hits: list[DetectionHit],
) -> None:
    """통계 요약 출력"""
    print(f"\n{'=' * 80}")
    print(" 분석 통계 요약")
    print(f"{'=' * 80}")
    print(f"  전체 이벤트 수:     {len(all_events):,}")
    print(f"  탐지 의심 이벤트:   {len(hits):,}")

    severity_counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for hit in hits:
        severity_counts[hit.rule.severity] = severity_counts.get(hit.rule.severity, 0) + 1

    print(f"\n  심각도별 탐지:")
    for sev, cnt in severity_counts.items():
        if cnt > 0:
            print(f"    {sev:10s}: {cnt:,}건")

    # 상위 사용자
    user_event_count: dict[str, int] = {}
    for e in all_events:
        key = e.user_name or e.user_arn or "unknown"
        user_event_count[key] = user_event_count.get(key, 0) + 1

    print(f"\n  상위 활동 사용자 (Top 5):")
    for user, cnt in sorted(user_event_count.items(), key=lambda x: -x[1])[:5]:
        print(f"    {user:50s} {cnt:,}건")

    # 상위 이벤트
    event_count: dict[str, int] = {}
    for e in all_events:
        event_count[e.event_name] = event_count.get(e.event_name, 0) + 1

    print(f"\n  상위 API 이벤트 (Top 10):")
    for evt, cnt in sorted(event_count.items(), key=lambda x: -x[1])[:10]:
        print(f"    {evt:50s} {cnt:,}건")

    # 소스 IP
    ip_count: dict[str, int] = {}
    for e in all_events:
        if e.source_ip and not e.source_ip.startswith("AWS"):
            ip_count[e.source_ip] = ip_count.get(e.source_ip, 0) + 1

    print(f"\n  상위 소스 IP (Top 5):")
    for ip, cnt in sorted(ip_count.items(), key=lambda x: -x[1])[:5]:
        print(f"    {ip:50s} {cnt:,}건")

    print()


# ── CLI 진입점 ────────────────────────────────────────────────────────────────

def parse_datetime_arg(value: str) -> datetime:
    """날짜/시간 문자열 파싱 (ISO 8601 형식)"""
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"날짜/시간 형식 오류: '{value}'. ISO 8601 형식 사용 (예: 2024-01-15T09:00:00Z)"
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aws_cloudtrail_analyzer",
        description="AWS CloudTrail 로그 분석기 — gzip JSON 로그에서 의심 API 호출을 탐지한다.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
사용 예:
  %(prog)s --log-file trail.json.gz
  %(prog)s --log-file trail.json --user attacker --start-time 2024-01-15T00:00:00Z
  %(prog)s --log-file trail.json.gz --event-filter CreateUser CreateAccessKey
  %(prog)s --log-file trail.json.gz --all-severities
        """,
    )
    parser.add_argument(
        "--log-file", "-f",
        dest="log_file",
        type=Path,
        required=True,
        help="CloudTrail 로그 파일 경로 (.json 또는 .json.gz)",
    )
    parser.add_argument(
        "--user", "-u",
        default=None,
        help="특정 사용자 이름/ARN 필터 (부분 일치)",
    )
    parser.add_argument(
        "--start-time",
        dest="start_time",
        type=parse_datetime_arg,
        default=None,
        help="조회 시작 시각 (ISO 8601, 예: 2024-01-15T00:00:00Z)",
    )
    parser.add_argument(
        "--end-time",
        dest="end_time",
        type=parse_datetime_arg,
        default=None,
        help="조회 종료 시각 (ISO 8601, 예: 2024-01-15T23:59:59Z)",
    )
    parser.add_argument(
        "--event-filter", "-e",
        dest="event_filter",
        nargs="+",
        default=None,
        help="특정 이벤트명 필터 (공백으로 구분, 예: CreateUser CreateAccessKey)",
    )
    parser.add_argument(
        "--all-severities",
        action="store_true",
        help="모든 심각도 탐지 결과 출력 (기본: CRITICAL/HIGH만)",
    )
    parser.add_argument(
        "--stats-only",
        action="store_true",
        help="통계 요약만 출력 (타임라인 생략)",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if not args.log_file.exists():
        print(f"[오류] 로그 파일을 찾을 수 없습니다: {args.log_file}", file=sys.stderr)
        sys.exit(1)

    print(f"[정보] 로그 파일 로드 중: {args.log_file}")
    events = parse_cloudtrail_file(args.log_file)

    if not events:
        print("[오류] 파싱된 이벤트가 없습니다.", file=sys.stderr)
        sys.exit(1)

    print(f"[정보] 총 {len(events):,}개 이벤트 로드 완료")

    # 필터 적용
    filtered = apply_filters(
        events,
        user_filter=args.user,
        start_time=args.start_time,
        end_time=args.end_time,
        event_filter=args.event_filter,
    )

    if len(filtered) != len(events):
        print(f"[정보] 필터 적용 후: {len(filtered):,}개 이벤트")

    # 탐지 실행
    hits = detect_suspicious_events(filtered)

    # 출력
    if not args.stats_only:
        print_timeline(hits, show_all=args.all_severities)

    print_statistics(filtered, hits)


if __name__ == "__main__":
    main()
```

### 사용 방법

```bash
# 기본 분석 (CRITICAL/HIGH만 출력)
python aws_cloudtrail_analyzer.py --log-file cloudtrail-2024-01-15.json.gz

# 특정 사용자 활동 필터
python aws_cloudtrail_analyzer.py --log-file trail.json.gz --user attacker

# 시간 범위 지정
python aws_cloudtrail_analyzer.py --log-file trail.json.gz \
    --start-time 2024-01-15T09:00:00Z \
    --end-time 2024-01-15T18:00:00Z

# 특정 이벤트만 분석
python aws_cloudtrail_analyzer.py --log-file trail.json.gz \
    --event-filter CreateUser CreateAccessKey AssumeRole

# 모든 심각도 포함
python aws_cloudtrail_analyzer.py --log-file trail.json.gz --all-severities

# 통계만 출력
python aws_cloudtrail_analyzer.py --log-file trail.json.gz --stats-only
```

---

## 5. AWS 포렌식 추가 참고사항

### 5.1 다중 계정 환경에서의 조사

| 항목 | 단일 계정 | 조직(AWS Organizations) |
|------|---------|----------------------|
| CloudTrail | 계정별 Trail | 조직 Trail 중앙 수집 |
| 로그 집중 | 개별 S3 버킷 | 보안 계정 중앙 버킷 |
| 교차 계정 롤 | 개별 설정 | SCP로 포렌식 역할 강제 |
| GuardDuty | 개별 활성화 | 마스터 계정 위임 관리 |

### 5.2 AWS 포렌식 전용 IAM 정책 최소 권한 예시

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "cloudtrail:LookupEvents",
                "cloudtrail:GetTrailStatus",
                "s3:GetObject",
                "ec2:DescribeInstances",
                "ec2:CreateSnapshot",
                "iam:GenerateCredentialReport",
                "iam:GetCredentialReport",
                "guardduty:ListFindings",
                "guardduty:GetFindings"
            ],
            "Resource": "*"
        }
    ]
}
```

---

<a name="english"></a>

# AWS Forensics

## 1. Key AWS Log Sources

The most important log sources when conducting forensic investigations in an AWS environment are listed below. Since each service records activity at a different layer, you must combine the appropriate logs depending on the type of incident to construct a complete timeline.

| Log Source | Recorded Content | Enabled by Default | Retention Period | Primary Forensic Use |
|----------|---------|-----------|---------|--------------|
| CloudTrail | API calls (management events) | Yes (Event History 90 days) | Unlimited when stored in S3 | Tracking IAM changes, resource manipulation |
| CloudTrail Data Events | S3/Lambda data-level events | No (requires separate configuration) | Depends on Trail settings | Tracking S3 object access, Lambda execution |
| VPC Flow Logs | Network flow metadata | No | CloudWatch/S3 | Detecting lateral movement, C2 communication |
| S3 Server Access Log | S3 bucket HTTP requests | No | Unlimited when stored in S3 | Tracing data exfiltration paths |
| ELB Access Log | Load balancer requests | No | Stored in S3 | Analyzing web attack paths |
| CloudFront Log | CDN request logs | No | Stored in S3 | Tracking attacker IPs |
| GuardDuty Findings | AI-based threat detection results | No (requires activation) | 90 days | Immediate threat alerts |
| AWS Config | Resource configuration change history | No | Stored in S3 | Configuration change timeline |
| Route53 Resolver Query Log | DNS query records | No | CloudWatch/S3 | Detecting C2 domain access |
| SSM Session Manager Log | Remote session activity | Optional | S3/CloudWatch | Command execution history |
| WAF Log | Web firewall detection/block logs | No | S3/CloudWatch | Analyzing web attack patterns |
| Macie Findings | Sensitive data detection results | No | 90 days | Identifying personal data leaks |

### 1.1 CloudTrail Event Structure

```json
{
    "eventVersion": "1.08",
    "userIdentity": {
        "type": "IAMUser",
        "principalId": "AIDAXXXXXXXXXXXXXXXXX",
        "arn": "arn:aws:iam::123456789012:user/attacker",
        "accountId": "123456789012",
        "userName": "attacker"
    },
    "eventTime": "2024-01-15T09:23:11Z",
    "eventSource": "iam.amazonaws.com",
    "eventName": "CreateAccessKey",
    "awsRegion": "us-east-1",
    "sourceIPAddress": "203.0.113.42",
    "userAgent": "aws-cli/2.x Python/3.x",
    "requestParameters": {"userName": "backdoor-user"},
    "responseElements": {"accessKey": {"accessKeyId": "AKIAXXXXXXXXXX"}},
    "errorCode": null,
    "errorMessage": null
}
```

---

## 2. IAM Privilege Escalation Patterns

IAM privilege escalation is the most frequently observed attack technique in AWS breach incidents. After gaining initial access, attackers start with low privileges and attempt to escalate to administrator-level permissions.

| Escalation Technique | Required Initial Permission | Permissions Gained | Detection Event |
|---------------|------------|---------|-----------|
| AttachUserPolicy | iam:AttachUserPolicy | Attach arbitrary policies | AttachUserPolicy |
| CreatePolicyVersion | iam:CreatePolicyVersion | Modify existing policies | CreatePolicyVersion |
| SetDefaultPolicyVersion | iam:SetDefaultPolicyVersion | Rollback to previous version | SetDefaultPolicyVersion |
| CreateAccessKey | iam:CreateAccessKey | Create keys for other users | CreateAccessKey |
| CreateLoginProfile | iam:CreateLoginProfile | Add console access | CreateLoginProfile |
| UpdateLoginProfile | iam:UpdateLoginProfile | Change other user's password | UpdateLoginProfile |
| AssumeRole (OIDC) | sts:AssumeRoleWithWebIdentity | Obtain role permissions | AssumeRoleWithWebIdentity |
| PassRole + Lambda | iam:PassRole, lambda:* | Lambda execution role permissions | CreateFunction, InvokeFunction |
| PassRole + EC2 | iam:PassRole, ec2:RunInstances | Instance profile permissions | RunInstances |
| UpdateAssumeRolePolicy | iam:UpdateAssumeRolePolicy | Modify role trust policy | UpdateAssumeRolePolicy |

### 2.1 Key Query Patterns for Escalation Detection

```
Target API events for detection:
- iam:CreateUser + iam:AttachUserPolicy (backdoor account creation)
- iam:CreateAccessKey (issuing keys for other accounts)
- sts:AssumeRole (role assumption, especially cross-account)
- iam:PutUserPolicy / iam:PutRolePolicy (adding inline policies)
- iam:AddUserToGroup (adding to privileged groups)
```

---

## 3. EC2 Memory Dump Procedure

Dumping memory from an EC2 instance is more complex than on-premises. Since direct hypervisor access is not available, the process must be performed from within the operating system or by leveraging the hibernation feature.

### 3.1 In-Instance Memory Collection via SSM (Linux)

```bash
# 1. Start SSM session (using a dedicated forensics role)
aws ssm start-session --target i-0123456789abcdef0 \
    --profile forensics-readonly

# 2. Memory dump using LiME kernel module (inside the instance)
sudo insmod lime-$(uname -r).ko \
    "path=/tmp/memory.lime format=lime"

# 3. Upload dump file to S3
aws s3 cp /tmp/memory.lime \
    s3://forensics-bucket/evidence/i-0123456789/memory.lime \
    --sse aws:kms

# 4. Calculate and record hash values
sha256sum /tmp/memory.lime | tee /tmp/memory.lime.sha256
```

### 3.2 Memory Preservation Using Hibernation

```bash
# 1. Isolate the running instance (block network access)
aws ec2 modify-instance-attribute \
    --instance-id i-0123456789abcdef0 \
    --groups sg-forensics-isolated

# 2. Create EBS snapshot (preserve current state)
aws ec2 create-snapshot \
    --volume-id vol-0123456789abcdef0 \
    --description "forensics-$(date +%Y%m%d-%H%M%S)" \
    --tag-specifications 'ResourceType=snapshot,Tags=[{Key=Purpose,Value=forensics}]'

# 3. Wait for snapshot completion
aws ec2 wait snapshot-completed \
    --snapshot-ids snap-0123456789abcdef0
```

### 3.3 Attaching Volume to Forensics Analysis Instance

```bash
# 1. Create new volume from snapshot (do not modify original)
aws ec2 create-volume \
    --snapshot-id snap-0123456789abcdef0 \
    --availability-zone us-east-1a \
    --volume-type gp3

# 2. Attach to forensics analysis instance
aws ec2 attach-volume \
    --volume-id vol-new \
    --instance-id i-forensics \
    --device /dev/xvdf

# 3. Mount read-only (write protection)
sudo mount -o ro,noexec /dev/xvdf /mnt/evidence
```

---

## 4. Python CLI: AWS CloudTrail Log Analyzer

```python
#!/usr/bin/env python3
"""
AWS CloudTrail Log Analyzer
- Parses CloudTrail logs in gzip-compressed JSON format to detect suspicious API calls.
- Outputs results in timeline format.
"""

from __future__ import annotations

import argparse
import gzip
import json
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# ── Detection Rule Definitions ────────────────────────────────────────────────

@dataclass
class DetectionRule:
    """Single detection rule"""
    rule_id: str
    name: str
    event_names: list[str]
    severity: str          # CRITICAL / HIGH / MEDIUM / LOW
    description: str
    tags: list[str]


DETECTION_RULES: list[DetectionRule] = [
    DetectionRule(
        rule_id="CT-001",
        name="Backdoor IAM User Creation",
        event_names=["CreateUser"],
        severity="CRITICAL",
        description="A new IAM user was created. Possible attempt to establish attacker persistence.",
        tags=["persistence", "iam"],
    ),
    DetectionRule(
        rule_id="CT-002",
        name="IAM User Access Key Creation",
        event_names=["CreateAccessKey"],
        severity="HIGH",
        description="IAM access key created. Especially dangerous if key is created for another user's account.",
        tags=["persistence", "credential_access"],
    ),
    DetectionRule(
        rule_id="CT-003",
        name="IAM Policy Attachment",
        event_names=["AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy"],
        severity="HIGH",
        description="Policy attached to IAM entity. Possible privilege escalation attempt.",
        tags=["privilege_escalation", "iam"],
    ),
    DetectionRule(
        rule_id="CT-004",
        name="Role Assumption (AssumeRole)",
        event_names=["AssumeRole", "AssumeRoleWithWebIdentity", "AssumeRoleWithSAML"],
        severity="MEDIUM",
        description="IAM role assumed. Dangerous if cross-account or abnormal role assumption occurs.",
        tags=["lateral_movement", "iam"],
    ),
    DetectionRule(
        rule_id="CT-005",
        name="CloudTrail Disabled",
        event_names=["StopLogging", "DeleteTrail", "UpdateTrail"],
        severity="CRITICAL",
        description="CloudTrail logging stopped or deleted. Evidence destruction attempt.",
        tags=["defense_evasion"],
    ),
    DetectionRule(
        rule_id="CT-006",
        name="GuardDuty Disabled",
        event_names=["DeleteDetector", "DisassociateFromMasterAccount", "UpdateDetector"],
        severity="CRITICAL",
        description="GuardDuty detection disabled. Detection evasion attempt.",
        tags=["defense_evasion"],
    ),
    DetectionRule(
        rule_id="CT-007",
        name="S3 Bucket Made Public",
        event_names=["PutBucketAcl", "DeletePublicAccessBlock", "PutBucketPolicy"],
        severity="HIGH",
        description="S3 bucket access control changed. Possible creation of data exfiltration path.",
        tags=["exfiltration", "s3"],
    ),
    DetectionRule(
        rule_id="CT-008",
        name="Security Group Inbound Rule Changed",
        event_names=["AuthorizeSecurityGroupIngress"],
        severity="MEDIUM",
        description="Security group inbound rule added. Especially dangerous if 0.0.0.0/0 is allowed.",
        tags=["defense_evasion", "initial_access"],
    ),
    DetectionRule(
        rule_id="CT-009",
        name="Secrets Manager Secret Accessed",
        event_names=["GetSecretValue"],
        severity="HIGH",
        description="Secret value accessed. Possible credential theft attempt.",
        tags=["credential_access"],
    ),
    DetectionRule(
        rule_id="CT-010",
        name="Instance Terminated",
        event_names=["TerminateInstances"],
        severity="HIGH",
        description="EC2 instance forcibly terminated. Possible evidence destruction or service disruption.",
        tags=["impact"],
    ),
    DetectionRule(
        rule_id="CT-011",
        name="KMS Key Deleted/Disabled",
        event_names=["ScheduleKeyDeletion", "DisableKey"],
        severity="CRITICAL",
        description="KMS encryption key deletion scheduled or disabled. Possible ransomware attempt.",
        tags=["impact"],
    ),
    DetectionRule(
        rule_id="CT-012",
        name="Root Account Activity",
        event_names=["*"],
        severity="HIGH",
        description="API call made using root account. Recommended to avoid in normal operations.",
        tags=["iam", "root"],
    ),
    DetectionRule(
        rule_id="CT-013",
        name="Inline IAM Policy Added",
        event_names=["PutUserPolicy", "PutRolePolicy", "PutGroupPolicy"],
        severity="HIGH",
        description="Inline IAM policy directly added. Harder to track than managed policies.",
        tags=["privilege_escalation", "iam"],
    ),
    DetectionRule(
        rule_id="CT-014",
        name="Console Login Profile Created",
        event_names=["CreateLoginProfile", "UpdateLoginProfile"],
        severity="HIGH",
        description="IAM user console access password set. Dangerous if configured for another user.",
        tags=["persistence", "iam"],
    ),
]

# Event name → rule fast-lookup index
_RULE_INDEX: dict[str, list[DetectionRule]] = {}
for _rule in DETECTION_RULES:
    for _event in _rule.event_names:
        _RULE_INDEX.setdefault(_event, []).append(_rule)


# ── Data Structures ───────────────────────────────────────────────────────────

@dataclass
class CloudTrailEvent:
    """Parsed CloudTrail event"""
    event_time: datetime
    event_name: str
    event_source: str
    user_type: str
    user_arn: str
    user_name: str
    account_id: str
    source_ip: str
    user_agent: str
    aws_region: str
    error_code: str | None
    error_message: str | None
    request_parameters: dict[str, Any]
    response_elements: dict[str, Any]
    raw: dict[str, Any]

    @classmethod
    def from_dict(cls, record: dict[str, Any]) -> "CloudTrailEvent":
        identity = record.get("userIdentity", {})
        return cls(
            event_time=datetime.fromisoformat(
                record["eventTime"].replace("Z", "+00:00")
            ),
            event_name=record.get("eventName", ""),
            event_source=record.get("eventSource", ""),
            user_type=identity.get("type", ""),
            user_arn=identity.get("arn", ""),
            user_name=identity.get("userName", identity.get("principalId", "")),
            account_id=identity.get("accountId", record.get("recipientAccountId", "")),
            source_ip=record.get("sourceIPAddress", ""),
            user_agent=record.get("userAgent", ""),
            aws_region=record.get("awsRegion", ""),
            error_code=record.get("errorCode"),
            error_message=record.get("errorMessage"),
            request_parameters=record.get("requestParameters") or {},
            response_elements=record.get("responseElements") or {},
            raw=record,
        )

    @property
    def is_root(self) -> bool:
        return self.user_type == "Root"

    @property
    def is_error(self) -> bool:
        return self.error_code is not None


@dataclass
class DetectionHit:
    """Detected suspicious event"""
    event: CloudTrailEvent
    rule: DetectionRule

    def to_timeline_line(self) -> str:
        severity_icon = {
            "CRITICAL": "[!!!]",
            "HIGH":     "[ ! ]",
            "MEDIUM":   "[ * ]",
            "LOW":      "[ - ]",
        }.get(self.rule.severity, "[ ? ]")
        ts = self.event.event_time.strftime("%Y-%m-%d %H:%M:%S UTC")
        user = self.event.user_name or self.event.user_arn
        error_info = f" [Error: {self.event.error_code}]" if self.event.is_error else ""
        return (
            f"{ts} {severity_icon} [{self.rule.rule_id}] {self.rule.name}\n"
            f"           Event: {self.event.event_name} | "
            f"User: {user} | IP: {self.event.source_ip} | "
            f"Region: {self.event.aws_region}{error_info}\n"
            f"           Description: {self.rule.description}"
        )


# ── Parsing and Analysis Functions ────────────────────────────────────────────

def parse_cloudtrail_file(path: Path) -> list[CloudTrailEvent]:
    """Parse CloudTrail log file (gzip JSON or plain JSON)"""
    try:
        if path.suffix == ".gz":
            with gzip.open(path, "rt", encoding="utf-8") as fh:
                data = json.load(fh)
        else:
            data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, gzip.BadGzipFile) as exc:
        print(f"[ERROR] Failed to parse file ({path.name}): {exc}", file=sys.stderr)
        return []

    # CloudTrail standard format: {"Records": [...]}
    records = data.get("Records", []) if isinstance(data, dict) else data
    events: list[CloudTrailEvent] = []
    for rec in records:
        try:
            events.append(CloudTrailEvent.from_dict(rec))
        except (KeyError, ValueError) as exc:
            print(f"[WARN] Skipping record parse: {exc}", file=sys.stderr)
    return events


def apply_filters(
    events: list[CloudTrailEvent],
    user_filter: str | None,
    start_time: datetime | None,
    end_time: datetime | None,
    event_filter: list[str] | None,
) -> list[CloudTrailEvent]:
    """Apply user, time, and event name filters"""
    result = events
    if user_filter:
        uf = user_filter.lower()
        result = [
            e for e in result
            if uf in e.user_name.lower() or uf in e.user_arn.lower()
        ]
    if start_time:
        result = [e for e in result if e.event_time >= start_time]
    if end_time:
        result = [e for e in result if e.event_time <= end_time]
    if event_filter:
        ef_lower = [f.lower() for f in event_filter]
        result = [e for e in result if e.event_name.lower() in ef_lower]
    return result


def detect_suspicious_events(events: list[CloudTrailEvent]) -> list[DetectionHit]:
    """Match detection rules"""
    hits: list[DetectionHit] = []
    for event in events:
        matched_rules: list[DetectionRule] = []

        # Event name-based matching
        if event.event_name in _RULE_INDEX:
            matched_rules.extend(_RULE_INDEX[event.event_name])

        # Root account activity (CT-012)
        if event.is_root:
            root_rule = next((r for r in DETECTION_RULES if r.rule_id == "CT-012"), None)
            if root_rule and root_rule not in matched_rules:
                matched_rules.append(root_rule)

        for rule in matched_rules:
            hits.append(DetectionHit(event=event, rule=rule))

    # Sort by time
    hits.sort(key=lambda h: h.event.event_time)
    return hits


def print_timeline(hits: list[DetectionHit], show_all: bool = False) -> None:
    """Print timeline format output"""
    if not hits:
        print("\n[INFO] No suspicious events detected.")
        return

    print(f"\n{'=' * 80}")
    print(f" CloudTrail Suspicious Event Timeline  (Total: {len(hits)} events)")
    print(f"{'=' * 80}\n")

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    if not show_all:
        hits = [h for h in hits if h.rule.severity in ("CRITICAL", "HIGH")]

    for hit in hits:
        print(hit.to_timeline_line())
        print()


def print_statistics(
    all_events: list[CloudTrailEvent],
    hits: list[DetectionHit],
) -> None:
    """Print statistical summary"""
    print(f"\n{'=' * 80}")
    print(" Analysis Statistics Summary")
    print(f"{'=' * 80}")
    print(f"  Total events:              {len(all_events):,}")
    print(f"  Suspicious events detected: {len(hits):,}")

    severity_counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for hit in hits:
        severity_counts[hit.rule.severity] = severity_counts.get(hit.rule.severity, 0) + 1

    print(f"\n  Detections by severity:")
    for sev, cnt in severity_counts.items():
        if cnt > 0:
            print(f"    {sev:10s}: {cnt:,} events")

    # Top users
    user_event_count: dict[str, int] = {}
    for e in all_events:
        key = e.user_name or e.user_arn or "unknown"
        user_event_count[key] = user_event_count.get(key, 0) + 1

    print(f"\n  Top active users (Top 5):")
    for user, cnt in sorted(user_event_count.items(), key=lambda x: -x[1])[:5]:
        print(f"    {user:50s} {cnt:,} events")

    # Top events
    event_count: dict[str, int] = {}
    for e in all_events:
        event_count[e.event_name] = event_count.get(e.event_name, 0) + 1

    print(f"\n  Top API events (Top 10):")
    for evt, cnt in sorted(event_count.items(), key=lambda x: -x[1])[:10]:
        print(f"    {evt:50s} {cnt:,} events")

    # Source IPs
    ip_count: dict[str, int] = {}
    for e in all_events:
        if e.source_ip and not e.source_ip.startswith("AWS"):
            ip_count[e.source_ip] = ip_count.get(e.source_ip, 0) + 1

    print(f"\n  Top source IPs (Top 5):")
    for ip, cnt in sorted(ip_count.items(), key=lambda x: -x[1])[:5]:
        print(f"    {ip:50s} {cnt:,} events")

    print()


# ── CLI Entry Point ────────────────────────────────────────────────────────────

def parse_datetime_arg(value: str) -> datetime:
    """Parse date/time string (ISO 8601 format)"""
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"Date/time format error: '{value}'. Use ISO 8601 format (e.g., 2024-01-15T09:00:00Z)"
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aws_cloudtrail_analyzer",
        description="AWS CloudTrail Log Analyzer — Detects suspicious API calls from gzip JSON logs.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --log-file trail.json.gz
  %(prog)s --log-file trail.json --user attacker --start-time 2024-01-15T00:00:00Z
  %(prog)s --log-file trail.json.gz --event-filter CreateUser CreateAccessKey
  %(prog)s --log-file trail.json.gz --all-severities
        """,
    )
    parser.add_argument(
        "--log-file", "-f",
        dest="log_file",
        type=Path,
        required=True,
        help="CloudTrail log file path (.json or .json.gz)",
    )
    parser.add_argument(
        "--user", "-u",
        default=None,
        help="Filter by specific user name/ARN (partial match)",
    )
    parser.add_argument(
        "--start-time",
        dest="start_time",
        type=parse_datetime_arg,
        default=None,
        help="Query start time (ISO 8601, e.g., 2024-01-15T00:00:00Z)",
    )
    parser.add_argument(
        "--end-time",
        dest="end_time",
        type=parse_datetime_arg,
        default=None,
        help="Query end time (ISO 8601, e.g., 2024-01-15T23:59:59Z)",
    )
    parser.add_argument(
        "--event-filter", "-e",
        dest="event_filter",
        nargs="+",
        default=None,
        help="Filter by specific event names (space-separated, e.g., CreateUser CreateAccessKey)",
    )
    parser.add_argument(
        "--all-severities",
        action="store_true",
        help="Output all severity detection results (default: CRITICAL/HIGH only)",
    )
    parser.add_argument(
        "--stats-only",
        action="store_true",
        help="Output statistics summary only (skip timeline)",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if not args.log_file.exists():
        print(f"[ERROR] Log file not found: {args.log_file}", file=sys.stderr)
        sys.exit(1)

    print(f"[INFO] Loading log file: {args.log_file}")
    events = parse_cloudtrail_file(args.log_file)

    if not events:
        print("[ERROR] No events parsed.", file=sys.stderr)
        sys.exit(1)

    print(f"[INFO] Loaded {len(events):,} events total")

    # Apply filters
    filtered = apply_filters(
        events,
        user_filter=args.user,
        start_time=args.start_time,
        end_time=args.end_time,
        event_filter=args.event_filter,
    )

    if len(filtered) != len(events):
        print(f"[INFO] After filters: {len(filtered):,} events")

    # Run detection
    hits = detect_suspicious_events(filtered)

    # Output
    if not args.stats_only:
        print_timeline(hits, show_all=args.all_severities)

    print_statistics(filtered, hits)


if __name__ == "__main__":
    main()
```

### Usage

```bash
# Basic analysis (CRITICAL/HIGH only)
python aws_cloudtrail_analyzer.py --log-file cloudtrail-2024-01-15.json.gz

# Filter by specific user activity
python aws_cloudtrail_analyzer.py --log-file trail.json.gz --user attacker

# Specify time range
python aws_cloudtrail_analyzer.py --log-file trail.json.gz \
    --start-time 2024-01-15T09:00:00Z \
    --end-time 2024-01-15T18:00:00Z

# Analyze specific events only
python aws_cloudtrail_analyzer.py --log-file trail.json.gz \
    --event-filter CreateUser CreateAccessKey AssumeRole

# Include all severities
python aws_cloudtrail_analyzer.py --log-file trail.json.gz --all-severities

# Output statistics only
python aws_cloudtrail_analyzer.py --log-file trail.json.gz --stats-only
```

---

## 5. Additional AWS Forensics Reference

### 5.1 Investigation in Multi-Account Environments

| Item | Single Account | Organization (AWS Organizations) |
|------|---------|----------------------|
| CloudTrail | Per-account Trail | Centralized organization Trail collection |
| Log aggregation | Individual S3 buckets | Central bucket in security account |
| Cross-account role | Individual configuration | Forensics role enforced via SCP |
| GuardDuty | Individual activation | Delegated management from master account |

### 5.2 Minimum Privilege IAM Policy Example for AWS Forensics

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "cloudtrail:LookupEvents",
                "cloudtrail:GetTrailStatus",
                "s3:GetObject",
                "ec2:DescribeInstances",
                "ec2:CreateSnapshot",
                "iam:GenerateCredentialReport",
                "iam:GetCredentialReport",
                "guardduty:ListFindings",
                "guardduty:GetFindings"
            ],
            "Resource": "*"
        }
    ]
}
```
