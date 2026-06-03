> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 클라우드 위협 헌팅

## 0. 초보자를 위한 개념 이해

### 클라우드 위협 헌팅이란?

클라우드 위협 헌팅은 자동화된 보안 탐지 시스템이 놓쳤을 수 있는 고도화된 공격자를 사람이 직접 능동적으로 찾아내는 활동이다. 경보가 없어도 "혹시 공격자가 이미 들어와 있지 않을까?"라는 가설에서 출발하여 로그를 분석한다. 클라우드에서는 API 이벤트, 네트워크 흐름, IAM 활동이 주요 헌팅 데이터 소스이다.

**왜 배우는가:**
```
[위협 헌팅 vs 일반 보안 탐지 비교]

일반 SIEM/탐지:            위협 헌팅:
경보 → 조사                 가설 → 로그 분석 → 침해 발견
(반응적)                    (능동적)

[헌팅이 필요한 이유]
APT(고급 지속 위협) 공격자는 수개월간 탐지 없이 내부에 존재 가능
  ├─ 정상적인 관리자 계정 사용 (경보 없음)
  ├─ 작은 양의 데이터를 천천히 유출
  └─ 신뢰할 수 있는 서비스처럼 위장

헌팅 사이클:
가설 수립 → 데이터 수집 → 패턴 분석 → 침해 지표(IoC) 발견 → 대응
     ↑___________________________________|
                   피드백 루프
```

### 핵심 개념 정리

```
주요 용어:
- 위협 헌팅(Threat Hunting): 가설 기반으로 숨겨진 위협을 능동적으로 탐지하는 활동
- IoC(Indicator of Compromise): 침해를 나타내는 지표 (IP, 도메인, 파일 해시 등)
- TTP(Tactics, Techniques, Procedures): 공격자의 전술·기법·절차 체계
- MITRE ATT&CK for Cloud: 클라우드 환경 공격 기법 분류 프레임워크
- 피벗팅(Pivoting): 한 침해 지점에서 연관된 다른 자산으로 조사 확장
- 베이스라인(Baseline): 정상 활동 기준선 - 이상값 탐지의 기준
- UEBA(User and Entity Behavior Analytics): 사용자·엔티티 행동 이상 탐지
```

### 필요한 도구 및 환경
- **Jupyter Notebook**: 대화형 로그 분석 환경
- **Python 3.10+**: pandas, matplotlib (로그 분석·시각화)
- **Sigma Rules**: 클라우드 위협 탐지 규칙 프레임워크
- **MITRE ATT&CK Navigator**: 클라우드 공격 기법 매핑 도구

### 기초 실습 예제
```python
import json
from collections import defaultdict, Counter
from datetime import datetime

def cloud_threat_hunting_demo():
    """
    클라우드 위협 헌팅 시뮬레이션
    샘플 CloudTrail 로그에서 이상 패턴 탐지
    """

    # 샘플 클라우드 활동 로그 (실제 환경: CloudTrail/Audit Log JSON)
    sample_logs = [
        {"time": "2025-01-15T00:01:00Z", "user": "alice", "action": "S3:GetObject",    "ip": "10.0.1.5",     "region": "us-east-1"},
        {"time": "2025-01-15T00:02:00Z", "user": "alice", "action": "S3:GetObject",    "ip": "10.0.1.5",     "region": "us-east-1"},
        {"time": "2025-01-15T02:15:00Z", "user": "alice", "action": "ConsoleLogin",    "ip": "203.0.113.42", "region": "us-east-1"},  # 새벽 해외 IP
        {"time": "2025-01-15T02:16:00Z", "user": "alice", "action": "IAM:CreateKey",   "ip": "203.0.113.42", "region": "us-east-1"},  # 의심
        {"time": "2025-01-15T02:17:00Z", "user": "alice", "action": "S3:ListBuckets",  "ip": "203.0.113.42", "region": "us-east-1"},
        {"time": "2025-01-15T02:18:00Z", "user": "alice", "action": "S3:GetObject",    "ip": "203.0.113.42", "region": "us-east-1"},
        {"time": "2025-01-15T02:18:10Z", "user": "alice", "action": "S3:GetObject",    "ip": "203.0.113.42", "region": "us-east-1"},
        {"time": "2025-01-15T02:18:20Z", "user": "alice", "action": "S3:GetObject",    "ip": "203.0.113.42", "region": "us-east-1"},  # 대량 조회
        {"time": "2025-01-15T02:19:00Z", "user": "alice", "action": "EC2:RunInstances","ip": "203.0.113.42", "region": "ap-southeast-1"},  # 다른 리전
        {"time": "2025-01-15T09:00:00Z", "user": "bob",   "action": "S3:GetObject",    "ip": "10.0.1.8",     "region": "us-east-1"},
    ]

    print("=== 클라우드 위협 헌팅 분석 ===\n")

    # ── 헌팅 가설 1: 새벽 시간 해외 IP 로그인 ──
    print("[가설 1] 비정상 시간대 + 비정상 IP에서의 로그인")
    for log in sample_logs:
        hour = int(log["time"][11:13])
        is_external = not log["ip"].startswith("10.")
        if log["action"] == "ConsoleLogin" and is_external and (hour < 6 or hour > 22):
            print(f"  발견: {log['user']} | {log['time']} | IP: {log['ip']} [비업무시간 외부 IP]")

    # ── 헌팅 가설 2: 로그인 직후 IAM 키 생성 (백도어) ──
    print("\n[가설 2] 로그인 후 5분 내 IAM 키 생성 (백도어 심기)")
    user_login_time = {}
    for log in sorted(sample_logs, key=lambda x: x["time"]):
        if log["action"] == "ConsoleLogin":
            user_login_time[log["user"]] = log["time"]
        elif log["action"] == "IAM:CreateKey" and log["user"] in user_login_time:
            login_t = datetime.fromisoformat(user_login_time[log["user"]].replace("Z", "+00:00"))
            action_t = datetime.fromisoformat(log["time"].replace("Z", "+00:00"))
            diff_min = (action_t - login_t).seconds / 60
            if diff_min < 5:
                print(f"  발견: {log['user']} | 로그인 {diff_min:.1f}분 후 키 생성 | IP: {log['ip']}")

    # ── 헌팅 가설 3: S3 대량 접근 (데이터 유출) ──
    print("\n[가설 3] 단일 IP에서 S3 대량 접근 (데이터 유출)")
    ip_s3_count = Counter(
        log["ip"] for log in sample_logs
        if "S3:Get" in log["action"]
    )
    for ip, count in ip_s3_count.items():
        if count >= 3:
            external = "외부" if not ip.startswith("10.") else "내부"
            flag = " ← 의심" if not ip.startswith("10.") else ""
            print(f"  IP {ip} ({external}): S3 접근 {count}회{flag}")

    # ── 헌팅 가설 4: 멀티 리전 활동 ──
    print("\n[가설 4] 동일 세션에서 여러 리전 활동 (측면 이동)")
    user_regions = defaultdict(set)
    for log in sample_logs:
        if not log["ip"].startswith("10."):  # 외부 IP만
            user_regions[f"{log['user']}@{log['ip']}"].add(log["region"])
    for user_ip, regions in user_regions.items():
        if len(regions) > 1:
            print(f"  발견: {user_ip} → 리전: {regions} [멀티 리전 활동]")

    print("\n헌팅 완료: 발견된 침해 지표를 MITRE ATT&CK에 매핑 후 대응 권고서 작성")

cloud_threat_hunting_demo()
```

---

## 1. 클라우드 위협 헌팅 방법론

위협 헌팅(Threat Hunting)은 자동화된 탐지 시스템이 놓칠 수 있는 고도화된 위협을 능동적으로 찾아내는 활동이다. 클라우드 환경에서는 API 이벤트와 로그가 주요 헌팅 데이터 소스가 된다.

| 방법론 | 설명 | 적합한 환경 | 주요 도구 |
|--------|------|-----------|---------|
| 가설 기반 헌팅 | 공격 시나리오 가설 수립 후 증거 탐색 | 성숙한 SOC 환경 | SIEM, 헌팅 플랫폼 |
| 지표 기반 헌팅 | 알려진 IOC(IP/도메인/해시) 활용 | 위협 인텔리전스 보유 환경 | TIP 연동 SIEM |
| TTP 기반 헌팅 | MITRE ATT&CK 기반 전술/기법 탐색 | 고급 분석 역량 보유 | Sigma, KQL, SPL |
| 이상 탐지 기반 | ML/통계 기반 베이스라인 이탈 탐지 | 충분한 로그 데이터 | UEBA, 머신러닝 |
| 데이터 스택 헌팅 | 집계/통계로 이상 패턴 발굴 | 대용량 로그 환경 | BigQuery, Athena, Spark |

### 1.1 클라우드 헌팅 프로세스

| 단계 | 활동 | 산출물 |
|------|------|--------|
| 1. 목적 정의 | 헌팅 대상 위협 유형 결정 | 헌팅 목표 문서 |
| 2. 가설 수립 | "공격자가 X를 했다면 Y가 관찰될 것" | 탐지 가설 목록 |
| 3. 데이터 수집 | 관련 로그 소스 식별 및 수집 | 정제된 데이터셋 |
| 4. 분석 및 탐색 | 쿼리/시각화/통계 분석 | 의심 이벤트 목록 |
| 5. 검증 | 탐지된 이벤트 진양성 확인 | 확인된 위협 보고서 |
| 6. 대응 | IR 팀 에스컬레이션 | 사고 대응 요청 |
| 7. 탐지 규칙화 | 재사용 가능한 탐지 규칙 생성 | SIEM 규칙, Sigma |

---

## 2. 멀티클라우드 환경 통합 모니터링

단일 클라우드를 넘어 멀티클라우드(AWS + Azure + GCP)를 동시에 운영하는 조직은 각 플랫폼의 로그를 통합하는 SIEM이나 데이터 레이크가 필수적이다.

| 통합 방법 | 설명 | 장점 | 단점 |
|---------|------|------|------|
| 클라우드 네이티브 SIEM | Microsoft Sentinel, Chronicle Security | 깊은 네이티브 통합 | 특정 CSP에 종속 |
| 오픈소스 SIEM | Elastic SIEM, OpenSearch | 비용 효율, 커스터마이징 | 운영 부담 |
| 상용 SIEM | Splunk, QRadar, LogRhythm | 성숙한 기능셋 | 높은 라이선스 비용 |
| 데이터 레이크 헌팅 | Athena + S3, BigQuery | 대용량 저비용 분석 | 실시간성 낮음 |
| XDR 플랫폼 | CrowdStrike, Palo Alto Cortex | 엔드포인트+클라우드 통합 | 에이전트 종속 |

### 2.1 통합 로그 스키마 설계

멀티클라우드 환경에서 로그를 통합 분석하려면 공통 스키마로 정규화가 필요하다.

| 공통 필드 | AWS 소스 필드 | Azure 소스 필드 | GCP 소스 필드 |
|---------|------------|--------------|------------|
| timestamp | eventTime | time | timestamp |
| source_ip | sourceIPAddress | claims.ipaddr | protoPayload.requestMetadata.callerIp |
| principal | userIdentity.userName | caller | protoPayload.authenticationInfo.principalEmail |
| action | eventName | operationName.value | protoPayload.methodName |
| resource | resources[].ARN | resourceId | protoPayload.resourceName |
| status | errorCode (null=성공) | status.value | protoPayload.status.code (0=성공) |
| region | awsRegion | location | resource.labels.location |
| service | eventSource | operationName (prefix) | protoPayload.serviceName |

---

## 3. MITRE ATT&CK Cloud Matrix 주요 기법

| 전술 | 기법 ID | 기법명 | AWS 탐지 | Azure 탐지 | GCP 탐지 |
|------|--------|--------|---------|----------|---------|
| 초기 접근 | T1078.004 | 유효 클라우드 계정 | 비정상 리전/시간 로그인 | Impossible Travel | SA 키 비정상 사용 |
| 초기 접근 | T1190 | 퍼블릭 애플리케이션 취약점 | WAF 로그 | App Gateway 로그 | Cloud Armor 로그 |
| 실행 | T1059.009 | Cloud API | CloudTrail API 호출 | Activity Log | Cloud Audit Log |
| 실행 | T1648 | 서버리스 함수 실행 | Lambda Invoke | Function App | Cloud Functions |
| 지속성 | T1098.001 | 추가 클라우드 자격증명 | CreateAccessKey | addPassword | CreateServiceAccountKey |
| 지속성 | T1136.003 | 클라우드 계정 생성 | CreateUser | 게스트 초대 | CreateServiceAccount |
| 권한 에스컬레이션 | T1548 | 임시 고권한 획득 | AssumeRole | PIM 활성화 | generateAccessToken |
| 권한 에스컬레이션 | T1078.004 | 유효 계정 남용 | 루트 계정 활동 | 글로벌 관리자 | 오너 역할 사용 |
| 방어 우회 | T1562.008 | 클라우드 로깅 비활성화 | StopLogging | DeleteDiagnosticSetting | DeleteSink |
| 자격증명 접근 | T1552.005 | 클라우드 인스턴스 메타데이터 | IMDS 접근 | IMDS 접근 | Metadata Server |
| 자격증명 접근 | T1555 | 자격증명 저장소 | SecretsManager | Key Vault | Secret Manager |
| 횡이동 | T1550.001 | 앱 액세스 토큰 | AssumeRole 체인 | 서비스 주체 토큰 | SA 역할 사칭 |
| 수집 | T1530 | 클라우드 스토리지 오브젝트 | S3 GetObject | Blob 다운로드 | GCS 객체 읽기 |
| 유출 | T1537 | 클라우드 계정으로 전송 | S3 퍼블릭 복사 | 퍼블릭 컨테이너 | GCS allUsers |
| 영향 | T1485 | 데이터 파괴 | DeleteBucket | DeleteResourceGroup | DeleteBucket |
| 영향 | T1486 | 데이터 암호화(랜섬) | KMS 키 삭제 | Key Vault 키 삭제 | KMS 키 비활성화 |

---

## 4. Python CLI: 멀티클라우드 위협 헌팅 대시보드 데이터 수집기

```python
#!/usr/bin/env python3
"""
멀티클라우드 위협 헌팅 대시보드 데이터 수집기
- AWS/Azure/GCP 로그를 통합 스키마로 정규화한다.
- concurrent.futures로 병렬 수집을 수행한다.
- SIEM 연동을 위한 JSON 출력을 생성한다.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed, Future
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable
import uuid


# ── 통합 스키마 정의 ──────────────────────────────────────────────────────────

@dataclass
class NormalizedEvent:
    """멀티클라우드 통합 이벤트 스키마"""
    event_id: str
    timestamp: str           # ISO 8601 UTC
    provider: str            # aws / azure / gcp
    service: str             # 원본 서비스명
    action: str              # API 호출 / 작업명
    principal: str           # 사용자/계정/SA
    principal_type: str      # user / service_account / role / root
    source_ip: str
    region: str
    resource: str
    status: str              # success / failure
    error_code: str
    raw_severity: str        # 원본 심각도
    tags: list[str]          # ATT&CK 전술 태그
    raw_event: dict[str, Any] = field(default_factory=dict)

    def to_siem_dict(self) -> dict[str, Any]:
        """SIEM 연동용 딕셔너리 (raw_event 제외)"""
        d = asdict(self)
        d.pop("raw_event", None)
        return d


# ── 제공자별 파서 ─────────────────────────────────────────────────────────────

class AWSLogParser:
    """AWS CloudTrail 로그 파서 (통합 스키마로 정규화)"""

    # 전술 태그 매핑
    TACTIC_MAP: dict[str, list[str]] = {
        "CreateUser": ["T1136.003", "persistence"],
        "CreateAccessKey": ["T1098.001", "persistence"],
        "AttachUserPolicy": ["T1548", "privilege_escalation"],
        "AttachRolePolicy": ["T1548", "privilege_escalation"],
        "AssumeRole": ["T1550.001", "lateral_movement"],
        "StopLogging": ["T1562.008", "defense_evasion"],
        "DeleteTrail": ["T1562.008", "defense_evasion"],
        "GetSecretValue": ["T1555", "credential_access"],
        "PutBucketAcl": ["T1530", "collection"],
        "TerminateInstances": ["T1485", "impact"],
        "ScheduleKeyDeletion": ["T1486", "impact"],
    }

    def parse_record(self, record: dict[str, Any]) -> NormalizedEvent:
        identity = record.get("userIdentity", {})
        user_type = identity.get("type", "")
        user_name = identity.get("userName", identity.get("principalId", "unknown"))

        principal_type_map = {
            "Root": "root",
            "IAMUser": "user",
            "AssumedRole": "role",
            "FederatedUser": "federated",
            "Service": "service_account",
        }

        event_name = record.get("eventName", "")
        tags = self.TACTIC_MAP.get(event_name, [])

        return NormalizedEvent(
            event_id=record.get("eventID", str(uuid.uuid4())),
            timestamp=record.get("eventTime", ""),
            provider="aws",
            service=record.get("eventSource", ""),
            action=event_name,
            principal=user_name,
            principal_type=principal_type_map.get(user_type, "unknown"),
            source_ip=record.get("sourceIPAddress", ""),
            region=record.get("awsRegion", ""),
            resource=";".join(
                r.get("ARN", "") for r in record.get("resources", [])
            ),
            status="failure" if record.get("errorCode") else "success",
            error_code=record.get("errorCode", ""),
            raw_severity="INFO",
            tags=tags,
            raw_event=record,
        )

    def parse_file(self, path: Path) -> list[NormalizedEvent]:
        """CloudTrail JSON 파일 파싱"""
        import gzip
        try:
            if path.suffix == ".gz":
                with gzip.open(path, "rt", encoding="utf-8") as fh:
                    data = json.load(fh)
            else:
                data = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            print(f"[AWS 파서] 파일 파싱 실패 {path}: {exc}", file=sys.stderr)
            return []

        records = data.get("Records", []) if isinstance(data, dict) else data
        events: list[NormalizedEvent] = []
        for rec in records:
            try:
                events.append(self.parse_record(rec))
            except Exception as exc:
                print(f"[AWS 파서] 레코드 오류: {exc}", file=sys.stderr)
        return events


class AzureLogParser:
    """Azure Activity Log 파서 (통합 스키마로 정규화)"""

    TACTIC_MAP: dict[str, list[str]] = {
        "roleassignments/write": ["T1548", "privilege_escalation"],
        "roledefinitions/write": ["T1548", "privilege_escalation"],
        "diagnosticsettings/delete": ["T1562.008", "defense_evasion"],
        "vaults/secrets": ["T1555", "credential_access"],
        "applications/addpassword": ["T1098.001", "persistence"],
        "virtualMachines/extensions/write": ["T1059.009", "execution"],
        "resourcegroups/delete": ["T1485", "impact"],
    }

    def _get_tags(self, operation_name: str) -> list[str]:
        op_lower = operation_name.lower()
        for pattern, tags in self.TACTIC_MAP.items():
            if pattern.lower() in op_lower:
                return tags
        return []

    def parse_record(self, record: dict[str, Any]) -> NormalizedEvent:
        op_name = record.get("operationName", {})
        if isinstance(op_name, dict):
            op_name = op_name.get("value", "")

        status = record.get("status", {})
        if isinstance(status, dict):
            status = status.get("value", "Succeeded")

        claims = record.get("claims", {})
        source_ip = claims.get("ipaddr", "")

        time_str = record.get("time", record.get("eventTimestamp", ""))
        caller = record.get("caller", "unknown")

        # 호출자 유형 분류
        if "#" in caller:
            principal_type = "service_principal"
        elif "@" in caller:
            principal_type = "user"
        else:
            principal_type = "unknown"

        return NormalizedEvent(
            event_id=record.get("correlationId", str(uuid.uuid4())),
            timestamp=time_str,
            provider="azure",
            service=op_name.split("/")[0] if "/" in op_name else op_name,
            action=op_name,
            principal=caller,
            principal_type=principal_type,
            source_ip=source_ip,
            region=record.get("location", ""),
            resource=record.get("resourceId", ""),
            status="success" if "succeeded" in status.lower() else "failure",
            error_code="" if "succeeded" in status.lower() else status,
            raw_severity=record.get("level", ""),
            tags=self._get_tags(op_name),
            raw_event=record,
        )

    def parse_file(self, path: Path) -> list[NormalizedEvent]:
        """Azure Activity Log JSON 파일 파싱"""
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            print(f"[Azure 파서] 파일 파싱 실패 {path}: {exc}", file=sys.stderr)
            return []

        records = raw if isinstance(raw, list) else raw.get("value", [raw])
        events: list[NormalizedEvent] = []
        for rec in records:
            try:
                events.append(self.parse_record(rec))
            except Exception as exc:
                print(f"[Azure 파서] 레코드 오류: {exc}", file=sys.stderr)
        return events


class GCPLogParser:
    """GCP Cloud Audit Log 파서 (통합 스키마로 정규화)"""

    TACTIC_MAP: dict[str, list[str]] = {
        "CreateServiceAccountKey": ["T1098.001", "persistence"],
        "SetIamPolicy": ["T1548", "privilege_escalation"],
        "DeleteSink": ["T1562.008", "defense_evasion"],
        "AccessSecretVersion": ["T1555", "credential_access"],
        "CreateFunction": ["T1648", "execution"],
        "GenerateAccessToken": ["T1550.001", "lateral_movement"],
    }

    def _get_tags(self, method_name: str) -> list[str]:
        short = method_name.split(".")[-1] if method_name else ""
        return self.TACTIC_MAP.get(short, [])

    def parse_record(self, record: dict[str, Any]) -> NormalizedEvent:
        proto = record.get("protoPayload", {})
        req_meta = proto.get("requestMetadata", {})
        auth_info = proto.get("authenticationInfo", {})
        resource = record.get("resource", {})
        labels = resource.get("labels", {})

        principal = auth_info.get("principalEmail", "unknown")
        principal_type = (
            "service_account"
            if principal.endswith(".gserviceaccount.com")
            else "user"
        )

        ts = record.get("timestamp", record.get("receiveTimestamp", ""))
        status = proto.get("status", {})
        status_code = status.get("code", 0) if isinstance(status, dict) else 0

        return NormalizedEvent(
            event_id=record.get("insertId", str(uuid.uuid4())),
            timestamp=ts,
            provider="gcp",
            service=proto.get("serviceName", ""),
            action=proto.get("methodName", ""),
            principal=principal,
            principal_type=principal_type,
            source_ip=req_meta.get("callerIp", ""),
            region=labels.get("location", labels.get("zone", "")),
            resource=proto.get("resourceName", ""),
            status="success" if status_code == 0 else "failure",
            error_code="" if status_code == 0 else str(status_code),
            raw_severity=record.get("severity", ""),
            tags=self._get_tags(proto.get("methodName", "")),
            raw_event=record,
        )

    def parse_file(self, path: Path) -> list[NormalizedEvent]:
        """GCP Cloud Audit Log JSON Lines 파일 파싱"""
        events: list[NormalizedEvent] = []
        try:
            content = path.read_text(encoding="utf-8")
        except OSError as exc:
            print(f"[GCP 파서] 파일 읽기 실패 {path}: {exc}", file=sys.stderr)
            return []

        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
                events.append(self.parse_record(record))
            except Exception as exc:
                print(f"[GCP 파서] 레코드 오류: {exc}", file=sys.stderr)
        return events


# ── 수집 작업 ─────────────────────────────────────────────────────────────────

@dataclass
class CollectionJob:
    """단일 수집 작업 정의"""
    provider: str
    log_file: Path
    parser: AWSLogParser | AzureLogParser | GCPLogParser


@dataclass
class CollectionResult:
    """수집 작업 결과"""
    provider: str
    log_file: Path
    events: list[NormalizedEvent]
    duration_sec: float
    error: str | None = None


def run_collection_job(job: CollectionJob) -> CollectionResult:
    """단일 수집 작업 실행 (스레드에서 호출)"""
    start = time.monotonic()
    try:
        events = job.parser.parse_file(job.log_file)
        duration = time.monotonic() - start
        return CollectionResult(
            provider=job.provider,
            log_file=job.log_file,
            events=events,
            duration_sec=duration,
        )
    except Exception as exc:
        duration = time.monotonic() - start
        return CollectionResult(
            provider=job.provider,
            log_file=job.log_file,
            events=[],
            duration_sec=duration,
            error=str(exc),
        )


# ── 헌팅 로직 ─────────────────────────────────────────────────────────────────

@dataclass
class ThreatHuntingResult:
    """위협 헌팅 결과"""
    collection_time: str
    providers: list[str]
    lookback_hours: int
    total_events: int
    events_by_provider: dict[str, int]
    suspicious_events: list[dict[str, Any]]
    tactic_summary: dict[str, int]
    top_principals: list[dict[str, Any]]
    top_source_ips: list[dict[str, Any]]
    collection_stats: list[dict[str, Any]]


def filter_by_lookback(
    events: list[NormalizedEvent],
    lookback_hours: int,
) -> list[NormalizedEvent]:
    """lookback 시간 기준 이벤트 필터링"""
    cutoff = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)
    result: list[NormalizedEvent] = []
    for event in events:
        try:
            ts = datetime.fromisoformat(event.timestamp.replace("Z", "+00:00"))
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            if ts >= cutoff:
                result.append(event)
        except (ValueError, AttributeError):
            result.append(event)  # 파싱 실패 시 포함
    return result


def identify_suspicious_events(events: list[NormalizedEvent]) -> list[NormalizedEvent]:
    """ATT&CK 태그 기반 의심 이벤트 필터링"""
    return [e for e in events if e.tags]


def aggregate_results(
    all_events: list[NormalizedEvent],
    collection_stats: list[dict[str, Any]],
    providers: list[str],
    lookback_hours: int,
) -> ThreatHuntingResult:
    """수집 결과 집계"""
    now = datetime.now(timezone.utc).isoformat()

    events_by_provider: dict[str, int] = {}
    for event in all_events:
        events_by_provider[event.provider] = (
            events_by_provider.get(event.provider, 0) + 1
        )

    suspicious = identify_suspicious_events(all_events)

    tactic_summary: dict[str, int] = {}
    for event in suspicious:
        for tag in event.tags:
            tactic_summary[tag] = tactic_summary.get(tag, 0) + 1

    # 상위 주체 (의심 이벤트 기준)
    principal_counts: dict[str, int] = {}
    for event in suspicious:
        principal_counts[event.principal] = (
            principal_counts.get(event.principal, 0) + 1
        )
    top_principals = [
        {"principal": p, "count": c, "provider": ""}
        for p, c in sorted(principal_counts.items(), key=lambda x: -x[1])[:10]
    ]
    # 제공자 추가
    principal_providers: dict[str, set[str]] = {}
    for event in suspicious:
        principal_providers.setdefault(event.principal, set()).add(event.provider)
    for entry in top_principals:
        entry["provider"] = ",".join(sorted(principal_providers.get(entry["principal"], set())))

    # 상위 소스 IP
    ip_counts: dict[str, int] = {}
    for event in suspicious:
        if event.source_ip and not event.source_ip.lower().startswith("aws"):
            ip_counts[event.source_ip] = ip_counts.get(event.source_ip, 0) + 1
    top_ips = [
        {"ip": ip, "count": cnt}
        for ip, cnt in sorted(ip_counts.items(), key=lambda x: -x[1])[:10]
    ]

    return ThreatHuntingResult(
        collection_time=now,
        providers=providers,
        lookback_hours=lookback_hours,
        total_events=len(all_events),
        events_by_provider=events_by_provider,
        suspicious_events=[e.to_siem_dict() for e in suspicious],
        tactic_summary=tactic_summary,
        top_principals=top_principals,
        top_source_ips=top_ips,
        collection_stats=collection_stats,
    )


def save_results(result: ThreatHuntingResult, output_dir: Path) -> None:
    """결과를 JSON 파일로 저장"""
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    # 전체 요약 JSON
    summary_path = output_dir / f"hunt_summary_{timestamp}.json"
    summary_data = {
        "collection_time": result.collection_time,
        "providers": result.providers,
        "lookback_hours": result.lookback_hours,
        "total_events": result.total_events,
        "events_by_provider": result.events_by_provider,
        "suspicious_event_count": len(result.suspicious_events),
        "tactic_summary": result.tactic_summary,
        "top_principals": result.top_principals,
        "top_source_ips": result.top_source_ips,
        "collection_stats": result.collection_stats,
    }
    summary_path.write_text(json.dumps(summary_data, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[완료] 요약 저장: {summary_path}")

    # 의심 이벤트 JSON Lines (SIEM 연동용)
    if result.suspicious_events:
        siem_path = output_dir / f"hunt_suspicious_{timestamp}.jsonl"
        lines = [
            json.dumps(evt, ensure_ascii=False)
            for evt in result.suspicious_events
        ]
        siem_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        print(f"[완료] 의심 이벤트 저장: {siem_path} ({len(result.suspicious_events)}건)")


def print_hunt_report(result: ThreatHuntingResult) -> None:
    """콘솔 헌팅 보고서 출력"""
    print(f"\n{'=' * 80}")
    print(f" 멀티클라우드 위협 헌팅 결과")
    print(f"{'=' * 80}")
    print(f"  수집 시각:     {result.collection_time}")
    print(f"  대상 제공자:   {', '.join(result.providers)}")
    print(f"  조회 기간:     최근 {result.lookback_hours}시간")
    print(f"  전체 이벤트:   {result.total_events:,}")
    print(f"  의심 이벤트:   {len(result.suspicious_events):,}")

    print(f"\n  제공자별 이벤트:")
    for provider, cnt in result.events_by_provider.items():
        print(f"    {provider.upper():8s}: {cnt:,}")

    if result.tactic_summary:
        print(f"\n  ATT&CK 전술/기법 탐지:")
        for tactic, cnt in sorted(result.tactic_summary.items(), key=lambda x: -x[1]):
            print(f"    {tactic:30s}: {cnt:,}건")

    if result.top_principals:
        print(f"\n  의심 이벤트 상위 주체:")
        for entry in result.top_principals[:5]:
            print(
                f"    [{entry['provider']:12s}] {entry['principal']:50s} "
                f"{entry['count']:,}건"
            )

    if result.top_source_ips:
        print(f"\n  의심 이벤트 상위 소스 IP:")
        for entry in result.top_source_ips[:5]:
            print(f"    {entry['ip']:20s}: {entry['count']:,}건")

    print(f"\n  수집 통계:")
    for stat in result.collection_stats:
        status = "오류" if stat.get("error") else "성공"
        print(
            f"    [{stat['provider'].upper():5s}] {stat['file']:40s} "
            f"{stat['events']:,}건 | {stat['duration_sec']:.2f}초 | {status}"
        )
    print()


# ── CLI 진입점 ────────────────────────────────────────────────────────────────

def discover_log_files(
    provider: str,
    log_dir: Path | None,
    log_files: list[Path],
) -> list[Path]:
    """지정된 디렉토리에서 제공자 로그 파일 자동 탐색"""
    found: list[Path] = list(log_files)
    if log_dir and log_dir.is_dir():
        extensions = [".json", ".jsonl", ".json.gz"]
        for ext in extensions:
            found.extend(log_dir.glob(f"*{ext}"))
    return found


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cloud_threat_hunter",
        description=(
            "멀티클라우드 위협 헌팅 대시보드 데이터 수집기\n"
            "AWS/Azure/GCP 로그를 병렬 수집하여 통합 스키마로 정규화한다."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
사용 예:
  %(prog)s --providers aws azure gcp --aws-log-file cloudtrail.json.gz --azure-log-file activity.json --gcp-log-file audit.jsonl
  %(prog)s --providers aws --aws-log-dir /logs/aws --lookback-hours 48 --output-dir ./hunt_results
  %(prog)s --providers aws azure --aws-log-file trail.json --azure-log-file activity.json --output-dir ./output
        """,
    )
    parser.add_argument(
        "--providers", "-p",
        nargs="+",
        choices=["aws", "azure", "gcp"],
        required=True,
        help="수집 대상 클라우드 제공자 목록",
    )
    parser.add_argument(
        "--lookback-hours",
        dest="lookback_hours",
        type=int,
        default=24,
        help="조회 기간 (시간 단위, 기본값: 24)",
    )
    parser.add_argument(
        "--output-dir",
        dest="output_dir",
        type=Path,
        default=Path("."),
        help="결과 저장 디렉토리 (기본값: 현재 디렉토리)",
    )
    # AWS 로그 소스
    parser.add_argument(
        "--aws-log-file",
        dest="aws_log_files",
        nargs="+",
        type=Path,
        default=[],
        help="AWS CloudTrail 로그 파일 경로",
    )
    parser.add_argument(
        "--aws-log-dir",
        dest="aws_log_dir",
        type=Path,
        default=None,
        help="AWS CloudTrail 로그 디렉토리 (파일 자동 탐색)",
    )
    # Azure 로그 소스
    parser.add_argument(
        "--azure-log-file",
        dest="azure_log_files",
        nargs="+",
        type=Path,
        default=[],
        help="Azure Activity Log JSON 파일 경로",
    )
    parser.add_argument(
        "--azure-log-dir",
        dest="azure_log_dir",
        type=Path,
        default=None,
        help="Azure 로그 디렉토리",
    )
    # GCP 로그 소스
    parser.add_argument(
        "--gcp-log-file",
        dest="gcp_log_files",
        nargs="+",
        type=Path,
        default=[],
        help="GCP Cloud Audit Log JSON Lines 파일 경로",
    )
    parser.add_argument(
        "--gcp-log-dir",
        dest="gcp_log_dir",
        type=Path,
        default=None,
        help="GCP 로그 디렉토리",
    )
    parser.add_argument(
        "--max-workers",
        dest="max_workers",
        type=int,
        default=4,
        help="병렬 수집 스레드 수 (기본값: 4)",
    )
    parser.add_argument(
        "--no-save",
        action="store_true",
        help="결과 파일 저장 건너뜀 (콘솔 출력만)",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    # 수집 작업 목록 구성
    jobs: list[CollectionJob] = []

    provider_config = {
        "aws": {
            "files": args.aws_log_files,
            "log_dir": args.aws_log_dir,
            "parser": AWSLogParser(),
        },
        "azure": {
            "files": args.azure_log_files,
            "log_dir": args.azure_log_dir,
            "parser": AzureLogParser(),
        },
        "gcp": {
            "files": args.gcp_log_files,
            "log_dir": args.gcp_log_dir,
            "parser": GCPLogParser(),
        },
    }

    for provider in args.providers:
        cfg = provider_config[provider]
        log_files = discover_log_files(
            provider,
            cfg["log_dir"],
            cfg["files"],
        )
        if not log_files:
            print(
                f"[경고] {provider.upper()} 로그 파일이 없습니다. "
                f"--{provider}-log-file 또는 --{provider}-log-dir을 지정하세요.",
                file=sys.stderr,
            )
            continue
        for lf in log_files:
            jobs.append(CollectionJob(
                provider=provider,
                log_file=lf,
                parser=cfg["parser"],
            ))

    if not jobs:
        print("[오류] 수집할 로그 파일이 없습니다.", file=sys.stderr)
        sys.exit(1)

    print(f"[정보] {len(jobs)}개 수집 작업을 {args.max_workers}개 스레드로 병렬 실행...")

    # 병렬 수집 실행
    all_events: list[NormalizedEvent] = []
    collection_stats: list[dict[str, Any]] = []

    with ThreadPoolExecutor(max_workers=args.max_workers) as executor:
        future_to_job: dict[Future, CollectionJob] = {
            executor.submit(run_collection_job, job): job
            for job in jobs
        }

        for future in as_completed(future_to_job):
            job = future_to_job[future]
            try:
                result = future.result()
            except Exception as exc:
                print(f"[오류] {job.provider}/{job.log_file.name}: {exc}", file=sys.stderr)
                collection_stats.append({
                    "provider": job.provider,
                    "file": str(job.log_file),
                    "events": 0,
                    "duration_sec": 0.0,
                    "error": str(exc),
                })
                continue

            if result.error:
                print(f"[오류] {result.provider}/{result.log_file.name}: {result.error}", file=sys.stderr)
            else:
                # lookback 필터 적용
                filtered = filter_by_lookback(result.events, args.lookback_hours)
                all_events.extend(filtered)
                print(
                    f"[완료] {result.provider.upper():5s} {result.log_file.name:40s} "
                    f"{len(filtered):,}/{len(result.events):,}건 ({result.duration_sec:.2f}초)"
                )

            collection_stats.append({
                "provider": result.provider,
                "file": str(result.log_file),
                "events": len(result.events),
                "duration_sec": round(result.duration_sec, 3),
                "error": result.error,
            })

    print(f"\n[정보] 총 {len(all_events):,}개 이벤트 수집 완료")

    # 결과 집계
    hunt_result = aggregate_results(
        all_events,
        collection_stats,
        args.providers,
        args.lookback_hours,
    )

    # 콘솔 보고서 출력
    print_hunt_report(hunt_result)

    # 파일 저장
    if not args.no_save:
        args.output_dir.mkdir(parents=True, exist_ok=True)
        save_results(hunt_result, args.output_dir)


if __name__ == "__main__":
    main()
```

### 사용 방법

```bash
# AWS + Azure + GCP 통합 헌팅
python cloud_threat_hunter.py \
    --providers aws azure gcp \
    --aws-log-file cloudtrail.json.gz \
    --azure-log-file activity_log.json \
    --gcp-log-file audit.jsonl \
    --lookback-hours 48 \
    --output-dir ./hunt_results

# AWS만 디렉토리 기반 자동 탐색
python cloud_threat_hunter.py \
    --providers aws \
    --aws-log-dir /var/log/cloudtrail/ \
    --lookback-hours 24 \
    --output-dir ./aws_hunt

# 스레드 수 조정 (대용량 처리)
python cloud_threat_hunter.py \
    --providers aws azure \
    --aws-log-file trail.json \
    --azure-log-file activity.json \
    --max-workers 8 \
    --output-dir ./output

# 파일 저장 없이 콘솔 출력만
python cloud_threat_hunter.py \
    --providers gcp \
    --gcp-log-file audit.jsonl \
    --no-save
```

---

## 5. 클라우드 위협 헌팅 쿼리 예시 모음

### 5.1 AWS Athena 헌팅 쿼리

```sql
-- IAM 자격증명 침해 가능성: 새로운 IP에서 처음 보는 사용자 활동
SELECT
    useridentity.username,
    sourceipaddress,
    COUNT(*) AS event_count,
    MIN(eventtime) AS first_seen,
    MAX(eventtime) AS last_seen,
    ARRAY_AGG(DISTINCT eventname) AS actions
FROM cloudtrail_logs
WHERE year = '2024' AND month = '01'
    AND useridentity.type = 'IAMUser'
    AND sourceipaddress NOT LIKE 'AWS%'
GROUP BY useridentity.username, sourceipaddress
HAVING MIN(eventtime) > DATE_ADD('day', -7, NOW())
ORDER BY event_count DESC;
```

### 5.2 Microsoft Sentinel KQL 헌팅 쿼리

```kusto
// 멀티클라우드 자격증명 에스컬레이션 상관 분석
let timeWindow = 24h;
let suspiciousOps = AzureActivity
    | where TimeGenerated > ago(timeWindow)
    | where OperationNameValue in (
        "Microsoft.Authorization/roleAssignments/write",
        "Microsoft.Authorization/roleDefinitions/write"
    )
    | summarize OpCount = count() by Caller, bin(TimeGenerated, 1h)
    | where OpCount > 5;
suspiciousOps
| join kind=inner (
    SigninLogs
    | where TimeGenerated > ago(timeWindow)
    | where RiskLevelDuringSignIn in ("medium", "high")
) on $left.Caller == $right.UserPrincipalName
| project TimeGenerated, Caller, OpCount, RiskLevelDuringSignIn, IPAddress
| order by TimeGenerated desc
```

### 5.3 GCP BigQuery 헌팅 쿼리

```sql
-- 서비스 계정 이상 행동: 여러 프로젝트에서 동시 활동
SELECT
    protopayload_auditlog.authenticationinfo.principalemail AS sa_email,
    COUNT(DISTINCT resource.labels.project_id) AS project_count,
    COUNT(*) AS total_events,
    ARRAY_AGG(DISTINCT protopayload_auditlog.methodname LIMIT 10) AS methods
FROM `my-org.audit_logs.cloudaudit_googleapis_com_activity_*`
WHERE _TABLE_SUFFIX >= FORMAT_DATE('%Y%m%d', DATE_SUB(CURRENT_DATE(), INTERVAL 7 DAY))
    AND protopayload_auditlog.authenticationinfo.principalemail LIKE '%.gserviceaccount.com'
GROUP BY sa_email
HAVING project_count > 3
ORDER BY total_events DESC
LIMIT 20;
```

---

## 6. SIEM 연동 및 운영 고려사항

| 항목 | 권장 사항 |
|------|---------|
| 로그 수집 주기 | 실시간 스트리밍 또는 최대 5분 주기 |
| 데이터 보존 | 핫 스토리지 90일, 콜드 스토리지 1년 이상 |
| 탐지 규칙 업데이트 | 신규 CVE/TTP 반영하여 월 1회 이상 검토 |
| 오탐(False Positive) 관리 | 베이스라인 화이트리스트 정기 갱신 |
| 헌팅 주기 | 위험 환경 주 1회, 일반 환경 월 1회 |
| 결과 문서화 | 헌팅 노트북(Jupyter) 또는 위키에 기록 |
| 팀 역량 강화 | 시뮬레이션(Atomic Red Team) 정기 실행 |

---

<a name="english"></a>

# Cloud Threat Hunting

## 1. Cloud Threat Hunting Methodology

Threat Hunting is the proactive activity of seeking out advanced threats that automated detection systems may miss. In cloud environments, API events and logs serve as the primary hunting data sources.

| Methodology | Description | Suitable Environment | Key Tools |
|-------------|-------------|---------------------|-----------|
| Hypothesis-based Hunting | Formulate attack scenario hypothesis then search for evidence | Mature SOC environment | SIEM, hunting platforms |
| Indicator-based Hunting | Utilize known IOCs (IP/domain/hash) | Environments with threat intelligence | TIP-integrated SIEM |
| TTP-based Hunting | Search for tactics/techniques based on MITRE ATT&CK | Advanced analysis capability | Sigma, KQL, SPL |
| Anomaly Detection-based | ML/statistics-based baseline deviation detection | Sufficient log data | UEBA, machine learning |
| Data Stack Hunting | Discover anomalous patterns via aggregation/statistics | Large-scale log environments | BigQuery, Athena, Spark |

### 1.1 Cloud Hunting Process

| Stage | Activity | Deliverable |
|-------|----------|-------------|
| 1. Define Objective | Determine target threat type | Hunting objective document |
| 2. Form Hypothesis | "If attacker did X, Y would be observed" | Detection hypothesis list |
| 3. Data Collection | Identify and collect relevant log sources | Refined dataset |
| 4. Analysis | Query/visualization/statistical analysis | Suspicious event list |
| 5. Validation | Confirm true positives among detected events | Confirmed threat report |
| 6. Response | Escalate to IR team | Incident response request |
| 7. Rule Creation | Create reusable detection rules | SIEM rules, Sigma |

---

## 2. Multi-Cloud Integrated Monitoring

Organizations operating across AWS + Azure + GCP simultaneously require a SIEM or data lake to aggregate logs from each platform.

| Integration Method | Description | Advantages | Disadvantages |
|-------------------|-------------|------------|---------------|
| Cloud-native SIEM | Microsoft Sentinel, Chronicle Security | Deep native integration | Tied to specific CSP |
| Open-source SIEM | Elastic SIEM, OpenSearch | Cost-effective, customizable | Operational burden |
| Commercial SIEM | Splunk, QRadar, LogRhythm | Mature feature set | High license costs |
| Data Lake Hunting | Athena + S3, BigQuery | Large-scale low-cost analysis | Lower real-time capability |
| XDR Platform | CrowdStrike, Palo Alto Cortex | Endpoint + cloud integration | Agent dependency |

### 2.1 Unified Log Schema Design

To integrate and analyze logs across multi-cloud environments, normalization to a common schema is necessary.

| Common Field | AWS Source Field | Azure Source Field | GCP Source Field |
|-------------|-----------------|-------------------|-----------------|
| timestamp | eventTime | time | timestamp |
| source_ip | sourceIPAddress | claims.ipaddr | protoPayload.requestMetadata.callerIp |
| principal | userIdentity.userName | caller | protoPayload.authenticationInfo.principalEmail |
| action | eventName | operationName.value | protoPayload.methodName |
| resource | resources[].ARN | resourceId | protoPayload.resourceName |
| status | errorCode (null=success) | status.value | protoPayload.status.code (0=success) |
| region | awsRegion | location | resource.labels.location |
| service | eventSource | operationName (prefix) | protoPayload.serviceName |

---

## 3. Key Techniques from the MITRE ATT&CK Cloud Matrix

| Tactic | Technique ID | Technique Name | AWS Detection | Azure Detection | GCP Detection |
|--------|-------------|----------------|--------------|----------------|--------------|
| Initial Access | T1078.004 | Valid Cloud Accounts | Abnormal region/time login | Impossible Travel | SA key abnormal use |
| Initial Access | T1190 | Public Application Vulnerability | WAF logs | App Gateway logs | Cloud Armor logs |
| Execution | T1059.009 | Cloud API | CloudTrail API calls | Activity Log | Cloud Audit Log |
| Execution | T1648 | Serverless Function Execution | Lambda Invoke | Function App | Cloud Functions |
| Persistence | T1098.001 | Additional Cloud Credentials | CreateAccessKey | addPassword | CreateServiceAccountKey |
| Persistence | T1136.003 | Cloud Account Creation | CreateUser | Guest invitation | CreateServiceAccount |
| Privilege Escalation | T1548 | Temporary Elevated Privileges | AssumeRole | PIM activation | generateAccessToken |
| Privilege Escalation | T1078.004 | Valid Account Abuse | Root account activity | Global admin | Owner role usage |
| Defense Evasion | T1562.008 | Disable Cloud Logging | StopLogging | DeleteDiagnosticSetting | DeleteSink |
| Credential Access | T1552.005 | Cloud Instance Metadata | IMDS access | IMDS access | Metadata Server |
| Credential Access | T1555 | Credential Stores | SecretsManager | Key Vault | Secret Manager |
| Lateral Movement | T1550.001 | Application Access Token | AssumeRole chain | Service principal token | SA role impersonation |
| Collection | T1530 | Cloud Storage Objects | S3 GetObject | Blob download | GCS object read |
| Exfiltration | T1537 | Transfer to Cloud Account | S3 public copy | Public container | GCS allUsers |
| Impact | T1485 | Data Destruction | DeleteBucket | DeleteResourceGroup | DeleteBucket |
| Impact | T1486 | Data Encryption (Ransomware) | KMS key deletion | Key Vault key deletion | KMS key deactivation |

---

## 4. Python CLI: Multi-Cloud Threat Hunting Dashboard Data Collector

See the Korean section for the full Python code listing.

### Usage

```bash
# Integrated hunting across AWS + Azure + GCP
python cloud_threat_hunter.py \
    --providers aws azure gcp \
    --aws-log-file cloudtrail.json.gz \
    --azure-log-file activity_log.json \
    --gcp-log-file audit.jsonl \
    --lookback-hours 48 \
    --output-dir ./hunt_results

# AWS-only directory-based auto-discovery
python cloud_threat_hunter.py \
    --providers aws \
    --aws-log-dir /var/log/cloudtrail/ \
    --lookback-hours 24 \
    --output-dir ./aws_hunt

# Adjust thread count (for large-scale processing)
python cloud_threat_hunter.py \
    --providers aws azure \
    --aws-log-file trail.json \
    --azure-log-file activity.json \
    --max-workers 8 \
    --output-dir ./output

# Console output only, no file saving
python cloud_threat_hunter.py \
    --providers gcp \
    --gcp-log-file audit.jsonl \
    --no-save
```

---

## 5. Cloud Threat Hunting Query Examples

### 5.1 AWS Athena Hunting Queries

```sql
-- Potential IAM credential compromise: first-seen user activity from new IP
SELECT
    useridentity.username,
    sourceipaddress,
    COUNT(*) AS event_count,
    MIN(eventtime) AS first_seen,
    MAX(eventtime) AS last_seen,
    ARRAY_AGG(DISTINCT eventname) AS actions
FROM cloudtrail_logs
WHERE year = '2024' AND month = '01'
    AND useridentity.type = 'IAMUser'
    AND sourceipaddress NOT LIKE 'AWS%'
GROUP BY useridentity.username, sourceipaddress
HAVING MIN(eventtime) > DATE_ADD('day', -7, NOW())
ORDER BY event_count DESC;
```

### 5.2 Microsoft Sentinel KQL Hunting Queries

```kusto
// Multi-cloud credential escalation correlation analysis
let timeWindow = 24h;
let suspiciousOps = AzureActivity
    | where TimeGenerated > ago(timeWindow)
    | where OperationNameValue in (
        "Microsoft.Authorization/roleAssignments/write",
        "Microsoft.Authorization/roleDefinitions/write"
    )
    | summarize OpCount = count() by Caller, bin(TimeGenerated, 1h)
    | where OpCount > 5;
suspiciousOps
| join kind=inner (
    SigninLogs
    | where TimeGenerated > ago(timeWindow)
    | where RiskLevelDuringSignIn in ("medium", "high")
) on $left.Caller == $right.UserPrincipalName
| project TimeGenerated, Caller, OpCount, RiskLevelDuringSignIn, IPAddress
| order by TimeGenerated desc
```

### 5.3 GCP BigQuery Hunting Queries

```sql
-- Service account anomaly: simultaneous activity across multiple projects
SELECT
    protopayload_auditlog.authenticationinfo.principalemail AS sa_email,
    COUNT(DISTINCT resource.labels.project_id) AS project_count,
    COUNT(*) AS total_events,
    ARRAY_AGG(DISTINCT protopayload_auditlog.methodname LIMIT 10) AS methods
FROM `my-org.audit_logs.cloudaudit_googleapis_com_activity_*`
WHERE _TABLE_SUFFIX >= FORMAT_DATE('%Y%m%d', DATE_SUB(CURRENT_DATE(), INTERVAL 7 DAY))
    AND protopayload_auditlog.authenticationinfo.principalemail LIKE '%.gserviceaccount.com'
GROUP BY sa_email
HAVING project_count > 3
ORDER BY total_events DESC
LIMIT 20;
```

---

## 6. SIEM Integration and Operational Considerations

| Item | Recommendation |
|------|----------------|
| Log collection frequency | Real-time streaming or max 5-minute intervals |
| Data retention | 90 days hot storage, 1+ year cold storage |
| Detection rule updates | Review at least monthly to incorporate new CVEs/TTPs |
| False positive management | Regularly refresh baseline whitelist |
| Hunting frequency | High-risk environments weekly, general monthly |
| Result documentation | Record in hunting notebooks (Jupyter) or wiki |
| Team capability building | Run simulations (Atomic Red Team) regularly |
