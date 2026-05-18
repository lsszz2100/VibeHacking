# 05 — 위협 헌팅 프로그램 운영

## 목차
1. 위협 헌팅 프로그램 수립 및 거버넌스
2. 헌팅 인텔리전스 수집 체계
3. 데이터 파이프라인 및 플랫폼 구성
4. 헌팅 팀 역량 개발
5. 헌팅 결과 관리 및 피드백 루프
6. 산업별 특화 헌팅 시나리오
7. Python 도구: 헌팅 캠페인 관리 시스템
8. 헌팅 프로그램 성숙도 측정

---

## 1. 위협 헌팅 프로그램 수립 및 거버넌스

### 1.1 헌팅 프로그램 3가지 모델

```
모델 1: 인텔 주도(Intelligence-Led)
  - CTI 팀의 위협 보고서 → 헌팅 가설 → 조사
  - 장점: 알려진 위협에 높은 적중률
  - 단점: CTI 품질에 의존

모델 2: 상황 인식(Situational Awareness)
  - 환경 변화(합병, 신규 서비스) → 새 공격 표면 헌팅
  - 장점: 조직 맥락 반영
  - 단점: 범위 설정 어려움

모델 3: 가설 기반(Hypothesis-Driven)
  - MITRE ATT&CK TTP → 우리 환경에서 발생 가능? → 검증
  - 장점: 체계적 커버리지
  - 단점: 노력 집약적
```

### 1.2 헌팅 차터(Charter) 구성요소

조직 내 헌팅 프로그램의 공식 승인 및 범위 정의 문서.

```
헌팅 차터 포함 내용:
  1. 프로그램 목적 및 비전
  2. 범위: 커버리지 환경, 제외 시스템
  3. 우선순위: 크라운 주얼, 핵심 인프라
  4. 팀 구성 및 역할/책임 (RACI)
  5. 데이터 접근 권한 및 절차
  6. 에스컬레이션 경로 (CISO, 법무팀)
  7. 성과 지표(KPI) 및 보고 주기
  8. 예산 및 도구 할당
```

### 1.3 헌팅 프로그램 조직 내 위치

```
SOC 조직도에서의 헌팅 팀:

CISO
 └── SOC Director
      ├── L1/L2 Analysts (Alert Triage)
      ├── L3 Incident Response
      ├── Threat Intelligence Team ←→ 헌팅 가설 공급
      └── Threat Hunting Team ←────────────────────────
           ├── Hunt Lead
           ├── Senior Hunters (2~4명)
           └── Junior Hunters / Rotation Program
```

---

## 2. 헌팅 인텔리전스 수집 체계

### 2.1 헌팅 인텔 소스 우선순위

| 우선순위 | 인텔 소스 | 유형 | 헌팅 활용 |
|----------|-----------|------|-----------|
| P1 | CISA KEV | 알려진 악용 취약점 | 우리 환경의 취약 자산 확인 |
| P1 | 내부 IR 보고서 | 이전 침해 TTP | 동일 TTP 재확인 헌팅 |
| P2 | 산업별 ISAC | 동종 업계 위협 | 업계 특화 헌팅 가설 |
| P2 | Dragos/Mandiant | APT 보고서 | 특정 그룹 TTP 기반 헌팅 |
| P3 | VirusTotal / OTX | IOC 피드 | IOC 기반 레트로헌팅 |
| P3 | Twitter/X CTI | 실시간 공개 | 신규 캠페인 초기 정보 |

### 2.2 위협 인텔 → 헌팅 가설 변환

```
인텔 보고서 수신 예시:
"APT29가 SolarWinds Orion을 이용한 공급망 공격에서
 TEARDROP 악성코드를 Cobalt Strike Beacon 전에 드롭"

변환 과정:

단계 1: TTP 추출
  T1059.001: PowerShell 실행
  T1055: 프로세스 인젝션 (DLL 사이드로딩)
  T1078: 유효한 계정 사용 (Gold SAML)
  T1036: 위장(Masquerading) — svchost 위장

단계 2: 환경 적용성 평가
  Q: 우리 환경에 SolarWinds Orion이 있는가? → 자산DB 확인
  Q: 우리 IdP가 SAML을 사용하는가? → AD FS 사용 확인
  Q: PowerShell 실행 로그가 있는가? → Sysmon 이벤트 ID 4688

단계 3: 헌팅 가설 작성
  가설: "Orion 서버(192.168.10.5)에서 비정상 PowerShell이
         DLL 사이드로딩 후 외부 C2와 통신했을 수 있다"

단계 4: 쿼리 개발 → 실행 → 분석
```

---

## 3. 데이터 파이프라인 및 플랫폼 구성

### 3.1 헌팅 데이터 스택

```
데이터 소스:
  Endpoints: Sysmon(Win), auditd(Linux), EDR 텔레메트리
  Network: NetFlow, DNS 로그, Proxy 로그, PCAP
  Cloud: CloudTrail, Azure Activity, GCP Audit
  Identity: AD 이벤트, Okta 로그, PAM 세션

수집 레이어:
  Elastic Agent / Filebeat → Kafka → Elasticsearch
  또는
  Cribl Stream → Splunk / Microsoft Sentinel

헌팅 레이어:
  Jupyter Notebook + pandas + Elasticsearch-DSL
  또는
  Splunk SPL / KQL 쿼리 인터페이스

장기 보관:
  S3/Azure Blob (콜드 스토리지, 최소 13개월)
  레트로헌팅(Retrohunting)용 파케이(Parquet) 형식
```

### 3.2 MISP와 헌팅 플랫폼 연동

```python
# MISP에서 최신 IOC를 가져와 Splunk/Elastic에 자동 주입
import requests

MISP_URL = "https://misp.internal"
MISP_KEY = "your_api_key_here"

def fetch_misp_iocs(event_days: int = 7) -> list[dict]:
    headers = {"Authorization": MISP_KEY, "Accept": "application/json"}
    params = {
        "type": ["ip-dst", "domain", "url", "md5", "sha256"],
        "last": f"{event_days}d",
        "to_ids": 1,
    }
    resp = requests.post(
        f"{MISP_URL}/attributes/restSearch",
        json=params,
        headers=headers,
        verify=False,
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json().get("response", {}).get("Attribute", [])
```

---

## 4. 헌팅 팀 역량 개발

### 4.1 헌팅 역량 매트릭스

| 역량 | 주니어 헌터 | 시니어 헌터 | 헌팅 리드 |
|------|------------|------------|----------|
| MITRE ATT&CK 이해 | 기본 전술 | TTP 심화 | 프레임워크 기여 |
| 쿼리 작성 | KQL/SPL 기본 | 복잡한 상관 쿼리 | 쿼리 라이브러리 관리 |
| 악성코드 분석 | IOC 식별 | 샌드박스 분석 | 리버싱, YARA |
| 포렌식 | 기본 아티팩트 | 메모리 포렌식 | 타임라인 재구성 |
| 프로그래밍 | Python 기초 | 자동화 스크립트 | 헌팅 플랫폼 개발 |
| 리포팅 | 발견 사항 기술 | 영향도 분석 | 경영진 보고 |

### 4.2 헌터 역량 개발 프로그램

```
주니어 헌터 육성 커리큘럼 (12개월):

M1-3: 기초
  - MITRE ATT&CK Navigator 숙달
  - Splunk/Elastic 쿼리 50개 실습
  - CTF 참여 (HTB, BTLO)
  - 시니어 헌터 1:1 섀도잉

M4-6: 심화
  - 독립 헌트 1개 리드
  - YARA 룰 작성 10개
  - 악성코드 샘플 분석 20개
  - 블루 팀 CTF 우승 도전

M7-9: 전문화
  - 특정 위협 그룹 전문성 확보
  - 헌팅 플레이북 2개 작성
  - 팀 내 위협 브리핑 발표

M10-12: 독립
  - 전체 헌팅 캠페인 단독 수행
  - 발견 사항 CISO 보고
  - 신입 헌터 멘토링
```

### 4.3 Purple Team 협업

```
Purple Team 세션 구조:

1. 준비 (Pre-session)
   Red Team: 공격 시나리오 선택 (ATT&CK TTP 기반)
   Blue Team: 현재 탐지 커버리지 매핑

2. 실행 (Execution)
   Red Team: TTP 실행 (제한된 환경)
   Blue Team: 실시간 탐지 시도

3. 분석 (Analysis)
   탐지됨: 탐지 방법, 탐지 시간 기록
   탐지 안됨: 왜 놓쳤는가? → 헌팅 가설로 전환

4. 개선 (Improvement)
   탐지 룰 업데이트
   헌팅 쿼리 추가
   Runbook 업데이트

5. 검증 (Validation)
   동일 TTP 재실행 → 탐지 확인
```

---

## 5. 헌팅 결과 관리 및 피드백 루프

### 5.1 헌팅 발견사항 분류

```
분류 1: 확인된 위협 (Confirmed Threat)
  → 즉시 IR 팀에 에스컬레이션
  → P1 인시던트 처리

분류 2: 악의적 아님 / 설명 가능 (Benign/Explained)
  → 예외 목록 업데이트 (false positive 감소)
  → 쿼리 튜닝

분류 3: 위험 행동 (Risky but not malicious)
  → 정책 위반 → 보안 교육 또는 정책 변경
  → 규칙 추가 (예방적 감지)

분류 4: 가시성 격차 (Visibility Gap)
  → 로그 소스 부재 확인 → 로깅 확대
  → 데이터 파이프라인 개선 요청

분류 5: 새 TTP 발견 (Novel TTP)
  → 탐지 룰 즉시 작성 및 배포
  → 위협 인텔 팀에 공유
  → 외부 공개 가능 시 CTI 커뮤니티 공유
```

### 5.2 피드백 루프 구조

```
헌팅 결과 → SOC L1/L2 개선
  탐지 룰 추가 → Alert 생성
  위양성 감소 → Alert 정밀도 향상

헌팅 결과 → IR 팀 개선
  새 IOC → 차단 목록 업데이트
  새 TTP → Playbook 업데이트
  포렌식 결과 → 수사 기법 개선

헌팅 결과 → CTI 팀 개선
  새 행위자 TTP → 위협 보고서 업데이트
  캠페인 연결 → 행위자 추적 강화

헌팅 결과 → 보안 아키텍처 개선
  반복 탐지 TTP → 근본 취약점 제거
  가시성 격차 → 로깅 인프라 개선
```

---

## 6. 산업별 특화 헌팅 시나리오

### 6.1 금융 업종

```
시나리오 1: SWIFT 시스템 측면 이동
  가설: 공격자가 직원 계정으로 SWIFT 시스템에 접근했을 수 있다
  헌팅 쿼리:
    SELECT user, src_ip, dst_ip, action, timestamp
    FROM auth_logs
    WHERE dst_system LIKE '%swift%'
      AND login_hour NOT BETWEEN 8 AND 18
      AND login_day_of_week IN ('Saturday', 'Sunday')
    ORDER BY timestamp DESC;

시나리오 2: 트레이딩 시스템 내부자 위협
  지표: 동일 계정이 여러 시스템에 순차적 접근
  → 접근 패턴 베이스라인과 비교
  → 이상 접근 시간/볼륨 탐지
```

### 6.2 의료 업종

```
시나리오: 랜섬웨어 선행 지표 탐지
  알려진 선행 TTP (Ryuk, Conti):
    1. Cobalt Strike Beacon → SMB 측면 이동
    2. ADFind.exe 실행 (AD 열거)
    3. net view, net use 명령어
    4. 대규모 파일 복사 (데이터 유출)
    5. vssadmin delete shadows (랜섬웨어 직전)

  헌팅 우선순위: vssadmin 실행 → ADFind 실행 → SMB 연결 급증
```

### 6.3 OT/ICS 환경

```
시나리오: IT/OT 경계 횡단 탐지
  가설: 공격자가 IT 네트워크에서 OT DMZ를 거쳐
        엔지니어링 워크스테이션에 도달했을 수 있다

  데이터 소스: IT/OT 경계 방화벽 로그, EWS 이벤트 로그
  
  이상 지표:
    - IT IP → DMZ 방화벽 → OT VLAN (기준선 없는 통신)
    - 비업무 시간 EWS 로그인
    - EWS에서 PLC 접속 도구(Step7, TIA Portal) 비정상 실행
    - 소규모 아웃바운드(< 100KB) C2 통신 패턴
```

---

## 7. Python 도구: 헌팅 캠페인 관리 시스템

```python
#!/usr/bin/env python3
"""
Threat Hunt Campaign Manager
헌팅 캠페인 생명주기 관리 — 가설, 실행, 결과, 피드백 추적
"""

from __future__ import annotations
import argparse
import json
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
import uuid


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class HuntFinding:
    finding_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    classification: str = ""  # confirmed_threat | benign | risky | gap | novel_ttp
    description: str = ""
    affected_systems: list[str] = field(default_factory=list)
    iocs: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    action_taken: str = ""
    timestamp: str = field(default_factory=_now_iso)


@dataclass
class HuntCampaign:
    campaign_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    title: str = ""
    hypothesis: str = ""
    status: str = "planned"  # planned | active | completed | abandoned
    priority: str = "MEDIUM"  # LOW | MEDIUM | HIGH | CRITICAL
    assigned_to: str = ""
    mitre_techniques: list[str] = field(default_factory=list)
    data_sources: list[str] = field(default_factory=list)
    queries: list[str] = field(default_factory=list)
    findings: list[HuntFinding] = field(default_factory=list)
    created_at: str = field(default_factory=_now_iso)
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    notes: str = ""

    def start(self) -> None:
        self.status = "active"
        self.started_at = _now_iso()

    def complete(self) -> None:
        self.status = "completed"
        self.completed_at = _now_iso()

    def add_finding(self, finding: HuntFinding) -> None:
        self.findings.append(finding)

    @property
    def confirmed_threats(self) -> list[HuntFinding]:
        return [f for f in self.findings if f.classification == "confirmed_threat"]

    @property
    def novel_ttps(self) -> list[HuntFinding]:
        return [f for f in self.findings if f.classification == "novel_ttp"]


class HuntManager:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self._campaigns: dict[str, HuntCampaign] = {}
        self._load()

    def _load(self) -> None:
        if self.db_path.exists():
            try:
                raw = json.loads(self.db_path.read_text(encoding="utf-8"))
                for item in raw.get("campaigns", []):
                    findings = [HuntFinding(**f) for f in item.pop("findings", [])]
                    camp = HuntCampaign(**item)
                    camp.findings = findings
                    self._campaigns[camp.campaign_id] = camp
            except (json.JSONDecodeError, TypeError):
                pass

    def _save(self) -> None:
        data = {"campaigns": [asdict(c) for c in self._campaigns.values()]}
        self.db_path.write_text(
            json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8"
        )

    def create(self, title: str, hypothesis: str, priority: str = "MEDIUM",
               assigned_to: str = "", mitre: Optional[list[str]] = None,
               sources: Optional[list[str]] = None) -> HuntCampaign:
        campaign = HuntCampaign(
            title=title,
            hypothesis=hypothesis,
            priority=priority,
            assigned_to=assigned_to,
            mitre_techniques=mitre or [],
            data_sources=sources or [],
        )
        self._campaigns[campaign.campaign_id] = campaign
        self._save()
        return campaign

    def get(self, campaign_id: str) -> Optional[HuntCampaign]:
        return self._campaigns.get(campaign_id)

    def list_campaigns(self, status: Optional[str] = None,
                       priority: Optional[str] = None) -> list[HuntCampaign]:
        campaigns = list(self._campaigns.values())
        if status:
            campaigns = [c for c in campaigns if c.status == status]
        if priority:
            campaigns = [c for c in campaigns if c.priority == priority]
        return sorted(campaigns, key=lambda c: c.created_at, reverse=True)

    def start_campaign(self, campaign_id: str) -> Optional[HuntCampaign]:
        camp = self.get(campaign_id)
        if camp and camp.status == "planned":
            camp.start()
            self._save()
        return camp

    def complete_campaign(self, campaign_id: str) -> Optional[HuntCampaign]:
        camp = self.get(campaign_id)
        if camp and camp.status == "active":
            camp.complete()
            self._save()
        return camp

    def add_finding(self, campaign_id: str, classification: str,
                    description: str, systems: Optional[list[str]] = None,
                    iocs: Optional[list[str]] = None,
                    techniques: Optional[list[str]] = None,
                    action: str = "") -> Optional[HuntFinding]:
        camp = self.get(campaign_id)
        if not camp:
            return None
        finding = HuntFinding(
            classification=classification,
            description=description,
            affected_systems=systems or [],
            iocs=iocs or [],
            mitre_techniques=techniques or [],
            action_taken=action,
        )
        camp.add_finding(finding)
        self._save()
        return finding

    def report(self, campaign_id: Optional[str] = None,
               fmt: str = "text") -> str:
        if campaign_id:
            camp = self.get(campaign_id)
            if not camp:
                return f"[오류] 캠페인 {campaign_id}를 찾을 수 없습니다."
            campaigns = [camp]
        else:
            campaigns = self.list_campaigns()

        if fmt == "json":
            return json.dumps(
                [asdict(c) for c in campaigns],
                ensure_ascii=False, indent=2,
            )

        lines: list[str] = []
        lines.append("=" * 65)
        lines.append("위협 헌팅 캠페인 현황")
        lines.append("=" * 65)

        status_counts: dict[str, int] = {}
        for c in campaigns:
            status_counts[c.status] = status_counts.get(c.status, 0) + 1

        lines.append(f"\n총 캠페인: {len(campaigns)}개")
        for s, cnt in status_counts.items():
            lines.append(f"  {s:12s}: {cnt}개")

        total_findings = sum(len(c.findings) for c in campaigns)
        total_threats = sum(len(c.confirmed_threats) for c in campaigns)
        lines.append(f"총 발견: {total_findings}개 (확인된 위협: {total_threats}개)")

        lines.append("\n[캠페인 상세]")
        lines.append("-" * 65)

        priority_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        for camp in sorted(campaigns, key=lambda c: priority_order.get(c.priority, 4)):
            lines.append(f"\n[{camp.priority}] {camp.title} (ID: {camp.campaign_id})")
            lines.append(f"  상태    : {camp.status}")
            lines.append(f"  담당자  : {camp.assigned_to or '미지정'}")
            lines.append(f"  가설    : {camp.hypothesis}")
            if camp.mitre_techniques:
                lines.append(f"  ATT&CK  : {', '.join(camp.mitre_techniques)}")
            lines.append(f"  발견수  : {len(camp.findings)}개")
            for f in camp.findings:
                lines.append(f"    [{f.classification}] {f.description[:60]}")
            if camp.notes:
                lines.append(f"  비고    : {camp.notes}")

        return "\n".join(lines)

    def metrics(self) -> dict[str, int | float]:
        campaigns = list(self._campaigns.values())
        completed = [c for c in campaigns if c.status == "completed"]
        total_findings = sum(len(c.findings) for c in campaigns)
        threats = sum(len(c.confirmed_threats) for c in campaigns)
        novel = sum(len(c.novel_ttps) for c in campaigns)

        duration_hours: list[float] = []
        for c in completed:
            if c.started_at and c.completed_at:
                start = datetime.fromisoformat(c.started_at)
                end = datetime.fromisoformat(c.completed_at)
                duration_hours.append((end - start).total_seconds() / 3600)

        avg_duration = (
            sum(duration_hours) / len(duration_hours) if duration_hours else 0
        )

        return {
            "total_campaigns": len(campaigns),
            "active": sum(1 for c in campaigns if c.status == "active"),
            "completed": len(completed),
            "total_findings": total_findings,
            "confirmed_threats": threats,
            "novel_ttps": novel,
            "avg_campaign_hours": round(avg_duration, 1),
            "threat_discovery_rate": round(threats / max(len(completed), 1), 2),
        }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="위협 헌팅 캠페인 관리 시스템",
    )
    parser.add_argument(
        "--db",
        type=Path,
        default=Path("hunts.json"),
        help="데이터베이스 파일 경로 (기본: hunts.json)",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # create
    sp_create = subparsers.add_parser("create", help="새 캠페인 생성")
    sp_create.add_argument("--title", required=True)
    sp_create.add_argument("--hypothesis", required=True)
    sp_create.add_argument("--priority", default="MEDIUM",
                           choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"])
    sp_create.add_argument("--assigned-to", default="")
    sp_create.add_argument("--mitre", nargs="*", default=[])
    sp_create.add_argument("--sources", nargs="*", default=[])

    # start / complete
    for cmd in ("start", "complete"):
        sp = subparsers.add_parser(cmd, help=f"캠페인 {cmd}")
        sp.add_argument("campaign_id")

    # finding
    sp_find = subparsers.add_parser("finding", help="발견 사항 추가")
    sp_find.add_argument("campaign_id")
    sp_find.add_argument("--class", dest="classification", required=True,
                         choices=["confirmed_threat", "benign", "risky",
                                  "gap", "novel_ttp"])
    sp_find.add_argument("--desc", required=True)
    sp_find.add_argument("--systems", nargs="*", default=[])
    sp_find.add_argument("--iocs", nargs="*", default=[])
    sp_find.add_argument("--action", default="")

    # report
    sp_report = subparsers.add_parser("report", help="캠페인 보고서")
    sp_report.add_argument("campaign_id", nargs="?", default=None)
    sp_report.add_argument("-f", "--format", choices=["text", "json"], default="text")

    # metrics
    subparsers.add_parser("metrics", help="프로그램 성과 지표")

    return parser.parse_args()


def main() -> None:
    args = parse_args()
    manager = HuntManager(args.db)

    if args.command == "create":
        camp = manager.create(
            title=args.title,
            hypothesis=args.hypothesis,
            priority=args.priority,
            assigned_to=args.assigned_to,
            mitre=args.mitre,
            sources=args.sources,
        )
        print(f"[생성] 캠페인 ID: {camp.campaign_id} — {camp.title}")

    elif args.command == "start":
        camp = manager.start_campaign(args.campaign_id)
        if camp:
            print(f"[시작] {camp.title} (ID: {camp.campaign_id})")
        else:
            print(f"[오류] 캠페인 {args.campaign_id} 시작 실패", file=sys.stderr)

    elif args.command == "complete":
        camp = manager.complete_campaign(args.campaign_id)
        if camp:
            print(f"[완료] {camp.title} (발견: {len(camp.findings)}개)")
        else:
            print(f"[오류] 캠페인 {args.campaign_id} 완료 실패", file=sys.stderr)

    elif args.command == "finding":
        finding = manager.add_finding(
            args.campaign_id,
            classification=args.classification,
            description=args.desc,
            systems=args.systems,
            iocs=args.iocs,
            action=args.action,
        )
        if finding:
            print(f"[발견] ID: {finding.finding_id} — {finding.classification}")
        else:
            print(f"[오류] 캠페인 {args.campaign_id}를 찾을 수 없습니다", file=sys.stderr)

    elif args.command == "report":
        print(manager.report(args.campaign_id, args.format))

    elif args.command == "metrics":
        m = manager.metrics()
        print("\n[헌팅 프로그램 성과 지표]")
        for k, v in m.items():
            print(f"  {k:30s}: {v}")


if __name__ == "__main__":
    main()
```

**사용 예시:**

```bash
# 새 캠페인 생성
python hunt_manager.py create \
  --title "APT29 SAML Token Forgery 헌팅" \
  --hypothesis "공격자가 ADFS 서버에서 골든 SAML 토큰을 발급했을 수 있다" \
  --priority HIGH \
  --assigned-to "hunter1" \
  --mitre T1078.004 T1550.001 \
  --sources "ADFS 이벤트 로그" "Azure AD 로그"

# 캠페인 시작
python hunt_manager.py start abc12345

# 발견사항 추가
python hunt_manager.py finding abc12345 \
  --class confirmed_threat \
  --desc "ADFS 서버에서 비정상 토큰 발급 (사용자: svc-azure, 시간: 03:22 KST)" \
  --systems "ADFS-01 (10.0.1.5)" \
  --iocs "svc-azure" "185.220.101.47" \
  --action "계정 즉시 잠금, IR 팀 에스컬레이션"

# 보고서 출력
python hunt_manager.py report
python hunt_manager.py metrics
```

---

## 8. 헌팅 프로그램 성숙도 측정

### 8.1 성숙도 프레임워크 (OTHF 기반)

Open Threat Hunting Framework 5단계 성숙도:

```
레벨 1 — 초기 (Initial)
  □ 임시(Ad-hoc) 헌팅, 문서화 없음
  □ 경보 기반 반응적 조사
  □ 기본 SIEM 쿼리 능력

레벨 2 — 관리됨 (Managed)
  □ 공식 헌팅 프로세스 존재
  □ 헌팅 결과 추적 및 문서화
  □ ATT&CK 기반 가설 수립

레벨 3 — 정의됨 (Defined)
  □ 표준화된 헌팅 플레이북
  □ 정기적 헌팅 캘린더 (월간)
  □ 피드백 루프 → 탐지 룰 개선
  □ Purple Team 정기 실시

레벨 4 — 측정됨 (Measured)
  □ KPI/KRI 정기 보고
  □ 헌팅 커버리지 매핑 (ATT&CK)
  □ 데이터 품질 측정
  □ ROI 측정 가능

레벨 5 — 최적화됨 (Optimized)
  □ ML 기반 이상 탐지 통합
  □ 자동화 헌팅 (Automated Hunting)
  □ 커뮤니티 CTI 공유
  □ 지속적 자기 개선 루프
```

### 8.2 헌팅 커버리지 대시보드

```
MITRE ATT&CK 커버리지 추적:

전술          | 기법 수 | 헌팅 커버 | 탐지 룰 | 우선순위
─────────────|---------|----------|---------|─────────
초기 접근     |    9    |    6     |    4    | HIGH
실행          |   14    |    8     |    7    | HIGH
지속성        |   19    |    5     |    3    | MEDIUM
권한 에스컬  |   13    |    4     |    2    | HIGH
방어 회피     |   42    |   12     |    8    | CRITICAL
자격증명 접근 |   17    |    9     |    6    | HIGH
발견          |   31    |   10     |    5    | MEDIUM
측면 이동     |    9    |    5     |    4    | HIGH
수집          |   17    |    3     |    2    | MEDIUM
C2           |   16    |    6     |    4    | HIGH
유출          |    9    |    2     |    1    | HIGH
영향          |   14    |    3     |    2    | MEDIUM
```

---

## 참고 자료

- **MITRE ATT&CK** — [https://attack.mitre.org](https://attack.mitre.org)
- **Open Threat Hunting Framework (OTHF)** — 헌팅 성숙도 모델
- **TaHiTI** — Threat hunting methodology by ABN AMRO Bank
- **Sqrrl Threat Hunting Reference Guide** — 헌팅 기초 가이드
- **SANS FOR508** — Advanced Incident Response & Threat Hunting
- **Cyb3rWard0g 블로그** — 실전 헌팅 사례 연구
