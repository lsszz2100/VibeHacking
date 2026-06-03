> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 위협 헌팅 방법론 (Threat Hunting Methodology)

## 0. 초보자를 위한 개념 이해

### 위협 헌팅이란?

위협 헌팅(Threat Hunting)은 기존 SIEM 알림이나 AV 탐지를 기다리지 않고, 보안 분석가가 직접 가설을 세우고 데이터를 분석해 숨겨진 위협을 능동적으로 찾아내는 활동이다. 공격자가 평균 200일 이상 탐지되지 않고 잠복할 수 있다는 통계가 위협 헌팅의 필요성을 만들었다. 인텔리전스 기반 가설, 데이터 탐색, 패턴 분석을 통해 기존 보안 도구의 탐지 사각지대를 커버한다.

**왜 배우는가:**
```
[위협 헌팅이 필요한 이유]

  기존 보안 도구의 한계:
  SIEM: 알려진 규칙에만 반응
  AV/EDR: 알려진 악성코드 시그니처 기반
  방화벽: 규칙 기반 트래픽 차단

  공격자의 전략 변화:
  ┌─ 탐지 회피 기법 사용 (Living off the Land)
  │   정상 도구(PowerShell, WMI, certutil) 악용
  ├─ 느린 이동 (Low & Slow)
  │   수개월에 걸쳐 조용히 이동
  └─ 파일리스 공격 (Fileless)
      디스크에 파일 없음 → AV 탐지 불가

  위협 헌팅으로:
  Dwell time 207일 → 조기 발견
  알려지지 않은 TTP 패턴 발굴
  탐지 규칙 개선 피드백 제공
```

### 핵심 개념 정리

```
[위협 헌팅 3단계 사이클]

1. 가설 수립 (Hypothesis)
   인텔리전스 기반: 새 CVE, APT 보고서, IOC
   경험 기반: "PowerShell이 Base64를 자주 실행하면?"
   데이터 기반: 통계적 이상값 탐색
   → 구체적 질문으로 변환

2. 데이터 탐색 (Investigation)
   SIEM 쿼리(KQL/SPL)로 관련 이벤트 검색
   EDR 텔레메트리 분석
   네트워크 트래픽 패턴 분석
   → 가설 검증/기각

3. 패턴 발견 → 탐지 규칙화 (Detection Engineering)
   새로운 악성 패턴 발견 → SIEM 규칙 추가
   정상 행동과 이상 행동 기준선 확립
   Playbook 작성 → 다음 헌팅 사이클

[헌팅 성숙도 (SQRRL 모델)]
  레벨 0: 수동적 (알림 대응만)
  레벨 1: 최소적 (IoC 검색)
  레벨 2: 절차적 (정해진 프로세스)
  레벨 3: 혁신적 (가설 기반 헌팅)
  레벨 4: 선도적 (자동화 + ML)
```

### 필요한 도구 및 환경
- **Microsoft Sentinel**: 클라우드 SIEM (KQL 쿼리)
- **Splunk**: 엔터프라이즈 SIEM (SPL 쿼리)
- **Elastic SIEM**: 오픈소스 보안 분석 플랫폼
- **MITRE ATT&CK Navigator**: TTP 매핑 및 헌팅 계획 시각화

### 기초 실습 예제
```python
from dataclasses import dataclass, field
from datetime import datetime

@dataclass
class HuntHypothesis:
    """위협 헌팅 가설 구조체."""
    title: str
    mitre_technique: str  # 예: T1059.001
    hypothesis: str
    data_sources: list[str]
    hunting_query: str
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    status: str = "draft"  # draft, active, completed, false_positive

def create_hunt_hypothesis(
    title: str,
    technique_id: str,
    hypothesis: str,
    data_sources: list[str],
    query: str
) -> HuntHypothesis:
    """위협 헌팅 가설을 생성하고 출력한다."""
    hunt = HuntHypothesis(
        title=title,
        mitre_technique=technique_id,
        hypothesis=hypothesis,
        data_sources=data_sources,
        hunting_query=query,
    )

    print(f"\n[*] 위협 헌팅 가설 생성:")
    print(f"    제목: {hunt.title}")
    print(f"    MITRE: {hunt.mitre_technique}")
    print(f"    가설: {hunt.hypothesis}")
    print(f"    데이터 소스: {', '.join(hunt.data_sources)}")
    print(f"    쿼리 미리보기:")
    print(f"    {hunt.hunting_query[:100]}...")

    return hunt

# 사용 예시
hunt = create_hunt_hypothesis(
    title="PowerShell 인코딩 명령 실행 탐지",
    technique_id="T1059.001",
    hypothesis="공격자가 PowerShell의 Base64 인코딩 기능으로 악성 코드를 숨겨 실행하고 있을 것이다",
    data_sources=["Windows Security Event Log (4688)", "Sysmon Event ID 1"],
    query="SecurityEvent | where EventID == 4688 | where CommandLine has '-EncodedCommand'"
)
```

---

## 1. 위협 헌팅이란 무엇인가

### 1.1 정의

위협 헌팅(Threat Hunting)은 기존 보안 도구가 탐지하지 못한 숨겨진 위협을 **능동적·반복적으로 탐색**하는 사이버 보안 활동이다. 단순히 알림(alert)에 반응하는 것이 아니라, 분석가의 가설과 인텔리전스를 바탕으로 네트워크 및 엔드포인트 내부를 직접 수색한다.

- **목표**: 잠복 중인 공격자(dwell time 감소), 새로운 TTP 발굴, 탐지 로직 개선
- **키워드**: 프로액티브(Proactive), 가설 기반(Hypothesis-driven), 반복(Iterative)

### 1.2 반응형 보안과의 차이

| 구분 | 반응형 보안 (Reactive) | 위협 헌팅 (Proactive) |
|------|----------------------|----------------------|
| 트리거 | 알림 또는 인시던트 발생 | 분석가의 가설 |
| 시작점 | 경보(alert) | 인텔리전스·데이터 |
| 목적 | 사고 대응 및 수습 | 숨겨진 위협 발굴 |
| 탐지 시간 | 평균 207일 (IBM 보고서 기준) | Dwell time 단축 목표 |
| 결과물 | 인시던트 보고서 | 새로운 탐지 규칙, TTP 파악 |

### 1.3 위협 헌팅의 가치

1. **MTTD(Mean Time to Detect) 단축**: 잠복 기간 감소
2. **탐지 공백 발견**: 기존 SIEM 규칙의 블라인드 스팟 식별
3. **위협 인텔리전스 생성**: 내부 환경 맞춤 IOC/TTP 데이터
4. **보안 운영 성숙도 향상**: 헌팅 결과가 자동화 탐지로 전환

---

## 2. 헌팅 성숙도 모델 (Hunting Maturity Model, HMM)

Sqrrl이 제안하고 업계 표준으로 자리 잡은 HMM은 0~4단계로 조직의 헌팅 역량을 평가한다.

### HMM 0단계 — Initial (초기)

- **특징**: 로그 수집 부재, 탐지는 AV/IDS 알림에만 의존
- **데이터 품질**: 거의 없음
- **자동화**: 없음
- **헌팅**: 불가능
- **조치**: 기본 로깅 활성화, SIEM 도입

### HMM 1단계 — Minimal (최소)

- **특징**: 일부 로그 수집, 기본적인 IOC 검색 가능
- **데이터 품질**: IP/도메인/해시 기반 매칭
- **자동화**: 수동 쿼리 실행
- **헌팅**: IOC 기반 단순 검색
- **조치**: 위협 인텔리전스 피드 통합

### HMM 2단계 — Procedural (절차적)

- **특징**: 다른 팀의 헌팅 절차를 따라 실행
- **데이터 품질**: 구조화된 로그, EDR 데이터 보유
- **자동화**: 일부 쿼리 자동화
- **헌팅**: TTP 기반, 문서화된 플레이북 사용
- **조치**: 내부 절차 표준화, 플레이북 작성

### HMM 3단계 — Innovative (혁신적)

- **특징**: 자체 TTP 기반 헌팅 절차 생성
- **데이터 품질**: 풍부한 컨텍스트, 행위 데이터
- **자동화**: 반복 헌팅 자동화
- **헌팅**: 가설 기반, 맞춤형 분석
- **조치**: 내부 연구, 새로운 탐지 기법 개발

### HMM 4단계 — Leading (선도)

- **특징**: 머신러닝 기반 이상 탐지, 업계 선도
- **데이터 품질**: 완전한 가시성, 실시간 스트리밍
- **자동화**: 고도화된 자동화, 피드백 루프
- **헌팅**: 예측적 헌팅, 행위 분석
- **조치**: 공개 연구 발표, 커뮤니티 기여

---

## 3. 가설 기반 헌팅 프로세스

### 3.1 헌팅 사이클 (The Hunting Loop)

```
[가설 수립] → [데이터 수집] → [분석 수행] → [패턴 발견] → [대응/보고] → [자동화]
     ↑                                                                        |
     └────────────────────────────────────────────────────────────────────────┘
```

### 3.2 가설 생성 방법

**방법 1: 인텔리전스 기반**
- 최신 위협 보고서(Mandiant, CrowdStrike 등) 참조
- 업계 특화 위협 그룹의 TTP 적용
- 예: "APT28이 T1566(피싱)으로 초기 접근 후 T1059(명령줄)을 사용한다는 보고 존재"

**방법 2: 환경 기반**
- 내부 취약점 스캔 결과 활용
- 최근 패치되지 않은 취약점 대상
- 예: "우리 환경에 Log4Shell 취약 시스템이 존재할 수 있음"

**방법 3: 분석가 경험**
- 과거 인시던트 패턴
- "지난번 침해에서 공격자가 WMI를 통해 측면 이동했음"

**방법 4: MITRE ATT&CK**
- 매트릭스에서 커버리지가 낮은 기술 선택
- 예: "T1003(자격증명 덤프) 탐지가 미흡함"

### 3.3 가설 문서화 형식

```
가설 ID: HYP-2024-001
제목: PowerShell을 통한 비정상적 프로세스 실행
MITRE ATT&CK: T1059.001 (PowerShell)
가설 내용:
  공격자가 PowerShell을 인코딩된 명령으로 실행하여
  보안 솔루션의 탐지를 우회할 것이다.
데이터 소스: Windows Event Log (ID 4104), EDR Process 로그
헌팅 쿼리:
  - encoded 파라미터(-enc, -encodedcommand) 탐지
  - Base64 인코딩 길이 임계값 초과
  - 비정상 부모 프로세스 (Office → PowerShell)
성공 기준: 의심 인스턴스 발견 또는 정상 행위 확인
예상 소요 시간: 4시간
```

### 3.4 헌팅 결과 처리

- **위협 발견 시**: 인시던트 대응팀 에스컬레이션 → 탐지 규칙 생성
- **위협 미발견 시**: 정상 행위 베이스라인 강화 → 다음 가설로
- **모든 경우**: 결과 문서화, KPI 측정(탐지율, 소요시간 등)

---

## 4. 데이터 소스

### 4.1 EDR (Endpoint Detection and Response)

EDR은 위협 헌팅의 핵심 데이터 소스로, 엔드포인트 수준의 상세 행위를 수집한다.

**수집 데이터**:
- 프로세스 생성/종료 (명령줄 인수 포함)
- 파일 생성/수정/삭제
- 레지스트리 변경
- 네트워크 연결 (프로세스별)
- 드라이버 로딩
- WMI 이벤트 구독

**주요 EDR 솔루션**: CrowdStrike Falcon, Microsoft Defender for Endpoint, Carbon Black, SentinelOne

### 4.2 NDR (Network Detection and Response)

**수집 데이터**:
- 전체 패킷 캡처 (PCAP)
- 플로우 데이터 (NetFlow, IPFIX)
- DNS 쿼리/응답
- HTTP/HTTPS 메타데이터
- 인증서 정보
- 프로토콜 이상 탐지

### 4.3 로그 (Logs)

**Windows 이벤트 로그 핵심 ID**:
| 이벤트 ID | 설명 |
|-----------|------|
| 4624 | 로그온 성공 |
| 4625 | 로그온 실패 |
| 4688 | 프로세스 생성 |
| 4698 | 예약 작업 생성 |
| 4720 | 계정 생성 |
| 7045 | 새 서비스 설치 |
| 4104 | PowerShell 스크립트 블록 로깅 |

**Linux 핵심 로그**:
- `/var/log/auth.log`: 인증 이벤트
- `/var/log/syslog`: 시스템 이벤트
- Auditd: 시스템 콜 감사
- `/proc/`: 프로세스 정보

### 4.4 NetFlow

NetFlow는 IP 트래픽 통계를 제공하며, 전체 패킷 캡처보다 적은 저장 공간으로 네트워크 행위를 분석한다.

**헌팅 활용 사례**:
- 비정상 데이터 전송량 (데이터 유출 탐지)
- 새로운 통신 쌍 (C2 연결 탐지)
- 포트 스캐닝 패턴
- 비표준 포트 사용
- Beaconing 패턴 분석

---

## 5. MITRE ATT&CK 기반 헌팅 우선순위

### 5.1 우선순위 결정 기준

1. **영향도**: 해당 기술이 성공 시 피해 규모
2. **빈도**: 실제 공격에서 사용 빈도 (ATT&CK 통계)
3. **탐지 공백**: 현재 탐지 커버리지 부족 영역
4. **환경 적합성**: 내부 환경에서 실현 가능한 공격 경로

### 5.2 전술별 헌팅 우선순위

```
Priority 1 (즉시 헌팅):
  - T1003: OS Credential Dumping (Lsass dump)
  - T1055: Process Injection
  - T1059: Command and Scripting Interpreter
  - T1078: Valid Accounts

Priority 2 (주간 헌팅):
  - T1566: Phishing
  - T1021: Remote Services
  - T1547: Boot/Logon Autostart Execution
  - T1053: Scheduled Task/Job

Priority 3 (월간 헌팅):
  - T1190: Exploit Public-Facing Application
  - T1027: Obfuscated Files or Information
  - T1083: File and Directory Discovery
```

### 5.3 커버리지 매트릭스 관리

```python
# 예시: 탐지 커버리지 평가
탐지_없음 = 0
부분_탐지 = 1
완전_탐지 = 2

커버리지 = {
    "T1003": 부분_탐지,  # Lsass는 탐지, 다른 방법 미탐지
    "T1055": 탐지_없음,  # 프로세스 인젝션 탐지 미흡
    "T1059": 완전_탐지,  # PowerShell, CMD 모두 탐지
}
```

---

## 6. Python: 헌팅 가설 관리 및 추적 도구

```python
#!/usr/bin/env python3
"""
위협 헌팅 가설 관리 및 추적 CLI 도구
사용법: python3 hunt_tracker.py [command] [options]
"""

import argparse
import json
import sys
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

HUNT_DB_PATH = Path.home() / ".threat_hunting" / "hunts.json"
MITRE_TACTICS = [
    "TA0001-Initial Access",
    "TA0002-Execution",
    "TA0003-Persistence",
    "TA0004-Privilege Escalation",
    "TA0005-Defense Evasion",
    "TA0006-Credential Access",
    "TA0007-Discovery",
    "TA0008-Lateral Movement",
    "TA0009-Collection",
    "TA0010-Exfiltration",
    "TA0011-Command and Control",
    "TA0040-Impact",
]

STATUS_OPTIONS = ["open", "in_progress", "completed", "escalated", "closed"]
PRIORITY_OPTIONS = ["critical", "high", "medium", "low"]


def load_db() -> dict:
    """헌팅 데이터베이스 로드."""
    HUNT_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    if not HUNT_DB_PATH.exists():
        return {"hunts": [], "metadata": {"version": "1.0", "created": _now()}}
    try:
        return json.loads(HUNT_DB_PATH.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        print(f"[ERROR] DB 로드 실패: {e}", file=sys.stderr)
        sys.exit(1)


def save_db(db: dict) -> None:
    """헌팅 데이터베이스 저장."""
    try:
        HUNT_DB_PATH.write_text(
            json.dumps(db, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
    except OSError as e:
        print(f"[ERROR] DB 저장 실패: {e}", file=sys.stderr)
        sys.exit(1)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def cmd_add(args: argparse.Namespace) -> None:
    """새 헌팅 가설 추가."""
    db = load_db()
    hunt_id = f"HYP-{datetime.now().strftime('%Y%m%d')}-{str(uuid.uuid4())[:4].upper()}"
    hunt = {
        "id": hunt_id,
        "title": args.title,
        "hypothesis": args.hypothesis,
        "mitre_technique": args.technique,
        "mitre_tactic": args.tactic,
        "data_sources": [s.strip() for s in args.sources.split(",")],
        "priority": args.priority,
        "status": "open",
        "analyst": args.analyst or "unknown",
        "created_at": _now(),
        "updated_at": _now(),
        "findings": [],
        "queries": [],
        "estimated_hours": args.hours,
        "actual_hours": 0,
        "tags": [t.strip() for t in args.tags.split(",")] if args.tags else [],
    }
    db["hunts"].append(hunt)
    save_db(db)
    print(f"[+] 헌팅 가설 추가 완료: {hunt_id}")
    print(f"    제목: {args.title}")
    print(f"    MITRE: {args.technique} / {args.tactic}")
    print(f"    우선순위: {args.priority}")


def cmd_list(args: argparse.Namespace) -> None:
    """헌팅 가설 목록 출력."""
    db = load_db()
    hunts = db["hunts"]

    # 필터 적용
    if args.status:
        hunts = [h for h in hunts if h["status"] == args.status]
    if args.priority:
        hunts = [h for h in hunts if h["priority"] == args.priority]
    if args.analyst:
        hunts = [h for h in hunts if h["analyst"] == args.analyst]

    if not hunts:
        print("[-] 조건에 맞는 헌팅 가설이 없습니다.")
        return

    # 우선순위 정렬
    priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    hunts.sort(key=lambda h: priority_order.get(h["priority"], 99))

    print(f"\n{'ID':<30} {'상태':<12} {'우선순위':<10} {'MITRE':<15} 제목")
    print("-" * 90)
    for h in hunts:
        status_icon = {
            "open": "○",
            "in_progress": "◎",
            "completed": "●",
            "escalated": "▲",
            "closed": "✗",
        }.get(h["status"], "?")
        print(
            f"{h['id']:<30} {status_icon} {h['status']:<10} "
            f"{h['priority']:<10} {h.get('mitre_technique','N/A'):<15} {h['title']}"
        )
    print(f"\n총 {len(hunts)}개의 헌팅 가설")


def cmd_update(args: argparse.Namespace) -> None:
    """헌팅 가설 상태/결과 업데이트."""
    db = load_db()
    hunt = next((h for h in db["hunts"] if h["id"] == args.id), None)
    if not hunt:
        print(f"[ERROR] ID '{args.id}' 를 찾을 수 없습니다.", file=sys.stderr)
        sys.exit(1)

    if args.status:
        if args.status not in STATUS_OPTIONS:
            print(f"[ERROR] 유효하지 않은 상태: {args.status}", file=sys.stderr)
            sys.exit(1)
        hunt["status"] = args.status

    if args.finding:
        hunt["findings"].append({
            "timestamp": _now(),
            "content": args.finding,
            "analyst": args.analyst or hunt["analyst"],
        })

    if args.query:
        hunt["queries"].append({
            "timestamp": _now(),
            "query": args.query,
            "platform": args.platform or "unknown",
        })

    if args.hours:
        hunt["actual_hours"] = args.hours

    hunt["updated_at"] = _now()
    save_db(db)
    print(f"[+] 헌팅 가설 업데이트 완료: {args.id}")
    if args.status:
        print(f"    상태: {args.status}")
    if args.finding:
        print(f"    발견 사항 추가: {args.finding[:80]}...")


def cmd_report(args: argparse.Namespace) -> None:
    """헌팅 가설 상세 보고서 출력."""
    db = load_db()
    hunt = next((h for h in db["hunts"] if h["id"] == args.id), None)
    if not hunt:
        print(f"[ERROR] ID '{args.id}' 를 찾을 수 없습니다.", file=sys.stderr)
        sys.exit(1)

    print(f"\n{'='*60}")
    print(f"헌팅 가설 보고서")
    print(f"{'='*60}")
    print(f"ID          : {hunt['id']}")
    print(f"제목        : {hunt['title']}")
    print(f"상태        : {hunt['status']}")
    print(f"우선순위    : {hunt['priority']}")
    print(f"분석가      : {hunt['analyst']}")
    print(f"MITRE 기술  : {hunt.get('mitre_technique', 'N/A')}")
    print(f"MITRE 전술  : {hunt.get('mitre_tactic', 'N/A')}")
    print(f"데이터 소스 : {', '.join(hunt.get('data_sources', []))}")
    print(f"예상 시간   : {hunt.get('estimated_hours', 0)}h")
    print(f"실제 시간   : {hunt.get('actual_hours', 0)}h")
    print(f"생성 일시   : {hunt['created_at']}")
    print(f"최종 수정   : {hunt['updated_at']}")
    print(f"\n가설 내용:")
    print(f"  {hunt['hypothesis']}")

    if hunt.get("queries"):
        print(f"\n실행된 쿼리 ({len(hunt['queries'])}개):")
        for i, q in enumerate(hunt["queries"], 1):
            print(f"  [{i}] [{q['platform']}] {q['timestamp'][:10]}")
            print(f"      {q['query'][:100]}")

    if hunt.get("findings"):
        print(f"\n발견 사항 ({len(hunt['findings'])}개):")
        for i, f in enumerate(hunt["findings"], 1):
            print(f"  [{i}] {f['timestamp'][:19]} - {f['analyst']}")
            print(f"      {f['content']}")
    else:
        print("\n발견 사항: 없음")

    if hunt.get("tags"):
        print(f"\n태그: {', '.join(hunt['tags'])}")


def cmd_stats(args: argparse.Namespace) -> None:
    """헌팅 통계 및 커버리지 분석."""
    db = load_db()
    hunts = db["hunts"]
    if not hunts:
        print("[-] 저장된 헌팅 가설이 없습니다.")
        return

    total = len(hunts)
    by_status: dict[str, int] = {}
    by_priority: dict[str, int] = {}
    by_tactic: dict[str, int] = {}
    total_estimated = 0
    total_actual = 0
    findings_count = 0

    for h in hunts:
        by_status[h["status"]] = by_status.get(h["status"], 0) + 1
        by_priority[h["priority"]] = by_priority.get(h["priority"], 0) + 1
        tactic = h.get("mitre_tactic", "Unknown")
        by_tactic[tactic] = by_tactic.get(tactic, 0) + 1
        total_estimated += h.get("estimated_hours", 0)
        total_actual += h.get("actual_hours", 0)
        findings_count += len(h.get("findings", []))

    print(f"\n{'='*50}")
    print(f"위협 헌팅 통계 리포트")
    print(f"{'='*50}")
    print(f"총 헌팅 가설: {total}개")
    print(f"총 발견 사항: {findings_count}개")
    print(f"예상 투입 시간: {total_estimated}h / 실제 투입: {total_actual}h")

    print(f"\n[상태별 분포]")
    for status, count in sorted(by_status.items()):
        bar = "█" * count
        print(f"  {status:<12}: {bar} ({count})")

    print(f"\n[우선순위별 분포]")
    for pri in ["critical", "high", "medium", "low"]:
        count = by_priority.get(pri, 0)
        bar = "█" * count
        print(f"  {pri:<10}: {bar} ({count})")

    print(f"\n[전술별 커버리지]")
    for tactic, count in sorted(by_tactic.items()):
        print(f"  {tactic:<35}: {count}개 가설")

    # 완료율 계산
    completed = by_status.get("completed", 0) + by_status.get("closed", 0)
    completion_rate = (completed / total * 100) if total > 0 else 0
    print(f"\n완료율: {completion_rate:.1f}% ({completed}/{total})")


def cmd_bulk_analyze(args: argparse.Namespace) -> None:
    """병렬로 다수의 헌팅 가설 유효성 검사."""
    db = load_db()
    open_hunts = [h for h in db["hunts"] if h["status"] == "open"]

    if not open_hunts:
        print("[-] 분석할 미완료 헌팅 가설이 없습니다.")
        return

    def analyze_hunt(hunt: dict) -> dict[str, str]:
        """단일 헌팅 가설 분석 (시뮬레이션)."""
        issues = []
        if not hunt.get("hypothesis"):
            issues.append("가설 내용 누락")
        if not hunt.get("mitre_technique"):
            issues.append("MITRE 기술 ID 누락")
        if not hunt.get("data_sources"):
            issues.append("데이터 소스 미지정")
        if not hunt.get("queries"):
            issues.append("실행된 쿼리 없음")
        if hunt.get("estimated_hours", 0) == 0:
            issues.append("예상 시간 미설정")

        return {
            "id": hunt["id"],
            "title": hunt["title"],
            "status": "OK" if not issues else "WARN",
            "issues": "; ".join(issues) if issues else "없음",
        }

    print(f"[*] {len(open_hunts)}개의 미완료 헌팅 가설 분석 시작...")
    results = []
    with ThreadPoolExecutor(max_workers=min(10, len(open_hunts))) as executor:
        futures = {executor.submit(analyze_hunt, h): h for h in open_hunts}
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception as e:
                hunt = futures[future]
                results.append({
                    "id": hunt["id"],
                    "title": hunt["title"],
                    "status": "ERROR",
                    "issues": str(e),
                })

    print(f"\n{'ID':<30} {'상태':<6} 이슈")
    print("-" * 80)
    for r in sorted(results, key=lambda x: x["status"]):
        icon = "✓" if r["status"] == "OK" else "⚠" if r["status"] == "WARN" else "✗"
        print(f"{r['id']:<30} {icon} {r['status']:<4} {r['issues']}")

    ok_count = sum(1 for r in results if r["status"] == "OK")
    warn_count = sum(1 for r in results if r["status"] == "WARN")
    print(f"\n정상: {ok_count}, 경고: {warn_count}, 오류: {len(results)-ok_count-warn_count}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="위협 헌팅 가설 관리 및 추적 CLI 도구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
예시:
  python3 hunt_tracker.py add -t "LSASS 메모리 덤프" -H "공격자가 mimikatz로 LSASS를 덤프할 것" \\
      --technique T1003.001 --tactic "TA0006-Credential Access" \\
      --sources "EDR,WinEventLog:4104" --priority high --hours 4

  python3 hunt_tracker.py list --status open --priority high
  python3 hunt_tracker.py update --id HYP-20240101-AB12 --status in_progress \\
      --finding "powershell.exe가 lsass에 OpenProcess 호출 발견"
  python3 hunt_tracker.py report --id HYP-20240101-AB12
  python3 hunt_tracker.py stats
  python3 hunt_tracker.py bulk-analyze
        """,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # add
    p_add = sub.add_parser("add", help="새 헌팅 가설 추가")
    p_add.add_argument("-t", "--title", required=True, help="가설 제목")
    p_add.add_argument("-H", "--hypothesis", required=True, help="가설 내용")
    p_add.add_argument("--technique", default="", help="MITRE ATT&CK 기술 ID (예: T1059.001)")
    p_add.add_argument("--tactic", default="", choices=MITRE_TACTICS + [""], help="MITRE ATT&CK 전술")
    p_add.add_argument("--sources", default="", help="데이터 소스 (쉼표 구분)")
    p_add.add_argument("--priority", default="medium", choices=PRIORITY_OPTIONS, help="우선순위")
    p_add.add_argument("--analyst", default="", help="담당 분석가")
    p_add.add_argument("--hours", type=float, default=0, help="예상 소요 시간 (h)")
    p_add.add_argument("--tags", default="", help="태그 (쉼표 구분)")
    p_add.set_defaults(func=cmd_add)

    # list
    p_list = sub.add_parser("list", help="헌팅 가설 목록")
    p_list.add_argument("--status", choices=STATUS_OPTIONS, help="상태 필터")
    p_list.add_argument("--priority", choices=PRIORITY_OPTIONS, help="우선순위 필터")
    p_list.add_argument("--analyst", help="담당자 필터")
    p_list.set_defaults(func=cmd_list)

    # update
    p_upd = sub.add_parser("update", help="헌팅 가설 업데이트")
    p_upd.add_argument("--id", required=True, help="헌팅 가설 ID")
    p_upd.add_argument("--status", choices=STATUS_OPTIONS, help="새 상태")
    p_upd.add_argument("--finding", help="발견 사항 추가")
    p_upd.add_argument("--query", help="실행된 쿼리 추가")
    p_upd.add_argument("--platform", help="쿼리 플랫폼 (KQL/SPL/SQL 등)")
    p_upd.add_argument("--analyst", help="담당 분석가")
    p_upd.add_argument("--hours", type=float, help="실제 투입 시간 (h)")
    p_upd.set_defaults(func=cmd_update)

    # report
    p_rep = sub.add_parser("report", help="상세 보고서")
    p_rep.add_argument("--id", required=True, help="헌팅 가설 ID")
    p_rep.set_defaults(func=cmd_report)

    # stats
    p_stats = sub.add_parser("stats", help="통계 및 커버리지 분석")
    p_stats.set_defaults(func=cmd_stats)

    # bulk-analyze
    p_bulk = sub.add_parser("bulk-analyze", help="병렬 유효성 검사")
    p_bulk.set_defaults(func=cmd_bulk_analyze)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
```

---

## 7. 헌팅 팁 및 모범 사례

### 7.1 효과적인 헌팅을 위한 원칙

1. **데이터 품질 우선**: 로그가 없으면 헌팅도 없다. 먼저 수집 환경을 점검한다.
2. **가설 문서화**: 모든 가설과 결과를 기록한다. 재사용 가능한 자산이 된다.
3. **시간 박싱**: 가설당 최대 투입 시간을 정한다. 결과가 없어도 중단 기준을 지킨다.
4. **베이스라인 필수**: 정상 행위를 모르면 이상 행위를 찾을 수 없다.
5. **팀 협업**: 단독 헌팅보다 2~3인 팀이 더 효과적이다.

### 7.2 흔한 실수

- 너무 광범위한 가설 설정 → 구체적인 TTP로 범위 좁히기
- 데이터 없이 가설 수립 → 먼저 데이터 가용성 확인
- 탐지 실패를 성공으로 착각 → "없음"도 하나의 결과
- 결과를 탐지 규칙으로 미전환 → 모든 헌팅은 자동화로 이어져야 함

### 7.3 KPI 측정 항목

| 지표 | 설명 |
|------|------|
| Hunt Coverage | 커버된 MITRE ATT&CK 기술 비율 |
| True Positive Rate | 헌팅으로 발견된 실제 위협 비율 |
| Mean Hunt Duration | 평균 헌팅 소요 시간 |
| Automation Conversion Rate | 헌팅 → 탐지 규칙 전환 비율 |
| Dwell Time Reduction | 헌팅 도입 후 평균 잠복 기간 감소 |

---

<a name="english"></a>

# Threat Hunting Methodology

## 1. What is Threat Hunting?

### 1.1 Definition

Threat Hunting is a cybersecurity activity that **proactively and iteratively searches** for hidden threats that existing security tools have failed to detect. Rather than simply responding to alerts, analysts search networks and endpoints based on hypotheses and intelligence.

- **Goal**: Reduce dwell time of lurking attackers, discover new TTPs, improve detection logic
- **Keywords**: Proactive, Hypothesis-driven, Iterative

### 1.2 Differences from Reactive Security

| Category | Reactive Security | Threat Hunting (Proactive) |
|----------|------------------|---------------------------|
| Trigger | Alert or incident occurrence | Analyst hypothesis |
| Starting point | Alert | Intelligence and data |
| Purpose | Incident response and recovery | Discover hidden threats |
| Detection time | Average 207 days (IBM report) | Goal: reduce dwell time |
| Output | Incident report | New detection rules, TTP identification |

### 1.3 Value of Threat Hunting

1. **MTTD (Mean Time to Detect) reduction**: Reduce dwell time
2. **Detection gap discovery**: Identify blind spots in existing SIEM rules
3. **Threat intelligence generation**: IOC/TTP data tailored to internal environment
4. **Security operations maturity improvement**: Hunting results convert to automated detection

---

## 2. Hunting Maturity Model (HMM)

Proposed by Sqrrl and adopted as industry standard, HMM evaluates an organization's hunting capabilities on a 0-4 scale.

### HMM Level 0 — Initial

- **Characteristics**: No log collection, detection relies only on AV/IDS alerts
- **Data quality**: Nearly none
- **Automation**: None
- **Hunting**: Impossible
- **Actions**: Enable basic logging, implement SIEM

### HMM Level 1 — Minimal

- **Characteristics**: Some log collection, basic IOC search possible
- **Data quality**: IP/domain/hash-based matching
- **Automation**: Manual query execution
- **Hunting**: Simple IOC-based search
- **Actions**: Integrate threat intelligence feeds

### HMM Level 2 — Procedural

- **Characteristics**: Follow hunting procedures from other teams
- **Data quality**: Structured logs, EDR data available
- **Automation**: Some query automation
- **Hunting**: TTP-based, using documented playbooks
- **Actions**: Standardize internal procedures, write playbooks

### HMM Level 3 — Innovative

- **Characteristics**: Create own TTP-based hunting procedures
- **Data quality**: Rich context, behavioral data
- **Automation**: Repetitive hunting automation
- **Hunting**: Hypothesis-based, custom analysis
- **Actions**: Internal research, develop new detection techniques

### HMM Level 4 — Leading

- **Characteristics**: ML-based anomaly detection, industry-leading
- **Data quality**: Complete visibility, real-time streaming
- **Automation**: Advanced automation, feedback loop
- **Hunting**: Predictive hunting, behavioral analysis
- **Actions**: Publish research, community contributions

---

## 3. Hypothesis-Based Hunting Process

### 3.1 The Hunting Loop

```
[Form Hypothesis] → [Collect Data] → [Perform Analysis] → [Find Patterns] → [Respond/Report] → [Automate]
     ↑                                                                                                |
     └────────────────────────────────────────────────────────────────────────────────────────────────┘
```

### 3.2 Hypothesis Generation Methods

**Method 1: Intelligence-Based**
- Reference latest threat reports (Mandiant, CrowdStrike, etc.)
- Apply TTPs of industry-specific threat groups
- Example: "Reports indicate APT28 uses T1566 (phishing) for initial access followed by T1059 (command-line)"

**Method 2: Environment-Based**
- Utilize internal vulnerability scan results
- Target recently unpatched vulnerabilities
- Example: "Log4Shell vulnerable systems may exist in our environment"

**Method 3: Analyst Experience**
- Past incident patterns
- "In the last breach, the attacker used WMI for lateral movement"

**Method 4: MITRE ATT&CK**
- Select techniques with low coverage in the matrix
- Example: "T1003 (credential dumping) detection is insufficient"

### 3.3 Hypothesis Documentation Format

```
Hypothesis ID: HYP-2024-001
Title: Abnormal Process Execution via PowerShell
MITRE ATT&CK: T1059.001 (PowerShell)
Hypothesis:
  The attacker will execute PowerShell with encoded commands
  to bypass security solution detection.
Data Sources: Windows Event Log (ID 4104), EDR Process logs
Hunting Queries:
  - Detect encoded parameters (-enc, -encodedcommand)
  - Base64 encoding length exceeds threshold
  - Abnormal parent process (Office → PowerShell)
Success Criteria: Find suspicious instances or confirm normal behavior
Estimated Time: 4 hours
```

### 3.4 Processing Hunting Results

- **When threat found**: Escalate to incident response team → Create detection rule
- **When no threat found**: Strengthen normal behavior baseline → Move to next hypothesis
- **All cases**: Document results, measure KPIs (detection rate, time spent, etc.)

---

## 4. Data Sources

### 4.1 EDR (Endpoint Detection and Response)

EDR is the core data source for threat hunting, collecting detailed endpoint-level behaviors.

**Collected Data**:
- Process creation/termination (including command-line arguments)
- File creation/modification/deletion
- Registry changes
- Network connections (per process)
- Driver loading
- WMI event subscriptions

**Key EDR Solutions**: CrowdStrike Falcon, Microsoft Defender for Endpoint, Carbon Black, SentinelOne

### 4.2 NDR (Network Detection and Response)

**Collected Data**:
- Full packet capture (PCAP)
- Flow data (NetFlow, IPFIX)
- DNS queries/responses
- HTTP/HTTPS metadata
- Certificate information
- Protocol anomaly detection

### 4.3 Logs

**Key Windows Event Log IDs**:
| Event ID | Description |
|----------|-------------|
| 4624 | Logon success |
| 4625 | Logon failure |
| 4688 | Process creation |
| 4698 | Scheduled task creation |
| 4720 | Account creation |
| 7045 | New service installation |
| 4104 | PowerShell script block logging |

**Key Linux Logs**:
- `/var/log/auth.log`: Authentication events
- `/var/log/syslog`: System events
- Auditd: System call auditing
- `/proc/`: Process information

### 4.4 NetFlow

NetFlow provides IP traffic statistics, analyzing network behavior with less storage space than full packet capture.

**Hunting Use Cases**:
- Abnormal data transfer volume (data exfiltration detection)
- New communication pairs (C2 connection detection)
- Port scanning patterns
- Non-standard port usage
- Beaconing pattern analysis

---

## 5. MITRE ATT&CK-Based Hunting Prioritization

### 5.1 Prioritization Criteria

1. **Impact**: Damage scale if the technique succeeds
2. **Frequency**: Frequency of use in actual attacks (ATT&CK statistics)
3. **Detection gap**: Areas with insufficient current detection coverage
4. **Environment suitability**: Feasible attack paths in the internal environment

### 5.2 Priority by Tactic

```
Priority 1 (Immediate Hunting):
  - T1003: OS Credential Dumping (Lsass dump)
  - T1055: Process Injection
  - T1059: Command and Scripting Interpreter
  - T1078: Valid Accounts

Priority 2 (Weekly Hunting):
  - T1566: Phishing
  - T1021: Remote Services
  - T1547: Boot/Logon Autostart Execution
  - T1053: Scheduled Task/Job

Priority 3 (Monthly Hunting):
  - T1190: Exploit Public-Facing Application
  - T1027: Obfuscated Files or Information
  - T1083: File and Directory Discovery
```

---

## 6. Hunting Tips and Best Practices

### 6.1 Principles for Effective Hunting

1. **Data quality first**: No logs, no hunting. Check the collection environment first.
2. **Document hypotheses**: Record all hypotheses and results. They become reusable assets.
3. **Time-boxing**: Set maximum time per hypothesis. Stop when criteria are met even without results.
4. **Baseline required**: Cannot find anomalous behavior without knowing normal behavior.
5. **Team collaboration**: A team of 2-3 is more effective than hunting alone.

### 6.2 Common Mistakes

- Setting too broad a hypothesis → narrow scope to specific TTPs
- Forming hypothesis without data → first check data availability
- Mistaking detection failure for success → "nothing found" is also a result
- Not converting results to detection rules → all hunting should lead to automation

### 6.3 KPI Measurement Items

| Metric | Description |
|--------|-------------|
| Hunt Coverage | Percentage of MITRE ATT&CK techniques covered |
| True Positive Rate | Percentage of actual threats found through hunting |
| Mean Hunt Duration | Average hunting time |
| Automation Conversion Rate | Hunting → detection rule conversion rate |
| Dwell Time Reduction | Reduction in average dwell time after introducing hunting |
