> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 04 — ICS 보안 아키텍처 및 방어 전략

## 0. 초보자를 위한 개념 이해

### ICS 보안이 일반 IT 보안과 다른 이유

**ICS(Industrial Control System)**는 공장, 발전소, 수자원 시설 등 물리적 인프라를 제어합니다.

```
IT 보안 (정보 기술):
  주요 관심사: CIA (기밀성, 무결성, 가용성)
  우선순위: 기밀성 > 무결성 > 가용성
  침해 결과: 데이터 유출, 서비스 중단
  패치 방식: 빠른 패치 권장
  
OT/ICS 보안 (운영 기술):
  주요 관심사: 가용성 > 무결성 > 기밀성
  우선순위: 가용성 최우선 (멈추면 안 됨!)
  침해 결과: 물리적 손상, 인명 피해, 환경 재해
  패치 방식: 테스트 후 계획적으로 (무중단)
```

**비유:**
- IT 서버 해킹 = 회사 서류 도난 (재산 피해)
- ICS 해킹 = 발전소/댐 제어 시스템 탈취 (국가 인프라 위기)

### Purdue Reference Model (퍼듀 참조 모델)

ICS 환경의 네트워크 계층 구조를 나타내는 표준 모델입니다:

```
레벨 5: 엔터프라이즈 IT
  회사 네트워크, 이메일, ERP
  ↕ (방화벽)
레벨 4: 비즈니스 인텔리전스
  MES (제조실행시스템), 히스토리안
  ↕ (DMZ)
레벨 3: 운영 관리
  SCADA 서버, 히스토리안
  ↕ (방화벽)
레벨 2: 지역 제어
  HMI, 엔지니어링 워크스테이션
  ↕
레벨 1: 기초 제어
  PLC, DCS, RTU
  ↕
레벨 0: 현장 장치
  센서, 액추에이터, 모터, 밸브
  (실제 물리적 프로세스)
```

**공격자 목표:** 레벨 0의 물리적 장치를 직접 제어하는 것

### OT/ICS 보안의 특수한 도전

```
레거시 시스템:
  20~30년 된 PLC가 현역
  → 패치, 업그레이드 어려움 또는 불가
  → 알려진 취약점이 있어도 수정 불가

가용성 요구사항:
  발전소: 365일 24시간 운영
  → 패치를 위한 다운타임 허용 안 됨
  → 연간 정기 점검 시에만 패치 기회

공기 간격(Air Gap) 신화:
  "인터넷에 연결 안 되어 있으면 안전하다"
  → Stuxnet이 USB로 에어갭 우회 (2010)
  → 유지보수용 노트북이 악성코드 전달
```

---

## 목차
1. ICS 보안 아키텍처 설계 원칙
2. 네트워크 세분화 및 DMZ 구성
3. ICS 전용 보안 솔루션
4. 취약점 관리 및 패치 전략
5. ICS 보안 모니터링 체계
6. 인시던트 대응 및 복구
7. Python 도구: ICS 자산 위험도 평가기
8. ICS 보안 컴플라이언스 (NERC CIP · IEC 62443)

---

## 1. ICS 보안 아키텍처 설계 원칙

### 1.1 심층 방어(Defense-in-Depth) 모델

ICS 환경에서 심층 방어는 물리적·논리적·관리적 통제를 계층화한다.

```
┌─────────────────────────────────────────────┐
│  레벨 5: 기업 네트워크 (IT 영역)               │
│  방화벽 + DMZ + SIEM                         │
├─────────────────────────────────────────────┤
│  DMZ: Historian 미러, 파일 전송 서버           │
│  단방향 데이터 다이오드 또는 이중 방화벽         │
├─────────────────────────────────────────────┤
│  레벨 3: 운영 네트워크                         │
│  MES, SCADA 서버, 엔지니어링 워크스테이션       │
├─────────────────────────────────────────────┤
│  레벨 2: 제어 네트워크                         │
│  HMI, DCS 컨트롤러                            │
├─────────────────────────────────────────────┤
│  레벨 1: 필드 레벨                            │
│  PLC, RTU, 지능형 전자 장치(IED)              │
├─────────────────────────────────────────────┤
│  레벨 0: 물리적 프로세스                       │
│  센서, 액추에이터, 밸브, 모터                  │
└─────────────────────────────────────────────┘
```

**핵심 원칙:**
- **최소 권한**: 각 레벨은 업무상 필요한 통신만 허용
- **격리**: OT 네트워크는 인터넷 직접 연결 금지
- **가용성 우선**: 보안 조치가 운영 연속성을 침해하면 안 됨
- **레거시 고려**: 패치 불가 시스템을 위한 보완 통제

### 1.2 제로 트러스트 OT 모델

전통적 "내부 신뢰" 모델은 ICS에서도 폐기되는 추세다.

```
전통 모델                    제로 트러스트 OT 모델
─────────────────           ─────────────────────────
IT/OT 경계 신뢰              모든 연결 지속 검증
내부 트래픽 허용              최소 권한 세션 기반 접근
VPN = 완전 접근              원격 접근 시 MFA + 세션 기록
공급업체 원격 신뢰             공급업체 접근 주문형 격리 채널
```

---

## 2. 네트워크 세분화 및 DMZ 구성

### 2.1 이중 방화벽 DMZ

```
[IT 네트워크]
     │
  [방화벽 A] ← IT 정책 (표준 방화벽)
     │
  [DMZ 영역]
  ├── Historian 미러 (읽기 전용)
  ├── 파일 전송 서버 (단방향)
  ├── 원격 접근 게이트웨이
  └── 패치 배포 서버
     │
  [방화벽 B] ← OT 정책 (화이트리스트 기반)
     │
  [OT 네트워크]
```

**방화벽 B 화이트리스트 규칙 예시:**

| 출발지 | 목적지 | 포트 | 프로토콜 | 목적 |
|--------|--------|------|----------|------|
| DMZ Historian | OT Historian | 1433 | MSSQL | 데이터 동기화 |
| 패치 서버 | WSUS 에이전트 | 8530 | HTTPS | Windows 업데이트 |
| 원격 게이트웨이 | HMI | 3389 | RDP | 엔지니어 접근 |
| 모든 OT | SIEM | 514 | Syslog | 로그 전송 |

### 2.2 데이터 다이오드(단방향 게이트웨이)

**사용 사례:** OT → IT 방향으로만 데이터 전송 (역방향 물리적 차단)

```
OT 네트워크          데이터 다이오드        IT 네트워크
─────────────       ────────────────      ─────────────
Historian ──TX──►  [광섬유 단방향]  ──►  Historian 미러
(원본)              물리적 RX 없음         (복제본)
```

**솔루션:** Owl Cyber Defense, Waterfall Security, Fox DataDiode

### 2.3 VLAN 및 마이크로세분화

```bash
# Cisco IOS 기반 OT VLAN 설정 예시
interface GigabitEthernet0/1
  description PLC_Network
  switchport mode access
  switchport access vlan 100
  storm-control broadcast level 10
  spanning-tree portfast
  ip arp inspection limit rate 100

# ACL: PLC VLAN → HMI VLAN만 허용 (역방향 차단)
ip access-list extended OT_VLAN_POLICY
  permit tcp 192.168.100.0 0.0.0.255 192.168.200.0 0.0.0.255 eq 102
  permit udp 192.168.100.0 0.0.0.255 192.168.200.0 0.0.0.255 eq 502
  deny   ip any any log
```

---

## 3. ICS 전용 보안 솔루션

### 3.1 ICS 패시브 모니터링 솔루션 비교

| 솔루션 | 제조사 | 주요 기능 | 지원 프로토콜 |
|--------|--------|-----------|---------------|
| Dragos Platform | Dragos | 위협 탐지, 자산 인벤토리 | 250+ OT 프로토콜 |
| Claroty xDome | Claroty | 자산 가시성, 취약점 관리 | Modbus, DNP3, PROFINET |
| Nozomi Networks | Nozomi | AI 이상 탐지, 네트워크 가시성 | 150+ 프로토콜 |
| Tenable OT | Tenable | 취약점 스캐닝, 컴플라이언스 | 주요 ICS 프로토콜 |
| Microsoft Defender for IoT | Microsoft | 에이전트리스 탐지 | IT/OT 통합 |

### 3.2 패시브 트래픽 분석 구성

```
OT 네트워크 스위치
      │
   [SPAN 포트] ─────────────► ICS 모니터링 센서
      │                        (Dragos/Claroty/Nozomi)
   [TAP 장치] ──────────────► 패킷 캡처 서버
                               (장기 보관)
```

### 3.3 산업용 방화벽 기능

ICS 전용 방화벽은 OT 프로토콜 DPI(심층 패킷 검사)를 지원한다.

```
Modbus TCP DPI 예시:
  허용: Function Code 03 (읽기만 허용)
  차단: Function Code 05, 06 (코일/레지스터 쓰기 차단)
  알림: Function Code 08 (진단 명령)

Profinet DPI:
  허용: DCP(Discovery), CyclicData
  차단: Acyclic Write (파라미터 변경 차단)
```

---

## 4. 취약점 관리 및 패치 전략

### 4.1 OT 패치 관리의 어려움

| 문제 | 설명 | 완화 방법 |
|------|------|-----------|
| 가동 중단 불가 | 24/7 운영 시스템 | 계획된 정비 창(Maintenance Window) 활용 |
| 제조사 인증 필요 | 미인증 패치 시 보증 무효 | 제조사 승인 패치만 적용 |
| 레거시 OS | 지원 종료 Windows XP/7 | 가상화 격리, 보완 통제 적용 |
| 테스트 환경 부재 | 패치 전 테스트 불가 | 디지털 트윈/시뮬레이터 구축 |
| 긴 패치 주기 | 분기·반기별 패치 | 네트워크 세분화로 위험 감소 |

### 4.2 보완 통제(Compensating Controls)

패치 적용이 불가한 레거시 시스템을 위한 대안:

```
레거시 PLC/HMI 보호 전략:

1. 네트워크 격리
   - 전용 VLAN, ACL로 최소 통신만 허용
   - 해당 세그먼트로의 접근 제어

2. 애플리케이션 화이트리스팅
   - McAfee Application Control, Bit9/Carbon Black
   - 허용된 실행 파일 외 모든 프로세스 차단

3. 포트/프로토콜 제한
   - USB 포트 물리적 봉인
   - 사용하지 않는 서비스 비활성화

4. 모니터링 강화
   - 해당 시스템 트래픽 100% 캡처
   - 기준선 대비 이상 탐지

5. 물리적 접근 통제
   - 잠금 캐비닛, 물리적 자물쇠
   - 접근 로그 유지
```

---

## 5. ICS 보안 모니터링 체계

### 5.1 ICS SOC 모니터링 레벨

```
레벨 1: 자산 가시성
  - 모든 OT 자산 인벤토리 (IP, MAC, 펌웨어, 프로토콜)
  - 통신 기준선 수립

레벨 2: 이상 탐지
  - 기준선 대비 통신 패턴 이탈
  - 알려진 OT 취약점 악용 탐지
  - 비정상 Modbus/DNP3 Function Code

레벨 3: 위협 인텔리전스 연동
  - OT 특화 CTI (Dragos WorldView, ICS-CERT)
  - APT 그룹 TTP 매핑 (TRITON, Industroyer, CRASHOVERRIDE)
  - IOC 자동 비교

레벨 4: 상관관계 분석
  - IT/OT 이벤트 상관분석
  - 물리적 이벤트와 사이버 이벤트 연계
  - 다단계 공격 시퀀스 탐지
```

### 5.2 OT 핵심 로그 소스

| 로그 소스 | 수집 방법 | 핵심 이벤트 |
|-----------|-----------|-------------|
| 방화벽 (IT/OT 경계) | Syslog | 정책 위반, 비허가 연결 |
| ICS 모니터링 센서 | SIEM API | OT 이상 알림 |
| 엔지니어링 워크스테이션 | WEF/Sysmon | 프로젝트 파일 변경, USB |
| HMI | OPC 이벤트 | 오퍼레이터 조작, 알람 |
| 네트워크 스위치 | SNMP/NetFlow | 트래픽 기준선 이탈 |
| 인증 서버 | LDAP/RADIUS | 로그인 실패, 비정상 시간 |

---

## 6. 인시던트 대응 및 복구

### 6.1 OT 인시던트 대응 계획의 특수성

```
IT 인시던트 대응        OT 인시던트 대응
─────────────          ─────────────────────
격리 → 근절 → 복구     가용성 유지 → 봉쇄 → 분석 → 복구

핵심 차이점:
- 즉각적 시스템 종료 불가 (물리적 프로세스 안전 확보 우선)
- 물리적 영향 평가 필수 (인명, 환경 피해 가능성)
- 복구 시간 목표(RTO): 수 시간 ~ 수 일
- 백업 PLC 프로그램 가용성 사전 확보 필수
```

### 6.2 OT 인시던트 대응 단계

```
단계 1: 탐지 및 분석 (Detection & Analysis)
  ├── OT 보안 팀에 즉시 통보
  ├── 물리적 프로세스 안전 상태 확인
  ├── 영향받은 시스템 범위 확정
  └── 운영팀 협조 요청

단계 2: 봉쇄 (Containment)
  ├── 영향받은 세그먼트 네트워크 격리
  ├── 감염 시스템 수동 운전 전환 (필요 시)
  ├── 백업 엔지니어링 워크스테이션 준비
  └── 원격 접근 임시 차단

단계 3: 근절 (Eradication)
  ├── 악성 코드/구성 변경 제거
  ├── PLC 프로그램 무결성 검증
  ├── 공장 초기화 (Factory Reset) 고려
  └── 알려진 양호 스냅샷으로 복원

단계 4: 복구 (Recovery)
  ├── 네트워크 재연결 전 검증 체크리스트
  ├── 단계적 프로세스 재가동
  ├── 모니터링 강화 기간 운영 (30일)
  └── 운영 팀 확인 후 정상화

단계 5: 사후 분석 (Lessons Learned)
  ├── 타임라인 문서화
  ├── 루트 원인 분석
  ├── 규제 기관 보고 (NERC CIP, ICS-CERT)
  └── 보안 아키텍처 개선 계획
```

---

## 7. Python 도구: ICS 자산 위험도 평가기

```python
#!/usr/bin/env python3
"""
ICS Asset Risk Assessor
OT 네트워크 자산의 위험도를 다차원 스코어링으로 평가
"""

from __future__ import annotations
import argparse
import csv
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


CVSS_WEIGHT = 0.35
EXPOSURE_WEIGHT = 0.25
IMPACT_WEIGHT = 0.25
PATCH_WEIGHT = 0.15

RISK_BANDS = [
    (9.0, "CRITICAL", "즉시 조치 필요"),
    (7.0, "HIGH",     "30일 내 조치"),
    (4.0, "MEDIUM",   "분기 내 조치"),
    (0.0, "LOW",      "연간 검토"),
]


@dataclass
class Asset:
    name: str
    ip: str
    asset_type: str           # PLC | HMI | EWS | Historian | Network
    os: str
    os_patched: bool
    firmware_version: str
    firmware_patched: bool
    network_exposure: str     # isolated | internal | dmz | internet
    cvss_scores: list[float] = field(default_factory=list)
    criticality: str = "HIGH" # LOW | MEDIUM | HIGH | CRITICAL
    has_backup: bool = True
    remote_access_enabled: bool = False
    default_credentials: bool = False
    notes: str = ""

    @property
    def max_cvss(self) -> float:
        return max(self.cvss_scores) if self.cvss_scores else 0.0

    @property
    def exposure_score(self) -> float:
        mapping = {"isolated": 1.0, "internal": 4.0, "dmz": 7.0, "internet": 10.0}
        base = mapping.get(self.network_exposure, 5.0)
        if self.remote_access_enabled:
            base = min(10.0, base + 1.5)
        if self.default_credentials:
            base = min(10.0, base + 2.0)
        return base

    @property
    def impact_score(self) -> float:
        criticality_map = {"LOW": 3.0, "MEDIUM": 5.0, "HIGH": 8.0, "CRITICAL": 10.0}
        base = criticality_map.get(self.criticality, 5.0)
        if not self.has_backup:
            base = min(10.0, base + 1.0)
        return base

    @property
    def patch_score(self) -> float:
        """패치 미적용 점수 (높을수록 위험)"""
        unpatched = 0
        total = 2
        if not self.os_patched:
            unpatched += 1
        if not self.firmware_patched:
            unpatched += 1
        return (unpatched / total) * 10.0

    @property
    def risk_score(self) -> float:
        return (
            self.max_cvss * CVSS_WEIGHT
            + self.exposure_score * EXPOSURE_WEIGHT
            + self.impact_score * IMPACT_WEIGHT
            + self.patch_score * PATCH_WEIGHT
        )

    @property
    def risk_level(self) -> tuple[str, str]:
        score = self.risk_score
        for threshold, label, action in RISK_BANDS:
            if score >= threshold:
                return label, action
        return "LOW", "연간 검토"


def load_assets_from_csv(path: Path) -> list[Asset]:
    assets: list[Asset] = []
    with path.open(encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            cvss_raw = row.get("cvss_scores", "")
            cvss_scores = [
                float(s.strip()) for s in cvss_raw.split(";") if s.strip()
            ] if cvss_raw else []

            assets.append(Asset(
                name=row["name"],
                ip=row["ip"],
                asset_type=row.get("asset_type", "Unknown"),
                os=row.get("os", "Unknown"),
                os_patched=row.get("os_patched", "false").lower() == "true",
                firmware_version=row.get("firmware_version", "Unknown"),
                firmware_patched=row.get("firmware_patched", "false").lower() == "true",
                network_exposure=row.get("network_exposure", "internal"),
                cvss_scores=cvss_scores,
                criticality=row.get("criticality", "HIGH").upper(),
                has_backup=row.get("has_backup", "true").lower() == "true",
                remote_access_enabled=row.get("remote_access", "false").lower() == "true",
                default_credentials=row.get("default_creds", "false").lower() == "true",
                notes=row.get("notes", ""),
            ))
    return assets


def load_assets_from_json(path: Path) -> list[Asset]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return [Asset(**item) for item in data]


def generate_report(assets: list[Asset], output_format: str) -> str:
    sorted_assets = sorted(assets, key=lambda a: a.risk_score, reverse=True)

    if output_format == "json":
        result = []
        for a in sorted_assets:
            level, action = a.risk_level
            result.append({
                "name": a.name,
                "ip": a.ip,
                "type": a.asset_type,
                "risk_score": round(a.risk_score, 2),
                "risk_level": level,
                "recommended_action": action,
                "max_cvss": a.max_cvss,
                "exposure": a.network_exposure,
                "criticality": a.criticality,
                "os_patched": a.os_patched,
                "firmware_patched": a.firmware_patched,
                "notes": a.notes,
            })
        return json.dumps(result, ensure_ascii=False, indent=2)

    # 텍스트 리포트
    lines: list[str] = []
    lines.append("=" * 70)
    lines.append("ICS 자산 위험도 평가 보고서")
    lines.append("=" * 70)

    summary: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for a in sorted_assets:
        level, _ = a.risk_level
        summary[level] += 1

    lines.append(f"\n[요약] 총 자산: {len(assets)}개")
    for level, count in summary.items():
        lines.append(f"  {level:8s}: {count}개")

    lines.append("\n[자산별 위험도 상세]")
    lines.append("-" * 70)

    for a in sorted_assets:
        level, action = a.risk_level
        lines.append(f"\n자산명  : {a.name} ({a.ip})")
        lines.append(f"유형    : {a.asset_type} | OS: {a.os}")
        lines.append(f"위험도  : {level} (스코어: {a.risk_score:.2f}/10.0)")
        lines.append(f"권고조치: {action}")
        lines.append(f"세부    : CVSS={a.max_cvss:.1f}, 노출={a.network_exposure}, "
                     f"중요도={a.criticality}")
        patch_status = []
        if not a.os_patched:
            patch_status.append("OS 미패치")
        if not a.firmware_patched:
            patch_status.append("펌웨어 미패치")
        if a.remote_access_enabled:
            patch_status.append("원격접근 활성화")
        if a.default_credentials:
            patch_status.append("기본 자격증명 사용")
        if patch_status:
            lines.append(f"위험요인: {', '.join(patch_status)}")
        if a.notes:
            lines.append(f"비고    : {a.notes}")

    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="ICS 자산 위험도 평가기 — 다차원 스코어링 기반 OT 자산 분석",
    )
    parser.add_argument(
        "input",
        type=Path,
        help="자산 목록 파일 (.csv 또는 .json)",
    )
    parser.add_argument(
        "-f", "--format",
        choices=["text", "json"],
        default="text",
        help="출력 형식 (기본: text)",
    )
    parser.add_argument(
        "-o", "--output",
        type=Path,
        help="결과 저장 파일 (미지정 시 stdout)",
    )
    parser.add_argument(
        "--min-risk",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        default="LOW",
        help="이 수준 이상의 자산만 출력 (기본: LOW)",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if not args.input.exists():
        print(f"[오류] 파일을 찾을 수 없습니다: {args.input}", file=sys.stderr)
        sys.exit(1)

    try:
        if args.input.suffix == ".csv":
            assets = load_assets_from_csv(args.input)
        elif args.input.suffix == ".json":
            assets = load_assets_from_json(args.input)
        else:
            print(f"[오류] 지원하지 않는 파일 형식: {args.input.suffix}", file=sys.stderr)
            sys.exit(1)
    except Exception as exc:
        print(f"[오류] 파일 로드 실패: {exc}", file=sys.stderr)
        sys.exit(1)

    # 최소 위험 수준 필터링
    rank = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    min_rank = rank[args.min_risk]
    filtered = [a for a in assets if rank[a.risk_level[0]] >= min_rank]

    report = generate_report(filtered, args.format)

    if args.output:
        args.output.write_text(report, encoding="utf-8")
        print(f"[완료] 결과 저장: {args.output}")
    else:
        print(report)


if __name__ == "__main__":
    main()
```

**사용 예시:**

```bash
# CSV 파일로 평가
python ics_risk_assessor.py assets.csv

# HIGH 이상 위험 자산만 JSON으로 출력
python ics_risk_assessor.py assets.csv --min-risk HIGH --format json -o report.json

# CSV 예시 (assets.csv)
# name,ip,asset_type,os,os_patched,firmware_version,firmware_patched,
# network_exposure,cvss_scores,criticality,has_backup,remote_access,default_creds,notes
# PLC-A1,192.168.100.10,PLC,VxWorks,false,1.2.3,false,internal,9.8;7.5,CRITICAL,false,false,true,생산 라인 제어
# HMI-01,192.168.200.5,HMI,Windows 7,false,N/A,true,dmz,,HIGH,true,true,false,운영자 화면
```

---

## 8. ICS 보안 컴플라이언스

### 8.1 NERC CIP (북미 전력망)

Critical Infrastructure Protection 표준 — 전력 산업 필수 규정.

| 표준 | 제목 | 핵심 요구사항 |
|------|------|---------------|
| CIP-002 | 자산 분류 | BES 사이버 시스템 식별 |
| CIP-003 | 보안 관리 | 정책, 리더십, 예외 관리 |
| CIP-005 | 전자적 보안 경계 | ESP 정의, 원격 접근 통제 |
| CIP-007 | 시스템 보안 | 포트 관리, 패치, 계정 관리 |
| CIP-010 | 구성 관리 | 기준선 구성, 변경 관리 |
| CIP-013 | 공급망 위험 | 벤더 리스크 관리 |

### 8.2 IEC 62443 (산업 자동화 보안)

국제 OT 보안 표준 체계 — 보안 레벨(SL) 0~4 정의.

```
보안 레벨(Security Level):
  SL 0: 보안 요구사항 없음
  SL 1: 의도하지 않은 공격에 저항
  SL 2: 일반 기술의 고의적 공격에 저항
  SL 3: 정교한 기술의 고의적 공격에 저항
  SL 4: 국가급 수준의 공격에 저항

IEC 62443 시리즈 구조:
  62443-1: 일반 개념 및 용어
  62443-2: 정책 및 절차 (조직)
  62443-3: 시스템 보안 요구사항
  62443-4: 컴포넌트 보안 요구사항
```

### 8.3 KISA 산업제어시스템 보안 가이드

국내 ICS 보안 지침 (과학기술정보통신부/KISA 발간):

```
주요 가이드라인:
1. 산업제어시스템 보안 가이드 (2021)
   - ICS 보안 위협 분석
   - 네트워크 구성 보안 방안
   - 보안 솔루션 적용 방안

2. 원자력·에너지 분야 사이버 보안 (NRC/NSSC)
   - 핵안보 요건 충족
   - 방사선 방호 시스템 보호

참조 링크:
  https://www.kisa.or.kr/ics
  https://www.cisa.gov/topics/industrial-control-systems
```

---

## 참고 자료

- **NIST SP 800-82 r3** — 산업제어시스템 보안 가이드
- **ICS-CERT Advisory** — [https://www.cisa.gov/ics-advisories](https://www.cisa.gov/ics-advisories)
- **Dragos Year In Review** — OT 위협 연간 보고서
- **ENISA ICS/SCADA** — 유럽 OT 보안 프레임워크
- **Idaho National Lab** — ICS-CERT 합동 훈련 자료

---

<!-- detect-validate-37 -->
## ICS 보안 아키텍처 검증 (설정됨 ≠ 작동함)

ICS 보안 아키텍처는 *네트워크 세분화·DMZ·OT 보안 솔루션·패치 전략·모니터링*으로 구성된다. "설계했다"는 다이어그램과 "세분화가 실제로 트래픽을 막는다"는 다르다 — 각 통제를 소유 OT 랩에서 검증한다.

### 검증 항목 → 확인 질문 → 측정 신호 → 함정

| 검증 항목 | 확인 질문 | 측정 신호 | 함정 |
|---|---|---|---|
| 네트워크 세분화 | 레벨 간 차단? | L3→L1 연결 거부 | 다이어그램만, 평면 실재 |
| DMZ | 직접 통과 막나? | IT가 OT 직접 못 닿음 | DMZ 우회 경로 존재 |
| OT 모니터링 | 이상 탐지·로깅? | 비정상 write 알람 | 패시브 탭 없음 |
| 패치 전략 | 위험기반 적용? | 임계 취약 추적 | 무패치 방치 |

### 아키텍처 검증 (직접 확인)

```bash
# 1) 소유 랩에서 L3 호스트가 L1 PLC에 직접 도달 가능한지 — 도달되면 세분화 미작동 신호
nc -z -w2 plc-l1.ot.internal 502 2>&1 | grep -E 'succeeded|open' && echo "L3->L1 reachable (세분화 실패)"
# 2) OT 모니터가 비정상 write를 잡는지(소유 캡처) — 알람 미발생이면 탭 미작동 신호
tshark -r ot_capture.pcap -Y 'modbus.func_code==6' -T fields -e ip.src 2>/dev/null | sort -u | head
```

> ICS 아키텍처는 *세분화가 작동하는가*다 — "DMZ가 설계됐다"와 "L3가 L1에 직접 못 닿고 비정상 write가 모니터에 잡힌다"는 다르다. 각 통제를 소유 OT 랩에서 직접 검증한다([[63_OT_ICS_Advanced]], [[37_ICS_SCADA]], [[39_Zero_Trust_Architecture]]).

---

<a name="english"></a>

# 04 — ICS Security Architecture and Defense Strategy

## 1. ICS Security Architecture Design Principles

### Defense-in-Depth Model

ICS defense-in-depth layers physical, logical, and administrative controls:

- **Level 5**: Enterprise Network (IT zone) — Firewall + DMZ + SIEM
- **DMZ**: Historian mirror, file transfer server — unidirectional data diode or dual firewall
- **Level 3**: Operations Network — MES, SCADA servers, engineering workstations
- **Level 2**: Control Network — HMI, DCS controllers
- **Level 1**: Field Level — PLC, RTU, IEDs
- **Level 0**: Physical Process — sensors, actuators, valves, motors

Core principles: **Least Privilege** (only necessary communications per level), **Isolation** (no direct OT internet connection), **Availability First** (security must not compromise operational continuity), **Legacy Consideration** (compensating controls for unpatchable systems).

### Zero Trust OT Model

Moving away from traditional perimeter trust model toward continuous verification of all connections, least-privilege session-based access, MFA + session recording for remote access, and on-demand isolated channels for vendor access.

---

## 2. Network Segmentation and DMZ Design

### Dual Firewall DMZ

IT Network → Firewall A (IT policy, standard firewall) → DMZ (Historian mirror, file transfer, remote access gateway, patch distribution) → Firewall B (OT policy, whitelist-based) → OT Network.

**Firewall B Whitelist Rules**: Allow DMZ Historian → OT Historian on MSSQL 1433, patch server → WSUS agents on HTTPS 8530, remote gateway → HMI on RDP 3389, all OT → SIEM on Syslog 514.

### Data Diodes (Unidirectional Gateways)

Physically permit only OT→IT data flow (no reverse path): OT Historian ──TX──► [Fiber Optic Unidirectional] ──► IT Historian Mirror. Solutions include Owl Cyber Defense, Waterfall Security, Fox DataDiode.

---

## 3. ICS-Specific Security Solutions

| Solution | Vendor | Key Features | Supported Protocols |
|----------|--------|--------------|---------------------|
| Dragos Platform | Dragos | Threat detection, asset inventory | 250+ OT protocols |
| Claroty xDome | Claroty | Asset visibility, vulnerability management | Modbus, DNP3, PROFINET |
| Nozomi Networks | Nozomi | AI anomaly detection, network visibility | 150+ protocols |
| Tenable OT | Tenable | Vulnerability scanning, compliance | Major ICS protocols |
| Microsoft Defender for IoT | Microsoft | Agentless detection | IT/OT integrated |

ICS-specific firewalls support OT protocol DPI: allow Modbus FC 03 (read only), block FC 05/06 (coil/register writes), alert on FC 08 (diagnostic commands).

---

## 4. Vulnerability Management and Patch Strategy

| Challenge | Description | Mitigation |
|-----------|-------------|------------|
| No downtime allowed | 24/7 operating systems | Use planned maintenance windows |
| Vendor certification required | Unapproved patches void warranty | Apply only vendor-approved patches |
| Legacy OS | End-of-life Windows XP/7 | Virtualized isolation, compensating controls |
| No test environment | Cannot test patches pre-deployment | Build digital twin/simulator |
| Long patch cycles | Quarterly/semi-annual patches | Reduce risk via network segmentation |

---

## 5. ICS Security Monitoring Framework

Four monitoring levels:
1. **Asset Visibility**: Full OT asset inventory (IP, MAC, firmware, protocols), communication baseline
2. **Anomaly Detection**: Communication pattern deviation from baseline, known OT vulnerability exploitation, abnormal Modbus/DNP3 function codes
3. **Threat Intelligence Integration**: OT-specific CTI (Dragos WorldView, ICS-CERT), APT TTP mapping (TRITON, Industroyer), automated IOC comparison
4. **Correlation Analysis**: IT/OT event correlation, physical and cyber event linkage, multi-stage attack sequence detection

---

## 6. Incident Response and Recovery

**OT Incident Response Phases**:
1. Detection & Analysis — notify OT security team, verify physical process safety, determine affected scope
2. Containment — network isolation of affected segments, switch to manual operation if needed, block remote access
3. Eradication — remove malware/config changes, verify PLC program integrity, consider factory reset, restore from known-good snapshot
4. Recovery — validation checklist before network reconnection, staged process restart, 30-day enhanced monitoring
5. Lessons Learned — timeline documentation, root cause analysis, regulatory reporting (NERC CIP, ICS-CERT), security architecture improvements

---

## 7. Python Tool: ICS Asset Risk Assessor

A multi-dimensional risk scoring tool for OT network assets. Calculates weighted risk scores across four dimensions: CVSS (35%), Network Exposure (25%), Business Impact (25%), and Patch Status (15%). Risk bands: CRITICAL (≥9.0), HIGH (≥7.0), MEDIUM (≥4.0), LOW (≥0.0). Supports CSV/JSON input, text/JSON output formats, and minimum severity filtering.

---

## 8. ICS Security Compliance

### NERC CIP (North American Electric Grid)

| Standard | Title | Key Requirements |
|----------|-------|-----------------|
| CIP-002 | Asset Classification | Identify BES Cyber Systems |
| CIP-005 | Electronic Security Perimeter | Define ESP, control remote access |
| CIP-007 | System Security | Port management, patching, account management |
| CIP-010 | Configuration Management | Baseline configuration, change management |
| CIP-013 | Supply Chain Risk | Vendor risk management |

### IEC 62443 (Industrial Automation Security)

Security Levels (SL) 0–4: SL 0 (no requirements) through SL 4 (nation-state attack resistance). The standard series covers general concepts (62443-1), policies/procedures (62443-2), system security requirements (62443-3), and component security requirements (62443-4).

---

## References

- **NIST SP 800-82 r3** — Industrial Control Systems Security Guide
- **ICS-CERT Advisory** — https://www.cisa.gov/ics-advisories
- **Dragos Year In Review** — OT Threat Annual Report
- **ENISA ICS/SCADA** — European OT Security Framework

<!-- detect-validate-37 -->
## ICS Security Architecture Validation (Configured != Working)

ICS security architecture comprises *network segmentation, DMZ, OT security solutions, patch strategy, and monitoring*. "We designed it" differs from "segmentation actually blocks traffic" -- validate each control on owned OT labs.

### Validation item -> Question -> Measured signal -> Pitfall

| Validation item | Question | Measured signal | Pitfall |
|---|---|---|---|
| Network segmentation | Levels blocked? | L3->L1 connection refused | Diagram only, flat in reality |
| DMZ | Block direct pass? | IT cannot reach OT directly | DMZ-bypass path exists |
| OT monitoring | Detect/log anomalies? | Alarm on abnormal write | No passive tap |
| Patch strategy | Risk-based applied? | Critical vulns tracked | Left unpatched |

### Architecture validation (verify directly)

```bash
# 1) Whether an L3 host can directly reach an L1 PLC on an owned lab — reachable signals segmentation does not work
nc -z -w2 plc-l1.ot.internal 502 2>&1 | grep -E 'succeeded|open' && echo "L3->L1 reachable (segmentation failed)"
# 2) Whether OT monitoring catches abnormal writes (owned capture) — no alarm signals the tap is not working
tshark -r ot_capture.pcap -Y 'modbus.func_code==6' -T fields -e ip.src 2>/dev/null | sort -u | head
```

> ICS architecture is *whether segmentation works* -- "the DMZ is designed" differs from "L3 cannot reach L1 directly and abnormal writes are caught by monitoring". Validate each control on owned OT labs directly ([[63_OT_ICS_Advanced]], [[37_ICS_SCADA]], [[39_Zero_Trust_Architecture]]).
