> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# Zero Trust 구현 전략

## 0. 초보자를 위한 개념 이해

### Zero Trust 구현 전략이란?

Zero Trust 구현은 하나의 제품을 설치하는 것이 아니라 보안 철학과 아키텍처의 전환이다. CISA(미국 사이버보안 인프라 보안국)는 5단계 성숙도 모델을 제시하며, 조직의 현재 상태를 평가하고 단계적으로 Zero Trust 원칙을 도입하도록 안내한다. 핵심은 신원, 기기, 네트워크, 애플리케이션, 데이터 5개 기둥(Pillar)에 각각 보안을 내재화하는 것이다.

**왜 배우는가:**
```
[Zero Trust 구현 없이 발생한 실제 사고]

  SolarWinds (2020):
    내부 네트워크 신뢰 → 공급망으로 진입 후
    18,000개 조직에서 수개월간 잠복

  Colonial Pipeline (2021):
    레거시 VPN 자격증명 탈취 →
    인증 한 번으로 OT 네트워크까지 접근

  [Zero Trust 도입 시 차단 가능했던 것]
  ✓ 자격증명 탈취되어도 MFA로 차단
  ✓ 내부 진입해도 마이크로세그멘테이션으로 이동 차단
  ✓ 이상 행동 탐지로 조기 발견
  ✓ 최소 권한으로 피해 범위 제한
```

### 핵심 개념 정리

```
[Zero Trust 5개 기둥(Pillar)]

1. 신원 (Identity)
   MFA 전면 도입
   Just-In-Time 권한 부여
   특권 계정 관리(PAM)

2. 기기 (Device)
   MDM 등록 의무화
   EDR 에이전트 필수
   기기 상태 지속 검증

3. 네트워크 (Network)
   VPN → ZTNA 전환
   마이크로세그멘테이션
   East-West 트래픽 암호화

4. 애플리케이션 (Application)
   API 게이트웨이 인증
   세션 단위 접근 결정
   애플리케이션 레벨 암호화

5. 데이터 (Data)
   데이터 분류 및 레이블링
   DLP(데이터 유출 방지)
   저장 데이터 암호화

[구현 우선순위]
  1단계: MFA + 특권 계정 관리
  2단계: 기기 신뢰 + 조건부 접근
  3단계: 마이크로세그멘테이션
  4단계: 앱/데이터 레이어 보안
  5단계: 자동화 + 지속적 검증
```

### 필요한 도구 및 환경
- **Azure AD Conditional Access / Okta**: 조건부 접근 정책
- **Microsoft Defender for Endpoint**: 기기 신뢰 검증
- **Cloudflare One / Zscaler ZPA**: ZTNA 구현
- **SIEM 도구**: Splunk, Microsoft Sentinel (행동 분석)

### 기초 실습 예제
```python
def zero_trust_maturity_assessment(org_config: dict) -> dict:
    """
    조직의 Zero Trust 성숙도를 평가하고 다음 단계를 제안한다.
    """
    score = 0
    max_score = 100
    findings = []
    recommendations = []

    # 1. 신원 보안 (30점)
    if org_config.get("mfa_enabled_all_users"):
        score += 15
        findings.append("[+15] 전 사용자 MFA 활성화")
    else:
        recommendations.append("우선순위 HIGH: 전 사용자 MFA 도입")

    if org_config.get("privileged_access_management"):
        score += 15
        findings.append("[+15] PAM 솔루션 도입")
    else:
        recommendations.append("우선순위 HIGH: PAM 도입 (CyberArk/Vault)")

    # 2. 기기 신뢰 (20점)
    if org_config.get("mdm_enrollment_required"):
        score += 10
        findings.append("[+10] MDM 기기 등록 의무화")
    else:
        recommendations.append("우선순위 MEDIUM: MDM 등록 정책 강제화")

    if org_config.get("edr_deployed"):
        score += 10
        findings.append("[+10] EDR 전체 배포")
    else:
        recommendations.append("우선순위 HIGH: EDR 배포 (Defender/CrowdStrike)")

    # 3. 네트워크 보안 (25점)
    if org_config.get("ztna_deployed"):
        score += 15
        findings.append("[+15] ZTNA 배포 (VPN 대체)")
    else:
        recommendations.append("우선순위 MEDIUM: ZTNA 전환 계획 수립")

    if org_config.get("microsegmentation"):
        score += 10
        findings.append("[+10] 마이크로세그멘테이션 구현")
    else:
        recommendations.append("우선순위 MEDIUM: 네트워크 세그멘테이션 강화")

    # 4. 데이터 보안 (25점)
    if org_config.get("data_classification"):
        score += 15
        findings.append("[+15] 데이터 분류 체계 운영")
    else:
        recommendations.append("우선순위 LOW: 데이터 분류·레이블링 도입")

    if org_config.get("dlp_enabled"):
        score += 10
        findings.append("[+10] DLP 활성화")
    else:
        recommendations.append("우선순위 LOW: DLP 솔루션 도입")

    # 성숙도 레벨 결정
    if score >= 80:
        level = "최적화 (Optimal)"
    elif score >= 60:
        level = "발전 (Advanced)"
    elif score >= 40:
        level = "초기 (Initial)"
    else:
        level = "전통적 (Traditional)"

    result = {
        "점수": f"{score}/{max_score}",
        "성숙도 레벨": level,
        "충족 항목": findings,
        "개선 권고사항": recommendations
    }

    print(f"\n[*] Zero Trust 성숙도 평가 결과")
    print(f"    점수: {score}/{max_score} ({level})")
    print(f"\n  충족 항목:")
    for f in findings:
        print(f"    {f}")
    print(f"\n  개선 권고사항:")
    for r in recommendations:
        print(f"    - {r}")

    return result

# 사용 예시
sample_org = {
    "mfa_enabled_all_users": True,
    "privileged_access_management": False,
    "mdm_enrollment_required": True,
    "edr_deployed": True,
    "ztna_deployed": False,
    "microsegmentation": False,
    "data_classification": False,
    "dlp_enabled": False,
}
zero_trust_maturity_assessment(sample_org)
```

---

## 1. Zero Trust 구현 로드맵

### 1.1 CISA 5단계 Zero Trust 성숙도 모델

미국 사이버보안 인프라 보안국(CISA)은 Zero Trust 성숙도를 5단계로 정의한다.

```
단계 0: 전통적 (Traditional)
  └── 경계 기반 보안, 내부 신뢰

단계 1: 초기 (Initial)
  └── 일부 Zero Trust 원칙 채택
  └── 특정 고위험 영역에 MFA 적용

단계 2: 발전 (Advanced)
  └── 대부분의 시스템에 Zero Trust 적용
  └── 자동화된 정책 집행 시작

단계 3: 최적 (Optimal)
  └── 완전한 Zero Trust 구현
  └── AI/ML 기반 위협 탐지
  └── 지속적 자동화 개선
```

### 1.2 단계별 구현 로드맵

#### Phase 1: 기반 구축 (0-6개월)

**핵심 목표:**
- 전체 자산 인벤토리 구축
- 강력한 신원 관리 기반 마련
- 가시성 확보

**실행 항목:**
```
신원 및 접근 관리:
├── IdP 통합 (Okta, Azure AD)
├── 전체 사용자 MFA 활성화
├── 서비스 계정 인벤토리 및 정리
└── 특권 계정 (PAM) 구축

기기 관리:
├── MDM 솔루션 도입 및 기기 등록
├── 기기 인벤토리 100% 달성
└── 기기 보안 기준선 정책 수립

가시성:
├── SIEM 구축 및 로그 통합
├── 네트워크 트래픽 가시성 확보
└── 자산 분류 (공개/내부/기밀)
```

#### Phase 2: 제어 강화 (6-12개월)

**핵심 목표:**
- 네트워크 세그멘테이션 구현
- 조건부 접근 정책 적용
- 데이터 분류 및 보호

**실행 항목:**
```
네트워크:
├── 마이크로세그멘테이션 시작 (고위험 영역 우선)
├── ZTNA 솔루션 도입 (VPN 대체 시작)
└── DNS 보안 강화

애플리케이션:
├── 조건부 접근 정책 구현
├── API 게이트웨이 배포
└── 앱별 접근 제어 정책

데이터:
├── DLP 솔루션 도입
├── 데이터 분류 레이블링
└── 암호화 정책 강화
```

#### Phase 3: 자동화 및 최적화 (12-24개월)

**핵심 목표:**
- 정책 자동화
- 지속적 검증
- Zero Trust 전체 적용

**실행 항목:**
```
자동화:
├── SOAR 연동으로 자동 대응
├── 정책 위반 자동 격리
└── IaC로 보안 정책 코드화

지속적 검증:
├── 행동 분석 (UEBA) 도입
├── AI 기반 이상 감지
└── 정기적 접근 인증 캠페인

고급 기능:
├── 완전한 East-West 트래픽 제어
├── 제로 트러스트 데이터 보호
└── 공급망 보안 확장
```

---

## 2. SASE (Secure Access Service Edge)

### 2.1 SASE 개념

SASE는 Gartner가 2019년 정의한 아키텍처로, 네트워크와 보안을 클라우드 서비스로 통합한다.

```
SASE = SD-WAN + 클라우드 보안 서비스

┌────────────────────────────────────────────────┐
│            SASE 클라우드 플랫폼                  │
│                                                │
│  네트워크 기능:          보안 기능:              │
│  ┌──────────────┐       ┌──────────────────┐  │
│  │   SD-WAN     │       │      ZTNA        │  │
│  │   WAN 최적화 │       │   SWG (웹 게이트) │  │
│  │   QoS        │       │   CASB           │  │
│  └──────────────┘       │   FWaaS          │  │
│                         │   UEBA/DLP       │  │
│                         └──────────────────┘  │
└────────────────────────────────────────────────┘
         │                          │
  [지사/원격사용자]            [본사/데이터센터]
```

### 2.2 SASE 구성 요소

**SD-WAN (Software-Defined WAN):**
- 다중 WAN 링크 자동 최적화
- 애플리케이션 인식 라우팅
- 중앙 집중 관리

**SWG (Secure Web Gateway):**
- URL 필터링
- 악성코드 탐지 (SSL 검사 포함)
- 데이터 유출 방지

**CASB (Cloud Access Security Broker):**
- SaaS 앱 가시성 및 제어
- 섀도 IT 탐지
- 클라우드 DLP

**FWaaS (Firewall as a Service):**
- 클라우드 기반 차세대 방화벽
- L7 정책
- 위협 인텔리전스 통합

**ZTNA:**
- 앱별 접근 제어
- 에이전트/에이전트리스 지원

---

## 3. 주요 ZTNA/SASE 솔루션 비교

### 3.1 Zscaler

**주요 제품:**
- **Zscaler Internet Access (ZIA)**: SWG, CASB, DLP
- **Zscaler Private Access (ZPA)**: ZTNA, 내부 앱 접근
- **Zscaler Digital Experience (ZDX)**: 사용자 경험 모니터링

**특징:**
```
장점:
├── 완전한 프록시 아키텍처 (인라인 검사)
├── 광범위한 글로벌 PoP (150개+ 데이터센터)
├── SSL/TLS 트래픽 완전 검사
├── Zero Trust Exchange 통합 플랫폼
└── 대기업 레퍼런스 다수

단점:
├── 높은 비용
├── 복잡한 설정
└── 에이전트 필수 (일부 시나리오)
```

**아키텍처:**
```
[사용자] → [Zscaler Client Connector (에이전트)]
               │
        [Zscaler 클라우드]
               │
        ┌──────┴──────┐
        │             │
    [인터넷 앱]  [내부 앱 (ZPA)]
```

### 3.2 Cloudflare One

**주요 제품:**
- **Cloudflare Access**: ZTNA
- **Cloudflare Gateway**: SWG, DNS 필터링
- **Magic WAN**: SD-WAN 대체
- **Cloudflare Tunnel**: 내부 앱 연결

**특징:**
```
장점:
├── 세계 최대 네트워크 활용 (330개+ 도시)
├── 상대적으로 저렴한 비용
├── 개발자 친화적 (API 우선)
├── Workers/Zero Trust 네이티브 통합
└── 무료 티어 제공 (소규모 조직)

단점:
├── 엔터프라이즈 기능 일부 제한
├── 레거시 앱 통합 복잡
└── 에이전트리스 세밀한 제어 제한
```

**Cloudflare Tunnel 동작:**
```
[내부 서버] → [cloudflared 데몬]
                    │ 아웃바운드 연결
              [Cloudflare 엣지]
                    │
              [사용자 접근]
              (포트 개방 불필요)
```

### 3.3 Palo Alto Networks Prisma Access

**주요 제품:**
- **Prisma Access**: SASE (SD-WAN + 보안)
- **Prisma Cloud**: 클라우드 네이티브 보안
- **GlobalProtect**: 원격 접근

**특징:**
```
장점:
├── 업계 최고 수준의 위협 방지 (WildFire)
├── 완전한 SASE 통합 플랫폼
├── ML 기반 차세대 방화벽
├── Cortex XDR 연동
└── Panorama 중앙 관리

단점:
├── 매우 높은 비용
├── 복잡한 설정 및 운영
└── 전문 인력 필요
```

### 3.4 솔루션 선택 가이드

| 요소 | Zscaler | Cloudflare One | Palo Alto Prisma |
|------|---------|----------------|-----------------|
| 비용 | 높음 | 중간 | 매우 높음 |
| 엔터프라이즈 기능 | 매우 높음 | 높음 | 매우 높음 |
| 위협 방지 | 높음 | 중간 | 매우 높음 |
| 설정 복잡도 | 높음 | 중간 | 매우 높음 |
| SMB 적합성 | 낮음 | 높음 | 낮음 |
| 글로벌 PoP | 많음 | 매우 많음 | 많음 |

---

## 4. 레거시 시스템 통합 전략

### 4.1 레거시 시스템의 Zero Trust 통합 과제

```
레거시 시스템 특성:
├── 현대 인증 미지원 (Kerberos, NTLM만 지원)
├── 암호화 미지원 (평문 통신)
├── API 없음 (RPC, SOAP 등 구식 프로토콜)
├── 변경 불가 (소스코드 없음, 지원 종료)
└── 하드코딩된 서비스 계정
```

### 4.2 통합 전략

#### 전략 1: 프록시/게이트웨이 배치

레거시 앱 앞에 Zero Trust 인식 프록시를 배치한다.

```
[사용자] → [ZTNA 게이트웨이] → [레거시 앱]
               │
        신원 + 기기 검증
        (레거시 앱 수정 없음)
```

**구현 예시 (Cloudflare Tunnel):**
```bash
# 레거시 앱 서버에 cloudflared 설치
cloudflared tunnel create legacy-app

# 설정 파일
ingress:
  - hostname: legacy-app.company.com
    service: http://localhost:8080
  - service: http_status:404

# 터널 실행
cloudflared tunnel run legacy-app
```

#### 전략 2: ID 브로커 (Identity Broker)

현대 IdP와 레거시 인증 시스템을 연결하는 브로커를 배치한다.

```
[SAML/OIDC] ←→ [ID 브로커] ←→ [LDAP/Kerberos]
(현대 IdP)                      (레거시 AD)
```

**도구:**
- **Shibboleth**: SAML 2.0 IdP, LDAP 연동
- **Keycloak**: 오픈소스 IdM, 다양한 프로토콜 지원
- **ADFS**: Active Directory Federation Services

#### 전략 3: PAM (Privileged Access Management)

레거시 시스템의 서비스 계정을 PAM으로 관리한다.

```
기존 방식: 하드코딩된 비밀번호
           [앱] → [레거시 DB] (비밀번호 코드에 하드코딩)

PAM 방식: 동적 크리덴셜
           [앱] → [PAM Vault] → 임시 크리덴셜 발급 → [레거시 DB]
```

#### 전략 4: 마이그레이션 (장기)

```
단기: 프록시로 제어
중기: API 레이어 추가 (Strangler Fig 패턴)
장기: 현대 아키텍처로 완전 교체
```

---

## 5. Zero Trust 성숙도 모델 평가

### 5.1 Forrester ZTX 7개 기둥

Forrester의 Zero Trust eXtended (ZTX) 프레임워크:

1. **Networks**: 세그멘테이션, 암호화
2. **Devices**: 기기 인벤토리, 신뢰 평가
3. **Identity**: 강력한 인증, 권한 관리
4. **Workloads**: 애플리케이션, 클라우드 보안
5. **Data**: 분류, 암호화, DLP
6. **Visibility & Analytics**: 가시성, SIEM, UEBA
7. **Automation & Orchestration**: 자동화, SOAR

### 5.2 성숙도 레벨 정의

각 기둥별 성숙도 레벨:

**레벨 1 - 전통적:**
- 경계 기반 방화벽
- 정적 사용자 이름/비밀번호
- 수동 프로세스

**레벨 2 - 발전:**
- 일부 MFA 적용
- 기본 세그멘테이션 (VLAN)
- 부분적 로그 수집

**레벨 3 - 성숙:**
- 전체 MFA 및 RBAC
- 마이크로세그멘테이션
- SIEM 통합 로그

**레벨 4 - 최적:**
- 적응형 인증
- 자동화된 정책 집행
- AI 기반 위협 탐지

---

## 6. 실전 Python 도구: Zero Trust 성숙도 자가 평가

```python
#!/usr/bin/env python3
"""
Zero Trust 성숙도 자가 평가 도구

CISA Zero Trust Maturity Model 및 Forrester ZTX 기반으로
조직의 Zero Trust 성숙도를 평가합니다.

사용법:
    python zt_maturity_assessment.py --interactive
    python zt_maturity_assessment.py --input answers.json --output report.json
    python zt_maturity_assessment.py --generate-questions
    python zt_maturity_assessment.py --compare baseline.json current.json
"""

import argparse
import json
import sys
import logging
from datetime import datetime, timezone
from typing import Any
from dataclasses import dataclass, field, asdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from enum import Enum


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)


class MaturityLevel(Enum):
    TRADITIONAL = 0
    INITIAL = 1
    ADVANCED = 2
    OPTIMAL = 3


MATURITY_LABELS = {
    MaturityLevel.TRADITIONAL: "전통적 (Traditional)",
    MaturityLevel.INITIAL: "초기 (Initial)",
    MaturityLevel.ADVANCED: "발전 (Advanced)",
    MaturityLevel.OPTIMAL: "최적 (Optimal)",
}


@dataclass
class Question:
    """평가 질문"""
    id: str
    pillar: str           # 평가 기둥
    text: str             # 질문 내용
    options: list[str]    # 선택지 (인덱스 = 레벨)
    weight: float = 1.0   # 가중치


@dataclass
class Answer:
    """질문 답변"""
    question_id: str
    selected_level: int   # 0-3
    notes: str = ""


@dataclass
class PillarScore:
    """기둥별 점수"""
    pillar: str
    score: float          # 0-100
    maturity_level: MaturityLevel
    answered_questions: int
    max_questions: int
    strengths: list[str] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)


@dataclass
class MaturityReport:
    """성숙도 평가 보고서"""
    organization: str = "평가 대상 조직"
    assessment_date: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    overall_score: float = 0.0
    overall_maturity: MaturityLevel = MaturityLevel.TRADITIONAL
    pillar_scores: list[PillarScore] = field(default_factory=list)
    top_priorities: list[str] = field(default_factory=list)
    quick_wins: list[str] = field(default_factory=list)
    long_term_goals: list[str] = field(default_factory=list)


# 평가 질문 정의
ASSESSMENT_QUESTIONS: list[dict[str, Any]] = [
    # ── 신원 (Identity) ──
    {
        "id": "IDN-001",
        "pillar": "신원 (Identity)",
        "text": "사용자 인증 방식은 무엇입니까?",
        "options": [
            "비밀번호만 사용",
            "일부 시스템에 MFA 적용",
            "모든 시스템에 MFA 필수, 리스크 기반 인증 일부 적용",
            "전체 FIDO2/패스키 + 적응형 인증, 비밀번호리스 진행 중",
        ],
        "weight": 1.5,
    },
    {
        "id": "IDN-002",
        "pillar": "신원 (Identity)",
        "text": "특권 계정(관리자, 서비스 계정) 관리 수준은?",
        "options": [
            "특권 계정 인벤토리 없음, 공유 계정 사용",
            "특권 계정 목록 있음, 기본 비밀번호 정책 적용",
            "PAM 솔루션 도입, JIT 접근 일부 적용",
            "완전한 PAM, JIT 특권 접근, 세션 녹화, 자동 비밀번호 로테이션",
        ],
        "weight": 1.2,
    },
    {
        "id": "IDN-003",
        "pillar": "신원 (Identity)",
        "text": "사용자 프로비저닝/디프로비저닝 프로세스는?",
        "options": [
            "수동 처리, 퇴직자 계정 정리 지연",
            "프로세스 있지만 수동, SLA 없음",
            "ITSM 연동 반자동화, 퇴직 후 24시간 내 비활성화",
            "IGA 플랫폼 완전 자동화, 실시간 디프로비저닝",
        ],
        "weight": 1.0,
    },
    # ── 기기 (Device) ──
    {
        "id": "DEV-001",
        "pillar": "기기 (Device)",
        "text": "기기 관리 및 인벤토리 수준은?",
        "options": [
            "기기 인벤토리 없음, BYOD 무제한",
            "기본 MDM 있지만 일부만 등록",
            "모든 기업 기기 MDM 등록, 기기 상태 모니터링",
            "MDM 100% + 기기 신뢰 점수 실시간 평가, 비준수 자동 격리",
        ],
        "weight": 1.2,
    },
    {
        "id": "DEV-002",
        "pillar": "기기 (Device)",
        "text": "엔드포인트 보안 수준은?",
        "options": [
            "기본 안티바이러스만",
            "EPP 솔루션 대부분 배포",
            "EDR 솔루션 전체 배포, 중앙 관리",
            "EDR + XDR 통합, AI 기반 행동 탐지, 자동 격리",
        ],
        "weight": 1.0,
    },
    {
        "id": "DEV-003",
        "pillar": "기기 (Device)",
        "text": "기기 보안 정책 준수 검증 방식은?",
        "options": [
            "정기 감사 없음",
            "연 1회 수동 감사",
            "자동화된 준수 모니터링, 비준수 알림",
            "실시간 준수 검증, 접근 결정에 기기 상태 자동 반영",
        ],
        "weight": 1.0,
    },
    # ── 네트워크 (Network) ──
    {
        "id": "NET-001",
        "pillar": "네트워크 (Network)",
        "text": "네트워크 세그멘테이션 수준은?",
        "options": [
            "단일 내부 네트워크, 세그멘테이션 없음",
            "기본 VLAN 세그멘테이션 (DMZ, 내부)",
            "3계층 이상 세그멘테이션, 핵심 자산 격리",
            "완전한 마이크로세그멘테이션, 기본 거부 정책",
        ],
        "weight": 1.3,
    },
    {
        "id": "NET-002",
        "pillar": "네트워크 (Network)",
        "text": "원격 접근 방식은?",
        "options": [
            "전통적 VPN (전체 네트워크 접근)",
            "VPN + 일부 MFA",
            "ZTNA 일부 도입 (VPN 병행)",
            "완전한 ZTNA, 앱별 세밀한 접근 제어",
        ],
        "weight": 1.2,
    },
    {
        "id": "NET-003",
        "pillar": "네트워크 (Network)",
        "text": "East-West 트래픽 제어 수준은?",
        "options": [
            "내부 트래픽 제어 없음",
            "일부 VLAN 간 ACL",
            "마이크로세그멘테이션 핵심 시스템 적용",
            "전체 East-West 제어, 서비스 메시 + mTLS",
        ],
        "weight": 1.1,
    },
    # ── 워크로드 (Workload) ──
    {
        "id": "WKL-001",
        "pillar": "워크로드 (Workload)",
        "text": "클라우드/컨테이너 보안 수준은?",
        "options": [
            "클라우드 기본 보안 설정만",
            "클라우드 보안 구성 검토 주기적 실시",
            "CSPM 도구로 자동 모니터링",
            "완전한 CNAPP, 개발부터 런타임까지 보안 통합",
        ],
        "weight": 1.0,
    },
    {
        "id": "WKL-002",
        "pillar": "워크로드 (Workload)",
        "text": "애플리케이션 간 접근 제어는?",
        "options": [
            "서비스 간 신뢰 없음 (모두 허용)",
            "IP 기반 기본 접근 제어",
            "API 키 또는 토큰 기반 서비스 인증",
            "서비스 메시 mTLS + 서비스 간 세밀한 권한 부여",
        ],
        "weight": 1.1,
    },
    # ── 데이터 (Data) ──
    {
        "id": "DAT-001",
        "pillar": "데이터 (Data)",
        "text": "데이터 분류 및 레이블링 수준은?",
        "options": [
            "데이터 분류 없음",
            "기본 분류 기준 있음 (수동 적용)",
            "자동화된 분류 도구 일부 적용",
            "완전 자동화 분류, 모든 데이터에 레이블 적용",
        ],
        "weight": 1.0,
    },
    {
        "id": "DAT-002",
        "pillar": "데이터 (Data)",
        "text": "데이터 암호화 수준은?",
        "options": [
            "암호화 최소 수준 (일부 저장 데이터만)",
            "저장 데이터 암호화 대부분, 전송 암호화 일부",
            "저장+전송 암호화 전체, 키 관리 체계 있음",
            "저장+전송+사용 중 암호화, HSM 기반 키 관리",
        ],
        "weight": 1.2,
    },
    {
        "id": "DAT-003",
        "pillar": "데이터 (Data)",
        "text": "DLP (데이터 유출 방지) 수준은?",
        "options": [
            "DLP 없음",
            "기본 이메일 DLP",
            "이메일+클라우드 DLP, 정책 수동 튜닝",
            "완전 통합 DLP (이메일, 클라우드, 엔드포인트), ML 기반",
        ],
        "weight": 1.0,
    },
    # ── 가시성 및 분석 (Visibility & Analytics) ──
    {
        "id": "VIS-001",
        "pillar": "가시성 및 분석 (Visibility)",
        "text": "로그 수집 및 분석 수준은?",
        "options": [
            "로그 수집 없거나 최소화",
            "주요 시스템 로그 수집, 수동 분석",
            "SIEM 구축, 기본 상관관계 분석",
            "완전한 SIEM, SOAR, UEBA 통합, AI 기반 이상 탐지",
        ],
        "weight": 1.2,
    },
    {
        "id": "VIS-002",
        "pillar": "가시성 및 분석 (Visibility)",
        "text": "위협 탐지 및 대응 수준은?",
        "options": [
            "사후 탐지 (침해 후 발견)",
            "기본 IDS/IPS",
            "SOC 운영, 24/7 모니터링",
            "MDR/XDR, SOAR 자동화, MTTR 1시간 이하",
        ],
        "weight": 1.3,
    },
    # ── 자동화 및 오케스트레이션 (Automation) ──
    {
        "id": "AUT-001",
        "pillar": "자동화 및 오케스트레이션 (Automation)",
        "text": "보안 정책 관리 자동화 수준은?",
        "options": [
            "완전 수동 정책 관리",
            "일부 스크립트로 자동화",
            "IaC 기반 정책 관리, CI/CD 통합",
            "완전 자동화, Policy-as-Code, GitOps 기반 변경 관리",
        ],
        "weight": 1.0,
    },
    {
        "id": "AUT-002",
        "pillar": "자동화 및 오케스트레이션 (Automation)",
        "text": "보안 사고 대응 자동화 수준은?",
        "options": [
            "수동 대응",
            "기본 플레이북 있음 (수동 실행)",
            "SOAR 기반 반자동 대응",
            "완전 자동화 대응, 사람 개입 최소화",
        ],
        "weight": 1.1,
    },
]


class MaturityAssessor:
    """Zero Trust 성숙도 평가기"""

    PILLAR_WEIGHTS: dict[str, float] = {
        "신원 (Identity)": 1.3,
        "기기 (Device)": 1.2,
        "네트워크 (Network)": 1.2,
        "워크로드 (Workload)": 1.0,
        "데이터 (Data)": 1.1,
        "가시성 및 분석 (Visibility)": 1.1,
        "자동화 및 오케스트레이션 (Automation)": 1.0,
    }

    def __init__(self, questions: list[dict[str, Any]]):
        self.questions: list[Question] = []
        for q in questions:
            self.questions.append(Question(
                id=q["id"],
                pillar=q["pillar"],
                text=q["text"],
                options=q["options"],
                weight=q.get("weight", 1.0),
            ))

        # 기둥별 질문 그룹화
        self.pillar_questions: dict[str, list[Question]] = {}
        for q in self.questions:
            if q.pillar not in self.pillar_questions:
                self.pillar_questions[q.pillar] = []
            self.pillar_questions[q.pillar].append(q)

    def calculate_pillar_score(
        self,
        pillar: str,
        answers: dict[str, Answer],
    ) -> PillarScore:
        """기둥별 점수 계산"""
        questions = self.pillar_questions.get(pillar, [])
        if not questions:
            return PillarScore(pillar=pillar, score=0, maturity_level=MaturityLevel.TRADITIONAL,
                               answered_questions=0, max_questions=0)

        total_weighted = 0.0
        max_weighted = 0.0
        answered = 0

        strengths: list[str] = []
        gaps: list[str] = []
        recommendations: list[str] = []

        for q in questions:
            ans = answers.get(q.id)
            if ans is None:
                continue

            answered += 1
            level = ans.selected_level
            max_level = len(q.options) - 1

            # 가중 점수 계산 (정규화)
            normalized = level / max_level if max_level > 0 else 0
            total_weighted += normalized * q.weight
            max_weighted += q.weight

            # 강점 및 격차 분류
            if level >= 2:
                strengths.append(f"[{q.id}] {q.text[:50]}... (레벨 {level})")
            elif level <= 1:
                gaps.append(f"[{q.id}] {q.text[:50]}... (현재 레벨 {level}, 목표 레벨 3)")
                recommendations.append(self._get_recommendation(q, level))

        score = (total_weighted / max_weighted * 100) if max_weighted > 0 else 0

        # 성숙도 레벨 결정
        if score >= 75:
            maturity = MaturityLevel.OPTIMAL
        elif score >= 50:
            maturity = MaturityLevel.ADVANCED
        elif score >= 25:
            maturity = MaturityLevel.INITIAL
        else:
            maturity = MaturityLevel.TRADITIONAL

        return PillarScore(
            pillar=pillar,
            score=round(score, 1),
            maturity_level=maturity,
            answered_questions=answered,
            max_questions=len(questions),
            strengths=strengths,
            gaps=gaps,
            recommendations=[r for r in recommendations if r],
        )

    def _get_recommendation(self, question: Question, current_level: int) -> str:
        """레벨에 따른 구체적 권고사항 생성"""
        next_level = min(current_level + 1, len(question.options) - 1)
        next_desc = question.options[next_level] if next_level < len(question.options) else ""

        if next_desc:
            return f"[{question.id}] 다음 단계: {next_desc}"
        return ""

    def calculate_overall_score(
        self,
        pillar_scores: list[PillarScore],
    ) -> tuple[float, MaturityLevel]:
        """전체 점수 및 성숙도 레벨 계산"""
        total_weighted = 0.0
        total_weight = 0.0

        for ps in pillar_scores:
            weight = self.PILLAR_WEIGHTS.get(ps.pillar, 1.0)
            total_weighted += ps.score * weight
            total_weight += weight

        overall = (total_weighted / total_weight) if total_weight > 0 else 0

        if overall >= 75:
            level = MaturityLevel.OPTIMAL
        elif overall >= 50:
            level = MaturityLevel.ADVANCED
        elif overall >= 25:
            level = MaturityLevel.INITIAL
        else:
            level = MaturityLevel.TRADITIONAL

        return round(overall, 1), level

    def generate_report(
        self,
        answers: dict[str, Answer],
        organization: str = "평가 대상 조직",
    ) -> MaturityReport:
        """성숙도 평가 보고서 생성"""
        report = MaturityReport(organization=organization)

        # 기둥별 점수 병렬 계산
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = {
                executor.submit(self.calculate_pillar_score, pillar, answers): pillar
                for pillar in self.pillar_questions
            }

            for future in as_completed(futures):
                ps = future.result()
                report.pillar_scores.append(ps)

        # 기둥 이름순 정렬
        report.pillar_scores.sort(key=lambda x: x.pillar)

        # 전체 점수
        report.overall_score, report.overall_maturity = self.calculate_overall_score(
            report.pillar_scores
        )

        # 우선순위 도출
        report.top_priorities = self._extract_priorities(report.pillar_scores)
        report.quick_wins = self._extract_quick_wins(answers)
        report.long_term_goals = self._extract_long_term_goals(report.pillar_scores)

        return report

    def _extract_priorities(self, pillar_scores: list[PillarScore]) -> list[str]:
        """최우선 개선 항목 추출 (점수 낮은 기둥 우선)"""
        sorted_pillars = sorted(pillar_scores, key=lambda x: x.score)
        priorities: list[str] = []

        for ps in sorted_pillars[:3]:
            if ps.gaps:
                priorities.append(f"{ps.pillar} (점수: {ps.score}) - {ps.gaps[0][:80]}")

        return priorities

    def _extract_quick_wins(self, answers: dict[str, Answer]) -> list[str]:
        """빠른 성과 항목 추출 (레벨 0-1인 것 중 달성 쉬운 것)"""
        quick_wins: list[str] = []

        priority_ids = ["IDN-001", "DEV-001", "NET-002", "VIS-001"]
        for qid in priority_ids:
            ans = answers.get(qid)
            q = next((q for q in self.questions if q.id == qid), None)
            if ans and q and ans.selected_level <= 1:
                quick_wins.append(
                    f"[{qid}] {q.text[:50]}... → "
                    f"목표: '{q.options[min(ans.selected_level + 1, 3)][:60]}'"
                )

        return quick_wins[:5]

    def _extract_long_term_goals(self, pillar_scores: list[PillarScore]) -> list[str]:
        """장기 목표 추출"""
        goals: list[str] = []

        for ps in pillar_scores:
            if ps.maturity_level == MaturityLevel.TRADITIONAL:
                goals.append(f"{ps.pillar}: 2년 내 '발전' 단계 달성 목표")
            elif ps.maturity_level == MaturityLevel.INITIAL:
                goals.append(f"{ps.pillar}: 1년 내 '발전' 단계 달성 목표")

        return goals[:5]


def run_interactive_assessment(assessor: MaturityAssessor, organization: str) -> MaturityReport:
    """대화형 자가 평가 실행"""
    print(f"\n=== Zero Trust 성숙도 자가 평가 ===")
    print(f"조직: {organization}")
    print(f"총 {len(assessor.questions)}개 질문\n")
    print("각 질문에 해당하는 번호를 입력하세요 (0-3)\n")

    answers: dict[str, Answer] = {}

    for idx, q in enumerate(assessor.questions, 1):
        print(f"[{idx}/{len(assessor.questions)}] [{q.pillar}]")
        print(f"  {q.text}")
        for opt_idx, opt in enumerate(q.options):
            print(f"    {opt_idx}: {opt}")

        while True:
            try:
                user_input = input(f"  선택 (0-{len(q.options)-1}): ").strip()
                level = int(user_input)
                if 0 <= level <= len(q.options) - 1:
                    answers[q.id] = Answer(question_id=q.id, selected_level=level)
                    break
                else:
                    print(f"  0에서 {len(q.options)-1} 사이의 숫자를 입력하세요.")
            except (ValueError, KeyboardInterrupt):
                print("\n평가를 중단합니다.")
                sys.exit(0)
        print()

    return assessor.generate_report(answers, organization)


def print_maturity_report(report: MaturityReport) -> None:
    """성숙도 보고서 출력"""
    print("\n" + "=" * 70)
    print("Zero Trust 성숙도 평가 보고서")
    print("=" * 70)
    print(f"조직     : {report.organization}")
    print(f"평가 일시: {report.assessment_date}")
    print(f"\n전체 성숙도 점수: {report.overall_score}/100")
    print(f"전체 성숙도 레벨: {MATURITY_LABELS[report.overall_maturity]}")

    # ASCII 진행 바
    bar_length = 40
    filled = int(report.overall_score / 100 * bar_length)
    bar = "█" * filled + "░" * (bar_length - filled)
    print(f"[{bar}] {report.overall_score:.1f}%")

    print("\n" + "-" * 70)
    print("기둥별 점수:")
    print("-" * 70)

    for ps in report.pillar_scores:
        level_label = MATURITY_LABELS[ps.maturity_level]
        answered_pct = (ps.answered_questions / ps.max_questions * 100) if ps.max_questions > 0 else 0
        print(f"\n{ps.pillar}")
        print(f"  점수: {ps.score}/100 | 레벨: {level_label}")
        print(f"  응답: {ps.answered_questions}/{ps.max_questions} ({answered_pct:.0f}%)")

        if ps.strengths:
            print(f"  강점:")
            for s in ps.strengths[:2]:
                print(f"    + {s[:75]}")

        if ps.gaps:
            print(f"  격차:")
            for g in ps.gaps[:2]:
                print(f"    - {g[:75]}")

    if report.top_priorities:
        print("\n" + "-" * 70)
        print("최우선 개선 항목:")
        for i, p in enumerate(report.top_priorities, 1):
            print(f"  {i}. {p[:80]}")

    if report.quick_wins:
        print("\n빠른 성과 (Quick Wins):")
        for i, w in enumerate(report.quick_wins, 1):
            print(f"  {i}. {w[:80]}")

    if report.long_term_goals:
        print("\n장기 목표:")
        for i, g in enumerate(report.long_term_goals, 1):
            print(f"  {i}. {g}")

    print("\n" + "=" * 70)


def compare_reports(baseline_path: str, current_path: str) -> None:
    """두 평가 보고서 비교"""
    with open(baseline_path, encoding="utf-8") as f:
        baseline_data = json.load(f)
    with open(current_path, encoding="utf-8") as f:
        current_data = json.load(f)

    b_score = baseline_data.get("overall_score", 0)
    c_score = current_data.get("overall_score", 0)
    delta = c_score - b_score

    print("\n=== Zero Trust 성숙도 비교 ===")
    print(f"기준 평가: {baseline_data.get('assessment_date', 'N/A')} - {b_score:.1f}/100")
    print(f"현재 평가: {current_data.get('assessment_date', 'N/A')} - {c_score:.1f}/100")
    print(f"변화량:    {'+'if delta >= 0 else ''}{delta:.1f}점\n")

    print("기둥별 변화:")
    b_pillars = {ps["pillar"]: ps["score"] for ps in baseline_data.get("pillar_scores", [])}
    c_pillars = {ps["pillar"]: ps["score"] for ps in current_data.get("pillar_scores", [])}

    for pillar in sorted(set(b_pillars) | set(c_pillars)):
        b = b_pillars.get(pillar, 0)
        c = c_pillars.get(pillar, 0)
        d = c - b
        trend = "▲" if d > 0 else "▼" if d < 0 else "─"
        print(f"  {trend} {pillar[:40]}: {b:.1f} → {c:.1f} ({'+' if d >= 0 else ''}{d:.1f})")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Zero Trust 성숙도 자가 평가 도구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
사용 예시:
  # 대화형 자가 평가
  python zt_maturity_assessment.py --interactive

  # JSON 답변 파일로 평가
  python zt_maturity_assessment.py --input answers.json --output report.json

  # 질문 목록 출력
  python zt_maturity_assessment.py --generate-questions

  # 두 보고서 비교
  python zt_maturity_assessment.py --compare baseline.json current.json

  # 조직명 지정
  python zt_maturity_assessment.py --interactive --org "ACME Corp"
        """
    )

    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--interactive", action="store_true", help="대화형 평가 실행")
    mode.add_argument("--input", metavar="FILE", help="JSON 답변 파일로 평가")
    mode.add_argument("--generate-questions", action="store_true", help="질문 목록 JSON 출력")
    mode.add_argument("--compare", nargs=2, metavar=("BASELINE", "CURRENT"), help="두 보고서 비교")

    parser.add_argument("--output", metavar="FILE", help="보고서 저장 파일")
    parser.add_argument("--org", default="평가 대상 조직", help="조직명")
    parser.add_argument("--verbose", action="store_true", help="상세 로그 출력")

    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.generate_questions:
        output = {
            "questions": ASSESSMENT_QUESTIONS,
            "instructions": "각 질문에 대해 selected_level (0-3)을 설정하세요.",
        }
        print(json.dumps(output, ensure_ascii=False, indent=2))
        return

    if args.compare:
        compare_reports(args.compare[0], args.compare[1])
        return

    assessor = MaturityAssessor(ASSESSMENT_QUESTIONS)

    if args.interactive:
        report = run_interactive_assessment(assessor, args.org)
    else:
        input_path = Path(args.input)
        if not input_path.exists():
            logger.error(f"파일 없음: {args.input}")
            sys.exit(1)

        with open(input_path, encoding="utf-8") as f:
            data = json.load(f)

        raw_answers = data.get("answers", data)
        answers: dict[str, Answer] = {}

        if isinstance(raw_answers, list):
            for item in raw_answers:
                qid = item["question_id"]
                answers[qid] = Answer(
                    question_id=qid,
                    selected_level=item["selected_level"],
                    notes=item.get("notes", ""),
                )
        elif isinstance(raw_answers, dict):
            for qid, level in raw_answers.items():
                answers[qid] = Answer(question_id=qid, selected_level=int(level))

        report = assessor.generate_report(answers, args.org)

    print_maturity_report(report)

    if args.output:
        output_data = asdict(report)
        # Enum을 문자열로 직렬화
        output_data["overall_maturity"] = report.overall_maturity.name
        for ps in output_data.get("pillar_scores", []):
            if isinstance(ps.get("maturity_level"), MaturityLevel):
                ps["maturity_level"] = ps["maturity_level"].name

        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(output_data, f, ensure_ascii=False, indent=2, default=str)
        logger.info(f"보고서 저장: {args.output}")


if __name__ == "__main__":
    main()
```

---

## 7. 구현 성공 지표 (KPI)

### 7.1 기술 지표

| 지표 | 초기 목표 | 성숙 목표 |
|------|----------|----------|
| MFA 적용률 | 80% | 100% |
| 기기 MDM 등록률 | 70% | 100% |
| 기기 규정 준수율 | 60% | 95% |
| 패치 완료율 (30일 내) | 70% | 99% |
| 레거시 VPN 사용 감소 | 30% 감소 | 100% ZTNA 전환 |
| East-West 마이크로세그멘테이션 범위 | 50% | 100% |

### 7.2 보안 지표

| 지표 | 목표 |
|------|------|
| MTTR (평균 탐지 대응 시간) | 4시간 이내 |
| 측면 이동 사고 | 90% 감소 |
| 권한 초과 계정 | 0 |
| 비인가 접근 시도 차단율 | 99.9% |

### 7.3 비즈니스 지표

| 지표 | 목표 |
|------|------|
| 보안 사고 비용 | 50% 감소 |
| 감사 준비 시간 | 70% 감소 |
| 신규 앱 보안 온보딩 시간 | 80% 단축 |
| 사용자 생산성 영향 | 최소화 (5% 미만) |

---

## 8. 일반적인 실수와 해결책

### 8.1 빅뱅 접근법

**문제:** 한번에 모든 것을 Zero Trust로 전환하려 시도

**해결책:**
- 고위험/고가치 자산부터 시작
- 파일럿 → 확장 방식으로 단계적 전개
- 각 단계에서 가치 증명 후 다음 단계 진행

### 8.2 사용자 경험 무시

**문제:** 과도한 보안 마찰로 사용자 불만 증가, 우회 시도

**해결책:**
- SSO로 로그인 횟수 최소화
- 적응형 MFA로 저위험 시 투명한 인증
- 사용자 교육 및 변화 관리

### 8.3 레거시 예외 누적

**문제:** 레거시 시스템을 위한 정책 예외가 쌓여 Zero Trust가 유명무실

**해결책:**
- 예외는 시간 제한(Time-bound) 적용
- 레거시 현대화 로드맵 수립
- 프록시로 임시 보호하면서 장기 교체 계획 실행

---

## 9. 참고 자료

- CISA: Zero Trust Maturity Model v2.0 (2023)
- Gartner: SASE Convergence Guide
- Forrester: Zero Trust eXtended (ZTX) Research
- NIST SP 800-207: Zero Trust Architecture
- Zscaler: Zero Trust Transformation Playbook
- Microsoft: Zero Trust Deployment Guide for Microsoft 365
- Cloud Security Alliance: Zero Trust Advancement Center
- IBM: Cost of a Data Breach Report 2023

---

*최종 업데이트: 2024년*

<!-- detect-validate-39 -->
## 구현 검증 — ZTNA가 VPN 암묵신뢰를 실제로 대체했는가

ZT 구현은 *솔루션을 샀는가*가 아니라 **모든 접근이 정책 게이트웨이를 강제로 경유하고 평면 VPN 폴백이 없는가**로 판정한다. 게이트웨이 우회 경로와 미보호 레거시를 직접 찾는다. 검증은 **소유 환경**에서만.

### 통제 → 실패 모드 → 검증 방법 → 양호 신호

| 통제 | 실패 모드 | 검증 방법 | 양호 신호 |
|---|---|---|---|
| ZTNA 적용 | VPN 폴백 잔존 | 폴백 경로 점검 | 평면 VPN 비활성 |
| 정책 게이트웨이 | 우회 경로 | 직접 접근 시도 | 게이트웨이 강제 |
| 레거시 통합 | 미보호 레거시 | 자산 인벤토리 | 레거시도 프록시 경유 |
| 성숙도 측정 | 자가평가 과대 | 증거 기반 평가 | 통제별 증거 존재 |

### 방어 검증 (직접 확인)

```bash
# 1) ZTNA 게이트웨이를 우회한 오리진 직접 접근이 가능한지(우회 시 ZT 무력화) — 소유 환경
curl -s -o /dev/null -w '%{http_code}\n' --resolve app.owned:443:ORIGIN_IP https://app.owned/   # 차단 기대
# 2) 평면 VPN 폴백(스플릿터널/전체허용)이 비활성인지 설정 확인
grep -riE 'split-tunnel|full-access|allow-all' vpn_config* 2>/dev/null | head
```

> 검증은 반드시 **소유 환경**에서만 한다. "ZTNA를 도입했다"와 "게이트웨이 우회 경로가 0이다"는 다르다 — 오리진 직접접근·VPN 폴백을 직접 점검한다([[14_Cloud_Security]], [[68_Purple_Team]]).

---

<a name="english"></a>

# Zero Trust Implementation Strategy

## 1. Zero Trust Implementation Roadmap

### 1.1 CISA 5-Stage Zero Trust Maturity Model

The U.S. Cybersecurity and Infrastructure Security Agency (CISA) defines Zero Trust maturity in 5 stages.

```
Stage 0: Traditional
  └── Perimeter-based security, internal trust

Stage 1: Initial
  └── Adopt some Zero Trust principles
  └── Apply MFA to certain high-risk areas

Stage 2: Advanced
  └── Apply Zero Trust to most systems
  └── Begin automated policy enforcement

Stage 3: Optimal
  └── Complete Zero Trust implementation
  └── AI/ML-based threat detection
  └── Continuous automated improvement
```

### 1.2 Phased Implementation Roadmap

#### Phase 1: Foundation Building (0-6 months)

**Core Goals:**
- Build complete asset inventory
- Establish strong identity management foundation
- Gain visibility

**Action Items:**
```
Identity and Access Management:
├── IdP integration (Okta, Azure AD)
├── Enable MFA for all users
├── Service account inventory and cleanup
└── Establish privileged account (PAM) management

Device Management:
├── Implement MDM solution and register devices
├── Achieve 100% device inventory
└── Establish device security baseline policy

Visibility:
├── Build SIEM and integrate logs
├── Gain network traffic visibility
└── Asset classification (public/internal/confidential)
```

#### Phase 2: Control Strengthening (6-12 months)

**Core Goals:**
- Implement network segmentation
- Apply conditional access policies
- Classify and protect data

#### Phase 3: Automation and Optimization (12-24 months)

**Core Goals:**
- Policy automation
- Continuous verification
- Full Zero Trust application

---

## 2. SASE (Secure Access Service Edge)

### 2.1 SASE Concept

SASE is an architecture defined by Gartner in 2019 that integrates networking and security as cloud services.

```
SASE = SD-WAN + Cloud Security Services

┌────────────────────────────────────────────────┐
│            SASE Cloud Platform                   │
│                                                │
│  Network Functions:        Security Functions:  │
│  ┌──────────────┐         ┌──────────────────┐  │
│  │   SD-WAN     │         │      ZTNA        │  │
│  │   WAN opt.   │         │   SWG (web gw.)  │  │
│  │   QoS        │         │   CASB           │  │
│  └──────────────┘         │   FWaaS          │  │
│                           │   UEBA/DLP       │  │
│                           └──────────────────┘  │
└────────────────────────────────────────────────┘
         │                          │
  [Branch/Remote users]      [HQ/Data center]
```

### 2.2 SASE Components

**SD-WAN (Software-Defined WAN):**
- Automatic optimization of multiple WAN links
- Application-aware routing
- Centralized management

**SWG (Secure Web Gateway):**
- URL filtering
- Malware detection (including SSL inspection)
- Data loss prevention

**CASB (Cloud Access Security Broker):**
- SaaS app visibility and control
- Shadow IT detection
- Cloud DLP

**FWaaS (Firewall as a Service):**
- Cloud-based next-generation firewall
- L7 policies
- Threat intelligence integration

---

## 3. Comparison of Major ZTNA/SASE Solutions

### 3.1 Zscaler

**Key Products:**
- **Zscaler Internet Access (ZIA)**: SWG, CASB, DLP
- **Zscaler Private Access (ZPA)**: ZTNA, internal app access
- **Zscaler Digital Experience (ZDX)**: User experience monitoring

### 3.2 Cloudflare One

**Key Products:**
- **Cloudflare Access**: ZTNA
- **Cloudflare Gateway**: SWG, DNS filtering
- **Magic WAN**: SD-WAN replacement
- **Cloudflare Tunnel**: Internal app connectivity

### 3.3 Palo Alto Networks Prisma Access

**Key Products:**
- **Prisma Access**: SASE (SD-WAN + security)
- **Prisma Cloud**: Cloud-native security
- **GlobalProtect**: Remote access

### 3.4 Solution Selection Guide

| Factor | Zscaler | Cloudflare One | Palo Alto Prisma |
|--------|---------|----------------|-----------------|
| Cost | High | Medium | Very high |
| Enterprise features | Very high | High | Very high |
| Threat prevention | High | Medium | Very high |
| Configuration complexity | High | Medium | Very high |
| SMB suitability | Low | High | Low |
| Global PoP | Many | Very many | Many |

---

## 4. Legacy System Integration Strategy

### 4.1 Challenges of Integrating Legacy Systems with Zero Trust

```
Legacy System Characteristics:
├── No modern authentication support (only Kerberos, NTLM)
├── No encryption support (plaintext communication)
├── No API (uses outdated protocols like RPC, SOAP)
├── Cannot be changed (no source code, end of support)
└── Hardcoded service accounts
```

### 4.2 Integration Strategies

#### Strategy 1: Proxy/Gateway Deployment

Deploy a Zero Trust-aware proxy in front of legacy apps.

```
[User] → [ZTNA Gateway] → [Legacy App]
               │
        Identity + device verification
        (No modification to legacy app)
```

#### Strategy 2: Identity Broker

Deploy a broker connecting modern IdP with legacy authentication systems.

```
[SAML/OIDC] ←→ [Identity Broker] ←→ [LDAP/Kerberos]
(Modern IdP)                        (Legacy AD)
```

**Tools:**
- **Shibboleth**: SAML 2.0 IdP, LDAP integration
- **Keycloak**: Open-source IdM, supports various protocols
- **ADFS**: Active Directory Federation Services

#### Strategy 3: PAM (Privileged Access Management)

Manage service accounts in legacy systems with PAM.

#### Strategy 4: Migration (Long-term)

```
Short-term: Control with proxy
Medium-term: Add API layer (Strangler Fig pattern)
Long-term: Complete replacement with modern architecture
```

---

## 5. Zero Trust Maturity Model Assessment

### 5.1 Forrester ZTX 7 Pillars

Forrester's Zero Trust eXtended (ZTX) framework:

1. **Networks**: Segmentation, encryption
2. **Devices**: Device inventory, trust assessment
3. **Identity**: Strong authentication, authorization management
4. **Workloads**: Application, cloud security
5. **Data**: Classification, encryption, DLP
6. **Visibility & Analytics**: Visibility, SIEM, UEBA
7. **Automation & Orchestration**: Automation, SOAR

### 5.2 Maturity Level Definitions

**Level 1 - Traditional:**
- Perimeter-based firewall
- Static username/password
- Manual processes

**Level 2 - Advancing:**
- Some MFA applied
- Basic segmentation (VLAN)
- Partial log collection

**Level 3 - Mature:**
- Full MFA and RBAC
- Microsegmentation
- SIEM integrated logs

**Level 4 - Optimal:**
- Adaptive authentication
- Automated policy enforcement
- AI-based threat detection

---

## 6. Implementation Success Metrics (KPIs)

### 6.1 Technical Metrics

| Metric | Initial Target | Mature Target |
|--------|---------------|---------------|
| MFA coverage | 80% | 100% |
| Device MDM enrollment | 70% | 100% |
| Device compliance rate | 60% | 95% |
| Patch completion rate (within 30 days) | 70% | 99% |
| Legacy VPN usage reduction | 30% reduction | 100% ZTNA transition |
| East-West microsegmentation coverage | 50% | 100% |

### 6.2 Security Metrics

| Metric | Target |
|--------|--------|
| MTTR (Mean Time to Detection and Response) | Within 4 hours |
| Lateral movement incidents | 90% reduction |
| Over-privileged accounts | 0 |
| Unauthorized access attempt blocking rate | 99.9% |

### 6.3 Business Metrics

| Metric | Target |
|--------|--------|
| Security incident cost | 50% reduction |
| Audit preparation time | 70% reduction |
| New app security onboarding time | 80% shorter |
| User productivity impact | Minimized (under 5%) |

---

## 7. Common Mistakes and Solutions

### 7.1 Big Bang Approach

**Problem:** Attempting to transition everything to Zero Trust at once

**Solution:**
- Start with high-risk/high-value assets
- Pilot → expand in phases
- Prove value at each stage before proceeding to the next

### 7.2 Ignoring User Experience

**Problem:** Excessive security friction increases user dissatisfaction and bypass attempts

**Solution:**
- Minimize login count with SSO
- Transparent authentication for low-risk with adaptive MFA
- User education and change management

### 7.3 Accumulation of Legacy Exceptions

**Problem:** Policy exceptions for legacy systems accumulate, making Zero Trust nominal

**Solution:**
- Apply time limits to exceptions
- Establish legacy modernization roadmap
- Execute long-term replacement plan while using proxy for temporary protection

---

## 8. References

- CISA: Zero Trust Maturity Model v2.0 (2023)
- Gartner: SASE Convergence Guide
- Forrester: Zero Trust eXtended (ZTX) Research
- NIST SP 800-207: Zero Trust Architecture
- Zscaler: Zero Trust Transformation Playbook
- Microsoft: Zero Trust Deployment Guide for Microsoft 365
- Cloud Security Alliance: Zero Trust Advancement Center
- IBM: Cost of a Data Breach Report 2023

---

*Last updated: 2024*

<!-- detect-validate-39 -->
## Implementation Validation — Did ZTNA Actually Replace VPN Implicit Trust?

ZT implementation is judged not by *whether a solution was bought* but by **whether every access is forced through the policy gateway with no flat-VPN fallback**. Hunt gateway-bypass paths and unprotected legacy directly. Validate only on **owned environments**.

### Control -> Failure mode -> Validation method -> Healthy signal

| Control | Failure mode | Validation method | Healthy signal |
|---|---|---|---|
| ZTNA applied | VPN fallback remains | Inspect fallback path | Flat VPN disabled |
| Policy gateway | Bypass path | Try direct access | Gateway enforced |
| Legacy integration | Unprotected legacy | Asset inventory | Legacy also via proxy |
| Maturity measurement | Inflated self-assessment | Evidence-based eval | Per-control evidence exists |

### Defense validation (verify directly)

```bash
# 1) Whether direct-to-origin access bypassing the ZTNA gateway works (bypass nullifies ZT) — owned env
curl -s -o /dev/null -w '%{http_code}\n' --resolve app.owned:443:ORIGIN_IP https://app.owned/   # expect blocked
# 2) Whether flat-VPN fallback (split-tunnel/allow-all) is disabled, via config
grep -riE 'split-tunnel|full-access|allow-all' vpn_config* 2>/dev/null | head
```

> Validate only on **owned environments**. "We deployed ZTNA" differs from "zero gateway-bypass paths remain" — check direct-to-origin and VPN fallback directly ([[14_Cloud_Security]], [[68_Purple_Team]]).
