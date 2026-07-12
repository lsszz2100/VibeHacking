> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# PASTA, DREAD, Attack Trees, Kill Chain

## 0. 초보자를 위한 개념 이해

### PASTA, DREAD, Attack Trees란?

이 세 가지는 보안 위협을 분석하고 우선순위를 결정하는 보완적인 방법론이다. PASTA는 비즈니스 영향을 중심으로 한 7단계 위협 분석 프로세스, DREAD는 위협의 심각도를 수치화하는 점수 체계, Attack Trees는 공격자 관점에서 목표 달성 경로를 트리 구조로 시각화하는 기법이다.

**왜 배우는가:**
```
위협 분석 도구 선택 가이드:

  PASTA (Process for Attack Simulation and Threat Analysis)
    언제: 비즈니스 위험 중심의 전사적 위협 모델링
    강점: 비즈니스 임팩트와 기술적 위협을 연결
    결과물: 리스크 기반 우선순위 완화 로드맵

  DREAD (점수화)
    언제: 여러 위협 중 어느 것을 먼저 해결할지 결정
    강점: 객관적 수치로 경영진에게 보고 용이
    결과물: 위협별 우선순위 점수 (0~10)

  Attack Trees (공격 트리)
    언제: 특정 공격 목표에 대한 모든 경로 파악
    강점: "공격자는 어떻게 이 목표에 도달하는가" 시각화
    결과물: 공격 경로 트리 다이어그램 + 각 노드 대응책

  Kill Chain (사이버 킬체인)
    언제: APT 공격의 단계별 방어 포인트 식별
    강점: 어느 단계에서 공격을 차단할지 결정
    결과물: 단계별 탐지·차단 전략
```

### 핵심 개념 정리

```
DREAD 점수 계산 (각 항목 0~10점):

  D - Damage Potential   손해 잠재성: 악용 시 피해 규모
  R - Reproducibility    재현 가능성: 공격 재현 얼마나 쉬운가
  E - Exploitability     악용 가능성: 공격 기술 수준 요구
  A - Affected Users     영향 사용자: 몇 명이 영향받는가
  D - Discoverability    발견 가능성: 취약점 발견 얼마나 쉬운가

  DREAD 점수 = (D+R+E+A+D) / 5
  0-3: 낮음, 4-6: 중간, 7-10: 높음

Attack Tree 구조:
  루트 노드 (공격 목표)
    ├── AND 노드: 모든 자식 조건 만족 필요
    │   ├── 조건 1
    │   └── 조건 2
    └── OR 노드: 하나라도 만족하면 성공
        ├── 경로 A (쉬움)
        └── 경로 B (어려움)
```

### 필요한 도구 및 환경
- **Excel/Notion**: DREAD 점수 계산 스프레드시트
- **draw.io**: Attack Tree 다이어그램 작성
- **AttackTree+** (상용): 전문 Attack Tree 분석 도구
- **MITRE ATT&CK**: Kill Chain 단계별 TTP 참조

### 기초 실습 예제
```python
#!/usr/bin/env python3
"""
DREAD 점수 자동 계산기 및 위협 우선순위 결정 도구
"""
import json
from dataclasses import dataclass


@dataclass
class DREADThreat:
    """DREAD 위협 평가 항목"""
    name: str
    description: str
    damage: int        # 손해 잠재성 (0-10)
    reproducibility: int  # 재현 가능성 (0-10)
    exploitability: int   # 악용 가능성 (0-10)
    affected_users: int   # 영향 사용자 (0-10)
    discoverability: int  # 발견 가능성 (0-10)

    def __post_init__(self) -> None:
        """점수 범위 검증"""
        for field_name in ["damage", "reproducibility", "exploitability",
                           "affected_users", "discoverability"]:
            value = getattr(self, field_name)
            if not 0 <= value <= 10:
                raise ValueError(f"{field_name} 점수는 0-10 범위여야 합니다: {value}")

    @property
    def score(self) -> float:
        """DREAD 종합 점수를 계산한다."""
        total = (self.damage + self.reproducibility + self.exploitability +
                 self.affected_users + self.discoverability)
        return round(total / 5, 1)

    @property
    def severity(self) -> str:
        """점수에 따른 위협 등급을 반환한다."""
        s = self.score
        if s >= 7:
            return "높음 (즉각 조치)"
        elif s >= 4:
            return "중간 (단기 계획)"
        else:
            return "낮음 (장기 계획)"


def analyze_threats(threats: list[DREADThreat]) -> dict:
    """여러 위협의 DREAD 점수를 계산하고 우선순위를 정렬한다."""
    results = []
    for threat in sorted(threats, key=lambda t: t.score, reverse=True):
        results.append({
            "위협명": threat.name,
            "설명": threat.description,
            "DREAD_점수": threat.score,
            "등급": threat.severity,
            "세부점수": {
                "손해잠재성(D)": threat.damage,
                "재현가능성(R)": threat.reproducibility,
                "악용가능성(E)": threat.exploitability,
                "영향사용자(A)": threat.affected_users,
                "발견가능성(D)": threat.discoverability,
            },
        })
    return {"위협_우선순위": results, "분석_위협수": len(threats)}


if __name__ == "__main__":
    # 웹 애플리케이션 위협 분석 예시
    threats = [
        DREADThreat(
            name="SQL Injection",
            description="로그인 폼을 통한 DB 전체 접근",
            damage=9, reproducibility=8, exploitability=7,
            affected_users=10, discoverability=8,
        ),
        DREADThreat(
            name="XSS (저장형)",
            description="댓글란을 통한 세션 쿠키 탈취",
            damage=7, reproducibility=7, exploitability=6,
            affected_users=8, discoverability=7,
        ),
        DREADThreat(
            name="정보 과다 노출",
            description="에러 페이지에 스택 트레이스 노출",
            damage=3, reproducibility=10, exploitability=9,
            affected_users=2, discoverability=10,
        ),
    ]

    result = analyze_threats(threats)
    print(json.dumps(result, ensure_ascii=False, indent=2))
```

---

## 목차
1. [PASTA 7단계 방법론](#pasta-7단계-방법론)
2. [DREAD 점수 계산](#dread-점수-계산)
3. [Attack Trees 작성법](#attack-trees-작성법)
4. [Lockheed Martin Cyber Kill Chain](#lockheed-martin-cyber-kill-chain)
5. [MITRE ATT&CK 프레임워크 연계](#mitre-attck-프레임워크-연계)
6. [DREAD 자동화 스크립트](#dread-자동화-스크립트)

---

## PASTA 7단계 방법론

PASTA(Process for Attack Simulation and Threat Analysis)는 비즈니스 목표와 기술적 요구사항을 연계한 위험 중심(Risk-centric) 위협 모델링 방법론이다. Tony UcedaVelez가 개발했으며 7단계 프로세스로 구성된다.

### 단계 1: 비즈니스 목표 정의 (Define Objectives)

비즈니스 관점에서 보안 요구사항을 정의한다.

```
질문 항목:
□ 이 시스템이 보호해야 할 핵심 비즈니스 자산은?
□ 규제 준수 요구사항은? (PCI-DSS, HIPAA, GDPR)
□ 가용성 요구사항 (SLA)은?
□ 보안 사고 발생 시 비즈니스 영향은?
□ 허용 가능한 위험 수준(Risk Appetite)은?

예시 (전자상거래):
비즈니스 목표:
- 결제 정보 보호 (PCI-DSS 준수)
- 99.9% 서비스 가용성 유지
- 고객 개인정보 보호 (GDPR)
- 사기 거래 최소화
```

### 단계 2: 기술 범위 정의 (Define Technical Scope)

분석 대상 시스템의 기술 스택과 범위를 문서화한다.

```
산출물:
- 기술 스택 인벤토리
  - 언어/프레임워크: Python 3.11, FastAPI, React
  - DB: PostgreSQL 15, Redis 7
  - 인프라: AWS EKS, RDS, ElastiCache
  - 네트워크: VPC, ALB, WAF

- 의존성 목록
  - 외부 API: Stripe 결제, SendGrid 메일
  - 오픈소스 라이브러리 목록

- 배포 아키텍처 다이어그램
  - 컨테이너 구성
  - 네트워크 토폴로지
  - 데이터 흐름
```

### 단계 3: 애플리케이션 분해 (Decompose Application)

시스템을 구성 요소로 분해하고 데이터 흐름을 식별한다.

```
DFD 작성:
[사용자] → [ALB] → [API Gateway] → [서비스 메시]
                                        ├── [인증 서비스] → [사용자 DB]
                                        ├── [주문 서비스] → [주문 DB]
                                        └── [결제 서비스] → [Stripe API]

진입점(Entry Points) 식별:
EP001: HTTPS /api/v1/* (공개 API)
EP002: HTTPS /admin/* (관리자 콘솔)
EP003: SSH 22 (배포 서버)
EP004: kubectl (K8s API 서버)
EP005: RDS 5432 (VPN 내부만)

자산(Assets) 식별:
A001: 결제 카드 정보 (Critical)
A002: 사용자 개인정보 (High)
A003: 세션 토큰 (High)
A004: 소스 코드 (Medium)
A005: 시스템 로그 (Medium)
```

### 단계 4: 위협 분석 (Threat Analysis)

위협 인텔리전스를 활용하여 관련 위협 행위자와 공격 패턴을 식별한다.

```
위협 행위자 프로파일링:
┌───────────────────┬──────────────┬──────────────────┬────────────────┐
│ 위협 행위자       │ 동기         │ 능력             │ 관련 위협      │
├───────────────────┼──────────────┼──────────────────┼────────────────┤
│ 사이버 범죄 조직  │ 금전적 이익  │ 높음             │ 결제 정보 탈취 │
│ 내부자            │ 불만/이익    │ 중간             │ 데이터 유출    │
│ 국가 지원 해커    │ 정보 수집    │ 매우 높음        │ APT 공격       │
│ 핵티비스트        │ 이념적 목적  │ 중간             │ DDoS, 변조     │
│ 스크립트 키디     │ 재미/명성    │ 낮음             │ 취약점 스캔    │
└───────────────────┴──────────────┴──────────────────┴────────────────┘

위협 인텔리전스 소스:
- CVE 데이터베이스
- MITRE ATT&CK
- OWASP Top 10
- 업계 ISAC (FS-ISAC, H-ISAC)
- 보안 뉴스 (Krebs on Security, DarkReading)
```

### 단계 5: 취약점 분석 (Vulnerability Analysis)

식별된 위협에 대한 시스템 취약점을 분석한다.

```
취약점 식별 방법:
1. 자동화 스캔
   - SAST: Bandit, Semgrep, SonarQube
   - DAST: OWASP ZAP, Burp Suite
   - SCA: Snyk, OWASP Dependency-Check
   - 인프라: Trivy, Checkov

2. 수동 코드 리뷰
   - 인증/인가 로직
   - 암호화 구현
   - 입력 검증

3. 구성 검토
   - 클라우드 보안 설정 (AWS Config)
   - K8s RBAC 설정
   - TLS 설정

취약점 매핑 예시:
위협 T001 (SQL Injection) → CVE 참조
→ 애플리케이션 코드: 취약한 쿼리 패턴 발견
→ CVSS 점수: 9.8 (Critical)
→ 영향받는 컴포넌트: 사용자 서비스, 주문 서비스
```

### 단계 6: 공격 모델링 (Attack Modeling)

공격 트리와 Attack Chains를 구성하여 실제 공격 경로를 시뮬레이션한다.

```
공격 시나리오 구성:
시나리오: 결제 정보 탈취

공격 체인:
1. 정찰: 공개 API 엔드포인트 스캔
2. 초기 접근: SQLI via 상품 검색 API
3. 권한 상승: DB 관리자 계정 탈취
4. 측면 이동: 내부 네트워크 피벗
5. 자산 탈취: 결제 정보 테이블 덤프

MITRE ATT&CK 매핑:
T1190 - Exploit Public-Facing Application
T1078 - Valid Accounts
T1021 - Remote Services
T1041 - Exfiltration Over C2 Channel
```

### 단계 7: 위험 및 영향 분석 (Risk and Impact Analysis)

비즈니스 영향을 정량화하고 위험을 우선순위화한다.

```
위험 계산:
위험 = 위협 가능성(Likelihood) × 비즈니스 영향(Business Impact)

비즈니스 영향 요소:
- 재무적 손실 (벌금, 소송, 수익 손실)
- 평판 손상
- 규제 위반
- 운영 중단

위험 매트릭스:
           │  낮음  │  중간  │  높음  │
───────────┼────────┼────────┼────────┤
높은 가능성 │  중간  │  높음  │ 긴급   │
중간 가능성 │  낮음  │  중간  │  높음  │
낮은 가능성 │  낮음  │  낮음  │  중간  │

우선순위 권고:
긴급: 즉시 해결 (24시간 내)
높음: 단기 해결 (1주일 내)
중간: 계획 해결 (1개월 내)
낮음: 백로그 관리
```

---

## DREAD 점수 계산

DREAD는 위협의 심각도를 5가지 기준으로 정량화하는 위험 평가 프레임워크다.

### DREAD 기준 상세

```
D - Damage (피해 규모)
  10: 전체 시스템 장악, 모든 데이터 탈취
  7-9: 민감 데이터 탈취, 권한 상승
  4-6: 제한적 데이터 노출, 부분 기능 중단
  1-3: 최소한의 피해, 공개 정보만 노출
  0: 피해 없음

R - Reproducibility (재현성)
  10: HTTP 요청 1개로 항상 성공
  7-9: 약간의 조건 필요, 쉽게 재현
  4-6: 여러 시도 필요, 일부 조건 의존
  1-3: 재현이 어렵고 조건이 복잡
  0: 재현 불가능

E - Exploitability (악용 용이성)
  10: 초보자도 도구 없이 가능
  7-9: 공개 익스플로잇 존재
  4-6: 중급 기술 필요
  1-3: 고급 기술 필요, 맞춤 익스플로잇
  0: 실질적 악용 불가능

A - Affected Users (영향받는 사용자)
  10: 전체 사용자
  7-9: 대부분 사용자 또는 기본값 사용자
  4-6: 일부 사용자
  1-3: 소수의 사용자
  0: 사용자 영향 없음

D - Discoverability (발견 용이성)
  10: 브라우저 주소창에서 쉽게 발견
  7-9: 공개 도구로 발견 가능
  4-6: 기술적 탐색 필요
  1-3: 소스코드 접근 또는 내부자 필요
  0: 발견 불가능 (이론적)
```

### DREAD 점수 해석

```
총점 = (D + R + E + A + D) / 5

임계값:
12-10: Critical - 즉시 패치 필요
9-7:   High - 빠른 대응 필요
6-4:   Medium - 계획된 수정
3-1:   Low - 장기 개선 계획

취약점 우선순위 예시:
┌─────────────────────┬────┬────┬────┬────┬────┬───────┬──────────┐
│ 취약점              │ D  │ R  │ E  │ A  │ D  │ 점수  │ 우선순위 │
├─────────────────────┼────┼────┼────┼────┼────┼───────┼──────────┤
│ SQL Injection       │ 9  │ 9  │ 8  │ 10 │ 8  │ 8.8   │ Critical │
│ XSS (Stored)        │ 7  │ 8  │ 7  │ 8  │ 7  │ 7.4   │ High     │
│ IDOR (주문 조회)    │ 6  │ 9  │ 9  │ 8  │ 8  │ 8.0   │ Critical │
│ JWT alg:none        │ 10 │ 10 │ 7  │ 10 │ 6  │ 8.6   │ Critical │
│ 취약한 비밀번호정책 │ 5  │ 5  │ 5  │ 7  │ 5  │ 5.4   │ Medium   │
│ 불필요한 HTTP 헤더  │ 2  │ 9  │ 9  │ 10 │ 9  │ 7.8   │ High     │
└─────────────────────┴────┴────┴────┴────┴────┴───────┴──────────┘
```

---

## Attack Trees 작성법

Attack Tree는 공격 목표를 루트 노드로, 가능한 공격 방법을 하위 노드로 구성하는 계층적 위협 모델이다.

### Attack Tree 구조

```
노드 유형:
OR 노드: 하위 조건 중 하나만 달성해도 상위 목표 달성
AND 노드: 모든 하위 조건을 달성해야 상위 목표 달성

표기법:
[목표] - 루트 또는 중간 노드
(OR)   - OR 게이트
(AND)  - AND 게이트
{조건} - 리프 노드 (실제 공격 행위)
```

### 예시: 관리자 계정 탈취

```
[관리자 계정 탈취]
        (OR)
        ├── [자격증명 탈취]
        │       (OR)
        │       ├── {피싱 공격}
        │       ├── {키로거 설치}
        │       ├── {DB 덤프 후 크래킹}
        │       └── [중간자 공격]
        │               (AND)
        │               ├── {네트워크 위치 확보}
        │               └── {TLS 다운그레이드}
        │
        ├── [인증 우회]
        │       (OR)
        │       ├── {SQL Injection on Login}
        │       ├── {세션 토큰 예측}
        │       └── {JWT 서명 알고리즘 혼동}
        │
        └── [권한 상승]
                (OR)
                ├── {IDOR를 통한 관리자 API 접근}
                ├── {역할 파라미터 변조}
                └── [OS 권한 상승]
                        (AND)
                        ├── {RCE 취약점 악용}
                        └── {SUID 바이너리 악용}
```

### 예시: 결제 정보 탈취

```
[결제 정보 탈취]
        (OR)
        ├── [전송 중 도청]
        │       (AND)
        │       ├── {MITM 위치 확보}
        │       └── {TLS 암호화 해제}
        │               (OR)
        │               ├── {인증서 위조}
        │               └── {BEAST/POODLE 공격}
        │
        ├── [저장된 데이터 탈취]
        │       (OR)
        │       ├── {DB 직접 접근}
        │       │       (OR)
        │       │       ├── {자격증명 탈취}
        │       │       └── {SQLi를 통한 DB 쿼리}
        │       └── {백업 파일 접근}
        │
        └── [애플리케이션 메모리 덤프]
                (AND)
                ├── {RCE 획득}
                └── {메모리 스캔}
```

### Attack Tree에 비용/확률 주석

```
각 리프 노드에 속성 부여:
{SQL Injection on Login}
  - 비용: $0 (공개 도구 사용)
  - 기술 수준: 낮음
  - 탐지 가능성: 높음
  - 성공 확률: 0.3 (WAF 있는 경우)

AND 노드 확률 = P(A) × P(B)
OR 노드 확률 = 1 - (1-P(A)) × (1-P(B))

예시:
[중간자 공격] (AND)
  P = P(네트워크 위치 확보) × P(TLS 다운그레이드)
  P = 0.1 × 0.05 = 0.005 (0.5%)

[자격증명 탈취] (OR: 피싱, 키로거, DB크래킹)
  P = 1 - (1-0.4) × (1-0.1) × (1-0.05)
  P ≈ 0.51 (51%)
```

---

## Lockheed Martin Cyber Kill Chain

Kill Chain은 사이버 공격의 7단계를 설명하는 모델로, 각 단계에서 공격을 탐지/차단할 수 있다.

### Kill Chain 7단계

```
1단계: 정찰 (Reconnaissance)
   공격자 행위:
   - 오픈소스 정보 수집 (OSINT)
   - 기술 스택 파악
   - 직원 SNS 프로파일링
   - 취약점 스캔 (Shodan, Censys)
   - 도메인/서브도메인 열거

   탐지/대응:
   - 웹 스캐너 트래픽 탐지
   - 비정상 DNS 조회 모니터링
   - 공개 정보 최소화

2단계: 무기화 (Weaponization)
   공격자 행위:
   - 익스플로잇 코드 개발
   - 악성 문서/링크 제작
   - RAT/백도어 패키징
   - C2 인프라 구축

   탐지/대응:
   - 위협 인텔리전스 구독
   - 악성 도구 시그니처 업데이트

3단계: 전달 (Delivery)
   공격자 행위:
   - 스피어 피싱 이메일 발송
   - 악성 웹사이트 운영 (Watering Hole)
   - USB 드롭 공격
   - 공급망 오염

   탐지/대응:
   - 이메일 필터링 (SPF, DKIM, DMARC)
   - 웹 프록시 필터링
   - 사용자 보안 인식 교육

4단계: 익스플로잇 (Exploitation)
   공격자 행위:
   - 취약점 악용
   - 코드 실행 유발
   - 브라우저/플러그인 취약점 활용

   탐지/대응:
   - EDR 솔루션
   - 취약점 패치 관리
   - 애플리케이션 화이트리스팅

5단계: 설치 (Installation)
   공격자 행위:
   - 백도어/RAT 설치
   - Rootkit 설치
   - 지속성(Persistence) 확보

   탐지/대응:
   - 파일 무결성 모니터링
   - 이상 프로세스 탐지
   - 레지스트리/시스템 모니터링

6단계: C2 통신 (Command & Control)
   공격자 행위:
   - C2 채널 수립
   - 비컨 통신 (Beacon)
   - DNS 터널링
   - HTTPS 기반 은닉 통신

   탐지/대응:
   - 비정상 아웃바운드 트래픽 탐지
   - DNS 이상 탐지
   - 네트워크 행동 분석 (NBA)

7단계: 목표 달성 (Actions on Objectives)
   공격자 행위:
   - 데이터 탈취 (Exfiltration)
   - 랜섬웨어 배포
   - 서비스 파괴
   - 측면 이동 (Lateral Movement)

   탐지/대응:
   - DLP 솔루션
   - 이상 데이터 전송 탐지
   - 네트워크 세그멘테이션
```

### Kill Chain 기반 위협 모델 매핑

```
공격 시나리오 → Kill Chain 매핑:

시나리오: 웹앱을 통한 내부망 침투

1. Reconnaissance
   → Shodan으로 443 포트 서비스 파악
   → whatweb으로 기술 스택 식별
   → gobuster로 디렉토리 열거

2. Weaponization
   → CVE-2024-XXXX PoC 코드 수집
   → Metasploit 모듈 커스터마이징

3. Delivery
   → 취약한 API 엔드포인트 직접 공격

4. Exploitation
   → SQL Injection → RCE
   → CVE 악용

5. Installation
   → 웹쉘 업로드 (/uploads/shell.php)
   → Cron 등록으로 지속성 확보

6. C2
   → DNS 터널링 (dnscat2)
   → HTTPS 역방향 쉘

7. Actions
   → 내부 DB 스캔
   → 결제 정보 추출
   → 데이터 압축 후 외부 전송
```

---

## MITRE ATT&CK 프레임워크 연계

### ATT&CK 매트릭스 구조

```
전술(Tactics) - 14개:
TA0001: Initial Access       (초기 접근)
TA0002: Execution            (실행)
TA0003: Persistence          (지속성)
TA0004: Privilege Escalation (권한 상승)
TA0005: Defense Evasion      (방어 회피)
TA0006: Credential Access    (자격증명 접근)
TA0007: Discovery            (탐색)
TA0008: Lateral Movement     (측면 이동)
TA0009: Collection           (수집)
TA0010: Exfiltration         (유출)
TA0011: Command and Control  (명령제어)
TA0040: Impact               (영향)
TA0042: Resource Development (리소스 개발)
TA0043: Reconnaissance       (정찰)

기법(Techniques) 예시:
T1190: Exploit Public-Facing Application
T1059: Command and Scripting Interpreter
T1078: Valid Accounts
T1110: Brute Force
T1055: Process Injection
```

### ATT&CK Navigator 활용

```bash
# ATT&CK Navigator 로컬 실행
git clone https://github.com/mitre-attack/attack-navigator
cd attack-navigator/nav-app
npm install
npm start
# http://localhost:4200 접속

# Python으로 ATT&CK 데이터 조회
pip3 install attackcti

python3 << 'EOF'
from attackcti import attack_client

client = attack_client()

# 웹 애플리케이션 관련 기법 조회
techniques = client.get_techniques_by_platform("Windows")
for t in techniques[:5]:
    print(f"{t['external_references'][0]['external_id']}: {t['name']}")
EOF
```

### 위협 모델과 ATT&CK 연계

```
STRIDE ↔ ATT&CK 매핑:

Spoofing (스푸핑):
  → T1078 Valid Accounts
  → T1134 Access Token Manipulation
  → T1539 Steal Web Session Cookie

Tampering (변조):
  → T1565 Data Manipulation
  → T1491 Defacement
  → T1059 Command and Scripting Interpreter

Repudiation (부인):
  → T1562 Impair Defenses
  → T1070 Indicator Removal

Information Disclosure (정보 노출):
  → T1552 Unsecured Credentials
  → T1530 Data from Cloud Storage
  → T1213 Data from Information Repositories

Denial of Service:
  → T1499 Endpoint Denial of Service
  → T1498 Network Denial of Service

Elevation of Privilege:
  → T1068 Exploitation for Privilege Escalation
  → T1548 Abuse Elevation Control Mechanism
  → T1055 Process Injection
```

---

## DREAD 자동화 스크립트

```python
#!/usr/bin/env python3
"""
DREAD 위험 점수 계산 및 우선순위 정렬 도구

사용법:
    python3 dread_calculator.py --input threats.json --output report.json
    python3 dread_calculator.py --interactive
    python3 dread_calculator.py --input threats.json --format html --output report.html
    python3 dread_calculator.py --demo
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, asdict, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional


class RiskLevel(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"

    @staticmethod
    def from_score(score: float) -> "RiskLevel":
        if score >= 8.0:
            return RiskLevel.CRITICAL
        elif score >= 6.0:
            return RiskLevel.HIGH
        elif score >= 3.0:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW

    @property
    def color(self) -> str:
        colors = {
            "Critical": "#dc3545",
            "High": "#fd7e14",
            "Medium": "#ffc107",
            "Low": "#28a745",
        }
        return colors[self.value]

    @property
    def priority_order(self) -> int:
        order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        return order[self.value]


@dataclass
class DREADScores:
    damage: int           # 0-10: 성공 시 피해 규모
    reproducibility: int  # 0-10: 공격 재현 용이성
    exploitability: int   # 0-10: 익스플로잇 난이도
    affected_users: int   # 0-10: 영향받는 사용자 수
    discoverability: int  # 0-10: 취약점 발견 용이성

    def __post_init__(self) -> None:
        for field_name in ["damage", "reproducibility", "exploitability",
                           "affected_users", "discoverability"]:
            val = getattr(self, field_name)
            if not 0 <= val <= 10:
                raise ValueError(
                    f"{field_name} 점수는 0-10 사이여야 합니다. 입력값: {val}"
                )

    @property
    def total(self) -> float:
        return (
            self.damage
            + self.reproducibility
            + self.exploitability
            + self.affected_users
            + self.discoverability
        ) / 5.0

    @property
    def risk_level(self) -> RiskLevel:
        return RiskLevel.from_score(self.total)

    def to_dict(self) -> dict:
        return {
            "damage": self.damage,
            "reproducibility": self.reproducibility,
            "exploitability": self.exploitability,
            "affected_users": self.affected_users,
            "discoverability": self.discoverability,
            "total": round(self.total, 1),
            "risk_level": self.risk_level.value,
        }


@dataclass
class AttackTreeNode:
    id: str
    name: str
    description: str
    node_type: str  # "OR", "AND", "LEAF"
    children: list["AttackTreeNode"] = field(default_factory=list)
    cost: Optional[str] = None
    probability: Optional[float] = None
    skill_level: Optional[str] = None

    def calculate_probability(self) -> float:
        """Attack Tree 확률 계산"""
        if self.node_type == "LEAF":
            return self.probability or 0.0

        child_probs = [c.calculate_probability() for c in self.children]

        if not child_probs:
            return 0.0

        if self.node_type == "OR":
            # OR: 1 - ∏(1 - P(i))
            result = 1.0
            for p in child_probs:
                result *= (1 - p)
            return 1 - result

        elif self.node_type == "AND":
            # AND: ∏P(i)
            result = 1.0
            for p in child_probs:
                result *= p
            return result

        return 0.0


@dataclass
class Threat:
    id: str
    name: str
    description: str
    affected_component: str
    attack_vector: str
    dread: DREADScores
    mitigations: list[str] = field(default_factory=list)
    cve_references: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    kill_chain_stage: Optional[str] = None
    status: str = "Open"
    attack_tree: Optional[AttackTreeNode] = None

    @property
    def priority_score(self) -> float:
        return self.dread.total

    def to_dict(self) -> dict:
        d = {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "affected_component": self.affected_component,
            "attack_vector": self.attack_vector,
            "dread": self.dread.to_dict(),
            "mitigations": self.mitigations,
            "cve_references": self.cve_references,
            "mitre_techniques": self.mitre_techniques,
            "kill_chain_stage": self.kill_chain_stage,
            "status": self.status,
        }
        if self.attack_tree:
            d["attack_tree_probability"] = round(
                self.attack_tree.calculate_probability(), 3
            )
        return d


class DREADAnalyzer:
    """DREAD 분석 엔진"""

    def __init__(self) -> None:
        self.threats: list[Threat] = []

    def add_threat(self, threat: Threat) -> None:
        self.threats.append(threat)

    def load_from_json(self, path: Path) -> None:
        """JSON 파일에서 위협 목록 로드"""
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            raise ValueError(f"JSON 파일 로드 실패: {e}") from e

        for item in data.get("threats", []):
            try:
                dread_data = item["dread"]
                dread = DREADScores(
                    damage=dread_data["damage"],
                    reproducibility=dread_data["reproducibility"],
                    exploitability=dread_data["exploitability"],
                    affected_users=dread_data["affected_users"],
                    discoverability=dread_data["discoverability"],
                )
                threat = Threat(
                    id=item["id"],
                    name=item["name"],
                    description=item.get("description", ""),
                    affected_component=item.get("affected_component", ""),
                    attack_vector=item.get("attack_vector", ""),
                    dread=dread,
                    mitigations=item.get("mitigations", []),
                    cve_references=item.get("cve_references", []),
                    mitre_techniques=item.get("mitre_techniques", []),
                    kill_chain_stage=item.get("kill_chain_stage"),
                    status=item.get("status", "Open"),
                )
                self.threats.append(threat)
            except (KeyError, ValueError) as e:
                print(f"경고: 위협 {item.get('id', '?')} 로드 실패 - {e}",
                      file=sys.stderr)

    def get_sorted_threats(self) -> list[Threat]:
        """DREAD 점수 내림차순 정렬"""
        return sorted(
            self.threats,
            key=lambda t: (-t.priority_score, t.dread.risk_level.priority_order),
        )

    def get_by_risk_level(self) -> dict[str, list[Threat]]:
        result: dict[str, list[Threat]] = {
            level.value: [] for level in RiskLevel
        }
        for threat in self.threats:
            result[threat.dread.risk_level.value].append(threat)
        return result

    def generate_summary(self) -> dict:
        by_level = self.get_by_risk_level()
        avg_score = (
            sum(t.priority_score for t in self.threats) / len(self.threats)
            if self.threats else 0
        )

        # Kill Chain 분포
        kill_chain_dist: dict[str, int] = {}
        for t in self.threats:
            if t.kill_chain_stage:
                kill_chain_dist[t.kill_chain_stage] = (
                    kill_chain_dist.get(t.kill_chain_stage, 0) + 1
                )

        return {
            "total_threats": len(self.threats),
            "by_risk_level": {k: len(v) for k, v in by_level.items()},
            "average_score": round(avg_score, 1),
            "open_threats": sum(1 for t in self.threats if t.status == "Open"),
            "kill_chain_distribution": kill_chain_dist,
        }

    def generate_json_report(self) -> str:
        sorted_threats = self.get_sorted_threats()
        return json.dumps({
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "tool": "DREAD Analyzer",
                "version": "1.0",
            },
            "summary": self.generate_summary(),
            "threats": [t.to_dict() for t in sorted_threats],
        }, ensure_ascii=False, indent=2)

    def generate_html_report(self) -> str:
        summary = self.generate_summary()
        sorted_threats = self.get_sorted_threats()

        rows = []
        for t in sorted_threats:
            color = t.dread.risk_level.color
            mitigations_html = "<br>".join(f"• {m}" for m in t.mitigations)
            mitre_html = ", ".join(t.mitre_techniques) or "-"
            rows.append(
                f"<tr>"
                f"<td><strong>{t.id}</strong></td>"
                f"<td>{t.name}</td>"
                f"<td>{t.affected_component}</td>"
                f"<td style='text-align:center'>{t.dread.damage}</td>"
                f"<td style='text-align:center'>{t.dread.reproducibility}</td>"
                f"<td style='text-align:center'>{t.dread.exploitability}</td>"
                f"<td style='text-align:center'>{t.dread.affected_users}</td>"
                f"<td style='text-align:center'>{t.dread.discoverability}</td>"
                f"<td style='text-align:center;font-weight:bold'>{t.dread.total:.1f}</td>"
                f"<td><span style='color:{color};font-weight:bold'>"
                f"{t.dread.risk_level.value}</span></td>"
                f"<td>{mitre_html}</td>"
                f"<td>{mitigations_html}</td>"
                f"<td>{t.status}</td>"
                f"</tr>"
            )

        summary_cards = []
        for level in RiskLevel:
            count = summary["by_risk_level"].get(level.value, 0)
            summary_cards.append(
                f"<div style='display:inline-block;margin:10px;padding:15px;"
                f"background:{level.color}22;border:2px solid {level.color};"
                f"border-radius:8px;text-align:center;min-width:100px'>"
                f"<div style='font-size:2em;font-weight:bold;color:{level.color}'>"
                f"{count}</div>"
                f"<div>{level.value}</div>"
                f"</div>"
            )

        return f"""<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<title>DREAD 위협 분석 보고서</title>
<style>
  body {{ font-family: 'Malgun Gothic', Arial, sans-serif; margin: 20px; background: #f8f9fa; }}
  h1, h2 {{ color: #333; }}
  .summary {{ background: white; padding: 20px; border-radius: 10px; margin-bottom: 20px;
              box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
  table {{ width: 100%; border-collapse: collapse; background: white;
           box-shadow: 0 2px 4px rgba(0,0,0,0.1); border-radius: 8px; }}
  th {{ background: #343a40; color: white; padding: 12px 8px; text-align: left; font-size: 0.9em; }}
  td {{ padding: 8px; border-bottom: 1px solid #dee2e6; font-size: 0.85em; vertical-align: top; }}
  tr:hover {{ background: #f5f5f5; }}
  .stat {{ color: #666; }}
</style>
</head>
<body>
<h1>DREAD 위협 분석 보고서</h1>
<p class="stat">생성 일시: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>

<div class="summary">
  <h2>요약</h2>
  {''.join(summary_cards)}
  <p>총 위협: <strong>{summary['total_threats']}</strong> |
     평균 DREAD 점수: <strong>{summary['average_score']}</strong> |
     미해결 위협: <strong>{summary['open_threats']}</strong></p>
</div>

<h2>위협 목록 (DREAD 점수 기준 정렬)</h2>
<table>
<tr>
  <th>ID</th><th>위협명</th><th>영향 컴포넌트</th>
  <th>D</th><th>R</th><th>E</th><th>A</th><th>D</th>
  <th>점수</th><th>위험도</th><th>ATT&CK</th><th>완화방안</th><th>상태</th>
</tr>
{''.join(rows)}
</table>

<p style="margin-top:30px;color:#999;font-size:0.8em">
DREAD: D=Damage, R=Reproducibility, E=Exploitability, A=Affected Users, D=Discoverability
</p>
</body>
</html>"""

    def interactive_input(self) -> None:
        """대화형 위협 입력"""
        print("\n=== DREAD 대화형 위협 입력 ===")
        print("점수 범위: 0(낮음) ~ 10(높음)\n")

        count = 0
        while True:
            count += 1
            print(f"\n--- 위협 {count} ---")
            name = input("위협 이름 (빈 줄로 종료): ").strip()
            if not name:
                break

            desc = input("설명: ").strip()
            component = input("영향받는 컴포넌트: ").strip()
            attack_vector = input("공격 벡터: ").strip()

            print("\nDREAD 점수 입력 (0-10):")
            scores = {}
            labels = {
                "damage": "D - 피해 규모",
                "reproducibility": "R - 재현 용이성",
                "exploitability": "E - 익스플로잇 난이도",
                "affected_users": "A - 영향받는 사용자",
                "discoverability": "D - 발견 용이성",
            }
            for key, label in labels.items():
                while True:
                    try:
                        val = int(input(f"  {label}: "))
                        if 0 <= val <= 10:
                            scores[key] = val
                            break
                        print("  0-10 사이 값을 입력하세요.")
                    except ValueError:
                        print("  숫자를 입력하세요.")

            dread = DREADScores(**scores)
            threat = Threat(
                id=f"T{count:03d}",
                name=name,
                description=desc,
                affected_component=component,
                attack_vector=attack_vector,
                dread=dread,
            )

            self.threats.append(threat)
            print(f"\n  → DREAD 점수: {dread.total:.1f} ({dread.risk_level.value})")


def create_demo_threats() -> list[Threat]:
    """데모용 위협 목록 생성"""
    demo_data = [
        {
            "id": "T001", "name": "로그인 SQL Injection",
            "description": "로그인 폼 username 파라미터에 SQL 인젝션",
            "affected_component": "인증 서비스", "attack_vector": "HTTP POST /api/login",
            "dread": DREADScores(9, 9, 8, 10, 8),
            "mitigations": ["파라미터화 쿼리 사용", "ORM 적용", "WAF 배포"],
            "mitre_techniques": ["T1190"],
            "kill_chain_stage": "Exploitation",
        },
        {
            "id": "T002", "name": "JWT 알고리즘 혼동",
            "description": "alg:none 또는 RS256→HS256 알고리즘 혼동 공격",
            "affected_component": "인증 미들웨어", "attack_vector": "HTTP 헤더 조작",
            "dread": DREADScores(10, 10, 7, 10, 6),
            "mitigations": ["알고리즘 명시적 검증", "최신 JWT 라이브러리 사용"],
            "mitre_techniques": ["T1078", "T1134"],
            "kill_chain_stage": "Exploitation",
        },
        {
            "id": "T003", "name": "IDOR 주문 데이터 접근",
            "description": "다른 사용자의 주문 조회/수정 가능",
            "affected_component": "주문 서비스", "attack_vector": "GET /api/orders/{id}",
            "dread": DREADScores(6, 9, 9, 8, 8),
            "mitigations": ["서버 측 소유권 검증", "UUID 사용"],
            "mitre_techniques": ["T1078"],
            "kill_chain_stage": "Actions on Objectives",
        },
        {
            "id": "T004", "name": "Stored XSS in 리뷰",
            "description": "상품 리뷰에 악성 스크립트 삽입",
            "affected_component": "상품 서비스", "attack_vector": "POST /api/reviews",
            "dread": DREADScores(7, 8, 7, 8, 7),
            "mitigations": ["출력 인코딩", "CSP 헤더", "DOMPurify 적용"],
            "mitre_techniques": ["T1059.007"],
            "kill_chain_stage": "Delivery",
        },
        {
            "id": "T005", "name": "결제 금액 파라미터 변조",
            "description": "결제 요청 시 금액 파라미터 클라이언트 측 변조",
            "affected_component": "결제 서비스", "attack_vector": "POST /api/payment",
            "dread": DREADScores(9, 9, 9, 10, 7),
            "mitigations": ["서버 측 금액 재계산", "서명된 결제 요청"],
            "mitre_techniques": ["T1565"],
            "kill_chain_stage": "Actions on Objectives",
        },
        {
            "id": "T006", "name": "API Rate Limit 미적용",
            "description": "로그인 API에 브루트포스 가능",
            "affected_component": "API Gateway", "attack_vector": "HTTP POST /api/login",
            "dread": DREADScores(7, 10, 10, 9, 9),
            "mitigations": ["Rate Limiting (5req/min)", "계정 잠금", "CAPTCHA"],
            "mitre_techniques": ["T1110"],
            "kill_chain_stage": "Reconnaissance",
        },
        {
            "id": "T007", "name": "환경변수 민감정보 노출",
            "description": "/api/debug 엔드포인트에서 환경변수 노출",
            "affected_component": "웹 서버", "attack_vector": "GET /api/debug",
            "dread": DREADScores(8, 10, 10, 10, 9),
            "mitigations": ["디버그 엔드포인트 비활성화", "민감 환경변수 Secret Manager 이전"],
            "mitre_techniques": ["T1552"],
            "kill_chain_stage": "Reconnaissance",
        },
    ]

    threats = []
    for d in demo_data:
        threat = Threat(
            id=d["id"],
            name=d["name"],
            description=d["description"],
            affected_component=d["affected_component"],
            attack_vector=d["attack_vector"],
            dread=d["dread"],
            mitigations=d["mitigations"],
            mitre_techniques=d["mitre_techniques"],
            kill_chain_stage=d["kill_chain_stage"],
        )
        threats.append(threat)

    return threats


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="DREAD 위험 점수 계산 및 우선순위 정렬 도구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
예시:
  %(prog)s --demo --format html --output demo_report.html
  %(prog)s --input threats.json --output sorted_report.json
  %(prog)s --interactive --format html --output my_threats.html
        """,
    )

    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument("--input", type=Path, help="위협 목록 JSON 파일")
    input_group.add_argument("--interactive", action="store_true", help="대화형 입력")
    input_group.add_argument("--demo", action="store_true", help="데모 위협 목록 사용")

    parser.add_argument(
        "--format", choices=["json", "html"], default="json",
        help="출력 형식",
    )
    parser.add_argument(
        "--output", type=Path, default=Path("dread_report.json"),
        help="출력 파일 경로",
    )
    parser.add_argument(
        "--top", type=int, default=0,
        help="상위 N개 위협만 출력 (0=전체)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    analyzer = DREADAnalyzer()

    try:
        if args.demo:
            for threat in create_demo_threats():
                analyzer.add_threat(threat)
            print(f"데모 위협 {len(analyzer.threats)}개 로드됨")

        elif args.interactive:
            analyzer.interactive_input()
            if not analyzer.threats:
                print("입력된 위협이 없습니다.", file=sys.stderr)
                return 1

        elif args.input:
            analyzer.load_from_json(args.input)
            print(f"{len(analyzer.threats)}개 위협 로드됨")

    except ValueError as e:
        print(f"오류: {e}", file=sys.stderr)
        return 1

    # 요약 출력
    summary = analyzer.generate_summary()
    print(f"\n=== DREAD 분석 결과 ===")
    print(f"총 위협: {summary['total_threats']}")
    print(f"평균 DREAD 점수: {summary['average_score']}")
    for level in RiskLevel:
        count = summary["by_risk_level"].get(level.value, 0)
        if count > 0:
            print(f"  {level.value}: {count}건")

    # 상위 위협 출력
    sorted_threats = analyzer.get_sorted_threats()
    if args.top > 0:
        sorted_threats = sorted_threats[:args.top]
        analyzer.threats = sorted_threats

    print(f"\n상위 위협 Top {min(5, len(sorted_threats))}:")
    for i, t in enumerate(sorted_threats[:5], 1):
        print(f"  {i}. [{t.dread.risk_level.value}] {t.name} (DREAD: {t.dread.total:.1f})")

    # 보고서 생성
    try:
        if args.format == "json":
            report = analyzer.generate_json_report()
        else:
            report = analyzer.generate_html_report()

        args.output.write_text(report, encoding="utf-8")
        print(f"\n보고서 저장: {args.output}")
    except OSError as e:
        print(f"저장 실패: {e}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
```

### 실행 예시

```bash
# 데모 데이터로 HTML 보고서 생성
python3 dread_calculator.py --demo --format html --output demo.html

# 상위 5개 위협 JSON 보고서
python3 dread_calculator.py --demo --top 5 --output top5.json

# 기존 위협 JSON 파일 분석
python3 dread_calculator.py --input threats.json --format html --output report.html

# 대화형 입력
python3 dread_calculator.py --interactive --format html --output my_report.html
```

### 입력 JSON 형식

```json
{
  "threats": [
    {
      "id": "T001",
      "name": "SQL Injection",
      "description": "로그인 폼 SQL 인젝션",
      "affected_component": "인증 서비스",
      "attack_vector": "POST /api/login",
      "dread": {
        "damage": 9,
        "reproducibility": 9,
        "exploitability": 8,
        "affected_users": 10,
        "discoverability": 8
      },
      "mitigations": ["파라미터화 쿼리", "WAF"],
      "mitre_techniques": ["T1190"],
      "kill_chain_stage": "Exploitation",
      "status": "Open"
    }
  ]
}
```

---

## 참고 자료

- [PASTA Threat Modeling](https://www.wiley.com/en-us/Risk+Centric+Threat+Modeling-p-9780470500965)
- [DREAD Risk Rating Model](https://en.wikipedia.org/wiki/DREAD_%28risk_assessment_model%29)
- [Attack Trees (Bruce Schneier)](https://www.schneier.com/academic/archives/1999/12/attack_trees.html)
- [Lockheed Martin Cyber Kill Chain](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)

---

<!-- detect-validate-48 -->
## 위험 평가·공격 트리 검증 (점수화됨 ≠ 검증됨)

PASTA·DREAD·공격 트리·킬체인은 *위협을 점수화하고 공격 경로를 구조화*한다. "위험 점수를 매겼다"는 평가와 "그 경로가 실제로 도달·악용 가능한가"는 다르다 — 고위험 경로를 소유 환경에서 검증한다.

### 검증 항목 → 확인 질문 → 측정 신호 → 함정

| 검증 항목 | 확인 질문 | 측정 신호 | 함정 |
|---|---|---|---|
| 경로 도달성 | 리프→루트 가능? | PoC로 경로 재현 | 이론적 트리 |
| 위험 점수 근거 | 데이터 기반? | 실측 악용성 반영 | 주관적 DREAD |
| 통제 차단점 | 경로 끊기나? | 통제 후 경로 불가 | 통제 미검증 |
| 우선순위 | 실제 위험순? | 검증된 경로 우선 | 점수만 신뢰 |

### 평가 검증 (직접 확인)

```bash
# 1) 공격 트리의 고위험 리프가 실제 도달 가능한지(소유 환경) — PoC 재현으로 이론↔실제 구분
jq -r '.attack_tree.leaves[] | select(.risk=="high") | .path' attack_tree.json 2>/dev/null | head
# 2) 통제 적용 후 경로 차단 검증 — 차단점 통제가 실제 경로를 끊으면 위험 하락 신호
grep -rIiE 'rate.?limit|mfa|allowlist|waf' controls/ 2>/dev/null | head
```

> 위험 평가는 *경로가 도달·차단되는가*다 — "DREAD 점수가 높다"와 "그 경로가 PoC로 도달되고 통제 적용 시 끊긴다"는 다르다. 고위험 경로를 소유 환경에서 직접 검증한다([[68_Purple_Team]], [[30_Vulnerability_Research]], [[17_Red_Team_Operations]]).

**최신 기법·통제 (2025–2026):**
- 리스크중심(PASTA)·공격트리로 우선순위화 — 검증: 우선순위가 실제 익스플로잇 가능성과 일치하는가([[30_Vulnerability_Research]])
- 정량 리스크 — 데이터로 뒷받침되는지 확인

---

<a name="english"></a>

# PASTA, DREAD, Attack Trees, Kill Chain

## Table of Contents
1. [PASTA 7-Step Methodology](#pasta-7-step-methodology)
2. [DREAD Score Calculation](#dread-score-calculation)
3. [Writing Attack Trees](#writing-attack-trees)
4. [Lockheed Martin Cyber Kill Chain](#lockheed-martin-cyber-kill-chain-en)
5. [MITRE ATT&CK Framework Integration](#mitre-attck-framework-integration)
6. [DREAD Automation Script](#dread-automation-script)

---

## PASTA 7-Step Methodology

PASTA (Process for Attack Simulation and Threat Analysis) is a risk-centric threat modeling methodology that aligns business objectives with technical requirements. Developed by Tony UcedaVelez, it consists of a 7-stage process.

### Stage 1: Define Objectives

Define security requirements from a business perspective.

```
Questions:
□ What are the core business assets this system must protect?
□ What are the regulatory compliance requirements? (PCI-DSS, HIPAA, GDPR)
□ What are the availability requirements (SLA)?
□ What is the business impact of a security incident?
□ What is the acceptable risk level (Risk Appetite)?

Example (e-commerce):
Business objectives:
- Protect payment information (PCI-DSS compliance)
- Maintain 99.9% service availability
- Protect customer personal data (GDPR)
- Minimize fraudulent transactions
```

### Stage 2: Define Technical Scope

Document the technology stack and scope of the systems being analyzed.

```
Deliverables:
- Technology stack inventory
  - Languages/Frameworks: Python 3.11, FastAPI, React
  - DB: PostgreSQL 15, Redis 7
  - Infrastructure: AWS EKS, RDS, ElastiCache
  - Network: VPC, ALB, WAF

- Dependency list
  - External APIs: Stripe payments, SendGrid email
  - Open-source library list

- Deployment architecture diagram
  - Container configuration
  - Network topology
  - Data flows
```

### Stage 3: Decompose Application

Decompose the system into components and identify data flows.

```
DFD construction:
[User] → [ALB] → [API Gateway] → [Service Mesh]
                                    ├── [Auth Service] → [User DB]
                                    ├── [Order Service] → [Order DB]
                                    └── [Payment Service] → [Stripe API]

Entry Points identification:
EP001: HTTPS /api/v1/* (public API)
EP002: HTTPS /admin/* (admin console)
EP003: SSH 22 (deployment server)
EP004: kubectl (K8s API server)
EP005: RDS 5432 (internal VPN only)

Asset identification:
A001: Payment card information (Critical)
A002: User personal data (High)
A003: Session tokens (High)
A004: Source code (Medium)
A005: System logs (Medium)
```

### Stage 4: Threat Analysis

Use threat intelligence to identify relevant threat actors and attack patterns.

```
Threat actor profiling:
┌───────────────────┬──────────────┬──────────────────┬────────────────┐
│ Threat Actor      │ Motivation   │ Capability       │ Related Threat │
├───────────────────┼──────────────┼──────────────────┼────────────────┤
│ Cybercrime org    │ Financial    │ High             │ Payment theft  │
│ Insider           │ Grudge/Gain  │ Medium           │ Data exfil     │
│ Nation-state      │ Intelligence │ Very High        │ APT attacks    │
│ Hacktivist        │ Ideological  │ Medium           │ DDoS, defacing │
│ Script kiddie     │ Fun/Fame     │ Low              │ Vuln scanning  │
└───────────────────┴──────────────┴──────────────────┴────────────────┘

Threat intelligence sources:
- CVE database
- MITRE ATT&CK
- OWASP Top 10
- Industry ISACs (FS-ISAC, H-ISAC)
- Security news (Krebs on Security, DarkReading)
```

### Stage 5: Vulnerability Analysis

Analyze system vulnerabilities against identified threats.

```
Vulnerability identification methods:
1. Automated scanning
   - SAST: Bandit, Semgrep, SonarQube
   - DAST: OWASP ZAP, Burp Suite
   - SCA: Snyk, OWASP Dependency-Check
   - Infrastructure: Trivy, Checkov

2. Manual code review
   - Authentication/authorization logic
   - Cryptography implementation
   - Input validation

3. Configuration review
   - Cloud security settings (AWS Config)
   - K8s RBAC settings
   - TLS settings

Vulnerability mapping example:
Threat T001 (SQL Injection) → CVE reference
→ Application code: vulnerable query pattern found
→ CVSS score: 9.8 (Critical)
→ Affected components: user service, order service
```

### Stage 6: Attack Modeling

Construct attack trees and attack chains to simulate actual attack paths.

```
Attack scenario construction:
Scenario: Payment information theft

Attack chain:
1. Reconnaissance: scan public API endpoints
2. Initial access: SQLi via product search API
3. Privilege escalation: capture DB admin credentials
4. Lateral movement: pivot to internal network
5. Asset exfiltration: dump payment information table

MITRE ATT&CK mapping:
T1190 - Exploit Public-Facing Application
T1078 - Valid Accounts
T1021 - Remote Services
T1041 - Exfiltration Over C2 Channel
```

### Stage 7: Risk and Impact Analysis

Quantify business impact and prioritize risks.

```
Risk calculation:
Risk = Threat Likelihood × Business Impact

Business impact factors:
- Financial loss (fines, litigation, revenue loss)
- Reputational damage
- Regulatory violations
- Operational disruption

Risk matrix:
             │  Low   │ Medium │  High  │
─────────────┼────────┼────────┼────────┤
High likelihood│ Medium │  High  │Urgent  │
Med likelihood │  Low   │ Medium │  High  │
Low likelihood │  Low   │  Low   │ Medium │

Priority recommendations:
Urgent: Resolve immediately (within 24 hours)
High: Resolve short-term (within 1 week)
Medium: Planned resolution (within 1 month)
Low: Backlog management
```

---

## DREAD Score Calculation

DREAD is a risk assessment framework that quantifies the severity of threats across 5 criteria.

### DREAD Criteria Details

```
D - Damage (damage potential)
  10: Full system compromise, all data exfiltrated
  7-9: Sensitive data theft, privilege escalation
  4-6: Limited data exposure, partial service disruption
  1-3: Minimal damage, only public information exposed
  0: No damage

R - Reproducibility
  10: Always succeeds with a single HTTP request
  7-9: Minor conditions needed, easily reproducible
  4-6: Multiple attempts needed, some condition dependency
  1-3: Difficult to reproduce, complex conditions
  0: Not reproducible

E - Exploitability
  10: Even a beginner can do it without tools
  7-9: Public exploit exists
  4-6: Intermediate skills required
  1-3: Advanced skills required, custom exploit needed
  0: Practically not exploitable

A - Affected Users
  10: All users
  7-9: Most users or users with default settings
  4-6: Some users
  1-3: A small number of users
  0: No user impact

D - Discoverability
  10: Easily found in browser address bar
  7-9: Discoverable with public tools
  4-6: Technical exploration required
  1-3: Source code access or insider required
  0: Cannot be discovered (theoretical)
```

### DREAD Score Interpretation

```
Total = (D + R + E + A + D) / 5

Thresholds:
10-12: Critical - Immediate patch required
7-9:   High - Rapid response required
4-6:   Medium - Planned fix
1-3:   Low - Long-term improvement plan

Vulnerability prioritization example:
┌─────────────────────┬────┬────┬────┬────┬────┬───────┬──────────┐
│ Vulnerability       │ D  │ R  │ E  │ A  │ D  │ Score │ Priority │
├─────────────────────┼────┼────┼────┼────┼────┼───────┼──────────┤
│ SQL Injection       │ 9  │ 9  │ 8  │ 10 │ 8  │ 8.8   │ Critical │
│ XSS (Stored)        │ 7  │ 8  │ 7  │ 8  │ 7  │ 7.4   │ High     │
│ IDOR (order lookup) │ 6  │ 9  │ 9  │ 8  │ 8  │ 8.0   │ Critical │
│ JWT alg:none        │ 10 │ 10 │ 7  │ 10 │ 6  │ 8.6   │ Critical │
│ Weak password policy│ 5  │ 5  │ 5  │ 7  │ 5  │ 5.4   │ Medium   │
│ Unnecessary headers │ 2  │ 9  │ 9  │ 10 │ 9  │ 7.8   │ High     │
└─────────────────────┴────┴────┴────┴────┴────┴───────┴──────────┘
```

---

## Writing Attack Trees

An Attack Tree is a hierarchical threat model with the attack goal as the root node and possible attack methods as child nodes.

### Attack Tree Structure

```
Node types:
OR node: achieving any one child condition achieves the parent goal
AND node: all child conditions must be achieved to reach the parent goal

Notation:
[goal]  - root or intermediate node
(OR)    - OR gate
(AND)   - AND gate
{condition} - leaf node (actual attack action)
```

### Example: Administrator Account Takeover

```
[Administrator Account Takeover]
        (OR)
        ├── [Credential Theft]
        │       (OR)
        │       ├── {Phishing attack}
        │       ├── {Install keylogger}
        │       ├── {DB dump then crack}
        │       └── [Man-in-the-Middle Attack]
        │               (AND)
        │               ├── {Gain network position}
        │               └── {TLS downgrade}
        │
        ├── [Authentication Bypass]
        │       (OR)
        │       ├── {SQL Injection on Login}
        │       ├── {Session token prediction}
        │       └── {JWT signature algorithm confusion}
        │
        └── [Privilege Escalation]
                (OR)
                ├── {Admin API access via IDOR}
                ├── {Role parameter tampering}
                └── [OS Privilege Escalation]
                        (AND)
                        ├── {Exploit RCE vulnerability}
                        └── {Exploit SUID binary}
```

### Example: Payment Information Theft

```
[Payment Information Theft]
        (OR)
        ├── [Intercept in Transit]
        │       (AND)
        │       ├── {Establish MITM position}
        │       └── {Break TLS encryption}
        │               (OR)
        │               ├── {Forge certificate}
        │               └── {BEAST/POODLE attack}
        │
        ├── [Steal Stored Data]
        │       (OR)
        │       ├── {Direct DB access}
        │       │       (OR)
        │       │       ├── {Steal credentials}
        │       │       └── {DB query via SQLi}
        │       └── {Access backup files}
        │
        └── [Application Memory Dump]
                (AND)
                ├── {Obtain RCE}
                └── {Scan memory}
```

### Attack Tree Cost/Probability Annotations

```
Assign attributes to each leaf node:
{SQL Injection on Login}
  - Cost: $0 (using public tools)
  - Skill level: Low
  - Detectability: High
  - Success probability: 0.3 (with WAF)

AND node probability = P(A) × P(B)
OR node probability = 1 - (1-P(A)) × (1-P(B))

Example:
[Man-in-the-Middle Attack] (AND)
  P = P(gain network position) × P(TLS downgrade)
  P = 0.1 × 0.05 = 0.005 (0.5%)

[Credential Theft] (OR: phishing, keylogger, DB cracking)
  P = 1 - (1-0.4) × (1-0.1) × (1-0.05)
  P ≈ 0.51 (51%)
```

---

<a name="lockheed-martin-cyber-kill-chain-en"></a>
## Lockheed Martin Cyber Kill Chain

The Kill Chain is a model describing 7 stages of a cyber attack, where the attack can be detected/blocked at each stage.

### Kill Chain 7 Stages

```
Stage 1: Reconnaissance
   Attacker actions:
   - Open-source intelligence gathering (OSINT)
   - Identify technology stack
   - Employee social media profiling
   - Vulnerability scanning (Shodan, Censys)
   - Domain/subdomain enumeration

   Detection/Response:
   - Detect web scanner traffic
   - Monitor abnormal DNS lookups
   - Minimize publicly available information

Stage 2: Weaponization
   Attacker actions:
   - Develop exploit code
   - Create malicious documents/links
   - Package RAT/backdoor
   - Build C2 infrastructure

   Detection/Response:
   - Subscribe to threat intelligence
   - Update malicious tool signatures

Stage 3: Delivery
   Attacker actions:
   - Send spear phishing emails
   - Operate malicious websites (Watering Hole)
   - USB drop attacks
   - Supply chain compromise

   Detection/Response:
   - Email filtering (SPF, DKIM, DMARC)
   - Web proxy filtering
   - User security awareness training

Stage 4: Exploitation
   Attacker actions:
   - Exploit vulnerabilities
   - Trigger code execution
   - Exploit browser/plugin vulnerabilities

   Detection/Response:
   - EDR solutions
   - Vulnerability patch management
   - Application whitelisting

Stage 5: Installation
   Attacker actions:
   - Install backdoor/RAT
   - Install rootkit
   - Establish persistence

   Detection/Response:
   - File integrity monitoring
   - Anomalous process detection
   - Registry/system monitoring

Stage 6: Command & Control (C2)
   Attacker actions:
   - Establish C2 channel
   - Beacon communication
   - DNS tunneling
   - HTTPS-based covert communication

   Detection/Response:
   - Detect abnormal outbound traffic
   - DNS anomaly detection
   - Network behavior analysis (NBA)

Stage 7: Actions on Objectives
   Attacker actions:
   - Data exfiltration
   - Ransomware deployment
   - Service destruction
   - Lateral movement

   Detection/Response:
   - DLP solutions
   - Anomalous data transfer detection
   - Network segmentation
```

### Kill Chain-Based Threat Model Mapping

```
Attack scenario → Kill Chain mapping:

Scenario: Internal network infiltration via web app

1. Reconnaissance
   → Identify port 443 services with Shodan
   → Identify technology stack with whatweb
   → Enumerate directories with gobuster

2. Weaponization
   → Collect CVE-2024-XXXX PoC code
   → Customize Metasploit module

3. Delivery
   → Direct attack on vulnerable API endpoint

4. Exploitation
   → SQL Injection → RCE
   → CVE exploitation

5. Installation
   → Upload webshell (/uploads/shell.php)
   → Register cron for persistence

6. C2
   → DNS tunneling (dnscat2)
   → HTTPS reverse shell

7. Actions
   → Scan internal DB
   → Extract payment information
   → Compress and exfiltrate data
```

---

## MITRE ATT&CK Framework Integration

### ATT&CK Matrix Structure

```
Tactics (14):
TA0001: Initial Access
TA0002: Execution
TA0003: Persistence
TA0004: Privilege Escalation
TA0005: Defense Evasion
TA0006: Credential Access
TA0007: Discovery
TA0008: Lateral Movement
TA0009: Collection
TA0010: Exfiltration
TA0011: Command and Control
TA0040: Impact
TA0042: Resource Development
TA0043: Reconnaissance

Techniques (examples):
T1190: Exploit Public-Facing Application
T1059: Command and Scripting Interpreter
T1078: Valid Accounts
T1110: Brute Force
T1055: Process Injection
```

### Using ATT&CK Navigator

```bash
# Run ATT&CK Navigator locally
git clone https://github.com/mitre-attack/attack-navigator
cd attack-navigator/nav-app
npm install
npm start
# Access http://localhost:4200

# Query ATT&CK data with Python
pip3 install attackcti

python3 << 'EOF'
from attackcti import attack_client

client = attack_client()

# Query techniques related to web applications
techniques = client.get_techniques_by_platform("Windows")
for t in techniques[:5]:
    print(f"{t['external_references'][0]['external_id']}: {t['name']}")
EOF
```

### Linking Threat Model with ATT&CK

```
STRIDE ↔ ATT&CK Mapping:

Spoofing:
  → T1078 Valid Accounts
  → T1134 Access Token Manipulation
  → T1539 Steal Web Session Cookie

Tampering:
  → T1565 Data Manipulation
  → T1491 Defacement
  → T1059 Command and Scripting Interpreter

Repudiation:
  → T1562 Impair Defenses
  → T1070 Indicator Removal

Information Disclosure:
  → T1552 Unsecured Credentials
  → T1530 Data from Cloud Storage
  → T1213 Data from Information Repositories

Denial of Service:
  → T1499 Endpoint Denial of Service
  → T1498 Network Denial of Service

Elevation of Privilege:
  → T1068 Exploitation for Privilege Escalation
  → T1548 Abuse Elevation Control Mechanism
  → T1055 Process Injection
```

---

## DREAD Automation Script

```python
#!/usr/bin/env python3
"""
DREAD risk score calculation and priority sorting tool

Usage:
    python3 dread_calculator.py --input threats.json --output report.json
    python3 dread_calculator.py --interactive
    python3 dread_calculator.py --input threats.json --format html --output report.html
    python3 dread_calculator.py --demo
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, asdict, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional


class RiskLevel(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"

    @staticmethod
    def from_score(score: float) -> "RiskLevel":
        if score >= 8.0:
            return RiskLevel.CRITICAL
        elif score >= 6.0:
            return RiskLevel.HIGH
        elif score >= 3.0:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW

    @property
    def color(self) -> str:
        colors = {
            "Critical": "#dc3545",
            "High": "#fd7e14",
            "Medium": "#ffc107",
            "Low": "#28a745",
        }
        return colors[self.value]

    @property
    def priority_order(self) -> int:
        order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        return order[self.value]


@dataclass
class DREADScores:
    damage: int           # 0-10: damage potential on success
    reproducibility: int  # 0-10: ease of reproducing the attack
    exploitability: int   # 0-10: ease of exploitation
    affected_users: int   # 0-10: number of affected users
    discoverability: int  # 0-10: ease of discovering the vulnerability

    def __post_init__(self) -> None:
        for field_name in ["damage", "reproducibility", "exploitability",
                           "affected_users", "discoverability"]:
            val = getattr(self, field_name)
            if not 0 <= val <= 10:
                raise ValueError(
                    f"{field_name} score must be between 0-10. Input value: {val}"
                )

    @property
    def total(self) -> float:
        return (
            self.damage
            + self.reproducibility
            + self.exploitability
            + self.affected_users
            + self.discoverability
        ) / 5.0

    @property
    def risk_level(self) -> RiskLevel:
        return RiskLevel.from_score(self.total)

    def to_dict(self) -> dict:
        return {
            "damage": self.damage,
            "reproducibility": self.reproducibility,
            "exploitability": self.exploitability,
            "affected_users": self.affected_users,
            "discoverability": self.discoverability,
            "total": round(self.total, 1),
            "risk_level": self.risk_level.value,
        }


@dataclass
class AttackTreeNode:
    id: str
    name: str
    description: str
    node_type: str  # "OR", "AND", "LEAF"
    children: list["AttackTreeNode"] = field(default_factory=list)
    cost: Optional[str] = None
    probability: Optional[float] = None
    skill_level: Optional[str] = None

    def calculate_probability(self) -> float:
        """Calculate Attack Tree probability"""
        if self.node_type == "LEAF":
            return self.probability or 0.0

        child_probs = [c.calculate_probability() for c in self.children]

        if not child_probs:
            return 0.0

        if self.node_type == "OR":
            # OR: 1 - ∏(1 - P(i))
            result = 1.0
            for p in child_probs:
                result *= (1 - p)
            return 1 - result

        elif self.node_type == "AND":
            # AND: ∏P(i)
            result = 1.0
            for p in child_probs:
                result *= p
            return result

        return 0.0


@dataclass
class Threat:
    id: str
    name: str
    description: str
    affected_component: str
    attack_vector: str
    dread: DREADScores
    mitigations: list[str] = field(default_factory=list)
    cve_references: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    kill_chain_stage: Optional[str] = None
    status: str = "Open"
    attack_tree: Optional[AttackTreeNode] = None

    @property
    def priority_score(self) -> float:
        return self.dread.total

    def to_dict(self) -> dict:
        d = {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "affected_component": self.affected_component,
            "attack_vector": self.attack_vector,
            "dread": self.dread.to_dict(),
            "mitigations": self.mitigations,
            "cve_references": self.cve_references,
            "mitre_techniques": self.mitre_techniques,
            "kill_chain_stage": self.kill_chain_stage,
            "status": self.status,
        }
        if self.attack_tree:
            d["attack_tree_probability"] = round(
                self.attack_tree.calculate_probability(), 3
            )
        return d


class DREADAnalyzer:
    """DREAD analysis engine"""

    def __init__(self) -> None:
        self.threats: list[Threat] = []

    def add_threat(self, threat: Threat) -> None:
        self.threats.append(threat)

    def load_from_json(self, path: Path) -> None:
        """Load threat list from JSON file"""
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            raise ValueError(f"Failed to load JSON file: {e}") from e

        for item in data.get("threats", []):
            try:
                dread_data = item["dread"]
                dread = DREADScores(
                    damage=dread_data["damage"],
                    reproducibility=dread_data["reproducibility"],
                    exploitability=dread_data["exploitability"],
                    affected_users=dread_data["affected_users"],
                    discoverability=dread_data["discoverability"],
                )
                threat = Threat(
                    id=item["id"],
                    name=item["name"],
                    description=item.get("description", ""),
                    affected_component=item.get("affected_component", ""),
                    attack_vector=item.get("attack_vector", ""),
                    dread=dread,
                    mitigations=item.get("mitigations", []),
                    cve_references=item.get("cve_references", []),
                    mitre_techniques=item.get("mitre_techniques", []),
                    kill_chain_stage=item.get("kill_chain_stage"),
                    status=item.get("status", "Open"),
                )
                self.threats.append(threat)
            except (KeyError, ValueError) as e:
                print(f"Warning: Failed to load threat {item.get('id', '?')} - {e}",
                      file=sys.stderr)

    def get_sorted_threats(self) -> list[Threat]:
        """Sort threats by DREAD score descending"""
        return sorted(
            self.threats,
            key=lambda t: (-t.priority_score, t.dread.risk_level.priority_order),
        )

    def get_by_risk_level(self) -> dict[str, list[Threat]]:
        result: dict[str, list[Threat]] = {
            level.value: [] for level in RiskLevel
        }
        for threat in self.threats:
            result[threat.dread.risk_level.value].append(threat)
        return result

    def generate_summary(self) -> dict:
        by_level = self.get_by_risk_level()
        avg_score = (
            sum(t.priority_score for t in self.threats) / len(self.threats)
            if self.threats else 0
        )

        # Kill Chain distribution
        kill_chain_dist: dict[str, int] = {}
        for t in self.threats:
            if t.kill_chain_stage:
                kill_chain_dist[t.kill_chain_stage] = (
                    kill_chain_dist.get(t.kill_chain_stage, 0) + 1
                )

        return {
            "total_threats": len(self.threats),
            "by_risk_level": {k: len(v) for k, v in by_level.items()},
            "average_score": round(avg_score, 1),
            "open_threats": sum(1 for t in self.threats if t.status == "Open"),
            "kill_chain_distribution": kill_chain_dist,
        }

    def generate_json_report(self) -> str:
        sorted_threats = self.get_sorted_threats()
        return json.dumps({
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "tool": "DREAD Analyzer",
                "version": "1.0",
            },
            "summary": self.generate_summary(),
            "threats": [t.to_dict() for t in sorted_threats],
        }, ensure_ascii=False, indent=2)

    def interactive_input(self) -> None:
        """Interactive threat input"""
        print("\n=== DREAD Interactive Threat Input ===")
        print("Score range: 0 (low) ~ 10 (high)\n")

        count = 0
        while True:
            count += 1
            print(f"\n--- Threat {count} ---")
            name = input("Threat name (empty line to finish): ").strip()
            if not name:
                break

            desc = input("Description: ").strip()
            component = input("Affected component: ").strip()
            attack_vector = input("Attack vector: ").strip()

            print("\nEnter DREAD scores (0-10):")
            scores = {}
            labels = {
                "damage": "D - Damage potential",
                "reproducibility": "R - Reproducibility",
                "exploitability": "E - Exploitability",
                "affected_users": "A - Affected users",
                "discoverability": "D - Discoverability",
            }
            for key, label in labels.items():
                while True:
                    try:
                        val = int(input(f"  {label}: "))
                        if 0 <= val <= 10:
                            scores[key] = val
                            break
                        print("  Please enter a value between 0-10.")
                    except ValueError:
                        print("  Please enter a number.")

            dread = DREADScores(**scores)
            threat = Threat(
                id=f"T{count:03d}",
                name=name,
                description=desc,
                affected_component=component,
                attack_vector=attack_vector,
                dread=dread,
            )

            self.threats.append(threat)
            print(f"\n  → DREAD score: {dread.total:.1f} ({dread.risk_level.value})")


def create_demo_threats() -> list[Threat]:
    """Create demo threat list"""
    demo_data = [
        {
            "id": "T001", "name": "Login SQL Injection",
            "description": "SQL injection in login form username parameter",
            "affected_component": "Auth Service", "attack_vector": "HTTP POST /api/login",
            "dread": DREADScores(9, 9, 8, 10, 8),
            "mitigations": ["Use parameterized queries", "Apply ORM", "Deploy WAF"],
            "mitre_techniques": ["T1190"],
            "kill_chain_stage": "Exploitation",
        },
        {
            "id": "T002", "name": "JWT Algorithm Confusion",
            "description": "alg:none or RS256→HS256 algorithm confusion attack",
            "affected_component": "Auth Middleware", "attack_vector": "HTTP header manipulation",
            "dread": DREADScores(10, 10, 7, 10, 6),
            "mitigations": ["Explicit algorithm validation", "Use latest JWT library"],
            "mitre_techniques": ["T1078", "T1134"],
            "kill_chain_stage": "Exploitation",
        },
        {
            "id": "T003", "name": "IDOR Order Data Access",
            "description": "View/modify other users' orders",
            "affected_component": "Order Service", "attack_vector": "GET /api/orders/{id}",
            "dread": DREADScores(6, 9, 9, 8, 8),
            "mitigations": ["Server-side ownership validation", "Use UUID"],
            "mitre_techniques": ["T1078"],
            "kill_chain_stage": "Actions on Objectives",
        },
        {
            "id": "T004", "name": "Stored XSS in Reviews",
            "description": "Inject malicious script into product reviews",
            "affected_component": "Product Service", "attack_vector": "POST /api/reviews",
            "dread": DREADScores(7, 8, 7, 8, 7),
            "mitigations": ["Output encoding", "CSP header", "Apply DOMPurify"],
            "mitre_techniques": ["T1059.007"],
            "kill_chain_stage": "Delivery",
        },
        {
            "id": "T005", "name": "Payment Amount Parameter Tampering",
            "description": "Client-side tampering of payment amount parameter",
            "affected_component": "Payment Service", "attack_vector": "POST /api/payment",
            "dread": DREADScores(9, 9, 9, 10, 7),
            "mitigations": ["Server-side amount recalculation", "Signed payment request"],
            "mitre_techniques": ["T1565"],
            "kill_chain_stage": "Actions on Objectives",
        },
        {
            "id": "T006", "name": "No API Rate Limit",
            "description": "Brute force possible on login API",
            "affected_component": "API Gateway", "attack_vector": "HTTP POST /api/login",
            "dread": DREADScores(7, 10, 10, 9, 9),
            "mitigations": ["Rate Limiting (5req/min)", "Account lockout", "CAPTCHA"],
            "mitre_techniques": ["T1110"],
            "kill_chain_stage": "Reconnaissance",
        },
        {
            "id": "T007", "name": "Environment Variable Sensitive Info Exposure",
            "description": "Environment variables exposed at /api/debug endpoint",
            "affected_component": "Web Server", "attack_vector": "GET /api/debug",
            "dread": DREADScores(8, 10, 10, 10, 9),
            "mitigations": ["Disable debug endpoint", "Move sensitive env vars to Secret Manager"],
            "mitre_techniques": ["T1552"],
            "kill_chain_stage": "Reconnaissance",
        },
    ]

    threats = []
    for d in demo_data:
        threat = Threat(
            id=d["id"],
            name=d["name"],
            description=d["description"],
            affected_component=d["affected_component"],
            attack_vector=d["attack_vector"],
            dread=d["dread"],
            mitigations=d["mitigations"],
            mitre_techniques=d["mitre_techniques"],
            kill_chain_stage=d["kill_chain_stage"],
        )
        threats.append(threat)

    return threats


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="DREAD risk score calculation and priority sorting tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --demo --format html --output demo_report.html
  %(prog)s --input threats.json --output sorted_report.json
  %(prog)s --interactive --format html --output my_threats.html
        """,
    )

    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument("--input", type=Path, help="Threat list JSON file")
    input_group.add_argument("--interactive", action="store_true", help="Interactive input")
    input_group.add_argument("--demo", action="store_true", help="Use demo threat list")

    parser.add_argument(
        "--format", choices=["json", "html"], default="json",
        help="Output format",
    )
    parser.add_argument(
        "--output", type=Path, default=Path("dread_report.json"),
        help="Output file path",
    )
    parser.add_argument(
        "--top", type=int, default=0,
        help="Output only top N threats (0=all)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    analyzer = DREADAnalyzer()

    try:
        if args.demo:
            for threat in create_demo_threats():
                analyzer.add_threat(threat)
            print(f"Loaded {len(analyzer.threats)} demo threats")

        elif args.interactive:
            analyzer.interactive_input()
            if not analyzer.threats:
                print("No threats entered.", file=sys.stderr)
                return 1

        elif args.input:
            analyzer.load_from_json(args.input)
            print(f"Loaded {len(analyzer.threats)} threats")

    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    # Print summary
    summary = analyzer.generate_summary()
    print(f"\n=== DREAD Analysis Results ===")
    print(f"Total threats: {summary['total_threats']}")
    print(f"Average DREAD score: {summary['average_score']}")
    for level in RiskLevel:
        count = summary["by_risk_level"].get(level.value, 0)
        if count > 0:
            print(f"  {level.value}: {count}")

    # Print top threats
    sorted_threats = analyzer.get_sorted_threats()
    if args.top > 0:
        sorted_threats = sorted_threats[:args.top]
        analyzer.threats = sorted_threats

    print(f"\nTop {min(5, len(sorted_threats))} threats:")
    for i, t in enumerate(sorted_threats[:5], 1):
        print(f"  {i}. [{t.dread.risk_level.value}] {t.name} (DREAD: {t.dread.total:.1f})")

    # Generate report
    try:
        if args.format == "json":
            report = analyzer.generate_json_report()
        else:
            report = analyzer.generate_html_report()

        args.output.write_text(report, encoding="utf-8")
        print(f"\nReport saved: {args.output}")
    except OSError as e:
        print(f"Save failed: {e}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
```

### Execution Examples

```bash
# Generate HTML report with demo data
python3 dread_calculator.py --demo --format html --output demo.html

# Top 5 threats JSON report
python3 dread_calculator.py --demo --top 5 --output top5.json

# Analyze existing threat JSON file
python3 dread_calculator.py --input threats.json --format html --output report.html

# Interactive input
python3 dread_calculator.py --interactive --format html --output my_report.html
```

### Input JSON Format

```json
{
  "threats": [
    {
      "id": "T001",
      "name": "SQL Injection",
      "description": "SQL injection in login form",
      "affected_component": "Auth Service",
      "attack_vector": "POST /api/login",
      "dread": {
        "damage": 9,
        "reproducibility": 9,
        "exploitability": 8,
        "affected_users": 10,
        "discoverability": 8
      },
      "mitigations": ["Parameterized queries", "WAF"],
      "mitre_techniques": ["T1190"],
      "kill_chain_stage": "Exploitation",
      "status": "Open"
    }
  ]
}
```

---

## References

- [PASTA Threat Modeling](https://www.wiley.com/en-us/Risk+Centric+Threat+Modeling-p-9780470500965)
- [DREAD Risk Rating Model](https://en.wikipedia.org/wiki/DREAD_%28risk_assessment_model%29)
- [Attack Trees (Bruce Schneier)](https://www.schneier.com/academic/archives/1999/12/attack_trees.html)
- [Lockheed Martin Cyber Kill Chain](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)

<!-- detect-validate-48 -->
## Risk-Assessment / Attack-Tree Validation (Scored != Validated)

PASTA, DREAD, attack trees, and kill chains *score threats and structure attack paths*. "We scored the risk" differs from "that path is actually reachable and exploitable" -- validate high-risk paths on owned environments.

### Validation item -> Question -> Measured signal -> Pitfall

| Validation item | Question | Measured signal | Pitfall |
|---|---|---|---|
| Path reachability | Leaf->root possible? | Reproduce path via PoC | Theoretical tree |
| Risk-score basis | Data-driven? | Reflects measured exploitability | Subjective DREAD |
| Control choke point | Does it cut the path? | Path impossible after control | Control unvalidated |
| Prioritization | Real risk order? | Validated paths first | Trust scores only |

### Assessment validation (verify directly)

```bash
# 1) Whether a high-risk attack-tree leaf is actually reachable (owned env) — PoC reproduction separates theory from reality
jq -r '.attack_tree.leaves[] | select(.risk=="high") | .path' attack_tree.json 2>/dev/null | head
# 2) Validate path cut after applying a control — a choke-point control that breaks the real path signals risk reduction
grep -rIiE 'rate.?limit|mfa|allowlist|waf' controls/ 2>/dev/null | head
```

> Risk assessment is *whether paths are reachable and cut* -- "the DREAD score is high" differs from "that path is reached via PoC and is cut when a control is applied". Validate high-risk paths on owned environments directly ([[68_Purple_Team]], [[30_Vulnerability_Research]], [[17_Red_Team_Operations]]).
