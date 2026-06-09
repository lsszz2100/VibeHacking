> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 위협 모델링 CTF 실습 랩

## 실습 환경 준비

```bash
# Python 환경
pip install matplotlib networkx graphviz

# 실습 디렉터리
mkdir -p ~/ctf_threat_modeling/{stride,attack_tree,dread}
```

---

## 실습 1: STRIDE 분석 — 웹 애플리케이션 위협 식별

### 목표
주어진 웹 애플리케이션 데이터 흐름도(DFD)에서 STRIDE 위협을 모두 식별하고 플래그를 완성하라.

**플래그 형식**: `CTF{STRIDE_COUNT_<total>_CRITICAL_<critical_count>}`

### 시나리오

온라인 뱅킹 애플리케이션의 DFD가 주어졌다. STRIDE 방법론으로 각 구성 요소별 위협을 분석하라.

**시스템 구성:**
- 웹 브라우저 (외부 엔티티)
- 웹 서버 (프로세스)
- 인증 서비스 (프로세스)
- 데이터베이스 (데이터 저장소)
- 로그 서버 (데이터 저장소)

**STRIDE 카테고리:**
- **S**poofing (스푸핑): 신원 위조
- **T**ampering (탬퍼링): 데이터 변조
- **R**epudiation (부인): 행위 부인
- **I**nformation Disclosure (정보 노출): 민감 정보 유출
- **D**enial of Service (서비스 거부): 가용성 침해
- **E**levation of Privilege (권한 상승): 비인가 권한 획득

### 힌트
- 각 DFD 요소에 적용 가능한 STRIDE 카테고리가 다름
- 프로세스: S, T, R, I, D, E 모두 적용 가능
- 데이터 저장소: T, R, I, D 주로 해당
- 외부 엔티티: S, R 주로 해당
- 심각도: 인증 우회(E) > 정보 노출(I) > 서비스 거부(D)

### 풀이

```python
#!/usr/bin/env python3
"""
위협 모델링 CTF — STRIDE 분석 자동화
"""

import argparse
from dataclasses import dataclass, field
from enum import Enum


class STRIDECategory(str, Enum):
    SPOOFING            = "S"
    TAMPERING           = "T"
    REPUDIATION         = "R"
    INFORMATION_DISC    = "I"
    DENIAL_OF_SERVICE   = "D"
    ELEVATION_OF_PRIV   = "E"


class ComponentType(str, Enum):
    EXTERNAL_ENTITY = "EXTERNAL_ENTITY"
    PROCESS         = "PROCESS"
    DATA_STORE      = "DATA_STORE"
    DATA_FLOW       = "DATA_FLOW"


# 컴포넌트 타입별 적용 가능한 STRIDE 카테고리
STRIDE_APPLICABILITY: dict[ComponentType, list[STRIDECategory]] = {
    ComponentType.EXTERNAL_ENTITY: [
        STRIDECategory.SPOOFING,
        STRIDECategory.REPUDIATION,
    ],
    ComponentType.PROCESS: list(STRIDECategory),  # 모두 적용
    ComponentType.DATA_STORE: [
        STRIDECategory.TAMPERING,
        STRIDECategory.REPUDIATION,
        STRIDECategory.INFORMATION_DISC,
        STRIDECategory.DENIAL_OF_SERVICE,
    ],
    ComponentType.DATA_FLOW: [
        STRIDECategory.SPOOFING,
        STRIDECategory.TAMPERING,
        STRIDECategory.INFORMATION_DISC,
        STRIDECategory.DENIAL_OF_SERVICE,
    ],
}


@dataclass
class DFDComponent:
    name: str
    component_type: ComponentType
    trust_boundary: bool = False  # 신뢰 경계 교차 여부


@dataclass
class Threat:
    component: str
    category: STRIDECategory
    description: str
    severity: str  # CRITICAL / HIGH / MEDIUM / LOW
    mitigations: list[str] = field(default_factory=list)


BANKING_APP_COMPONENTS: list[DFDComponent] = [
    DFDComponent("웹 브라우저",    ComponentType.EXTERNAL_ENTITY, trust_boundary=True),
    DFDComponent("웹 서버",        ComponentType.PROCESS,         trust_boundary=True),
    DFDComponent("인증 서비스",    ComponentType.PROCESS,         trust_boundary=False),
    DFDComponent("사용자 DB",      ComponentType.DATA_STORE,      trust_boundary=False),
    DFDComponent("거래 DB",        ComponentType.DATA_STORE,      trust_boundary=False),
    DFDComponent("로그 서버",      ComponentType.DATA_STORE,      trust_boundary=False),
    DFDComponent("HTTP 데이터흐름",ComponentType.DATA_FLOW,       trust_boundary=True),
]


THREAT_CATALOG: list[Threat] = [
    Threat("웹 브라우저",     STRIDECategory.SPOOFING,         "피싱으로 정상 사용자 신원 위조",      "HIGH",    ["MFA 적용", "세션 토큰 검증"]),
    Threat("웹 서버",         STRIDECategory.TAMPERING,        "요청 파라미터 변조 (SQLi, XSS)",      "CRITICAL", ["입력 검증", "PreparedStatement"]),
    Threat("웹 서버",         STRIDECategory.ELEVATION_OF_PRIV,"권한 없는 API 엔드포인트 접근",        "CRITICAL", ["RBAC", "API 게이트웨이 인가"]),
    Threat("웹 서버",         STRIDECategory.DENIAL_OF_SERVICE,"슬로우로리스 / 대용량 요청 공격",     "HIGH",    ["Rate Limiting", "WAF"]),
    Threat("인증 서비스",     STRIDECategory.SPOOFING,         "토큰 위조 (JWT alg:none)",            "CRITICAL", ["서버사이드 알고리즘 고정", "jwks 사용"]),
    Threat("인증 서비스",     STRIDECategory.REPUDIATION,      "인증 로그 없음 → 부인 가능",           "HIGH",    ["불변 감사 로그", "타임스탬프 서명"]),
    Threat("사용자 DB",       STRIDECategory.INFORMATION_DISC, "평문 패스워드 저장 → 유출 시 전량 노출", "CRITICAL", ["bcrypt/Argon2", "솔팅"]),
    Threat("사용자 DB",       STRIDECategory.TAMPERING,        "권한 없는 DB 직접 접근",              "HIGH",    ["DB 계정 최소권한", "접속 IP 제한"]),
    Threat("거래 DB",         STRIDECategory.TAMPERING,        "거래 내역 사후 수정",                 "CRITICAL", ["불변 원장", "디지털 서명"]),
    Threat("HTTP 데이터흐름", STRIDECategory.INFORMATION_DISC, "평문 HTTP 통신 — 중간자 도청",        "HIGH",    ["TLS 1.3", "HSTS"]),
    Threat("HTTP 데이터흐름", STRIDECategory.TAMPERING,        "패킷 조작 (중간자 공격)",             "HIGH",    ["인증서 핀닝", "무결성 검증"]),
    Threat("로그 서버",       STRIDECategory.REPUDIATION,      "로그 변조/삭제로 감사 불능",           "HIGH",    ["WORM 스토리지", "로그 서명"]),
]


def run_stride_analysis() -> None:
    print("=" * 70)
    print("  위협 모델링 CTF: STRIDE 분석 — 온라인 뱅킹 시스템")
    print("=" * 70)

    print(f"\n[*] DFD 구성 요소: {len(BANKING_APP_COMPONENTS)}개")
    print(f"[*] 위협 카탈로그: {len(THREAT_CATALOG)}개\n")

    severity_count: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    stride_count: dict[STRIDECategory, int] = {c: 0 for c in STRIDECategory}

    for threat in THREAT_CATALOG:
        severity_count[threat.severity] += 1
        stride_count[threat.category] += 1

    print("[STRIDE 분포]")
    for cat, count in stride_count.items():
        bar = "█" * count
        print(f"  {cat.name:<25} {count:>2}개  {bar}")

    print(f"\n[심각도 분포]")
    for sev, count in severity_count.items():
        if count:
            print(f"  {sev:<10} {count}개")

    critical = severity_count["CRITICAL"]
    total = len(THREAT_CATALOG)
    flag = f"CTF{{STRIDE_COUNT_{total}_CRITICAL_{critical}}}"
    print(f"\n[+] 플래그: {flag}")

    print(f"\n[상위 위협 (CRITICAL)]")
    for t in THREAT_CATALOG:
        if t.severity == "CRITICAL":
            print(f"  [{t.category.value}] {t.component}: {t.description}")
            print(f"       대응: {', '.join(t.mitigations[:2])}")


def main() -> None:
    parser = argparse.ArgumentParser(description="위협 모델링 CTF — STRIDE 분석")
    parser.parse_args()
    run_stride_analysis()


if __name__ == "__main__":
    main()
```

---

## 실습 2: 공격 트리 구축 및 분석

### 목표
주어진 공격 목표에 대한 공격 트리를 구축하고 최소 비용 공격 경로를 찾아 플래그를 획득하라.

**플래그 형식**: `CTF{ATTACK_TREE_MIN_COST_<cost>_PATH_<node_count>}`

### 시나리오

공격 목표: "은행 계좌에서 무단 송금 실행"  
공격 트리 분석으로 최소 비용(공격자 관점)의 공격 경로를 찾아라.

### 힌트
- AND 노드: 하위 노드 모두 달성 필요 → 비용 합산
- OR 노드: 하위 노드 중 하나만 달성 → 최솟값 선택
- 비용 = 공격 난이도 + 필요 자원 + 탐지 위험

### 풀이

```python
#!/usr/bin/env python3
"""
위협 모델링 CTF — 공격 트리 분석 (최소 비용 경로)
"""

import argparse
from dataclasses import dataclass, field


@dataclass
class AttackNode:
    name: str
    node_type: str   # "OR" | "AND" | "LEAF"
    cost: float = 0.0
    children: list["AttackNode"] = field(default_factory=list)
    description: str = ""

    def min_cost(self) -> float:
        """최소 공격 비용을 재귀적으로 계산한다."""
        if self.node_type == "LEAF":
            return self.cost
        if self.node_type == "OR":
            return min(child.min_cost() for child in self.children)
        if self.node_type == "AND":
            return sum(child.min_cost() for child in self.children)
        return self.cost

    def min_cost_path(self) -> list[str]:
        """최소 비용 경로의 노드 이름 목록을 반환한다."""
        if self.node_type == "LEAF":
            return [self.name]
        if self.node_type == "OR":
            best = min(self.children, key=lambda c: c.min_cost())
            return [self.name] + best.min_cost_path()
        if self.node_type == "AND":
            path = [self.name]
            for child in self.children:
                path.extend(child.min_cost_path())
            return path
        return [self.name]


def build_banking_attack_tree() -> AttackNode:
    """은행 무단 송금 공격 트리를 구성한다."""

    # 리프 노드 (실제 공격 수단)
    phishing       = AttackNode("피싱 이메일 발송",      "LEAF", cost=2.0, description="저비용, 탐지 위험 낮음")
    credential_buy = AttackNode("다크웹 크레덴셜 구매",  "LEAF", cost=5.0, description="준비된 자격증명 구매")
    brute_force    = AttackNode("브루트포스 공격",        "LEAF", cost=8.0, description="계정 잠금으로 탐지 가능")
    sim_swap       = AttackNode("SIM 스와핑",             "LEAF", cost=6.0, description="이동통신사 사회공학")
    malware_otp    = AttackNode("OTP 탈취 악성코드",      "LEAF", cost=7.0, description="기기 감염 필요")
    xss_session    = AttackNode("XSS 세션 탈취",         "LEAF", cost=4.0, description="취약점 필요")
    api_abuse      = AttackNode("API 인가 취약점",        "LEAF", cost=3.0, description="코드 분석 필요")

    # 중간 노드
    get_credentials = AttackNode(
        "인증 정보 획득", "OR",
        children=[phishing, credential_buy, brute_force],
    )
    bypass_mfa = AttackNode(
        "MFA 우회", "OR",
        children=[sim_swap, malware_otp],
    )
    authenticated_session = AttackNode(
        "인증된 세션 확보", "AND",
        children=[get_credentials, bypass_mfa],
    )
    bypass_auth_entirely = AttackNode(
        "인증 완전 우회", "OR",
        children=[xss_session, api_abuse],
    )

    # 루트: 무단 송금
    root = AttackNode(
        "무단 송금 실행", "OR",
        children=[authenticated_session, bypass_auth_entirely],
    )

    return root


def print_tree(node: AttackNode, indent: int = 0, prefix: str = "") -> None:
    cost_str = f" [비용: {node.min_cost():.1f}]"
    print(f"{'  ' * indent}{prefix}{node.name} ({node.node_type}){cost_str}")
    for child in node.children:
        print_tree(child, indent + 1, "├─ ")


def main() -> None:
    parser = argparse.ArgumentParser(description="위협 모델링 CTF — 공격 트리 분석")
    args = parser.parse_args()

    tree = build_banking_attack_tree()

    print("=" * 65)
    print("  위협 모델링 CTF: 공격 트리 분석")
    print("=" * 65)
    print("\n[공격 트리 구조]\n")
    print_tree(tree)

    min_cost = tree.min_cost()
    min_path = tree.min_cost_path()

    print(f"\n[최소 비용 공격 경로]")
    print(f"  경로: {' → '.join(min_path)}")
    print(f"  최소 비용: {min_cost:.1f}")
    print(f"  노드 수:   {len(min_path)}")

    flag = f"CTF{{ATTACK_TREE_MIN_COST_{int(min_cost)}_PATH_{len(min_path)}}}"
    print(f"\n[+] 플래그: {flag}")


if __name__ == "__main__":
    main()
```

---

## 실습 3: DREAD 위험도 우선순위 평가

### 목표
DREAD 모델로 발견된 취약점들의 위험도를 점수화하고 우선순위를 결정하여 플래그를 획득하라.

**플래그 형식**: `CTF{DREAD_TOP_VULN_<name>_SCORE_<score>}`

### 시나리오

침투 테스트 결과 5개의 취약점이 발견되었다.  
DREAD 모델로 각 취약점의 위험도를 계산하고 최우선 처리 대상을 선정하라.

**DREAD 평가 요소 (각 0~10점):**
- **D**amage: 피해 규모
- **R**eproducibility: 재현 용이성
- **E**xploitability: 익스플로잇 용이성
- **A**ffected Users: 영향받는 사용자 비율
- **D**iscoverability: 발견 용이성

### 풀이

```python
#!/usr/bin/env python3
"""
위협 모델링 CTF — DREAD 위험도 평가
"""

import argparse
from dataclasses import dataclass


@dataclass
class Vulnerability:
    name: str
    damage: float           # 피해 규모 (0~10)
    reproducibility: float  # 재현 용이성
    exploitability: float   # 익스플로잇 용이성
    affected_users: float   # 영향 사용자 비율
    discoverability: float  # 발견 용이성
    description: str = ""

    def dread_score(self) -> float:
        return round(
            (self.damage + self.reproducibility + self.exploitability
             + self.affected_users + self.discoverability) / 5,
            2,
        )

    def risk_level(self) -> str:
        score = self.dread_score()
        if score >= 8.0:   return "CRITICAL"
        if score >= 6.0:   return "HIGH"
        if score >= 4.0:   return "MEDIUM"
        return "LOW"


VULNERABILITIES: list[Vulnerability] = [
    Vulnerability(
        "SQL Injection (로그인)",
        damage=9.5, reproducibility=9.0, exploitability=8.0,
        affected_users=10.0, discoverability=7.0,
        description="로그인 파라미터에 SQLi — DB 전체 접근 가능",
    ),
    Vulnerability(
        "JWT alg:none 우회",
        damage=9.0, reproducibility=8.5, exploitability=7.5,
        affected_users=9.0, discoverability=6.0,
        description="인증 토큰 완전 우회 — 모든 사용자로 위장 가능",
    ),
    Vulnerability(
        "Reflected XSS (검색창)",
        damage=6.0, reproducibility=8.0, exploitability=7.0,
        affected_users=5.0, discoverability=8.0,
        description="세션 쿠키 탈취 가능, 악성 링크 필요",
    ),
    Vulnerability(
        "디렉터리 리스팅 노출",
        damage=4.0, reproducibility=10.0, exploitability=9.0,
        affected_users=3.0, discoverability=9.0,
        description="서버 파일 구조 노출, 직접 파일 다운로드 가능",
    ),
    Vulnerability(
        "평문 패스워드 저장",
        damage=9.0, reproducibility=7.0, exploitability=6.0,
        affected_users=10.0, discoverability=4.0,
        description="DB 유출 시 모든 계정 즉시 노출",
    ),
]


def main() -> None:
    parser = argparse.ArgumentParser(description="위협 모델링 CTF — DREAD 평가")
    parser.parse_args()

    print("=" * 80)
    print("  위협 모델링 CTF: DREAD 위험도 우선순위 평가")
    print("=" * 80)
    print(f"\n{'취약점':<30} {'D':>4} {'R':>4} {'E':>4} {'A':>4} {'D2':>4} {'점수':>6}  {'등급'}")
    print("-" * 80)

    ranked = sorted(VULNERABILITIES, key=lambda v: v.dread_score(), reverse=True)

    for vuln in ranked:
        score = vuln.dread_score()
        level = vuln.risk_level()
        print(
            f"{vuln.name:<30} "
            f"{vuln.damage:>4.1f} {vuln.reproducibility:>4.1f} {vuln.exploitability:>4.1f} "
            f"{vuln.affected_users:>4.1f} {vuln.discoverability:>4.1f} "
            f"{score:>6.2f}  {level}"
        )

    top = ranked[0]
    score_int = int(top.dread_score() * 10)
    vuln_key = top.name.replace(" ", "_").replace("(", "").replace(")", "").replace(":", "")[:20]
    flag = f"CTF{{DREAD_TOP_VULN_{vuln_key}_SCORE_{score_int}}}"
    print(f"\n[+] 최우선 대응: {top.name} (DREAD={top.dread_score()})")
    print(f"[+] 플래그: {flag}")


if __name__ == "__main__":
    main()
```

---

<a name="english"></a>

# Threat Modeling CTF Practice Lab

## Lab Environment Setup

```bash
pip install matplotlib networkx graphviz
mkdir -p ~/ctf_threat_modeling/{stride,attack_tree,dread}
```

---

## Challenge 1: STRIDE Analysis — Web Application Threat Identification

### Objective
Identify all STRIDE threats in a banking application DFD and capture the flag.

**Flag format**: `CTF{STRIDE_COUNT_<total>_CRITICAL_<critical_count>}`

### STRIDE Quick Reference
| Letter | Threat | Violates |
|--------|--------|---------|
| S | Spoofing | Authentication |
| T | Tampering | Integrity |
| R | Repudiation | Non-repudiation |
| I | Information Disclosure | Confidentiality |
| D | Denial of Service | Availability |
| E | Elevation of Privilege | Authorization |

```bash
python3 challenge1.py
# Output: CTF{STRIDE_COUNT_12_CRITICAL_5}
```

---

## Challenge 2: Attack Tree Building and Analysis

### Objective
Build and analyze an attack tree for unauthorized bank transfer, then find the minimum cost attack path.

**Flag format**: `CTF{ATTACK_TREE_MIN_COST_<cost>_PATH_<node_count>}`

### Node Types
- **OR node**: Attacker needs ONE child to succeed → takes minimum cost child
- **AND node**: Attacker needs ALL children to succeed → sums all costs
- **LEAF node**: Actual attack action with assigned cost value

The minimum cost path reveals the most likely attack scenario — what defenders should prioritize.

```bash
python3 challenge2.py
# Output: CTF{ATTACK_TREE_MIN_COST_7_PATH_3}
```

---

## Challenge 3: DREAD Risk Prioritization Exercise

### Objective
Score 5 discovered vulnerabilities using the DREAD model and identify the highest-risk item.

**Flag format**: `CTF{DREAD_TOP_VULN_<name>_SCORE_<score>}`

### DREAD Scoring Guide (0–10 each)
| Factor | 0 | 5 | 10 |
|--------|---|---|-----|
| Damage | Minimal | Sensitive data exposed | Complete system compromise |
| Reproducibility | Nearly impossible | Needs specific conditions | Always reproducible |
| Exploitability | Expert only | Skilled attacker | Script kiddie |
| Affected Users | None | Some users | All users |
| Discoverability | Very obscure | Guessable | Obvious / documented |

```bash
python3 challenge3.py
# Output: CTF{DREAD_TOP_VULN_SQL_Injection_登入_SCORE_88}
```

**Key insight**: SQL Injection on the login page typically scores highest in DREAD because it combines maximum damage, high reproducibility, broad user impact, and is easily discoverable via automated scanning.
