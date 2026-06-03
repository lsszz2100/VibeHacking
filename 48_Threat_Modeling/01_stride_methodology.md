> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# STRIDE 위협 모델링 방법론

## 0. 초보자를 위한 개념 이해

### STRIDE 위협 모델링이란?

STRIDE는 소프트웨어 시스템을 설계할 때 발생할 수 있는 보안 위협을 6가지 범주로 체계적으로 찾아내는 프레임워크다. Microsoft가 개발했으며 현재 업계 표준으로 사용된다. "어떤 기능을 만들 것인가"가 아닌 "어떻게 공격받을 수 있는가"를 먼저 생각하게 만드는 방법론이다.

**왜 배우는가:**
```
위협 모델링 없이 개발했을 때:

  설계 → 개발 → 출시 → [보안 취약점 발견] → 패치
                                             ↑
                              수정 비용 = 설계 단계의 30배

위협 모델링 적용 시:

  설계 → [STRIDE 적용] → 취약점 발견 → 안전한 설계 → 개발 → 출시
           ↑
    수정 비용 최소화 (설계 변경은 무료)

STRIDE 각 글자 의미:
  S - Spoofing       (스푸핑): "나는 관리자다" 위장
  T - Tampering      (변조):   데이터/코드 무단 수정
  R - Repudiation    (부인):   "나는 그런 행동 안 했다" 부인
  I - Info Disclosure(정보노출): 비밀 데이터 유출
  D - Denial of Service(서비스 거부): 서비스 마비
  E - Elevation of Privilege(권한상승): 관리자 권한 탈취
```

### 핵심 개념 정리

```
STRIDE + DFD 프로세스:

DFD (Data Flow Diagram) 작성
  - 시스템의 데이터 흐름을 시각적으로 표현
  - 구성요소: 프로세스(원), 데이터저장소(평행선), 외부엔티티(사각형), 데이터흐름(화살표)
  - 신뢰 경계(Trust Boundary): 권한이 다른 영역 구분선

신뢰 경계 예시:
  [인터넷 사용자] → | 신뢰경계 | → [웹서버] → [DB서버]
  낮은 신뢰                          높은 신뢰  최고 신뢰

STRIDE per Element:
  - 각 DFD 구성요소마다 해당 STRIDE 위협 체계적 적용
  - 프로세스: S, T, R, I, D, E 모두 적용
  - 데이터저장소: T, I, D만 적용
  - 데이터흐름: T, I, D만 적용
  - 외부엔티티: S, R만 적용
```

### 필요한 도구 및 환경
- **Microsoft Threat Modeling Tool**: 무료, STRIDE 자동 적용 (Windows 전용)
- **OWASP Threat Dragon**: 오픈소스 웹/데스크톱 DFD 작성 도구
- **draw.io**: DFD 작성용 무료 다이어그램 도구
- **Python**: 자동화 스크립트 작성

### 기초 실습 예제
```python
#!/usr/bin/env python3
"""
STRIDE 위협 분석 자동화 — 시스템 컴포넌트에 STRIDE 위협을 매핑한다
"""
import json
from dataclasses import dataclass, field
from enum import Enum


class ComponentType(Enum):
    """DFD 구성요소 유형"""
    PROCESS = "프로세스"           # 원
    DATA_STORE = "데이터저장소"    # 평행선
    DATA_FLOW = "데이터흐름"       # 화살표
    EXTERNAL_ENTITY = "외부엔티티" # 사각형


# 컴포넌트 유형별 적용 가능한 STRIDE 위협
STRIDE_PER_ELEMENT: dict[ComponentType, list[str]] = {
    ComponentType.PROCESS: ["Spoofing", "Tampering", "Repudiation", "Info Disclosure", "DoS", "EoP"],
    ComponentType.DATA_STORE: ["Tampering", "Info Disclosure", "DoS"],
    ComponentType.DATA_FLOW: ["Tampering", "Info Disclosure", "DoS"],
    ComponentType.EXTERNAL_ENTITY: ["Spoofing", "Repudiation"],
}

STRIDE_DESCRIPTIONS = {
    "Spoofing": ("인증 위반", "공격자가 합법적인 사용자나 시스템으로 위장"),
    "Tampering": ("무결성 위반", "데이터나 코드의 무단 수정"),
    "Repudiation": ("부인 방지 위반", "행위 후 수행 사실 부인"),
    "Info Disclosure": ("기밀성 위반", "허가되지 않은 정보 노출"),
    "DoS": ("가용성 위반", "서비스 거부 공격으로 가용성 저하"),
    "EoP": ("권한 위반", "낮은 권한으로 높은 권한 작업 수행"),
}


@dataclass
class SystemComponent:
    """DFD 구성요소"""
    name: str
    component_type: ComponentType
    description: str = ""
    crosses_trust_boundary: bool = False


def analyze_stride_threats(components: list[SystemComponent]) -> dict:
    """시스템 컴포넌트 목록에 STRIDE 위협을 자동으로 매핑한다."""
    results = []

    for comp in components:
        applicable_threats = STRIDE_PER_ELEMENT[comp.component_type]
        threats = []

        for threat in applicable_threats:
            desc, detail = STRIDE_DESCRIPTIONS[threat]
            mitigation = get_mitigation(threat)
            threats.append({
                "위협": threat,
                "보안속성": desc,
                "설명": detail,
                "완화방법": mitigation,
                "신뢰경계_위험증가": comp.crosses_trust_boundary,
            })

        results.append({
            "컴포넌트": comp.name,
            "유형": comp.component_type.value,
            "설명": comp.description,
            "위협목록": threats,
            "위협수": len(threats),
        })

    return {"분석결과": results, "총_위협수": sum(r["위협수"] for r in results)}


def get_mitigation(threat: str) -> str:
    """각 STRIDE 위협에 대한 일반적인 완화 방법을 반환한다."""
    mitigations = {
        "Spoofing": "강력한 인증(MFA), 디지털 서명, 인증서 검증",
        "Tampering": "디지털 서명, HMAC, 입력값 검증, 접근 제어",
        "Repudiation": "감사 로그(Audit Log), 타임스탬프, 디지털 서명",
        "Info Disclosure": "암호화(전송·저장), 최소 권한 원칙, 마스킹",
        "DoS": "속도 제한(Rate Limiting), 자원 할당 제한, 로드밸런싱",
        "EoP": "최소 권한 원칙, 권한 검증, 안전한 기본값",
    }
    return mitigations.get(threat, "보안 정책 적용")


if __name__ == "__main__":
    # 간단한 웹앱 예시: 로그인 시스템
    components = [
        SystemComponent("사용자 브라우저", ComponentType.EXTERNAL_ENTITY, "웹 사용자"),
        SystemComponent("인증 API", ComponentType.PROCESS, "로그인 처리", crosses_trust_boundary=True),
        SystemComponent("사용자 DB", ComponentType.DATA_STORE, "계정 정보 저장"),
        SystemComponent("HTTP 요청", ComponentType.DATA_FLOW, "브라우저 → API", crosses_trust_boundary=True),
    ]

    result = analyze_stride_threats(components)
    print(json.dumps(result, ensure_ascii=False, indent=2))
```

---

## 목차
1. [STRIDE 개요](#stride-개요)
2. [위협 유형별 상세 분석](#위협-유형별-상세-분석)
3. [DFD 작성법](#dfd-작성법)
4. [신뢰 경계 식별](#신뢰-경계-식별)
5. [STRIDE per Element 기법](#stride-per-element-기법)
6. [실전 시나리오](#실전-시나리오)
7. [STRIDE 자동화 스크립트](#stride-자동화-스크립트)

---

## STRIDE 개요

STRIDE는 Microsoft가 1999년 개발한 위협 모델링 프레임워크로, 소프트웨어 시스템에서 발생 가능한 위협을 6개 범주로 분류한다.

| 위협 유형 | 영문 | 보안 속성 침해 | 위반 원칙 |
|-----------|------|---------------|-----------|
| 스푸핑 | Spoofing | 인증(Authentication) | 신원 위조 |
| 변조 | Tampering | 무결성(Integrity) | 데이터 수정 |
| 부인 | Repudiation | 부인 방지(Non-repudiation) | 행위 부정 |
| 정보 노출 | Information Disclosure | 기밀성(Confidentiality) | 무단 접근 |
| 서비스 거부 | Denial of Service | 가용성(Availability) | 서비스 중단 |
| 권한 상승 | Elevation of Privilege | 인가(Authorization) | 권한 초과 |

### STRIDE 프로세스

```
1. 시스템 분해 (Decompose the System)
   ↓
2. 위협 식별 (Identify Threats)
   ↓
3. 위협 등급화 (Rate the Threats)
   ↓
4. 완화 방안 도출 (Mitigate Threats)
   ↓
5. 완화 검증 (Validate Mitigations)
```

---

## 위협 유형별 상세 분析

### S - Spoofing (스푸핑)

공격자가 다른 사용자, 시스템, 서비스로 신원을 위조하는 행위.

**웹 애플리케이션 예시:**
```
공격 시나리오:
- 세션 토큰 탈취 후 피해자로 위장
- JWT 서명 알고리즘 혼동 공격 (alg:none)
- CSRF 공격으로 피해자 권한 악용
- 피싱으로 자격증명 탈취 후 로그인

예시 취약점:
POST /api/login
{
  "username": "admin",
  "token": "<탈취한_세션_토큰>"
}
```

**API 예시:**
```
OAuth2 Token Spoofing:
- Access Token 재사용 (replay attack)
- Client ID/Secret 노출 후 타 클라이언트로 위장
- API Key 탈취 (Git 히스토리, 로그 파일)

마이크로서비스 예시:
- Service-to-Service 통신에서 mTLS 미적용
- 내부 서비스 IP 위조
- DNS 스푸핑으로 서비스 요청 가로채기
```

**완화 방안:**
- 강력한 인증 메커니즘 (MFA, FIDO2)
- 세션 관리 강화 (HttpOnly, Secure, SameSite 쿠키)
- mTLS로 서비스 간 인증
- JWT 서명 알고리즘 명시적 검증

---

### T - Tampering (변조)

데이터, 코드, 설정을 무단으로 수정하는 행위.

**웹 애플리케이션 예시:**
```
파라미터 변조:
GET /api/order?price=0.01&quantity=100
→ price 파라미터를 1원으로 변조

Hidden Field 변조:
<input type="hidden" name="discount" value="0">
→ 브라우저 개발자 도구로 discount=100 변조

SQL Injection을 통한 DB 변조:
UPDATE users SET role='admin' WHERE id=1--
```

**파일 시스템 변조:**
```bash
# Path Traversal을 통한 설정 파일 변조
GET /download?file=../../../../etc/passwd

# 업로드된 파일을 통한 웹쉘 삽입
POST /upload
Content-Disposition: form-data; name="file"; filename="shell.php"
<?php system($_GET['cmd']); ?>
```

**완화 방안:**
- 서버 측 입력 검증 (절대 클라이언트 측만 의존 금지)
- 파일 무결성 모니터링 (AIDE, Tripwire)
- 디지털 서명으로 코드/설정 무결성 보장
- WAF 배포

---

### R - Repudiation (부인)

공격자가 자신의 행위를 부정하거나, 정당한 사용자가 수행한 행위를 시스템이 증명하지 못하는 상황.

**시나리오:**
```
금융 거래 부인:
- "나는 그 이체를 요청한 적 없다"
- 로그가 없거나 변조 가능한 경우 입증 불가

관리자 행위 부인:
- 데이터 삭제 후 "실수가 아니라 의도적 공격"
- 감사 로그 미비로 내부자 행위 추적 불가
```

**완화 방안:**
```
감사 로그 요구사항:
- 누가(Who): 사용자 ID, IP 주소
- 언제(When): 타임스탬프 (UTC, 변조 방지)
- 무엇을(What): 수행한 작업 상세
- 결과(Result): 성공/실패

구현:
- 불변 로그 저장소 (WORM 스토리지)
- 로그 서명 (HMAC 또는 디지털 서명)
- 분산 로그 수집 (ELK, Splunk)
- 중요 거래에 디지털 서명 요구
```

---

### I - Information Disclosure (정보 노출)

권한 없는 주체에게 민감한 정보가 노출되는 상황.

**웹 애플리케이션 예시:**
```
에러 메시지 정보 노출:
- 스택 트레이스 노출: "java.sql.SQLException at com.example..."
- DB 쿼리 노출: "ERROR: relation 'users' doesn't exist"
- 내부 경로 노출: "/var/www/html/config/database.php"

디렉토리 리스팅:
http://example.com/backup/ → 파일 목록 노출

민감 파일 노출:
/.git/ → 소스코드 노출
/.env → 환경변수 노출
/backup.sql → DB 덤프 노출
```

**API 과다 정보 노출:**
```json
// 취약한 응답 - 불필요한 내부 정보 포함
{
  "id": 1,
  "username": "alice",
  "password_hash": "$2b$12$...",
  "internal_role_id": 3,
  "created_by_admin": "bob@company.com"
}

// 안전한 응답 - 필요 정보만 반환
{
  "id": 1,
  "username": "alice"
}
```

**완화 방안:**
- 제네릭 에러 메시지 사용
- API 응답 최소화 (필드 필터링)
- 민감 파일 웹 루트 외부 배치
- TLS 전송 암호화
- 미사용 엔드포인트 비활성화

---

### D - Denial of Service (서비스 거부)

서비스를 정상 사용자가 이용하지 못하게 만드는 공격.

**유형별 분류:**
```
볼류메트릭 공격:
- UDP/ICMP Flood
- DNS Amplification
- NTP Amplification

프로토콜 공격:
- SYN Flood
- Slowloris (느린 HTTP 요청)
- SSL/TLS 핸드셰이크 공격

애플리케이션 레이어:
- HTTP Flood (GET/POST)
- 복잡한 쿼리 공격 (GraphQL, ReDoS)
- 자원 소진 (파일 업로드, 대용량 요청)
```

**ReDoS 취약점 예시:**
```python
import re

# 취약한 정규표현식 (지수적 백트래킹)
pattern = r'^(a+)+$'
# 입력: "aaaaaaaaaaaaaaab" → CPU 100% 점유

# 완화: 타임아웃 적용
import signal

def regex_with_timeout(pattern, text, timeout=1):
    def handler(signum, frame):
        raise TimeoutError("Regex timeout")
    signal.signal(signal.SIGALRM, handler)
    signal.alarm(timeout)
    try:
        return re.match(pattern, text)
    finally:
        signal.alarm(0)
```

**완화 방안:**
- Rate Limiting (API, 로그인)
- CAPTCHA
- CDN/DDoS 방어 서비스
- 자원 제한 (요청 크기, 쿼리 복잡도)
- 자동 스케일링

---

### E - Elevation of Privilege (권한 상승)

낮은 권한을 가진 주체가 더 높은 권한을 획득하는 행위.

**수직 권한 상승:**
```
일반 사용자 → 관리자
IDOR 공격:
GET /api/admin/users → 일반 사용자가 관리자 API 접근

JWT 조작:
{
  "sub": "user123",
  "role": "user"  →  "role": "admin"
}
```

**수평 권한 상승:**
```
A 사용자 → B 사용자 데이터 접근
GET /api/users/456/profile  (본인은 ID 123)

파라미터 변조:
POST /transfer
{"from_account": "456", "to_account": "攻击者계좌"}
```

**마이크로서비스 권한 상승:**
```
컨테이너 탈출 → 호스트 접근:
docker run --privileged ...
→ 컨테이너 내부에서 호스트 파일시스템 마운트

SSRF를 통한 내부 서비스 접근:
POST /api/fetch
{"url": "http://169.254.169.254/latest/meta-data/"}
→ AWS 메타데이터로 IAM 자격증명 획득
```

**완화 방안:**
- 최소 권한 원칙 (PoLP)
- 모든 API에 인가 검사
- 서버 측 권한 검증 (클라이언트 데이터 신뢰 금지)
- 권한 분리 (Separation of Duties)

---

## DFD 작성법

### DFD 구성 요소

```
기호 설명:
┌─────────┐
│ Process │  → 원/타원: 프로세스 (데이터 변환)
└─────────┘

┌═════════╗
║External ║  → 직사각형: 외부 엔티티 (사람/시스템)
║ Entity  ║
╚═════════╝

═══════════  → 평행선: 데이터 저장소
 Data Store
═══════════

────────→    → 화살표: 데이터 흐름
```

### Level 0 DFD (Context Diagram) 예시

```
                    ┌─────────────────────────────────┐
                    │         신뢰 경계                │
  [고객]  ──────→  │  [웹 서버]  ──────→  [DB 서버]  │
          ←──────  │             ←──────              │
                    │                ║Users║           │
                    │                ║Orders║          │
                    └─────────────────────────────────┘
                              ↕
                         [결제 게이트웨이]
                         (외부 신뢰 경계)
```

### Level 1 DFD (상세 분해) 예시

```
[브라우저]
    │ HTTPS 요청
    ↓
[Load Balancer]
    │ HTTP 포워딩
    ↓
[웹 애플리케이션 서버]──────────────[세션 스토어(Redis)]
    │ SQL 쿼리                              │
    ↓                                       │
[데이터베이스]                         [캐시 레이어]
    │
    ↓
[백업 스토리지]

신뢰 경계 표시:
- 인터넷 ↔ DMZ
- DMZ ↔ 내부 네트워크
- 내부 네트워크 ↔ DB 서버
```

### DFD 작성 절차

```
1단계: 시스템 경계 정의
   - 분석 범위 결정
   - 외부 엔티티 식별

2단계: 프로세스 식별
   - 데이터를 변환/처리하는 모든 컴포넌트
   - 각 프로세스에 번호 부여

3단계: 데이터 흐름 매핑
   - 모든 데이터 이동 경로 표시
   - 데이터 형식 및 프로토콜 명시

4단계: 데이터 저장소 식별
   - DB, 파일, 캐시, 쿠키

5단계: 신뢰 경계 표시
   - 신뢰 수준이 변경되는 모든 지점
```

---

## 신뢰 경계 식별

### 신뢰 경계란?

신뢰 경계(Trust Boundary)는 데이터나 제어가 서로 다른 신뢰 수준의 컨텍스트 간에 이동하는 지점이다. 이 경계를 넘는 모든 데이터는 잠재적 위협 벡터다.

### 일반적인 신뢰 경계 유형

```
네트워크 기반:
┌──────────────────────────────────────────┐
│  인터넷 (신뢰도 0)                        │
│  ┌────────────────────────────────────┐  │
│  │  DMZ (신뢰도 1)                    │  │
│  │  ┌──────────────────────────────┐  │  │
│  │  │  내부 네트워크 (신뢰도 2)    │  │  │
│  │  │  ┌────────────────────────┐  │  │  │
│  │  │  │  DB 서버 (신뢰도 3)   │  │  │  │
│  │  │  └────────────────────────┘  │  │  │
│  │  └──────────────────────────────┘  │  │
│  └────────────────────────────────────┘  │
└──────────────────────────────────────────┘

프로세스 기반:
- 사용자 공간 ↔ 커널 공간
- 비권한 프로세스 ↔ 권한 프로세스
- 컨테이너 ↔ 호스트

데이터 기반:
- 인증된 세션 ↔ 미인증 세션
- 암호화 채널 ↔ 평문 채널
```

### 경계에서 검증해야 할 항목

```
입력 검증:
□ 데이터 유형 검증
□ 길이/범위 검증
□ 형식 검증 (화이트리스트)
□ 인코딩/이스케이핑 적용

인증/인가:
□ 자격증명 검증
□ 세션 유효성 확인
□ 권한 확인
□ CSRF 토큰 검증

암호화:
□ 전송 중 암호화 (TLS)
□ 저장 시 암호화
□ 키 관리
```

---

## STRIDE per Element 기법

각 DFD 요소(Element)에 STRIDE를 체계적으로 적용하는 방법.

### 요소별 적용 가능한 위협

```
프로세스 (Process):
┌─────────────────────────────────────┐
│  S - 프로세스 신원 위조              │
│  T - 프로세스가 처리하는 데이터 변조 │
│  R - 수행 작업 부인                  │
│  I - 처리 중 정보 노출               │
│  D - 프로세스 중단/과부하            │
│  E - 상위 권한으로 실행              │
└─────────────────────────────────────┘

데이터 흐름 (Data Flow):
┌─────────────────────────────────────┐
│  T - 전송 중 데이터 변조             │
│  I - 전송 중 도청                    │
│  D - 데이터 흐름 차단                │
└─────────────────────────────────────┘

데이터 저장소 (Data Store):
┌─────────────────────────────────────┐
│  T - 저장된 데이터 변조              │
│  R - 저장소 접근 기록 부재           │
│  I - 저장된 데이터 노출              │
│  D - 저장소 접근 불가                │
└─────────────────────────────────────┘

외부 엔티티 (External Entity):
┌─────────────────────────────────────┐
│  S - 외부 엔티티 신원 위조           │
│  R - 외부 엔티티의 행위 부인         │
└─────────────────────────────────────┘
```

### 분석 매트릭스 예시 (REST API 서버)

```
컴포넌트: /api/v1/auth/login 엔드포인트

┌──────┬──────────────────────────────┬──────────────────────────┐
│위협  │ 시나리오                      │ 완화 방안                │
├──────┼──────────────────────────────┼──────────────────────────┤
│  S   │ 탈취한 자격증명으로 로그인    │ MFA, 비정상 로그인 탐지  │
│  T   │ 전송 중 비밀번호 변조         │ TLS 1.3 필수             │
│  R   │ 로그인 시도 로그 미보관       │ 감사 로그 + SIEM         │
│  I   │ 에러 메시지에 계정 존재 노출  │ 제네릭 에러 응답         │
│  D   │ 브루트포스로 계정 잠금        │ Rate Limit, CAPTCHA      │
│  E   │ SQL Injection으로 관리자 획득 │ 파라미터화 쿼리, ORM     │
└──────┴──────────────────────────────┴──────────────────────────┘
```

---

## 실전 시나리오

### 시나리오 1: 전자상거래 API

```
구성요소:
- 클라이언트 (모바일/웹)
- API Gateway
- 인증 서비스
- 주문 서비스
- 결제 서비스
- 상품 서비스
- PostgreSQL DB
- Redis Cache
- S3 파일 저장소

신뢰 경계:
B1: 인터넷 ↔ API Gateway
B2: API Gateway ↔ 내부 서비스
B3: 서비스 ↔ 데이터베이스

STRIDE 분석 (주문 서비스):
S: 다른 사용자의 주문 조회/수정 (IDOR)
T: 주문 금액 변조, 수량 변조
R: 주문 생성/취소 이력 미기록
I: 결제 정보, 배송지 정보 노출
D: 대량 주문 생성으로 서비스 과부하
E: 쿠폰 시스템 우회로 무한 할인
```

### 시나리오 2: Kubernetes 마이크로서비스

```
구성요소:
- Ingress Controller
- API Pod
- Auth Pod
- DB StatefulSet
- ConfigMap/Secret
- Service Account

STRIDE 분석:
S: 서비스 어카운트 토큰 탈취로 K8s API 위장
T: ConfigMap 변조로 서비스 설정 변경
R: Pod 로그 미수집으로 행위 추적 불가
I: Secret 평문 저장 (base64 ≠ 암호화)
D: 리소스 제한(limits) 미설정으로 OOM
E: privileged 컨테이너로 노드 탈출
```

---

## STRIDE 자동화 스크립트

```python
#!/usr/bin/env python3
"""
STRIDE 위협 모델링 자동화 도구

사용법:
    python3 stride_analyzer.py --system ecommerce --output report.json
    python3 stride_analyzer.py --system kubernetes --format html --output report.html
    python3 stride_analyzer.py --interactive
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional


class StrideCategory(str, Enum):
    SPOOFING = "S"
    TAMPERING = "T"
    REPUDIATION = "R"
    INFORMATION_DISCLOSURE = "I"
    DENIAL_OF_SERVICE = "D"
    ELEVATION_OF_PRIVILEGE = "E"

    @property
    def full_name(self) -> str:
        names = {
            "S": "Spoofing (스푸핑)",
            "T": "Tampering (변조)",
            "R": "Repudiation (부인)",
            "I": "Information Disclosure (정보 노출)",
            "D": "Denial of Service (서비스 거부)",
            "E": "Elevation of Privilege (권한 상승)",
        }
        return names[self.value]

    @property
    def violated_property(self) -> str:
        props = {
            "S": "인증 (Authentication)",
            "T": "무결성 (Integrity)",
            "R": "부인 방지 (Non-repudiation)",
            "I": "기밀성 (Confidentiality)",
            "D": "가용성 (Availability)",
            "E": "인가 (Authorization)",
        }
        return props[self.value]


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class ElementType(str, Enum):
    PROCESS = "Process"
    DATA_FLOW = "DataFlow"
    DATA_STORE = "DataStore"
    EXTERNAL_ENTITY = "ExternalEntity"


@dataclass
class TrustBoundary:
    id: str
    name: str
    description: str
    from_zone: str
    to_zone: str


@dataclass
class DFDElement:
    id: str
    name: str
    element_type: ElementType
    description: str
    trust_boundary: Optional[str] = None
    technologies: list[str] = field(default_factory=list)


@dataclass
class Threat:
    id: str
    stride_category: StrideCategory
    title: str
    description: str
    affected_element: str
    attack_scenario: str
    impact: str
    severity: Severity
    likelihood: str
    mitigation: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    status: str = "Open"

    def to_dict(self) -> dict:
        d = asdict(self)
        d["stride_category"] = self.stride_category.value
        d["stride_full_name"] = self.stride_category.full_name
        d["violated_property"] = self.stride_category.violated_property
        d["element_type_label"] = self.severity.value
        return d


@dataclass
class ThreatModel:
    name: str
    description: str
    version: str
    created_at: str
    elements: list[DFDElement] = field(default_factory=list)
    trust_boundaries: list[TrustBoundary] = field(default_factory=list)
    threats: list[Threat] = field(default_factory=list)

    def add_element(self, element: DFDElement) -> None:
        self.elements.append(element)

    def add_trust_boundary(self, boundary: TrustBoundary) -> None:
        self.trust_boundaries.append(boundary)

    def add_threat(self, threat: Threat) -> None:
        self.threats.append(threat)

    def get_threats_by_severity(self) -> dict[str, list[Threat]]:
        result: dict[str, list[Threat]] = {s.value: [] for s in Severity}
        for threat in self.threats:
            result[threat.severity.value].append(threat)
        return result

    def get_threats_by_category(self) -> dict[str, list[Threat]]:
        result: dict[str, list[Threat]] = {c.value: [] for c in StrideCategory}
        for threat in self.threats:
            result[threat.stride_category.value].append(threat)
        return result

    def get_summary(self) -> dict:
        by_severity = self.get_threats_by_severity()
        by_category = self.get_threats_by_category()
        return {
            "total_threats": len(self.threats),
            "by_severity": {k: len(v) for k, v in by_severity.items()},
            "by_category": {k: len(v) for k, v in by_category.items()},
            "open_threats": sum(1 for t in self.threats if t.status == "Open"),
            "mitigated_threats": sum(1 for t in self.threats if t.status == "Mitigated"),
        }


class StrideTemplateLibrary:
    """STRIDE 위협 템플릿 라이브러리"""

    ELEMENT_THREAT_MAP: dict[ElementType, list[StrideCategory]] = {
        ElementType.PROCESS: [
            StrideCategory.SPOOFING,
            StrideCategory.TAMPERING,
            StrideCategory.REPUDIATION,
            StrideCategory.INFORMATION_DISCLOSURE,
            StrideCategory.DENIAL_OF_SERVICE,
            StrideCategory.ELEVATION_OF_PRIVILEGE,
        ],
        ElementType.DATA_FLOW: [
            StrideCategory.TAMPERING,
            StrideCategory.INFORMATION_DISCLOSURE,
            StrideCategory.DENIAL_OF_SERVICE,
        ],
        ElementType.DATA_STORE: [
            StrideCategory.TAMPERING,
            StrideCategory.REPUDIATION,
            StrideCategory.INFORMATION_DISCLOSURE,
            StrideCategory.DENIAL_OF_SERVICE,
        ],
        ElementType.EXTERNAL_ENTITY: [
            StrideCategory.SPOOFING,
            StrideCategory.REPUDIATION,
        ],
    }

    @staticmethod
    def get_threat_templates(
        element: DFDElement,
    ) -> list[dict]:
        """요소 유형에 따른 위협 템플릿 반환"""
        categories = StrideTemplateLibrary.ELEMENT_THREAT_MAP.get(
            element.element_type, []
        )
        templates = []

        for category in categories:
            template = StrideTemplateLibrary._build_template(element, category)
            templates.append(template)

        return templates

    @staticmethod
    def _build_template(element: DFDElement, category: StrideCategory) -> dict:
        title_map = {
            StrideCategory.SPOOFING: f"{element.name} 신원 위조",
            StrideCategory.TAMPERING: f"{element.name} 데이터 변조",
            StrideCategory.REPUDIATION: f"{element.name} 행위 부인",
            StrideCategory.INFORMATION_DISCLOSURE: f"{element.name} 정보 노출",
            StrideCategory.DENIAL_OF_SERVICE: f"{element.name} 서비스 거부",
            StrideCategory.ELEVATION_OF_PRIVILEGE: f"{element.name} 권한 상승",
        }

        scenario_map = {
            StrideCategory.SPOOFING: f"공격자가 {element.name}의 신원을 위조하여 시스템에 접근",
            StrideCategory.TAMPERING: f"공격자가 {element.name}의 데이터를 무단 수정",
            StrideCategory.REPUDIATION: f"{element.name}에서 발생한 작업에 대한 감사 로그 미비",
            StrideCategory.INFORMATION_DISCLOSURE: f"공격자가 {element.name}의 민감 정보에 접근",
            StrideCategory.DENIAL_OF_SERVICE: f"공격자가 {element.name}을 과부하시켜 서비스 중단",
            StrideCategory.ELEVATION_OF_PRIVILEGE: f"공격자가 {element.name}을 통해 상위 권한 획득",
        }

        mitigation_map = {
            StrideCategory.SPOOFING: [
                "강력한 인증 메커니즘 적용 (MFA)",
                "세션 관리 강화",
                "mTLS 서비스 간 인증",
            ],
            StrideCategory.TAMPERING: [
                "입력값 검증 및 무결성 검사",
                "디지털 서명 적용",
                "WAF 배포",
            ],
            StrideCategory.REPUDIATION: [
                "불변 감사 로그 구현",
                "중요 작업에 디지털 서명",
                "SIEM 연동",
            ],
            StrideCategory.INFORMATION_DISCLOSURE: [
                "최소 권한 원칙 적용",
                "데이터 암호화 (전송/저장)",
                "API 응답 최소화",
            ],
            StrideCategory.DENIAL_OF_SERVICE: [
                "Rate Limiting 적용",
                "자원 제한 설정",
                "CDN/DDoS 방어 서비스 사용",
            ],
            StrideCategory.ELEVATION_OF_PRIVILEGE: [
                "최소 권한 원칙 적용",
                "서버 측 인가 검증",
                "권한 분리 구현",
            ],
        }

        return {
            "stride_category": category,
            "title": title_map[category],
            "attack_scenario": scenario_map[category],
            "mitigation": mitigation_map[category],
            "severity": Severity.MEDIUM,
        }


class StrideAnalyzer:
    """STRIDE 분석 엔진"""

    def __init__(self, model: ThreatModel) -> None:
        self.model = model
        self._threat_counter = 0

    def _next_threat_id(self) -> str:
        self._threat_counter += 1
        return f"T{self._threat_counter:04d}"

    def analyze_element(self, element: DFDElement) -> list[Threat]:
        """특정 DFD 요소에 대한 STRIDE 분석 수행"""
        templates = StrideTemplateLibrary.get_threat_templates(element)
        threats = []

        for tmpl in templates:
            threat = Threat(
                id=self._next_threat_id(),
                stride_category=tmpl["stride_category"],
                title=tmpl["title"],
                description=f"{element.name} ({element.element_type.value}) 관련 {tmpl['stride_category'].full_name} 위협",
                affected_element=element.id,
                attack_scenario=tmpl["attack_scenario"],
                impact="시스템 보안 속성 침해",
                severity=tmpl["severity"],
                likelihood="Medium",
                mitigation=tmpl["mitigation"],
            )
            threats.append(threat)

        return threats

    def analyze_all(self) -> None:
        """전체 DFD 요소 자동 분석"""
        for element in self.model.elements:
            threats = self.analyze_element(element)
            for threat in threats:
                self.model.add_threat(threat)

    def generate_report(self, fmt: str = "json") -> str:
        if fmt == "json":
            return self._generate_json_report()
        elif fmt == "html":
            return self._generate_html_report()
        elif fmt == "markdown":
            return self._generate_markdown_report()
        else:
            raise ValueError(f"지원하지 않는 형식: {fmt}")

    def _generate_json_report(self) -> str:
        summary = self.model.get_summary()
        report = {
            "metadata": {
                "name": self.model.name,
                "description": self.model.description,
                "version": self.model.version,
                "generated_at": datetime.now().isoformat(),
                "created_at": self.model.created_at,
            },
            "summary": summary,
            "elements": [
                {
                    "id": e.id,
                    "name": e.name,
                    "type": e.element_type.value,
                    "description": e.description,
                    "technologies": e.technologies,
                }
                for e in self.model.elements
            ],
            "trust_boundaries": [
                {
                    "id": b.id,
                    "name": b.name,
                    "from": b.from_zone,
                    "to": b.to_zone,
                }
                for b in self.model.trust_boundaries
            ],
            "threats": [t.to_dict() for t in self.model.threats],
        }
        return json.dumps(report, ensure_ascii=False, indent=2)

    def _generate_markdown_report(self) -> str:
        summary = self.model.get_summary()
        lines = [
            f"# 위협 모델 보고서: {self.model.name}",
            f"\n생성 일시: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"\n## 개요\n\n{self.model.description}",
            "\n## 요약",
            f"\n- 총 위협 수: **{summary['total_threats']}**",
            f"- 미해결 위협: **{summary['open_threats']}**",
            f"- 완화된 위협: **{summary['mitigated_threats']}**",
            "\n### 심각도별 분포\n",
        ]

        for sev, count in summary["by_severity"].items():
            if count > 0:
                lines.append(f"- {sev}: {count}건")

        lines.append("\n### STRIDE 범주별 분포\n")
        by_cat = self.model.get_threats_by_category()
        for cat_code, threats in by_cat.items():
            if threats:
                cat_name = StrideCategory(cat_code).full_name
                lines.append(f"- {cat_name}: {len(threats)}건")

        lines.append("\n## 위협 목록\n")
        for threat in sorted(
            self.model.threats,
            key=lambda t: ["Critical", "High", "Medium", "Low", "Info"].index(
                t.severity.value
            ),
        ):
            lines.extend([
                f"### [{threat.id}] {threat.title}",
                f"\n- **범주**: {threat.stride_category.full_name}",
                f"- **심각도**: {threat.severity.value}",
                f"- **가능성**: {threat.likelihood}",
                f"- **상태**: {threat.status}",
                f"\n**공격 시나리오**: {threat.attack_scenario}",
                f"\n**영향**: {threat.impact}",
                "\n**완화 방안**:",
            ])
            for mitigation in threat.mitigation:
                lines.append(f"- {mitigation}")
            lines.append("")

        return "\n".join(lines)

    def _generate_html_report(self) -> str:
        json_data = self._generate_json_report()
        summary = self.model.get_summary()

        severity_colors = {
            "Critical": "#dc3545",
            "High": "#fd7e14",
            "Medium": "#ffc107",
            "Low": "#28a745",
            "Info": "#17a2b8",
        }

        threat_rows = []
        for t in self.model.threats:
            color = severity_colors.get(t.severity.value, "#6c757d")
            mitigations = "<br>".join(f"• {m}" for m in t.mitigation)
            threat_rows.append(
                f"<tr>"
                f"<td>{t.id}</td>"
                f"<td>{t.stride_category.full_name}</td>"
                f"<td>{t.title}</td>"
                f"<td><span style='color:{color};font-weight:bold'>{t.severity.value}</span></td>"
                f"<td>{t.attack_scenario}</td>"
                f"<td>{mitigations}</td>"
                f"<td>{t.status}</td>"
                f"</tr>"
            )

        return f"""<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<title>STRIDE 위협 모델 보고서</title>
<style>
  body {{ font-family: Arial, sans-serif; margin: 20px; }}
  h1 {{ color: #333; }}
  .summary {{ background: #f5f5f5; padding: 15px; border-radius: 5px; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
  th {{ background: #333; color: white; padding: 10px; text-align: left; }}
  td {{ padding: 8px; border-bottom: 1px solid #ddd; vertical-align: top; }}
  tr:nth-child(even) {{ background: #f9f9f9; }}
</style>
</head>
<body>
<h1>STRIDE 위협 모델 보고서: {self.model.name}</h1>
<div class="summary">
  <h2>요약</h2>
  <p>총 위협: <strong>{summary['total_threats']}</strong> |
     미해결: <strong>{summary['open_threats']}</strong> |
     완화됨: <strong>{summary['mitigated_threats']}</strong></p>
</div>
<table>
<tr>
  <th>ID</th><th>STRIDE</th><th>위협명</th><th>심각도</th>
  <th>공격 시나리오</th><th>완화 방안</th><th>상태</th>
</tr>
{''.join(threat_rows)}
</table>
</body>
</html>"""


def build_ecommerce_model() -> ThreatModel:
    """전자상거래 시스템 위협 모델 구성"""
    model = ThreatModel(
        name="전자상거래 플랫폼",
        description="REST API 기반 전자상거래 시스템 STRIDE 위협 모델",
        version="1.0",
        created_at=datetime.now().isoformat(),
    )

    # 신뢰 경계 추가
    model.add_trust_boundary(TrustBoundary(
        id="TB001", name="인터넷-DMZ 경계",
        description="외부 인터넷과 DMZ 간 경계",
        from_zone="인터넷", to_zone="DMZ",
    ))
    model.add_trust_boundary(TrustBoundary(
        id="TB002", name="DMZ-내부 경계",
        description="DMZ와 내부 네트워크 간 경계",
        from_zone="DMZ", to_zone="내부 네트워크",
    ))

    # DFD 요소 추가
    elements = [
        DFDElement("E001", "웹 브라우저", ElementType.EXTERNAL_ENTITY,
                   "최종 사용자 웹 브라우저", trust_boundary="TB001"),
        DFDElement("P001", "API Gateway", ElementType.PROCESS,
                   "요청 라우팅 및 인증 처리", technologies=["Nginx", "Kong"]),
        DFDElement("P002", "인증 서비스", ElementType.PROCESS,
                   "사용자 인증/인가 처리", technologies=["JWT", "OAuth2"]),
        DFDElement("P003", "주문 서비스", ElementType.PROCESS,
                   "주문 생성/조회/취소 처리", technologies=["Python", "FastAPI"]),
        DFDElement("P004", "결제 서비스", ElementType.PROCESS,
                   "결제 처리 및 결제 게이트웨이 연동", technologies=["Python"]),
        DFDElement("DS001", "사용자 DB", ElementType.DATA_STORE,
                   "사용자 계정 및 프로필 저장", technologies=["PostgreSQL"]),
        DFDElement("DS002", "주문 DB", ElementType.DATA_STORE,
                   "주문 데이터 저장", technologies=["PostgreSQL"]),
        DFDElement("DS003", "세션 캐시", ElementType.DATA_STORE,
                   "사용자 세션 토큰 저장", technologies=["Redis"]),
        DFDElement("DF001", "HTTPS 요청", ElementType.DATA_FLOW,
                   "클라이언트-서버 간 HTTPS 통신"),
        DFDElement("DF002", "내부 API 호출", ElementType.DATA_FLOW,
                   "마이크로서비스 간 HTTP 통신"),
        DFDElement("E002", "결제 게이트웨이", ElementType.EXTERNAL_ENTITY,
                   "외부 결제 처리 서비스", trust_boundary="TB001"),
    ]

    for element in elements:
        model.add_element(element)

    return model


def build_kubernetes_model() -> ThreatModel:
    """Kubernetes 클러스터 위협 모델 구성"""
    model = ThreatModel(
        name="Kubernetes 클러스터",
        description="멀티테넌트 Kubernetes 클러스터 STRIDE 위협 모델",
        version="1.0",
        created_at=datetime.now().isoformat(),
    )

    model.add_trust_boundary(TrustBoundary(
        id="TB001", name="인터넷-클러스터 경계",
        description="외부 트래픽 진입점",
        from_zone="인터넷", to_zone="클러스터",
    ))
    model.add_trust_boundary(TrustBoundary(
        id="TB002", name="네임스페이스 경계",
        description="테넌트 간 격리 경계",
        from_zone="테넌트 A", to_zone="테넌트 B",
    ))

    elements = [
        DFDElement("E001", "개발자", ElementType.EXTERNAL_ENTITY,
                   "kubectl 사용 개발자"),
        DFDElement("P001", "kube-apiserver", ElementType.PROCESS,
                   "Kubernetes API 서버", technologies=["Go", "RBAC"]),
        DFDElement("P002", "kubelet", ElementType.PROCESS,
                   "노드 에이전트", technologies=["Go"]),
        DFDElement("P003", "애플리케이션 Pod", ElementType.PROCESS,
                   "워크로드 컨테이너", technologies=["Docker", "containerd"]),
        DFDElement("DS001", "etcd", ElementType.DATA_STORE,
                   "클러스터 상태 저장소", technologies=["etcd"]),
        DFDElement("DS002", "Secret", ElementType.DATA_STORE,
                   "K8s Secret 오브젝트", technologies=["Kubernetes"]),
        DFDElement("DF001", "API 통신", ElementType.DATA_FLOW,
                   "kubectl ↔ kube-apiserver TLS 통신"),
    ]

    for element in elements:
        model.add_element(element)

    return model


def interactive_mode() -> ThreatModel:
    """대화형 위협 모델 구성"""
    print("\n=== STRIDE 위협 모델링 대화형 모드 ===\n")

    name = input("시스템 이름: ").strip() or "미명명 시스템"
    description = input("시스템 설명: ").strip() or ""

    model = ThreatModel(
        name=name,
        description=description,
        version="1.0",
        created_at=datetime.now().isoformat(),
    )

    print("\n--- DFD 요소 추가 (빈 줄로 종료) ---")
    element_count = 0
    type_map = {
        "1": ElementType.PROCESS,
        "2": ElementType.DATA_FLOW,
        "3": ElementType.DATA_STORE,
        "4": ElementType.EXTERNAL_ENTITY,
    }

    while True:
        print(f"\n요소 {element_count + 1}:")
        elem_name = input("  이름 (빈 줄로 종료): ").strip()
        if not elem_name:
            break

        print("  유형: 1=Process, 2=DataFlow, 3=DataStore, 4=ExternalEntity")
        type_choice = input("  선택: ").strip()
        elem_type = type_map.get(type_choice, ElementType.PROCESS)

        elem_desc = input("  설명: ").strip()
        element_count += 1

        element = DFDElement(
            id=f"E{element_count:03d}",
            name=elem_name,
            element_type=elem_type,
            description=elem_desc,
        )
        model.add_element(element)
        print(f"  추가됨: {elem_name} ({elem_type.value})")

    return model


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="STRIDE 위협 모델링 자동화 도구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
예시:
  %(prog)s --system ecommerce --output report.json
  %(prog)s --system kubernetes --format html --output k8s_threats.html
  %(prog)s --system ecommerce --format markdown --output threats.md
  %(prog)s --interactive --format json --output custom.json
        """,
    )
    parser.add_argument(
        "--system",
        choices=["ecommerce", "kubernetes"],
        help="분석할 사전 정의된 시스템 선택",
    )
    parser.add_argument(
        "--interactive",
        action="store_true",
        help="대화형 모드로 시스템 정의",
    )
    parser.add_argument(
        "--format",
        choices=["json", "html", "markdown"],
        default="json",
        help="출력 형식 (기본값: json)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("stride_report.json"),
        help="출력 파일 경로",
    )
    parser.add_argument(
        "--summary-only",
        action="store_true",
        help="요약 정보만 출력",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if not args.system and not args.interactive:
        print("오류: --system 또는 --interactive 옵션 중 하나를 지정하세요.", file=sys.stderr)
        return 1

    # 모델 구성
    if args.interactive:
        model = interactive_mode()
    elif args.system == "ecommerce":
        model = build_ecommerce_model()
    elif args.system == "kubernetes":
        model = build_kubernetes_model()
    else:
        print(f"알 수 없는 시스템: {args.system}", file=sys.stderr)
        return 1

    # 분석 실행
    analyzer = StrideAnalyzer(model)
    analyzer.analyze_all()

    # 요약 출력
    summary = model.get_summary()
    print(f"\n[{model.name}] STRIDE 분석 완료")
    print(f"  요소 수: {len(model.elements)}")
    print(f"  총 위협 수: {summary['total_threats']}")
    print(f"  Critical: {summary['by_severity']['Critical']}")
    print(f"  High: {summary['by_severity']['High']}")
    print(f"  Medium: {summary['by_severity']['Medium']}")

    if args.summary_only:
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        return 0

    # 보고서 생성
    try:
        report = analyzer.generate_report(fmt=args.format)
        args.output.write_text(report, encoding="utf-8")
        print(f"\n보고서 저장 완료: {args.output}")
    except (OSError, ValueError) as e:
        print(f"보고서 생성 실패: {e}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
```

### 실행 방법

```bash
# 전자상거래 시스템 JSON 보고서
python3 stride_analyzer.py --system ecommerce --output ecom_threats.json

# Kubernetes HTML 보고서
python3 stride_analyzer.py --system kubernetes --format html --output k8s.html

# Markdown 보고서
python3 stride_analyzer.py --system ecommerce --format markdown --output threats.md

# 요약만 출력
python3 stride_analyzer.py --system kubernetes --summary-only

# 대화형 모드
python3 stride_analyzer.py --interactive --format json --output custom.json
```

### 샘플 JSON 출력

```json
{
  "metadata": {
    "name": "전자상거래 플랫폼",
    "version": "1.0",
    "generated_at": "2025-01-15T10:00:00"
  },
  "summary": {
    "total_threats": 42,
    "by_severity": {
      "Critical": 0,
      "High": 0,
      "Medium": 42,
      "Low": 0
    },
    "open_threats": 42
  },
  "threats": [
    {
      "id": "T0001",
      "stride_category": "S",
      "stride_full_name": "Spoofing (스푸핑)",
      "title": "웹 브라우저 신원 위조",
      "severity": "Medium",
      "status": "Open"
    }
  ]
}
```

---

## 참고 자료

- [Microsoft STRIDE 위협 모델링](https://docs.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats)
- [OWASP 위협 모델링 치트 시트](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html)
- [Shostack, A. (2014). Threat Modeling: Designing for Security]
- [NIST SP 800-154: Guide to Data-Centric System Threat Modeling]

---

<a name="english"></a>

# STRIDE Threat Modeling Methodology

## Table of Contents
1. [STRIDE Overview](#stride-overview)
2. [Detailed Analysis by Threat Type](#detailed-analysis-by-threat-type)
3. [How to Create DFDs](#how-to-create-dfds)
4. [Trust Boundary Identification](#trust-boundary-identification)
5. [STRIDE per Element Technique](#stride-per-element-technique)
6. [Real-World Scenarios](#real-world-scenarios)
7. [STRIDE Automation Script](#stride-automation-script)

---

## STRIDE Overview

STRIDE is a threat modeling framework developed by Microsoft in 1999 that classifies threats in software systems into six categories.

| Threat Type | Full Name | Security Property Violated | Violated Principle |
|-------------|-----------|---------------------------|-------------------|
| Spoofing | Spoofing | Authentication | Identity forgery |
| Tampering | Tampering | Integrity | Data modification |
| Repudiation | Repudiation | Non-repudiation | Denial of action |
| Information Disclosure | Information Disclosure | Confidentiality | Unauthorized access |
| Denial of Service | Denial of Service | Availability | Service disruption |
| Elevation of Privilege | Elevation of Privilege | Authorization | Privilege escalation |

### STRIDE Process

```
1. Decompose the System
   ↓
2. Identify Threats
   ↓
3. Rate the Threats
   ↓
4. Mitigate Threats
   ↓
5. Validate Mitigations
```

---

## Detailed Analysis by Threat Type

### S - Spoofing

An attacker impersonates another user, system, or service to forge their identity.

**Web Application Examples:**
```
Attack scenarios:
- Steal session token and impersonate victim
- JWT signature algorithm confusion attack (alg:none)
- Exploit victim's permissions via CSRF attack
- Steal credentials via phishing and log in

Example vulnerability:
POST /api/login
{
  "username": "admin",
  "token": "<stolen_session_token>"
}
```

**API Examples:**
```
OAuth2 Token Spoofing:
- Reuse Access Token (replay attack)
- Expose Client ID/Secret to impersonate another client
- Steal API Key (Git history, log files)

Microservice examples:
- mTLS not applied in Service-to-Service communication
- Forge internal service IP
- Intercept service requests via DNS spoofing
```

**Mitigations:**
- Strong authentication mechanisms (MFA, FIDO2)
- Hardened session management (HttpOnly, Secure, SameSite cookies)
- mTLS for service-to-service authentication
- Explicit JWT signature algorithm validation

---

### T - Tampering

Unauthorized modification of data, code, or configuration.

**Web Application Examples:**
```
Parameter tampering:
GET /api/order?price=0.01&quantity=100
→ Tamper price parameter to 0.01

Hidden field tampering:
<input type="hidden" name="discount" value="0">
→ Modify discount=100 using browser developer tools

DB modification via SQL Injection:
UPDATE users SET role='admin' WHERE id=1--
```

**File System Tampering:**
```bash
# Configuration file modification via Path Traversal
GET /download?file=../../../../etc/passwd

# Web shell insertion via uploaded file
POST /upload
Content-Disposition: form-data; name="file"; filename="shell.php"
<?php system($_GET['cmd']); ?>
```

**Mitigations:**
- Server-side input validation (never rely solely on client-side)
- File integrity monitoring (AIDE, Tripwire)
- Digital signatures to guarantee code/configuration integrity
- WAF deployment

---

### R - Repudiation

An attacker denies their actions, or the system fails to prove actions performed by legitimate users.

**Scenarios:**
```
Financial transaction repudiation:
- "I never requested that transfer"
- Cannot prove it if logs are absent or tampered

Administrator action repudiation:
- After deleting data: "That was an intentional attack, not a mistake"
- Cannot track insider behavior due to insufficient audit logs
```

**Mitigations:**
```
Audit log requirements:
- Who: User ID, IP address
- When: Timestamp (UTC, tamper-proof)
- What: Details of the action performed
- Result: Success/Failure

Implementation:
- Immutable log storage (WORM storage)
- Log signing (HMAC or digital signature)
- Centralized log collection (ELK, Splunk)
- Require digital signatures for critical transactions
```

---

### I - Information Disclosure

Sensitive information is exposed to unauthorized parties.

**Web Application Examples:**
```
Error message information disclosure:
- Stack trace exposure: "java.sql.SQLException at com.example..."
- DB query exposure: "ERROR: relation 'users' doesn't exist"
- Internal path exposure: "/var/www/html/config/database.php"

Directory listing:
http://example.com/backup/ → file list exposed

Sensitive file exposure:
/.git/ → source code exposed
/.env → environment variables exposed
/backup.sql → DB dump exposed
```

**API over-exposure:**
```json
// Vulnerable response - contains unnecessary internal information
{
  "id": 1,
  "username": "alice",
  "password_hash": "$2b$12$...",
  "internal_role_id": 3,
  "created_by_admin": "bob@company.com"
}

// Safe response - returns only necessary information
{
  "id": 1,
  "username": "alice"
}
```

**Mitigations:**
- Use generic error messages
- Minimize API responses (field filtering)
- Place sensitive files outside web root
- TLS transport encryption
- Disable unused endpoints

---

### D - Denial of Service

Attacks that prevent legitimate users from using a service.

**Classification by Type:**
```
Volumetric attacks:
- UDP/ICMP Flood
- DNS Amplification
- NTP Amplification

Protocol attacks:
- SYN Flood
- Slowloris (slow HTTP requests)
- SSL/TLS handshake attacks

Application layer:
- HTTP Flood (GET/POST)
- Complex query attacks (GraphQL, ReDoS)
- Resource exhaustion (file uploads, large requests)
```

**ReDoS Vulnerability Example:**
```python
import re

# Vulnerable regular expression (exponential backtracking)
pattern = r'^(a+)+$'
# Input: "aaaaaaaaaaaaaaab" → 100% CPU usage

# Mitigation: apply timeout
import signal

def regex_with_timeout(pattern, text, timeout=1):
    def handler(signum, frame):
        raise TimeoutError("Regex timeout")
    signal.signal(signal.SIGALRM, handler)
    signal.alarm(timeout)
    try:
        return re.match(pattern, text)
    finally:
        signal.alarm(0)
```

**Mitigations:**
- Rate Limiting (API, login)
- CAPTCHA
- CDN/DDoS protection services
- Resource limits (request size, query complexity)
- Auto-scaling

---

### E - Elevation of Privilege

A low-privileged entity gains higher privileges.

**Vertical Privilege Escalation:**
```
Regular user → Administrator
IDOR attack:
GET /api/admin/users → regular user accesses admin API

JWT manipulation:
{
  "sub": "user123",
  "role": "user"  →  "role": "admin"
}
```

**Horizontal Privilege Escalation:**
```
User A → accesses User B's data
GET /api/users/456/profile  (own ID is 123)

Parameter tampering:
POST /transfer
{"from_account": "456", "to_account": "attacker_account"}
```

**Microservice Privilege Escalation:**
```
Container escape → host access:
docker run --privileged ...
→ Mount host filesystem from inside container

Internal service access via SSRF:
POST /api/fetch
{"url": "http://169.254.169.254/latest/meta-data/"}
→ Obtain IAM credentials via AWS metadata
```

**Mitigations:**
- Principle of Least Privilege (PoLP)
- Authorization checks on all APIs
- Server-side permission validation (never trust client data)
- Separation of Duties

---

## How to Create DFDs

### DFD Components

```
Symbol descriptions:
┌─────────┐
│ Process │  → Circle/oval: Process (data transformation)
└─────────┘

┌═════════╗
║External ║  → Rectangle: External Entity (person/system)
║ Entity  ║
╚═════════╝

═══════════  → Parallel lines: Data Store
 Data Store
═══════════

────────→    → Arrow: Data Flow
```

### Level 0 DFD (Context Diagram) Example

```
                    ┌─────────────────────────────────┐
                    │         Trust Boundary           │
  [Customer] ─────→│  [Web Server]  ─────→  [DB Server]│
             ←─────│               ←─────              │
                    │                ║Users║            │
                    │                ║Orders║           │
                    └─────────────────────────────────┘
                              ↕
                         [Payment Gateway]
                         (External Trust Boundary)
```

### Level 1 DFD (Detailed Decomposition) Example

```
[Browser]
    │ HTTPS Request
    ↓
[Load Balancer]
    │ HTTP Forwarding
    ↓
[Web Application Server]──────────────[Session Store (Redis)]
    │ SQL Query                               │
    ↓                                         │
[Database]                              [Cache Layer]
    │
    ↓
[Backup Storage]

Trust boundary markers:
- Internet ↔ DMZ
- DMZ ↔ Internal Network
- Internal Network ↔ DB Server
```

### DFD Creation Procedure

```
Step 1: Define system boundaries
   - Determine analysis scope
   - Identify external entities

Step 2: Identify processes
   - All components that transform/process data
   - Assign a number to each process

Step 3: Map data flows
   - Show all data movement paths
   - Specify data formats and protocols

Step 4: Identify data stores
   - DB, files, cache, cookies

Step 5: Mark trust boundaries
   - All points where the trust level changes
```

---

## Trust Boundary Identification

### What is a Trust Boundary?

A Trust Boundary is the point at which data or control moves between contexts of different trust levels. All data crossing these boundaries is a potential threat vector.

### Common Types of Trust Boundaries

```
Network-based:
┌──────────────────────────────────────────┐
│  Internet (Trust level 0)                │
│  ┌────────────────────────────────────┐  │
│  │  DMZ (Trust level 1)               │  │
│  │  ┌──────────────────────────────┐  │  │
│  │  │  Internal Network (Level 2)  │  │  │
│  │  │  ┌────────────────────────┐  │  │  │
│  │  │  │  DB Server (Level 3)   │  │  │  │
│  │  │  └────────────────────────┘  │  │  │
│  │  └──────────────────────────────┘  │  │
│  └────────────────────────────────────┘  │
└──────────────────────────────────────────┘

Process-based:
- User space ↔ Kernel space
- Unprivileged process ↔ Privileged process
- Container ↔ Host

Data-based:
- Authenticated session ↔ Unauthenticated session
- Encrypted channel ↔ Plaintext channel
```

### Items to Validate at Boundaries

```
Input validation:
□ Data type validation
□ Length/range validation
□ Format validation (whitelist)
□ Encoding/escaping applied

Authentication/Authorization:
□ Credential validation
□ Session validity check
□ Permission check
□ CSRF token validation

Encryption:
□ Encryption in transit (TLS)
□ Encryption at rest
□ Key management
```

---

## STRIDE per Element Technique

A method for systematically applying STRIDE to each DFD element.

### Applicable Threats by Element Type

```
Process:
┌─────────────────────────────────────┐
│  S - Process identity spoofing       │
│  T - Tampering with data the process │
│      handles                         │
│  R - Repudiation of actions          │
│  I - Information disclosure during   │
│      processing                      │
│  D - Process interruption/overload   │
│  E - Execution with elevated rights  │
└─────────────────────────────────────┘

Data Flow:
┌─────────────────────────────────────┐
│  T - Tampering with data in transit  │
│  I - Eavesdropping in transit        │
│  D - Data flow interruption          │
└─────────────────────────────────────┘

Data Store:
┌─────────────────────────────────────┐
│  T - Tampering with stored data      │
│  R - Absence of access records       │
│  I - Disclosure of stored data       │
│  D - Store inaccessible              │
└─────────────────────────────────────┘

External Entity:
┌─────────────────────────────────────┐
│  S - External entity identity spoof  │
│  R - Repudiation by external entity  │
└─────────────────────────────────────┘
```

### Analysis Matrix Example (REST API Server)

```
Component: /api/v1/auth/login endpoint

┌──────┬──────────────────────────────┬──────────────────────────────┐
│Threat│ Scenario                      │ Mitigation                   │
├──────┼──────────────────────────────┼──────────────────────────────┤
│  S   │ Login with stolen credentials │ MFA, anomalous login detect. │
│  T   │ Password tampering in transit │ TLS 1.3 required             │
│  R   │ Login attempts not logged     │ Audit logs + SIEM            │
│  I   │ Account existence in errors   │ Generic error responses      │
│  D   │ Brute-force account lockout   │ Rate Limit, CAPTCHA          │
│  E   │ SQL Injection to gain admin   │ Parameterized queries, ORM   │
└──────┴──────────────────────────────┴──────────────────────────────┘
```

---

## Real-World Scenarios

### Scenario 1: E-commerce API

```
Components:
- Client (mobile/web)
- API Gateway
- Authentication Service
- Order Service
- Payment Service
- Product Service
- PostgreSQL DB
- Redis Cache
- S3 File Storage

Trust Boundaries:
B1: Internet ↔ API Gateway
B2: API Gateway ↔ Internal Services
B3: Services ↔ Database

STRIDE Analysis (Order Service):
S: View/modify another user's orders (IDOR)
T: Tamper with order amount, quantity
R: Order creation/cancellation history not recorded
I: Payment information, shipping address exposed
D: Service overload by creating massive orders
E: Infinite discounts by bypassing coupon system
```

### Scenario 2: Kubernetes Microservices

```
Components:
- Ingress Controller
- API Pod
- Auth Pod
- DB StatefulSet
- ConfigMap/Secret
- Service Account

STRIDE Analysis:
S: Steal service account token to impersonate K8s API
T: Modify ConfigMap to change service configuration
R: Pod logs not collected — actions untraceable
I: Secrets stored in plaintext (base64 ≠ encryption)
D: OOM due to missing resource limits
E: Node escape via privileged container
```

---

## STRIDE Automation Script

```python
#!/usr/bin/env python3
"""
STRIDE Threat Modeling Automation Tool

Usage:
    python3 stride_analyzer.py --system ecommerce --output report.json
    python3 stride_analyzer.py --system kubernetes --format html --output report.html
    python3 stride_analyzer.py --interactive
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional


class StrideCategory(str, Enum):
    SPOOFING = "S"
    TAMPERING = "T"
    REPUDIATION = "R"
    INFORMATION_DISCLOSURE = "I"
    DENIAL_OF_SERVICE = "D"
    ELEVATION_OF_PRIVILEGE = "E"

    @property
    def full_name(self) -> str:
        names = {
            "S": "Spoofing",
            "T": "Tampering",
            "R": "Repudiation",
            "I": "Information Disclosure",
            "D": "Denial of Service",
            "E": "Elevation of Privilege",
        }
        return names[self.value]

    @property
    def violated_property(self) -> str:
        props = {
            "S": "Authentication",
            "T": "Integrity",
            "R": "Non-repudiation",
            "I": "Confidentiality",
            "D": "Availability",
            "E": "Authorization",
        }
        return props[self.value]


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class ElementType(str, Enum):
    PROCESS = "Process"
    DATA_FLOW = "DataFlow"
    DATA_STORE = "DataStore"
    EXTERNAL_ENTITY = "ExternalEntity"


@dataclass
class TrustBoundary:
    id: str
    name: str
    description: str
    from_zone: str
    to_zone: str


@dataclass
class DFDElement:
    id: str
    name: str
    element_type: ElementType
    description: str
    trust_boundary: Optional[str] = None
    technologies: list[str] = field(default_factory=list)


@dataclass
class Threat:
    id: str
    stride_category: StrideCategory
    title: str
    description: str
    affected_element: str
    attack_scenario: str
    impact: str
    severity: Severity
    likelihood: str
    mitigation: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    status: str = "Open"

    def to_dict(self) -> dict:
        d = asdict(self)
        d["stride_category"] = self.stride_category.value
        d["stride_full_name"] = self.stride_category.full_name
        d["violated_property"] = self.stride_category.violated_property
        d["element_type_label"] = self.severity.value
        return d


@dataclass
class ThreatModel:
    name: str
    description: str
    version: str
    created_at: str
    elements: list[DFDElement] = field(default_factory=list)
    trust_boundaries: list[TrustBoundary] = field(default_factory=list)
    threats: list[Threat] = field(default_factory=list)

    def add_element(self, element: DFDElement) -> None:
        self.elements.append(element)

    def add_trust_boundary(self, boundary: TrustBoundary) -> None:
        self.trust_boundaries.append(boundary)

    def add_threat(self, threat: Threat) -> None:
        self.threats.append(threat)

    def get_threats_by_severity(self) -> dict[str, list[Threat]]:
        result: dict[str, list[Threat]] = {s.value: [] for s in Severity}
        for threat in self.threats:
            result[threat.severity.value].append(threat)
        return result

    def get_threats_by_category(self) -> dict[str, list[Threat]]:
        result: dict[str, list[Threat]] = {c.value: [] for c in StrideCategory}
        for threat in self.threats:
            result[threat.stride_category.value].append(threat)
        return result

    def get_summary(self) -> dict:
        by_severity = self.get_threats_by_severity()
        by_category = self.get_threats_by_category()
        return {
            "total_threats": len(self.threats),
            "by_severity": {k: len(v) for k, v in by_severity.items()},
            "by_category": {k: len(v) for k, v in by_category.items()},
            "open_threats": sum(1 for t in self.threats if t.status == "Open"),
            "mitigated_threats": sum(1 for t in self.threats if t.status == "Mitigated"),
        }


class StrideTemplateLibrary:
    """STRIDE threat template library"""

    ELEMENT_THREAT_MAP: dict[ElementType, list[StrideCategory]] = {
        ElementType.PROCESS: [
            StrideCategory.SPOOFING,
            StrideCategory.TAMPERING,
            StrideCategory.REPUDIATION,
            StrideCategory.INFORMATION_DISCLOSURE,
            StrideCategory.DENIAL_OF_SERVICE,
            StrideCategory.ELEVATION_OF_PRIVILEGE,
        ],
        ElementType.DATA_FLOW: [
            StrideCategory.TAMPERING,
            StrideCategory.INFORMATION_DISCLOSURE,
            StrideCategory.DENIAL_OF_SERVICE,
        ],
        ElementType.DATA_STORE: [
            StrideCategory.TAMPERING,
            StrideCategory.REPUDIATION,
            StrideCategory.INFORMATION_DISCLOSURE,
            StrideCategory.DENIAL_OF_SERVICE,
        ],
        ElementType.EXTERNAL_ENTITY: [
            StrideCategory.SPOOFING,
            StrideCategory.REPUDIATION,
        ],
    }

    @staticmethod
    def get_threat_templates(
        element: DFDElement,
    ) -> list[dict]:
        """Return threat templates based on element type"""
        categories = StrideTemplateLibrary.ELEMENT_THREAT_MAP.get(
            element.element_type, []
        )
        templates = []

        for category in categories:
            template = StrideTemplateLibrary._build_template(element, category)
            templates.append(template)

        return templates

    @staticmethod
    def _build_template(element: DFDElement, category: StrideCategory) -> dict:
        title_map = {
            StrideCategory.SPOOFING: f"{element.name} Identity Spoofing",
            StrideCategory.TAMPERING: f"{element.name} Data Tampering",
            StrideCategory.REPUDIATION: f"{element.name} Action Repudiation",
            StrideCategory.INFORMATION_DISCLOSURE: f"{element.name} Information Disclosure",
            StrideCategory.DENIAL_OF_SERVICE: f"{element.name} Denial of Service",
            StrideCategory.ELEVATION_OF_PRIVILEGE: f"{element.name} Privilege Escalation",
        }

        scenario_map = {
            StrideCategory.SPOOFING: f"Attacker spoofs the identity of {element.name} to access the system",
            StrideCategory.TAMPERING: f"Attacker unauthorizedly modifies data in {element.name}",
            StrideCategory.REPUDIATION: f"Insufficient audit logs for actions performed on {element.name}",
            StrideCategory.INFORMATION_DISCLOSURE: f"Attacker accesses sensitive information from {element.name}",
            StrideCategory.DENIAL_OF_SERVICE: f"Attacker overloads {element.name} causing service disruption",
            StrideCategory.ELEVATION_OF_PRIVILEGE: f"Attacker gains elevated privileges through {element.name}",
        }

        mitigation_map = {
            StrideCategory.SPOOFING: [
                "Apply strong authentication mechanisms (MFA)",
                "Harden session management",
                "mTLS service-to-service authentication",
            ],
            StrideCategory.TAMPERING: [
                "Input validation and integrity checks",
                "Apply digital signatures",
                "WAF deployment",
            ],
            StrideCategory.REPUDIATION: [
                "Implement immutable audit logs",
                "Digital signatures for critical operations",
                "SIEM integration",
            ],
            StrideCategory.INFORMATION_DISCLOSURE: [
                "Apply principle of least privilege",
                "Data encryption (in transit/at rest)",
                "Minimize API responses",
            ],
            StrideCategory.DENIAL_OF_SERVICE: [
                "Apply Rate Limiting",
                "Set resource limits",
                "Use CDN/DDoS protection services",
            ],
            StrideCategory.ELEVATION_OF_PRIVILEGE: [
                "Apply principle of least privilege",
                "Server-side authorization validation",
                "Implement separation of duties",
            ],
        }

        return {
            "stride_category": category,
            "title": title_map[category],
            "attack_scenario": scenario_map[category],
            "mitigation": mitigation_map[category],
            "severity": Severity.MEDIUM,
        }


class StrideAnalyzer:
    """STRIDE analysis engine"""

    def __init__(self, model: ThreatModel) -> None:
        self.model = model
        self._threat_counter = 0

    def _next_threat_id(self) -> str:
        self._threat_counter += 1
        return f"T{self._threat_counter:04d}"

    def analyze_element(self, element: DFDElement) -> list[Threat]:
        """Perform STRIDE analysis on a specific DFD element"""
        templates = StrideTemplateLibrary.get_threat_templates(element)
        threats = []

        for tmpl in templates:
            threat = Threat(
                id=self._next_threat_id(),
                stride_category=tmpl["stride_category"],
                title=tmpl["title"],
                description=f"{tmpl['stride_category'].full_name} threat related to {element.name} ({element.element_type.value})",
                affected_element=element.id,
                attack_scenario=tmpl["attack_scenario"],
                impact="Violation of system security properties",
                severity=tmpl["severity"],
                likelihood="Medium",
                mitigation=tmpl["mitigation"],
            )
            threats.append(threat)

        return threats

    def analyze_all(self) -> None:
        """Automated analysis of all DFD elements"""
        for element in self.model.elements:
            threats = self.analyze_element(element)
            for threat in threats:
                self.model.add_threat(threat)

    def generate_report(self, fmt: str = "json") -> str:
        if fmt == "json":
            return self._generate_json_report()
        elif fmt == "html":
            return self._generate_html_report()
        elif fmt == "markdown":
            return self._generate_markdown_report()
        else:
            raise ValueError(f"Unsupported format: {fmt}")

    def _generate_json_report(self) -> str:
        summary = self.model.get_summary()
        report = {
            "metadata": {
                "name": self.model.name,
                "description": self.model.description,
                "version": self.model.version,
                "generated_at": datetime.now().isoformat(),
                "created_at": self.model.created_at,
            },
            "summary": summary,
            "elements": [
                {
                    "id": e.id,
                    "name": e.name,
                    "type": e.element_type.value,
                    "description": e.description,
                    "technologies": e.technologies,
                }
                for e in self.model.elements
            ],
            "trust_boundaries": [
                {
                    "id": b.id,
                    "name": b.name,
                    "from": b.from_zone,
                    "to": b.to_zone,
                }
                for b in self.model.trust_boundaries
            ],
            "threats": [t.to_dict() for t in self.model.threats],
        }
        return json.dumps(report, ensure_ascii=False, indent=2)

    def _generate_markdown_report(self) -> str:
        summary = self.model.get_summary()
        lines = [
            f"# Threat Model Report: {self.model.name}",
            f"\nGenerated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"\n## Overview\n\n{self.model.description}",
            "\n## Summary",
            f"\n- Total threats: **{summary['total_threats']}**",
            f"- Open threats: **{summary['open_threats']}**",
            f"- Mitigated threats: **{summary['mitigated_threats']}**",
            "\n### Distribution by Severity\n",
        ]

        for sev, count in summary["by_severity"].items():
            if count > 0:
                lines.append(f"- {sev}: {count}")

        lines.append("\n### Distribution by STRIDE Category\n")
        by_cat = self.model.get_threats_by_category()
        for cat_code, threats in by_cat.items():
            if threats:
                cat_name = StrideCategory(cat_code).full_name
                lines.append(f"- {cat_name}: {len(threats)}")

        lines.append("\n## Threat List\n")
        for threat in sorted(
            self.model.threats,
            key=lambda t: ["Critical", "High", "Medium", "Low", "Info"].index(
                t.severity.value
            ),
        ):
            lines.extend([
                f"### [{threat.id}] {threat.title}",
                f"\n- **Category**: {threat.stride_category.full_name}",
                f"- **Severity**: {threat.severity.value}",
                f"- **Likelihood**: {threat.likelihood}",
                f"- **Status**: {threat.status}",
                f"\n**Attack Scenario**: {threat.attack_scenario}",
                f"\n**Impact**: {threat.impact}",
                "\n**Mitigations**:",
            ])
            for mitigation in threat.mitigation:
                lines.append(f"- {mitigation}")
            lines.append("")

        return "\n".join(lines)

    def _generate_html_report(self) -> str:
        json_data = self._generate_json_report()
        summary = self.model.get_summary()

        severity_colors = {
            "Critical": "#dc3545",
            "High": "#fd7e14",
            "Medium": "#ffc107",
            "Low": "#28a745",
            "Info": "#17a2b8",
        }

        threat_rows = []
        for t in self.model.threats:
            color = severity_colors.get(t.severity.value, "#6c757d")
            mitigations = "<br>".join(f"• {m}" for m in t.mitigation)
            threat_rows.append(
                f"<tr>"
                f"<td>{t.id}</td>"
                f"<td>{t.stride_category.full_name}</td>"
                f"<td>{t.title}</td>"
                f"<td><span style='color:{color};font-weight:bold'>{t.severity.value}</span></td>"
                f"<td>{t.attack_scenario}</td>"
                f"<td>{mitigations}</td>"
                f"<td>{t.status}</td>"
                f"</tr>"
            )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>STRIDE Threat Model Report</title>
<style>
  body {{ font-family: Arial, sans-serif; margin: 20px; }}
  h1 {{ color: #333; }}
  .summary {{ background: #f5f5f5; padding: 15px; border-radius: 5px; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
  th {{ background: #333; color: white; padding: 10px; text-align: left; }}
  td {{ padding: 8px; border-bottom: 1px solid #ddd; vertical-align: top; }}
  tr:nth-child(even) {{ background: #f9f9f9; }}
</style>
</head>
<body>
<h1>STRIDE Threat Model Report: {self.model.name}</h1>
<div class="summary">
  <h2>Summary</h2>
  <p>Total threats: <strong>{summary['total_threats']}</strong> |
     Open: <strong>{summary['open_threats']}</strong> |
     Mitigated: <strong>{summary['mitigated_threats']}</strong></p>
</div>
<table>
<tr>
  <th>ID</th><th>STRIDE</th><th>Threat Name</th><th>Severity</th>
  <th>Attack Scenario</th><th>Mitigations</th><th>Status</th>
</tr>
{''.join(threat_rows)}
</table>
</body>
</html>"""


def build_ecommerce_model() -> ThreatModel:
    """Build threat model for an e-commerce system"""
    model = ThreatModel(
        name="E-commerce Platform",
        description="STRIDE threat model for a REST API-based e-commerce system",
        version="1.0",
        created_at=datetime.now().isoformat(),
    )

    # Add trust boundaries
    model.add_trust_boundary(TrustBoundary(
        id="TB001", name="Internet-DMZ Boundary",
        description="Boundary between external internet and DMZ",
        from_zone="Internet", to_zone="DMZ",
    ))
    model.add_trust_boundary(TrustBoundary(
        id="TB002", name="DMZ-Internal Boundary",
        description="Boundary between DMZ and internal network",
        from_zone="DMZ", to_zone="Internal Network",
    ))

    # Add DFD elements
    elements = [
        DFDElement("E001", "Web Browser", ElementType.EXTERNAL_ENTITY,
                   "End-user web browser", trust_boundary="TB001"),
        DFDElement("P001", "API Gateway", ElementType.PROCESS,
                   "Request routing and authentication handling", technologies=["Nginx", "Kong"]),
        DFDElement("P002", "Auth Service", ElementType.PROCESS,
                   "User authentication/authorization", technologies=["JWT", "OAuth2"]),
        DFDElement("P003", "Order Service", ElementType.PROCESS,
                   "Order creation/retrieval/cancellation", technologies=["Python", "FastAPI"]),
        DFDElement("P004", "Payment Service", ElementType.PROCESS,
                   "Payment processing and gateway integration", technologies=["Python"]),
        DFDElement("DS001", "User DB", ElementType.DATA_STORE,
                   "User accounts and profiles", technologies=["PostgreSQL"]),
        DFDElement("DS002", "Order DB", ElementType.DATA_STORE,
                   "Order data storage", technologies=["PostgreSQL"]),
        DFDElement("DS003", "Session Cache", ElementType.DATA_STORE,
                   "User session token storage", technologies=["Redis"]),
        DFDElement("DF001", "HTTPS Request", ElementType.DATA_FLOW,
                   "HTTPS communication between client and server"),
        DFDElement("DF002", "Internal API Call", ElementType.DATA_FLOW,
                   "HTTP communication between microservices"),
        DFDElement("E002", "Payment Gateway", ElementType.EXTERNAL_ENTITY,
                   "External payment processing service", trust_boundary="TB001"),
    ]

    for element in elements:
        model.add_element(element)

    return model


def build_kubernetes_model() -> ThreatModel:
    """Build threat model for a Kubernetes cluster"""
    model = ThreatModel(
        name="Kubernetes Cluster",
        description="STRIDE threat model for a multi-tenant Kubernetes cluster",
        version="1.0",
        created_at=datetime.now().isoformat(),
    )

    model.add_trust_boundary(TrustBoundary(
        id="TB001", name="Internet-Cluster Boundary",
        description="External traffic entry point",
        from_zone="Internet", to_zone="Cluster",
    ))
    model.add_trust_boundary(TrustBoundary(
        id="TB002", name="Namespace Boundary",
        description="Isolation boundary between tenants",
        from_zone="Tenant A", to_zone="Tenant B",
    ))

    elements = [
        DFDElement("E001", "Developer", ElementType.EXTERNAL_ENTITY,
                   "Developer using kubectl"),
        DFDElement("P001", "kube-apiserver", ElementType.PROCESS,
                   "Kubernetes API server", technologies=["Go", "RBAC"]),
        DFDElement("P002", "kubelet", ElementType.PROCESS,
                   "Node agent", technologies=["Go"]),
        DFDElement("P003", "Application Pod", ElementType.PROCESS,
                   "Workload container", technologies=["Docker", "containerd"]),
        DFDElement("DS001", "etcd", ElementType.DATA_STORE,
                   "Cluster state store", technologies=["etcd"]),
        DFDElement("DS002", "Secret", ElementType.DATA_STORE,
                   "K8s Secret object", technologies=["Kubernetes"]),
        DFDElement("DF001", "API Communication", ElementType.DATA_FLOW,
                   "kubectl ↔ kube-apiserver TLS communication"),
    ]

    for element in elements:
        model.add_element(element)

    return model


def interactive_mode() -> ThreatModel:
    """Build threat model interactively"""
    print("\n=== STRIDE Threat Modeling Interactive Mode ===\n")

    name = input("System name: ").strip() or "Unnamed System"
    description = input("System description: ").strip() or ""

    model = ThreatModel(
        name=name,
        description=description,
        version="1.0",
        created_at=datetime.now().isoformat(),
    )

    print("\n--- Add DFD elements (empty line to finish) ---")
    element_count = 0
    type_map = {
        "1": ElementType.PROCESS,
        "2": ElementType.DATA_FLOW,
        "3": ElementType.DATA_STORE,
        "4": ElementType.EXTERNAL_ENTITY,
    }

    while True:
        print(f"\nElement {element_count + 1}:")
        elem_name = input("  Name (empty line to finish): ").strip()
        if not elem_name:
            break

        print("  Type: 1=Process, 2=DataFlow, 3=DataStore, 4=ExternalEntity")
        type_choice = input("  Select: ").strip()
        elem_type = type_map.get(type_choice, ElementType.PROCESS)

        elem_desc = input("  Description: ").strip()
        element_count += 1

        element = DFDElement(
            id=f"E{element_count:03d}",
            name=elem_name,
            element_type=elem_type,
            description=elem_desc,
        )
        model.add_element(element)
        print(f"  Added: {elem_name} ({elem_type.value})")

    return model


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="STRIDE threat modeling automation tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --system ecommerce --output report.json
  %(prog)s --system kubernetes --format html --output k8s_threats.html
  %(prog)s --system ecommerce --format markdown --output threats.md
  %(prog)s --interactive --format json --output custom.json
        """,
    )
    parser.add_argument(
        "--system",
        choices=["ecommerce", "kubernetes"],
        help="Select a predefined system to analyze",
    )
    parser.add_argument(
        "--interactive",
        action="store_true",
        help="Define system in interactive mode",
    )
    parser.add_argument(
        "--format",
        choices=["json", "html", "markdown"],
        default="json",
        help="Output format (default: json)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("stride_report.json"),
        help="Output file path",
    )
    parser.add_argument(
        "--summary-only",
        action="store_true",
        help="Print summary information only",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if not args.system and not args.interactive:
        print("Error: specify either --system or --interactive.", file=sys.stderr)
        return 1

    # Build model
    if args.interactive:
        model = interactive_mode()
    elif args.system == "ecommerce":
        model = build_ecommerce_model()
    elif args.system == "kubernetes":
        model = build_kubernetes_model()
    else:
        print(f"Unknown system: {args.system}", file=sys.stderr)
        return 1

    # Run analysis
    analyzer = StrideAnalyzer(model)
    analyzer.analyze_all()

    # Print summary
    summary = model.get_summary()
    print(f"\n[{model.name}] STRIDE analysis complete")
    print(f"  Elements: {len(model.elements)}")
    print(f"  Total threats: {summary['total_threats']}")
    print(f"  Critical: {summary['by_severity']['Critical']}")
    print(f"  High: {summary['by_severity']['High']}")
    print(f"  Medium: {summary['by_severity']['Medium']}")

    if args.summary_only:
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        return 0

    # Generate report
    try:
        report = analyzer.generate_report(fmt=args.format)
        args.output.write_text(report, encoding="utf-8")
        print(f"\nReport saved: {args.output}")
    except (OSError, ValueError) as e:
        print(f"Report generation failed: {e}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
```

### How to Run

```bash
# E-commerce system JSON report
python3 stride_analyzer.py --system ecommerce --output ecom_threats.json

# Kubernetes HTML report
python3 stride_analyzer.py --system kubernetes --format html --output k8s.html

# Markdown report
python3 stride_analyzer.py --system ecommerce --format markdown --output threats.md

# Print summary only
python3 stride_analyzer.py --system kubernetes --summary-only

# Interactive mode
python3 stride_analyzer.py --interactive --format json --output custom.json
```

### Sample JSON Output

```json
{
  "metadata": {
    "name": "E-commerce Platform",
    "version": "1.0",
    "generated_at": "2025-01-15T10:00:00"
  },
  "summary": {
    "total_threats": 42,
    "by_severity": {
      "Critical": 0,
      "High": 0,
      "Medium": 42,
      "Low": 0
    },
    "open_threats": 42
  },
  "threats": [
    {
      "id": "T0001",
      "stride_category": "S",
      "stride_full_name": "Spoofing",
      "title": "Web Browser Identity Spoofing",
      "severity": "Medium",
      "status": "Open"
    }
  ]
}
```

---

## References

- [Microsoft STRIDE Threat Modeling](https://docs.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats)
- [OWASP Threat Modeling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html)
- [Shostack, A. (2014). Threat Modeling: Designing for Security]
- [NIST SP 800-154: Guide to Data-Centric System Threat Modeling]
