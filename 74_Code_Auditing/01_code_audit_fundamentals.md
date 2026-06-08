> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 코드 감사(Code Auditing) 기초

## 코드 감사란 무엇인가?

**코드 감사(Code Auditing)**란 소프트웨어의 소스코드를 체계적으로 검토하여 보안 취약점, 논리적 오류, 설계 결함을 찾아내는 과정입니다. 병원에서 환자의 X-ray를 촬영하듯, 코드 감사는 소프트웨어의 내부를 들여다보고 숨겨진 병변을 찾아내는 작업입니다.

펜테스터가 "문 앞에서 자물쇠를 따는 사람"이라면, 코드 감사자는 "건축 도면을 보고 취약한 구조를 찾아내는 사람"입니다.

---

## 코드 감사 vs 펜테스트

| 구분 | 코드 감사 | 펜테스트 |
|------|----------|---------|
| 접근 방식 | 화이트박스 (소스코드 보유) | 블랙/그레이박스 |
| 분석 깊이 | 논리 흐름, 데이터 흐름 추적 | 외부 입력 기반 테스트 |
| 발견 취약점 | 잠재적 취약점 포함 | 실제 익스플로잇 가능 취약점 |
| 시간 효율 | 더 많은 시간 필요 | 비교적 빠름 |
| 커버리지 | 모든 코드 경로 가능 | 접근 가능한 경로만 |

두 접근법은 서로 보완적이며, 이상적으로는 함께 사용해야 합니다.

---

## 위협 모델링: STRIDE 모델

코드 감사를 시작하기 전, **위협 모델링**으로 어디를 집중해서 볼지 정해야 합니다. Microsoft가 개발한 **STRIDE** 모델은 6가지 위협 유형을 정의합니다.

```
S - Spoofing        (위장/스푸핑)    - 다른 사용자/시스템인 척
T - Tampering       (변조)          - 데이터나 코드 무단 수정
R - Repudiation     (부인)          - "나는 그런 행동 안 했다" 주장
I - Information Disclosure (정보 노출) - 민감 정보 유출
D - Denial of Service (서비스 거부) - 가용성 방해
E - Elevation of Privilege (권한 상승) - 허가 없는 권한 획득
```

### STRIDE 기반 코드 감사 초점 예시

```python
#!/usr/bin/env python3
"""
STRIDE 기반 코드 감사 체크리스트 생성기
Python 3.10+, 타입 힌트 포함
"""

from dataclasses import dataclass, field
from enum import Enum
import argparse
import json
import sys


class StrideCategory(Enum):
    SPOOFING = "S - 스푸핑 (Spoofing)"
    TAMPERING = "T - 변조 (Tampering)"
    REPUDIATION = "R - 부인 (Repudiation)"
    INFO_DISCLOSURE = "I - 정보 노출 (Information Disclosure)"
    DENIAL_OF_SERVICE = "D - 서비스 거부 (Denial of Service)"
    ELEVATION_OF_PRIVILEGE = "E - 권한 상승 (Elevation of Privilege)"


@dataclass
class CheckItem:
    category: StrideCategory
    question: str
    code_pattern: str
    severity: str  # HIGH / MEDIUM / LOW


CHECKLIST: list[CheckItem] = [
    CheckItem(
        category=StrideCategory.SPOOFING,
        question="사용자 인증이 모든 엔드포인트에 적용되어 있는가?",
        code_pattern="@login_required, JWT 검증, 세션 확인",
        severity="HIGH",
    ),
    CheckItem(
        category=StrideCategory.TAMPERING,
        question="데이터베이스 쿼리에 파라미터화된 쿼리를 사용하는가?",
        code_pattern="cursor.execute(query, params) — ?/%s 플레이스홀더",
        severity="HIGH",
    ),
    CheckItem(
        category=StrideCategory.REPUDIATION,
        question="중요 작업(결제, 삭제 등)에 감사 로그가 기록되는가?",
        code_pattern="audit_log.info(f'user={user_id} action={action}')",
        severity="MEDIUM",
    ),
    CheckItem(
        category=StrideCategory.INFO_DISCLOSURE,
        question="오류 메시지에 스택 트레이스나 내부 경로가 노출되지 않는가?",
        code_pattern="DEBUG=False, 커스텀 에러 핸들러",
        severity="HIGH",
    ),
    CheckItem(
        category=StrideCategory.DENIAL_OF_SERVICE,
        question="파일 업로드에 크기 및 타입 제한이 있는가?",
        code_pattern="MAX_CONTENT_LENGTH, 확장자 화이트리스트",
        severity="MEDIUM",
    ),
    CheckItem(
        category=StrideCategory.ELEVATION_OF_PRIVILEGE,
        question="역할 기반 접근 제어(RBAC)가 서버 측에서 검증되는가?",
        code_pattern="require_role('admin'), 서버사이드 권한 확인",
        severity="HIGH",
    ),
]


def print_checklist(severity_filter: str | None = None) -> None:
    """STRIDE 체크리스트 출력"""
    items = CHECKLIST
    if severity_filter:
        items = [i for i in items if i.severity == severity_filter.upper()]

    if not items:
        print(f"[!] '{severity_filter}' 심각도에 해당하는 항목이 없습니다.")
        sys.exit(1)

    for item in items:
        print(f"\n{'='*60}")
        print(f"카테고리 : {item.category.value}")
        print(f"심각도   : {item.severity}")
        print(f"확인사항 : {item.question}")
        print(f"코드패턴 : {item.code_pattern}")


def export_json(output_path: str) -> None:
    """체크리스트를 JSON으로 저장"""
    data = [
        {
            "category": item.category.value,
            "question": item.question,
            "code_pattern": item.code_pattern,
            "severity": item.severity,
        }
        for item in CHECKLIST
    ]
    try:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        print(f"[+] 체크리스트 저장 완료: {output_path}")
    except OSError as e:
        print(f"[-] 파일 저장 실패: {e}", file=sys.stderr)
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="STRIDE 기반 코드 감사 체크리스트 생성기",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--severity",
        choices=["HIGH", "MEDIUM", "LOW"],
        help="심각도 필터 (기본: 전체 출력)",
    )
    parser.add_argument(
        "--export",
        metavar="FILE",
        help="결과를 JSON 파일로 저장",
    )
    args = parser.parse_args()

    print("[*] STRIDE 코드 감사 체크리스트")
    print_checklist(args.severity)

    if args.export:
        export_json(args.export)


if __name__ == "__main__":
    main()
```

---

## 감사 준비: 코드베이스 이해

### 1단계: 문서 및 구조 파악

코드를 한 줄씩 읽기 전에, 전체 지도를 파악해야 합니다.

```
프로젝트 구조 파악 순서:
1. README, CHANGELOG — 무엇을 하는 시스템인지
2. 의존성 파일 — requirements.txt, package.json, pom.xml
3. 설정 파일 — .env.example, config.yml, settings.py
4. 데이터 흐름 — API 엔드포인트, 데이터베이스 스키마
5. 인증/권한 — 어디서 로그인하고 권한을 확인하는가
```

### 2단계: 공격 표면 분석

**공격 표면(Attack Surface)**이란 외부 입력이 시스템에 진입하는 모든 지점입니다.

```
공격 표면 유형:
- 웹 API 엔드포인트 (GET, POST, PUT, DELETE)
- 파일 업로드
- 쿠키, 세션 토큰
- URL 파라미터, 쿼리 스트링
- 환경 변수, 설정 파일
- 서드파티 라이브러리 인터페이스
- 메시지 큐, 이벤트 핸들러
```

### 3단계: 우선순위 설정

모든 코드를 동등하게 감사할 시간은 없습니다. 다음 기준으로 우선순위를 정하세요.

| 우선순위 | 영역 | 이유 |
|---------|------|------|
| 최상 | 인증/권한 코드 | 우회 시 전체 시스템 위험 |
| 상 | 데이터베이스 쿼리 | SQL Injection 위험 |
| 상 | 파일 처리 | Path Traversal, 업로드 취약점 |
| 중 | 직렬화/역직렬화 | RCE 가능성 |
| 중 | 외부 API 호출 | SSRF 가능성 |
| 하 | 정적 파일 서비스 | 상대적으로 위험 낮음 |

---

## 코드 감사의 흐름

```
[문서 검토] → [구조 파악] → [공격 표면 식별]
      ↓
[위협 모델링] → [우선순위 설정]
      ↓
[정적 분석 도구 실행] → [수동 리뷰]
      ↓
[취약점 검증] → [보고서 작성] → [개발팀 전달]
```

---

## 참고 자료

- OWASP Code Review Guide: https://owasp.org/www-project-code-review-guide/

---

<a name="english"></a>

# Code Auditing Fundamentals

## What is Code Auditing?

**Code Auditing** is the systematic examination of software source code to identify security vulnerabilities, logical errors, and design flaws. Just as a doctor takes X-rays to find hidden problems in the body, a code audit looks inside software to uncover concealed weaknesses.

If a penetration tester is "the person picking the lock at the front door," a code auditor is "the person reviewing the blueprints to find structural weaknesses."

---

## Code Auditing vs Penetration Testing

| Aspect | Code Auditing | Penetration Testing |
|--------|--------------|---------------------|
| Approach | White-box (source code available) | Black/Gray-box |
| Depth | Logic flow, data flow tracing | External input-based testing |
| Findings | Potential vulnerabilities too | Only exploitable vulnerabilities |
| Time | More time required | Relatively faster |
| Coverage | All code paths possible | Only accessible paths |

Both approaches are complementary and ideally should be used together.

---

## Threat Modeling: The STRIDE Model

Before starting a code audit, use **threat modeling** to decide where to focus. Microsoft's **STRIDE** model defines six threat categories.

```
S - Spoofing           - Pretending to be another user/system
T - Tampering          - Unauthorized modification of data or code
R - Repudiation        - "I didn't do that" claims
I - Information Disclosure - Leaking sensitive data
D - Denial of Service  - Disrupting availability
E - Elevation of Privilege - Gaining unauthorized access
```

### STRIDE-Based Code Audit Checklist Tool

```python
#!/usr/bin/env python3
"""
STRIDE-based code audit checklist generator
Python 3.10+, with type hints
"""

from dataclasses import dataclass
from enum import Enum
import argparse
import json
import sys


class StrideCategory(Enum):
    SPOOFING = "S - Spoofing"
    TAMPERING = "T - Tampering"
    REPUDIATION = "R - Repudiation"
    INFO_DISCLOSURE = "I - Information Disclosure"
    DENIAL_OF_SERVICE = "D - Denial of Service"
    ELEVATION_OF_PRIVILEGE = "E - Elevation of Privilege"


@dataclass
class CheckItem:
    category: StrideCategory
    question: str
    code_pattern: str
    severity: str  # HIGH / MEDIUM / LOW


CHECKLIST: list[CheckItem] = [
    CheckItem(
        category=StrideCategory.SPOOFING,
        question="Is authentication enforced on all endpoints?",
        code_pattern="@login_required, JWT validation, session checks",
        severity="HIGH",
    ),
    CheckItem(
        category=StrideCategory.TAMPERING,
        question="Are parameterized queries used for all database access?",
        code_pattern="cursor.execute(query, params) with ? or %s placeholders",
        severity="HIGH",
    ),
    CheckItem(
        category=StrideCategory.REPUDIATION,
        question="Are audit logs recorded for critical actions (payments, deletions)?",
        code_pattern="audit_log.info(f'user={user_id} action={action}')",
        severity="MEDIUM",
    ),
    CheckItem(
        category=StrideCategory.INFO_DISCLOSURE,
        question="Do error messages avoid exposing stack traces or internal paths?",
        code_pattern="DEBUG=False, custom error handlers",
        severity="HIGH",
    ),
    CheckItem(
        category=StrideCategory.DENIAL_OF_SERVICE,
        question="Are file uploads restricted by size and type?",
        code_pattern="MAX_CONTENT_LENGTH, extension whitelist",
        severity="MEDIUM",
    ),
    CheckItem(
        category=StrideCategory.ELEVATION_OF_PRIVILEGE,
        question="Is RBAC verified server-side for all privileged actions?",
        code_pattern="require_role('admin'), server-side permission checks",
        severity="HIGH",
    ),
]


def print_checklist(severity_filter: str | None = None) -> None:
    """Print the STRIDE checklist, optionally filtered by severity."""
    items = CHECKLIST
    if severity_filter:
        items = [i for i in items if i.severity == severity_filter.upper()]

    if not items:
        print(f"[!] No items found for severity '{severity_filter}'.")
        sys.exit(1)

    for item in items:
        print(f"\n{'='*60}")
        print(f"Category : {item.category.value}")
        print(f"Severity : {item.severity}")
        print(f"Question : {item.question}")
        print(f"Pattern  : {item.code_pattern}")


def export_json(output_path: str) -> None:
    """Export checklist to a JSON file."""
    data = [
        {
            "category": item.category.value,
            "question": item.question,
            "code_pattern": item.code_pattern,
            "severity": item.severity,
        }
        for item in CHECKLIST
    ]
    try:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        print(f"[+] Checklist saved to: {output_path}")
    except OSError as e:
        print(f"[-] Failed to save file: {e}", file=sys.stderr)
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="STRIDE-based code audit checklist generator",
    )
    parser.add_argument(
        "--severity",
        choices=["HIGH", "MEDIUM", "LOW"],
        help="Filter by severity (default: show all)",
    )
    parser.add_argument(
        "--export",
        metavar="FILE",
        help="Export results to a JSON file",
    )
    args = parser.parse_args()

    print("[*] STRIDE Code Audit Checklist")
    print_checklist(args.severity)

    if args.export:
        export_json(args.export)


if __name__ == "__main__":
    main()
```

---

## Audit Preparation: Understanding the Codebase

### Step 1: Review Documentation and Structure

Before reading code line by line, build a map of the whole system.

```
Order of codebase exploration:
1. README, CHANGELOG — what does this system do?
2. Dependency files — requirements.txt, package.json, pom.xml
3. Configuration files — .env.example, config.yml, settings.py
4. Data flow — API endpoints, database schemas
5. Auth & authorization — where is login handled? where are permissions checked?
```

### Step 2: Attack Surface Analysis

The **attack surface** encompasses all points where external input enters the system.

```
Attack surface types:
- Web API endpoints (GET, POST, PUT, DELETE)
- File uploads
- Cookies, session tokens
- URL parameters, query strings
- Environment variables, config files
- Third-party library interfaces
- Message queues, event handlers
```

### Step 3: Setting Priorities

You won't have time to audit every line equally. Prioritize using these criteria:

| Priority | Area | Reason |
|----------|------|--------|
| Critical | Auth/authorization code | Bypass risks the entire system |
| High | Database queries | SQL injection risk |
| High | File handling | Path traversal, upload vulnerabilities |
| Medium | Serialization/deserialization | RCE potential |
| Medium | External API calls | SSRF potential |
| Low | Static file serving | Relatively lower risk |

---

## The Code Audit Workflow

```
[Review Docs] → [Understand Structure] → [Identify Attack Surface]
      ↓
[Threat Modeling] → [Set Priorities]
      ↓
[Run Static Analysis Tools] → [Manual Review]
      ↓
[Validate Findings] → [Write Report] → [Hand Off to Dev Team]
```

---

## References

- OWASP Code Review Guide: https://owasp.org/www-project-code-review-guide/
