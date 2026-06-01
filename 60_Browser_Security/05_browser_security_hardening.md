> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 브라우저 보안 강화

## 1. 엔터프라이즈 브라우저 보안 정책

### 1.1 주요 관리 채널 비교

| 관리 방법 | 지원 브라우저 | 운영체제 | 정책 범위 | 특징 |
|-----------|--------------|---------|-----------|------|
| Group Policy (GPO) | Chrome, Edge, Firefox | Windows | 도메인 가입 기기 | AD 인프라 필요, 즉시 적용 |
| MDM (Intune, Jamf) | Chrome, Edge, Safari | 모든 OS | 등록된 모바일/PC | 클라우드 관리, BYOD 지원 |
| Chrome Browser Cloud Management | Chrome | 모든 OS | 클라우드 계정 | AD 불필요, 클라우드 정책 |
| Enterprise Policy JSON (Linux) | Chrome, Firefox | Linux | 로컬 정책 파일 | /etc/opt/chrome/policies/ |
| Firefox AutoConfig | Firefox | 모든 OS | .cfg 파일 | 스크립트 기반 세밀한 설정 |
| Edge Policy Templates | Edge | Windows, macOS | ADMX 템플릿 | GPO 기반 |

### 1.2 필수 엔터프라이즈 보안 정책 항목

| 정책 이름 | Chrome 정책 키 | Firefox 정책 키 | 권장 값 | 목적 |
|-----------|---------------|----------------|---------|------|
| 안전 브라우징 활성화 | SafeBrowsingEnabled | EnableTrackingProtection | true | 피싱/악성코드 차단 |
| 자동 업데이트 강제 | AutoUpdateCheckPeriodMinutes | AppAutoUpdate | 최소 720 (12시간) | 취약점 패치 |
| 확장 설치 허용 목록 | ExtensionInstallAllowlist | ExtensionSettings | 승인된 ID만 | 악성 확장 차단 |
| 서드파티 쿠키 차단 | BlockThirdPartyCookies | Cookies | true | 트래킹 방지 |
| 개발자 도구 비활성화 | DeveloperToolsDisabled | BlockAboutConfig | true | 내부 공격 차단 |
| HTTPS 강제 | HttpsOnlyMode | HttpsOnlyMode | force_enabled | MitM 방어 |
| 게스트 모드 비활성화 | BrowserGuestModeEnabled | DisablePrivateBrowsing | false | 정책 우회 방지 |
| 비밀번호 저장 금지 | PasswordManagerEnabled | PasswordManagerEnabled | false | 크레덴셜 격리 |
| 자동 완성 비활성화 | AutofillAddressEnabled | DisableFormHistory | false | 데이터 노출 방지 |
| 원격 접근 비활성화 | RemoteAccessHostFirewallTraversal | - | false | 원격 제어 방지 |
| 인증서 오류 무시 금지 | SSLErrorOverrideAllowed | - | false | MitM 방어 |
| 인쇄 제한 | PrintingEnabled | PrintingEnabled | 정책에 따라 | 데이터 유출 방지 |

---

## 2. CSP (Content Security Policy) 설계 원칙

### 2.1 CSP 지시자 완전 목록

| 지시자 | 역할 | 권장 설정 | 보안 고려 사항 |
|--------|------|-----------|---------------|
| `default-src` | 모든 리소스 기본 정책 | `'self'` | 화이트리스트 기반 |
| `script-src` | JS 소스 제어 | `'self'` + nonce/hash | `'unsafe-eval'` 절대 금지 |
| `style-src` | CSS 소스 제어 | `'self'` + nonce | `'unsafe-inline'` 지양 |
| `img-src` | 이미지 소스 제어 | `'self' data: https:` | 외부 트래킹 픽셀 차단 |
| `connect-src` | XHR/fetch/WebSocket 대상 | 명시적 도메인만 | 데이터 유출 방어 |
| `frame-src` | iframe 소스 제어 | `'none'` 또는 명시적 | 클릭재킹 방어 |
| `object-src` | 플러그인 소스 제어 | `'none'` | Flash 등 취약 플러그인 차단 |
| `base-uri` | `<base>` 태그 제한 | `'self'` | Base URI 인젝션 방어 |
| `form-action` | 폼 제출 대상 제한 | `'self'` | CSRF + XSS 방어 |
| `frame-ancestors` | 자신을 embed한 부모 제한 | `'none'` 또는 `'self'` | 클릭재킹 방어 (X-Frame-Options 대체) |
| `upgrade-insecure-requests` | HTTP를 HTTPS로 업그레이드 | 포함 | Mixed Content 방어 |
| `require-trusted-types-for` | DOM XSS 방어 (Trusted Types) | `'script'` | DOM XSS 원천 차단 |
| `trusted-types` | Trusted Types 정책 정의 | 명명된 정책 | 안전한 DOM 조작 강제 |
| `report-to` | 위반 보고 엔드포인트 | 모니터링 서버 | 실시간 위반 탐지 |

### 2.2 CSP 우회 방어 기법

**'unsafe-inline' 대체 — Nonce 기반:**
```html
<!-- 서버가 매 요청마다 새로운 nonce 생성 -->
<meta http-equiv="Content-Security-Policy"
      content="script-src 'nonce-r4nd0m1337Base64=='">
<script nonce="r4nd0m1337Base64==">
    // 이 스크립트만 실행 허용
</script>
```

**Hash 기반 (정적 스크립트):**
```
Content-Security-Policy: script-src 'sha256-base64encodedHash=='
```

**CSP 우회 패턴 및 방어:**

| 우회 기법 | 조건 | 방어 방법 |
|-----------|------|-----------|
| JSONP 엔드포인트 악용 | `script-src` 에 신뢰 도메인 포함 | 최소한의 도메인만 허용, `strict-dynamic` 사용 |
| Angular 템플릿 인젝션 | `unsafe-eval` 또는 Angular가 허용 목록에 | Angular 컴파일 모드 사용, `unsafe-eval` 제거 |
| 기존 JS 파일 활용 (CSPBYPASS) | 신뢰 도메인에 업로드 가능한 JS 존재 | 파일 업로드 제한, `strict-dynamic` |
| `data:` URI 악용 | `script-src data:` 허용 시 | `data:` 절대 허용 금지 |
| `base-uri` 미설정 | base 태그 인젝션으로 상대 경로 변경 | `base-uri 'self'` 명시 |
| `object-src` 미설정 | Flash, PDF 인젝션 | `object-src 'none'` 필수 |

### 2.3 CSP 레벨별 보안 강도

| CSP 레벨 | 특징 | 권장 상황 |
|----------|------|-----------|
| 레벨 1 | `'unsafe-inline'`, `'unsafe-eval'` 포함 | 레거시 — 피해야 함 |
| 레벨 2 | Nonce/Hash 기반, `strict-dynamic` | 대부분의 현대 앱 |
| 레벨 3 | Trusted Types, `require-trusted-types-for 'script'` | 고보안 금융/의료 |

---

## 3. 쿠키 보안, HSTS, Certificate Transparency

### 3.1 SameSite 쿠키 속성

| SameSite 값 | 동작 | 보호 대상 | 부작용 |
|-------------|------|-----------|--------|
| `Strict` | 크로스 사이트 요청에 쿠키 전송 안 함 | CSRF 완전 방어 | 외부 링크 클릭 시 로그아웃 경험 |
| `Lax` | 안전한 최상위 탐색(GET)에만 전송 | 대부분의 CSRF 방어 | POST CSRF는 방어 못 함 |
| `None` | 항상 전송 | 없음 | `Secure` 속성 필수 동반 |

**권장 쿠키 설정 조합:**
```
Set-Cookie: session=abc123; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=3600
```

| 속성 | 목적 |
|------|------|
| `Secure` | HTTPS 연결에서만 전송 |
| `HttpOnly` | JS에서 접근 불가 (XSS로 탈취 방지) |
| `SameSite=Strict` | CSRF 방어 |
| `Path=/` | 최소 범위 제한 |
| `Max-Age` | 만료 시간 명시 |

### 3.2 HSTS (HTTP Strict Transport Security)

| HSTS 항목 | 설명 | 권장값 |
|-----------|------|--------|
| `max-age` | HSTS 적용 유지 기간(초) | 31536000 (1년) 이상 |
| `includeSubDomains` | 서브도메인도 포함 | 포함 권장 |
| `preload` | 브라우저 내장 HSTS 목록에 등재 | 가능하면 등록 |

**예시:**
```
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
```

HSTS Preload 등록을 위한 조건:
- 유효한 HTTPS 인증서
- HTTP → HTTPS 리다이렉트
- 모든 서브도메인에 HTTPS 적용
- `includeSubDomains` + `preload` 지시자 포함
- `max-age` 1년 이상

### 3.3 Certificate Transparency (CT)

| 항목 | 설명 |
|------|------|
| 개념 | 모든 TLS 인증서를 공개 로그에 기록하여 감사 가능성 보장 |
| 적용 방식 | CA가 인증서 발급 시 CT 로그에 제출, SCT 발급 |
| 브라우저 검증 | Chrome: 2018년부터 SCT 없는 인증서 오류 표시 |
| Expect-CT 헤더 | 브라우저에 CT 준수 강제 및 위반 보고 |
| 목적 | 루트 CA 오용/도용 탐지 (예: DigiNotar 사건) |

```
Expect-CT: max-age=86400, enforce, report-uri="https://report.example.com/ct"
```

---

## 4. Python CLI: 웹사이트 브라우저 보안 헤더 감사기

```python
#!/usr/bin/env python3
"""
웹사이트 브라우저 보안 헤더 감사기
대상 URL의 HTTP 응답 헤더를 수집하고 보안 헤더 설정 현황을
분석하여 점수화 및 개선 권고를 출력한다.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# 보안 헤더 검사 규칙
# ---------------------------------------------------------------------------

@dataclass
class HeaderRule:
    name:          str
    header_key:    str
    max_score:     int
    description:   str
    check_fn:      Any  # Callable[[str | None], tuple[int, str, list[str]]]


def check_strict_transport_security(value: str | None) -> tuple[int, str, list[str]]:
    """HSTS 헤더를 점검하고 (획득점수, 등급, 권고사항) 를 반환한다."""
    recommendations: list[str] = []
    if value is None:
        return 0, "누락", ["HSTS 헤더를 추가하세요: Strict-Transport-Security: max-age=63072000; includeSubDomains; preload"]
    score = 0
    v_lower = value.lower()

    max_age_m = re.search(r"max-age\s*=\s*(\d+)", v_lower)
    if max_age_m:
        max_age = int(max_age_m.group(1))
        if max_age >= 31536000:
            score += 10
        elif max_age >= 2592000:
            score += 6
            recommendations.append("max-age를 최소 31536000 (1년) 이상으로 늘리세요.")
        else:
            score += 2
            recommendations.append("max-age가 너무 짧습니다. 31536000 이상을 권장합니다.")
    else:
        recommendations.append("max-age 지시자가 없습니다.")

    if "includesubdomains" in v_lower:
        score += 5
    else:
        recommendations.append("includeSubDomains를 추가하여 서브도메인도 보호하세요.")

    if "preload" in v_lower:
        score += 5
    else:
        recommendations.append("preload를 추가하고 hstspreload.org에 등록하세요.")

    grade = "우수" if score >= 18 else ("양호" if score >= 12 else "미흡")
    return score, grade, recommendations


def check_content_security_policy(value: str | None) -> tuple[int, str, list[str]]:
    """CSP 헤더를 점검한다."""
    recommendations: list[str] = []
    if value is None:
        return 0, "누락", ["Content-Security-Policy 헤더를 추가하세요."]
    score = 0
    v_lower = value.lower()

    if "default-src" in v_lower:
        score += 5
    else:
        recommendations.append("default-src 지시자를 추가하세요.")

    if "'unsafe-inline'" in v_lower:
        score -= 5
        recommendations.append("'unsafe-inline'을 제거하고 nonce 또는 hash를 사용하세요.")

    if "'unsafe-eval'" in v_lower:
        score -= 5
        recommendations.append("'unsafe-eval'을 반드시 제거하세요.")

    if "nonce-" in v_lower or "sha256-" in v_lower or "sha384-" in v_lower:
        score += 8

    if "object-src 'none'" in v_lower:
        score += 4
    else:
        recommendations.append("object-src 'none'을 추가하세요.")

    if "base-uri" in v_lower:
        score += 3
    else:
        recommendations.append("base-uri 'self'를 추가하세요.")

    if "frame-ancestors" in v_lower:
        score += 3
    else:
        recommendations.append("frame-ancestors를 추가하여 클릭재킹을 방어하세요.")

    if "upgrade-insecure-requests" in v_lower:
        score += 2

    if "require-trusted-types-for" in v_lower:
        score += 5

    if "report-to" in v_lower or "report-uri" in v_lower:
        score += 2

    score = max(0, score)
    grade = "우수" if score >= 20 else ("양호" if score >= 12 else "미흡")
    return score, grade, recommendations


def check_x_frame_options(value: str | None) -> tuple[int, str, list[str]]:
    """X-Frame-Options 헤더를 점검한다."""
    if value is None:
        return 0, "누락", ["X-Frame-Options: DENY 또는 SAMEORIGIN을 추가하세요. (또는 CSP frame-ancestors 사용)"]
    v_upper = value.upper().strip()
    if v_upper == "DENY":
        return 10, "우수", []
    if v_upper == "SAMEORIGIN":
        return 8, "양호", ["완전한 클릭재킹 방어를 위해 DENY를 고려하세요."]
    return 3, "미흡", [f"유효하지 않은 값: {value}. DENY 또는 SAMEORIGIN을 사용하세요."]


def check_x_content_type_options(value: str | None) -> tuple[int, str, list[str]]:
    """X-Content-Type-Options 헤더를 점검한다."""
    if value is None:
        return 0, "누락", ["X-Content-Type-Options: nosniff를 추가하세요."]
    if value.lower().strip() == "nosniff":
        return 8, "우수", []
    return 3, "미흡", [f"유효하지 않은 값: {value}. nosniff를 사용하세요."]


def check_referrer_policy(value: str | None) -> tuple[int, str, list[str]]:
    """Referrer-Policy 헤더를 점검한다."""
    SAFE_VALUES = {
        "no-referrer":                        10,
        "no-referrer-when-downgrade":         7,
        "strict-origin":                      9,
        "strict-origin-when-cross-origin":    8,
        "same-origin":                        6,
    }
    WEAK_VALUES = {
        "origin":                             3,
        "origin-when-cross-origin":           4,
        "unsafe-url":                         0,
    }
    if value is None:
        return 0, "누락", ["Referrer-Policy 헤더를 추가하세요. 권장값: strict-origin-when-cross-origin"]
    v_lower = value.lower().strip()
    if v_lower in SAFE_VALUES:
        return SAFE_VALUES[v_lower], "양호-우수", []
    if v_lower in WEAK_VALUES:
        sc = WEAK_VALUES[v_lower]
        return sc, "미흡", [f"'{v_lower}'는 정보를 노출합니다. strict-origin-when-cross-origin을 권장합니다."]
    return 3, "불명확", [f"알 수 없는 Referrer-Policy 값: {value}"]


def check_permissions_policy(value: str | None) -> tuple[int, str, list[str]]:
    """Permissions-Policy 헤더를 점검한다."""
    recommendations: list[str] = []
    if value is None:
        return 0, "누락", [
            "Permissions-Policy 헤더를 추가하여 브라우저 기능을 제한하세요.",
            "예: Permissions-Policy: geolocation=(), microphone=(), camera=()",
        ]
    score = 5
    sensitive_features = [
        "geolocation", "microphone", "camera", "payment",
        "usb", "fullscreen", "autoplay",
    ]
    v_lower = value.lower()
    for feat in sensitive_features:
        if feat in v_lower:
            score += 1
        else:
            recommendations.append(f"{feat} 기능의 정책을 명시적으로 설정하세요.")

    score = min(15, score)
    grade = "우수" if score >= 12 else ("양호" if score >= 8 else "미흡")
    return score, grade, recommendations


def check_expect_ct(value: str | None) -> tuple[int, str, list[str]]:
    """Expect-CT 헤더를 점검한다."""
    if value is None:
        return 0, "누락", ["Expect-CT 헤더 추가를 고려하세요 (CT 위반 강제 및 보고)."]
    score = 3
    v_lower = value.lower()
    if "enforce" in v_lower:
        score += 3
    if "report-uri" in v_lower:
        score += 2
    grade = "양호" if score >= 6 else "미흡"
    return score, grade, []


def check_cross_origin_headers(headers: dict[str, str]) -> tuple[int, str, list[str]]:
    """COOP / COEP / CORP 헤더를 점검한다."""
    score = 0
    recommendations: list[str] = []

    coop = headers.get("cross-origin-opener-policy", "")
    if "same-origin" in coop.lower():
        score += 5
    else:
        recommendations.append("Cross-Origin-Opener-Policy: same-origin 을 추가하세요 (Spectre 방어).")

    coep = headers.get("cross-origin-embedder-policy", "")
    if "require-corp" in coep.lower():
        score += 5
    else:
        recommendations.append("Cross-Origin-Embedder-Policy: require-corp 을 추가하세요.")

    corp = headers.get("cross-origin-resource-policy", "")
    if corp.lower() in ("same-origin", "same-site"):
        score += 3
    else:
        recommendations.append("Cross-Origin-Resource-Policy: same-origin 을 추가하세요.")

    grade = "우수" if score >= 11 else ("양호" if score >= 6 else "미흡")
    return score, grade, recommendations


# ---------------------------------------------------------------------------
# 데이터 클래스
# ---------------------------------------------------------------------------

@dataclass
class HeaderCheckResult:
    header:          str
    value:           str | None
    score:           int
    max_score:       int
    grade:           str
    recommendations: list[str]


@dataclass
class AuditResult:
    url:             str
    final_url:       str
    status_code:     int
    total_score:     int
    max_score:       int
    checks:          list[HeaderCheckResult] = field(default_factory=list)
    server_info:     str = ""
    https:           bool = False

    @property
    def percentage(self) -> float:
        if self.max_score == 0:
            return 0.0
        return (self.total_score / self.max_score) * 100

    @property
    def grade(self) -> str:
        pct = self.percentage
        if pct >= 85:
            return "A"
        if pct >= 70:
            return "B"
        if pct >= 55:
            return "C"
        if pct >= 40:
            return "D"
        return "F"


# ---------------------------------------------------------------------------
# HTTP 요청 및 헤더 수집
# ---------------------------------------------------------------------------

def fetch_headers(
    url: str,
    follow_redirects: bool,
    timeout: float = 15.0,
) -> tuple[int, str, dict[str, str]]:
    headers_out = {
        "User-Agent": "Mozilla/5.0 (SecurityAudit/1.0; +https://github.com/)",
    }
    req = urllib.request.Request(url, headers=headers_out, method="HEAD")

    if not follow_redirects:
        response_handler = urllib.request.urlopen
    else:
        response_handler = urllib.request.urlopen

    try:
        with response_handler(req, timeout=timeout) as resp:
            raw_headers = dict(resp.headers)
            normalized: dict[str, str] = {k.lower(): v for k, v in raw_headers.items()}
            return resp.status, resp.url, normalized
    except urllib.error.HTTPError as exc:
        raw_headers = dict(exc.headers) if exc.headers else {}
        normalized = {k.lower(): v for k, v in raw_headers.items()}
        return exc.code, url, normalized
    except urllib.error.URLError as exc:
        print(f"[!] 연결 오류: {exc.reason}", file=sys.stderr)
        sys.exit(1)


# ---------------------------------------------------------------------------
# 분석 실행
# ---------------------------------------------------------------------------

def run_audit(url: str, follow_redirects: bool) -> AuditResult:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    print(f"[+] 헤더 수집 중: {url}")
    status_code, final_url, headers = fetch_headers(url, follow_redirects)
    print(f"[+] 응답 상태: {status_code} | 최종 URL: {final_url}")

    parsed = urlparse(final_url)
    is_https = parsed.scheme == "https"

    result = AuditResult(
        url=url,
        final_url=final_url,
        status_code=status_code,
        total_score=0,
        max_score=0,
        https=is_https,
        server_info=headers.get("server", "미공개"),
    )

    if is_https:
        result.total_score += 10
    else:
        result.checks.append(HeaderCheckResult(
            header="HTTPS",
            value="사용 안 함",
            score=0,
            max_score=10,
            grade="실패",
            recommendations=["HTTPS를 반드시 활성화하세요. HTTP는 전송 중 데이터 노출 위험이 있습니다."],
        ))
    result.max_score += 10

    single_checks: list[tuple[str, str | None, Any, int]] = [
        ("Strict-Transport-Security", headers.get("strict-transport-security"),
         check_strict_transport_security, 20),
        ("Content-Security-Policy",   headers.get("content-security-policy"),
         check_content_security_policy, 30),
        ("X-Frame-Options",           headers.get("x-frame-options"),
         check_x_frame_options, 10),
        ("X-Content-Type-Options",    headers.get("x-content-type-options"),
         check_x_content_type_options, 8),
        ("Referrer-Policy",           headers.get("referrer-policy"),
         check_referrer_policy, 10),
        ("Permissions-Policy",        headers.get("permissions-policy"),
         check_permissions_policy, 15),
        ("Expect-CT",                 headers.get("expect-ct"),
         check_expect_ct, 8),
    ]

    for header_name, header_val, check_fn, max_sc in single_checks:
        score, grade, recs = check_fn(header_val)
        score = min(score, max_sc)
        result.checks.append(HeaderCheckResult(
            header=header_name,
            value=header_val or "없음",
            score=score,
            max_score=max_sc,
            grade=grade,
            recommendations=recs,
        ))
        result.total_score += score
        result.max_score   += max_sc

    co_score, co_grade, co_recs = check_cross_origin_headers(headers)
    result.checks.append(HeaderCheckResult(
        header="Cross-Origin-*",
        value=f"COOP={headers.get('cross-origin-opener-policy','없음')} | "
              f"COEP={headers.get('cross-origin-embedder-policy','없음')} | "
              f"CORP={headers.get('cross-origin-resource-policy','없음')}",
        score=co_score,
        max_score=13,
        grade=co_grade,
        recommendations=co_recs,
    ))
    result.total_score += co_score
    result.max_score   += 13

    server = headers.get("server", "")
    x_powered = headers.get("x-powered-by", "")
    info_recs: list[str] = []
    info_score = 5
    if re.search(r"\d", server):
        info_score -= 2
        info_recs.append(f"Server 헤더에 버전 정보 포함: '{server}'. 버전을 제거하세요.")
    if x_powered:
        info_score -= 2
        info_recs.append(f"X-Powered-By 헤더 노출: '{x_powered}'. 헤더를 제거하세요.")
    info_score = max(0, info_score)
    result.checks.append(HeaderCheckResult(
        header="서버 정보 노출",
        value=f"Server={server or '없음'} | X-Powered-By={x_powered or '없음'}",
        score=info_score,
        max_score=5,
        grade="우수" if info_score == 5 else "미흡",
        recommendations=info_recs,
    ))
    result.total_score += info_score
    result.max_score   += 5

    return result


# ---------------------------------------------------------------------------
# 출력 포맷터
# ---------------------------------------------------------------------------

def format_text(result: AuditResult) -> str:
    lines: list[str] = []
    lines.append("=" * 70)
    lines.append(f"  웹사이트 브라우저 보안 헤더 감사 보고서")
    lines.append("=" * 70)
    lines.append(f"  대상 URL    : {result.url}")
    lines.append(f"  최종 URL    : {result.final_url}")
    lines.append(f"  상태 코드   : {result.status_code}")
    lines.append(f"  HTTPS       : {'예' if result.https else '아니오'}")
    lines.append(f"  서버        : {result.server_info}")
    lines.append(f"  총점        : {result.total_score} / {result.max_score}  "
                 f"({result.percentage:.1f}%)  등급: {result.grade}")
    lines.append("=" * 70)

    for chk in result.checks:
        lines.append(f"\n헤더 : {chk.header}")
        lines.append(f"  값     : {chk.value}")
        lines.append(f"  점수   : {chk.score} / {chk.max_score}  [{chk.grade}]")
        for rec in chk.recommendations:
            lines.append(f"  [권고] {rec}")

    lines.append("\n" + "=" * 70)
    lines.append(f"  최종 등급: {result.grade}  (점수: {result.total_score}/{result.max_score})")
    lines.append("=" * 70)
    return "\n".join(lines)


def format_json(result: AuditResult) -> str:
    data = {
        "url":          result.url,
        "final_url":    result.final_url,
        "status_code":  result.status_code,
        "https":        result.https,
        "server":       result.server_info,
        "total_score":  result.total_score,
        "max_score":    result.max_score,
        "percentage":   round(result.percentage, 1),
        "grade":        result.grade,
        "checks": [
            {
                "header":          c.header,
                "value":           c.value,
                "score":           c.score,
                "max_score":       c.max_score,
                "grade":           c.grade,
                "recommendations": c.recommendations,
            }
            for c in result.checks
        ],
    }
    return json.dumps(data, ensure_ascii=False, indent=2)


def format_md(result: AuditResult) -> str:
    lines: list[str] = []
    lines.append(f"# 보안 헤더 감사 보고서: {result.final_url}")
    lines.append(f"\n- **최종 URL**: {result.final_url}")
    lines.append(f"- **상태 코드**: {result.status_code}")
    lines.append(f"- **HTTPS**: {'예' if result.https else '아니오'}")
    lines.append(f"- **총점**: {result.total_score}/{result.max_score} ({result.percentage:.1f}%) — 등급 **{result.grade}**")
    lines.append(f"\n## 헤더 점검 결과\n")
    lines.append("| 헤더 | 점수 | 최대 | 등급 |")
    lines.append("|------|------|------|------|")
    for chk in result.checks:
        lines.append(f"| {chk.header} | {chk.score} | {chk.max_score} | {chk.grade} |")
    lines.append("\n## 개선 권고 사항\n")
    for chk in result.checks:
        if chk.recommendations:
            lines.append(f"### {chk.header}")
            for rec in chk.recommendations:
                lines.append(f"- {rec}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI 진입점
# ---------------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="header_audit",
        description="웹사이트 브라우저 보안 헤더 감사기 — CSP, HSTS, 쿠키 정책 등 분석",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
예시:
  # 기본 텍스트 출력
  python3 05_browser_security_hardening.py --url https://example.com

  # JSON 출력, 리다이렉트 따라가기
  python3 05_browser_security_hardening.py \\
      --url https://example.com \\
      --follow-redirects \\
      --output-format json

  # Markdown 출력 후 파일 저장
  python3 05_browser_security_hardening.py \\
      --url https://example.com \\
      --output-format md \\
      --output report.md
        """,
    )
    parser.add_argument(
        "--url",
        required=True,
        help="감사할 웹사이트 URL (예: https://example.com)",
    )
    parser.add_argument(
        "--follow-redirects",
        action="store_true",
        default=True,
        help="HTTP 리다이렉트를 따라가서 최종 URL의 헤더를 점검 (기본값: True)",
    )
    parser.add_argument(
        "--output-format",
        choices=["text", "json", "md"],
        default="text",
        help="출력 형식 (text / json / md, 기본값: text)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="결과 저장 파일 경로 (생략 시 stdout 출력)",
    )
    return parser


def main() -> None:
    parser = build_arg_parser()
    args   = parser.parse_args()

    result = run_audit(args.url, args.follow_redirects)

    if args.output_format == "json":
        content = format_json(result)
    elif args.output_format == "md":
        content = format_md(result)
    else:
        content = format_text(result)

    if args.output:
        args.output.write_text(content, encoding="utf-8")
        print(f"[+] 보고서 저장 완료: {args.output}")
    else:
        print(content)


if __name__ == "__main__":
    main()
```

---

## 5. 브라우저 보안 강화 체크리스트

### 5.1 서버/개발자 관점

| 항목 | 필수 여부 | 구현 예시 |
|------|-----------|-----------|
| HTTPS 전용 운영 | 필수 | Let's Encrypt, 인증서 자동 갱신 |
| HSTS + preload | 강력 권장 | max-age=63072000; includeSubDomains; preload |
| CSP 설정 | 필수 | nonce/hash 기반, unsafe-eval 금지 |
| X-Frame-Options | 필수 | DENY |
| X-Content-Type-Options | 필수 | nosniff |
| Referrer-Policy | 권장 | strict-origin-when-cross-origin |
| Permissions-Policy | 권장 | 불필요한 기능 명시적 비활성화 |
| SameSite=Strict | 필수 | 세션 쿠키에 적용 |
| HttpOnly 쿠키 | 필수 | 모든 세션 쿠키 |
| 서버 버전 정보 제거 | 권장 | Server: 헤더 최소화 |
| COOP/COEP | 권장 | Spectre 방어 필요 시 |
| Certificate Transparency | 필수 (CA 강제) | SCT 포함 인증서 사용 |
| Subresource Integrity (SRI) | 권장 | CDN 리소스에 integrity 속성 |

### 5.2 엔드유저/기업 관점

| 항목 | 설명 | 도구/방법 |
|------|------|-----------|
| 브라우저 최신 버전 유지 | 취약점 패치 | 자동 업데이트 활성화 |
| uBlock Origin 설치 | 광고/트래킹 차단 | 스토어에서 설치 |
| HTTPS Everywhere | HTTP 사이트 강제 전환 | 확장프로그램 |
| 불필요한 확장 제거 | 공격 표면 최소화 | 주기적 감사 |
| DNS over HTTPS (DoH) | DNS 쿼리 암호화 | 브라우저 내장 설정 |
| 쿠키 만료 시간 관리 | 오래된 세션 제거 | 브라우저 설정 |
| 기업 MDM 정책 적용 | 표준 보안 설정 강제 | Intune, Jamf |

---

## 6. 참고 자료

- OWASP Secure Headers Project (https://owasp.org/www-project-secure-headers/)
- CSP 평가 도구 — csp-evaluator.withgoogle.com
- Security Headers 스캐너 — securityheaders.com
- HSTS Preload 등록 — hstspreload.org
- Mozilla Observatory (https://observatory.mozilla.org/)
- Google Web Fundamentals — Security Headers
- NIST SP 800-44 (웹 서버 보안 가이드)

---

<a name="english"></a>

# Browser Security Hardening

## 1. Enterprise Browser Security Policies

### 1.1 Key Management Channel Comparison

| Management Method | Supported Browsers | OS | Policy Scope | Features |
|------------------|-------------------|----|--------------|----------|
| Group Policy (GPO) | Chrome, Edge, Firefox | Windows | Domain-joined devices | Requires AD infrastructure, immediate application |
| MDM (Intune, Jamf) | Chrome, Edge, Safari | All OS | Enrolled mobile/PC | Cloud management, BYOD support |
| Chrome Browser Cloud Management | Chrome | All OS | Cloud accounts | No AD required, cloud policies |
| Enterprise Policy JSON (Linux) | Chrome, Firefox | Linux | Local policy files | /etc/opt/chrome/policies/ |
| Firefox AutoConfig | Firefox | All OS | .cfg files | Script-based fine-grained settings |
| Edge Policy Templates | Edge | Windows, macOS | ADMX templates | GPO-based |

### 1.2 Essential Enterprise Security Policy Items

| Policy Name | Chrome Policy Key | Firefox Policy Key | Recommended Value | Purpose |
|-------------|------------------|-------------------|-------------------|---------|
| Enable safe browsing | SafeBrowsingEnabled | EnableTrackingProtection | true | Block phishing/malware |
| Force auto-update | AutoUpdateCheckPeriodMinutes | AppAutoUpdate | Min 720 (12h) | Vulnerability patching |
| Extension install allowlist | ExtensionInstallAllowlist | ExtensionSettings | Approved IDs only | Block malicious extensions |
| Block third-party cookies | BlockThirdPartyCookies | Cookies | true | Prevent tracking |
| Disable developer tools | DeveloperToolsDisabled | BlockAboutConfig | true | Block insider attacks |
| Force HTTPS | HttpsOnlyMode | HttpsOnlyMode | force_enabled | MitM defense |
| Disable guest mode | BrowserGuestModeEnabled | DisablePrivateBrowsing | false | Prevent policy bypass |
| Disable password saving | PasswordManagerEnabled | PasswordManagerEnabled | false | Credential isolation |
| Disable autofill | AutofillAddressEnabled | DisableFormHistory | false | Prevent data exposure |
| Disable remote access | RemoteAccessHostFirewallTraversal | - | false | Prevent remote control |
| Prohibit certificate error override | SSLErrorOverrideAllowed | - | false | MitM defense |
| Restrict printing | PrintingEnabled | PrintingEnabled | Per policy | Prevent data leakage |

---

## 2. CSP (Content Security Policy) Design Principles

### 2.1 Complete List of CSP Directives

| Directive | Role | Recommended Setting | Security Considerations |
|-----------|------|---------------------|------------------------|
| `default-src` | Default policy for all resources | `'self'` | Whitelist-based |
| `script-src` | Control JS sources | `'self'` + nonce/hash | Never use `'unsafe-eval'` |
| `style-src` | Control CSS sources | `'self'` + nonce | Avoid `'unsafe-inline'` |
| `img-src` | Control image sources | `'self' data: https:` | Block external tracking pixels |
| `connect-src` | XHR/fetch/WebSocket targets | Explicit domains only | Defense against data exfiltration |
| `frame-src` | Control iframe sources | `'none'` or explicit | Clickjacking defense |
| `object-src` | Control plugin sources | `'none'` | Block vulnerable plugins like Flash |
| `base-uri` | Restrict `<base>` tag | `'self'` | Base URI injection defense |
| `form-action` | Restrict form submission targets | `'self'` | CSRF + XSS defense |
| `frame-ancestors` | Restrict parent embeds | `'none'` or `'self'` | Clickjacking defense (replaces X-Frame-Options) |
| `upgrade-insecure-requests` | Upgrade HTTP to HTTPS | Include | Mixed Content defense |
| `require-trusted-types-for` | DOM XSS defense (Trusted Types) | `'script'` | DOM XSS root prevention |
| `trusted-types` | Define Trusted Types policies | Named policies | Enforce safe DOM manipulation |
| `report-to` | Violation reporting endpoint | Monitoring server | Real-time violation detection |

### 2.2 CSP Bypass Defense Techniques

**Replacing 'unsafe-inline' — Nonce-based:**
```html
<!-- Server generates new nonce per request -->
<meta http-equiv="Content-Security-Policy"
      content="script-src 'nonce-r4nd0m1337Base64=='">
<script nonce="r4nd0m1337Base64==">
    // Only this script is allowed to execute
</script>
```

**Hash-based (static scripts):**
```
Content-Security-Policy: script-src 'sha256-base64encodedHash=='
```

**CSP Bypass Patterns and Defenses:**

| Bypass Technique | Condition | Defense |
|-----------------|-----------|---------|
| JSONP endpoint abuse | Trusted domain in `script-src` | Allow minimal domains, use `strict-dynamic` |
| Angular template injection | `unsafe-eval` or Angular in allowlist | Use Angular compiled mode, remove `unsafe-eval` |
| Existing JS file abuse (CSPBYPASS) | Uploadable JS exists on trusted domain | Restrict file uploads, `strict-dynamic` |
| `data:` URI abuse | `script-src data:` allowed | Never allow `data:` |
| `base-uri` not set | Base tag injection changes relative paths | Explicitly set `base-uri 'self'` |
| `object-src` not set | Flash, PDF injection | Must have `object-src 'none'` |

### 2.3 CSP Security Level by Version

| CSP Level | Features | Recommended Use |
|-----------|----------|-----------------|
| Level 1 | Includes `'unsafe-inline'`, `'unsafe-eval'` | Legacy — should be avoided |
| Level 2 | Nonce/Hash-based, `strict-dynamic` | Most modern applications |
| Level 3 | Trusted Types, `require-trusted-types-for 'script'` | High-security finance/healthcare |

---

## 3. Cookie Security, HSTS, Certificate Transparency

### 3.1 SameSite Cookie Attribute

| SameSite Value | Behavior | Protection | Side Effects |
|----------------|----------|------------|--------------|
| `Strict` | No cookie sent on cross-site requests | Full CSRF protection | Logout experience on external link clicks |
| `Lax` | Sent only on safe top-level navigation (GET) | Most CSRF protection | Cannot protect against POST CSRF |
| `None` | Always sent | None | Must be accompanied by `Secure` attribute |

**Recommended cookie setting combination:**
```
Set-Cookie: session=abc123; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=3600
```

| Attribute | Purpose |
|-----------|---------|
| `Secure` | Transmitted only over HTTPS connections |
| `HttpOnly` | Inaccessible via JS (prevents XSS theft) |
| `SameSite=Strict` | CSRF defense |
| `Path=/` | Minimum scope restriction |
| `Max-Age` | Explicit expiration time |

### 3.2 HSTS (HTTP Strict Transport Security)

| HSTS Item | Description | Recommended Value |
|-----------|-------------|-------------------|
| `max-age` | Duration to maintain HSTS (seconds) | 31536000 (1 year) or more |
| `includeSubDomains` | Include subdomains | Recommended to include |
| `preload` | List in browser's built-in HSTS list | Register if possible |

**Example:**
```
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
```

Requirements for HSTS Preload registration:
- Valid HTTPS certificate
- HTTP → HTTPS redirect
- HTTPS applied to all subdomains
- Includes `includeSubDomains` + `preload` directives
- `max-age` of at least 1 year

### 3.3 Certificate Transparency (CT)

| Item | Description |
|------|-------------|
| Concept | Record all TLS certificates in public logs to ensure auditability |
| Implementation | CA submits certificates to CT log upon issuance, receives SCT |
| Browser validation | Chrome: Displays error for certificates without SCT since 2018 |
| Expect-CT header | Enforce CT compliance and report violations to browser |
| Purpose | Detect root CA misuse/theft (e.g., DigiNotar incident) |

```
Expect-CT: max-age=86400, enforce, report-uri="https://report.example.com/ct"
```

---

## 4. Python CLI: Website Browser Security Header Auditor

```python
#!/usr/bin/env python3
"""
Website Browser Security Header Auditor
Collects HTTP response headers from target URL, analyzes security header
configuration, scores it, and outputs improvement recommendations.
"""

# (See Korean section above for full implementation — same code with English comments)
# Key functions:
# - fetch_headers(): Collects HTTP headers via HEAD request
# - run_audit(): Runs full security header audit
# - format_text/json/md(): Output formatters
# - check_*(): Individual header check functions
```

---

## 5. Browser Security Hardening Checklist

### 5.1 Server/Developer Perspective

| Item | Required | Implementation Example |
|------|----------|----------------------|
| HTTPS-only operation | Required | Let's Encrypt, automatic certificate renewal |
| HSTS + preload | Strongly recommended | max-age=63072000; includeSubDomains; preload |
| CSP configuration | Required | nonce/hash-based, no unsafe-eval |
| X-Frame-Options | Required | DENY |
| X-Content-Type-Options | Required | nosniff |
| Referrer-Policy | Recommended | strict-origin-when-cross-origin |
| Permissions-Policy | Recommended | Explicitly disable unnecessary features |
| SameSite=Strict | Required | Apply to session cookies |
| HttpOnly cookies | Required | All session cookies |
| Remove server version info | Recommended | Minimize Server: header |
| COOP/COEP | Recommended | When Spectre defense required |
| Certificate Transparency | Required (CA enforced) | Use certificates with SCT |
| Subresource Integrity (SRI) | Recommended | integrity attribute on CDN resources |

### 5.2 End-User/Enterprise Perspective

| Item | Description | Tool/Method |
|------|-------------|-------------|
| Keep browser up to date | Vulnerability patching | Enable auto-update |
| Install uBlock Origin | Block ads/tracking | Install from store |
| HTTPS Everywhere | Force HTTP sites to HTTPS | Browser extension |
| Remove unnecessary extensions | Minimize attack surface | Periodic audit |
| DNS over HTTPS (DoH) | Encrypt DNS queries | Built-in browser settings |
| Manage cookie expiration | Remove stale sessions | Browser settings |
| Apply enterprise MDM policies | Enforce standard security settings | Intune, Jamf |

---

## 6. References

- OWASP Secure Headers Project (https://owasp.org/www-project-secure-headers/)
- CSP evaluation tool — csp-evaluator.withgoogle.com
- Security Headers scanner — securityheaders.com
- HSTS Preload registration — hstspreload.org
- Mozilla Observatory (https://observatory.mozilla.org/)
- Google Web Fundamentals — Security Headers
- NIST SP 800-44 (Web Server Security Guide)
