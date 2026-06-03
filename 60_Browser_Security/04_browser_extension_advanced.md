> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 브라우저 확장프로그램 심화 공격

## 0. 초보자를 위한 개념 이해

### 브라우저 확장프로그램 공격이란?

브라우저 확장프로그램은 브라우저에 추가 기능을 제공하지만, 과도한 권한을 가진 악성 확장은 모든 웹 페이지의 내용을 읽고 수정하거나, 사용자 입력을 가로채거나, 쿠키와 비밀번호를 탈취할 수 있다. 2022년 3200만 명이 설치한 악성 확장 'Great Suspender' 사례처럼, 정상 확장이 악성으로 전환될 수도 있다.

**왜 배우는가:**
```
[확장프로그램의 권한 수준]

일반 웹페이지:
  - 자신의 출처(origin) 데이터만 접근
  - 다른 탭 접근 불가

확장프로그램 (넓은 권한 허용 시):
  - 모든 탭의 URL, 내용 읽기/수정
  - 모든 요청/응답 가로채기 (webRequest API)
  - 쿠키, 세션, 비밀번호 접근
  - 로컬 파일 시스템 접근 (일부)
  - 다른 웹사이트에 JS 삽입

[악성 확장의 공격 시나리오]
1. 유명 확장 복제 + 악성 코드 추가 → 스토어에 업로드
2. 정상 확장 개발자 계정 탈취 → 업데이트에 악성코드 삽입
3. 확장 개발사 인수 → 악성 업데이트 배포
→ 수백만 사용자 자동 감염
```

### 핵심 개념 정리

```
주요 용어:
- Manifest V3 (MV3): Chrome의 새 확장 API (2023~) - 보안 강화, 일부 기능 제한
- 콘텐츠 스크립트: 웹 페이지 컨텍스트에서 실행되는 확장 코드
- 배경 서비스 워커: 확장의 핵심 로직을 실행하는 이벤트 기반 백그라운드
- 메시지 패싱: 콘텐츠 스크립트 ↔ 배경 스크립트 간 통신 API
- 선언적 네트워크 요청 (DNR): MV3의 새 요청 차단/수정 API (webRequest 대체)
- 교차 출처 격리: 확장이 모든 사이트에 접근 가능한 넓은 권한의 위험성
- 확장 CSP: 확장 내 인라인 스크립트 실행을 제한하는 콘텐츠 보안 정책
```

### 필요한 도구 및 환경
- **Chrome/Firefox 개발자 모드**: 로컬 확장 로드 및 디버깅
- **Chrome DevTools**: 확장 배경 스크립트 디버깅
- **CRXcavator (crxcavator.io)**: 확장 권한 및 위험도 분석
- **ExtAnalysis**: 오프라인 확장 패키지 분석 도구

### 기초 실습 예제
```python
import json
import zipfile
import re
from pathlib import Path

def analyze_extension_permissions(crx_or_dir_path: str) -> dict:
    """
    Chrome 확장프로그램의 권한 위험도 분석
    manifest.json을 분석하여 악성 가능성이 높은 권한 조합 탐지
    """
    # 고위험 권한 목록과 설명
    HIGH_RISK_PERMISSIONS = {
        "<all_urls>": "모든 웹사이트 접근 (가장 위험)",
        "tabs": "모든 탭 URL 및 내용 접근",
        "webRequest": "모든 HTTP 요청 가로채기",
        "webRequestBlocking": "HTTP 요청 차단/수정 가능",
        "cookies": "모든 사이트 쿠키 접근",
        "history": "브라우저 방문 기록 접근",
        "downloads": "파일 다운로드 제어",
        "nativeMessaging": "로컬 앱과 통신 (OS 접근)",
        "debugger": "탭 디버깅 (임의 JS 실행 가능)",
        "contentSettings": "사이트별 콘텐츠 설정 변경",
    }

    MEDIUM_RISK_PERMISSIONS = {
        "storage": "로컬 저장소 접근",
        "identity": "Google 계정 접근",
        "bookmarks": "북마크 읽기/쓰기",
        "clipboardRead": "클립보드 읽기",
        "clipboardWrite": "클립보드 쓰기",
    }

    path = Path(crx_or_dir_path)

    # manifest.json 읽기
    if path.is_dir():
        manifest_path = path / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
    elif path.suffix == ".zip":
        with zipfile.ZipFile(path) as zf:
            manifest = json.loads(zf.read("manifest.json"))
    else:
        # 샘플 데이터로 시연
        manifest = {
            "name": "Super PDF Viewer",
            "version": "2.1.0",
            "manifest_version": 3,
            "permissions": ["tabs", "cookies", "storage", "history", "clipboardRead"],
            "host_permissions": ["<all_urls>"],
            "content_scripts": [{"matches": ["<all_urls>"], "js": ["content.js"]}],
        }
        print("(실제 파일 없음 - 샘플 manifest.json으로 시연)\n")

    # 권한 분석
    all_perms = set(manifest.get("permissions", []) + manifest.get("host_permissions", []))
    found_high = {p: HIGH_RISK_PERMISSIONS[p] for p in all_perms if p in HIGH_RISK_PERMISSIONS}
    found_medium = {p: MEDIUM_RISK_PERMISSIONS[p] for p in all_perms if p in MEDIUM_RISK_PERMISSIONS}

    risk_score = len(found_high) * 20 + len(found_medium) * 5
    risk_level = "매우 높음" if risk_score >= 60 else "높음" if risk_score >= 30 else "중간" if risk_score >= 10 else "낮음"

    result = {
        "name": manifest.get("name"),
        "version": manifest.get("version"),
        "manifest_version": manifest.get("manifest_version", 2),
        "risk_score": min(risk_score, 100),
        "risk_level": risk_level,
        "high_risk_permissions": found_high,
        "medium_risk_permissions": found_medium,
    }

    print(f"=== 확장프로그램 권한 분석 ===\n")
    print(f"이름: {result['name']} v{result['version']}")
    print(f"Manifest 버전: V{result['manifest_version']}")
    print(f"위험도: {result['risk_level']} ({result['risk_score']}점)\n")

    if found_high:
        print("[고위험 권한]")
        for perm, desc in found_high.items():
            print(f"  ! {perm}: {desc}")
    if found_medium:
        print("[중간 위험 권한]")
        for perm, desc in found_medium.items():
            print(f"  ~ {perm}: {desc}")

    if risk_score >= 40:
        print("\n권고: 이 확장은 높은 위험을 가지고 있습니다.")
        print("      실제로 이 권한이 모두 필요한지 검토 후 설치하세요.")

    return result

analyze_extension_permissions(".")
```

---

## 1. Manifest V2 vs V3 보안 비교

### 1.1 핵심 차이점 비교표

| 항목 | Manifest V2 | Manifest V3 | 보안 영향 |
|------|-------------|-------------|-----------|
| 배경 스크립트 | Persistent background page | Service Worker | V3에서 지속 실행 제한 |
| 원격 코드 실행 | 원격 URL 스크립트 허용 | 원격 코드 실행 금지 | V3에서 동적 코드 인젝션 차단 |
| 콘텐츠 스크립트 주입 | tabs.executeScript() | scripting.executeScript() | V3에서 선언적 방식 권장 |
| 네트워크 요청 인터셉트 | webRequest API (blocking) | declarativeNetRequest | V3에서 차단 규칙 선언적으로 제한 |
| host_permissions | permissions에 포함 | 별도 host_permissions | V3에서 런타임 권한 요청 가능 |
| eval() 사용 | 제한적으로 허용 | 완전 금지 | V3에서 코드 인젝션 차단 |
| cross-origin XHR | 권한 내 허용 | fetch() 사용, 제한 강화 | V3에서 CORS 강화 |
| 스토리지 | chrome.storage, localStorage | chrome.storage만 허용 | V3에서 접근 제한 |
| 업데이트 방식 | 자동 업데이트 즉시 적용 | 검토 강화 | V3 스토어 검토 강화 |
| 수명 주기 | 항상 실행 | 이벤트 기반, 짧은 수명 | V3에서 지속 실행 악성코드 어려움 |

### 1.2 V2 vs V3 공격 표면 변화

V3로의 전환이 보안을 강화하지만, 완전한 해결책은 아니다.

**V3에서도 여전히 가능한 공격:**
- `host_permissions`로 모든 사이트(`<all_urls>`) 접근
- 콘텐츠 스크립트를 통한 DOM 조작 및 키로깅
- `chrome.cookies` API를 통한 쿠키 탈취 (권한 획득 시)
- `chrome.history`, `chrome.bookmarks` 데이터 수집
- `chrome.webRequest`를 읽기 전용으로 네트워크 감시

---

## 2. 악성 확장프로그램 탐지 기법

### 2.1 행동 분석 기반 탐지 지표

| 행동 패턴 | 설명 | 위험도 | 탐지 방법 |
|-----------|------|--------|-----------|
| 폼 데이터 스니핑 | input 이벤트 리스너로 비밀번호 수집 | 최상 | DOM 이벤트 모니터링 |
| 쿠키 원격 전송 | chrome.cookies → fetch()로 외부 전송 | 최상 | 네트워크 트래픽 분석 |
| 화면 캡처 | chrome.tabs.captureVisibleTab() 반복 호출 | 상 | API 호출 빈도 분석 |
| 클립보드 읽기 | document.execCommand('copy') 또는 Clipboard API | 상 | 권한 + API 호출 |
| 브라우저 히스토리 수집 | chrome.history.search() 반복 | 중 | API 호출 패턴 |
| 동적 코드 생성 | eval() / new Function() 사용 | 상 | 정적 코드 분석 |
| 난독화 코드 | 헥스 인코딩, 치환 암호화 | 상 | 엔트로피 분석 |
| 외부 도메인 통신 | 알 수 없는 도메인으로 데이터 전송 | 상 | 도메인 평판 분석 |
| 권한 동적 요청 | 런타임에 추가 권한 요청 | 중 | 권한 변경 감시 |
| 다른 확장 메시지 | chrome.runtime.sendMessage 다른 확장 대상 | 중 | 메시지 대상 분석 |

### 2.2 코드 난독화 탐지 기법

| 난독화 기법 | 특징 | 탐지 방법 | 도구 |
|-------------|------|-----------|------|
| 변수명 압축 | a, b, c 등 의미 없는 1~2자 변수 | 엔트로피, 길이 분포 | js-beautify |
| 문자열 분할 | "mal"+"ware" 형식 | 정적 분석 | AST 분석 |
| 16진수 인코딩 | "\x65\x76\x61\x6c" (eval) | 정규식 탐지 | grep/regex |
| Base64 인코딩 | atob() 로 디코딩 후 실행 | atob 호출 탐지 | 정적 분석 |
| 동적 키 접근 | obj["ev"+"al"]() | 문자열 연결 패턴 | AST 분석 |
| 코드 압축 | UglifyJS/Terser 출력 | 라인당 길이 | 엔트로피 |
| 프록시 패턴 | Proxy 객체로 API 호출 가로채기 | Proxy 사용 | AST 분석 |

### 2.3 Cross-Extension 공격 패턴

Chrome 확장프로그램 간 통신이 가능하기 때문에 악성 확장이 신뢰받는 확장에 메시지를 보내 권한을 남용할 수 있다.

**공격 시나리오:**
1. 낮은 권한의 악성 확장 A가 설치됨
2. 높은 권한의 신뢰 확장 B에 메시지 전송
3. 확장 B가 메시지를 검증 없이 처리
4. 확장 B의 권한으로 민감한 작업 수행

```javascript
// 악성 확장의 메시지 전송 (개념 예시)
chrome.runtime.sendMessage(
    "신뢰할_확장의_ID_abcdefgh",
    { action: "fetch_cookies", domain: ".bank.com" },
    (response) => { exfiltrate(response.data); }
);
```

---

## 3. 확장프로그램 권한 남용 사례

### 3.1 권한 남용 사례 분류표

| 권한 | 정당한 용도 | 남용 방법 | 실제 사례 |
|------|-------------|-----------|-----------|
| `<all_urls>` | 모든 사이트에 스크립트 주입 | 키로깅, 폼 데이터 수집 | DataSpii (2019) |
| `cookies` | 세션 관리 | 인증 쿠키 탈취 | Session Hijacking |
| `history` | 방문 기록 분석 | 브라우징 행동 프로파일링 | DataSpii (2019) |
| `tabs` | 탭 목록 접근 | 사용자 활동 감시 | 다수 애드웨어 |
| `webRequest` | 요청 모니터링 | 네트워크 트래픽 스니핑 | 피싱 검출 악용 |
| `downloads` | 다운로드 관리 | 파일 탈취, 악성파일 다운로드 | 다운로더 악성코드 |
| `notifications` | 알림 표시 | 피싱 알림, 광고 | 클릭재킹 사기 |
| `geolocation` | 위치 기반 서비스 | 사용자 위치 추적 | 스파이웨어 |
| `clipboardRead` | 복사 데이터 접근 | 비밀번호/주소 탈취 | 클립보드 하이재커 |
| `nativeMessaging` | 네이티브 앱 통신 | 로컬 파일 접근, 코드 실행 | 고급 APT 악성코드 |

### 3.2 실제 악성 확장프로그램 사례

| 이름/캠페인 | 연도 | 피해 규모 | 주요 권한 악용 | 탐지 방법 |
|-------------|------|-----------|---------------|-----------|
| DataSpii | 2019 | 수백만 사용자 | `<all_urls>`, history | 네트워크 트래픽 분석 |
| The Great Suspender | 2020 | ~200만 설치 | 원격 코드 실행 | 코드 변경 탐지 |
| Nigelthorn | 2018 | 10만+ | tabs, webRequest | 소셜 미디어 전파 |
| ChromeBack | 2021 | 미상 | cookies, tabs | 스토어 자동 탐지 |
| CacheFlow | 2020 | 300만+ | `<all_urls>` | 동적 분석 |

---

## 4. Python CLI: 브라우저 확장프로그램 정적 분석기

```python
#!/usr/bin/env python3
"""
브라우저 확장프로그램 정적 분석기
로컬의 확장프로그램 디렉토리(.crx 압축 해제 포함)를 분석하여
위험 권한, 코드 패턴, 난독화, 데이터 유출 시도를 탐지한다.
"""

from __future__ import annotations

import argparse
import ast
import json
import math
import os
import re
import sys
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator


# ---------------------------------------------------------------------------
# 위험 권한 정의
# ---------------------------------------------------------------------------

CRITICAL_PERMISSIONS: set[str] = {
    "<all_urls>", "cookies", "nativeMessaging",
    "clipboardRead", "downloads", "management",
}
HIGH_PERMISSIONS: set[str] = {
    "tabs", "webRequest", "webRequestBlocking", "history",
    "bookmarks", "topSites", "browsingData",
}
MEDIUM_PERMISSIONS: set[str] = {
    "notifications", "geolocation", "contextMenus",
    "activeTab", "identity", "proxy",
}

# ---------------------------------------------------------------------------
# 위험 JS 패턴
# ---------------------------------------------------------------------------

DANGEROUS_JS_PATTERNS: list[dict[str, Any]] = [
    {
        "name":     "eval_usage",
        "pattern":  re.compile(r"\beval\s*\(", re.MULTILINE),
        "severity": "HIGH",
        "desc":     "eval() 사용 — 동적 코드 실행 위험",
    },
    {
        "name":     "new_function",
        "pattern":  re.compile(r"new\s+Function\s*\(", re.MULTILINE),
        "severity": "HIGH",
        "desc":     "new Function() 사용 — 동적 코드 실행 위험",
    },
    {
        "name":     "hex_encoded_strings",
        "pattern":  re.compile(r'["\']\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){4,}["\']'),
        "severity": "HIGH",
        "desc":     "16진수 인코딩된 긴 문자열 — 난독화 의심",
    },
    {
        "name":     "atob_decode",
        "pattern":  re.compile(r"\batob\s*\(", re.MULTILINE),
        "severity": "MEDIUM",
        "desc":     "atob() 사용 — Base64 디코딩 후 실행 가능성",
    },
    {
        "name":     "exfiltration_fetch",
        "pattern":  re.compile(
            r"fetch\s*\(\s*['\"]https?://(?!(?:www\.)?google|(?:www\.)?microsoft|(?:www\.)?mozilla)",
            re.MULTILINE,
        ),
        "severity": "HIGH",
        "desc":     "의심스러운 외부 도메인으로 fetch() 호출 — 데이터 유출 가능성",
    },
    {
        "name":     "xmlhttprequest_open",
        "pattern":  re.compile(r"\.open\s*\(\s*['\"](?:POST|PUT)['\"]", re.MULTILINE | re.IGNORECASE),
        "severity": "MEDIUM",
        "desc":     "XMLHttpRequest POST/PUT — 데이터 전송 가능성",
    },
    {
        "name":     "clipboard_read",
        "pattern":  re.compile(r"navigator\.clipboard\.readText|document\.execCommand\s*\(\s*['\"]paste['\"]", re.MULTILINE),
        "severity": "HIGH",
        "desc":     "클립보드 읽기 API 사용",
    },
    {
        "name":     "password_selector",
        "pattern":  re.compile(r'querySelector\s*\([\'"]input\[type=[\'"]?password', re.MULTILINE),
        "severity": "CRITICAL",
        "desc":     "비밀번호 입력 필드 직접 접근 — 키로거 패턴",
    },
    {
        "name":     "cookie_access",
        "pattern":  re.compile(r"\bdocument\.cookie\b", re.MULTILINE),
        "severity": "HIGH",
        "desc":     "document.cookie 직접 접근",
    },
    {
        "name":     "dynamic_script_inject",
        "pattern":  re.compile(r"document\.createElement\s*\(\s*['\"]script['\"]", re.MULTILINE),
        "severity": "MEDIUM",
        "desc":     "동적 스크립트 태그 생성 — 코드 인젝션 위험",
    },
    {
        "name":     "send_message_external",
        "pattern":  re.compile(r"chrome\.runtime\.sendMessage\s*\(\s*['\"][a-z]{32}['\"]", re.MULTILINE),
        "severity": "MEDIUM",
        "desc":     "다른 확장프로그램으로 메시지 전송 — Cross-extension 공격 가능성",
    },
    {
        "name":     "obfuscated_string_concat",
        "pattern":  re.compile(r'["\'][a-z]{1,4}["\']\s*\+\s*["\'][a-z]{1,4}["\'](?:\s*\+\s*["\'][a-z]{1,4}["\']){2,}', re.MULTILINE),
        "severity": "MEDIUM",
        "desc":     "짧은 문자열 연결로 난독화 의심",
    },
    {
        "name":     "native_messaging_connect",
        "pattern":  re.compile(r"chrome\.runtime\.connectNative\s*\(", re.MULTILINE),
        "severity": "HIGH",
        "desc":     "네이티브 앱과의 연결 — 로컬 시스템 접근 가능성",
    },
]


# ---------------------------------------------------------------------------
# 데이터 클래스
# ---------------------------------------------------------------------------

@dataclass
class PatternMatch:
    file:     str
    pattern:  str
    severity: str
    desc:     str
    line_num: int
    line:     str


@dataclass
class PermissionFinding:
    permission: str
    severity:   str
    context:    str


@dataclass
class AnalysisReport:
    extension_name:     str
    extension_version:  str
    manifest_version:   int
    path:               str
    permission_findings: list[PermissionFinding] = field(default_factory=list)
    pattern_findings:   list[PatternMatch] = field(default_factory=list)
    file_count:         int = 0
    js_file_count:      int = 0
    risk_score:         int = 0

    def compute_score(self) -> None:
        score = 0
        sev_map = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3}
        for pf in self.permission_findings:
            score += sev_map.get(pf.severity, 0)
        for mf in self.pattern_findings:
            score += sev_map.get(mf.severity, 0)
        self.risk_score = min(100, score)

    def risk_level(self) -> str:
        if self.risk_score >= 70:
            return "CRITICAL"
        if self.risk_score >= 45:
            return "HIGH"
        if self.risk_score >= 20:
            return "MEDIUM"
        return "LOW"


# ---------------------------------------------------------------------------
# Manifest 분석
# ---------------------------------------------------------------------------

def analyze_manifest(manifest: dict[str, Any]) -> list[PermissionFinding]:
    findings: list[PermissionFinding] = []

    all_perms: list[str] = []
    all_perms.extend(manifest.get("permissions", []))
    all_perms.extend(manifest.get("host_permissions", []))
    all_perms.extend(manifest.get("optional_permissions", []))

    for perm in all_perms:
        if perm in CRITICAL_PERMISSIONS:
            findings.append(PermissionFinding(
                permission=perm,
                severity="CRITICAL",
                context="manifest.json permissions",
            ))
        elif perm in HIGH_PERMISSIONS:
            findings.append(PermissionFinding(
                permission=perm,
                severity="HIGH",
                context="manifest.json permissions",
            ))
        elif perm in MEDIUM_PERMISSIONS:
            findings.append(PermissionFinding(
                permission=perm,
                severity="MEDIUM",
                context="manifest.json permissions",
            ))
        elif re.match(r"https?://\*/", perm) or re.match(r"\*://\*/", perm):
            findings.append(PermissionFinding(
                permission=perm,
                severity="HIGH",
                context="와일드카드 host permission",
            ))

    # CSP 확인
    csp = manifest.get("content_security_policy", "")
    if isinstance(csp, dict):
        csp = " ".join(csp.values())
    if "unsafe-eval" in csp:
        findings.append(PermissionFinding(
            permission="CSP:unsafe-eval",
            severity="HIGH",
            context="content_security_policy에 unsafe-eval 포함",
        ))
    if "unsafe-inline" in csp:
        findings.append(PermissionFinding(
            permission="CSP:unsafe-inline",
            severity="MEDIUM",
            context="content_security_policy에 unsafe-inline 포함",
        ))

    # background scripts 확인
    bg = manifest.get("background", {})
    if bg.get("persistent", False) and manifest.get("manifest_version", 2) == 2:
        findings.append(PermissionFinding(
            permission="background.persistent=true",
            severity="MEDIUM",
            context="영구 백그라운드 스크립트 (MV2)",
        ))

    return findings


# ---------------------------------------------------------------------------
# JS 코드 분석
# ---------------------------------------------------------------------------

def shannon_entropy(text: str) -> float:
    """문자열의 Shannon 엔트로피를 계산한다 (높을수록 난독화 가능성 높음)."""
    if not text:
        return 0.0
    freq: dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def analyze_js_file(js_path: Path, rel_path: str) -> list[PatternMatch]:
    """단일 JS 파일에서 위험 패턴을 탐지한다."""
    matches: list[PatternMatch] = []
    try:
        content = js_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return matches

    lines = content.splitlines()

    # 패턴 매칭
    for rule in DANGEROUS_JS_PATTERNS:
        for m in rule["pattern"].finditer(content):
            line_num = content[:m.start()].count("\n") + 1
            line_content = lines[line_num - 1] if line_num <= len(lines) else ""
            matches.append(PatternMatch(
                file=rel_path,
                pattern=rule["name"],
                severity=rule["severity"],
                desc=rule["desc"],
                line_num=line_num,
                line=line_content.strip()[:100],
            ))

    # 고 엔트로피 문자열 탐지 (난독화)
    long_string_re = re.compile(r'["\']([A-Za-z0-9+/=]{60,})["\']')
    for m in long_string_re.finditer(content):
        s   = m.group(1)
        ent = shannon_entropy(s)
        if ent > 5.0:
            line_num = content[:m.start()].count("\n") + 1
            line_content = lines[line_num - 1] if line_num <= len(lines) else ""
            matches.append(PatternMatch(
                file=rel_path,
                pattern="high_entropy_string",
                severity="MEDIUM",
                desc=f"고 엔트로피 문자열(entropy={ent:.2f}) — Base64/암호화 데이터 의심",
                line_num=line_num,
                line=line_content.strip()[:100],
            ))

    return matches


# ---------------------------------------------------------------------------
# 확장프로그램 디렉토리 순회
# ---------------------------------------------------------------------------

def iter_js_files(ext_path: Path) -> Iterator[tuple[Path, str]]:
    """확장프로그램 디렉토리에서 JS 파일을 순회한다."""
    for js_file in ext_path.rglob("*.js"):
        rel = str(js_file.relative_to(ext_path))
        yield js_file, rel


def extract_crx(crx_path: Path, dest_dir: Path) -> Path | None:
    """
    .crx 파일을 ZIP으로 추출한다.
    CRX3 헤더(4바이트 magic + 4바이트 version + 4바이트 header_len)를 건너뛴다.
    """
    if not crx_path.suffix.lower() == ".crx":
        return None
    try:
        raw = crx_path.read_bytes()
        # CRX3: "Cr24" + version(4) + header_size(4) = 12 바이트 + header_size
        if raw[:4] == b"Cr24":
            import struct
            header_len = struct.unpack_from("<I", raw, 8)[0]
            zip_start  = 12 + header_len
        else:
            zip_start = 0

        zip_data   = raw[zip_start:]
        dest_dir.mkdir(parents=True, exist_ok=True)
        import io
        with zipfile.ZipFile(io.BytesIO(zip_data)) as zf:
            zf.extractall(dest_dir)
        return dest_dir
    except Exception as exc:
        print(f"[!] CRX 추출 실패: {exc}", file=sys.stderr)
        return None


# ---------------------------------------------------------------------------
# 분석 실행
# ---------------------------------------------------------------------------

def run_analysis(
    ext_path: Path,
    checks: list[str],
) -> AnalysisReport:
    """
    확장프로그램 경로를 분석하고 AnalysisReport를 반환한다.
    checks는 ["permissions", "code", "manifest"] 중 하나 이상.
    """
    manifest_path = ext_path / "manifest.json"
    if not manifest_path.exists():
        print(f"[!] manifest.json을 찾을 수 없습니다: {manifest_path}", file=sys.stderr)
        sys.exit(1)

    try:
        manifest: dict[str, Any] = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"[!] manifest.json 파싱 오류: {exc}", file=sys.stderr)
        sys.exit(1)

    report = AnalysisReport(
        extension_name=manifest.get("name", "알 수 없음"),
        extension_version=manifest.get("version", "알 수 없음"),
        manifest_version=manifest.get("manifest_version", 2),
        path=str(ext_path),
    )

    # 파일 수 집계
    all_files = list(ext_path.rglob("*"))
    report.file_count    = sum(1 for f in all_files if f.is_file())
    report.js_file_count = sum(1 for f in all_files if f.suffix == ".js")

    # 권한 분석
    if "permissions" in checks or "manifest" in checks:
        report.permission_findings = analyze_manifest(manifest)

    # JS 코드 분석
    if "code" in checks:
        for js_file, rel_path in iter_js_files(ext_path):
            report.pattern_findings.extend(analyze_js_file(js_file, rel_path))

    report.compute_score()
    return report


# ---------------------------------------------------------------------------
# 결과 출력
# ---------------------------------------------------------------------------

def print_report(report: AnalysisReport) -> None:
    """분석 보고서를 사람이 읽기 쉬운 형식으로 출력한다."""
    print("=" * 65)
    print(f"  브라우저 확장프로그램 보안 분석 보고서")
    print("=" * 65)
    print(f"  이름        : {report.extension_name}")
    print(f"  버전        : {report.extension_version}")
    print(f"  Manifest V  : {report.manifest_version}")
    print(f"  경로        : {report.path}")
    print(f"  총 파일     : {report.file_count}개 (JS: {report.js_file_count}개)")
    print(f"  위험 점수   : {report.risk_score}/100  [{report.risk_level()}]")
    print("=" * 65)

    if report.permission_findings:
        print(f"\n[권한 분석] — {len(report.permission_findings)}건")
        for pf in sorted(report.permission_findings, key=lambda x: x.severity):
            print(f"  [{pf.severity}] {pf.permission}")
            print(f"           → {pf.context}")

    if report.pattern_findings:
        print(f"\n[코드 패턴 분석] — {len(report.pattern_findings)}건")
        # 심각도 순 정렬
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        sorted_findings = sorted(
            report.pattern_findings,
            key=lambda x: order.get(x.severity, 99),
        )
        for mf in sorted_findings:
            print(f"  [{mf.severity}] {mf.file}:{mf.line_num} — {mf.desc}")
            if mf.line:
                print(f"           코드: {mf.line}")

    if not report.permission_findings and not report.pattern_findings:
        print("\n[+] 위험 항목이 발견되지 않았습니다.")

    print()


def export_json(report: AnalysisReport, out_path: Path) -> None:
    data = {
        "extension_name":    report.extension_name,
        "extension_version": report.extension_version,
        "manifest_version":  report.manifest_version,
        "path":              report.path,
        "file_count":        report.file_count,
        "js_file_count":     report.js_file_count,
        "risk_score":        report.risk_score,
        "risk_level":        report.risk_level(),
        "permission_findings": [
            {"permission": p.permission, "severity": p.severity, "context": p.context}
            for p in report.permission_findings
        ],
        "pattern_findings": [
            {
                "file": m.file, "line": m.line_num,
                "pattern": m.pattern, "severity": m.severity,
                "desc": m.desc, "code": m.line,
            }
            for m in report.pattern_findings
        ],
    }
    out_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[+] JSON 보고서 저장: {out_path}")


# ---------------------------------------------------------------------------
# CLI 진입점
# ---------------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ext_analyzer",
        description="브라우저 확장프로그램 정적 분석기 — 권한/코드/Manifest 위험 탐지",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
예시:
  # 압축 해제된 확장 디렉토리 전체 분석
  python3 04_browser_extension_advanced.py \\
      --extension-path ./my_extension \\
      --check permissions code manifest

  # 권한만 점검 후 JSON 저장
  python3 04_browser_extension_advanced.py \\
      --extension-path ./my_extension \\
      --check permissions --output report.json

  # .crx 파일 직접 분석 (임시 디렉토리에 추출)
  python3 04_browser_extension_advanced.py \\
      --extension-path ./suspicious.crx \\
      --check permissions code manifest
        """,
    )
    parser.add_argument(
        "--extension-path",
        type=Path,
        required=True,
        help="분석할 확장프로그램 디렉토리 또는 .crx 파일 경로",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="분석 결과 JSON 저장 경로 (생략 시 stdout 텍스트 출력)",
    )
    parser.add_argument(
        "--check",
        nargs="+",
        choices=["permissions", "code", "manifest"],
        default=["permissions", "code", "manifest"],
        help="점검 항목 (복수 선택 가능, 기본값: 모두)",
    )
    return parser


def main() -> None:
    parser = build_arg_parser()
    args   = parser.parse_args()

    ext_path: Path = args.extension_path.expanduser().resolve()

    # .crx 파일이면 추출
    tmp_dir: Path | None = None
    if ext_path.suffix.lower() == ".crx":
        tmp_dir  = Path("/tmp") / f"ext_analysis_{ext_path.stem}"
        extracted = extract_crx(ext_path, tmp_dir)
        if extracted is None:
            print("[!] CRX 추출에 실패했습니다.", file=sys.stderr)
            sys.exit(1)
        ext_path = extracted
        print(f"[+] CRX 추출 완료: {ext_path}")

    if not ext_path.is_dir():
        print(f"[!] 디렉토리가 아닙니다: {ext_path}", file=sys.stderr)
        sys.exit(1)

    print(f"[+] 분석 시작: {ext_path}")
    report = run_analysis(ext_path, args.check)

    if args.output:
        export_json(report, args.output)
    else:
        print_report(report)

    # 임시 디렉토리 정리
    if tmp_dir and tmp_dir.exists():
        import shutil
        shutil.rmtree(tmp_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
```

---

## 5. 확장프로그램 보안 강화 권고

| 권고 사항 | 대상 | 설명 |
|-----------|------|------|
| 최소 권한 원칙 | 개발자 | 필요한 host_permissions만 선언 |
| Manifest V3 전환 | 개발자 | 원격 코드 실행 차단, 선언적 규칙 사용 |
| 서드파티 확장 제한 | 기업 관리자 | Group Policy로 허용 목록만 설치 |
| 확장 정기 감사 | 보안팀 | 설치된 확장 권한 주기적 검토 |
| 코드 서명 검증 | 스토어 | 확장 업데이트 서명 필수화 |
| 행동 기반 탐지 | 보안 제품 | 런타임에서 이상 API 호출 탐지 |

---

## 6. 참고 자료

- Chrome Extension Manifest V3 Migration (https://developer.chrome.com/docs/extensions/mv3/intro/)
- DataSpii Analysis — Sam Jadali (2019)
- "Malicious Browser Extensions" — USENIX Security 2012
- Chrome Web Store Policy (https://developer.chrome.com/docs/webstore/program_policies/)
- Firefox Extension Workshop Security (https://extensionworkshop.com/documentation/develop/build-a-secure-extension/)

---

<a name="english"></a>

# Advanced Browser Extension Attacks

## 1. Manifest V2 vs V3 Security Comparison

### 1.1 Key Differences Comparison Table

| Item | Manifest V2 | Manifest V3 | Security Impact |
|------|-------------|-------------|-----------------|
| Background script | Persistent background page | Service Worker | Persistent execution restricted in V3 |
| Remote code execution | Remote URL scripts allowed | Remote code execution prohibited | Dynamic code injection blocked in V3 |
| Content script injection | tabs.executeScript() | scripting.executeScript() | Declarative approach recommended in V3 |
| Network request intercept | webRequest API (blocking) | declarativeNetRequest | Blocking rules declaratively restricted in V3 |
| host_permissions | Included in permissions | Separate host_permissions | Runtime permission requests possible in V3 |
| eval() usage | Allowed with restrictions | Completely prohibited | Code injection blocked in V3 |
| Cross-origin XHR | Allowed within permissions | Uses fetch(), stricter limits | CORS enforcement strengthened in V3 |
| Storage | chrome.storage, localStorage | chrome.storage only | Access restricted in V3 |
| Update mechanism | Auto-update applied immediately | Enhanced review | V3 store review strengthened |
| Lifecycle | Always running | Event-driven, short lifetime | Persistent malware harder in V3 |

### 1.2 Attack Surface Changes: V2 vs V3

The transition to V3 enhances security, but is not a complete solution.

**Attacks still possible in V3:**
- Access all sites via `host_permissions` (`<all_urls>`)
- DOM manipulation and keylogging through content scripts
- Cookie theft via `chrome.cookies` API (when permissions acquired)
- Data collection via `chrome.history`, `chrome.bookmarks`
- Network surveillance using `chrome.webRequest` in read-only mode

---

## 2. Malicious Extension Detection Techniques

### 2.1 Behavioral Analysis Indicators

| Behavior Pattern | Description | Risk Level | Detection Method |
|-----------------|-------------|------------|------------------|
| Form data sniffing | Password collection via input event listeners | Critical | DOM event monitoring |
| Cookie remote transmission | chrome.cookies → fetch() to external host | Critical | Network traffic analysis |
| Screen capture | Repeated chrome.tabs.captureVisibleTab() calls | High | API call frequency analysis |
| Clipboard reading | document.execCommand('copy') or Clipboard API | High | Permission + API call |
| Browser history collection | Repeated chrome.history.search() | Medium | API call pattern |
| Dynamic code generation | eval() / new Function() usage | High | Static code analysis |
| Obfuscated code | Hex encoding, substitution ciphers | High | Entropy analysis |
| External domain communication | Data sent to unknown domains | High | Domain reputation analysis |
| Dynamic permission requests | Additional permission requests at runtime | Medium | Permission change monitoring |
| Cross-extension messaging | chrome.runtime.sendMessage targeting other extensions | Medium | Message target analysis |

### 2.2 Code Obfuscation Detection Techniques

| Obfuscation Technique | Characteristics | Detection Method | Tool |
|----------------------|-----------------|------------------|------|
| Variable name compression | Meaningless 1-2 char variables (a, b, c) | Entropy, length distribution | js-beautify |
| String splitting | "mal"+"ware" format | Static analysis | AST analysis |
| Hex encoding | "\x65\x76\x61\x6c" (eval) | Regex detection | grep/regex |
| Base64 encoding | Decoded with atob() then executed | atob call detection | Static analysis |
| Dynamic key access | obj["ev"+"al"]() | String concatenation pattern | AST analysis |
| Code minification | UglifyJS/Terser output | Line length | Entropy |
| Proxy pattern | Intercepting API calls via Proxy object | Proxy usage | AST analysis |

### 2.3 Cross-Extension Attack Patterns

Because Chrome extensions can communicate with each other, a malicious extension can send messages to a trusted extension to abuse its permissions.

**Attack scenario:**
1. Low-privilege malicious extension A is installed
2. Message sent to high-privilege trusted extension B
3. Extension B processes the message without validation
4. Sensitive operations performed with extension B's permissions

```javascript
// Message transmission from malicious extension (conceptual example)
chrome.runtime.sendMessage(
    "trusted_extension_ID_abcdefgh",
    { action: "fetch_cookies", domain: ".bank.com" },
    (response) => { exfiltrate(response.data); }
);
```

---

## 3. Extension Permission Abuse Cases

### 3.1 Permission Abuse Classification Table

| Permission | Legitimate Use | Abuse Method | Real-World Case |
|------------|----------------|--------------|-----------------|
| `<all_urls>` | Script injection into all sites | Keylogging, form data collection | DataSpii (2019) |
| `cookies` | Session management | Authentication cookie theft | Session Hijacking |
| `history` | Visit history analysis | Browsing behavior profiling | DataSpii (2019) |
| `tabs` | Tab list access | User activity surveillance | Numerous adware |
| `webRequest` | Request monitoring | Network traffic sniffing | Phishing detection abuse |
| `downloads` | Download management | File theft, malicious file download | Downloader malware |
| `notifications` | Display notifications | Phishing alerts, ads | Clickjacking fraud |
| `geolocation` | Location-based services | User location tracking | Spyware |
| `clipboardRead` | Access copied data | Password/address theft | Clipboard hijackers |
| `nativeMessaging` | Native app communication | Local file access, code execution | Advanced APT malware |

### 3.2 Real-World Malicious Extension Cases

| Name/Campaign | Year | Impact Scale | Key Permission Abused | Detection Method |
|--------------|------|-------------|----------------------|------------------|
| DataSpii | 2019 | Millions of users | `<all_urls>`, history | Network traffic analysis |
| The Great Suspender | 2020 | ~2M installs | Remote code execution | Code change detection |
| Nigelthorn | 2018 | 100K+ | tabs, webRequest | Social media propagation |
| ChromeBack | 2021 | Unknown | cookies, tabs | Store automated detection |
| CacheFlow | 2020 | 3M+ | `<all_urls>` | Dynamic analysis |

---

## 4. Python CLI: Browser Extension Static Analyzer

```python
#!/usr/bin/env python3
"""
Browser Extension Static Analyzer
Analyzes a local extension directory (including extracted .crx files)
to detect dangerous permissions, code patterns, obfuscation, and data exfiltration attempts.
"""

from __future__ import annotations

import argparse
import ast
import json
import math
import os
import re
import sys
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator


# ---------------------------------------------------------------------------
# Dangerous permission definitions
# ---------------------------------------------------------------------------

CRITICAL_PERMISSIONS: set[str] = {
    "<all_urls>", "cookies", "nativeMessaging",
    "clipboardRead", "downloads", "management",
}
HIGH_PERMISSIONS: set[str] = {
    "tabs", "webRequest", "webRequestBlocking", "history",
    "bookmarks", "topSites", "browsingData",
}
MEDIUM_PERMISSIONS: set[str] = {
    "notifications", "geolocation", "contextMenus",
    "activeTab", "identity", "proxy",
}

# ---------------------------------------------------------------------------
# Dangerous JS patterns
# ---------------------------------------------------------------------------

DANGEROUS_JS_PATTERNS: list[dict[str, Any]] = [
    {
        "name":     "eval_usage",
        "pattern":  re.compile(r"\beval\s*\(", re.MULTILINE),
        "severity": "HIGH",
        "desc":     "eval() usage — dynamic code execution risk",
    },
    {
        "name":     "new_function",
        "pattern":  re.compile(r"new\s+Function\s*\(", re.MULTILINE),
        "severity": "HIGH",
        "desc":     "new Function() usage — dynamic code execution risk",
    },
    {
        "name":     "hex_encoded_strings",
        "pattern":  re.compile(r'["\']\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){4,}["\']'),
        "severity": "HIGH",
        "desc":     "Long hex-encoded string — suspected obfuscation",
    },
    {
        "name":     "atob_decode",
        "pattern":  re.compile(r"\batob\s*\(", re.MULTILINE),
        "severity": "MEDIUM",
        "desc":     "atob() usage — possible Base64 decode then execute",
    },
    {
        "name":     "exfiltration_fetch",
        "pattern":  re.compile(
            r"fetch\s*\(\s*['\"]https?://(?!(?:www\.)?google|(?:www\.)?microsoft|(?:www\.)?mozilla)",
            re.MULTILINE,
        ),
        "severity": "HIGH",
        "desc":     "fetch() call to suspicious external domain — possible data exfiltration",
    },
    {
        "name":     "xmlhttprequest_open",
        "pattern":  re.compile(r"\.open\s*\(\s*['\"](?:POST|PUT)['\"]", re.MULTILINE | re.IGNORECASE),
        "severity": "MEDIUM",
        "desc":     "XMLHttpRequest POST/PUT — possible data transmission",
    },
    {
        "name":     "clipboard_read",
        "pattern":  re.compile(r"navigator\.clipboard\.readText|document\.execCommand\s*\(\s*['\"]paste['\"]", re.MULTILINE),
        "severity": "HIGH",
        "desc":     "Clipboard read API usage",
    },
    {
        "name":     "password_selector",
        "pattern":  re.compile(r'querySelector\s*\([\'"]input\[type=[\'"]?password', re.MULTILINE),
        "severity": "CRITICAL",
        "desc":     "Direct access to password input field — keylogger pattern",
    },
    {
        "name":     "cookie_access",
        "pattern":  re.compile(r"\bdocument\.cookie\b", re.MULTILINE),
        "severity": "HIGH",
        "desc":     "Direct document.cookie access",
    },
    {
        "name":     "dynamic_script_inject",
        "pattern":  re.compile(r"document\.createElement\s*\(\s*['\"]script['\"]", re.MULTILINE),
        "severity": "MEDIUM",
        "desc":     "Dynamic script tag creation — code injection risk",
    },
    {
        "name":     "send_message_external",
        "pattern":  re.compile(r"chrome\.runtime\.sendMessage\s*\(\s*['\"][a-z]{32}['\"]", re.MULTILINE),
        "severity": "MEDIUM",
        "desc":     "Message sent to another extension — possible cross-extension attack",
    },
    {
        "name":     "obfuscated_string_concat",
        "pattern":  re.compile(r'["\'][a-z]{1,4}["\']\s*\+\s*["\'][a-z]{1,4}["\'](?:\s*\+\s*["\'][a-z]{1,4}["\']){2,}', re.MULTILINE),
        "severity": "MEDIUM",
        "desc":     "Short string concatenation — suspected obfuscation",
    },
    {
        "name":     "native_messaging_connect",
        "pattern":  re.compile(r"chrome\.runtime\.connectNative\s*\(", re.MULTILINE),
        "severity": "HIGH",
        "desc":     "Connection to native app — possible local system access",
    },
]


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class PatternMatch:
    file:     str
    pattern:  str
    severity: str
    desc:     str
    line_num: int
    line:     str


@dataclass
class PermissionFinding:
    permission: str
    severity:   str
    context:    str


@dataclass
class AnalysisReport:
    extension_name:     str
    extension_version:  str
    manifest_version:   int
    path:               str
    permission_findings: list[PermissionFinding] = field(default_factory=list)
    pattern_findings:   list[PatternMatch] = field(default_factory=list)
    file_count:         int = 0
    js_file_count:      int = 0
    risk_score:         int = 0

    def compute_score(self) -> None:
        score = 0
        sev_map = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3}
        for pf in self.permission_findings:
            score += sev_map.get(pf.severity, 0)
        for mf in self.pattern_findings:
            score += sev_map.get(mf.severity, 0)
        self.risk_score = min(100, score)

    def risk_level(self) -> str:
        if self.risk_score >= 70:
            return "CRITICAL"
        if self.risk_score >= 45:
            return "HIGH"
        if self.risk_score >= 20:
            return "MEDIUM"
        return "LOW"


def analyze_manifest(manifest: dict[str, Any]) -> list[PermissionFinding]:
    findings: list[PermissionFinding] = []
    all_perms: list[str] = []
    all_perms.extend(manifest.get("permissions", []))
    all_perms.extend(manifest.get("host_permissions", []))
    all_perms.extend(manifest.get("optional_permissions", []))

    for perm in all_perms:
        if perm in CRITICAL_PERMISSIONS:
            findings.append(PermissionFinding(perm, "CRITICAL", "manifest.json permissions"))
        elif perm in HIGH_PERMISSIONS:
            findings.append(PermissionFinding(perm, "HIGH", "manifest.json permissions"))
        elif perm in MEDIUM_PERMISSIONS:
            findings.append(PermissionFinding(perm, "MEDIUM", "manifest.json permissions"))
        elif re.match(r"https?://\*/", perm) or re.match(r"\*://\*/", perm):
            findings.append(PermissionFinding(perm, "HIGH", "Wildcard host permission"))

    csp = manifest.get("content_security_policy", "")
    if isinstance(csp, dict):
        csp = " ".join(csp.values())
    if "unsafe-eval" in csp:
        findings.append(PermissionFinding("CSP:unsafe-eval", "HIGH", "unsafe-eval in content_security_policy"))
    if "unsafe-inline" in csp:
        findings.append(PermissionFinding("CSP:unsafe-inline", "MEDIUM", "unsafe-inline in content_security_policy"))

    bg = manifest.get("background", {})
    if bg.get("persistent", False) and manifest.get("manifest_version", 2) == 2:
        findings.append(PermissionFinding("background.persistent=true", "MEDIUM", "Persistent background script (MV2)"))

    return findings


def shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string (higher = more likely obfuscated)."""
    if not text:
        return 0.0
    freq: dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def analyze_js_file(js_path: Path, rel_path: str) -> list[PatternMatch]:
    """Detect dangerous patterns in a single JS file."""
    matches: list[PatternMatch] = []
    try:
        content = js_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return matches

    lines = content.splitlines()
    for rule in DANGEROUS_JS_PATTERNS:
        for m in rule["pattern"].finditer(content):
            line_num = content[:m.start()].count("\n") + 1
            line_content = lines[line_num - 1] if line_num <= len(lines) else ""
            matches.append(PatternMatch(
                file=rel_path, pattern=rule["name"], severity=rule["severity"],
                desc=rule["desc"], line_num=line_num, line=line_content.strip()[:100],
            ))

    long_string_re = re.compile(r'["\']([A-Za-z0-9+/=]{60,})["\']')
    for m in long_string_re.finditer(content):
        s = m.group(1)
        ent = shannon_entropy(s)
        if ent > 5.0:
            line_num = content[:m.start()].count("\n") + 1
            line_content = lines[line_num - 1] if line_num <= len(lines) else ""
            matches.append(PatternMatch(
                file=rel_path, pattern="high_entropy_string", severity="MEDIUM",
                desc=f"High-entropy string (entropy={ent:.2f}) — suspected Base64/encrypted data",
                line_num=line_num, line=line_content.strip()[:100],
            ))
    return matches


def iter_js_files(ext_path: Path) -> Iterator[tuple[Path, str]]:
    for js_file in ext_path.rglob("*.js"):
        rel = str(js_file.relative_to(ext_path))
        yield js_file, rel


def extract_crx(crx_path: Path, dest_dir: Path) -> Path | None:
    if not crx_path.suffix.lower() == ".crx":
        return None
    try:
        raw = crx_path.read_bytes()
        if raw[:4] == b"Cr24":
            import struct
            header_len = struct.unpack_from("<I", raw, 8)[0]
            zip_start = 12 + header_len
        else:
            zip_start = 0
        zip_data = raw[zip_start:]
        dest_dir.mkdir(parents=True, exist_ok=True)
        import io
        with zipfile.ZipFile(io.BytesIO(zip_data)) as zf:
            zf.extractall(dest_dir)
        return dest_dir
    except Exception as exc:
        print(f"[!] CRX extraction failed: {exc}", file=sys.stderr)
        return None


def run_analysis(ext_path: Path, checks: list[str]) -> AnalysisReport:
    manifest_path = ext_path / "manifest.json"
    if not manifest_path.exists():
        print(f"[!] manifest.json not found: {manifest_path}", file=sys.stderr)
        sys.exit(1)
    try:
        manifest: dict[str, Any] = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"[!] manifest.json parse error: {exc}", file=sys.stderr)
        sys.exit(1)

    report = AnalysisReport(
        extension_name=manifest.get("name", "Unknown"),
        extension_version=manifest.get("version", "Unknown"),
        manifest_version=manifest.get("manifest_version", 2),
        path=str(ext_path),
    )
    all_files = list(ext_path.rglob("*"))
    report.file_count = sum(1 for f in all_files if f.is_file())
    report.js_file_count = sum(1 for f in all_files if f.suffix == ".js")

    if "permissions" in checks or "manifest" in checks:
        report.permission_findings = analyze_manifest(manifest)
    if "code" in checks:
        for js_file, rel_path in iter_js_files(ext_path):
            report.pattern_findings.extend(analyze_js_file(js_file, rel_path))

    report.compute_score()
    return report


def print_report(report: AnalysisReport) -> None:
    print("=" * 65)
    print(f"  Browser Extension Security Analysis Report")
    print("=" * 65)
    print(f"  Name          : {report.extension_name}")
    print(f"  Version       : {report.extension_version}")
    print(f"  Manifest V    : {report.manifest_version}")
    print(f"  Path          : {report.path}")
    print(f"  Total files   : {report.file_count} (JS: {report.js_file_count})")
    print(f"  Risk score    : {report.risk_score}/100  [{report.risk_level()}]")
    print("=" * 65)

    if report.permission_findings:
        print(f"\n[Permission Analysis] — {len(report.permission_findings)} findings")
        for pf in sorted(report.permission_findings, key=lambda x: x.severity):
            print(f"  [{pf.severity}] {pf.permission}")
            print(f"           → {pf.context}")

    if report.pattern_findings:
        print(f"\n[Code Pattern Analysis] — {len(report.pattern_findings)} findings")
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        sorted_findings = sorted(report.pattern_findings, key=lambda x: order.get(x.severity, 99))
        for mf in sorted_findings:
            print(f"  [{mf.severity}] {mf.file}:{mf.line_num} — {mf.desc}")
            if mf.line:
                print(f"           Code: {mf.line}")

    if not report.permission_findings and not report.pattern_findings:
        print("\n[+] No risky items found.")
    print()


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ext_analyzer",
        description="Browser Extension Static Analyzer — Permission/Code/Manifest Risk Detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full analysis of unpacked extension directory
  python3 04_browser_extension_advanced.py \\
      --extension-path ./my_extension \\
      --check permissions code manifest

  # Permission check only, save JSON
  python3 04_browser_extension_advanced.py \\
      --extension-path ./my_extension \\
      --check permissions --output report.json

  # Analyze .crx file directly (extracted to temp dir)
  python3 04_browser_extension_advanced.py \\
      --extension-path ./suspicious.crx \\
      --check permissions code manifest
        """,
    )
    parser.add_argument("--extension-path", type=Path, required=True,
                        help="Extension directory or .crx file path to analyze")
    parser.add_argument("--output", type=Path, default=None,
                        help="Path to save JSON report (stdout text output if omitted)")
    parser.add_argument("--check", nargs="+",
                        choices=["permissions", "code", "manifest"],
                        default=["permissions", "code", "manifest"],
                        help="Check items (multiple allowed, default: all)")
    return parser


def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()
    ext_path: Path = args.extension_path.expanduser().resolve()

    tmp_dir: Path | None = None
    if ext_path.suffix.lower() == ".crx":
        tmp_dir = Path("/tmp") / f"ext_analysis_{ext_path.stem}"
        extracted = extract_crx(ext_path, tmp_dir)
        if extracted is None:
            print("[!] CRX extraction failed.", file=sys.stderr)
            sys.exit(1)
        ext_path = extracted
        print(f"[+] CRX extracted: {ext_path}")

    if not ext_path.is_dir():
        print(f"[!] Not a directory: {ext_path}", file=sys.stderr)
        sys.exit(1)

    print(f"[+] Starting analysis: {ext_path}")
    report = run_analysis(ext_path, args.check)

    if args.output:
        data = {
            "extension_name": report.extension_name,
            "extension_version": report.extension_version,
            "manifest_version": report.manifest_version,
            "path": report.path,
            "file_count": report.file_count,
            "js_file_count": report.js_file_count,
            "risk_score": report.risk_score,
            "risk_level": report.risk_level(),
            "permission_findings": [
                {"permission": p.permission, "severity": p.severity, "context": p.context}
                for p in report.permission_findings
            ],
            "pattern_findings": [
                {"file": m.file, "line": m.line_num, "pattern": m.pattern,
                 "severity": m.severity, "desc": m.desc, "code": m.line}
                for m in report.pattern_findings
            ],
        }
        args.output.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"[+] JSON report saved: {args.output}")
    else:
        print_report(report)

    if tmp_dir and tmp_dir.exists():
        import shutil
        shutil.rmtree(tmp_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
```

---

## 5. Extension Security Hardening Recommendations

| Recommendation | Target | Description |
|---------------|--------|-------------|
| Principle of least privilege | Developers | Declare only the necessary host_permissions |
| Migrate to Manifest V3 | Developers | Block remote code execution, use declarative rules |
| Restrict third-party extensions | Enterprise admins | Install only allowlisted extensions via Group Policy |
| Regular extension audits | Security team | Periodically review permissions of installed extensions |
| Code signature verification | Store | Mandate signing for extension updates |
| Behavior-based detection | Security products | Detect anomalous API calls at runtime |

---

## 6. References

- Chrome Extension Manifest V3 Migration (https://developer.chrome.com/docs/extensions/mv3/intro/)
- DataSpii Analysis — Sam Jadali (2019)
- "Malicious Browser Extensions" — USENIX Security 2012
- Chrome Web Store Policy (https://developer.chrome.com/docs/webstore/program_policies/)
- Firefox Extension Workshop Security (https://extensionworkshop.com/documentation/develop/build-a-secure-extension/)
