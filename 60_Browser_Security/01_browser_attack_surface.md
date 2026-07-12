> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 브라우저 공격 표면 분석

## 0. 초보자를 위한 개념 이해

### 브라우저 공격 표면이란?

브라우저 공격 표면은 악의적인 웹 페이지나 파일이 브라우저를 통해 사용자의 시스템을 공격할 수 있는 모든 진입점의 집합이다. JavaScript 엔진, 렌더링 엔진, PDF 파서, 오디오/비디오 코덱, 확장프로그램 API 등 수백만 줄의 복잡한 코드가 신뢰할 수 없는 웹 콘텐츠를 처리하기 때문에 지속적으로 새로운 취약점이 발견된다.

**왜 배우는가:**
```
[브라우저 공격 경로]

악성 웹사이트
     │
     ▼
브라우저 렌더러 프로세스 (낮은 권한)
  ├─ JavaScript 엔진 (V8/SpiderMonkey) → JIT 버그, UAF
  ├─ HTML/CSS 파서 → 파싱 버그
  ├─ 미디어 코덱 → 버퍼 오버플로우
  └─ WebGL/WebAssembly → GPU 공격

     │ 렌더러 익스플로잇 성공
     ▼
샌드박스 탈출 시도 → 브라우저 프로세스 침해
     │ 샌드박스 탈출 성공
     ▼
OS 권한 획득 → 전체 시스템 장악

이것이 "브라우저 풀체인 익스플로잇"이며
최고 수준의 제로데이 취약점으로 거래됨 (수십억 원 가치)
```

### 핵심 개념 정리

```
주요 용어:
- 렌더러 프로세스: 웹 콘텐츠를 처리하는 격리된 프로세스 (낮은 권한)
- 샌드박스: 렌더러가 OS에 직접 접근하지 못하게 격리하는 보안 경계
- UAF(Use-After-Free): 해제된 메모리를 재사용하는 메모리 오염 취약점
- UXSS(Universal Cross-Site Scripting): 브라우저 자체의 버그로 SOP를 우회하는 공격
- 사이트 격리(Site Isolation): 각 사이트를 별도 프로세스에서 실행하는 보안 기능
- JIT(Just-In-Time) 컴파일러: JS를 기계어로 실시간 변환 - 복잡성으로 취약점 다수
- Spectre/Meltdown: 투기적 실행 기반 브라우저 정보 유출 공격
```

### 필요한 도구 및 환경
- **Chromium 소스코드**: https://chromium.googlesource.com/chromium/src
- **WinDBG / GDB**: 브라우저 프로세스 디버깅
- **JavaScript 디버거**: Chrome DevTools의 JS 디버거
- **AddressSanitizer**: 메모리 오류 탐지 (빌드 시 -fsanitize=address)

### 기초 실습 예제
```python
"""
브라우저 공격 표면 분석 - 교육용 개념 시연
실제 브라우저 취약점 연구는 Chromium Bug Tracker(crbug.com)의
공개된 취약점 리포트를 참조하세요
"""

def analyze_browser_attack_surface():
    """
    브라우저의 주요 공격 표면 카테고리와 관련 CVE 유형 정리
    """
    attack_surfaces = {
        "JavaScript 엔진 (V8)": {
            "컴포넌트": ["JIT 컴파일러", "가비지 컬렉터", "파서", "런타임"],
            "취약점 유형": ["UAF", "타입 컨퓨전", "OOB 읽기/쓰기", "정수 오버플로우"],
            "최근 CVE 예시": "CVE-2021-21220 (V8 타입 컨퓨전)",
            "CVE 빈도": "매우 높음",
        },
        "HTML/CSS 렌더링 (Blink)": {
            "컴포넌트": ["DOM 파서", "레이아웃 엔진", "CSS 처리기"],
            "취약점 유형": ["UAF", "힙 오버플로우", "로직 버그"],
            "최근 CVE 예시": "CVE-2022-0609 (Animation UAF)",
            "CVE 빈도": "높음",
        },
        "미디어 코덱": {
            "컴포넌트": ["MP4/WebM 파서", "오디오 디코더", "이미지 파서"],
            "취약점 유형": ["버퍼 오버플로우", "OOB 읽기"],
            "최근 CVE 예시": "libpng/libwebp 취약점",
            "CVE 빈도": "중간",
        },
        "브라우저 확장프로그램 API": {
            "컴포넌트": ["Chrome Extension API", "WebExtension API"],
            "취약점 유형": ["권한 상승", "데이터 유출", "악성 확장"],
            "최근 CVE 예시": "악성 확장으로 인한 정보 탈취",
            "CVE 빈도": "중간",
        },
        "WebAssembly": {
            "컴포넌트": ["WASM 컴파일러", "런타임", "JIT"],
            "취약점 유형": ["OOB 접근", "타입 컨퓨전"],
            "최근 CVE 예시": "WASM JIT 메모리 오염",
            "CVE 빈도": "낮음 (증가 추세)",
        },
    }

    print("=== 브라우저 공격 표면 분석 ===\n")
    for surface, info in attack_surfaces.items():
        print(f"[{surface}]")
        print(f"  컴포넌트: {', '.join(info['컴포넌트'])}")
        print(f"  주요 취약점: {', '.join(info['취약점 유형'])}")
        print(f"  CVE 예시: {info['최근 CVE 예시']}")
        print(f"  발생 빈도: {info['CVE 빈도']}")
        print()

    print("=== 보안 연구 학습 경로 ===")
    print("1. Chrome Bug Tracker(crbug.com) 공개된 보안 버그 분석")
    print("2. Project Zero 블로그 취약점 분석 보고서 연구")
    print("3. CTF의 Browser 카테고리 문제 풀기")
    print("4. Chromium 디버그 빌드로 PoC 재현 실습")

analyze_browser_attack_surface()
```

---

## 1. 브라우저 아키텍처 개요

현대 브라우저는 보안을 위해 다중 프로세스 아키텍처를 채택한다. Chromium 기반 브라우저는 브라우저 프로세스, 렌더러 프로세스, GPU 프로세스, 유틸리티 프로세스 등을 분리하여 한 컴포넌트의 침해가 전체 시스템으로 확산되지 않도록 설계한다.

### 1.1 주요 프로세스 역할 비교

| 프로세스 | 역할 | 권한 수준 | 샌드박스 여부 | 보안 위협 |
|----------|------|-----------|---------------|-----------|
| Browser Process | UI, 탭 관리, 파일 I/O, 네트워크 | 높음 (OS 수준) | 미적용 | 권한 상승의 최종 목표 |
| Renderer Process | HTML/CSS 파싱, JS 실행, DOM | 낮음 (샌드박스) | 적용 | XSS, JS 엔진 취약점 |
| GPU Process | WebGL, 가속 렌더링 | 중간 | 부분 적용 | GPU 드라이버 취약점 |
| Network Service | HTTP 요청, 캐시, 쿠키 | 중간 | 적용 | SSRF, 쿠키 탈취 |
| Plugin/Extension | 서드파티 기능 | 사용자 설정 | 제한적 | 악성 코드 실행 |
| Utility Process | 오디오, 인쇄, 파일 변환 | 낮음 | 적용 | 데이터 노출 |
| Zygote (Linux) | 프로세스 스포닝 | 중간 | 부분 | 샌드박스 우회 |

### 1.2 IPC (Inter-Process Communication) 통신 구조

렌더러 프로세스와 브라우저 프로세스는 Mojo IPC 프레임워크를 통해 통신한다. 이 통신 채널은 공격자가 렌더러를 장악한 후 브라우저 프로세스로 권한을 상승시키는 주요 경로다.

```
[Renderer Process] ←→ Mojo IPC ←→ [Browser Process]
       ↓                                    ↓
  샌드박스 내부                        OS 전체 접근
  (제한된 권한)                        (파일, 네트워크 등)
```

---

## 2. 공격 표면 분류

### 2.1 주요 공격 표면 분석표

| 공격 표면 | 설명 | 위험도 | 대표 취약점 유형 | 완화 기법 |
|-----------|------|--------|------------------|-----------|
| JavaScript 엔진 | V8/SpiderMonkey/JSC JIT 컴파일러 | 최상 | 타입 혼동, UAF, OOB | Sandbox, Site Isolation |
| DOM API | 웹 표준 API 구현체 | 상 | UAF, 레이스 컨디션 | 격리, CORS |
| IPC 인터페이스 | Mojo 바인딩, 메시지 처리 | 상 | 입력 검증 실패, TOCTOU | 인터페이스 감사 |
| 플러그인 (PDF, Flash) | NPAPI/PPAPI 구현체 | 상 | 힙 오버플로, 포맷 파싱 오류 | Flash 제거, PDF 격리 |
| 네트워크 스택 | HTTP/2, QUIC, WebSocket | 중 | 헤더 인젝션, SSRF | HSTS, Certificate Pinning |
| 렌더링 엔진 | Blink/Gecko CSS 처리 | 중 | OOB 읽기, 정보 유출 | 퍼징, 경계 검사 |
| 확장프로그램 API | chrome.*, browser.* API | 중 | 권한 남용, 메시지 스푸핑 | MV3 제한, 검토 정책 |
| WebAssembly | WASM 실행 환경 | 중 | 메모리 안전성, 타입 혼동 | 선형 메모리 모델 |
| Media 처리 | 비디오/오디오 디코더 | 중 | 파서 취약점, 힙 손상 | 미디어 프로세스 격리 |
| GPU 드라이버 | WebGL, WebGPU | 중 | 드라이버 버그, 정보 유출 | GPU 샌드박스 |
| 파일 시스템 API | File, IndexedDB, Cache | 하 | 경로 순회, 정보 유출 | 출처 격리 |
| DevTools 프로토콜 | CDP (Chrome DevTools Protocol) | 하-중 | 원격 코드 실행 (노출 시) | 인증, 로컬 바인딩 |

### 2.2 공격 표면별 진입점 상세

**JavaScript 엔진 진입점:**
- 웹 페이지의 `<script>` 태그 실행
- eval(), Function() 동적 코드 생성
- WebAssembly.compile() / instantiate()
- Service Worker 스크립트

**네트워크 스택 진입점:**
- HTTP/HTTPS 요청 헤더 파싱
- TLS 핸드셰이크 처리
- HTTP/2 HPACK 헤더 압축/해제
- WebSocket 프레임 처리

---

## 3. CVE 통계 및 역대 취약점 현황

### 3.1 Chrome (Chromium) 연도별 CVE 통계

| 연도 | 전체 CVE | Critical | High | Medium | Low | 주요 취약점 유형 |
|------|----------|----------|------|--------|-----|-----------------|
| 2019 | 186 | 8 | 85 | 72 | 21 | UAF, 힙 버퍼 오버플로 |
| 2020 | 276 | 3 | 143 | 95 | 35 | UAF, 부적절한 구현 |
| 2021 | 312 | 7 | 165 | 102 | 38 | UAF, OOB 읽기/쓰기 |
| 2022 | 276 | 5 | 145 | 98 | 28 | 타입 혼동, UAF |
| 2023 | 224 | 2 | 118 | 80 | 24 | OOB, 힙 손상 |
| 2024 | 198 | 3 | 98 | 74 | 23 | UAF, 정수 오버플로 |

### 3.2 Firefox (SpiderMonkey) 연도별 CVE 통계

| 연도 | 전체 CVE | Critical | High | Medium | Low | 주요 취약점 유형 |
|------|----------|----------|------|--------|-----|-----------------|
| 2019 | 281 | 15 | 98 | 126 | 42 | 메모리 안전성, XSS |
| 2020 | 194 | 9 | 76 | 89 | 20 | UAF, 버퍼 오버플로 |
| 2021 | 178 | 7 | 81 | 72 | 18 | 메모리 손상, CORS |
| 2022 | 161 | 5 | 74 | 61 | 21 | 스크립팅 취약점 |
| 2023 | 145 | 4 | 65 | 57 | 19 | OOB, 타입 혼동 |
| 2024 | 128 | 3 | 58 | 49 | 18 | 메모리 안전성 |

### 3.3 Safari (WebKit/JavaScriptCore) 연도별 CVE 통계

| 연도 | 전체 CVE | Critical | High | Medium | Low | 주요 취약점 유형 |
|------|----------|----------|------|--------|-----|-----------------|
| 2019 | 243 | 6 | 87 | 115 | 35 | 임의 코드 실행, 정보 유출 |
| 2020 | 231 | 4 | 91 | 108 | 28 | 메모리 손상, XSS |
| 2021 | 198 | 5 | 84 | 88 | 21 | UAF, 타입 혼동 |
| 2022 | 175 | 3 | 72 | 79 | 21 | 스크립팅, 메모리 |
| 2023 | 152 | 4 | 63 | 68 | 17 | 메모리 손상 |
| 2024 | 134 | 2 | 56 | 58 | 18 | 임의 코드 실행 |

### 3.4 주요 브라우저 구성 요소별 취약점 분포

| 구성 요소 | Chrome 비율 | Firefox 비율 | Safari 비율 | 공통 패턴 |
|-----------|-------------|-------------|------------|-----------|
| JS 엔진 | 28% | 31% | 35% | JIT, 파서 |
| 렌더링 엔진 | 22% | 19% | 21% | CSS, HTML 파싱 |
| IPC/샌드박스 | 15% | 11% | 8% | 메시지 검증 |
| 미디어 처리 | 12% | 14% | 13% | 디코더 파서 |
| 네트워크 스택 | 10% | 12% | 9% | HTTP 처리 |
| 기타 | 13% | 13% | 14% | 다양 |

---

## 4. Python CLI: 브라우저 보안 설정 감사기

```python
#!/usr/bin/env python3
"""
브라우저 보안 설정 감사기
Chrome 및 Firefox의 보안 관련 설정 파일을 읽어 위험 설정을 탐지한다.
"""

from __future__ import annotations

import argparse
import json
import sys
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


@dataclass
class AuditFinding:
    """단일 감사 항목 결과."""
    setting_key: str
    current_value: Any
    expected_value: Any
    severity: Severity
    description: str
    recommendation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "setting_key":   self.setting_key,
            "current_value": self.current_value,
            "expected_value": self.expected_value,
            "severity":      self.severity.value,
            "description":   self.description,
            "recommendation": self.recommendation,
        }


@dataclass
class AuditReport:
    """감사 보고서 전체 결과."""
    browser:   str
    profile:   str
    findings:  list[AuditFinding] = field(default_factory=list)

    @property
    def score(self) -> int:
        """100점 만점 보안 점수 계산."""
        deductions = {
            Severity.CRITICAL: 20,
            Severity.HIGH:     10,
            Severity.MEDIUM:    5,
            Severity.LOW:       2,
            Severity.INFO:      0,
        }
        total_deduction = sum(deductions[f.severity] for f in self.findings)
        return max(0, 100 - total_deduction)

    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts


# ---------------------------------------------------------------------------
# Chrome 감사 규칙
# ---------------------------------------------------------------------------

CHROME_RULES: list[dict[str, Any]] = [
    {
        "key":         "profile.default_content_setting_values.mixed_script",
        "bad_value":   1,
        "severity":    Severity.HIGH,
        "description": "Mixed Content Script 허용 설정이 활성화되어 있음",
        "recommendation": "Mixed script를 차단(0)하거나 기본값을 유지하세요.",
    },
    {
        "key":         "profile.default_content_setting_values.notifications",
        "bad_value":   1,
        "severity":    Severity.MEDIUM,
        "description": "모든 사이트의 알림 자동 허용이 설정됨",
        "recommendation": "알림을 사이트별로 묻도록(3) 변경하세요.",
    },
    {
        "key":         "safebrowsing.enabled",
        "bad_value":   False,
        "severity":    Severity.CRITICAL,
        "description": "Google Safe Browsing이 비활성화되어 있음",
        "recommendation": "Safe Browsing을 반드시 활성화(true)하세요.",
    },
    {
        "key":         "safebrowsing.enhanced",
        "bad_value":   False,
        "severity":    Severity.LOW,
        "description": "Safe Browsing 강화 보호 모드가 비활성화됨",
        "recommendation": "Enhanced Protection 활성화를 권장합니다.",
    },
    {
        "key":         "net.network_prediction_options",
        "bad_value":   0,
        "severity":    Severity.LOW,
        "description": "네트워크 예측(DNS Prefetch)이 항상 활성화됨",
        "recommendation": "네트워크 예측을 2(비활성화)로 설정하세요.",
    },
    {
        "key":         "profile.password_manager_enabled",
        "bad_value":   False,
        "severity":    Severity.INFO,
        "description": "내장 비밀번호 관리자가 비활성화됨",
        "recommendation": "외부 관리자를 사용 중이라면 문제 없습니다.",
    },
    {
        "key":         "sync.requested",
        "bad_value":   True,
        "severity":    Severity.MEDIUM,
        "description": "Google 계정 동기화가 활성화됨 (기업 환경 위험)",
        "recommendation": "기업 환경에서는 동기화를 비활성화하세요.",
    },
    {
        "key":         "extensions.ui.developer_mode",
        "bad_value":   True,
        "severity":    Severity.MEDIUM,
        "description": "확장프로그램 개발자 모드가 활성화됨",
        "recommendation": "프로덕션 환경에서는 개발자 모드를 비활성화하세요.",
    },
]

# ---------------------------------------------------------------------------
# Firefox 감사 규칙 (user.js / prefs.js 기준)
# ---------------------------------------------------------------------------

FIREFOX_RULES: list[dict[str, Any]] = [
    {
        "key":         "network.cookie.cookieBehavior",
        "bad_value":   0,
        "severity":    Severity.HIGH,
        "description": "서드파티 쿠키가 모두 허용됨",
        "recommendation": "cookieBehavior를 1(서드파티 차단) 이상으로 설정하세요.",
    },
    {
        "key":         "browser.privatebrowsing.autostart",
        "bad_value":   False,
        "severity":    Severity.INFO,
        "description": "자동 사생활 보호 모드가 비활성화됨",
        "recommendation": "민감한 환경에서는 자동 시작을 고려하세요.",
    },
    {
        "key":         "security.mixed_content.block_active_content",
        "bad_value":   False,
        "severity":    Severity.CRITICAL,
        "description": "Mixed Active Content 차단이 비활성화됨",
        "recommendation": "반드시 true로 설정하세요.",
    },
    {
        "key":         "security.mixed_content.block_display_content",
        "bad_value":   False,
        "severity":    Severity.MEDIUM,
        "description": "Mixed Passive Content 차단이 비활성화됨",
        "recommendation": "true로 설정을 권장합니다.",
    },
    {
        "key":         "network.http.sendRefererHeader",
        "bad_value":   2,
        "severity":    Severity.LOW,
        "description": "Referer 헤더가 항상 전송됨",
        "recommendation": "1(같은 도메인만)로 변경하세요.",
    },
    {
        "key":         "browser.safebrowsing.malware.enabled",
        "bad_value":   False,
        "severity":    Severity.HIGH,
        "description": "Firefox 악성코드 다운로드 차단이 비활성화됨",
        "recommendation": "반드시 true로 설정하세요.",
    },
    {
        "key":         "dom.storage.enabled",
        "bad_value":   False,
        "severity":    Severity.INFO,
        "description": "로컬 스토리지가 비활성화됨 (일부 사이트 오작동 가능)",
        "recommendation": "필요한 경우 활성화하세요.",
    },
    {
        "key":         "network.dns.disablePrefetch",
        "bad_value":   False,
        "severity":    Severity.LOW,
        "description": "DNS 프리페치가 활성화됨",
        "recommendation": "프라이버시 강화를 위해 true로 설정하세요.",
    },
]


def get_nested_value(data: dict[str, Any], dotted_key: str) -> Any:
    """점(.) 구분 키로 중첩 딕셔너리 값을 가져온다."""
    keys = dotted_key.split(".")
    current: Any = data
    for k in keys:
        if not isinstance(current, dict) or k not in current:
            return None
        current = current[k]
    return current


def audit_chrome(profile_path: Path) -> list[AuditFinding]:
    """Chrome Preferences 파일을 파싱하여 보안 설정을 점검한다."""
    prefs_file = profile_path / "Preferences"
    if not prefs_file.exists():
        print(f"[!] Preferences 파일을 찾을 수 없음: {prefs_file}", file=sys.stderr)
        return []

    try:
        data: dict[str, Any] = json.loads(prefs_file.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"[!] JSON 파싱 오류: {exc}", file=sys.stderr)
        return []

    findings: list[AuditFinding] = []
    for rule in CHROME_RULES:
        value = get_nested_value(data, rule["key"])
        if value == rule["bad_value"]:
            findings.append(
                AuditFinding(
                    setting_key=rule["key"],
                    current_value=value,
                    expected_value=f"!= {rule['bad_value']}",
                    severity=rule["severity"],
                    description=rule["description"],
                    recommendation=rule["recommendation"],
                )
            )
    return findings


def parse_firefox_prefs(prefs_path: Path) -> dict[str, Any]:
    """Firefox user.js / prefs.js 형식을 파싱하여 딕셔너리로 반환한다."""
    result: dict[str, Any] = {}
    if not prefs_path.exists():
        return result

    for line in prefs_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        # user_pref("key", value); 형식
        if not line.startswith("user_pref(") and not line.startswith("pref("):
            continue
        try:
            inner = line.split("(", 1)[1].rstrip(");")
            # 첫 번째 쉼표를 기준으로 키와 값 분리
            comma_idx = inner.index(",")
            key_raw = inner[:comma_idx].strip().strip('"')
            val_raw = inner[comma_idx + 1:].strip()
            if val_raw.lower() == "true":
                val: Any = True
            elif val_raw.lower() == "false":
                val = False
            elif val_raw.startswith('"') and val_raw.endswith('"'):
                val = val_raw[1:-1]
            else:
                val = int(val_raw)
            result[key_raw] = val
        except (ValueError, IndexError):
            continue
    return result


def audit_firefox(profile_path: Path) -> list[AuditFinding]:
    """Firefox 프로필의 user.js, prefs.js를 분석하여 보안 설정을 점검한다."""
    data: dict[str, Any] = {}
    for fname in ("user.js", "prefs.js"):
        parsed = parse_firefox_prefs(profile_path / fname)
        data.update(parsed)

    if not data:
        print("[!] Firefox 설정 파일을 찾지 못했습니다.", file=sys.stderr)
        return []

    findings: list[AuditFinding] = []
    for rule in FIREFOX_RULES:
        value = data.get(rule["key"])
        if value == rule["bad_value"]:
            findings.append(
                AuditFinding(
                    setting_key=rule["key"],
                    current_value=value,
                    expected_value=f"!= {rule['bad_value']}",
                    severity=rule["severity"],
                    description=rule["description"],
                    recommendation=rule["recommendation"],
                )
            )
    return findings


def format_report_text(report: AuditReport) -> str:
    """감사 결과를 사람이 읽기 쉬운 텍스트로 변환한다."""
    lines: list[str] = []
    lines.append("=" * 60)
    lines.append(f"브라우저 보안 설정 감사 보고서")
    lines.append(f"브라우저  : {report.browser}")
    lines.append(f"프로필    : {report.profile}")
    lines.append(f"보안 점수 : {report.score} / 100")
    lines.append("=" * 60)

    summary = report.summary()
    lines.append(f"[요약] CRITICAL={summary['CRITICAL']} HIGH={summary['HIGH']} "
                 f"MEDIUM={summary['MEDIUM']} LOW={summary['LOW']} INFO={summary['INFO']}")
    lines.append("")

    severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                      Severity.LOW, Severity.INFO]
    for sev in severity_order:
        group = [f for f in report.findings if f.severity == sev]
        if not group:
            continue
        lines.append(f"--- [{sev.value}] ---")
        for finding in group:
            lines.append(f"  설정 키     : {finding.setting_key}")
            lines.append(f"  현재 값     : {finding.current_value}")
            lines.append(f"  문제        : {finding.description}")
            lines.append(f"  권장 조치   : {finding.recommendation}")
            lines.append("")
    return "\n".join(lines)


def write_output(content: str, output_path: Path | None) -> None:
    if output_path is None:
        print(content)
    else:
        output_path.write_text(content, encoding="utf-8")
        print(f"[+] 보고서 저장 완료: {output_path}")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="browser_audit",
        description="브라우저 보안 설정 감사기 — Chrome / Firefox 프로필 점검",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
예시:
  python3 01_browser_attack_surface.py --browser chrome \\
      --profile-path ~/.config/google-chrome/Default \\
      --output report.txt

  python3 01_browser_attack_surface.py --browser firefox \\
      --profile-path ~/.mozilla/firefox/abcd1234.default
        """,
    )
    parser.add_argument(
        "--browser",
        choices=["chrome", "firefox"],
        required=True,
        help="감사할 브라우저 종류 (chrome / firefox)",
    )
    parser.add_argument(
        "--profile-path",
        type=Path,
        required=True,
        help="브라우저 프로필 디렉토리 경로",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="보고서 저장 경로 (지정하지 않으면 stdout 출력)",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="출력 형식 (text / json, 기본값: text)",
    )
    return parser


def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()

    profile_path: Path = args.profile_path.expanduser().resolve()

    if not profile_path.is_dir():
        print(f"[!] 프로필 경로가 존재하지 않습니다: {profile_path}", file=sys.stderr)
        sys.exit(1)

    if args.browser == "chrome":
        findings = audit_chrome(profile_path)
    else:
        findings = audit_firefox(profile_path)

    report = AuditReport(
        browser=args.browser,
        profile=str(profile_path),
        findings=findings,
    )

    if not findings:
        print("[+] 위험 설정이 발견되지 않았습니다. 보안 점수: 100/100")
        return

    if args.format == "json":
        content = json.dumps(
            {
                "browser":  report.browser,
                "profile":  report.profile,
                "score":    report.score,
                "summary":  report.summary(),
                "findings": [f.to_dict() for f in report.findings],
            },
            ensure_ascii=False,
            indent=2,
        )
    else:
        content = format_report_text(report)

    write_output(content, args.output)


if __name__ == "__main__":
    main()
```

---

## 5. 브라우저 기본 보안 메커니즘 요약

| 보안 메커니즘 | 설명 | Chrome | Firefox | Safari |
|---------------|------|--------|---------|--------|
| Site Isolation | 사이트별 렌더러 격리 | 완전 지원 | 부분 지원 | 부분 지원 |
| Strict Mixed Content | HTTP 리소스 차단 | 지원 | 지원 | 지원 |
| HTTPS Upgrade | HTTP→HTTPS 자동 전환 | 지원 | 지원 | 지원 |
| Spectre 완화 | COOP/COEP 헤더 | 지원 | 지원 | 지원 |
| Safe Browsing | 악성 URL 차단 | Google SB | Google SB | Safe Browsing |
| Sandboxing | 프로세스 격리 | seccomp, namespace | seccomp | macOS sandbox |
| CSP 지원 | Content Security Policy | 지원 | 지원 | 지원 |
| Certificate Transparency | CT 로그 검증 | 필수 적용 | 선택 적용 | 필수 적용 |

---

## 6. 참고 자료

- Chromium Security Architecture (https://www.chromium.org/Home/chromium-security/)
- Mozilla Security Blog (https://blog.mozilla.org/security/)
- WebKit Security (https://webkit.org/security/)
- CVE Details Browser Statistics (https://www.cvedetails.com/)
- Google Project Zero Blog (https://googleprojectzero.blogspot.com/)


<!-- detect-validate-60 -->
## 공격면 검증 — 줄였다고 한 기능이 실제로 꺼져 있는가

브라우저 공격면 관리는 *위협을 안다*가 아니라 **레거시 API·플러그인·위험 기능이 실제로 비활성이고, 서버 측 보호 헤더(CSP·격리)가 실제 응답에 존재하는가**로 판정한다. 검증은 **소유 사이트·테스트 프로파일**에서만.

### 항목 → 실패 모드 → 검증 방법 → 양호 신호

| 항목 | 실패 모드 | 검증 방법 | 양호 신호 |
|---|---|---|---|
| CSP 적용 | 헤더 부재/우회 | 응답 헤더 확인 | 엄격 CSP 존재 |
| 교차출처 격리 | COOP/COEP 부재 | 격리 헤더 점검 | crossOriginIsolated |
| 레거시 기능 | 위험 API 활성 | 기능 정책 확인 | 불필요 기능 차단 |
| 프레이밍 | clickjacking 가능 | frame-ancestors 확인 | 임베드 제한 |

### 방어 검증 (직접 확인)

```bash
# 1) 내 사이트 응답에 CSP·교차출처 격리 헤더가 실제 존재하는지 — 소유 사이트에서만
curl -sI https://localhost/ | grep -iE 'content-security-policy|cross-origin-(opener|embedder)-policy|x-frame-options'
# 2) Permissions-Policy로 위험 기능(카메라·지오 등)이 제한되는지
curl -sI https://localhost/ | grep -i 'permissions-policy' || echo "no Permissions-Policy (features unrestricted)"
```

> 검증은 반드시 **소유 사이트·테스트 프로파일**에서만 한다. "공격면을 줄였다"와 "위험 기능이 실제 꺼졌다"는 다르다 — 응답 헤더로 직접 확인한다([[05_Web_Hacking]], [[51_Browser_Extension_Security]]).

**최신 기법·통제 (2025–2026):**
- V8 샌드박스·Site Isolation·MiraclePtr로 익스플로잇 난이도 상승 — 검증: 완화 활성시 익스플로잇이 실패하는지 재현(소유 랩)([[05_Web_Hacking]])
- 렌더러/브로커 경계 — 강제되는지 확인

---

<a name="english"></a>

# Browser Attack Surface Analysis

## 1. Browser Architecture Overview

Modern browsers adopt a multi-process architecture for security. Chromium-based browsers separate the browser process, renderer process, GPU process, utility process, and others so that the compromise of one component does not spread to the entire system.

### 1.1 Major Process Role Comparison

| Process | Role | Privilege Level | Sandboxed | Security Threat |
|----------|------|-----------|---------------|-----------|
| Browser Process | UI, tab management, file I/O, networking | High (OS level) | No | Ultimate target for privilege escalation |
| Renderer Process | HTML/CSS parsing, JS execution, DOM | Low (sandboxed) | Yes | XSS, JS engine vulnerabilities |
| GPU Process | WebGL, accelerated rendering | Medium | Partial | GPU driver vulnerabilities |
| Network Service | HTTP requests, cache, cookies | Medium | Yes | SSRF, cookie theft |
| Plugin/Extension | Third-party features | User-defined | Limited | Malicious code execution |
| Utility Process | Audio, printing, file conversion | Low | Yes | Data exposure |
| Zygote (Linux) | Process spawning | Medium | Partial | Sandbox bypass |

### 1.2 IPC (Inter-Process Communication) Structure

The renderer process and browser process communicate through the Mojo IPC framework. This communication channel is the primary path attackers use to escalate privileges from the renderer to the browser process.

```
[Renderer Process] ←→ Mojo IPC ←→ [Browser Process]
       ↓                                    ↓
  Inside sandbox                      Full OS access
  (restricted privileges)             (files, network, etc.)
```

---

## 2. Attack Surface Classification

### 2.1 Major Attack Surface Analysis Table

| Attack Surface | Description | Risk | Representative Vulnerability Types | Mitigation |
|-----------|------|--------|------------------|-----------|
| JavaScript Engine | V8/SpiderMonkey/JSC JIT compiler | Critical | Type confusion, UAF, OOB | Sandbox, Site Isolation |
| DOM API | Web standard API implementation | High | UAF, race conditions | Isolation, CORS |
| IPC Interface | Mojo bindings, message handling | High | Input validation failures, TOCTOU | Interface auditing |
| Plugins (PDF, Flash) | NPAPI/PPAPI implementations | High | Heap overflow, format parsing errors | Flash removal, PDF isolation |
| Network Stack | HTTP/2, QUIC, WebSocket | Medium | Header injection, SSRF | HSTS, Certificate Pinning |
| Rendering Engine | Blink/Gecko CSS processing | Medium | OOB read, information leakage | Fuzzing, bounds checking |
| Extension API | chrome.*, browser.* APIs | Medium | Permission abuse, message spoofing | MV3 restrictions, review policies |
| WebAssembly | WASM execution environment | Medium | Memory safety, type confusion | Linear memory model |
| Media Processing | Video/audio decoders | Medium | Parser vulnerabilities, heap corruption | Media process isolation |
| GPU Driver | WebGL, WebGPU | Medium | Driver bugs, information leakage | GPU sandboxing |
| File System API | File, IndexedDB, Cache | Low | Path traversal, information leakage | Origin isolation |
| DevTools Protocol | CDP (Chrome DevTools Protocol) | Low-Medium | Remote code execution (if exposed) | Authentication, local binding |

### 2.2 Attack Surface Entry Points Detail

**JavaScript Engine Entry Points:**
- `<script>` tag execution on web pages
- eval(), Function() dynamic code generation
- WebAssembly.compile() / instantiate()
- Service Worker scripts

**Network Stack Entry Points:**
- HTTP/HTTPS request header parsing
- TLS handshake processing
- HTTP/2 HPACK header compression/decompression
- WebSocket frame processing

---

## 3. CVE Statistics and Historical Vulnerability Overview

### 3.1 Chrome (Chromium) Annual CVE Statistics

| Year | Total CVEs | Critical | High | Medium | Low | Primary Vulnerability Types |
|------|----------|----------|------|--------|-----|-----------------|
| 2019 | 186 | 8 | 85 | 72 | 21 | UAF, heap buffer overflow |
| 2020 | 276 | 3 | 143 | 95 | 35 | UAF, improper implementation |
| 2021 | 312 | 7 | 165 | 102 | 38 | UAF, OOB read/write |
| 2022 | 276 | 5 | 145 | 98 | 28 | Type confusion, UAF |
| 2023 | 224 | 2 | 118 | 80 | 24 | OOB, heap corruption |
| 2024 | 198 | 3 | 98 | 74 | 23 | UAF, integer overflow |

### 3.2 Firefox (SpiderMonkey) Annual CVE Statistics

| Year | Total CVEs | Critical | High | Medium | Low | Primary Vulnerability Types |
|------|----------|----------|------|--------|-----|-----------------|
| 2019 | 281 | 15 | 98 | 126 | 42 | Memory safety, XSS |
| 2020 | 194 | 9 | 76 | 89 | 20 | UAF, buffer overflow |
| 2021 | 178 | 7 | 81 | 72 | 18 | Memory corruption, CORS |
| 2022 | 161 | 5 | 74 | 61 | 21 | Scripting vulnerabilities |
| 2023 | 145 | 4 | 65 | 57 | 19 | OOB, type confusion |
| 2024 | 128 | 3 | 58 | 49 | 18 | Memory safety |

### 3.3 Safari (WebKit/JavaScriptCore) Annual CVE Statistics

| Year | Total CVEs | Critical | High | Medium | Low | Primary Vulnerability Types |
|------|----------|----------|------|--------|-----|-----------------|
| 2019 | 243 | 6 | 87 | 115 | 35 | Arbitrary code execution, information leakage |
| 2020 | 231 | 4 | 91 | 108 | 28 | Memory corruption, XSS |
| 2021 | 198 | 5 | 84 | 88 | 21 | UAF, type confusion |
| 2022 | 175 | 3 | 72 | 79 | 21 | Scripting, memory |
| 2023 | 152 | 4 | 63 | 68 | 17 | Memory corruption |
| 2024 | 134 | 2 | 56 | 58 | 18 | Arbitrary code execution |

### 3.4 Vulnerability Distribution by Browser Component

| Component | Chrome % | Firefox % | Safari % | Common Pattern |
|-----------|-------------|-------------|------------|-----------|
| JS Engine | 28% | 31% | 35% | JIT, parser |
| Rendering Engine | 22% | 19% | 21% | CSS, HTML parsing |
| IPC/Sandbox | 15% | 11% | 8% | Message validation |
| Media Processing | 12% | 14% | 13% | Decoder parser |
| Network Stack | 10% | 12% | 9% | HTTP handling |
| Other | 13% | 13% | 14% | Various |

---

## 4. Python CLI: Browser Security Settings Auditor

```python
#!/usr/bin/env python3
"""
Browser Security Settings Auditor
Reads Chrome and Firefox security-related configuration files
and detects risky settings.
"""

from __future__ import annotations

import argparse
import json
import sys
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


@dataclass
class AuditFinding:
    """A single audit item result."""
    setting_key: str
    current_value: Any
    expected_value: Any
    severity: Severity
    description: str
    recommendation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "setting_key":   self.setting_key,
            "current_value": self.current_value,
            "expected_value": self.expected_value,
            "severity":      self.severity.value,
            "description":   self.description,
            "recommendation": self.recommendation,
        }


@dataclass
class AuditReport:
    """Full audit report results."""
    browser:   str
    profile:   str
    findings:  list[AuditFinding] = field(default_factory=list)

    @property
    def score(self) -> int:
        """Calculate security score out of 100."""
        deductions = {
            Severity.CRITICAL: 20,
            Severity.HIGH:     10,
            Severity.MEDIUM:    5,
            Severity.LOW:       2,
            Severity.INFO:      0,
        }
        total_deduction = sum(deductions[f.severity] for f in self.findings)
        return max(0, 100 - total_deduction)

    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts


# ---------------------------------------------------------------------------
# Chrome audit rules
# ---------------------------------------------------------------------------

CHROME_RULES: list[dict[str, Any]] = [
    {
        "key":         "profile.default_content_setting_values.mixed_script",
        "bad_value":   1,
        "severity":    Severity.HIGH,
        "description": "Mixed Content Script allow setting is enabled",
        "recommendation": "Block mixed scripts (0) or keep the default value.",
    },
    {
        "key":         "profile.default_content_setting_values.notifications",
        "bad_value":   1,
        "severity":    Severity.MEDIUM,
        "description": "Auto-allow notifications from all sites is set",
        "recommendation": "Change to ask per site (3).",
    },
    {
        "key":         "safebrowsing.enabled",
        "bad_value":   False,
        "severity":    Severity.CRITICAL,
        "description": "Google Safe Browsing is disabled",
        "recommendation": "Enable Safe Browsing (true).",
    },
    {
        "key":         "safebrowsing.enhanced",
        "bad_value":   False,
        "severity":    Severity.LOW,
        "description": "Safe Browsing Enhanced Protection mode is disabled",
        "recommendation": "Recommended to enable Enhanced Protection.",
    },
    {
        "key":         "net.network_prediction_options",
        "bad_value":   0,
        "severity":    Severity.LOW,
        "description": "Network prediction (DNS Prefetch) is always enabled",
        "recommendation": "Set network prediction to 2 (disabled).",
    },
    {
        "key":         "profile.password_manager_enabled",
        "bad_value":   False,
        "severity":    Severity.INFO,
        "description": "Built-in password manager is disabled",
        "recommendation": "No issue if using an external manager.",
    },
    {
        "key":         "sync.requested",
        "bad_value":   True,
        "severity":    Severity.MEDIUM,
        "description": "Google account sync is enabled (risk in enterprise environments)",
        "recommendation": "Disable sync in enterprise environments.",
    },
    {
        "key":         "extensions.ui.developer_mode",
        "bad_value":   True,
        "severity":    Severity.MEDIUM,
        "description": "Extension developer mode is enabled",
        "recommendation": "Disable developer mode in production environments.",
    },
]

# ---------------------------------------------------------------------------
# Firefox audit rules (based on user.js / prefs.js)
# ---------------------------------------------------------------------------

FIREFOX_RULES: list[dict[str, Any]] = [
    {
        "key":         "network.cookie.cookieBehavior",
        "bad_value":   0,
        "severity":    Severity.HIGH,
        "description": "All third-party cookies are allowed",
        "recommendation": "Set cookieBehavior to 1 (block third-party) or higher.",
    },
    {
        "key":         "browser.privatebrowsing.autostart",
        "bad_value":   False,
        "severity":    Severity.INFO,
        "description": "Auto private browsing mode is disabled",
        "recommendation": "Consider enabling auto-start in sensitive environments.",
    },
    {
        "key":         "security.mixed_content.block_active_content",
        "bad_value":   False,
        "severity":    Severity.CRITICAL,
        "description": "Mixed Active Content blocking is disabled",
        "recommendation": "Must be set to true.",
    },
    {
        "key":         "security.mixed_content.block_display_content",
        "bad_value":   False,
        "severity":    Severity.MEDIUM,
        "description": "Mixed Passive Content blocking is disabled",
        "recommendation": "Recommended to set to true.",
    },
    {
        "key":         "network.http.sendRefererHeader",
        "bad_value":   2,
        "severity":    Severity.LOW,
        "description": "Referer header is always sent",
        "recommendation": "Change to 1 (same domain only).",
    },
    {
        "key":         "browser.safebrowsing.malware.enabled",
        "bad_value":   False,
        "severity":    Severity.HIGH,
        "description": "Firefox malware download blocking is disabled",
        "recommendation": "Must be set to true.",
    },
    {
        "key":         "dom.storage.enabled",
        "bad_value":   False,
        "severity":    Severity.INFO,
        "description": "Local storage is disabled (may cause some sites to malfunction)",
        "recommendation": "Enable if needed.",
    },
    {
        "key":         "network.dns.disablePrefetch",
        "bad_value":   False,
        "severity":    Severity.LOW,
        "description": "DNS prefetching is enabled",
        "recommendation": "Set to true to enhance privacy.",
    },
]


def get_nested_value(data: dict[str, Any], dotted_key: str) -> Any:
    """Retrieve a value from a nested dictionary using dot-separated key."""
    keys = dotted_key.split(".")
    current: Any = data
    for k in keys:
        if not isinstance(current, dict) or k not in current:
            return None
        current = current[k]
    return current


def audit_chrome(profile_path: Path) -> list[AuditFinding]:
    """Parse Chrome Preferences file and check security settings."""
    prefs_file = profile_path / "Preferences"
    if not prefs_file.exists():
        print(f"[!] Preferences file not found: {prefs_file}", file=sys.stderr)
        return []

    try:
        data: dict[str, Any] = json.loads(prefs_file.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"[!] JSON parse error: {exc}", file=sys.stderr)
        return []

    findings: list[AuditFinding] = []
    for rule in CHROME_RULES:
        value = get_nested_value(data, rule["key"])
        if value == rule["bad_value"]:
            findings.append(
                AuditFinding(
                    setting_key=rule["key"],
                    current_value=value,
                    expected_value=f"!= {rule['bad_value']}",
                    severity=rule["severity"],
                    description=rule["description"],
                    recommendation=rule["recommendation"],
                )
            )
    return findings


def format_report_text(report: AuditReport) -> str:
    """Convert audit results to human-readable text."""
    lines: list[str] = []
    lines.append("=" * 60)
    lines.append("Browser Security Settings Audit Report")
    lines.append(f"Browser  : {report.browser}")
    lines.append(f"Profile  : {report.profile}")
    lines.append(f"Security Score : {report.score} / 100")
    lines.append("=" * 60)

    summary = report.summary()
    lines.append(f"[Summary] CRITICAL={summary['CRITICAL']} HIGH={summary['HIGH']} "
                 f"MEDIUM={summary['MEDIUM']} LOW={summary['LOW']} INFO={summary['INFO']}")
    lines.append("")

    severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                      Severity.LOW, Severity.INFO]
    for sev in severity_order:
        group = [f for f in report.findings if f.severity == sev]
        if not group:
            continue
        lines.append(f"--- [{sev.value}] ---")
        for finding in group:
            lines.append(f"  Setting Key   : {finding.setting_key}")
            lines.append(f"  Current Value : {finding.current_value}")
            lines.append(f"  Issue         : {finding.description}")
            lines.append(f"  Recommendation: {finding.recommendation}")
            lines.append("")
    return "\n".join(lines)
```

---

## 5. Browser Core Security Mechanisms Summary

| Security Mechanism | Description | Chrome | Firefox | Safari |
|---------------|------|--------|---------|--------|
| Site Isolation | Per-site renderer isolation | Full support | Partial support | Partial support |
| Strict Mixed Content | Block HTTP resources | Supported | Supported | Supported |
| HTTPS Upgrade | Automatic HTTP→HTTPS upgrade | Supported | Supported | Supported |
| Spectre Mitigation | COOP/COEP headers | Supported | Supported | Supported |
| Safe Browsing | Block malicious URLs | Google SB | Google SB | Safe Browsing |
| Sandboxing | Process isolation | seccomp, namespace | seccomp | macOS sandbox |
| CSP Support | Content Security Policy | Supported | Supported | Supported |
| Certificate Transparency | CT log verification | Required | Optional | Required |

---

## 6. References

- Chromium Security Architecture (https://www.chromium.org/Home/chromium-security/)
- Mozilla Security Blog (https://blog.mozilla.org/security/)
- WebKit Security (https://webkit.org/security/)
- CVE Details Browser Statistics (https://www.cvedetails.com/)
- Google Project Zero Blog (https://googleprojectzero.blogspot.com/)

<!-- detect-validate-60 -->
## Attack-Surface Validation — Are the Features You "Reduced" Actually Off?

Browser attack-surface management is judged not by *knowing threats* but by **whether legacy APIs/plugins/risky features are actually disabled and server-side protection headers (CSP, isolation) actually exist in responses**. Validate only on **owned sites / test profiles**.

### Item -> Failure mode -> Validation method -> Healthy signal

| Item | Failure mode | Validation method | Healthy signal |
|---|---|---|---|
| CSP applied | Header absent/bypassable | Inspect response header | Strict CSP present |
| Cross-origin isolation | No COOP/COEP | Check isolation headers | crossOriginIsolated |
| Legacy features | Risky API enabled | Check feature policy | Unneeded features blocked |
| Framing | Clickjacking possible | Check frame-ancestors | Embedding restricted |

### Defense validation (verify directly)

```bash
# 1) Whether your site's responses actually carry CSP / cross-origin isolation headers — owned site only
curl -sI https://localhost/ | grep -iE 'content-security-policy|cross-origin-(opener|embedder)-policy|x-frame-options'
# 2) Whether Permissions-Policy restricts risky features (camera/geo/etc.)
curl -sI https://localhost/ | grep -i 'permissions-policy' || echo "no Permissions-Policy (features unrestricted)"
```

> Validate only on **owned sites / test profiles**. "Reduced the attack surface" differs from "risky features are actually off" — confirm directly via response headers ([[05_Web_Hacking]], [[51_Browser_Extension_Security]]).
