# 브라우저 확장 아키텍처와 보안 모델

## 1. 브라우저 확장 개요

브라우저 확장(Browser Extension)은 브라우저에 추가 기능을 부여하는 소프트웨어 컴포넌트다. 웹 페이지 컨텍스트와 브라우저 API에 동시에 접근할 수 있어 강력하면서도 잠재적으로 위험한 공격 표면을 형성한다.

### 확장이 접근 가능한 리소스
- 모든 탭의 DOM 조작
- HTTP 요청/응답 인터셉트 및 수정
- 브라우저 쿠키, 히스토리, 북마크
- 다운로드, 클립보드, 알림
- 네이티브 애플리케이션 통신 (nativeMessaging)
- 특정 호스트의 모든 네트워크 트래픽

---

## 2. Manifest V2 vs Manifest V3

### 2.1 Manifest V2 구조

```json
{
  "manifest_version": 2,
  "name": "Example Extension",
  "version": "1.0.0",
  "description": "보안 감사용 예제 확장",
  "permissions": [
    "activeTab",
    "storage",
    "cookies",
    "webRequest",
    "webRequestBlocking",
    "<all_urls>"
  ],
  "background": {
    "scripts": ["background.js"],
    "persistent": true
  },
  "content_scripts": [
    {
      "matches": ["https://*/*", "http://*/*"],
      "js": ["content.js"],
      "run_at": "document_start"
    }
  ],
  "browser_action": {
    "default_popup": "popup.html",
    "default_icon": "icon.png"
  },
  "options_page": "options.html",
  "content_security_policy": "script-src 'self'; object-src 'self'"
}
```

**V2 주요 특징:**
- 영구적 Background Page (persistent: true) — 항상 메모리 상주
- `webRequestBlocking` — 요청을 동기적으로 차단/수정 가능
- `eval()` 허용 (CSP 완화 가능)
- 원격 코드 로딩 가능 (외부 스크립트 삽입)

### 2.2 Manifest V3 구조

```json
{
  "manifest_version": 3,
  "name": "Example Extension MV3",
  "version": "1.0.0",
  "description": "MV3 기반 보안 확장",
  "permissions": [
    "activeTab",
    "storage",
    "cookies",
    "declarativeNetRequest"
  ],
  "host_permissions": [
    "https://*.example.com/*"
  ],
  "background": {
    "service_worker": "background.js",
    "type": "module"
  },
  "content_scripts": [
    {
      "matches": ["https://*/*"],
      "js": ["content.js"],
      "run_at": "document_start"
    }
  ],
  "action": {
    "default_popup": "popup.html",
    "default_icon": {
      "16": "icons/icon16.png",
      "48": "icons/icon48.png",
      "128": "icons/icon128.png"
    }
  },
  "content_security_policy": {
    "extension_pages": "script-src 'self'; object-src 'self'",
    "sandbox": "sandbox allow-scripts; script-src 'self'"
  }
}
```

**V3 주요 변경점:**

| 항목 | V2 | V3 |
|------|----|----|
| 백그라운드 | Background Page (영구) | Service Worker (이벤트 기반) |
| 네트워크 차단 | webRequestBlocking | declarativeNetRequest |
| 동적 코드 실행 | eval() 허용 | eval() 금지 |
| 원격 코드 | 가능 | 금지 |
| 권한 분리 | permissions에 host 포함 | host_permissions 분리 |

---

## 3. 핵심 컴포넌트 분석

### 3.1 Background Script / Service Worker

확장의 핵심 로직을 담당한다. 브라우저 이벤트를 수신하고 다른 컴포넌트와 통신한다.

```javascript
// background.js (MV3 Service Worker)

// 설치 이벤트 처리
chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason === 'install') {
    console.log('[BG] 확장 최초 설치');
    chrome.storage.local.set({ installTime: Date.now() });
  } else if (details.reason === 'update') {
    console.log('[BG] 확장 업데이트:', details.previousVersion, '->', chrome.runtime.getManifest().version);
  }
});

// 탭 업데이트 감시
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url) {
    // 현재 탭 URL 분석
    analyzeTabUrl(tabId, tab.url);
  }
});

function analyzeTabUrl(tabId, url) {
  try {
    const parsed = new URL(url);
    // 의심스러운 도메인 패턴 탐지
    const suspiciousPatterns = [
      /[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/,  // IP 주소
      /\.tk$|\.ml$|\.ga$|\.cf$/,  // 무료 도메인
    ];
    for (const pattern of suspiciousPatterns) {
      if (pattern.test(parsed.hostname)) {
        console.warn('[BG] 의심 URL 탐지:', url);
      }
    }
  } catch (e) {
    // chrome://, about: 등 파싱 불가 URL 무시
  }
}

// Content Script로부터 메시지 수신
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  console.log('[BG] 메시지 수신:', message.type, '발신자:', sender.tab?.url);
  
  switch (message.type) {
    case 'GET_STORAGE':
      chrome.storage.local.get(message.keys, (data) => {
        sendResponse({ success: true, data });
      });
      return true;  // 비동기 응답을 위해 true 반환

    case 'REPORT_THREAT':
      handleThreatReport(message.data, sender);
      sendResponse({ success: true });
      break;

    default:
      sendResponse({ success: false, error: '알 수 없는 메시지 타입' });
  }
});

function handleThreatReport(data, sender) {
  chrome.storage.local.get(['threats'], (result) => {
    const threats = result.threats || [];
    threats.push({
      url: sender.tab?.url,
      data,
      timestamp: Date.now()
    });
    chrome.storage.local.set({ threats });
  });
}
```

### 3.2 Content Script

웹 페이지 컨텍스트에서 실행되지만 격리된 JavaScript 환경(Isolated World)을 가진다.

```javascript
// content.js

(function() {
  'use strict';

  // Content Script는 페이지 JavaScript와 분리된 환경에서 실행됨
  // window 객체 공유하지만 JavaScript 네임스페이스는 격리됨

  // 페이지에서 민감한 폼 탐지
  function detectSensitiveForms() {
    const forms = document.querySelectorAll('form');
    forms.forEach((form) => {
      const inputs = form.querySelectorAll('input[type="password"], input[name*="card"], input[name*="cvv"]');
      if (inputs.length > 0) {
        console.log('[CS] 민감한 폼 탐지:', form.action);
        // Background로 보고
        chrome.runtime.sendMessage({
          type: 'REPORT_THREAT',
          data: {
            type: 'sensitive_form',
            action: form.action,
            fields: Array.from(inputs).map(i => i.name || i.id)
          }
        });
      }
    });
  }

  // DOM 변조 탐지 (MutationObserver)
  const observer = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      for (const node of mutation.addedNodes) {
        if (node.nodeType === Node.ELEMENT_NODE) {
          // 외부 스크립트 삽입 탐지
          if (node.tagName === 'SCRIPT' && node.src && !node.src.startsWith(window.location.origin)) {
            console.warn('[CS] 외부 스크립트 삽입 탐지:', node.src);
          }
        }
      }
    }
  });

  observer.observe(document.documentElement, {
    childList: true,
    subtree: true
  });

  // 페이지 로드 완료 후 폼 스캔
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', detectSensitiveForms);
  } else {
    detectSensitiveForms();
  }

  // 페이지 JavaScript와 통신 (window.postMessage 방식)
  window.addEventListener('message', (event) => {
    // 동일 출처만 허용
    if (event.source !== window) return;
    if (event.data?.from === 'page_script') {
      chrome.runtime.sendMessage({
        type: 'PAGE_MESSAGE',
        data: event.data
      });
    }
  });
})();
```

### 3.3 Popup (browser_action / action)

사용자가 확장 아이콘 클릭 시 표시되는 UI 컴포넌트다. 독립적인 HTML 페이지로 동작한다.

```html
<!-- popup.html -->
<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8">
  <meta http-equiv="Content-Security-Policy" content="script-src 'self'; object-src 'none'">
  <title>보안 감사 확장</title>
  <style>
    body { width: 350px; padding: 16px; font-family: sans-serif; }
    .threat-item { background: #fff3cd; border: 1px solid #ffc107; padding: 8px; margin: 4px 0; border-radius: 4px; }
    .safe { color: #28a745; }
    .danger { color: #dc3545; }
  </style>
</head>
<body>
  <h2>보안 감사 대시보드</h2>
  <div id="status"></div>
  <div id="threats-list"></div>
  <button id="clear-btn">위협 목록 초기화</button>
  <script src="popup.js"></script>
</body>
</html>
```

```javascript
// popup.js
document.addEventListener('DOMContentLoaded', () => {
  loadThreats();
  
  document.getElementById('clear-btn').addEventListener('click', () => {
    chrome.storage.local.set({ threats: [] }, () => {
      loadThreats();
    });
  });
});

function loadThreats() {
  chrome.storage.local.get(['threats', 'installTime'], (data) => {
    const threats = data.threats || [];
    const statusEl = document.getElementById('status');
    const listEl = document.getElementById('threats-list');

    if (threats.length === 0) {
      statusEl.innerHTML = '<span class="safe">위협 탐지 없음</span>';
      listEl.innerHTML = '';
    } else {
      statusEl.innerHTML = `<span class="danger">위협 ${threats.length}건 탐지</span>`;
      listEl.innerHTML = threats.map((t) => `
        <div class="threat-item">
          <strong>${t.data.type}</strong><br>
          URL: ${t.url || '알 수 없음'}<br>
          <small>${new Date(t.timestamp).toLocaleString('ko-KR')}</small>
        </div>
      `).join('');
    }
  });
}
```

---

## 4. 권한 모델

### 4.1 권한 유형

```
permissions (일반 권한):
  - activeTab       : 현재 활성 탭에만 접근 (사용자 제스처 후)
  - storage         : chrome.storage API
  - cookies         : 쿠키 읽기/쓰기
  - tabs            : 탭 메타데이터 (URL 포함)
  - history         : 브라우저 히스토리
  - bookmarks       : 북마크
  - downloads       : 다운로드 관리
  - notifications   : 시스템 알림
  - contextMenus    : 우클릭 메뉴
  - webRequest      : HTTP 요청 관찰 (V2)
  - webRequestBlocking: HTTP 요청 차단/수정 (V2만)
  - declarativeNetRequest: 규칙 기반 요청 처리 (V3)
  - nativeMessaging : 네이티브 앱 통신
  - management      : 다른 확장 관리
  - debugger        : Chrome DevTools Protocol
  - proxy           : 프록시 설정
  - contentSettings : 콘텐츠 설정

host_permissions (호스트 권한):
  - "https://example.com/*"  : 특정 도메인
  - "https://*.example.com/*": 서브도메인 포함
  - "<all_urls>"             : 모든 URL (최고 위험)
  - "https://*/*"            : 모든 HTTPS URL
```

### 4.2 권한별 위험도 분류

```javascript
// 권한 위험도 분류 (보안 감사 기준)
const PERMISSION_RISK = {
  critical: [
    '<all_urls>',
    'webRequestBlocking',
    'nativeMessaging',
    'debugger',
    'proxy',
    'management'
  ],
  high: [
    'cookies',
    'history',
    'tabs',
    'webRequest',
    'downloads',
    'contentSettings'
  ],
  medium: [
    'storage',
    'notifications',
    'contextMenus',
    'bookmarks'
  ],
  low: [
    'activeTab',
    'alarms',
    'idle',
    'fontSettings'
  ]
};

function assessPermissionRisk(permissions, hostPermissions) {
  const risks = [];
  
  for (const perm of permissions) {
    for (const [level, perms] of Object.entries(PERMISSION_RISK)) {
      if (perms.includes(perm)) {
        risks.push({ permission: perm, level });
      }
    }
  }
  
  // 호스트 권한 평가
  for (const host of (hostPermissions || [])) {
    if (host === '<all_urls>' || host.startsWith('https://*/*')) {
      risks.push({ permission: host, level: 'critical' });
    }
  }
  
  return risks;
}
```

---

## 5. 메시지 패싱

### 5.1 일회성 메시지 (sendMessage)

```javascript
// Content Script → Background
chrome.runtime.sendMessage(
  { type: 'ACTION', payload: { key: 'value' } },
  (response) => {
    if (chrome.runtime.lastError) {
      console.error('메시지 오류:', chrome.runtime.lastError.message);
      return;
    }
    console.log('응답:', response);
  }
);

// Background → Content Script
chrome.tabs.sendMessage(
  tabId,
  { type: 'INJECT_SCRIPT', code: '...' },
  (response) => {
    console.log('CS 응답:', response);
  }
);
```

### 5.2 장기 연결 (Port 통신)

```javascript
// Content Script 측 - 연결 개시
const port = chrome.runtime.connect({ name: 'security-channel' });

port.onMessage.addListener((msg) => {
  console.log('[CS] Port 메시지:', msg);
  if (msg.type === 'SCAN_PAGE') {
    const result = scanCurrentPage();
    port.postMessage({ type: 'SCAN_RESULT', data: result });
  }
});

port.onDisconnect.addListener(() => {
  console.log('[CS] Port 연결 해제');
});

// Background 측 - 연결 수신
chrome.runtime.onConnect.addListener((port) => {
  if (port.name !== 'security-channel') return;
  
  console.log('[BG] Port 연결:', port.sender.tab?.url);
  
  port.onMessage.addListener((msg) => {
    if (msg.type === 'SCAN_RESULT') {
      processSecurityScanResult(msg.data, port.sender.tab);
    }
  });

  port.onDisconnect.addListener(() => {
    console.log('[BG] Port 연결 종료');
  });

  // 연결 즉시 스캔 요청
  port.postMessage({ type: 'SCAN_PAGE' });
});
```

### 5.3 외부 메시지 (externally_connectable)

```json
// manifest.json에 허용할 외부 출처 등록
{
  "externally_connectable": {
    "matches": ["https://trusted-website.example.com/*"],
    "ids": ["aaabbbcccdddeeefffggg"]
  }
}
```

```javascript
// 외부 웹페이지에서 확장으로 메시지 전송
const EXTENSION_ID = 'your-extension-id-here';

chrome.runtime.sendMessage(EXTENSION_ID, { type: 'QUERY' }, (response) => {
  if (chrome.runtime.lastError) {
    console.error('확장 통신 실패:', chrome.runtime.lastError);
    return;
  }
  console.log('확장 응답:', response);
});

// Background에서 외부 메시지 수신
chrome.runtime.onMessageExternal.addListener((message, sender, sendResponse) => {
  console.log('[BG] 외부 메시지:', message, '발신:', sender.url);
  // 발신 출처 검증 필수
  if (!sender.url?.startsWith('https://trusted-website.example.com/')) {
    sendResponse({ error: '허가되지 않은 출처' });
    return;
  }
  sendResponse({ data: 'ok' });
});
```

---

## 6. Content Security Policy (CSP) in Extensions

### 6.1 확장 페이지 CSP

```json
// manifest.json V3
{
  "content_security_policy": {
    "extension_pages": "script-src 'self'; object-src 'self'; base-uri 'self'",
    "sandbox": "sandbox allow-scripts allow-forms; script-src 'self' 'unsafe-inline'"
  }
}
```

### 6.2 CSP 우회 패턴 (취약한 설정)

```json
// 취약한 CSP 예시 (절대 사용 금지)
{
  "content_security_policy": "script-src 'self' 'unsafe-eval' 'unsafe-inline' https://cdn.example.com; object-src *"
}
```

위 설정의 문제점:
- `unsafe-eval`: eval(), Function() 허용 → 코드 인젝션 위험
- `unsafe-inline`: 인라인 스크립트 허용
- 외부 CDN 허용: CDN 탈취 시 악성 코드 실행 가능
- `object-src *`: 플러그인 오브젝트 무제한 허용

---

## 7. 확장의 공격 표면 분석

### 7.1 공격 표면 목록

```
1. Manifest 파일
   - 과도한 권한 요청
   - 취약한 CSP 설정
   - 과도한 host_permissions

2. Background Script
   - 검증 없는 메시지 처리
   - 동적 코드 실행 (eval)
   - 원격 코드 로딩

3. Content Script
   - DOM-based XSS
   - 신뢰할 수 없는 페이지 데이터 처리
   - postMessage 검증 부재

4. Popup / Options Page
   - innerHTML을 통한 XSS
   - 저장된 데이터 렌더링 시 sanitization 부재

5. Storage
   - 민감 데이터 평문 저장
   - 암호화 없이 토큰/패스워드 저장

6. External Communication
   - HTTPS 미사용
   - 서버 응답 검증 부재
   - CORS 설정 오류
```

### 7.2 공격 표면 시각화

```
[웹 페이지] ←→ [Content Script] ←→ [Background/SW] ←→ [외부 서버]
     ↑                 ↑                    ↑                 ↑
  DOM XSS         메시지 인젝션          권한 남용         데이터 유출
  스크립트 삽입    postMessage 스푸핑     원격 코드 실행    중간자 공격
```

---

## 8. 보안 감사용 확장 실전 작성

### 8.1 완성형 보안 감사 확장

다음은 실제로 동작하는 보안 감사 확장의 전체 코드다.

**manifest.json**

```json
{
  "manifest_version": 3,
  "name": "Security Auditor",
  "version": "1.0.0",
  "description": "웹 페이지 보안 감사 도구",
  "permissions": [
    "activeTab",
    "storage",
    "tabs",
    "scripting"
  ],
  "host_permissions": [],
  "background": {
    "service_worker": "background.js"
  },
  "content_scripts": [
    {
      "matches": ["https://*/*", "http://*/*"],
      "js": ["content-audit.js"],
      "run_at": "document_idle"
    }
  ],
  "action": {
    "default_popup": "popup.html"
  },
  "content_security_policy": {
    "extension_pages": "script-src 'self'; object-src 'none'; base-uri 'self'"
  }
}
```

**content-audit.js**

```javascript
// content-audit.js — 페이지 보안 감사 스크립트

(function securityAudit() {
  'use strict';

  const findings = [];

  // 1. 혼합 콘텐츠 탐지
  function checkMixedContent() {
    if (location.protocol === 'https:') {
      const httpResources = [];
      document.querySelectorAll('img[src], script[src], link[href], iframe[src]').forEach((el) => {
        const src = el.src || el.href;
        if (src && src.startsWith('http://')) {
          httpResources.push({ tag: el.tagName, src });
        }
      });
      if (httpResources.length > 0) {
        findings.push({
          type: 'MIXED_CONTENT',
          severity: 'high',
          count: httpResources.length,
          details: httpResources.slice(0, 5)
        });
      }
    }
  }

  // 2. 인라인 이벤트 핸들러 탐지 (XSS 위험)
  function checkInlineHandlers() {
    const dangerous = [];
    const allElements = document.querySelectorAll('*');
    const dangerousAttrs = ['onclick', 'onmouseover', 'onload', 'onerror', 'onsubmit', 'onkeyup'];
    
    allElements.forEach((el) => {
      dangerousAttrs.forEach((attr) => {
        if (el.getAttribute(attr)) {
          dangerous.push({ tag: el.tagName, attr, value: el.getAttribute(attr).substring(0, 50) });
        }
      });
    });

    if (dangerous.length > 0) {
      findings.push({
        type: 'INLINE_EVENT_HANDLER',
        severity: 'medium',
        count: dangerous.length,
        details: dangerous.slice(0, 3)
      });
    }
  }

  // 3. 민감 정보 노출 탐지 (주석 내 하드코딩된 키)
  function checkHardcodedSecrets() {
    const scripts = document.querySelectorAll('script:not([src])');
    const patterns = [
      { name: 'API Key', pattern: /['"]?api[_-]?key['"]?\s*[=:]\s*['"][A-Za-z0-9]{20,}['"]/i },
      { name: 'Secret Key', pattern: /['"]?secret[_-]?key['"]?\s*[=:]\s*['"][A-Za-z0-9]{20,}['"]/i },
      { name: 'Password', pattern: /['"]?password['"]?\s*[=:]\s*['"][^'"]{8,}['"]/i },
      { name: 'Token', pattern: /['"]?token['"]?\s*[=:]\s*['"][A-Za-z0-9\-_]{20,}['"]/i }
    ];

    scripts.forEach((script) => {
      const code = script.textContent;
      patterns.forEach(({ name, pattern }) => {
        if (pattern.test(code)) {
          findings.push({
            type: 'HARDCODED_SECRET',
            severity: 'critical',
            secretType: name,
            snippet: code.match(pattern)?.[0]?.substring(0, 30) + '...'
          });
        }
      });
    });
  }

  // 4. CSP 헤더 확인 (meta 태그)
  function checkCSP() {
    const cspMeta = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
    if (!cspMeta) {
      findings.push({
        type: 'MISSING_CSP',
        severity: 'medium',
        message: 'Content-Security-Policy 헤더/메타 없음'
      });
    } else {
      const cspContent = cspMeta.getAttribute('content') || '';
      if (cspContent.includes('unsafe-eval')) {
        findings.push({ type: 'WEAK_CSP', severity: 'high', issue: "unsafe-eval 허용" });
      }
      if (cspContent.includes('unsafe-inline')) {
        findings.push({ type: 'WEAK_CSP', severity: 'medium', issue: "unsafe-inline 허용" });
      }
    }
  }

  // 5. 외부 스크립트 탐지
  function checkExternalScripts() {
    const externalScripts = [];
    document.querySelectorAll('script[src]').forEach((script) => {
      if (!script.src.startsWith(location.origin)) {
        externalScripts.push({
          src: script.src,
          integrity: script.integrity || null,
          crossorigin: script.crossOrigin || null
        });
      }
    });

    if (externalScripts.length > 0) {
      const withoutIntegrity = externalScripts.filter(s => !s.integrity);
      if (withoutIntegrity.length > 0) {
        findings.push({
          type: 'EXTERNAL_SCRIPT_NO_SRI',
          severity: 'medium',
          count: withoutIntegrity.length,
          details: withoutIntegrity.slice(0, 3)
        });
      }
    }
  }

  // 모든 검사 실행
  checkMixedContent();
  checkInlineHandlers();
  checkHardcodedSecrets();
  checkCSP();
  checkExternalScripts();

  // 결과를 Background로 전송
  if (findings.length > 0) {
    chrome.runtime.sendMessage({
      type: 'AUDIT_RESULTS',
      url: location.href,
      findings,
      timestamp: Date.now()
    }).catch(() => {
      // Service Worker가 inactive 상태일 수 있음 — 무시
    });
  }
})();
```

---

## 9. 확장 ID와 격리 메커니즘

### 9.1 확장 ID 구조

```
크롬 확장 ID: 32자리 소문자 알파벳 (a-p)
예: aaaabbbbccccddddeeeeffffgggghhhh

ID 생성 방식:
- 공개 키(public key) SHA-256 해시의 처음 128비트
- 각 바이트를 a-p 범위 문자로 인코딩
- 동일한 private key → 동일한 확장 ID
```

### 9.2 Isolated World 메커니즘

```
[페이지 World]          [Extension World (CS)]
  window.myVar = 1      window.myVar === undefined
  document.body (공유)  document.body (동일 DOM 공유)
  JS 실행 환경 분리     JS 실행 환경 분리
       ↓                        ↓
  DOM 접근 공유         chrome.* API 접근 가능
```

Content Script는 페이지의 JavaScript와 동일한 DOM을 공유하지만, JavaScript 실행 환경(Isolated World)은 완전히 분리된다. 따라서 페이지의 변수, 함수에 직접 접근할 수 없다.

---

## 10. 실전 분석: 확장 파일 구조 탐색

크롬에 설치된 확장의 파일을 직접 분석하는 방법이다.

```bash
# 크롬 확장 설치 경로 (Linux)
~/.config/google-chrome/Default/Extensions/

# 크롬 확장 설치 경로 (Windows WSL)
/mnt/c/Users/<username>/AppData/Local/Google/Chrome/User Data/Default/Extensions/

# 특정 확장 파일 목록
ls ~/.config/google-chrome/Default/Extensions/<EXTENSION_ID>/

# manifest.json 확인
cat ~/.config/google-chrome/Default/Extensions/<EXTENSION_ID>/<version>/manifest.json | python3 -m json.tool

# JavaScript 파일 전체 검색
find ~/.config/google-chrome/Default/Extensions/<EXTENSION_ID>/ -name "*.js" -exec wc -l {} +

# 외부 URL 패턴 검색
grep -r "https\?://" ~/.config/google-chrome/Default/Extensions/<EXTENSION_ID>/ --include="*.js" | grep -v "chrome-extension://"
```

---

## 참고 자료

- Chrome Extensions Developer Guide: https://developer.chrome.com/docs/extensions/
- Manifest V3 Migration Guide: https://developer.chrome.com/docs/extensions/mv3/mv2-sunset/
- Chrome Extension Security FAQ: https://developer.chrome.com/docs/extensions/mv3/security/
- OWASP Browser Extension Security: https://owasp.org/www-community/attacks/
