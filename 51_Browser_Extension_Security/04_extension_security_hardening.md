> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 브라우저 확장 보안 강화

## 0. 초보자를 위한 개념 이해

### 브라우저 확장 보안 강화란?

**브라우저 확장 보안 강화(Extension Security Hardening)**는 개발 중인 확장의 공격 표면을 최소화하고, 알려진 취약점 패턴을 방어하는 코딩 관행과 설정 방법입니다.

**개발자가 왜 배워야 하는가:**
```
보안 강화 없이 개발된 확장의 위험:
  - XSS 하나 → 모든 사이트의 데이터 접근 가능
  - 무분별한 권한 → 사용자 신뢰 손상
  - 원격 코드 실행 → 사용자 브라우저 완전 장악

크롬 스토어 요구사항:
  - MV3 의무 전환 (2024년~)
  - CSP 필수 설정
  - 최소 권한 원칙
```

### 핵심 보안 원칙

```
1. 최소 권한 원칙
   필요한 권한만 요청 (Optional Permissions 사용)
   activeTab > <all_urls>

2. CSP 설정
   manifest.json:
   "content_security_policy": {
       "extension_pages": "script-src 'self'; object-src 'none'"
   }
   → eval(), innerHTML 등 차단

3. 입력 검증
   DOM 조작 시:
   elem.textContent = userInput  // 안전
   elem.innerHTML = userInput    // 위험!

4. 메시지 검증
   발신자 origin 확인
   허가된 도메인만 통신 허용

5. 원격 코드 로드 금지
   모든 스크립트는 확장 패키지에 포함
   CDN 직접 로드 금지
```

### 필요한 도구
- **eslint-plugin-no-unsanitized**: XSS 방지 린터
- **web-ext**: 확장 개발·테스트 CLI
- **CRXcavator**: 보안 점수 확인

### 기초 실습 예제
```javascript
// 보안 강화된 content.js 패턴
// 1. 안전한 DOM 조작
function safeSetText(element, text) {
    element.textContent = text;  // innerHTML 대신 textContent
}

// 2. 메시지 발신자 검증
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    const ALLOWED_ORIGINS = ['https://myapp.com'];

    if (!ALLOWED_ORIGINS.includes(sender.url?.split('/').slice(0, 3).join('/'))) {
        console.warn('허가되지 않은 발신자:', sender.url);
        return;
    }

    // 허가된 작업만 처리
    if (message.type === 'getData') {
        sendResponse({ data: 'safe_data' });
    }
});

// 3. 권한 요청 최소화
chrome.permissions.request(
    { permissions: ['tabs'], origins: ['https://specific-site.com/*'] },
    (granted) => { if (granted) console.log('권한 획득'); }
);
```

---

## 1. Manifest V3 보안 개선사항

### 1.1 Service Worker vs Background Page

```
Manifest V2 Background Page         Manifest V3 Service Worker
────────────────────────────────    ──────────────────────────────
항상 메모리 상주                      이벤트 기반 — 유휴 시 종료
eval() 허용 가능                      eval() 완전 금지
원격 코드 로딩 가능                   원격 코드 로딩 금지
webRequestBlocking 사용              declarativeNetRequest 사용
DOM 접근 불가 (이미 제한됨)          DOM 접근 불가
```

**보안 영향:**
- 영구 백그라운드 프로세스 제거 → 지속적 악성 코드 실행 어려워짐
- eval 금지 → 동적 코드 인젝션 불가
- 원격 코드 금지 → 업데이트를 통한 악성 코드 삽입 차단

### 1.2 declarativeNetRequest 보안 모델

```json
// rules.json — 정적 규칙 정의
[
  {
    "id": 1,
    "priority": 1,
    "action": { "type": "block" },
    "condition": {
      "urlFilter": "||malicious-tracker.example.com",
      "resourceTypes": ["script", "xmlhttprequest"]
    }
  },
  {
    "id": 2,
    "priority": 2,
    "action": {
      "type": "modifyHeaders",
      "requestHeaders": [
        { "header": "Referer", "operation": "remove" }
      ]
    },
    "condition": {
      "urlFilter": "||third-party-analytics.example.com",
      "resourceTypes": ["xmlhttprequest"]
    }
  }
]
```

```json
// manifest.json에 규칙 파일 등록
{
  "declarative_net_request": {
    "rule_resources": [
      {
        "id": "ruleset_1",
        "enabled": true,
        "path": "rules.json"
      }
    ]
  },
  "permissions": ["declarativeNetRequest"]
}
```

V3의 declarativeNetRequest는 규칙 기반이므로 확장이 임의로 요청 내용을 읽거나 수정할 수 없다. 브라우저가 규칙만 보고 처리하므로 사용자 트래픽 노출 없이 필터링이 가능하다.

---

## 2. 안전한 확장 개발 가이드라인 (OWASP 기반)

### 2.1 입력 검증 및 출력 인코딩

```javascript
// 안전한 DOM 조작 유틸리티
class SafeDOM {
  /**
   * XSS 없이 텍스트 삽입
   * @param {HTMLElement} container
   * @param {string} text
   */
  static setText(container, text) {
    container.textContent = String(text);
  }

  /**
   * 허용된 태그만 포함한 안전한 HTML 삽입
   * @param {HTMLElement} container
   * @param {string} html
   */
  static setSafeHTML(container, html) {
    // 허용 태그 화이트리스트
    const ALLOWED_TAGS = new Set(['b', 'i', 'em', 'strong', 'span', 'div', 'p', 'br']);
    
    const template = document.createElement('template');
    template.innerHTML = html;
    
    // 모든 엘리먼트 순회하며 비허용 태그 제거
    const removeDisallowed = (node) => {
      const children = Array.from(node.childNodes);
      for (const child of children) {
        if (child.nodeType === Node.ELEMENT_NODE) {
          if (!ALLOWED_TAGS.has(child.tagName.toLowerCase())) {
            // 비허용 태그: 내용은 유지하되 태그 제거
            child.replaceWith(...child.childNodes);
          } else {
            // 모든 이벤트 속성 제거
            Array.from(child.attributes).forEach((attr) => {
              if (attr.name.startsWith('on') || attr.name === 'href' && attr.value.startsWith('javascript:')) {
                child.removeAttribute(attr.name);
              }
            });
            removeDisallowed(child);
          }
        }
      }
    };
    
    removeDisallowed(template.content);
    container.innerHTML = '';
    container.appendChild(template.content);
  }

  /**
   * URL 안전성 검증
   * @param {string} url
   * @returns {string|null} 안전한 URL 또는 null
   */
  static sanitizeURL(url) {
    try {
      const parsed = new URL(url);
      const allowedProtocols = new Set(['https:', 'http:']);
      if (!allowedProtocols.has(parsed.protocol)) {
        return null;  // javascript:, data: 등 차단
      }
      return parsed.href;
    } catch {
      return null;
    }
  }
}
```

### 2.2 메시지 검증 미들웨어

```javascript
// message-validator.js — Background Script용 메시지 검증 미들웨어

class MessageValidator {
  constructor() {
    // 허용된 메시지 타입과 스키마 정의
    this.schemas = new Map();
  }

  /**
   * 메시지 타입 등록
   * @param {string} type - 메시지 타입
   * @param {object} schema - 필드 검증 스키마
   * @param {string[]} allowedSenders - 허용된 발신자 (tab URL 패턴 또는 'extension')
   */
  register(type, schema, allowedSenders = ['extension']) {
    this.schemas.set(type, { schema, allowedSenders });
    return this;
  }

  /**
   * 메시지 검증
   * @param {object} message
   * @param {chrome.runtime.MessageSender} sender
   * @returns {{ valid: boolean, error?: string }}
   */
  validate(message, sender) {
    if (!message || typeof message !== 'object') {
      return { valid: false, error: '메시지가 객체가 아님' };
    }
    if (!message.type || typeof message.type !== 'string') {
      return { valid: false, error: 'type 필드 없음' };
    }

    const config = this.schemas.get(message.type);
    if (!config) {
      return { valid: false, error: `알 수 없는 메시지 타입: ${message.type}` };
    }

    // 발신자 검증
    if (!this._validateSender(sender, config.allowedSenders)) {
      return { valid: false, error: `허가되지 않은 발신자: ${sender.url || sender.id}` };
    }

    // 필드 스키마 검증
    const fieldError = this._validateFields(message, config.schema);
    if (fieldError) {
      return { valid: false, error: fieldError };
    }

    return { valid: true };
  }

  _validateSender(sender, allowedSenders) {
    for (const allowed of allowedSenders) {
      if (allowed === 'extension' && !sender.tab) return true;
      if (allowed === 'content_script' && sender.tab) return true;
      if (sender.url && sender.url.startsWith(allowed)) return true;
      if (sender.id === allowed) return true;
    }
    return false;
  }

  _validateFields(message, schema) {
    for (const [field, rules] of Object.entries(schema)) {
      const value = message[field];
      if (rules.required && value === undefined) {
        return `필수 필드 없음: ${field}`;
      }
      if (value !== undefined && rules.type && typeof value !== rules.type) {
        return `타입 오류: ${field} (${typeof value} != ${rules.type})`;
      }
      if (rules.maxLength && typeof value === 'string' && value.length > rules.maxLength) {
        return `필드 길이 초과: ${field}`;
      }
      if (rules.pattern && typeof value === 'string' && !rules.pattern.test(value)) {
        return `패턴 불일치: ${field}`;
      }
    }
    return null;
  }
}

// 사용 예시
const validator = new MessageValidator()
  .register('GET_TAB_INFO', {}, ['extension', 'content_script'])
  .register('REPORT_THREAT', {
    threatType: { required: true, type: 'string', maxLength: 50 },
    url: { required: true, type: 'string', maxLength: 2000 },
  }, ['content_script'])
  .register('UPDATE_SETTING', {
    key: { required: true, type: 'string', maxLength: 100, pattern: /^[a-zA-Z_][a-zA-Z0-9_]*$/ },
    value: { required: true },
  }, ['extension']);

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const { valid, error } = validator.validate(message, sender);
  if (!valid) {
    console.warn('[BG] 메시지 검증 실패:', error);
    sendResponse({ success: false, error });
    return;
  }
  // 검증 통과 후 처리
  handleMessage(message, sender, sendResponse);
  return true;
});
```

---

## 3. 확장 코드 감사 체크리스트

### 3.1 Manifest 보안 체크

```
[ ] manifest_version: 3 사용 (V2 지양)
[ ] name, version, description 적절히 설정
[ ] permissions 최소 권한 원칙 적용
    [ ] activeTab 우선 사용 (tabs보다 안전)
    [ ] <all_urls> 미사용
    [ ] 실제 사용하지 않는 권한 제거
[ ] host_permissions 필요한 도메인만 명시
[ ] content_security_policy 명시
    [ ] script-src 'self' 만 허용
    [ ] object-src 'none' 또는 'self'
    [ ] unsafe-eval 미포함
    [ ] unsafe-inline 미포함
    [ ] 외부 CDN 미포함
[ ] externally_connectable 명시적 허용 목록
[ ] web_accessible_resources 최소화
    [ ] 불필요한 파일 노출 금지
    [ ] matches를 특정 도메인으로 제한
```

### 3.2 JavaScript 코드 보안 체크

```
Content Script:
[ ] window 출처 검증 없는 postMessage 처리 없음
[ ] innerHTML/outerHTML 직접 할당 없음
[ ] document.write 사용 없음
[ ] 페이지에서 받은 데이터 검증 후 사용
[ ] chrome.runtime.sendMessage에서 lastError 처리

Background Script:
[ ] 모든 메시지 발신자 검증
[ ] 허용된 URL 목록 기반 fetch
[ ] eval(), new Function() 사용 없음
[ ] 원격 코드 로딩 없음
[ ] chrome.storage에 민감 데이터 암호화 저장

Popup / Options Page:
[ ] innerHTML에 사용자 입력 직접 삽입 없음
[ ] chrome.storage 데이터 렌더링 시 textContent 사용
[ ] 외부 스크립트 로딩 없음
[ ] 인라인 이벤트 핸들러 없음 (onclick="..." 형식)
[ ] CSP가 팝업에도 적용되는지 확인
```

### 3.3 자동화 코드 감사 스크립트

```bash
#!/bin/bash
# extension_audit.sh — 확장 기본 보안 감사

EXT_DIR="$1"
if [ -z "$EXT_DIR" ]; then
    echo "사용법: $0 <확장_디렉토리>"
    exit 1
fi

echo "=== 브라우저 확장 보안 감사 ==="
echo "대상: $EXT_DIR"
echo ""

# 1. 위험 권한 체크
echo "[1] 위험 권한 분석"
python3 -c "
import json, sys
try:
    m = json.load(open('$EXT_DIR/manifest.json'))
    dangerous = ['<all_urls>', 'webRequestBlocking', 'nativeMessaging', 'debugger', 'management', 'proxy', 'cookies', 'history']
    perms = m.get('permissions', []) + m.get('host_permissions', [])
    found = [p for p in perms if p in dangerous or p.startswith('https://*/*')]
    if found:
        print('  [경고] 위험 권한:', found)
    else:
        print('  [OK] 위험 권한 없음')
except Exception as e:
    print('  [오류]', e)
"

# 2. CSP 검사
echo ""
echo "[2] CSP 분석"
python3 -c "
import json
m = json.load(open('$EXT_DIR/manifest.json'))
csp = m.get('content_security_policy', {})
if isinstance(csp, dict):
    csp = csp.get('extension_pages', '')
if not csp:
    print('  [경고] CSP 미설정')
elif 'unsafe-eval' in csp:
    print('  [경고] unsafe-eval 포함')
elif 'unsafe-inline' in csp:
    print('  [경고] unsafe-inline 포함')
else:
    print('  [OK] CSP 설정됨:', csp[:60])
"

# 3. 코드 패턴 검사
echo ""
echo "[3] 위험 코드 패턴"

patterns=(
    "eval("
    "innerHTML ="
    "document.write"
    "new Function("
    "atob("
    "_0x[0-9a-f]"
)

for pattern in "${patterns[@]}"; do
    count=$(grep -rn "$pattern" "$EXT_DIR" --include="*.js" 2>/dev/null | wc -l)
    if [ "$count" -gt 0 ]; then
        echo "  [경고] '$pattern' $count건:"
        grep -rn "$pattern" "$EXT_DIR" --include="*.js" 2>/dev/null | head -3 | sed 's/^/    /'
    fi
done

# 4. 외부 URL 목록
echo ""
echo "[4] 외부 URL 목록"
grep -rEoh "https?://[a-zA-Z0-9._/-]+" "$EXT_DIR" --include="*.js" 2>/dev/null | \
    grep -v "chrome-extension://" | sort -u | head -20

echo ""
echo "=== 감사 완료 ==="
```

---

## 4. 권한 최소화 원칙

### 4.1 권한 다운그레이드 패턴

```javascript
// 나쁜 예: 모든 탭에 대한 tabs 권한 요청
// manifest.json: "permissions": ["tabs"]

// 좋은 예: activeTab만 사용 — 사용자 클릭 시에만 접근
// manifest.json: "permissions": ["activeTab"]

// activeTab 활용 패턴
chrome.action.onClicked.addListener(async (tab) => {
  // activeTab 권한으로 현재 탭 URL 접근 가능 (사용자 클릭 후)
  console.log('현재 탭 URL:', tab.url);
  
  // scripting.executeScript로 코드 실행
  await chrome.scripting.executeScript({
    target: { tabId: tab.id },
    func: () => {
      return document.title;
    }
  });
});
```

### 4.2 선택적 권한 (Optional Permissions)

```json
// manifest.json
{
  "permissions": ["storage"],
  "optional_permissions": ["history", "bookmarks", "cookies"],
  "optional_host_permissions": ["https://*/*"]
}
```

```javascript
// 필요할 때만 권한 요청
async function requestHistoryAccess() {
  const granted = await chrome.permissions.request({
    permissions: ['history'],
  });
  
  if (granted) {
    console.log('[+] history 권한 획득');
    return true;
  } else {
    console.log('[-] 사용자가 권한 거부');
    return false;
  }
}

// 권한 확인
async function checkPermissions() {
  const hasHistory = await chrome.permissions.contains({ permissions: ['history'] });
  console.log('history 권한:', hasHistory);
  return { history: hasHistory };
}

// 불필요 권한 반환
async function revokeUnneededPermissions() {
  await chrome.permissions.remove({ permissions: ['history', 'bookmarks'] });
  console.log('[+] 불필요 권한 반환 완료');
}
```

---

## 5. 기업 환경 확장 관리 (Chrome Enterprise Policy)

### 5.1 정책 파일 설정

```json
// /etc/opt/chrome/policies/managed/extensions.json (Linux)
// HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome (Windows)

{
  // 특정 확장만 허용
  "ExtensionAllowlist": [
    "cjpalhdlnbpafiamejdnhcphjbkeiagm",  // uBlock Origin
    "mnjggcdmjocbbbhaepdhchncahnbgone"   // 허용된 보안 확장
  ],
  
  // 특정 확장 차단
  "ExtensionBlocklist": [
    "*",  // 모든 확장 차단 (AllowList에 없는 것)
    "aapocclcgogkmnckokdopfmhonfmgoek"  // 특정 ID 차단
  ],
  
  // 강제 설치 확장
  "ExtensionInstallForcelist": [
    "cjpalhdlnbpafiamejdnhcphjbkeiagm;https://clients2.google.com/service/update2/crx"
  ],
  
  // 위험 권한 차단
  "ExtensionSettings": {
    "*": {
      "blocked_permissions": [
        "history",
        "nativeMessaging", 
        "debugger"
      ]
    }
  },
  
  // 확장 설치 소스 제한
  "ExtensionInstallSources": [
    "https://clients2.google.com/service/update2/crx",
    "https://internal-ext-server.company.example.com/*"
  ]
}
```

### 5.2 정책 배포 (Linux)

```bash
# 정책 디렉토리 생성
sudo mkdir -p /etc/opt/chrome/policies/managed/

# 정책 파일 작성
sudo tee /etc/opt/chrome/policies/managed/security_policy.json << 'EOF'
{
  "ExtensionBlocklist": ["*"],
  "ExtensionAllowlist": [
    "cjpalhdlnbpafiamejdnhcphjbkeiagm"
  ],
  "BrowserSignin": 1,
  "RestrictSigninToPattern": ".*@company.example.com"
}
EOF

# 권한 설정
sudo chmod 644 /etc/opt/chrome/policies/managed/security_policy.json

# 정책 확인 (Chrome에서)
# chrome://policy 접속하여 정책 적용 확인
```

### 5.3 Windows GPO를 통한 배포

```powershell
# PowerShell — 크롬 확장 정책 설정
$chromePolicyPath = "HKLM:\SOFTWARE\Policies\Google\Chrome"
$extensionPath = "$chromePolicyPath\ExtensionInstallForcelist"

# 레지스트리 경로 생성
New-Item -Path $extensionPath -Force | Out-Null

# 강제 설치 확장 추가
$extensionId = "cjpalhdlnbpafiamejdnhcphjbkeiagm"
$updateUrl = "https://clients2.google.com/service/update2/crx"
Set-ItemProperty -Path $extensionPath -Name "1" -Value "$extensionId;$updateUrl"

# 차단 목록 설정
$blockPath = "$chromePolicyPath\ExtensionBlocklist"
New-Item -Path $blockPath -Force | Out-Null
Set-ItemProperty -Path $blockPath -Name "1" -Value "*"

Write-Host "[+] 정책 설정 완료"
```

---

## 6. 확장 업데이트 무결성 검증

### 6.1 CRX 서명 검증

```python
#!/usr/bin/env python3
"""
CRX 파일 서명 및 무결성 검증 도구
사용법: python3 verify_crx.py <crx_파일>
"""

import argparse
import hashlib
import json
import os
import struct
import sys
import zipfile
from pathlib import Path
from dataclasses import dataclass
from typing import Optional


@dataclass
class CRXInfo:
    version: int
    zip_hash_sha256: str
    file_count: int
    total_size: int
    manifest_hash: str
    extension_name: str = ""
    extension_version: str = ""


def compute_file_hash(path: Path, algorithm: str = "sha256") -> str:
    """파일 해시 계산"""
    h = hashlib.new(algorithm)
    with path.open("rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def extract_crx_zip_offset(data: bytes) -> int:
    """CRX에서 ZIP 데이터 시작 오프셋 반환"""
    magic = data[:4]
    
    if magic == b"Cr24":
        version = struct.unpack_from("<I", data, 4)[0]
        if version == 3:
            header_size = struct.unpack_from("<I", data, 8)[0]
            return 12 + header_size
        elif version == 2:
            pubkey_len = struct.unpack_from("<I", data, 8)[0]
            sig_len = struct.unpack_from("<I", data, 12)[0]
            return 16 + pubkey_len + sig_len
    
    # ZIP 직접
    if magic[:2] == b"PK":
        return 0
    
    raise ValueError(f"지원하지 않는 형식: {magic}")


def verify_crx(crx_path: Path) -> CRXInfo:
    """CRX 파일 무결성 검증"""
    data = crx_path.read_bytes()
    
    # ZIP 오프셋 계산
    zip_offset = extract_crx_zip_offset(data)
    zip_data = data[zip_offset:]
    
    # ZIP 해시
    zip_hash = hashlib.sha256(zip_data).hexdigest()
    
    # ZIP 내용 분석
    import io
    with zipfile.ZipFile(io.BytesIO(zip_data)) as zf:
        file_list = zf.namelist()
        total_size = sum(info.file_size for info in zf.infolist())
        
        # manifest.json 파싱
        manifest_data = zf.read("manifest.json")
        manifest_hash = hashlib.sha256(manifest_data).hexdigest()
        manifest = json.loads(manifest_data)
    
    return CRXInfo(
        version=struct.unpack_from("<I", data, 4)[0] if data[:4] == b"Cr24" else 0,
        zip_hash_sha256=zip_hash,
        file_count=len(file_list),
        total_size=total_size,
        manifest_hash=manifest_hash,
        extension_name=manifest.get("name", ""),
        extension_version=manifest.get("version", "")
    )


def compare_versions(current_path: Path, previous_path: Path) -> dict:
    """두 CRX 버전의 차이점 비교"""
    import io, zipfile
    
    def get_crx_files(crx_path: Path) -> dict[str, str]:
        data = crx_path.read_bytes()
        offset = extract_crx_zip_offset(data)
        files = {}
        with zipfile.ZipFile(io.BytesIO(data[offset:])) as zf:
            for name in zf.namelist():
                content = zf.read(name)
                files[name] = hashlib.sha256(content).hexdigest()
        return files
    
    current_files = get_crx_files(current_path)
    previous_files = get_crx_files(previous_path)
    
    added = {k: v for k, v in current_files.items() if k not in previous_files}
    removed = {k: v for k, v in previous_files.items() if k not in current_files}
    modified = {
        k: {"old": previous_files[k], "new": current_files[k]}
        for k in current_files
        if k in previous_files and current_files[k] != previous_files[k]
    }
    
    return {"added": added, "removed": removed, "modified": modified}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="CRX 무결성 검증 및 버전 비교")
    parser.add_argument("crx", help="검증할 CRX 파일")
    parser.add_argument("--compare", metavar="PREV_CRX", help="이전 버전 CRX와 비교")
    parser.add_argument("--expected-hash", help="예상 SHA-256 해시 (검증용)")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    crx_path = Path(args.crx)
    
    if not crx_path.exists():
        print(f"[!] 파일 없음: {crx_path}", file=sys.stderr)
        return 1
    
    try:
        info = verify_crx(crx_path)
        
        print("\n=== CRX 무결성 정보 ===")
        print(f"  이름: {info.extension_name}")
        print(f"  버전: {info.extension_version}")
        print(f"  CRX 버전: {info.version}")
        print(f"  파일 수: {info.file_count}")
        print(f"  총 크기: {info.total_size:,} 바이트")
        print(f"  ZIP SHA-256: {info.zip_hash_sha256}")
        print(f"  manifest SHA-256: {info.manifest_hash}")
        
        if args.expected_hash:
            if info.zip_hash_sha256 == args.expected_hash.lower():
                print("\n[OK] 해시 검증 성공 — 무결성 확인됨")
            else:
                print("\n[경고] 해시 불일치!")
                print(f"  예상: {args.expected_hash.lower()}")
                print(f"  실제: {info.zip_hash_sha256}")
                return 2
        
        if args.compare:
            prev_path = Path(args.compare)
            if not prev_path.exists():
                print(f"[!] 이전 버전 파일 없음: {prev_path}", file=sys.stderr)
                return 1
            
            diff = compare_versions(crx_path, prev_path)
            
            print("\n=== 버전 비교 ===")
            if diff["added"]:
                print(f"  추가된 파일 ({len(diff['added'])}개):")
                for f in diff["added"]:
                    print(f"    + {f}")
            if diff["removed"]:
                print(f"  제거된 파일 ({len(diff['removed'])}개):")
                for f in diff["removed"]:
                    print(f"    - {f}")
            if diff["modified"]:
                print(f"  변경된 파일 ({len(diff['modified'])}개):")
                for f in diff["modified"]:
                    print(f"    ~ {f}")
            
            if not any(diff.values()):
                print("  변경사항 없음")
    
    except Exception as e:
        print(f"[!] 오류: {e}", file=sys.stderr)
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

---

## 7. 조직 내 설치된 확장 위험도 평가 스크립트

```python
#!/usr/bin/env python3
"""
조직 내 설치된 Chrome 확장 위험도 평가 도구
사용법: python3 org_ext_auditor.py --profile-dir /path/to/chrome/profile
"""

import argparse
import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
import hashlib


# ───────────────────────────── 위험도 DB ─────────────────────────────

DANGEROUS_PERMISSIONS = {
    "<all_urls>":           (10, "모든 URL 접근"),
    "webRequestBlocking":   (10, "HTTP 요청 차단 및 수정"),
    "nativeMessaging":      (10, "로컬 시스템 통신"),
    "debugger":             (10, "Chrome DevTools 접근"),
    "proxy":                (10, "프록시 설정 변경"),
    "management":           (9,  "다른 확장 제어"),
    "cookies":              (7,  "쿠키 접근"),
    "history":              (7,  "브라우저 히스토리"),
    "tabs":                 (6,  "모든 탭 URL 접근"),
    "webRequest":           (6,  "HTTP 요청 관찰"),
    "clipboardRead":        (6,  "클립보드 읽기"),
    "downloads":            (5,  "다운로드 관리"),
    "bookmarks":            (4,  "북마크 접근"),
    "contentSettings":      (6,  "사이트 콘텐츠 설정"),
    "geolocation":          (6,  "위치 정보"),
    "storage":              (2,  "확장 스토리지"),
    "notifications":        (2,  "알림 표시"),
    "activeTab":            (1,  "현재 탭 접근"),
    "scripting":            (3,  "스크립트 동적 주입"),
}


@dataclass
class ExtensionAuditResult:
    extension_id: str
    name: str
    version: str
    manifest_version: int
    enabled: bool
    install_time: str = ""
    permissions: list[str] = field(default_factory=list)
    host_permissions: list[str] = field(default_factory=list)
    risk_score: int = 0
    risk_level: str = "low"
    risk_reasons: list[str] = field(default_factory=list)
    external_urls: list[str] = field(default_factory=list)


def calculate_risk(permissions: list[str], host_perms: list[str]) -> tuple[int, str, list[str]]:
    """권한 기반 위험도 점수 계산"""
    score = 0
    reasons = []
    all_perms = permissions + host_perms
    
    for perm in all_perms:
        if perm in DANGEROUS_PERMISSIONS:
            s, reason = DANGEROUS_PERMISSIONS[perm]
            score += s
            reasons.append(f"{perm}: {reason} (+{s}점)")
        elif "*" in perm and (perm.startswith("http") or perm == "<all_urls>"):
            score += 8
            reasons.append(f"와일드카드 호스트 권한: {perm} (+8점)")
        elif perm.startswith("http"):
            score += 3
            reasons.append(f"호스트 권한: {perm} (+3점)")
    
    # 위험 조합 보너스
    perm_set = set(all_perms)
    if "webRequestBlocking" in perm_set and "cookies" in perm_set:
        score += 5
        reasons.append("webRequestBlocking + cookies 조합 (+5점)")
    if "history" in perm_set and "tabs" in perm_set:
        score += 3
        reasons.append("history + tabs 조합 (행동 추적 가능) (+3점)")
    
    if score >= 20:
        level = "critical"
    elif score >= 12:
        level = "high"
    elif score >= 6:
        level = "medium"
    else:
        level = "low"
    
    return score, level, reasons


def scan_extensions(profile_dir: Path) -> list[ExtensionAuditResult]:
    """Chrome 프로필 내 설치된 확장 스캔"""
    ext_dir = profile_dir / "Extensions"
    if not ext_dir.exists():
        raise FileNotFoundError(f"Extensions 디렉토리 없음: {ext_dir}")
    
    # 확장 상태 파일 (활성/비활성 정보)
    prefs_path = profile_dir / "Preferences"
    installed_extensions: dict[str, dict] = {}
    
    if prefs_path.exists():
        try:
            prefs = json.loads(prefs_path.read_text(encoding="utf-8"))
            ext_settings = prefs.get("extensions", {}).get("settings", {})
            for ext_id, ext_data in ext_settings.items():
                installed_extensions[ext_id] = {
                    "enabled": ext_data.get("state", 1) == 1,
                    "install_time": ext_data.get("install_time", "")
                }
        except (json.JSONDecodeError, OSError):
            pass
    
    results = []
    
    for ext_id_dir in ext_dir.iterdir():
        if not ext_id_dir.is_dir():
            continue
        
        ext_id = ext_id_dir.name
        
        # 최신 버전 디렉토리 찾기
        version_dirs = sorted(
            [d for d in ext_id_dir.iterdir() if d.is_dir()],
            reverse=True
        )
        
        if not version_dirs:
            continue
        
        manifest_path = version_dirs[0] / "manifest.json"
        if not manifest_path.exists():
            continue
        
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8", errors="ignore"))
        except (json.JSONDecodeError, OSError):
            continue
        
        # 권한 파싱
        raw_perms = manifest.get("permissions", [])
        raw_host = manifest.get("host_permissions", [])
        
        mv = manifest.get("manifest_version", 2)
        if mv == 2:
            host_perms = [p for p in raw_perms if p.startswith("http") or p == "<all_urls>"]
            api_perms = [p for p in raw_perms if not (p.startswith("http") or p == "<all_urls>")]
        else:
            api_perms = raw_perms
            host_perms = raw_host
        
        # 위험도 계산
        risk_score, risk_level, risk_reasons = calculate_risk(api_perms, host_perms)
        
        # 외부 URL 추출 (간단 버전)
        external_urls = []
        for js_file in version_dirs[0].rglob("*.js"):
            try:
                content = js_file.read_text(encoding="utf-8", errors="ignore")
                import re
                urls = re.findall(r"https?://[a-zA-Z0-9._/-]+", content)
                for url in urls:
                    if not url.startswith("chrome-extension://") and url not in external_urls:
                        external_urls.append(url)
            except OSError:
                continue
        
        ext_info = installed_extensions.get(ext_id, {})
        
        result = ExtensionAuditResult(
            extension_id=ext_id,
            name=manifest.get("name", "알 수 없음"),
            version=manifest.get("version", "?"),
            manifest_version=mv,
            enabled=ext_info.get("enabled", True),
            install_time=ext_info.get("install_time", ""),
            permissions=api_perms,
            host_permissions=host_perms,
            risk_score=risk_score,
            risk_level=risk_level,
            risk_reasons=risk_reasons,
            external_urls=list(set(external_urls))[:20]
        )
        results.append(result)
    
    return sorted(results, key=lambda r: r.risk_score, reverse=True)


def print_audit_report(results: list[ExtensionAuditResult], min_risk: str = "low") -> None:
    COLORS = {
        "critical": "\033[91m", "high": "\033[31m",
        "medium": "\033[33m", "low": "\033[32m", "reset": "\033[0m"
    }
    RISK_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    min_order = RISK_ORDER.get(min_risk, 3)
    
    def c(text, level):
        return f"{COLORS.get(level,'')}{text}{COLORS['reset']}"
    
    filtered = [r for r in results if RISK_ORDER.get(r.risk_level, 3) <= min_order]
    
    print("\n" + "="*65)
    print("  조직 Chrome 확장 위험도 평가 리포트")
    print("="*65)
    print(f"  전체 확장: {len(results)}개 | 출력 대상: {len(filtered)}개 (최소: {min_risk})")
    
    # 위험도별 통계
    stats = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for r in results:
        stats[r.risk_level] = stats.get(r.risk_level, 0) + 1
    
    print("\n--- 위험도 분포 ---")
    for level, count in stats.items():
        bar = "█" * min(count, 20)
        print(f"  {c(level.upper():8}, level)}: {count:3}개  {bar}")
    
    print("\n--- 확장별 상세 ---")
    for r in filtered:
        status = "활성" if r.enabled else "비활성"
        print(f"\n  [{c(r.risk_level.upper(), r.risk_level)}] {r.name} (v{r.version}) — {status}")
        print(f"    ID: {r.extension_id}")
        print(f"    위험 점수: {r.risk_score}점 | MV{r.manifest_version}")
        if r.risk_reasons:
            print(f"    위험 사유:")
            for reason in r.risk_reasons[:3]:
                print(f"      • {reason}")
        if r.external_urls:
            print(f"    외부 URL ({len(r.external_urls)}개, 상위 3개):")
            for url in r.external_urls[:3]:
                print(f"      • {url[:60]}")
    
    print("\n" + "="*65 + "\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="조직 내 Chrome 확장 위험도 평가",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
예시:
  # Linux Chrome 기본 프로필
  python3 org_ext_auditor.py --profile-dir ~/.config/google-chrome/Default

  # Windows (WSL에서)
  python3 org_ext_auditor.py --profile-dir "/mnt/c/Users/user/AppData/Local/Google/Chrome/User Data/Default"

  # 위험 이상만 출력
  python3 org_ext_auditor.py --profile-dir ~/.config/google-chrome/Default --min-risk high

  # JSON 저장
  python3 org_ext_auditor.py --profile-dir ~/.config/google-chrome/Default --json report.json
"""
    )
    parser.add_argument("--profile-dir", required=True, help="Chrome 프로필 디렉토리")
    parser.add_argument("--min-risk", choices=["critical","high","medium","low"], 
                        default="low", help="이 위험도 이상만 출력")
    parser.add_argument("--json", metavar="OUTPUT", help="JSON 리포트 저장")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    profile_dir = Path(args.profile_dir)
    
    if not profile_dir.exists():
        print(f"[!] 프로필 디렉토리 없음: {profile_dir}", file=sys.stderr)
        return 1
    
    print(f"[*] 확장 스캔 중: {profile_dir}")
    
    try:
        results = scan_extensions(profile_dir)
    except FileNotFoundError as e:
        print(f"[!] {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"[!] 스캔 오류: {e}", file=sys.stderr)
        return 1
    
    print_audit_report(results, args.min_risk)
    
    if args.json:
        import dataclasses
        output_path = Path(args.json)
        output_path.write_text(
            json.dumps([dataclasses.asdict(r) for r in results], ensure_ascii=False, indent=2),
            encoding="utf-8"
        )
        print(f"[+] JSON 저장: {output_path}")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

---

## 8. 안전한 확장 아키텍처 설계 패턴

### 8.1 최소 권한 아키텍처

```
[최소 권한 확장 설계]

사용 케이스별 권한 선택:

케이스: 현재 페이지 분석
  ❌ "tabs" 권한 + host_permissions: ["<all_urls>"]
  ✅ "activeTab" 권한만 (사용자 클릭 시 현재 탭만 접근)

케이스: 특정 사이트와 통신
  ❌ host_permissions: ["<all_urls>"]
  ✅ host_permissions: ["https://api.myservice.example.com/*"]

케이스: HTTP 요청 필터링
  ❌ "webRequestBlocking" (V2)
  ✅ "declarativeNetRequest" + rules.json (V3)

케이스: 데이터 동기화
  ❌ chrome.storage.sync + 평문 저장
  ✅ chrome.storage.local + AES-GCM 암호화
```

### 8.2 암호화 스토리지 패턴

```javascript
// secure-storage.js — AES-GCM 기반 안전한 스토리지

class SecureStorage {
  constructor() {
    this.keyPromise = this._getOrCreateKey();
  }

  async _getOrCreateKey() {
    // 기존 키 로드 또는 신규 생성
    const existing = await chrome.storage.local.get(['_encKey']);
    
    if (existing._encKey) {
      // JWK 형식으로 저장된 키 복원
      return crypto.subtle.importKey(
        'jwk',
        JSON.parse(existing._encKey),
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt']
      );
    }
    
    // 새 AES-256-GCM 키 생성
    const key = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );
    
    // 키 저장
    const exported = await crypto.subtle.exportKey('jwk', key);
    await chrome.storage.local.set({ _encKey: JSON.stringify(exported) });
    
    return key;
  }

  async set(key, value) {
    const cryptoKey = await this.keyPromise;
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encoded = new TextEncoder().encode(JSON.stringify(value));
    
    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      cryptoKey,
      encoded
    );
    
    // IV + 암호문을 base64로 저장
    const combined = new Uint8Array(iv.length + ciphertext.byteLength);
    combined.set(iv);
    combined.set(new Uint8Array(ciphertext), iv.length);
    
    const b64 = btoa(String.fromCharCode(...combined));
    await chrome.storage.local.set({ [key]: { __encrypted: true, data: b64 } });
  }

  async get(key) {
    const result = await chrome.storage.local.get([key]);
    const stored = result[key];
    
    if (!stored || !stored.__encrypted) {
      return stored;
    }
    
    const cryptoKey = await this.keyPromise;
    const combined = Uint8Array.from(atob(stored.data), c => c.charCodeAt(0));
    const iv = combined.slice(0, 12);
    const ciphertext = combined.slice(12);
    
    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      cryptoKey,
      ciphertext
    );
    
    return JSON.parse(new TextDecoder().decode(decrypted));
  }

  async remove(key) {
    await chrome.storage.local.remove(key);
  }
}

// 사용 예시
const secureStorage = new SecureStorage();

// 토큰 안전하게 저장
await secureStorage.set('authToken', { token: 'sensitive-value', expiry: Date.now() + 3600000 });

// 토큰 복호화하여 읽기
const tokenData = await secureStorage.get('authToken');
```

### 8.3 안전한 Content Script 통신 패턴

```javascript
// secure-messaging.js — HMAC 서명 기반 메시지 인증

class SecureMessenger {
  constructor(sharedSecret) {
    this.secretPromise = crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(sharedSecret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign', 'verify']
    );
  }

  async signMessage(payload) {
    const key = await this.secretPromise;
    const timestamp = Date.now();
    const nonce = crypto.getRandomValues(new Uint8Array(8)).join('');
    const data = JSON.stringify({ payload, timestamp, nonce });
    
    const signature = await crypto.subtle.sign(
      'HMAC',
      key,
      new TextEncoder().encode(data)
    );
    
    return {
      data,
      signature: btoa(String.fromCharCode(...new Uint8Array(signature))),
      timestamp,
      nonce
    };
  }

  async verifyMessage(signedMessage) {
    const { data, signature, timestamp } = signedMessage;
    
    // 타임스탬프 검증 (5분 이내)
    if (Math.abs(Date.now() - timestamp) > 5 * 60 * 1000) {
      throw new Error('메시지 타임스탬프 만료');
    }
    
    const key = await this.secretPromise;
    const sigBytes = Uint8Array.from(atob(signature), c => c.charCodeAt(0));
    
    const valid = await crypto.subtle.verify(
      'HMAC',
      key,
      sigBytes,
      new TextEncoder().encode(data)
    );
    
    if (!valid) {
      throw new Error('메시지 서명 검증 실패');
    }
    
    return JSON.parse(data).payload;
  }
}
```

---

## 9. 확장 보안 체크리스트 요약

```
개발 단계:
✓ Manifest V3 사용
✓ 최소 권한 원칙 (activeTab 우선)
✓ CSP 엄격하게 설정 (unsafe-eval/unsafe-inline 없음)
✓ 모든 외부 통신 HTTPS
✓ 메시지 발신자 검증
✓ 사용자 입력 textContent로 처리
✓ 민감 데이터 암호화 저장
✓ SRI (Subresource Integrity) 적용

코드 리뷰:
✓ eval(), Function(), setTimeout(string) 없음
✓ innerHTML 직접 할당 없음
✓ postMessage 출처 검증
✓ chrome.storage.get(null) 없음
✓ 하드코딩된 시크릿 없음

배포 및 운영:
✓ 코드 서명 (CRX signing key 안전 보관)
✓ 업데이트 전 변경사항 검토
✓ Chrome Web Store 2단계 인증
✓ 기업 환경 ExtensionBlocklist 정책
✓ 정기적 확장 설치 현황 감사
```

---

## 참고 자료

- Chrome Extensions Security: https://developer.chrome.com/docs/extensions/mv3/security/
- OWASP Browser Extension Security: https://owasp.org/
- Chrome Enterprise Policy: https://chromeenterprise.google/policies/
- Web Crypto API: https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API
- Cure53 Extension Security Audits: https://cure53.de/

---

<!-- detect-validate-51 -->
## 확장 보안 강화 검증 (설정됨 ≠ 작동함)

확장 보안 강화는 *MV3 전환·안전 개발 가이드(OWASP)·권한 최소화·기업 정책·업데이트 무결성*으로 구성된다. "MV3로 바꿨다"는 설정과 "원격 코드가 실제로 막히고 권한이 최소인가"는 다르다 — 각 통제를 소유 확장에서 검증한다.

### 검증 항목 → 확인 질문 → 측정 신호 → 함정

| 검증 항목 | 확인 질문 | 측정 신호 | 함정 |
|---|---|---|---|
| MV3 코드 금지 | 원격/eval 없나? | eval/원격 src 0 | MV2 잔재 |
| 권한 최소화 | 필요분만? | host 최소·optional | <all_urls> 잔존 |
| 업데이트 무결성 | 서명 검증? | 변조 업데이트 거부 | 미서명 수용 |
| 기업 정책 | 허용목록 강제? | force_install만 | 자유 설치 허용 |

### 방어 검증 (직접 확인)

```bash
# 1) 소유 확장이 MV3 코드 금지를 지키는지 — eval/원격 스크립트 잔존이 강화 미흡 신호
jq -r '.manifest_version' manifest.json 2>/dev/null; grep -rInE '\beval\(|\.src\s*=\s*["'"'"']https?://|unsafe-eval' *.js manifest.json 2>/dev/null | head
# 2) 권한 최소화 검증 — host_permissions에 광역 패턴 잔존이 과대권한 신호
jq -r '.host_permissions[]?, .permissions[]?' manifest.json 2>/dev/null | grep -iE '<all_urls>|\*://\*' | head
```

> 확장 강화는 *통제가 강제되는가*다 — "MV3다"와 "eval/원격 코드가 없고 host 권한이 최소이며 업데이트가 서명 검증된다"는 다르다. 각 통제를 소유 확장에서 직접 검증한다([[60_Browser_Security]], [[35_Supply_Chain_Attacks]], [[18_DevSecOps]]).

**최신 기법·통제 (2025–2026):**
- MV3·최소권한·CSP·원격코드 금지가 표준 — 검증: 정책 위반 확장이 배포/실행에서 차단되는가([[18_DevSecOps]])
- 공급망(서드파티 라이브러리) — 강제되는지 확인

---

<a name="english"></a>

# Browser Extension Security Hardening

## 1. Manifest V3 Security Improvements

### 1.1 Service Worker vs Background Page

```
Manifest V2 Background Page         Manifest V3 Service Worker
────────────────────────────────    ──────────────────────────────
Always resident in memory            Event-driven — terminated when idle
eval() allowed                       eval() completely forbidden
Remote code loading allowed          Remote code loading forbidden
Uses webRequestBlocking              Uses declarativeNetRequest
No DOM access (already restricted)   No DOM access
```

**Security Implications:**
- Removal of persistent background processes → harder to run persistent malicious code
- eval() ban → dynamic code injection impossible
- Remote code ban → blocks malicious code insertion via updates

### 1.2 declarativeNetRequest Security Model

```json
// rules.json — static rule definitions
[
  {
    "id": 1,
    "priority": 1,
    "action": { "type": "block" },
    "condition": {
      "urlFilter": "||malicious-tracker.example.com",
      "resourceTypes": ["script", "xmlhttprequest"]
    }
  },
  {
    "id": 2,
    "priority": 2,
    "action": {
      "type": "modifyHeaders",
      "requestHeaders": [
        { "header": "Referer", "operation": "remove" }
      ]
    },
    "condition": {
      "urlFilter": "||third-party-analytics.example.com",
      "resourceTypes": ["xmlhttprequest"]
    }
  }
]
```

```json
// Register rule file in manifest.json
{
  "declarative_net_request": {
    "rule_resources": [
      {
        "id": "ruleset_1",
        "enabled": true,
        "path": "rules.json"
      }
    ]
  },
  "permissions": ["declarativeNetRequest"]
}
```

V3's declarativeNetRequest is rule-based, so extensions cannot arbitrarily read or modify request content. The browser processes only the rules, enabling filtering without exposing user traffic.

---

## 2. Secure Extension Development Guidelines (OWASP-based)

### 2.1 Input Validation and Output Encoding

```javascript
// Safe DOM manipulation utility
class SafeDOM {
  /**
   * Insert text without XSS
   * @param {HTMLElement} container
   * @param {string} text
   */
  static setText(container, text) {
    container.textContent = String(text);
  }

  /**
   * Safe HTML insertion with only allowed tags
   * @param {HTMLElement} container
   * @param {string} html
   */
  static setSafeHTML(container, html) {
    // Whitelist of allowed tags
    const ALLOWED_TAGS = new Set(['b', 'i', 'em', 'strong', 'span', 'div', 'p', 'br']);
    
    const template = document.createElement('template');
    template.innerHTML = html;
    
    // Traverse all elements and remove disallowed tags
    const removeDisallowed = (node) => {
      const children = Array.from(node.childNodes);
      for (const child of children) {
        if (child.nodeType === Node.ELEMENT_NODE) {
          if (!ALLOWED_TAGS.has(child.tagName.toLowerCase())) {
            // Disallowed tag: keep content but remove tag
            child.replaceWith(...child.childNodes);
          } else {
            // Remove all event attributes
            Array.from(child.attributes).forEach((attr) => {
              if (attr.name.startsWith('on') || attr.name === 'href' && attr.value.startsWith('javascript:')) {
                child.removeAttribute(attr.name);
              }
            });
            removeDisallowed(child);
          }
        }
      }
    };
    
    removeDisallowed(template.content);
    container.innerHTML = '';
    container.appendChild(template.content);
  }

  /**
   * URL safety validation
   * @param {string} url
   * @returns {string|null} safe URL or null
   */
  static sanitizeURL(url) {
    try {
      const parsed = new URL(url);
      const allowedProtocols = new Set(['https:', 'http:']);
      if (!allowedProtocols.has(parsed.protocol)) {
        return null;  // Block javascript:, data:, etc.
      }
      return parsed.href;
    } catch {
      return null;
    }
  }
}
```

### 2.2 Message Validation Middleware

```javascript
// message-validator.js — Message validation middleware for Background Script

class MessageValidator {
  constructor() {
    // Define allowed message types and schemas
    this.schemas = new Map();
  }

  /**
   * Register message type
   * @param {string} type - message type
   * @param {object} schema - field validation schema
   * @param {string[]} allowedSenders - allowed senders (tab URL patterns or 'extension')
   */
  register(type, schema, allowedSenders = ['extension']) {
    this.schemas.set(type, { schema, allowedSenders });
    return this;
  }

  /**
   * Validate message
   * @param {object} message
   * @param {chrome.runtime.MessageSender} sender
   * @returns {{ valid: boolean, error?: string }}
   */
  validate(message, sender) {
    if (!message || typeof message !== 'object') {
      return { valid: false, error: 'Message is not an object' };
    }
    if (!message.type || typeof message.type !== 'string') {
      return { valid: false, error: 'Missing type field' };
    }

    const config = this.schemas.get(message.type);
    if (!config) {
      return { valid: false, error: `Unknown message type: ${message.type}` };
    }

    // Validate sender
    if (!this._validateSender(sender, config.allowedSenders)) {
      return { valid: false, error: `Unauthorized sender: ${sender.url || sender.id}` };
    }

    // Field schema validation
    const fieldError = this._validateFields(message, config.schema);
    if (fieldError) {
      return { valid: false, error: fieldError };
    }

    return { valid: true };
  }

  _validateSender(sender, allowedSenders) {
    for (const allowed of allowedSenders) {
      if (allowed === 'extension' && !sender.tab) return true;
      if (allowed === 'content_script' && sender.tab) return true;
      if (sender.url && sender.url.startsWith(allowed)) return true;
      if (sender.id === allowed) return true;
    }
    return false;
  }

  _validateFields(message, schema) {
    for (const [field, rules] of Object.entries(schema)) {
      const value = message[field];
      if (rules.required && value === undefined) {
        return `Required field missing: ${field}`;
      }
      if (value !== undefined && rules.type && typeof value !== rules.type) {
        return `Type error: ${field} (${typeof value} != ${rules.type})`;
      }
      if (rules.maxLength && typeof value === 'string' && value.length > rules.maxLength) {
        return `Field length exceeded: ${field}`;
      }
      if (rules.pattern && typeof value === 'string' && !rules.pattern.test(value)) {
        return `Pattern mismatch: ${field}`;
      }
    }
    return null;
  }
}
```

---

## 3. Extension Code Audit Checklist

### 3.1 Manifest Security Check

```
[ ] Use manifest_version: 3 (avoid V2)
[ ] name, version, description properly set
[ ] Apply least privilege principle to permissions
    [ ] Prefer activeTab (safer than tabs)
    [ ] Do not use <all_urls>
    [ ] Remove unused permissions
[ ] host_permissions limited to required domains
[ ] content_security_policy specified
    [ ] Only allow script-src 'self'
    [ ] object-src 'none' or 'self'
    [ ] No unsafe-eval
    [ ] No unsafe-inline
    [ ] No external CDN
[ ] externally_connectable explicit allowlist
[ ] Minimize web_accessible_resources
    [ ] Do not expose unnecessary files
    [ ] Restrict matches to specific domains
```

### 3.2 JavaScript Code Security Check

```
Content Script:
[ ] No postMessage handling without origin validation
[ ] No direct innerHTML/outerHTML assignment
[ ] No document.write usage
[ ] Validate data received from page before use
[ ] Handle lastError in chrome.runtime.sendMessage

Background Script:
[ ] Validate all message senders
[ ] Fetch only from allowed URL list
[ ] No eval(), new Function() usage
[ ] No remote code loading
[ ] Store sensitive data encrypted in chrome.storage

Popup / Options Page:
[ ] No direct insertion of user input into innerHTML
[ ] Use textContent when rendering chrome.storage data
[ ] No loading external scripts
[ ] No inline event handlers (onclick="..." format)
[ ] Verify CSP applies to popup as well
```

### 3.3 Automated Code Audit Script

```bash
#!/bin/bash
# extension_audit.sh — Basic extension security audit

EXT_DIR="$1"
if [ -z "$EXT_DIR" ]; then
    echo "Usage: $0 <extension_directory>"
    exit 1
fi

echo "=== Browser Extension Security Audit ==="
echo "Target: $EXT_DIR"
echo ""

# 1. Dangerous permissions check
echo "[1] Dangerous Permission Analysis"
python3 -c "
import json, sys
try:
    m = json.load(open('$EXT_DIR/manifest.json'))
    dangerous = ['<all_urls>', 'webRequestBlocking', 'nativeMessaging', 'debugger', 'management', 'proxy', 'cookies', 'history']
    perms = m.get('permissions', []) + m.get('host_permissions', [])
    found = [p for p in perms if p in dangerous or p.startswith('https://*/*')]
    if found:
        print('  [WARNING] Dangerous permissions:', found)
    else:
        print('  [OK] No dangerous permissions found')
except Exception as e:
    print('  [ERROR]', e)
"

# 2. CSP inspection
echo ""
echo "[2] CSP Analysis"
python3 -c "
import json
m = json.load(open('$EXT_DIR/manifest.json'))
csp = m.get('content_security_policy', {})
if isinstance(csp, dict):
    csp = csp.get('extension_pages', '')
if not csp:
    print('  [WARNING] CSP not set')
elif 'unsafe-eval' in csp:
    print('  [WARNING] Contains unsafe-eval')
elif 'unsafe-inline' in csp:
    print('  [WARNING] Contains unsafe-inline')
else:
    print('  [OK] CSP configured:', csp[:60])
"

# 3. Code pattern check
echo ""
echo "[3] Dangerous Code Patterns"

patterns=(
    "eval("
    "innerHTML ="
    "document.write"
    "new Function("
    "atob("
    "_0x[0-9a-f]"
)

for pattern in "${patterns[@]}"; do
    count=$(grep -rn "$pattern" "$EXT_DIR" --include="*.js" 2>/dev/null | wc -l)
    if [ "$count" -gt 0 ]; then
        echo "  [WARNING] '$pattern' found $count times:"
        grep -rn "$pattern" "$EXT_DIR" --include="*.js" 2>/dev/null | head -3 | sed 's/^/    /'
    fi
done

# 4. External URL list
echo ""
echo "[4] External URL List"
grep -rEoh "https?://[a-zA-Z0-9._/-]+" "$EXT_DIR" --include="*.js" 2>/dev/null | \
    grep -v "chrome-extension://" | sort -u | head -20

echo ""
echo "=== Audit Complete ==="
```

---

## 4. Principle of Least Privilege

### 4.1 Permission Downgrade Patterns

```javascript
// Bad: requesting tabs permission for all tabs
// manifest.json: "permissions": ["tabs"]

// Good: use only activeTab — access only on user click
// manifest.json: "permissions": ["activeTab"]

// activeTab usage pattern
chrome.action.onClicked.addListener(async (tab) => {
  // activeTab permission allows current tab URL access (after user click)
  console.log('Current tab URL:', tab.url);
  
  // Execute code with scripting.executeScript
  await chrome.scripting.executeScript({
    target: { tabId: tab.id },
    func: () => {
      return document.title;
    }
  });
});
```

### 4.2 Optional Permissions

```json
// manifest.json
{
  "permissions": ["storage"],
  "optional_permissions": ["history", "bookmarks", "cookies"],
  "optional_host_permissions": ["https://*/*"]
}
```

```javascript
// Request permissions only when needed
async function requestHistoryAccess() {
  const granted = await chrome.permissions.request({
    permissions: ['history'],
  });
  
  if (granted) {
    console.log('[+] history permission granted');
    return true;
  } else {
    console.log('[-] User denied permission');
    return false;
  }
}

// Check permissions
async function checkPermissions() {
  const hasHistory = await chrome.permissions.contains({ permissions: ['history'] });
  console.log('history permission:', hasHistory);
  return { history: hasHistory };
}

// Revoke unneeded permissions
async function revokeUnneededPermissions() {
  await chrome.permissions.remove({ permissions: ['history', 'bookmarks'] });
  console.log('[+] Unnecessary permissions revoked');
}
```

---

## 5. Enterprise Extension Management (Chrome Enterprise Policy)

### 5.1 Policy File Configuration

```json
// /etc/opt/chrome/policies/managed/extensions.json (Linux)
// HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome (Windows)

{
  // Allow only specific extensions
  "ExtensionAllowlist": [
    "cjpalhdlnbpafiamejdnhcphjbkeiagm",  // uBlock Origin
    "mnjggcdmjocbbbhaepdhchncahnbgone"   // Approved security extension
  ],
  
  // Block specific extensions
  "ExtensionBlocklist": [
    "*",  // Block all extensions (those not in AllowList)
    "aapocclcgogkmnckokdopfmhonfmgoek"  // Block specific ID
  ],
  
  // Force-install extensions
  "ExtensionInstallForcelist": [
    "cjpalhdlnbpafiamejdnhcphjbkeiagm;https://clients2.google.com/service/update2/crx"
  ],
  
  // Block dangerous permissions
  "ExtensionSettings": {
    "*": {
      "blocked_permissions": [
        "history",
        "nativeMessaging", 
        "debugger"
      ]
    }
  },
  
  // Restrict extension installation sources
  "ExtensionInstallSources": [
    "https://clients2.google.com/service/update2/crx",
    "https://internal-ext-server.company.example.com/*"
  ]
}
```

### 5.2 Policy Deployment (Linux)

```bash
# Create policy directory
sudo mkdir -p /etc/opt/chrome/policies/managed/

# Write policy file
sudo tee /etc/opt/chrome/policies/managed/security_policy.json << 'EOF'
{
  "ExtensionBlocklist": ["*"],
  "ExtensionAllowlist": [
    "cjpalhdlnbpafiamejdnhcphjbkeiagm"
  ],
  "BrowserSignin": 1,
  "RestrictSigninToPattern": ".*@company.example.com"
}
EOF

# Set permissions
sudo chmod 644 /etc/opt/chrome/policies/managed/security_policy.json

# Verify policy (in Chrome)
# Visit chrome://policy to confirm policy application
```

### 5.3 Deployment via Windows GPO

```powershell
# PowerShell — Set Chrome extension policy
$chromePolicyPath = "HKLM:\SOFTWARE\Policies\Google\Chrome"
$extensionPath = "$chromePolicyPath\ExtensionInstallForcelist"

# Create registry path
New-Item -Path $extensionPath -Force | Out-Null

# Add force-install extension
$extensionId = "cjpalhdlnbpafiamejdnhcphjbkeiagm"
$updateUrl = "https://clients2.google.com/service/update2/crx"
Set-ItemProperty -Path $extensionPath -Name "1" -Value "$extensionId;$updateUrl"

# Set blocklist
$blockPath = "$chromePolicyPath\ExtensionBlocklist"
New-Item -Path $blockPath -Force | Out-Null
Set-ItemProperty -Path $blockPath -Name "1" -Value "*"

Write-Host "[+] Policy configuration complete"
```

---

## 6. Extension Update Integrity Verification

See the Korean section above for the full CRX verification tool — code blocks are preserved as-is.

---

## 7. Organization-wide Extension Risk Assessment

See the Korean section above for the full risk assessment tool — code blocks are preserved as-is.

---

## 8. Secure Extension Architecture Design Patterns

### 8.1 Least Privilege Architecture

```
[Least Privilege Extension Design]

Permission selection by use case:

Case: Analyze current page
  No: "tabs" permission + host_permissions: ["<all_urls>"]
  Yes: Only "activeTab" permission (access only current tab on user click)

Case: Communicate with specific site
  No: host_permissions: ["<all_urls>"]
  Yes: host_permissions: ["https://api.myservice.example.com/*"]

Case: HTTP request filtering
  No: "webRequestBlocking" (V2)
  Yes: "declarativeNetRequest" + rules.json (V3)

Case: Data synchronization
  No: chrome.storage.sync + plaintext storage
  Yes: chrome.storage.local + AES-GCM encryption
```

### 8.2 Encrypted Storage Pattern

See the Korean section above for the full SecureStorage implementation — code blocks are preserved as-is.

### 8.3 Secure Content Script Communication Pattern

See the Korean section above for the full SecureMessenger implementation — code blocks are preserved as-is.

---

## 9. Extension Security Checklist Summary

```
Development Phase:
✓ Use Manifest V3
✓ Least privilege principle (prefer activeTab)
✓ Strict CSP (no unsafe-eval/unsafe-inline)
✓ All external communication over HTTPS
✓ Validate message senders
✓ Handle user input with textContent
✓ Encrypt sensitive data before storage
✓ Apply SRI (Subresource Integrity)

Code Review:
✓ No eval(), Function(), setTimeout(string)
✓ No direct innerHTML assignment
✓ Validate postMessage origin
✓ No chrome.storage.get(null)
✓ No hardcoded secrets

Deployment and Operations:
✓ Code signing (keep CRX signing key secure)
✓ Review changes before updates
✓ Chrome Web Store two-factor authentication
✓ Enterprise ExtensionBlocklist policy
✓ Regular audit of installed extensions
```

---

## References

- Chrome Extensions Security: https://developer.chrome.com/docs/extensions/mv3/security/
- OWASP Browser Extension Security: https://owasp.org/
- Chrome Enterprise Policy: https://chromeenterprise.google/policies/
- Web Crypto API: https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API
- Cure53 Extension Security Audits: https://cure53.de/

<!-- detect-validate-51 -->
## Extension Security-Hardening Validation (Configured != Working)

Extension hardening comprises *MV3 migration, secure-dev guidance (OWASP), least permission, enterprise policy, and update integrity*. "We migrated to MV3" differs from "remote code is actually blocked and permissions are minimal" -- validate each control on owned extensions.

### Validation item -> Question -> Measured signal -> Pitfall

| Validation item | Question | Measured signal | Pitfall |
|---|---|---|---|
| MV3 code ban | No remote/eval? | 0 eval/remote src | MV2 leftovers |
| Least permission | Only what's needed? | Minimal host, optional | <all_urls> remains |
| Update integrity | Signature verified? | Tampered update rejected | Unsigned accepted |
| Enterprise policy | Allowlist enforced? | force_install only | Free install allowed |

### Defense validation (verify directly)

```bash
# 1) Whether the owned extension respects the MV3 code ban — leftover eval/remote scripts signal weak hardening
jq -r '.manifest_version' manifest.json 2>/dev/null; grep -rInE '\beval\(|\.src\s*=\s*["'"'"']https?://|unsafe-eval' *.js manifest.json 2>/dev/null | head
# 2) Least-permission check — broad patterns remaining in host_permissions signal over-privilege
jq -r '.host_permissions[]?, .permissions[]?' manifest.json 2>/dev/null | grep -iE '<all_urls>|\*://\*' | head
```

> Extension hardening is *whether controls are enforced* -- "it is MV3" differs from "there is no eval/remote code, host permissions are minimal, and updates are signature-verified". Validate each control on owned extensions directly ([[60_Browser_Security]], [[35_Supply_Chain_Attacks]], [[18_DevSecOps]]).
