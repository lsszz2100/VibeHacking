# DB 포렌식 및 방어 — 침해 탐지와 감사

## 1. DB 포렌식 개요

```
수집 대상:
  1. DB 감사 로그 (audit trail)
  2. 트랜잭션 로그 / redo log / binlog
  3. 에러 로그
  4. 네트워크 캡처 (DB 쿼리 재구성)
  5. 메모리 덤프 (실행 중인 쿼리, 연결 목록)

핵심 질문:
  - 언제 침해가 발생했나?
  - 어떤 계정이 사용됐나?
  - 어떤 데이터가 접근/유출됐나?
  - DB에서 OS로 이동했나?
```

---

## 2. Oracle 포렌식

### 2-1. 감사 로그 분석

SQL 쿼리문입니다. SQL 인젝션 공격은 사용자 입력이 쿼리에 직접 포함될 때 발생하며 데이터베이스 전체를 침해할 수 있습니다.

```sql
-- Oracle Unified Auditing (12c+) 감사 이벤트 조회
SELECT event_timestamp, db_username, action_name,
       object_name, sql_text, unified_audit_policies
FROM unified_audit_trail
WHERE event_timestamp > SYSDATE - 7
ORDER BY event_timestamp DESC;

-- 실패한 로그인 시도 (브루트포스 탐지)
SELECT event_timestamp, db_username, userhost,
       return_code
FROM unified_audit_trail
WHERE action_name = 'LOGON'
  AND return_code != 0
ORDER BY event_timestamp DESC;

-- 특정 테이블에 대한 DML 감사
SELECT event_timestamp, db_username, sql_text
FROM unified_audit_trail
WHERE object_name = 'USERS'
  AND action_name IN ('INSERT','UPDATE','DELETE')
ORDER BY event_timestamp DESC;

-- DDL(스키마 변경) 이력
SELECT event_timestamp, db_username, action_name, object_name, sql_text
FROM unified_audit_trail
WHERE action_name IN ('CREATE TABLE','DROP TABLE','ALTER USER',
                      'CREATE PROCEDURE','GRANT')
ORDER BY event_timestamp DESC;
```

### 2-2. Redo Log로 삭제/변경 데이터 복구

SQL 쿼리문입니다. SQL 인젝션 공격은 사용자 입력이 쿼리에 직접 포함될 때 발생하며 데이터베이스 전체를 침해할 수 있습니다.

```sql
-- LogMiner로 Redo Log 분석
-- 1. LogMiner 초기화
EXECUTE DBMS_LOGMNR.ADD_LOGFILE(
  LOGFILENAME => '/u01/app/oracle/oradata/orcl/redo01.log',
  OPTIONS     => DBMS_LOGMNR.NEW
);

-- 2. 분석 시작
EXECUTE DBMS_LOGMNR.START_LOGMNR(
  STARTTIME => TO_DATE('2026-04-01 00:00:00','YYYY-MM-DD HH24:MI:SS'),
  ENDTIME   => TO_DATE('2026-04-20 23:59:59','YYYY-MM-DD HH24:MI:SS'),
  OPTIONS   => DBMS_LOGMNR.DICT_FROM_ONLINE_CATALOG
);

-- 3. 결과 조회
SELECT timestamp, username, sql_redo, sql_undo
FROM v$logmnr_contents
WHERE seg_name = 'USERS'
  AND operation IN ('INSERT','UPDATE','DELETE')
ORDER BY timestamp;

-- 4. LogMiner 종료
EXECUTE DBMS_LOGMNR.END_LOGMNR;
```

### 2-3. 현재 세션 및 이상 연결 탐지

SQL 쿼리문입니다. SQL 인젝션 공격은 사용자 입력이 쿼리에 직접 포함될 때 발생하며 데이터베이스 전체를 침해할 수 있습니다.

```sql
-- 현재 활성 세션
SELECT s.sid, s.serial#, s.username, s.osuser,
       s.machine, s.program, s.status,
       s.logon_time, q.sql_text
FROM v$session s
LEFT JOIN v$sql q ON s.sql_id = q.sql_id
WHERE s.type != 'BACKGROUND'
ORDER BY s.logon_time DESC;

-- 장시간 실행 중인 쿼리
SELECT s.sid, s.username, q.sql_text,
       ROUND(q.elapsed_time/1e6, 2) AS elapsed_sec
FROM v$session s JOIN v$sql q ON s.sql_id = q.sql_id
WHERE q.elapsed_time > 30e6   -- 30초 이상
ORDER BY q.elapsed_time DESC;

-- 비정상적으로 많은 SELECT 세션 탐지
SELECT username, COUNT(*) AS cnt
FROM v$session
WHERE type != 'BACKGROUND'
GROUP BY username
HAVING COUNT(*) > 10;
```

---

## 3. MySQL 포렌식

### 3-1. Binary Log 분석 (변경 이력 추적)


데이터베이스 침해 흔적을 분석합니다. 쿼리 이력, 접속 로그, 감사 로그에서 비정상적인 대용량 SELECT, 권한 변경, 시스템 함수 호출 등 공격 패턴을 추적합니다.

```bash
# binlog 목록 확인
mysql -u root -p -e "SHOW BINARY LOGS;"

# mysqlbinlog으로 binlog 분석
mysqlbinlog /var/lib/mysql/mysql-bin.000001 \
  --start-datetime="2026-04-01 00:00:00" \
  --stop-datetime="2026-04-20 23:59:59" \
  | grep -A5 "DELETE\|DROP\|INSERT INTO users"

# 특정 DB만 필터
mysqlbinlog --database=webapp mysql-bin.000001

# binlog를 SQL로 출력 (데이터 복구 용도)
mysqlbinlog --base64-output=DECODE-ROWS \
  -v mysql-bin.000001 > binlog_decoded.sql
```

### 3-2. 일반 쿼리 로그 / 에러 로그 분석

SQL 쿼리문입니다. SQL 인젝션 공격은 사용자 입력이 쿼리에 직접 포함될 때 발생하며 데이터베이스 전체를 침해할 수 있습니다.

```sql
-- 일반 쿼리 로그 위치 확인
SHOW VARIABLES LIKE 'general_log%';
SHOW VARIABLES LIKE 'log_error';

-- 실시간 감사 (Performance Schema)
SELECT event_time, user_host, argument
FROM mysql.general_log
WHERE argument LIKE '%DROP%'
   OR argument LIKE '%INTO OUTFILE%'
   OR argument LIKE '%LOAD_FILE%'
   OR argument LIKE '%sys_exec%'
ORDER BY event_time DESC
LIMIT 100;
```

### 3-3. InnoDB 언두 로그로 데이터 복구

```bash
# undrop-for-innodb 도구 사용
git clone https://github.com/twindb/undrop-for-innodb.git
cd undrop-for-innodb && make

# InnoDB 페이지에서 삭제된 레코드 추출
./stream_parser -f /var/lib/mysql/ibdata1

# 특정 테이블 스키마로 레코드 복구
./c_parser -f pages-ibdata1/FIL_PAGE_INDEX/0000000000000012.page \
  -t "id INT, username VARCHAR(50), password VARCHAR(100)" \
  > recovered_users.tsv
```

---

## 4. 네트워크 레벨 DB 트래픽 분석

```python
from scapy.all import rdpcap, TCP
import re
import argparse

MYSQL_PORT = 3306
ORACLE_PORT = 1521

def extract_db_queries(pcap_file: str, port: int = MYSQL_PORT) -> list[str]:
    packets = rdpcap(pcap_file)
    queries: list[str] = []

    for pkt in packets:
        if not (pkt.haslayer(TCP) and pkt[TCP].dport == port):
            continue
        payload = bytes(pkt[TCP].payload)
        if len(payload) < 5:
            continue

        # MySQL 쿼리 패킷: 4바이트 헤더 + 커맨드 바이트(0x03=COM_QUERY)
        if port == MYSQL_PORT and payload[4:5] == b'\x03':
            try:
                query = payload[5:].decode('utf-8', errors='replace').strip()
                if query:
                    queries.append(query)
            except Exception:
                pass

    return queries

def analyze_suspicious(queries: list[str]) -> None:
    patterns = [
        (r'INTO\s+OUTFILE',       "파일 쓰기 시도"),
        (r'LOAD_FILE',            "파일 읽기 시도"),
        (r'sys_exec|sys_eval',    "UDF 명령 실행"),
        (r'DROP\s+TABLE',         "테이블 삭제"),
        (r'xp_cmdshell',          "MSSQL 명령 실행"),
        (r'UNION\s+SELECT',       "UNION 기반 SQLi"),
        (r'INFORMATION_SCHEMA',   "스키마 정보 수집"),
        (r'--\s*$|#\s*$|/\*.*\*/', "SQL 주석 (SQLi 패턴)"),
    ]

    print(f"\n[*] 총 쿼리: {len(queries)}개")
    for query in queries:
        for pattern, desc in patterns:
            if re.search(pattern, query, re.IGNORECASE):
                print(f"\n[!] {desc}")
                print(f"    {query[:200]}")
                break

def main() -> None:
    parser = argparse.ArgumentParser(description="DB 트래픽 분석")
    parser.add_argument("pcap", help="pcap 파일")
    parser.add_argument("--port", type=int, default=MYSQL_PORT)
    args = parser.parse_args()

    queries = extract_db_queries(args.pcap, args.port)
    analyze_suspicious(queries)

if __name__ == "__main__":
    main()
```

---

## 5. DB 감사 정책 설정

### 5-1. Oracle 감사 활성화

SQL 쿼리문입니다. SQL 인젝션 공격은 사용자 입력이 쿼리에 직접 포함될 때 발생하며 데이터베이스 전체를 침해할 수 있습니다.

```sql
-- Unified Auditing 정책 생성
CREATE AUDIT POLICY sensitive_access
  ACTIONS SELECT ON HR.EMPLOYEES,
          INSERT ON HR.SALARY,
          DELETE ON HR.SALARY,
          EXECUTE ON SYS.DBMS_SCHEDULER
  WHEN 'SYS_CONTEXT(''USERENV'', ''SESSION_USER'') != ''HR'''
  EVALUATE PER SESSION;

AUDIT POLICY sensitive_access;

-- 실패한 로그인 감사
CREATE AUDIT POLICY failed_logins
  ACTIONS LOGON
  WHEN 'ACTION = 100'  -- 100 = LOGON
  EVALUATE PER SESSION;
AUDIT POLICY failed_logins WHENEVER NOT SUCCESSFUL;
```

### 5-2. MySQL 감사 활성화 (MariaDB Audit Plugin)


데이터베이스 침해 흔적을 분석합니다. 쿼리 이력, 접속 로그, 감사 로그에서 비정상적인 대용량 SELECT, 권한 변경, 시스템 함수 호출 등 공격 패턴을 추적합니다.

```bash
# MariaDB Audit Plugin 설치
mysql_plugin -u root -p ENABLE server_audit

# my.cnf 설정
cat >> /etc/mysql/my.cnf << 'EOF'
[mysqld]
plugin-load-add=server_audit=server_audit.so
server_audit_logging=ON
server_audit_events=CONNECT,QUERY,TABLE
server_audit_file_path=/var/log/mysql/audit.log
server_audit_file_rotate_size=100000000
server_audit_excl_users=replicator
EOF
```

---

## 6. 침해 탐지 자동화

```python
import pymysql
import smtplib
import time
import argparse
from email.mime.text import MIMEText
from datetime import datetime, timedelta

SUSPICIOUS_PATTERNS = [
    "INTO OUTFILE", "LOAD_FILE", "sys_exec", "sys_eval",
    "DROP TABLE", "DROP DATABASE", "xp_cmdshell",
    "INFORMATION_SCHEMA", "GRANT ALL", "CREATE USER",
]

def check_general_log(conn: pymysql.Connection, since: datetime) -> list[dict]:
    cur = conn.cursor(pymysql.cursors.DictCursor)
    cur.execute(
        "SELECT event_time, user_host, argument "
        "FROM mysql.general_log "
        "WHERE event_time > %s",
        (since,)
    )
    rows = cur.fetchall()
    cur.close()

    alerts = []
    for row in rows:
        arg = str(row.get("argument", "")).upper()
        for pat in SUSPICIOUS_PATTERNS:
            if pat in arg:
                alerts.append({
                    "time": row["event_time"],
                    "user": row["user_host"],
                    "query": str(row["argument"])[:300],
                    "pattern": pat,
                })
                break
    return alerts

def send_alert(alerts: list[dict], smtp_host: str, to_addr: str) -> None:
    body = "\n".join(
        f"[{a['time']}] {a['user']}\n  패턴: {a['pattern']}\n  쿼리: {a['query']}\n"
        for a in alerts
    )
    msg = MIMEText(body)
    msg["Subject"] = f"[DB Alert] 의심 쿼리 {len(alerts)}건"
    msg["From"] = "db-monitor@example.com"
    msg["To"] = to_addr

    with smtplib.SMTP(smtp_host) as smtp:
        smtp.send_message(msg)

def monitor(host: str, user: str, password: str,
            smtp_host: str, alert_to: str, interval: int = 60) -> None:
    conn = pymysql.connect(host=host, user=user, password=password, db='mysql')
    print(f"[*] DB 모니터링 시작: {host} (간격 {interval}초)")
    last_check = datetime.now() - timedelta(seconds=interval)

    while True:
        alerts = check_general_log(conn, last_check)
        if alerts:
            print(f"[!] {len(alerts)}건 의심 이벤트 감지 — 알림 발송")
            if smtp_host and alert_to:
                send_alert(alerts, smtp_host, alert_to)
            for a in alerts:
                print(f"    [{a['time']}] {a['pattern']} — {a['query'][:80]}")
        last_check = datetime.now()
        time.sleep(interval)

def main() -> None:
    parser = argparse.ArgumentParser(description="MySQL 실시간 감사 모니터")
    parser.add_argument("--host",     required=True)
    parser.add_argument("--user",     required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--smtp",     default="")
    parser.add_argument("--alert-to", default="")
    parser.add_argument("--interval", type=int, default=60)
    args = parser.parse_args()

    monitor(args.host, args.user, args.password,
            args.smtp, args.alert_to, args.interval)

if __name__ == "__main__":
    main()
```
