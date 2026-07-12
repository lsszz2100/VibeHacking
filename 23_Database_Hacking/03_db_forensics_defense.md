> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# DB 포렌식 및 방어 — 침해 탐지와 감사

## 0. 초보자를 위한 개념 이해

### DB 포렌식이란?

**데이터베이스 포렌식(DB Forensics)**은 데이터베이스가 해킹되거나 데이터가 유출됐을 때, **"무슨 일이 있었는지"를 추적하고 증거를 수집하는 작업**입니다.

**비유:** 편의점 절도 사건에서 CCTV 영상을 분석하는 것처럼, DB 로그와 감사 기록을 분석해 침해 사실을 증명합니다.

### DB 포렌식이 필요한 상황들

```
상황 1: 고객 데이터 유출 의심
  - 수백만 명의 개인정보가 다크웹에 올라옴
  - "우리 DB에서 가져간 게 맞나요?"
  - → binlog, 감사 로그 분석으로 확인

상황 2: DB 계정 탈취
  - 알 수 없는 IP에서 DBA 계정 로그인
  - 새벽 3시에 대량 SELECT 쿼리 실행
  - → 로그인 기록, 쿼리 로그 분석

상황 3: 내부자 위협
  - 퇴직 직원이 고객 데이터를 빼낸 것 같음
  - "누가, 언제, 얼마나 가져갔나?"
  - → 감사 로그 + 네트워크 트래픽 분석

상황 4: 랜섬웨어 공격
  - DB 데이터가 암호화됨
  - 복구를 위해 어떤 테이블이 얼마나 손상됐는지 파악
  - → binlog, redo log로 복구 가능한 시점 확인
```

### DB 포렌식 vs 일반 포렌식

| 항목 | 일반 파일시스템 포렌식 | DB 포렌식 |
|------|----------------------|-----------|
| 증거 위치 | 파일 삭제 흔적, 임시 파일 | 감사 로그, binlog, redo log |
| 주요 도구 | Autopsy, FTK, dd | mysqlbinlog, LogMiner, pgaudit |
| 복구 가능성 | 클러스터 미사용 영역 | 언두 로그, binlog 재적용 |
| 쿼리 추적 | 불가 | 감사 로그 활성화 시 가능 |
| 법적 증거력 | 높음 (불변성 중요) | 감사 로그 무결성 검증 필요 |

---

## 1. DB 포렌식 개요

### 증거 수집 우선순위

```
1순위 (휘발성 높음, 즉시 수집):
  - 현재 활성 연결/세션 목록
  - 실행 중인 쿼리 (processlist)
  - 메모리에 있는 버퍼/캐시

2순위 (지속성 있지만 롤오버 가능):
  - 트랜잭션 로그 (MySQL binlog, Oracle redo log)
  - 에러 로그
  - 슬로우 쿼리 로그

3순위 (장기 보존):
  - DB 감사 로그 (audit trail)
  - 네트워크 패킷 캡처
  - OS 레벨 로그 (auth.log, syslog)
  - DB 스냅샷/백업

수집 대상:
  1. DB 감사 로그 (audit trail) — 누가 무엇을 했는지
  2. 트랜잭션 로그 / redo log / binlog — 데이터 변경 이력
  3. 에러 로그 — 실패한 접근 시도, 비정상 동작
  4. 네트워크 캡처 — DB 쿼리 재구성 (암호화 없는 경우)
  5. 메모리 덤프 — 실행 중인 쿼리, 연결 목록

핵심 질문:
  - 언제 침해가 발생했나? (타임라인 재구성)
  - 어떤 계정이 사용됐나? (정상 계정 탈취? 새 계정 생성?)
  - 어떤 데이터가 접근/유출됐나? (SELECT 쿼리, INTO OUTFILE)
  - DB에서 OS로 이동했나? (xp_cmdshell, INTO OUTFILE, UDF)
  - 얼마나 많은 데이터가 빠져나갔나? (행 수, 데이터 크기)
```

### DB 포렌식 체인 오브 커스터디

**법적 증거로 사용하려면 증거가 변조되지 않았음을 증명해야 합니다:**

```bash
# 1. 로그 파일 해시 계산 (무결성 증명)
sha256sum /var/log/mysql/mysql-bin.000001 > mysql-bin.000001.sha256

# 2. 로그 파일을 읽기 전용으로 마운트 또는 즉시 백업
cp -p /var/log/mysql/audit.log /evidence/$(date +%Y%m%d_%H%M%S)_audit.log
sha256sum /evidence/*_audit.log >> /evidence/checksums.txt

# 3. 증거 수집 타임스탬프 기록
date -u +"%Y-%m-%dT%H:%M:%SZ" > /evidence/collection_time.txt
```

---

## 2. Oracle 포렌식

### Oracle DB 기본 구조 (초보자용)

```
Oracle DB 주요 로그:
  Alert Log (경보 로그): DB 시작/종료, 오류, 보안 이벤트
  Audit Trail: 설정된 감사 정책에 따라 사용자 활동 기록
  Redo Log: 모든 데이터 변경 사항 기록 (복구용 + 포렌식용)
  Archived Log: Redo Log의 아카이브 (장기 보존)
  
Oracle 포렌식의 핵심:
  - Unified Auditing (12c+): 중앙화된 감사 뷰 (UNIFIED_AUDIT_TRAIL)
  - LogMiner: Redo Log를 분석해 삭제/수정된 데이터 복구
  - V$ 뷰: DB 내부 상태 실시간 조회 (활성 세션, SQL 등)
```

### 2-1. 감사 로그 분석

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

**Oracle LogMiner란?** Redo Log에 기록된 모든 변경 사항을 SQL 형태로 재구성하는 툴입니다. `sql_undo` 컬럼에는 변경 전 상태를 복구하는 SQL이 자동 생성됩니다. 삭제된 데이터도 이 방법으로 복구할 수 있습니다.

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

**V$ 뷰:** Oracle의 동적 성능 뷰로, DB 내부 상태를 실시간으로 조회합니다. 침해 발생 시 가장 먼저 확인해야 할 뷰들입니다.

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

### MySQL Binary Log란?

**Binary Log(binlog)**는 MySQL에서 데이터를 변경하는 모든 SQL 문(INSERT, UPDATE, DELETE, DDL)을 기록하는 파일입니다. 원래 목적은 복제(Replication)와 복구지만, 포렌식에서도 필수 증거입니다.

```
binlog 활성화 확인:
mysql> SHOW VARIABLES LIKE 'log_bin';
+---------------+-------+
| Variable_name | Value |
+---------------+-------+
| log_bin       | ON    |  ← 활성화된 경우에만 포렌식 가능
+---------------+-------+

binlog 파일 위치:
/var/lib/mysql/mysql-bin.000001
/var/lib/mysql/mysql-bin.000002  ← 파일 크기 한계 도달 시 새 파일
...

binlog 포맷 종류:
- STATEMENT: SQL 문 그대로 기록 (공간 효율, 분석 쉬움)
- ROW: 변경된 행 데이터 기록 (정확한 데이터 복구 가능)
- MIXED: 상황에 따라 둘 중 하나 선택
```

### 3-1. Binary Log 분석 (변경 이력 추적)

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

**일반 쿼리 로그(General Query Log):** MySQL에 실행된 **모든** SQL 쿼리를 기록합니다. 성능에 영향을 주므로 평상시에는 끄고, 침해 의심 시 일시적으로 켭니다.

> ⚠️ 주의: general_log를 항상 켜두면 성능 저하 및 디스크 소진 위험이 있습니다.

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

**InnoDB 언두 로그란?** 트랜잭션이 롤백될 때 데이터를 원상 복구하기 위한 로그입니다. 커밋된 후에도 일정 기간 보존되어 포렌식에 활용할 수 있습니다.

> 💡 **언제 사용하나:** `DELETE FROM users WHERE id = 1`이 실행됐는데 binlog가 없을 때, 언두 로그에서 복구를 시도할 수 있습니다.

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

### 왜 네트워크 레벨 분석이 필요한가?

DB 감사 로그는 공격자가 삭제할 수 있습니다. 반면 네트워크 패킷은 DB 서버 밖에서 수집되므로 공격자가 조작하기 어렵습니다.

**전제 조건:** DB 트래픽이 암호화되지 않아야 합니다 (SSL/TLS 미적용). 암호화된 경우에는 SSLKEYLOGFILE 또는 인증서 개인키로 복호화가 필요합니다.

**MySQL 패킷 구조:**
```
TCP 페이로드 구조:
  [0-3] 패킷 길이 (3바이트 리틀엔디안 + 1바이트 시퀀스)
  [4]   커맨드 바이트 (0x03 = COM_QUERY = SQL 실행)
  [5+]  SQL 문 본문

예: 패킷 페이로드 hex 덤프
00 00 00 03 53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 75 73 65 72 73
              ^  ^-- "SELECT * FROM users" (ASCII)
              |
              0x03 = COM_QUERY
```

```python
#!/usr/bin/env python3
"""MySQL/Oracle 네트워크 트래픽 분석 — DB 쿼리 재구성 및 공격 탐지.

pcap 파일에서 암호화되지 않은 DB 쿼리를 추출하고 공격 패턴을 탐지합니다.

요구사항:
  pip install scapy
"""

from scapy.all import rdpcap, TCP
import re
import argparse

MYSQL_PORT = 3306
ORACLE_PORT = 1521


def extract_db_queries(pcap_file: str, port: int = MYSQL_PORT) -> list[str]:
    """pcap 파일에서 DB 쿼리 추출.
    
    MySQL COM_QUERY 패킷의 구조를 이용해 SQL 문을 재구성합니다.
    """
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

### 감사(Auditing) vs 로깅의 차이

```
일반 로그:
  - 에러, 슬로우 쿼리 등을 기록
  - 보안 감사 목적으로 설계되지 않음
  - 무결성 보장 없음

감사(Auditing):
  - 보안 이벤트를 전용으로 기록
  - 누가, 언제, 무엇을 했는지 추적
  - 법적 증거 요건을 고려한 설계
  - 일반적으로 별도 저장소에 보관
```

**감사 설정의 원칙:**
1. **최소 필요 항목**: 모든 쿼리를 감사하면 성능 저하. 고위험 작업만 선택
2. **감사 로그 보호**: DB 내부에만 저장하면 DBA가 삭제 가능 → 외부 SIEM으로 전송
3. **보존 기간**: 법규에 따라 최소 1~3년 이상 보존 필요

### 5-1. Oracle 감사 활성화

**Oracle Unified Auditing (12c+)이란?** 감사 설정을 정책으로 관리하는 통합 감사 시스템입니다.

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

**MySQL 감사 플러그인 옵션:**
- **MariaDB Audit Plugin**: 무료, MariaDB/MySQL 모두 지원
- **MySQL Enterprise Audit**: MySQL Enterprise Edition 전용 (유료)
- **Percona Audit Log**: Percona Server 전용 (무료)

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

### 실시간 모니터링이 중요한 이유

수동으로 로그를 확인하면 공격 발생 후 수일이 지나서야 발견할 수 있습니다. 자동화된 모니터링으로 실시간 탐지가 가능합니다.

**탐지해야 할 의심 패턴:**
| 패턴 | 의미 | 공격 유형 |
|------|------|-----------|
| `INTO OUTFILE` | 파일로 데이터 저장 | 데이터 유출, 웹쉘 업로드 |
| `LOAD_FILE` | 파일 내용 읽기 | 민감 파일 탈취 |
| `sys_exec`, `sys_eval` | UDF로 OS 명령 실행 | 권한 상승, RCE |
| `DROP TABLE` | 테이블 삭제 | 랜섬웨어, 데이터 파괴 |
| `xp_cmdshell` | MSSQL OS 명령 실행 | MSSQL RCE |
| `GRANT ALL` | 모든 권한 부여 | 백도어 계정 생성 |
| `CREATE USER` | 새 계정 생성 | 지속성 확보 |
| `INFORMATION_SCHEMA` | 스키마 정보 수집 | SQL 인젝션 정찰 단계 |

```python
#!/usr/bin/env python3
"""MySQL 실시간 감사 모니터.

general_log를 주기적으로 조회해 의심 쿼리를 탐지하고 이메일로 알림을 보냅니다.

전제 조건:
  - MySQL general_log가 활성화되어 있어야 함
  - pip install pymysql

보안 주의:
  - 비밀번호는 명령행 인수 대신 환경 변수나 설정 파일에서 읽어야 함
  - 운영 환경에서는 .env 파일 또는 AWS Secrets Manager 사용 권장
"""

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

---

<!-- detect-validate-23 -->
## DB 감사·포렌식 역량 검증

이 문서는 포렌식·방어를 다루므로, 여기서는 *무엇을 감사하는가*를 넘어 **감사가 실제 공격을 포착하는가**와 **침해 시 추적 가능한 증거가 남는가**를 검증하는 데 집중한다. "감사 켰다 ≠ 공격이 보인다".

### 검증 항목 → 질문 → 측정 신호 → 함정

| 검증 항목 | 질문 | 측정 신호 | 함정 |
|---|---|---|---|
| 감사 커버리지 | 핵심 행위가 기록되나? | 감사 정책 범위 | 읽기/메타 미감사 |
| 로그 무결성 | 변조 방지되나? | append-only/원격 전송 | DBA 가 로그 삭제 가능 |
| 추적성 | 행위자 식별되나? | 사용자/세션 귀속 | 공유 계정으로 익명화 |
| 보존 | 충분히 보관되나? | 보존 기간 | 순환 삭제로 증거 소실 |

### 검증 (직접 확인)

```bash
# 감사가 실제 적용·발화하는지 검증(소유 DB) — 감사 플러그인/정책 확인
mysql -e "SELECT @@global.audit_log_policy;" 2>/dev/null || echo 'audit plugin NOT installed'
mysql -e "SHOW VARIABLES LIKE 'log_output';"   # TABLE/FILE 로 감사 출력 경로 확인
# 검증: 알려진 공격성 쿼리(information_schema 대량조회)를 소유 DB 에 실행 후
#       감사 로그에 해당 쿼리가 사용자 귀속으로 남는지 직접 확인
```

> 검증은 **소유한 DB·통제 환경**에서만. 감사 설정 존재가 포착을 보장하지 않는다 — 공격 쿼리를 재생해 감사 로그에 행위자와 함께 남고, 로그가 변조 방지되는지 확인한다([[13_SOC_Blue_Team]], [[44_Incident_Response_DFIR]]).

**최신 기법·통제 (2025–2026):**
- DB 포렌식(트랜잭션로그·감사추적)으로 침해 재구성 — 검증: 이상 접근이 로그로 재현되는가([[44_Incident_Response_DFIR]])
- 로그 무결성·보존 — 강제되는지 확인

---

<a name="english"></a>

# DB Forensics and Defense — Breach Detection and Auditing

## 0. Beginner Concepts

### What is DB Forensics?

**Database Forensics** is the process of investigating what happened when a database was compromised or data was leaked, collecting and analyzing evidence systematically.

**Analogy:** Like reviewing CCTV footage after a shoplifting incident, you analyze DB logs and audit records to prove a breach occurred.

### Common DB Forensics Scenarios

```
Scenario 1: Customer data leaked to dark web
  - Millions of personal records appeared online
  - "Did it come from our DB?"
  - → Analyze binlog, audit logs to verify

Scenario 2: Unknown IP logged into DBA account
  - Mass SELECT queries at 3 AM
  - → Analyze login history, query logs

Scenario 3: Insider threat
  - Departing employee may have exfiltrated customer data
  - "Who took what, when, and how much?"
  - → Audit logs + network traffic analysis

Scenario 4: Ransomware attack
  - DB data was encrypted
  - Need to assess damage before recovery
  - → binlog/redo log to find last clean recovery point
```

### Evidence Collection Priority

```
Priority 1 (highly volatile — collect immediately):
  - Active connection/session list
  - Running queries (processlist)
  - In-memory buffer/cache state

Priority 2 (persists but can be overwritten):
  - Transaction logs (MySQL binlog, Oracle redo log)
  - Error logs
  - Slow query log

Priority 3 (long-term preservation):
  - DB audit logs
  - Network packet captures
  - OS-level logs (auth.log, syslog)
  - DB snapshots/backups
```

## 1. DB Forensics Overview

```
Database Forensics Scope:

Evidence Types:
  - Query logs (who executed what, when)
  - Audit logs (login/logout, privilege changes)
  - Error logs (failed queries, connection errors)
  - Binary logs (MySQL: data change records)
  - Transaction logs (PostgreSQL WAL: write-ahead log)

Forensic Goals:
  - Identify attacker activity timeline
  - Determine data breach scope (which tables, how many rows)
  - Find backdoor accounts or privilege escalations
  - Verify data integrity (were records tampered?)
  - Determine if attacker moved from DB to OS
  - Quantify exfiltrated data volume
```

---

## 2. MySQL Forensics

```sql
-- Check current users and permissions
SELECT user, host, authentication_string FROM mysql.user;
SELECT * FROM information_schema.USER_PRIVILEGES;

-- Recent login history
SELECT user, host, time, command FROM information_schema.PROCESSLIST;

-- Slow query log
SHOW VARIABLES LIKE 'slow_query_log%';
SHOW VARIABLES LIKE 'long_query_time';

-- Enable general log (all queries)
SET GLOBAL general_log = 'ON';
SET GLOBAL general_log_file = '/var/log/mysql/general.log';

-- Check for suspicious accounts
SELECT user, host FROM mysql.user 
WHERE user NOT IN ('root', 'mysql', 'debian-sys-maint')
  AND host = '%';

-- Find triggers (possible backdoors)
SELECT trigger_name, event_manipulation, event_object_table,
       action_statement
FROM information_schema.TRIGGERS;
```

---

## 3. PostgreSQL Forensics

```sql
-- Check pg_audit log
-- Configure in postgresql.conf:
-- shared_preload_libraries = 'pgaudit'
-- pgaudit.log = 'all'

-- Active connections
SELECT pid, usename, application_name, client_addr, 
       query_start, state, query
FROM pg_stat_activity
WHERE state != 'idle';

-- User permission check
SELECT grantee, table_name, privilege_type
FROM information_schema.role_table_grants
WHERE grantee NOT IN ('PUBLIC', 'postgres');

-- Find suspicious functions
SELECT routine_name, routine_definition
FROM information_schema.routines
WHERE routine_type = 'FUNCTION'
  AND routine_definition ILIKE '%copy%'
  OR routine_definition ILIKE '%pg_read_file%';
```

---

## 4. Database Hardening Checklist

```sql
-- MySQL Hardening

-- 1. Remove anonymous users
DELETE FROM mysql.user WHERE user = '';
FLUSH PRIVILEGES;

-- 2. Remove test database
DROP DATABASE IF EXISTS test;

-- 3. Restrict root to localhost only
UPDATE mysql.user SET host = 'localhost' WHERE user = 'root';
FLUSH PRIVILEGES;

-- 4. Enable binary logging (for point-in-time recovery)
-- In my.cnf:
-- log_bin = /var/log/mysql/mysql-bin.log
-- binlog_format = ROW
-- expire_logs_days = 7

-- 5. Enable audit plugin
INSTALL PLUGIN audit_log SONAME 'audit_log.so';
SET GLOBAL audit_log_policy = ALL;
```

---

## 5. Real-time Monitoring

```python
#!/usr/bin/env python3
"""Real-time database activity monitoring"""
import MySQLdb
import time
import smtplib
from email.mime.text import MIMEText

def monitor(host: str, user: str, password: str,
            smtp_server: str = None, alert_to: str = None,
            interval: int = 60) -> None:
    """Monitor database for suspicious activity"""
    
    conn = MySQLdb.connect(host=host, user=user, passwd=password)
    cursor = conn.cursor()
    
    known_users = set()
    
    while True:
        # Check for new connections
        cursor.execute("""
            SELECT user, host, db, command, info
            FROM information_schema.PROCESSLIST
            WHERE command != 'Sleep'
        """)
        
        for row in cursor.fetchall():
            user_key = f"{row[0]}@{row[1]}"
            query = row[4] or ""
            
            # Detect suspicious patterns
            suspicious_patterns = [
                "information_schema",
                "mysql.user", 
                "INTO OUTFILE",
                "LOAD_FILE",
                "xp_cmdshell",
                "UNION SELECT",
            ]
            
            for pattern in suspicious_patterns:
                if pattern.lower() in query.lower():
                    alert = f"SUSPICIOUS: {user_key} | {pattern} | {query[:100]}"
                    print(f"[!] {alert}")
                    
                    # Send email alert
                    if smtp_server and alert_to:
                        send_alert(smtp_server, alert_to, alert)
        
        time.sleep(interval)

def send_alert(smtp_server: str, to: str, message: str) -> None:
    msg = MIMEText(message)
    msg['Subject'] = '[DB SECURITY ALERT]'
    msg['From'] = 'dbmonitor@company.com'
    msg['To'] = to
    
    with smtplib.SMTP(smtp_server) as s:
        s.send_message(msg)
```

<!-- detect-validate-23 -->
## Validating DB Audit and Forensic Capability

Since this document covers forensics/defense, here we go beyond *what to audit* to verify **whether auditing actually captures attacks** and **whether breaches leave traceable evidence**. "Enabled audit != attacks are visible."

### Element -> Question -> Measured signal -> Pitfall

| Element | Question | Measured signal | Pitfall |
|---|---|---|---|
| Audit coverage | Are key actions recorded? | Audit policy scope | Reads/metadata not audited |
| Log integrity | Tamper-protected? | Append-only/remote shipping | DBA can delete logs |
| Traceability | Is the actor identifiable? | User/session attribution | Anonymized via shared accounts |
| Retention | Kept long enough? | Retention period | Evidence lost to rotation |

### Validation (verify directly)

```bash
# Verify auditing is applied and firing (own DB) — check audit plugin/policy
mysql -e "SELECT @@global.audit_log_policy;" 2>/dev/null || echo 'audit plugin NOT installed'
mysql -e "SHOW VARIABLES LIKE 'log_output';"   # confirm audit output path (TABLE/FILE)
# Validate: run a known attack query (bulk information_schema read) on your own DB,
#           then confirm it lands in the audit log attributed to the user
```

> Validate only on **owned DBs / controlled environments**. Audit configuration does not guarantee capture — replay an attack query to confirm it lands in the audit log with actor attribution and that logs are tamper-protected ([[13_SOC_Blue_Team]], [[44_Incident_Response_DFIR]]).
