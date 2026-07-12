> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# DB 방어 및 하드닝

## 0. 초보자를 위한 개념 이해

### 왜 DB 보안이 중요한가?

데이터베이스는 조직의 핵심 자산(개인정보, 금융 데이터, 영업 기밀)을 저장합니다. DB가 침해되면 단순한 시스템 침해와 달리 **데이터 자체가 유출**되므로 복구가 불가능한 피해가 발생합니다.

```
공격 경로 예시:
  웹 애플리케이션 → SQL 인젝션 → DB 접근 → 데이터 탈취
  내부 직원        → 과도한 권한  → 무단 조회 → 내부자 위협
  DBA 계정 탈취    → 루트 권한   → 전체 DB 장악
```

### DB 하드닝의 핵심 원칙

| 원칙 | 설명 | 예시 |
|------|------|------|
| 최소 권한 | 필요한 권한만 부여 | SELECT만 필요한 계정에 INSERT 금지 |
| 입력 검증 | 모든 입력을 신뢰하지 않음 | PreparedStatement 사용 |
| 감사 로깅 | 모든 접근 기록 | 로그인 성공/실패, 중요 쿼리 기록 |
| 암호화 | 저장 데이터 보호 | TDE, 컬럼 암호화 |
| 패치 관리 | 취약점 신속 대응 | 정기 업데이트 스케줄 |

---

## 1. DB 계정 최소 권한 원칙 (GRANT 관리)

### 1-1. MySQL 권한 관리

```sql
-- 현재 사용자 권한 확인
SHOW GRANTS FOR 'appuser'@'localhost';

-- 나쁜 예: 모든 권한 부여
-- GRANT ALL PRIVILEGES ON *.* TO 'appuser'@'%';

-- 좋은 예: 필요한 권한만 부여
-- 읽기 전용 사용자
CREATE USER 'reader'@'192.168.1.%' IDENTIFIED BY 'StrongPass!123';
GRANT SELECT ON myapp.* TO 'reader'@'192.168.1.%';

-- 애플리케이션 전용 사용자 (특정 DB, 특정 권한)
CREATE USER 'appuser'@'10.0.0.1' IDENTIFIED BY 'AppPass!456';
GRANT SELECT, INSERT, UPDATE ON myapp.users TO 'appuser'@'10.0.0.1';
GRANT SELECT, INSERT ON myapp.orders TO 'appuser'@'10.0.0.1';
-- DELETE 권한은 별도 관리자 계정으로만

-- 권한 적용
FLUSH PRIVILEGES;

-- 과도한 권한 회수
REVOKE DELETE ON myapp.* FROM 'appuser'@'10.0.0.1';
REVOKE SUPER ON *.* FROM 'appuser'@'10.0.0.1';
```

### 1-2. Oracle 권한 관리

```sql
-- 역할(Role) 기반 권한 관리
CREATE ROLE app_readonly;
GRANT SELECT ON hr.employees TO app_readonly;
GRANT SELECT ON hr.departments TO app_readonly;

-- 사용자에게 역할 부여
CREATE USER appuser IDENTIFIED BY "SecurePass#789";
GRANT app_readonly TO appuser;
GRANT CONNECT TO appuser;  -- 로그인만 허용

-- 시스템 권한 최소화 (DBA 역할 금지)
-- 나쁜 예: GRANT DBA TO appuser;
-- 좋은 예: 필요한 오브젝트 권한만 개별 부여

-- 현재 권한 확인
SELECT * FROM DBA_SYS_PRIVS WHERE GRANTEE = 'APPUSER';
SELECT * FROM DBA_TAB_PRIVS WHERE GRANTEE = 'APPUSER';
```

### 1-3. 위험한 기본 계정 처리

```sql
-- MySQL 기본 계정 확인
SELECT user, host, authentication_string 
FROM mysql.user 
WHERE user IN ('root', 'anonymous', '');

-- 익명 계정 삭제
DELETE FROM mysql.user WHERE user = '';
FLUSH PRIVILEGES;

-- root 원격 접속 차단
DELETE FROM mysql.user WHERE user = 'root' AND host != 'localhost';
FLUSH PRIVILEGES;

-- 사용하지 않는 테스트 DB 삭제
DROP DATABASE IF EXISTS test;
```

---

## 2. SQL 인젝션 방어: PreparedStatement와 파라미터 바인딩

### 2-1. 취약한 코드 vs 안전한 코드

```python
import mysql.connector
import sqlite3

# 취약한 예 (SQL 인젝션 가능)
def vulnerable_login(username: str, password: str) -> bool:
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # 공격자 입력: username = "admin' --"
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor.execute(query)  # 인젝션 발생!
    return cursor.fetchone() is not None

# 안전한 예 (파라미터 바인딩)
def safe_login(username: str, password: str) -> bool:
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # ? 플레이스홀더 사용 - 입력이 데이터로만 처리됨
    query = "SELECT * FROM users WHERE username=? AND password=?"
    cursor.execute(query, (username, password))
    return cursor.fetchone() is not None

# MySQL용 파라미터 바인딩
def mysql_safe_query(host: str, user: str, password: str, 
                     search_term: str) -> list[dict]:
    conn = mysql.connector.connect(
        host=host, user=user, password=password, database="myapp"
    )
    cursor = conn.cursor(dictionary=True)
    # %s 플레이스홀더 사용
    query = "SELECT id, name, email FROM users WHERE name LIKE %s"
    cursor.execute(query, (f"%{search_term}%",))
    results = cursor.fetchall()
    conn.close()
    return results
```

### 2-2. ORM을 활용한 인젝션 방어

```python
# SQLAlchemy ORM 사용 예
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

engine = create_engine("mysql+mysqlconnector://user:pass@localhost/myapp")

# 취약한 raw SQL (ORM에서도 주의 필요)
def vulnerable_orm_query(user_id: str) -> list:
    with Session(engine) as session:
        # 나쁜 예: f-string으로 SQL 조합
        result = session.execute(text(f"SELECT * FROM users WHERE id = {user_id}"))
        return result.fetchall()

# 안전한 ORM 쿼리
def safe_orm_query(user_id: int) -> list:
    with Session(engine) as session:
        # 좋은 예: bindparam 사용
        result = session.execute(
            text("SELECT * FROM users WHERE id = :uid"),
            {"uid": user_id}
        )
        return result.fetchall()
```

### 2-3. 입력 검증 레이어 추가

```python
import re
from typing import Any

class InputValidator:
    """DB 입력값 검증 클래스"""
    
    # 위험한 SQL 키워드 패턴
    SQL_INJECTION_PATTERNS = [
        r"(\b(UNION|SELECT|INSERT|UPDATE|DELETE|DROP|EXEC|EXECUTE)\b)",
        r"(--|;|\/\*|\*\/|xp_|sp_)",
        r"(\bOR\b|\bAND\b).*[=<>]",
    ]
    
    @classmethod
    def is_safe_string(cls, value: str) -> bool:
        """SQL 인젝션 패턴 탐지"""
        value_upper = value.upper()
        for pattern in cls.SQL_INJECTION_PATTERNS:
            if re.search(pattern, value_upper, re.IGNORECASE):
                return False
        return True
    
    @classmethod
    def sanitize_identifier(cls, identifier: str) -> str:
        """테이블/컬럼명 검증 (화이트리스트 방식)"""
        # 알파벳, 숫자, 언더스코어만 허용
        if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', identifier):
            raise ValueError(f"유효하지 않은 식별자: {identifier}")
        return identifier
    
    @classmethod
    def validate_int(cls, value: Any, min_val: int = 0, 
                     max_val: int = 2**31) -> int:
        """정수형 입력 검증"""
        try:
            int_val = int(value)
            if not (min_val <= int_val <= max_val):
                raise ValueError(f"범위 초과: {int_val}")
            return int_val
        except (TypeError, ValueError) as e:
            raise ValueError(f"정수 변환 실패: {e}") from e
```

---

## 3. DB 감사 로깅 설정

### 3-1. MySQL 감사 로깅

```sql
-- MySQL Enterprise Audit Plugin 활성화
-- my.cnf에 추가:
-- [mysqld]
-- plugin-load-add=audit_log.so
-- audit_log_file=/var/log/mysql/audit.log
-- audit_log_format=JSON
-- audit_log_policy=ALL

-- 일반 쿼리 로그 (개발/테스트 환경)
SET GLOBAL general_log = 'ON';
SET GLOBAL general_log_file = '/var/log/mysql/general.log';

-- 느린 쿼리 로그 (성능 및 비정상 탐지)
SET GLOBAL slow_query_log = 'ON';
SET GLOBAL slow_query_log_file = '/var/log/mysql/slow.log';
SET GLOBAL long_query_time = 2;  -- 2초 이상 소요 쿼리 기록

-- 바이너리 로그 (변경 사항 추적)
-- my.cnf: log_bin=/var/log/mysql/mysql-bin.log
SHOW BINARY LOGS;
SHOW BINLOG EVENTS IN 'mysql-bin.000001' LIMIT 20;
```

### 3-2. Oracle 감사 로깅

```sql
-- Unified Auditing 활성화 (Oracle 12c+)
-- 감사 정책 생성
CREATE AUDIT POLICY sensitive_data_access
    ACTIONS SELECT ON hr.employees,
             SELECT ON finance.accounts,
             DELETE ON hr.employees
    WHEN 'SYS_CONTEXT(''USERENV'',''SESSION_USER'') != ''HR_ADMIN'''
    EVALUATE PER SESSION;

-- 정책 활성화
AUDIT POLICY sensitive_data_access;

-- 로그인 실패 감사
CREATE AUDIT POLICY login_failures
    ACTIONS LOGON
    WHEN 'ACTION = 100';  -- ORA-01017: invalid username/password

-- 감사 로그 조회
SELECT event_timestamp, db_username, action_name, object_name, sql_text
FROM unified_audit_trail
WHERE event_timestamp > SYSDATE - 1
ORDER BY event_timestamp DESC;
```

### 3-3. 감사 로그 분석 자동화

```python
import json
import re
from pathlib import Path
from datetime import datetime
from collections import Counter

def analyze_mysql_audit_log(log_path: str) -> dict[str, Any]:
    """MySQL 감사 로그 분석"""
    failed_logins: Counter = Counter()
    suspicious_queries: list[dict] = []
    
    log_file = Path(log_path)
    if not log_file.exists():
        raise FileNotFoundError(f"로그 파일 없음: {log_path}")
    
    with log_file.open() as f:
        for line in f:
            try:
                entry = json.loads(line.strip())
            except json.JSONDecodeError:
                continue
            
            # 로그인 실패 집계
            if entry.get("event_class") == "connection" and \
               entry.get("status") != 0:
                user = entry.get("user", "unknown")
                host = entry.get("ip", "unknown")
                failed_logins[f"{user}@{host}"] += 1
            
            # 의심스러운 쿼리 탐지
            sql = entry.get("sql_text", "")
            if any(kw in sql.upper() for kw in 
                   ["UNION", "INTO OUTFILE", "LOAD_FILE", "INFORMATION_SCHEMA"]):
                suspicious_queries.append({
                    "timestamp": entry.get("timestamp"),
                    "user": entry.get("user"),
                    "sql": sql[:200]
                })
    
    return {
        "failed_logins": dict(failed_logins.most_common(10)),
        "suspicious_queries": suspicious_queries[:20],
        "analysis_time": datetime.now().isoformat()
    }
```

---

## 4. 암호화: 컬럼 암호화와 TDE

### 4-1. MySQL TDE (Transparent Data Encryption)

```sql
-- InnoDB TDE 설정 (my.cnf)
-- [mysqld]
-- early-plugin-load=keyring_file.so
-- keyring_file_data=/var/lib/mysql-keyring/keyring

-- 암호화 키 생성
ALTER INSTANCE ROTATE INNODB MASTER KEY;

-- 테이블 암호화 적용
CREATE TABLE sensitive_data (
    id INT PRIMARY KEY AUTO_INCREMENT,
    ssn VARCHAR(20),
    credit_card VARCHAR(20)
) ENCRYPTION='Y';

-- 기존 테이블에 암호화 적용
ALTER TABLE users ENCRYPTION='Y';

-- 암호화 상태 확인
SELECT TABLE_SCHEMA, TABLE_NAME, CREATE_OPTIONS
FROM INFORMATION_SCHEMA.TABLES
WHERE CREATE_OPTIONS LIKE '%ENCRYPTION%';
```

### 4-2. 애플리케이션 레벨 컬럼 암호화

```python
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
import sqlite3

class ColumnEncryptor:
    """민감 데이터 컬럼 암호화 클래스"""
    
    def __init__(self, master_key: bytes | None = None):
        if master_key is None:
            master_key = os.urandom(32)
        
        # PBKDF2로 암호화 키 파생
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"db_column_salt_v1",  # 실제 환경에서는 랜덤 솔트 사용
            iterations=100_000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(master_key))
        self.fernet = Fernet(key)
    
    def encrypt(self, plaintext: str) -> str:
        """평문 → 암호화된 문자열"""
        return self.fernet.encrypt(plaintext.encode()).decode()
    
    def decrypt(self, ciphertext: str) -> str:
        """암호화된 문자열 → 평문"""
        return self.fernet.decrypt(ciphertext.encode()).decode()
    
    def store_encrypted(self, conn: sqlite3.Connection, 
                        user_id: int, ssn: str, card_number: str) -> None:
        """민감 데이터 암호화 저장"""
        encrypted_ssn = self.encrypt(ssn)
        encrypted_card = self.encrypt(card_number)
        
        conn.execute(
            "INSERT INTO sensitive_data (user_id, ssn_encrypted, card_encrypted) "
            "VALUES (?, ?, ?)",
            (user_id, encrypted_ssn, encrypted_card)
        )
        conn.commit()
    
    def retrieve_decrypted(self, conn: sqlite3.Connection, 
                           user_id: int) -> dict[str, str] | None:
        """암호화 데이터 조회 및 복호화"""
        cursor = conn.execute(
            "SELECT ssn_encrypted, card_encrypted FROM sensitive_data "
            "WHERE user_id = ?",
            (user_id,)
        )
        row = cursor.fetchone()
        if row is None:
            return None
        return {
            "ssn": self.decrypt(row[0]),
            "card_number": self.decrypt(row[1])
        }
```

---

## 5. Python DB 권한 감사 스크립트

```python
#!/usr/bin/env python3
"""
DB 권한 감사 스크립트 - MySQL/MariaDB 대상
사용법: python3 db_audit.py --host localhost --user audit_user --check-level high
"""

import argparse
import sys
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime

try:
    import mysql.connector
    from mysql.connector import Error as MySQLError
except ImportError:
    print("[오류] mysql-connector-python 설치 필요: pip install mysql-connector-python")
    sys.exit(1)


@dataclass
class AuditFinding:
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    category: str
    description: str
    detail: str
    recommendation: str


@dataclass
class AuditReport:
    host: str
    timestamp: str
    check_level: str
    findings: list[AuditFinding] = field(default_factory=list)
    
    def add_finding(self, severity: str, category: str, 
                    description: str, detail: str, recommendation: str) -> None:
        self.findings.append(AuditFinding(
            severity=severity,
            category=category,
            description=description,
            detail=detail,
            recommendation=recommendation
        ))
    
    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts


class DBAuditor:
    """MySQL DB 권한 및 설정 감사 클래스"""
    
    def __init__(self, host: str, user: str, password: str, 
                 port: int = 3306, check_level: str = "medium"):
        self.host = host
        self.user = user
        self.password = password
        self.port = port
        self.check_level = check_level.lower()
        self.conn: mysql.connector.MySQLConnection | None = None
    
    def connect(self) -> bool:
        try:
            self.conn = mysql.connector.connect(
                host=self.host,
                user=self.user,
                password=self.password,
                port=self.port
            )
            return True
        except MySQLError as e:
            print(f"[연결 실패] {e}")
            return False
    
    def disconnect(self) -> None:
        if self.conn and self.conn.is_connected():
            self.conn.close()
    
    def _execute(self, query: str, params: tuple = ()) -> list[dict]:
        if not self.conn:
            return []
        cursor = self.conn.cursor(dictionary=True)
        cursor.execute(query, params)
        result = cursor.fetchall()
        cursor.close()
        return result
    
    def check_anonymous_accounts(self, report: AuditReport) -> None:
        """익명 계정 확인"""
        rows = self._execute(
            "SELECT user, host FROM mysql.user WHERE user = ''"
        )
        if rows:
            report.add_finding(
                severity="CRITICAL",
                category="계정 관리",
                description="익명(anonymous) 계정 존재",
                detail=f"발견된 익명 계정: {rows}",
                recommendation="DELETE FROM mysql.user WHERE user=''; FLUSH PRIVILEGES;"
            )
    
    def check_root_remote_access(self, report: AuditReport) -> None:
        """root 원격 접속 허용 여부 확인"""
        rows = self._execute(
            "SELECT user, host FROM mysql.user "
            "WHERE user = 'root' AND host NOT IN ('localhost', '127.0.0.1', '::1')"
        )
        if rows:
            report.add_finding(
                severity="CRITICAL",
                category="계정 관리",
                description="root 계정의 원격 접속 허용",
                detail=f"원격 root 접속 가능 호스트: {[r['host'] for r in rows]}",
                recommendation="root 원격 접속 호스트 삭제 후 FLUSH PRIVILEGES"
            )
    
    def check_wildcard_grants(self, report: AuditReport) -> None:
        """와일드카드 권한(*.*)을 가진 일반 계정 확인"""
        rows = self._execute(
            "SELECT GRANTEE, PRIVILEGE_TYPE FROM information_schema.USER_PRIVILEGES "
            "WHERE GRANTEE NOT LIKE '%root%' "
            "AND PRIVILEGE_TYPE IN ('SUPER', 'FILE', 'PROCESS', 'SHUTDOWN')"
        )
        for row in rows:
            report.add_finding(
                severity="HIGH",
                category="권한 관리",
                description=f"위험 권한 보유: {row['GRANTEE']}",
                detail=f"권한: {row['PRIVILEGE_TYPE']}",
                recommendation=f"REVOKE {row['PRIVILEGE_TYPE']} ON *.* FROM {row['GRANTEE']}"
            )
    
    def check_password_policy(self, report: AuditReport) -> None:
        """비밀번호 정책 확인"""
        rows = self._execute(
            "SHOW VARIABLES LIKE 'validate_password%'"
        )
        policy_vars = {r['Variable_name']: r['Value'] for r in rows}
        
        if not policy_vars:
            report.add_finding(
                severity="HIGH",
                category="비밀번호 정책",
                description="비밀번호 검증 플러그인 미설치",
                detail="validate_password 플러그인 없음",
                recommendation="INSTALL PLUGIN validate_password SONAME 'validate_password.so';"
            )
        elif policy_vars.get("validate_password_length", "0") < "12":
            report.add_finding(
                severity="MEDIUM",
                category="비밀번호 정책",
                description="비밀번호 최소 길이 부족",
                detail=f"현재 설정: {policy_vars.get('validate_password_length', 'N/A')}",
                recommendation="SET GLOBAL validate_password_length = 12;"
            )
    
    def check_ssl_configuration(self, report: AuditReport) -> None:
        """SSL/TLS 설정 확인"""
        rows = self._execute("SHOW VARIABLES LIKE 'have_ssl'")
        ssl_status = rows[0]['Value'] if rows else "DISABLED"
        
        if ssl_status != "YES":
            report.add_finding(
                severity="MEDIUM",
                category="암호화",
                description="SSL/TLS 미설정",
                detail=f"have_ssl = {ssl_status}",
                recommendation="my.cnf에 ssl-ca, ssl-cert, ssl-key 설정 추가"
            )
    
    def check_audit_log(self, report: AuditReport) -> None:
        """감사 로그 설정 확인"""
        rows = self._execute("SHOW VARIABLES LIKE 'general_log'")
        if rows and rows[0]['Value'] == 'OFF':
            report.add_finding(
                severity="LOW",
                category="감사 로깅",
                description="일반 쿼리 로그 비활성화",
                detail="general_log = OFF",
                recommendation="프로덕션: audit_log 플러그인 사용, 개발: SET GLOBAL general_log='ON'"
            )
    
    def run(self) -> AuditReport:
        """감사 실행"""
        report = AuditReport(
            host=self.host,
            timestamp=datetime.now().isoformat(),
            check_level=self.check_level
        )
        
        checks_basic = [
            self.check_anonymous_accounts,
            self.check_root_remote_access,
        ]
        checks_medium = checks_basic + [
            self.check_wildcard_grants,
            self.check_password_policy,
        ]
        checks_high = checks_medium + [
            self.check_ssl_configuration,
            self.check_audit_log,
        ]
        
        level_map = {
            "low": checks_basic,
            "medium": checks_medium,
            "high": checks_high
        }
        checks = level_map.get(self.check_level, checks_medium)
        
        for check_fn in checks:
            try:
                check_fn(report)
            except Exception as e:
                print(f"[경고] 점검 실패 ({check_fn.__name__}): {e}")
        
        return report


def print_report(report: AuditReport, output_format: str = "text") -> None:
    """감사 결과 출력"""
    if output_format == "json":
        data = {
            "host": report.host,
            "timestamp": report.timestamp,
            "check_level": report.check_level,
            "summary": report.summary(),
            "findings": [asdict(f) for f in report.findings]
        }
        print(json.dumps(data, ensure_ascii=False, indent=2))
        return
    
    print(f"\n{'='*60}")
    print(f"DB 권한 감사 보고서")
    print(f"대상: {report.host} | 시각: {report.timestamp}")
    print(f"점검 수준: {report.check_level.upper()}")
    print(f"{'='*60}")
    
    summary = report.summary()
    print(f"\n[요약] CRITICAL:{summary['CRITICAL']} HIGH:{summary['HIGH']} "
          f"MEDIUM:{summary['MEDIUM']} LOW:{summary['LOW']}")
    
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    sorted_findings = sorted(report.findings, 
                              key=lambda f: severity_order.get(f.severity, 99))
    
    for i, finding in enumerate(sorted_findings, 1):
        severity_emoji = {"CRITICAL": "[!!]", "HIGH": "[! ]", 
                          "MEDIUM": "[ ~]", "LOW": "[  ]"}
        marker = severity_emoji.get(finding.severity, "[ ]")
        print(f"\n{marker} [{finding.severity}] {finding.description}")
        print(f"   분류: {finding.category}")
        print(f"   상세: {finding.detail}")
        print(f"   조치: {finding.recommendation}")
    
    if not report.findings:
        print("\n[OK] 발견된 취약점 없음")
    
    print(f"\n{'='*60}\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="MySQL/MariaDB 권한 및 설정 감사 도구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
사용 예시:
  python3 db_audit.py --host localhost --user root --check-level high
  python3 db_audit.py --host 192.168.1.10 --user auditor --port 3307 --format json
        """
    )
    parser.add_argument("--host", required=True, help="DB 호스트 주소")
    parser.add_argument("--user", required=True, help="DB 접속 계정")
    parser.add_argument("--password", default="", help="DB 비밀번호 (미입력 시 프롬프트)")
    parser.add_argument("--port", type=int, default=3306, help="DB 포트 (기본: 3306)")
    parser.add_argument(
        "--check-level",
        choices=["low", "medium", "high"],
        default="medium",
        help="점검 수준: low(기본 계정), medium(+권한), high(+암호화/로깅)"
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="출력 형식 (기본: text)"
    )
    
    args = parser.parse_args()
    
    # 비밀번호 안전 입력
    password = args.password
    if not password:
        import getpass
        password = getpass.getpass(f"비밀번호 ({args.user}@{args.host}): ")
    
    auditor = DBAuditor(
        host=args.host,
        user=args.user,
        password=password,
        port=args.port,
        check_level=args.check_level
    )
    
    print(f"[*] {args.host}:{args.port} 연결 중...")
    if not auditor.connect():
        sys.exit(1)
    
    try:
        report = auditor.run()
        print_report(report, output_format=args.format)
        
        # 심각한 취약점 발견 시 비정상 종료 코드
        summary = report.summary()
        if summary["CRITICAL"] > 0:
            sys.exit(2)
        elif summary["HIGH"] > 0:
            sys.exit(1)
    finally:
        auditor.disconnect()


if __name__ == "__main__":
    main()
```

**참고 자료:**
- sqlmap (SQL 인젝션 테스트 도구): https://github.com/sqlmapproject/sqlmap

---

## 5.5 대량 조회(Bulk Exfiltration) 탐지 — 쿼리 감사로그 기반

SQL 인젝션 방어(2절)와 최소 권한(1절)을 다 갖춰도, **정상 인증된 애플리케이션 계정**이 평소와 다르게 테이블 전체를 긁어가는 패턴(예: 내부자 유출, 탈취된 앱 서버로 대량 SELECT)은 별도로 탐지해야 한다. 감사 로그(3절에서 설정)에서 계정별 평소 조회 행 수 기준선을 만들고, 이를 크게 벗어나는 쿼리를 실시간으로 잡아낸다.

```python
#!/usr/bin/env python3
"""DB 감사 로그(PostgreSQL pgaudit 형식 가정)에서 계정별 대량 조회 이상치 탐지."""
import re
import statistics
from collections import defaultdict
from pathlib import Path


def parse_audit_log(path: Path) -> list[dict]:
    """pgaudit 로그 라인에서 사용자·행수·쿼리를 추출 (예: rows=52341)."""
    entries = []
    pattern = re.compile(
        r'user=(?P<user>\S+).*?rows=(?P<rows>\d+).*?statement=(?P<query>SELECT.*)'
    )
    for line in path.read_text(errors="ignore").splitlines():
        m = pattern.search(line)
        if m:
            entries.append({
                "user": m.group("user"),
                "rows": int(m.group("rows")),
                "query": m.group("query")[:120],
            })
    return entries


def detect_outliers(entries: list[dict], z_threshold: float = 3.0) -> None:
    by_user = defaultdict(list)
    for e in entries:
        by_user[e["user"]].append(e["rows"])

    for user, row_counts in by_user.items():
        if len(row_counts) < 5:
            continue
        mean = statistics.mean(row_counts)
        stdev = statistics.pstdev(row_counts) or 1
        for e in entries:
            if e["user"] != user:
                continue
            z = (e["rows"] - mean) / stdev
            if z > z_threshold and e["rows"] > 10_000:
                print(f"[!] {user}: {e['rows']}행 조회 (z={z:.1f}) — {e['query']}")


if __name__ == "__main__":
    entries = parse_audit_log(Path("pgaudit.log"))
    detect_outliers(entries)
```

**탐지/방어**: 절대 임계값(예: "1만 행 이상")만 쓰면 배치 리포팅 같은 정상 대량 조회를 오탐하므로, 반드시 **계정별 과거 기준선 대비 상대적 이상치**(z-score 등)로 판단한다. 애플리케이션 계정이 페이지네이션 없이 `SELECT *`로 전체 테이블을 가져가는 패턴은 특히 우선순위 높은 신호다. 근본 대응으로는 애플리케이션 계층에 결과 행수 상한(`LIMIT` 강제)을 걸고, 이를 우회하는 직접 DB 접속 경로 자체를 차단하는 것이 병행되어야 한다.

---

<!-- detect-validate-23 -->
## DB 하드닝의 적용 검증

이 문서는 하드닝을 다루므로, 여기서는 *무엇을 설정하는가*를 넘어 **하드닝이 실제 런타임에 적용됐는가**와 **회귀하지 않는가**를 검증하는 데 집중한다. "가이드 적용 ≠ 실제 적용"이다.

### 검증 항목 → 질문 → 측정 신호 → 함정

| 검증 항목 | 질문 | 측정 신호 | 함정 |
|---|---|---|---|
| 익명/기본 계정 | 제거됐나? | 빈 user 0행 | 기본계정 잔존 |
| 전송 암호화 | TLS 강제되나? | require_secure_transport=ON | 평문 연결 허용 |
| 최소권한 | 과도권한 없나? | FILE/SUPER 보유 0 | 앱계정 과권한 |
| 감사/백업 | 작동·복구되나? | 감사 발화·복원 테스트 | 미검증 백업 |

### 검증 (직접 확인)

```bash
# 하드닝이 실제 적용됐는지 검증(소유 DB) — 익명계정 제거·TLS 강제·과도권한 점검
mysql -e "SELECT user,host FROM mysql.user WHERE user='';"          # 익명계정 0행이어야
mysql -e "SHOW VARIABLES LIKE 'require_secure_transport';"          # ON 이어야 TLS 강제
mysql -e "SELECT user,host FROM mysql.user WHERE Super_priv='Y';"   # SUPER 보유 최소여야
# 각 항목이 기준을 벗어나면 하드닝 미적용/회귀 → CI/정기 점검으로 재발 방지
```

> 검증은 **소유한 DB·통제 환경**에서만. 하드닝 가이드 적용이 곧 런타임 적용을 의미하지 않는다 — 익명계정·TLS·권한을 직접 조회해 기준 충족을 확인하고, 정기 점검으로 회귀를 막는다([[26_Linux_Hardening]], [[68_Purple_Team]]).

**최신 기법·통제 (2025–2026):**
- 최소권한·암호화(TDE/전송)·감사·마스킹이 표준 — 검증: 통제가 런타임에 강제되는지 재현([[26_Linux_Hardening]])
- 이상 쿼리·대량조회 탐지 — 발화하는지 확인([[40_Threat_Hunting]])

---

<a name="english"></a>

# Database Defense and Hardening

## 0. Concept Overview for Beginners

### Why Does DB Security Matter?

Databases store an organization's core assets — personal data, financial records, and trade secrets. Unlike ordinary system breaches, a compromised database means **the data itself is exfiltrated**, causing irreversible damage.

```
Attack Path Examples:
  Web App → SQL Injection → DB Access → Data Theft
  Insider  → Excessive Privileges → Unauthorized Query → Insider Threat
  DBA Credential Theft → Root Access → Full DB Takeover
```

### Core DB Hardening Principles

| Principle | Description | Example |
|-----------|-------------|---------|
| Least Privilege | Grant only necessary permissions | Block INSERT for SELECT-only accounts |
| Input Validation | Never trust user input | Use PreparedStatements |
| Audit Logging | Record all access | Log logins, critical queries |
| Encryption | Protect data at rest | TDE, column encryption |
| Patch Management | Respond to vulnerabilities quickly | Regular update schedule |

---

## 1. Least Privilege Principle (GRANT Management)

### 1-1. MySQL Privilege Management

```sql
-- Check current user privileges
SHOW GRANTS FOR 'appuser'@'localhost';

-- Bad: Grant all privileges
-- GRANT ALL PRIVILEGES ON *.* TO 'appuser'@'%';

-- Good: Grant only necessary privileges
-- Read-only user
CREATE USER 'reader'@'192.168.1.%' IDENTIFIED BY 'StrongPass!123';
GRANT SELECT ON myapp.* TO 'reader'@'192.168.1.%';

-- Application-specific user (specific DB, specific privileges)
CREATE USER 'appuser'@'10.0.0.1' IDENTIFIED BY 'AppPass!456';
GRANT SELECT, INSERT, UPDATE ON myapp.users TO 'appuser'@'10.0.0.1';
GRANT SELECT, INSERT ON myapp.orders TO 'appuser'@'10.0.0.1';
-- DELETE restricted to separate admin account

FLUSH PRIVILEGES;

-- Revoke excessive privileges
REVOKE DELETE ON myapp.* FROM 'appuser'@'10.0.0.1';
REVOKE SUPER ON *.* FROM 'appuser'@'10.0.0.1';
```

### 1-2. Dangerous Default Account Cleanup

```sql
-- Check MySQL default accounts
SELECT user, host FROM mysql.user WHERE user IN ('root', 'anonymous', '');

-- Delete anonymous accounts
DELETE FROM mysql.user WHERE user = '';
FLUSH PRIVILEGES;

-- Block root remote access
DELETE FROM mysql.user WHERE user = 'root' AND host != 'localhost';
FLUSH PRIVILEGES;

-- Remove test database
DROP DATABASE IF EXISTS test;
```

---

## 2. SQL Injection Defense: PreparedStatements and Parameter Binding

### 2-1. Vulnerable vs. Safe Code

```python
import sqlite3

# VULNERABLE (SQL injection possible)
def vulnerable_login(username: str, password: str) -> bool:
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # Attacker input: username = "admin' --"
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor.execute(query)  # Injection occurs!
    return cursor.fetchone() is not None

# SAFE (parameter binding)
def safe_login(username: str, password: str) -> bool:
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # ? placeholder — input treated as data only
    query = "SELECT * FROM users WHERE username=? AND password=?"
    cursor.execute(query, (username, password))
    return cursor.fetchone() is not None
```

---

## 3. DB Audit Logging Configuration

### 3-1. MySQL Audit Logging

```sql
-- Enable general query log (development/testing)
SET GLOBAL general_log = 'ON';
SET GLOBAL general_log_file = '/var/log/mysql/general.log';

-- Slow query log (performance and anomaly detection)
SET GLOBAL slow_query_log = 'ON';
SET GLOBAL long_query_time = 2;  -- Queries taking > 2 seconds

-- View binary log events (change tracking)
SHOW BINARY LOGS;
SHOW BINLOG EVENTS IN 'mysql-bin.000001' LIMIT 20;
```

---

## 4. Encryption: Column Encryption and TDE

### 4-1. MySQL TDE

```sql
-- Enable TDE for a table
CREATE TABLE sensitive_data (
    id INT PRIMARY KEY AUTO_INCREMENT,
    ssn VARCHAR(20),
    credit_card VARCHAR(20)
) ENCRYPTION='Y';

-- Apply encryption to existing table
ALTER TABLE users ENCRYPTION='Y';

-- Verify encryption status
SELECT TABLE_NAME, CREATE_OPTIONS
FROM INFORMATION_SCHEMA.TABLES
WHERE CREATE_OPTIONS LIKE '%ENCRYPTION%';
```

### 4-2. Application-Level Column Encryption

```python
from cryptography.fernet import Fernet
import base64, os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class ColumnEncryptor:
    def __init__(self, master_key: bytes | None = None):
        if master_key is None:
            master_key = os.urandom(32)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(), length=32,
            salt=b"db_column_salt_v1", iterations=100_000
        )
        self.fernet = Fernet(base64.urlsafe_b64encode(kdf.derive(master_key)))
    
    def encrypt(self, plaintext: str) -> str:
        return self.fernet.encrypt(plaintext.encode()).decode()
    
    def decrypt(self, ciphertext: str) -> str:
        return self.fernet.decrypt(ciphertext.encode()).decode()
```

---

## 5. Python DB Privilege Audit Script

```python
#!/usr/bin/env python3
"""
DB Privilege Audit Script - MySQL/MariaDB
Usage: python3 db_audit.py --host localhost --user audit_user --check-level high
"""
import argparse, sys, getpass
# (Full implementation in the Korean section above)

def main() -> None:
    parser = argparse.ArgumentParser(description="MySQL/MariaDB privilege audit tool")
    parser.add_argument("--host", required=True, help="DB host address")
    parser.add_argument("--user", required=True, help="DB login account")
    parser.add_argument("--password", default="", help="DB password (prompted if omitted)")
    parser.add_argument("--port", type=int, default=3306, help="DB port (default: 3306)")
    parser.add_argument(
        "--check-level",
        choices=["low", "medium", "high"],
        default="medium",
        help="Audit depth: low=accounts, medium=+privileges, high=+encryption/logging"
    )
    parser.add_argument("--format", choices=["text", "json"], default="text")
    args = parser.parse_args()
    
    password = args.password or getpass.getpass(f"Password ({args.user}@{args.host}): ")
    print(f"[*] Connecting to {args.host}:{args.port} ...")
    # (Remaining logic mirrors the Korean section implementation)

if __name__ == "__main__":
    main()
```

**Reference:**
- sqlmap (SQL injection testing tool): https://github.com/sqlmapproject/sqlmap

---

## 5.5 Detecting Bulk Query Exfiltration via Audit Logs

Even with SQL injection defenses (section 2) and least privilege (section 1) in place, a **legitimately authenticated application account** pulling an entire table in a way that departs from its usual pattern — an insider exfiltrating data, or a compromised app server running mass SELECTs — needs its own detection layer. Build a per-account baseline of typical row-count retrieval from the audit log (configured in section 3), and flag queries that deviate sharply from it in real time.

```python
#!/usr/bin/env python3
"""Detect bulk-query outliers per account from a DB audit log (assumes PostgreSQL pgaudit format)."""
import re
import statistics
from collections import defaultdict
from pathlib import Path


def parse_audit_log(path: Path) -> list[dict]:
    """Extract user, row count, and query from pgaudit log lines (e.g. rows=52341)."""
    entries = []
    pattern = re.compile(
        r'user=(?P<user>\S+).*?rows=(?P<rows>\d+).*?statement=(?P<query>SELECT.*)'
    )
    for line in path.read_text(errors="ignore").splitlines():
        m = pattern.search(line)
        if m:
            entries.append({
                "user": m.group("user"),
                "rows": int(m.group("rows")),
                "query": m.group("query")[:120],
            })
    return entries


def detect_outliers(entries: list[dict], z_threshold: float = 3.0) -> None:
    by_user = defaultdict(list)
    for e in entries:
        by_user[e["user"]].append(e["rows"])

    for user, row_counts in by_user.items():
        if len(row_counts) < 5:
            continue
        mean = statistics.mean(row_counts)
        stdev = statistics.pstdev(row_counts) or 1
        for e in entries:
            if e["user"] != user:
                continue
            z = (e["rows"] - mean) / stdev
            if z > z_threshold and e["rows"] > 10_000:
                print(f"[!] {user}: retrieved {e['rows']} rows (z={z:.1f}) — {e['query']}")


if __name__ == "__main__":
    entries = parse_audit_log(Path("pgaudit.log"))
    detect_outliers(entries)
```

**Detection/Defense**: an absolute threshold alone (e.g., "more than 10,000 rows") will false-positive on legitimate bulk operations like batch reporting, so judge outliers **relative to each account's own historical baseline** (z-score or similar) instead. An application account fetching an entire table via `SELECT *` with no pagination is a particularly high-priority signal. As a root-cause fix, enforce a result-row cap (a mandatory `LIMIT`) at the application layer, paired with blocking any direct DB access path that bypasses it.

---

<!-- detect-validate-23 -->
## Validating DB Hardening Application

Since this document covers hardening, here we go beyond *what to configure* to verify **whether hardening is actually applied at runtime** and **does not regress**. "Applied the guide != actually applied."

### Element -> Question -> Measured signal -> Pitfall

| Element | Question | Measured signal | Pitfall |
|---|---|---|---|
| Anonymous/default accounts | Removed? | Empty user = 0 rows | Default accounts remain |
| Transport encryption | TLS enforced? | require_secure_transport=ON | Cleartext connections allowed |
| Least privilege | No excess rights? | 0 with FILE/SUPER | Over-privileged app accounts |
| Audit/backup | Works & restores? | Audit fires, restore test | Unverified backups |

### Validation (verify directly)

```bash
# Verify hardening is actually applied (own DB) — remove anon accounts, enforce TLS, check excess privilege
mysql -e "SELECT user,host FROM mysql.user WHERE user='';"          # must be 0 rows (no anon accounts)
mysql -e "SHOW VARIABLES LIKE 'require_secure_transport';"          # must be ON to enforce TLS
mysql -e "SELECT user,host FROM mysql.user WHERE Super_priv='Y';"   # SUPER holders should be minimal
# Any item off-baseline means hardening unapplied/regressed -> prevent recurrence via CI/periodic checks
```

> Validate only on **owned DBs / controlled environments**. Applying a hardening guide does not mean it is applied at runtime — directly query anonymous accounts, TLS, and privileges to confirm baselines, and prevent regression via periodic checks ([[26_Linux_Hardening]], [[68_Purple_Team]]).
