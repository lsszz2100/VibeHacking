> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 정보보안기사 실기 완전 대비

## 0. 초보자를 위한 개념 이해

### 정보보안기사 실기 시험이란?

정보보안기사 실기는 필기 합격 후 치르는 두 번째 관문으로, 실무 지식을 서술·단답형으로 평가합니다. 필기보다 어렵다고 알려져 있으며 평균 합격률이 낮습니다.

**시험 특징:**
```
실기 시험 구성:
  - 형식: 필답형 (주관식)
  - 시간: 3시간
  - 합격: 60점 이상

자주 출제되는 영역:
  네트워크 공격 도구 및 대응
    → nmap, Wireshark 사용법
    → DDoS 대응 방법

  암호화 계산 문제
    → RSA 키 생성 과정
    → 해시값 계산

  시스템 보안 설정
    → Linux 파일 권한 (chmod, chown)
    → PAM 설정, sudoers 파일

  법령 및 인증
    → ISMS-P 인증 절차
    → 개인정보보호법 조항
```

### 핵심 암기 사항

```
자주 나오는 단답형:
  - 사이버 킬체인 7단계: 정찰→무기화→전달→익스플로잇→설치→C2→목표
  - OWASP Top 10 순위
  - 3A (인증·인가·감사로깅, AAA)
  - STRIDE 위협 모델 6가지

서술형 빈출:
  - IDS vs IPS 차이점
  - SQL 인젝션 공격 원리와 대응
  - 방화벽 정책 설정 방법
```

### 공부 방법
- **기출 분석**: 최근 5년 실기 기출 패턴 파악
- **키워드 암기**: 각 용어의 정의를 정확히 서술 연습
- **실습**: Kali Linux 설치 후 직접 명령어 실행

### 기초 실습 예제
```bash
# 자주 나오는 Linux 보안 명령어
# 1. SUID 파일 찾기 (취약점 탐색)
find / -perm -4000 -type f 2>/dev/null

# 2. 열린 포트 확인
netstat -tlnp    # 또는 ss -tlnp

# 3. 파일 권한 설정
chmod 600 /etc/shadow    # 소유자만 읽기
chmod 755 /usr/bin/ls    # rwxr-xr-x

# 4. 사용자 계정 잠금
passwd -l username       # 계정 잠금
usermod -L username      # 로그인 비활성화
```

---

## 실기 시험 개요

### 시험 형식

| 유형 | 비율 | 특징 |
|------|------|------|
| 단답형 | 약 40% | 용어, 프로토콜, 개념 1~3단어 답 |
| 서술형 | 약 40% | 4~10줄 분량 설명 |
| 실무형(분석형) | 약 20% | 로그/코드 분석, 취약점 진단 |

### 합격 전략
- 단답형: 한국어 표준 용어 정확히 기재 (약어 병기 권장)
- 서술형: 핵심 키워드 포함, 구조화된 답변 작성
- 실무형: 로그 패턴 분석 능력, 취약점 식별 및 대응책 제시

---

## 취약점 분석 및 대응

### 웹 취약점

#### SQL 인젝션
**취약 코드 예시:**
```python
query = "SELECT * FROM users WHERE id='" + user_input + "'"
```
**공격 페이로드:** `' OR '1'='1' --`
**대응:**
- Prepared Statement (파라미터화 쿼리) 사용
- 입력값 화이트리스트 검증
- 최소 권한 DB 계정 사용
- WAF 적용

#### XSS (크로스사이트 스크립팅)
**공격 페이로드:** `<script>document.cookie를 외부로 전송</script>`
**유형:**
- Stored XSS: DB 저장 후 다수 사용자에게 실행
- Reflected XSS: URL 파라미터 즉시 반사
- DOM XSS: 클라이언트 측 DOM 조작

**대응:**
- 출력 시 HTML 엔티티 인코딩
- Content-Security-Policy 헤더 설정
- HttpOnly 쿠키 적용
- X-XSS-Protection 헤더

#### CSRF
**공격 원리:** 피해자의 인증 쿠키를 이용하여 위조 요청 전송
**대응:**
- CSRF 토큰 발급 및 검증
- SameSite 쿠키 속성 설정
- Referer 헤더 검증
- 이중 쿠키 제출 패턴

### 시스템 취약점

#### 버퍼 오버플로우
**원리:** 경계값 미검증 입력으로 스택의 리턴 주소 변조
**대응:**
- ASLR (주소 공간 배치 난수화)
- Stack Canary (카나리 값 검증)
- DEP/NX (데이터 영역 실행 방지)
- 안전한 함수 사용 (strncpy, snprintf)

#### 권한 상승
**원리:** setuid 파일, 잘못된 sudo 설정, 커널 취약점 등 활용
**대응:**
- 불필요한 setuid 파일 제거
- sudo 최소 권한 설정
- 정기적 권한 감사
- 커널 패치 최신 유지

### 네트워크 취약점

#### ARP 스푸핑 탐지
**증상:** 동일 IP에 대한 ARP 응답에서 MAC 주소 변경
**대응:**
- ARP 스푸핑 탐지 도구 (Arpwatch)
- 정적 ARP 테이블 설정
- 동적 ARP Inspection (DAI)
- VPN 사용

---

## 침해사고 대응 절차

### 6단계 대응 절차 (SANS 기준)

#### 1단계: 준비 (Preparation)
- 사고대응팀 구성 및 역할 정의
- 사고대응 정책 및 절차서 수립
- 모니터링 도구 및 포렌식 장비 준비
- 연락처 및 에스컬레이션 체계 구축

#### 2단계: 식별 (Identification)
- IDS/SIEM 경보 분석
- 로그 분석으로 비정상 행위 식별
- 침해 지표(IOC) 수집
- 사고 범위 및 영향도 초기 평가

#### 3단계: 격리 (Containment)
- **단기 격리**: 감염 시스템 네트워크 차단
- **장기 격리**: 백업 시스템으로 업무 전환
- 증거 보전을 위한 시스템 이미징
- 추가 피해 확산 방지

#### 4단계: 제거 (Eradication)
- 악성코드 완전 제거
- 루트킷 탐지 및 제거
- 취약점 패치 적용
- 변경된 계정 및 설정 복원

#### 5단계: 복구 (Recovery)
- 안전한 백업에서 시스템 복원
- 서비스 재시작 및 정상 동작 확인
- 모니터링 강화
- 단계적 서비스 정상화

#### 6단계: 교훈 (Lessons Learned)
- 사후 검토 회의 (사고 후 2주 이내)
- 침해사고 보고서 작성
- 재발 방지 대책 수립
- 정책/절차 업데이트

### KISA 침해사고 신고 절차
1. 침해사고 인지 즉시 내부 보고
2. **24시간 이내** KISA 신고 (118 또는 인터넷침해대응센터)
3. 사고 관련 증거 보전
4. 신고서 제출 (피해 현황, 조치 사항 포함)

---

## 보안 솔루션 설명

### 방화벽 (Firewall)

**정의:** 네트워크 트래픽을 분석하여 허가되지 않은 접근을 차단하는 보안 장비

**세대별 분류:**
- 1세대: 패킷 필터링 (IP, 포트, 프로토콜 기반)
- 2세대: 애플리케이션 게이트웨이 (프록시)
- 3세대: 상태 기반 검사 (연결 추적)
- 4세대: 차세대 방화벽 NGFW (DPI, 애플리케이션 인식)

**주요 기능:**
- 접근 제어 정책 (ACL) 적용
- NAT/PAT 처리
- VPN 종단점
- 로깅 및 감사

### IDS/IPS (침입탐지/방지 시스템)

| 구분 | IDS | IPS |
|------|-----|-----|
| 동작 | 탐지 후 경보 | 탐지 즉시 차단 |
| 위치 | Out-of-band | Inline |
| 오탐 영향 | 경보 과다 | 정상 트래픽 차단 |
| 성능 영향 | 낮음 | 있음 |

**탐지 방식:**
- 시그니처 기반: 알려진 공격 패턴 매칭 (낮은 오탐, 높은 미탐)
- 이상 탐지: 정상 기준 이탈 감지 (높은 오탐, 낮은 미탐)
- 하이브리드: 두 방식 결합

### WAF (웹 애플리케이션 방화벽)

**정의:** HTTP/HTTPS 트래픽을 분석하여 웹 공격을 탐지·차단하는 보안 장비

**주요 방어 대상:** SQL 인젝션, XSS, CSRF, 파일 업로드 취약점, 경로 탐색

**운영 모드:**
- 탐지 모드: 공격 탐지 후 로깅만
- 차단 모드: 공격 즉시 차단
- 학습 모드: 정상 트래픽 패턴 자동 학습

### DLP (데이터 유출 방지)

**정의:** 중요 데이터의 비인가 외부 유출을 탐지하고 차단하는 시스템

**탐지 방법:**
- 키워드 필터링
- 정규식 패턴 (주민번호, 카드번호)
- 디지털 핑거프린팅
- 머신러닝 기반 분류

**적용 영역:**
- 네트워크 DLP: 이메일, 웹, FTP 모니터링
- 엔드포인트 DLP: USB, 프린터, 클립보드 제어
- 스토리지 DLP: 중요 데이터 위치 파악

### NAC (네트워크 접근 제어)

**정의:** 네트워크 접속 단말의 보안 상태를 검사하고 정책 미준수 단말의 접속을 제어하는 시스템

**주요 기능:**
- 단말 인증 (802.1X)
- 보안 상태 검사 (패치, 백신 등)
- 격리 및 치료
- 네트워크 접근 정책 적용

---

## 실기 빈출 문제 유형 30개 (문제+풀이)

### 단답형 문제

**문제 1.** 공격자가 ARP Reply 패킷을 위조하여 피해자의 ARP 캐시를 변조함으로써 네트워크 트래픽을 자신에게 우회시키는 공격은?
**답:** ARP 스푸핑 (ARP Spoofing)

**문제 2.** 블록 암호의 운용 모드 중 인증 태그를 함께 생성하여 암호화와 인증을 동시에 제공하는 모드는?
**답:** GCM (Galois/Counter Mode)

**문제 3.** 디지털 포렌식의 4대 원칙을 쓰시오.
**답:** 무결성, 연계 보관성, 재현성, 신속성

**문제 4.** 악성코드가 실행된 후 자신을 숨기고 관리자 권한을 유지하기 위해 커널 레벨에서 동작하는 악성코드 유형은?
**답:** 루트킷 (Rootkit)

**문제 5.** SSL/TLS에서 핸드셰이크 과정 중 클라이언트가 서버에게 전송하는 첫 번째 메시지는?
**답:** ClientHello

**문제 6.** 웹 서버 로그에서 `../../../../etc/passwd` 패턴이 발견되었다. 이 공격의 유형은?
**답:** 경로 탐색 공격 (Directory Traversal / Path Traversal)

**문제 7.** 해시 함수의 4가지 특성을 쓰시오.
**답:** 일방향성, 충돌 저항성, 역상 저항성, 제2역상 저항성

**문제 8.** IPsec의 두 가지 프로토콜과 각각의 기능을 쓰시오.
**답:** AH(Authentication Header) - 인증 및 무결성 제공 / ESP(Encapsulating Security Payload) - 암호화, 인증, 무결성 제공

**문제 9.** OWASP에서 권장하는 SQL 인젝션 방어 기법 중 가장 효과적인 방법은?
**답:** Prepared Statement (파라미터화 쿼리)

**문제 10.** 정보보호 위험 관리에서 ALE를 구하는 공식을 쓰시오.
**답:** ALE(연간 예상 손실) = SLE(단일 예상 손실) × ARO(연간 발생 빈도)

### 서술형 문제

**문제 11.** 방화벽의 3가지 유형을 설명하고 각각의 특징을 서술하시오.
**답:**
1. **패킷 필터링 방화벽**: IP 주소, 포트 번호, 프로토콜을 기준으로 패킷을 필터링. 속도가 빠르고 구현이 단순하나 애플리케이션 계층 공격에 취약
2. **상태 기반 검사(Stateful Inspection) 방화벽**: 연결의 상태를 추적하여 패킷을 필터링. 세션 상태를 고려하여 패킷 필터링 방화벽보다 강화된 보안 제공
3. **애플리케이션 게이트웨이(프록시 방화벽)**: 애플리케이션 계층에서 동작하며 프록시를 통해 트래픽을 중계. 가장 강력한 보안을 제공하나 성능 저하 발생

**문제 12.** 침해사고 대응 6단계를 순서대로 설명하시오.
**답:** ①준비(정책/도구 준비) → ②식별(사고 탐지 및 범위 파악) → ③격리(추가 피해 차단) → ④제거(악성코드 제거 및 취약점 패치) → ⑤복구(시스템 복원 및 서비스 재개) → ⑥교훈(사후 검토 및 재발 방지)

**문제 13.** XSS 공격의 3가지 유형을 설명하고 방어 방법을 2가지 이상 서술하시오.
**답:**
유형:
- Stored XSS: 악성 스크립트를 DB에 저장하여 다수 사용자에게 지속적으로 실행
- Reflected XSS: URL 파라미터의 스크립트가 응답에 즉시 반사되어 실행
- DOM XSS: 클라이언트 측 JavaScript가 DOM을 동적으로 조작할 때 발생

방어 방법:
- HTML 특수문자 엔티티 인코딩(출력 인코딩)
- Content-Security-Policy 헤더 설정
- HttpOnly 쿠키 속성 적용
- 입력값 화이트리스트 검증

**문제 14.** PKI(공개키 기반구조)의 구성 요소를 설명하시오.
**답:**
- CA(인증 기관): 디지털 인증서 발급, 관리, 폐지
- RA(등록 기관): 인증서 신청자 신원 확인 및 CA에 전달
- 인증서 저장소: 발급된 인증서 저장 및 배포
- CRL(인증서 폐지 목록): 폐지된 인증서 목록 관리
- OCSP: 실시간 인증서 유효성 확인 프로토콜

**문제 15.** DDoS 공격의 유형 3가지를 설명하고 각각의 대응 방안을 서술하시오.
**답:**
- SYN Flooding: TCP 3-way 핸드셰이크를 미완성으로 서버 연결 대기 큐 고갈 → SYN Cookie 적용
- HTTP Flooding: 정상 HTTP 요청을 대량 발송하여 웹 서버 과부하 → 사용자 행위 분석, CAPTCHA 적용
- DNS 증폭 공격: 소량의 쿼리로 대량의 DNS 응답을 피해자에게 유도 → DNS 응답 속도 제한, BCP38 적용

### 실무형(분석형) 문제

**문제 16.** 다음 웹 서버 로그를 분석하고 공격 유형과 대응 방안을 서술하시오.
```
GET /search?q=<script>alert(document.cookie)</script> HTTP/1.1
```
**답:** Reflected XSS 공격. 공격자가 URL 파라미터에 스크립트를 삽입하여 피해자 브라우저에서 실행시키는 공격. 대응: 출력 시 HTML 엔티티 인코딩, CSP 헤더 설정, WAF 적용

**문제 17.** 다음 로그를 분석하고 어떤 공격인지 설명하시오.
```
192.168.1.100 - - [10/May/2024] "GET /admin?id=1 OR 1=1-- HTTP/1.1" 200
```
**답:** SQL 인젝션 공격. `OR 1=1--`을 통해 WHERE 조건을 항상 참으로 만들어 인증 우회. 대응: Prepared Statement 사용, WAF 적용, 입력값 검증 강화

**문제 18.** 다음 네트워크 로그에서 이상 징후를 찾고 설명하시오.
```
[ARP] 192.168.1.1 is at AA:BB:CC:DD:EE:FF
[ARP] 192.168.1.1 is at 11:22:33:44:55:66  (2초 후)
```
**답:** ARP 스푸핑 공격 의심. 동일 IP(192.168.1.1)에 대해 두 개의 다른 MAC 주소가 응답. 공격자가 ARP 응답을 위조하여 트래픽을 자신에게 우회. 대응: DAI 적용, 정적 ARP 설정, Arpwatch 모니터링

**문제 19.** 다음 코드의 취약점을 분석하고 안전한 코드로 수정하시오.
```c
void vulnerable(char *input) {
    char buffer[64];
    strcpy(buffer, input);  // 취약점
}
```
**답:** 버퍼 오버플로우 취약점. strcpy는 길이 검사 없이 복사.
안전한 코드:
```c
void safe(char *input) {
    char buffer[64];
    strncpy(buffer, input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';
}
```

**문제 20.** 다음 상황에서 침해사고 대응 절차를 서술하시오.
상황: 웹 서버에서 악성코드 탐지, 고객 개인정보 유출 의심
**답:**
1. 즉시 해당 웹 서버 네트워크 격리 (업무 시스템 분리)
2. 서버 이미지 복사 (증거 보전, 해시값 기록)
3. 로그 수집 및 분석 (웹 로그, 시스템 로그, 접근 기록)
4. 악성코드 분석 및 제거
5. 취약점 파악 및 패치 적용
6. 24시간 이내 KISA 침해사고 신고
7. 개인정보 유출 확인 시 개인정보보호위원회 신고 및 피해자 통지
8. 서비스 복구 및 모니터링 강화

**문제 21.** ISMS-P 인증의 3개 영역을 설명하시오.
**답:**
- 관리체계 수립·운영(16개 통제항목): PDCA 기반 보안 관리체계 수립, 운영, 점검, 개선
- 보호대책 요구사항(64개 통제항목): 정책, 인적보안, 외부자보안, 물리보안, 시스템보안 등 세부 보호 조치
- 개인정보 처리단계별 요구사항(22개 통제항목): 수집, 저장·관리, 이용·제공, 파기까지 단계별 개인정보 보호

**문제 22.** 대칭키 암호와 비대칭키 암호를 비교하고 실제 적용 사례를 설명하시오.
**답:**
- 대칭키: 동일한 키로 암호화/복호화. 빠른 속도, 키 배포 문제. 예: AES, SEED (대용량 데이터 암호화)
- 비대칭키: 공개키 암호화, 개인키 복호화. 느린 속도, 키 배포 용이. 예: RSA (디지털 서명, 키 교환)
- 실제 적용: TLS 핸드셰이크에서 비대칭키로 세션 키 교환 후, 실제 통신은 대칭키로 암호화 (하이브리드 방식)

**문제 23.** 개인정보 암호화 적용 기준을 서술하시오.
**답:** 개인정보보호법 시행령에 따라
- 고유식별정보(주민번호, 외국인등록번호, 여권번호, 운전면허번호): 저장 시 암호화 필수
- 비밀번호: 일방향 해시 함수 적용 필수
- 바이오정보: 저장 시 암호화 필수
- 신용카드번호, 계좌번호: 저장 시 암호화 필수
- 전송 시: 암호화 채널(TLS) 사용 필수

**문제 24.** 포렌식 조사 시 증거 수집 및 보존 원칙을 서술하시오.
**답:**
- 무결성: 수집 시 해시값(SHA-256) 계산, 원본 변경 금지
- 연계 보관성(Chain of Custody): 증거 취급자, 시간, 장소 기록
- 재현성: 동일 방법으로 동일 결과 도출 가능
- 쓰기 방지: Write Blocker 사용하여 원본 훼손 방지
- 문서화: 모든 과정을 상세히 기록

**문제 25.** 다음 패킷을 분석하고 공격 유형을 설명하시오.
```
Source IP: 192.168.1.1, Dest IP: 192.168.1.1
Source Port: 80, Dest Port: 80
Flags: SYN
```
**답:** Land Attack. 출발지 IP와 목적지 IP, 포트가 동일하여 시스템이 자기 자신에게 응답을 보내는 무한 루프 상태에 빠지게 하는 DoS 공격. 대응: 출발지=목적지 동일 패킷 방화벽 차단 규칙 적용

**문제 26.** 망분리의 종류와 각각의 특징을 서술하시오.
**답:**
- 물리적 망분리: 업무망과 인터넷망 컴퓨터를 별도 장비로 완전 분리. 가장 강력하나 비용이 높음
- 논리적 망분리(VDI): 가상화 기술로 동일 PC에서 업무망과 인터넷망 분리. 물리적 분리 대비 비용 절감
- 물리적 망분리 의무 대상: 금융회사, 전자금융업자(전자금융거래법), 공공기관(일정 규모 이상)

**문제 27.** 악성코드의 분류와 각각의 특징을 서술하시오.
**답:**
- 바이러스: 숙주 파일에 코드 삽입, 사용자 실행 시 감염 전파
- 웜: 자기복제 후 네트워크를 통해 자동 전파, 숙주 불필요
- 트로이 목마: 정상 프로그램으로 위장, 백도어 설치
- 랜섬웨어: 파일 암호화 후 복구 비용 요구
- 루트킷: 자신과 다른 악성코드를 숨기는 스텔스 악성코드
- 스파이웨어: 사용자 정보 무단 수집 및 전송
- 봇(Bot): C&C 서버 명령으로 원격 제어되는 좀비 PC

**문제 28.** TLS 핸드셰이크 과정을 순서대로 설명하시오.
**답:**
1. ClientHello: 클라이언트가 지원하는 암호 스위트, TLS 버전, 랜덤값 전송
2. ServerHello: 서버가 선택한 암호 스위트, 서버 인증서, 랜덤값 전송
3. 인증서 검증: 클라이언트가 서버 인증서 유효성 확인
4. Key Exchange: 클라이언트가 Pre-Master Secret을 서버 공개키로 암호화 전송
5. Session Key 생성: 양측에서 동일한 세션 키 생성
6. Finished: 암호화 통신 시작

**문제 29.** 개인정보보호법상 개인정보 유출 시 신고 의무를 서술하시오.
**답:**
- 1천 명 이상 개인정보 유출 시: 72시간 이내 개인정보보호위원회 신고 (2023년 개정)
- 정보주체 통지: 유출 사실 인지 즉시 (지체없이) 해당 정보주체에게 통지
- 통지 내용: 유출 항목, 유출 시점, 피해 최소화 방법, 조치 사항, 담당부서 연락처
- 통지 방법: 서면, 전자우편, 문자메시지 등

**문제 30.** 취약점 관리 프로세스를 단계별로 설명하시오.
**답:**
1. 자산 식별: 취약점 점검 대상 자산 목록 작성
2. 취약점 스캐닝: 자동화 도구(Nessus, OpenVAS 등)로 취약점 탐지
3. 취약점 분석: 발견된 취약점의 심각도(CVSS 점수) 및 위험도 평가
4. 우선순위 결정: 위험도 기반 패치 순서 결정 (Critical → High → Medium)
5. 패치 적용: 테스트 환경 검증 후 운영 환경 적용
6. 재점검: 패치 적용 후 취약점 해소 확인
7. 문서화: 취약점 발견부터 해소까지 전 과정 기록

---

## Python CLI: 실기 기출 유형 랜덤 출제 및 채점 도구

```python
#!/usr/bin/env python3
"""
정보보안기사 실기 기출 유형 랜덤 출제 및 채점 CLI 도구
사용법: python3 practical_quiz.py [--type TYPE] [--count N] [--review]
"""

import argparse
import json
import random
import sys
import datetime
from pathlib import Path
from typing import Optional

PRACTICAL_QUESTIONS: dict[str, list[dict]] = {
    "단답형": [
        {
            "question": "공격자가 ARP Reply를 위조하여 피해자 ARP 캐시를 변조, 트래픽을 우회시키는 공격은?",
            "answer": "ARP 스푸핑",
            "keywords": ["ARP", "스푸핑"],
            "difficulty": "하",
        },
        {
            "question": "블록 암호 모드 중 인증 태그를 포함하여 암호화와 인증을 동시에 제공하는 모드는?",
            "answer": "GCM",
            "keywords": ["GCM", "Galois"],
            "difficulty": "중",
        },
        {
            "question": "디지털 포렌식의 4대 원칙을 모두 쓰시오.",
            "answer": "무결성, 연계 보관성, 재현성, 신속성",
            "keywords": ["무결성", "연계", "재현", "신속"],
            "difficulty": "중",
        },
        {
            "question": "커널 레벨에서 동작하며 자신과 악성코드를 숨기는 악성코드 유형은?",
            "answer": "루트킷",
            "keywords": ["루트킷", "rootkit"],
            "difficulty": "하",
        },
        {
            "question": "SQL 인젝션 방어를 위해 OWASP가 가장 권장하는 기법은?",
            "answer": "Prepared Statement",
            "keywords": ["Prepared", "파라미터화"],
            "difficulty": "하",
        },
        {
            "question": "연간 예상 손실(ALE)을 구하는 공식을 쓰시오.",
            "answer": "ALE = SLE × ARO",
            "keywords": ["SLE", "ARO", "ALE"],
            "difficulty": "중",
        },
        {
            "question": "출발지 IP와 목적지 IP가 동일한 패킷을 이용한 DoS 공격은?",
            "answer": "Land Attack",
            "keywords": ["Land", "랜드"],
            "difficulty": "중",
        },
        {
            "question": "해시 함수의 4가지 특성을 쓰시오.",
            "answer": "일방향성, 충돌 저항성, 역상 저항성, 제2역상 저항성",
            "keywords": ["일방향", "충돌", "역상"],
            "difficulty": "중",
        },
    ],
    "서술형": [
        {
            "question": "방화벽의 3가지 유형(패킷 필터링, 상태 기반, 프록시)을 각각 설명하시오.",
            "answer": "1.패킷 필터링: IP/포트 기반 빠른 필터링, 애플리케이션 취약 2.상태 기반: 연결 상태 추적, 보안 강화 3.프록시: 앱 계층 중계, 가장 강력한 보안",
            "keywords": ["패킷 필터링", "상태", "프록시", "애플리케이션"],
            "difficulty": "중",
        },
        {
            "question": "XSS 공격의 3가지 유형을 설명하고 방어 방법 2가지를 서술하시오.",
            "answer": "Stored XSS(DB저장), Reflected XSS(즉시반사), DOM XSS(클라이언트). 방어: 출력인코딩, CSP헤더",
            "keywords": ["Stored", "Reflected", "DOM", "인코딩", "CSP"],
            "difficulty": "중",
        },
        {
            "question": "침해사고 대응 6단계를 순서대로 설명하시오.",
            "answer": "준비→식별→격리→제거→복구→교훈",
            "keywords": ["준비", "식별", "격리", "제거", "복구", "교훈"],
            "difficulty": "중",
        },
        {
            "question": "DDoS 공격 3가지 유형과 각각의 대응 방안을 서술하시오.",
            "answer": "SYN Flooding(SYN Cookie), HTTP Flooding(CAPTCHA), DNS증폭(BCP38)",
            "keywords": ["SYN", "HTTP", "DNS", "SYN Cookie"],
            "difficulty": "상",
        },
        {
            "question": "PKI의 구성 요소를 설명하시오.",
            "answer": "CA(인증 기관), RA(등록 기관), 인증서 저장소, CRL, OCSP",
            "keywords": ["CA", "RA", "CRL", "OCSP"],
            "difficulty": "중",
        },
    ],
    "실무형": [
        {
            "question": "다음 웹 로그를 분석하시오: GET /search?q=<script>alert(1)</script>\n→ 공격 유형과 대응 방안을 서술하시오.",
            "answer": "Reflected XSS. 대응: 출력 인코딩, CSP 헤더, WAF",
            "keywords": ["XSS", "Reflected", "인코딩"],
            "difficulty": "중",
        },
        {
            "question": "다음 쿼리를 분석하시오: SELECT * FROM users WHERE id='' OR '1'='1'\n→ 공격 유형과 대응 방안을 서술하시오.",
            "answer": "SQL 인젝션. 대응: Prepared Statement, WAF, 입력값 검증",
            "keywords": ["SQL", "인젝션", "Prepared"],
            "difficulty": "하",
        },
        {
            "question": "다음 코드의 취약점을 찾고 수정 방법을 서술하시오:\nvoid f(char *s) { char buf[64]; strcpy(buf, s); }",
            "answer": "버퍼 오버플로우. 수정: strncpy 사용, 경계값 검사",
            "keywords": ["버퍼", "오버플로우", "strncpy"],
            "difficulty": "중",
        },
        {
            "question": "다음 ARP 로그를 분석하시오:\n192.168.1.1 → AA:BB:CC:DD:EE:FF\n192.168.1.1 → 11:22:33:44:55:66 (2초 후)\n→ 공격 유형과 대응을 서술하시오.",
            "answer": "ARP 스푸핑. 대응: DAI, 정적 ARP, Arpwatch",
            "keywords": ["ARP", "스푸핑", "DAI"],
            "difficulty": "중",
        },
    ],
}

RESULT_FILE = Path.home() / ".practical_quiz_results.json"


def load_results() -> list[dict]:
    if RESULT_FILE.exists():
        try:
            with open(RESULT_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return []
    return []


def save_result(result: dict) -> None:
    results = load_results()
    results.append(result)
    try:
        with open(RESULT_FILE, "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
    except OSError as e:
        print(f"결과 저장 실패: {e}", file=sys.stderr)


def evaluate_answer(user_answer: str, correct_answer: str, keywords: list[str]) -> tuple[bool, int]:
    if not user_answer.strip():
        return False, 0

    keyword_hits = sum(1 for kw in keywords if kw.lower() in user_answer.lower())
    score = int((keyword_hits / len(keywords)) * 100) if keywords else 0

    passed = score >= 60
    return passed, score


def run_practical_quiz(question_type: Optional[str], count: int) -> None:
    if question_type and question_type in PRACTICAL_QUESTIONS:
        pool = [{"type": question_type, **q} for q in PRACTICAL_QUESTIONS[question_type]]
    else:
        pool = [
            {"type": qtype, **q}
            for qtype, questions in PRACTICAL_QUESTIONS.items()
            for q in questions
        ]

    random.shuffle(pool)
    selected = pool[:min(count, len(pool))]

    total_score = 0
    session_results = []

    print(f"\n{'='*70}")
    print(f" 정보보안기사 실기 모의고사 (총 {len(selected)}문제)")
    print(f"{'='*70}\n")
    print("※ 핵심 키워드를 포함하여 답변하세요. 60점 이상이면 해당 문제 합격입니다.\n")

    for i, q in enumerate(selected, 1):
        print(f"[{i}/{len(selected)}] [{q['type']}] 난이도: {q['difficulty']}")
        print(f"문제: {q['question']}")
        print("\n답변 입력 (빈 줄 2개 입력 시 완료):")

        lines = []
        empty_count = 0
        while empty_count < 2:
            line = input()
            if line == "":
                empty_count += 1
            else:
                empty_count = 0
                lines.append(line)

        user_answer = "\n".join(lines)
        passed, score = evaluate_answer(user_answer, q["answer"], q["keywords"])

        print(f"\n[채점 결과] 점수: {score}/100 → {'합격' if passed else '불합격'}")
        print(f"[모범 답안] {q['answer']}")
        print(f"[핵심 키워드] {', '.join(q['keywords'])}\n")
        print("-" * 70)

        total_score += score
        session_results.append({
            "question": q["question"][:50],
            "type": q["type"],
            "score": score,
            "passed": passed,
        })

    avg_score = total_score / len(selected) if selected else 0
    passed_count = sum(1 for r in session_results if r["passed"])

    print(f"\n{'='*70}")
    print(f" 최종 결과: {passed_count}/{len(selected)} 문제 합격")
    print(f" 평균 점수: {avg_score:.1f}/100")
    print(f"{'='*70}")

    if avg_score >= 60:
        print(" 합격권입니다! 실전에서도 좋은 결과를 기대합니다.")
    else:
        print(" 핵심 키워드 중심으로 답안을 구성하는 연습이 필요합니다.")

    save_result({
        "date": datetime.datetime.now().isoformat(),
        "total": len(selected),
        "passed": passed_count,
        "avg_score": avg_score,
        "details": session_results,
    })


def show_review() -> None:
    results = load_results()
    if not results:
        print("저장된 결과가 없습니다.")
        return

    print(f"\n{'='*70}")
    print(f" 실기 모의고사 이력 (총 {len(results)}회)")
    print(f"{'='*70}\n")

    for i, r in enumerate(results[-5:], 1):
        print(f"[{i}회] {r['date'][:10]}: 평균 {r['avg_score']:.1f}점 ({r['passed']}/{r['total']} 합격)")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="정보보안기사 실기 기출 유형 랜덤 출제 도구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
사용 예시:
  python3 practical_quiz.py                    # 전체 유형 랜덤 5문제
  python3 practical_quiz.py --type 단답형      # 단답형만 출제
  python3 practical_quiz.py --type 서술형      # 서술형만 출제
  python3 practical_quiz.py --type 실무형      # 실무형만 출제
  python3 practical_quiz.py --count 10         # 10문제 출제
  python3 practical_quiz.py --review           # 이전 결과 확인
        """,
    )
    parser.add_argument("--type", "-t", choices=["단답형", "서술형", "실무형"], help="문제 유형 선택")
    parser.add_argument("--count", "-n", type=int, default=5, help="출제 문제 수 (기본: 5)")
    parser.add_argument("--review", "-r", action="store_true", help="이전 결과 확인")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if args.review:
        show_review()
        return

    run_practical_quiz(args.type, args.count)


if __name__ == "__main__":
    main()
```

---

## 실기 대비 핵심 정리

### 서술형 답안 작성 원칙

1. **핵심 용어 정확 사용**: 약어는 반드시 풀어서 기재 (예: IDS - Intrusion Detection System)
2. **구조화된 답변**: 번호 매기기, 단계별 서술
3. **원인-원리-대응 구조**: 취약점 원인 → 공격 원리 → 방어 대응책
4. **분량 준수**: 서술형은 최소 4줄 이상, 실무형은 6줄 이상 작성
5. **키워드 포함**: 채점관이 확인하는 핵심 용어 반드시 포함

### 빈출 암호 알고리즘 비교표

| 구분 | 알고리즘 | 키 길이 | 특징 |
|------|---------|---------|------|
| 대칭키 | AES | 128/192/256비트 | 현재 표준 |
| 대칭키 | SEED | 128비트 | 한국 표준 |
| 대칭키 | ARIA | 128/192/256비트 | 경량 한국 표준 |
| 비대칭키 | RSA | 2048비트 이상 | 소인수분해 기반 |
| 비대칭키 | ECC | 256비트 | 타원곡선 기반 |
| 해시 | SHA-256 | 256비트 출력 | 현재 표준 |
| 해시 | MD5 | 128비트 출력 | 취약, 사용 지양 |

<!-- detect-validate-41 -->
## 실기 역량 검증 — 답안이 실제로 동작하는가

정보보안기사 실기는 *답안을 외웠는가*가 아니라 **실제 환경에서 명령·분석이 의도대로 동작하는가**로 판정된다. 자주 출제되는 점검을 직접 실행해 본다. 검증은 **소유 실습 환경**에서만.

### 출제 영역 → 함정 → 실습 검증 → 양호 신호

| 출제 영역 | 함정 | 실습 검증 | 양호 신호 |
|---|---|---|---|
| 로그 분석 | 필드 오독 | 실제 로그 파싱 | 공격 흔적 식별 |
| 취약점 점검 | 설정 오판 | 유효설정 질의 | 기대값 일치 |
| 패킷 분석 | 도구 미숙 | tcpdump/tshark | 흐름 재구성 |
| 보안설정 | 미적용 | 적용 후 재확인 | 런타임 반영 |

### 검증 (직접 확인)

```bash
# 1) 로그 분석 실기 — 인증 실패 폭주(브루트포스 흔적)를 직접 집계. 소유 호스트에서
grep -aiE 'failed password|authentication failure' /var/log/auth.log 2>/dev/null | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head
# 2) 패킷 분석 실기 — SYN 폭주 등 이상 흐름 재구성(소유 캡처 파일)
tcpdump -nr owned_capture.pcap 'tcp[tcpflags] & tcp-syn != 0' 2>/dev/null | head
```

> 검증은 반드시 **소유 실습 환경**에서만 한다. "답안을 외웠다"와 "실제로 동작·재현된다"는 다르다 — 점검 명령을 직접 실행해 확인한다([[07_Digital_Forensics]], [[02_Network_Hacking]]).

---

<a name="english"></a>

# Information Security Engineer Practical Exam — Complete Preparation

## Practical Exam Overview

### Exam Format

| Type | Percentage | Characteristics |
|------|-----------|----------------|
| Short answer | ~40% | 1-3 word answers for terms, protocols, concepts |
| Descriptive | ~40% | 4-10 line explanations |
| Practical (analytical) | ~20% | Log/code analysis, vulnerability diagnosis |

### Passing Strategy
- Short answer: Write exact Korean standard terms (abbreviations with full form recommended)
- Descriptive: Include core keywords, write structured answers
- Practical: Log pattern analysis ability, vulnerability identification and countermeasure presentation

---

## Vulnerability Analysis and Response

### Web Vulnerabilities

#### SQL Injection
**Vulnerable code example:**
```python
query = "SELECT * FROM users WHERE id='" + user_input + "'"
```
**Attack payload:** `' OR '1'='1' --`
**Countermeasures:**
- Use Prepared Statement (parameterized query)
- Whitelist input validation
- Minimum privilege DB account
- Apply WAF

#### XSS (Cross-Site Scripting)
**Attack payload:** `<script>Send document.cookie to external</script>`
**Types:**
- Stored XSS: Stored in DB and executed for multiple users
- Reflected XSS: URL parameter immediately reflected
- DOM XSS: Client-side DOM manipulation

**Countermeasures:**
- HTML entity encoding on output
- Content-Security-Policy header configuration
- HttpOnly cookie application
- X-XSS-Protection header

#### CSRF
**Attack principle:** Sends forged requests using victim's authentication cookie
**Countermeasures:**
- Issue and validate CSRF tokens
- Set SameSite cookie attribute
- Verify Referer header
- Double cookie submission pattern

### System Vulnerabilities

#### Buffer Overflow
**Principle:** Unvalidated boundary input modifies stack return address
**Countermeasures:**
- ASLR (Address Space Layout Randomization)
- Stack Canary (canary value validation)
- DEP/NX (Data Execution Prevention)
- Use safe functions (strncpy, snprintf)

#### Privilege Escalation
**Principle:** Uses setuid files, misconfigured sudo, kernel vulnerabilities
**Countermeasures:**
- Remove unnecessary setuid files
- Minimum privilege sudo configuration
- Regular privilege auditing
- Keep kernel patches up to date

### Network Vulnerabilities

#### ARP Spoofing Detection
**Symptoms:** MAC address changes in ARP responses for the same IP
**Countermeasures:**
- ARP spoofing detection tools (Arpwatch)
- Static ARP table configuration
- Dynamic ARP Inspection (DAI)
- Use VPN

---

## Incident Response Procedures

### 6-Stage Response Procedure (SANS Standard)

#### Stage 1: Preparation
- Assemble incident response team and define roles
- Establish incident response policy and procedures
- Prepare monitoring tools and forensics equipment
- Establish contact information and escalation framework

#### Stage 2: Identification
- Analyze IDS/SIEM alerts
- Identify abnormal behavior through log analysis
- Collect indicators of compromise (IOC)
- Initial assessment of incident scope and impact

#### Stage 3: Containment
- **Short-term containment**: Disconnect infected systems from network
- **Long-term containment**: Switch operations to backup systems
- System imaging for evidence preservation
- Prevent further damage spread

#### Stage 4: Eradication
- Complete removal of malware
- Rootkit detection and removal
- Apply vulnerability patches
- Restore changed accounts and configurations

#### Stage 5: Recovery
- Restore systems from safe backups
- Restart services and verify normal operation
- Enhance monitoring
- Gradual service normalization

#### Stage 6: Lessons Learned
- Post-incident review meeting (within 2 weeks of incident)
- Write breach incident report
- Establish recurrence prevention measures
- Update policies/procedures

---

## Security Solutions

### Firewall

**Definition:** Security device that analyzes network traffic and blocks unauthorized access

**Generation Classification:**
- 1st Gen: Packet filtering (IP, port, protocol-based)
- 2nd Gen: Application gateway (proxy)
- 3rd Gen: Stateful inspection (connection tracking)
- 4th Gen: Next-gen firewall NGFW (DPI, application awareness)

### IDS/IPS

| Category | IDS | IPS |
|----------|-----|-----|
| Operation | Detect then alert | Detect then immediately block |
| Position | Out-of-band | Inline |
| False positive impact | Excessive alerts | Block legitimate traffic |
| Performance impact | Low | Present |

**Detection Methods:**
- Signature-based: Known attack pattern matching (low false positive, high miss)
- Anomaly detection: Deviation from normal baseline (high false positive, low miss)
- Hybrid: Combination of both methods

### WAF (Web Application Firewall)

**Definition:** Security device that analyzes HTTP/HTTPS traffic to detect and block web attacks

**Key Defense Targets:** SQL injection, XSS, CSRF, file upload vulnerabilities, path traversal

### DLP (Data Loss Prevention)

**Definition:** System that detects and blocks unauthorized external leakage of sensitive data

**Detection Methods:**
- Keyword filtering
- Regular expressions (SSN, card numbers)
- Digital fingerprinting
- Machine learning-based classification

### NAC (Network Access Control)

**Definition:** System that inspects the security state of network-connected terminals and controls access for non-compliant terminals

---

## Key Practical Q&A (30 Questions)

### Short Answer

**Q1.** An attack where the attacker forges ARP Reply packets to manipulate the victim's ARP cache and redirect network traffic to themselves?
**A:** ARP Spoofing

**Q2.** The block cipher operation mode that generates an authentication tag to simultaneously provide encryption and authentication?
**A:** GCM (Galois/Counter Mode)

**Q3.** Write the four principles of digital forensics.
**A:** Integrity, Chain of Custody, Reproducibility, Timeliness

**Q4.** The malware type that operates at kernel level to hide itself and maintain administrator privileges after execution?
**A:** Rootkit

**Q5.** The first message sent from client to server during SSL/TLS handshake?
**A:** ClientHello

**Q6.** `../../../../etc/passwd` pattern found in web server logs. What type of attack is this?
**A:** Directory Traversal / Path Traversal

**Q7.** Write the four properties of hash functions.
**A:** One-way property, Collision resistance, Preimage resistance, Second preimage resistance

**Q8.** Write the two IPsec protocols and their functions.
**A:** AH (Authentication Header) - provides authentication and integrity / ESP (Encapsulating Security Payload) - provides encryption, authentication, and integrity

**Q9.** The most effective defense technique against SQL injection recommended by OWASP?
**A:** Prepared Statement (parameterized query)

**Q10.** Write the formula for calculating ALE in information security risk management.
**A:** ALE (Annual Loss Expectancy) = SLE (Single Loss Expectancy) × ARO (Annual Rate of Occurrence)

### Descriptive

**Q11.** Describe three types of firewalls and their characteristics.
**A:**
1. **Packet filtering firewall**: Filters packets based on IP address, port number, protocol. Fast and simple implementation but vulnerable to application layer attacks
2. **Stateful Inspection firewall**: Filters packets by tracking connection state. Provides stronger security than packet filtering by considering session state
3. **Application gateway (proxy firewall)**: Operates at application layer and proxies traffic. Provides the strongest security but causes performance degradation

**Q12.** List the 6 stages of incident response in order.
**A:** Preparation → Identification → Containment → Eradication → Recovery → Lessons Learned

**Q13.** Describe three types of XSS attacks and list two or more defense methods.
**A:**
Types:
- Stored XSS: Malicious script stored in DB and continuously executed for multiple users
- Reflected XSS: Script in URL parameter immediately reflected and executed in response
- DOM XSS: Occurs when client-side JavaScript dynamically manipulates DOM

Defense methods:
- HTML special character entity encoding (output encoding)
- Content-Security-Policy header configuration
- HttpOnly cookie attribute application
- Whitelist input validation

**Q14.** Describe the components of PKI (Public Key Infrastructure).
**A:**
- CA (Certificate Authority): Issues, manages, and revokes digital certificates
- RA (Registration Authority): Verifies identity of certificate applicants and forwards to CA
- Certificate Repository: Stores and distributes issued certificates
- CRL (Certificate Revocation List): Manages list of revoked certificates
- OCSP: Real-time certificate validity verification protocol

**Q15.** Describe three types of DDoS attacks and countermeasures for each.
**A:**
- SYN Flooding: Exhausts server connection queue with incomplete TCP 3-way handshake → Apply SYN Cookie
- HTTP Flooding: Overloads web server with mass normal HTTP requests → User behavior analysis, CAPTCHA
- DNS Amplification: Directs large DNS responses to victim using small queries → DNS response rate limiting, BCP38

---

## Python CLI: Random Question Generator and Scoring Tool

(See Korean section for complete implementation — code structure identical)

---

## Key Encryption Algorithm Comparison Table

| Category | Algorithm | Key Length | Characteristics |
|----------|-----------|-----------|----------------|
| Symmetric | AES | 128/192/256 bits | Current standard |
| Symmetric | SEED | 128 bits | Korean standard |
| Symmetric | ARIA | 128/192/256 bits | Lightweight Korean standard |
| Asymmetric | RSA | 2048+ bits | Factorization-based |
| Asymmetric | ECC | 256 bits | Elliptic curve-based |
| Hash | SHA-256 | 256-bit output | Current standard |
| Hash | MD5 | 128-bit output | Vulnerable, avoid use |

<!-- detect-validate-41 -->
## Practical-Skill Validation — Does the Answer Actually Work?

The practical exam is judged not by *whether you memorized an answer* but by **whether the command/analysis actually works as intended in a real environment**. Run the frequently-tested checks yourself. Validate only in an **owned lab**.

### Exam area -> Pitfall -> Hands-on validation -> Healthy signal

| Exam area | Pitfall | Hands-on validation | Healthy signal |
|---|---|---|---|
| Log analysis | Misreading fields | Parse real logs | Attack trace identified |
| Vulnerability check | Config misjudgment | Query effective config | Matches expected |
| Packet analysis | Tool inexperience | tcpdump/tshark | Flow reconstructed |
| Security config | Not applied | Re-check after apply | Reflected at runtime |

### Validation (verify directly)

```bash
# 1) Log-analysis task — directly tally auth-failure floods (brute-force trace). On owned host
grep -aiE 'failed password|authentication failure' /var/log/auth.log 2>/dev/null | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head
# 2) Packet-analysis task — reconstruct anomalous flow such as a SYN flood (owned capture file)
tcpdump -nr owned_capture.pcap 'tcp[tcpflags] & tcp-syn != 0' 2>/dev/null | head
```

> Validate only in an **owned lab**. "Memorized the answer" differs from "it actually works and reproduces" — run the check commands directly ([[07_Digital_Forensics]], [[02_Network_Hacking]]).
