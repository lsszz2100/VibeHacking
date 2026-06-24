> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 메일 서버 보안 — SPF/DKIM/DMARC 및 공격 기법

## 0. 초보자를 위한 개념 이해

### 메일 서버 보안이란?

이메일은 인터넷 초창기에 "발신자가 누구인지 확인하지 않아도 된다"는 가정으로 설계되었다. 때문에 누구나 `from: ceo@company.com`처럼 아무 주소나 적어 이메일을 보낼 수 있다. SPF, DKIM, DMARC는 이 근본적인 문제를 해결하기 위해 수십 년에 걸쳐 추가된 보안 계층이다. 이 세 가지를 이해하면 피싱 이메일이 어떻게 작동하고 어떻게 막는지 알 수 있다.

**왜 배우는가:**
```
이메일 스푸핑 공격 흐름

공격자:
  발신 주소를 ceo@company.com 으로 위조
  → "내일 긴급 계좌이체 해주세요" 발송
  → 직원이 속아 이체 실행 (BEC 사기)

방어 메커니즘:
  SPF  → 이 IP가 해당 도메인 발송 허용 IP인가?
  DKIM → 메일 내용이 발송 후 변조되지 않았는가?
  DMARC → SPF/DKIM 실패 시 어떻게 처리할 것인가?
```

### 핵심 개념 정리

```
SPF / DKIM / DMARC 역할 비교

SPF (Sender Policy Framework):
  DNS TXT 레코드에 "이 도메인을 보낼 수 있는 IP 목록" 게시
  예: v=spf1 ip4:203.0.113.10 include:_spf.google.com ~all
  → 수신 서버가 발신 IP를 DNS에서 조회해 허용 여부 확인

DKIM (DomainKeys Identified Mail):
  발신 서버가 메일에 디지털 서명 추가
  공개키는 DNS에 게시, 수신 서버가 서명 검증
  → 전송 중 변조 탐지 가능

DMARC (Domain-based Message Auth):
  SPF/DKIM 실패 시 정책: none(감시만) → quarantine(스팸) → reject(거부)
  리포트 수신 주소 설정 → 누가 내 도메인을 사칭하는지 파악
```

### 필요한 도구 및 환경
- **dig**: SPF/DKIM/DMARC 레코드 조회
- **mxtoolbox.com**: 이메일 보안 설정 온라인 확인 (실습 용이)
- **swaks**: SMTP 테스트 도구 (`apt install swaks`)

### 기초 실습 예제
```bash
# 1. SPF 레코드 확인
dig TXT example.com | grep spf
# 결과 예시: "v=spf1 include:_spf.google.com ~all"

# 2. DMARC 레코드 확인
dig TXT _dmarc.example.com
# 결과 예시: "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"

# 3. DKIM 공개키 확인 (셀렉터 이름은 도메인마다 다름)
dig TXT google._domainkey.example.com
# 결과 예시: "v=DKIM1; k=rsa; p=MIGfMA0GCS..."

# 4. 이메일 헤더에서 인증 결과 확인
# 받은 이메일의 원본 헤더에서 이 줄을 찾아보기:
# Authentication-Results: mx.example.com;
#   spf=pass (sender IP matches)
#   dkim=pass header.d=example.com
#   dmarc=pass
```

---

## 1. 메일 인증 체계 개요

이메일은 인터넷 초기에 "누가 보냈는가"를 검증하는 메커니즘 없이 설계되었습니다. 발신자 주소는 편지 봉투에 손으로 쓴 이름과 같아서 누구나 마음대로 적을 수 있었습니다. SPF, DKIM, DMARC는 이 문제를 해결하기 위해 수십 년에 걸쳐 점진적으로 도입된 표준입니다.

```
이메일 스푸핑 방어 3단계:

SPF (Sender Policy Framework)
  → "이 도메인을 보낼 수 있는 IP 목록"
  → TXT 레코드로 DNS에 게시
  → 수신 서버가 발신 IP 검증

DKIM (DomainKeys Identified Mail)
  → 메일 헤더/본문에 디지털 서명 추가
  → 공개키는 DNS TXT 레코드에 게시
  → 전송 중 내용 변조 탐지 가능

DMARC (Domain-based Message Auth, Reporting & Conformance)
  → SPF/DKIM 실패 시 처리 정책 정의
  → none / quarantine / reject
  → 리포트 수신 주소 지정 (실패 사례 수집)
```

### 1-1. 이메일 전달 흐름 — SMTP/IMAP/POP3 완전 이해

이메일이 발신자 PC에서 수신자 받은편지함까지 도달하는 경로를 이해하면 어디서 인증이 일어나고 어디서 공격이 가능한지 명확해집니다.

```
[발신자]
   │  (1) MUA → MSA: 포트 587 (SUBMISSION, 인증 필수)
   ▼
[발신 메일 서버 — MTA]
   │  (2) DNS MX 조회: "수신 도메인의 메일 서버는?"
   │  (3) MTA → MTA: 포트 25 (SMTP, 서버간 릴레이)
   │       ← SPF 검증 발생 지점 (수신 MTA가 발신 IP 확인)
   │       ← DKIM 서명은 발신 MTA가 메일에 삽입
   ▼
[수신 메일 서버 — MTA/MDA]
   │       ← DMARC 정책 적용 (SPF/DKIM 결과 종합)
   │  (4) 스팸 필터, 바이러스 스캔
   ▼
[수신자 메일함]
   │  (5) MUA → MDA: 포트 993 (IMAP SSL) 또는 포트 995 (POP3 SSL)
   ▼
[수신자 MUA — Outlook, Thunderbird 등]

프로토콜 요약:
  SMTP (포트 25/465/587) : 메일 전송 (서버간, 클라이언트→서버)
  IMAP (포트 143/993)    : 메일 조회 — 서버에 메일 보존, 여러 기기 동기화
  POP3 (포트 110/995)    : 메일 다운로드 — 서버에서 삭제 후 로컬 저장
```

**실생활 비유:** SMTP는 우체국 직원이 편지를 배달하는 과정, IMAP은 우체국 사서함을 여러 곳에서 열어 보는 것, POP3는 우체국에서 편지를 집으로 가져와서 사서함은 비우는 것입니다.

### 1-2. 왜 SPF만으로 부족한가

```
공격 시나리오:
  발신자 헤더: From: ceo@example.com (사용자가 보는 주소)
  봉투 발신자: MAIL FROM: attacker@evil.com (SMTP 레벨)

SPF 검사 대상: 봉투 발신자 (MAIL FROM)
→ SPF가 evil.com을 허용했다면 "SPF 통과"
→ 하지만 사용자는 "ceo@example.com"에서 온 메일로 인식
→ DMARC가 없으면 이 불일치를 아무도 잡지 않음!
```

이것이 SPF + DKIM + DMARC 세 가지가 함께 작동해야 하는 이유입니다.

---

## 2. SPF 설정 및 분석

### 2-1. SPF 레코드 구조 상세 해설

```
v=spf1 ip4:203.0.113.0/24 include:_spf.google.com -all

구문 분해:
  v=spf1           → SPF 버전 1 (현재 유일한 버전)
  ip4:203.0.113.0/24 → 이 IP 대역에서 발송하면 허용
  include:_spf.google.com → Google의 SPF 레코드를 포함 (G Suite 사용 시)
  -all             → 위 목록 외 모든 발신자 거부

메커니즘:
  ip4:주소    → 특정 IPv4 허용
  ip6:주소    → 특정 IPv6 허용
  a           → 도메인의 A 레코드 IP 허용
  mx          → 도메인의 MX 서버 허용
  include:    → 다른 도메인의 SPF 포함
  all         → 나머지 모두

한정자(Qualifier):
  +all → 허용 (기본값, 권장 안 함) ← 사실상 SPF 무력화
  -all → 거부 (Fail — 가장 강함)   ← 프로덕션 권장
  ~all → 소프트 실패 (SoftFail — 수신하되 스팸 표시)
  ?all → 중립 (권장 안 함)         ← 아무 보호 없음
```

### 2-2. SPF 레코드 예시 비교표

| 조직 유형 | SPF 레코드 예시 | 설명 |
|-----------|-----------------|------|
| 단순 (자체 서버만) | `v=spf1 ip4:1.2.3.4 -all` | IP 하나만 허용 |
| Google Workspace 사용 | `v=spf1 include:_spf.google.com -all` | Google 서버 전체 허용 |
| 복합 (자체 + 외부) | `v=spf1 ip4:203.0.113.0/24 include:_spf.google.com include:sendgrid.net -all` | 혼합 |
| 잘못된 설정 | `v=spf1 +all` | 누구나 발송 가능 — 위험! |

### 2-3. SPF 조회 및 분석

SPF(Sender Policy Framework) 레코드를 조회하고 분석합니다. 허용된 발신 IP 목록을 확인하고 설정 오류나 너무 허용적인 정책을 탐지합니다.

```bash
# SPF 레코드 확인
dig TXT example.com | grep spf

# spf-tools 설치 후 SPF lookup 전개
python3 -m pip install pyspf
# 또는
nmap --script dns-check-zone <domain>

# MXToolbox 방식 수동 분석
dig TXT _spf.google.com
dig TXT example.com
```

### 2-4. SPF 우회 기법

```
1. 허용된 IP 내 다른 서버 침해 후 메일 발송
2. include: 체인에서 약한 서드파티 도메인 탈취
3. subdomain에 SPF 없는 경우 subdomain 사용
4. Header From != Envelope From 악용 (DMARC 없을 때)

탐지 방법:
  dig TXT subdomain.example.com  # SPF 없으면 취약
  → 피싱에 악용 가능
```

---

## 3. DKIM 설정 및 검증

### 3-1. DKIM 동작 원리 — 단계별 설명

DKIM은 공개키 암호화를 이용해 메일에 "디지털 도장"을 찍습니다.

```
[발신 서버 측]
1. 메일 본문과 주요 헤더의 해시(SHA-256)를 계산
2. 도메인의 개인키(비밀키)로 해시를 암호화 → 서명 생성
3. DKIM-Signature 헤더로 메일에 삽입

DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=mail;
  h=from:to:subject:date:message-id;
  bh=abc123...;  ← 본문 해시
  b=XYZ789...;   ← 서명값

[DNS에 게시]
mail._domainkey.example.com TXT "v=DKIM1; k=rsa; p=MIIBIj..."
                                                    ↑ 공개키

[수신 서버 측]
1. 메일의 DKIM-Signature 헤더에서 도메인(d=), 셀렉터(s=) 읽기
2. DNS에서 공개키 조회: mail._domainkey.example.com
3. 공개키로 서명 검증: 해시 일치 여부 확인
4. 본문/헤더가 전송 중 변조됐으면 → 검증 실패
```

**실생활 비유:** DKIM은 봉투를 밀랍으로 봉하고 도장 찍는 것과 같습니다. 도장이 깨져 있으면(해시 불일치) 누군가가 중간에 편지를 열어봤다는 증거입니다.

### 3-2. DKIM 키 생성 및 DNS 게시

OpenDKIM으로 DKIM 서명 키 쌍을 생성하고 공개키를 DNS에 게시합니다. 이메일 발신자 인증으로 스푸핑 공격을 방지합니다.

```bash
# OpenDKIM으로 키 생성
opendkim-genkey -t -s mail -d example.com
# → mail.private (개인키), mail.txt (DNS에 게시할 공개키)

# DNS에 게시할 레코드 확인
cat mail.txt
# mail._domainkey IN TXT ( "v=DKIM1; k=rsa; "
#   "p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQE..." )

# DNS에 추가 (bind zone 파일)
mail._domainkey.example.com. IN TXT "v=DKIM1; k=rsa; p=..."

# 검증
dig TXT mail._domainkey.example.com
```

### 3-3. Postfix + OpenDKIM 설정

```bash
# 설치
apt install postfix opendkim opendkim-tools

# /etc/opendkim.conf
Domain                  example.com
KeyFile                 /etc/dkimkeys/mail.private
Selector                mail
Socket                  inet:12301@localhost
UMask                   022
UserID                  opendkim

# /etc/postfix/main.cf에 milter 추가
milter_protocol = 2
milter_default_action = accept
smtpd_milters = inet:localhost:12301
non_smtpd_milters = inet:localhost:12301

systemctl restart opendkim postfix
```

### 3-4. DKIM 셀렉터(Selector) 관리 전략

```
셀렉터란: DNS 레코드에서 공개키를 구분하는 이름
  mail._domainkey.example.com  ← "mail"이 셀렉터

여러 셀렉터를 사용하는 이유:
  - 키 교체 시 무중단: 새 키(selector2)를 먼저 DNS에 등록 → 
    발송 서버를 새 키로 전환 → 구 키(mail) 삭제
  - 외부 발송 서비스 구분: google._domainkey, sendgrid._domainkey 등
  - 서비스별 독립 관리: 한 셀렉터 침해 시 다른 서비스 영향 없음

권장 키 교체 주기: 1년 (최소), 6개월 (권장)
```

---

## 4. DMARC 설정

### 4-1. DMARC 정책 모드 상세 설명

DMARC(Domain-based Message Authentication) 레코드를 설정합니다. SPF/DKIM 인증 실패 시 메일을 거부(reject)하거나 격리(quarantine)하는 정책을 정의합니다.

```
DMARC 정책 3가지:

p=none (모니터링 모드)
  → 메일 처리에 영향 없음
  → 실패한 메일을 그냥 통과시킴
  → 리포트만 수신하여 현황 파악
  → 처음 도입 시 사용: "일단 현황을 보자"

p=quarantine (격리 모드)
  → 인증 실패 메일을 스팸함/격리함으로 이동
  → 수신자는 볼 수 있지만 받은편지함에는 없음
  → 중간 단계: "의심스러운 건 격리하자"

p=reject (거부 모드)
  → 인증 실패 메일을 완전히 거부 (수신 서버가 반송)
  → 가장 강력한 보호
  → 충분한 모니터링 후 최종 목표로 설정
```

### 4-2. DMARC 정렬(Alignment) 개념

```
DMARC가 "통과"하려면 SPF 또는 DKIM이 도메인과 정렬되어야 함

SPF 정렬:
  MAIL FROM 도메인 == From 헤더 도메인
  예: MAIL FROM: user@example.com + From: user@example.com → 정렬 OK

DKIM 정렬:
  DKIM-Signature의 d= 도메인 == From 헤더 도메인
  예: d=example.com + From: user@example.com → 정렬 OK

정렬 모드 (adkim=, aspf=):
  s (strict): 도메인 완전 일치
  r (relaxed): 서브도메인도 허용 (기본값)
    → mail.example.com DKIM d= → From: example.com → 정렬 OK
```

### 4-3. DMARC 단계적 배포

```bash
# DMARC 레코드 구조
# _dmarc.example.com IN TXT "v=DMARC1; p=reject; rua=mailto:dmarc@example.com; ruf=mailto:dmarc@example.com; pct=100"

# 단계적 배포 권장:
# 1단계: none (모니터링만)
"v=DMARC1; p=none; rua=mailto:dmarc@example.com"

# 2단계: quarantine (스팸함으로)
"v=DMARC1; p=quarantine; pct=25; rua=mailto:dmarc@example.com"

# 3단계: reject (완전 차단)
"v=DMARC1; p=reject; rua=mailto:dmarc@example.com; ruf=mailto:dmarc@example.com"

# 확인
dig TXT _dmarc.example.com
```

### 4-4. DMARC 리포트 해석

```xml
<!-- DMARC 집계 리포트 (rua) 예시 — XML 형식 -->
<feedback>
  <report_metadata>
    <date_range>
      <begin>1706745600</begin>  <!-- 2024-02-01 -->
      <end>1706831999</end>
    </date_range>
  </report_metadata>
  <policy_published>
    <domain>example.com</domain>
    <p>reject</p>
  </policy_published>
  <record>
    <row>
      <source_ip>192.0.2.1</source_ip>
      <count>847</count>         <!-- 이 IP에서 847통 발송 -->
      <policy_evaluated>
        <disposition>reject</disposition>  <!-- 거부됨 -->
        <dkim>fail</dkim>
        <spf>fail</spf>
      </policy_evaluated>
    </row>
  </record>
</feedback>
```

**리포트 분석 포인트:**
- `source_ip`가 모르는 IP라면? → 허가되지 않은 발송 서버
- `dkim=fail, spf=fail`이 대량이라면? → 스푸핑 공격 시도
- `count`가 갑자기 급증? → 이메일 폭탄 또는 침해 징후

---

## 5. 메일 서버 공격 기법

### 5-1. SMTP 오픈 릴레이 탐지

오픈 릴레이(Open Relay)는 인증 없이 외부→외부 메일 전송을 허용하는 잘못된 메일 서버 설정입니다. 스팸 발송에 악용되며, Postfix에서 `smtpd_recipient_restrictions`을 올바르게 설정하여 차단합니다.

```bash
# nmap으로 SMTP 릴레이 탐지
nmap -p 25 --script smtp-open-relay <target>

# 수동 테스트
telnet mail.example.com 25
EHLO attacker.com
MAIL FROM:<attacker@attacker.com>
RCPT TO:<victim@anotherdomain.com>  # 외부 도메인으로 릴레이 시도
DATA
Subject: Test

Test
.
QUIT
```

### 5-2. SMTP 사용자 열거 (VRFY/EXPN)

SMTP VRFY/EXPN 명령으로 서버에 등록된 사용자 계정을 열거합니다. 스피어 피싱이나 브루트포스 공격의 사전 정찰 단계에 사용합니다.

```bash
# VRFY 명령으로 사용자 존재 확인
nmap -p 25 --script smtp-enum-users \
  --script-args smtp-enum-users.methods=VRFY \
  <target>

# 수동
telnet mail.example.com 25
VRFY admin
VRFY root
EXPN admins  # 그룹 멤버 열거

# smtp-user-enum 도구
smtp-user-enum -M VRFY -U /usr/share/wordlists/users.txt -t <target>
```

### 5-3. 이메일 헤더 분석 — 스푸핑 탐지 가이드

실제 수신된 이메일의 헤더를 분석하면 발신자의 실제 경로와 스푸핑 여부를 파악할 수 있습니다.

```
이메일 헤더 읽는 순서: 아래→위 (가장 아래가 최초 발신지)

Received: from mail.example.com (mail.example.com [203.0.113.5])
          by mx.google.com with ESMTPS id abc123
          for <victim@gmail.com>
          (TLS 확인: 정상)

Authentication-Results: mx.google.com;
       dkim=pass header.i=@example.com      ← DKIM 통과
       spf=pass smtp.mailfrom=example.com   ← SPF 통과
       dmarc=pass (p=REJECT) header.from=example.com ← DMARC 통과

From: CEO <ceo@example.com>
Reply-To: attacker@evil.com    ← 주의! 회신 주소가 다름
X-Originating-IP: 203.0.113.5
Message-ID: <unique-id@mail.example.com>

피싱 이메일 주요 지표:
1. Reply-To 주소가 From과 다른 도메인
2. Received 경로에 알 수 없는 서버 포함
3. Authentication-Results에 dmarc=fail, spf=fail
4. Message-ID 도메인이 From 도메인과 다름
5. X-Mailer에 알 수 없는 발송 도구 표시
6. 발신 시각이 수신자 시간대와 매우 다름 (심야 등)
```

### 5-4. 이메일 헤더 위조 (스푸핑)

Python smtplib으로 발신자 주소를 위조한 이메일을 전송합니다. SPF/DKIM/DMARC가 없거나 잘못 설정된 서버에서 스푸핑이 가능합니다.

```python
import smtplib
import argparse
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def send_spoofed(
    smtp_host: str, smtp_port: int,
    from_display: str, from_envelope: str,
    to_addr: str, subject: str, body: str
) -> None:
    """SPF/DKIM/DMARC 없는 도메인 스푸핑 테스트 (허가된 환경 전용)"""
    msg = MIMEMultipart()
    msg["From"]    = from_display   # 표시 주소 (위조 가능)
    msg["To"]      = to_addr
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as smtp:
        # envelope from과 header from을 다르게 설정
        smtp.sendmail(from_envelope, [to_addr], msg.as_string())
        print(f"[+] 발송 완료: {from_display} → {to_addr}")

def main() -> None:
    parser = argparse.ArgumentParser(description="메일 스푸핑 테스트 (허가된 환경 전용)")
    parser.add_argument("--smtp",     required=True)
    parser.add_argument("--port",     type=int, default=25)
    parser.add_argument("--from-display",  required=True)
    parser.add_argument("--from-envelope", required=True)
    parser.add_argument("--to",       required=True)
    parser.add_argument("--subject",  default="Test")
    parser.add_argument("--body",     default="Test email")
    args = parser.parse_args()

    send_spoofed(args.smtp, args.port,
                 args.from_display, args.from_envelope,
                 args.to, args.subject, args.body)

if __name__ == "__main__":
    main()
```

### 5-5. 피싱 이메일 지표 (IOC) 체크리스트

```
기술적 지표:
  [ ] SPF fail / dmarc fail in Authentication-Results
  [ ] Reply-To 도메인이 From 도메인과 다름
  [ ] Received 헤더의 발신 IP가 SPF 레코드에 없음
  [ ] Message-ID 없음 또는 의심스러운 형식
  [ ] X-Originating-IP가 외국 IP (예상치 못한 국가)

내용적 지표:
  [ ] 긴급함 강조 ("즉시", "오늘까지", "계정 잠금 예정")
  [ ] 링크 URL이 표시된 텍스트와 다름 (호버로 확인)
  [ ] 첨부파일 확장자 위장 (invoice.pdf.exe 등)
  [ ] 맞춤법 오류, 어색한 한국어
  [ ] 로고/브랜딩이 미세하게 다름

행동 유도:
  [ ] 자격증명 입력 요구
  [ ] 첨부파일 실행 유도
  [ ] 전화 콜백 요청
  [ ] 개인정보/금융정보 요청
```

### 5-6. qmail 보안 설정 (레거시 서버)

레거시 qmail 서버의 SPF 패치 적용 여부를 확인합니다. 구버전 메일 서버는 최신 이메일 보안 표준을 지원하지 않는 경우가 많습니다.

```bash
# qmail SPF 패치 확인
qmail --version | grep spf

# qmail-smtpd 실행 계정 확인 (root로 실행되면 위험)
ps aux | grep qmail-smtpd

# /var/qmail/control/ 주요 설정 파일
cat /var/qmail/control/rcpthosts    # 허용 수신 도메인
cat /var/qmail/control/locals       # 로컬 도메인
cat /var/qmail/control/relayclients # 릴레이 허용 IP

# 오픈 릴레이 방지: rcpthosts에 없는 도메인 수신 거부 확인
echo "외부@anotherdomain.com" | /var/qmail/bin/qmail-inject
```

---

## 6. 도메인별 SPF/DKIM/DMARC 종합 검증 Python 도구

도메인의 이메일 보안 설정 전체를 자동으로 조회하고 분석하는 완전한 CLI 도구입니다.

```python
#!/usr/bin/env python3
"""
mail_security_checker.py — 도메인 이메일 보안 종합 점검 도구

사용법:
  python3 mail_security_checker.py example.com
  python3 mail_security_checker.py example.com --dkim-selector mail
  python3 mail_security_checker.py example.com --json-output

의존성:
  pip install dnspython
"""

import argparse
import json
import sys
import smtplib
import ssl
from dataclasses import dataclass, field
from typing import Optional

try:
    import dns.resolver
    import dns.exception
except ImportError:
    print("[!] dnspython 필요: pip install dnspython", file=sys.stderr)
    sys.exit(1)


# ── 데이터 모델 ────────────────────────────────────────────────────────────────

@dataclass
class SpfResult:
    record: str = ""
    found: bool = False
    qualifier: str = ""       # +all, -all, ~all, ?all
    mechanisms: list[str] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)
    score: int = 0            # 0~30


@dataclass
class DkimResult:
    selector: str = ""
    record: str = ""
    found: bool = False
    key_bits: int = 0
    issues: list[str] = field(default_factory=list)
    score: int = 0            # 0~30


@dataclass
class DmarcResult:
    record: str = ""
    found: bool = False
    policy: str = ""          # none / quarantine / reject
    pct: int = 100
    rua: str = ""
    ruf: str = ""
    issues: list[str] = field(default_factory=list)
    score: int = 0            # 0~40


@dataclass
class MailSecReport:
    domain: str
    spf: SpfResult = field(default_factory=SpfResult)
    dkim: DkimResult = field(default_factory=DkimResult)
    dmarc: DmarcResult = field(default_factory=DmarcResult)
    mx_hosts: list[str] = field(default_factory=list)
    starttls_supported: bool = False
    open_relay: bool = False
    total_score: int = 0      # 0~100
    grade: str = "F"


# ── DNS 조회 헬퍼 ───────────────────────────────────────────────────────────────

def resolve_txt(fqdn: str) -> list[str]:
    """TXT 레코드 조회. 실패 시 빈 리스트 반환."""
    try:
        answers = dns.resolver.resolve(fqdn, "TXT", lifetime=5)
        results = []
        for rdata in answers:
            text = b"".join(rdata.strings).decode("utf-8", errors="replace")
            results.append(text)
        return results
    except (dns.exception.DNSException, Exception):
        return []


def resolve_mx(domain: str) -> list[str]:
    """MX 레코드 조회. 우선순위 순으로 정렬."""
    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=5)
        sorted_mx = sorted(answers, key=lambda r: r.preference)
        return [str(r.exchange).rstrip(".") for r in sorted_mx]
    except Exception:
        return []


# ── SPF 분석 ───────────────────────────────────────────────────────────────────

def analyze_spf(domain: str) -> SpfResult:
    result = SpfResult()
    txt_records = resolve_txt(domain)

    for txt in txt_records:
        if txt.startswith("v=spf1"):
            result.found = True
            result.record = txt
            break

    if not result.found:
        result.issues.append("SPF 레코드 없음 — 이메일 스푸핑에 무방비")
        result.score = 0
        return result

    # 메커니즘 파싱
    parts = result.record.split()
    result.mechanisms = parts[1:]

    # 한정자(qualifier) 확인
    if "-all" in result.record:
        result.qualifier = "-all"
        result.score = 30
    elif "~all" in result.record:
        result.qualifier = "~all"
        result.score = 20
        result.issues.append("~all (SoftFail) — 스팸 표시만, 거부 아님. -all 권장")
    elif "+all" in result.record:
        result.qualifier = "+all"
        result.score = 0
        result.issues.append("[위험] +all — 모든 서버에서 발송 허용. 즉시 수정 필요")
    elif "?all" in result.record:
        result.qualifier = "?all"
        result.score = 5
        result.issues.append("?all (중립) — 보호 없음. -all 또는 ~all로 변경 필요")
    else:
        result.score = 10
        result.issues.append("all 지정자 없음 — 명시적 정책 필요")

    # include 체인 깊이 (10개 제한)
    include_count = result.record.count("include:")
    if include_count > 7:
        result.issues.append(f"include 참조 {include_count}개 — DNS 조회 한도(10) 초과 위험")

    return result


# ── DKIM 분석 ──────────────────────────────────────────────────────────────────

def analyze_dkim(domain: str, selector: str = "mail") -> DkimResult:
    result = DkimResult(selector=selector)
    fqdn = f"{selector}._domainkey.{domain}"
    txt_records = resolve_txt(fqdn)

    for txt in txt_records:
        if "v=DKIM1" in txt or "k=rsa" in txt or "p=" in txt:
            result.found = True
            result.record = txt
            break

    if not result.found:
        result.issues.append(
            f"DKIM 레코드 없음 ({fqdn}) — "
            f"다른 셀렉터로 재시도: --dkim-selector default"
        )
        result.score = 0
        return result

    # 공개키 길이 추정 (p= 값의 base64 길이로)
    p_start = result.record.find("p=")
    if p_start != -1:
        p_value = result.record[p_start + 2:].split(";")[0].strip()
        # RSA-2048 공개키 base64 길이는 약 392자
        key_len = len(p_value)
        if key_len < 200:
            result.key_bits = 1024
            result.issues.append("RSA-1024 키 추정 — 2048비트로 교체 권장")
            result.score = 15
        else:
            result.key_bits = 2048
            result.score = 30

    # 키가 취소됐는지 확인 (p= 비어있으면 취소됨)
    if "p=;" in result.record or result.record.endswith("p="):
        result.issues.append("DKIM 키 취소됨 (p= 비어있음)")
        result.score = 0

    return result


# ── DMARC 분석 ─────────────────────────────────────────────────────────────────

def analyze_dmarc(domain: str) -> DmarcResult:
    result = DmarcResult()
    fqdn = f"_dmarc.{domain}"
    txt_records = resolve_txt(fqdn)

    for txt in txt_records:
        if "v=DMARC1" in txt:
            result.found = True
            result.record = txt
            break

    if not result.found:
        result.issues.append("DMARC 레코드 없음 — SPF/DKIM 실패해도 메일 통과")
        result.score = 0
        return result

    # 정책 파싱
    for part in result.record.split(";"):
        part = part.strip()
        if part.startswith("p="):
            result.policy = part[2:].strip()
        elif part.startswith("pct="):
            try:
                result.pct = int(part[4:])
            except ValueError:
                pass
        elif part.startswith("rua="):
            result.rua = part[4:].strip()
        elif part.startswith("ruf="):
            result.ruf = part[4:].strip()

    # 점수 및 이슈
    if result.policy == "reject":
        result.score = 40
    elif result.policy == "quarantine":
        result.score = 25
        result.issues.append("p=quarantine — 격리만, 완전 차단 아님. reject 권장")
    elif result.policy == "none":
        result.score = 10
        result.issues.append("p=none — 모니터링 모드, 스푸핑 메일 차단 안 됨")
    else:
        result.score = 0
        result.issues.append(f"알 수 없는 정책: {result.policy}")

    if result.pct < 100:
        result.issues.append(f"pct={result.pct} — 정책이 {result.pct}%에만 적용됨")

    if not result.rua:
        result.issues.append("rua 없음 — 집계 리포트 수신 불가 (모니터링 불가)")

    return result


# ── SMTP 검사 ──────────────────────────────────────────────────────────────────

def check_smtp(mx_host: str, timeout: int = 8) -> tuple[bool, bool]:
    """(starttls_지원, 오픈릴레이) 반환"""
    starttls = False
    relay = False
    try:
        with smtplib.SMTP(mx_host, 25, timeout=timeout) as smtp:
            ehlo_resp = smtp.ehlo()[1].decode("utf-8", errors="replace").lower()
            starttls = "starttls" in ehlo_resp

            # 오픈 릴레이 테스트
            smtp.mail("probe@test-spoof.invalid")
            code, _ = smtp.rcpt("test@external-domain.invalid")
            relay = (code == 250)
    except smtplib.SMTPRecipientsRefused:
        relay = False  # 정상적으로 거부됨
    except Exception:
        pass
    return starttls, relay


# ── 종합 보고 ──────────────────────────────────────────────────────────────────

def grade_score(score: int) -> str:
    if score >= 90:
        return "A"
    elif score >= 75:
        return "B"
    elif score >= 60:
        return "C"
    elif score >= 40:
        return "D"
    return "F"


def audit_domain(domain: str, dkim_selector: str = "mail") -> MailSecReport:
    report = MailSecReport(domain=domain)

    print(f"[*] SPF 분석 중...")
    report.spf = analyze_spf(domain)

    print(f"[*] DKIM 분석 중 (셀렉터: {dkim_selector})...")
    report.dkim = analyze_dkim(domain, dkim_selector)

    print(f"[*] DMARC 분석 중...")
    report.dmarc = analyze_dmarc(domain)

    print(f"[*] MX 서버 조회 중...")
    report.mx_hosts = resolve_mx(domain)

    if report.mx_hosts:
        print(f"[*] SMTP 검사 중: {report.mx_hosts[0]}...")
        report.starttls_supported, report.open_relay = check_smtp(report.mx_hosts[0])

    report.total_score = report.spf.score + report.dkim.score + report.dmarc.score
    report.grade = grade_score(report.total_score)

    return report


def print_report(report: MailSecReport) -> None:
    border = "=" * 60
    print(f"\n{border}")
    print(f"  이메일 보안 감사 결과: {report.domain}")
    print(f"  총점: {report.total_score}/100  등급: {report.grade}")
    print(border)

    # MX 서버
    if report.mx_hosts:
        print(f"\nMX 서버: {', '.join(report.mx_hosts[:3])}")
    print(f"STARTTLS: {'지원' if report.starttls_supported else '미지원 [!]'}")
    print(f"오픈 릴레이: {'취약 [!!]' if report.open_relay else '차단됨'}")

    # SPF
    print(f"\n[SPF] 점수: {report.spf.score}/30")
    if report.spf.found:
        print(f"  레코드: {report.spf.record[:80]}...")
        print(f"  한정자: {report.spf.qualifier}")
    for issue in report.spf.issues:
        print(f"  → {issue}")

    # DKIM
    print(f"\n[DKIM] 점수: {report.dkim.score}/30  셀렉터: {report.dkim.selector}")
    if report.dkim.found:
        print(f"  키 크기: ~{report.dkim.key_bits}비트")
    for issue in report.dkim.issues:
        print(f"  → {issue}")

    # DMARC
    print(f"\n[DMARC] 점수: {report.dmarc.score}/40")
    if report.dmarc.found:
        print(f"  정책: p={report.dmarc.policy}  pct={report.dmarc.pct}%")
        if report.dmarc.rua:
            print(f"  집계 리포트: {report.dmarc.rua}")
    for issue in report.dmarc.issues:
        print(f"  → {issue}")

    # 권고사항
    all_issues = (
        report.spf.issues + report.dkim.issues +
        report.dmarc.issues
    )
    if not all_issues and not report.open_relay:
        print(f"\n[+] 주요 이메일 보안 설정 양호")
    else:
        print(f"\n[권고사항 우선순위]")
        if report.open_relay:
            print("  1순위: 오픈 릴레이 즉시 차단 (Postfix smtpd_recipient_restrictions)")
        if not report.spf.found:
            print("  1순위: SPF 레코드 추가")
        if not report.dmarc.found:
            print("  1순위: DMARC 레코드 추가 (p=none으로 시작)")
        if not report.dkim.found:
            print("  2순위: DKIM 서명 설정 (opendkim)")
        if not report.starttls_supported:
            print("  2순위: STARTTLS 활성화 (평문 전송 위험)")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="도메인 이메일 보안 종합 점검",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
사용 예시:
  python3 mail_security_checker.py example.com
  python3 mail_security_checker.py example.com --dkim-selector google
  python3 mail_security_checker.py example.com --json-output
        """,
    )
    parser.add_argument("domain", help="검사할 도메인 (예: example.com)")
    parser.add_argument(
        "--dkim-selector", default="mail",
        help="DKIM 셀렉터 (기본: mail). 'default', 'google', 'k1' 등 시도"
    )
    parser.add_argument(
        "--json-output", action="store_true",
        help="결과를 JSON으로 출력"
    )
    args = parser.parse_args()

    report = audit_domain(args.domain, args.dkim_selector)

    if args.json_output:
        import dataclasses
        print(json.dumps(dataclasses.asdict(report), indent=2, ensure_ascii=False))
    else:
        print_report(report)

    # CI/CD 연동: 점수 60 미만이면 비정상 종료
    sys.exit(0 if report.total_score >= 60 else 1)


if __name__ == "__main__":
    main()
```

---

## 7. 메일 서버 보안 점검 자동화 (기존 버전)

메일 서버 보안 설정(SPF, DKIM, DMARC)을 자동으로 점검합니다. DNS 레코드를 조회하여 각 보안 메커니즘의 설정 상태를 확인합니다.

```python
import dns.resolver
import smtplib
import ssl
import argparse
from dataclasses import dataclass, field

@dataclass
class MailSecResult:
    domain: str
    spf: str = ""
    dmarc: str = ""
    dkim_selector: str = ""
    open_relay: bool = False
    starttls: bool = False
    issues: list[str] = field(default_factory=list)

def check_txt_record(domain: str, prefix: str = "") -> str:
    target = f"{prefix}.{domain}" if prefix else domain
    try:
        answers = dns.resolver.resolve(target, "TXT", lifetime=5)
        for r in answers:
            text = b"".join(r.strings).decode()
            if "v=spf1" in text or "v=DMARC1" in text or "v=DKIM1" in text:
                return text
    except Exception:
        pass
    return ""

def check_smtp(mx_host: str) -> tuple[bool, bool]:
    """릴레이, STARTTLS 여부 반환"""
    relay, starttls = False, False
    try:
        with smtplib.SMTP(mx_host, 25, timeout=10) as smtp:
            caps = smtp.ehlo()[1].decode().lower()
            starttls = "starttls" in caps

            smtp.mail("test@attacker.com")
            code, _ = smtp.rcpt("test@external.com")
            relay = (code == 250)
    except Exception:
        pass
    return relay, starttls

def audit_mail_security(domain: str) -> MailSecResult:
    result = MailSecResult(domain=domain)

    result.spf   = check_txt_record(domain)
    result.dmarc = check_txt_record(domain, "_dmarc")

    if not result.spf:
        result.issues.append("SPF 레코드 없음 — 이메일 스푸핑 취약")
    elif "-all" not in result.spf and "~all" not in result.spf:
        result.issues.append("SPF ?all / +all — 릴레이 차단 미흡")

    if not result.dmarc:
        result.issues.append("DMARC 없음 — 스푸핑 정책 미설정")
    elif "p=none" in result.dmarc:
        result.issues.append("DMARC p=none — 모니터링만, 차단 없음")

    try:
        mx_records = dns.resolver.resolve(domain, "MX", lifetime=5)
        mx_host = str(sorted(mx_records, key=lambda r: r.preference)[0].exchange).rstrip(".")
        relay, starttls = check_smtp(mx_host)
        result.open_relay = relay
        result.starttls   = starttls

        if relay:
            result.issues.append(f"오픈 릴레이 감지: {mx_host}")
        if not starttls:
            result.issues.append("STARTTLS 미지원 — 평문 전송")
    except Exception as e:
        result.issues.append(f"MX 조회 실패: {e}")

    return result

def main() -> None:
    parser = argparse.ArgumentParser(description="메일 서버 보안 점검")
    parser.add_argument("domain")
    args = parser.parse_args()

    r = audit_mail_security(args.domain)
    print(f"\n[메일 보안 감사] {r.domain}")
    print(f"  SPF:     {r.spf or '없음'}")
    print(f"  DMARC:   {r.dmarc or '없음'}")
    print(f"  STARTTLS: {'지원' if r.starttls else '미지원'}")
    print(f"  릴레이:   {'취약' if r.open_relay else '차단됨'}")
    if r.issues:
        print("\n  [!] 문제점:")
        for i in r.issues:
            print(f"    → {i}")
    else:
        print("\n  [+] 주요 보안 설정 양호")

if __name__ == "__main__":
    main()
```

---

## 8. 메일 서버 보안 강화 체크리스트

| 카테고리 | 항목 | 우선순위 | 설명 |
|----------|------|----------|------|
| SPF | v=spf1 레코드 존재 | 필수 | 없으면 스푸핑 완전 무방비 |
| SPF | -all 사용 | 권장 | ~all보다 강력한 차단 |
| SPF | include 체인 10개 미만 | 필수 | DNS 조회 한도 초과 시 fail |
| DKIM | 셀렉터 설정 및 DNS 등록 | 필수 | 본문 변조 탐지 불가 |
| DKIM | RSA 2048비트 이상 | 필수 | 1024비트는 취약 |
| DKIM | 연 1회 키 교체 | 권장 | 유출 시 피해 최소화 |
| DMARC | _dmarc 레코드 존재 | 필수 | SPF/DKIM 효과를 완성 |
| DMARC | p=none → quarantine → reject 단계 진행 | 권장 | 단계적 강화 |
| DMARC | rua 주소 설정 | 권장 | 리포트 없이는 현황 파악 불가 |
| SMTP | STARTTLS 지원 | 필수 | 평문 전송 차단 |
| SMTP | 오픈 릴레이 차단 | 필수 | 스팸 발송지로 악용 방지 |
| SMTP | VRFY/EXPN 비활성화 | 권장 | 사용자 열거 방지 |
| 일반 | 서브도메인 SPF 설정 | 권장 | 서브도메인 스푸핑 방지 |
| 일반 | MTA-STS 설정 | 권장 | 다운그레이드 공격 방지 |

---

<!-- detect-validate-24 -->
## 메일 스푸핑·릴레이 탐지와 방어 검증

메일 위장은 *SPF/DKIM/DMARC 부재·개방 릴레이·표시이름 위장*을 노린다. 방어자는 **자체 도메인이 위장 메일을 거부·격리하는가**를 검증해야 한다. 검증은 **소유 도메인/메일서버**에서만.

### 공격 → 노리는 약점 → 1차 통제(방어자) → 탐지 신호

| 기법 | 노리는 약점 | 1차 통제(방어자) | 탐지 신호 |
|---|---|---|---|
| 발신자 위장 | SPF/DMARC 미적용 | DMARC p=reject | DMARC 실패 리포트 |
| 개방 릴레이 | 인증 없는 중계 | 인증 강제·릴레이 차단 | 외부→외부 중계 시도 |
| 헤더 인젝션 | 미검증 입력 | 헤더 검증·인코딩 | 비정상 헤더 필드 |
| 표시이름/동형문자 위장 | 시각 신뢰 | 외부 배너·동형 탐지 | 유사 도메인 발신 |

### 방어 검증 (직접 확인)

```bash
# 1) 자체 도메인 SPF/DMARC 정책 강도 점검(소유 도메인) — none/누락이면 위장 차단 불가
dig +short TXT example.com | grep -i spf; dig +short TXT _dmarc.example.com | grep -iE "p=reject|p=quarantine"
# 2) 개방 릴레이 여부 점검(소유 메일서버) — 외부→외부 중계가 거부돼야 함
swaks --to ext@elsewhere.com --from spoof@notyours.com --server your.mail.server 2>&1 | grep -E "550|554|Relay" | head
```

> 메일 방어는 *위장이 실제로 거부되는가*다 — "메일 서버 있다"와 "SPF/DKIM/DMARC가 p=reject로 위장을 격리한다"는 다르다. 소유 도메인의 DMARC 정책과 릴레이 거부를 직접 확인한다([[17_Red_Team_Operations]], [[33_OSINT_Social_Engineering]], [[13_SOC_Blue_Team]]).

---

<a name="english"></a>

# Mail Server Security — SPF/DKIM/DMARC and Attack Techniques

## 1. Email Authentication Overview

Email was designed in the early days of the internet without any mechanism to verify "who sent it." The sender address is like a name handwritten on an envelope — anyone can write anything. SPF, DKIM, and DMARC are standards introduced incrementally over decades to solve this problem.

```
Email Authentication Three Layers:

SPF (Sender Policy Framework):
  - DNS TXT record listing authorized sending IP addresses
  - Receiving server checks if sender IP is in SPF record
  - v=spf1 ip4:192.168.1.0/24 include:_spf.google.com ~all

DKIM (DomainKeys Identified Mail):
  - Cryptographic signature added to email header
  - Public key stored in DNS, private key used to sign
  - Verifies email wasn't tampered in transit

DMARC (Domain-based Message Authentication, Reporting & Conformance):
  - Policy for handling SPF/DKIM failures
  - Three policies: none (monitor), quarantine, reject
  - Provides reporting on authentication failures

Attack Protection:
  SPF: Prevents IP spoofing
  DKIM: Prevents content tampering
  DMARC: Enforces policy + reporting
```

### 1-1. Email Delivery Flow — SMTP/IMAP/POP3 Explained

Understanding the path an email takes from sender to recipient's inbox makes it clear where authentication happens and where attacks are possible.

```
[Sender]
   │  (1) MUA → MSA: Port 587 (SUBMISSION, authentication required)
   ▼
[Sending Mail Server — MTA]
   │  (2) DNS MX lookup: "Which server handles mail for this domain?"
   │  (3) MTA → MTA: Port 25 (SMTP, server-to-server relay)
   │       ← SPF verification occurs here (receiving MTA checks sending IP)
   │       ← DKIM signature is inserted by the sending MTA
   ▼
[Receiving Mail Server — MTA/MDA]
   │       ← DMARC policy applied (combines SPF/DKIM results)
   │  (4) Spam filter, virus scan
   ▼
[Recipient Mailbox]
   │  (5) MUA → MDA: Port 993 (IMAP SSL) or Port 995 (POP3 SSL)
   ▼
[Recipient MUA — Outlook, Thunderbird, etc.]

Protocol Summary:
  SMTP (port 25/465/587) : Mail transmission (server-to-server, client-to-server)
  IMAP (port 143/993)    : Mail retrieval — preserves mail on server, multi-device sync
  POP3 (port 110/995)    : Mail download — removes from server, stores locally
```

**Real-world analogy:** SMTP is like a postal worker delivering letters, IMAP is like accessing a P.O. box from multiple locations, and POP3 is like taking your letters home and emptying the box.

### 1-2. Why SPF Alone Is Insufficient

```
Attack Scenario:
  Display header: From: ceo@example.com (what the user sees)
  Envelope sender: MAIL FROM: attacker@evil.com (SMTP level)

SPF checks: The envelope sender (MAIL FROM)
→ If SPF allows evil.com, result is "SPF pass"
→ But the user sees mail from "ceo@example.com"
→ Without DMARC, nobody catches this mismatch!
```

This is why all three — SPF + DKIM + DMARC — must work together.

---

## 2. SPF Configuration and Testing

### SPF Record Structure Explained

```
v=spf1 ip4:203.0.113.0/24 include:_spf.google.com -all

Breakdown:
  v=spf1              → SPF version 1 (the only version)
  ip4:203.0.113.0/24  → Allow sending from this IP range
  include:_spf.google.com → Include Google's SPF (for G Suite)
  -all                → Reject all other senders

Mechanisms:
  ip4:addr    → Allow specific IPv4 address/range
  ip6:addr    → Allow specific IPv6 address/range
  a           → Allow domain's A record IP
  mx          → Allow domain's MX servers
  include:    → Include another domain's SPF
  all         → Match everything else

Qualifiers:
  +all → Pass (default, NOT recommended) ← effectively disables SPF
  -all → Fail (reject — strongest)        ← recommended for production
  ~all → SoftFail (accept but mark spam)
  ?all → Neutral (not recommended)        ← no protection at all
```

### SPF Record Comparison Table

| Organization Type | SPF Record Example | Notes |
|-------------------|-------------------|-------|
| Simple (own server only) | `v=spf1 ip4:1.2.3.4 -all` | Single IP allowed |
| Using Google Workspace | `v=spf1 include:_spf.google.com -all` | All Google servers allowed |
| Hybrid (own + external) | `v=spf1 ip4:203.0.113.0/24 include:_spf.google.com include:sendgrid.net -all` | Mixed |
| Misconfigured | `v=spf1 +all` | Anyone can send — dangerous! |

```bash
# Check SPF record
dig TXT example.com | grep spf

# Common SPF record formats
v=spf1 ip4:192.168.1.0/24 include:_spf.google.com ~all

# Test SPF validity
pip install pyspf
python3 -c "import spf; print(spf.check2('1.2.3.4', 'test@example.com', 'example.com'))"
```

---

## 3. DKIM Configuration — Step-by-Step

### How DKIM Works

DKIM uses public-key cryptography to place a "digital seal" on emails.

```
[Sending Server Side]
1. Calculate hash (SHA-256) of email body and key headers
2. Encrypt hash with domain's private key → creates signature
3. Insert into email as DKIM-Signature header

DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=mail;
  h=from:to:subject:date:message-id;
  bh=abc123...;  ← body hash
  b=XYZ789...;   ← signature value

[DNS Publication]
mail._domainkey.example.com TXT "v=DKIM1; k=rsa; p=MIIBIj..."
                                                    ↑ public key

[Receiving Server Side]
1. Read domain (d=) and selector (s=) from DKIM-Signature header
2. Look up public key in DNS: mail._domainkey.example.com
3. Verify signature with public key: check hash match
4. If body/headers were modified in transit → verification fails
```

**Real-world analogy:** DKIM is like sealing an envelope with wax and stamping it. If the seal is broken (hash mismatch), it's evidence someone opened the letter in transit.

```bash
# Check DKIM record
dig TXT default._domainkey.example.com

# DKIM public key record format:
v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3...

# Generate DKIM key pair
openssl genrsa -out dkim_private.pem 2048
openssl rsa -in dkim_private.pem -pubout -out dkim_public.pem

# DNS record (publish public key):
# default._domainkey.example.com TXT "v=DKIM1; k=rsa; p=<base64-public-key>"

# Test DKIM signing
# opendkim-testkey -d example.com -s default -vvv
```

---

## 4. DMARC Configuration — Policy Modes Explained

### DMARC Policy Modes

```
Three DMARC policy levels:

p=none (Monitoring mode)
  → No action taken on mail delivery
  → Failing emails pass through anyway
  → Reports are collected to understand current state
  → Use first: "Let's see what's happening"

p=quarantine (Quarantine mode)
  → Authentication-failing emails go to spam/quarantine folder
  → Recipients can still find them, but not in inbox
  → Middle step: "Let's quarantine suspicious ones"

p=reject (Reject mode)
  → Authentication-failing emails are completely rejected
  → Most powerful protection
  → Ultimate goal after sufficient monitoring
```

### DMARC Alignment Explained

```
For DMARC to "pass," SPF or DKIM must align with the domain:

SPF alignment:
  MAIL FROM domain == From header domain
  Example: MAIL FROM: user@example.com + From: user@example.com → Aligned

DKIM alignment:
  DKIM-Signature d= domain == From header domain
  Example: d=example.com + From: user@example.com → Aligned

Alignment modes (adkim=, aspf=):
  s (strict): exact domain match required
  r (relaxed): subdomains allowed (default)
    → DKIM d=mail.example.com → From: example.com → OK (relaxed)
```

```bash
# Check DMARC record
dig TXT _dmarc.example.com

# DMARC record example:
v=DMARC1; p=reject; rua=mailto:dmarc@example.com; ruf=mailto:forensics@example.com; pct=100

# Parameters:
# p=none       - Monitor only, no action
# p=quarantine - Mark as spam
# p=reject     - Reject email
# rua=         - Aggregate report recipient
# ruf=         - Forensic report recipient
# pct=         - Percentage to apply policy to
```

### DMARC Aggregate Report Interpretation

```xml
<!-- DMARC aggregate report (rua) — XML format -->
<feedback>
  <policy_published>
    <domain>example.com</domain>
    <p>reject</p>
  </policy_published>
  <record>
    <row>
      <source_ip>192.0.2.1</source_ip>
      <count>847</count>          <!-- 847 messages from this IP -->
      <policy_evaluated>
        <disposition>reject</disposition>
        <dkim>fail</dkim>
        <spf>fail</spf>
      </policy_evaluated>
    </row>
  </record>
</feedback>
```

**Key analysis points:**
- Unknown `source_ip`? → Unauthorized sending server
- Large count of `dkim=fail, spf=fail`? → Spoofing attack attempts
- Sudden spike in `count`? → Email bomb or compromise indicator

---

## 5. Email Spoofing Attack Detection

### Phishing Email Header Analysis Guide

```
Reading email headers — bottom to top (bottom is the original sender):

Received: from mail.example.com (mail.example.com [203.0.113.5])
          by mx.google.com with ESMTPS id abc123

Authentication-Results: mx.google.com;
       dkim=pass header.i=@example.com
       spf=pass smtp.mailfrom=example.com
       dmarc=pass (p=REJECT) header.from=example.com

From: CEO <ceo@example.com>
Reply-To: attacker@evil.com    ← Warning! Reply address differs
X-Originating-IP: 203.0.113.5
Message-ID: <unique-id@mail.example.com>

Phishing email indicators:
1. Reply-To domain differs from From domain
2. Unknown servers in Received chain
3. Authentication-Results shows dmarc=fail, spf=fail
4. Message-ID domain differs from From domain
5. Unknown sending tools in X-Mailer
6. Send time very different from recipient's timezone
```

```python
#!/usr/bin/env python3
"""Email security configuration checker"""
import dns.resolver
import sys

def check_spf(domain: str) -> dict:
    """Check SPF record"""
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            txt = str(rdata).strip('"')
            if txt.startswith('v=spf1'):
                return {"found": True, "record": txt, 
                        "issues": check_spf_issues(txt)}
        return {"found": False, "issues": ["No SPF record found"]}
    except Exception as e:
        return {"found": False, "error": str(e)}

def check_spf_issues(spf: str) -> list:
    issues = []
    if '+all' in spf:
        issues.append("CRITICAL: +all allows any server to send")
    if '?all' in spf:
        issues.append("WARNING: ?all is neutral, provides no protection")
    if '~all' in spf and '-all' not in spf:
        issues.append("INFO: ~all softfail; consider -all for stricter policy")
    return issues

def check_dmarc(domain: str) -> dict:
    """Check DMARC record"""
    try:
        answers = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
        for rdata in answers:
            txt = str(rdata).strip('"')
            if 'v=DMARC1' in txt:
                return {"found": True, "record": txt,
                        "issues": check_dmarc_issues(txt)}
        return {"found": False, "issues": ["No DMARC record found"]}
    except Exception as e:
        return {"found": False, "error": str(e)}

def check_dmarc_issues(dmarc: str) -> list:
    issues = []
    if 'p=none' in dmarc:
        issues.append("WARNING: p=none only monitors, no enforcement")
    if 'rua=' not in dmarc:
        issues.append("INFO: No aggregate report address configured")
    return issues

def check_domain_security(domain: str):
    print(f"\n=== Email Security Check: {domain} ===")
    
    for check_name, check_func in [("SPF", check_spf), ("DMARC", check_dmarc)]:
        result = check_func(domain)
        status = "[+]" if result.get("found") else "[-]"
        print(f"\n{status} {check_name}: {result.get('record', 'Not found')}")
        for issue in result.get("issues", []):
            print(f"    → {issue}")

if __name__ == "__main__":
    domain = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    check_domain_security(domain)
```

---

## 6. Comprehensive SPF/DKIM/DMARC Audit Tool (Python)

```python
#!/usr/bin/env python3
"""
mail_security_checker.py — Comprehensive email security audit tool

Usage:
  python3 mail_security_checker.py example.com
  python3 mail_security_checker.py example.com --dkim-selector mail
  python3 mail_security_checker.py example.com --json-output

Dependencies:
  pip install dnspython
"""

import argparse
import json
import sys
import smtplib
from dataclasses import dataclass, field
from typing import Optional

try:
    import dns.resolver
    import dns.exception
except ImportError:
    print("[!] dnspython required: pip install dnspython", file=sys.stderr)
    sys.exit(1)


@dataclass
class SpfResult:
    record: str = ""
    found: bool = False
    qualifier: str = ""
    mechanisms: list[str] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)
    score: int = 0


@dataclass
class DkimResult:
    selector: str = ""
    record: str = ""
    found: bool = False
    key_bits: int = 0
    issues: list[str] = field(default_factory=list)
    score: int = 0


@dataclass
class DmarcResult:
    record: str = ""
    found: bool = False
    policy: str = ""
    pct: int = 100
    rua: str = ""
    ruf: str = ""
    issues: list[str] = field(default_factory=list)
    score: int = 0


@dataclass
class MailSecReport:
    domain: str
    spf: SpfResult = field(default_factory=SpfResult)
    dkim: DkimResult = field(default_factory=DkimResult)
    dmarc: DmarcResult = field(default_factory=DmarcResult)
    mx_hosts: list[str] = field(default_factory=list)
    starttls_supported: bool = False
    open_relay: bool = False
    total_score: int = 0
    grade: str = "F"


def resolve_txt(fqdn: str) -> list[str]:
    """Resolve TXT records. Returns empty list on failure."""
    try:
        answers = dns.resolver.resolve(fqdn, "TXT", lifetime=5)
        return [
            b"".join(rdata.strings).decode("utf-8", errors="replace")
            for rdata in answers
        ]
    except Exception:
        return []


def analyze_spf(domain: str) -> SpfResult:
    result = SpfResult()
    for txt in resolve_txt(domain):
        if txt.startswith("v=spf1"):
            result.found = True
            result.record = txt
            break

    if not result.found:
        result.issues.append("No SPF record — completely vulnerable to email spoofing")
        return result

    result.mechanisms = result.record.split()[1:]

    if "-all" in result.record:
        result.qualifier = "-all"
        result.score = 30
    elif "~all" in result.record:
        result.qualifier = "~all"
        result.score = 20
        result.issues.append("~all (SoftFail) — marks but doesn't reject. Use -all")
    elif "+all" in result.record:
        result.qualifier = "+all"
        result.score = 0
        result.issues.append("[CRITICAL] +all — allows any server to send. Fix immediately")
    else:
        result.score = 10
        result.issues.append("No 'all' qualifier — explicit policy needed")

    if result.record.count("include:") > 7:
        result.issues.append(f"Too many include: chains — risk of exceeding DNS lookup limit (10)")

    return result


def analyze_dkim(domain: str, selector: str = "mail") -> DkimResult:
    result = DkimResult(selector=selector)
    fqdn = f"{selector}._domainkey.{domain}"

    for txt in resolve_txt(fqdn):
        if "v=DKIM1" in txt or "k=rsa" in txt or "p=" in txt:
            result.found = True
            result.record = txt
            break

    if not result.found:
        result.issues.append(
            f"No DKIM record ({fqdn}) — "
            f"Try other selectors: --dkim-selector default"
        )
        return result

    p_start = result.record.find("p=")
    if p_start != -1:
        p_value = result.record[p_start + 2:].split(";")[0].strip()
        if len(p_value) < 200:
            result.key_bits = 1024
            result.issues.append("RSA-1024 key estimated — upgrade to 2048-bit")
            result.score = 15
        else:
            result.key_bits = 2048
            result.score = 30

    if "p=;" in result.record or result.record.endswith("p="):
        result.issues.append("DKIM key has been revoked (p= is empty)")
        result.score = 0

    return result


def analyze_dmarc(domain: str) -> DmarcResult:
    result = DmarcResult()
    for txt in resolve_txt(f"_dmarc.{domain}"):
        if "v=DMARC1" in txt:
            result.found = True
            result.record = txt
            break

    if not result.found:
        result.issues.append("No DMARC record — spoofed emails bypass policy enforcement")
        return result

    for part in result.record.split(";"):
        part = part.strip()
        if part.startswith("p="):
            result.policy = part[2:].strip()
        elif part.startswith("pct="):
            try:
                result.pct = int(part[4:])
            except ValueError:
                pass
        elif part.startswith("rua="):
            result.rua = part[4:].strip()
        elif part.startswith("ruf="):
            result.ruf = part[4:].strip()

    if result.policy == "reject":
        result.score = 40
    elif result.policy == "quarantine":
        result.score = 25
        result.issues.append("p=quarantine — quarantine only, not rejected. Upgrade to reject")
    elif result.policy == "none":
        result.score = 10
        result.issues.append("p=none — monitoring mode only, spoofed emails not blocked")
    else:
        result.score = 0
        result.issues.append(f"Unknown policy: {result.policy}")

    if result.pct < 100:
        result.issues.append(f"pct={result.pct} — policy only applied to {result.pct}% of mail")
    if not result.rua:
        result.issues.append("No rua — cannot receive aggregate reports (blind monitoring)")

    return result


def grade_score(score: int) -> str:
    if score >= 90:
        return "A"
    elif score >= 75:
        return "B"
    elif score >= 60:
        return "C"
    elif score >= 40:
        return "D"
    return "F"


def audit_domain(domain: str, dkim_selector: str = "mail") -> MailSecReport:
    report = MailSecReport(domain=domain)
    report.spf = analyze_spf(domain)
    report.dkim = analyze_dkim(domain, dkim_selector)
    report.dmarc = analyze_dmarc(domain)

    try:
        mx_answers = dns.resolver.resolve(domain, "MX", lifetime=5)
        report.mx_hosts = [
            str(r.exchange).rstrip(".")
            for r in sorted(mx_answers, key=lambda x: x.preference)
        ]
    except Exception:
        pass

    if report.mx_hosts:
        try:
            with smtplib.SMTP(report.mx_hosts[0], 25, timeout=8) as smtp:
                ehlo = smtp.ehlo()[1].decode("utf-8", errors="replace").lower()
                report.starttls_supported = "starttls" in ehlo
                smtp.mail("probe@test-spoof.invalid")
                code, _ = smtp.rcpt("test@external-domain.invalid")
                report.open_relay = (code == 250)
        except smtplib.SMTPRecipientsRefused:
            report.open_relay = False
        except Exception:
            pass

    report.total_score = report.spf.score + report.dkim.score + report.dmarc.score
    report.grade = grade_score(report.total_score)
    return report


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Comprehensive email security audit"
    )
    parser.add_argument("domain", help="Domain to audit (e.g. example.com)")
    parser.add_argument(
        "--dkim-selector", default="mail",
        help="DKIM selector (default: mail). Try 'default', 'google', 'k1'"
    )
    parser.add_argument(
        "--json-output", action="store_true",
        help="Output results as JSON"
    )
    args = parser.parse_args()

    report = audit_domain(args.domain, args.dkim_selector)

    if args.json_output:
        import dataclasses
        print(json.dumps(dataclasses.asdict(report), indent=2))
    else:
        print(f"\n{'='*60}")
        print(f"  Email Security Audit: {report.domain}")
        print(f"  Total Score: {report.total_score}/100  Grade: {report.grade}")
        print(f"{'='*60}")

        if report.mx_hosts:
            print(f"\nMX Servers: {', '.join(report.mx_hosts[:3])}")
        print(f"STARTTLS: {'Supported' if report.starttls_supported else 'NOT SUPPORTED [!]'}")
        print(f"Open Relay: {'VULNERABLE [!!]' if report.open_relay else 'Blocked'}")

        for label, result, max_score in [
            ("SPF", report.spf, 30),
            ("DKIM", report.dkim, 30),
            ("DMARC", report.dmarc, 40),
        ]:
            print(f"\n[{label}] Score: {result.score}/{max_score}")
            if result.found:
                print(f"  Record: {result.record[:80]}...")
            for issue in result.issues:
                print(f"  → {issue}")

    sys.exit(0 if report.total_score >= 60 else 1)


if __name__ == "__main__":
    main()
```

---

## 7. Mail Server Security Hardening Checklist

| Category | Item | Priority | Details |
|----------|------|----------|---------|
| SPF | v=spf1 record exists | Required | Without it, spoofing is undefended |
| SPF | Use -all | Recommended | Stronger than ~all |
| SPF | include chain under 10 | Required | DNS lookup limit |
| DKIM | Selector configured and DNS published | Required | Cannot detect body tampering without it |
| DKIM | RSA 2048-bit or higher | Required | 1024-bit is weak |
| DKIM | Annual key rotation | Recommended | Minimize damage from key compromise |
| DMARC | _dmarc record exists | Required | Completes SPF/DKIM effectiveness |
| DMARC | Progress: none → quarantine → reject | Recommended | Gradual enforcement |
| DMARC | rua address configured | Recommended | Can't monitor without reports |
| SMTP | STARTTLS supported | Required | Prevents plaintext transmission |
| SMTP | Open relay blocked | Required | Prevents abuse as spam relay |
| SMTP | VRFY/EXPN disabled | Recommended | Prevents user enumeration |
| General | SPF set on subdomains | Recommended | Prevents subdomain spoofing |
| General | MTA-STS configured | Recommended | Prevents downgrade attacks |

<!-- detect-validate-24 -->
## Mail Spoofing and Relay Detection and Defense Validation

Mail impersonation targets *missing SPF/DKIM/DMARC, open relays, and display-name spoofing*. Defenders must verify **whether their domain rejects or quarantines spoofed mail**. Validate only on **owned domains/mail servers**.

### Attack -> Targeted weakness -> Primary control (defender) -> Detection signal

| Technique | Targeted weakness | Primary control (defender) | Detection signal |
|---|---|---|---|
| Sender spoofing | No SPF/DMARC | DMARC p=reject | DMARC failure reports |
| Open relay | Unauthenticated relay | Enforce auth, block relay | External->external relay attempt |
| Header injection | Unvalidated input | Header validation, encoding | Abnormal header fields |
| Display-name/homoglyph spoofing | Visual trust | External banner, homoglyph detection | Look-alike sender domains |

### Defense validation (verify directly)

```bash
# 1) Check your domain's SPF/DMARC policy strength (owned domain) — none/missing means spoofing isn't blocked
dig +short TXT example.com | grep -i spf; dig +short TXT _dmarc.example.com | grep -iE "p=reject|p=quarantine"
# 2) Check for open relay (owned mail server) — external->external relay must be rejected
swaks --to ext@elsewhere.com --from spoof@notyours.com --server your.mail.server 2>&1 | grep -E "550|554|Relay" | head
```

> Mail defense is *whether spoofing is actually rejected* -- "we have a mail server" differs from "SPF/DKIM/DMARC quarantine spoofing with p=reject". Confirm your domain's DMARC policy and relay rejection directly ([[17_Red_Team_Operations]], [[33_OSINT_Social_Engineering]], [[13_SOC_Blue_Team]]).
