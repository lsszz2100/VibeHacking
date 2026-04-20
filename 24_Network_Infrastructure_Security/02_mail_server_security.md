# 메일 서버 보안 — SPF/DKIM/DMARC 및 공격 기법

## 1. 메일 인증 체계 개요

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

---

## 2. SPF 설정 및 분석

### 2-1. SPF 레코드 구조

```
v=spf1 ip4:203.0.113.0/24 include:_spf.google.com -all

메커니즘:
  ip4:주소    → 특정 IPv4 허용
  ip6:주소    → 특정 IPv6 허용
  a           → 도메인의 A 레코드 IP 허용
  mx          → 도메인의 MX 서버 허용
  include:    → 다른 도메인의 SPF 포함
  all         → 나머지 모두

한정자(Qualifier):
  +all → 허용 (기본값, 권장 안 함)
  -all → 거부 (Fail — 가장 강함)
  ~all → 소프트 실패 (SoftFail — 수신하되 마킹)
  ?all → 중립 (권장 안 함)
```

### 2-2. SPF 조회 및 분석

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

### 2-3. SPF 우회 기법

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

### 3-1. DKIM 키 생성 및 DNS 게시

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

### 3-2. Postfix + OpenDKIM 설정

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

---

## 4. DMARC 설정

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

---

## 5. 메일 서버 공격 기법

### 5-1. SMTP 오픈 릴레이 탐지

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

### 5-3. 이메일 헤더 위조 (스푸핑)

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

### 5-4. qmail 보안 설정 (레거시 서버)

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

## 6. 메일 서버 보안 점검 자동화

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
