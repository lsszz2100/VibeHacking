> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 33-01. OSINT 방법론과 고급 검색 — 공개 정보를 표적 정찰로 바꾸는 체계

> 한 줄 요약: 공개된 단편 정보를 사이클·연산자·자동화 파이프라인으로 엮어 "표적이 무엇을 노출했는지" 한 페이지로 압축하는 기술이다.

---

## 1. 왜 OSINT부터인가

침투 테스트든 레드팀 작전이든 첫 며칠은 거의 정찰에 쓰인다. 한국 실무에서는 보통 전체 공수 중 30~40% 가까이가 OSINT와 외부 자산 매핑에 들어간다. 코드 한 줄 짜기 전에 표적의 도메인 트리, 외주 협력사, 임직원 이메일 패턴, 노출된 S3 버킷, 폐쇄망 점검 시점에 깜빡 켜둔 RDP 포트까지 식별해 두는 것이 절대 시간을 절약하는 길이다.

2026년 기준 환경이 크게 바뀐 부분이 세 가지 있다.

- **자동 인덱싱의 가속화**: Shodan·Censys·FOFA·ZoomEye·Hunter가 IPv4 전수를 하루 몇 차례씩 돌리고, GitHub·GitLab·HuggingFace 등 코드 호스팅 플랫폼은 푸시 후 수 분 안에 검색 인덱스에 반영된다. "어제 올린 백업 SQL"이 점심시간에 외부에 노출된다.
- **AI 보조 정찰**: LLM 기반 ReconAgent·OSINT-GPT 류 도구가 사람이 일일이 돌려 보던 dorking 쿼리 수백 개를 자동으로 변형·재시도한다. 방어자도 같은 도구를 쓴다.
- **프라이버시 규제 강화**: 한국 개인정보보호법 2024 개정, EU AI Act, 미국 주별 CCPA 변형이 동시에 적용되면서 "공개돼 있다고 다 모아도 되는가"라는 질문이 늘 따라온다.

따라서 OSINT는 더 이상 "구글에서 찾아봤어요" 수준의 사전 작업이 아니라, **요구사항 정의 → 수집 → 분석 → 증거 보존**까지 명문화된 절차로 다뤄야 한다.

---

## 2. OSINT 사이클 — 정보 분석 5단계의 실무 적용

미국 ODNI·영국 SIS가 쓰는 정보 사이클을 그대로 가져오되, 한국 침투/포렌식 실무 표현으로 다시 적었다.

```
                  ┌─────────────────────────┐
                  │ 1) 요구사항 (Direction) │
                  │  - 무엇을 찾을지 정의   │
                  │  - 범위·시간·법적 한계  │
                  └────────────┬────────────┘
                               │
                  ┌────────────▼────────────┐
                  │ 2) 수집 (Collection)    │
                  │  - 공개검색·API·스크래핑│
                  │  - passive / active     │
                  └────────────┬────────────┘
                               │
                  ┌────────────▼────────────┐
                  │ 3) 처리 (Processing)    │
                  │  - 정규화·중복 제거     │
                  │  - 언어·문자셋 통일     │
                  └────────────┬────────────┘
                               │
                  ┌────────────▼────────────┐
                  │ 4) 분석 (Analysis)      │
                  │  - 가설·연결·우선순위   │
                  │  - 표적도(target map)   │
                  └────────────┬────────────┘
                               │
                  ┌────────────▼────────────┐
                  │ 5) 배포 (Dissemination) │
                  │  - 보고서·티켓·MISP     │
                  │  - 운영팀과의 핸드오프  │
                  └─────────────────────────┘
```

### 2-1. 요구사항(Direction)

- **무엇을(what)**: 외부 노출 자산? 임직원 명단? 특정 임원의 SNS 패턴?
- **왜(why)**: 모의해킹 사전 정찰? 인수합병 실사? 사고 대응?
- **누가 본다(audience)**: 기술팀·법무팀·고객 임원
- **법적 한계(limit)**: 한국 개인정보보호법, 정보통신망법, 통신비밀보호법, 계약상 NDA·RoE

이 단계에서 "비밀번호 평문이 적힌 GitHub 커밋을 끝까지 추적해도 되는가" 같은 질문에 미리 답해 두지 않으면 분석 도중 손이 멈춘다.

### 2-2. 수집(Collection)

수집은 두 갈래로 나뉜다.

| 구분 | 정의 | 예시 |
|---|---|---|
| Passive | 표적과 직접 통신하지 않음 | crt.sh, Shodan 캐시, 구글 dork, archive.org |
| Active | 표적 인프라와 직접 통신 | nmap, dirbuster, HTTP 헤더 직접 요청 |

OSINT라는 단어는 보통 passive 영역을 가리키지만, 실무에서는 둘 사이가 모호한 경우가 많다 (예: Shodan가 보내는 배너 그래빙은 표적 입장에서 active로 보일 수 있다).

### 2-3. 처리(Processing)

수집물은 거의 항상 더럽다.

- 도메인은 대소문자·trailing dot·IDN(국제화 도메인) 처리 필요
- 이메일은 `+`, `.`, 대소문자 정규화 (Gmail은 `.` 무시)
- IP는 IPv4·IPv6·CIDR 통일
- 인코딩: UTF-8로 통일, 한글 깨짐(`í•œêµ­`) 자동 복구 스크립트 준비

### 2-4. 분석(Analysis)

처리된 데이터를 **가설**로 묶는다. 예) "이 회사는 AWS Seoul 리전을 쓰고, 외주 개발사가 GitLab self-hosted를 운영한다. 외주사 GitLab에 회사 임직원 SSH 키가 등록되어 있을 가능성이 높다."

분석 산출물은 다음 중 하나다.

- 표적도(target map): 도메인 → 자산 → 취약점 후보
- 조직도: 임직원·역할·이메일 패턴
- 기술 스택 매트릭스: 프레임워크·버전·CVE 매핑

### 2-5. 배포(Dissemination)

- 침투팀: 다음 단계로 직접 전달 (예: BloodHound 입력)
- 고객 보고서: PDF·HTML, 출처와 시간 포함
- 위협 인텔: MISP·OpenCTI 객체로 공유

---

## 3. 고급 검색 연산자 — 검색창에서 90%를 끝내는 법

### 3-1. Google dorking

가장 자주 쓰는 연산자만 추리면 다음과 같다.

| 연산자 | 의미 | 예시 |
|---|---|---|
| `site:` | 도메인 한정 | `site:example.co.kr` |
| `-site:` | 도메인 제외 | `site:example.co.kr -site:blog.example.co.kr` |
| `intext:` | 본문 매칭 | `intext:"DB_PASSWORD"` |
| `intitle:` | 제목 매칭 | `intitle:"index of /backup"` |
| `inurl:` | URL 매칭 | `inurl:admin inurl:login` |
| `filetype:` | 확장자 | `filetype:env` |
| `cache:` | 구글 캐시 | `cache:example.co.kr` (2024년 이후 사실상 폐지) |
| `before:` / `after:` | 기간 | `after:2025-01-01 before:2026-01-01` |
| `"..."` | 정확 일치 | `"-----BEGIN RSA PRIVATE KEY-----"` |

실전 dork 모음(허용된 자기 도메인 한정으로 사용):

```
site:example.co.kr filetype:env
site:example.co.kr filetype:sql intext:"INSERT INTO"
site:example.co.kr intitle:"phpinfo()"
site:example.co.kr inurl:"/.git/"
site:example.co.kr "DB_PASSWORD" OR "AWS_ACCESS_KEY"
site:s3.amazonaws.com "example"
site:trello.com "example.co.kr"
site:pastebin.com "example.co.kr"
```

> 주의: Google은 dorking 트래픽을 자동 탐지해 reCAPTCHA·차단을 건다. 짧은 시간에 같은 IP로 수백 건 돌리지 말고, 결과는 SerpAPI·Brave Search API 같은 정식 API로 받아 두는 편이 안정적이다.

### 3-2. Bing·DuckDuckGo의 차이

- **Bing**: `site:`·`filetype:` 동일하게 동작. `contains:` 연산자가 살아 있어 `site:example.co.kr contains:bak` 같은 패턴이 가능. API(Bing Web Search v7)는 2025년 8월 종료되었고 후속은 Microsoft Copilot Search API로 통합되는 중.
- **DuckDuckGo**: 개인정보 수집을 강조해 dorking 결과가 Google·Bing보다 적다. 하지만 `!g`, `!so`, `!gh` 같은 bang 명령으로 다른 엔진에 즉시 위임 가능.
- **Naver·Daum**: 한국 도메인 중 `.go.kr`, `.or.kr` 같이 국내에서만 인덱싱되는 콘텐츠는 네이버·다음이 더 잘 잡는다. 단, 고급 연산자는 Google보다 약하다.

### 3-3. GitHub dorking

GitHub는 자격증명 유출의 압도적 1위 채널이다.

```
org:exampleinc AWS_ACCESS_KEY_ID
org:exampleinc filename:.env DB_PASSWORD
org:exampleinc filename:id_rsa
org:exampleinc language:python "boto3.client" "aws_secret_access_key"
org:exampleinc path:.github/workflows secret
org:exampleinc extension:pem
"example.co.kr" "BEGIN OPENSSH PRIVATE KEY"
"@example.co.kr" filename:.env
```

자주 쓰이는 자격증명 패턴:

| 서비스 | 정규식 |
|---|---|
| AWS Access Key | `AKIA[0-9A-Z]{16}` |
| AWS Secret | `(?i)aws.{0,20}?(secret|key).{0,20}?[a-z0-9/+=]{40}` |
| Slack Token | `xox[abprs]-[0-9a-zA-Z-]{10,48}` |
| GitHub PAT | `ghp_[A-Za-z0-9]{36}` |
| Stripe Live | `sk_live_[0-9a-zA-Z]{24}` |
| Google API | `AIza[0-9A-Za-z\\-_]{35}` |

### 3-4. 코드 검색에서 절대 하지 말아야 할 것

- **GitHub TOS**: 자동화된 다중 계정 스크래핑·rate limit 우회 금지. Search API는 분당 30회 인증 호출이 상한.
- **한국 정보통신망법 제48조**: 정보통신시스템에 침입하는 행위 금지. 공개 검색 자체는 합법이지만, 검색으로 얻은 자격증명을 그대로 사용하는 순간 "정당한 접근 권한 없는 침입"이 된다.
- **개인정보보호법**: 임직원 명단을 GitHub에서 긁어 별도 DB로 보관하는 것은 처리(저장) 행위이며, 본인 동의 없는 처리에 해당할 수 있다. 모의해킹 계약서에 명시적 위탁 조항이 있어야 안전.

---

## 4. 장비·서비스 검색 엔진

### 4-1. Shodan

Shodan은 IPv4 전체 + 일부 IPv6를 주기적으로 스캔해 배너를 색인한다. 무료 계정은 검색 결과가 페이지당 10건·1페이지로 제한되며, 유료(`Membership`·`Freelancer`·`Corporate`)에서 필터·CSV·API가 풀린다.

자주 쓰는 필터:

```
org:"Example Corp"
asn:AS17596
country:KR
port:3389
port:445 os:"Windows Server 2008"
ssl.cert.issuer.cn:"R3"
ssl.cert.subject.cn:*.example.co.kr
hostname:example.co.kr
http.title:"login"
http.favicon.hash:-247388890
product:nginx version:1.18.0
vuln:CVE-2024-3094
tag:ics
```

`http.favicon.hash`는 favicon의 mmh3 해시로, 같은 해시를 가진 호스트를 한 번에 묶을 수 있다. 어드민 패널이 동일 favicon을 쓰는 회사 자산을 식별할 때 강력하다.

#### 실전 예시: 한 회사 외부 노출 자산을 한 번에 찾기

다음은 `example.com`을 표적으로 가정해 Shodan에서 자산을 한 번에 모으는 Python 3.10+ 스크립트다. `SHODAN_API_KEY` 환경변수를 사용한다.

```python
# file: shodan_recon.py
# usage: python shodan_recon.py example.com --org "Example Inc"
from __future__ import annotations

import argparse
import asyncio
import os
import sys
from dataclasses import dataclass
from typing import Any

import httpx

SHODAN_API = "https://api.shodan.io"


@dataclass(slots=True)
class ShodanHit:
    ip: str
    port: int
    product: str
    org: str
    hostnames: list[str]
    vulns: list[str]


class ShodanClient:
    def __init__(self, api_key: str, timeout: float = 30.0) -> None:
        if not api_key:
            raise ValueError("SHODAN_API_KEY 환경변수가 필요합니다")
        self._client = httpx.AsyncClient(timeout=timeout)
        self._key = api_key

    async def search(self, query: str, pages: int = 1) -> list[ShodanHit]:
        hits: list[ShodanHit] = []
        for page in range(1, pages + 1):
            r = await self._client.get(
                f"{SHODAN_API}/shodan/host/search",
                params={"key": self._key, "query": query, "page": page},
            )
            r.raise_for_status()
            data = r.json()
            for m in data.get("matches", []):
                hits.append(
                    ShodanHit(
                        ip=m.get("ip_str", ""),
                        port=int(m.get("port", 0)),
                        product=str(m.get("product", "") or ""),
                        org=str(m.get("org", "") or ""),
                        hostnames=list(m.get("hostnames", [])),
                        vulns=list((m.get("vulns") or {}).keys()),
                    )
                )
        return hits

    async def aclose(self) -> None:
        await self._client.aclose()


async def amain(args: argparse.Namespace) -> int:
    api = os.environ.get("SHODAN_API_KEY", "")
    client = ShodanClient(api)
    try:
        queries = [
            f'hostname:{args.domain}',
            f'ssl.cert.subject.cn:*.{args.domain}',
        ]
        if args.org:
            queries.append(f'org:"{args.org}"')

        seen: set[tuple[str, int]] = set()
        for q in queries:
            print(f"[+] query: {q}", file=sys.stderr)
            for hit in await client.search(q, pages=args.pages):
                key = (hit.ip, hit.port)
                if key in seen:
                    continue
                seen.add(key)
                vuln_tag = f" vulns={','.join(hit.vulns)}" if hit.vulns else ""
                print(
                    f"{hit.ip}:{hit.port}\t{hit.product}\t"
                    f"{','.join(hit.hostnames) or '-'}{vuln_tag}"
                )
    finally:
        await client.aclose()
    return 0


def main() -> None:
    p = argparse.ArgumentParser(description="Shodan 표적 정찰")
    p.add_argument("domain")
    p.add_argument("--org", help="회사명 (Shodan org 필터)")
    p.add_argument("--pages", type=int, default=1, help="검색 페이지 수")
    args = p.parse_args()
    raise SystemExit(asyncio.run(amain(args)))


if __name__ == "__main__":
    main()
```

실행 예:

```bash
export SHODAN_API_KEY="****"
python shodan_recon.py example.com --org "Example Inc" --pages 2
```

### 4-2. Censys

Censys는 인증서·호스트·소프트웨어 인덱스를 BigQuery 비슷한 SQL스러운 쿼리로 검색한다. 2025년 개편 이후 검색 UI가 `Hosts`, `Certificates`, `Web` 세 갈래로 분리됐다.

```
services.tls.certificates.leaf_data.subject.common_name: *.example.co.kr
services.service_name: HTTP and services.http.response.body: "phpMyAdmin"
location.country: "South Korea" and services.port: 5432
autonomous_system.asn: 17596
```

Censys API는 `requests`와도 잘 맞지만, 페이지네이션이 cursor 기반이라 비동기 호출이 편하다.

### 4-3. FOFA / ZoomEye / Hunter.io

| 엔진 | 강점 | 약점 |
|---|---|---|
| FOFA (중국) | ICS·국내 미인덱싱 자산 | 영문 UI 부족, 가격 |
| ZoomEye (중국) | 산업제어, IoT 펌웨어 | API 제한 빡빡 |
| Hunter.io | 임직원 이메일 패턴, 도메인별 명단 | 공개 SNS와 중복 다수 |
| Quake (중국, 360) | 빠른 신규 자산 인덱싱 | 가입 까다로움 |

한국 IDC·KT·LG U+ IP 대역이 잘 잡히는 엔진은 Shodan·Censys·FOFA 순이다. 셋을 동시에 돌려 결과 합집합을 만드는 것이 일반적인 실무 패턴.

### 4-4. 가격 비교 (2026년 기준 대략치, 변동 가능)

- Shodan Membership: $69/년 (1회성), Freelancer $59/월, Corporate $1,099/월
- Censys Pro: $99/월
- FOFA Pro: 약 ¥4,200/년
- Hunter.io Starter: $49/월

회사 단위 모의해킹팀이라면 **Shodan Freelancer + Censys Pro + Hunter Growth** 조합이 비용 대비 가장 무난하다.

---

## 5. 인증서 투명성 로그(CT)

CT(Certificate Transparency)는 모든 발급 인증서를 공개 로그에 등록하도록 강제하는 RFC 6962 시스템이다. 표적이 `*.internal.example.co.kr` 같은 비공개 호스트명을 인증서에 박아두면, 그 순간 전 세계가 본다.

자주 쓰는 소스:

- **crt.sh**: PostgreSQL 기반, JSON 출력 지원
- **Censys Certificates**: 풍부한 메타데이터
- **Cloudflare Merkle Town**: 시각화 + 실시간 스트림
- **Google Argon/Yeti/Sabre**: 원본 로그 서버

### 5-1. crt.sh JSON으로 하위도메인 자동 수집 (asyncio)

```python
# file: ct_subdomains.py
# usage: python ct_subdomains.py example.co.kr
from __future__ import annotations

import argparse
import asyncio
import re
import sys
from typing import Iterable

import httpx

CRT_URL = "https://crt.sh/"
SUBDOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)+$")


async def fetch_crtsh(client: httpx.AsyncClient, domain: str) -> list[dict]:
    r = await client.get(
        CRT_URL,
        params={"q": f"%.{domain}", "output": "json"},
        headers={"User-Agent": "ct-recon/1.0"},
    )
    r.raise_for_status()
    return r.json()


def normalize(names: Iterable[str], root: str) -> set[str]:
    out: set[str] = set()
    for raw in names:
        for n in raw.split("\n"):
            n = n.strip().lower().lstrip("*.")
            if not n.endswith(root):
                continue
            if SUBDOMAIN_RE.match(n):
                out.add(n)
    return out


async def amain(domain: str) -> int:
    async with httpx.AsyncClient(timeout=60.0) as client:
        try:
            entries = await fetch_crtsh(client, domain)
        except httpx.HTTPError as e:
            print(f"[!] crt.sh 호출 실패: {e}", file=sys.stderr)
            return 1
    subs = normalize((e.get("name_value", "") for e in entries), domain.lower())
    for s in sorted(subs):
        print(s)
    print(f"[+] total {len(subs)} unique subdomains", file=sys.stderr)
    return 0


def main() -> None:
    p = argparse.ArgumentParser(description="CT 로그 기반 하위도메인 수집")
    p.add_argument("domain")
    args = p.parse_args()
    raise SystemExit(asyncio.run(amain(args.domain)))


if __name__ == "__main__":
    main()
```

실행:

```bash
python ct_subdomains.py example.co.kr | tee subs.txt
```

crt.sh가 종종 느려지면 `https://crt.sh/?q=&output=json` 외에 `https://api.certspotter.com/v1/issuances?domain=example.co.kr&include_subdomains=true&expand=dns_names` 를 백업으로 쓰면 된다.

### 5-2. CT 결과의 함정

- **스테이징 인증서**: `Let's Encrypt Staging` CA가 발급한 항목은 실제 운영 인증서가 아닐 수 있다. `issuer_ca_id`로 거른다.
- **프리시디케이션(precertificate)**: 같은 호스트가 두 번 등장한다. `min_cert_id`로 정렬해 중복 제거.
- **이미 만료된 인증서**: `not_after`가 지난 항목은 별도 컬럼으로 분리. 자산이 살아 있는지는 별도 DNS 검증이 필요.

---

## 6. DNS·whois 기반 자산 식별

CT는 인증서 기반이라 평문 HTTP만 쓰는 자산은 잡히지 않는다. DNS·whois를 함께 봐야 한다.

### 6-1. Passive DNS

- **SecurityTrails**: 5년치 A·AAAA·MX·NS 변경 이력
- **VirusTotal Graph**: 도메인 ↔ IP ↔ 샘플 그래프
- **DNSDB (Farsight, 현재 DomainTools 산하)**: 가장 큰 상용 DB
- **CIRCL Passive DNS**: 유럽 CERT 운영, 무료 등록

쓰는 방식은 비슷하다. API 키로 도메인을 던지면 "과거에 이 도메인을 가리킨 IP / 이 IP가 가리킨 도메인" 리스트가 돌아온다.

### 6-2. whois·RDAP

전통 whois는 KISA·Verisign·APNIC 별로 포맷이 제각각이다. **RDAP**(RFC 7480)는 JSON 기반 후속 표준으로, `https://rdap.krnic.net/rdap/domain/example.co.kr` 같이 쿼리한다.

```bash
curl -s https://rdap.krnic.net/rdap/domain/example.co.kr | jq '.entities[].vcardArray[1]'
```

한국 `.co.kr` 도메인은 등록인 정보가 마스킹되는 경우가 많아, 행정/기술 담당자 이메일 패턴(`@example.co.kr`)만 건져도 충분한 출발점이 된다.

### 6-3. 한국 KISA 자료의 활용

- **KISA DNS sinkhole 정보**: 악성코드 C2로 분류된 도메인 리스트를 매일 갱신. 표적이 보유한 도메인이 들어 있는지 역으로 확인하면 IR 사고 단서가 된다.
- **KrCERT 보안공지·취약점 신고**: 표적 산업 동종 사고 패턴 파악.
- **Whois.kisa.or.kr**: `.kr` 도메인 일괄 조회.

### 6-4. 자산 분류 표 예시

수집된 데이터는 다음 같은 표로 정리해 두면 다음 단계(취약점 매핑)에서 그대로 입력으로 쓸 수 있다.

| 자산 | 유형 | 출처 | 최초 관측 | 비고 |
|---|---|---|---|---|
| api.example.co.kr | 도메인 | crt.sh | 2024-08-12 | TLS 1.2, nginx 1.18 |
| 203.0.113.42 | IPv4 | Shodan | 2025-12-03 | port 22, 80, 443, 8080 |
| s3://example-backup | S3 버킷 | Google dork | 2026-02-19 | public-read 의심 |

---

## 7. 데이터 보존과 출처 관리

OSINT 결과는 며칠만 지나도 사라진다. CDN 캐시 갱신, GitHub 강제 푸시, 기사 수정·삭제, S3 권한 변경. 그래서 **수집 즉시 캡처**가 원칙이다.

### 7-1. 캡처 도구

- **SingleFile (브라우저 확장)**: HTML+이미지+CSS를 단일 `.html`로 저장
- **Hunchly**: 세션 단위 자동 캡처, 케이스 ID 부여, OCR
- **archive.org Wayback Machine "Save Page Now"**: 영구 URL 확보
- **shot-scraper**: 헤드리스 크롬 기반 CLI 스크린샷
- **wkhtmltopdf / weasyprint**: PDF 변환

### 7-2. 무결성 보장 절차

1. 원본 캡처(`.html`, `.png`, `.warc`) 저장
2. SHA-256 해시 계산 → CSV 로그
3. 로그 자체를 RFC 3161 타임스탬프 서버에 서명 의뢰
4. 케이스별로 별도 폴더, 폴더명에 ISO 8601 일시 포함

```python
# file: capture_log.py 일부
import hashlib, csv, datetime, pathlib

def sha256_of(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()

def append_log(case_dir: pathlib.Path, source_url: str, file_path: pathlib.Path) -> None:
    log = case_dir / "evidence.csv"
    new = not log.exists()
    with log.open("a", newline="") as f:
        w = csv.writer(f)
        if new:
            w.writerow(["timestamp_iso", "source_url", "file", "sha256"])
        w.writerow([
            datetime.datetime.now(datetime.UTC).isoformat(),
            source_url,
            str(file_path.relative_to(case_dir)),
            sha256_of(file_path),
        ])
```

법정 증거로 쓸 가능성이 있다면, 캡처 시점부터 작업자 PC가 NTP 동기화돼 있어야 하고, 캡처에 사용된 도구·버전·OS도 함께 기록한다(소위 "프로비넌스(provenance)").

---

## 8. 자동화 파이프라인 예시

지금까지 다룬 것을 한 번에 돌리는 파이프라인을 만든다. 입력은 도메인 하나, 출력은 다음과 같다.

- 하위도메인 (CT 로그)
- 메일 패턴 (Hunter.io)
- 임직원 후보 (Hunter.io 결과 + LinkedIn 공개 ID는 별도 처리)
- 기술 스택 추정 (HTTP 헤더·favicon 해시)

httpx + asyncio + 세마포어로 동시성 제어. Hunter.io 키와 Shodan 키는 환경변수로 주입한다.

```python
# file: recon_pipeline.py
# usage: python recon_pipeline.py example.co.kr --concurrency 10 --out result.json
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import sys
from dataclasses import asdict, dataclass, field
from typing import Any

import httpx
import mmh3  # pip install mmh3


@dataclass(slots=True)
class ReconResult:
    domain: str
    subdomains: list[str] = field(default_factory=list)
    email_pattern: str | None = None
    employees: list[dict[str, Any]] = field(default_factory=list)
    tech: list[dict[str, Any]] = field(default_factory=list)


class ReconPipeline:
    def __init__(self, domain: str, concurrency: int = 10) -> None:
        self.domain = domain.lower().rstrip(".")
        self.sem = asyncio.Semaphore(concurrency)
        self.client = httpx.AsyncClient(
            timeout=20.0,
            headers={"User-Agent": "vibe-recon/1.0"},
            follow_redirects=True,
        )
        self.hunter = os.environ.get("HUNTER_API_KEY", "")

    async def aclose(self) -> None:
        await self.client.aclose()

    async def fetch_subdomains(self) -> list[str]:
        r = await self.client.get(
            "https://crt.sh/",
            params={"q": f"%.{self.domain}", "output": "json"},
        )
        r.raise_for_status()
        names: set[str] = set()
        for entry in r.json():
            for n in entry.get("name_value", "").split("\n"):
                n = n.strip().lower().lstrip("*.")
                if n.endswith(self.domain) and "*" not in n:
                    names.add(n)
        return sorted(names)

    async def fetch_hunter(self) -> tuple[str | None, list[dict[str, Any]]]:
        if not self.hunter:
            return None, []
        r = await self.client.get(
            "https://api.hunter.io/v2/domain-search",
            params={"domain": self.domain, "api_key": self.hunter, "limit": 50},
        )
        if r.status_code != 200:
            return None, []
        data = r.json().get("data", {})
        emails = [
            {"email": e.get("value"), "first": e.get("first_name"),
             "last": e.get("last_name"), "position": e.get("position")}
            for e in data.get("emails", [])
        ]
        return data.get("pattern"), emails

    async def fingerprint(self, host: str) -> dict[str, Any] | None:
        async with self.sem:
            for scheme in ("https", "http"):
                url = f"{scheme}://{host}/"
                try:
                    r = await self.client.get(url)
                except (httpx.HTTPError, OSError):
                    continue
                fav = await self._favicon_hash(scheme, host)
                return {
                    "host": host,
                    "url": str(r.url),
                    "status": r.status_code,
                    "server": r.headers.get("server"),
                    "powered_by": r.headers.get("x-powered-by"),
                    "favicon_mmh3": fav,
                }
        return None

    async def _favicon_hash(self, scheme: str, host: str) -> int | None:
        try:
            r = await self.client.get(f"{scheme}://{host}/favicon.ico")
        except (httpx.HTTPError, OSError):
            return None
        if r.status_code != 200 or not r.content:
            return None
        import base64
        b64 = base64.encodebytes(r.content)
        return mmh3.hash(b64)

    async def run(self) -> ReconResult:
        result = ReconResult(domain=self.domain)
        subs_task = asyncio.create_task(self.fetch_subdomains())
        hunter_task = asyncio.create_task(self.fetch_hunter())
        result.subdomains = await subs_task
        result.email_pattern, result.employees = await hunter_task
        fps = await asyncio.gather(*(self.fingerprint(h) for h in result.subdomains[:50]))
        result.tech = [f for f in fps if f]
        return result


async def amain(args: argparse.Namespace) -> int:
    pipe = ReconPipeline(args.domain, concurrency=args.concurrency)
    try:
        res = await pipe.run()
    finally:
        await pipe.aclose()
    payload = json.dumps(asdict(res), ensure_ascii=False, indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(payload)
        print(f"[+] saved -> {args.out}", file=sys.stderr)
    else:
        print(payload)
    return 0


def main() -> None:
    p = argparse.ArgumentParser(description="도메인 1개로 OSINT 1차 리포트 생성")
    p.add_argument("domain")
    p.add_argument("--concurrency", type=int, default=10)
    p.add_argument("--out", help="JSON 저장 경로")
    args = p.parse_args()
    raise SystemExit(asyncio.run(amain(args)))


if __name__ == "__main__":
    main()
```

실행 결과 JSON에는 다음 같은 필드가 들어 있다.

```json
{
  "domain": "example.co.kr",
  "subdomains": ["api.example.co.kr", "mail.example.co.kr", "..."],
  "email_pattern": "{first}.{last}@example.co.kr",
  "employees": [{"email": "kim.jinho@example.co.kr", "position": "DevOps"}],
  "tech": [
    {"host": "api.example.co.kr", "server": "nginx/1.18.0",
     "powered_by": null, "favicon_mmh3": -247388890}
  ]
}
```

이 JSON 한 덩어리가 다음 문서(02 타깃 프로파일링) 입력이 된다.

### 8-1. 운영 팁

- **rate limit 존중**: crt.sh는 동시 1~2 요청, Hunter는 분당 25 요청.
- **결과 캐시**: 같은 도메인을 반복 조사하므로 SQLite·diskcache로 캐시 권장.
- **차단 회피 != 우회**: 회피와 우회는 다르다. User-Agent를 `vibe-recon/1.0`처럼 명시해 식별 가능하게 두는 것이 사고 시 책임 소재 정리에 유리.
- **로깅**: 모든 외부 호출은 `(timestamp, url, status, bytes)` 형태로 NDJSON 기록.

---

## 9. 법적·윤리적 경계

### 9-1. 한국·해외 주요 법령 매트릭스

| 행위 | 한국 개인정보보호법 | 한국 정보통신망법 | 한국 통신비밀보호법 | EU GDPR | US CCPA |
|---|---|---|---|---|---|
| 공개된 임직원 이름·직책 수집 | 주의 (목적·보유기간 명시) | 허용 | 허용 | 주의 (정당한 이익) | 주의 (cancel 권리) |
| 공개된 임직원 이메일 주소 수집 | 주의 (식별가능 개인정보) | 허용 | 허용 | 주의 | 주의 |
| 공개된 비밀번호 해시·평문 수집 | 금지(특수정보) | 사실상 금지 | 주의 | 금지 | 금지 |
| GitHub 노출 자격증명 단순 열람 | 허용 | 허용 | 허용 | 허용 | 허용 |
| GitHub 노출 자격증명으로 로그인 | 금지 (권한 없는 처리) | 금지(48조) | 금지 | 금지 | 금지 |
| 표적 시스템에 nmap 풀 스캔 | 주의 | 금지(권한 필요) | 주의 | 금지 | 금지 |
| 통신 내용 가로채기 | 금지 | 금지 | 금지(매우 무거움) | 금지 | 금지 |
| 다크웹 시장에서 유출 데이터 구매 | 금지 | 금지 | 금지 | 금지 | 금지 |

### 9-2. 실무 체크리스트

작업 시작 전에 다음 5개 질문에 yes 라고 답할 수 있는지 확인한다.

1. RoE(Rules of Engagement)와 NDA가 서명됐는가
2. 표적 자산 범위(in-scope)가 도메인·CIDR·서비스 단위로 명확한가
3. 수집 대상에 개인정보가 포함될 경우 보유기간·파기 절차가 정의됐는가
4. 캡처물의 저장 위치는 통제된 환경(암호화 디스크, 접근 통제)인가
5. 사고가 났을 때 통보할 고객 contact가 24시간 가용인가

### 9-3. 자기 도메인 기준 OSINT가 제일 안전하다

학습용 실습은 **본인 또는 회사 소유 도메인**, **HackTheBox/TryHackMe/PortSwigger Web Security Academy의 합법 랩**, **CTF 출제 서버**로 한정한다. 위에서 본 dork·Shodan 쿼리는 그대로 자기 자산 모니터링에 쓸 수 있다.

---

## 10. 마무리 — 다음 문서로 가는 다리

여기까지 모은 것은 **자산의 외형**이다. 도메인, IP, 포트, 임직원 이메일 패턴, 노출된 자격증명 후보. 그러나 표적은 사람과 조직으로 움직인다. 다음 문서(33-02 타깃 프로파일링)에서는 이 자산 데이터를 **사람·역할·관계** 차원으로 끌어올린다.

- 누가 어느 시스템 권한을 갖는지
- 어떤 SaaS·메신저를 쓰는지
- 사회공학 시나리오에서 가장 약한 고리는 누구인지

이 단계까지 정리되면, 그 다음 33-03(피싱 인프라 구축) 부터는 거의 코드와 도메인 등록 작업이다. 그러니 지금 단계의 핵심 산출물은 한 가지로 압축된다.

> "표적의 모든 외부 자산과 임직원 이메일 패턴이 들어 있는 단일 JSON과, 그 출처·시간·해시가 적힌 evidence.csv."

이 두 파일이 나오면 33-01은 완료다. 만약 둘 중 하나라도 없다면, 8장의 `recon_pipeline.py`와 7장의 `capture_log.py`를 다시 돌려라.

---

### 부록 A. 자주 쓰는 dork·쿼리 모음 (자기 자산 점검용)

```
# Google
site:example.co.kr (ext:env OR ext:bak OR ext:sql OR ext:log)
site:example.co.kr intext:"-----BEGIN RSA PRIVATE KEY-----"
site:example.co.kr inurl:wp-admin
site:s3.amazonaws.com "example"
site:trello.com "example"
site:atlassian.net "example.co.kr"

# GitHub
org:example "AKIA"
org:example filename:.env
"@example.co.kr" "BEGIN OPENSSH PRIVATE KEY"

# Shodan
hostname:example.co.kr
ssl.cert.subject.cn:*.example.co.kr
org:"Example Inc" port:3389
http.favicon.hash:-247388890

# Censys
services.tls.certificates.leaf_data.subject.common_name: *.example.co.kr
services.http.response.body: "Welcome to Example" and location.country: "South Korea"

# crt.sh
https://crt.sh/?q=%25.example.co.kr&output=json
```

### 부록 B. 환경 세팅 한 줄

```bash
python -m venv .venv && source .venv/bin/activate
pip install "httpx>=0.27" "mmh3>=4.1" "rich>=13.7" "tldextract>=5.1"
export SHODAN_API_KEY="..."
export HUNTER_API_KEY="..."
```

### 부록 C. 실무 체크리스트 한 장 요약

- [ ] RoE·NDA 서명 완료, 범위 문서화
- [ ] 자기 도메인/실습 랩 외에는 active 스캔 금지
- [ ] crt.sh + Shodan + Censys 결과를 같은 JSON 스키마로 합침
- [ ] 모든 캡처물에 SHA-256 + ISO 8601 타임스탬프
- [ ] Hunter·SecurityTrails 같은 유료 API는 분당 호출 수 명시
- [ ] 작업 종료 후 `evidence.csv` + JSON을 케이스 폴더에 압축, 암호화
- [ ] 보고서 본문에는 출처 URL·캡처 시각·해시를 각주로

---

이 문서가 끝나면 표적의 외형 90%는 손에 들어와 있다. 다음 33-02에서 그 외형에 사람을 채워 넣는다.

---

<a name="english"></a>

# 33-01. OSINT Methodology and Advanced Search — Turning Public Information into Targeted Reconnaissance

> One-line summary: The technique of weaving scattered public information through cycles, operators, and automated pipelines to compress "what the target has exposed" into a single page.

---

## 1. Why Start with OSINT?

Whether it's a penetration test or a red team operation, the first few days are almost entirely spent on reconnaissance. In Korean practice, roughly 30–40% of total effort goes into OSINT and external asset mapping. Before writing a single line of code, identifying the target's domain tree, subcontractors, employee email patterns, exposed S3 buckets, and even an RDP port accidentally left open during a closed-network inspection saves enormous time overall.

Three things have changed significantly by 2026:

- **Accelerated automatic indexing**: Shodan, Censys, FOFA, ZoomEye, and Hunter scan all IPv4 addresses multiple times a day, and code hosting platforms like GitHub, GitLab, and HuggingFace reflect pushes in search indexes within minutes. A "backup SQL uploaded yesterday" can be exposed to the outside world by lunchtime.
- **AI-assisted reconnaissance**: LLM-based tools like ReconAgent and OSINT-GPT automatically vary and retry hundreds of dorking queries that humans previously had to run manually. Defenders use the same tools.
- **Strengthened privacy regulations**: The Korean Personal Information Protection Act 2024 amendment, EU AI Act, and US state-level CCPA variants now apply simultaneously, raising the constant question "just because it's public, can we collect everything?"

Therefore, OSINT is no longer a preliminary "I googled it" step — it must be treated as a formalized procedure covering **requirements definition → collection → analysis → evidence preservation**.

---

## 2. The OSINT Cycle — Practical Application of 5-Stage Intelligence Analysis

The intelligence cycle used by the US ODNI and UK SIS, rewritten in Korean penetration/forensics practice terms.

```
                  ┌─────────────────────────┐
                  │ 1) Direction            │
                  │  - Define what to find  │
                  │  - Scope/time/legal limits│
                  └────────────┬────────────┘
                               │
                  ┌────────────▼────────────┐
                  │ 2) Collection           │
                  │  - Public search/API/   │
                  │    scraping             │
                  │  - passive / active     │
                  └────────────┬────────────┘
                               │
                  ┌────────────▼────────────┐
                  │ 3) Processing           │
                  │  - Normalization/dedup  │
                  │  - Language/charset     │
                  │    unification          │
                  └────────────┬────────────┘
                               │
                  ┌────────────▼────────────┐
                  │ 4) Analysis             │
                  │  - Hypothesis/linking/  │
                  │    prioritization       │
                  │  - Target map           │
                  └────────────┬────────────┘
                               │
                  ┌────────────▼────────────┐
                  │ 5) Dissemination        │
                  │  - Report/ticket/MISP   │
                  │  - Handoff to ops team  │
                  └─────────────────────────┘
```

### 2-1. Direction

- **What**: External exposed assets? Employee list? Specific executive's social media patterns?
- **Why**: Pre-penetration reconnaissance? M&A due diligence? Incident response?
- **Audience**: Technical team, legal team, client executives
- **Legal limits**: Korean Personal Information Protection Act, Information and Communications Network Act, Communications Secrets Protection Act, contractual NDA/RoE

If you don't answer questions like "Are we allowed to trace a GitHub commit with plaintext passwords all the way through?" at this stage, your hands will stop during analysis.

### 2-2. Collection

Collection splits into two branches:

| Category | Definition | Examples |
|---|---|---|
| Passive | No direct communication with target | crt.sh, Shodan cache, Google dork, archive.org |
| Active | Direct communication with target infrastructure | nmap, dirbuster, direct HTTP header requests |

The word OSINT usually refers to the passive domain, but in practice the line is often blurry (e.g., banner grabbing by Shodan may appear active from the target's perspective).

### 2-3. Processing

Collected data is almost always dirty:

- Domains need case normalization, trailing-dot handling, and IDN (internationalized domain) processing
- Emails need `+`, `.`, and case normalization (Gmail ignores `.`)
- IPs need IPv4/IPv6/CIDR unification
- Encoding: unify to UTF-8, prepare auto-recovery scripts for garbled Korean text

### 2-4. Analysis

Cluster processed data into **hypotheses**. Example: "This company uses AWS Seoul region, and an outsourced developer runs a self-hosted GitLab. It's likely that company employee SSH keys are registered in that outsourcer's GitLab."

Analysis outputs are one of the following:

- Target map: domain → asset → vulnerability candidates
- Org chart: employees, roles, email patterns
- Technology stack matrix: frameworks, versions, CVE mapping

### 2-5. Dissemination

- Penetration team: direct handoff to next stage (e.g., BloodHound input)
- Client report: PDF/HTML including sources and timestamps
- Threat intel: share as MISP/OpenCTI objects

---

## 3. Advanced Search Operators — Finishing 90% from the Search Bar

### 3-1. Google Dorking

The most commonly used operators:

| Operator | Meaning | Example |
|---|---|---|
| `site:` | Restrict to domain | `site:example.co.kr` |
| `-site:` | Exclude domain | `site:example.co.kr -site:blog.example.co.kr` |
| `intext:` | Body text match | `intext:"DB_PASSWORD"` |
| `intitle:` | Title match | `intitle:"index of /backup"` |
| `inurl:` | URL match | `inurl:admin inurl:login` |
| `filetype:` | Extension | `filetype:env` |
| `cache:` | Google cache | `cache:example.co.kr` (effectively deprecated after 2024) |
| `before:` / `after:` | Date range | `after:2025-01-01 before:2026-01-01` |
| `"..."` | Exact match | `"-----BEGIN RSA PRIVATE KEY-----"` |

Practical dork collection (use only on authorized domains):

```
site:example.co.kr filetype:env
site:example.co.kr filetype:sql intext:"INSERT INTO"
site:example.co.kr intitle:"phpinfo()"
site:example.co.kr inurl:"/.git/"
site:example.co.kr "DB_PASSWORD" OR "AWS_ACCESS_KEY"
site:s3.amazonaws.com "example"
site:trello.com "example.co.kr"
site:pastebin.com "example.co.kr"
```

> Caution: Google automatically detects dorking traffic and triggers reCAPTCHA/blocking. Don't run hundreds of queries from the same IP in a short time; use official APIs like SerpAPI or Brave Search API for stable results.

### 3-2. Differences Between Bing, DuckDuckGo

- **Bing**: `site:` and `filetype:` work identically. The `contains:` operator is still active, enabling patterns like `site:example.co.kr contains:bak`. The Bing Web Search v7 API ended in August 2025; its successor is being integrated into the Microsoft Copilot Search API.
- **DuckDuckGo**: Emphasizes privacy protection, so dorking results are sparser than Google/Bing. However, bang commands like `!g`, `!so`, `!gh` immediately delegate to other engines.
- **Naver/Daum**: For Korean domains like `.go.kr` or `.or.kr` with content indexed only domestically, Naver and Daum find more. However, advanced operators are weaker than Google.

### 3-3. GitHub Dorking

GitHub is by far the #1 channel for credential leaks.

```
org:exampleinc AWS_ACCESS_KEY_ID
org:exampleinc filename:.env DB_PASSWORD
org:exampleinc filename:id_rsa
org:exampleinc language:python "boto3.client" "aws_secret_access_key"
org:exampleinc path:.github/workflows secret
org:exampleinc extension:pem
"example.co.kr" "BEGIN OPENSSH PRIVATE KEY"
"@example.co.kr" filename:.env
```

Common credential patterns:

| Service | Regex |
|---|---|
| AWS Access Key | `AKIA[0-9A-Z]{16}` |
| AWS Secret | `(?i)aws.{0,20}?(secret|key).{0,20}?[a-z0-9/+=]{40}` |
| Slack Token | `xox[abprs]-[0-9a-zA-Z-]{10,48}` |
| GitHub PAT | `ghp_[A-Za-z0-9]{36}` |
| Stripe Live | `sk_live_[0-9a-zA-Z]{24}` |
| Google API | `AIza[0-9A-Za-z\\-_]{35}` |

### 3-4. What Never to Do in Code Search

- **GitHub TOS**: Automated multi-account scraping and rate limit circumvention are prohibited. The Search API caps at 30 authenticated calls per minute.
- **Korean Information and Communications Network Act Article 48**: Prohibits intrusion into information and communications systems. Public searching itself is legal, but using found credentials constitutes "unauthorized intrusion."
- **Personal Information Protection Act**: Scraping employee lists from GitHub and storing them in a separate DB is a processing (storage) act that may constitute processing without consent. A penetration testing contract must have an explicit delegation clause.

---

## 4. Device and Service Search Engines

### 4-1. Shodan

Shodan periodically scans all of IPv4 plus some IPv6 and indexes banners. Free accounts are limited to 10 results per page and 1 page; paid plans (`Membership`, `Freelancer`, `Corporate`) unlock filters, CSV export, and API.

Commonly used filters:

```
org:"Example Corp"
asn:AS17596
country:KR
port:3389
port:445 os:"Windows Server 2008"
ssl.cert.issuer.cn:"R3"
ssl.cert.subject.cn:*.example.co.kr
hostname:example.co.kr
http.title:"login"
http.favicon.hash:-247388890
product:nginx version:1.18.0
vuln:CVE-2024-3094
tag:ics
```

`http.favicon.hash` uses the mmh3 hash of a favicon to group all hosts with the same hash at once. Very powerful for identifying company assets whose admin panels share the same favicon.

### 4-2. Censys

Censys searches certificate, host, and software indexes with SQL-like queries similar to BigQuery. Since the 2025 redesign, the search UI is split into `Hosts`, `Certificates`, and `Web`.

```
services.tls.certificates.leaf_data.subject.common_name: *.example.co.kr
services.service_name: HTTP and services.http.response.body: "phpMyAdmin"
location.country: "South Korea" and services.port: 5432
autonomous_system.asn: 17596
```

### 4-3. FOFA / ZoomEye / Hunter.io

| Engine | Strengths | Weaknesses |
|---|---|---|
| FOFA (China) | ICS, domestically un-indexed assets | Lack of English UI, pricing |
| ZoomEye (China) | Industrial control, IoT firmware | Strict API limits |
| Hunter.io | Employee email patterns, per-domain lists | Many overlaps with public SNS |
| Quake (China, 360) | Fast indexing of new assets | Difficult registration |

For Korean IDC, KT, and LG U+ IP ranges, Shodan, Censys, and FOFA (in that order) are best. Running all three simultaneously and taking the union of results is a standard practice.

### 4-4. Pricing Comparison (Approximate 2026 figures, subject to change)

- Shodan Membership: $69/year (one-time), Freelancer $59/month, Corporate $1,099/month
- Censys Pro: $99/month
- FOFA Pro: approximately ¥4,200/year
- Hunter.io Starter: $49/month

For a company-level pentest team, the **Shodan Freelancer + Censys Pro + Hunter Growth** combination offers the best value.

---

## 5. Certificate Transparency (CT) Logs

CT (Certificate Transparency) is the RFC 6962 system that forces all issued certificates to be registered in public logs. If a target embeds a private hostname like `*.internal.example.co.kr` in a certificate, the entire world sees it instantly.

Commonly used sources:

- **crt.sh**: PostgreSQL-based, supports JSON output
- **Censys Certificates**: Rich metadata
- **Cloudflare Merkle Town**: Visualization + real-time stream
- **Google Argon/Yeti/Sabre**: Original log servers

### 5-1. Automated Subdomain Collection via crt.sh JSON (asyncio)

(See Korean section for full Python code — code comments are self-explanatory)

Run:

```bash
python ct_subdomains.py example.co.kr | tee subs.txt
```

If crt.sh is slow, use `https://api.certspotter.com/v1/issuances?domain=example.co.kr&include_subdomains=true&expand=dns_names` as a backup.

### 5-2. CT Result Pitfalls

- **Staging certificates**: Items issued by `Let's Encrypt Staging` CA may not be production certificates. Filter by `issuer_ca_id`.
- **Precertificates**: The same host appears twice. Sort by `min_cert_id` and deduplicate.
- **Expired certificates**: Separate items where `not_after` has passed into a different column. Separate DNS verification is needed to confirm assets are still live.

---

## 6. DNS and WHOIS-Based Asset Identification

CT is certificate-based, so assets using only plaintext HTTP won't appear. DNS and WHOIS must be checked as well.

### 6-1. Passive DNS

- **SecurityTrails**: 5 years of A/AAAA/MX/NS change history
- **VirusTotal Graph**: Domain ↔ IP ↔ sample graph
- **DNSDB (Farsight, now under DomainTools)**: Largest commercial DB
- **CIRCL Passive DNS**: Operated by European CERT, free registration

Usage is similar for all: submit a domain with an API key and receive a list of "IPs this domain pointed to in the past / domains this IP pointed to."

### 6-2. WHOIS / RDAP

Traditional WHOIS formats vary between KISA, Verisign, and APNIC. **RDAP** (RFC 7480) is the JSON-based successor standard, queried like `https://rdap.krnic.net/rdap/domain/example.co.kr`.

```bash
curl -s https://rdap.krnic.net/rdap/domain/example.co.kr | jq '.entities[].vcardArray[1]'
```

For Korean `.co.kr` domains, registrant information is often masked. Even just collecting the admin/technical contact email pattern (`@example.co.kr`) is a sufficient starting point.

### 6-3. Using Korean KISA Resources

- **KISA DNS Sinkhole Information**: Malware C2-classified domain lists updated daily. Cross-referencing whether target-owned domains appear here can provide IR incident clues.
- **KrCERT Security Advisories/Vulnerability Reports**: Understanding incident patterns in the target's industry.
- **Whois.kisa.or.kr**: Bulk lookup of `.kr` domains.

### 6-4. Asset Classification Table Example

Collected data organized in the following table can serve directly as input for the next phase (vulnerability mapping):

| Asset | Type | Source | First Observed | Notes |
|---|---|---|---|---|
| api.example.co.kr | Domain | crt.sh | 2024-08-12 | TLS 1.2, nginx 1.18 |
| 203.0.113.42 | IPv4 | Shodan | 2025-12-03 | port 22, 80, 443, 8080 |
| s3://example-backup | S3 Bucket | Google dork | 2026-02-19 | Suspected public-read |

---

## 7. Data Preservation and Provenance Management

OSINT results disappear in just a few days — CDN cache refreshes, GitHub force pushes, article edits/deletions, S3 permission changes. Therefore, **capture immediately upon collection** is the principle.

### 7-1. Capture Tools

- **SingleFile (browser extension)**: Saves HTML + images + CSS as a single `.html` file
- **Hunchly**: Automatic session-based capture, case ID assignment, OCR
- **archive.org Wayback Machine "Save Page Now"**: Obtain permanent URL
- **shot-scraper**: Headless Chrome-based CLI screenshot tool
- **wkhtmltopdf / weasyprint**: PDF conversion

### 7-2. Integrity Assurance Procedure

1. Save original capture (`.html`, `.png`, `.warc`)
2. Calculate SHA-256 hash → CSV log
3. Submit the log itself to an RFC 3161 timestamp server for signing
4. Separate folder per case, folder name includes ISO 8601 datetime

(See Korean section for full Python code)

If the evidence may be used in court, the operator's PC must be NTP-synchronized from the capture moment, and the tool/version/OS used for capture must also be recorded (so-called "provenance").

---

## 8. Automation Pipeline Example

A pipeline to run everything covered so far in one shot. Input: one domain. Output:

- Subdomains (CT logs)
- Email pattern (Hunter.io)
- Employee candidates (Hunter.io results + LinkedIn public IDs handled separately)
- Technology stack estimate (HTTP headers, favicon hash)

Concurrency controlled with httpx + asyncio + semaphore. Hunter.io and Shodan keys are injected via environment variables.

(See Korean section for full Python code)

The resulting JSON contains:

```json
{
  "domain": "example.co.kr",
  "subdomains": ["api.example.co.kr", "mail.example.co.kr", "..."],
  "email_pattern": "{first}.{last}@example.co.kr",
  "employees": [{"email": "kim.jinho@example.co.kr", "position": "DevOps"}],
  "tech": [
    {"host": "api.example.co.kr", "server": "nginx/1.18.0",
     "powered_by": null, "favicon_mmh3": -247388890}
  ]
}
```

This single JSON becomes the input for the next document (02 Target Profiling).

### 8-1. Operational Tips

- **Respect rate limits**: crt.sh handles 1–2 concurrent requests; Hunter allows 25 requests per minute.
- **Cache results**: Since the same domain is repeatedly investigated, SQLite or diskcache caching is recommended.
- **Evasion ≠ circumvention**: They're different. Identifying yourself with a User-Agent like `vibe-recon/1.0` makes accountability easier if an incident occurs.
- **Logging**: Record all external calls as `(timestamp, url, status, bytes)` in NDJSON format.

---

## 9. Legal and Ethical Boundaries

### 9-1. Korean and International Legal Matrix

| Action | Korean PIPA | Korean ICNA | Korean CSPA | EU GDPR | US CCPA |
|---|---|---|---|---|---|
| Collecting public employee names/titles | Caution (must specify purpose/retention) | Permitted | Permitted | Caution (legitimate interest) | Caution (right to cancel) |
| Collecting public employee email addresses | Caution (identifiable personal info) | Permitted | Permitted | Caution | Caution |
| Collecting public password hashes/plaintext | Prohibited (special info) | Effectively prohibited | Caution | Prohibited | Prohibited |
| Simply viewing GitHub-exposed credentials | Permitted | Permitted | Permitted | Permitted | Permitted |
| Logging in with GitHub-exposed credentials | Prohibited (unauthorized processing) | Prohibited (Art. 48) | Prohibited | Prohibited | Prohibited |
| Full nmap scan on target system | Caution | Prohibited (requires authorization) | Caution | Prohibited | Prohibited |
| Intercepting communications | Prohibited | Prohibited | Prohibited (very severe) | Prohibited | Prohibited |
| Purchasing leaked data on dark web markets | Prohibited | Prohibited | Prohibited | Prohibited | Prohibited |

### 9-2. Practical Checklist

Before starting work, confirm you can answer "yes" to all 5 questions:

1. Are the RoE (Rules of Engagement) and NDA signed?
2. Is the target asset scope (in-scope) clearly defined at the domain/CIDR/service level?
3. If collected data includes personal information, are retention and disposal procedures defined?
4. Is the capture storage location a controlled environment (encrypted disk, access control)?
5. Is there a 24/7 available client contact to notify in case of an incident?

### 9-3. Your Own Domain is the Safest

For learning practice, limit to **domains you or your company own**, **legal labs on HackTheBox/TryHackMe/PortSwigger Web Security Academy**, or **CTF servers**. The dork and Shodan queries shown above can be used as-is for monitoring your own assets.

---

## 10. Conclusion — Bridge to the Next Document

What we've gathered here is the **external appearance of assets**: domains, IPs, ports, employee email patterns, exposed credential candidates. But targets move through people and organizations. The next document (33-02 Target Profiling) elevates this asset data to the **people, roles, and relationships** dimension:

- Who has access to which systems
- What SaaS tools and messengers they use
- Who is the weakest link in social engineering scenarios

Once this is organized, the next step (33-03 Phishing Infrastructure) becomes almost entirely code and domain registration work. So the core deliverable of this stage compresses to one thing:

> "A single JSON containing all of the target's external assets and employee email patterns, and an evidence.csv recording the source, time, and hash of each."

Once these two files exist, 33-01 is complete. If either is missing, re-run `recon_pipeline.py` from section 8 and `capture_log.py` from section 7.

---

### Appendix A. Frequently Used Dork/Query Collection (for own asset verification)

```
# Google
site:example.co.kr (ext:env OR ext:bak OR ext:sql OR ext:log)
site:example.co.kr intext:"-----BEGIN RSA PRIVATE KEY-----"
site:example.co.kr inurl:wp-admin
site:s3.amazonaws.com "example"
site:trello.com "example"
site:atlassian.net "example.co.kr"

# GitHub
org:example "AKIA"
org:example filename:.env
"@example.co.kr" "BEGIN OPENSSH PRIVATE KEY"

# Shodan
hostname:example.co.kr
ssl.cert.subject.cn:*.example.co.kr
org:"Example Inc" port:3389
http.favicon.hash:-247388890

# Censys
services.tls.certificates.leaf_data.subject.common_name: *.example.co.kr
services.http.response.body: "Welcome to Example" and location.country: "South Korea"

# crt.sh
https://crt.sh/?q=%25.example.co.kr&output=json
```

### Appendix B. One-Line Environment Setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install "httpx>=0.27" "mmh3>=4.1" "rich>=13.7" "tldextract>=5.1"
export SHODAN_API_KEY="..."
export HUNTER_API_KEY="..."
```

### Appendix C. One-Page Practical Checklist

- [ ] RoE/NDA signed, scope documented
- [ ] No active scanning outside own domain/lab
- [ ] crt.sh + Shodan + Censys results merged into same JSON schema
- [ ] All captures have SHA-256 + ISO 8601 timestamp
- [ ] Paid APIs like Hunter and SecurityTrails have per-minute call counts documented
- [ ] After work: compress and encrypt `evidence.csv` + JSON in case folder
- [ ] Report body cites source URL, capture time, and hash as footnotes

---

When this document is complete, 90% of the target's external appearance is in hand. In 33-02, we fill that appearance with people.
