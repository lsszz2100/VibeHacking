> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 33-02. 타깃 프로파일링 — 도메인 하나에서 사람과 인프라 전체로 확장

## 0. 초보자를 위한 개념 이해

### 타깃 프로파일링이란?

**타깃 프로파일링(Target Profiling)**은 공격 대상에 대한 모든 공개 정보를 체계적으로 수집해 하나의 프로파일로 합치는 작업입니다. 도메인 하나에서 시작해 서버 IP, 직원 정보, 사용 기술, 이메일 패턴까지 연결합니다.

**왜 배우는가:**
```
정찰 없이 공격하면:
  - 어떤 서비스가 열려 있는지 모름
  - 피싱 메일 대상 직원 이메일 모름
  - 사용 기술 스택 몰라 적합한 익스플로잇 선택 불가

프로파일링 후:
  - 공격 표면 명확히 파악
  - 사회공학 공격 정교화 가능
```

### 핵심 수집 항목

```
도메인 → 프로파일 카드:

인프라 정보:
  DNS 레코드 (A, MX, TXT, SPF, DKIM)
  WHOIS 등록자 정보
  SSL 인증서 → 서브도메인 발견
  Shodan → 노출된 서비스

직원/인물 정보:
  LinkedIn → 직원 이름, 직급
  이메일 패턴 추론: firstname.lastname@company.com
  SNS → 개인 관심사 (스피어피싱에 활용)

기술 스택:
  wappalyzer → 웹 기술 파악
  BuiltWith → 프레임워크, CDN
  GitHub → 사용 언어, 오픈소스 프로젝트
```

### 필요한 도구
- **theHarvester**: 이메일·서브도메인 자동 수집
- **Amass**: 서브도메인 열거
- **Maltego**: 시각적 연결 분석

### 기초 실습 예제
```bash
# 도메인 프로파일링 기본 명령어
domain="target.com"
whois $domain | grep -E "Registrar:|Updated Date:|Creation Date:"
dig $domain MX +short    # 메일 서버
dig $domain TXT +short   # SPF/DKIM
# 서브도메인 발견
amass enum -passive -d $domain
```

---

## 0. 이 문서를 읽기 전에

이전 문서(33-01)에서는 OSINT의 큰 그림과 합법성 경계를 다뤘다. 이 문서는 한 단계 더 들어가, **한 도메인을 받았을 때 어떤 순서로 무엇을 수집하고 어떻게 한 덩어리의 데이터로 정리할지**를 다룬다. 가정은 다음과 같다.

- 모의침투 계약서(SOW)에 정찰 범위가 명시돼 있다
- 대상은 `example.com` 단일 루트 도메인이고 결과물은 후속 단계(피싱 시나리오, 외부 침투)에 그대로 넘길 수 있어야 한다
- 운영체제는 Ubuntu 22.04 또는 Kali 2026.1 계열, Python 3.10+ 가정

> 주의: 모든 도구 사용은 **소유 자산** 또는 **명시적 동의가 있는 자산**에 한정된다. 같은 명령을 동의 없는 제3자 도메인에 돌리는 순간 정통법·정보통신망법 위반 가능성이 생긴다.

---

## 1. 표적 프로파일이란 — 명단이 아니라 "행동 모델"

흔한 실수가 OSINT 결과를 "엑셀 한 장"으로 끝내는 것이다. 그러면 3주 뒤에 같은 표적을 다시 봤을 때 무엇이 달라졌는지 알 수 없다. 표적 프로파일은 정적 명단이 아니라 **자산(Assets)**, **사람(Identities)**, **습관(Patterns)** 셋을 동시에 담는 행동 모델이어야 한다. 한 곳에 보관하기 위해 우리는 **타깃 카드(JSON)**를 정의한다.

```json
{
  "schema_version": "2026.04",
  "target_id": "example-com-2026q2",
  "captured_at": "2026-04-25T09:30:00+09:00",
  "scope": {
    "in_scope_domains": ["example.com", "*.example.com"],
    "in_scope_cidr": ["203.0.113.0/24"],
    "out_of_scope": ["payroll.example.com"]
  },
  "assets": {"subdomains": [], "live_hosts": [], "tech_stack": [], "git_repos": []},
  "identities": [
    {"full_name": "홍길동", "role": "DevOps Lead",
     "emails": ["gd.hong@example.com"], "github": "ghong-dev",
     "evidence": ["공개 채용공고", "GitHub commit author"]}
  ],
  "patterns": {
    "email_format": "{first}.{last}@example.com",
    "tech_keywords": ["Spring Boot 3.x", "Kafka", "AWS EKS"],
    "deploy_window_kst": "화·목 14:00~16:00"
  },
  "hypotheses": [],
  "leaks": []
}
```

JSON으로 잡아두면 Maltego·BloodHound·Obsidian Graph 어떤 도구든 import 되고, diff가 가능해 "지난주 대비 새 서브도메인 12개 발견" 같은 일일 리포트가 자동 생성되며, LLM 기반 분석기에 그대로 컨텍스트로 넘길 수 있다.

---

## 2. 도메인 → 인프라 확장

```bash
mkdir -p ./recon/example.com/{passive,active,parsed,reports}
cd ./recon/example.com && export TARGET=example.com
```

### 2.1 theHarvester — 패시브 첫 단추

검색엔진·인증서·DNS 기반으로 이메일·서브도메인·IP를 모은다. 2026년 기준 v4.6 이후 `-b all`이 안정적이다.

```bash
theHarvester -d "$TARGET" -b all -l 500 -f passive/harvester.json 2>&1 | tee passive/harvester.log
```

`-b all`은 모든 소스(Bing, DuckDuckGo, crtsh, Anubis, HackerTarget 등), `-l 500`은 검색엔진 결과 500건까지, `-f`는 JSON·HTML·XML 저장이다.

```python
# parsed/parse_harvester.py — theHarvester JSON → 정규화된 카드 조각
from __future__ import annotations
import argparse, json, sys
from pathlib import Path
from typing import TypedDict

class HarvesterSlice(TypedDict):
    emails: list[str]; hosts: list[str]; ips: list[str]

def parse(path: Path) -> HarvesterSlice:
    raw = json.loads(path.read_text(encoding="utf-8"))
    return {
        "emails": sorted({e.strip().lower() for e in raw.get("emails", []) if "@" in e}),
        "hosts": sorted({h.strip().lower() for h in raw.get("hosts", []) if "." in h}),
        "ips": sorted({i.strip() for i in raw.get("ips", []) if i}),
    }

def main() -> int:
    p = argparse.ArgumentParser(description="theHarvester JSON parser")
    p.add_argument("input", type=Path)
    p.add_argument("--out", type=Path, default=Path("parsed/harvester.json"))
    args = p.parse_args()
    if not args.input.exists():
        print(f"[!] {args.input} 없음", file=sys.stderr); return 1
    sliced = parse(args.input)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(sliced, ensure_ascii=False, indent=2), "utf-8")
    print(f"[+] 이메일 {len(sliced['emails'])} / 호스트 {len(sliced['hosts'])} / IP {len(sliced['ips'])}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
```

### 2.2 Amass / Subfinder / Findomain — 셋을 합쳐라

| 도구 | 속도 | 패시브 소스 | 활성 모드 | 한 줄 평 |
|------|------|-------------|-----------|----------|
| Amass | 5~20분 | 80+ | 강력 | 가장 깊지만 가장 시끄러움 |
| Subfinder | 1~3분 | 50+ | 없음 | CI에서 매일 돌리기 좋음 |
| Findomain | 30초 | 20+ | 옵션 | 일회성 빠른 스냅샷용 |

```bash
subfinder -d "$TARGET" -all -silent -o passive/subfinder.txt &
findomain -t "$TARGET" -q -u passive/findomain.txt &
amass enum -passive -d "$TARGET" -o passive/amass.txt &
wait
sort -u passive/{subfinder,findomain,amass}.txt > parsed/subdomains.txt
wc -l parsed/subdomains.txt
```

`amass enum -passive`는 활성 DNS 질의를 안 보내 표적 권한 DNS 로그에 안 찍힌다. 모의침투 초기에는 패시브만 쓰는 게 안전하다.

### 2.3 dnsx + httpx — 살아있는 자산만 골라내기

서브도메인 1,000개 중 90%는 죽어 있거나 와일드카드다. 살아있는 것만 추리는 게 다음 단계.

```bash
dnsx -l parsed/subdomains.txt -a -resp -silent -o parsed/dns_alive.txt
httpx -l parsed/subdomains.txt -title -tech-detect -status-code \
  -content-length -json -silent -o parsed/httpx.jsonl
```

httpx 결과 한 줄 예시: `{"url":"https://api.example.com","status_code":200,"title":"API","tech":["Nginx","Spring Boot"]}`.

```python
# parsed/build_assets.py — httpx JSONL → assets.live_hosts/tech_stack
from __future__ import annotations
import argparse, json
from collections import Counter
from pathlib import Path
from typing import Any

def build(rows: list[dict[str, Any]]) -> dict[str, Any]:
    live: list[dict[str, Any]] = []
    tech: Counter[str] = Counter()
    for r in rows:
        live.append({"url": r.get("url"), "status": r.get("status_code"),
                     "title": r.get("title"), "tech": r.get("tech", [])})
        tech.update(r.get("tech", []))
    return {"live_hosts": live,
            "tech_stack": [{"name": k, "count": v} for k, v in tech.most_common()]}

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("input", type=Path)
    ap.add_argument("--out", type=Path, default=Path("parsed/live.json"))
    args = ap.parse_args()
    rows = [json.loads(l) for l in args.input.read_text("utf-8").splitlines() if l.strip()]
    out = build(rows)
    args.out.write_text(json.dumps(out, ensure_ascii=False, indent=2), "utf-8")
    print(f"[+] live={len(out['live_hosts'])} tech_unique={len(out['tech_stack'])}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
```

이 시점에서 우리는 표적이 어떤 프레임워크·CDN·WAF 뒤에 있는지, `dev.example.com` 같은 비공식 환경이 노출돼 있는지 안다. 마지막 항목이 자주 침투 시작점이 된다. 운영망은 잘 막혀 있어도 **개발/스테이징은 인증이 약하다**.

---

## 3. 사람 추적

### 3.1 LinkedIn — 한국 회사 직원 수집

한국 IT기업의 LinkedIn 노출은 부서별 편차가 크다. 글로벌 사업부·외국계 자회사는 노출이 높고, 공공 SI·금융권 내부 직원은 잡코리아·사람인 비중이 더 크다.

**약관·법 한계.** LinkedIn ToS는 자동 스크래핑을 금지한다. 2022년 hiQ Labs 판결로 "공개 데이터 스크래핑이 무조건 불법은 아니다"라고 정리됐지만 ToS 위반은 별개다. 한국에서는 공개된 직원 정보라도 결합해 신원을 특정하면 개인정보보호법 적용 대상이다. 모의침투 계약 안에서도 자동 스크래핑은 회색지대이고, **눈으로 보고 손으로 옮기는 수준**이 안전선이다.

`crosslinked`는 LinkedIn **검색결과 페이지**(공개)만 긁어 이름·직책 리스트를 만든다. 인증 없이 동작한다.

```bash
pip install crosslinked
crosslinked -f '{first}.{last}@example.com' -t 200 'Example Corp' -o passive/employees.csv
```

생성 CSV 예: `gd.hong@example.com,Hong Gil-Dong,Senior DevOps Engineer`. 이메일 형식은 추정이며 다음 절에서 검증한다.

### 3.2 GitHub — 자격증명 노출의 99%가 여기서 새어 나간다

```bash
gh repo list example-corp --limit 200 --json name,sshUrl \
  | jq -r '.[].sshUrl' | xargs -I {} -P 4 git clone {} ./mirror/
gitleaks detect --source ./mirror --report-path parsed/gitleaks.json --report-format json
trufflehog filesystem ./mirror --json --only-verified > parsed/trufflehog.json
```

`gitleaks`는 200+ 패턴(AWS 키·Slack 토큰·GCP SA 등)을 검사하고, `trufflehog`는 엔트로피 기반에 유효성 검증까지 한다. `--only-verified`가 핵심이다 — **여전히 살아있는 키만** 보고하므로 노이즈가 크게 준다.

**한 직원의 GitHub → 회사 비밀.** 직원 A의 개인 GitHub `ghong-dev`에서 사이드 프로젝트 `my-blog`를 발견했다고 하자. 옛날 커밋에 `application-dev.yml`이 잠깐 들어갔다 빠졌다면 `git log -p --all -- application-dev.yml`로 복원할 수 있고, 안에 사내 RDS 엔드포인트와 IAM access key가 살아있을 수 있다. 이 흐름은 2026년 현재도 한국 스타트업·중견 IT에서 매달 한두 건씩 재현된다. 직원 한 명이 회사 보안 경계를 통째로 무력화한다.

```python
# parsed/github_map.py — 직원 이름 → GitHub 후보 계정 매핑
from __future__ import annotations
import argparse, asyncio, json, os
from pathlib import Path
from typing import Any
import httpx

GH_API = "https://api.github.com"

async def search_user(c: httpx.AsyncClient, query: str) -> list[dict[str, Any]]:
    r = await c.get(f"{GH_API}/search/users", params={"q": query, "per_page": 5})
    r.raise_for_status()
    return r.json().get("items", [])

async def map_one(c: httpx.AsyncClient, name: str, company: str) -> dict[str, Any]:
    q = f'"{name}" in:fullname'
    if company: q += f' "{company}" in:bio'
    items = await search_user(c, q)
    return {"name": name,
            "candidates": [{"login": it["login"], "url": it["html_url"],
                            "score": it.get("score", 0)} for it in items]}

async def run(names: list[str], company: str, token: str | None) -> list[dict[str, Any]]:
    headers = {"Accept": "application/vnd.github+json"}
    if token: headers["Authorization"] = f"Bearer {token}"
    async with httpx.AsyncClient(headers=headers, timeout=20) as c:
        sem = asyncio.Semaphore(4)
        async def guarded(n: str) -> dict[str, Any]:
            async with sem: return await map_one(c, n, company)
        return await asyncio.gather(*(guarded(n) for n in names))

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("names", type=Path)
    ap.add_argument("--company", default="")
    ap.add_argument("--out", type=Path, default=Path("parsed/github_map.json"))
    args = ap.parse_args()
    names = [n.strip() for n in args.names.read_text("utf-8").splitlines() if n.strip()]
    res = asyncio.run(run(names, args.company, os.environ.get("GITHUB_TOKEN")))
    args.out.write_text(json.dumps(res, ensure_ascii=False, indent=2), "utf-8")
    print(f"[+] {len(res)}명 매핑 완료"); return 0

if __name__ == "__main__":
    raise SystemExit(main())
```

토큰은 명령어에 적지 말고 환경변수로 넘긴다(레포 CLAUDE.md 규칙). `export GITHUB_TOKEN=$(pass show github/recon-readonly)`.

### 3.3 X / Mastodon / Threads — 활동 패턴

타깃 한 명의 게시 시각은 그 사람의 **평일 일과 + 시차 + 출장 패턴**을 그대로 보여준다. 평일 09~18 KST 집중이면 사무직, 23~01시 집중이면 야간 운영. 위치 단서는 EXIF가 아니라 **캡션 속 지명·카페 태그·콘퍼런스 해시태그**에서 나오고, 트윗 클라이언트(iPhone vs Android)는 피싱 페이지 디자인 결정의 단서다. 2024년 X API 정책 변경 이후 `snscrape`는 제한이 많고, 2026년에는 Mastodon/Threads 공개 타임라인이 더 잘 긁힌다. 예: `curl -s "https://mastodon.social/@target.rss" | xq .`.

### 3.4 한국 특화 SNS

| 채널 | 정찰 가치 | 포인트 |
|------|-----------|--------|
| 네이버 블로그 | ★★★ | "회사 워크숍 후기"에 사옥 내부 사진·부서 인원수 노출 |
| 네이버 카페 | ★★ | 직무 카페 면접 후기 → 채용 절차·기술스택 공개 |
| 인스타그램 | ★★★ | 위치 태그가 가장 강력. 사옥/협력사 위치 단서 |
| 잡코리아·사람인 | ★★★★ | 채용공고 원문에 기술 스택, 인프라 규모 노출 |
| 로켓펀치·원티드 | ★★★ | 합병·투자 정보, 핵심 인력 이동 |
| 디스콰이엇·리멤버 | ★★ | 직장인 익명 글에서 사내 도구·정책 단서 |

---

## 4. 사용자명·이메일 정찰

### 4.1 Sherlock — 한 사용자명을 400+ 사이트에 동시 검색

```bash
pip install sherlock-project
sherlock ghong-dev --output parsed/sherlock_ghong.txt --timeout 10
```

```python
# parsed/sherlock_to_json.py
from __future__ import annotations
import argparse, json, re
from pathlib import Path

PATTERN = re.compile(r"^\[\+\]\s+([^:]+):\s+(https?://\S+)\s*$")

def parse(path: Path) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for line in path.read_text("utf-8").splitlines():
        m = PATTERN.match(line.strip())
        if m: out.append({"site": m.group(1).strip(), "url": m.group(2).strip()})
    return out

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("input", type=Path); ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    args.out.write_text(json.dumps(parse(args.input), ensure_ascii=False, indent=2), "utf-8")
    print(f"[+] {args.out}"); return 0

if __name__ == "__main__":
    raise SystemExit(main())
```

### 4.2 Holehe — 이 이메일이 어디 가입돼 있나

```bash
pip install holehe
holehe gd.hong@example.com --only-used --no-color > parsed/holehe.txt
```

`--only-used`는 가입 흔적이 확인된 사이트만 보고한다. GitHub 가입 흔적이 있으면 "GitHub 보안 알림" 위장이 자연스러워지는 식으로, 이 한 줄이 피싱 시나리오 설계 시 **어떤 브랜드를 흉내 낼지**를 결정한다.

### 4.3 haveibeenpwned — k-Anonymity 모델

HIBP는 비밀번호 평문이나 해시 전체를 보내지 않고 **SHA-1 해시 앞 5자**만 보낸 뒤, 그 prefix를 가진 모든 해시 묶음을 받아 클라이언트가 매칭한다. 서버는 어떤 비밀번호인지 모른다.

```python
# parsed/hibp_check.py
from __future__ import annotations
import argparse, hashlib
import httpx

def is_pwned(password: str) -> int:
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    r = httpx.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=10)
    r.raise_for_status()
    for line in r.text.splitlines():
        h, count = line.split(":")
        if h == suffix: return int(count)
    return 0

def main() -> int:
    ap = argparse.ArgumentParser(); ap.add_argument("password")
    args = ap.parse_args()
    n = is_pwned(args.password)
    print(f"노출 횟수: {n:,}" if n else "노출 이력 없음")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
```

이메일 단위·도메인 단위 조회는 별도 API 키와 도메인 소유 검증을 거쳐야 한다.

### 4.4 이메일 형식 추론과 검증

한국 회사 이메일 형식은 다섯 가지 안에서 거의 수렴한다.

| 패턴 | 예시 | 자주 보이는 곳 |
|------|------|----------------|
| `{first}.{last}@` | gildong.hong@ | 외국계, 글로벌 SaaS |
| `{firstinitial}{last}@` | ghong@ | 국내 IT 대기업·금융 |
| `{last}{firstinitial}@` | honggd@ | 공공기관·SI |
| `{korean_romanized}@` | hong_gd@ / hgd@ | 스타트업 |
| `{employee_id}@` | k123456@ | 일부 대기업·통신사 |

검증은 두 단계다. (1) Hunter.io / Skymem 같은 외부 서비스로 도메인 패턴 조회, (2) SMTP RCPT TO 직접 검증(주의: 표적 메일 서버 로그에 찍힘 → 모의침투 계약 범위 확인 필수). 다음 스크립트는 **검색만** 한다.

```python
# parsed/hunter.py — Hunter.io로 회사 이메일 패턴 추정
from __future__ import annotations
import argparse, os
import httpx

def fetch(domain: str, key: str) -> dict:
    r = httpx.get("https://api.hunter.io/v2/domain-search",
                  params={"domain": domain, "api_key": key, "limit": 25}, timeout=20)
    r.raise_for_status(); return r.json()

def main() -> int:
    ap = argparse.ArgumentParser(); ap.add_argument("domain")
    args = ap.parse_args()
    data = fetch(args.domain, os.environ["HUNTER_API_KEY"])
    print(f"패턴: {data['data'].get('pattern', '?')}")
    for e in [x['value'] for x in data['data'].get('emails', [])][:10]:
        print(f"  - {e}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
```

---

## 5. 그래프 시각화 — Maltego와 SpiderFoot

수집한 점들을 **선으로 잇는 순간** 새 가설이 보인다. 명단 상태에선 안 보이던 패턴이 그래프에서 갑자기 드러난다.

### 5.1 Maltego CE — 직접 만든 Local Transform

Maltego는 "Transform"이라는 작은 함수가 한 종류의 노드를 다른 종류로 변환한다(예: 도메인 → 서브도메인 N개). CE는 무료고, 로컬 Transform을 Python으로 만들 수 있다.

```python
# maltego_transforms/dnsx_subdomains.py — domain → subdomains via crt.sh
from __future__ import annotations
import sys
from xml.etree.ElementTree import Element, SubElement, tostring
import httpx

def crtsh(domain: str) -> list[str]:
    r = httpx.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=30)
    r.raise_for_status()
    names: set[str] = set()
    for row in r.json():
        for n in row.get("name_value", "").splitlines():
            n = n.strip().lower().lstrip("*.")
            if n.endswith(domain): names.add(n)
    return sorted(names)

def to_xml(items: list[str]) -> bytes:
    msg = Element("MaltegoMessage")
    tx = SubElement(msg, "MaltegoTransformResponseMessage")
    ents = SubElement(tx, "Entities")
    for value in items:
        e = SubElement(ents, "Entity", {"Type": "maltego.DNSName"})
        SubElement(e, "Value").text = value
    return tostring(msg)

def main() -> int:
    if len(sys.argv) < 2:
        print("usage: dnsx_subdomains.py <domain>", file=sys.stderr); return 2
    sys.stdout.buffer.write(to_xml(crtsh(sys.argv[1]))); return 0

if __name__ == "__main__":
    raise SystemExit(main())
```

Maltego CE에서 `Manage Local Transforms → New Local Transform`으로 등록하고 Input Entity Type을 `maltego.Domain`으로 잡는다. 이 한 개만 있어도 도메인을 더블클릭하면 서브도메인이 별처럼 펼쳐진다.

### 5.2 SpiderFoot — 자동 스캔 + JSON

SpiderFoot는 200+ 모듈을 켜고 끄는 식으로 자동 스캔한다.

```bash
spiderfoot -s "$TARGET" -t DOMAIN_NAME \
  -m sfp_dnsresolve,sfp_crossref,sfp_haveibeenpwned,sfp_threatcrowd,sfp_github \
  -F json -o spiderfoot.json
```

결과 JSON은 `(source, type, data)` 트리플 시퀀스다. BloodHound처럼 보고 싶다면 Cytoscape elements로 바꾼다.

```python
# parsed/sf_to_cytoscape.py
from __future__ import annotations
import argparse, json
from pathlib import Path

def convert(rows: list[dict]) -> dict:
    nodes: dict[str, dict] = {}
    edges: list[dict] = []
    for r in rows:
        src, typ, val = r["source"], r["type"], r["data"]
        for n in (src, val): nodes.setdefault(n, {"data": {"id": n, "label": n}})
        edges.append({"data": {"source": src, "target": val, "label": typ}})
    return {"nodes": list(nodes.values()), "edges": edges}

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("input", type=Path)
    ap.add_argument("--out", type=Path, default=Path("parsed/graph.json"))
    args = ap.parse_args()
    rows = json.loads(args.input.read_text("utf-8"))
    args.out.write_text(json.dumps(convert(rows), ensure_ascii=False, indent=2), "utf-8")
    print(f"[+] {args.out}"); return 0

if __name__ == "__main__":
    raise SystemExit(main())
```

이 JSON을 Cytoscape.js로 띄우면 무료로 BloodHound급 그래프가 나온다.

---

## 6. 한국 특화 OSINT 소스

- **DART 전자공시.** 상장사라면 사업보고서에 임원 명단·약력·보유 주식·자회사 지배구조가 그대로 있다. 임원 한 명을 표적으로 잡을 때 이 자료 한 장이 LinkedIn 50개와 맞먹는다. `curl -G "https://opendart.fss.or.kr/api/list.json" --data-urlencode "crtfc_key=$DART_KEY" --data-urlencode "corp_code=00126380"`.
- **국세청 사업자번호 조회.** 사업자번호 10자리만 있으면 개업일·과세유형·휴폐업 여부를 확인할 수 있다. 협력사 사칭 피싱을 만들 때 진짜 등록 사업자명을 확보하는 데 쓴다.
- **KIPRIS(특허청).** 표적 회사 이름으로 출원된 최근 5년 특허를 보면 개발 중인 기술이 그대로 드러난다. "양자내성암호 기반 키 교환"이 특허로 나왔다면 표적은 PQC 마이그레이션 중이고 그 과정의 중간 상태가 약점이 될 수 있다.
- **채용 공고 → 기술 스택 역추출.** 가장 효율적인 한국식 OSINT다. "Spring Boot 3.x, Kafka 3.6, AWS EKS 1.29, ArgoCD, OpenSearch 2.x"라는 한 줄에서 Java 17+, KRaft 모드 가능성, EKS 1.29 EOL 도래 시 업그레이드 윈도우, GitOps 사용 흔적, OpenSearch 기본 admin 가능성까지 다섯 개의 시작점이 나온다.
- **공공데이터포털 / KISA Whois.** 공공기관 IP 대역과 도메인 등록 정보, `.kr` 도메인 등록자(법인이면 공개, 개인이면 부분 마스킹)는 `whois example.kr` 한 줄로 시작한다.

---

## 7. 자동화 통합 스크립트

도메인 한 개를 입력으로 받아 위 절차의 핵심을 한 JSON으로 합친다.

```python
# tools/recon_aggregate.py — 도메인 → 통합 타깃 카드 생성기
from __future__ import annotations
import argparse, asyncio, json, os, shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import httpx


class ReconError(RuntimeError): ...


class TargetProfiler:
    def __init__(self, domain: str, workdir: Path, gh_token: str | None) -> None:
        self.domain = domain.lower().strip()
        self.workdir = workdir
        self.gh_token = gh_token
        self.workdir.mkdir(parents=True, exist_ok=True)

    def _need(self, binary: str) -> None:
        if shutil.which(binary) is None:
            raise ReconError(f"{binary} 미설치")

    async def subdomains(self) -> list[str]:
        self._need("subfinder")
        out = self.workdir / "subdomains.txt"
        proc = await asyncio.create_subprocess_exec(
            "subfinder", "-d", self.domain, "-all", "-silent", "-o", str(out)
        )
        await proc.wait()
        return sorted({l.strip() for l in out.read_text("utf-8").splitlines() if l.strip()})

    async def live_hosts(self, subs: list[str]) -> list[dict[str, Any]]:
        self._need("httpx")
        infile = self.workdir / "subs_input.txt"
        infile.write_text("\n".join(subs), "utf-8")
        outfile = self.workdir / "httpx.jsonl"
        proc = await asyncio.create_subprocess_exec(
            "httpx", "-l", str(infile), "-title", "-tech-detect",
            "-status-code", "-json", "-silent", "-o", str(outfile),
        )
        await proc.wait()
        if not outfile.exists(): return []
        return [json.loads(l) for l in outfile.read_text("utf-8").splitlines() if l.strip()]

    async def crtsh_emails(self) -> list[str]:
        async with httpx.AsyncClient(timeout=30) as c:
            r = await c.get(f"https://crt.sh/?q={self.domain}&output=json")
            r.raise_for_status()
            emails: set[str] = set()
            for row in r.json():
                blob = (row.get("name_value", "") + " " + row.get("issuer_name", "")).lower()
                for tok in blob.replace(",", " ").split():
                    if "@" in tok and tok.endswith(self.domain):
                        emails.add(tok.strip().strip(".,;"))
            return sorted(emails)

    async def github_org(self) -> dict[str, Any]:
        if not self.gh_token: return {"skipped": "no GITHUB_TOKEN"}
        org = self.domain.split(".")[0]
        async with httpx.AsyncClient(
            headers={"Authorization": f"Bearer {self.gh_token}"}, timeout=20
        ) as c:
            r = await c.get(f"https://api.github.com/orgs/{org}/repos?per_page=100")
            if r.status_code != 200: return {"skipped": f"org {org} not found"}
            return {"org_login": org,
                    "repos": [{"name": x["name"], "url": x["html_url"],
                               "stars": x["stargazers_count"]} for x in r.json()]}

    async def aggregate(self) -> dict[str, Any]:
        subs = await self.subdomains()
        live, emails, gh = await asyncio.gather(
            self.live_hosts(subs), self.crtsh_emails(), self.github_org()
        )
        tech: dict[str, int] = {}
        for row in live:
            for t in row.get("tech", []) or []:
                tech[t] = tech.get(t, 0) + 1
        return {
            "schema_version": "2026.04",
            "target_id": f"{self.domain}-{datetime.now().strftime('%Y%m%d')}",
            "captured_at": datetime.now(timezone.utc).isoformat(),
            "scope": {"in_scope_domains": [self.domain, f"*.{self.domain}"]},
            "assets": {
                "subdomains": subs,
                "live_hosts": [{"url": r.get("url"), "status": r.get("status_code"),
                                "title": r.get("title"), "tech": r.get("tech", [])}
                               for r in live],
                "tech_stack": [{"name": k, "count": v}
                               for k, v in sorted(tech.items(), key=lambda kv: -kv[1])],
            },
            "identities": [{"emails": [e]} for e in emails],
            "github": gh, "patterns": {}, "hypotheses": [], "leaks": [],
        }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("domain")
    ap.add_argument("--workdir", type=Path, default=Path("./recon"))
    ap.add_argument("--out", type=Path, default=Path("card.json"))
    args = ap.parse_args()
    profiler = TargetProfiler(args.domain, args.workdir / args.domain,
                              os.environ.get("GITHUB_TOKEN"))
    try:
        card = asyncio.run(profiler.aggregate())
    except ReconError as e:
        print(f"[!] {e}"); return 1
    args.out.write_text(json.dumps(card, ensure_ascii=False, indent=2), "utf-8")
    print(f"[+] {args.out} 작성 완료 (subdomains={len(card['assets']['subdomains'])})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

실행: `export GITHUB_TOKEN=$(pass show github/recon-readonly) && python tools/recon_aggregate.py example.com --out card_example.json`. 이 카드 한 장이 다음 단계(피싱 시나리오, 외부 침투, 사회공학)의 입력이 된다.

---

## 8. 데이터 정리와 가설 수립

수집은 끝이 아니라 시작이다. 모은 데이터에서 **"이 회사의 약한 고리"** 가설을 끌어내는 작업이 핵심이다. `reports/hypotheses.md`에 다음 표를 둔다.

| ID | 가설 | 근거 | 검증 방법 | 위험도 | 우선순위 |
|----|------|------|-----------|--------|----------|
| H-01 | `staging-old.example.com`에 인증이 없다 | httpx 200 + 로그인 폼 없음 | 브라우저 직접 접속 | 상 | 1 |
| H-02 | DevOps Lead의 GitHub 사이드 프로젝트에 사내 RDS 엔드포인트 노출 | gitleaks 매치 1건, 2024-11 | 키 만료 여부 확인 | 상 | 1 |
| H-03 | 채용공고로 미루어 ArgoCD 사용. GitOps 리포 노출 시 클러스터 통제 가능 | jobkorea/saramin 공고 3건 | 조직 GitHub `.argocd/` 검색 | 중 | 2 |
| H-04 | 홍보팀 임원이 자주 이용하는 카페가 사옥 1km 내 | 인스타그램 위치 태그 12회 | 물리 정찰(필요 시) | 하 | 3 |
| H-05 | 이메일 형식 `{firstinitial}{last}@example.com` | crosslinked + Hunter.io 일치 | SMTP 검증 시 로그 노출 → 보류 | 중 | 2 |

가설은 **검증 가능**해야 하고 **위험도/우선순위**가 매겨져 있어야 한다. 위험도 상이고 우선순위 1인 항목 두세 개가 다음 주 작업 대상이 된다. 가설 H-02를 시나리오로 풀면: (1) 키 유효성 확인(`aws sts get-caller-identity`, 범위 안일 때만) → (2) 권한 매핑(`enumerate-iam`) → (3) 침투 경로 도식화(개인 GitHub → 키 → IAM → S3 → 사내 정책) → (4) 보고서에 "한 명의 사이드 프로젝트로 회사 보안 경계가 한 번에 무너지는 시연"으로 정리. 이 흐름이 다음 문서(33-03)와 만난다.

---

## 9. 방어 측 관점 — 자기 회사 가시성 줄이기

같은 도구는 방어자가 더 자주 돌려야 한다. 자기 회사를 외부 시점에서 보는 게 가장 빠른 보안 점검이다.

**임직원 SNS 가이드라인.** 사옥 내부 사진(기둥·창문·천장 패턴이 위치 단서) SNS 업로드 금지, 콘퍼런스 발표 슬라이드 마지막 페이지의 사내 시스템 스크린샷 금지, 회사 도메인 이메일을 외부 서비스 회원가입에 쓰지 않기(별도 alias), 채용공고에 정확한 버전 번호 노출 금지("Spring Boot 최신 버전" 정도로 추상화), LinkedIn 프로필에 "특정 시스템명 + 운영 중" 같은 내부 식별자 금지.

**GitHub 비밀 자동 스캔.** 조직 단위로 매일 돌린다.

```yaml
# .github/workflows/secret-scan.yml
name: secret-scan
on: { schedule: [{ cron: '0 18 * * *' }] }
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: gitleaks/gitleaks-action@v2
        env: { GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }} }
```

추가로 GitHub Push Protection 켜기, 직원 개인 계정의 회사 코드 푸시 차단(SSO + IP 제한), 비밀 노출 발견 시 30분 내 키 회수 자동화(AWS Secrets Manager 회전 정책)를 둔다.

**외부 자산 모니터링.** 일 1회 `subfinder + httpx`를 자기 도메인에 돌려 새 자산이 생기면 Slack 알림, 인증서 투명성 로그(`crt.sh`) RSS 구독으로 신규 인증서 발급 즉시 감지, HIBP Domain Search로 직원 이메일이 새 유출에 등장하면 즉시 비밀번호 강제 변경.

**채용공고 검수.** 인사팀 → 보안팀 → 게시 순서로 30초만 검수해도 외부 정찰의 70%를 막을 수 있다. 보안팀이 채용공고를 1차 검수하는 회사가 아직 드물다.

---

## 10. 마무리 — 다음 문서로

이 문서에서 우리는 도메인 한 개를 받아 (1) 살아있는 자산 목록과 기술 스택, (2) 직원 이름·이메일 형식·GitHub 매핑, (3) 자격증명 유출 후보, (4) 가설 다섯 개와 우선순위를 만들었다.

다음 문서(`33_OSINT_Social_Engineering/03_social_engineering_techniques.md`)는 이 카드 한 장을 입력으로 받아 사회공학 공격 시나리오를 어떻게 설계하는지 다룬다. 가설 H-02 같은 기술적 약점을 비기술적 진입(전화·이메일)으로 어떻게 묶는가, 한국 직장 문화에서 통하는 가짜 사내 메일 패턴(인사팀·보안팀 사칭), 음성 피싱(vishing)과 QR 피싱(quishing)의 2026년 트렌드, 방어 측이 사람을 훈련시키는 측정 가능한 방법(피싱 시뮬레이션 KPI)이 주제다.

정찰의 끝은 침투의 시작이 아니라 **"가설"의 시작**이다. 가설이 정확할수록 다음 단계의 노이즈가 줄고, 노이즈가 줄수록 표적 시스템에 남기는 흔적이 줄고, 흔적이 줄수록 모의침투의 실전성이 올라간다.

— 33-02 끝.

---

<!-- detect-validate-33 -->
## 타깃 프로파일링 탐지와 노출 방어 검증

프로파일링은 *직원 명단·이메일 패턴·기술 스택·소셜 노출*로 도메인 하나에서 사람·인프라로 확장한다. 방어자는 **자체 조직의 프로파일 가능 표면이 통제되는가**를 검증해야 한다. 검증은 **소유 자산/공개 출처**에서만.

### 공격 → 노리는 약점 → 1차 통제(방어자) → 탐지 신호

| 기법 | 노리는 약점 | 1차 통제(방어자) | 탐지 신호 |
|---|---|---|---|
| 이메일 패턴 수집 | 예측 가능 형식 | 별칭·노출 최소 | 패턴 추정 성공 |
| 직원/소셜 노출 | 과다 공개 | 프라이버시 정책·인식 | 역할/연락처 노출 |
| 기술 스택 핑거프린팅 | 노출 헤더/배너 | 배너 최소화 | 버전 노출 |
| 유출 자격증명 연계 | 재사용 | HIBP·강제 변경 | 유출셋 일치 |

### 방어 검증 (직접 확인)

```bash
# 1) 자체 도메인 이메일/직원 노출 점검(소유 도메인, theHarvester) — 공개 표면
theHarvester -d example.com -b bing -l 100 2>/dev/null | grep -iE "@example.com" | head
# 2) 노출 기술 스택 핑거프린트 — 헤더/배너 버전 노출
curl -sI https://example.com 2>/dev/null | grep -iE "server|x-powered-by|x-aspnet"
```

> 프로파일링 방어는 *프로파일 표면이 좁은가*다 — "웹 있다"와 "이메일 패턴이 노출 안 되고 기술 스택 버전이 안 새며 유출 자격증명이 없다"는 다르다. 소유 도메인에서 공개 이메일·배너 노출을 직접 확인한다([[10_Pentest_Methodology]], [[22_Password_Cracking]], [[13_SOC_Blue_Team]]).

**최신 기법·통제 (2025–2026):**
- 소셜·유출·메타데이터 상관으로 프로파일링 — 최소수집·목적제한 원칙. 검증: 활동이 승인범위 내인가([[10_Pentest_Methodology]])
- 데이터 보존·삭제 — 강제되는지 확인

---

<a name="english"></a>

# 33-02. Target Profiling — Expanding from a Single Domain to People and Full Infrastructure

> One-line summary: The procedure and automation for taking a single domain as input and combining infrastructure, people, and credential exposures into a single profile card.

## Overview

In the previous document (33-01), we covered the big picture of OSINT and its legality boundaries. This document goes one level deeper, covering **what to collect in what order when given a domain, and how to organize it into a cohesive body of data**. The assumptions are:

- You are operating within a lawful penetration testing engagement
- You need to build a target profile from a single domain
- The goal is to create hypotheses about attack vectors

## Key Collection Steps

1. **Infrastructure mapping**: Subdomains, open ports, web technologies, cloud services
2. **Personnel mapping**: Employee names, email formats, GitHub accounts
3. **Credential exposure**: HIBP checks, credential dumps, leaked tokens
4. **Technology stack fingerprinting**: Detect CMS, frameworks, CDN, hosting providers

## Defense Perspective

**External asset monitoring.** Running `subfinder + httpx` against your own domain once daily with Slack alerts for new assets, subscribing to certificate transparency log (`crt.sh`) RSS for immediate detection of new certificate issuance, and using HIBP Domain Search to force immediate password changes when employee emails appear in new breaches.

**Job posting review.** Even 30 seconds of review — HR → Security → Post — can block 70% of external reconnaissance. Companies where the security team performs primary review of job postings are still rare.

## Conclusion

The end of reconnaissance is not the beginning of penetration but the beginning of **"hypotheses"**. The more accurate the hypothesis, the less noise in the next stage, the less noise the fewer traces left on the target system, and the fewer the traces the higher the realism of the penetration test.

— End of 33-02.

<!-- detect-validate-33 -->
## Target Profiling Detection and Exposure Defense Validation

Profiling expands from one domain to people and infrastructure via *employee rosters, email patterns, tech-stack, and social exposure*. Defenders must verify **whether their org's profilable surface is controlled**. Validate only on **owned assets/public sources**.

### Attack -> Targeted weakness -> Primary control (defender) -> Detection signal

| Technique | Targeted weakness | Primary control (defender) | Detection signal |
|---|---|---|---|
| Email-pattern harvesting | Predictable format | Aliases, minimize exposure | Pattern inference succeeds |
| Employee/social exposure | Over-sharing | Privacy policy, awareness | Role/contact exposed |
| Tech-stack fingerprinting | Exposed headers/banners | Minimize banners | Version exposed |
| Leaked-credential linkage | Reuse | HIBP, forced reset | Match against breach sets |

### Defense validation (verify directly)

```bash
# 1) Check your domain's email/employee exposure (owned domain, theHarvester) — public surface
theHarvester -d example.com -b bing -l 100 2>/dev/null | grep -iE "@example.com" | head
# 2) Fingerprint exposed tech stack — header/banner version exposure
curl -sI https://example.com 2>/dev/null | grep -iE "server|x-powered-by|x-aspnet"
```

> Profiling defense is *whether the profilable surface is narrow* -- "we have a website" differs from "email patterns aren't exposed, stack versions don't leak, and there are no leaked credentials". Confirm public email and banner exposure on owned domains directly ([[10_Pentest_Methodology]], [[22_Password_Cracking]], [[13_SOC_Blue_Team]]).
