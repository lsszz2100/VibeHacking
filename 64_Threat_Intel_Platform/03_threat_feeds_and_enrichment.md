> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 위협 피드 및 IoC 강화

## 0. 초보자를 위한 개념 이해

### 위협 피드(Threat Feed)란?

**위협 피드**는 지속적으로 업데이트되는 위협 인텔리전스 데이터 스트림입니다.

```
피드 구독 비유:
  뉴스 RSS 피드: 새 기사가 올라오면 자동으로 받음
  위협 피드:    새 IOC가 추가되면 자동으로 시스템에 반영
  
위협 피드 종류:
  무료 피드:
    - Abuse.ch의 MalwareBazaar: 악성코드 샘플 해시
    - Abuse.ch의 ThreatFox: C2 서버 IOC
    - URLhaus: 악성 URL
    - AlienVault OTX: 커뮤니티 위협 공유
    
  유료 피드:
    - CrowdStrike Intel
    - Recorded Future
    - Mandiant Threat Intelligence
```

### IOC 강화(Enrichment)란?

```
기본 IOC: IP 주소 "203.0.113.42"

강화 후:
  - ASN: AS12345 (알려진 불량 호스팅 회사)
  - 위치: 러시아 모스크바
  - 신뢰도: VirusTotal 72/90 엔진에서 악성
  - 카테고리: C2 서버 (Cobalt Strike)
  - 관련 캠페인: APT29 "Cozy Bear"
  - 첫 발견: 2026-01-15
  
강화 데이터 소스:
  - VirusTotal, Shodan, Censys
  - WHOIS, BGP 정보
  - 패시브 DNS
```

---

## 무료 위협 피드 목록

```
OSINT 피드 (무료)
├── AlienVault OTX — https://otx.alienvault.com/
├── Abuse.ch — URLhaus, MalwareBazaar, FeodoTracker
├── CIRCL OSINT — MISP 형식
├── Emerging Threats — Suricata/Snort 규칙
├── Malware Domain List — 악성 도메인
├── PhishTank — 피싱 URL
├── Spamhaus — IP/도메인 블랙리스트
├── GreyNoise — 인터넷 스캐너 IP
└── Shodan InternetDB — 취약한 호스트

상용 피드 (구독)
├── Recorded Future — 광범위한 다크웹/서피스웹
├── Intel 471 — 사이버 범죄 포럼 전문
├── Mandiant Advantage — APT 그룹 특화
├── CrowdStrike Falcon X — 악성코드 분석
└── Flashpoint — 다크웹 인텔리전스
```

## 위협 피드 수집 자동화

```python
#!/usr/bin/env python3
"""다중 위협 피드 자동 수집 및 정규화."""

import argparse
import urllib.request
import urllib.error
import json
import csv
import hashlib
import time
import sys
from pathlib import Path
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone


@dataclass
class ThreatIndicator:
    value: str
    ioc_type: str
    source: str
    first_seen: str
    last_seen: str
    tags: list[str] = field(default_factory=list)
    confidence: int = 50
    description: str = ""

    def __hash__(self) -> int:
        return hash(f"{self.ioc_type}:{self.value}")

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ThreatIndicator):
            return False
        return self.ioc_type == other.ioc_type and self.value == other.value


@dataclass
class FeedConfig:
    name: str
    url: str
    format: str  # csv, json, txt, misp
    ioc_type: str | None = None
    auth_header: str | None = None
    confidence: int = 70


FEED_CONFIGS = [
    FeedConfig(
        name="URLhaus_URLs",
        url="https://urlhaus.abuse.ch/downloads/csv_recent/",
        format="csv",
        ioc_type="url",
        confidence=85,
    ),
    FeedConfig(
        name="Feodo_C2",
        url="https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        format="txt",
        ioc_type="ip-dst",
        confidence=90,
    ),
    FeedConfig(
        name="PhishTank",
        url="https://data.phishtank.com/data/online-valid.json",
        format="json",
        ioc_type="url",
        confidence=80,
    ),
]


def fetch_feed(config: FeedConfig, timeout: int = 30) -> bytes | None:
    """피드 다운로드."""
    req = urllib.request.Request(config.url)
    req.add_header("User-Agent", "ThreatIntelCollector/1.0")
    if config.auth_header:
        req.add_header("Authorization", config.auth_header)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read()
    except urllib.error.URLError as e:
        print(f"[!] {config.name} 다운로드 실패: {e}", file=sys.stderr)
        return None


def parse_txt_feed(
    raw: bytes, ioc_type: str, source: str, confidence: int
) -> list[ThreatIndicator]:
    """일반 텍스트 피드 (한 줄에 하나의 IoC)."""
    indicators: list[ThreatIndicator] = []
    now = datetime.now(timezone.utc).isoformat()
    for line in raw.decode("utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        indicators.append(ThreatIndicator(
            value=line,
            ioc_type=ioc_type,
            source=source,
            first_seen=now,
            last_seen=now,
            confidence=confidence,
        ))
    return indicators


def parse_csv_urlhaus(raw: bytes, source: str) -> list[ThreatIndicator]:
    """URLhaus CSV 피드 파싱."""
    indicators: list[ThreatIndicator] = []
    now = datetime.now(timezone.utc).isoformat()
    lines = raw.decode("utf-8", errors="ignore").splitlines()
    # 헤더 건너뜀 (# 주석)
    data_lines = [l for l in lines if not l.startswith("#") and l.strip()]
    reader = csv.DictReader(data_lines)
    for row in reader:
        url = row.get("url", "").strip()
        tags = [t.strip() for t in row.get("tags", "").split(",") if t.strip()]
        if url:
            indicators.append(ThreatIndicator(
                value=url,
                ioc_type="url",
                source=source,
                first_seen=row.get("dateadded", now),
                last_seen=now,
                tags=tags,
                confidence=85,
                description=f"URLhaus: {row.get('threat', '')}",
            ))
    return indicators


def parse_phishtank(raw: bytes, source: str) -> list[ThreatIndicator]:
    """PhishTank JSON 피드 파싱."""
    indicators: list[ThreatIndicator] = []
    now = datetime.now(timezone.utc).isoformat()
    try:
        entries = json.loads(raw)
        for entry in entries[:1000]:  # 상위 1000개만
            url = entry.get("url", "").strip()
            if url:
                indicators.append(ThreatIndicator(
                    value=url,
                    ioc_type="url",
                    source=source,
                    first_seen=entry.get("submission_time", now),
                    last_seen=now,
                    tags=["phishing"],
                    confidence=80,
                    description=f"PhishTank ID: {entry.get('phish_id')}",
                ))
    except json.JSONDecodeError:
        pass
    return indicators


def deduplicate(indicators: list[ThreatIndicator]) -> list[ThreatIndicator]:
    """중복 제거 및 신뢰도 최대값 유지."""
    seen: dict[tuple, ThreatIndicator] = {}
    for ind in indicators:
        key = (ind.ioc_type, ind.value)
        if key not in seen or ind.confidence > seen[key].confidence:
            seen[key] = ind
    return list(seen.values())


def export_csv(indicators: list[ThreatIndicator], path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "value", "ioc_type", "source", "confidence",
            "first_seen", "last_seen", "tags", "description",
        ])
        writer.writeheader()
        for ind in indicators:
            writer.writerow({
                "value": ind.value,
                "ioc_type": ind.ioc_type,
                "source": ind.source,
                "confidence": ind.confidence,
                "first_seen": ind.first_seen,
                "last_seen": ind.last_seen,
                "tags": ",".join(ind.tags),
                "description": ind.description,
            })


def export_stix2_bundle(indicators: list[ThreatIndicator], path: Path) -> None:
    """간단한 STIX 2.1 번들 생성."""
    objects = []
    for ind in indicators:
        pattern = f"[{ind.ioc_type}:value = '{ind.value}']"
        # ip 유형 수정
        if ind.ioc_type in ("ip-src", "ip-dst"):
            pattern = f"[ipv4-addr:value = '{ind.value}']"
        elif ind.ioc_type == "url":
            safe_val = ind.value.replace("'", "\\'")
            pattern = f"[url:value = '{safe_val}']"
        elif ind.ioc_type in ("md5", "sha1", "sha256"):
            pattern = f"[file:hashes.{ind.ioc_type.upper()} = '{ind.value}']"
        elif ind.ioc_type == "domain":
            pattern = f"[domain-name:value = '{ind.value}']"

        obj_id = f"indicator--{hashlib.sha256(f'{ind.ioc_type}:{ind.value}'.encode()).hexdigest()[:36]}"
        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": obj_id,
            "created": ind.first_seen,
            "modified": ind.last_seen,
            "name": f"{ind.ioc_type}: {ind.value[:50]}",
            "description": ind.description,
            "indicator_types": ["malicious-activity"],
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": ind.first_seen,
            "labels": ind.tags,
            "confidence": ind.confidence,
        })

    bundle = {
        "type": "bundle",
        "id": f"bundle--{hashlib.sha256(str(time.time()).encode()).hexdigest()[:36]}",
        "spec_version": "2.1",
        "objects": objects,
    }
    path.write_text(json.dumps(bundle, indent=2))


def collect_all_feeds(configs: list[FeedConfig]) -> list[ThreatIndicator]:
    """모든 피드 병렬 수집."""
    all_indicators: list[ThreatIndicator] = []

    def fetch_and_parse(config: FeedConfig) -> list[ThreatIndicator]:
        raw = fetch_feed(config)
        if not raw:
            return []
        match config.format:
            case "txt":
                return parse_txt_feed(raw, config.ioc_type or "unknown",
                                      config.name, config.confidence)
            case "csv" if config.name.startswith("URLhaus"):
                return parse_csv_urlhaus(raw, config.name)
            case "json" if config.name == "PhishTank":
                return parse_phishtank(raw, config.name)
            case _:
                return []

    with ThreadPoolExecutor(max_workers=5) as ex:
        futures = {ex.submit(fetch_and_parse, c): c for c in configs}
        for fut in as_completed(futures):
            config = futures[fut]
            try:
                indicators = fut.result()
                print(f"[+] {config.name}: {len(indicators)}개 IoC")
                all_indicators.extend(indicators)
            except Exception as e:
                print(f"[!] {config.name} 오류: {e}", file=sys.stderr)

    return deduplicate(all_indicators)


def main() -> None:
    parser = argparse.ArgumentParser(description="위협 피드 자동 수집 도구")
    parser.add_argument("-o", "--output-dir", type=Path, default=Path("."))
    parser.add_argument("--format", choices=["csv", "stix", "both"], default="csv")
    parser.add_argument("--max-age-hours", type=int, default=24,
                        help="최신 캐시 사용 (시간)")
    args = parser.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)

    print(f"[*] 피드 수집 시작 ({len(FEED_CONFIGS)}개 피드)")
    indicators = collect_all_feeds(FEED_CONFIGS)
    print(f"\n[+] 총 수집 (중복 제거): {len(indicators)}개 IoC")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M")
    if args.format in ("csv", "both"):
        csv_path = args.output_dir / f"iocs_{timestamp}.csv"
        export_csv(indicators, csv_path)
        print(f"[+] CSV 저장: {csv_path}")

    if args.format in ("stix", "both"):
        stix_path = args.output_dir / f"bundle_{timestamp}.json"
        export_stix2_bundle(indicators, stix_path)
        print(f"[+] STIX 저장: {stix_path}")


if __name__ == "__main__":
    main()
```

## IoC 강화 (Enrichment)

```python
#!/usr/bin/env python3
"""IoC 강화 — VirusTotal, Shodan, AbuseIPDB 통합."""

import argparse
import urllib.request
import urllib.parse
import json
import time
import sys
from dataclasses import dataclass


@dataclass
class EnrichmentResult:
    ioc: str
    ioc_type: str
    vt_score: str = "N/A"
    vt_tags: list[str] | None = None
    abuse_score: int = 0
    shodan_ports: list[int] | None = None
    whois_org: str = ""
    malicious: bool = False


class VirusTotalEnricher:
    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str):
        self.api_key = api_key

    def _get(self, endpoint: str) -> dict | None:
        req = urllib.request.Request(
            f"{self.BASE_URL}/{endpoint}",
            headers={"x-apikey": self.api_key},
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return json.loads(resp.read())
        except Exception:
            return None

    def check_ip(self, ip: str) -> dict | None:
        data = self._get(f"ip_addresses/{ip}")
        if not data:
            return None
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        total = sum(stats.values())
        return {
            "score": f"{malicious}/{total}",
            "country": attrs.get("country"),
            "tags": attrs.get("tags", []),
            "malicious": malicious > 3,
        }

    def check_domain(self, domain: str) -> dict | None:
        data = self._get(f"domains/{domain}")
        if not data:
            return None
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        total = sum(stats.values())
        return {
            "score": f"{malicious}/{total}",
            "categories": attrs.get("categories", {}),
            "malicious": malicious > 3,
        }

    def check_hash(self, file_hash: str) -> dict | None:
        data = self._get(f"files/{file_hash}")
        if not data:
            return None
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        total = sum(stats.values())
        return {
            "score": f"{malicious}/{total}",
            "name": attrs.get("meaningful_name", ""),
            "type": attrs.get("type_description", ""),
            "malware_family": attrs.get("popular_threat_name", ""),
            "malicious": malicious > 5,
        }


class AbuseIPDBEnricher:
    BASE_URL = "https://api.abuseipdb.com/api/v2"

    def __init__(self, api_key: str):
        self.api_key = api_key

    def check_ip(self, ip: str, max_age_days: int = 30) -> dict | None:
        url = f"{self.BASE_URL}/check?ipAddress={ip}&maxAgeInDays={max_age_days}"
        req = urllib.request.Request(
            url,
            headers={
                "Key": self.api_key,
                "Accept": "application/json",
            }
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())
                d = data.get("data", {})
                return {
                    "score": d.get("abuseConfidenceScore", 0),
                    "country": d.get("countryCode"),
                    "reports": d.get("totalReports", 0),
                    "malicious": d.get("abuseConfidenceScore", 0) > 50,
                }
        except Exception:
            return None


def enrich_ioc(
    ioc: str,
    ioc_type: str,
    vt_key: str | None = None,
    abuse_key: str | None = None,
) -> EnrichmentResult:
    result = EnrichmentResult(ioc=ioc, ioc_type=ioc_type)

    if vt_key:
        vt = VirusTotalEnricher(vt_key)
        vt_data = None
        match ioc_type:
            case "ip-src" | "ip-dst":
                vt_data = vt.check_ip(ioc)
            case "domain" | "hostname":
                vt_data = vt.check_domain(ioc)
            case "md5" | "sha1" | "sha256":
                vt_data = vt.check_hash(ioc)
        if vt_data:
            result.vt_score = vt_data.get("score", "N/A")
            result.vt_tags = vt_data.get("tags", [])
            result.malicious = result.malicious or vt_data.get("malicious", False)

    if abuse_key and ioc_type in ("ip-src", "ip-dst"):
        abuse = AbuseIPDBEnricher(abuse_key)
        abuse_data = abuse.check_ip(ioc)
        if abuse_data:
            result.abuse_score = abuse_data.get("score", 0)
            result.malicious = result.malicious or abuse_data.get("malicious", False)

    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="IoC 강화 도구")
    parser.add_argument("ioc", help="강화할 IoC")
    parser.add_argument("--type", required=True,
                        choices=["ip-dst", "domain", "md5", "sha256"],
                        dest="ioc_type")
    parser.add_argument("--vt-key", help="VirusTotal API 키")
    parser.add_argument("--abuse-key", help="AbuseIPDB API 키")
    args = parser.parse_args()

    result = enrich_ioc(args.ioc, args.ioc_type, args.vt_key, args.abuse_key)

    print(f"\n{'='*50}")
    print(f"IoC     : {result.ioc}")
    print(f"유형    : {result.ioc_type}")
    print(f"VT 점수 : {result.vt_score}")
    print(f"Abuse점수: {result.abuse_score}")
    if result.vt_tags:
        print(f"태그    : {', '.join(result.vt_tags)}")
    print(f"악성 판정: {'예' if result.malicious else '아니오'}")


if __name__ == "__main__":
    main()
```

다음 파일에서 IoC 관리 자동화를 다룬다.


<!-- detect-validate-64 -->
## 피드·강화 검증 — 강화가 실제로 노이즈를 줄이는가

피드 강화는 *피드를 붙였다*가 아니라 **인디케이터가 실제 컨텍스트(평판·지오·관련 캠페인)로 강화되고, 오탐·노이즈(예: 공용 인프라 IP)가 걸러져 신뢰도가 올라가는가**로 판정한다. 검증은 **소유 TIP**에서만.

### 항목 → 실패 모드 → 검증 방법 → 양호 신호

| 항목 | 실패 모드 | 검증 방법 | 양호 신호 |
|---|---|---|---|
| 강화 적용 | 맨 IOC | 강화 필드 확인 | 평판·지오·관계 부가 |
| 노이즈 제거 | 화이트IP 차단 | 오탐 비율 측정 | 공용/허용 IP 제외 |
| 중복 상관 | 분산 중복 | 상관·병합 확인 | 동일 위협 묶임 |
| 신뢰 가중 | 단일 출처 맹신 | 다출처 교차검증 | 교차확인 시 가중 |

### 방어 검증 (직접 확인)

```bash
# 1) 인디케이터가 실제 강화 컨텍스트(평판/지오/관계)를 갖는지 — 소유 TIP에서만
curl -s -H "Authorization: $TIP_KEY" https://tip.local/api/indicators?limit=5 2>/dev/null | jq '.[] | {value, enrichment, confidence}' || echo "verify enrichment fields populated"
# 2) 알려진 양성(공용 DNS 등)이 차단 목록에 잘못 들어갔는지 점검(오탐)
printf '8.8.8.8\n1.1.1.1\n' | while read ip; do grep -q "$ip" blocklist.txt 2>/dev/null && echo "FALSE POSITIVE: $ip in blocklist"; done
```

> 검증은 반드시 **소유 TIP**에서만 한다. "피드를 붙였다"와 "강화가 노이즈를 줄인다"는 다르다 — 강화 필드·오탐으로 직접 확인한다([[25_Threat_Intelligence]], [[40_Threat_Hunting]]).

**최신 기법·통제 (2025–2026):**
- 다중피드 상관·인리치먼트·중복제거가 표준 — 오정보/오염 대응. 검증: 인리치가 근거와 함께 재현되는가([[40_Threat_Hunting]])
- 오탐 IOC 필터 — 강제되는지 확인

---

<a name="english"></a>

# Threat Feeds and IoC Enrichment

## Free Threat Feed List

```
OSINT feeds (free)
├── AlienVault OTX — https://otx.alienvault.com/
├── Abuse.ch — URLhaus, MalwareBazaar, FeodoTracker
├── CIRCL OSINT — MISP format
├── Emerging Threats — Suricata/Snort rules
├── Malware Domain List — Malicious domains
├── PhishTank — Phishing URLs
├── Spamhaus — IP/domain blocklists
├── GreyNoise — Internet scanner IPs
└── Shodan InternetDB — Vulnerable hosts

Commercial feeds (subscription)
├── Recorded Future — Broad dark web/surface web coverage
├── Intel 471 — Cybercrime forum specialization
├── Mandiant Advantage — APT group focus
├── CrowdStrike Falcon X — Malware analysis
└── Flashpoint — Dark web intelligence
```

## Threat Feed Collection Automation

```python
#!/usr/bin/env python3
"""Automated collection and normalization of multiple threat feeds."""

import argparse
import urllib.request
import urllib.error
import json
import csv
import hashlib
import time
import sys
from pathlib import Path
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone


@dataclass
class ThreatIndicator:
    value: str
    ioc_type: str
    source: str
    first_seen: str
    last_seen: str
    tags: list[str] = field(default_factory=list)
    confidence: int = 50
    description: str = ""

    def __hash__(self) -> int:
        return hash(f"{self.ioc_type}:{self.value}")

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ThreatIndicator):
            return False
        return self.ioc_type == other.ioc_type and self.value == other.value


@dataclass
class FeedConfig:
    name: str
    url: str
    format: str  # csv, json, txt, misp
    ioc_type: str | None = None
    auth_header: str | None = None
    confidence: int = 70


FEED_CONFIGS = [
    FeedConfig(
        name="URLhaus_URLs",
        url="https://urlhaus.abuse.ch/downloads/csv_recent/",
        format="csv",
        ioc_type="url",
        confidence=85,
    ),
    FeedConfig(
        name="Feodo_C2",
        url="https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        format="txt",
        ioc_type="ip-dst",
        confidence=90,
    ),
    FeedConfig(
        name="PhishTank",
        url="https://data.phishtank.com/data/online-valid.json",
        format="json",
        ioc_type="url",
        confidence=80,
    ),
]


def fetch_feed(config: FeedConfig, timeout: int = 30) -> bytes | None:
    """Download a feed."""
    req = urllib.request.Request(config.url)
    req.add_header("User-Agent", "ThreatIntelCollector/1.0")
    if config.auth_header:
        req.add_header("Authorization", config.auth_header)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read()
    except urllib.error.URLError as e:
        print(f"[!] {config.name} download failed: {e}", file=sys.stderr)
        return None


def parse_txt_feed(
    raw: bytes, ioc_type: str, source: str, confidence: int
) -> list[ThreatIndicator]:
    """Plain text feed (one IoC per line)."""
    indicators: list[ThreatIndicator] = []
    now = datetime.now(timezone.utc).isoformat()
    for line in raw.decode("utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        indicators.append(ThreatIndicator(
            value=line,
            ioc_type=ioc_type,
            source=source,
            first_seen=now,
            last_seen=now,
            confidence=confidence,
        ))
    return indicators


def parse_csv_urlhaus(raw: bytes, source: str) -> list[ThreatIndicator]:
    """Parse URLhaus CSV feed."""
    indicators: list[ThreatIndicator] = []
    now = datetime.now(timezone.utc).isoformat()
    lines = raw.decode("utf-8", errors="ignore").splitlines()
    # Skip headers (# comments)
    data_lines = [l for l in lines if not l.startswith("#") and l.strip()]
    reader = csv.DictReader(data_lines)
    for row in reader:
        url = row.get("url", "").strip()
        tags = [t.strip() for t in row.get("tags", "").split(",") if t.strip()]
        if url:
            indicators.append(ThreatIndicator(
                value=url,
                ioc_type="url",
                source=source,
                first_seen=row.get("dateadded", now),
                last_seen=now,
                tags=tags,
                confidence=85,
                description=f"URLhaus: {row.get('threat', '')}",
            ))
    return indicators


def parse_phishtank(raw: bytes, source: str) -> list[ThreatIndicator]:
    """Parse PhishTank JSON feed."""
    indicators: list[ThreatIndicator] = []
    now = datetime.now(timezone.utc).isoformat()
    try:
        entries = json.loads(raw)
        for entry in entries[:1000]:  # Top 1000 entries only
            url = entry.get("url", "").strip()
            if url:
                indicators.append(ThreatIndicator(
                    value=url,
                    ioc_type="url",
                    source=source,
                    first_seen=entry.get("submission_time", now),
                    last_seen=now,
                    tags=["phishing"],
                    confidence=80,
                    description=f"PhishTank ID: {entry.get('phish_id')}",
                ))
    except json.JSONDecodeError:
        pass
    return indicators


def deduplicate(indicators: list[ThreatIndicator]) -> list[ThreatIndicator]:
    """Remove duplicates while retaining the highest confidence score."""
    seen: dict[tuple, ThreatIndicator] = {}
    for ind in indicators:
        key = (ind.ioc_type, ind.value)
        if key not in seen or ind.confidence > seen[key].confidence:
            seen[key] = ind
    return list(seen.values())


def export_csv(indicators: list[ThreatIndicator], path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "value", "ioc_type", "source", "confidence",
            "first_seen", "last_seen", "tags", "description",
        ])
        writer.writeheader()
        for ind in indicators:
            writer.writerow({
                "value": ind.value,
                "ioc_type": ind.ioc_type,
                "source": ind.source,
                "confidence": ind.confidence,
                "first_seen": ind.first_seen,
                "last_seen": ind.last_seen,
                "tags": ",".join(ind.tags),
                "description": ind.description,
            })


def export_stix2_bundle(indicators: list[ThreatIndicator], path: Path) -> None:
    """Generate a simple STIX 2.1 bundle."""
    objects = []
    for ind in indicators:
        pattern = f"[{ind.ioc_type}:value = '{ind.value}']"
        # Normalize IP type
        if ind.ioc_type in ("ip-src", "ip-dst"):
            pattern = f"[ipv4-addr:value = '{ind.value}']"
        elif ind.ioc_type == "url":
            safe_val = ind.value.replace("'", "\\'")
            pattern = f"[url:value = '{safe_val}']"
        elif ind.ioc_type in ("md5", "sha1", "sha256"):
            pattern = f"[file:hashes.{ind.ioc_type.upper()} = '{ind.value}']"
        elif ind.ioc_type == "domain":
            pattern = f"[domain-name:value = '{ind.value}']"

        obj_id = f"indicator--{hashlib.sha256(f'{ind.ioc_type}:{ind.value}'.encode()).hexdigest()[:36]}"
        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": obj_id,
            "created": ind.first_seen,
            "modified": ind.last_seen,
            "name": f"{ind.ioc_type}: {ind.value[:50]}",
            "description": ind.description,
            "indicator_types": ["malicious-activity"],
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": ind.first_seen,
            "labels": ind.tags,
            "confidence": ind.confidence,
        })

    bundle = {
        "type": "bundle",
        "id": f"bundle--{hashlib.sha256(str(time.time()).encode()).hexdigest()[:36]}",
        "spec_version": "2.1",
        "objects": objects,
    }
    path.write_text(json.dumps(bundle, indent=2))


def collect_all_feeds(configs: list[FeedConfig]) -> list[ThreatIndicator]:
    """Collect all feeds in parallel."""
    all_indicators: list[ThreatIndicator] = []

    def fetch_and_parse(config: FeedConfig) -> list[ThreatIndicator]:
        raw = fetch_feed(config)
        if not raw:
            return []
        match config.format:
            case "txt":
                return parse_txt_feed(raw, config.ioc_type or "unknown",
                                      config.name, config.confidence)
            case "csv" if config.name.startswith("URLhaus"):
                return parse_csv_urlhaus(raw, config.name)
            case "json" if config.name == "PhishTank":
                return parse_phishtank(raw, config.name)
            case _:
                return []

    with ThreadPoolExecutor(max_workers=5) as ex:
        futures = {ex.submit(fetch_and_parse, c): c for c in configs}
        for fut in as_completed(futures):
            config = futures[fut]
            try:
                indicators = fut.result()
                print(f"[+] {config.name}: {len(indicators)} IoCs")
                all_indicators.extend(indicators)
            except Exception as e:
                print(f"[!] {config.name} error: {e}", file=sys.stderr)

    return deduplicate(all_indicators)


def main() -> None:
    parser = argparse.ArgumentParser(description="Automated threat feed collection tool")
    parser.add_argument("-o", "--output-dir", type=Path, default=Path("."))
    parser.add_argument("--format", choices=["csv", "stix", "both"], default="csv")
    parser.add_argument("--max-age-hours", type=int, default=24,
                        help="Use latest cache (hours)")
    args = parser.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)

    print(f"[*] Feed collection started ({len(FEED_CONFIGS)} feeds)")
    indicators = collect_all_feeds(FEED_CONFIGS)
    print(f"\n[+] Total collected (deduplicated): {len(indicators)} IoCs")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M")
    if args.format in ("csv", "both"):
        csv_path = args.output_dir / f"iocs_{timestamp}.csv"
        export_csv(indicators, csv_path)
        print(f"[+] CSV saved: {csv_path}")

    if args.format in ("stix", "both"):
        stix_path = args.output_dir / f"bundle_{timestamp}.json"
        export_stix2_bundle(indicators, stix_path)
        print(f"[+] STIX saved: {stix_path}")


if __name__ == "__main__":
    main()
```

## IoC Enrichment

```python
#!/usr/bin/env python3
"""IoC enrichment — VirusTotal, Shodan, AbuseIPDB integration."""

import argparse
import urllib.request
import urllib.parse
import json
import time
import sys
from dataclasses import dataclass


@dataclass
class EnrichmentResult:
    ioc: str
    ioc_type: str
    vt_score: str = "N/A"
    vt_tags: list[str] | None = None
    abuse_score: int = 0
    shodan_ports: list[int] | None = None
    whois_org: str = ""
    malicious: bool = False


class VirusTotalEnricher:
    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str):
        self.api_key = api_key

    def _get(self, endpoint: str) -> dict | None:
        req = urllib.request.Request(
            f"{self.BASE_URL}/{endpoint}",
            headers={"x-apikey": self.api_key},
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return json.loads(resp.read())
        except Exception:
            return None

    def check_ip(self, ip: str) -> dict | None:
        data = self._get(f"ip_addresses/{ip}")
        if not data:
            return None
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        total = sum(stats.values())
        return {
            "score": f"{malicious}/{total}",
            "country": attrs.get("country"),
            "tags": attrs.get("tags", []),
            "malicious": malicious > 3,
        }

    def check_domain(self, domain: str) -> dict | None:
        data = self._get(f"domains/{domain}")
        if not data:
            return None
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        total = sum(stats.values())
        return {
            "score": f"{malicious}/{total}",
            "categories": attrs.get("categories", {}),
            "malicious": malicious > 3,
        }

    def check_hash(self, file_hash: str) -> dict | None:
        data = self._get(f"files/{file_hash}")
        if not data:
            return None
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        total = sum(stats.values())
        return {
            "score": f"{malicious}/{total}",
            "name": attrs.get("meaningful_name", ""),
            "type": attrs.get("type_description", ""),
            "malware_family": attrs.get("popular_threat_name", ""),
            "malicious": malicious > 5,
        }


class AbuseIPDBEnricher:
    BASE_URL = "https://api.abuseipdb.com/api/v2"

    def __init__(self, api_key: str):
        self.api_key = api_key

    def check_ip(self, ip: str, max_age_days: int = 30) -> dict | None:
        url = f"{self.BASE_URL}/check?ipAddress={ip}&maxAgeInDays={max_age_days}"
        req = urllib.request.Request(
            url,
            headers={
                "Key": self.api_key,
                "Accept": "application/json",
            }
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())
                d = data.get("data", {})
                return {
                    "score": d.get("abuseConfidenceScore", 0),
                    "country": d.get("countryCode"),
                    "reports": d.get("totalReports", 0),
                    "malicious": d.get("abuseConfidenceScore", 0) > 50,
                }
        except Exception:
            return None


def enrich_ioc(
    ioc: str,
    ioc_type: str,
    vt_key: str | None = None,
    abuse_key: str | None = None,
) -> EnrichmentResult:
    result = EnrichmentResult(ioc=ioc, ioc_type=ioc_type)

    if vt_key:
        vt = VirusTotalEnricher(vt_key)
        vt_data = None
        match ioc_type:
            case "ip-src" | "ip-dst":
                vt_data = vt.check_ip(ioc)
            case "domain" | "hostname":
                vt_data = vt.check_domain(ioc)
            case "md5" | "sha1" | "sha256":
                vt_data = vt.check_hash(ioc)
        if vt_data:
            result.vt_score = vt_data.get("score", "N/A")
            result.vt_tags = vt_data.get("tags", [])
            result.malicious = result.malicious or vt_data.get("malicious", False)

    if abuse_key and ioc_type in ("ip-src", "ip-dst"):
        abuse = AbuseIPDBEnricher(abuse_key)
        abuse_data = abuse.check_ip(ioc)
        if abuse_data:
            result.abuse_score = abuse_data.get("score", 0)
            result.malicious = result.malicious or abuse_data.get("malicious", False)

    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="IoC enrichment tool")
    parser.add_argument("ioc", help="IoC to enrich")
    parser.add_argument("--type", required=True,
                        choices=["ip-dst", "domain", "md5", "sha256"],
                        dest="ioc_type")
    parser.add_argument("--vt-key", help="VirusTotal API key")
    parser.add_argument("--abuse-key", help="AbuseIPDB API key")
    args = parser.parse_args()

    result = enrich_ioc(args.ioc, args.ioc_type, args.vt_key, args.abuse_key)

    print(f"\n{'='*50}")
    print(f"IoC        : {result.ioc}")
    print(f"Type       : {result.ioc_type}")
    print(f"VT Score   : {result.vt_score}")
    print(f"Abuse Score: {result.abuse_score}")
    if result.vt_tags:
        print(f"Tags       : {', '.join(result.vt_tags)}")
    print(f"Malicious  : {'Yes' if result.malicious else 'No'}")


if __name__ == "__main__":
    main()
```

The next file covers IoC management automation.

<!-- detect-validate-64 -->
## Feeds & Enrichment Validation — Does Enrichment Actually Reduce Noise?

Feed enrichment is judged not by *having connected feeds* but by **whether indicators are actually enriched with context (reputation/geo/related campaigns) and false positives/noise (e.g., shared-infra IPs) are filtered so confidence rises**. Validate only on **owned TIPs**.

### Item -> Failure mode -> Validation method -> Healthy signal

| Item | Failure mode | Validation method | Healthy signal |
|---|---|---|---|
| Enrichment applied | Bare IOC | Check enrichment fields | Reputation/geo/relations added |
| Noise removal | Blocks whitelisted IP | Measure FP rate | Public/allowed IPs excluded |
| Dedup correlation | Scattered duplicates | Check correlation/merge | Same threat grouped |
| Confidence weighting | Trusts single source | Cross-source validation | Weighted on corroboration |

### Defense validation (verify directly)

```bash
# 1) Whether indicators actually carry enrichment context (reputation/geo/relations) — owned TIP only
curl -s -H "Authorization: $TIP_KEY" https://tip.local/api/indicators?limit=5 2>/dev/null | jq '.[] | {value, enrichment, confidence}' || echo "verify enrichment fields populated"
# 2) Check whether known-benign (public DNS, etc.) wrongly entered the blocklist (false positive)
printf '8.8.8.8\n1.1.1.1\n' | while read ip; do grep -q "$ip" blocklist.txt 2>/dev/null && echo "FALSE POSITIVE: $ip in blocklist"; done
```

> Validate only on **owned TIPs**. "Connected feeds" differs from "enrichment reduces noise" — confirm directly via enrichment fields and false positives ([[25_Threat_Intelligence]], [[40_Threat_Hunting]]).
