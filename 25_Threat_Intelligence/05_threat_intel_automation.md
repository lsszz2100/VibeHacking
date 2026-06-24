> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 위협 인텔리전스 자동화 — MISP·OpenCTI·IOC 보강·STIX/TAXII

## 0. 초보자를 위한 개념 이해

### 위협 인텔리전스란?

위협 인텔리전스(Threat Intelligence, TI)는 사이버 공격자, 그들의 도구, 전술, 절차(TTP)에 대한 정보를 수집·분석·공유하는 체계입니다. "어떤 IP가 우리를 공격할 수 있는가?"에 대한 근거 있는 답을 제공합니다.

```
위협 인텔리전스 유형:

  전술적 TI (Tactical):
    IOC (Indicator of Compromise): IP, 도메인, 해시, URL
    → 즉시 SIEM/방화벽에 적용 가능
    → 유효 기간 짧음 (IP는 수일~수주)

  운영적 TI (Operational):
    공격 캠페인 정보: 어떤 그룹이 어떤 방법으로?
    → 보안 운영팀 대응 계획 수립

  전략적 TI (Strategic):
    장기 위협 트렌드: 어떤 산업이 타겟?
    → CISO/경영진 의사결정 지원

  STIX 2.1 주요 객체:
    Indicator        → IOC 표현 (패턴 기반)
    Threat Actor     → 공격 그룹
    Attack Pattern   → MITRE ATT&CK TTPs
    Malware          → 악성코드 정보
    Campaign         → 공격 캠페인
    Relationship     → 객체 간 연관 관계
```

---

## 1. MISP 플랫폼 연동

### 1.1 MISP API 자동화

```bash
# MISP Docker 빠른 설치
git clone https://github.com/MISP/misp-docker
cd misp-docker
cp template.env .env
# .env에서 관리자 패스워드, 도메인 설정
docker compose up -d

# MISP API 키 생성
# MISP 웹UI → Administration → Auth Keys → Add auth key
```

```python
#!/usr/bin/env python3
"""
MISP API를 통한 IOC 자동 수집 및 이벤트 생성.
참고: https://pymisp.readthedocs.io/
pip install pymisp
"""
from __future__ import annotations

import argparse
import logging
from datetime import datetime, timezone
from typing import Optional

try:
    from pymisp import PyMISP, MISPEvent, MISPAttribute
except ImportError:
    print("pip install pymisp 필요")
    raise

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)


def connect_misp(url: str, api_key: str, verify_ssl: bool = True) -> PyMISP:
    """MISP 인스턴스 연결."""
    return PyMISP(url, api_key, ssl=verify_ssl)


def create_incident_event(
    misp: PyMISP,
    title: str,
    threat_level: int = 2,  # 1=High, 2=Medium, 3=Low, 4=Undefined
    iocs: Optional[dict[str, list[str]]] = None,
) -> dict:
    """
    인시던트 기반 MISP 이벤트 생성.
    iocs 예: {"ip-dst": ["1.2.3.4"], "domain": ["evil.example.com"], "md5": ["abc123..."]}
    """
    event = MISPEvent()
    event.info = title
    event.threat_level_id = threat_level
    event.analysis = 1  # 1=Ongoing
    event.distribution = 0  # 0=Your organisation only

    # 태그 추가
    event.add_tag("tlp:amber")
    event.add_tag("type:incident")

    # 속성(IOC) 추가
    if iocs:
        for attr_type, values in iocs.items():
            for value in values:
                attr = MISPAttribute()
                attr.type = attr_type
                attr.value = value
                attr.to_ids = True  # SIEM/IDS로 내보내기 표시
                event.add_attribute(**attr)

    result = misp.add_event(event)
    if hasattr(result, "id"):
        log.info("MISP 이벤트 생성 완료: ID=%s, 제목=%s", result.id, title)
        return {"id": result.id, "uuid": result.uuid}
    else:
        log.error("이벤트 생성 실패: %s", result)
        return {}


def search_ioc(misp: PyMISP, indicator: str) -> list[dict]:
    """IOC 검색 — IP, 도메인, 해시 등."""
    results = misp.search(value=indicator, pythonify=True)
    matches = []
    for event in results:
        for attr in event.attributes:
            if str(attr.value) == indicator:
                matches.append({
                    "event_id": event.id,
                    "event_title": event.info,
                    "type": attr.type,
                    "value": attr.value,
                    "threat_level": event.threat_level_id,
                    "timestamp": str(attr.timestamp),
                })
    return matches


def export_iocs_for_siem(
    misp: PyMISP,
    output_file: str = "misp_iocs.txt",
    attr_types: Optional[list[str]] = None,
) -> int:
    """MISP IOC를 SIEM 피드 형식(텍스트)으로 내보내기."""
    if attr_types is None:
        attr_types = ["ip-dst", "domain", "url", "md5", "sha256"]

    exported_count = 0
    with open(output_file, "w", encoding="utf-8") as f:
        for attr_type in attr_types:
            attrs = misp.search(type_attribute=attr_type, to_ids=True, pythonify=True)
            for attr in attrs:
                if hasattr(attr, "value"):
                    f.write(f"{attr.value}\n")
                    exported_count += 1

    log.info("SIEM 피드 내보내기 완료: %d IOC → %s", exported_count, output_file)
    return exported_count


def enrich_ip_with_misp(misp: PyMISP, ip: str) -> dict:
    """IP 주소 MISP 위협 인텔리전스 보강."""
    matches = search_ioc(misp, ip)
    return {
        "ip": ip,
        "found_in_misp": bool(matches),
        "event_count": len(matches),
        "threat_levels": list({m["threat_level"] for m in matches}),
        "events": matches[:3],  # 최대 3개
    }
```

---

## 2. STIX 2.1 위협 인텔리전스 생성 및 공유

### 2.1 STIX 객체 생성

```python
#!/usr/bin/env python3
"""
STIX 2.1 위협 인텔리전스 객체 생성 및 TAXII 서버 공유.
참고: https://stix2.readthedocs.io/
pip install stix2
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Optional

try:
    import stix2
    from stix2 import (
        Bundle, Indicator, Malware, ThreatActor,
        Relationship, AttackPattern, Campaign,
        Filter, MemoryStore,
    )
except ImportError:
    print("pip install stix2 필요")
    raise

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)


def create_malware_indicator(
    malware_name: str,
    file_hashes: dict[str, str],
    description: str = "",
    c2_ips: Optional[list[str]] = None,
) -> Bundle:
    """
    악성코드 관련 STIX 번들 생성.
    Malware + Indicator(해시) + Indicator(C2 IP) + Relationship.
    """
    now = datetime.now(timezone.utc)

    # 악성코드 객체
    malware_obj = Malware(
        name=malware_name,
        description=description or f"{malware_name} 악성코드",
        malware_types=["trojan"],
        is_family=False,
    )

    objects: list = [malware_obj]

    # 파일 해시 Indicator
    for hash_type, hash_value in file_hashes.items():
        hash_type_stix = hash_type.upper().replace("-", "")  # MD5, SHA256 등
        indicator = Indicator(
            name=f"{malware_name} 파일 해시 ({hash_type})",
            description=f"{malware_name} 바이너리 {hash_type} 해시",
            pattern=f"[file:hashes.'{hash_type_stix}' = '{hash_value}']",
            pattern_type="stix",
            indicator_types=["malicious-activity"],
            valid_from=now,
        )
        rel = Relationship(
            relationship_type="indicates",
            source_ref=indicator.id,
            target_ref=malware_obj.id,
        )
        objects.extend([indicator, rel])

    # C2 IP Indicator
    if c2_ips:
        for ip in c2_ips:
            ip_indicator = Indicator(
                name=f"{malware_name} C2 서버 IP",
                description=f"{malware_name} 커맨드앤컨트롤 서버",
                pattern=f"[network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value = '{ip}']",
                pattern_type="stix",
                indicator_types=["malicious-activity", "compromised"],
                valid_from=now,
            )
            rel = Relationship(
                relationship_type="indicates",
                source_ref=ip_indicator.id,
                target_ref=malware_obj.id,
            )
            objects.extend([ip_indicator, rel])

    bundle = Bundle(*objects)
    log.info("STIX 번들 생성 완료: %d 객체", len(bundle.objects))
    return bundle


def create_apt_profile(
    actor_name: str,
    aliases: list[str],
    target_sectors: list[str],
    mitre_techniques: list[str],
    known_malware: list[str],
) -> Bundle:
    """
    APT 그룹 STIX 프로파일 생성.
    ThreatActor + AttackPattern(ATT&CK) + Malware + 관계.
    """
    actor = ThreatActor(
        name=actor_name,
        aliases=aliases,
        threat_actor_types=["nation-state"],
        description=f"{actor_name} APT 그룹. 타겟 섹터: {', '.join(target_sectors)}",
        sophistication="advanced",
        resource_level="government",
    )

    objects: list = [actor]

    # ATT&CK 기법 매핑
    for technique_id in mitre_techniques:
        ap = AttackPattern(
            name=technique_id,
            description=f"MITRE ATT&CK {technique_id}",
            external_references=[{
                "source_name": "mitre-attack",
                "external_id": technique_id,
                "url": f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/",
            }],
        )
        rel = Relationship(
            relationship_type="uses",
            source_ref=actor.id,
            target_ref=ap.id,
        )
        objects.extend([ap, rel])

    return Bundle(*objects)


def save_bundle_to_file(bundle: Bundle, output_path: str) -> None:
    """STIX 번들을 JSON 파일로 저장."""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(bundle.serialize(pretty=True))
    log.info("STIX 번들 저장: %s", output_path)


def load_and_query_bundle(bundle_file: str, pattern: str = "") -> list:
    """STIX 번들 로드 후 필터 쿼리."""
    with open(bundle_file, encoding="utf-8") as f:
        bundle_data = json.load(f)

    store = MemoryStore()
    store.add(stix2.parse(json.dumps(bundle_data), allow_custom=True))

    if pattern:
        results = store.query([Filter("type", "=", pattern)])
    else:
        results = list(store.query())

    return results
```

---

## 3. IOC 자동 보강 파이프라인

```python
#!/usr/bin/env python3
"""
IOC 자동 보강 파이프라인.
IP/도메인/해시를 여러 위협 인텔 소스로 교차 확인.
참고: https://developers.virustotal.com/
"""
from __future__ import annotations

import hashlib
import logging
import time
from dataclasses import dataclass, field
from typing import Optional

import requests

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)


@dataclass
class IOCEnrichment:
    indicator: str
    indicator_type: str  # ip, domain, hash, url
    malicious_score: int = 0  # 0-100
    sources: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    context: dict = field(default_factory=dict)
    verdict: str = "unknown"  # clean/suspicious/malicious/unknown


def enrich_with_virustotal(
    indicator: str,
    indicator_type: str,
    api_key: str,
    delay: float = 15.0,  # 무료 API: 4req/분
) -> dict:
    """
    VirusTotal API v3 IOC 조회.
    실제 API 키를 환경 변수 VT_API_KEY에서 읽어야 함.
    """
    base_url = "https://www.virustotal.com/api/v3"
    headers = {"x-apikey": api_key}

    endpoint_map = {
        "ip": f"/ip_addresses/{indicator}",
        "domain": f"/domains/{indicator}",
        "hash": f"/files/{indicator}",
        "url": f"/urls/{indicator}",
    }

    endpoint = endpoint_map.get(indicator_type)
    if not endpoint:
        return {"error": f"지원하지 않는 유형: {indicator_type}"}

    try:
        resp = requests.get(f"{base_url}{endpoint}", headers=headers, timeout=10)
        time.sleep(delay)  # API 속도 제한

        if resp.status_code == 200:
            data = resp.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            total = sum(stats.values()) or 1
            return {
                "malicious": malicious,
                "total": total,
                "score": int(malicious / total * 100),
                "reputation": data.get("data", {}).get("attributes", {}).get("reputation", 0),
            }
        elif resp.status_code == 404:
            return {"score": 0, "note": "데이터 없음"}
        else:
            return {"error": f"HTTP {resp.status_code}"}
    except requests.RequestException as exc:
        return {"error": str(exc)}


def enrich_with_abuseipdb(ip: str, api_key: str) -> dict:
    """
    AbuseIPDB API로 IP 악성 여부 확인.
    참고: https://docs.abuseipdb.com/
    """
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 30},
            timeout=10,
        )
        if resp.status_code == 200:
            data = resp.json().get("data", {})
            return {
                "abuse_score": data.get("abuseConfidenceScore", 0),
                "is_whitelisted": data.get("isWhitelisted", False),
                "country_code": data.get("countryCode", ""),
                "total_reports": data.get("totalReports", 0),
                "isp": data.get("isp", ""),
            }
    except requests.RequestException as exc:
        return {"error": str(exc)}
    return {}


def bulk_enrich_iocs(
    iocs: list[dict[str, str]],
    vt_api_key: str = "",
    abuseipdb_key: str = "",
) -> list[IOCEnrichment]:
    """
    IOC 목록 일괄 보강.
    iocs: [{"indicator": "1.2.3.4", "type": "ip"}, ...]
    """
    results: list[IOCEnrichment] = []

    for ioc in iocs:
        indicator = ioc.get("indicator", "")
        itype = ioc.get("type", "ip")
        enrichment = IOCEnrichment(indicator=indicator, indicator_type=itype)

        # VirusTotal 보강
        if vt_api_key:
            vt = enrich_with_virustotal(indicator, itype, vt_api_key)
            score = vt.get("score", 0)
            enrichment.malicious_score = max(enrichment.malicious_score, score)
            if score > 0:
                enrichment.sources.append("virustotal")
            enrichment.context["virustotal"] = vt

        # AbuseIPDB 보강 (IP만)
        if abuseipdb_key and itype == "ip":
            abuse = enrich_with_abuseipdb(indicator, abuseipdb_key)
            abuse_score = abuse.get("abuse_score", 0)
            enrichment.malicious_score = max(enrichment.malicious_score, abuse_score)
            if abuse_score > 25:
                enrichment.sources.append("abuseipdb")
            enrichment.context["abuseipdb"] = abuse

        # 최종 판정
        if enrichment.malicious_score >= 75:
            enrichment.verdict = "malicious"
        elif enrichment.malicious_score >= 25:
            enrichment.verdict = "suspicious"
        elif enrichment.sources:
            enrichment.verdict = "clean"

        results.append(enrichment)
        log.info("[%s] %s → %s (score: %d)",
                 itype, indicator, enrichment.verdict, enrichment.malicious_score)

    return results


def main() -> None:
    import argparse
    import os

    parser = argparse.ArgumentParser(description="IOC 자동 보강 도구")
    parser.add_argument("indicators", nargs="+", help="조회할 IP/도메인/해시")
    parser.add_argument("--type", choices=["ip", "domain", "hash", "url"],
                        default="ip", help="IOC 유형")
    args = parser.parse_args()

    vt_key = os.environ.get("VT_API_KEY", "")
    abuse_key = os.environ.get("ABUSEIPDB_KEY", "")

    if not vt_key and not abuse_key:
        print("VT_API_KEY 또는 ABUSEIPDB_KEY 환경 변수 설정 필요")
        return

    iocs = [{"indicator": i, "type": args.type} for i in args.indicators]
    results = bulk_enrich_iocs(iocs, vt_key, abuse_key)

    for r in results:
        print(f"\n{r.indicator} [{r.indicator_type}]")
        print(f"  판정: {r.verdict} (점수: {r.malicious_score})")
        print(f"  소스: {', '.join(r.sources) or '없음'}")


if __name__ == "__main__":
    main()
```

---

## 4. TAXII 서버 연동

```python
#!/usr/bin/env python3
"""
TAXII 2.1 서버에서 위협 인텔리전스 피드 수집.
pip install taxii2-client
참고: https://taxii2client.readthedocs.io/
"""
from __future__ import annotations

import logging
from typing import Optional

try:
    from taxii2client.v21 import Server, Collection
except ImportError:
    print("pip install taxii2-client 필요")
    raise

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)


def connect_taxii_server(
    server_url: str,
    username: str = "",
    password: str = "",
) -> Server:
    """TAXII 2.1 서버 연결."""
    if username and password:
        server = Server(server_url, user=username, password=password)
    else:
        server = Server(server_url)
    log.info("TAXII 서버 연결: %s (타이틀: %s)", server_url, server.title)
    return server


def list_collections(server: Server) -> list[dict]:
    """사용 가능한 TAXII 컬렉션 목록 조회."""
    collections = []
    for api_root in server.api_roots:
        for collection in api_root.collections:
            collections.append({
                "api_root": api_root.url,
                "id": collection.id,
                "title": collection.title,
                "can_read": collection.can_read,
                "can_write": collection.can_write,
            })
            log.info("컬렉션: %s (%s)", collection.title, collection.id)
    return collections


def fetch_indicators(
    collection: Collection,
    added_after: Optional[str] = None,
    limit: int = 100,
) -> list[dict]:
    """컬렉션에서 Indicator 객체만 수집."""
    filters = [{"property": "type", "op": "=", "value": "indicator"}]
    if added_after:
        filters.append({"property": "added_after", "op": "=", "value": added_after})

    objects = collection.get_objects(limit=limit)
    indicators = []
    for obj in objects.get("objects", []):
        if obj.get("type") == "indicator":
            indicators.append({
                "id": obj.get("id"),
                "name": obj.get("name"),
                "pattern": obj.get("pattern"),
                "valid_from": obj.get("valid_from"),
                "indicator_types": obj.get("indicator_types", []),
            })
    return indicators
```

---

## 5. 참고 자료

- **MISP 공식 문서**: https://www.misp-project.org/documentation/
- **STIX 2.1 명세**: https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html
- **MITRE ATT&CK**: https://attack.mitre.org/

---

<!-- detect-validate-25 -->
## 위협 인텔 자동화 작동 검증과 회귀

인텔 자동화는 *돌렸다*가 아니라 *보강·검증·배포가 멱등하게 동작하는가*로 가치가 갈린다. 운영자는 **STIX 유효성·IOC 보강·자동 배포가 사일런트 실패 없이 동작하는가**를 검증해야 한다. 검증은 **소유 데이터/파이프라인**에서만.

### 검증 항목 → 질문 → 측정 신호 → 함정

| 검증 항목 | 질문 | 측정 신호 | 함정 |
|---|---|---|---|
| IOC 보강 | enrichment이 실제 붙나? | 보강 필드 채움률 | API 한도 무시 |
| STIX 유효성 | 스키마를 통과하나? | validator 오류 0 | 깨진 객체 전파 |
| 자동 배포 | 룰이 배포되나? | 배포 성공률 | 사일런트 실패 |
| 멱등성 | 중복 실행이 안전한가? | 재실행 후 중복 0 | 중복 알림 폭증 |

### 방어 검증 (직접 확인)

```bash
# 1) STIX 번들 유효성 — 깨진/빈 객체는 다운스트림 전파(소유 데이터)
python3 -c "import json; d=json.load(open('bundle.json')); print('objects:', len(d.get('objects', [])))" 2>&1 | head
# 2) IOC 보강 멱등성 — 중복 객체 ID는 멱등성 결함 신호
jq -r '.objects[].id' bundle.json 2>/dev/null | sort | uniq -d | head
```

> 인텔 자동화 검증은 *돌렸는가*가 아니라 *멱등하게 보강·배포되는가*다 — "파이프라인 있다"와 "STIX가 유효하고 재실행해도 중복이 안 생긴다"는 다르다. 소유 데이터에서 스키마 유효성·중복 ID를 직접 확인한다([[64_Threat_Intel_Platform]], [[40_Threat_Hunting]], [[68_Purple_Team]]).

---

<a name="english"></a>

# Threat Intelligence Automation — MISP, OpenCTI, IOC Enrichment, STIX/TAXII

## Overview

Threat Intelligence automation converts raw IOC data into actionable security decisions. The pipeline: collect → enrich → share → act.

## TI Automation Pipeline

```
External Feeds (TAXII, MISP, OSINT)
            ↓
IOC Enrichment (VirusTotal, AbuseIPDB, Shodan)
            ↓
STIX Bundle Creation (standardized format)
            ↓
MISP Event Storage (searchable, shareable)
            ↓
SIEM/Firewall Export (blocking rules, alerts)
            ↓
Automated Response (block IP, quarantine host)
```

## Key Standards

| Standard | Purpose | Tool |
|----------|---------|------|
| STIX 2.1 | Structured threat description | stix2 Python lib |
| TAXII 2.1 | Threat intel transport protocol | taxii2-client |
| MISP | TI sharing platform | PyMISP |
| OpenIOC | IOC format (legacy) | ioc-parser |

## Quick Start

```bash
# Install dependencies
pip install pymisp stix2 taxii2-client requests

# Enrich IOCs
export VT_API_KEY="your_key_here"
export ABUSEIPDB_KEY="your_key_here"
python3 ioc_enrichment.py 1.2.3.4 evil.example.com --type ip

# Create STIX bundle
python3 stix_creator.py --malware "TestRAT" --hash "abc123..."

# Sync with MISP
python3 misp_automation.py --url https://misp.example.com --export-iocs
```

## References

- MISP documentation: https://www.misp-project.org/documentation/
- STIX 2.1 specification: https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html
- MITRE ATT&CK: https://attack.mitre.org/

<!-- detect-validate-25 -->
## Threat-Intel Automation Effectiveness Validation and Regression

Intel automation's value comes not from *whether it ran* but from *whether enrichment, validation, and deployment work idempotently*. Operators must verify **whether STIX validity, IOC enrichment, and auto-deployment work without silent failure**. Validate only on **owned data/pipelines**.

### Check -> Question -> Signal -> Pitfall

| Check | Question | Signal | Pitfall |
|---|---|---|---|
| IOC enrichment | Is enrichment actually attached? | Enriched-field fill rate | Ignoring API limits |
| STIX validity | Does it pass schema? | Zero validator errors | Propagating broken objects |
| Auto-deployment | Do rules deploy? | Deployment success rate | Silent failure |
| Idempotency | Is re-running safe? | Zero duplicates after re-run | Duplicate-alert explosion |

### Defense validation (verify directly)

```bash
# 1) STIX bundle validity — broken/empty objects propagate downstream (owned data)
python3 -c "import json; d=json.load(open('bundle.json')); print('objects:', len(d.get('objects', [])))" 2>&1 | head
# 2) IOC-enrichment idempotency — duplicate object IDs signal an idempotency flaw
jq -r '.objects[].id' bundle.json 2>/dev/null | sort | uniq -d | head
```

> Intel-automation validation is *whether it enriches/deploys idempotently*, not *whether it ran* -- "we have a pipeline" differs from "STIX is valid and re-running produces no duplicates". Confirm schema validity and duplicate IDs on owned data directly ([[64_Threat_Intel_Platform]], [[40_Threat_Hunting]], [[68_Purple_Team]]).
