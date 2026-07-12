> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# CTI 플랫폼 운영

## 0. 초보자를 위한 개념 이해

### CTI 플랫폼을 직접 운영해야 하는가?

대부분의 조직은 상용 CTI 서비스(VirusTotal, CrowdStrike 등)를 사용하지만, 자체 플랫폼이 필요한 경우도 있습니다.

```
상용 CTI 서비스를 사용하면 좋은 경우:
  - 소규모 팀 (인력 부족)
  - 빠른 구축 필요
  - 유지관리 부담 없이 사용
  
자체 MISP/OpenCTI 운영이 필요한 경우:
  - 기밀 정보를 외부 서비스에 올릴 수 없는 조직
    (정부기관, 군, 방산, 금융)
  - 다른 조직과 IOC를 비공개로 공유
  - 커스터마이징이 필요한 경우
  - 비용 절감이 중요한 경우
```

### CTI 플랫폼 생태계

```
수집 → 처리 → 분석 → 공유 → 탐지

수집:
  OSINT 피드, 다크웹 모니터링
  ISAC, 파트너사 공유

처리:
  MISP, OpenCTI → IOC 정규화, 중복 제거

분석:
  Maltego → 관계 시각화
  MITRE ATT&CK → TTP 매핑

공유:
  TAXII 서버 → 자동 배포
  STIX 형식 → 표준화된 교환

탐지:
  SIEM (Splunk, Elastic) → 룰 적용
  방화벽, EDR → 차단 목록 업데이트
```

### STIX/TAXII 실전 이해

```
STIX (Structured Threat Information Expression):
  위협 정보를 JSON 형태로 구조화

  예시 STIX Indicator:
  {
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--8e2e2d2b-...",
    "name": "악성 C2 IP",
    "pattern": "[ipv4-addr:value = '203.0.113.42']",
    "valid_from": "2026-01-01T00:00:00Z",
    "labels": ["malicious-activity"]
  }

TAXII (Trusted Automated Exchange of Intelligence):
  STIX 데이터를 주고받는 API 규약
  
  TAXII 서버 → 구독 클라이언트들에게 자동 배포
  (마치 RSS 피드처럼 IOC를 구독)
```

---

MISP, OpenCTI 같은 오픈소스 위협 인텔리전스 플랫폼 운영과 IOC 관리, 위협 피드 자동화, STIX/TAXII 표준 연동을 다룬다. 실제 운영 환경에서 활용하는 자동화 스크립트를 중심으로 정리한다.

---

## 1. MISP 플랫폼

### 1.1 MISP 설치 및 초기 설정

```bash
# Docker Compose로 MISP 배포
cat > docker-compose.yml << 'EOF'
version: '3.8'
services:
  misp:
    image: ghcr.io/misp/misp-docker:latest
    ports:
      - "443:443"
      - "80:80"
    environment:
      MISP_ADMIN_EMAIL: "admin@example.com"
      MISP_ADMIN_PASSPHRASE: "ChangeMe2024!"
      MISP_BASEURL: "https://misp.local"
      MYSQL_HOST: db
      MYSQL_DATABASE: misp
      MYSQL_USER: misp
      MYSQL_PASSWORD: "DBPassword!"
    depends_on:
      - db
    volumes:
      - misp_data:/var/www/MISP

  db:
    image: mysql:8.0
    environment:
      MYSQL_ROOT_PASSWORD: "RootPass!"
      MYSQL_DATABASE: misp
      MYSQL_USER: misp
      MYSQL_PASSWORD: "DBPassword!"
    volumes:
      - mysql_data:/var/lib/mysql

volumes:
  misp_data:
  mysql_data:
EOF

docker compose up -d
```

### 1.2 PyMISP — 이벤트 자동 생성

```python
#!/usr/bin/env python3
"""MISP IOC 일괄 업로드 자동화"""
import argparse
import csv
import json
from pathlib import Path
from typing import Any

from pymisp import MISPEvent, MISPObject, PyMISP


def connect_misp(url: str, key: str, verify_ssl: bool = False) -> PyMISP:
    return PyMISP(url, key, ssl=verify_ssl)


def create_event(
    misp: PyMISP,
    title: str,
    threat_level: int = 2,
    distribution: int = 1,
    analysis: int = 1,
) -> MISPEvent:
    event = MISPEvent()
    event.info = title
    event.threat_level_id = threat_level   # 1=High, 2=Medium, 3=Low, 4=Undefined
    event.distribution = distribution       # 0=org only, 1=community, 3=all
    event.analysis = analysis               # 0=initial, 1=ongoing, 2=complete
    return misp.add_event(event, pythonify=True)


def add_iocs_from_csv(misp: PyMISP, event: MISPEvent, csv_path: Path) -> int:
    count = 0
    with csv_path.open() as f:
        reader = csv.DictReader(f)
        for row in reader:
            ioc_type = row.get("type", "").strip()
            value = row.get("value", "").strip()
            comment = row.get("comment", "").strip()

            if not value:
                continue

            type_map = {
                "ip": "ip-dst",
                "domain": "domain",
                "url": "url",
                "hash_md5": "md5",
                "hash_sha256": "sha256",
                "email": "email-src",
                "filename": "filename",
            }

            attr_type = type_map.get(ioc_type, "other")
            misp.add_attribute(event, {
                "type": attr_type,
                "value": value,
                "comment": comment,
                "to_ids": True,
            })
            count += 1

    return count


def search_ioc(misp: PyMISP, value: str) -> list[dict]:
    results = misp.search(value=value, pythonify=True)
    return [
        {
            "event_id": e.id,
            "title": e.info,
            "date": str(e.date),
            "threat_level": e.threat_level_id,
        }
        for e in results
    ]


def main() -> None:
    parser = argparse.ArgumentParser(description="MISP IOC 관리")
    parser.add_argument("--url", required=True, help="MISP URL")
    parser.add_argument("--key", required=True, help="API 키")
    subparsers = parser.add_subparsers(dest="command")

    upload_p = subparsers.add_parser("upload", help="CSV에서 IOC 업로드")
    upload_p.add_argument("csv_file")
    upload_p.add_argument("--title", required=True)

    search_p = subparsers.add_parser("search", help="IOC 검색")
    search_p.add_argument("value")

    args = parser.parse_args()
    misp = connect_misp(args.url, args.key)

    if args.command == "upload":
        event = create_event(misp, args.title)
        count = add_iocs_from_csv(misp, event, Path(args.csv_file))
        print(f"[+] 이벤트 생성: {event.id}, IOC {count}개 업로드")

    elif args.command == "search":
        results = search_ioc(misp, args.value)
        if results:
            for r in results:
                print(f"[+] 이벤트 {r['event_id']}: {r['title']} ({r['date']})")
        else:
            print("[-] 검색 결과 없음")


if __name__ == "__main__":
    main()
```

### 1.3 위협 피드 자동 가져오기

```python
#!/usr/bin/env python3
"""외부 위협 피드 → MISP 자동 동기화"""
import argparse
import hashlib
from datetime import datetime

import requests
from pymisp import MISPEvent, PyMISP


THREAT_FEEDS = {
    "feodotracker_ip": {
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        "type": "ip-dst",
        "comment": "Feodo Tracker C2 IP",
    },
    "urlhaus": {
        "url": "https://urlhaus.abuse.ch/downloads/text/",
        "type": "url",
        "comment": "URLhaus 악성 URL",
    },
}


def fetch_feed(url: str) -> list[str]:
    resp = requests.get(url, timeout=30)
    resp.raise_for_status()
    lines = []
    for line in resp.text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            lines.append(line)
    return lines


def sync_feed(misp: PyMISP, feed_name: str, feed_config: dict, limit: int = 500) -> None:
    iocs = fetch_feed(feed_config["url"])[:limit]
    print(f"[*] {feed_name}: {len(iocs)}개 IOC 가져옴")

    event = MISPEvent()
    event.info = f"자동 피드: {feed_name} ({datetime.now().date()})"
    event.threat_level_id = 2
    event.distribution = 1
    event.analysis = 1

    created = misp.add_event(event, pythonify=True)

    batch = [
        {"type": feed_config["type"], "value": ioc, "comment": feed_config["comment"], "to_ids": True}
        for ioc in iocs
    ]
    misp.add_attribute(created, batch)
    print(f"[+] 이벤트 {created.id} 생성 완료")


def main() -> None:
    parser = argparse.ArgumentParser(description="위협 피드 동기화")
    parser.add_argument("--url", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--feed", choices=list(THREAT_FEEDS.keys()), default="feodotracker_ip")
    parser.add_argument("--limit", type=int, default=500)
    args = parser.parse_args()

    misp = PyMISP(args.url, args.key, ssl=False)
    sync_feed(misp, args.feed, THREAT_FEEDS[args.feed], args.limit)


if __name__ == "__main__":
    main()
```

---

## 2. OpenCTI 플랫폼

### 2.1 OpenCTI API 연동

```python
#!/usr/bin/env python3
"""OpenCTI STIX 객체 조회 및 생성"""
import argparse
from pycti import OpenCTIApiClient


def connect_opencti(url: str, token: str) -> OpenCTIApiClient:
    return OpenCTIApiClient(url, token)


def list_indicators(client: OpenCTIApiClient, limit: int = 50) -> list[dict]:
    indicators = client.indicator.list(first=limit)
    return [
        {
            "id": ind["id"],
            "name": ind["name"],
            "pattern": ind.get("pattern", ""),
            "confidence": ind.get("confidence", 0),
            "valid_until": ind.get("valid_until", ""),
        }
        for ind in indicators
    ]


def create_ip_indicator(
    client: OpenCTIApiClient,
    ip: str,
    description: str = "",
    confidence: int = 75,
) -> str:
    indicator = client.indicator.create(
        name=f"Malicious IP: {ip}",
        description=description,
        pattern=f"[ipv4-addr:value = '{ip}']",
        pattern_type="stix",
        confidence=confidence,
        x_opencti_main_observable_type="IPv4-Addr",
    )
    return indicator["id"]


def search_threat_actors(client: OpenCTIApiClient, name: str) -> list[dict]:
    results = client.threat_actor.list(filters={"key": "name", "values": [name]})
    return [{"id": r["id"], "name": r["name"], "description": r.get("description", "")} for r in results]


def main() -> None:
    parser = argparse.ArgumentParser(description="OpenCTI API 도구")
    parser.add_argument("--url", required=True)
    parser.add_argument("--token", required=True)
    subparsers = parser.add_subparsers(dest="command")

    list_p = subparsers.add_parser("list-indicators")
    list_p.add_argument("--limit", type=int, default=20)

    add_p = subparsers.add_parser("add-ip")
    add_p.add_argument("ip")
    add_p.add_argument("--description", default="")

    search_p = subparsers.add_parser("search-actor")
    search_p.add_argument("name")

    args = parser.parse_args()
    client = connect_opencti(args.url, args.token)

    if args.command == "list-indicators":
        for ind in list_indicators(client, args.limit):
            print(f"[+] {ind['name']} | 신뢰도: {ind['confidence']} | {ind['pattern'][:60]}")

    elif args.command == "add-ip":
        ind_id = create_ip_indicator(client, args.ip, args.description)
        print(f"[+] 인디케이터 생성: {ind_id}")

    elif args.command == "search-actor":
        for actor in search_threat_actors(client, args.name):
            print(f"[+] {actor['name']}: {actor['description'][:100]}")


if __name__ == "__main__":
    main()
```

---

## 3. STIX/TAXII 표준 연동

### 3.1 STIX 2.1 객체 생성

```python
#!/usr/bin/env python3
"""STIX 2.1 위협 인텔리전스 패키지 생성"""
import argparse
import json
from datetime import datetime, timezone

from stix2 import (
    Bundle, Campaign, Indicator, IntrusionSet,
    Malware, Relationship, ThreatActor,
)


def create_apt_bundle(
    actor_name: str,
    malware_name: str,
    ioc_ip: str,
    ioc_domain: str,
) -> Bundle:
    actor = ThreatActor(
        name=actor_name,
        description=f"위협 행위자: {actor_name}",
        sophistication="advanced",
        resource_level="government",
        primary_motivation="espionage",
    )

    malware = Malware(
        name=malware_name,
        is_family=False,
        description=f"{actor_name} 사용 악성코드",
        malware_types=["backdoor"],
    )

    ip_indicator = Indicator(
        name=f"악성 IP: {ioc_ip}",
        pattern=f"[ipv4-addr:value = '{ioc_ip}']",
        pattern_type="stix",
        valid_from=datetime.now(timezone.utc),
        indicator_types=["malicious-activity"],
    )

    domain_indicator = Indicator(
        name=f"악성 도메인: {ioc_domain}",
        pattern=f"[domain-name:value = '{ioc_domain}']",
        pattern_type="stix",
        valid_from=datetime.now(timezone.utc),
        indicator_types=["malicious-activity"],
    )

    rel_uses = Relationship(actor, "uses", malware)
    rel_ip = Relationship(actor, "uses", ip_indicator)
    rel_domain = Relationship(actor, "uses", domain_indicator)

    return Bundle(actor, malware, ip_indicator, domain_indicator, rel_uses, rel_ip, rel_domain)


def main() -> None:
    parser = argparse.ArgumentParser(description="STIX 2.1 번들 생성")
    parser.add_argument("--actor", required=True, help="위협 행위자명")
    parser.add_argument("--malware", required=True, help="악성코드명")
    parser.add_argument("--ip", required=True, help="C2 IP")
    parser.add_argument("--domain", required=True, help="C2 도메인")
    parser.add_argument("-o", "--output", default="stix_bundle.json")
    args = parser.parse_args()

    bundle = create_apt_bundle(args.actor, args.malware, args.ip, args.domain)
    with open(args.output, "w") as f:
        f.write(bundle.serialize(pretty=True))
    print(f"[+] STIX 번들 저장: {args.output} ({len(bundle.objects)}개 객체)")


if __name__ == "__main__":
    main()
```

### 3.2 TAXII 2.1 클라이언트

```python
#!/usr/bin/env python3
"""TAXII 2.1 서버에서 위협 인텔리전스 수집"""
import argparse

from taxii2client.v21 import Server, as_pages


def list_collections(taxii_url: str, username: str = "", password: str = "") -> None:
    server = Server(taxii_url, user=username, password=password)
    for api_root in server.api_roots:
        print(f"[+] API Root: {api_root.title}")
        for collection in api_root.collections:
            print(f"  [*] 컬렉션: {collection.title} (ID: {collection.id})")


def fetch_indicators(
    taxii_url: str,
    collection_id: str,
    username: str = "",
    password: str = "",
    limit: int = 100,
) -> list[dict]:
    server = Server(taxii_url, user=username, password=password)
    indicators = []

    for api_root in server.api_roots:
        for collection in api_root.collections:
            if collection.id == collection_id:
                for bundle in as_pages(collection.get_objects, per_request=limit):
                    for obj in bundle.get("objects", []):
                        if obj.get("type") == "indicator":
                            indicators.append({
                                "id": obj["id"],
                                "name": obj.get("name", ""),
                                "pattern": obj.get("pattern", ""),
                                "valid_from": obj.get("valid_from", ""),
                            })
    return indicators


def main() -> None:
    parser = argparse.ArgumentParser(description="TAXII 클라이언트")
    parser.add_argument("url", help="TAXII 서버 URL")
    parser.add_argument("-u", "--username", default="")
    parser.add_argument("-p", "--password", default="")
    parser.add_argument("--collection", help="컬렉션 ID")
    parser.add_argument("--list", action="store_true", help="컬렉션 목록")
    args = parser.parse_args()

    if args.list:
        list_collections(args.url, args.username, args.password)
    elif args.collection:
        indicators = fetch_indicators(args.url, args.collection, args.username, args.password)
        for ind in indicators:
            print(f"[+] {ind['name']}: {ind['pattern'][:80]}")


if __name__ == "__main__":
    main()
```

---

## 4. IOC 관리 자동화

### 4.1 IOC 중복 제거 및 정규화

```python
#!/usr/bin/env python3
"""다중 피드 IOC 통합 및 정규화"""
import argparse
import ipaddress
import re
from collections import defaultdict
from pathlib import Path


class IOCNormalizer:
    IP_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    DOMAIN_RE = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")
    URL_RE = re.compile(r"^https?://")
    HASH_MD5 = re.compile(r"^[a-fA-F0-9]{32}$")
    HASH_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")

    def detect_type(self, value: str) -> str:
        value = value.strip()
        if self.HASH_SHA256.match(value):
            return "sha256"
        if self.HASH_MD5.match(value):
            return "md5"
        if self.URL_RE.match(value):
            return "url"
        if self.IP_RE.match(value):
            try:
                ipaddress.ip_address(value)
                return "ip"
            except ValueError:
                pass
        if self.DOMAIN_RE.match(value):
            return "domain"
        return "unknown"

    def normalize(self, value: str) -> str:
        return value.strip().lower()

    def process_file(self, path: Path) -> dict[str, set[str]]:
        iocs: dict[str, set[str]] = defaultdict(set)
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            ioc_type = self.detect_type(line)
            if ioc_type != "unknown":
                iocs[ioc_type].add(self.normalize(line))
        return iocs


def merge_feeds(files: list[Path]) -> dict[str, set[str]]:
    normalizer = IOCNormalizer()
    merged: dict[str, set[str]] = defaultdict(set)
    for path in files:
        feed_iocs = normalizer.process_file(path)
        for ioc_type, values in feed_iocs.items():
            merged[ioc_type].update(values)
    return merged


def main() -> None:
    parser = argparse.ArgumentParser(description="IOC 통합 도구")
    parser.add_argument("files", nargs="+", help="피드 파일 목록")
    parser.add_argument("-o", "--output", default="merged_iocs.csv")
    args = parser.parse_args()

    merged = merge_feeds([Path(f) for f in args.files])

    with open(args.output, "w") as out:
        out.write("type,value\n")
        for ioc_type, values in sorted(merged.items()):
            for v in sorted(values):
                out.write(f"{ioc_type},{v}\n")

    total = sum(len(v) for v in merged.values())
    print(f"[+] 총 {total}개 IOC 통합 완료 → {args.output}")
    for t, vals in sorted(merged.items()):
        print(f"  {t}: {len(vals)}개")


if __name__ == "__main__":
    main()
```

---

## 5. CTI 플랫폼 비교

| 항목 | MISP | OpenCTI | TheHive |
|------|------|---------|---------|
| 주요 용도 | IOC 공유 | 지식 그래프 | 사고 대응 |
| 표준 | MISP 형식, STIX | STIX 2.1 | MISP 연동 |
| API | REST + PyMISP | GraphQL | REST |
| 커뮤니티 | CIRCL 주도 | Filigran | StrangeBee |
| 피드 통합 | 다양한 공식 피드 | TAXII 네이티브 | MISP 경유 |
| 설치 난이도 | 중간 | 복잡 (Elasticsearch) | 중간 |

### 5.1 통합 아키텍처

```
외부 피드 (TAXII / HTTP)
         ↓
    피드 수집기 (Python)
         ↓
     MISP / OpenCTI
      ↙         ↘
   SIEM          SOAR
(Splunk/ELK)  (Shuffle/XSOAR)
```

---

<!-- detect-validate-25 -->
## CTI 플랫폼 운영 검증 (피드 통합·탐지 전환)

CTI 플랫폼은 *설치했다*가 아니라 *피드가 살아 있고 탐지로 흐르는가*로 가치가 갈린다. 운영자는 **피드 수집·중복제거·SIEM 연동·TAXII 동기가 실제 동작하는가**를 검증해야 한다. 검증은 **소유 플랫폼**에서만.

### 검증 항목 → 질문 → 측정 신호 → 함정

| 검증 항목 | 질문 | 측정 신호 | 함정 |
|---|---|---|---|
| 피드 수집 | 피드가 실제 들어오나? | 신규 indicator/일 | 죽은 피드 방치 |
| 중복제거 | 중복 IOC를 거르나? | 중복률 | 노이즈 폭증 |
| 탐지 연동 | SIEM 룰로 가나? | IOC→룰 매핑률 | 보관만 됨 |
| TAXII 동기화 | 양방향 동작하나? | 마지막 동기 시각 | 토큰 만료 |

### 방어 검증 (직접 확인)

```bash
# 1) TAXII/피드 동기 신선도 — 마지막 수집 시각이 오래됐으면 죽은 피드
curl -s -H "Accept: application/taxii+json;version=2.1" "https://taxii.example/collections" 2>/dev/null | jq '.collections[].title' | head
# 2) 수집 IOC가 탐지로 전환됐는지 — 미매핑 indicator는 보관용일 뿐
jq -r '.objects[] | select(.type=="indicator") | .pattern' feed.json 2>/dev/null | wc -l
```

> 플랫폼 운영 검증은 *깔았는가*가 아니라 *피드가 살아 탐지로 흐르는가*다 — "MISP 있다"와 "피드가 갱신되고 IOC가 SIEM 룰로 매핑된다"는 다르다. 소유 플랫폼에서 동기 신선도·룰 전환을 직접 확인한다([[64_Threat_Intel_Platform]], [[40_Threat_Hunting]], [[13_SOC_Blue_Team]]).

**최신 기법·통제 (2025–2026):**
- TIP(MISP/OpenCTI)로 IOC 정규화·품질필터·배포 — 검증: 저품질 IOC가 자동차단 전 필터링되는가([[64_Threat_Intel_Platform]])
- 피드 상관·중복제거 — 강제되는지 확인

---

<a name="english"></a>

# CTI Platform Operations

This section covers operating open-source threat intelligence platforms such as MISP and OpenCTI, including IOC management, threat feed automation, and STIX/TAXII standard integration. The focus is on automation scripts used in real production environments.

---

## 1. MISP Platform

### 1.1 MISP Installation and Initial Configuration

```bash
# Deploy MISP with Docker Compose
cat > docker-compose.yml << 'EOF'
version: '3.8'
services:
  misp:
    image: ghcr.io/misp/misp-docker:latest
    ports:
      - "443:443"
      - "80:80"
    environment:
      MISP_ADMIN_EMAIL: "admin@example.com"
      MISP_ADMIN_PASSPHRASE: "ChangeMe2024!"
      MISP_BASEURL: "https://misp.local"
      MYSQL_HOST: db
      MYSQL_DATABASE: misp
      MYSQL_USER: misp
      MYSQL_PASSWORD: "DBPassword!"
    depends_on:
      - db
    volumes:
      - misp_data:/var/www/MISP

  db:
    image: mysql:8.0
    environment:
      MYSQL_ROOT_PASSWORD: "RootPass!"
      MYSQL_DATABASE: misp
      MYSQL_USER: misp
      MYSQL_PASSWORD: "DBPassword!"
    volumes:
      - mysql_data:/var/lib/mysql

volumes:
  misp_data:
  mysql_data:
EOF

docker compose up -d
```

### 1.2 PyMISP — Automated Event Creation

```python
#!/usr/bin/env python3
"""Automated MISP IOC bulk upload"""
import argparse
import csv
import json
from pathlib import Path
from typing import Any

from pymisp import MISPEvent, MISPObject, PyMISP


def connect_misp(url: str, key: str, verify_ssl: bool = False) -> PyMISP:
    return PyMISP(url, key, ssl=verify_ssl)


def create_event(
    misp: PyMISP,
    title: str,
    threat_level: int = 2,
    distribution: int = 1,
    analysis: int = 1,
) -> MISPEvent:
    event = MISPEvent()
    event.info = title
    event.threat_level_id = threat_level   # 1=High, 2=Medium, 3=Low, 4=Undefined
    event.distribution = distribution       # 0=org only, 1=community, 3=all
    event.analysis = analysis               # 0=initial, 1=ongoing, 2=complete
    return misp.add_event(event, pythonify=True)


def add_iocs_from_csv(misp: PyMISP, event: MISPEvent, csv_path: Path) -> int:
    count = 0
    with csv_path.open() as f:
        reader = csv.DictReader(f)
        for row in reader:
            ioc_type = row.get("type", "").strip()
            value = row.get("value", "").strip()
            comment = row.get("comment", "").strip()

            if not value:
                continue

            type_map = {
                "ip": "ip-dst",
                "domain": "domain",
                "url": "url",
                "hash_md5": "md5",
                "hash_sha256": "sha256",
                "email": "email-src",
                "filename": "filename",
            }

            attr_type = type_map.get(ioc_type, "other")
            misp.add_attribute(event, {
                "type": attr_type,
                "value": value,
                "comment": comment,
                "to_ids": True,
            })
            count += 1

    return count


def search_ioc(misp: PyMISP, value: str) -> list[dict]:
    results = misp.search(value=value, pythonify=True)
    return [
        {
            "event_id": e.id,
            "title": e.info,
            "date": str(e.date),
            "threat_level": e.threat_level_id,
        }
        for e in results
    ]


def main() -> None:
    parser = argparse.ArgumentParser(description="MISP IOC Management")
    parser.add_argument("--url", required=True, help="MISP URL")
    parser.add_argument("--key", required=True, help="API key")
    subparsers = parser.add_subparsers(dest="command")

    upload_p = subparsers.add_parser("upload", help="Upload IOCs from CSV")
    upload_p.add_argument("csv_file")
    upload_p.add_argument("--title", required=True)

    search_p = subparsers.add_parser("search", help="Search for IOC")
    search_p.add_argument("value")

    args = parser.parse_args()
    misp = connect_misp(args.url, args.key)

    if args.command == "upload":
        event = create_event(misp, args.title)
        count = add_iocs_from_csv(misp, event, Path(args.csv_file))
        print(f"[+] Event created: {event.id}, {count} IOCs uploaded")

    elif args.command == "search":
        results = search_ioc(misp, args.value)
        if results:
            for r in results:
                print(f"[+] Event {r['event_id']}: {r['title']} ({r['date']})")
        else:
            print("[-] No results found")


if __name__ == "__main__":
    main()
```

### 1.3 Automated Threat Feed Import

```python
#!/usr/bin/env python3
"""Sync external threat feeds into MISP automatically"""
import argparse
import hashlib
from datetime import datetime

import requests
from pymisp import MISPEvent, PyMISP


THREAT_FEEDS = {
    "feodotracker_ip": {
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        "type": "ip-dst",
        "comment": "Feodo Tracker C2 IP",
    },
    "urlhaus": {
        "url": "https://urlhaus.abuse.ch/downloads/text/",
        "type": "url",
        "comment": "URLhaus malicious URLs",
    },
}


def fetch_feed(url: str) -> list[str]:
    resp = requests.get(url, timeout=30)
    resp.raise_for_status()
    lines = []
    for line in resp.text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            lines.append(line)
    return lines


def sync_feed(misp: PyMISP, feed_name: str, feed_config: dict, limit: int = 500) -> None:
    iocs = fetch_feed(feed_config["url"])[:limit]
    print(f"[*] {feed_name}: {len(iocs)} IOCs fetched")

    event = MISPEvent()
    event.info = f"Auto feed: {feed_name} ({datetime.now().date()})"
    event.threat_level_id = 2
    event.distribution = 1
    event.analysis = 1

    created = misp.add_event(event, pythonify=True)

    batch = [
        {"type": feed_config["type"], "value": ioc, "comment": feed_config["comment"], "to_ids": True}
        for ioc in iocs
    ]
    misp.add_attribute(created, batch)
    print(f"[+] Event {created.id} created successfully")


def main() -> None:
    parser = argparse.ArgumentParser(description="Threat Feed Synchronization")
    parser.add_argument("--url", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--feed", choices=list(THREAT_FEEDS.keys()), default="feodotracker_ip")
    parser.add_argument("--limit", type=int, default=500)
    args = parser.parse_args()

    misp = PyMISP(args.url, args.key, ssl=False)
    sync_feed(misp, args.feed, THREAT_FEEDS[args.feed], args.limit)


if __name__ == "__main__":
    main()
```

---

## 2. OpenCTI Platform

### 2.1 OpenCTI API Integration

```python
#!/usr/bin/env python3
"""Query and create OpenCTI STIX objects"""
import argparse
from pycti import OpenCTIApiClient


def connect_opencti(url: str, token: str) -> OpenCTIApiClient:
    return OpenCTIApiClient(url, token)


def list_indicators(client: OpenCTIApiClient, limit: int = 50) -> list[dict]:
    indicators = client.indicator.list(first=limit)
    return [
        {
            "id": ind["id"],
            "name": ind["name"],
            "pattern": ind.get("pattern", ""),
            "confidence": ind.get("confidence", 0),
            "valid_until": ind.get("valid_until", ""),
        }
        for ind in indicators
    ]


def create_ip_indicator(
    client: OpenCTIApiClient,
    ip: str,
    description: str = "",
    confidence: int = 75,
) -> str:
    indicator = client.indicator.create(
        name=f"Malicious IP: {ip}",
        description=description,
        pattern=f"[ipv4-addr:value = '{ip}']",
        pattern_type="stix",
        confidence=confidence,
        x_opencti_main_observable_type="IPv4-Addr",
    )
    return indicator["id"]


def search_threat_actors(client: OpenCTIApiClient, name: str) -> list[dict]:
    results = client.threat_actor.list(filters={"key": "name", "values": [name]})
    return [{"id": r["id"], "name": r["name"], "description": r.get("description", "")} for r in results]


def main() -> None:
    parser = argparse.ArgumentParser(description="OpenCTI API Tool")
    parser.add_argument("--url", required=True)
    parser.add_argument("--token", required=True)
    subparsers = parser.add_subparsers(dest="command")

    list_p = subparsers.add_parser("list-indicators")
    list_p.add_argument("--limit", type=int, default=20)

    add_p = subparsers.add_parser("add-ip")
    add_p.add_argument("ip")
    add_p.add_argument("--description", default="")

    search_p = subparsers.add_parser("search-actor")
    search_p.add_argument("name")

    args = parser.parse_args()
    client = connect_opencti(args.url, args.token)

    if args.command == "list-indicators":
        for ind in list_indicators(client, args.limit):
            print(f"[+] {ind['name']} | Confidence: {ind['confidence']} | {ind['pattern'][:60]}")

    elif args.command == "add-ip":
        ind_id = create_ip_indicator(client, args.ip, args.description)
        print(f"[+] Indicator created: {ind_id}")

    elif args.command == "search-actor":
        for actor in search_threat_actors(client, args.name):
            print(f"[+] {actor['name']}: {actor['description'][:100]}")


if __name__ == "__main__":
    main()
```

---

## 3. STIX/TAXII Standard Integration

### 3.1 Creating STIX 2.1 Objects

```python
#!/usr/bin/env python3
"""Create STIX 2.1 threat intelligence packages"""
import argparse
import json
from datetime import datetime, timezone

from stix2 import (
    Bundle, Campaign, Indicator, IntrusionSet,
    Malware, Relationship, ThreatActor,
)


def create_apt_bundle(
    actor_name: str,
    malware_name: str,
    ioc_ip: str,
    ioc_domain: str,
) -> Bundle:
    actor = ThreatActor(
        name=actor_name,
        description=f"Threat actor: {actor_name}",
        sophistication="advanced",
        resource_level="government",
        primary_motivation="espionage",
    )

    malware = Malware(
        name=malware_name,
        is_family=False,
        description=f"Malware used by {actor_name}",
        malware_types=["backdoor"],
    )

    ip_indicator = Indicator(
        name=f"Malicious IP: {ioc_ip}",
        pattern=f"[ipv4-addr:value = '{ioc_ip}']",
        pattern_type="stix",
        valid_from=datetime.now(timezone.utc),
        indicator_types=["malicious-activity"],
    )

    domain_indicator = Indicator(
        name=f"Malicious domain: {ioc_domain}",
        pattern=f"[domain-name:value = '{ioc_domain}']",
        pattern_type="stix",
        valid_from=datetime.now(timezone.utc),
        indicator_types=["malicious-activity"],
    )

    rel_uses = Relationship(actor, "uses", malware)
    rel_ip = Relationship(actor, "uses", ip_indicator)
    rel_domain = Relationship(actor, "uses", domain_indicator)

    return Bundle(actor, malware, ip_indicator, domain_indicator, rel_uses, rel_ip, rel_domain)


def main() -> None:
    parser = argparse.ArgumentParser(description="Create STIX 2.1 bundle")
    parser.add_argument("--actor", required=True, help="Threat actor name")
    parser.add_argument("--malware", required=True, help="Malware name")
    parser.add_argument("--ip", required=True, help="C2 IP")
    parser.add_argument("--domain", required=True, help="C2 domain")
    parser.add_argument("-o", "--output", default="stix_bundle.json")
    args = parser.parse_args()

    bundle = create_apt_bundle(args.actor, args.malware, args.ip, args.domain)
    with open(args.output, "w") as f:
        f.write(bundle.serialize(pretty=True))
    print(f"[+] STIX bundle saved: {args.output} ({len(bundle.objects)} objects)")


if __name__ == "__main__":
    main()
```

### 3.2 TAXII 2.1 Client

```python
#!/usr/bin/env python3
"""Collect threat intelligence from a TAXII 2.1 server"""
import argparse

from taxii2client.v21 import Server, as_pages


def list_collections(taxii_url: str, username: str = "", password: str = "") -> None:
    server = Server(taxii_url, user=username, password=password)
    for api_root in server.api_roots:
        print(f"[+] API Root: {api_root.title}")
        for collection in api_root.collections:
            print(f"  [*] Collection: {collection.title} (ID: {collection.id})")


def fetch_indicators(
    taxii_url: str,
    collection_id: str,
    username: str = "",
    password: str = "",
    limit: int = 100,
) -> list[dict]:
    server = Server(taxii_url, user=username, password=password)
    indicators = []

    for api_root in server.api_roots:
        for collection in api_root.collections:
            if collection.id == collection_id:
                for bundle in as_pages(collection.get_objects, per_request=limit):
                    for obj in bundle.get("objects", []):
                        if obj.get("type") == "indicator":
                            indicators.append({
                                "id": obj["id"],
                                "name": obj.get("name", ""),
                                "pattern": obj.get("pattern", ""),
                                "valid_from": obj.get("valid_from", ""),
                            })
    return indicators


def main() -> None:
    parser = argparse.ArgumentParser(description="TAXII Client")
    parser.add_argument("url", help="TAXII server URL")
    parser.add_argument("-u", "--username", default="")
    parser.add_argument("-p", "--password", default="")
    parser.add_argument("--collection", help="Collection ID")
    parser.add_argument("--list", action="store_true", help="List collections")
    args = parser.parse_args()

    if args.list:
        list_collections(args.url, args.username, args.password)
    elif args.collection:
        indicators = fetch_indicators(args.url, args.collection, args.username, args.password)
        for ind in indicators:
            print(f"[+] {ind['name']}: {ind['pattern'][:80]}")


if __name__ == "__main__":
    main()
```

---

## 4. IOC Management Automation

### 4.1 IOC Deduplication and Normalization

```python
#!/usr/bin/env python3
"""Consolidate and normalize IOCs from multiple feeds"""
import argparse
import ipaddress
import re
from collections import defaultdict
from pathlib import Path


class IOCNormalizer:
    IP_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    DOMAIN_RE = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")
    URL_RE = re.compile(r"^https?://")
    HASH_MD5 = re.compile(r"^[a-fA-F0-9]{32}$")
    HASH_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")

    def detect_type(self, value: str) -> str:
        value = value.strip()
        if self.HASH_SHA256.match(value):
            return "sha256"
        if self.HASH_MD5.match(value):
            return "md5"
        if self.URL_RE.match(value):
            return "url"
        if self.IP_RE.match(value):
            try:
                ipaddress.ip_address(value)
                return "ip"
            except ValueError:
                pass
        if self.DOMAIN_RE.match(value):
            return "domain"
        return "unknown"

    def normalize(self, value: str) -> str:
        return value.strip().lower()

    def process_file(self, path: Path) -> dict[str, set[str]]:
        iocs: dict[str, set[str]] = defaultdict(set)
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            ioc_type = self.detect_type(line)
            if ioc_type != "unknown":
                iocs[ioc_type].add(self.normalize(line))
        return iocs


def merge_feeds(files: list[Path]) -> dict[str, set[str]]:
    normalizer = IOCNormalizer()
    merged: dict[str, set[str]] = defaultdict(set)
    for path in files:
        feed_iocs = normalizer.process_file(path)
        for ioc_type, values in feed_iocs.items():
            merged[ioc_type].update(values)
    return merged


def main() -> None:
    parser = argparse.ArgumentParser(description="IOC Consolidation Tool")
    parser.add_argument("files", nargs="+", help="Feed file list")
    parser.add_argument("-o", "--output", default="merged_iocs.csv")
    args = parser.parse_args()

    merged = merge_feeds([Path(f) for f in args.files])

    with open(args.output, "w") as out:
        out.write("type,value\n")
        for ioc_type, values in sorted(merged.items()):
            for v in sorted(values):
                out.write(f"{ioc_type},{v}\n")

    total = sum(len(v) for v in merged.values())
    print(f"[+] Total {total} IOCs consolidated → {args.output}")
    for t, vals in sorted(merged.items()):
        print(f"  {t}: {len(vals)}")


if __name__ == "__main__":
    main()
```

---

## 5. CTI Platform Comparison

| Item | MISP | OpenCTI | TheHive |
|------|------|---------|---------|
| Primary Use | IOC sharing | Knowledge graph | Incident response |
| Standard | MISP format, STIX | STIX 2.1 | MISP integration |
| API | REST + PyMISP | GraphQL | REST |
| Community | CIRCL-led | Filigran | StrangeBee |
| Feed Integration | Various official feeds | Native TAXII | Via MISP |
| Installation Difficulty | Medium | Complex (Elasticsearch) | Medium |

### 5.1 Integrated Architecture

```
External Feeds (TAXII / HTTP)
         ↓
    Feed Collector (Python)
         ↓
     MISP / OpenCTI
      ↙         ↘
   SIEM          SOAR
(Splunk/ELK)  (Shuffle/XSOAR)
```

<!-- detect-validate-25 -->
## CTI Platform Operations Validation (Feed Integration, Detection Conversion)

A CTI platform's value comes not from *whether it's installed* but from *whether feeds are alive and flow into detection*. Operators must verify **whether feed ingest, deduplication, SIEM integration, and TAXII sync actually work**. Validate only on **owned platforms**.

### Check -> Question -> Signal -> Pitfall

| Check | Question | Signal | Pitfall |
|---|---|---|---|
| Feed ingest | Are feeds actually arriving? | New indicators/day | Leaving dead feeds |
| Deduplication | Does it filter duplicate IOCs? | Duplicate rate | Noise explosion |
| Detection integration | Does it reach SIEM rules? | IOC->rule mapping rate | Stored only |
| TAXII sync | Does bidirectional work? | Last sync timestamp | Token expiry |

### Defense validation (verify directly)

```bash
# 1) TAXII/feed sync freshness — a stale last-collection time means a dead feed
curl -s -H "Accept: application/taxii+json;version=2.1" "https://taxii.example/collections" 2>/dev/null | jq '.collections[].title' | head
# 2) Check whether ingested IOCs converted to detection — unmapped indicators are just storage
jq -r '.objects[] | select(.type=="indicator") | .pattern' feed.json 2>/dev/null | wc -l
```

> Platform-ops validation is *whether feeds are alive and flow to detection*, not *whether it's installed* -- "we have MISP" differs from "feeds update and IOCs map into SIEM rules". Confirm sync freshness and rule conversion on owned platforms directly ([[64_Threat_Intel_Platform]], [[40_Threat_Hunting]], [[13_SOC_Blue_Team]]).
