> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# MISP 플랫폼 활용

## MISP 설치 및 구성

```bash
# Docker Compose로 MISP 배포
cat > docker-compose.yml <<'EOF'
version: '3'
services:
  misp:
    image: coolacid/misp-docker:core-latest
    ports:
      - "443:443"
    environment:
      - MISP_BASEURL=https://localhost
      - MISP_ADMIN_EMAIL=admin@example.com
      - MISP_ADMIN_PASSWORD=SecurePass123!
    volumes:
      - misp_data:/var/www/MISP/app/files
      - misp_certs:/etc/nginx/certs
  mysql:
    image: mysql:8.0
    environment:
      - MYSQL_DATABASE=misp
      - MYSQL_USER=misp
      - MYSQL_PASSWORD=misp_db_pass
      - MYSQL_ROOT_PASSWORD=root_pass
    volumes:
      - mysql_data:/var/lib/mysql
  redis:
    image: redis:alpine

volumes:
  misp_data:
  misp_certs:
  mysql_data:
EOF

docker-compose up -d

# 초기 접속
# https://localhost (admin@admin.test / admin)
```

## PyMISP API 활용

```python
#!/usr/bin/env python3
"""PyMISP를 활용한 위협 인텔리전스 자동화."""

import argparse
import json
import sys
from pathlib import Path
from datetime import datetime, timezone
from dataclasses import dataclass


@dataclass
class MISPConfig:
    url: str
    key: str
    verify_tls: bool = False


def get_misp_client(config: MISPConfig):
    """PyMISP 클라이언트 초기화."""
    try:
        from pymisp import PyMISP
        return PyMISP(config.url, config.key, config.verify_tls)
    except ImportError:
        print("[!] pip install pymisp 필요", file=sys.stderr)
        sys.exit(1)


def create_event(
    misp,
    title: str,
    threat_level: int = 2,
    distribution: int = 0,
    analysis: int = 0,
    tags: list[str] | None = None,
) -> dict:
    """MISP 이벤트 생성.
    threat_level: 1=High, 2=Medium, 3=Low, 4=Undefined
    distribution: 0=Your org, 1=Community, 2=Connected, 3=All
    analysis: 0=Initial, 1=Ongoing, 2=Completed
    """
    from pymisp import MISPEvent

    event = MISPEvent()
    event.info = title
    event.threat_level_id = threat_level
    event.distribution = distribution
    event.analysis = analysis
    event.date = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    if tags:
        for tag in tags:
            event.add_tag(tag)

    result = misp.add_event(event, pythonify=True)
    return result


def add_ioc_batch(
    misp,
    event_id: int,
    iocs: list[dict[str, str]],
) -> list[dict]:
    """IoC 배치 추가.
    ioc 형식: {"type": "ip-dst", "value": "1.2.3.4", "comment": "C2"}
    """
    from pymisp import MISPAttribute

    results = []
    event = misp.get_event(event_id, pythonify=True)

    for ioc in iocs:
        attr = MISPAttribute()
        attr.type = ioc["type"]
        attr.value = ioc["value"]
        attr.comment = ioc.get("comment", "")
        attr.to_ids = ioc.get("to_ids", True)
        attr.distribution = ioc.get("distribution", 0)

        result = misp.add_attribute(event, attr, pythonify=True)
        results.append(result)

    return results


def search_ioc(misp, value: str) -> list[dict]:
    """IoC 검색."""
    results = misp.search(value=value, pythonify=True)
    found = []
    for event in results:
        for attr in getattr(event, "attributes", []):
            if value.lower() in str(attr.value).lower():
                found.append({
                    "event_id": event.id,
                    "event_info": event.info,
                    "attr_type": attr.type,
                    "attr_value": attr.value,
                    "threat_level": event.threat_level_id,
                })
    return found


def export_stix2(misp, event_id: int, output_path: Path) -> None:
    """이벤트를 STIX 2.1 형식으로 내보내기."""
    stix_data = misp.get_event(event_id, pythonify=False)
    # MISP → STIX 변환 (misp-stix 라이브러리)
    try:
        from misp_stix_converter import MISPtoSTIX21Parser
        parser = MISPtoSTIX21Parser()
        parser.parse_misp_event(stix_data)
        bundle = parser.stix_objects
        output_path.write_text(json.dumps(bundle, indent=2))
        print(f"[+] STIX 2.1 내보내기: {output_path}")
    except ImportError:
        print("[!] pip install misp-stix 필요")


def sync_feed(misp, feed_url: str, feed_name: str) -> dict:
    """외부 MISP 피드 동기화."""
    feed = {
        "name": feed_name,
        "provider": "External",
        "url": feed_url,
        "enabled": True,
        "caching_enabled": True,
        "input_source": "network",
        "source_format": "misp",
        "distribution": 0,
        "sharing_group_id": 0,
        "tag_id": 0,
        "fixed_event": False,
        "delta_merge": True,
        "pull_rules": {},
        "lookup_visible": True,
        "headers": "",
    }
    result = misp.add_feed(feed, pythonify=True)
    return result


def generate_ioc_report(misp, event_ids: list[int]) -> str:
    """다수 이벤트에서 IoC 보고서 생성."""
    all_iocs: dict[str, list[str]] = {}

    for event_id in event_ids:
        event = misp.get_event(event_id, pythonify=True)
        for attr in getattr(event, "attributes", []):
            ioc_type = attr.type
            if ioc_type not in all_iocs:
                all_iocs[ioc_type] = []
            all_iocs[ioc_type].append(attr.value)

    lines = [f"# IoC 보고서 — {datetime.now().strftime('%Y-%m-%d')}"]
    lines.append(f"이벤트 수: {len(event_ids)}\n")

    for ioc_type, values in sorted(all_iocs.items()):
        lines.append(f"## {ioc_type} ({len(values)}개)")
        for v in sorted(set(values)):
            lines.append(f"- {v}")
        lines.append("")

    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="MISP 자동화 도구")
    parser.add_argument("--url", required=True, help="MISP URL")
    parser.add_argument("--key", required=True, help="API 키")
    parser.add_argument("--no-verify", action="store_true")
    sub = parser.add_subparsers(dest="cmd", required=True)

    # 이벤트 생성
    create_p = sub.add_parser("create-event", help="이벤트 생성")
    create_p.add_argument("title")
    create_p.add_argument("--threat-level", type=int, default=2,
                          choices=[1, 2, 3, 4])
    create_p.add_argument("--tags", nargs="*", default=[])

    # IoC 추가
    ioc_p = sub.add_parser("add-iocs", help="IoC 배치 추가")
    ioc_p.add_argument("event_id", type=int)
    ioc_p.add_argument("ioc_file", type=Path, help="JSON IoC 파일")

    # 검색
    search_p = sub.add_parser("search", help="IoC 검색")
    search_p.add_argument("value")

    # 보고서
    report_p = sub.add_parser("report", help="IoC 보고서 생성")
    report_p.add_argument("event_ids", nargs="+", type=int)
    report_p.add_argument("-o", "--output", type=Path)

    args = parser.parse_args()
    config = MISPConfig(args.url, args.key, not args.no_verify)
    misp = get_misp_client(config)

    if args.cmd == "create-event":
        event = create_event(misp, args.title, args.threat_level,
                             tags=args.tags)
        print(f"[+] 이벤트 생성: ID={event.id}, UUID={event.uuid}")

    elif args.cmd == "add-iocs":
        iocs = json.loads(args.ioc_file.read_text())
        results = add_ioc_batch(misp, args.event_id, iocs)
        print(f"[+] IoC {len(results)}개 추가 완료")

    elif args.cmd == "search":
        found = search_ioc(misp, args.value)
        if found:
            print(f"[+] {len(found)}개 결과:")
            for r in found:
                print(f"  이벤트 {r['event_id']}: {r['attr_type']} = {r['attr_value']}")
        else:
            print(f"[-] '{args.value}' 미발견")

    elif args.cmd == "report":
        report = generate_ioc_report(misp, args.event_ids)
        if args.output:
            args.output.write_text(report)
            print(f"[+] 보고서 저장: {args.output}")
        else:
            print(report)


if __name__ == "__main__":
    main()
```

## MISP 규칙 및 속성 유형

```
주요 속성 유형
네트워크
├── ip-src, ip-dst — 소스/목적지 IP
├── domain — 도메인
├── hostname — 호스트명
├── url — URL
├── email-src, email-dst — 이메일
└── AS — 자율 시스템 번호

파일
├── md5, sha1, sha256 — 파일 해시
├── filename — 파일명
├── filename|md5 — 파일명|해시 복합
└── size-in-bytes — 파일 크기

페이로드
├── malware-type — 악성코드 유형
├── yara — YARA 규칙
└── snort — Snort 시그니처

공격 패턴
├── vulnerability — CVE
├── attack-pattern — ATT&CK 기법
└── course-of-action — 대응 방안

갤럭시
└── MITRE ATT&CK, Ransomware, RAT, Tool 태그
```

## MISP 자동화 워크플로우

```bash
# PyMISP 설치
pip install pymisp misp-stix

# 환경 변수 설정
export MISP_URL="https://misp.local"
export MISP_KEY="your-api-key"

# VirusTotal → MISP 자동 보고
python3 vt_to_misp.py --hash abc123... --event-id 42

# SIEM → MISP IoC 자동 등록
python3 siem_alert_to_misp.py --alert-json alert.json

# MISP → Splunk 피드 동기화
python3 misp_to_splunk_lookup.py --output /opt/splunk/lookups/
```

## 피드 관리

```python
#!/usr/bin/env python3
"""MISP 피드 자동 동기화 관리."""

import subprocess
import sys

FREE_MISP_FEEDS = [
    {
        "name": "CIRCL OSINT",
        "url": "https://www.circl.lu/doc/misp/feed-osint/",
        "format": "misp",
        "provider": "CIRCL",
    },
    {
        "name": "Botvrij.eu",
        "url": "https://www.botvrij.eu/data/feed-osint/",
        "format": "misp",
        "provider": "Botvrij",
    },
    {
        "name": "ESET Export",
        "url": "https://github.com/eset/malware-ioc",
        "format": "freetext",
        "provider": "ESET",
    },
]


def print_feed_list() -> None:
    print("추천 무료 MISP 피드:")
    for i, feed in enumerate(FREE_MISP_FEEDS, 1):
        print(f"{i}. {feed['name']} ({feed['provider']})")
        print(f"   URL: {feed['url']}")


if __name__ == "__main__":
    print_feed_list()
```

다음 파일에서 위협 피드 관리 및 강화를 다룬다.

---

<a name="english"></a>

# MISP Platform Usage

## MISP Installation and Configuration

```bash
# Deploy MISP with Docker Compose
cat > docker-compose.yml <<'EOF'
version: '3'
services:
  misp:
    image: coolacid/misp-docker:core-latest
    ports:
      - "443:443"
    environment:
      - MISP_BASEURL=https://localhost
      - MISP_ADMIN_EMAIL=admin@example.com
      - MISP_ADMIN_PASSWORD=SecurePass123!
    volumes:
      - misp_data:/var/www/MISP/app/files
      - misp_certs:/etc/nginx/certs
  mysql:
    image: mysql:8.0
    environment:
      - MYSQL_DATABASE=misp
      - MYSQL_USER=misp
      - MYSQL_PASSWORD=misp_db_pass
      - MYSQL_ROOT_PASSWORD=root_pass
    volumes:
      - mysql_data:/var/lib/mysql
  redis:
    image: redis:alpine

volumes:
  misp_data:
  misp_certs:
  mysql_data:
EOF

docker-compose up -d

# Initial access
# https://localhost (admin@admin.test / admin)
```

## PyMISP API Usage

```python
#!/usr/bin/env python3
"""Threat intelligence automation using PyMISP."""

import argparse
import json
import sys
from pathlib import Path
from datetime import datetime, timezone
from dataclasses import dataclass


@dataclass
class MISPConfig:
    url: str
    key: str
    verify_tls: bool = False


def get_misp_client(config: MISPConfig):
    """Initialize PyMISP client."""
    try:
        from pymisp import PyMISP
        return PyMISP(config.url, config.key, config.verify_tls)
    except ImportError:
        print("[!] pip install pymisp required", file=sys.stderr)
        sys.exit(1)


def create_event(
    misp,
    title: str,
    threat_level: int = 2,
    distribution: int = 0,
    analysis: int = 0,
    tags: list[str] | None = None,
) -> dict:
    """Create a MISP event.
    threat_level: 1=High, 2=Medium, 3=Low, 4=Undefined
    distribution: 0=Your org, 1=Community, 2=Connected, 3=All
    analysis: 0=Initial, 1=Ongoing, 2=Completed
    """
    from pymisp import MISPEvent

    event = MISPEvent()
    event.info = title
    event.threat_level_id = threat_level
    event.distribution = distribution
    event.analysis = analysis
    event.date = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    if tags:
        for tag in tags:
            event.add_tag(tag)

    result = misp.add_event(event, pythonify=True)
    return result


def add_ioc_batch(
    misp,
    event_id: int,
    iocs: list[dict[str, str]],
) -> list[dict]:
    """Add IoCs in batch.
    ioc format: {"type": "ip-dst", "value": "1.2.3.4", "comment": "C2"}
    """
    from pymisp import MISPAttribute

    results = []
    event = misp.get_event(event_id, pythonify=True)

    for ioc in iocs:
        attr = MISPAttribute()
        attr.type = ioc["type"]
        attr.value = ioc["value"]
        attr.comment = ioc.get("comment", "")
        attr.to_ids = ioc.get("to_ids", True)
        attr.distribution = ioc.get("distribution", 0)

        result = misp.add_attribute(event, attr, pythonify=True)
        results.append(result)

    return results


def search_ioc(misp, value: str) -> list[dict]:
    """Search for an IoC."""
    results = misp.search(value=value, pythonify=True)
    found = []
    for event in results:
        for attr in getattr(event, "attributes", []):
            if value.lower() in str(attr.value).lower():
                found.append({
                    "event_id": event.id,
                    "event_info": event.info,
                    "attr_type": attr.type,
                    "attr_value": attr.value,
                    "threat_level": event.threat_level_id,
                })
    return found


def export_stix2(misp, event_id: int, output_path: Path) -> None:
    """Export an event to STIX 2.1 format."""
    stix_data = misp.get_event(event_id, pythonify=False)
    # MISP → STIX conversion (misp-stix library)
    try:
        from misp_stix_converter import MISPtoSTIX21Parser
        parser = MISPtoSTIX21Parser()
        parser.parse_misp_event(stix_data)
        bundle = parser.stix_objects
        output_path.write_text(json.dumps(bundle, indent=2))
        print(f"[+] STIX 2.1 exported: {output_path}")
    except ImportError:
        print("[!] pip install misp-stix required")


def sync_feed(misp, feed_url: str, feed_name: str) -> dict:
    """Synchronize an external MISP feed."""
    feed = {
        "name": feed_name,
        "provider": "External",
        "url": feed_url,
        "enabled": True,
        "caching_enabled": True,
        "input_source": "network",
        "source_format": "misp",
        "distribution": 0,
        "sharing_group_id": 0,
        "tag_id": 0,
        "fixed_event": False,
        "delta_merge": True,
        "pull_rules": {},
        "lookup_visible": True,
        "headers": "",
    }
    result = misp.add_feed(feed, pythonify=True)
    return result


def generate_ioc_report(misp, event_ids: list[int]) -> str:
    """Generate an IoC report from multiple events."""
    all_iocs: dict[str, list[str]] = {}

    for event_id in event_ids:
        event = misp.get_event(event_id, pythonify=True)
        for attr in getattr(event, "attributes", []):
            ioc_type = attr.type
            if ioc_type not in all_iocs:
                all_iocs[ioc_type] = []
            all_iocs[ioc_type].append(attr.value)

    lines = [f"# IoC Report — {datetime.now().strftime('%Y-%m-%d')}"]
    lines.append(f"Events: {len(event_ids)}\n")

    for ioc_type, values in sorted(all_iocs.items()):
        lines.append(f"## {ioc_type} ({len(values)} entries)")
        for v in sorted(set(values)):
            lines.append(f"- {v}")
        lines.append("")

    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="MISP automation tool")
    parser.add_argument("--url", required=True, help="MISP URL")
    parser.add_argument("--key", required=True, help="API key")
    parser.add_argument("--no-verify", action="store_true")
    sub = parser.add_subparsers(dest="cmd", required=True)

    # Create event
    create_p = sub.add_parser("create-event", help="Create event")
    create_p.add_argument("title")
    create_p.add_argument("--threat-level", type=int, default=2,
                          choices=[1, 2, 3, 4])
    create_p.add_argument("--tags", nargs="*", default=[])

    # Add IoCs
    ioc_p = sub.add_parser("add-iocs", help="Add IoCs in batch")
    ioc_p.add_argument("event_id", type=int)
    ioc_p.add_argument("ioc_file", type=Path, help="JSON IoC file")

    # Search
    search_p = sub.add_parser("search", help="Search IoC")
    search_p.add_argument("value")

    # Report
    report_p = sub.add_parser("report", help="Generate IoC report")
    report_p.add_argument("event_ids", nargs="+", type=int)
    report_p.add_argument("-o", "--output", type=Path)

    args = parser.parse_args()
    config = MISPConfig(args.url, args.key, not args.no_verify)
    misp = get_misp_client(config)

    if args.cmd == "create-event":
        event = create_event(misp, args.title, args.threat_level,
                             tags=args.tags)
        print(f"[+] Event created: ID={event.id}, UUID={event.uuid}")

    elif args.cmd == "add-iocs":
        iocs = json.loads(args.ioc_file.read_text())
        results = add_ioc_batch(misp, args.event_id, iocs)
        print(f"[+] {len(results)} IoCs added successfully")

    elif args.cmd == "search":
        found = search_ioc(misp, args.value)
        if found:
            print(f"[+] {len(found)} results:")
            for r in found:
                print(f"  Event {r['event_id']}: {r['attr_type']} = {r['attr_value']}")
        else:
            print(f"[-] '{args.value}' not found")

    elif args.cmd == "report":
        report = generate_ioc_report(misp, args.event_ids)
        if args.output:
            args.output.write_text(report)
            print(f"[+] Report saved: {args.output}")
        else:
            print(report)


if __name__ == "__main__":
    main()
```

## MISP Attribute Types and Rules

```
Key attribute types
Network
├── ip-src, ip-dst — Source/destination IP
├── domain — Domain name
├── hostname — Hostname
├── url — URL
├── email-src, email-dst — Email addresses
└── AS — Autonomous system number

File
├── md5, sha1, sha256 — File hashes
├── filename — Filename
├── filename|md5 — Filename|hash compound
└── size-in-bytes — File size

Payload
├── malware-type — Malware type
├── yara — YARA rule
└── snort — Snort signature

Attack patterns
├── vulnerability — CVE
├── attack-pattern — ATT&CK technique
└── course-of-action — Countermeasure

Galaxy
└── MITRE ATT&CK, Ransomware, RAT, Tool tags
```

## MISP Automation Workflow

```bash
# Install PyMISP
pip install pymisp misp-stix

# Set environment variables
export MISP_URL="https://misp.local"
export MISP_KEY="your-api-key"

# VirusTotal → MISP automated reporting
python3 vt_to_misp.py --hash abc123... --event-id 42

# SIEM → MISP IoC auto-registration
python3 siem_alert_to_misp.py --alert-json alert.json

# MISP → Splunk feed synchronization
python3 misp_to_splunk_lookup.py --output /opt/splunk/lookups/
```

## Feed Management

```python
#!/usr/bin/env python3
"""MISP feed automatic synchronization management."""

import subprocess
import sys

FREE_MISP_FEEDS = [
    {
        "name": "CIRCL OSINT",
        "url": "https://www.circl.lu/doc/misp/feed-osint/",
        "format": "misp",
        "provider": "CIRCL",
    },
    {
        "name": "Botvrij.eu",
        "url": "https://www.botvrij.eu/data/feed-osint/",
        "format": "misp",
        "provider": "Botvrij",
    },
    {
        "name": "ESET Export",
        "url": "https://github.com/eset/malware-ioc",
        "format": "freetext",
        "provider": "ESET",
    },
]


def print_feed_list() -> None:
    print("Recommended free MISP feeds:")
    for i, feed in enumerate(FREE_MISP_FEEDS, 1):
        print(f"{i}. {feed['name']} ({feed['provider']})")
        print(f"   URL: {feed['url']}")


if __name__ == "__main__":
    print_feed_list()
```

The next file covers threat feed management and enrichment.
