> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 위협 인텔리전스 플랫폼 기초

## 0. 초보자를 위한 개념 이해

### TIP(위협 인텔리전스 플랫폼)이란?

**TIP(Threat Intelligence Platform)**는 위협 정보를 수집, 처리, 분석, 공유하는 전용 소프트웨어 플랫폼입니다.

```
TIP 없을 때:
  팀원 A: 스프레드시트에 IOC 관리
  팀원 B: 별도 텍스트 파일에 IOC 저장
  팀원 C: 이메일로 IOC 공유
  → 중복, 오류, 최신성 유지 불가

TIP 있을 때:
  중앙 플랫폼에서 IOC 통합 관리
  → 자동 중복 제거
  → API로 SIEM/방화벽에 자동 동기화
  → 팀 간 실시간 공유
  → 신뢰도/만료일 자동 관리
```

### 주요 TIP 솔루션 비교

| TIP | 유형 | 특징 |
|-----|------|------|
| **MISP** | 오픈소스 (무료) | 커뮤니티 공유 중심, 가장 널리 사용 |
| **OpenCTI** | 오픈소스 (무료) | 그래프 기반 관계 분석, 현대적 UI |
| **ThreatConnect** | 상용 | 기업용, 자동화 워크플로우 |
| **Anomali ThreatStream** | 상용 | 대용량 피드 처리 |
| **Recorded Future** | 상용 | AI 기반 예측 인텔리전스 |

### STIX와 TAXII란?

```
STIX (Structured Threat Information Expression):
  위협 인텔리전스 데이터의 표준 형식
  "이 데이터를 어떻게 표현할 것인가?"
  
  STIX 객체 예시:
  {
    "type": "indicator",
    "id": "indicator--...",
    "name": "Cobalt Strike C2",
    "pattern": "[network-traffic:dst_port = 443 AND ...]",
    "valid_from": "2026-01-01T00:00:00Z"
  }

TAXII (Trusted Automated Exchange of Intelligence Information):
  위협 인텔리전스 데이터의 전송 프로토콜
  "이 데이터를 어떻게 주고받을 것인가?"
  
  TAXII 서버 → TAXII 클라이언트 (자동화된 IOC 구독)
```

### 왜 TIP가 필요한가?

```
SOC 팀의 실제 문제:
  하루에 수천 개의 IOC 업데이트
  → 수동 관리 불가능

TIP로 해결:
  1. 자동 수집: AlienVault, VirusTotal, ISAC 피드 자동 수집
  2. 자동 처리: 중복 제거, 만료 관리, 신뢰도 계산
  3. 자동 배포: 방화벽, SIEM, EDR에 자동 업데이트
  4. 공유: 같은 업종 다른 기업과 IOC 공유 (ISAC)
```

---

## 위협 인텔리전스 개요

위협 인텔리전스(TI)는 현재 또는 잠재적 위협에 대한 근거 기반 지식으로, 의사결정을 지원한다. 단순한 IoC(침해 지표) 수집이 아닌, 맥락(Context)이 있는 실행 가능한 정보여야 한다.

## 인텔리전스 유형

### 전략적 인텔리전스
- 대상: C-Suite, 경영진
- 내용: 위협 행위자 동향, 지정학적 위험, 산업 트렌드
- 형식: 경영진 보고서, 위험 평가서

### 운영 인텔리전스
- 대상: SOC 관리자, 사고 대응팀
- 내용: 캠페인 분석, TTPs, 공격 타임라인
- 형식: 위협 보고서, 캠페인 브리핑

### 전술적 인텔리전스
- 대상: 방어자, 위협 헌팅 팀
- 내용: TTPs (MITRE ATT&CK), 공격 패턴
- 형식: ATT&CK 매핑, 헌팅 플레이북

### 기술적 인텔리전스
- 대상: SOC 분석가, SIEM 관리자
- 내용: IoC (IP, 도메인, 해시, 인증서)
- 형식: STIX/TAXII, CSV, JSON, OpenIOC

## 인텔리전스 생명주기

```
계획 → 수집 → 처리 → 분석 → 전파 → 피드백
  ↑___________________________________|

계획     : 인텔리전스 요구사항 정의 (RFI, PIR)
수집     : OSINT, 상용 피드, 인간 인텔리전스
처리     : 정규화, 중복 제거, 형식 변환
분석     : 맥락화, 연관 분석, 귀속
전파     : SIEM 통합, 보고서, API
피드백   : 효용성 평가, 우선순위 조정
```

## 핵심 표준 및 프레임워크

### STIX 2.1 (Structured Threat Information eXpression)
```json
{
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--a720571b-de4b-4a8a-b71f-a5bef2a4afe5",
    "created": "2024-01-15T10:00:00.000Z",
    "modified": "2024-01-15T10:00:00.000Z",
    "name": "악성 IP 주소",
    "indicator_types": ["malicious-activity"],
    "pattern": "[ipv4-addr:value = '192.0.2.1']",
    "pattern_type": "stix",
    "valid_from": "2024-01-01T00:00:00Z",
    "labels": ["malicious-activity"]
}
```

### TAXII 2.1 (Trusted Automated eXchange of Intelligence Information)
```
TAXII 컬렉션 API
GET /taxii/   — 서버 정보
GET /api1/    — API 루트
GET /api1/collections/   — 컬렉션 목록
GET /api1/collections/{id}/objects/ — STIX 객체
POST /api1/collections/{id}/objects/ — STIX 업로드
```

### MITRE ATT&CK
```
엔터프라이즈 ATT&CK
├── 14개 전술 (Tactic)
├── 200+ 기법 (Technique)
├── 400+ 하위 기법 (Sub-technique)
└── 행위자/소프트웨어 매핑

ICS ATT&CK (OT)
└── OT 환경 특화 전술/기법
```

## TIP 플랫폼 비교

```
오픈소스
├── MISP (Malware Information Sharing Platform)
│   — 가장 활발, 강력한 커뮤니티
├── OpenCTI
│   — STIX 2.1 네이티브, 현대적 UI
├── Hive/Cortex
│   — 사고 대응 연동
└── IntelOwl
│   — 멀티 분석기 통합

상용
├── Anomali ThreatStream
├── Recorded Future
├── ThreatConnect
├── Mandiant Advantage
└── IBM X-Force Exchange
```

## 인텔리전스 품질 평가

```
신뢰도 (Confidence)
  Admiralty Scale: A-F (출처 신뢰도) × 1-6 (정보 신뢰도)
  퍼센트: 0~100%

적시성 (Timeliness)
  IP/도메인 IoC: 수시간~수일
  해시: 수일~수주
  TTPs: 수개월~수년

관련성 (Relevance)
  산업 분야, 지역, 기술 스택 매칭

실행 가능성 (Actionability)
  탐지 규칙 직접 생성 가능 여부
```

## TIP 환경 구성

```python
#!/usr/bin/env python3
"""위협 인텔리전스 플랫폼 설정 검증 도구."""

import argparse
import urllib.request
import urllib.error
import json
import sys
from dataclasses import dataclass


@dataclass
class TIPEndpoint:
    name: str
    url: str
    api_key: str
    platform: str


def check_misp_connection(url: str, api_key: str) -> dict:
    """MISP 연결 테스트."""
    endpoint = f"{url.rstrip('/')}/servers/getPyMISPVersion.json"
    req = urllib.request.Request(
        endpoint,
        headers={
            "Authorization": api_key,
            "Accept": "application/json",
        }
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
            return {"status": "ok", "version": data.get("version")}
    except urllib.error.HTTPError as e:
        return {"status": "error", "code": e.code}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def check_opencti_connection(url: str, api_key: str) -> dict:
    """OpenCTI GraphQL 연결 테스트."""
    endpoint = f"{url.rstrip('/')}/graphql"
    query = '{"query": "{ about { version } }"}'
    req = urllib.request.Request(
        endpoint,
        data=query.encode(),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
            version = data.get("data", {}).get("about", {}).get("version")
            return {"status": "ok", "version": version}
    except Exception as e:
        return {"status": "error", "message": str(e)[:100]}


def check_taxii_server(url: str, auth_header: str | None = None) -> dict:
    """TAXII 2.1 서버 연결 테스트."""
    discovery_url = f"{url.rstrip('/')}/taxii/"
    headers: dict = {"Accept": "application/taxii+json;version=2.1"}
    if auth_header:
        headers["Authorization"] = auth_header
    req = urllib.request.Request(discovery_url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
            return {
                "status": "ok",
                "title": data.get("title"),
                "description": data.get("description", "")[:100],
            }
    except Exception as e:
        return {"status": "error", "message": str(e)[:100]}


def validate_stix_bundle(bundle_path: str) -> dict:
    """STIX 번들 기본 검증."""
    import pathlib
    try:
        data = json.loads(pathlib.Path(bundle_path).read_text())
        if data.get("type") != "bundle":
            return {"valid": False, "error": "번들 타입이 아님"}
        objects = data.get("objects", [])
        types = {}
        for obj in objects:
            t = obj.get("type", "unknown")
            types[t] = types.get(t, 0) + 1
        return {
            "valid": True,
            "spec_version": data.get("spec_version"),
            "object_count": len(objects),
            "types": types,
        }
    except json.JSONDecodeError as e:
        return {"valid": False, "error": f"JSON 파싱 오류: {e}"}
    except FileNotFoundError:
        return {"valid": False, "error": "파일 없음"}


def main() -> None:
    parser = argparse.ArgumentParser(description="TIP 연결 및 검증 도구")
    sub = parser.add_subparsers(dest="cmd", required=True)

    misp_p = sub.add_parser("misp", help="MISP 연결 테스트")
    misp_p.add_argument("url")
    misp_p.add_argument("api_key")

    octi_p = sub.add_parser("opencti", help="OpenCTI 연결 테스트")
    octi_p.add_argument("url")
    octi_p.add_argument("api_key")

    taxii_p = sub.add_parser("taxii", help="TAXII 서버 테스트")
    taxii_p.add_argument("url")
    taxii_p.add_argument("--auth", help="Authorization 헤더 값")

    stix_p = sub.add_parser("validate-stix", help="STIX 번들 검증")
    stix_p.add_argument("bundle_path")

    args = parser.parse_args()

    if args.cmd == "misp":
        result = check_misp_connection(args.url, args.api_key)
        print(f"MISP: {result}")

    elif args.cmd == "opencti":
        result = check_opencti_connection(args.url, args.api_key)
        print(f"OpenCTI: {result}")

    elif args.cmd == "taxii":
        result = check_taxii_server(args.url, args.auth)
        print(f"TAXII: {result}")

    elif args.cmd == "validate-stix":
        result = validate_stix_bundle(args.bundle_path)
        if result["valid"]:
            print(f"[+] 유효한 STIX 번들")
            print(f"    버전: {result.get('spec_version')}")
            print(f"    객체: {result.get('object_count')}개")
            print(f"    타입: {result.get('types')}")
        else:
            print(f"[!] 유효하지 않음: {result.get('error')}")


if __name__ == "__main__":
    main()
```

다음 파일에서 MISP 플랫폼 활용을 다룬다.


<!-- detect-validate-64 -->
## TIP 가치 검증 — 인텔이 실제로 운영에 전달되는가

위협 인텔 플랫폼은 *피드를 모았다*가 아니라 **수집한 인텔이 정보 요구사항(PIR)에 매핑되고, 실제 탐지·차단·대응 의사결정으로 전달되어 행동가능(actionable)한가**로 판정한다. 검증은 **소유 TIP**에서만.

### 항목 → 실패 모드 → 검증 방법 → 양호 신호

| 항목 | 실패 모드 | 검증 방법 | 양호 신호 |
|---|---|---|---|
| 요구사항 매핑 | 무목적 수집 | PIR 대비 커버리지 | 인텔→요구 매핑 |
| 행동가능성 | 보고서로만 | 탐지 전달 추적 | 룰/차단으로 전환 |
| 적시성 | 지연 인텔 | 수집→배포 지연 측정 | SLA 내 배포 |
| 신뢰도 | 출처 미평가 | 신뢰도 스코어링 | 출처·신뢰 라벨 |

### 방어 검증 (직접 확인)

```bash
# 1) TIP의 인텔이 실제로 탐지 시스템(SIEM/EDR)으로 내보내지는지 — 소유 TIP에서만
curl -s -H "Authorization: $TIP_KEY" https://tip.local/api/exports 2>/dev/null | jq '.[].destination' | sort -u || echo "verify intel export integrations exist"
# 2) 수집된 인텔이 PIR/우선순위 태그를 실제 가지는지(무태그=비행동가능)
curl -s -H "Authorization: $TIP_KEY" https://tip.local/api/indicators?limit=20 2>/dev/null | jq '.[].tags' | head || echo "check that indicators carry priority/PIR tags"
```

> 검증은 반드시 **소유 TIP**에서만 한다. "피드를 모았다"와 "인텔이 운영에 전달된다"는 다르다 — 익스포트·태그로 직접 확인한다([[25_Threat_Intelligence]], [[13_SOC_Blue_Team]]).

---

<a name="english"></a>

# Threat Intelligence Platform Fundamentals

## Threat Intelligence Overview

Threat Intelligence (TI) is evidence-based knowledge about current or potential threats that supports decision-making. It must be actionable information with context — not merely a collection of IoCs (Indicators of Compromise).

## Intelligence Types

### Strategic Intelligence
- Audience: C-Suite, executives
- Content: Threat actor trends, geopolitical risks, industry trends
- Format: Executive reports, risk assessments

### Operational Intelligence
- Audience: SOC managers, incident response teams
- Content: Campaign analysis, TTPs, attack timelines
- Format: Threat reports, campaign briefings

### Tactical Intelligence
- Audience: Defenders, threat hunting teams
- Content: TTPs (MITRE ATT&CK), attack patterns
- Format: ATT&CK mappings, hunting playbooks

### Technical Intelligence
- Audience: SOC analysts, SIEM administrators
- Content: IoCs (IPs, domains, hashes, certificates)
- Format: STIX/TAXII, CSV, JSON, OpenIOC

## Intelligence Lifecycle

```
Plan → Collect → Process → Analyze → Disseminate → Feedback
  ↑___________________________________________________|

Plan        : Define intelligence requirements (RFI, PIR)
Collect     : OSINT, commercial feeds, human intelligence
Process     : Normalization, deduplication, format conversion
Analyze     : Contextualization, correlation analysis, attribution
Disseminate : SIEM integration, reports, API
Feedback    : Evaluate usefulness, adjust priorities
```

## Core Standards and Frameworks

### STIX 2.1 (Structured Threat Information eXpression)
```json
{
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--a720571b-de4b-4a8a-b71f-a5bef2a4afe5",
    "created": "2024-01-15T10:00:00.000Z",
    "modified": "2024-01-15T10:00:00.000Z",
    "name": "Malicious IP address",
    "indicator_types": ["malicious-activity"],
    "pattern": "[ipv4-addr:value = '192.0.2.1']",
    "pattern_type": "stix",
    "valid_from": "2024-01-01T00:00:00Z",
    "labels": ["malicious-activity"]
}
```

### TAXII 2.1 (Trusted Automated eXchange of Intelligence Information)
```
TAXII Collections API
GET /taxii/   — Server information
GET /api1/    — API root
GET /api1/collections/   — Collection list
GET /api1/collections/{id}/objects/ — STIX objects
POST /api1/collections/{id}/objects/ — Upload STIX
```

### MITRE ATT&CK
```
Enterprise ATT&CK
├── 14 Tactics
├── 200+ Techniques
├── 400+ Sub-techniques
└── Threat actor / software mapping

ICS ATT&CK (OT)
└── OT environment-specific tactics and techniques
```

## TIP Platform Comparison

```
Open Source
├── MISP (Malware Information Sharing Platform)
│   — Most active, strong community
├── OpenCTI
│   — STIX 2.1 native, modern UI
├── Hive/Cortex
│   — Incident response integration
└── IntelOwl
│   — Multi-analyzer integration

Commercial
├── Anomali ThreatStream
├── Recorded Future
├── ThreatConnect
├── Mandiant Advantage
└── IBM X-Force Exchange
```

## Intelligence Quality Assessment

```
Confidence
  Admiralty Scale: A-F (source reliability) × 1-6 (information reliability)
  Percentage: 0–100%

Timeliness
  IP/Domain IoCs: hours to days
  Hashes: days to weeks
  TTPs: months to years

Relevance
  Matching industry sector, region, and technology stack

Actionability
  Whether detection rules can be directly generated
```

## TIP Environment Setup

```python
#!/usr/bin/env python3
"""Threat Intelligence Platform configuration validation tool."""

import argparse
import urllib.request
import urllib.error
import json
import sys
from dataclasses import dataclass


@dataclass
class TIPEndpoint:
    name: str
    url: str
    api_key: str
    platform: str


def check_misp_connection(url: str, api_key: str) -> dict:
    """Test MISP connection."""
    endpoint = f"{url.rstrip('/')}/servers/getPyMISPVersion.json"
    req = urllib.request.Request(
        endpoint,
        headers={
            "Authorization": api_key,
            "Accept": "application/json",
        }
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
            return {"status": "ok", "version": data.get("version")}
    except urllib.error.HTTPError as e:
        return {"status": "error", "code": e.code}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def check_opencti_connection(url: str, api_key: str) -> dict:
    """Test OpenCTI GraphQL connection."""
    endpoint = f"{url.rstrip('/')}/graphql"
    query = '{"query": "{ about { version } }"}'
    req = urllib.request.Request(
        endpoint,
        data=query.encode(),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
            version = data.get("data", {}).get("about", {}).get("version")
            return {"status": "ok", "version": version}
    except Exception as e:
        return {"status": "error", "message": str(e)[:100]}


def check_taxii_server(url: str, auth_header: str | None = None) -> dict:
    """Test TAXII 2.1 server connection."""
    discovery_url = f"{url.rstrip('/')}/taxii/"
    headers: dict = {"Accept": "application/taxii+json;version=2.1"}
    if auth_header:
        headers["Authorization"] = auth_header
    req = urllib.request.Request(discovery_url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
            return {
                "status": "ok",
                "title": data.get("title"),
                "description": data.get("description", "")[:100],
            }
    except Exception as e:
        return {"status": "error", "message": str(e)[:100]}


def validate_stix_bundle(bundle_path: str) -> dict:
    """Basic validation of a STIX bundle."""
    import pathlib
    try:
        data = json.loads(pathlib.Path(bundle_path).read_text())
        if data.get("type") != "bundle":
            return {"valid": False, "error": "Not a bundle type"}
        objects = data.get("objects", [])
        types = {}
        for obj in objects:
            t = obj.get("type", "unknown")
            types[t] = types.get(t, 0) + 1
        return {
            "valid": True,
            "spec_version": data.get("spec_version"),
            "object_count": len(objects),
            "types": types,
        }
    except json.JSONDecodeError as e:
        return {"valid": False, "error": f"JSON parse error: {e}"}
    except FileNotFoundError:
        return {"valid": False, "error": "File not found"}


def main() -> None:
    parser = argparse.ArgumentParser(description="TIP connection and validation tool")
    sub = parser.add_subparsers(dest="cmd", required=True)

    misp_p = sub.add_parser("misp", help="Test MISP connection")
    misp_p.add_argument("url")
    misp_p.add_argument("api_key")

    octi_p = sub.add_parser("opencti", help="Test OpenCTI connection")
    octi_p.add_argument("url")
    octi_p.add_argument("api_key")

    taxii_p = sub.add_parser("taxii", help="Test TAXII server")
    taxii_p.add_argument("url")
    taxii_p.add_argument("--auth", help="Authorization header value")

    stix_p = sub.add_parser("validate-stix", help="Validate STIX bundle")
    stix_p.add_argument("bundle_path")

    args = parser.parse_args()

    if args.cmd == "misp":
        result = check_misp_connection(args.url, args.api_key)
        print(f"MISP: {result}")

    elif args.cmd == "opencti":
        result = check_opencti_connection(args.url, args.api_key)
        print(f"OpenCTI: {result}")

    elif args.cmd == "taxii":
        result = check_taxii_server(args.url, args.auth)
        print(f"TAXII: {result}")

    elif args.cmd == "validate-stix":
        result = validate_stix_bundle(args.bundle_path)
        if result["valid"]:
            print(f"[+] Valid STIX bundle")
            print(f"    Version: {result.get('spec_version')}")
            print(f"    Objects: {result.get('object_count')}")
            print(f"    Types: {result.get('types')}")
        else:
            print(f"[!] Invalid: {result.get('error')}")


if __name__ == "__main__":
    main()
```

The next file covers MISP platform usage.

<!-- detect-validate-64 -->
## TIP-Value Validation — Does Intel Actually Reach Operations?

A threat-intel platform is judged not by *having aggregated feeds* but by **whether collected intel maps to intelligence requirements (PIRs) and actually reaches detection/blocking/response decisions to be actionable**. Validate only on **owned TIPs**.

### Item -> Failure mode -> Validation method -> Healthy signal

| Item | Failure mode | Validation method | Healthy signal |
|---|---|---|---|
| Requirement mapping | Aimless collection | Coverage vs PIRs | Intel->requirement mapped |
| Actionability | Reports only | Trace detection handoff | Converted to rules/blocks |
| Timeliness | Stale intel | Measure collect->distribute lag | Distributed within SLA |
| Confidence | Unrated source | Confidence scoring | Source/confidence labeled |

### Defense validation (verify directly)

```bash
# 1) Whether TIP intel is actually exported to detection systems (SIEM/EDR) — owned TIP only
curl -s -H "Authorization: $TIP_KEY" https://tip.local/api/exports 2>/dev/null | jq '.[].destination' | sort -u || echo "verify intel export integrations exist"
# 2) Whether collected intel actually carries PIR/priority tags (no tags = not actionable)
curl -s -H "Authorization: $TIP_KEY" https://tip.local/api/indicators?limit=20 2>/dev/null | jq '.[].tags' | head || echo "check that indicators carry priority/PIR tags"
```

> Validate only on **owned TIPs**. "Aggregated feeds" differs from "intel reaches operations" — confirm directly via exports and tagging ([[25_Threat_Intelligence]], [[13_SOC_Blue_Team]]).
