# 위협 인텔리전스 플랫폼 기초

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
