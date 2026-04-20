# 위협 인텔리전스 기초 (CTI)

## 1. CTI 개요

```
위협 인텔리전스(CTI)란:
  단순 보안 이벤트 데이터가 아닌,
  "누가, 왜, 어떻게 공격하는가"에 대한
  맥락화된 정보.

인텔리전스 계층:
  ┌────────────────────────────────────┐
  │  Strategic (전략적)                 │
  │  "어떤 위협 행위자가 우리 산업을    │
  │   타깃으로 삼는가?"                  │
  │  대상: CISO, 경영진                 │
  ├────────────────────────────────────┤
  │  Operational (운영적)               │
  │  "이번 캠페인의 TTP는?"             │
  │  대상: 보안 분석팀                   │
  ├────────────────────────────────────┤
  │  Tactical (전술적)                  │
  │  IOC — IP, 도메인, 해시, YARA 룰   │
  │  대상: SOC, SIEM                   │
  └────────────────────────────────────┘
```

---

## 2. 위협 행위자 분류 (TTPs)

```
MITRE ATT&CK 프레임워크:
  Tactics (전술) → Techniques (기법) → Procedures (절차)

  TA0001 초기 접근    T1566 피싱, T1190 공개 서버 취약점 익스플로잇
  TA0002 실행         T1059 커맨드라인, T1203 클라이언트 익스플로잇
  TA0003 지속성       T1053 예약 작업, T1547 부팅 자동 실행
  TA0004 권한 상승    T1055 프로세스 인젝션, T1548 UAC 우회
  TA0005 방어 우회    T1070 흔적 삭제, T1027 코드 난독화
  TA0006 크레덴셜 접근 T1110 브루트포스, T1555 패스워드 스토어
  TA0007 탐색         T1082 시스템 정보, T1083 파일 탐색
  TA0008 수평 이동    T1021 원격 서비스, T1534 내부 스피어피싱
  TA0009 수집         T1113 화면 캡처, T1056 키로깅
  TA0010 유출         T1041 C2 채널, T1567 웹 서비스
  TA0011 C2           T1071 앱 레이어 프로토콜 (HTTP/DNS)
  TA0040 영향         T1486 랜섬웨어, T1485 데이터 파괴
```

---

## 3. IOC 유형 및 수집

```
IOC 신뢰도 피라미드 (David Bianco의 Pyramid of Pain):

  ┌────────────────────────────────────┐  방어자에게
  │  TTPs (행동 패턴)                   │  ← 가장 어렵게 변경
  │  도구 (공격 툴킷)                   │
  │  네트워크/호스트 아티팩트            │
  │  도메인/IP                          │
  │  해시값                             │  ← 가장 쉽게 변경
  └────────────────────────────────────┘  공격자에게

IOC 유형:
  파일 해시:  MD5, SHA-1, SHA-256
  IP/도메인: C2 서버, 악성 배포지
  URL:        다운로드 경로, 피싱 페이지
  이메일:     발신자, 제목 패턴
  레지스트리: 지속성 키
  뮤텍스:     악성코드 단독 실행 보장
  인증서:     TLS 인증서 지문
```

---

## 4. 주요 CTI 피드 및 플랫폼

```
무료 피드:
  AlienVault OTX   → https://otx.alienvault.com
  VirusTotal       → https://virustotal.com
  Abuse.ch         → URLhaus, MalwareBazaar, ThreatFox
  Shodan           → 인터넷 노출 자산
  Censys           → 인터넷 스캔 데이터
  Have I Been Pwned → 크레덴셜 유출 확인

위협 보고서:
  CrowdStrike Global Threat Report
  Verizon DBIR (Data Breach Investigations Report)
  Mandiant M-Trends
  Microsoft MSTIC

CTI 플랫폼:
  MISP    → 오픈소스 위협 인텔리전스 공유
  OpenCTI → 오픈소스 CTI 관리 플랫폼
  TheHive → 인시던트 대응 + CTI 통합
```

---

## 5. CTI 수집 자동화

```python
import requests
import hashlib
import json
import argparse
from pathlib import Path
from datetime import datetime

# VirusTotal API v3 래퍼
VT_BASE = "https://www.virustotal.com/api/v3"

def vt_file_report(api_key: str, file_path: str) -> dict:
    sha256 = hashlib.sha256(Path(file_path).read_bytes()).hexdigest()
    headers = {"x-apikey": api_key}
    resp = requests.get(f"{VT_BASE}/files/{sha256}", headers=headers, timeout=10)
    if resp.status_code == 404:
        return {"error": "파일 미발견", "sha256": sha256}
    return resp.json()

def vt_url_scan(api_key: str, url: str) -> dict:
    headers = {"x-apikey": api_key, "Content-Type": "application/x-www-form-urlencoded"}
    submit = requests.post(f"{VT_BASE}/urls", headers=headers,
                           data=f"url={url}", timeout=10)
    analysis_id = submit.json()["data"]["id"]

    import time; time.sleep(5)
    result = requests.get(f"{VT_BASE}/analyses/{analysis_id}", headers=headers, timeout=10)
    return result.json()

def vt_ip_report(api_key: str, ip: str) -> dict:
    headers = {"x-apikey": api_key}
    resp = requests.get(f"{VT_BASE}/ip_addresses/{ip}", headers=headers, timeout=10)
    return resp.json()

def parse_vt_result(data: dict) -> dict[str, object]:
    try:
        attrs = data["data"]["attributes"]
        stats = attrs.get("last_analysis_stats", {})
        return {
            "malicious":  stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "undetected": stats.get("undetected", 0),
            "verdict":    "악성" if stats.get("malicious", 0) >= 5 else
                          "의심" if stats.get("suspicious", 0) >= 3 else "정상",
            "names":      attrs.get("names", [])[:5],
            "tags":       attrs.get("tags", []),
        }
    except (KeyError, TypeError):
        return {"raw": data}

def main() -> None:
    parser = argparse.ArgumentParser(description="VirusTotal IOC 조회")
    parser.add_argument("--api-key",  required=True)
    parser.add_argument("--file",     help="파일 경로")
    parser.add_argument("--ip",       help="IP 주소")
    parser.add_argument("--url",      help="URL")
    args = parser.parse_args()

    if args.file:
        raw = vt_file_report(args.api_key, args.file)
        result = parse_vt_result(raw)
        print(f"[파일] {args.file}\n  {json.dumps(result, ensure_ascii=False, indent=2)}")

    if args.ip:
        raw = vt_ip_report(args.api_key, args.ip)
        result = parse_vt_result(raw)
        print(f"[IP] {args.ip}\n  {json.dumps(result, ensure_ascii=False, indent=2)}")

if __name__ == "__main__":
    main()
```

---

## 6. MISP — 오픈소스 CTI 공유 플랫폼

```bash
# MISP Docker 설치
git clone https://github.com/MISP/misp-docker.git
cd misp-docker
cp template.env .env
docker compose up -d

# MISP API로 IOC 추가
curl -H "Authorization: YOUR_API_KEY" \
     -H "Content-Type: application/json" \
     -X POST https://misp.local/attributes \
     -d '{
       "value": "185.234.218.23",
       "type": "ip-dst",
       "category": "Network activity",
       "to_ids": true,
       "comment": "Cobalt Strike C2"
     }'
```

```python
from pymisp import PyMISP, MISPEvent, MISPAttribute
import argparse

def push_iocs_to_misp(
    misp_url: str, api_key: str,
    iocs: list[dict], event_info: str
) -> None:
    misp = PyMISP(misp_url, api_key, ssl=False)

    event = MISPEvent()
    event.info = event_info
    event.distribution = 1  # 커뮤니티
    event.threat_level_id = 2  # 중간
    event.analysis = 1  # 진행 중

    created = misp.add_event(event)
    event_id = created["Event"]["id"]

    for ioc in iocs:
        attr = MISPAttribute()
        attr.type     = ioc["type"]
        attr.value    = ioc["value"]
        attr.to_ids   = ioc.get("to_ids", True)
        attr.comment  = ioc.get("comment", "")
        misp.add_attribute(event_id, attr)

    print(f"[+] MISP 이벤트 생성: ID={event_id}, IOC {len(iocs)}개")

def main() -> None:
    parser = argparse.ArgumentParser(description="MISP IOC 업로드")
    parser.add_argument("--url",     required=True)
    parser.add_argument("--key",     required=True)
    parser.add_argument("--event",   default="Automated CTI Feed")
    parser.add_argument("--ioc-file", required=True, help="JSON 파일 경로")
    args = parser.parse_args()

    import json
    iocs = json.loads(open(args.ioc_file).read())
    push_iocs_to_misp(args.url, args.key, iocs, args.event)

if __name__ == "__main__":
    main()
```

---

## 7. 위협 행위자 프로파일링

```
주요 APT 그룹 분류:

[국가 후원]
  APT28 (Fancy Bear)  — 러시아, GRU, 정치/군사 스파이
  APT29 (Cozy Bear)   — 러시아, SVR, 외교·싱크탱크
  APT41               — 중국, 스파이 + 금전적 동기
  Lazarus Group       — 북한, 금융기관·암호화폐 타겟
  APT33 (Elfin)       — 이란, 에너지·항공우주

[금전적 동기]
  FIN7/Carbanak  — PoS 시스템, 뱅킹 트로이목마
  Evil Corp      — Dridex, 랜섬웨어 배포
  REvil/Sodinokibi → 서비스형 랜섬웨어 (RaaS)

프로파일 항목:
  - 동기 (간첩/금전/핵티비즘)
  - 주요 타겟 산업
  - 초기 침투 벡터
  - 선호 악성코드/도구
  - C2 인프라 특징
  - MITRE ATT&CK 매핑
```

---

## 8. CTI 보고서 작성 구조

```
Executive Summary (1페이지):
  - 위협 행위자 식별 또는 캠페인명
  - 타깃 및 잠재적 영향
  - 주요 권고사항 3가지

Technical Analysis:
  1. 공격 타임라인
  2. 초기 침투 벡터
  3. 사용된 악성코드 분석 (해시, 행위)
  4. C2 인프라 (IP, 도메인, 인증서)
  5. MITRE ATT&CK 매핑 테이블
  6. 탐지 시그니처 (YARA, Sigma)

Indicators of Compromise:
  MD5/SHA-256 해시 목록
  IP 주소 목록
  도메인 목록
  URL 목록
  레지스트리 키

Mitigation & Recommendations:
  즉시 조치 (24시간)
  단기 조치 (1주)
  장기 조치 (1개월+)
```
