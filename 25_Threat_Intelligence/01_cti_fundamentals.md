> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 위협 인텔리전스 기초 (CTI)

## 0. 초보자를 위한 개념 이해

### 위협 인텔리전스(CTI)란?

**CTI(Cyber Threat Intelligence)**는 단순한 보안 데이터가 아니라, 공격자에 대한 **"맥락 있는 정보"**입니다.

```
데이터 vs 인텔리전스 비교:

데이터 (단순 로그):
  "2026-06-02 03:15:42 IP 203.0.113.42에서 로그인 실패"
  → 이 IP가 위험한지? 왜 공격하는지? 모름

인텔리전스 (맥락화된 정보):
  "203.0.113.42는 Lazarus Group(북한 국가 지원 APT)이 사용하는
   C2 서버 IP입니다. 금융 기관을 주로 표적으로 삼으며,
   최근 국내 은행 3곳에 스피어피싱 캠페인 진행 중입니다."
  → 즉각 차단 + 임원 보고 + 다른 금융 기관과 공유 결정 가능
```

**비유:** 범죄 수사에서의 차이
- 단순 데이터 = 범죄 현장 사진 몇 장
- 인텔리전스 = 범인의 과거 전력, 범행 수법, 공범 네트워크, 다음 타깃 예측

### CTI가 왜 필요한가?

```
CTI가 없는 보안팀:
  알림 폭탄 → 우선순위 없이 모두 처리 → 과부하 → 중요한 것 놓침
  
CTI가 있는 보안팀:
  알림 → CTI로 컨텍스트 파악 → 우선순위 결정 → 효율적 대응
  
구체적 활용:
  1. 방어 우선순위 결정: 우리를 공격하는 APT 그룹은 무엇을 노리나?
  2. 선제적 차단: IOC 기반으로 공격 시작 전에 차단
  3. 탐지 개선: 알려진 TTP 기반으로 SIEM 룰 작성
  4. 사고 대응 가속: "이 악성코드는 Cobalt Strike 변형, 다음 단계는..."
```

### 핵심 용어 정리

| 용어 | 의미 | 예시 |
|------|------|------|
| IOC (침해 지표) | 공격이 발생했음을 나타내는 증거 | 악성 IP, 악성 도메인, 파일 해시 |
| TTP | 전술(Tactics), 기법(Techniques), 절차(Procedures) | 스피어피싱 → 악성 매크로 → Cobalt Strike |
| APT | Advanced Persistent Threat (국가 지원 또는 고도화된 공격 그룹) | Lazarus(북한), APT28(러시아) |
| TTL (침해 지표 유효 기간) | IOC가 유효한 기간 | IP는 수일, 도메인은 수주, TTP는 수개월 |
| MISP | 오픈소스 CTI 공유 플랫폼 | 조직 간 IOC 공유 |
| STIX/TAXII | CTI 데이터 표준 형식/전송 프로토콜 | 자동화된 인텔리전스 공유 |

---

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
  │  예: 북한 APT가 2024년부터 국내     │
  │      반도체 기업 집중 공격           │
  ├────────────────────────────────────┤
  │  Operational (운영적)               │
  │  "이번 캠페인의 TTP는?"             │
  │  대상: 보안 분석팀                   │
  │  예: Lazarus가 이메일 피싱→드로퍼  │
  │      →Cobalt Strike 순서로 진행     │
  ├────────────────────────────────────┤
  │  Tactical (전술적)                  │
  │  IOC — IP, 도메인, 해시, YARA 룰   │
  │  대상: SOC, SIEM                   │
  │  예: C2 서버 IP 목록, 악성 도메인  │
  │      목록을 방화벽에 즉시 차단      │
  └────────────────────────────────────┘
```

---

## 2. 위협 행위자 분류 (TTPs)

### MITRE ATT&CK이란?

**MITRE ATT&CK**은 실제 공격자들의 행동 방식을 체계적으로 분류한 지식 베이스입니다. 전 세계 보안팀이 공통 언어로 사용합니다.

**왜 중요한가?**
```
ATT&CK 없을 때:
  "악성코드가 실행됐어요" → 어떻게 대응해야 할지 막막

ATT&CK 있을 때:
  "T1059.003 Windows Command Shell이 실행됐어요"
  → 다음 단계는 T1082 시스템 정보 수집이나 T1003 크레덴셜 덤프일 가능성
  → 선제적으로 해당 탐지 룰 강화, 네트워크 격리 준비
```

**ATT&CK 활용 방법:**
1. **탐지 개선**: 각 기법에는 "탐지 방법"이 있어 SIEM 룰 작성에 활용
2. **공격 시뮬레이션**: 레드팀이 실제 APT의 TTP를 재현해서 방어 능력 테스트
3. **갭 분석**: "우리가 못 막는 기법은 어떤 것인가?" 파악
4. **위협 리포트 작성**: 표준화된 언어로 공격 그룹의 TTP 문서화

MITRE ATT&CK 프레임워크는 실제 공격자의 전술(Tactics)과 기법(Techniques)을 분류한 지식 베이스입니다. 위협 인텔리전스 분석, 보안 탐지 룰 작성, 레드팀 시뮬레이션 계획 수립에 표준 참조 체계로 활용됩니다.

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

### IOC(침해 지표)란?

**IOC(Indicator of Compromise)**는 공격이 발생했다는 **증거 또는 신호**입니다.

**비유:** 집에 도둑이 들었다는 증거처럼:
- 깨진 창문 = 특정 파일 해시 (악성코드 파일)
- 낯선 발자국 = 알 수 없는 IP 접속 기록
- 도둑이 자주 쓰는 수법 = TTP

**중요한 개념: Pyramid of Pain (고통의 피라미드)**  
공격자가 IOC를 바꾸기 얼마나 쉬운지를 나타냅니다:

```
         [TTPs]         ← 방어자가 막기 가장 어렵지만
        [Tools]           공격자가 바꾸기도 가장 어려움
   [Network/Host Artifacts]
     [Domain Names / IPs]
        [Hash Values]   ← 공격자가 1초 만에 변경 가능

→ 파일 해시만 차단하면 공격자가 파일 조금만 바꿔서 우회
→ TTP를 탐지/방어하는 것이 진짜 효과적인 방어
```

IoC(Indicator of Compromise)는 침해 발생 증거인 MD5 해시, IP 주소, 도메인, 파일 경로 등의 기술적 식별자입니다. SIEM이나 방화벽에 IoC를 등록하면 동일 공격자의 재방문을 자동으로 탐지하고 차단합니다.

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

### 자동화가 필요한 이유

수동으로 IOC를 수집하면:
- 하루에 수천 개의 새 IOC 발생
- 각 플랫폼마다 수동으로 확인 = 비효율
- 방화벽 업데이트 지연 = 보호 공백

자동화하면:
- 새 IOC가 등록되면 자동으로 방화벽/SIEM 차단 목록에 추가
- 여러 플랫폼의 IOC를 통합해서 중복 제거
- 만료된 IOC 자동 제거 (허위 차단 방지)

**VirusTotal API 사용법 기초:**
```
무료 API: 분당 4회 요청, 일일 500회
유료 API: 무제한 (기업용)

API 키 발급: https://www.virustotal.com → 회원가입 → API Key
```

CTI(사이버 위협 인텔리전스) 수집을 자동화합니다. VirusTotal, AbuseIPDB 등 공개 API에서 IOC 데이터를 수집하여 분석합니다.

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

MISP(Malware Information Sharing Platform)를 Docker로 설치합니다. 위협 인텔리전스를 구조화하고 조직 간 IOC를 공유하는 플랫폼입니다.

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

PyMISP 라이브러리로 MISP API에 접근합니다. IOC를 이벤트와 속성으로 추가하고 자동화된 위협 인텔리전스 수집 파이프라인을 구축합니다.

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

---

<!-- detect-validate-25 -->
## 위협 인텔 품질 검증 (정확·적시·실행가능)

위협 인텔은 *수집됐다*가 아니라 *정확하고 신선하며 탐지로 전환되는가*로 가치가 갈린다. 방어자는 **인텔이 오탐 없이 실행 가능한 탐지가 되는가**를 검증해야 한다. 검증은 **소유 피드/자산**에서만.

### 검증 항목 → 질문 → 측정 신호 → 함정

| 검증 항목 | 질문 | 측정 신호 | 함정 |
|---|---|---|---|
| IOC 신선도 | 만료된 IOC를 거르나? | 만료/age 분포 | TTL 무시 |
| 출처 신뢰도 | 1차 출처와 대조하나? | 다중출처 교차율 | 단일 출처 맹신 |
| 오탐(FP) | 정상 자산을 오인하나? | 화이트리스트 충돌 수 | 내부 인프라 차단 |
| 실행가능성 | 탐지로 전환되나? | IOC→룰 전환율 | 보고서로만 남음 |

### 방어 검증 (직접 확인)

```bash
# 1) IOC 신선도/만료 점검 — 오래된 IOC는 FP·소음 유발(소유 피드)
jq -r '.objects[] | select(.type=="indicator") | .valid_until' feed.json 2>/dev/null | sort | head
# 2) IOC가 정상 자산과 충돌하는지 화이트리스트 대조 — 충돌 = FP 위험
comm -12 <(sort iocs.txt 2>/dev/null) <(sort known_good_assets.txt 2>/dev/null) | head
```

> CTI 검증은 *수집됐는가*가 아니라 *정확·신선·실행가능한가*다 — "피드 받는다"와 "만료 IOC를 거르고 정상 자산과 충돌 없이 탐지로 전환된다"는 다르다. 소유 피드에서 신선도·FP를 직접 확인한다([[40_Threat_Hunting]], [[64_Threat_Intel_Platform]], [[13_SOC_Blue_Team]]).

---

<a name="english"></a>

# Cyber Threat Intelligence (CTI) Fundamentals

## 1. CTI Overview

```
Cyber Threat Intelligence (CTI):
  Not just raw security event data, but
  contextualized information about
  "who is attacking, why, and how."

Intelligence Tiers:
  ┌────────────────────────────────────┐
  │  Strategic                          │
  │  "Which threat actors are           │
  │   targeting our industry?"          │
  │  Audience: CISO, Executives         │
  ├────────────────────────────────────┤
  │  Operational                        │
  │  "What TTPs does this campaign use?"│
  │  Audience: Security Analysis Team   │
  ├────────────────────────────────────┤
  │  Tactical                           │
  │  IOCs — IPs, domains, hashes,       │
  │  YARA rules                         │
  │  Audience: SOC, SIEM                │
  └────────────────────────────────────┘
```

---

## 2. Threat Actor Classification (TTPs)

The MITRE ATT&CK framework is a knowledge base classifying real attackers' Tactics and Techniques. It is used as a standard reference for threat intelligence analysis, writing security detection rules, and planning red team simulations.

```
MITRE ATT&CK Framework:
  Tactics → Techniques → Procedures

  TA0001 Initial Access     T1566 Phishing, T1190 Exploit Public-Facing App
  TA0002 Execution          T1059 Command-Line, T1203 Client-Side Exploit
  TA0003 Persistence        T1053 Scheduled Task, T1547 Boot Autorun
  TA0004 Privilege Escalation T1055 Process Injection, T1548 UAC Bypass
  TA0005 Defense Evasion    T1070 Indicator Removal, T1027 Obfuscation
  TA0006 Credential Access  T1110 Brute Force, T1555 Password Stores
  TA0007 Discovery          T1082 System Info, T1083 File Discovery
  TA0008 Lateral Movement   T1021 Remote Services, T1534 Internal Spearphishing
  TA0009 Collection         T1113 Screen Capture, T1056 Keylogging
  TA0010 Exfiltration       T1041 C2 Channel, T1567 Web Service
  TA0011 Command & Control  T1071 App Layer Protocol (HTTP/DNS)
  TA0040 Impact             T1486 Ransomware, T1485 Data Destruction
```

---

## 3. IOC Types and Collection

An IoC (Indicator of Compromise) is a technical identifier such as an MD5 hash, IP address, domain, or file path that serves as evidence of a breach. Registering IoCs in a SIEM or firewall allows automatic detection and blocking of returning attackers.

```
IOC Confidence Pyramid (David Bianco's Pyramid of Pain):

  ┌────────────────────────────────────┐  Most painful
  │  TTPs (Behavioral Patterns)        │  ← Hardest for attacker to change
  │  Tools (Attack Toolkit)            │
  │  Network/Host Artifacts            │
  │  Domains/IPs                       │
  │  Hash Values                       │  ← Easiest to change
  └────────────────────────────────────┘  Least painful

IOC Types:
  File Hashes:  MD5, SHA-1, SHA-256
  IPs/Domains:  C2 servers, malware distribution points
  URLs:         Download paths, phishing pages
  Email:        Sender addresses, subject patterns
  Registry:     Persistence keys
  Mutex:        Malware singleton enforcement
  Certificates: TLS certificate fingerprints
```

---

## 4. Major CTI Feeds and Platforms

```
Free Feeds:
  AlienVault OTX   → https://otx.alienvault.com
  VirusTotal       → https://virustotal.com
  Abuse.ch         → URLhaus, MalwareBazaar, ThreatFox
  Shodan           → Internet-exposed assets
  Censys           → Internet scan data
  Have I Been Pwned → Credential leak verification

Threat Reports:
  CrowdStrike Global Threat Report
  Verizon DBIR (Data Breach Investigations Report)
  Mandiant M-Trends
  Microsoft MSTIC

CTI Platforms:
  MISP    → Open-source threat intelligence sharing
  OpenCTI → Open-source CTI management platform
  TheHive → Incident response + CTI integration
```

---

## 5. CTI Collection Automation

Automates CTI (Cyber Threat Intelligence) collection. Collects and analyzes IOC data from public APIs such as VirusTotal and AbuseIPDB.

```python
import requests
import hashlib
import json
import argparse
from pathlib import Path
from datetime import datetime

# VirusTotal API v3 wrapper
VT_BASE = "https://www.virustotal.com/api/v3"

def vt_file_report(api_key: str, file_path: str) -> dict:
    sha256 = hashlib.sha256(Path(file_path).read_bytes()).hexdigest()
    headers = {"x-apikey": api_key}
    resp = requests.get(f"{VT_BASE}/files/{sha256}", headers=headers, timeout=10)
    if resp.status_code == 404:
        return {"error": "File not found", "sha256": sha256}
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
            "verdict":    "malicious" if stats.get("malicious", 0) >= 5 else
                          "suspicious" if stats.get("suspicious", 0) >= 3 else "clean",
            "names":      attrs.get("names", [])[:5],
            "tags":       attrs.get("tags", []),
        }
    except (KeyError, TypeError):
        return {"raw": data}

def main() -> None:
    parser = argparse.ArgumentParser(description="VirusTotal IOC Lookup")
    parser.add_argument("--api-key",  required=True)
    parser.add_argument("--file",     help="File path")
    parser.add_argument("--ip",       help="IP address")
    parser.add_argument("--url",      help="URL")
    args = parser.parse_args()

    if args.file:
        raw = vt_file_report(args.api_key, args.file)
        result = parse_vt_result(raw)
        print(f"[File] {args.file}\n  {json.dumps(result, ensure_ascii=False, indent=2)}")

    if args.ip:
        raw = vt_ip_report(args.api_key, args.ip)
        result = parse_vt_result(raw)
        print(f"[IP] {args.ip}\n  {json.dumps(result, ensure_ascii=False, indent=2)}")

if __name__ == "__main__":
    main()
```

---

## 6. MISP — Open-Source CTI Sharing Platform

Install MISP (Malware Information Sharing Platform) via Docker. A platform for structuring threat intelligence and sharing IOCs between organizations.

```bash
# Install MISP via Docker
git clone https://github.com/MISP/misp-docker.git
cd misp-docker
cp template.env .env
docker compose up -d

# Add IOC via MISP API
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

Access the MISP API using the PyMISP library. Add IOCs as events and attributes, and build an automated threat intelligence collection pipeline.

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
    event.distribution = 1  # Community
    event.threat_level_id = 2  # Medium
    event.analysis = 1  # Ongoing

    created = misp.add_event(event)
    event_id = created["Event"]["id"]

    for ioc in iocs:
        attr = MISPAttribute()
        attr.type     = ioc["type"]
        attr.value    = ioc["value"]
        attr.to_ids   = ioc.get("to_ids", True)
        attr.comment  = ioc.get("comment", "")
        misp.add_attribute(event_id, attr)

    print(f"[+] MISP event created: ID={event_id}, {len(iocs)} IOCs")

def main() -> None:
    parser = argparse.ArgumentParser(description="MISP IOC Upload")
    parser.add_argument("--url",     required=True)
    parser.add_argument("--key",     required=True)
    parser.add_argument("--event",   default="Automated CTI Feed")
    parser.add_argument("--ioc-file", required=True, help="JSON file path")
    args = parser.parse_args()

    import json
    iocs = json.loads(open(args.ioc_file).read())
    push_iocs_to_misp(args.url, args.key, iocs, args.event)

if __name__ == "__main__":
    main()
```

---

## 7. Threat Actor Profiling

```
Major APT Group Classification:

[Nation-State Sponsored]
  APT28 (Fancy Bear)  — Russia, GRU, political/military espionage
  APT29 (Cozy Bear)   — Russia, SVR, diplomatic & think-tank targets
  APT41               — China, espionage + financial motivation
  Lazarus Group       — North Korea, financial institutions & cryptocurrency
  APT33 (Elfin)       — Iran, energy & aerospace

[Financially Motivated]
  FIN7/Carbanak  — PoS systems, banking trojans
  Evil Corp      — Dridex, ransomware distribution
  REvil/Sodinokibi → Ransomware-as-a-Service (RaaS)

Profile Items:
  - Motivation (espionage / financial / hacktivism)
  - Primary target industries
  - Initial access vectors
  - Preferred malware/tools
  - C2 infrastructure characteristics
  - MITRE ATT&CK mapping
```

---

## 8. CTI Report Structure

```
Executive Summary (1 page):
  - Threat actor identification or campaign name
  - Target and potential impact
  - Top 3 key recommendations

Technical Analysis:
  1. Attack timeline
  2. Initial access vector
  3. Malware analysis (hashes, behaviors)
  4. C2 infrastructure (IPs, domains, certificates)
  5. MITRE ATT&CK mapping table
  6. Detection signatures (YARA, Sigma)

Indicators of Compromise:
  MD5/SHA-256 hash list
  IP address list
  Domain list
  URL list
  Registry keys

Mitigation & Recommendations:
  Immediate actions (24 hours)
  Short-term actions (1 week)
  Long-term actions (1 month+)
```

<!-- detect-validate-25 -->
## Threat-Intel Quality Validation (Accurate, Timely, Actionable)

Threat intel's value comes not from *whether it was collected* but from *whether it is accurate, fresh, and converts into detection*. Defenders must verify **whether intel becomes actionable detection without false positives**. Validate only on **owned feeds/assets**.

### Check -> Question -> Signal -> Pitfall

| Check | Question | Signal | Pitfall |
|---|---|---|---|
| IOC freshness | Does it filter expired IOCs? | Expiry/age distribution | Ignoring TTL |
| Source reliability | Cross-checked with primary source? | Multi-source cross rate | Trusting a single source |
| False positives | Does it misflag good assets? | Whitelist conflict count | Blocking internal infra |
| Actionability | Does it convert to detection? | IOC->rule conversion rate | Stays as a report only |

### Defense validation (verify directly)

```bash
# 1) Check IOC freshness/expiry — stale IOCs cause FPs/noise (owned feed)
jq -r '.objects[] | select(.type=="indicator") | .valid_until' feed.json 2>/dev/null | sort | head
# 2) Cross-check IOCs against a whitelist for conflicts — conflict = FP risk
comm -12 <(sort iocs.txt 2>/dev/null) <(sort known_good_assets.txt 2>/dev/null) | head
```

> CTI validation is *whether it's accurate, fresh, and actionable*, not *whether it was collected* -- "we get a feed" differs from "it filters expired IOCs and converts to detection without conflicting with good assets". Confirm freshness and FPs on owned feeds directly ([[40_Threat_Hunting]], [[64_Threat_Intel_Platform]], [[13_SOC_Blue_Team]]).
