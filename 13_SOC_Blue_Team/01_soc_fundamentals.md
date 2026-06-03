> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# SOC 핵심 개념 및 Blue Team 기초

## 0. 초보자를 위한 개념 이해

### SOC란?

SOC(Security Operations Center)는 조직의 IT 시스템을 24시간 모니터링하고 사이버 위협에 대응하는 전담 보안 팀입니다. 공격자(Red Team)와 반대로, SOC는 방어자(Blue Team) 역할을 수행하며 로그 분석, 침해 탐지, 사고 대응을 담당합니다. 현대 보안 직군 중 가장 안정적이고 수요가 높은 분야로, SIEM 운영과 인시던트 대응 능력이 핵심입니다.

**왜 배우는가:**
```
사이버 보안 직군에서 SOC의 위치:

  공격팀 (Red Team)
    침투 테스트 / 버그바운티
           ↕  (Purple Team — 협력)
  방어팀 (Blue Team = SOC)
    탐지 / 대응 / 위협 헌팅

  SOC 취업 경로:
    IT 운영 경험 → Tier 1 분석가 →
    Tier 2 조사관 → Tier 3 위협 헌터 →
    탐지 엔지니어 / CISO
```

### 핵심 개념 정리

```
SOC 핵심 용어:

  SIEM      — 보안 정보·이벤트 관리 (Splunk, QRadar)
  Alert     — SIEM이 이상 탐지 시 발생하는 알림
  Triage    — 알림의 우선순위 분류 및 초기 조사
  IOC       — Indicator of Compromise (침해 지표)
              IP, 도메인, 파일 해시, 레지스트리 키
  TTPs      — Tactics/Techniques/Procedures (공격 패턴)
  MITRE ATT&CK — 공격 기법 분류 체계 (표준 참조)
  Playbook  — 특정 알림 유형에 대한 대응 절차서

Tier별 역할:
  Tier 1 — 알림 모니터링, 초기 분류, 에스컬레이션
  Tier 2 — 심층 분석, 포렌식, 인시던트 대응
  Tier 3 — 위협 헌팅, 제로데이, 악성코드 리버싱
```

### 필요한 도구 및 환경
- **Splunk Free**: SIEM 기본 학습 환경 (무료 500MB/일)
- **MITRE ATT&CK Navigator**: 공격 기법 시각화 및 학습
- **Elastic SIEM (ELK Stack)**: 오픈소스 SIEM 환경
- **Any.run / VirusTotal**: 악성코드 분석 온라인 샌드박스

### 기초 실습 예제
```python
#!/usr/bin/env python3
"""SOC 알림 트리아지 — 우선순위 자동 분류기."""

from dataclasses import dataclass
from datetime import datetime
from enum import IntEnum


class Severity(IntEnum):
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    INFO = 0


@dataclass
class Alert:
    alert_id: str
    title: str
    severity: Severity
    source_ip: str
    event_count: int
    first_seen: datetime
    mitre_technique: str | None = None


def triage_alert(alert: Alert) -> dict[str, str]:
    """알림 심각도와 컨텍스트를 기반으로 대응 권고안 생성."""
    action_map: dict[Severity, str] = {
        Severity.CRITICAL: "즉시 에스컬레이션 — Tier 2 호출",
        Severity.HIGH:     "30분 내 조사 시작 — IOC 확인",
        Severity.MEDIUM:   "4시간 내 검토 — FP 여부 확인",
        Severity.LOW:      "일일 배치 검토",
        Severity.INFO:     "로그 보관만",
    }
    return {
        "alert_id":      alert.alert_id,
        "recommended":   action_map[alert.severity],
        "ioc_to_check":  alert.source_ip,
        "mitre":         alert.mitre_technique or "미분류",
    }


if __name__ == "__main__":
    sample = Alert(
        alert_id="ALT-2026-001",
        title="Brute Force Login Attempt",
        severity=Severity.HIGH,
        source_ip="203.0.113.45",
        event_count=250,
        first_seen=datetime.now(),
        mitre_technique="T1110 — Brute Force",
    )
    result = triage_alert(sample)
    for k, v in result.items():
        print(f"{k:15s}: {v}")
```

---

## SOC (Security Operations Center) 개요

```
SOC 구조도
─────────────────────────────────────────────
                  CISO
                   │
              SOC Manager
                   │
     ┌─────────────┼─────────────┐
     │             │             │
  Tier 1         Tier 2        Tier 3
 (Alert)      (Analysis)   (Threat Hunt)
  모니터링       조사/대응     APT 추적
─────────────────────────────────────────────

Tier 1: 알림 트리아지, 초기 대응, 에스컬레이션
Tier 2: 심층 분석, 인시던트 대응, 포렌식
Tier 3: 위협 헌팅, 제로데이, 악성코드 리버싱
```

---

## 1. SOC 핵심 프로세스

### 인시던트 대응 사이클 (PICERL)

```
Preparation → Identification → Containment
     │                               │
 Recovery ← Eradication ← Lessons Learned
```

| 단계 | 행동 |
|------|------|
| **Preparation** | 도구 준비, 플레이북 작성, 훈련 |
| **Identification** | 이상 탐지, 알림 분류, 초기 조사 |
| **Containment** | 격리, 네트워크 차단, 계정 잠금 |
| **Eradication** | 악성코드 제거, 취약점 패치 |
| **Recovery** | 시스템 복구, 서비스 재개, 모니터링 강화 |
| **Lessons Learned** | 사후 분석, 문서화, 개선 |

### SOC 메트릭 (KPI)

```
MTTD (Mean Time to Detect): 탐지까지 평균 시간
MTTR (Mean Time to Respond): 대응까지 평균 시간
MTTC (Mean Time to Contain): 격리까지 평균 시간

업계 평균:
  MTTD: 197일 (IBM Cost of Data Breach 2023)
  MTTR: 70일
  목표: MTTD < 1시간, MTTR < 4시간
```

---

## 2. SIEM 아키텍처

### 데이터 수집 흐름

```
엔드포인트/서버    네트워크 장비    클라우드/앱
     │                 │               │
  Syslog/WEF       SNMP/NetFlow     API/웹훅
     └────────────────┬───────────────┘
                      │
                  Log Shipper
              (Fluentd/Logstash/
               NXLog/Winlogbeat)
                      │
                  [SIEM 엔진]
              (Splunk/QRadar/ELK)
                      │
          ┌───────────┼───────────┐
      파싱/정규화    상관분석    알림/대시보드
```

### 수집해야 할 핵심 로그 소스

```
우선순위 1 (필수):
  ✓ Windows Security Event Log (ID 4624, 4625, 4688...)
  ✓ Active Directory (로그인, 정책 변경, 그룹 변경)
  ✓ Firewall/IDS/IPS 로그
  ✓ DNS 쿼리 로그
  ✓ DHCP 로그
  ✓ Proxy/웹 필터 로그
  ✓ EDR (Endpoint Detection & Response) 알림

우선순위 2 (권장):
  ✓ VPN 접속 로그
  ✓ 이메일 게이트웨이 로그
  ✓ 클라우드 서비스 (AWS CloudTrail, Azure Activity)
  ✓ 웹 서버 (Apache/Nginx/IIS)
  ✓ 데이터베이스 감사 로그

우선순위 3 (고급):
  ✓ NetFlow/IPFIX 네트워크 플로우
  ✓ 인증서 투명성 로그
  ✓ Honeypot 알림
```

---

## 3. 핵심 Windows 이벤트 ID

### 인증 관련

```
4624  - 로그인 성공
  Logon Type 2  = 대화형 로그인 (콘솔)
  Logon Type 3  = 네트워크 로그인 (SMB, 파일 공유)
  Logon Type 4  = 배치 작업
  Logon Type 5  = 서비스 로그인
  Logon Type 7  = 워크스테이션 잠금 해제
  Logon Type 8  = 네트워크 평문 자격증명
  Logon Type 10 = 원격 대화형 (RDP)
  Logon Type 11 = 캐시된 자격증명

4625  - 로그인 실패
  Sub Status:
  0xC000006D = 잘못된 사용자명 또는 비밀번호
  0xC000006A = 잘못된 비밀번호
  0xC0000064 = 존재하지 않는 사용자
  0xC000006F = 허용 시간 외 로그인
  0xC0000070 = 허용되지 않은 워크스테이션
  0xC0000234 = 계정 잠김

4648  - 명시적 자격증명으로 로그인 (RunAs)
4768  - Kerberos TGT 요청
4769  - Kerberos 서비스 티켓 요청
4771  - Kerberos 사전 인증 실패
4776  - NTLM 인증 시도
```

### 프로세스 관련

```
4688  - 새 프로세스 생성 (CommandLine 포함 필수)
4689  - 프로세스 종료
4698  - 예약 작업 생성
4702  - 예약 작업 수정
7045  - 새 서비스 설치
4697  - 새 서비스 설치 (Security 로그)
```

### 계정/권한 관련

```
4720  - 사용자 계정 생성
4722  - 사용자 계정 활성화
4725  - 사용자 계정 비활성화
4726  - 사용자 계정 삭제
4728  - 보안 그룹에 멤버 추가
4732  - 로컬 그룹에 멤버 추가
4756  - 유니버설 그룹에 멤버 추가
4738  - 사용자 계정 변경
4740  - 사용자 계정 잠김
4767  - 사용자 계정 잠금 해제

1102  - 감사 로그 삭제 (의심스러운 행동!)
4719  - 감사 정책 변경
```

### 네트워크/공유 관련

```
5140  - 네트워크 공유 접근
5145  - 공유 파일 접근 확인
5156  - Windows 방화벽 연결 허용
5157  - Windows 방화벽 연결 차단
4776  - NTLM 자격증명 검증
```

---

## 4. 핵심 공격 탐지 패턴

### 무차별 대입 탐지

```
패턴: 동일 IP에서 짧은 시간 내 다수의 4625 이벤트

쿼리 예시 (Splunk):
index=security EventCode=4625
| stats count as FailedLogins, values(TargetUserName) as Users
  by IpAddress, host
| where FailedLogins > 10
| sort -FailedLogins

알림 임계값:
  5분 내 같은 IP에서 10회 이상 실패 → 알림
  1분 내 같은 IP에서 30회 이상 실패 → 즉시 차단
```

### 패스워드 스프레이 탐지

```
패턴: 많은 계정에 대해 소수의 로그인 시도
     (무차별 대입과 반대 방향)

쿼리:
index=security EventCode=4625
| bucket _time span=5m
| stats dc(TargetUserName) as UniqueUsers, count as Attempts
  by IpAddress, _time
| where UniqueUsers > 20 AND Attempts < 50
→ 많은 계정, 적은 시도 = 스프레이 공격
```

### Pass-the-Hash 탐지

```
패턴: Logon Type 3 + NTLM 인증 + 관리 공유 접근

index=security EventCode=4624 LogonType=3
| search AuthenticationPackageName="NTLM"
| search TargetUserName="*$" OR IpPort IN (445)
| table _time, IpAddress, TargetUserName, WorkstationName

추가 신호:
  - 정상 시간 외 접근
  - 관리자 계정으로 다수 호스트 이동
  - 방어: Protected Users 그룹 + Credential Guard
```

### Kerberoasting 탐지

```
패턴: 다수의 4769 이벤트, RC4 암호화 (0x17)

index=security EventCode=4769
| where TicketEncryptionType="0x17"  
| stats count by SubjectUserName, ServiceName, IpAddress
| where count > 5
| sort -count

→ 짧은 시간 내 여러 SPN의 RC4 티켓 요청 = Kerberoasting
```

### Golden Ticket 탐지

```
패턴: krbtgt 계정으로 발급된 것처럼 위장
     비정상적으로 긴 티켓 수명 (기본 10시간 초과)

index=security EventCode=4769
| eval ticket_lifetime_hours = (TicketEndTime - TicketStartTime) / 3600
| where ticket_lifetime_hours > 10
| table _time, AccountName, ServiceName, ticket_lifetime_hours

또는:
EventCode=4768 AND TicketOptions=0x40810010 AND EncryptionType=0x17
```

### Lateral Movement 탐지

```
패턴: 단일 호스트에서 다수 내부 호스트로 연결

# PsExec 탐지
EventCode=7045 AND ImagePath CONTAINS "PSEXESVC"

# WMI 원격 실행
EventCode=4688 AND Process_Command_Line CONTAINS "wmic"
                AND Process_Command_Line CONTAINS "/node:"

# PowerShell Remoting
EventCode=4688 AND Process_Command_Line CONTAINS "Enter-PSSession"
EventCode=4688 AND Process_Command_Line CONTAINS "Invoke-Command"

# 비정상 네트워크 연결 (포트 기반)
index=network dest_port IN (445, 135, 139, 5985, 5986)
| stats dc(dest) as UniqueTargets by src
| where UniqueTargets > 10
```

---

## 5. EDR 알림 분석

### EDR 도구 비교

| 도구 | 강점 | 특이점 |
|------|------|--------|
| **CrowdStrike Falcon** | 클라우드 기반, 인텔리전스 | 시장 점유율 1위 |
| **Microsoft Defender for Endpoint** | Windows 통합 | M365 E5 포함 |
| **SentinelOne** | AI 기반 자율 대응 | Rollback 기능 |
| **Carbon Black** | 프로세스 트리 시각화 | VMware 인수 |
| **Elastic Security** | 오픈소스 + ELK | 비용 효율적 |

### EDR 알림 분류 가이드

```
True Positive (TP): 실제 위협 → 즉시 대응
False Positive (FP): 정상 행위 → 화이트리스트 추가
True Negative (TN): 정상 통과 → 정상
False Negative (FN): 위협 미탐 → 규칙 개선

FP 처리 프로세스:
1. 알림 맥락 분석 (시간, 사용자, 행위)
2. 해당 사용자/팀에 확인
3. 정상 업무 확인 시 예외 추가
4. 예외 사유 문서화
5. 주기적 예외 목록 검토
```

---

## 6. 인시던트 대응 플레이북

### 멀웨어 감염 대응

```
1. 탐지
   - EDR 알림 수신
   - 영향받은 호스트 확인
   
2. 초기 트리아지 (15분 내)
   - 호스트 격리 여부 결정
   - 비즈니스 영향도 평가
   - 에스컬레이션 여부 결정

3. 격리 (결정 후 즉시)
   - 네트워크 격리 (EDR/NAC)
   - 비밀번호 변경 (해당 계정)
   - 관련 시스템 임시 차단

4. 조사 (1-4시간)
   - 프로세스 트리 분석
   - 네트워크 연결 분석
   - 파일 시스템 변경 확인
   - 감염 경로 추적 (이메일? 웹? USB?)

5. 제거 (4-8시간)
   - 악성 파일 삭제
   - 레지스트리 정리
   - 지속성 메커니즘 제거
   - 취약점 패치

6. 복구
   - 클린 이미지 복원 OR 정리 후 검증
   - 서비스 재개
   - 72시간 집중 모니터링

7. 사후 분석
   - 타임라인 재구성
   - IOC 추출 및 공유
   - 탐지 갭 식별
   - 예방 조치 권고
```

### 피싱 이메일 대응

```
1. 신고 접수
   - 이메일 전체 헤더 확보
   - 첨부파일/링크 절대 클릭 금지

2. 분석
   - 발신자 도메인/IP 확인
   - 링크 분석 (VirusTotal, URLScan)
   - 첨부파일 분석 (Sandbox)
   - 동일 이메일 수신자 확인 (SIEM)

3. 격리
   - 이메일 게이트웨이에서 동일 이메일 차단
   - 이미 클릭한 사용자 식별
   - 링크/첨부파일 차단 (프록시/방화벽)

4. 사용자 통지
   - 영향받은 사용자에게 즉시 통보
   - 비밀번호 변경 지시
   - MFA 확인

5. 사후 분석
   - 피싱 유형 분류 (자격증명 수집? 멀웨어 배포?)
   - SPF/DKIM/DMARC 정책 강화
   - 보안 인식 훈련 업데이트
```

---

## 7. 위협 인텔리전스 활용

### IOC (Indicator of Compromise) 유형

```
네트워크 기반:
  IP 주소: 192.168.1.100
  도메인: malware.evil.com
  URL: http://evil.com/payload.exe
  SSL 인증서 해시
  JA3/JA3S 핑거프린트

호스트 기반:
  파일 해시 (MD5, SHA1, SHA256)
  파일 경로: C:\Users\Public\svchot.exe
  레지스트리 키
  뮤텍스 이름
  파이프 이름

행위 기반 (TTP):
  MITRE ATT&CK 기법 ID
  PowerShell 난독화 패턴
  네트워크 통신 패턴
```

### MITRE ATT&CK 프레임워크 활용

```
전술 (Tactics) → 전략 (Techniques) → 절차 (Procedures)

예: Cobalt Strike 탐지
  전술: Command and Control (TA0011)
  기법: Application Layer Protocol (T1071)
  절차: HTTP/S를 통한 C2 비콘

MITRE 매핑으로:
1. 공격자 행위 표준화
2. 탐지 갭 식별
3. 커버리지 측정

도구: ATT&CK Navigator
  https://mitre-attack.github.io/attack-navigator/
```

### 위협 인텔리전스 피드 통합

```python
#!/usr/bin/env python3
"""
멀티소스 위협 인텔리전스 조회 CLI
사용: python3 threat_intel.py --ip 1.2.3.4 --abuseipdb-key KEY --vt-key KEY
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import dataclass, field
from typing import Optional

import requests


@dataclass
class IOCResult:
    indicator: str
    indicator_type: str
    sources: dict = field(default_factory=dict)
    is_malicious: bool = False
    confidence: int = 0

    def to_dict(self) -> dict:
        return {
            "indicator": self.indicator,
            "type": self.indicator_type,
            "is_malicious": self.is_malicious,
            "confidence": self.confidence,
            "sources": self.sources,
        }


class ThreatIntelClient:
    """AbuseIPDB + VirusTotal 멀티소스 위협 인텔리전스 클라이언트"""

    ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
    VT_IP_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    VT_HASH_URL = "https://www.virustotal.com/api/v3/files/{hash}"
    VT_DOMAIN_URL = "https://www.virustotal.com/api/v3/domains/{domain}"

    def __init__(
        self,
        abuseipdb_key: Optional[str] = None,
        vt_key: Optional[str] = None,
        timeout: int = 10,
    ) -> None:
        self.abuseipdb_key = abuseipdb_key
        self.vt_key = vt_key
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers["User-Agent"] = "ThreatIntelCLI/1.0"

    # ------------------------------------------------------------------ #
    #  AbuseIPDB
    # ------------------------------------------------------------------ #
    def _query_abuseipdb(self, ip: str) -> dict:
        if not self.abuseipdb_key:
            return {}
        try:
            resp = self.session.get(
                self.ABUSEIPDB_URL,
                params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
                headers={"Key": self.abuseipdb_key, "Accept": "application/json"},
                timeout=self.timeout,
            )
            resp.raise_for_status()
            data = resp.json().get("data", {})
            return {
                "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                "country": data.get("countryCode", ""),
                "total_reports": data.get("totalReports", 0),
                "last_reported": data.get("lastReportedAt", ""),
                "isp": data.get("isp", ""),
                "domain": data.get("domain", ""),
                "is_tor": data.get("isTor", False),
            }
        except requests.RequestException as exc:
            return {"error": str(exc)}

    # ------------------------------------------------------------------ #
    #  VirusTotal
    # ------------------------------------------------------------------ #
    def _query_vt(self, url: str) -> dict:
        if not self.vt_key:
            return {}
        try:
            resp = self.session.get(
                url,
                headers={"x-apikey": self.vt_key},
                timeout=self.timeout,
            )
            resp.raise_for_status()
            attrs = resp.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "reputation": attrs.get("reputation", 0),
                "tags": attrs.get("tags", []),
            }
        except requests.RequestException as exc:
            return {"error": str(exc)}

    # ------------------------------------------------------------------ #
    #  공개 조회 메서드
    # ------------------------------------------------------------------ #
    def check_ip(self, ip: str, malicious_threshold: int = 30) -> IOCResult:
        result = IOCResult(indicator=ip, indicator_type="ip")
        abuse = self._query_abuseipdb(ip)
        vt = self._query_vt(self.VT_IP_URL.format(ip=ip))
        result.sources = {"abuseipdb": abuse, "virustotal": vt}

        score = abuse.get("abuse_confidence_score", 0)
        vt_malicious = vt.get("malicious", 0)
        result.confidence = max(score, min(vt_malicious * 10, 100))
        result.is_malicious = score >= malicious_threshold or vt_malicious >= 3
        return result

    def check_hash(self, file_hash: str) -> IOCResult:
        result = IOCResult(indicator=file_hash, indicator_type="hash")
        vt = self._query_vt(self.VT_HASH_URL.format(hash=file_hash))
        result.sources = {"virustotal": vt}
        vt_malicious = vt.get("malicious", 0)
        result.confidence = min(vt_malicious * 10, 100)
        result.is_malicious = vt_malicious >= 3
        return result

    def check_domain(self, domain: str) -> IOCResult:
        result = IOCResult(indicator=domain, indicator_type="domain")
        vt = self._query_vt(self.VT_DOMAIN_URL.format(domain=domain))
        result.sources = {"virustotal": vt}
        vt_malicious = vt.get("malicious", 0)
        result.confidence = min(vt_malicious * 10, 100)
        result.is_malicious = vt_malicious >= 3
        return result

    def bulk_check(
        self, indicators: list[str], ioc_type: str = "ip", rate_limit: float = 0.5
    ) -> list[IOCResult]:
        """여러 IOC를 레이트 리밋을 지키며 일괄 조회"""
        results: list[IOCResult] = []
        dispatch = {"ip": self.check_ip, "hash": self.check_hash, "domain": self.check_domain}
        checker = dispatch.get(ioc_type)
        if checker is None:
            raise ValueError(f"지원하지 않는 유형: {ioc_type}. 가능한 값: {list(dispatch)}")

        for idx, indicator in enumerate(indicators, 1):
            print(f"[{idx}/{len(indicators)}] {indicator} 조회 중...", file=sys.stderr)
            res = checker(indicator)
            results.append(res)
            if idx < len(indicators):
                time.sleep(rate_limit)
        return results


# ------------------------------------------------------------------ #
#  CLI
# ------------------------------------------------------------------ #
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="멀티소스 위협 인텔리전스 IOC 조회 도구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="예시:\n"
               "  python3 threat_intel.py --ip 8.8.8.8\n"
               "  python3 threat_intel.py --hash d41d8cd98f00b204e9800998ecf8427e\n"
               "  python3 threat_intel.py --domain evil.example.com\n"
               "  python3 threat_intel.py --file iocs.txt --type ip --json",
    )
    parser.add_argument("--ip", metavar="IP", help="단일 IP 주소 조회")
    parser.add_argument("--hash", metavar="HASH", help="파일 해시 조회 (MD5/SHA256)")
    parser.add_argument("--domain", metavar="DOMAIN", help="도메인 조회")
    parser.add_argument("--file", metavar="FILE", help="IOC 목록 파일 (한 줄에 하나)")
    parser.add_argument(
        "--type",
        choices=["ip", "hash", "domain"],
        default="ip",
        help="--file 사용 시 IOC 유형 (기본: ip)",
    )
    parser.add_argument("--abuseipdb-key", metavar="KEY", help="AbuseIPDB API 키")
    parser.add_argument("--vt-key", metavar="KEY", help="VirusTotal API 키")
    parser.add_argument("--threshold", type=int, default=30, help="악성 판단 임계값 0-100 (기본: 30)")
    parser.add_argument("--json", action="store_true", help="JSON 형식으로 출력")
    parser.add_argument("--rate-limit", type=float, default=0.5, help="요청 간 대기 시간(초, 기본: 0.5)")
    return parser


def print_result(res: IOCResult, as_json: bool = False) -> None:
    if as_json:
        print(json.dumps(res.to_dict(), ensure_ascii=False, indent=2))
        return
    verdict = "악성" if res.is_malicious else "정상"
    color = "\033[91m" if res.is_malicious else "\033[92m"
    reset = "\033[0m"
    print(f"\n{'='*60}")
    print(f"IOC       : {res.indicator} ({res.indicator_type})")
    print(f"판정      : {color}{verdict}{reset}  (신뢰도: {res.confidence}%)")
    for src, data in res.sources.items():
        if data and "error" not in data:
            print(f"\n[{src}]")
            for k, v in data.items():
                print(f"  {k:<30}: {v}")


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    client = ThreatIntelClient(
        abuseipdb_key=args.abuseipdb_key,
        vt_key=args.vt_key,
    )

    results: list[IOCResult] = []

    if args.ip:
        results.append(client.check_ip(args.ip, malicious_threshold=args.threshold))
    elif args.hash:
        results.append(client.check_hash(args.hash))
    elif args.domain:
        results.append(client.check_domain(args.domain))
    elif args.file:
        try:
            with open(args.file, encoding="utf-8") as fh:
                indicators = [line.strip() for line in fh if line.strip()]
        except OSError as exc:
            parser.error(f"파일 읽기 실패: {exc}")
        results = client.bulk_check(indicators, ioc_type=args.type, rate_limit=args.rate_limit)
    else:
        parser.print_help()
        sys.exit(1)

    for res in results:
        print_result(res, as_json=args.json)

    malicious_count = sum(1 for r in results if r.is_malicious)
    if len(results) > 1:
        print(f"\n총 {len(results)}개 중 악성 {malicious_count}개")


if __name__ == "__main__":
    main()
```

---

## 8. SOC 도구 스택 (오픈소스)

```
SIEM/로그 분석:
  Elastic SIEM (ELK Stack + Security)
  Wazuh (오픈소스 SIEM + EDR)
  Graylog

네트워크 탐지:
  Zeek (네트워크 트래픽 분석)
  Suricata (IDS/IPS)
  NetworkMiner (패킷 분석)

위협 인텔리전스 플랫폼:
  MISP (Malware Information Sharing Platform)
  OpenCTI

인시던트 대응:
  TheHive (케이스 관리)
  Cortex (자동화 분석)
  Shuffle (SOAR 자동화)

포렌식:
  Velociraptor (원격 포렌식)
  GRR Rapid Response
  Timesketch (타임라인 분석)
```

---

## 9. 인시던트 대응 체크시트 — Linux

### 9-1. 사용자 계정 조사

침해 의심 시스템의 사용자 계정과 권한을 조사합니다. 알 수 없는 계정이나 관리자 그룹에 추가된 계정이 있는지 확인합니다.

```bash
# 모든 사용자 계정 목록 확인 (수상한 계정 탐지)
cat /etc/passwd

# 특정 사용자 상태 확인 (패스워드 상태)
passwd -S username

# UID 0 (root 권한) 계정 확인 — 비정상 root 계정 탐지
grep :0: /etc/passwd

# 소유자 없는 파일 탐지 — 공격자가 만든 임시 파일
find / -nouser -print

# 암호화된 패스워드 확인 (root 전용)
cat /etc/shadow

# 그룹 정보 확인
cat /etc/group

# sudo 권한 설정 확인
cat /etc/sudoers
```

### 9-2. 로그 조사

```bash
# 최근 로그인 기록 확인
lastlog

# SSH/telnet 인증 로그 확인 (수상한 로그인 탐지)
cd /var/log && tail auth.log

# 명령어 히스토리 확인
history | less
```

### 9-3. 시스템 리소스 / 프로세스

```bash
# 시스템 가동 시간 및 부하
uptime

# 메모리 사용량
free

# 상세 메모리 정보
cat /proc/meminfo

# 마운트 정보 (알 수 없는 마운트 확인)
cat /proc/mounts

# 실시간 프로세스 목록
top

# 전체 프로세스 상태 (악성 프로세스 탐지)
ps aux

# 특정 PID의 열린 파일 목록
lsof -p [PID]
```

### 9-4. 서비스 및 네트워크

```bash
# 실행 중인 서비스 전체 확인
service --status-all

# 스케줄 작업 확인 (악성 크론잡 탐지)
cat /etc/crontab

# DNS 설정 확인
more /etc/resolv.conf

# hosts 파일 확인 (DNS 리다이렉션 탐지)
more /etc/hosts

# 방화벽 규칙 확인
iptables -L -n

# 네트워크 인터페이스 확인
ifconfig -a

# 포트를 리슨 중인 프로세스 목록
lsof -i

# 모든 연결 포트 확인
netstat -nap

# ARP 캐시 확인 (ARP 스푸핑 탐지)
arp -a

# PATH 환경변수 확인 (PATH 하이재킹 탐지)
echo $PATH
```

### 9-5. 파일 조사


최근 변경된 파일을 탐색합니다. 악성코드는 종종 `/tmp`, `/var/tmp`, 홈 디렉토리에 실행 파일을 드롭합니다. `find`로 최근 24~48시간 내 생성·수정된 파일을 수집하여 악성 파일을 식별합니다.

```bash
# 홈 디렉토리에서 512KB 초과 파일 탐지
find /home/ -type f -size +512k -exec ls -lh {} \;

# 최근 2일 내 수정된 파일 탐지
find / -mtime -2 -ls
```

---

---

## 11. SOC 구축 핵심 원칙 (예산 절약형)

### SOC 4~5인 팀 역할 매트릭스
```
Tier 1 트리아지 전문가:
  기술: Linux/Mac/Windows 관리, Python/Java/C 프로그래밍, CISSP/GCIA/GCIH
  역할:
  - 최신 알림 심각도 검토 및 관련성/긴급성 판단
  - Tier 2 에스컬레이션 티켓 생성
  - 취약점 스캔 실행 및 보고서 검토
  - 보안 모니터링 도구(IDS/상관분석 규칙) 관리

Tier 2 인시던트 대응자:
  기술: Tier 1 + 자연적 호기심, 근본원인 추적 능력, 압박 상황에서 침착함
  역할:
  - Tier 1 티켓 검토, 위협 인텔(IOC/규칙) 활용
  - 영향받은 시스템 및 공격 범위 확인
  - 자산 데이터(설정, 실행 프로세스) 수집
  - 복구 방향 결정 및 지시

Tier 3 위협 헌터:
  기술: Tier 1+2 + 데이터 시각화/침투테스트 도구 활용
  역할:
  - 자산/취약점 데이터 검토
  - 스텔스 위협 식별 (최신 인텔 활용)
  - 운영 시스템 침투 테스트 (탄력성 검증)
  - 보안 모니터링 도구 최적화 권고

Tier 4 SOC 관리자:
  기술: 전 Tier + 강력한 리더십/커뮤니케이션 능력
  역할:
  - SOC 팀 감독, 채용/훈련/평가
  - 에스컬레이션 프로세스 검토, 인시던트 보고서 감독
  - CISO 대상 위기 커뮤니케이션 계획 수립 및 실행
  - 컴플라이언스 보고, SOC 성과 지표 측정
```

### SOC 핵심 프로세스 4단계
```
1. 이벤트 분류 및 트리아지
   목표: 노이즈에서 신호 찾기
   - 로그 데이터에서 IOC(파일 해시, IP, 도메인) 탐지
   - 가장 높은 심각도 이벤트부터 검토
   - 모든 활동 문서화 (메모, 티켓 등)

2. 우선순위화 및 분석
   - Cyber Kill Chain 단계별 분류
   - 공격자 관점에서 환경/인프라 분석
   - 초기 단계에서 탐지할수록 성공 가능성 높음

3. 복구 및 치료
   - 위협 격리, 악성 파일 제거, 취약점 패치
   - 영향받은 시스템 복원

4. 평가 및 감사
   - 정기 검토로 진행 상황 측정
   - SOC 성과 지표 기반 개선

Cyber Kill Chain 경보 유형 (심각도 순):
  정찰/무기화 → 낮음
  전달/익스플로잇 → 중간
  설치/C2 → 높음
  목표달성 (Action on Objectives) → 위험
```

### SOC 핵심 인프라 구성 (최소 구성)
```
필수 로그 소스 (모두 SIEM으로 전송):
  ✓ 방화벽 (Accept/Deny 로그)
  ✓ 도메인 컨트롤러 (Active Directory)
  ✓ DNS 서버
  ✓ 이메일 게이트웨이
  ✓ 웹 서버/프록시
  ✓ 파일 서버
  ✓ 데이터베이스 서버

핵심 도구:
  자산 발견: 네트워크 스캐닝 → 알 수 없는 장치 탐지
  취약점 평가: CVSS 기반 우선순위 취약점 관리
  침입 탐지: IDS/IPS (시그니처 + 행위 기반)
  행위 모니터링: 비정상 사용자/시스템 활동 탐지
  SIEM/보안 분석: 로그 상관분석, 대시보드, 알림

MSSP 활용 기준:
  - 팀이 탐지/격리/대응을 자신 있게 수행하기 어려운 경우
  - 보안 외 다른 우선순위에 자원이 집중되는 경우
```

---

## 12. Zero Trust 아키텍처 (DoD 기준)

### Zero Trust 핵심 원칙
```
"Never Trust, Always Verify" (절대 신뢰하지 말고 항상 검증)

전통 경계 보안의 한계:
  - 내부 네트워크를 신뢰 → 침해 후 자유 이동
  - 물리적/네트워크 위치 기반 신뢰 → VPN 우회 등으로 무력화

Zero Trust 전환:
  - 사용자, 자산, 리소스 중심 보안 (네트워크 경계 X)
  - 다중 속성 기반 신뢰 레벨 평가
  - 최소 권한 접근 (데이터 필요 시에만, 필요한 양만)
```

### DoD 7대 Zero Trust 핵심 기둥 (Pillars)
```
1. Users (사용자)
   - MFA 필수, 신원 지속 검증
   - 권한 있는 계정 특별 관리

2. Devices (장치)
   - 모든 엔드포인트 건강 상태 지속 모니터링
   - 비규격 장치 접근 차단

3. Networks (네트워크)
   - 마이크로세그멘테이션으로 내부 이동 차단
   - 암호화된 통신 강제

4. Applications & Workloads (앱/워크로드)
   - 앱 수준 접근 제어
   - 컨테이너/클라우드 워크로드 보호

5. Data (데이터)
   - 데이터 분류 및 레이블링
   - DLP(데이터 유출 방지) 정책

6. Visibility & Analytics (가시성/분석)
   - 지속적인 모니터링 및 로그 수집
   - SIEM + 행위 분석 (UEBA)

7. Automation & Orchestration (자동화)
   - 탐지 → 대응 자동화 (SOAR)
   - 정책 적용 자동화
```

### Zero Trust 구현 성숙도 단계
```
Target Level (기본):
  - MFA 전사 적용
  - 마이크로세그멘테이션 시작
  - 중앙 집중식 로그 수집
  - 데이터 분류 정책 수립

Advanced Level (고급):
  - 연속 다중 인증
  - AI/ML 기반 행위 분석
  - 자동화된 위협 대응
  - 실시간 정책 조정

핵심 전환 과제:
  - "신뢰하되 검증" → "검증하고 검증" 마인드셋 변화
  - 레거시 시스템의 Zero Trust 적용 복잡성
  - 사용자 경험과 보안 균형 유지
```

---

## 13. 인시던트 대응 체크시트 — Windows

### 10-1. 사용자 계정 조사


침해 의심 시스템의 사용자 계정을 조사합니다. 숨겨진 관리자 계정, 최근 생성된 계정, 패스워드 없는 계정 등을 확인하여 공격자가 만든 백도어 계정을 탐지합니다.

```cmd
REM GUI: 로컬 사용자 관리
lusrmgr.msc

REM 로컬 사용자 목록
net user

REM 관리자 그룹 멤버 확인
net localgroup administrators
```

PowerShell Get 커맨드렛으로 시스템 정보를 조회합니다. 프로세스, 서비스, 레지스트리 항목 등 시스템 상태를 확인하는 데 사용합니다.

```powershell
# PowerShell: 로컬 사용자 목록 (활성화 여부 포함)
Get-LocalUser
```

### 10-2. 프로세스 조사


Windows 프로세스 조사 명령어입니다. `tasklist /svc`로 각 프로세스가 실행하는 서비스를, `wmic process get`으로 부모 프로세스 ID 포함 상세 정보를 수집합니다.

```cmd
REM 프로세스 목록 (PID, 메모리 포함)
tasklist

REM 프로세스별 서비스 연결 확인
tasklist /svc
```

PowerShell Get 커맨드렛으로 시스템 정보를 조회합니다. 프로세스, 서비스, 레지스트리 항목 등 시스템 상태를 확인하는 데 사용합니다.

```powershell
# PowerShell: 프로세스 목록
Get-Process

# WMIC: 전체 프로세스 정보
wmic process list full

# WMIC: 부모 프로세스 관계 파악
wmic process get name,parentprocessid,processid

# WMIC: 특정 PID의 실행 커맨드라인 확인
wmic process where 'ProcessID=1234' get Commandline
```

### 10-3. 서비스 및 자동 실행


서비스와 자동 실행 항목을 조사합니다. `sc query`로 실행 중인 서비스를, `reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`으로 레지스트리 자동 실행 항목을 확인합니다.

```cmd
REM 실행 중인 서비스 목록
net start

REM 서비스 상세 정보
sc query | more

REM 스케줄 작업 목록
schtasks
```

PowerShell Get 커맨드렛으로 시스템 정보를 조회합니다. 프로세스, 서비스, 레지스트리 항목 등 시스템 상태를 확인하는 데 사용합니다.

```powershell
# 시작 프로그램 목록 (WMIC)
wmic startup get caption,command

# 시작 프로그램 상세 (PowerShell)
Get-CimInstance Win32_StartupCommand | Select-Object Name, command, Location, User | Format-List
```

### 10-4. 레지스트리 Run 키 확인

```powershell
# HKLM Run 키 (시스템 전체 자동 실행)
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

# HKCU Run 키 (현재 사용자 자동 실행)
reg query HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
```

### 10-5. 네트워크 조사


활성 네트워크 연결을 분석합니다. 알 수 없는 외부 IP 연결, 비표준 포트 사용, ESTABLISHED 상태에서 비정상적으로 많은 연결을 확인하여 C2 통신 징후를 탐지합니다.

```cmd
REM 활성 TCP/UDP 연결 (PID 포함)
netstat -ano

REM 파일 공유 확인
net view \\127.0.0.1

REM 세션 연결 확인 (외부 시스템과 세션)
net use
net session
```

PowerShell Get 커맨드렛으로 시스템 정보를 조회합니다. 프로세스, 서비스, 레지스트리 항목 등 시스템 상태를 확인하는 데 사용합니다.

```powershell
# TCP 연결 상태 확인
Get-NetTCPConnection -LocalAddress 192.168.x.x | Sort-Object LocalPort

# 파일 공유 목록
Get-SMBShare
```

### 10-6. 방화벽 및 로그

```cmd
REM 방화벽 설정 확인
netsh firewall show config
netsh advfirewall show currentprofile

REM 보안 이벤트 로그 내보내기
wevtutil qe security
```

PowerShell Get 커맨드렛으로 시스템 정보를 조회합니다. 프로세스, 서비스, 레지스트리 항목 등 시스템 상태를 확인하는 데 사용합니다.

```powershell
# 이벤트 로그 목록
Get-EventLog -List

# 파일 최근 수정 탐지 (최근 10일 내 .exe 파일)
forfiles /D -10 /S /M *.exe /C "cmd /c echo @path"
forfiles /D -10 /S /M *.exe /C "cmd /c echo @ext @fname @fdate"
forfiles /p c: /S /D -10
```

---

## 14. 허니팟 (Honeypot) 운영

### 허니팟 유형
```
상호작용 수준별 분류:

저상호작용 (Low-Interaction):
  - 제한된 서비스/포트 시뮬레이션
  - UDP, TCP, ICMP 포트 모니터링
  - 가짜 데이터베이스/파일로 공격자 유인
  - 도구: Honeytrap, Specter, KFsensor

중상호작용 (Medium-Interaction):
  - 실제 OS와 애플리케이션 모방
  - 공격자를 더 오래 묶어두어 대응 시간 확보
  - 도구: Cowrie, HoneyPy

고상호작용 (High-Interaction):
  - 실제 취약 시스템 운영 (진짜 OS + 앱)
  - 가장 많은 정보 수집 가능, 관리 복잡
  - 도구: Honeynet

Pure Honeypot:
  - 실제 프로덕션 환경을 모방
  - 공격자가 가장 많은 시간을 투자하게 유도

Production Honeypot:
  - 실제 네트워크 내 배치 → 내부 공격자 탐지에 유용

Research Honeypot:
  - 정부/군사 기관의 공격 행위 연구 목적
```

### 목적별 허니팟 유형
```
멀웨어 허니팟:   악성코드 행위 패턴 수집
이메일 허니팟:   스팸/피싱 발신자 정보 수집
DB 허니팟:       SQL 인젝션 패턴 수집 (가짜 민감 데이터)
스파이더 허니팟: 웹 크롤러/스크레이퍼 탐지
스팸 허니팟:     스패머 행위 분석
허니넷:          가상/격리 환경의 허니팟 네트워크
```

### 허니팟이 수집하는 공격자 정보
```
- 공격자 IP 주소
- 입력한 키스트로크 (패스워드 추측, 명령어)
- 사용한 사용자명과 권한 수준
- 접근/삭제/수정한 데이터
- 사용한 도구 및 익스플로잇 방법
```

### 허니팟 환경별 구축 (Windows)
```bash
# Windows: HoneyBOT 설치 후 운영
# nmap 스캔 시 수백 개의 가짜 열린 포트 표시
# FTP, SSH 등 접속 시도를 로그로 기록
# CSV 형식 로그 저장 가능
# 이메일 알림 설정 가능
```

### 허니팟 환경별 구축 (Linux)
```python
#!/usr/bin/env python3
"""
Cowrie SSH 허니팟 로그 분석기 CLI
사용: python3 honeypot_analyzer.py --log /var/log/cowrie/cowrie.json [--top 20] [--json]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Iterator


# ------------------------------------------------------------------ #
#  로그 파서
# ------------------------------------------------------------------ #
def iter_cowrie_json(log_path: Path) -> Iterator[dict]:
    """Cowrie JSON 로그를 한 줄씩 파싱"""
    with log_path.open(encoding="utf-8", errors="replace") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as exc:
                print(f"[경고] 줄 {lineno} 파싱 실패: {exc}", file=sys.stderr)


def parse_cowrie_text(log_path: Path) -> Iterator[dict]:
    """Cowrie 텍스트 로그 파싱 (fallback)"""
    pattern = re.compile(
        r"(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[^\s]*)\s+"
        r"\[(?P<component>[^\]]+)\]\s+(?P<message>.+)"
    )
    with log_path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            m = pattern.match(line.strip())
            if m:
                yield {
                    "timestamp": m.group("ts"),
                    "eventid": "",
                    "src_ip": "",
                    "message": m.group("message"),
                }


# ------------------------------------------------------------------ #
#  통계 집계
# ------------------------------------------------------------------ #
def analyze(events: list[dict], top_n: int = 10) -> dict:
    stats: dict = {
        "total_events": len(events),
        "unique_src_ips": set(),
        "event_counts": Counter(),
        "top_attackers": Counter(),
        "commands_run": [],
        "credentials_tried": [],
        "sessions": defaultdict(list),
        "timeline": defaultdict(int),
    }

    for ev in events:
        eid = ev.get("eventid", "")
        src = ev.get("src_ip", "")
        session = ev.get("session", "")
        ts = ev.get("timestamp", "")[:10]  # YYYY-MM-DD

        stats["event_counts"][eid] += 1
        if src:
            stats["unique_src_ips"].add(src)
            stats["top_attackers"][src] += 1
        if ts:
            stats["timeline"][ts] += 1
        if session:
            stats["sessions"][session].append(eid)

        # 실행된 명령어 수집
        if eid == "cowrie.command.input":
            stats["commands_run"].append(
                {"time": ts, "src": src, "cmd": ev.get("input", "")}
            )

        # 자격증명 시도 수집
        if eid in ("cowrie.login.failed", "cowrie.login.success"):
            stats["credentials_tried"].append(
                {
                    "time": ts,
                    "src": src,
                    "username": ev.get("username", ""),
                    "password": ev.get("password", ""),
                    "success": eid == "cowrie.login.success",
                }
            )

    # set → list 직렬화 가능하게
    stats["unique_src_ips"] = list(stats["unique_src_ips"])
    stats["top_attackers_list"] = stats["top_attackers"].most_common(top_n)
    stats["top_commands"] = Counter(
        c["cmd"] for c in stats["commands_run"]
    ).most_common(top_n)
    stats["top_usernames"] = Counter(
        c["username"] for c in stats["credentials_tried"]
    ).most_common(top_n)
    stats["top_passwords"] = Counter(
        c["password"] for c in stats["credentials_tried"]
    ).most_common(top_n)

    return stats


# ------------------------------------------------------------------ #
#  출력
# ------------------------------------------------------------------ #
def print_report(stats: dict, as_json: bool = False) -> None:
    if as_json:
        serializable = {
            k: (list(v) if isinstance(v, set) else dict(v) if isinstance(v, Counter) else v)
            for k, v in stats.items()
            if k != "sessions"
        }
        print(json.dumps(serializable, ensure_ascii=False, indent=2))
        return

    print(f"\n{'='*60}")
    print(f"총 이벤트    : {stats['total_events']:,}")
    print(f"고유 공격자  : {len(stats['unique_src_ips']):,}")
    print(f"실행 명령어  : {len(stats['commands_run']):,}")
    print(f"자격증명 시도: {len(stats['credentials_tried']):,}")

    print("\n[상위 공격자 IP]")
    for ip, cnt in stats["top_attackers_list"]:
        print(f"  {ip:<20} {cnt:>6}회")

    print("\n[가장 많이 실행된 명령어]")
    for cmd, cnt in stats["top_commands"]:
        short = cmd[:60] + "..." if len(cmd) > 60 else cmd
        print(f"  {cnt:>5}회  {short}")

    print("\n[가장 많이 시도된 비밀번호]")
    for pw, cnt in stats["top_passwords"]:
        print(f"  {cnt:>5}회  {pw}")

    print("\n[일별 공격 추이]")
    for day in sorted(stats["timeline"])[-14:]:
        bar = "#" * min(stats["timeline"][day] // 10, 50)
        print(f"  {day}  {bar} {stats['timeline'][day]}")


# ------------------------------------------------------------------ #
#  CLI
# ------------------------------------------------------------------ #
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Cowrie SSH 허니팟 로그 분석기",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="예시:\n"
               "  python3 honeypot_analyzer.py --log cowrie.json\n"
               "  python3 honeypot_analyzer.py --log cowrie.json --top 20 --json",
    )
    parser.add_argument(
        "--log",
        required=True,
        metavar="FILE",
        help="Cowrie JSON 로그 파일 경로",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=10,
        metavar="N",
        help="상위 N개 표시 (기본: 10)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="JSON 형식으로 출력",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    log_path = Path(args.log)
    if not log_path.exists():
        parser.error(f"파일을 찾을 수 없음: {log_path}")

    # JSON 로그 우선, 실패 시 텍스트 파싱 시도
    if log_path.suffix in (".json", ".jsonl"):
        events = list(iter_cowrie_json(log_path))
    else:
        events = list(parse_cowrie_text(log_path))

    if not events:
        print("분석할 이벤트가 없습니다.", file=sys.stderr)
        sys.exit(1)

    stats = analyze(events, top_n=args.top)
    print_report(stats, as_json=args.json)


if __name__ == "__main__":
    main()
```

---

## 15. UBA/UEBA (사용자 행위 분석)

### UBA가 전통 보안과 다른 점
```
전통 감사 방법의 한계:
  - 임계값 기반 알림 → 느린 공격 및 내부자 탐지 실패
  - 많은 오탐(False Positive) → 실제 위협 놓침
  - 2017년 침해사고의 68%가 1개월 이상 탐지 미흡

UBA(User Behavior Analytics) 특징:
  - ML 기반으로 각 사용자의 정상 행위 기준선(Baseline) 수립
  - 기준선 이탈 시 자동 이상 탐지
  - 임계값 없이도 느린 공격 탐지 가능
```

### UBA 탐지 영역
```
이상 행위 탐지:
  - 특정 이벤트 비정상적 볼륨 (로그인 급증 등)
  - 비정상 시간대 로그인 또는 자원 접근
  - 평소 사용하지 않는 시스템 로그인
  - 처음으로 특정 자원에 접근 시도
  - 비정상적인 파일 활동 (대량 수정/복사/삭제)

권한 남용 탐지:
  - 권한 있는 사용자의 민감 파일 대량 접근
  - 관리자 계정의 비정상 행위 탐지
  - 과도한 권한으로 민감 데이터 조회

내부자 위협:
  - 내부 침해사고의 약 28% 비중
  - 퇴직 예정자 또는 불만 직원의 데이터 유출 시도
  - 권한 없는 자원 반복 접근 시도
```

### UBA 위험 평가 보고서 활용
```
리스크 평가 지표:
  - 가장 많은 자산에 연결된 계정
  - 과활성(Hyperactive) 계정 식별
  - 고위험 계정의 활동 카운트 (파일 활동량 등)

SIEM에서의 UBA 통합:
  - 정상 로그인 패턴 학습 후 이탈 감지
  - Splunk UBA, Elastic ML, Microsoft Sentinel 등
  - 알림을 관리자 이메일/SMS로 즉시 전달
```

---

<a name="english"></a>

# SOC Core Concepts and Blue Team Fundamentals

## SOC (Security Operations Center) Overview

```
SOC Organizational Chart
─────────────────────────────────────────────
                  CISO
                   │
              SOC Manager
                   │
     ┌─────────────┼─────────────┐
     │             │             │
  Tier 1         Tier 2        Tier 3
 (Alert)      (Analysis)   (Threat Hunt)
 Monitoring  Investigate/  APT Tracking
              Respond
─────────────────────────────────────────────

Tier 1: Alert triage, initial response, escalation
Tier 2: In-depth analysis, incident response, forensics
Tier 3: Threat hunting, zero-days, malware reversing
```

---

## 1. Core SOC Processes

### Incident Response Cycle (PICERL)

```
Preparation → Identification → Containment
     │                               │
 Recovery ← Eradication ← Lessons Learned
```

| Phase | Actions |
|-------|---------|
| **Preparation** | Tool readiness, playbook creation, training |
| **Identification** | Anomaly detection, alert classification, initial investigation |
| **Containment** | Isolation, network blocking, account lockout |
| **Eradication** | Malware removal, vulnerability patching |
| **Recovery** | System restoration, service resumption, enhanced monitoring |
| **Lessons Learned** | Post-mortem analysis, documentation, improvements |

### SOC Metrics (KPIs)

```
MTTD (Mean Time to Detect): Average time to detect a threat
MTTR (Mean Time to Respond): Average time to respond
MTTC (Mean Time to Contain): Average time to contain

Industry Averages:
  MTTD: 197 days (IBM Cost of Data Breach 2023)
  MTTR: 70 days
  Target: MTTD < 1 hour, MTTR < 4 hours
```

---

## 2. SIEM Architecture

### Data Collection Flow

```
Endpoints/Servers   Network Devices    Cloud/Apps
       │                  │                │
  Syslog/WEF          SNMP/NetFlow      API/Webhook
       └─────────────────┬───────────────┘
                         │
                     Log Shipper
                 (Fluentd/Logstash/
                  NXLog/Winlogbeat)
                         │
                     [SIEM Engine]
                 (Splunk/QRadar/ELK)
                         │
             ┌───────────┼───────────┐
         Parsing/     Correlation  Alerts/
        Normalization  Analysis   Dashboard
```

### Key Log Sources to Collect

```
Priority 1 (Required):
  ✓ Windows Security Event Log (IDs 4624, 4625, 4688...)
  ✓ Active Directory (logins, policy changes, group changes)
  ✓ Firewall/IDS/IPS logs
  ✓ DNS query logs
  ✓ DHCP logs
  ✓ Proxy/web filter logs
  ✓ EDR (Endpoint Detection & Response) alerts

Priority 2 (Recommended):
  ✓ VPN access logs
  ✓ Email gateway logs
  ✓ Cloud services (AWS CloudTrail, Azure Activity)
  ✓ Web servers (Apache/Nginx/IIS)
  ✓ Database audit logs

Priority 3 (Advanced):
  ✓ NetFlow/IPFIX network flows
  ✓ Certificate transparency logs
  ✓ Honeypot alerts
```

---

## 3. Key Windows Event IDs

### Authentication-Related

```
4624  - Successful logon
  Logon Type 2  = Interactive logon (console)
  Logon Type 3  = Network logon (SMB, file share)
  Logon Type 4  = Batch job
  Logon Type 5  = Service logon
  Logon Type 7  = Workstation unlock
  Logon Type 8  = Network cleartext credentials
  Logon Type 10 = Remote interactive (RDP)
  Logon Type 11 = Cached credentials

4625  - Failed logon
  Sub Status:
  0xC000006D = Bad username or password
  0xC000006A = Bad password
  0xC0000064 = Non-existent user
  0xC000006F = Login outside allowed hours
  0xC0000070 = Unauthorized workstation
  0xC0000234 = Account locked out

4648  - Logon with explicit credentials (RunAs)
4768  - Kerberos TGT request
4769  - Kerberos service ticket request
4771  - Kerberos pre-authentication failure
4776  - NTLM authentication attempt
```

### Process-Related

```
4688  - New process created (CommandLine logging required)
4689  - Process terminated
4698  - Scheduled task created
4702  - Scheduled task modified
7045  - New service installed
4697  - New service installed (Security log)
```

### Account/Privilege-Related

```
4720  - User account created
4722  - User account enabled
4725  - User account disabled
4726  - User account deleted
4728  - Member added to security group
4732  - Member added to local group
4756  - Member added to universal group
4738  - User account changed
4740  - User account locked out
4767  - User account unlocked

1102  - Audit log cleared (suspicious behavior!)
4719  - Audit policy changed
```

### Network/Share-Related

```
5140  - Network share accessed
5145  - Shared file access checked
5156  - Windows Firewall connection allowed
5157  - Windows Firewall connection blocked
4776  - NTLM credential validation
```

---

## 4. Key Attack Detection Patterns

### Brute Force Detection

```
Pattern: Multiple 4625 events from the same IP within a short time

Example Query (Splunk):
index=security EventCode=4625
| stats count as FailedLogins, values(TargetUserName) as Users
  by IpAddress, host
| where FailedLogins > 10
| sort -FailedLogins

Alert Thresholds:
  10+ failures from the same IP within 5 minutes → Alert
  30+ failures from the same IP within 1 minute → Immediate block
```

### Password Spray Detection

```
Pattern: Few login attempts across many accounts
         (opposite direction from brute force)

Query:
index=security EventCode=4625
| bucket _time span=5m
| stats dc(TargetUserName) as UniqueUsers, count as Attempts
  by IpAddress, _time
| where UniqueUsers > 20 AND Attempts < 50
→ Many accounts, few attempts = spray attack
```

### Pass-the-Hash Detection

```
Pattern: Logon Type 3 + NTLM authentication + admin share access

index=security EventCode=4624 LogonType=3
| search AuthenticationPackageName="NTLM"
| search TargetUserName="*$" OR IpPort IN (445)
| table _time, IpAddress, TargetUserName, WorkstationName

Additional signals:
  - Access outside normal hours
  - Admin account moving to multiple hosts
  - Defense: Protected Users group + Credential Guard
```

### Kerberoasting Detection

```
Pattern: Multiple 4769 events, RC4 encryption (0x17)

index=security EventCode=4769
| where TicketEncryptionType="0x17"  
| stats count by SubjectUserName, ServiceName, IpAddress
| where count > 5
| sort -count

→ RC4 ticket requests for multiple SPNs in short time = Kerberoasting
```

### Golden Ticket Detection

```
Pattern: Disguised as tickets issued by the krbtgt account
         Abnormally long ticket lifetime (exceeds default 10 hours)

index=security EventCode=4769
| eval ticket_lifetime_hours = (TicketEndTime - TicketStartTime) / 3600
| where ticket_lifetime_hours > 10
| table _time, AccountName, ServiceName, ticket_lifetime_hours

Or:
EventCode=4768 AND TicketOptions=0x40810010 AND EncryptionType=0x17
```

### Lateral Movement Detection

```
Pattern: Single host connecting to many internal hosts

# PsExec detection
EventCode=7045 AND ImagePath CONTAINS "PSEXESVC"

# WMI remote execution
EventCode=4688 AND Process_Command_Line CONTAINS "wmic"
                AND Process_Command_Line CONTAINS "/node:"

# PowerShell Remoting
EventCode=4688 AND Process_Command_Line CONTAINS "Enter-PSSession"
EventCode=4688 AND Process_Command_Line CONTAINS "Invoke-Command"

# Abnormal network connections (port-based)
index=network dest_port IN (445, 135, 139, 5985, 5986)
| stats dc(dest) as UniqueTargets by src
| where UniqueTargets > 10
```

---

## 5. EDR Alert Analysis

### EDR Tool Comparison

| Tool | Strengths | Notes |
|------|-----------|-------|
| **CrowdStrike Falcon** | Cloud-based, intelligence | #1 market share |
| **Microsoft Defender for Endpoint** | Windows integration | Included in M365 E5 |
| **SentinelOne** | AI-based autonomous response | Rollback capability |
| **Carbon Black** | Process tree visualization | Acquired by VMware |
| **Elastic Security** | Open source + ELK | Cost-effective |

### EDR Alert Classification Guide

```
True Positive (TP): Actual threat → Immediate response
False Positive (FP): Normal behavior → Add to whitelist
True Negative (TN): Normal pass → Benign
False Negative (FN): Missed threat → Improve detection rules

FP Handling Process:
1. Analyze alert context (time, user, behavior)
2. Confirm with the relevant user/team
3. Add exception if confirmed as normal business activity
4. Document the reason for the exception
5. Periodically review the exception list
```

---

## 6. Incident Response Playbooks

### Malware Infection Response

```
1. Detection
   - Receive EDR alert
   - Identify affected hosts
   
2. Initial Triage (within 15 minutes)
   - Decide whether to isolate the host
   - Assess business impact
   - Decide whether to escalate

3. Containment (immediately after decision)
   - Network isolation (EDR/NAC)
   - Password change (affected accounts)
   - Temporarily block related systems

4. Investigation (1-4 hours)
   - Analyze process tree
   - Analyze network connections
   - Check filesystem changes
   - Trace infection vector (email? web? USB?)

5. Eradication (4-8 hours)
   - Delete malicious files
   - Clean registry
   - Remove persistence mechanisms
   - Patch vulnerabilities

6. Recovery
   - Restore from clean image OR clean and validate
   - Resume services
   - Intensive monitoring for 72 hours

7. Post-Incident Analysis
   - Reconstruct timeline
   - Extract and share IOCs
   - Identify detection gaps
   - Recommend preventive measures
```

### Phishing Email Response

```
1. Report Intake
   - Obtain complete email headers
   - Never click attachments/links

2. Analysis
   - Check sender domain/IP
   - Analyze links (VirusTotal, URLScan)
   - Analyze attachments (Sandbox)
   - Identify recipients of the same email (SIEM)

3. Containment
   - Block the same email at the email gateway
   - Identify users who already clicked
   - Block links/attachments (proxy/firewall)

4. User Notification
   - Immediately notify affected users
   - Direct password change
   - Verify MFA

5. Post-Incident Analysis
   - Classify phishing type (credential harvesting? malware delivery?)
   - Strengthen SPF/DKIM/DMARC policies
   - Update security awareness training
```

---

## 7. Threat Intelligence Utilization

### IOC (Indicator of Compromise) Types

```
Network-Based:
  IP address: 192.168.1.100
  Domain: malware.evil.com
  URL: http://evil.com/payload.exe
  SSL certificate hash
  JA3/JA3S fingerprint

Host-Based:
  File hashes (MD5, SHA1, SHA256)
  File path: C:\Users\Public\svchot.exe
  Registry keys
  Mutex names
  Pipe names

Behavior-Based (TTPs):
  MITRE ATT&CK technique IDs
  PowerShell obfuscation patterns
  Network communication patterns
```

### MITRE ATT&CK Framework Usage

```
Tactics → Techniques → Procedures

Example: Cobalt Strike detection
  Tactic: Command and Control (TA0011)
  Technique: Application Layer Protocol (T1071)
  Procedure: C2 beacon over HTTP/S

Using MITRE mapping to:
1. Standardize attacker behavior
2. Identify detection gaps
3. Measure coverage

Tool: ATT&CK Navigator
  https://mitre-attack.github.io/attack-navigator/
```

### Threat Intelligence Feed Integration

```python
#!/usr/bin/env python3
"""
Multi-source threat intelligence lookup CLI
Usage: python3 threat_intel.py --ip 1.2.3.4 --abuseipdb-key KEY --vt-key KEY
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import dataclass, field
from typing import Optional

import requests


@dataclass
class IOCResult:
    indicator: str
    indicator_type: str
    sources: dict = field(default_factory=dict)
    is_malicious: bool = False
    confidence: int = 0

    def to_dict(self) -> dict:
        return {
            "indicator": self.indicator,
            "type": self.indicator_type,
            "is_malicious": self.is_malicious,
            "confidence": self.confidence,
            "sources": self.sources,
        }


class ThreatIntelClient:
    """AbuseIPDB + VirusTotal multi-source threat intelligence client"""

    ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
    VT_IP_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    VT_HASH_URL = "https://www.virustotal.com/api/v3/files/{hash}"
    VT_DOMAIN_URL = "https://www.virustotal.com/api/v3/domains/{domain}"

    def __init__(
        self,
        abuseipdb_key: Optional[str] = None,
        vt_key: Optional[str] = None,
        timeout: int = 10,
    ) -> None:
        self.abuseipdb_key = abuseipdb_key
        self.vt_key = vt_key
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers["User-Agent"] = "ThreatIntelCLI/1.0"

    # ------------------------------------------------------------------ #
    #  AbuseIPDB
    # ------------------------------------------------------------------ #
    def _query_abuseipdb(self, ip: str) -> dict:
        if not self.abuseipdb_key:
            return {}
        try:
            resp = self.session.get(
                self.ABUSEIPDB_URL,
                params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
                headers={"Key": self.abuseipdb_key, "Accept": "application/json"},
                timeout=self.timeout,
            )
            resp.raise_for_status()
            data = resp.json().get("data", {})
            return {
                "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                "country": data.get("countryCode", ""),
                "total_reports": data.get("totalReports", 0),
                "last_reported": data.get("lastReportedAt", ""),
                "isp": data.get("isp", ""),
                "domain": data.get("domain", ""),
                "is_tor": data.get("isTor", False),
            }
        except requests.RequestException as exc:
            return {"error": str(exc)}

    # ------------------------------------------------------------------ #
    #  VirusTotal
    # ------------------------------------------------------------------ #
    def _query_vt(self, url: str) -> dict:
        if not self.vt_key:
            return {}
        try:
            resp = self.session.get(
                url,
                headers={"x-apikey": self.vt_key},
                timeout=self.timeout,
            )
            resp.raise_for_status()
            attrs = resp.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "reputation": attrs.get("reputation", 0),
                "tags": attrs.get("tags", []),
            }
        except requests.RequestException as exc:
            return {"error": str(exc)}

    # ------------------------------------------------------------------ #
    #  Public lookup methods
    # ------------------------------------------------------------------ #
    def check_ip(self, ip: str, malicious_threshold: int = 30) -> IOCResult:
        result = IOCResult(indicator=ip, indicator_type="ip")
        abuse = self._query_abuseipdb(ip)
        vt = self._query_vt(self.VT_IP_URL.format(ip=ip))
        result.sources = {"abuseipdb": abuse, "virustotal": vt}

        score = abuse.get("abuse_confidence_score", 0)
        vt_malicious = vt.get("malicious", 0)
        result.confidence = max(score, min(vt_malicious * 10, 100))
        result.is_malicious = score >= malicious_threshold or vt_malicious >= 3
        return result

    def check_hash(self, file_hash: str) -> IOCResult:
        result = IOCResult(indicator=file_hash, indicator_type="hash")
        vt = self._query_vt(self.VT_HASH_URL.format(hash=file_hash))
        result.sources = {"virustotal": vt}
        vt_malicious = vt.get("malicious", 0)
        result.confidence = min(vt_malicious * 10, 100)
        result.is_malicious = vt_malicious >= 3
        return result

    def check_domain(self, domain: str) -> IOCResult:
        result = IOCResult(indicator=domain, indicator_type="domain")
        vt = self._query_vt(self.VT_DOMAIN_URL.format(domain=domain))
        result.sources = {"virustotal": vt}
        vt_malicious = vt.get("malicious", 0)
        result.confidence = min(vt_malicious * 10, 100)
        result.is_malicious = vt_malicious >= 3
        return result

    def bulk_check(
        self, indicators: list[str], ioc_type: str = "ip", rate_limit: float = 0.5
    ) -> list[IOCResult]:
        """Bulk lookup of multiple IOCs while respecting rate limits"""
        results: list[IOCResult] = []
        dispatch = {"ip": self.check_ip, "hash": self.check_hash, "domain": self.check_domain}
        checker = dispatch.get(ioc_type)
        if checker is None:
            raise ValueError(f"Unsupported type: {ioc_type}. Valid values: {list(dispatch)}")

        for idx, indicator in enumerate(indicators, 1):
            print(f"[{idx}/{len(indicators)}] Looking up {indicator}...", file=sys.stderr)
            res = checker(indicator)
            results.append(res)
            if idx < len(indicators):
                time.sleep(rate_limit)
        return results


# ------------------------------------------------------------------ #
#  CLI
# ------------------------------------------------------------------ #
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Multi-source threat intelligence IOC lookup tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
               "  python3 threat_intel.py --ip 8.8.8.8\n"
               "  python3 threat_intel.py --hash d41d8cd98f00b204e9800998ecf8427e\n"
               "  python3 threat_intel.py --domain evil.example.com\n"
               "  python3 threat_intel.py --file iocs.txt --type ip --json",
    )
    parser.add_argument("--ip", metavar="IP", help="Single IP address lookup")
    parser.add_argument("--hash", metavar="HASH", help="File hash lookup (MD5/SHA256)")
    parser.add_argument("--domain", metavar="DOMAIN", help="Domain lookup")
    parser.add_argument("--file", metavar="FILE", help="IOC list file (one per line)")
    parser.add_argument(
        "--type",
        choices=["ip", "hash", "domain"],
        default="ip",
        help="IOC type when using --file (default: ip)",
    )
    parser.add_argument("--abuseipdb-key", metavar="KEY", help="AbuseIPDB API key")
    parser.add_argument("--vt-key", metavar="KEY", help="VirusTotal API key")
    parser.add_argument("--threshold", type=int, default=30, help="Malicious verdict threshold 0-100 (default: 30)")
    parser.add_argument("--json", action="store_true", help="Output in JSON format")
    parser.add_argument("--rate-limit", type=float, default=0.5, help="Delay between requests in seconds (default: 0.5)")
    return parser


def print_result(res: IOCResult, as_json: bool = False) -> None:
    if as_json:
        print(json.dumps(res.to_dict(), ensure_ascii=False, indent=2))
        return
    verdict = "MALICIOUS" if res.is_malicious else "CLEAN"
    color = "\033[91m" if res.is_malicious else "\033[92m"
    reset = "\033[0m"
    print(f"\n{'='*60}")
    print(f"IOC       : {res.indicator} ({res.indicator_type})")
    print(f"Verdict   : {color}{verdict}{reset}  (Confidence: {res.confidence}%)")
    for src, data in res.sources.items():
        if data and "error" not in data:
            print(f"\n[{src}]")
            for k, v in data.items():
                print(f"  {k:<30}: {v}")


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    client = ThreatIntelClient(
        abuseipdb_key=args.abuseipdb_key,
        vt_key=args.vt_key,
    )

    results: list[IOCResult] = []

    if args.ip:
        results.append(client.check_ip(args.ip, malicious_threshold=args.threshold))
    elif args.hash:
        results.append(client.check_hash(args.hash))
    elif args.domain:
        results.append(client.check_domain(args.domain))
    elif args.file:
        try:
            with open(args.file, encoding="utf-8") as fh:
                indicators = [line.strip() for line in fh if line.strip()]
        except OSError as exc:
            parser.error(f"Failed to read file: {exc}")
        results = client.bulk_check(indicators, ioc_type=args.type, rate_limit=args.rate_limit)
    else:
        parser.print_help()
        sys.exit(1)

    for res in results:
        print_result(res, as_json=args.json)

    malicious_count = sum(1 for r in results if r.is_malicious)
    if len(results) > 1:
        print(f"\nTotal: {malicious_count} malicious out of {len(results)}")


if __name__ == "__main__":
    main()
```

---

## 8. SOC Tool Stack (Open Source)

```
SIEM/Log Analysis:
  Elastic SIEM (ELK Stack + Security)
  Wazuh (Open Source SIEM + EDR)
  Graylog

Network Detection:
  Zeek (Network traffic analysis)
  Suricata (IDS/IPS)
  NetworkMiner (Packet analysis)

Threat Intelligence Platforms:
  MISP (Malware Information Sharing Platform)
  OpenCTI

Incident Response:
  TheHive (Case management)
  Cortex (Automated analysis)
  Shuffle (SOAR automation)

Forensics:
  Velociraptor (Remote forensics)
  GRR Rapid Response
  Timesketch (Timeline analysis)
```

---

## 9. Incident Response Checklist — Linux

### 9-1. User Account Investigation

Investigate user accounts and privileges on a suspected compromised system. Check for unknown accounts or accounts added to administrator groups.

```bash
# List all user accounts (detect suspicious accounts)
cat /etc/passwd

# Check specific user status (password status)
passwd -S username

# Check UID 0 (root-level) accounts — detect unauthorized root accounts
grep :0: /etc/passwd

# Detect files with no owner — temporary files created by attackers
find / -nouser -print

# Check encrypted passwords (root only)
cat /etc/shadow

# Check group information
cat /etc/group

# Check sudo privilege configuration
cat /etc/sudoers
```

### 9-2. Log Investigation

```bash
# Check recent login history
lastlog

# Check SSH/telnet authentication logs (detect suspicious logins)
cd /var/log && tail auth.log

# Check command history
history | less
```

### 9-3. System Resources / Processes

```bash
# System uptime and load
uptime

# Memory usage
free

# Detailed memory information
cat /proc/meminfo

# Mount information (check for unknown mounts)
cat /proc/mounts

# Real-time process list
top

# Full process status (detect malicious processes)
ps aux

# List of open files for a specific PID
lsof -p [PID]
```

### 9-4. Services and Network

```bash
# Check all running services
service --status-all

# Check scheduled tasks (detect malicious cron jobs)
cat /etc/crontab

# Check DNS configuration
more /etc/resolv.conf

# Check hosts file (detect DNS redirection)
more /etc/hosts

# Check firewall rules
iptables -L -n

# Check network interfaces
ifconfig -a

# List processes listening on ports
lsof -i

# Check all connected ports
netstat -nap

# Check ARP cache (detect ARP spoofing)
arp -a

# Check PATH environment variable (detect PATH hijacking)
echo $PATH
```

### 9-5. File Investigation

Search for recently modified files. Malware often drops executables in `/tmp`, `/var/tmp`, and home directories. Use `find` to collect files created or modified within the last 24-48 hours to identify malicious files.

```bash
# Detect files larger than 512KB in home directories
find /home/ -type f -size +512k -exec ls -lh {} \;

# Detect files modified within the last 2 days
find / -mtime -2 -ls
```

---

---

## 11. Core SOC Building Principles (Budget-Conscious)

### SOC 4-5 Person Team Role Matrix
```
Tier 1 Triage Specialist:
  Skills: Linux/Mac/Windows administration, Python/Java/C programming, CISSP/GCIA/GCIH
  Roles:
  - Review latest alert severity and determine relevance/urgency
  - Create Tier 2 escalation tickets
  - Run vulnerability scans and review reports
  - Manage security monitoring tools (IDS/correlation rules)

Tier 2 Incident Responder:
  Skills: Tier 1 + natural curiosity, root cause tracking ability, composure under pressure
  Roles:
  - Review Tier 1 tickets, utilize threat intel (IOCs/rules)
  - Confirm affected systems and attack scope
  - Collect asset data (configurations, running processes)
  - Determine and direct recovery actions

Tier 3 Threat Hunter:
  Skills: Tier 1+2 + data visualization/penetration testing tool proficiency
  Roles:
  - Review asset/vulnerability data
  - Identify stealthy threats (using latest intelligence)
  - Penetration test operational systems (validate resilience)
  - Recommend security monitoring tool optimizations

Tier 4 SOC Manager:
  Skills: All tiers + strong leadership/communication abilities
  Roles:
  - Oversee SOC team, handle hiring/training/evaluation
  - Review escalation processes, oversee incident reports
  - Develop and execute crisis communication plans for CISO
  - Compliance reporting, measure SOC performance metrics
```

### SOC Core Process — 4 Stages
```
1. Event Classification and Triage
   Goal: Find signals in the noise
   - Detect IOCs (file hashes, IPs, domains) in log data
   - Review highest-severity events first
   - Document all activities (notes, tickets, etc.)

2. Prioritization and Analysis
   - Classify by Cyber Kill Chain stage
   - Analyze environment/infrastructure from attacker's perspective
   - Earlier detection in the kill chain increases success probability

3. Recovery and Remediation
   - Isolate threats, remove malicious files, patch vulnerabilities
   - Restore affected systems

4. Evaluation and Audit
   - Measure progress through regular reviews
   - Drive improvements based on SOC performance metrics

Cyber Kill Chain Alert Types (by severity):
  Reconnaissance/Weaponization → Low
  Delivery/Exploitation → Medium
  Installation/C2 → High
  Action on Objectives → Critical
```

### Core SOC Infrastructure Configuration (Minimum Viable)
```
Required Log Sources (all forwarded to SIEM):
  ✓ Firewall (Accept/Deny logs)
  ✓ Domain Controller (Active Directory)
  ✓ DNS server
  ✓ Email gateway
  ✓ Web servers/proxy
  ✓ File servers
  ✓ Database servers

Key Tools:
  Asset Discovery: Network scanning → detect unknown devices
  Vulnerability Assessment: CVSS-based prioritized vulnerability management
  Intrusion Detection: IDS/IPS (signature + behavior-based)
  Behavior Monitoring: Detect abnormal user/system activity
  SIEM/Security Analysis: Log correlation, dashboards, alerts

When to Use MSSP:
  - When the team lacks confidence in detection/isolation/response
  - When resources are focused on priorities other than security
```

---

## 12. Zero Trust Architecture (DoD Standard)

### Zero Trust Core Principles
```
"Never Trust, Always Verify"

Limitations of Traditional Perimeter Security:
  - Trust internal network → free movement after breach
  - Location-based trust → nullified by VPN bypass and similar techniques

Zero Trust Transition:
  - User, asset, and resource-centric security (no network perimeter)
  - Multi-attribute-based trust level assessment
  - Least-privilege access (only when needed, only what is needed)
```

### DoD 7 Zero Trust Pillars
```
1. Users
   - Mandatory MFA, continuous identity verification
   - Special management of privileged accounts

2. Devices
   - Continuously monitor health status of all endpoints
   - Block access from non-compliant devices

3. Networks
   - Block lateral movement via micro-segmentation
   - Enforce encrypted communications

4. Applications & Workloads
   - Application-level access controls
   - Protect containers/cloud workloads

5. Data
   - Data classification and labeling
   - DLP (Data Loss Prevention) policies

6. Visibility & Analytics
   - Continuous monitoring and log collection
   - SIEM + behavior analysis (UEBA)

7. Automation & Orchestration
   - Automate detection → response (SOAR)
   - Automate policy enforcement
```

### Zero Trust Implementation Maturity Levels
```
Target Level (Basic):
  - Enterprise-wide MFA deployment
  - Begin micro-segmentation
  - Centralized log collection
  - Establish data classification policies

Advanced Level:
  - Continuous multi-factor authentication
  - AI/ML-based behavior analysis
  - Automated threat response
  - Real-time policy adjustment

Key Transformation Challenges:
  - Mindset shift from "trust but verify" to "verify and verify again"
  - Complexity of applying Zero Trust to legacy systems
  - Balancing user experience with security
```

---

## 13. Incident Response Checklist — Windows

### 10-1. User Account Investigation

Investigate user accounts on a suspected compromised system. Check for hidden administrator accounts, recently created accounts, and accounts without passwords to detect backdoor accounts created by attackers.

```cmd
REM GUI: Local user management
lusrmgr.msc

REM List local users
net user

REM Check administrator group members
net localgroup administrators
```

Use PowerShell Get cmdlets to query system information. Used to check system state including processes, services, and registry entries.

```powershell
# PowerShell: List local users (including enabled status)
Get-LocalUser
```

### 10-2. Process Investigation

Windows process investigation commands. Use `tasklist /svc` to see services run by each process, and `wmic process get` to collect detailed information including parent process IDs.

```cmd
REM Process list (includes PID and memory)
tasklist

REM Check service associations per process
tasklist /svc
```

Use PowerShell Get cmdlets to query system information. Used to check system state including processes, services, and registry entries.

```powershell
# PowerShell: Process list
Get-Process

# WMIC: Full process information
wmic process list full

# WMIC: Identify parent-child process relationships
wmic process get name,parentprocessid,processid

# WMIC: Check command line for a specific PID
wmic process where 'ProcessID=1234' get Commandline
```

### 10-3. Services and Auto-Start Entries

Investigate services and auto-start entries. Use `sc query` to check running services, and `reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` to check registry auto-run entries.

```cmd
REM List running services
net start

REM Detailed service information
sc query | more

REM List scheduled tasks
schtasks
```

Use PowerShell Get cmdlets to query system information. Used to check system state including processes, services, and registry entries.

```powershell
# Startup program list (WMIC)
wmic startup get caption,command

# Startup program details (PowerShell)
Get-CimInstance Win32_StartupCommand | Select-Object Name, command, Location, User | Format-List
```

### 10-4. Registry Run Key Inspection

```powershell
# HKLM Run key (system-wide auto-run)
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

# HKCU Run key (current user auto-run)
reg query HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
```

### 10-5. Network Investigation

Analyze active network connections. Check for unknown external IP connections, non-standard port usage, and abnormally high numbers of ESTABLISHED connections to detect C2 communication indicators.

```cmd
REM Active TCP/UDP connections (with PID)
netstat -ano

REM Check file shares
net view \\127.0.0.1

REM Check session connections (sessions with external systems)
net use
net session
```

Use PowerShell Get cmdlets to query system information. Used to check system state including processes, services, and registry entries.

```powershell
# Check TCP connection status
Get-NetTCPConnection -LocalAddress 192.168.x.x | Sort-Object LocalPort

# List file shares
Get-SMBShare
```

### 10-6. Firewall and Logs

```cmd
REM Check firewall configuration
netsh firewall show config
netsh advfirewall show currentprofile

REM Export security event logs
wevtutil qe security
```

Use PowerShell Get cmdlets to query system information. Used to check system state including processes, services, and registry entries.

```powershell
# List event logs
Get-EventLog -List

# Detect recently modified files (executable files from last 10 days)
forfiles /D -10 /S /M *.exe /C "cmd /c echo @path"
forfiles /D -10 /S /M *.exe /C "cmd /c echo @ext @fname @fdate"
forfiles /p c: /S /D -10
```

---

## 14. Honeypot Operations

### Honeypot Types
```
Classification by Interaction Level:

Low-Interaction:
  - Limited service/port simulation
  - Monitors UDP, TCP, ICMP ports
  - Lures attackers with fake databases/files
  - Tools: Honeytrap, Specter, KFsensor

Medium-Interaction:
  - Emulates real OS and applications
  - Keeps attackers engaged longer to gain response time
  - Tools: Cowrie, HoneyPy

High-Interaction:
  - Operates real vulnerable systems (actual OS + apps)
  - Collects the most information, but complex to manage
  - Tools: Honeynet

Pure Honeypot:
  - Mimics a real production environment
  - Motivates attackers to invest the most time

Production Honeypot:
  - Deployed within the actual network → useful for detecting internal attackers

Research Honeypot:
  - Used by government/military agencies for studying attack behavior
```

### Honeypot Types by Purpose
```
Malware Honeypot:   Collects malware behavior patterns
Email Honeypot:     Collects spam/phishing sender information
DB Honeypot:        Collects SQL injection patterns (with fake sensitive data)
Spider Honeypot:    Detects web crawlers/scrapers
Spam Honeypot:      Analyzes spammer behavior
Honeynet:           A network of honeypots in a virtual/isolated environment
```

### Attacker Information Collected by Honeypots
```
- Attacker IP addresses
- Keystrokes entered (password guesses, commands)
- Usernames and privilege levels used
- Data accessed/deleted/modified
- Tools and exploitation methods used
```

### Honeypot Deployment by Environment (Windows)
```bash
# Windows: Deploy HoneyBOT
# Displays hundreds of fake open ports during nmap scans
# Logs FTP, SSH, and other connection attempts
# Can save logs in CSV format
# Can configure email alerts
```

### Honeypot Deployment by Environment (Linux)
```python
#!/usr/bin/env python3
"""
Cowrie SSH Honeypot Log Analyzer CLI
Usage: python3 honeypot_analyzer.py --log /var/log/cowrie/cowrie.json [--top 20] [--json]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Iterator


# ------------------------------------------------------------------ #
#  Log Parser
# ------------------------------------------------------------------ #
def iter_cowrie_json(log_path: Path) -> Iterator[dict]:
    """Parse Cowrie JSON log line by line"""
    with log_path.open(encoding="utf-8", errors="replace") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as exc:
                print(f"[WARNING] Failed to parse line {lineno}: {exc}", file=sys.stderr)


def parse_cowrie_text(log_path: Path) -> Iterator[dict]:
    """Parse Cowrie text logs (fallback)"""
    pattern = re.compile(
        r"(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[^\s]*)\s+"
        r"\[(?P<component>[^\]]+)\]\s+(?P<message>.+)"
    )
    with log_path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            m = pattern.match(line.strip())
            if m:
                yield {
                    "timestamp": m.group("ts"),
                    "eventid": "",
                    "src_ip": "",
                    "message": m.group("message"),
                }


# ------------------------------------------------------------------ #
#  Statistics Aggregation
# ------------------------------------------------------------------ #
def analyze(events: list[dict], top_n: int = 10) -> dict:
    stats: dict = {
        "total_events": len(events),
        "unique_src_ips": set(),
        "event_counts": Counter(),
        "top_attackers": Counter(),
        "commands_run": [],
        "credentials_tried": [],
        "sessions": defaultdict(list),
        "timeline": defaultdict(int),
    }

    for ev in events:
        eid = ev.get("eventid", "")
        src = ev.get("src_ip", "")
        session = ev.get("session", "")
        ts = ev.get("timestamp", "")[:10]  # YYYY-MM-DD

        stats["event_counts"][eid] += 1
        if src:
            stats["unique_src_ips"].add(src)
            stats["top_attackers"][src] += 1
        if ts:
            stats["timeline"][ts] += 1
        if session:
            stats["sessions"][session].append(eid)

        # Collect executed commands
        if eid == "cowrie.command.input":
            stats["commands_run"].append(
                {"time": ts, "src": src, "cmd": ev.get("input", "")}
            )

        # Collect credential attempts
        if eid in ("cowrie.login.failed", "cowrie.login.success"):
            stats["credentials_tried"].append(
                {
                    "time": ts,
                    "src": src,
                    "username": ev.get("username", ""),
                    "password": ev.get("password", ""),
                    "success": eid == "cowrie.login.success",
                }
            )

    # Convert set to list for serialization
    stats["unique_src_ips"] = list(stats["unique_src_ips"])
    stats["top_attackers_list"] = stats["top_attackers"].most_common(top_n)
    stats["top_commands"] = Counter(
        c["cmd"] for c in stats["commands_run"]
    ).most_common(top_n)
    stats["top_usernames"] = Counter(
        c["username"] for c in stats["credentials_tried"]
    ).most_common(top_n)
    stats["top_passwords"] = Counter(
        c["password"] for c in stats["credentials_tried"]
    ).most_common(top_n)

    return stats


# ------------------------------------------------------------------ #
#  Output
# ------------------------------------------------------------------ #
def print_report(stats: dict, as_json: bool = False) -> None:
    if as_json:
        serializable = {
            k: (list(v) if isinstance(v, set) else dict(v) if isinstance(v, Counter) else v)
            for k, v in stats.items()
            if k != "sessions"
        }
        print(json.dumps(serializable, ensure_ascii=False, indent=2))
        return

    print(f"\n{'='*60}")
    print(f"Total Events      : {stats['total_events']:,}")
    print(f"Unique Attackers  : {len(stats['unique_src_ips']):,}")
    print(f"Commands Executed : {len(stats['commands_run']):,}")
    print(f"Credential Attempts: {len(stats['credentials_tried']):,}")

    print("\n[Top Attacker IPs]")
    for ip, cnt in stats["top_attackers_list"]:
        print(f"  {ip:<20} {cnt:>6} times")

    print("\n[Most Executed Commands]")
    for cmd, cnt in stats["top_commands"]:
        short = cmd[:60] + "..." if len(cmd) > 60 else cmd
        print(f"  {cnt:>5}x  {short}")

    print("\n[Most Attempted Passwords]")
    for pw, cnt in stats["top_passwords"]:
        print(f"  {cnt:>5}x  {pw}")

    print("\n[Daily Attack Trend]")
    for day in sorted(stats["timeline"])[-14:]:
        bar = "#" * min(stats["timeline"][day] // 10, 50)
        print(f"  {day}  {bar} {stats['timeline'][day]}")


# ------------------------------------------------------------------ #
#  CLI
# ------------------------------------------------------------------ #
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Cowrie SSH Honeypot Log Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
               "  python3 honeypot_analyzer.py --log cowrie.json\n"
               "  python3 honeypot_analyzer.py --log cowrie.json --top 20 --json",
    )
    parser.add_argument(
        "--log",
        required=True,
        metavar="FILE",
        help="Path to Cowrie JSON log file",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=10,
        metavar="N",
        help="Show top N results (default: 10)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    log_path = Path(args.log)
    if not log_path.exists():
        parser.error(f"File not found: {log_path}")

    # Prefer JSON log; fall back to text parsing if needed
    if log_path.suffix in (".json", ".jsonl"):
        events = list(iter_cowrie_json(log_path))
    else:
        events = list(parse_cowrie_text(log_path))

    if not events:
        print("No events to analyze.", file=sys.stderr)
        sys.exit(1)

    stats = analyze(events, top_n=args.top)
    print_report(stats, as_json=args.json)


if __name__ == "__main__":
    main()
```

---

## 15. UBA/UEBA (User Behavior Analytics)

### How UBA Differs from Traditional Security
```
Limitations of Traditional Audit Methods:
  - Threshold-based alerts → fail to detect slow attacks and insider threats
  - High false positives → miss actual threats
  - 68% of 2017 breaches went undetected for over a month

UBA (User Behavior Analytics) Characteristics:
  - ML-based establishment of normal behavior baseline for each user
  - Automatic anomaly detection when deviating from baseline
  - Can detect slow attacks without threshold settings
```

### UBA Detection Areas
```
Anomalous Behavior Detection:
  - Abnormal volume of specific events (sudden spike in logins, etc.)
  - Login or resource access at abnormal hours
  - Logging into systems not normally used
  - First-time access attempt to a specific resource
  - Abnormal file activity (mass modifications/copies/deletions)

Privilege Abuse Detection:
  - Privileged users accessing large numbers of sensitive files
  - Abnormal behavior by administrator accounts
  - Querying sensitive data with excessive privileges

Insider Threat:
  - Approximately 28% of internal breach incidents
  - Data exfiltration attempts by employees about to resign or disgruntled employees
  - Repeated access attempts to unauthorized resources
```

### Utilizing UBA Risk Assessment Reports
```
Risk Assessment Indicators:
  - Accounts connected to the most assets
  - Identifying hyperactive accounts
  - Activity count for high-risk accounts (file activity volume, etc.)

UBA Integration in SIEM:
  - Learn normal login patterns and detect deviations
  - Splunk UBA, Elastic ML, Microsoft Sentinel, etc.
  - Immediately deliver alerts to admin email/SMS
```
