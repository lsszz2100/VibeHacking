# SOC 핵심 개념 및 Blue Team 기초

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
import requests
import json

class ThreatIntelFeed:
    def __init__(self):
        self.feeds = {
            'alienvault': 'https://otx.alienvault.com/api/v1/pulses/subscribed',
            'abuseipdb': 'https://api.abuseipdb.com/api/v2/blacklist',
        }
    
    def check_ip(self, ip: str) -> dict:
        """IP를 여러 위협 인텔리전스 소스에서 확인"""
        results = {}
        
        # AbuseIPDB
        headers = {'Key': 'YOUR_API_KEY', 'Accept': 'application/json'}
        resp = requests.get(
            f'https://api.abuseipdb.com/api/v2/check',
            params={'ipAddress': ip, 'maxAgeInDays': 90},
            headers=headers
        )
        if resp.status_code == 200:
            data = resp.json().get('data', {})
            results['abuseipdb'] = {
                'score': data.get('abuseConfidenceScore'),
                'country': data.get('countryCode'),
                'reports': data.get('totalReports')
            }
        
        # VirusTotal
        headers = {'x-apikey': 'YOUR_VT_KEY'}
        resp = requests.get(
            f'https://www.virustotal.com/api/v3/ip_addresses/{ip}',
            headers=headers
        )
        if resp.status_code == 200:
            stats = resp.json()['data']['attributes']['last_analysis_stats']
            results['virustotal'] = {
                'malicious': stats.get('malicious'),
                'suspicious': stats.get('suspicious')
            }
        
        return results
    
    def is_malicious(self, ip: str, threshold: int = 50) -> bool:
        result = self.check_ip(ip)
        score = result.get('abuseipdb', {}).get('score', 0)
        vt_malicious = result.get('virustotal', {}).get('malicious', 0)
        return score > threshold or vt_malicious > 3
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
