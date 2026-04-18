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

---

## 9. 인시던트 대응 체크시트 — Linux

### 9-1. 사용자 계정 조사

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

```cmd
REM GUI: 로컬 사용자 관리
lusrmgr.msc

REM 로컬 사용자 목록
net user

REM 관리자 그룹 멤버 확인
net localgroup administrators
```

```powershell
# PowerShell: 로컬 사용자 목록 (활성화 여부 포함)
Get-LocalUser
```

### 10-2. 프로세스 조사

```cmd
REM 프로세스 목록 (PID, 메모리 포함)
tasklist

REM 프로세스별 서비스 연결 확인
tasklist /svc
```

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

```cmd
REM 실행 중인 서비스 목록
net start

REM 서비스 상세 정보
sc query | more

REM 스케줄 작업 목록
schtasks
```

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

```cmd
REM 활성 TCP/UDP 연결 (PID 포함)
netstat -ano

REM 파일 공유 확인
net view \\127.0.0.1

REM 세션 연결 확인 (외부 시스템과 세션)
net use
net session
```

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
```bash
# Cowrie (SSH 허니팟) 설치
pip install cowrie

# 실행
cowrie start

# 공격자 세션 로그 확인
cat /var/log/cowrie/cowrie.log | grep "New connection"
cat /var/log/cowrie/cowrie.json   # JSON 형식 로그
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
