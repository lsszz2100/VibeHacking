# 위협 헌팅 & 랜섬웨어 침해 대응

## 위협 헌팅이란

```
수동적 방어 (Reactive)  →  능동적 방어 (Proactive)
알림 대기               →  선제적 위협 탐색

헌팅 가설 예시:
  "공격자가 LOLBAS를 이용해 PowerShell 없이 실행 중이다"
  "APT는 DNS over HTTPS로 C2 통신을 숨기고 있다"
  "내부자가 야간에 대용량 데이터를 추출하고 있다"
```

---

## 1. 위협 헌팅 방법론

### 가설 기반 헌팅 (TaHiTI 모델)

```
1. 인텔리전스 수집
   - 최신 위협 보고서 분석
   - MITRE ATT&CK 기법 선택
   - 유사 업계 침해 사례 연구

2. 가설 수립
   "공격자는 T1218.005 (mshta.exe)를 이용해
    HTA 파일을 통해 초기 접근을 시도할 것이다"

3. 헌팅 실행
   - 관련 데이터 소스 쿼리
   - 이상 패턴 식별
   - 기준선(Baseline)과 비교

4. 분석 및 검증
   - 발견된 이상 행위 조사
   - TP/FP 판정

5. 개선
   - 자동 탐지 규칙 생성
   - 추가 로그 수집 필요성 식별
   - 인텔리전스 업데이트
```

---

## 2. 랜섬웨어 침해 조사

### 랜섬웨어 실행 단계별 아티팩트

```
1. 초기 접근 (Initial Access)
   ├── 피싱 이메일 (이메일 헤더, 첨부파일)
   ├── RDP 브루트포스 (이벤트 ID 4625 급증)
   └── 취약점 익스플로잇 (IIS/VPN 로그)

2. 지속성 확립 (Persistence)
   ├── 예약 작업 (이벤트 ID 4698)
   ├── 서비스 등록 (이벤트 ID 7045)
   └── 레지스트리 Run 키

3. 권한 상승 (Privilege Escalation)
   ├── Mimikatz 실행 (LSASS 접근)
   └── Kerberoasting (4769 이벤트)

4. 내부 이동 (Lateral Movement)
   ├── PsExec (SMB 연결 + 서비스 등록)
   ├── WMI 원격 실행
   └── RDP 세션

5. 데이터 탈취 (Exfiltration)
   ├── 대용량 외부 전송
   └── 클라우드 스토리지 업로드

6. 암호화 (Encryption)
   ├── 볼륨 섀도우 삭제 (vssadmin)
   ├── 백업 삭제 (wbadmin)
   └── 부트 설정 변경 (bcdedit)
```

### 랜섬웨어 타임라인 재구성

```spl
# 랜섬웨어 초기 지표 탐지
index=sysmon (EventCode=1 OR EventCode=11 OR EventCode=13)
| where match(CommandLine, "(?i)vssadmin|wbadmin|bcdedit")
  OR match(TargetFilename, "(?i)\\.ransom|\\.encrypted|README|DECRYPT")
  OR match(TargetObject, "(?i)vssvc|backup")
| sort _time
| table _time, host, User, EventCode, Image, CommandLine, TargetFilename

# 감염 시작 시점 추적 (최초 악성 파일 실행)
index=sysmon EventCode=1
| where match(Image, "(?i)\\\\Temp\\\\|\\\\AppData\\\\|\\\\Downloads\\\\")
| where NOT Signed="true"
| table _time, host, User, Image, CommandLine, Hashes

# 내부 전파 경로 추적
index=security EventCode=4624 LogonType=3
| where match(user, "DOMAIN\\\\") AND src_ip != "127.0.0.1"
| stats dc(host) as InfectedHosts, values(host) as HostList
  by user, src_ip
| where InfectedHosts > 3
| sort -InfectedHosts
```

### 랜섬웨어 IOC 추출

```python
#!/usr/bin/env python3
"""랜섬웨어 IOC 자동 추출"""
import os
import hashlib
import json
from pathlib import Path

def extract_ioc_from_sample(filepath: str) -> dict:
    """악성 파일에서 IOC 추출"""
    ioc = {
        "file_hash": {},
        "strings": [],
        "ips": [],
        "domains": [],
        "files": [],
        "registry": []
    }
    
    # 파일 해시
    with open(filepath, 'rb') as f:
        data = f.read()
    ioc["file_hash"]["md5"] = hashlib.md5(data).hexdigest()
    ioc["file_hash"]["sha256"] = hashlib.sha256(data).hexdigest()
    
    # 문자열 추출 (PE 바이너리)
    import subprocess
    result = subprocess.run(['strings', filepath], 
                          capture_output=True, text=True)
    strings = result.stdout.split('\n')
    
    # IP 주소 추출
    import re
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    ioc["ips"] = list(set(re.findall(ip_pattern, result.stdout)))
    
    # 도메인 추출
    domain_pattern = r'\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|onion)\b'
    ioc["domains"] = list(set(re.findall(domain_pattern, result.stdout)))
    
    # 레지스트리 키 추출
    reg_pattern = r'(?:HKEY_[A-Z_]+|HKLM|HKCU)\\[^\s"\'<>]+'
    ioc["registry"] = list(set(re.findall(reg_pattern, result.stdout)))
    
    # 파일 경로 추출
    file_pattern = r'[A-Za-z]:\\[^\s"\'<>]+'
    ioc["files"] = list(set(re.findall(file_pattern, result.stdout)))
    
    return ioc

def generate_yara_rule(ioc: dict, rule_name: str) -> str:
    """IOC에서 YARA 룰 자동 생성"""
    yara = f"""
rule {rule_name} {{
    meta:
        description = "Auto-generated from IOC extraction"
        date = "{__import__('datetime').date.today()}"
        hash = "{ioc['file_hash']['sha256']}"
    
    strings:
"""
    # 문자열 추가
    for i, domain in enumerate(ioc['domains'][:5]):
        yara += f'        $domain_{i} = "{domain}" nocase\n'
    
    for i, reg in enumerate(ioc['registry'][:3]):
        yara += f'        $reg_{i} = "{reg}" nocase wide\n'
    
    yara += """    
    condition:
        uint16(0) == 0x5A4D  // PE 파일
        and filesize < 5MB
        and (any of ($domain_*) or any of ($reg_*))
}
"""
    return yara

if __name__ == "__main__":
    ioc = extract_ioc_from_sample("malware_sample.exe")
    print(json.dumps(ioc, indent=2))
    
    yara_rule = generate_yara_rule(ioc, "Ransomware_Custom_001")
    with open("ransomware.yar", "w") as f:
        f.write(yara_rule)
    print("[+] YARA 룰 생성: ransomware.yar")
```

---

## 3. APT 추적 기법

### APT 탐지 체인 (Diamond Model)

```
    Adversary
        │
    Capability ──── Infrastructure
        │
      Victim

각 꼭짓점에서 피벗:
  인프라 → 동일 IP/도메인 사용하는 다른 캠페인
  도구 → 동일 멀웨어 패밀리
  피해자 → 동일 업종/지역 타겟
  공격자 → TTP 유사도 분석
```

### Cobalt Strike 탐지

```spl
# HTTP 비콘 패턴 (기본 프로필)
index=proxy
| where uri_path IN ("/submit.php", "/jquery-3.3.1.min.js", "/ie9compat.js")
  AND method = "POST"
| stats count, dc(_time) as Days, avg(bytes_in) as AvgSize
  by src_ip, dest_host
| where Days > 3 AND AvgSize < 500  # 작고 규칙적인 비콘

# JA3 핑거프린트 기반 탐지
index=ssl
| lookup ja3_blacklist ja3_hash OUTPUT threat_name
| where isnotnull(threat_name)
| table _time, src_ip, dest_ip, ja3_hash, threat_name

# Cobalt Strike 기본 인증서 탐지
index=ssl
| where match(ssl_subject, "(?i)Major Cobalt Strike|cobaltstrike")
  OR ssl_serial = "146473198"  # CS 기본 인증서 시리얼

# Named Pipe 기반 탐지
index=sysmon EventCode=17 OR EventCode=18
| where match(PipeName, "(?i)msagent_|status_|postex_|mojo|ntsvcs")
| table _time, host, User, EventType, PipeName
```

### DNS Tunneling 탐지

```spl
# 비정상적으로 긴 DNS 쿼리 (터널링)
index=dns
| eval query_len = len(query)
| where query_len > 50
| stats count, avg(query_len) as AvgLen
  by src_ip, query
| where count > 10 AND AvgLen > 40

# 동일 도메인 높은 빈도 쿼리
index=dns
| rex field=query "(?P<base_domain>[^.]+\.[^.]+)$"
| stats count, dc(query) as UniqueSubdomains
  by src_ip, base_domain
| where UniqueSubdomains > 100 AND count > 200

# TXT 레코드 쿼리 (데이터 전송에 활용)
index=dns query_type=TXT
| stats count by src_ip, query
| where count > 5
| sort -count
```

---

## 4. 네트워크 포렌식 (Zeek/Bro)

### Zeek 로그 분석

```bash
# conn.log: 네트워크 연결 전체 기록
# dns.log: DNS 쿼리/응답
# http.log: HTTP 트랜잭션
# ssl.log: TLS/SSL 연결
# files.log: 전송된 파일 메타데이터
# weird.log: 비정상 패킷

# conn.log 주요 필드
zeek-cut ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto duration orig_bytes resp_bytes < conn.log

# 대용량 전송 찾기
cat conn.log | zeek-cut ts id.orig_h id.resp_h orig_bytes resp_bytes \
| awk '$5 > 10000000 {print}' \
| sort -k5 -n -r | head 20

# DNS 고빈도 쿼리
cat dns.log | zeek-cut ts id.orig_h query qtype_name \
| sort | uniq -c | sort -rn | head 20

# 비정상 JA3 핑거프린트
cat ssl.log | zeek-cut ts id.orig_h id.resp_h ja3 server_name \
| grep -v "^-$" | sort | uniq -c | sort -rn
```

### Zeek 스크립트 - C2 탐지

```zeek
# c2_detection.zeek
@load base/protocols/http

module C2Detection;

export {
    redef enum Notice::Type += {
        Suspicious_C2_Beacon
    };
}

# HTTP 비콘 패턴 탐지
event http_request(c: connection, method: string, original_URI: string, 
                   unescaped_URI: string, version: string) {
    
    # 의심스러운 User-Agent
    local suspicious_ua = /(?i)(python-requests|curl\/|wget\/|Go-http-client)/;
    
    if (c$http?$user_agent && suspicious_ua in c$http$user_agent) {
        NOTICE([$note=Suspicious_C2_Beacon,
                $conn=c,
                $msg=fmt("Suspicious User-Agent: %s", c$http$user_agent),
                $identifier=cat(c$id$orig_h)]);
    }
}
```

---

## 5. 랜섬웨어 침해 대응 플레이북

### 초기 대응 (0-4시간)

```
즉시 수행:
□ 침해된 호스트 네트워크 격리 (케이블 분리/VLAN)
□ 영향 범위 파악 (암호화된 파일 확장자 확인)
□ 랜섬노트 텍스트 수집 → 랜섬웨어 패밀리 식별
□ Ransomware ID (https://id-ransomware.malwarehunterteam.com) 확인
□ 백업 상태 확인 (오프라인 백업 여부)
□ 경영진 보고 및 법적/규제 요건 확인

수집 (격리 전):
□ 메모리 덤프 (winpmem/LiME)
□ 네트워크 연결 상태 (netstat -an)
□ 실행 중 프로세스 (tasklist /v)
□ 이벤트 로그 백업
□ 감염 파일 샘플 (안전한 환경에서)
```

### 조사 (4-24시간)

```bash
# 랜섬웨어 초기 진입점 찾기
grep -i "4625\|rdp\|vpn" security.evtx.txt | grep "01/15/2024"

# 최초 악성 파일 확인
dir /tc C:\Users\%USERNAME%\AppData\Roaming\ /od
dir /tc C:\Temp\ /od

# 볼륨 섀도우 삭제 확인
wevtutil qe Security /q:"*[System[EventID=4688] and EventData[Data[@Name='CommandLine'] and Data[contains(.,'vssadmin')]]]"

# 네트워크 연결 확인 (감염 시점 주변)
# 이벤트 로그 5156/5157 기반
```

### 복구 결정 매트릭스

```
백업 있음?
├── YES → 백업에서 복구
│         └── 진입점 패치 후 복구
└── NO  → 복호화 키 획득 가능?
           ├── YES (법집행 통해 키 획득) → 복호화 시도
           ├── YES (NoMoreRansom.org 복호화 도구) → 복호화
           └── NO → 클린 재설치 OR 몸값 협상 고려
                    (권장하지 않음, 법적 위험 검토 필요)
```

---

## 6. Suricata IDS 규칙 작성

### 기본 규칙 문법

```
action proto src_ip src_port -> dest_ip dest_port (options)

alert tcp $EXTERNAL_NET any -> $HOME_NET 80
    (msg:"HTTP Suspicious User-Agent";
     content:"User-Agent: python-requests";
     sid:1000001; rev:1;)
```

### 실전 탐지 규칙

```
# Cobalt Strike 기본 비콘 탐지
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"MALWARE Cobalt Strike Default HTTP Beacon";
    flow:established,to_server;
    content:"GET";
    http_method;
    content:"/submit.php";
    http_uri;
    content:"Accept: */*";
    http_header;
    classtype:trojan-activity;
    sid:9000001;
    rev:1;
)

# DNS Tunneling 탐지 (TXT 쿼리)
alert dns any any -> any 53 (
    msg:"DNS Tunneling via TXT Record";
    dns.query;
    content:"|00 10|";  # TXT 레코드 타입
    threshold:type threshold, track by_src, count 10, seconds 60;
    classtype:policy-violation;
    sid:9000002;
    rev:1;
)

# 랜섬웨어 SMB 전파 탐지
alert smb $HOME_NET any -> $HOME_NET 445 (
    msg:"RANSOMWARE SMB Lateral Movement";
    flow:established,to_server;
    content:"|FF|SMB";
    threshold:type both, track by_src, count 10, seconds 30;
    classtype:trojan-activity;
    sid:9000003;
    rev:1;
)

# Log4Shell 탐지
alert http any any -> $HTTP_SERVERS any (
    msg:"EXPLOIT Log4Shell JNDI Injection Attempt";
    flow:established,to_server;
    content:"${jndi:";
    nocase;
    http_header;
    classtype:web-application-attack;
    sid:9000004;
    rev:1;
)
```

---

## 7. 침해 지표(IOC) 공유

### STIX/TAXII 포맷

```python
from stix2 import Indicator, Bundle, ThreatActor, Malware, Relationship

# IOC 생성
ip_indicator = Indicator(
    name="Malicious IP - Ransomware C2",
    pattern="[ipv4-addr:value = '192.168.100.1']",
    pattern_type="stix",
    valid_from="2024-01-15T00:00:00Z",
    labels=["malicious-activity"]
)

malware = Malware(
    name="RansomGroup_2024",
    is_family=True,
    labels=["ransomware"]
)

relationship = Relationship(
    relationship_type="indicates",
    source_ref=ip_indicator.id,
    target_ref=malware.id
)

bundle = Bundle(objects=[ip_indicator, malware, relationship])

# MISP에 업로드
import requests
requests.post(
    "https://misp.corp/events/add",
    json=bundle,
    headers={"Authorization": "MISP_API_KEY"}
)
```

### IOC를 Splunk에 자동 적용

```python
import requests
import json

def update_splunk_lookup(iocs: list, lookup_name: str):
    """수집된 IOC를 Splunk 룩업 테이블에 자동 추가"""
    
    splunk_url = "https://splunk.corp:8089"
    headers = {"Authorization": "Splunk YOUR_TOKEN"}
    
    # 현재 룩업 테이블 조회
    resp = requests.get(
        f"{splunk_url}/servicesNS/admin/search/data/transforms/lookups/{lookup_name}",
        headers=headers,
        verify=False
    )
    
    # IOC 형식으로 변환
    csv_content = "ip,type,threat,date\n"
    for ioc in iocs:
        csv_content += f"{ioc['ip']},{ioc['type']},{ioc['threat']},{ioc['date']}\n"
    
    # 룩업 파일 업로드
    requests.post(
        f"{splunk_url}/servicesNS/admin/search/data/lookup-table-files/{lookup_name}.csv",
        headers=headers,
        data=csv_content,
        verify=False
    )
    
    print(f"[+] {len(iocs)}개 IOC를 Splunk에 업데이트 완료")
```

---

## 8. MITRE ATT&CK 프레임워크 심화

### 8-1. ATT&CK 개요

MITRE ATT&CK(Adversarial Tactics, Techniques, and Common Knowledge)은 실제 관찰된 공격자 전술·기법을 기반으로 한 글로벌 지식 베이스다. 민간·정부·보안 제품 개발에 위협 모델과 방어 방법론을 수립하는 데 사용되며 무료로 공개되어 있다.

### 8-2. ATT&CK Enterprise 14가지 전술 (Tactics)

| 번호 | 전술 | 설명 | 예시 기법 |
|------|------|------|-----------|
| TA0043 | Reconnaissance | 미래 작전을 위한 정보 수집 | 조직 정보 수집, OSINT |
| TA0042 | Resource Development | 작전 지원 자원 확보 | C2 인프라 구축 |
| TA0001 | Initial Access | 네트워크 초기 침투 | 스피어 피싱, 취약점 익스플로잇 |
| TA0002 | Execution | 악성 코드 실행 | 원격 접근 도구 실행 |
| TA0003 | Persistence | 거점 유지 | 설정 변경, 자동 시작 등록 |
| TA0004 | Privilege Escalation | 상위 권한 획득 | 취약점으로 권한 상승 |
| TA0005 | Defense Evasion | 탐지 회피 | 신뢰 프로세스로 악성코드 은닉 |
| TA0006 | Credential Access | 계정 정보 탈취 | 키로깅, 자격 증명 덤프 |
| TA0007 | Discovery | 환경 정찰 | 시스템·네트워크 탐색 |
| TA0008 | Lateral Movement | 내부 이동 | 정상 자격 증명으로 다른 시스템 피벗 |
| TA0009 | Collection | 데이터 수집 | 클라우드 스토리지 데이터 접근 |
| TA0011 | Command and Control | 침해 시스템 제어 | 정상 웹 트래픽 모방 C2 통신 |
| TA0010 | Exfiltration | 데이터 유출 | 클라우드 계정으로 데이터 전송 |
| TA0040 | Impact | 시스템·데이터 파괴/방해 | 랜섬웨어로 데이터 암호화 |

### 8-3. ATT&CK vs. Cyber Kill Chain 비교

| MITRE ATT&CK | Cyber Kill Chain (Lockheed Martin) |
|---|---|
| Initial Access | Reconnaissance → Intrusion |
| Execution | Exploitation |
| Persistence | — |
| Privilege Escalation | Privilege Escalation |
| Defense Evasion | Obfuscation / Anti-forensics |
| Credential Access | — |
| Discovery | — |
| Lateral Movement | Lateral Movement |
| Collection | — |
| Exfiltration | Exfiltration |
| Command and Control | — |
| Impact | Denial of Service |

ATT&CK는 Kill Chain보다 세분화된 기법 수준의 맵핑을 제공하므로 탐지 규칙 작성과 갭 분석에 더 유용하다.

### 8-4. ATT&CK 활용 방법

```
1. 위협 탐지 우선순위 설정
   - 자신의 환경에서 가장 많이 사용되는 기법 식별
   - 탐지 커버리지 갭 분석
   - 높은 영향도 기법부터 탐지 규칙 적용

2. 레드팀/블루팀 연동
   - 레드팀: ATT&CK 기법 기반 TTP 시뮬레이션
   - 블루팀: 탐지 로직 검증 및 개선
   - ATT&CK Evaluations 결과 참고

3. 인텔리전스 매핑
   - 위협 행위자 그룹(APT)의 TTP를 ATT&CK로 매핑
   - STIX/TAXII 형식으로 위협 인텔 공유
   - MISP와 연동하여 자동 IOC 매핑

4. SIEM 탐지 규칙 개발
   - ATT&CK 기법별 Sigma 규칙 작성
   - Splunk, QRadar, Elastic SIEM에 적용
   - Atomic Red Team으로 탐지 검증
```

### 8-5. 주요 기법별 탐지 포인트

| ATT&CK 기법 | ID | 탐지 방법 |
|-------------|-----|-----------|
| PowerShell 실행 | T1059.001 | Event 4104 (Script Block Logging), `-EncodedCommand` 파라미터 |
| 예약 작업 생성 | T1053.005 | Event 4698, `schtasks` 명령어 모니터링 |
| 자격 증명 덤프 | T1003.001 | Event 4656 (lsass.exe 핸들), Mimikatz 시그니처 |
| Pass-the-Hash | T1550.002 | Event 4624 (Type 3 로그인), NTLM 인증 모니터링 |
| DLL 사이드로딩 | T1574.002 | 비표준 경로에서 로드된 DLL, 서명 없는 DLL |
| Living off the Land | T1218 | certutil, regsvr32, mshta 등 LOLBin 실행 |
| DNS 터널링 | T1071.004 | 비정상적으로 긴 DNS 쿼리, 높은 TXT 레코드 빈도 |
| 데이터 스테이징 | T1074 | 대용량 파일 임시 폴더 집중, 압축 도구 사용 |
| VSSAdmin 삭제 | T1490 | `vssadmin delete shadows`, WMI 기반 VSS 삭제 |
| 원격 서비스 | T1021.002 | Event 4624/4625, SMB 횡이동, psexec 패턴 |

### 8-6. ATT&CK Navigator 활용

```
ATT&CK Navigator (https://mitre-attack.github.io/attack-navigator/)

활용 시나리오:
1. 방어 커버리지 시각화
   - 현재 탐지 가능한 기법을 녹색으로 표시
   - 탐지 불가 기법을 빨간색으로 표시
   - 갭(Gap)을 한눈에 파악

2. 위협 그룹 TTP 오버레이
   - APT29, Lazarus 등 그룹의 TTP 레이어 불러오기
   - 자신의 환경과 비교하여 우선순위 도출

3. 레드팀 캠페인 계획
   - 시뮬레이션할 기법 선택 및 색상 분류
   - 팀 간 캠페인 계획 공유
```

---

## 9. ATT&CK 매핑 모범 사례 (CISA 가이드)

### ATT&CK 4계층 구조
```
1. 전술 (Tactics)
   - "무엇을", "왜" → 공격자의 기술적 목표
   - 예: Credential Access (자격증명 획득)
   - 주의: ATT&CK 전술은 선형 순서가 아님
   - 공격자가 모든 전술을 사용할 필요 없음

2. 기법 (Techniques)
   - "어떻게" → 목표 달성 방법
   - 예: Credential Dumping (자격증명 덤프)
   - 정당한 시스템 기능을 악용하는 경우 多 (LOtL)

3. 서브기법 (Sub-techniques)
   - 기법의 더 세분화된 설명
   - 예: OS Credential Dumping → LSASS Memory [T1003.001]
   - OS/플랫폼 특화인 경우 많음

4. 절차 (Procedures)
   - 특정 기법/서브기법의 실제 사용 사례
   - 적대자 에뮬레이션 및 탐지에 유용
```

### 정확한 ATT&CK 매핑 5단계 프로세스
```
1단계: 행위 찾기
   - IOC(해시, URL, IP) 찾기 → X
   - 공격자가 플랫폼과 상호작용한 방식 찾기 → O
   - Living-off-the-Land 기법 여부 확인
   - 초기 침해 방법 + 침해 후 활동 모두 식별

2단계: 행위 연구
   - 의심 행위 이해를 위한 추가 연구
   - 원본 CTI 보고서, 보안 벤더 보고서, CERT 자료 참조
   - ATT&CK 웹사이트에서 핵심 동사 검색
     (예: "명령 실행", "지속성 생성", "예약 작업 생성")

3단계: 전술 식별
   - 공격자가 달성하려는 목표 파악
   - 예:
     "사용자에게 SYSTEM 권한 부여" → TA0004 (권한 상승)
     "cmd.exe /C whoami" → TA0007 (탐색)
     "예약 작업 생성" → TA0003 (지속성)

4단계: 기법 식별
   - 전술 달성 방법 기술 세부사항 검토
   - 여러 기법이 동시에 적용 가능 예:
     "포트 8088을 통한 HTTP C2" → T1571 (비표준 포트) + T1071.001 (웹 프로토콜)
   - 명시적으로 언급되지 않으면 추론 금지

5단계: 서브기법 식별
   - 충분한 컨텍스트 없으면 부모 기법만 매핑
   - 예: Brute Force [T1110]의 서브기법:
     T1110.001 패스워드 추측
     T1110.002 패스워드 크래킹
     T1110.003 패스워드 스프레이
     T1110.004 자격증명 스터핑
```

### ATT&CK 기술 도메인별 범위
```
Enterprise ATT&CK:
  - Windows, Linux, MacOS 환경
  - 클라우드: AWS, GCP, Azure, Office 365, Azure AD, SaaS
  - 네트워크: 네트워크 인프라 장치

Mobile ATT&CK:
  - Android, iOS 플랫폼
  - 네트워크 기반 효과 (장치 접근 없이 사용 가능한 기법)

ICS ATT&CK (산업제어시스템):
  - SCADA 및 산업 제어 시스템 특화
  - 산업 프로세스 방해를 목표로 하는 기법
```

### ATT&CK 매핑 시 주의사항
```
매핑 품질 기준:
  ✓ 탐지, 완화, 대응 목적으로 실행 가능한 수준
  ✗ 단순 전술/기법 목록 (컨텍스트 없는 매핑) → 가치 낮음

서브기법 주의 사례:
  Obfuscated Files: Software Packing [T1027.002]
    = 실행 파일 압축/암호화 → Defense Evasion
  vs Data Encoding [T1132]
    = C2 트래픽 콘텐츠 인코딩 → Command and Control
  (전술이 다름!)

  Masquerading [T1036] = 일반적 위장
  vs Masquerade Task/Service [T1036.004] = 시스템 작업 위장
  (서브기법 세부 구별 필요)

ATT&CK Navigator 활용 팁:
  - 이미지/그래픽/커맨드라인 예시에 추가 기법 숨어있음
  - 한 번에 모든 매핑을 찾기 어려움 → 2차 검토 필수
  - 세부 정보 부족 시 전술 수준에서만 매핑
```

---

## 10. 공격 그래프(Attack Graphs) 활용 — Purple Team

### 원자적 vs 멀티스테이지 위협 분석 비교
```
원자적 분석 (Atomic Approach):
  - 단일 TTP 하나씩 분리 테스트
  - 장점: ATT&CK 기반 첫 발걸음으로 유용
  - 단점:
    1. 전체 공격 시퀀스 연결 미흡
    2. AI/ML 기반 보안 도구 트리거 어려움
       (단독 행위는 실제 공격처럼 보이지 않음)
    3. 블루팀 적절한 대응 준비 어려움

멀티스테이지 공격 그래프 (Attack Graph/Flow):
  - 전체 Kill Chain을 연결된 TTP 시퀀스로 표현
  - 장점:
    1. 실제 공격과 동일한 현실적 시뮬레이션
    2. AI/ML 보안 도구 효과적 테스트
    3. 블루팀 방어 갭 식별 및 Kill Chain 차단점 파악
```

### WannaCry 공격 그래프 예시
```
STEP 0: 스캔
  WannaCry가 CVE-2017-0144(EternalBlue) 취약 시스템 스캔
  ATT&CK: T1595 (Active Scanning)
    ↓
STEP 1: 익스플로잇
  SMBv1 취약점 익스플로잇, WannaCry 페이로드 전달
  ATT&CK: T1190 (Exploit Public-Facing Application)
    ↓ [방어 실패 시]
STEP 2: 파일시스템 저장
  페이로드를 파일시스템에 저장
    ↓ [방어 실패 시]
STEP 3: 측면 이동
  추가 취약 시스템으로 전파 (SMB)
  ATT&CK: T1021.002 (SMB/Windows Admin Shares)
    ↓
STEP 4: 시스템 탐색
  주변 장치/원격 시스템 탐색
  ATT&CK: T1082, T1018
    ↓
STEP 5: C2 통신
  Tor 채널 암호화 C2 연결
  ATT&CK: T1573 (Encrypted Channel)
    ↓
STEP 6: 암호화 (최종 목표)
  파일 암호화 후 몸값 요구
  ATT&CK: T1486 (Data Encrypted for Impact)
```

### Purple Team에서의 공격 그래프 활용
```
Purple Team = Red Team + Blue Team 협력

공격 그래프 기반 Purple Team 절차:
1. 공격 시나리오 선택 (특정 위협 그룹 또는 랜섬웨어)
2. 공격 그래프 작성 (전체 TTP 시퀀스 맵핑)
3. Red Team: 공격 그래프대로 단계별 공격 실행
4. Blue Team: 각 단계에서 탐지/차단 여부 검증
5. 결과 기록:
   - 탐지된 단계 vs 탐지 실패 단계
   - 어느 단계에서 Kill Chain 차단 가능한지
6. 탐지 갭 식별 → 새 탐지 규칙 생성

대표 활용 도구:
  - MITRE Caldera: 자동화된 ATT&CK 기반 에뮬레이션
  - Atomic Red Team: 기법별 테스트 케이스
  - AttackIQ: 엔터프라이즈급 BAS(Breach and Attack Simulation)
```
