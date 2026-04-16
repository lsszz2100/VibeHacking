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
