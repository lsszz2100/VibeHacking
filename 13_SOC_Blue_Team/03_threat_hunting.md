> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

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


위협 헌팅은 '공격자가 이미 내부에 있다'는 가정 하에 능동적으로 침해 흔적을 찾는 활동입니다. MITRE ATT&CK 기법을 가설로 설정하고, 로그와 메모리를 분석하여 탐지 시스템이 놓친 공격자 활동을 추적합니다.

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

Splunk SPL 쿼리로 랜섬웨어 공격의 타임라인을 재구성합니다. 초기 침투부터 파일 암호화까지 각 단계의 이벤트를 시계열로 조합합니다.

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

메모리 덤프나 악성 파일에서 랜섬웨어 IOC를 추출합니다. 암호화 확장자, 랜섬노트 파일명, C2 주소, 비트코인 지갑 주소를 탐지합니다.

```python
#!/usr/bin/env python3
"""
랜섬웨어 IOC 자동 추출 및 YARA/Sigma 룰 생성기 CLI
사용: python3 ioc_extractor.py --file malware.exe --rule-name Ransomware_XYZ --out-dir ./rules
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path


# ------------------------------------------------------------------ #
#  데이터 구조
# ------------------------------------------------------------------ #
@dataclass
class IOCBundle:
    filepath: str
    file_hashes: dict = field(default_factory=dict)
    ips: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    registry_keys: list[str] = field(default_factory=list)
    file_paths: list[str] = field(default_factory=list)
    mutex_names: list[str] = field(default_factory=list)
    raw_strings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "filepath": self.filepath,
            "hashes": self.file_hashes,
            "ips": self.ips,
            "domains": self.domains,
            "urls": self.urls,
            "registry_keys": self.registry_keys,
            "file_paths": self.file_paths,
            "mutex_names": self.mutex_names,
        }


# ------------------------------------------------------------------ #
#  IOC 추출
# ------------------------------------------------------------------ #
def compute_hashes(data: bytes) -> dict[str, str]:
    return {
        "md5":    hashlib.md5(data).hexdigest(),
        "sha1":   hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


_IP_RE      = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b')
_DOMAIN_RE  = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|onion|xyz|ru|cn|info|biz)\b', re.I)
_URL_RE     = re.compile(r'https?://[^\s\'"<>]+', re.I)
_REG_RE     = re.compile(r'(?:HKEY_[A-Z_]+|HKLM|HKCU|HKU)\\[^\s\'"<>\x00]+')
_WINPATH_RE = re.compile(r'[A-Za-z]:\\(?:[^\s\'"<>\x00\\/:*?|]+\\)*[^\s\'"<>\x00\\/:*?|]+')
_MUTEX_RE   = re.compile(r'(?:Global\\|Local\\)?[A-Za-z0-9_\-]{8,40}Mutex', re.I)

# 내부 IP 제외 필터
_PRIVATE_IP_RE = re.compile(
    r'^(?:127\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)'
)

# 정상 Windows 도메인 제외
_BENIGN_DOMAINS = {
    "microsoft.com", "windows.com", "windowsupdate.com",
    "msftncsi.com", "msn.com", "bing.com",
}


def extract_strings(filepath: Path) -> list[str]:
    """strings 명령으로 출력 가능한 문자열 추출 (Linux/macOS) — 없으면 자체 구현"""
    try:
        result = subprocess.run(
            ["strings", "-n", "6", str(filepath)],
            capture_output=True, text=True, timeout=30,
        )
        return result.stdout.splitlines()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        # strings 없는 환경 대비 자체 추출
        data = filepath.read_bytes()
        printable = re.compile(rb'[ -~]{6,}')
        return [m.group().decode("ascii", errors="replace") for m in printable.finditer(data)]


def extract_iocs(filepath: Path) -> IOCBundle:
    bundle = IOCBundle(filepath=str(filepath))
    data = filepath.read_bytes()
    bundle.file_hashes = compute_hashes(data)

    strings = extract_strings(filepath)
    bundle.raw_strings = strings
    combined = "\n".join(strings)

    # IP (사설 IP 제외)
    bundle.ips = sorted({
        ip for ip in _IP_RE.findall(combined)
        if not _PRIVATE_IP_RE.match(ip)
    })

    # 도메인 (정상 도메인 제외)
    bundle.domains = sorted({
        d.lower() for d in _DOMAIN_RE.findall(combined)
        if d.lower() not in _BENIGN_DOMAINS
    })

    bundle.urls = sorted(set(_URL_RE.findall(combined)))
    bundle.registry_keys = sorted(set(_REG_RE.findall(combined)))
    bundle.file_paths = sorted(set(_WINPATH_RE.findall(combined)))
    bundle.mutex_names = sorted(set(_MUTEX_RE.findall(combined)))

    return bundle


# ------------------------------------------------------------------ #
#  YARA 룰 생성
# ------------------------------------------------------------------ #
def generate_yara(bundle: IOCBundle, rule_name: str) -> str:
    sha256 = bundle.file_hashes.get("sha256", "unknown")
    today = date.today().isoformat()

    strings_block = ""
    for i, domain in enumerate(bundle.domains[:5]):
        strings_block += f'        $domain_{i} = "{domain}" ascii nocase\n'
    for i, reg in enumerate(bundle.registry_keys[:4]):
        escaped = reg.replace("\\", "\\\\")
        strings_block += f'        $reg_{i} = "{escaped}" ascii nocase wide\n'
    for i, url in enumerate(bundle.urls[:3]):
        strings_block += f'        $url_{i} = "{url}" ascii nocase\n'
    for i, mutex in enumerate(bundle.mutex_names[:3]):
        strings_block += f'        $mutex_{i} = "{mutex}" ascii nocase wide\n'

    if not strings_block:
        strings_block = '        $hash = "placeholder"\n'

    condition_parts = []
    if bundle.domains:
        condition_parts.append("any of ($domain_*)")
    if bundle.registry_keys:
        condition_parts.append("any of ($reg_*)")
    if bundle.urls:
        condition_parts.append("any of ($url_*)")
    if bundle.mutex_names:
        condition_parts.append("any of ($mutex_*)")
    condition = " or\n        ".join(condition_parts) if condition_parts else "true"

    return f"""rule {rule_name}
{{
    meta:
        description = "Auto-generated IOC rule"
        date        = "{today}"
        sha256      = "{sha256}"
        filepath    = "{bundle.filepath}"

    strings:
{strings_block}
    condition:
        uint16(0) == 0x5A4D and  // PE 파일
        filesize < 10MB and
        (
        {condition}
        )
}}
"""


# ------------------------------------------------------------------ #
#  Sigma 룰 생성
# ------------------------------------------------------------------ #
def generate_sigma(bundle: IOCBundle, rule_name: str) -> str:
    today = date.today().isoformat()
    domains_yaml = "\n            - ".join(bundle.domains[:5]) if bundle.domains else "placeholder.evil.com"
    ips_yaml = "\n            - ".join(bundle.ips[:5]) if bundle.ips else "198.51.100.1"

    return f"""title: {rule_name} Network IOC Detection
id: auto-generated-{bundle.file_hashes.get('md5', 'unknown')[:8]}
status: experimental
description: |
    Auto-generated Sigma rule from IOC extraction of {Path(bundle.filepath).name}
date: {today}
tags:
    - attack.command_and_control
    - attack.t1071

detection:
    selection_domain:
        dns.query.name|contains:
            - {domains_yaml}
    selection_ip:
        destination.ip:
            - {ips_yaml}
    condition: selection_domain or selection_ip

falsepositives:
    - Unknown
level: high

fields:
    - src_ip
    - dest_ip
    - dns.query.name
"""


# ------------------------------------------------------------------ #
#  CLI
# ------------------------------------------------------------------ #
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="악성 파일 IOC 추출 및 YARA/Sigma 룰 자동 생성기",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="예시:\n"
               "  python3 ioc_extractor.py --file malware.exe\n"
               "  python3 ioc_extractor.py --file malware.exe --rule-name Ransomware_XYZ --out-dir ./rules\n"
               "  python3 ioc_extractor.py --file malware.exe --json",
    )
    parser.add_argument("--file", required=True, metavar="FILE", help="분석할 파일 경로")
    parser.add_argument("--rule-name", default="Malware_AutoGenerated", help="생성할 룰 이름")
    parser.add_argument("--out-dir", metavar="DIR", help="룰 파일 출력 디렉토리")
    parser.add_argument("--json", action="store_true", help="IOC를 JSON으로 출력")
    parser.add_argument("--no-yara", action="store_true", help="YARA 룰 생성 건너뜀")
    parser.add_argument("--no-sigma", action="store_true", help="Sigma 룰 생성 건너뜀")
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    target = Path(args.file)
    if not target.exists():
        parser.error(f"파일 없음: {target}")

    print(f"[*] IOC 추출 중: {target}", file=sys.stderr)
    bundle = extract_iocs(target)

    # JSON 출력
    if args.json:
        print(json.dumps(bundle.to_dict(), ensure_ascii=False, indent=2))
    else:
        print(f"\n{'='*60}")
        print(f"파일     : {target.name}")
        print(f"MD5      : {bundle.file_hashes['md5']}")
        print(f"SHA256   : {bundle.file_hashes['sha256']}")
        print(f"IP       : {len(bundle.ips)}개  {bundle.ips[:5]}")
        print(f"도메인   : {len(bundle.domains)}개  {bundle.domains[:5]}")
        print(f"URL      : {len(bundle.urls)}개")
        print(f"레지스트리: {len(bundle.registry_keys)}개")
        print(f"파일경로 : {len(bundle.file_paths)}개")
        print(f"Mutex    : {len(bundle.mutex_names)}개")

    out_dir = Path(args.out_dir) if args.out_dir else Path(".")
    out_dir.mkdir(parents=True, exist_ok=True)

    if not args.no_yara:
        yara_path = out_dir / f"{args.rule_name}.yar"
        yara_rule = generate_yara(bundle, args.rule_name)
        yara_path.write_text(yara_rule, encoding="utf-8")
        print(f"[+] YARA 룰 생성: {yara_path}")

    if not args.no_sigma:
        sigma_path = out_dir / f"{args.rule_name}.yml"
        sigma_rule = generate_sigma(bundle, args.rule_name)
        sigma_path.write_text(sigma_rule, encoding="utf-8")
        print(f"[+] Sigma 룰 생성: {sigma_path}")

    ioc_path = out_dir / f"{args.rule_name}_iocs.json"
    ioc_path.write_text(
        json.dumps(bundle.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"[+] IOC JSON 저장: {ioc_path}")


if __name__ == "__main__":
    main()
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

Splunk로 Cobalt Strike 비콘의 HTTP 통신 패턴을 탐지합니다. 비콘의 주기적인 체크인 패턴과 기본 Malleable C2 프로필 특징을 탐지합니다.

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

Zeek 스크립트로 C2 통신을 탐지합니다. 비콘 주기, 데이터 크기, 통신 패턴을 기반으로 의심스러운 연결을 실시간으로 탐지하고 알림을 발생시킵니다.

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


로그 파일에서 위협 헌팅 패턴을 검색합니다. 알려진 C2 도메인, 비정상 명령 실행, base64 인코딩된 PowerShell, 의심스러운 프로세스 이름 등을 grep으로 빠르게 탐색합니다.

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

STIX/TAXII 형식으로 위협 인텔리전스를 공유합니다. STIX 2.1 오브젝트로 IOC를 구조화하고 TAXII 서버를 통해 자동으로 배포합니다.

```python
#!/usr/bin/env python3
"""
STIX2 IOC 공유 스크립트 — IOC를 STIX2 Bundle로 패키징하고 MISP/TAXII 서버로 전송
사용: python3 stix_share.py --ioc-file iocs.json --misp-url https://misp.corp --misp-key KEY
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

try:
    from stix2 import (
        Bundle, Indicator, Malware, Relationship,
        ThreatActor, AttackPattern, ExternalReference,
    )
    from stix2.exceptions import STIXError
    HAS_STIX2 = True
except ImportError:
    HAS_STIX2 = False

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


# ------------------------------------------------------------------ #
#  STIX2 객체 생성 헬퍼
# ------------------------------------------------------------------ #
def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def make_ip_indicator(ip: str, description: str = "", labels: Optional[list] = None) -> "Indicator":
    return Indicator(
        name=f"Malicious IP: {ip}",
        description=description or f"Threat intelligence IOC: {ip}",
        pattern=f"[ipv4-addr:value = '{ip}']",
        pattern_type="stix",
        valid_from=now_utc(),
        labels=labels or ["malicious-activity"],
        confidence=75,
    )


def make_domain_indicator(domain: str, description: str = "") -> "Indicator":
    return Indicator(
        name=f"Malicious Domain: {domain}",
        description=description or f"C2 Domain: {domain}",
        pattern=f"[domain-name:value = '{domain}']",
        pattern_type="stix",
        valid_from=now_utc(),
        labels=["malicious-activity", "c2"],
        confidence=70,
    )


def make_hash_indicator(sha256: str, filename: str = "", description: str = "") -> "Indicator":
    name = filename or f"Malicious File ({sha256[:8]}...)"
    return Indicator(
        name=name,
        description=description or "Malware file hash",
        pattern=f"[file:hashes.'SHA-256' = '{sha256}']",
        pattern_type="stix",
        valid_from=now_utc(),
        labels=["malicious-activity"],
        confidence=90,
    )


def make_malware_object(name: str, malware_types: Optional[list] = None) -> "Malware":
    return Malware(
        name=name,
        is_family=True,
        malware_types=malware_types or ["ransomware"],
    )


def build_bundle(ioc_list: list[dict]) -> "Bundle":
    """
    IOC 목록을 STIX2 Bundle로 변환
    ioc_list 항목 형식:
      {"type": "ip",     "value": "1.2.3.4",   "description": "...", "malware": "..."}
      {"type": "domain", "value": "evil.com",   ...}
      {"type": "hash",   "value": "sha256hex",  "filename": "..."}
    """
    objects: list = []
    relationships: list = []

    malware_cache: dict[str, "Malware"] = {}

    for item in ioc_list:
        itype = item.get("type", "").lower()
        value = item.get("value", "").strip()
        desc = item.get("description", "")
        malware_name = item.get("malware", "")

        if not value:
            continue

        if itype == "ip":
            indicator = make_ip_indicator(value, desc)
        elif itype == "domain":
            indicator = make_domain_indicator(value, desc)
        elif itype in ("hash", "sha256", "md5"):
            indicator = make_hash_indicator(
                value, filename=item.get("filename", ""), description=desc
            )
        else:
            print(f"[경고] 알 수 없는 IOC 유형 '{itype}', 건너뜀", file=sys.stderr)
            continue

        objects.append(indicator)

        # 관련 악성코드 객체 연결
        if malware_name:
            if malware_name not in malware_cache:
                mal = make_malware_object(malware_name, item.get("malware_types"))
                malware_cache[malware_name] = mal
                objects.append(mal)
            rel = Relationship(
                relationship_type="indicates",
                source_ref=indicator.id,
                target_ref=malware_cache[malware_name].id,
            )
            relationships.append(rel)

    return Bundle(objects=objects + relationships)


# ------------------------------------------------------------------ #
#  전송 함수
# ------------------------------------------------------------------ #
def send_to_misp(bundle: "Bundle", misp_url: str, misp_key: str, verify_ssl: bool = True) -> bool:
    if not HAS_REQUESTS:
        print("[-] requests 라이브러리 없음: pip install requests", file=sys.stderr)
        return False

    headers = {
        "Authorization": misp_key,
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    endpoint = f"{misp_url.rstrip('/')}/events/add"
    payload = json.loads(bundle.serialize())

    try:
        resp = requests.post(endpoint, json=payload, headers=headers,
                             timeout=15, verify=verify_ssl)
        resp.raise_for_status()
        print(f"[+] MISP 업로드 성공: {resp.status_code}")
        return True
    except requests.RequestException as exc:
        print(f"[-] MISP 업로드 실패: {exc}", file=sys.stderr)
        return False


# ------------------------------------------------------------------ #
#  CLI
# ------------------------------------------------------------------ #
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="STIX2 IOC 패키징 및 MISP 공유 도구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="IOC JSON 파일 형식 (배열):\n"
               '  [{"type":"ip","value":"1.2.3.4","malware":"Ransomware_X"},\n'
               '   {"type":"domain","value":"c2.evil.com"},\n'
               '   {"type":"hash","value":"sha256hex","filename":"loader.exe"}]\n\n'
               "예시:\n"
               "  python3 stix_share.py --ioc-file iocs.json --out bundle.json\n"
               "  python3 stix_share.py --ioc-file iocs.json --misp-url https://misp.corp --misp-key KEY",
    )
    parser.add_argument("--ioc-file", required=True, metavar="FILE",
                        help="IOC 목록 JSON 파일")
    parser.add_argument("--out", metavar="FILE",
                        help="STIX2 Bundle 출력 파일 (기본: 화면 출력)")
    parser.add_argument("--misp-url", metavar="URL",
                        help="MISP 서버 URL (예: https://misp.corp)")
    parser.add_argument("--misp-key", metavar="KEY",
                        help="MISP API 키")
    parser.add_argument("--no-verify-ssl", action="store_true",
                        help="SSL 인증서 검증 비활성화")
    return parser


def main() -> None:
    if not HAS_STIX2:
        print("stix2 라이브러리 필요: pip install stix2", file=sys.stderr)
        sys.exit(1)

    parser = build_parser()
    args = parser.parse_args()

    ioc_path = Path(args.ioc_file)
    if not ioc_path.exists():
        parser.error(f"파일 없음: {ioc_path}")

    try:
        ioc_list: list[dict] = json.loads(ioc_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        parser.error(f"IOC 파일 읽기 실패: {exc}")

    print(f"[*] {len(ioc_list)}개 IOC 처리 중...", file=sys.stderr)

    try:
        bundle = build_bundle(ioc_list)
    except STIXError as exc:
        print(f"[-] STIX2 Bundle 생성 실패: {exc}", file=sys.stderr)
        sys.exit(1)

    bundle_json = bundle.serialize(pretty=True)
    indicator_count = sum(1 for o in bundle.objects if o.type == "indicator")
    print(f"[+] Bundle 생성: {indicator_count}개 Indicator, "
          f"{len(bundle.objects)}개 객체 총합", file=sys.stderr)

    if args.out:
        Path(args.out).write_text(bundle_json, encoding="utf-8")
        print(f"[+] Bundle 저장: {args.out}")
    else:
        print(bundle_json)

    if args.misp_url:
        if not args.misp_key:
            parser.error("--misp-key 필요")
        send_to_misp(bundle, args.misp_url, args.misp_key,
                     verify_ssl=not args.no_verify_ssl)


if __name__ == "__main__":
    main()
```

### IOC를 Splunk에 자동 적용

```python
#!/usr/bin/env python3
"""
Elastic Security Python API 위협 헌팅 쿼리 도구
사용: python3 elastic_hunt.py --host https://es:9200 --user elastic --password PASS --hunt lateral
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone, timedelta
from typing import Any, Iterator

try:
    from elasticsearch import Elasticsearch, AuthenticationException
    HAS_ES = True
except ImportError:
    HAS_ES = False


# ------------------------------------------------------------------ #
#  헌팅 쿼리 라이브러리
# ------------------------------------------------------------------ #
HUNT_QUERIES: dict[str, dict[str, Any]] = {

    "lateral_movement": {
        "description": "내부 SMB/WMI/PSExec 이동 탐지",
        "index": "winlogbeat-*",
        "query": {
            "bool": {
                "filter": [
                    {"terms": {"event.code": ["4624", "4625", "7045"]}},
                    {"term": {"winlog.event_data.LogonType": "3"}},
                    {"range": {"@timestamp": {"gte": "now-24h"}}},
                ],
                "must_not": [
                    {"term": {"source.ip": "127.0.0.1"}},
                ],
            }
        },
        "aggs": {
            "by_source_ip": {
                "terms": {"field": "source.ip", "size": 20},
                "aggs": {
                    "unique_hosts": {
                        "cardinality": {"field": "host.name"}
                    }
                },
            }
        },
    },

    "kerberoasting": {
        "description": "Kerberoasting 탐지 (RC4 암호화 TGS 요청)",
        "index": "winlogbeat-*",
        "query": {
            "bool": {
                "filter": [
                    {"term": {"event.code": "4769"}},
                    {"term": {"winlog.event_data.TicketEncryptionType": "0x17"}},
                    {"range": {"@timestamp": {"gte": "now-1h"}}},
                ]
            }
        },
        "aggs": {
            "by_user": {
                "terms": {"field": "winlog.event_data.SubjectUserName.keyword", "size": 10},
                "aggs": {
                    "services": {
                        "terms": {"field": "winlog.event_data.ServiceName.keyword", "size": 10}
                    }
                },
            }
        },
    },

    "password_spray": {
        "description": "패스워드 스프레이 탐지 (다수 계정 소수 시도)",
        "index": "winlogbeat-*",
        "query": {
            "bool": {
                "filter": [
                    {"term": {"event.code": "4625"}},
                    {"range": {"@timestamp": {"gte": "now-5m"}}},
                ]
            }
        },
        "aggs": {
            "by_src_ip": {
                "terms": {"field": "source.ip", "size": 20},
                "aggs": {
                    "unique_users": {
                        "cardinality": {"field": "winlog.event_data.TargetUserName.keyword"}
                    },
                    "attempt_count": {"value_count": {"field": "@timestamp"}},
                },
            }
        },
    },

    "lolbins": {
        "description": "LOLBins 실행 탐지 (certutil/mshta/regsvr32 등)",
        "index": "winlogbeat-*,sysmon-*",
        "query": {
            "bool": {
                "filter": [
                    {"term": {"event.code": "1"}},
                    {"range": {"@timestamp": {"gte": "now-24h"}}},
                ],
                "should": [
                    {"wildcard": {"process.executable": "*certutil*"}},
                    {"wildcard": {"process.executable": "*mshta*"}},
                    {"wildcard": {"process.executable": "*regsvr32*"}},
                    {"wildcard": {"process.executable": "*rundll32*"}},
                    {"wildcard": {"process.executable": "*bitsadmin*"}},
                    {"wildcard": {"process.executable": "*wscript*"}},
                    {"wildcard": {"process.executable": "*cscript*"}},
                ],
                "minimum_should_match": 1,
            }
        },
        "aggs": {
            "by_process": {
                "terms": {"field": "process.name", "size": 20},
                "aggs": {
                    "by_host": {"terms": {"field": "host.name", "size": 5}}
                },
            }
        },
    },

    "dns_tunneling": {
        "description": "DNS 터널링 탐지 (비정상적으로 긴 서브도메인)",
        "index": "packetbeat-*",
        "query": {
            "bool": {
                "filter": [
                    {"term": {"type": "dns"}},
                    {"range": {"@timestamp": {"gte": "now-1h"}}},
                    {"script": {
                        "script": {
                            "source": "doc['dns.question.name'].value.length() > 50",
                            "lang": "painless",
                        }
                    }},
                ]
            }
        },
        "aggs": {
            "by_src": {
                "terms": {"field": "source.ip", "size": 10},
                "aggs": {
                    "unique_domains": {
                        "cardinality": {"field": "dns.question.name"}
                    }
                },
            }
        },
    },
}


# ------------------------------------------------------------------ #
#  Elasticsearch 클라이언트
# ------------------------------------------------------------------ #
class ElasticHunter:
    def __init__(
        self,
        host: str,
        user: str = "elastic",
        password: str = "",
        verify_certs: bool = True,
    ) -> None:
        if not HAS_ES:
            raise RuntimeError("elasticsearch 라이브러리 필요: pip install elasticsearch")
        self.es = Elasticsearch(
            host,
            basic_auth=(user, password),
            verify_certs=verify_certs,
        )

    def run_hunt(self, hunt_name: str, size: int = 100) -> dict[str, Any]:
        if hunt_name not in HUNT_QUERIES:
            raise ValueError(
                f"헌팅 쿼리 없음: {hunt_name}. 가능한 목록: {list(HUNT_QUERIES)}"
            )
        spec = HUNT_QUERIES[hunt_name]
        body: dict[str, Any] = {
            "query": spec["query"],
            "size": size,
        }
        if "aggs" in spec:
            body["aggs"] = spec["aggs"]

        try:
            resp = self.es.search(index=spec["index"], body=body)
        except AuthenticationException:
            raise RuntimeError("Elasticsearch 인증 실패")

        hits = resp["hits"]["hits"]
        aggs = resp.get("aggregations", {})

        return {
            "hunt": hunt_name,
            "description": spec["description"],
            "total_hits": resp["hits"]["total"]["value"],
            "returned": len(hits),
            "aggregations": aggs,
            "hits": [h["_source"] for h in hits[:10]],
        }

    def list_hunts(self) -> None:
        for name, spec in HUNT_QUERIES.items():
            print(f"  {name:<25} — {spec['description']}")


# ------------------------------------------------------------------ #
#  출력
# ------------------------------------------------------------------ #
def print_result(result: dict[str, Any], as_json: bool = False) -> None:
    if as_json:
        print(json.dumps(result, ensure_ascii=False, indent=2, default=str))
        return

    print(f"\n{'='*60}")
    print(f"헌팅  : {result['hunt']}")
    print(f"설명  : {result['description']}")
    print(f"총 히트: {result['total_hits']:,}개 (표시: {result['returned']})")

    aggs = result.get("aggregations", {})
    for agg_name, agg_data in aggs.items():
        buckets = agg_data.get("buckets", [])
        if buckets:
            print(f"\n[집계: {agg_name}]")
            for b in buckets[:10]:
                key = b.get("key", "")
                count = b.get("doc_count", 0)
                # 중첩 집계 출력
                nested = {k: v for k, v in b.items()
                          if isinstance(v, dict) and "buckets" in v}
                print(f"  {key:<40} {count:>6}건")
                for nested_name, nested_data in nested.items():
                    for nb in nested_data.get("buckets", [])[:3]:
                        print(f"    └─ {nb.get('key','')}: {nb.get('doc_count',0)}")


# ------------------------------------------------------------------ #
#  CLI
# ------------------------------------------------------------------ #
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Elastic Security 위협 헌팅 쿼리 도구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="예시:\n"
               "  python3 elastic_hunt.py --list\n"
               "  python3 elastic_hunt.py --host https://es:9200 --hunt lateral_movement\n"
               "  python3 elastic_hunt.py --host https://es:9200 --hunt kerberoasting --json",
    )
    parser.add_argument("--host", default="https://localhost:9200",
                        help="Elasticsearch 호스트 (기본: https://localhost:9200)")
    parser.add_argument("--user", default="elastic", help="사용자명 (기본: elastic)")
    parser.add_argument("--password", default="", help="비밀번호")
    parser.add_argument("--hunt", metavar="NAME",
                        help="실행할 헌팅 쿼리 이름")
    parser.add_argument("--list", action="store_true",
                        help="사용 가능한 헌팅 쿼리 목록 표시")
    parser.add_argument("--size", type=int, default=100,
                        help="반환할 최대 문서 수 (기본: 100)")
    parser.add_argument("--json", action="store_true", help="JSON 형식으로 출력")
    parser.add_argument("--no-verify-ssl", action="store_true",
                        help="SSL 인증서 검증 비활성화")
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.list:
        print("[사용 가능한 헌팅 쿼리]")
        for name, spec in HUNT_QUERIES.items():
            print(f"  {name:<25} — {spec['description']}")
        return

    if not args.hunt:
        parser.print_help()
        sys.exit(1)

    if not HAS_ES:
        print("elasticsearch 라이브러리 필요: pip install elasticsearch", file=sys.stderr)
        sys.exit(1)

    try:
        hunter = ElasticHunter(
            host=args.host,
            user=args.user,
            password=args.password,
            verify_certs=not args.no_verify_ssl,
        )
        result = hunter.run_hunt(args.hunt, size=args.size)
        print_result(result, as_json=args.json)
    except (ValueError, RuntimeError) as exc:
        print(f"[-] 오류: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
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

---

<a name="english"></a>

# Threat Hunting & Ransomware Incident Response

## What is Threat Hunting

```
Reactive vs Proactive Security:

Traditional SOC (Reactive):
  Waiting for alerts → Alert arrives → Investigate → Respond
  Problem: Average dwell time 200+ days (attacker stays undetected)

Threat Hunting (Proactive):
  Hypothesis → Data search → Evidence collection → Detection rule creation
  Goal: Find attackers that bypassed automated detection
```

---

## 1. Threat Hunting Methodology

### Intelligence-Driven Hunting

```
Process:
1. Hypothesis formulation (based on threat intel, TTPs)
   Example: "Our industry is experiencing APT29 attacks using WMI persistence"

2. ATT&CK technique mapping
   APT29 → T1047 (WMI), T1543 (Create/Modify Service), T1055 (Process Injection)

3. Data source identification
   WMI → Windows Event ID 5857, 5860, 5861
   Service → Event ID 7045, registry HKLM\SYSTEM\CurrentControlSet\Services

4. SPL/KQL query writing
   index=windows (EventCode=5857 OR EventCode=5860)
   | table _time, host, user, Consumer, Filter

5. Analysis and IOC extraction
   - Legitimate WMI subscriptions vs malicious ones
   - Known malware patterns
```

---

## 2. Ransomware Incident Response

### Initial Response Checklist

```bash
# 1. Isolate infected system (immediate)
# - Disconnect from network (but do NOT power off)
# - Preserve memory dump

# 2. Collect volatile data
# Windows
wmic process list full > processes.txt
netstat -anob > network.txt
ipconfig /all > network_config.txt

# 3. Identify ransomware strain
# Check ransom note contents
# Search file extension on https://id-ransomware.malwarehunterteam.com/

# 4. Timeline creation
# EventCode=4663 (file access), EventCode=4688 (process creation)
# Find first encrypted file → work backwards

# 5. Determine attack vector
# Phishing email? RDP brute force? VPN vulnerability?
```

### Ransomware Detection SPL

```spl
# Mass file rename/extension change detection
index=windows EventCode=4663 ObjectType=File
| eval extension=mvindex(split(ObjectName, "."), -1)
| where extension IN ("encrypted", "locked", "ransom", "crypted", "enc")
| stats count dc(ObjectName) as UniqueFiles by host, ProcessName, User
| where UniqueFiles > 50
| eval severity="CRITICAL - Possible Ransomware"
| table _time, host, User, ProcessName, UniqueFiles, severity

# VSS (shadow copy) deletion detection
index=windows EventCode=4688
| where CommandLine LIKE "%vssadmin%delete%" OR
        CommandLine LIKE "%wmic%shadowcopy%delete%" OR
        CommandLine LIKE "%bcdedit%recoveryenabled%no%"
| table _time, host, User, CommandLine
```

---

## 3. Lateral Movement Hunting

### Pass-the-Hash Detection

```spl
# PtH: NTLM auth from workstation to workstation
index=windows EventCode=4624 LogonType=3
| where AuthPackage="NTLM"
| lookup asset_lookup src_ip OUTPUT asset_type as src_type
| lookup asset_lookup dest_ip OUTPUT asset_type as dest_type
| where src_type="workstation" AND dest_type="workstation"
| stats count dc(dest_ip) as TargetCount by src_ip, user
| where TargetCount > 3
| eval alert="Possible Pass-the-Hash"
```

### Kerberoasting Detection

```spl
# Service ticket requests targeting many SPNs from single account
index=windows EventCode=4769
| where TicketEncryptionType="0x17"  # RC4 - weak encryption
| stats count dc(ServiceName) as SPNCount by user, src_ip
| where SPNCount > 5
| table _time, user, src_ip, SPNCount
```

---

## 4. Memory Forensics

```bash
# Volatility 3 analysis
# Process list
vol -f memory.dmp windows.pslist

# Network connections
vol -f memory.dmp windows.netstat

# Inject code detection
vol -f memory.dmp windows.malfind

# Process memory extraction
vol -f memory.dmp windows.dumpfiles --pid 1234

# Registry analysis
vol -f memory.dmp windows.registry.hivelist
vol -f memory.dmp windows.registry.printkey \
    --key "SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
```

---

## 5. Threat Hunting Automation

```python
#!/usr/bin/env python3
"""Threat hunting automation using Splunk API"""
import requests
import json
import time

class ThreatHunter:
    def __init__(self, splunk_url: str, token: str):
        self.base_url = splunk_url
        self.headers = {"Authorization": f"Bearer {token}"}
        self.findings = []
    
    def run_hunt(self, hunt_name: str, spl_query: str, 
                 time_range: str = "-24h") -> list:
        """Execute hunting query and collect results"""
        
        # Submit search job
        resp = requests.post(
            f"{self.base_url}/services/search/jobs",
            headers=self.headers,
            data={
                "search": f"search {spl_query}",
                "earliest_time": time_range,
                "latest_time": "now",
                "output_mode": "json"
            },
            verify=False
        )
        
        job_id = resp.json().get("sid")
        print(f"[{hunt_name}] Job started: {job_id}")
        
        # Wait for completion
        while True:
            status_resp = requests.get(
                f"{self.base_url}/services/search/jobs/{job_id}",
                headers=self.headers,
                params={"output_mode": "json"},
                verify=False
            )
            status = status_resp.json()["entry"][0]["content"]["dispatchState"]
            if status == "DONE":
                break
            time.sleep(2)
        
        # Retrieve results
        results_resp = requests.get(
            f"{self.base_url}/services/search/jobs/{job_id}/results",
            headers=self.headers,
            params={"output_mode": "json", "count": 1000},
            verify=False
        )
        
        results = results_resp.json().get("results", [])
        if results:
            print(f"[{hunt_name}] Found {len(results)} suspicious events")
            self.findings.extend([{**r, "hunt": hunt_name} for r in results])
        
        return results
    
    def run_playbook(self):
        """Execute all hunting queries"""
        hunts = [
            ("Ransomware Detection", 
             'index=windows EventCode=4663 | eval ext=mvindex(split(ObjectName,"."), -1) | where ext IN ("encrypted","locked") | stats count by host,user | where count > 50'),
            ("Lateral Movement - PtH",
             'index=windows EventCode=4624 LogonType=3 AuthPackage=NTLM | stats dc(dest_ip) as targets by src_ip,user | where targets > 3'),
            ("Kerberoasting",
             'index=windows EventCode=4769 TicketEncryptionType=0x17 | stats dc(ServiceName) as spns by user | where spns > 5'),
        ]
        
        for hunt_name, query in hunts:
            self.run_hunt(hunt_name, query)
        
        return self.findings
```

---

## 6. Breach and Attack Simulation (BAS)

```
Purple Team Approach:

1. Attack preparation
   - Choose ATT&CK technique
   - Create test environment (sandbox)

2. Execute attack
   - MITRE Caldera or Atomic Red Team
   - Record exact commands, network traffic, artifacts

3. Detection validation
   - Were SIEM alerts triggered?
   - Detected stages vs undetected stages
   - At which stage can the Kill Chain be blocked?

4. Detection gap identification → Create new detection rules

Key tools:
  - MITRE Caldera: Automated ATT&CK-based emulation
  - Atomic Red Team: Test cases per technique
  - AttackIQ: Enterprise-grade BAS (Breach and Attack Simulation)
```
