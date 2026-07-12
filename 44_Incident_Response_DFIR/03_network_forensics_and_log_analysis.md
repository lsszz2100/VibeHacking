> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 네트워크 포렌식과 로그 분석

네트워크 포렌식은 PCAP 캡처 분석과 흐름 기반 C2 탐지를 포함한다. 로그 분석은 Windows 이벤트 ID 패턴과 Sysmon 이벤트를 중심으로 공격자 행적을 재구성한다.

## 0. 초보자를 위한 개념 이해

### 네트워크 포렌식과 로그 분석이란?

네트워크 포렌식(Network Forensics)은 네트워크를 오간 패킷 데이터를 수집·분석해 사이버 공격의 흔적을 찾는 조사 기법이다. 로그 분석은 시스템, 애플리케이션, 보안 장비가 남긴 기록을 검토해 공격자의 행적을 시간순으로 재구성한다. 두 기법을 결합하면 "언제, 어디서, 어떻게" 침해가 발생했는지 규명할 수 있다.

**왜 배우는가:**
```
침해사고 조사 흐름:

  [공격 발생]
      │
      ▼
  네트워크 패킷 캡처 (PCAP)    → C2 통신, 데이터 유출 경로 확인
      │
  Windows 이벤트 로그          → 로그인 시도, 프로세스 실행 추적
      │
  Sysmon 로그                  → 파일 생성, 레지스트리 변경 추적
      │
      ▼
  [공격 타임라인 완성]          → 법적 증거 자료, 재발 방지 조치
```

### 핵심 개념 정리

```
주요 용어:

PCAP (Packet Capture)
  - 네트워크를 지나는 모든 패킷을 파일로 저장한 것
  - .pcap 또는 .pcapng 확장자
  - Wireshark로 열어 시각적으로 분석 가능

C2 (Command & Control)
  - 공격자가 감염된 컴퓨터에 명령을 내리는 서버
  - 피해 PC → C2 서버로 주기적 통신 (비콘, Beacon)
  - 탐지 방법: 규칙적인 통신 간격, 비정상 포트

Windows 이벤트 ID (Event ID)
  - Windows가 기록하는 보안 이벤트 번호
  - 4624 = 로그인 성공, 4625 = 로그인 실패
  - 4688 = 프로세스 생성, 4648 = 명시적 자격증명 사용

Sysmon (System Monitor)
  - Microsoft 무료 도구로 세밀한 시스템 활동 기록
  - 이벤트 ID 1 = 프로세스 생성, ID 3 = 네트워크 연결
  - 악성코드 탐지에 필수적인 상세 로그 제공
```

### 필요한 도구 및 환경
- **Wireshark**: GUI 패킷 분석 도구 (https://wireshark.org)
- **tshark**: Wireshark의 커맨드라인 버전
- **Sysmon**: Microsoft Sysinternals Suite 포함
- **Python + scapy**: PCAP 파일 자동 분석 스크립트 작성
- **ELK Stack (선택)**: Elasticsearch + Logstash + Kibana 로그 시각화

### 기초 실습 예제
```python
#!/usr/bin/env python3
"""PCAP 파일에서 의심스러운 C2 통신 패턴을 탐지하는 기초 스크립트"""
import json
from collections import Counter, defaultdict


def analyze_pcap_summary(log_entries: list[dict]) -> dict:
    """
    파싱된 패킷 로그에서 통신 패턴을 분석한다.

    실제 사용 시 scapy로 pcap을 파싱:
        from scapy.all import rdpcap, IP, TCP
        packets = rdpcap("capture.pcap")
    """
    dst_counter: Counter = Counter()
    port_counter: Counter = Counter()
    ip_intervals: dict = defaultdict(list)

    for entry in log_entries:
        dst_ip = entry.get("dst_ip", "")
        dst_port = entry.get("dst_port", 0)
        timestamp = entry.get("timestamp", 0)

        dst_counter[dst_ip] += 1
        port_counter[dst_port] += 1
        ip_intervals[dst_ip].append(timestamp)

    # 비콘 탐지: 같은 IP에 규칙적인 간격으로 연결 시도
    beacon_suspects = []
    for ip, times in ip_intervals.items():
        if len(times) < 5:
            continue
        sorted_times = sorted(times)
        intervals = [sorted_times[i+1] - sorted_times[i]
                     for i in range(len(sorted_times)-1)]
        avg = sum(intervals) / len(intervals)
        variance = sum((x - avg)**2 for x in intervals) / len(intervals)
        # 표준편차가 평균의 10% 미만이면 규칙적 패턴 의심
        if variance**0.5 < avg * 0.1 and avg > 0:
            beacon_suspects.append({
                "ip": ip,
                "연결횟수": len(times),
                "평균간격_초": round(avg, 1),
                "의심도": "높음"
            })

    return {
        "상위_목적지_IP": dst_counter.most_common(5),
        "상위_목적지_포트": port_counter.most_common(5),
        "C2_비콘_의심": beacon_suspects,
    }


if __name__ == "__main__":
    # 예제 데이터 (실제 환경에서는 scapy로 pcap 파싱)
    sample_logs = [
        {"dst_ip": "192.168.1.100", "dst_port": 443, "timestamp": 0},
        {"dst_ip": "192.168.1.100", "dst_port": 443, "timestamp": 60},
        {"dst_ip": "192.168.1.100", "dst_port": 443, "timestamp": 120},
        {"dst_ip": "192.168.1.100", "dst_port": 443, "timestamp": 180},
        {"dst_ip": "192.168.1.100", "dst_port": 443, "timestamp": 240},
        {"dst_ip": "8.8.8.8", "dst_port": 53, "timestamp": 10},
        {"dst_ip": "8.8.8.8", "dst_port": 53, "timestamp": 25},
    ]
    result = analyze_pcap_summary(sample_logs)
    print(json.dumps(result, ensure_ascii=False, indent=2))
```

---

## 1. Wireshark/tshark 실전 필터

### 1.1 핵심 필터 모음

```bash
# ── 기본 탐색 ──────────────────────────────────────────
tshark -r capture.pcap -T fields -e frame.time -e ip.src -e ip.dst -e tcp.port | head -50

# 특정 IP 통신
tshark -r capture.pcap "ip.addr == 192.168.1.100"

# HTTP 요청만
tshark -r capture.pcap -Y "http.request" -T fields \
    -e http.host -e http.request.uri -e http.user_agent

# DNS 쿼리 분석
tshark -r capture.pcap -Y "dns.qry.type == 1" -T fields \
    -e dns.qry.name -e ip.src | sort | uniq -c | sort -rn

# 대용량 파일 전송 탐지 (>1MB)
tshark -r capture.pcap -Y "tcp.len > 1000000"

# TLS/SSL 인증서 정보
tshark -r capture.pcap -Y "tls.handshake.type == 11" -T fields \
    -e tls.handshake.certificate

# ── C2 탐지 ────────────────────────────────────────────
# 비정상 포트 TCP 연결 (80/443/53 제외)
tshark -r capture.pcap -Y "tcp.flags.syn==1 and !tcp.flags.ack==1" \
    -T fields -e ip.dst -e tcp.dstport | grep -vE ":(80|443|53|22|25|110|143)$"

# 장시간 지속 연결 (C2 비콘 의심)
tshark -r capture.pcap -z conv,tcp | awk '$9 > 300'  # 300초 이상

# 규칙적 트래픽 패턴 (비콘)
tshark -r capture.pcap -Y "ip.dst == [suspicious_ip]" -T fields -e frame.time_relative | \
    awk 'NR>1 {printf "%.0f\n", $1-prev} {prev=$1}' | sort | uniq -c | sort -rn

# ── 자격증명 탐지 ───────────────────────────────────────
# HTTP Basic Auth
tshark -r capture.pcap -Y "http.authorization" -T fields \
    -e ip.src -e http.authorization

# FTP 비밀번호
tshark -r capture.pcap -Y "ftp.request.command == PASS" -T fields \
    -e ip.src -e ftp.request.arg

# NTLM 인증
tshark -r capture.pcap -Y "ntlmssp" -T fields \
    -e ntlmssp.identifier -e ntlmssp.messagetype
```

---

## 2. Zeek(Bro) 로그 분석

### 2.1 Zeek 로그 파일 구조

```bash
# Zeek 실행 (PCAP에서 로그 생성)
zeek -r capture.pcap LogAscii::use_json=T

# 생성되는 로그 파일:
# conn.log     — 전체 연결 (IP/포트/바이트/기간)
# dns.log      — DNS 쿼리/응답
# http.log     — HTTP 요청
# ssl.log      — TLS/SSL 핸드셰이크
# files.log    — 전송된 파일
# notice.log   — 이상 탐지 알림
```

### 2.2 핵심 Zeek 분석 명령어

```bash
# conn.log: 연결 상위 목적지
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p duration orig_bytes | \
    sort -k4 -rn | head -20

# DNS: 장문 서브도메인 (DNS 터널링 탐지)
cat dns.log | zeek-cut query | awk 'length($0)>50' | sort | uniq -c | sort -rn

# HTTP: User-Agent 이상 탐지
cat http.log | zeek-cut user_agent | sort | uniq -c | sort -rn | head -20

# SSL: 유효하지 않은 인증서
cat ssl.log | zeek-cut server_name validation_status | grep -v "ok"

# files.log: 실행 파일 전송
cat files.log | zeek-cut mime_type filename md5 | grep -i "application/x-dosexec\|application/x-pe"
```

---

## 3. Windows 이벤트 로그 분석

### 3.1 핵심 이벤트 ID 목록

| Event ID | 로그 | 의미 |
|----------|------|------|
| 4624 | Security | 로그온 성공 |
| 4625 | Security | 로그온 실패 |
| 4634/4647 | Security | 로그오프 |
| 4648 | Security | 명시적 자격증명으로 로그온 (Pass-the-Hash) |
| 4672 | Security | 관리자 권한 로그온 |
| 4688 | Security | 프로세스 생성 (커맨드라인 포함 시) |
| 4698/4702 | Security | 예약 작업 생성/수정 |
| 4720/4722 | Security | 계정 생성/활성화 |
| 4732 | Security | 로컬 그룹 멤버 추가 |
| 4756 | Security | 유니버설 그룹 멤버 추가 |
| 4776 | Security | NTLM 인증 시도 |
| 7045 | System | 새 서비스 설치 |
| 4104 | PowerShell | 스크립트 블록 로깅 |

### 3.2 PowerShell을 이용한 이벤트 분석

```powershell
# 로그온 실패 이벤트 분석 (브루트포스 탐지)
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4625
    StartTime = (Get-Date).AddHours(-24)
} | Group-Object { $_.Properties[5].Value } |  # 계정명 그룹화
    Sort-Object Count -Descending | Select-Object -First 20 | 
    Format-Table Name, Count

# 비정상 시간대 로그온 탐지 (오전 0~6시)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} |
    Where-Object { $_.TimeCreated.Hour -ge 0 -and $_.TimeCreated.Hour -lt 6 } |
    Select-Object TimeCreated, 
        @{N='User'; E={$_.Properties[5].Value}},
        @{N='LogonType'; E={$_.Properties[8].Value}},
        @{N='SourceIP'; E={$_.Properties[18].Value}}

# 예약 작업 생성 탐지 (공격자 지속성)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4698} |
    Select-Object TimeCreated,
        @{N='TaskName'; E={$_.Properties[4].Value}},
        @{N='Command'; E={$_.Properties[6].Value}}

# 프로세스 생성 (4688) — PowerShell 인코딩 명령 탐지
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} |
    Where-Object { $_.Properties[8].Value -match '-enc|-encodedcommand' } |
    Select-Object TimeCreated,
        @{N='ProcessName'; E={$_.Properties[5].Value}},
        @{N='CommandLine'; E={$_.Properties[8].Value}}
```

---

## 4. Sysmon 로그 분석

### 4.1 핵심 Sysmon 이벤트

| Event ID | 이벤트명 | 감지 가능 공격 |
|----------|---------|-------------|
| 1 | ProcessCreate | 악성 프로세스 실행, 인젝션 |
| 3 | NetworkConnect | C2 통신, 비콘 |
| 7 | ImageLoad | DLL 인젝션 |
| 8 | CreateRemoteThread | 프로세스 인젝션 |
| 11 | FileCreate | 악성 파일 드롭 |
| 12/13 | RegistryEvent | 지속성 레지스트리 키 |
| 15 | FileCreateStreamHash | ADS (대체 데이터 스트림) |
| 22 | DnsQuery | C2 도메인 조회 |

### 4.2 Sysmon 분석 쿼리 (XML 이벤트 파싱)

```powershell
# C2 통신 탐지 (알려지지 않은 외부 IP로 연결)
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
    Where-Object { $_.Id -eq 3 } |
    Select-Object TimeCreated,
        @{N='ProcessName'; E={$_.Properties[4].Value}},
        @{N='DestIP'; E={$_.Properties[14].Value}},
        @{N='DestPort'; E={$_.Properties[15].Value}} |
    Where-Object { $_.DestIP -notmatch '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)' }

# DLL 인젝션 탐지 (Event ID 8: CreateRemoteThread)
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
    Where-Object { $_.Id -eq 8 } |
    Select-Object TimeCreated,
        @{N='SourceProcess'; E={$_.Properties[4].Value}},
        @{N='TargetProcess'; E={$_.Properties[7].Value}},
        @{N='StartFunction'; E={$_.Properties[14].Value}}
```

---

## 5. PCAP C2 IOC 추출 CLI

```python
#!/usr/bin/env python3
"""PCAP 파일에서 C2 IOC 추출 CLI"""

import argparse
import ipaddress
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

try:
    import dpkt
except ImportError:
    print("[!] dpkt 필요: pip install dpkt", file=sys.stderr)
    sys.exit(1)


PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
]

SUSPICIOUS_PORTS = {
    1080: "SOCKS Proxy",
    4444: "Metasploit default",
    4445: "Metasploit",
    5555: "Android ADB",
    6666: "IRC/악성코드",
    8080: "웹 프록시",
    9999: "일반 악성코드",
    31337: "Back Orifice 전통 포트",
}

SUSPICIOUS_UA_PATTERNS = [
    re.compile(r'Go-http-client', re.I),
    re.compile(r'python-requests', re.I),
    re.compile(r'curl/[0-9]', re.I),
    re.compile(r'Wget/[0-9]', re.I),
    re.compile(r'^Mozilla/5\.0 \(compatible\)$', re.I),
    re.compile(r'[Cc]obalt [Ss]trike'),
]


@dataclass
class Connection:
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str
    byte_count: int = 0
    packet_count: int = 0


@dataclass
class IOCReport:
    external_connections: list[Connection] = field(default_factory=list)
    suspicious_dns: list[str] = field(default_factory=list)
    suspicious_http: list[dict] = field(default_factory=list)
    suspicious_ports: list[tuple] = field(default_factory=list)
    beaconing_candidates: list[dict] = field(default_factory=list)


def is_private(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in PRIVATE_RANGES)
    except ValueError:
        return True


def analyze_pcap(filepath: str) -> IOCReport:
    report = IOCReport()
    connection_times: dict[str, list[float]] = defaultdict(list)
    byte_counts: dict[tuple, int] = defaultdict(int)

    try:
        with open(filepath, 'rb') as f:
            pcap = dpkt.pcap.Reader(f)

            for ts, buf in pcap:
                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                    if not isinstance(eth.data, dpkt.ip.IP):
                        continue

                    ip = eth.data
                    src = str(ipaddress.ip_address(ip.src))
                    dst = str(ipaddress.ip_address(ip.dst))

                    if isinstance(ip.data, (dpkt.tcp.TCP, dpkt.udp.UDP)):
                        trans = ip.data
                        proto = "TCP" if isinstance(trans, dpkt.tcp.TCP) else "UDP"
                        dst_port = trans.dport

                        # 외부 연결 기록
                        if not is_private(dst):
                            key = f"{src}→{dst}:{dst_port}"
                            connection_times[key].append(ts)
                            byte_counts[(src, dst, dst_port, proto)] += len(buf)

                            # 의심 포트
                            if dst_port in SUSPICIOUS_PORTS:
                                report.suspicious_ports.append(
                                    (src, dst, dst_port, SUSPICIOUS_PORTS[dst_port])
                                )

                        # HTTP 분석
                        if dst_port in (80, 8080) and isinstance(trans, dpkt.tcp.TCP):
                            try:
                                http = dpkt.http.Request(trans.data)
                                ua = http.headers.get('user-agent', '')
                                host = http.headers.get('host', dst)
                                uri = http.uri

                                for pat in SUSPICIOUS_UA_PATTERNS:
                                    if pat.search(ua):
                                        report.suspicious_http.append({
                                            'src': src, 'host': host,
                                            'uri': uri, 'ua': ua[:80],
                                            'reason': f"의심 User-Agent: {pat.pattern}",
                                        })
                                        break
                            except Exception:
                                pass

                    # DNS 분석
                    if isinstance(ip.data, dpkt.udp.UDP) and ip.data.dport == 53:
                        try:
                            dns = dpkt.dns.DNS(ip.data.data)
                            for q in dns.qd:
                                name = q.name
                                # 긴 서브도메인 (DNS 터널링 탐지)
                                if len(name) > 50:
                                    report.suspicious_dns.append(name)
                                # 높은 엔트로피 서브도메인
                                parts = name.split('.')
                                if parts and len(parts[0]) > 20:
                                    report.suspicious_dns.append(f"[long_subdomain] {name}")
                        except Exception:
                            pass

                except Exception:
                    continue

    except FileNotFoundError:
        print(f"[!] 파일 없음: {filepath}", file=sys.stderr)
        sys.exit(1)

    # 비콘 탐지: 규칙적 연결 간격
    for key, times in connection_times.items():
        if len(times) < 5:
            continue
        intervals = [times[i+1] - times[i] for i in range(len(times)-1)]
        if not intervals:
            continue
        avg_interval = sum(intervals) / len(intervals)
        variance = sum((x - avg_interval)**2 for x in intervals) / len(intervals)
        # 낮은 분산 = 규칙적 = 비콘 의심
        if avg_interval > 0 and (variance / avg_interval**2) < 0.1 and len(times) > 10:
            src, rest = key.split('→')
            dst_info = rest
            report.beaconing_candidates.append({
                'connection': key,
                'count': len(times),
                'avg_interval_sec': round(avg_interval, 1),
                'variance_ratio': round(variance / avg_interval**2, 4),
            })

    # 외부 연결 목록 생성
    seen = set()
    for (src, dst, port, proto), size in sorted(byte_counts.items(), key=lambda x: -x[1]):
        if not is_private(dst):
            key = f"{src}→{dst}:{port}/{proto}"
            if key not in seen:
                seen.add(key)
                report.external_connections.append(Connection(
                    src_ip=src, dst_ip=dst, dst_port=port,
                    protocol=proto, byte_count=size,
                ))

    return report


def print_ioc_report(report: IOCReport) -> None:
    print(f"\n{'='*65}")
    print("PCAP C2 IOC 추출 보고서")
    print(f"{'='*65}\n")

    print(f"[외부 연결 — 상위 20개]")
    for conn in sorted(report.external_connections, key=lambda c: -c.byte_count)[:20]:
        print(f"  {conn.src_ip:<15} → {conn.dst_ip:<15} :{conn.dst_port}/{conn.protocol} "
              f"{conn.byte_count/1024:.1f}KB")

    if report.suspicious_ports:
        print(f"\n[의심 포트 연결 — {len(report.suspicious_ports)}개]")
        for src, dst, port, desc in report.suspicious_ports[:10]:
            print(f"  ⚠ {src} → {dst}:{port} ({desc})")

    if report.beaconing_candidates:
        print(f"\n[비콘 후보 — {len(report.beaconing_candidates)}개]")
        for b in report.beaconing_candidates[:5]:
            print(f"  ⚠ {b['connection']}")
            print(f"      횟수: {b['count']}, 평균 간격: {b['avg_interval_sec']}초")

    if report.suspicious_dns:
        print(f"\n[의심 DNS 쿼리 — {len(report.suspicious_dns)}개]")
        for dns in list(set(report.suspicious_dns))[:10]:
            print(f"  ⚠ {dns[:80]}")

    if report.suspicious_http:
        print(f"\n[의심 HTTP — {len(report.suspicious_http)}개]")
        for h in report.suspicious_http[:5]:
            print(f"  ⚠ {h['src']} → {h['host']}{h['uri'][:50]}")
            print(f"      {h['reason']}")


def main() -> None:
    parser = argparse.ArgumentParser(description="PCAP C2 IOC 추출 CLI")
    parser.add_argument("pcap_file", help="분석할 PCAP 파일")
    args = parser.parse_args()

    print(f"[*] PCAP 분석: {args.pcap_file}")
    report = analyze_pcap(args.pcap_file)
    print_ioc_report(report)


if __name__ == "__main__":
    main()
```

---

## 6. ELK Stack 로그 상관 분석 설정

```yaml
# Logstash 파이프라인 예시 (Windows Event Log)
input {
  beats {
    port => 5044
  }
}

filter {
  if [event][code] == "4625" {
    mutate { add_tag => ["failed_login"] }
  }
  if [event][code] == "4688" {
    if [process][command_line] =~ /powershell.*-enc/ {
      mutate { add_tag => ["encoded_powershell", "suspicious"] }
    }
  }
}

output {
  elasticsearch {
    hosts => ["localhost:9200"]
    index => "winlog-%{+YYYY.MM.dd}"
  }
}
```

```
# Kibana KQL 쿼리 예시
# 브루트포스 탐지
event.code: "4625" AND winlog.event_data.TargetUserName: "Administrator"

# 측면 이동 탐지
event.code: "4624" AND winlog.event_data.LogonType: "3" AND NOT source.ip: "10.0.0.0/8"

# 의심 예약 작업
event.code: "4698" AND winlog.event_data.TaskContent: *powershell*
```

<!-- detect-validate-44 -->
## 네트워크 증거 검증 — IOC가 실제 C2를 가리키는가

네트워크 포렌식은 *패킷을 봤는가*가 아니라 **추출한 IOC가 실제 악성 통신을 가리키고 재현 가능한가**로 신뢰된다. 정상 베이스라인과 대조한다. 검증은 **소유 캡처**에서만.

### 항목 → 위험 → 검증 방법 → 신뢰 신호

| 항목 | 위험 | 검증 방법 | 신뢰 신호 |
|---|---|---|---|
| IOC 정확도 | 정상 오탐 | 베이스라인 대조 | 정상엔 미존재 |
| C2 식별 | 우연 일치 | 비콘 주기 분석 | 규칙적 비콘 |
| 로그 완전성 | 누락 구간 | 시퀀스/갭 확인 | 연속 캡처 |
| 시간 동기 | NTP 미동기 | 소스 시간 정렬 | 단일 타임라인 |

### 방어 검증 (직접 확인)

```bash
# 1) 추출한 C2 IP/도메인이 정상 트래픽엔 없는지(오탐 배제) — 소유 캡처에서
tshark -r owned.pcap -Y 'ip.addr==SUSPECT_IP' -T fields -e frame.time -e ip.dst 2>/dev/null | head
# 2) 비콘 주기성(C2 신호) — 동일 목적지로의 간격이 규칙적인지
tshark -r owned.pcap -Y 'ip.dst==SUSPECT_IP' -T fields -e frame.time_epoch 2>/dev/null | awk 'NR>1{print $1-p} {p=$1}' | head
```

> 검증은 반드시 **소유 캡처**에서만 한다. "패킷을 봤다"와 "IOC가 실제 C2를 가리킨다"는 다르다 — 베이스라인 대조·비콘 주기로 직접 확인한다([[40_Threat_Hunting]], [[06_Malware_Analysis]]).

**최신 기법·통제 (2025–2026):**
- 암호화 트래픽 메타데이터·중앙 로그(SIEM) 상관이 핵심 — 검증: 침해 세션이 재구성되는가([[40_Threat_Hunting]])
- 로그 무결성·보존 — 강제되는지 확인

---

<a name="english"></a>

# Network Forensics and Log Analysis

Network forensics involves analyzing PCAP captures and detecting C2 communications through flow analysis. Log analysis reconstructs attacker activity by focusing on Windows Event ID patterns and Sysmon events.

---

## 1. Wireshark/tshark Practical Filters

### 1.1 Core Filter Collection

```bash
# ── Basic Navigation ──────────────────────────────────────
tshark -r capture.pcap -T fields -e frame.time -e ip.src -e ip.dst -e tcp.port | head -50

# Specific IP communication
tshark -r capture.pcap "ip.addr == 192.168.1.100"

# HTTP requests only
tshark -r capture.pcap -Y "http.request" -T fields \
    -e http.host -e http.request.uri -e http.user_agent

# DNS query analysis
tshark -r capture.pcap -Y "dns.qry.type == 1" -T fields \
    -e dns.qry.name -e ip.src | sort | uniq -c | sort -rn

# Large file transfer detection (>1MB)
tshark -r capture.pcap -Y "tcp.len > 1000000"

# TLS/SSL certificate information
tshark -r capture.pcap -Y "tls.handshake.type == 11" -T fields \
    -e tls.handshake.certificate

# ── C2 Detection ───────────────────────────────────────────
# Non-standard port TCP connections (excluding 80/443/53)
tshark -r capture.pcap -Y "tcp.flags.syn==1 and !tcp.flags.ack==1" \
    -T fields -e ip.dst -e tcp.dstport | grep -vE ":(80|443|53|22|25|110|143)$"

# Long-duration persistent connections (suspected C2 beacon)
tshark -r capture.pcap -z conv,tcp | awk '$9 > 300'  # over 300 seconds

# Regular traffic patterns (beaconing)
tshark -r capture.pcap -Y "ip.dst == [suspicious_ip]" -T fields -e frame.time_relative | \
    awk 'NR>1 {printf "%.0f\n", $1-prev} {prev=$1}' | sort | uniq -c | sort -rn

# ── Credential Detection ────────────────────────────────────
# HTTP Basic Auth
tshark -r capture.pcap -Y "http.authorization" -T fields \
    -e ip.src -e http.authorization

# FTP password
tshark -r capture.pcap -Y "ftp.request.command == PASS" -T fields \
    -e ip.src -e ftp.request.arg

# NTLM authentication
tshark -r capture.pcap -Y "ntlmssp" -T fields \
    -e ntlmssp.identifier -e ntlmssp.messagetype
```

---

## 2. Zeek (Bro) Log Analysis

### 2.1 Zeek Log File Structure

```bash
# Run Zeek (generate logs from PCAP)
zeek -r capture.pcap LogAscii::use_json=T

# Generated log files:
# conn.log     — all connections (IP/port/bytes/duration)
# dns.log      — DNS queries/responses
# http.log     — HTTP requests
# ssl.log      — TLS/SSL handshakes
# files.log    — transferred files
# notice.log   — anomaly detection alerts
```

### 2.2 Key Zeek Analysis Commands

```bash
# conn.log: top destination connections
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p duration orig_bytes | \
    sort -k4 -rn | head -20

# DNS: long subdomains (DNS tunneling detection)
cat dns.log | zeek-cut query | awk 'length($0)>50' | sort | uniq -c | sort -rn

# HTTP: user-agent anomaly detection
cat http.log | zeek-cut user_agent | sort | uniq -c | sort -rn | head -20

# SSL: invalid certificates
cat ssl.log | zeek-cut server_name validation_status | grep -v "ok"

# files.log: executable file transfers
cat files.log | zeek-cut mime_type filename md5 | grep -i "application/x-dosexec\|application/x-pe"
```

---

## 3. Windows Event Log Analysis

### 3.1 Key Event ID List

| Event ID | Log | Meaning |
|----------|-----|---------|
| 4624 | Security | Successful logon |
| 4625 | Security | Failed logon |
| 4634/4647 | Security | Logoff |
| 4648 | Security | Logon with explicit credentials (Pass-the-Hash) |
| 4672 | Security | Admin privilege logon |
| 4688 | Security | Process creation (includes command line) |
| 4698/4702 | Security | Scheduled task creation/modification |
| 4720/4722 | Security | Account creation/activation |
| 4732 | Security | Local group member added |
| 4756 | Security | Universal group member added |
| 4776 | Security | NTLM authentication attempt |
| 7045 | System | New service installed |
| 4104 | PowerShell | Script block logging |

### 3.2 Event Analysis with PowerShell

```powershell
# Failed logon event analysis (brute-force detection)
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4625
    StartTime = (Get-Date).AddHours(-24)
} | Group-Object { $_.Properties[5].Value } |  # group by account name
    Sort-Object Count -Descending | Select-Object -First 20 | 
    Format-Table Name, Count

# Unusual hour logon detection (midnight to 6am)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} |
    Where-Object { $_.TimeCreated.Hour -ge 0 -and $_.TimeCreated.Hour -lt 6 } |
    Select-Object TimeCreated, 
        @{N='User'; E={$_.Properties[5].Value}},
        @{N='LogonType'; E={$_.Properties[8].Value}},
        @{N='SourceIP'; E={$_.Properties[18].Value}}

# Scheduled task creation detection (attacker persistence)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4698} |
    Select-Object TimeCreated,
        @{N='TaskName'; E={$_.Properties[4].Value}},
        @{N='Command'; E={$_.Properties[6].Value}}

# Process creation (4688) — PowerShell encoded command detection
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} |
    Where-Object { $_.Properties[8].Value -match '-enc|-encodedcommand' } |
    Select-Object TimeCreated,
        @{N='ProcessName'; E={$_.Properties[5].Value}},
        @{N='CommandLine'; E={$_.Properties[8].Value}}
```

---

## 4. Sysmon Log Analysis

### 4.1 Key Sysmon Events

| Event ID | Event Name | Detectable Attacks |
|----------|-----------|-------------------|
| 1 | ProcessCreate | Malicious process execution, injection |
| 3 | NetworkConnect | C2 communication, beaconing |
| 7 | ImageLoad | DLL injection |
| 8 | CreateRemoteThread | Process injection |
| 11 | FileCreate | Malicious file drop |
| 12/13 | RegistryEvent | Persistence registry keys |
| 15 | FileCreateStreamHash | ADS (Alternate Data Streams) |
| 22 | DnsQuery | C2 domain lookup |

### 4.2 Sysmon Analysis Queries (XML Event Parsing)

```powershell
# C2 communication detection (connections to unknown external IPs)
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
    Where-Object { $_.Id -eq 3 } |
    Select-Object TimeCreated,
        @{N='ProcessName'; E={$_.Properties[4].Value}},
        @{N='DestIP'; E={$_.Properties[14].Value}},
        @{N='DestPort'; E={$_.Properties[15].Value}} |
    Where-Object { $_.DestIP -notmatch '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)' }

# DLL injection detection (Event ID 8: CreateRemoteThread)
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
    Where-Object { $_.Id -eq 8 } |
    Select-Object TimeCreated,
        @{N='SourceProcess'; E={$_.Properties[4].Value}},
        @{N='TargetProcess'; E={$_.Properties[7].Value}},
        @{N='StartFunction'; E={$_.Properties[14].Value}}
```

---

## 5. PCAP C2 IOC Extraction CLI

```python
#!/usr/bin/env python3
"""PCAP File C2 IOC Extraction CLI"""

import argparse
import ipaddress
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

try:
    import dpkt
except ImportError:
    print("[!] dpkt required: pip install dpkt", file=sys.stderr)
    sys.exit(1)


PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
]

SUSPICIOUS_PORTS = {
    1080: "SOCKS Proxy",
    4444: "Metasploit default",
    4445: "Metasploit",
    5555: "Android ADB",
    6666: "IRC/Malware",
    8080: "Web Proxy",
    9999: "Generic malware",
    31337: "Back Orifice traditional port",
}

SUSPICIOUS_UA_PATTERNS = [
    re.compile(r'Go-http-client', re.I),
    re.compile(r'python-requests', re.I),
    re.compile(r'curl/[0-9]', re.I),
    re.compile(r'Wget/[0-9]', re.I),
    re.compile(r'^Mozilla/5\.0 \(compatible\)$', re.I),
    re.compile(r'[Cc]obalt [Ss]trike'),
]


@dataclass
class Connection:
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str
    byte_count: int = 0
    packet_count: int = 0


@dataclass
class IOCReport:
    external_connections: list[Connection] = field(default_factory=list)
    suspicious_dns: list[str] = field(default_factory=list)
    suspicious_http: list[dict] = field(default_factory=list)
    suspicious_ports: list[tuple] = field(default_factory=list)
    beaconing_candidates: list[dict] = field(default_factory=list)


def is_private(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in PRIVATE_RANGES)
    except ValueError:
        return True


def analyze_pcap(filepath: str) -> IOCReport:
    report = IOCReport()
    connection_times: dict[str, list[float]] = defaultdict(list)
    byte_counts: dict[tuple, int] = defaultdict(int)

    try:
        with open(filepath, 'rb') as f:
            pcap = dpkt.pcap.Reader(f)

            for ts, buf in pcap:
                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                    if not isinstance(eth.data, dpkt.ip.IP):
                        continue

                    ip = eth.data
                    src = str(ipaddress.ip_address(ip.src))
                    dst = str(ipaddress.ip_address(ip.dst))

                    if isinstance(ip.data, (dpkt.tcp.TCP, dpkt.udp.UDP)):
                        trans = ip.data
                        proto = "TCP" if isinstance(trans, dpkt.tcp.TCP) else "UDP"
                        dst_port = trans.dport

                        # Record external connections
                        if not is_private(dst):
                            key = f"{src}→{dst}:{dst_port}"
                            connection_times[key].append(ts)
                            byte_counts[(src, dst, dst_port, proto)] += len(buf)

                            # Suspicious ports
                            if dst_port in SUSPICIOUS_PORTS:
                                report.suspicious_ports.append(
                                    (src, dst, dst_port, SUSPICIOUS_PORTS[dst_port])
                                )

                        # HTTP analysis
                        if dst_port in (80, 8080) and isinstance(trans, dpkt.tcp.TCP):
                            try:
                                http = dpkt.http.Request(trans.data)
                                ua = http.headers.get('user-agent', '')
                                host = http.headers.get('host', dst)
                                uri = http.uri

                                for pat in SUSPICIOUS_UA_PATTERNS:
                                    if pat.search(ua):
                                        report.suspicious_http.append({
                                            'src': src, 'host': host,
                                            'uri': uri, 'ua': ua[:80],
                                            'reason': f"Suspicious User-Agent: {pat.pattern}",
                                        })
                                        break
                            except Exception:
                                pass

                    # DNS analysis
                    if isinstance(ip.data, dpkt.udp.UDP) and ip.data.dport == 53:
                        try:
                            dns = dpkt.dns.DNS(ip.data.data)
                            for q in dns.qd:
                                name = q.name
                                # Long subdomains (DNS tunneling detection)
                                if len(name) > 50:
                                    report.suspicious_dns.append(name)
                                # High-entropy subdomains
                                parts = name.split('.')
                                if parts and len(parts[0]) > 20:
                                    report.suspicious_dns.append(f"[long_subdomain] {name}")
                        except Exception:
                            pass

                except Exception:
                    continue

    except FileNotFoundError:
        print(f"[!] File not found: {filepath}", file=sys.stderr)
        sys.exit(1)

    # Beacon detection: regular connection intervals
    for key, times in connection_times.items():
        if len(times) < 5:
            continue
        intervals = [times[i+1] - times[i] for i in range(len(times)-1)]
        if not intervals:
            continue
        avg_interval = sum(intervals) / len(intervals)
        variance = sum((x - avg_interval)**2 for x in intervals) / len(intervals)
        # Low variance = regular = suspected beacon
        if avg_interval > 0 and (variance / avg_interval**2) < 0.1 and len(times) > 10:
            src, rest = key.split('→')
            dst_info = rest
            report.beaconing_candidates.append({
                'connection': key,
                'count': len(times),
                'avg_interval_sec': round(avg_interval, 1),
                'variance_ratio': round(variance / avg_interval**2, 4),
            })

    # Generate external connection list
    seen = set()
    for (src, dst, port, proto), size in sorted(byte_counts.items(), key=lambda x: -x[1]):
        if not is_private(dst):
            key = f"{src}→{dst}:{port}/{proto}"
            if key not in seen:
                seen.add(key)
                report.external_connections.append(Connection(
                    src_ip=src, dst_ip=dst, dst_port=port,
                    protocol=proto, byte_count=size,
                ))

    return report


def print_ioc_report(report: IOCReport) -> None:
    print(f"\n{'='*65}")
    print("PCAP C2 IOC Extraction Report")
    print(f"{'='*65}\n")

    print(f"[External Connections — Top 20]")
    for conn in sorted(report.external_connections, key=lambda c: -c.byte_count)[:20]:
        print(f"  {conn.src_ip:<15} → {conn.dst_ip:<15} :{conn.dst_port}/{conn.protocol} "
              f"{conn.byte_count/1024:.1f}KB")

    if report.suspicious_ports:
        print(f"\n[Suspicious Port Connections — {len(report.suspicious_ports)}]")
        for src, dst, port, desc in report.suspicious_ports[:10]:
            print(f"  ⚠ {src} → {dst}:{port} ({desc})")

    if report.beaconing_candidates:
        print(f"\n[Beacon Candidates — {len(report.beaconing_candidates)}]")
        for b in report.beaconing_candidates[:5]:
            print(f"  ⚠ {b['connection']}")
            print(f"      Count: {b['count']}, Avg interval: {b['avg_interval_sec']}s")

    if report.suspicious_dns:
        print(f"\n[Suspicious DNS Queries — {len(report.suspicious_dns)}]")
        for dns in list(set(report.suspicious_dns))[:10]:
            print(f"  ⚠ {dns[:80]}")

    if report.suspicious_http:
        print(f"\n[Suspicious HTTP — {len(report.suspicious_http)}]")
        for h in report.suspicious_http[:5]:
            print(f"  ⚠ {h['src']} → {h['host']}{h['uri'][:50]}")
            print(f"      {h['reason']}")


def main() -> None:
    parser = argparse.ArgumentParser(description="PCAP C2 IOC Extraction CLI")
    parser.add_argument("pcap_file", help="PCAP file to analyze")
    args = parser.parse_args()

    print(f"[*] PCAP Analysis: {args.pcap_file}")
    report = analyze_pcap(args.pcap_file)
    print_ioc_report(report)


if __name__ == "__main__":
    main()
```

---

## 6. ELK Stack Log Correlation Configuration

```yaml
# Logstash pipeline example (Windows Event Log)
input {
  beats {
    port => 5044
  }
}

filter {
  if [event][code] == "4625" {
    mutate { add_tag => ["failed_login"] }
  }
  if [event][code] == "4688" {
    if [process][command_line] =~ /powershell.*-enc/ {
      mutate { add_tag => ["encoded_powershell", "suspicious"] }
    }
  }
}

output {
  elasticsearch {
    hosts => ["localhost:9200"]
    index => "winlog-%{+YYYY.MM.dd}"
  }
}
```

```
# Kibana KQL Query Examples
# Brute-force detection
event.code: "4625" AND winlog.event_data.TargetUserName: "Administrator"

# Lateral movement detection
event.code: "4624" AND winlog.event_data.LogonType: "3" AND NOT source.ip: "10.0.0.0/8"

# Suspicious scheduled tasks
event.code: "4698" AND winlog.event_data.TaskContent: *powershell*
```

<!-- detect-validate-44 -->
## Network-Evidence Validation — Does the IOC Actually Point to C2?

Network forensics is trusted not by *whether you looked at packets* but by **whether the extracted IOC actually points to malicious comms and is reproducible**. Compare against a normal baseline. Validate only on **owned captures**.

### Item -> Risk -> Validation method -> Trust signal

| Item | Risk | Validation method | Trust signal |
|---|---|---|---|
| IOC accuracy | Normal false positive | Compare baseline | Absent in normal |
| C2 identification | Coincidental match | Beacon-interval analysis | Regular beacon |
| Log completeness | Missing window | Sequence/gap check | Continuous capture |
| Time sync | NTP unsynced | Align source time | One timeline |

### Defense validation (verify directly)

```bash
# 1) Whether the extracted C2 IP/domain is absent in normal traffic (excludes false positive) — owned capture
tshark -r owned.pcap -Y 'ip.addr==SUSPECT_IP' -T fields -e frame.time -e ip.dst 2>/dev/null | head
# 2) Beacon periodicity (C2 signal) — whether intervals to the same destination are regular
tshark -r owned.pcap -Y 'ip.dst==SUSPECT_IP' -T fields -e frame.time_epoch 2>/dev/null | awk 'NR>1{print $1-p} {p=$1}' | head
```

> Validate only on **owned captures**. "Looked at packets" differs from "the IOC actually points to C2" — confirm via baseline comparison and beacon periodicity directly ([[40_Threat_Hunting]], [[06_Malware_Analysis]]).
