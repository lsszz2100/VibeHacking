> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 네트워크 포렌식 — 패킷 분석 및 침해 대응

## 0. 초보자를 위한 개념 이해

### 네트워크 포렌식이란?

네트워크 포렌식은 네트워크 트래픽을 수집하고 분석하여 보안 사고의 원인과 경로를 밝히는 기술입니다. 공격자의 C&C(Command & Control) 통신, 데이터 유출, 내부 이동 경로를 패킷 수준에서 추적합니다.

**왜 배우는가:**
```
네트워크 포렌식으로 밝힐 수 있는 것:

  침해 사고 분석:
  → "공격자가 어느 IP에서 들어왔나?"
  → "어떤 파일을 외부로 가져갔나?"
  → "내부 어느 시스템까지 이동했나?"

  악성코드 통신 탐지:
  → C&C 서버 주소 (비콘 통신 패턴)
  → DNS 터널링 탐지 (비정상적으로 긴 DNS 쿼리)
  → HTTPS 내 악성 트래픽 (TLS 인증서 분석)

  실제 활용:
  방화벽 로그 없어도 PCAP 파일로 공격 재구성
  IDS/IPS 경보와 패킷을 연계하여 false positive 확인
  법정 제출용 증거 패킷 추출
```

### 핵심 개념 정리

```
네트워크 포렌식 분석 레이어:

  PCAP 분석 (패킷 수준):
    → Wireshark, tshark
    → 개별 패킷의 헤더, 페이로드 분석
    → 파일 재조합 (HTTP/FTP 전송된 파일 복원)

  NetFlow 분석 (흐름 수준):
    → 전체 패킷 저장 불가 시 사용
    → 출발지/목적지 IP, 포트, 바이트 수
    → 대용량 트래픽에서 이상 패턴 탐지

  로그 분석:
    → 방화벽, IDS, 프록시 로그
    → 차단/허용 기록 → 공격 타임라인 구성

악성 트래픽 탐지 포인트:
  비콘(Beacon): 일정 시간 간격 C&C 통신 (30초, 60초 주기)
  DGA 도메인: 무작위로 보이는 도메인 (mxk3jdhs.com 등)
  DNS 터널링: TXT/AAAA 레코드에 데이터 숨김
  Large POST: 비정상적으로 큰 HTTP POST (데이터 유출)
```

### 필요한 도구 및 환경
- **Wireshark**: PCAP 파일 시각화 분석 — 프로토콜 계층별 디코딩
- **tshark**: CLI 기반 Wireshark — 자동화 스크립트와 연동, 대용량 PCAP 처리
- **Zeek(Bro)**: 네트워크 트래픽을 구조화된 로그로 변환 — 대규모 환경 분석

### 기초 실습 예제
```python
#!/usr/bin/env python3
"""PCAP 파일에서 의심스러운 DNS 쿼리 탐지 (교육용)."""
import re
from dataclasses import dataclass
from collections import Counter
from typing import Optional

@dataclass
class DNSQuery:
    timestamp: str
    src_ip: str
    domain: str
    query_type: str

def calculate_domain_entropy(domain: str) -> float:
    """도메인 이름의 엔트로피 계산 — 높으면 DGA 도메인 의심."""
    import math
    name = domain.split(".")[0]  # TLD 제외한 호스트명
    if not name:
        return 0.0
    freq = Counter(name)
    entropy = -sum(
        (count / len(name)) * math.log2(count / len(name))
        for count in freq.values()
    )
    return round(entropy, 3)

def detect_suspicious_dns(queries: list[DNSQuery]) -> list[dict[str, str]]:
    """의심스러운 DNS 쿼리 탐지."""
    suspicious: list[dict[str, str]] = []
    for q in queries:
        entropy = calculate_domain_entropy(q.domain)
        reasons = []
        if entropy > 3.5:
            reasons.append(f"높은 엔트로피({entropy}) → DGA 의심")
        if len(q.domain) > 50:
            reasons.append("긴 도메인 → DNS 터널링 의심")
        if re.search(r"[0-9a-f]{16,}", q.domain):
            reasons.append("16진수 패턴 → 인코딩된 데이터")
        if reasons:
            suspicious.append({
                "도메인": q.domain,
                "출발지": q.src_ip,
                "이유": "; ".join(reasons),
            })
    return suspicious

if __name__ == "__main__":
    # 테스트 데이터
    test_queries = [
        DNSQuery("2026-01-01T10:00:00", "192.168.1.100", "google.com", "A"),
        DNSQuery("2026-01-01T10:00:05", "192.168.1.100", "mxk3jdhs9qw2.com", "A"),  # DGA 의심
        DNSQuery("2026-01-01T10:00:10", "192.168.1.100",
                 "aGVsbG8gd29ybGQ.exfil-c2.xyz", "TXT"),  # 터널링 의심
    ]
    for finding in detect_suspicious_dns(test_queries):
        print(f"[의심] {finding['도메인']}")
        print(f"  출발지: {finding['출발지']}")
        print(f"  이유: {finding['이유']}")
```

---

## 1. 네트워크 포렌식 개요

```
네트워크 포렌식 = 네트워크 트래픽에서 증거 수집 및 분석

수집 방법:
1. PCAP 파일 분석 (사전 캡처된 패킷)
2. NetFlow/IPFIX 분석 (요약 트래픽 데이터)
3. 방화벽/IDS 로그 분석
4. DNS 로그 분석

분석 목표:
✔ C&C 서버 통신 탐지
✔ 데이터 유출 탐지
✔ 측면 이동 탐지
✔ 악성 도메인/IP 식별
✔ 프로토콜 이상 탐지
```

---

## 2. Wireshark 실전 분석

### 2-1. 기본 필터

Wireshark 필터 표현식입니다. 디스플레이 필터로 특정 조건의 패킷만 표시하여 대용량 캡처에서 관심 있는 트래픽을 빠르게 찾습니다.

```wireshark
# IP 필터
ip.addr == 192.168.1.1          # 해당 IP 관련 모든 패킷
ip.src == 192.168.1.1           # 출발지 IP
ip.dst == 10.0.0.1              # 목적지 IP
ip.addr == 192.168.1.0/24       # 서브넷

# 포트 필터
tcp.port == 80                  # HTTP
tcp.port == 443                 # HTTPS
tcp.dstport == 4444             # 역방향 쉘 포트 (의심)
udp.port == 53                  # DNS

# 프로토콜 필터
http                            # HTTP
dns                             # DNS
ftp                             # FTP
ssh                             # SSH
smtp                            # 이메일
icmp                            # ICMP (핑)

# 조합 필터
ip.src == 192.168.1.100 && tcp.dstport == 80
http.request.method == "POST"
http && ip.dst != 192.168.1.1   # 외부 HTTP

# 패킷 내용 검색
frame contains "password"
tcp contains "cmd.exe"
http.request.uri contains "/shell"
```

### 2-2. HTTP 분석

Wireshark에서 HTTP 트래픽을 분석하는 필터입니다. 웹 요청/응답, 인증 시도, 악성 페이로드 전송 등을 확인합니다.

```wireshark
# HTTP 요청
http.request
http.request.method == "GET"
http.request.method == "POST"
http.request.uri contains "login"
http.request.uri contains ".php?cmd="   # 웹쉘 의심

# HTTP 응답
http.response.code == 200
http.response.code == 404
http.response.code >= 400       # 에러 응답

# HTTP 헤더
http.user_agent contains "curl"        # 자동화 도구
http.user_agent contains "sqlmap"      # SQL Injection 도구
http.cookie contains "PHPSESSID"

# 파일 다운로드 재조립
# File → Export Objects → HTTP → 저장
```

### 2-3. DNS 분석

Wireshark DNS 필터로 도메인 조회 패턴을 분석합니다. DNS 터널링, C2 통신, DGA(Domain Generation Algorithm) 사용 여부를 탐지합니다.

```wireshark
# DNS 쿼리
dns.flags.response == 0         # DNS 요청만
dns.flags.response == 1         # DNS 응답만
dns.qry.name contains ".onion"  # 토르 도메인
dns.qry.name matches ".*[0-9]{5,}.*"  # 의심 도메인 (긴 숫자)

# DNS 터널링 탐지
dns.qry.name.len > 50          # 비정상적으로 긴 도메인
# DNS 터널링: 데이터를 DNS 쿼리 서브도메인에 인코딩
# 예: aGVsbG8gd29ybGQ=.attacker.com (Base64 데이터)
```

### 2-4. 악성 트래픽 패턴

Wireshark에서 포트 스캔, SYN Flood 등 악성 트래픽 패턴을 탐지하는 필터입니다. 비정상적인 연결 시도와 대량 패킷을 식별합니다.

```wireshark
# 포트 스캔 탐지 (SYN 스캔)
tcp.flags.syn == 1 && tcp.flags.ack == 0 && ip.src == [스캐너IP]

# 역방향 쉘 (비표준 포트 연결)
tcp.dstport > 1024 && tcp.dstport < 65535 && !tcp.port == 443

# 대용량 데이터 유출
# Statistics → Conversations → TCP → Sort by Bytes
# 비정상적으로 큰 전송량 확인

# Beaconing (C&C 주기적 통신) 탐지
# Statistics → IO Graphs → 규칙적인 패턴 확인
```

---

## 3. NetworkMiner 분석

```
NetworkMiner = PCAP 파일 파싱 GUI 도구

주요 탭:
Hosts     → 통신에 참여한 모든 호스트
Files     → 전송된 파일 자동 추출 (HTTP, SMB, FTP)
Images    → 전송된 이미지 파일
Messages  → 이메일, 채팅
Credentials → 캡처된 자격증명 (평문)
Sessions  → 세션 목록
DNS       → DNS 쿼리 목록
```

---

## 4. tcpdump 실전

네트워크 포렌식을 위한 tcpdump 캡처 명령어입니다. 인시던트 발생 시 즉시 패킷 캡처를 시작하고, BPF 필터로 의심 IP나 포트의 트래픽만 저장합니다. `-w`로 pcap 파일에 저장 후 Wireshark로 상세 분석합니다.

```bash
# 기본 캡처
tcpdump -i eth0 -w capture.pcap

# 특정 호스트
tcpdump -i eth0 host 192.168.1.1 -w capture.pcap

# 특정 포트
tcpdump -i eth0 port 80 -w capture.pcap
tcpdump -i eth0 'port 80 or port 443' -w capture.pcap

# 특정 네트워크
tcpdump -i eth0 net 192.168.1.0/24 -w capture.pcap

# 파일 크기/개수 제한
tcpdump -i eth0 -C 100 -W 10 -w capture.pcap  # 100MB씩 10개 순환

# PCAP 읽기
tcpdump -r capture.pcap
tcpdump -r capture.pcap -n -A  # ASCII 출력
tcpdump -r capture.pcap 'tcp port 80' | head -50
```

---

## 5. 침해 지표(IOC) 분석

### 네트워크 IOC 유형
```
IP 주소 (C&C 서버, 공격자)
도메인 (악성 도메인)
URL (악성 URL, 피싱 페이지)
파일 해시 (악성 파일)
User-Agent (악성 도구 식별자)
JA3 해시 (TLS 클라이언트 지문)
```

### IOC 추출 자동화

```python
#!/usr/bin/env python3
"""
PCAP IOC 자동 추출기
용도: 패킷 캡처 파일에서 IP, 도메인, URL, User-Agent, DNS 쿼리 등 IOC 추출
의존성: pip install dpkt scapy
사용법: python3 pcap_ioc.py capture.pcap [--output iocs.json]
"""
from __future__ import annotations
import argparse
import json
import re
import socket
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

try:
    import dpkt
except ImportError:
    print("[!] 의존성 누락: pip install dpkt", file=sys.stderr)
    sys.exit(1)

# RFC1918 사설 주소 필터 (외부 C2 탐지 목적)
PRIVATE_NETS = [
    re.compile(r"^10\."),
    re.compile(r"^172\.(1[6-9]|2\d|3[01])\."),
    re.compile(r"^192\.168\."),
    re.compile(r"^127\."),
    re.compile(r"^::1$"),
]

SUSPICIOUS_PORTS = {4444, 5555, 1337, 8888, 31337, 9001, 9002}  # 역방향 쉘 / Tor

DNS_TUNNEL_THRESHOLD = 50  # 도메인 길이 임계값


def is_public(ip: str) -> bool:
    return not any(rx.match(ip) for rx in PRIVATE_NETS)


def inet_str(raw: bytes) -> str:
    try:
        if len(raw) == 4:
            return socket.inet_ntop(socket.AF_INET, raw)
        return socket.inet_ntop(socket.AF_INET6, raw)
    except Exception:
        return ""


@dataclass
class IOCResult:
    external_ips: Counter = field(default_factory=Counter)
    dns_queries: Counter = field(default_factory=Counter)
    http_urls: list[str] = field(default_factory=list)
    user_agents: Counter = field(default_factory=Counter)
    suspicious_connections: list[dict] = field(default_factory=list)
    dns_tunnel_candidates: list[str] = field(default_factory=list)
    beaconing_candidates: dict[str, list[float]] = field(default_factory=lambda: defaultdict(list))
    total_packets: int = 0


def _parse_http(data: bytes, src: str, dst: str, result: IOCResult) -> None:
    try:
        req = dpkt.http.Request(data)
        host = req.headers.get("host", dst)
        url = f"http://{host}{req.uri}"
        result.http_urls.append(url)
        ua = req.headers.get("user-agent", "")
        if ua:
            result.user_agents[ua] += 1
    except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
        pass


def _parse_dns(data: bytes, result: IOCResult) -> None:
    try:
        dns = dpkt.dns.DNS(data)
        for q in dns.qd:
            name = q.name if isinstance(q.name, str) else q.name.decode("utf-8", errors="replace")
            name = name.rstrip(".")
            result.dns_queries[name] += 1
            # DNS 터널링 탐지: 서브도메인이 비정상적으로 긴 경우
            labels = name.split(".")
            if labels and len(labels[0]) >= DNS_TUNNEL_THRESHOLD:
                result.dns_tunnel_candidates.append(name)
    except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError, UnicodeDecodeError):
        pass


def extract_iocs(pcap_path: str) -> IOCResult:
    result = IOCResult()

    with open(pcap_path, "rb") as fh:
        try:
            reader: Iterator = dpkt.pcap.Reader(fh)
        except ValueError:
            fh.seek(0)
            reader = dpkt.pcapng.Reader(fh)

        last_ts: dict[str, float] = {}

        for ts, buf in reader:
            result.total_packets += 1
            try:
                eth = dpkt.ethernet.Ethernet(buf)
            except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                continue

            ip = getattr(eth, "data", None)
            if not isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)):
                continue

            src_ip = inet_str(ip.src)
            dst_ip = inet_str(ip.dst)

            # 외부 IP 수집
            for addr in (src_ip, dst_ip):
                if addr and is_public(addr):
                    result.external_ips[addr] += 1

            transport = getattr(ip, "data", None)

            # TCP 처리
            if isinstance(transport, dpkt.tcp.TCP):
                dport = transport.dport
                sport = transport.sport

                # 의심 포트 연결
                if dport in SUSPICIOUS_PORTS or sport in SUSPICIOUS_PORTS:
                    result.suspicious_connections.append({
                        "ts": round(ts, 3),
                        "src": f"{src_ip}:{sport}",
                        "dst": f"{dst_ip}:{dport}",
                        "reason": f"의심 포트 {dport if dport in SUSPICIOUS_PORTS else sport}",
                    })

                payload = bytes(transport.data)
                if payload:
                    if dport == 80:
                        _parse_http(payload, src_ip, dst_ip, result)

                # 비컨 탐지: 동일 src→dst 연결 간격 기록
                conn_key = f"{src_ip}->{dst_ip}:{dport}"
                if conn_key in last_ts:
                    interval = ts - last_ts[conn_key]
                    result.beaconing_candidates[conn_key].append(interval)
                last_ts[conn_key] = ts

            # UDP 처리 (DNS)
            elif isinstance(transport, dpkt.udp.UDP):
                if transport.dport == 53:
                    _parse_dns(bytes(transport.data), result)

    # 비컨 탐지: 일정 간격(±5%)이 10회 이상 반복되는 연결
    beaconing_confirmed: dict[str, float] = {}
    for conn, intervals in result.beaconing_candidates.items():
        if len(intervals) < 10:
            continue
        avg = sum(intervals) / len(intervals)
        if avg < 1:
            continue
        variance = sum((x - avg) ** 2 for x in intervals) / len(intervals)
        cv = (variance ** 0.5) / avg  # 변동계수
        if cv < 0.1:  # 매우 규칙적인 패턴
            beaconing_confirmed[conn] = round(avg, 2)

    result.beaconing_candidates = beaconing_confirmed  # type: ignore[assignment]
    return result


def print_report(result: IOCResult, top_n: int = 20) -> None:
    print(f"\n{'='*65}")
    print(f"  PCAP IOC 분석 보고서  (총 패킷: {result.total_packets:,})")
    print(f"{'='*65}")

    print(f"\n[외부 IP 상위 {top_n}개]")
    for ip, cnt in result.external_ips.most_common(top_n):
        print(f"  {ip:<20} {cnt:>6}회")

    print(f"\n[DNS 쿼리 상위 {top_n}개]")
    for domain, cnt in result.dns_queries.most_common(top_n):
        print(f"  {domain:<50} {cnt:>5}회")

    print(f"\n[HTTP URL 샘플 (최대 20개)]")
    seen: set[str] = set()
    for url in result.http_urls:
        if url not in seen:
            print(f"  {url[:100]}")
            seen.add(url)
        if len(seen) >= 20:
            break

    if result.suspicious_connections:
        print(f"\n[의심 포트 연결 ({len(result.suspicious_connections)}건)]")
        for c in result.suspicious_connections[:20]:
            print(f"  {c['ts']:>12.3f}s  {c['src']:<25} → {c['dst']:<25} ({c['reason']})")

    if result.dns_tunnel_candidates:
        print(f"\n[DNS 터널링 의심 도메인 ({len(result.dns_tunnel_candidates)}건)]")
        for d in result.dns_tunnel_candidates[:10]:
            print(f"  {d[:100]}")

    if result.beaconing_candidates:
        print(f"\n[비컨 통신 의심 연결 (규칙적 인터벌)]")
        for conn, avg_interval in list(result.beaconing_candidates.items())[:10]:
            print(f"  {conn:<50} 평균 간격: {avg_interval}s")

    if result.user_agents:
        print(f"\n[User-Agent 상위 10개]")
        for ua, cnt in result.user_agents.most_common(10):
            print(f"  {cnt:>5}회  {ua[:80]}")


def main() -> None:
    parser = argparse.ArgumentParser(description="PCAP IOC 자동 추출기")
    parser.add_argument("pcap", help=".pcap 또는 .pcapng 파일 경로")
    parser.add_argument("--output", help="결과를 저장할 JSON 파일 경로")
    parser.add_argument("--top", type=int, default=20, help="상위 항목 표시 수 (기본값: 20)")
    args = parser.parse_args()

    if not Path(args.pcap).exists():
        print(f"[!] 파일 없음: {args.pcap}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] 분석 중: {args.pcap}")
    result = extract_iocs(args.pcap)
    print_report(result, args.top)

    if args.output:
        out_data = {
            "total_packets": result.total_packets,
            "external_ips": dict(result.external_ips.most_common(100)),
            "dns_queries": dict(result.dns_queries.most_common(100)),
            "http_urls": list(dict.fromkeys(result.http_urls))[:200],
            "user_agents": dict(result.user_agents.most_common(50)),
            "suspicious_connections": result.suspicious_connections[:100],
            "dns_tunnel_candidates": result.dns_tunnel_candidates[:50],
            "beaconing_candidates": result.beaconing_candidates,
        }
        Path(args.output).write_text(
            json.dumps(out_data, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        print(f"\n[+] JSON IOC 저장: {args.output}")


if __name__ == "__main__":
    main()
```

---

## 6. Zeek (Bro) 네트워크 분석

Zeek(구 Bro) 네트워크 분석 프레임워크를 설치하고 실행합니다. 패킷을 구조화된 로그로 변환하여 대용량 트래픽 분석에 효율적입니다.

```bash
# 설치
sudo apt install zeek

# PCAP 분석
zeek -r capture.pcap

# 생성되는 로그 파일:
# conn.log    → 모든 연결 (소스, 목적지, 포트, 바이트)
# http.log    → HTTP 요청/응답
# dns.log     → DNS 쿼리
# ssl.log     → TLS/SSL 세션
# files.log   → 전송된 파일
# weird.log   → 이상 프로토콜 동작

# conn.log 분석 (쉼표 구분)
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p proto duration orig_bytes | sort -k7 -rn | head -20

# DNS 쿼리 목록
cat dns.log | zeek-cut query | sort | uniq -c | sort -rn | head -20

# HTTPS 연결 (JA3 지문)
cat ssl.log | zeek-cut id.orig_h id.resp_h server_name ja3
```

---

## 7. Suricata IDS 규칙

Suricata IDS/IPS를 설치하고 규칙을 관리합니다. Snort 규칙과 호환되며 멀티스레드 처리로 고속 트래픽 분석이 가능합니다.

```bash
# 설치
sudo apt install suricata

# PCAP 분석
suricata -r capture.pcap -l output/

# 규칙 작성 예시
# fast.log에서 경고 확인

# 기본 규칙 예시
# 역방향 쉘 탐지
alert tcp any any -> any 4444 (msg:"Suspicious Reverse Shell - Port 4444"; sid:100001;)

# Meterpreter 트래픽 탐지 (Metasploit)
alert tcp any any -> any any (msg:"Meterpreter HTTPS"; 
  content:"METERPRETER"; nocase; sid:100002;)

# 웹쉘 접근 탐지
alert http any any -> any any (msg:"Webshell Access - cmd parameter";
  http.uri; content:"cmd="; nocase; sid:100003;)

# DNS 터널링 탐지
alert dns any any -> any any (msg:"Long DNS Query - Possible Tunneling";
  dns.query; dsize:>100; sid:100004;)

# 포트 스캔 탐지 (Threshold)
alert tcp any any -> $HOME_NET any (msg:"Port Scan Detected";
  flags:S; threshold: type both, track by_src, count 20, seconds 60;
  sid:100005;)
```

---

## 8. 이메일 포렌식

### 이메일 헤더 분석

```
From:      발신자 (위조 가능)
To:        수신자
Subject:   제목
Date:      발송 시간
Message-ID: 고유 메시지 ID
Received:  경유한 메일 서버 체인 (역순으로 읽음 → 원본 서버 확인)
X-Originating-IP: 실제 발신자 IP (일부 서버)
DKIM-Signature: 도메인 서명
SPF:       발신 서버 검증
DMARC:     SPF/DKIM 정책
```

이메일 헤더를 분석하여 발신 경로, 위조 여부, 스팸 점수를 확인합니다. 피싱 이메일 조사 시 Received 헤더를 역추적합니다.

```bash
# 이메일 헤더 분석 도구
# Google Admin Toolbox: https://toolbox.googleapps.com/apps/messageheader/
# MX Toolbox: https://mxtoolbox.com/EmailHeaders.aspx

# 스피어피싱 분석 체크리스트
□ Received 헤더의 실제 발신 IP
□ Reply-To가 From과 다른지 확인
□ 링크 도메인 (표시 텍스트 vs 실제 URL)
□ 첨부파일 해시 → VirusTotal
□ 도메인 타이포스쿼팅 확인
```

---

## 9. 실전 시나리오: APT 침해 조사

### 단계별 조사

```
1단계: 초기 유입 (Initial Access) 확인
- 스피어피싱 이메일 로그
- 웹 서버 액세스 로그 (웹 익스플로잇)
- VPN/RDP 인증 실패 로그

2단계: 실행 (Execution) 확인
- Prefetch에서 비정상 프로세스 실행
- 이벤트 ID 4688 (프로세스 생성)
- PowerShell 로그 (4104) - 인코딩된 명령

3단계: 지속성 (Persistence) 확인
- 레지스트리 Run 키
- 예약 작업
- 서비스 생성 (이벤트 7045)

4단계: 내부 이동 (Lateral Movement) 확인
- 이벤트 ID 4624 Type 3 (네트워크 로그인)
- SMB 트래픽
- PsExec 흔적

5단계: 정보 수집 및 유출 (Exfiltration) 확인
- 대용량 외부 전송
- 클라우드 스토리지 업로드
- DNS 터널링

6단계: C&C 통신 확인
- 주기적 아웃바운드 연결
- 비표준 포트 사용
- TLS/SSL 암호화된 통신 → JA3 지문
```

---

## 10. 방화벽/IDS 로그 분석

### 로그 분석 기본

Apache 액세스 로그를 grep, awk, sort 등으로 분석합니다. 가장 많은 요청을 보낸 IP, 접근 빈도 높은 URL, 에러 코드 분포를 파악합니다.

```bash
# Apache 액세스 로그 분석
# SQL Injection 시도 탐지
grep -E "UNION|SELECT|INSERT|DROP|OR%201=1" access.log

# 웹쉘 접근 시도
grep -E "cmd=|shell=|exec=|eval\(" access.log

# 스캐너 User-Agent
grep -Ei "nikto|nmap|masscan|sqlmap|acunetix|nessus" access.log

# 브루트포스 (동일 IP 다수 요청)
awk '{print $1}' access.log | sort | uniq -c | sort -rn | head -20

# 404 에러 다수 (디렉토리 열거)
grep " 404 " access.log | awk '{print $1}' | sort | uniq -c | sort -rn | head -10

# 응답 크기 이상 (데이터 유출)
awk '{print $10, $7}' access.log | sort -rn | head -20  # 응답 크기 큰 URL

# 특정 시간대 분석
grep "01/Jan/2024:14:" access.log | wc -l
```

### fail2ban 로그 분석

fail2ban 로그에서 SSH 브루트포스 차단 기록을 확인합니다. 어떤 IP가 차단되었는지, 얼마나 많은 시도가 있었는지 분석합니다.

```bash
# SSH 브루트포스 차단 기록
grep "Ban\|Unban" /var/log/fail2ban.log

# 차단된 IP 목록
grep "Ban " /var/log/fail2ban.log | awk '{print $NF}' | sort | uniq -c | sort -rn

# 현재 차단 상태
fail2ban-client status sshd
```

---

## 11. Blue Team 기본 네트워크 도구

### ping / tracert / pathping
```bash
# 기본 연결 확인
ping -c 4 192.168.1.1              # Linux
ping 192.168.1.1                   # Windows

# 경로 추적
traceroute 8.8.8.8                 # Linux
tracert 8.8.8.8                    # Windows

# traceroute + 통계 결합 (Windows)
# pathping: 각 홉에서 패킷 손실률 통계 제공
pathping 8.8.8.8

# WinMTR: traceroute + ping 실시간 통합
# → 경로별 지연 및 패킷 손실 실시간 확인
```

### nslookup / DNS 분석
```bash
# 기본 쿼리
nslookup example.com
nslookup -querytype=mx example.com    # MX 레코드 (메일 서버)
nslookup -querytype=txt example.com   # TXT 레코드 (SPF, DMARC)
nslookup -querytype=ns example.com    # NS 레코드 (네임서버)

# 역방향 조회 (IP → 도메인)
nslookup 8.8.8.8

# dig (Linux 심화)
dig example.com ANY          # 모든 레코드
dig @8.8.8.8 example.com    # 특정 DNS 서버 조회
dig +trace example.com       # 재귀 추적
```

### NetStat 활용

netstat으로 활성 네트워크 연결과 대기 포트를 확인합니다. 비정상적인 외부 연결이나 알 수 없는 리스닝 포트를 탐지합니다.

```bash
# 활성 연결 목록
netstat -an        # 모든 연결 (숫자 표시)
netstat -antp      # TCP + PID 포함 (Linux)
netstat -ano       # Windows (PID 포함)

# 통계 정보 확인
netstat -s         # 프로토콜별 통계

# 포트가 열려있는지 확인
netstat -an | grep :80
netstat -an | grep LISTEN
```

---

## 12. CIS 컨트롤 v7 상위 6개 (Blue Team 필수)

### CIS Basic Controls — Top 6
```
1. 허가된 및 비허가된 장치 인벤토리 (Hardware Inventory)
   - 모든 하드웨어 자산 목록 유지
   - 비허가 장치 즉시 탐지 및 차단
   - 네트워크 스캐닝으로 알 수 없는 장치 식별
   - 도구: Nmap, 네트워크 접근 제어(NAC)

2. 허가된 및 비허가된 소프트웨어 인벤토리 (Software Inventory)
   - 모든 소프트웨어 목록 유지
   - 비허가 소프트웨어 실행 차단 (화이트리스트)
   - 도구: SCCM, Ansible, Puppet

3. 지속적인 취약점 평가 및 교정 (Vulnerability Management)
   - 정기 취약점 스캔 실행
   - CVSS 기반 우선순위 패치 적용
   - 도구: Nessus, OpenVAS, Nexpose

4. 관리자 권한의 통제된 사용 (Controlled Use of Admin Privileges)
   - 최소 권한 원칙 적용
   - 관리자 계정 일상 업무에 사용 금지
   - MFA 강제, 특권 접근 관리(PAM)

5. 모바일 장치, 노트북, 워크스테이션 하드웨어/소프트웨어 보안 설정 유지
   - CIS 벤치마크 기반 하드닝 적용
   - 기본 패스워드 변경, 불필요한 서비스 비활성화
   - 도구: CIS-CAT, Lynis

6. 감사 로그 유지, 모니터링, 분석
   - 모든 중요 시스템의 로그 수집
   - 중앙 집중식 로그 관리 (SIEM)
   - 로그 보존 기간 정책 수립 (최소 1년 권장)
   - 도구: Splunk, ELK Stack, Graylog
```

---

<a name="english"></a>

# Network Forensics — Packet Analysis and Incident Response

## 1. Network Forensics Overview

```
Network Forensics = Evidence collection and analysis from network traffic

Collection methods:
1. PCAP file analysis (pre-captured packets)
2. NetFlow/IPFIX analysis (summarized traffic data)
3. Firewall/IDS log analysis
4. DNS log analysis

Analysis objectives:
✔ Detect C&C server communication
✔ Detect data exfiltration
✔ Detect lateral movement
✔ Identify malicious domains/IPs
✔ Detect protocol anomalies
```

---

## 2. Wireshark Practical Analysis

### 2-1. Basic Filters

Wireshark filter expressions. Use display filters to show only packets matching specific conditions, enabling quick identification of traffic of interest in large captures.

```wireshark
# IP filters
ip.addr == 192.168.1.1          # All packets related to this IP
ip.src == 192.168.1.1           # Source IP
ip.dst == 10.0.0.1              # Destination IP
ip.addr == 192.168.1.0/24       # Subnet

# Port filters
tcp.port == 80                  # HTTP
tcp.port == 443                 # HTTPS
tcp.dstport == 4444             # Reverse shell port (suspicious)
udp.port == 53                  # DNS

# Protocol filters
http                            # HTTP
dns                             # DNS
ftp                             # FTP
ssh                             # SSH
smtp                            # Email
icmp                            # ICMP (ping)

# Combined filters
ip.src == 192.168.1.100 && tcp.dstport == 80
http.request.method == "POST"
http && ip.dst != 192.168.1.1   # External HTTP

# Packet content search
frame contains "password"
tcp contains "cmd.exe"
http.request.uri contains "/shell"
```

### 2-2. HTTP Analysis

```wireshark
# HTTP requests
http.request
http.request.method == "GET"
http.request.method == "POST"
http.request.uri contains "login"
http.request.uri contains ".php?cmd="   # Webshell suspected

# HTTP responses
http.response.code == 200
http.response.code == 404
http.response.code >= 400       # Error responses

# HTTP headers
http.user_agent contains "curl"        # Automation tools
http.user_agent contains "sqlmap"      # SQL Injection tools
http.cookie contains "PHPSESSID"

# File download reassembly
# File → Export Objects → HTTP → Save
```

### 2-3. DNS Analysis

```wireshark
# DNS queries
dns.flags.response == 0         # DNS requests only
dns.flags.response == 1         # DNS responses only
dns.qry.name contains ".onion"  # Tor domain
dns.qry.name matches ".*[0-9]{5,}.*"  # Suspicious domain (long numbers)

# DNS tunneling detection
dns.qry.name.len > 50          # Abnormally long domain
# DNS tunneling: data encoded in DNS query subdomains
# Example: aGVsbG8gd29ybGQ=.attacker.com (Base64 data)
```

### 2-4. Malicious Traffic Patterns

```wireshark
# Port scan detection (SYN scan)
tcp.flags.syn == 1 && tcp.flags.ack == 0 && ip.src == [scannerIP]

# Reverse shell (non-standard port connection)
tcp.dstport > 1024 && tcp.dstport < 65535 && !tcp.port == 443

# Large data exfiltration
# Statistics → Conversations → TCP → Sort by Bytes
# Check for abnormally large transfer volumes

# Beaconing (periodic C&C communication) detection
# Statistics → IO Graphs → Look for regular patterns
```

---

## 3. NetworkMiner Analysis

```
NetworkMiner = PCAP file parsing GUI tool

Main tabs:
Hosts       → All hosts participating in communication
Files       → Automatically extracted transferred files (HTTP, SMB, FTP)
Images      → Transferred image files
Messages    → Emails, chat
Credentials → Captured credentials (plaintext)
Sessions    → Session list
DNS         → DNS query list
```

---

## 4. tcpdump in Practice

```bash
# Basic capture
tcpdump -i eth0 -w capture.pcap

# Specific host
tcpdump -i eth0 host 192.168.1.1 -w capture.pcap

# Specific port
tcpdump -i eth0 port 80 -w capture.pcap
tcpdump -i eth0 'port 80 or port 443' -w capture.pcap

# Specific network
tcpdump -i eth0 net 192.168.1.0/24 -w capture.pcap

# File size/count limits
tcpdump -i eth0 -C 100 -W 10 -w capture.pcap  # 100MB rotating, 10 files

# Read PCAP
tcpdump -r capture.pcap
tcpdump -r capture.pcap -n -A  # ASCII output
tcpdump -r capture.pcap 'tcp port 80' | head -50
```

---

## 5. Indicator of Compromise (IOC) Analysis

### Network IOC Types
```
IP addresses (C&C servers, attackers)
Domains (malicious domains)
URLs (malicious URLs, phishing pages)
File hashes (malicious files)
User-Agent (malicious tool identifiers)
JA3 hash (TLS client fingerprint)
```

---

## 6. Zeek (Bro) Network Analysis

Zeek (formerly Bro) is a network analysis framework. It converts packets to structured logs, making it efficient for large-scale traffic analysis.

```bash
# Install
sudo apt install zeek

# Analyze PCAP
zeek -r capture.pcap

# Generated log files:
# conn.log    → All connections (source, destination, port, bytes)
# http.log    → HTTP requests/responses
# dns.log     → DNS queries
# ssl.log     → TLS/SSL sessions
# files.log   → Transferred files
# weird.log   → Abnormal protocol behavior

# Analyze conn.log
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p proto duration orig_bytes | sort -k7 -rn | head -20

# DNS query list
cat dns.log | zeek-cut query | sort | uniq -c | sort -rn | head -20

# HTTPS connections (JA3 fingerprint)
cat ssl.log | zeek-cut id.orig_h id.resp_h server_name ja3
```

---

## 7. Suricata IDS Rules

```bash
# Install
sudo apt install suricata

# Analyze PCAP
suricata -r capture.pcap -l output/

# Example rules:

# Reverse shell detection
alert tcp any any -> any 4444 (msg:"Suspicious Reverse Shell - Port 4444"; sid:100001;)

# Meterpreter traffic detection (Metasploit)
alert tcp any any -> any any (msg:"Meterpreter HTTPS"; 
  content:"METERPRETER"; nocase; sid:100002;)

# Webshell access detection
alert http any any -> any any (msg:"Webshell Access - cmd parameter";
  http.uri; content:"cmd="; nocase; sid:100003;)

# DNS tunneling detection
alert dns any any -> any any (msg:"Long DNS Query - Possible Tunneling";
  dns.query; dsize:>100; sid:100004;)

# Port scan detection (Threshold)
alert tcp any any -> $HOME_NET any (msg:"Port Scan Detected";
  flags:S; threshold: type both, track by_src, count 20, seconds 60;
  sid:100005;)
```

---

## 8. Email Forensics

### Email Header Analysis

```
From:       Sender (can be forged)
To:         Recipient
Subject:    Subject line
Date:       Sending time
Message-ID: Unique message ID
Received:   Mail server chain traversed (read in reverse → identify origin server)
X-Originating-IP: Actual sender IP (some servers)
DKIM-Signature: Domain signature
SPF:        Sender server verification
DMARC:      SPF/DKIM policy
```

```bash
# Email header analysis tools
# Google Admin Toolbox: https://toolbox.googleapps.com/apps/messageheader/
# MX Toolbox: https://mxtoolbox.com/EmailHeaders.aspx

# Spear phishing analysis checklist
□ Actual sender IP in Received header
□ Check if Reply-To differs from From
□ Link domain (display text vs actual URL)
□ Attachment hash → VirusTotal
□ Check for domain typosquatting
```

---

## 9. Real-world Scenario: APT Breach Investigation

### Step-by-Step Investigation

```
Step 1: Confirm Initial Access
- Spear phishing email logs
- Web server access logs (web exploits)
- VPN/RDP authentication failure logs

Step 2: Confirm Execution
- Abnormal process execution in Prefetch
- Event ID 4688 (process creation)
- PowerShell logs (4104) - encoded commands

Step 3: Confirm Persistence
- Registry Run keys
- Scheduled tasks
- Service creation (Event 7045)

Step 4: Confirm Lateral Movement
- Event ID 4624 Type 3 (network login)
- SMB traffic
- PsExec artifacts

Step 5: Confirm Exfiltration
- Large external transfers
- Cloud storage uploads
- DNS tunneling

Step 6: Confirm C&C Communication
- Periodic outbound connections
- Non-standard port usage
- TLS/SSL encrypted communication → JA3 fingerprint
```

---

## 10. Firewall/IDS Log Analysis

### Log Analysis Basics

```bash
# Apache access log analysis
# SQL Injection attempt detection
grep -E "UNION|SELECT|INSERT|DROP|OR%201=1" access.log

# Webshell access attempts
grep -E "cmd=|shell=|exec=|eval\(" access.log

# Scanner User-Agent
grep -Ei "nikto|nmap|masscan|sqlmap|acunetix|nessus" access.log

# Brute force (many requests from same IP)
awk '{print $1}' access.log | sort | uniq -c | sort -rn | head -20

# Multiple 404 errors (directory enumeration)
grep " 404 " access.log | awk '{print $1}' | sort | uniq -c | sort -rn | head -10

# Large response size (data exfiltration)
awk '{print $10, $7}' access.log | sort -rn | head -20

# Specific time period analysis
grep "01/Jan/2024:14:" access.log | wc -l
```

---

## 11. Blue Team Essential Network Tools

### ping / tracert / pathping
```bash
# Basic connectivity check
ping -c 4 192.168.1.1              # Linux
ping 192.168.1.1                   # Windows

# Route tracing
traceroute 8.8.8.8                 # Linux
tracert 8.8.8.8                    # Windows

# pathping: combined traceroute + statistics (Windows)
pathping 8.8.8.8
```

### nslookup / DNS Analysis
```bash
# Basic query
nslookup example.com
nslookup -querytype=mx example.com    # MX record (mail server)
nslookup -querytype=txt example.com   # TXT record (SPF, DMARC)
nslookup -querytype=ns example.com    # NS record (nameserver)

# Reverse lookup (IP → domain)
nslookup 8.8.8.8

# dig (Linux advanced)
dig example.com ANY          # All records
dig @8.8.8.8 example.com    # Query specific DNS server
dig +trace example.com       # Recursive trace
```

### NetStat Usage

```bash
# Active connection list
netstat -an        # All connections (numeric display)
netstat -antp      # TCP + PID included (Linux)
netstat -ano       # Windows (PID included)

# Protocol statistics
netstat -s

# Check if a port is open
netstat -an | grep :80
netstat -an | grep LISTEN
```

---

## 12. CIS Controls v7 Top 6 (Blue Team Essentials)

### CIS Basic Controls — Top 6
```
1. Inventory of Authorized and Unauthorized Devices (Hardware Inventory)
   - Maintain list of all hardware assets
   - Immediately detect and block unauthorized devices
   - Identify unknown devices through network scanning
   - Tools: Nmap, Network Access Control (NAC)

2. Inventory of Authorized and Unauthorized Software (Software Inventory)
   - Maintain list of all software
   - Block execution of unauthorized software (whitelisting)
   - Tools: SCCM, Ansible, Puppet

3. Continuous Vulnerability Assessment and Remediation (Vulnerability Management)
   - Run regular vulnerability scans
   - Apply CVSS-based priority patching
   - Tools: Nessus, OpenVAS, Nexpose

4. Controlled Use of Administrative Privileges
   - Apply principle of least privilege
   - Do not use admin accounts for daily tasks
   - Enforce MFA, Privileged Access Management (PAM)

5. Secure Configuration for Hardware and Software on Mobile Devices, Laptops, Workstations
   - Apply CIS benchmark-based hardening
   - Change default passwords, disable unnecessary services
   - Tools: CIS-CAT, Lynis

6. Maintenance, Monitoring and Analysis of Audit Logs
   - Collect logs from all critical systems
   - Centralized log management (SIEM)
   - Establish log retention policy (minimum 1 year recommended)
   - Tools: Splunk, ELK Stack, Graylog
```
