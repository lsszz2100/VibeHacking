> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# Python 보안 자동화 — Scapy·requests·paramiko·자동화 도구

## 0. 초보자를 위한 개념 이해

### Python 보안 자동화란?

Python은 보안 엔지니어의 스위스 아미 나이프입니다. 네트워크 패킷 조작(Scapy), HTTP 자동화(requests), SSH 원격 실행(paramiko), 취약점 스캐닝 자동화까지 단일 언어로 처리할 수 있습니다.

**왜 배우는가:**
```
보안 자동화의 필요성:

  수동 테스트의 한계:
  → 1000개 서버에 수동으로 SSH → 불가능
  → 매일 새로운 CVE 패치 상태 확인 → 사람이 할 수 없음

  자동화의 효과:
  [수동] nmap → wireshark → 분석 → 보고서 → 3시간
  [자동화] scan.py → 결과 파싱 → Slack 알림 → 5분

  핵심 라이브러리:
    Scapy     → 패킷 생성/캡처/분석
    requests  → HTTP/HTTPS 자동화, API 연동
    paramiko  → SSH 원격 명령 실행
    nmap      → python-nmap으로 포트 스캔 자동화
    shodan    → Shodan API로 인터넷 자산 발견
```

### 핵심 개념 정리

```
Python 보안 라이브러리 생태계:

  네트워크 계층:
    Scapy       → L2~L7 패킷 완전 제어
    socket      → 기본 TCP/UDP 소켓
    python-nmap → nmap 결과 파이썬 객체화

  HTTP/웹 계층:
    requests         → 동기 HTTP 클라이언트
    httpx            → 비동기 HTTP, HTTP/2 지원
    beautifulsoup4   → HTML 파싱
    playwright       → 헤드리스 브라우저 자동화

  시스템/원격:
    paramiko    → SSH 클라이언트/서버
    subprocess  → 로컬 시스템 명령 실행
    fabric      → paramiko 기반 고수준 SSH

  분석:
    python-magic  → 파일 타입 감지
    yara-python   → 악성코드 시그니처 매칭
    volatility3   → 메모리 포렌식
```

### 필요한 도구 및 환경

```bash
# 보안 자동화 환경 설정
python3 -m venv security-env
source security-env/bin/activate

pip install scapy requests paramiko python-nmap httpx \
            beautifulsoup4 yara-python shodan

# Scapy는 패킷 조작을 위해 root 권한 또는 CAP_NET_RAW 필요
sudo setcap cap_net_raw=eip $(which python3)
```

---

## 1. Scapy — 패킷 수준 보안 자동화

### 1.1 Scapy 기초 패킷 조작

```python
#!/usr/bin/env python3
"""
Scapy 기반 네트워크 패킷 조작 기초.
실습 환경(허가된 네트워크)에서만 사용.
참고: https://scapy.readthedocs.io/en/latest/
"""
from scapy.all import (
    IP, TCP, UDP, ICMP, ARP, Ether,
    send, sendp, sr1, srp, sniff,
    wrpcap, rdpcap, ls, conf
)
from scapy.layers.http import HTTPRequest, HTTPResponse
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)


def icmp_ping(target: str, timeout: int = 2) -> bool:
    """ICMP echo 핑 전송 후 응답 여부 반환."""
    pkt = IP(dst=target) / ICMP()
    response = sr1(pkt, timeout=timeout, verbose=False)
    if response:
        log.info("Host %s is alive (TTL=%d)", target, response.ttl)
        return True
    log.info("Host %s did not respond", target)
    return False


def tcp_syn_scan(target: str, ports: list[int], timeout: int = 1) -> dict[int, str]:
    """
    SYN 스캔으로 포트 상태 확인.
    열린 포트 → SYN-ACK 응답, 닫힌 포트 → RST 응답.
    """
    results: dict[int, str] = {}
    for port in ports:
        pkt = IP(dst=target) / TCP(dport=port, flags="S")
        resp = sr1(pkt, timeout=timeout, verbose=False)
        if resp is None:
            results[port] = "filtered"
        elif resp.haslayer(TCP):
            if resp[TCP].flags == 0x12:  # SYN-ACK
                # RST 전송하여 연결 완료 방지
                send(IP(dst=target) / TCP(dport=port, flags="R"), verbose=False)
                results[port] = "open"
            elif resp[TCP].flags == 0x14:  # RST-ACK
                results[port] = "closed"
        else:
            results[port] = "unknown"
    return results


def arp_scan(network: str) -> list[dict[str, str]]:
    """
    ARP 스캔으로 로컬 네트워크 호스트 발견.
    예: network="192.168.1.0/24"
    """
    arp_req = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network)
    answered, _ = srp(arp_req, timeout=2, verbose=False)
    hosts = []
    for sent_pkt, recv_pkt in answered:
        hosts.append({
            "ip": recv_pkt[ARP].psrc,
            "mac": recv_pkt[ARP].hwsrc,
        })
        log.info("Found: %s → %s", recv_pkt[ARP].psrc, recv_pkt[ARP].hwsrc)
    return hosts


def capture_http_requests(interface: str = "eth0", count: int = 10) -> None:
    """HTTP 요청 패킷 캡처 및 URL 출력."""

    def process_packet(pkt: object) -> None:
        if pkt.haslayer(HTTPRequest):
            host = pkt[HTTPRequest].Host.decode(errors="replace")
            path = pkt[HTTPRequest].Path.decode(errors="replace")
            method = pkt[HTTPRequest].Method.decode(errors="replace")
            log.info("[HTTP] %s http://%s%s", method, host, path)

    log.info("Capturing %d HTTP packets on %s...", count, interface)
    sniff(iface=interface, filter="tcp port 80", prn=process_packet, count=count)


def detect_arp_spoofing(interface: str = "eth0", packet_count: int = 100) -> None:
    """ARP 스푸핑 감지: 동일 IP에 대해 다른 MAC이 응답하면 경고."""
    arp_table: dict[str, str] = {}

    def check_arp(pkt: object) -> None:
        if pkt.haslayer(ARP) and pkt[ARP].op == 2:  # ARP reply
            ip = pkt[ARP].psrc
            mac = pkt[ARP].hwsrc
            if ip in arp_table and arp_table[ip] != mac:
                log.warning(
                    "[ARP SPOOFING DETECTED] IP %s: was %s, now %s",
                    ip, arp_table[ip], mac
                )
            else:
                arp_table[ip] = mac

    sniff(iface=interface, filter="arp", prn=check_arp, count=packet_count)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Scapy 보안 자동화 도구")
    subparsers = parser.add_subparsers(dest="command")

    ping_p = subparsers.add_parser("ping", help="ICMP 핑")
    ping_p.add_argument("target", help="대상 IP")

    scan_p = subparsers.add_parser("scan", help="TCP SYN 스캔")
    scan_p.add_argument("target", help="대상 IP")
    scan_p.add_argument("--ports", nargs="+", type=int, default=[22, 80, 443, 8080])

    arp_p = subparsers.add_parser("arp", help="ARP 스캔")
    arp_p.add_argument("network", help="CIDR 네트워크 (예: 192.168.1.0/24)")

    args = parser.parse_args()

    if args.command == "ping":
        icmp_ping(args.target)
    elif args.command == "scan":
        results = tcp_syn_scan(args.target, args.ports)
        for port, state in results.items():
            print(f"  {port}/tcp  {state}")
    elif args.command == "arp":
        hosts = arp_scan(args.network)
        print(f"발견된 호스트: {len(hosts)}개")
```

### 1.2 고급 패킷 분석 — PCAP 파싱

```python
#!/usr/bin/env python3
"""
PCAP 파일 분석 및 보안 이벤트 추출.
Wireshark 없이 Python으로 패킷 파일 분석.
"""
from __future__ import annotations

import hashlib
from collections import Counter
from pathlib import Path

from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR
from scapy.layers.http import HTTPRequest


def analyze_pcap(pcap_path: str) -> dict:
    """PCAP 파일에서 보안 관련 통계 추출."""
    path = Path(pcap_path)
    if not path.exists():
        raise FileNotFoundError(f"PCAP 파일 없음: {pcap_path}")

    packets = rdpcap(str(path))
    stats: dict = {
        "total_packets": len(packets),
        "ip_conversations": Counter(),
        "dns_queries": [],
        "http_requests": [],
        "suspicious_ports": [],
    }

    known_malware_ports = {4444, 1337, 31337, 6666, 6667}

    for pkt in packets:
        # IP 대화 쌍 집계
        if pkt.haslayer(IP):
            pair = tuple(sorted([pkt[IP].src, pkt[IP].dst]))
            stats["ip_conversations"][pair] += 1

            # 의심 포트 감지
            if pkt.haslayer(TCP):
                dport = pkt[TCP].dport
                sport = pkt[TCP].sport
                if dport in known_malware_ports or sport in known_malware_ports:
                    stats["suspicious_ports"].append({
                        "src": pkt[IP].src,
                        "dst": pkt[IP].dst,
                        "port": dport if dport in known_malware_ports else sport,
                    })

        # DNS 쿼리 추출
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            query = pkt[DNSQR].qname.decode(errors="replace").rstrip(".")
            stats["dns_queries"].append(query)

        # HTTP 요청 추출
        if pkt.haslayer(HTTPRequest):
            host = pkt[HTTPRequest].Host.decode(errors="replace")
            path_val = pkt[HTTPRequest].Path.decode(errors="replace")
            stats["http_requests"].append(f"http://{host}{path_val}")

    return stats


def extract_files_from_pcap(pcap_path: str, output_dir: str = "/tmp/extracted") -> list[str]:
    """PCAP에서 HTTP를 통해 전송된 파일 복원 (기초 구현)."""
    import os
    os.makedirs(output_dir, exist_ok=True)

    packets = rdpcap(pcap_path)
    extracted: list[str] = []
    buffer: dict[tuple, bytes] = {}

    for pkt in packets:
        if pkt.haslayer(TCP) and pkt.haslayer(IP):
            key = (pkt[IP].src, pkt[IP].dst, pkt[TCP].sport, pkt[TCP].dport)
            if bytes(pkt[TCP].payload):
                buffer[key] = buffer.get(key, b"") + bytes(pkt[TCP].payload)

    for key, data in buffer.items():
        if b"\r\n\r\n" in data and len(data) > 100:
            _, body = data.split(b"\r\n\r\n", 1)
            if body:
                file_hash = hashlib.md5(body).hexdigest()[:8]
                out_path = f"{output_dir}/{file_hash}.bin"
                Path(out_path).write_bytes(body)
                extracted.append(out_path)

    return extracted
```

---

## 2. requests — HTTP 보안 자동화

### 2.1 웹 취약점 자동화 스캐너

```python
#!/usr/bin/env python3
"""
requests 기반 웹 보안 자동화 스캐너.
허가된 대상에만 사용할 것.
참고: https://requests.readthedocs.io/en/latest/
"""
from __future__ import annotations

import time
import argparse
import logging
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin, urlparse

import requests
from requests import Session, Response
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)


@dataclass
class ScanResult:
    url: str
    vulnerability: str
    severity: str
    details: str
    evidence: str = ""


def create_session(timeout: int = 10, max_retries: int = 3) -> Session:
    """재시도 로직을 갖춘 requests 세션 생성."""
    session = Session()
    retry = Retry(total=max_retries, backoff_factor=0.5,
                  status_forcelist=[500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update({
        "User-Agent": "SecurityScanner/1.0 (Authorized Testing)"
    })
    return session


def check_security_headers(url: str, session: Optional[Session] = None) -> list[ScanResult]:
    """HTTP 보안 헤더 누락 감지."""
    if session is None:
        session = create_session()

    results: list[ScanResult] = []
    required_headers = {
        "Strict-Transport-Security": "HSTS 헤더 누락 — HTTPS 다운그레이드 공격 가능",
        "X-Content-Type-Options": "X-Content-Type-Options 누락 — MIME 스니핑 공격 가능",
        "X-Frame-Options": "X-Frame-Options 누락 — Clickjacking 공격 가능",
        "Content-Security-Policy": "CSP 헤더 누락 — XSS 위험 증가",
        "Permissions-Policy": "Permissions-Policy 누락 — 브라우저 기능 남용 가능",
    }

    try:
        resp = session.get(url, timeout=10, verify=False)
        for header, message in required_headers.items():
            if header.lower() not in {k.lower() for k in resp.headers}:
                results.append(ScanResult(
                    url=url,
                    vulnerability="Missing Security Header",
                    severity="Medium",
                    details=message,
                    evidence=f"Header '{header}' not present",
                ))
        log.info("Security header check complete: %d issues found", len(results))
    except requests.RequestException as exc:
        log.error("Request failed for %s: %s", url, exc)

    return results


def check_sql_injection(
    url: str,
    params: dict[str, str],
    session: Optional[Session] = None,
) -> list[ScanResult]:
    """
    기본 SQL 인젝션 감지 — 에러 기반.
    실제 페이로드가 아닌 에러 메시지 유무로 판단.
    """
    if session is None:
        session = create_session()

    results: list[ScanResult] = []
    # 기본적인 SQL 에러 유발 테스트 페이로드 (에러 감지용)
    test_payloads = ["'", "''", "`", "1'1", "1 OR 1=1--"]
    error_signatures = [
        "sql syntax", "mysql_fetch", "ora-01756", "sqlite_step",
        "pg_query", "syntax error", "unclosed quotation",
    ]

    for param_name in params:
        for payload in test_payloads:
            test_params = {**params, param_name: payload}
            try:
                resp = session.get(url, params=test_params, timeout=10)
                body_lower = resp.text.lower()
                for sig in error_signatures:
                    if sig in body_lower:
                        results.append(ScanResult(
                            url=url,
                            vulnerability="SQL Injection (Error-based)",
                            severity="Critical",
                            details=f"파라미터 '{param_name}'에 SQL 에러 응답",
                            evidence=f"Payload: {payload!r}, Signature: {sig!r}",
                        ))
                        break
                time.sleep(0.1)  # 요청 속도 제한
            except requests.RequestException as exc:
                log.debug("Request error for payload %r: %s", payload, exc)

    return results


def directory_bruteforce(
    base_url: str,
    wordlist: list[str],
    session: Optional[Session] = None,
    delay: float = 0.05,
) -> list[dict[str, object]]:
    """디렉터리/파일 존재 여부 브루트포스 확인."""
    if session is None:
        session = create_session()

    found: list[dict[str, object]] = []
    for path in wordlist:
        url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
        try:
            resp = session.get(url, timeout=5, allow_redirects=False)
            if resp.status_code in {200, 301, 302, 403}:
                log.info("[%d] %s", resp.status_code, url)
                found.append({"url": url, "status": resp.status_code,
                               "length": len(resp.content)})
            time.sleep(delay)
        except requests.RequestException:
            pass

    return found


def check_open_redirect(url: str, param: str, session: Optional[Session] = None) -> bool:
    """오픈 리다이렉트 취약점 감지."""
    if session is None:
        session = create_session()

    test_url = f"https://evil.example.com"
    test_full_url = f"{url}?{param}={test_url}"
    try:
        resp = session.get(test_full_url, timeout=10, allow_redirects=False)
        location = resp.headers.get("Location", "")
        if "evil.example.com" in location:
            log.warning("[OPEN REDIRECT] %s → %s", test_full_url, location)
            return True
    except requests.RequestException as exc:
        log.debug("Open redirect check error: %s", exc)
    return False


def main() -> None:
    parser = argparse.ArgumentParser(description="HTTP 보안 자동화 스캐너")
    parser.add_argument("url", help="스캔 대상 URL")
    parser.add_argument("--headers", action="store_true", help="보안 헤더 검사")
    parser.add_argument("--sqli", action="store_true", help="SQL 인젝션 검사")
    parser.add_argument("--param", nargs="+", help="SQLi 테스트 파라미터 (name=value)")
    args = parser.parse_args()

    session = create_session()

    if args.headers:
        results = check_security_headers(args.url, session)
        for r in results:
            print(f"[{r.severity}] {r.vulnerability}: {r.details}")

    if args.sqli and args.param:
        params = dict(p.split("=", 1) for p in args.param)
        results = check_sql_injection(args.url, params, session)
        for r in results:
            print(f"[{r.severity}] {r.vulnerability}: {r.evidence}")


if __name__ == "__main__":
    main()
```

---

## 3. paramiko — SSH 원격 보안 자동화

### 3.1 SSH 감사 자동화

```python
#!/usr/bin/env python3
"""
paramiko 기반 SSH 원격 보안 감사 자동화.
허가된 서버에만 사용. SSH 키 기반 인증 권장.
참고: https://www.paramiko.org/
"""
from __future__ import annotations

import argparse
import io
import logging
from dataclasses import dataclass, field
from typing import Optional

import paramiko

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)


@dataclass
class AuditFinding:
    host: str
    check: str
    severity: str
    current_value: str
    recommended: str
    remediation: str


class SSHSecurityAuditor:
    """SSH를 통한 Linux 서버 보안 감사."""

    def __init__(self, host: str, port: int = 22,
                 username: str = "", key_path: str = "") -> None:
        self.host = host
        self.port = port
        self.username = username
        self.key_path = key_path
        self._client: Optional[paramiko.SSHClient] = None

    def connect(self) -> None:
        """SSH 연결 (키 기반 인증 우선)."""
        self._client = paramiko.SSHClient()
        self._client.set_missing_host_key_policy(paramiko.RejectPolicy())

        if self.key_path:
            key = paramiko.RSAKey.from_private_key_file(self.key_path)
            self._client.connect(
                self.host, port=self.port,
                username=self.username, pkey=key,
                timeout=10
            )
        else:
            raise ValueError("SSH 키 경로를 제공해야 합니다 (패스워드 인증 비권장)")

        log.info("Connected to %s:%d", self.host, self.port)

    def run(self, command: str) -> tuple[str, str, int]:
        """원격 명령 실행 → (stdout, stderr, exit_code) 반환."""
        if not self._client:
            raise RuntimeError("연결되지 않음. connect() 먼저 호출")
        _, stdout, stderr = self._client.exec_command(command, timeout=30)
        exit_code = stdout.channel.recv_exit_status()
        return (
            stdout.read().decode(errors="replace").strip(),
            stderr.read().decode(errors="replace").strip(),
            exit_code,
        )

    def audit_ssh_config(self) -> list[AuditFinding]:
        """SSH 서버 설정 보안 감사."""
        findings: list[AuditFinding] = []

        checks = [
            ("PermitRootLogin", "no",
             "Root 직접 로그인 허용",
             "Critical",
             "PermitRootLogin no 설정 후 sshd 재시작"),
            ("PasswordAuthentication", "no",
             "SSH 패스워드 인증 허용",
             "High",
             "PasswordAuthentication no 설정 (키 인증으로 전환 후)"),
            ("X11Forwarding", "no",
             "X11 포워딩 활성화",
             "Medium",
             "X11Forwarding no 설정"),
            ("MaxAuthTries", "3",
             "과도한 인증 시도 허용",
             "Medium",
             "MaxAuthTries 3 이하로 설정"),
            ("Protocol", "2",
             "SSH Protocol 버전",
             "High",
             "Protocol 2 설정 (SSH v1 사용 금지)"),
        ]

        stdout, _, _ = self.run("cat /etc/ssh/sshd_config 2>/dev/null || echo 'NOT_FOUND'")

        for directive, safe_value, description, severity, remediation in checks:
            current = "not set"
            for line in stdout.splitlines():
                line = line.strip()
                if line.startswith(directive + " ") and not line.startswith("#"):
                    current = line.split()[1]
                    break

            if current.lower() != safe_value.lower() and current != "not set":
                findings.append(AuditFinding(
                    host=self.host,
                    check=f"sshd_config: {directive}",
                    severity=severity,
                    current_value=current,
                    recommended=safe_value,
                    remediation=remediation,
                ))
            elif current == "not set":
                findings.append(AuditFinding(
                    host=self.host,
                    check=f"sshd_config: {directive}",
                    severity=severity,
                    current_value="(기본값 사용)",
                    recommended=safe_value,
                    remediation=f"{directive} {safe_value} 명시적 설정 권장",
                ))

        return findings

    def audit_users(self) -> list[AuditFinding]:
        """사용자 계정 보안 감사."""
        findings: list[AuditFinding] = []

        # UID 0을 가진 계정 (root 외)
        stdout, _, _ = self.run("awk -F: '$3==0{print $1}' /etc/passwd")
        uid0_users = [u for u in stdout.splitlines() if u and u != "root"]
        if uid0_users:
            findings.append(AuditFinding(
                host=self.host,
                check="UID 0 계정",
                severity="Critical",
                current_value=", ".join(uid0_users),
                recommended="root 만 UID 0 보유",
                remediation="해당 계정 UID 수정 또는 삭제",
            ))

        # 빈 패스워드 계정
        stdout, _, _ = self.run("awk -F: '($2==\"\" || $2==\"!\"){print $1}' /etc/shadow 2>/dev/null")
        empty_pw = [u for u in stdout.splitlines() if u]
        if empty_pw:
            findings.append(AuditFinding(
                host=self.host,
                check="빈 패스워드 계정",
                severity="Critical",
                current_value=", ".join(empty_pw),
                recommended="모든 계정 패스워드 설정",
                remediation="passwd <username>으로 패스워드 설정",
            ))

        return findings

    def audit_open_ports(self) -> list[dict[str, str]]:
        """개방된 포트 및 서비스 목록 조회."""
        stdout, _, _ = self.run("ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null")
        ports: list[dict[str, str]] = []
        for line in stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 4:
                ports.append({"state": parts[0], "local": parts[3]})
        return ports

    def close(self) -> None:
        if self._client:
            self._client.close()
            log.info("Connection to %s closed", self.host)

    def __enter__(self) -> "SSHSecurityAuditor":
        self.connect()
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


def batch_audit(
    hosts: list[str],
    username: str,
    key_path: str,
    port: int = 22,
) -> dict[str, list[AuditFinding]]:
    """여러 호스트 일괄 감사."""
    all_findings: dict[str, list[AuditFinding]] = {}
    for host in hosts:
        log.info("Auditing %s...", host)
        try:
            with SSHSecurityAuditor(host, port, username, key_path) as auditor:
                findings = auditor.audit_ssh_config() + auditor.audit_users()
                all_findings[host] = findings
                log.info("  → %d findings", len(findings))
        except Exception as exc:
            log.error("Failed to audit %s: %s", host, exc)
            all_findings[host] = []
    return all_findings


def main() -> None:
    parser = argparse.ArgumentParser(description="SSH 보안 감사 자동화")
    parser.add_argument("host", help="대상 호스트 또는 쉼표 구분 목록")
    parser.add_argument("-u", "--user", required=True, help="SSH 사용자명")
    parser.add_argument("-k", "--key", required=True, help="SSH 개인키 경로")
    parser.add_argument("-p", "--port", type=int, default=22, help="SSH 포트")
    args = parser.parse_args()

    hosts = [h.strip() for h in args.host.split(",")]
    results = batch_audit(hosts, args.user, args.key, args.port)

    for host, findings in results.items():
        print(f"\n{'='*60}")
        print(f"호스트: {host} — 발견 사항 {len(findings)}개")
        print('='*60)
        for f in findings:
            print(f"  [{f.severity}] {f.check}")
            print(f"    현재값: {f.current_value}")
            print(f"    권장값: {f.recommended}")
            print(f"    조치:   {f.remediation}")


if __name__ == "__main__":
    main()
```

---

## 4. 종합 보안 자동화 파이프라인

### 4.1 자산 발견 → 스캔 → 보고 파이프라인

```python
#!/usr/bin/env python3
"""
통합 보안 자동화 파이프라인:
  1. ARP/nmap으로 자산 발견
  2. 웹 서비스 보안 헤더 검사
  3. SSH 감사 (키 파일 있는 경우)
  4. JSON 보고서 출력
"""
from __future__ import annotations

import json
import logging
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)


def nmap_scan(target: str) -> dict[str, Any]:
    """nmap XML 출력 파싱으로 열린 포트 목록 반환."""
    try:
        result = subprocess.run(
            ["nmap", "-sV", "-oX", "-", "--open", target],
            capture_output=True, text=True, timeout=120, check=False
        )
        # 간단한 파싱: 실제로는 python-nmap 또는 xml.etree 사용 권장
        open_ports: list[int] = []
        for line in result.stdout.splitlines():
            if 'portid=' in line and 'state="open"' in line:
                import re
                m = re.search(r'portid="(\d+)"', line)
                if m:
                    open_ports.append(int(m.group(1)))
        return {"target": target, "open_ports": open_ports}
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        log.error("nmap failed for %s: %s", target, exc)
        return {"target": target, "open_ports": [], "error": str(exc)}


def check_web_services(host: str, ports: list[int]) -> list[dict[str, Any]]:
    """HTTP/HTTPS 서비스 보안 헤더 일괄 검사."""
    issues: list[dict[str, Any]] = []
    web_ports = {p for p in ports if p in {80, 443, 8080, 8443, 8888, 3000}}

    for port in web_ports:
        scheme = "https" if port in {443, 8443} else "http"
        url = f"{scheme}://{host}:{port}/"
        try:
            resp = requests.get(url, timeout=5, verify=False)
            missing = []
            for h in ["Strict-Transport-Security", "X-Content-Type-Options",
                       "X-Frame-Options", "Content-Security-Policy"]:
                if h.lower() not in {k.lower() for k in resp.headers}:
                    missing.append(h)
            if missing:
                issues.append({"url": url, "missing_headers": missing})
        except requests.RequestException:
            pass

    return issues


def generate_report(findings: list[dict[str, Any]], output_path: str = "") -> str:
    """JSON 형식 보안 보고서 생성."""
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_hosts": len(findings),
        "total_issues": sum(len(f.get("issues", [])) for f in findings),
        "findings": findings,
    }
    report_json = json.dumps(report, ensure_ascii=False, indent=2)

    if output_path:
        Path(output_path).write_text(report_json, encoding="utf-8")
        log.info("보고서 저장: %s", output_path)

    return report_json


def run_pipeline(targets: list[str], output: str = "security_report.json") -> None:
    """전체 파이프라인 실행."""
    all_findings: list[dict[str, Any]] = []

    for target in targets:
        log.info("Scanning target: %s", target)
        scan_result = nmap_scan(target)
        web_issues = check_web_services(target, scan_result.get("open_ports", []))

        all_findings.append({
            "host": target,
            "open_ports": scan_result.get("open_ports", []),
            "issues": web_issues,
        })

    report = generate_report(all_findings, output)
    print(report)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="통합 보안 자동화 파이프라인")
    parser.add_argument("targets", nargs="+", help="스캔 대상 IP/호스트명")
    parser.add_argument("-o", "--output", default="security_report.json", help="보고서 저장 경로")
    args = parser.parse_args()
    run_pipeline(args.targets, args.output)
```

---

## 5. YARA 기반 악성코드 자동 탐지

```python
#!/usr/bin/env python3
"""
yara-python을 이용한 악성코드 시그니처 탐지 자동화.
참고: https://yara.readthedocs.io/en/stable/
"""
from __future__ import annotations

import argparse
import logging
from pathlib import Path
from typing import Optional

try:
    import yara
except ImportError:
    print("pip install yara-python 필요")
    raise

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

SAMPLE_YARA_RULES = """
rule Webshell_PHP_Basic {
    meta:
        description = "PHP 웹쉘 기본 시그니처"
        severity = "HIGH"
    strings:
        $cmd1 = "eval(base64_decode" ascii nocase
        $cmd2 = "system($_" ascii
        $cmd3 = "passthru($_" ascii
        $cmd4 = "shell_exec($_" ascii
        $cmd5 = "assert($_" ascii
    condition:
        any of them
}

rule Suspicious_PowerShell {
    meta:
        description = "PowerShell 다운로더 패턴"
        severity = "HIGH"
    strings:
        $ps1 = "Invoke-Expression" ascii nocase
        $ps2 = "DownloadString" ascii nocase
        $ps3 = "-EncodedCommand" ascii nocase
        $combo = "IEX" ascii
    condition:
        2 of them
}
"""


def compile_rules(rule_source: str) -> yara.Rules:
    """YARA 룰 컴파일."""
    return yara.compile(source=rule_source)


def scan_file(file_path: str, rules: yara.Rules) -> list[dict]:
    """단일 파일 YARA 스캔."""
    matches = rules.match(file_path)
    results = []
    for match in matches:
        results.append({
            "file": file_path,
            "rule": match.rule,
            "tags": list(match.tags),
            "strings": [(hex(s.offset), s.identifier, s.plaintext().decode(errors="replace")[:50])
                        for s in match.strings],
        })
    return results


def scan_directory(
    directory: str,
    rules: yara.Rules,
    extensions: Optional[list[str]] = None,
) -> list[dict]:
    """디렉터리 재귀 스캔."""
    if extensions is None:
        extensions = [".php", ".asp", ".aspx", ".jsp", ".py", ".sh", ".ps1"]

    all_matches: list[dict] = []
    base_path = Path(directory)

    for file_path in base_path.rglob("*"):
        if file_path.is_file() and file_path.suffix.lower() in extensions:
            try:
                matches = scan_file(str(file_path), rules)
                if matches:
                    log.warning("[MATCH] %s → %d rules matched",
                                file_path, len(matches))
                    all_matches.extend(matches)
            except yara.Error as exc:
                log.debug("YARA error on %s: %s", file_path, exc)

    log.info("Scan complete: %d files scanned, %d matches",
             sum(1 for _ in base_path.rglob("*") if _.is_file()), len(all_matches))
    return all_matches


def main() -> None:
    parser = argparse.ArgumentParser(description="YARA 악성코드 스캐너")
    parser.add_argument("path", help="스캔 대상 파일 또는 디렉터리")
    parser.add_argument("--rules", help="YARA 룰 파일 경로 (기본: 내장 룰)")
    args = parser.parse_args()

    if args.rules:
        rules = yara.compile(filepath=args.rules)
    else:
        rules = compile_rules(SAMPLE_YARA_RULES)

    target = Path(args.path)
    if target.is_dir():
        results = scan_directory(str(target), rules)
    else:
        results = scan_file(str(target), rules)

    for r in results:
        print(f"\n[ALERT] Rule: {r['rule']}")
        print(f"  File: {r['file']}")
        for offset, identifier, text in r["strings"]:
            print(f"  Match @ {offset}: {identifier} → {text!r}")


if __name__ == "__main__":
    main()
```

---

## 6. 참고 자료

- **Scapy 공식 문서**: https://scapy.readthedocs.io/en/latest/
- **paramiko 공식 문서**: https://www.paramiko.org/
- **YARA 공식 문서**: https://yara.readthedocs.io/en/stable/
- **requests 공식 문서**: https://requests.readthedocs.io/en/latest/

---

<!-- detect-validate-08 -->
## 자동화 공격 탐지와 방어 검증

scapy·paramiko·nmap 오케스트레이션은 작업을 대량 자동화하지만, 자동화가 *실행됨*과 *안전·정확하게 동작함*은 다르다. 작성자는 **자동화가 어떤 통제에 걸리는가**와 **드라이런·결과검증 게이트가 있는가**를 확인해야 한다.

### 공격 기법 → 계층 → 통제 → 탐지 신호

| 공격 기법 | 계층 | 통제 | 탐지 신호 |
|---|---|---|---|
| scapy 패킷 주입/스푸핑 | 네트워크 | 무결성·이상탐지, RPF | spoofed src, 비정상 패킷 |
| paramiko 대량 SSH | 접근 | 키 기반, fail2ban | 비대화형 SSH 버스트 |
| nmap 자동 스캔 | 네트워크 | IDS | 스캔 시그니처 |
| 스케줄/오케스트레이션 | 호스트 | 실행 모니터 | 비정상 cron/프로세스 트리 |

### 방어 검증 (직접 확인)

```bash
# 소유/허가 자산만 대상으로, 드라이런과 결과검증 게이트를 거쳐 실행(부작용·오작동 방지)
arp -a > before.txt   # scapy 스푸핑 전후 ARP 테이블 비교(소유 랩)
sudo fail2ban-client status sshd 2>/dev/null | grep -i banned   # paramiko 버스트가 차단되는지
# 자동화 멱등성/안전성: 두 번 실행해 부작용이 누적되지 않는지(같은 결과) 확인
diff <(sort run1.out) <(sort run2.out) && echo "idempotent"
```

> 자동화는 **소유/허가된 자산**만 대상으로 한다. 자동화가 "실행됨"과 "안전·정확하게 동작함"은 다르므로 드라이런·멱등성·결과검증 게이트를 두고, 스푸핑·SSH 버스트·스캔의 탐지 footprint도 확인해야 한다([[02_Network_Hacking]], [[20_Shell_Scripting]], [[68_Purple_Team]]).

---

<a name="english"></a>

# Python Security Automation — Scapy, requests, paramiko, Automation Tools

## Overview

Python is the Swiss Army knife for security engineers. With Scapy for packet manipulation, requests for HTTP automation, paramiko for SSH remote execution, and yara-python for malware detection, nearly all security automation tasks can be handled in a single language.

## Key Libraries

| Library | Layer | Primary Use |
|---------|-------|-------------|
| Scapy | L2–L7 | Packet crafting, capture, ARP scanning |
| requests / httpx | HTTP | Web vulnerability scanning, API interaction |
| paramiko | SSH | Remote command execution, server auditing |
| yara-python | File | Malware signature matching |
| python-nmap | Network | Port scan automation |

## Core Concepts

### Scapy Packet Flow
```
craft packet (IP/TCP/...) → send → receive response → parse layers
```

### paramiko Authentication Model
Always prefer key-based authentication over password authentication. Load private keys with `paramiko.RSAKey.from_private_key_file()` and use `RejectPolicy` to prevent MITM attacks.

### Security Automation Pipeline
```
Asset Discovery (ARP/nmap)
        ↓
Service Enumeration (open ports, banners)
        ↓
Vulnerability Checks (headers, SQLi patterns, config audit)
        ↓
Report Generation (JSON/HTML output)
        ↓
Alerting (Slack, email, SIEM)
```

## Quick Start

```bash
# Install dependencies
pip install scapy requests paramiko yara-python python-nmap

# SYN scan a host
sudo python3 scapy_tools.py scan 192.168.1.1 --ports 22 80 443 8080

# Audit SSH server security
python3 ssh_auditor.py 192.168.1.10 -u admin -k ~/.ssh/id_rsa

# Run full pipeline
python3 pipeline.py 192.168.1.0/24 -o report.json
```

## References

- Scapy documentation: https://scapy.readthedocs.io/en/latest/
- paramiko documentation: https://www.paramiko.org/
- YARA documentation: https://yara.readthedocs.io/en/stable/

<!-- detect-validate-08 -->
## Automation Attack Detection and Defense Validation

scapy/paramiko/nmap orchestration automates tasks en masse, but automation *running* differs from it *behaving safely and correctly*. The author must confirm **which control the automation trips** and **whether dry-run and result-validation gates exist**.

### Attack technique -> Layer -> Control -> Detection signal

| Attack technique | Layer | Control | Detection signal |
|---|---|---|---|
| scapy packet injection/spoofing | Network | Integrity/anomaly detection, RPF | Spoofed src, abnormal packets |
| paramiko mass SSH | Access | Key-based auth, fail2ban | Non-interactive SSH burst |
| nmap automated scan | Network | IDS | Scan signature |
| Schedule/orchestration | Host | Execution monitoring | Abnormal cron/process tree |

### Defense validation (verify directly)

```bash
# Target only owned/authorized assets, running through dry-run and result-validation gates (avoid side effects/malfunction)
arp -a > before.txt   # compare ARP table before/after scapy spoofing (owned lab)
sudo fail2ban-client status sshd 2>/dev/null | grep -i banned   # confirm paramiko bursts get banned
# Automation idempotency/safety: run twice and confirm side effects do not accumulate (same result)
diff <(sort run1.out) <(sort run2.out) && echo "idempotent"
```

> Target only **owned/authorized assets**. Automation "running" differs from it "behaving safely and correctly" — add dry-run, idempotency, and result-validation gates, and confirm the detection footprint of spoofing, SSH bursts, and scans ([[02_Network_Hacking]], [[20_Shell_Scripting]], [[68_Purple_Team]]).
