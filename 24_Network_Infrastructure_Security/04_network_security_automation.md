> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 네트워크 보안 자동화

## 0. 초보자를 위한 개념 이해

### 네트워크 보안 자동화란?

네트워크 보안 자동화는 포트 스캔, 취약점 검색, 방화벽 규칙 감사, 패킷 분석 등 반복적인 보안 작업을 코드로 자동화하는 것이다. 수백 대의 서버를 수작업으로 점검하는 것은 불가능하며, 자동화를 통해 대규모 인프라를 일관되게 점검하고 결과를 표준화된 리포트로 출력할 수 있다.

**왜 배우는가:**
```
네트워크 보안 자동화의 필요성

수작업 한계:
  서버 100대 → 각각 nmap 실행 → 결과 수동 정리
  → 수십 시간 소요, 실수 발생, 일관성 없음

자동화 효과:
  Python 스크립트 → 병렬 스캔 → 통합 리포트 자동 생성
  → 수분 이내 완료, 100% 일관성, CI/CD 파이프라인 통합 가능

활용 분야:
  - 정기 취약점 스캔 (주간/월간 자동 실행)
  - 신규 자산 발견 즉시 알림
  - 방화벽 규칙 준수 여부 자동 검증
```

### 핵심 개념 정리

```
네트워크 보안 자동화 핵심 도구

도구             역할                       Python 인터페이스
──────────────────────────────────────────────────────────
Nmap             포트/서비스/OS 스캔        python-nmap
Scapy            패킷 조작/분석             직접 import
Shodan           인터넷 연결 기기 검색      shodan (API)
Masscan          초고속 포트 스캔           subprocess
Zeek/Suricata    트래픽 분석/IDS            로그 파싱
```

### 필요한 도구 및 환경
- **python-nmap**: `pip install python-nmap`
- **scapy**: `pip install scapy`
- **nmap**: `apt install nmap` (python-nmap의 백엔드)
- **테스트 환경**: 자신이 소유한 네트워크 또는 격리된 VM

### 기초 실습 예제
```python
#!/usr/bin/env python3
"""간단한 포트 스캐너 — 소켓 기반 초보자 예제"""
import socket
import concurrent.futures

def check_port(host: str, port: int, timeout: float = 1.0) -> bool:
    """단일 포트 연결 가능 여부 확인"""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (ConnectionRefusedError, TimeoutError, OSError):
        return False

def scan_ports(host: str, ports: list[int]) -> dict[int, bool]:
    """여러 포트 병렬 스캔"""
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        futures = {ex.submit(check_port, host, p): p for p in ports}
        for future in concurrent.futures.as_completed(futures):
            port = futures[future]
            results[port] = future.result()
    return results

# 사용 예 — 로컬호스트 스캔 (안전)
host = "127.0.0.1"
common_ports = [22, 80, 443, 3306, 5432, 6379, 8080, 8443]
print(f"[*] {host} 스캔 중...")
for port, open_ in sorted(scan_ports(host, common_ports).items()):
    if open_:
        print(f"  [OPEN] {host}:{port}")
```

---

대규모 인프라의 보안 점검은 수작업으로 한계가 있다. Nmap 스크립트 엔진, Scapy 패킷 조작, 방화벽 규칙 자동 감사 등 Python 기반 네트워크 보안 자동화 기법을 정리한다.

---

## 1. Nmap 자동화

### 1.1 python-nmap을 활용한 대규모 스캔

```python
#!/usr/bin/env python3
"""Nmap 래퍼 — 대규모 네트워크 자동 스캔 및 보고서 생성"""
import argparse
import json
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

import nmap


@dataclass
class HostResult:
    ip: str
    hostname: str = ""
    state: str = ""
    os: str = ""
    open_ports: list[dict] = field(default_factory=list)


def scan_host(ip: str, ports: str, arguments: str) -> HostResult:
    nm = nmap.PortScanner()
    result = HostResult(ip=ip)
    try:
        nm.scan(hosts=ip, ports=ports, arguments=arguments)
        if ip in nm.all_hosts():
            host = nm[ip]
            result.state = host.state()
            result.hostname = host.hostname()
            for proto in host.all_protocols():
                for port in host[proto].keys():
                    service = host[proto][port]
                    if service["state"] == "open":
                        result.open_ports.append({
                            "port": port,
                            "proto": proto,
                            "service": service.get("name", ""),
                            "version": service.get("version", ""),
                            "product": service.get("product", ""),
                        })
    except Exception as e:
        result.state = f"error: {e}"
    return result


def scan_network(
    targets: list[str],
    ports: str = "22,80,443,3306,5432,6379,27017",
    arguments: str = "-sV -sC --script vuln",
    workers: int = 20,
) -> list[HostResult]:
    results = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(scan_host, ip, ports, arguments): ip for ip in targets}
        for future in as_completed(futures):
            results.append(future.result())
    return results


def generate_report(results: list[HostResult], output: Path) -> None:
    data = {
        "scan_time": datetime.now().isoformat(),
        "total_hosts": len(results),
        "up_hosts": sum(1 for r in results if r.state == "up"),
        "hosts": [
            {
                "ip": r.ip,
                "hostname": r.hostname,
                "state": r.state,
                "os": r.os,
                "open_ports": r.open_ports,
            }
            for r in results
        ],
    }
    output.write_text(json.dumps(data, indent=2, ensure_ascii=False))
    print(f"[+] 보고서 저장: {output}")


def main() -> None:
    parser = argparse.ArgumentParser(description="네트워크 자동 스캔")
    parser.add_argument("targets", nargs="+", help="IP 또는 CIDR 목록")
    parser.add_argument("-p", "--ports", default="22,80,443,3306,5432,6379,27017")
    parser.add_argument("-o", "--output", default="scan_report.json")
    parser.add_argument("-w", "--workers", type=int, default=20)
    parser.add_argument("--vuln", action="store_true", help="취약점 스크립트 실행")
    args = parser.parse_args()

    arguments = "-sV -sC"
    if args.vuln:
        arguments += " --script vuln"

    results = scan_network(args.targets, args.ports, arguments, args.workers)
    generate_report(results, Path(args.output))

    up = sum(1 for r in results if r.state == "up")
    print(f"[+] 완료: {up}/{len(results)} 호스트 응답")


if __name__ == "__main__":
    main()
```

### 1.2 NSE 스크립트 — 커스텀 취약점 탐지

```lua
-- Nmap 스크립트: 기본 자격증명 탐지 (nse)
description = [[
  일반적인 기본 자격증명으로 HTTP 기본 인증 우회 시도
]]

categories = {"auth", "brute"}

local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"

portrule = shortport.http

local credentials = {
  {"admin", "admin"},
  {"admin", "password"},
  {"root", "root"},
  {"admin", ""},
}

action = function(host, port)
  local results = {}
  for _, cred in ipairs(credentials) do
    local user, pass = cred[1], cred[2]
    local resp = http.get(host, port, "/", {auth = {username=user, password=pass}})
    if resp and resp.status == 200 then
      table.insert(results, string.format("기본 자격증명 유효: %s:%s", user, pass))
    end
  end
  if #results > 0 then
    return table.concat(results, "\n")
  end
end
```

---

## 2. Scapy 패킷 조작

### 2.1 ARP 스푸핑 탐지

```python
#!/usr/bin/env python3
"""ARP 캐시 변조 탐지 (스푸핑 방어 모드)"""
import argparse
import time
from collections import defaultdict

from scapy.all import ARP, Ether, sniff


class ARPMonitor:
    def __init__(self) -> None:
        self.arp_table: dict[str, set[str]] = defaultdict(set)
        self.alerts: list[str] = []

    def process_arp(self, pkt) -> None:
        if not pkt.haslayer(ARP):
            return

        arp = pkt[ARP]
        if arp.op != 2:  # ARP Reply만 처리
            return

        ip = arp.psrc
        mac = arp.hwsrc

        if ip in self.arp_table and mac not in self.arp_table[ip]:
            old_macs = ", ".join(self.arp_table[ip])
            alert = (
                f"[!] ARP 스푸핑 의심: IP {ip} → 기존 MAC {old_macs}, "
                f"새 MAC {mac}"
            )
            print(alert)
            self.alerts.append(alert)

        self.arp_table[ip].add(mac)

    def start(self, iface: str = "eth0", count: int = 0) -> None:
        print(f"[*] ARP 모니터링 시작: {iface}")
        sniff(iface=iface, filter="arp", prn=self.process_arp, count=count, store=False)


def main() -> None:
    parser = argparse.ArgumentParser(description="ARP 스푸핑 탐지")
    parser.add_argument("-i", "--interface", default="eth0")
    parser.add_argument("-c", "--count", type=int, default=0, help="0=무한")
    args = parser.parse_args()

    monitor = ARPMonitor()
    monitor.start(args.interface, args.count)


if __name__ == "__main__":
    main()
```

### 2.2 포트 스캔 탐지 (SYN Flood / 스캔 감지)

```python
#!/usr/bin/env python3
"""비정상 포트 스캔 패턴 탐지"""
import argparse
import time
from collections import defaultdict
from dataclasses import dataclass, field

from scapy.all import IP, TCP, sniff


@dataclass
class ScanDetector:
    threshold: int = 20        # 초당 포트 수
    window: float = 5.0        # 감지 윈도우 (초)
    src_ports: dict = field(default_factory=lambda: defaultdict(set))
    last_reset: float = field(default_factory=time.time)

    def check(self, pkt) -> None:
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
            return

        now = time.time()
        if now - self.last_reset > self.window:
            self.src_ports.clear()
            self.last_reset = now

        if pkt[TCP].flags == "S":  # SYN 패킷
            src = pkt[IP].src
            dst_port = pkt[TCP].dport
            self.src_ports[src].add(dst_port)

            if len(self.src_ports[src]) >= self.threshold:
                print(
                    f"[!] 포트 스캔 탐지: {src} → "
                    f"{len(self.src_ports[src])}개 포트 ({self.window}초 내)"
                )
                self.src_ports[src].clear()


def main() -> None:
    parser = argparse.ArgumentParser(description="포트 스캔 탐지")
    parser.add_argument("-i", "--interface", default="eth0")
    parser.add_argument("-t", "--threshold", type=int, default=20)
    parser.add_argument("-w", "--window", type=float, default=5.0)
    args = parser.parse_args()

    detector = ScanDetector(threshold=args.threshold, window=args.window)
    print(f"[*] 탐지 기준: {args.window}초 내 {args.threshold}개 이상 포트 → 스캔 의심")
    sniff(iface=args.interface, filter="tcp", prn=detector.check, store=False)


if __name__ == "__main__":
    main()
```

---

## 3. 방화벽 규칙 자동 감사

### 3.1 iptables 규칙 분석기

```python
#!/usr/bin/env python3
"""iptables 규칙 감사 및 위험 규칙 탐지"""
import argparse
import subprocess
from dataclasses import dataclass


@dataclass
class FirewallRule:
    chain: str
    target: str
    proto: str
    source: str
    destination: str
    options: str
    risk: str = ""


def parse_iptables(table: str = "filter") -> list[FirewallRule]:
    try:
        output = subprocess.check_output(
            ["iptables", "-t", table, "-L", "-n", "--line-numbers", "-v"],
            text=True,
            stderr=subprocess.DEVNULL,
        )
    except subprocess.CalledProcessError:
        return []

    rules = []
    current_chain = ""

    for line in output.splitlines():
        if line.startswith("Chain "):
            current_chain = line.split()[1]
        elif line.strip() and not line.startswith("num") and not line.startswith("pkts"):
            parts = line.split()
            if len(parts) >= 5:
                rules.append(FirewallRule(
                    chain=current_chain,
                    target=parts[3] if len(parts) > 3 else "",
                    proto=parts[4] if len(parts) > 4 else "",
                    source=parts[7] if len(parts) > 7 else "",
                    destination=parts[8] if len(parts) > 8 else "",
                    options=" ".join(parts[9:]) if len(parts) > 9 else "",
                ))

    return rules


def audit_rules(rules: list[FirewallRule]) -> list[dict]:
    findings = []

    for rule in rules:
        if rule.target == "ACCEPT" and rule.source in ("0.0.0.0/0", "anywhere", ""):
            findings.append({
                "severity": "HIGH",
                "chain": rule.chain,
                "issue": f"모든 소스에서 {rule.proto} {rule.options} 허용",
                "rule": rule,
            })

        if rule.target == "ACCEPT" and any(
            p in rule.options for p in ["dpt:22", "dpt:3389", "dpt:23"]
        ) and rule.source in ("0.0.0.0/0", "anywhere", ""):
            findings.append({
                "severity": "CRITICAL",
                "chain": rule.chain,
                "issue": "원격 관리 포트 인터넷 전체 허용",
                "rule": rule,
            })

    return findings


def main() -> None:
    parser = argparse.ArgumentParser(description="iptables 규칙 감사")
    parser.add_argument("-t", "--table", default="filter", choices=["filter", "nat", "mangle"])
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    rules = parse_iptables(args.table)
    findings = audit_rules(rules)

    print(f"[+] 총 {len(rules)}개 규칙 분석, {len(findings)}개 문제 발견\n")
    for f in findings:
        print(f"[{f['severity']}] {f['chain']}: {f['issue']}")


if __name__ == "__main__":
    main()
```

### 3.2 네트워크 장비 설정 감사 (Cisco/Juniper)

```python
#!/usr/bin/env python3
"""Netmiko 기반 네트워크 장비 자동 감사"""
import argparse
import csv
from pathlib import Path

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException


AUDIT_COMMANDS = {
    "cisco_ios": [
        "show running-config | include enable secret",
        "show running-config | include service password-encryption",
        "show running-config | include no ip source-route",
        "show running-config | include no ip directed-broadcast",
        "show running-config | section snmp",
        "show running-config | section aaa",
        "show ip interface brief",
    ],
    "juniper_junos": [
        "show configuration system services",
        "show configuration system login",
        "show configuration firewall",
        "show interfaces terse",
    ],
}


def audit_device(host: str, username: str, password: str, device_type: str) -> dict:
    result = {"host": host, "status": "ok", "findings": {}}
    try:
        conn = ConnectHandler(
            device_type=device_type,
            host=host,
            username=username,
            password=password,
            timeout=10,
        )
        for cmd in AUDIT_COMMANDS.get(device_type, []):
            output = conn.send_command(cmd)
            result["findings"][cmd] = output
        conn.disconnect()
    except NetmikoAuthenticationException:
        result["status"] = "auth_failed"
    except NetmikoTimeoutException:
        result["status"] = "timeout"
    return result


def check_cisco_hardening(config: str) -> list[str]:
    issues = []
    checks = {
        "service password-encryption": "패스워드 암호화 미설정",
        "enable secret": "Enable Secret 미설정 (Enable Password만 사용)",
        "no ip source-route": "IP Source Route 비활성화 미설정",
        "no ip directed-broadcast": "Directed Broadcast 비활성화 미설정",
        "aaa new-model": "AAA 미설정",
        "logging": "Syslog 미설정",
    }
    for keyword, issue in checks.items():
        if keyword not in config:
            issues.append(issue)
    return issues


def main() -> None:
    parser = argparse.ArgumentParser(description="네트워크 장비 보안 감사")
    parser.add_argument("host", help="장비 IP")
    parser.add_argument("-u", "--username", required=True)
    parser.add_argument("-p", "--password", required=True)
    parser.add_argument("-t", "--type", default="cisco_ios",
                        choices=["cisco_ios", "juniper_junos"])
    args = parser.parse_args()

    result = audit_device(args.host, args.username, args.password, args.type)
    if result["status"] == "ok":
        full_config = "\n".join(result["findings"].values())
        issues = check_cisco_hardening(full_config)
        print(f"[+] {args.host} 감사 완료")
        for issue in issues:
            print(f"  [!] {issue}")
    else:
        print(f"[-] 연결 실패: {result['status']}")


if __name__ == "__main__":
    main()
```

---

## 4. 네트워크 트래픽 이상 탐지

### 4.1 DNS 터널링 탐지

```python
#!/usr/bin/env python3
"""DNS 터널링 이상 트래픽 탐지"""
import argparse
import statistics
from collections import defaultdict

from scapy.all import DNS, DNSQR, IP, UDP, sniff


class DNSTunnelDetector:
    def __init__(self, entropy_threshold: float = 3.5, query_threshold: int = 100):
        self.entropy_threshold = entropy_threshold
        self.query_threshold = query_threshold
        self.dns_counts: dict[str, int] = defaultdict(int)
        self.long_queries: dict[str, int] = defaultdict(int)

    def calc_entropy(self, s: str) -> float:
        from math import log2
        if not s:
            return 0.0
        freq = {c: s.count(c) / len(s) for c in set(s)}
        return -sum(p * log2(p) for p in freq.values())

    def process(self, pkt) -> None:
        if not (pkt.haslayer(DNS) and pkt.haslayer(DNSQR)):
            return

        src = pkt[IP].src if pkt.haslayer(IP) else "unknown"
        qname = pkt[DNSQR].qname.decode(errors="replace").rstrip(".")

        self.dns_counts[src] += 1

        subdomain = qname.split(".")[0] if "." in qname else qname
        entropy = self.calc_entropy(subdomain)
        query_len = len(qname)

        if entropy > self.entropy_threshold or query_len > 50:
            self.long_queries[src] += 1

        if self.long_queries[src] > 10:
            print(
                f"[!] DNS 터널링 의심: {src} — "
                f"고엔트로피/장문 쿼리 {self.long_queries[src]}건 "
                f"(최근: {qname[:60]})"
            )
            self.long_queries[src] = 0


def main() -> None:
    parser = argparse.ArgumentParser(description="DNS 터널링 탐지")
    parser.add_argument("-i", "--interface", default="eth0")
    parser.add_argument("-e", "--entropy", type=float, default=3.5)
    args = parser.parse_args()

    detector = DNSTunnelDetector(entropy_threshold=args.entropy)
    print("[*] DNS 터널링 탐지 시작")
    sniff(iface=args.interface, filter="udp port 53", prn=detector.process, store=False)


if __name__ == "__main__":
    main()
```

---

## 5. 자동화 체크리스트

| 영역 | 도구 | 자동화 수준 |
|------|------|-----------|
| 포트 스캔 | python-nmap | 완전 자동화 |
| ARP 탐지 | Scapy | 실시간 모니터링 |
| 방화벽 감사 | subprocess + iptables | 배치 실행 |
| 장비 감사 | Netmiko | SSH 자동화 |
| DNS 이상 | Scapy | 실시간 모니터링 |
| 패킷 캡처 분석 | PyShark/Scapy | 오프라인 분석 |

### 5.1 통합 자동화 파이프라인

```bash
# 1. 네트워크 스캔
python3 network_scanner.py 192.168.1.0/24 -o scan.json

# 2. 취약한 서비스 필터링
jq '.hosts[] | select(.open_ports[].service == "telnet")' scan.json

# 3. 방화벽 규칙 감사
python3 firewall_audit.py --table filter > audit_report.txt

# 4. 실시간 이상 탐지 (백그라운드)
python3 arp_monitor.py -i eth0 &
python3 dns_tunnel_detect.py -i eth0 &
```

---

<!-- detect-validate-24 -->
## 자동 스캔 탐지와 결과 검증

네트워크 자동화는 *대량 스캔·패킷 조작·설정 감사*를 빠르게 하지만, 방어자에겐 **그 소음이 탐지되는가**, 결과에는 **자동 finding이 오탐이 아닌가**가 관건이다. 검증은 **소유 망**에서만.

### 공격 → 노리는 약점 → 1차 통제(방어자) → 탐지 신호

| 기법 | 노리는 약점 | 1차 통제(방어자) | 탐지 신호 |
|---|---|---|---|
| 대량 포트스캔 | 노출 서비스 | IDS 룰·rate limit | 단시간 다포트 SYN |
| Scapy 패킷 조작 | 스푸핑 허용 | rp_filter·ingress 필터 | 위조 출발지/비정상 플래그 |
| 방화벽 규칙 감사 | 설정 드리프트 | 베이스라인 diff | 예상외 허용 규칙 |
| 자동 취약점 탐지 | 스캐너 오탐 | 수동 재현 | 미검증 finding 비율 |

### 방어 검증 (직접 확인)

```bash
# 1) 스캔 자동화 소음이 IDS에 잡히는지 확인(소유 망) — fast.log 발화
sudo tail -5 /var/log/suricata/fast.log 2>/dev/null | grep -iE "scan|portscan|sweep"
# 2) 자동 스캔 결과 오탐 검증 — open 포트를 수동 배너로 재확인
nc -nv -w3 127.0.0.1 80 2>&1 | head
```

> 자동화 검증은 *소음이 잡히고 결과가 참인가*다 — "스캔 돌렸다"와 "IDS가 발화하고 finding이 수동 재현된다"는 다르다. 소유 망에서 fast.log 발화와 배너 재확인을 직접 한다([[10_Pentest_Methodology]], [[40_Threat_Hunting]], [[13_SOC_Blue_Team]]).

**최신 기법·통제 (2025–2026):**
- IaC·정책자동화로 방화벽/세그먼트 관리 — 검증: 위반 구성이 게이트에서 차단되는가([[18_DevSecOps]])
- 드리프트 탐지 — 강제되는지 확인

---

<a name="english"></a>

# Network Security Automation

Security auditing of large-scale infrastructure has limitations when done manually. This section covers Python-based network security automation techniques including Nmap scripting engine, Scapy packet manipulation, and firewall rule automated auditing.

---

## 1. Nmap Automation

```python
#!/usr/bin/env python3
"""Automated network scanning and analysis"""
import subprocess
import json
import xml.etree.ElementTree as ET
from pathlib import Path

def run_nmap_scan(target: str, options: str = "-sV -sC --open") -> dict:
    """Run nmap and parse results"""
    xml_output = "/tmp/nmap_result.xml"
    
    cmd = f"nmap {options} -oX {xml_output} {target}"
    subprocess.run(cmd.split(), capture_output=True, timeout=300)
    
    return parse_nmap_xml(xml_output)

def parse_nmap_xml(xml_file: str) -> dict:
    """Parse nmap XML output"""
    results = {"hosts": []}
    
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        
        for host in root.findall(".//host"):
            host_data = {
                "ip": "",
                "hostname": "",
                "open_ports": []
            }
            
            addr = host.find("address[@addrtype='ipv4']")
            if addr is not None:
                host_data["ip"] = addr.get("addr")
            
            hostname = host.find(".//hostname")
            if hostname is not None:
                host_data["hostname"] = hostname.get("name", "")
            
            for port in host.findall(".//port[@protocol='tcp']"):
                state = port.find("state")
                if state is not None and state.get("state") == "open":
                    service = port.find("service")
                    port_data = {
                        "port": port.get("portid"),
                        "service": service.get("name", "") if service is not None else "",
                        "version": service.get("version", "") if service is not None else "",
                        "product": service.get("product", "") if service is not None else ""
                    }
                    host_data["open_ports"].append(port_data)
            
            if host_data["open_ports"]:
                results["hosts"].append(host_data)
    
    except Exception as e:
        results["error"] = str(e)
    
    return results

def find_vulnerable_services(scan_results: dict) -> list:
    """Identify potentially vulnerable services"""
    findings = []
    
    RISKY_SERVICES = {
        "telnet": "HIGH - Telnet transmits data in cleartext",
        "ftp": "MEDIUM - FTP transmits credentials in cleartext",
        "rsh": "HIGH - Remote Shell with no encryption",
        "rlogin": "HIGH - Remote Login with no encryption",
        "vnc": "MEDIUM - VNC may have weak authentication",
        "rdp": "MEDIUM - RDP exposed to internet",
        "ms-sql": "MEDIUM - Database exposed",
        "mysql": "MEDIUM - Database exposed",
        "mongodb": "HIGH - NoSQL database potentially unauthenticated",
        "redis": "HIGH - Redis potentially unauthenticated",
    }
    
    for host in scan_results.get("hosts", []):
        for port in host.get("open_ports", []):
            service = port.get("service", "").lower()
            for risky_service, risk_desc in RISKY_SERVICES.items():
                if risky_service in service:
                    findings.append({
                        "ip": host["ip"],
                        "port": port["port"],
                        "service": service,
                        "risk": risk_desc
                    })
    
    return findings

if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.0/24"
    
    print(f"[*] Scanning: {target}")
    results = run_nmap_scan(target)
    
    print(f"[+] Found {len(results['hosts'])} hosts with open ports")
    
    findings = find_vulnerable_services(results)
    if findings:
        print(f"\n[!] Potentially vulnerable services ({len(findings)}):")
        for f in findings:
            print(f"  {f['ip']}:{f['port']} ({f['service']}) - {f['risk']}")
    
    # Save JSON
    Path("scan_results.json").write_text(json.dumps(results, indent=2))
    print("\n[+] Full results saved: scan_results.json")
```

---

## 2. Scapy Packet Analysis

```python
#!/usr/bin/env python3
"""Network packet analysis and anomaly detection with Scapy"""
from scapy.all import sniff, IP, TCP, UDP, ARP, DNS, DNSQR
from collections import defaultdict
import time

class NetworkAnomalyDetector:
    def __init__(self, interface: str = "eth0"):
        self.interface = interface
        self.connection_counts = defaultdict(int)
        self.dns_queries = defaultdict(list)
        self.arp_table = {}
        self.alerts = []
    
    def detect_port_scan(self, packet):
        """Detect SYN port scan"""
        if TCP in packet and packet[TCP].flags == 0x002:  # SYN only
            src = packet[IP].src
            self.connection_counts[src] += 1
            
            if self.connection_counts[src] > 50:  # More than 50 SYN in time window
                self.alert(f"Port scan detected from {src}: {self.connection_counts[src]} SYN packets")
    
    def detect_arp_spoofing(self, packet):
        """Detect ARP spoofing"""
        if ARP in packet and packet[ARP].op == 2:  # ARP reply
            ip = packet[ARP].psrc
            mac = packet[ARP].hwsrc
            
            if ip in self.arp_table:
                if self.arp_table[ip] != mac:
                    self.alert(f"ARP Spoofing detected! IP {ip}: {self.arp_table[ip]} → {mac}")
            else:
                self.arp_table[ip] = mac
    
    def detect_dns_tunneling(self, packet):
        """Detect DNS tunneling (long/many subdomain queries)"""
        if DNS in packet and DNSQR in packet:
            query = packet[DNSQR].qname.decode('utf-8', errors='replace')
            src = packet[IP].src if IP in packet else "unknown"
            
            # Long subdomain queries suggest tunneling
            parts = query.split('.')
            longest_label = max(len(p) for p in parts) if parts else 0
            
            if longest_label > 50:
                self.alert(f"Possible DNS tunneling from {src}: {query[:80]}")
            
            self.dns_queries[src].append(query)
            
            # Many unique domains = possible tunneling
            if len(self.dns_queries[src]) > 100:
                unique_domains = len(set('.'.join(q.split('.')[-2:]) 
                                        for q in self.dns_queries[src]))
                if unique_domains > 50:
                    self.alert(f"High DNS entropy from {src}: {unique_domains} unique domains")
    
    def alert(self, message: str):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        alert_msg = f"[{timestamp}] ALERT: {message}"
        print(alert_msg)
        self.alerts.append(alert_msg)
    
    def packet_handler(self, packet):
        if IP in packet:
            self.detect_port_scan(packet)
            self.detect_dns_tunneling(packet)
        if ARP in packet:
            self.detect_arp_spoofing(packet)
    
    def start_monitoring(self):
        print(f"[*] Starting network monitoring on {self.interface}")
        sniff(iface=self.interface, prn=self.packet_handler, store=0)

if __name__ == "__main__":
    detector = NetworkAnomalyDetector("eth0")
    detector.start_monitoring()
```

---

## 3. Firewall Rule Auditing

```python
#!/usr/bin/env python3
"""Automated firewall rule audit"""
import subprocess
import json

def get_iptables_rules(table: str = "filter") -> list:
    """Get current iptables rules"""
    try:
        result = subprocess.run(
            ["iptables", "-t", table, "-L", "-n", "--line-numbers", "-v"],
            capture_output=True, text=True
        )
        return parse_iptables_output(result.stdout)
    except Exception as e:
        return [{"error": str(e)}]

def parse_iptables_output(output: str) -> list:
    """Parse iptables output"""
    rules = []
    current_chain = None
    
    for line in output.splitlines():
        if line.startswith("Chain "):
            current_chain = line.split()[1]
        elif line.strip() and not line.startswith("num") and not line.startswith("pkts"):
            parts = line.split()
            if len(parts) >= 4 and parts[0].isdigit():
                rules.append({
                    "chain": current_chain,
                    "num": parts[0],
                    "target": parts[3],
                    "prot": parts[4] if len(parts) > 4 else "",
                    "source": parts[7] if len(parts) > 7 else "",
                    "destination": parts[8] if len(parts) > 8 else "",
                    "raw": line.strip()
                })
    
    return rules

def audit_firewall() -> dict:
    """Audit firewall rules for security issues"""
    issues = []
    rules = get_iptables_rules()
    
    for rule in rules:
        target = rule.get("target", "")
        source = rule.get("source", "0.0.0.0/0")
        
        # Check for overly permissive rules
        if target == "ACCEPT" and source == "0.0.0.0/0":
            issues.append({
                "severity": "Medium",
                "rule": rule.get("raw"),
                "issue": "Rule accepts all source IPs"
            })
    
    return {
        "total_rules": len(rules),
        "issues": issues,
        "issue_count": len(issues)
    }

# Usage
result = audit_firewall()
print(f"Rules audited: {result['total_rules']}")
print(f"Issues found: {result['issue_count']}")
for issue in result["issues"]:
    print(f"  [{issue['severity']}] {issue['issue']}")
    print(f"    Rule: {issue['rule']}")
```

---

## 4. Quick Reference — Network Security Automation

```bash
# 1. Quick port scan
nmap -sV --open -T4 target.com

# 2. Find exposed databases
jq '.hosts[] | select(.open_ports[].service == "telnet")' scan.json

# 3. Firewall rule audit
python3 firewall_audit.py --table filter > audit_report.txt

# 4. Real-time anomaly detection (background)
python3 arp_monitor.py -i eth0 &
python3 dns_tunnel_detect.py -i eth0 &
```

<!-- detect-validate-24 -->
## Automated Scan Detection and Result Validation

Network automation speeds up *mass scanning, packet manipulation, and config auditing*, but for defenders the question is **whether that noise is detected**, and for results **whether automated findings are false positives**. Validate only on **owned networks**.

### Attack -> Targeted weakness -> Primary control (defender) -> Detection signal

| Technique | Targeted weakness | Primary control (defender) | Detection signal |
|---|---|---|---|
| Mass port scan | Exposed services | IDS rules, rate limit | Many-port SYN in short window |
| Scapy packet manipulation | Spoofing allowed | rp_filter, ingress filter | Forged source / abnormal flags |
| Firewall rule audit | Config drift | Baseline diff | Unexpected allow rule |
| Automated vuln detection | Scanner false positives | Manual reproduction | Rate of unverified findings |

### Defense validation (verify directly)

```bash
# 1) Confirm scan-automation noise is caught by the IDS (owned network) — fast.log fires
sudo tail -5 /var/log/suricata/fast.log 2>/dev/null | grep -iE "scan|portscan|sweep"
# 2) Validate automated scan results for false positives — re-check an open port via manual banner
nc -nv -w3 127.0.0.1 80 2>&1 | head
```

> Automation validation is *whether the noise is caught and the result is true* -- "we ran the scan" differs from "the IDS fired and the finding reproduces manually". Confirm fast.log firing and banner re-check on owned networks directly ([[10_Pentest_Methodology]], [[40_Threat_Hunting]], [[13_SOC_Blue_Team]]).
