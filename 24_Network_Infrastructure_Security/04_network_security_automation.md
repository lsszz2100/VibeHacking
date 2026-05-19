# 네트워크 보안 자동화

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
