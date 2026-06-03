> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 리눅스 방화벽 — iptables / nftables / firewalld

## 0. 초보자를 위한 개념 이해

### 방화벽이란?

**방화벽(Firewall)**은 네트워크 트래픽을 검사해서 허용하거나 차단하는 보안 장치/소프트웨어입니다.

```
방화벽 없을 때:
  인터넷 → [서버] (모든 포트, 모든 IP 접근 가능)
  → 공격자가 22번 포트(SSH) 브루트포스
  → 3306번 포트(MySQL) 직접 접근
  → 취약한 서비스 찾아서 익스플로잇

방화벽 있을 때:
  인터넷 → [방화벽] → [서버]
          (화이트리스트에 없으면 차단)
  → SSH: 특정 IP에서만 허용
  → MySQL: 로컬호스트에서만 허용
  → HTTP/HTTPS: 모든 IP 허용
```

**비유:** 건물 경비원
- 모든 사람을 검사해서 방문 목적이 있는 사람만 통과
- 허가된 층수만 올라갈 수 있도록 통제

### Linux 방화벽 도구 비교

| 도구 | 설명 | 사용 권장 환경 |
|------|------|---------------|
| **iptables** | 전통적인 커널 방화벽 (Netfilter 인터페이스) | 서버, 복잡한 규칙 |
| **nftables** | iptables 후계자, 더 현대적인 문법 | 최신 배포판 |
| **firewalld** | Zone 기반 동적 방화벽 관리 데몬 | RHEL/CentOS/Fedora |
| **ufw** | Ubuntu 방화벽 (iptables 래퍼) | Ubuntu/Debian, 초보자 |

**어느 도구를 써야 하나?**
```
Ubuntu/Debian → ufw (간단) 또는 nftables (고급)
RHEL/CentOS → firewalld
복잡한 NAT/라우팅 → iptables 또는 nftables
Kubernetes → iptables (kube-proxy가 사용)
```

### 핵심 개념: 체인과 테이블

**iptables의 구조:**
```
테이블 (Table):
  filter  ← 기본 테이블, 패킷 허용/차단
  nat     ← NAT, 포트 포워딩
  mangle  ← 패킷 헤더 수정
  raw     ← 연결 추적 전 처리

체인 (Chain):
  INPUT    → 이 서버로 들어오는 패킷
  OUTPUT   → 이 서버에서 나가는 패킷
  FORWARD  → 이 서버를 통과하는 패킷 (라우터)
  PREROUTING  → 라우팅 결정 전
  POSTROUTING → 라우팅 결정 후

규칙 처리 순서:
  첫 번째 규칙부터 순서대로 매칭
  → 매칭 시 ACCEPT 또는 DROP 실행
  → 모두 매칭 안 되면 기본 정책(Policy) 적용
```

---

## 1. 방화벽 계층 구조

```
인터넷
  ↓
[외부 방화벽 / 라우터 ACL]
  ↓
[서버 iptables/nftables]   ← 호스트 기반 방화벽
  ↓
[서비스 포트 바인딩]
  ↓
애플리케이션

Netfilter 훅 포인트:
  PREROUTING → INPUT → (LOCAL PROCESS)
                              ↓
  POSTROUTING ← OUTPUT ←─────┘
       ↓
    FORWARD (라우터 역할 시)
```

---

## 2. iptables 기본 설정

### 2-1. 정책 초기화 및 기본 차단

**기본 원칙: 화이트리스트(허용 목록) 방식**
```
블랙리스트 방식: 알려진 나쁜 것만 차단 → 모르는 공격에 취약
화이트리스트 방식: 알려진 좋은 것만 허용 → 나머지는 모두 차단 ← 권장!

iptables 기본 정책:
  -P INPUT DROP   → 모든 인바운드 차단 (화이트리스트)
  -P OUTPUT ACCEPT → 모든 아웃바운드 허용 (내부에서 나가는 것)
  -P FORWARD DROP → 포워딩 차단 (라우터 아닌 경우)
```

```bash
# 기존 규칙 초기화
iptables -F
iptables -X
iptables -Z
iptables -t nat    -F
iptables -t mangle -F

# 기본 정책: 모두 차단 후 허용 목록 추가
iptables -P INPUT   DROP
iptables -P FORWARD DROP
iptables -P OUTPUT  ACCEPT   # 아웃바운드는 일단 허용

# 루프백 허용
iptables -A INPUT -i lo -j ACCEPT

# 기존 연결 상태 유지
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
```

### 2-2. 서비스별 규칙

SSH, HTTP, HTTPS 등 서비스별 방화벽 규칙을 추가합니다. 관리 서비스는 허용된 IP만, 공개 서비스는 전체 허용으로 최소 권한을 적용합니다.

```bash
# SSH — 관리자 IP만 허용
iptables -A INPUT -p tcp --dport 22 -s 10.0.0.0/8 -j ACCEPT

# HTTP/HTTPS
iptables -A INPUT -p tcp --dport 80  -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# ICMP (ping) — 제한적 허용
iptables -A INPUT -p icmp --icmp-type echo-request -m limit \
  --limit 1/s --limit-burst 5 -j ACCEPT

# SSH 브루트포스 방지 (최근 60초간 3번 초과 시 차단)
iptables -A INPUT -p tcp --dport 22 -m recent --name SSH --set
iptables -A INPUT -p tcp --dport 22 -m recent --name SSH \
  --update --seconds 60 --hitcount 4 -j DROP

# 포트 스캔 탐지 및 차단
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP   # NULL 스캔
iptables -A INPUT -p tcp --tcp-flags ALL ALL  -j DROP   # XMAS 스캔

# 스텔스 스캔 차단
iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP
```

### 2-3. 규칙 영구 저장

iptables 규칙을 파일에 저장하여 재부팅 후에도 유지합니다. iptables-persistent(Debian/Ubuntu)나 iptables-services(RHEL/CentOS)를 사용합니다.

```bash
# Debian/Ubuntu
apt install iptables-persistent
iptables-save > /etc/iptables/rules.v4
ip6tables-save > /etc/iptables/rules.v6

# RHEL/CentOS
service iptables save
# 또는
iptables-save > /etc/sysconfig/iptables
```

---

## 3. nftables (현대적 방화벽)


nftables는 iptables를 대체하는 현대적 패킷 필터링 프레임워크입니다. `inet` 패밀리로 IPv4/IPv6를 단일 규칙으로 처리하며, `/etc/nftables.conf`에 규칙을 저장하고 `systemd`로 부팅 시 자동 로드합니다.

```bash
# 기본 설정 파일 /etc/nftables.conf
cat > /etc/nftables.conf << 'EOF'
#!/usr/sbin/nft -f
flush ruleset

table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;

        # 루프백
        iif lo accept

        # 기존 연결 유지
        ct state established,related accept

        # SSH (관리자 IP만)
        tcp dport 22 ip saddr 10.0.0.0/8 accept

        # 웹 서비스
        tcp dport { 80, 443 } accept

        # ICMP 제한
        icmp type echo-request limit rate 1/second accept

        # 로깅 후 기본 차단
        log prefix "nft-drop: " drop
    }

    chain output {
        type filter hook output priority 0; policy accept;
    }

    chain forward {
        type filter hook forward priority 0; policy drop;
    }
}

# NAT 테이블 (필요 시)
table ip nat {
    chain prerouting {
        type nat hook prerouting priority -100;
    }
    chain postrouting {
        type nat hook postrouting priority 100;
        oifname "eth0" masquerade
    }
}
EOF

systemctl enable --now nftables
nft -f /etc/nftables.conf
nft list ruleset
```

---

## 4. firewalld (RHEL/CentOS/Fedora)

```bash
# 서비스 허용
firewall-cmd --permanent --add-service=ssh
firewall-cmd --permanent --add-service=http
firewall-cmd --permanent --add-service=https

# 특정 포트 허용
firewall-cmd --permanent --add-port=8080/tcp

# 특정 IP만 SSH 허용
firewall-cmd --permanent --add-rich-rule=\
  'rule family="ipv4" source address="10.0.0.0/8" service name="ssh" accept'

# 포트 포워딩
firewall-cmd --permanent --add-forward-port=port=80:proto=tcp:toport=8080

# 존(zone) 관리
firewall-cmd --get-zones
firewall-cmd --list-all --zone=public

# 적용 및 확인
firewall-cmd --reload
firewall-cmd --list-all
```

---

## 5. 방화벽 감사 자동화

Python subprocess로 방화벽 규칙을 자동으로 감사합니다. iptables 출력을 파싱하여 보안 정책 위반 규칙을 탐지합니다.

```python
import subprocess
import re
import argparse
from dataclasses import dataclass, field

@dataclass
class FirewallAudit:
    open_ports:  list[str] = field(default_factory=list)
    issues:      list[str] = field(default_factory=list)
    suggestions: list[str] = field(default_factory=list)

def get_iptables_rules() -> str:
    result = subprocess.run(
        ["iptables", "-L", "-n", "-v", "--line-numbers"],
        capture_output=True, text=True
    )
    return result.stdout

def get_listening_ports() -> list[tuple[str, str, str]]:
    result = subprocess.run(
        ["ss", "-tulpn"], capture_output=True, text=True
    )
    ports = []
    for line in result.stdout.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 5:
            continue
        proto    = parts[0]
        local    = parts[4]
        process  = parts[-1] if '"' in parts[-1] else ""
        ports.append((proto, local, process))
    return ports

def audit_firewall() -> FirewallAudit:
    audit = FirewallAudit()
    rules = get_iptables_rules()
    ports = get_listening_ports()

    # 기본 정책 확인
    if "policy ACCEPT" in rules and "Chain INPUT" in rules:
        input_section = rules[rules.find("Chain INPUT"):]
        if "policy ACCEPT" in input_section.split("Chain")[0]:
            audit.issues.append("INPUT 기본 정책이 ACCEPT — DROP으로 변경 권장")

    # 노출된 포트 수집
    for proto, local, proc in ports:
        if "0.0.0.0" in local or "*" in local or "::" in local:
            audit.open_ports.append(f"{proto} {local} ({proc})")

    # 위험 포트 탐지
    danger_ports = {
        "23":    "Telnet — 평문 전송, SSH로 교체 권장",
        "21":    "FTP — 평문 전송, SFTP/FTPS 사용 권장",
        "3306":  "MySQL — 외부 노출 시 위험",
        "1521":  "Oracle — 외부 노출 시 위험",
        "27017": "MongoDB — 인증 없이 노출 가능",
        "6379":  "Redis — 기본값 인증 없음",
    }
    for proto, local, proc in ports:
        port = local.split(":")[-1]
        if port in danger_ports and ("0.0.0.0" in local or "*" in local):
            audit.issues.append(f"위험 포트 노출: {port}/tcp — {danger_ports[port]}")

    # SSH 브루트포스 방어 확인
    if "recent" not in rules and "limit" not in rules:
        audit.suggestions.append("SSH 브루트포스 방어(iptables -m recent) 설정 권장")

    # NULL/XMAS 스캔 차단 확인
    if "NONE" not in rules or "ALL ALL" not in rules:
        audit.suggestions.append("포트 스캔 방어 규칙 추가 권장 (NULL/XMAS 스캔)")

    return audit

def main() -> None:
    audit = audit_firewall()

    print("\n[방화벽 감사 결과]\n")
    print("외부 노출 포트:")
    for p in audit.open_ports:
        print(f"  {p}")

    if audit.issues:
        print("\n[!] 발견된 문제:")
        for i in audit.issues:
            print(f"  → {i}")

    if audit.suggestions:
        print("\n[권고사항]:")
        for s in audit.suggestions:
            print(f"  → {s}")

    if not audit.issues and not audit.suggestions:
        print("[+] 주요 방화벽 설정 양호")

if __name__ == "__main__":
    main()
```

---

## 6. 커널 네트워크 보안 파라미터

sysctl.conf로 커널 수준의 네트워크 보안 파라미터를 설정합니다. IP 스푸핑 방지, ICMP 리다이렉트 차단, SYN 쿠키 활성화 등을 적용합니다.

```bash
# /etc/sysctl.conf 보안 강화 설정
cat >> /etc/sysctl.conf << 'EOF'

# IP 스푸핑 방지
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# ICMP 리다이렉트 무시
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv6.conf.all.accept_redirects = 0

# 소스 라우팅 비활성화
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

# SYN Flood 방어
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# IP 포워딩 비활성화 (라우터가 아닌 서버)
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# 브로드캐스트 핑 무시
net.ipv4.icmp_echo_ignore_broadcasts = 1

# bogus 에러 메시지 무시
net.ipv4.icmp_ignore_bogus_error_responses = 1

# TCP TIME_WAIT 최적화
net.ipv4.tcp_tw_reuse = 1

# 커널 로그 주소 노출 방지
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
EOF

sysctl -p
```

---

<a name="english"></a>

# Linux Firewall — iptables / nftables / firewalld

## 1. Firewall Layer Architecture

```
Internet
  ↓
[External Firewall / Router ACL]
  ↓
[Server iptables/nftables]   ← Host-based firewall
  ↓
[Service Port Binding]
  ↓
Application

Netfilter Hook Points:
  PREROUTING → INPUT → (LOCAL PROCESS)
                              ↓
  POSTROUTING ← OUTPUT ←─────┘
       ↓
    FORWARD (when acting as a router)
```

---

## 2. iptables Basic Configuration

### 2-1. Flush Rules and Set Default DROP Policy

Flush existing iptables rules and set a default DROP policy. All inbound/forwarded traffic is set to DROP, then only required services are permitted.

```bash
# Flush existing rules
iptables -F
iptables -X
iptables -Z
iptables -t nat    -F
iptables -t mangle -F

# Default policy: block all, then add allowlist
iptables -P INPUT   DROP
iptables -P FORWARD DROP
iptables -P OUTPUT  ACCEPT   # Allow outbound for now

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT

# Allow established/related connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
```

### 2-2. Service-Specific Rules

Add per-service firewall rules for SSH, HTTP, HTTPS, etc. Apply the principle of least privilege — restrict management services to allowed IPs, and allow public services globally.

```bash
# SSH — allow from admin IP only
iptables -A INPUT -p tcp --dport 22 -s 10.0.0.0/8 -j ACCEPT

# HTTP/HTTPS
iptables -A INPUT -p tcp --dport 80  -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# ICMP (ping) — rate-limited allow
iptables -A INPUT -p icmp --icmp-type echo-request -m limit \
  --limit 1/s --limit-burst 5 -j ACCEPT

# SSH brute-force protection (block if >3 attempts in 60 seconds)
iptables -A INPUT -p tcp --dport 22 -m recent --name SSH --set
iptables -A INPUT -p tcp --dport 22 -m recent --name SSH \
  --update --seconds 60 --hitcount 4 -j DROP

# Port scan detection and blocking
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP   # NULL scan
iptables -A INPUT -p tcp --tcp-flags ALL ALL  -j DROP   # XMAS scan

# Stealth scan blocking
iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP
```

### 2-3. Persistent Rule Storage

Save iptables rules to a file so they persist across reboots. Use iptables-persistent (Debian/Ubuntu) or iptables-services (RHEL/CentOS).

```bash
# Debian/Ubuntu
apt install iptables-persistent
iptables-save > /etc/iptables/rules.v4
ip6tables-save > /etc/iptables/rules.v6

# RHEL/CentOS
service iptables save
# or
iptables-save > /etc/sysconfig/iptables
```

---

## 3. nftables (Modern Firewall)

nftables is a modern packet filtering framework that replaces iptables. The `inet` family handles both IPv4 and IPv6 with a single ruleset. Rules are stored in `/etc/nftables.conf` and auto-loaded at boot via `systemd`.

```bash
# Base configuration file /etc/nftables.conf
cat > /etc/nftables.conf << 'EOF'
#!/usr/sbin/nft -f
flush ruleset

table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;

        # Loopback
        iif lo accept

        # Allow established connections
        ct state established,related accept

        # SSH (admin IP only)
        tcp dport 22 ip saddr 10.0.0.0/8 accept

        # Web services
        tcp dport { 80, 443 } accept

        # Rate-limited ICMP
        icmp type echo-request limit rate 1/second accept

        # Log and drop by default
        log prefix "nft-drop: " drop
    }

    chain output {
        type filter hook output priority 0; policy accept;
    }

    chain forward {
        type filter hook forward priority 0; policy drop;
    }
}

# NAT table (if needed)
table ip nat {
    chain prerouting {
        type nat hook prerouting priority -100;
    }
    chain postrouting {
        type nat hook postrouting priority 100;
        oifname "eth0" masquerade
    }
}
EOF

systemctl enable --now nftables
nft -f /etc/nftables.conf
nft list ruleset
```

---

## 4. firewalld (RHEL/CentOS/Fedora)

```bash
# Allow services
firewall-cmd --permanent --add-service=ssh
firewall-cmd --permanent --add-service=http
firewall-cmd --permanent --add-service=https

# Allow specific port
firewall-cmd --permanent --add-port=8080/tcp

# Allow SSH from specific IP only
firewall-cmd --permanent --add-rich-rule=\
  'rule family="ipv4" source address="10.0.0.0/8" service name="ssh" accept'

# Port forwarding
firewall-cmd --permanent --add-forward-port=port=80:proto=tcp:toport=8080

# Zone management
firewall-cmd --get-zones
firewall-cmd --list-all --zone=public

# Apply and verify
firewall-cmd --reload
firewall-cmd --list-all
```

---

## 5. Firewall Audit Automation

Automatically audit firewall rules using Python subprocess. Parse iptables output to detect rules that violate security policy.

```python
import subprocess
import re
import argparse
from dataclasses import dataclass, field

@dataclass
class FirewallAudit:
    open_ports:  list[str] = field(default_factory=list)
    issues:      list[str] = field(default_factory=list)
    suggestions: list[str] = field(default_factory=list)

def get_iptables_rules() -> str:
    result = subprocess.run(
        ["iptables", "-L", "-n", "-v", "--line-numbers"],
        capture_output=True, text=True
    )
    return result.stdout

def get_listening_ports() -> list[tuple[str, str, str]]:
    result = subprocess.run(
        ["ss", "-tulpn"], capture_output=True, text=True
    )
    ports = []
    for line in result.stdout.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 5:
            continue
        proto    = parts[0]
        local    = parts[4]
        process  = parts[-1] if '"' in parts[-1] else ""
        ports.append((proto, local, process))
    return ports

def audit_firewall() -> FirewallAudit:
    audit = FirewallAudit()
    rules = get_iptables_rules()
    ports = get_listening_ports()

    # Check default policy
    if "policy ACCEPT" in rules and "Chain INPUT" in rules:
        input_section = rules[rules.find("Chain INPUT"):]
        if "policy ACCEPT" in input_section.split("Chain")[0]:
            audit.issues.append("INPUT default policy is ACCEPT — recommend changing to DROP")

    # Collect externally exposed ports
    for proto, local, proc in ports:
        if "0.0.0.0" in local or "*" in local or "::" in local:
            audit.open_ports.append(f"{proto} {local} ({proc})")

    # Detect dangerous ports
    danger_ports = {
        "23":    "Telnet — plaintext transmission, replace with SSH",
        "21":    "FTP — plaintext transmission, use SFTP/FTPS",
        "3306":  "MySQL — dangerous if externally exposed",
        "1521":  "Oracle — dangerous if externally exposed",
        "27017": "MongoDB — may be exposed without authentication",
        "6379":  "Redis — no authentication by default",
    }
    for proto, local, proc in ports:
        port = local.split(":")[-1]
        if port in danger_ports and ("0.0.0.0" in local or "*" in local):
            audit.issues.append(f"Dangerous port exposed: {port}/tcp — {danger_ports[port]}")

    # Check SSH brute-force defense
    if "recent" not in rules and "limit" not in rules:
        audit.suggestions.append("Recommend configuring SSH brute-force defense (iptables -m recent)")

    # Check NULL/XMAS scan blocking
    if "NONE" not in rules or "ALL ALL" not in rules:
        audit.suggestions.append("Recommend adding port scan defense rules (NULL/XMAS scan)")

    return audit

def main() -> None:
    audit = audit_firewall()

    print("\n[Firewall Audit Results]\n")
    print("Externally exposed ports:")
    for p in audit.open_ports:
        print(f"  {p}")

    if audit.issues:
        print("\n[!] Issues found:")
        for i in audit.issues:
            print(f"  → {i}")

    if audit.suggestions:
        print("\n[Recommendations]:")
        for s in audit.suggestions:
            print(f"  → {s}")

    if not audit.issues and not audit.suggestions:
        print("[+] Major firewall settings are in good shape")

if __name__ == "__main__":
    main()
```

---

## 6. Kernel Network Security Parameters

Configure kernel-level network security parameters via sysctl.conf. Apply settings to prevent IP spoofing, block ICMP redirects, enable SYN cookies, and more.

```bash
# Security hardening settings in /etc/sysctl.conf
cat >> /etc/sysctl.conf << 'EOF'

# Prevent IP spoofing
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv6.conf.all.accept_redirects = 0

# Disable source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

# SYN Flood defense
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# Disable IP forwarding (for servers, not routers)
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# Ignore broadcast pings
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Ignore bogus ICMP error responses
net.ipv4.icmp_ignore_bogus_error_responses = 1

# TCP TIME_WAIT optimization
net.ipv4.tcp_tw_reuse = 1

# Prevent kernel address exposure in logs
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
EOF

sysctl -p
```
