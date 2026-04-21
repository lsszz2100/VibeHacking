# 리눅스 방화벽 — iptables / nftables / firewalld

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

iptables 규칙을 초기화하고 기본 차단 정책을 설정합니다. 모든 인바운드/포워딩 트래픽을 DROP으로 설정한 후 필요한 서비스만 허용합니다.

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
