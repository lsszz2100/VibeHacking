> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# Python 해킹 CTF 실습 랩

## 실습 환경 준비

### Docker Compose 환경

아래 `docker-compose.yml`을 사용해 실습 환경을 구성한다.

```yaml
# docker-compose.yml
version: "3.9"

services:
  # 실습 1: 취약한 에코 서버 (Buffer-like overflow 시뮬레이션)
  echo-server:
    image: python:3.11-slim
    container_name: echo-server
    networks:
      ctf-net:
        ipv4_address: 10.20.10.10
    command: >
      sh -c "python3 -c \"
import socket, os
flag = 'CTF{scapy_packet_craft3r_m4st3r}'
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', 9001))
s.listen(5)
while True:
    c, a = s.accept()
    data = c.recv(1024)
    if data.startswith(b'\\x41' * 64):
        c.send(b'FLAG: ' + flag.encode() + b'\\n')
    else:
        c.send(b'Echo: ' + data)
    c.close()
\""
    ports:
      - "9001:9001"

  # 실습 2: HTTP 토큰 인증 우회 서버
  token-server:
    image: python:3.11-slim
    container_name: token-server
    networks:
      ctf-net:
        ipv4_address: 10.20.10.20
    command: >
      sh -c "pip install flask -q && python3 -c \"
from flask import Flask, request, jsonify
import hashlib, time
app = Flask(__name__)
SECRET = 'supersecret2024'
FLAG = 'CTF{t0k3n_forg3ry_via_t1m1ng_4tt4ck}'
@app.route('/login', methods=['POST'])
def login():
    user = request.json.get('user','')
    ts = request.json.get('ts', 0)
    sig = request.json.get('sig','')
    expected = hashlib.md5(f'{user}{ts}{SECRET}'.encode()).hexdigest()
    if sig == expected:
        return jsonify({'flag': FLAG})
    return jsonify({'error': 'invalid'}), 403
@app.route('/hint')
def hint():
    ts = int(time.time())
    sample = hashlib.md5(f'admin{ts}WRONG'.encode()).hexdigest()
    return jsonify({'ts': ts, 'sample': sample})
app.run('0.0.0.0', 5000)
\""
    ports:
      - "5000:5000"

  # 실습 3: Raw 소켓 패킷 스니핑 챌린지
  packet-challenge:
    image: python:3.11-slim
    container_name: packet-challenge
    networks:
      ctf-net:
        ipv4_address: 10.20.10.30
    cap_add:
      - NET_ADMIN
      - NET_RAW
    command: >
      sh -c "pip install scapy -q && python3 -c \"
from scapy.all import *
import time, threading
FLAG_FRAGMENTS = ['CTF{sc4py', '_r4w_s0ck3t', '_h4ck3r}']
def send_fragments():
    while True:
        for i, frag in enumerate(FLAG_FRAGMENTS):
            pkt = IP(dst='10.20.10.100', id=0x1337, flags='MF' if i<2 else 0, frag=i*4)/Raw(load=frag.encode())
            send(pkt, verbose=0)
        time.sleep(5)
t = threading.Thread(target=send_fragments)
t.daemon = True
t.start()
time.sleep(9999)
\""

  # 실습 4: pwntools 원격 익스플로잇 서버
  pwn-server:
    image: python:3.11-slim
    container_name: pwn-server
    networks:
      ctf-net:
        ipv4_address: 10.20.10.40
    command: >
      sh -c "python3 -c \"
import socket, struct
FLAG = 'CTF{pwnt00ls_r3m0t3_3xpl01t_succ3ss}'
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', 4444))
s.listen(5)
while True:
    c, _ = s.accept()
    c.send(b'Welcome! Enter magic bytes: ')
    data = c.recv(256)
    magic = struct.unpack('<I', data[:4])[0] if len(data)>=4 else 0
    if magic == 0xdeadbeef:
        c.send(b'Stage 2 - Enter XOR key (1 byte): ')
        key_data = c.recv(16)
        if key_data and key_data[0] ^ 0x42 == 0x13:
            c.send(b'FLAG: ' + FLAG.encode() + b'\\n')
        else:
            c.send(b'Wrong key\\n')
    else:
        c.send(b'Wrong magic\\n')
    c.close()
\""
    ports:
      - "4444:4444"

  # 공격자 워크스테이션
  attacker:
    image: python:3.11-slim
    container_name: attacker
    networks:
      ctf-net:
        ipv4_address: 10.20.10.100
    command: >
      sh -c "pip install scapy pwntools requests -q && sleep infinity"
    cap_add:
      - NET_ADMIN
      - NET_RAW
    tty: true

networks:
  ctf-net:
    driver: bridge
    ipam:
      config:
        - subnet: 10.20.10.0/24
```

환경 시작:

```bash
docker compose up -d
docker exec -it attacker bash
```

---

## 실습 1: Scapy 패킷 조작으로 에코 서버 공략

### 목표
특정 패턴의 바이트를 전송해야만 플래그를 반환하는 커스텀 TCP 에코 서버를 분석하고 공략한다.

**플래그 형식**: `CTF{scapy_packet_craft3r_m4st3r}`

### 시나리오
CTF 운영팀은 `10.20.10.10:9001`에 특수 에코 서버를 배포했다. 일반 문자열을 보내면 그대로 에코만 하지만, 특정 매직 바이트 패턴을 보내면 플래그를 반환한다. 네트워크 패킷을 분석하고 올바른 페이로드를 구성해야 한다.

### 힌트
1. `netcat`으로 서버에 연결해 응답 방식을 먼저 확인한다.
2. 서버가 수신 데이터의 **시작 부분**을 검사한다.
3. `\x41`은 ASCII 문자 'A'에 해당한다.
4. 64바이트 반복 패턴을 테스트해 본다.
5. Scapy의 `Raw` 레이어와 Python의 `socket` 모듈을 함께 활용한다.

### 풀이

**1단계: 서버 수동 탐색**

```bash
# 기본 연결 테스트
echo "hello" | nc 10.20.10.10 9001

# 다양한 패턴 테스트
python3 -c "import sys; sys.stdout.buffer.write(b'A'*10)" | nc 10.20.10.10 9001
python3 -c "import sys; sys.stdout.buffer.write(b'A'*64)" | nc 10.20.10.10 9001
```

**2단계: Scapy로 패킷 분석**

```bash
# Scapy로 패킷 캡처하면서 서버 동작 분석
python3 << 'EOF'
from scapy.all import *

# SYN 패킷 전송 후 응답 분석
ans, _ = sr(IP(dst="10.20.10.10")/TCP(dport=9001, flags="S"), timeout=2, verbose=0)
for s, r in ans:
    print(f"[+] SYN-ACK received from {r[IP].src}:{r[TCP].sport}")
    print(f"[+] Server ISN: {r[TCP].seq}")
EOF
```

**3단계: Python 자동화 익스플로잇 스크립트**

```python
#!/usr/bin/env python3
"""
실습 1 익스플로잇: 에코 서버 매직 바이트 공략
"""
import socket
import struct
import argparse
from typing import Optional


def probe_server(host: str, port: int, payload: bytes) -> Optional[bytes]:
    """서버에 페이로드를 전송하고 응답을 수신한다."""
    try:
        with socket.create_connection((host, port), timeout=5) as sock:
            sock.sendall(payload)
            response = sock.recv(1024)
            return response
    except (ConnectionRefusedError, TimeoutError) as e:
        print(f"[-] 연결 실패: {e}")
        return None


def brute_magic_bytes(host: str, port: int) -> None:
    """매직 바이트 패턴을 단계적으로 브루트포스한다."""
    print(f"[*] {host}:{port} 에코 서버 분석 시작")

    # 1단계: 일반 텍스트 응답 확인
    resp = probe_server(host, port, b"hello\n")
    if resp:
        print(f"[*] 일반 응답: {resp!r}")

    # 2단계: 단일 바이트 반복 패턴 테스트
    for byte_val in [0x41, 0x42, 0x90, 0xff, 0x00]:
        for length in [32, 64, 128]:
            payload = bytes([byte_val]) * length
            resp = probe_server(host, port, payload)
            if resp and b"FLAG" in resp:
                print(f"[+] 플래그 발견! 바이트: 0x{byte_val:02x}, 길이: {length}")
                print(f"[+] 응답: {resp.decode(errors='replace')}")
                return
            elif resp:
                preview = resp[:30]
                print(f"[-] 0x{byte_val:02x} x{length}: {preview!r}")

    print("[-] 자동 탐지 실패, 수동 분석 필요")


def exploit(host: str, port: int) -> None:
    """최종 익스플로잇: 64개의 0x41 바이트 전송."""
    print(f"\n[*] 최종 익스플로잇 시도")
    magic_payload = b"\x41" * 64
    resp = probe_server(host, port, magic_payload)
    if resp:
        print(f"[+] 서버 응답:\n{resp.decode(errors='replace')}")
        if b"CTF{" in resp:
            import re
            flag = re.search(rb"CTF\{[^}]+\}", resp)
            if flag:
                print(f"\n[!] 플래그 획득: {flag.group().decode()}")


def main() -> None:
    parser = argparse.ArgumentParser(description="에코 서버 매직 바이트 익스플로잇")
    parser.add_argument("--host", default="10.20.10.10", help="대상 호스트")
    parser.add_argument("--port", type=int, default=9001, help="대상 포트")
    parser.add_argument("--mode", choices=["probe", "exploit"], default="exploit")
    args = parser.parse_args()

    if args.mode == "probe":
        brute_magic_bytes(args.host, args.port)
    else:
        exploit(args.host, args.port)


if __name__ == "__main__":
    main()
```

실행:
```bash
python3 exploit_echo.py --host 10.20.10.10 --port 9001 --mode probe
python3 exploit_echo.py --host 10.20.10.10 --port 9001 --mode exploit
```

---

## 실습 2: HTTP 토큰 위조 (타이밍 분석)

### 목표
HMAC/MD5 기반 토큰 서명 메커니즘을 분석하고 Python `requests`와 해시 역산으로 인증을 우회한다.

**플래그 형식**: `CTF{t0k3n_forg3ry_via_t1m1ng_4tt4ck}`

### 시나리오
`10.20.10.20:5000`에 토큰 기반 인증 API가 배포되어 있다. `/hint` 엔드포인트가 타임스탬프와 샘플 해시를 노출한다. 서명 알고리즘을 역분석해 `admin` 계정으로 로그인하고 플래그를 획득한다.

### 힌트
1. `/hint` 엔드포인트는 타임스탬프와 무언가의 MD5 해시를 반환한다.
2. 서명 공식은 `MD5(username + timestamp + secret)`이다.
3. `/hint`의 샘플 해시에는 틀린 비밀키가 사용되어 있다 — 하지만 타임스탬프는 실제 값이다.
4. 서버의 시크릿 키를 알아야 한다. 소스코드 힌트를 다시 읽어라.
5. 힌트 응답의 타임스탬프를 재사용해 올바른 서명을 계산한다.

### 풀이

**1단계: API 탐색**

```bash
# 힌트 엔드포인트 확인
curl -s http://10.20.10.20:5000/hint | python3 -m json.tool

# 로그인 엔드포인트 구조 파악
curl -s -X POST http://10.20.10.20:5000/login \
  -H "Content-Type: application/json" \
  -d '{"user":"admin","ts":0,"sig":"test"}' | python3 -m json.tool
```

**2단계: 서명 알고리즘 분석 및 위조**

```python
#!/usr/bin/env python3
"""
실습 2 익스플로잇: HTTP 토큰 서명 위조
"""
import hashlib
import time
import argparse
import requests
from typing import Optional


BASE_URL_DEFAULT = "http://10.20.10.20:5000"


def get_hint(base_url: str) -> dict:
    """서버 힌트 엔드포인트에서 타임스탬프와 샘플 해시를 가져온다."""
    resp = requests.get(f"{base_url}/hint", timeout=5)
    resp.raise_for_status()
    data = resp.json()
    print(f"[*] 힌트 응답: {data}")
    return data


def forge_token(username: str, timestamp: int, secret: str) -> str:
    """MD5(username + ts + secret) 서명을 위조한다."""
    raw = f"{username}{timestamp}{secret}"
    return hashlib.md5(raw.encode()).hexdigest()


def try_login(base_url: str, user: str, ts: int, sig: str) -> Optional[dict]:
    """위조된 토큰으로 로그인을 시도한다."""
    payload = {"user": user, "ts": ts, "sig": sig}
    resp = requests.post(f"{base_url}/login", json=payload, timeout=5)
    if resp.status_code == 200:
        return resp.json()
    return None


def exploit(base_url: str) -> None:
    """알려진 비밀키 후보군으로 토큰을 위조해 로그인한다."""
    print(f"[*] 대상: {base_url}")

    # 힌트에서 타임스탬프 획득
    hint = get_hint(base_url)
    ts = hint.get("ts", int(time.time()))
    print(f"[*] 서버 타임스탬프: {ts}")

    # 비밀키 후보 목록 (CTF에서 일반적인 패턴)
    secret_candidates = [
        "supersecret2024",
        "secret",
        "password",
        "admin",
        "flag",
        "ctf2024",
        "hackme",
    ]

    for secret in secret_candidates:
        # 현재 타임스탬프와 힌트 타임스탬프 둘 다 시도
        for test_ts in [ts, int(time.time()), ts - 1, ts + 1]:
            sig = forge_token("admin", test_ts, secret)
            result = try_login(base_url, "admin", test_ts, sig)
            if result and "flag" in result:
                print(f"\n[+] 성공! 비밀키: '{secret}', TS: {test_ts}")
                print(f"[!] 플래그 획득: {result['flag']}")
                return
            print(f"[-] 시도: secret='{secret}', ts={test_ts}")

    print("[-] 모든 후보 실패. 비밀키 목록을 확장해야 합니다.")


def main() -> None:
    parser = argparse.ArgumentParser(description="HTTP 토큰 서명 위조 익스플로잇")
    parser.add_argument("--url", default=BASE_URL_DEFAULT, help="대상 URL")
    parser.add_argument("--secret", help="알고 있는 경우 직접 비밀키 지정")
    args = parser.parse_args()

    if args.secret:
        hint = get_hint(args.url)
        ts = hint.get("ts", int(time.time()))
        sig = forge_token("admin", ts, args.secret)
        result = try_login(args.url, "admin", ts, sig)
        print(f"[*] 결과: {result}")
    else:
        exploit(args.url)


if __name__ == "__main__":
    main()
```

실행:
```bash
python3 exploit_token.py --url http://10.20.10.20:5000
# 또는 비밀키를 직접 지정
python3 exploit_token.py --url http://10.20.10.20:5000 --secret supersecret2024
```

---

## 실습 3: Scapy IP 단편화 재조합으로 플래그 수집

### 목표
네트워크 상에 단편화되어 전송되는 IP 패킷을 Scapy로 캡처하고 재조합해 플래그를 추출한다.

**플래그 형식**: `CTF{sc4py_r4w_s0ck3t_h4ck3r}`

### 시나리오
내부 네트워크에서 누군가 IP 단편화를 이용해 데이터를 조각조각 전송하고 있다. `packet-challenge` 컨테이너가 5초 간격으로 ID `0x1337`인 단편화 IP 패킷을 보낸다. 이 패킷들을 캡처하고 재조합해 숨겨진 플래그를 찾아내라.

### 힌트
1. `tcpdump -i any` 또는 Scapy의 `sniff()`로 트래픽을 모니터링한다.
2. IP 단편화에서 `frag` 필드는 8바이트 단위 오프셋이다.
3. `MF` 플래그(More Fragments)가 0이면 마지막 단편이다.
4. 같은 `IP.id` 값을 가진 패킷들이 하나의 원본 패킷을 구성한다.
5. 단편들을 오프셋 순으로 정렬한 뒤 페이로드를 합친다.

### 풀이

**1단계: 트래픽 관찰**

```bash
# tcpdump으로 단편화 패킷 확인
tcpdump -i eth0 -n "ip[6:2] & 0x3fff != 0" -A 2>/dev/null | head -40

# Scapy 인터랙티브로 패킷 확인
python3 -c "
from scapy.all import *
pkts = sniff(filter='ip', timeout=8, iface='eth0')
for p in pkts:
    if IP in p and (p[IP].flags == 'MF' or p[IP].frag > 0):
        print(f'ID={hex(p[IP].id)} frag={p[IP].frag} flags={p[IP].flags} payload={bytes(p[Raw]).hex() if Raw in p else \"\"}')
"
```

**2단계: 자동 단편 재조합 스크립트**

```python
#!/usr/bin/env python3
"""
실습 3 익스플로잇: IP 단편화 패킷 캡처 및 재조합
"""
import argparse
import sys
from collections import defaultdict
from typing import Optional

try:
    from scapy.all import IP, Raw, sniff
except ImportError:
    print("[-] scapy가 설치되지 않았습니다: pip install scapy")
    sys.exit(1)


class FragmentReassembler:
    """IP 단편화 패킷을 수집하고 재조합하는 클래스."""

    def __init__(self, target_id: Optional[int] = None) -> None:
        self.fragments: dict[int, list[tuple[int, bytes]]] = defaultdict(list)
        self.target_id = target_id
        self.found_flags: list[str] = []

    def process_packet(self, pkt) -> None:
        """수신 패킷을 분석하고 단편이면 저장한다."""
        if IP not in pkt:
            return

        ip = pkt[IP]
        is_fragment = ip.flags == "MF" or ip.frag > 0

        if not is_fragment:
            return

        if self.target_id and ip.id != self.target_id:
            return

        payload = bytes(pkt[Raw]) if Raw in pkt else b""
        offset = ip.frag * 8  # 오프셋은 8바이트 단위

        print(f"[+] 단편 수신: ID={hex(ip.id)} offset={offset} MF={ip.flags=='MF'} data={payload!r}")
        self.fragments[ip.id].append((offset, payload, ip.flags != "MF"))

        # 마지막 단편(MF=0)이 도착하면 재조합 시도
        if ip.flags != "MF":
            self._reassemble(ip.id)

    def _reassemble(self, pkt_id: int) -> None:
        """저장된 단편들을 재조합해 원본 데이터를 복원한다."""
        frags = self.fragments.get(pkt_id, [])
        if not frags:
            return

        # 오프셋 순으로 정렬
        frags.sort(key=lambda x: x[0])
        reassembled = b"".join(payload for _, payload, _ in frags)

        print(f"\n[*] 재조합 완료 (ID={hex(pkt_id)}): {len(reassembled)} bytes")
        try:
            decoded = reassembled.decode("utf-8")
            print(f"[*] 복원 데이터: {decoded}")
            if "CTF{" in decoded:
                import re
                flags = re.findall(r"CTF\{[^}]+\}", decoded)
                for flag in flags:
                    print(f"\n[!] 플래그 발견: {flag}")
                    self.found_flags.append(flag)
        except UnicodeDecodeError:
            print(f"[*] 바이너리 데이터 (hex): {reassembled.hex()}")


def capture_fragments(
    iface: str,
    timeout: int,
    target_id: Optional[int],
    count: int,
) -> None:
    """지정된 인터페이스에서 IP 단편화 패킷을 캡처한다."""
    reassembler = FragmentReassembler(target_id=target_id)

    print(f"[*] {iface} 인터페이스에서 단편화 패킷 캡처 시작 (최대 {timeout}초)")
    if target_id:
        print(f"[*] 대상 ID 필터: {hex(target_id)}")

    sniff(
        iface=iface,
        filter="ip",
        prn=reassembler.process_packet,
        timeout=timeout,
        count=count,
        store=False,
    )

    if reassembler.found_flags:
        print(f"\n[+] 총 {len(reassembler.found_flags)}개 플래그 획득:")
        for f in reassembler.found_flags:
            print(f"  -> {f}")
    else:
        print("\n[-] 플래그를 찾지 못했습니다. 캡처 시간을 늘려보세요.")


def main() -> None:
    parser = argparse.ArgumentParser(description="IP 단편화 패킷 재조합 도구")
    parser.add_argument("--iface", default="eth0", help="캡처 인터페이스")
    parser.add_argument("--timeout", type=int, default=30, help="캡처 제한 시간(초)")
    parser.add_argument(
        "--id",
        type=lambda x: int(x, 16) if x.startswith("0x") else int(x),
        default=None,
        help="필터링할 IP ID (예: 0x1337)",
    )
    parser.add_argument("--count", type=int, default=0, help="최대 패킷 수 (0=무제한)")
    args = parser.parse_args()

    capture_fragments(args.iface, args.timeout, args.id, args.count)


if __name__ == "__main__":
    main()
```

실행:
```bash
# root 권한 필요
python3 exploit_fragments.py --iface eth0 --timeout 15 --id 0x1337
```

---

## 실습 4: pwntools 원격 이진 프로토콜 익스플로잇

### 목표
커스텀 바이너리 프로토콜을 사용하는 서버의 다단계 인증을 pwntools로 자동화해 플래그를 획득한다.

**플래그 형식**: `CTF{pwnt00ls_r3m0t3_3xpl01t_succ3ss}`

### 시나리오
`10.20.10.40:4444` 서버는 2단계 인증을 요구한다. 1단계에서는 매직 정수를 리틀 엔디안 4바이트로 제출해야 하고, 2단계에서는 XOR 연산 결과가 특정 값이 되는 키를 찾아야 한다. 수동으로 연결해 프로토콜을 분석하고 pwntools 자동화 스크립트를 작성한다.

### 힌트
1. `netcat`으로 서버에 연결해 프롬프트를 관찰한다.
2. 서버는 리틀 엔디안 바이너리 데이터를 기대한다.
3. Python `struct.pack('<I', value)`로 4바이트 리틀 엔디안을 생성한다.
4. XOR 연산: `key ^ 0x42 == 0x13` 이면 `key = ?`
5. pwntools의 `remote()`, `recv()`, `send()` 함수를 활용한다.

### 풀이

**1단계: 수동 프로토콜 분석**

```bash
# 서버 프롬프트 확인
nc 10.20.10.40 4444

# Python으로 매직 바이트 테스트
python3 -c "
import socket, struct
s = socket.create_connection(('10.20.10.40', 4444))
print(s.recv(256))
s.send(struct.pack('<I', 0xdeadbeef))
print(s.recv(256))
s.send(bytes([0x51]))  # 0x51 ^ 0x42 = 0x13
print(s.recv(256))
s.close()
"
```

**2단계: pwntools 자동화 스크립트**

```python
#!/usr/bin/env python3
"""
실습 4 익스플로잇: pwntools 다단계 이진 프로토콜 공략
"""
import struct
import argparse
import sys

try:
    from pwn import remote, context, log
    context.log_level = "info"
except ImportError:
    print("[-] pwntools가 없습니다: pip install pwntools")
    sys.exit(1)


def solve_xor_stage(target_xor: int, xor_key: int) -> int:
    """XOR 방정식 key ^ xor_key == target_xor 를 풀어 key를 반환한다."""
    return target_xor ^ xor_key


def exploit(host: str, port: int) -> None:
    """다단계 인증 서버를 자동으로 공략한다."""
    print(f"[*] {host}:{port}에 연결 중...")

    conn = remote(host, port)

    # --- 1단계: 매직 정수 ---
    prompt = conn.recv(timeout=3)
    print(f"[*] 서버 메시지: {prompt.decode(errors='replace')}")

    magic = 0xDEADBEEF
    magic_bytes = struct.pack("<I", magic)
    print(f"[*] 매직 전송: {hex(magic)} -> {magic_bytes.hex()}")
    conn.send(magic_bytes)

    response = conn.recv(timeout=3)
    print(f"[*] 1단계 응답: {response.decode(errors='replace')}")

    if b"Stage 2" not in response:
        print("[-] 1단계 실패")
        conn.close()
        return

    # --- 2단계: XOR 키 ---
    # key ^ 0x42 == 0x13  -->  key = 0x13 ^ 0x42 = 0x51
    xor_key = solve_xor_stage(0x13, 0x42)
    print(f"[*] XOR 키 계산: 0x13 ^ 0x42 = {hex(xor_key)}")

    conn.send(bytes([xor_key]))

    final = conn.recvall(timeout=3)
    print(f"[*] 최종 응답: {final.decode(errors='replace')}")

    import re
    flags = re.findall(r"CTF\{[^}]+\}", final.decode(errors="replace"))
    if flags:
        print(f"\n[!] 플래그 획득: {flags[0]}")
    else:
        print("[-] 플래그를 찾지 못했습니다.")

    conn.close()


def bruteforce_stage2(host: str, port: int) -> None:
    """2단계 XOR 키를 브루트포스한다 (0x00-0xFF)."""
    print("[*] XOR 키 브루트포스 시작...")
    for key_byte in range(256):
        try:
            conn = remote(host, port, timeout=2)
            conn.recv(timeout=1)
            conn.send(struct.pack("<I", 0xDEADBEEF))
            resp = conn.recv(timeout=1)
            if b"Stage 2" in resp:
                conn.send(bytes([key_byte]))
                final = conn.recv(timeout=1)
                if b"FLAG" in final:
                    print(f"[+] 키 발견: {hex(key_byte)}")
                    print(f"[+] 응답: {final.decode(errors='replace')}")
                    conn.close()
                    return
            conn.close()
        except Exception:
            pass
        if key_byte % 32 == 0:
            print(f"[-] 진행: {key_byte}/255")
    print("[-] 브루트포스 실패")


def main() -> None:
    parser = argparse.ArgumentParser(description="pwntools 이진 프로토콜 익스플로잇")
    parser.add_argument("--host", default="10.20.10.40", help="대상 호스트")
    parser.add_argument("--port", type=int, default=4444, help="대상 포트")
    parser.add_argument(
        "--mode",
        choices=["exploit", "bruteforce"],
        default="exploit",
        help="실행 모드",
    )
    args = parser.parse_args()

    if args.mode == "bruteforce":
        bruteforce_stage2(args.host, args.port)
    else:
        exploit(args.host, args.port)


if __name__ == "__main__":
    main()
```

실행:
```bash
# 직접 익스플로잇
python3 exploit_pwn.py --host 10.20.10.40 --port 4444

# 또는 브루트포스 모드
python3 exploit_pwn.py --host 10.20.10.40 --port 4444 --mode bruteforce
```

---

<a name="english"></a>

# Python Hacking CTF Practice Lab

## Lab Environment Setup

### Docker Compose Environment

Use the `docker-compose.yml` above to spin up the lab. Start with:

```bash
docker compose up -d
docker exec -it attacker bash
```

---

## Challenge 1: Echo Server Magic Bytes via Scapy Packet Crafting

### Objective
Analyze a custom TCP echo server that only returns the flag when a specific byte pattern is sent, then craft the correct payload.

**Flag format**: `CTF{scapy_packet_craft3r_m4st3r}`

### Scenario
A special echo server is running at `10.20.10.10:9001`. Ordinary strings are echoed back, but a specific magic byte pattern causes the server to return the flag. Analyze the network behavior and craft the correct payload.

### Hints
1. Use `netcat` to connect first and observe how the server responds.
2. The server inspects the **start** of received data.
3. `\x41` is the ASCII character 'A'.
4. Test a 64-byte repeated pattern.
5. Combine Scapy's `Raw` layer with Python's `socket` module.

### Solution

**Step 1: Manual server exploration**

```bash
echo "hello" | nc 10.20.10.10 9001
python3 -c "import sys; sys.stdout.buffer.write(b'A'*64)" | nc 10.20.10.10 9001
```

**Step 2: Automated exploit**

Run `exploit_echo.py` (see Korean section above) with:
```bash
python3 exploit_echo.py --host 10.20.10.10 --port 9001 --mode exploit
```

The script tests `\x41 * 64` and similar patterns, detects a `FLAG:` response, and extracts the flag with a regex.

---

## Challenge 2: HTTP Token Forgery via Timing Analysis

### Objective
Reverse-engineer an MD5-based token signing mechanism and forge an `admin` login token.

**Flag format**: `CTF{t0k3n_forg3ry_via_t1m1ng_4tt4ck}`

### Scenario
A token-authenticated API lives at `10.20.10.20:5000`. The `/hint` endpoint leaks a timestamp. The signing formula is `MD5(username + timestamp + secret)`. Figure out the secret, forge a valid signature, and retrieve the flag.

### Hints
1. The `/hint` endpoint reveals a timestamp and a sample MD5 hash.
2. The signing formula is `MD5(username + timestamp + secret)`.
3. The sample hash in `/hint` uses a wrong secret — but the timestamp is real.
4. Re-read the server source for the secret key.
5. Reuse the leaked timestamp to compute the correct signature.

### Solution

```bash
# 1. Inspect the hint endpoint
curl -s http://10.20.10.20:5000/hint | python3 -m json.tool

# 2. Run the exploit
python3 exploit_token.py --url http://10.20.10.20:5000
# or directly specify the secret
python3 exploit_token.py --url http://10.20.10.20:5000 --secret supersecret2024
```

The script iterates over common CTF secret candidates, computes `MD5(admin + ts + secret)` for each, and calls `/login` until a `200` response with a `flag` field is returned.

---

## Challenge 3: IP Fragment Reassembly with Scapy

### Objective
Capture fragmented IP packets on the network, reassemble them in offset order, and extract the hidden flag.

**Flag format**: `CTF{sc4py_r4w_s0ck3t_h4ck3r}`

### Scenario
A host inside the network is transmitting data using IP fragmentation every 5 seconds. The packets all share IP ID `0x1337` and arrive in three fragments. Capture and reassemble them to recover the flag.

### Hints
1. Use `tcpdump` or Scapy's `sniff()` to monitor traffic.
2. The `frag` field in an IP header is an 8-byte-unit offset.
3. When `MF=0`, that packet is the last fragment.
4. Group packets by the same `IP.id` value.
5. Sort fragments by offset and concatenate payloads.

### Solution

```bash
# Requires root / NET_RAW capability
python3 exploit_fragments.py --iface eth0 --timeout 15 --id 0x1337
```

The `FragmentReassembler` class tracks arriving fragments keyed by IP ID, sorts by offset when the last fragment (MF=0) arrives, joins the payloads, and searches for `CTF{...}`.

---

## Challenge 4: pwntools Remote Binary Protocol Exploit

### Objective
Automate a two-stage binary authentication protocol using pwntools to retrieve the flag.

**Flag format**: `CTF{pwnt00ls_r3m0t3_3xpl01t_succ3ss}`

### Scenario
The server at `10.20.10.40:4444` uses a two-stage binary protocol. Stage 1 requires submitting a 4-byte little-endian integer magic value. Stage 2 requires solving an XOR equation. Use pwntools to automate the interaction.

### Hints
1. Connect with `netcat` and observe the prompts.
2. The server expects little-endian binary data.
3. Use `struct.pack('<I', value)` to generate a 4-byte little-endian integer.
4. For Stage 2: `key ^ 0x42 == 0x13`, so `key = 0x13 ^ 0x42`.
5. pwntools `remote()`, `recv()`, `send()` handle the interaction cleanly.

### Solution

```bash
python3 exploit_pwn.py --host 10.20.10.40 --port 4444

# If you want to brute-force Stage 2 instead of solving analytically:
python3 exploit_pwn.py --host 10.20.10.40 --port 4444 --mode bruteforce
```

**Key calculation:**
- Magic: `0xdeadbeef` → little-endian bytes `ef be ad de`
- XOR key: `0x13 ^ 0x42 = 0x51`

The pwntools script sends the magic bytes, waits for "Stage 2", then sends the computed XOR key and reads the flag from the final response.
