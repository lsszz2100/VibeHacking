> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>
# 포렌식 CTF 실습 랩

## 실습 환경 준비

```bash
# Docker 기반 실습 환경
docker pull remnux/remnux-distro
docker run -it --name forensics-lab -v $(pwd)/evidence:/evidence remnux/remnux-distro bash

# 필수 도구 설치 (Ubuntu/Kali)
sudo apt update && sudo apt install -y \
    autopsy sleuthkit volatility3 \
    wireshark tshark binwalk foremost \
    python3-pip

pip3 install yara-python python-magic pwntools
```

---

## 실습 1: Autopsy로 삭제된 파일 복구 + 플래그 추출

### 목표

CTF에서 제공된 디스크 이미지(`challenge.dd`)에서 삭제된 파일을 복구하고, 그 안에 숨겨진 플래그를 추출한다.

### 시나리오

용의자가 범행 증거를 삭제했다. 디스크 이미지를 분석해 삭제된 텍스트 파일을 복구하고, `flag{...}` 형식의 플래그를 찾아라.

### 힌트

1. `mmls`로 파티션 구조를 먼저 파악한다.
2. `fls -r -d` 옵션으로 삭제된 파일만 나열한다. (`-d` = deleted only)
3. `icat`으로 inode 번호를 지정해 파일 내용을 복구한다.
4. 복구된 파일에 `strings` 또는 `grep`으로 플래그 패턴을 검색한다.
5. 파일이 이미지 형식이라면 `foremost`나 `binwalk`로 카빙한다.

### 풀이

**단계 1: 파티션 구조 파악**

```bash
mmls challenge.dd
# 출력 예시:
# 000: Meta  0000000000  0000000000  0000000001  Primary Table (#0)
# 001: -----  0000000000  0000000000  0000000001  Unallocated
# 002: NTFS  0000002048  0000206847  0000204800  Basic data partition
```

**단계 2: 삭제된 파일 목록 출력**

```bash
# offset=2048 (파티션 시작 섹터)
fls -r -d -o 2048 challenge.dd
# 출력 예시:
# d/d * 23: $OrphanFiles
# r/r * 45: secret_note.txt
# r/r * 67: flag_backup.txt
```

**단계 3: icat으로 파일 내용 복구**

```bash
# inode 45번 파일 복구
icat -o 2048 challenge.dd 45 > secret_note.txt
cat secret_note.txt

# inode 67번 파일 복구
icat -o 2048 challenge.dd 67 > flag_backup.txt
cat flag_backup.txt
# 출력: flag{d3l3t3d_but_not_g0ne_a1b2c3}
```

**단계 4: 자동화 스크립트**

```python
#!/usr/bin/env python3
"""
recover_deleted.py
디스크 이미지에서 삭제된 파일을 자동으로 복구한다.
"""

import argparse
import subprocess
import re
from pathlib import Path


def get_partition_offset(image_path: str) -> int | None:
    """mmls로 첫 번째 유효 파티션 오프셋을 반환한다."""
    result = subprocess.run(
        ["mmls", image_path], capture_output=True, text=True
    )
    for line in result.stdout.splitlines():
        # NTFS, FAT, ext2/3/4 파티션 탐지
        if any(fs in line for fs in ("NTFS", "FAT", "Linux", "ext")):
            parts = line.split()
            for p in parts:
                if p.isdigit() and int(p) > 0:
                    return int(p)
    return None


def list_deleted_inodes(image_path: str, offset: int) -> list[tuple[str, str]]:
    """삭제된 파일의 (inode, 이름) 목록을 반환한다."""
    result = subprocess.run(
        ["fls", "-r", "-d", "-o", str(offset), image_path],
        capture_output=True, text=True
    )
    entries = []
    for line in result.stdout.splitlines():
        # "r/r * 45:  filename.txt" 형식 파싱
        match = re.search(r"\*\s+(\d+):\s+(.+)", line)
        if match:
            entries.append((match.group(1), match.group(2).strip()))
    return entries


def recover_file(image_path: str, offset: int, inode: str, out_path: Path) -> bool:
    """icat으로 파일을 복구한다. 성공 시 True를 반환한다."""
    result = subprocess.run(
        ["icat", "-o", str(offset), image_path, inode],
        capture_output=True
    )
    if result.returncode == 0 and result.stdout:
        out_path.write_bytes(result.stdout)
        return True
    return False


def search_flag(file_path: Path, pattern: str = r"flag\{[^}]+\}") -> list[str]:
    """파일에서 플래그 패턴을 검색한다."""
    try:
        content = file_path.read_text(errors="replace")
        return re.findall(pattern, content, re.IGNORECASE)
    except Exception:
        return []


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="디스크 이미지에서 삭제된 파일을 복구하고 플래그를 탐색한다."
    )
    parser.add_argument("--image", "-i", required=True, help="디스크 이미지 경로")
    parser.add_argument("--output", "-o", required=True, help="복구 파일 저장 디렉터리")
    parser.add_argument(
        "--pattern", "-p",
        default=r"flag\{[^}]+\}",
        help="플래그 정규식 패턴 (기본: flag{...})",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"[*] 이미지 분석: {args.image}")
    offset = get_partition_offset(args.image)
    if offset is None:
        print("[-] 파티션을 찾을 수 없음")
        return
    print(f"[*] 파티션 오프셋: {offset}")

    deleted = list_deleted_inodes(args.image, offset)
    print(f"[*] 삭제된 파일 {len(deleted)}개 발견")

    flags_found = []
    for inode, name in deleted:
        safe_name = name.replace("/", "_").replace(" ", "_")
        out_file = out_dir / f"{inode}_{safe_name}"
        if recover_file(args.image, offset, inode, out_file):
            print(f"[+] 복구: [{inode}] {name}")
            flags = search_flag(out_file, args.pattern)
            for flag in flags:
                print(f"[!!!] 플래그 발견: {flag}")
                flags_found.append(flag)

    print(f"\n[*] 완료. 총 플래그 {len(flags_found)}개")


if __name__ == "__main__":
    main()
```

```bash
python recover_deleted.py --image challenge.dd --output ./recovered
# [*] 이미지 분석: challenge.dd
# [*] 파티션 오프셋: 2048
# [*] 삭제된 파일 2개 발견
# [+] 복구: [45] secret_note.txt
# [+] 복구: [67] flag_backup.txt
# [!!!] 플래그 발견: flag{d3l3t3d_but_not_g0ne_a1b2c3}
```

---

## 실습 2: Volatility로 프로세스 숨김 탐지

### 목표

CTF에서 제공된 메모리 덤프(`memory.raw`)에서 루트킷이 숨긴 악성 프로세스를 탐지하고, 해당 프로세스의 이름에서 플래그를 추출한다.

### 시나리오

메모리 덤프를 분석해 일반 프로세스 목록에는 보이지 않지만 실제로 실행 중인 프로세스를 찾아라. 숨겨진 프로세스 이름이 플래그의 일부다.

### 힌트

1. `windows.pslist`와 `windows.psscan` 결과를 비교한다.
2. pslist에 없고 psscan에 있는 프로세스가 숨겨진 프로세스다.
3. `windows.dlllist` 또는 `windows.cmdline`으로 프로세스 상세 정보를 확인한다.
4. 프로세스 메모리에서 `windows.memmap --dump` 후 strings로 플래그를 검색한다.

### 풀이

**단계 1: 프로파일 확인 및 프로세스 목록**

```bash
# Volatility 3 사용
python3 vol.py -f memory.raw windows.info

# 일반 프로세스 목록
python3 vol.py -f memory.raw windows.pslist > pslist.txt

# 물리 메모리 스캔 기반 목록
python3 vol.py -f memory.raw windows.psscan > psscan.txt
```

**단계 2: 숨겨진 프로세스 비교**

```bash
# pslist PID 추출
awk 'NR>1 {print $2}' pslist.txt | sort > pslist_pids.txt

# psscan PID 추출
awk 'NR>1 {print $2}' psscan.txt | sort > psscan_pids.txt

# psscan에만 있는 PID (숨겨진 프로세스)
comm -13 pslist_pids.txt psscan_pids.txt
# 출력: 1337  ← 숨겨진 프로세스 PID
```

**단계 3: 숨겨진 프로세스 상세 분석**

```bash
# 프로세스 메모리 덤프
python3 vol.py -f memory.raw windows.memmap --pid 1337 --dump

# 덤프 파일에서 플래그 검색
strings pid.1337.dmp | grep -i "flag{"
# 출력: flag{h1dd3n_pr0c3ss_f0und_d3adbeef}
```

**단계 4: 자동화 비교 스크립트**

```python
#!/usr/bin/env python3
"""
find_hidden_processes.py
Volatility 출력에서 숨겨진 프로세스를 자동으로 탐지한다.
"""

import argparse
import subprocess
import re
from pathlib import Path


def run_volatility(memory: str, plugin: str) -> list[dict]:
    """Volatility 플러그인을 실행하고 프로세스 정보를 반환한다."""
    result = subprocess.run(
        ["python3", "vol.py", "-f", memory, plugin],
        capture_output=True, text=True
    )
    processes = []
    for line in result.stdout.splitlines()[2:]:   # 헤더 2줄 건너뜀
        parts = line.split()
        if len(parts) >= 3:
            try:
                processes.append({
                    "pid": int(parts[1]),
                    "name": parts[0],
                    "ppid": int(parts[2]),
                })
            except ValueError:
                continue
    return processes


def find_hidden(pslist: list[dict], psscan: list[dict]) -> list[dict]:
    """pslist에 없고 psscan에 있는 숨겨진 프로세스를 반환한다."""
    pslist_pids = {p["pid"] for p in pslist}
    return [p for p in psscan if p["pid"] not in pslist_pids]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="메모리 덤프에서 숨겨진 프로세스를 탐지한다."
    )
    parser.add_argument("--memory", "-m", required=True, help="메모리 덤프 경로")
    parser.add_argument("--dump", action="store_true", help="숨겨진 프로세스 메모리 덤프")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    print("[*] pslist 실행 중...")
    pslist = run_volatility(args.memory, "windows.pslist")
    print(f"    pslist 프로세스: {len(pslist)}개")

    print("[*] psscan 실행 중...")
    psscan = run_volatility(args.memory, "windows.psscan")
    print(f"    psscan 프로세스: {len(psscan)}개")

    hidden = find_hidden(pslist, psscan)
    if not hidden:
        print("[*] 숨겨진 프로세스 없음")
        return

    print(f"\n[!] 숨겨진 프로세스 {len(hidden)}개 발견:")
    for proc in hidden:
        print(f"    PID={proc['pid']}  PPID={proc['ppid']}  NAME={proc['name']}")

    if args.dump:
        for proc in hidden:
            print(f"\n[*] PID {proc['pid']} 메모리 덤프 중...")
            subprocess.run([
                "python3", "vol.py", "-f", args.memory,
                "windows.memmap", "--pid", str(proc["pid"]), "--dump"
            ])
            dump_file = Path(f"pid.{proc['pid']}.dmp")
            if dump_file.exists():
                result = subprocess.run(
                    ["strings", str(dump_file)], capture_output=True, text=True
                )
                flags = re.findall(r"flag\{[^}]+\}", result.stdout, re.IGNORECASE)
                for flag in flags:
                    print(f"[!!!] 플래그: {flag}")


if __name__ == "__main__":
    main()
```

---

## 실습 3: 네트워크 캡처에서 자격증명 추출

### 목표

CTF에서 제공된 PCAP 파일(`traffic.pcap`)을 분석해 평문으로 전송된 자격증명을 추출하고, 비밀번호가 플래그임을 확인한다.

### 시나리오

네트워크 트래픽 캡처에 HTTP 기본 인증, FTP 로그인, Telnet 세션이 포함되어 있다. 각 프로토콜에서 자격증명을 추출하라.

### 힌트

1. `tshark` 또는 Wireshark로 프로토콜별 트래픽을 필터링한다.
2. HTTP Basic Auth는 Base64로 인코딩되어 있다 — 디코딩 필수.
3. FTP는 `USER`와 `PASS` 명령이 평문으로 전송된다.
4. Telnet 세션은 개별 키 입력이 패킷에 그대로 포함된다.
5. `strings traffic.pcap | grep -i "pass\|password\|login"` 로 빠르게 탐색.

### 풀이

**단계 1: 캡처 파일 개요 확인**

```bash
tshark -r traffic.pcap -q -z conv,tcp
capinfos traffic.pcap
```

**단계 2: HTTP Basic Auth 추출**

```bash
# HTTP Authorization 헤더 추출
tshark -r traffic.pcap -Y "http.authorization" \
    -T fields -e http.authorization
# 출력: Basic YWRtaW46ZmxhZ3tiYXNlNjRfY3JlZHN9

# Base64 디코딩
echo "YWRtaW46ZmxhZ3tiYXNlNjRfY3JlZHN9" | base64 -d
# 출력: admin:flag{bas364_cr3ds_exposed}
```

**단계 3: FTP 자격증명 추출**

```bash
# FTP USER/PASS 명령 추출
tshark -r traffic.pcap -Y "ftp.request.command == USER or ftp.request.command == PASS" \
    -T fields -e ftp.request.command -e ftp.request.arg
# 출력:
# USER  ftpuser
# PASS  flag{ftp_plaintext_bad_idea}
```

**단계 4: 자동화 추출 스크립트**

```python
#!/usr/bin/env python3
"""
extract_credentials.py
PCAP 파일에서 평문 자격증명과 플래그를 자동 추출한다.
"""

import argparse
import base64
import json
import re
import subprocess
from pathlib import Path


def run_tshark(pcap: str, display_filter: str, fields: list[str]) -> list[list[str]]:
    """tshark로 특정 필드를 추출한다."""
    cmd = ["tshark", "-r", pcap, "-Y", display_filter, "-T", "fields"]
    for field in fields:
        cmd.extend(["-e", field])
    result = subprocess.run(cmd, capture_output=True, text=True)
    rows = []
    for line in result.stdout.splitlines():
        if line.strip():
            rows.append(line.split("\t"))
    return rows


def extract_http_auth(pcap: str) -> list[dict]:
    """HTTP Basic Auth 자격증명을 추출한다."""
    rows = run_tshark(pcap, "http.authorization contains Basic", ["http.authorization"])
    creds = []
    for row in rows:
        if not row:
            continue
        auth_header = row[0]
        if "Basic " in auth_header:
            encoded = auth_header.split("Basic ")[1].strip()
            try:
                decoded = base64.b64decode(encoded).decode("utf-8", errors="replace")
                user, _, password = decoded.partition(":")
                creds.append({"protocol": "HTTP Basic", "username": user, "password": password})
            except Exception:
                pass
    return creds


def extract_ftp_creds(pcap: str) -> list[dict]:
    """FTP USER/PASS 자격증명을 추출한다."""
    rows = run_tshark(
        pcap,
        "ftp.request.command",
        ["ftp.request.command", "ftp.request.arg"],
    )
    creds = []
    current: dict = {}
    for row in rows:
        if len(row) < 2:
            continue
        cmd, arg = row[0].strip(), row[1].strip()
        if cmd == "USER":
            current = {"protocol": "FTP", "username": arg}
        elif cmd == "PASS" and current:
            current["password"] = arg
            creds.append(current)
            current = {}
    return creds


def search_flags(creds: list[dict], pattern: str = r"flag\{[^}]+\}") -> list[str]:
    """자격증명에서 플래그 패턴을 검색한다."""
    flags = []
    for cred in creds:
        for value in cred.values():
            matches = re.findall(pattern, str(value), re.IGNORECASE)
            flags.extend(matches)
    return list(set(flags))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="PCAP 파일에서 평문 자격증명과 플래그를 추출한다."
    )
    parser.add_argument("--pcap", "-p", required=True, help="PCAP 파일 경로")
    parser.add_argument("--output", "-o", help="결과 JSON 저장 경로")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    print(f"[*] PCAP 분석: {args.pcap}")
    all_creds: list[dict] = []

    print("[*] HTTP Basic Auth 추출 중...")
    http_creds = extract_http_auth(args.pcap)
    all_creds.extend(http_creds)
    for c in http_creds:
        print(f"    HTTP: {c['username']} / {c['password']}")

    print("[*] FTP 자격증명 추출 중...")
    ftp_creds = extract_ftp_creds(args.pcap)
    all_creds.extend(ftp_creds)
    for c in ftp_creds:
        print(f"    FTP:  {c['username']} / {c['password']}")

    flags = search_flags(all_creds)
    if flags:
        print(f"\n[!!!] 플래그 발견:")
        for flag in flags:
            print(f"      {flag}")

    if args.output:
        Path(args.output).write_text(
            json.dumps({"credentials": all_creds, "flags": flags}, indent=2, ensure_ascii=False)
        )
        print(f"\n[*] 결과 저장: {args.output}")


if __name__ == "__main__":
    main()
```

```bash
python extract_credentials.py --pcap traffic.pcap --output results.json
# [*] HTTP Basic Auth 추출 중...
#     HTTP: admin / flag{bas364_cr3ds_exposed}
# [*] FTP 자격증명 추출 중...
#     FTP:  ftpuser / flag{ftp_plaintext_bad_idea}
# [!!!] 플래그 발견:
#       flag{bas364_cr3ds_exposed}
#       flag{ftp_plaintext_bad_idea}
```

---

<a name="english"></a>
# Forensics CTF Lab

## Lab Environment Setup

```bash
# Docker-based lab environment
docker pull remnux/remnux-distro
docker run -it --name forensics-lab -v $(pwd)/evidence:/evidence remnux/remnux-distro bash

# Install required tools (Ubuntu/Kali)
sudo apt update && sudo apt install -y \
    autopsy sleuthkit volatility3 \
    wireshark tshark binwalk foremost \
    python3-pip

pip3 install yara-python python-magic pwntools
```

---

## Lab 1: File Recovery with Autopsy + Flag Extraction

### Objective

Recover deleted files from a provided disk image (`challenge.dd`) and extract the hidden flag from the recovered data.

### Scenario

A suspect deleted evidence files. Analyze the disk image to recover deleted text files and find a `flag{...}` pattern.

### Hints

1. Use `mmls` to understand the partition structure first.
2. Use `fls -r -d` to list only deleted files (`-d` = deleted only).
3. Use `icat` with the inode number to recover file content.
4. Search recovered files with `strings` or `grep` for the flag pattern.
5. If files are images, use `foremost` or `binwalk` for file carving.

### Solution

**Step 1: Identify partition structure**

```bash
mmls challenge.dd
# Example output:
# 002: NTFS  0000002048  0000206847  0000204800  Basic data partition
```

**Step 2: List deleted files**

```bash
fls -r -d -o 2048 challenge.dd
# r/r * 45:  secret_note.txt
# r/r * 67:  flag_backup.txt
```

**Step 3: Recover files with icat**

```bash
icat -o 2048 challenge.dd 67 > flag_backup.txt
cat flag_backup.txt
# flag{d3l3t3d_but_not_g0ne_a1b2c3}
```

**Step 4: Automated recovery** — see `recover_deleted.py` in the Korean section above.

---

## Lab 2: Hidden Process Detection with Volatility

### Objective

Analyze a memory dump (`memory.raw`) to detect a rootkit-hidden process and extract the flag from its memory.

### Scenario

Find a process that does not appear in the normal process list but is actually running. The hidden process name or memory content contains the flag.

### Hints

1. Compare `windows.pslist` and `windows.psscan` results.
2. Processes present in psscan but absent from pslist are hidden.
3. Use `windows.cmdline` for process command-line details.
4. Dump process memory with `--dump` and search with `strings`.

### Solution

```bash
# Generate both process lists
python3 vol.py -f memory.raw windows.pslist > pslist.txt
python3 vol.py -f memory.raw windows.psscan > psscan.txt

# Find hidden PIDs
comm -13 <(awk 'NR>1{print $2}' pslist.txt | sort) \
         <(awk 'NR>1{print $2}' psscan.txt | sort)
# Output: 1337

# Dump and search hidden process memory
python3 vol.py -f memory.raw windows.memmap --pid 1337 --dump
strings pid.1337.dmp | grep -i "flag{"
# flag{h1dd3n_pr0c3ss_f0und_d3adbeef}
```

---

## Lab 3: Credential Extraction from Network Capture

### Objective

Analyze `traffic.pcap` to extract plaintext credentials transmitted over the network, where the password is the flag.

### Scenario

The capture contains HTTP Basic Auth, FTP login, and Telnet sessions. Extract credentials from each protocol.

### Hints

1. Filter traffic by protocol using `tshark` or Wireshark.
2. HTTP Basic Auth is Base64-encoded — decode it.
3. FTP sends `USER` and `PASS` commands in plaintext.
4. Use `strings traffic.pcap | grep -i "pass\|login"` for quick scanning.

### Solution

```bash
# HTTP Basic Auth
tshark -r traffic.pcap -Y "http.authorization contains Basic" \
    -T fields -e http.authorization | \
    sed 's/Basic //' | base64 -d
# admin:flag{bas364_cr3ds_exposed}

# FTP credentials
tshark -r traffic.pcap \
    -Y "ftp.request.command == USER or ftp.request.command == PASS" \
    -T fields -e ftp.request.command -e ftp.request.arg
# PASS  flag{ftp_plaintext_bad_idea}
```

Automated extraction — see `extract_credentials.py` in the Korean section above.
