> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 인시던트 대응 (Incident Response)

## 0. 초보자를 위한 개념 이해

### CTI와 인시던트 대응의 관계

**CTI(위협 인텔리전스)와 IR(인시던트 대응)**은 서로 긴밀하게 연결됩니다.

```
CTI → IR 관계:
  CTI가 제공하는 것:
  - 공격자의 TTP(전술, 기법, 절차)
  - IOC(침해 지표) 목록
  - 공격 그룹 정보
  
  IR팀이 사용하는 방법:
  - CTI IOC로 감염 범위 파악
  - TTP 기반으로 공격 단계 예측
  - 같은 그룹의 다른 공격 선제 차단

예시:
  Lazarus Group의 랜섬웨어 공격 발생
  → CTI에서 Lazarus 사용 IOC 확인
  → 내부 시스템에서 동일 IOC 탐색
  → 추가 감염 시스템 발견
  → 선제 격리로 피해 최소화
```

### IR팀의 역할

```
SOC (Security Operations Center):
  24/7 모니터링
  초기 탐지 및 분류
  
CSIRT (Computer Security Incident Response Team):
  보안 사고 전문 대응팀
  더 심각한 사고 처리
  
DFIR (Digital Forensics and Incident Response):
  디지털 포렌식 + 사고 대응
  법적 증거 수집 가능
```

### 사고 심각도 분류

```
P1 (Critical/심각):
  - 전사 시스템 마비
  - 대규모 데이터 유출
  - 국가 기반 시설 침해
  → 즉각 대응, C레벨 보고

P2 (High/높음):
  - 중요 시스템 침해
  - 랜섬웨어 감염
  → 1시간 내 대응

P3 (Medium/중간):
  - 단일 시스템 침해
  - 의심스러운 계정 활동
  → 4시간 내 대응

P4 (Low/낮음):
  - 스캔 시도
  - 스팸 이메일
  → 24시간 내 검토
```

---

## 1. IR 프레임워크

```
NIST SP 800-61 사이클:

  준비(Preparation)
      ↓
  탐지·분석(Detection & Analysis)
      ↓
  격리·박멸(Containment & Eradication)
      ↓
  복구(Recovery)
      ↓
  사후 검토(Post-Incident Activity)
      ↑_____________________________|

SANS PICERL:
  Preparation → Identification → Containment
  → Eradication → Recovery → Lessons Learned
```

---

## 2. 탐지 및 분류

### 2-1. 심각도 분류

```
P1 — 긴급 (2시간 내 대응)
  - 활성 랜섬웨어 확산 중
  - 중요 시스템 완전 장악 확인
  - 대규모 데이터 유출 진행 중

P2 — 높음 (4시간 내 대응)
  - 내부 횡이동(Lateral Movement) 탐지
  - APT 침해 의심
  - 크리티컬 인프라 이상 징후

P3 — 중간 (24시간 내 대응)
  - 단일 엔드포인트 악성코드 감염
  - 피싱 메일 클릭 사고
  - 계정 크레덴셜 유출

P4 — 낮음 (72시간 내 대응)
  - 스캔 시도 감지
  - 정책 위반 (USB 연결 등)
```

### 2-2. 초기 분류 체크리스트

```bash
# 의심 시스템 기본 정보 수집
hostname && whoami && id
uname -a && uptime
date && last -n 20

# 네트워크 연결 상태
ss -tulpn
netstat -anp | grep ESTABLISHED
lsof -i -n

# 실행 중인 프로세스
ps auxf
pstree -ap

# 최근 로그인 및 명령 이력
last -n 50
cat /var/log/auth.log | tail -100
cat ~/.bash_history

# 예약 작업
crontab -l
systemctl list-units --type=service --state=running
ls /etc/cron.* /var/spool/cron/
```

---

## 3. 포렌식 이미징 및 증거 수집

### 3-1. 메모리 덤프

```bash
# LiME (Linux Memory Extractor) 커널 모듈
insmod lime-$(uname -r).ko "path=/evidence/memory.lime format=lime"

# avml (Microsoft) — 커널 모듈 없이 메모리 수집
./avml /evidence/memory.raw

# Windows WinPMEM
winpmem_mini_x64_rc2.exe /evidence/memory.raw

# Volatility3으로 분석
vol -f memory.lime linux.pslist
vol -f memory.lime linux.pstree
vol -f memory.lime linux.netstat
vol -f memory.lime linux.bash
```

### 3-2. 디스크 이미징


인시던트 대응 시 메모리와 디스크 포렌식 이미지를 수집합니다. 메모리는 가장 휘발성이 높은 증거이므로 가장 먼저 덤프해야 하며, 디스크 이미지는 쓰기 방지 장치를 사용하여 원본을 보존합니다.

```bash
# dd로 이미지 생성 (해시 포함)
dd if=/dev/sda bs=4M conv=sync,noerror \
  | tee /evidence/disk.img \
  | sha256sum > /evidence/disk.sha256

# dcfldd — 해시 계산 동시 진행
dcfldd if=/dev/sda of=/evidence/disk.img \
  hash=sha256 hashlog=/evidence/disk.hash \
  bs=4M

# ewfacquire — EWF 포렌식 형식
ewfacquire /dev/sda -t /evidence/disk -c best \
  -e "Case: IR-2026-001" -d "Incident disk"
```

### 3-3. 로그 수집 자동화


인시던트 대응 자동화 스크립트입니다. 여러 시스템에서 동시에 포렌식 증거를 수집하고, IoC를 자동 매칭하며, 타임라인을 생성하여 사고 조사 시간을 단축합니다.

```python
import subprocess
import tarfile
import shutil
import argparse
from pathlib import Path
from datetime import datetime

LOG_DIRS = [
    "/var/log",
    "/var/log/apache2",
    "/var/log/nginx",
    "/var/log/mysql",
    "/var/log/auth.log",
    "/var/log/syslog",
    "/etc/cron.d",
    "/etc/cron.daily",
    "/etc/cron.hourly",
    "/tmp",
    "/var/tmp",
]

SHELL_HISTORY = [
    Path.home() / ".bash_history",
    Path.home() / ".zsh_history",
    Path("/root/.bash_history"),
]

def collect_evidence(output_dir: str) -> None:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = Path(output_dir) / f"evidence_{ts}"
    base.mkdir(parents=True, exist_ok=True)

    print(f"[*] 증거 수집 시작: {base}")

    # 시스템 정보 수집
    cmds = {
        "ps_aux.txt":     ["ps", "auxf"],
        "netstat.txt":    ["ss", "-tulpn"],
        "connections.txt":["ss", "-anp"],
        "last.txt":       ["last", "-n", "100"],
        "lsof.txt":       ["lsof", "-n"],
        "crontab.txt":    ["crontab", "-l"],
        "systemctl.txt":  ["systemctl", "list-units", "--type=service"],
    }
    for fname, cmd in cmds.items():
        try:
            out = subprocess.run(cmd, capture_output=True, text=True).stdout
            (base / fname).write_text(out)
            print(f"  [+] {fname}")
        except Exception as e:
            print(f"  [!] {fname} 실패: {e}")

    # 쉘 히스토리
    for hist in SHELL_HISTORY:
        if hist.exists():
            dst = base / hist.name
            shutil.copy2(hist, dst)
            print(f"  [+] {hist}")

    # 로그 아카이브
    archive_path = base / "logs.tar.gz"
    with tarfile.open(archive_path, "w:gz") as tar:
        for log_path in LOG_DIRS:
            p = Path(log_path)
            if p.exists():
                try:
                    tar.add(p, arcname=str(p))
                    print(f"  [+] 로그 추가: {p}")
                except PermissionError:
                    pass

    # 해시 계산
    import hashlib
    hash_file = base / "hashes.txt"
    with hash_file.open("w") as hf:
        for f in base.rglob("*"):
            if f.is_file() and f != hash_file:
                sha256 = hashlib.sha256(f.read_bytes()).hexdigest()
                hf.write(f"{sha256}  {f.name}\n")

    print(f"\n[+] 수집 완료: {base}")

def main() -> None:
    parser = argparse.ArgumentParser(description="인시던트 증거 수집")
    parser.add_argument("--output", "-o", default="/tmp/evidence")
    args = parser.parse_args()
    collect_evidence(args.output)

if __name__ == "__main__":
    main()
```

---

## 4. 타임라인 재구성


인시던트 대응 자동화 스크립트입니다. 여러 시스템에서 동시에 포렌식 증거를 수집하고, IoC를 자동 매칭하며, 타임라인을 생성하여 사고 조사 시간을 단축합니다.

```python
import re
import argparse
from datetime import datetime
from pathlib import Path

TIMESTAMP_PATTERNS = [
    # auth.log: Apr 20 13:45:22
    (r'(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})', "%b %d %H:%M:%S", "syslog"),
    # nginx/apache: [20/Apr/2026:13:45:22 +0900]
    (r'\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})', "%d/%b/%Y:%H:%M:%S", "web"),
    # ISO 8601: 2026-04-20T13:45:22
    (r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})', "%Y-%m-%dT%H:%M:%S", "iso"),
]

SUSPICIOUS_KEYWORDS = [
    "Failed password", "Invalid user", "sudo:", "su:",
    "wget", "curl", "chmod +x", "bash -i", "python -c",
    "base64", "/tmp/", "useradd", "passwd", "ssh",
    "crontab", "nc ", "ncat", "/dev/tcp",
]

def parse_log(log_path: str, start: datetime | None = None) -> list[tuple[datetime, str, str]]:
    events: list[tuple[datetime, str, str]] = []
    current_year = datetime.now().year

    for line in Path(log_path).read_text(errors="replace").splitlines():
        line_stripped = line.strip()
        if not line_stripped:
            continue

        ts_obj = None
        for pattern, fmt, src in TIMESTAMP_PATTERNS:
            m = re.search(pattern, line_stripped)
            if m:
                try:
                    ts_str = m.group(1)
                    if src == "syslog":
                        ts_obj = datetime.strptime(f"{current_year} {ts_str}", f"%Y {fmt}")
                    else:
                        ts_obj = datetime.strptime(ts_str, fmt)
                    break
                except ValueError:
                    continue

        if not ts_obj:
            continue
        if start and ts_obj < start:
            continue

        # 의심 키워드 포함 이벤트만 수집
        for kw in SUSPICIOUS_KEYWORDS:
            if kw.lower() in line_stripped.lower():
                events.append((ts_obj, kw, line_stripped[:200]))
                break

    return sorted(events, key=lambda x: x[0])

def build_timeline(log_files: list[str]) -> None:
    all_events: list[tuple[datetime, str, str, str]] = []
    for lf in log_files:
        events = parse_log(lf)
        all_events.extend((ts, kw, line, lf) for ts, kw, line in events)

    all_events.sort(key=lambda x: x[0])

    print(f"\n[*] 침해 타임라인 — 의심 이벤트 {len(all_events)}건\n")
    for ts, kw, line, src in all_events[:100]:
        print(f"  [{ts.strftime('%m-%d %H:%M:%S')}] [{kw}]")
        print(f"    {Path(src).name}: {line[:120]}")

def main() -> None:
    parser = argparse.ArgumentParser(description="침해 타임라인 재구성")
    parser.add_argument("logs", nargs="+", help="분석할 로그 파일들")
    args = parser.parse_args()
    build_timeline(args.logs)

if __name__ == "__main__":
    main()
```

---

## 5. 격리 및 박멸

```bash
# 네트워크 격리 (즉시 실행)
# 방법 1: 인터페이스 다운
ip link set eth0 down

# 방법 2: 모든 연결 차단 (SSH 제외)
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP
iptables -A INPUT  -s [관리자IP] -p tcp --dport 22 -j ACCEPT
iptables -A OUTPUT -d [관리자IP] -p tcp --sport 22 -j ACCEPT

# 의심 프로세스 종료
kill -9 <PID>
# 또는 컨테이너라면
docker stop <container_id>

# 악성코드 지속성 제거
# crontab
crontab -r
crontab -r -u root

# systemd 서비스
systemctl disable malicious.service
systemctl stop malicious.service
rm /etc/systemd/system/malicious.service
systemctl daemon-reload

# 악성 파일 격리 (삭제 전 보존)
mkdir -p /evidence/malware
mv /tmp/suspicious_binary /evidence/malware/
sha256sum /evidence/malware/suspicious_binary > /evidence/malware/hash.txt
```

---

## 6. 허니팟 구축


인시던트 대응 자동화 스크립트입니다. 여러 시스템에서 동시에 포렌식 증거를 수집하고, IoC를 자동 매칭하며, 타임라인을 생성하여 사고 조사 시간을 단축합니다.

```python
import socket
import threading
import logging
import argparse
from datetime import datetime
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(message)s",
    handlers=[
        logging.FileHandler("honeypot.log"),
        logging.StreamHandler(),
    ]
)

FAKE_BANNERS = {
    21:  b"220 FTP server ready\r\n",
    22:  b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n",
    23:  b"\xff\xfb\x01\xff\xfb\x03\xff\xfd\x18\xff\xfd\x1f",
    25:  b"220 mail.example.com ESMTP Postfix\r\n",
    80:  b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.51\r\n\r\n<html><body>Welcome</body></html>",
    443: b"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n\r\n",
    3306: b"\x4a\x00\x00\x00\x0a\x38\x2e\x30\x2e\x33\x33",  # MySQL handshake imitation
    3389: b"\x03\x00\x00\x0b\x06\xd0\x00\x00\x12\x34\x00",   # RDP imitation
}

def handle_connection(conn: socket.socket, addr: tuple, port: int) -> None:
    ip, client_port = addr
    logging.warning(f"[Connection] {ip}:{client_port} → port {port}")

    try:
        if port in FAKE_BANNERS:
            conn.send(FAKE_BANNERS[port])
        data = conn.recv(4096)
        if data:
            logging.warning(f"[Data] {ip} → {data[:200]!r}")
    except Exception:
        pass
    finally:
        conn.close()

def start_honeypot(ports: list[int]) -> None:
    for port in ports:
        def listen(p: int) -> None:
            try:
                srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                srv.bind(("0.0.0.0", p))
                srv.listen(5)
                logging.info(f"[*] Honeypot listening: port {p}")
                while True:
                    conn, addr = srv.accept()
                    threading.Thread(
                        target=handle_connection, args=(conn, addr, p), daemon=True
                    ).start()
            except PermissionError:
                logging.error(f"Failed to open port {p} (root privileges required)")

        threading.Thread(target=listen, args=(port,), daemon=True).start()

def main() -> None:
    parser = argparse.ArgumentParser(description="Multi-port Honeypot")
    parser.add_argument(
        "--ports", nargs="+", type=int,
        default=[21, 22, 23, 25, 80, 3306, 3389]
    )
    args = parser.parse_args()

    start_honeypot(args.ports)
    logging.info("[*] Honeypot running. Press Ctrl+C to stop.")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        logging.info("Stopped")

if __name__ == "__main__":
    main()
```

---

<a name="english"></a>

# Incident Response (IR)

## 1. IR Frameworks

```
NIST SP 800-61 Cycle:

  Preparation
      ↓
  Detection & Analysis
      ↓
  Containment & Eradication
      ↓
  Recovery
      ↓
  Post-Incident Activity
      ↑_____________________________|

SANS PICERL:
  Preparation → Identification → Containment
  → Eradication → Recovery → Lessons Learned
```

---

## 2. Detection and Triage

### 2-1. Severity Classification

```
P1 — Critical (respond within 2 hours)
  - Active ransomware spreading
  - Confirmed full compromise of critical systems
  - Ongoing large-scale data exfiltration

P2 — High (respond within 4 hours)
  - Lateral movement detected internally
  - Suspected APT compromise
  - Anomalous behavior in critical infrastructure

P3 — Medium (respond within 24 hours)
  - Single endpoint malware infection
  - Phishing email click incident
  - Account credential leak

P4 — Low (respond within 72 hours)
  - Scan attempt detected
  - Policy violation (unauthorized USB connection, etc.)
```

### 2-2. Initial Triage Checklist

```bash
# Collect basic information from the suspicious system
hostname && whoami && id
uname -a && uptime
date && last -n 20

# Network connection status
ss -tulpn
netstat -anp | grep ESTABLISHED
lsof -i -n

# Running processes
ps auxf
pstree -ap

# Recent logins and command history
last -n 50
cat /var/log/auth.log | tail -100
cat ~/.bash_history

# Scheduled tasks
crontab -l
systemctl list-units --type=service --state=running
ls /etc/cron.* /var/spool/cron/
```

---

## 3. Forensic Imaging and Evidence Collection

### 3-1. Memory Dump

```bash
# LiME (Linux Memory Extractor) kernel module
insmod lime-$(uname -r).ko "path=/evidence/memory.lime format=lime"

# avml (Microsoft) — memory collection without a kernel module
./avml /evidence/memory.raw

# Windows WinPMEM
winpmem_mini_x64_rc2.exe /evidence/memory.raw

# Analyze with Volatility3
vol -f memory.lime linux.pslist
vol -f memory.lime linux.pstree
vol -f memory.lime linux.netstat
vol -f memory.lime linux.bash
```

### 3-2. Disk Imaging

Collect memory and disk forensic images during incident response. Memory is the most volatile evidence and must be dumped first; disk images should use write blockers to preserve the original.

```bash
# Create image with dd (including hash)
dd if=/dev/sda bs=4M conv=sync,noerror \
  | tee /evidence/disk.img \
  | sha256sum > /evidence/disk.sha256

# dcfldd — compute hash concurrently
dcfldd if=/dev/sda of=/evidence/disk.img \
  hash=sha256 hashlog=/evidence/disk.hash \
  bs=4M

# ewfacquire — EWF forensic format
ewfacquire /dev/sda -t /evidence/disk -c best \
  -e "Case: IR-2026-001" -d "Incident disk"
```

### 3-3. Log Collection Automation

An incident response automation script. Simultaneously collects forensic evidence from multiple systems, automatically matches IoCs, and generates timelines to speed up investigation.

```python
import subprocess
import tarfile
import shutil
import argparse
from pathlib import Path
from datetime import datetime

LOG_DIRS = [
    "/var/log",
    "/var/log/apache2",
    "/var/log/nginx",
    "/var/log/mysql",
    "/var/log/auth.log",
    "/var/log/syslog",
    "/etc/cron.d",
    "/etc/cron.daily",
    "/etc/cron.hourly",
    "/tmp",
    "/var/tmp",
]

SHELL_HISTORY = [
    Path.home() / ".bash_history",
    Path.home() / ".zsh_history",
    Path("/root/.bash_history"),
]

def collect_evidence(output_dir: str) -> None:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = Path(output_dir) / f"evidence_{ts}"
    base.mkdir(parents=True, exist_ok=True)

    print(f"[*] Evidence collection started: {base}")

    # Collect system information
    cmds = {
        "ps_aux.txt":     ["ps", "auxf"],
        "netstat.txt":    ["ss", "-tulpn"],
        "connections.txt":["ss", "-anp"],
        "last.txt":       ["last", "-n", "100"],
        "lsof.txt":       ["lsof", "-n"],
        "crontab.txt":    ["crontab", "-l"],
        "systemctl.txt":  ["systemctl", "list-units", "--type=service"],
    }
    for fname, cmd in cmds.items():
        try:
            out = subprocess.run(cmd, capture_output=True, text=True).stdout
            (base / fname).write_text(out)
            print(f"  [+] {fname}")
        except Exception as e:
            print(f"  [!] {fname} failed: {e}")

    # Shell history
    for hist in SHELL_HISTORY:
        if hist.exists():
            dst = base / hist.name
            shutil.copy2(hist, dst)
            print(f"  [+] {hist}")

    # Log archive
    archive_path = base / "logs.tar.gz"
    with tarfile.open(archive_path, "w:gz") as tar:
        for log_path in LOG_DIRS:
            p = Path(log_path)
            if p.exists():
                try:
                    tar.add(p, arcname=str(p))
                    print(f"  [+] Log added: {p}")
                except PermissionError:
                    pass

    # Compute hashes
    import hashlib
    hash_file = base / "hashes.txt"
    with hash_file.open("w") as hf:
        for f in base.rglob("*"):
            if f.is_file() and f != hash_file:
                sha256 = hashlib.sha256(f.read_bytes()).hexdigest()
                hf.write(f"{sha256}  {f.name}\n")

    print(f"\n[+] Collection complete: {base}")

def main() -> None:
    parser = argparse.ArgumentParser(description="Incident Evidence Collection")
    parser.add_argument("--output", "-o", default="/tmp/evidence")
    args = parser.parse_args()
    collect_evidence(args.output)

if __name__ == "__main__":
    main()
```

---

## 4. Timeline Reconstruction

An incident response automation script. Collects forensic evidence from multiple systems simultaneously, automatically matches IoCs, and generates timelines to reduce investigation time.

```python
import re
import argparse
from datetime import datetime
from pathlib import Path

TIMESTAMP_PATTERNS = [
    # auth.log: Apr 20 13:45:22
    (r'(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})', "%b %d %H:%M:%S", "syslog"),
    # nginx/apache: [20/Apr/2026:13:45:22 +0900]
    (r'\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})', "%d/%b/%Y:%H:%M:%S", "web"),
    # ISO 8601: 2026-04-20T13:45:22
    (r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})', "%Y-%m-%dT%H:%M:%S", "iso"),
]

SUSPICIOUS_KEYWORDS = [
    "Failed password", "Invalid user", "sudo:", "su:",
    "wget", "curl", "chmod +x", "bash -i", "python -c",
    "base64", "/tmp/", "useradd", "passwd", "ssh",
    "crontab", "nc ", "ncat", "/dev/tcp",
]

def parse_log(log_path: str, start: datetime | None = None) -> list[tuple[datetime, str, str]]:
    events: list[tuple[datetime, str, str]] = []
    current_year = datetime.now().year

    for line in Path(log_path).read_text(errors="replace").splitlines():
        line_stripped = line.strip()
        if not line_stripped:
            continue

        ts_obj = None
        for pattern, fmt, src in TIMESTAMP_PATTERNS:
            m = re.search(pattern, line_stripped)
            if m:
                try:
                    ts_str = m.group(1)
                    if src == "syslog":
                        ts_obj = datetime.strptime(f"{current_year} {ts_str}", f"%Y {fmt}")
                    else:
                        ts_obj = datetime.strptime(ts_str, fmt)
                    break
                except ValueError:
                    continue

        if not ts_obj:
            continue
        if start and ts_obj < start:
            continue

        # Collect only events containing suspicious keywords
        for kw in SUSPICIOUS_KEYWORDS:
            if kw.lower() in line_stripped.lower():
                events.append((ts_obj, kw, line_stripped[:200]))
                break

    return sorted(events, key=lambda x: x[0])

def build_timeline(log_files: list[str]) -> None:
    all_events: list[tuple[datetime, str, str, str]] = []
    for lf in log_files:
        events = parse_log(lf)
        all_events.extend((ts, kw, line, lf) for ts, kw, line in events)

    all_events.sort(key=lambda x: x[0])

    print(f"\n[*] Compromise Timeline — {len(all_events)} suspicious events\n")
    for ts, kw, line, src in all_events[:100]:
        print(f"  [{ts.strftime('%m-%d %H:%M:%S')}] [{kw}]")
        print(f"    {Path(src).name}: {line[:120]}")

def main() -> None:
    parser = argparse.ArgumentParser(description="Compromise Timeline Reconstruction")
    parser.add_argument("logs", nargs="+", help="Log files to analyze")
    args = parser.parse_args()
    build_timeline(args.logs)

if __name__ == "__main__":
    main()
```

---

## 5. Containment and Eradication

```bash
# Network isolation (execute immediately)
# Method 1: Bring down the interface
ip link set eth0 down

# Method 2: Block all connections (except SSH)
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP
iptables -A INPUT  -s [AdminIP] -p tcp --dport 22 -j ACCEPT
iptables -A OUTPUT -d [AdminIP] -p tcp --sport 22 -j ACCEPT

# Terminate suspicious processes
kill -9 <PID>
# Or for containers
docker stop <container_id>

# Remove malware persistence
# crontab
crontab -r
crontab -r -u root

# systemd service
systemctl disable malicious.service
systemctl stop malicious.service
rm /etc/systemd/system/malicious.service
systemctl daemon-reload

# Quarantine malicious files (preserve before deletion)
mkdir -p /evidence/malware
mv /tmp/suspicious_binary /evidence/malware/
sha256sum /evidence/malware/suspicious_binary > /evidence/malware/hash.txt
```

---

## 6. Honeypot Deployment

An incident response automation script. Simultaneously collects forensic evidence from multiple systems, automatically matches IoCs, and generates timelines to speed up investigation.

```python
import socket
import threading
import logging
import argparse
from datetime import datetime
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(message)s",
    handlers=[
        logging.FileHandler("honeypot.log"),
        logging.StreamHandler(),
    ]
)

FAKE_BANNERS = {
    21:  b"220 FTP server ready\r\n",
    22:  b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n",
    23:  b"\xff\xfb\x01\xff\xfb\x03\xff\xfd\x18\xff\xfd\x1f",
    25:  b"220 mail.example.com ESMTP Postfix\r\n",
    80:  b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.51\r\n\r\n<html><body>Welcome</body></html>",
    443: b"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n\r\n",
    3306: b"\x4a\x00\x00\x00\x0a\x38\x2e\x30\x2e\x33\x33",  # MySQL handshake imitation
    3389: b"\x03\x00\x00\x0b\x06\xd0\x00\x00\x12\x34\x00",   # RDP imitation
}

def handle_connection(conn: socket.socket, addr: tuple, port: int) -> None:
    ip, client_port = addr
    logging.warning(f"[Connection] {ip}:{client_port} → port {port}")

    try:
        if port in FAKE_BANNERS:
            conn.send(FAKE_BANNERS[port])
        data = conn.recv(4096)
        if data:
            logging.warning(f"[Data] {ip} → {data[:200]!r}")
    except Exception:
        pass
    finally:
        conn.close()

def start_honeypot(ports: list[int]) -> None:
    for port in ports:
        def listen(p: int) -> None:
            try:
                srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                srv.bind(("0.0.0.0", p))
                srv.listen(5)
                logging.info(f"[*] Honeypot listening: port {p}")
                while True:
                    conn, addr = srv.accept()
                    threading.Thread(
                        target=handle_connection, args=(conn, addr, p), daemon=True
                    ).start()
            except PermissionError:
                logging.error(f"Failed to open port {p} (root privileges required)")

        threading.Thread(target=listen, args=(port,), daemon=True).start()

def main() -> None:
    parser = argparse.ArgumentParser(description="Multi-port Honeypot")
    parser.add_argument(
        "--ports", nargs="+", type=int,
        default=[21, 22, 23, 25, 80, 3306, 3389]
    )
    args = parser.parse_args()

    start_honeypot(args.ports)
    logging.info("[*] Honeypot running. Press Ctrl+C to stop.")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        logging.info("Stopped")

if __name__ == "__main__":
    main()
```
