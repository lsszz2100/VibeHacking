# 인시던트 대응 (Incident Response)

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
    3306: b"\x4a\x00\x00\x00\x0a\x38\x2e\x30\x2e\x33\x33",  # MySQL 핸드쉐이크 모방
    3389: b"\x03\x00\x00\x0b\x06\xd0\x00\x00\x12\x34\x00",   # RDP 모방
}

def handle_connection(conn: socket.socket, addr: tuple, port: int) -> None:
    ip, client_port = addr
    logging.warning(f"[연결] {ip}:{client_port} → 포트 {port}")

    try:
        if port in FAKE_BANNERS:
            conn.send(FAKE_BANNERS[port])
        data = conn.recv(4096)
        if data:
            logging.warning(f"[데이터] {ip} → {data[:200]!r}")
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
                logging.info(f"[*] 허니팟 리스닝: 포트 {p}")
                while True:
                    conn, addr = srv.accept()
                    threading.Thread(
                        target=handle_connection, args=(conn, addr, p), daemon=True
                    ).start()
            except PermissionError:
                logging.error(f"포트 {p} 열기 실패 (root 권한 필요)")

        threading.Thread(target=listen, args=(port,), daemon=True).start()

def main() -> None:
    parser = argparse.ArgumentParser(description="다중 포트 허니팟")
    parser.add_argument(
        "--ports", nargs="+", type=int,
        default=[21, 22, 23, 25, 80, 3306, 3389]
    )
    args = parser.parse_args()

    start_honeypot(args.ports)
    logging.info("[*] 허니팟 실행 중. Ctrl+C로 종료.")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        logging.info("종료")

if __name__ == "__main__":
    main()
```
