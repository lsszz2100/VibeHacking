> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>
# Linux 보안 도구 모음

Linux 환경에서 보안 전문가가 반드시 숙지해야 할 핵심 도구들을 다룬다. 네트워크 분석부터 파일 무결성 검사, 사용자·프로세스 감사, 방화벽 설정, 그리고 Python 기반 시스템 모니터링 CLI까지 실무 중심으로 정리한다.

---

## 1. 네트워크 도구

### 1.1 nmap — 포트 스캐너

```bash
# 기본 TCP SYN 스캔
nmap -sS -T4 192.168.1.0/24

# 서비스 버전 + OS 탐지
nmap -sV -O -A 192.168.1.100

# NSE 스크립트로 취약점 점검
nmap --script vuln 192.168.1.100

# UDP 스캔 (느리지만 중요한 서비스 발견)
nmap -sU --top-ports 100 192.168.1.100

# 출력 저장 (XML + 일반 텍스트)
nmap -sS -oX scan.xml -oN scan.txt 192.168.1.0/24
```

**주요 플래그 정리**

| 플래그 | 의미 |
|--------|------|
| `-sS` | SYN 스텔스 스캔 (루트 권한 필요) |
| `-sV` | 서비스 버전 탐지 |
| `-p-` | 전체 65535 포트 스캔 |
| `-T0~5` | 타이밍 (0=느림, 5=공격적) |
| `--open` | 열린 포트만 출력 |

### 1.2 netcat (nc) — 네트워크 스위스아미 나이프

```bash
# 포트 리스닝 (서버 역할)
nc -lvnp 4444

# 원격 호스트에 연결
nc 192.168.1.100 4444

# 배너 그래빙
echo "" | nc -w1 192.168.1.100 22

# 파일 전송 (수신 측)
nc -lvnp 9999 > received_file.bin

# 파일 전송 (송신 측)
nc 192.168.1.100 9999 < /path/to/file.bin

# 포트 스캔
nc -zv 192.168.1.100 20-1024 2>&1 | grep succeeded
```

### 1.3 tcpdump — 패킷 캡처

```bash
# 특정 인터페이스에서 캡처
tcpdump -i eth0

# HTTP 트래픽만 필터
tcpdump -i eth0 -A port 80

# 특정 호스트와의 트래픽
tcpdump -i eth0 host 192.168.1.100

# pcap 파일로 저장
tcpdump -i eth0 -w capture.pcap

# 저장된 pcap 분석
tcpdump -r capture.pcap -n 'tcp[tcpflags] & tcp-syn != 0'

# SYN 플러드 탐지 패턴
tcpdump -i eth0 'tcp[13] == 2' | awk '{print $3}' | cut -d. -f1-4 | sort | uniq -c | sort -rn | head -20
```

### 1.4 ss — 소켓 통계

```bash
# 모든 TCP 연결 보기
ss -tnp

# LISTEN 상태만
ss -tlnp

# UDP 소켓
ss -unlp

# 특정 포트 필터
ss -tnp sport = :443

# 연결 상태 요약
ss -s

# 프로세스 정보 포함 (루트 권한)
sudo ss -tnpe
```

---

## 2. 파일 무결성 검사

### 2.1 sha256sum 스크립트

```bash
# 단일 파일 해시 생성
sha256sum /bin/bash > /etc/baseline_hashes/bash.sha256

# 디렉토리 전체 해시 기록
find /bin /sbin /usr/bin /usr/sbin -type f \
  | sort | xargs sha256sum > /etc/baseline_hashes/system_baseline.sha256

# 기준값 대비 변경 탐지
sha256sum --check /etc/baseline_hashes/system_baseline.sha256 2>&1 \
  | grep -v ": OK" | tee /var/log/integrity_alerts.log
```

### 2.2 AIDE (Advanced Intrusion Detection Environment)

```bash
# AIDE 설치 (Debian/Ubuntu)
sudo apt install aide

# 초기 데이터베이스 생성
sudo aideinit
sudo cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db

# 무결성 검사 실행
sudo aide --check

# 데이터베이스 갱신 (정상 변경 후)
sudo aide --update
```

`/etc/aide/aide.conf` 핵심 설정:

```
# 감시 규칙 정의
NORMAL = p+i+n+u+g+s+m+acl+sha256
# p=권한, i=inode, n=링크수, u=uid, g=gid, s=파일크기, m=수정시간

/bin    NORMAL
/sbin   NORMAL
/etc    NORMAL
!/etc/mtab   # 제외 항목
```

### 2.3 Tripwire (엔터프라이즈급)

```bash
# 설치 및 초기화
sudo apt install tripwire
sudo twadmin --generate-keys
sudo tripwire --init

# 검사 실행
sudo tripwire --check

# 보고서 조회
sudo twprint --print-report -r /var/lib/tripwire/report/$(ls /var/lib/tripwire/report/ | tail -1)
```

---

## 3. 사용자 및 프로세스 감사

### 3.1 auditd — 커널 레벨 감사

```bash
# auditd 설치 및 시작
sudo apt install auditd
sudo systemctl enable --now auditd

# 감사 규칙 추가 (실시간)
sudo auditctl -w /etc/passwd -p wa -k passwd_changes
sudo auditctl -w /etc/sudoers -p wa -k sudoers_changes
sudo auditctl -a always,exit -F arch=b64 -S execve -k exec_tracking

# 현재 규칙 확인
sudo auditctl -l

# 로그 검색
sudo ausearch -k passwd_changes
sudo ausearch -k exec_tracking --start today

# 보고서 생성
sudo aureport --summary
sudo aureport --auth  # 인증 이벤트
sudo aureport --failed  # 실패한 이벤트
```

`/etc/audit/rules.d/security.rules` 예시:

```
# 시스템 호출 감사
-a always,exit -F arch=b64 -S open,openat -F exit=-EPERM -k access_denied
-a always,exit -F arch=b64 -S ptrace -k ptrace_calls
-w /sbin/insmod -p x -k kernel_modules
-w /sbin/rmmod  -p x -k kernel_modules
-w /etc/cron.d  -p wa -k cron_changes
```

### 3.2 lsof — 열린 파일/소켓 분석

```bash
# 특정 포트 사용 프로세스 확인
sudo lsof -i :80
sudo lsof -i :4444

# 특정 프로세스의 파일
sudo lsof -p 1234

# 삭제됐지만 열려 있는 파일 (디스크 누수)
sudo lsof +L1

# 네트워크 연결 전체
sudo lsof -i -n -P

# 특정 사용자의 모든 파일
sudo lsof -u suspicious_user
```

### 3.3 ps로 의심 프로세스 분석

```bash
# 숨겨진 프로세스 탐색 (ps vs /proc 비교)
comm -23 <(ps aux | awk '{print $2}' | sort -n) \
         <(ls /proc | grep '^[0-9]' | sort -n)

# CPU/메모리 상위 프로세스
ps aux --sort=-%cpu | head -20
ps aux --sort=-%mem | head -20

# 프로세스 트리
ps auxf | grep -A5 suspicious_process

# 프로세스 환경변수 확인 (루트)
sudo cat /proc/<PID>/environ | tr '\0' '\n'

# 프로세스 실행 경로
sudo ls -la /proc/<PID>/exe
```

---

## 4. 방화벽 기초

### 4.1 iptables 규칙 작성

```bash
# 기본 정책 설정 (DROP 기본, 명시적 허용)
sudo iptables -P INPUT DROP
sudo iptables -P FORWARD DROP
sudo iptables -P OUTPUT ACCEPT

# 루프백 허용
sudo iptables -A INPUT -i lo -j ACCEPT

# 수립된 연결 허용 (상태 기반)
sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# SSH 허용 (특정 IP만)
sudo iptables -A INPUT -s 192.168.1.0/24 -p tcp --dport 22 -j ACCEPT

# HTTP/HTTPS 허용
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# ICMP 핑 허용
sudo iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT

# 포트 스캔 탐지 및 차단
sudo iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
sudo iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP

# 규칙 저장
sudo iptables-save > /etc/iptables/rules.v4

# 규칙 목록 확인
sudo iptables -L -v -n --line-numbers
```

### 4.2 nftables (현대적 대안)

```bash
# nft 기본 테이블/체인 생성
sudo nft add table inet filter
sudo nft add chain inet filter input '{ type filter hook input priority 0; policy drop; }'
sudo nft add chain inet filter output '{ type filter hook output priority 0; policy accept; }'

# 규칙 추가
sudo nft add rule inet filter input iif lo accept
sudo nft add rule inet filter input ct state established,related accept
sudo nft add rule inet filter input ip saddr 192.168.1.0/24 tcp dport 22 accept
sudo nft add rule inet filter input tcp dport { 80, 443 } accept

# 규칙 확인
sudo nft list ruleset

# 파일로 저장
sudo nft list ruleset > /etc/nftables.conf
```

---

## 5. Python 시스템 모니터링 CLI 도구

아래 스크립트는 Linux 시스템의 CPU, 메모리, 네트워크 연결, 의심 프로세스를 실시간으로 모니터링한다.

```python
#!/usr/bin/env python3
"""
linux_monitor.py — Linux 시스템 보안 상태 모니터링 CLI
Python 3.10+ 필요, 외부 의존성: psutil

설치: pip install psutil
사용: python3 linux_monitor.py [--interval 5] [--watch cpu|mem|net|proc|all]
"""

import argparse
import os
import re
import socket
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import NamedTuple

try:
    import psutil
except ImportError:
    sys.exit("[ERROR] psutil 미설치. 실행: pip install psutil")


# ──────────────────────────────────────────────
# 데이터 구조
# ──────────────────────────────────────────────

@dataclass
class CpuSnapshot:
    percent: float
    per_core: list[float]
    load_avg: tuple[float, float, float]


@dataclass
class MemSnapshot:
    total_gb: float
    used_gb: float
    available_gb: float
    percent: float
    swap_used_gb: float
    swap_percent: float


@dataclass
class NetConn:
    local_addr: str
    remote_addr: str
    status: str
    pid: int
    process_name: str


@dataclass
class SuspiciousProcess:
    pid: int
    name: str
    cmdline: str
    cpu_percent: float
    mem_percent: float
    reason: str
    username: str


# ──────────────────────────────────────────────
# 수집 함수
# ──────────────────────────────────────────────

def collect_cpu() -> CpuSnapshot:
    percent = psutil.cpu_percent(interval=0.5)
    per_core = psutil.cpu_percent(interval=0.5, percpu=True)
    load_avg = psutil.getloadavg()
    return CpuSnapshot(percent=percent, per_core=per_core, load_avg=load_avg)


def collect_mem() -> MemSnapshot:
    vm = psutil.virtual_memory()
    sw = psutil.swap_memory()
    return MemSnapshot(
        total_gb=round(vm.total / 1e9, 2),
        used_gb=round(vm.used / 1e9, 2),
        available_gb=round(vm.available / 1e9, 2),
        percent=vm.percent,
        swap_used_gb=round(sw.used / 1e9, 2),
        swap_percent=sw.percent,
    )


def collect_net_connections() -> list[NetConn]:
    results: list[NetConn] = []
    for conn in psutil.net_connections(kind="inet"):
        if conn.status not in ("ESTABLISHED", "LISTEN"):
            continue
        laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "-"
        raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "-"
        try:
            proc = psutil.Process(conn.pid)
            pname = proc.name()
        except (psutil.NoSuchProcess, psutil.AccessDenied, TypeError):
            pname = "unknown"
        results.append(NetConn(
            local_addr=laddr,
            remote_addr=raddr,
            status=conn.status,
            pid=conn.pid or -1,
            process_name=pname,
        ))
    return results


SUSPICIOUS_PATTERNS: list[tuple[str, str]] = [
    (r"nc\s+-[lLe]", "netcat 리스너"),
    (r"bash\s+-i", "인터랙티브 쉘"),
    (r"/tmp/[a-zA-Z0-9]{8,}", "/tmp 임의 실행파일"),
    (r"python.*-c.*socket", "Python 소켓 원-라이너"),
    (r"curl.*\|\s*bash", "원격 스크립트 실행"),
    (r"wget.*-O.*\|", "wget 파이프"),
    (r"chmod.*\+s", "setuid 설정"),
    (r"base64.*--decode", "base64 디코딩"),
]


def collect_suspicious_processes(
    cpu_threshold: float = 80.0,
    mem_threshold: float = 50.0,
) -> list[SuspiciousProcess]:
    results: list[SuspiciousProcess] = []
    for proc in psutil.process_iter(
        ["pid", "name", "cmdline", "cpu_percent", "memory_percent", "username"]
    ):
        try:
            info = proc.info
            cmdline = " ".join(info["cmdline"] or [])
            reasons: list[str] = []

            # 패턴 기반 탐지
            for pattern, label in SUSPICIOUS_PATTERNS:
                if re.search(pattern, cmdline, re.IGNORECASE):
                    reasons.append(label)

            # 리소스 과다 사용
            cpu_p = info["cpu_percent"] or 0.0
            mem_p = info["memory_percent"] or 0.0
            if cpu_p >= cpu_threshold:
                reasons.append(f"CPU {cpu_p:.1f}%")
            if mem_p >= mem_threshold:
                reasons.append(f"MEM {mem_p:.1f}%")

            # /proc/<PID>/exe 심볼릭 링크가 끊긴 경우 (삭제된 실행파일)
            exe_path = Path(f"/proc/{info['pid']}/exe")
            if exe_path.exists():
                try:
                    target = os.readlink(exe_path)
                    if "(deleted)" in target:
                        reasons.append("삭제된 실행파일 실행 중")
                except PermissionError:
                    pass

            if reasons:
                results.append(SuspiciousProcess(
                    pid=info["pid"],
                    name=info["name"] or "",
                    cmdline=cmdline[:120],
                    cpu_percent=cpu_p,
                    mem_percent=mem_p,
                    reason=", ".join(reasons),
                    username=info["username"] or "?",
                ))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return results


# ──────────────────────────────────────────────
# 출력 함수
# ──────────────────────────────────────────────

BAR_WIDTH = 30
RESET = "\033[0m"
RED = "\033[91m"
YLW = "\033[93m"
GRN = "\033[92m"
CYN = "\033[96m"
BLD = "\033[1m"


def color_for(percent: float) -> str:
    if percent >= 80:
        return RED
    if percent >= 50:
        return YLW
    return GRN


def render_bar(percent: float) -> str:
    filled = int(BAR_WIDTH * percent / 100)
    bar = "█" * filled + "░" * (BAR_WIDTH - filled)
    c = color_for(percent)
    return f"{c}[{bar}]{RESET} {percent:5.1f}%"


def print_cpu(snap: CpuSnapshot) -> None:
    print(f"\n{BLD}{CYN}── CPU ──────────────────────────────{RESET}")
    print(f"  전체: {render_bar(snap.percent)}")
    print(f"  로드 평균 (1/5/15분): "
          f"{snap.load_avg[0]:.2f} / {snap.load_avg[1]:.2f} / {snap.load_avg[2]:.2f}")
    for i, p in enumerate(snap.per_core):
        print(f"  Core {i:2d}: {render_bar(p)}")


def print_mem(snap: MemSnapshot) -> None:
    print(f"\n{BLD}{CYN}── 메모리 ───────────────────────────{RESET}")
    print(f"  RAM : {render_bar(snap.percent)}  "
          f"({snap.used_gb:.1f} / {snap.total_gb:.1f} GB)")
    print(f"  Swap: {render_bar(snap.swap_percent)}  "
          f"(사용 {snap.swap_used_gb:.1f} GB)")


def print_net(conns: list[NetConn]) -> None:
    print(f"\n{BLD}{CYN}── 네트워크 연결 ({len(conns)}개) ───────────{RESET}")
    fmt = "  {:<6} {:<26} {:<26} {:<14} {}"
    print(fmt.format("PID", "로컬 주소", "원격 주소", "상태", "프로세스"))
    print("  " + "-" * 80)
    for c in sorted(conns, key=lambda x: x.status)[:30]:
        status_c = GRN if c.status == "ESTABLISHED" else YLW
        print(fmt.format(
            c.pid,
            c.local_addr[:25],
            c.remote_addr[:25],
            f"{status_c}{c.status}{RESET}",
            c.process_name,
        ))


def print_suspicious(procs: list[SuspiciousProcess]) -> None:
    print(f"\n{BLD}{CYN}── 의심 프로세스 ({len(procs)}개) ────────────{RESET}")
    if not procs:
        print(f"  {GRN}탐지된 의심 프로세스 없음{RESET}")
        return
    for p in procs:
        print(f"  {RED}[!]{RESET} PID={p.pid} user={p.username} name={p.name}")
        print(f"       이유: {YLW}{p.reason}{RESET}")
        print(f"       cmd : {p.cmdline}")


# ──────────────────────────────────────────────
# 메인
# ──────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="linux_monitor",
        description="Linux 시스템 보안 상태 모니터링 CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
예시:
  python3 linux_monitor.py                     # 전체 한 번 실행
  python3 linux_monitor.py --watch all --interval 10
  python3 linux_monitor.py --watch cpu,mem
  python3 linux_monitor.py --watch proc --cpu-threshold 90
        """,
    )
    parser.add_argument(
        "--watch",
        default="all",
        help="감시 항목 (cpu, mem, net, proc, all). 쉼표로 다중 선택. 기본: all",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=0.0,
        metavar="SEC",
        help="반복 주기 (초). 0이면 1회 실행. 기본: 0",
    )
    parser.add_argument(
        "--cpu-threshold",
        type=float,
        default=80.0,
        metavar="PCT",
        help="의심 CPU 임계값 (%%). 기본: 80",
    )
    parser.add_argument(
        "--mem-threshold",
        type=float,
        default=50.0,
        metavar="PCT",
        help="의심 메모리 임계값 (%%). 기본: 50",
    )
    return parser


def run_once(targets: set[str], args: argparse.Namespace) -> None:
    hostname = socket.gethostname()
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"\n{BLD}{'='*50}{RESET}")
    print(f"  호스트: {hostname}  |  시각: {ts}")
    print(f"{BLD}{'='*50}{RESET}")

    if "cpu" in targets or "all" in targets:
        print_cpu(collect_cpu())

    if "mem" in targets or "all" in targets:
        print_mem(collect_mem())

    if "net" in targets or "all" in targets:
        print_net(collect_net_connections())

    if "proc" in targets or "all" in targets:
        print_suspicious(
            collect_suspicious_processes(
                cpu_threshold=args.cpu_threshold,
                mem_threshold=args.mem_threshold,
            )
        )


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    targets = {t.strip().lower() for t in args.watch.split(",")}

    valid = {"cpu", "mem", "net", "proc", "all"}
    unknown = targets - valid
    if unknown:
        parser.error(f"알 수 없는 감시 항목: {unknown}. 선택 가능: {valid}")

    if args.interval > 0:
        try:
            while True:
                run_once(targets, args)
                time.sleep(args.interval)
        except KeyboardInterrupt:
            print(f"\n{YLW}모니터링 종료{RESET}")
    else:
        run_once(targets, args)


if __name__ == "__main__":
    main()
```

### 실행 예시

```bash
# 전체 한 번 확인
python3 linux_monitor.py

# 10초마다 CPU + 메모리 감시
python3 linux_monitor.py --watch cpu,mem --interval 10

# 의심 프로세스 탐지 (CPU 50% 이상)
python3 linux_monitor.py --watch proc --cpu-threshold 50

# 네트워크 연결만 5초마다
python3 linux_monitor.py --watch net --interval 5
```

---

## 6. 빠른 참조: 도구별 핵심 명령 한눈에 보기

| 목적 | 도구 | 핵심 명령 |
|------|------|----------|
| 포트 스캔 | nmap | `nmap -sS -sV -O target` |
| 연결 테스트 | netcat | `nc -lvnp 4444` |
| 패킷 분석 | tcpdump | `tcpdump -i eth0 -w out.pcap` |
| 소켓 현황 | ss | `ss -tnpe` |
| 파일 무결성 | AIDE | `aide --check` |
| 커널 감사 | auditd | `ausearch -k tag` |
| 열린 파일 | lsof | `lsof -i :port` |
| 방화벽 | iptables | `iptables -L -v -n` |

---

## 참고 자료

- [The Book of Secret Knowledge](https://github.com/trimstray/the-book-of-secret-knowledge) — 보안 전문가를 위한 명령어·도구·자료 모음

---

<a name="english"></a>
# Linux Security Tools Reference

This section covers essential security tools for Linux environments: network analysis, file integrity checking, user/process auditing, firewall configuration, and a Python-based system monitoring CLI.

---

## 1. Network Tools

### 1.1 nmap — Port Scanner

```bash
# Basic TCP SYN scan
nmap -sS -T4 192.168.1.0/24

# Service version + OS detection
nmap -sV -O -A 192.168.1.100

# Vulnerability check with NSE scripts
nmap --script vuln 192.168.1.100

# UDP scan
nmap -sU --top-ports 100 192.168.1.100

# Save output (XML + plain text)
nmap -sS -oX scan.xml -oN scan.txt 192.168.1.0/24
```

**Key Flags**

| Flag | Meaning |
|------|---------|
| `-sS` | SYN stealth scan (requires root) |
| `-sV` | Service version detection |
| `-p-` | Scan all 65535 ports |
| `-T0~5` | Timing (0=paranoid, 5=insane) |
| `--open` | Show only open ports |

### 1.2 netcat (nc) — Swiss Army Knife

```bash
# Listen on port (server mode)
nc -lvnp 4444

# Connect to remote host
nc 192.168.1.100 4444

# Banner grabbing
echo "" | nc -w1 192.168.1.100 22

# File transfer (receive)
nc -lvnp 9999 > received_file.bin

# File transfer (send)
nc 192.168.1.100 9999 < /path/to/file.bin

# Port scan
nc -zv 192.168.1.100 20-1024 2>&1 | grep succeeded
```

### 1.3 tcpdump — Packet Capture

```bash
# Capture on interface
tcpdump -i eth0

# Filter HTTP traffic
tcpdump -i eth0 -A port 80

# Traffic to/from specific host
tcpdump -i eth0 host 192.168.1.100

# Write to pcap file
tcpdump -i eth0 -w capture.pcap

# Analyze saved pcap
tcpdump -r capture.pcap -n 'tcp[tcpflags] & tcp-syn != 0'
```

### 1.4 ss — Socket Statistics

```bash
# All TCP connections
ss -tnp

# LISTEN state only
ss -tlnp

# UDP sockets
ss -unlp

# Filter by port
ss -tnp sport = :443

# Summary
ss -s
```

---

## 2. File Integrity Checking

### 2.1 sha256sum Script

```bash
# Generate hash for a file
sha256sum /bin/bash > /etc/baseline_hashes/bash.sha256

# Record entire directory
find /bin /sbin /usr/bin /usr/sbin -type f \
  | sort | xargs sha256sum > /etc/baseline_hashes/system_baseline.sha256

# Detect changes against baseline
sha256sum --check /etc/baseline_hashes/system_baseline.sha256 2>&1 \
  | grep -v ": OK" | tee /var/log/integrity_alerts.log
```

### 2.2 AIDE

```bash
sudo apt install aide
sudo aideinit
sudo cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
sudo aide --check
sudo aide --update   # after legitimate changes
```

---

## 3. User and Process Auditing

### 3.1 auditd — Kernel-level Auditing

```bash
# Add audit rules
sudo auditctl -w /etc/passwd -p wa -k passwd_changes
sudo auditctl -a always,exit -F arch=b64 -S execve -k exec_tracking

# Search logs
sudo ausearch -k passwd_changes
sudo aureport --summary
```

### 3.2 lsof — Open Files and Sockets

```bash
sudo lsof -i :80           # process using port 80
sudo lsof -p 1234          # files opened by PID 1234
sudo lsof +L1              # deleted-but-open files
sudo lsof -u suspicious    # all files by user
```

### 3.3 Process Analysis with ps

```bash
# Top CPU / memory consumers
ps aux --sort=-%cpu | head -20
ps aux --sort=-%mem | head -20

# Full process tree
ps auxf

# Check process environment (root required)
sudo cat /proc/<PID>/environ | tr '\0' '\n'
```

---

## 4. Firewall Basics

### 4.1 iptables

```bash
# Default-deny policy
sudo iptables -P INPUT DROP
sudo iptables -P FORWARD DROP

# Allow established connections
sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow SSH from LAN
sudo iptables -A INPUT -s 192.168.1.0/24 -p tcp --dport 22 -j ACCEPT

# Allow HTTP/HTTPS
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Save rules
sudo iptables-save > /etc/iptables/rules.v4
```

### 4.2 nftables

```bash
sudo nft add table inet filter
sudo nft add chain inet filter input '{ type filter hook input priority 0; policy drop; }'
sudo nft add rule inet filter input ct state established,related accept
sudo nft add rule inet filter input tcp dport { 80, 443 } accept
sudo nft list ruleset
```

---

## 5. Python System Monitoring CLI

The script in the Korean section above (`linux_monitor.py`) is fully functional. Key design points:

- **Python 3.10+** with type hints throughout
- **argparse** for a clean CLI interface with `--watch`, `--interval`, `--cpu-threshold`, `--mem-threshold`
- **psutil** for cross-platform system data collection
- Detects suspicious processes by regex patterns (netcat listeners, deleted executables, base64 decoders, etc.)
- Color-coded terminal output with ASCII progress bars

```bash
# One-shot full check
python3 linux_monitor.py

# Watch CPU + memory every 10 seconds
python3 linux_monitor.py --watch cpu,mem --interval 10

# Hunt suspicious processes (CPU > 50%)
python3 linux_monitor.py --watch proc --cpu-threshold 50
```

---

## Quick Reference

| Purpose | Tool | Key Command |
|---------|------|-------------|
| Port scan | nmap | `nmap -sS -sV -O target` |
| Connection test | netcat | `nc -lvnp 4444` |
| Packet analysis | tcpdump | `tcpdump -i eth0 -w out.pcap` |
| Socket status | ss | `ss -tnpe` |
| File integrity | AIDE | `aide --check` |
| Kernel auditing | auditd | `ausearch -k tag` |
| Open files | lsof | `lsof -i :port` |
| Firewall | iptables | `iptables -L -v -n` |

---

## References

- [The Book of Secret Knowledge](https://github.com/trimstray/the-book-of-secret-knowledge) — A curated list of hacking tools, cheat sheets, and resources for security professionals
