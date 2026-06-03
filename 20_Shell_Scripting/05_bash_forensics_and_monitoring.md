> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# Bash 포렌식·모니터링 자동화 — 로그 분석·이상 탐지·인시던트 대응

## 0. 초보자를 위한 개념 이해

### 포렌식과 모니터링이란?

디지털 포렌식(Digital Forensics)은 사이버 사고가 발생했을 때 "무슨 일이 있었는가"를 증거에 근거하여 규명하는 과학적 조사 과정이다. 모니터링은 사고 발생 전에 이상 징후를 실시간으로 탐지하는 활동이다. Bash 스크립트로 이 두 가지를 자동화하면 사고 대응 시간(MTTR)을 크게 단축할 수 있다.

**왜 배우는가:**
```
포렌식·모니터링이 필요한 이유

사고 발생
    │
    ├── 모니터링(사전): 이상 탐지 → 조기 경보 → 피해 최소화
    │
    └── 포렌식(사후):  증거 수집 → 원인 규명 → 재발 방지

Bash 자동화 효과:
  - 휘발성 데이터(RAM, 프로세스, 연결)를 즉시 수집
  - 수천 줄 로그를 패턴으로 자동 필터링
  - 24/7 모니터링을 사람 없이 실행
```

### 핵심 개념 정리

```
포렌식 조사 우선순위 (휘발성 순서 — 먼저 사라지는 것부터)

1순위  RAM / 실행 중인 프로세스 (전원 끄면 사라짐)
2순위  네트워크 연결 상태, ARP 캐시
3순위  로그인 세션, 열린 파일
4순위  파일시스템 타임스탬프 (접근시간 atime)
5순위  디스크 이미지 (비교적 영구적)
```

### 필요한 도구 및 환경
- **ss / netstat**: 네트워크 연결 상태 확인
- **ps / lsof**: 프로세스 및 열린 파일 목록
- **auditd**: 리눅스 감사 로그 (`apt install auditd`)
- **rsyslog**: 시스템 로그 수집 및 전송

### 기초 실습 예제
```bash
#!/usr/bin/env bash
# 간단한 라이브 포렌식 스냅샷 — 초보자용
OUT="/tmp/forensics_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUT"

echo "[*] 포렌식 수집 시작: $OUT"

# 1. 실행 중인 프로세스 (가장 먼저!)
ps auxf > "$OUT/processes.txt"

# 2. 네트워크 연결 상태
ss -antp > "$OUT/connections.txt"

# 3. 로그인한 사용자
who > "$OUT/logged_users.txt"
last -20 > "$OUT/recent_logins.txt"

# 4. 최근 수정된 파일 (24시간 이내)
find /tmp /var/tmp /dev/shm -newer /etc/passwd 2>/dev/null \
    > "$OUT/recent_files.txt"

echo "[+] 수집 완료. 파일: $OUT/"
ls -la "$OUT/"
```

---

## 1. 시스템 포렌식 수집 자동화

```bash
#!/usr/bin/env bash
# live_forensics.sh — 리눅스 라이브 포렌식 데이터 수집

set -euo pipefail
OUT_DIR="/tmp/forensics_$(hostname)_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUT_DIR"

log() { echo "[$(date '+%H:%M:%S')] $*" | tee -a "$OUT_DIR/collection.log"; }

log "=== 라이브 포렌식 수집 시작 ==="

# 시스템 정보
log "시스템 기본 정보 수집"
{
  echo "=== uname ===" && uname -a
  echo "=== uptime ===" && uptime
  echo "=== date ===" && date -u
  echo "=== id ===" && id
} > "$OUT_DIR/system_info.txt"

# 프로세스 스냅샷
log "프로세스 목록 수집"
ps auxf > "$OUT_DIR/processes.txt"
ls -la /proc/*/exe 2>/dev/null | grep -v "Permission denied" > "$OUT_DIR/proc_exe.txt" || true

# 네트워크 상태
log "네트워크 연결 수집"
ss -tlnp > "$OUT_DIR/listening_ports.txt"
ss -antp > "$OUT_DIR/all_connections.txt"
ip route > "$OUT_DIR/routes.txt"
arp -n > "$OUT_DIR/arp_cache.txt" 2>/dev/null || true

# 로그인 기록
log "로그인 기록 수집"
last -F -n 100 > "$OUT_DIR/last_logins.txt"
lastb -F -n 50 > "$OUT_DIR/failed_logins.txt" 2>/dev/null || true
who > "$OUT_DIR/current_users.txt"

# 파일 시스템 수상한 파일
log "의심 파일 탐색"
find /tmp /var/tmp /dev/shm -type f -newer /tmp -ls 2>/dev/null > "$OUT_DIR/recent_tmp_files.txt" || true
find / -perm -4000 -type f 2>/dev/null > "$OUT_DIR/suid_files.txt" || true
find / -perm -2000 -type f 2>/dev/null > "$OUT_DIR/sgid_files.txt" || true

# cron 작업
log "예약 작업 수집"
crontab -l 2>/dev/null > "$OUT_DIR/user_crontab.txt" || true
cat /etc/crontab > "$OUT_DIR/system_crontab.txt" 2>/dev/null || true
ls -la /etc/cron.* 2>/dev/null > "$OUT_DIR/cron_dirs.txt" || true

# 서비스 목록
log "서비스 목록 수집"
systemctl list-units --type=service --state=active 2>/dev/null > "$OUT_DIR/active_services.txt" || \
  service --status-all 2>&1 > "$OUT_DIR/active_services.txt" || true

# 환경 변수 (자격증명 포함 가능)
log "환경 변수 수집"
env | grep -iE "(pass|secret|key|token|api)" > "$OUT_DIR/sensitive_env.txt" 2>/dev/null || true

# 최근 수정 파일
log "최근 수정 파일 탐색"
find /etc /var/www /home -type f -newer /var/log -ls 2>/dev/null \
  | head -100 > "$OUT_DIR/recently_modified.txt" || true

# 아티팩트 압축
log "수집 완료 — 압축 중"
ARCHIVE="${OUT_DIR}.tar.gz"
tar czf "$ARCHIVE" -C "$(dirname "$OUT_DIR")" "$(basename "$OUT_DIR")"
log "저장: $ARCHIVE"

echo ""
echo "수집 완료: $ARCHIVE"
```

---

## 2. 로그 이상 탐지 스크립트

```python
#!/usr/bin/env python3
"""시스템 로그 이상 탐지 — auth.log·syslog 분석."""

import argparse
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path


@dataclass
class LoginAttempt:
    timestamp: str
    user: str
    src_ip: str
    success: bool


@dataclass
class AnomalyReport:
    brute_force_ips: list[dict] = field(default_factory=list)
    invalid_users: list[dict] = field(default_factory=list)
    off_hours_logins: list[dict] = field(default_factory=list)
    privilege_escalations: list[str] = field(default_factory=list)
    new_services: list[str] = field(default_factory=list)


def parse_auth_log(log_path: Path) -> list[LoginAttempt]:
    attempts: list[LoginAttempt] = []

    # SSH 실패 패턴
    fail_re = re.compile(
        r"(?P<ts>\w+ \d+ \d+:\d+:\d+).*Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)"
    )
    # SSH 성공 패턴
    success_re = re.compile(
        r"(?P<ts>\w+ \d+ \d+:\d+:\d+).*Accepted \w+ for (?P<user>\S+) from (?P<ip>[\d.]+)"
    )

    for line in log_path.read_text(errors="ignore").splitlines():
        m = fail_re.search(line)
        if m:
            attempts.append(LoginAttempt(m["ts"], m["user"], m["ip"], False))
            continue
        m = success_re.search(line)
        if m:
            attempts.append(LoginAttempt(m["ts"], m["user"], m["ip"], True))

    return attempts


def detect_brute_force(
    attempts: list[LoginAttempt],
    threshold: int = 10,
    window_minutes: int = 5,
) -> list[dict]:
    """IP별 실패 횟수가 임계값 초과 탐지."""
    ip_fails: Counter = Counter()
    for attempt in attempts:
        if not attempt.success:
            ip_fails[attempt.src_ip] += 1

    return [
        {"ip": ip, "fail_count": count, "risk": "HIGH"}
        for ip, count in ip_fails.most_common()
        if count >= threshold
    ]


def detect_invalid_user_enum(attempts: list[LoginAttempt], threshold: int = 5) -> list[dict]:
    """존재하지 않는 사용자명 열거 탐지."""
    user_counts: Counter = Counter(a.user for a in attempts if not a.success)
    suspicious_users = [u for u, c in user_counts.items() if c >= threshold]

    result = []
    for user in suspicious_users:
        ips = list({a.src_ip for a in attempts if a.user == user})
        result.append({
            "username": user,
            "attempt_count": user_counts[user],
            "src_ips": ips[:5],
        })
    return result


def detect_off_hours_logins(
    attempts: list[LoginAttempt],
    business_hours: tuple[int, int] = (9, 18),
) -> list[dict]:
    """업무 시간 외 성공적 로그인 탐지."""
    off_hours = []
    for attempt in attempts:
        if not attempt.success:
            continue
        try:
            ts = datetime.strptime(attempt.timestamp, "%b %d %H:%M:%S")
            hour = ts.hour
            if not (business_hours[0] <= hour < business_hours[1]):
                off_hours.append({
                    "timestamp": attempt.timestamp,
                    "user": attempt.user,
                    "src_ip": attempt.src_ip,
                    "hour": hour,
                })
        except ValueError:
            pass
    return off_hours


def detect_sudo_abuse(syslog_path: Path) -> list[str]:
    """sudo/su 남용 탐지."""
    findings = []
    patterns = [
        r"sudo.*COMMAND=.*",
        r"su: pam_unix.*session opened for user root",
        r"sudo:.*NOT in sudoers",
    ]

    for line in syslog_path.read_text(errors="ignore").splitlines():
        for pattern in patterns:
            if re.search(pattern, line):
                findings.append(line.strip())
                break

    return findings[-50:]  # 최근 50개


def main() -> None:
    parser = argparse.ArgumentParser(description="리눅스 로그 이상 탐지")
    parser.add_argument("--auth-log", type=Path, default=Path("/var/log/auth.log"))
    parser.add_argument("--syslog", type=Path, default=Path("/var/log/syslog"))
    parser.add_argument("--brute-threshold", type=int, default=10)
    parser.add_argument("--business-start", type=int, default=9)
    parser.add_argument("--business-end", type=int, default=18)
    args = parser.parse_args()

    print("=== 로그 이상 탐지 분석 ===\n")
    report = AnomalyReport()

    if args.auth_log.exists():
        attempts = parse_auth_log(args.auth_log)
        print(f"[*] 로그인 시도 {len(attempts)}개 분석")

        report.brute_force_ips = detect_brute_force(attempts, args.brute_threshold)
        report.invalid_users = detect_invalid_user_enum(attempts)
        report.off_hours_logins = detect_off_hours_logins(
            attempts, (args.business_start, args.business_end)
        )

        if report.brute_force_ips:
            print(f"\n[!] 브루트포스 의심 IP {len(report.brute_force_ips)}개:")
            for item in report.brute_force_ips[:10]:
                print(f"  {item['ip']}: {item['fail_count']}회 실패")

        if report.invalid_users:
            print(f"\n[!] 사용자 열거 의심 {len(report.invalid_users)}개:")
            for item in report.invalid_users[:10]:
                print(f"  {item['username']}: {item['attempt_count']}회")

        if report.off_hours_logins:
            print(f"\n[!] 업무 외 시간 로그인 {len(report.off_hours_logins)}개:")
            for item in report.off_hours_logins[:5]:
                print(f"  {item['timestamp']} — {item['user']} from {item['src_ip']}")
    else:
        print(f"[-] {args.auth_log} 없음")

    if args.syslog.exists():
        sudo_events = detect_sudo_abuse(args.syslog)
        if sudo_events:
            print(f"\n[!] sudo/su 이벤트 {len(sudo_events)}개:")
            for e in sudo_events[-5:]:
                print(f"  {e[:120]}")


if __name__ == "__main__":
    main()
```

---

## 3. 실시간 파일 변경 모니터링

```bash
#!/usr/bin/env bash
# file_integrity_monitor.sh — inotifywait 기반 파일 무결성 모니터링

WATCH_DIRS="${1:-/etc /var/www /usr/bin /usr/sbin}"
LOG_FILE="/var/log/fim_$(date +%Y%m%d).log"

log_event() {
  echo "$(date '+%Y-%m-%d %H:%M:%S') | $1 | $2 | $3" | tee -a "$LOG_FILE"
}

echo "[*] FIM 모니터링 시작: $WATCH_DIRS"
echo "[*] 로그: $LOG_FILE"

if ! command -v inotifywait &>/dev/null; then
  echo "inotify-tools 설치 필요: apt install inotify-tools"
  exit 1
fi

# 초기 해시 스냅샷
SNAPSHOT_FILE="/tmp/fim_snapshot_$(date +%Y%m%d).sha256"
if [[ ! -f "$SNAPSHOT_FILE" ]]; then
  echo "[*] 초기 스냅샷 생성..."
  find $WATCH_DIRS -type f -exec sha256sum {} + 2>/dev/null > "$SNAPSHOT_FILE"
  echo "[+] 스냅샷 저장: $SNAPSHOT_FILE"
fi

# inotifywait 모니터링
inotifywait -m -r -e modify,create,delete,moved_from,moved_to \
  --format "%w%f %e %T" --timefmt "%Y-%m-%d %H:%M:%S" \
  $WATCH_DIRS 2>/dev/null | while read filepath event timestamp; do

  # 의심 이벤트 분류
  case "$event" in
    CREATE|MOVED_TO)
      log_event "NEW_FILE" "$filepath" "$event"
      # 실행 가능 파일 생성 시 추가 경고
      if [[ -x "$filepath" ]]; then
        log_event "ALERT_EXECUTABLE" "$filepath" "새 실행 파일 생성"
      fi
      ;;
    MODIFY)
      log_event "MODIFIED" "$filepath" "$event"
      # 해시 변경 확인
      if [[ -f "$filepath" ]]; then
        current_hash=$(sha256sum "$filepath" 2>/dev/null | cut -d' ' -f1)
        prev_hash=$(grep " $filepath$" "$SNAPSHOT_FILE" 2>/dev/null | cut -d' ' -f1)
        if [[ -n "$prev_hash" && "$current_hash" != "$prev_hash" ]]; then
          log_event "HASH_CHANGED" "$filepath" "이전=$prev_hash 현재=$current_hash"
        fi
      fi
      ;;
    DELETE|MOVED_FROM)
      log_event "DELETED" "$filepath" "$event"
      ;;
  esac
done
```

---

## 4. 인시던트 대응 자동화

```bash
#!/usr/bin/env bash
# incident_response.sh — 침해 의심 시스템 초기 대응

set -euo pipefail
INCIDENT_DIR="/tmp/incident_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$INCIDENT_DIR"

echo "[*] 인시던트 대응 시작: $INCIDENT_DIR"

# 1. 현재 활성 연결 격리 (선택적 — 주석 해제 시 네트워크 차단)
# iptables -I OUTPUT -j DROP
# iptables -I INPUT -j DROP

# 2. 메모리 스냅샷 (프로세스 메모리 덤프)
echo "[*] 의심 프로세스 탐색"
ps aux --sort=-%cpu | head -20 > "$INCIDENT_DIR/top_processes.txt"

# 삭제된 실행 파일로 실행 중인 프로세스 탐지
ls -la /proc/*/exe 2>/dev/null | grep "(deleted)" | tee "$INCIDENT_DIR/deleted_exe_processes.txt"

# 숨겨진 프로세스 탐지 (ps vs /proc 비교)
ps_pids=$(ps -e --no-headers -o pid | sort -n)
proc_pids=$(ls /proc | grep -E '^[0-9]+$' | sort -n)
comm -23 <(echo "$proc_pids") <(echo "$ps_pids") > "$INCIDENT_DIR/hidden_pids.txt" 2>/dev/null || true

# 3. 네트워크 아티팩트
echo "[*] 네트워크 상태 수집"
ss -antp 2>/dev/null > "$INCIDENT_DIR/network_connections.txt"
ip neigh show > "$INCIDENT_DIR/arp_table.txt"
cat /etc/hosts > "$INCIDENT_DIR/hosts_file.txt"

# 4. 지속성 메커니즘 확인
echo "[*] 지속성 메커니즘 확인"
{
  echo "=== crontabs ==="
  for user in $(cut -f1 -d: /etc/passwd); do
    crontab -u "$user" -l 2>/dev/null && echo "--- $user ---" || true
  done
  echo ""
  echo "=== /etc/cron.d ==="
  ls -la /etc/cron.d/ 2>/dev/null || true
  echo ""
  echo "=== systemd 서비스 ==="
  find /etc/systemd /usr/lib/systemd -name "*.service" -newer /etc/passwd 2>/dev/null || true
} > "$INCIDENT_DIR/persistence_artifacts.txt"

# 5. 악성 파일 탐색
echo "[*] 악성 파일 탐색"
# SUID 파일
find / -perm -4000 -type f 2>/dev/null > "$INCIDENT_DIR/suid_files.txt" || true
# /tmp의 실행 파일
find /tmp /var/tmp /dev/shm -type f -executable 2>/dev/null > "$INCIDENT_DIR/tmp_executables.txt" || true
# 최근 24시간 변경 파일 (/bin, /usr/bin)
find /bin /usr/bin /sbin /usr/sbin -type f -newer /etc/passwd -ls 2>/dev/null > "$INCIDENT_DIR/modified_system_bins.txt" || true

# 6. 아티팩트 패키지
echo "[*] 아티팩트 패키지 생성"
tar czf "${INCIDENT_DIR}.tar.gz" -C "$(dirname "$INCIDENT_DIR")" "$(basename "$INCIDENT_DIR")"
echo "[+] 완료: ${INCIDENT_DIR}.tar.gz"
echo ""
echo "다음 단계:"
echo "  1. 아티팩트 분석: ${INCIDENT_DIR}.tar.gz"
echo "  2. 필요 시 네트워크 격리"
echo "  3. 메모리 덤프: avml /tmp/memory.lime"
echo "  4. 포렌식 이미징 후 시스템 종료"
```

---

## 5. 자동화 로그 수집 요약

| 작업 | 도구 | 수집 항목 |
|------|------|-----------|
| 라이브 수집 | bash + coreutils | 프로세스·네트워크·파일·cron |
| 로그 분석 | Python + re | 브루트포스·사용자 열거·업무외 로그인 |
| 파일 무결성 | inotifywait | 실시간 변경 탐지 + 해시 비교 |
| 인시던트 대응 | bash | 은닉 프로세스·지속성·악성 파일 |
| 메모리 획득 | avml/LiME | 커널 모듈 없이 메모리 덤프 |

---

<a name="english"></a>

# Bash Forensics & Monitoring Automation — Log Analysis, Anomaly Detection, Incident Response

## 1. System Forensics Collection Automation

```bash
#!/bin/bash
# forensics_collection.sh - Live forensics data collection
OUTPUT_DIR="forensics_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTPUT_DIR"

echo "[*] Collecting forensic data..."

# Process information
ps auxf > "$OUTPUT_DIR/processes.txt"
ls -la /proc/*/exe 2>/dev/null | grep -v Permission > "$OUTPUT_DIR/proc_exe.txt"

# Network connections
netstat -anltp 2>/dev/null > "$OUTPUT_DIR/network.txt"
ss -anltp > "$OUTPUT_DIR/ss.txt"

# Login history
last -F > "$OUTPUT_DIR/login_history.txt"
lastlog > "$OUTPUT_DIR/lastlog.txt"
w > "$OUTPUT_DIR/current_users.txt"

# Cron jobs
for user in $(cut -d: -f1 /etc/passwd); do
    crontab -l -u "$user" 2>/dev/null >> "$OUTPUT_DIR/crontabs.txt"
done
ls -la /etc/cron* > "$OUTPUT_DIR/system_crons.txt"

# Startup/persistence mechanisms
ls -la /etc/rc*.d/ >> "$OUTPUT_DIR/startup.txt"
systemctl list-units --type=service >> "$OUTPUT_DIR/services.txt"

# Recent file modifications (last 24h)
find / -mtime -1 -type f 2>/dev/null | grep -v proc > "$OUTPUT_DIR/recent_files.txt"

# SUID/SGID files
find / -perm -4000 -o -perm -2000 2>/dev/null > "$OUTPUT_DIR/suid_sgid.txt"

# Hash sensitive files
for f in /etc/passwd /etc/shadow /etc/hosts /etc/sudoers; do
    [ -f "$f" ] && md5sum "$f" >> "$OUTPUT_DIR/file_hashes.txt"
done

echo "[+] Forensic collection complete: $OUTPUT_DIR/"
```

---

## 2. Log Analysis and Anomaly Detection

```python
#!/usr/bin/env python3
"""
Automated log analysis and anomaly detection
Analyzes auth.log for brute force, user enumeration, off-hours logins
"""
import re
from datetime import datetime
from collections import defaultdict
from pathlib import Path

def analyze_auth_log(log_path: str = "/var/log/auth.log") -> dict:
    """Analyze authentication logs for anomalies"""
    
    results = {
        "brute_force": [],
        "off_hours_logins": [],
        "new_users": [],
        "sudo_escalations": []
    }
    
    # Parse log
    failed_logins = defaultdict(list)
    successful_logins = []
    
    log_pattern = re.compile(
        r'(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+sshd\[(\d+)\]:\s+(.*)'
    )
    
    failed_pattern = re.compile(r'Failed password for (?:invalid user )?(\S+) from (\S+)')
    success_pattern = re.compile(r'Accepted (\S+) for (\S+) from (\S+)')
    
    with open(log_path, 'r', errors='ignore') as f:
        for line in f:
            match = log_pattern.match(line)
            if not match:
                continue
            
            timestamp_str, pid, message = match.groups()
            
            # Failed login attempt
            failed = failed_pattern.search(message)
            if failed:
                user, ip = failed.groups()
                failed_logins[ip].append({
                    "time": timestamp_str,
                    "user": user
                })
            
            # Successful login
            success = success_pattern.search(message)
            if success:
                method, user, ip = success.groups()
                successful_logins.append({
                    "time": timestamp_str,
                    "user": user,
                    "ip": ip,
                    "method": method
                })
    
    # Detect brute force (>10 failures from same IP)
    for ip, attempts in failed_logins.items():
        if len(attempts) > 10:
            results["brute_force"].append({
                "ip": ip,
                "count": len(attempts),
                "users_tried": list(set(a["user"] for a in attempts))
            })
    
    # Detect off-hours logins (outside 7am-7pm)
    for login in successful_logins:
        # Parse hour from timestamp
        try:
            hour = int(login["time"].split(":")[0].split()[-1])
            if hour < 7 or hour > 19:
                results["off_hours_logins"].append(login)
        except:
            pass
    
    return results

if __name__ == "__main__":
    results = analyze_auth_log()
    
    if results["brute_force"]:
        print(f"[!] Brute force detected from {len(results['brute_force'])} IPs")
        for bf in results["brute_force"][:5]:
            print(f"    {bf['ip']}: {bf['count']} attempts")
    
    if results["off_hours_logins"]:
        print(f"[!] Off-hours logins: {len(results['off_hours_logins'])}")
```

---

## 3. File Integrity Monitoring

```bash
#!/bin/bash
# file_integrity_monitor.sh - Real-time file change detection

WATCH_DIRS="/etc /usr/bin /usr/sbin /bin /sbin"
BASELINE_FILE="/var/lib/fim/baseline.db"
ALERT_LOG="/var/log/fim_alerts.log"

mkdir -p "$(dirname "$BASELINE_FILE")"

# Create baseline
create_baseline() {
    echo "[*] Creating file integrity baseline..."
    for dir in $WATCH_DIRS; do
        find "$dir" -type f 2>/dev/null -exec sha256sum {} \; 2>/dev/null
    done > "$BASELINE_FILE"
    echo "[+] Baseline created: $(wc -l < "$BASELINE_FILE") files"
}

# Check against baseline
check_integrity() {
    echo "[*] Checking file integrity..."
    local changes=0
    
    while IFS= read -r line; do
        expected_hash="${line%% *}"
        filepath="${line#* }"
        filepath="${filepath:1}"  # Remove leading space
        
        if [ ! -f "$filepath" ]; then
            echo "$(date): DELETED: $filepath" | tee -a "$ALERT_LOG"
            ((changes++))
        else
            actual_hash=$(sha256sum "$filepath" 2>/dev/null | cut -d' ' -f1)
            if [ "$expected_hash" != "$actual_hash" ]; then
                echo "$(date): MODIFIED: $filepath" | tee -a "$ALERT_LOG"
                ((changes++))
            fi
        fi
    done < "$BASELINE_FILE"
    
    echo "[+] Check complete. Changes: $changes"
}

# Real-time monitoring with inotify
monitor_realtime() {
    echo "[*] Starting real-time monitoring..."
    inotifywait -m -r -e modify,create,delete,move \
        --format '%T %w%f %e' --timefmt '%Y-%m-%d %H:%M:%S' \
        $WATCH_DIRS 2>/dev/null | \
    while read -r event; do
        echo "$event" | tee -a "$ALERT_LOG"
        # Alert if critical file modified
        if echo "$event" | grep -qE '/etc/passwd|/etc/shadow|/etc/sudoers'; then
            logger -p security.critical "FIM ALERT: Critical file modified: $event"
        fi
    done
}

case "${1:-help}" in
    baseline) create_baseline ;;
    check)    check_integrity ;;
    monitor)  monitor_realtime ;;
    *) echo "Usage: $0 {baseline|check|monitor}" ;;
esac
```

---

## 4. Automated Log Collection Summary

| Task | Tool | Collection Items |
|------|------|----------------|
| Live collection | bash + coreutils | processes, network, files, cron |
| Log analysis | Python + re | brute force, user enumeration, off-hours logins |
| File integrity | inotifywait | real-time change detection + hash comparison |
| Incident response | bash | hidden processes, persistence, malicious files |
| Memory acquisition | avml/LiME | memory dump without kernel module |
