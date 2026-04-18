# 디지털 포렌식 — 이론과 실전 완전 가이드

## 1. 디지털 포렌식 개요

### 포렌식의 정의
디지털 기기에서 법적 증거 능력이 있는 디지털 증거를 수집, 보존, 분석, 제출하는 과학적 과정.

### 포렌식의 원칙
1. **무결성 보존**: 원본 증거 변경 금지 (해시로 검증)
2. **연계 보관성 (Chain of Custody)**: 증거 취급 이력 완벽 기록
3. **재현 가능성**: 동일 도구로 동일 결과 도출 가능
4. **문서화**: 모든 절차를 상세히 기록

### 포렌식 조사 절차
```
1. 현장 보존
   ↓
2. 증거 수집 (이미징)
   ↓
3. 무결성 검증 (해시 비교)
   ↓
4. 증거 분석
   ↓
5. 보고서 작성
   ↓
6. 법정 제출
```

---

## 2. 증거 수집 및 이미징

### 디스크 이미징 도구
```bash
# dd (기본 도구)
dd if=/dev/sda of=/evidence/disk.img bs=4096
# if: 입력 파일 (원본 디스크)
# of: 출력 파일 (이미지)
# bs: 블록 크기 (4096 권장)

# 해시 생성 (동시에)
dd if=/dev/sda | tee /evidence/disk.img | md5sum > /evidence/hash.md5

# dcfldd (향상된 dd, 포렌식 특화)
dcfldd if=/dev/sda of=/evidence/disk.img hash=md5,sha256 hashlog=/evidence/hash.log

# ewfacquire (E01 포맷, FTK/EnCase 호환)
ewfacquire /dev/sda -t /evidence/disk
# → /evidence/disk.E01 생성

# 무결성 검증
md5sum disk.img        # 이미지 생성 직후
md5sum disk.img        # 분석 후
# 두 값이 동일해야 함
```

### 메모리 이미징
```bash
# Linux 메모리 덤프
# LiME (Linux Memory Extractor) 커널 모듈 사용

# LiME 설치 및 실행
apt-get install build-essential linux-headers-$(uname -r)
git clone https://github.com/504ensicsLabs/LiME
cd LiME/src
make

insmod lime-$(uname -r).ko "path=/evidence/memory.lime format=lime"

# Windows 메모리 덤프 도구
# - WinPmem
# - Magnet RAM Capture (GUI)
# - DumpIt (원클릭)
# - FTK Imager (상용)

# WinPmem 사용법
winpmem_mini_x64.exe memory.aff4
```

---

## 3. Windows 포렌식

### 주요 아티팩트 위치
```
사용자 행위 기록:
├── %USERPROFILE%\AppData\Local\Microsoft\Windows\History  ← IE/Edge 기록
├── %USERPROFILE%\AppData\Roaming\Mozilla\Firefox\Profiles  ← Firefox
├── %USERPROFILE%\AppData\Local\Google\Chrome\User Data    ← Chrome
├── %USERPROFILE%\Recent  ← 최근 파일
├── %USERPROFILE%\AppData\Roaming\Microsoft\Windows\Recent ← 최근 파일 링크
└── %TEMP%  ← 임시 파일

시스템 정보:
├── C:\Windows\System32\config\SAM     ← 계정 정보
├── C:\Windows\System32\config\SYSTEM  ← 시스템 설정
├── C:\Windows\System32\config\SOFTWARE← 소프트웨어 목록
├── C:\Windows\System32\winevt\Logs\   ← 이벤트 로그 (.evtx)
└── C:\Windows\Prefetch\               ← 실행 프로그램 기록 (.pf)

네트워크:
├── C:\Windows\System32\drivers\etc\hosts  ← 호스트 파일
└── C:\Windows\System32\config\SYSTEM (네트워크 설정)
```

### Windows 이벤트 로그 분석
```
주요 이벤트 ID:

보안 로그 (Security.evtx):
- 4624: 로그인 성공
- 4625: 로그인 실패 (브루트포스 탐지)
- 4634: 로그아웃
- 4648: 명시적 자격증명으로 로그인 (runas)
- 4720: 사용자 계정 생성
- 4722: 사용자 계정 활성화
- 4728: 보안 그룹에 구성원 추가
- 4732: 로컬 그룹에 구성원 추가
- 4756: 전역 그룹에 구성원 추가
- 4776: 자격증명 유효성 확인 (DC에서)

시스템 로그 (System.evtx):
- 7034: 서비스 비정상 종료
- 7035: 서비스 상태 변경 (시작/중지)
- 7036: 서비스 상태 변경 알림
- 7045: 새 서비스 설치 (악성 서비스 탐지)

응용 프로그램 로그 (Application.evtx):
- 1102: 감사 로그 삭제 (로그 삭제 탐지!)
- 4688: 새 프로세스 생성 (Process Create, 정책 활성화 필요)
```

```powershell
# PowerShell로 이벤트 로그 분석
# 로그인 실패 조회
Get-WinEvent -LogName Security | 
    Where-Object {$_.Id -eq 4625} | 
    Select-Object TimeCreated, Message | 
    Format-List

# 서비스 설치 이벤트
Get-WinEvent -LogName System | 
    Where-Object {$_.Id -eq 7045} |
    Select-Object TimeCreated, Message

# 특정 기간 이벤트 조회
$start = [DateTime]"2024-01-01"
$end   = [DateTime]"2024-01-31"
Get-WinEvent -LogName Security -FilterXPath "*[System[TimeCreated[@SystemTime>='$start' and @SystemTime<='$end']]]"
```

### Prefetch 분석 (실행 프로그램 추적)
```
Prefetch 파일 위치: C:\Windows\Prefetch\*.pf
형식: PROGRAMNAME-XXXXXXXX.pf

분석 가능 정보:
1. 프로그램 이름
2. 실행 횟수
3. 마지막 실행 시간 (최대 8번의 실행 시간)
4. 로드된 DLL/파일 목록

도구:
WinPrefetchView (NirSoft) — GUI 분석 도구
prefetch-parser.py — 오프라인 분석

명령 프롬프트에서:
dir C:\Windows\Prefetch\ | findstr "POWERSHELL"  # PowerShell 실행 흔적
dir C:\Windows\Prefetch\ | findstr "CMD"          # CMD 실행 흔적
```

### LNK (바로가기) 파일 분석
```
.lnk 파일은 최근 열어본 파일의 원본 정보 저장:
- 원본 파일 경로
- 타임스탬프
- 파일 크기
- MAC 주소 (네트워크 파일인 경우)
- 볼륨 시리얼 번호 (이동식 디스크)

위치:
%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Recent\

도구:
lnkparse (Python) — Linux에서 분석
Windows File Analyzer — GUI 도구

# lnkparse 사용
pip install lnkparse
lnkparse file.lnk
```

---

## 4. Linux 포렌식

### 주요 로그 파일
```bash
# 인증 로그
/var/log/auth.log    # Debian/Ubuntu
/var/log/secure      # RHEL/CentOS

# 시스템 로그
/var/log/syslog      # Debian/Ubuntu
/var/log/messages    # RHEL/CentOS

# 커널 로그
/var/log/kern.log
dmesg

# 웹 서버
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/nginx/access.log

# FTP
/var/log/vsftpd.log

# 크론 작업
/var/log/cron.log
```

### 침해 사고 분석 명령어 모음
```bash
# 현재 로그인 사용자
who
w
last | head -20        # 최근 로그인 이력
lastlog                # 모든 계정 마지막 로그인

# 실행 중인 프로세스 분석
ps auxf                # 프로세스 트리
lsof -p PID            # 프로세스가 열은 파일
lsof -i TCP:4444       # 특정 포트 사용 프로세스

# 네트워크 연결 분석
ss -antp               # 모든 TCP 연결 (PID 포함)
netstat -antp          # 동일
ss -anup               # UDP 연결
cat /proc/net/tcp      # 로우 데이터

# 파일 시스템 분석
# 최근 24시간 내 수정된 파일
find / -mtime -1 -type f 2>/dev/null | grep -v proc

# 최근 1시간 내 접근된 파일
find / -atime -0.04 -type f 2>/dev/null

# SetUID 파일 검사
find / -perm -4000 -type f 2>/dev/null

# 숨겨진 파일
find / -name ".*" -type f 2>/dev/null | head -20

# 삭제된 파일 (아직 실행 중)
lsof | grep "(deleted)"

# 계정 분석
cat /etc/passwd | awk -F: '$3==0{print}'  # UID=0인 계정 (root 권한)
cat /etc/shadow | awk -F: '$2!="!"&&$2!="*"{print $1}'  # 활성 계정
```

### Volatility (메모리 분석)
```python
#!/usr/bin/env python3
"""
volatility3 자동화 분석 스크립트
용도: 메모리 덤프에서 핵심 포렌식 아티팩트를 일괄 추출
의존성: pip install volatility3
"""
from __future__ import annotations
import argparse
import subprocess
import sys
import json
from pathlib import Path
from datetime import datetime


PLUGINS: dict[str, str] = {
    "windows": [
        "windows.info",
        "windows.pslist",
        "windows.pstree",
        "windows.psscan",       # 숨겨진 프로세스 탐지
        "windows.cmdline",
        "windows.netstat",
        "windows.malfind",      # 주입된 코드 탐지
        "windows.dlllist",
        "windows.hashdump",
        "windows.registry.hivelist",
    ],
    "linux": [
        "banners.Banners",
        "linux.pslist",
        "linux.netstat",
        "linux.bash",
    ],
}


def run_plugin(
    vol_bin: str,
    dump_path: str,
    plugin: str,
    extra_args: list[str] | None = None,
) -> tuple[int, str, str]:
    """단일 플러그인 실행 후 (returncode, stdout, stderr) 반환."""
    cmd = [vol_bin, "-f", dump_path, plugin]
    if extra_args:
        cmd.extend(extra_args)
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    return result.returncode, result.stdout, result.stderr


def analyze_dump(
    dump_path: str,
    os_type: str,
    output_dir: str,
    vol_bin: str = "vol",
) -> dict[str, str]:
    """
    메모리 덤프를 대상으로 플러그인 목록을 순차 실행하고
    결과를 output_dir 아래에 저장한다.
    반환값: {plugin_name: output_file_path}
    """
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    results: dict[str, str] = {}
    plugins = PLUGINS.get(os_type, [])

    print(f"[*] 분석 시작: {dump_path}  ({os_type.upper()})")
    print(f"[*] 출력 디렉토리: {out.resolve()}")

    for plugin in plugins:
        safe_name = plugin.replace(".", "_")
        out_file = out / f"{timestamp}_{safe_name}.txt"
        print(f"  [+] {plugin} ... ", end="", flush=True)

        try:
            rc, stdout, stderr = run_plugin(vol_bin, dump_path, plugin)
            out_file.write_text(stdout, encoding="utf-8")
            status = "OK" if rc == 0 else f"RC={rc}"
            print(status)
            results[plugin] = str(out_file)
        except subprocess.TimeoutExpired:
            print("TIMEOUT")
        except Exception as exc:
            print(f"ERROR: {exc}")

    # 추가: Run 키 (Windows 지속성)
    if os_type == "windows":
        run_key = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        rc, stdout, _ = run_plugin(
            vol_bin, dump_path,
            "windows.registry.printkey",
            ["--key", run_key],
        )
        key_file = out / f"{timestamp}_registry_run.txt"
        key_file.write_text(stdout, encoding="utf-8")
        results["registry.Run"] = str(key_file)
        print(f"  [+] registry.printkey (Run) ... OK")

    summary_path = out / f"{timestamp}_summary.json"
    summary_path.write_text(json.dumps(results, indent=2, ensure_ascii=False))
    print(f"\n[*] 요약 저장: {summary_path}")
    return results


def main() -> None:
    parser = argparse.ArgumentParser(
        description="volatility3 플러그인 자동화 분석기"
    )
    parser.add_argument("dump", help="메모리 덤프 파일 경로 (.dmp/.lime/.raw)")
    parser.add_argument(
        "--os", choices=["windows", "linux"], default="windows",
        help="대상 OS (기본값: windows)"
    )
    parser.add_argument(
        "--output", default="vol_output",
        help="결과 저장 디렉토리 (기본값: vol_output)"
    )
    parser.add_argument(
        "--vol", default="vol",
        help="vol3 실행 경로 (기본값: vol)"
    )
    args = parser.parse_args()

    if not Path(args.dump).exists():
        print(f"[!] 파일을 찾을 수 없습니다: {args.dump}", file=sys.stderr)
        sys.exit(1)

    analyze_dump(args.dump, args.os, args.output, args.vol)


if __name__ == "__main__":
    main()
```

---

## 5. 타임라인 분석

### 파일 타임스탬프 분석 (MACE)
```
MACE:
M - Modified  : 파일 내용 수정 시간
A - Accessed  : 파일 접근 시간 (읽기 포함)
C - Changed   : 메타데이터 변경 시간 (이름 변경, 이동 등)
E - Entry     : MFT 엔트리 수정 시간

타임스탬프 조작 탐지 (Timestomping):
- M 시간이 C/B 시간보다 이전이면 의심
- 나노초 값이 모두 0이면 조작 의심 (일부 도구는 나노초 미지원)
```

```bash
# Linux에서 파일 타임스탬프 확인
stat file.txt
# Access: 2024-01-01 09:00:00
# Modify: 2024-01-01 08:00:00
# Change: 2024-01-01 08:00:00
# Birth:  2024-01-01 08:00:00

# 타임라인 생성
find / -printf "%M;%U;%G;%s;%a;%t;%c;%n;%p\n" 2>/dev/null > timeline.csv
```

### log2timeline / Plaso
```bash
# 여러 소스에서 통합 타임라인 생성
pip install plaso

# 이미지에서 타임라인 추출
log2timeline.py --storage-file case.plaso disk.img

# 필터링 및 출력
psort.py -o L2tcsv case.plaso > timeline.csv

# Excel/LibreOffice로 분석
# 시간 기준 정렬 후 이상 행위 식별
```

---

## 6. 웹 서버 포렌식

### Apache 로그 분석
```python
#!/usr/bin/env python3
"""
Apache/Nginx access.log 포렌식 분석기
용도: 공격 패턴(SQLi, XSS, 경로탐색, 브루트포스) 탐지 및 통계 생성
"""
from __future__ import annotations
import argparse
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator


# Combined Log Format 정규식
LOG_RE = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<uri>\S+) \S+" '
    r'(?P<status>\d{3}) (?P<size>\S+)'
    r'(?: "(?P<referer>[^"]*)" "(?P<ua>[^"]*)")?'
)

ATTACK_PATTERNS: dict[str, list[str]] = {
    "SQLi": [
        r"(?i)(union.+select|select.+from|insert.+into|drop.+table)",
        r"(?i)(%27|'|%22|\"|%60|`)(\s|%20)*(or|and|union|select)",
        r"(?i)(1=1|1%3d1|or%201|'%20or%20'1)",
        r"(?i)(sleep\s*\(|benchmark\s*\(|waitfor\s+delay)",
    ],
    "XSS": [
        r"(?i)<script[\s>]",
        r"(?i)(onerror|onload|onmouseover|onclick)\s*=",
        r"(?i)javascript\s*:",
        r"(?i)%3cscript|%3e",
    ],
    "PathTraversal": [
        r"\.\./|\.\.%2f|%2e%2e/|%252e%252e",
        r"(?i)(etc/passwd|windows/system32|win\.ini)",
    ],
    "ScannerUA": [
        r"(?i)(nikto|sqlmap|nmap|masscan|acunetix|nessus|dirb|gobuster|wfuzz)",
    ],
}


@dataclass
class LogEntry:
    ip: str
    time: str
    method: str
    uri: str
    status: int
    size: int
    ua: str = ""


@dataclass
class AnalysisResult:
    total: int = 0
    top_ips: Counter = field(default_factory=Counter)
    status_dist: Counter = field(default_factory=Counter)
    attack_hits: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))
    large_responses: list[tuple[int, str]] = field(default_factory=list)


def parse_log(path: Path) -> Iterator[LogEntry]:
    with path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            m = LOG_RE.match(line)
            if not m:
                continue
            try:
                yield LogEntry(
                    ip=m["ip"],
                    time=m["time"],
                    method=m["method"],
                    uri=m["uri"],
                    status=int(m["status"]),
                    size=int(m["size"]) if m["size"].isdigit() else 0,
                    ua=m["ua"] or "",
                )
            except (ValueError, TypeError):
                continue


def analyze(path: Path, top_n: int = 10, large_threshold: int = 1_000_000) -> AnalysisResult:
    res = AnalysisResult()
    compiled = {
        category: [re.compile(p) for p in patterns]
        for category, patterns in ATTACK_PATTERNS.items()
    }

    for entry in parse_log(path):
        res.total += 1
        res.top_ips[entry.ip] += 1
        res.status_dist[entry.status] += 1

        # 공격 패턴 매칭 (URI + UA 대상)
        target = entry.uri + " " + entry.ua
        for category, regexes in compiled.items():
            for rx in regexes:
                if rx.search(target):
                    res.attack_hits[category].append(
                        f"[{entry.time}] {entry.ip} {entry.method} {entry.uri[:120]}"
                    )
                    break

        # 비정상적으로 큰 응답 (데이터 유출 가능성)
        if entry.size >= large_threshold:
            res.large_responses.append((entry.size, entry.uri[:100]))

    return res


def print_report(res: AnalysisResult, top_n: int) -> None:
    print(f"\n{'='*60}")
    print(f"  Apache 로그 포렌식 분석 보고서  (총 {res.total:,}줄)")
    print(f"{'='*60}")

    print(f"\n[상위 IP {top_n}개]")
    for ip, cnt in res.top_ips.most_common(top_n):
        print(f"  {ip:<20} {cnt:>6}회")

    print(f"\n[HTTP 상태 코드 분포]")
    for code, cnt in sorted(res.status_dist.items()):
        bar = "█" * min(cnt // 50, 40)
        print(f"  {code}  {cnt:>7}  {bar}")

    print(f"\n[공격 패턴 탐지]")
    for category, hits in res.attack_hits.items():
        print(f"  {category}: {len(hits)}건")
        for h in hits[:5]:
            print(f"    {h}")
        if len(hits) > 5:
            print(f"    ... 외 {len(hits)-5}건")

    if res.large_responses:
        print(f"\n[대용량 응답 (데이터 유출 의심)]")
        for size, uri in sorted(res.large_responses, reverse=True)[:10]:
            print(f"  {size/1024:.1f} KB  {uri}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Apache access.log 포렌식 분석기")
    parser.add_argument("logfile", help="access.log 경로")
    parser.add_argument("--top", type=int, default=10, help="상위 IP 표시 개수 (기본값: 10)")
    parser.add_argument(
        "--large-threshold", type=int, default=1_000_000,
        help="대용량 응답 임계값(바이트, 기본값: 1MB)"
    )
    args = parser.parse_args()

    log_path = Path(args.logfile)
    if not log_path.exists():
        print(f"[!] 파일 없음: {log_path}", file=sys.stderr)
        sys.exit(1)

    result = analyze(log_path, args.top, args.large_threshold)
    print_report(result, args.top)


if __name__ == "__main__":
    main()
```

### IIS 로그 분석 (Windows)
```powershell
# IIS 로그 경로: C:\inetpub\logs\LogFiles\W3SVC1\
# 형식: u-ex{날짜}.log

# PowerShell로 분석
Import-Csv -Delimiter " " u-ex240101.log | 
    Group-Object "cs-ip" | 
    Sort-Object Count -Descending | 
    Select-Object -First 10

# 404 에러 조회
Get-Content u-ex240101.log | Where-Object {$_ -match " 404 "}
```

---

## 7. 삭제 파일 복구 (Digital Forensics Playbook)

### 복구 전 주의사항
```
1. 복구 대상 드라이브 즉시 사용 중단
   - 삭제된 데이터가 새 내용으로 덮어쓰이면 복구 불가
2. 외부 드라이브 포맷 금지
3. 하드드라이브 수리 시도 금지
```

### 소프트웨어로 복구
```
1. 복구 소프트웨어 다운로드
2. 삭제 파일이 있던 디스크/카드 선택 → 스캔
3. 복구할 파일 선택
4. 저장 위치 선택 (원본 위치와 다른 위치에 저장 필수!)

도구 예시:
  - Recuva (무료, Windows)
  - PhotoRec / TestDisk (크로스플랫폼, 무료)
  - R-Studio (상용)
  - Stellar Data Recovery (상용)
```

### CMD로 복구 (숨김 파일 복원)
```cmd
ATTRIB -H -R -S /S /D X:*.*
:: X를 실제 드라이브 문자로 교체
:: -H: 숨김 해제, -R: 읽기전용 해제, -S: 시스템 속성 해제
:: /S: 하위폴더 포함, /D: 폴더도 포함
```

### 이전 버전으로 복구 (Volume Shadow Copy)
```
1. 파일이 있던 폴더 → 우클릭 → 속성
2. 이전 버전 탭 클릭
3. 복구할 버전 선택
4. 복원 클릭

VSS (Volume Shadow Service) 관련:
  vssadmin list shadows         → 섀도 복사본 목록
  vssadmin delete shadows /all  → 모든 섀도 삭제 (랜섬웨어 행위!)
```

---

## 8. 인시던트 대응 Do's and Don'ts

### 인시던트 대응 시 해야 할 것 (Do's)
```
1. 포렌식 도구를 이용해 휘발성 데이터 및 아티팩트 수집
2. 식별된 IOC 기반 외부 인텔리전스 수집
3. 포렌식 수집을 위해 시스템 및 미디어 보안 유지
4. 네트워크 및 엔드포인트 레벨 로그 수집
5. 고객/이해관계자에게 신속히 커뮤니케이션
```

### 인시던트 대응 시 하지 말아야 할 것 (Don'ts)
```
1. 당황하지 말 것 (실수 유발)
2. 침해된 시스템 즉시 종료 금지 (메모리 증거 손실)
3. 지시 없이 인시던트 내용 외부 공유 금지
4. 침해 시스템에 도메인 관리자 자격증명 사용 금지
5. 침해 시스템에 비포렌식 소프트웨어 실행 금지
```

### 인시던트 대응 계획 (CSIRP) 효과
```
✓ 위협에 자신 있게 대응
✓ 인시던트 영향 최소화
✓ 전반적인 사이버보안 상태 개선
✓ 고객 신뢰 강화
✓ 브랜드 평판 유지
✓ 컴플라이언스 준수
✓ 비즈니스 연속성 유지
✓ 위협 확산 방지
```

---

## 10. 도구 모음

| 도구 | 용도 | 플랫폼 |
|------|------|--------|
| Autopsy | 종합 포렌식 분석 | Cross |
| FTK Imager | 이미지 생성/마운트 | Windows |
| EnCase | 상용 포렌식 도구 | Windows |
| Volatility | 메모리 분석 | Cross |
| Plaso | 타임라인 생성 | Cross |
| SIFT Workstation | 포렌식 분석 VM | Linux |
| REMnux | 악성코드 분석 VM | Linux |
| Wireshark | 네트워크 분석 | Cross |
| NetworkMiner | 네트워크 포렌식 | Windows |
| Redline | 메모리 분석 (Mandiant) | Windows |
| WinPrefetchView | Prefetch 분석 | Windows |
| RegRipper | 레지스트리 분석 | Cross |
| bulk_extractor | 대용량 데이터 추출 | Cross |
| TestDisk/PhotoRec | 삭제 파일 복구 | Cross |

---

## 11. CISA 인시던트 대응 플레이북 (FCEB 기준)

### 인시던트 유형별 플레이북 적용 기준
```
적용 대상 인시던트:
✓ 측면 이동(Lateral Movement), 자격증명 접근, 데이터 유출
✓ 다수 사용자/시스템에 걸친 네트워크 침해
✓ 관리자 계정 침해

적용 제외:
✗ 의도하지 않은 행동으로 추정되는 분류 정보 유출
✗ 피싱 이메일 클릭 후 침해가 없는 경우
✗ 단일 머신의 일반 악성코드 (대규모 피해 가능성 낮음)
```

### 위협 인텔리전스 지표 유형
```
1. 원자적 지표 (Atomic Indicators)
   - 도메인, IP 주소 → 알려진 캠페인 탐지에 유용
   - 단점: 공격자가 인프라를 자주 교체 (shelf-life 짧음)

2. 계산형 지표 (Computed Indicators)
   - YARA 규칙, 정규표현식 → 알려진 악성 아티팩트 탐지

3. 행위 기반 지표 (TTP Patterns)
   - MITRE ATT&CK 기법 기반 → 가장 지속성 높음
   - 공격자가 인프라를 바꿔도 TTP는 유사하게 유지
```

### CISA 준비 활동 체크리스트
```
정책/절차:
□ 인시던트 대응 계획 문서화 (조정 리더 지정 절차 포함)
□ 주요 인시던트 에스컬레이션/보고 절차 수립
□ 법집행기관 통지 및 증거 공유 정책

계측 (Instrumentation):
□ AV/EDR, DLP, IDPS 광범위 구축
□ 호스트/앱/클라우드 로그 중앙 수집
□ SIEM 운영 + 위협 인텔리전스 피드 연동
□ 로그 보존 기간: EO 14028 Sec.8 기준 충족

능동 방어 (Active Defense):
□ 허니팟/허니넷으로 공격자 샌드박스 유도 가능 여부
□ 허니토큰(fictitious data)으로 악성 활동 경보 설정
□ 다크넷으로 공격자 합법 인프라 발견 지연

고가치 자산 (HVA):
□ 비즈니스 HVA 목록화 (서버, 앱, 데이터, 신원)
□ HVA에 강화된 보호/탐지 컨트롤 적용
□ HVA 복구 절차 문서화 및 검증
```

### 인시던트 위기 대응 커뮤니케이션 원칙
```
효과적인 위기 커뮤니케이션 원칙:
1. 투명성 (Transparency)
   - 사실에 기반한 정기 업데이트 제공
   - 추측이나 억압된 정보는 더 큰 혼란 초래

2. 이해관계자별 맞춤 커뮤니케이션
   - 내부: CEO, CRO, GC, 사업부장
   - 외부: 고객, 파트너, 규제기관, 미디어
   - 각 그룹에 필요한 정보만 (Need-to-know)

3. 신속 대응
   - 침묵은 더 많은 추측을 낳음
   - 소셜 미디어 허위 정보 선제적 대응

커뮤니케이션 시 주의:
✗ 검증되지 않은 기술 세부사항 공개 금지
✗ 기술 담당자가 외부 언론 직접 응대 금지 (압박 취약)
✗ 협력사/컨설턴트의 정보 유출 방지 (NDA 필수)
```

---

## 12. 취약점 대응 플레이북 (CISA FCEB 기준)

### 취약점 대응 프로세스 4단계
```
1. 식별 (Identification)
   - CISA 지시/경고, 스캐너 결과, 벤더 권고문 기반 취약점 식별
   - CVE ID, CVSS 점수, 익스플로잇 가능 여부 확인
   - 영향받는 자산 목록화 (인벤토리 기반)

2. 평가 (Evaluation)
   - 비즈니스 영향도와 익스플로잇 위험성 기반 우선순위 결정
   - 패치 가능 여부 판단 (즉시 패치 / 완화 조치 / 수용)
   - 의존성 및 롤백 계획 검토

3. 치료 (Remediation)
   - 고위험: 24-72시간 내 패치 적용 목표
   - 중위험: 30일 내 처리
   - 저위험: 분기별 패치 사이클
   - 패치 불가 시: 네트워크 분리, 방화벽 규칙, 모니터링 강화

4. 보고 (Reporting)
   - 패치 완료 확인 (스캔 재실행)
   - CISA 보고 요건 충족 여부 확인
   - 보고서 작성 (취약점 → 조치 → 검증 타임라인)
```

### 취약점 대응 체크리스트 (CISA)
```
준비:
□ 자산 인벤토리 최신 상태 유지 (소프트웨어, 하드웨어)
□ 패치 관리 도구 구성 (WSUS, Ansible, Puppet)
□ 취약점 스캔 도구 정기 실행 (Nessus, OpenVAS)
□ 벤더 보안 공지 구독

식별/평가:
□ CVSS v3.1 기준 9.0 이상 → 즉시 조치
□ CISA KEV(Known Exploited Vulnerabilities) 카탈로그 확인
□ 익스플로잇 코드 공개 여부 확인

완화:
□ 패치 적용 또는 임시 완화 조치 문서화
□ 완화 후 재스캔으로 치료 검증
□ 재발 방지 대책 수립
```

---

## 13. 복구 결정 프레임워크 (Incident Response Reference Guide)

### 사전 복구 준비 사항
```
기술 준비:
✓ 신뢰할 수 있는 소프트웨어 배포 시스템 검증
  → 스크립트/설치관리자를 모든 엔드포인트에 신속 실행 가능 여부
✓ 오프라인 백업 및 랜섬웨어 저항 백업 검증 (복구 테스트)
✓ 침해된 계정 복구 절차 문서화
  - 침해 신뢰도 수준별 처리 (활성 공격자 vs 의심 계정)
  - 비밀번호 재설정 vs 계정 재생성 기준
✓ 호스트 OS 재구축 절차 (워크스테이션/서버별)
✓ 인터넷 이그레스 지점 C2 채널 탐지/차단 절차

운영 준비:
✓ ICS(Incident Command System) 체계 적용
✓ 정기 위기 시뮬레이션 및 Tabletop 훈련
✓ 비상 신속 승인 프로세스 수립
✓ 에스컬레이션 임계값 문서화 (내부 vs 외부 전문가 전환 기준)

법적/커뮤니케이션 준비:
✓ 법무팀과 인시던트 보고 요건 사전 검토
✓ 위기 커뮤니케이션 계획 및 대변인 지정
✓ 고객/파트너 통지 절차

핵심 교훈:
- 비밀번호 재설정 + C2 차단만으로는 불충분
  → 호스트에서 악성코드 탐지 및 제거 병행 필수
- 보안 직원을 IT 운영과 겸직시키면 효과 저하
- 도구를 구매해도 사용 기술/시간 없으면 낭비
```

---

## 14. 위기 커뮤니케이션 (Cyber Crisis Communication)

### 위기 커뮤니케이션 이해관계자 분류
```
내부 이해관계자 (알림 우선순위 높음):
  CEO, CRO, GC(법무), CFO, COO, CMO, 비즈니스 리더

외부 이해관계자 (Need-to-Know 원칙):
  고객, 파트너, 공급망, 규제기관, 미디어, 보험사

위기 커뮤니케이션 4R 원칙:
  Readiness (준비)   - 위기 시나리오별 커뮤니케이션 플레이북
  Response  (대응)   - 신속하고 사실 기반 초기 대응
  Reassurance (안심) - 이해관계자 신뢰 회복 메시지
  Recovery  (복구)   - 재발 방지 및 개선 사항 공유
```

### 위기 커뮤니케이션 플레이북 핵심
```
"What to communicate, When, to Whom, How, Why, by Who"

정의해야 할 시나리오 예시 (15~20개):
  - 랜섬웨어 발생
  - 민감정보 다크웹 유출
  - DDoS 공격
  - 내부 시스템 취약점 공개
  - 대용량 데이터 유출 시도
  - 내부 네트워크 악성코드 전파

위기 커뮤니케이션 함정 회피:
✗ 검증되지 않은 기술 세부사항 즉시 공개 금지
✗ 기술 담당자(SOC)가 외부 미디어 직접 대응 금지
  → SOC 인력이 압박 상황에서 실수하기 쉬움
✗ 협력사/컨설턴트의 정보 유출 방지 (NDA 체결 필수)
✗ "우리는 해킹당하지 않았다"는 부인보다 사실 공개 우선
  → 나중에 드러나면 신뢰 회복 불가

사회적 미디어 대응:
  - 침묵은 더 많은 추측을 낳음
  - 소셜 미디어 허위 정보 선제적 차단
  - 공식 채널을 통한 정기 업데이트 제공
```

---

## 15. DDoS 공격 대응 가이드 (CISA)

### OSI 계층별 DDoS 공격 및 완화
```
7계층 (Application):
  공격: HTTP GET/POST 플러드, Slowloris
  영향: 서비스 리소스 고갈
  완화: 애플리케이션 모니터링, WAF, 속도 제한

6계층 (Presentation):
  공격: 비정형 SSL 요청 (SSL 검사는 리소스 집약적)
  영향: SSL 연결 처리 불가
  완화: SSL 오프로딩, 애플리케이션 딜리버리 플랫폼(ADP)

5계층 (Session):
  공격: Telnet DDoS (세션 관리 취약점)
  영향: 스위치 관리 기능 마비

4계층 (Transport):
  공격: SYN Flood, UDP Flood
  영향: 대역폭/연결 한계 초과
  완화: 블랙홀링(Blackholing), 속도 제한

3계층 (Network):
  공격: ICMP Flooding (Smurf Attack)
  영향: 네트워크 대역폭 포화
  완화: ICMP 트래픽 속도 제한

2계층 (Data Link):
  공격: MAC 주소 플러딩
  영향: 스위치 CAM 테이블 포화
  완화: 포트별 MAC 수 제한, AAA 서버 인증
```

### DDoS 대응 전략
```
블랙홀링(Blackholing):
  - ISP 수준에서 공격 트래픽 차단
  - 단점: 합법적 트래픽도 차단됨

스크러빙 센터:
  - 트래픽을 스크러빙 센터로 우회
  - 악성 트래픽 제거 후 원본 서버로 전달

CDN/클라우드 DDoS 보호:
  - Cloudflare, AWS Shield, Azure DDoS Protection
  - 분산 인프라로 공격 트래픽 흡수
```
