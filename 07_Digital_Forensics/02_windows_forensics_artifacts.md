# Windows 포렌식 아티팩트 완전 분석

## 1. Windows 포렌식 핵심 아티팩트

```
아티팩트(Artifact) = 사용자/시스템 활동의 디지털 흔적

주요 아티팩트 위치:
├── 레지스트리 하이브
├── 이벤트 로그 (.evtx)
├── Prefetch 파일
├── LNK 파일 (바로가기)
├── Jump Lists
├── 썸네일 캐시
├── 브라우저 히스토리
├── 윈도우 페이지 파일 / 하이버네이션
└── $MFT (마스터 파일 테이블)
```

---

## 2. 레지스트리 포렌식

### 주요 하이브 파일 위치
```
C:\Windows\System32\config\
├── SAM         → 사용자 계정 정보 (비밀번호 해시)
├── SECURITY    → 보안 정책 및 LSA 시크릿
├── SYSTEM      → 하드웨어 설정, 서비스, 네트워크
├── SOFTWARE    → 설치된 프로그램, 시스템 설정
└── DEFAULT     → 기본 사용자 프로파일

C:\Users\[사용자]\
├── NTUSER.DAT  → 사용자별 설정, MRU 목록
└── AppData\Local\Microsoft\Windows\UsrClass.dat → Shell Bags
```

### 2-1. 사용자 계정 분석 (SAM)

```bash
# impacket으로 해시 덤프
secretsdump.py -sam SAM -system SYSTEM LOCAL

# Volatility (메모리에서)
python3 vol.py -f memdump.raw windows.hashdump

# 결과 형식:
# Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
#  사용자명  RID         LM Hash                              NT Hash

# NT Hash 크랙 (hashcat)
hashcat -m 1000 -a 0 hashes.txt rockyou.txt
hashcat -m 1000 -a 3 31d6cfe0d16ae931b73c59d7e0c089c0 ?a?a?a?a?a?a?a?a
```

### 2-2. 자동 실행 분석 (지속성)

```
주요 자동 실행 레지스트리 키:

[시스템 전체]
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run  (32bit on 64bit)
HKLM\SYSTEM\CurrentControlSet\Services  (서비스)

[현재 사용자]
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\Load

[숨겨진 자동 실행]
HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell  (보통 explorer.exe)
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit

[AppInit DLL (모든 프로세스에 로드)]
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs
```

```bash
# Autoruns (Sysinternals) - GUI 도구
autoruns.exe  # 자동 실행 항목 모두 표시 + VirusTotal 연동

# RegRipper
rip.pl -r NTUSER.DAT -p run  # Run 키 추출
rip.pl -r SOFTWARE -p autoruns  # 모든 자동 실행
```

### 2-3. 최근 실행 프로그램 (MRU)

```
최근 실행 파일 목록:
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths

최근 열린 파일:
HKCU\SOFTWARE\Microsoft\Office\[버전]\Word\File MRU
HKCU\SOFTWARE\Microsoft\Office\[버전]\Excel\File MRU

검색 기록:
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery
```

### 2-4. USB 연결 기록

```
연결된 USB 디바이스:
HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR
├── 제조사_모델명_버전
│   └── 고유 시리얼 번호
│       ├── FriendlyName (표시 이름)
│       └── 마지막 연결 시간

HKLM\SYSTEM\CurrentControlSet\Enum\USB  (USB 컨트롤러)
HKLM\SYSTEM\MountedDevices  (드라이브 문자 매핑)
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2

# RegRipper로 USB 기록 추출
rip.pl -r SYSTEM -p usbstor
```

---

## 3. 이벤트 로그 포렌식

### 주요 이벤트 로그 파일
```
C:\Windows\System32\winevt\Logs\

Security.evtx     → 로그인/로그아웃, 파일 접근, 권한 변경
System.evtx       → 시스템 이벤트, 서비스 시작/중지
Application.evtx  → 응용프로그램 이벤트
Microsoft-Windows-PowerShell%4Operational.evtx  → PowerShell 명령 기록
Microsoft-Windows-Sysmon%4Operational.evtx      → Sysmon (있을 경우)
Microsoft-Windows-TaskScheduler%4Operational.evtx → 예약 작업
Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx → RDP 세션
```

### 3-1. 중요 이벤트 ID

```
[로그인/로그아웃]
4624  → 성공적인 로그인
4625  → 로그인 실패 (브루트포스 확인)
4634  → 로그오프
4648  → 명시적 자격증명으로 로그인 (Runas)
4672  → 관리자 권한 로그인 (특별 권한)
4768  → Kerberos TGT 요청
4769  → Kerberos 서비스 티켓 요청
4776  → NTLM 인증

[계정 관리]
4720  → 사용자 계정 생성
4722  → 사용자 계정 활성화
4724  → 비밀번호 재설정 시도
4728  → 그룹에 사용자 추가
4732  → Administrators 그룹에 사용자 추가!
4756  → Universal 그룹에 멤버 추가

[프로세스/실행]
4688  → 프로세스 생성 (감사 정책 활성화 시)
4689  → 프로세스 종료
7045  → 새 서비스 설치 (System 로그)
7036  → 서비스 상태 변경

[파일/레지스트리]
4663  → 파일/레지스트리 접근 (감사 설정 필요)
4656  → 파일/레지스트리 핸들 요청

[PowerShell]
4103  → 파이프라인 실행 (모듈 로깅)
4104  → 스크립트 블록 로깅 (코드 내용 기록)

[네트워크]
5156  → Windows Filtering Platform 허용
5158  → 소켓 바인딩 허용
```

### 3-2. 이벤트 로그 분석 도구

```python
#!/usr/bin/env python3
"""
Windows EVTX 이벤트 로그 포렌식 분석기
용도: .evtx 파일에서 IOC·공격 패턴 추출, CSV/JSON 리포트 생성
의존성: pip install python-evtx
"""
from __future__ import annotations
import argparse
import csv
import json
import sys
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path

try:
    import Evtx.Evtx as evtx
    import Evtx.Views as e_views
except ImportError:
    print("[!] 의존성 누락: pip install python-evtx", file=sys.stderr)
    sys.exit(1)

# 탐지 대상 이벤트 ID 정의
SECURITY_EVENTS: dict[int, str] = {
    4624: "로그인 성공",
    4625: "로그인 실패 (브루트포스 의심)",
    4634: "로그오프",
    4648: "명시적 자격증명 로그인 (Runas)",
    4672: "관리자 권한 로그인",
    4720: "사용자 계정 생성",
    4722: "사용자 계정 활성화",
    4732: "Administrators 그룹에 구성원 추가",
    4756: "전역 그룹에 구성원 추가",
    4776: "NTLM 자격증명 검증",
    4688: "프로세스 생성",
    7045: "새 서비스 설치 (악성 서비스 의심)",
    1102: "감사 로그 삭제 (로그 조작 의심)",
    4104: "PowerShell 스크립트 블록 로깅",
}

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


@dataclass
class EventRecord:
    event_id: int
    time_created: str
    description: str
    computer: str
    user_sid: str
    ip_address: str
    raw_data: dict


def _get_text(elem: ET.Element | None) -> str:
    return (elem.text or "").strip() if elem is not None else ""


def parse_event(xml_str: str) -> EventRecord | None:
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        return None

    system = root.find(f"{NS}System")
    if system is None:
        return None

    eid_elem = system.find(f"{NS}EventID")
    event_id = int(_get_text(eid_elem)) if eid_elem is not None else 0

    time_elem = system.find(f"{NS}TimeCreated")
    time_str = time_elem.get("SystemTime", "") if time_elem is not None else ""

    computer = _get_text(system.find(f"{NS}Computer"))

    security = system.find(f"{NS}Security")
    user_sid = security.get("UserID", "") if security is not None else ""

    # EventData 파싱
    raw_data: dict[str, str] = {}
    event_data = root.find(f"{NS}EventData")
    if event_data is not None:
        for data in event_data.findall(f"{NS}Data"):
            name = data.get("Name", "")
            value = _get_text(data)
            if name:
                raw_data[name] = value

    ip_address = raw_data.get("IpAddress", raw_data.get("WorkstationName", ""))
    description = SECURITY_EVENTS.get(event_id, f"EventID {event_id}")

    return EventRecord(
        event_id=event_id,
        time_created=time_str,
        description=description,
        computer=computer,
        user_sid=user_sid,
        ip_address=ip_address,
        raw_data=raw_data,
    )


def analyze_evtx(
    evtx_path: str,
    target_ids: set[int] | None = None,
    output_fmt: str = "console",
    output_file: str | None = None,
) -> list[EventRecord]:
    """
    EVTX 파일 분석 후 매칭 레코드 목록 반환.
    target_ids가 None이면 SECURITY_EVENTS 전체를 대상으로 함.
    """
    if target_ids is None:
        target_ids = set(SECURITY_EVENTS.keys())

    records: list[EventRecord] = []
    stats: Counter = Counter()

    with evtx.Evtx(evtx_path) as log:
        for record in log.records():
            try:
                xml_str = record.xml()
            except Exception:
                continue
            parsed = parse_event(xml_str)
            if parsed is None:
                continue
            stats[parsed.event_id] += 1
            if parsed.event_id in target_ids:
                records.append(parsed)

    # 브루트포스 탐지 (4625 IP 집계)
    fail_ips: Counter = Counter(
        r.ip_address for r in records if r.event_id == 4625 and r.ip_address
    )

    _output(records, stats, fail_ips, output_fmt, output_file)
    return records


def _output(
    records: list[EventRecord],
    stats: Counter,
    fail_ips: Counter,
    fmt: str,
    output_file: str | None,
) -> None:
    if fmt == "json":
        data = {
            "total_matched": len(records),
            "stats": dict(stats.most_common(20)),
            "brute_force_ips": fail_ips.most_common(10),
            "events": [asdict(r) for r in records],
        }
        text = json.dumps(data, indent=2, ensure_ascii=False)
        if output_file:
            Path(output_file).write_text(text, encoding="utf-8")
            print(f"[+] JSON 저장: {output_file}")
        else:
            print(text)

    elif fmt == "csv":
        rows = [asdict(r) for r in records]
        if rows:
            out = Path(output_file) if output_file else Path("evtx_analysis.csv")
            with out.open("w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=rows[0].keys())
                writer.writeheader()
                # raw_data는 JSON 직렬화
                for row in rows:
                    row["raw_data"] = json.dumps(row["raw_data"], ensure_ascii=False)
                    writer.writerow(row)
            print(f"[+] CSV 저장: {out}")

    else:  # console
        print(f"\n[*] 매칭 이벤트: {len(records)}건")
        print(f"\n[상위 이벤트 ID]")
        for eid, cnt in stats.most_common(10):
            desc = SECURITY_EVENTS.get(eid, "기타")
            print(f"  {eid:5d}  {cnt:6d}회  {desc}")

        if fail_ips:
            print(f"\n[브루트포스 의심 IP (4625 로그인 실패)]")
            for ip, cnt in fail_ips.most_common(10):
                print(f"  {ip:<20} {cnt}회")

        print(f"\n[최근 이벤트 (최대 20개)]")
        for r in records[-20:]:
            ts = r.time_created[:19].replace("T", " ")
            target = r.raw_data.get("TargetUserName", r.raw_data.get("SubjectUserName", ""))
            print(f"  [{ts}] EID={r.event_id:5d} {r.description:<30} {target} {r.ip_address}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Windows EVTX 이벤트 로그 포렌식 분석기")
    parser.add_argument("evtx", help=".evtx 파일 경로")
    parser.add_argument(
        "--ids", nargs="+", type=int,
        help="분석할 EventID 목록 (미지정 시 기본 보안 이벤트 전체)"
    )
    parser.add_argument(
        "--format", choices=["console", "json", "csv"], default="console",
        help="출력 형식 (기본값: console)"
    )
    parser.add_argument("--output", help="출력 파일 경로 (json/csv 형식 사용 시)")
    args = parser.parse_args()

    if not Path(args.evtx).exists():
        print(f"[!] 파일 없음: {args.evtx}", file=sys.stderr)
        sys.exit(1)

    analyze_evtx(
        args.evtx,
        target_ids=set(args.ids) if args.ids else None,
        output_fmt=args.format,
        output_file=args.output,
    )


if __name__ == "__main__":
    main()
```

---

## 4. Prefetch 분석

### Prefetch란?
```
Windows가 앱 로딩 속도 향상을 위해 저장하는 파일
C:\Windows\Prefetch\*.pf

포함 정보:
- 실행 파일 이름
- 실행 횟수
- 마지막 실행 시간 (최대 8회)
- 실행 시 로드된 DLL/파일 목록
- 실행 파일 경로

활성화 확인:
HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters
EnablePrefetcher = 1 또는 3
```

```bash
# PECmd (EricZimmerman 도구)
PECmd.exe -f MALWARE.EXE-XXXXXXXX.pf
PECmd.exe -d C:\Windows\Prefetch --csv output\ --csvf prefetch.csv

# Python (prefetch parser)
pip install prefetch-parser
python -m prefetch_parser MALWARE.EXE-XXXXXXXX.pf
```

---

## 5. LNK 파일 및 Jump Lists

### LNK (바로가기) 파일
```
최근 열린 파일의 바로가기:
C:\Users\[사용자]\AppData\Roaming\Microsoft\Windows\Recent\*.lnk

포함 정보:
- 원본 파일 경로 (로컬/네트워크)
- 파일 크기, 생성/수정/접근 시간
- 볼륨 시리얼 번호 (어떤 드라이브인지)
- 호스트명 (네트워크 파일인 경우)
```

```bash
# LECmd (LNK 파서)
LECmd.exe -f malware.lnk
LECmd.exe -d "C:\Users\user\Recent" --csv output\

# Python
from lnkparse3 import lnk_file
lnk = lnk_file("file.lnk")
print(lnk.get_json())
```

### Jump Lists
```
최근 파일 및 작업 목록 (작업 표시줄/시작 메뉴):
C:\Users\[사용자]\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\
C:\Users\[사용자]\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\
```

---

## 6. 브라우저 포렌식

### Chrome/Edge 아티팩트
```
C:\Users\[사용자]\AppData\Local\Google\Chrome\User Data\Default\

History          → 방문 기록 (SQLite)
Cache\           → 캐시 파일
Downloads        → 다운로드 기록 (SQLite)
Login Data       → 저장된 비밀번호 (암호화된 SQLite)
Cookies          → 쿠키 (SQLite)
Bookmarks        → 북마크 (JSON)
Extensions\      → 설치된 확장
```

```python
#!/usr/bin/env python3
"""
Chrome/Edge 브라우저 포렌식 분석기
용도: History SQLite DB에서 방문기록·다운로드·저장 폼 데이터 추출
의존성: 표준 라이브러리만 사용 (sqlite3, shutil)
"""
from __future__ import annotations
import argparse
import json
import shutil
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

# Chrome epoch: 1601-01-01 기준 마이크로초
CHROME_EPOCH_OFFSET = 11_644_473_600


def chrome_ts(microseconds: int) -> str:
    """Chrome 타임스탬프 → 사람이 읽을 수 있는 UTC 문자열."""
    if not microseconds:
        return ""
    try:
        ts = microseconds / 1_000_000 - CHROME_EPOCH_OFFSET
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (OSError, OverflowError):
        return str(microseconds)


def safe_copy(src: Path) -> Path:
    """
    Chrome이 잠근 DB를 직접 열면 오류 발생 → 임시 복사본 사용.
    """
    tmp = Path("/tmp") / f"chrome_forensic_{src.name}"
    shutil.copy2(src, tmp)
    return tmp


def extract_history(db_path: Path, limit: int = 200) -> list[dict]:
    tmp = safe_copy(db_path)
    records = []
    try:
        con = sqlite3.connect(f"file:{tmp}?mode=ro", uri=True)
        cur = con.execute(
            """
            SELECT url, title, visit_count, last_visit_time
            FROM urls
            ORDER BY last_visit_time DESC
            LIMIT ?
            """,
            (limit,),
        )
        for row in cur:
            records.append({
                "url": row[0],
                "title": row[1],
                "visit_count": row[2],
                "last_visit": chrome_ts(row[3]),
            })
        con.close()
    finally:
        tmp.unlink(missing_ok=True)
    return records


def extract_downloads(db_path: Path) -> list[dict]:
    tmp = safe_copy(db_path)
    records = []
    try:
        con = sqlite3.connect(f"file:{tmp}?mode=ro", uri=True)
        cur = con.execute(
            """
            SELECT target_path, tab_url, total_bytes, start_time, end_time, state
            FROM downloads
            ORDER BY start_time DESC
            LIMIT 200
            """
        )
        for row in cur:
            state_map = {0: "진행중", 1: "완료", 2: "취소", 4: "중단"}
            records.append({
                "path": row[0],
                "source_url": row[1],
                "size_bytes": row[2],
                "start": chrome_ts(row[3]),
                "end": chrome_ts(row[4]),
                "state": state_map.get(row[5], str(row[5])),
            })
        con.close()
    finally:
        tmp.unlink(missing_ok=True)
    return records


def analyze_profile(profile_dir: str, output_json: str | None = None) -> None:
    base = Path(profile_dir)
    history_db = base / "History"
    if not history_db.exists():
        print(f"[!] History DB 없음: {history_db}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] 프로파일 분석: {base}")

    history = extract_history(history_db)
    downloads = extract_downloads(history_db)

    # 의심 도메인 플래그
    suspicious_keywords = [".onion", "pastebin", "ngrok", "raw.githubusercontent", "temp.sh"]
    flagged = [
        h for h in history
        if any(kw in h["url"].lower() for kw in suspicious_keywords)
    ]

    result = {
        "profile": str(base),
        "history_count": len(history),
        "download_count": len(downloads),
        "flagged_count": len(flagged),
        "recent_history": history[:50],
        "downloads": downloads,
        "flagged_urls": flagged,
    }

    if output_json:
        Path(output_json).write_text(
            json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        print(f"[+] JSON 저장: {output_json}")
    else:
        print(f"\n[방문 기록 최근 20건]")
        for h in history[:20]:
            print(f"  {h['last_visit']}  {h['visit_count']:>3}회  {h['url'][:80]}")

        print(f"\n[다운로드 기록 ({len(downloads)}건)]")
        for d in downloads[:10]:
            print(f"  {d['start']}  {d['state']:<6}  {Path(d['path']).name}")

        if flagged:
            print(f"\n[의심 URL ({len(flagged)}건)]")
            for f in flagged:
                print(f"  {f['last_visit']}  {f['url']}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Chrome/Edge 브라우저 포렌식 분석기")
    parser.add_argument(
        "profile",
        help=(
            "Chrome 프로파일 디렉토리 경로\n"
            "  예: C:\\Users\\user\\AppData\\Local\\Google\\Chrome\\User Data\\Default"
        ),
    )
    parser.add_argument("--output", help="결과를 저장할 JSON 파일 경로")
    args = parser.parse_args()

    analyze_profile(args.profile, args.output)


if __name__ == "__main__":
    main()
```

---

## 7. 타임라인 분석

### 통합 타임라인 생성

```bash
# Plaso (log2timeline) — 강력한 타임라인 도구
# 이미지에서 모든 아티팩트 추출 → 통합 타임라인

# 이미지 파싱 (시간이 걸림)
log2timeline.py timeline.plaso disk_image.dd

# 타임라인 필터링
psort.py -o l2tcsv timeline.plaso "date > '2024-01-01 00:00:00' and date < '2024-01-02 00:00:00'" > timeline.csv

# Timesketch (웹 기반 타임라인 분석)
docker-compose up  # 설치 후
# 브라우저: http://localhost
```

### 수동 타임라인 구성

```bash
# KAPE (Kroll Artifact Parser and Extractor)
kape.exe --tsource C:\ --tdest output\ --tflux Windows
kape.exe --msource output\ --mdest results\ --mflux !EZParser

# 주요 아티팩트 수집 자동화:
# - 레지스트리 하이브
# - 이벤트 로그
# - Prefetch
# - LNK 파일
# - 브라우저 히스토리
# - Amcache.hve
```

---

## 8. 악성 활동 탐지 시나리오

### 시나리오 1: 악성코드 실행 흔적

```
조사 경로:
1. Prefetch → 악성 실행파일 실행 여부/시간 확인
2. 레지스트리 Run 키 → 지속성 메커니즘 확인
3. 이벤트 ID 4688 → 프로세스 생성 (명령행 인수 포함)
4. Amcache.hve → 처음 실행된 실행파일 기록
5. ShimCache/AppCompatCache → 실행 이력

# Amcache 분석 (처음 실행된 프로그램)
AmcacheParser.exe -f Amcache.hve --csv output\

# AppCompatCache (ShimCache) 분석
AppCompatCacheParser.exe -f SYSTEM --csv output\
```

### 시나리오 2: 측면 이동 (Lateral Movement)

```
조사 경로:
1. 이벤트 ID 4624 (로그인) + 로그온 타입
   - Type 3: 네트워크 로그인 (PsExec, net use)
   - Type 10: RemoteInteractive (RDP)
2. 이벤트 ID 4648 (명시적 자격증명)
3. C:\Windows\System32\winevt\Logs\Microsoft-Windows-TerminalServices-*.evtx
4. 서비스 생성 (이벤트 ID 7045) - PsExec 사용 시

로그온 타입 의미:
Type 2  → 대화형 (로컬 로그인)
Type 3  → 네트워크 (SMB, PsExec)
Type 4  → 배치 (예약 작업)
Type 5  → 서비스 계정
Type 7  → 잠금 해제
Type 8  → 네트워크 평문 전송
Type 9  → 새 자격증명 (RunAs)
Type 10 → 원격 대화형 (RDP)
Type 11 → 캐시된 대화형
```

### 시나리오 3: 데이터 유출

```
조사 경로:
1. 브라우저 다운로드/업로드 기록
2. USB 연결 기록 (USBSTOR)
3. 이메일 클라이언트 첨부파일 (Outlook PST)
4. 클라우드 동기화 폴더 (OneDrive, Dropbox)
5. 네트워크 공유 연결 기록
   HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2
6. 최근 파일 목록 (LNK, Jump Lists)
```

---

## 9. 레지스트리 중요 항목 심화 (포렌식 시험 필수)

### 레지스트리 하이브 파일 매핑
```
HKLM\Hardware          → 메모리에만 저장 (라이브 포렌식에서 직접 분석)
HKLM\SAM               → WINDOWS\system32\config\SAM
HKLM\Security          → WINDOWS\system32\config\SECURITY
HKLM\Software          → WINDOWS\system32\config\software
HKLM\SYSTEM            → WINDOWS\system32\config\system
HKU                    → Documents and Settings\사용자명\ntuser.dat
HKU\.DEFAULT           → WINDOWS\system32\config\default
```

### 포렌식 핵심 레지스트리 키
```
[OS 설치 정보]
HKLM\Software\Microsoft\WindowsNT\CurrentVersion
  - installDate   : DCode 프로그램으로 디코드 (Unix:32bit Hex Value - Big Endian)
  - CurrentVersion: OS 버전 (5.1 = WindowsXP)
  - CSDVersion    : 설치된 서비스팩

[마지막 로그인 사용자]
HKLM\Software\Microsoft\Winnt\CurrentVersion\Winlogon
  - default Username   : 마지막 사용한 사용자
  - default Domainname : 컴퓨터이름

[시스템 종료 시간]
HKLM\SYSTEM\CurrentControlSet\Control\Windows
  - ShutdownTime : 가장 최근 시스템 종료 시간
  - 디코드: DCode → Windows: 64bit Hex Value - Little Endian

[타임존]
HKLM\SYSTEM\CurrentControlSet\Control\TimeZoneInformation
  - 대한민국 표준시 : UTC +09:00

[UserAssist - 실행 프로그램 기록]
HKU\{SID}\Software\Microsoft\Windows\CurrentVersion\Explorer\Userassist\75...\Count
  - ROT13 인코딩 되어 있음 (A→N, B→O...)
  - www.rot13.org 에서 디코드 가능

[SID 구조]
S-1-5-21-{시스템고유번호}-{사용자번호}
  - 500 = Administrator
  - 501 = Guest
  - 1000번 이상 = 일반 계정 (순서대로 부여)

[MRU (Most Recently Used) 목록]
HKU\{SID}\Software\Microsoft\Windows\CurrentVersion\Explorer\Comdlg32\OpenSaveMRU\{확장자}
  → 마지막으로 열거나 저장한 파일 목록

HKU\{SID}\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
  → [실행] 창 입력 내역

[MUI Cache - 설치된 프로그램 흔적]
HKU\{SID}\Software\Microsoft\Windows\ShellNoRoam\MUICache

[네트워크 인터페이스 정보]
HKLM\System\CurrentControlSet\Service\Tcpip\Parameters\Interfaces\{GUID}
  → 현재/과거 NIC의 IP 주소, 서브넷 등 네트워크 설정

[공유자원 기록]
HKLM\SYSTEM\CurrentControlSet\Services\LANmanserver\Shares
  → 수동으로 설정한 공유항목
```

### 자동 실행 관련 레지스트리 (악성코드 지속성 탐지)
```
시스템 전체 자동 실행:
HKLM\SYSTEM\CurrentControlSet\Services\*
HKLM\Software\Microsoft\Windows\CurrentVersion\Run      ← 로그온 없이도 실행
HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce

사용자 자동 실행:
HKCU\Software\Microsoft\Windows\CurrentVersion\Run      ← 사용자 로그온 시 실행
HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce

포인트: 해커 제작 서비스는 설명(Description) 항목이 비어 있는 경우가 많음
```

### 이동식 저장소 연결 기록 (USB 포렌식 상세)
```
HKLM\System\CurrentControlSet\Enum\USB
  - Vendor Id (16bit): 하드웨어 제조사 고유번호
  - Device ID(=Product ID): 하드웨어 모델 고유번호
  - 참고: pciids.sourceforge.net

ControlSet 구조:
  HKLM\SYSTEM\CurrentControlSet → 바로가기
  ControlSet001 → 가장 최근 부팅에서 사용된 키 값 (일반)
  ControlSet002 → 마지막으로 성공한 구성 키 값
```

---

## 10. Windows Live Data 수집 (휘발성 정보 수집 순서)

### 수집 우선순위 (휘발성 높은 순)
```
① 물리메모리 덤프
② 시스템 기본 정보 (날짜/시간, OS 버전, 호스트명)
③ 네트워크 정보
④ 프로세스 정보
⑤ DLL 파일 목록
⑥ 로그온 유저
⑦ 열린 파일
⑧ 서비스 / 시작프로그램 정보
⑨ 명령 히스토리
⑩ 예약 작업
⑪ 클립보드
⑫ 공유자원

주의: Live Data 수집 시 가급적 CLI(Command Line Interface) 사용
  - 메모리를 적게 사용
  - DLL 의존도 낮음
  - 시스템에 미치는 영향 최소화
```

### 휘발성 정보 수집 명령어 (Windows)
```cmd
:: 날짜/시간 확인 (가장 먼저 수행)
date /t & time /t
now.exe

:: 시스템 기본 정보
hostname
ver
echo %username% %userdomain%
uptime
systeminfo

:: 네트워크 정보
netstat -nao          :: 모든 연결 (PID 포함)
                      :: 1024 이상 포트 상세 조사 필요
ipconfig /all
promiscdetect         :: NIC가 promiscuous mode인지 확인

:: 프로세스 정보
tasklist
pslist                :: PID, 우선순위, 스레드, 핸들, 가상메모리
tlist [PID]           :: 특정 프로세스 경로 확인
listdlls              :: 프로세스별 DLL 목록
listdlls [PID]        :: 특정 프로세스 DLL 확인

:: 핵심 프로세스 위치 검증 (비정상이면 악성 의심)
:: smss.exe, lsass.exe, taskmgr, wininit, winlogon.exe
:: → 정상 위치: C:\Windows\system32\

:: 로그온 유저
net session            :: 현재 로그온 세션
psloggedon             :: 로컬 + 원격 접속 사용자
logonsessions          :: SID, 인증방식, 로그온 타입, 로그온 시간 포함

:: 열린 파일
psfile                 :: 원격에서 실행 중인 파일

:: 서비스 / 시작프로그램
psservice              :: 모든 서비스 목록 + 세부정보
autorunsc              :: 시작프로그램 목록

:: 명령 히스토리
doskey /history

:: 예약 작업 (백도어 확인)
at

:: 클립보드
clipbrd

:: 공유자원 (악성코드 전파 경로)
net share

:: NC를 이용한 원격 데이터 전송
:: 조사 시스템: nc -l -p 5555 > c:\output.txt
:: 피해 시스템: psinfo.exe | nc [조사IP] 5555
```

### Windows 이벤트 로그 파일 위치
```
C:\WINDOWS\system32\config\
  AppEvent.evt   → 응용프로그램 이벤트 (구버전 Windows)
  SecEvent.evt   → 보안 이벤트
  SysEvent.evt   → 시스템 이벤트

C:\Windows\System32\winevt\Logs\  (Vista 이상 .evtx 형식)
  Security.evtx
  System.evtx
  Application.evtx

IIS 로그:
  C:\WINDOWS\system32\Logfiles\W3SVC1\ex{날짜}.log
  필드: date time s-ip cs-method cs-uri-stem s-port c-ip sc-status
```

---

## 11. 디지털 증거 수집 절차

### 현장 수집 순서 (증거 휘발성 순서)

```
1. CPU 레지스터, 캐시
2. 메모리 (RAM) ← Volatility로 분석
3. 네트워크 트래픽, 상태 (netstat, arp)
4. 실행 중인 프로세스 목록
5. 디스크 이미지 (FTK Imager, dd)
6. 로그 파일
7. 타임존 설정
```

### 증거 무결성 보장

```bash
# 디스크 이미지 생성 (쓰기 방지 필수!)
# 쓰기 차단 장치 연결 후:
dd if=/dev/sdb of=evidence.dd bs=4096 conv=noerror,sync status=progress

# 또는 FTK Imager (GUI, 해시 자동 생성)
# 또는 dcfldd (해시 동시 생성)
dcfldd if=/dev/sdb of=evidence.dd hash=sha256 hashlog=hash.txt

# 이미지 무결성 검증
sha256sum evidence.dd > evidence.dd.sha256
sha256sum -c evidence.dd.sha256  # 이후 검증 시

# 증거 봉인 메모 (Chain of Custody)
echo "증거물: evidence.dd" > chain_of_custody.txt
echo "수집일시: $(date)" >> chain_of_custody.txt
echo "수집자: [이름]" >> chain_of_custody.txt
echo "SHA256: $(sha256sum evidence.dd)" >> chain_of_custody.txt
```

---

## 12. 레지스트리 심화 — 포렌식 시험 핵심

### USBSTOR 장치 최초 설치 시각 확인
```
USBSTOR 연결 기록 추가 정보:
HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR\{제품}\{시리얼}

파생 정보:
  - 0064 항목: 장치 최초 설치 시간 (수동 계산)
  - FriendlyName: 사용자에게 표시된 드라이브명
  - 타임스탬프: setupapi.log에서 최초 연결 시각 확인 가능

setupapi.log 위치:
  XP:    C:\WINDOWS\setupapi.log
  Vista+: C:\Windows\inf\setupapi.dev.log

분석:
  - "[Device Install" 문자열 검색
  - 해당 시리얼 번호와 매칭하여 최초 연결 일시 확인
```

### Windows 이벤트 로그 파일 포맷 역사
```
Windows XP/2003 (구버전):
  - 확장자: .evt
  - 위치: C:\WINDOWS\system32\config\
  - 파일: AppEvent.evt, SecEvent.evt, SysEvent.evt

Windows Vista 이상 (현재):
  - 확장자: .evtx
  - 위치: C:\Windows\System32\winevt\Logs\
  - 파일: Security.evtx, System.evtx, Application.evtx

IIS 로그 위치 및 형식:
  C:\WINDOWS\system32\Logfiles\W3SVC1\ex{날짜}.log
  주요 필드: date time s-ip cs-method cs-uri-stem s-port c-ip sc-status
```

### UserAssist 디코딩
```
UserAssist 키 경로:
HKU\{SID}\Software\Microsoft\Windows\CurrentVersion\
  Explorer\UserAssist\{GUID}\Count

특징:
  - ROT13 인코딩 (A↔N, B↔O, ... Z↔M)
  - 실행 횟수, 마지막 실행 시간 포함
  - 디코딩 도구: www.rot13.org

ROT13 디코딩 예시:
  URYHF.RKR → HELUS.EXE (Hulu.exe)
  PZQYL.RKR → cmd.exe

GUID별 의미:
  {75048700-...} → 파일 시스템 개체
  {CEBFF5CD-...} → 실행 가능 파일
```

---

## 13. 파일시스템 포렌식 핵심 개념

### NTFS $MFT (마스터 파일 테이블)
```
$MFT 구조:
  - NTFS 볼륨의 모든 파일/폴더에 대한 메타데이터 레코드
  - 각 레코드: 1KB (기본)
  - 파일 삭제 시 MFT 레코드는 "사용 가능"으로 표시 → 내용은 남음

$MFT 주요 속성:
  $STANDARD_INFORMATION  → MACE 타임스탬프 (수정 가능 - 타임스톰핑)
  $FILE_NAME             → 파일명에 연결된 타임스탬프 (조작 어려움)
  $DATA                  → 실제 파일 데이터
  $BITMAP                → 클러스터 할당 상태

타임스톰핑 탐지:
  $STANDARD_INFORMATION 수정 시간 < $FILE_NAME 생성 시간
    → 타임스톰핑 의심 (나노초 값 = 0도 의심 신호)
```

### 삭제 파일 복구 원리
```
파일 삭제 시 OS 동작:
  1. MFT 레코드를 "미사용"으로 표시
  2. $Bitmap에서 해당 클러스터를 "사용 가능"으로 표시
  3. 실제 데이터는 덮어쓰기 전까지 디스크에 남음

복구 가능성 결정 요인:
  - 삭제 후 경과 시간 (짧을수록 복구 가능성 높음)
  - 시스템 사용 정도 (사용할수록 덮어쓰기 가능성 증가)
  - SSD vs HDD: SSD는 TRIM 명령으로 즉시 삭제될 수 있음

파일 카빙 (File Carving):
  - MFT 레코드 없이도 파일 시그니처로 파일 복구
  - 파일 헤더/푸터 시그니처 기반 스캔
  - 도구: PhotoRec, Foremost, Scalpel

파일 시그니처 예시:
  JPG: FF D8 FF (헤더) ... FF D9 (푸터)
  PNG: 89 50 4E 47 0D 0A 1A 0A (헤더)
  PDF: 25 50 44 46 (헤더, "%PDF")
  ZIP: 50 4B 03 04 (헤더)
  DOCX: 50 4B 03 04 (ZIP 기반)
```

### 볼륨 섀도 복사본(VSS) 포렌식
```
VSS 위치 및 접근:
  vssadmin list shadows  → 섀도 복사본 목록 확인

포렌식에서의 활용:
  - 삭제된 파일의 이전 버전 복구
  - 레지스트리 하이브 이전 상태 복구
  - 악성코드 실행 전 상태 분석

VSS 마운트 (관리자 권한):
  mklink /d C:\shadow \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\

랜섬웨어 대응 관점:
  vssadmin delete shadows /all  → 랜섬웨어의 전형적 행위
  wmic shadowcopy delete        → WMI 기반 VSS 삭제 (동일 목적)
  → 이 명령 실행 = 랜섬웨어 또는 악의적 행위 강한 의심
```
