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

```bash
# Windows 이벤트 뷰어
eventvwr.msc

# PowerShell로 이벤트 검색
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4624]]" | 
  Select-Object TimeCreated, Message | Format-List

# 특정 기간 이벤트 검색
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4624 and TimeCreated[@SystemTime>='2024-01-01T00:00:00']]]"

# 로그인 실패 IP 추출
Get-WinEvent -LogName Security | 
  Where-Object {$_.Id -eq 4625} | 
  ForEach-Object {
    $xml = [xml]$_.ToXml()
    $xml.Event.EventData.Data | Where-Object {$_.Name -eq "IpAddress"}
  }
```

```bash
# EvtxECmd (KAPE 도구)
EvtxECmd.exe -f Security.evtx --csv output\ --csvf security_events.csv

# Chainsaw (Rust 기반 빠른 분석)
chainsaw hunt Security.evtx --rules rules/ --sigma sigma/

# Hayabusa (Windows 이벤트 로그 분석)
hayabusa-2.x.x-win-x64.exe csv-timeline -f Security.evtx -o timeline.csv
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

```bash
# SQLite로 히스토리 추출
sqlite3 History "SELECT datetime(last_visit_time/1000000-11644473600,'unixepoch','localtime'), url, title FROM urls ORDER BY last_visit_time DESC LIMIT 100;"

# HindsightBrowser (자동화)
hindsight.py -i "C:\Users\user\AppData\Local\Google\Chrome\User Data\Default" -o output

# NirSoft BrowsingHistoryView (GUI)
BrowsingHistoryView.exe /shtml output.html
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

## 9. 디지털 증거 수집 절차

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
