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
```bash
# 설치
pip install volatility3
# 또는
git clone https://github.com/volatilityfoundation/volatility3

# OS 프로파일 식별
vol.py -f memory.lime banners.Banners   # Linux
vol.py -f memory.dmp windows.info       # Windows

# 프로세스 목록
vol.py -f memory.dmp windows.pslist
vol.py -f memory.dmp windows.pstree    # 트리 형태
vol.py -f memory.dmp windows.psscan    # 숨겨진 프로세스 탐지

# 네트워크 연결
vol.py -f memory.dmp windows.netstat

# 악성코드 탐지
vol.py -f memory.dmp windows.malfind   # 주입된 코드 탐지
vol.py -f memory.dmp windows.dlllist   # DLL 목록
vol.py -f memory.dmp windows.cmdline   # 명령줄 인자

# 레지스트리 분석
vol.py -f memory.dmp windows.registry.hivelist  # 하이브 목록
vol.py -f memory.dmp windows.registry.printkey --key "Software\Microsoft\Windows\CurrentVersion\Run"

# 파일 복구
vol.py -f memory.dmp windows.dumpfiles --physaddr 0x1234  # 특정 파일

# 해시 덤프
vol.py -f memory.dmp windows.hashdump  # SAM 해시 추출
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
```bash
# access.log 형식:
# IP - - [날짜] "메서드 경로 프로토콜" 상태코드 크기 "Referer" "User-Agent"

# 공격 IP 상위 10개
awk '{print $1}' access.log | sort | uniq -c | sort -rn | head -10

# 에러 응답 (공격 탐지)
grep " 404 " access.log | head
grep " 500 " access.log | head

# SQL Injection 시도 탐지
grep -i "union\|select\|drop\|insert\|delete\|update" access.log
grep -i "'\|%27\|1=1\|or 1" access.log

# XSS 시도 탐지
grep -i "script\|javascript\|onerror\|onload" access.log

# 디렉토리 탐색 시도
grep "\.\./\|\.\.%2f\|%2e%2e" access.log

# 특정 시간대 분석
awk '$4 >= "[01/Jan/2024:09:00:00" && $4 <= "[01/Jan/2024:10:00:00"' access.log

# 상태 코드별 통계
awk '{print $9}' access.log | sort | uniq -c | sort -rn
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

## 7. 도구 모음

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
