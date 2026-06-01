> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 01 Bash Scripting Basics

---

## 1. 변수와 배열

### 기본 변수


배시 스크립트의 시작 부분입니다. `set -euo pipefail`을 추가하면 오류 발생 시 즉시 종료하는 안전한 스크립트를 작성할 수 있습니다.

```bash
#!/usr/bin/env bash
set -euo pipefail   # 오류 즉시 종료, 미정의 변수 오류, 파이프 오류 전파
IFS=$'\n\t'         # 안전한 구분자

# 변수 선언 및 타입
TARGET="192.168.1.0/24"
PORT=443
readonly LOG_DIR="/var/log/scan"   # 읽기 전용
declare -i COUNT=0                  # 정수형
declare -l LOWER="HELLO"           # 자동 소문자 → hello
declare -u UPPER="world"           # 자동 대문자 → WORLD

# 문자열 조작
PATH_STR="/home/user/file.txt"
echo "${PATH_STR##*/}"     # 파일명만: file.txt
echo "${PATH_STR%/*}"      # 디렉토리만: /home/user
echo "${PATH_STR%.txt}"    # 확장자 제거: /home/user/file
echo "${PATH_STR/user/root}"  # 치환: /home/root/file.txt

# 기본값 처리
NAME="${1:-anonymous}"          # 인자 없으면 anonymous
CONFIG="${CONFIG_FILE:=/etc/app.conf}"  # 미설정이면 기본값 세팅
: "${REQUIRED_VAR:?'REQUIRED_VAR must be set'}"  # 미설정 시 에러
```

### 배열

```bash
# 인덱스 배열
PORTS=(22 80 443 8080 8443)
PORTS+=(3306 5432)               # 추가
echo "${PORTS[0]}"               # 첫 번째 원소: 22
echo "${PORTS[@]}"               # 전체 원소
echo "${#PORTS[@]}"              # 원소 개수: 7
echo "${PORTS[@]:2:3}"           # 슬라이싱 (인덱스 2부터 3개)
unset 'PORTS[1]'                 # 특정 원소 삭제

# 연관 배열 (딕셔너리)
declare -A SERVICES
SERVICES[ssh]=22
SERVICES[http]=80
SERVICES[https]=443

for svc in "${!SERVICES[@]}"; do
    printf "%-10s → %d\n" "$svc" "${SERVICES[$svc]}"
done

# 배열로 명령어 출력 읽기
mapfile -t OPEN_PORTS < <(ss -tlnp | awk 'NR>1 {print $4}' | grep -oP ':\K\d+' | sort -un)
echo "열린 포트: ${OPEN_PORTS[*]}"
```

---

## 2. 산술 연산

```bash
# 정수 연산
A=10; B=3
echo $(( A + B ))    # 13
echo $(( A % B ))    # 1
echo $(( A ** B ))   # 1000  (거듭제곱)
echo $(( A / B ))    # 3 (정수 나눗셈)

# 부동소수점 — bc 사용
PI=$(echo "scale=5; 4*a(1)" | bc -l)
RATIO=$(echo "scale=2; $A / $B" | printf "%.2f" $(bc -l))

# 비트 연산 (포트/IP 계산에 유용)
IP_INT=$(( (192 << 24) | (168 << 16) | (1 << 8) | 100 ))
echo "IP 정수값: $IP_INT"

# 증감
(( COUNT++ ))
(( COUNT += 5 ))
let "TOTAL = COUNT * 2"
```

---

## 3. 조건문


배시 스크립트의 시작 부분입니다. `set -euo pipefail`을 추가하면 오류 발생 시 즉시 종료하는 안전한 스크립트를 작성할 수 있습니다.

```bash
#!/usr/bin/env bash

TARGET="${1:-localhost}"

# 파일/디렉토리 검사
[[ -f /etc/passwd ]]    && echo "파일 존재"
[[ -d /tmp ]]           && echo "디렉토리 존재"
[[ -r /etc/shadow ]]    && echo "읽기 가능" || echo "읽기 불가"
[[ -s /var/log/auth.log ]] && echo "비어있지 않은 파일"
[[ -x /usr/bin/nmap ]]  || { echo "nmap 없음. 설치 필요"; exit 1; }

# 문자열 비교
OS=$(uname -s)
if [[ "$OS" == "Linux" ]]; then
    DISTRO=$(. /etc/os-release && echo "$ID")
elif [[ "$OS" == "Darwin" ]]; then
    DISTRO="macos"
else
    DISTRO="unknown"
fi

# 숫자 비교
KERNEL_VER=$(uname -r | cut -d. -f1)
if (( KERNEL_VER >= 5 )); then
    echo "커널 5.x 이상"
fi

# 정규식 매칭
IP_PATTERN='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
if [[ "$TARGET" =~ $IP_PATTERN ]]; then
    echo "유효한 IP 주소"
else
    echo "도메인 또는 잘못된 입력"
fi

# case 문
case "$DISTRO" in
    ubuntu|debian)  PKG_MGR="apt-get" ;;
    centos|rhel)    PKG_MGR="yum"     ;;
    arch)           PKG_MGR="pacman"  ;;
    *)              PKG_MGR="unknown" ;;
esac
```

---

## 4. 반복문

```bash
# for - 범위
for i in {1..254}; do
    ping -c1 -W1 "192.168.1.$i" &>/dev/null && echo "192.168.1.$i UP" &
done
wait  # 백그라운드 작업 대기

# for - 배열 순회
TARGETS=("192.168.1.1" "10.0.0.1" "172.16.0.1")
for t in "${TARGETS[@]}"; do
    echo "스캔 중: $t"
done

# for - C 스타일
for (( i=0; i<256; i+=16 )); do
    printf "서브넷: 10.0.%d.0/28\n" "$i"
done

# while - 파일 라인 읽기
while IFS= read -r line; do
    [[ -z "$line" || "$line" == \#* ]] && continue  # 빈줄/주석 스킵
    host "$line" 2>/dev/null | grep "has address" | awk '{print $NF}'
done < wordlist.txt

# while - 재시도 로직
MAX_RETRY=5; ATTEMPT=0
until curl -sf "http://$TARGET/health" &>/dev/null; do
    (( ATTEMPT++ ))
    (( ATTEMPT >= MAX_RETRY )) && { echo "연결 실패"; exit 1; }
    echo "재시도 $ATTEMPT/$MAX_RETRY ..."
    sleep $(( ATTEMPT * 2 ))  # 지수 백오프
done

# select - 메뉴
PS3="선택: "
select OPTION in "스캔" "분석" "보고서" "종료"; do
    case $REPLY in
        1) echo "스캔 시작" ;;
        2) echo "분석 시작" ;;
        3) echo "보고서 생성" ;;
        4) break ;;
        *) echo "잘못된 선택" ;;
    esac
done
```

---

## 5. 함수


배시 스크립트의 시작 부분입니다. `set -euo pipefail`을 추가하면 오류 발생 시 즉시 종료하는 안전한 스크립트를 작성할 수 있습니다.

```bash
#!/usr/bin/env bash

# 기본 함수 (반환값 = 종료 코드, 출력 = 명령치환으로 캡처)
check_port() {
    local host="${1:?'host 필요'}"
    local port="${2:?'port 필요'}"
    local timeout="${3:-1}"
    
    if timeout "$timeout" bash -c "echo >/dev/tcp/$host/$port" 2>/dev/null; then
        return 0  # 열림
    else
        return 1  # 닫힘
    fi
}

# 출력 반환 함수
get_ip() {
    local domain="$1"
    dig +short "$domain" A | head -1
}

# 에러 처리 포함 함수
require_root() {
    if (( EUID != 0 )); then
        echo "[!] root 권한 필요" >&2
        return 1
    fi
}

# 함수 내 지역 배열
port_scan() {
    local target="$1"
    shift
    local -a ports=("$@")
    local -a open_ports=()
    
    for port in "${ports[@]}"; do
        if check_port "$target" "$port"; then
            open_ports+=("$port")
        fi
    done
    
    printf '%s\n' "${open_ports[@]}"
}

# 사용 예
TARGET="scanme.nmap.org"
mapfile -t RESULTS < <(port_scan "$TARGET" 22 80 443 8080 8443)
echo "열린 포트: ${RESULTS[*]}"

# 재귀 함수 — 디렉토리 탐색
find_suid() {
    local dir="${1:-/}"
    local depth="${2:-0}"
    
    (( depth > 5 )) && return  # 깊이 제한
    
    while IFS= read -r -d '' entry; do
        if [[ -f "$entry" ]]; then
            stat -c "%A %U %n" "$entry" 2>/dev/null
        fi
    done < <(find "$dir" -maxdepth 1 -perm /4000 -print0 2>/dev/null)
}

# 트랩으로 정리 함수 등록
TMPDIR_CLEAN=$(mktemp -d)
cleanup() {
    rm -rf "$TMPDIR_CLEAN"
    echo "[*] 임시 파일 정리 완료"
}
trap cleanup EXIT INT TERM
```

---

## 6. 파일 입출력


배시 스크립트의 시작 부분입니다. `set -euo pipefail`을 추가하면 오류 발생 시 즉시 종료하는 안전한 스크립트를 작성할 수 있습니다.

```bash
#!/usr/bin/env bash

# 리다이렉션
command > out.txt        # stdout 덮어쓰기
command >> out.txt       # stdout 추가
command 2> err.txt       # stderr 덮어쓰기
command &> all.txt       # stdout+stderr 합쳐서
command 2>&1 | tee log.txt  # 화면+파일 동시 출력

# here-doc / here-string
cat > /tmp/payload.sh << 'EOF'
#!/bin/bash
id; whoami; hostname
uname -a
EOF

rev <<< "hello"  # olleh

# 파일 읽기 방법들
# 방법 1: while read (권장 — 큰 파일도 안전)
while IFS=',' read -r ip port svc; do
    printf "IP:%-16s PORT:%-6s SVC:%s\n" "$ip" "$port" "$svc"
done < targets.csv

# 방법 2: mapfile (전체를 배열에)
mapfile -t LINES < /etc/hosts
echo "총 ${#LINES[@]}줄"

# 방법 3: 프로세스 치환
while IFS= read -r line; do
    echo "$line"
done < <(curl -sf "http://target/wordlist.txt")

# fd를 이용한 고급 I/O
exec 3< /etc/passwd    # fd 3으로 파일 열기
exec 4> /tmp/output.txt  # fd 4로 출력 파일 열기

while IFS=: read -r -u3 user _ uid _ _ _ _; do
    (( uid >= 1000 )) && echo "$user (UID $uid)" >&4
done

exec 3<&-  # fd 닫기
exec 4>&-

# 임시 파일/디렉토리
TMPFILE=$(mktemp /tmp/scan.XXXXXXXX)
TMPDIR=$(mktemp -d /tmp/work.XXXXXXXX)
trap 'rm -rf "$TMPFILE" "$TMPDIR"' EXIT

# 파일 잠금 (동시 실행 방지)
LOCKFILE="/var/run/myscanner.lock"
exec 9>"$LOCKFILE"
flock -n 9 || { echo "이미 실행 중"; exit 1; }
```

---

## 7. 정규표현식 — grep / sed / awk

### grep

```bash
# 기본 grep
grep -E "^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" nmap_output.txt
grep -oP '(?<=open\s)\w+' nmap_output.txt   # PCRE lookahead
grep -v "^#\|^$" /etc/ssh/sshd_config       # 주석/빈줄 제거

# 여러 파일에서 패턴 검색
grep -rl "password\s*=" /etc/ 2>/dev/null    # 파일명만
grep -rn --include="*.conf" "PermitRootLogin yes" /etc/

# 이진 파일에서 문자열 추출
grep -a -oP '[\w.]+@[\w.]+\.\w+' binary_file  # 이메일 추출
strings binary | grep -E "https?://[^\s]+"    # URL 추출
```

### sed

```bash
# 치환
sed 's/password/[REDACTED]/gi' log.txt        # 대소문자 무시 전역 치환
sed -i.bak 's/^#Port 22/Port 2222/' /etc/ssh/sshd_config  # 인플레이스 (백업)

# 라인 조작
sed -n '10,20p' file.txt         # 10~20번 라인만 출력
sed '/^#/d; /^$/d' config.txt    # 주석/빈 줄 삭제
sed -n '/BEGIN CERT/,/END CERT/p' ssl.log   # 블록 추출

# 주소 조합
sed '1~2s/^/# /' file.txt        # 홀수 번째 줄에 # 추가
sed '$d' file.txt                 # 마지막 줄 삭제
sed '0,/TARGET/{s/TARGET/FOUND/}' file.txt   # 첫 번째만 치환

# 고급 — 멀티라인 처리
sed -n '/^Host /,/^$/{ /^Host \|^\s/p }' ~/.ssh/config

# IP 주소 추출 후 정렬
sed -n 's/.*Nmap scan report for \([0-9.]*\).*/\1/p' scan.txt | sort -V
```

### awk

```bash
# 필드 처리
awk -F: '$3 >= 1000 {print $1, $3, $7}' /etc/passwd  # UID>=1000 사용자

# 패턴 블록
awk '/open/{print $1, $3}' nmap_grep_output.txt

# 집계
awk '{sum[$1]++} END {for(ip in sum) print sum[ip], ip}' access.log | sort -rn | head -20

# 조건 + 계산
awk -F, '
NR>1 {
    if ($5 > 200) {
        warn_count++
        print "WARN:", $0
    }
}
END {
    print "총 경고:", warn_count
}' report.csv

# 로그 파싱 — Apache/Nginx 접근 로그
awk '
{
    ip     = $1
    method = $6
    url    = $7
    code   = $9
    size   = $10

    if (code ~ /^[45]/) {
        errors[ip]++
    }
}
END {
    print "에러 요청 상위 IP:"
    for (ip in errors) print errors[ip], ip
}' /var/log/nginx/access.log | sort -rn | head -10

# 멀티파일 처리
awk 'FNR==1{print "=== " FILENAME " ==="}1' /etc/passwd /etc/group
```

---

## 8. 프로세스 관리


배시 스크립트의 시작 부분입니다. `set -euo pipefail`을 추가하면 오류 발생 시 즉시 종료하는 안전한 스크립트를 작성할 수 있습니다.

```bash
#!/usr/bin/env bash

# 백그라운드 실행 & PID 관리
nmap -sV -p- "$TARGET" -oX /tmp/scan.xml &
NMAP_PID=$!
echo "nmap PID: $NMAP_PID"

# PID 파일 방식
start_daemon() {
    local pidfile="/var/run/$1.pid"
    [[ -f "$pidfile" ]] && kill -0 "$(cat "$pidfile")" 2>/dev/null && {
        echo "이미 실행 중 (PID $(cat "$pidfile"))"; return 1
    }
    "$@" &
    echo $! > "$pidfile"
}

# 병렬 작업 + 동시 실행 제한
MAX_JOBS=10
JOB_COUNT=0

for subnet in 192.168.{1..5}.0/24; do
    nmap -sn "$subnet" -oG - 2>/dev/null | awk '/Up/{print $2}' &
    (( ++JOB_COUNT >= MAX_JOBS )) && { wait; JOB_COUNT=0; }
done
wait

# timeout으로 프로세스 제한
timeout 30 nmap -sV "$TARGET" || echo "스캔 타임아웃"
timeout --kill-after=5 60 long_running_command

# 프로세스 신호 처리
CHILD_PIDS=()
spawn_worker() {
    sleep 100 &
    CHILD_PIDS+=($!)
}

sigterm_handler() {
    echo "종료 신호 수신, 자식 프로세스 정리..."
    for pid in "${CHILD_PIDS[@]}"; do
        kill -TERM "$pid" 2>/dev/null
    done
    wait
    exit 0
}
trap sigterm_handler SIGTERM SIGINT

# cgroups v2로 메모리/CPU 제한 (root)
cgcreate_scan() {
    local group="pentest_scan"
    cgcreate -g memory,cpu:/pentest_scan 2>/dev/null || true
    echo "512M" > /sys/fs/cgroup/memory/pentest_scan/memory.limit_in_bytes
    cgexec -g memory,cpu:/pentest_scan nmap "$@"
}

# /proc 에서 프로세스 정보 추출
list_network_procs() {
    for pid in /proc/[0-9]*/net/tcp; do
        [[ -r "$pid" ]] || continue
        local proc_pid
        proc_pid=$(echo "$pid" | grep -oP '/proc/\K[0-9]+')
        local comm
        comm=$(cat "/proc/$proc_pid/comm" 2>/dev/null)
        echo "PID $proc_pid ($comm):"
        awk 'NR>1 && $4=="0A" {
            split($3,a,":"); printf "  LISTEN :%d\n", strtonum("0x" a[2])
        }' "$pid" 2>/dev/null
    done
}
```

---

## 9. 실전 보안 유틸리티 스크립트

### 9-1. TCP 포트 스캐너


배시 스크립트의 시작 부분입니다. `set -euo pipefail`을 추가하면 오류 발생 시 즉시 종료하는 안전한 스크립트를 작성할 수 있습니다.

```bash
#!/usr/bin/env bash
# 순수 bash TCP 포트 스캐너 (nmap 없이)
# 사용법: ./port_scanner.sh <target> [start_port] [end_port] [threads]

set -euo pipefail

TARGET="${1:?'대상 IP/호스트 필요. 사용법: $0 <target> [start] [end] [threads]'}"
START_PORT="${2:-1}"
END_PORT="${3:-1024}"
MAX_THREADS="${4:-50}"
TIMEOUT=1

# 컬러 출력
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

info()  { echo -e "${YELLOW}[*]${NC} $*"; }
ok()    { echo -e "${GREEN}[+]${NC} $*"; }
err()   { echo -e "${RED}[-]${NC} $*" >&2; }

# 호스트 활성 여부 확인
is_host_up() {
    ping -c1 -W2 "$1" &>/dev/null || \
    timeout 2 bash -c "echo >/dev/tcp/$1/80" 2>/dev/null
}

# 단일 포트 스캔
scan_port() {
    local host="$1" port="$2"
    if timeout "$TIMEOUT" bash -c "echo >/dev/tcp/$host/$port" 2>/dev/null; then
        # 배너 그랩 시도
        local banner
        banner=$(timeout 2 bash -c "echo | nc -w2 $host $port 2>/dev/null | head -1 | tr -d '\r\n'")
        ok "포트 $port/tcp OPEN${banner:+  [$banner]}"
    fi
}

# 일반적인 포트 서비스명 매핑
port_service() {
    local -A SVC=(
        [21]="FTP" [22]="SSH" [23]="Telnet" [25]="SMTP"
        [53]="DNS" [80]="HTTP" [110]="POP3" [143]="IMAP"
        [443]="HTTPS" [445]="SMB" [3306]="MySQL"
        [3389]="RDP" [5432]="PostgreSQL" [6379]="Redis"
        [8080]="HTTP-Alt" [8443]="HTTPS-Alt" [27017]="MongoDB"
    )
    echo "${SVC[$1]:-unknown}"
}

main() {
    info "대상: $TARGET  포트 범위: $START_PORT-$END_PORT  스레드: $MAX_THREADS"
    
    if ! is_host_up "$TARGET"; then
        err "호스트 응답 없음 (계속 진행)"
    fi
    
    local START_TIME
    START_TIME=$(date +%s)
    local ACTIVE=0
    
    for (( port=START_PORT; port<=END_PORT; port++ )); do
        scan_port "$TARGET" "$port" &
        (( ++ACTIVE >= MAX_THREADS )) && { wait; ACTIVE=0; }
    done
    wait
    
    local ELAPSED=$(( $(date +%s) - START_TIME ))
    info "스캔 완료: ${ELAPSED}초 소요"
}

main
```

### 9-2. 로그 분석기


배시 스크립트의 시작 부분입니다. `set -euo pipefail`을 추가하면 오류 발생 시 즉시 종료하는 안전한 스크립트를 작성할 수 있습니다.

```bash
#!/usr/bin/env bash
# 웹 서버 로그 보안 분석기
# 사용법: ./log_analyzer.sh [log_file] [--top N] [--threshold N]

set -euo pipefail

LOG_FILE="${1:-/var/log/nginx/access.log}"
TOP_N="${TOP:-20}"
THRESHOLD="${THRESHOLD:-100}"

# 컬러
RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'
YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'

header() { echo -e "\n${BOLD}${CYAN}=== $* ===${NC}"; }
warn()   { echo -e "${YELLOW}[!]${NC} $*"; }
alert()  { echo -e "${RED}[ALERT]${NC} $*"; }

[[ -f "$LOG_FILE" ]] || { echo "로그 파일 없음: $LOG_FILE" >&2; exit 1; }

TOTAL=$(wc -l < "$LOG_FILE")
echo -e "${BOLD}로그 파일:${NC} $LOG_FILE  (${TOTAL}줄)"
echo -e "${BOLD}기간:${NC} $(awk 'NR==1{print $4}' "$LOG_FILE" | tr -d '[') ~ $(tail -1 "$LOG_FILE" | awk '{print $4}' | tr -d '[')"

# 1. 요청 많은 IP
header "상위 $TOP_N 요청 IP (임계값: $THRESHOLD)"
awk '{print $1}' "$LOG_FILE" | sort | uniq -c | sort -rn | head -"$TOP_N" | \
while read -r count ip; do
    (( count >= THRESHOLD )) && PREFIX="${RED}[!]${NC} " || PREFIX="    "
    printf "${PREFIX}%6d  %s\n" "$count" "$ip"
done

# 2. HTTP 에러 코드 분포
header "HTTP 상태 코드 분포"
awk '{print $9}' "$LOG_FILE" | grep -E '^[0-9]{3}$' | \
    sort | uniq -c | sort -rn | \
while read -r count code; do
    case "${code:0:1}" in
        2) color=$GREEN ;;
        3) color=$CYAN ;;
        4) color=$YELLOW ;;
        5) color=$RED ;;
        *) color=$NC ;;
    esac
    printf "${color}  %6d  HTTP %s${NC}\n" "$count" "$code"
done

# 3. SQL Injection 패턴 탐지
header "SQL Injection 의심 요청"
grep -iE "(union.+select|select.+from|drop.+table|insert.+into|'\s*or\s*'1'='1|--\s*$|xp_cmdshell)" \
    "$LOG_FILE" 2>/dev/null | \
    awk '{print $1, $7}' | sort | uniq -c | sort -rn | head -20 | \
while read -r count ip url; do
    alert "횟수:$count  IP:$ip  URL:$url"
done || echo "  탐지 없음"

# 4. XSS 패턴 탐지
header "XSS 의심 요청"
grep -iE "(<script|javascript:|onerror=|onload=|alert\(|document\.cookie)" \
    "$LOG_FILE" 2>/dev/null | \
    awk '{print $1, $7}' | head -20 | \
while read -r ip url; do
    alert "IP:$ip  URL:$url"
done || echo "  탐지 없음"

# 5. 디렉토리 트래버설
header "디렉토리 트래버설 의심"
grep -E "\.\./|%2e%2e%2f|%252e%252e" "$LOG_FILE" 2>/dev/null | \
    awk '{print $1, $7}' | head -20 | \
while read -r ip url; do
    alert "IP:$ip  URL:$url"
done || echo "  탐지 없음"

# 6. 스캐너/봇 User-Agent
header "자동화 스캐너 탐지"
grep -iE "(nikto|sqlmap|nmap|masscan|zgrab|hydra|medusa|metasploit|dirbuster|gobuster|nuclei)" \
    "$LOG_FILE" 2>/dev/null | \
    awk '{print $1}' | sort | uniq -c | sort -rn | head -10 | \
while read -r count ip; do
    alert "횟수:$count  IP:$ip (스캐너 탐지)"
done || echo "  탐지 없음"

# 7. 시간대별 요청 분포
header "시간대별 요청 분포 (최근 24시간)"
awk '{
    match($4, /[0-9]{2}:[0-9]{2}/)
    hour = substr(RSTART==0?"00:00":$4, RSTART, 2)
    hourly[hour]++
}
END {
    for (h in hourly) printf "%s %d\n", h, hourly[h]
}' "$LOG_FILE" | sort | \
while read -r hour count; do
    bar=$(printf '%0.s#' $(seq 1 $(( count / 10 + 1 ))))
    printf "  %s: %-50s %d\n" "$hour" "$bar" "$count"
done

# 8. 보고서 저장
REPORT="/tmp/log_analysis_$(date +%Y%m%d_%H%M%S).txt"
{
    echo "Log Analysis Report — $(date)"
    echo "File: $LOG_FILE | Total Lines: $TOTAL"
    echo "---"
    awk '{ip[$1]++; code[$9]++}
    END {
        print "Top IPs:"; for(i in ip) print ip[i], i
        print "\nStatus Codes:"; for(c in code) print code[c], c
    }' "$LOG_FILE"
} > "$REPORT"
echo -e "\n${GREEN}[+]${NC} 보고서 저장: $REPORT"
```

---

## 10. 유용한 Bash 패턴 모음

```bash
# 진행률 표시
show_progress() {
    local current="$1" total="$2" width=50
    local pct=$(( current * 100 / total ))
    local filled=$(( current * width / total ))
    local bar
    bar=$(printf '%0.s#' $(seq 1 "$filled"))
    printf "\r[%-${width}s] %3d%% (%d/%d)" "$bar" "$pct" "$current" "$total"
    (( current == total )) && echo
}

# 재시도 래퍼
retry() {
    local max="${1}"; shift
    local delay="${1}"; shift
    local attempt=0
    until "$@"; do
        (( ++attempt >= max )) && { echo "실패: $*" >&2; return 1; }
        echo "재시도 $attempt/$max (${delay}s 대기)..."
        sleep "$delay"
    done
}
retry 3 5 curl -sf "http://target/api"

# 로깅 함수
LOG_FILE="/tmp/script_$(date +%Y%m%d).log"
log() {
    local level="$1"; shift
    printf '[%s] [%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$level" "$*" | tee -a "$LOG_FILE"
}
log INFO  "스크립트 시작"
log WARN  "경고 발생"
log ERROR "오류 발생"

# 의존성 체크
require_tools() {
    local missing=()
    for tool in "$@"; do
        command -v "$tool" &>/dev/null || missing+=("$tool")
    done
    if (( ${#missing[@]} > 0 )); then
        echo "필수 도구 없음: ${missing[*]}" >&2
        return 1
    fi
}
require_tools nmap curl jq python3 || exit 1
```

---

<a name="english"></a>

# 01 Bash Scripting Basics

---

## 1. Variables and Arrays

### Basic Variables

This is the beginning of a bash script. Adding `set -euo pipefail` allows you to write safe scripts that exit immediately on error.

```bash
#!/usr/bin/env bash
set -euo pipefail   # Exit immediately on error, error on undefined variables, propagate pipe errors
IFS=$'\n\t'         # Safe field separator

# Variable declaration and types
TARGET="192.168.1.0/24"
PORT=443
readonly LOG_DIR="/var/log/scan"   # Read-only
declare -i COUNT=0                  # Integer type
declare -l LOWER="HELLO"           # Auto lowercase → hello
declare -u UPPER="world"           # Auto uppercase → WORLD

# String manipulation
PATH_STR="/home/user/file.txt"
echo "${PATH_STR##*/}"     # Filename only: file.txt
echo "${PATH_STR%/*}"      # Directory only: /home/user
echo "${PATH_STR%.txt}"    # Remove extension: /home/user/file
echo "${PATH_STR/user/root}"  # Substitution: /home/root/file.txt

# Default value handling
NAME="${1:-anonymous}"          # Use 'anonymous' if no argument
CONFIG="${CONFIG_FILE:=/etc/app.conf}"  # Set default if not set
: "${REQUIRED_VAR:?'REQUIRED_VAR must be set'}"  # Error if not set
```

### Arrays

```bash
# Indexed arrays
PORTS=(22 80 443 8080 8443)
PORTS+=(3306 5432)               # Append
echo "${PORTS[0]}"               # First element: 22
echo "${PORTS[@]}"               # All elements
echo "${#PORTS[@]}"              # Number of elements: 7
echo "${PORTS[@]:2:3}"           # Slice (3 elements starting at index 2)
unset 'PORTS[1]'                 # Delete specific element

# Associative arrays (dictionaries)
declare -A SERVICES
SERVICES[ssh]=22
SERVICES[http]=80
SERVICES[https]=443

for svc in "${!SERVICES[@]}"; do
    printf "%-10s → %d\n" "$svc" "${SERVICES[$svc]}"
done

# Read command output into an array
mapfile -t OPEN_PORTS < <(ss -tlnp | awk 'NR>1 {print $4}' | grep -oP ':\K\d+' | sort -un)
echo "Open ports: ${OPEN_PORTS[*]}"
```

---

## 2. Arithmetic Operations

```bash
# Integer arithmetic
A=10; B=3
echo $(( A + B ))    # 13
echo $(( A % B ))    # 1
echo $(( A ** B ))   # 1000  (exponentiation)
echo $(( A / B ))    # 3 (integer division)

# Floating-point — use bc
PI=$(echo "scale=5; 4*a(1)" | bc -l)
RATIO=$(echo "scale=2; $A / $B" | printf "%.2f" $(bc -l))

# Bitwise operations (useful for port/IP calculations)
IP_INT=$(( (192 << 24) | (168 << 16) | (1 << 8) | 100 ))
echo "IP integer value: $IP_INT"

# Increment/decrement
(( COUNT++ ))
(( COUNT += 5 ))
let "TOTAL = COUNT * 2"
```

---

## 3. Conditionals

This is the beginning of a bash script. Adding `set -euo pipefail` allows you to write safe scripts that exit immediately on error.

```bash
#!/usr/bin/env bash

TARGET="${1:-localhost}"

# File/directory checks
[[ -f /etc/passwd ]]    && echo "File exists"
[[ -d /tmp ]]           && echo "Directory exists"
[[ -r /etc/shadow ]]    && echo "Readable" || echo "Not readable"
[[ -s /var/log/auth.log ]] && echo "Non-empty file"
[[ -x /usr/bin/nmap ]]  || { echo "nmap not found. Install required"; exit 1; }

# String comparison
OS=$(uname -s)
if [[ "$OS" == "Linux" ]]; then
    DISTRO=$(. /etc/os-release && echo "$ID")
elif [[ "$OS" == "Darwin" ]]; then
    DISTRO="macos"
else
    DISTRO="unknown"
fi

# Numeric comparison
KERNEL_VER=$(uname -r | cut -d. -f1)
if (( KERNEL_VER >= 5 )); then
    echo "Kernel 5.x or later"
fi

# Regex matching
IP_PATTERN='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
if [[ "$TARGET" =~ $IP_PATTERN ]]; then
    echo "Valid IP address"
else
    echo "Domain or invalid input"
fi

# case statement
case "$DISTRO" in
    ubuntu|debian)  PKG_MGR="apt-get" ;;
    centos|rhel)    PKG_MGR="yum"     ;;
    arch)           PKG_MGR="pacman"  ;;
    *)              PKG_MGR="unknown" ;;
esac
```

---

## 4. Loops

```bash
# for - range
for i in {1..254}; do
    ping -c1 -W1 "192.168.1.$i" &>/dev/null && echo "192.168.1.$i UP" &
done
wait  # Wait for background jobs

# for - array iteration
TARGETS=("192.168.1.1" "10.0.0.1" "172.16.0.1")
for t in "${TARGETS[@]}"; do
    echo "Scanning: $t"
done

# for - C-style
for (( i=0; i<256; i+=16 )); do
    printf "Subnet: 10.0.%d.0/28\n" "$i"
done

# while - reading file lines
while IFS= read -r line; do
    [[ -z "$line" || "$line" == \#* ]] && continue  # Skip empty lines/comments
    host "$line" 2>/dev/null | grep "has address" | awk '{print $NF}'
done < wordlist.txt

# while - retry logic
MAX_RETRY=5; ATTEMPT=0
until curl -sf "http://$TARGET/health" &>/dev/null; do
    (( ATTEMPT++ ))
    (( ATTEMPT >= MAX_RETRY )) && { echo "Connection failed"; exit 1; }
    echo "Retry $ATTEMPT/$MAX_RETRY ..."
    sleep $(( ATTEMPT * 2 ))  # Exponential backoff
done

# select - menu
PS3="Select: "
select OPTION in "Scan" "Analyze" "Report" "Exit"; do
    case $REPLY in
        1) echo "Starting scan" ;;
        2) echo "Starting analysis" ;;
        3) echo "Generating report" ;;
        4) break ;;
        *) echo "Invalid selection" ;;
    esac
done
```

---

## 5. Functions

This is the beginning of a bash script. Adding `set -euo pipefail` allows you to write safe scripts that exit immediately on error.

```bash
#!/usr/bin/env bash

# Basic function (return value = exit code, output = captured via command substitution)
check_port() {
    local host="${1:?'host required'}"
    local port="${2:?'port required'}"
    local timeout="${3:-1}"
    
    if timeout "$timeout" bash -c "echo >/dev/tcp/$host/$port" 2>/dev/null; then
        return 0  # Open
    else
        return 1  # Closed
    fi
}

# Function returning output
get_ip() {
    local domain="$1"
    dig +short "$domain" A | head -1
}

# Function with error handling
require_root() {
    if (( EUID != 0 )); then
        echo "[!] root privileges required" >&2
        return 1
    fi
}

# Local arrays inside functions
port_scan() {
    local target="$1"
    shift
    local -a ports=("$@")
    local -a open_ports=()
    
    for port in "${ports[@]}"; do
        if check_port "$target" "$port"; then
            open_ports+=("$port")
        fi
    done
    
    printf '%s\n' "${open_ports[@]}"
}

# Usage example
TARGET="scanme.nmap.org"
mapfile -t RESULTS < <(port_scan "$TARGET" 22 80 443 8080 8443)
echo "Open ports: ${RESULTS[*]}"

# Recursive function — directory traversal
find_suid() {
    local dir="${1:-/}"
    local depth="${2:-0}"
    
    (( depth > 5 )) && return  # Depth limit
    
    while IFS= read -r -d '' entry; do
        if [[ -f "$entry" ]]; then
            stat -c "%A %U %n" "$entry" 2>/dev/null
        fi
    done < <(find "$dir" -maxdepth 1 -perm /4000 -print0 2>/dev/null)
}

# Register cleanup function with trap
TMPDIR_CLEAN=$(mktemp -d)
cleanup() {
    rm -rf "$TMPDIR_CLEAN"
    echo "[*] Temporary files cleaned up"
}
trap cleanup EXIT INT TERM
```

---

## 6. File I/O

This is the beginning of a bash script. Adding `set -euo pipefail` allows you to write safe scripts that exit immediately on error.

```bash
#!/usr/bin/env bash

# Redirection
command > out.txt        # Overwrite stdout
command >> out.txt       # Append to stdout
command 2> err.txt       # Overwrite stderr
command &> all.txt       # Combine stdout+stderr
command 2>&1 | tee log.txt  # Output to screen and file simultaneously

# here-doc / here-string
cat > /tmp/payload.sh << 'EOF'
#!/bin/bash
id; whoami; hostname
uname -a
EOF

rev <<< "hello"  # olleh

# Methods for reading files
# Method 1: while read (recommended — safe for large files)
while IFS=',' read -r ip port svc; do
    printf "IP:%-16s PORT:%-6s SVC:%s\n" "$ip" "$port" "$svc"
done < targets.csv

# Method 2: mapfile (load all into array)
mapfile -t LINES < /etc/hosts
echo "Total ${#LINES[@]} lines"

# Method 3: process substitution
while IFS= read -r line; do
    echo "$line"
done < <(curl -sf "http://target/wordlist.txt")

# Advanced I/O with file descriptors
exec 3< /etc/passwd    # Open file on fd 3
exec 4> /tmp/output.txt  # Open output file on fd 4

while IFS=: read -r -u3 user _ uid _ _ _ _; do
    (( uid >= 1000 )) && echo "$user (UID $uid)" >&4
done

exec 3<&-  # Close fd
exec 4>&-

# Temporary files/directories
TMPFILE=$(mktemp /tmp/scan.XXXXXXXX)
TMPDIR=$(mktemp -d /tmp/work.XXXXXXXX)
trap 'rm -rf "$TMPFILE" "$TMPDIR"' EXIT

# File locking (prevent concurrent execution)
LOCKFILE="/var/run/myscanner.lock"
exec 9>"$LOCKFILE"
flock -n 9 || { echo "Already running"; exit 1; }
```

---

## 7. Regular Expressions — grep / sed / awk

### grep

```bash
# Basic grep
grep -E "^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" nmap_output.txt
grep -oP '(?<=open\s)\w+' nmap_output.txt   # PCRE lookahead
grep -v "^#\|^$" /etc/ssh/sshd_config       # Remove comments/blank lines

# Pattern search across multiple files
grep -rl "password\s*=" /etc/ 2>/dev/null    # Filenames only
grep -rn --include="*.conf" "PermitRootLogin yes" /etc/

# Extract strings from binary files
grep -a -oP '[\w.]+@[\w.]+\.\w+' binary_file  # Extract emails
strings binary | grep -E "https?://[^\s]+"    # Extract URLs
```

### sed

```bash
# Substitution
sed 's/password/[REDACTED]/gi' log.txt        # Case-insensitive global substitution
sed -i.bak 's/^#Port 22/Port 2222/' /etc/ssh/sshd_config  # In-place (with backup)

# Line manipulation
sed -n '10,20p' file.txt         # Print only lines 10-20
sed '/^#/d; /^$/d' config.txt    # Delete comments/blank lines
sed -n '/BEGIN CERT/,/END CERT/p' ssl.log   # Extract block

# Address combinations
sed '1~2s/^/# /' file.txt        # Add # to odd-numbered lines
sed '$d' file.txt                 # Delete last line
sed '0,/TARGET/{s/TARGET/FOUND/}' file.txt   # Replace only first occurrence

# Advanced — multiline processing
sed -n '/^Host /,/^$/{ /^Host \|^\s/p }' ~/.ssh/config

# Extract and sort IP addresses
sed -n 's/.*Nmap scan report for \([0-9.]*\).*/\1/p' scan.txt | sort -V
```

### awk

```bash
# Field processing
awk -F: '$3 >= 1000 {print $1, $3, $7}' /etc/passwd  # Users with UID>=1000

# Pattern blocks
awk '/open/{print $1, $3}' nmap_grep_output.txt

# Aggregation
awk '{sum[$1]++} END {for(ip in sum) print sum[ip], ip}' access.log | sort -rn | head -20

# Conditionals + calculations
awk -F, '
NR>1 {
    if ($5 > 200) {
        warn_count++
        print "WARN:", $0
    }
}
END {
    print "Total warnings:", warn_count
}' report.csv

# Log parsing — Apache/Nginx access log
awk '
{
    ip     = $1
    method = $6
    url    = $7
    code   = $9
    size   = $10

    if (code ~ /^[45]/) {
        errors[ip]++
    }
}
END {
    print "Top IPs with errors:"
    for (ip in errors) print errors[ip], ip
}' /var/log/nginx/access.log | sort -rn | head -10

# Multi-file processing
awk 'FNR==1{print "=== " FILENAME " ==="}1' /etc/passwd /etc/group
```

---

## 8. Process Management

This is the beginning of a bash script. Adding `set -euo pipefail` allows you to write safe scripts that exit immediately on error.

```bash
#!/usr/bin/env bash

# Background execution & PID management
nmap -sV -p- "$TARGET" -oX /tmp/scan.xml &
NMAP_PID=$!
echo "nmap PID: $NMAP_PID"

# PID file approach
start_daemon() {
    local pidfile="/var/run/$1.pid"
    [[ -f "$pidfile" ]] && kill -0 "$(cat "$pidfile")" 2>/dev/null && {
        echo "Already running (PID $(cat "$pidfile"))"; return 1
    }
    "$@" &
    echo $! > "$pidfile"
}

# Parallel jobs + concurrency limit
MAX_JOBS=10
JOB_COUNT=0

for subnet in 192.168.{1..5}.0/24; do
    nmap -sn "$subnet" -oG - 2>/dev/null | awk '/Up/{print $2}' &
    (( ++JOB_COUNT >= MAX_JOBS )) && { wait; JOB_COUNT=0; }
done
wait

# Limit processes with timeout
timeout 30 nmap -sV "$TARGET" || echo "Scan timed out"
timeout --kill-after=5 60 long_running_command

# Process signal handling
CHILD_PIDS=()
spawn_worker() {
    sleep 100 &
    CHILD_PIDS+=($!)
}

sigterm_handler() {
    echo "Termination signal received, cleaning up child processes..."
    for pid in "${CHILD_PIDS[@]}"; do
        kill -TERM "$pid" 2>/dev/null
    done
    wait
    exit 0
}
trap sigterm_handler SIGTERM SIGINT

# Memory/CPU limits with cgroups v2 (root)
cgcreate_scan() {
    local group="pentest_scan"
    cgcreate -g memory,cpu:/pentest_scan 2>/dev/null || true
    echo "512M" > /sys/fs/cgroup/memory/pentest_scan/memory.limit_in_bytes
    cgexec -g memory,cpu:/pentest_scan nmap "$@"
}

# Extract process information from /proc
list_network_procs() {
    for pid in /proc/[0-9]*/net/tcp; do
        [[ -r "$pid" ]] || continue
        local proc_pid
        proc_pid=$(echo "$pid" | grep -oP '/proc/\K[0-9]+')
        local comm
        comm=$(cat "/proc/$proc_pid/comm" 2>/dev/null)
        echo "PID $proc_pid ($comm):"
        awk 'NR>1 && $4=="0A" {
            split($3,a,":"); printf "  LISTEN :%d\n", strtonum("0x" a[2])
        }' "$pid" 2>/dev/null
    done
}
```

---

## 9. Practical Security Utility Scripts

### 9-1. TCP Port Scanner

This is the beginning of a bash script. Adding `set -euo pipefail` allows you to write safe scripts that exit immediately on error.

```bash
#!/usr/bin/env bash
# Pure bash TCP port scanner (without nmap)
# Usage: ./port_scanner.sh <target> [start_port] [end_port] [threads]

set -euo pipefail

TARGET="${1:?'Target IP/host required. Usage: $0 <target> [start] [end] [threads]'}"
START_PORT="${2:-1}"
END_PORT="${3:-1024}"
MAX_THREADS="${4:-50}"
TIMEOUT=1

# Color output
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

info()  { echo -e "${YELLOW}[*]${NC} $*"; }
ok()    { echo -e "${GREEN}[+]${NC} $*"; }
err()   { echo -e "${RED}[-]${NC} $*" >&2; }

# Check if host is up
is_host_up() {
    ping -c1 -W2 "$1" &>/dev/null || \
    timeout 2 bash -c "echo >/dev/tcp/$1/80" 2>/dev/null
}

# Scan a single port
scan_port() {
    local host="$1" port="$2"
    if timeout "$TIMEOUT" bash -c "echo >/dev/tcp/$host/$port" 2>/dev/null; then
        # Attempt banner grab
        local banner
        banner=$(timeout 2 bash -c "echo | nc -w2 $host $port 2>/dev/null | head -1 | tr -d '\r\n'")
        ok "Port $port/tcp OPEN${banner:+  [$banner]}"
    fi
}

# Common port-to-service name mapping
port_service() {
    local -A SVC=(
        [21]="FTP" [22]="SSH" [23]="Telnet" [25]="SMTP"
        [53]="DNS" [80]="HTTP" [110]="POP3" [143]="IMAP"
        [443]="HTTPS" [445]="SMB" [3306]="MySQL"
        [3389]="RDP" [5432]="PostgreSQL" [6379]="Redis"
        [8080]="HTTP-Alt" [8443]="HTTPS-Alt" [27017]="MongoDB"
    )
    echo "${SVC[$1]:-unknown}"
}

main() {
    info "Target: $TARGET  Port range: $START_PORT-$END_PORT  Threads: $MAX_THREADS"
    
    if ! is_host_up "$TARGET"; then
        err "Host not responding (continuing anyway)"
    fi
    
    local START_TIME
    START_TIME=$(date +%s)
    local ACTIVE=0
    
    for (( port=START_PORT; port<=END_PORT; port++ )); do
        scan_port "$TARGET" "$port" &
        (( ++ACTIVE >= MAX_THREADS )) && { wait; ACTIVE=0; }
    done
    wait
    
    local ELAPSED=$(( $(date +%s) - START_TIME ))
    info "Scan complete: ${ELAPSED} seconds elapsed"
}

main
```

### 9-2. Log Analyzer

This is the beginning of a bash script. Adding `set -euo pipefail` allows you to write safe scripts that exit immediately on error.

```bash
#!/usr/bin/env bash
# Web server log security analyzer
# Usage: ./log_analyzer.sh [log_file] [--top N] [--threshold N]

set -euo pipefail

LOG_FILE="${1:-/var/log/nginx/access.log}"
TOP_N="${TOP:-20}"
THRESHOLD="${THRESHOLD:-100}"

# Colors
RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'
YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'

header() { echo -e "\n${BOLD}${CYAN}=== $* ===${NC}"; }
warn()   { echo -e "${YELLOW}[!]${NC} $*"; }
alert()  { echo -e "${RED}[ALERT]${NC} $*"; }

[[ -f "$LOG_FILE" ]] || { echo "Log file not found: $LOG_FILE" >&2; exit 1; }

TOTAL=$(wc -l < "$LOG_FILE")
echo -e "${BOLD}Log file:${NC} $LOG_FILE  (${TOTAL} lines)"
echo -e "${BOLD}Period:${NC} $(awk 'NR==1{print $4}' "$LOG_FILE" | tr -d '[') ~ $(tail -1 "$LOG_FILE" | awk '{print $4}' | tr -d '[')"

# 1. Top requesting IPs
header "Top $TOP_N requesting IPs (threshold: $THRESHOLD)"
awk '{print $1}' "$LOG_FILE" | sort | uniq -c | sort -rn | head -"$TOP_N" | \
while read -r count ip; do
    (( count >= THRESHOLD )) && PREFIX="${RED}[!]${NC} " || PREFIX="    "
    printf "${PREFIX}%6d  %s\n" "$count" "$ip"
done

# 2. HTTP error code distribution
header "HTTP status code distribution"
awk '{print $9}' "$LOG_FILE" | grep -E '^[0-9]{3}$' | \
    sort | uniq -c | sort -rn | \
while read -r count code; do
    case "${code:0:1}" in
        2) color=$GREEN ;;
        3) color=$CYAN ;;
        4) color=$YELLOW ;;
        5) color=$RED ;;
        *) color=$NC ;;
    esac
    printf "${color}  %6d  HTTP %s${NC}\n" "$count" "$code"
done

# 3. SQL Injection pattern detection
header "Suspected SQL Injection requests"
grep -iE "(union.+select|select.+from|drop.+table|insert.+into|'\s*or\s*'1'='1|--\s*$|xp_cmdshell)" \
    "$LOG_FILE" 2>/dev/null | \
    awk '{print $1, $7}' | sort | uniq -c | sort -rn | head -20 | \
while read -r count ip url; do
    alert "Count:$count  IP:$ip  URL:$url"
done || echo "  None detected"

# 4. XSS pattern detection
header "Suspected XSS requests"
grep -iE "(<script|javascript:|onerror=|onload=|alert\(|document\.cookie)" \
    "$LOG_FILE" 2>/dev/null | \
    awk '{print $1, $7}' | head -20 | \
while read -r ip url; do
    alert "IP:$ip  URL:$url"
done || echo "  None detected"

# 5. Directory traversal
header "Suspected directory traversal"
grep -E "\.\./|%2e%2e%2f|%252e%252e" "$LOG_FILE" 2>/dev/null | \
    awk '{print $1, $7}' | head -20 | \
while read -r ip url; do
    alert "IP:$ip  URL:$url"
done || echo "  None detected"

# 6. Scanner/bot User-Agents
header "Automated scanner detection"
grep -iE "(nikto|sqlmap|nmap|masscan|zgrab|hydra|medusa|metasploit|dirbuster|gobuster|nuclei)" \
    "$LOG_FILE" 2>/dev/null | \
    awk '{print $1}' | sort | uniq -c | sort -rn | head -10 | \
while read -r count ip; do
    alert "Count:$count  IP:$ip (scanner detected)"
done || echo "  None detected"

# 7. Hourly request distribution
header "Hourly request distribution (last 24 hours)"
awk '{
    match($4, /[0-9]{2}:[0-9]{2}/)
    hour = substr(RSTART==0?"00:00":$4, RSTART, 2)
    hourly[hour]++
}
END {
    for (h in hourly) printf "%s %d\n", h, hourly[h]
}' "$LOG_FILE" | sort | \
while read -r hour count; do
    bar=$(printf '%0.s#' $(seq 1 $(( count / 10 + 1 ))))
    printf "  %s: %-50s %d\n" "$hour" "$bar" "$count"
done

# 8. Save report
REPORT="/tmp/log_analysis_$(date +%Y%m%d_%H%M%S).txt"
{
    echo "Log Analysis Report — $(date)"
    echo "File: $LOG_FILE | Total Lines: $TOTAL"
    echo "---"
    awk '{ip[$1]++; code[$9]++}
    END {
        print "Top IPs:"; for(i in ip) print ip[i], i
        print "\nStatus Codes:"; for(c in code) print code[c], c
    }' "$LOG_FILE"
} > "$REPORT"
echo -e "\n${GREEN}[+]${NC} Report saved: $REPORT"
```

---

## 10. Useful Bash Patterns

```bash
# Progress bar
show_progress() {
    local current="$1" total="$2" width=50
    local pct=$(( current * 100 / total ))
    local filled=$(( current * width / total ))
    local bar
    bar=$(printf '%0.s#' $(seq 1 "$filled"))
    printf "\r[%-${width}s] %3d%% (%d/%d)" "$bar" "$pct" "$current" "$total"
    (( current == total )) && echo
}

# Retry wrapper
retry() {
    local max="${1}"; shift
    local delay="${1}"; shift
    local attempt=0
    until "$@"; do
        (( ++attempt >= max )) && { echo "Failed: $*" >&2; return 1; }
        echo "Retry $attempt/$max (waiting ${delay}s)..."
        sleep "$delay"
    done
}
retry 3 5 curl -sf "http://target/api"

# Logging function
LOG_FILE="/tmp/script_$(date +%Y%m%d).log"
log() {
    local level="$1"; shift
    printf '[%s] [%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$level" "$*" | tee -a "$LOG_FILE"
}
log INFO  "Script started"
log WARN  "Warning occurred"
log ERROR "Error occurred"

# Dependency check
require_tools() {
    local missing=()
    for tool in "$@"; do
        command -v "$tool" &>/dev/null || missing+=("$tool")
    done
    if (( ${#missing[@]} > 0 )); then
        echo "Required tools missing: ${missing[*]}" >&2
        return 1
    fi
}
require_tools nmap curl jq python3 || exit 1
```
