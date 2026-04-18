# Linux 필수 명령어 완전 정리

## 1. 파일 및 디렉토리 조작

### 기본 탐색
```bash
pwd                    # 현재 디렉토리 확인
ls -al                 # 숨김 파일 포함 상세 목록
ls -alh                # 사람이 읽기 쉬운 파일 크기
cd /var/log            # 절대 경로로 이동
cd ..                  # 상위 디렉토리
cd ~                   # 홈 디렉토리
find / -name "*.conf"  # 전체 시스템에서 파일 검색
find / -perm -4000     # SetUID 파일 검색 (보안 감사에 매우 중요)
locate passwd          # 데이터베이스 기반 빠른 파일 검색
```

### 파일 조작
```bash
cp -r src/ dst/        # 디렉토리 재귀 복사
mv oldname newname     # 파일 이동/이름 변경
rm -rf dirName         # 디렉토리 강제 삭제 (주의!)
mkdir -p a/b/c         # 중첩 디렉토리 일괄 생성
touch filename         # 빈 파일 생성 또는 타임스탬프 갱신
ln -s /etc/passwd sym  # 심볼릭 링크 생성
```

### 파일 내용 확인
```bash
cat /etc/passwd        # 파일 전체 출력
head -20 /etc/log      # 앞 20줄 출력
tail -f /var/log/syslog  # 실시간 로그 모니터링 (F 옵션 중요)
less /etc/passwd       # 페이지 단위 보기
grep "root" /etc/passwd  # 특정 문자열 검색
grep -r "password" /etc/  # 디렉토리 재귀 검색
grep -i "error" /var/log/syslog  # 대소문자 무시
awk -F: '{print $1}' /etc/passwd  # 필드 구분자로 파싱
```

---

## 2. 사용자 및 권한 관리

### 사용자 계정 관리
```bash
useradd username       # 사용자 추가
useradd -m -s /bin/bash username  # 홈 디렉토리와 쉘 지정
passwd username        # 비밀번호 설정
userdel -r username    # 사용자 삭제 (홈 디렉토리 포함)
usermod -aG sudo username  # sudo 그룹에 추가
id username            # UID, GID, 그룹 정보 확인
who                    # 현재 로그인 사용자
w                      # 로그인 사용자 및 작업 상태
last                   # 로그인 이력
lastlog                # 마지막 로그인 시간
```

### 파일 권한
```bash
chmod 755 file         # rwxr-xr-x
chmod 644 file         # rw-r--r--
chmod +x script.sh     # 실행 권한 추가
chown root:root file   # 소유자/그룹 변경
chown -R www-data /var/www  # 재귀적 소유자 변경
```

#### 권한 숫자 계산
```
r(읽기)  = 4
w(쓰기)  = 2
x(실행)  = 1

755 = rwx(7) r-x(5) r-x(5)  → 소유자: 전체, 그룹/기타: 읽기+실행
644 = rw-(6) r--(4) r--(4)  → 소유자: 읽기+쓰기, 나머지: 읽기만
```

### SetUID / SetGID (보안 핵심)
```bash
# SetUID: 파일 실행 시 소유자 권한으로 실행
chmod 4755 file        # SetUID 설정
chmod u+s file         # 동일

# SetGID: 파일 실행 시 그룹 권한으로 실행
chmod 2755 file        # SetGID 설정

# 시스템 내 SetUID 파일 전수조사 (해킹 시 필수)
find / -perm -4000 -type f 2>/dev/null
find / -perm -2000 -type f 2>/dev/null

# 대표적인 SetUID 파일들
ls -la /usr/bin/passwd   # passwd는 root 권한으로 shadow 수정
ls -la /bin/su
ls -la /usr/bin/sudo
```

---

## 3. 프로세스 관리

```bash
ps aux                 # 전체 프로세스 목록
ps -ef | grep apache   # 특정 프로세스 검색
top                    # 실시간 프로세스 모니터링
htop                   # 향상된 프로세스 모니터링
kill -9 PID            # 강제 종료
killall apache2        # 이름으로 프로세스 종료
nice -n 10 process     # 우선순위 낮춰 실행
nohup command &        # 터미널 종료 후에도 실행 유지
```

---

## 4. 네트워크 명령어

```bash
ifconfig               # 네트워크 인터페이스 정보 (구버전)
ip addr show           # 네트워크 인터페이스 정보 (신버전)
ip route show          # 라우팅 테이블
netstat -tuln          # 열린 포트 확인
netstat -antp          # 연결 상태 및 PID 확인
ss -tuln               # netstat 대체 (더 빠름)
ping -c 4 8.8.8.8      # 연결 테스트
traceroute 8.8.8.8     # 경로 추적
nslookup google.com    # DNS 조회
dig google.com         # 상세 DNS 조회
dig +short google.com  # 간단한 IP 조회
host google.com        # 호스트 정보 조회
curl -I http://site.com  # HTTP 헤더만 조회
wget http://site.com/file  # 파일 다운로드
```

---

## 5. 아카이브 및 압축

```bash
tar -czvf archive.tar.gz dir/    # gzip 압축
tar -xzvf archive.tar.gz         # gzip 해제
tar -cjvf archive.tar.bz2 dir/   # bzip2 압축 (높은 압축률)
tar -xjvf archive.tar.bz2        # bzip2 해제
zip -r archive.zip dir/          # zip 압축
unzip archive.zip                # zip 해제
unzip -P password archive.zip    # 암호화된 zip 해제
```

---

## 6. 패키지 관리

### Debian/Ubuntu/Kali 계열
```bash
apt-get update              # 패키지 목록 갱신
apt-get upgrade             # 설치된 패키지 업그레이드
apt-get install nmap        # 패키지 설치
apt-get remove nmap         # 패키지 제거
apt-get autoremove          # 불필요한 패키지 제거
dpkg -l | grep nmap         # 설치 여부 확인
```

### RedHat/CentOS/Fedora 계열
```bash
yum update                  # 패키지 업데이트
yum install nmap            # 패키지 설치
rpm -qa | grep nmap         # 설치 확인
```

---

## 7. 텍스트 처리 (보안 분석에 필수)

```bash
# 로그에서 특정 IP만 추출
grep "192.168" access.log | awk '{print $1}' | sort | uniq -c | sort -rn

# 비밀번호 파일에서 UID가 0인 계정 찾기 (루트 권한 계정)
awk -F: '$3==0 {print}' /etc/passwd

# sed로 문자열 치환
sed -i 's/old_text/new_text/g' file.txt

# cut으로 필드 추출
cut -d: -f1 /etc/passwd      # 사용자명만 추출
cut -d: -f1,3 /etc/passwd    # 사용자명과 UID 추출

# 중복 제거 및 정렬
cat list.txt | sort | uniq   # 정렬 후 중복 제거
cat list.txt | sort | uniq -c | sort -rn  # 빈도수 포함

# 파이프라인을 활용한 복잡한 분석
cat /var/log/auth.log | grep "Failed" | awk '{print $11}' | sort | uniq -c | sort -rn | head -10
```

---

## 8. 시스템 정보 수집 (해킹 후 내부 정찰)

```bash
uname -a               # 커널 버전 및 시스템 정보
cat /etc/os-release    # OS 버전
hostname               # 호스트명
cat /etc/hostname
env                    # 환경변수 전체 출력
echo $PATH             # PATH 확인
cat /proc/cpuinfo      # CPU 정보
free -h                # 메모리 사용량
df -h                  # 디스크 사용량
mount                  # 마운트된 파일시스템
lsblk                  # 블록 장치 목록
dmesg | tail -50       # 커널 메시지
cat /etc/crontab       # 크론 작업 확인 (권한 상승 경로)
ls -la /etc/cron.d/    # 크론 작업 디렉토리
sudo -l                # sudo 가능한 명령어 목록 (권한 상승 벡터)
```

---

## 9. SSH 및 원격 접속

```bash
ssh user@192.168.1.100          # SSH 접속
ssh -p 2222 user@host           # 포트 지정
ssh -i ~/.ssh/id_rsa user@host  # 키 파일로 접속
ssh -L 8080:localhost:80 user@host  # 로컬 포트 포워딩
ssh -R 4444:localhost:22 user@host  # 리버스 포트 포워딩
ssh -D 1080 user@host           # SOCKS 프록시
scp file.txt user@host:/tmp/    # 파일 복사
scp -r dir/ user@host:/tmp/     # 디렉토리 복사
rsync -avz dir/ user@host:/tmp/ # 동기화 방식 복사
```

### SSH 키 생성 및 관리
```bash
ssh-keygen -t rsa -b 4096 -C "email@example.com"
ssh-keygen -t ed25519          # 더 안전한 알고리즘

# 공개키를 서버에 등록
ssh-copy-id user@host
cat ~/.ssh/id_rsa.pub >> ~/.ssh/authorized_keys

# known_hosts 관리
ssh-keyscan host >> ~/.ssh/known_hosts
```

---

## 10. 로그 분석 (포렌식/보안 감사)

```bash
# 주요 로그 파일
/var/log/auth.log         # 인증 관련 (로그인, sudo)
/var/log/syslog           # 시스템 전반
/var/log/kern.log         # 커널 메시지
/var/log/apache2/access.log   # 웹 서버 접근 로그
/var/log/apache2/error.log    # 웹 서버 오류 로그
/var/log/mysql/error.log  # MySQL 오류

# 실패한 로그인 시도 추적
grep "Failed password" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -rn

# 성공한 로그인 추적
grep "Accepted" /var/log/auth.log

# su 사용 이력
grep "session opened for user root" /var/log/auth.log
```

---

## 11. 사용자 계정 보안 관리 (심화)

### /etc/passwd 구조 이해
```
root:x:0:0:root:/root:/bin/bash
 │   │ │ │  │     │       └── 로그인 쉘
 │   │ │ │  │     └── 홈 디렉토리
 │   │ │ │  └── GECOS (설명)
 │   │ │ └── GID (그룹 ID)
 │   │ └── UID (사용자 ID)
 │   └── 패스워드 필드 (x = shadow 파일 참조)
 └── 사용자명
```

### /etc/shadow 구조 이해
```
root:$6$salt$hash:15285:0:99999:7:::
      │              │   │   │   └── 비활성화 기간
      │              │   │   └── 최대 사용 기간 (99999 = 무제한)
      │              │   └── 최소 사용 기간
      │              └── 마지막 변경일 (1970-01-01 기준 일수)
      └── 해시 ($6$ = SHA-512)
```

### 해시 알고리즘 식별
```
$1$  → MD5
$2a$ → Blowfish (bcrypt)
$5$  → SHA-256
$6$  → SHA-512 (리눅스 기본)
```

### shadow 파일과 passwd 파일 병합 (크랙용)
```bash
# unshadow — passwd와 shadow를 합쳐 John the Ripper 형식으로
unshadow /etc/passwd /etc/shadow > combined.txt
john combined.txt
john --wordlist=wordlist.txt combined.txt
john --show combined.txt  # 크랙된 결과 출력
```

### 계정 잠금 및 상태 확인
```bash
passwd -l username      # 계정 잠금
passwd -u username      # 잠금 해제
passwd -S username      # 계정 상태 확인
chage -l username       # 비밀번호 만료 정보 확인
chage -M 90 username    # 최대 90일마다 변경 강제
chage -E 2025-12-31 username  # 계정 만료일 설정
```

### UID 0 계정 탐지 (루트 권한 백도어 탐지)
```bash
# UID가 0인 계정 전수 확인 (root 외에 있으면 위험)
awk -F: '$3==0 {print $1}' /etc/passwd

# 로그인 쉘이 있는 계정만 확인
awk -F: '$7 !~ /nologin|false/ {print $1, $7}' /etc/passwd
```

---

## 12. Linux PAM (Pluggable Authentication Modules)

### PAM 개요
```
PAM = 리눅스 인증 시스템의 핵심 모듈
위치: /etc/pam.d/
설정 형식: [type] [control] [module] [arguments]
```

### PAM 타입
```
auth     → 사용자 신원 확인 (비밀번호 검증)
account  → 계정 조건 확인 (만료, 시간 제한 등)
password → 비밀번호 업데이트 규칙
session  → 로그인/로그아웃 시 환경 설정
```

### PAM 컨트롤 플래그
```
required   → 실패해도 계속 진행, 최종적으로 실패
requisite  → 실패 즉시 중단
sufficient → 성공하면 이후 생략
optional   → 결과가 최종 판단에 영향 없음
```

### 주요 PAM 모듈

#### pam_tally2 — 로그인 실패 횟수 제한
```bash
# /etc/pam.d/login 또는 /etc/pam.d/sshd 에 추가
auth required pam_tally2.so deny=5 unlock_time=600 onerr=fail

# 현재 실패 횟수 확인
pam_tally2 --user=username

# 수동으로 카운터 초기화
pam_tally2 --user=username --reset
```

#### pam_time — 시간 기반 접근 제어
```bash
# /etc/security/time.conf 설정 예시
# 서비스;터미널;사용자;시간
login;*;username;Mo-Fr0900-1800   # 월~금 09:00~18:00만 허용
sshd;*;ALL;Al0000-2400            # 모든 시간 허용

# /etc/pam.d/login 에 추가
account required pam_time.so
```

#### pam_access — 호스트 기반 접근 제어
```bash
# /etc/security/access.conf 설정
# 형식: + 또는 - : 사용자 : 호스트/IP
+:root:192.168.1.0/24     # 내부망에서만 root 허용
-:root:ALL                # 그 외 root 거부
+:ALL:LOCAL               # 로컬 로그인은 모두 허용
-:ALL:ALL                 # 나머지 전부 거부

# /etc/pam.d/sshd 에 추가
account required pam_access.so
```

#### pam_pwquality — 비밀번호 복잡도 정책
```bash
# /etc/security/pwquality.conf
minlen = 12           # 최소 12자
minclass = 3          # 최소 3가지 문자 클래스
maxrepeat = 3         # 동일 문자 최대 3회 반복
dcredit = -1          # 숫자 최소 1개
ucredit = -1          # 대문자 최소 1개
lcredit = -1          # 소문자 최소 1개
ocredit = -1          # 특수문자 최소 1개

# /etc/pam.d/common-password 에 추가
password requisite pam_pwquality.so retry=3
```

---

## 13. 방화벽 설정 (iptables)

### iptables 기본 구조
```
테이블: filter, nat, mangle, raw
체인:
  INPUT   → 들어오는 패킷 (서버로 향하는)
  OUTPUT  → 나가는 패킷 (서버에서 나가는)
  FORWARD → 통과하는 패킷 (라우터 역할 시)

규칙 평가: 위에서 아래로 순서대로, 매칭되면 즉시 적용
기본 정책: ACCEPT 또는 DROP
```

### 기본 iptables 명령어
```bash
# 현재 규칙 확인
iptables -L -n -v          # 기본 (filter 테이블)
iptables -L -n -v --line-numbers  # 줄 번호 포함

# 규칙 추가
iptables -A INPUT -p tcp --dport 22 -j ACCEPT   # SSH 허용
iptables -A INPUT -p tcp --dport 80 -j ACCEPT   # HTTP 허용
iptables -A INPUT -p tcp --dport 443 -j ACCEPT  # HTTPS 허용

# 특정 IP 허용/차단
iptables -A INPUT -s 192.168.1.100 -j ACCEPT    # 특정 IP 허용
iptables -A INPUT -s 10.0.0.0/8 -j DROP         # 대역 차단

# 기본 정책 설정 (화이트리스트 방식)
iptables -P INPUT DROP     # 기본적으로 모두 차단
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT  # 나가는 것은 허용

# 이미 연결된 세션 유지 (필수)
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT   # 루프백 허용

# 규칙 삭제
iptables -D INPUT 3        # 3번 규칙 삭제
iptables -F                # 전체 초기화 (주의!)

# 규칙 저장 및 복원
iptables-save > /etc/iptables/rules.v4
iptables-restore < /etc/iptables/rules.v4
```

### 기본 서버 보안 정책 예시
```bash
#!/bin/bash
# 기본 서버 방화벽 설정 스크립트

# 기존 규칙 초기화
iptables -F
iptables -X

# 기본 정책: 차단
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# 루프백 및 기존 연결 허용
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# SSH 허용 (관리용)
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# 웹 서비스 허용
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# ICMP (ping) 허용
iptables -A INPUT -p icmp -j ACCEPT

# 로그 기록 후 차단
iptables -A INPUT -j LOG --log-prefix "DROPPED: " --log-level 4
iptables -A INPUT -j DROP

echo "[+] 방화벽 규칙 적용 완료"
iptables -L -n -v
```

### nftables (iptables 후속)
```bash
# 현재 규칙 확인
nft list ruleset

# 기본 설정
nft add table inet filter
nft add chain inet filter input { type filter hook input priority 0 \; policy drop \; }
nft add chain inet filter output { type filter hook output priority 0 \; policy accept \; }

# SSH 허용
nft add rule inet filter input tcp dport 22 accept

# 규칙 저장
nft list ruleset > /etc/nftables.conf
```

---

## 리눅스 서버 기본 보안 정책

### SSH 브루트포스 방어 — /etc/passwd 계정 관리
```bash
# 사용하지 않는 계정 비활성화 (앞에 # 추가)
# /etc/passwd 파일에서 쉘이 /bin/bash 인 미사용 계정 확인
grep "/bin/bash\|/bin/sh" /etc/passwd

# 미사용 계정 로그인 차단 (쉘을 nologin으로 변경)
usermod -s /sbin/nologin [계정명]

# 또는 /etc/passwd에서 직접 주석 처리
# rpm:x:37:37::/var/lib/rpm:/bin/bash
# → #rpm:x:37:37::/var/lib/rpm:/bin/bash

# 강력한 패스워드 정책 (브루트포스 방어):
# - 특수문자 조합
# - 사전 파일에 없는 문자열
# - 8자 이상 권장
```

### PortSentry — 포트 스캔 탐지 및 자동 차단
```bash
# PortSentry 설정 파일
# /etc/portsentry/portsentry.conf

# 스텔스 모드 설정 (TCP/UDP)
BLOCK_UDP="1"
BLOCK_TCP="1"

# 공격자 자동 차단 (hosts.deny 추가)
KILL_ROUTE="/sbin/route add -host $TARGET$ reject"
# 또는 iptables로 차단
KILL_ROUTE="/sbin/iptables -I INPUT -s $TARGET$ -j DROP"

# 차단된 IP 확인
cat /etc/hosts.deny | grep "ALL:"

# PortSentry 실행 (스텔스 모드)
portsentry -stcp   # TCP 스텔스 스캔 탐지
portsentry -sudp   # UDP 스텔스 스캔 탐지
```

### chkrootkit — 백도어 탐지
```bash
# 설치
apt-get install chkrootkit
# 또는
yum install chkrootkit

# 전체 시스템 루트킷 검사
chkrootkit

# 특정 테스트만 실행
chkrootkit sniffer    # 스니퍼 탐지
chkrootkit bindshell  # 백도어 바인드 쉘 탐지
chkrootkit lkm        # 커널 모듈 루트킷 탐지

# 주기적 실행 (cron)
echo "0 3 * * * root /usr/sbin/chkrootkit 2>&1 | mail -s 'chkrootkit report' admin@example.com" >> /etc/crontab

# INFECTED 결과 시 조치:
# 1. 네트워크 즉시 분리
# 2. 포렌식 이미지 생성
# 3. 클린 시스템에서 재구축 고려
```

### 파일 퍼미션 강화
```bash
# 주요 설정 파일 권한 제한
chmod 600 /etc/shadow         # root만 읽기
chmod 644 /etc/passwd         # 모두 읽기, root만 쓰기
chmod 644 /etc/group
chmod 600 /etc/gshadow
chmod 700 /root                # root 홈 디렉토리

# 불필요한 SUID 비트 제거
find / -perm -4000 -type f 2>/dev/null  # SUID 파일 목록
chmod u-s /path/to/suspicious_file

# World-writable 파일/디렉토리 탐지
find / -perm -o+w -type f 2>/dev/null | grep -v proc
find / -perm -o+w -type d 2>/dev/null | grep -v proc

# 소유자 없는 파일 탐지 (공격자가 만든 임시 파일)
find / -nouser -print 2>/dev/null
find / -nogroup -print 2>/dev/null
```

### Apache httpd.conf 보안 설정 핵심
```apache
# 서버 정보 숨기기
ServerSignature Off
ServerTokens Prod

# 디렉토리 리스팅 비활성화
Options -Indexes

# 심볼릭 링크 따라가기 비활성화
Options -FollowSymLinks

# 불필요한 HTTP 메서드 비활성화
<LimitExcept GET POST>
    Deny from all
</LimitExcept>

# .htaccess 파일 Override 비활성화 (성능 + 보안)
AllowOverride None

# CGI 실행 금지 (필요한 경우만 허용)
Options -ExecCGI

# 파일 포함 방지
Options -Includes
```

### PHP 보안 설정 (php.ini)
```ini
# 오류 정보 외부 노출 방지
display_errors = Off
log_errors = On
error_log = /var/log/php_errors.log

# 원격 파일 포함 비활성화 (RFI 방지)
allow_url_include = Off
allow_url_fopen = Off

# 파일 업로드 제한
file_uploads = On
upload_max_filesize = 2M
max_file_uploads = 20

# 위험한 함수 비활성화
disable_functions = exec,passthru,shell_exec,system,proc_open,popen,
                    curl_exec,curl_multi_exec,parse_ini_file,show_source

# PHP 버전 정보 숨기기
expose_php = Off

# 세션 보안
session.cookie_httponly = 1
session.cookie_secure = 1
session.use_strict_mode = 1
```
